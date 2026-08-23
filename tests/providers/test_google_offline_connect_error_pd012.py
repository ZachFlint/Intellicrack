# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""PD-012 offline falsifiable gate: ``connect()`` must convert a real ``httpx.ConnectError``.

``GoogleProvider.connect`` builds a real ``google.genai.Client`` and probes it
with ``models.list()``.  When the probe cannot reach a listener at all, the
underlying transport raises ``httpx.ConnectError`` -- whose MRO
(``ConnectError`` -> ``NetworkError`` -> ``TransportError`` -> ``RequestError``
-> ``HTTPError`` -> ``Exception``) shares no base with any of the builtin
exceptions ``connect()`` originally caught (``ConnectionError``,
``TimeoutError``, ``OSError``, ``ValueError``, ``RuntimeError``).  This test
forces a genuine (unmocked) connection failure by pointing the real ``genai``
client at a local TCP port with no listener, so the transport itself raises
``httpx.ConnectError``, and asserts ``connect()`` surfaces the contracted
``ProviderError("Connection failed")`` instead of letting the raw transport
error escape.
"""

from __future__ import annotations

import os
import socket

import google.genai as _real_genai
import pytest
from google.genai import Client as GenaiClient
from google.genai.types import HttpOptions

from intellicrack.core.types import ProviderCredentials, ProviderError
from intellicrack.providers.google import GoogleProvider


def _reserve_closed_local_port() -> int:
    """Reserve then immediately release a loopback TCP port with no listener.

    Binding to port 0 asks the OS for a currently-free ephemeral port; the
    socket is closed before the port number is returned, so nothing is
    listening on it when the test uses it, guaranteeing the connect attempt
    is actively refused rather than merely slow.

    Returns:
        int: A loopback TCP port number with no active listener.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _unroutable_genai_client(*, api_key: str | None = None) -> GenaiClient:
    """Build a real ``genai.Client`` forced onto a listener-less local port.

    Installed in place of the plain ``genai.Client`` constructor inside
    ``GoogleProvider._connect_impl`` so the ``models.list()`` probe issues a
    genuine outbound TCP connection attempt -- to a port this test reserved
    and released -- and lets the real ``httpx`` transport raise
    ``httpx.ConnectError`` on its own, without any exception being mocked.

    Args:
        api_key: API key forwarded from ``connect()``'s
            ``genai.Client(api_key=credentials.api_key)`` call.

    Returns:
        GenaiClient: A real client instance whose HTTP requests all target
        a dead loopback port.
    """
    closed_port = _reserve_closed_local_port()
    return GenaiClient(
        api_key=api_key,
        http_options=HttpOptions(base_url=f"http://127.0.0.1:{closed_port}"),
    )


@pytest.mark.asyncio
async def test_connect_wraps_real_httpx_connect_error_as_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real ``httpx.ConnectError`` from the probe surfaces as ``ProviderError``.

    ``_unroutable_genai_client`` points the real ``genai.Client`` at a loopback
    port with no listener, so ``models.list()`` triggers an actual refused
    TCP connection and the real ``httpx`` sync transport raises
    ``httpx.ConnectError`` -- no exception is constructed or injected by the
    test.  Before the PD-012 fix, ``connect()``'s ``except`` clause at
    google.py listed only ``(ConnectionError, TimeoutError, OSError,
    ValueError, RuntimeError)``, none of which are base classes of
    ``httpx.ConnectError``, so the raw transport error propagated out of
    ``connect()`` instead of the contracted ``ProviderError("Connection
    failed")``.

    Oracle: the documented ``connect()`` contract (see the sibling
    ``test_connect_gemini_api_key_restored_after_failure`` gate) is that any
    probe failure raises ``ProviderError`` with the ``_MSG_CONNECTION_FAILED``
    message; the real ``httpx.ConnectError`` MRO is independently verifiable
    and shares no base with the exception tuple ``connect()`` previously
    caught.

    Mutation caught: reverting the ``except`` clause to omit
    ``httpx.ConnectError`` (or an equivalent ``httpx`` base) lets a raw
    ``httpx.ConnectError`` escape ``connect()`` instead of the wrapped
    ``ProviderError``; ``pytest.raises(ProviderError, ...)`` then fails
    because a different exception type propagates.
    """
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(_real_genai, "Client", _unroutable_genai_client)
    provider = GoogleProvider()
    creds = ProviderCredentials(api_key="fake-offline-key")

    with pytest.raises(ProviderError, match="Connection failed"):
        await provider.connect(creds)

    assert provider.connected is False
    assert provider.client is None


@pytest.mark.asyncio
async def test_connect_real_connect_error_leaves_env_restored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``GEMINI_API_KEY`` restoration contract also holds for a real transport failure.

    Mirrors ``test_connect_gemini_api_key_restored_after_failure`` but drives
    the failure through a genuine ``httpx.ConnectError`` instead of an
    injected ``OSError``, proving the env-var restoration ``finally`` block
    is reached regardless of which exception type the probe raises.

    Mutation caught: removing the ``os.environ["GEMINI_API_KEY"] =
    saved_gemini_key`` restoration would leave the sentinel value absent
    after this real-transport failure too.
    """
    sentinel = "test-sentinel-gemini-env-pd012"
    monkeypatch.setenv("GEMINI_API_KEY", sentinel)
    monkeypatch.setattr(_real_genai, "Client", _unroutable_genai_client)
    provider = GoogleProvider()
    creds = ProviderCredentials(api_key="fake-offline-key")

    with pytest.raises(ProviderError, match="Connection failed"):
        await provider.connect(creds)

    assert os.environ.get("GEMINI_API_KEY") == sentinel
