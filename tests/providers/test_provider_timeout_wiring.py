# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wire-level gates: a saved request timeout reaches every SDK-backed provider.

``ProviderCredentials.timeout`` carries the timeout saved in Provider
Settings. OpenAI, Grok and Anthropic build ``openai``/``anthropic`` SDK clients,
and Google builds a ``google-genai`` client; each used to ignore the value.
These gates connect the real providers to a loopback server through the real
SDKs and read the timeout the SDK actually announces on the wire:

* the Stainless-generated ``openai`` and ``anthropic`` clients send the
  effective read timeout as ``x-stainless-read-timeout``;
* ``google-genai`` sends ``X-Server-Timeout`` (whole seconds) only when a
  timeout is configured.

Each gate also pins the no-timeout case to the SDK default, so a provider that
forwards ``timeout=None`` -- which disables the SDK timeout entirely -- fails.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.provider_endpoint_server import (
    ANTHROPIC_MODELS_PATH,
    GEMINI_MODELS_PATH,
    OPENAI_COMPATIBLE_MODELS_PATH,
    ProviderEndpointServer,
)
from tests._helpers.provider_state import isolate_provider_environment


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.providers.base import LLMProviderBase


_ACCEPTED_KEY = "loopback-accepted-" + ("k" * 24)
_SDK_DEFAULT_READ_TIMEOUT = "600"
_CONFIGURED_TIMEOUT = 37.5


@pytest.fixture
def endpoint_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[ProviderEndpointServer]:
    """Provide a loopback provider endpoint server in a provider-free environment.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        ProviderEndpointServer: The running server.
    """
    isolate_provider_environment(monkeypatch)
    with ProviderEndpointServer(accepted_key=_ACCEPTED_KEY, model_ids=["loopback-model"]) as server:
        yield server


async def _connect_and_disconnect(provider: LLMProviderBase, credentials: ProviderCredentials) -> None:
    """Connect a provider, require success, then disconnect it.

    Args:
        provider: The provider under test.
        credentials: Credentials to connect with.
    """
    await provider.connect(credentials)
    try:
        assert provider.is_connected
    finally:
        await provider.disconnect()


def _last_header(server: ProviderEndpointServer, path: str, header: str) -> str | None:
    """Return a header from the most recent request to ``path``.

    Args:
        server: The loopback server.
        path: The endpoint path.
        header: Lower-cased header name.

    Returns:
        str | None: The header value, or ``None`` when the header was not sent.
    """
    requests = server.requests(path)
    assert requests, f"no request reached {path}"
    return requests[-1].headers.get(header)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_factory", [OpenAIProvider, GrokProvider], ids=["openai", "grok"])
async def test_openai_sdk_providers_send_saved_timeout(
    endpoint_server: ProviderEndpointServer,
    provider_factory: type[OpenAIProvider | GrokProvider],
) -> None:
    """OpenAI and Grok hand the saved timeout to their ``openai`` SDK client.

    Args:
        endpoint_server: Loopback server fixture.
        provider_factory: Provider class under test.
    """
    base_url = endpoint_server.openai_compatible_base_url

    await _connect_and_disconnect(
        provider_factory(),
        ProviderCredentials(api_key=_ACCEPTED_KEY, api_base=base_url, timeout=_CONFIGURED_TIMEOUT),
    )
    assert _last_header(endpoint_server, OPENAI_COMPATIBLE_MODELS_PATH, "x-stainless-read-timeout") == str(_CONFIGURED_TIMEOUT)

    await _connect_and_disconnect(provider_factory(), ProviderCredentials(api_key=_ACCEPTED_KEY, api_base=base_url))
    assert _last_header(endpoint_server, OPENAI_COMPATIBLE_MODELS_PATH, "x-stainless-read-timeout") == _SDK_DEFAULT_READ_TIMEOUT


@pytest.mark.asyncio
async def test_anthropic_sends_saved_timeout(endpoint_server: ProviderEndpointServer) -> None:
    """Anthropic hands the saved timeout to its ``anthropic`` SDK client.

    Args:
        endpoint_server: Loopback server fixture.
    """
    base_url = endpoint_server.anthropic_base_url

    await _connect_and_disconnect(
        AnthropicProvider(),
        ProviderCredentials(api_key=_ACCEPTED_KEY, api_base=base_url, timeout=_CONFIGURED_TIMEOUT),
    )
    assert _last_header(endpoint_server, ANTHROPIC_MODELS_PATH, "x-stainless-read-timeout") == str(_CONFIGURED_TIMEOUT)

    await _connect_and_disconnect(AnthropicProvider(), ProviderCredentials(api_key=_ACCEPTED_KEY, api_base=base_url))
    assert _last_header(endpoint_server, ANTHROPIC_MODELS_PATH, "x-stainless-read-timeout") == _SDK_DEFAULT_READ_TIMEOUT


@pytest.mark.asyncio
async def test_google_sends_saved_timeout(endpoint_server: ProviderEndpointServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """Google hands the saved timeout, rounded up to whole milliseconds, to its genai client.

    ``GOOGLE_GEMINI_BASE_URL`` is the google-genai SDK's own endpoint override.

    Args:
        endpoint_server: Loopback server fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", endpoint_server.gemini_base_url)

    await _connect_and_disconnect(GoogleProvider(), ProviderCredentials(api_key=_ACCEPTED_KEY, timeout=_CONFIGURED_TIMEOUT))
    assert _last_header(endpoint_server, GEMINI_MODELS_PATH, "x-server-timeout") == "38"

    await _connect_and_disconnect(GoogleProvider(), ProviderCredentials(api_key=_ACCEPTED_KEY))
    assert _last_header(endpoint_server, GEMINI_MODELS_PATH, "x-server-timeout") is None
