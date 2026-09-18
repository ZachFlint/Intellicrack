# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Every HTTP provider must report an unreachable endpoint as ``ProviderError``.

``connect`` documents that it raises ``ProviderError`` when the connection
fails, and every caller relies on that: the model-refresh worker, the
connection test and the orchestrator all catch ``ProviderError`` and turn it
into a message. A transport error that escapes unwrapped reaches none of them.

In the provider-settings dialog that meant the model-refresh ``QThread`` died
without emitting ``refresh_finished``, so the model list stayed in its loading
state with no error shown -- for exactly the case a user most needs told
about, a base URL that does not answer.

The OpenAI SDK reports a refused connection as ``openai.APIConnectionError``,
which derives from ``openai.APIError`` and from none of the builtin
``ConnectionError``, ``TimeoutError`` or ``OSError``. ``OpenAIProvider``
caught ``openai.APIError``; ``GrokProvider``, built on the same SDK, did not.
Parametrizing over every provider that honours ``api_base`` keeps one of them
from drifting again.

Each case points the real client at a loopback port with no listener, so the
failure is a genuine refused connection rather than a stubbed exception.
"""

from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import AuthenticationError, ProviderCredentials, ProviderError
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from intellicrack.providers.base import LLMProviderBase


_PROVIDERS: tuple[type[LLMProviderBase], ...] = (OpenAIProvider, GrokProvider, OpenRouterProvider)

_CONNECT_TIMEOUT_SECONDS = 5.0
"""Bounds each attempt so a regression cannot hang the suite; a refusal is immediate."""


def _closed_loopback_port() -> int:
    """Reserve and release a loopback port, leaving nothing listening on it.

    Returns:
        int: A loopback TCP port a connection attempt will be refused on.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    finally:
        probe.close()
    return port


@pytest.mark.parametrize("provider_class", _PROVIDERS, ids=lambda cls: cls.__name__)
def test_a_refused_connection_raises_provider_error(provider_class: type[LLMProviderBase]) -> None:
    """A base URL with nothing behind it must surface as ``ProviderError``.

    Args:
        provider_class: The provider under test.
    """
    provider = provider_class()
    probe_key = "unreachable-endpoint-probe"
    credentials = ProviderCredentials(
        api_key=probe_key,
        api_base=f"http://127.0.0.1:{_closed_loopback_port()}/v1",
        timeout=_CONNECT_TIMEOUT_SECONDS,
    )

    with pytest.raises(ProviderError) as raised:
        asyncio.run(provider.connect(credentials))

    assert not isinstance(raised.value, AuthenticationError), "a refused connection is not a credential problem"
    assert provider.connected is False
