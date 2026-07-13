# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
"""Every provider must reject an empty message list with a typed error.

A chat completion needs at least one message to respond to, so ``chat`` and
``chat_stream`` reject an empty ``messages`` list with :class:`ProviderError`
before any connection or network work. The guard lives in
:meth:`LLMProviderBase._reject_empty_messages` and is invoked at the top of
every provider's ``chat``/``chat_stream``.

These gates are credential-free: the rejection happens before the connection
check, so a fresh unconnected provider is enough. To stay falsifiable they
assert on the *empty-messages* error text specifically — an unconnected
provider would otherwise raise the ``not connected`` :class:`ProviderError`,
which must NOT satisfy the gate if the guard is ever removed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import ProviderError
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from intellicrack.providers.base import LLMProviderBase

pytestmark = pytest.mark.asyncio

_EMPTY_MESSAGE_MATCH = "at least one message"
_PROVIDERS: list[type[LLMProviderBase]] = [
    AnthropicProvider,
    OpenAIProvider,
    GoogleProvider,
    GrokProvider,
    OpenRouterProvider,
    OllamaProvider,
    HuggingFaceProvider,
    LocalTransformersProvider,
]


@pytest.mark.parametrize("provider_cls", _PROVIDERS, ids=lambda cls: cls.__name__)
async def test_chat_rejects_empty_messages(provider_cls: type[LLMProviderBase]) -> None:
    """chat() rejects an empty message list with the empty-messages error.

    Args:
        provider_cls: The provider class under test.
    """
    provider = provider_cls()
    with pytest.raises(ProviderError, match=_EMPTY_MESSAGE_MATCH):
        _ = await provider.chat([], model="test-model")


@pytest.mark.parametrize("provider_cls", _PROVIDERS, ids=lambda cls: cls.__name__)
async def test_chat_stream_rejects_empty_messages(provider_cls: type[LLMProviderBase]) -> None:
    """chat_stream() rejects an empty message list with the empty-messages error.

    Args:
        provider_cls: The provider class under test.
    """
    provider = provider_cls()
    with pytest.raises(ProviderError, match=_EMPTY_MESSAGE_MATCH):
        async for _ in provider.chat_stream([], model="test-model"):
            pass
