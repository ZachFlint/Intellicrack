# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OpenAI model families resolve to their documented capabilities.

The values checked here come from OpenAI's model pages: GPT-4.1 has a
1,047,576-token window, the GPT-4 Turbo previews have 128k, and
``gpt-5-chat-latest`` is the non-reasoning chat snapshot that takes a
temperature over Chat Completions. Realtime, audio, transcription, TTS and
computer-use models cannot run a chat turn and must not be offered as chat
models. The listing is read by a real :class:`OpenAIProvider` from a loopback
``/v1/models`` endpoint, and a chat turn is sent through the real SDK so the
wire body shows which API and parameters the capability record selected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator


_API_KEY: Final[str] = "sk-" + "loopbackHeuristicsKey0123456789"
_CHAT_IDS: Final[tuple[str, ...]] = (
    "gpt-4.1",
    "gpt-4.1-mini-2025-04-14",
    "gpt-4-0125-preview",
    "gpt-4-1106-preview",
    "gpt-5-chat-latest",
    "gpt-5.2",
    "gpt-4o",
)
_NON_CHAT_IDS: Final[tuple[str, ...]] = (
    "gpt-4o-realtime-preview",
    "gpt-realtime",
    "gpt-4o-audio-preview",
    "gpt-audio",
    "gpt-4o-transcribe",
    "gpt-4o-mini-transcribe",
    "gpt-4o-mini-tts",
    "computer-use-preview",
    "text-embedding-3-large",
)


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback OpenAI endpoint listing chat and non-chat models.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    listing = {
        "object": "list",
        "data": [{"id": model, "object": "model", "created": 0, "owned_by": "openai"} for model in _CHAT_IDS + _NON_CHAT_IDS],
    }
    completion: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-5-chat-latest",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }
    running = ScriptedHTTPServer({
        ("GET", "/v1/models"): json_response(listing),
        ("POST", "/v1/chat/completions"): json_response(completion),
    })
    yield running
    running.close()


async def _connected(server: ScriptedHTTPServer) -> OpenAIProvider:
    """Connect a real OpenAI provider to the loopback endpoint.

    Args:
        server: The running server.

    Returns:
        OpenAIProvider: The connected provider.
    """
    provider = OpenAIProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
    return provider


@pytest.mark.asyncio
async def test_listing_offers_only_chat_models_with_documented_windows(server: ScriptedHTTPServer) -> None:
    """Speech, realtime and computer-use models are filtered out; windows match the model pages."""
    provider = await _connected(server)

    models = {model.id: model for model in await provider.list_models()}

    assert set(models) == set(_CHAT_IDS)
    assert models["gpt-4.1"].context_window == 1_047_576
    assert models["gpt-4.1-mini-2025-04-14"].context_window == 1_047_576
    assert models["gpt-4-0125-preview"].context_window == 128_000
    assert models["gpt-4-1106-preview"].context_window == 128_000
    assert models["gpt-5-chat-latest"].context_window == 128_000


@pytest.mark.asyncio
async def test_gpt5_chat_latest_is_a_non_reasoning_chat_completions_model(server: ScriptedHTTPServer) -> None:
    """``gpt-5-chat-latest`` goes to Chat Completions with the caller's temperature and no reasoning knob."""
    provider = await _connected(server)
    capabilities = provider.capabilities_for("gpt-5-chat-latest")

    await provider.chat([Message(role="user", content="hi")], "gpt-5-chat-latest", temperature=0.25)

    assert capabilities.dialect is ApiDialect.CHAT_COMPLETIONS
    assert capabilities.reasoning.supported is False
    assert capabilities.supports_temperature is True
    body: dict[str, Any] = server.requests("/v1/chat/completions")[-1].body
    assert body["model"] == "gpt-5-chat-latest"
    assert body["temperature"] == pytest.approx(0.25)
    assert "reasoning_effort" not in body
    assert provider.capabilities_for("gpt-5.2").dialect is ApiDialect.RESPONSES
