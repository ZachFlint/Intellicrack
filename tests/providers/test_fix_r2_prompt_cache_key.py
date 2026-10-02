# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 29: ``prompt_cache_key`` names the conversation, not the model.

With the model id as the key, every conversation with a model shared one cache route, so a busy session crowded the cached prefix of
every other out. The gates drive the real built-in :class:`OpenAIProvider` over the Responses API and a Chat Completions instance
against a loopback endpoint, and read the keys sent: the turns of one conversation share a key, two conversations that open with the
same words do not, and neither key is the model id.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import Message, ProviderCredentials
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.scripted_sdk_server import ScriptedHTTPServer, json_response


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.providers.base import LLMProviderBase


_MODEL: Final[str] = "gpt-5.2"
_API_KEY: Final[str] = "sk-proj-loopbackCacheKey0123456789"
_OPENED: Final[datetime] = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _responses_body() -> dict[str, Any]:
    """Build a Responses answer.

    Returns:
        dict[str, Any]: The body.
    """
    message: dict[str, Any] = {
        "type": "message",
        "id": "msg_1",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": "ok", "annotations": []}],
    }
    return {
        "id": "resp_1",
        "object": "response",
        "created_at": 1_760_000_000,
        "model": _MODEL,
        "status": "completed",
        "output": [message],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4},
    }


def _chat_body() -> dict[str, Any]:
    """Build a Chat Completions answer.

    Returns:
        dict[str, Any]: The body.
    """
    return {
        "id": "c1",
        "object": "chat.completion",
        "created": 0,
        "model": _MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    }


@pytest.fixture
def server() -> Iterator[ScriptedHTTPServer]:
    """Run a loopback OpenAI-compatible endpoint.

    Yields:
        ScriptedHTTPServer: The running server.
    """
    listing = json_response({"object": "list", "data": [{"id": _MODEL, "object": "model", "created": 0, "owned_by": "o"}]})
    running = ScriptedHTTPServer({
        ("GET", "/v1/models"): listing,
        ("POST", "/v1/responses"): json_response(_responses_body()),
        ("POST", "/v1/chat/completions"): json_response(_chat_body()),
    })
    yield running
    running.close()


async def _connect(server: ScriptedHTTPServer, *, builtin: bool) -> LLMProviderBase:
    """Connect the built-in OpenAI provider or a Chat Completions instance.

    Args:
        server: The running server.
        builtin: Whether to connect the built-in provider.

    Returns:
        LLMProviderBase: The provider.
    """
    if builtin:
        provider: LLMProviderBase = OpenAIProvider()
        await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
        return provider
    instance = ProviderInstance(
        instance_id="chat-gw",
        dialect=ApiDialect.CHAT_COMPLETIONS,
        api_base=f"{server.origin}/v1",
        model_overrides={_MODEL: CapabilityOverride(supports_prompt_cache_key=True)},
    )
    provider = ConfigurableProvider(instance)
    await provider.connect(ProviderCredentials(api_key=_API_KEY))
    return provider


def _conversation(opened: datetime) -> list[Message]:
    """Open a conversation with the same words every time.

    Args:
        opened: When its first message was written.

    Returns:
        list[Message]: The conversation so far.
    """
    return [
        Message(role="system", content="You are a reverse engineer.", timestamp=opened),
        Message(role="user", content="Where is the licence check?", timestamp=opened),
    ]


@pytest.mark.parametrize("builtin", [True, False], ids=["builtin-responses", "chat-completions-instance"])
def test_cache_key_names_the_conversation(server: ScriptedHTTPServer, *, builtin: bool) -> None:
    """Two turns of one conversation share a key; a second conversation with the same opening gets another; neither is the model id.

    Args:
        server: The loopback endpoint.
        builtin: Whether to use the built-in provider.
    """
    first = _conversation(_OPENED)
    second = _conversation(_OPENED + timedelta(minutes=5))
    path = "/v1/responses" if builtin else "/v1/chat/completions"

    async def run() -> None:
        """Send two turns of the first conversation and one of the second."""
        provider = await _connect(server, builtin=builtin)
        reply, _ = await provider.chat(first, _MODEL, enable_cache=True)
        _ = await provider.chat([*first, reply, Message(role="user", content="And the trial timer?")], _MODEL, enable_cache=True)
        _ = await provider.chat(second, _MODEL, enable_cache=True)

    asyncio.run(run())
    keys = [request.body.get("prompt_cache_key") for request in server.requests(path)]
    assert len(keys) == len(("first turn", "second turn", "other conversation"))
    assert all(isinstance(key, str) and key for key in keys)
    assert keys[0] == keys[1]
    assert keys[2] != keys[0]
    assert _MODEL not in keys
