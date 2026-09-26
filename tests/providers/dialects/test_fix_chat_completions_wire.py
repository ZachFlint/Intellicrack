# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Chat Completions wire-format gates: tool-message contiguity, reasoning key, error chunks.

Each test drives a real ConfigurableProvider against a loopback endpoint that
answers with real Chat Completions JSON bodies and real server-sent-event byte
streams, and asserts on the request body the provider actually sent.
"""

from __future__ import annotations

from typing import Any, Final

import pytest

from intellicrack.core.types import (
    ImageResultPart,
    Message,
    ProviderError,
    ReasoningKind,
    TextResultPart,
    ToolCall,
    ToolResult,
)
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride, ReasoningSupport
from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint, json_reply, sse_reply
from tests.providers.dialects.wire_support import collect, connect_provider


_MODEL: Final[str] = "vision-reasoner"
_PNG_A: Final[str] = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
_PNG_B: Final[str] = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="


def _completion(message: dict[str, Any]) -> dict[str, Any]:
    """Build a Chat Completions response body.

    Args:
        message: The assistant message.

    Returns:
        dict[str, Any]: The body.
    """
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": _MODEL,
        "choices": [{"index": 0, "message": {"role": "assistant", **message}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def _screenshot_result(call_id: str, image: str) -> ToolResult:
    """Build a tool result carrying text and one PNG image.

    Args:
        call_id: The call the result answers.
        image: Base64 PNG data.

    Returns:
        ToolResult: The result.
    """
    return ToolResult(
        call_id=call_id,
        success=True,
        result=None,
        error=None,
        duration_ms=1.0,
        content=[TextResultPart(text=f"screenshot {call_id}"), ImageResultPart(data=image, mime_type="image/png")],
    )


def _two_call_turn() -> Message:
    """Build an assistant turn that requested two screenshots.

    Returns:
        Message: The assistant message.
    """
    return Message(
        role="assistant",
        content="",
        tool_calls=[
            ToolCall(id="call_a", tool_name="x64dbg", function_name="x64dbg.screenshot", arguments={}),
            ToolCall(id="call_b", tool_name="x64dbg", function_name="x64dbg.screenshot", arguments={}),
        ],
    )


@pytest.mark.parametrize("split_messages", [False, True], ids=["one-tool-message", "one-message-per-result"])
@pytest.mark.asyncio
async def test_image_results_follow_the_whole_run_of_tool_messages(*, split_messages: bool) -> None:
    """Every ``tool`` message answering a turn stays contiguous; the images follow in one ``user`` message.

    Args:
        split_messages: Whether each result arrives in its own tool message
            rather than both in one.
    """
    results = [_screenshot_result("call_a", _PNG_A), _screenshot_result("call_b", _PNG_B)]
    tool_messages = (
        [Message(role="tool", content="", tool_results=[result]) for result in results]
        if split_messages
        else [Message(role="tool", content="", tool_results=results)]
    )
    history = [Message(role="user", content="capture both windows"), _two_call_turn(), *tool_messages]
    overrides = {_MODEL: CapabilityOverride(supports_vision=True)}
    with ScriptedHttpEndpoint([json_reply(_completion({"content": "seen"}))]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.CHAT_COMPLETIONS, model=_MODEL, overrides=overrides)
        await provider.chat(history, _MODEL)
        await provider.disconnect()

    sent = endpoint.requests[0].body["messages"]
    assert [message["role"] for message in sent] == ["user", "assistant", "tool", "tool", "user"]
    assert [message["tool_call_id"] for message in sent[2:4]] == ["call_a", "call_b"]
    image_urls = [part["image_url"]["url"] for part in sent[4]["content"] if part["type"] == "image_url"]
    assert image_urls == [f"data:image/png;base64,{_PNG_A}", f"data:image/png;base64,{_PNG_B}"]
    labels = [part["text"] for part in sent[4]["content"] if part["type"] == "text"]
    assert labels == ["Images returned by tool call call_a:", "Images returned by tool call call_b:"]


@pytest.mark.asyncio
async def test_configured_reasoning_key_is_read_from_responses_and_streams() -> None:
    """A gateway that sends reasoning under ``reasoning`` is read through the model's ``reasoning_key``."""
    overrides = {_MODEL: CapabilityOverride(reasoning=ReasoningSupport(supported=True, reasoning_key="reasoning"))}
    stream: list[dict[str, Any]] = [
        {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"reasoning": "Checking imports."}}]},
        {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "Packed."}}]},
        {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]
    replies = [
        json_reply(_completion({"content": "UPX.", "reasoning": "Section names match UPX."})),
        sse_reply(stream, named=False, done=True),
    ]
    with ScriptedHttpEndpoint(replies) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.CHAT_COMPLETIONS, model=_MODEL, overrides=overrides)
        assistant, _ = await provider.chat([Message(role="user", content="packer?")], _MODEL)
        chat_thinking = provider.get_pending_thinking()
        text = await collect(provider.chat_stream([Message(role="user", content="packer?"), assistant], _MODEL))
        thinking = provider.get_pending_thinking()
        await provider.disconnect()

    assert assistant.reasoning is not None
    assert [(item.kind, item.text) for item in assistant.reasoning] == [(ReasoningKind.REASONING_CONTENT, "Section names match UPX.")]
    assert chat_thinking == ["Section names match UPX."]
    assert text == "Packed."
    assert thinking == ["Checking imports."]
    replayed = endpoint.requests[1].body["messages"][1]
    assert replayed["reasoning"] == "Section names match UPX."
    assert "reasoning_content" not in replayed


@pytest.mark.asyncio
async def test_error_chunk_mid_stream_raises_with_the_gateway_message() -> None:
    """A gateway ``{"error": ...}`` chunk after the stream opened raises instead of ending the stream quietly."""
    stream: list[dict[str, Any]] = [
        {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "Partial"}}]},
        {"error": {"message": "Upstream provider timed out", "code": 502}},
    ]
    with ScriptedHttpEndpoint([sse_reply(stream, named=False, done=True)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.CHAT_COMPLETIONS, model=_MODEL)
        with pytest.raises(ProviderError, match="502: Upstream provider timed out"):
            await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        await provider.disconnect()
