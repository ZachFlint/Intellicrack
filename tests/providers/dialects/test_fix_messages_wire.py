# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Anthropic Messages wire-format gates: usage, server tool replay, pause_turn, errors, headers.

Each test drives a real ConfigurableProvider against a loopback endpoint that
answers with real Messages JSON bodies and real server-sent-event byte
streams. Replayed server tool blocks are validated with the installed
``anthropic`` SDK's own models.
"""

from __future__ import annotations

from typing import Any, Final

import pytest
from anthropic.types import ServerToolUseBlock, ToolSearchToolResultBlock

from intellicrack.core.types import Message, ProviderError, ReasoningKind, ToolDefinition, ToolFunction, ToolParameter, ToolResult
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.dialects.messages import ANTHROPIC_VERSION, MessagesAdapter
from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint, json_reply, sse_reply
from tests.providers.dialects.wire_support import TEST_API_KEY, collect, connect_provider


_MODEL: Final[str] = "claude-opus-5-5"
_TOOL_SEARCH_OVERRIDE: Final[dict[str, CapabilityOverride]] = {
    _MODEL: CapabilityOverride(tool_search=MessagesAdapter.tool_search_capabilities()),
}

_SERVER_TOOL_USE: Final[dict[str, Any]] = {
    "type": "server_tool_use",
    "id": "srvtoolu_01ABC123",
    "name": "tool_search_tool_regex",
    "input": {"pattern": "spawn", "limit": 5},
}
_TOOL_SEARCH_RESULT: Final[dict[str, Any]] = {
    "type": "tool_search_tool_result",
    "tool_use_id": "srvtoolu_01ABC123",
    "content": {
        "type": "tool_search_tool_search_result",
        "tool_references": [{"type": "tool_reference", "tool_name": "frida__spawn"}],
    },
}
_CLIENT_TOOL_USE: Final[dict[str, Any]] = {
    "type": "tool_use",
    "id": "toolu_01XYZ789",
    "name": "frida__spawn",
    "input": {"target": "notepad.exe"},
}


def _tools() -> list[ToolDefinition]:
    """Build two bridge tools, the second of which tool search defers.

    Returns:
        list[ToolDefinition]: ``ghidra`` then ``frida``.
    """
    target = ToolParameter(name="target", type="string", description="What to act on")
    return [
        ToolDefinition(
            tool_name="ghidra",
            description="Ghidra decompiler",
            functions=[ToolFunction(name="ghidra.decompile", description="Decompile a function", parameters=[target], returns="C")],
        ),
        ToolDefinition(
            tool_name="frida",
            description="Frida instrumentation",
            functions=[ToolFunction(name="frida.spawn", description="Spawn a process", parameters=[target], returns="pid")],
        ),
    ]


def _message(content: list[dict[str, Any]], stop_reason: str) -> dict[str, Any]:
    """Build a Messages response body.

    Args:
        content: The content blocks.
        stop_reason: The stop reason.

    Returns:
        dict[str, Any]: The body.
    """
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": _MODEL,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 50, "output_tokens": 10},
    }


def _message_start(usage: dict[str, Any]) -> dict[str, Any]:
    """Build a ``message_start`` event.

    Args:
        usage: The usage the event carries.

    Returns:
        dict[str, Any]: The event.
    """
    return {
        "type": "message_start",
        "message": {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": _MODEL,
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": usage,
        },
    }


def _text_events(index: int, text: str) -> list[dict[str, Any]]:
    """Build the events of one streamed text block.

    Args:
        index: The block index.
        text: The block text.

    Returns:
        list[dict[str, Any]]: Start, one delta, stop.
    """
    return [
        {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": index},
    ]


def _server_search_events(start: int) -> list[dict[str, Any]]:
    """Build the events of a streamed tool search, input arriving in fragments.

    Args:
        start: The index of the ``server_tool_use`` block.

    Returns:
        list[dict[str, Any]]: The call block's events, then the result block's.
    """
    opened: dict[str, Any] = {**_SERVER_TOOL_USE, "input": {}}
    return [
        {"type": "content_block_start", "index": start, "content_block": opened},
        {"type": "content_block_delta", "index": start, "delta": {"type": "input_json_delta", "partial_json": '{"pattern": "spa'}},
        {"type": "content_block_delta", "index": start, "delta": {"type": "input_json_delta", "partial_json": 'wn", "limit": 5}'}},
        {"type": "content_block_stop", "index": start},
        {"type": "content_block_start", "index": start + 1, "content_block": _TOOL_SEARCH_RESULT},
        {"type": "content_block_stop", "index": start + 1},
    ]


def _message_end(stop_reason: str, output_tokens: int) -> list[dict[str, Any]]:
    """Build the closing ``message_delta`` and ``message_stop`` events.

    Args:
        stop_reason: The stop reason.
        output_tokens: The cumulative output-token count.

    Returns:
        list[dict[str, Any]]: The two events.
    """
    return [
        {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None}, "usage": {"output_tokens": output_tokens}},
        {"type": "message_stop"},
    ]


@pytest.mark.asyncio
async def test_streamed_usage_merges_message_start_input_and_cache_tokens() -> None:
    """Input and cache tokens arrive only on ``message_start``; output tokens on ``message_delta``."""
    start_usage = {"input_tokens": 500, "cache_read_input_tokens": 300, "cache_creation_input_tokens": 40, "output_tokens": 1}
    events: list[dict[str, Any]] = [_message_start(start_usage), *_text_events(0, "Done."), *_message_end("end_turn", 77)]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL)
        text = await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        usage = provider.get_pending_usage()
        await provider.disconnect()

    assert text == "Done."
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.cache_read_tokens, usage.cache_creation_tokens) == (500, 77, 300, 40)
    assert usage.total_tokens == 577


@pytest.mark.asyncio
async def test_server_tool_blocks_are_replayed_verbatim_and_in_order() -> None:
    """The ``server_tool_use`` and ``tool_search_tool_result`` blocks go back unchanged, ahead of the client ``tool_use``."""
    first = _message([{"type": "text", "text": "Searching."}, _SERVER_TOOL_USE, _TOOL_SEARCH_RESULT, _CLIENT_TOOL_USE], "tool_use")
    with ScriptedHttpEndpoint([json_reply(first), json_reply(_message([{"type": "text", "text": "ok"}], "end_turn"))]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        history = [Message(role="user", content="spawn notepad")]
        assistant, calls = await provider.chat(history, _MODEL, tools=_tools())
        assert calls is not None
        assert [call.function_name for call in calls] == ["frida.spawn"]
        history += [
            assistant,
            Message(
                role="tool",
                content="",
                tool_results=[ToolResult(call_id="toolu_01XYZ789", success=True, result="pid 42", error=None, duration_ms=1.0)],
            ),
        ]
        await provider.chat(history, _MODEL, tools=_tools())
        await provider.disconnect()

    replayed = endpoint.requests[1].body["messages"][1]
    assert replayed["role"] == "assistant"
    blocks = replayed["content"]
    assert [block["type"] for block in blocks] == ["server_tool_use", "tool_search_tool_result", "text", "tool_use"]
    assert blocks[0] == _SERVER_TOOL_USE
    assert blocks[1] == _TOOL_SEARCH_RESULT
    ServerToolUseBlock.model_validate(blocks[0])
    ToolSearchToolResultBlock.model_validate(blocks[1])
    results = endpoint.requests[1].body["messages"][2]["content"]
    assert [result["tool_use_id"] for result in results] == ["toolu_01XYZ789"]


@pytest.mark.asyncio
async def test_streamed_server_tool_blocks_are_captured_with_their_input() -> None:
    """A streamed tool search is captured as two provider items, its streamed input reassembled, and yields no tool call."""
    events: list[dict[str, Any]] = [
        _message_start({"input_tokens": 40, "output_tokens": 1}),
        *_server_search_events(0),
        {"type": "content_block_start", "index": 2, "content_block": {**_CLIENT_TOOL_USE, "input": {}}},
        {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": '{"target": "notepad.exe"}'}},
        {"type": "content_block_stop", "index": 2},
        *_message_end("tool_use", 20),
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        await collect(provider.chat_stream([Message(role="user", content="spawn notepad")], _MODEL, tools=_tools()))
        calls = provider.get_pending_tool_calls()
        reasoning = provider.get_pending_reasoning()
        await provider.disconnect()

    assert [(call.id, call.function_name, call.arguments) for call in calls] == [
        ("toolu_01XYZ789", "frida.spawn", {"target": "notepad.exe"}),
    ]
    provider_items = [item.payload for item in reasoning if item.kind is ReasoningKind.PROVIDER_ITEM]
    assert provider_items == [_SERVER_TOOL_USE, _TOOL_SEARCH_RESULT]


@pytest.mark.asyncio
async def test_pause_turn_is_resent_and_the_turn_completes() -> None:
    """``pause_turn`` resends the partial turn, server blocks included, and the call returns the finished turn."""
    paused = _message([{"type": "text", "text": "Looking. "}, _SERVER_TOOL_USE, _TOOL_SEARCH_RESULT], "pause_turn")
    finished = _message([{"type": "text", "text": "Found it."}], "end_turn")
    with ScriptedHttpEndpoint([json_reply(paused), json_reply(finished)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        assistant, calls = await provider.chat([Message(role="user", content="find a spawner")], _MODEL, tools=_tools())
        usage = provider.get_pending_usage()
        await provider.disconnect()

    assert len(endpoint.requests) == 2
    resent = endpoint.requests[1].body["messages"]
    assert [message["role"] for message in resent] == ["user", "assistant"]
    assert [block["type"] for block in resent[1]["content"]] == ["server_tool_use", "tool_search_tool_result", "text"]
    assert assistant.content == "Looking. Found it."
    assert calls is None
    assert assistant.reasoning is not None
    assert [item.payload for item in assistant.reasoning] == [_SERVER_TOOL_USE, _TOOL_SEARCH_RESULT]
    assert usage is not None
    assert usage.prompt_tokens == 100


@pytest.mark.asyncio
async def test_streamed_pause_turn_is_resent_and_streams_the_continuation() -> None:
    """A streamed ``pause_turn`` resends the partial turn and streams the continuation as the same response."""
    paused = [_message_start({"input_tokens": 40, "output_tokens": 1}), *_text_events(0, "Looking. "), *_server_search_events(1)]
    paused += _message_end("pause_turn", 12)
    finished = [_message_start({"input_tokens": 60, "output_tokens": 1}), *_text_events(0, "Found it."), *_message_end("end_turn", 8)]
    with ScriptedHttpEndpoint([sse_reply(paused), sse_reply(finished)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        text = await collect(provider.chat_stream([Message(role="user", content="find a spawner")], _MODEL, tools=_tools()))
        usage = provider.get_pending_usage()
        await provider.disconnect()

    assert text == "Looking. Found it."
    assert len(endpoint.requests) == 2
    resent = endpoint.requests[1].body["messages"][-1]
    assert resent["role"] == "assistant"
    assert resent["content"][0] == _SERVER_TOOL_USE
    assert resent["content"][1] == _TOOL_SEARCH_RESULT
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens) == (100, 20)


@pytest.mark.asyncio
async def test_error_event_mid_stream_raises_with_the_endpoint_message() -> None:
    """An ``error`` event after the stream opened raises instead of ending as a silent completion."""
    events: list[dict[str, Any]] = [
        _message_start({"input_tokens": 40, "output_tokens": 1}),
        *_text_events(0, "Partial"),
        {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}},
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.MESSAGES, model=_MODEL)
        with pytest.raises(ProviderError, match="overloaded_error: Overloaded"):
            await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        await provider.disconnect()


@pytest.mark.asyncio
async def test_custom_auth_header_keeps_the_required_anthropic_version() -> None:
    """A gateway auth header replaces ``x-api-key`` but never the ``anthropic-version`` every request needs."""
    with ScriptedHttpEndpoint([json_reply(_message([{"type": "text", "text": "ok"}], "end_turn"))]) as endpoint:
        provider = await connect_provider(
            endpoint,
            ApiDialect.MESSAGES,
            model=_MODEL,
            headers={"Authorization": "Bearer ${apiKey}", "X-Gateway-Route": "claude"},
        )
        await provider.chat([Message(role="user", content="go")], _MODEL)
        await provider.disconnect()

    headers = endpoint.requests[0].headers
    assert headers["anthropic-version"] == ANTHROPIC_VERSION
    assert headers["authorization"] == f"Bearer {TEST_API_KEY}"
    assert headers["x-gateway-route"] == "claude"
    assert "x-api-key" not in headers
