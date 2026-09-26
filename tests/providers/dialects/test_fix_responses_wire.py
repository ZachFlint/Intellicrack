# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Responses wire-format gates: reasoning replay, tool-search namespaces, stream failures.

Each test drives a real ConfigurableProvider against a loopback endpoint, so
request bodies are the ones the provider actually sends and replies are real
JSON bodies and real server-sent-event byte streams. Replayed items are
validated with the installed ``openai`` SDK's own models, which encode which
fields the API requires.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from openai.types.responses import ResponseFunctionToolCall, ResponseReasoningItem

from intellicrack.core.session import Session, SessionStore
from intellicrack.core.types import (
    Message,
    ProviderError,
    ReasoningItem,
    ReasoningKind,
    ThinkingConfig,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
    ToolResult,
)
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride, ToolSearchStyle, ToolSearchSupport
from tests._helpers.scripted_http_endpoint import ScriptedHttpEndpoint, json_reply, sse_reply
from tests.providers.dialects.wire_support import collect, connect_provider


if TYPE_CHECKING:
    from pathlib import Path


_MODEL = "gpt-5.5"
_TOOL_SEARCH_OVERRIDE = {_MODEL: CapabilityOverride(tool_search=ToolSearchSupport(style=ToolSearchStyle.OPENAI_TOOL_SEARCH))}


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


def _usage() -> dict[str, Any]:
    """Build a Responses usage object.

    Returns:
        dict[str, Any]: The usage object.
    """
    return {
        "input_tokens": 120,
        "input_tokens_details": {"cached_tokens": 20},
        "output_tokens": 30,
        "output_tokens_details": {"reasoning_tokens": 10},
        "total_tokens": 150,
    }


def _response(output: list[dict[str, Any]], *, status: str = "completed") -> dict[str, Any]:
    """Build a Responses response body.

    Args:
        output: The output items.
        status: The response status.

    Returns:
        dict[str, Any]: The body.
    """
    return {"id": "resp_1", "object": "response", "model": _MODEL, "status": status, "output": output, "usage": _usage()}


_TOOL_SEARCH_CALL: dict[str, Any] = {
    "type": "tool_search_call",
    "id": "tsc_1",
    "call_id": None,
    "execution": "server",
    "status": "completed",
    "arguments": {"query": "spawn a process"},
}
_TOOL_SEARCH_OUTPUT: dict[str, Any] = {
    "type": "tool_search_output",
    "id": "tso_1",
    "call_id": None,
    "execution": "server",
    "status": "completed",
    "tools": [
        {
            "type": "namespace",
            "name": "frida",
            "description": "Frida instrumentation",
            "tools": [{"type": "function", "name": "spawn", "defer_loading": True, "parameters": {"type": "object"}}],
        },
    ],
}
_NAMESPACED_CALL: dict[str, Any] = {
    "type": "function_call",
    "id": "fc_1",
    "call_id": "call_spawn",
    "name": "spawn",
    "namespace": "frida",
    "arguments": '{"target": "notepad.exe"}',
    "status": "completed",
}


@pytest.mark.asyncio
async def test_reasoning_request_asks_for_a_summary() -> None:
    """A reasoning request must ask for ``reasoning.summary``, or no readable reasoning comes back."""
    with ScriptedHttpEndpoint([json_reply(_response([]))]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL)
        await provider.chat(
            [Message(role="user", content="analyse")],
            _MODEL,
            thinking=ThinkingConfig(enabled=True, budget_tokens=8000),
        )
        await provider.disconnect()

    reasoning = endpoint.requests[0].body["reasoning"]
    assert reasoning["summary"] == "auto"
    assert reasoning["effort"]


@pytest.mark.asyncio
async def test_replayed_reasoning_item_carries_the_required_summary() -> None:
    """A reasoning item with no summary text is replayed with ``summary: []``, which the API requires."""
    first = _response([
        {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "opaque-body=="},
        {"type": "function_call", "id": "fc_0", "call_id": "call_d", "name": "ghidra__decompile", "arguments": "{}"},
    ])
    with ScriptedHttpEndpoint([json_reply(first), json_reply(_response([]))]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL)
        history = [Message(role="user", content="analyse")]
        assistant, calls = await provider.chat(history, _MODEL, tools=_tools())
        assert calls
        history += [
            assistant,
            Message(
                role="tool",
                content="",
                tool_results=[ToolResult(call_id="call_d", success=True, result="int main()", error=None, duration_ms=1.0)],
            ),
        ]
        await provider.chat(history, _MODEL, tools=_tools())
        await provider.disconnect()

    replayed = [item for item in endpoint.requests[1].body["input"] if item.get("type") == "reasoning"]
    assert len(replayed) == 1
    validated = ResponseReasoningItem.model_validate(replayed[0])
    assert validated.summary == []
    assert validated.encrypted_content == "opaque-body=="


@pytest.mark.asyncio
async def test_namespaced_call_resolves_and_replays_with_its_namespace() -> None:
    """A tool-search call named ``(frida, spawn)`` routes to ``frida.spawn`` and replays as that pair, search items included."""
    first = _response([_TOOL_SEARCH_CALL, _TOOL_SEARCH_OUTPUT, _NAMESPACED_CALL])
    with ScriptedHttpEndpoint([json_reply(first), json_reply(_response([]))]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        history = [Message(role="user", content="spawn notepad")]
        assistant, calls = await provider.chat(history, _MODEL, tools=_tools())
        assert calls is not None
        assert [(call.function_name, call.tool_name) for call in calls] == [("frida.spawn", "frida")]
        assert calls[0].arguments == {"target": "notepad.exe"}
        history += [
            assistant,
            Message(
                role="tool",
                content="",
                tool_results=[ToolResult(call_id="call_spawn", success=True, result="pid 42", error=None, duration_ms=1.0)],
            ),
        ]
        await provider.chat(history, _MODEL, tools=_tools())
        await provider.disconnect()

    replayed = endpoint.requests[1].body["input"]
    types = [item.get("type") for item in replayed]
    assert types[1:4] == ["tool_search_call", "tool_search_output", "function_call"]
    assert replayed[1] == _TOOL_SEARCH_CALL
    assert replayed[2] == _TOOL_SEARCH_OUTPUT
    call = ResponseFunctionToolCall.model_validate(replayed[3])
    assert (call.namespace, call.name, call.call_id) == ("frida", "spawn", "call_spawn")


@pytest.mark.asyncio
async def test_streamed_namespaced_call_resolves_to_its_canonical_name() -> None:
    """A streamed call announced with a namespace reassembles under its canonical dotted name."""
    added = {key: value for key, value in _NAMESPACED_CALL.items() if key != "arguments"}
    events: list[dict[str, Any]] = [
        {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}},
        {"type": "response.output_item.done", "output_index": 0, "item": _TOOL_SEARCH_CALL},
        {"type": "response.output_item.done", "output_index": 1, "item": _TOOL_SEARCH_OUTPUT},
        {"type": "response.output_item.added", "output_index": 2, "item": {**added, "arguments": ""}},
        {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 2, "delta": '{"target": '},
        {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 2, "delta": '"notepad.exe"}'},
        {"type": "response.output_item.done", "output_index": 2, "item": _NAMESPACED_CALL},
        {"type": "response.completed", "response": _response([_TOOL_SEARCH_CALL, _TOOL_SEARCH_OUTPUT, _NAMESPACED_CALL])},
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL, overrides=_TOOL_SEARCH_OVERRIDE)
        await collect(provider.chat_stream([Message(role="user", content="spawn notepad")], _MODEL, tools=_tools()))
        calls = provider.get_pending_tool_calls()
        reasoning = provider.get_pending_reasoning()
        await provider.disconnect()

    assert [(call.function_name, call.arguments) for call in calls] == [("frida.spawn", {"target": "notepad.exe"})]
    assert [item.payload for item in reasoning if item.kind is ReasoningKind.PROVIDER_ITEM] == [_TOOL_SEARCH_CALL, _TOOL_SEARCH_OUTPUT]


@pytest.mark.asyncio
async def test_response_failed_event_raises_with_the_endpoint_message() -> None:
    """``response.failed`` ends the stream as an error carrying the endpoint's code and message."""
    failed = _response([], status="failed")
    failed["error"] = {"code": "server_error", "message": "The model crashed mid-response"}
    events: list[dict[str, Any]] = [
        {"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}},
        {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "Partial"},
        {"type": "response.failed", "response": failed},
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL)
        with pytest.raises(ProviderError, match="server_error: The model crashed mid-response"):
            await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        await provider.disconnect()


@pytest.mark.asyncio
async def test_error_event_raises_with_the_endpoint_message() -> None:
    """A bare ``error`` event ends the stream as an error rather than as a silent completion."""
    events: list[dict[str, Any]] = [
        {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "Partial"},
        {"type": "error", "code": "rate_limit_exceeded", "message": "Slow down", "param": None, "sequence_number": 2},
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL)
        with pytest.raises(ProviderError, match="rate_limit_exceeded: Slow down"):
            await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        await provider.disconnect()


@pytest.mark.asyncio
async def test_response_incomplete_event_keeps_output_and_usage() -> None:
    """``response.incomplete`` is a truncated success: its text and usage survive and nothing raises."""
    incomplete = _response([], status="incomplete")
    incomplete["incomplete_details"] = {"reason": "max_output_tokens"}
    events: list[dict[str, Any]] = [
        {"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "Truncated answer"},
        {"type": "response.incomplete", "response": incomplete},
    ]
    with ScriptedHttpEndpoint([sse_reply(events)]) as endpoint:
        provider = await connect_provider(endpoint, ApiDialect.RESPONSES, model=_MODEL)
        text = await collect(provider.chat_stream([Message(role="user", content="go")], _MODEL))
        usage = provider.get_pending_usage()
        await provider.disconnect()

    assert text == "Truncated answer"
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.cache_read_tokens) == (120, 30, 20)


def test_provider_items_survive_a_session_round_trip(tmp_path: Path) -> None:
    """A tool-search provider item keeps its complete payload through a session save and load.

    Args:
        tmp_path: Per-test temporary directory holding the session database.
    """
    store = SessionStore(tmp_path / "sessions.db")
    session = Session.create("loopback-wire", _MODEL, "tool search replay")
    item = ReasoningItem(kind=ReasoningKind.PROVIDER_ITEM, item_id="tso_1", payload=dict(_TOOL_SEARCH_OUTPUT))
    session.add_message(Message(role="assistant", content="", reasoning=[item]))
    store.save(session)
    reloaded = store.load(session.id)

    assert reloaded is not None
    assert reloaded.messages[-1].reasoning == [item]
