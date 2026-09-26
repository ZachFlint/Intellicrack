# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Streaming over the OpenAI Responses API through the real ``openai`` SDK.

Every test connects a real :class:`OpenAIProvider` -- and so a real
``openai.AsyncOpenAI`` client -- to a loopback HTTP server that answers
``POST /v1/responses`` with genuine Responses ``text/event-stream`` bytes. The
SDK decodes those bytes into its typed stream events, and the assertions read
what the provider made of them: visible text, reasoning, tool calls, usage,
and the typed error a failure surfaces as.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ReasoningKind,
    ThinkingConfig,
)
from intellicrack.providers.openai import OpenAIProvider
from tests._helpers.scripted_http_server import ScriptedHTTPServer, ScriptedResponse, json_response, sse_response


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


_MODEL: Final[str] = "gpt-5.2"
_KEY_PREFIX: Final[str] = "sk-proj-"
_KEY_BODY: Final[str] = "loopbackResponsesKey0123456789"
_API_KEY: Final[str] = _KEY_PREFIX + _KEY_BODY
_MODELS_PATH: Final[str] = "/v1/models"
_RESPONSES_PATH: Final[str] = "/v1/responses"


def _response_object(status: str, *, usage: Mapping[str, object] | None = None, **extra: object) -> dict[str, Any]:
    """Build the ``response`` object a Responses lifecycle event carries.

    Args:
        status: The response status.
        usage: The usage block, or ``None`` to omit it.
        **extra: Further fields to set on the response object.

    Returns:
        dict[str, Any]: The response object.
    """
    response: dict[str, Any] = {
        "id": "resp_loopback",
        "object": "response",
        "created_at": 1_760_000_000,
        "model": _MODEL,
        "status": status,
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    }
    if usage is not None:
        response["usage"] = usage
    response.update(extra)
    return response


def _usage() -> dict[str, Any]:
    """Build a Responses usage block.

    Returns:
        dict[str, Any]: Usage with cached and reasoning token details.
    """
    return {
        "input_tokens": 41,
        "input_tokens_details": {"cached_tokens": 7, "cache_write_tokens": 0},
        "output_tokens": 19,
        "output_tokens_details": {"reasoning_tokens": 5},
        "total_tokens": 60,
    }


def _full_turn_events() -> list[dict[str, Any]]:
    """Build the event sequence of one reasoning turn that calls a tool.

    Returns:
        list[dict[str, Any]]: Responses stream events in wire order.
    """
    reasoning_item = {
        "id": "rs_1",
        "type": "reasoning",
        "summary": [{"type": "summary_text", "text": "Plan the spawn."}],
        "encrypted_content": "gAAAA-encrypted-state",
    }
    return [
        {"type": "response.created", "sequence_number": 0, "response": _response_object("in_progress")},
        {
            "type": "response.output_item.added",
            "sequence_number": 1,
            "output_index": 0,
            "item": {"id": "rs_1", "type": "reasoning", "summary": []},
        },
        {
            "type": "response.reasoning_summary_text.delta",
            "sequence_number": 2,
            "item_id": "rs_1",
            "output_index": 0,
            "summary_index": 0,
            "delta": "Plan the spawn.",
        },
        {"type": "response.output_item.done", "sequence_number": 3, "output_index": 0, "item": reasoning_item},
        {
            "type": "response.output_item.added",
            "sequence_number": 4,
            "output_index": 1,
            "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []},
        },
        {
            "type": "response.output_text.delta",
            "sequence_number": 5,
            "item_id": "msg_1",
            "output_index": 1,
            "content_index": 0,
            "delta": "Spawning ",
            "logprobs": [],
        },
        {
            "type": "response.output_text.delta",
            "sequence_number": 6,
            "item_id": "msg_1",
            "output_index": 1,
            "content_index": 0,
            "delta": "now.",
            "logprobs": [],
        },
        {
            "type": "response.output_item.added",
            "sequence_number": 7,
            "output_index": 2,
            "item": {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_abc",
                "name": "frida__spawn",
                "arguments": "",
                "status": "in_progress",
            },
        },
        {
            "type": "response.function_call_arguments.delta",
            "sequence_number": 8,
            "item_id": "fc_1",
            "output_index": 2,
            "delta": '{"target": ',
        },
        {
            "type": "response.function_call_arguments.delta",
            "sequence_number": 9,
            "item_id": "fc_1",
            "output_index": 2,
            "delta": '"notepad.exe"}',
        },
        {"type": "response.completed", "sequence_number": 10, "response": _response_object("completed", usage=_usage())},
    ]


@pytest.fixture
def server_factory() -> Iterator[list[ScriptedHTTPServer]]:
    """Collect started servers and stop them after the test.

    Yields:
        list[ScriptedHTTPServer]: The list a test appends its servers to.
    """
    started: list[ScriptedHTTPServer] = []
    yield started
    for server in started:
        server.close()


def _start(started: list[ScriptedHTTPServer], responses: ScriptedResponse | Sequence[ScriptedResponse]) -> ScriptedHTTPServer:
    """Start a loopback server that lists one model and answers ``/responses``.

    Args:
        started: The fixture's list of servers to stop afterwards.
        responses: What ``POST /v1/responses`` answers with.

    Returns:
        ScriptedHTTPServer: The running server.
    """
    server = ScriptedHTTPServer({
        ("GET", _MODELS_PATH): json_response({
            "object": "list",
            "data": [{"id": _MODEL, "object": "model", "created": 0, "owned_by": "openai"}],
        }),
        ("POST", _RESPONSES_PATH): responses,
    })
    started.append(server)
    return server


async def _connected(server: ScriptedHTTPServer) -> OpenAIProvider:
    """Connect a real OpenAI provider to the loopback server.

    Args:
        server: The running loopback server.

    Returns:
        OpenAIProvider: The connected provider, whose SDK client retries
        nothing.
    """
    provider = OpenAIProvider()
    await provider.connect(ProviderCredentials(api_key=_API_KEY, api_base=f"{server.origin}/v1"))
    assert provider.client is not None
    provider.client = provider.client.with_options(max_retries=0)
    return provider


async def _drain(provider: OpenAIProvider, *, thinking: ThinkingConfig | None = None) -> list[str]:
    """Stream one turn to completion.

    Args:
        provider: The connected provider.
        thinking: Thinking configuration for the turn.

    Returns:
        list[str]: The text chunks yielded, in order.
    """
    return [
        chunk
        async for chunk in provider.chat_stream(
            [Message(role="user", content="spawn notepad")],
            _MODEL,
            thinking=thinking,
        )
    ]


@pytest.mark.asyncio
async def test_responses_stream_yields_text_tool_calls_reasoning_and_usage(server_factory: list[ScriptedHTTPServer]) -> None:
    """A streamed Responses turn surfaces every part the typed events carry."""
    server = _start(server_factory, sse_response(_full_turn_events()))
    provider = await _connected(server)

    chunks = await _drain(provider, thinking=ThinkingConfig(enabled=True, budget_tokens=8000))

    assert chunks == ["Spawning ", "now."]
    calls = provider.get_pending_tool_calls()
    assert [(call.id, call.function_name, call.arguments) for call in calls] == [("call_abc", "frida.spawn", {"target": "notepad.exe"})]
    usage = provider.get_pending_usage()
    assert usage is not None
    assert (usage.prompt_tokens, usage.completion_tokens, usage.total_tokens) == (41, 19, 60)
    assert (usage.cache_read_tokens, usage.reasoning_tokens) == (7, 5)
    reasoning = provider.get_pending_reasoning()
    assert len(reasoning) == 1
    assert reasoning[0].kind is ReasoningKind.RESPONSES_ITEM
    assert (reasoning[0].item_id, reasoning[0].encrypted_content, reasoning[0].summary) == (
        "rs_1",
        "gAAAA-encrypted-state",
        ("Plan the spawn.",),
    )
    assert provider.get_pending_thinking() == ["Plan the spawn."]
    sent = server.requests(_RESPONSES_PATH)[0].body
    assert sent["stream"] is True
    assert sent["model"] == _MODEL


@pytest.mark.asyncio
async def test_responses_stream_namespaced_call_resolves_to_canonical_name(server_factory: list[ScriptedHTTPServer]) -> None:
    """A tool-search namespaced call is rebuilt from its (namespace, name) pair."""
    events = [
        {
            "type": "response.output_item.added",
            "sequence_number": 0,
            "output_index": 0,
            "item": {"id": "fc_9", "type": "function_call", "call_id": "call_ns", "name": "attach", "namespace": "ghidra", "arguments": ""},
        },
        {"type": "response.function_call_arguments.delta", "sequence_number": 1, "item_id": "fc_9", "output_index": 0, "delta": "{}"},
        {"type": "response.completed", "sequence_number": 2, "response": _response_object("completed", usage=_usage())},
    ]
    provider = await _connected(_start(server_factory, sse_response(events)))

    assert await _drain(provider) == []
    assert [call.function_name for call in provider.get_pending_tool_calls()] == ["ghidra.attach"]


@pytest.mark.asyncio
async def test_responses_stream_failed_event_raises_provider_error(server_factory: list[ScriptedHTTPServer]) -> None:
    """``response.failed`` ends the turn with a provider error carrying its reason."""
    events = [
        {"type": "response.created", "sequence_number": 0, "response": _response_object("in_progress")},
        {
            "type": "response.failed",
            "sequence_number": 1,
            "response": _response_object("failed", error={"code": "server_error", "message": "upstream exploded"}),
        },
    ]
    provider = await _connected(_start(server_factory, sse_response(events)))

    with pytest.raises(ProviderError, match="upstream exploded"):
        await _drain(provider)


@pytest.mark.asyncio
async def test_responses_stream_error_event_raises_provider_error(server_factory: list[ScriptedHTTPServer]) -> None:
    """A stream-level ``error`` event surfaces as a provider error."""
    events = [{"type": "error", "sequence_number": 0, "code": "rate_limit_exceeded", "message": "slow down", "param": None}]
    provider = await _connected(_start(server_factory, sse_response(events)))

    with pytest.raises(ProviderError, match="slow down"):
        await _drain(provider)


@pytest.mark.asyncio
async def test_responses_stream_http_errors_are_translated(server_factory: list[ScriptedHTTPServer]) -> None:
    """HTTP failures on the Responses stream become Intellicrack typed errors, not raw SDK errors."""
    server = _start(
        server_factory,
        [
            json_response({"error": {"message": "bad key", "type": "invalid_request_error", "code": "invalid_api_key"}}, status=401),
            json_response({"error": {"message": "too many requests", "type": "requests", "code": "rate_limit_exceeded"}}, status=429),
            json_response({"error": {"message": "backend down", "type": "server_error", "code": None}}, status=500),
        ],
    )
    provider = await _connected(server)

    with pytest.raises(AuthenticationError, match="bad key"):
        await _drain(provider)
    with pytest.raises(RateLimitError, match="too many requests"):
        await _drain(provider)
    with pytest.raises(ProviderError, match="backend down") as excinfo:
        await _drain(provider)
    assert type(excinfo.value) is ProviderError


@pytest.mark.asyncio
async def test_responses_stream_error_text_is_redacted(server_factory: list[ScriptedHTTPServer]) -> None:
    """An error body that echoes the key is redacted before it reaches the exception."""
    echoed = f"Incorrect API key provided: {_API_KEY}. Authorization: Bearer {_API_KEY}"
    server = _start(server_factory, json_response({"error": {"message": echoed, "type": "invalid_request_error"}}, status=400))
    provider = await _connected(server)

    with pytest.raises(ProviderError) as excinfo:
        await _drain(provider)
    assert "Incorrect API key provided" in str(excinfo.value)
    assert _KEY_BODY not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)
