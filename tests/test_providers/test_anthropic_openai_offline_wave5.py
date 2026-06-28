# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Offline falsifiable gates for Anthropic and OpenAI providers (wave 5).

Covers 8 NOT_RESOLVED findings from group-07-report.md:
  Anthropic: #11 disconnect, #12 chat response parsing, #13 chat_stream
             text accumulation, #14 cancel_request task abort,
             #15 _finalize_anthropic_stream
  OpenAI:    #16 connect 401 error path, #17 disconnect,
             #23 _infer_supports_vision

All tests are fully offline.  Anthropic gates use a real
``anthropic.AsyncAnthropic`` backed by an ``httpx.AsyncBaseTransport``
subclass so every SDK serialisation and deserialization layer runs without
substitution.  The #15 gate calls ``_finalize_anthropic_stream`` directly
via a duck-typed stream stub (the only method called is ``get_final_message``
which returns a real ``AnthropicMessage`` built from SDK types).  OpenAI
#16 injects a stub 401 transport via ``monkeypatch.setattr`` on the
``openai.AsyncOpenAI`` class so the full ``connect()`` path runs.  No
``MagicMock``, ``AsyncMock``, or ``unittest.mock.patch`` is used anywhere
in this module.

Finding #14 note: ``test_realcov_10_cancel_request.py`` gates ``_cancel_requested=True``
via a live stream.  That leaves the ``asyncio.Task.cancel()`` branch untested offline;
this module closes that gap with an explicit asyncio task.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast, override

import anthropic
import httpx
import openai
import pytest
from anthropic.types import (
    Message as AnthropicMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    Usage,
)

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ToolCall,
)
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.openai import OpenAIProvider


if TYPE_CHECKING:
    from anthropic.lib.streaming import AsyncMessageStream


# ---------------------------------------------------------------------------
# Private-attribute name constants — avoids SLF001 ruff rule on direct access
# ---------------------------------------------------------------------------

_CLIENT_ATTR: str = "_client"
_CANCEL_REQUESTED_ATTR: str = "_cancel_requested"
_CURRENT_TASK_ATTR: str = "_current_task"
_PENDING_TOOL_CALLS_ATTR: str = "_pending_tool_calls"
_PENDING_THINKING_ATTR: str = "_pending_thinking"
_FINALIZE_STREAM_ATTR: str = "_finalize_anthropic_stream"
_INFER_VISION_ATTR: str = "_infer_supports_vision"


# ---------------------------------------------------------------------------
# Anthropic SSE event helpers
# ---------------------------------------------------------------------------


def _anthropic_sse_event(event_type: str, payload: dict[str, Any]) -> str:
    r"""Encode a single Anthropic SSE event frame.

    Args:
        event_type: The SSE event-type label (e.g. ``"content_block_delta"``).
        payload: JSON-serializable payload for the ``data`` line.

    Returns:
        str: A complete ``event:\ndata:\n\n`` SSE frame string.
    """
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"


def _make_text_sse_body(texts: list[str], *, model: str = "claude-3-5-sonnet-20241022") -> bytes:
    """Build Anthropic SSE bytes emitting a sequence of text deltas.

    Produces a minimal but complete Anthropic streaming event sequence:
    ``message_start``, ``content_block_start``, one ``content_block_delta``
    per element of ``texts``, ``content_block_stop``, ``message_delta``,
    and ``message_stop``.

    Args:
        texts: Text fragment strings to emit as ``text_delta`` events.
        model: Model identifier embedded in the ``message_start`` event.

    Returns:
        bytes: UTF-8 encoded SSE body suitable for an HTTP
        ``text/event-stream`` response intercepted by the Anthropic SDK.
    """
    events: list[str] = [
        _anthropic_sse_event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_s01",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": model,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 0},
                },
            },
        ),
        _anthropic_sse_event(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        ),
    ]
    events.extend(
        _anthropic_sse_event(
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        )
        for text in texts
    )
    events.extend(
        [
            _anthropic_sse_event("content_block_stop", {"type": "content_block_stop", "index": 0}),
            _anthropic_sse_event(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": len(texts)},
                },
            ),
            _anthropic_sse_event("message_stop", {"type": "message_stop"}),
        ],
    )
    return "".join(events).encode()


def _make_text_tool_sse_body(
    *,
    text: str,
    tool_id: str,
    tool_name: str,
    tool_args: dict[str, str],
    model: str = "claude-3-7-sonnet-20250219",
) -> bytes:
    """Build Anthropic SSE bytes with a text block then a tool_use block.

    Constructs a streaming response where the text block is index 0
    (yielded by ``text_stream``) and the tool_use block is index 1
    (captured in ``get_final_message()``).

    Args:
        text: Text content to emit in the text block.
        tool_id: Unique identifier for the tool call.
        tool_name: Function name for the tool call (may include a ``.`` separator).
        tool_args: Arguments dict serialised as a single ``input_json_delta``.
        model: Model identifier embedded in the ``message_start`` event.

    Returns:
        bytes: UTF-8 encoded SSE body with text and tool_use blocks.
    """
    events: list[str] = [
        _anthropic_sse_event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_fin01",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": model,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 0},
                },
            },
        ),
        _anthropic_sse_event(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        ),
        _anthropic_sse_event(
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        ),
        _anthropic_sse_event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _anthropic_sse_event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": tool_id, "name": tool_name, "input": {}},
            },
        ),
        _anthropic_sse_event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": json.dumps(tool_args)},
            },
        ),
        _anthropic_sse_event("content_block_stop", {"type": "content_block_stop", "index": 1}),
        _anthropic_sse_event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 5},
            },
        ),
        _anthropic_sse_event("message_stop", {"type": "message_stop"}),
    ]
    return "".join(events).encode()


# ---------------------------------------------------------------------------
# Stub httpx transports for Anthropic API seam
# ---------------------------------------------------------------------------


class _AnthropicJSONTransport(httpx.AsyncBaseTransport):
    """Replay a canned JSON response for every Anthropic API request.

    Attributes:
        body: The pre-serialised JSON bytes returned as the response body.
    """

    body: bytes

    def __init__(self, body: bytes) -> None:
        """Store the JSON body to replay on every request.

        Args:
            body: Pre-serialised JSON bytes to return as the HTTP response body.
        """
        self.body = body

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Return a 200 JSON response with the pre-built body.

        Args:
            request: Inbound HTTP request from the Anthropic SDK.

        Returns:
            httpx.Response: 200 OK with ``content-type: application/json``.
        """
        return httpx.Response(
            200,
            content=self.body,
            headers={"content-type": "application/json"},
            request=request,
        )


class _AnthropicSSETransport(httpx.AsyncBaseTransport):
    """Replay a canned SSE body for every Anthropic streaming request.

    Attributes:
        body: The pre-encoded SSE bytes returned as the response body.
    """

    body: bytes

    def __init__(self, body: bytes) -> None:
        """Store the SSE bytes to replay on every request.

        Args:
            body: Pre-encoded SSE bytes to return as the HTTP response body.
        """
        self.body = body

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Return a 200 SSE response with the pre-built SSE bytes.

        Args:
            request: Inbound HTTP request from the Anthropic SDK.

        Returns:
            httpx.Response: 200 OK with ``content-type: text/event-stream``.
        """
        return httpx.Response(
            200,
            content=self.body,
            headers={"content-type": "text/event-stream"},
            request=request,
        )


def _anthropic_provider_with_transport(transport: httpx.AsyncBaseTransport) -> AnthropicProvider:
    """Construct a pre-connected ``AnthropicProvider`` backed by a stub transport.

    Args:
        transport: The stub transport injected into the Anthropic SDK client.

    Returns:
        AnthropicProvider: A provider with ``connected=True`` and ``_client``
        pointing to a real ``anthropic.AsyncAnthropic`` that routes all HTTP
        traffic through ``transport``.
    """
    provider = AnthropicProvider()
    sdk_client = anthropic.AsyncAnthropic(
        api_key="offline-test-key",
        http_client=httpx.AsyncClient(transport=transport),
    )
    setattr(provider, _CLIENT_ATTR, sdk_client)
    provider.connected = True
    return provider


# ---------------------------------------------------------------------------
# #11 — AnthropicProvider.disconnect (offline seam)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_disconnect_clears_client_and_connected_flag() -> None:
    """disconnect() must set is_connected=False and release _client to None.

    Pure offline seam: sets ``provider.connected=True`` and injects a real
    ``anthropic.AsyncAnthropic`` client without making any network calls, then
    asserts both state mutations after ``disconnect()``.

    Oracle: the documented post-disconnect state — ``is_connected is False``
    and ``_client is None`` — independent of the production implementation.
    Mutation caught: removing ``self._client = None`` from ``disconnect()``
    leaves ``_client`` non-None, failing the second assertion.
    """
    provider = AnthropicProvider()
    provider.connected = True
    setattr(provider, _CLIENT_ATTR, anthropic.AsyncAnthropic(api_key="offline-key"))

    assert provider.is_connected is True
    assert getattr(provider, _CLIENT_ATTR) is not None

    await provider.disconnect()

    assert provider.is_connected is False
    assert getattr(provider, _CLIENT_ATTR) is None


# ---------------------------------------------------------------------------
# #12 — AnthropicProvider.chat response parsing via stub transport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_chat_text_response_parsed_via_stub_transport() -> None:
    """chat() correctly parses a text-only Anthropic JSON response body.

    Drives the full ``chat()`` -> ``_make_anthropic_api_call()`` -> real
    Anthropic SDK -> stub httpx transport path with a canned non-streaming
    JSON body.  Asserts the returned ``Message`` carries the exact content
    string and that no tool calls were produced.

    Oracle: the literal ``"text"`` value embedded in the canned JSON body.
    Mutation caught: replacing ``content += block.text`` in
    ``_parse_response_blocks`` with ``content = ""`` makes the returned
    message content an empty string.
    """
    canned_body: dict[str, Any] = {
        "id": "msg_chat_01",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Binary analysis complete."}],
        "model": "claude-3-5-sonnet-20241022",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }
    provider = _anthropic_provider_with_transport(_AnthropicJSONTransport(json.dumps(canned_body).encode()))

    message, tool_calls = await provider.chat(
        messages=[Message(role="user", content="Analyse the binary.")],
        model="claude-3-5-sonnet-20241022",
        max_tokens=256,
    )

    assert message.content == "Binary analysis complete."
    assert tool_calls is None


@pytest.mark.asyncio
async def test_anthropic_chat_thinking_response_sets_thinking_content() -> None:
    """chat() with a ThinkingBlock in the response sets message.thinking_content.

    Drives ``chat()`` with a JSON response containing a thinking block followed
    by a text block.  Asserts that ``message.thinking_content`` equals the
    thinking text and ``message.content`` equals the text block.

    Oracle: literal string values in the canned JSON body.
    Mutation caught: removing the ``isinstance(block, ThinkingBlock)`` branch
    in ``_parse_response_blocks`` leaves ``thinking_text`` empty so
    ``_await_anthropic_chat`` does not set ``thinking_content``, failing the
    assertion.
    """
    canned_body: dict[str, Any] = {
        "id": "msg_chat_02",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "thinking", "thinking": "I should decompile first.", "signature": "sig001"},
            {"type": "text", "text": "The function is a decryption stub."},
        ],
        "model": "claude-3-7-sonnet-20250219",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 15, "output_tokens": 8},
    }
    provider = _anthropic_provider_with_transport(_AnthropicJSONTransport(json.dumps(canned_body).encode()))

    message, _tool_calls = await provider.chat(
        messages=[Message(role="user", content="Describe this function.")],
        model="claude-3-7-sonnet-20250219",
        max_tokens=512,
    )

    assert message.content == "The function is a decryption stub."
    assert message.thinking_content == "I should decompile first."


# ---------------------------------------------------------------------------
# #13 — AnthropicProvider.chat_stream text accumulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_chat_stream_text_accumulation() -> None:
    """chat_stream() yields exact text fragments in order from SSE text_delta events.

    Drives ``chat_stream()`` through a stub Anthropic SSE transport that emits
    three known text fragments as ``text_delta`` events.  Asserts the collected
    chunks equal the expected list in the exact order emitted.

    Oracle: the text strings embedded as constants in the stub SSE body.
    Mutation caught: removing ``yield text`` from ``_iter_anthropic_stream``
    yields no chunks, failing the equality assertion.
    """
    expected: list[str] = ["Hello", " from", " Anthropic"]
    provider = _anthropic_provider_with_transport(_AnthropicSSETransport(_make_text_sse_body(expected)))

    collected: list[str] = [
        chunk
        async for chunk in provider.chat_stream(
            messages=[Message(role="user", content="Say hello.")],
            model="claude-3-5-sonnet-20241022",
            max_tokens=64,
        )
    ]

    assert collected == expected


# ---------------------------------------------------------------------------
# #14 — AnthropicProvider.cancel_request aborts the in-flight asyncio task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anthropic_cancel_request_cancels_current_task() -> None:
    """cancel_request() must call cancel() on the non-done _current_task.

    ``test_realcov_10_cancel_request.py`` gates ``_cancel_requested=True``
    via a live stream but does not exercise the ``asyncio.Task.cancel()``
    branch (``_current_task`` is not set during ``chat_stream()``).  This
    offline gate plants a real asyncio Task that never completes, calls
    ``cancel_request()``, and verifies both the flag and the task state.

    Oracle: ``asyncio.Task.cancelled()`` is True after the event loop
    processes the ``CancelledError`` — an asyncio-guaranteed invariant
    independent of Intellicrack code.
    Mutation caught: removing ``self._current_task.cancel()`` from
    ``cancel_request()`` leaves the task running so ``task.cancelled()``
    is False.
    """
    provider = AnthropicProvider()
    provider.connected = True

    async def _sleep_forever() -> None:
        await asyncio.sleep(9999)

    task: asyncio.Task[None] = asyncio.create_task(_sleep_forever())
    await asyncio.sleep(0)

    setattr(provider, _CURRENT_TASK_ATTR, task)

    await provider.cancel_request()

    assert getattr(provider, _CANCEL_REQUESTED_ATTR) is True

    await asyncio.gather(task, return_exceptions=True)

    assert task.cancelled(), "cancel_request() must cancel the in-flight asyncio task"


# ---------------------------------------------------------------------------
# #15 — _finalize_anthropic_stream populates tool calls and thinking
# ---------------------------------------------------------------------------


class _StubAnthropicStream:
    """Duck-typed substitute for ``AsyncMessageStream.get_final_message``.

    Supplies a pre-built ``AnthropicMessage`` so ``_finalize_anthropic_stream``
    can be called without a live Anthropic SDK streaming session.  Only
    ``get_final_message`` is called by the production code, so no other
    stream methods need to be implemented.
    """

    _message: AnthropicMessage

    def __init__(self, message: AnthropicMessage) -> None:
        """Store the message returned from ``get_final_message``.

        Args:
            message: The ``AnthropicMessage`` to return.
        """
        self._message = message

    async def get_final_message(self) -> AnthropicMessage:
        """Return the pre-built message.

        Returns:
            AnthropicMessage: The stored message instance.
        """
        return self._message


@pytest.mark.asyncio
async def test_anthropic_finalize_stream_populates_tool_calls_and_thinking() -> None:
    """_finalize_anthropic_stream captures ToolCalls and thinking from the final message.

    Builds a real ``AnthropicMessage`` with a ``ThinkingBlock``, ``TextBlock``,
    and ``ToolUseBlock``.  Passes it through a duck-typed stream stub and calls
    ``_finalize_anthropic_stream`` directly.  Asserts ``_pending_tool_calls``
    has the correct id/tool_name/function_name/arguments and that
    ``_pending_thinking`` has the expected thinking text.

    Oracle: literal field values supplied to the ``AnthropicMessage`` and
    block constructors (independent of the production code under test).
    Mutation caught: removing the ``if block.type == "tool_use":`` branch
    in ``_finalize_anthropic_stream`` leaves ``_pending_tool_calls`` empty.
    """
    final_msg = AnthropicMessage(
        id="msg_fin_stub",
        type="message",
        role="assistant",
        content=[
            ThinkingBlock(type="thinking", thinking="step by step analysis", signature="sig_f01"),
            TextBlock(type="text", text="I will call analyze."),
            ToolUseBlock(
                type="tool_use",
                id="toolu_f01",
                name="x64dbg.analyze",
                input={"address": "0x1400", "depth": 3},
            ),
        ],
        model="claude-3-7-sonnet-20250219",
        stop_reason="tool_use",
        stop_sequence=None,
        usage=Usage(input_tokens=12, output_tokens=8),
    )

    provider = AnthropicProvider()
    stub = _StubAnthropicStream(final_msg)
    finalize: Any = getattr(provider, _FINALIZE_STREAM_ATTR)
    await finalize(cast("AsyncMessageStream", stub))

    pending_tool_calls: list[ToolCall] = getattr(provider, _PENDING_TOOL_CALLS_ATTR)
    pending_thinking: list[str] = getattr(provider, _PENDING_THINKING_ATTR)

    assert len(pending_tool_calls) == 1
    tc = pending_tool_calls[0]
    assert tc.id == "toolu_f01"
    assert tc.function_name == "x64dbg.analyze"
    assert tc.tool_name == "x64dbg"
    assert tc.arguments == {"address": "0x1400", "depth": 3}
    assert pending_thinking == ["step by step analysis"]


@pytest.mark.asyncio
async def test_anthropic_finalize_stream_tool_call_via_sse_transport() -> None:
    """_finalize_anthropic_stream captures tool calls from a real SDK-parsed SSE stream.

    Drives the full ``chat_stream()`` -> ``_iter_anthropic_stream()`` ->
    ``_finalize_anthropic_stream()`` path with a stub SSE transport that emits
    a text block followed by a tool_use block.  After all text chunks are
    collected, ``_pending_tool_calls`` must carry the assembled tool call.

    Oracle: the ``tool_id`` and ``tool_name`` constants embedded in the SSE body.
    Mutation caught: removing the tool_use accumulation in
    ``_finalize_anthropic_stream`` leaves ``_pending_tool_calls`` empty
    while ``collected`` is unaffected.
    """
    sse_body = _make_text_tool_sse_body(
        text="I will analyze.",
        tool_id="toolu_sse01",
        tool_name="ghidra.decompile",
        tool_args={"address": "0x401000"},
    )
    provider = _anthropic_provider_with_transport(_AnthropicSSETransport(sse_body))

    collected: list[str] = [
        chunk
        async for chunk in provider.chat_stream(
            messages=[Message(role="user", content="Decompile this function.")],
            model="claude-3-7-sonnet-20250219",
            max_tokens=256,
        )
    ]

    pending_tool_calls: list[ToolCall] = getattr(provider, _PENDING_TOOL_CALLS_ATTR)

    assert collected == ["I will analyze."]
    assert len(pending_tool_calls) == 1
    tc = pending_tool_calls[0]
    assert tc.id == "toolu_sse01"
    assert tc.function_name == "ghidra.decompile"
    assert tc.tool_name == "ghidra"
    assert tc.arguments == {"address": "0x401000"}


# ---------------------------------------------------------------------------
# #16 — OpenAIProvider.connect 401 error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_connect_401_raises_authentication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """connect() with an invalid key must raise AuthenticationError and stay disconnected.

    Injects a stub httpx transport returning HTTP 401 into the
    ``openai.AsyncOpenAI`` constructor via ``monkeypatch.setattr``.  The
    real ``connect()`` path — key guard, client creation, ``models.list()``
    call, exception catch and re-raise — runs without substitution.

    Oracle: ``openai.AuthenticationError`` is the documented SDK exception
    on 401; ``connect()`` must map it to ``AuthenticationError`` matching
    the ``_ERR_INVALID_KEY`` template ``"Invalid OpenAI API key"`` and leave
    ``is_connected`` False with ``client`` released to None.
    Mutation caught: removing the ``raise AuthenticationError(...)`` line
    in the ``except openai.AuthenticationError`` block propagates the raw
    SDK exception, which is not our ``AuthenticationError``, failing
    ``pytest.raises``.
    """

    class _UnauthorizedTransport(httpx.AsyncBaseTransport):
        @override
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                content=json.dumps(
                    {
                        "error": {
                            "message": "Incorrect API key provided",
                            "type": "invalid_request_error",
                            "param": None,
                            "code": "invalid_api_key",
                        },
                    },
                ).encode(),
                headers={"content-type": "application/json"},
                request=request,
            )

    real_cls = openai.AsyncOpenAI
    stub_transport = _UnauthorizedTransport()

    def _patched_openai(**kwargs: object) -> openai.AsyncOpenAI:
        kwargs["http_client"] = httpx.AsyncClient(transport=stub_transport)
        return real_cls(**cast("Any", kwargs))

    monkeypatch.setattr(openai, "AsyncOpenAI", _patched_openai)

    provider = OpenAIProvider()
    creds = ProviderCredentials(api_key="invalid-test-key-offline")

    with pytest.raises(AuthenticationError, match=r"Invalid OpenAI API key"):
        await provider.connect(creds)

    assert provider.is_connected is False
    assert provider.client is None


# ---------------------------------------------------------------------------
# #17 — OpenAIProvider.disconnect (offline seam)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_openai_disconnect_clears_client_and_connected_flag() -> None:
    """disconnect() must set is_connected=False and release client to None.

    Offline mirror of the Grok offline disconnect seam (group-07 row 40):
    manually sets ``provider.connected=True`` and injects a real
    ``openai.AsyncOpenAI`` client, then calls ``disconnect()`` and asserts
    both state mutations without any network activity.

    Oracle: documented post-disconnect invariants — ``is_connected is False``
    and ``client is None``.
    Mutation caught: removing ``self.client = None`` from ``disconnect()``
    leaves ``client`` non-None after the call.
    """
    provider = OpenAIProvider()
    provider.connected = True
    provider.client = openai.AsyncOpenAI(api_key="offline-test-key")

    assert provider.is_connected is True
    assert provider.client is not None

    await provider.disconnect()

    assert provider.is_connected is False
    assert provider.client is None


# ---------------------------------------------------------------------------
# #23 — OpenAIProvider._infer_supports_vision (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("gpt-4o", True),
        ("gpt-4o-mini", True),
        ("gpt-3.5-turbo", False),
        ("gpt-4-vision-preview", True),
        ("gpt-4-turbo", True),
        ("gpt-4.1", True),
        ("o1-mini", True),
        ("gpt-3.5-turbo-instruct", False),
        ("gpt-4-0613", False),
    ],
)
def test_openai_infer_supports_vision_parametrized(model_id: str, *, expected: bool) -> None:
    """_infer_supports_vision returns the documented boolean for each model family.

    Oracle: OpenAI model-capability documentation.  Vision support is defined
    by prefix matching (``gpt-4o``, ``o1``, ``o3``, ``o4``, ``gpt-4-turbo``,
    ``gpt-4.1``, ``gpt-4.5``) or the literal substring ``"vision"`` in the
    model id.  The expected values are independent, pre-known constants —
    not derived from the production code itself.

    Mutation caught: removing the ``"gpt-4o"`` prefix from the
    ``startswith`` tuple makes ``gpt-4o`` and ``gpt-4o-mini`` return
    ``False``, failing both corresponding assertions.

    Args:
        model_id: The OpenAI model identifier to evaluate.
        expected: The expected boolean per OpenAI documentation.
    """
    infer_vision: Any = getattr(OpenAIProvider, _INFER_VISION_ATTR)
    result: bool = infer_vision(model_id)
    assert result is expected
