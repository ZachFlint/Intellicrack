# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable offline gates for OpenAI provider offline transforms.

Wave-2d audit remediation for section-09-cloud-providers.md.

Covers four operations that had NO or FAKE offline coverage:

* ``_is_chat_model`` — table-driven against OpenAI's published model-type list.
* ``_infer_context_window`` — exact context-window integers from OpenAI docs.
* ``_iter_openai_stream`` — real SSE frames fed through the real SDK parsing
  layer; asserts exact accumulated text and tool-call structures.
* ``_open_openai_stream`` — parameter-dispatch correctness captured from
  the HTTP request body (``max_completion_tokens`` vs ``max_tokens``,
  ``temperature=1.0`` forced for o-series, tools forwarded).

``_translate_openai_errors`` is *already* gated in
``test_openai_format_helpers.py`` with REAL assertions (auth, rate-limit,
quota, transport, passthrough, unrelated propagation).  It is omitted here
to avoid duplication.

All tests are fully offline.  The seam is a real
``httpx.AsyncBaseTransport`` subclass that feeds pre-built SSE bytes
into the real ``openai.AsyncOpenAI`` SDK so every deserialisation and
parsing layer executes without substitution.  No ``MagicMock`` or
``AsyncMock`` is used anywhere in this module.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any, override

import httpx
import openai
import pytest

from intellicrack.core.types import ProviderError
from intellicrack.providers.openai import OpenAIProvider


if TYPE_CHECKING:
    from intellicrack.providers.base import UsageInfo


_IS_CHAT_MODEL_ATTR: str = "_is_chat_model"
_INFER_CTX_ATTR: str = "_infer_context_window"
_ITER_STREAM_ATTR: str = "_iter_openai_stream"
_OPEN_STREAM_ATTR: str = "_open_openai_stream"
_PENDING_USAGE_ATTR: str = "_pending_usage"
_PENDING_TOOL_CALLS_ATTR: str = "_pending_tool_calls"
_CANCEL_REQUESTED_ATTR: str = "_cancel_requested"

_is_chat_model: Any = getattr(OpenAIProvider, _IS_CHAT_MODEL_ATTR)
_infer_context_window: Any = getattr(OpenAIProvider, _INFER_CTX_ATTR)


def _build_sdk_client(transport: httpx.AsyncBaseTransport) -> openai.AsyncOpenAI:
    """Construct a real ``openai.AsyncOpenAI`` backed by a stub transport.

    Args:
        transport: The ``httpx.AsyncBaseTransport`` that intercepts every
            HTTP request the SDK would otherwise send to the network.

    Returns:
        openai.AsyncOpenAI: A fully initialised async SDK client that
        routes all traffic through ``transport``.
    """
    return openai.AsyncOpenAI(
        api_key="offline-test-key",
        http_client=httpx.AsyncClient(transport=transport),
    )


def _make_provider_with_client(transport: httpx.AsyncBaseTransport) -> OpenAIProvider:
    """Return a pre-connected ``OpenAIProvider`` backed by a stub transport.

    Args:
        transport: The stub transport injected into the SDK client.

    Returns:
        OpenAIProvider: A provider whose ``client`` attribute points to a real
        ``openai.AsyncOpenAI`` object that will call ``transport`` instead of
        the network, and whose ``connected`` flag is ``True``.
    """
    provider = OpenAIProvider()
    provider.client = _build_sdk_client(transport)
    provider.connected = True
    return provider


def _sse_bytes(chunks: list[dict[str, object]], *, include_done: bool = True) -> bytes:
    """Serialise a list of chunk dicts into an SSE-framed byte string.

    The OpenAI SDK's SSE parser expects lines starting with ``data: ``
    followed by a JSON object and a blank line, terminated by
    ``data: [DONE]``.

    Args:
        chunks: List of raw dictionaries matching the
            ``chat.completion.chunk`` object shape.
        include_done: When ``True`` (the default), append the
            ``data: [DONE]`` terminator that signals end-of-stream.

    Returns:
        bytes: UTF-8 encoded SSE body suitable for an HTTP response.
    """
    lines = [f"data: {json.dumps(chunk)}\n\n" for chunk in chunks]
    if include_done:
        lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def _text_chunk(content: str, *, model: str = "gpt-4o", chunk_id: str = "chatcmpl-test") -> dict[str, object]:
    """Build a single text-delta SSE chunk dict.

    Args:
        content: Text content for the delta.
        model: OpenAI model identifier embedded in the chunk.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: A dict matching the ``chat.completion.chunk`` shape
        with ``choices[0].delta.content`` set to ``content``.
    """
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None}],
    }


def _tool_start_chunk(
    *,
    call_id: str,
    function_name: str,
    model: str = "gpt-4o",
    chunk_id: str = "chatcmpl-tc",
) -> dict[str, object]:
    """Build the first tool-call delta chunk (carries ``id`` and ``name``).

    Args:
        call_id: The tool call identifier issued by the model.
        function_name: Name of the function the model wants to call.
        model: OpenAI model identifier.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: First SSE chunk for a streaming tool call.
    """
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": call_id,
                            "type": "function",
                            "function": {"name": function_name, "arguments": ""},
                        },
                    ],
                },
                "finish_reason": None,
            },
        ],
    }


def _tool_args_chunk(
    arguments: str,
    *,
    model: str = "gpt-4o",
    chunk_id: str = "chatcmpl-tc",
) -> dict[str, object]:
    """Build a tool-call argument-fragment delta chunk.

    Args:
        arguments: Partial JSON argument string to append.
        model: OpenAI model identifier.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: An SSE chunk carrying a partial ``arguments``
        string for index 0 of the in-progress tool call.
    """
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"tool_calls": [{"index": 0, "function": {"arguments": arguments}}]},
                "finish_reason": None,
            },
        ],
    }


def _finish_chunk(
    *,
    finish_reason: str = "stop",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
    model: str = "gpt-4o",
    chunk_id: str = "chatcmpl-test",
) -> dict[str, object]:
    """Build a finish-signal chunk that carries usage statistics.

    Args:
        finish_reason: The ``finish_reason`` value (``"stop"``,
            ``"tool_calls"``, etc.).
        prompt_tokens: Prompt token count for the ``usage`` field.
        completion_tokens: Completion token count.
        total_tokens: Total token count; ``0`` exercises the fallback
            sum path inside ``_build_usage_from_openai_chunk``.
        model: OpenAI model identifier.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: A final SSE chunk marking end-of-stream with
        usage statistics.
    """
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        },
    }


class _StaticSSETransport(httpx.AsyncBaseTransport):
    """Replay a pre-built SSE body for every incoming request."""

    def __init__(self, body: bytes) -> None:
        """Initialise with the SSE bytes to replay.

        Sets ``self.body`` to the raw SSE bytes replayed on every request
        and ``self.last_request_body`` to the JSON-decoded inbound payload
        captured on the first call.

        Args:
            body: Pre-encoded SSE body.
        """
        self.body: bytes = body
        self.last_request_body: dict[str, object] = {}

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Capture the request body and replay the pre-built SSE bytes.

        Args:
            request: The inbound HTTP request from the SDK.

        Returns:
            httpx.Response: A 200 response with the fixed SSE body and
            ``content-type: text/event-stream``.
        """
        if request.content:
            self.last_request_body = json.loads(request.content)
        return httpx.Response(
            200,
            content=self.body,
            headers={"content-type": "text/event-stream"},
            request=request,
        )


async def _collect_stream(
    provider: OpenAIProvider,
    *,
    model: str = "gpt-4o",
    openai_messages: list[dict[str, object]] | None = None,
    openai_tools: list[dict[str, object]] | None = None,
) -> list[str]:
    """Drive ``_iter_openai_stream`` and return all yielded text chunks.

    Args:
        provider: A pre-connected provider instance.
        model: Model identifier to pass to the stream.
        openai_messages: Messages in OpenAI wire format.
        openai_tools: Tools in OpenAI wire format, or ``None``.

    Returns:
        list[str]: All text chunks yielded by ``_iter_openai_stream``.
    """
    if openai_messages is None:
        openai_messages = [{"role": "user", "content": "hello"}]

    method: Any = getattr(provider, _ITER_STREAM_ATTR)
    return [
        chunk
        async for chunk in method(
            model=model,
            openai_messages=openai_messages,
            temperature=0.7,
            max_tokens=256,
            openai_tools=openai_tools,
            tool_choice_value=None,
            reasoning_effort=None,
        )
    ]


class TestIsChatModel:
    """Table-driven gates for ``OpenAIProvider._is_chat_model``.

    Oracle: OpenAI public documentation on model types.
    A model is a chat model when it does NOT start with any of the
    non-chat prefixes listed in ``_is_chat_model``.
    """

    @pytest.mark.parametrize(
        "model_id",
        [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-4-turbo-preview",
            "gpt-4-0613",
            "gpt-3.5-turbo",
            "o1",
            "o1-mini",
            "o3",
            "o3-mini",
            "o4-mini",
            "gpt-4.1",
            "gpt-4.5",
        ],
    )
    def test_chat_models_return_true(self, model_id: str) -> None:
        """Chat-capable model IDs must return ``True``.

        Mutation caught: ``_is_chat_model`` returning ``False`` for a
        real model ID (e.g. swapping the ``not`` logic in the return
        statement) would fail this assertion.

        Args:
            model_id: A model identifier known to be chat-capable.
        """
        assert _is_chat_model(model_id) is True

    @pytest.mark.parametrize(
        "model_id",
        [
            "text-embedding-3-small",
            "text-embedding-3-large",
            "text-embedding-ada-002",
            "dall-e-3",
            "dall-e-2",
            "whisper-1",
            "tts-1",
            "tts-1-hd",
            "text-moderation-latest",
            "text-moderation-stable",
            "davinci-002",
            "babbage-002",
            "text-davinci-003",
            "text-babbage-001",
            "text-curie-001",
            "text-ada-001",
            "code-davinci-002",
            "code-cushman-001",
        ],
    )
    def test_non_chat_models_return_false(self, model_id: str) -> None:
        """Non-chat model IDs (embedding, image, audio, completion) must return ``False``.

        Mutation caught: removing any prefix from the ``non_chat_prefixes``
        tuple would cause the corresponding model ID to incorrectly return
        ``True``.

        Args:
            model_id: A model identifier known to be non-chat (embedding,
                image-generation, audio, or legacy-completion).
        """
        assert _is_chat_model(model_id) is False


class TestInferContextWindow:
    """Table-driven gates for ``OpenAIProvider._infer_context_window``.

    Oracle: OpenAI public platform documentation at
    https://platform.openai.com/docs/models for each named model.
    All expected values are integers documented by OpenAI.
    """

    @pytest.mark.parametrize(
        ("model_id", "expected"),
        [
            ("gpt-4o", 128000),
            ("gpt-4o-mini", 128000),
            ("gpt-4o-2024-11-20", 128000),
            ("gpt-4-turbo", 128000),
            ("gpt-4-turbo-preview", 128000),
            ("gpt-4.1", 128000),
            ("gpt-4.1-mini", 128000),
            ("gpt-4.5", 128000),
            ("gpt-3.5-turbo", 16385),
            ("gpt-3.5-turbo-0125", 16385),
            ("o1", 200000),
            ("o1-mini", 200000),
            ("o1-preview", 200000),
            ("o3", 200000),
            ("o3-mini", 200000),
            ("o4-mini", 200000),
        ],
    )
    def test_known_model_exact_context_window(self, model_id: str, expected: int) -> None:
        """Exact context-window integers must match the OpenAI published spec.

        Mutation caught: returning the wrong constant (e.g. 128000 for an
        o-series model that should return 200000, or 16385 for gpt-4o that
        should return 128000).

        Args:
            model_id: An OpenAI model identifier.
            expected: The documented context-window size in tokens.
        """
        assert _infer_context_window(model_id) == expected

    def test_unknown_model_returns_128000_default(self) -> None:
        """Unrecognised model IDs fall back to the 128k default.

        OpenAI's newest models all have at least 128k context;
        defaulting to 128000 for unknown models is intentional.

        Mutation caught: changing the default branch to return a different
        value (e.g. 4096) would break this gate.
        """
        assert _infer_context_window("totally-unknown-model-xyz") == 128000

    def test_gpt4_base_dated_variant_returns_8192(self) -> None:
        """``gpt-4-0613`` (base gpt-4 with date suffix) maps to 8192.

        The ``gpt-4-`` prefix rule catches ``gpt-4-0613`` and similar
        dated variants that are not turbo, returning 8192 per the
        OpenAI docs (base GPT-4 has an 8k context window).

        Mutation caught: a ``startswith`` check omitting the trailing hyphen
        would also match ``gpt-4o`` models, incorrectly returning 8192
        instead of 128000 for them.
        """
        assert _infer_context_window("gpt-4-0613") == 8192


class TestIterOpenAIStreamTextAccumulation:
    """Gate: ``_iter_openai_stream`` accumulates text delta chunks correctly.

    Drives the real method through a real ``openai.AsyncOpenAI`` client
    backed by a stub ``httpx.AsyncBaseTransport`` that returns pre-built
    SSE frames.  Asserts the exact list of text chunks yielded and the
    exact ``UsageInfo`` stored on the provider.
    """

    @pytest.mark.asyncio
    async def test_two_text_deltas_accumulated_in_order(self) -> None:
        """Two consecutive text deltas are yielded in order.

        Mutation caught: reversing the accumulation order or
        returning a single merged string instead of individual deltas
        would violate the ``["Hello", " world"]`` assertion.
        """
        body = _sse_bytes([
            _text_chunk("Hello"),
            _text_chunk(" world"),
            _finish_chunk(prompt_tokens=10, completion_tokens=2, total_tokens=12),
        ])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        chunks = await _collect_stream(provider)

        assert chunks == ["Hello", " world"]

    @pytest.mark.asyncio
    async def test_empty_stream_yields_no_chunks(self) -> None:
        """A stream with only a finish chunk yields no text.

        Mutation caught: mistakenly yielding the finish ``delta`` (which
        has no ``content``) would produce a spurious empty string.
        """
        body = _sse_bytes([_finish_chunk(prompt_tokens=5, completion_tokens=0, total_tokens=5)])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        chunks = await _collect_stream(provider)

        assert chunks == []

    @pytest.mark.asyncio
    async def test_usage_populated_from_finish_chunk(self) -> None:
        """Usage statistics from the final SSE chunk populate ``_pending_usage``.

        Oracle: ``stream_options: {include_usage: True}`` is set by
        ``_open_openai_stream``; the SDK then includes a ``usage`` object
        on the last chunk.  The method must store those exact integers on
        ``provider._pending_usage``.

        Mutation caught: storing ``None`` usage or swapping prompt/
        completion fields would fail the field-level assertions.
        """
        body = _sse_bytes([
            _text_chunk("Hi"),
            _finish_chunk(prompt_tokens=17, completion_tokens=3, total_tokens=20),
        ])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        await _collect_stream(provider)

        usage: UsageInfo | None = getattr(provider, _PENDING_USAGE_ATTR)
        assert usage is not None
        assert usage.prompt_tokens == 17
        assert usage.completion_tokens == 3
        assert usage.total_tokens == 20


class TestIterOpenAIStreamToolCallAccumulation:
    """Gate: ``_iter_openai_stream`` reassembles streamed tool calls via ToolCallBufferManager.

    The tool call arrives in three deltas: (1) id+name, (2) first arg fragment,
    (3) second arg fragment.  The method must yield no text and, after the
    stream is exhausted, store a single fully-parsed ``ToolCall`` on
    ``_pending_tool_calls``.
    """

    @pytest.mark.asyncio
    async def test_tool_call_id_and_name_exact(self) -> None:
        """Streamed tool-call id and function_name are preserved exactly.

        Mutation caught: ``ToolCallBufferManager.accumulate`` reading
        ``id`` from the wrong delta index would produce an empty id,
        causing the tool call to be discarded by ``finalize``.
        """
        body = _sse_bytes([
            _tool_start_chunk(call_id="call_abc123", function_name="get_weather"),
            _tool_args_chunk('{"city": "London"}'),
            _finish_chunk(finish_reason="tool_calls", prompt_tokens=20, completion_tokens=15, total_tokens=35),
        ])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        chunks = await _collect_stream(provider)

        assert chunks == [], "tool-call stream must yield no text"
        tool_calls: list[Any] = getattr(provider, _PENDING_TOOL_CALLS_ATTR)
        assert len(tool_calls) == 1
        tc = tool_calls[0]
        assert tc.id == "call_abc123"
        assert tc.function_name == "get_weather"
        assert tc.tool_name == "get_weather"

    @pytest.mark.asyncio
    async def test_tool_call_arguments_reassembled_from_fragments(self) -> None:
        """Argument fragments arriving across multiple deltas are joined correctly.

        Oracle: ``{"cmd": "ls -la"}`` = first fragment ``{"cmd":`` + second
        fragment `` "ls -la"}``.  The ``ToolCallBufferManager`` joins them by
        string concatenation; the resulting JSON must parse to the exact dict.

        Mutation caught: truncating the argument at the first fragment
        (``{"cmd":``) would produce a ``JSONDecodeError`` and yield an
        empty ``arguments`` dict instead of ``{"cmd": "ls -la"}``.
        """
        body = _sse_bytes([
            _tool_start_chunk(call_id="call_xyz", function_name="run_command"),
            _tool_args_chunk('{"cmd":'),
            _tool_args_chunk(' "ls -la"}'),
            _finish_chunk(finish_reason="tool_calls", prompt_tokens=15, completion_tokens=10, total_tokens=25),
        ])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        await _collect_stream(provider)

        tool_calls_2: list[Any] = getattr(provider, _PENDING_TOOL_CALLS_ATTR)
        assert len(tool_calls_2) == 1
        assert tool_calls_2[0].arguments == {"cmd": "ls -la"}

    @pytest.mark.asyncio
    async def test_two_parallel_tool_calls_both_accumulated(self) -> None:
        """Two parallel tool-call deltas (index 0 and index 1) both survive.

        The ``ToolCallBufferManager`` uses the ``index`` field as the key.
        Having two distinct indices must produce two ``ToolCall`` objects
        in the correct order.

        Mutation caught: using a fixed ``index=0`` instead of the delta's
        ``index`` would collapse both calls into one.
        """
        tc_start: dict[str, object] = {
            "id": "chatcmpl-tc2",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {"index": 0, "id": "call_first", "type": "function", "function": {"name": "alpha", "arguments": ""}},
                            {"index": 1, "id": "call_second", "type": "function", "function": {"name": "beta", "arguments": ""}},
                        ],
                    },
                    "finish_reason": None,
                },
            ],
        }
        tc_args: dict[str, object] = {
            "id": "chatcmpl-tc2",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": "gpt-4o",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {"index": 0, "function": {"arguments": '{"x":1}'}},
                            {"index": 1, "function": {"arguments": '{"y":2}'}},
                        ],
                    },
                    "finish_reason": None,
                },
            ],
        }
        body = _sse_bytes([tc_start, tc_args, _finish_chunk(finish_reason="tool_calls")])
        transport = _StaticSSETransport(body)
        provider = _make_provider_with_client(transport)

        await _collect_stream(provider)

        tool_calls_parallel: list[Any] = getattr(provider, _PENDING_TOOL_CALLS_ATTR)
        assert len(tool_calls_parallel) == 2
        names = {tc.function_name for tc in tool_calls_parallel}
        assert names == {"alpha", "beta"}
        args_by_name = {tc.function_name: tc.arguments for tc in tool_calls_parallel}
        assert args_by_name["alpha"] == {"x": 1}
        assert args_by_name["beta"] == {"y": 2}

    @pytest.mark.asyncio
    async def test_cancel_flag_stops_iteration_before_all_chunks(self) -> None:
        """Setting ``_cancel_requested`` before streaming stops chunk consumption.

        The transport sets ``_cancel_requested`` before any chunk is read.
        The gate asserts that fewer than three chunks are collected (the
        iteration breaks at the first ``if self._cancel_requested: break``).

        Mutation caught: removing the cancel guard in ``_iter_openai_stream``
        would yield all three chunks.
        """
        body = _sse_bytes([
            _text_chunk("chunk1"),
            _text_chunk("chunk2"),
            _text_chunk("chunk3"),
            _finish_chunk(),
        ])

        class _CancelOnFirstRequest(httpx.AsyncBaseTransport):
            def __init__(self, inner_body: bytes, provider_ref: OpenAIProvider) -> None:
                self._body = inner_body
                self._provider = provider_ref

            @override
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                setattr(self._provider, _CANCEL_REQUESTED_ATTR, True)
                return httpx.Response(
                    200,
                    content=self._body,
                    headers={"content-type": "text/event-stream"},
                    request=request,
                )

        provider = OpenAIProvider()
        provider.connected = True
        provider.client = openai.AsyncOpenAI(
            api_key="offline-test-key",
            http_client=httpx.AsyncClient(transport=_CancelOnFirstRequest(body, provider)),
        )

        chunks = await _collect_stream(provider)
        assert len(chunks) < 3


class TestOpenOpenAIStreamParamDispatch:
    """Gate: ``_open_openai_stream`` routes parameters correctly to the HTTP layer.

    The real ``openai.AsyncOpenAI`` client serialises the request arguments
    into a JSON body that the ``httpx.AsyncBaseTransport`` intercepts.
    Asserting against the captured body verifies which branch of the 16-path
    dispatch tree was taken without mocking the function under test.
    """

    @pytest.mark.asyncio
    async def test_non_o_series_uses_max_tokens_not_max_completion_tokens(self) -> None:
        """Non-o-series models receive ``max_tokens``, not ``max_completion_tokens``.

        OpenAI documents ``max_tokens`` as the parameter for all GPT-4o
        and GPT-3.5 models; ``max_completion_tokens`` is reserved for
        o-series reasoning models.

        Mutation caught: always using ``max_completion_tokens`` regardless
        of model would fail the ``"max_tokens" in body`` assertion.
        """
        body_bytes = _sse_bytes([_text_chunk("ok"), _finish_chunk()])
        transport = _StaticSSETransport(body_bytes)
        provider = _make_provider_with_client(transport)

        method: Any = getattr(provider, _OPEN_STREAM_ATTR)
        stream = await method(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hi"}],
            temperature=0.7,
            max_tokens=512,
            tools=None,
            tool_choice=None,
            reasoning_effort=None,
        )
        async for _ in stream:
            pass

        body = transport.last_request_body
        assert "max_tokens" in body
        assert "max_completion_tokens" not in body
        assert body["max_tokens"] == 512

    @pytest.mark.asyncio
    async def test_o_series_uses_max_completion_tokens_and_temp_1(self) -> None:
        """O-series models receive ``max_completion_tokens`` and ``temperature=1.0``.

        OpenAI requires ``max_completion_tokens`` for o1/o3/o4 models and
        forces ``temperature=1.0`` regardless of caller-supplied value.

        Mutation caught: keeping ``max_tokens`` for o-series or omitting
        the ``temperature=1.0`` override would fail either assertion.
        """
        body_bytes = _sse_bytes([_text_chunk("reasoning"), _finish_chunk()])
        transport = _StaticSSETransport(body_bytes)
        provider = _make_provider_with_client(transport)

        method: Any = getattr(provider, _OPEN_STREAM_ATTR)
        stream = await method(
            model="o4-mini",
            messages=[{"role": "user", "content": "think"}],
            temperature=0.3,
            max_tokens=1024,
            tools=None,
            tool_choice=None,
            reasoning_effort=None,
        )
        async for _ in stream:
            pass

        body = transport.last_request_body
        assert "max_completion_tokens" in body, "o-series must use max_completion_tokens"
        assert "max_tokens" not in body, "o-series must not send max_tokens"
        assert body["max_completion_tokens"] == 1024
        assert body["temperature"] == pytest.approx(1.0), "o-series temperature must be pinned to 1.0"

    @pytest.mark.asyncio
    async def test_tools_forwarded_when_provided(self) -> None:
        """When ``tools`` is non-empty the HTTP body includes a ``tools`` key.

        Mutation caught: an early return before the ``tools=tools`` branch
        would send the request without tools, silently losing function-calling
        capability.
        """
        body_bytes = _sse_bytes([_finish_chunk()])
        transport = _StaticSSETransport(body_bytes)
        provider = _make_provider_with_client(transport)

        fake_tools: list[dict[str, object]] = [
            {
                "type": "function",
                "function": {
                    "name": "get_info",
                    "description": "Gets info.",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
        ]

        method: Any = getattr(provider, _OPEN_STREAM_ATTR)
        stream = await method(
            model="gpt-4o",
            messages=[{"role": "user", "content": "info"}],
            temperature=0.5,
            max_tokens=128,
            tools=fake_tools,
            tool_choice=None,
            reasoning_effort=None,
        )
        async for _ in stream:
            pass

        body = transport.last_request_body
        assert "tools" in body
        assert '"get_info"' in json.dumps(body["tools"])

    @pytest.mark.asyncio
    async def test_not_connected_raises_provider_error(self) -> None:
        """Calling ``_open_openai_stream`` without a client raises :class:`ProviderError`.

        Mutation caught: removing the ``if self.client is None`` guard
        would raise ``AttributeError`` on ``NoneType`` instead of the
        typed :class:`ProviderError`.
        """
        provider = OpenAIProvider()
        provider.connected = False
        provider.client = None

        method: Any = getattr(provider, _OPEN_STREAM_ATTR)
        with pytest.raises(ProviderError, match="Not connected"):
            await method(
                model="gpt-4o",
                messages=[{"role": "user", "content": "hi"}],
                temperature=0.7,
                max_tokens=64,
                tools=None,
                tool_choice=None,
                reasoning_effort=None,
            )
