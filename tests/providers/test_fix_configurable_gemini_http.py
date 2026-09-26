# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on the ConfigurableProvider HTTP layer and the Gemini dialect.

Every test drives the real :class:`~intellicrack.providers.configurable.ConfigurableProvider`
over a real loopback socket. The server writes the bytes the vendor services
put on the wire -- Gemini's ``alt=sse`` event stream and its pretty-printed
JSON array, Anthropic's named SSE events, the vendors' error bodies and
``Retry-After`` headers -- so each assertion is about what the provider does
with real traffic rather than with a stand-in.
"""

from __future__ import annotations

import asyncio
import base64
import email.utils
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from google.genai import types as genai_types

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ReasoningItem,
    ToolCall,
    ToolResult,
)
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.dialects.base import ToolNameStyle
from intellicrack.providers.dialects.gemini import GeminiAdapter
from intellicrack.providers.instances import ProviderInstance
from tests._helpers.scripted_http_server import (
    RecordedRequest,
    ScriptedHttpServer,
    ScriptedResponse,
    json_response,
    sse_response,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


_API_KEY = "loopback-test-key"
_GEMINI_MODEL = "gemini-2.5-flash"
_GEMINI_STREAM_PATH = f"/gemini/v1beta/models/{_GEMINI_MODEL}:streamGenerateContent"
_GEMINI_GENERATE_PATH = f"/gemini/v1beta/models/{_GEMINI_MODEL}:generateContent"
_GEMINI_MODELS_PATH = "/gemini/v1beta/models"
_ANTHROPIC_MESSAGES_PATH = "/anthropic/v1/messages"
_ANTHROPIC_MODELS_PATH = "/anthropic/v1/models"
_OPENAI_CHAT_PATH = "/openai/chat/completions"
_RAW_SIGNATURE = b"\x00\x01gemini-3-thought-signature\xff\xfe"
_ENCODED_SIGNATURE = base64.b64encode(_RAW_SIGNATURE).decode("ascii")


@pytest.fixture
def server() -> Iterator[ScriptedHttpServer]:
    """Run a scripted loopback HTTP server for one test.

    Yields:
        ScriptedHttpServer: The running server.
    """
    with ScriptedHttpServer() as running:
        yield running


async def _connect(
    server: ScriptedHttpServer,
    dialect: ApiDialect,
    prefix: str,
    *,
    extra_body: dict[str, Any] | None = None,
) -> ConfigurableProvider:
    """Build and connect a provider instance pointed at the loopback server.

    Args:
        server: The loopback server.
        dialect: The wire format the instance speaks.
        prefix: Path prefix the instance's base URL carries.
        extra_body: Body parameters merged into every request.

    Returns:
        ConfigurableProvider: The connected provider.
    """
    instance = ProviderInstance(
        instance_id=f"loopback-{dialect.value}",
        dialect=dialect,
        api_base=f"{server.origin}/{prefix}",
        extra_body=dict(extra_body or {}),
    )
    provider = ConfigurableProvider(instance)
    await provider.connect(ProviderCredentials(api_key=_API_KEY))
    return provider


def _gemini_chunk(parts: list[dict[str, Any]], *, finish: str | None = None, usage: bool = False) -> dict[str, Any]:
    """Build one Gemini ``GenerateContentResponse`` chunk.

    Args:
        parts: The candidate's content parts.
        finish: The candidate's finish reason, if this is the last chunk.
        usage: Whether to attach ``usageMetadata``.

    Returns:
        dict[str, Any]: The chunk.
    """
    candidate: dict[str, Any] = {"content": {"parts": parts, "role": "model"}, "index": 0}
    if finish is not None:
        candidate["finishReason"] = finish
    chunk: dict[str, Any] = {"candidates": [candidate], "modelVersion": _GEMINI_MODEL, "responseId": "resp-loopback"}
    if usage:
        chunk["usageMetadata"] = {"promptTokenCount": 11, "candidatesTokenCount": 7, "totalTokenCount": 18}
    return chunk


def _gemini_sse_bytes(chunks: list[dict[str, Any]]) -> list[bytes]:
    """Frame Gemini chunks exactly as ``streamGenerateContent?alt=sse`` does.

    Args:
        chunks: The response chunks.

    Returns:
        list[bytes]: One ``data:`` event per chunk, CRLF-terminated.
    """
    return [b"data: " + json.dumps(chunk, separators=(",", ":")).encode() + b"\r\n\r\n" for chunk in chunks]


def _gemini_json_array_bytes(chunks: list[dict[str, Any]]) -> bytes:
    """Render Gemini chunks as the pretty-printed JSON array sent without ``alt=sse``.

    Args:
        chunks: The response chunks.

    Returns:
        bytes: The array body.
    """
    return ("[" + ",\r\n".join(json.dumps(chunk, indent=2) for chunk in chunks) + "]").encode()


def _gemini_stream_route(chunks: list[dict[str, Any]]) -> Callable[[RecordedRequest], ScriptedResponse]:
    """Build a route handler answering like the real Gemini streaming endpoint.

    Args:
        chunks: The response chunks to stream.

    Returns:
        Callable[[RecordedRequest], ScriptedResponse]: Emits SSE only when the
        request asked for ``alt=sse``, and the JSON array otherwise.
    """

    def answer(request: RecordedRequest) -> ScriptedResponse:
        if request.query.get("alt") == ["sse"]:
            return sse_response(_gemini_sse_bytes(chunks))
        return ScriptedResponse(chunks=(_gemini_json_array_bytes(chunks),))

    return answer


def _anthropic_event(payload: dict[str, Any]) -> bytes:
    """Frame one Anthropic stream event as the Messages API sends it.

    Args:
        payload: The event payload; its ``type`` names the SSE event.

    Returns:
        bytes: The ``event:``/``data:`` frame.
    """
    return f"event: {payload['type']}\ndata: {json.dumps(payload)}\n\n".encode()


def _user(text: str = "summarize the import table") -> list[Message]:
    """Build a one-turn history.

    Args:
        text: The user's message.

    Returns:
        list[Message]: The history.
    """
    return [Message(role="user", content=text)]


async def _collect(provider: ConfigurableProvider, model: str, messages: list[Message] | None = None) -> str:
    """Drain one streamed turn.

    Args:
        provider: The connected provider.
        model: The model to stream from.
        messages: Conversation history, or a single user turn by default.

    Returns:
        str: The concatenated streamed text.
    """
    return "".join([chunk async for chunk in provider.chat_stream(messages or _user(), model)])


def _gemini_generate_ok(text: str) -> ScriptedResponse:
    """Build a successful non-streamed Gemini response.

    Args:
        text: The model's reply.

    Returns:
        ScriptedResponse: The response.
    """
    return json_response(200, _gemini_chunk([{"text": text}], finish="STOP", usage=True))


@pytest.mark.asyncio
async def test_gemini_stream_requests_sse_and_yields_text(server: ScriptedHttpServer) -> None:
    """Item 6: streaming asks for ``alt=sse`` and yields every text chunk."""
    chunks = [
        _gemini_chunk([{"text": "The binary imports "}]),
        _gemini_chunk([{"text": "kernel32.dll"}]),
        _gemini_chunk([{"text": " and user32.dll."}], finish="STOP", usage=True),
    ]
    server.script("POST", _GEMINI_STREAM_PATH, _gemini_stream_route(chunks))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        text = await _collect(provider, _GEMINI_MODEL)
        usage = provider.get_pending_usage()
    finally:
        await provider.disconnect()

    assert text == "The binary imports kernel32.dll and user32.dll."
    recorded = server.requests(_GEMINI_STREAM_PATH)
    assert len(recorded) == 1
    assert recorded[0].query.get("alt") == ["sse"]
    assert recorded[0].headers.get("x-goog-api-key") == _API_KEY
    assert usage is not None
    assert usage.total_tokens == 18


@pytest.mark.asyncio
async def test_sse_event_split_across_data_lines_is_joined(server: ScriptedHttpServer) -> None:
    """Item 6: an SSE event whose payload spans two ``data:`` lines still decodes."""
    chunk = json.dumps(_gemini_chunk([{"text": "multi-line event"}], finish="STOP"), indent=1)
    framed = "".join(f"data: {line}\r\n" for line in chunk.splitlines()) + "\r\n"
    server.script("POST", _GEMINI_STREAM_PATH, sse_response([framed.encode()]))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        text = await _collect(provider, _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert text == "multi-line event"


@pytest.mark.asyncio
async def test_stream_http_error_surfaces_body_not_stream_closed(server: ScriptedHttpServer) -> None:
    """Items 49 and 61: a failed stream raises the typed error with the body's detail."""
    error_body = {"error": {"code": 404, "message": "models/gemini-9 is not found for API version v1beta", "status": "NOT_FOUND"}}
    server.script("POST", _GEMINI_STREAM_PATH, json_response(404, error_body))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        with pytest.raises(ProviderError) as caught:
            _ = await _collect(provider, _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert type(caught.value) is ProviderError
    assert "is not found for API version v1beta" in str(caught.value)
    assert caught.value.status_code == 404


@pytest.mark.asyncio
async def test_stream_auth_error_carries_body_detail(server: ScriptedHttpServer) -> None:
    """Item 49: a 401 on a stream becomes AuthenticationError with the endpoint's explanation."""
    error_body = {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}
    server.script("POST", _ANTHROPIC_MESSAGES_PATH, json_response(401, error_body))
    provider = await _connect(server, ApiDialect.MESSAGES, "anthropic")
    try:
        with pytest.raises(AuthenticationError, match="invalid x-api-key"):
            _ = await _collect(provider, "claude-sonnet-5")
    finally:
        await provider.disconnect()


@pytest.mark.asyncio
async def test_non_stream_error_keeps_detail_for_every_status(server: ScriptedHttpServer) -> None:
    """Item 61: a 400 from ``chat`` and a 500 from ``list_models`` keep the body's detail."""
    bad_request = {"error": {"code": 400, "message": 'Invalid JSON payload received. Unknown name "foo"', "status": "INVALID_ARGUMENT"}}
    server.script("POST", _GEMINI_GENERATE_PATH, json_response(400, bad_request))
    server.script("GET", _GEMINI_MODELS_PATH, json_response(500, {"error": {"code": 500, "message": "backend exploded"}}))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        with pytest.raises(ProviderError) as chat_error:
            _ = await provider.chat(_user(), _GEMINI_MODEL)
        with pytest.raises(ProviderError) as list_error:
            _ = await provider.list_models()
    finally:
        await provider.disconnect()
    assert 'Unknown name \\"foo\\"' in str(chat_error.value)
    assert chat_error.value.status_code == 400
    assert "backend exploded" in str(list_error.value)
    assert list_error.value.status_code == 500


def _signed_history() -> list[Message]:
    """Build a history replaying a signed Gemini function call and its result.

    Returns:
        list[Message]: User turn, signed assistant call, tool result.
    """
    call = ToolCall(
        id="fc-1",
        tool_name="hex_editor",
        function_name="hex_editor.open_file",
        arguments={"path": "C:/target.exe"},
        thought_signature=_ENCODED_SIGNATURE,
    )
    return [
        Message(role="user", content="open the target"),
        Message(role="assistant", content="", tool_calls=[call]),
        Message(
            role="tool",
            content="",
            tool_results=[ToolResult(call_id="fc-1", success=True, result={"opened": True}, error=None, duration_ms=1.0)],
        ),
    ]


@pytest.mark.asyncio
async def test_thought_signature_replayed_as_base64_string(server: ScriptedHttpServer) -> None:
    """Item 51: a signed call is replayed over raw HTTP with its base64 signature."""
    server.script("POST", _GEMINI_GENERATE_PATH, _gemini_generate_ok("opened"))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        message, _ = await provider.chat(_signed_history(), _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert message.content == "opened"
    sent = server.requests(_GEMINI_GENERATE_PATH)[0].json_object()
    model_turn = sent["contents"][1]
    assert model_turn["role"] == "model"
    assert model_turn["parts"][0]["thought_signature"] == _ENCODED_SIGNATURE
    replayed = genai_types.Part.model_validate(model_turn["parts"][0])
    assert replayed.thought_signature == _RAW_SIGNATURE


def test_function_call_part_is_valid_for_google_genai() -> None:
    """Item 51: the shared part builder still yields the signature bytes through google-genai."""
    call = _signed_history()[1].tool_calls
    assert call is not None
    part = GeminiAdapter.build_function_call_part(call[0], name_style=ToolNameStyle.DOUBLE_UNDERSCORE)
    assert json.loads(json.dumps(part))["thought_signature"] == _ENCODED_SIGNATURE
    assert genai_types.Part.model_validate(part).thought_signature == _RAW_SIGNATURE


@pytest.mark.asyncio
async def test_unencodable_body_raises_provider_error(server: ScriptedHttpServer) -> None:
    """Item 51: a body JSON cannot represent raises ProviderError, not TypeError, and sends nothing."""
    provider = await _connect(server, ApiDialect.GEMINI, "gemini", extra_body={"labels": {"a", "b"}})
    try:
        with pytest.raises(ProviderError, match="cannot be encoded as JSON"):
            _ = await provider.chat(_user(), _GEMINI_MODEL)
        with pytest.raises(ProviderError, match="cannot be encoded as JSON"):
            _ = await _collect(provider, _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert server.requests() == []


@pytest.mark.asyncio
async def test_listed_gemini_model_id_is_not_doubled(server: ScriptedHttpServer) -> None:
    """Item 59: a model id taken from the listing reaches ``/v1beta/models/<id>`` once."""
    server.script(
        "GET",
        _GEMINI_MODELS_PATH,
        json_response(200, {"models": [{"name": f"models/{_GEMINI_MODEL}", "displayName": "Gemini 2.5 Flash"}]}),
    )
    server.script("POST", _GEMINI_GENERATE_PATH, _gemini_generate_ok("non-stream ok"))
    server.script("POST", _GEMINI_STREAM_PATH, _gemini_stream_route([_gemini_chunk([{"text": "stream ok"}], finish="STOP")]))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        models = await provider.list_models()
        listed_id = models[0].id
        message, _ = await provider.chat(_user(), listed_id)
        streamed = await _collect(provider, listed_id)
    finally:
        await provider.disconnect()
    assert listed_id == f"models/{_GEMINI_MODEL}"
    assert message.content == "non-stream ok"
    assert streamed == "stream ok"


@pytest.mark.asyncio
async def test_streamed_function_calls_keep_ids_and_signatures(server: ScriptedHttpServer) -> None:
    """Item 60: streamed calls use Gemini's id, never merge, never use the name, and keep signatures."""
    chunks = [
        _gemini_chunk([{"functionCall": {"name": "hex_editor__read", "args": {"offset": 0}}}]),
        _gemini_chunk([{"functionCall": {"name": "hex_editor__read", "args": {"offset": 512}}}]),
        _gemini_chunk(
            [{"functionCall": {"id": "fc-real-7", "name": "pe__imports", "args": {}}, "thoughtSignature": _ENCODED_SIGNATURE}],
            finish="STOP",
        ),
    ]
    server.script("POST", _GEMINI_STREAM_PATH, _gemini_stream_route(chunks))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        _ = await _collect(provider, _GEMINI_MODEL)
        calls = provider.get_pending_tool_calls()
    finally:
        await provider.disconnect()

    assert [call.function_name for call in calls] == ["hex_editor.read", "hex_editor.read", "pe.imports"]
    assert [call.arguments for call in calls] == [{"offset": 0}, {"offset": 512}, {}]
    assert calls[0].id != calls[1].id
    assert all(call.id not in {"hex_editor__read", "hex_editor.read"} for call in calls[:2])
    assert calls[2].id == "fc-real-7"
    assert calls[2].thought_signature == _ENCODED_SIGNATURE
    assert calls[0].thought_signature is None


@pytest.mark.asyncio
async def test_non_streamed_same_name_calls_get_distinct_ids(server: ScriptedHttpServer) -> None:
    """Item 60: two id-less calls to one function get distinct ids that are not the name."""
    body = _gemini_chunk(
        [
            {"functionCall": {"name": "hex_editor__read", "args": {"offset": 0}}},
            {"functionCall": {"name": "hex_editor__read", "args": {"offset": 64}}},
        ],
        finish="STOP",
    )
    server.script("POST", _GEMINI_GENERATE_PATH, json_response(200, body))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        _, calls = await provider.chat(_user(), _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert calls is not None
    assert len(calls) == 2
    assert calls[0].id != calls[1].id
    assert "hex_editor__read" not in {calls[0].id, calls[1].id}


def _openai_ok() -> ScriptedResponse:
    """Build a successful Chat Completions response.

    Returns:
        ScriptedResponse: The response.
    """
    return json_response(
        200,
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": "gpt-loopback",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "retried ok"}, "finish_reason": "stop"}],
        },
    )


def _rate_limited(headers: tuple[tuple[str, str], ...] = (), message: str = "Rate limit reached for requests") -> ScriptedResponse:
    """Build an OpenAI-shaped 429 response.

    Args:
        headers: Extra response headers, such as ``Retry-After``.
        message: The error message.

    Returns:
        ScriptedResponse: The response.
    """
    return json_response(429, {"error": {"message": message, "type": "requests", "code": "rate_limit_exceeded"}}, headers)


@pytest.mark.asyncio
async def test_retry_after_seconds_is_honoured(server: ScriptedHttpServer) -> None:
    """Item 62: ``Retry-After: 2`` delays the retry by two seconds, not the 1s backoff."""
    server.script("POST", _OPENAI_CHAT_PATH, _rate_limited((("retry-after", "2"),)), _openai_ok())
    provider = await _connect(server, ApiDialect.CHAT_COMPLETIONS, "openai")
    try:
        started = time.monotonic()
        message, _ = await provider.chat(_user(), "gpt-loopback")
        elapsed = time.monotonic() - started
    finally:
        await provider.disconnect()
    assert message.content == "retried ok"
    assert len(server.requests(_OPENAI_CHAT_PATH)) == 2
    assert elapsed >= 1.95


@pytest.mark.asyncio
async def test_retry_after_http_date_is_honoured(server: ScriptedHttpServer) -> None:
    """Item 62: an HTTP-date ``Retry-After`` delays the retry until that moment."""
    when = datetime.now(tz=UTC) + timedelta(seconds=3)
    header = email.utils.format_datetime(when, usegmt=True)
    server.script("POST", _OPENAI_CHAT_PATH, _rate_limited((("retry-after", header),)), _openai_ok())
    provider = await _connect(server, ApiDialect.CHAT_COMPLETIONS, "openai")
    try:
        started = time.monotonic()
        _ = await provider.chat(_user(), "gpt-loopback")
        elapsed = time.monotonic() - started
    finally:
        await provider.disconnect()
    assert len(server.requests(_OPENAI_CHAT_PATH)) == 2
    assert elapsed >= 1.8


@pytest.mark.asyncio
async def test_retry_after_beyond_limit_fails_fast(server: ScriptedHttpServer) -> None:
    """Item 62: a wait longer than the retry ceiling raises at once instead of hanging."""
    server.script("POST", _OPENAI_CHAT_PATH, _rate_limited((("retry-after", "3600"),)), _openai_ok())
    provider = await _connect(server, ApiDialect.CHAT_COMPLETIONS, "openai")
    try:
        with pytest.raises(RateLimitError) as caught:
            _ = await provider.chat(_user(), "gpt-loopback")
    finally:
        await provider.disconnect()
    assert caught.value.retry_after == pytest.approx(3600.0)
    assert len(server.requests(_OPENAI_CHAT_PATH)) == 1


@pytest.mark.asyncio
async def test_permanent_quota_error_is_not_retried(server: ScriptedHttpServer) -> None:
    """Item 62: a 429 reporting exhausted billing quota fails once, without retries."""
    exhausted = json_response(
        429,
        {
            "error": {
                "message": "You exceeded your current quota, please check your plan and billing details.",
                "code": "insufficient_quota",
            },
        },
    )
    server.script("POST", _OPENAI_CHAT_PATH, exhausted, _openai_ok())
    provider = await _connect(server, ApiDialect.CHAT_COMPLETIONS, "openai")
    try:
        with pytest.raises(ProviderError) as caught:
            _ = await provider.chat(_user(), "gpt-loopback")
    finally:
        await provider.disconnect()
    assert not isinstance(caught.value, RateLimitError)
    assert "insufficient_quota" in str(caught.value)
    assert len(server.requests(_OPENAI_CHAT_PATH)) == 1


@pytest.mark.asyncio
async def test_gemini_retry_info_marks_quota_429_transient(server: ScriptedHttpServer) -> None:
    """Item 62: Gemini's per-minute 429 carries ``RetryInfo`` and is retried after its delay.

    The failure is captured as a plain outcome string rather than left to
    propagate, because the package conftest turns any ``ProviderError``
    mentioning an exceeded quota into a skip meant for live-account limits.
    """
    per_minute = json_response(
        429,
        {
            "error": {
                "code": 429,
                "message": "You exceeded your current quota, please check your plan and billing details.",
                "status": "RESOURCE_EXHAUSTED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                        "violations": [{"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier"}],
                    },
                    {"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "1s"},
                ],
            },
        },
    )
    server.script("POST", _GEMINI_GENERATE_PATH, per_minute, _gemini_generate_ok("after retry"))
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        message, _ = await provider.chat(_user(), _GEMINI_MODEL)
        outcome = message.content
    except ProviderError as exc:
        outcome = f"raised {type(exc).__name__} with status {exc.status_code}"
    finally:
        await provider.disconnect()
    assert outcome == "after retry"
    assert len(server.requests(_GEMINI_GENERATE_PATH)) == 2


@pytest.mark.asyncio
async def test_rate_limited_stream_is_retried_before_any_text(server: ScriptedHttpServer) -> None:
    """Item 62: a stream rejected with 429 before any bytes is retried and then streams."""
    ok = _gemini_stream_route([_gemini_chunk([{"text": "streamed after retry"}], finish="STOP")])
    limited = json_response(
        429,
        {"error": {"code": 429, "message": "Resource has been exhausted", "status": "RESOURCE_EXHAUSTED"}},
        (("retry-after", "0"),),
    )
    server.script("POST", _GEMINI_STREAM_PATH, limited, ok)
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        text = await _collect(provider, _GEMINI_MODEL)
    finally:
        await provider.disconnect()
    assert text == "streamed after retry"
    assert len(server.requests(_GEMINI_STREAM_PATH)) == 2


def _thinking_stream(label: str, *, gates: dict[int, threading.Event], signals: dict[int, threading.Event]) -> ScriptedResponse:
    """Build an Anthropic stream with one signed thinking block, split in two chunks.

    Args:
        label: Distinguishes this stream's thinking text and signature.
        gates: Chunk gates for interleaving with another stream.
        signals: Chunk signals for interleaving with another stream.

    Returns:
        ScriptedResponse: The two-chunk stream.
    """
    opening = b"".join(
        [
            _anthropic_event(
                {
                    "type": "message_start",
                    "message": {
                        "id": f"msg_{label}",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-sonnet-5",
                        "content": [],
                        "stop_reason": None,
                        "usage": {"input_tokens": 12, "output_tokens": 1},
                    },
                },
            ),
            _anthropic_event({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "thinking", "thinking": "", "signature": ""},
            }),
            _anthropic_event({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "thinking_delta", "thinking": f"{label} reasoning"},
            }),
        ],
    )
    closing = b"".join(
        [
            _anthropic_event({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "signature_delta", "signature": f"sig-{label}"},
            }),
            _anthropic_event({"type": "content_block_stop", "index": 0}),
            _anthropic_event({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
            _anthropic_event({"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": f"{label} answer"}}),
            _anthropic_event({"type": "content_block_stop", "index": 1}),
            _anthropic_event({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 9},
            }),
            _anthropic_event({"type": "message_stop"}),
        ],
    )
    return sse_response([opening, closing], chunk_delay=0.3, gates=gates, signals=signals)


@pytest.mark.asyncio
async def test_concurrent_streams_do_not_share_thinking_state(server: ScriptedHttpServer) -> None:
    """Item 64: two interleaved Messages streams on one provider keep their own thinking blocks."""
    alpha_open, beta_open, alpha_done = threading.Event(), threading.Event(), threading.Event()
    streams = {
        "alpha": _thinking_stream("alpha", gates={1: beta_open}, signals={0: alpha_open, 1: alpha_done}),
        "beta": _thinking_stream("beta", gates={0: alpha_open, 1: alpha_done}, signals={0: beta_open}),
    }

    def answer(request: RecordedRequest) -> ScriptedResponse:
        sent = request.json_object()
        content = sent["messages"][0]["content"]
        return streams[content if isinstance(content, str) else content[0]["text"]]

    server.script("POST", _ANTHROPIC_MESSAGES_PATH, answer, answer)
    provider = await _connect(server, ApiDialect.MESSAGES, "anthropic")

    async def run(label: str) -> tuple[str, list[ReasoningItem]]:
        text = "".join([chunk async for chunk in provider.chat_stream(_user(label), "claude-sonnet-5")])
        return text, provider.get_pending_reasoning()

    try:
        (alpha_text, alpha_reasoning), (beta_text, beta_reasoning) = await asyncio.wait_for(
            asyncio.gather(run("alpha"), run("beta")),
            timeout=20.0,
        )
    finally:
        await provider.disconnect()

    assert alpha_text == "alpha answer"
    assert beta_text == "beta answer"
    assert [(item.text, item.signature) for item in alpha_reasoning] == [("alpha reasoning", "sig-alpha")]
    assert [(item.text, item.signature) for item in beta_reasoning] == [("beta reasoning", "sig-beta")]


@pytest.mark.asyncio
async def test_anthropic_model_listing_follows_every_page(server: ScriptedHttpServer) -> None:
    """Item 66: Anthropic listing follows ``has_more``/``last_id`` through ``after_id``."""

    def entry(model_id: str) -> dict[str, Any]:
        return {
            "type": "model",
            "id": model_id,
            "display_name": model_id,
            "created_at": "2026-01-01T00:00:00Z",
            "max_input_tokens": 1_000_000,
        }

    server.script(
        "GET",
        _ANTHROPIC_MODELS_PATH,
        json_response(200, {"data": [entry("claude-opus-5")], "has_more": True, "first_id": "claude-opus-5", "last_id": "claude-opus-5"}),
        json_response(
            200,
            {"data": [entry("claude-sonnet-5")], "has_more": False, "first_id": "claude-sonnet-5", "last_id": "claude-sonnet-5"},
        ),
    )
    provider = await _connect(server, ApiDialect.MESSAGES, "anthropic")
    try:
        models = await provider.list_models()
    finally:
        await provider.disconnect()
    assert [model.id for model in models] == ["claude-opus-5", "claude-sonnet-5"]
    pages = server.requests(_ANTHROPIC_MODELS_PATH)
    assert [page.query.get("after_id") for page in pages] == [None, ["claude-opus-5"]]
    assert all(page.query.get("limit") == ["1000"] for page in pages)


@pytest.mark.asyncio
async def test_gemini_model_listing_follows_every_page(server: ScriptedHttpServer) -> None:
    """Item 66: Gemini listing follows ``nextPageToken`` through ``pageToken``."""
    server.script(
        "GET",
        _GEMINI_MODELS_PATH,
        json_response(200, {"models": [{"name": "models/gemini-2.5-pro"}], "nextPageToken": "page-two-token"}),
        json_response(200, {"models": [{"name": "models/gemini-2.5-flash"}]}),
    )
    provider = await _connect(server, ApiDialect.GEMINI, "gemini")
    try:
        models = await provider.list_models()
    finally:
        await provider.disconnect()
    assert [model.id for model in models] == ["models/gemini-2.5-flash", "models/gemini-2.5-pro"]
    pages = server.requests(_GEMINI_MODELS_PATH)
    assert [page.query.get("pageToken") for page in pages] == [None, ["page-two-token"]]
    assert all(page.query.get("pageSize") == ["1000"] for page in pages)
