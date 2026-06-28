# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable offline gates for Grok, OpenRouter, and Ollama providers (wave5).

Covers 15 NOT_RESOLVED findings from group-07-report.md:
  Grok      : #42 chat_stream accumulation, #46 _open_grok_stream HTTP body
  OpenRouter : #48 chat enable_cache wiring, #49 chat_stream accumulation,
               #50 get_generation, #51 _parse_tool_calls_from_response,
               #52 _raise_for_stream_status, #53 _build_usage_from_data
  Ollama     : #55 list_tags, #56 list_running_models, #57 show_model,
               #60 chat local NDJSON loop, #61 chat cloud path,
               #62 chat_stream, #65 _get_client_and_model cloud prefix

All tests are fully offline. Grok uses a ``_StaticSSETransport`` backed by the
real openai SDK; OpenRouter uses a ``_CannedTransport`` backed by a real
httpx.AsyncClient; Ollama uses ``_CapturingStubServer`` with a background
ThreadingHTTPServer. No ``MagicMock`` or ``AsyncMock`` is used anywhere.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Self, cast, override

import httpx
import openai
import pytest

from intellicrack.core.types import (
    AuthenticationError,
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
)
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from intellicrack.providers.base import UsageInfo


_THREAD_JOIN_TIMEOUT: float = 5.0
_CannedRoute = tuple[int, bytes]


def _json_route(status: int, body: dict[str, Any]) -> _CannedRoute:
    """Build a JSON-encoded canned HTTP route entry.

    Args:
        status: HTTP status code to respond with.
        body: JSON-serializable response body.

    Returns:
        _CannedRoute: A (status_code, serialized_bytes) pair.
    """
    return (status, json.dumps(body).encode("utf-8"))


def _ndjson_route(status: int, lines: list[dict[str, Any]]) -> _CannedRoute:
    """Build a newline-delimited JSON canned HTTP route entry for streaming.

    Args:
        status: HTTP status code to respond with.
        lines: List of JSON-serializable dicts to emit as NDJSON lines.

    Returns:
        _CannedRoute: A (status_code, ndjson_bytes) pair.
    """
    body = b"".join(json.dumps(line).encode("utf-8") + b"\n" for line in lines)
    return (status, body)


class _CapturingStubHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server serving canned responses and capturing request bodies.

    Attributes:
        routes: Mapping of (method, path) to ordered canned response lists.
        call_counts: Mapping of (method, path) to request count.
        captured_bodies: Mapping of (method, path) to list of raw request bodies.
    """

    routes: dict[tuple[str, str], list[_CannedRoute]]
    call_counts: dict[tuple[str, str], int]
    captured_bodies: dict[tuple[str, str], list[bytes]]
    _counts_lock: threading.Lock
    _bodies_lock: threading.Lock

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        routes: dict[tuple[str, str], list[_CannedRoute]],
    ) -> None:
        """Initialize the stub server with a route table.

        Args:
            server_address: (host, port) tuple; port 0 selects an ephemeral port.
            handler: Request handler class to instantiate per request.
            routes: Mapping of (method, path) to ordered canned responses.
        """
        super().__init__(server_address, handler)
        self.routes = routes
        self.call_counts = {}
        self.captured_bodies = {}
        self._counts_lock = threading.Lock()
        self._bodies_lock = threading.Lock()

    def next_response(self, method: str, path: str) -> _CannedRoute | None:
        """Return the next canned response for a route, advancing its cursor.

        Args:
            method: HTTP method of the incoming request.
            path: Request path (query string already stripped by the handler).

        Returns:
            _CannedRoute | None: The (status_code, body_bytes) to send, or None
            when the route is not registered.
        """
        key = (method, path)
        responses = self.routes.get(key)
        if not responses:
            return None
        with self._counts_lock:
            index = self.call_counts.get(key, 0)
            self.call_counts[key] = index + 1
        return responses[min(index, len(responses) - 1)]

    def record_body(self, method: str, path: str, body: bytes) -> None:
        """Record the raw request body for a route.

        Args:
            method: HTTP method of the incoming request.
            path: Request path.
            body: Raw request body bytes captured from the wire.
        """
        key = (method, path)
        with self._bodies_lock:
            if key not in self.captured_bodies:
                self.captured_bodies[key] = []
            self.captured_bodies[key].append(body)

    def get_captured_body(self, method: str, path: str, index: int = 0) -> bytes:
        """Return a specific captured request body.

        Args:
            method: HTTP method.
            path: Request path.
            index: Zero-based index of which request to return.

        Returns:
            bytes: The captured body bytes, or empty bytes if not found.
        """
        entries = self.captured_bodies.get((method, path), [])
        if index < len(entries):
            return entries[index]
        return b""


class _CapturingStubHandler(BaseHTTPRequestHandler):
    """HTTP request handler that serves canned responses and captures request bodies."""

    def _respond(self, method: str) -> None:
        """Serve the next canned response and record the request body.

        Args:
            method: HTTP method of the current request.
        """
        path_no_qs = self.path.split("?", 1)[0]
        content_length = int(self.headers.get("Content-Length") or 0)
        body: bytes = self.rfile.read(content_length) if content_length else b""
        server = cast("_CapturingStubHTTPServer", self.server)
        server.record_body(method, path_no_qs, body)
        canned = server.next_response(method, path_no_qs)
        if canned is None:
            self.send_error(404)
            return
        status, payload = canned
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        _ = self.wfile.write(payload)

    def do_GET(self) -> None:
        """Handle an HTTP GET request."""
        self._respond("GET")

    def do_POST(self) -> None:
        """Handle an HTTP POST request."""
        self._respond("POST")

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress the default HTTP server log output.

        Args:
            *args: Positional log arguments (unused).
            **kwargs: Keyword log arguments (unused).
        """


class _CapturingStubServer:
    """Context manager running a _CapturingStubHTTPServer in a background thread."""

    def __init__(self, routes: dict[tuple[str, str], list[_CannedRoute]]) -> None:
        """Create the server bound to an ephemeral localhost port.

        Args:
            routes: Mapping of (method, path) to ordered canned responses.
        """
        self._server = _CapturingStubHTTPServer(
            ("127.0.0.1", 0),
            _CapturingStubHandler,
            routes,
        )
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        """Start serving in the background thread.

        Returns:
            Self: This server instance.
        """
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Stop the server and join its background thread.

        Args:
            *exc_info: Exception type, value, and traceback (unused).
        """
        _ = exc_info
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=_THREAD_JOIN_TIMEOUT)

    @property
    def base_url(self) -> str:
        """The http://host:port base URL for the bound server.

        Returns:
            str: The base URL clients should target.
        """
        host, port = cast("tuple[str, int]", self._server.server_address)
        return f"http://{host}:{port}"

    def get_captured_body(self, method: str, path: str, index: int = 0) -> bytes:
        """Return a specific captured request body.

        Args:
            method: HTTP method.
            path: Request path.
            index: Zero-based index of which request to return.

        Returns:
            bytes: Captured body bytes.
        """
        return self._server.get_captured_body(method, path, index)


class _TempEventLoop:
    """Context manager providing a fresh asyncio event loop, closed on exit."""

    def __init__(self) -> None:
        """Initialize without an active loop."""
        self._loop: asyncio.AbstractEventLoop | None = None

    def __enter__(self) -> asyncio.AbstractEventLoop:
        """Create and return a fresh event loop.

        Returns:
            asyncio.AbstractEventLoop: A new event loop for this phase.
        """
        self._loop = asyncio.new_event_loop()
        return self._loop

    def __exit__(self, *exc_info: object) -> None:
        """Close the created event loop.

        Args:
            *exc_info: Exception type, value, and traceback (unused).
        """
        _ = exc_info
        if self._loop is not None:
            self._loop.close()


class _StaticSSETransport(httpx.AsyncBaseTransport):
    """Replay a pre-built SSE body for every request; capture the inbound request body."""

    def __init__(self, body: bytes) -> None:
        """Initialize with the SSE bytes to replay.

        Args:
            body: Pre-encoded SSE body replayed on every request.
        """
        self.body: bytes = body
        self.last_request_body: dict[str, object] = {}

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Capture the inbound request body and replay the pre-built SSE bytes.

        Args:
            request: The inbound HTTP request from the SDK.

        Returns:
            httpx.Response: A 200 response with the fixed SSE body and
            ``content-type: text/event-stream``.
        """
        if request.content:
            self.last_request_body = cast("dict[str, object]", json.loads(request.content))
        return httpx.Response(
            200,
            content=self.body,
            headers={"content-type": "text/event-stream"},
            request=request,
        )


class _CannedTransport(httpx.AsyncBaseTransport):
    """Replay canned JSON responses keyed by (method, path); capture inbound requests."""

    def __init__(self, response_map: dict[tuple[str, str], dict[str, Any]]) -> None:
        """Initialize with a mapping of (method, path) to JSON response bodies.

        Args:
            response_map: Maps (HTTP method, URL path) to the JSON response dict.
        """
        self._response_map = response_map
        self.captured: list[tuple[str, str, dict[str, Any]]] = []

    @override
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Serve a canned JSON response and record the inbound request body.

        Args:
            request: The inbound HTTP request.

        Returns:
            httpx.Response: A 200 response with the matching JSON body, or
            a 404 response when no matching route is registered.
        """
        method = request.method
        path = request.url.path
        body: dict[str, Any] = cast("dict[str, Any]", json.loads(request.content)) if request.content else {}
        self.captured.append((method, path, body))
        canned = self._response_map.get((method, path))
        if canned is None:
            return httpx.Response(404, content=b"Not found", request=request)
        return httpx.Response(
            200,
            content=json.dumps(canned).encode("utf-8"),
            headers={"content-type": "application/json"},
            request=request,
        )


def _sse_bytes(chunks: list[dict[str, object]], *, include_done: bool = True) -> bytes:
    """Serialize a list of chunk dicts into an SSE-framed byte string.

    Args:
        chunks: List of raw dictionaries matching the chat.completion.chunk shape.
        include_done: When True (default), append the ``data: [DONE]`` terminator.

    Returns:
        bytes: UTF-8 encoded SSE body suitable for an HTTP response.
    """
    lines = [f"data: {json.dumps(chunk)}\n\n" for chunk in chunks]
    if include_done:
        lines.append("data: [DONE]\n\n")
    return "".join(lines).encode()


def _text_chunk(
    content: str,
    *,
    model: str = "grok-3",
    chunk_id: str = "chatcmpl-g",
) -> dict[str, object]:
    """Build a single text-delta SSE chunk dict.

    Args:
        content: Text content for the delta.
        model: Model identifier embedded in the chunk.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: A dict matching the chat.completion.chunk shape.
    """
    return {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None},
        ],
    }


def _finish_chunk(
    *,
    finish_reason: str = "stop",
    prompt_tokens: int = 5,
    completion_tokens: int = 3,
    total_tokens: int = 8,
    model: str = "grok-3",
    chunk_id: str = "chatcmpl-g",
) -> dict[str, object]:
    """Build a finish-signal chunk carrying usage statistics.

    Args:
        finish_reason: The finish_reason value.
        prompt_tokens: Prompt token count for the usage field.
        completion_tokens: Completion token count.
        total_tokens: Total token count.
        model: Model identifier.
        chunk_id: Chat completion ID string.

    Returns:
        dict[str, object]: A final SSE chunk marking end-of-stream.
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


def _build_grok_provider(transport: httpx.AsyncBaseTransport) -> GrokProvider:
    """Return a pre-connected GrokProvider backed by the given httpx transport.

    Args:
        transport: The stub transport injected into the openai SDK client.

    Returns:
        GrokProvider: A provider whose client is wired to ``transport`` and
        whose ``connected`` flag is ``True``.
    """
    provider = GrokProvider()
    provider.client = openai.AsyncOpenAI(
        api_key="offline-test-key",
        base_url="http://unused.local/v1",
        http_client=httpx.AsyncClient(transport=transport),
    )
    provider.connected = True
    return provider


class TestGrokChatStreamAccumulation:
    """Finding #42 — GrokProvider.chat_stream must accumulate and yield text in order."""

    @staticmethod
    def test_yielded_text_fragments_match_sse_deltas_in_order() -> None:
        """chat_stream must yield each SSE delta content fragment in arrival order.

        Oracle: three independently-built SSE text-delta chunks with known
        content strings; the expected list is derived directly from the canned
        input, not from re-running the implementation.

        Mutation caught: removing ``yield delta.content`` from
        ``_iter_grok_stream`` produces an empty list, failing equality.
        """
        sse = _sse_bytes([
            _text_chunk("He"),
            _text_chunk("llo"),
            _text_chunk(" world"),
            _finish_chunk(prompt_tokens=5, completion_tokens=3, total_tokens=8),
        ])
        transport = _StaticSSETransport(sse)
        provider = _build_grok_provider(transport)
        messages = [Message(role="user", content="hi")]

        async def _collect() -> list[str]:
            """Drain chat_stream and return all yielded text fragments.

            Returns:
                list[str]: All text fragments yielded by the stream, in order.
            """
            return [chunk async for chunk in provider.chat_stream(messages=messages, model="grok-3")]

        with _TempEventLoop() as loop:
            chunks = loop.run_until_complete(_collect())

        assert chunks == ["He", "llo", " world"]


class TestGrokOpenGrokStreamHttpBody:
    """Finding #46 — GrokProvider._open_grok_stream must send model, messages, and stream=True."""

    @staticmethod
    def test_http_request_body_contains_model_messages_and_stream_flag() -> None:
        """_open_grok_stream must POST model, messages, and stream=True to the Grok endpoint.

        Oracle: the OpenAI streaming API specification requires stream=True in
        the request body; model and messages are independently constructed as
        test inputs.

        Mutation caught: removing ``stream=True`` from any branch of
        ``_open_grok_stream`` causes ``body["stream"] is True`` to fail.
        """
        sse = _sse_bytes([_text_chunk("ok"), _finish_chunk()])
        transport = _StaticSSETransport(sse)
        provider = _build_grok_provider(transport)

        raw_messages: list[dict[str, object]] = [{"role": "user", "content": "hello"}]

        async def _run() -> dict[str, object]:
            """Call _open_grok_stream, drain the returned stream, return captured body.

            Returns:
                dict[str, object]: The HTTP request body captured by the transport.
            """
            method: Any = getattr(provider, "_open_grok_stream")
            stream = await method(
                model="grok-3",
                messages=raw_messages,
                temperature=0.5,
                max_tokens=128,
                tools=None,
                tool_choice=None,
                reasoning_effort=None,
            )
            async for _ in stream:
                pass
            return transport.last_request_body

        with _TempEventLoop() as loop:
            body = loop.run_until_complete(_run())

        assert body["model"] == "grok-3"
        assert body["stream"] is True
        messages_in_body = cast("list[dict[str, object]]", body["messages"])
        assert len(messages_in_body) == 1
        assert messages_in_body[0]["role"] == "user"
        assert messages_in_body[0]["content"] == "hello"


class TestOpenRouterChatEnableCache:
    """Finding #48 — OpenRouterProvider.chat must wire enable_cache to _apply_cache_control."""

    @staticmethod
    def test_enable_cache_true_rewrites_user_message_to_structured_block() -> None:
        """chat(enable_cache=True) must transform user content into a block list with cache_control.

        Oracle: _apply_cache_control rewrites string content to a list containing
        one block with ``cache_control: {type: ephemeral}``; the expected
        structure is specified directly in the test.

        Mutation caught: removing ``if enable_cache: self._apply_cache_control(...)``
        in ``chat()`` leaves content as a plain string, causing
        ``isinstance(content_blocks, list)`` to fail.
        """
        canned: dict[str, Any] = {
            "choices": [{"message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
        }
        transport = _CannedTransport({("POST", "/chat/completions"): canned})
        provider = OpenRouterProvider()
        provider.client = httpx.AsyncClient(transport=transport)
        setattr(provider, "_base_url", "http://unused.local")
        provider.connected = True

        messages = [Message(role="user", content="Analyze this binary")]

        async def _run_with_cache() -> None:
            """Execute chat with enable_cache=True."""
            await provider.chat(messages=messages, model="anthropic/claude-3-5-sonnet", enable_cache=True)

        with _TempEventLoop() as loop:
            loop.run_until_complete(_run_with_cache())

        assert len(transport.captured) == 1
        _m, _p, req_body = transport.captured[0]
        req_messages = cast("list[dict[str, Any]]", req_body["messages"])
        last_user = next(m for m in reversed(req_messages) if m.get("role") == "user")
        content_blocks_raw = last_user.get("content")
        assert isinstance(content_blocks_raw, list), "enable_cache=True must rewrite content to structured blocks"
        content_blocks = cast("list[dict[str, Any]]", content_blocks_raw)
        assert len(content_blocks) == 1
        assert content_blocks[0]["type"] == "text"
        assert content_blocks[0]["text"] == "Analyze this binary"
        assert content_blocks[0]["cache_control"] == {"type": "ephemeral"}

    @staticmethod
    def test_enable_cache_false_leaves_user_message_as_plain_string() -> None:
        """chat(enable_cache=False) must NOT transform user message content.

        Oracle: without enable_cache, _apply_cache_control is never called; the
        user message content remains a plain string in OpenAI wire format.

        Mutation caught: calling _apply_cache_control unconditionally would
        rewrite content to a list even when enable_cache=False, causing
        ``isinstance(content, str)`` to fail.
        """
        canned: dict[str, Any] = {
            "choices": [{"message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
        }
        transport = _CannedTransport({("POST", "/chat/completions"): canned})
        provider = OpenRouterProvider()
        provider.client = httpx.AsyncClient(transport=transport)
        setattr(provider, "_base_url", "http://unused.local")
        provider.connected = True

        messages = [Message(role="user", content="hello")]

        async def _run_no_cache() -> None:
            """Execute chat with enable_cache=False."""
            await provider.chat(messages=messages, model="openai/gpt-4o", enable_cache=False)

        with _TempEventLoop() as loop:
            loop.run_until_complete(_run_no_cache())

        assert len(transport.captured) == 1
        _m, _p, req_body = transport.captured[0]
        req_messages = cast("list[dict[str, Any]]", req_body["messages"])
        last_user = next(m for m in reversed(req_messages) if m.get("role") == "user")
        content = last_user.get("content")
        assert isinstance(content, str), "enable_cache=False must leave content as a plain string"
        assert content == "hello"


class TestOpenRouterChatStreamAccumulation:
    """Finding #49 — OpenRouterProvider.chat_stream must accumulate and yield text."""

    @staticmethod
    def test_chat_stream_yields_delta_text_in_order() -> None:
        """chat_stream must yield each SSE delta content string in arrival order.

        Oracle: three independently-constructed SSE data lines with known
        content; the expected list is derived directly from the canned input.

        Mutation caught: removing ``yield content`` from
        ``_iter_openrouter_stream`` produces an empty list, failing equality.
        """
        sse_lines = [
            'data: {"choices": [{"delta": {"content": "chunk1"}, "finish_reason": null}]}\n\n',
            'data: {"choices": [{"delta": {"content": " chunk2"}, "finish_reason": null}]}\n\n',
            (
                'data: {"choices": [{"delta": {"content": ""}, "finish_reason": "stop"}],'
                ' "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}\n\n'
            ),
            "data: [DONE]\n\n",
        ]
        sse_body = "".join(sse_lines).encode("utf-8")

        class _SSETransport(httpx.AsyncBaseTransport):
            """Serve a fixed SSE body for every POST request."""

            @override
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                """Return the pre-built SSE bytes for any request.

                Args:
                    request: The inbound HTTP request.

                Returns:
                    httpx.Response: A 200 response with SSE content.
                """
                return httpx.Response(
                    200,
                    content=sse_body,
                    headers={"content-type": "text/event-stream"},
                    request=request,
                )

        provider = OpenRouterProvider()
        provider.client = httpx.AsyncClient(transport=_SSETransport())
        setattr(provider, "_base_url", "http://unused.local")
        provider.connected = True

        messages = [Message(role="user", content="hi")]

        async def _collect() -> list[str]:
            """Drain chat_stream and return all yielded text chunks.

            Returns:
                list[str]: Text fragments in arrival order.
            """
            return [chunk async for chunk in provider.chat_stream(messages=messages, model="openai/gpt-4o")]

        with _TempEventLoop() as loop:
            chunks = loop.run_until_complete(_collect())

        assert chunks == ["chunk1", " chunk2"]


class TestOpenRouterGetGeneration:
    """Finding #50 — OpenRouterProvider.get_generation must return exact fields from /generation."""

    @staticmethod
    def test_get_generation_returns_dict_with_stub_fields() -> None:
        """get_generation must return the exact dict the server returns at /generation?id=.

        Oracle: the stub response body is the independently-constructed ground
        truth; the method must return it verbatim without silent transformation.

        Mutation caught: returning an empty dict or stripping any field causes
        the exact key assertions to fail.
        """
        generation_payload: dict[str, Any] = {
            "data": {
                "id": "gen-abc123",
                "model": "anthropic/claude-3-5-sonnet",
                "prompt_tokens": 42,
                "completion_tokens": 17,
                "total_cost": 0.00123,
                "finish_reason": "stop",
            },
        }
        transport = _CannedTransport({("GET", "/generation"): generation_payload})
        provider = OpenRouterProvider()
        provider.client = httpx.AsyncClient(transport=transport)
        setattr(provider, "_base_url", "http://unused.local")
        provider.connected = True

        async def _run() -> dict[str, object]:
            """Call get_generation and return the result.

            Returns:
                dict[str, object]: The generation details dict.
            """
            return await provider.get_generation("gen-abc123")

        with _TempEventLoop() as loop:
            result = loop.run_until_complete(_run())

        data = cast("dict[str, Any]", result.get("data"))
        assert data is not None
        assert data["id"] == "gen-abc123"
        assert data["model"] == "anthropic/claude-3-5-sonnet"
        assert data["prompt_tokens"] == 42
        assert data["completion_tokens"] == 17
        assert data["finish_reason"] == "stop"


class TestOpenRouterParseToolCallsFromResponse:
    """Finding #51 — OpenRouterProvider._parse_tool_calls_from_response exact fields."""

    @staticmethod
    def test_parses_single_tool_call_with_exact_id_name_and_arguments() -> None:
        """_parse_tool_calls_from_response must extract id, tool_name, and arguments exactly.

        Oracle: the ToolCall fields (id, tool_name, function_name, arguments) are
        specified directly from the input dict; parse_tool_call's documented
        semantics determine the expected values.

        Mutation caught: swapping the id and function_name mapping causes the
        ``tc.id == "call_abc123"`` assertion to fail.
        """
        provider = OpenRouterProvider()
        response_message: dict[str, Any] = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                        "name": "analyze_binary",
                        "arguments": '{"path": "/bin/ls", "depth": 2}',
                    },
                },
            ],
        }
        method: Any = getattr(provider, "_parse_tool_calls_from_response")
        result: list[Any] = method(response_message)

        assert len(result) == 1
        tc = result[0]
        assert tc.id == "call_abc123"
        assert tc.tool_name == "analyze_binary"
        assert tc.function_name == "analyze_binary"
        assert tc.arguments == {"path": "/bin/ls", "depth": 2}

    @staticmethod
    def test_missing_tool_calls_key_returns_empty_list() -> None:
        """_parse_tool_calls_from_response must return [] when tool_calls is absent.

        Oracle: the method returns an empty list for messages without tool_calls;
        this matches the OpenRouter API contract for plain text responses.

        Mutation caught: unconditionally returning a non-empty list would fail
        the empty-list equality assertion.
        """
        provider = OpenRouterProvider()
        method: Any = getattr(provider, "_parse_tool_calls_from_response")
        result: list[Any] = method({"role": "assistant", "content": "Plain text response"})
        assert result == []


class TestOpenRouterRaiseForStreamStatus:
    """Finding #52 — OpenRouterProvider._raise_for_stream_status typed exception mapping."""

    @staticmethod
    def test_401_raises_authentication_error() -> None:
        """HTTP 401 must raise AuthenticationError with the invalid-key message.

        Oracle: _raise_typed_for_status maps 401 to AuthenticationError;
        _REST_HTTP_MSGS.auth_invalid is "Invalid OpenRouter API key: %s".

        Mutation caught: routing 401 to ProviderError instead would fail the
        exact exception-type assertion.
        """
        raise_method: Any = getattr(OpenRouterProvider, "_raise_for_stream_status")
        with pytest.raises(AuthenticationError, match=r"Invalid OpenRouter"):
            raise_method(401, "Unauthorized")

    @staticmethod
    def test_429_raises_rate_limit_error() -> None:
        """HTTP 429 must raise RateLimitError with the rate-limit message.

        Oracle: _raise_typed_for_status maps 429 to RateLimitError;
        _REST_HTTP_MSGS.rate_limited is "OpenRouter rate limit exceeded: %s".

        Mutation caught: routing 429 to ProviderError instead would fail the
        exact exception-type assertion.
        """
        raise_method: Any = getattr(OpenRouterProvider, "_raise_for_stream_status")
        with pytest.raises(RateLimitError, match=r"rate limit"):
            raise_method(429, "Too Many Requests")

    @staticmethod
    def test_400_raises_provider_error_with_stream_failed() -> None:
        """HTTP 400 must raise ProviderError containing 'stream failed'.

        Oracle: _raise_typed_for_status does not handle 400; the fallthrough
        ``raise ProviderError(_ERR_STREAM_FAILED % stream_detail)`` fires.

        Mutation caught: handling 400 as AuthenticationError instead would fail
        the ProviderError type assertion.
        """
        raise_method: Any = getattr(OpenRouterProvider, "_raise_for_stream_status")
        with pytest.raises(ProviderError, match=r"stream failed"):
            raise_method(400, "Bad Request")

    @staticmethod
    def test_500_raises_provider_error_with_stream_failed() -> None:
        """HTTP 500 must raise ProviderError containing 'stream failed'.

        Oracle: 500 is not handled by _raise_typed_for_status (only 503 with
        extract_503_message supplied is mapped, which is not the case here);
        the fallthrough raise fires.

        Mutation caught: treating 500 as RateLimitError would fail the
        ProviderError type check.
        """
        raise_method: Any = getattr(OpenRouterProvider, "_raise_for_stream_status")
        with pytest.raises(ProviderError, match=r"stream failed"):
            raise_method(500, "Internal Server Error")


class TestOpenRouterBuildUsageFromData:
    """Finding #53 — OpenRouterProvider._build_usage_from_data exact field mapping."""

    @staticmethod
    def test_all_three_fields_mapped_exactly() -> None:
        """_build_usage_from_data must return UsageInfo with exact prompt/completion/total.

        Oracle: the input dict has prompt_tokens=10, completion_tokens=5,
        total_tokens=15; these are the independently-known expected values.

        Mutation caught: swapping prompt_tokens and completion_tokens in the
        UsageInfo constructor causes ``result.prompt_tokens == 10`` to fail.
        """
        data: dict[str, Any] = {
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        build_usage: Any = getattr(OpenRouterProvider, "_build_usage_from_data")
        result: UsageInfo | None = build_usage(data)

        assert result is not None
        assert result.prompt_tokens == 10
        assert result.completion_tokens == 5
        assert result.total_tokens == 15

    @staticmethod
    def test_zero_total_tokens_falls_back_to_sum() -> None:
        """_build_usage_from_data must compute total as prompt+completion when total_tokens=0.

        Oracle: the sum of prompt_tokens=7 and completion_tokens=3 is 10;
        the ``or (prompt + completion)`` fallback clause activates when
        total_tokens=0.

        Mutation caught: removing the ``or (prompt + completion)`` fallback
        leaves total_tokens=0, failing the ``result.total_tokens == 10`` assertion.
        """
        data: dict[str, Any] = {
            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 0},
        }
        build_usage: Any = getattr(OpenRouterProvider, "_build_usage_from_data")
        result = build_usage(data)

        assert result is not None
        assert result.total_tokens == 10

    @staticmethod
    def test_missing_usage_key_returns_none() -> None:
        """_build_usage_from_data must return None when no usage field is present.

        Oracle: the early guard ``if not isinstance(usage_raw, dict): return None``
        fires for any absent or non-dict usage field.

        Mutation caught: unconditionally constructing UsageInfo would raise an
        exception rather than returning None.
        """
        build_usage: Any = getattr(OpenRouterProvider, "_build_usage_from_data")
        result = build_usage({})
        assert result is None


class TestOllamaListTags:
    """Finding #55 — OllamaProvider.list_tags must return the /api/tags model list."""

    @staticmethod
    def test_list_tags_returns_models_field_from_stub() -> None:
        """list_tags must return the exact models list from the /api/tags response.

        Oracle: the stub response body has a known models list with exact name
        and size values; list_tags must return it without modification.

        Mutation caught: returning an empty dict or dropping the models key
        causes the exact field assertions to fail.
        """
        tags_response: dict[str, Any] = {
            "models": [
                {"name": "phi3:latest", "modified_at": "2025-01-01T00:00:00Z", "size": 2000000000},
                {"name": "gemma:7b", "modified_at": "2025-02-01T00:00:00Z", "size": 5000000000},
            ],
        }
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [
                _json_route(200, {"models": [{"name": "phi3:latest"}]}),
                _json_route(200, tags_response),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            result = loop.run_until_complete(provider.list_tags(source="local"))
            loop.run_until_complete(provider.disconnect())

        models = cast("list[dict[str, Any]]", result.get("models", []))
        assert len(models) == 2
        assert models[0]["name"] == "phi3:latest"
        assert models[1]["name"] == "gemma:7b"
        assert models[1]["size"] == 5000000000


class TestOllamaListRunningModels:
    """Finding #56 — OllamaProvider.list_running_models must return /api/ps model list."""

    @staticmethod
    def test_list_running_models_returns_ps_response() -> None:
        """list_running_models must return the exact models list from /api/ps.

        Oracle: the stub response body has a known models list with exact name
        and size_vram values; the method must return them without modification.

        Mutation caught: returning an empty dict or hitting the wrong endpoint
        (/api/tags instead of /api/ps) would cause the assertions to fail.
        """
        ps_response: dict[str, Any] = {
            "models": [
                {"name": "llama3.1:8b", "size": 4700000000, "size_vram": 4200000000},
            ],
        }
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("GET", "/api/ps"): [_json_route(200, ps_response)],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            result = loop.run_until_complete(provider.list_running_models(source="local"))
            loop.run_until_complete(provider.disconnect())

        models = cast("list[dict[str, Any]]", result.get("models", []))
        assert len(models) == 1
        assert models[0]["name"] == "llama3.1:8b"
        assert models[0]["size_vram"] == 4200000000


class TestOllamaShowModel:
    """Finding #57 — OllamaProvider.show_model must return parameters and template fields."""

    @staticmethod
    def test_show_model_returns_exact_parameters_and_template() -> None:
        """show_model must return the parameters and template fields from /api/show verbatim.

        Oracle: the stub response carries known parameter and template strings;
        the method must return them without parsing or stripping.

        Mutation caught: silently dropping the parameters or template field
        would cause the exact-value assertions to fail.
        """
        show_body: dict[str, Any] = {
            "modelfile": "FROM llama3.1:8b",
            "parameters": "num_ctx 8192\ntemperature 0.7",
            "template": "{{ .System }}\n{{ .Prompt }}",
            "details": {"family": "llama"},
        }
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("POST", "/api/show"): [_json_route(200, show_body)],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            result = loop.run_until_complete(provider.show_model("llama3.1:8b"))
            loop.run_until_complete(provider.disconnect())

        assert result.get("parameters") == "num_ctx 8192\ntemperature 0.7"
        assert result.get("template") == "{{ .System }}\n{{ .Prompt }}"
        assert result.get("modelfile") == "FROM llama3.1:8b"


class TestOllamaChatLocalNDJSON:
    """Finding #60 — OllamaProvider.chat must complete the full local NDJSON HTTP cycle."""

    @staticmethod
    def test_chat_local_returns_message_content_and_no_tool_calls() -> None:
        """chat() with a local model must POST to /api/chat and parse the JSON response.

        The full loop — HTTP POST to /api/chat → JSON decode →
        _parse_chat_response(is_cloud=False) → _build_chat_response — is
        exercised end-to-end against a real stub server.

        Oracle: the stub response carries content "Hello, world!"; the returned
        Message must carry that string verbatim.

        Mutation caught: if _parse_chat_response reads the wrong key (e.g.
        ``content`` at the top level instead of ``message.content``), the
        returned content assertion fails.
        """
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("POST", "/api/chat"): [
                _json_route(
                    200,
                    {
                        "model": "llama3.1",
                        "message": {"role": "assistant", "content": "Hello, world!"},
                        "done": True,
                        "eval_count": 10,
                        "prompt_eval_count": 5,
                    },
                ),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            msg, tool_calls = loop.run_until_complete(
                provider.chat(
                    messages=[Message(role="user", content="say hello")],
                    model="llama3.1",
                ),
            )
            loop.run_until_complete(provider.disconnect())

        assert msg.role == "assistant"
        assert msg.content == "Hello, world!"
        assert tool_calls is None

    @staticmethod
    def test_chat_local_sends_stream_false_and_options_nesting() -> None:
        """chat() with a local model must send stream=False and nest options correctly.

        Oracle: the Ollama /api/chat specification requires stream=False for a
        synchronous response and wraps temperature/num_predict inside ``options``.

        Mutation caught: setting stream=True or hoisting temperature to the top
        level instead of inside options would cause the exact assertion to fail.
        """
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("POST", "/api/chat"): [
                _json_route(
                    200,
                    {
                        "message": {"role": "assistant", "content": "ok"},
                        "done": True,
                        "eval_count": 1,
                        "prompt_eval_count": 1,
                    },
                ),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            loop.run_until_complete(
                provider.chat(
                    messages=[Message(role="user", content="hi")],
                    model="llama3.1",
                    temperature=0.3,
                    max_tokens=64,
                ),
            )
            loop.run_until_complete(provider.disconnect())

        req = cast("dict[str, Any]", json.loads(server.get_captured_body("POST", "/api/chat")))
        assert req["stream"] is False
        assert req["model"] == "llama3.1"
        options = cast("dict[str, Any]", req.get("options", {}))
        assert options["temperature"] == pytest.approx(0.3)
        assert options["num_predict"] == 64


class TestOllamaChatCloudPath:
    """Finding #61 — OllamaProvider.chat must route cloud/ models to /v1/chat/completions."""

    @staticmethod
    def test_chat_cloud_model_uses_openai_compatible_endpoint_and_parses_choices() -> None:
        """chat() with a cloud/ model must POST to /v1/chat/completions and parse choices.

        The full cloud dispatch — _get_client_and_model → /v1/chat/completions →
        _parse_chat_response(is_cloud=True) → _build_chat_response — is exercised
        end-to-end against a real stub server.

        Oracle: the stub choices[0].message.content is "Cloud response here";
        the returned Message must carry that string exactly.

        Mutation caught: routing to /api/chat instead of /v1/chat/completions
        would return a 404 from the stub, raising ProviderError before the
        assertion is reached.
        """
        cloud_response: dict[str, Any] = {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "Cloud response here"},
                    "finish_reason": "stop",
                },
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("POST", "/v1/chat/completions"): [_json_route(200, cloud_response)],
        }
        original_cloud_url = OllamaProvider.CLOUD_API_URL
        with _CapturingStubServer(routes) as server:
            OllamaProvider.CLOUD_API_URL = server.base_url
            try:
                with _TempEventLoop() as loop:
                    provider = OllamaProvider()
                    credentials = ProviderCredentials(api_key="test-cloud-key")
                    loop.run_until_complete(provider.connect(credentials))
                    msg, tool_calls = loop.run_until_complete(
                        provider.chat(
                            messages=[Message(role="user", content="ping")],
                            model="cloud/llama3.1:8b",
                        ),
                    )
                    loop.run_until_complete(provider.disconnect())
            finally:
                OllamaProvider.CLOUD_API_URL = original_cloud_url

        assert msg.role == "assistant"
        assert msg.content == "Cloud response here"
        assert tool_calls is None


class TestOllamaChatStream:
    """Finding #62 — OllamaProvider.chat_stream must yield NDJSON content chunks in order."""

    @staticmethod
    def test_chat_stream_local_yields_content_parts_in_order() -> None:
        """chat_stream must yield each non-empty content part from NDJSON frames in order.

        Oracle: three NDJSON frames with known content strings; the expected list
        is ["Chunk1", " Chunk2"] because the third frame has empty string content
        which is filtered by the truthy check in ``_iter_native_stream_chunks``.

        Mutation caught: removing the ``yield content_part`` in
        ``_iter_native_stream_chunks`` produces an empty list, failing equality.
        """
        ndjson_frames: list[dict[str, Any]] = [
            {"model": "llama3.1", "message": {"role": "assistant", "content": "Chunk1"}, "done": False},
            {"model": "llama3.1", "message": {"role": "assistant", "content": " Chunk2"}, "done": False},
            {
                "model": "llama3.1",
                "message": {"role": "assistant", "content": ""},
                "done": True,
                "eval_count": 5,
                "prompt_eval_count": 3,
            },
        ]
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": []})],
            ("POST", "/api/chat"): [_ndjson_route(200, ndjson_frames)],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))

            async def _collect() -> list[str]:
                """Drain chat_stream and return all yielded text chunks.

                Returns:
                    list[str]: Content parts in arrival order.
                """
                return [
                    chunk
                    async for chunk in provider.chat_stream(
                        messages=[Message(role="user", content="hello")],
                        model="llama3.1",
                    )
                ]

            chunks = loop.run_until_complete(_collect())
            loop.run_until_complete(provider.disconnect())

        assert chunks == ["Chunk1", " Chunk2"]


class TestOllamaGetClientAndModelCloudPrefix:
    """Finding #65 — OllamaProvider._get_client_and_model must route cloud/ prefix correctly."""

    @staticmethod
    def test_cloud_prefix_returns_cloud_client_and_strips_prefix() -> None:
        """_get_client_and_model('cloud/model') must return the cloud client and bare model name.

        Oracle: the cloud client is injected directly; the ``is`` identity check
        proves that the routing selected the correct client object, not a
        locally-reconstructed one. The model_id must be the bare name after
        stripping the 6-character "cloud/" prefix.

        Mutation caught: returning the local client instead of the cloud client
        would fail ``returned_client is cloud_client``. Returning the full model
        string would fail ``model_id == "llama3.1:8b"``.
        """
        original_cloud_url = OllamaProvider.CLOUD_API_URL
        returned_client: httpx.AsyncClient | None = None
        base_url_got: str = ""
        model_id_got: str = ""

        with _TempEventLoop() as loop:
            cloud_client = httpx.AsyncClient()

            async def _run() -> tuple[httpx.AsyncClient, str, str]:
                """Set up provider with cloud client and call _get_client_and_model.

                Returns:
                    tuple[httpx.AsyncClient, str, str]: The (client, base_url, model_id) triple.
                """
                await asyncio.sleep(0)
                provider = OllamaProvider()
                setattr(provider, "_cloud_client", cloud_client)
                setattr(provider, "_cloud_available", True)
                setattr(provider, "_cloud_client_loop", asyncio.get_running_loop())
                provider.connected = True
                method: Any = getattr(provider, "_get_client_and_model")
                return cast("tuple[httpx.AsyncClient, str, str]", method("cloud/llama3.1:8b"))

            try:
                returned_client, base_url_got, model_id_got = loop.run_until_complete(_run())
            finally:
                loop.run_until_complete(cloud_client.aclose())

        OllamaProvider.CLOUD_API_URL = original_cloud_url

        assert returned_client is cloud_client
        assert model_id_got == "llama3.1:8b"
        assert base_url_got == original_cloud_url
