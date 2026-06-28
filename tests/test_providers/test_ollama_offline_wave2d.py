# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Offline test gates for OllamaProvider transforms (wave2d remediation).

Covers operations that had zero offline coverage per section-09 audit:
_parse_chat_response (local NDJSON and cloud OpenAI paths), _parse_ollama_tool_calls,
_accumulate_native_tool_call_deltas, _finalize_native_tool_calls,
_record_usage_from_chunk, _record_usage_from_openai_payload,
_raise_for_status (Ollama-specific HTTP status mapping),
generate, embeddings, and pull_model.

All tests are fully offline. A loopback stub HTTP server supplies canned
JSON and NDJSON responses; no live Ollama endpoint is contacted.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self, cast

import httpx
import pytest

from intellicrack.core.types import (
    AuthenticationError,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ToolCall,
)
from intellicrack.providers.ollama import OllamaProvider


_ATTR_PARSE_CHAT_RESPONSE: str = "_parse_chat_response"
_ATTR_PARSE_OLLAMA_TOOL_CALLS: str = "_parse_ollama_tool_calls"
_ATTR_ACCUMULATE_NATIVE_DELTAS: str = "_accumulate_native_tool_call_deltas"
_ATTR_FINALIZE_NATIVE_TOOL_CALLS: str = "_finalize_native_tool_calls"
_ATTR_RECORD_USAGE_CHUNK: str = "_record_usage_from_chunk"
_ATTR_RECORD_USAGE_OPENAI: str = "_record_usage_from_openai_payload"
_ATTR_RAISE_FOR_STATUS: str = "_raise_for_status"

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
            path: Request path.

        Returns:
            _CannedRoute | None: The (status_code, body_bytes) to send,
            or None when the route is not registered.
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
        content_length = int(self.headers.get("Content-Length") or 0)
        body: bytes = self.rfile.read(content_length) if content_length else b""
        server = cast("_CapturingStubHTTPServer", self.server)
        server.record_body(method, self.path, body)
        canned = server.next_response(method, self.path)
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


def _call_parse_chat_response(
    provider: OllamaProvider,
    data: dict[str, Any],
    *,
    is_cloud: bool,
) -> tuple[Any, Any]:
    """Invoke OllamaProvider._parse_chat_response via getattr.

    Args:
        provider: The OllamaProvider instance under test.
        data: The parsed JSON response dict.
        is_cloud: True for the cloud OpenAI-compatible path.

    Returns:
        tuple[Any, Any]: The (content, tool_calls) pair returned by the method.

    Raises:
        TypeError: If the attribute is absent or the method returns a non-tuple.
    """
    method: object = getattr(provider, _ATTR_PARSE_CHAT_RESPONSE)
    if not callable(method):
        msg = "_parse_chat_response is not callable"
        raise TypeError(msg)
    result: object = method(data, is_cloud=is_cloud)
    if not isinstance(result, tuple):
        msg = "_parse_chat_response did not return a tuple"
        raise TypeError(msg)
    return cast("tuple[Any, Any]", result)


def _call_parse_ollama_tool_calls(
    provider: OllamaProvider,
    data: dict[str, Any],
) -> list[Any]:
    """Invoke OllamaProvider._parse_ollama_tool_calls via getattr.

    Args:
        provider: The OllamaProvider instance under test.
        data: The parsed JSON response dict.

    Returns:
        list[Any]: The list of ToolCall objects extracted from the response.

    Raises:
        TypeError: If the attribute is absent or the method returns a non-list.
    """
    method: object = getattr(provider, _ATTR_PARSE_OLLAMA_TOOL_CALLS)
    if not callable(method):
        msg = "_parse_ollama_tool_calls is not callable"
        raise TypeError(msg)
    result: object = method(data)
    if not isinstance(result, list):
        msg = "_parse_ollama_tool_calls did not return a list"
        raise TypeError(msg)
    return cast("list[Any]", result)


def _call_accumulate_native_deltas(
    message_obj: dict[str, Any],
    accumulated: dict[str, dict[str, Any]],
    order: list[str],
) -> None:
    """Invoke OllamaProvider._accumulate_native_tool_call_deltas via getattr.

    Args:
        message_obj: The ``message`` dict from a single NDJSON streaming chunk.
        accumulated: Mapping from call ID to the merged tool-call payload.
        order: Insertion-order list of unique call IDs encountered so far.

    Raises:
        TypeError: If the static method is absent or not callable.
    """
    method: object = getattr(OllamaProvider, _ATTR_ACCUMULATE_NATIVE_DELTAS)
    if not callable(method):
        msg = "_accumulate_native_tool_call_deltas is not callable"
        raise TypeError(msg)
    method(message_obj, accumulated, order)


def _call_finalize_native_tool_calls(
    provider: OllamaProvider,
    accumulated: dict[str, dict[str, Any]],
    order: list[str],
) -> list[Any]:
    """Invoke OllamaProvider._finalize_native_tool_calls via getattr.

    Args:
        provider: The OllamaProvider instance under test.
        accumulated: Mapping from call ID to the merged tool-call payload.
        order: Insertion-order list of unique call IDs.

    Returns:
        list[Any]: The finalised list of ToolCall objects.

    Raises:
        TypeError: If the attribute is absent or the method returns a non-list.
    """
    method: object = getattr(provider, _ATTR_FINALIZE_NATIVE_TOOL_CALLS)
    if not callable(method):
        msg = "_finalize_native_tool_calls is not callable"
        raise TypeError(msg)
    result: object = method(accumulated, order)
    if not isinstance(result, list):
        msg = "_finalize_native_tool_calls did not return a list"
        raise TypeError(msg)
    return cast("list[Any]", result)


def _call_record_usage_from_chunk(
    provider: OllamaProvider,
    data: dict[str, Any],
) -> None:
    """Invoke OllamaProvider._record_usage_from_chunk via getattr.

    Args:
        provider: The OllamaProvider instance under test.
        data: The chunk or final-frame dict containing Ollama usage fields.

    Raises:
        TypeError: If the attribute is absent or not callable.
    """
    method: object = getattr(provider, _ATTR_RECORD_USAGE_CHUNK)
    if not callable(method):
        msg = "_record_usage_from_chunk is not callable"
        raise TypeError(msg)
    method(data)


def _call_record_usage_from_openai_payload(
    provider: OllamaProvider,
    data: dict[str, Any],
) -> None:
    """Invoke OllamaProvider._record_usage_from_openai_payload via getattr.

    Args:
        provider: The OllamaProvider instance under test.
        data: The parsed JSON response or chunk dict containing an OpenAI usage field.

    Raises:
        TypeError: If the attribute is absent or not callable.
    """
    method: object = getattr(provider, _ATTR_RECORD_USAGE_OPENAI)
    if not callable(method):
        msg = "_record_usage_from_openai_payload is not callable"
        raise TypeError(msg)
    method(data)


def _call_raise_for_status(response: httpx.Response) -> None:
    """Invoke OllamaProvider._raise_for_status via getattr.

    The wrapped method may raise AuthenticationError, RateLimitError,
    or ProviderError depending on the HTTP status code.

    Args:
        response: The httpx.Response to evaluate.

    Raises:
        TypeError: If the static method is absent or not callable.
    """
    method: object = getattr(OllamaProvider, _ATTR_RAISE_FOR_STATUS)
    if not callable(method):
        msg = "_raise_for_status is not callable"
        raise TypeError(msg)
    method(response)


def _make_response(status: int, text: str) -> httpx.Response:
    """Construct a minimal httpx.Response for status-mapping tests.

    Args:
        status: HTTP status code.
        text: Response body text.

    Returns:
        httpx.Response: A response with the given status and text body.
    """
    return httpx.Response(
        status_code=status,
        content=text.encode("utf-8"),
        request=httpx.Request("GET", "http://localhost"),
    )


class TestRaiseForStatus:
    """Exact HTTP-status to exception-type mapping for OllamaProvider."""

    @staticmethod
    def test_401_raises_authentication_error_with_status_code() -> None:
        """HTTP 401 must raise AuthenticationError with status_code=401.

        Mutation caught: if the implementation raises ProviderError instead
        of AuthenticationError for 401, this test fails because the
        pytest.raises context asserts the exact type AuthenticationError,
        which is a subclass of ProviderError but not its base class.

        Oracle: the Ollama HTTP spec classifies 401 as an auth failure;
        the Intellicrack typed-error hierarchy maps auth failures to
        AuthenticationError, not the generic ProviderError.
        """
        with pytest.raises(AuthenticationError, match="401"):
            _call_raise_for_status(_make_response(401, "Unauthorized"))

    @staticmethod
    def test_403_raises_authentication_error_with_status_code() -> None:
        """HTTP 403 must raise AuthenticationError with status_code=403.

        Mutation caught: if the status check omits 403 from the auth-error
        set, HTTP 403 would fall through to the generic ProviderError branch
        and the AuthenticationError assertion fails.

        Oracle: RFC 7231 treats 403 (Forbidden) as an authorization denial,
        which Intellicrack maps to AuthenticationError alongside 401.
        """
        with pytest.raises(AuthenticationError, match="403"):
            _call_raise_for_status(_make_response(403, "Forbidden"))

    @staticmethod
    def test_429_raises_rate_limit_error() -> None:
        """HTTP 429 must raise RateLimitError.

        Mutation caught: if 429 is not handled as a distinct case, it would
        reach the generic ProviderError branch and the RateLimitError
        assertion fails.

        Oracle: HTTP 429 Too Many Requests is the canonical rate-limit status
        code; Intellicrack maps it to RateLimitError.
        """
        with pytest.raises(RateLimitError, match="429"):
            _call_raise_for_status(_make_response(429, "Too Many Requests"))

    @staticmethod
    def test_500_raises_provider_error_not_auth_error() -> None:
        """HTTP 500 must raise ProviderError, not AuthenticationError.

        Mutation caught: if the 5xx branch is changed to raise
        AuthenticationError instead of ProviderError, the explicit
        AuthenticationError exclusion via isinstance fails.

        Oracle: HTTP 500 is a server error, not a client auth failure.
        """
        with pytest.raises(ProviderError) as exc_info:
            _call_raise_for_status(_make_response(500, "Internal Server Error"))
        exc = exc_info.value
        assert not isinstance(exc, AuthenticationError)
        assert not isinstance(exc, RateLimitError)

    @staticmethod
    def test_200_does_not_raise() -> None:
        """HTTP 200 must not raise any exception.

        Mutation caught: if the success-range check is corrupted (e.g. using
        ``status != 200`` instead of ``not (200 <= status < 300)``), valid
        responses would incorrectly trigger exception paths.

        Oracle: HTTP 200 OK is unambiguously successful.
        """
        _call_raise_for_status(_make_response(200, "OK"))


class TestParseChatResponse:
    """Exact content and tool-call extraction for both Ollama response shapes."""

    @staticmethod
    def test_local_path_extracts_message_content() -> None:
        """Local path must read content from data['message']['content'].

        Mutation caught: if the implementation reads from ``data.get('text')``
        or from ``data.get('choices')[0]['message']['content']`` (the cloud
        path), the returned string would be empty or raise KeyError.

        Oracle: Ollama /api/chat (local) wraps the assistant message in a
        top-level ``message`` object with a ``content`` string field.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "model": "llama3.1:8b",
            "message": {"role": "assistant", "content": "Paris is the capital of France."},
            "done": True,
        }
        content, tool_calls = _call_parse_chat_response(provider, data, is_cloud=False)
        assert isinstance(content, str)
        assert content == "Paris is the capital of France."
        assert isinstance(tool_calls, list)
        assert tool_calls == []

    @staticmethod
    def test_local_path_extracts_tool_calls_from_message() -> None:
        """Local path must parse tool calls from data['message']['tool_calls'].

        Mutation caught: if the implementation reads ``data['tool_calls']``
        directly (omitting the ``message`` nesting), no tool calls are found
        and the length assertion fails.

        Oracle: Ollama native tool-call format places tool_calls inside the
        ``message`` object, not at the top level of the response.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "read_binary", "arguments": {"offset": 0, "length": 16}}},
                ],
            },
            "done": True,
        }
        content, tool_calls = _call_parse_chat_response(provider, data, is_cloud=False)
        assert not content
        assert len(tool_calls) == 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.function_name == "read_binary"
        assert call.arguments == {"offset": 0, "length": 16}

    @staticmethod
    def test_cloud_path_reads_choices_array() -> None:
        """Cloud path must read content from data['choices'][0]['message']['content'].

        Mutation caught: if the implementation uses the local path
        (``data.get('message')['content']``) when is_cloud=True, the
        OpenAI-compatible ``choices`` envelope is ignored and the content
        is empty or raises KeyError.

        Oracle: Ollama cloud exposes /v1/chat/completions; content is nested
        as choices[0].message.content.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "id": "chatcmpl-abc",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hello from cloud."},
                    "finish_reason": "stop",
                },
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        content, tool_calls = _call_parse_chat_response(provider, data, is_cloud=True)
        assert content == "Hello from cloud."
        assert tool_calls == []

    @staticmethod
    def test_cloud_path_extracts_tool_calls_from_choices_message() -> None:
        """Cloud path must parse tool calls from choices[0].message.tool_calls.

        Mutation caught: if the cloud path reads ``data.get('message')``
        instead of ``choices[0]['message']``, tool calls are not found and
        the ToolCall assertion fails.

        Oracle: OpenAI /v1/chat/completions places tool_calls inside
        choices[0].message, not at the top level.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_cloud_99",
                                "type": "function",
                                "function": {
                                    "name": "disassemble",
                                    "arguments": '{"address": 4096, "count": 8}',
                                },
                            },
                        ],
                    },
                },
            ],
        }
        content, tool_calls = _call_parse_chat_response(provider, data, is_cloud=True)
        assert not content
        assert len(tool_calls) == 1
        call = tool_calls[0]
        assert isinstance(call, ToolCall)
        assert call.id == "call_cloud_99"
        assert call.function_name == "disassemble"
        assert call.arguments == {"address": 4096, "count": 8}

    @staticmethod
    def test_local_path_empty_message_returns_empty_string() -> None:
        """Local path must return empty content when message key is absent.

        Mutation caught: if the implementation calls ``data['message']['content']``
        without a default, a missing ``message`` key raises KeyError and the
        test fails with an unexpected exception instead of returning empty.

        Oracle: Ollama may return done-frames with no message body; the
        provider must tolerate this without raising.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {"done": True, "prompt_eval_count": 5, "eval_count": 2}
        content, tool_calls = _call_parse_chat_response(provider, data, is_cloud=False)
        assert not content
        assert tool_calls == []


class TestParseOllamaToolCalls:
    """Exact field extraction from the Ollama native tool-call format."""

    @staticmethod
    def test_single_tool_call_with_dict_args() -> None:
        """Native format with dict arguments must produce ToolCall with exact fields.

        Mutation caught: if the implementation reads ``data['tool_calls']``
        (top-level) instead of ``data['message']['tool_calls']``, the
        extraction returns an empty list and the length assertion fails.

        Oracle: Ollama /api/chat places tool_calls under the message object.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"name": "analyze", "arguments": {"path": "/bin/ls", "depth": 3}}},
                ],
            },
        }
        calls = _call_parse_ollama_tool_calls(provider, data)
        assert len(calls) == 1
        call = calls[0]
        assert isinstance(call, ToolCall)
        assert call.id == "call_0"
        assert call.function_name == "analyze"
        assert call.tool_name == "analyze"
        assert call.arguments == {"path": "/bin/ls", "depth": 3}

    @staticmethod
    def test_no_tool_calls_key_returns_empty_list() -> None:
        """Message dict without tool_calls key must return an empty list.

        Mutation caught: if the implementation uses ``message.get('tool_calls', [])``
        incorrectly and returns a truthy sentinel, the empty-list assertion fails.

        Oracle: the absence of tool_calls in the message object means the
        model made a regular text response with no function calls.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "message": {"role": "assistant", "content": "No tools needed."},
        }
        calls = _call_parse_ollama_tool_calls(provider, data)
        assert calls == []

    @staticmethod
    def test_no_message_key_returns_empty_list() -> None:
        """Response without a message key must return an empty list.

        Mutation caught: if the implementation does not guard against a
        missing message key, a KeyError would propagate instead of returning
        an empty list.

        Oracle: Ollama may return done-frames with no message body; the
        provider must treat them as having no tool calls.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {"done": True}
        calls = _call_parse_ollama_tool_calls(provider, data)
        assert calls == []


class TestAccumulateNativeToolCallDeltas:
    """Delta-accumulation for native Ollama NDJSON tool-call streaming."""

    @staticmethod
    def test_accumulates_by_explicit_id_field() -> None:
        """Tool-call deltas must be keyed by the explicit id field, not by index.

        Mutation caught: if the implementation keys entries by their array
        index instead of the explicit id string, two deltas for the same
        logical call would create duplicate entries; the count assertion fails.

        Oracle: native Ollama tool-call streaming provides an ``id`` field
        on each delta; the accumulator uses that as the stable key.
        """
        accumulated: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        msg1: dict[str, Any] = {
            "tool_calls": [{"id": "call_abc", "function": {"name": "get_info", "arguments": ""}}],
        }
        msg2: dict[str, Any] = {
            "tool_calls": [{"id": "call_abc", "function": {"arguments": '{"key": "value"}'}}],
        }
        _call_accumulate_native_deltas(msg1, accumulated, order)
        _call_accumulate_native_deltas(msg2, accumulated, order)
        assert len(accumulated) == 1
        assert order == ["call_abc"]
        entry = accumulated["call_abc"]
        assert isinstance(entry, dict)
        func: object = entry.get("function")
        assert isinstance(func, dict)
        func_dict = cast("dict[str, Any]", func)
        assert func_dict.get("name") == "get_info"
        assert func_dict.get("arguments") == '{"key": "value"}'

    @staticmethod
    def test_concatenates_string_args_across_chunks() -> None:
        """String argument deltas must be concatenated, not overwritten.

        Mutation caught: if the implementation assigns ``arguments = delta``
        instead of ``arguments += delta``, only the last chunk's fragment
        is kept and the reconstructed JSON assertion fails.

        Oracle: streaming JSON arguments arrive as incremental string
        fragments; correct reassembly requires concatenation in arrival order.
        """
        accumulated: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        chunks: list[dict[str, Any]] = [
            {"tool_calls": [{"id": "tc1", "function": {"name": "search", "arguments": ""}}]},
            {"tool_calls": [{"id": "tc1", "function": {"arguments": '{"query":'}}]},
            {"tool_calls": [{"id": "tc1", "function": {"arguments": ' "needle"}'}}]},
        ]
        for chunk in chunks:
            _call_accumulate_native_deltas(chunk, accumulated, order)
        func_args: object = accumulated["tc1"]["function"]["arguments"]
        assert func_args == '{"query": "needle"}'

    @staticmethod
    def test_dict_args_replace_string_accumulator() -> None:
        """A dict-typed arguments field must replace the string accumulator.

        Mutation caught: if the implementation always tries to concatenate,
        a dict argument would fail with TypeError; if it discards the dict,
        the assertion on argument type fails.

        Oracle: Ollama may emit a complete dict in a single chunk rather than
        streaming JSON string fragments; both shapes must be accepted.
        """
        accumulated: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        msg1: dict[str, Any] = {
            "tool_calls": [{"id": "tc2", "function": {"name": "load", "arguments": ""}}],
        }
        msg2: dict[str, Any] = {
            "tool_calls": [{"id": "tc2", "function": {"arguments": {"file": "C:/testdata/x"}}}],
        }
        _call_accumulate_native_deltas(msg1, accumulated, order)
        _call_accumulate_native_deltas(msg2, accumulated, order)
        func_args: object = accumulated["tc2"]["function"]["arguments"]
        assert isinstance(func_args, dict)
        assert func_args == {"file": "C:/testdata/x"}


class TestFinalizeNativeToolCalls:
    """ToolCall assembly from accumulated native Ollama streaming deltas."""

    @staticmethod
    def test_preserves_insertion_order_for_multiple_calls() -> None:
        """Multiple accumulated calls must be returned in insertion order.

        Mutation caught: if the implementation iterates over the accumulated
        dict in arbitrary order (e.g. sorted by key string), calls that
        arrived out-of-alphabetical-key order would be reordered, and the
        first-call function_name assertion fails.

        Oracle: the order list explicitly records arrival order; final output
        must follow that list, not dict iteration order.
        """
        provider = OllamaProvider()
        accumulated: dict[str, dict[str, Any]] = {
            "call_z": {"id": "call_z", "function": {"name": "second_fn", "arguments": "{}"}},
            "call_a": {"id": "call_a", "function": {"name": "first_fn", "arguments": "{}"}},
        }
        order: list[str] = ["call_z", "call_a"]
        results = _call_finalize_native_tool_calls(provider, accumulated, order)
        assert len(results) == 2
        assert results[0].function_name == "second_fn"
        assert results[1].function_name == "first_fn"

    @staticmethod
    def test_parses_json_string_args_to_dict() -> None:
        """JSON string arguments must be parsed into a dict on the ToolCall.

        Mutation caught: if the implementation stores the raw string in
        arguments instead of parsing it, ToolCall.arguments would be a
        string and the dict-key assertion fails.

        Oracle: ToolCall.arguments is typed as dict[str, Any]; the JSON
        string must be deserialized before storing.
        """
        provider = OllamaProvider()
        accumulated: dict[str, dict[str, Any]] = {
            "call_1": {
                "id": "call_1",
                "function": {
                    "name": "decompile",
                    "arguments": '{"address": 8192, "lang": "c"}',
                },
            },
        }
        order: list[str] = ["call_1"]
        results = _call_finalize_native_tool_calls(provider, accumulated, order)
        assert len(results) == 1
        call = results[0]
        assert isinstance(call, ToolCall)
        assert call.id == "call_1"
        assert call.function_name == "decompile"
        assert call.arguments == {"address": 8192, "lang": "c"}


class TestRecordUsageFromChunk:
    """Usage extraction from Ollama native NDJSON final frames."""

    @staticmethod
    def test_sets_prompt_and_completion_tokens_from_eval_counts() -> None:
        """prompt_eval_count and eval_count must map to prompt and completion tokens.

        Mutation caught: if the keys are swapped (reading eval_count for
        prompt_tokens and prompt_eval_count for completion_tokens), the
        assertion on exact values fails.

        Oracle: Ollama documentation names the fields ``prompt_eval_count``
        (tokens in the prompt) and ``eval_count`` (tokens generated).
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "prompt_eval_count": 42,
            "eval_count": 17,
            "done": True,
        }
        _call_record_usage_from_chunk(provider, data)
        usage = provider.get_pending_usage()
        assert usage is not None
        assert usage.prompt_tokens == 42
        assert usage.completion_tokens == 17
        assert usage.total_tokens == 59

    @staticmethod
    def test_all_zero_counts_leaves_pending_usage_none() -> None:
        """All-zero token counts must not create a pending usage entry.

        Mutation caught: if the guard is changed to ``< 0`` instead of
        ``== 0``, zero-token responses incorrectly populate pending_usage,
        and the None assertion fails.

        Oracle: a frame with both counts at zero indicates no tokens were
        consumed; the provider should not report spurious zero-usage entries.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {"prompt_eval_count": 0, "eval_count": 0}
        _call_record_usage_from_chunk(provider, data)
        assert provider.get_pending_usage() is None


class TestRecordUsageFromOpenaiPayload:
    """Usage extraction from OpenAI-compatible cloud response payloads."""

    @staticmethod
    def test_reads_prompt_tokens_and_completion_tokens() -> None:
        """usage.prompt_tokens and usage.completion_tokens must map exactly.

        Mutation caught: if the implementation reads ``input_tokens`` and
        ``output_tokens`` (Anthropic field names) instead of the OpenAI
        ``prompt_tokens`` / ``completion_tokens`` fields, both values are
        zero and the exact-value assertion fails.

        Oracle: OpenAI /v1/chat/completions ``usage`` object names the
        fields ``prompt_tokens`` and ``completion_tokens``.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "usage": {
                "prompt_tokens": 80,
                "completion_tokens": 30,
                "total_tokens": 110,
            },
        }
        _call_record_usage_from_openai_payload(provider, data)
        usage = provider.get_pending_usage()
        assert usage is not None
        assert usage.prompt_tokens == 80
        assert usage.completion_tokens == 30
        assert usage.total_tokens == 110

    @staticmethod
    def test_total_tokens_computed_when_absent() -> None:
        """total_tokens must be computed as prompt + completion when not provided.

        Mutation caught: if the implementation returns zero for total_tokens
        when the field is absent instead of summing the parts, the
        total assertion fails.

        Oracle: the implementation's fallback is
        ``total_tokens = prompt_tokens + completion_tokens`` when the
        server omits the total.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "usage": {"prompt_tokens": 60, "completion_tokens": 25},
        }
        _call_record_usage_from_openai_payload(provider, data)
        usage = provider.get_pending_usage()
        assert usage is not None
        assert usage.prompt_tokens == 60
        assert usage.completion_tokens == 25
        assert usage.total_tokens == 85

    @staticmethod
    def test_all_zero_usage_leaves_pending_none() -> None:
        """Zero token counts in the usage object must not populate pending usage.

        Mutation caught: if the zero-guard is removed, zero-token cloud
        responses incorrectly set pending_usage and the None assertion fails.

        Oracle: zero usage indicates no tokens were consumed; the provider
        should not surface these as usage events.
        """
        provider = OllamaProvider()
        data: dict[str, Any] = {
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        _call_record_usage_from_openai_payload(provider, data)
        assert provider.get_pending_usage() is None


class TestGenerate:
    """Request framing and response parsing for the /api/generate endpoint."""

    @staticmethod
    def test_request_body_has_stream_false_and_options_nesting() -> None:
        """generate() must post stream=False with options.num_predict wrapping.

        Mutation caught: if stream is omitted or set to True, Ollama would
        return an NDJSON stream and the JSON parser would fail. If
        num_predict is sent at the top level instead of inside options,
        Ollama ignores it and generation length is uncontrolled.

        Oracle: Ollama /api/generate spec requires stream=False for a single
        JSON response and options.num_predict for the token limit.
        """
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": [{"name": "llama3.1:8b"}]})],
            ("POST", "/api/show"): [_json_route(200, {"parameters": "num_ctx 4096", "template": ""})],
            ("POST", "/api/generate"): [
                _json_route(
                    200,
                    {
                        "model": "llama3.1:8b",
                        "response": "Paris.",
                        "done": True,
                        "prompt_eval_count": 10,
                        "eval_count": 3,
                    },
                ),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            loop.run_until_complete(
                provider.generate(
                    "llama3.1:8b",
                    "What is the capital?",
                    temperature=0.3,
                    max_tokens=50,
                ),
            )
            loop.run_until_complete(provider.disconnect())

        req = json.loads(server.get_captured_body("POST", "/api/generate"))
        assert req["model"] == "llama3.1:8b"
        assert req["prompt"] == "What is the capital?"
        assert req["stream"] is False
        assert req["options"]["temperature"] == pytest.approx(0.3)
        assert req["options"]["num_predict"] == 50

    @staticmethod
    def test_response_field_is_returned_verbatim() -> None:
        """generate() must return the server response dict including the response field.

        Mutation caught: if the implementation returns only the usage portion
        or an empty dict, the response-text assertion fails.

        Oracle: Ollama /api/generate returns a JSON object whose ``response``
        field carries the generated text.
        """
        generated_text = "The answer is 42."
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": [{"name": "llama3.1:8b"}]})],
            ("POST", "/api/show"): [_json_route(200, {"parameters": "", "template": ""})],
            ("POST", "/api/generate"): [
                _json_route(
                    200,
                    {
                        "model": "llama3.1:8b",
                        "response": generated_text,
                        "done": True,
                        "prompt_eval_count": 5,
                        "eval_count": 4,
                    },
                ),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            result = loop.run_until_complete(provider.generate("llama3.1:8b", "What is the answer?"))
            loop.run_until_complete(provider.disconnect())

        assert result.get("response") == generated_text
        assert result.get("done") is True

    @staticmethod
    def test_pending_usage_is_set_from_eval_counts() -> None:
        """generate() must populate pending usage from prompt_eval_count and eval_count.

        Mutation caught: if the implementation skips the usage recording step
        after parsing the response, get_pending_usage() returns None and the
        assertion fails.

        Oracle: /api/generate responses carry ``prompt_eval_count`` and
        ``eval_count`` which map to prompt_tokens and completion_tokens.
        """
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": [{"name": "llama3.1:8b"}]})],
            ("POST", "/api/show"): [_json_route(200, {"parameters": "", "template": ""})],
            ("POST", "/api/generate"): [
                _json_route(
                    200,
                    {
                        "model": "llama3.1:8b",
                        "response": "Done.",
                        "done": True,
                        "prompt_eval_count": 20,
                        "eval_count": 7,
                    },
                ),
            ],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            loop.run_until_complete(provider.generate("llama3.1:8b", "Summarize."))
            usage = provider.get_pending_usage()
            loop.run_until_complete(provider.disconnect())

        assert usage is not None
        assert usage.prompt_tokens == 20
        assert usage.completion_tokens == 7
        assert usage.total_tokens == 27

    @staticmethod
    @pytest.mark.asyncio
    async def test_generate_raises_when_not_connected() -> None:
        """generate() must raise ProviderError when the provider is not connected.

        Mutation caught: if the not-connected guard is removed, the method
        would attempt to call _get_client_and_model which raises a different
        error; the specific match string fails.

        Oracle: _MSG_NOT_CONNECTED = "Not connected"; the guard raises this
        unconditionally before any HTTP call is attempted.
        """
        provider = OllamaProvider()
        with pytest.raises(ProviderError, match="Not connected"):
            await provider.generate("llama3.1:8b", "hello")


class TestEmbeddings:
    """Request framing and response parsing for the /api/embeddings endpoint."""

    @staticmethod
    def test_request_body_contains_model_and_prompt() -> None:
        """embeddings() must post model and prompt fields to /api/embeddings.

        Mutation caught: if the implementation sends ``input`` instead of
        ``prompt`` (the OpenAI field name), Ollama ignores the prompt and
        returns an invalid embedding; the exact vector assertion fails.

        Oracle: Ollama /api/embeddings spec requires ``model`` and ``prompt``
        fields in the request body.
        """
        embedding_vector = [0.1, 0.2, 0.3, 0.4, 0.5]
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": [{"name": "nomic-embed-text:latest"}]})],
            ("POST", "/api/show"): [_json_route(200, {"parameters": "", "template": ""})],
            ("POST", "/api/embeddings"): [_json_route(200, {"embedding": embedding_vector})],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))
            result = loop.run_until_complete(
                provider.embeddings("nomic-embed-text:latest", "Hello world"),
            )
            loop.run_until_complete(provider.disconnect())

        req = json.loads(server.get_captured_body("POST", "/api/embeddings"))
        assert req["model"] == "nomic-embed-text:latest"
        assert req["prompt"] == "Hello world"
        assert result.get("embedding") == embedding_vector

    @staticmethod
    @pytest.mark.asyncio
    async def test_embeddings_raises_when_not_connected() -> None:
        """embeddings() must raise ProviderError when the provider is not connected.

        Mutation caught: if the not-connected guard is removed, the method
        would reach _get_client_and_model and raise a different error;
        the specific match string fails.

        Oracle: _MSG_NOT_CONNECTED = "Not connected"; the guard raises this
        before any HTTP call.
        """
        provider = OllamaProvider()
        with pytest.raises(ProviderError, match="Not connected"):
            await provider.embeddings("nomic-embed-text", "hello")


class TestPullModel:
    """NDJSON progress streaming for the /api/pull endpoint."""

    @staticmethod
    def test_yields_all_status_strings_from_ndjson_stream() -> None:
        """pull_model must yield each status string from the NDJSON stream.

        Mutation caught: if the implementation reads ``data.get('message')``
        instead of ``data.get('status')`` from each NDJSON line, the yielded
        strings are empty and the exact-values assertion fails.

        Oracle: Ollama /api/pull streams NDJSON objects; each has a
        ``status`` string field describing the download phase.
        """
        pull_lines: list[dict[str, Any]] = [
            {"status": "pulling manifest"},
            {"status": "downloading layers", "total": 1024, "completed": 256},
            {"status": "verifying sha256 digest"},
            {"status": "success"},
        ]
        routes: dict[tuple[str, str], list[_CannedRoute]] = {
            ("GET", "/api/tags"): [_json_route(200, {"models": [{"name": "llama3.1:8b"}]})],
            ("POST", "/api/show"): [_json_route(200, {"parameters": "", "template": ""})],
            ("POST", "/api/pull"): [_ndjson_route(200, pull_lines)],
        }
        with _CapturingStubServer(routes) as server, _TempEventLoop() as loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            loop.run_until_complete(provider.connect(credentials))

            async def _collect() -> list[str]:
                """Collect all status strings from pull_model.

                Returns:
                    list[str]: All status strings yielded by pull_model.
                """
                return [status async for status in provider.pull_model("llama3.1:8b")]

            statuses = loop.run_until_complete(_collect())
            loop.run_until_complete(provider.disconnect())

        assert statuses == [
            "pulling manifest",
            "downloading layers",
            "verifying sha256 digest",
            "success",
        ]

    @staticmethod
    @pytest.mark.asyncio
    async def test_pull_model_raises_when_local_unavailable() -> None:
        """pull_model must raise ProviderError when local Ollama is unavailable.

        Mutation caught: if the local-availability guard is removed, the
        method proceeds to _iter_pull_progress which raises AttributeError
        on the None client; the specific match string fails.

        Oracle: _ERR_LOCAL_PULL_UNAVAILABLE = "Local Ollama not available
        for model pull"; raised when _local_available is False or
        _local_client is None.
        """
        provider = OllamaProvider()
        with pytest.raises(ProviderError, match="Local Ollama not available for model pull"):
            async for _ in provider.pull_model("llama3.1:8b"):
                pass
