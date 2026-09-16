# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live-wire gates: the Anthropic provider never sends sampling params.

The anthropic 1.x SDK removed ``temperature``/``top_p``/``top_k`` from
``AsyncMessages.create``/``stream`` (passing one is a ``TypeError``), and
current Claude models reject them at the API layer.  These gates stand up a
real loopback HTTP server, connect a real ``AnthropicProvider`` through the
real ``anthropic.AsyncAnthropic`` client, and inspect the exact JSON that
reaches the wire.

Falsifiability - each gate fails if the drop is reverted:

* Re-adding ``temperature`` as a direct ``messages.create`` kwarg makes the
  SDK raise ``TypeError`` before any HTTP request, so ``chat()`` /
  ``chat_stream()`` raise and the ``await`` fails.
* Routing ``temperature`` through ``extra_body`` (the other way to reach the
  API) puts a ``"temperature"`` key back into the request body, so the
  ``"temperature" not in body`` assertions fail.
* Dropping ``temperature`` from the provider's public signature makes
  ``chat(..., temperature=...)`` raise ``TypeError`` for an unexpected
  keyword, so the interface stays covered too.

No mocks or SDK substitution: the client makes genuine HTTP calls over the
loopback interface and the assertions read the bytes the SDK actually sent.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.types import Message, ProviderCredentials, ThinkingConfig
from intellicrack.providers.anthropic import AnthropicProvider


if TYPE_CHECKING:
    from collections.abc import Iterator

_MODEL_ID = "claude-opus-4-5"
_MODELS_SUFFIX = "/v1/models"
_MESSAGES_SUFFIX = "/v1/messages"


def _models_page_body() -> bytes:
    """Build the JSON body for a ``GET /v1/models`` probe.

    Returns:
        bytes: A single-page models listing the SDK's ``models.list`` accepts.
    """
    return json.dumps(
        {
            "data": [
                {
                    "id": _MODEL_ID,
                    "type": "model",
                    "display_name": "Claude Opus 4.5",
                    "created_at": "2025-11-01T00:00:00Z",
                },
            ],
            "has_more": False,
            "first_id": _MODEL_ID,
            "last_id": _MODEL_ID,
        },
    ).encode()


def _message_json_body(*, text: str) -> bytes:
    """Build a non-streaming ``messages`` JSON response body.

    Args:
        text: Assistant text returned in the single content block.

    Returns:
        bytes: A complete Anthropic ``message`` object as UTF-8 JSON.
    """
    return json.dumps(
        {
            "id": "msg_live_01",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
            "model": _MODEL_ID,
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 3, "output_tokens": 2},
        },
    ).encode()


def _message_sse_body(*, texts: list[str]) -> bytes:
    r"""Build a streaming ``messages`` SSE response body.

    Emits a minimal but complete event sequence: ``message_start``,
    ``content_block_start``, one ``content_block_delta`` per fragment,
    ``content_block_stop``, ``message_delta``, and ``message_stop``.

    Args:
        texts: Text fragments emitted as ``text_delta`` events.

    Returns:
        bytes: UTF-8 encoded ``text/event-stream`` body.
    """

    def _event(event_type: str, payload: dict[str, Any]) -> str:
        return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"

    frames: list[str] = [
        _event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_live_stream",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": _MODEL_ID,
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 3, "output_tokens": 0},
                },
            },
        ),
        _event(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        ),
    ]
    frames.extend(
        _event(
            "content_block_delta",
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": fragment}},
        )
        for fragment in texts
    )
    frames.extend(
        [
            _event("content_block_stop", {"type": "content_block_stop", "index": 0}),
            _event(
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": len(texts)},
                },
            ),
            _event("message_stop", {"type": "message_stop"}),
        ],
    )
    return "".join(frames).encode()


class _AnthropicRecordingServer:
    """A loopback HTTP server that records ``messages`` request bodies.

    Answers the SDK's model probe and both streaming and non-streaming
    ``messages`` calls, capturing every POST body sent to a ``/v1/messages``
    path so tests can assert on the exact wire payload.

    Attributes:
        message_bodies: Decoded JSON of every ``/v1/messages`` request body,
            in arrival order.
    """

    message_bodies: list[dict[str, Any]]

    def __init__(self, stream_texts: list[str], reply_text: str) -> None:
        """Start the server on an ephemeral loopback port.

        Args:
            stream_texts: Fragments emitted for streaming ``messages`` calls.
            reply_text: Assistant text for non-streaming ``messages`` calls.
        """
        self.message_bodies = []
        recorder = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, body: bytes, content_type: str) -> None:
                self.send_response(200)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                _ = self.wfile.write(body)

            def do_GET(self) -> None:
                """Answer the SDK model probe; 404 everything else."""
                if self.path.split("?", 1)[0].endswith(_MODELS_SUFFIX):
                    self._send(_models_page_body(), "application/json")
                    return
                self.send_error(404)

            def do_POST(self) -> None:
                """Record the messages request body and reply JSON or SSE."""
                length = int(self.headers.get("content-length", "0"))
                raw = self.rfile.read(length)
                if not self.path.split("?", 1)[0].endswith(_MESSAGES_SUFFIX):
                    self.send_error(404)
                    return
                payload: dict[str, Any] = json.loads(raw)
                recorder.message_bodies.append(payload)
                if payload.get("stream") is True:
                    self._send(_message_sse_body(texts=stream_texts), "text/event-stream")
                else:
                    self._send(_message_json_body(text=reply_text), "application/json")

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Suppress the default stderr request logging.

                Args:
                    *args: Positional log arguments (unused).
                    **kwargs: Keyword log arguments (unused).
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        """The ``/anthropic``-prefixed base URL for the SDK client.

        Returns:
            str: A base URL whose ``/v1/...`` children this server answers.
        """
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host}:{port}/anthropic"

    def shutdown(self) -> None:
        """Stop serving and join the background thread."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5.0)


@pytest.fixture
def recording_server() -> Iterator[_AnthropicRecordingServer]:
    """Provide a running loopback Anthropic server, torn down after the test.

    Yields:
        _AnthropicRecordingServer: A live server recording request bodies.
    """
    server = _AnthropicRecordingServer(stream_texts=["po", "ng"], reply_text="pong")
    try:
        yield server
    finally:
        server.shutdown()


async def _connected_provider(server: _AnthropicRecordingServer) -> AnthropicProvider:
    """Connect a real ``AnthropicProvider`` to the loopback server.

    Args:
        server: The running recording server to target.

    Returns:
        AnthropicProvider: A connected provider whose client hits ``server``.
    """
    provider = AnthropicProvider()
    await provider.connect(ProviderCredentials(api_key="offline-test-key", api_base=server.base_url))
    return provider


def _last_messages_body(server: _AnthropicRecordingServer) -> dict[str, Any]:
    """Return the most recent ``/v1/messages`` request body.

    Args:
        server: The recording server.

    Returns:
        dict[str, Any]: The decoded JSON of the last messages request.
    """
    assert server.message_bodies, "no /v1/messages request reached the server"
    return server.message_bodies[-1]


def _assert_no_sampling_params(body: dict[str, Any]) -> None:
    """Assert the wire body carries none of the removed sampling params.

    Args:
        body: A decoded ``/v1/messages`` request body.
    """
    for banned in ("temperature", "top_p", "top_k"):
        assert banned not in body, f"{banned!r} must not be forwarded to the Anthropic API, wire body was {body}"


@pytest.mark.asyncio
async def test_chat_does_not_forward_temperature_to_wire(
    recording_server: _AnthropicRecordingServer,
) -> None:
    """chat() with an explicit temperature succeeds and omits it from the body.

    Passing ``temperature=0.33`` proves the provider still accepts the
    cross-provider ``temperature`` argument, while the recorded wire body
    proves it is dropped rather than forwarded (as a kwarg or via
    ``extra_body``).
    """
    provider = await _connected_provider(recording_server)
    try:
        message, tool_calls = await provider.chat(
            messages=[Message(role="user", content="ping")],
            model=_MODEL_ID,
            temperature=0.33,
            max_tokens=32,
        )
    finally:
        await provider.disconnect()

    assert message.content == "pong"
    assert tool_calls is None

    body = _last_messages_body(recording_server)
    assert body["model"] == _MODEL_ID
    assert body["max_tokens"] == 32
    assert isinstance(body["messages"], list), "messages must reach the wire as a list"
    assert body["messages"], "messages must reach the wire"
    _assert_no_sampling_params(body)


@pytest.mark.asyncio
async def test_chat_stream_does_not_forward_temperature_to_wire(
    recording_server: _AnthropicRecordingServer,
) -> None:
    """chat_stream() with an explicit temperature streams text and omits it.

    Drives the ``messages.stream`` path (a distinct SDK call site from
    ``messages.create``) and asserts both the streamed text and the absence
    of sampling params from the streaming request body.
    """
    provider = await _connected_provider(recording_server)
    try:
        collected: list[str] = [
            chunk
            async for chunk in provider.chat_stream(
                messages=[Message(role="user", content="ping")],
                model=_MODEL_ID,
                temperature=0.9,
                max_tokens=32,
            )
        ]
    finally:
        await provider.disconnect()

    assert collected == ["po", "ng"]

    body = _last_messages_body(recording_server)
    assert body.get("stream") is True, "chat_stream must issue a streaming request"
    _assert_no_sampling_params(body)


@pytest.mark.asyncio
async def test_thinking_request_omits_temperature_but_keeps_thinking(
    recording_server: _AnthropicRecordingServer,
) -> None:
    """Thinking-enabled chat() sends the thinking block and no temperature.

    The old-style thinking path used to pin ``temperature=1.0``; the wire
    body must now carry the ``thinking`` config and an inflated
    ``max_tokens`` while sending no sampling params at all.
    """
    provider = await _connected_provider(recording_server)
    try:
        await provider.chat(
            messages=[Message(role="user", content="ping")],
            model=_MODEL_ID,
            temperature=0.5,
            max_tokens=100,
            thinking=ThinkingConfig(enabled=True, budget_tokens=5000),
        )
    finally:
        await provider.disconnect()

    body = _last_messages_body(recording_server)
    assert body["thinking"] == {"type": "enabled", "budget_tokens": 5000}
    assert body["max_tokens"] == 5000 + 1024, "thinking must inflate max_tokens to budget + 1024"
    _assert_no_sampling_params(body)
