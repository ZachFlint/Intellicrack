# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loopback HTTP endpoint that answers each request with the next scripted reply.

Wire-format tests need a real HTTP peer: the provider under test must open a
real connection, send a real JSON body and read a real byte stream -- a
server-sent-event stream in particular, whose framing is exactly what a
dialect's stream parser has to survive. This server answers every ``POST`` or
``GET`` with the next reply from a queue the test supplies, streaming the reply
body in the chunks it was given, and records each request's path, headers and
decoded JSON body so the test can assert on what actually went over the wire.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Final, Self


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from types import TracebackType


_SHUTDOWN_JOIN_SECONDS: Final[float] = 5.0
_HTTP_INTERNAL_ERROR: Final[int] = 500


@dataclass(frozen=True)
class ScriptedReply:
    """One reply the endpoint sends.

    Attributes:
        chunks: The body, as the byte chunks to write and flush one by one.
        status: HTTP status code.
        content_type: ``Content-Type`` of the body.
    """

    chunks: tuple[bytes, ...]
    status: int = 200
    content_type: str = "application/json"


@dataclass(frozen=True)
class CapturedRequest:
    """One request the endpoint received.

    Attributes:
        method: HTTP method.
        path: Request path, including any query string.
        headers: Request headers keyed by lower-cased name.
        body: The decoded JSON body, or ``None`` when there was none.
    """

    method: str
    path: str
    headers: dict[str, str]
    body: Any = field(default=None)


def sse_reply(events: Iterable[Mapping[str, Any]], *, named: bool = True, done: bool = False) -> ScriptedReply:
    """Frame JSON events as a ``text/event-stream`` reply, one chunk per event.

    Args:
        events: The event payloads, each carrying its ``type`` when ``named``.
        named: Whether each frame carries an ``event:`` line naming the
            payload's ``type``, as Anthropic and OpenAI Responses send.
        done: Whether to finish with the ``data: [DONE]`` sentinel Chat
            Completions sends.

    Returns:
        ScriptedReply: The streaming reply.
    """
    chunks: list[bytes] = []
    for event in events:
        frame = f"data: {json.dumps(event)}\n\n"
        if named:
            frame = f"event: {event.get('type', 'message')}\n{frame}"
        chunks.append(frame.encode())
    if done:
        chunks.append(b"data: [DONE]\n\n")
    return ScriptedReply(chunks=tuple(chunks), content_type="text/event-stream")


def json_reply(payload: Mapping[str, Any], *, status: int = 200) -> ScriptedReply:
    """Build a single-chunk JSON reply.

    Args:
        payload: The JSON body.
        status: HTTP status code.

    Returns:
        ScriptedReply: The reply.
    """
    return ScriptedReply(chunks=(json.dumps(payload).encode(),), status=status)


class ScriptedHttpEndpoint:
    """A loopback server replying from a queue and recording every request.

    Use as a context manager; the server listens on an ephemeral loopback port
    for the lifetime of the ``with`` block.

    Attributes:
        requests: Every request received, in arrival order.
    """

    def __init__(self, replies: Iterable[ScriptedReply]) -> None:
        """Queue the replies the endpoint will send, in order.

        Args:
            replies: One reply per expected request.
        """
        self._replies: deque[ScriptedReply] = deque(replies)
        self._lock = threading.Lock()
        self.requests: list[CapturedRequest] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        """The server origin, with a trailing slash.

        Returns:
            str: ``http://127.0.0.1:<port>/``.
        """
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}/"

    def _next_reply(self) -> ScriptedReply:
        """Pop the next queued reply.

        Returns:
            ScriptedReply: The reply, or a 500 when the queue ran dry.
        """
        with self._lock:
            if self._replies:
                return self._replies.popleft()
        return json_reply({"error": {"message": "no scripted reply left"}}, status=_HTTP_INTERNAL_ERROR)

    def _record(self, request: CapturedRequest) -> None:
        """Record one received request.

        Args:
            request: The request.
        """
        with self._lock:
            self.requests.append(request)

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        """Build the request handler bound to this endpoint.

        Returns:
            type[BaseHTTPRequestHandler]: The handler class.
        """
        endpoint = self

        class _Handler(BaseHTTPRequestHandler):
            """Answers every request with the endpoint's next scripted reply."""

            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Silence the default stderr access log.

                Args:
                    *args: Positional log arguments (unused).
                    **kwargs: Keyword log arguments (unused).
                """

            def _serve(self) -> None:
                """Record the request and stream the next reply."""
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                body: Any = json.loads(raw) if raw else None
                endpoint._record(
                    CapturedRequest(
                        method=self.command,
                        path=self.path,
                        headers={name.lower(): value for name, value in self.headers.items()},
                        body=body,
                    ),
                )
                reply = endpoint._next_reply()
                self.send_response(reply.status)
                self.send_header("Content-Type", reply.content_type)
                self.send_header("Content-Length", str(sum(len(chunk) for chunk in reply.chunks)))
                self.end_headers()
                for chunk in reply.chunks:
                    self.wfile.write(chunk)
                    self.wfile.flush()

            def do_POST(self) -> None:
                """Serve a ``POST``."""
                self._serve()

            def do_GET(self) -> None:
                """Serve a ``GET``."""
                self._serve()

        return _Handler

    def __enter__(self) -> Self:
        """Start serving.

        Returns:
            Self: This endpoint.
        """
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop serving and release the socket.

        Args:
            exc_type: The exception type, if the block raised.
            exc: The exception, if the block raised.
            traceback: The traceback, if the block raised.
        """
        del exc_type, exc, traceback
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=_SHUTDOWN_JOIN_SECONDS)
