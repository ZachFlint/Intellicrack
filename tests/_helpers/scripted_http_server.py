# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loopback HTTP server that answers each request from a per-route script.

Provider HTTP layers are only trustworthy when they are driven against real
bytes on a real socket. This server listens on the loopback interface, records
every request it receives (method, path, query, headers and body), and answers
each one with the next scripted response for its route. A scripted response is
written with ``Transfer-Encoding: chunked`` one chunk at a time, so a test can
emit a genuine server-sent-event stream, pause between events, or gate a chunk
on a :class:`threading.Event` to interleave two concurrent streams.

A route's script can also be a callable, which lets a test answer the way the
real service does depending on the request (for example Gemini returning SSE
only when the request carries ``?alt=sse``).
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Final, Self
from urllib.parse import parse_qs, urlsplit

from intellicrack.core.json_payload import is_json_object


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType


_HTTP_NOT_FOUND: Final[int] = 404
_SHUTDOWN_JOIN_SECONDS: Final[float] = 5.0


@dataclass(frozen=True)
class RecordedRequest:
    """One request received by :class:`ScriptedHttpServer`.

    Attributes:
        method: HTTP method.
        path: Request path without the query string.
        query: Query parameters, each name mapped to its values in order.
        headers: Request headers keyed by lower-cased header name.
        body: Raw request body bytes.
    """

    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes

    def json_object(self) -> dict[str, Any]:
        """Decode the request body as a JSON object.

        Returns:
            dict[str, Any]: The decoded body.

        Raises:
            TypeError: If the body is not a JSON object.
        """
        decoded: object = json.loads(self.body)
        if not is_json_object(decoded):
            msg = f"request body is {type(decoded).__name__}, not a JSON object"
            raise TypeError(msg)
        return decoded


@dataclass(frozen=True)
class ScriptedResponse:
    """One scripted HTTP response.

    Attributes:
        status: HTTP status code.
        headers: Response headers, in order.
        chunks: Body chunks, each written and flushed as its own HTTP chunk.
        chunk_delay: Seconds to sleep before writing every chunk after the first.
        gates: Chunk index mapped to an event the server waits on before
            writing that chunk.
        signals: Chunk index mapped to an event the server sets once that
            chunk has been written and flushed.
    """

    status: int = 200
    headers: tuple[tuple[str, str], ...] = (("content-type", "application/json"),)
    chunks: tuple[bytes, ...] = ()
    chunk_delay: float = 0.0
    gates: dict[int, threading.Event] = field(default_factory=dict)
    signals: dict[int, threading.Event] = field(default_factory=dict)


type ScriptEntry = ScriptedResponse | Callable[[RecordedRequest], ScriptedResponse]
"""A fixed response, or a function computing the response from the request."""


def json_response(status: int, payload: object, headers: Sequence[tuple[str, str]] = ()) -> ScriptedResponse:
    """Build a single-chunk JSON response.

    Args:
        status: HTTP status code.
        payload: The JSON-serializable body.
        headers: Extra response headers.

    Returns:
        ScriptedResponse: The response.
    """
    return ScriptedResponse(
        status=status,
        headers=(("content-type", "application/json"), *headers),
        chunks=(json.dumps(payload).encode(),),
    )


def sse_response(
    events: Sequence[bytes],
    *,
    chunk_delay: float = 0.0,
    gates: dict[int, threading.Event] | None = None,
    signals: dict[int, threading.Event] | None = None,
) -> ScriptedResponse:
    """Build a ``text/event-stream`` response from pre-framed event bytes.

    Args:
        events: Wire bytes, one element per chunk, already framed as SSE.
        chunk_delay: Seconds to sleep before every chunk after the first.
        gates: Chunk index mapped to an event awaited before that chunk.
        signals: Chunk index mapped to an event set after that chunk.

    Returns:
        ScriptedResponse: The response.
    """
    return ScriptedResponse(
        status=200,
        headers=(("content-type", "text/event-stream"), ("cache-control", "no-cache")),
        chunks=tuple(events),
        chunk_delay=chunk_delay,
        gates=dict(gates or {}),
        signals=dict(signals or {}),
    )


class ScriptedHttpServer:
    """Loopback server answering each route from a queue of scripted responses."""

    def __init__(self) -> None:
        """Start serving on an ephemeral loopback port."""
        self._requests: list[RecordedRequest] = []
        self._scripts: dict[tuple[str, str], deque[ScriptEntry]] = {}
        self._lock = threading.Lock()
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                """Answer a GET request from the script."""
                self._answer("GET")

            def do_POST(self) -> None:
                """Answer a POST request from the script."""
                self._answer("POST")

            def _answer(self, method: str) -> None:
                """Record the request and write its scripted response.

                Args:
                    method: The HTTP method being answered.
                """
                split = urlsplit(self.path)
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                request = RecordedRequest(
                    method=method,
                    path=split.path,
                    query=parse_qs(split.query, keep_blank_values=True),
                    headers={name.lower(): value for name, value in self.headers.items()},
                    body=body,
                )
                response = server.take(request)
                self.send_response(response.status)
                for name, value in response.headers:
                    self.send_header(name, value)
                self.send_header("transfer-encoding", "chunked")
                self.end_headers()
                for index, chunk in enumerate(response.chunks):
                    gate = response.gates.get(index)
                    if gate is not None:
                        _ = gate.wait(timeout=10.0)
                    if index and response.chunk_delay:
                        time.sleep(response.chunk_delay)
                    if chunk:
                        _ = self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        self.wfile.flush()
                    signal = response.signals.get(index)
                    if signal is not None:
                        signal.set()
                _ = self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Suppress the default stderr request logging.

                Args:
                    *args: Positional log arguments (unused).
                    **kwargs: Keyword log arguments (unused).
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="scripted-http-server", daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        """The server origin, for example ``http://127.0.0.1:50123``.

        Returns:
            str: Scheme, host and port without a trailing slash.
        """
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host!s}:{port}"

    def script(self, method: str, path: str, *entries: ScriptEntry) -> None:
        """Queue responses for one route, answered in order.

        Args:
            method: HTTP method of the route.
            path: Request path of the route, without the query string.
            *entries: Responses, or callables computing them, in answer order.
        """
        with self._lock:
            self._scripts.setdefault((method, path), deque()).extend(entries)

    def take(self, request: RecordedRequest) -> ScriptedResponse:
        """Record a request and pop the next scripted response for its route.

        Args:
            request: The received request.

        Returns:
            ScriptedResponse: The scripted response, or a ``404`` when the
            route has nothing left.
        """
        with self._lock:
            self._requests.append(request)
            queue = self._scripts.get((request.method, request.path))
            entry = queue.popleft() if queue else None
        if entry is None:
            return json_response(_HTTP_NOT_FOUND, {"error": {"message": f"unscripted {request.method} {request.path}"}})
        return entry if isinstance(entry, ScriptedResponse) else entry(request)

    def requests(self, path: str | None = None) -> list[RecordedRequest]:
        """Return a snapshot of received requests.

        Args:
            path: Only return requests for this exact path when given.

        Returns:
            list[RecordedRequest]: Requests in arrival order.
        """
        with self._lock:
            snapshot = list(self._requests)
        return snapshot if path is None else [request for request in snapshot if request.path == path]

    def shutdown(self) -> None:
        """Stop serving and release the port."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=_SHUTDOWN_JOIN_SECONDS)

    def __enter__(self) -> Self:
        """Enter the context manager.

        Returns:
            Self: This running server.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Shut the server down when leaving the context manager.

        Args:
            exc_type: Exception type raised inside the block, if any.
            exc_value: Exception raised inside the block, if any.
            traceback: Traceback of that exception, if any.
        """
        self.shutdown()
