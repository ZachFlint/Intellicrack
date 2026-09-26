# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A loopback HTTP server that replays scripted provider responses.

Tests point a real provider SDK at this server, so every request travels
through the SDK's own HTTP stack and every response is parsed from real bytes:
JSON bodies, error bodies, and ``text/event-stream`` bodies alike. Each request
the server receives is recorded with its method, path, headers and decoded
JSON body, so a test can assert on exactly what reached the wire.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Self, cast


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from types import TracebackType


@dataclass(frozen=True, slots=True)
class ScriptedResponse:
    """One canned HTTP response.

    Attributes:
        status: HTTP status code.
        body: Raw response body bytes.
        content_type: Value of the ``Content-Type`` header.
        headers: Extra response headers.
    """

    status: int
    body: bytes
    content_type: str = "application/json"
    headers: Mapping[str, str] = field(default_factory=dict[str, str])


@dataclass(frozen=True, slots=True)
class ReceivedRequest:
    """One request the server received.

    Attributes:
        method: HTTP method.
        path: Request path including any query string.
        headers: Request headers, with lower-cased names.
        body: The decoded JSON body, or ``None`` when the body was empty.
    """

    method: str
    path: str
    headers: dict[str, str]
    body: Any


def json_response(payload: object, *, status: int = 200) -> ScriptedResponse:
    """Build a JSON response.

    Args:
        payload: The JSON-serialisable body.
        status: HTTP status code.

    Returns:
        ScriptedResponse: The canned response.
    """
    return ScriptedResponse(status=status, body=json.dumps(payload).encode())


def sse_response(events: Sequence[Mapping[str, object]], *, named: bool = True, done_marker: bool = False) -> ScriptedResponse:
    """Build a ``text/event-stream`` response from event payloads.

    Args:
        events: Event payloads, each carrying a ``type`` field.
        named: Whether each frame carries an ``event:`` line naming its type.
        done_marker: Whether the stream ends with a ``data: [DONE]`` frame.

    Returns:
        ScriptedResponse: The canned streaming response.
    """
    frames: list[str] = []
    for event in events:
        prefix = f"event: {event['type']}\n" if named and "type" in event else ""
        frames.append(f"{prefix}data: {json.dumps(event)}\n\n")
    if done_marker:
        frames.append("data: [DONE]\n\n")
    return ScriptedResponse(status=200, body="".join(frames).encode(), content_type="text/event-stream")


class ScriptedHTTPServer:
    """Serve scripted responses on a loopback port and record every request.

    Routes are keyed by ``(method, path)`` where ``path`` excludes the query
    string. A route may hold several responses, which are served in order;
    the last one repeats once the others are used up.
    """

    def __init__(self, routes: Mapping[tuple[str, str], ScriptedResponse | Sequence[ScriptedResponse]]) -> None:
        """Start the server.

        Args:
            routes: Responses keyed by ``(method, path)``.
        """
        self._lock = threading.Lock()
        self._routes: dict[tuple[str, str], list[ScriptedResponse]] = {
            key: [value] if isinstance(value, ScriptedResponse) else list(value) for key, value in routes.items()
        }
        self._requests: list[ReceivedRequest] = []
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(length) if length else b""
                owner.record(
                    ReceivedRequest(
                        method=self.command,
                        path=self.path,
                        headers={name.lower(): value for name, value in self.headers.items()},
                        body=json.loads(raw) if raw else None,
                    ),
                )
                response = owner.response_for(self.command, self.path.split("?", 1)[0])
                self.send_response(response.status)
                self.send_header("Content-Type", response.content_type)
                self.send_header("Content-Length", str(len(response.body)))
                for name, value in response.headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(response.body)

            def do_GET(self) -> None:
                self._serve()

            def do_POST(self) -> None:
                self._serve()

            def log_message(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        """The server's ``http://127.0.0.1:<port>`` origin.

        Returns:
            str: The origin URL.
        """
        host, port = cast("tuple[str, int]", self._server.server_address)
        return f"http://{host}:{port}"

    def record(self, request: ReceivedRequest) -> None:
        """Record one received request.

        Args:
            request: The request to record.
        """
        with self._lock:
            self._requests.append(request)

    def response_for(self, method: str, path: str) -> ScriptedResponse:
        """Pick the scripted response for a request.

        Args:
            method: HTTP method.
            path: Request path without its query string.

        Returns:
            ScriptedResponse: The next scripted response, or a 404 JSON error
            when no route matches.
        """
        with self._lock:
            queue = self._routes.get((method, path))
            if not queue:
                return json_response({"error": {"message": f"no route for {method} {path}"}}, status=404)
            return queue.pop(0) if len(queue) > 1 else queue[0]

    def requests(self, path: str | None = None) -> list[ReceivedRequest]:
        """Return the recorded requests, optionally filtered by path.

        Args:
            path: Only return requests whose path, without query string,
                equals this value.

        Returns:
            list[ReceivedRequest]: The matching requests in arrival order.
        """
        with self._lock:
            snapshot = list(self._requests)
        return [request for request in snapshot if path is None or request.path.split("?", 1)[0] == path]

    def close(self) -> None:
        """Stop serving and release the port."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> Self:
        """Enter the context manager.

        Returns:
            Self: This server.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop the server on context exit.

        Args:
            exc_type: The exception type, if any.
            exc: The exception, if any.
            traceback: The traceback, if any.
        """
        self.close()
