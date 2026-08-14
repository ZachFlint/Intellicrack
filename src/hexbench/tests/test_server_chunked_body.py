# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""A ``Transfer-Encoding: chunked`` request body must be read, not silently dropped.

``BenchRequestHandler._read_body`` used to consult only ``Content-Length``. A
standard HTTP/1.1 client that streams a request body sends
``Transfer-Encoding: chunked`` instead and omits ``Content-Length`` entirely,
so the handler returned an empty body without reading a single byte off the
socket -- while the real chunk-framed bytes stayed sitting unread in the
connection's receive buffer. Because the connection was then kept alive for
another request, that leftover framing corrupted the *next* request parsed off
the same socket.

This is exercised over a genuine loopback socket, not the in-process
:class:`~hexbench.api.Application` shortcut every other suite uses, because
the defect only exists at the byte level: it is about what the handler reads
off ``self.rfile``, not about routing.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import unittest
from contextlib import ExitStack
from typing import TYPE_CHECKING, Final

from hexbench.api import Application
from hexbench.jobs import JobQueue
from hexbench.registry import Registry
from hexbench.server import BenchHTTPServer, build_server
from hexbench.tests._support import PACKAGE_ROOT, SESSION_TOKEN, Assertions


if TYPE_CHECKING:
    from hexbench.codec import JsonValue


_HOST: Final = "127.0.0.1"
_STATIC_ROOT: Final = PACKAGE_ROOT / "static"
_WORKERS: Final = 2
_SOCKET_TIMEOUT: Final = 10.0
_POLL_INTERVAL: Final = 0.05
_JOIN_TIMEOUT: Final = 10.0

_OK: Final = 200
_TOO_LARGE: Final = 413
_AUTH_HEADER: Final = "X-Hexbench-Token"
_SAMPLE_BYTES: Final = bytes(range(40))
_CHUNK_SIZE: Final = 9


class _LiveServer:
    """A hexbench application bound to a real loopback socket, serving on a thread."""

    def __init__(self) -> None:
        """Bind an application to a free port and start serving it."""
        self._registry = Registry()
        self._jobs = JobQueue(_WORKERS)

        def _stop() -> None:
            self._server.shutdown()

        self._application = Application(self._registry, self._jobs, static_root=_STATIC_ROOT, token=SESSION_TOKEN, shutdown=_stop)
        self._server: BenchHTTPServer = build_server(self._application, _HOST, 0)
        self._application.bind(self._server.bound_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": _POLL_INTERVAL},
            name="hexbench-chunked-body-test-server",
            daemon=True,
        )
        self._thread.start()

    @property
    def port(self) -> int:
        """Report the port the operating system assigned.

        Returns:
            int: The bound port.
        """
        return self._server.bound_address[1]

    @property
    def host_header(self) -> str:
        """The ``Host`` header value this server requires.

        Returns:
            str: Loopback address and bound port.
        """
        return f"{_HOST}:{self.port}"

    def close(self) -> None:
        """Stop serving and release every resource this server holds."""
        self._server.shutdown()
        self._thread.join(_JOIN_TIMEOUT)
        self._server.server_close()
        self._jobs.shutdown()
        self._registry.shutdown()


def _live_server(stack: ExitStack) -> _LiveServer:
    """Start a live server and register its teardown on an exit stack.

    Args:
        stack: Exit stack the caller is already unwinding on cleanup.

    Returns:
        _LiveServer: The running server.
    """
    live = _LiveServer()
    stack.callback(live.close)
    return live


def _chunk_encode(payload: bytes, chunk_size: int) -> bytes:
    """Frame a payload as an HTTP/1.1 chunked transfer body.

    Args:
        payload: Bytes to frame.
        chunk_size: Maximum size of each chunk, forcing several chunks for a
            payload larger than one, so multi-chunk parsing is exercised.

    Returns:
        bytes: The chunk-framed body, including the terminating zero chunk.
    """
    framed: list[bytes] = []
    for start in range(0, len(payload), chunk_size):
        piece = payload[start : start + chunk_size]
        framed.extend((f"{len(piece):x}\r\n".encode("ascii"), piece, b"\r\n"))
    framed.append(b"0\r\n\r\n")
    return b"".join(framed)


def _request_line_headers(method: str, path: str, host: str, extra: dict[str, str]) -> bytes:
    """Render an HTTP/1.1 request line and header block.

    Args:
        method: HTTP method.
        path: Request path.
        host: Value for the ``Host`` header.
        extra: Additional headers to send, in order.

    Returns:
        bytes: The request line and headers, ending in the blank line that
        separates them from the body.
    """
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", f"{_AUTH_HEADER}: {SESSION_TOKEN}"]
    lines.extend(f"{name}: {value}" for name, value in extra.items())
    lines.extend(("", ""))
    return "\r\n".join(lines).encode("ascii")


class ChunkedRequestBodyTests(Assertions, unittest.TestCase):
    """A chunked request body must reach the application, and leave the socket in sync."""

    def test_chunked_body_reaches_the_operation_and_keeps_the_connection_in_sync(self) -> None:
        """The server must decode the chunked body and answer the next request on the same connection correctly."""
        with ExitStack() as stack:
            live = _live_server(stack)
            sock = socket.create_connection((_HOST, live.port), timeout=_SOCKET_TIMEOUT)
            stack.callback(sock.close)

            body = json.dumps({"arguments": {"data": _SAMPLE_BYTES.hex()}}).encode("utf-8")
            request = _request_line_headers(
                "POST",
                "/api/op/open_bytes",
                live.host_header,
                {"Transfer-Encoding": "chunked", "Connection": "keep-alive"},
            )
            sock.sendall(request + _chunk_encode(body, _CHUNK_SIZE))

            first = http.client.HTTPResponse(sock)
            first.begin()
            self.equal(first.status, _OK, "status of the chunked open_bytes request")
            payload = json.loads(first.read())
            created_handle = payload.get("created_handle")
            self.require(isinstance(created_handle, str) and created_handle, "response carries no created_handle")
            document = payload.get("document")
            self.require(isinstance(document, dict), "response carries no document object")
            self.equal(document.get("length"), len(_SAMPLE_BYTES), "length of the document opened over the chunked body")
            self.falsy(first.will_close, "server closed the connection after a well-formed chunked request")

            second_request = _request_line_headers("GET", "/api/documents", live.host_header, {"Connection": "keep-alive"})
            sock.sendall(second_request)
            second = http.client.HTTPResponse(sock)
            second.begin()
            self.equal(second.status, _OK, "status of the follow-up request on the same connection")
            listed: JsonValue = json.loads(second.read())
            self.require(isinstance(listed, list), "document listing is not a JSON array")
            entries: list[JsonValue] = listed if isinstance(listed, list) else []
            handles = [entry["handle"] for entry in entries if isinstance(entry, dict) and "handle" in entry]
            self.contains(created_handle, handles, "handles reported by the follow-up request")

    def test_malformed_chunk_framing_is_rejected_and_the_connection_is_closed(self) -> None:
        """Garbage chunk-size framing must fail cleanly rather than hang or desync the connection."""
        with ExitStack() as stack:
            live = _live_server(stack)
            sock = socket.create_connection((_HOST, live.port), timeout=_SOCKET_TIMEOUT)
            stack.callback(sock.close)

            request = _request_line_headers("POST", "/api/documents", live.host_header, {"Transfer-Encoding": "chunked"})
            sock.sendall(request + b"not-a-hex-chunk-size\r\n\r\n")

            response = http.client.HTTPResponse(sock)
            response.begin()
            self.equal(response.status, _TOO_LARGE, "status for malformed chunk framing")
            response.read()
            self.truthy(response.will_close, "server did not mark the connection for closure after malformed framing")
            remainder = sock.recv(1)
            self.equal(remainder, b"", "socket produced more bytes after a connection the server marked for closure")


if __name__ == "__main__":
    unittest.main()
