# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The socket layer, which knows about bytes and nothing about routes.

Every request is turned into a :class:`~hexbench.api.Request`, handed to
:meth:`~hexbench.api.Application.handle`, and the returned
:class:`~hexbench.api.Response` is written back. No decision about what a route
means is taken here.

Two settings are deliberate. ``allow_reuse_address`` is switched off because on
Windows ``SO_REUSEADDR`` lets an unrelated process bind a port this server is
already listening on, which for a server that reads and writes files on request
would be a hijack rather than a convenience. And log output goes to a bounded
in-memory ring rather than to standard error, because the process is normally
launched from a desktop shortcut with nowhere for standard error to go, and
because a chatty request log would otherwise interleave with the one line the
entry point prints for a user who has no browser.
"""

from __future__ import annotations

import logging
import threading
import traceback
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Final, cast
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from hexbench.api import Request, Response


if TYPE_CHECKING:
    from hexbench.api import Application


__all__ = ["BenchHTTPServer", "BenchRequestHandler", "bound_url", "build_server"]

_logger = logging.getLogger(__name__)

_DEFAULT_HOST: Final = "127.0.0.1"
_DEFAULT_PORT: Final = 0
_SCHEME: Final = "http://"
_AUTH_QUERY: Final = "token"

_LOG_LIMIT: Final = 512
_DEFAULT_LOG_LINES: Final = 100
_MAX_BODY: Final = 64 * 1024 * 1024
_MAX_CHUNK_LINE: Final = 64 * 1024
_STATUS_TOO_LARGE: Final = 413
_STATUS_INTERNAL: Final = 500
_JSON_TYPE: Final = "application/json; charset=utf-8"
_TOO_LARGE_BODY: Final = b'{"error":{"kind":"too_large","status":413,"message":"the request body exceeds the accepted size"}}'
_INTERNAL_ERROR_BODY: Final = (
    b'{"error":{"kind":"internal","status":500,"message":"an unhandled error occurred while serving the request"}}'
)
_CHUNK_TERMINATOR: Final = b"\r\n"

_SECURITY_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)


def _render_log(client: str, args: tuple[object, ...]) -> str:
    """Render one log call from the request handler as a single line.

    Args:
        client: Identity of the peer the line concerns.
        args: The template and its values, exactly as the handler passed them.

    Returns:
        str: The rendered line, falling back to the joined arguments when the
        template and its values do not agree.
    """
    if not args:
        return client
    template = args[0]
    values = args[1:]
    if isinstance(template, str) and values:
        try:
            rendered = template % values
        except (TypeError, ValueError):
            rendered = " ".join(str(item) for item in args)
    else:
        rendered = " ".join(str(item) for item in args)
    return f"{client} {rendered}"


class BenchRequestHandler(BaseHTTPRequestHandler):
    """Translates between the socket and the routing table."""

    protocol_version = "HTTP/1.1"
    server_version = "hexbench"

    def do_GET(self) -> None:
        """Serve a read request."""
        self._serve(read_body=False)

    def do_POST(self) -> None:
        """Serve a request that carries a body."""
        self._serve(read_body=True)

    def do_DELETE(self) -> None:
        """Serve a delete request."""
        self._serve(read_body=True)

    def log_message(self, *args: object, **_kwargs: object) -> None:
        """Record a line in the server's ring buffer instead of on standard error.

        Args:
            *args: The template and values the base handler supplies.
            **_kwargs: Accepted so no caller of the base signature can fail; the
                base handler passes none.
        """
        server = cast("BenchHTTPServer", self.server)
        server.record(_render_log(self.address_string(), args))

    def _serve(self, *, read_body: bool) -> None:
        """Route one request and write its response.

        Args:
            read_body: Whether the method being served carries a request body.
        """
        body = self._read_body() if read_body else b""
        if body is None:
            self.close_connection = True
            self._send(Response(status=_STATUS_TOO_LARGE, body=_TOO_LARGE_BODY, content_type=_JSON_TYPE))
            return
        server = cast("BenchHTTPServer", self.server)
        parsed = urlsplit(self.path)
        request = Request(
            method=self.command or "",
            path=unquote(parsed.path),
            query=parse_qs(parsed.query, keep_blank_values=True),
            headers=dict(self.headers.items()),
            body=body,
        )
        try:
            response = server.application.handle(request)
        except Exception as exc:
            server.record(
                f"unhandled error serving {self.address_string()} {request.method} {request.path}: {exc!r}\n{traceback.format_exc()}",
            )
            _logger.exception("unhandled error serving %s %s", request.method, request.path)
            self.close_connection = True
            response = Response(status=_STATUS_INTERNAL, body=_INTERNAL_ERROR_BODY, content_type=_JSON_TYPE)
        self._send(response)

    def _read_body(self) -> bytes | None:
        """Read the request body, however the client declared its framing.

        A ``Transfer-Encoding: chunked`` request takes precedence over any
        ``Content-Length`` header, matching how a real HTTP/1.1 client frames
        such a request. Every branch either returns the exact bytes the body
        consists of or fully drains what the client sent before reporting
        failure, so the next request parsed off the same keep-alive connection
        can never desynchronise on bytes this call left unread.

        Returns:
            bytes | None: The body, or ``None`` when the declared or decoded
            length exceeds what this server accepts, or the chunked framing
            is malformed.
        """
        transfer_encoding = self.headers.get("Transfer-Encoding", "")
        if "chunked" in transfer_encoding.lower():
            return self._read_chunked_body()
        declared = self.headers.get("Content-Length")
        if declared is None:
            return b""
        try:
            length = int(declared)
        except ValueError:
            return b""
        if length <= 0:
            return b""
        if length > _MAX_BODY:
            return None
        return self.rfile.read(length)

    def _read_chunked_body(self) -> bytes | None:
        """Decode a ``Transfer-Encoding: chunked`` request body.

        Returns:
            bytes | None: The fully decoded body, or ``None`` when the decoded
            size exceeds what this server accepts, or the chunked framing does
            not parse as valid chunk-size/chunk-data/trailer sequences.
        """
        chunks: list[bytes] = []
        total = 0
        while True:
            line = self.rfile.readline(_MAX_CHUNK_LINE)
            if not line.endswith(_CHUNK_TERMINATOR):
                return None
            size_field = line.split(b";", 1)[0].strip()
            try:
                size = int(size_field, 16)
            except ValueError:
                return None
            if size < 0:
                return None
            if size == 0:
                break
            total += size
            if total > _MAX_BODY:
                return None
            data = self.rfile.read(size)
            if len(data) != size:
                return None
            chunks.append(data)
            if self.rfile.read(len(_CHUNK_TERMINATOR)) != _CHUNK_TERMINATOR:
                return None
        while True:
            trailer_line = self.rfile.readline(_MAX_CHUNK_LINE)
            if not trailer_line.endswith(_CHUNK_TERMINATOR):
                return None
            if trailer_line == _CHUNK_TERMINATOR:
                break
        return b"".join(chunks)

    def _send(self, response: Response) -> None:
        """Write one response to the socket.

        A client that has already gone away makes the write fail; that is
        ordinary during shutdown and is recorded rather than raised.

        Args:
            response: The response to write.
        """
        try:
            self._write(response)
        except OSError as exc:
            self.close_connection = True
            server = cast("BenchHTTPServer", self.server)
            server.record(f"{self.address_string()} write failed: {exc}")

    def _write(self, response: Response) -> None:
        """Write one response's status line, headers and body.

        When the handler has already decided to drop the connection, the
        response says so. Without that header an HTTP/1.1 client keeps the
        socket in its pool and only discovers the closure on the next request
        it tries to send over it.

        Args:
            response: The response to write.
        """
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in (*_SECURITY_HEADERS, *response.headers):
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(response.body)


class BenchHTTPServer(ThreadingHTTPServer):
    """A threaded loopback server bound to one routing table."""

    daemon_threads = True
    allow_reuse_address = False
    application: Application

    def __init__(self, server_address: tuple[str, int], handler: type[BenchRequestHandler], application: Application) -> None:
        """Bind a listening socket and attach the routing table to it.

        Args:
            server_address: Host and port to bind; a port of zero asks the
                operating system to choose one.
            handler: Request handler class to instantiate per connection.
            application: Routing table every request is passed to.
        """
        self.application = application
        self._log: deque[str] = deque(maxlen=_LOG_LIMIT)
        self._log_lock = threading.Lock()
        super().__init__(server_address, handler)

    @property
    def bound_address(self) -> tuple[str, int]:
        """Report the address the listening socket actually holds.

        Returns:
            tuple[str, int]: The bound host and the port the operating system
            assigned, which is the only way to learn the port after binding zero.
        """
        name = self.socket.getsockname()
        return (str(name[0]), int(name[1]))

    def record(self, message: str) -> None:
        """Append one line to the bounded log ring.

        Args:
            message: The line to record.
        """
        with self._log_lock:
            self._log.append(message)

    def recent_log(self, limit: int = _DEFAULT_LOG_LINES) -> tuple[str, ...]:
        """Read the most recent log lines.

        Args:
            limit: Maximum number of lines to return; values below one yield an
                empty result.

        Returns:
            tuple[str, ...]: The lines, oldest first.
        """
        if limit < 1:
            return ()
        with self._log_lock:
            lines = tuple(self._log)
        return lines[-limit:]

    def handle_error(self, request: object, client_address: object) -> None:
        """Record a failure that escaped the routing table.

        The base implementation prints to standard error, which this server does
        not use.

        Args:
            request: The connection being served.
            client_address: Address of the peer being served.
        """
        self.record(f"unhandled error serving {client_address} on {request!r}: {traceback.format_exc()}")


def build_server(application: Application, host: str = _DEFAULT_HOST, port: int = _DEFAULT_PORT) -> BenchHTTPServer:
    """Bind a server for one routing table.

    Args:
        application: Routing table every request is passed to.
        host: Interface to bind; the loopback address by default.
        port: Port to bind; zero asks the operating system to choose a free one,
            which is read back from :attr:`BenchHTTPServer.bound_address`.

    Returns:
        BenchHTTPServer: The bound server, not yet serving.
    """
    return BenchHTTPServer((host, port), BenchRequestHandler, application)


def bound_url(server: BenchHTTPServer, token: str) -> str:
    """Build the address the browser should open.

    Args:
        server: The bound server.
        token: Session token, carried as a query parameter because this is the
            one request that cannot yet set a header.

    Returns:
        str: The complete URL of the application document.
    """
    host, port = server.bound_address
    return f"{_SCHEME}{host}:{port}/?{urlencode({_AUTH_QUERY: token})}"
