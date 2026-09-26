# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loopback servers that misbehave the way real networks do.

* :class:`StallingServer` accepts TCP connections, reads whatever arrives and
  never answers. Used as an origin it models a server that hangs after the
  handshake; used as ``HTTPS_PROXY`` it models a proxy that never completes
  ``CONNECT``, which stalls every HTTPS client in the process that has no
  timeout of its own.
* :class:`ScriptedHttpServer` answers every ``GET`` with a fixed status and
  body, optionally trickling the body out one chunk at a time, and counts the
  requests it receives.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Final, Protocol, Self


if TYPE_CHECKING:
    from types import TracebackType


_JOIN_SECONDS: Final[float] = 5.0
_ACCEPT_POLL_SECONDS: Final[float] = 0.1
_RECV_BYTES: Final[int] = 65536


class StallingServer:
    """A TCP listener that accepts connections and never responds."""

    def __init__(self) -> None:
        """Bind to an ephemeral loopback port and start accepting."""
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(_ACCEPT_POLL_SECONDS)
        self._held: list[socket.socket] = []
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="stalling-server", daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        """The server's ``http://`` origin.

        Returns:
            str: ``http://127.0.0.1:<port>``.
        """
        port: int = self._listener.getsockname()[1]
        return f"http://127.0.0.1:{port}"

    @property
    def connections(self) -> int:
        """How many connections have been accepted so far.

        Returns:
            int: The accepted connection count.
        """
        with self._lock:
            return len(self._held)

    def _serve(self) -> None:
        """Accept connections and hold them open until shutdown."""
        while not self._stopping.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            connection.settimeout(_ACCEPT_POLL_SECONDS)
            with self._lock:
                self._held.append(connection)
            threading.Thread(target=self._drain, args=(connection,), daemon=True).start()

    def _drain(self, connection: socket.socket) -> None:
        """Read and discard whatever a client sends until shutdown.

        Args:
            connection: The accepted connection.
        """
        while not self._stopping.is_set():
            try:
                if not connection.recv(_RECV_BYTES):
                    return
            except TimeoutError:
                continue
            except OSError:
                return

    def shutdown(self) -> None:
        """Stop accepting and close every held connection."""
        self._stopping.set()
        self._listener.close()
        self._thread.join(_JOIN_SECONDS)
        with self._lock:
            for connection in self._held:
                connection.close()

    def __enter__(self) -> Self:
        """Return the running server.

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
        """Shut the server down.

        Args:
            exc_type: Exception type, if the block raised.
            exc: Exception instance, if the block raised.
            traceback: Traceback, if the block raised.
        """
        self.shutdown()


class ScriptedHttpServer:
    """A loopback HTTP server answering every ``GET`` with one scripted response."""

    def __init__(self, *, status: int, body: bytes, chunk_size: int = 0, chunk_delay_s: float = 0.0) -> None:
        """Start serving.

        Args:
            status: HTTP status of every response.
            body: Body of every response.
            chunk_size: When positive, send the body in chunks of this many
                bytes, pausing ``chunk_delay_s`` before each one.
            chunk_delay_s: Pause before each chunk.
        """
        self._status = status
        self._body = body
        self._chunk_size = chunk_size
        self._chunk_delay_s = chunk_delay_s
        self._lock = threading.Lock()
        self._requests = 0
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            """Serves the scripted response."""

            def do_GET(self) -> None:
                """Answer one ``GET``."""
                owner.record()
                self.send_response(owner.status)
                self.send_header("Content-Length", str(len(owner.body)))
                self.end_headers()
                try:
                    owner.write_body(self.wfile)
                except OSError:
                    return

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Silence per-request logging.

                Args:
                    *args: Ignored.
                    **kwargs: Ignored.
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="scripted-http", daemon=True)
        self._thread.start()

    @property
    def status(self) -> int:
        """The scripted status.

        Returns:
            int: The HTTP status every response carries.
        """
        return self._status

    @property
    def body(self) -> bytes:
        """The scripted body.

        Returns:
            bytes: The body every response carries.
        """
        return self._body

    @property
    def url(self) -> str:
        """The URL of the served file.

        Returns:
            str: ``http://127.0.0.1:<port>/file``.
        """
        port: int = self._server.server_address[1]
        return f"http://127.0.0.1:{port}/file"

    @property
    def requests(self) -> int:
        """How many requests have been received.

        Returns:
            int: The request count.
        """
        with self._lock:
            return self._requests

    def record(self) -> None:
        """Count one received request."""
        with self._lock:
            self._requests += 1

    def write_body(self, stream: _Writable) -> None:
        """Write the scripted body, trickling it when configured to.

        Args:
            stream: The response stream.
        """
        if self._chunk_size <= 0:
            _ = stream.write(self._body)
            return
        for start in range(0, len(self._body), self._chunk_size):
            time.sleep(self._chunk_delay_s)
            _ = stream.write(self._body[start : start + self._chunk_size])
            stream.flush()

    def shutdown(self) -> None:
        """Stop serving."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(_JOIN_SECONDS)

    def __enter__(self) -> Self:
        """Return the running server.

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
        """Shut the server down.

        Args:
            exc_type: Exception type, if the block raised.
            exc: Exception instance, if the block raised.
            traceback: Traceback, if the block raised.
        """
        self.shutdown()


class _Writable(Protocol):
    """The part of a response stream :meth:`ScriptedHttpServer.write_body` uses."""

    def write(self, data: bytes, /) -> int:
        """Write bytes.

        Args:
            data: The bytes to write.

        Returns:
            int: How many bytes were written.
        """
        ...

    def flush(self) -> None:
        """Flush buffered bytes."""
        ...
