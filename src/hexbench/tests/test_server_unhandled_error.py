# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""An exception that escapes ``Application.handle`` must still answer the client.

``BenchRequestHandler._serve`` used to call ``server.application.handle(request)``
with no surrounding ``try``/``except``. If that call ever raised instead of
returning a :class:`~hexbench.api.Response` -- a bug in routing reached before
a response is built, say -- the exception propagated out of ``do_GET``/``do_POST``,
``socketserver`` caught it far above the handler and routed it only to
``BenchHTTPServer.handle_error``, which appends a line to the server's private
log ring and never touches the client's socket. The caller saw the TCP
connection reset with zero bytes of response, with no way to tell a bug from a
network failure.

This is exercised over a real loopback socket, with ``Application.handle``
patched to raise -- a legitimate use of ``unittest.mock`` against a public
method of a public class, not a reach into anything private -- so the
connection-level outcome is what a real client would actually observe.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import unittest
from contextlib import ExitStack
from typing import Final
from unittest import mock

from hexbench.api import Application
from hexbench.jobs import JobQueue
from hexbench.registry import Registry
from hexbench.server import BenchHTTPServer, build_server
from hexbench.tests._support import PACKAGE_ROOT, SESSION_TOKEN, Assertions


_HOST: Final = "127.0.0.1"
_STATIC_ROOT: Final = PACKAGE_ROOT / "static"
_WORKERS: Final = 2
_SOCKET_TIMEOUT: Final = 10.0
_POLL_INTERVAL: Final = 0.05
_JOIN_TIMEOUT: Final = 10.0

_INTERNAL_ERROR: Final = 500
_AUTH_HEADER: Final = "X-Hexbench-Token"
_ERROR_KEY: Final = "error"
_STATUS_KEY: Final = "status"
_FAILURE_MESSAGE: Final = "boom: a bug reached before any Response was built"


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
            name="hexbench-unhandled-error-test-server",
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

    @property
    def log(self) -> tuple[str, ...]:
        """The server's own diagnostic ring buffer.

        Returns:
            tuple[str, ...]: The most recent log lines.
        """
        return self._server.recent_log()

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


class UnhandledErrorResponseTests(Assertions, unittest.TestCase):
    """An exception escaping ``Application.handle`` must still reach the client as a response."""

    def test_client_receives_a_500_response_instead_of_a_dropped_connection(self) -> None:
        """A real socket client must read a diagnosable 500 response, not a bare connection reset."""
        with ExitStack() as stack:
            live = _live_server(stack)
            with mock.patch.object(Application, "handle", side_effect=RuntimeError(_FAILURE_MESSAGE)):
                connection = http.client.HTTPConnection(_HOST, live.port, timeout=_SOCKET_TIMEOUT)
                stack.callback(connection.close)
                connection.request("GET", "/api/documents", headers={"Host": live.host_header, _AUTH_HEADER: SESSION_TOKEN})
                response = connection.getresponse()
                self.equal(response.status, _INTERNAL_ERROR, "status reported for a routing exception")
                payload = json.loads(response.read())
                self.require(isinstance(payload, dict), "error response body is not a JSON object")
                error = payload.get(_ERROR_KEY)
                self.require(isinstance(error, dict), "error response carries no error object")
                self.equal(error.get(_STATUS_KEY), _INTERNAL_ERROR, "status field inside the error object")
                self.require(
                    any(_FAILURE_MESSAGE in line for line in live.log),
                    "the server's own diagnostic log carries no trace of the exception that escaped handle()",
                )

    def test_the_underlying_socket_still_delivers_bytes_rather_than_resetting(self) -> None:
        """The raw socket must carry a real HTTP response, not close with nothing sent."""
        with ExitStack() as stack:
            live = _live_server(stack)
            with mock.patch.object(Application, "handle", side_effect=RuntimeError(_FAILURE_MESSAGE)):
                sock = socket.create_connection((_HOST, live.port), timeout=_SOCKET_TIMEOUT)
                stack.callback(sock.close)
                request = f"GET /api/documents HTTP/1.1\r\nHost: {live.host_header}\r\n{_AUTH_HEADER}: {SESSION_TOKEN}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode("ascii"))
                received = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    received += chunk
                self.require(received.startswith(b"HTTP/1.1 500"), f"expected an HTTP/1.1 500 status line, got {received[:40]!r}")
                self.require(b"\r\n\r\n" in received, "response never terminated its header block")


if __name__ == "__main__":
    unittest.main()
