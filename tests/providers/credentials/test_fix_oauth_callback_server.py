# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the loopback OAuth callback server.

The server must wait for the real authorization redirect and nothing else: a browser's favicon fetch, a port probe, a request on another
path or a callback carrying the wrong ``state`` is answered and ignored. It must also own its port: starting it no longer flips
``socketserver.TCPServer.allow_reuse_address`` for the whole process, and two servers never share one port.
"""

from __future__ import annotations

import http.client
import socket
import socketserver
import sys
import threading
import time

import pytest

from intellicrack.credentials.oauth import OAuthCallbackError, OAuthCallbackServer, classify_callback


_STATE = "state-4f1c2b"


def _free_port() -> int:
    """Find a loopback port that is free right now.

    Returns:
        int: The port.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _get(port: int, target: str) -> int:
    """Send one GET to the loopback server.

    Args:
        port: The server's port.
        target: Path and query.

    Returns:
        int: The response status.
    """
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        _ = response.read()
        return response.status
    finally:
        connection.close()


class TestUnrelatedRequestsAreIgnored:
    """Only the redirect carrying the expected state ends the wait."""

    def test_stray_requests_do_not_end_the_flow(self) -> None:
        """Favicon, probes, wrong paths and wrong or missing state are all ignored; the real callback then wins."""
        port = _free_port()
        server = OAuthCallbackServer(port=port, timeout=10.0, expected_state=_STATE)
        server.start()
        statuses: dict[str, int] = {}
        result: dict[str, tuple[str, str]] = {}

        def wait() -> None:
            result["callback"] = server.wait_for_callback()

        waiter = threading.Thread(target=wait, daemon=True)
        waiter.start()
        try:
            for target in (
                "/favicon.ico",
                "/",
                "/robots.txt",
                "/other?code=abc&state=" + _STATE,
                "/callback",
                "/callback?code=forged",
                "/callback?code=forged&state=wrong",
                "/callback?error=access_denied&state=wrong",
                "/callback?error=access_denied",
            ):
                statuses[target] = _get(port, target)
                assert waiter.is_alive(), f"{target} ended the wait for the redirect"
            assert statuses["/favicon.ico"] == 404
            assert statuses["/callback?code=forged&state=wrong"] == 400
            assert _get(port, f"/callback?code=real-code&state={_STATE}&iss=https%3A%2F%2Fas.example") == 200
            waiter.join(timeout=5.0)
        finally:
            server.stop()
        assert result["callback"] == ("real-code", _STATE)
        assert server.received_issuer == "https://as.example"

    def test_only_junk_runs_out_the_timeout(self) -> None:
        """With nothing but unrelated requests the wait ends at its timeout, not at the first request."""
        port = _free_port()
        server = OAuthCallbackServer(port=port, timeout=1.5, expected_state=_STATE)
        server.start()
        started = time.monotonic()
        try:
            _ = _get(port, "/favicon.ico")
            _ = _get(port, "/callback?code=x&state=nope")
            with pytest.raises(OAuthCallbackError, match="Timeout"):
                server.wait_for_callback()
        finally:
            server.stop()
        assert time.monotonic() - started >= 1.4

    def test_idle_connection_does_not_block_the_redirect(self) -> None:
        """A client that connects and never sends a request cannot hold up the real callback."""
        port = _free_port()
        server = OAuthCallbackServer(port=port, timeout=10.0, expected_state=_STATE)
        server.start()
        idle = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        try:
            time.sleep(0.2)
            sender = threading.Thread(target=_get, args=(port, f"/callback?code=c1&state={_STATE}"), daemon=True)
            sender.start()
            assert server.wait_for_callback() == ("c1", _STATE)
            sender.join(timeout=5.0)
        finally:
            idle.close()
            server.stop()

    def test_state_required_before_it_is_known(self) -> None:
        """A server that must learn its state later accepts nothing until it has it."""
        port = _free_port()
        server = OAuthCallbackServer(port=port, timeout=10.0, require_state=True)
        server.start()
        try:
            assert _get(port, "/callback?code=early&state=anything") == 400
            server.expect_state(_STATE)
            assert _get(port, f"/callback?code=late&state={_STATE}") == 200
            assert server.wait_for_callback() == ("late", _STATE)
        finally:
            server.stop()

    def test_classify_callback_rules(self) -> None:
        """The pure classification decides exactly as the server acts."""
        assert classify_callback("/favicon.ico", callback_path="/callback", expected_state=_STATE, require_state=True)[0] == "ignore"
        assert (
            classify_callback(f"/callback?code=a&state={_STATE}", callback_path="/callback", expected_state=_STATE, require_state=True)[0]
            == "code"
        )
        assert (
            classify_callback(f"/callback?error=x&state={_STATE}", callback_path="/callback", expected_state=_STATE, require_state=True)[0]
            == "error"
        )
        assert (
            classify_callback("/callback?code=a&state=b", callback_path="/callback", expected_state=None, require_state=True)[0] == "ignore"
        )
        assert (
            classify_callback("/callback?code=a&state=b", callback_path="/callback", expected_state=None, require_state=False)[0] == "code"
        )


class TestPortOwnership:
    """Starting a callback server leaves global socket settings alone and never shares its port."""

    def test_start_does_not_change_tcpserver_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``socketserver.TCPServer.allow_reuse_address`` keeps its standard-library default through a start.

        Args:
            monkeypatch: Restores the class attribute whatever happens.
        """
        monkeypatch.setattr(socketserver.TCPServer, "allow_reuse_address", False)
        server = OAuthCallbackServer(port=0, timeout=1.0)
        server.start()
        try:
            assert socketserver.TCPServer.allow_reuse_address is False
            assert server.port != 0
        finally:
            server.stop()
        assert socketserver.TCPServer.allow_reuse_address is False

    def test_second_server_cannot_bind_a_port_in_use(self) -> None:
        """While one flow holds its port, another server on the same port fails to start."""
        first = OAuthCallbackServer(port=0, timeout=1.0)
        first.start()
        try:
            second = OAuthCallbackServer(port=first.port, timeout=1.0)
            with pytest.raises(OAuthCallbackError, match="Failed to bind"):
                second.start()
        finally:
            first.stop()

    def test_port_is_released_after_stop(self) -> None:
        """Stopping frees the port for the next flow straight away."""
        first = OAuthCallbackServer(port=0, timeout=1.0)
        first.start()
        port = first.port
        first.stop()
        second = OAuthCallbackServer(port=port, timeout=1.0)
        second.start()
        second.stop()


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="SO_REUSEADDR on Windows lets a second socket bind a listening port; the server must hold it with SO_EXCLUSIVEADDRUSE",
)
def test_windows_reuseaddr_socket_cannot_take_the_callback_port() -> None:
    """A socket opened with ``SO_REUSEADDR`` cannot bind over a running callback server on Windows."""
    server = OAuthCallbackServer(port=0, timeout=1.0)
    server.start()
    intruder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    intruder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        with pytest.raises(OSError, match=r"."):
            intruder.bind(("127.0.0.1", server.port))
    finally:
        intruder.close()
        server.stop()
