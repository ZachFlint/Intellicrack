# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for OAuth against a real authorization server.

``tests/_helpers/mcp_oauth_server.py`` is a genuine OAuth 2.1 authorization
server guarding a genuine MCP resource, run as a separate process. The whole
path runs for real: the ``401`` challenge, protected-resource metadata
discovery, authorization server metadata discovery, client registration, a
PKCE-protected authorization code, the token exchange, and the bearer token on
the tool call that follows.

Only the browser step is substituted, because these gates run headless: the
injected redirect handler fetches the authorization URL over HTTP instead of
opening a window. The server still issues and verifies everything itself.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from mcp.shared.auth import AuthorizationCodeResult

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, has_stored_credentials, issuer_for, sign_out
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator


_BOOT_TIMEOUT_S = 60.0
_CONNECT_TIMEOUT_S = 90.0
_TEARDOWN_GRACE_S = 15.0
_SERVER_ID = "oauth"


def _free_port() -> int:
    """Reserve a loopback port the authorization server can bind.

    Returns:
        int: A port that was free at the moment of asking.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _start(issuer_mode: str) -> tuple[subprocess.Popen[bytes], int]:
    """Start the authorization server and wait for it to accept.

    Args:
        issuer_mode: ``matched`` or ``mismatched``.

    Returns:
        tuple[subprocess.Popen[bytes], int]: The process and its port.

    Raises:
        RuntimeError: If the server exits or never accepts in time.
    """
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "tests._helpers.mcp_oauth_server", "--port", str(port), "--issuer-mode", issuer_mode],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    deadline = time.monotonic() + _BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            message = f"the authorization server exited with {process.returncode}"
            raise RuntimeError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return process, port
        except OSError:
            time.sleep(0.2)
    process.terminate()
    message = "the authorization server never accepted"
    raise RuntimeError(message)


def _stop(process: subprocess.Popen[bytes]) -> None:
    """Terminate the authorization server.

    Args:
        process: The server process.
    """
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


@pytest.fixture
def authorization_server() -> Iterator[int]:
    """Run an authorization server whose issuer matches its own origin.

    Yields:
        int: The loopback port it listens on.
    """
    process, port = _start("matched")
    try:
        yield port
    finally:
        _stop(process)


@pytest.fixture
def mismatched_issuer_server() -> Iterator[int]:
    """Run an authorization server advertising somebody else's issuer.

    Yields:
        int: The loopback port it listens on.
    """
    process, port = _start("mismatched")
    try:
        yield port
    finally:
        _stop(process)


class _Flow:
    """Drives the browser half of an authorization code flow headlessly.

    Attributes:
        code: The authorization code the server issued.
        state: The state value it echoed back.
        issuer: The ``iss`` the server returned on the redirect.
        visited: Whether the authorization endpoint was reached at all.
    """

    def __init__(self) -> None:
        """Start with nothing captured."""
        self.code: str | None = None
        self.state: str | None = None
        self.issuer: str | None = None
        self.visited = False

    async def redirect(self, authorization_url: str) -> None:
        """Fetch the authorization URL and capture the redirect it answers with.

        Args:
            authorization_url: Where a browser would have been sent.
        """
        self.visited = True
        async with httpx2.AsyncClient(follow_redirects=False) as client:
            response = await client.get(authorization_url)
            location = response.headers.get("location", "")
            query = parse_qs(urlparse(location).query)
            self.code = query.get("code", [None])[0]
            self.state = query.get("state", [None])[0]
            self.issuer = query.get("iss", [None])[0]

    async def callback(self) -> AuthorizationCodeResult:
        """Hand the captured code back to the client.

        Returns:
            AuthorizationCodeResult: The code and state to redeem.

        Raises:
            RuntimeError: If the authorization endpoint issued no code.
        """
        if self.code is None:
            message = "the authorization server issued no code"
            raise RuntimeError(message)
        return AuthorizationCodeResult(code=self.code, state=self.state)


def _connection(port: int, flow: _Flow, store: CredentialStore) -> McpConnection:
    """Build a connection that authorizes against the fixture server.

    Args:
        port: Loopback port the server listens on.
        flow: The headless browser stand-in.
        store: Credential store backing token persistence.

    Returns:
        McpConnection: An unconnected, OAuth-enabled connection.
    """
    spec = HttpServerSpec(url=f"http://127.0.0.1:{port}/mcp")
    config = McpServerConfig(server_id=_SERVER_ID, kind=McpTransportKind.HTTP, http=spec, enabled=True, request_timeout_s=30.0)
    storage = KeyringTokenStorage(store, _SERVER_ID, issuer_for(spec))

    def factory(_config: McpServerConfig) -> httpx2.Auth:
        """Build the authorization handler for this server.

        Args:
            _config: The resolved server configuration.

        Returns:
            httpx2.Auth: The OAuth handler.
        """
        return build_oauth_provider(spec, storage, redirect_handler=flow.redirect, callback_handler=flow.callback)

    return McpConnection(config, McpSecretResolver(store), auth_factory=factory)


async def _with_connection[T](connection: McpConnection, body: Callable[[], Awaitable[T]]) -> T:
    """Connect, run a body, and always disconnect.

    Args:
        connection: The connection to drive.
        body: Awaitable-returning callable run while connected.

    Returns:
        T: Whatever ``body`` produced.
    """
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        return await body()
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_GRACE_S)


class TestAuthorizationCodeFlow:
    """A protected server is reached by completing a real authorization flow."""

    def test_unauthenticated_request_is_challenged(self, authorization_server: int) -> None:
        """The resource answers ``401`` with a discovery pointer.

        Everything else depends on this challenge, so it is asserted directly
        rather than inferred from a later success.

        Args:
            authorization_server: Port of the running server.
        """
        with httpx2.Client() as client:
            response = client.post(
                f"http://127.0.0.1:{authorization_server}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
            )
        assert response.status_code == 401
        challenge = response.headers.get("www-authenticate", "")
        assert "resource_metadata=" in challenge

    def test_flow_completes_and_lists_tools(self, authorization_server: int) -> None:
        """Authorizing end to end yields the protected server's real catalog.

        Args:
            authorization_server: Port of the running server.
        """
        flow = _Flow()
        connection = _connection(authorization_server, flow, CredentialStore())

        async def body() -> int:
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            return catalog.tool_count

        count = asyncio.run(_with_connection(connection, body))
        assert flow.visited, "the client never reached the authorization endpoint"
        assert count > 0

    def test_authorized_tool_call_round_trips(self, authorization_server: int) -> None:
        """A tool call carries the bearer token the flow obtained.

        Args:
            authorization_server: Port of the running server.
        """
        flow = _Flow()
        connection = _connection(authorization_server, flow, CredentialStore())

        async def body() -> list[str]:
            result = await connection.call_tool("echo", {"message": "authorized"})
            return [getattr(block, "text", "") for block in result.content]

        assert "authorized" in asyncio.run(_with_connection(connection, body))

    def test_server_issues_its_own_issuer_on_the_redirect(self, authorization_server: int) -> None:
        """The redirect carries ``iss``, which RFC 9207 validation depends on.

        Args:
            authorization_server: Port of the running server.
        """
        flow = _Flow()
        connection = _connection(authorization_server, flow, CredentialStore())

        async def body() -> None:
            await asyncio.sleep(0)

        asyncio.run(_with_connection(connection, body))
        assert flow.issuer == f"http://127.0.0.1:{authorization_server}"


class TestIssuerValidation:
    """An authorization server claiming somebody else's identity is refused."""

    def test_mismatched_issuer_is_refused(self, mismatched_issuer_server: int) -> None:
        """Metadata advertising a foreign issuer does not yield a connection.

        The server is otherwise identical to the one the happy-path gates use,
        so a client that ignored the issuer would connect here just as well.

        Args:
            mismatched_issuer_server: Port of the running server.
        """
        flow = _Flow()
        connection = _connection(mismatched_issuer_server, flow, CredentialStore())

        with pytest.raises(McpConnectionError):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))


class TestTokenPersistence:
    """Tokens are filed per issuer and can be signed out."""

    def test_token_is_stored_and_signed_out(self, authorization_server: int) -> None:
        """A completed flow stores a token that sign-out then removes.

        Args:
            authorization_server: Port of the running server.
        """
        store = CredentialStore()
        spec = HttpServerSpec(url=f"http://127.0.0.1:{authorization_server}/mcp")
        issuer = issuer_for(spec)
        flow = _Flow()
        connection = _connection(authorization_server, flow, store)

        async def body() -> None:
            await asyncio.sleep(0)

        asyncio.run(_with_connection(connection, body))

        async def check() -> tuple[bool, bool, bool]:
            before = await has_stored_credentials(store, _SERVER_ID, issuer)
            removed = await sign_out(store, _SERVER_ID, issuer)
            after = await has_stored_credentials(store, _SERVER_ID, issuer)
            return before, removed, after

        before, removed, after = asyncio.run(check())
        assert before is True, "the completed flow stored no token"
        assert removed is True
        assert after is False, "sign-out left the token behind"

    def test_sign_out_without_an_issuer_removes_nothing(self) -> None:
        """A token can only be found under the issuer it was filed against."""
        assert asyncio.run(sign_out(CredentialStore(), _SERVER_ID, None)) is False
