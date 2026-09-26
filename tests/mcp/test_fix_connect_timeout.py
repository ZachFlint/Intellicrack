# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates proving the connect timeout counts the server's time, not the operator's.

The launch consent prompt and the OAuth sign-in both run inside a connection
attempt, and both wait on a person. The gates hold each open for longer than
the whole connect budget and require the connection to succeed anyway, and
separately require a server that never answers to still time out.
"""

from __future__ import annotations

import asyncio
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
from intellicrack.mcp import connection as connection_module
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, issuer_for, sign_out
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_lifecycle_support import approving_gate, connection_for, free_port, stdio_config, stop_process


if TYPE_CHECKING:
    from collections.abc import Iterator


_CONNECT_BUDGET_S = 8.0
"""The connect timeout the gates run under, generous for a loaded machine."""

_OPERATOR_PAUSE_S = 11.0
"""How long the operator takes, longer than the whole budget."""

_OUTER_TIMEOUT_S = 120.0
_TEARDOWN_TIMEOUT_S = 30.0
_BOOT_TIMEOUT_S = 60.0


@pytest.fixture
def authorization_server() -> Iterator[int]:
    """Run the OAuth-protected fixture server on loopback.

    Yields:
        int: The port it listens on.

    Raises:
        RuntimeError: If the server exits or never accepts.
    """
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "tests._helpers.mcp_oauth_server", "--port", str(port), "--issuer-mode", "matched"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    try:
        deadline = time.monotonic() + _BOOT_TIMEOUT_S
        while True:
            if process.poll() is not None or time.monotonic() > deadline:
                message = "the authorization server did not come up"
                raise RuntimeError(message)
            try:
                with httpx2.Client() as probe:
                    _ = probe.get(f"http://127.0.0.1:{port}/.well-known/oauth-authorization-server", timeout=0.5)
                break
            except httpx2.TransportError:
                time.sleep(0.2)
        yield port
    finally:
        stop_process(process)


class _SlowSignIn:
    """Completes the browser half of the sign-in, but only after a long pause.

    Attributes:
        code: The authorization code the server issued.
        state: The state value it echoed back.
    """

    def __init__(self) -> None:
        """Start with nothing captured."""
        self.code: str | None = None
        self.state: str | None = None

    async def redirect(self, authorization_url: str) -> None:
        """Visit the authorization URL the way a browser would.

        Args:
            authorization_url: Where the operator would be sent.
        """
        async with httpx2.AsyncClient(follow_redirects=False) as client:
            response = await client.get(authorization_url)
        query = parse_qs(urlparse(response.headers.get("location", "")).query)
        self.code = query.get("code", [None])[0]
        self.state = query.get("state", [None])[0]

    async def callback(self) -> AuthorizationCodeResult:
        """Hand the code back once the operator has finished signing in.

        Returns:
            AuthorizationCodeResult: The code and state to redeem.

        Raises:
            RuntimeError: If the server issued no code.
        """
        await asyncio.sleep(_OPERATOR_PAUSE_S)
        if self.code is None:
            message = "the authorization server issued no code"
            raise RuntimeError(message)
        return AuthorizationCodeResult(code=self.code, state=self.state)


class TestOperatorTimeIsExcluded:
    """A prompt left open longer than the budget does not fail the connection."""

    def test_slow_launch_consent_does_not_time_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The consent dialog stays open past the budget and the server still connects.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest fixture used to shorten the connect budget.
        """
        monkeypatch.setattr(connection_module, "CONNECT_TIMEOUT_S", _CONNECT_BUDGET_S)
        gate = approving_gate(tmp_path / "trust.json", delay_s=_OPERATOR_PAUSE_S)
        connection = connection_for(stdio_config("slow-consent"), gate)

        async def body() -> bool:
            await connection.connect()
            try:
                return connection.is_ready
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        assert asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    def test_slow_oauth_sign_in_does_not_time_out(self, authorization_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
        """The sign-in takes longer than the budget and the server still connects.

        Args:
            authorization_server: Port of the OAuth-protected server.
            monkeypatch: Pytest fixture used to shorten the connect budget.
        """
        monkeypatch.setattr(connection_module, "CONNECT_TIMEOUT_S", _CONNECT_BUDGET_S)
        store = CredentialStore()
        spec = HttpServerSpec(url=f"http://127.0.0.1:{authorization_server}/mcp")
        config = McpServerConfig(server_id="slow-oauth", kind=McpTransportKind.HTTP, http=spec, enabled=True, request_timeout_s=30.0)
        storage = KeyringTokenStorage(store, "slow-oauth", issuer_for(spec))
        sign_in = _SlowSignIn()

        def factory(_config: McpServerConfig) -> httpx2.Auth:
            """Build the OAuth handler with the slow browser stand-in.

            Args:
                _config: The resolved server configuration.

            Returns:
                httpx2.Auth: The handler.
            """
            return build_oauth_provider(spec, storage, redirect_handler=sign_in.redirect, callback_handler=sign_in.callback)

        connection = McpConnection(config, McpSecretResolver(store), auth_factory=factory)

        async def body() -> int:
            await connection.connect()
            try:
                catalog = connection.catalog
                return catalog.tool_count if catalog is not None else 0
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)
                _ = await sign_out(store, "slow-oauth", issuer_for(spec))

        assert asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S)) > 0


class TestServerTimeIsStillBounded:
    """A server that never finishes its handshake still times out."""

    def test_unresponsive_server_times_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A process that never speaks the protocol fails the connect within the budget.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest fixture used to shorten the connect budget.
        """
        monkeypatch.setattr(connection_module, "CONNECT_TIMEOUT_S", 2.0)
        config = stdio_config("mute", args=("-c", "import time; time.sleep(120)"))
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))
        started = time.monotonic()
        with pytest.raises(McpConnectionError, match="timed out"):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_OUTER_TIMEOUT_S))
        assert time.monotonic() - started < 30.0
