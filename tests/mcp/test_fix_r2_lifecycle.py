# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 9: connecting, stopping and restarting leave no server running that nobody asked for, and no notice lost.

Every gate runs real servers: the steerable lifecycle server over stdio, the OAuth-protected server over Streamable HTTP with the real
loopback sign-in listener, and a legacy SSE server whose listing changes while the client is still reading it. Consent prompts are held
open on an event the gate controls, so a gate can cancel or stop while a prompt is open and then answer it, the way an operator answering
late would.
"""

from __future__ import annotations

import asyncio
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import httpx2
import pytest

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, issuer_for
from intellicrack.mcp.config import HttpServerSpec, McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import AuthFactory, McpConnection, McpConnectionManager, McpHealth
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_http_process import free_port, running_module, running_server
from tests._helpers.mcp_lifecycle_support import approving_gate, stdio_config, wait_until
from tests._helpers.mcp_racing_list_server import FIRST_TOOL_NAME, LATE_TOOL_NAME
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from intellicrack.mcp.consent import DangerousPattern


_HELPERS: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers"
_OUTER_TIMEOUT_S: Final[float] = 120.0
_PROMPT_OPEN_TIMEOUT_S: Final[float] = 30.0
_AFTER_ANSWER_S: Final[float] = 4.0
_PROMPT_STOP_BUDGET_S: Final[float] = 5.0
_LINGERING_SERVERS: Final[int] = 5
_LINGER_S: Final[float] = 30.0
_CONCURRENT_STOP_BUDGET_S: Final[float] = 6.0
_NOTICE_TIMEOUT_S: Final[float] = 15.0


class _HeldPrompt:
    """A consent prompt that stays open until the gate answers it.

    Attributes:
        opened: Set once the prompt is on screen.
        answer: Set to approve the launch.
        cancelled: Whether the prompt was cancelled before it was answered.
    """

    opened: asyncio.Event
    answer: asyncio.Event
    cancelled: bool

    def __init__(self) -> None:
        """Start closed and unanswered."""
        self.opened = asyncio.Event()
        self.answer = asyncio.Event()
        self.cancelled = False

    async def __call__(self, config: McpServerConfig, rendered: str, findings: list[DangerousPattern]) -> bool:
        """Show the prompt and wait for the answer.

        Args:
            config: The server being launched.
            rendered: The launch description.
            findings: Dangerous patterns found in the command.

        Returns:
            bool: ``True`` once answered.

        Raises:
            asyncio.CancelledError: If the prompt is cancelled before it is answered.
        """
        del config, rendered, findings
        self.opened.set()
        try:
            _ = await self.answer.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return True


def _resolver(tmp_path: Path) -> McpSecretResolver:
    """Build a resolver over a credential store confined to the test.

    Args:
        tmp_path: Per-test directory holding the test's own ``.env``.

    Returns:
        McpSecretResolver: The resolver.
    """
    return McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))


def _manager(
    tmp_path: Path,
    configs: list[McpServerConfig],
    gate: McpConsentGate,
    *,
    auth_factory: AuthFactory | None = None,
) -> McpConnectionManager:
    """Build a manager over a configuration file holding the given servers.

    Args:
        tmp_path: Per-test directory.
        configs: The servers.
        gate: The consent gate.
        auth_factory: Builds the OAuth handler for a remote server.

    Returns:
        McpConnectionManager: The manager, not yet started.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=tuple(configs)))
    return McpConnectionManager(store, _resolver(tmp_path), gate, auth_factory=auth_factory)


class TestCancelledConnectLaunchesNothing:
    """Cancelling a connect abandons it, even if the prompt it was waiting on is answered afterwards."""

    def test_cancelled_connect_never_becomes_ready(self, tmp_path: Path) -> None:
        """A connect cancelled while its consent prompt is open never brings the server up.

        Args:
            tmp_path: Per-test directory.
        """
        prompt = _HeldPrompt()
        connection = McpConnection(
            stdio_config("abandoned"),
            _resolver(tmp_path),
            consent=McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt),
        )

        async def body() -> tuple[McpHealth, bool]:
            task = asyncio.create_task(connection.connect())
            _ = await asyncio.wait_for(prompt.opened.wait(), timeout=_PROMPT_OPEN_TIMEOUT_S)
            _ = task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            prompt.answer.set()
            await asyncio.sleep(_AFTER_ANSWER_S)
            health = connection.status.health
            ready = connection.client is not None
            await connection.disconnect()
            return health, ready

        health, ready = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

        assert prompt.cancelled
        assert health is McpHealth.DISCONNECTED
        assert not ready

    def test_cancelled_manager_start_never_brings_a_server_up(self, tmp_path: Path) -> None:
        """Cancelling the manager's start while a prompt is open leaves every server down.

        Args:
            tmp_path: Per-test directory.
        """
        prompt = _HeldPrompt()
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt)
        manager = _manager(tmp_path, [stdio_config("abandoned")], gate)

        async def body() -> list[McpHealth]:
            task = asyncio.create_task(manager.start())
            _ = await asyncio.wait_for(prompt.opened.wait(), timeout=_PROMPT_OPEN_TIMEOUT_S)
            _ = task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            prompt.answer.set()
            await asyncio.sleep(_AFTER_ANSWER_S)
            healths = [status.health for status in manager.statuses()]
            await manager.stop()
            return healths

        healths = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

        assert prompt.cancelled
        assert McpHealth.READY not in healths


def test_disconnect_during_connect_is_reported_at_once(tmp_path: Path) -> None:
    """A connect whose server is stopped under it says so at once, instead of waiting out the connect timeout.

    Args:
        tmp_path: Per-test directory.
    """
    prompt = _HeldPrompt()
    connection = McpConnection(
        stdio_config("stopped"),
        _resolver(tmp_path),
        consent=McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt),
    )

    async def body() -> tuple[float, str]:
        task = asyncio.create_task(connection.connect())
        _ = await asyncio.wait_for(prompt.opened.wait(), timeout=_PROMPT_OPEN_TIMEOUT_S)
        started = time.monotonic()
        await connection.disconnect()
        with pytest.raises(McpConnectionError) as caught:
            await task
        return time.monotonic() - started, str(caught.value)

    elapsed, message = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    assert "stopped before it became ready" in message
    assert elapsed < _PROMPT_STOP_BUDGET_S
    assert prompt.cancelled


def test_stop_tears_servers_down_concurrently(tmp_path: Path) -> None:
    """Stopping servers that are each slow to exit takes about as long as one of them, not all of them.

    Args:
        tmp_path: Per-test directory.
    """
    configs = [stdio_config(f"slow{index}", extra_args=("--linger-s", str(_LINGER_S))) for index in range(_LINGERING_SERVERS)]
    manager = _manager(tmp_path, configs, approving_gate(tmp_path / "trust.json"))

    async def body() -> tuple[int, float, list[McpHealth]]:
        await manager.start()
        ready = sum(status.health is McpHealth.READY for status in manager.statuses())
        started = time.monotonic()
        await manager.stop()
        return ready, time.monotonic() - started, [status.health for status in manager.statuses()]

    ready, elapsed, after = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    assert ready == _LINGERING_SERVERS
    assert elapsed < _CONCURRENT_STOP_BUDGET_S
    assert McpHealth.READY not in after


def test_stop_ends_an_open_sign_in(tmp_path: Path) -> None:
    """Stopping while a sign-in waits on the browser ends the wait at once and closes the loopback listener.

    Args:
        tmp_path: Per-test directory holding the private keyring and ``.env``.
    """
    visited: list[str] = []

    async def never_signs_in(url: str) -> None:
        """Load the authorization page the way a browser would, then never approve it.

        Args:
            url: The authorization page.
        """
        async with httpx2.AsyncClient(follow_redirects=False) as browser:
            _ = await browser.get(url)
        visited.append(url)

    callback_port = free_port()
    with running_module("tests._helpers.mcp_oauth_server", "--issuer-mode", "matched") as port:
        spec = HttpServerSpec(url=f"http://127.0.0.1:{port}/mcp")
        config = McpServerConfig(server_id="signing-in", kind=McpTransportKind.HTTP, http=spec, enabled=True)
        store = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))

        def factory(resolved: McpServerConfig) -> httpx2.Auth:
            """Build the real OAuth handler with its real loopback listener.

            Args:
                resolved: The resolved server configuration.

            Returns:
                httpx2.Auth: The handler.
            """
            assert resolved.http is not None
            storage = KeyringTokenStorage(store, resolved.server_id, issuer_for(resolved.http))
            return build_oauth_provider(resolved.http, storage, redirect_handler=never_signs_in, callback_port=callback_port)

        manager = _manager(tmp_path, [config], approving_gate(tmp_path / "trust.json"), auth_factory=factory)

        async def body() -> float:
            start = asyncio.create_task(manager.start())
            assert await wait_until(lambda: bool(visited), timeout_s=_PROMPT_OPEN_TIMEOUT_S)
            started = time.monotonic()
            await manager.stop()
            elapsed = time.monotonic() - started
            await start
            return elapsed

        with installed_keyring(private_file_keyring(tmp_path / "keyring.cfg")):
            elapsed = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    assert elapsed < _PROMPT_STOP_BUDGET_S
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", callback_port))


class TestNoStartAfterStop:
    """A start that arrives after the manager was stopped brings nothing up."""

    def test_remote_start_after_stop_is_refused(self, tmp_path: Path) -> None:
        """A remote server, which asks no consent, is not connected by a start queued behind the stop.

        Args:
            tmp_path: Per-test directory.
        """
        with running_server(_HELPERS / "mcp_interactive_server.py", "--transport", "http") as port:
            config = McpServerConfig(
                server_id="remote",
                kind=McpTransportKind.HTTP,
                http=HttpServerSpec(url=f"http://127.0.0.1:{port}/mcp"),
                enabled=True,
            )
            manager = _manager(tmp_path, [config], approving_gate(tmp_path / "trust.json"))

            async def body() -> tuple[str, McpConnection | None, McpHealth]:
                await manager.stop()
                with pytest.raises(McpConnectionError) as caught:
                    _ = await manager.start_server("remote")
                refused = str(caught.value)
                left = manager.connection("remote")
                await manager.start()
                health = next(status.health for status in manager.statuses() if status.server_id == "remote")
                await manager.stop()
                return refused, left, health

            refused, left, health = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

        assert "shut down" in refused
        assert left is None
        assert health is McpHealth.READY


def test_legacy_change_notice_during_first_listing_is_followed(tmp_path: Path) -> None:
    """A legacy server's change notice that arrives while the first listing is being read still leads to a re-list.

    Args:
        tmp_path: Per-test directory.
    """
    with running_server(_HELPERS / "mcp_racing_list_server.py") as port:
        config = McpServerConfig(
            server_id="racing",
            kind=McpTransportKind.SSE,
            http=HttpServerSpec(url=f"http://127.0.0.1:{port}/sse"),
            enabled=True,
        )
        connection = McpConnection(config, _resolver(tmp_path))

        def names() -> set[str]:
            catalog = connection.catalog
            return {entry.name for entry in catalog.entries} if catalog is not None else set()

        async def body() -> tuple[set[str], bool]:
            await connection.connect()
            first = names()
            connection.start_listening(lambda _server_id: None)
            followed = await wait_until(lambda: LATE_TOOL_NAME in names(), timeout_s=_NOTICE_TIMEOUT_S)
            await connection.disconnect()
            return first, followed

        first, followed = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    assert first == {FIRST_TOOL_NAME}
    assert followed, "the change notice sent during the first listing was lost"
