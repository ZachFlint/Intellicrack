# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates proving a dead server stops being reported ready, and comes back.

Every gate drives ``tests/_helpers/mcp_lifecycle_server.py``, a real
:class:`~mcp.server.mcpserver.MCPServer`, through the connection under test:
the server exits cleanly, crashes mid-call, or is killed from outside, and the
gate watches what the connection does about it.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from intellicrack.mcp import connection as connection_module
from intellicrack.mcp.config import McpTransportKind
from intellicrack.mcp.connection import McpConnection, McpHealth
from intellicrack.mcp.errors import McpConnectionError
from tests._helpers.mcp_lifecycle_support import (
    approving_gate,
    call_text,
    connection_for,
    network_config,
    network_server,
    stdio_config,
    stop_process,
    wait_until,
)


if TYPE_CHECKING:
    from pathlib import Path


_CONNECT_TIMEOUT_S = 90.0
_TEARDOWN_TIMEOUT_S = 30.0
_RECOVERY_DEADLINE_S = 8.0
"""How long a gate allows for a dead server to be noticed and replaced.

Well under :data:`~intellicrack.mcp.connection.HEARTBEAT_INTERVAL_S`, so a gate
only passes when the death is noticed as it happens rather than by the next
periodic probe.
"""


async def _pid_of(connection: McpConnection) -> int | None:
    """Ask the connected server for its process id.

    Args:
        connection: The connection.

    Returns:
        int | None: The server's process id, or ``None`` when it cannot be
        asked right now.
    """
    if not connection.is_ready:
        return None
    try:
        return int(await call_text(connection, "whoami"))
    except McpConnectionError:
        return None


async def _replaced(connection: McpConnection, previous: int) -> bool:
    """Report whether a different server process is now serving the connection.

    Args:
        connection: The connection.
        previous: The process id that served it before.

    Returns:
        bool: ``True`` once a new process answers.
    """
    current = await _pid_of(connection)
    return current is not None and current != previous


class TestLocalServerDeath:
    """A local server that goes away is replaced at once."""

    def test_clean_exit_is_noticed_and_reconnected(self, tmp_path: Path) -> None:
        """A server that exits with status zero is replaced without waiting for a probe.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = connection_for(stdio_config("liveness"), approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[int, bool]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                first = await _pid_of(connection)
                assert first is not None
                assert await call_text(connection, "quit") == "leaving"
                return first, await wait_until(lambda: _replaced(connection, first), timeout_s=_RECOVERY_DEADLINE_S)
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        first, replaced = asyncio.run(body())
        assert first > 0
        assert replaced, "the server exited cleanly but the connection neither noticed nor reconnected"

    def test_connection_closed_mid_call_is_reconnected(self, tmp_path: Path) -> None:
        """A server that dies during a call fails that call and is then replaced.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = connection_for(stdio_config("liveness"), approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[str, bool]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                first = await _pid_of(connection)
                assert first is not None
                with pytest.raises(McpConnectionError) as failure:
                    _ = await connection.call_tool("crash", {})
                recovered = await wait_until(lambda: _replaced(connection, first), timeout_s=_RECOVERY_DEADLINE_S)
                return str(failure.value), recovered
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        error, recovered = asyncio.run(body())
        assert "Connection closed" in error
        assert recovered, "a call found the connection closed, yet the connection never reconnected"


class TestRemoteServerLiveness:
    """A remote server that vanishes silently is caught by the liveness probe."""

    def test_modern_server_is_probed_without_ping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 2026-07-28 server that dies silently stops being reported ready.

        Such a server has no ``ping``. A probe that relied on it would be
        refused on the first beat and then switched off for good, leaving a
        dead server reported ready indefinitely.

        Args:
            monkeypatch: Pytest fixture used to shorten the probe interval.
        """
        monkeypatch.setattr(connection_module, "HEARTBEAT_INTERVAL_S", 0.3)
        with network_server("http") as (process, port):
            connection = connection_for(network_config("liveness", port, McpTransportKind.HTTP))

            async def body() -> tuple[str | None, McpHealth]:
                await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
                try:
                    client = connection.client
                    version = client.protocol_version if client is not None else None
                    await asyncio.sleep(1.5)
                    assert connection.is_ready, "the probe reported a healthy modern server as dead"
                    stop_process(process)
                    _ = await wait_until(lambda: not connection.is_ready, timeout_s=_RECOVERY_DEADLINE_S)
                    return version, connection.status.health
                finally:
                    await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

            version, health = asyncio.run(body())
        assert version == "2026-07-28"
        assert health is not McpHealth.READY, "the server was killed but the connection still reports it ready"


class TestReconnectBudget:
    """Occasional drops of a healthy server do not use up its retries."""

    def test_attempt_count_resets_after_a_ready_period(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A server that stays up between drops is reconnected every time.

        With a budget of two attempts, the second drop would exhaust a
        counter that never resets.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest fixture used to shrink the retry budget.
        """
        monkeypatch.setattr(connection_module, "MAX_RECONNECT_ATTEMPTS", 2)
        monkeypatch.setattr(connection_module, "RECONNECT_RESET_AFTER_S", 0.3)
        connection = connection_for(stdio_config("liveness"), approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[int, McpHealth]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                survived = 0
                for _ in range(3):
                    await asyncio.sleep(0.6)
                    current = await _pid_of(connection)
                    assert current is not None
                    _ = await call_text(connection, "quit")
                    if not await wait_until(lambda pid=current: _replaced(connection, pid), timeout_s=_RECOVERY_DEADLINE_S):
                        break
                    survived += 1
                return survived, connection.status.health
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        survived, health = asyncio.run(body())
        assert survived == 3, f"only {survived} of 3 drops were recovered from"
        assert health is McpHealth.READY
