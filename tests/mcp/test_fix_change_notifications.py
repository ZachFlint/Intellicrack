# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates proving a tool-list change notice always produces a real re-list.

The server's ``grow`` tool adds a tool and announces the change: to
``subscriptions/listen`` subscribers on a 2026-07-28 connection, and as a
plain ``notifications/tools/list_changed`` on a handshake-era one. The gates
check the connection's catalog picks the new tool up -- after a reconnect, on
a legacy SSE connection, and while the listing is still inside its ``ttlMs``
freshness window.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from intellicrack.mcp.config import McpTransportKind
from tests._helpers.mcp_lifecycle_server import GROWN_TOOL_PREFIX
from tests._helpers.mcp_lifecycle_support import (
    approving_gate,
    call_text,
    connection_for,
    network_config,
    network_server,
    stdio_config,
    wait_until,
)


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.mcp.connection import McpConnection


_CONNECT_TIMEOUT_S = 90.0
_TEARDOWN_TIMEOUT_S = 30.0
_NOTICE_DEADLINE_S = 8.0
_GROWN = f"{GROWN_TOOL_PREFIX}0"
_TTL_MS = 600_000


def _has_tool(connection: McpConnection, name: str) -> bool:
    """Report whether the connection's current catalog lists a tool.

    Args:
        connection: The connection.
        name: The server's tool name.

    Returns:
        bool: ``True`` when the tool is listed.
    """
    catalog = connection.catalog
    return catalog is not None and catalog.entry_by_name(name) is not None


async def _grow_and_wait(connection: McpConnection) -> bool:
    """Make the server add a tool, then wait for the catalog to show it.

    Args:
        connection: A ready, listening connection.

    Returns:
        bool: Whether the new tool reached the catalog in time.
    """
    assert await call_text(connection, "grow") == _GROWN
    return await wait_until(lambda: _has_tool(connection, _GROWN), timeout_s=_NOTICE_DEADLINE_S)


class TestSubscriptionAcrossReconnects:
    """The change subscription follows the connection through a reconnect."""

    def test_notice_after_reconnect_updates_the_catalog(self, tmp_path: Path) -> None:
        """A change announced by the replacement server still reaches the catalog.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = connection_for(stdio_config("notices"), approving_gate(tmp_path / "trust.json"))
        changes: list[str] = []

        async def body() -> tuple[bool, bool, bool]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                connection.start_listening(changes.append)
                await asyncio.sleep(0.5)
                before = await _grow_and_wait(connection)
                first = int(await call_text(connection, "whoami"))
                _ = await call_text(connection, "quit")

                async def fresh_server() -> bool:
                    if not connection.is_ready or _has_tool(connection, _GROWN):
                        return False
                    return int(await call_text(connection, "whoami")) != first

                replaced = await wait_until(fresh_server, timeout_s=_NOTICE_DEADLINE_S)
                await asyncio.sleep(0.5)
                return before, replaced, await _grow_and_wait(connection)
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        before, replaced, after = asyncio.run(body())
        assert before, "the first connection never picked up the announced tool"
        assert replaced, "the server was never replaced after it exited"
        assert after, "after the reconnect the change notice was never followed"
        assert "notices" in changes


class TestLegacyNotifications:
    """A handshake-era server's change notification is acted on."""

    def test_sse_list_changed_notification_updates_the_catalog(self) -> None:
        """A ``notifications/tools/list_changed`` on a legacy connection forces a re-list."""
        with network_server("sse") as (_process, port):
            connection = connection_for(network_config("notices", port, McpTransportKind.SSE))
            changes: list[str] = []

            async def body() -> tuple[str | None, bool, list[str]]:
                await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
                try:
                    client = connection.client
                    version = client.protocol_version if client is not None else None
                    connection.start_listening(changes.append)
                    grown = await _grow_and_wait(connection)
                    return version, grown, list(changes)
                finally:
                    await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

            version, grown, reported = asyncio.run(body())
        assert version == "2025-11-25"
        assert grown, "the legacy server's list_changed notification was ignored"
        assert reported == ["notices"]


class TestNoticeInsideFreshnessWindow:
    """A change notice beats the server's own freshness hint."""

    def test_notice_within_ttl_refreshes_the_catalog(self, tmp_path: Path) -> None:
        """A listing ten minutes from stale is still re-read when the server says it changed.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        config = stdio_config("notices", extra_args=("--ttl-ms", str(_TTL_MS)))
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[int | None, bool]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                catalog = connection.catalog
                ttl = catalog.ttl_ms if catalog is not None else None
                connection.start_listening(lambda _server_id: None)
                await asyncio.sleep(0.5)
                return ttl, await _grow_and_wait(connection)
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        ttl, grown = asyncio.run(body())
        assert ttl == _TTL_MS
        assert grown, "the change notice was answered from the still-fresh cached listing"

    def test_forced_refresh_bypasses_both_caches(self, tmp_path: Path) -> None:
        """``refresh_catalog(force=True)`` asks the server even inside ``ttlMs``.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        config = stdio_config("notices", extra_args=("--ttl-ms", str(_TTL_MS)))
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[bool, bool]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                _ = await call_text(connection, "grow")
                cached = await connection.refresh_catalog()
                forced = await connection.refresh_catalog(force=True)
                return cached.entry_by_name(_GROWN) is not None, forced.entry_by_name(_GROWN) is not None
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        cached, forced = asyncio.run(body())
        assert not cached, "an unforced refresh inside ttlMs should be served from the fresh listing"
        assert forced, "a forced refresh was answered from a cache"
