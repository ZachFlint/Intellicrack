# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 33: servers' own log messages reach Intellicrack's logging, at the level the operator chose.

The gates connect Intellicrack's real connection to a real ``MCPServer`` that logs from inside a tool, on 2026-07-28 over stdio (where
logging is opted into per request) and 2025-11-25 over SSE (where ``logging/setLevel`` governs it). Messages arrive with the server they
came from, at or above the chosen level, cleaned of hidden characters, in the structlog pipeline the log viewer reads and in the log
book the MCP settings show. Changing the level applies to the running server; a server that floods is held to its rate.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final

import pytest
import structlog
from mcp_types import TextContent

from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.server_logs import McpServerLogBook
from tests._helpers.mcp_features_server import CHATTER_LOGGER, CHATTER_TOOL, HIDDEN_MARK, LOG_LEVEL_SEEN_TOOL
from tests._helpers.mcp_features_support import Era, features_connection


if TYPE_CHECKING:
    from collections.abc import MutableMapping
    from pathlib import Path

    from intellicrack.mcp.connection import McpConnection


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_TIMEOUT_S: Final[float] = 90.0


async def _chatter(connection: McpConnection, count: int = 1) -> None:
    """Run the logging tool.

    Args:
        connection: The connection.
        count: Rounds of messages.
    """
    result = await connection.call_tool(CHATTER_TOOL, {"count": count})
    assert not result.is_error


async def _settle() -> None:
    """Let notifications already on the wire be delivered."""
    await asyncio.sleep(0.3)


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_server_messages_reach_the_log_at_the_chosen_level(tmp_path: Path, era: Era) -> None:
    """Messages at or above ``info`` arrive attributed and cleaned; ``debug`` is not asked for; raising the level applies at once.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    book = McpServerLogBook()
    hooks = McpClientHooks(logging=book.callback_for("features"))

    async def run() -> tuple[list[tuple[str, str | None, str]], list[str], list[MutableMapping[str, Any]]]:
        """Log at info, then at warning.

        Returns:
            tuple[list[tuple[str, str | None, str]], list[str], list[MutableMapping[str, Any]]]: The records at info, the levels at
            warning, and what structlog received.
        """
        async with features_connection(tmp_path, era, hooks=hooks, log_level="info") as connection:
            with structlog.testing.capture_logs() as captured:
                await _chatter(connection)
                await _settle()
            first = [(record.level, record.logger, record.text) for record in book.records("features")]
            await connection.set_log_level("warning")
            await _chatter(connection)
            await _settle()
            later = [record.level for record in book.records("features")[len(first) :]]
            return first, later, captured

    first, later, captured = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert [level for level, _, _ in first] == ["info", "warning", "error"]
    assert {logger for _, logger, _ in first} == {CHATTER_LOGGER}
    assert all(HIDDEN_MARK not in text for _, _, text in first)
    assert first[0][2] == '{"round":0,"text":"info 0"}'
    assert first[1][2] == "warning 0"
    assert later == ["warning", "error"]
    routed = [entry for entry in captured if entry.get("event") == "mcp_server_log"]
    assert [(entry["mcp_server"], entry["mcp_level"], entry["log_level"]) for entry in routed] == [
        ("features", "info", "info"),
        ("features", "warning", "warning"),
        ("features", "error", "error"),
    ]


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_a_server_that_ignores_the_level_is_still_filtered(tmp_path: Path, era: Era) -> None:
    """A server that logs every level whatever it was asked still reaches the log only at or above the chosen level.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    book = McpServerLogBook()

    async def run() -> list[str]:
        """Run the careless logging tool at ``warning``.

        Returns:
            list[str]: The levels that reached the log book.
        """
        hooks = McpClientHooks(logging=book.callback_for("features"))
        async with features_connection(tmp_path, era, hooks=hooks, log_level="warning") as connection:
            result = await connection.call_tool(CHATTER_TOOL, {"count": 1, "heed_level": False})
            assert not result.is_error
            await _settle()
            return [record.level for record in book.records("features")]

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == ["warning", "error"]


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_lowering_the_level_applies_to_the_next_call(tmp_path: Path, era: Era) -> None:
    """A level lowered while connected reaches the server, so the next call's lower-severity messages arrive.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    book = McpServerLogBook()

    async def run() -> tuple[list[str], list[str]]:
        """Log at ``error``, then at ``info``.

        Returns:
            tuple[list[str], list[str]]: The levels received before and after lowering.
        """
        hooks = McpClientHooks(logging=book.callback_for("features"))
        async with features_connection(tmp_path, era, hooks=hooks, log_level="error") as connection:
            await _chatter(connection)
            await _settle()
            first = [record.level for record in book.records("features")]
            await connection.set_log_level("info")
            await _chatter(connection)
            await _settle()
            return first, [record.level for record in book.records("features")[len(first) :]]

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == (["error"], ["info", "warning", "error"])


def test_legacy_server_is_sent_the_chosen_level(tmp_path: Path) -> None:
    """A 2025-11-25 server is sent ``logging/setLevel`` with the configured level on connect, and again when it changes.

    Args:
        tmp_path: Per-test directory.
    """

    async def seen(connection: McpConnection) -> str:
        """Ask the server which level it was last sent.

        Args:
            connection: The connection.

        Returns:
            str: The level, or ``none``.
        """
        result = await connection.call_tool(LOG_LEVEL_SEEN_TOOL, {})
        assert not result.is_error
        [block] = result.content
        assert isinstance(block, TextContent)
        return block.text

    async def run() -> tuple[str, str]:
        """Connect at ``notice``, then change to ``critical``.

        Returns:
            tuple[str, str]: The level the server saw after connecting and after the change.
        """
        hooks = McpClientHooks(logging=McpServerLogBook().callback_for("features"))
        async with features_connection(tmp_path, Era.LEGACY, hooks=hooks, log_level="notice") as connection:
            first = await seen(connection)
            await connection.set_log_level("critical")
            return first, await seen(connection)

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == ("notice", "critical")


def test_modern_connection_without_a_level_asks_for_nothing(tmp_path: Path) -> None:
    """On 2026-07-28 a connection that chose no level receives no log messages at all.

    Args:
        tmp_path: Per-test directory.
    """
    book = McpServerLogBook()

    async def run() -> int:
        """Run the logging tool with no level chosen.

        Returns:
            int: Records received.
        """
        async with features_connection(tmp_path, Era.MODERN, hooks=McpClientHooks(logging=book.callback_for("features"))) as connection:
            await _chatter(connection)
            await _settle()
            return len(book.records("features"))

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == 0


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_a_flooding_server_is_held_to_its_rate(tmp_path: Path, era: Era) -> None:
    """A server logging far more than its burst has the excess counted rather than logged.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    book = McpServerLogBook(burst=5, rate_per_s=0.0)

    async def run() -> tuple[int, int]:
        """Flood the log.

        Returns:
            tuple[int, int]: Records kept and records held back.
        """
        hooks = McpClientHooks(logging=book.callback_for("features"))
        async with features_connection(tmp_path, era, hooks=hooks, log_level="debug") as connection:
            await _chatter(connection, count=10)
            await _settle()
            return len(book.records("features")), book.suppressed("features")

    kept, held = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert kept == 5
    assert held == 40 - 5
