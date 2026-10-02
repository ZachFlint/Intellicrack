# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 34: servers report progress on long requests, progress stretches deadlines within a limit, and calls can be cancelled.

The gates connect Intellicrack's real connection to a real ``MCPServer`` on 2026-07-28 over stdio and 2025-11-25 over SSE. Tool calls,
resource reads and prompt fetches ask for progress and receive it attributed and cleaned. The deadline rule is pinned: each notice that
reports more progress than before gives the request its full timeout again; a server whose progress stops advancing times out one
timeout after its last advance; and no amount of progress carries a request past ten timeouts. Cancelling a call cancels it on the
server. The deadline clock's cap is also shown to leave the operator's time out.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final

import pytest
from mcp_types import TextContent

from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.operator_wait import PROGRESS_RENEWAL_FACTOR, OperatorWaitClock
from intellicrack.mcp.progress import McpProgress, ProgressKind
from intellicrack.mcp.resources import get_prompt, read_resource
from tests._helpers.mcp_features_server import CANCELLATIONS_TOOL, HIDDEN_MARK, SLOW_PROMPT, SLOW_RESOURCE, SLOW_TOOL
from tests._helpers.mcp_features_support import Era, features_connection


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.mcp.connection import McpConnection


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_ERA_IDS: Final[list[str]] = [era.name.lower() for era in _ERAS]
_TIMEOUT_S: Final[float] = 120.0
_SHORT_TIMEOUT_S: Final[float] = 1.0
_STEP_S: Final[float] = 0.25


async def _cancellations(connection: McpConnection) -> str:
    """Ask the server how many slow calls it saw cancelled.

    Args:
        connection: The connection.

    Returns:
        str: The count.
    """
    result = await connection.call_tool(CANCELLATIONS_TOOL, {})
    [block] = result.content
    assert isinstance(block, TextContent)
    return block.text


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_tool_progress_arrives_attributed_and_cleaned(tmp_path: Path, era: Era) -> None:
    """Each step the server reports reaches the caller, naming the server and tool, its message cleaned.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    seen: list[McpProgress] = []

    async def run() -> None:
        """Run a three-step call."""
        async with features_connection(tmp_path, era) as connection:
            result = await connection.call_tool(SLOW_TOOL, {"steps": 3, "delay": 0.05}, on_progress=seen.append)
            assert not result.is_error

    asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert [(item.progress, item.total, item.message) for item in seen] == [(1, 3, "step 1"), (2, 3, "step 2"), (3, 3, "step 3")]
    assert {(item.server_id, item.kind, item.subject) for item in seen} == {("features", ProgressKind.TOOL, SLOW_TOOL)}
    assert all(HIDDEN_MARK not in (item.message or "") for item in seen)
    assert seen[-1].fraction == pytest.approx(1.0)
    assert seen[0].describe() == "1/3: step 1"


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_advancing_progress_renews_the_deadline(tmp_path: Path, era: Era) -> None:
    """A call that advances every quarter of its timeout runs well past the timeout and succeeds.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> tuple[bool, float]:
        """Run a call lasting several timeouts.

        Returns:
            tuple[bool, float]: Whether it reported an error, and how long it took.
        """
        async with features_connection(tmp_path, era, request_timeout_s=_SHORT_TIMEOUT_S) as connection:
            started = time.monotonic()
            result = await connection.call_tool(SLOW_TOOL, {"steps": 12, "delay": _STEP_S})
            return result.is_error, time.monotonic() - started

    is_error, took = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert not is_error
    assert took > 2 * _SHORT_TIMEOUT_S


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_progress_that_does_not_advance_does_not_renew(tmp_path: Path, era: Era) -> None:
    """A server repeating the same progress times out one timeout after it started, and the server sees the call cancelled.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> tuple[str, float, str]:
        """Run a call whose progress never advances.

        Returns:
            tuple[str, float, str]: The error, how long it took, and the server's cancellation count.
        """
        async with features_connection(tmp_path, era, request_timeout_s=_SHORT_TIMEOUT_S) as connection:
            started = time.monotonic()
            with pytest.raises(McpConnectionError) as caught:
                _ = await connection.call_tool(SLOW_TOOL, {"steps": 12, "delay": _STEP_S, "stuck": True})
            took = time.monotonic() - started
            await asyncio.sleep(0.3)
            return str(caught.value), took, await _cancellations(connection)

    error, took, cancelled = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert "without progress" in error
    assert took < 2 * _SHORT_TIMEOUT_S
    assert cancelled == "1"


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_progress_cannot_stretch_a_call_past_its_limit(tmp_path: Path, era: Era) -> None:
    """A call that keeps advancing is still stopped at ten timeouts.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    limit = _SHORT_TIMEOUT_S * PROGRESS_RENEWAL_FACTOR

    async def run() -> float:
        """Run a call that would advance for longer than its limit.

        Returns:
            float: How long it ran before it was stopped.
        """
        async with features_connection(tmp_path, era, request_timeout_s=_SHORT_TIMEOUT_S) as connection:
            started = time.monotonic()
            with pytest.raises(McpConnectionError):
                _ = await connection.call_tool(SLOW_TOOL, {"steps": int(2 * limit / _STEP_S), "delay": _STEP_S})
            return time.monotonic() - started

    took = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert limit - _STEP_S <= took < limit + _SHORT_TIMEOUT_S


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_cancelling_a_call_cancels_it_on_the_server(tmp_path: Path, era: Era) -> None:
    """A caller cancelled mid-call stops waiting at once, and the server's own handler is cancelled.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> str:
        """Start a long call, cancel it after its first step, and ask the server.

        Returns:
            str: The server's cancellation count.
        """
        async with features_connection(tmp_path, era) as connection:
            first = asyncio.Event()
            call = asyncio.create_task(
                connection.call_tool(SLOW_TOOL, {"steps": 200, "delay": 0.05}, on_progress=lambda _progress: first.set()),
            )
            await first.wait()
            _ = call.cancel()
            with pytest.raises(asyncio.CancelledError):
                await call
            await asyncio.sleep(0.3)
            return await _cancellations(connection)

    assert asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S)) == "1"


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_resource_reads_and_prompts_report_progress(tmp_path: Path, era: Era) -> None:
    """Reading a resource and fetching a prompt ask for progress and receive it, attributed to what was asked for.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    seen: list[McpProgress] = []

    async def run() -> None:
        """Read the slow resource and fetch the slow prompt."""
        async with features_connection(tmp_path, era) as connection:
            parts = await read_resource(connection, SLOW_RESOURCE, on_progress=seen.append)
            assert parts
            messages = await get_prompt(connection, SLOW_PROMPT, {}, on_progress=seen.append)
            assert messages

    asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert [(item.kind, item.subject, item.progress, item.message) for item in seen] == [
        (ProgressKind.RESOURCE, SLOW_RESOURCE, 1, "reading"),
        (ProgressKind.RESOURCE, SLOW_RESOURCE, 2, "read"),
        (ProgressKind.PROMPT, SLOW_PROMPT, 1, "building"),
    ]


def test_the_limit_does_not_count_the_operators_time() -> None:
    """A request that waited on the operator for longer than its whole limit can still be renewed afterwards."""

    async def run() -> bool:
        """Wait on the operator past the limit, then report progress.

        Returns:
            bool: Whether the renewal after the wait moved the deadline.
        """
        clock = OperatorWaitClock()
        budget = 0.05
        async with clock.deadline(budget) as deadline:
            async with clock.operator_turn():
                await asyncio.sleep(budget * PROGRESS_RENEWAL_FACTOR * 1.5)
            await asyncio.sleep(budget / 4)
            return deadline.renew()

    assert asyncio.run(run()) is True
