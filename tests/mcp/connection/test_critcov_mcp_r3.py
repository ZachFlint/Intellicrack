# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass critical-coverage tests for ``intellicrack.mcp.connection``: progress for a call nobody is following.

A server reports progress under the token the request carried in its ``_meta``. The connection follows only the tokens of the calls it
started itself. A real fixture server is asked to report progress under a token the connection never issued, by sending the request
straight through the connection's own SDK client, so the notification reaches the connection through the SDK's real message path. What
a user would see is asserted: the notice is not delivered to the call that is being followed, nothing is recorded under the stranger's
token, the SDK's notification handler does not fail on it, the connection stays ready, and an ordinary call afterwards still works.
A control shows that a notice under the tracked token is delivered and its tracker is gone once the call ends.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final, cast

import pytest
from mcp_types import TextContent

from intellicrack.mcp.progress import ProgressKind
from tests._helpers.mcp_features_server import SLOW_TOOL
from tests._helpers.mcp_features_support import Era, features_connection


if TYPE_CHECKING:
    from pathlib import Path

    from mcp_types import RequestParamsMeta

    from intellicrack.mcp.connection import McpConnection
    from intellicrack.mcp.progress import McpProgress


pytestmark = pytest.mark.spawns_process

_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_ERA_IDS: Final[list[str]] = [era.name.lower() for era in _ERAS]
_TIMEOUT_S: Final[float] = 120.0
_STEP_S: Final[float] = 0.05
_FOLLOWED_STEPS: Final[int] = 3
_STRAY_STEPS: Final[int] = 5
_STRANGER_TOKENS: Final[list[str | int]] = ["stranger", 424242]
_STRANGER_IDS: Final[list[str]] = ["string_token", "integer_token"]
_HANDLER_FAILURE: Final[str] = "notification callback for 'notifications/progress' raised"


def _tracked_tokens(connection: McpConnection) -> list[str]:
    """List the progress tokens a connection is following.

    Args:
        connection: The connection.

    Returns:
        list[str]: The tokens of its calls that are still running.
    """
    return sorted(cast("dict[str, object]", getattr(connection, "_progress")))


def _text_of(result_content: object) -> str:
    """Read the text of the only content part of a tool result.

    Args:
        result_content: The ``content`` list of a tool result.

    Returns:
        str: The part's text.
    """
    [block] = cast("list[object]", result_content)
    assert isinstance(block, TextContent)
    return block.text


def _handler_failures(caplog: pytest.LogCaptureFixture) -> list[str]:
    """List the logged failures of the SDK's notification handler for a progress notice.

    Args:
        caplog: The log capture.

    Returns:
        list[str]: The messages of error records that name the failure.
    """
    return [record.getMessage() for record in caplog.records if record.levelno >= logging.ERROR and _HANDLER_FAILURE in record.getMessage()]


@pytest.mark.parametrize("token", _STRANGER_TOKENS, ids=_STRANGER_IDS)
@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_progress_under_a_token_nobody_follows_is_ignored_and_the_connection_keeps_working(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    era: Era,
    token: str | int,
) -> None:
    """A notice under an unknown token reaches no call, leaves no record, and the connection still serves calls.

    A followed call and a call sent under a stranger's token run side by side, so a notice that is wrongly routed to whatever call is
    being followed shows up in what that call's caller saw. The stranger's call reports five steps and the followed call three.

    Args:
        tmp_path: Per-test directory.
        caplog: The log capture.
        era: The protocol generation.
        token: The progress token the stranger's call carries.
    """
    seen: list[tuple[float, float | None, str | None]] = []

    async def run() -> tuple[str, str, str, bool, list[str]]:
        """Run the followed call beside the stranger's, then an ordinary call.

        Returns:
            tuple[str, str, str, bool, list[str]]: The followed call's text, the stranger's call's text, the ordinary call's text,
            whether the connection is ready, and the tokens still followed afterwards.
        """
        async with features_connection(tmp_path, era) as connection:
            client = connection.client
            assert client is not None
            stranger = cast("RequestParamsMeta", {"progressToken": token})

            def note(progress: McpProgress) -> None:
                """Record one notice handed to the followed call's caller.

                Args:
                    progress: The notice.
                """
                seen.append((progress.progress, progress.total, progress.message))

            followed, stray = await asyncio.gather(
                connection.call_tool(SLOW_TOOL, {"steps": _FOLLOWED_STEPS, "delay": _STEP_S}, on_progress=note),
                client.call_tool(SLOW_TOOL, {"steps": _STRAY_STEPS, "delay": _STEP_S}, meta=stranger),
            )
            ordinary = await connection.call_tool(SLOW_TOOL, {"steps": 1, "delay": 0.0})
            return (
                _text_of(followed.content),
                _text_of(stray.content),
                _text_of(ordinary.content),
                connection.is_ready,
                _tracked_tokens(connection),
            )

    with caplog.at_level(logging.ERROR):
        followed_text, stray_text, ordinary_text, ready, left = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert followed_text == f"took {_FOLLOWED_STEPS} steps"
    assert stray_text == f"took {_STRAY_STEPS} steps"
    assert ordinary_text == "took 1 steps"
    assert ready
    assert left == []
    assert seen == [(1, 3, "step 1"), (2, 3, "step 2"), (3, 3, "step 3")]
    assert _handler_failures(caplog) == []


@pytest.mark.parametrize("era", _ERAS, ids=_ERA_IDS)
def test_progress_under_a_followed_token_is_delivered_and_the_tracker_ends_with_the_call(tmp_path: Path, era: Era) -> None:
    """Control: a notice under the token a call carries reaches its caller, and no token is followed once the call ends.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    seen: list[tuple[ProgressKind, str, float]] = []
    mid_call: list[list[str]] = []

    async def run() -> list[str]:
        """Run one followed call, looking at the followed tokens while it runs.

        Returns:
            list[str]: The tokens still followed after the call.
        """
        async with features_connection(tmp_path, era) as connection:

            def note(progress: McpProgress) -> None:
                """Record one notice and the tokens followed when it arrived.

                Args:
                    progress: The notice.
                """
                seen.append((progress.kind, progress.subject, progress.progress))
                mid_call.append(_tracked_tokens(connection))

            result = await connection.call_tool(SLOW_TOOL, {"steps": _FOLLOWED_STEPS, "delay": _STEP_S}, on_progress=note)
            assert _text_of(result.content) == f"took {_FOLLOWED_STEPS} steps"
            return _tracked_tokens(connection)

    left = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert seen == [(ProgressKind.TOOL, SLOW_TOOL, 1), (ProgressKind.TOOL, SLOW_TOOL, 2), (ProgressKind.TOOL, SLOW_TOOL, 3)]
    assert [len(tokens) for tokens in mid_call] == [1, 1, 1]
    assert mid_call[0][0].startswith("intellicrack-")
    assert left == []
