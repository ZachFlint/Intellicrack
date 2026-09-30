# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 34: the operator sees a running MCP call's progress and can cancel that one call while the turn goes on.

The gates run the real agent loop against a loopback model endpoint that asks for one call to a real ``MCPServer``'s slow tool, on
2026-07-28 over stdio and 2025-11-25 over SSE. The orchestrator reports the call's progress under the call's id; cancelling the call
cancels it on the server, ends it with a failed result saying the operator cancelled it, and the model is asked again with that result.
Cancelling the whole turn stops a running call at once rather than waiting for it to finish.
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any, Final

import pytest
from mcp_types import TextContent

from intellicrack.core.orchestrator import OPERATOR_CANCELLED_ERROR
from intellicrack.core.types import ConfirmationLevel
from intellicrack.mcp.config import to_canonical_name
from intellicrack.providers.capabilities import ApiDialect
from tests._helpers.mcp_agent_harness import DIALECT_SCRIPTS, TURN_TIMEOUT_S, agent_stack
from tests._helpers.mcp_features_server import CANCELLATIONS_TOOL, SLOW_TOOL
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, features_config
from tests._helpers.mcp_http_process import running_server


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.core.tool_progress import ToolProgress
    from intellicrack.core.types import ToolCall, ToolResult
    from tests._helpers.scripted_http_server import RecordedRequest, ScriptedResponse


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_DIALECT: Final[ApiDialect] = ApiDialect.CHAT_COMPLETIONS


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_operator_cancels_one_running_call_and_the_turn_goes_on(tmp_path: Path, era: Era) -> None:
    """Progress is reported under the call's id; cancelling it fails that call, stops it on the server, and the model hears why.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    script = DIALECT_SCRIPTS[_DIALECT]
    function_name = to_canonical_name("features", SLOW_TOOL)

    async def run() -> tuple[list[ToolProgress], bool, list[ToolResult], list[str], str, list[dict[str, object]]]:
        """Drive the turn, cancelling the call after its first progress.

        Returns:
            tuple[list[ToolProgress], bool, list[ToolResult], list[str], str, list[dict[str, object]]]: The progress reported, whether
            the cancel found the call running, the results, the calls running afterwards, the server's cancellation count, and the
            model requests.
        """
        async with AsyncExitStack() as stack:
            port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
            responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
                script.tool_call(function_name, {"steps": 400, "delay": 0.05}),
                script.final(),
            ]
            agents = await stack.enter_async_context(agent_stack(tmp_path, _DIALECT, (features_config(era, port=port),), responses))
            progress: list[ToolProgress] = []
            first = asyncio.Event()

            def record(item: ToolProgress) -> None:
                """Keep one progress report.

                Args:
                    item: The report.
                """
                progress.append(item)
                first.set()

            agents.orchestrator.tool_calls.set_progress_callback(record)
            turn = asyncio.create_task(agents.orchestrator.process_user_input("call the tool"))
            await asyncio.wait_for(first.wait(), TURN_TIMEOUT_S)
            cancelled = await agents.orchestrator.tool_calls.cancel(progress[0].call_id)
            await asyncio.wait_for(turn, TURN_TIMEOUT_S)
            await asyncio.sleep(0.3)
            connection = agents.manager.connection("features")
            assert connection is not None
            count = await connection.call_tool(CANCELLATIONS_TOOL, {})
            [block] = count.content
            assert isinstance(block, TextContent)
            return progress, cancelled, list(agents.results), agents.orchestrator.tool_calls.running, block.text, agents.model_requests()

    progress, cancelled, results, running, server_cancellations, requests = asyncio.run(run())
    assert cancelled is True
    assert progress[0].message == "step 1"
    assert progress[0].total == pytest.approx(400)
    [result] = results
    assert result.call_id == progress[0].call_id
    assert (result.success, result.error) == (False, OPERATOR_CANCELLED_ERROR)
    assert running == []
    assert server_cancellations == "1"
    assert len(requests) == len(("tool call", "after the cancelled result"))
    assert OPERATOR_CANCELLED_ERROR in json.dumps(requests[1])


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_cancelling_the_turn_stops_the_running_call(tmp_path: Path, era: Era) -> None:
    """Cancelling the whole turn stops a call still running on the server instead of waiting for it.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    script = DIALECT_SCRIPTS[_DIALECT]
    function_name = to_canonical_name("features", SLOW_TOOL)

    async def run() -> tuple[bool, float, str]:
        """Start the turn, then cancel it once the call has reported progress.

        Returns:
            tuple[bool, float, str]: Whether the turn ended cancelled, how long the cancel took, and the server's cancellation count.
        """
        async with AsyncExitStack() as stack:
            port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
            responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
                script.tool_call(function_name, {"steps": 2000, "delay": 0.05}),
                script.final(),
            ]
            agents = await stack.enter_async_context(agent_stack(tmp_path, _DIALECT, (features_config(era, port=port),), responses))
            first = asyncio.Event()
            agents.orchestrator.tool_calls.set_progress_callback(lambda _item: first.set())
            turn = asyncio.create_task(agents.orchestrator.process_user_input("call the tool"))
            await asyncio.wait_for(first.wait(), TURN_TIMEOUT_S)
            started = time.monotonic()
            await agents.orchestrator.cancel()
            try:
                await asyncio.wait_for(turn, TURN_TIMEOUT_S)
            except asyncio.CancelledError:
                cancelled = True
            else:
                cancelled = False
            took = time.monotonic() - started
            await asyncio.sleep(0.3)
            connection = agents.manager.connection("features")
            assert connection is not None
            count = await connection.call_tool(CANCELLATIONS_TOOL, {})
            [block] = count.content
            assert isinstance(block, TextContent)
            return cancelled, took, block.text

    cancelled, took, server_cancellations = asyncio.run(run())
    assert cancelled is True
    assert took < TURN_TIMEOUT_S / 10
    assert server_cancellations == "1"


def test_a_declined_call_still_reports_its_result(tmp_path: Path) -> None:
    """A call the operator declines to confirm reports its failed result, so anything showing it as running can stop.

    Args:
        tmp_path: Per-test directory.
    """
    script = DIALECT_SCRIPTS[_DIALECT]

    async def run() -> tuple[list[str], list[ToolResult]]:
        """Run a turn whose one call the operator declines.

        Returns:
            tuple[list[str], list[ToolResult]]: The calls reported as started, and the results reported.
        """
        responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
            script.tool_call(to_canonical_name("features", SLOW_TOOL), {"steps": 1, "delay": 0.0}),
            script.final(),
        ]
        async with agent_stack(tmp_path, _DIALECT, (features_config(Era.MODERN),), responses) as agents:
            started: list[str] = []

            def decline(_call: ToolCall) -> asyncio.Future[bool]:
                """Decline the call at once.

                Args:
                    _call: The call.

                Returns:
                    asyncio.Future[bool]: A settled refusal.
                """
                answer: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
                answer.set_result(False)
                return answer

            agents.orchestrator.set_confirmation_level(ConfirmationLevel.ALL)
            agents.orchestrator.set_async_confirmation_callback(decline)
            agents.orchestrator.set_tool_call_callback(lambda call: started.append(call.id))
            await asyncio.wait_for(agents.orchestrator.process_user_input("call the tool"), TURN_TIMEOUT_S)
            return started, list(agents.results)

    started, results = asyncio.run(run())
    assert [result.call_id for result in results] == started
    assert [result.error for result in results] == ["User declined confirmation"]
