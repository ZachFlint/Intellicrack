# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for operator wait time and for starting servers side by side.

A server that asks the operator something mid-call must not have the
operator's reading time charged against the call's deadline, and a server
waiting on the operator at startup must not hold back every server configured
after it. Both are exercised against the SDK's own server over a real stdio
pipe, with the operator's answers given by real callables that take real time.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from mcp_types import ElicitResult

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnection, McpConnectionManager
from intellicrack.mcp.consent import ConsentAnswer, McpConsentGate, TrustStore
from intellicrack.mcp.operator_wait import OperatorWaitClock
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_interactive_server import ASK_TOOL_NAME


if TYPE_CHECKING:
    from mcp.client.session import ClientRequestContext
    from mcp_types import ElicitRequestParams

    from intellicrack.mcp.consent import DangerousPattern


_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_interactive_server.py"
_CALL_BUDGET_S = 1.5
_OPERATOR_DELAY_S = 3.0
_READY_WAIT_S = 30.0


def _config(server_id: str, *, timeout_s: float = 30.0) -> McpServerConfig:
    """Build an enabled stdio configuration for the interactive fixture server.

    Args:
        server_id: Identifier for the server.
        timeout_s: Per-call timeout.

    Returns:
        McpServerConfig: The configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT),))
    return McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=timeout_s)


def _approving_gate(tmp_path: Path) -> McpConsentGate:
    """Build a consent gate that approves every launch.

    Args:
        tmp_path: Directory backing the trust store.

    Returns:
        McpConsentGate: The gate.
    """

    def approve(_config: McpServerConfig, _description: str, _findings: list[DangerousPattern]) -> bool:
        """Approve the launch.

        Args:
            _config: The server being launched.
            _description: The rendered launch description.
            _findings: Flagged patterns.

        Returns:
            bool: Always ``True``.
        """
        return True

    return McpConsentGate(TrustStore(tmp_path / "trust.json"), approve)


class TestOperatorWaitClock:
    """Deadlines stop while the operator is being asked, and only then."""

    def test_deadline_still_fires_without_a_question(self) -> None:
        """A block that overruns its budget with nobody being asked times out."""

        async def body() -> None:
            """Overrun a short deadline."""
            clock = OperatorWaitClock()
            async with clock.deadline(0.2):
                await asyncio.sleep(2.0)

        with pytest.raises(TimeoutError):
            asyncio.run(body())

    def test_open_question_suspends_the_deadline(self) -> None:
        """Time spent inside an operator turn is not charged to the deadline."""

        async def body() -> str:
            """Spend longer than the budget answering a question.

            Returns:
                str: A marker proving the block completed.
            """
            clock = OperatorWaitClock()
            async with clock.deadline(0.5):
                async with clock.operator_turn():
                    await asyncio.sleep(1.0)
                await asyncio.sleep(0.1)
            return "completed"

        assert asyncio.run(body()) == "completed"

    def test_budget_left_resumes_after_the_answer(self) -> None:
        """The deadline resumes with the budget it had left, so overrunning afterwards still fails."""

        async def body() -> None:
            """Answer a question, then overrun what is left of the budget."""
            clock = OperatorWaitClock()
            async with clock.deadline(0.5):
                async with clock.operator_turn():
                    await asyncio.sleep(0.6)
                await asyncio.sleep(1.0)

        with pytest.raises(TimeoutError):
            asyncio.run(body())


class TestElicitationDoesNotCountAgainstTheCall:
    """A slow operator answer does not fail the call that asked for it."""

    def test_call_outlives_its_budget_while_the_operator_answers(self, tmp_path: Path) -> None:
        """The call succeeds although the operator took longer than the call's whole budget.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """

        async def answer(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
            """Answer the server after the operator has thought about it.

            Args:
                context: The SDK's request context.
                params: The request the server sent.

            Returns:
                ElicitResult: The accepted form.
            """
            del context, params
            await asyncio.sleep(_OPERATOR_DELAY_S)
            return ElicitResult(action="accept", content={"name": "ada"})

        connection = McpConnection(
            _config("ask", timeout_s=_CALL_BUDGET_S),
            McpSecretResolver(CredentialStore()),
            consent=_approving_gate(tmp_path),
            elicitation_callback=answer,
        )

        async def body() -> str:
            """Call the eliciting tool.

            Returns:
                str: The tool's text result.
            """
            await connection.connect()
            try:
                result = await connection.call_tool(ASK_TOOL_NAME, {})
            finally:
                await connection.disconnect()
            return "".join(getattr(block, "text", "") for block in result.content)

        assert asyncio.run(body()) == "hello ada"


class TestServersStartSideBySide:
    """One server waiting on the operator does not hold back the others."""

    def test_second_server_is_ready_while_the_first_awaits_consent(self, tmp_path: Path) -> None:
        """The second server connects while the first one's consent prompt is still open.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = McpConfigStore(tmp_path / "mcp.json")
        store.save(McpConfigDocument(servers=(_config("first"), _config("second"))))

        async def body() -> tuple[bool, bool, bool]:
            """Start both servers, holding the first one's consent open.

            Returns:
                tuple[bool, bool, bool]: Whether the second became ready while
                the first was pending, whether the first was still pending
                then, and whether the first became ready once answered.
            """
            released = asyncio.Event()

            async def prompt(config: McpServerConfig, _description: str, _findings: list[DangerousPattern]) -> ConsentAnswer:
                """Hold the first server's consent until released.

                Args:
                    config: The server being launched.
                    _description: The rendered launch description.
                    _findings: Flagged patterns.

                Returns:
                    ConsentAnswer: Approval, once released for the first server.
                """
                if config.server_id == "first":
                    await released.wait()
                return ConsentAnswer(approved=True)

            gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt)
            manager = McpConnectionManager(store, McpSecretResolver(CredentialStore()), gate)
            start = asyncio.create_task(manager.start())
            try:
                second_ready = False
                async with asyncio.timeout(_READY_WAIT_S):
                    while not second_ready and not start.done():
                        second = manager.connection("second")
                        second_ready = second is not None and second.is_ready
                        await asyncio.sleep(0.1)
                first = manager.connection("first")
                first_pending = first is not None and not first.is_ready
                released.set()
                await asyncio.wait_for(start, timeout=_READY_WAIT_S)
                first = manager.connection("first")
                first_ready = first is not None and first.is_ready
            finally:
                released.set()
                await manager.stop()
            return second_ready, first_pending, first_ready

        second_ready, first_pending, first_ready = asyncio.run(body())
        assert second_ready, "the second server did not come up while the first waited for consent"
        assert first_pending, "the first server was not actually waiting, so this proves nothing"
        assert first_ready, "the first server never started once its consent was given"
