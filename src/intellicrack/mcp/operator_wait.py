# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Keeps the operator's thinking time out of a server's request deadlines.

A tool call carries a deadline so a hung server cannot hold a turn forever. A
server may also stop mid-call and ask the operator something, and the operator
may take minutes to read the question. That time is theirs, not the server's:
charging it against the call's deadline would fail a call that was only
waiting for a human, long before the question's own timeout expired.

A :class:`OperatorWaitClock` belongs to one server connection. Deadlines
entered through :meth:`OperatorWaitClock.deadline` are suspended for as long
as any question from that server is open, and resume with the budget they had
left once the last one is answered.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from mcp.client.session import ClientRequestContext, ElicitationFnT
    from mcp_types import ElicitRequestParams, ElicitResult, ErrorData


@dataclass(eq=False, slots=True)
class _Deadline:
    """One running deadline and the budget it had left when suspended.

    Attributes:
        timeout: The timeout context enforcing the deadline.
        remaining_s: Seconds left when the deadline was suspended, or
            ``None`` while it is running.
    """

    timeout: asyncio.Timeout
    remaining_s: float | None = None


class OperatorWaitClock:
    """Suspends one server's request deadlines while its questions are open."""

    def __init__(self) -> None:
        """Initialize a clock with no deadlines and no open questions."""
        self._open_questions = 0
        self._deadlines: list[_Deadline] = []

    @property
    def waiting(self) -> bool:
        """Whether a question to the operator is currently open.

        Returns:
            bool: ``True`` while at least one question is unanswered.
        """
        return self._open_questions > 0

    @asynccontextmanager
    async def deadline(self, budget_s: float) -> AsyncGenerator[None]:
        """Enforce a deadline that does not run while the operator is being asked.

        Args:
            budget_s: Seconds the guarded block may take, not counting time
                spent waiting for the operator.

        A block that overruns its budget is interrupted with the
        :class:`TimeoutError` :func:`asyncio.timeout` raises.

        Yields:
            None: Control passes to the guarded block.
        """
        async with asyncio.timeout(budget_s) as timeout:
            entry = _Deadline(timeout)
            if self.waiting:
                entry.remaining_s = budget_s
                timeout.reschedule(None)
            self._deadlines.append(entry)
            try:
                yield
            finally:
                self._deadlines.remove(entry)

    @asynccontextmanager
    async def operator_turn(self) -> AsyncGenerator[None]:
        """Mark a question to the operator as open for the duration of the block.

        Yields:
            None: Control passes to the block that asks the question.
        """
        loop = asyncio.get_running_loop()
        self._open_questions += 1
        if self._open_questions == 1:
            now = loop.time()
            for entry in self._deadlines:
                when = entry.timeout.when()
                if when is not None:
                    entry.remaining_s = max(0.0, when - now)
                    entry.timeout.reschedule(None)
        try:
            yield
        finally:
            self._open_questions -= 1
            if self._open_questions == 0:
                now = loop.time()
                for entry in self._deadlines:
                    if entry.remaining_s is not None and not entry.timeout.expired():
                        entry.timeout.reschedule(now + entry.remaining_s)
                    entry.remaining_s = None

    def pause_while[**P, R](self, handler: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        """Wrap any operator-facing coroutine so its wait is not charged to a deadline.

        Args:
            handler: The coroutine function that waits on the operator, such
                as an OAuth redirect or callback handler.

        Returns:
            Callable[P, Awaitable[R]]: A function that suspends this clock's
            deadlines while the wrapped one runs.
        """

        async def _paused(*args: P.args, **kwargs: P.kwargs) -> R:
            """Run the handler with every deadline on this clock suspended.

            Args:
                *args: Positional arguments for the handler.
                **kwargs: Keyword arguments for the handler.

            Returns:
                R: What the handler returned.
            """
            async with self.operator_turn():
                return await handler(*args, **kwargs)

        return _paused

    def pause_during(self, callback: ElicitationFnT) -> ElicitationFnT:
        """Wrap an elicitation handler so its wait is not charged to any call.

        Args:
            callback: The handler that asks the operator.

        Returns:
            ElicitationFnT: A handler that suspends this clock's deadlines
            while the wrapped one runs.
        """

        async def _answer(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult | ErrorData:
            """Ask the operator with every deadline on this server suspended.

            Args:
                context: The SDK's request context.
                params: The request the server sent.

            Returns:
                ElicitResult | ErrorData: What the wrapped handler answered.
            """
            async with self.operator_turn():
                return await callback(context, params)

        return _answer
