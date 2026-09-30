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

A request that reports progress may run past its budget. Each time the server
reports more progress than before, :meth:`RequestDeadline.renew` gives the
request its full budget again from that moment, so a long call that keeps
moving is not cut off while a call that stops moving still fails one budget
after its last step. Renewals never carry a request past
:data:`PROGRESS_RENEWAL_FACTOR` times its budget from when it started, so a
server that reports progress forever cannot hold a request open forever.
Operator time counts toward neither the budget nor that cap.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, ParamSpec, TypeVar


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

    from mcp.client.session import ClientRequestContext, ElicitationFnT, SamplingFnT
    from mcp_types import (
        CreateMessageRequestParams,
        CreateMessageResult,
        CreateMessageResultWithTools,
        ElicitRequestParams,
        ElicitResult,
        ErrorData,
    )


_P = ParamSpec("_P")
_R = TypeVar("_R")


PROGRESS_RENEWAL_FACTOR: Final[float] = 10.0
"""How many budgets, in all, progress can stretch one request to."""


@dataclass(eq=False, slots=True)
class _Deadline:
    """One running deadline and the budget it had left when suspended.

    Attributes:
        timeout: The timeout context enforcing the deadline.
        budget_s: The request's budget, which a renewal restores.
        cap_at: The loop time past which no renewal carries the request,
            moved later by every stretch spent waiting for the operator.
        remaining_s: Seconds left when the deadline was suspended, or
            ``None`` while it is running.
    """

    timeout: asyncio.Timeout
    budget_s: float
    cap_at: float
    remaining_s: float | None = None


class RequestDeadline:
    """The deadline of one request, which progress from the server can renew."""

    def __init__(self, clock: OperatorWaitClock, entry: _Deadline) -> None:
        """Bind the handle to its clock and deadline.

        Args:
            clock: The clock the deadline runs on.
            entry: The deadline.
        """
        self._clock = clock
        self._entry = entry

    def renew(self) -> bool:
        """Give the request its full budget again from now, within its cap.

        Returns:
            bool: Whether the deadline moved later; ``False`` once the cap is
            reached, or when the request has already timed out.
        """
        return self._clock.renew(self._entry)


class OperatorWaitClock:
    """Suspends one server's request deadlines while its questions are open."""

    def __init__(self) -> None:
        """Initialize a clock with no deadlines and no open questions."""
        self._open_questions = 0
        self._deadlines: list[_Deadline] = []
        self._paused_at: float | None = None

    @property
    def waiting(self) -> bool:
        """Whether a question to the operator is currently open.

        Returns:
            bool: ``True`` while at least one question is unanswered.
        """
        return self._open_questions > 0

    @asynccontextmanager
    async def deadline(self, budget_s: float) -> AsyncGenerator[RequestDeadline]:
        """Enforce a deadline that does not run while the operator is being asked.

        Args:
            budget_s: Seconds the guarded block may take, not counting time
                spent waiting for the operator.

        A block that overruns its budget is interrupted with the
        :class:`TimeoutError` :func:`asyncio.timeout` raises.

        Yields:
            RequestDeadline: The deadline, which progress can renew.
        """
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(budget_s) as timeout:
            entry = _Deadline(timeout, budget_s, loop.time() + budget_s * PROGRESS_RENEWAL_FACTOR)
            if self.waiting:
                entry.remaining_s = budget_s
                timeout.reschedule(None)
            self._deadlines.append(entry)
            try:
                yield RequestDeadline(self, entry)
            finally:
                self._deadlines.remove(entry)

    def renew(self, entry: _Deadline) -> bool:
        """Restore one deadline's full budget from now, never past its cap.

        While the operator is being asked, the deadline is suspended; the
        renewal then restores the budget it resumes with, bounded by what is
        left of its cap as of the moment the wait began.

        Args:
            entry: The deadline.

        Returns:
            bool: Whether the deadline moved later.
        """
        if entry.timeout.expired():
            return False
        now = asyncio.get_running_loop().time()
        paused_at = self._paused_at
        if entry.remaining_s is not None and paused_at is not None:
            renewed = min(entry.budget_s, max(0.0, entry.cap_at - paused_at))
            if renewed <= entry.remaining_s:
                return False
            entry.remaining_s = renewed
            return True
        target = min(now + entry.budget_s, entry.cap_at)
        current = entry.timeout.when()
        if current is not None and target <= current:
            return False
        entry.timeout.reschedule(target)
        return True

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
            self._paused_at = now
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
                paused_for = now - (self._paused_at if self._paused_at is not None else now)
                self._paused_at = None
                for entry in self._deadlines:
                    entry.cap_at += paused_for
                    if entry.remaining_s is not None and not entry.timeout.expired():
                        entry.timeout.reschedule(now + entry.remaining_s)
                    entry.remaining_s = None

    def pause_while(self, handler: Callable[_P, Awaitable[_R]]) -> Callable[_P, Awaitable[_R]]:
        """Wrap any operator-facing coroutine so its wait is not charged to a deadline.

        Args:
            handler: The coroutine function that waits on the operator, such
                as an OAuth redirect or callback handler.

        Returns:
            Callable[_P, Awaitable[_R]]: A function that suspends this clock's
            deadlines while the wrapped one runs.
        """

        async def _paused(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            """Run the handler with every deadline on this clock suspended.

            Args:
                *args: Positional arguments for the handler.
                **kwargs: Keyword arguments for the handler.

            Returns:
                _R: What the handler returned.
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

    def pause_sampling(self, callback: SamplingFnT) -> SamplingFnT:
        """Wrap a sampling handler so the operator's approval and the model's answer are not charged to any call.

        A server that samples in the middle of ``tools/call`` is waiting on
        the operator and then on a model; neither is the server's time.

        Args:
            callback: The handler that approves and runs the sampling request.

        Returns:
            SamplingFnT: A handler that suspends this clock's deadlines while
            the wrapped one runs.
        """

        async def _sample(
            context: ClientRequestContext,
            params: CreateMessageRequestParams,
        ) -> CreateMessageResult | CreateMessageResultWithTools | ErrorData:
            """Sample with every deadline on this server suspended.

            Args:
                context: The SDK's request context.
                params: The request the server sent.

            Returns:
                CreateMessageResult | CreateMessageResultWithTools | ErrorData:
                What the wrapped handler answered.
            """
            async with self.operator_turn():
                return await callback(context, params)

        return _sample
