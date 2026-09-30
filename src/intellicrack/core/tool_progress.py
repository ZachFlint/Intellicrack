# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Progress a running tool call reports, carried from the tool back to the operator.

The orchestrator runs each tool call with a reporter bound for that call. Whatever carries out the call -- a server's tool, reached
through the MCP tool source -- picks the reporter up with :func:`current_progress_reporter` when the call starts, and reports through it
for as long as the call runs, even from another task. The orchestrator turns each report into a :class:`ToolProgress` for the call and
hands it to the UI, which shows it beside the running call.

:class:`RunningToolCalls` runs each call as a task of its own, which is what lets the operator cancel one call while the turn goes on.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, TypeVar, cast


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator


_T = TypeVar("_T")


type ToolProgressReporter = Callable[[float, float | None, str | None], None]
"""Reports how far a call has got, its total if known, and a message."""


_REPORTER: ContextVar[ToolProgressReporter | None] = ContextVar("intellicrack_tool_progress_reporter", default=None)


@dataclass(frozen=True, slots=True)
class ToolProgress:
    """How far one running tool call has got.

    Attributes:
        call_id: The call.
        progress: How far it has got.
        total: The total it is working towards, or ``None`` when unknown.
        message: What the tool said about it, already cleaned, or ``None``.
    """

    call_id: str
    progress: float
    total: float | None = None
    message: str | None = None

    @property
    def fraction(self) -> float | None:
        """How much of the total is done.

        Returns:
            float | None: A value from 0 to 1, or ``None`` when the total is
            unknown.
        """
        if self.total is None or self.total <= 0:
            return None
        return min(1.0, max(0.0, self.progress / self.total))

    def describe(self) -> str:
        """Render the progress for the operator.

        Returns:
            str: How far the call has got, out of what total, and what the
            tool said, such as ``3/10: indexing sections``.
        """
        amount = f"{self.progress:g}/{self.total:g}" if self.total is not None else f"{self.progress:g}"
        return f"{amount}: {self.message}" if self.message else amount


def current_progress_reporter() -> ToolProgressReporter | None:
    """Find the reporter bound for the tool call running in this context.

    Returns:
        ToolProgressReporter | None: The reporter, or ``None`` outside a
        tool call.
    """
    return _REPORTER.get()


@contextmanager
def reporting_progress(reporter: ToolProgressReporter) -> Generator[None]:
    """Bind a reporter for the tool call that runs inside the block.

    Args:
        reporter: Receives the call's progress.

    Yields:
        None: Control passes to the block.
    """
    token = _REPORTER.set(reporter)
    try:
        yield
    finally:
        _REPORTER.reset(token)


class ToolCallCancelledError(Exception):
    """Raised for a tool call the operator cancelled on its own."""


class RunningToolCalls:
    """The tool calls running now, which the operator can cancel one at a time.

    Each call runs as its own task with a progress reporter bound, so the
    operator can stop one call and let the turn go on, and see how far each
    one has got meanwhile. Everything here runs on the orchestrator's loop.
    """

    def __init__(self) -> None:
        """Start with no calls running."""
        self._tasks: dict[str, asyncio.Task[object]] = {}
        self._cancelled: set[str] = set()
        self._on_progress: Callable[[ToolProgress], None] | None = None

    def set_progress_callback(self, callback: Callable[[ToolProgress], None] | None) -> None:
        """Choose who receives running calls' progress.

        Args:
            callback: Receives each report, or ``None`` to stop reporting.
        """
        self._on_progress = callback

    @property
    def running(self) -> list[str]:
        """The ids of the calls running now.

        Returns:
            list[str]: The call ids.
        """
        return [call_id for call_id, task in self._tasks.items() if not task.done()]

    async def run(self, call_id: str, work: Callable[[], Awaitable[_T]]) -> _T:
        """Run one call as a task of its own, with its progress reported.

        Args:
            call_id: The call.
            work: Carries the call out.

        Returns:
            _T: What the call returned.

        Raises:
            ToolCallCancelledError: If the operator cancelled this call.
            asyncio.CancelledError: If whoever awaits the call was cancelled,
                which cancels the call with it.
        """

        async def _reporting() -> _T:
            """Carry the call out with its reporter bound.

            Returns:
                _T: What the call returned.
            """
            with reporting_progress(partial(self._report, call_id)):
                return await work()

        task: asyncio.Task[_T] = asyncio.create_task(_reporting(), name=f"tool-call-{call_id}")
        self._tasks[call_id] = cast("asyncio.Task[object]", task)
        try:
            return await task
        except asyncio.CancelledError as exc:
            current = asyncio.current_task()
            if call_id not in self._cancelled or (current is not None and current.cancelling() > 0):
                raise
            message = f"tool call {call_id} was cancelled by the operator"
            raise ToolCallCancelledError(message) from exc
        finally:
            _ = self._tasks.pop(call_id, None)
            self._cancelled.discard(call_id)

    def _report(self, call_id: str, progress: float, total: float | None, message: str | None) -> None:
        """Hand one call's progress on.

        Args:
            call_id: The call.
            progress: How far it has got.
            total: Its total, or ``None``.
            message: What the tool said, or ``None``.
        """
        callback = self._on_progress
        if callback is not None:
            callback(ToolProgress(call_id=call_id, progress=progress, total=total, message=message))

    async def cancel(self, call_id: str) -> bool:
        """Cancel one running call and wait for it to stop.

        Args:
            call_id: The call.

        Returns:
            bool: Whether the call was running and has now stopped.
        """
        task = self._tasks.get(call_id)
        if task is None or task.done():
            return False
        self._cancelled.add(call_id)
        _ = task.cancel()
        _ = await asyncio.wait({task})
        return True

    def cancel_all(self) -> None:
        """Cancel every running call as part of cancelling the whole turn."""
        for task in list(self._tasks.values()):
            _ = task.cancel()
