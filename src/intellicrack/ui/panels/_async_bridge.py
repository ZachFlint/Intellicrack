"""Shared async-to-sync bridge runner for Qt UI panels.

Provides a coroutine runner that safely executes async bridge
methods from synchronous Qt slots, with proper error logging
for both inline and event-loop-deferred execution paths.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from ...core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Coroutine

_logger = get_logger("ui.panels.async_bridge")


def run_bridge_coroutine[T](coro: Coroutine[object, object, T]) -> T | None:
    """Run an async bridge coroutine from a synchronous Qt context.

    Attempts to execute the coroutine on the current event loop.
    When called from within a running loop (typical in Qt apps),
    the coroutine is scheduled as a task with an error-logging
    callback instead of being silently dropped. When no loop is
    running, the coroutine is executed synchronously via
    ``asyncio.run``.

    Args:
        coro: Coroutine to execute.

    Returns:
        Coroutine result when executed synchronously, or None
        when the coroutine was scheduled on a running loop.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        task = loop.create_task(coro)
        task.add_done_callback(_log_task_exception)
        return None

    return asyncio.run(coro)


def _log_task_exception(task: asyncio.Task[object]) -> None:
    """Log exceptions from completed async bridge tasks.

    Args:
        task: The completed asyncio task to inspect.
    """
    if task.cancelled():
        _logger.debug("bridge_task_cancelled")
        return
    exc = task.exception()
    if exc is not None:
        _logger.error("bridge_task_failed: %s: %s", type(exc).__name__, exc)
