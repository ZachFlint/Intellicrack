# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared async-to-sync bridge runner for Qt UI panels.

Provides a coroutine runner that safely executes async bridge
methods from synchronous Qt slots, using a persistent background
event loop thread to preserve asyncio primitives across calls.
Includes both blocking and non-blocking variants for different
use cases.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import QThread, pyqtSignal

from ...core.logging import get_logger


__all__ = [
    "BridgeCallWorker",
    "run_bridge_coroutine",
    "run_bridge_coroutine_async",
    "shutdown_bridge_loop",
]


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtCore import QObject

_logger = get_logger("ui.panels.async_bridge")


class _LoopState:
    """Module-level mutable state for the persistent event loop."""

    loop: asyncio.AbstractEventLoop | None = None
    thread: threading.Thread | None = None
    lock: threading.Lock = threading.Lock()


_state = _LoopState()


def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Run the event loop forever in a background thread.

    Args:
        loop: The event loop to run.
    """
    asyncio.set_event_loop(loop)
    loop.run_forever()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    """Lazily start and return the persistent background event loop.

    Returns:
        The running background event loop.
    """
    if _state.loop is not None and _state.loop.is_running():
        return _state.loop

    with _state.lock:
        if _state.loop is not None and _state.loop.is_running():
            return _state.loop

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=_run_loop, args=(loop,), daemon=True, name="bridge-event-loop")
        thread.start()

        _state.loop = loop
        _state.thread = thread
        _logger.debug("bridge_event_loop_started", extra={"thread_name": thread.name})

    return _state.loop


class BridgeCallWorker(QThread):
    """Worker thread for non-blocking bridge coroutine execution.

    Submits a coroutine to the persistent bridge event loop and
    emits signals with the result on completion, allowing the Qt
    UI to remain responsive during bridge operations.  Auto-cleans
    up via deleteLater when the underlying QThread finishes.
    """

    call_finished: pyqtSignal = pyqtSignal(object)
    call_error: pyqtSignal = pyqtSignal(object)

    def __init__(
        self,
        coro: Coroutine[object, object, object],
        parent: QObject | None = None,
    ) -> None:
        """Initialize the bridge call worker.

        Args:
            coro: Coroutine to execute on the bridge event loop.
            parent: Parent QObject for lifecycle management.
        """
        super().__init__(parent)
        self._coro: Coroutine[object, object, object] = coro
        _: object = self.finished.connect(self.deleteLater)

    @override
    def run(self) -> None:
        """Execute the coroutine on the persistent event loop."""
        try:
            loop = _ensure_loop()
            future = asyncio.run_coroutine_threadsafe(self._coro, loop)
            result = future.result()
            self.call_finished.emit(result)
        except Exception as exc:
            _logger.exception("async_bridge_worker_failed")
            self.call_error.emit(exc)


def run_bridge_coroutine[T](coro: Coroutine[object, object, T]) -> T | None:
    """Run an async bridge coroutine from a synchronous Qt context.

    Uses a persistent background event loop thread to execute
    the coroutine, preserving asyncio primitives across calls.
    When called from within a running loop (e.g. nested Qt event
    processing), the coroutine is scheduled as a task with an
    error-logging callback instead of blocking.

    This is the **blocking** variant.  Use ``run_bridge_coroutine_async``
    for non-blocking execution with signal-based result delivery.

    Args:
        coro: Coroutine to execute.

    Returns:
        Coroutine result when executed synchronously, or None
        when the coroutine was scheduled on a running loop.
    """
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None

    if running is not None and running.is_running():
        task = running.create_task(coro)
        task.add_done_callback(_log_task_exception)
        return None

    loop = _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


def run_bridge_coroutine_async(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None = None,
    on_error: Callable[[object], None] | None = None,
    parent: QObject | None = None,
) -> None:
    """Run an async bridge coroutine without blocking the Qt main thread.

    Creates a ``BridgeCallWorker`` that executes the coroutine on the
    persistent background event loop.  Results and errors are delivered
    via Qt signals back to the main thread.

    Args:
        coro: Coroutine to execute.
        on_success: Callback invoked on the main thread with the result.
        on_error: Callback invoked on the main thread with the exception.
        parent: Parent QObject for worker lifecycle management.
    """
    worker = BridgeCallWorker(coro, parent)
    if on_success is not None:
        _ = worker.call_finished.connect(on_success)
    if on_error is not None:
        _ = worker.call_error.connect(on_error)
    worker.start()


def shutdown_bridge_loop() -> None:
    """Shut down the persistent background event loop.

    Should be called during application exit to cleanly stop
    the background thread.
    """
    if _state.loop is None:
        return

    _ = _state.loop.call_soon_threadsafe(_state.loop.stop)

    if _state.thread is not None and _state.thread.is_alive():
        _state.thread.join(timeout=2.0)

    _state.loop = None
    _state.thread = None
    _logger.debug("bridge_event_loop_shutdown", extra={"had_loop": _state.loop is not None})


def _log_task_exception(task: asyncio.Task[object]) -> None:
    """Log exceptions from completed async bridge tasks.

    Args:
        task: The completed asyncio task to inspect.
    """
    if task.cancelled():
        _logger.debug("bridge_task_cancelled", extra={"task_name": task.get_name()})
        return
    exc = task.exception()
    if exc is not None:
        _logger.error("bridge_task_failed", extra={"exception_type": type(exc).__name__, "error": str(exc)})
