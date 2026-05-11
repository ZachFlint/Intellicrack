# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared async-to-sync bridge runner for Qt UI panels.

Provides a coroutine runner that safely executes async bridge methods from synchronous Qt slots, using a persistent background event loop
thread to preserve asyncio primitives across calls. Includes both blocking and non-blocking variants for different use cases.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import TYPE_CHECKING, Any, override

from PyQt6.QtCore import QThread, pyqtSignal

from intellicrack.core.logging import get_logger


__all__ = [
    "WORKER_DEFAULT_EXCEPTIONS",
    "BridgeCallWorker",
    "GenericCallableWorker",
    "run_bridge_coroutine",
    "run_bridge_coroutine_async",
    "shutdown_bridge_loop",
]


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtCore import QObject

_logger = get_logger(__name__)


WORKER_DEFAULT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ArithmeticError,
    AttributeError,
    LookupError,
    OSError,
    PermissionError,
    RuntimeError,
    SyntaxError,
    TimeoutError,
    TypeError,
    ValueError,
    json.JSONDecodeError,
)
"""Default exception classes caught by ``GenericCallableWorker``.

This tuple is the union of error types currently raised by hex-editor mixin callables. Worker callers may pass a narrower or broader tuple
via the ``exceptions`` constructor argument.
"""

class _LoopState:
    """Module-level mutable state for the persistent event loop."""

    loop: asyncio.AbstractEventLoop | None = None
    thread: threading.Thread | None = None
    lock: threading.Lock = threading.Lock()


_state = _LoopState()

_LOOP_READY_TIMEOUT: float = 2.0


def _run_loop(loop: asyncio.AbstractEventLoop, ready: threading.Event) -> None:
    """Run the event loop forever in a background thread.

    Args:
        loop: The event loop to run.
        ready: Event signaled once the loop is bound to the thread and about to start.
    """
    asyncio.set_event_loop(loop)
    ready.set()
    loop.run_forever()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    """Lazily start and return the persistent background event loop.

    Uses a ``threading.Event`` sentinel to guarantee that a newly created loop is
    bound to its thread before ``_ensure_loop`` returns, preventing a race where
    parallel callers could each create and start a loop because the first thread
    had not yet entered ``run_forever``.

    Returns:
        asyncio.AbstractEventLoop: The running background event loop.
    """
    existing = _state.loop
    if existing is not None:
        return existing

    with _state.lock:
        if _state.loop is not None:
            return _state.loop

        loop = asyncio.new_event_loop()
        ready = threading.Event()
        thread = threading.Thread(
            target=_run_loop,
            args=(loop, ready),
            daemon=True,
            name="bridge-event-loop",
        )
        thread.start()

        _state.loop = loop
        _state.thread = thread
        _logger.debug("bridge_event_loop_started", thread_name=thread.name)

        if not ready.wait(timeout=_LOOP_READY_TIMEOUT):
            _logger.warning(
                "bridge_event_loop_initialization_timed_out",
                thread_name=thread.name,
                timeout_s=_LOOP_READY_TIMEOUT,
            )

    return loop


def ensure_loop() -> asyncio.AbstractEventLoop:
    """Lazily start and return the persistent background event loop.

    Returns:
        asyncio.AbstractEventLoop: The running background event loop.
    """
    return _ensure_loop()


class BridgeCallWorker(QThread):
    """Worker thread for non-blocking bridge coroutine execution.

    Submits a coroutine to the persistent bridge event loop and
    emits signals with the result on completion, allowing the Qt
    UI to remain responsive during bridge operations.  Auto-cleans
    up via deleteLater when the underlying QThread finishes.

    Attributes:
        call_finished: Signal emitted with the coroutine result on success.
        call_error: Signal emitted with the exception on failure.
    """

    call_finished: pyqtSignal = pyqtSignal(object)
    call_error: pyqtSignal = pyqtSignal(object)

    def __init__(
        self,
        coro: Coroutine[object, object, object],
        parent: QObject | None = None,
    ) -> None:
        """Initialize the AsyncBridgeWorker with the given coroutine.

        Args:
            coro: Coroutine to execute on the persistent event loop.
            parent: Parent QObject.
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
        except (TimeoutError, RuntimeError, OSError, ValueError, TypeError, asyncio.CancelledError) as exc:
            _logger.exception("async_bridge_worker_failed")
            self.call_error.emit(exc)


class GenericCallableWorker(QThread):
    """Worker thread for non-blocking execution of synchronous callables.

    Runs an arbitrary synchronous ``func(*args, **kwargs)`` on a background
    QThread and emits ``call_finished`` with the return value or
    ``call_error`` with the raised exception. Auto-cleans up via
    ``deleteLater`` when the underlying QThread finishes.

    This is the synchronous counterpart to :class:`BridgeCallWorker` and
    is intended for FFI calls into native modules (PyO3, ctypes) and
    pure-Python compute helpers that should not block the Qt event loop.

    Attributes:
        call_finished: Signal emitted with the callable's return value on success.
        call_error: Signal emitted with the raised exception object on failure.
    """

    call_finished: pyqtSignal = pyqtSignal(object)
    call_error: pyqtSignal = pyqtSignal(object)

    def __init__(
        self,
        func: Callable[..., object],
        /,
        *args: object,
        exceptions: tuple[type[BaseException], ...] = WORKER_DEFAULT_EXCEPTIONS,
        parent: QObject | None = None,
        **kwargs: object,
    ) -> None:
        """Initialise the worker with the callable and its arguments.

        Args:
            func: Synchronous callable to execute on the background thread.
            *args: Positional arguments forwarded to ``func``.
            exceptions: Exception classes captured and re-emitted via
                ``call_error``. Anything outside this tuple propagates and
                terminates the thread.
            parent: Parent QObject for Qt ownership and cleanup.
            **kwargs: Keyword arguments forwarded to ``func``.
        """
        super().__init__(parent)
        self._func: Callable[..., object] = func
        self._args: tuple[object, ...] = args
        self._kwargs: dict[str, Any] = dict(kwargs)
        self._exceptions: tuple[type[BaseException], ...] = exceptions
        _: object = self.finished.connect(self.deleteLater)

    @override
    def run(self) -> None:
        """Execute the callable and emit the result or captured exception."""
        try:
            result = self._func(*self._args, **self._kwargs)
        except self._exceptions as exc:
            _logger.exception(
                "generic_callable_worker_failed",
                func_name=getattr(self._func, "__name__", repr(self._func)),
                error_type=type(exc).__name__,
            )
            self.call_error.emit(exc)
            return
        self.call_finished.emit(result)


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
        coro: Coroutine to execute on the persistent event loop.

    Returns:
        T | None: Coroutine result when executed synchronously, or None
            when the coroutine was scheduled on a running loop.
    """
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        _logger.debug("no_running_event_loop", exc_info=True)
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

    Should be called during application exit to cleanly stop the background thread.
    """
    if _state.loop is None:
        return

    _ = _state.loop.call_soon_threadsafe(_state.loop.stop)

    if _state.thread is not None and _state.thread.is_alive():
        _state.thread.join(timeout=2.0)

    _state.loop = None
    _state.thread = None
    _logger.info("bridge_event_loop_shutdown", had_loop=True)


def _log_task_exception(task: asyncio.Task[object]) -> None:
    """Log exceptions from completed async bridge tasks.

    Args:
        task: The completed asyncio task to inspect.
    """
    if task.cancelled():
        _logger.debug("bridge_task_cancelled", task_name=task.get_name())
        return
    exc = task.exception()
    if exc is not None:
        _logger.error("bridge_task_failed", exception_type=type(exc).__name__, error=str(exc))
