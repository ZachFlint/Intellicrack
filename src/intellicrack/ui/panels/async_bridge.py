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
from concurrent.futures import (
    Future,
    TimeoutError as FuturesTimeoutError,
)
from typing import TYPE_CHECKING, Any, ClassVar, Literal, overload, override

from PyQt6.QtCore import QThread, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.core.types import IntellicrackError


__all__ = [
    "WORKER_DEFAULT_EXCEPTIONS",
    "BridgeCallWorker",
    "GenericCallableWorker",
    "cancel_pending_main_loop_tasks",
    "drain_bridge_workers",
    "drain_bridge_workers_for",
    "run_bridge_coroutine",
    "run_bridge_coroutine_async",
    "run_bridge_coroutine_logged",
    "shutdown_bridge_loop",
]


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    import structlog
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

_BRIDGE_CALL_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)
"""Exception classes caught by ``BridgeCallWorker``.

Extends ``WORKER_DEFAULT_EXCEPTIONS`` with the Intellicrack domain hierarchy (``IntellicrackError`` and every subclass, including
``ToolError`` raised by the bridges) and task cancellation. Without ``ToolError`` in this tuple a failing bridge coroutine would propagate
out of ``BridgeCallWorker.run`` and terminate the worker thread without emitting ``call_finished`` or ``call_error``, leaving callers (e.g.
the process panel's "Refreshing..." button) stuck indefinitely with no result and no surfaced error.
"""

class _LoopState:
    """Module-level mutable state for the persistent event loop."""

    loop: asyncio.AbstractEventLoop | None = None
    thread: threading.Thread | None = None
    lock: threading.Lock = threading.Lock()


_state = _LoopState()


class _WorkerRegistry:
    """Strong references to in-flight worker threads.

    A fire-and-forget ``QThread`` whose only Python reference is a local in the launching function is garbage-collected the moment that
    function returns. If the underlying OS thread is still running, Qt aborts the whole process with ``QThread: Destroyed while thread is
    still running``. Retaining each started worker here until it has fully finished lets a caller start a worker without a Qt parent
    (``parent=None``) and without a running Qt event loop, which is exactly the case in unit tests and in any bridge dispatch whose owner is
    not a ``QWidget``.
    """

    workers: ClassVar[set[QThread]] = set()
    lock: ClassVar[threading.Lock] = threading.Lock()


def _retain_worker(worker: QThread) -> None:
    """Pin ``worker`` against premature garbage collection until it finishes.

    Fully finished workers already in the registry are pruned first so the
    set stays bounded. ``isFinished`` is queried defensively: if a worker's
    ``deleteLater`` has already destroyed the underlying C++ object the sip
    wrapper raises ``RuntimeError``, which simply means the worker is done
    and can be dropped.

    Args:
        worker: The worker thread being started.
    """
    with _WorkerRegistry.lock:
        stale: set[QThread] = set()
        for existing in _WorkerRegistry.workers:
            try:
                if existing.isFinished():
                    stale.add(existing)
            except RuntimeError:
                stale.add(existing)
        _WorkerRegistry.workers.difference_update(stale)
        _WorkerRegistry.workers.add(worker)


class _RetainedWorker(QThread):
    """``QThread`` base that pins itself against premature GC on ``start``.

    Subclasses are retained in :class:`_WorkerRegistry` for the lifetime of their OS thread, preventing the ``QThread: Destroyed while
    thread is still running`` abort that occurs when an unparented worker's only Python reference goes out of scope while the thread is
    still executing.
    """

    @override
    def start(self, priority: QThread.Priority = QThread.Priority.InheritPriority) -> None:
        """Retain this worker, then start its OS thread.

        Args:
            priority: Scheduling priority forwarded to ``QThread.start``.
        """
        _retain_worker(self)
        super().start(priority)


_LOOP_READY_TIMEOUT: float = 2.0

_WORKER_POLL_INTERVAL_S: float = 0.1
"""Polling slice, in seconds, used by :meth:`BridgeCallWorker.run` to wait on its coroutine future while staying responsive to loop
teardown.
"""

_WORKER_DRAIN_TIMEOUT_MS: int = 5000
"""Default per-worker wait, in milliseconds, applied by :func:`drain_bridge_workers`."""


class _PendingTaskTracker:
    """Module-level registry of in-flight tasks scheduled on the main loop.

    ``run_bridge_coroutine`` will, when it detects an already-running event loop on the calling thread, schedule the coroutine as a fire-
    and-forget task on that loop. When the main loop is the Qt application's asyncio loop, it can be blocked inside ``app.exec()`` for the
    lifetime of the GUI, leaving every scheduled task pending until application teardown. The tracker keeps a reference to each such task so
    shutdown can cancel them cleanly before the loop is closed, preventing ``Task was destroyed but it is pending!`` warnings from cascading
    through the logging pipeline.
    """

    tasks: ClassVar[set[asyncio.Task[object]]] = set()
    lock: threading.Lock = threading.Lock()


_pending = _PendingTaskTracker()


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


class BridgeCallWorker(_RetainedWorker):
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

    @staticmethod
    def _await_future(loop: asyncio.AbstractEventLoop, future: Future[object]) -> tuple[bool, object]:
        """Wait for ``future`` while staying responsive to loop teardown.

        The future is awaited in bounded polling slices rather than a single
        unbounded ``future.result()`` so that if the shared bridge loop is torn
        down (``shutdown_bridge_loop``) while this worker is still in flight, the
        worker detects the dead loop, cancels its pending future, and returns
        instead of blocking its OS thread forever. A worker left blocked on a
        stopped loop becomes an unjoinable zombie whose ``QThread`` later aborts
        the process when destroyed - the class of non-deterministic hang/crash
        seen when the whole suite shares one loop across thousands of tests.

        Args:
            loop: The persistent bridge event loop the coroutine runs on.
            future: The cross-thread future returned by
                :func:`asyncio.run_coroutine_threadsafe`.

        Returns:
            tuple[bool, object]: ``(True, result)`` when the coroutine completed,
            or ``(False, None)`` when the loop was torn down before completion.
        """
        while True:
            try:
                return True, future.result(timeout=_WORKER_POLL_INTERVAL_S)
            except FuturesTimeoutError:
                if loop.is_closed() or not loop.is_running():
                    _ = future.cancel()
                    _logger.warning("async_bridge_worker_abandoned_dead_loop")
                    return False, None

    @override
    def run(self) -> None:
        """Execute the coroutine on the persistent event loop."""
        try:
            loop = _ensure_loop()
            future = asyncio.run_coroutine_threadsafe(self._coro, loop)
            completed, result = self._await_future(loop, future)
            if completed:
                self.call_finished.emit(result)
        except _BRIDGE_CALL_EXCEPTIONS as exc:
            _logger.exception("async_bridge_worker_failed")
            self.call_error.emit(exc)


class GenericCallableWorker(_RetainedWorker):
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


@overload
def run_bridge_coroutine[T](coro: Coroutine[object, object, T], /, *, timeout_s: float | None = None) -> T | None: ...


@overload
def run_bridge_coroutine[T](*, coro: Coroutine[object, object, T], timeout_s: float | None = None) -> T | None: ...


def run_bridge_coroutine(
    _coro_positional: Coroutine[object, object, object] | None = None,
    /,
    *,
    coro: Coroutine[object, object, object] | None = None,
    timeout_s: float | None = None,
) -> object | None:
    """Run an async bridge coroutine from a synchronous Qt context.

    Uses a persistent background event loop thread to execute
    the coroutine, preserving asyncio primitives across calls.
    When called from within a running loop (e.g. nested Qt event
    processing), the coroutine is scheduled as a task with an
    error-logging callback instead of blocking.

    This is the **blocking** variant.  Use ``run_bridge_coroutine_async``
    for non-blocking execution with signal-based result delivery.

    Args:
        _coro_positional: Coroutine passed positionally.
        coro: Coroutine passed by keyword.
        timeout_s: Optional wall-clock ceiling, in seconds, for the blocking
            wait on the background loop. When the coroutine does not complete
            in time a :class:`TimeoutError` is raised (the coroutine keeps
            running on the loop and is not cancelled) so a slow or hung backend
            cannot freeze the caller indefinitely. ``None`` waits forever
            (legacy behaviour).

    Returns:
        object | None: Coroutine result when executed synchronously, or
            ``None`` when the coroutine was scheduled on a running loop.

    Raises:
        TypeError: If neither a positional nor keyword coroutine is given.
        TimeoutError: If ``timeout_s`` elapses before the coroutine completes.
    """
    resolved_coro = _coro_positional if _coro_positional is not None else coro
    if resolved_coro is None:
        msg = "run_bridge_coroutine() requires a coroutine argument"
        raise TypeError(msg)
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        _logger.debug("no_running_event_loop", exc_info=True)
        running = None

    if running is not None and running.is_running():
        task = running.create_task(resolved_coro)
        with _pending.lock:
            _pending.tasks.add(task)
        task.add_done_callback(_log_task_exception)
        task.add_done_callback(_discard_pending_task)
        return None

    loop = _ensure_loop()
    future = asyncio.run_coroutine_threadsafe(resolved_coro, loop)
    try:
        return future.result(timeout=timeout_s)
    except FuturesTimeoutError as exc:
        _logger.warning("bridge_coroutine_timed_out", timeout_s=timeout_s)
        _ = future.cancel()
        msg = f"bridge coroutine did not complete within {timeout_s}s"
        raise TimeoutError(msg) from exc


def _discard_pending_task(task: asyncio.Task[object]) -> None:
    """Remove ``task`` from the pending-task registry once it completes.

    Args:
        task: The completed asyncio task to forget.
    """
    with _pending.lock:
        _pending.tasks.discard(task)


def cancel_pending_main_loop_tasks() -> int:
    """Cancel every tracked main-loop task scheduled via ``run_bridge_coroutine``.

    Intended to be called from the application shutdown sequence after the Qt
    event loop has exited and before the asyncio loop is closed. The call must
    be made from a coroutine running on the same loop that originally executed
    the tasks; the cancellation is queued via ``Task.cancel()`` and the caller
    is expected to ``await asyncio.sleep(0)`` (or otherwise yield) so the loop
    can deliver ``CancelledError`` to the suspended coroutines and complete
    their teardown before the loop is torn down.

    Returns:
        int: Number of tasks that were still pending and have been requested
            to cancel.
    """
    cancelled = 0
    with _pending.lock:
        snapshot = list(_pending.tasks)
    for task in snapshot:
        if not task.done():
            _ = task.cancel()
            cancelled += 1
    if cancelled:
        _logger.debug("bridge_pending_tasks_cancelled", count=cancelled)
    return cancelled


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


def run_bridge_coroutine_logged(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None,
    on_error: Callable[[object], None] | None,
    parent: QObject | None,
    *,
    event: str,
    logger: structlog.stdlib.BoundLogger,
    level: Literal["debug", "info"] = "debug",
    **context: object,
) -> None:
    """Run a bridge coroutine with structured entry / success / failure logs.

    Emits ``<event>_started`` before dispatch, ``<event>_succeeded`` after
    success (in addition to invoking ``on_success``), and ``<event>_failed``
    on failure (in addition to invoking ``on_error``). State-mutation sites
    should pass ``level="info"`` to surface entry/success at info level;
    refresh and query sites use the default ``level="debug"``. Failures are
    always logged at warning level.

    Args:
        coro: Bridge coroutine to execute.
        on_success: Optional caller success callback invoked after the success log.
        on_error: Optional caller error callback invoked after the failure log.
        parent: Qt parent for worker lifetime management.
        event: Snake-case base event name (e.g. ``"ghidra_rename_function"``).
            ``_started``/``_succeeded``/``_failed`` are appended automatically.
        logger: Caller's module-level ``BoundLogger`` to emit on.
        level: ``"info"`` for state-mutation sites, ``"debug"`` for read-only
            refresh and query operations.
        **context: Structured kwargs included in every emitted log entry.
    """
    emit = logger.info if level == "info" else logger.debug
    emit("bridge_coroutine_started", op_event=event, **context)

    def _logged_success(result: object) -> None:
        emit("bridge_coroutine_succeeded", op_event=event, **context)
        if on_success is not None:
            on_success(result)

    def _logged_error(exc: object) -> None:
        error_obj = exc if isinstance(exc, BaseException) else RuntimeError(repr(exc))
        logger.warning(
            "bridge_coroutine_failed",
            op_event=event,
            error=str(error_obj),
            error_type=type(error_obj).__name__,
            **context,
        )
        if on_error is not None:
            on_error(exc)

    run_bridge_coroutine_async(coro, _logged_success, _logged_error, parent)


def drain_bridge_workers(timeout_ms: int = _WORKER_DRAIN_TIMEOUT_MS) -> int:
    """Block until every retained background worker thread has finished.

    Each :func:`run_bridge_coroutine_async` / :func:`run_bridge_coroutine_logged`
    call starts a :class:`BridgeCallWorker` ``QThread`` that is pinned in
    :class:`_WorkerRegistry` for the lifetime of its OS thread. While the Qt
    event loop is spinning, each worker's ``finished`` signal fires its
    ``deleteLater`` slot and the thread is reaped normally. During application
    shutdown - and between unit tests, where no event loop is running - a worker
    whose OS thread is still executing would be destroyed mid-flight, aborting
    the whole process with ``QThread: Destroyed while thread is still running``.
    Draining first waits for each such worker to finish so teardown is clean.

    Args:
        timeout_ms: Maximum number of milliseconds to wait for each individual
            worker thread to finish before moving on to the next one.

    Returns:
        int: The number of retained workers confirmed finished (or already gone).
    """
    with _WorkerRegistry.lock:
        snapshot = list(_WorkerRegistry.workers)
    drained = 0
    for worker in snapshot:
        try:
            if not worker.isRunning() or worker.wait(timeout_ms):
                drained += 1
        except RuntimeError:
            drained += 1
    return drained


def _worker_has_ancestor(worker: QThread, root: QObject) -> bool:
    """Report whether ``root`` appears anywhere in ``worker``'s Qt parent chain.

    Walks ``worker.parent()`` upward comparing each node identity against
    ``root``. A worker started with ``parent=root`` (or parented to any widget
    nested inside ``root``, such as a tab reparented into a ``QTabWidget``)
    resolves to ``True``. If the underlying C++ object of any node has already
    been destroyed the sip wrapper raises ``RuntimeError``; that is treated as
    "not a descendant" so a partially torn-down worker is simply skipped.

    Args:
        worker: The retained worker thread whose ancestry is inspected.
        root: The candidate ancestor object.

    Returns:
        bool: True if ``root`` is ``worker`` itself or one of its Qt ancestors.
    """
    try:
        node: QObject | None = worker
        while node is not None:
            if node is root:
                return True
            node = node.parent()
    except RuntimeError:
        return False
    return False


def drain_bridge_workers_for(root: QObject, timeout_ms: int = _WORKER_DRAIN_TIMEOUT_MS) -> int:
    """Block until every retained worker parented under ``root`` has finished.

    A scoped counterpart to :func:`drain_bridge_workers`: it waits only for the
    worker threads whose Qt parent chain includes ``root`` (see
    :func:`_worker_has_ancestor`), leaving workers owned by unrelated widgets
    untouched. This is what a panel calls when it is being closed or torn down:
    its own in-flight refresh / architecture / privilege coroutines are joined so
    their result callbacks cannot fire against a half-destroyed panel and, more
    importantly, so the still-running child ``QThread`` objects are not destroyed
    mid-flight when Qt deletes the panel subtree (which would abort the process
    with ``QThread: Destroyed while thread is still running``). Draining globally
    instead would join and flush callbacks for workers belonging to entirely
    different widgets, which can resurrect their side effects at the wrong time.

    Args:
        root: The widget whose owned worker subtree should be joined.
        timeout_ms: Maximum number of milliseconds to wait for each individual
            worker thread to finish before moving on to the next one.

    Returns:
        int: The number of matching workers confirmed finished (or already gone).
    """
    with _WorkerRegistry.lock:
        snapshot = list(_WorkerRegistry.workers)
    drained = 0
    for worker in snapshot:
        if not _worker_has_ancestor(worker, root):
            continue
        try:
            if not worker.isRunning() or worker.wait(timeout_ms):
                drained += 1
        except RuntimeError:
            drained += 1
    return drained


def shutdown_bridge_loop() -> None:
    """Shut down the persistent background event loop.

    Should be called during application exit to cleanly stop the background thread. In-flight workers are drained first so none is left
    blocked on a future that the loop would never complete once stopped; any worker that outlasts the drain budget detects the stopped loop
    and abandons its future rather than zombieing (see :meth:`BridgeCallWorker.run`).
    """
    if _state.loop is None:
        return

    _ = drain_bridge_workers()
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
