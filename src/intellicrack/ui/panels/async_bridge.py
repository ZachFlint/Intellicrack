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

from PyQt6 import sip
from PyQt6.QtCore import QThread, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.core.types import IntellicrackError


__all__ = [
    "WORKER_DEFAULT_EXCEPTIONS",
    "BridgeCallWorker",
    "GenericCallableWorker",
    "bridge_workers_for",
    "cancel_pending_main_loop_tasks",
    "discard_worker",
    "drain_bridge_workers",
    "drain_bridge_workers_for",
    "guarded_delivery",
    "run_bridge_coroutine",
    "run_bridge_coroutine_async",
    "run_bridge_coroutine_logged",
    "run_callable_async",
    "shutdown_bridge_loop",
    "worker_is_running",
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

    A worker may additionally record the widget that dispatched it as its *owner*. The owner is deliberately not the worker's Qt parent:
    Qt destroys a parent's children along with it, and destroying a ``QThread`` whose OS thread is still running aborts the process with a
    native access violation and no Python traceback. Recording the owner separately keeps :func:`drain_bridge_workers_for` able to find a
    widget's in-flight workers without handing that widget the power to delete them mid-flight.
    """

    def __init__(self, parent: QObject | None = None, *, owner: QObject | None = None) -> None:
        """Initialise the worker with an optional Qt parent and owning widget.

        Args:
            parent: Qt parent for ownership and cleanup. Leave it ``None`` for any worker that may still be running when the widget that
                started it is destroyed.
            owner: Widget that dispatched this worker, recorded for scoped draining and delivery guards only. It is never used as a Qt
                parent, so it cannot destroy the worker.
        """
        super().__init__(parent)
        self._owner: QObject | None = owner

    def owner(self) -> QObject | None:
        """Return the widget recorded as this worker's owner.

        Returns:
            QObject | None: The owning object passed at construction, or ``None`` for a worker dispatched without one.
        """
        return self._owner

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
        *,
        owner: QObject | None = None,
    ) -> None:
        """Initialize the AsyncBridgeWorker with the given coroutine.

        Args:
            coro: Coroutine to execute on the persistent event loop.
            parent: Parent QObject. Dispatch sites leave this ``None`` so that closing the calling widget cannot destroy a thread that is
                still running its coroutine.
            owner: Widget that dispatched the call, recorded for scoped draining without becoming the worker's Qt parent.
        """
        super().__init__(parent, owner=owner)
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
        """Execute the coroutine on the persistent event loop.

        An ``IntellicrackError`` reaching this handler is an anticipated outcome of the call, not a fault in the worker: a bad API key, a
        rate limit, or a bridge that is not connected all arrive as domain errors and are delivered to the caller's ``on_error`` for
        display. Those are logged at warning with the error and its type, matching :func:`run_bridge_coroutine_logged`. A traceback under a
        generic "worker failed" event is reserved for exceptions that really do mean the worker plumbing broke, so routine provider failures
        stop burying the real ones.
        """
        try:
            loop = _ensure_loop()
            future = asyncio.run_coroutine_threadsafe(self._coro, loop)
            completed, result = self._await_future(loop, future)
            if completed:
                self.call_finished.emit(result)
        except _BRIDGE_CALL_EXCEPTIONS as exc:
            if isinstance(exc, IntellicrackError):
                _logger.warning(
                    "async_bridge_call_error",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
            else:
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
        owner: QObject | None = None,
        **kwargs: object,
    ) -> None:
        """Initialise the worker with the callable and its arguments.

        Args:
            func: Synchronous callable to execute on the background thread.
            *args: Positional arguments forwarded to ``func``.
            exceptions: Exception classes captured and re-emitted via
                ``call_error``. Anything outside this tuple propagates and
                terminates the thread.
            parent: Parent QObject for Qt ownership and cleanup. Dispatch sites leave this ``None`` and pass ``owner`` instead, so that
                closing the widget cannot destroy a thread that is still running its callable.
            owner: Widget that dispatched this worker, recorded for scoped draining and delivery guards without becoming its Qt parent.
            **kwargs: Keyword arguments forwarded to ``func``.
        """
        super().__init__(parent, owner=owner)
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


def worker_is_running(worker: QThread | None) -> bool:
    """Safely report whether ``worker`` is a live thread still executing.

    A :class:`GenericCallableWorker` (and :class:`BridgeCallWorker`) wires
    ``finished -> deleteLater``, so once it has finished, its underlying C++
    object may already be destroyed while a Python reference lingers. Probing
    ``isRunning`` on that dangling sip wrapper raises ``RuntimeError``. Re-arm
    guards only need to know whether a *genuinely in-flight* worker exists
    before starting a replacement, so both ``None`` and a deleted wrapper are
    reported as "not running" instead of crashing the caller.

    Args:
        worker: The worker thread to probe, or ``None``.

    Returns:
        bool: ``True`` only when ``worker`` is a live thread that reports itself
            as still running; ``False`` when it is ``None`` or its underlying
            C++ object has already been destroyed.
    """
    if worker is None:
        return False
    try:
        return worker.isRunning()
    except RuntimeError:
        return False


def discard_worker(worker: QThread | None) -> None:
    """Safely schedule a finished ``worker`` for deletion.

    Counterpart to :func:`worker_is_running` for the re-arm sites that eagerly
    ``deleteLater`` the previous (finished) worker before starting a new one.
    A worker whose ``finished -> deleteLater`` has already destroyed its C++
    object raises ``RuntimeError`` when ``deleteLater`` is called again; that is
    the desired end state (the object is already gone), so it is swallowed at
    debug level rather than propagated.

    Args:
        worker: The worker thread to discard, or ``None``.
    """
    if worker is None:
        return
    try:
        worker.deleteLater()
    except RuntimeError:
        _logger.debug("worker_discard_wrapper_already_deleted")


# The two overloads carry no docstring of their own: they are signature
# declarations for the positional and keyword call forms, and the behaviour
# both describe is documented once on the implementation below.
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


def guarded_delivery(
    callback: Callable[[object], None],
    owner: QObject | None,
    kind: Literal["success", "error"],
) -> Callable[[object], None]:
    """Wrap ``callback`` so a late result never reaches a destroyed ``owner``.

    A worker outlives the widget that dispatched it (see :func:`run_bridge_coroutine_async` and :func:`run_callable_async`), so its result
    can arrive after that widget's C++ object is gone: the panel was closed, the tab detached, or the dialog dismissed while the call was
    still in flight. Invoking the caller's callback then raises ``RuntimeError: wrapped C/C++ object ... has been deleted`` out of a Qt
    slot, the same class of late-callback crash the Cutter tabs and the log viewer already guard with ``sip.isdeleted``. The check runs at
    delivery time rather than at dispatch because the owner can die at any point while the work runs. Holding ``owner`` in the closure for
    as long as the connection lives is what keeps ``sip.isdeleted`` answerable, instead of a probe against a garbage-collected wrapper.

    Both dispatch helpers wrap their callbacks with this, so a call site needs it directly only when it builds its own worker - a site
    whose callback must capture the worker instance it belongs to, for instance, since such a callback cannot be handed to a helper that
    creates the worker itself.

    The guard is what covers the callbacks Qt cannot help with. PyQt breaks a connection by itself when the slot is a bound method of a
    ``QObject`` and that object's C++ side is destroyed, so those late results are simply never delivered. A closure, a ``functools.partial``
    or any other plain callable has no receiver ``QObject`` to detect, so Qt delivers into it regardless and the call raises out of the slot.
    Dispatch sites pass both kinds - a panel's own handler here, a closure capturing a PID or a worker instance there - so the helpers wrap
    every callback rather than leaving each site to reason about which kind it has.

    Args:
        callback: Caller-supplied success or error callback.
        owner: Widget whose lifetime bounds delivery, or ``None`` to deliver unconditionally.
        kind: Which delivery this wraps, recorded on the drop log entry.

    Returns:
        Callable[[object], None]: ``callback`` itself when there is no owner to outlive, otherwise a guarded wrapper around it.
    """
    if owner is None:
        return callback

    def _deliver(payload: object) -> None:
        """Invoke the wrapped callback unless the owner has already been deleted.

        Args:
            payload: Result object or exception emitted by the worker.
        """
        if sip.isdeleted(owner):
            _logger.debug("bridge_result_dropped", delivery=kind, owner_type=type(owner).__name__)
            return
        callback(payload)

    return _deliver


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

    ``parent`` is the delivery context, not the worker's Qt parent. Parenting the worker to the caller made Qt delete a running
    ``QThread`` along with that caller - which is what closing a panel or dialog mid-call does - and Qt answers that with a native access
    violation that takes the whole process down with no Python traceback. The worker is therefore dispatched unparented and pinned in
    :class:`_WorkerRegistry` until its OS thread finishes, with ``parent`` recorded as its owner so :func:`drain_bridge_workers_for` still
    finds it and so :func:`guarded_delivery` can drop a result that arrives once ``parent`` is gone.

    Args:
        coro: Coroutine to execute.
        on_success: Callback invoked on the main thread with the result.
        on_error: Callback invoked on the main thread with the exception.
        parent: Widget whose lifetime bounds callback delivery and whose :func:`drain_bridge_workers_for` calls should find this worker.
            ``None`` delivers unconditionally, which is what a non-widget caller (a bridge dispatch, a unit test) wants.
    """
    worker = BridgeCallWorker(coro, owner=parent)
    if on_success is not None:
        _ = worker.call_finished.connect(guarded_delivery(on_success, parent, "success"))
    if on_error is not None:
        _ = worker.call_error.connect(guarded_delivery(on_error, parent, "error"))
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
        parent: Widget whose lifetime bounds delivery, forwarded to :func:`run_bridge_coroutine_async`. It is not the worker's Qt parent;
            once its C++ object is deleted the whole delivery is dropped, success and failure log entries included, and the drop is logged
            instead.
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
        """Emit a success log entry then invoke the caller success callback.

        Args:
            result: Value produced by the completed bridge coroutine.
        """
        emit("bridge_coroutine_succeeded", op_event=event, **context)
        if on_success is not None:
            on_success(result)

    def _logged_error(exc: object) -> None:
        """Emit a failure log entry then invoke the caller error callback.

        Args:
            exc: Exception or error payload from the bridge worker.
        """
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


def run_callable_async(
    func: Callable[..., object],
    /,
    *args: object,
    on_success: Callable[[object], None] | None = None,
    on_error: Callable[[object], None] | None = None,
    parent: QObject | None = None,
    exceptions: tuple[type[BaseException], ...] = WORKER_DEFAULT_EXCEPTIONS,
    **kwargs: object,
) -> GenericCallableWorker:
    """Run a synchronous callable on a background thread without blocking the Qt main thread.

    The synchronous counterpart to :func:`run_bridge_coroutine_async`, and it treats ``parent`` the same way: as the delivery context
    rather than the worker's Qt parent. A worker parented to the calling widget is destroyed together with that widget, and Qt answers the
    destruction of a still-running ``QThread`` with a native access violation that takes the process down with no Python traceback - which
    is what closing a panel or dialog during a long entropy scan, signature scan or pattern search used to do. The worker is therefore
    created unparented and pinned in :class:`_WorkerRegistry` until its OS thread finishes, with ``parent`` recorded as its owner so
    :func:`drain_bridge_workers_for` still finds it, and both callbacks are wrapped by :func:`guarded_delivery` so a result arriving after
    ``parent`` is gone is dropped instead of raising out of a Qt slot.

    The started worker is returned because call sites track it: they gate a re-arm on :func:`worker_is_running`, ask it to stop through
    ``requestInterruption``, or wait on it. Callbacks are connected before the thread starts, so a callable that finishes immediately
    cannot emit into a worker with no connections yet.

    Args:
        func: Synchronous callable to execute on the background thread.
        *args: Positional arguments forwarded to ``func``.
        on_success: Callback invoked on the delivery context's thread with the callable's return value.
        on_error: Callback invoked on the delivery context's thread with the raised exception.
        parent: Widget whose lifetime bounds callback delivery and whose :func:`drain_bridge_workers_for` calls should find this worker.
            ``None`` delivers unconditionally, which is what a non-widget caller (a plain dialog helper, a unit test) wants.
        exceptions: Exception classes captured by the worker and re-emitted through ``on_error``. Anything outside this tuple propagates
            and terminates the thread.
        **kwargs: Keyword arguments forwarded to ``func``. They are re-bound through a ``dict[str, Any]`` before construction because the
            worker's own ``exceptions`` / ``parent`` / ``owner`` keywords share this namespace; a call site that shadows one of those
            names is a ``TypeError`` at construction, exactly as it is on the worker itself.

    Returns:
        GenericCallableWorker: The started worker, for callers that track or join it.
    """
    forwarded: dict[str, Any] = dict(kwargs)
    worker = GenericCallableWorker(func, *args, exceptions=exceptions, owner=parent, **forwarded)
    if on_success is not None:
        _ = worker.call_finished.connect(guarded_delivery(on_success, parent, "success"))
    if on_error is not None:
        _ = worker.call_error.connect(guarded_delivery(on_error, parent, "error"))
    worker.start()
    return worker


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


def _object_chain_contains(node: QObject | None, root: QObject) -> bool:
    """Report whether ``root`` appears anywhere in ``node``'s Qt parent chain.

    Walks ``node.parent()`` upward comparing each node identity against ``root``. ``node`` itself counts as a match, so an owner whose C++
    object has already been destroyed still matches itself without any C++ access at all. If a node further up the chain has been
    destroyed the sip wrapper raises ``RuntimeError``; that is treated as "not a descendant" so a partially torn-down chain is skipped
    rather than propagated.

    Args:
        node: Object to walk upward from, or ``None`` when there is no chain.
        root: The candidate ancestor object.

    Returns:
        bool: True if ``root`` is ``node`` itself or one of its Qt ancestors.
    """
    try:
        current = node
        while current is not None:
            if current is root:
                return True
            current = current.parent()
    except RuntimeError:
        return False
    return False


def _worker_is_owned_by(worker: QThread, root: QObject) -> bool:
    """Report whether ``root`` owns ``worker`` by Qt parentage or recorded ownership.

    Two ownership routes are recognised. A worker built with a Qt parent - the ``GenericCallableWorker`` sites in the hex editor, for
    instance, or a worker parented to a tab nested inside ``root`` - matches through its own parent chain. A worker dispatched by
    :func:`run_bridge_coroutine_async` is deliberately unparented, because Qt would otherwise destroy the running thread along with the
    widget, so it carries that widget as its recorded owner instead and the owner's parent chain is matched the same way. A worker with
    neither belongs to no widget and is left to the global :func:`drain_bridge_workers`.

    Args:
        worker: The retained worker thread whose ownership is inspected.
        root: The candidate owner.

    Returns:
        bool: True when ``root`` owns ``worker`` through either route.
    """
    if _object_chain_contains(worker, root):
        return True
    owner = worker.owner() if isinstance(worker, _RetainedWorker) else None
    return _object_chain_contains(owner, root)


def bridge_workers_for(root: QObject) -> list[QThread]:
    """Return every retained worker thread that ``root`` owns.

    Args:
        root: The widget whose in-flight (or finished but not yet reaped) workers are wanted.

    Returns:
        list[QThread]: The matching workers, in no particular order. The result is a snapshot: a worker in it can finish, and a new one
            can be dispatched, immediately after it is taken.
    """
    with _WorkerRegistry.lock:
        snapshot = list(_WorkerRegistry.workers)
    return [worker for worker in snapshot if _worker_is_owned_by(worker, root)]


def drain_bridge_workers_for(root: QObject, timeout_ms: int = _WORKER_DRAIN_TIMEOUT_MS) -> int:
    """Block until every retained worker owned by ``root`` has finished.

    A scoped counterpart to :func:`drain_bridge_workers`: it waits only for the workers ``root`` owns (see :func:`_worker_is_owned_by`),
    leaving workers owned by unrelated widgets untouched. This is what a panel calls when it is being closed or torn down: its own
    in-flight refresh / architecture / privilege coroutines are joined so their result callbacks cannot fire against a half-destroyed
    panel that is still alive, and so the bridge handles those coroutines hold are released before the panel drops its bridge. Draining
    globally instead would join and flush callbacks for workers belonging to entirely different widgets, which can resurrect their side
    effects at the wrong time.

    For bridge-call workers this is no longer what keeps Qt from destroying a running thread: they are unparented and pinned in the worker
    registry (see :func:`run_bridge_coroutine_async`), and a result that outlives ``root`` entirely is dropped at delivery, so one that
    outlasts the drain budget keeps running safely until :func:`drain_bridge_workers` joins it at shutdown or test teardown. Workers that
    do carry a Qt parent still depend on this drain completing before that parent is destroyed.

    Args:
        root: The widget whose owned workers should be joined.
        timeout_ms: Maximum number of milliseconds to wait for each individual worker thread to finish before moving on to the next one.

    Returns:
        int: The number of matching workers confirmed finished (or already gone).
    """
    drained = 0
    for worker in bridge_workers_for(root):
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
