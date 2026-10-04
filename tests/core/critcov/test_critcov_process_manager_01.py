# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the process manager paths the existing suites leave unexecuted.

Every process that is registered, signalled or terminated here is a child this
module started itself: ``sys.executable`` running a script that prints a ready
marker and then blocks reading stdin, so it ends on its own when the test closes
the pipe and is otherwise ended by the code under test. Nothing here registers,
signals or terminates the pytest process, one of its ancestors, or any process
this module did not start.

Paths that cannot be driven honestly are left out: the POSIX branches, the
branches that need the pytest process or an ancestor in the registry, and the
ones that need the operating system to refuse access to a process.
"""

from __future__ import annotations

import asyncio
import ctypes
import inspect
import signal
import sys
import threading
import time
from typing import TYPE_CHECKING, Final, cast

import psutil
import pytest
from structlog.testing import capture_logs

import intellicrack.core.process_manager as _pm_module
from intellicrack.core.process_manager import ProcessManager, ProcessType, TrackedProcess
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen, TimeoutExpired


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Mapping, Sequence
    from types import FrameType


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 15.0
_POLL_S: Final[float] = 0.005
_READY_MARKER: Final[bytes] = b"ready"
_BLOCKING_CHILD_SCRIPT: Final[str] = "import sys\nprint('ready', flush=True)\nsys.stdin.read()\n"
_UNREACHABLE_PID: Final[int] = 0x7FFFFFFE
_SIGNAL_CLEANUP_THREAD: Final[str] = "ProcessManagerSignalCleanup"
_CALLBACK_FAILURE: Final[str] = "cleanup callback failed"

_pid_handle_alive: Final = cast(
    "Callable[[ctypes.CDLL, int], bool]",
    getattr(_pm_module, "_pid_handle_alive"),
)


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager singleton and discard it afterwards.

    Yields:
        ProcessManager: A freshly created singleton with an empty registry.
    """
    ProcessManager.reset_instance()
    manager = ProcessManager.get_instance()
    yield manager
    manager.uninstall_handlers()
    ProcessManager.reset_instance()


def _reap(child: Popen[bytes]) -> None:
    """Kill the child if it is still running, wait for it and close its pipes.

    Args:
        child: A process this module started.
    """
    if child.poll() is None:
        child.kill()
    _ = child.wait(timeout=_WAIT_S)
    for stream in (child.stdin, child.stdout):
        if stream is not None:
            stream.close()


def _spawn_blocking_child() -> Popen[bytes]:
    """Start a child that prints a ready marker and then blocks on stdin.

    Returns:
        Popen[bytes]: The running child, already past its ready marker.
    """
    child = Popen([sys.executable, "-c", _BLOCKING_CHILD_SCRIPT], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    marker = child.stdout.readline().strip() if child.stdout is not None else b""
    if marker != _READY_MARKER:
        _reap(child)
        pytest.fail(f"child printed {marker!r} instead of {_READY_MARKER!r}")
    return child


def _release(child: Popen[bytes]) -> None:
    """Close the child's stdin so that it exits by itself with status 0.

    Args:
        child: A child started by :func:`_spawn_blocking_child`.
    """
    assert child.stdin is not None
    child.stdin.close()


def _wait_exit(child: Popen[bytes]) -> int:
    """Wait for the child to end and return its exit status.

    Args:
        child: A process this module started.

    Returns:
        int: The exit status.
    """
    try:
        return child.wait(timeout=_WAIT_S)
    except TimeoutExpired:
        pytest.fail(f"child {child.pid} was still running after {_WAIT_S:g}s")


async def _spawn_async_blocking_child() -> asyncio.subprocess.Process:
    """Start an asyncio child that prints a ready marker and then blocks on stdin.

    Returns:
        asyncio.subprocess.Process: The running child, already past its ready marker.
    """
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        _BLOCKING_CHILD_SCRIPT,
        stdin=PIPE,
        stdout=PIPE,
        stderr=DEVNULL,
    )
    assert child.stdout is not None
    marker = (await asyncio.wait_for(child.stdout.readline(), timeout=_WAIT_S)).strip()
    if marker != _READY_MARKER:
        child.kill()
        _ = await child.wait()
        pytest.fail(f"child printed {marker!r} instead of {_READY_MARKER!r}")
    return child


async def _reap_async(child: asyncio.subprocess.Process) -> None:
    """Kill the asyncio child if it is still running and wait for it.

    Args:
        child: A process this module started.
    """
    if child.returncode is None:
        child.kill()
    _ = await asyncio.wait_for(child.wait(), timeout=_WAIT_S)
    if child.stdin is not None:
        child.stdin.close()


async def _wait_for_event(captured: Sequence[Mapping[str, object]], name: str) -> None:
    """Poll the captured log records until one with the given event name appears.

    Args:
        captured: The list a ``capture_logs`` context fills in.
        name: The event name to wait for.

    Raises:
        AssertionError: If no such record appears within the wait limit.
    """
    deadline = time.monotonic() + _WAIT_S
    while not _events(captured, name):
        if time.monotonic() > deadline:
            message = f"log event {name!r} never appeared"
            raise AssertionError(message)
        await asyncio.sleep(_POLL_S)


async def _cancel(task: asyncio.Task[None]) -> None:
    """Cancel a helper task and wait until it has finished.

    Args:
        task: The helper task to stop.
    """
    _ = task.cancel()
    _ = await asyncio.gather(task, return_exceptions=True)


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Select the captured log records with the given event name.

    Args:
        captured: The list a ``capture_logs`` context fills in.
        name: The event name to select.

    Returns:
        list[Mapping[str, object]]: The matching records in emission order.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _external_registry(manager: ProcessManager) -> dict[int, object]:
    """Return the manager's external PID registry.

    Args:
        manager: The manager to inspect.

    Returns:
        dict[int, object]: The live registry mapping.
    """
    return cast("dict[int, object]", getattr(manager, "_external_pids"))


def _sync_cleanup(manager: ProcessManager) -> None:
    """Run the manager's synchronous cleanup.

    Args:
        manager: The manager to clean up.
    """
    cast("Callable[[], None]", getattr(manager, "_sync_cleanup"))()


def _cleanup_in_progress(manager: ProcessManager) -> bool:
    """Read the manager's cleanup-in-progress flag.

    Args:
        manager: The manager to inspect.

    Returns:
        bool: The flag's current value.
    """
    return cast("bool", getattr(manager, "_cleanup_in_progress"))


def _set_cleanup_in_progress(manager: ProcessManager, *, value: bool) -> None:
    """Put the manager's cleanup-in-progress flag in the given state.

    Args:
        manager: The manager to change.
        value: The state to put the flag in.
    """
    setattr(manager, "_cleanup_in_progress", value)


def _run_on_a_worker_thread(action: Callable[[], None]) -> BaseException | None:
    """Run the action on a thread that is not the main thread and join it.

    Args:
        action: The callable to run.

    Returns:
        BaseException | None: The error the action raised, or None.
    """
    failures: list[BaseException] = []

    def runner() -> None:
        """Run the action and remember an error it raises."""
        try:
            action()
        except (ValueError, OSError, RuntimeError) as error:
            failures.append(error)

    worker = threading.Thread(target=runner, name="process-manager-worker", daemon=True)
    worker.start()
    worker.join(timeout=_WAIT_S)
    assert not worker.is_alive()
    return failures[0] if failures else None


def _join_signal_cleanup_threads() -> None:
    """Join the background cleanup threads the signal handler starts."""
    for thread in threading.enumerate():
        if thread.name == _SIGNAL_CLEANUP_THREAD:
            thread.join(timeout=_WAIT_S)


def test_a_failed_exit_code_query_counts_the_process_as_alive() -> None:
    """A handle the kernel cannot query for an exit code is reported as alive.

    A NULL handle is never valid, so ``GetExitCodeProcess`` fails on it, and the
    function documents that a failed query must not be read as a dead process.

    Falsifiable: changing ``== 0`` to ``!= 0`` on process_manager.py line 118
    makes the failed query fall through to the exit-code comparison, which
    reports False for the untouched exit code.
    """
    kernel32 = ctypes.WinDLL("kernel32")

    assert _pid_handle_alive(kernel32, 0) is True


def test_check_running_reports_a_popen_until_it_exits() -> None:
    """``check_running`` tracks a ``Popen`` from running to exited.

    Falsifiable: changing ``is None`` to ``is not None`` on process_manager.py
    line 294 inverts both assertions.
    """
    child = _spawn_blocking_child()
    try:
        tracked = TrackedProcess(process=child, process_type=ProcessType.SUBPROCESS, name="popen-child")

        assert tracked.check_running() is True

        _release(child)
        _ = _wait_exit(child)

        assert tracked.check_running() is False
    finally:
        _reap(child)


@pytest.mark.asyncio
async def test_check_running_reports_an_asyncio_process_until_it_exits() -> None:
    """``check_running`` tracks an asyncio subprocess from running to exited.

    Falsifiable: changing ``is None`` to ``is not None`` on process_manager.py
    line 295 inverts both assertions.
    """
    child = await _spawn_async_blocking_child()
    try:
        tracked = TrackedProcess(process=child, process_type=ProcessType.ASYNC_SUBPROCESS, name="asyncio-child")

        assert tracked.check_running() is True

        assert child.stdin is not None
        child.stdin.close()
        _ = await asyncio.wait_for(child.wait(), timeout=_WAIT_S)

        assert tracked.check_running() is False
    finally:
        await _reap_async(child)


def test_a_constructor_that_lost_the_race_returns_the_winning_instance(process_manager: ProcessManager) -> None:
    """A thread that passed the first singleton check gets the instance installed meanwhile.

    The worker is held on the class lock after it saw no instance; the test then
    installs the existing manager as the instance and releases the lock.

    Falsifiable: deleting the second ``if cls._instance is None`` check on
    process_manager.py line 347 makes the worker build and return a new object.

    Args:
        process_manager: The singleton the worker must be handed back.
    """
    lock = cast("threading.Lock", getattr(ProcessManager, "_lock"))
    lines, first_line = inspect.getsourcelines(ProcessManager.__new__)
    lock_line = first_line + next(offset for offset, text in enumerate(lines) if "with cls._lock" in text)
    current_frames = cast("Callable[[], dict[int, FrameType]]", getattr(sys, "_current_frames"))
    results: list[ProcessManager] = []

    def construct() -> None:
        """Construct the singleton the way application code does."""
        results.append(ProcessManager())

    worker = threading.Thread(target=construct, name="process-manager-racer", daemon=True)
    setattr(ProcessManager, "_instance", None)
    lock.acquire()
    try:
        worker.start()
        deadline = time.monotonic() + _WAIT_S
        while True:
            frame = current_frames().get(worker.ident or -1)
            if frame is not None and frame.f_code.co_name == "__new__" and frame.f_lineno == lock_line:
                break
            if time.monotonic() > deadline:
                pytest.fail("the worker never blocked on the singleton lock")
            time.sleep(_POLL_S)
        setattr(ProcessManager, "_instance", process_manager)
    finally:
        lock.release()
        worker.join(timeout=_WAIT_S)
        setattr(ProcessManager, "_instance", process_manager)

    assert not worker.is_alive()
    assert len(results) == 1
    assert results[0] is process_manager


def test_install_handlers_off_the_main_thread_logs_the_refusal_and_keeps_the_atexit_hook(process_manager: ProcessManager) -> None:
    """The operating system refuses signal handlers off the main thread; the manager logs that and carries on.

    Falsifiable: removing the ``try``/``except`` around the handler installation
    on process_manager.py lines 424-434 lets the ``ValueError`` escape the call.

    Args:
        process_manager: The singleton to install handlers on.
    """
    interrupt_handler_before = signal.getsignal(signal.SIGINT)

    with capture_logs() as captured:
        failure = _run_on_a_worker_thread(process_manager.install_handlers)

    refusals = _events(captured, "signal_handler_install_failed")
    assert failure is None
    assert [entry.get("error_type") for entry in refusals] == ["ValueError"]
    assert process_manager.atexit_registered is True
    assert _events(captured, "handlers_installed")
    assert signal.getsignal(signal.SIGINT) is interrupt_handler_before


def test_uninstall_handlers_off_the_main_thread_logs_the_refusal_and_still_clears_the_flag(process_manager: ProcessManager) -> None:
    """Restoring the interrupt handler off the main thread is refused; the manager logs it and still finishes.

    Falsifiable: removing the ``try``/``except`` around the restore on
    process_manager.py lines 446-449 lets the ``ValueError`` escape the call.

    Args:
        process_manager: The singleton to install and uninstall handlers on.
    """

    def install_then_uninstall() -> None:
        """Install the handlers and then uninstall them, both off the main thread."""
        process_manager.install_handlers()
        process_manager.uninstall_handlers()

    with capture_logs() as captured:
        failure = _run_on_a_worker_thread(install_then_uninstall)

    refusals = _events(captured, "signal_handler_uninstall_failed")
    assert failure is None
    assert len(refusals) == 1
    assert process_manager.atexit_registered is False
    assert _events(captured, "handlers_uninstalled")


def test_the_signal_handler_hands_an_interrupt_to_the_original_handler_and_nothing_else(process_manager: ProcessManager) -> None:
    """The interrupt that started the cleanup is also delivered to the handler it replaced.

    A terminate signal must not be forwarded: only the interrupt goes to the
    original handler.

    Falsifiable: deleting process_manager.py line 511 means the original
    handler never receives the interrupt.

    Args:
        process_manager: The singleton whose handler is invoked.
    """
    received: list[tuple[int, FrameType | None]] = []

    def original_handler(signum: int, frame: FrameType | None) -> None:
        """Record the signal the way an application's own handler would.

        Args:
            signum: The signal number delivered.
            frame: The interrupted frame, or None.
        """
        received.append((signum, frame))

    handler = cast("Callable[[int, FrameType | None], None]", getattr(process_manager, "_signal_handler"))
    setattr(process_manager, "_original_sigint_handler", original_handler)
    try:
        handler(int(signal.SIGTERM), None)
        _join_signal_cleanup_threads()
        forwarded_for_terminate = list(received)

        handler(int(signal.SIGINT), None)
        _join_signal_cleanup_threads()
    finally:
        setattr(process_manager, "_original_sigint_handler", None)

    assert forwarded_for_terminate == []
    assert received == [(int(signal.SIGINT), None)]
    assert process_manager.is_shutdown_requested() is True


def test_the_atexit_hook_without_a_singleton_does_nothing() -> None:
    """The global exit hook leaves a process that has no manager alone and creates none.

    Falsifiable: replacing the ``return`` on process_manager.py line 465 with
    ``pass`` makes the hook call a method on ``None``.
    """
    ProcessManager.reset_instance()
    hook = cast("Callable[[], None]", getattr(ProcessManager, "_atexit_cleanup_global"))

    hook()

    assert getattr(ProcessManager, "_instance") is None


def test_the_atexit_hook_sweeps_the_registered_child_and_discards_the_singleton(process_manager: ProcessManager) -> None:
    """The global exit hook runs the manager's exit cleanup, ending a registered child.

    Falsifiable: deleting process_manager.py line 466 leaves the child running,
    so the wait for its exit times out.

    Args:
        process_manager: The singleton the hook delegates to.
    """
    child = _spawn_blocking_child()
    try:
        process_manager.register_external_pid(child.pid, name="exit-sweep")
        hook = cast("Callable[[], None]", getattr(ProcessManager, "_atexit_cleanup_global"))

        hook()

        assert _wait_exit(child) != 0
        assert _external_registry(process_manager) == {}
        assert getattr(ProcessManager, "_instance") is None
    finally:
        _reap(child)


def test_the_exit_cleanup_does_nothing_while_another_cleanup_runs(process_manager: ProcessManager) -> None:
    """An exit cleanup that arrives during a running cleanup leaves the child and the singleton alone.

    Falsifiable: deleting the ``return`` on process_manager.py line 521 makes the
    call sweep the child and reset the singleton.

    Args:
        process_manager: The singleton to run the exit cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        process_manager.register_external_pid(child.pid, name="guarded-exit")
        _set_cleanup_in_progress(process_manager, value=True)

        process_manager.run_atexit_cleanup()

        assert child.poll() is None
        assert child.pid in _external_registry(process_manager)
        assert getattr(ProcessManager, "_instance") is process_manager
    finally:
        _set_cleanup_in_progress(process_manager, value=False)
        _reap(child)


def test_the_sync_cleanup_does_nothing_while_another_cleanup_runs(process_manager: ProcessManager) -> None:
    """A synchronous cleanup that arrives during a running cleanup leaves the child alone.

    Falsifiable: deleting the ``return`` on process_manager.py line 530 makes the
    call terminate the child and empty the registry.

    Args:
        process_manager: The singleton to run the synchronous cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        process_manager.register_external_pid(child.pid, name="guarded-sync")
        _set_cleanup_in_progress(process_manager, value=True)

        _sync_cleanup(process_manager)

        assert child.poll() is None
        assert child.pid in _external_registry(process_manager)
    finally:
        _set_cleanup_in_progress(process_manager, value=False)
        _reap(child)


@pytest.mark.asyncio
async def test_the_async_cleanup_does_nothing_while_another_cleanup_runs(process_manager: ProcessManager) -> None:
    """An async cleanup that arrives during a running cleanup leaves a tracked child alone.

    Falsifiable: deleting the ``return`` on process_manager.py line 970 makes the
    call terminate the tracked child.

    Args:
        process_manager: The singleton to run the async cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        _ = process_manager.register(child, name="guarded-async")
        _set_cleanup_in_progress(process_manager, value=True)

        await process_manager.cleanup_all_async()

        assert child.poll() is None
        assert process_manager.get_tracked(child.pid) is not None
    finally:
        _set_cleanup_in_progress(process_manager, value=False)
        _reap(child)


def test_the_sync_cleanup_logs_an_external_process_that_ended_before_the_sweep(process_manager: ProcessManager) -> None:
    """A registered external process that no longer exists is logged and does not stop the sweep.

    Falsifiable: removing the ``except psutil.NoSuchProcess`` clause on
    process_manager.py line 553 lets the lookup error escape the cleanup.

    Args:
        process_manager: The singleton to run the synchronous cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        pid = child.pid
        process_manager.register_external_pid(pid, name="ends-before-sweep")
        child.kill()
        _ = _wait_exit(child)

        with capture_logs() as captured:
            _sync_cleanup(process_manager)

        assert [entry.get("pid") for entry in _events(captured, "process_lookup_failed")] == [pid]
        assert _external_registry(process_manager) == {}
        assert _cleanup_in_progress(process_manager) is False
    finally:
        _reap(child)


def test_the_sync_cleanup_signals_a_process_registered_twice_once(process_manager: ProcessManager) -> None:
    """A process tracked both as a subprocess and as an external PID is terminated once.

    Falsifiable: deleting the ``if p.pid not in seen_pids`` guard on
    process_manager.py line 559 appends the process twice, so it is signalled twice.

    Args:
        process_manager: The singleton to run the synchronous cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        pid = child.pid
        process_manager.register_external_pid(pid, name="as-external")
        _ = process_manager.register(child, name="as-tracked")

        with capture_logs() as captured:
            _sync_cleanup(process_manager)

        signalled = [
            entry
            for entry in captured
            if entry.get("event") in {"signal_sent", "process_terminate_target_missing"} and entry.get("pid") == pid
        ]
        assert len(signalled) == 1
        assert _wait_exit(child) != 0
    finally:
        _reap(child)


def test_the_sync_cleanup_leaves_no_survivor_when_the_grace_period_is_zero(process_manager: ProcessManager) -> None:
    """With no grace period every process counts as a survivor of the first signal, and none outlives the sweep.

    ``psutil.wait_procs`` with a zero timeout waits for nothing, so the sweep
    escalates to the forced kill for processes that may already be ending. The
    instance's grace period is set to zero for this.

    Falsifiable: deleting ``psutil.wait_procs(alive, ...)`` on process_manager.py
    line 579 lets the call return while the child is still ending.

    Args:
        process_manager: The singleton to run the synchronous cleanup on.
    """
    child = _spawn_blocking_child()
    try:
        process_manager.register_external_pid(child.pid, name="zero-grace-sweep")
        process_manager.DEFAULT_GRACEFUL_TIMEOUT = 0.0

        _sync_cleanup(process_manager)

        assert child.poll() is not None
        assert _external_registry(process_manager) == {}
        assert _cleanup_in_progress(process_manager) is False
    finally:
        _reap(child)


def test_terminate_tree_with_no_grace_period_ends_the_process_before_returning() -> None:
    """A tree termination with a zero grace period still returns only once the child is gone.

    Falsifiable: deleting ``psutil.wait_procs(alive, ...)`` on process_manager.py
    line 699 lets the call return while the child is still ending.
    """
    child = _spawn_blocking_child()
    try:
        ProcessManager.terminate_tree(child.pid, graceful_timeout=0.0, force_timeout=_WAIT_S)

        assert child.poll() is not None
    finally:
        _reap(child)


def test_force_kill_ends_the_process_and_logs_the_signal() -> None:
    """The forced kill ends a live process and logs which process it signalled.

    Falsifiable: replacing ``p.kill()`` on process_manager.py line 602 with
    ``pass`` leaves the child running, so the wait for its exit times out.
    """
    child = _spawn_blocking_child()
    try:
        force_kill = cast("Callable[[psutil.Process], None]", getattr(ProcessManager, "_force_kill_process"))
        target = psutil.Process(child.pid)

        with capture_logs() as captured:
            force_kill(target)

        assert _wait_exit(child) != 0
        assert [entry.get("pid") for entry in _events(captured, "win32_terminate_signal_sent")] == [child.pid]
    finally:
        _reap(child)


def test_terminate_process_sync_ends_the_process_tree_of_a_popen() -> None:
    """The synchronous terminate helper ends the child behind a ``Popen`` handle.

    Falsifiable: deleting the ``_terminate_tree_with_psutil`` call on
    process_manager.py line 617 leaves the child running, so the wait for its
    exit times out.
    """
    child = _spawn_blocking_child()
    try:
        terminate = cast("Callable[[Popen[bytes]], None]", getattr(ProcessManager, "_terminate_process_sync"))

        terminate(child)

        assert _wait_exit(child) != 0
    finally:
        _reap(child)


@pytest.mark.asyncio
async def test_terminate_process_stops_after_a_cleanup_callback_that_ended_the_process(process_manager: ProcessManager) -> None:
    """A cleanup callback that ends the process makes the tree termination unnecessary.

    The child exits with status 0 on its own, which a termination would not
    produce, and the tree-termination log record never appears.

    Falsifiable: inverting ``if not tracked.check_running()`` on
    process_manager.py line 870 sends the already-ended process through the
    tree termination, which logs ``process_terminated_tree``.

    Args:
        process_manager: The singleton the child is tracked by.
    """
    child = _spawn_blocking_child()
    try:

        async def stop_child() -> None:
            """Close the child's stdin, as a bridge's shutdown request does, and wait for it to exit."""
            _release(child)
            _ = await asyncio.to_thread(child.wait, _WAIT_S)

        pid = process_manager.register(child, name="stops-itself", cleanup_callback=stop_child)

        with capture_logs() as captured:
            terminated = await process_manager.terminate_process(pid)

        assert terminated is True
        assert child.returncode == 0
        assert process_manager.get_tracked(pid) is None
        assert _events(captured, "process_terminated_tree") == []
        assert _events(captured, "cleanup_callback_failed") == []
    finally:
        _reap(child)


@pytest.mark.asyncio
async def test_terminate_process_ends_a_process_the_cleanup_callback_left_running(process_manager: ProcessManager) -> None:
    """A cleanup callback that leaves the process running is followed by the tree termination.

    Falsifiable: inverting ``if not tracked.check_running()`` on
    process_manager.py line 870 returns right after the callback, leaving the
    child running, so the wait for its exit times out.

    Args:
        process_manager: The singleton the child is tracked by.
    """
    child = _spawn_blocking_child()
    try:

        async def leave_running() -> None:
            """Return without stopping the child."""

        pid = process_manager.register(child, name="left-running", cleanup_callback=leave_running)

        terminated = await process_manager.terminate_process(pid)

        assert terminated is True
        assert _wait_exit(child) != 0
        assert process_manager.get_tracked(pid) is None
    finally:
        _reap(child)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [OSError(_CALLBACK_FAILURE), RuntimeError(_CALLBACK_FAILURE)])
async def test_terminate_process_logs_a_failing_cleanup_callback_and_still_ends_the_process(
    process_manager: ProcessManager,
    failure: Exception,
) -> None:
    """An ``OSError`` or ``RuntimeError`` from the cleanup callback is logged and the termination proceeds.

    Falsifiable: removing the ``except (OSError, RuntimeError)`` clause on
    process_manager.py line 873 lets the callback's error escape the call.

    Args:
        process_manager: The singleton the child is tracked by.
        failure: The error the callback raises.
    """
    child = _spawn_blocking_child()
    try:

        async def broken_cleanup() -> None:
            """Fail the way a bridge's shutdown does when its connection is gone.

            Raises:
                failure: Always, the error the test supplied.
            """
            await asyncio.sleep(0)
            raise failure

        pid = process_manager.register(child, name="callback-fails", cleanup_callback=broken_cleanup)

        with capture_logs() as captured:
            terminated = await process_manager.terminate_process(pid)

        failures = _events(captured, "cleanup_callback_failed")
        assert terminated is True
        assert [entry.get("error") for entry in failures] == [_CALLBACK_FAILURE]
        assert [entry.get("process_name") for entry in failures] == ["callback-fails"]
        assert _wait_exit(child) != 0
        assert process_manager.get_tracked(pid) is None
    finally:
        _reap(child)


@pytest.mark.asyncio
async def test_the_async_cleanup_logs_a_process_that_cannot_be_terminated_and_continues(process_manager: ProcessManager) -> None:
    """A tracked process whose cleanup callback raises a psutil error is logged and the next one is still ended.

    Falsifiable: removing the ``except`` clause on process_manager.py line 986
    lets the callback's error escape ``cleanup_all_async``.

    Args:
        process_manager: The singleton the children are tracked by.
    """
    vanishing = _spawn_blocking_child()
    plain = _spawn_blocking_child()
    try:

        async def vanished() -> None:
            """Fail the way a callback does when psutil finds its process gone.

            Raises:
                psutil.NoSuchProcess: Always.
            """
            await asyncio.sleep(0)
            raise psutil.NoSuchProcess(vanishing.pid)

        _ = process_manager.register(vanishing, name="vanishing", cleanup_callback=vanished)
        _ = process_manager.register(plain, name="plain")

        with capture_logs() as captured:
            await process_manager.cleanup_all_async()

        failures = _events(captured, "cleanup_pid_failed")
        assert [entry.get("pid") for entry in failures] == [vanishing.pid]
        assert [entry.get("error") for entry in failures] == [str(psutil.NoSuchProcess(vanishing.pid))]
        assert _wait_exit(plain) != 0
        assert vanishing.poll() is None
        assert _cleanup_in_progress(process_manager) is False
    finally:
        _reap(vanishing)
        _reap(plain)


@pytest.mark.asyncio
async def test_terminate_subprocess_waits_for_a_process_the_tree_walk_did_not_reach() -> None:
    """A process still running after the tree walk is waited for rather than abandoned.

    The tree walk is pointed at a PID that no process has, as happens when the
    system refuses to signal the real process: the child's ``pid`` attribute is
    set to an unused value for the call. The child is released only after the
    fallback has been logged, and it must have exited by the time the call
    returns.

    Falsifiable: deleting ``await asyncio.to_thread(process.wait)`` on
    process_manager.py line 918 returns while the child is still running.
    """
    terminate_subprocess = cast(
        "Callable[[Popen[bytes], str, float, float], Awaitable[None]]",
        getattr(ProcessManager, "_terminate_subprocess"),
    )
    child = _spawn_blocking_child()
    real_pid = child.pid
    try:
        child.pid = _UNREACHABLE_PID
        with capture_logs() as captured:

            async def release_when_logged() -> None:
                """Release the child once the zombie fallback has been logged."""
                await _wait_for_event(captured, "process_zombie_fallback")
                _release(child)

            releaser = asyncio.create_task(release_when_logged())
            try:
                await terminate_subprocess(child, "zombie-child", 1.0, 1.0)
                exit_status = child.poll()
            finally:
                await _cancel(releaser)

        assert exit_status == 0
        assert [entry.get("process_name") for entry in _events(captured, "process_zombie_fallback")] == ["zombie-child"]
        assert _events(captured, "process_terminated_tree")
    finally:
        child.pid = real_pid
        _reap(child)


@pytest.mark.asyncio
async def test_terminate_async_subprocess_waits_for_a_process_the_tree_walk_did_not_reach() -> None:
    """An asyncio process still running after the tree walk is waited for rather than abandoned.

    The tree walk is pointed at a PID that no process has: the child's ``pid``
    attribute is set to an unused value for the call. The child is released only
    after the fallback has been logged, and it must have exited by the time the
    call returns.

    Falsifiable: deleting ``await process.wait()`` on process_manager.py line
    952 returns while the child is still running.
    """
    terminate_async_subprocess = cast(
        "Callable[[asyncio.subprocess.Process, str, float, float], Awaitable[None]]",
        getattr(ProcessManager, "_terminate_async_subprocess"),
    )
    child = await _spawn_async_blocking_child()
    real_pid = child.pid
    try:
        child.pid = _UNREACHABLE_PID
        with capture_logs() as captured:

            async def release_when_logged() -> None:
                """Release the child once the zombie fallback has been logged."""
                await _wait_for_event(captured, "async_process_zombie_fallback")
                assert child.stdin is not None
                child.stdin.close()

            releaser = asyncio.create_task(release_when_logged())
            try:
                await terminate_async_subprocess(child, "zombie-async-child", 1.0, 1.0)
                return_code = child.returncode
            finally:
                await _cancel(releaser)

        assert return_code == 0
        assert [entry.get("process_name") for entry in _events(captured, "async_process_zombie_fallback")] == ["zombie-async-child"]
        assert _events(captured, "async_process_terminated_tree")
    finally:
        child.pid = real_pid
        await _reap_async(child)
