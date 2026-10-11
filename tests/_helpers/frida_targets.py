# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Readiness and bounded-call helpers for tests that drive Frida against a spawned target.

Frida injects its agent with a remote thread, and a target that is still inside
its loader when that happens can leave the injection blocked for good. A fixed
``time.sleep`` after ``Popen`` only guesses that the target has finished starting,
so these helpers wait for the target to say so instead: a GUI process through
``WaitForInputIdle`` and a script child through a line it prints once it is up.
Both have a hard deadline and fail with a message naming what never happened.

Nothing in Frida's Python API bounds a native call. :func:`run_bounded` gives a
coroutine a deadline. A call that misses it means the agent behind that bridge's
session has stopped answering, so every later bounded call on the same bridge
fails at once instead of each waiting out its own deadline. Calls on any other
bridge, and calls that belong to no bridge, are unaffected: nothing measured
shows one wedged session slowing another.
"""

from __future__ import annotations

import asyncio
import ctypes
import inspect
import logging
import os
import shutil
import threading
import time
from concurrent.futures import (
    Future,
    wait as wait_futures,
)
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

import pytest

from intellicrack.core.types import ToolError
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.core.subprocess_compat import Popen


_logger = logging.getLogger(__name__)


class SupportsShutdown(Protocol):
    """An object with an async ``shutdown``, such as a ``FridaBridge``."""

    async def shutdown(self) -> None:
        """Release the object's Frida resources."""


READY_TIMEOUT_SECONDS: Final[float] = 30.0
"""Longest a freshly spawned target may take to report that it is ready."""

CALL_TIMEOUT_SECONDS: Final[float] = 20.0
"""Longest a single Frida bridge call may take.

Healthy calls against a spawned notepad took 1 to 250 ms in the container. A call on
a session whose agent has stopped answering ends by itself only after Frida's own
25 s transport timeout, so this is set just under that to fail first and refuse the
calls that would each wait out another 25 s.
"""

COUNTER_ADDRESS_PLACEHOLDER: Final[str] = "__COUNTER_ADDRESS__"
"""Text in :data:`WORKER_THREAD_SCRIPT` to replace with the address (``hex``) of an 8 byte block the worker counts into."""

WORKER_THREAD_SCRIPT: Final[str] = """
var k32 = Process.findModuleByName('kernel32.dll');
var Sleep = k32.getExportByName('Sleep');
var counter = ptr('__COUNTER_ADDRESS__');
counter.writeU32(0);
var code = Memory.alloc(4096);
Memory.protect(code, 4096, 'rwx');
var bytes = [
    0x48, 0x83, 0xEC, 0x28
];
bytes.push(0x49, 0xBC);
var a = Sleep;
for (var i = 0; i < 8; i++) {
    bytes.push(a.and(0xFF).toInt32());
    a = a.shr(8);
}
bytes.push(0x48, 0xB8);
var c = counter;
for (var j = 0; j < 8; j++) {
    bytes.push(c.and(0xFF).toInt32());
    c = c.shr(8);
}
bytes = bytes.concat([
    0xFF, 0x00,
    0xB9, 0x0A, 0x00, 0x00, 0x00,
    0x41, 0xFF, 0xD4,
    0xEB, 0xEA
]);
code.writeByteArray(bytes);
var CreateThread = new NativeFunction(
    k32.getExportByName('CreateThread'),
    'pointer', ['pointer', 'size_t', 'pointer', 'pointer', 'uint32', 'pointer']
);
var tidBuf = Memory.alloc(4);
CreateThread(ptr(0), 0, code, ptr(0), 0, tidBuf);
send({ type: 'worker', tid: tidBuf.readU32() });
"""
"""A script that starts a thread in the target which calls ``Sleep(10)`` in a loop forever and adds one to a counter each pass."""

SHUTDOWN_TIMEOUT_SECONDS: Final[float] = 10.0
"""Longest a bridge may take to shut down once its target process has been killed."""

_TARGET_EXIT_SECONDS: Final[float] = 5.0
_PROCESS_SUSPEND_RESUME: Final[int] = 0x0800
_PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
_SYNCHRONIZE: Final[int] = 0x00100000
_INHERIT_HANDLE: Final[bool] = False
_WAIT_FAILED: Final[int] = 0xFFFFFFFF
_IDLE_SLICE_MS: Final[int] = 250
_MS_PER_SECOND: Final[int] = 1000

_hung_calls: dict[int, tuple[object, str]] = {}
"""Bridges whose agent stopped answering, keyed by ``id``, with the first call that missed its deadline.

The bridge is kept alongside its name so its ``id`` cannot be reused while recorded.
"""

_SELF_NAME: Final[str] = "self"


def notepad_executable() -> str:
    """Locate the ``notepad.exe`` that the Frida tests spawn as a target.

    Returns:
        str: Path to ``notepad.exe``.
    """
    return shutil.which("notepad.exe") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe")


def suspend_process(pid: int) -> int:
    """Freeze every thread of a process, so nothing in it (including an injected agent) answers any more.

    Args:
        pid: Process to freeze.

    Returns:
        int: A handle to pass to :func:`resume_process`.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME, _INHERIT_HANDLE, pid)
    ntdll.NtSuspendProcess(handle)
    return int(handle)


def resume_process(handle: int) -> None:
    """Thaw a process frozen by :func:`suspend_process` and release the handle.

    Args:
        handle: The handle :func:`suspend_process` returned.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess(handle)
    kernel32.CloseHandle(handle)


def clear_hung_calls() -> None:
    """Forget every recorded missed deadline so later bounded calls run again."""
    _hung_calls.clear()


def _owner_of(coro: Coroutine[object, object, object]) -> object | None:
    """Return the object whose method ``coro`` is running, if any.

    A call such as ``bridge.attach(pid)`` is a coroutine whose frame already holds
    ``self``, so the bridge it belongs to can be read without every caller naming it.

    Args:
        coro: A coroutine that has not started running yet.

    Returns:
        object | None: The bound ``self``, or ``None`` for a coroutine that is not a method.
    """
    try:
        return inspect.getcoroutinelocals(coro).get(_SELF_NAME)
    except (AttributeError, TypeError):
        return None


def run_bounded[T](
    coro: Coroutine[object, object, T],
    *,
    timeout: float = CALL_TIMEOUT_SECONDS,
    what: str | None = None,
    loop: asyncio.AbstractEventLoop | None = None,
    respect_hung: bool = True,
) -> T:
    """Run ``coro`` to completion, failing the test if it takes longer than ``timeout``.

    The coroutine runs on its own daemon thread, and the calling thread only waits
    on a plain event for ``timeout`` seconds. The limit therefore holds whatever
    the coroutine does: one that swallows cancellation, blocks inside a native
    call, or stops its own event loop from firing timers cannot keep the caller
    waiting, which cancelling it from inside the loop could not guarantee.

    A call that misses the limit is abandoned on its thread and left to finish
    or hang by itself. The bridge the coroutine belongs to is recorded as stuck,
    and every later call on that same bridge fails immediately naming the first
    one instead of waiting out its own deadline. Other bridges, and coroutines
    that are not bridge methods, still run. A loop passed in as ``loop`` is run
    from that thread and must not be reused once a call on it has been abandoned.

    Args:
        coro: The coroutine to run.
        timeout: Seconds the coroutine may take.
        what: Name used in failure messages; defaults to the coroutine's qualified name.
        loop: Event loop to run on and leave open; a private loop is created and closed when omitted.
        respect_hung: When ``False``, run even on a bridge already recorded as stuck, for the
            teardown that must still try to release it.

    Returns:
        T: The coroutine's result; an exception the coroutine raised is raised here instead.
    """
    label = what if what is not None else getattr(coro, "__qualname__", repr(coro))
    owner = _owner_of(coro)
    recorded = _hung_calls.get(id(owner)) if owner is not None else None
    if recorded is not None and respect_hung:
        coro.close()
        pytest.fail(
            f"{label} was not attempted: Frida call {recorded[1]} never returned earlier on this bridge, "
            "so its agent has stopped answering and nothing further can be driven through it",
            pytrace=False,
        )
    outcome: Future[T] = Future()

    def drive() -> None:
        """Run the coroutine to completion on this thread's own loop and record how it ended."""
        worker_loop = asyncio.new_event_loop() if loop is None else loop
        try:
            task = worker_loop.create_task(coro)
            worker_loop.run_until_complete(asyncio.wait({task}))
            if task.cancelled():
                _ = outcome.cancel()
            elif (error := task.exception()) is not None:
                outcome.set_exception(error)
            else:
                outcome.set_result(task.result())
        finally:
            if not outcome.done():
                outcome.set_exception(RuntimeError(f"the loop running {label} stopped before the call finished"))
            if loop is None:
                worker_loop.close()

    threading.Thread(target=drive, name=f"run-bounded-{label}", daemon=True).start()
    _ = wait_futures([outcome], timeout=timeout)
    if not outcome.done():
        if owner is not None:
            _hung_calls.setdefault(id(owner), (owner, label))
        pytest.fail(
            f"Frida call {label} did not return within {timeout:g}s; the agent behind it has stopped answering, "
            "so the remaining calls on this bridge are skipped",
            pytrace=False,
        )
    return outcome.result()


def end_target_then_shutdown(process: Popen[bytes], bridge: SupportsShutdown | None) -> None:
    """Kill a spawned target and its descendants, then shut its bridge down under a deadline.

    The target goes first so a wedged agent has nothing left to hold the shutdown
    on. The shutdown runs even if the bridge was recorded as stuck, and a
    ``ToolError`` from it is expected once the process is gone and is only logged.

    Args:
        process: The spawned target.
        bridge: The bridge attached to it, or ``None`` when setup never got that far.
    """
    kill_pid_tree(process.pid)
    process.wait(timeout=_TARGET_EXIT_SECONDS)
    if bridge is None:
        return
    try:
        run_bounded(
            bridge.shutdown(),
            timeout=SHUTDOWN_TIMEOUT_SECONDS,
            what="bridge shutdown after its target was killed",
            respect_hung=False,
        )
    except ToolError:
        _logger.debug("bridge_shutdown_after_target_kill_failed", exc_info=True)


def wait_for_gui_process_ready(process: Popen[bytes], *, timeout: float = READY_TIMEOUT_SECONDS) -> float:
    """Block until a freshly spawned GUI process has finished starting and is waiting for input.

    Uses ``WaitForInputIdle``, which returns once the process's first thread has
    finished initializing and drained its message queue. Window visibility is not
    consulted, because it is not reported in a headless container.

    Args:
        process: The spawned GUI process.
        timeout: Seconds to wait before failing.

    Returns:
        float: Seconds the process took to become ready.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    user32.WaitForInputIdle.restype = wintypes.DWORD
    user32.WaitForInputIdle.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    early_exit_code = process.poll()
    if early_exit_code is not None:
        pytest.fail(f"spawned process {process.pid} exited with code {early_exit_code} before it became ready", pytrace=False)
    handle = kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION | _SYNCHRONIZE, _INHERIT_HANDLE, process.pid)
    if not handle:
        error = ctypes.get_last_error()
        pytest.fail(f"cannot open spawned process {process.pid} to wait for it: error {error}: {ctypes.FormatError(error)}", pytrace=False)
    started = time.monotonic()
    deadline = started + timeout
    try:
        while True:
            exit_code = process.poll()
            if exit_code is not None:
                pytest.fail(f"spawned process {process.pid} exited with code {exit_code} before it became ready", pytrace=False)
            remaining_ms = int((deadline - time.monotonic()) * _MS_PER_SECOND)
            if remaining_ms <= 0:
                pytest.fail(f"spawned process {process.pid} was not ready (WaitForInputIdle) within {timeout:g}s", pytrace=False)
            result = user32.WaitForInputIdle(handle, min(_IDLE_SLICE_MS, remaining_ms))
            if result == 0:
                return time.monotonic() - started
            if result == _WAIT_FAILED:
                error = ctypes.get_last_error()
                pytest.fail(
                    f"WaitForInputIdle failed for spawned process {process.pid}: error {error}: {ctypes.FormatError(error)}",
                    pytrace=False,
                )
    finally:
        kernel32.CloseHandle(handle)


def wait_for_stdout_line(process: Popen[bytes], expected: bytes, *, timeout: float = READY_TIMEOUT_SECONDS) -> float:
    """Block until a spawned child prints its readiness line on stdout.

    The child must have been started with ``stdout=PIPE``. A child that dies
    before printing closes the pipe, which ends the wait at once; a child that
    hangs before printing is terminated when the deadline passes. On failure the
    child is terminated but its stdout pipe is left for the caller to close.

    Args:
        process: The spawned child.
        expected: The exact line (without newline) the child prints when ready.
        timeout: Seconds to wait before failing.

    Returns:
        float: Seconds the child took to become ready.
    """
    stream = process.stdout
    if stream is None:
        process.terminate()
        pytest.fail("the spawned child has no stdout pipe to read its readiness line from", pytrace=False)
    lines: list[bytes] = []

    def read_line() -> None:
        """Read the child's first line of output."""
        lines.append(stream.readline())

    started = time.monotonic()
    reader = threading.Thread(target=read_line, name="wait-for-stdout-line", daemon=True)
    reader.start()
    reader.join(timeout)
    if reader.is_alive():
        process.terminate()
        pytest.fail(f"spawned child {process.pid} printed no readiness line within {timeout:g}s", pytrace=False)
    line = lines[0].strip() if lines else b""
    if line != expected:
        process.terminate()
        pytest.fail(f"spawned child {process.pid} printed {line!r} instead of its readiness line {expected!r}", pytrace=False)
    return time.monotonic() - started
