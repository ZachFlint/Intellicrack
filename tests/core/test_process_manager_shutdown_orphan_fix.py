# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the orphaned-child-process shutdown bug.

Covers the shutdown path that left tracked subprocesses (e.g. the Ghidra headless
``python.exe`` bridge process) running after ``MainWindow.closeEvent`` closed the
application. Two constraints must hold:

1. ``ProcessManager.cleanup_all_async`` must not treat its own ``shutdown_event``
   flag as an abort signal: a set flag must not ``break`` the per-pid termination
   loop on its first iteration, or every tracked ``Popen``-based subprocess is skipped.
   2. ``request_shutdown()`` must terminate tracked processes, not only set the flag.

``closeEvent`` calls ``request_shutdown()``, and the flag is not cleared before
the application's final ``cleanup_all_async()`` sweep (see ``_finalize_shutdown``
in ``main.py``). A tracked subprocess whose owning bridge did not tear itself down
(a timed-out or silently failed bridge ``shutdown()``/``stop()``, or an abandoned
prior bridge instance) would otherwise keep running: a process leak.

Each test below spawns a long-lived Python subprocess and asserts via
``psutil.pid_exists`` that it is dead afterward.
Removing either behavior makes the corresponding test fail.
"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

import psutil
import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import PIPE, Popen


if TYPE_CHECKING:
    from collections.abc import Generator

_POLL_INTERVAL = 0.1
_POLL_TIMEOUT = 15.0


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ``ProcessManager`` singleton isolated per test.

    Yields:
        ProcessManager: A freshly reset ``ProcessManager`` instance.
    """
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


def _spawn_sleeper() -> Popen[bytes]:
    """Spawn a long-lived Python subprocess to use as an orphan-leak oracle.

    Returns:
        Popen[bytes]: The spawned subprocess handle.
    """
    return Popen(
        [sys.executable, "-c", "import time; time.sleep(300)"],
        stdout=PIPE,
        stderr=PIPE,
    )


def _spawn_sleeper_with_child() -> tuple[Popen[bytes], int]:
    """Spawn a subprocess that itself spawns a grandchild subprocess.

    Mirrors the shape of the Ghidra headless bridge process, whose
    descendants must also be reaped when the root is terminated.

    Returns:
        tuple[Popen[bytes], int]: The parent process handle and the PID of
            the child process it printed to stdout.
    """
    child_code = "import time; time.sleep(300)"
    parent_code = (
        "import subprocess, sys, time\n"
        f"p = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "print(p.pid)\n"
        "sys.stdout.flush()\n"
        "time.sleep(300)\n"
    )
    process = Popen(
        [sys.executable, "-c", parent_code],
        stdout=PIPE,
        stderr=PIPE,
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    child_pid = int(line.strip())
    return process, child_pid


def _wait_until_dead(pid: int, timeout: float = _POLL_TIMEOUT) -> bool:
    """Poll ``psutil.pid_exists`` until the PID disappears or timeout elapses.

    Args:
        pid: Process ID to poll.
        timeout: Maximum number of seconds to wait.

    Returns:
        bool: True if the process was confirmed dead before the timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        time.sleep(_POLL_INTERVAL)
    return not psutil.pid_exists(pid)


class TestCleanupAllAsyncIgnoresShutdownFlag:
    """cleanup_all_async must terminate tracked processes regardless of shutdown_event."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_cleanup_all_async_terminates_process_when_shutdown_flag_already_set(
        process_manager: ProcessManager,
    ) -> None:
        """A tracked process is still reaped when shutdown_event is pre-set.

        This is the exact sequence the real application hits: ``closeEvent``
        calls ``request_shutdown()`` (which sets ``shutdown_event``) before the
        application's final ``cleanup_all_async()`` sweep runs, and the flag is
        never cleared in between. ``cleanup_all_async`` must not treat an already-set ``shutdown_event`` as a
        reason to ``break`` out of its per-pid termination loop on the very first
        iteration; doing so silently skips every tracked subprocess, and the spawned
        process would still be alive after the call.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the test harness.
        """
        proc = _spawn_sleeper()
        pid = proc.pid
        process_manager.register(proc, name="orphan-fix-test", process_type=ProcessType.EXTERNAL_TOOL)

        assert psutil.pid_exists(pid), "Sanity check: process must be running before cleanup"

        # Reproduce the closeEvent ordering: the shutdown flag is already set by the
        # time the final async sweep runs.
        process_manager.shutdown_event.set()

        await process_manager.cleanup_all_async()

        assert _wait_until_dead(pid), (
            "cleanup_all_async must terminate tracked processes even when shutdown_event is already set; "
            "the process is still alive, meaning the early-break-on-shutdown-flag regression is back."
        )


class TestRequestShutdownActuallyCleansUp:
    """request_shutdown() must terminate tracked processes, not just flip a flag."""

    @staticmethod
    def test_request_shutdown_kills_tracked_process(
        process_manager: ProcessManager,
    ) -> None:
        """request_shutdown() terminates a real tracked subprocess synchronously.

        ``request_shutdown()`` must terminate tracked processes synchronously. Merely
        setting ``shutdown_event`` leaves the spawned process alive after this call,
        failing the assertion below.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the test harness.
        """
        proc = _spawn_sleeper()
        pid = proc.pid
        process_manager.register(proc, name="request-shutdown-test", process_type=ProcessType.EXTERNAL_TOOL)

        assert psutil.pid_exists(pid), "Sanity check: process must be running before request_shutdown"

        process_manager.request_shutdown()

        assert not psutil.pid_exists(pid), (
            "request_shutdown() must synchronously terminate every tracked process; the process "
            "is still alive, meaning request_shutdown() is back to being a no-op flag flip."
        )
        assert process_manager.is_shutdown_requested(), "request_shutdown() must still set the shutdown flag for observers"

    @staticmethod
    def test_request_shutdown_kills_process_tree(
        process_manager: ProcessManager,
    ) -> None:
        """request_shutdown() reaps descendant processes, mirroring the Ghidra headless shape.

        The orphan-leak case involves a bridge (Ghidra headless) whose root process
        is tracked by ProcessManager. This test spawns a
        parent/child process pair and verifies request_shutdown()'s
        synchronous sweep kills both, not just the tracked root PID.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the test harness.
        """
        process, child_pid = _spawn_sleeper_with_child()
        parent_pid = process.pid
        process_manager.register(process, name="request-shutdown-tree-test", process_type=ProcessType.EXTERNAL_TOOL)

        assert psutil.pid_exists(parent_pid), "Sanity check: parent must be running"
        assert psutil.pid_exists(child_pid), "Sanity check: child must be running"

        process_manager.request_shutdown()

        assert not psutil.pid_exists(parent_pid), "request_shutdown() must kill the tracked parent process"
        assert not psutil.pid_exists(child_pid), "request_shutdown() must also reap descendant processes, not just the tracked root PID"
