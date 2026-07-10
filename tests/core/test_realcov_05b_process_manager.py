# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-process coverage for :mod:`intellicrack.core.process_manager`.

Audit shard 05 listed several ProcessManager public surfaces as untested. The
existing ``tests/test_core/test_process_manager.py`` and
``tests/core/test_process_manager_leaks.py`` already exercise ``register``,
``unregister``, ``run_tracked``/``run_tracked_async``, ``cleanup_all_async``,
``terminate_process`` (process-tree teardown), external-PID handling, and signal
handler installation against real OS subprocesses.

This module adds the remaining real-process coverage the audit called out and
that the existing suites do not reach:

* the public static :meth:`ProcessManager.terminate_tree` killing a real
  parent/child process tree;
* :meth:`ProcessManager.run_tracked` driving a *real system PE*
  (``C:/Windows/System32/cmd.exe`` on Windows) rather than only the Python
  interpreter, capturing its genuine stdout;
* :meth:`ProcessManager.terminate_process` returning ``False`` for an unknown
  PID and reaping an already-exited tracked process;
* :meth:`ProcessManager.get_tracked` round-tripping a registered real process.

Every test that starts an OS process carries the ``spawns_process`` marker so
the harness gates it to the Docker sandbox. No process operation under test is
mocked; assertions check real PIDs, real exit behaviour, and real captured
output.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import psutil
import pytest

from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.subprocess_compat import PIPE, Popen


if TYPE_CHECKING:
    from collections.abc import Generator


_STARTUP_DELAY: Final[float] = 0.2
_TREE_SETTLE_DELAY: Final[float] = 0.5
_WAIT_TIMEOUT: Final[int] = 10
_UNKNOWN_PID: Final[int] = 0x7FFFFFFE
_CMD_EXE: Final[Path] = Path("C:/Windows/System32/cmd.exe")


def _spawn_parent_with_child() -> tuple[Popen[bytes], int]:
    """Spawn a real parent process that spawns a long-sleeping child.

    Returns:
        tuple[Popen[bytes], int]: The parent ``Popen`` and the child PID it
        printed on stdout.
    """
    child_code = "import time; time.sleep(60)"
    parent_code = (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    parent = Popen([sys.executable, "-c", parent_code], stdout=PIPE, stderr=PIPE)
    assert parent.stdout is not None
    child_pid = int(parent.stdout.readline().strip())
    return parent, child_pid


def _reap(parent: Popen[bytes]) -> None:
    """Kill and reap a parent process if it is still alive.

    Args:
        parent: The parent process to terminate and wait on.
    """
    if parent.poll() is None:
        parent.kill()
    parent.wait(timeout=_WAIT_TIMEOUT)


def _assert_tree_terminated(parent: Popen[bytes], child_pid: int) -> None:
    """Terminate the parent tree and assert both PIDs are gone.

    Args:
        parent: Live parent process whose tree to terminate.
        child_pid: PID of the child the parent spawned.
    """
    assert psutil.pid_exists(parent.pid)
    assert psutil.pid_exists(child_pid)

    ProcessManager.terminate_tree(parent.pid)
    time.sleep(_TREE_SETTLE_DELAY)

    assert not psutil.pid_exists(parent.pid), "parent leaked after terminate_tree"
    assert not psutil.pid_exists(child_pid), "child leaked after terminate_tree"


def _assert_round_trip(process_manager: ProcessManager, proc: Popen[bytes]) -> None:
    """Register ``proc`` and assert it round-trips through the tracker APIs.

    Args:
        process_manager: ProcessManager under test.
        proc: A live real subprocess to register and inspect.
    """
    pid = process_manager.register(
        proc,
        name="realcov-roundtrip",
        process_type=ProcessType.EXTERNAL_TOOL,
        metadata={"origin": "test_realcov_05b"},
    )

    tracked = process_manager.get_tracked(pid)
    assert tracked is not None
    assert tracked.pid == proc.pid
    assert tracked.name == "realcov-roundtrip"
    assert tracked.process_type is ProcessType.EXTERNAL_TOOL
    assert tracked.metadata["origin"] == "test_realcov_05b"
    assert tracked.is_running is True
    assert tracked in process_manager.get_all_tracked()


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager instance for each test.

    Yields:
        Generator[ProcessManager]: A fresh singleton ProcessManager.
    """
    ProcessManager.reset_instance()
    pm = ProcessManager.get_instance()
    yield pm
    pm.uninstall_handlers()
    ProcessManager.reset_instance()


class TestTerminateTreePublic:
    """The public ``terminate_tree`` static method kills a real process tree."""

    @staticmethod
    @pytest.mark.spawns_process
    def test_terminate_tree_kills_parent_and_child() -> None:
        """A real parent and the child it spawns are both terminated.

        Spawns a Python parent that itself spawns a long-sleeping child, then
        calls the public ``ProcessManager.terminate_tree`` on the parent PID and
        verifies the OS no longer reports either PID.
        """
        parent, child_pid = _spawn_parent_with_child()
        try:
            _assert_tree_terminated(parent, child_pid)
        finally:
            _reap(parent)


class TestRunTrackedRealSystemBinary:
    """``run_tracked`` executes a real Windows system PE and captures output."""

    @staticmethod
    @pytest.mark.spawns_process
    def test_run_tracked_cmd_exe_captures_real_output(
        process_manager: ProcessManager,
    ) -> None:
        """Running the real ``cmd.exe`` PE captures its genuine stdout.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the harness.
        """
        if sys.platform != "win32" or not _CMD_EXE.exists():
            pytest.skip("real cmd.exe is only available on Windows hosts/containers")

        marker = "INTELLICRACK_REALCOV_05B"
        result = process_manager.run_tracked(
            [str(_CMD_EXE), "/c", "echo", marker],
            name="realcov-cmd",
        )

        assert result.returncode == 0
        assert marker in result.stdout
        assert process_manager.process_count == 0


class TestTerminateProcessEdgeCases:
    """``terminate_process`` handles unknown and already-stopped processes."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_terminate_unknown_pid_returns_false(
        process_manager: ProcessManager,
    ) -> None:
        """Terminating an untracked PID returns ``False`` without raising.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the harness.
        """
        terminated = await process_manager.terminate_process(_UNKNOWN_PID)
        assert terminated is False

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_terminate_already_exited_process_unregisters(
        process_manager: ProcessManager,
    ) -> None:
        """A tracked process that already exited is reaped and unregistered.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the harness.
        """
        proc = Popen([sys.executable, "-c", "pass"], stdout=PIPE, stderr=PIPE)
        proc.wait(timeout=_WAIT_TIMEOUT)
        pid = process_manager.register(proc, name="realcov-already-exited")

        assert process_manager.get_tracked(pid) is not None

        terminated = await process_manager.terminate_process(pid)

        assert terminated is True
        assert process_manager.get_tracked(pid) is None
        assert process_manager.process_count == 0

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.spawns_process
    async def test_terminate_running_process_kills_it(
        process_manager: ProcessManager,
    ) -> None:
        """A tracked, running real process is terminated by ``terminate_process``.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the harness.
        """
        proc = Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=PIPE,
            stderr=PIPE,
        )
        pid = process_manager.register(proc, name="realcov-running", process_type=ProcessType.SUBPROCESS)
        await asyncio.sleep(_STARTUP_DELAY)

        assert psutil.pid_exists(pid)

        terminated = await process_manager.terminate_process(pid)
        proc.wait(timeout=_WAIT_TIMEOUT)

        assert terminated is True
        assert not psutil.pid_exists(pid)
        assert process_manager.get_tracked(pid) is None


class TestGetTrackedRoundTrip:
    """``get_tracked`` and ``get_all_tracked`` reflect a real registration."""

    @staticmethod
    @pytest.mark.spawns_process
    def test_get_tracked_returns_registered_real_process(
        process_manager: ProcessManager,
    ) -> None:
        """A registered real process round-trips through ``get_tracked``.

        Args:
            process_manager: Fresh ProcessManager fixture supplied by the harness.
        """
        proc = Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=PIPE,
            stderr=PIPE,
        )
        try:
            _assert_round_trip(process_manager, proc)
        finally:
            proc.terminate()
            proc.wait(timeout=_WAIT_TIMEOUT)
            process_manager.unregister(proc.pid)
