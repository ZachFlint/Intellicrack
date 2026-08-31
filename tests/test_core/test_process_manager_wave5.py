# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for ProcessManager error paths (Group 06 Wave 5).

Covers:
  S7-09 — ``ProcessManager.run_tracked`` raises ``ProcessStateError`` with
           correct attributes when ``returncode`` is ``None`` after communicate.
  S7-10 — ``_pid_exists_windows`` kernel32 → psutil fallback path; also
           tests ``_pid_exists`` zero-pid boundary.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Final, cast

import pytest

import intellicrack.core.process_manager as _pm_module
from intellicrack.core.process_manager import (
    ProcessManager,
    ProcessStateError,
)


_CMD_EXE: Final[str] = shutil.which("cmd.exe") or "cmd.exe"
_pid_exists: Callable[[int], bool] = cast(
    Callable[[int], bool],
    getattr(_pm_module, "_pid_exists"),
)
_pid_exists_windows: Callable[[int], bool] = cast(
    Callable[[int], bool],
    getattr(_pm_module, "_pid_exists_windows"),
)


class _ZombieProcess:
    """Fake subprocess whose returncode stays None after communicate().

    Simulates a process that exits without reporting a return code,
    triggering the ``ProcessStateError`` path in ``run_tracked``.
    """

    pid: int = 999_997

    def __init__(self) -> None:
        """Initialize with returncode=None and no pipes."""
        self.returncode: int | None = None
        self.stdin: None = None

    def communicate(self, timeout: float | None = None) -> tuple[bytes | None, bytes | None]:
        """Return without setting returncode.

        Args:
            timeout: Unused timeout parameter.

        Returns:
            tuple[bytes | None, bytes | None]: Empty stdout and stderr.
        """
        del timeout
        return None, None

    def kill(self) -> None:
        """No-op kill."""

    def wait(self, timeout: float | None = None) -> int | None:
        """Return None to simulate a process that never reports exit.

        Args:
            timeout: Unused.

        Returns:
            int | None: Always None.
        """
        del timeout
        return None

    def poll(self) -> int | None:
        """Return None (process not yet terminated).

        Returns:
            int | None: Always None.
        """
        return None


def _zombie_popen(*_args: object, **_kwargs: object) -> _ZombieProcess:
    """Replace subprocess.Popen with a zombie that never sets returncode.

    Args:
        *_args: Ignored positional arguments.
        **_kwargs: Ignored keyword arguments.

    Returns:
        _ZombieProcess: A fake process with returncode=None.
    """
    return _ZombieProcess()


class TestProcessStateError:
    """Gate for S7-09: ProcessStateError attributes and message format."""

    def test_constructor_sets_process_name_and_pid(self) -> None:
        """ProcessStateError sets process_name, pid, and includes them in str().

        Oracle: ``ProcessStateError.__init__`` docstring specifies
        ``f"{detail} (name={name!r}, pid={pid})"`` as the message format.
        Mutation: removing ``self.process_name = name`` or ``self.pid = pid``
        fails the attribute assertions; removing the f-string fails the
        ``in str(err)`` check.
        """
        err = ProcessStateError(name="cmd.exe", pid=12345)
        assert err.process_name == "cmd.exe", f"process_name should be 'cmd.exe'; got {err.process_name!r}"
        assert err.pid == 12345, f"pid should be 12345; got {err.pid}"
        assert "cmd.exe" in str(err), f"str(err) missing 'cmd.exe': {str(err)!r}"
        assert "12345" in str(err), f"str(err) missing '12345': {str(err)!r}"

    def test_default_detail_in_message(self) -> None:
        """Default message contains 'subprocess returned no exit status'.

        Oracle: the ``detail`` fallback in ``ProcessStateError.__init__`` is
        ``'subprocess returned no exit status'``.  Mutation: changing this
        string literal fails the ``in str(err)`` assertion.
        """
        err = ProcessStateError(name="python.exe", pid=1)
        assert "subprocess returned no exit status" in str(err), f"Default detail absent from error message: {str(err)!r}"

    def test_custom_message_used_when_provided(self) -> None:
        """Custom message overrides the default detail.

        Oracle: when ``message`` kwarg is provided, it appears in ``str(err)``
        instead of the default.  Mutation: ignoring the ``message`` kwarg
        means the custom text is absent, failing the assertion.
        """
        err = ProcessStateError(name="helper.exe", pid=9999, message="out-of-band exit")
        assert "out-of-band exit" in str(err), f"Custom message absent from error: {str(err)!r}"
        assert "subprocess returned no exit status" not in str(err), f"Default message should not appear when custom is given: {str(err)!r}"

    def test_is_a_runtime_error(self) -> None:
        """ProcessStateError subclasses RuntimeError.

        Oracle: class hierarchy requires ``isinstance(err, RuntimeError)`` so
        callers catching ``RuntimeError`` also catch zombie-process conditions.
        Mutation: changing the base class to ``Exception`` fails this.
        """
        err = ProcessStateError(name="test.exe", pid=0)
        assert isinstance(err, RuntimeError)

    def test_run_tracked_raises_process_state_error_on_null_returncode(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """run_tracked raises ProcessStateError when subprocess returncode stays None.

        Args:
            monkeypatch: Pytest monkeypatch fixture.

        Oracle: ``run_tracked`` checks ``if returncode is None: raise ProcessStateError(name, pid)``
        (process_manager.py ~L1085).  Mutation: removing that guard returns
        a ``CompletedProcess`` with ``returncode=None``, causing the assertion
        to raise ``AttributeError`` on the caller side — the test would fail
        differently but still fail.

        This test replaces the ``Popen`` name in the ``process_manager`` module
        with ``_zombie_popen``, which returns a fake process whose
        ``returncode`` attribute remains ``None`` after ``communicate()`` — the
        exact scenario that triggers the ``ProcessStateError`` branch.
        """
        monkeypatch.setattr(_pm_module, "Popen", _zombie_popen)
        mgr = ProcessManager()
        with pytest.raises(ProcessStateError) as exc_info:
            mgr.run_tracked(["fake_cmd.exe"], name="zombie_proc")

        err = exc_info.value
        assert err.process_name == "zombie_proc", f"Expected process_name='zombie_proc'; got {err.process_name!r}"
        assert err.pid == _ZombieProcess.pid, f"Expected pid={_ZombieProcess.pid}; got {err.pid}"
        assert "zombie_proc" in str(err)


@pytest.mark.skipif(sys.platform != "win32", reason="_pid_exists_windows is Windows-only")
class TestPidExistsWindowsFallback:
    """Gate for S7-10: _pid_exists_windows kernel32 and psutil fallback paths."""

    def test_pid_exists_current_process_returns_true(self) -> None:
        """_pid_exists_windows returns True for the current process PID.

        Oracle: the current process is alive; ``os.getpid()`` is its PID.
        Mutation: returning ``False`` for the current PID unconditionally fails
        this assertion; swapping the return value of the kernel32 path also fails.
        """
        result = _pid_exists_windows(os.getpid())
        assert result is True, f"_pid_exists_windows({os.getpid()}) should be True for the current process; got {result}"

    def test_pid_exists_zero_pid_returns_false_via_pid_exists(self) -> None:
        """_pid_exists(0) returns False because pid <= 0 triggers the early return.

        Oracle: ``_pid_exists`` guards with ``if pid <= 0: return False`` before
        any kernel call; PID 0 is the System Idle Process and is never a valid
        trackable process.  Mutation: removing this guard and passing 0 to
        ``OpenProcess`` would either crash or return an error code, but the
        ``False`` assertion would still fail if the function returns True.
        """
        result = _pid_exists(0)
        assert result is False, f"_pid_exists(0) should be False; got {result}"

    def test_pid_exists_negative_pid_returns_false(self) -> None:
        """_pid_exists(-1) returns False via the pid <= 0 early return.

        Oracle: negative PIDs are impossible on Windows; the guard catches them.
        Mutation: removing the guard and passing -1 to OpenProcess would raise
        OverflowError on ctypes marshal — the test would fail with an exception
        rather than a False return.
        """
        result = _pid_exists(-1)
        assert result is False, f"_pid_exists(-1) should be False; got {result}"

    def test_pid_exists_psutil_fallback_with_current_process(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_pid_exists_windows uses psutil when ctypes.windll is None.

        Args:
            monkeypatch: Pytest monkeypatch fixture.

        Oracle: monkeypatching ``ctypes.windll`` to None forces the function
        to take the ``if windll is None: return psutil.pid_exists(pid)`` branch;
        the current process is alive so the result must be True.  Mutation:
        removing the fallback branch causes an ``AttributeError`` on
        ``None.kernel32`` before the return, making the function raise instead
        of returning True.
        """
        monkeypatch.setattr(ctypes, "windll", None)
        result = _pid_exists_windows(os.getpid())
        assert result is True, f"psutil fallback should return True for current PID; got {result}"

    def test_pid_exists_psutil_fallback_with_dead_pid(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_pid_exists_windows(dead_pid) returns False via psutil fallback.

        Args:
            monkeypatch: Pytest monkeypatch fixture.

        Oracle: a subprocess started and waited for has a terminated PID; psutil
        reports it as not alive.  Mutation: returning True for dead PIDs would
        fail this assertion.
        """
        proc = subprocess.Popen(
            [_CMD_EXE, "/c", "exit 0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.wait()
        dead_pid = proc.pid

        monkeypatch.setattr(ctypes, "windll", None)
        result = _pid_exists_windows(dead_pid)
        assert result is False, f"psutil fallback should return False for terminated PID {dead_pid}; got {result}"
