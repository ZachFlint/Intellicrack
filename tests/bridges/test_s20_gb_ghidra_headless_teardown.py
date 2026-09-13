# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the S20-D08 Ghidra headless bridge teardown fix.

Before this fix, ``GhidraBridge.start_headless`` spawned a ``python.exe``
process that embeds the Ghidra JVM in-process via PyGhidra/jpype with no
tracked teardown mechanism: if the app process died without running
:meth:`GhidraBridge.shutdown` (crash, forced kill), the headless bridge child
kept running, held the jfx_bridge RPC port open, and kept an exclusive OS
lock on the Ghidra project's ``.lock``/``.lock~`` files. The next launch's
``start_headless`` then hit a ``LockException`` opening the same project.

Two independent mechanisms were added to close this gap:

* A Win32 "kill-on-job-close" job object (:func:`_create_kill_on_close_job_object`,
  :func:`_assign_process_to_job_object`, :func:`_close_job_object_handle`) that
  guarantees the OS itself terminates the headless child the instant the last
  handle to the job is closed -- including on a hard crash that never reaches
  any Python-level cleanup code.
* A stale-lock reclaim (:func:`_reclaim_stale_project_lock`,
  :func:`_project_lock_is_stale`) that deletes a project's lock files only when
  an OS-level exclusive open of every existing lock file succeeds -- proving no
  live process still holds it -- and otherwise leaves them untouched.

These tests exercise both mechanisms against real Win32 primitives: a real
spawned child process placed in a real job object, and a real exclusive
``CreateFileW`` handle standing in for a live Ghidra project lock holder. No
part of either mechanism is mocked or stubbed.
"""

from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes
from typing import TYPE_CHECKING, Final, cast

import psutil
import pytest

from intellicrack.bridges import ghidra as ghidra_module
from tests._helpers.process_cleanup import ManagedProcess


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_KILL_WAIT_TIMEOUT_S: Final[float] = 10.0
_KILL_POLL_INTERVAL_S: Final[float] = 0.1

_GENERIC_READ: Final[int] = 0x80000000
_GENERIC_WRITE: Final[int] = 0x40000000
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x80
_INVALID_HANDLE_VALUE: Final[int] = ctypes.c_void_p(-1).value or -1


def _get_private(name: str) -> Callable[..., object]:
    """Dynamically resolve a module-private helper from :mod:`intellicrack.bridges.ghidra`.

    These gates deliberately exercise :mod:`intellicrack.bridges.ghidra`'s
    internal teardown and lock-reclaim helpers, which are module-private by
    design (they are implementation details of :meth:`GhidraBridge.start_headless`/
    :meth:`GhidraBridge.shutdown`, not part of the bridge's public API).
    Resolving them through :func:`getattr` rather than a direct import keeps
    this an explicit, intentional white-box probe of that private surface.

    Args:
        name: The private helper's module-level attribute name.

    Returns:
        Callable[..., object]: The resolved callable.
    """
    return cast("Callable[..., object]", getattr(ghidra_module, name))


_create_kill_on_close_job_object = cast("Callable[[], int | None]", _get_private("_create_kill_on_close_job_object"))
_assign_process_to_job_object = cast("Callable[[int, int], None]", _get_private("_assign_process_to_job_object"))
_close_job_object_handle = cast("Callable[[int], None]", _get_private("_close_job_object_handle"))
_project_lock_paths = cast("Callable[[Path, str], tuple[Path, ...]]", _get_private("_project_lock_paths"))
_reclaim_stale_project_lock = cast("Callable[[Path, str], None]", _get_private("_reclaim_stale_project_lock"))


def _sleeper_argv() -> list[str]:
    """Build an argv that spawns a disposable, long-sleeping Python child.

    Returns:
        list[str]: Argument vector for a child process that sleeps far
        longer than any assertion in this module waits, so it is still
        alive until this module's own cleanup (job-object kill or
        :class:`ManagedProcess` teardown) reaps it.
    """
    return [sys.executable, "-c", "import time; time.sleep(120)"]


def _open_exclusive_handle(path: Path) -> int:
    """Open ``path`` with a Win32 share mode of zero, denying all sharing.

    Reproduces, from a real OS handle, exactly the kind of exclusive lock a
    live Ghidra project-lock holder places on ``.lock``/``.lock~``: any
    other attempt to open the same path for read or write -- including the
    plain :func:`pathlib.Path.open` probe inside
    :func:`intellicrack.bridges.ghidra._project_lock_is_stale` -- must fail
    with a sharing violation for as long as this handle stays open.

    Args:
        path: Existing file to open exclusively.

    Returns:
        int: The raw Win32 ``HANDLE`` value. Caller must close it via
        :func:`_close_raw_handle`.

    Raises:
        OSError: If ``CreateFileW`` fails to open the file.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_READ | _GENERIC_WRITE,
        0,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if not handle or int(handle) == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        message = f"CreateFileW exclusive open of {path} failed: WinError {error}"
        raise OSError(message)
    return int(handle)


def _close_raw_handle(handle: int) -> None:
    """Close a raw Win32 handle opened by :func:`_open_exclusive_handle`.

    Args:
        handle: The handle value to close.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle(handle)


def _wait_until_dead(pid: int, *, timeout: float = _KILL_WAIT_TIMEOUT_S) -> bool:
    """Poll until a process is gone or ``timeout`` elapses.

    Args:
        pid: Process ID to poll.
        timeout: Maximum seconds to wait.

    Returns:
        bool: True if the process was no longer running before the timeout,
        False if it was still alive when the timeout elapsed.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        time.sleep(_KILL_POLL_INTERVAL_S)
    return not psutil.pid_exists(pid)


class TestKillOnCloseJobObject:
    """S20-D08: a kill-on-close job object reaps its assigned child."""

    @pytest.mark.spawns_process
    def test_closing_job_handle_terminates_assigned_process(self) -> None:
        """Closing the job handle kills a real assigned child process.

        Spawns a genuine long-sleeping Python child, assigns it to a job
        object created by :func:`_create_kill_on_close_job_object`, and
        proves the OS itself terminates the child the moment
        :func:`_close_job_object_handle` releases the last handle to that
        job -- exactly the guarantee :meth:`GhidraBridge.start_headless`
        relies on for the PyGhidra bridge subprocess.
        """
        with ManagedProcess(_sleeper_argv()) as managed:
            pid = managed.pid
            assert psutil.pid_exists(pid), "precondition: the spawned child must be alive before job assignment"

            job_handle = _create_kill_on_close_job_object()
            assert job_handle is not None
            assert job_handle > 0

            _assign_process_to_job_object(job_handle, pid)
            assert psutil.pid_exists(pid), "assigning to the job object must not itself kill the process"

            _close_job_object_handle(job_handle)

            assert _wait_until_dead(pid), (
                f"pid {pid} must be terminated by the OS once the last handle to its kill-on-close job object is closed"
            )


class TestReclaimStaleProjectLock:
    """S20-D08: stale-lock reclaim deletes dead locks and preserves live ones."""

    def test_reclaims_lock_left_by_a_dead_process(self, tmp_path: Path) -> None:
        """Lock files nobody holds open are deleted.

        Args:
            tmp_path: Pytest-provided scratch directory standing in for a
                Ghidra project directory.
        """
        project_name = "gb_dead_lock_proj"
        lock_paths = _project_lock_paths(tmp_path, project_name)
        for path in lock_paths:
            path.write_bytes(b"stale-lock-from-a-dead-process")

        _reclaim_stale_project_lock(tmp_path, project_name)

        for path in lock_paths:
            assert not path.exists(), f"{path} must be reclaimed once no live process holds it open"

    def test_never_deletes_a_lock_a_live_process_holds_open(self, tmp_path: Path) -> None:
        """Lock files are left untouched while a real exclusive handle is open on one of them.

        Args:
            tmp_path: Pytest-provided scratch directory standing in for a
                Ghidra project directory.
        """
        project_name = "gb_live_lock_proj"
        lock_paths = _project_lock_paths(tmp_path, project_name)
        for path in lock_paths:
            path.write_bytes(b"lock-held-by-a-live-process")

        held_path = lock_paths[0]
        handle = _open_exclusive_handle(held_path)
        try:
            _reclaim_stale_project_lock(tmp_path, project_name)

            for path in lock_paths:
                assert path.exists(), (
                    f"{path} must never be deleted while {held_path} is held open by a live "
                    "exclusive handle, even though it is a different lock file in the same pair"
                )
        finally:
            _close_raw_handle(handle)

        _reclaim_stale_project_lock(tmp_path, project_name)
        for path in lock_paths:
            assert not path.exists(), f"{path} must be reclaimed once the live handle on {held_path} is released"
