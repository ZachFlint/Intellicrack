# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Exclusive use of the machine-wide monitor stop event by one test at a time.

The sandbox monitor scripts and ``stop_monitors.cmd`` coordinate shutdown
through one named kernel event, ``IntellicrackMonitorStop``. Inside a guest
that is one fleet per machine. In the test suite it is one name shared by
every pytest process in the session: a stop signaled by a test in one process
ends the monitors a test in another process has just started, and a
manual-reset event stays signaled for as long as any process holds it open.

A test that starts monitors, signals the event or resets it therefore runs
inside :func:`monitor_stop_event_reserved`, which holds a named mutex for the
duration and leaves the event unsignaled on entry and on exit.
"""

from __future__ import annotations

import contextlib
import ctypes
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Generator


MONITOR_STOP_EVENT_NAME: Final[str] = "IntellicrackMonitorStop"
_RESERVATION_MUTEX_NAME: Final[str] = "IntellicrackMonitorStopEventTestReservation"
_RESERVATION_WAIT_MS: Final[int] = 900_000
_WAIT_OBJECT_0: Final[int] = 0x00000000
_WAIT_ABANDONED: Final[int] = 0x00000080
_EVENT_MODIFY_STATE: Final[int] = 0x0002


def reset_monitor_stop_event() -> None:
    """Return the named stop event to its unsignaled state when any process holds it open.

    An event nobody holds open does not exist and needs no reset: the next
    process that creates it gets a new, unsignaled one.

    Raises:
        OSError: When the system refuses to reset an event that exists.
    """
    if sys.platform != "win32":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_event = kernel32.OpenEventW
    open_event.restype = wintypes.HANDLE
    open_event.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    reset_event = kernel32.ResetEvent
    reset_event.restype = wintypes.BOOL
    reset_event.argtypes = [wintypes.HANDLE]
    close_handle = kernel32.CloseHandle
    close_handle.restype = wintypes.BOOL
    close_handle.argtypes = [wintypes.HANDLE]
    handle = open_event(_EVENT_MODIFY_STATE, 0, MONITOR_STOP_EVENT_NAME)
    if not handle:
        return
    try:
        if not reset_event(handle):
            message = f"ResetEvent on {MONITOR_STOP_EVENT_NAME} failed with error {ctypes.get_last_error()}"
            raise OSError(message)
    finally:
        close_handle(handle)


@contextlib.contextmanager
def monitor_stop_event_reserved() -> Generator[None]:
    """Hold the stop event for one test: no other reserving test runs meanwhile, and the event starts and ends unsignaled.

    The reservation is a named mutex, so it spans pytest processes, is
    released by the system when its holder dies, and may be taken again by the
    thread that already holds it. The wait for it ends when the test holding
    it finishes.

    Yields:
        None: Control returns to the caller while the reservation is held.

    Raises:
        OSError: When the system refuses to create the reservation mutex.
        TimeoutError: When another process kept the reservation longer than
            any test that uses the event runs.
    """
    if sys.platform != "win32":
        yield
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel32.CreateMutexW
    create_mutex.restype = wintypes.HANDLE
    create_mutex.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.restype = wintypes.DWORD
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    release_mutex = kernel32.ReleaseMutex
    release_mutex.restype = wintypes.BOOL
    release_mutex.argtypes = [wintypes.HANDLE]
    close_handle = kernel32.CloseHandle
    close_handle.restype = wintypes.BOOL
    close_handle.argtypes = [wintypes.HANDLE]
    mutex = create_mutex(None, 0, _RESERVATION_MUTEX_NAME)
    if not mutex:
        message = f"CreateMutexW for {_RESERVATION_MUTEX_NAME} failed with error {ctypes.get_last_error()}"
        raise OSError(message)
    try:
        outcome = int(wait_for_single_object(mutex, _RESERVATION_WAIT_MS))
        if outcome not in {_WAIT_OBJECT_0, _WAIT_ABANDONED}:
            message = f"the monitor stop event was still reserved by another test after {_RESERVATION_WAIT_MS // 1000}s (wait result {outcome:#x})"
            raise TimeoutError(message)
        try:
            reset_monitor_stop_event()
            yield
        finally:
            try:
                reset_monitor_stop_event()
            finally:
                release_mutex(mutex)
    finally:
        close_handle(mutex)
