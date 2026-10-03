# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Startup gates for a process launched under the confined restricted token.

The sandboxed-server launch derives a restricted, Low integrity token and
starts the server with it. On a hosted runner the server died in loader
initialization with ``STATUS_DLL_INIT_FAILED`` before it ran a line of its own
code, which the full launch surfaced only as a connection failure. The cause
was console allocation: a console-subsystem process with no console to inherit
allocates its own, and standing one up under the restricted token fails on the
runner. It fails the same way for a console-subsystem grandchild a shim or
launcher starts, which a flag on the direct child cannot prevent.

The launch therefore sets no console-creation flag and instead gives the whole
confined tree a console to inherit, allocated under the launcher's own
unrestricted token by :func:`ensure_inheritable_console`. These gates lock that
in: one asserts the launch requests no console of its own, so a return to
``CREATE_NO_WINDOW`` fails here rather than only on the runner; the other runs a
real process -- which itself starts a console-subsystem grandchild -- under the
real :func:`create_restricted_token` and requires the whole tree to reach its
exit code, so a console the restricted token cannot stand up is caught as the
exact loader status rather than a server handshake timeout.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import ClassVar, Final

import pytest

from intellicrack.mcp.sandbox_launch import (
    CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT,
    SANDBOX_CREATION_FLAGS,
    create_restricted_token,
    ensure_inheritable_console,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="restricted tokens and CreateProcessAsUserW are Windows-only Win32 facilities",
)

_DETACHED_PROCESS: Final[int] = 0x00000008
_SYSTEM_CMD: Final[str] = r"C:\Windows\System32\cmd.exe"
_PROBE_EXIT_CODE: Final[int] = 7
_WAIT_TIMEOUT_MS: Final[int] = 30000
_WAIT_OBJECT_0: Final[int] = 0x00000000
_ERROR_ACCESS_DENIED: Final[int] = 5


class _StartupInfoW(ctypes.Structure):
    """Win32 ``STARTUPINFOW``, the fields this probe sets left zeroed."""

    _fields_: ClassVar = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _ProcessInformation(ctypes.Structure):
    """Win32 ``PROCESS_INFORMATION``."""

    _fields_: ClassVar = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _run_under_token(command: str, creation_flags: int) -> int:
    """Run ``command`` under a fresh confined token and return its exit status.

    Args:
        command: The command line to run.
        creation_flags: Process creation flags for the child.

    Returns:
        int: The child's exit code, or the negated Win32 error when the process
        could not be created at all.

    Raises:
        ctypes.WinError: If waiting on or reading the child's exit fails.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    token = create_restricted_token()
    try:
        startup = _StartupInfoW()
        startup.cb = ctypes.sizeof(startup)
        info = _ProcessInformation()
        created = advapi32.CreateProcessAsUserW(
            wintypes.HANDLE(token),
            None,
            ctypes.create_unicode_buffer(command),
            None,
            None,
            wintypes.BOOL(0),
            creation_flags,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(info),
        )
        if not created:
            return -ctypes.get_last_error()
        try:
            if kernel32.WaitForSingleObject(info.hProcess, _WAIT_TIMEOUT_MS) != _WAIT_OBJECT_0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = wintypes.DWORD(0)
            if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
                raise ctypes.WinError(ctypes.get_last_error())
            return int(code.value)
        finally:
            _ = kernel32.CloseHandle(info.hProcess)
            _ = kernel32.CloseHandle(info.hThread)
    finally:
        _ = kernel32.CloseHandle(wintypes.HANDLE(token))


def _process_has_console() -> bool:
    """Report whether this process has a console attached.

    ``AllocConsole`` fails with ``ERROR_ACCESS_DENIED`` when a console already
    exists, which is a reliable attached-console test where the console-window
    handle is not, since a window-less console returns no handle.

    Returns:
        bool: ``True`` if a console is attached.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if kernel32.AllocConsole():
        return False
    return ctypes.get_last_error() == _ERROR_ACCESS_DENIED


class TestConfinedProcessStartup:
    """A confined process tree inherits a console rather than allocating one under the restricted token."""

    def test_the_launch_requests_no_console_of_its_own(self) -> None:
        """The confined launch sets no console-creation flag, so the tree inherits one.

        Allocating a console under the restricted token fails in loader
        initialization on a hosted runner, so a return to ``CREATE_NO_WINDOW``
        or a switch to ``DETACHED_PROCESS`` -- either of which makes a tree
        member allocate its own -- must fail here rather than only on the runner.
        """
        assert not SANDBOX_CREATION_FLAGS & CREATE_NO_WINDOW, (
            "the confined launch must not set CREATE_NO_WINDOW: its fresh console cannot be stood up under the restricted token"
        )
        assert not SANDBOX_CREATION_FLAGS & _DETACHED_PROCESS, (
            "the confined launch must not set DETACHED_PROCESS: a console-subsystem grandchild would then allocate its own console"
        )

    def test_ensure_inheritable_console_leaves_a_console_attached(self) -> None:
        """After the launch's console setup, this process has a console for children to inherit."""
        ensure_inheritable_console()
        assert _process_has_console(), "ensure_inheritable_console left no console for the confined tree to inherit"

    def test_a_confined_tree_reaches_its_exit_code_inheriting_the_console(self) -> None:
        """A confined process and the console-subsystem grandchild it starts both run to completion.

        The child is created with the launch's own console setting (none, so it
        inherits), and it starts a further console-subsystem process. A console
        the restricted token cannot stand up anywhere in that tree surfaces as
        the child's loader status rather than a server handshake timeout.
        """
        ensure_inheritable_console()
        console_setting = SANDBOX_CREATION_FLAGS & (CREATE_NO_WINDOW | _DETACHED_PROCESS)
        command = f'{_SYSTEM_CMD} /c ""{_SYSTEM_CMD}" /c exit {_PROBE_EXIT_CODE}"'
        code = _run_under_token(command, console_setting | CREATE_UNICODE_ENVIRONMENT)
        assert code == _PROBE_EXIT_CODE, f"confined cmd.exe tree exited 0x{code & 0xFFFFFFFF:08X}, not {_PROBE_EXIT_CODE}"
