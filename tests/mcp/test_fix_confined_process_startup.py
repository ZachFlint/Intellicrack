# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Startup gates for a process launched under the confined restricted token.

The sandboxed-server launch derives a restricted, Low integrity token and
starts the server with it. On a hosted runner the server has been dying in
loader initialization with ``STATUS_DLL_INIT_FAILED`` before it runs a line of
its own code, which the full launch reports only as a connection failure. These
gates isolate that startup from the rest of the launch: each runs a trivial
process under the real :func:`create_restricted_token` and asserts it reaches
its own exit code, so a loader-time death is reported as the exact status the
child exited with, against a known binary and a known creation-flag set, rather
than buried in a server handshake.

A System32 binary isolates the token from the project interpreter's own
libraries; the console-free variant isolates console allocation (the launch
creates with ``CREATE_NO_WINDOW``) from the token itself.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import ClassVar

import pytest

from intellicrack.mcp.sandbox_launch import CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, create_restricted_token


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="restricted tokens and CreateProcessAsUserW are Windows-only Win32 facilities",
)

_DETACHED_PROCESS = 0x00000008
_SYSTEM_CMD = r"C:\Windows\System32\cmd.exe"
_PROBE_EXIT_CODE = 7
_WAIT_TIMEOUT_MS = 30000
_WAIT_OBJECT_0 = 0x00000000


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
        creation_flags: Process creation flags, as the launch passes them.

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


class TestConfinedProcessStartup:
    """A process created with the confined token must reach its own exit code."""

    def test_system32_binary_starts_with_the_launch_flags(self) -> None:
        """A System32 binary runs under the restricted token with the launch's creation flags.

        This isolates the token and the ``CREATE_NO_WINDOW`` flag from the
        project interpreter: a loader-time death here is the token or the
        console, not the interpreter's own libraries.
        """
        code = _run_under_token(f"{_SYSTEM_CMD} /c exit {_PROBE_EXIT_CODE}", CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
        assert code == _PROBE_EXIT_CODE, f"confined System32 cmd.exe exited 0x{code & 0xFFFFFFFF:08X}, not {_PROBE_EXIT_CODE}"

    def test_system32_binary_starts_without_a_console(self) -> None:
        """The same System32 binary runs under the restricted token with no console allocated.

        Paired with :meth:`test_system32_binary_starts_with_the_launch_flags`,
        this isolates console allocation: if the console-free variant reaches
        its exit code where the ``CREATE_NO_WINDOW`` variant dies in the loader,
        the console allocation is what the restricted token cannot complete.
        """
        code = _run_under_token(f"{_SYSTEM_CMD} /c exit {_PROBE_EXIT_CODE}", _DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT)
        assert code == _PROBE_EXIT_CODE, f"confined console-free cmd.exe exited 0x{code & 0xFFFFFFFF:08X}, not {_PROBE_EXIT_CODE}"

    def test_interpreter_starts_with_the_launch_flags(self) -> None:
        """The project interpreter runs under the restricted token with the launch's creation flags.

        This is the binary the real launch starts; a loader-time death here but
        not for the System32 binary points at the interpreter's own libraries or
        their path rather than the token itself.
        """
        code = _run_under_token(
            f'"{sys.executable}" -c "raise SystemExit({_PROBE_EXIT_CODE})"',
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        )
        assert code == _PROBE_EXIT_CODE, f"confined interpreter exited 0x{code & 0xFFFFFFFF:08X}, not {_PROBE_EXIT_CODE}"
