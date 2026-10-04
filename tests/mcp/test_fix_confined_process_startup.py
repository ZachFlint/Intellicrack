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

A second cause surfaced once the tree started: an elevated operator's token
carries a default access list naming Administrators and SYSTEM but not the
operator's own account, and the confined copy holds Administrators deny-only,
so a confined process could not open the other end of a pipe it had just
created and no launcher could start a child with redirected output. The last
gate gives this process's token that default list for its duration and requires
a process confined by :func:`create_restricted_token` to create a pipe.
"""

from __future__ import annotations

import ctypes
import sys
from contextlib import contextmanager
from ctypes import wintypes
from typing import TYPE_CHECKING, ClassVar, Final

import pytest

from intellicrack.mcp.sandbox_launch import (
    CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT,
    SANDBOX_CREATION_FLAGS,
    create_restricted_token,
    ensure_inheritable_console,
)


if TYPE_CHECKING:
    from collections.abc import Generator


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
_STD_HANDLES: Final[tuple[int, int, int]] = (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4)
_ERROR_INSUFFICIENT_BUFFER: Final[int] = 122
_TOKEN_QUERY: Final[int] = 0x0008
_TOKEN_ADJUST_DEFAULT: Final[int] = 0x0080
_TOKEN_DEFAULT_DACL_CLASS: Final[int] = 6
_SDDL_REVISION_1: Final[int] = 1
_ELEVATED_DEFAULT_DACL_SDDL: Final[str] = "D:(A;;GA;;;BA)(A;;GA;;;SY)"
_PIPE_PROBE: Final[str] = f"import _winapi, sys; _winapi.CreatePipe(None, 0); sys.exit({_PROBE_EXIT_CODE})"


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


class _TokenDefaultDacl(ctypes.Structure):
    """Win32 ``TOKEN_DEFAULT_DACL``."""

    _fields_: ClassVar = [("DefaultDacl", ctypes.c_void_p)]


def _set_default_dacl(
    advapi32: ctypes.WinDLL,
    token: wintypes.HANDLE,
    information: ctypes.Array[ctypes.c_char] | _TokenDefaultDacl,
) -> None:
    """Replace a token's default access list.

    Args:
        advapi32: The security API.
        token: The token to change.
        information: A ``TOKEN_DEFAULT_DACL`` naming the new list.

    Raises:
        ctypes.WinError: If the token could not be changed.
    """
    if not advapi32.SetTokenInformation(token, _TOKEN_DEFAULT_DACL_CLASS, ctypes.byref(information), ctypes.sizeof(information)):
        raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def _default_access_of_an_elevated_operator() -> Generator[None]:
    """Give this process's token the default access list an elevated operator's token has, then put its own back.

    That list names Administrators and SYSTEM and leaves the account itself
    out, which is what a confined token is copied from on a runner whose
    account is an elevated administrator.

    Yields:
        None: While the elevated list is in force.

    Raises:
        ctypes.WinError: If the token could not be opened, read or changed.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    own = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY | _TOKEN_ADJUST_DEFAULT, ctypes.byref(own)):
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.c_void_p()
    try:
        needed = wintypes.DWORD(0)
        _ = advapi32.GetTokenInformation(own, _TOKEN_DEFAULT_DACL_CLASS, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(ctypes.get_last_error())
        original = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(own, _TOKEN_DEFAULT_DACL_CLASS, original, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _ELEVATED_DEFAULT_DACL_SDDL,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        elevated = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(elevated), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        _set_default_dacl(advapi32, own, _TokenDefaultDacl(DefaultDacl=elevated))
        try:
            yield
        finally:
            _set_default_dacl(advapi32, own, original)
    finally:
        _ = kernel32.LocalFree(descriptor)
        _ = kernel32.CloseHandle(own)


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

    def test_a_launcher_with_no_console_gets_a_hidden_one_and_keeps_its_standard_handles(self) -> None:
        """A launcher that starts with no console, as a windowed application does, is given one that shows no window.

        This process is detached from its console first, which is the state
        the application's own process starts in. The console setup is then run
        without its once-per-process memo, and must leave a console attached,
        show no window for it, and leave the launcher's standard handles where
        they were. A console is attached again whatever happens, so a failure
        here cannot leave the rest of the run with nothing to inherit.
        """
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleWindow.restype = wintypes.HWND
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        before = [kernel32.GetStdHandle(std) for std in _STD_HANDLES]
        _ = kernel32.FreeConsole()
        try:
            assert not kernel32.GetConsoleCP(), "the process still had a console after detaching from it"

            ensure_inheritable_console.__wrapped__()

            assert kernel32.GetConsoleCP(), "a launcher with no console was not given one for the confined tree to inherit"
            window = kernel32.GetConsoleWindow()
            assert not window or not user32.IsWindowVisible(window), "the console allocated for the confined tree shows a window"
            assert [kernel32.GetStdHandle(std) for std in _STD_HANDLES] == before, "the launcher's standard handles were repointed"
        finally:
            _ = kernel32.AllocConsole()

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

    def test_a_confined_process_can_use_a_pipe_it_creates_under_an_elevated_operator(self) -> None:
        """A process confined from an elevated operator's token creates a pipe and opens both of its ends.

        The confined token is derived while this process carries the default
        access list of an elevated administrator, which leaves the account
        itself out. Creating a pipe opens its second end against the access
        list the first end was created with, so a confined token that kept
        that list unchanged fails here with "Access is denied", exactly as
        every launcher that redirects a child's output did on the runner.
        """
        ensure_inheritable_console()
        command = f'"{sys.executable}" -c "{_PIPE_PROBE}"'
        with _default_access_of_an_elevated_operator():
            code = _run_under_token(command, CREATE_UNICODE_ENVIRONMENT)
        assert code == _PROBE_EXIT_CODE, (
            f"a confined process could not create a pipe under an elevated operator's default access list: exit 0x{code & 0xFFFFFFFF:08X}"
        )
