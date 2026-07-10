# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Launch GUI processes on a dedicated, never-visible Windows desktop.

Some external tools Intellicrack drives - notably x64dbg - are GUI-only
applications whose windows Intellicrack must keep off the user's screen so the
only user-facing surface is the Intellicrack panel fed over the tool's IPC
transport. ``STARTUPINFO.wShowWindow = SW_HIDE`` is insufficient for such tools
because Qt (and most GUI frameworks) call ``ShowWindow(SW_SHOW)`` unconditionally
during startup, ignoring the ``nCmdShow`` the parent requested. The window
therefore paints for a moment before any in-process hook can hide it, producing
a visible flash.

The robust remedy is to associate the child with its own desktop object created
via ``CreateDesktopW`` and passed through ``STARTUPINFOW.lpDesktop``. Windows on
a desktop that is never made the input desktop are never composited to the
screen, so the child - and every window it or its own children create - is
invisible from the very first frame regardless of what the framework does.
``subprocess.Popen`` cannot set ``lpDesktop`` (the standard library exposes no
such field), so this module calls ``CreateProcessW`` directly and returns a
:class:`DesktopProcess` that mirrors the subset of the :class:`subprocess.Popen`
surface Intellicrack's process bookkeeping relies on.
"""

from __future__ import annotations

import ctypes
import itertools
import os
import sys
import threading
from ctypes import wintypes
from typing import TYPE_CHECKING, ClassVar, Self

from intellicrack.core.logging import get_logger
from intellicrack.core.subprocess_compat import list2cmdline


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path


_logger = get_logger(__name__)

_IS_WIN32: bool = sys.platform == "win32"

_GENERIC_ALL: int = 0x10000000
_STARTF_USESHOWWINDOW: int = 0x00000001
_STARTF_USESTDHANDLES: int = 0x00000100
_SW_HIDE: int = 0
_CREATE_UNICODE_ENVIRONMENT: int = 0x00000400
_CREATE_NO_WINDOW: int = 0x08000000
_STILL_ACTIVE: int = 259
_WAIT_OBJECT_0: int = 0x00000000
_WAIT_TIMEOUT: int = 0x00000102
_INFINITE: int = 0xFFFFFFFF
_UOI_NAME: int = 2
_INHERIT_HANDLES: int = 1

_GENERIC_READ: int = 0x80000000
_GENERIC_WRITE: int = 0x40000000
_FILE_SHARE_READ: int = 0x00000001
_FILE_SHARE_WRITE: int = 0x00000002
_OPEN_EXISTING: int = 3
_INVALID_HANDLE_VALUE: int = -1

_desktop_name_counter = itertools.count(1)
_desktop_name_lock = threading.Lock()


class _SecurityAttributes(ctypes.Structure):
    """Win32 ``SECURITY_ATTRIBUTES`` used to mark the NUL handles inheritable."""

    _fields_: ClassVar = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _StartupInfoW(ctypes.Structure):
    """Win32 ``STARTUPINFOW`` exposing the ``lpDesktop`` field ``subprocess`` hides."""

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
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _ProcessInformation(ctypes.Structure):
    """Win32 ``PROCESS_INFORMATION`` populated by ``CreateProcessW``."""

    _fields_: ClassVar = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _Win32Bindings:
    """Win32 entry points for launching a process on a hidden desktop.

    Bound lazily on first use (never at import) so that importing this module -
    which the x64dbg bridge and its tests do transitively - performs no
    ``ctypes`` work and stays side-effect free in constrained environments such
    as headless CI containers.
    """

    def __init__(self) -> None:
        """Load ``kernel32``/``user32`` and bind the required entry points."""
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)

        self.create_desktop = user32.CreateDesktopW
        self.create_desktop.restype = wintypes.HANDLE
        self.create_desktop.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]

        self.close_desktop = user32.CloseDesktop
        self.close_desktop.restype = wintypes.BOOL
        self.close_desktop.argtypes = [wintypes.HANDLE]

        self.get_thread_desktop = user32.GetThreadDesktop
        self.get_thread_desktop.restype = wintypes.HANDLE
        self.get_thread_desktop.argtypes = [wintypes.DWORD]

        self.get_user_object_information = user32.GetUserObjectInformationW
        self.get_user_object_information.restype = wintypes.BOOL
        self.get_user_object_information.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]

        self.create_process = kernel32.CreateProcessW
        self.create_process.restype = wintypes.BOOL
        self.create_process.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            ctypes.POINTER(_SecurityAttributes),
            ctypes.POINTER(_SecurityAttributes),
            wintypes.BOOL,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(_StartupInfoW),
            ctypes.POINTER(_ProcessInformation),
        ]

        self.create_file = kernel32.CreateFileW
        self.create_file.restype = wintypes.HANDLE
        self.create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_SecurityAttributes),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]

        self.get_exit_code = kernel32.GetExitCodeProcess
        self.get_exit_code.restype = wintypes.BOOL
        self.get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

        self.wait_for_single_object = kernel32.WaitForSingleObject
        self.wait_for_single_object.restype = wintypes.DWORD
        self.wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]

        self.terminate_process = kernel32.TerminateProcess
        self.terminate_process.restype = wintypes.BOOL
        self.terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]

        self.close_handle = kernel32.CloseHandle
        self.close_handle.restype = wintypes.BOOL
        self.close_handle.argtypes = [wintypes.HANDLE]

        self.get_current_thread_id = kernel32.GetCurrentThreadId
        self.get_current_thread_id.restype = wintypes.DWORD
        self.get_current_thread_id.argtypes = []


_api_cache: list[_Win32Bindings] = []
_api_lock = threading.Lock()


def _win32() -> _Win32Bindings:
    """Return the lazily-bound Win32 entry points, creating them on first use.

    Returns:
        _Win32Bindings: The cached bindings.

    Raises:
        OSError: If called on a non-Windows platform.
    """
    if not _api_cache:
        if not _IS_WIN32:
            msg = "hidden-desktop process launching is only supported on Windows"
            raise OSError(msg)
        with _api_lock:
            if not _api_cache:
                _api_cache.append(_Win32Bindings())
    return _api_cache[0]


def _win32_error(operation: str) -> tuple[int, str]:
    """Return ``OSError`` constructor arguments for the last Win32 error.

    Args:
        operation: Name of the Win32 call that failed, for the message.

    Returns:
        tuple[int, str]: The ``GetLastError`` code and a formatted message,
        suitable for ``raise OSError(*_win32_error(...))``.
    """
    err = ctypes.get_last_error()
    msg = ctypes.FormatError(err).strip()
    return err, f"{operation} failed: {msg}"


def _next_desktop_name() -> str:
    """Return a process-unique name for a new hidden desktop.

    Returns:
        str: A desktop name unique within this window station, built from the
        process ID and a monotonic counter.
    """
    with _desktop_name_lock:
        index = next(_desktop_name_counter)
    return f"IntellicrackHidden_{os.getpid()}_{index}"


def _build_environment_block(env: Mapping[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    """Build a Unicode environment block for ``CreateProcessW``.

    Args:
        env: Environment variables to encode.

    Returns:
        ctypes.Array[ctypes.c_wchar]: A double-null-terminated ``KEY=VALUE``
        block sorted case-insensitively as Windows expects.
    """
    items = sorted(env.items(), key=lambda kv: kv[0].upper())
    block = "".join(f"{key}={value}\x00" for key, value in items) + "\x00"
    return ctypes.create_unicode_buffer(block, len(block))


def get_thread_desktop_name() -> str:
    """Return the name of the desktop the calling thread is assigned to.

    A process launched through :func:`spawn_on_hidden_desktop` runs on the
    hidden desktop, so its threads report that desktop's name here - the
    property that makes the child's windows invisible. This is the check callers
    and tests use to confirm the ``lpDesktop`` assignment took effect.

    Returns:
        str: The current thread's desktop name (for example ``"Default"`` or an
        Intellicrack hidden-desktop name).

    Raises:
        OSError: If called on a non-Windows platform or if the desktop name
            cannot be queried.
    """
    api = _win32()
    hdesk = api.get_thread_desktop(api.get_current_thread_id())
    if not hdesk:
        raise OSError(*_win32_error("GetThreadDesktop"))
    needed = wintypes.DWORD(0)
    api.get_user_object_information(wintypes.HANDLE(hdesk), _UOI_NAME, None, 0, ctypes.byref(needed))
    char_size = ctypes.sizeof(ctypes.c_wchar)
    buffer = ctypes.create_unicode_buffer((needed.value // char_size) + 1 if needed.value else 256)
    got = api.get_user_object_information(
        wintypes.HANDLE(hdesk),
        _UOI_NAME,
        buffer,
        ctypes.sizeof(buffer),
        ctypes.byref(needed),
    )
    if not got:
        raise OSError(*_win32_error("GetUserObjectInformationW"))
    return buffer.value


class HiddenDesktop:
    """A Win32 desktop object that is created but never made the input desktop.

    Windows placed on this desktop are never composited to the screen, so any
    process launched against it is fully invisible to the user for its entire
    lifetime. The desktop's ``name`` is set at construction and the handle is
    released with :meth:`close`.
    """

    def __init__(self) -> None:
        """Create a fresh, uniquely named hidden desktop.

        Raises:
            OSError: If called on a non-Windows platform or if
                ``CreateDesktopW`` fails.
        """
        api = _win32()
        self.name: str = _next_desktop_name()
        handle = api.create_desktop(self.name, None, None, 0, _GENERIC_ALL, None)
        if not handle:
            raise OSError(*_win32_error(f"CreateDesktopW({self.name})"))
        self._handle: int = int(handle)
        _logger.debug("hidden_desktop_created", desktop=self.name)

    def close(self) -> None:
        """Release the desktop handle if it is still open."""
        if self._handle:
            _win32().close_desktop(wintypes.HANDLE(self._handle))
            _logger.debug("hidden_desktop_closed", desktop=self.name)
            self._handle = 0

    def __enter__(self) -> Self:
        """Enter the runtime context and return this desktop.

        Returns:
            Self: This instance.
        """
        return self

    def __exit__(self, *exc: object) -> None:
        """Exit the runtime context, releasing the desktop handle.

        Args:
            *exc: Unused exception triple supplied by the ``with`` statement.
        """
        self.close()


class DesktopProcess:
    """A ``CreateProcessW`` child bound to a :class:`HiddenDesktop`.

    Mirrors the subset of :class:`subprocess.Popen` that Intellicrack's process
    bookkeeping uses (:attr:`pid`, :attr:`returncode`, :meth:`poll`,
    :meth:`wait`, :meth:`terminate`, :meth:`kill`) so callers can treat it
    interchangeably. The owned desktop is released when the process handles are
    closed via :meth:`close`.
    """

    def __init__(self, info: _ProcessInformation, desktop: HiddenDesktop) -> None:
        """Adopt a spawned process and the desktop it was launched on.

        Args:
            info: The ``PROCESS_INFORMATION`` returned by ``CreateProcessW``.
            desktop: The hidden desktop the process is bound to; closed with the
                process handles.
        """
        self._hprocess: int = int(info.hProcess)
        self._hthread: int = int(info.hThread)
        self.pid: int = int(info.dwProcessId)
        self._desktop: HiddenDesktop = desktop
        self.returncode: int | None = None

    @property
    def desktop_name(self) -> str:
        """Name of the hidden desktop this process is bound to.

        Returns:
            str: The desktop name; the child's threads report this name, which
            is what keeps its windows off the visible desktop.
        """
        return self._desktop.name

    def poll(self) -> int | None:
        """Return the exit code if the process has exited, else ``None``.

        Returns:
            int | None: The exit code, or ``None`` while the process runs.

        Raises:
            OSError: If ``GetExitCodeProcess`` fails.
        """
        if self.returncode is not None:
            return self.returncode
        api = _win32()
        code = wintypes.DWORD()
        if not api.get_exit_code(wintypes.HANDLE(self._hprocess), ctypes.byref(code)):
            raise OSError(*_win32_error("GetExitCodeProcess"))
        if code.value == _STILL_ACTIVE:
            if api.wait_for_single_object(wintypes.HANDLE(self._hprocess), 0) == _WAIT_OBJECT_0:
                self.returncode = int(code.value)
                return self.returncode
            return None
        self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        """Block until the process exits and return its exit code.

        Args:
            timeout: Maximum seconds to wait, or ``None`` to wait indefinitely.

        Returns:
            int: The process exit code.

        Raises:
            TimeoutError: If the process does not exit within ``timeout``.
            OSError: If the wait or exit-code query fails.
        """
        api = _win32()
        ms = _INFINITE if timeout is None else max(0, int(timeout * 1000))
        result = api.wait_for_single_object(wintypes.HANDLE(self._hprocess), ms)
        if result == _WAIT_TIMEOUT:
            msg = f"process {self.pid} did not exit within {timeout}s"
            raise TimeoutError(msg)
        if result != _WAIT_OBJECT_0:
            raise OSError(*_win32_error("WaitForSingleObject"))
        code = wintypes.DWORD()
        if not api.get_exit_code(wintypes.HANDLE(self._hprocess), ctypes.byref(code)):
            raise OSError(*_win32_error("GetExitCodeProcess"))
        self.returncode = int(code.value)
        return self.returncode

    def terminate(self) -> None:
        """Forcibly terminate the process.

        Raises:
            OSError: If ``TerminateProcess`` fails while the process is alive.
        """
        if self.poll() is not None:
            return
        if not _win32().terminate_process(wintypes.HANDLE(self._hprocess), 1):
            err = ctypes.get_last_error()
            if self.poll() is None:
                msg = ctypes.FormatError(err).strip()
                raise OSError(err, f"TerminateProcess failed: {msg}")

    def kill(self) -> None:
        """Forcibly terminate the process (alias of :meth:`terminate`)."""
        self.terminate()

    def close(self) -> None:
        """Close the process and thread handles and release the desktop."""
        api = _win32()
        if self._hthread:
            api.close_handle(wintypes.HANDLE(self._hthread))
            self._hthread = 0
        if self._hprocess:
            api.close_handle(wintypes.HANDLE(self._hprocess))
            self._hprocess = 0
        self._desktop.close()


def _open_nul_handle(inherit_sa: _SecurityAttributes) -> int:
    """Open an inheritable handle to the ``NUL`` device.

    Args:
        inherit_sa: Security attributes marking the handle inheritable.

    Returns:
        int: The opened ``NUL`` handle.

    Raises:
        OSError: If ``CreateFileW`` fails.
    """
    handle = _win32().create_file(
        "NUL",
        _GENERIC_READ | _GENERIC_WRITE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        ctypes.byref(inherit_sa),
        _OPEN_EXISTING,
        0,
        wintypes.HANDLE(0),
    )
    if int(handle) == _INVALID_HANDLE_VALUE or not handle:
        raise OSError(*_win32_error("CreateFileW(NUL)"))
    return int(handle)


def spawn_on_hidden_desktop(
    executable: Path,
    args: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> DesktopProcess:
    """Launch a GUI executable on a fresh, never-visible desktop.

    The child and every window it creates are invisible for the process's whole
    lifetime because the desktop they live on is never made the input desktop.
    Standard handles are wired to ``NUL`` so a GUI child that writes diagnostics
    cannot deadlock on an undrained pipe.

    Args:
        executable: Absolute path to the executable to launch.
        args: Command-line arguments to pass after the executable.
        env: Environment for the child; defaults to the current environment.

    Returns:
        DesktopProcess: A handle to the spawned process bound to its desktop.

    Raises:
        OSError: If called on a non-Windows platform or if any Win32 call in the
            launch sequence fails.
    """
    api = _win32()
    desktop = HiddenDesktop()
    nul_handle = 0
    launched = False
    info = _ProcessInformation()
    try:
        inherit_sa = _SecurityAttributes(
            nLength=ctypes.sizeof(_SecurityAttributes),
            lpSecurityDescriptor=None,
            bInheritHandle=_INHERIT_HANDLES,
        )
        nul_handle = _open_nul_handle(inherit_sa)

        command_line = list2cmdline([str(executable), *(args or ())])
        cmd_buffer = ctypes.create_unicode_buffer(command_line)

        startup = _StartupInfoW()
        startup.cb = ctypes.sizeof(_StartupInfoW)
        startup.lpDesktop = desktop.name
        startup.dwFlags = _STARTF_USESHOWWINDOW | _STARTF_USESTDHANDLES
        startup.wShowWindow = _SW_HIDE
        startup.hStdInput = nul_handle
        startup.hStdOutput = nul_handle
        startup.hStdError = nul_handle

        env_block = _build_environment_block(env if env is not None else dict(os.environ))
        created = api.create_process(
            str(executable),
            cmd_buffer,
            None,
            None,
            _INHERIT_HANDLES,
            _CREATE_UNICODE_ENVIRONMENT | _CREATE_NO_WINDOW,
            ctypes.cast(env_block, wintypes.LPVOID),
            None,
            ctypes.byref(startup),
            ctypes.byref(info),
        )
        if not created:
            raise OSError(*_win32_error(f"CreateProcessW({executable})"))
        launched = True
    finally:
        if nul_handle:
            api.close_handle(wintypes.HANDLE(nul_handle))
        if not launched:
            desktop.close()

    _logger.info(
        "process_spawned_on_hidden_desktop",
        pid=int(info.dwProcessId),
        desktop=desktop.name,
        executable=str(executable),
    )
    return DesktopProcess(info, desktop)
