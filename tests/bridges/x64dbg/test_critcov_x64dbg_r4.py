# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fourth-pass critical-coverage test for the x64dbg bridge's module snapshot walker.

The walker is a static method that takes the ``kernel32`` binding, the snapshot handle and the record layout as arguments, so it runs
here against a real Toolhelp snapshot made by the test. The expectation rests on a measurement in the test container: a snapshot made
with ``TH32CS_SNAPPROCESS`` holds no module records, so ``Module32FirstW`` returns FALSE with ``ERROR_NO_MORE_FILES`` (18).

Probe key: ``first_0x2_Module32FirstW`` (``ok`` false, ``gle`` 18).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

from intellicrack.bridges.win32_types import INVALID_HANDLE_VALUE, TH32CS_SNAPPROCESS
from intellicrack.bridges.x64dbg import X64DbgBridge


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.types import ModuleInfo


_ERROR_NO_MORE_FILES: Final[int] = 18


class _ModuleEntry32W(ctypes.Structure):
    """Layout of the Win32 ``MODULEENTRY32W`` snapshot record."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def _sync_method(owner: object, name: str) -> Callable[..., Any]:
    """Fetch a plain function by name.

    Args:
        owner: Object or class that carries the member.
        name: Member name.

    Returns:
        Callable[..., Any]: The member, typed as a callable.
    """
    return cast("Callable[..., Any]", getattr(owner, name))


def _typed_kernel32() -> ctypes.WinDLL:
    """Create a private ``kernel32`` binding with the module-walk entry points typed.

    Returns:
        ctypes.WinDLL: Binding with last-error tracking and explicit ``restype``/``argtypes``.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return kernel32


def test_enumerate_modules_into_lists_nothing_for_a_snapshot_without_module_records() -> None:
    """A process-only snapshot has no module records, so the walk returns at once and leaves the list empty.

    The test first proves the premise with its own call: ``Module32FirstW`` on the snapshot returns FALSE and the operating system
    reports ``ERROR_NO_MORE_FILES``. The walker must then add nothing; a walker that went on to the loop would append one zeroed entry.

    Mutation: deleting the ``return`` at x64dbg.py:6285 makes the walker append an entry built from the unfilled record.
    """
    kernel32 = _typed_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    assert snapshot is not None
    assert snapshot != INVALID_HANDLE_VALUE
    try:
        oracle_entry = _ModuleEntry32W()
        oracle_entry.dwSize = ctypes.sizeof(_ModuleEntry32W)
        ctypes.set_last_error(0)
        assert not kernel32.Module32FirstW(snapshot, ctypes.byref(oracle_entry))
        assert ctypes.get_last_error() == _ERROR_NO_MORE_FILES

        modules: list[ModuleInfo] = []
        walked = _sync_method(X64DbgBridge, "_enumerate_modules_into")(kernel32, snapshot, _ModuleEntry32W, modules)
    finally:
        kernel32.CloseHandle(snapshot)

    assert walked is None
    assert modules == []
