# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for X64DbgBridge introspection over a live process.

These tests drive the bridge's process-introspection surface against the
current Python process using real Windows APIs and the bridge's in-memory PE
parser (the documented local fallback used when the x64dbg plugin pipe is not
connected). They assert on independently verifiable ground truth:

* ``get_modules`` returns the real loaded system DLLs (``kernel32.dll``,
  ``ntdll.dll``) at the same base addresses Windows reports, with entry points
  parsed from the in-memory PE headers.
* ``get_module_exports`` returns real ``kernel32`` exports whose virtual
  addresses match the live values returned by ``GetProcAddress``.
* ``get_entry_point`` parses a real PE entry-point RVA consistent with the
  module base.
* ``get_threads`` enumerates the current process' real threads.
* ``get_process_info`` aggregates real threads and modules.

All tests target the current process only (no spawning) and skip cleanly when
not on Windows or when capstone is required and unavailable.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from intellicrack.bridges.x64dbg import X64DbgBridge

from intellicrack.bridges.x64dbg import X64DbgBridge as _X64DbgBridge


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


if sys.platform == "win32":
    from ctypes import wintypes


_KERNEL32 = "kernel32.dll"
_NTDLL = "ntdll.dll"
_WELL_KNOWN_EXPORTS = ("LoadLibraryA", "GetProcAddress", "VirtualAlloc")


@pytest.fixture
def attached_bridge() -> X64DbgBridge:
    """Create a bridge attached to the current Python process.

    Returns:
        X64DbgBridge: Bridge whose ``attached_pid`` is the current process.
    """
    bridge = _X64DbgBridge()
    bridge.attached_pid = os.getpid()
    return bridge


def _live_module_base(module_name: str) -> int:
    """Resolve the live base address of a loaded module via the OS loader.

    Args:
        module_name: Module file name, for example ``kernel32.dll``.

    Returns:
        int: Base address that the Windows loader reports for the module.
    """
    get_module_handle = ctypes.windll.kernel32.GetModuleHandleW
    get_module_handle.restype = ctypes.c_void_p
    get_module_handle.argtypes = [wintypes.LPCWSTR]
    handle = get_module_handle(module_name)
    assert handle, f"Module {module_name} is not loaded in the current process"
    return int(handle)


def _live_proc_address(module_name: str, export: str) -> int:
    """Resolve the live virtual address of an exported function.

    Args:
        module_name: Module file name owning the export.
        export: Exported function name to resolve.

    Returns:
        int: Virtual address returned by ``GetProcAddress`` for the export.
    """
    module = ctypes.WinDLL(module_name, use_last_error=True)
    get_proc_address = ctypes.windll.kernel32.GetProcAddress
    get_proc_address.restype = ctypes.c_void_p
    get_proc_address.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    module_handle = ctypes.c_void_p(module._handle).value
    address = get_proc_address(module_handle, export.encode("ascii"))
    assert address, f"Export {export} not found in {module_name}"
    return int(address)


@pytest.mark.asyncio
async def test_get_modules_returns_real_system_dlls(attached_bridge: X64DbgBridge) -> None:
    """Verify get_modules enumerates real system DLLs at real base addresses.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    modules = await attached_bridge.get_modules()
    assert modules

    by_name = {m.name.lower(): m for m in modules}
    assert _KERNEL32 in by_name
    assert _NTDLL in by_name

    kernel32 = by_name[_KERNEL32]
    assert kernel32.base_address == _live_module_base(_KERNEL32)
    assert kernel32.size > 0


@pytest.mark.asyncio
async def test_get_modules_entry_point_within_module(attached_bridge: X64DbgBridge) -> None:
    """Verify parsed entry points fall inside the owning module image.

    The entry point is parsed from the real in-memory PE header. A valid entry
    point (when non-zero) must lie within ``[base, base + size)``.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    modules = await attached_bridge.get_modules()
    checked = 0
    for module in modules:
        if module.entry_point == 0:
            continue
        assert module.base_address <= module.entry_point < module.base_address + module.size, (
            f"Entry point {module.entry_point:#x} outside {module.name} image"
        )
        checked += 1
    assert checked > 0, "No module reported a non-zero parsed entry point"


@pytest.mark.asyncio
async def test_get_entry_point_matches_get_modules(attached_bridge: X64DbgBridge) -> None:
    """Verify get_entry_point parses a base consistent with the live loader.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    result = await attached_bridge.get_entry_point(_KERNEL32)
    assert result["module"] == _KERNEL32
    assert int(result["base_address"], 16) == _live_module_base(_KERNEL32)

    entry_rva = int(result["entry_point_rva"], 16)
    entry_va = int(result["entry_point_va"], 16)
    assert entry_va == int(result["base_address"], 16) + entry_rva


@pytest.mark.asyncio
async def test_get_module_exports_match_live_proc_addresses(attached_bridge: X64DbgBridge) -> None:
    """Verify parsed kernel32 export VAs match live GetProcAddress results.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    exports = await attached_bridge.get_module_exports(_KERNEL32)
    assert exports

    by_name: dict[str, int] = {}
    for entry in exports:
        name = entry.get("name")
        address = entry.get("address")
        if isinstance(name, str) and isinstance(address, str):
            by_name[name] = int(address, 16)

    matched = 0
    for export in _WELL_KNOWN_EXPORTS:
        if export not in by_name:
            continue
        assert by_name[export] == _live_proc_address(_KERNEL32, export), f"Parsed VA for {export} disagrees with live GetProcAddress"
        matched += 1
    assert matched > 0, f"None of {_WELL_KNOWN_EXPORTS} found in parsed kernel32 exports"


@pytest.mark.asyncio
async def test_get_threads_enumerates_current_process(attached_bridge: X64DbgBridge) -> None:
    """Verify get_threads enumerates the real threads of the current process.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    threads = await attached_bridge.get_threads()
    assert threads

    current_tid = ctypes.windll.kernel32.GetCurrentThreadId()
    thread_ids = {t.tid for t in threads}
    assert current_tid in thread_ids


@pytest.mark.asyncio
async def test_get_process_info_aggregates_real_state(attached_bridge: X64DbgBridge) -> None:
    """Verify get_process_info aggregates real threads and modules.

    Args:
        attached_bridge: Bridge attached to the current process.
    """
    info = await attached_bridge.get_process_info()
    assert info.pid == os.getpid()
    assert info.threads
    assert info.modules

    module_names = {m.name.lower() for m in info.modules}
    assert _KERNEL32 in module_names
    assert _NTDLL in module_names
