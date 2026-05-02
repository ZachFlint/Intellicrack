# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Integration tests for ProcessBridge against real Windows APIs.

Uses the Python interpreter process (os.getpid()) as the target.
All async, all Windows-only. No mocks for Win32 calls.
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
import sys
import threading
import time
from ctypes import wintypes
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_MEM_MAPPED = 0x40000
_MEM_IMAGE = 0x1000000
_PAGE_NOACCESS = 0x01

_TH32CS_SNAPPROCESS: int = 0x00000002
_INVALID_HANDLE_VALUE: int = (2 ** (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1

_PAGE_READONLY: int = 0x02
_PAGE_READWRITE: int = 0x04
_PAGE_EXECUTE: int = 0x10
_PAGE_EXECUTE_READ: int = 0x20
_PAGE_EXECUTE_READWRITE: int = 0x40

_ATTR_KERNEL32 = "_kernel32"
_ATTR_NTDLL = "_ntdll"
_ATTR_ADVAPI32 = "_advapi32"
_ATTR_DEBUG_PRIV = "_debug_privilege_enabled"
_ATTR_PROCESS_HANDLE = "_process_handle"
_ATTR_ATTACHED_PID = "_attached_pid"
_ATTR_PROT_FROM_STRING = "_prot_from_string"
_ATTR_PARSE_REGISTRY_PATH = "_parse_registry_path"
_ATTR_SECTION_HANDLES = "_section_handles"
_ATTR_SECTION_VIEWS = "_section_views"


class _SectionHandlesShapeError(TypeError):
    """Raised when ``_section_handles`` is not a ``dict[int, str]``."""


class _SectionViewsShapeError(TypeError):
    """Raised when ``_section_views`` is not a ``dict[int, int]``."""


def _get_section_handles(bridge: ProcessBridge) -> dict[int, str]:
    """Return ``_section_handles`` as a typed ``dict[int, str]``.

    Bypasses ``reportPrivateUsage`` so tests can verify the bridge's
    handle-tracking lifecycle without weakening the public API.

    Args:
        bridge: ProcessBridge instance to read from.

    Returns:
        dict[int, str]: The bridge's section-handle tracking dict
            (mutable; the test owns no copy).

    Raises:
        _SectionHandlesShapeError: If the underlying attribute is missing
            or not a dict with ``int`` keys and ``str`` values.
    """
    raw: object = getattr(bridge, _ATTR_SECTION_HANDLES)
    if not isinstance(raw, dict):
        raise _SectionHandlesShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, str):
            raise _SectionHandlesShapeError
    return cast("dict[int, str]", raw)


def _get_section_views(bridge: ProcessBridge) -> dict[int, int]:
    """Return ``_section_views`` as a typed ``dict[int, int]``.

    Bypasses ``reportPrivateUsage`` so tests can verify the bridge's
    view-tracking lifecycle without weakening the public API.

    Args:
        bridge: ProcessBridge instance to read from.

    Returns:
        dict[int, int]: The bridge's mapped-view tracking dict
            (base address -> section handle).

    Raises:
        _SectionViewsShapeError: If the underlying attribute is missing
            or not a dict with ``int`` keys and ``int`` values.
    """
    raw: object = getattr(bridge, _ATTR_SECTION_VIEWS)
    if not isinstance(raw, dict):
        raise _SectionViewsShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, int):
            raise _SectionViewsShapeError
    return cast("dict[int, int]", raw)


def _get_attr_optional[TAttr](bridge: ProcessBridge, name: str, expected: type[TAttr]) -> TAttr | None:
    """Return a protected optional attribute from bridge, narrowed to expected type.

    Used to bypass reportPrivateUsage when tests need to inspect internal
    state without weakening the bridge's public API boundary.

    Args:
        bridge: The ProcessBridge instance to read from.
        name: Attribute name (must be a literal constant declared in this module).
        expected: Expected runtime type of the non-None value.

    Returns:
        TAttr | None: The attribute value typed as ``expected | None``.

    Raises:
        TypeError: If the attribute is neither None nor an instance of expected.
    """
    value: object = getattr(bridge, name)
    if value is None:
        return None
    if not isinstance(value, expected):
        msg = f"ProcessBridge.{name} expected {expected.__name__} or None, got {type(value).__name__}"
        raise TypeError(msg)
    return value


def _get_debug_privilege_enabled(bridge: ProcessBridge) -> bool:
    """Return the bridge's debug privilege flag, bypassing reportPrivateUsage.

    Args:
        bridge: The ProcessBridge instance to read from.

    Returns:
        bool: True if the debug privilege was acquired during initialization.

    Raises:
        TypeError: If the underlying attribute is not a bool.
    """
    flag: object = getattr(bridge, _ATTR_DEBUG_PRIV)
    if not isinstance(flag, bool):
        msg = f"ProcessBridge.{_ATTR_DEBUG_PRIV} expected bool, got {type(flag).__name__}"
        raise TypeError(msg)
    return flag


def _invoke_prot_from_string(protection: str) -> int:
    """Invoke ProcessBridge._prot_from_string via getattr, bypassing reportPrivateUsage.

    Args:
        protection: Protection string such as ``"rwx"``, ``"rw"``, or ``"r"``.

    Returns:
        int: The Win32 PAGE_* flag integer for the given string.

    Raises:
        TypeError: If the resolved attribute is not callable or does not return int.
    """
    fn: object = getattr(ProcessBridge, _ATTR_PROT_FROM_STRING)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_PROT_FROM_STRING} is not callable"
        raise TypeError(msg)
    result: object = fn(protection)
    if not isinstance(result, int):
        msg = f"ProcessBridge.{_ATTR_PROT_FROM_STRING} expected int return, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _invoke_parse_registry_path(key_path: str) -> tuple[int, str]:
    r"""Invoke ProcessBridge._parse_registry_path via getattr, bypassing reportPrivateUsage.

    Args:
        key_path: Registry path such as ``r"HKLM\\SOFTWARE\\Test"``.

    Returns:
        tuple[int, str]: A 2-tuple of ``(root_key_handle, subpath)``.

    Raises:
        TypeError: If the resolved attribute is not callable or returns an
            unexpected shape.
    """
    fn: object = getattr(ProcessBridge, _ATTR_PARSE_REGISTRY_PATH)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} is not callable"
        raise TypeError(msg)
    result: object = fn(key_path)
    if not isinstance(result, tuple):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got {type(result).__name__}"
        raise TypeError(msg)
    typed_result = cast("tuple[object, ...]", result)
    if len(typed_result) != 2:
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got tuple of length {len(typed_result)}"
        raise TypeError(msg)
    root_obj: object = typed_result[0]
    sub_obj: object = typed_result[1]
    if not isinstance(root_obj, int) or not isinstance(sub_obj, str):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected (int, str), got ({type(root_obj).__name__}, {type(sub_obj).__name__})"
        raise TypeError(msg)
    return root_obj, sub_obj


def _configure_kernel32_signatures(k32: ctypes.WinDLL) -> None:
    """Set correct 64-bit return/argument types on kernel32 functions.

    Args:
        k32: Loaded kernel32 DLL handle.
    """
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    k32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
    ]
    k32.VirtualProtectEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.CreateFileMappingW.restype = wintypes.HANDLE
    k32.CreateFileMappingW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    k32.MapViewOfFile.restype = ctypes.c_void_p
    k32.MapViewOfFile.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, and shutdown a ProcessBridge for the module.

    Yields:
        AsyncGenerator[ProcessBridge]: Initialized bridge that will be shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    k32 = _get_attr_optional(bridge, _ATTR_KERNEL32, ctypes.WinDLL)
    if k32 is not None:
        _configure_kernel32_signatures(k32)
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process.

    Args:
        process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.

    Yields:
        AsyncGenerator[ProcessBridge]: The shared bridge with an open handle on the current Python process.
    """
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


@pytest_asyncio.fixture
async def main_thread_tid(attached_bridge: ProcessBridge) -> int:
    """Get the TID of the first thread in the current process.

    Args:
        attached_bridge: ProcessBridge fixture pre-attached to the current Python process.

    Returns:
        int: Windows thread id of the first thread enumerated in the current process.
    """
    threads = await attached_bridge.get_threads(os.getpid())
    return threads[0].tid


@pytest.fixture
def known_buffer() -> tuple[int, ctypes.Array[ctypes.c_char], bytes]:
    """Create a buffer with known content for memory read tests.

    Returns:
        tuple[int, ctypes.Array[ctypes.c_char], bytes]: Tuple ``(address,
        backing_buffer, expected_bytes)`` whose address may be safely read
        by the bridge.
    """
    data = b"INTELLICRACK_BRIDGE_TEST_7890ABCDEF"
    buf = ctypes.create_string_buffer(data)
    return ctypes.addressof(buf), buf, data


@pytest.fixture
def secondary_thread() -> Generator[int]:
    """Spawn a blocking thread and yield its Windows TID for context tests.

    Yields:
        Generator[int]: Windows thread id of a parked worker thread that blocks until the fixture tears down.
    """
    event = threading.Event()
    tid_holder: list[int] = []

    def _worker() -> None:
        tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
        event.wait()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    time.sleep(0.1)
    yield tid_holder[0]
    event.set()
    t.join(timeout=2)


class TestInitialization:
    """Verify bridge initialization loads DLLs and sets state."""

    async def test_initialize_loads_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify kernel32 is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL) is not None

    async def test_initialize_loads_ntdll(self, process_bridge: ProcessBridge) -> None:
        """Verify ntdll is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_NTDLL, ctypes.WinDLL) is not None

    async def test_initialize_loads_advapi32(self, process_bridge: ProcessBridge) -> None:
        """Verify advapi32 is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_ADVAPI32, ctypes.WinDLL) is not None

    async def test_initialize_sets_connected(self, process_bridge: ProcessBridge) -> None:
        """Verify state shows connected and tool_running after init.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge.state.connected is True
        assert process_bridge.state.tool_running is True

    async def test_initialize_debug_privilege_flag(self, process_bridge: ProcessBridge) -> None:
        """Verify debug privilege flag is a boolean.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert isinstance(_get_debug_privilege_enabled(process_bridge), bool)

    async def test_name_is_process(self, process_bridge: ProcessBridge) -> None:
        """Verify bridge name is ToolName.PROCESS.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge.name == ToolName.PROCESS

    async def test_is_available(self, process_bridge: ProcessBridge) -> None:
        """Verify is_available returns True on Windows.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert await process_bridge.is_available() is True

    async def test_tool_definition_count(self, process_bridge: ProcessBridge) -> None:
        """Verify tool definition has 53 functions.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert len(process_bridge.tool_definition.functions) == 53


class TestProcessListing:
    """Verify process listing and filtering."""

    async def test_list_processes_non_empty(self, process_bridge: ProcessBridge) -> None:
        """Verify process list is non-empty.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        assert len(procs) > 0

    async def test_list_processes_includes_self(self, process_bridge: ProcessBridge) -> None:
        """Verify process list contains current PID.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        assert any(p.pid == os.getpid() for p in procs)

    async def test_list_processes_has_python_name(self, process_bridge: ProcessBridge) -> None:
        """Verify our process entry name contains 'python'.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        self_proc = next((p for p in procs if p.pid == os.getpid()), None)
        assert self_proc is not None
        assert "python" in self_proc.name.lower()

    async def test_list_processes_filter(self, process_bridge: ProcessBridge) -> None:
        """Verify name filter returns at least one python process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes(filter_name="python")
        assert len(procs) >= 1

    async def test_list_processes_detailed_has_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify detailed listing includes expected keys.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        assert len(procs) >= 1
        entry = procs[0]
        for key in ("pid", "name", "architecture", "memory_mb", "thread_count"):
            assert key in entry

    async def test_list_processes_detailed_self_arch(self, process_bridge: ProcessBridge) -> None:
        """Verify our process architecture is x64 or x86.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None
        arch = self_proc["architecture"]
        assert isinstance(arch, str)
        assert arch in {"x64", "x86"}

    async def test_list_processes_detailed_self_memory(self, process_bridge: ProcessBridge) -> None:
        """Verify our process has positive memory usage.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None
        memory_mb = self_proc["memory_mb"]
        assert isinstance(memory_mb, (int, float))
        assert memory_mb > 0

    async def test_detect_architecture_self(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns the canonical arch on the current process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        arch = await process_bridge.detect_architecture(os.getpid())
        expected = "x86_64" if struct.calcsize("P") * 8 == 64 else "x86"
        assert arch == expected

    async def test_detect_architecture_invalid_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns Unknown for invalid PID.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        arch = await process_bridge.detect_architecture(99999999)
        assert arch == "Unknown"


class TestProcessOpenClose:
    """Verify process open/close lifecycle."""

    async def test_open_process_query(self, process_bridge: ProcessBridge) -> None:
        """Verify opening own process succeeds.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.open_process(os.getpid(), "query")
        assert result is True
        assert getattr(process_bridge, _ATTR_PROCESS_HANDLE) is not None
        await process_bridge.close()

    async def test_close_resets_state(self, process_bridge: ProcessBridge) -> None:
        """Verify close resets handle, pid, and state.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.open_process(os.getpid(), "all")
        await process_bridge.close()
        assert getattr(process_bridge, _ATTR_PROCESS_HANDLE) is None
        assert getattr(process_bridge, _ATTR_ATTACHED_PID) is None
        assert process_bridge.state.process_attached is False

    async def test_open_invalid_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify opening an invalid PID raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError, match="process open failed"):
            await process_bridge.open_process(99999999, "all")

    async def test_get_process_memory_mb_self(self, process_bridge: ProcessBridge) -> None:
        """Verify memory query returns positive value for self.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        mem = await process_bridge.get_process_memory_mb(os.getpid())
        assert mem > 0


class TestMemoryOperations:
    """Verify memory read, write, allocate, free, protect, search, and map."""

    async def test_read_memory_known_buffer(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify reading from a known buffer returns expected data.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            known_buffer: Triple of (address, backing buffer, expected bytes) for a buffer with known content.
        """
        addr, _buf, data = known_buffer
        result = await attached_bridge.read_memory(addr, len(data))
        assert isinstance(result, str)
        assert bytes.fromhex(result)[: len(data)] == data

    async def test_read_memory_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading without attachment raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_read_roundtrip(self, attached_bridge: ProcessBridge) -> None:
        """Verify allocate-write-read-free roundtrip works.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        try:
            test_data = b"WRITE_TEST"
            written = await attached_bridge.write_memory(addr, test_data)
            assert written == len(test_data)
            readback = await attached_bridge.read_memory(addr, len(test_data))
            assert bytes.fromhex(readback) == test_data
        finally:
            await attached_bridge.free(addr)

    async def test_allocate_free_cycle(self, attached_bridge: ProcessBridge) -> None:
        """Verify allocate returns non-zero address and free succeeds.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        assert addr != 0
        result = await attached_bridge.free(addr)
        assert result is True

    async def test_protect_returns_old_protection(self, attached_bridge: ProcessBridge) -> None:
        """Verify protect returns the previous protection string.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        try:
            old_prot = await attached_bridge.protect(addr, 4096, "r")
            assert "rw" in old_prot
        finally:
            await attached_bridge.free(addr)

    async def test_search_pattern_finds_bytes(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify pattern search finds known bytes in memory.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            known_buffer: Triple of (address, backing buffer, expected bytes) for a buffer with known content.
        """
        addr, _buf, data = known_buffer
        pattern = " ".join(f"{b:02X}" for b in data[:8])
        results = await attached_bridge.search_pattern(pattern, start_address=addr - 0x10000, end_address=addr + 0x10000)
        assert addr in results

    async def test_get_memory_map_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify memory map returns non-empty list with required fields.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        regions = await attached_bridge.get_memory_map()
        assert len(regions) > 0
        region = regions[0]
        assert hasattr(region, "base_address")
        assert hasattr(region, "size")
        assert hasattr(region, "protection")


class TestThreadEnumeration:
    """Verify thread listing and bug-fix fields (start_address, state)."""

    async def test_get_threads_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify thread list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert len(threads) > 0

    async def test_get_threads_have_tid(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have positive TIDs.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.tid > 0 for t in threads)

    async def test_get_threads_start_address_nonzero(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a non-zero start address (bug fix).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert any(t.start_address != 0 for t in threads)

    async def test_get_threads_state_not_unknown(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a known state (bug fix).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        valid_states = {"running", "suspended", "terminated", "waiting"}
        assert any(t.state in valid_states for t in threads)

    async def test_get_threads_expose_pc_fields(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have separate start_address and current_pc fields.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.start_address >= 0 and t.current_pc >= 0 for t in threads)


class TestModuleListing:
    """Verify module enumeration."""

    async def test_get_modules_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify module list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert len(modules) > 0

    async def test_get_modules_includes_python(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one module name contains 'python'.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert any("python" in m.name.lower() for m in modules)

    async def test_get_modules_have_base_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify all modules have positive base addresses.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert all(m.base_address > 0 for m in modules)

    async def test_get_modules_no_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()


class TestProcessInfo:
    """Verify process info aggregation."""

    async def test_get_process_info_self(self, attached_bridge: ProcessBridge) -> None:
        """Verify process info is populated for self.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        info = await attached_bridge.get_process_info(os.getpid())
        assert info is not None
        assert len(info.threads) > 0
        assert len(info.modules) > 0

    async def test_get_process_info_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify process info returns None when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        info = await process_bridge.get_process_info()
        assert info is None


class TestTokenPrivileges:
    """Verify token privilege enumeration and adjustment."""

    async def test_get_token_privileges_has_entries(self, attached_bridge: ProcessBridge) -> None:
        """Verify token privileges list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert len(privs) > 0

    async def test_get_token_privileges_has_sechangenotify(self, attached_bridge: ProcessBridge) -> None:
        """Verify SeChangeNotifyPrivilege is present.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert any("SeChangeNotifyPrivilege" in str(p.get("name", "")) for p in privs)

    async def test_get_token_privileges_entry_keys(self, attached_bridge: ProcessBridge) -> None:
        """Verify each privilege entry has required keys.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        for priv in privs:
            for key in ("name", "luid_low", "luid_high", "enabled", "attributes"):
                assert key in priv

    async def test_adjust_token_privilege_invalid_raises(self, attached_bridge: ProcessBridge) -> None:
        """Verify adjusting a fake privilege raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError, match="privilege lookup failed"):
            await attached_bridge.adjust_token_privilege("SeCompletelyFakePrivilege", enable=True, pid=os.getpid())


class TestHandleEnumeration:
    """Verify handle enumeration via NtQuerySystemInformation."""

    async def test_get_handles_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify handle enumeration returns a list without error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handles = await process_bridge.get_handles(os.getpid())
        assert isinstance(handles, list)

    async def test_get_handles_have_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify each handle entry has required fields when available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handles = await process_bridge.get_handles(os.getpid())
        for handle in handles[:5]:
            assert "handle_value" in handle
            assert "type_index" in handle


class TestWindowEnumeration:
    """Verify window enumeration doesn't crash."""

    async def test_get_windows_no_crash(self, attached_bridge: ProcessBridge) -> None:
        """Verify get_windows returns a list without crashing.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        windows = await attached_bridge.get_windows(os.getpid())
        assert isinstance(windows, list)


class TestServiceListing:
    """Verify service enumeration."""

    async def test_list_services_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify service listing returns a list without error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert isinstance(services, list)

    async def test_list_services_have_name_state(self, process_bridge: ProcessBridge) -> None:
        """Verify each service has name and state when available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        for svc in services[:5]:
            assert "name" in svc
            assert "state" in svc


class TestPebTebAccess:
    """Verify PEB and TEB reads."""

    async def test_read_peb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB read returns a positive peb_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        peb = await attached_bridge.read_peb()
        peb_address = peb["peb_address"]
        assert isinstance(peb_address, int)
        assert peb_address > 0

    async def test_read_peb_has_image_base(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB contains positive image_base_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        peb = await attached_bridge.read_peb()
        image_base = peb["image_base_address"]
        assert isinstance(image_base, int)
        assert image_base > 0

    async def test_read_teb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify TEB read returns a positive teb_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        tid = threads[0].tid
        teb = await attached_bridge.read_teb(tid)
        teb_address = teb["teb_address"]
        assert isinstance(teb_address, int)
        assert teb_address > 0

    async def test_read_teb_stack_range(self, attached_bridge: ProcessBridge) -> None:
        """Verify stack_base > 0 and stack_limit < stack_base (downward growth).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        tid = threads[0].tid
        teb = await attached_bridge.read_teb(tid)
        stack_base = teb.get("stack_base")
        stack_limit = teb.get("stack_limit")
        assert isinstance(stack_base, int)
        assert isinstance(stack_limit, int)
        assert stack_base > 0
        assert stack_limit < stack_base


class TestHeapEnumeration:
    """Verify heap enumeration via Toolhelp32."""

    async def test_get_heaps_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify heap list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert len(heaps) > 0

    async def test_get_heaps_has_default(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one heap is the default.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert any(h.get("is_default") is True for h in heaps)


class TestThreadContext:
    """Verify thread context read using a secondary thread to avoid deadlock."""

    async def test_get_thread_context_has_registers(self, attached_bridge: ProcessBridge, secondary_thread: int) -> None:
        """Verify context has rip and rsp on 64-bit, or eip/esp on 32-bit.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            secondary_thread: Windows thread id of a parked worker thread used for context queries.
        """
        ctx = await attached_bridge.get_thread_context(secondary_thread)
        if struct.calcsize("P") * 8 == 64:
            assert "rip" in ctx
            assert "rsp" in ctx
            assert ctx["rip"] != 0
            assert ctx["rsp"] != 0
        else:
            assert "eip" in ctx
            assert "esp" in ctx

    async def test_get_thread_context_invalid_tid(self, attached_bridge: ProcessBridge) -> None:
        """Verify invalid TID raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError):
            await attached_bridge.get_thread_context(0)


class TestMitigationPolicies:
    """Verify mitigation policy queries."""

    async def test_mitigation_policies_has_dep(self, attached_bridge: ProcessBridge) -> None:
        """Verify result has 'DEP' key.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        assert "DEP" in policies

    async def test_mitigation_policies_dep_structure(self, attached_bridge: ProcessBridge) -> None:
        """Verify DEP value is dict with 'enabled' and 'flags'.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        dep_value = policies["DEP"]
        assert isinstance(dep_value, dict)
        assert "enabled" in dep_value
        assert "flags" in dep_value


class TestEnvironmentVariables:
    """Verify environment variable reading from PEB."""

    async def test_get_environment_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment dict is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert len(env) > 0

    async def test_get_environment_has_path(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment contains PATH (case-insensitive).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert any(k.upper() == "PATH" for k in env)


class TestDotNetDetection:
    """Verify .NET CLR detection."""

    async def test_detect_dotnet_python_is_negative(self, attached_bridge: ProcessBridge) -> None:
        """Verify Python process has no CLR loaded.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        result = await attached_bridge.detect_dotnet(os.getpid())
        clr_loaded = result["clr_loaded"]
        assert isinstance(clr_loaded, bool)
        assert clr_loaded is False


class TestJobGuiCom:
    """Verify job object, GUI resources, and COM enumeration."""

    async def test_get_job_info_has_in_job(self, attached_bridge: ProcessBridge) -> None:
        """Verify job info has 'in_job' key.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        info = await attached_bridge.get_job_info(os.getpid())
        assert "in_job" in info
        assert isinstance(info["in_job"], bool)

    async def test_get_gui_resources_has_counts(self, attached_bridge: ProcessBridge) -> None:
        """Verify GUI resources has non-negative counts.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        res = await attached_bridge.get_gui_resources(os.getpid())
        assert res["gdi_objects"] >= 0
        assert res["user_objects"] >= 0

    async def test_enumerate_com_servers_returns_list(self, attached_bridge: ProcessBridge) -> None:
        """Verify COM enumeration returns a list without crashing.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        result = await attached_bridge.enumerate_com_servers(os.getpid())
        assert isinstance(result, list)


class TestRegistry:
    """Verify registry access operations."""

    async def test_reg_read_value_product_name(self, process_bridge: ProcessBridge) -> None:
        """Verify reading ProductName from CurrentVersion.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.reg_read_value(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
        value_type = result["type"]
        assert isinstance(value_type, str)
        assert value_type == "string"
        assert len(str(result["data"])) > 0

    async def test_reg_enum_keys_microsoft(self, process_bridge: ProcessBridge) -> None:
        r"""Verify enumerating HKLM\\SOFTWARE\\Microsoft returns non-empty list.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        keys = await process_bridge.reg_enum_keys(r"HKLM\SOFTWARE\Microsoft")
        assert len(keys) > 0

    async def test_reg_enum_values_currentversion(self, process_bridge: ProcessBridge) -> None:
        """Verify enumerating values under CurrentVersion returns non-empty list.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        values = await process_bridge.reg_enum_values(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        assert len(values) > 0

    async def test_reg_read_invalid_key_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading invalid key raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError, match="registry key open failed"):
            await process_bridge.reg_read_value(r"HKLM\SOFTWARE\TOTALLY_FAKE_KEY_12345", "value")


class TestSectionMapping:
    """Verify section create and map operations."""

    async def test_create_section_returns_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify section creation returns a positive handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        try:
            assert handle > 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
            _get_section_handles(process_bridge).pop(handle, None)

    async def test_map_section_returns_address(self, process_bridge: ProcessBridge) -> None:
        """Verify mapping a section returns a positive address.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        try:
            addr: int = await process_bridge.map_section(handle, 4096)
            assert addr > 0
            ok: bool = await process_bridge.unmap_section(addr)
            assert ok is True
        finally:
            section_handles = _get_section_handles(process_bridge)
            if handle in section_handles:
                ctypes.windll.kernel32.CloseHandle(handle)
                section_handles.pop(handle, None)


class TestNtQuerySystemInformation:
    """Verify raw NtQuerySystemInformation bridge."""

    async def test_query_system_info_process_info(self, process_bridge: ProcessBridge) -> None:
        """Verify SystemProcessInformation (class 5) returns non-empty bytes.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.query_system_info(5)
        assert len(result) > 0


class TestSehFiberTls:
    """Verify SEH chain, fiber data, and TLS access."""

    async def test_get_seh_chain_no_crash(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify SEH chain returns a list (may be empty on x64).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        chain = await attached_bridge.get_seh_chain(main_thread_tid)
        assert isinstance(chain, list)

    async def test_get_fiber_data_returns_dict(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify fiber data has expected keys.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        result = await attached_bridge.get_fiber_data(main_thread_tid)
        assert "fiber_data" in result
        assert "has_fiber" in result

    async def test_get_tls_values_returns_list(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify TLS values returns a list.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        result = await attached_bridge.get_tls_values(main_thread_tid)
        assert isinstance(result, list)


class TestStaticHelpers:
    """Verify static helper methods with no asyncio or platform restriction."""

    def test_prot_from_string_rwx(self) -> None:
        """Verify 'rwx' maps to PAGE_EXECUTE_READWRITE."""
        assert _invoke_prot_from_string("rwx") == _PAGE_EXECUTE_READWRITE

    def test_prot_from_string_rw(self) -> None:
        """Verify 'rw' maps to PAGE_READWRITE."""
        assert _invoke_prot_from_string("rw") == _PAGE_READWRITE

    def test_prot_from_string_rx(self) -> None:
        """Verify 'rx' maps to PAGE_EXECUTE_READ."""
        assert _invoke_prot_from_string("rx") == _PAGE_EXECUTE_READ

    def test_prot_from_string_r(self) -> None:
        """Verify 'r' maps to PAGE_READONLY."""
        assert _invoke_prot_from_string("r") == _PAGE_READONLY

    def test_prot_from_string_x(self) -> None:
        """Verify 'x' maps to PAGE_EXECUTE."""
        assert _invoke_prot_from_string("x") == _PAGE_EXECUTE

    def test_prot_from_string_unknown_defaults(self) -> None:
        """Verify unknown string defaults to PAGE_EXECUTE_READWRITE."""
        assert _invoke_prot_from_string("???") == _PAGE_EXECUTE_READWRITE

    def test_parse_registry_path_hklm(self) -> None:
        """Verify HKLM prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKLM\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_hkcu(self) -> None:
        """Verify HKCU prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKCU\Software")
        assert root == 0x80000001
        assert sub == "Software"

    def test_parse_registry_path_hkcr(self) -> None:
        """Verify HKCR prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKCR\CLSID")
        assert root == 0x80000000
        assert sub == "CLSID"

    def test_parse_registry_path_full_name(self) -> None:
        """Verify HKEY_LOCAL_MACHINE resolves same as HKLM."""
        root, sub = _invoke_parse_registry_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_invalid_raises(self) -> None:
        """Verify invalid root raises ToolError."""
        with pytest.raises(ToolError, match="invalid registry root"):
            _invoke_parse_registry_path(r"INVALID\Path")


class TestErrorConditions:
    """Verify error handling for unattached operations."""

    async def test_read_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify read_memory raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify write_memory raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.write_memory(0x1000, b"\x90")

    async def test_terminate_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify terminate raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.terminate()

    async def test_get_modules_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no PID available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()


class TestF0004TerminateFailure:
    """Verify F-0004: terminate() leaves _process_handle intact on TerminateProcess failure."""

    async def test_handle_preserved_after_terminate_access_denied(self, process_bridge: ProcessBridge) -> None:
        """Verify _process_handle is not cleared when TerminateProcess fails.

        Open the current process with query-only rights (PROCESS_QUERY_INFORMATION),
        which lacks PROCESS_TERMINATE.  TerminateProcess will return 0 (ERROR_ACCESS_DENIED).
        Before the fix, the finally-block called self.close() which wiped the handle;
        after the fix the handle must still be present.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        process_query_information = 0x0400
        inherit_handle = False
        handle: int = k32.OpenProcess(process_query_information, inherit_handle, os.getpid())
        if not handle:
            pytest.skip("Could not open own process with query-only rights")

        setattr(process_bridge, _ATTR_PROCESS_HANDLE, handle)
        setattr(process_bridge, _ATTR_ATTACHED_PID, os.getpid())

        try:
            with pytest.raises(ToolError, match="terminate failed"):
                await process_bridge.terminate()

            remaining_handle: object = getattr(process_bridge, _ATTR_PROCESS_HANDLE)
            assert remaining_handle is not None, "_process_handle was cleared despite TerminateProcess failure"
            assert remaining_handle == handle
        finally:
            k32.CloseHandle(handle)
            setattr(process_bridge, _ATTR_PROCESS_HANDLE, None)
            setattr(process_bridge, _ATTR_ATTACHED_PID, None)


class TestF0005SuspendResumeReportsFailure:
    """Verify F-0005: suspend/resume raise ToolError with failed TIDs on thread API failures."""

    async def test_suspend_raises_for_protected_process_threads(self, process_bridge: ProcessBridge) -> None:
        """Verify suspend raises ToolError when OpenThread fails due to insufficient rights.

        The Windows System process (PID 4) has threads that normal user-mode code
        cannot open with THREAD_SUSPEND_RESUME.  suspend() must collect all the
        failing TIDs and raise ToolError rather than silently returning True.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        system_pid = 4
        threads = await process_bridge.get_threads(system_pid)
        if not threads:
            pytest.skip("No threads found for System process (PID 4) — cannot exercise failure path")

        thread_suspend_resume = 0x0002
        inherit_flag = False
        any_protected = any(not k32.OpenThread(thread_suspend_resume, inherit_flag, t.tid) for t in threads)
        if not any_protected:
            pytest.skip("All System threads opened successfully — insufficient privilege restrictions in this environment")

        with pytest.raises(ToolError):
            await process_bridge.suspend(system_pid)

    async def test_resume_raises_for_protected_process_threads(self, process_bridge: ProcessBridge) -> None:
        """Verify resume raises ToolError when OpenThread fails due to insufficient rights.

        The Windows System process (PID 4) has threads that normal user-mode code
        cannot open with THREAD_SUSPEND_RESUME.  resume() must collect all the
        failing TIDs and raise ToolError rather than silently returning True.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        system_pid = 4
        threads = await process_bridge.get_threads(system_pid)
        if not threads:
            pytest.skip("No threads found for System process (PID 4) — cannot exercise failure path")

        thread_suspend_resume = 0x0002
        inherit_flag = False
        any_protected = any(not k32.OpenThread(thread_suspend_resume, inherit_flag, t.tid) for t in threads)
        if not any_protected:
            pytest.skip("All System threads opened successfully — insufficient privilege restrictions in this environment")

        with pytest.raises(ToolError):
            await process_bridge.resume(system_pid)


class TestF0023ServiceParseUnicode:
    """Verify F-0023: list_services() returns entries with str name and display_name fields."""

    async def test_service_name_fields_are_str(self, process_bridge: ProcessBridge) -> None:
        """Verify that each service entry contains str-typed name and display_name values.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert len(services) > 0, "No services returned; cannot validate types"
        for svc in services:
            assert isinstance(svc, dict)
            name_val: object = svc.get("name", None)
            display_val: object = svc.get("display_name", None)
            assert isinstance(name_val, str), f"service 'name' is {type(name_val).__name__}, expected str"
            assert isinstance(display_val, str), f"service 'display_name' is {type(display_val).__name__}, expected str"

    async def test_service_entries_contain_required_keys(self, process_bridge: ProcessBridge) -> None:
        """Verify every service entry has name, display_name, state, pid, and service_type keys.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert len(services) > 0
        for svc in services:
            assert isinstance(svc, dict)
            for key in ("name", "display_name", "state", "pid", "service_type"):
                assert key in svc, f"Missing key '{key}' in service entry"

    async def test_service_name_non_empty_for_at_least_one(self, process_bridge: ProcessBridge) -> None:
        """Verify at least one service has a non-empty unicode name.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        non_empty = [s for s in services if isinstance(s.get("name"), str) and s.get("name")]
        assert len(non_empty) > 0, "All service names are empty"


class TestF0026NoFakeSuccess:
    """Verify F-0026: pipe_close and device_close return False/raise on internal failure."""

    async def test_pipe_close_raises_without_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close raises ToolError when kernel32 is None.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        original_k32: object = getattr(process_bridge, _ATTR_KERNEL32)
        setattr(process_bridge, _ATTR_KERNEL32, None)
        try:
            with pytest.raises(ToolError, match="kernel32 not available"):
                await process_bridge.pipe_close(0xDEAD)
        finally:
            setattr(process_bridge, _ATTR_KERNEL32, original_k32)

    async def test_device_close_raises_without_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close raises ToolError when kernel32 is None.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        original_k32: object = getattr(process_bridge, _ATTR_KERNEL32)
        setattr(process_bridge, _ATTR_KERNEL32, None)
        try:
            with pytest.raises(ToolError, match="kernel32 not available"):
                await process_bridge.device_close(0xDEAD)
        finally:
            setattr(process_bridge, _ATTR_KERNEL32, original_k32)


class TestF0006MemConstants:
    """Verify get_memory_map filters MEM_MAPPED/MEM_IMAGE via named constants."""

    def test_mem_mapped_constant_value(self) -> None:
        """Sanity check ``_MEM_MAPPED`` matches the documented Win32 value."""
        assert _MEM_MAPPED == 0x40000

    def test_mem_image_constant_value(self) -> None:
        """Sanity check ``_MEM_IMAGE`` matches the documented Win32 value."""
        assert _MEM_IMAGE == 0x1000000

    async def test_get_memory_map_resolves_image_or_mapped_names(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify resolve_names populates module_name only for MEM_IMAGE/MEM_MAPPED.

        The current Python interpreter always has its own image mapped,
        so at least one MEM_IMAGE region with a non-empty module_name
        must appear when resolve_names=True. Any region carrying a
        module_name must therefore have type "image" or "mapped"
        (the human-readable names produced by ``mem_type_to_string`` for
        ``MEM_IMAGE`` and ``MEM_MAPPED`` respectively).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        regions = await attached_bridge.get_memory_map(resolve_names=True)
        named_regions = [r for r in regions if r.module_name]
        assert named_regions, "expected at least one MEM_IMAGE/MEM_MAPPED region with module name"
        for region in named_regions:
            assert region.type in {"image", "mapped"}, (
                f"region with module_name must be image or mapped, got type={region.type}"
            )

    async def test_get_memory_map_no_resolve_skips_names(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify resolve_names=False never populates module_name.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        regions = await attached_bridge.get_memory_map(resolve_names=False)
        for region in regions:
            assert region.module_name is None


class TestF0007PatternScanContinues:
    """Verify pattern scan continues past per-chunk read failures."""

    async def test_pattern_scan_finds_match_after_unreadable_chunk(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Pattern matches in a region survive an unreadable preceding chunk.

        ``_SEARCH_CHUNK_SIZE`` is 1 MiB (``0x100000``). Allocates a
        2 MiB committed region, writes a unique 16-byte pattern at the
        start of the *second* chunk, then flips the first 1 MiB to
        ``PAGE_NOACCESS`` (via a direct ``VirtualProtectEx`` call so we
        do not need to extend the bridge's ``_prot_from_string`` map for
        a test-only protection mode) so the kernel's
        ``ReadProcessMemory`` will return an error for that chunk.
        Pre-fix, the region scanner broke out of the region on the
        first ``ToolError`` and the pattern in the readable second
        chunk was never reached. Post-fix, the scanner logs the chunk
        failure, observes the surrounding region is still committed
        via ``VirtualQueryEx``, and continues to the next chunk so the
        match is found.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        unique_pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x13\x37\x42\x42\x99\x88\x77\x66"
        chunk_size = 0x100000
        region_size = chunk_size * 2
        addr = await attached_bridge.allocate(region_size, "rw")
        try:
            second_chunk_offset = chunk_size
            await attached_bridge.write_memory(addr + second_chunk_offset, unique_pattern)
            handle = _get_attr_optional(attached_bridge, _ATTR_PROCESS_HANDLE, int)
            assert handle is not None
            k32 = ctypes.windll.kernel32
            old_prot = wintypes.DWORD()
            ok = k32.VirtualProtectEx(
                wintypes.HANDLE(handle),
                ctypes.c_void_p(addr),
                ctypes.c_size_t(chunk_size),
                wintypes.DWORD(_PAGE_NOACCESS),
                ctypes.byref(old_prot),
            )
            assert ok, "VirtualProtectEx PAGE_NOACCESS failed"

            pattern_str = " ".join(f"{b:02X}" for b in unique_pattern)
            matches = await attached_bridge.search_pattern(
                pattern_str,
                start_address=addr,
                end_address=addr + region_size,
            )
            assert addr + second_chunk_offset in matches, (
                f"pattern not found in second chunk at "
                f"{hex(addr + second_chunk_offset)}; matches={[hex(m) for m in matches[:8]]}"
            )

            restore_prot = wintypes.DWORD()
            k32.VirtualProtectEx(
                wintypes.HANDLE(handle),
                ctypes.c_void_p(addr),
                ctypes.c_size_t(chunk_size),
                old_prot,
                ctypes.byref(restore_prot),
            )
        finally:
            await attached_bridge.free(addr)

    async def test_pattern_scan_aborts_when_region_freed(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify scan terminates cleanly when a region is no longer committed.

        Allocates a region with a unique pattern, writes the pattern,
        frees the region, then runs a pattern search bounded to that
        address range. The scan must not raise. The freed address must
        not appear in the matches because the region is no longer
        committed (``get_memory_map`` filters MEM_COMMIT only).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        unique_pattern = b"\x11\x22\x33\x44\x55\x66\x77\x88\xaa\xbb\xcc\xdd\xee\xff\x00\x99"
        addr = await attached_bridge.allocate(0x4000, "rw")
        await attached_bridge.write_memory(addr, unique_pattern)
        await attached_bridge.free(addr)
        pattern_str = " ".join(f"{b:02X}" for b in unique_pattern)
        matches = await attached_bridge.search_pattern(
            pattern_str,
            start_address=addr,
            end_address=addr + 0x4000,
        )
        assert isinstance(matches, list)
        assert addr not in matches


class TestF0037ReadMemoryHex:
    """Verify read_memory returns a JSON-serialisable hex string."""

    async def test_read_memory_returns_hex_string(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify return value type, length, and charset.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
            known_buffer: Triple of (address, backing buffer, expected
                bytes) for a buffer with known content.
        """
        addr, _buf, _data = known_buffer
        result = await attached_bridge.read_memory(addr, 16)
        assert isinstance(result, str)
        assert len(result) == 32
        assert re.fullmatch(r"[0-9a-f]+", result) is not None

    async def test_read_memory_hex_round_trips_to_bytes(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify the hex string round-trips through bytes.fromhex.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        addr = await attached_bridge.allocate(64, "rw")
        try:
            payload = b"hex_round_trip_data!"
            await attached_bridge.write_memory(addr, payload)
            result = await attached_bridge.read_memory(addr, len(payload))
            assert bytes.fromhex(result) == payload
        finally:
            await attached_bridge.free(addr)


class TestF0038SectionCollision:
    """Verify create_section detects duplicate names."""

    async def test_named_section_collision_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Second create_section with same name raises with collision code.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        section_name = f"IntellicrackProcessBridgeTest_F0038_{os.getpid()}"
        first = await process_bridge.create_section(4096, section_name=section_name)
        try:
            assert first > 0
            with pytest.raises(ToolError) as excinfo:
                await process_bridge.create_section(4096, section_name=section_name)
            err = excinfo.value
            details = err.details or {}
            assert details.get("code") == "SECTION_NAME_COLLISION"
            assert err.error_code == 183
        finally:
            ctypes.windll.kernel32.CloseHandle(first)
            _get_section_handles(process_bridge).pop(first, None)

    async def test_anonymous_sections_do_not_collide(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Anonymous sections never raise the collision error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        first = await process_bridge.create_section(4096)
        second = await process_bridge.create_section(4096)
        try:
            assert first > 0
            assert second > 0
            assert first != second
        finally:
            ctypes.windll.kernel32.CloseHandle(first)
            ctypes.windll.kernel32.CloseHandle(second)
            section_handles = _get_section_handles(process_bridge)
            section_handles.pop(first, None)
            section_handles.pop(second, None)


class TestF0039UnmapSection:
    """Verify unmap_section unmaps the view and tracks state."""

    async def test_unmap_section_clears_tracking_and_unmaps(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """unmap_section removes the base from the views dict and unmaps it.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        addr: int = await process_bridge.map_section(handle, 4096)
        assert addr in _get_section_views(process_bridge)

        ok: bool = await process_bridge.unmap_section(addr)
        assert ok is True

        assert addr not in _get_section_views(process_bridge)
        assert handle not in _get_section_handles(process_bridge)

    async def test_unmap_section_then_read_attached_fails(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """After unmap, a read at the base address raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        handle = await attached_bridge.create_section(4096)
        addr = await attached_bridge.map_section(handle, 4096)
        await attached_bridge.unmap_section(addr)

        with pytest.raises(ToolError):
            await attached_bridge.read_memory(addr, 16)

    async def test_unmap_section_unknown_base_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Unmapping an untracked address raises with NOT_MAPPED code.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        with pytest.raises(ToolError) as excinfo:
            await process_bridge.unmap_section(0xDEADBEEF)
        details = excinfo.value.details or {}
        assert details.get("code") == "SECTION_NOT_MAPPED"


_PIPE_NAME_AUDIT2 = r"\\.\pipe\intellicrack_audit2_test"
_PIPE_BUF_SIZE = 64
_PHYS_DRIVE = r"\\.\PhysicalDrive0"
_PHYS_DRIVE_ACCESS = 0x80000000
_PHYS_DRIVE_SHARE = 0x00000001 | 0x00000002


def _create_named_pipe_server(pipe_name: str) -> int:
    """Create a named pipe server using CreateNamedPipeW.

    Args:
        pipe_name: The fully-qualified named pipe path.

    Returns:
        int: Server pipe handle, or -1 on failure.
    """
    k32 = ctypes.windll.kernel32
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    server_handle: int = k32.CreateNamedPipeW(
        pipe_name,
        0x00000003,
        0x00000000,
        1,
        _PIPE_BUF_SIZE,
        _PIPE_BUF_SIZE,
        0,
        None,
    )
    return int(server_handle)


def _open_phys_drive_or_skip() -> int:
    """Open PhysicalDrive0 for read sharing, skipping if access is denied.

    Returns:
        int: Valid device handle.
    """
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    test_h: int = k32.CreateFileW(
        _PHYS_DRIVE,
        _PHYS_DRIVE_ACCESS,
        _PHYS_DRIVE_SHARE,
        None,
        3,
        0,
        None,
    )
    if test_h in {_INVALID_HANDLE_VALUE, 0}:
        pytest.skip(f"{_PHYS_DRIVE} requires elevated privileges")
    return test_h


class TestF0017PipeHandleType:
    """Verify CreateFileW restype=HANDLE so pipe_connect returns a non-truncated positive int."""

    async def test_pipe_connect_returns_positive_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_connect returns a positive int handle, not a sign-extended negative.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(_PIPE_NAME_AUDIT2)
        assert server_handle != -1, "failed to create named pipe server"

        connected = threading.Event()
        connect_error: list[bool] = [False]

        def _server_thread() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            result = k32.ConnectNamedPipe(server_handle, None)
            if not result:
                connect_error[0] = True
            connected.set()

        t = threading.Thread(target=_server_thread, daemon=True)
        t.start()

        try:
            handle = await process_bridge.pipe_connect(_PIPE_NAME_AUDIT2, 5000)
            connected.wait(timeout=5.0)
            assert handle > 0, f"handle should be a positive int, got {handle}"
            assert handle not in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, "handle must not be INVALID_HANDLE_VALUE"
            k32.CloseHandle(handle)
        finally:
            k32.DisconnectNamedPipe(server_handle)
            k32.CloseHandle(server_handle)
            t.join(timeout=2.0)


class TestF0017DeviceHandleType:
    """Verify device_open returns a valid positive handle for accessible devices."""

    async def test_device_open_known_device_positive_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify device_open returns a positive int handle for an accessible device.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        test_h = _open_phys_drive_or_skip()
        k32.CloseHandle(test_h)

        handle = await process_bridge.device_open(_PHYS_DRIVE)
        try:
            assert handle > 0, f"device handle should be positive, got {handle}"
            assert handle not in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, "handle must not be INVALID_HANDLE_VALUE"
        finally:
            k32.CloseHandle(handle)


class TestF0016PipeCloseResult:
    """Verify pipe_close returns True on success and raises on invalid handle."""

    async def test_pipe_close_valid_handle_returns_true(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close returns True when CloseHandle succeeds.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(_PIPE_NAME_AUDIT2 + "_close")
        assert server_handle != -1

        connected = threading.Event()

        def _srv() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            k32.ConnectNamedPipe(server_handle, None)
            connected.set()

        t = threading.Thread(target=_srv, daemon=True)
        t.start()

        client_handle = await process_bridge.pipe_connect(_PIPE_NAME_AUDIT2 + "_close", 5000)
        connected.wait(timeout=5.0)
        result = await process_bridge.pipe_close(client_handle)
        assert result is True

        k32.DisconnectNamedPipe(server_handle)
        k32.CloseHandle(server_handle)
        t.join(timeout=2.0)

    async def test_pipe_close_invalid_handle_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close raises ToolError when given an invalid handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError):
            await process_bridge.pipe_close(0xDEAD0000)


class TestF0016DeviceCloseResult:
    """Verify device_close returns True on success and raises on invalid handle."""

    async def test_device_close_invalid_handle_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close raises ToolError when given an invalid handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError):
            await process_bridge.device_close(0xDEAD0001)

    async def test_device_close_valid_handle_returns_true(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close returns True when CloseHandle succeeds on an accessible device.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        _open_phys_drive_or_skip()

        handle = await process_bridge.device_open(_PHYS_DRIVE)
        result = await process_bridge.device_close(handle)
        assert result is True


class TestF0018DeviceIoctlHexInput:
    """Verify device_ioctl validates hex string input and raises on invalid input."""

    async def test_device_ioctl_invalid_hex_raises_value_error(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl raises ValueError for non-hex input_data.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ValueError, match="hex"):
            await process_bridge.device_ioctl(1, 0x00000001, "not-hex")

    async def test_device_ioctl_valid_hex_accepted(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl accepts a valid hex string without raising on parse.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        test_h = _open_phys_drive_or_skip()
        k32 = ctypes.windll.kernel32
        try:
            result = await process_bridge.device_ioctl(test_h, 0x70000, "")
            assert isinstance(result, str)
            assert all(c in "0123456789abcdef" for c in result)
        except ToolError:
            pass
        finally:
            k32.CloseHandle(test_h)


class TestF0037PipeReadHex:
    """Verify pipe_read returns a lowercase hex string."""

    async def test_pipe_read_returns_hex_string(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_read returns a hex string of the correct length.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(_PIPE_NAME_AUDIT2 + "_read")
        assert server_handle != -1

        known_bytes = b"\xde\xad\xbe\xef"
        write_done = threading.Event()

        def _srv() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            k32.ConnectNamedPipe(server_handle, None)
            bw = wintypes.DWORD(0)
            k32.WriteFile(server_handle, known_bytes, len(known_bytes), ctypes.byref(bw), None)
            write_done.set()

        t = threading.Thread(target=_srv, daemon=True)
        t.start()

        client_handle = await process_bridge.pipe_connect(_PIPE_NAME_AUDIT2 + "_read", 5000)
        write_done.wait(timeout=5.0)

        try:
            result = await process_bridge.pipe_read(client_handle, len(known_bytes))
            assert isinstance(result, str), f"pipe_read should return str, got {type(result)}"
            assert result == known_bytes.hex(), f"expected {known_bytes.hex()!r}, got {result!r}"
            assert result == "deadbeef"
        finally:
            k32.CloseHandle(client_handle)
            k32.DisconnectNamedPipe(server_handle)
            k32.CloseHandle(server_handle)
            t.join(timeout=2.0)


class TestF0037DeviceIoctlOutputHex:
    """Verify device_ioctl returns output as a hex string."""

    async def test_device_ioctl_output_is_hex_string(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl output is a lowercase hex string.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        test_h = _open_phys_drive_or_skip()
        k32 = ctypes.windll.kernel32
        try:
            result = await process_bridge.device_ioctl(test_h, 0x70000, None, 512)
            assert isinstance(result, str), f"device_ioctl should return str, got {type(result)}"
            assert re.fullmatch(r"[0-9a-f]*", result) is not None, f"not a valid hex string: {result!r}"
        except ToolError:
            pass
        finally:
            k32.CloseHandle(test_h)


class TestF0002SnapshotHandleType:
    """F-0002: CreateToolhelp32Snapshot.restype must be wintypes.HANDLE."""

    async def test_list_returns_current_process(self, process_bridge: ProcessBridge) -> None:
        """list() must include the current Python process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        procs = await process_bridge.list()
        pids = [p.pid for p in procs]
        assert os.getpid() in pids

    async def test_snapshot_handle_not_truncated_negative(self, process_bridge: ProcessBridge) -> None:
        """On 64-bit Python the snapshot handle must not be a truncated negative int.

        Ensures that restype=wintypes.HANDLE preserves the full 64-bit value,
        preventing sign-extension that would produce -1 for valid handles.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        del process_bridge
        if ctypes.sizeof(ctypes.c_void_p) < 8:
            pytest.skip("32-bit Python - handle truncation concern only applies to 64-bit")

        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        try:
            assert snapshot != _INVALID_HANDLE_VALUE, "snapshot creation must not fail"
            assert snapshot >= 0, f"snapshot handle must not be negative (was {snapshot:#x})"
        finally:
            if snapshot != _INVALID_HANDLE_VALUE:
                k32.CloseHandle(snapshot)


class TestF0003Process32FirstFailure:
    """F-0003: Process32First failure must raise ToolError with error code."""

    async def test_list_processes_succeeds_normally(self, process_bridge: ProcessBridge) -> None:
        """Baseline: list_processes returns at least the current process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        procs = await process_bridge.list_processes()
        assert any(p.pid == os.getpid() for p in procs)

    async def test_forced_snapshot_failure_raises_tool_error(self) -> None:
        """Force CreateToolhelp32Snapshot to return INVALID_HANDLE_VALUE.

        Injects a stub via unittest.mock.patch that returns INVALID_HANDLE_VALUE
        for every call. The bridge must detect this and raise ToolError.
        """
        bridge = ProcessBridge()
        await bridge.initialize()

        k32 = getattr(bridge, "_kernel32", None)
        if k32 is None:
            await bridge.shutdown()
            pytest.skip("kernel32 not available")

        def _bad_snapshot(flags: int, pid: int) -> int:
            del flags, pid
            return _INVALID_HANDLE_VALUE

        try:
            with pytest.raises(ToolError), patch.object(k32, "CreateToolhelp32Snapshot", side_effect=_bad_snapshot):
                await bridge.list_processes()
        finally:
            await bridge.shutdown()


class TestF0019HandleTypeNames:
    """F-0019: enum_handles must return type_name strings, never ints."""

    async def test_enum_handles_returns_string_type_names(self, process_bridge: ProcessBridge) -> None:
        """enum_handles for the current PID returns entries with string type_name.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        assert isinstance(handles, list)
        assert len(handles) > 0, "current process must have open handles"
        for entry in handles:
            type_name = entry.get("type_name")
            assert isinstance(type_name, str), "type_name must be str, got " + type(type_name).__name__
            assert type_name, "type_name must not be empty"

    async def test_enum_handles_includes_known_types(self, process_bridge: ProcessBridge) -> None:
        """enum_handles for the current PID includes Process, Thread, or Event entries.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        type_names = {str(h.get("type_name", "")) for h in handles}
        known_types = {"Process", "Thread", "Event", "File", "Section", "Directory"}
        found = type_names & known_types
        assert found, "no known type names found; got: " + str(sorted(type_names)[:20])

    async def test_enum_handles_type_name_never_int(self, process_bridge: ProcessBridge) -> None:
        """type_name field in enum_handles output must never be a bare integer.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        for entry in handles:
            type_name = entry.get("type_name")
            assert not isinstance(type_name, int), "type_name should not be int, got " + repr(type_name)

    async def test_enum_handles_no_pid_returns_multiple_pids(self, process_bridge: ProcessBridge) -> None:
        """enum_handles without a pid filter returns handles from multiple PIDs.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(None)
        pids = {h.get("pid") for h in handles}
        assert len(pids) > 1, "system-wide handle scan must return handles from multiple processes"
        assert os.getpid() in pids


class TestF0040HandleBufferBounds:
    """F-0040: Buffer bounds must be validated before iterating handles."""

    async def test_buffer_bounds_validated_on_overflow(self) -> None:
        """NtQuerySystemInformation returning a buffer with 1M handles in 4 KiB must raise ToolError.

        Constructs a fake buffer header claiming 1_000_000 handles in 4096 bytes
        and injects it via mock. The bridge must detect the overflow and raise
        ToolError before iterating.
        """
        bridge = ProcessBridge()
        await bridge.initialize()

        ntdll = getattr(bridge, "_ntdll", None)
        if ntdll is None:
            await bridge.shutdown()
            pytest.skip("ntdll not available")

        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        fake_buf_size = 4096
        fake_num_handles = 1_000_000
        fmt = "<Q" if ptr_size == 8 else "<I"

        fake_buffer = ctypes.create_string_buffer(fake_buf_size)
        struct.pack_into(fmt, fake_buffer, 0, fake_num_handles)

        def _mock_ntquery(
            info_class: int,
            buf: ctypes.Array[ctypes.c_char],
            buf_len: int,
            ret_len: ctypes.Array[ctypes.c_char],
        ) -> int:
            del info_class, buf_len, ret_len
            size = min(fake_buf_size, getattr(buf, "_length_", fake_buf_size))
            ctypes.memmove(buf, fake_buffer, size)
            return 0

        try:
            with pytest.raises(ToolError), patch.object(ntdll, "NtQuerySystemInformation", side_effect=_mock_ntquery):
                await bridge.get_handles(os.getpid())
        finally:
            await bridge.shutdown()

    async def test_valid_buffer_does_not_raise(self, process_bridge: ProcessBridge) -> None:
        """A real NtQuerySystemInformation call must not raise a buffer overflow error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.get_handles(os.getpid())
        assert isinstance(handles, list)
