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
import struct
import sys
import threading
import time
from typing import TYPE_CHECKING, TypeVar, cast

import pytest
import pytest_asyncio

from intellicrack.bridges._win32_types import (
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_READONLY,
    PAGE_READWRITE,
)
from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_T = TypeVar("_T")

_ATTR_KERNEL32 = "_kernel32"
_ATTR_NTDLL = "_ntdll"
_ATTR_ADVAPI32 = "_advapi32"
_ATTR_DEBUG_PRIV = "_debug_privilege_enabled"
_ATTR_PROCESS_HANDLE = "_process_handle"
_ATTR_ATTACHED_PID = "_attached_pid"
_ATTR_PROT_FROM_STRING = "_prot_from_string"
_ATTR_PARSE_REGISTRY_PATH = "_parse_registry_path"


def _get_attr_optional(bridge: ProcessBridge, name: str, expected: type[_T]) -> _T | None:
    """Return a protected optional attribute from bridge, narrowed to expected type.

    Used to bypass reportPrivateUsage when tests need to inspect internal
    state without weakening the bridge's public API boundary.

    Args:
        bridge: The ProcessBridge instance to read from.
        name: Attribute name (must be a literal constant declared in this module).
        expected: Expected runtime type of the non-None value.

    Returns:
        _T | None: The attribute value typed as ``expected | None``.

    Raises:
        TypeError: If the attribute is neither None nor an instance of expected.
    """
    value: object = getattr(bridge, name)
    if value is None:
        return None
    if not isinstance(value, expected):
        raise TypeError(
            f"ProcessBridge.{name} expected {expected.__name__} or None, got {type(value).__name__}",
        )
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
        raise TypeError(
            f"ProcessBridge.{_ATTR_DEBUG_PRIV} expected bool, got {type(flag).__name__}",
        )
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
        raise TypeError(f"ProcessBridge.{_ATTR_PROT_FROM_STRING} is not callable")
    result: object = fn(protection)
    if not isinstance(result, int):
        raise TypeError(
            f"ProcessBridge.{_ATTR_PROT_FROM_STRING} expected int return, got {type(result).__name__}",
        )
    return result


def _invoke_parse_registry_path(key_path: str) -> tuple[int, str]:
    """Invoke ProcessBridge._parse_registry_path via getattr, bypassing reportPrivateUsage.

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
        raise TypeError(f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} is not callable")
    result: object = fn(key_path)
    if not isinstance(result, tuple):
        raise TypeError(
            f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got {type(result).__name__}",
        )
    typed_result = cast("tuple[object, ...]", result)
    if len(typed_result) != 2:
        raise TypeError(
            f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got tuple of length {len(typed_result)}",
        )
    root_obj: object = typed_result[0]
    sub_obj: object = typed_result[1]
    if not isinstance(root_obj, int) or not isinstance(sub_obj, str):
        raise TypeError(
            f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected (int, str), got ({type(root_obj).__name__}, {type(sub_obj).__name__})",
        )
    return root_obj, sub_obj


def _configure_kernel32_signatures(k32: ctypes.WinDLL) -> None:
    """Set correct 64-bit return/argument types on kernel32 functions.

    Args:
        k32: Loaded kernel32 DLL handle.
    """
    from ctypes import wintypes

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
        assert process_bridge._kernel32 is not None

    async def test_initialize_loads_ntdll(self, process_bridge: ProcessBridge) -> None:
        """Verify ntdll is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge._ntdll is not None

    async def test_initialize_loads_advapi32(self, process_bridge: ProcessBridge) -> None:
        """Verify advapi32 is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge._advapi32 is not None

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
        assert isinstance(process_bridge._debug_privilege_enabled, bool)

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
        """Verify architecture detection returns x64 on 64-bit Python.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        arch = await process_bridge.detect_architecture(os.getpid())
        expected = "x64" if struct.calcsize("P") * 8 == 64 else "x86"
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
        assert result[: len(data)] == data

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
            assert readback == test_data
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
        """Verify enumerating HKLM\\SOFTWARE\\Microsoft returns non-empty list.

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

    async def test_map_section_returns_address(self, process_bridge: ProcessBridge) -> None:
        """Verify mapping a section returns a positive address.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
        handle = await process_bridge.create_section(4096)
        try:
            addr = await process_bridge.map_section(handle, 4096)
            try:
                assert addr > 0
            finally:
                k32.UnmapViewOfFile(addr)
        finally:
            k32.CloseHandle(handle)


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
        assert _invoke_prot_from_string("rwx") == PAGE_EXECUTE_READWRITE

    def test_prot_from_string_rw(self) -> None:
        """Verify 'rw' maps to PAGE_READWRITE."""
        assert _invoke_prot_from_string("rw") == PAGE_READWRITE

    def test_prot_from_string_rx(self) -> None:
        """Verify 'rx' maps to PAGE_EXECUTE_READ."""
        assert _invoke_prot_from_string("rx") == PAGE_EXECUTE_READ

    def test_prot_from_string_r(self) -> None:
        """Verify 'r' maps to PAGE_READONLY."""
        assert _invoke_prot_from_string("r") == PAGE_READONLY

    def test_prot_from_string_x(self) -> None:
        """Verify 'x' maps to PAGE_EXECUTE."""
        assert _invoke_prot_from_string("x") == PAGE_EXECUTE

    def test_prot_from_string_unknown_defaults(self) -> None:
        """Verify unknown string defaults to PAGE_EXECUTE_READWRITE."""
        assert _invoke_prot_from_string("???") == PAGE_EXECUTE_READWRITE

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
