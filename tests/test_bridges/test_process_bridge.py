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
from typing import TYPE_CHECKING

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
    """Create, initialize, and shutdown a ProcessBridge for the module."""
    bridge = ProcessBridge()
    await bridge.initialize()
    if bridge._kernel32 is not None:
        _configure_kernel32_signatures(bridge._kernel32)
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process."""
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


@pytest_asyncio.fixture
async def main_thread_tid(attached_bridge: ProcessBridge) -> int:
    """Get the TID of the first thread in the current process."""
    threads = await attached_bridge.get_threads(os.getpid())
    return threads[0].tid


@pytest.fixture
def known_buffer() -> tuple[int, ctypes.Array[ctypes.c_char], bytes]:
    """Create a buffer with known content for memory read tests."""
    data = b"INTELLICRACK_BRIDGE_TEST_7890ABCDEF"
    buf = ctypes.create_string_buffer(data)
    return ctypes.addressof(buf), buf, data


@pytest.fixture
def secondary_thread() -> Generator[int]:
    """Spawn a blocking thread and yield its Windows TID for context tests."""
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
        """Verify kernel32 is loaded after initialization."""
        assert process_bridge._kernel32 is not None

    async def test_initialize_loads_ntdll(self, process_bridge: ProcessBridge) -> None:
        """Verify ntdll is loaded after initialization."""
        assert process_bridge._ntdll is not None

    async def test_initialize_loads_advapi32(self, process_bridge: ProcessBridge) -> None:
        """Verify advapi32 is loaded after initialization."""
        assert process_bridge._advapi32 is not None

    async def test_initialize_sets_connected(self, process_bridge: ProcessBridge) -> None:
        """Verify state shows connected and tool_running after init."""
        assert process_bridge.state.connected is True
        assert process_bridge.state.tool_running is True

    async def test_initialize_debug_privilege_flag(self, process_bridge: ProcessBridge) -> None:
        """Verify debug privilege flag is a boolean."""
        assert isinstance(process_bridge._debug_privilege_enabled, bool)

    async def test_name_is_process(self, process_bridge: ProcessBridge) -> None:
        """Verify bridge name is ToolName.PROCESS."""
        assert process_bridge.name == ToolName.PROCESS

    async def test_is_available(self, process_bridge: ProcessBridge) -> None:
        """Verify is_available returns True on Windows."""
        assert await process_bridge.is_available() is True

    async def test_tool_definition_count(self, process_bridge: ProcessBridge) -> None:
        """Verify tool definition has 53 functions."""
        assert len(process_bridge.tool_definition.functions) == 53


class TestProcessListing:
    """Verify process listing and filtering."""

    async def test_list_processes_non_empty(self, process_bridge: ProcessBridge) -> None:
        """Verify process list is non-empty."""
        procs = await process_bridge.list_processes()
        assert len(procs) > 0

    async def test_list_processes_includes_self(self, process_bridge: ProcessBridge) -> None:
        """Verify process list contains current PID."""
        procs = await process_bridge.list_processes()
        assert any(p.pid == os.getpid() for p in procs)

    async def test_list_processes_has_python_name(self, process_bridge: ProcessBridge) -> None:
        """Verify our process entry name contains 'python'."""
        procs = await process_bridge.list_processes()
        self_proc = next((p for p in procs if p.pid == os.getpid()), None)
        assert self_proc is not None
        assert "python" in self_proc.name.lower()

    async def test_list_processes_filter(self, process_bridge: ProcessBridge) -> None:
        """Verify name filter returns at least one python process."""
        procs = await process_bridge.list_processes(filter_name="python")
        assert len(procs) >= 1

    async def test_list_processes_detailed_has_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify detailed listing includes expected keys."""
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        assert len(procs) >= 1
        entry = procs[0]
        for key in ("pid", "name", "architecture", "memory_mb", "thread_count"):
            assert key in entry

    async def test_list_processes_detailed_self_arch(self, process_bridge: ProcessBridge) -> None:
        """Verify our process architecture is x64 or x86."""
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None
        assert self_proc["architecture"] in {"x64", "x86"}

    async def test_list_processes_detailed_self_memory(self, process_bridge: ProcessBridge) -> None:
        """Verify our process has positive memory usage."""
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None
        assert self_proc["memory_mb"] > 0

    async def test_detect_architecture_self(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns x64 on 64-bit Python."""
        arch = await process_bridge.detect_architecture(os.getpid())
        expected = "x64" if struct.calcsize("P") * 8 == 64 else "x86"
        assert arch == expected

    async def test_detect_architecture_invalid_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns Unknown for invalid PID."""
        arch = await process_bridge.detect_architecture(99999999)
        assert arch == "Unknown"


class TestProcessOpenClose:
    """Verify process open/close lifecycle."""

    async def test_open_process_query(self, process_bridge: ProcessBridge) -> None:
        """Verify opening own process succeeds."""
        result = await process_bridge.open_process(os.getpid(), "query")
        assert result is True
        assert process_bridge._process_handle is not None
        await process_bridge.close()

    async def test_close_resets_state(self, process_bridge: ProcessBridge) -> None:
        """Verify close resets handle, pid, and state."""
        await process_bridge.open_process(os.getpid(), "all")
        await process_bridge.close()
        assert process_bridge._process_handle is None
        assert process_bridge._attached_pid is None
        assert process_bridge.state.process_attached is False

    async def test_open_invalid_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify opening an invalid PID raises ToolError."""
        with pytest.raises(ToolError, match="process open failed"):
            await process_bridge.open_process(99999999, "all")

    async def test_get_process_memory_mb_self(self, process_bridge: ProcessBridge) -> None:
        """Verify memory query returns positive value for self."""
        mem = await process_bridge.get_process_memory_mb(os.getpid())
        assert mem > 0


class TestMemoryOperations:
    """Verify memory read, write, allocate, free, protect, search, and map."""

    async def test_read_memory_known_buffer(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify reading from a known buffer returns expected data."""
        addr, _buf, data = known_buffer
        result = await attached_bridge.read_memory(addr, len(data))
        assert result[: len(data)] == data

    async def test_read_memory_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading without attachment raises ToolError."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_read_roundtrip(self, attached_bridge: ProcessBridge) -> None:
        """Verify allocate-write-read-free roundtrip works."""
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
        """Verify allocate returns non-zero address and free succeeds."""
        addr = await attached_bridge.allocate(4096, "rw")
        assert addr != 0
        result = await attached_bridge.free(addr)
        assert result is True

    async def test_protect_returns_old_protection(self, attached_bridge: ProcessBridge) -> None:
        """Verify protect returns the previous protection string."""
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
        """Verify pattern search finds known bytes in memory."""
        addr, _buf, data = known_buffer
        pattern = " ".join(f"{b:02X}" for b in data[:8])
        results = await attached_bridge.search_pattern(
            pattern, start_address=addr - 0x10000, end_address=addr + 0x10000
        )
        assert addr in results

    async def test_get_memory_map_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify memory map returns non-empty list with required fields."""
        regions = await attached_bridge.get_memory_map()
        assert len(regions) > 0
        region = regions[0]
        assert hasattr(region, "base_address")
        assert hasattr(region, "size")
        assert hasattr(region, "protection")


class TestThreadEnumeration:
    """Verify thread listing and bug-fix fields (start_address, state)."""

    async def test_get_threads_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify thread list is non-empty."""
        threads = await attached_bridge.get_threads(os.getpid())
        assert len(threads) > 0

    async def test_get_threads_have_tid(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have positive TIDs."""
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.tid > 0 for t in threads)

    async def test_get_threads_start_address_nonzero(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a non-zero start address (bug fix)."""
        threads = await attached_bridge.get_threads(os.getpid())
        assert any(t.start_address != 0 for t in threads)

    async def test_get_threads_state_not_unknown(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a known state (bug fix)."""
        threads = await attached_bridge.get_threads(os.getpid())
        valid_states = {"running", "suspended", "terminated", "waiting"}
        assert any(t.state in valid_states for t in threads)

    async def test_get_threads_have_priority(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have non-negative priority."""
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.priority >= 0 for t in threads)


class TestModuleListing:
    """Verify module enumeration."""

    async def test_get_modules_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify module list is non-empty."""
        modules = await attached_bridge.get_modules(os.getpid())
        assert len(modules) > 0

    async def test_get_modules_includes_python(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one module name contains 'python'."""
        modules = await attached_bridge.get_modules(os.getpid())
        assert any("python" in m.name.lower() for m in modules)

    async def test_get_modules_have_base_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify all modules have positive base addresses."""
        modules = await attached_bridge.get_modules(os.getpid())
        assert all(m.base_address > 0 for m in modules)

    async def test_get_modules_no_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no process is attached."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()


class TestProcessInfo:
    """Verify process info aggregation."""

    async def test_get_process_info_self(self, attached_bridge: ProcessBridge) -> None:
        """Verify process info is populated for self."""
        info = await attached_bridge.get_process_info(os.getpid())
        assert info is not None
        assert len(info.threads) > 0
        assert len(info.modules) > 0

    async def test_get_process_info_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify process info returns None when no process is attached."""
        await process_bridge.close()
        info = await process_bridge.get_process_info()
        assert info is None


class TestTokenPrivileges:
    """Verify token privilege enumeration and adjustment."""

    async def test_get_token_privileges_has_entries(self, attached_bridge: ProcessBridge) -> None:
        """Verify token privileges list is non-empty."""
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert len(privs) > 0

    async def test_get_token_privileges_has_sechangenotify(
        self, attached_bridge: ProcessBridge
    ) -> None:
        """Verify SeChangeNotifyPrivilege is present."""
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert any("SeChangeNotifyPrivilege" in str(p.get("name", "")) for p in privs)

    async def test_get_token_privileges_entry_keys(self, attached_bridge: ProcessBridge) -> None:
        """Verify each privilege entry has required keys."""
        privs = await attached_bridge.get_token_privileges(os.getpid())
        for priv in privs:
            for key in ("name", "luid_low", "luid_high", "enabled", "attributes"):
                assert key in priv

    async def test_adjust_token_privilege_invalid_raises(
        self, attached_bridge: ProcessBridge
    ) -> None:
        """Verify adjusting a fake privilege raises ToolError."""
        with pytest.raises(ToolError, match="privilege lookup failed"):
            await attached_bridge.adjust_token_privilege(
                "SeCompletelyFakePrivilege", enable=True, pid=os.getpid()
            )


class TestHandleEnumeration:
    """Verify handle enumeration via NtQuerySystemInformation."""

    async def test_get_handles_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify handle enumeration returns a list without error."""
        handles = await process_bridge.get_handles(os.getpid())
        assert isinstance(handles, list)

    async def test_get_handles_have_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify each handle entry has required fields when available."""
        handles = await process_bridge.get_handles(os.getpid())
        for handle in handles[:5]:
            assert "handle_value" in handle
            assert "type_index" in handle


class TestWindowEnumeration:
    """Verify window enumeration doesn't crash."""

    async def test_get_windows_no_crash(self, attached_bridge: ProcessBridge) -> None:
        """Verify get_windows returns a list without crashing."""
        windows = await attached_bridge.get_windows(os.getpid())
        assert isinstance(windows, list)


class TestServiceListing:
    """Verify service enumeration."""

    async def test_list_services_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify service listing returns a list without error."""
        services = await process_bridge.list_services()
        assert isinstance(services, list)

    async def test_list_services_have_name_state(self, process_bridge: ProcessBridge) -> None:
        """Verify each service has name and state when available."""
        services = await process_bridge.list_services()
        for svc in services[:5]:
            assert "name" in svc
            assert "state" in svc


class TestPebTebAccess:
    """Verify PEB and TEB reads."""

    async def test_read_peb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB read returns a positive peb_address."""
        peb = await attached_bridge.read_peb()
        assert peb["peb_address"] > 0

    async def test_read_peb_has_image_base(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB contains positive image_base_address."""
        peb = await attached_bridge.read_peb()
        assert peb["image_base_address"] > 0

    async def test_read_teb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify TEB read returns a positive teb_address."""
        threads = await attached_bridge.get_threads(os.getpid())
        tid = threads[0].tid
        teb = await attached_bridge.read_teb(tid)
        assert teb["teb_address"] > 0

    async def test_read_teb_stack_range(self, attached_bridge: ProcessBridge) -> None:
        """Verify stack_base > 0 and stack_limit < stack_base (downward growth)."""
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
        """Verify heap list is non-empty."""
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert len(heaps) > 0

    async def test_get_heaps_has_default(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one heap is the default."""
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert any(h.get("is_default") is True for h in heaps)


class TestThreadContext:
    """Verify thread context read using a secondary thread to avoid deadlock."""

    async def test_get_thread_context_has_registers(
        self, attached_bridge: ProcessBridge, secondary_thread: int
    ) -> None:
        """Verify context has rip and rsp on 64-bit, or eip/esp on 32-bit."""
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
        """Verify invalid TID raises ToolError."""
        with pytest.raises(ToolError):
            await attached_bridge.get_thread_context(0)


class TestMitigationPolicies:
    """Verify mitigation policy queries."""

    async def test_mitigation_policies_has_dep(self, attached_bridge: ProcessBridge) -> None:
        """Verify result has 'DEP' key."""
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        assert "DEP" in policies

    async def test_mitigation_policies_dep_structure(self, attached_bridge: ProcessBridge) -> None:
        """Verify DEP value is dict with 'enabled' and 'flags'."""
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        dep = policies["DEP"]
        assert isinstance(dep, dict)
        assert "enabled" in dep
        assert "flags" in dep


class TestEnvironmentVariables:
    """Verify environment variable reading from PEB."""

    async def test_get_environment_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment dict is non-empty."""
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert len(env) > 0

    async def test_get_environment_has_path(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment contains PATH (case-insensitive)."""
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert any(k.upper() == "PATH" for k in env)


class TestDotNetDetection:
    """Verify .NET CLR detection."""

    async def test_detect_dotnet_python_is_negative(self, attached_bridge: ProcessBridge) -> None:
        """Verify Python process has no CLR loaded."""
        result = await attached_bridge.detect_dotnet(os.getpid())
        assert result["clr_loaded"] is False


class TestJobGuiCom:
    """Verify job object, GUI resources, and COM enumeration."""

    async def test_get_job_info_has_in_job(self, attached_bridge: ProcessBridge) -> None:
        """Verify job info has 'in_job' key."""
        info = await attached_bridge.get_job_info(os.getpid())
        assert "in_job" in info
        assert isinstance(info["in_job"], bool)

    async def test_get_gui_resources_has_counts(self, attached_bridge: ProcessBridge) -> None:
        """Verify GUI resources has non-negative counts."""
        res = await attached_bridge.get_gui_resources(os.getpid())
        assert res["gdi_objects"] >= 0
        assert res["user_objects"] >= 0

    async def test_enumerate_com_servers_returns_list(
        self, attached_bridge: ProcessBridge
    ) -> None:
        """Verify COM enumeration returns a list without crashing."""
        result = await attached_bridge.enumerate_com_servers(os.getpid())
        assert isinstance(result, list)


class TestRegistry:
    """Verify registry access operations."""

    async def test_reg_read_value_product_name(self, process_bridge: ProcessBridge) -> None:
        """Verify reading ProductName from CurrentVersion."""
        result = await process_bridge.reg_read_value(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName"
        )
        assert result["type"] == "string"
        assert len(str(result["data"])) > 0

    async def test_reg_enum_keys_microsoft(self, process_bridge: ProcessBridge) -> None:
        """Verify enumerating HKLM\\SOFTWARE\\Microsoft returns non-empty list."""
        keys = await process_bridge.reg_enum_keys(r"HKLM\SOFTWARE\Microsoft")
        assert len(keys) > 0

    async def test_reg_enum_values_currentversion(self, process_bridge: ProcessBridge) -> None:
        """Verify enumerating values under CurrentVersion returns non-empty list."""
        values = await process_bridge.reg_enum_values(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        assert len(values) > 0

    async def test_reg_read_invalid_key_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading invalid key raises ToolError."""
        with pytest.raises(ToolError, match="registry key open failed"):
            await process_bridge.reg_read_value(
                r"HKLM\SOFTWARE\TOTALLY_FAKE_KEY_12345", "value"
            )


class TestSectionMapping:
    """Verify section create and map operations."""

    async def test_create_section_returns_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify section creation returns a positive handle."""
        handle = await process_bridge.create_section(4096)
        try:
            assert handle > 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    async def test_map_section_returns_address(self, process_bridge: ProcessBridge) -> None:
        """Verify mapping a section returns a positive address."""
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
        """Verify SystemProcessInformation (class 5) returns non-empty bytes."""
        result = await process_bridge.query_system_info(5)
        assert isinstance(result, bytes)
        assert len(result) > 0


class TestSehFiberTls:
    """Verify SEH chain, fiber data, and TLS access."""

    async def test_get_seh_chain_no_crash(
        self, attached_bridge: ProcessBridge, main_thread_tid: int
    ) -> None:
        """Verify SEH chain returns a list (may be empty on x64)."""
        chain = await attached_bridge.get_seh_chain(main_thread_tid)
        assert isinstance(chain, list)

    async def test_get_fiber_data_returns_dict(
        self, attached_bridge: ProcessBridge, main_thread_tid: int
    ) -> None:
        """Verify fiber data has expected keys."""
        result = await attached_bridge.get_fiber_data(main_thread_tid)
        assert "fiber_data" in result
        assert "has_fiber" in result

    async def test_get_tls_values_returns_list(
        self, attached_bridge: ProcessBridge, main_thread_tid: int
    ) -> None:
        """Verify TLS values returns a list."""
        result = await attached_bridge.get_tls_values(main_thread_tid)
        assert isinstance(result, list)


class TestStaticHelpers:
    """Verify static helper methods with no asyncio or platform restriction."""

    def test_prot_from_string_rwx(self) -> None:
        """Verify 'rwx' maps to PAGE_EXECUTE_READWRITE."""
        assert ProcessBridge._prot_from_string("rwx") == PAGE_EXECUTE_READWRITE

    def test_prot_from_string_rw(self) -> None:
        """Verify 'rw' maps to PAGE_READWRITE."""
        assert ProcessBridge._prot_from_string("rw") == PAGE_READWRITE

    def test_prot_from_string_rx(self) -> None:
        """Verify 'rx' maps to PAGE_EXECUTE_READ."""
        assert ProcessBridge._prot_from_string("rx") == PAGE_EXECUTE_READ

    def test_prot_from_string_r(self) -> None:
        """Verify 'r' maps to PAGE_READONLY."""
        assert ProcessBridge._prot_from_string("r") == PAGE_READONLY

    def test_prot_from_string_x(self) -> None:
        """Verify 'x' maps to PAGE_EXECUTE."""
        assert ProcessBridge._prot_from_string("x") == PAGE_EXECUTE

    def test_prot_from_string_unknown_defaults(self) -> None:
        """Verify unknown string defaults to PAGE_EXECUTE_READWRITE."""
        assert ProcessBridge._prot_from_string("???") == PAGE_EXECUTE_READWRITE

    def test_parse_registry_path_hklm(self) -> None:
        """Verify HKLM prefix resolves correctly."""
        root, sub = ProcessBridge._parse_registry_path(r"HKLM\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_hkcu(self) -> None:
        """Verify HKCU prefix resolves correctly."""
        root, sub = ProcessBridge._parse_registry_path(r"HKCU\Software")
        assert root == 0x80000001
        assert sub == "Software"

    def test_parse_registry_path_hkcr(self) -> None:
        """Verify HKCR prefix resolves correctly."""
        root, sub = ProcessBridge._parse_registry_path(r"HKCR\CLSID")
        assert root == 0x80000000
        assert sub == "CLSID"

    def test_parse_registry_path_full_name(self) -> None:
        """Verify HKEY_LOCAL_MACHINE resolves same as HKLM."""
        root, sub = ProcessBridge._parse_registry_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_invalid_raises(self) -> None:
        """Verify invalid root raises ToolError."""
        with pytest.raises(ToolError, match="invalid registry root"):
            ProcessBridge._parse_registry_path(r"INVALID\Path")


class TestErrorConditions:
    """Verify error handling for unattached operations."""

    async def test_read_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify read_memory raises when not attached."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify write_memory raises when not attached."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.write_memory(0x1000, b"\x90")

    async def test_terminate_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify terminate raises when not attached."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.terminate()

    async def test_get_modules_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no PID available."""
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()
