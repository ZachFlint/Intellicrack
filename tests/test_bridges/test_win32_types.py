# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for shared Win32 ctypes structures, constants, and DLL helpers."""

from __future__ import annotations

import ctypes
import os
import sys
from typing import ClassVar

import pytest

from intellicrack.bridges import named_pipe_client, x64dbg
from intellicrack.bridges.win32_types import (
    CONTEXT32,
    CONTEXT64,
    CONTEXT_ALL,
    CONTEXT_AMD64,
    CONTEXT_CONTROL,
    CONTEXT_DEBUG_REGISTERS,
    CONTEXT_FLOATING_POINT,
    CONTEXT_INTEGER,
    CONTEXT_SEGMENTS,
    GENERIC_READ,
    GENERIC_WRITE,
    HKEY_LOCAL_MACHINE,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_IA64,
    INVALID_HANDLE_VALUE,
    LUID,
    MEM_COMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    MEMORY_BASIC_INFORMATION,
    NT_HEADERS_OPTIONAL_OFFSET,
    OPEN_EXISTING,
    PE_HEADER_OFFSET,
    PE_MAGIC_OFFSET,
    PROCESS_ALL_ACCESS,
    PROCESS_MEMORY_COUNTERS,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    TH32CS_SNAPALL,
    TH32CS_SNAPPROCESS,
    THREAD_ALL_ACCESS,
    THREAD_STATE_NAMES,
    THREADENTRY32,
    get_advapi32,
    get_dbghelp,
    get_kernel32,
    get_ntdll,
    get_psapi,
    get_user32,
    mem_type_to_string,
    protection_to_string,
    state_to_string,
)


class _OSVERSIONINFOW(ctypes.Structure):
    """Minimal RTL_OSVERSIONINFOW layout for use with RtlGetVersion.

    The Windows SDK documents this struct as the input/output buffer for
    RtlGetVersion. The caller must set dwOSVersionInfoSize to sizeof the
    struct before the call; the kernel validates this field before writing.
    """

    _fields_: ClassVar = [
        ("dwOSVersionInfoSize", ctypes.c_ulong),
        ("dwMajorVersion", ctypes.c_ulong),
        ("dwMinorVersion", ctypes.c_ulong),
        ("dwBuildNumber", ctypes.c_ulong),
        ("dwPlatformId", ctypes.c_ulong),
        ("szCSDVersion", ctypes.c_wchar * 128),
    ]


class TestProtectionToString:
    """Tests for the protection_to_string conversion function."""

    def test_noaccess(self) -> None:
        """Verify PAGE_NOACCESS maps to '---'."""
        assert protection_to_string(0x01) == "---"

    def test_readonly(self) -> None:
        """Verify PAGE_READONLY maps to 'r--'."""
        assert protection_to_string(0x02) == "r--"

    def test_readwrite(self) -> None:
        """Verify PAGE_READWRITE maps to 'rw-'."""
        assert protection_to_string(0x04) == "rw-"

    def test_writecopy(self) -> None:
        """Verify PAGE_WRITECOPY maps to 'rw-c'."""
        assert protection_to_string(0x08) == "rw-c"

    def test_execute(self) -> None:
        """Verify PAGE_EXECUTE maps to '--x'."""
        assert protection_to_string(0x10) == "--x"

    def test_execute_read(self) -> None:
        """Verify PAGE_EXECUTE_READ maps to 'r-x'."""
        assert protection_to_string(0x20) == "r-x"

    def test_execute_readwrite(self) -> None:
        """Verify PAGE_EXECUTE_READWRITE maps to 'rwx'."""
        assert protection_to_string(0x40) == "rwx"

    def test_execute_writecopy(self) -> None:
        """Verify PAGE_EXECUTE_WRITECOPY maps to 'rwxc'."""
        assert protection_to_string(0x80) == "rwxc"

    def test_with_guard(self) -> None:
        """Verify PAGE_GUARD modifier appends '+G'."""
        assert protection_to_string(0x04 | 0x100) == "rw-+G"

    def test_unknown(self) -> None:
        """Verify unrecognized base protection returns '???'."""
        assert protection_to_string(0xFF) == "???"

    def test_zero(self) -> None:
        """Verify zero protection returns '???'."""
        assert protection_to_string(0) == "???"


class TestStateToString:
    """Tests for the state_to_string conversion function."""

    def test_commit(self) -> None:
        """Verify MEM_COMMIT maps to 'committed'."""
        assert state_to_string(0x1000) == "committed"

    def test_reserve(self) -> None:
        """Verify MEM_RESERVE maps to 'reserved'."""
        assert state_to_string(0x2000) == "reserved"

    def test_free(self) -> None:
        """Verify MEM_FREE maps to 'free'."""
        assert state_to_string(0x10000) == "free"

    def test_unknown(self) -> None:
        """Verify unrecognized state returns ``unknown(0x...)``."""
        assert state_to_string(0x9999) == "unknown(0x9999)"


class TestMemTypeToString:
    """Tests for the mem_type_to_string conversion function."""

    def test_private(self) -> None:
        """Verify MEM_PRIVATE maps to 'private'."""
        assert mem_type_to_string(0x20000) == "private"

    def test_mapped(self) -> None:
        """Verify MEM_MAPPED maps to 'mapped'."""
        assert mem_type_to_string(0x40000) == "mapped"

    def test_image(self) -> None:
        """Verify MEM_IMAGE maps to 'image'."""
        assert mem_type_to_string(0x1000000) == "image"

    def test_unknown(self) -> None:
        """Verify unrecognized type returns ``unknown(0x...)``."""
        assert mem_type_to_string(0) == "unknown(0x0)"


class TestConstantSpotChecks:
    """Spot-check key Win32 constant values."""

    def test_process_all_access_value(self) -> None:
        """Verify PROCESS_ALL_ACCESS equals 0x1F0FFF."""
        assert PROCESS_ALL_ACCESS == 0x1F0FFF

    def test_thread_all_access_value(self) -> None:
        """Verify THREAD_ALL_ACCESS equals 0x1F03FF."""
        assert THREAD_ALL_ACCESS == 0x1F03FF

    def test_th32cs_snapall_value(self) -> None:
        """Verify TH32CS_SNAPALL equals 0x1F."""
        assert TH32CS_SNAPALL == 0x1F

    def test_hkey_local_machine_value(self) -> None:
        """Verify HKEY_LOCAL_MACHINE equals 0x80000002."""
        assert HKEY_LOCAL_MACHINE == 0x80000002

    def test_context_amd64_value(self) -> None:
        """Verify CONTEXT_AMD64 equals 0x00100000."""
        assert CONTEXT_AMD64 == 0x00100000

    def test_context_all_includes_all_groups(self) -> None:
        """Verify CONTEXT_ALL includes CONTROL, INTEGER, FLOAT, SEGMENTS, DEBUG."""
        assert CONTEXT_ALL & CONTEXT_CONTROL == CONTEXT_CONTROL
        assert CONTEXT_ALL & CONTEXT_INTEGER == CONTEXT_INTEGER
        assert CONTEXT_ALL & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT
        assert CONTEXT_ALL & CONTEXT_SEGMENTS == CONTEXT_SEGMENTS
        assert CONTEXT_ALL & CONTEXT_DEBUG_REGISTERS == CONTEXT_DEBUG_REGISTERS

    def test_thread_state_names_complete(self) -> None:
        """Verify THREAD_STATE_NAMES has all 8 entries for values 0-7."""
        assert len(THREAD_STATE_NAMES) == 8
        for i in range(8):
            assert i in THREAD_STATE_NAMES


class TestInvalidHandleValue:
    """Tests for the dynamic INVALID_HANDLE_VALUE computation."""

    def test_constant_is_int(self) -> None:
        """Verify INVALID_HANDLE_VALUE is an int."""
        assert isinstance(INVALID_HANDLE_VALUE, int)

    def test_value_matches_expected_bit_pattern(self) -> None:
        """Verify INVALID_HANDLE_VALUE equals the Windows-documented all-bits-set sentinel.

        The Windows documentation states INVALID_HANDLE_VALUE is (HANDLE)(LONG_PTR)(-1),
        which on a 64-bit process evaluates to 0xFFFFFFFFFFFFFFFF and on a 32-bit process
        to 0xFFFFFFFF. The production code must produce this exact value without any
        alteration. We independently compute the expected value from the documented
        pointer width (not from the HANDLE type itself, which is the production code's
        own mechanism) and assert equality.
        """
        void_ptr_size = ctypes.sizeof(ctypes.c_void_p)
        if sys.platform == "win32":
            if void_ptr_size == 8:
                assert INVALID_HANDLE_VALUE == 0xFFFFFFFFFFFFFFFF
            else:
                assert INVALID_HANDLE_VALUE == 0xFFFFFFFF
        else:
            assert INVALID_HANDLE_VALUE == 0xFFFFFFFF


class TestGenericAccessConstants:
    """Tests for CreateFileW / CreateNamedPipeW generic-access constants."""

    def test_generic_read_value(self) -> None:
        """Verify GENERIC_READ equals 0x80000000."""
        assert GENERIC_READ == 0x80000000

    def test_generic_write_value(self) -> None:
        """Verify GENERIC_WRITE equals 0x40000000."""
        assert GENERIC_WRITE == 0x40000000

    def test_open_existing_value(self) -> None:
        """Verify OPEN_EXISTING equals 3."""
        assert OPEN_EXISTING == 3


class TestPeHeaderOffsets:
    """Tests for PE header layout offset constants."""

    def test_pe_header_offset(self) -> None:
        """Verify PE_HEADER_OFFSET equals 0x3C (DOS e_lfanew)."""
        assert PE_HEADER_OFFSET == 0x3C

    def test_pe_magic_offset(self) -> None:
        """Verify PE_MAGIC_OFFSET equals 0x40 (end of e_lfanew)."""
        assert PE_MAGIC_OFFSET == 0x40

    def test_nt_headers_optional_offset(self) -> None:
        """Verify NT_HEADERS_OPTIONAL_OFFSET equals 0x18."""
        assert NT_HEADERS_OPTIONAL_OFFSET == 0x18

    def test_offsets_are_distinct(self) -> None:
        """Verify the three PE offsets do not collide."""
        offsets = {PE_HEADER_OFFSET, PE_MAGIC_OFFSET, NT_HEADERS_OPTIONAL_OFFSET}
        assert len(offsets) == 3


class TestPeMachineConstants:
    """Tests for IMAGE_FILE_MACHINE_* constants used in PE COFF parsing."""

    def test_i386_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_I386 equals 0x014C."""
        assert IMAGE_FILE_MACHINE_I386 == 0x014C

    def test_amd64_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_AMD64 equals 0x8664."""
        assert IMAGE_FILE_MACHINE_AMD64 == 0x8664

    def test_arm_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_ARM equals 0x01C0."""
        assert IMAGE_FILE_MACHINE_ARM == 0x01C0

    def test_armnt_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_ARMNT equals 0x01C4."""
        assert IMAGE_FILE_MACHINE_ARMNT == 0x01C4

    def test_arm64_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_ARM64 equals 0xAA64."""
        assert IMAGE_FILE_MACHINE_ARM64 == 0xAA64

    def test_ia64_value(self) -> None:
        """Verify IMAGE_FILE_MACHINE_IA64 equals 0x0200."""
        assert IMAGE_FILE_MACHINE_IA64 == 0x0200


class TestConsumersUseCanonicalConstants:
    """Verify Win32 constant consumers import from ``win32_types`` (audit Group 1)."""

    def test_x64dbg_imports_canonical_invalid_handle_value(self) -> None:
        """Verify x64dbg's INVALID_HANDLE_VALUE equals the canonical value."""
        assert x64dbg.INVALID_HANDLE_VALUE == INVALID_HANDLE_VALUE

    def test_x64dbg_imports_canonical_pe_header_offset(self) -> None:
        """Verify x64dbg's PE_HEADER_OFFSET matches the canonical value."""
        assert x64dbg.PE_HEADER_OFFSET == PE_HEADER_OFFSET

    def test_x64dbg_imports_canonical_pe_magic_offset(self) -> None:
        """Verify x64dbg's PE_MAGIC_OFFSET matches the canonical value."""
        assert x64dbg.PE_MAGIC_OFFSET == PE_MAGIC_OFFSET

    def test_x64dbg_imports_canonical_nt_headers_optional_offset(self) -> None:
        """Verify x64dbg's NT_HEADERS_OPTIONAL_OFFSET matches the canonical value."""
        assert x64dbg.NT_HEADERS_OPTIONAL_OFFSET == NT_HEADERS_OPTIONAL_OFFSET

    def test_x64dbg_imports_canonical_pe_machine_constants(self) -> None:
        """Verify x64dbg's PE32_MACHINE / PE64_MACHINE map to canonical IMAGE_FILE_MACHINE_*."""
        assert x64dbg.PE32_MACHINE == IMAGE_FILE_MACHINE_I386
        assert x64dbg.PE64_MACHINE == IMAGE_FILE_MACHINE_AMD64

    def test_x64dbg_imports_canonical_th32cs_snapprocess(self) -> None:
        """Verify x64dbg's TH32CS_SNAPPROCESS matches the canonical value."""
        assert x64dbg.TH32CS_SNAPPROCESS == TH32CS_SNAPPROCESS

    def test_x64dbg_win_mem_constants_match_canonical(self) -> None:
        """Verify x64dbg's WIN_MEM_* aliases match canonical MEM_* constants."""
        assert x64dbg.WIN_MEM_COMMIT == MEM_COMMIT
        assert x64dbg.WIN_MEM_RESERVE == MEM_RESERVE
        assert x64dbg.WIN_MEM_RELEASE == MEM_RELEASE

    def test_x64dbg_win_process_constants_match_canonical(self) -> None:
        """Verify x64dbg's WIN_PROCESS_* aliases match canonical PROCESS_* constants."""
        assert x64dbg.WIN_PROCESS_QUERY_INFORMATION == PROCESS_QUERY_INFORMATION
        assert x64dbg.WIN_PROCESS_VM_OPERATION == PROCESS_VM_OPERATION
        assert x64dbg.WIN_PROCESS_VM_READ == PROCESS_VM_READ
        assert x64dbg.WIN_PROCESS_VM_WRITE == PROCESS_VM_WRITE

    def test_named_pipe_client_uses_canonical_invalid_handle_value(self) -> None:
        """Verify named_pipe_client uses the canonical INVALID_HANDLE_VALUE."""
        assert named_pipe_client.INVALID_HANDLE_VALUE == INVALID_HANDLE_VALUE

    def test_named_pipe_client_uses_canonical_open_existing(self) -> None:
        """Verify named_pipe_client uses the canonical OPEN_EXISTING."""
        assert named_pipe_client.OPEN_EXISTING == OPEN_EXISTING

    def test_named_pipe_client_uses_canonical_generic_read(self) -> None:
        """Verify named_pipe_client uses the canonical GENERIC_READ."""
        assert named_pipe_client.GENERIC_READ == GENERIC_READ

    def test_named_pipe_client_uses_canonical_generic_write(self) -> None:
        """Verify named_pipe_client uses the canonical GENERIC_WRITE."""
        assert named_pipe_client.GENERIC_WRITE == GENERIC_WRITE


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestStructureFieldVerification:
    """Verify ctypes structure sizes and field presence."""

    def test_threadentry32_size(self) -> None:
        """Verify THREADENTRY32 is 28 bytes."""
        assert ctypes.sizeof(THREADENTRY32) == 28

    def test_luid_size(self) -> None:
        """Verify LUID is 8 bytes."""
        assert ctypes.sizeof(LUID) == 8

    def test_context64_layout(self) -> None:
        """Verify CONTEXT64 total size and critical register field offsets match the Win32 AMD64 ABI.

        The Windows SDK documents CONTEXT (AMD64) as exactly 1232 bytes with Rip at byte
        offset 0xF8 (248) and Rsp at byte offset 0x98 (152). An incorrect _fields_ ordering
        or wrong field type changes both the total size and the offsets, breaking
        GetThreadContext/SetThreadContext interop. We independently derive the expected
        offsets from the documented SDK layout rather than from the production _fields_ list.
        """
        assert ctypes.sizeof(CONTEXT64) == 1232
        assert CONTEXT64.Rip.offset == 248
        assert CONTEXT64.Rsp.offset == 152
        assert CONTEXT64.Rax.offset == 120
        assert CONTEXT64.Rbx.offset == 144

    def test_context32_layout(self) -> None:
        """Verify CONTEXT32 total size and critical register field offsets match the Win32 I386 ABI.

        The Windows SDK documents CONTEXT (I386) as exactly 204 bytes with Eip at byte
        offset 0xB8 (184) and Esp at byte offset 0xC4 (196). An incorrect _fields_ ordering
        or wrong field type changes both the total size and the offsets, breaking
        GetThreadContext/SetThreadContext interop for 32-bit and WOW64 threads.
        """
        assert ctypes.sizeof(CONTEXT32) == 204
        assert CONTEXT32.Eip.offset == 184
        assert CONTEXT32.Esp.offset == 196
        assert CONTEXT32.Eax.offset == 176
        assert CONTEXT32.Ebx.offset == 164

    def test_memory_basic_information_layout(self) -> None:
        """Verify MEMORY_BASIC_INFORMATION total size and field offsets match the Win32 ABI.

        The Windows SDK documents MEMORY_BASIC_INFORMATION as 48 bytes on 64-bit and 28 bytes
        on 32-bit. We independently derive expected offsets from the documented pointer-width-
        dependent layout rather than from the production _fields_ list, so an incorrect
        ordering or field type is caught by the offset assertions.
        """
        ptr_size: int = ctypes.sizeof(ctypes.c_void_p)
        if ptr_size == 8:
            expected_sizeof: int = 48
            expected_region_size_offset: int = 24
            expected_state_offset: int = 32
            expected_protect_offset: int = 36
            expected_type_offset: int = 40
        else:
            expected_sizeof = 28
            expected_region_size_offset = 12
            expected_state_offset = 16
            expected_protect_offset = 20
            expected_type_offset = 24
        assert ctypes.sizeof(MEMORY_BASIC_INFORMATION) == expected_sizeof
        assert MEMORY_BASIC_INFORMATION.RegionSize.offset == expected_region_size_offset
        assert MEMORY_BASIC_INFORMATION.State.offset == expected_state_offset
        assert MEMORY_BASIC_INFORMATION.Protect.offset == expected_protect_offset
        assert MEMORY_BASIC_INFORMATION.Type.offset == expected_type_offset


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestDllHelperCaching:
    """Verify DLL helpers return non-None and cache results."""

    def test_get_kernel32_resolves_getcurrentprocessid(self) -> None:
        """Verify get_kernel32 returns the correct DLL by calling GetCurrentProcessId.

        GetCurrentProcessId is a well-known kernel32 export that must return the current
        process PID. We cross-check against os.getpid() as an independent oracle so a wrong
        DLL handle (or a broken helper that returned a different module) would produce a
        mismatched PID and fail this assertion.
        """
        k32: ctypes.WinDLL = get_kernel32()
        k32.GetCurrentProcessId.restype = ctypes.c_ulong
        k32.GetCurrentProcessId.argtypes = []
        assert k32.GetCurrentProcessId() == os.getpid()

    def test_get_kernel32_cached(self) -> None:
        """Verify get_kernel32 returns the same cached object."""
        assert get_kernel32() is get_kernel32()

    def test_get_ntdll_resolves_rtlgetversion(self) -> None:
        """Verify get_ntdll returns the correct DLL by calling RtlGetVersion.

        RtlGetVersion is a stable ntdll export available on all Windows versions. It must
        return STATUS_SUCCESS (0) for the current host. A wrong DLL handle (or a helper
        that returned a different module) would fail to resolve the export and raise, or
        return a non-zero NTSTATUS, failing this assertion.

        The call uses a properly allocated RTL_OSVERSIONINFOW structure with dwOSVersionInfoSize
        initialised so the kernel can validate the buffer before writing. Passing a null pointer
        (argtypes=[c_void_p], value=None) causes an access violation because RtlGetVersion writes
        into the struct immediately without a null check.
        """
        ntdll: ctypes.WinDLL = get_ntdll()
        ntdll.RtlGetVersion.restype = ctypes.c_long
        ntdll.RtlGetVersion.argtypes = [ctypes.POINTER(_OSVERSIONINFOW)]
        osver: _OSVERSIONINFOW = _OSVERSIONINFOW()
        osver.dwOSVersionInfoSize = ctypes.sizeof(_OSVERSIONINFOW)
        ntstatus: int = ntdll.RtlGetVersion(ctypes.byref(osver))
        assert ntstatus == 0
        assert osver.dwMajorVersion >= 6

    def test_get_ntdll_cached(self) -> None:
        """Verify get_ntdll returns the same cached object."""
        assert get_ntdll() is get_ntdll()

    def test_get_advapi32_resolves_lookupprivilegevaluew(self) -> None:
        """Verify get_advapi32 returns the correct DLL by calling LookupPrivilegeValueW.

        LookupPrivilegeValueW is a stable advapi32 export. Called with the well-known
        SeDebugPrivilege name it must succeed (return 1). A wrong DLL handle would fail
        to resolve the symbol or return an error code, failing this assertion.
        """
        adv: ctypes.WinDLL = get_advapi32()
        adv.LookupPrivilegeValueW.restype = ctypes.c_int
        adv.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p]
        luid: ctypes.Array[ctypes.c_ulong] = (ctypes.c_ulong * 2)()
        result: int = adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", luid)
        assert result == 1

    def test_get_advapi32_cached(self) -> None:
        """Verify get_advapi32 returns the same cached object."""
        assert get_advapi32() is get_advapi32()

    def test_get_user32_resolves_getdesktopwindow(self) -> None:
        """Verify get_user32 returns the correct DLL by calling GetDesktopWindow.

        GetDesktopWindow is a stable user32 export that always returns a valid non-NULL
        HWND on Windows (the desktop window is always present). A wrong DLL handle would
        fail to resolve the symbol or return NULL (0), failing this assertion.
        """
        u32: ctypes.WinDLL = get_user32()
        u32.GetDesktopWindow.restype = ctypes.c_void_p
        u32.GetDesktopWindow.argtypes = []
        hwnd: int | None = u32.GetDesktopWindow()
        assert hwnd is not None
        assert hwnd != 0

    def test_get_user32_cached(self) -> None:
        """Verify get_user32 returns the same cached object."""
        assert get_user32() is get_user32()

    def test_get_dbghelp_resolves_symgetoptions(self) -> None:
        """Verify get_dbghelp returns the correct DLL by calling SymGetOptions.

        SymGetOptions is a stable dbghelp export that returns a DWORD bitmask of current
        symbol handler options. The call must not raise and must return an integer. A wrong
        DLL handle would fail to resolve the symbol or raise, failing this assertion.
        """
        dbg: ctypes.WinDLL = get_dbghelp()
        dbg.SymGetOptions.restype = ctypes.c_ulong
        dbg.SymGetOptions.argtypes = []
        opts: int = dbg.SymGetOptions()
        assert isinstance(opts, int)

    def test_get_dbghelp_cached(self) -> None:
        """Verify get_dbghelp returns the same cached object."""
        assert get_dbghelp() is get_dbghelp()

    def test_get_psapi_resolves_getprocessmemoryinfo(self) -> None:
        """Verify get_psapi returns the correct DLL by calling GetProcessMemoryInfo.

        GetProcessMemoryInfo is a stable psapi export. Called for the current process it
        must succeed (return non-zero) and report a non-zero WorkingSetSize that we
        independently verify is plausible (greater than zero). A wrong DLL handle would
        fail to resolve the symbol or return 0, failing this assertion.
        """
        psapi: ctypes.WinDLL = get_psapi()
        k32: ctypes.WinDLL = get_kernel32()
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.GetCurrentProcess.argtypes = []
        proc_handle: int | None = k32.GetCurrentProcess()
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.c_ulong]
        pmc: PROCESS_MEMORY_COUNTERS = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        ret: int = psapi.GetProcessMemoryInfo(proc_handle, ctypes.byref(pmc), pmc.cb)
        assert ret != 0
        assert pmc.WorkingSetSize > 0

    def test_get_psapi_cached(self) -> None:
        """Verify get_psapi returns the same cached object."""
        assert get_psapi() is get_psapi()
