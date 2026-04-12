# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for shared Win32 ctypes structures, constants, and DLL helpers."""

from __future__ import annotations

import sys

import pytest

from intellicrack.bridges._win32_types import (
    CONTEXT_ALL,
    CONTEXT_AMD64,
    CONTEXT_CONTROL,
    CONTEXT_DEBUG_REGISTERS,
    CONTEXT_FLOATING_POINT,
    CONTEXT_INTEGER,
    CONTEXT_SEGMENTS,
    HKEY_LOCAL_MACHINE,
    PROCESS_ALL_ACCESS,
    TH32CS_SNAPALL,
    THREAD_ALL_ACCESS,
    THREAD_STATE_NAMES,
    mem_type_to_string,
    protection_to_string,
    state_to_string,
)


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
        """Verify unrecognized state returns 'unknown'."""
        assert state_to_string(0x9999) == "unknown"


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
        """Verify unrecognized type returns 'unknown'."""
        assert mem_type_to_string(0) == "unknown"


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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestStructureFieldVerification:
    """Verify ctypes structure sizes and field presence."""

    def test_threadentry32_size(self) -> None:
        """Verify THREADENTRY32 is 28 bytes."""
        import ctypes

        from intellicrack.bridges._win32_types import THREADENTRY32

        assert ctypes.sizeof(THREADENTRY32) == 28

    def test_luid_size(self) -> None:
        """Verify LUID is 8 bytes."""
        import ctypes

        from intellicrack.bridges._win32_types import LUID

        assert ctypes.sizeof(LUID) == 8

    def test_context64_has_rip_rsp(self) -> None:
        """Verify CONTEXT64 has Rip, Rsp, Rax, Rbx fields."""
        from intellicrack.bridges._win32_types import CONTEXT64

        ctx = CONTEXT64()
        assert hasattr(ctx, "Rip")
        assert hasattr(ctx, "Rsp")
        assert hasattr(ctx, "Rax")
        assert hasattr(ctx, "Rbx")

    def test_context32_has_eip_esp(self) -> None:
        """Verify CONTEXT32 has Eip, Esp, Eax, Ebx fields."""
        from intellicrack.bridges._win32_types import CONTEXT32

        ctx = CONTEXT32()
        assert hasattr(ctx, "Eip")
        assert hasattr(ctx, "Esp")
        assert hasattr(ctx, "Eax")
        assert hasattr(ctx, "Ebx")

    def test_memory_basic_information_has_all_fields(self) -> None:
        """Verify MEMORY_BASIC_INFORMATION has all 7 fields."""
        from intellicrack.bridges._win32_types import MEMORY_BASIC_INFORMATION

        mbi = MEMORY_BASIC_INFORMATION()
        assert hasattr(mbi, "BaseAddress")
        assert hasattr(mbi, "AllocationBase")
        assert hasattr(mbi, "AllocationProtect")
        assert hasattr(mbi, "RegionSize")
        assert hasattr(mbi, "State")
        assert hasattr(mbi, "Protect")
        assert hasattr(mbi, "Type")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
class TestDllHelperCaching:
    """Verify DLL helpers return non-None and cache results."""

    def test_get_kernel32_returns_non_none(self) -> None:
        """Verify get_kernel32 returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_kernel32

        assert get_kernel32() is not None

    def test_get_kernel32_cached(self) -> None:
        """Verify get_kernel32 returns the same cached object."""
        from intellicrack.bridges._win32_types import get_kernel32

        assert get_kernel32() is get_kernel32()

    def test_get_ntdll_returns_non_none(self) -> None:
        """Verify get_ntdll returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_ntdll

        assert get_ntdll() is not None

    def test_get_ntdll_cached(self) -> None:
        """Verify get_ntdll returns the same cached object."""
        from intellicrack.bridges._win32_types import get_ntdll

        assert get_ntdll() is get_ntdll()

    def test_get_advapi32_returns_non_none(self) -> None:
        """Verify get_advapi32 returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_advapi32

        assert get_advapi32() is not None

    def test_get_advapi32_cached(self) -> None:
        """Verify get_advapi32 returns the same cached object."""
        from intellicrack.bridges._win32_types import get_advapi32

        assert get_advapi32() is get_advapi32()

    def test_get_user32_returns_non_none(self) -> None:
        """Verify get_user32 returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_user32

        assert get_user32() is not None

    def test_get_user32_cached(self) -> None:
        """Verify get_user32 returns the same cached object."""
        from intellicrack.bridges._win32_types import get_user32

        assert get_user32() is get_user32()

    def test_get_dbghelp_returns_non_none(self) -> None:
        """Verify get_dbghelp returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_dbghelp

        assert get_dbghelp() is not None

    def test_get_dbghelp_cached(self) -> None:
        """Verify get_dbghelp returns the same cached object."""
        from intellicrack.bridges._win32_types import get_dbghelp

        assert get_dbghelp() is get_dbghelp()

    def test_get_psapi_returns_non_none(self) -> None:
        """Verify get_psapi returns a non-None handle."""
        from intellicrack.bridges._win32_types import get_psapi

        assert get_psapi() is not None

    def test_get_psapi_cached(self) -> None:
        """Verify get_psapi returns the same cached object."""
        from intellicrack.bridges._win32_types import get_psapi

        assert get_psapi() is get_psapi()
