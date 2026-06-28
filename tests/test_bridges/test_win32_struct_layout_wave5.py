# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 struct-layout gates for win32_types.py.

Each test asserts ctypes.sizeof and key field offsets for a Win32 ctypes
structure against the Windows SDK documented values.  The oracle is the
WinSDK spec and platform-pointer-size arithmetic, not the production code
itself.  All values are computed for 64-bit Python on Windows (pointers are
8 bytes, natural alignment rules apply).

Mutations caught:
- reordering or removing a field changes ctypes.sizeof → size assertion fails
- moving a field across a pointer-alignment boundary changes field.offset →
  offset assertion fails
"""

from __future__ import annotations

import ctypes
import sys

import pytest

from intellicrack.bridges.win32_types import (
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    LUID_AND_ATTRIBUTES,
    MODULEENTRY32,
    PROCESS_MITIGATION_ASLR_POLICY,
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
    PROCESS_MITIGATION_DEP_POLICY,
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
    PROCESS_MITIGATION_FONT_DISABLE_POLICY,
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    PROCESSENTRY32,
    SERVICE_STATUS_PROCESS,
    STACKFRAME64,
    SYMBOL_INFO,
    TOKEN_PRIVILEGES,
)


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

_PTR_SIZE: int = ctypes.sizeof(ctypes.c_void_p)

_IS_64BIT: bool = _PTR_SIZE == 8


class TestProcessEntry32Layout:
    """Verify PROCESSENTRY32 sizeof and critical field offsets.

    The Windows SDK documents PROCESSENTRY32 as 304 bytes on 64-bit Windows
    because th32DefaultHeapID is a ULONG_PTR (pointer-sized) field that
    induces 4 bytes of alignment padding on 64-bit.

    Mutation caught: removing the pointer field or its padding changes sizeof.
    """

    def test_sizeof_equals_sdk_value(self) -> None:
        """Assert ctypes.sizeof(PROCESSENTRY32) matches the WinSDK 64-bit value of 304."""
        if not _IS_64BIT:
            pytest.skip("size formula is 64-bit specific")
        assert ctypes.sizeof(PROCESSENTRY32) == 304

    def test_th32defaultheapid_offset_reflects_pointer_alignment(self) -> None:
        """Assert th32DefaultHeapID is at offset 16, proving the 4-byte alignment pad is present.

        On 64-bit, three DWORDs (12 bytes) precede th32DefaultHeapID.  The
        next 8-byte-aligned boundary after offset 12 is 16, so 4 bytes of
        padding must be inserted.  Mutation: swapping th32DefaultHeapID with
        a DWORD before it would move it to offset 12, failing this assertion.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert PROCESSENTRY32.th32DefaultHeapID.offset == 16

    def test_szexefile_offset_accounts_for_all_preceding_fields(self) -> None:
        """Assert szExeFile begins at offset 44 on 64-bit.

        After the pointer at 16 (8 bytes) and five DWORD/LONG fields (20 bytes),
        szExeFile starts at 44.  Mutation: removing dwFlags shifts szExeFile
        to 40, failing this assertion.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert PROCESSENTRY32.szExeFile.offset == 44

    def test_sizeof_consistent_with_field_count(self) -> None:
        """Assert the struct has exactly 10 declared fields (no silent extras)."""
        assert len(PROCESSENTRY32._fields_) == 10


class TestModuleEntry32Layout:
    """Verify MODULEENTRY32 sizeof and pointer-field offsets.

    On 64-bit Windows, both modBaseAddr (POINTER(c_byte)) and hModule
    (c_void_p / HMODULE) are 8-byte fields requiring 8-byte alignment.
    This forces alignment gaps after the preceding 4-byte DWORD fields.

    Mutation caught: removing either pointer changes sizeof by at least 8 bytes
    and shifts szModule / szExePath offsets.
    """

    def test_sizeof_equals_64bit_value(self) -> None:
        """Assert ctypes.sizeof(MODULEENTRY32) equals 568 on 64-bit Windows.

        On 64-bit: 5 DWORDs (20 bytes) + 4-byte pad + POINTER (8 bytes) +
        DWORD (4 bytes) + 4-byte pad + HMODULE (8 bytes) + szModule (256) +
        szExePath (260) = 564 bytes, padded to 8-byte struct alignment → 568.
        """
        if not _IS_64BIT:
            pytest.skip("size formula is 64-bit specific")
        assert ctypes.sizeof(MODULEENTRY32) == 568

    def test_modbaseaddr_offset_reflects_pointer_alignment_gap(self) -> None:
        """Assert modBaseAddr is at offset 24 (alignment pad after 5 DWORDs at 20).

        Mutation: replacing POINTER(c_byte) with a DWORD would remove the
        padding and shift modBaseAddr to offset 20.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert MODULEENTRY32.modBaseAddr.offset == 24

    def test_hmodule_offset_reflects_second_pointer_alignment_gap(self) -> None:
        """Assert hModule is at offset 40.

        After modBaseAddr (8 bytes at 24) + modBaseSize (DWORD at 32),
        hModule (8-byte HMODULE) needs an 8-byte boundary; offset 36 is not,
        so 4 bytes of padding land at 36-39 and hModule is at 40.
        Mutation: removing modBaseSize shifts hModule to 32.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert MODULEENTRY32.hModule.offset == 40

    def test_szexepath_offset_follows_szmodule(self) -> None:
        """Assert szExePath starts at offset 304 (48 + 256).

        Mutation: shrinking szModule from 256 to a smaller buffer would
        shift szExePath left of 304.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert MODULEENTRY32.szExePath.offset == 304


class TestTokenPrivilegesLayout:
    """Verify TOKEN_PRIVILEGES and LUID_AND_ATTRIBUTES sizes and offsets."""

    def test_token_privileges_sizeof_equals_16(self) -> None:
        """Assert sizeof(TOKEN_PRIVILEGES) == 16 on any pointer width.

        LUID_AND_ATTRIBUTES is 12 bytes (LUID=8 + Attributes=4, align 4).
        TOKEN_PRIVILEGES = PrivilegeCount (4) + Privileges[1] (12) = 16.
        Mutation: removing Privileges or PrivilegeCount changes sizeof.
        """
        assert ctypes.sizeof(TOKEN_PRIVILEGES) == 16

    def test_privileges_field_offset_equals_4(self) -> None:
        """Assert Privileges array starts at offset 4 (immediately after PrivilegeCount).

        Mutation: reordering fields would change the offset.
        """
        assert TOKEN_PRIVILEGES.Privileges.offset == 4

    def test_luid_and_attributes_sizeof_equals_12(self) -> None:
        """Assert sizeof(LUID_AND_ATTRIBUTES) == 12.

        LUID is 8 bytes (LowPart DWORD + HighPart LONG, align 4).
        Attributes is DWORD (4 bytes).  Total = 12, alignment = 4.
        Mutation: removing HighPart from LUID reduces LUID to 4 bytes.
        """
        assert ctypes.sizeof(LUID_AND_ATTRIBUTES) == 12

    def test_luid_and_attributes_attributes_offset_equals_8(self) -> None:
        """Assert Attributes field is at offset 8 within LUID_AND_ATTRIBUTES.

        Mutation: swapping Luid and Attributes would move Attributes to 0.
        """
        assert LUID_AND_ATTRIBUTES.Attributes.offset == 8


class TestStackFrame64Layout:
    """Verify STACKFRAME64 sizeof and KdHelp field offset.

    STACKFRAME64 contains five ADDRESS64 structs (16 bytes each), a c_void_p,
    a 4-element c_ulonglong array, two BOOLs, a 3-element c_ulonglong array,
    and a 128-byte byte array.  Total = 280 bytes on 64-bit.

    Mutation caught: removing an ADDRESS64 field shifts KdHelp left by 16 bytes.
    """

    def test_sizeof_geq_280_on_64bit(self) -> None:
        """Assert ctypes.sizeof(STACKFRAME64) == 280 on 64-bit Windows.

        Manual layout (64-bit): 5 * ADDRESS64 (5 * 16 = 80) + c_void_p (8) at
        80 + c_ulonglong*4 (32) at 88 + BOOL (4) at 120 + BOOL (4) at 124 +
        c_ulonglong*3 (24) at 128 + c_byte*128 (128) at 152 = 280 bytes,
        which is already a multiple of 8 so no trailing padding is added.
        """
        if not _IS_64BIT:
            pytest.skip("size formula is 64-bit specific")
        assert ctypes.sizeof(STACKFRAME64) == 280

    def test_kdhelp_offset_equals_152_on_64bit(self) -> None:
        """Assert KdHelp (128-byte raw buffer) starts at offset 152 on 64-bit.

        Layout: 5 * ADDRESS64 (80) + FuncTableEntry (8) + Params (32) +
        Far (4) + Virtual (4) + Reserved (24) = 152.
        Mutation: removing a Reserved ulonglong shifts KdHelp left by 8.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert STACKFRAME64.KdHelp.offset == 152

    def test_addrpc_offset_is_zero(self) -> None:
        """Assert AddrPC is the first field at offset 0."""
        assert STACKFRAME64.AddrPC.offset == 0

    def test_sizeof_lower_bound(self) -> None:
        """Assert sizeof(STACKFRAME64) >= 64 on any architecture.

        Even on 32-bit, the structure must contain at minimum 5 ADDRESS64
        structs (each 16 bytes) plus additional fields, so the realistic
        minimum is well above 64.
        """
        assert ctypes.sizeof(STACKFRAME64) >= 64


class TestSymbolInfoLayout:
    """Verify SYMBOL_INFO sizeof and key field offsets.

    SYMBOL_INFO has a gap between Flags (ULONG at 40) and Value (c_ulonglong)
    because Value needs 8-byte alignment.  On 64-bit, the struct is 1112 bytes.

    Mutation caught: removing the alignment gap shifts Value from 48 to 44,
    failing the Value offset assertion and changing sizeof.
    """

    def test_sizeof_equals_1112_on_64bit(self) -> None:
        """Assert ctypes.sizeof(SYMBOL_INFO) == 1112 on 64-bit Windows.

        Layout: 4 + 4 + 16 + 4 + 4 + 8 + 4 + [4 pad] + 8 + 8 + 4 + 4 + 4 +
        4 + 4 + 1024 = 1108 bytes, padded to next multiple of 8 → 1112.
        """
        if not _IS_64BIT:
            pytest.skip("size formula is 64-bit specific")
        assert ctypes.sizeof(SYMBOL_INFO) == 1112

    def test_value_field_offset_equals_48_on_64bit(self) -> None:
        """Assert Value (c_ulonglong) is at offset 48 due to the 4-byte alignment gap.

        After Flags (4 bytes at offset 40), the next 8-byte-aligned address is
        48, inserting 4 bytes of padding.  Mutation: removing Flags shrinks the
        gap and shifts Value to 40.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert SYMBOL_INFO.Value.offset == 48

    def test_name_field_offset_equals_84(self) -> None:
        """Assert Name (c_char * 1024) starts at offset 84.

        After MaxNameLen (ULONG at 80), Name (alignment 1) starts immediately
        at 84.  Mutation: adding a field between MaxNameLen and Name shifts Name
        right; removing MaxNameLen shifts it left to 80.
        """
        assert SYMBOL_INFO.Name.offset == 84


class TestServiceStatusProcessLayout:
    """Verify SERVICE_STATUS_PROCESS sizeof and field ordering.

    The struct is nine DWORD fields = 36 bytes, no alignment gaps.
    The WinSDK value is 36 on both 32-bit and 64-bit.

    Mutation caught: removing any DWORD field reduces sizeof by 4.
    """

    def test_sizeof_equals_36(self) -> None:
        """Assert ctypes.sizeof(SERVICE_STATUS_PROCESS) == 36 on all platforms."""
        assert ctypes.sizeof(SERVICE_STATUS_PROCESS) == 36

    def test_field_count_is_nine(self) -> None:
        """Assert the struct has exactly 9 DWORD fields."""
        assert len(SERVICE_STATUS_PROCESS._fields_) == 9

    def test_dwserviceflags_is_last_field_at_offset_32(self) -> None:
        """Assert dwServiceFlags (the 9th DWORD) is at offset 32.

        Mutation: inserting a new field before it shifts dwServiceFlags right.
        """
        assert SERVICE_STATUS_PROCESS.dwServiceFlags.offset == 32


class TestJobObjectExtendedLimitInformationLayout:
    """Verify JOBOBJECT_EXTENDED_LIMIT_INFORMATION sizeof and sub-struct offsets.

    On 64-bit: BasicLimitInformation (64 bytes) + IoInfo (48 bytes) +
    4 c_size_t fields (32 bytes) = 144 bytes, already aligned to 8.

    Mutation caught: removing a c_size_t field reduces sizeof by 8.
    """

    def test_sizeof_equals_144_on_64bit(self) -> None:
        """Assert ctypes.sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144 on 64-bit.

        BasicLimitInformation is 64 bytes, IoInfo is 48 bytes, and the
        four c_size_t tail fields are 8 bytes each = 32 bytes.  Total = 144.
        """
        if not _IS_64BIT:
            pytest.skip("size formula is 64-bit specific")
        assert ctypes.sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) == 144

    def test_ioinfo_offset_follows_basiclimitinformation(self) -> None:
        """Assert IoInfo starts at offset 64 (immediately after BasicLimitInformation).

        Mutation: adding a field to BasicLimitInformation shifts IoInfo right.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert JOBOBJECT_EXTENDED_LIMIT_INFORMATION.IoInfo.offset == 64

    def test_peakjobmemoryused_offset_is_136_on_64bit(self) -> None:
        """Assert PeakJobMemoryUsed is at offset 136 on 64-bit.

        After IoInfo (48 bytes at 64) + three c_size_t fields (24 bytes at
        112) = 136.  Mutation: removing PeakProcessMemoryUsed shifts this
        field to 128.
        """
        if not _IS_64BIT:
            pytest.skip("offset formula is 64-bit specific")
        assert JOBOBJECT_EXTENDED_LIMIT_INFORMATION.PeakJobMemoryUsed.offset == 136


class TestProcessMitigationStructLayouts:
    """Verify sizeof for PROCESS_MITIGATION_* policy structs.

    Most structs contain a single DWORD (Flags) so sizeof == 4.
    PROCESS_MITIGATION_DEP_POLICY additionally contains a BOOLEAN field
    (Permanent, 1 byte), which after the DWORD rounds up to sizeof == 8
    (struct alignment of the containing DWORD field is 4, so total rounds
    to the next multiple of 4 after the 5-byte content, giving 8).

    Mutation caught: removing Permanent from DEP_POLICY reduces its sizeof
    to 4; the assertion fails.
    """

    def test_dep_policy_sizeof_equals_8(self) -> None:
        """Assert sizeof(PROCESS_MITIGATION_DEP_POLICY) == 8.

        Contains Flags (DWORD, 4 bytes) + Permanent (BOOLEAN, 1 byte).
        Struct alignment = 4 (from DWORD).  5 bytes padded to multiple of 4
        → 8 bytes.  Mutation: removing Permanent changes sizeof to 4.
        """
        assert ctypes.sizeof(PROCESS_MITIGATION_DEP_POLICY) == 8

    def test_dep_policy_permanent_offset_equals_4(self) -> None:
        """Assert Permanent is at offset 4, immediately after Flags."""
        assert PROCESS_MITIGATION_DEP_POLICY.Permanent.offset == 4

    def test_single_dword_structs_sizeof_equals_4(self) -> None:
        """Assert that each single-DWORD mitigation struct has sizeof == 4.

        Mutation: adding an extra field to any of these structs would increase
        sizeof beyond 4.
        """
        single_dword_structs: list[type[ctypes.Structure]] = [
            PROCESS_MITIGATION_ASLR_POLICY,
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
            PROCESS_MITIGATION_FONT_DISABLE_POLICY,
        ]
        for struct_cls in single_dword_structs:
            assert ctypes.sizeof(struct_cls) == 4, (
                f"Expected sizeof({struct_cls.__name__}) == 4, "
                f"got {ctypes.sizeof(struct_cls)}"
            )
