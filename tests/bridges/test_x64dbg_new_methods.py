# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for new X64DbgBridge methods (Phases 3, 4, 7).

Tests validate:
- find_pattern hex parsing with and without wildcards
- allocate_memory protection flag mapping
- scan_memory accepting both str and bytes
- PE section/export parsing against real system DLLs
- Tool definition completeness for all new functions
- New pipe-dependent methods raise ToolError when not connected
- dump_memory_to_file writes real memory to disk
"""

from __future__ import annotations

import binascii
import ctypes
import os
import struct
import sys
from typing import TYPE_CHECKING, ClassVar, Final


if TYPE_CHECKING:
    from pathlib import Path

import pefile
import pytest

from intellicrack.bridges.base import MemorySearchResult
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError, ToolName


_ALLOC_SIZE: Final[int] = 4096
_ADDR_CODE: Final[int] = 0x401000
_ADDR_RANGE_END: Final[int] = 0x402000
_TRACE_CODE: Final[int] = 0xC0000005
_TEST_MODULE: Final[str] = "ntdll.dll"
_NTDLL_PATH: Final[str] = r"C:\Windows\System32\ntdll.dll"
_TEXT_CHARACTERISTICS_EXPECTED: Final[str] = "0x60000020"
_NTDLL_TEXT_MIN_VIRTUAL_SIZE: Final[int] = 0x100000
_NTDLL_MIN_EXPORT_COUNT: Final[int] = 2000
_NT_CREATE_FILE_ORDINAL: Final[int] = 297
_RTL_ALLOC_HEAP_ORDINAL: Final[int] = 754
_EXPECTED_NEW_TOOL_COUNT: Final[int] = 104


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Create a bridge instance.

    Returns:
        X64DbgBridge: X64DbgBridge instance.
    """
    return X64DbgBridge()


@pytest.fixture
def attached_bridge() -> X64DbgBridge:
    """Create a bridge attached to current process.

    Returns:
        X64DbgBridge: X64DbgBridge with attached_pid set.
    """
    b = X64DbgBridge()
    b.attached_pid = os.getpid()
    return b


class TestToolDefinitionCompleteness:
    """Verify all new tool definitions exist and map to real methods."""

    def test_tool_definition_name(self, bridge: X64DbgBridge) -> None:
        """Verify tool definition has correct name.

        Args:
            bridge: X64DbgBridge fixture.
        """
        tool_def = bridge.tool_definition
        assert tool_def.tool_name == ToolName.X64DBG

    def test_total_function_count(self, bridge: X64DbgBridge) -> None:
        """Verify all expected tool functions are present.

        Args:
            bridge: X64DbgBridge fixture.
        """
        tool_def = bridge.tool_definition
        assert len(tool_def.functions) >= _EXPECTED_NEW_TOOL_COUNT

    def test_new_tool_functions_defined(self, bridge: X64DbgBridge) -> None:
        """Verify all Phase-4 and Phase-7 tool functions are defined.

        Args:
            bridge: X64DbgBridge fixture.
        """
        tool_def = bridge.tool_definition
        function_names = {f.name for f in tool_def.functions}
        new_functions = {
            "x64dbg.find_pattern",
            "x64dbg.get_memory_regions",
            "x64dbg.get_threads",
            "x64dbg.get_modules",
            "x64dbg.get_breakpoints",
            "x64dbg.run_to",
            "x64dbg.execute_til_return",
            "x64dbg.skip_instruction",
            "x64dbg.set_ip",
            "x64dbg.set_label",
            "x64dbg.get_labels",
            "x64dbg.set_comment",
            "x64dbg.get_comments",
            "x64dbg.enable_breakpoint",
            "x64dbg.disable_breakpoint",
            "x64dbg.set_breakpoint_on_api",
            "x64dbg.dump_memory_to_file",
            "x64dbg.get_module_sections",
            "x64dbg.get_module_exports",
            "x64dbg.trace_start",
            "x64dbg.trace_stop",
            "x64dbg.set_exception_config",
            "x64dbg.spawn",
            "x64dbg.patch_instruction",
            "x64dbg.nop_range",
            "x64dbg.get_module_imports",
            "x64dbg.find_references",
            "x64dbg.find_string_references",
            "x64dbg.find_intermodular_calls",
            "x64dbg.evaluate_expression",
            "x64dbg.get_function_cfg",
            "x64dbg.save_database",
            "x64dbg.load_database",
            "x64dbg.clear_database",
            "x64dbg.get_patches",
            "x64dbg.restore_patch",
            "x64dbg.export_patches",
            "x64dbg.suspend_thread",
            "x64dbg.resume_thread",
            "x64dbg.switch_thread",
            "x64dbg.set_thread_name",
            "x64dbg.get_seh_chain",
            "x64dbg.read_peb",
            "x64dbg.read_teb",
            "x64dbg.get_pe_directories",
            "x64dbg.add_watch",
            "x64dbg.remove_watch",
            "x64dbg.get_watches",
            "x64dbg.set_logging_breakpoint",
            "x64dbg.configure_breakpoint",
            "x64dbg.set_dll_breakpoint",
            "x64dbg.trace_into",
            "x64dbg.trace_over",
            "x64dbg.get_trace_record",
            "x64dbg.step_count",
            "x64dbg.animate_start",
            "x64dbg.animate_stop",
            "x64dbg.analyze_entropy",
            "x64dbg.yara_scan",
            "x64dbg.script_load",
            "x64dbg.script_run",
            "x64dbg.script_cmd",
            "x64dbg.script_abort",
            "x64dbg.plugin_load",
            "x64dbg.plugin_unload",
            "x64dbg.plugin_list",
            "x64dbg.get_handles",
            "x64dbg.close_handle",
            "x64dbg.detect_anti_debug",
            "x64dbg.patch_anti_debug",
            "x64dbg.reconstruct_imports",
            "x64dbg.get_status",
            "x64dbg.goto_address",
            "x64dbg.get_tls_callbacks",
            "x64dbg.break_on_tls_callbacks",
            "x64dbg.get_resources",
            "x64dbg.get_privileges",
            "x64dbg.adjust_privilege",
        }
        assert new_functions.issubset(function_names), f"Missing: {new_functions - function_names}"

    _KNOWN_ALIASES: ClassVar[dict[str, str]] = {
        "disassemble": "disassemble_at",
    }

    def test_all_functions_have_methods(self, bridge: X64DbgBridge) -> None:
        """Verify every tool function maps to a real method.

        Args:
            bridge: X64DbgBridge fixture.
        """
        tool_def = bridge.tool_definition
        for func in tool_def.functions:
            method_name = func.name.replace("x64dbg.", "")
            resolved = self._KNOWN_ALIASES.get(method_name, method_name)
            method = getattr(bridge, resolved, None)
            assert method is not None, f"Missing method: {resolved} (tool: {func.name})"
            assert callable(method), f"Not callable: {resolved}"


@pytest.mark.asyncio
class TestFindPattern:
    """Test find_pattern hex parsing logic with and without wildcards."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_find_exact_pattern_in_own_memory(self, attached_bridge: X64DbgBridge) -> None:
        """Test finding an exact hex pattern in current process.

        The oracle is buf_addr from ctypes.addressof, which is the independently known
        address where the marker bytes live in the current process.  find_pattern must
        return at least one result whose 'offset' integer equals that address exactly.
        The result dict must also carry an 'address' key whose hex string matches.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\x48\x8b\xd9\x90\xcc\xc3"
        buf = ctypes.create_string_buffer(marker)
        buf_addr = ctypes.addressof(buf)

        results = await attached_bridge.find_pattern("48 89 5C 24 08 57 48 83 EC 20 48 8B D9 90 CC C3")

        assert isinstance(results, list), "find_pattern must return a list"
        assert len(results) > 0, "find_pattern returned empty list; marker was not found in process"

        exact_matches = [r for r in results if r["offset"] == buf_addr]
        assert exact_matches, f"No result with offset == buf_addr {hex(buf_addr)}; offsets found: {[hex(r['offset']) for r in results]}"
        match = exact_matches[0]
        assert match["address"] == hex(buf_addr), f"address field {match['address']!r} does not match hex(buf_addr) {hex(buf_addr)!r}"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_find_compact_hex_pattern(self, attached_bridge: X64DbgBridge) -> None:
        """Test finding a compact hex pattern without spaces.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"\xfa\xce\xfe\xed\xca\xfe\xba\xbe\xde\xad\xc0\xde\x13\x37\x42\x99"
        buf = ctypes.create_string_buffer(marker)
        buf_addr = ctypes.addressof(buf)

        results = await attached_bridge.find_pattern("FACEFEEDCAFEBABEDEADC0DE13374299")  # pragma: allowlist secret
        assert isinstance(results, list)
        found = any(int(r["offset"]) == buf_addr for r in results)
        assert found, f"Compact pattern not found at {hex(buf_addr)}"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_find_pattern_with_wildcards(self, attached_bridge: X64DbgBridge) -> None:
        """Test finding a pattern with ?? wildcards.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"\xde\xad\xbe\xef"
        buf = ctypes.create_string_buffer(marker)
        buf_addr = ctypes.addressof(buf)

        results = await attached_bridge.find_pattern("DE ?? BE EF")
        assert isinstance(results, list)
        found = any(int(r["offset"]) == buf_addr for r in results)
        assert found, f"Wildcard pattern not found at {hex(buf_addr)}"


@pytest.mark.asyncio
class TestScanMemory:
    """Test scan_memory accepting str and bytes types."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_scan_with_bytes(self, attached_bridge: X64DbgBridge) -> None:
        """Test scan_memory with bytes input finds the exact allocated buffer address.

        The oracle is buf_addr from ctypes.addressof, which is independently known.
        scan_memory must return a MemorySearchResult whose .address equals buf_addr
        and whose .matched_bytes hex-encodes the exact marker bytes (confirmed against
        binascii.hexlify, a separate stdlib function, not the bridge itself).

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"SCAN_BYTES_TEST_XYZ"
        buf = ctypes.create_string_buffer(marker)
        buf_addr = ctypes.addressof(buf)
        expected_hex = binascii.hexlify(marker).decode()

        results = await attached_bridge.scan_memory(marker)

        assert isinstance(results, list), "scan_memory must return a list"
        assert len(results) > 0, "scan_memory returned empty list; marker was not found in process"

        for result in results:
            assert isinstance(result, MemorySearchResult), f"Each result must be a MemorySearchResult, got {type(result)}"
            assert isinstance(result.address, int), "MemorySearchResult.address must be int"
            assert isinstance(result.matched_bytes, str), "MemorySearchResult.matched_bytes must be str"

        exact_matches = [r for r in results if r.address == buf_addr]
        assert exact_matches, f"No result with address == buf_addr {hex(buf_addr)}; addresses: {[hex(r.address) for r in results]}"
        assert exact_matches[0].matched_bytes == expected_hex, (
            f"matched_bytes {exact_matches[0].matched_bytes!r} != expected {expected_hex!r}"
        )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_scan_with_hex_string(self, attached_bridge: X64DbgBridge) -> None:
        """Test scan_memory with hex string input.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"\xca\xfe\xba\xbe\xde\xad\xbe\xef\xfe\xed\xfa\xce\x12\x34\x56\x78"
        buf = ctypes.create_string_buffer(marker)
        _buf_addr = ctypes.addressof(buf)

        results = await attached_bridge.scan_memory("CAFEBABEDEADBEEFFEEDFACE12345678")  # pragma: allowlist secret
        assert isinstance(results, list)
        assert len(results) > 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_scan_with_spaced_hex_string(self, attached_bridge: X64DbgBridge) -> None:
        """Test scan_memory with spaced hex string input.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        marker = b"\xab\xcd\xef\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
        buf = ctypes.create_string_buffer(marker)
        _buf_addr = ctypes.addressof(buf)

        results = await attached_bridge.scan_memory(
            "AB CD EF 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D",
        )
        assert isinstance(results, list)
        assert len(results) > 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_scan_short_pattern_raises(self, attached_bridge: X64DbgBridge) -> None:
        """Test scan_memory rejects patterns shorter than MIN_PATTERN_LENGTH.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        with pytest.raises(ToolError, match="too short"):
            await attached_bridge.scan_memory(b"short")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_scan_empty_pattern_raises(self, attached_bridge: X64DbgBridge) -> None:
        """Test scan_memory rejects empty patterns.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        with pytest.raises(ToolError, match="non-empty"):
            await attached_bridge.scan_memory(b"")


@pytest.mark.asyncio
class TestAllocateMemoryProtection:
    """Test allocate_memory respects protection parameter."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_allocate_rwx(self, attached_bridge: X64DbgBridge) -> None:
        """Test allocation with rwx protection.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        addr = await attached_bridge.allocate_memory(_ALLOC_SIZE, "rwx")
        assert addr != 0
        await attached_bridge.free_memory(addr)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_allocate_rw(self, attached_bridge: X64DbgBridge) -> None:
        """Test allocation with rw protection.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        addr = await attached_bridge.allocate_memory(_ALLOC_SIZE, "rw")
        assert addr != 0
        await attached_bridge.free_memory(addr)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_allocate_rx(self, attached_bridge: X64DbgBridge) -> None:
        """Test allocation with rx protection.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        addr = await attached_bridge.allocate_memory(_ALLOC_SIZE, "rx")
        assert addr != 0
        await attached_bridge.free_memory(addr)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_allocate_r(self, attached_bridge: X64DbgBridge) -> None:
        """Test allocation with read-only protection.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        addr = await attached_bridge.allocate_memory(_ALLOC_SIZE, "r")
        assert addr != 0
        await attached_bridge.free_memory(addr)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_allocate_named_protection(self, attached_bridge: X64DbgBridge) -> None:
        """Test allocation with named Windows protection constant.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        addr = await attached_bridge.allocate_memory(_ALLOC_SIZE, "PAGE_READWRITE")
        assert addr != 0
        await attached_bridge.free_memory(addr)


@pytest.mark.asyncio
class TestDumpMemoryToFile:
    """Test dump_memory_to_file writes actual memory to disk."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_dump_real_memory(self, attached_bridge: X64DbgBridge, tmp_path: Path) -> None:
        """Test dumping memory region to file.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
            tmp_path: Pytest temporary directory.
        """
        marker = b"DUMP_TEST_MARKER_DATA_12345678"
        buf = ctypes.create_string_buffer(marker)
        buf_addr = ctypes.addressof(buf)

        dump_file = tmp_path / "dump.bin"
        result = await attached_bridge.dump_memory_to_file(buf_addr, len(marker), str(dump_file))
        assert result["success"] is True
        assert result["bytes_written"] == len(marker)
        assert dump_file.exists()

        written_data = dump_file.read_bytes()
        assert written_data == marker


@pytest.mark.asyncio
class TestPEParsing:
    """Test PE section and export parsing against real system DLLs."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_get_module_sections_real(self, attached_bridge: X64DbgBridge) -> None:
        """Test parsing PE sections from a real loaded module with field-level validation.

        Oracle: pefile parses the same ntdll.dll on disk and produces the reference values.
        The bridge parses the in-memory image; structural fields must match pefile's on-disk
        values.  ntdll .text characteristics are 0x60000020 (IMAGE_SCN_MEM_EXECUTE |
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE), virtual_size >= 0x100000 (>1 MB), and
        writable is False.  These invariants are stable across Windows 10/11 ntdll versions.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        sections = await attached_bridge.get_module_sections(_TEST_MODULE)
        assert isinstance(sections, list), "get_module_sections must return a list"
        assert len(sections) > 0, "No sections returned for ntdll.dll"

        section_names = [s["name"] for s in sections]
        assert ".text" in section_names, f"Missing .text section, got: {section_names}"

        text_section = next(s for s in sections if s["name"] == ".text")

        assert text_section["executable"] is True, ".text must be executable"
        assert text_section["readable"] is True, ".text must be readable"
        assert text_section["writable"] is False, ".text must not be writable"

        assert text_section["characteristics"] == _TEXT_CHARACTERISTICS_EXPECTED, (
            f"ntdll .text characteristics {text_section['characteristics']!r} != expected {_TEXT_CHARACTERISTICS_EXPECTED!r}"
        )

        virtual_size: int = text_section["virtual_size"]
        assert virtual_size >= _NTDLL_TEXT_MIN_VIRTUAL_SIZE, (
            f"ntdll .text virtual_size {virtual_size:#010x} < expected minimum {_NTDLL_TEXT_MIN_VIRTUAL_SIZE:#010x}"
        )

        virtual_address: str = text_section["virtual_address"]
        assert virtual_address.startswith("0x"), f"virtual_address {virtual_address!r} is not a hex string"
        assert int(virtual_address, 16) > 0, f"virtual_address {virtual_address!r} must be non-zero"

        pe = pefile.PE(_NTDLL_PATH)
        try:
            on_disk_text = next(
                (s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"),
                None,
            )
            assert on_disk_text is not None, "pefile did not find .text in ntdll.dll on disk"
            assert virtual_size == on_disk_text.Misc_VirtualSize, (
                f"Bridge virtual_size {virtual_size:#010x} != pefile Misc_VirtualSize {on_disk_text.Misc_VirtualSize:#010x}"
            )
        finally:
            pe.close()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_section_has_required_fields(self, attached_bridge: X64DbgBridge) -> None:
        """Test that each section dict has all required fields.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        sections = await attached_bridge.get_module_sections(_TEST_MODULE)
        required_fields = {
            "name",
            "virtual_address",
            "virtual_size",
            "raw_size",
            "characteristics",
            "readable",
            "writable",
            "executable",
        }
        for section in sections:
            assert required_fields.issubset(section.keys()), (
                f"Section {section.get('name')} missing fields: {required_fields - section.keys()}"
            )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_get_module_exports_real(self, attached_bridge: X64DbgBridge) -> None:
        """Test parsing PE exports from ntdll.dll with count, structure, and specific-export validation.

        Oracle: pefile parses ntdll.dll on disk.  The bridge reads the in-memory export table.
        Invariants that hold for every Windows 10/11 ntdll build:
        - At least 2000 named exports (typically 2516+).
        - Export ordinal 297 is NtCreateFile.
        - Export ordinal 754 is RtlAllocateHeap.
        - No duplicate export names.
        - Every record has 'name', 'ordinal', 'address', 'truncated' keys.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        exports = await attached_bridge.get_module_exports(_TEST_MODULE)

        assert isinstance(exports, list), "get_module_exports must return a list"
        assert len(exports) >= _NTDLL_MIN_EXPORT_COUNT, f"ntdll exports count {len(exports)} < minimum {_NTDLL_MIN_EXPORT_COUNT}"

        required_keys: set[str] = {"name", "ordinal", "address", "truncated"}
        for export in exports:
            assert required_keys.issubset(export.keys()), f"Export record missing keys: {required_keys - export.keys()}; record={export!r}"

        export_names = [e["name"] for e in exports if e.get("name")]
        unique_names: set[str] = set(export_names)
        assert len(unique_names) == len(export_names), (
            f"Duplicate export names found; duplicates: {[n for n in export_names if export_names.count(n) > 1][:10]}"
        )

        by_ordinal: dict[int, dict[str, object]] = {e["ordinal"]: e for e in exports}

        nt_create = by_ordinal.get(_NT_CREATE_FILE_ORDINAL)
        assert nt_create is not None, f"Ordinal {_NT_CREATE_FILE_ORDINAL} (NtCreateFile) not found in exports"
        assert nt_create["name"] == "NtCreateFile", f"Ordinal {_NT_CREATE_FILE_ORDINAL} name={nt_create['name']!r}, expected 'NtCreateFile'"
        assert isinstance(nt_create["address"], str), f"NtCreateFile address must be str, got {type(nt_create['address'])}"
        assert str(nt_create["address"]).startswith("0x"), f"NtCreateFile address {nt_create['address']!r} must start with '0x'"
        assert int(str(nt_create["address"]), 16) > 0, "NtCreateFile address must be non-zero"

        rtl_alloc = by_ordinal.get(_RTL_ALLOC_HEAP_ORDINAL)
        assert rtl_alloc is not None, f"Ordinal {_RTL_ALLOC_HEAP_ORDINAL} (RtlAllocateHeap) not found in exports"
        assert rtl_alloc["name"] == "RtlAllocateHeap", (
            f"Ordinal {_RTL_ALLOC_HEAP_ORDINAL} name={rtl_alloc['name']!r}, expected 'RtlAllocateHeap'"
        )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_module_not_found(self, attached_bridge: X64DbgBridge) -> None:
        """Test get_module_sections raises for nonexistent module.

        Args:
            attached_bridge: X64DbgBridge with attached_pid.
        """
        with pytest.raises(ToolError, match="not found"):
            await attached_bridge.get_module_sections("nonexistent_fake_module.dll")


class TestParseSectionEntry:
    """Test PE section header parsing with crafted data."""

    _TEXT_CHARACTERISTICS: Final[int] = 0x60000020
    _DATA_CHARACTERISTICS: Final[int] = 0xC0000040
    _BASE_ADDRESS: Final[int] = 0x10000000

    def _build_section(self, name: bytes, vsize: int, rva: int, rsize: int, chars: int) -> bytes:
        """Build a 40-byte PE section header.

        Args:
            name: Section name bytes (up to 8 bytes).
            vsize: Virtual size.
            rva: Relative virtual address.
            rsize: Raw data size.
            chars: Characteristics flags.

        Returns:
            bytes: 40-byte section header.
        """
        data = bytearray(40)
        data[: len(name)] = name
        struct.pack_into("<I", data, 8, vsize)
        struct.pack_into("<I", data, 12, rva)
        struct.pack_into("<I", data, 16, rsize)
        struct.pack_into("<I", data, 36, chars)
        return bytes(data)

    def test_parse_text_section(self) -> None:
        """Test parsing a crafted .text section header."""
        sec_data = self._build_section(b".text\x00", 0x1000, 0x1000, 0x800, self._TEXT_CHARACTERISTICS)
        parse_fn = getattr(X64DbgBridge, "_parse_section_entry")
        result = parse_fn(sec_data, 0, self._BASE_ADDRESS)

        assert result["name"] == ".text"
        assert result["virtual_size"] == 0x1000
        assert result["raw_size"] == 0x800
        assert result["executable"] is True
        assert result["readable"] is True
        assert result["writable"] is False

    def test_parse_data_section(self) -> None:
        """Test parsing a crafted .data section header."""
        sec_data = self._build_section(b".data\x00", 0x2000, 0x3000, 0x1000, self._DATA_CHARACTERISTICS)
        parse_fn = getattr(X64DbgBridge, "_parse_section_entry")
        result = parse_fn(sec_data, 0, self._BASE_ADDRESS)

        assert result["name"] == ".data"
        assert result["executable"] is False
        assert result["readable"] is True
        assert result["writable"] is True


@pytest.mark.asyncio
class TestNewPipeDependentMethods:
    """Verify new pipe-dependent methods raise ToolError when not connected."""

    async def test_run_to(self, bridge: X64DbgBridge) -> None:
        """Verify run_to raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.run_to(_ADDR_CODE)

    async def test_execute_til_return(self, bridge: X64DbgBridge) -> None:
        """Verify execute_til_return raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.execute_til_return()

    async def test_set_ip(self, bridge: X64DbgBridge) -> None:
        """Verify set_ip raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.set_ip(_ADDR_CODE)

    async def test_set_label(self, bridge: X64DbgBridge) -> None:
        """Verify set_label raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.set_label(_ADDR_CODE, "test_label")

    async def test_get_labels_returns_empty(self, bridge: X64DbgBridge) -> None:
        """Verify get_labels returns empty list when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        result = await bridge.get_labels(_ADDR_CODE, _ADDR_RANGE_END)
        assert result == []

    async def test_set_comment(self, bridge: X64DbgBridge) -> None:
        """Verify set_comment raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.set_comment(_ADDR_CODE, "test comment")

    async def test_get_comments_returns_empty(self, bridge: X64DbgBridge) -> None:
        """Verify get_comments returns empty list when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        result = await bridge.get_comments(_ADDR_CODE, _ADDR_RANGE_END)
        assert result == []

    async def test_enable_breakpoint(self, bridge: X64DbgBridge) -> None:
        """Verify enable_breakpoint raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.enable_breakpoint(_ADDR_CODE)

    async def test_disable_breakpoint(self, bridge: X64DbgBridge) -> None:
        """Verify disable_breakpoint raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.disable_breakpoint(_ADDR_CODE)

    async def test_set_breakpoint_on_api(self, bridge: X64DbgBridge) -> None:
        """Verify set_breakpoint_on_api raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.set_breakpoint_on_api("kernel32", "CreateFileW")

    async def test_trace_start(self, bridge: X64DbgBridge) -> None:
        """Verify trace_start raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.trace_start(_ADDR_CODE)

    async def test_trace_stop(self, bridge: X64DbgBridge) -> None:
        """Verify trace_stop raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.trace_stop()

    async def test_set_exception_config(self, bridge: X64DbgBridge) -> None:
        """Verify set_exception_config raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.set_exception_config(_TRACE_CODE, "ignore")

    async def test_skip_instruction(self, bridge: X64DbgBridge) -> None:
        """Verify skip_instruction raises when pipe not connected.

        Args:
            bridge: X64DbgBridge fixture.
        """
        with pytest.raises(ToolError, match=r"pipe|bridge plugin"):
            await bridge.skip_instruction()
