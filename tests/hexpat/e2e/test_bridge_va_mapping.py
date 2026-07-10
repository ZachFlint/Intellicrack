# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge virtual address mapping operations."""

from __future__ import annotations

import asyncio
import importlib
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)

# ---------------------------------------------------------------------------
# Independent oracle constants
# ---------------------------------------------------------------------------
# PE oracle values are derived from the conftest._build_pe_binary_full() layout
# without re-implementing the production mapping algorithm.
#
# PE_SIGNATURE_OFFSET (e_lfanew) is 0x80, ImageBase is 0x00400000.
# Header mapping:  file_offset 0, VA 0x400000, length equals e_lfanew (0x80).
# .text section:   file_offset 0x200, VA 0x401000, length 0x200.
# .data section:   file_offset 0x400, VA 0x402000, length 0x100.
#
# These values are INDEPENDENTLY KNOWN from the known fixture layout; they are
# NOT copied from production output.
_PE_ORACLE_HEADER_FILE_OFFSET: int = 0
_PE_ORACLE_HEADER_VA: int = 0x400000
_PE_ORACLE_HEADER_LENGTH: int = 0x80
_PE_ORACLE_TEXT_FILE_OFFSET: int = 0x200
_PE_ORACLE_TEXT_VA: int = 0x401000
_PE_ORACLE_TEXT_LENGTH: int = 0x200
_PE_ORACLE_DATA_FILE_OFFSET: int = 0x400
_PE_ORACLE_DATA_VA: int = 0x402000
_PE_ORACLE_DATA_LENGTH: int = 0x100
_PE_ORACLE_MAPPING_COUNT: int = 3

# ELF oracle values from conftest._build_elf_binary_with_loads() layout:
#   PT_LOAD seg1: p_offset=0x1000, p_vaddr=0x400000, p_filesz=0x200
#   PT_LOAD seg2: p_offset=0x2000, p_vaddr=0x401000, p_filesz=0x100
_ELF_ORACLE_SEG1_FILE_OFFSET: int = 0x1000
_ELF_ORACLE_SEG1_VA: int = 0x400000
_ELF_ORACLE_SEG1_LENGTH: int = 0x200
_ELF_ORACLE_SEG2_FILE_OFFSET: int = 0x2000
_ELF_ORACLE_SEG2_VA: int = 0x401000
_ELF_ORACLE_SEG2_LENGTH: int = 0x100
_ELF_ORACLE_MAPPING_COUNT: int = 2


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _has_native_va_mapping() -> bool:
    """Check if the native HexDocument exposes VA mapping methods.

    Returns:
        bool: True if native VA mapping is available.
    """
    module = importlib.import_module("intellicrack_hexcore")
    hex_doc_cls: object = getattr(module, "HexDocument", None)
    return hex_doc_cls is not None and hasattr(hex_doc_cls, "add_va_mapping")


class TestManualVAMappings:
    """Tests for manually adding, removing, and listing VA mappings."""

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_set_va_base_and_list(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify adding a VA mapping and listing it returns correct values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va.bin"
        f.write_bytes(b"\x00" * 1024)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        mappings = _run(bridge.list_va_mappings())
        assert len(mappings) >= 1
        found = any(m["file_offset"] == 0 and m["virtual_address"] == 0x400000 for m in mappings)
        assert found

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_set_va_base_returns_true(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_va_base returns True and the mapping is persisted with all exact field values.

        The return value alone is not a sufficient gate; this test also asserts
        that ``list_va_mappings`` reflects the newly registered mapping so the
        gate fails if ``set_va_base`` returns ``True`` without actually storing
        anything. All three fields (file_offset, virtual_address, length) must
        appear together in the same mapping entry to rule out partial storage.

        Additionally, a second mapping with different values is registered to
        confirm the bridge accumulates mappings rather than overwriting the first,
        and that each mapping's fields remain independent and exact.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_ret.bin"
        f.write_bytes(b"\x00" * 0x2000)
        _run(bridge.open_file(str(f)))

        result = _run(bridge.set_va_base(0, 0x400000, 0x200))
        assert result is True, "set_va_base must return True on success"

        mappings = _run(bridge.list_va_mappings())
        assert any(m["file_offset"] == 0 and m["virtual_address"] == 0x400000 and m["length"] == 0x200 for m in mappings), (
            f"mapping (offset=0, va=0x400000, len=0x200) missing from list after set_va_base; got {mappings!r}"
        )

        result2 = _run(bridge.set_va_base(0x1000, 0x500000, 0x800))
        assert result2 is True, "set_va_base must return True for the second mapping"

        mappings2 = _run(bridge.list_va_mappings())
        assert any(m["file_offset"] == 0 and m["virtual_address"] == 0x400000 and m["length"] == 0x200 for m in mappings2), (
            f"first mapping (offset=0, va=0x400000, len=0x200) disappeared after adding second; got {mappings2!r}"
        )
        assert any(m["file_offset"] == 0x1000 and m["virtual_address"] == 0x500000 and m["length"] == 0x800 for m in mappings2), (
            f"second mapping (offset=0x1000, va=0x500000, len=0x800) missing; got {mappings2!r}"
        )
        assert len(mappings2) >= 2, f"expected at least 2 mappings after adding two distinct ranges; got {len(mappings2)}: {mappings2!r}"

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_remove_va_mapping(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify removing a VA mapping reduces the list count.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_rm.bin"
        f.write_bytes(b"\x00" * 1024)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        _run(bridge.set_va_base(0x200, 0x401000, 0x100))
        before = _run(bridge.list_va_mappings())
        _run(bridge.remove_va_mapping(0))
        after = _run(bridge.list_va_mappings())
        assert len(after) == len(before) - 1


class TestVAConversion:
    """Tests for file offset to VA and VA to file offset conversions."""

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_file_offset_to_va(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify file_offset_to_va returns the correct virtual address.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_conv.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0x1000, 0x401000, 0x200))
        result = _run(bridge.file_offset_to_va(0x1000))
        assert result == 0x401000

    @pytest.mark.skipif(not _has_native_va_mapping(), reason="native VA mapping not available")
    def test_va_to_file_offset(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify va_to_file_offset returns the correct file offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_conv2.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0x1000, 0x401000, 0x200))
        result = _run(bridge.va_to_file_offset(0x401000))
        assert result == 0x1000

    def test_unmapped_offset_returns_none(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that an unmapped offset returns None.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "va_unmapped.bin"
        f.write_bytes(b"\x00" * 8192)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_va_base(0, 0x400000, 0x200))
        result = _run(bridge.file_offset_to_va(0x5000))
        assert result is None


class TestAutoDetectVAMappings:
    """Tests for auto-detecting VA mappings from PE and ELF headers."""

    def test_auto_detect_pe_va_mappings(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify auto-detection on PE produces mappings with exact ImageBase-based VAs.

        The PE fixture is built with PE_FULL_IMAGE_BASE = 0x00400000, a .text
        section at VirtualAddress 0x1000 (raw offset 0x200, size 0x200), and a
        .data section at VirtualAddress 0x2000 (raw offset 0x400, size 0x100).
        The header mapping uses file_offset=0, VA=ImageBase, and
        length=e_lfanew=0x80 (the byte offset of the PE signature in the
        fixture).

        Auto-detection must produce exactly 3 mappings (header + 2 sections).
        Every field of every mapping is verified against the independently-known
        oracle values derived from the fixture layout, not from the production
        code output.

        Additionally, the bridge's file_offset_to_va and va_to_file_offset
        round-trips are exercised after auto-detect to confirm the mappings are
        registered in the native document and not merely returned as a Python
        list without being stored.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        mappings = _run(bridge.auto_detect_va_mappings())
        assert len(mappings) == _PE_ORACLE_MAPPING_COUNT, (
            f"expected {_PE_ORACLE_MAPPING_COUNT} PE VA mappings (header + 2 sections); got {len(mappings)}: {mappings!r}"
        )

        vas = {m["virtual_address"] for m in mappings}
        assert _PE_ORACLE_HEADER_VA in vas, f"ImageBase mapping (VA=0x{_PE_ORACLE_HEADER_VA:X}) missing; got {vas!r}"
        assert _PE_ORACLE_TEXT_VA in vas, f".text mapping (VA=0x{_PE_ORACLE_TEXT_VA:X}) missing; got {vas!r}"
        assert _PE_ORACLE_DATA_VA in vas, f".data mapping (VA=0x{_PE_ORACLE_DATA_VA:X}) missing; got {vas!r}"

        header_map = next(m for m in mappings if m["virtual_address"] == _PE_ORACLE_HEADER_VA)
        assert header_map["file_offset"] == _PE_ORACLE_HEADER_FILE_OFFSET, (
            f"header mapping must have file_offset=0x{_PE_ORACLE_HEADER_FILE_OFFSET:X}; got 0x{header_map['file_offset']:X}"
        )
        assert header_map["length"] == _PE_ORACLE_HEADER_LENGTH, (
            f"header mapping length must be 0x{_PE_ORACLE_HEADER_LENGTH:X} (== e_lfanew); got 0x{header_map['length']:X}"
        )

        text_map = next(m for m in mappings if m["virtual_address"] == _PE_ORACLE_TEXT_VA)
        assert text_map["file_offset"] == _PE_ORACLE_TEXT_FILE_OFFSET, (
            f".text mapping must have file_offset=0x{_PE_ORACLE_TEXT_FILE_OFFSET:X}; got 0x{text_map['file_offset']:X}"
        )
        assert text_map["length"] == _PE_ORACLE_TEXT_LENGTH, (
            f".text mapping length must be 0x{_PE_ORACLE_TEXT_LENGTH:X}; got 0x{text_map['length']:X}"
        )

        data_map = next(m for m in mappings if m["virtual_address"] == _PE_ORACLE_DATA_VA)
        assert data_map["file_offset"] == _PE_ORACLE_DATA_FILE_OFFSET, (
            f".data mapping must have file_offset=0x{_PE_ORACLE_DATA_FILE_OFFSET:X}; got 0x{data_map['file_offset']:X}"
        )
        assert data_map["length"] == _PE_ORACLE_DATA_LENGTH, (
            f".data mapping length must be 0x{_PE_ORACLE_DATA_LENGTH:X}; got 0x{data_map['length']:X}"
        )

        text_va_result = _run(bridge.file_offset_to_va(_PE_ORACLE_TEXT_FILE_OFFSET))
        assert text_va_result == _PE_ORACLE_TEXT_VA, (
            f"file_offset_to_va(0x{_PE_ORACLE_TEXT_FILE_OFFSET:X}) after auto-detect "
            f"must return 0x{_PE_ORACLE_TEXT_VA:X}; got {text_va_result!r}"
        )

        text_offset_result = _run(bridge.va_to_file_offset(_PE_ORACLE_TEXT_VA))
        assert text_offset_result == _PE_ORACLE_TEXT_FILE_OFFSET, (
            f"va_to_file_offset(0x{_PE_ORACLE_TEXT_VA:X}) after auto-detect "
            f"must return 0x{_PE_ORACLE_TEXT_FILE_OFFSET:X}; got {text_offset_result!r}"
        )

    def test_auto_detect_elf_va_mappings(self, bridge: HexEditorBridge, elf_binary_with_loads: Path) -> None:
        """Verify auto-detection on ELF produces exact PT_LOAD segment VA mappings.

        The ELF fixture is built with two PT_LOAD segments:
         - segment 1: p_offset=0x1000, p_vaddr=0x400000, p_filesz=0x200
         - segment 2: p_offset=0x2000, p_vaddr=0x401000, p_filesz=0x100

        Both p_vaddr values must appear in the returned mappings. Checking only
        offsets does not catch a reversed or shifted VA calculation. The length
        of each segment must also match exactly; a bridge that stores p_memsz
        instead of p_filesz would be caught here.

        After auto-detect, the bridge's file_offset_to_va and va_to_file_offset
        are exercised to confirm the mappings were registered in the native
        document (not just returned as a Python list) and produce the correct
        inverse translation.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            elf_binary_with_loads: Path to an ELF binary with PT_LOAD segments.
        """
        _run(bridge.open_file(str(elf_binary_with_loads)))
        mappings = _run(bridge.auto_detect_va_mappings())
        assert len(mappings) == _ELF_ORACLE_MAPPING_COUNT, (
            f"expected {_ELF_ORACLE_MAPPING_COUNT} ELF PT_LOAD mappings; got {len(mappings)}: {mappings!r}"
        )

        offsets = {m["file_offset"] for m in mappings}
        assert _ELF_ORACLE_SEG1_FILE_OFFSET in offsets, f"PT_LOAD1 file_offset=0x{_ELF_ORACLE_SEG1_FILE_OFFSET:X} missing; got {offsets!r}"
        assert _ELF_ORACLE_SEG2_FILE_OFFSET in offsets, f"PT_LOAD2 file_offset=0x{_ELF_ORACLE_SEG2_FILE_OFFSET:X} missing; got {offsets!r}"

        vas = {m["virtual_address"] for m in mappings}
        assert _ELF_ORACLE_SEG1_VA in vas, f"PT_LOAD1 p_vaddr=0x{_ELF_ORACLE_SEG1_VA:X} missing from VAs; got {vas!r}"
        assert _ELF_ORACLE_SEG2_VA in vas, f"PT_LOAD2 p_vaddr=0x{_ELF_ORACLE_SEG2_VA:X} missing from VAs; got {vas!r}"

        seg1 = next(m for m in mappings if m["file_offset"] == _ELF_ORACLE_SEG1_FILE_OFFSET)
        assert seg1["virtual_address"] == _ELF_ORACLE_SEG1_VA, (
            f"PT_LOAD1 virtual_address must be 0x{_ELF_ORACLE_SEG1_VA:X}; got 0x{seg1['virtual_address']:X}"
        )
        assert seg1["length"] == _ELF_ORACLE_SEG1_LENGTH, (
            f"PT_LOAD1 length must be 0x{_ELF_ORACLE_SEG1_LENGTH:X} (== p_filesz); got 0x{seg1['length']:X}"
        )

        seg2 = next(m for m in mappings if m["file_offset"] == _ELF_ORACLE_SEG2_FILE_OFFSET)
        assert seg2["virtual_address"] == _ELF_ORACLE_SEG2_VA, (
            f"PT_LOAD2 virtual_address must be 0x{_ELF_ORACLE_SEG2_VA:X}; got 0x{seg2['virtual_address']:X}"
        )
        assert seg2["length"] == _ELF_ORACLE_SEG2_LENGTH, (
            f"PT_LOAD2 length must be 0x{_ELF_ORACLE_SEG2_LENGTH:X} (== p_filesz); got 0x{seg2['length']:X}"
        )

        seg1_va_result = _run(bridge.file_offset_to_va(_ELF_ORACLE_SEG1_FILE_OFFSET))
        assert seg1_va_result == _ELF_ORACLE_SEG1_VA, (
            f"file_offset_to_va(0x{_ELF_ORACLE_SEG1_FILE_OFFSET:X}) after auto-detect "
            f"must return 0x{_ELF_ORACLE_SEG1_VA:X}; got {seg1_va_result!r}"
        )

        seg1_offset_result = _run(bridge.va_to_file_offset(_ELF_ORACLE_SEG1_VA))
        assert seg1_offset_result == _ELF_ORACLE_SEG1_FILE_OFFSET, (
            f"va_to_file_offset(0x{_ELF_ORACLE_SEG1_VA:X}) after auto-detect "
            f"must return 0x{_ELF_ORACLE_SEG1_FILE_OFFSET:X}; got {seg1_offset_result!r}"
        )

    def test_auto_detect_non_pe_elf_returns_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify auto-detection on a non-PE/ELF file returns an empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "random.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        mappings = _run(bridge.auto_detect_va_mappings())
        assert mappings == []

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify auto_detect_va_mappings raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.auto_detect_va_mappings())
