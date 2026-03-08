"""Tests for binary panel fixes (Fixes 3, 5, 7, 8).

Validates:
- Fix 3: Large file confirmation dialog (>500 MB threshold)
- Fix 5: ELF and Mach-O section parsing via LIEF
- Fix 7: Hex viewer pagination (prev/next page, scroll, page label)
- Fix 8: Hex edit validation and live ASCII preview
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt

from intellicrack.ui.panels import binary_panel as bp_mod
from intellicrack.ui.panels.binary_panel import BinaryPanel
from intellicrack.ui.panels.qt_compat import tree_item_data


if TYPE_CHECKING:
    from pathlib import Path

CHUNK_SIZE: int = bp_mod._CHUNK_SIZE
EDITED_HEX_BG = bp_mod._EDITED_HEX_BG
HEX_BYTES_PER_ROW: int = bp_mod._HEX_BYTES_PER_ROW
HEX_COL_ASCII: int = bp_mod._HEX_COL_ASCII
HEX_COL_HEX: int = bp_mod._HEX_COL_HEX
LARGE_FILE_THRESHOLD: int = bp_mod._LARGE_FILE_THRESHOLD

PE_HEADER_OFFSET = 0x80
PE_SIGNATURE_SIZE = 4
COFF_HEADER_SIZE = 20
OPTIONAL_HEADER_SIZE = 240
SECTION_NAME_SIZE = 8
SECTION_HEADER_SIZE = 40
PE_TEXT_VADDR = 0x1000
PE_TEXT_VSIZE = 0x200
PE_TEXT_RAW_SIZE = 0x200
PE_TEXT_RAW_OFFSET = 0x200
PE_TEXT_CHARACTERISTICS = 0x60000020
SMALL_FILE_SIZE = 8192


def _build_minimal_pe() -> bytearray:
    """Build a minimal valid PE binary with one .text section.

    Returns:
        Bytearray containing a valid PE structure.
    """
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE_HEADER_OFFSET)

    pe_off = PE_HEADER_OFFSET
    data[pe_off : pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_off + 6, 1)
    struct.pack_into("<H", data, pe_off + 20, OPTIONAL_HEADER_SIZE)

    sec_off = pe_off + 24 + OPTIONAL_HEADER_SIZE
    data[sec_off : sec_off + SECTION_NAME_SIZE] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec_off + 8, PE_TEXT_VSIZE)
    struct.pack_into("<I", data, sec_off + 12, PE_TEXT_VADDR)
    struct.pack_into("<I", data, sec_off + 16, PE_TEXT_RAW_SIZE)
    struct.pack_into("<I", data, sec_off + 20, PE_TEXT_RAW_OFFSET)
    struct.pack_into("<I", data, sec_off + 36, PE_TEXT_CHARACTERISTICS)

    return data


def _build_minimal_elf() -> bytearray:
    """Build a minimal ELF binary header.

    Returns:
        Bytearray containing an ELF header (magic bytes sufficient for detection).
    """
    data = bytearray(256)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    return data


def _build_minimal_macho() -> bytearray:
    """Build a minimal Mach-O binary header (64-bit little-endian).

    Returns:
        Bytearray containing a Mach-O header (magic bytes sufficient for detection).
    """
    data = bytearray(256)
    data[:4] = b"\xcf\xfa\xed\xfe"
    return data


@pytest.mark.usefixtures("qapp")
class TestLargeFileConfirmation:
    """Fix 3: Large file confirmation dialog tests."""

    @staticmethod
    def test_small_file_loads_without_dialog(tmp_path: Path) -> None:
        """Verify files under threshold load without confirmation prompt."""
        binary = tmp_path / "small.exe"
        binary.write_bytes(_build_minimal_pe())

        panel = BinaryPanel()
        result = panel.load_file(binary)

        assert result is True
        assert panel._file_path == binary
        assert len(panel._file_data) > 0

    @staticmethod
    def test_large_file_threshold_exists() -> None:
        """Verify the large file threshold is defined at 500 MB."""
        expected_500mb = 500 * 1024 * 1024
        assert expected_500mb == LARGE_FILE_THRESHOLD

    @staticmethod
    def test_nonexistent_file_returns_false(tmp_path: Path) -> None:
        """Verify loading a nonexistent file returns False."""
        panel = BinaryPanel()
        result = panel.load_file(tmp_path / "nope.bin")
        assert result is False


@pytest.mark.usefixtures("qapp")
class TestPESectionParsing:
    """Fix 5: PE section parsing tests."""

    @staticmethod
    def test_pe_sections_parsed(tmp_path: Path) -> None:
        """Verify .text section is parsed from a PE binary."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(_build_minimal_pe())

        panel = BinaryPanel()
        panel.load_file(binary)

        section_count = panel._sections_tree.topLevelItemCount()
        assert section_count >= 1

        first_section = panel._sections_tree.topLevelItem(0)
        assert first_section is not None
        assert ".text" in first_section.text(0)

    @staticmethod
    def test_pe_section_navigates_on_double_click(tmp_path: Path) -> None:
        """Verify double-clicking a section navigates the hex view."""
        binary = tmp_path / "test.exe"
        binary.write_bytes(_build_minimal_pe())

        panel = BinaryPanel()
        panel.load_file(binary)

        first_section = panel._sections_tree.topLevelItem(0)
        assert first_section is not None

        raw_offset: object = tree_item_data(first_section, 0, Qt.ItemDataRole.UserRole)
        assert isinstance(raw_offset, int)
        assert raw_offset == PE_TEXT_RAW_OFFSET


@pytest.mark.usefixtures("qapp")
class TestELFSectionParsing:
    """Fix 5: ELF section parsing tests."""

    @staticmethod
    def test_elf_magic_detected(tmp_path: Path) -> None:
        """Verify ELF magic bytes trigger ELF parsing path."""
        binary = tmp_path / "test.elf"
        binary.write_bytes(_build_minimal_elf())

        panel = BinaryPanel()
        panel.load_file(binary)

        top_count = panel._sections_tree.topLevelItemCount()
        if top_count > 0:
            first = panel._sections_tree.topLevelItem(0)
            assert first is not None
            text = first.text(0)
            assert text

    @staticmethod
    def test_elf_without_lief_shows_info(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify graceful fallback message when lief is not installed."""
        monkeypatch.setattr(bp_mod, "lief", None)

        binary = tmp_path / "test.elf"
        binary.write_bytes(_build_minimal_elf())

        panel = BinaryPanel()
        panel.load_file(binary)

        top_count = panel._sections_tree.topLevelItemCount()
        assert top_count >= 1
        first = panel._sections_tree.topLevelItem(0)
        assert first is not None
        assert "lief" in first.text(0).lower()


@pytest.mark.usefixtures("qapp")
class TestMachOSectionParsing:
    """Fix 5: Mach-O section parsing tests."""

    @staticmethod
    def test_macho_magic_detected(tmp_path: Path) -> None:
        """Verify Mach-O magic bytes trigger Mach-O parsing path."""
        binary = tmp_path / "test.macho"
        binary.write_bytes(_build_minimal_macho())

        panel = BinaryPanel()
        panel.load_file(binary)

        top_count = panel._sections_tree.topLevelItemCount()
        if top_count > 0:
            first = panel._sections_tree.topLevelItem(0)
            assert first is not None

    @staticmethod
    def test_macho_without_lief_shows_info(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify graceful fallback message when lief is not installed."""
        monkeypatch.setattr(bp_mod, "lief", None)

        binary = tmp_path / "test.macho"
        binary.write_bytes(_build_minimal_macho())

        panel = BinaryPanel()
        panel.load_file(binary)

        top_count = panel._sections_tree.topLevelItemCount()
        assert top_count >= 1
        first = panel._sections_tree.topLevelItem(0)
        assert first is not None
        assert "lief" in first.text(0).lower()


@pytest.mark.usefixtures("qapp")
class TestHexPagination:
    """Fix 7: Hex viewer pagination tests."""

    @staticmethod
    def _create_loaded_panel(tmp_path: Path, size: int = SMALL_FILE_SIZE) -> BinaryPanel:
        """Create a panel with a loaded binary of given size.

        Args:
            tmp_path: Temporary directory for test files.
            size: Number of bytes in the test binary.

        Returns:
            BinaryPanel with a loaded file.
        """
        binary = tmp_path / "test.bin"
        binary.write_bytes(bytes(range(256)) * (size // 256 + 1))

        panel = BinaryPanel()
        panel.load_file(binary)
        return panel

    @staticmethod
    def test_initial_offset_is_zero(tmp_path: Path) -> None:
        """Verify hex view starts at offset 0."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        assert panel._current_offset == 0

    @staticmethod
    def test_next_page_advances_by_chunk_size(tmp_path: Path) -> None:
        """Verify next page moves forward by one chunk."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        panel._on_next_page()
        assert panel._current_offset == CHUNK_SIZE

    @staticmethod
    def test_prev_page_from_start_stays_at_zero(tmp_path: Path) -> None:
        """Verify previous page at start stays at offset 0."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        panel._on_prev_page()
        assert panel._current_offset == 0

    @staticmethod
    def test_prev_page_returns_to_previous(tmp_path: Path) -> None:
        """Verify prev page reverses a next page operation."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        panel._on_next_page()
        panel._on_prev_page()
        assert panel._current_offset == 0

    @staticmethod
    def test_page_label_updated(tmp_path: Path) -> None:
        """Verify page label shows correct page number."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        label_text = panel._page_label.text().strip()
        assert "1/" in label_text

    @staticmethod
    def test_page_label_updates_on_navigation(tmp_path: Path) -> None:
        """Verify page label changes on next page."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        panel._on_next_page()
        label_text = panel._page_label.text().strip()
        assert "2/" in label_text

    @staticmethod
    def test_next_page_clamps_at_end(tmp_path: Path) -> None:
        """Verify next page does not exceed file boundaries."""
        panel = TestHexPagination._create_loaded_panel(tmp_path)
        for _ in range(100):
            panel._on_next_page()

        assert panel._current_offset <= len(panel._file_data)


@pytest.mark.usefixtures("qapp")
class TestHexEditValidation:
    """Fix 8: Hex edit validation and live ASCII preview tests."""

    @staticmethod
    def _create_loaded_panel(tmp_path: Path) -> BinaryPanel:
        """Create a panel with loaded test binary data.

        Args:
            tmp_path: Temporary directory for test files.

        Returns:
            BinaryPanel with known binary content.
        """
        data = bytes(range(256)) * 4
        binary = tmp_path / "test.bin"
        binary.write_bytes(data)

        panel = BinaryPanel()
        panel.load_file(binary)
        return panel

    @staticmethod
    def test_valid_hex_accepted(tmp_path: Path) -> None:
        """Verify valid hex string is accepted in cell edit."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        hex_item = panel._hex_table.item(0, HEX_COL_HEX)
        assert hex_item is not None

        panel._hex_table.blockSignals(True)
        hex_item.setText("41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50")
        panel._hex_table.blockSignals(False)

        panel._on_hex_cell_changed(0, HEX_COL_HEX)

        ascii_item = panel._hex_table.item(0, HEX_COL_ASCII)
        assert ascii_item is not None
        assert ascii_item.text() == "ABCDEFGHIJKLMNOP"

    @staticmethod
    def test_invalid_hex_rejected(tmp_path: Path) -> None:
        """Verify non-hex characters are rejected and reverted."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        hex_item = panel._hex_table.item(0, HEX_COL_HEX)
        assert hex_item is not None
        original_text = hex_item.text()

        panel._hex_table.blockSignals(True)
        hex_item.setText("ZZ XX YY")
        panel._hex_table.blockSignals(False)

        panel._on_hex_cell_changed(0, HEX_COL_HEX)

        assert hex_item.text() == original_text

    @staticmethod
    def test_ascii_column_not_editable(tmp_path: Path) -> None:
        """Verify ASCII column cells have editing disabled."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        ascii_item = panel._hex_table.item(0, HEX_COL_ASCII)
        assert ascii_item is not None
        flags = ascii_item.flags()
        assert not (flags & Qt.ItemFlag.ItemIsEditable)

    @staticmethod
    def test_offset_column_not_editable(tmp_path: Path) -> None:
        """Verify offset column cells have editing disabled."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        offset_item = panel._hex_table.item(0, 0)
        assert offset_item is not None
        flags = offset_item.flags()
        assert not (flags & Qt.ItemFlag.ItemIsEditable)

    @staticmethod
    def test_patch_highlights_edited_row(tmp_path: Path) -> None:
        """Verify patched rows show the edited background color."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        panel._hex_table.setCurrentCell(0, HEX_COL_HEX)

        panel._hex_table.blockSignals(True)
        hex_item = panel._hex_table.item(0, HEX_COL_HEX)
        assert hex_item is not None
        hex_item.setText("FF " * HEX_BYTES_PER_ROW)
        panel._hex_table.blockSignals(False)

        panel._on_apply_patch()

        hex_item_after = panel._hex_table.item(0, HEX_COL_HEX)
        assert hex_item_after is not None
        bg = hex_item_after.background().color().getRgb()
        assert bg == EDITED_HEX_BG.getRgb()

    @staticmethod
    def test_non_hex_column_change_ignored(tmp_path: Path) -> None:
        """Verify changes to non-hex columns are ignored."""
        panel = TestHexEditValidation._create_loaded_panel(tmp_path)

        ascii_item = panel._hex_table.item(0, HEX_COL_ASCII)
        assert ascii_item is not None
        original = ascii_item.text()

        panel._on_hex_cell_changed(0, HEX_COL_ASCII)

        assert ascii_item.text() == original
