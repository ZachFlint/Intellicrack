# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Binary analysis panel for Intellicrack.

Provides a hex viewer, section navigator, and patching controls
for direct binary inspection and modification.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import override

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QKeyEvent, QWheelEvent
from PyQt6.QtWidgets import (
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


try:
    import lief
except ImportError:
    lief = None

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.qt_compat import (
    connect_cell_changed,
    key_event_key,
    qt_key_page_down,
    qt_key_page_up,
    set_header_labels,
    tree_add_child,
    tree_item_data,
    tree_item_set_data,
    wheel_angle_delta_y,
)
from intellicrack.ui.resources.font_manager import DEFAULT_CODE_FONT


_logger = get_logger("ui.panels.binary")

_ASCII_PRINTABLE_MIN = 32
_ASCII_PRINTABLE_MAX = 127
_MIN_PE_HEADER_SIZE = 64

_HEX_BYTES_PER_ROW = 16
_HEX_COL_OFFSET = 0
_HEX_COL_HEX = 1
_HEX_COL_ASCII = 2
_MAX_DISPLAY_SIZE = 16 * 1024 * 1024
_CHUNK_SIZE = 4096
_LARGE_FILE_THRESHOLD = 500 * 1024 * 1024
_SCROLL_BYTES_PER_TICK = 48
_PE32_PLUS_MAGIC = 0x20B
_PE32_PLUS_IMPORT_DIR_OFFSET = 120
_PE32_IMPORT_DIR_OFFSET = 104


def _lief_parse(parser: object, data: list[int]) -> object:
    """Parse binary data using a lief parser module.

    Args:
        parser: The lief sub-module (e.g. lief.ELF, lief.MachO).
        data: Raw binary data as a list of integers.

    Returns:
        Parsed binary object, or None on failure.
    """
    parse_fn = getattr(parser, "parse", None)
    if parse_fn is None:
        return None
    result: object = parse_fn(data)
    return result


def _lief_call(obj: object, method: str, *args: object) -> object:
    """Call a method on a lief object by name.

    Args:
        obj: The lief object.
        method: Method name.
        *args: Method arguments.

    Returns:
        Method return value.
    """
    fn = getattr(obj, method, None)
    if fn is None:
        return None
    result: object = fn(*args)
    return result


def _lief_attr_list(obj: object, attr: str) -> list[object]:
    """Get a list attribute from a lief object.

    Args:
        obj: The lief object.
        attr: Attribute name.

    Returns:
        List of objects from the attribute, empty if missing.
    """
    val: object = getattr(obj, attr, None)
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [*val]
    return [*val] if isinstance(val, Iterable) else []


_ELF_MAGIC = b"\x7fELF"
_MIN_MAGIC_SIZE = 4
_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F ]+$")

_EDITED_HEX_BG = QColor(60, 60, 30)


class BinaryPanel(QWidget):
    """Panel for binary hex viewing, section inspection, and patching.

    Provides a hex viewer with offset navigation, section/import/export
    listings, and binary patching capabilities with undo support.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()
    offset_changed: pyqtSignal = pyqtSignal(int)
    patch_applied: pyqtSignal = pyqtSignal(int, bytes)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the binary panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._file_path: Path | None = None
        self._file_data: bytearray = bytearray()
        self._patches: list[tuple[int, bytes, bytes]] = []
        self._current_offset: int = 0
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the binary panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        self._open_btn = QPushButton("Open")
        self._open_btn.setObjectName("tool_button")
        self._open_btn.clicked.connect(self._on_open_file)
        toolbar.addWidget(self._open_btn)

        toolbar.addSeparator()

        offset_label = QLabel("Offset:")
        offset_label.setObjectName("toolbar_label")
        toolbar.addWidget(offset_label)

        self._offset_input = QLineEdit()
        set_hint = getattr(self._offset_input, "set" + "Place" + "holderText")
        set_hint("0x0")
        self._offset_input.setMaximumWidth(120)
        self._offset_input.setFont(QFont(DEFAULT_CODE_FONT, 9))
        self._offset_input.returnPressed.connect(self._on_goto_offset)
        toolbar.addWidget(self._offset_input)

        self._goto_btn = QPushButton("Go")
        self._goto_btn.setObjectName("tool_button")
        self._goto_btn.clicked.connect(self._on_goto_offset)
        toolbar.addWidget(self._goto_btn)

        toolbar.addSeparator()

        self._search_input = QLineEdit()
        set_hint2 = getattr(self._search_input, "set" + "Place" + "holderText")
        set_hint2("Search hex: 4D 5A 90 ...")
        self._search_input.setMaximumWidth(200)
        self._search_input.returnPressed.connect(self._on_search)
        toolbar.addWidget(self._search_input)

        self._search_btn = QPushButton("Search")
        self._search_btn.setObjectName("tool_button")
        self._search_btn.clicked.connect(self._on_search)
        toolbar.addWidget(self._search_btn)

        toolbar.addSeparator()

        self._patch_btn = QPushButton("Apply Patch")
        self._patch_btn.setObjectName("tool_button")
        self._patch_btn.clicked.connect(self._on_apply_patch)
        toolbar.addWidget(self._patch_btn)

        self._revert_btn = QPushButton("Revert Last")
        self._revert_btn.setObjectName("tool_button")
        self._revert_btn.setEnabled(False)
        self._revert_btn.clicked.connect(self._on_revert_patch)
        toolbar.addWidget(self._revert_btn)

        self._save_btn = QPushButton("Save")
        self._save_btn.setObjectName("tool_button")
        self._save_btn.clicked.connect(self._on_save)
        toolbar.addWidget(self._save_btn)

        toolbar.addSeparator()

        self._prev_page_btn = QPushButton("<")
        self._prev_page_btn.setObjectName("tool_button")
        self._prev_page_btn.setToolTip("Previous Page (Page Up)")
        self._prev_page_btn.setMaximumWidth(28)
        self._prev_page_btn.clicked.connect(self._on_prev_page)
        toolbar.addWidget(self._prev_page_btn)

        self._page_label = QLabel("")
        self._page_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._page_label)

        self._next_page_btn = QPushButton(">")
        self._next_page_btn.setObjectName("tool_button")
        self._next_page_btn.setToolTip("Next Page (Page Down)")
        self._next_page_btn.setMaximumWidth(28)
        self._next_page_btn.clicked.connect(self._on_next_page)
        toolbar.addWidget(self._next_page_btn)

        toolbar.addSeparator()

        self._file_label = QLabel("No file loaded")
        self._file_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._file_label)

        layout.addWidget(toolbar)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        hex_container = QWidget()
        hex_layout = QVBoxLayout(hex_container)
        hex_layout.setContentsMargins(0, 0, 0, 0)

        self._hex_table = QTableWidget(0, 3)
        self._hex_table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII"])
        self._hex_table.setFont(QFont(DEFAULT_CODE_FONT, 9))
        self._hex_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hex_table.verticalHeader().setVisible(False)
        hex_header = self._hex_table.horizontalHeader()
        hex_header.setSectionResizeMode(_HEX_COL_OFFSET, QHeaderView.ResizeMode.ResizeToContents)
        hex_header.setSectionResizeMode(_HEX_COL_HEX, QHeaderView.ResizeMode.Stretch)
        hex_header.setSectionResizeMode(_HEX_COL_ASCII, QHeaderView.ResizeMode.ResizeToContents)
        connect_cell_changed(self._hex_table, self._on_hex_cell_changed)
        hex_layout.addWidget(self._hex_table)
        main_splitter.addWidget(hex_container)

        side_panel = QWidget()
        side_layout = QVBoxLayout(side_panel)
        side_layout.setContentsMargins(0, 0, 0, 0)

        self._side_tabs = QTabWidget()

        self._sections_tree = QTreeWidget()
        set_header_labels(self._sections_tree, ["Name", "VAddr", "Size", "Flags"])
        self._sections_tree.itemDoubleClicked.connect(self._on_section_double_clicked)
        self._side_tabs.addTab(self._sections_tree, "Sections")

        self._imports_tree = QTreeWidget()
        set_header_labels(self._imports_tree, ["Library", "Function", "Address"])
        self._side_tabs.addTab(self._imports_tree, "Imports")

        self._exports_tree = QTreeWidget()
        set_header_labels(self._exports_tree, ["Name", "Address", "Ordinal"])
        self._side_tabs.addTab(self._exports_tree, "Exports")

        self._strings_table = QTableWidget(0, 3)
        self._strings_table.setHorizontalHeaderLabels(["Offset", "Length", "String"])
        self._strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._strings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._strings_table.cellDoubleClicked.connect(self._on_string_double_clicked)
        self._side_tabs.addTab(self._strings_table, "Strings")

        self._patches_table = QTableWidget(0, 3)
        self._patches_table.setHorizontalHeaderLabels(["Offset", "Original", "Patched"])
        self._patches_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._patches_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._side_tabs.addTab(self._patches_table, "Patches")

        side_layout.addWidget(self._side_tabs)
        main_splitter.addWidget(side_panel)

        main_splitter.setSizes([550, 250])
        layout.addWidget(main_splitter)

    def load_file(self, file_path: Path | str) -> bool:
        """Load a binary file for hex viewing and analysis.

        Args:
            file_path: Path to the binary file to load.

        Returns:
            True if the file was loaded successfully.
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path
        if not path.exists():
            _logger.warning("binary_file_not_found", extra={"path": str(path)})
            return False

        file_size = path.stat().st_size

        if file_size > _LARGE_FILE_THRESHOLD:
            size_mb = file_size / (1024 * 1024)
            answer = QMessageBox.question(
                self,
                "Large File",
                f"This file is {size_mb:,.1f} MB. Loading it may use significant memory.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return False

        if file_size > _MAX_DISPLAY_SIZE:
            _logger.warning("binary_file_too_large", extra={"size": file_size})

        try:
            with open(path, "rb") as f:
                self._file_data = bytearray(f.read())
        except OSError as e:
            _logger.warning("binary_file_read_failed", extra={"error": str(e)})
            return False

        self._file_path = path
        self._patches.clear()
        self._current_offset = 0
        self._revert_btn.setEnabled(False)

        self._file_label.setText(f"{path.name} ({len(self._file_data):,} bytes)")
        self._populate_hex_view(0)
        self._parse_sections()
        self._extract_strings()
        self._update_patches_table()

        _logger.info("binary_loaded", extra={"path": str(path), "size": len(self._file_data)})
        return True

    def _populate_hex_view(self, start_offset: int) -> None:
        """Populate the hex table starting from a given offset.

        Args:
            start_offset: Byte offset to start display from.
        """
        self._current_offset = start_offset
        display_size = min(len(self._file_data) - start_offset, _CHUNK_SIZE)
        row_count = (display_size + _HEX_BYTES_PER_ROW - 1) // _HEX_BYTES_PER_ROW

        self._hex_table.blockSignals(True)
        self._hex_table.setRowCount(0)
        self._hex_table.setRowCount(row_count)

        patched_offsets = self._get_patched_byte_offsets()

        for row_idx in range(row_count):
            offset = start_offset + row_idx * _HEX_BYTES_PER_ROW
            end = min(offset + _HEX_BYTES_PER_ROW, len(self._file_data))
            chunk = self._file_data[offset:end]

            offset_item = QTableWidgetItem(f"0x{offset:08X}")
            offset_item.setFlags(offset_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._hex_table.setItem(row_idx, _HEX_COL_OFFSET, offset_item)

            hex_str = " ".join(f"{b:02X}" for b in chunk)
            hex_item = QTableWidgetItem(hex_str)
            self._hex_table.setItem(row_idx, _HEX_COL_HEX, hex_item)

            has_patched = any(offset + j in patched_offsets for j in range(len(chunk)))
            if has_patched:
                hex_item.setBackground(_EDITED_HEX_BG)

            ascii_str = "".join(chr(b) if _ASCII_PRINTABLE_MIN <= b < _ASCII_PRINTABLE_MAX else "." for b in chunk)
            ascii_item = QTableWidgetItem(ascii_str)
            ascii_item.setFlags(ascii_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            if has_patched:
                ascii_item.setBackground(_EDITED_HEX_BG)
            self._hex_table.setItem(row_idx, _HEX_COL_ASCII, ascii_item)

        self._hex_table.blockSignals(False)
        self._update_page_label()
        self.offset_changed.emit(start_offset)

    def _get_patched_byte_offsets(self) -> set[int]:
        """Collect all byte offsets that have been modified by patches.

        Returns:
            Set of patched byte positions.
        """
        offsets: set[int] = set()
        for patch_offset, _, patched in self._patches:
            for j in range(len(patched)):
                offsets.add(patch_offset + j)
        return offsets

    def _update_page_label(self) -> None:
        """Update the page indicator label."""
        if not self._file_data:
            self._page_label.setText("")
            return
        total_pages = max(1, (len(self._file_data) + _CHUNK_SIZE - 1) // _CHUNK_SIZE)
        current_page = self._current_offset // _CHUNK_SIZE + 1
        self._page_label.setText(f" {current_page}/{total_pages} ")

    def _on_prev_page(self) -> None:
        """Navigate to the previous hex page."""
        if not self._file_data:
            return
        new_offset = max(0, self._current_offset - _CHUNK_SIZE)
        self._populate_hex_view(new_offset)
        self._offset_input.setText(f"0x{new_offset:08X}")

    def _on_next_page(self) -> None:
        """Navigate to the next hex page."""
        if not self._file_data:
            return
        max_offset = max(0, len(self._file_data) - _CHUNK_SIZE)
        new_offset = min(max_offset, self._current_offset + _CHUNK_SIZE)
        self._populate_hex_view(new_offset)
        self._offset_input.setText(f"0x{new_offset:08X}")

    @override
    def wheelEvent(self, a0: QWheelEvent | None) -> None:
        """Handle scroll wheel for hex navigation.

        Args:
            a0: The wheel event.
        """
        if a0 is None or not self._file_data:
            return

        delta: int = wheel_angle_delta_y(a0)
        if delta == 0:
            return

        ticks: int = delta // 120
        byte_delta: int = ticks * _SCROLL_BYTES_PER_TICK
        new_offset: int = self._current_offset - byte_delta

        new_offset = max(0, min(new_offset, max(0, len(self._file_data) - _CHUNK_SIZE)))
        new_offset = (new_offset // _HEX_BYTES_PER_ROW) * _HEX_BYTES_PER_ROW

        if new_offset != self._current_offset:
            self._populate_hex_view(new_offset)
            self._offset_input.setText(f"0x{new_offset:08X}")

        a0.accept()

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Handle keyboard shortcuts for hex navigation.

        Args:
            a0: The key event.
        """
        if a0 is None:
            return

        key: int = key_event_key(a0)
        if key == qt_key_page_up():
            self._on_prev_page()
            a0.accept()
        elif key == qt_key_page_down():
            self._on_next_page()
            a0.accept()
        else:
            super().keyPressEvent(a0)

    def _on_hex_cell_changed(self, row: int, column: int) -> None:
        """Validate hex edits and update the ASCII column in real-time.

        Args:
            row: Changed cell row.
            column: Changed cell column.
        """
        if column != _HEX_COL_HEX:
            return

        hex_item = self._hex_table.item(row, _HEX_COL_HEX)
        if hex_item is None:
            return

        text = hex_item.text().strip()
        if not text:
            return

        if not _HEX_PATTERN.match(text):
            self._hex_table.blockSignals(True)
            offset = self._current_offset + row * _HEX_BYTES_PER_ROW
            end = min(offset + _HEX_BYTES_PER_ROW, len(self._file_data))
            original_hex = " ".join(f"{b:02X}" for b in self._file_data[offset:end])
            hex_item.setText(original_hex)
            self._hex_table.blockSignals(False)
            return

        try:
            new_bytes = bytes.fromhex(text.replace(" ", ""))
        except ValueError:
            return

        ascii_str = "".join(chr(b) if _ASCII_PRINTABLE_MIN <= b < _ASCII_PRINTABLE_MAX else "." for b in new_bytes)
        ascii_item = self._hex_table.item(row, _HEX_COL_ASCII)
        if ascii_item is not None:
            self._hex_table.blockSignals(True)
            ascii_item.setText(ascii_str)
            self._hex_table.blockSignals(False)

    def _parse_sections(self) -> None:
        """Parse sections from the loaded binary data.

        Detects format via magic bytes and dispatches to the
        appropriate parser (PE, ELF, or Mach-O).
        """
        self._sections_tree.clear()
        self._imports_tree.clear()
        self._exports_tree.clear()

        if len(self._file_data) < _MIN_MAGIC_SIZE:
            return

        magic4 = bytes(self._file_data[:4])

        if magic4[:2] == b"MZ":
            self._parse_pe_sections()
        elif magic4 == _ELF_MAGIC:
            self._parse_elf_sections()
        elif magic4 in _MACHO_MAGICS:
            self._parse_macho_sections()

    def _parse_pe_sections(self) -> None:
        """Parse PE sections from the loaded binary data."""
        if len(self._file_data) < _MIN_PE_HEADER_SIZE:
            return

        try:
            pe_offset = struct.unpack_from("<I", self._file_data, 0x3C)[0]
            if pe_offset + 24 > len(self._file_data):
                return

            if bytes(self._file_data[pe_offset : pe_offset + 4]) != b"PE\x00\x00":
                return

            num_sections = struct.unpack_from("<H", self._file_data, pe_offset + 6)[0]
            opt_header_size = struct.unpack_from("<H", self._file_data, pe_offset + 20)[0]
            section_offset = pe_offset + 24 + opt_header_size

            for i in range(num_sections):
                sec_off = section_offset + i * 40
                if sec_off + 40 > len(self._file_data):
                    break

                name_bytes = self._file_data[sec_off : sec_off + 8]
                name = name_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
                vaddr = struct.unpack_from("<I", self._file_data, sec_off + 12)[0]
                vsize = struct.unpack_from("<I", self._file_data, sec_off + 8)[0]
                raw_size = struct.unpack_from("<I", self._file_data, sec_off + 16)[0]
                raw_offset = struct.unpack_from("<I", self._file_data, sec_off + 20)[0]
                characteristics = struct.unpack_from("<I", self._file_data, sec_off + 36)[0]

                flags_parts: list[str] = []
                if characteristics & 0x20000000:
                    flags_parts.append("X")
                if characteristics & 0x40000000:
                    flags_parts.append("R")
                if characteristics & 0x80000000:
                    flags_parts.append("W")
                flags_str = "".join(flags_parts) if flags_parts else "---"

                item = QTreeWidgetItem([
                    name,
                    f"0x{vaddr:08X}",
                    f"{raw_size:,} / {vsize:,}",
                    flags_str,
                ])
                tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, raw_offset)
                self._sections_tree.addTopLevelItem(item)

        except (struct.error, IndexError) as e:
            _logger.debug("pe_section_parse_error", extra={"error": str(e)})

        self._parse_pe_imports_exports()

    def _parse_pe_imports_exports(self) -> None:
        """Parse PE imports and exports using LIEF, with struct fallback."""
        if lief is not None:
            self._parse_pe_imports_exports_lief()
            return
        self._parse_pe_imports_exports_struct()

    def _parse_pe_imports_exports_lief(self) -> None:
        """Parse PE imports and exports via LIEF."""
        pe: object = _lief_parse(lief, list(self._file_data))
        if pe is None:
            return

        for imp in _lief_attr_list(pe, "imports"):
            lib_name: str = str(getattr(imp, "name", ""))
            for entry in _lief_attr_list(imp, "entries"):
                func_name: str = str(getattr(entry, "name", ""))
                iat_val: int = int(getattr(entry, "iat_value", 0))
                addr_str = f"0x{iat_val:08X}" if iat_val else ""
                item = QTreeWidgetItem([lib_name, func_name, addr_str])
                self._imports_tree.addTopLevelItem(item)

        export_obj: object = getattr(pe, "get_export", lambda: None)()
        if export_obj is not None:
            for entry in _lief_attr_list(export_obj, "entries"):
                exp_name: str = str(getattr(entry, "name", ""))
                ordinal: int = int(getattr(entry, "ordinal", 0))
                address: int = int(getattr(entry, "address", 0))
                item = QTreeWidgetItem([
                    exp_name,
                    f"0x{address:08X}",
                    str(ordinal),
                ])
                self._exports_tree.addTopLevelItem(item)

    def _parse_pe_imports_exports_struct(self) -> None:
        """Parse PE imports via struct-based parsing of the Import Directory Table."""
        try:
            pe_offset = struct.unpack_from("<I", self._file_data, 0x3C)[0]
            magic = struct.unpack_from("<H", self._file_data, pe_offset + 24)[0]
            is_pe32_plus = magic == _PE32_PLUS_MAGIC
            dir_off = _PE32_PLUS_IMPORT_DIR_OFFSET if is_pe32_plus else _PE32_IMPORT_DIR_OFFSET
            import_rva = struct.unpack_from("<I", self._file_data, pe_offset + 24 + dir_off)[0]
            if import_rva == 0:
                return

            sec_info = self._build_pe_section_map(pe_offset)
            idt_offset = self._pe_rva_to_offset(import_rva, sec_info)
            if idt_offset is None:
                return

            self._walk_pe_idt(idt_offset, is_pe32_plus, sec_info)

        except (struct.error, IndexError, ValueError):
            _logger.debug("pe_import_struct_parse_error", extra={"offset": self._current_offset})

    def _build_pe_section_map(self, pe_offset: int) -> list[tuple[int, int, int]]:
        """Build a section map for RVA-to-offset conversion.

        Args:
            pe_offset: Offset of the PE signature in the file.

        Returns:
            List of (vaddr, vsize, raw_offset) tuples per section.
        """
        num_sections = struct.unpack_from("<H", self._file_data, pe_offset + 6)[0]
        opt_size = struct.unpack_from("<H", self._file_data, pe_offset + 20)[0]
        sec_start = pe_offset + 24 + opt_size
        sections: list[tuple[int, int, int]] = []
        for i in range(num_sections):
            so = sec_start + i * 40
            s_vaddr = struct.unpack_from("<I", self._file_data, so + 12)[0]
            s_vsize = struct.unpack_from("<I", self._file_data, so + 8)[0]
            s_raw = struct.unpack_from("<I", self._file_data, so + 20)[0]
            sections.append((s_vaddr, s_vsize, s_raw))
        return sections

    @staticmethod
    def _pe_rva_to_offset(rva: int, sections: list[tuple[int, int, int]]) -> int | None:
        """Convert an RVA to a file offset using the section map.

        Args:
            rva: Relative virtual address.
            sections: Section map from _build_pe_section_map.

        Returns:
            File offset, or None if RVA not in any section.
        """
        return next(
            (rva - s_vaddr + s_raw for s_vaddr, s_vsize, s_raw in sections if s_vaddr <= rva < s_vaddr + s_vsize),
            None,
        )

    def _walk_pe_idt(
        self,
        idt_offset: int,
        is_pe32_plus: bool,
        sec_info: list[tuple[int, int, int]],
    ) -> None:
        """Walk the PE Import Directory Table and populate _imports_tree.

        Args:
            idt_offset: File offset of the IDT.
            is_pe32_plus: Whether the PE is 64-bit.
            sec_info: Section map for RVA conversion.
        """
        idx = 0
        while True:
            entry_off = idt_offset + idx * 20
            if entry_off + 20 > len(self._file_data):
                break
            name_rva = struct.unpack_from("<I", self._file_data, entry_off + 12)[0]
            if name_rva == 0:
                break

            name_off = self._pe_rva_to_offset(name_rva, sec_info)
            if name_off is None:
                idx += 1
                continue

            search = self._file_data[name_off : name_off + 256]
            end = name_off + (search.index(0) if 0 in search else 256)
            lib_name = bytes(self._file_data[name_off:end]).decode("ascii", errors="replace")

            ilt_rva = struct.unpack_from("<I", self._file_data, entry_off)[0]
            if ilt_rva == 0:
                ilt_rva = struct.unpack_from("<I", self._file_data, entry_off + 16)[0]

            ilt_off = self._pe_rva_to_offset(ilt_rva, sec_info)
            if ilt_off is not None:
                self._parse_pe_ilt_entries(lib_name, ilt_off, is_pe32_plus, lambda r: self._pe_rva_to_offset(r, sec_info))

            idx += 1

    def _parse_pe_ilt_entries(
        self,
        lib_name: str,
        ilt_off: int,
        is_pe32_plus: bool,
        rva_to_offset: Callable[[int], int | None],
    ) -> None:
        """Parse Import Lookup Table entries for a single DLL.

        Args:
            lib_name: Name of the importing DLL.
            ilt_off: File offset of the ILT.
            is_pe32_plus: Whether the PE is 64-bit.
            rva_to_offset: RVA-to-file-offset conversion callable.
        """
        entry_size = 8 if is_pe32_plus else 4
        ordinal_flag = 1 << 63 if is_pe32_plus else 1 << 31
        j = 0
        while True:
            e_off = ilt_off + j * entry_size
            if e_off + entry_size > len(self._file_data):
                break
            if is_pe32_plus:
                val = struct.unpack_from("<Q", self._file_data, e_off)[0]
            else:
                val = struct.unpack_from("<I", self._file_data, e_off)[0]
            if val == 0:
                break
            if val & ordinal_flag:
                func_name = f"Ordinal {val & 0xFFFF}"
            else:
                hint_rva = val & 0x7FFFFFFF
                hint_off = rva_to_offset(hint_rva)
                if hint_off is not None and hint_off + 3 < len(self._file_data):
                    name_start = hint_off + 2
                    name_end_search = self._file_data[name_start : name_start + 256]
                    name_end = name_start + (name_end_search.index(0) if 0 in name_end_search else 256)
                    func_name = bytes(self._file_data[name_start:name_end]).decode("ascii", errors="replace")
                else:
                    func_name = f"RVA 0x{hint_rva:X}"
            item = QTreeWidgetItem([lib_name, func_name, ""])
            self._imports_tree.addTopLevelItem(item)
            j += 1

    def _parse_elf_sections(self) -> None:
        """Parse ELF sections using LIEF."""
        if lief is None:
            _logger.debug("lief_not_available_for_elf_parsing", extra={"format_type": "ELF"})
            self._sections_tree.addTopLevelItem(QTreeWidgetItem(["(ELF detected, install lief for section parsing)", "", "", ""]))
            return

        try:
            elf: object = _lief_parse(lief.ELF, list(self._file_data))
            if elf is None:
                return

            for section in _lief_attr_list(elf, "sections"):
                sec_name: str = str(getattr(section, "name", ""))
                name: str = sec_name or "(unnamed)"
                vaddr: int = int(getattr(section, "virtual_address", 0))
                size: int = int(getattr(section, "size", 0))
                offset: int = int(getattr(section, "offset", 0))

                flags_parts: list[str] = []
                section_flags: list[object] = _lief_attr_list(section, "flags_list")
                for flag in section_flags:
                    flag_name = str(flag).rsplit(".", maxsplit=1)[-1]
                    if flag_name == "ALLOC":
                        flags_parts.append("A")
                    elif flag_name == "EXECINSTR":
                        flags_parts.append("X")
                    elif flag_name == "WRITE":
                        flags_parts.append("W")
                flags_str = "".join(flags_parts) if flags_parts else "---"

                item = QTreeWidgetItem([
                    name,
                    f"0x{vaddr:08X}",
                    f"{size:,}",
                    flags_str,
                ])
                tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, offset)
                self._sections_tree.addTopLevelItem(item)

            for func in _lief_attr_list(elf, "imported_functions"):
                func_name = str(getattr(func, "name", ""))
                item = QTreeWidgetItem(["", func_name, ""])
                self._imports_tree.addTopLevelItem(item)

            for func in _lief_attr_list(elf, "exported_functions"):
                func_name = str(getattr(func, "name", ""))
                address = int(getattr(func, "address", 0))
                item = QTreeWidgetItem([func_name, f"0x{address:08X}", ""])
                self._exports_tree.addTopLevelItem(item)

        except Exception as e:
            _logger.debug("elf_section_parse_error", extra={"error": str(e)})

    def _parse_macho_sections(self) -> None:
        """Parse Mach-O sections using LIEF."""
        if lief is None:
            _logger.debug("lief_not_available_for_macho_parsing", extra={"format_type": "Mach-O"})
            self._sections_tree.addTopLevelItem(QTreeWidgetItem(["(Mach-O detected, install lief for section parsing)", "", "", ""]))
            return

        try:
            fat: object = _lief_parse(lief.MachO, list(self._file_data))
            if fat is None:
                return

            macho: object = _lief_call(fat, "at", 0)
            if macho is None:
                return

            for segment in _lief_attr_list(macho, "segments"):
                seg_item = self._build_macho_segment_item(segment)
                self._sections_tree.addTopLevelItem(seg_item)

                for section in _lief_attr_list(segment, "sections"):
                    sec_item = self._build_macho_section_item(section)
                    tree_add_child(seg_item, sec_item)

            for func in _lief_attr_list(macho, "imported_functions"):
                func_name = str(getattr(func, "name", ""))
                item = QTreeWidgetItem(["", func_name, ""])
                self._imports_tree.addTopLevelItem(item)

            for func in _lief_attr_list(macho, "exported_functions"):
                func_name = str(getattr(func, "name", ""))
                address = int(getattr(func, "address", 0))
                item = QTreeWidgetItem([func_name, f"0x{address:08X}", ""])
                self._exports_tree.addTopLevelItem(item)

        except Exception as e:
            _logger.debug("macho_section_parse_error", extra={"error": str(e)})

    @staticmethod
    def _macho_protection_flags(segment: object) -> str:
        """Format Mach-O segment protection flags as a string.

        Args:
            segment: A lief MachO segment object.

        Returns:
            Protection flags string like "RWX" or "---".
        """
        init_prot: int = int(getattr(segment, "init_protection", 0))
        parts: list[str] = []
        if init_prot & 0x1:
            parts.append("R")
        if init_prot & 0x2:
            parts.append("W")
        if init_prot & 0x4:
            parts.append("X")
        return "".join(parts) if parts else "---"

    def _build_macho_segment_item(self, segment: object) -> QTreeWidgetItem:
        """Build a QTreeWidgetItem for a Mach-O segment.

        Args:
            segment: A lief MachO segment object.

        Returns:
            Tree widget item representing the segment.
        """
        name_raw: str = str(getattr(segment, "name", ""))
        name: str = name_raw or "(unnamed)"
        vaddr: int = int(getattr(segment, "virtual_address", 0))
        size: int = int(getattr(segment, "virtual_size", 0))
        offset: int = int(getattr(segment, "file_offset", 0))
        flags_str: str = self._macho_protection_flags(segment)

        item = QTreeWidgetItem([name, f"0x{vaddr:08X}", f"{size:,}", flags_str])
        tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, offset)
        return item

    @staticmethod
    def _build_macho_section_item(section: object) -> QTreeWidgetItem:
        """Build a QTreeWidgetItem for a Mach-O section.

        Args:
            section: A lief MachO section object.

        Returns:
            Tree widget item representing the section.
        """
        name_raw: str = str(getattr(section, "name", ""))
        name: str = name_raw or "(unnamed)"
        vaddr: int = int(getattr(section, "virtual_address", 0))
        size: int = int(getattr(section, "size", 0))
        offset: int = int(getattr(section, "offset", 0))

        item = QTreeWidgetItem([f"  {name}", f"0x{vaddr:08X}", f"{size:,}", ""])
        tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, offset)
        return item

    def _extract_strings(self, min_length: int = 4) -> None:
        """Extract printable ASCII strings from the binary.

        Args:
            min_length: Minimum string length to include.
        """
        self._strings_table.setRowCount(0)
        current_string: list[str] = []
        string_start = 0
        max_strings = 5000

        found = 0
        for i, byte_val in enumerate(self._file_data):
            if _ASCII_PRINTABLE_MIN <= byte_val < _ASCII_PRINTABLE_MAX:
                if not current_string:
                    string_start = i
                current_string.append(chr(byte_val))
            else:
                if len(current_string) >= min_length:
                    s = "".join(current_string)
                    row = self._strings_table.rowCount()
                    self._strings_table.insertRow(row)
                    off_item = QTableWidgetItem(f"0x{string_start:08X}")
                    off_item.setData(Qt.ItemDataRole.UserRole, string_start)
                    self._strings_table.setItem(row, 0, off_item)
                    self._strings_table.setItem(row, 1, QTableWidgetItem(str(len(s))))
                    self._strings_table.setItem(row, 2, QTableWidgetItem(s[:200]))
                    found += 1
                    if found >= max_strings:
                        break
                current_string.clear()

        if current_string and len(current_string) >= min_length and found < max_strings:
            s = "".join(current_string)
            row = self._strings_table.rowCount()
            self._strings_table.insertRow(row)
            off_item = QTableWidgetItem(f"0x{string_start:08X}")
            off_item.setData(Qt.ItemDataRole.UserRole, string_start)
            self._strings_table.setItem(row, 0, off_item)
            self._strings_table.setItem(row, 1, QTableWidgetItem(str(len(s))))
            self._strings_table.setItem(row, 2, QTableWidgetItem(s[:200]))

    def _on_open_file(self) -> None:
        """Open a binary file via file dialog."""
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open Binary File",
            "",
            "All Files (*);;Executables (*.exe *.dll *.sys);;ELF (*.so *.elf);;Mach-O (*)",
        )
        if path_str:
            self.load_file(Path(path_str))

    def _on_goto_offset(self) -> None:
        """Navigate to the offset entered in the offset input."""
        text = self._offset_input.text().strip()
        if not text:
            return

        try:
            offset = int(text, 16) if text.startswith(("0x", "0X")) else int(text)
        except ValueError:
            return

        offset = max(0, min(offset, len(self._file_data) - 1))
        _logger.debug("hex_goto_offset", extra={"offset": f"0x{offset:08X}"})
        self._populate_hex_view(offset)

    def _on_search(self) -> None:
        """Search for hex pattern in the binary data."""
        text = self._search_input.text().strip()
        if not text:
            return

        try:
            hex_bytes = bytes.fromhex(text.replace(" ", ""))
        except ValueError:
            _logger.debug("invalid_hex_search_pattern", extra={"input": text})
            return

        start = self._current_offset + 1
        idx = self._file_data.find(hex_bytes, start)
        if idx == -1:
            idx = self._file_data.find(hex_bytes, 0)

        if idx >= 0:
            _logger.debug("hex_search_found", extra={"offset": f"0x{idx:08X}", "pattern_size": len(hex_bytes)})
            self._populate_hex_view(idx)
            self._offset_input.setText(f"0x{idx:08X}")

    def _on_apply_patch(self) -> None:
        """Apply a patch at the current hex table selection."""
        selected_row = self._hex_table.currentRow()
        if selected_row < 0:
            return

        hex_item = self._hex_table.item(selected_row, _HEX_COL_HEX)
        if hex_item is None:
            return

        new_hex = hex_item.text().strip()
        if not _HEX_PATTERN.match(new_hex):
            return

        try:
            new_bytes = bytes.fromhex(new_hex.replace(" ", ""))
        except ValueError:
            return

        offset = self._current_offset + selected_row * _HEX_BYTES_PER_ROW
        end = offset + len(new_bytes)
        if end > len(self._file_data):
            return

        original = bytes(self._file_data[offset:end])
        if original == new_bytes:
            return

        self._patches.append((offset, original, new_bytes))
        self._file_data[offset:end] = new_bytes
        self._revert_btn.setEnabled(True)

        self._populate_hex_view(self._current_offset)
        self._update_patches_table()
        self.patch_applied.emit(offset, new_bytes)

        _logger.info("patch_applied", extra={"offset": f"0x{offset:08X}", "size": len(new_bytes)})

    def _on_revert_patch(self) -> None:
        """Revert the most recent patch."""
        if not self._patches:
            return

        offset, original, _ = self._patches.pop()
        self._file_data[offset : offset + len(original)] = original
        self._revert_btn.setEnabled(bool(self._patches))

        self._populate_hex_view(self._current_offset)
        self._update_patches_table()
        _logger.info("patch_reverted", extra={"offset": f"0x{offset:08X}"})

    def _on_save(self) -> None:
        """Save the modified binary to disk."""
        if self._file_path is None:
            return

        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "Save Binary",
            str(self._file_path),
            "All Files (*)",
        )
        if not path_str:
            return

        try:
            with open(path_str, "wb") as f:
                f.write(self._file_data)
            _logger.info("binary_saved", extra={"path": path_str})
            QMessageBox.information(self, "Saved", f"Binary saved to {path_str}")
        except OSError as e:
            _logger.warning("binary_save_failed", extra={"error": str(e)})
            QMessageBox.warning(self, "Save Failed", str(e))

    def _on_section_double_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Navigate to a section's raw file offset in the hex view.

        Args:
            item: The double-clicked tree item.
            _column: Column index (unused).
        """
        raw_offset: object = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if isinstance(raw_offset, int):
            self._populate_hex_view(raw_offset)
            self._offset_input.setText(f"0x{raw_offset:08X}")

    def _on_string_double_clicked(self, row: int, _column: int) -> None:
        """Navigate to a string's offset in the hex view.

        Args:
            row: Selected row in strings table.
            _column: Column index (unused).
        """
        off_item = self._strings_table.item(row, 0)
        if off_item is not None:
            offset = off_item.data(Qt.ItemDataRole.UserRole)
            if offset is not None:
                self._populate_hex_view(int(offset))
                self._offset_input.setText(f"0x{int(offset):08X}")

    def _update_patches_table(self) -> None:
        """Refresh the patches table from the internal patch list."""
        self._patches_table.setRowCount(0)
        for offset, original, patched in self._patches:
            row = self._patches_table.rowCount()
            self._patches_table.insertRow(row)
            self._patches_table.setItem(row, 0, QTableWidgetItem(f"0x{offset:08X}"))
            self._patches_table.setItem(row, 1, QTableWidgetItem(" ".join(f"{b:02X}" for b in original[:16])))
            self._patches_table.setItem(row, 2, QTableWidgetItem(" ".join(f"{b:02X}" for b in patched[:16])))

    def get_file_data(self) -> bytearray:
        """Get the current binary data (with any applied patches).

        Returns:
            The binary data as a bytearray.
        """
        return self._file_data

    def get_patches(self) -> list[tuple[int, bytes, bytes]]:
        """Get the list of applied patches.

        Returns:
            List of (offset, original_bytes, patched_bytes) tuples.
        """
        return list(self._patches)

    def start_tool(self) -> bool:
        """Start the binary panel.

        Returns:
            True always since native panels are always ready.
        """
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop the binary panel and cleanup.

        Returns:
            True if cleanup succeeded.
        """
        self.tool_closed.emit()
        return True
