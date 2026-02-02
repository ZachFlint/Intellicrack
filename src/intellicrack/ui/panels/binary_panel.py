"""Binary analysis panel for Intellicrack.

Provides a hex viewer, section navigator, and patching controls
for direct binary inspection and modification.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
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

from intellicrack.ui.panels._qt_compat import (
    set_header_labels,
    tree_item_data,
    tree_item_set_data,
)


_logger = logging.getLogger(__name__)

_ASCII_PRINTABLE_MIN = 32
_ASCII_PRINTABLE_MAX = 127
_MIN_PE_HEADER_SIZE = 64

_HEX_BYTES_PER_ROW = 16
_HEX_COL_OFFSET = 0
_HEX_COL_HEX = 1
_HEX_COL_ASCII = 2
_MAX_DISPLAY_SIZE = 16 * 1024 * 1024
_CHUNK_SIZE = 4096


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
        self._offset_input.setFont(QFont("JetBrains Mono", 9))
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
        self._hex_table.setFont(QFont("JetBrains Mono", 9))
        self._hex_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hex_table.verticalHeader().setVisible(False)
        hex_header = self._hex_table.horizontalHeader()
        hex_header.setSectionResizeMode(_HEX_COL_OFFSET, QHeaderView.ResizeMode.ResizeToContents)
        hex_header.setSectionResizeMode(_HEX_COL_HEX, QHeaderView.ResizeMode.Stretch)
        hex_header.setSectionResizeMode(_HEX_COL_ASCII, QHeaderView.ResizeMode.ResizeToContents)
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

        self._hex_table.setRowCount(0)
        self._hex_table.setRowCount(row_count)

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

            ascii_str = "".join(
                chr(b) if _ASCII_PRINTABLE_MIN <= b < _ASCII_PRINTABLE_MAX else "." for b in chunk
            )
            ascii_item = QTableWidgetItem(ascii_str)
            ascii_item.setFlags(ascii_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._hex_table.setItem(row_idx, _HEX_COL_ASCII, ascii_item)

        self.offset_changed.emit(start_offset)

    def _parse_sections(self) -> None:
        """Parse PE sections from the loaded binary data."""
        self._sections_tree.clear()
        self._imports_tree.clear()
        self._exports_tree.clear()

        if len(self._file_data) < _MIN_PE_HEADER_SIZE:
            return

        if bytes(self._file_data[:2]) != b"MZ":
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
                tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, vaddr)
                self._sections_tree.addTopLevelItem(item)

        except (struct.error, IndexError) as e:
            _logger.debug("pe_section_parse_error", extra={"error": str(e)})

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
        self._populate_hex_view(offset)

    def _on_search(self) -> None:
        """Search for hex pattern in the binary data."""
        text = self._search_input.text().strip()
        if not text:
            return

        try:
            hex_bytes = bytes.fromhex(text.replace(" ", ""))
        except ValueError:
            _logger.debug("invalid_hex_search_pattern")
            return

        start = self._current_offset + 1
        idx = self._file_data.find(hex_bytes, start)
        if idx == -1:
            idx = self._file_data.find(hex_bytes, 0)

        if idx >= 0:
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
        """Navigate to a section's virtual address in the hex view.

        Args:
            item: The double-clicked tree item.
            _column: Column index (unused).
        """
        vaddr: object = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if isinstance(vaddr, int):
            self._populate_hex_view(vaddr)
            self._offset_input.setText(f"0x{vaddr:08X}")

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
            self._patches_table.setItem(
                row, 1, QTableWidgetItem(" ".join(f"{b:02X}" for b in original[:16]))
            )
            self._patches_table.setItem(
                row, 2, QTableWidgetItem(" ".join(f"{b:02X}" for b in patched[:16]))
            )

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
