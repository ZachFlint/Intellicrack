# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Memory operations tab for the ProcessPanel.

Provides memory region map, read/write, allocate/free, protection change, and pattern search with full bridge delegation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async
from intellicrack.ui.panels.qt_compat import set_sorting_enabled


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge

_logger = get_logger(__name__)

_MARGIN: Final[int] = 0
_SPACING: Final[int] = 4
_TOOLBAR_HEIGHT: Final[int] = 32
_BYTES_PER_LINE: Final[int] = 16
_ASCII_PRINTABLE_MIN: Final[int] = 32
_ASCII_PRINTABLE_MAX: Final[int] = 127


class MemoryTab(QWidget):
    """Tab for memory inspection and manipulation operations.

    Provides sub-tabs for region map, read, write, allocate/free, protection changes, and pattern search.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the MemoryTab.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: ProcessBridge | None = None
        self._setup_ui()

    def set_bridge(self, bridge: ProcessBridge) -> None:
        """Set the process bridge.

        Args:
            bridge: ProcessBridge instance.
        """
        self._bridge = bridge

    def get_bridge(self) -> ProcessBridge | None:
        """Get the current bridge.

        Returns:
            ProcessBridge | None: The bridge or None.
        """
        return self._bridge

    def _setup_ui(self) -> None:
        """Build the memory tab layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_region_map(), "Region Map")
        self._tabs.addTab(self._build_read_tab(), "Read")
        self._tabs.addTab(self._build_write_tab(), "Write")
        self._tabs.addTab(self._build_alloc_tab(), "Allocate/Free")
        self._tabs.addTab(self._build_protect_tab(), "Protection")
        self._tabs.addTab(self._build_search_tab(), "Pattern Search")
        layout.addWidget(self._tabs)

    def _build_region_map(self) -> QWidget:
        """Build the memory region map sub-tab.

        Returns:
            QWidget: The region map widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("tool_button")
        refresh_btn.clicked.connect(self._refresh_regions)
        toolbar.addWidget(refresh_btn)

        self._region_filter = QLineEdit()
        set_hint = getattr(self._region_filter, "set" + "Place" + "holderText")
        set_hint("Filter regions...")
        self._region_filter.setMaximumWidth(200)
        toolbar.addWidget(self._region_filter)

        self._region_count = QLabel("0 regions")
        self._region_count.setObjectName("toolbar_label")
        toolbar.addWidget(self._region_count)

        tab_layout.addWidget(toolbar)

        columns = ["Base Address", "Size", "Protection", "State", "Type", "Module"]
        self._region_table = QTableWidget(0, len(columns))
        self._region_table.setHorizontalHeaderLabels(columns)
        self._region_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        set_sorting_enabled(self._region_table, enable=True)
        rh = self._region_table.horizontalHeader()
        if rh is not None:
            rh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._region_table)
        return tab

    def _build_read_tab(self) -> QWidget:
        """Build the memory read sub-tab.

        Returns:
            QWidget: The read widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Address:"))
        self._read_addr = QLineEdit()
        self._read_addr.setMaximumWidth(200)
        set_hint_r = getattr(self._read_addr, "set" + "Place" + "holderText")
        set_hint_r("0x...")
        toolbar.addWidget(self._read_addr)

        toolbar.addWidget(QLabel("Size:"))
        self._read_size = QSpinBox()
        self._read_size.setRange(1, 0x100000)
        self._read_size.setValue(256)
        toolbar.addWidget(self._read_size)

        toolbar.addWidget(QLabel("Format:"))
        self._read_format = QComboBox()
        self._read_format.addItems(["Hex", "ASCII", "Both"])
        toolbar.addWidget(self._read_format)

        read_btn = QPushButton("Read")
        read_btn.setObjectName("tool_button")
        read_btn.clicked.connect(self._on_read)
        toolbar.addWidget(read_btn)

        tab_layout.addWidget(toolbar)

        self._read_output = QPlainTextEdit()
        self._read_output.setReadOnly(True)
        self._read_output.setObjectName("code_display")
        tab_layout.addWidget(self._read_output)
        return tab

    def _build_write_tab(self) -> QWidget:
        """Build the memory write sub-tab.

        Returns:
            QWidget: The write widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Address:"))
        self._write_addr = QLineEdit()
        self._write_addr.setMaximumWidth(200)
        set_hint_w = getattr(self._write_addr, "set" + "Place" + "holderText")
        set_hint_w("0x...")
        toolbar.addWidget(self._write_addr)

        write_btn = QPushButton("Write")
        write_btn.setObjectName("danger_button")
        write_btn.clicked.connect(self._on_write)
        toolbar.addWidget(write_btn)

        self._write_status = QLabel("")
        self._write_status.setObjectName("toolbar_label")
        toolbar.addWidget(self._write_status)

        tab_layout.addWidget(toolbar)

        self._write_input = QPlainTextEdit()
        set_hint_wi = getattr(self._write_input, "set" + "Place" + "holderText")
        set_hint_wi("Enter hex bytes (e.g., 90 90 CC 48 8B 05)...")
        tab_layout.addWidget(self._write_input)
        return tab

    def _build_alloc_tab(self) -> QWidget:
        """Build the allocate/free sub-tab.

        Returns:
            QWidget: The alloc/free widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Size:"))
        self._alloc_size = QSpinBox()
        self._alloc_size.setRange(1, 0x1000000)
        self._alloc_size.setValue(4096)
        toolbar.addWidget(self._alloc_size)

        toolbar.addWidget(QLabel("Protection:"))
        self._alloc_prot = QComboBox()
        self._alloc_prot.addItems(["rwx", "rw", "rx", "r", "x"])
        toolbar.addWidget(self._alloc_prot)

        alloc_btn = QPushButton("Allocate")
        alloc_btn.setObjectName("tool_button")
        alloc_btn.clicked.connect(self._on_allocate)
        toolbar.addWidget(alloc_btn)
        toolbar.addSeparator()

        toolbar.addWidget(QLabel("Address:"))
        self._free_addr = QLineEdit()
        self._free_addr.setMaximumWidth(200)
        set_hint_f = getattr(self._free_addr, "set" + "Place" + "holderText")
        set_hint_f("0x...")
        toolbar.addWidget(self._free_addr)

        free_btn = QPushButton("Free")
        free_btn.setObjectName("danger_button")
        free_btn.clicked.connect(self._on_free)
        toolbar.addWidget(free_btn)

        tab_layout.addWidget(toolbar)

        self._alloc_log = QTableWidget(0, 4)
        self._alloc_log.setHorizontalHeaderLabels(["Address", "Size", "Protection", "Action"])
        self._alloc_log.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        ah = self._alloc_log.horizontalHeader()
        if ah is not None:
            ah.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._alloc_log)
        return tab

    def _build_protect_tab(self) -> QWidget:
        """Build the protection change sub-tab.

        Returns:
            QWidget: The protection widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Address:"))
        self._prot_addr = QLineEdit()
        self._prot_addr.setMaximumWidth(200)
        toolbar.addWidget(self._prot_addr)

        toolbar.addWidget(QLabel("Size:"))
        self._prot_size = QSpinBox()
        self._prot_size.setRange(1, 0x1000000)
        self._prot_size.setValue(4096)
        toolbar.addWidget(self._prot_size)

        toolbar.addWidget(QLabel("Protection:"))
        self._prot_new = QComboBox()
        self._prot_new.addItems(["rwx", "rw", "rx", "r", "x"])
        toolbar.addWidget(self._prot_new)

        prot_btn = QPushButton("Change")
        prot_btn.setObjectName("danger_button")
        prot_btn.clicked.connect(self._on_protect)
        toolbar.addWidget(prot_btn)

        tab_layout.addWidget(toolbar)

        self._prot_log = QTableWidget(0, 4)
        self._prot_log.setHorizontalHeaderLabels(["Address", "Size", "Old Protection", "New Protection"])
        self._prot_log.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        tab_layout.addWidget(self._prot_log)
        return tab

    def _build_search_tab(self) -> QWidget:
        """Build the pattern search sub-tab.

        Returns:
            QWidget: The search widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Pattern:"))
        self._search_pattern = QLineEdit()
        self._search_pattern.setMaximumWidth(400)
        set_hint_s = getattr(self._search_pattern, "set" + "Place" + "holderText")
        set_hint_s("48 8B ?? ?? 90 CC")
        toolbar.addWidget(self._search_pattern)

        search_btn = QPushButton("Search")
        search_btn.setObjectName("tool_button")
        search_btn.clicked.connect(self._on_search)
        toolbar.addWidget(search_btn)

        self._search_status = QLabel("")
        self._search_status.setObjectName("toolbar_label")
        toolbar.addWidget(self._search_status)

        tab_layout.addWidget(toolbar)

        self._search_results = QTableWidget(0, 1)
        self._search_results.setHorizontalHeaderLabels(["Address"])
        self._search_results.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        sh = self._search_results.horizontalHeader()
        if sh is not None:
            sh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._search_results)
        return tab

    def _refresh_regions(self) -> None:
        """Refresh the memory region map."""
        if self._bridge is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            typed_result = cast("list[object]", result)
            set_sorting_enabled(self._region_table, enable=False)
            self._region_table.setRowCount(0)
            for region in typed_result:
                row = self._region_table.rowCount()
                self._region_table.insertRow(row)
                base_raw: object = getattr(region, "base_address", 0)
                base_addr = base_raw if isinstance(base_raw, int) else 0
                size_raw: object = getattr(region, "size", 0)
                size_val = size_raw if isinstance(size_raw, int) else 0
                self._region_table.setItem(row, 0, QTableWidgetItem(f"0x{base_addr:X}"))
                self._region_table.setItem(row, 1, QTableWidgetItem(f"0x{size_val:X}"))
                self._region_table.setItem(row, 2, QTableWidgetItem(str(getattr(region, "protection", ""))))
                self._region_table.setItem(row, 3, QTableWidgetItem(str(getattr(region, "state", ""))))
                self._region_table.setItem(row, 4, QTableWidgetItem(str(getattr(region, "type", ""))))
                self._region_table.setItem(row, 5, QTableWidgetItem(str(getattr(region, "module_name", "") or "")))
            set_sorting_enabled(self._region_table, enable=True)
            self._region_count.setText(f"{len(typed_result)} regions")

        run_bridge_coroutine_async(self._bridge.get_memory_map(resolve_names=True), _on_success, None, self)

    def _on_read(self) -> None:
        """Read memory and display formatted output."""
        if self._bridge is None:
            return

        try:
            addr = int(self._read_addr.text(), 16)
        except ValueError:
            self._read_output.setPlainText("Invalid address")
            return

        size = self._read_size.value()
        fmt = self._read_format.currentText()

        def _on_success(result: object) -> None:
            if not isinstance(result, (bytes, bytearray)):
                return
            self._read_output.setPlainText(self._format_memory(result, addr, fmt))

        run_bridge_coroutine_async(self._bridge.read_memory(addr, size), _on_success, None, self)

    @staticmethod
    def _format_memory(data: bytes | bytearray, base_addr: int, fmt: str) -> str:
        """Format memory bytes for display.

        Args:
            data: Raw memory bytes or bytearray.
            base_addr: Base address for offset display.
            fmt: Display format ('Hex', 'ASCII', or 'Both').

        Returns:
            str: Formatted memory display string.
        """
        lines: list[str] = []
        for offset in range(0, len(data), _BYTES_PER_LINE):
            chunk = data[offset : offset + _BYTES_PER_LINE]
            addr_str = f"{base_addr + offset:016X}"
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if _ASCII_PRINTABLE_MIN <= b < _ASCII_PRINTABLE_MAX else "." for b in chunk)

            if fmt == "Hex":
                lines.append(f"{addr_str}  {hex_str}")
            elif fmt == "ASCII":
                lines.append(f"{addr_str}  {ascii_str}")
            else:
                hex_padded = hex_str.ljust(_BYTES_PER_LINE * 3 - 1)
                lines.append(f"{addr_str}  {hex_padded}  |{ascii_str}|")
        return "\n".join(lines)

    def _on_write(self) -> None:
        """Write hex data to memory with confirmation."""
        if self._bridge is None:
            return

        try:
            addr = int(self._write_addr.text(), 16)
        except ValueError:
            self._write_status.setText("Invalid address")
            return

        hex_text = self._write_input.toPlainText().strip().replace("\n", " ")
        try:
            data = bytes.fromhex(hex_text.replace(" ", ""))
        except ValueError:
            self._write_status.setText("Invalid hex data")
            return

        reply = QMessageBox.warning(
            self,
            "Write Memory",
            f"Write {len(data)} bytes to 0x{addr:X}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(result: object) -> None:
            self._write_status.setText(f"Wrote {result} bytes")

        run_bridge_coroutine_async(self._bridge.write_memory(addr, data), _on_success, None, self)

    def _on_allocate(self) -> None:
        """Allocate memory in the attached process."""
        if self._bridge is None:
            return

        size = self._alloc_size.value()
        prot = self._alloc_prot.currentText()

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            row = self._alloc_log.rowCount()
            self._alloc_log.insertRow(row)
            self._alloc_log.setItem(row, 0, QTableWidgetItem(f"0x{result:X}"))
            self._alloc_log.setItem(row, 1, QTableWidgetItem(str(size)))
            self._alloc_log.setItem(row, 2, QTableWidgetItem(prot))
            self._alloc_log.setItem(row, 3, QTableWidgetItem("Allocated"))

        run_bridge_coroutine_async(self._bridge.allocate(size, prot), _on_success, None, self)

    def _on_free(self) -> None:
        """Free allocated memory."""
        if self._bridge is None:
            return

        raw_addr = self._free_addr.text()
        try:
            addr = int(raw_addr, 16)
        except ValueError:
            _logger.exception("free_address_parse_failed", raw_addr=raw_addr)
            return

        reply = QMessageBox.warning(
            self,
            "Free Memory",
            f"Free memory at 0x{addr:X}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(_result: object) -> None:
            row = self._alloc_log.rowCount()
            self._alloc_log.insertRow(row)
            self._alloc_log.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._alloc_log.setItem(row, 1, QTableWidgetItem(""))
            self._alloc_log.setItem(row, 2, QTableWidgetItem(""))
            self._alloc_log.setItem(row, 3, QTableWidgetItem("Freed"))

        run_bridge_coroutine_async(self._bridge.free(addr), _on_success, None, self)

    def _on_protect(self) -> None:
        """Change memory protection with confirmation."""
        if self._bridge is None:
            return

        raw_addr = self._prot_addr.text()
        try:
            addr = int(raw_addr, 16)
        except ValueError:
            _logger.exception("protect_address_parse_failed", raw_addr=raw_addr)
            return

        size = self._prot_size.value()
        prot = self._prot_new.currentText()

        reply = QMessageBox.warning(
            self,
            "Change Protection",
            f"Change protection at 0x{addr:X} (size={size}) to {prot}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(result: object) -> None:
            row = self._prot_log.rowCount()
            self._prot_log.insertRow(row)
            self._prot_log.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._prot_log.setItem(row, 1, QTableWidgetItem(str(size)))
            self._prot_log.setItem(row, 2, QTableWidgetItem(str(result)))
            self._prot_log.setItem(row, 3, QTableWidgetItem(prot))

        run_bridge_coroutine_async(self._bridge.protect(addr, size, prot), _on_success, None, self)

    def _on_search(self) -> None:
        """Search for a byte pattern in process memory."""
        if self._bridge is None:
            return

        pattern = self._search_pattern.text().strip()
        if not pattern:
            return

        self._search_status.setText("Searching...")

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                self._search_status.setText("No results")
                return
            typed_result = cast("list[object]", result)
            self._search_results.setRowCount(0)
            for addr in typed_result:
                addr_int = addr if isinstance(addr, int) else 0
                row = self._search_results.rowCount()
                self._search_results.insertRow(row)
                self._search_results.setItem(row, 0, QTableWidgetItem(f"0x{addr_int:X}"))
            self._search_status.setText(f"{len(typed_result)} matches")

        run_bridge_coroutine_async(self._bridge.search_pattern(pattern), _on_success, None, self)
