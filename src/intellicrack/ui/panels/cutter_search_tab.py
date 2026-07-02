# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Advanced search/compare tab for the Cutter/Rizin analysis panel.

Provides a self-contained Qt widget exposing every native rizin search and byte/disassembly comparison capability that is not already
covered by the regex string-search box or the ROP-gadget search tab: byte pattern search (``/xj``), wildcard byte pattern search (``/xj``
with ``..`` wildcards), literal string search (``/xj`` on UTF-8-encoded text), assembly instruction pattern search (``/aj``), cryptographic
constant search (``/cj``), magic signature search (``/mj``), numeric value search (``/vj``), byte comparison (``c``), and disassembly
comparison against another file (``cD``/``cCj``), all driven by the ``CutterBridge`` search surface (``cutter.py:2150-2200,3684-3862``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160
_SIZE_INPUT_MAX_WIDTH: Final[int] = 80
_TOP_SPLIT_LEFT: Final[int] = 550
_TOP_SPLIT_RIGHT: Final[int] = 350

_MODE_BYTES: Final[str] = "Bytes"
_MODE_WILDCARD: Final[str] = "Wildcard Bytes"
_MODE_STRING: Final[str] = "String"
_MODE_ASSEMBLY: Final[str] = "Assembly"
_MODE_CRYPTO: Final[str] = "Crypto Constants"
_MODE_MAGIC: Final[str] = "Magic Signatures"
_MODE_VALUE: Final[str] = "Numeric Value"

_SEARCH_MODES: Final[list[str]] = [
    _MODE_BYTES,
    _MODE_WILDCARD,
    _MODE_STRING,
    _MODE_ASSEMBLY,
    _MODE_CRYPTO,
    _MODE_MAGIC,
    _MODE_VALUE,
]

_VALUE_SIZES: Final[list[str]] = ["1", "2", "4", "8"]
_DEFAULT_VALUE_SIZE_INDEX: Final[int] = 2

_RESULT_COLUMNS: Final[list[str]] = ["Address", "Detail"]


def _parse_address(text: str) -> int | None:
    """Parse an address string in hex (``0x``/``0X`` prefix) or decimal form.

    Args:
        text: User-supplied address string.

    Returns:
        int | None: The parsed integer address, or ``None`` on invalid input.
    """
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return int(stripped, 16) if stripped.lower().startswith("0x") else int(stripped)
    except ValueError:
        return None


class SearchTab(QWidget):
    """Tab exposing rizin's advanced search and byte/disassembly comparison operations.

    Provides a mode selector (bytes/wildcard-bytes/string/assembly/crypto-constants/magic-
    signatures/numeric-value) driving a single pattern input and results table, plus a
    separate compare panel for comparing bytes or disassembly at an address against supplied
    data or another file, all driven by the ``CutterBridge`` search methods.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SearchTab with a mode-driven search panel and a compare panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.addWidget(self._build_search_panel(fm))
        split.addWidget(self._build_compare_panel(fm))
        split.setSizes([_TOP_SPLIT_LEFT, _TOP_SPLIT_RIGHT])
        layout.addWidget(split)

    def _build_search_panel(self, fm: FontManager) -> QWidget:
        """Build the mode-driven pattern search panel.

        Args:
            fm: Shared font manager instance.

        Returns:
            QWidget: Search panel container.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        vlayout.setSpacing(_PANEL_SPACING)

        search_label = QLabel(self.tr("Search"))
        search_label.setFont(fm.get_ui_font_bold(9))
        vlayout.addWidget(search_label)

        mode_row = QHBoxLayout()
        mode_label = QLabel(self.tr("Mode:"))
        mode_label.setFont(fm.get_ui_font(9))
        mode_row.addWidget(mode_label)
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(_SEARCH_MODES)
        self._mode_combo.currentTextChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self._mode_combo)

        self._value_size_combo = QComboBox()
        self._value_size_combo.addItems(_VALUE_SIZES)
        self._value_size_combo.setCurrentIndex(_DEFAULT_VALUE_SIZE_INDEX)
        self._value_size_combo.setVisible(False)
        mode_row.addWidget(self._value_size_combo)
        mode_row.addStretch()
        vlayout.addLayout(mode_row)

        pattern_row = QHBoxLayout()
        self._pattern_input = QLineEdit()
        self._pattern_input.setPlaceholderText("48 8B 05 00")
        self._pattern_input.returnPressed.connect(self._on_search)
        pattern_row.addWidget(self._pattern_input)

        self._search_btn = QPushButton(self.tr("Search"))
        self._search_btn.setObjectName("tool_button")
        self._search_btn.clicked.connect(self._on_search)
        pattern_row.addWidget(self._search_btn)
        vlayout.addLayout(pattern_row)

        self._search_status_label = QLabel(self.tr("Ready"))
        self._search_status_label.setFont(fm.get_ui_font(9))
        vlayout.addWidget(self._search_status_label)

        self._results_table = QTableWidget(0, len(_RESULT_COLUMNS))
        self._results_table.setHorizontalHeaderLabels(_RESULT_COLUMNS)
        self._results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        vlayout.addWidget(self._results_table)

        self._on_mode_changed(self._mode_combo.currentText())
        return container

    def _build_compare_panel(self, fm: FontManager) -> QWidget:
        """Build the byte/disassembly comparison panel.

        Args:
            fm: Shared font manager instance.

        Returns:
            QWidget: Compare panel container.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        vlayout.setSpacing(_PANEL_SPACING)

        compare_label = QLabel(self.tr("Compare"))
        compare_label.setFont(fm.get_ui_font_bold(9))
        vlayout.addWidget(compare_label)

        addr_row = QHBoxLayout()
        addr_label = QLabel(self.tr("Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        addr_row.addWidget(addr_label)
        self._compare_addr_input = QLineEdit()
        self._compare_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._compare_addr_input.setPlaceholderText("0x...")
        addr_row.addWidget(self._compare_addr_input)
        addr_row.addStretch()
        vlayout.addLayout(addr_row)

        bytes_row = QHBoxLayout()
        self._compare_hex_input = QLineEdit()
        self._compare_hex_input.setPlaceholderText("Hex bytes to compare (e.g. 90909090)")
        bytes_row.addWidget(self._compare_hex_input)
        self._compare_bytes_btn = QPushButton(self.tr("Compare Bytes"))
        self._compare_bytes_btn.setObjectName("tool_button")
        self._compare_bytes_btn.clicked.connect(self._on_compare_bytes)
        bytes_row.addWidget(self._compare_bytes_btn)
        vlayout.addLayout(bytes_row)

        file_row = QHBoxLayout()
        self._compare_file_input = QLineEdit()
        self._compare_file_input.setPlaceholderText("Path to file to compare against")
        file_row.addWidget(self._compare_file_input)
        self._compare_browse_btn = QPushButton(self.tr("Browse..."))
        self._compare_browse_btn.setObjectName("secondary_button")
        self._compare_browse_btn.clicked.connect(self._on_browse_compare_file)
        file_row.addWidget(self._compare_browse_btn)
        self._compare_disasm_btn = QPushButton(self.tr("Compare Disasm"))
        self._compare_disasm_btn.setObjectName("tool_button")
        self._compare_disasm_btn.clicked.connect(self._on_compare_disassembly)
        file_row.addWidget(self._compare_disasm_btn)
        vlayout.addLayout(file_row)

        self._compare_output = QPlainTextEdit()
        self._compare_output.setFont(fm.get_code_font(9))
        self._compare_output.setReadOnly(True)
        vlayout.addWidget(self._compare_output)

        return container

    def set_bridge(self, bridge: CutterBridge) -> None:
        """Set the CutterBridge instance used for search and compare operations.

        Args:
            bridge: The CutterBridge to use.
        """
        self._bridge = bridge

    def _on_mode_changed(self, mode: str) -> None:
        """Update the pattern input hint and controls for the selected search mode.

        Args:
            mode: The newly selected search mode label.
        """
        set_hint = self._pattern_input.setPlaceholderText
        no_input = mode in {_MODE_CRYPTO, _MODE_MAGIC}
        self._pattern_input.setEnabled(not no_input)
        self._value_size_combo.setVisible(mode == _MODE_VALUE)

        hints = {
            _MODE_BYTES: "48 8B 05 00",
            _MODE_WILDCARD: "48 8B ?? ??",
            _MODE_STRING: "License check failed",
            _MODE_ASSEMBLY: "mov eax, ebx",
            _MODE_CRYPTO: "(no input required)",
            _MODE_MAGIC: "(no input required)",
            _MODE_VALUE: "1234",
        }
        set_hint(hints.get(mode, ""))

    def _on_search(self) -> None:
        """Dispatch the search bridge call matching the currently selected mode."""
        if self._bridge is None:
            self._search_status_label.setText(self.tr("No bridge configured"))
            return

        mode = self._mode_combo.currentText()
        pattern = self._pattern_input.text().strip()
        if mode not in {_MODE_CRYPTO, _MODE_MAGIC} and not pattern:
            self._search_status_label.setText(self.tr("Enter a search pattern"))
            return

        self._search_btn.setEnabled(False)
        self._search_status_label.setText(self.tr("Searching..."))

        if mode == _MODE_BYTES:
            run_bridge_coroutine_logged(
                self._bridge.search_bytes(pattern),
                on_success=self._apply_addresses,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_bytes",
                logger=_logger,
                pattern=pattern,
            )
        elif mode == _MODE_WILDCARD:
            run_bridge_coroutine_logged(
                self._bridge.search_bytes_wildcard(pattern),
                on_success=self._apply_addresses,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_bytes_wildcard",
                logger=_logger,
                pattern=pattern,
            )
        elif mode == _MODE_STRING:
            run_bridge_coroutine_logged(
                self._bridge.search_string_live(pattern),
                on_success=self._apply_addresses,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_string_live",
                logger=_logger,
                text_length=len(pattern),
            )
        elif mode == _MODE_ASSEMBLY:
            run_bridge_coroutine_logged(
                self._bridge.search_assembly_pattern(pattern),
                on_success=self._apply_addresses,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_assembly_pattern",
                logger=_logger,
                pattern=pattern,
            )
        elif mode == _MODE_CRYPTO:
            run_bridge_coroutine_logged(
                self._bridge.search_crypto_constants(),
                on_success=self._apply_dict_results,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_crypto_constants",
                logger=_logger,
            )
        elif mode == _MODE_MAGIC:
            run_bridge_coroutine_logged(
                self._bridge.search_magic(),
                on_success=self._apply_dict_results,
                on_error=self._on_search_error,
                parent=self,
                event="cutter_search_magic",
                logger=_logger,
            )
        else:
            self._on_search_value(pattern)

    def _on_search_value(self, pattern: str) -> None:
        """Dispatch a numeric value search using the pattern text and selected size.

        Args:
            pattern: The user-supplied numeric value text.
        """
        value = _parse_address(pattern)
        if value is None:
            self._search_status_label.setText(self.tr("Invalid numeric value"))
            self._search_btn.setEnabled(True)
            return
        if self._bridge is None:
            return
        size = int(self._value_size_combo.currentText())
        run_bridge_coroutine_logged(
            self._bridge.search_value(value, size),
            on_success=self._apply_addresses,
            on_error=self._on_search_error,
            parent=self,
            event="cutter_search_value",
            logger=_logger,
            value=value,
            size=size,
        )

    def _apply_addresses(self, result: object) -> None:
        """Populate the results table with a list of matched addresses.

        Args:
            result: List of integer addresses from the bridge.
        """
        addresses: list[object] = [*result] if isinstance(result, list) else []
        self._results_table.setRowCount(0)
        for addr in addresses:
            if not isinstance(addr, int):
                continue
            row = self._results_table.rowCount()
            self._results_table.insertRow(row)
            self._results_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._results_table.setItem(row, 1, QTableWidgetItem(""))
        self._search_status_label.setText(f"{len(addresses)} match(es)")
        self._search_btn.setEnabled(True)

    def _apply_dict_results(self, result: object) -> None:
        """Populate the results table with a list of match dictionaries.

        Args:
            result: List of match dictionaries (crypto constants / magic signatures)
                from the bridge, each expected to carry an ``offset``/``addr`` key.
        """
        entries: list[object] = [*result] if isinstance(result, list) else []
        self._results_table.setRowCount(0)
        for entry_raw in entries:
            if not isinstance(entry_raw, dict):
                continue
            entry = cast("dict[str, Any]", entry_raw)
            offset = entry.get("offset", entry.get("addr", entry.get("vaddr", 0)))
            detail_keys = ("name", "type", "info", "comment")
            detail = next((str(entry[key]) for key in detail_keys if entry.get(key)), str(entry))
            row = self._results_table.rowCount()
            self._results_table.insertRow(row)
            addr_text = f"0x{offset:X}" if isinstance(offset, int) else str(offset)
            self._results_table.setItem(row, 0, QTableWidgetItem(addr_text))
            self._results_table.setItem(row, 1, QTableWidgetItem(detail))
        self._search_status_label.setText(f"{len(entries)} match(es)")
        self._search_btn.setEnabled(True)

    def _on_search_error(self, exc: object) -> None:
        """Handle search failure.

        Args:
            exc: The exception that occurred.
        """
        self._search_status_label.setText(f"Search failed: {exc}")
        _logger.warning("cutter_search_failed", error=str(exc))
        self._search_btn.setEnabled(True)

    def _on_browse_compare_file(self) -> None:
        """Open a file dialog and populate the compare-file input with the chosen path."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Select File to Compare Against"),
            "",
            self.tr("All Files (*)"),
        )
        if file_path:
            self._compare_file_input.setText(file_path)

    def _on_compare_bytes(self) -> None:
        """Compare the hex bytes in the compare input against the binary at the given address."""
        if self._bridge is None:
            self._compare_output.setPlainText("[error] No bridge configured")
            return
        address = _parse_address(self._compare_addr_input.text())
        if address is None:
            self._compare_output.setPlainText("[error] Invalid address")
            return
        hex_data = self._compare_hex_input.text().strip().replace(" ", "")
        if not hex_data:
            self._compare_output.setPlainText("[error] Enter hex bytes to compare")
            return

        self._compare_bytes_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.compare_bytes(hex_data, address),
            on_success=self._apply_compare_result,
            on_error=self._on_compare_error,
            parent=self,
            event="cutter_compare_bytes",
            logger=_logger,
            address=hex(address),
        )

    def _on_compare_disassembly(self) -> None:
        """Compare disassembly at an address against another file."""
        if self._bridge is None:
            self._compare_output.setPlainText("[error] No bridge configured")
            return
        address = _parse_address(self._compare_addr_input.text())
        if address is None:
            self._compare_output.setPlainText("[error] Invalid address")
            return
        file_path = self._compare_file_input.text().strip()
        if not file_path:
            self._compare_output.setPlainText("[error] Select a file to compare against")
            return

        self._compare_disasm_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.compare_disassembly(file_path, address),
            on_success=self._apply_compare_result,
            on_error=self._on_compare_error,
            parent=self,
            event="cutter_compare_disassembly",
            logger=_logger,
            address=hex(address),
            file_path=file_path,
        )

    def _apply_compare_result(self, result: object) -> None:
        """Render a comparison result string into the compare output view.

        Args:
            result: Comparison output text from the bridge.
        """
        self._compare_output.setPlainText(str(result) if result is not None else "")
        self._compare_bytes_btn.setEnabled(True)
        self._compare_disasm_btn.setEnabled(True)

    def _on_compare_error(self, exc: object) -> None:
        """Handle byte/disassembly comparison failure.

        Args:
            exc: The exception that occurred.
        """
        self._compare_output.setPlainText(f"[error] {exc}")
        _logger.warning("cutter_compare_failed", error=str(exc))
        self._compare_bytes_btn.setEnabled(True)
        self._compare_disasm_btn.setEnabled(True)
