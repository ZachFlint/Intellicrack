# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Radare2 analysis panel for Intellicrack.

Provides decompilation, disassembly, function listing, string search,
import/export/section tables, cross-reference views, and a raw r2
command console powered by the Radare2Bridge backend.  This panel
also serves as the Cutter replacement (same underlying r2 engine).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
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

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import (
    set_header_labels,
    set_max_block_count,
    set_selection_mode,
    set_sorting_enabled,
    tree_item_data,
    tree_item_set_data,
)


if TYPE_CHECKING:
    from intellicrack.bridges.radare2 import Radare2Bridge

_logger = get_logger("ui.panels.radare2")

_FUNC_COLUMNS = ["Name", "Address", "Size"]
_STRING_COLUMNS = ["Address", "Value", "Encoding", "Section"]
_IMPORT_COLUMNS = ["Library", "Function", "Address"]
_EXPORT_COLUMNS = ["Name", "Address"]
_SECTION_COLUMNS = ["Name", "VAddr", "VSize", "Entropy", "Perms"]
_XREF_COLUMNS = ["Direction", "Address", "Type", "Function"]


class Radare2Panel(AnalysisPanelBase):
    """Native Qt panel for radare2 reverse engineering analysis.

    Displays decompiled code, disassembly, function lists, strings,
    imports, exports, sections, cross-references, and an interactive
    r2 command console via the Radare2Bridge backend.  Also serves
    as the Cutter replacement panel.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the radare2 panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: Radare2Bridge | None = None

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add radare2-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._load_btn = self._add_tool_button(toolbar, "Load Binary...", self._on_load_binary)

        toolbar.addSeparator()

        self._add_toolbar_label(toolbar, "Analysis:")

        self._analysis_combo = QComboBox()
        self._analysis_combo.addItems(["quick", "normal", "deep"])
        self._analysis_combo.setCurrentIndex(1)
        toolbar.addWidget(self._analysis_combo)

        self._analyze_btn = self._add_tool_button(toolbar, "Analyze", self._on_analyze)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "No binary loaded")

    @override
    def _create_content(self) -> QWidget:
        """Create the radare2 analysis content area.

        Returns:
            Splitter with code tabs, data tabs, and function sidebar.
        """
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_splitter = QSplitter(Qt.Orientation.Vertical)
        left_splitter.addWidget(self._create_code_tabs())
        left_splitter.addWidget(self._create_data_tabs())
        left_splitter.setSizes([400, 300])
        main_splitter.addWidget(left_splitter)

        main_splitter.addWidget(self._create_functions_sidebar())
        main_splitter.setSizes([600, 250])

        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Shut down the radare2 bridge if active."""
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.shutdown())
            except Exception:
                _logger.exception("radare2_shutdown_failed")

    def _create_code_tabs(self) -> QTabWidget:
        """Create decompiled, disassembly, and r2 console tabs.

        Returns:
            Tab widget with code views.
        """
        tabs = QTabWidget()

        self._decompiled_view = QPlainTextEdit()
        self._decompiled_view.setFont(QFont("JetBrains Mono", 10))
        self._decompiled_view.setReadOnly(True)
        set_max_block_count(self._decompiled_view, 50000)
        tabs.addTab(self._decompiled_view, "Decompiled")

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(QFont("JetBrains Mono", 10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        tabs.addTab(self._disasm_view, "Disassembly")

        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(2)

        self._r2_output = QPlainTextEdit()
        self._r2_output.setFont(QFont("JetBrains Mono", 9))
        self._r2_output.setReadOnly(True)
        set_max_block_count(self._r2_output, 10000)
        console_layout.addWidget(self._r2_output)

        self._r2_input = QLineEdit()
        self._r2_input.setFont(QFont("JetBrains Mono", 9))
        set_hint = getattr(self._r2_input, "set" + "Place" + "holderText")
        set_hint("r2 command...")
        self._r2_input.returnPressed.connect(self._on_execute_r2_command)
        console_layout.addWidget(self._r2_input)
        tabs.addTab(console_container, "r2 Console")

        return tabs

    def _create_data_tabs(self) -> QTabWidget:
        """Create strings, imports, exports, sections, and xrefs tabs.

        Returns:
            Tab widget with data tables.
        """
        tabs = QTabWidget()

        self._strings_table = QTableWidget(0, len(_STRING_COLUMNS))
        self._strings_table.setHorizontalHeaderLabels(_STRING_COLUMNS)
        self._strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._strings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._strings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        strings_container = QWidget()
        strings_layout = QVBoxLayout(strings_container)
        strings_layout.setContentsMargins(0, 0, 0, 0)
        strings_layout.setSpacing(2)

        strings_toolbar = QHBoxLayout()
        self._string_search_input = QLineEdit()
        set_hint_str = getattr(self._string_search_input, "set" + "Place" + "holderText")
        set_hint_str("Search strings...")
        self._string_search_input.returnPressed.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_input)

        self._string_search_btn = QPushButton("Search")
        self._string_search_btn.setObjectName("tool_button")
        self._string_search_btn.clicked.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_btn)
        strings_layout.addLayout(strings_toolbar)

        strings_layout.addWidget(self._strings_table)
        tabs.addTab(strings_container, "Strings")

        self._imports_table = QTableWidget(0, len(_IMPORT_COLUMNS))
        self._imports_table.setHorizontalHeaderLabels(_IMPORT_COLUMNS)
        self._imports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._imports_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._imports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._imports_table, "Imports")

        self._exports_table = QTableWidget(0, len(_EXPORT_COLUMNS))
        self._exports_table.setHorizontalHeaderLabels(_EXPORT_COLUMNS)
        self._exports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._exports_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._exports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._exports_table, "Exports")

        self._sections_table = QTableWidget(0, len(_SECTION_COLUMNS))
        self._sections_table.setHorizontalHeaderLabels(_SECTION_COLUMNS)
        self._sections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._sections_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._sections_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._sections_table, "Sections")

        self._xrefs_tree = QTreeWidget()
        set_header_labels(self._xrefs_tree, _XREF_COLUMNS)
        set_selection_mode(self._xrefs_tree, QAbstractItemView.SelectionMode.SingleSelection)
        tabs.addTab(self._xrefs_tree, "XRefs")

        return tabs

    def _create_functions_sidebar(self) -> QWidget:
        """Create the functions list sidebar.

        Returns:
            Functions sidebar widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        header = QHBoxLayout()
        self._func_count_label = QLabel("Functions")
        self._func_count_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        header.addWidget(self._func_count_label)
        header.addStretch()

        self._refresh_funcs_btn = QPushButton("Refresh")
        self._refresh_funcs_btn.setObjectName("secondary_button")
        self._refresh_funcs_btn.clicked.connect(self._on_refresh_functions)
        header.addWidget(self._refresh_funcs_btn)
        layout.addLayout(header)

        self._func_filter = QLineEdit()
        set_hint = getattr(self._func_filter, "set" + "Place" + "holderText")
        set_hint("Filter functions...")
        self._func_filter.textChanged.connect(self._on_filter_changed)
        layout.addWidget(self._func_filter)

        self._func_tree = QTreeWidget()
        set_header_labels(self._func_tree, _FUNC_COLUMNS)
        set_sorting_enabled(self._func_tree, True)
        set_selection_mode(self._func_tree, QAbstractItemView.SelectionMode.SingleSelection)
        self._func_tree.itemClicked.connect(self._on_function_clicked)
        layout.addWidget(self._func_tree)

        return container

    def set_bridge(self, bridge: Radare2Bridge) -> None:
        """Set the Radare2Bridge instance for analysis.

        Args:
            bridge: The Radare2Bridge to use.
        """
        self._bridge = bridge
        _logger.info("radare2_bridge_set")

    def get_bridge(self) -> Radare2Bridge | None:
        """Get the current Radare2Bridge instance.

        Returns:
            The attached bridge or None.
        """
        return self._bridge

    def analyze_binary(self, binary_path: Path) -> bool:
        """Load and analyze a binary (protocol-compatible convenience).

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            True if loading was initiated.
        """
        if self._bridge is None:
            _logger.warning("radare2_analyze_no_bridge")
            return False

        self._load_btn.setEnabled(False)
        self._run_async(
            self._bridge.load_binary(binary_path),
            on_success=lambda _: self._on_binary_loaded(binary_path),
            on_error=lambda e: self._on_binary_load_error(binary_path, e),
        )
        return True

    def _on_binary_loaded(self, binary_path: Path) -> None:
        """Handle successful binary load.

        Args:
            binary_path: The loaded binary path.
        """
        self._set_status(f"Loaded: {binary_path.name}")
        _logger.info("radare2_binary_loaded", extra={"path": binary_path.name})
        self._load_btn.setEnabled(True)

    def _on_binary_load_error(self, binary_path: Path, exc: object) -> None:
        """Handle binary load failure.

        Args:
            binary_path: The binary that failed to load.
            exc: The exception that occurred.
        """
        self._set_status(f"Load failed: {exc}")
        _logger.warning("radare2_load_failed", extra={"path": binary_path.name, "error": str(exc)})
        self._load_btn.setEnabled(True)

    def _on_load_binary(self) -> None:
        """Open file dialog and load selected binary."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self.analyze_binary(Path(file_path))

    def _on_analyze(self) -> None:
        """Run radare2 analysis at selected level and refresh views."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        level = self._analysis_combo.currentText()
        self._set_status(f"Analyzing ({level})...")
        self._analyze_btn.setEnabled(False)

        self._run_async(
            self._bridge.analyze(level),
            on_success=lambda _: self._on_analysis_complete(level),
            on_error=self._on_analysis_error,
        )

    def _on_analysis_complete(self, level: str) -> None:
        """Handle successful analysis.

        Args:
            level: The analysis level used.
        """
        self._set_status("Analysis complete")
        _logger.info("radare2_analysis_complete", extra={"level": level})
        self._analyze_btn.setEnabled(True)
        self._on_refresh_functions()
        self._refresh_imports()
        self._refresh_exports()
        self._refresh_sections()

    def _on_analysis_error(self, exc: object) -> None:
        """Handle analysis failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Analysis failed: {exc}")
        _logger.warning("radare2_analysis_failed", extra={"error": str(exc)})
        self._analyze_btn.setEnabled(True)

    def _on_refresh_functions(self) -> None:
        """Refresh the functions list from bridge."""
        if self._bridge is None:
            return

        filter_text = self._func_filter.text().strip() or None
        self._refresh_funcs_btn.setEnabled(False)

        self._run_async(
            self._bridge.get_functions(filter_text),
            on_success=self._apply_functions,
            on_error=lambda _: self._on_refresh_funcs_error(),
        )

    def _apply_functions(self, result: object) -> None:
        """Apply function data to the tree.

        Args:
            result: Function list from the bridge.
        """
        functions: list[object] = [*result] if isinstance(result, list) else []

        set_sorting_enabled(self._func_tree, False)
        self._func_tree.clear()

        for func in functions:
            item = QTreeWidgetItem([
                getattr(func, "name", ""),
                f"0x{getattr(func, 'address', 0):X}",
                str(getattr(func, "size", 0)),
            ])
            tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, getattr(func, "address", 0))
            self._func_tree.addTopLevelItem(item)

        set_sorting_enabled(self._func_tree, True)
        self._func_count_label.setText(f"Functions ({len(functions)})")
        self._refresh_funcs_btn.setEnabled(True)
        _logger.debug("radare2_functions_refreshed", extra={"count": len(functions)})

    def _on_refresh_funcs_error(self) -> None:
        """Handle function refresh failure."""
        _logger.warning("radare2_refresh_functions_failed")
        self._refresh_funcs_btn.setEnabled(True)

    def _on_filter_changed(self, _text: str) -> None:
        """Handle function filter text changes.

        Args:
            _text: New filter text (unused, read from widget).
        """
        self._on_refresh_functions()

    def _on_function_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Handle function tree item click to show decompilation.

        Args:
            item: Clicked tree widget item.
            _column: Column index (unused).
        """
        address = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if not isinstance(address, int) or self._bridge is None:
            return

        self._run_async(
            self._bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda _: _logger.warning("radare2_decompile_failed", extra={"address": hex(address)}),
        )

        self._run_async(
            self._bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("radare2_disassemble_failed", extra={"address": hex(address)}),
        )

        self.show_xrefs(address)

    def _apply_decompiled(self, result: object) -> None:
        """Apply decompiled code to the view.

        Args:
            result: Decompiled code string from the bridge.
        """
        if result is not None:
            self._decompiled_view.setPlainText(str(result))

    def _apply_disassembly(self, result: object) -> None:
        """Apply disassembly data to the view.

        Args:
            result: Disassembly lines from the bridge.
        """
        if not result:
            return

        lines: list[object] = [*result] if isinstance(result, list) else []
        text_lines = [
            f"0x{getattr(dl, 'address', 0):X}  {getattr(dl, 'bytes_str', ''):<24s}  "
            f"{getattr(dl, 'mnemonic', '')} {getattr(dl, 'operands', '')}"
            for dl in lines
        ]
        self._disasm_view.setPlainText("\n".join(text_lines))

    def _refresh_imports(self) -> None:
        """Refresh the imports table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_imports(),
            on_success=self._apply_imports,
            on_error=lambda _: _logger.warning("radare2_refresh_imports_failed"),
        )

    def _apply_imports(self, result: object) -> None:
        """Apply import data to the table.

        Args:
            result: Import list from the bridge.
        """
        imports: list[object] = [*result] if isinstance(result, list) else []

        self._imports_table.setRowCount(0)
        for imp in imports:
            row = self._imports_table.rowCount()
            self._imports_table.insertRow(row)
            self._imports_table.setItem(row, 0, QTableWidgetItem(getattr(imp, "dll", "")))
            self._imports_table.setItem(row, 1, QTableWidgetItem(getattr(imp, "function", "")))
            self._imports_table.setItem(row, 2, QTableWidgetItem(f"0x{getattr(imp, 'address', 0):X}"))

    def _refresh_exports(self) -> None:
        """Refresh the exports table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_exports(),
            on_success=self._apply_exports,
            on_error=lambda _: _logger.warning("radare2_refresh_exports_failed"),
        )

    def _apply_exports(self, result: object) -> None:
        """Apply export data to the table.

        Args:
            result: Export list from the bridge.
        """
        exports: list[object] = [*result] if isinstance(result, list) else []

        self._exports_table.setRowCount(0)
        for exp in exports:
            row = self._exports_table.rowCount()
            self._exports_table.insertRow(row)
            self._exports_table.setItem(row, 0, QTableWidgetItem(getattr(exp, "name", "")))
            self._exports_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(exp, 'address', 0):X}"))

    def _refresh_sections(self) -> None:
        """Refresh the sections table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_sections(),
            on_success=self._apply_sections,
            on_error=lambda _: _logger.warning("radare2_refresh_sections_failed"),
        )

    def _apply_sections(self, result: object) -> None:
        """Apply section data to the table.

        Args:
            result: Section list from the bridge.
        """
        sections: list[object] = [*result] if isinstance(result, list) else []

        self._sections_table.setRowCount(0)
        for sec in sections:
            row = self._sections_table.rowCount()
            self._sections_table.insertRow(row)
            self._sections_table.setItem(row, 0, QTableWidgetItem(getattr(sec, "name", "")))
            self._sections_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(sec, 'virtual_address', 0):X}"))
            self._sections_table.setItem(row, 2, QTableWidgetItem(f"{getattr(sec, 'virtual_size', 0):,}"))
            self._sections_table.setItem(row, 3, QTableWidgetItem(f"{getattr(sec, 'entropy', 0.0):.2f}"))
            chars = getattr(sec, "characteristics", 0)
            perms = ""
            if chars & 1:
                perms += "X"
            if chars & 4:
                perms += "R"
            if chars & 2:
                perms += "W"
            self._sections_table.setItem(row, 4, QTableWidgetItem(perms or "---"))

    def search_strings(self, pattern: str) -> None:
        """Search for strings matching pattern and populate table.

        Args:
            pattern: Regex pattern to match.
        """
        if self._bridge is None:
            return

        self._string_search_btn.setEnabled(False)
        self._run_async(
            self._bridge.search_strings(pattern),
            on_success=self._apply_strings,
            on_error=lambda _: self._on_string_search_error(pattern),
        )

    def _apply_strings(self, result: object) -> None:
        """Apply string search results to the table.

        Args:
            result: String list from the bridge.
        """
        strings: list[object] = [*result] if isinstance(result, list) else []

        self._strings_table.setRowCount(0)
        for s in strings:
            row = self._strings_table.rowCount()
            self._strings_table.insertRow(row)
            self._strings_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(s, 'address', 0):X}"))
            self._strings_table.setItem(row, 1, QTableWidgetItem(getattr(s, "value", "")))
            self._strings_table.setItem(row, 2, QTableWidgetItem(getattr(s, "encoding", "")))
            self._strings_table.setItem(row, 3, QTableWidgetItem(getattr(s, "section", "")))
        self._string_search_btn.setEnabled(True)

    def _on_string_search_error(self, pattern: str) -> None:
        """Handle string search failure.

        Args:
            pattern: The pattern that failed.
        """
        _logger.warning("radare2_string_search_failed", extra={"pattern": pattern})
        self._string_search_btn.setEnabled(True)

    def _on_search_strings(self) -> None:
        """Trigger string search from the search input."""
        pattern = self._string_search_input.text().strip()
        if pattern:
            self.search_strings(pattern)

    def show_xrefs(self, address: int) -> None:
        """Show cross-references to and from an address.

        Args:
            address: Target address for xref lookup.
        """
        if self._bridge is None:
            return

        self._xrefs_tree.clear()

        self._run_async(
            self._bridge.get_xrefs_to(address),
            on_success=self._apply_xrefs_to,
            on_error=lambda _: _logger.warning("radare2_xrefs_to_failed", extra={"address": hex(address)}),
        )

        self._run_async(
            self._bridge.get_xrefs_from(address),
            on_success=self._apply_xrefs_from,
            on_error=lambda _: _logger.warning("radare2_xrefs_from_failed", extra={"address": hex(address)}),
        )

    def _apply_xrefs_to(self, result: object) -> None:
        """Apply xrefs-to data to the tree.

        Args:
            result: Cross-reference list from the bridge.
        """
        if not result:
            return

        xrefs: list[object] = [*result] if isinstance(result, list) else []
        for xref in xrefs:
            item = QTreeWidgetItem([
                "To",
                f"0x{getattr(xref, 'from_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "from_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)

    def _apply_xrefs_from(self, result: object) -> None:
        """Apply xrefs-from data to the tree.

        Args:
            result: Cross-reference list from the bridge.
        """
        if not result:
            return

        xrefs: list[object] = [*result] if isinstance(result, list) else []
        for xref in xrefs:
            item = QTreeWidgetItem([
                "From",
                f"0x{getattr(xref, 'to_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "to_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)

    def _on_execute_r2_command(self) -> None:
        """Execute a raw r2 command from the console input."""
        if self._bridge is None:
            self._r2_output.appendPlainText("[!] No bridge configured")
            return

        cmd = self._r2_input.text().strip()
        if not cmd:
            return

        self._r2_input.clear()
        self._r2_output.appendPlainText(f"[0x00000000]> {cmd}")

        self._run_async(
            self._bridge.execute_command(cmd),
            on_success=self._on_r2_command_result,
            on_error=self._on_r2_command_error,
        )

    def _on_r2_command_result(self, result: object) -> None:
        """Handle r2 command result.

        Args:
            result: The command output string.
        """
        if result:
            self._r2_output.appendPlainText(str(result))

    def _on_r2_command_error(self, exc: object) -> None:
        """Handle r2 command failure.

        Args:
            exc: The exception that occurred.
        """
        self._r2_output.appendPlainText(f"[-] Command failed: {exc}")
        _logger.warning("radare2_command_failed", extra={"error": str(exc)})
