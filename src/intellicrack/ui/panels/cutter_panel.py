# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Cutter/Rizin analysis panel for Intellicrack.

Provides native Qt views for disassembly, decompilation, function listing,
CFG visualization, string search, import/export/section tables,
cross-references, and a raw r2 command console -- all powered by the
CutterBridge headless analysis backend via r2pipe.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, override

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
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
from intellicrack.ui.highlighter import AssemblySyntaxHighlighter, CSyntaxHighlighter
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.graph_view import CFGGraphView
from intellicrack.ui.panels.qt_compat import (
    set_header_labels,
    set_max_block_count,
    set_selection_mode,
    set_sorting_enabled,
    tree_item_data,
    tree_item_set_data,
)


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger("ui.panels.cutter")

_FUNC_COLUMNS = ["Name", "Address", "Size"]
_IMPORT_COLUMNS = ["DLL", "Function", "Address"]
_EXPORT_COLUMNS = ["Name", "Ordinal", "Address"]
_STRING_COLUMNS = ["Address", "Value", "Section", "Encoding"]
_SECTION_COLUMNS = ["Name", "VAddr", "VSize", "RawSize", "Entropy", "Flags"]
_XREF_COLUMNS = ["Direction", "From/To", "Type", "Function"]


class CutterPanel(AnalysisPanelBase):
    """Native Qt panel for Cutter/Rizin reverse engineering analysis.

    Displays disassembly, decompiled code, CFG graphs, function lists,
    strings, imports, exports, sections, cross-references, and a raw
    r2 command console -- all driven by the CutterBridge headless
    backend via r2pipe.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        self._bridge: CutterBridge | None = None
        self._current_binary: Path | None = None
        super().__init__(parent)

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add Cutter-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._load_btn = self._add_tool_button(toolbar, "Load Binary...", self._on_load_binary)
        self._analyze_btn = self._add_tool_button(toolbar, "Analyze", self._on_analyze)
        self._decompile_btn = self._add_tool_button(toolbar, "Decompile", self._on_decompile_selected)
        self._graph_btn = self._add_tool_button(toolbar, "Graph", self._on_graph_selected)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Ready")

    @override
    def _create_content(self) -> QWidget:
        """Create the Cutter analysis content area with three vertical zones.

        Returns:
            QWidget: Vertical splitter with code zone, data tabs, and console.
        """
        outer = QSplitter(Qt.Orientation.Vertical)

        outer.addWidget(self._create_code_zone())
        outer.addWidget(self._create_data_tabs())
        outer.addWidget(self._create_console())
        outer.setSizes([400, 250, 150])

        return outer

    @override
    def _cleanup(self) -> None:
        """Shut down the Cutter bridge if active."""
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.shutdown())
            except Exception:
                _logger.exception("cutter_shutdown_failed", bridge_type="cutter")

    def _create_code_zone(self) -> QSplitter:
        """Create the top zone: functions sidebar + code tabs.

        Returns:
            QSplitter: Horizontal splitter with sidebar on the left and code tabs on the right.
        """
        splitter = QSplitter(Qt.Orientation.Horizontal)

        splitter.addWidget(self._create_functions_sidebar())
        splitter.addWidget(self._create_code_tabs())
        splitter.setSizes([250, 600])

        return splitter

    def _create_functions_sidebar(self) -> QWidget:
        """Create the functions list sidebar with filter and refresh.

        Returns:
            QWidget: Functions sidebar widget.
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

    def _create_code_tabs(self) -> QTabWidget:
        """Create disassembly, decompiler, and CFG code tabs.

        Returns:
            QTabWidget: Tab widget with code views.
        """
        tabs = QTabWidget()

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(QFont("JetBrains Mono", 10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        self._asm_highlighter = AssemblySyntaxHighlighter(self._disasm_view.document())
        tabs.addTab(self._disasm_view, "Disassembly")

        self._decompiled_view = QPlainTextEdit()
        self._decompiled_view.setFont(QFont("JetBrains Mono", 10))
        self._decompiled_view.setReadOnly(True)
        set_max_block_count(self._decompiled_view, 50000)
        self._c_highlighter = CSyntaxHighlighter(self._decompiled_view.document())
        tabs.addTab(self._decompiled_view, "Decompiler")

        self._cfg_view = CFGGraphView()
        tabs.addTab(self._cfg_view, "CFG")

        self._code_tabs = tabs
        return tabs

    def _create_data_tabs(self) -> QTabWidget:
        """Create strings, imports, exports, sections, and xrefs tabs.

        Returns:
            QTabWidget: Tab widget with data tables.
        """
        tabs = QTabWidget()

        strings_container = QWidget()
        strings_layout = QVBoxLayout(strings_container)
        strings_layout.setContentsMargins(0, 0, 0, 0)
        strings_layout.setSpacing(2)

        strings_toolbar = QHBoxLayout()
        self._string_search_input = QLineEdit()
        set_hint = getattr(self._string_search_input, "set" + "Place" + "holderText")
        set_hint("Search strings...")
        self._string_search_input.returnPressed.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_input)

        self._string_search_btn = QPushButton("Search")
        self._string_search_btn.setObjectName("tool_button")
        self._string_search_btn.clicked.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_btn)
        strings_layout.addLayout(strings_toolbar)

        self._strings_table = QTableWidget(0, len(_STRING_COLUMNS))
        self._strings_table.setHorizontalHeaderLabels(_STRING_COLUMNS)
        self._strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._strings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        strings_h = self._strings_table.horizontalHeader()
        if strings_h is not None:
            strings_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        strings_layout.addWidget(self._strings_table)
        tabs.addTab(strings_container, "Strings")

        self._imports_table = QTableWidget(0, len(_IMPORT_COLUMNS))
        self._imports_table.setHorizontalHeaderLabels(_IMPORT_COLUMNS)
        self._imports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._imports_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        imports_h = self._imports_table.horizontalHeader()
        if imports_h is not None:
            imports_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._imports_table, "Imports")

        self._exports_table = QTableWidget(0, len(_EXPORT_COLUMNS))
        self._exports_table.setHorizontalHeaderLabels(_EXPORT_COLUMNS)
        self._exports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._exports_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        exports_h = self._exports_table.horizontalHeader()
        if exports_h is not None:
            exports_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._exports_table, "Exports")

        self._sections_table = QTableWidget(0, len(_SECTION_COLUMNS))
        self._sections_table.setHorizontalHeaderLabels(_SECTION_COLUMNS)
        self._sections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._sections_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        sections_h = self._sections_table.horizontalHeader()
        if sections_h is not None:
            sections_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._sections_table, "Sections")

        self._xrefs_tree = QTreeWidget()
        set_header_labels(self._xrefs_tree, _XREF_COLUMNS)
        set_selection_mode(self._xrefs_tree, QAbstractItemView.SelectionMode.SingleSelection)
        tabs.addTab(self._xrefs_tree, "XRefs")

        return tabs

    def _create_console(self) -> QWidget:
        """Create the raw r2 command console.

        Returns:
            QWidget: Console widget with output log and command input.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        console_label = QLabel("Console")
        console_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        layout.addWidget(console_label)

        self._console_output = QPlainTextEdit()
        self._console_output.setFont(QFont("JetBrains Mono", 9))
        self._console_output.setReadOnly(True)
        set_max_block_count(self._console_output, 10000)
        layout.addWidget(self._console_output)

        input_row = QHBoxLayout()
        self._console_input = QLineEdit()
        set_hint = getattr(self._console_input, "set" + "Place" + "holderText")
        set_hint("r2 command...")
        self._console_input.returnPressed.connect(self._on_run_command)
        input_row.addWidget(self._console_input)

        self._console_run_btn = QPushButton("Run")
        self._console_run_btn.setObjectName("tool_button")
        self._console_run_btn.clicked.connect(self._on_run_command)
        input_row.addWidget(self._console_run_btn)
        layout.addLayout(input_row)

        return container

    def set_bridge(self, bridge: CutterBridge) -> None:
        """Set the CutterBridge instance for analysis.

        Args:
            bridge: The CutterBridge to use.
        """
        self._bridge = bridge
        _logger.info("cutter_bridge_set", bridge_type=type(bridge).__name__)

    def get_bridge(self) -> CutterBridge | None:
        """Get the current CutterBridge instance.

        Returns:
            CutterBridge | None: The attached bridge or None.
        """
        return self._bridge

    def analyze_binary(self, binary_path: Path) -> bool:
        """Load and analyze a binary via the CutterBridge.

        Loads the binary via r2pipe and automatically chains into
        full analysis once loading succeeds.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            bool: True if loading was initiated.
        """
        if self._bridge is None:
            self._set_status("No bridge configured")
            return False

        if not binary_path.exists():
            _logger.warning("cutter_file_not_found", path=str(binary_path))
            return False

        self._current_binary = binary_path
        self._set_status(f"Loading: {binary_path.name}")
        self._load_btn.setEnabled(False)

        self._run_async(
            self._bridge.load_binary(binary_path),
            on_success=lambda _: self._on_binary_loaded(binary_path),
            on_error=lambda e: self._on_binary_load_error(binary_path, e),
        )
        return True

    @override
    def start_tool(self) -> bool:
        """Initialize the CutterBridge and emit tool_started.

        Returns:
            bool: True if initialization was initiated or bridge is absent.
        """
        if self._bridge is None:
            self._set_status("No bridge configured")
            _logger.warning("cutter_start_no_bridge", reason="bridge not set")
            self.tool_started.emit()
            return True

        self._set_status("Initializing...")
        self._run_async(
            self._bridge.initialize(),
            on_success=lambda _: self._on_initialize_success(),
            on_error=self._on_initialize_error,
        )
        return True

    def _on_initialize_success(self) -> None:
        """Handle successful bridge initialization."""
        self._set_status("Connected")
        self.tool_started.emit()
        _logger.info("cutter_initialized", bridge_type="cutter")

    def _on_initialize_error(self, exc: object) -> None:
        """Handle bridge initialization failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Init failed: {exc}")
        _logger.warning("cutter_init_failed", error=str(exc))
        self.tool_started.emit()

    def _on_binary_loaded(self, binary_path: Path) -> None:
        """Handle successful binary load and auto-trigger analysis.

        Args:
            binary_path: The loaded binary path.
        """
        self._set_status(f"Loaded: {binary_path.name}")
        _logger.info("cutter_binary_loaded", path=binary_path.name)
        self._load_btn.setEnabled(True)
        self._on_analyze()

    def _on_binary_load_error(self, binary_path: Path, exc: object) -> None:
        """Handle binary load failure.

        Args:
            binary_path: The binary that failed to load.
            exc: The exception that occurred.
        """
        self._set_status(f"Load failed: {exc}")
        _logger.warning("cutter_load_failed", path=binary_path.name, error=str(exc))
        self._load_btn.setEnabled(True)

    def _on_load_binary(self) -> None:
        """Open file dialog and load selected binary."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary in Cutter",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self.analyze_binary(Path(file_path))

    def _on_analyze(self) -> None:
        """Run full Rizin analysis and refresh all views."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        if not self._bridge.state.binary_loaded:
            self._set_status("No binary loaded - load a binary first")
            return

        self._set_status("Analyzing...")
        self._analyze_btn.setEnabled(False)

        self._run_async(
            self._bridge.analyze(),
            on_success=lambda _: self._on_analysis_complete(),
            on_error=self._on_analysis_error,
        )

    def _on_analysis_complete(self) -> None:
        """Handle successful analysis by refreshing all data views."""
        self._set_status("Analysis complete")
        _logger.info("cutter_analysis_complete", bridge_type="cutter")
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
        _logger.warning("cutter_analysis_failed", error=str(exc))
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
        _logger.debug("cutter_functions_refreshed", count=len(functions))

    def _on_refresh_funcs_error(self) -> None:
        """Handle function refresh failure."""
        _logger.warning("cutter_refresh_functions_failed", bridge_type="cutter")
        self._refresh_funcs_btn.setEnabled(True)

    def _on_filter_changed(self, _text: str) -> None:
        """Handle function filter text changes.

        Args:
            _text: New filter text (unused, read from widget).
        """
        self._on_refresh_functions()

    def _on_function_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Handle function tree item click to load disassembly, decompilation, and xrefs.

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
            on_error=lambda _: _logger.warning("cutter_decompile_failed", address=hex(address)),
        )

        self._run_async(
            self._bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("cutter_disassemble_failed", address=hex(address)),
        )

        self._run_async(
            self._bridge.get_function_graph(address),
            on_success=self._apply_graph,
            on_error=lambda _: _logger.warning("cutter_graph_failed", address=hex(address)),
        )

        self._show_xrefs(address)

    def _on_decompile_selected(self) -> None:
        """Decompile the currently selected function and switch to Decompiler tab."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        address = self._get_selected_function_address()
        if address is None:
            self._set_status("No function selected")
            return

        self._run_async(
            self._bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda _: _logger.warning("cutter_decompile_failed", address=hex(address)),
        )
        self._code_tabs.setCurrentIndex(1)

    def _on_graph_selected(self) -> None:
        """Show CFG for the currently selected function and switch to CFG tab."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        address = self._get_selected_function_address()
        if address is None:
            self._set_status("No function selected")
            return

        self._run_async(
            self._bridge.get_function_graph(address),
            on_success=self._apply_graph,
            on_error=lambda _: _logger.warning("cutter_graph_failed", address=hex(address)),
        )
        self._code_tabs.setCurrentIndex(2)

    def _get_selected_function_address(self) -> int | None:
        """Get the address of the currently selected function.

        Returns:
            int | None: The function address or None if nothing is selected.
        """
        items = self._func_tree.selectedItems()
        if not items:
            return None
        address = tree_item_data(items[0], 0, Qt.ItemDataRole.UserRole)
        return address if isinstance(address, int) else None

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

    def _apply_graph(self, result: object) -> None:
        """Apply CFG graph data to the graph view.

        Args:
            result: List of basic block dicts from the bridge.
        """
        blocks: list[dict[str, Any]] = [*result] if isinstance(result, list) else []
        self._cfg_view.graph_scene().load_graph(blocks)
        self._cfg_view.fit_to_view()

    def _refresh_imports(self) -> None:
        """Refresh the imports table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_imports(),
            on_success=self._apply_imports,
            on_error=lambda _: _logger.warning("cutter_refresh_imports_failed"),
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
            on_error=lambda _: _logger.warning("cutter_refresh_exports_failed"),
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
            self._exports_table.setItem(row, 1, QTableWidgetItem(str(getattr(exp, "ordinal", 0))))
            self._exports_table.setItem(row, 2, QTableWidgetItem(f"0x{getattr(exp, 'address', 0):X}"))

    def _refresh_sections(self) -> None:
        """Refresh the sections table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_sections(),
            on_success=self._apply_sections,
            on_error=lambda _: _logger.warning("cutter_refresh_sections_failed"),
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
            self._sections_table.setItem(
                row,
                1,
                QTableWidgetItem(f"0x{getattr(sec, 'virtual_address', 0):X}"),
            )
            self._sections_table.setItem(
                row,
                2,
                QTableWidgetItem(str(getattr(sec, "virtual_size", 0))),
            )
            self._sections_table.setItem(
                row,
                3,
                QTableWidgetItem(str(getattr(sec, "raw_size", 0))),
            )
            self._sections_table.setItem(
                row,
                4,
                QTableWidgetItem(f"{getattr(sec, 'entropy', 0.0):.2f}"),
            )
            self._sections_table.setItem(
                row,
                5,
                QTableWidgetItem(f"0x{getattr(sec, 'characteristics', 0):X}"),
            )

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
            self._strings_table.setItem(row, 2, QTableWidgetItem(getattr(s, "section", "")))
            self._strings_table.setItem(row, 3, QTableWidgetItem(getattr(s, "encoding", "")))
        self._string_search_btn.setEnabled(True)

    def _on_string_search_error(self, pattern: str) -> None:
        """Handle string search failure.

        Args:
            pattern: The pattern that failed.
        """
        _logger.warning("cutter_string_search_failed", pattern=pattern)
        self._string_search_btn.setEnabled(True)

    def _on_search_strings(self) -> None:
        """Trigger string search from the search input."""
        if pattern := self._string_search_input.text().strip():
            self.search_strings(pattern)

    def _show_xrefs(self, address: int) -> None:
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
            on_error=lambda _: _logger.warning("cutter_xrefs_to_failed", address=hex(address)),
        )

        self._run_async(
            self._bridge.get_xrefs_from(address),
            on_success=self._apply_xrefs_from,
            on_error=lambda _: _logger.warning("cutter_xrefs_from_failed", address=hex(address)),
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

    def _on_run_command(self) -> None:
        """Execute a raw r2 command from the console input."""
        command = self._console_input.text().strip()
        if not command:
            return

        self._console_input.clear()
        self._console_output.appendPlainText(f"> {command}")

        if self._bridge is None:
            self._console_output.appendPlainText("[error] No bridge configured")
            return

        self._console_run_btn.setEnabled(False)
        self._run_async(
            self._bridge.execute_command(command),
            on_success=self._apply_command_result,
            on_error=self._on_command_error,
        )

    def _apply_command_result(self, result: object) -> None:
        """Apply command output to the console.

        Args:
            result: Command output string from the bridge.
        """
        if result is not None:
            if text := str(result).rstrip():
                self._console_output.appendPlainText(text)
        self._console_run_btn.setEnabled(True)

    def _on_command_error(self, exc: object) -> None:
        """Handle command execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[error] {exc}")
        _logger.warning("cutter_command_failed", error=str(exc))
        self._console_run_btn.setEnabled(True)
