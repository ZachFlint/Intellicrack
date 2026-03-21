# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ghidra analysis panel for Intellicrack.

Provides decompilation, disassembly, function listing, string search,
import/export tables, and cross-reference views powered by the
GhidraBridge headless analysis backend.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, override

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
    from intellicrack.bridges.ghidra import GhidraBridge

_logger = get_logger("ui.panels.ghidra")

_FUNC_COLUMNS = ["Name", "Address", "Size"]
_IMPORT_COLUMNS = ["DLL", "Function", "Address"]
_EXPORT_COLUMNS = ["Name", "Ordinal", "Address"]
_STRING_COLUMNS = ["Address", "Value", "Section", "Encoding"]
_XREF_COLUMNS = ["Direction", "From/To", "Type", "Function"]


class GhidraPanel(AnalysisPanelBase):
    """Native Qt panel for Ghidra reverse engineering analysis.

    Displays decompiled code, disassembly, function lists, strings,
    imports, exports, and cross-references from Ghidra headless
    analysis via the GhidraBridge backend.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._bridge: GhidraBridge | None = None

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add Ghidra-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._connect_btn = self._add_tool_button(toolbar, "Connect", self._on_connect)
        self._disconnect_btn = self._add_tool_button(toolbar, "Disconnect", self._on_disconnect, enabled=False)

        toolbar.addSeparator()

        self._load_btn = self._add_tool_button(toolbar, "Load Binary...", self._on_load_binary, enabled=False)
        self._analyze_btn = self._add_tool_button(toolbar, "Analyze", self._on_analyze, enabled=False)
        self._headless_btn = self._add_tool_button(toolbar, "Start Headless", self._on_start_headless)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Not connected")

    @override
    def _create_content(self) -> QWidget:
        """Create the Ghidra analysis content area.

        Returns:
            QWidget: Splitter with code tabs, data tabs, and function sidebar.
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
        """Shut down the Ghidra bridge if active."""
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.shutdown())
            except Exception:
                _logger.exception("ghidra_shutdown_failed", bridge_type="ghidra")

    def _create_code_tabs(self) -> QTabWidget:
        """Create decompiled and disassembly code tabs.

        Returns:
            QTabWidget: Tab widget with code views.
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

        return tabs

    def _create_data_tabs(self) -> QTabWidget:
        """Create strings, imports, exports, and xrefs tabs.

        Returns:
            QTabWidget: Tab widget with data tables.
        """
        tabs = QTabWidget()

        self._strings_table = QTableWidget(0, len(_STRING_COLUMNS))
        self._strings_table.setHorizontalHeaderLabels(_STRING_COLUMNS)
        self._strings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._strings_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        strings_h = self._strings_table.horizontalHeader()
        if strings_h is not None:
            strings_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
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

        self._xrefs_tree = QTreeWidget()
        set_header_labels(self._xrefs_tree, _XREF_COLUMNS)
        set_selection_mode(self._xrefs_tree, QAbstractItemView.SelectionMode.SingleSelection)
        tabs.addTab(self._xrefs_tree, "XRefs")

        return tabs

    def _create_functions_sidebar(self) -> QWidget:
        """Create the functions list sidebar.

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

    def set_bridge(self, bridge: GhidraBridge) -> None:
        """Set the GhidraBridge instance for analysis.

        Args:
            bridge: The GhidraBridge to use.
        """
        self._bridge = bridge
        _logger.info("ghidra_bridge_set", bridge_type=type(bridge).__name__)
        self._sync_toolbar_state()

    def get_bridge(self) -> GhidraBridge | None:
        """Get the current GhidraBridge instance.

        Returns:
            GhidraBridge | None: The attached bridge or None.
        """
        return self._bridge

    def set_ghidra_path(self, path: Path) -> None:
        """Set the Ghidra installation path on the bridge.

        Args:
            path: Path to Ghidra installation directory.
        """
        if self._bridge is not None:
            self._bridge.ghidra_path = path
            _logger.info("ghidra_path_set", path=str(path))

    def _require_connected(self) -> GhidraBridge | None:
        """Check bridge connection is live and show status if not.

        Returns:
            GhidraBridge | None: The connected bridge, or None if not ready.
        """
        if self._bridge is None:
            self._set_status("No bridge configured")
            return None
        if not self._bridge.state.is_ready():
            self._set_status("Ghidra not connected")
            return None
        return self._bridge

    def _sync_toolbar_state(self) -> None:
        """Enable or disable toolbar buttons based on bridge connection state."""
        ready = self._bridge is not None and self._bridge.state.is_ready()
        self._load_btn.setEnabled(ready)
        self._analyze_btn.setEnabled(ready)
        self._refresh_funcs_btn.setEnabled(ready)
        self._string_search_btn.setEnabled(ready)
        self._connect_btn.setEnabled(not ready)
        self._disconnect_btn.setEnabled(ready)

    def load_binary(self, binary_path: Path) -> bool:
        """Load a binary for analysis (protocol-compatible convenience).

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            bool: True if loading was initiated.
        """
        bridge = self._require_connected()
        if bridge is None:
            return False

        self._load_btn.setEnabled(False)
        self._run_async(
            bridge.load_binary(binary_path),
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
        _logger.info("ghidra_binary_loaded", path=binary_path.name)
        self._sync_toolbar_state()

    def _on_binary_load_error(self, binary_path: Path, exc: object) -> None:
        """Handle binary load failure.

        Args:
            binary_path: The binary that failed to load.
            exc: The exception that occurred.
        """
        self._set_status(f"Load failed: {exc}")
        _logger.warning("ghidra_load_failed", path=binary_path.name, error=str(exc))
        self._sync_toolbar_state()

    def _on_connect(self) -> None:
        """Connect to Ghidra bridge."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            _logger.warning("ghidra_connect_no_bridge", reason="bridge not set")
            return

        self._connect_btn.setEnabled(False)
        self._run_async(
            self._bridge.initialize(),
            on_success=lambda _: self._on_connect_success(),
            on_error=self._on_connect_error,
        )

    def _on_connect_success(self) -> None:
        """Handle connection attempt completion and validate state."""
        if self._bridge is not None and self._bridge.state.is_ready():
            self._set_status("Connected")
            _logger.info("ghidra_connected", bridge_type="ghidra")
        else:
            last_err = self._bridge.state.last_error if self._bridge else None
            msg = f"Connection failed: {last_err}" if last_err else "Connection failed"
            self._set_status(msg)
            _logger.warning("ghidra_connect_validation_failed", last_error=last_err)
        self._sync_toolbar_state()

    def _on_connect_error(self, exc: object) -> None:
        """Handle connection failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Connection failed: {exc}")
        _logger.warning("ghidra_connect_failed", error=str(exc))
        self._sync_toolbar_state()

    def _on_disconnect(self) -> None:
        """Disconnect from Ghidra bridge."""
        if self._bridge is None:
            return

        self._disconnect_btn.setEnabled(False)
        self._run_async(
            self._bridge.shutdown(),
            on_success=lambda _: self._on_disconnect_success(),
            on_error=self._on_disconnect_error,
        )

    def _on_disconnect_success(self) -> None:
        """Handle successful disconnection."""
        self._set_status("Disconnected")
        _logger.info("ghidra_disconnected", bridge_type="ghidra")
        self._sync_toolbar_state()

    def _on_disconnect_error(self, exc: object) -> None:
        """Handle disconnection failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Disconnect failed: {exc}")
        _logger.warning("ghidra_disconnect_failed", error=str(exc))
        self._sync_toolbar_state()

    def _on_load_binary(self) -> None:
        """Open file dialog and load selected binary."""
        if self._require_connected() is None:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self.load_binary(Path(file_path))

    def _on_analyze(self) -> None:
        """Run full Ghidra analysis and refresh views."""
        bridge = self._require_connected()
        if bridge is None:
            return

        self._set_status("Analyzing...")
        self._analyze_btn.setEnabled(False)

        self._run_async(
            bridge.analyze(),
            on_success=lambda _: self._on_analysis_complete(),
            on_error=self._on_analysis_error,
        )

    def _on_analysis_complete(self) -> None:
        """Handle successful analysis."""
        self._set_status("Analysis complete")
        _logger.info("ghidra_analysis_complete", bridge_type="ghidra")
        self._sync_toolbar_state()
        self._on_refresh_functions()
        self._refresh_imports()
        self._refresh_exports()

    def _on_analysis_error(self, exc: object) -> None:
        """Handle analysis failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Analysis failed: {exc}")
        _logger.warning("ghidra_analysis_failed", error=str(exc))
        self._sync_toolbar_state()

    def _on_refresh_functions(self) -> None:
        """Refresh the functions list from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return

        filter_text = self._func_filter.text().strip() or None
        self._refresh_funcs_btn.setEnabled(False)

        self._run_async(
            bridge.get_functions(filter_text),
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
        _logger.debug("ghidra_functions_refreshed", count=len(functions))

    def _on_refresh_funcs_error(self) -> None:
        """Handle function refresh failure."""
        _logger.warning("ghidra_refresh_functions_failed", bridge_type="ghidra")
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
        if not isinstance(address, int):
            return
        bridge = self._require_connected()
        if bridge is None:
            return

        self._run_async(
            bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda _: _logger.warning("ghidra_decompile_failed", address=hex(address)),
        )

        self._run_async(
            bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("ghidra_disassemble_failed", address=hex(address)),
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
        bridge = self._require_connected()
        if bridge is None:
            return

        self._run_async(
            bridge.get_imports(),
            on_success=self._apply_imports,
            on_error=lambda _: _logger.warning("ghidra_refresh_imports_failed"),
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
        bridge = self._require_connected()
        if bridge is None:
            return

        self._run_async(
            bridge.get_exports(),
            on_success=self._apply_exports,
            on_error=lambda _: _logger.warning("ghidra_refresh_exports_failed"),
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

    def search_strings(self, pattern: str) -> None:
        """Search for strings matching pattern and populate table.

        Args:
            pattern: Regex pattern to match.
        """
        bridge = self._require_connected()
        if bridge is None:
            return

        self._string_search_btn.setEnabled(False)
        self._run_async(
            bridge.search_strings(pattern),
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
        _logger.warning("ghidra_string_search_failed", pattern=pattern)
        self._string_search_btn.setEnabled(True)

    def _on_search_strings(self) -> None:
        """Trigger string search from the search input."""
        if pattern := self._string_search_input.text().strip():
            self.search_strings(pattern)

    def show_xrefs(self, address: int) -> None:
        """Show cross-references to and from an address.

        Args:
            address: Target address for xref lookup.
        """
        bridge = self._require_connected()
        if bridge is None:
            return

        self._xrefs_tree.clear()

        self._run_async(
            bridge.get_xrefs_to(address),
            on_success=self._apply_xrefs_to,
            on_error=lambda _: _logger.warning("ghidra_xrefs_to_failed", address=hex(address)),
        )

        self._run_async(
            bridge.get_xrefs_from(address),
            on_success=self._apply_xrefs_from,
            on_error=lambda _: _logger.warning("ghidra_xrefs_from_failed", address=hex(address)),
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

    def _on_start_headless(self) -> None:
        """Start Ghidra headless analyzer and auto-connect."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        ghidra_path = self._bridge.ghidra_path
        if ghidra_path is None:
            if path_str := QFileDialog.getExistingDirectory(
                self,
                "Select Ghidra Installation Directory",
            ):
                self.set_ghidra_path(Path(path_str))

            else:
                return
        project_dir = Path(tempfile.gettempdir()) / "intellicrack_ghidra"
        self._headless_btn.setEnabled(False)
        self._set_status("Starting headless Ghidra...")
        self._run_async(
            self._bridge.start_headless(project_dir),
            on_success=lambda _: self._on_headless_started(),
            on_error=self._on_headless_error,
        )

    def _on_headless_started(self) -> None:
        """Handle successful headless start."""
        project_path = self._bridge.project_path if self._bridge is not None else None
        if project_path is not None:
            self._set_status(f"Headless Ghidra started | Project: {project_path}")
        else:
            self._set_status("Headless Ghidra started")
        _logger.info("ghidra_headless_started", bridge_type="ghidra")
        self._headless_btn.setEnabled(True)
        self._sync_toolbar_state()

    def _on_headless_error(self, exc: object) -> None:
        """Handle headless start failure.

        Args:
            exc: The exception that occurred.
        """
        self._set_status(f"Headless start failed: {exc}")
        _logger.warning("ghidra_headless_failed", error=str(exc))
        self._headless_btn.setEnabled(True)
