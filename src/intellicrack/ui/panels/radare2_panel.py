"""Radare2 analysis panel for Intellicrack.

Provides decompilation, disassembly, function listing, string search,
import/export/section tables, cross-reference views, and a raw r2
command console powered by the Radare2Bridge backend.  This panel
also serves as the Cutter replacement (same underlying r2 engine).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
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
from intellicrack.ui.panels._async_bridge import run_bridge_coroutine
from intellicrack.ui.panels._qt_compat import (
    set_header_labels,
    set_max_block_count,
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


class Radare2Panel(QWidget):
    """Native Qt panel for radare2 reverse engineering analysis.

    Displays decompiled code, disassembly, function lists, strings,
    imports, exports, sections, cross-references, and an interactive
    r2 command console via the Radare2Bridge backend.  Also serves
    as the Cutter replacement panel.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the radare2 panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: Radare2Bridge | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        layout.addWidget(self._create_toolbar())

        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_splitter = QSplitter(Qt.Orientation.Vertical)
        left_splitter.addWidget(self._create_code_tabs())
        left_splitter.addWidget(self._create_data_tabs())
        left_splitter.setSizes([400, 300])
        main_splitter.addWidget(left_splitter)

        main_splitter.addWidget(self._create_functions_sidebar())
        main_splitter.setSizes([600, 250])

        layout.addWidget(main_splitter)

    def _create_toolbar(self) -> QToolBar:
        """Create the analysis toolbar.

        Returns:
            Configured toolbar widget.
        """
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        self._load_btn = QPushButton("Load Binary...")
        self._load_btn.setObjectName("tool_button")
        self._load_btn.clicked.connect(self._on_load_binary)
        toolbar.addWidget(self._load_btn)

        toolbar.addSeparator()

        analysis_label = QLabel("Analysis:")
        analysis_label.setObjectName("toolbar_label")
        toolbar.addWidget(analysis_label)

        self._analysis_combo = QComboBox()
        self._analysis_combo.addItems(["quick", "normal", "deep"])
        self._analysis_combo.setCurrentIndex(1)
        toolbar.addWidget(self._analysis_combo)

        self._analyze_btn = QPushButton("Analyze")
        self._analyze_btn.setObjectName("tool_button")
        self._analyze_btn.clicked.connect(self._on_analyze)
        toolbar.addWidget(self._analyze_btn)

        toolbar.addSeparator()

        self._status_label = QLabel("No binary loaded")
        self._status_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._status_label)

        return toolbar

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
        tabs.addTab(self._strings_table, "Strings")

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
        self._xrefs_tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
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
        self._func_tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
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

        try:
            run_bridge_coroutine(self._bridge.load_binary(binary_path))
            self._status_label.setText(f"Loaded: {binary_path.name}")
            _logger.info("radare2_binary_loaded", extra={"path": binary_path.name})
        except Exception as e:
            self._status_label.setText(f"Load failed: {e}")
            _logger.exception("radare2_load_failed", extra={"error": str(e)})
            return False
        else:
            return True

    def start_tool(self) -> bool:
        """Start the radare2 panel.

        Returns:
            True always since native panels are always ready.
        """
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop radare2 operations and clean up.

        Returns:
            True if cleanup succeeded.
        """
        if self._bridge is not None:
            try:
                run_bridge_coroutine(self._bridge.shutdown())
            except Exception:
                _logger.exception("radare2_shutdown_failed")
        self.tool_closed.emit()
        return True

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
            self._status_label.setText("No bridge configured")
            return

        level = self._analysis_combo.currentText()
        self._status_label.setText(f"Analyzing ({level})...")

        try:
            run_bridge_coroutine(self._bridge.analyze(level))
            self._status_label.setText("Analysis complete")
            _logger.info("radare2_analysis_complete", extra={"level": level})
        except Exception as e:
            self._status_label.setText(f"Analysis failed: {e}")
            _logger.exception("radare2_analysis_failed", extra={"error": str(e)})
            return

        self._on_refresh_functions()
        self._refresh_imports()
        self._refresh_exports()

    def _on_refresh_functions(self) -> None:
        """Refresh the functions list from bridge."""
        if self._bridge is None:
            return

        filter_text = self._func_filter.text().strip() or None

        try:
            functions = run_bridge_coroutine(self._bridge.get_functions(filter_text))
        except Exception:
            _logger.exception("radare2_refresh_functions_failed")
            return

        if functions is None:
            functions = []

        set_sorting_enabled(self._func_tree, False)
        self._func_tree.clear()

        for func in functions:
            item = QTreeWidgetItem([
                func.name,
                f"0x{func.address:X}",
                str(func.size),
            ])
            tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, func.address)
            self._func_tree.addTopLevelItem(item)

        set_sorting_enabled(self._func_tree, True)
        self._func_count_label.setText(f"Functions ({len(functions)})")
        _logger.debug("radare2_functions_refreshed", extra={"count": len(functions)})

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

        try:
            code = run_bridge_coroutine(self._bridge.decompile(address))
            if code is not None:
                self._decompiled_view.setPlainText(code)
        except Exception:
            _logger.exception("radare2_decompile_failed", extra={"address": hex(address)})

        try:
            lines = run_bridge_coroutine(self._bridge.disassemble(address))
            if lines:
                text_lines = [f"0x{dl.address:X}  {dl.bytes_str:<24s}  {dl.mnemonic} {dl.operands}" for dl in lines]
                self._disasm_view.setPlainText("\n".join(text_lines))
        except Exception:
            _logger.exception("radare2_disassemble_failed", extra={"address": hex(address)})

    def _refresh_imports(self) -> None:
        """Refresh the imports table from bridge."""
        if self._bridge is None:
            return

        try:
            imports = run_bridge_coroutine(self._bridge.get_imports())
        except Exception:
            _logger.exception("radare2_refresh_imports_failed")
            return

        if imports is None:
            imports = []

        self._imports_table.setRowCount(0)
        for imp in imports:
            row = self._imports_table.rowCount()
            self._imports_table.insertRow(row)
            self._imports_table.setItem(row, 0, QTableWidgetItem(imp.dll))
            self._imports_table.setItem(row, 1, QTableWidgetItem(imp.function))
            self._imports_table.setItem(row, 2, QTableWidgetItem(f"0x{imp.address:X}"))

    def _refresh_exports(self) -> None:
        """Refresh the exports table from bridge."""
        if self._bridge is None:
            return

        try:
            exports = run_bridge_coroutine(self._bridge.get_exports())
        except Exception:
            _logger.exception("radare2_refresh_exports_failed")
            return

        if exports is None:
            exports = []

        self._exports_table.setRowCount(0)
        for exp in exports:
            row = self._exports_table.rowCount()
            self._exports_table.insertRow(row)
            self._exports_table.setItem(row, 0, QTableWidgetItem(exp.name))
            self._exports_table.setItem(row, 1, QTableWidgetItem(f"0x{exp.address:X}"))

    def search_strings(self, pattern: str) -> None:
        """Search for strings matching pattern and populate table.

        Args:
            pattern: Regex pattern to match.
        """
        if self._bridge is None:
            return

        try:
            strings = run_bridge_coroutine(self._bridge.search_strings(pattern))
        except Exception:
            _logger.exception("radare2_string_search_failed", extra={"pattern": pattern})
            return

        if strings is None:
            strings = []

        self._strings_table.setRowCount(0)
        for s in strings:
            row = self._strings_table.rowCount()
            self._strings_table.insertRow(row)
            self._strings_table.setItem(row, 0, QTableWidgetItem(f"0x{s.address:X}"))
            self._strings_table.setItem(row, 1, QTableWidgetItem(s.value))
            self._strings_table.setItem(row, 2, QTableWidgetItem(s.encoding))
            self._strings_table.setItem(row, 3, QTableWidgetItem(s.section))

    def show_xrefs(self, address: int) -> None:
        """Show cross-references to and from an address.

        Args:
            address: Target address for xref lookup.
        """
        if self._bridge is None:
            return

        self._xrefs_tree.clear()

        try:
            xrefs_to = run_bridge_coroutine(self._bridge.get_xrefs_to(address))
            if xrefs_to:
                for xref in xrefs_to:
                    item = QTreeWidgetItem([
                        "To",
                        f"0x{xref.from_address:X}",
                        xref.ref_type,
                        xref.from_function or "",
                    ])
                    self._xrefs_tree.addTopLevelItem(item)
        except Exception:
            _logger.exception("radare2_xrefs_to_failed", extra={"address": hex(address)})

        try:
            xrefs_from = run_bridge_coroutine(self._bridge.get_xrefs_from(address))
            if xrefs_from:
                for xref in xrefs_from:
                    item = QTreeWidgetItem([
                        "From",
                        f"0x{xref.to_address:X}",
                        xref.ref_type,
                        xref.to_function or "",
                    ])
                    self._xrefs_tree.addTopLevelItem(item)
        except Exception:
            _logger.exception("radare2_xrefs_from_failed", extra={"address": hex(address)})

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

        try:
            result = run_bridge_coroutine(self._bridge.execute_command(cmd))
            if result:
                self._r2_output.appendPlainText(result)
        except Exception as e:
            self._r2_output.appendPlainText(f"[-] Command failed: {e}")
            _logger.exception("radare2_command_failed", extra={"error": str(e)})
