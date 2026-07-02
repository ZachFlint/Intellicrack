# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Cutter/Rizin analysis panel for Intellicrack.

Provides native Qt views for disassembly, decompilation, function listing, CFG visualization, string search, import/export/section tables,
cross-references, and a raw r2 command console -- all powered by the CutterBridge headless analysis backend via r2pipe.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, override

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtGui import QAction, QClipboard
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.cutter_debugger_tab import DebuggerTab
from intellicrack.ui.panels.cutter_project_tab import ProjectTab
from intellicrack.ui.panels.cutter_search_tab import SearchTab
from intellicrack.ui.panels.cutter_static_extra_tab import StaticAnalysisExtrasTab
from intellicrack.ui.panels.cutter_tabs import (
    AllStringsTab,
    CommentsTab,
    ConfigTab,
    ESILConsoleTab,
    FlagsTab,
    HeadersTab,
    HexdumpTab,
    LibrariesTab,
    RelocationsTab,
    ResourcesTab,
    ROPGadgetsTab,
    SegmentsTab,
    SymbolsTab,
    TypeBrowserTab,
)
from intellicrack.ui.panels.graph_view import CFGGraphView
from intellicrack.ui.panels.qt_compat import (
    set_header_labels,
    set_max_block_count,
    set_selection_mode,
    set_sorting_enabled,
    tree_item_data,
    tree_item_set_data,
)
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_OUTER_SPLIT_TOP: Final[int] = 400
_OUTER_SPLIT_MID: Final[int] = 250
_OUTER_SPLIT_BOT: Final[int] = 150
_INNER_SPLIT_LEFT: Final[int] = 250
_INNER_SPLIT_RIGHT: Final[int] = 600

_ANALYSIS_LEVELS: Final[list[str]] = ["quick", "normal", "deep"]
_DEFAULT_ANALYSIS_LEVEL: Final[str] = "normal"

_FUNC_COLUMNS = ["Name", "Address", "Size"]
_IMPORT_COLUMNS = ["DLL", "Function", "Address"]
_EXPORT_COLUMNS = ["Name", "Ordinal", "Address"]
_STRING_COLUMNS = ["Address", "Value", "Section", "Encoding"]
_SECTION_COLUMNS = ["Name", "VAddr", "VSize", "RawSize", "Entropy", "Flags"]
_XREF_COLUMNS = ["Direction", "From/To", "Type", "Function"]


def perm_to_rwx(perm: int) -> str:
    """Convert a Rizin section permission integer to an rwx string.

    Args:
        perm: Permission flags (4=read, 2=write, 1=execute).

    Returns:
        str: Human-readable permission string like 'r-x'.
    """
    r = "r" if perm & 4 else "-"
    w = "w" if perm & 2 else "-"
    x = "x" if perm & 1 else "-"
    return f"{r}{w}{x}"


class CutterPanel(AnalysisPanelBase):
    """Native Qt panel for Cutter/Rizin reverse engineering analysis.

    Displays disassembly, decompiled code, CFG graphs, function lists, strings, imports, exports, sections, cross-references, and a raw r2
    command console -- all driven by the CutterBridge headless backend via r2pipe.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CutterPanel widget.

        Args:
            parent: Parent widget.
        """
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

        self._analysis_level_combo = QComboBox()
        self._analysis_level_combo.addItems(_ANALYSIS_LEVELS)
        self._analysis_level_combo.setCurrentText(_DEFAULT_ANALYSIS_LEVEL)
        self._analysis_level_combo.setToolTip("Analysis depth: quick (aa), normal (aaa), deep (aaaa)")
        toolbar.addWidget(self._analysis_level_combo)

        self._analyze_btn = self._add_tool_button(toolbar, "Analyze", self._on_analyze)
        self._decompile_btn = self._add_tool_button(toolbar, "Decompile", self._on_decompile_selected)
        self._graph_btn = self._add_tool_button(toolbar, "Graph", self._on_graph_selected)

        toolbar.addSeparator()

        self._save_btn = self._add_tool_button(toolbar, "Save Binary", self._on_save_binary)
        self._patch_btn = self._add_tool_button(toolbar, "Patch...", self._on_patch_dialog)

        toolbar.addSeparator()

        self._goto_input = self._add_toolbar_input(toolbar, "Address...", max_width=120)
        self._goto_btn = self._add_tool_button(toolbar, "Go", self._on_goto_address)
        self._find_func_input = self._add_toolbar_input(toolbar, "Function name...", max_width=140)
        self._find_func_btn = self._add_tool_button(toolbar, "Find", self._on_find_function)

        toolbar.addSeparator()

        self.status_label = self._add_toolbar_label(toolbar, "Ready")

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
        outer.setSizes([_OUTER_SPLIT_TOP, _OUTER_SPLIT_MID, _OUTER_SPLIT_BOT])

        return outer

    @override
    def _cleanup(self) -> None:
        """Shut down the Cutter bridge if active."""
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.shutdown())
            except (RuntimeError, ConnectionError, OSError):
                _logger.exception("cutter_shutdown_failed", bridge_type="cutter")

    def _create_code_zone(self) -> QSplitter:
        """Create the top zone: functions sidebar + code tabs.

        Returns:
            QSplitter: Horizontal splitter with sidebar on the left and code tabs on the right.
        """
        splitter = QSplitter(Qt.Orientation.Horizontal)

        splitter.addWidget(self._create_functions_sidebar())
        splitter.addWidget(self._create_code_tabs())
        splitter.setSizes([_INNER_SPLIT_LEFT, _INNER_SPLIT_RIGHT])

        return splitter

    def _create_functions_sidebar(self) -> QWidget:
        """Create the functions list sidebar with filter and refresh.

        Returns:
            QWidget: Functions sidebar widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        fm = FontManager.get_instance()
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        header = QHBoxLayout()
        self._func_count_label = QLabel(self.tr("Functions"))
        self._func_count_label.setFont(fm.get_ui_font_bold(9))
        header.addWidget(self._func_count_label)
        header.addStretch()

        self._refresh_funcs_btn = QPushButton("Refresh")
        self._refresh_funcs_btn.setObjectName("secondary_button")
        self._refresh_funcs_btn.clicked.connect(self._on_refresh_functions)
        header.addWidget(self._refresh_funcs_btn)
        layout.addLayout(header)

        self._func_filter = QLineEdit()
        self._func_filter.setPlaceholderText("Filter functions...")
        self._func_filter.textChanged.connect(self._on_filter_changed)
        layout.addWidget(self._func_filter)

        self._func_tree = QTreeWidget()
        set_header_labels(self._func_tree, _FUNC_COLUMNS)
        set_sorting_enabled(self._func_tree, enable=True)
        set_selection_mode(self._func_tree, QAbstractItemView.SelectionMode.SingleSelection)
        self._func_tree.itemClicked.connect(self._on_function_clicked)
        self._func_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._func_tree.customContextMenuRequested.connect(self._on_func_context_menu)
        layout.addWidget(self._func_tree)

        return container

    def _create_code_tabs(self) -> QTabWidget:
        """Create disassembly, decompiler, and CFG code tabs.

        Returns:
            QTabWidget: Tab widget with code views.
        """
        fm = FontManager.get_instance()
        tabs = QTabWidget()

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(fm.get_code_font(10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        self._asm_highlighter = AssemblySyntaxHighlighter(self._disasm_view.document())
        tabs.addTab(self._disasm_view, self.tr("Disassembly"))

        self._decompiled_view = QPlainTextEdit()
        self._decompiled_view.setFont(fm.get_code_font(10))
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
        self._string_search_input.setPlaceholderText("Search strings...")
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

        self._all_strings_tab = AllStringsTab()
        tabs.addTab(self._all_strings_tab, "All Strings")

        self._symbols_tab = SymbolsTab()
        tabs.addTab(self._symbols_tab, "Symbols")

        self._libraries_tab = LibrariesTab()
        tabs.addTab(self._libraries_tab, "Libraries")

        self._headers_tab = HeadersTab()
        tabs.addTab(self._headers_tab, "Headers")

        self._relocations_tab = RelocationsTab()
        tabs.addTab(self._relocations_tab, "Relocations")

        self._resources_tab = ResourcesTab()
        tabs.addTab(self._resources_tab, "Resources")

        self._segments_tab = SegmentsTab()
        tabs.addTab(self._segments_tab, "Segments")

        self._comments_tab = CommentsTab()
        tabs.addTab(self._comments_tab, "Comments")

        self._flags_tab = FlagsTab()
        tabs.addTab(self._flags_tab, "Flags")

        self._rop_gadgets_tab = ROPGadgetsTab()
        tabs.addTab(self._rop_gadgets_tab, "ROP Gadgets")

        self._type_browser_tab = TypeBrowserTab()
        tabs.addTab(self._type_browser_tab, "Type Browser")

        self._hexdump_tab = HexdumpTab()
        tabs.addTab(self._hexdump_tab, "Hexdump")

        self._esil_tab = ESILConsoleTab()
        tabs.addTab(self._esil_tab, "ESIL Console")

        self._debugger_tab = DebuggerTab()
        tabs.addTab(self._debugger_tab, "Debugger")

        self._project_tab = ProjectTab()
        tabs.addTab(self._project_tab, "Project")

        self._search_tab = SearchTab()
        tabs.addTab(self._search_tab, "Advanced Search")

        self._static_extras_tab = StaticAnalysisExtrasTab()
        tabs.addTab(self._static_extras_tab, "Static Analysis Extras")

        self._config_tab = ConfigTab()
        tabs.addTab(self._config_tab, "Config")

        return tabs

    def _create_console(self) -> QWidget:
        """Create the raw r2 command console.

        Returns:
            QWidget: Console widget with output log and command input.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        fm = FontManager.get_instance()
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        console_label = QLabel(self.tr("Console"))
        console_label.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(console_label)

        self.console_output = QPlainTextEdit()
        self.console_output.setFont(fm.get_code_font(9))
        self.console_output.setReadOnly(True)
        set_max_block_count(self.console_output, 10000)
        layout.addWidget(self.console_output)

        input_row = QHBoxLayout()
        self._console_input = QLineEdit()
        self._console_input.setPlaceholderText("r2 command...")
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
        self._debugger_tab.set_bridge(bridge)
        self._project_tab.set_bridge(bridge)
        self._search_tab.set_bridge(bridge)
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

        run_bridge_coroutine_logged(
            self._bridge.load_binary(binary_path),
            on_success=lambda _: self._on_binary_loaded(binary_path),
            on_error=lambda e: self._on_binary_load_error(binary_path, e),
            parent=self,
            event="cutter_load_binary",
            logger=_logger,
            level="info",
            binary_path=str(binary_path),
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
        run_bridge_coroutine_logged(
            self._bridge.initialize(),
            on_success=lambda _: self._on_initialize_success(),
            on_error=self._on_initialize_error,
            parent=self,
            event="cutter_initialize",
            logger=_logger,
            level="info",
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
        self.tool_closed.emit()

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

        _logger.info("cutter_load_binary_requested", binary_path=file_path)
        self.analyze_binary(Path(file_path))

    def _on_analyze(self) -> None:
        """Run full Rizin analysis and refresh all views."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        if not self._bridge.state.binary_loaded:
            self._set_status("No binary loaded - load a binary first")
            return

        level = self._analysis_level_combo.currentText() or _DEFAULT_ANALYSIS_LEVEL
        self._set_status(f"Analyzing ({level})...")
        self._analyze_btn.setEnabled(False)

        run_bridge_coroutine_logged(
            self._bridge.analyze(level),
            on_success=lambda _: self._on_analysis_complete(),
            on_error=self._on_analysis_error,
            parent=self,
            event="cutter_analyze",
            logger=_logger,
            level="info",
            analysis_level=level,
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
        self._refresh_new_tabs()

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

        run_bridge_coroutine_logged(
            self._bridge.get_functions(filter_text),
            on_success=self._apply_functions,
            on_error=lambda _: self._on_refresh_funcs_error(),
            parent=self,
            event="cutter_get_functions",
            logger=_logger,
            filter=filter_text,
        )

    def _apply_functions(self, result: object) -> None:
        """Apply function data to the tree.

        Args:
            result: Function list from the bridge.
        """
        functions: list[object] = [*result] if isinstance(result, list) else []

        set_sorting_enabled(self._func_tree, enable=False)
        self._func_tree.clear()

        for func in functions:
            item = QTreeWidgetItem([
                getattr(func, "name", ""),
                f"0x{getattr(func, 'address', 0):X}",
                str(getattr(func, "size", 0)),
            ])
            tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, getattr(func, "address", 0))
            self._func_tree.addTopLevelItem(item)

        set_sorting_enabled(self._func_tree, enable=True)
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

        binary_path = str(self._current_binary) if self._current_binary is not None else "unset"
        _logger.info(
            "cutter_function_disassembly_requested",
            binary_path=binary_path,
            offset=hex(address),
        )

        run_bridge_coroutine_logged(
            self._bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda _: _logger.warning("cutter_decompile_failed", address=hex(address)),
            parent=self,
            event="cutter_decompile",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            self._bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("cutter_disassemble_failed", address=hex(address)),
            parent=self,
            event="cutter_disassemble",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            self._bridge.get_function_graph(address),
            on_success=self._apply_graph,
            on_error=lambda _: _logger.warning("cutter_graph_failed", address=hex(address)),
            parent=self,
            event="cutter_get_function_graph",
            logger=_logger,
            address=hex(address),
        )

        self._show_xrefs(address)
        self._static_extras_tab.show_function(address)

    def _on_decompile_selected(self) -> None:
        """Decompile the currently selected function and switch to Decompiler tab."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        address = self._get_selected_function_address()
        if address is None:
            self._set_status("No function selected")
            return

        binary_path = str(self._current_binary) if self._current_binary is not None else "unset"
        _logger.info(
            "cutter_decompile_requested",
            binary_path=binary_path,
            offset=hex(address),
        )

        run_bridge_coroutine_logged(
            self._bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda _: _logger.warning("cutter_decompile_failed", address=hex(address)),
            parent=self,
            event="cutter_decompile",
            logger=_logger,
            address=hex(address),
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

        run_bridge_coroutine_logged(
            self._bridge.get_function_graph(address),
            on_success=self._apply_graph,
            on_error=lambda _: _logger.warning("cutter_graph_failed", address=hex(address)),
            parent=self,
            event="cutter_get_function_graph",
            logger=_logger,
            address=hex(address),
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

    @staticmethod
    def _parse_address(text: str) -> int | None:
        """Parse an address string in hex (``0x``/``0X`` prefix) or decimal form.

        Accepts leading/trailing whitespace. Returns ``None`` when the input is empty
        or cannot be parsed as a non-negative integer.

        Args:
            text: User-supplied address string.

        Returns:
            int | None: The parsed integer address, or ``None`` on invalid input.
        """
        if not text:
            return None
        stripped = text.strip()
        if not stripped:
            return None
        lowered = stripped.lower()
        try:
            return int(stripped, 16) if lowered.startswith("0x") else int(stripped)
        except ValueError:
            _logger.warning("cutter_address_parse_failed", input_text=stripped)
            return None

    def _apply_decompiled(self, result: object) -> None:
        """Apply decompiled code to the view.

        Args:
            result: Decompiled code string from the bridge.
        """
        if result is None or not str(result).strip():
            self._decompiled_view.setPlainText("// No decompilation available at this address")
            return
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

        run_bridge_coroutine_logged(
            self._bridge.get_imports(),
            on_success=self._apply_imports,
            on_error=self._on_refresh_imports_error,
            parent=self,
            event="cutter_get_imports",
            logger=_logger,
        )

    def _on_refresh_imports_error(self, exc: object) -> None:
        """Handle imports refresh failure with logging and status update.

        Args:
            exc: Exception object raised by the bridge call.
        """
        _logger.warning("cutter_refresh_imports_failed", error=str(exc))
        self._set_status(f"Imports refresh failed: {exc}")

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

        run_bridge_coroutine_logged(
            self._bridge.get_exports(),
            on_success=self._apply_exports,
            on_error=self._on_refresh_exports_error,
            parent=self,
            event="cutter_get_exports",
            logger=_logger,
        )

    def _on_refresh_exports_error(self, exc: object) -> None:
        """Handle exports refresh failure with logging and status update.

        Args:
            exc: Exception object raised by the bridge call.
        """
        _logger.warning("cutter_refresh_exports_failed", error=str(exc))
        self._set_status(f"Exports refresh failed: {exc}")

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

        run_bridge_coroutine_logged(
            self._bridge.get_sections(),
            on_success=self._apply_sections,
            on_error=self._on_refresh_sections_error,
            parent=self,
            event="cutter_get_sections",
            logger=_logger,
        )

    def _on_refresh_sections_error(self, exc: object) -> None:
        """Handle sections refresh failure with logging and status update.

        Args:
            exc: Exception object raised by the bridge call.
        """
        _logger.warning("cutter_refresh_sections_failed", error=str(exc))
        self._set_status(f"Sections refresh failed: {exc}")

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
                QTableWidgetItem(perm_to_rwx(getattr(sec, "characteristics", 0))),
            )

    def search_strings(self, pattern: str) -> None:
        """Search for strings matching pattern and populate table.

        Args:
            pattern: Regex pattern to match.
        """
        if self._bridge is None:
            return

        self._string_search_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.search_strings(pattern),
            on_success=self._apply_strings,
            on_error=lambda _: self._on_string_search_error(pattern),
            parent=self,
            event="cutter_search_strings",
            logger=_logger,
            pattern=pattern,
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

        run_bridge_coroutine_logged(
            self._bridge.get_xrefs_to(address),
            on_success=self._apply_xrefs_to,
            on_error=lambda _: _logger.warning("cutter_xrefs_to_failed", address=hex(address)),
            parent=self,
            event="cutter_get_xrefs_to",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            self._bridge.get_xrefs_from(address),
            on_success=self._apply_xrefs_from,
            on_error=lambda _: _logger.warning("cutter_xrefs_from_failed", address=hex(address)),
            parent=self,
            event="cutter_get_xrefs_from",
            logger=_logger,
            address=hex(address),
        )

    def _apply_xrefs_to(self, result: object) -> None:
        """Apply xrefs-to data to the tree.

        Args:
            result: Cross-reference list from the bridge.
        """
        xrefs: list[object] = [*result] if isinstance(result, list) else []
        added = 0
        for xref in xrefs:
            item = QTreeWidgetItem([
                "To",
                f"0x{getattr(xref, 'from_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "from_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)
            added += 1
        if added == 0:
            self._xrefs_tree.addTopLevelItem(QTreeWidgetItem(["To", "—", "—", "(no callers)"]))

    def _apply_xrefs_from(self, result: object) -> None:
        """Apply xrefs-from data to the tree.

        Args:
            result: Cross-reference list from the bridge.
        """
        xrefs: list[object] = [*result] if isinstance(result, list) else []
        added = 0
        for xref in xrefs:
            item = QTreeWidgetItem([
                "From",
                f"0x{getattr(xref, 'to_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "to_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)
            added += 1
        if added == 0:
            self._xrefs_tree.addTopLevelItem(QTreeWidgetItem(["From", "—", "—", "(no callees)"]))

    def _on_run_command(self) -> None:
        """Execute a raw r2 command from the console input."""
        command = self._console_input.text().strip()
        if not command:
            return

        self._console_input.clear()
        self.console_output.appendPlainText(f"> {command}")

        if self._bridge is None:
            self.console_output.appendPlainText("[error] No bridge configured")
            return

        self._console_run_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.execute_command(command),
            on_success=self._apply_command_result,
            on_error=self._on_command_error,
            parent=self,
            event="cutter_execute_command",
            logger=_logger,
            level="info",
            command=command,
        )

    def _apply_command_result(self, result: object) -> None:
        """Apply command output to the console.

        Args:
            result: Command output string from the bridge.
        """
        if result is not None and (text := str(result).rstrip()):
            self.console_output.appendPlainText(text)
        self._console_run_btn.setEnabled(True)

    def _on_command_error(self, exc: object) -> None:
        """Handle command execution failure.

        Args:
            exc: The exception that occurred.
        """
        self.console_output.appendPlainText(f"[error] {exc}")
        _logger.warning("cutter_command_failed", error=str(exc))
        self._console_run_btn.setEnabled(True)

    def _refresh_new_tabs(self) -> None:
        """Refresh all new data tabs after analysis completes."""
        if self._bridge is None:
            return
        run_fn = self._run_async
        self._all_strings_tab.refresh(self._bridge, run_fn)
        self._symbols_tab.refresh(self._bridge, run_fn)
        self._libraries_tab.refresh(self._bridge, run_fn)
        self._headers_tab.refresh(self._bridge, run_fn)
        self._relocations_tab.refresh(self._bridge, run_fn)
        self._resources_tab.refresh(self._bridge, run_fn)
        self._segments_tab.refresh(self._bridge, run_fn)
        self._comments_tab.refresh(self._bridge, run_fn)
        self._flags_tab.refresh(self._bridge, run_fn)
        self._rop_gadgets_tab.refresh(self._bridge, run_fn)
        self._type_browser_tab.refresh(self._bridge, run_fn)
        self._hexdump_tab.refresh(self._bridge, run_fn)
        self._esil_tab.refresh(self._bridge, run_fn)
        self._project_tab.refresh(self._bridge, run_fn)
        self._static_extras_tab.refresh(self._bridge)
        self._config_tab.refresh(self._bridge, run_fn)

    def _on_save_binary(self) -> None:
        """Save the binary with cached patches via file dialog."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Patched Binary",
            "",
            "All Files (*)",
        )
        if not file_path:
            return

        self._set_status("Saving...")
        run_bridge_coroutine_logged(
            self._bridge.save_binary(file_path),
            on_success=lambda _: self._set_status(f"Saved: {file_path}"),
            on_error=lambda e: self._set_status(f"Save failed: {e}"),
            parent=self,
            event="cutter_save_binary",
            logger=_logger,
            level="info",
            file_path=file_path,
        )

    def _on_patch_dialog(self) -> None:
        """Open a dialog to apply a patch at an address."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        addr_str, ok = QInputDialog.getText(self, "Patch Address", "Address (hex):")
        if not ok or not addr_str:
            return

        address = self._parse_address(addr_str)
        if address is None:
            self._set_status("Invalid address")
            return

        hex_data, ok2 = QInputDialog.getText(self, "Patch Data", "Hex bytes (e.g. 90 90 90):")
        if not ok2 or not hex_data:
            return

        binary_path = str(self._current_binary) if self._current_binary is not None else "unset"
        _logger.info(
            "cutter_patch_bytes_requested",
            binary_path=binary_path,
            offset=hex(address),
            byte_count=len(hex_data.replace(" ", "")) // 2,
        )
        run_bridge_coroutine_logged(
            self._bridge.write_bytes(address, hex_data),
            on_success=lambda _: self._set_status(f"Patched @ 0x{address:X}"),
            on_error=lambda e: self._set_status(f"Patch failed: {e}"),
            parent=self,
            event="cutter_write_bytes",
            logger=_logger,
            level="info",
            address=hex(address),
            byte_count=len(hex_data.replace(" ", "")) // 2,
        )

    def _on_goto_address(self) -> None:
        """Seek to the address in the goto input and refresh disassembly."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        addr_text = self._goto_input.text().strip()
        if not addr_text:
            return

        address = self._parse_address(addr_text)
        if address is None:
            self._set_status("Invalid address")
            return

        run_bridge_coroutine_logged(
            self._bridge.seek(address),
            on_success=lambda _: self._on_goto_complete(address),
            on_error=lambda e: self._set_status(f"Seek failed: {e}"),
            parent=self,
            event="cutter_seek",
            logger=_logger,
            address=hex(address),
        )

    def _on_goto_complete(self, address: int) -> None:
        """Handle seek completion by refreshing disassembly.

        Args:
            address: Address that was sought.
        """
        if self._bridge is None:
            return
        self._set_status(f"@ 0x{address:X}")
        binary_path = str(self._current_binary) if self._current_binary is not None else "unset"
        _logger.info(
            "cutter_goto_disassembly_requested",
            binary_path=binary_path,
            offset=hex(address),
        )
        run_bridge_coroutine_logged(
            self._bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("cutter_disassemble_failed", address=hex(address)),
            parent=self,
            event="cutter_disassemble",
            logger=_logger,
            address=hex(address),
        )

    def _on_find_function(self) -> None:
        """Find a function by name and navigate to it."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        if name := self._find_func_input.text().strip():
            run_bridge_coroutine_logged(
                self._bridge.get_function_address(name),
                on_success=lambda addr: self._on_find_func_result(name, addr),
                on_error=lambda e: self._set_status(f"Find failed: {e}"),
                parent=self,
                event="cutter_get_function_address",
                logger=_logger,
                function_name=name,
            )
        else:
            return

    def _on_find_func_result(self, name: str, addr: object) -> None:
        """Handle function address lookup result.

        Args:
            name: Function name searched for.
            addr: Resolved address or None.
        """
        if addr is None or not isinstance(addr, int):
            self._set_status(f"Function not found: {name}")
            return
        self._set_status(f"{name} @ 0x{addr:X}")
        self._goto_input.setText(f"0x{addr:X}")
        self._on_goto_complete(addr)

    def _on_func_context_menu(self, pos: QPoint) -> None:
        """Show context menu for the function tree.

        Args:
            pos: Click position from the signal.
        """
        item = self._func_tree.itemAt(pos)
        if item is None:
            return

        address = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if not isinstance(address, int):
            return

        menu = QMenu(self)

        rename_action = QAction("Rename...", self)
        rename_action.triggered.connect(lambda: self._ctx_rename_function(address))
        menu.addAction(rename_action)

        comment_action = QAction("Add Comment...", self)
        comment_action.triggered.connect(lambda: self._ctx_add_comment(address))
        menu.addAction(comment_action)

        decompile_action = QAction("Decompile", self)
        decompile_action.triggered.connect(self._on_decompile_selected)
        menu.addAction(decompile_action)

        graph_action = QAction("Show Graph", self)
        graph_action.triggered.connect(self._on_graph_selected)
        menu.addAction(graph_action)

        copy_action = QAction("Copy Address", self)
        copy_action.triggered.connect(lambda: self._ctx_copy_address(address))
        menu.addAction(copy_action)

        read_action = QAction("Read Bytes...", self)
        read_action.triggered.connect(lambda: self._ctx_read_bytes(address))
        menu.addAction(read_action)

        menu.exec(self._func_tree.mapToGlobal(pos))

    def _ctx_rename_function(self, address: int) -> None:
        """Rename a function via input dialog.

        Args:
            address: Function address to rename.
        """
        if self._bridge is None:
            return
        new_name, ok = QInputDialog.getText(self, "Rename Function", "New name:")
        if not ok or not new_name:
            return
        run_bridge_coroutine_logged(
            self._bridge.rename_function(address, new_name),
            on_success=lambda _: self._on_rename_complete(address, new_name),
            on_error=lambda e: self._set_status(f"Rename failed: {e}"),
            parent=self,
            event="cutter_rename_function",
            logger=_logger,
            level="info",
            address=hex(address),
            new_name=new_name,
        )

    def _on_rename_complete(self, address: int, new_name: str) -> None:
        """Handle successful function rename.

        Args:
            address: Function address that was renamed.
            new_name: The new function name.
        """
        self._set_status(f"Renamed 0x{address:X} -> {new_name}")
        self._on_refresh_functions()

    def _ctx_add_comment(self, address: int) -> None:
        """Add a comment at an address via input dialog.

        Args:
            address: Address for the comment.
        """
        if self._bridge is None:
            return
        comment, ok = QInputDialog.getText(self, "Add Comment", "Comment:")
        if not ok or not comment:
            return
        run_bridge_coroutine_logged(
            self._bridge.add_comment(address, comment),
            on_success=lambda _: self._set_status(f"Comment added @ 0x{address:X}"),
            on_error=lambda e: self._set_status(f"Comment failed: {e}"),
            parent=self,
            event="cutter_add_comment",
            logger=_logger,
            level="info",
            address=hex(address),
            comment_length=len(comment),
        )

    def _ctx_copy_address(self, address: int) -> None:
        """Copy an address to the clipboard.

        Args:
            address: Address to copy.
        """
        clipboard: QClipboard | None = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(f"0x{address:X}")
            self._set_status(f"Copied 0x{address:X}")

    def _ctx_read_bytes(self, address: int) -> None:
        """Read bytes at an address and display in console.

        Args:
            address: Address to read from.
        """
        if self._bridge is None:
            return
        count, ok = QInputDialog.getInt(self, "Read Bytes", "Count:", 16, 1, 4096)
        if not ok:
            return
        run_bridge_coroutine_logged(
            self._bridge.read_bytes(address, count),
            on_success=lambda data: self._show_read_bytes(address, data),
            on_error=lambda e: self.console_output.appendPlainText(f"[error] Read failed: {e}"),
            parent=self,
            event="cutter_read_bytes",
            logger=_logger,
            address=hex(address),
            count=count,
        )

    def _show_read_bytes(self, address: int, data: object) -> None:
        """Display read bytes in the console.

        Args:
            address: Source address.
            data: Bytes read from the bridge.
        """
        if isinstance(data, bytes):
            hex_str = data.hex(" ")
            self.console_output.appendPlainText(f"[0x{address:X}] {hex_str}")
        elif data is not None:
            self.console_output.appendPlainText(f"[0x{address:X}] {data}")
