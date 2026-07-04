# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Ghidra analysis panel for Intellicrack.

Provides decompilation, disassembly, PCode, CFG, function listing, string search, import/export tables, cross-reference views,
label/bookmark management, structure definition, memory inspection, segment/program metadata, call graph analysis, comment management,
symbol search, and Ghidra scripting powered by the GhidraBridge headless analysis backend.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import QPoint, Qt, QTimer
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.ghidra_panel_data_types import DataTypeManagerWidget
from intellicrack.ui.panels.ghidra_panel_extras import GhidraAnalysisExtrasWidget
from intellicrack.ui.panels.ghidra_panel_program_tree import ProgramTreeWidget
from intellicrack.ui.panels.qt_compat import (
    set_header_labels,
    set_max_block_count,
    set_selection_mode,
    set_sorting_enabled,
    tree_add_child,
    tree_item_data,
    tree_item_set_data,
)
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from PyQt6.QtGui import QAction

    from intellicrack.bridges.ghidra import GhidraBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_CODE_SPLIT_RATIO_TOP: Final[int] = 400
_CODE_SPLIT_RATIO_BOTTOM: Final[int] = 300
_MAIN_SPLIT_RATIO_LEFT: Final[int] = 600
_MAIN_SPLIT_RATIO_RIGHT: Final[int] = 250

_FUNC_COLUMNS: Final[list[str]] = ["Name", "Address", "Size"]
_IMPORT_COLUMNS: Final[list[str]] = ["DLL", "Function", "Address"]
_EXPORT_COLUMNS: Final[list[str]] = ["Name", "Ordinal", "Address"]
_STRING_COLUMNS: Final[list[str]] = ["Address", "Value", "Section", "Encoding"]
_XREF_COLUMNS: Final[list[str]] = ["Direction", "From/To", "Type", "Function"]
_LABEL_COLUMNS: Final[list[str]] = ["Name", "Address", "Type"]
_BOOKMARK_COLUMNS: Final[list[str]] = ["Address", "Category", "Comment", "Type"]
_STRUCT_COLUMNS: Final[list[str]] = ["Name", "Size", "Fields", "Path"]
_MEMORY_COLUMNS: Final[list[str]] = ["Name", "Start", "End", "Size", "R", "W", "X", "Init"]
_SEGMENT_COLUMNS: Final[list[str]] = ["Name", "Start", "End", "Size", "R", "W", "X", "Type", "Source"]
_PROGRAM_INFO_COLUMNS: Final[list[str]] = ["Property", "Value"]
_CALL_GRAPH_COLUMNS: Final[list[str]] = ["Name", "Address"]
_COMMENT_COLUMNS: Final[list[str]] = ["Address", "Type", "Comment"]
_SYMBOL_COLUMNS: Final[list[str]] = ["Name", "Address", "Type", "Namespace"]
_NAMESPACE_COLUMNS: Final[list[str]] = ["Name", "Path"]
_EQUATE_COLUMNS: Final[list[str]] = ["Name", "Value", "References"]
_RELOCATION_COLUMNS: Final[list[str]] = ["Address", "Type", "Symbol"]

_ASCII_PRINTABLE_MIN: Final[int] = 32
_ASCII_PRINTABLE_MAX: Final[int] = 127

_FILTER_DEBOUNCE_MS: Final[int] = 250
_CLEANUP_SHUTDOWN_TIMEOUT_S: Final[float] = 5.0

try:
    from intellicrack.ui.panels.graph_view import CFGGraphView, NumericSortTreeItem
except ImportError:
    _logger.debug("ghidra_cfg_graph_view_unavailable", exc_info=True)
    CFGGraphView = None
    NumericSortTreeItem = QTreeWidgetItem

try:
    from intellicrack.ui.highlighter import PythonSyntaxHighlighter
except ImportError:
    _logger.debug("ghidra_python_syntax_highlighter_unavailable", exc_info=True)
    PythonSyntaxHighlighter = None


def _make_table(columns: list[str]) -> QTableWidget:
    """Create a read-only stretch-header table widget.

    Args:
        columns: Column header labels.

    Returns:
        QTableWidget: Configured table widget.
    """
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    header = table.horizontalHeader()
    if header is not None:
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    return table


class GhidraPanel(AnalysisPanelBase):
    """Native Qt panel for Ghidra reverse engineering analysis.

    Displays decompiled code, disassembly, PCode, CFG, function lists, strings, imports, exports, cross-references, labels, bookmarks,
    structures, memory maps, segments, program info, call graphs, comments, symbols, namespaces, equates, relocations, and a Ghidra script
    runner powered by the GhidraBridge backend.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the GhidraPanel widget.

        Args:
            parent: Parent widget.
        """
        self._bridge: GhidraBridge | None = None
        self._data_tabs: QTabWidget | None = None
        super().__init__(parent)

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add Ghidra-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._connect_btn = self._add_tool_button(toolbar, self.tr("Connect"), self._on_connect)
        self._disconnect_btn = self._add_tool_button(toolbar, self.tr("Disconnect"), self._on_disconnect, enabled=False)

        toolbar.addSeparator()

        self._load_btn = self._add_tool_button(toolbar, self.tr("Load Binary..."), self._on_load_binary, enabled=False)
        self._analyze_btn = self._add_tool_button(toolbar, self.tr("Analyze"), self._on_analyze, enabled=False)
        self._headless_btn = self._add_tool_button(toolbar, self.tr("Start Headless"), self._on_start_headless)

        toolbar.addSeparator()

        self._undo_btn = self._add_tool_button(toolbar, self.tr("Undo"), self._on_undo, enabled=False)
        self._redo_btn = self._add_tool_button(toolbar, self.tr("Redo"), self._on_redo, enabled=False)

        toolbar.addSeparator()

        self._byte_search_input = self._add_toolbar_input(toolbar, "Hex pattern (e.g. 48 8B ?? ??)")
        self._byte_search_btn = self._add_tool_button(toolbar, self.tr("Search Bytes"), self._on_search_bytes, enabled=False)

        toolbar.addSeparator()

        self._debug_info_btn = self._add_secondary_button(toolbar, self.tr("Debug Info..."), self._on_import_debug_info)
        self._diff_btn = self._add_secondary_button(toolbar, self.tr("Diff..."), self._on_diff_programs)

        self.status_label = self._add_toolbar_label(toolbar, self.tr("Not connected"))

    @override
    def _create_content(self) -> QWidget:
        """Create the Ghidra analysis content area.

        Returns:
            QWidget: Splitter with code tabs, data tabs, and function sidebar.
        """
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        left_splitter = QSplitter(Qt.Orientation.Vertical)
        left_splitter.setChildrenCollapsible(False)
        left_splitter.addWidget(self._create_code_tabs())
        left_splitter.addWidget(self._create_data_tabs())
        left_splitter.setSizes([_CODE_SPLIT_RATIO_TOP, _CODE_SPLIT_RATIO_BOTTOM])
        main_splitter.addWidget(left_splitter)

        main_splitter.addWidget(self._create_functions_sidebar())
        main_splitter.setSizes([_MAIN_SPLIT_RATIO_LEFT, _MAIN_SPLIT_RATIO_RIGHT])

        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Shut down the Ghidra bridge if active."""
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.shutdown(), timeout_s=_CLEANUP_SHUTDOWN_TIMEOUT_S)
            except (RuntimeError, ConnectionError, OSError):
                _logger.exception("ghidra_shutdown_failed", bridge_type="ghidra")

    # ------------------------------------------------------------------
    # Code Tabs
    # ------------------------------------------------------------------

    def _create_code_tabs(self) -> QTabWidget:
        """Create decompiled, disassembly, PCode, and CFG code tabs.

        Returns:
            QTabWidget: Tab widget with code views.
        """
        tabs = QTabWidget()
        fm = FontManager.get_instance()

        self._decompiled_view = QPlainTextEdit()
        self._decompiled_view.setFont(fm.get_code_font(10))
        self._decompiled_view.setReadOnly(True)
        set_max_block_count(self._decompiled_view, 50000)
        tabs.addTab(self._decompiled_view, self.tr("Decompiled"))

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(fm.get_code_font(10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        tabs.addTab(self._disasm_view, self.tr("Disassembly"))

        self._pcode_view = QPlainTextEdit()
        self._pcode_view.setFont(fm.get_code_font(10))
        self._pcode_view.setReadOnly(True)
        set_max_block_count(self._pcode_view, 50000)
        tabs.addTab(self._pcode_view, self.tr("PCode"))

        if CFGGraphView is not None:
            cfg_view = CFGGraphView()
            cfg_view.block_clicked.connect(self._on_cfg_block_clicked)
            self._cfg_view: QWidget = cfg_view
        else:
            cfg_fallback = QPlainTextEdit()
            cfg_fallback.setFont(fm.get_code_font(10))
            cfg_fallback.setReadOnly(True)
            self._cfg_view = cfg_fallback
        tabs.addTab(self._cfg_view, self.tr("CFG"))

        self._code_tabs = tabs
        return tabs

    # ------------------------------------------------------------------
    # Data Tabs
    # ------------------------------------------------------------------

    def _create_data_tabs(self) -> QTabWidget:
        """Create all data analysis tabs.

        Returns:
            QTabWidget: Tab widget with data tables for all analysis categories.
        """
        tabs = QTabWidget()
        self._data_tabs = tabs

        self._strings_table = _make_table(_STRING_COLUMNS)
        strings_container = QWidget()
        strings_layout = QVBoxLayout(strings_container)
        strings_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        strings_layout.setSpacing(_PANEL_SPACING)
        strings_toolbar = QHBoxLayout()
        self._string_search_input = QLineEdit()
        self._string_search_input.setPlaceholderText(self.tr("Search strings..."))
        self._string_search_input.returnPressed.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_input)
        self._string_search_btn = QPushButton(self.tr("Search"))
        self._string_search_btn.setObjectName("tool_button")
        self._string_search_btn.clicked.connect(self._on_search_strings)
        strings_toolbar.addWidget(self._string_search_btn)
        strings_layout.addLayout(strings_toolbar)
        strings_layout.addWidget(self._strings_table)
        tabs.addTab(strings_container, self.tr("Strings"))

        self._imports_table = _make_table(_IMPORT_COLUMNS)
        tabs.addTab(self._imports_table, self.tr("Imports"))

        self._exports_table = _make_table(_EXPORT_COLUMNS)
        tabs.addTab(self._exports_table, self.tr("Exports"))

        tabs.addTab(self._create_xrefs_tab(), self.tr("XRefs"))

        tabs.addTab(self._create_labels_bookmarks_tab(), self.tr("Labels/Bookmarks"))
        tabs.addTab(self._create_structures_tab(), self.tr("Structures"))
        tabs.addTab(self._create_memory_tab(), self.tr("Memory"))
        tabs.addTab(self._create_segments_program_tab(), self.tr("Segments/Program"))
        tabs.addTab(self._create_call_graph_tab(), self.tr("Call Graph"))
        tabs.addTab(self._create_comments_tab(), self.tr("Comments"))
        tabs.addTab(self._create_symbols_tab(), self.tr("Symbols"))
        tabs.addTab(self._create_scripting_tab(), self.tr("Scripting"))
        tabs.addTab(self._create_data_types_tab(), self.tr("Data Types"))
        tabs.addTab(self._create_program_tree_tab(), self.tr("Program Tree"))
        tabs.addTab(self._create_analysis_extras_tab(), self.tr("Analysis Extras"))

        return tabs

    # ------------------------------------------------------------------
    # Tab 4: XRefs
    # ------------------------------------------------------------------

    def _create_xrefs_tab(self) -> QWidget:
        """Create the XRefs tab with an editable reference table.

        Returns:
            QWidget: Widget with the cross-reference tree plus add/delete
            reference forms wired to ``GhidraBridge.add_reference`` and
            ``GhidraBridge.delete_reference``.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        self._xrefs_tree = QTreeWidget()
        set_header_labels(self._xrefs_tree, _XREF_COLUMNS)
        set_selection_mode(self._xrefs_tree, QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self._xrefs_tree)

        edit_label = QLabel(self.tr("Edit References"))
        layout.addWidget(edit_label)

        ref_form1 = QHBoxLayout()
        self._ref_from_input = QLineEdit()
        self._ref_from_input.setPlaceholderText("From address (hex)")
        self._ref_to_input = QLineEdit()
        self._ref_to_input.setPlaceholderText("To address (hex)")
        self._ref_type_combo = QComboBox()
        self._ref_type_combo.addItems(["DATA", "READ", "WRITE", "CALL", "UNCONDITIONAL_JUMP", "CONDITIONAL_JUMP"])
        ref_form1.addWidget(self._ref_from_input)
        ref_form1.addWidget(self._ref_to_input)
        ref_form1.addWidget(self._ref_type_combo)
        layout.addLayout(ref_form1)

        ref_form2 = QHBoxLayout()
        self._add_ref_btn = QPushButton(self.tr("Add Reference"))
        self._add_ref_btn.clicked.connect(self._on_add_reference)
        ref_form2.addWidget(self._add_ref_btn)
        self._delete_ref_btn = QPushButton(self.tr("Delete Reference"))
        self._delete_ref_btn.clicked.connect(self._on_delete_reference)
        ref_form2.addWidget(self._delete_ref_btn)
        ref_form2.addStretch()
        layout.addLayout(ref_form2)

        return container

    # ------------------------------------------------------------------
    # Tab 5: Labels / Bookmarks
    # ------------------------------------------------------------------

    def _create_labels_bookmarks_tab(self) -> QWidget:
        """Create the Labels and Bookmarks tab.

        Returns:
            QWidget: Vertical splitter with labels and bookmarks sections.
        """
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        labels_widget = QWidget()
        labels_layout = QVBoxLayout(labels_widget)
        labels_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        labels_layout.setSpacing(_PANEL_SPACING)

        lbl_form = QHBoxLayout()
        self._label_addr_input = QLineEdit()
        self._label_addr_input.setObjectName("label_addr_input")
        self._label_addr_input.setPlaceholderText("Address (hex)")
        self._label_name_input = QLineEdit()
        self._label_name_input.setPlaceholderText("Label name")
        self._label_primary_check = QCheckBox(self.tr("Primary"))
        self._set_label_btn = QPushButton(self.tr("Set Label"))
        self._set_label_btn.clicked.connect(self._on_set_label)
        lbl_form.addWidget(self._label_addr_input)
        lbl_form.addWidget(self._label_name_input)
        lbl_form.addWidget(self._label_primary_check)
        lbl_form.addWidget(self._set_label_btn)
        labels_layout.addLayout(lbl_form)

        self._labels_table = _make_table(_LABEL_COLUMNS)
        self._labels_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._labels_table.customContextMenuRequested.connect(self._on_label_context_menu)
        labels_layout.addWidget(self._labels_table)

        lbl_bottom_row = QHBoxLayout()
        lbl_refresh = QPushButton(self.tr("Refresh Labels"))
        lbl_refresh.setObjectName("refresh_labels_btn")
        lbl_refresh.clicked.connect(self._on_refresh_labels)
        lbl_bottom_row.addWidget(lbl_refresh)
        self._remove_label_btn = QPushButton(self.tr("Remove Selected"))
        self._remove_label_btn.clicked.connect(self._on_remove_label)
        lbl_bottom_row.addWidget(self._remove_label_btn)
        labels_layout.addLayout(lbl_bottom_row)
        splitter.addWidget(labels_widget)

        bm_widget = QWidget()
        bm_layout = QVBoxLayout(bm_widget)
        bm_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        bm_layout.setSpacing(_PANEL_SPACING)

        bm_form1 = QHBoxLayout()
        self._bm_addr_input = QLineEdit()
        self._bm_addr_input.setPlaceholderText("Address (hex)")
        self._bm_category_input = QLineEdit()
        self._bm_category_input.setPlaceholderText("Category")
        bm_form1.addWidget(self._bm_addr_input)
        bm_form1.addWidget(self._bm_category_input)
        bm_layout.addLayout(bm_form1)

        bm_form2 = QHBoxLayout()
        self._bm_comment_input = QLineEdit()
        self._bm_comment_input.setPlaceholderText("Comment")
        self._bm_type_combo = QComboBox()
        self._bm_type_combo.addItems(["Note", "Analysis", "Error", "Warning", "Info"])
        self._create_bm_btn = QPushButton(self.tr("Create"))
        self._create_bm_btn.clicked.connect(self._on_create_bookmark)
        bm_form2.addWidget(self._bm_comment_input)
        bm_form2.addWidget(self._bm_type_combo)
        bm_form2.addWidget(self._create_bm_btn)
        bm_layout.addLayout(bm_form2)

        self._bookmarks_table = _make_table(_BOOKMARK_COLUMNS)
        self._bookmarks_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._bookmarks_table.customContextMenuRequested.connect(self._on_bookmark_context_menu)
        bm_layout.addWidget(self._bookmarks_table)

        bm_bottom_row = QHBoxLayout()
        bm_refresh = QPushButton(self.tr("Refresh Bookmarks"))
        bm_refresh.clicked.connect(self._on_refresh_bookmarks)
        bm_bottom_row.addWidget(bm_refresh)
        self._remove_bm_btn = QPushButton(self.tr("Remove Selected"))
        self._remove_bm_btn.clicked.connect(self._on_remove_bookmark)
        bm_bottom_row.addWidget(self._remove_bm_btn)
        bm_layout.addLayout(bm_bottom_row)
        splitter.addWidget(bm_widget)

        return splitter

    # ------------------------------------------------------------------
    # Tab 6: Structures
    # ------------------------------------------------------------------

    def _create_structures_tab(self) -> QWidget:
        """Create the Structures tab.

        Returns:
            QWidget: Widget with structure list, definition form, and apply form.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        top_bar = QHBoxLayout()
        refresh_struct = QPushButton(self.tr("Refresh Structures"))
        refresh_struct.clicked.connect(self._on_refresh_structures)
        top_bar.addWidget(refresh_struct)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        self._structs_table = _make_table(_STRUCT_COLUMNS)
        layout.addWidget(self._structs_table)

        define_label = QLabel(self.tr("Define Structure"))
        layout.addWidget(define_label)

        define_row = QHBoxLayout()
        self._struct_name_input = QLineEdit()
        self._struct_name_input.setPlaceholderText("Structure name")
        define_row.addWidget(self._struct_name_input)
        self._add_field_btn = QPushButton(self.tr("Add Field"))
        self._add_field_btn.clicked.connect(self._on_add_struct_field)
        define_row.addWidget(self._add_field_btn)
        self._define_struct_btn = QPushButton(self.tr("Define"))
        self._define_struct_btn.clicked.connect(self._on_define_structure)
        define_row.addWidget(self._define_struct_btn)
        layout.addLayout(define_row)

        self._struct_fields_list: list[tuple[str, str]] = []
        self._struct_fields_label = QLabel("")
        self._struct_fields_label.setWordWrap(True)
        layout.addWidget(self._struct_fields_label)

        apply_label = QLabel(self.tr("Apply Structure"))
        layout.addWidget(apply_label)

        apply_row = QHBoxLayout()
        self._apply_struct_addr_input = QLineEdit()
        self._apply_struct_addr_input.setPlaceholderText("Address (hex)")
        self._apply_struct_name_input = QLineEdit()
        self._apply_struct_name_input.setPlaceholderText("Structure name")
        self._apply_struct_btn = QPushButton(self.tr("Apply"))
        self._apply_struct_btn.clicked.connect(self._on_apply_structure)
        apply_row.addWidget(self._apply_struct_addr_input)
        apply_row.addWidget(self._apply_struct_name_input)
        apply_row.addWidget(self._apply_struct_btn)
        layout.addLayout(apply_row)

        return container

    # ------------------------------------------------------------------
    # Tab 7: Memory
    # ------------------------------------------------------------------

    def _create_memory_tab(self) -> QWidget:
        """Create the Memory tab.

        Returns:
            QWidget: Widget with memory map, read/write controls, and create block form.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        mem_top = QHBoxLayout()
        refresh_mem = QPushButton(self.tr("Refresh Memory Map"))
        refresh_mem.clicked.connect(self._on_refresh_memory_map)
        mem_top.addWidget(refresh_mem)
        mem_top.addStretch()
        layout.addLayout(mem_top)

        self._memory_table = _make_table(_MEMORY_COLUMNS)
        layout.addWidget(self._memory_table)

        read_label = QLabel(self.tr("Read Bytes"))
        layout.addWidget(read_label)

        read_row = QHBoxLayout()
        self._read_addr_input = QLineEdit()
        self._read_addr_input.setPlaceholderText("Address (hex)")
        self._read_len_spin = QSpinBox()
        self._read_len_spin.setRange(1, 4096)
        self._read_len_spin.setValue(256)
        self._read_bytes_btn = QPushButton(self.tr("Read"))
        self._read_bytes_btn.clicked.connect(self._on_read_bytes)
        read_row.addWidget(self._read_addr_input)
        read_row.addWidget(self._read_len_spin)
        read_row.addWidget(self._read_bytes_btn)
        layout.addLayout(read_row)

        self._hex_dump_view = QPlainTextEdit()
        self._hex_dump_view.setReadOnly(True)
        self._hex_dump_view.setFixedHeight(100)
        layout.addWidget(self._hex_dump_view)

        write_label = QLabel(self.tr("Write Bytes"))
        layout.addWidget(write_label)

        write_row = QHBoxLayout()
        self._write_addr_input = QLineEdit()
        self._write_addr_input.setPlaceholderText("Address (hex)")
        self._write_hex_input = QLineEdit()
        self._write_hex_input.setPlaceholderText("Hex data (e.g. 90 90 90)")
        self._write_bytes_btn = QPushButton(self.tr("Write"))
        self._write_bytes_btn.clicked.connect(self._on_write_bytes)
        write_row.addWidget(self._write_addr_input)
        write_row.addWidget(self._write_hex_input)
        write_row.addWidget(self._write_bytes_btn)
        layout.addLayout(write_row)

        block_label = QLabel(self.tr("Create Memory Block"))
        layout.addWidget(block_label)

        block_row = QHBoxLayout()
        self._block_name_input = QLineEdit()
        self._block_name_input.setPlaceholderText("Block name")
        self._block_start_input = QLineEdit()
        self._block_start_input.setPlaceholderText("Start (hex)")
        self._block_size_spin = QSpinBox()
        self._block_size_spin.setRange(1, 0x7FFFFFFF)
        self._block_size_spin.setValue(4096)
        self._block_perms_input = QLineEdit()
        self._block_perms_input.setPlaceholderText("rwx")
        self._block_perms_input.setText("rwx")
        self._create_block_btn = QPushButton(self.tr("Create"))
        self._create_block_btn.clicked.connect(self._on_create_memory_block)
        block_row.addWidget(self._block_name_input)
        block_row.addWidget(self._block_start_input)
        block_row.addWidget(self._block_size_spin)
        block_row.addWidget(self._block_perms_input)
        block_row.addWidget(self._create_block_btn)
        layout.addLayout(block_row)

        self._build_memory_block_ops_rows(layout)

        overlay_label = QLabel(self.tr("Create Overlay Space"))
        layout.addWidget(overlay_label)

        overlay_row = QHBoxLayout()
        self._overlay_name_input = QLineEdit()
        self._overlay_name_input.setPlaceholderText("Overlay name")
        self._create_overlay_btn = QPushButton(self.tr("Create Overlay"))
        self._create_overlay_btn.clicked.connect(self._on_create_overlay_space)
        overlay_row.addWidget(self._overlay_name_input)
        overlay_row.addWidget(self._create_overlay_btn)
        layout.addLayout(overlay_row)

        return container

    def _build_memory_block_ops_rows(self, layout: QVBoxLayout) -> None:
        """Build the Remove/Split/Join memory block form rows.

        Args:
            layout: Parent layout to append the form rows to.
        """
        block_ops_label = QLabel(self.tr("Remove / Split / Join Memory Block"))
        layout.addWidget(block_ops_label)

        remove_row = QHBoxLayout()
        self._block_remove_name_input = QLineEdit()
        self._block_remove_name_input.setPlaceholderText("Block name to remove")
        self._remove_block_btn = QPushButton(self.tr("Remove"))
        self._remove_block_btn.clicked.connect(self._on_remove_memory_block)
        remove_row.addWidget(self._block_remove_name_input)
        remove_row.addWidget(self._remove_block_btn)
        layout.addLayout(remove_row)

        split_row = QHBoxLayout()
        self._block_split_name_input = QLineEdit()
        self._block_split_name_input.setPlaceholderText("Block name to split")
        self._block_split_addr_input = QLineEdit()
        self._block_split_addr_input.setPlaceholderText("Split address (hex)")
        self._split_block_btn = QPushButton(self.tr("Split"))
        self._split_block_btn.clicked.connect(self._on_split_memory_block)
        split_row.addWidget(self._block_split_name_input)
        split_row.addWidget(self._block_split_addr_input)
        split_row.addWidget(self._split_block_btn)
        layout.addLayout(split_row)

        join_row = QHBoxLayout()
        self._block_join_name1_input = QLineEdit()
        self._block_join_name1_input.setPlaceholderText("First block name")
        self._block_join_name2_input = QLineEdit()
        self._block_join_name2_input.setPlaceholderText("Second block name")
        self._join_blocks_btn = QPushButton(self.tr("Join"))
        self._join_blocks_btn.clicked.connect(self._on_join_memory_blocks)
        join_row.addWidget(self._block_join_name1_input)
        join_row.addWidget(self._block_join_name2_input)
        join_row.addWidget(self._join_blocks_btn)
        layout.addLayout(join_row)

    # ------------------------------------------------------------------
    # Tab 8: Segments / Program
    # ------------------------------------------------------------------

    def _create_segments_program_tab(self) -> QWidget:
        """Create the Segments and Program Info tab.

        Returns:
            QWidget: Widget with segment list, program info table, and metadata form.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        seg_top = QHBoxLayout()
        refresh_seg = QPushButton(self.tr("Refresh Segments"))
        refresh_seg.clicked.connect(self._on_refresh_segments)
        seg_top.addWidget(refresh_seg)
        seg_top.addStretch()
        layout.addLayout(seg_top)

        self._segments_table = _make_table(_SEGMENT_COLUMNS)
        layout.addWidget(self._segments_table)

        prog_top = QHBoxLayout()
        refresh_prog = QPushButton(self.tr("Refresh Program Info"))
        refresh_prog.clicked.connect(self._on_refresh_program_info)
        prog_top.addWidget(refresh_prog)
        prog_top.addStretch()
        layout.addLayout(prog_top)

        self._program_info_table = _make_table(_PROGRAM_INFO_COLUMNS)
        layout.addWidget(self._program_info_table)

        meta_label = QLabel(self.tr("Update Metadata"))
        layout.addWidget(meta_label)

        meta_row = QHBoxLayout()
        self._meta_name_input = QLineEdit()
        self._meta_name_input.setPlaceholderText("Program name")
        self._meta_base_input = QLineEdit()
        self._meta_base_input.setPlaceholderText("Image base (hex)")
        self._update_meta_btn = QPushButton(self.tr("Update"))
        self._update_meta_btn.clicked.connect(self._on_update_metadata)
        meta_row.addWidget(self._meta_name_input)
        meta_row.addWidget(self._meta_base_input)
        meta_row.addWidget(self._update_meta_btn)
        layout.addLayout(meta_row)

        return container

    # ------------------------------------------------------------------
    # Tab 9: Call Graph
    # ------------------------------------------------------------------

    def _create_call_graph_tab(self) -> QWidget:
        """Create the Call Graph tab.

        Returns:
            QWidget: Widget with call graph builder and result tree.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        cg_form = QHBoxLayout()
        self._cg_addr_input = QLineEdit()
        self._cg_addr_input.setPlaceholderText("Address (hex)")
        self._cg_depth_spin = QSpinBox()
        self._cg_depth_spin.setRange(1, 10)
        self._cg_depth_spin.setValue(2)
        self._cg_direction_combo = QComboBox()
        self._cg_direction_combo.addItems(["callees", "callers", "both"])
        self._build_cg_btn = QPushButton(self.tr("Build"))
        self._build_cg_btn.clicked.connect(self._on_build_call_graph)
        cg_form.addWidget(self._cg_addr_input)
        cg_form.addWidget(self._cg_depth_spin)
        cg_form.addWidget(self._cg_direction_combo)
        cg_form.addWidget(self._build_cg_btn)
        layout.addLayout(cg_form)

        self._call_graph_tree = QTreeWidget()
        set_header_labels(self._call_graph_tree, _CALL_GRAPH_COLUMNS)
        set_selection_mode(self._call_graph_tree, QAbstractItemView.SelectionMode.SingleSelection)
        layout.addWidget(self._call_graph_tree)

        btn_row = QHBoxLayout()
        self._callers_btn = QPushButton(self.tr("Show Callers"))
        self._callers_btn.clicked.connect(self._on_show_callers)
        self._slice_btn = QPushButton(self.tr("Get Slice"))
        self._slice_btn.clicked.connect(self._on_show_slice)
        btn_row.addWidget(self._callers_btn)
        btn_row.addWidget(self._slice_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return container

    # ------------------------------------------------------------------
    # Tab 10: Comments
    # ------------------------------------------------------------------

    def _create_comments_tab(self) -> QWidget:
        """Create the Comments tab.

        Returns:
            QWidget: Widget with comment form and comments table.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        add_label = QLabel(self.tr("Add Comment"))
        layout.addWidget(add_label)

        cmt_form1 = QHBoxLayout()
        self._cmt_addr_input = QLineEdit()
        self._cmt_addr_input.setPlaceholderText("Address (hex)")
        self._cmt_type_combo = QComboBox()
        self._cmt_type_combo.addItems(["EOL", "PRE", "POST", "PLATE", "REPEATABLE"])
        cmt_form1.addWidget(self._cmt_addr_input)
        cmt_form1.addWidget(self._cmt_type_combo)
        layout.addLayout(cmt_form1)

        self._cmt_text_input = QPlainTextEdit()
        self._cmt_text_input.setFixedHeight(60)
        self._cmt_text_input.setPlaceholderText("Comment text")
        layout.addWidget(self._cmt_text_input)

        cmt_btns = QHBoxLayout()
        self._add_cmt_btn = QPushButton(self.tr("Add Comment"))
        self._add_cmt_btn.clicked.connect(self._on_add_comment)
        cmt_btns.addWidget(self._add_cmt_btn)
        cmt_btns.addStretch()
        layout.addLayout(cmt_btns)

        self._comments_table = _make_table(_COMMENT_COLUMNS)
        layout.addWidget(self._comments_table)

        refresh_row = QHBoxLayout()
        self._refresh_cmt_range_btn = QPushButton(self.tr("Refresh Range"))
        self._refresh_cmt_range_btn.clicked.connect(self._on_refresh_comments)
        self._load_all_cmt_btn = QPushButton(self.tr("Load All"))
        self._load_all_cmt_btn.clicked.connect(self._on_load_all_comments)
        refresh_row.addWidget(self._refresh_cmt_range_btn)
        refresh_row.addWidget(self._load_all_cmt_btn)
        refresh_row.addStretch()
        layout.addLayout(refresh_row)

        return container

    # ------------------------------------------------------------------
    # Tab 11: Symbols
    # ------------------------------------------------------------------

    def _create_symbols_tab(self) -> QWidget:
        """Create the Symbols tab.

        Returns:
            QWidget: Widget with symbol search, namespaces, equates, relocations, and external functions.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        sym_form = QHBoxLayout()
        self._sym_name_input = QLineEdit()
        self._sym_name_input.setPlaceholderText("Symbol name")
        self._sym_type_combo = QComboBox()
        self._sym_type_combo.addItems(["", "Function", "Label", "Class", "Namespace"])
        self._search_sym_btn = QPushButton(self.tr("Search Symbols"))
        self._search_sym_btn.clicked.connect(self._on_search_symbols)
        sym_form.addWidget(self._sym_name_input)
        sym_form.addWidget(self._sym_type_combo)
        sym_form.addWidget(self._search_sym_btn)
        layout.addLayout(sym_form)

        self._symbols_table = _make_table(_SYMBOL_COLUMNS)
        layout.addWidget(self._symbols_table)

        ns_label = QLabel(self.tr("Namespaces"))
        layout.addWidget(ns_label)

        self._namespaces_table = _make_table(_NAMESPACE_COLUMNS)
        self._namespaces_table.setFixedHeight(80)
        layout.addWidget(self._namespaces_table)

        ns_form = QHBoxLayout()
        self._ns_name_input = QLineEdit()
        self._ns_name_input.setPlaceholderText("Namespace name")
        self._ns_parent_input = QLineEdit()
        self._ns_parent_input.setPlaceholderText("Parent namespace")
        self._create_ns_btn = QPushButton(self.tr("Create Namespace"))
        self._create_ns_btn.clicked.connect(self._on_create_namespace)
        self._refresh_ns_btn = QPushButton(self.tr("Refresh"))
        self._refresh_ns_btn.clicked.connect(self._on_refresh_namespaces)
        ns_form.addWidget(self._ns_name_input)
        ns_form.addWidget(self._ns_parent_input)
        ns_form.addWidget(self._create_ns_btn)
        ns_form.addWidget(self._refresh_ns_btn)
        layout.addLayout(ns_form)

        eq_label = QLabel(self.tr("Equates"))
        layout.addWidget(eq_label)

        self._equates_table = _make_table(_EQUATE_COLUMNS)
        self._equates_table.setFixedHeight(80)
        layout.addWidget(self._equates_table)

        eq_form = QHBoxLayout()
        self._eq_addr_input = QLineEdit()
        self._eq_addr_input.setPlaceholderText("Address (hex)")
        self._eq_value_input = QLineEdit()
        self._eq_value_input.setPlaceholderText("Value")
        self._eq_name_input = QLineEdit()
        self._eq_name_input.setPlaceholderText("Equate name")
        self._create_eq_btn = QPushButton(self.tr("Create Equate"))
        self._create_eq_btn.clicked.connect(self._on_create_equate)
        self._refresh_eq_btn = QPushButton(self.tr("Refresh"))
        self._refresh_eq_btn.clicked.connect(self._on_refresh_equates)
        eq_form.addWidget(self._eq_addr_input)
        eq_form.addWidget(self._eq_value_input)
        eq_form.addWidget(self._eq_name_input)
        eq_form.addWidget(self._create_eq_btn)
        eq_form.addWidget(self._refresh_eq_btn)
        layout.addLayout(eq_form)

        rel_label = QLabel(self.tr("Relocations"))
        layout.addWidget(rel_label)

        rel_top = QHBoxLayout()
        refresh_rel = QPushButton(self.tr("Refresh Relocations"))
        refresh_rel.clicked.connect(self._on_refresh_relocations)
        rel_top.addWidget(refresh_rel)
        rel_top.addStretch()
        layout.addLayout(rel_top)

        self._relocations_table = _make_table(_RELOCATION_COLUMNS)
        self._relocations_table.setFixedHeight(80)
        layout.addWidget(self._relocations_table)

        ext_label = QLabel(self.tr("External Functions"))
        layout.addWidget(ext_label)

        ext_form = QHBoxLayout()
        self._ext_lib_input = QLineEdit()
        self._ext_lib_input.setPlaceholderText("Library name")
        self._ext_func_input = QLineEdit()
        self._ext_func_input.setPlaceholderText("Function name")
        self._ext_addr_input = QLineEdit()
        self._ext_addr_input.setPlaceholderText("Address (hex)")
        self._add_ext_btn = QPushButton(self.tr("Add External"))
        self._add_ext_btn.clicked.connect(self._on_add_external_function)
        ext_form.addWidget(self._ext_lib_input)
        ext_form.addWidget(self._ext_func_input)
        ext_form.addWidget(self._ext_addr_input)
        ext_form.addWidget(self._add_ext_btn)
        layout.addLayout(ext_form)

        return container

    # ------------------------------------------------------------------
    # Tab 12: Scripting
    # ------------------------------------------------------------------

    def _create_scripting_tab(self) -> QWidget:
        """Create the Scripting tab.

        Returns:
            QWidget: Widget with script editor, output view, and configuration forms.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        script_label = QLabel(self.tr("Script (Python / Ghidra)"))
        layout.addWidget(script_label)

        self._script_editor = QPlainTextEdit()
        fm = FontManager.get_instance()
        self._script_editor.setFont(fm.get_code_font(10))
        if PythonSyntaxHighlighter is not None:
            doc = self._script_editor.document()
            if doc is not None:
                PythonSyntaxHighlighter(doc)
        layout.addWidget(self._script_editor)

        params_row = QHBoxLayout()
        params_lbl = QLabel(self.tr("Params (JSON):"))
        self._script_params_input = QLineEdit()
        self._script_params_input.setPlaceholderText('{"key": "value"}')
        params_row.addWidget(params_lbl)
        params_row.addWidget(self._script_params_input)
        layout.addLayout(params_row)

        script_btns = QHBoxLayout()
        self._run_script_btn = QPushButton(self.tr("Run"))
        self._run_script_btn.clicked.connect(self._on_run_script)
        self._run_script_params_btn = QPushButton(self.tr("Run with Params"))
        self._run_script_params_btn.clicked.connect(self._on_run_script_with_params)
        script_btns.addWidget(self._run_script_btn)
        script_btns.addWidget(self._run_script_params_btn)
        script_btns.addStretch()
        layout.addLayout(script_btns)

        output_label = QLabel(self.tr("Output"))
        layout.addWidget(output_label)

        self._script_output = QPlainTextEdit()
        self._script_output.setReadOnly(True)
        self._script_output.setFixedHeight(100)
        layout.addWidget(self._script_output)

        decomp_label = QLabel(self.tr("Decompiler Options"))
        layout.addWidget(decomp_label)

        decomp_row = QHBoxLayout()
        self._decomp_simplification_input = QLineEdit()
        self._decomp_simplification_input.setPlaceholderText("Simplification style")
        self._decomp_max_inst_spin = QSpinBox()
        self._decomp_max_inst_spin.setRange(1, 100000)
        self._decomp_max_inst_spin.setValue(2000)
        self._apply_decomp_btn = QPushButton(self.tr("Apply Decompiler Options"))
        self._apply_decomp_btn.clicked.connect(self._on_apply_decompiler_options)
        decomp_row.addWidget(self._decomp_simplification_input)
        decomp_row.addWidget(self._decomp_max_inst_spin)
        decomp_row.addWidget(self._apply_decomp_btn)
        layout.addLayout(decomp_row)

        analysis_label = QLabel(self.tr("Analysis Configuration"))
        layout.addWidget(analysis_label)

        analysis_row = QHBoxLayout()
        self._analyzer_name_input = QLineEdit()
        self._analyzer_name_input.setPlaceholderText("Analyzer name")
        self._analyzer_enabled_check = QCheckBox(self.tr("Enabled"))
        self._analyzer_enabled_check.setChecked(True)
        self._configure_analysis_btn = QPushButton(self.tr("Configure Analysis"))
        self._configure_analysis_btn.clicked.connect(self._on_configure_analysis)
        analysis_row.addWidget(self._analyzer_name_input)
        analysis_row.addWidget(self._analyzer_enabled_check)
        analysis_row.addWidget(self._configure_analysis_btn)
        layout.addLayout(analysis_row)

        self._analyzer_options_input = QPlainTextEdit()
        self._analyzer_options_input.setPlaceholderText(
            'Analyzer options as JSON, e.g. {"aggressive": true, "timeout_s": 120}',
        )
        self._analyzer_options_input.setFixedHeight(72)
        layout.addWidget(self._analyzer_options_input)

        return container

    # ------------------------------------------------------------------
    # Tab: Data Types
    # ------------------------------------------------------------------

    def _create_data_types_tab(self) -> QWidget:
        """Create the Data Types tab with get/set forms.

        Returns:
            QWidget: Widget with data type inspection and assignment controls.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        get_label = QLabel(self.tr("Get Data Type"))
        get_label.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(get_label)

        get_row = QHBoxLayout()
        get_addr_label = QLabel(self.tr("Address:"))
        get_addr_label.setFont(fm.get_ui_font(9))
        get_row.addWidget(get_addr_label)
        self._dt_get_addr_input = QLineEdit()
        self._dt_get_addr_input.setMaximumWidth(_MAIN_SPLIT_RATIO_RIGHT)
        self._dt_get_addr_input.setPlaceholderText("0x...")
        get_row.addWidget(self._dt_get_addr_input)
        self._dt_get_btn = QPushButton(self.tr("Get"))
        self._dt_get_btn.setObjectName("tool_button")
        self._dt_get_btn.clicked.connect(self._on_get_data_type)
        get_row.addWidget(self._dt_get_btn)
        get_row.addStretch()
        layout.addLayout(get_row)

        self._dt_result_view = QPlainTextEdit()
        self._dt_result_view.setReadOnly(True)
        self._dt_result_view.setFont(fm.get_code_font(10))
        self._dt_result_view.setFixedHeight(120)
        layout.addWidget(self._dt_result_view)

        set_label = QLabel(self.tr("Set Data Type"))
        set_label.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(set_label)

        set_row = QHBoxLayout()
        set_addr_label = QLabel(self.tr("Address:"))
        set_addr_label.setFont(fm.get_ui_font(9))
        set_row.addWidget(set_addr_label)
        self._dt_set_addr_input = QLineEdit()
        self._dt_set_addr_input.setMaximumWidth(_MAIN_SPLIT_RATIO_RIGHT)
        self._dt_set_addr_input.setPlaceholderText("0x...")
        set_row.addWidget(self._dt_set_addr_input)

        type_label = QLabel(self.tr("Type:"))
        type_label.setFont(fm.get_ui_font(9))
        set_row.addWidget(type_label)
        self._dt_type_input = QLineEdit()
        self._dt_type_input.setMaximumWidth(_CODE_SPLIT_RATIO_BOTTOM)
        self._dt_type_input.setPlaceholderText("e.g. dword, byte[16], char*")
        set_row.addWidget(self._dt_type_input)

        self._dt_set_btn = QPushButton(self.tr("Apply"))
        self._dt_set_btn.setObjectName("tool_button")
        self._dt_set_btn.clicked.connect(self._on_set_data_type)
        set_row.addWidget(self._dt_set_btn)
        set_row.addStretch()
        layout.addLayout(set_row)

        self._data_type_manager = DataTypeManagerWidget()
        if self._bridge is not None:
            self._data_type_manager.set_bridge(self._bridge)
        layout.addWidget(self._data_type_manager)

        layout.addStretch()
        return container

    def _create_program_tree_tab(self) -> QWidget:
        """Create the Program Tree tab.

        Returns:
            QWidget: Widget wrapping the module/fragment hierarchy browser
            and editor.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        self._program_tree = ProgramTreeWidget()
        if self._bridge is not None:
            self._program_tree.set_bridge(self._bridge)
        layout.addWidget(self._program_tree)

        return container

    def _create_analysis_extras_tab(self) -> QWidget:
        """Create the Analysis Extras tab.

        Returns:
            QWidget: Widget wrapping instruction-flow/register lookup,
            thunk management, external references, properties, and the
            bidirectional call graph controls.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        self._analysis_extras = GhidraAnalysisExtrasWidget()
        if self._bridge is not None:
            self._analysis_extras.set_bridge(self._bridge)
        layout.addWidget(self._analysis_extras)

        return container

    def _on_get_data_type(self) -> None:
        """Retrieve and display the data type at the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return

        addr_text = self._dt_get_addr_input.text().strip()
        if not addr_text:
            return

        try:
            address = int(addr_text, 16) if addr_text.startswith(("0x", "0X")) else int(addr_text)
        except ValueError:
            _logger.warning("ghidra_get_data_type_invalid_address", input_text=addr_text)
            self._dt_result_view.setPlainText("Invalid address")
            return

        self._dt_get_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_data_type(address),
            on_success=self._apply_get_data_type,
            on_error=self._on_get_data_type_error,
            parent=self,
            event="ghidra_get_data_type",
            logger=_logger,
            address=hex(address),
        )

    def _apply_get_data_type(self, result: object) -> None:
        """Display the retrieved data type information.

        Args:
            result: DataTypeInfo from the bridge, or None.
        """
        self._dt_get_btn.setEnabled(True)
        if result is None:
            self._dt_result_view.setPlainText("No data type defined at this address")
            return

        parts: list[str] = []
        if name := getattr(result, "name", None):
            parts.append(f"Name: {name}")
        if category := getattr(result, "category", None):
            parts.append(f"Category: {category}")
        size = getattr(result, "size", None)
        if size is not None:
            parts.append(f"Size: {size}")
        if description := getattr(result, "description", None):
            parts.append(f"Description: {description}")

        self._dt_result_view.setPlainText("\n".join(parts) if parts else str(result))

    def _on_get_data_type_error(self, exc: object) -> None:
        """Handle data type retrieval failure.

        Args:
            exc: The exception that occurred.
        """
        self._dt_get_btn.setEnabled(True)
        self._dt_result_view.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_get_data_type_failed", error=str(exc))

    def _on_set_data_type(self) -> None:
        """Apply a data type at the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return

        addr_text = self._dt_set_addr_input.text().strip()
        type_name = self._dt_type_input.text().strip()
        if not addr_text or not type_name:
            return

        try:
            address = int(addr_text, 16) if addr_text.startswith(("0x", "0X")) else int(addr_text)
        except ValueError:
            _logger.warning("ghidra_set_data_type_invalid_address", input_text=addr_text)
            self._set_status("Invalid address")
            return

        self._dt_set_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.set_data_type(address, type_name),
            on_success=self._apply_set_data_type,
            on_error=self._on_set_data_type_error,
            parent=self,
            event="ghidra_set_data_type",
            logger=_logger,
            level="info",
            address=hex(address),
            type_name=type_name,
        )

    def _apply_set_data_type(self, result: object) -> None:
        """Handle successful data type assignment.

        Args:
            result: Boolean success flag from the bridge.
        """
        self._dt_set_btn.setEnabled(True)
        if result:
            self._set_status("Data type applied successfully")
        else:
            self._set_status("Failed to apply data type")

    def _on_set_data_type_error(self, exc: object) -> None:
        """Handle data type assignment failure.

        Args:
            exc: The exception that occurred.
        """
        self._dt_set_btn.setEnabled(True)
        self._set_status(f"Set data type error: {exc}")
        _logger.warning("ghidra_set_data_type_gui_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Functions Sidebar
    # ------------------------------------------------------------------

    def _create_functions_sidebar(self) -> QWidget:
        """Create the functions list sidebar with context menu and create form.

        Returns:
            QWidget: Functions sidebar widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        header = QHBoxLayout()
        self._func_count_label = QLabel(self.tr("Functions"))
        self._func_count_label.setFont(FontManager.get_instance().get_ui_font_bold(9))
        header.addWidget(self._func_count_label)
        header.addStretch()

        self._refresh_funcs_btn = QPushButton(self.tr("Refresh"))
        self._refresh_funcs_btn.setObjectName("secondary_button")
        self._refresh_funcs_btn.clicked.connect(self._on_refresh_functions)
        header.addWidget(self._refresh_funcs_btn)
        layout.addLayout(header)

        self._filter_debounce = QTimer(self)
        self._filter_debounce.setSingleShot(True)
        self._filter_debounce.setInterval(_FILTER_DEBOUNCE_MS)
        self._filter_debounce.timeout.connect(self._on_refresh_functions)

        self._func_filter = QLineEdit()
        self._func_filter.setPlaceholderText(self.tr("Filter functions..."))
        self._func_filter.textChanged.connect(self._on_filter_changed)
        layout.addWidget(self._func_filter)

        goto_row = QHBoxLayout()
        self._goto_func_addr = QLineEdit()
        self._goto_func_addr.setPlaceholderText(self.tr("Go to address (hex)"))
        self._goto_func_addr.returnPressed.connect(self._on_goto_function)
        goto_row.addWidget(self._goto_func_addr)
        self._goto_func_btn = QPushButton(self.tr("Go"))
        self._goto_func_btn.clicked.connect(self._on_goto_function)
        goto_row.addWidget(self._goto_func_btn)
        layout.addLayout(goto_row)

        self._func_tree = QTreeWidget()
        set_header_labels(self._func_tree, _FUNC_COLUMNS)
        set_sorting_enabled(self._func_tree, enable=True)
        set_selection_mode(self._func_tree, QAbstractItemView.SelectionMode.SingleSelection)
        self._func_tree.itemClicked.connect(self._on_function_clicked)
        self._func_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._func_tree.customContextMenuRequested.connect(self._on_func_context_menu)
        func_tree_header = self._func_tree.header()
        if func_tree_header is not None:
            func_tree_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._func_tree)

        create_layout = QHBoxLayout()
        self._create_func_addr = QLineEdit()
        self._create_func_addr.setPlaceholderText("Address (hex)")
        self._create_func_name = QLineEdit()
        self._create_func_name.setPlaceholderText("Name (optional)")
        self._create_func_btn = QPushButton(self.tr("Create"))
        self._create_func_btn.clicked.connect(self._on_create_function)
        create_layout.addWidget(self._create_func_addr)
        create_layout.addWidget(self._create_func_name)
        create_layout.addWidget(self._create_func_btn)
        layout.addLayout(create_layout)

        return container

    # ------------------------------------------------------------------
    # Address helper
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_address(text: str) -> int | None:
        """Parse a hex or decimal address string.

        Args:
            text: Address string, optionally prefixed with '0x'.

        Returns:
            int | None: Parsed integer address, or None on failure.
        """
        try:
            text = text.strip()
            return int(text, 16) if text.startswith(("0x", "0X")) else int(text)
        except (ValueError, TypeError):
            _logger.warning("ghidra_parse_address_invalid_input", input_text=text)
            return None

    # ------------------------------------------------------------------
    # Bridge wiring
    # ------------------------------------------------------------------

    def set_bridge(self, bridge: GhidraBridge) -> None:
        """Set the GhidraBridge instance for analysis.

        Args:
            bridge: The GhidraBridge to use.
        """
        self._bridge = bridge
        self._data_type_manager.set_bridge(bridge)
        self._program_tree.set_bridge(bridge)
        self._analysis_extras.set_bridge(bridge)
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
        self._undo_btn.setEnabled(ready)
        self._redo_btn.setEnabled(ready)
        self._byte_search_btn.setEnabled(ready)

    # ------------------------------------------------------------------
    # Binary load
    # ------------------------------------------------------------------

    def load_binary(self, binary_path: Path) -> bool:
        """Load a binary for analysis.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            bool: True if loading was initiated.
        """
        bridge = self._require_connected()
        if bridge is None:
            return False

        self._load_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.load_binary(binary_path),
            on_success=lambda _: self._on_binary_loaded(binary_path),
            on_error=lambda e: self._on_binary_load_error(binary_path, e),
            parent=self,
            event="ghidra_load_binary",
            logger=_logger,
            level="info",
            binary_path=str(binary_path),
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

    # ------------------------------------------------------------------
    # Connect / Disconnect
    # ------------------------------------------------------------------

    def _on_connect(self) -> None:
        """Connect to Ghidra bridge."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            _logger.warning("ghidra_connect_no_bridge", reason="bridge not set")
            return

        self._connect_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.initialize(),
            on_success=lambda _: self._on_connect_success(),
            on_error=self._on_connect_error,
            parent=self,
            event="ghidra_initialize",
            logger=_logger,
            level="info",
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
        run_bridge_coroutine_logged(
            self._bridge.shutdown(),
            on_success=lambda _: self._on_disconnect_success(),
            on_error=self._on_disconnect_error,
            parent=self,
            event="ghidra_shutdown",
            logger=_logger,
            level="info",
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

    # ------------------------------------------------------------------
    # Load / Analyze / Headless
    # ------------------------------------------------------------------

    def _on_load_binary(self) -> None:
        """Open file dialog and load selected binary."""
        if self._require_connected() is None:
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Load Binary"),
            "",
            self.tr("All Files (*)"),
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

        run_bridge_coroutine_logged(
            bridge.analyze(),
            on_success=lambda _: self._on_analysis_complete(),
            on_error=self._on_analysis_error,
            parent=self,
            event="ghidra_analyze",
            logger=_logger,
            level="info",
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

    def _on_start_headless(self) -> None:
        """Start Ghidra headless analyzer and auto-connect."""
        if self._bridge is None:
            self._set_status("No bridge configured")
            return

        ghidra_path = self._bridge.ghidra_path
        if ghidra_path is None:
            if path_str := QFileDialog.getExistingDirectory(
                self,
                self.tr("Select Ghidra Installation Directory"),
            ):
                self.set_ghidra_path(Path(path_str))
            else:
                return
        project_dir = Path(tempfile.gettempdir()) / "intellicrack_ghidra"
        self._headless_btn.setEnabled(False)
        self._set_status("Starting headless Ghidra...")
        run_bridge_coroutine_logged(
            self._bridge.start_headless(project_dir),
            on_success=lambda _: self._on_headless_started(),
            on_error=self._on_headless_error,
            parent=self,
            event="ghidra_start_headless",
            logger=_logger,
            level="info",
            project_dir=str(project_dir),
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

    # ------------------------------------------------------------------
    # Undo / Redo
    # ------------------------------------------------------------------

    def _on_undo(self) -> None:
        """Undo the last Ghidra action."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.undo(),
            on_success=lambda _: self._set_status("Undo complete"),
            on_error=lambda e: self._set_status(f"Undo failed: {e}"),
            parent=self,
            event="ghidra_undo",
            logger=_logger,
            level="info",
        )

    def _on_redo(self) -> None:
        """Redo the last undone Ghidra action."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.redo(),
            on_success=lambda _: self._set_status("Redo complete"),
            on_error=lambda e: self._set_status(f"Redo failed: {e}"),
            parent=self,
            event="ghidra_redo",
            logger=_logger,
            level="info",
        )

    # ------------------------------------------------------------------
    # Byte search
    # ------------------------------------------------------------------

    def _on_search_bytes(self) -> None:
        """Search for a byte pattern from the toolbar input."""
        bridge = self._require_connected()
        if bridge is None:
            return
        pattern = self._byte_search_input.text().strip()
        if not pattern:
            return
        self._byte_search_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.search_bytes(pattern),
            on_success=self._apply_byte_search_results,
            on_error=self._on_byte_search_error,
            parent=self,
            event="ghidra_search_bytes",
            logger=_logger,
            pattern_length=len(pattern),
        )

    def _apply_byte_search_results(self, result: object) -> None:
        """Show byte search results in the scripting output tab.

        Args:
            result: List of match addresses from the bridge.
        """
        self._byte_search_btn.setEnabled(True)
        matches = cast("list[int]", result) if isinstance(result, list) else []
        lines = [f"0x{int(m):X}" for m in matches]
        if self._data_tabs is not None:
            self._data_tabs.setCurrentIndex(11)
        self._script_output.setPlainText("\n".join(lines) if lines else "No matches found.")
        self._set_status(f"Byte search: {len(matches)} match(es)")

    def _on_byte_search_error(self, exc: object) -> None:
        """Handle byte search failure.

        Args:
            exc: The exception that occurred.
        """
        self._byte_search_btn.setEnabled(True)
        self._set_status(f"Byte search failed: {exc}")
        _logger.warning("ghidra_byte_search_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Debug Info
    # ------------------------------------------------------------------

    def _on_import_debug_info(self) -> None:
        """Import debug information (PDB/DWARF) into current program."""
        bridge = self._require_connected()
        if bridge is None:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Select Debug Info File"),
            "",
            self.tr("Debug Files (*.pdb *.dbg);;All Files (*)"),
        )
        if not file_path:
            return
        run_bridge_coroutine_logged(
            bridge.import_debug_info(file_path),
            on_success=lambda _: self._set_status(f"Debug info imported: {Path(file_path).name}"),
            on_error=lambda e: self._set_status(f"Debug import failed: {e}"),
            parent=self,
            event="ghidra_import_debug_info",
            logger=_logger,
            level="info",
            file_path=file_path,
        )

    # ------------------------------------------------------------------
    # Diff Programs
    # ------------------------------------------------------------------

    def _on_diff_programs(self) -> None:
        """Compare current program with another program file."""
        bridge = self._require_connected()
        if bridge is None:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Select Program to Compare"),
            "",
            self.tr("All Files (*)"),
        )
        if not file_path:
            return
        self._set_status("Comparing programs...")
        run_bridge_coroutine_logged(
            bridge.diff_programs(file_path),
            on_success=self._apply_diff_results,
            on_error=lambda e: self._set_status(f"Diff failed: {e}"),
            parent=self,
            event="ghidra_diff_programs",
            logger=_logger,
            file_path=file_path,
        )

    def _apply_diff_results(self, result: object) -> None:
        """Display program diff results in the scripting output tab.

        Args:
            result: Diff result dict from the bridge.
        """
        if self._data_tabs is not None:
            self._data_tabs.setCurrentIndex(11)
        if isinstance(result, dict):
            diff_data = cast("dict[str, object]", result)
            diff_count = diff_data.get("differences", 0)
            details = diff_data.get("details", [])
            lines: list[str] = [f"Differences found: {diff_count}"]
            if isinstance(details, list):
                for detail in cast("list[dict[str, object]]", details):
                    addr_val = detail.get("address", 0)
                    lines.append(f"  0x{int(cast('int', addr_val)):X}")
            self._script_output.setPlainText("\n".join(lines))
        else:
            self._script_output.setPlainText(str(result))
        self._set_status("Diff complete")

    # ------------------------------------------------------------------
    # Overlay Space
    # ------------------------------------------------------------------

    def _on_create_overlay_space(self) -> None:
        """Create a new overlay address space."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._overlay_name_input.text().strip()
        if not name:
            self._set_status("Overlay name required")
            return
        run_bridge_coroutine_logged(
            bridge.create_overlay_space(name),
            on_success=lambda _: self._set_status(f"Overlay space '{name}' created"),
            on_error=lambda e: self._set_status(f"Create overlay failed: {e}"),
            parent=self,
            event="ghidra_create_overlay_space",
            logger=_logger,
            level="info",
            name=name,
        )

    # ------------------------------------------------------------------
    # Functions
    # ------------------------------------------------------------------

    def _on_refresh_functions(self) -> None:
        """Refresh the functions list from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return

        filter_text = self._func_filter.text().strip() or None
        self._refresh_funcs_btn.setEnabled(False)

        run_bridge_coroutine_logged(
            bridge.get_functions(filter_text),
            on_success=self._apply_functions,
            on_error=lambda _: self._on_refresh_funcs_error(),
            parent=self,
            event="ghidra_get_functions",
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
            func_name = getattr(func, "name", "")
            item = NumericSortTreeItem([
                func_name,
                f"0x{getattr(func, 'address', 0):X}",
                str(getattr(func, "size", 0)),
            ])
            item.setToolTip(0, func_name)
            tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, getattr(func, "address", 0))
            self._func_tree.addTopLevelItem(item)

        set_sorting_enabled(self._func_tree, enable=True)
        self._func_tree.resizeColumnToContents(0)
        self._func_count_label.setText(f"Functions ({len(functions)})")
        self._refresh_funcs_btn.setEnabled(True)
        _logger.debug("ghidra_functions_refreshed", count=len(functions))

    def _on_refresh_funcs_error(self) -> None:
        """Handle function refresh failure."""
        _logger.warning("ghidra_refresh_functions_failed", bridge_type="ghidra")
        self._refresh_funcs_btn.setEnabled(True)

    def _on_filter_changed(self, _text: str) -> None:
        """Restart the debounce timer so filtering runs once typing pauses.

        Args:
            _text: New filter text (unused, read from the widget on refresh).
        """
        self._filter_debounce.start()

    def _on_goto_function(self) -> None:
        """Look up the function at the entered address and load its code views."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = self._parse_address(self._goto_func_addr.text())
        if address is None:
            self._set_status("Invalid address for go to function")
            return
        self._goto_func_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_function(address),
            on_success=lambda r, addr=address: self._apply_goto_function(r, addr),
            on_error=self._on_goto_function_error,
            parent=self,
            event="ghidra_get_function",
            logger=_logger,
            address=hex(address),
        )

    def _apply_goto_function(self, result: object, address: int) -> None:
        """Load the resolved function's code views, or report that none was found.

        Args:
            result: FunctionInfo from the bridge, or None if no function
                exists at the requested address.
            address: The address that was looked up.
        """
        self._goto_func_btn.setEnabled(True)
        if result is None:
            self._set_status(f"No function found at 0x{address:X}")
            return
        func_name = getattr(result, "name", "")
        func_addr = getattr(result, "address", address)
        self._set_status(f"Found function '{func_name}' at 0x{func_addr:X}")
        self._load_function_at_address(func_addr)

    def _on_goto_function_error(self, exc: object) -> None:
        """Handle a go-to-function lookup failure.

        Args:
            exc: The exception that occurred.
        """
        self._goto_func_btn.setEnabled(True)
        self._set_status(f"Go to function failed: {exc}")
        _logger.warning("ghidra_goto_function_failed", error=str(exc))

    def _on_function_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        """Handle function tree item click to show decompilation, disassembly, PCode, and CFG.

        Args:
            item: Clicked tree widget item.
            _column: Column index (unused).
        """
        address = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if not isinstance(address, int):
            return
        self._load_function_at_address(address)

    def _load_function_at_address(self, address: int) -> None:
        """Load decompilation, disassembly, PCode, CFG, and xrefs for a function address.

        Args:
            address: Function address to load.
        """
        bridge = self._require_connected()
        if bridge is None:
            return

        binary_path = str(bridge.state.target_path) if bridge.state.target_path is not None else "unset"
        _logger.info(
            "ghidra_function_decompile_requested",
            binary_path=binary_path,
            offset=hex(address),
        )

        run_bridge_coroutine_logged(
            bridge.decompile(address),
            on_success=self._apply_decompiled,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_decompile_failed", "Decompile", addr, e),
            parent=self,
            event="ghidra_decompile",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_disassemble_failed", "Disassemble", addr, e),
            parent=self,
            event="ghidra_disassemble",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            bridge.get_pcode(address),
            on_success=self._apply_pcode,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_pcode_failed", "PCode", addr, e),
            parent=self,
            event="ghidra_get_pcode",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            bridge.get_basic_blocks(address),
            on_success=self._apply_cfg,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_cfg_failed", "CFG", addr, e),
            parent=self,
            event="ghidra_get_basic_blocks",
            logger=_logger,
            address=hex(address),
        )

        self.show_xrefs(address)

    def _apply_decompiled(self, result: object) -> None:
        """Display decompiled code, or an inline status note when Ghidra returned nothing.

        Args:
            result: Decompiled code string from the bridge.
        """
        if result is None or not str(result).strip():
            self._decompiled_view.setPlainText("// No decompilation available at this address")
            self._set_status("No decompilation available at this address")
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

    def _apply_pcode(self, result: object) -> None:
        """Apply PCode data to the PCode view.

        Args:
            result: PCode dict with function and pcode_ops, or raw text.
        """
        if result is None:
            return
        if isinstance(result, dict):
            pcode_data = cast("dict[str, object]", result)
            func_name = str(pcode_data.get("function", ""))
            ops_raw = pcode_data.get("pcode_ops", [])
            ops = cast("list[dict[str, object]]", ops_raw) if isinstance(ops_raw, list) else []
            lines: list[str] = []
            if func_name:
                lines.append(f"; Function: {func_name}")
            for op in ops:
                addr = int(cast("int", op.get("address", 0)))
                mnemonic = str(op.get("mnemonic", ""))
                lines.append(f"  0x{addr:X}  {mnemonic}")
            self._pcode_view.setPlainText("\n".join(lines))
        else:
            self._pcode_view.setPlainText(str(result))

    def _apply_cfg(self, result: object) -> None:
        """Apply basic block data to the CFG view.

        Args:
            result: Basic block dict with function and blocks, or raw data.
        """
        if result is None:
            return
        blocks_list: list[dict[str, object]] = []
        if isinstance(result, dict):
            cfg_result = cast("dict[str, object]", result)
            blocks_raw = cfg_result.get("blocks", [])
            if isinstance(blocks_raw, list):
                blocks_list = cast("list[dict[str, object]]", blocks_raw)
        if CFGGraphView is not None and isinstance(self._cfg_view, CFGGraphView):
            scene = self._cfg_view.graph_scene()
            scene.load_graph(blocks_list)
            self._cfg_view.fit_to_view()
        elif isinstance(self._cfg_view, QPlainTextEdit):
            lines2: list[str] = []
            for blk in blocks_list:
                blk_start = int(cast("int", blk.get("start", 0)))
                blk_end = int(cast("int", blk.get("end", 0)))
                lines2.append(f"Block: 0x{blk_start:X} - 0x{blk_end:X}")
                srcs = blk.get("sources", [])
                if isinstance(srcs, list) and (src_list := cast("list[int]", srcs)):
                    src_strs = [f"0x{s:X}" for s in src_list]
                    lines2.append(f"  Sources: {', '.join(src_strs)}")
                dsts = blk.get("destinations", [])
                if isinstance(dsts, list) and (dst_list := cast("list[int]", dsts)):
                    dst_strs = [f"0x{d:X}" for d in dst_list]
                    lines2.append(f"  Destinations: {', '.join(dst_strs)}")
            self._cfg_view.setPlainText("\n".join(lines2))

    def _on_cfg_block_clicked(self, address: int) -> None:
        """Navigate to a CFG basic block by loading its disassembly.

        Args:
            address: Start address of the clicked basic block.
        """
        bridge = self._require_connected()
        if bridge is None:
            return
        self._set_status(f"Block 0x{address:X}")
        self._code_tabs.setCurrentWidget(self._disasm_view)
        run_bridge_coroutine_logged(
            bridge.disassemble(address),
            on_success=self._apply_disassembly,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_disassemble_failed", "Disassemble", addr, e),
            parent=self,
            event="ghidra_disassemble",
            logger=_logger,
            address=hex(address),
        )

    def _show_function_body_info(self, result: object) -> None:
        """Display function body info including thunk status.

        Args:
            result: Function body dict from the bridge.
        """
        if not isinstance(result, dict):
            self._show_info_dialog("Function Body", str(result))
            return
        body = cast("dict[str, object]", result)
        lines: list[str] = [
            f"Function: {body.get('name', '')}",
            f"Address: 0x{int(cast('int', body.get('address', 0))):X}",
            f"Size: {body.get('total_size', 0)} bytes",
        ]
        if body.get("is_thunk", False):
            thunked = body.get("thunked_function", "")
            lines.append(f"Thunk -> {thunked}")
        ranges = body.get("ranges", [])
        if isinstance(ranges, list):
            for rng in cast("list[dict[str, object]]", ranges):
                rng_start = int(cast("int", rng.get("start", 0)))
                rng_end = int(cast("int", rng.get("end", 0)))
                lines.append(f"  Range: 0x{rng_start:X} - 0x{rng_end:X}")
        self._show_info_dialog("Function Body", "\n".join(lines))

    def _show_info_dialog(self, title: str, message: str) -> None:
        """Show an informational message box.

        Args:
            title: Dialog title.
            message: Message text to display.
        """
        QMessageBox.information(self, self.tr(title), message)

    def _on_op_error(self, event: str, label: str, address: int, error: object) -> None:
        """Log and display a bridge operation failure.

        Args:
            event: Operation identifier used as a structured log kwarg.
            label: Human-readable operation label for the status bar.
            address: Target address that the operation was attempted on.
            error: Exception or error object from the bridge.
        """
        _logger.warning(
            "ghidra_bridge_op_failed",
            operation=event,
            address=hex(address),
            error=str(error),
            error_type=type(error).__name__,
        )
        self._set_status(f"{label} failed: {error}")

    # ------------------------------------------------------------------
    # Create Function
    # ------------------------------------------------------------------

    def _on_create_function(self) -> None:
        """Create a new function at the specified address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._create_func_addr.text())
        if addr is None:
            self._set_status("Invalid address for create function")
            return
        name = self._create_func_name.text().strip() or None
        run_bridge_coroutine_logged(
            bridge.create_function(addr, name),
            on_success=lambda _: self._on_refresh_functions(),
            on_error=lambda e: self._set_status(f"Create function failed: {e}"),
            parent=self,
            event="ghidra_create_function",
            logger=_logger,
            level="info",
            address=hex(addr),
            name=name,
        )

    # ------------------------------------------------------------------
    # Function Context Menu
    # ------------------------------------------------------------------

    def _on_func_context_menu(self, pos: QPoint) -> None:
        """Show context menu for function tree items.

        Args:
            pos: Position where the right-click occurred.
        """
        item = self._func_tree.itemAt(pos)
        if item is None:
            return
        address = tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        if not isinstance(address, int):
            return
        func_name = item.text(0)

        menu = QMenu(self)
        raw_actions: dict[str, QAction | None] = {
            "rename": menu.addAction(self.tr("Rename Function")),
            "edit_sig": menu.addAction(self.tr("Edit Signature")),
            "add_cmt": menu.addAction(self.tr("Add Comment")),
            "set_var": menu.addAction(self.tr("Set Variable Type")),
            "call_graph": menu.addAction(self.tr("Show Call Graph")),
            "stack": menu.addAction(self.tr("Get Stack Frame")),
            "body": menu.addAction(self.tr("Get Function Body")),
            "conventions": menu.addAction(self.tr("Show Calling Conventions")),
            "set_color": menu.addAction(self.tr("Set Color")),
        }
        menu.addSeparator()
        raw_actions["delete"] = menu.addAction(self.tr("Delete Function"))

        if any(v is None for v in raw_actions.values()):
            return

        actions: dict[str, object] = {k: v for k, v in raw_actions.items() if v is not None}

        chosen = menu.exec(self._func_tree.mapToGlobal(pos))
        if chosen is None:
            return

        bridge = self._require_connected()
        if bridge is None:
            return

        self._dispatch_func_menu_action(chosen, actions, address, func_name, bridge)

    def _dispatch_func_menu_action(
        self,
        chosen: object,
        actions: dict[str, object],
        address: int,
        func_name: str,
        bridge: GhidraBridge,
    ) -> None:
        """Dispatch a selected function context menu action.

        Args:
            chosen: The selected QAction.
            actions: Mapping of action keys to QAction instances.
            address: Function address the action targets.
            func_name: Display name of the targeted function.
            bridge: Connected GhidraBridge instance.
        """
        if chosen is actions["rename"]:
            new_name, ok = QInputDialog.getText(self, self.tr("Rename Function"), self.tr("New name:"), text=func_name)
            if ok and new_name.strip():
                run_bridge_coroutine_logged(
                    bridge.rename_function(address, new_name.strip()),
                    on_success=lambda _: self._on_refresh_functions(),
                    on_error=lambda e: self._set_status(f"Rename failed: {e}"),
                    parent=self,
                    event="ghidra_rename_function",
                    logger=_logger,
                    level="info",
                    address=hex(address),
                    new_name=new_name.strip(),
                )

        elif chosen is actions["edit_sig"]:
            self._handle_edit_signature(address, func_name, bridge)

        elif chosen is actions["add_cmt"]:
            cmt_text, ok = QInputDialog.getText(self, self.tr("Add Comment"), self.tr("Comment:"))
            if ok and cmt_text.strip():
                run_bridge_coroutine_logged(
                    bridge.add_comment(address, cmt_text.strip(), "EOL"),
                    on_success=lambda _: self._set_status("Comment added"),
                    on_error=lambda e: self._set_status(f"Add comment failed: {e}"),
                    parent=self,
                    event="ghidra_add_comment",
                    logger=_logger,
                    level="info",
                    address=hex(address),
                    comment_type="EOL",
                    comment_length=len(cmt_text.strip()),
                )

        elif chosen is actions["set_var"]:
            var_info, ok = QInputDialog.getText(
                self,
                self.tr("Set Variable Type"),
                self.tr("Variable name:type (e.g. myVar:int):"),
            )
            if ok and ":" in var_info:
                var_name, var_type = var_info.split(":", 1)
                run_bridge_coroutine_logged(
                    bridge.set_function_variable_type(address, var_name.strip(), var_type.strip()),
                    on_success=lambda _: self._set_status("Variable type set"),
                    on_error=lambda e: self._set_status(f"Set variable type failed: {e}"),
                    parent=self,
                    event="ghidra_set_function_variable_type",
                    logger=_logger,
                    level="info",
                    address=hex(address),
                    variable_name=var_name.strip(),
                    variable_type=var_type.strip(),
                )

        elif chosen is actions["call_graph"]:
            if self._data_tabs is not None:
                self._data_tabs.setCurrentIndex(8)
            self._cg_addr_input.setText(hex(address))
            self._on_build_call_graph()

        elif chosen is actions["stack"]:
            run_bridge_coroutine_logged(
                bridge.get_stack_frame(address),
                on_success=lambda r: self._show_info_dialog("Stack Frame", str(r)),
                on_error=lambda e: self._set_status(f"Stack frame failed: {e}"),
                parent=self,
                event="ghidra_get_stack_frame",
                logger=_logger,
                address=hex(address),
            )

        elif chosen is actions["body"]:
            run_bridge_coroutine_logged(
                bridge.get_function_body(address),
                on_success=self._show_function_body_info,
                on_error=lambda e: self._set_status(f"Function body failed: {e}"),
                parent=self,
                event="ghidra_get_function_body",
                logger=_logger,
                address=hex(address),
            )

        elif chosen is actions["conventions"]:

            def _show_conventions(r: object) -> None:
                if isinstance(r, list):
                    conv_list = cast("list[object]", r)
                    body_text = "\n".join(str(c) for c in conv_list)
                else:
                    body_text = str(r)
                self._show_info_dialog("Calling Conventions", body_text)

            run_bridge_coroutine_logged(
                bridge.get_calling_conventions(),
                on_success=_show_conventions,
                on_error=lambda e: self._set_status(f"Calling conventions failed: {e}"),
                parent=self,
                event="ghidra_get_calling_conventions",
                logger=_logger,
            )

        elif chosen is actions["set_color"]:
            color_hex, ok = QInputDialog.getText(
                self,
                self.tr("Set Color"),
                self.tr("RGB color (e.g. FF0000 for red):"),
            )
            if ok and color_hex.strip():
                try:
                    color_int = int(color_hex.strip(), 16)
                except ValueError:
                    _logger.warning("ghidra_set_color_invalid_hex", input_text=color_hex)
                    self._set_status("Invalid color hex value")
                    return
                run_bridge_coroutine_logged(
                    bridge.set_color(address, color_int),
                    on_success=lambda _: self._set_status(f"Color set at 0x{address:X}"),
                    on_error=lambda e: self._set_status(f"Set color failed: {e}"),
                    parent=self,
                    event="ghidra_set_color",
                    logger=_logger,
                    level="info",
                    address=hex(address),
                    color=hex(color_int),
                )

        elif chosen is actions["delete"]:
            reply = QMessageBox.question(
                self,
                self.tr("Delete Function"),
                self.tr("Delete function '{name}' at 0x{addr:X}?").format(name=func_name, addr=address),
            )
            if reply == QMessageBox.StandardButton.Yes:
                run_bridge_coroutine_logged(
                    bridge.delete_function(address),
                    on_success=lambda _: self._on_refresh_functions(),
                    on_error=lambda e: self._set_status(f"Delete failed: {e}"),
                    parent=self,
                    event="ghidra_delete_function",
                    logger=_logger,
                    level="info",
                    address=hex(address),
                )

    def _handle_edit_signature(
        self,
        address: int,
        func_name: str,
        bridge: GhidraBridge,
    ) -> None:
        """Prompt the user to edit a function signature and apply it.

        Args:
            address: Function address to edit.
            func_name: Current function name used as default.
            bridge: Connected GhidraBridge instance.
        """
        ret_type, ok1 = QInputDialog.getText(self, self.tr("Edit Signature"), self.tr("Return type:"))
        if not ok1:
            return
        cc, ok2 = QInputDialog.getText(self, self.tr("Edit Signature"), self.tr("Calling convention:"))
        if not ok2:
            return
        new_sig_name, ok3 = QInputDialog.getText(self, self.tr("Edit Signature"), self.tr("Function name:"), text=func_name)
        if ok3:
            run_bridge_coroutine_logged(
                bridge.edit_function_signature(address, ret_type, cc, new_sig_name),
                on_success=lambda _: self._set_status("Signature updated"),
                on_error=lambda e: self._set_status(f"Signature update failed: {e}"),
                parent=self,
                event="ghidra_edit_function_signature",
                logger=_logger,
                level="info",
                address=hex(address),
                return_type=ret_type,
                calling_convention=cc,
                new_name=new_sig_name,
            )

    # ------------------------------------------------------------------
    # Imports / Exports
    # ------------------------------------------------------------------

    def _refresh_imports(self) -> None:
        """Refresh the imports table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return

        run_bridge_coroutine_logged(
            bridge.get_imports(),
            on_success=self._apply_imports,
            on_error=self._on_imports_refresh_error,
            parent=self,
            event="ghidra_get_imports",
            logger=_logger,
        )

    def _on_imports_refresh_error(self, exc: object) -> None:
        """Log and surface a failed Ghidra imports refresh.

        Args:
            exc: Exception raised by the bridge call.
        """
        _logger.warning("ghidra_refresh_imports_failed", error=str(exc))
        self._set_status(f"Imports refresh failed: {exc}")

    def _on_exports_refresh_error(self, exc: object) -> None:
        """Log and surface a failed Ghidra exports refresh.

        Args:
            exc: Exception raised by the bridge call.
        """
        _logger.warning("ghidra_refresh_exports_failed", error=str(exc))
        self._set_status(f"Exports refresh failed: {exc}")

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

        run_bridge_coroutine_logged(
            bridge.get_exports(),
            on_success=self._apply_exports,
            on_error=self._on_exports_refresh_error,
            parent=self,
            event="ghidra_get_exports",
            logger=_logger,
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

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def search_strings(self, pattern: str) -> None:
        """Search for strings matching pattern and populate table.

        Args:
            pattern: Regex pattern to match.
        """
        bridge = self._require_connected()
        if bridge is None:
            return

        self._string_search_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.search_strings(pattern),
            on_success=self._apply_strings,
            on_error=lambda _: self._on_string_search_error(pattern),
            parent=self,
            event="ghidra_search_strings",
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
        _logger.warning("ghidra_string_search_failed", pattern=pattern)
        self._string_search_btn.setEnabled(True)

    def _on_search_strings(self) -> None:
        """Trigger string search from the search input."""
        if pattern := self._string_search_input.text().strip():
            self.search_strings(pattern)

    # ------------------------------------------------------------------
    # XRefs
    # ------------------------------------------------------------------

    def show_xrefs(self, address: int) -> None:
        """Show cross-references to and from an address.

        Args:
            address: Target address for xref lookup.
        """
        bridge = self._require_connected()
        if bridge is None:
            return

        self._xrefs_tree.clear()

        run_bridge_coroutine_logged(
            bridge.get_xrefs_to(address),
            on_success=self._apply_xrefs_to,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_xrefs_to_failed", "Xrefs-to lookup", addr, e),
            parent=self,
            event="ghidra_get_xrefs_to",
            logger=_logger,
            address=hex(address),
        )

        run_bridge_coroutine_logged(
            bridge.get_xrefs_from(address),
            on_success=self._apply_xrefs_from,
            on_error=lambda e, addr=address: self._on_op_error("ghidra_xrefs_from_failed", "Xrefs-from lookup", addr, e),
            parent=self,
            event="ghidra_get_xrefs_from",
            logger=_logger,
            address=hex(address),
        )

    def _apply_xrefs_to(self, result: object) -> None:
        """Apply xrefs-to data to the tree, emitting a sentinel row when none exist.

        Args:
            result: Cross-reference list from the bridge.
        """
        xrefs: list[object] = [*result] if isinstance(result, list) else []
        if not xrefs:
            self._xrefs_tree.addTopLevelItem(QTreeWidgetItem(["To", "\u2014", "\u2014", "(no callers)"]))
            return
        for xref in xrefs:
            item = QTreeWidgetItem([
                "To",
                f"0x{getattr(xref, 'from_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "from_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)

    def _apply_xrefs_from(self, result: object) -> None:
        """Apply xrefs-from data to the tree, emitting a sentinel row when none exist.

        Args:
            result: Cross-reference list from the bridge.
        """
        xrefs: list[object] = [*result] if isinstance(result, list) else []
        if not xrefs:
            self._xrefs_tree.addTopLevelItem(QTreeWidgetItem(["From", "\u2014", "\u2014", "(no callees)"]))
            return
        for xref in xrefs:
            item = QTreeWidgetItem([
                "From",
                f"0x{getattr(xref, 'to_address', 0):X}",
                getattr(xref, "ref_type", ""),
                getattr(xref, "to_function", "") or "",
            ])
            self._xrefs_tree.addTopLevelItem(item)

    def _on_add_reference(self) -> None:
        """Add a manual memory reference between the two entered addresses."""
        bridge = self._require_connected()
        if bridge is None:
            return
        from_addr = self._parse_address(self._ref_from_input.text())
        if from_addr is None:
            self._set_status("Invalid from-address for add reference")
            return
        to_addr = self._parse_address(self._ref_to_input.text())
        if to_addr is None:
            self._set_status("Invalid to-address for add reference")
            return
        ref_type = self._ref_type_combo.currentText()
        run_bridge_coroutine_logged(
            bridge.add_reference(from_addr, to_addr, ref_type),
            on_success=lambda _, addr=from_addr: self.show_xrefs(addr),
            on_error=lambda e: self._set_status(f"Add reference failed: {e}"),
            parent=self,
            event="ghidra_add_reference",
            logger=_logger,
            level="info",
            from_addr=hex(from_addr),
            to_addr=hex(to_addr),
            ref_type=ref_type,
        )

    def _on_delete_reference(self) -> None:
        """Delete the memory reference between the two entered addresses."""
        bridge = self._require_connected()
        if bridge is None:
            return
        from_addr = self._parse_address(self._ref_from_input.text())
        if from_addr is None:
            self._set_status("Invalid from-address for delete reference")
            return
        to_addr = self._parse_address(self._ref_to_input.text())
        if to_addr is None:
            self._set_status("Invalid to-address for delete reference")
            return
        run_bridge_coroutine_logged(
            bridge.delete_reference(from_addr, to_addr),
            on_success=lambda _, addr=from_addr: self.show_xrefs(addr),
            on_error=lambda e: self._set_status(f"Delete reference failed: {e}"),
            parent=self,
            event="ghidra_delete_reference",
            logger=_logger,
            level="info",
            from_addr=hex(from_addr),
            to_addr=hex(to_addr),
        )

    # ------------------------------------------------------------------
    # Labels / Bookmarks
    # ------------------------------------------------------------------

    def _on_set_label(self) -> None:
        """Set a label at the specified address.

        Routes through ``add_label`` when the Primary checkbox is checked, since that is the only bridge method exposing the primary-label
        flag; otherwise uses the plain ``set_label`` create-or-modify path.
        """
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._label_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for set label")
            return
        name = self._label_name_input.text().strip()
        if not name:
            self._set_status("Label name required")
            return

        if self._label_primary_check.isChecked():
            run_bridge_coroutine_logged(
                bridge.add_label(addr, name, primary=True),
                on_success=lambda _: self._on_refresh_labels(),
                on_error=lambda e: self._set_status(f"Add label failed: {e}"),
                parent=self,
                event="ghidra_add_label",
                logger=_logger,
                level="info",
                address=hex(addr),
                name=name,
                primary=True,
            )
            return

        run_bridge_coroutine_logged(
            bridge.set_label(addr, name),
            on_success=lambda _: self._on_refresh_labels(),
            on_error=lambda e: self._set_status(f"Set label failed: {e}"),
            parent=self,
            event="ghidra_set_label",
            logger=_logger,
            level="info",
            address=hex(addr),
            name=name,
        )

    def _on_refresh_labels(self) -> None:
        """Refresh the labels table from bridge.

        Requires a valid address in the label address input. If the input is empty or unparsable, surfaces a UI error and short-circuits
        without invoking the bridge so the user's intent is never silently changed to address 0.
        """
        bridge = self._require_connected()
        if bridge is None:
            return
        raw = self._label_addr_input.text().strip()
        if not raw:
            self._set_status("Refresh labels requires an address (e.g. 0x401000)")
            return
        addr = self._parse_address(raw)
        if addr is None:
            self._set_status(f"Refresh labels: invalid address '{raw}'")
            return
        run_bridge_coroutine_logged(
            bridge.get_labels(addr),
            on_success=self._apply_labels,
            on_error=lambda e: self._set_status(f"Refresh labels failed: {e}"),
            parent=self,
            event="ghidra_get_labels",
            logger=_logger,
            address=hex(addr),
        )

    def _apply_labels(self, result: object) -> None:
        """Apply label data to the labels table.

        Args:
            result: Label list from the bridge.
        """
        labels = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._labels_table.setRowCount(0)
        for lbl in labels:
            row = self._labels_table.rowCount()
            self._labels_table.insertRow(row)
            self._labels_table.setItem(row, 0, QTableWidgetItem(str(lbl.get("name", ""))))
            addr = int(cast("int", lbl.get("address", 0)))
            self._labels_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}"))
            self._labels_table.setItem(row, 2, QTableWidgetItem(str(lbl.get("type", ""))))

    def _selected_label_row(self) -> tuple[int, str] | None:
        """Read the address and name of the selected labels-table row.

        Returns:
            tuple[int, str] | None: A tuple of (address, name) for the
            currently selected row, or None if no row is selected or the
            address cell cannot be parsed.
        """
        row = self._labels_table.currentRow()
        if row < 0:
            self._set_status("Select a label row first")
            return None
        addr_item = self._labels_table.item(row, 1)
        name_item = self._labels_table.item(row, 0)
        addr = self._parse_address(addr_item.text()) if addr_item is not None else None
        if addr is None:
            self._set_status("Selected label row has an invalid address")
            return None
        name = name_item.text() if name_item is not None else ""
        return addr, name

    def _on_remove_label(self) -> None:
        """Remove the label selected in the labels table."""
        bridge = self._require_connected()
        if bridge is None:
            return
        selected = self._selected_label_row()
        if selected is None:
            return
        addr, name = selected
        run_bridge_coroutine_logged(
            bridge.remove_label(addr, name),
            on_success=lambda _: self._on_refresh_labels(),
            on_error=lambda e: self._set_status(f"Remove label failed: {e}"),
            parent=self,
            event="ghidra_remove_label",
            logger=_logger,
            level="info",
            address=hex(addr),
            name=name,
        )

    def _on_label_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with a Remove Label action for the labels table.

        Args:
            pos: Position where the right-click occurred, in table viewport coordinates.
        """
        item = self._labels_table.itemAt(pos)
        if item is None:
            return
        self._labels_table.setCurrentCell(item.row(), 0)

        menu = QMenu(self)
        remove_action = menu.addAction(self.tr("Remove Label"))
        if remove_action is None:
            return

        chosen = menu.exec(self._labels_table.mapToGlobal(pos))
        if chosen is remove_action:
            self._on_remove_label()

    def _on_create_bookmark(self) -> None:
        """Create a bookmark at the specified address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._bm_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for bookmark")
            return
        category = self._bm_category_input.text().strip()
        if not category:
            self._set_status("Bookmark category required")
            return
        comment = self._bm_comment_input.text().strip()
        bm_type = self._bm_type_combo.currentText()
        run_bridge_coroutine_logged(
            bridge.create_bookmark(addr, category, comment, bm_type),
            on_success=lambda _: self._on_refresh_bookmarks(),
            on_error=lambda e: self._set_status(f"Create bookmark failed: {e}"),
            parent=self,
            event="ghidra_create_bookmark",
            logger=_logger,
            level="info",
            address=hex(addr),
            category=category,
            bookmark_type=bm_type,
        )

    def _on_refresh_bookmarks(self) -> None:
        """Refresh the bookmarks table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_bookmarks(),
            on_success=self._apply_bookmarks,
            on_error=lambda e: self._set_status(f"Refresh bookmarks failed: {e}"),
            parent=self,
            event="ghidra_get_bookmarks",
            logger=_logger,
        )

    def _apply_bookmarks(self, result: object) -> None:
        """Apply bookmark data to the bookmarks table.

        Args:
            result: Bookmark list from the bridge.
        """
        bookmarks = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._bookmarks_table.setRowCount(0)
        for bm in bookmarks:
            row = self._bookmarks_table.rowCount()
            self._bookmarks_table.insertRow(row)
            addr = int(cast("int", bm.get("address", 0)))
            self._bookmarks_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._bookmarks_table.setItem(row, 1, QTableWidgetItem(str(bm.get("category", ""))))
            self._bookmarks_table.setItem(row, 2, QTableWidgetItem(str(bm.get("comment", ""))))
            self._bookmarks_table.setItem(row, 3, QTableWidgetItem(str(bm.get("type", ""))))

    def _selected_bookmark_row(self) -> tuple[int, str, str] | None:
        """Read the address, category, and type of the selected bookmarks-table row.

        Returns:
            tuple[int, str, str] | None: A tuple of (address, category, bookmark_type)
            for the currently selected row, or None if no row is selected or the
            address cell cannot be parsed.
        """
        row = self._bookmarks_table.currentRow()
        if row < 0:
            self._set_status("Select a bookmark row first")
            return None
        addr_item = self._bookmarks_table.item(row, 0)
        category_item = self._bookmarks_table.item(row, 1)
        type_item = self._bookmarks_table.item(row, 3)
        addr = self._parse_address(addr_item.text()) if addr_item is not None else None
        if addr is None:
            self._set_status("Selected bookmark row has an invalid address")
            return None
        category = category_item.text() if category_item is not None else ""
        bookmark_type = type_item.text() if type_item is not None else ""
        return addr, category, bookmark_type

    def _on_remove_bookmark(self) -> None:
        """Remove the bookmark selected in the bookmarks table."""
        bridge = self._require_connected()
        if bridge is None:
            return
        selected = self._selected_bookmark_row()
        if selected is None:
            return
        addr, category, bookmark_type = selected
        run_bridge_coroutine_logged(
            bridge.remove_bookmark(addr, category or None, bookmark_type or None),
            on_success=lambda _: self._on_refresh_bookmarks(),
            on_error=lambda e: self._set_status(f"Remove bookmark failed: {e}"),
            parent=self,
            event="ghidra_remove_bookmark",
            logger=_logger,
            level="info",
            address=hex(addr),
            category=category,
            bookmark_type=bookmark_type,
        )

    def _on_bookmark_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with a Remove Bookmark action for the bookmarks table.

        Args:
            pos: Position where the right-click occurred, in table viewport coordinates.
        """
        item = self._bookmarks_table.itemAt(pos)
        if item is None:
            return
        self._bookmarks_table.setCurrentCell(item.row(), 0)

        menu = QMenu(self)
        remove_action = menu.addAction(self.tr("Remove Bookmark"))
        if remove_action is None:
            return

        chosen = menu.exec(self._bookmarks_table.mapToGlobal(pos))
        if chosen is remove_action:
            self._on_remove_bookmark()

    # ------------------------------------------------------------------
    # Structures
    # ------------------------------------------------------------------

    def _on_add_struct_field(self) -> None:
        """Prompt user to add a field to the pending structure definition."""
        field_name, ok1 = QInputDialog.getText(self, self.tr("Add Field"), self.tr("Field name:"))
        if not ok1 or not field_name.strip():
            return
        field_type, ok2 = QInputDialog.getText(self, self.tr("Add Field"), self.tr("Field type:"))
        if not ok2 or not field_type.strip():
            return
        self._struct_fields_list.append((field_name.strip(), field_type.strip()))
        fields_str = ", ".join(f"{n}:{t}" for n, t in self._struct_fields_list)
        label_text = f"Fields: {fields_str}"
        self._struct_fields_label.setText(label_text)
        self._struct_fields_label.setToolTip(label_text)

    def _on_define_structure(self) -> None:
        """Define a new structure in Ghidra."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._struct_name_input.text().strip()
        if not name:
            self._set_status("Structure name required")
            return
        field_dicts: list[dict[str, object]] = [{"name": n, "type": t, "size": 0} for n, t in self._struct_fields_list]
        self._struct_fields_list.clear()
        self._struct_fields_label.setText("")
        self._struct_fields_label.setToolTip("")
        run_bridge_coroutine_logged(
            bridge.define_structure(name, field_dicts),
            on_success=lambda _: self._on_refresh_structures(),
            on_error=lambda e: self._set_status(f"Define structure failed: {e}"),
            parent=self,
            event="ghidra_define_structure",
            logger=_logger,
            level="info",
            name=name,
            field_count=len(field_dicts),
        )

    def _on_refresh_structures(self) -> None:
        """Refresh the structures table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_structures(),
            on_success=self._apply_structures,
            on_error=lambda e: self._set_status(f"Refresh structures failed: {e}"),
            parent=self,
            event="ghidra_get_structures",
            logger=_logger,
        )

    def _apply_structures(self, result: object) -> None:
        """Apply structure data to the structures table.

        Args:
            result: Structure list from the bridge.
        """
        structs = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._structs_table.setRowCount(0)
        for st in structs:
            row = self._structs_table.rowCount()
            self._structs_table.insertRow(row)
            self._structs_table.setItem(row, 0, QTableWidgetItem(str(st.get("name", ""))))
            self._structs_table.setItem(row, 1, QTableWidgetItem(str(st.get("size", 0))))
            field_count = int(cast("int", st.get("field_count", 0)))
            self._structs_table.setItem(row, 2, QTableWidgetItem(str(field_count)))
            self._structs_table.setItem(row, 3, QTableWidgetItem(str(st.get("path", ""))))

    def _on_apply_structure(self) -> None:
        """Apply a structure type at the specified address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._apply_struct_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for apply structure")
            return
        struct_name = self._apply_struct_name_input.text().strip()
        if not struct_name:
            self._set_status("Structure name required")
            return
        run_bridge_coroutine_logged(
            bridge.apply_structure_at(addr, struct_name),
            on_success=lambda _: self._set_status(f"Structure '{struct_name}' applied at 0x{addr:X}"),
            on_error=lambda e: self._set_status(f"Apply structure failed: {e}"),
            parent=self,
            event="ghidra_apply_structure_at",
            logger=_logger,
            level="info",
            address=hex(addr),
            structure_name=struct_name,
        )

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def _on_refresh_memory_map(self) -> None:
        """Refresh the memory map table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_memory_map(),
            on_success=self._apply_memory_map,
            on_error=lambda e: self._set_status(f"Refresh memory map failed: {e}"),
            parent=self,
            event="ghidra_get_memory_map",
            logger=_logger,
        )

    def _apply_memory_map(self, result: object) -> None:
        """Apply memory map data to the memory table.

        Args:
            result: Memory block list from the bridge.
        """
        blocks = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._memory_table.setRowCount(0)
        for blk in blocks:
            row = self._memory_table.rowCount()
            self._memory_table.insertRow(row)
            self._memory_table.setItem(row, 0, QTableWidgetItem(str(blk.get("name", ""))))
            start = int(cast("int", blk.get("start", 0)))
            end = int(cast("int", blk.get("end", 0)))
            size = int(cast("int", blk.get("size", 0)))
            self._memory_table.setItem(row, 1, QTableWidgetItem(f"0x{start:X}"))
            self._memory_table.setItem(row, 2, QTableWidgetItem(f"0x{end:X}"))
            self._memory_table.setItem(row, 3, QTableWidgetItem(str(size)))
            self._memory_table.setItem(row, 4, QTableWidgetItem("R" if blk.get("read", False) else ""))
            self._memory_table.setItem(row, 5, QTableWidgetItem("W" if blk.get("write", False) else ""))
            self._memory_table.setItem(row, 6, QTableWidgetItem("X" if blk.get("execute", False) else ""))
            self._memory_table.setItem(row, 7, QTableWidgetItem("I" if blk.get("initialized", False) else ""))

    def _on_read_bytes(self) -> None:
        """Read bytes from the specified address and display hex dump."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._read_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for read bytes")
            return
        length = self._read_len_spin.value()
        run_bridge_coroutine_logged(
            bridge.read_bytes(addr, length),
            on_success=self._apply_read_bytes,
            on_error=lambda e: self._set_status(f"Read bytes failed: {e}"),
            parent=self,
            event="ghidra_read_bytes",
            logger=_logger,
            address=hex(addr),
            length=length,
        )

    def _apply_read_bytes(self, result: object) -> None:
        """Apply read bytes result to the hex dump view.

        Args:
            result: Dict with 'hex', 'bytes', and 'address' keys from the bridge,
                or raw bytes/hex string.
        """
        if result is None:
            self._hex_dump_view.setPlainText("")
            return
        raw: bytes
        if isinstance(result, dict):
            rd = cast("dict[str, object]", result)
            byte_list = rd.get("bytes", [])
            if isinstance(byte_list, list):
                typed_bytes = cast("list[int]", byte_list)
                raw = bytes(typed_bytes)
            else:
                hex_str = str(rd.get("hex", ""))
                raw = bytes.fromhex(hex_str.replace(" ", "")) if hex_str else b""
        elif isinstance(result, (bytes, bytearray)):
            raw = bytes(result)
        else:
            raw = bytes.fromhex(str(result).replace(" ", ""))
        lines: list[str] = []
        for offset in range(0, len(raw), 16):
            chunk = raw[offset : offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if _ASCII_PRINTABLE_MIN <= b < _ASCII_PRINTABLE_MAX else "." for b in chunk)
            lines.append(f"{offset:08X}  {hex_part:<47s}  {ascii_part}")
        self._hex_dump_view.setPlainText("\n".join(lines))

    def _on_write_bytes(self) -> None:
        """Write hex bytes to the specified address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._write_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for write bytes")
            return
        hex_data = self._write_hex_input.text().strip()
        if not hex_data:
            self._set_status("Hex data required")
            return
        clean_hex = hex_data.replace(" ", "")
        try:
            bytes.fromhex(clean_hex)
        except ValueError:
            self._set_status("Invalid hex data")
            _logger.warning("ghidra_write_bytes_invalid_hex", input_text=hex_data, address=hex(addr))
            return
        binary_path = str(bridge.state.target_path) if bridge.state.target_path is not None else "unset"
        _logger.info(
            "ghidra_write_bytes_requested",
            binary_path=binary_path,
            address=hex(addr),
            byte_count=len(clean_hex) // 2,
        )
        run_bridge_coroutine_logged(
            bridge.write_bytes(addr, hex_data),
            on_success=lambda _: self._set_status(f"Wrote {len(clean_hex) // 2} byte(s) at 0x{addr:X}"),
            on_error=lambda e: self._set_status(f"Write bytes failed: {e}"),
            parent=self,
            event="ghidra_write_bytes",
            logger=_logger,
            level="info",
            address=hex(addr),
            byte_count=len(clean_hex) // 2,
        )

    def _on_create_memory_block(self) -> None:
        """Create a new memory block in the program."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._block_name_input.text().strip()
        if not name:
            self._set_status("Block name required")
            return
        start = self._parse_address(self._block_start_input.text())
        if start is None:
            self._set_status("Invalid start address for memory block")
            return
        size = self._block_size_spin.value()
        perms = self._block_perms_input.text().strip()
        run_bridge_coroutine_logged(
            bridge.create_memory_block(name, start, size, perms),
            on_success=lambda _: self._on_refresh_memory_map(),
            on_error=lambda e: self._set_status(f"Create memory block failed: {e}"),
            parent=self,
            event="ghidra_create_memory_block",
            logger=_logger,
            level="info",
            name=name,
            start=hex(start),
            size=size,
            permissions=perms,
        )

    def _on_remove_memory_block(self) -> None:
        """Remove a memory block from the program."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._block_remove_name_input.text().strip()
        if not name:
            self._set_status("Block name required for remove")
            return
        run_bridge_coroutine_logged(
            bridge.remove_memory_block(name),
            on_success=lambda _: self._on_refresh_memory_map(),
            on_error=lambda e: self._set_status(f"Remove memory block failed: {e}"),
            parent=self,
            event="ghidra_remove_memory_block",
            logger=_logger,
            level="info",
            name=name,
        )

    def _on_split_memory_block(self) -> None:
        """Split a memory block into two blocks at an address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._block_split_name_input.text().strip()
        if not name:
            self._set_status("Block name required for split")
            return
        split_address = self._parse_address(self._block_split_addr_input.text())
        if split_address is None:
            self._set_status("Invalid split address for memory block")
            return
        run_bridge_coroutine_logged(
            bridge.split_memory_block(name, split_address),
            on_success=lambda _: self._on_refresh_memory_map(),
            on_error=lambda e: self._set_status(f"Split memory block failed: {e}"),
            parent=self,
            event="ghidra_split_memory_block",
            logger=_logger,
            level="info",
            name=name,
            split_address=hex(split_address),
        )

    def _on_join_memory_blocks(self) -> None:
        """Join two contiguous memory blocks into one."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name1 = self._block_join_name1_input.text().strip()
        name2 = self._block_join_name2_input.text().strip()
        if not name1 or not name2:
            self._set_status("Both block names required for join")
            return
        run_bridge_coroutine_logged(
            bridge.join_memory_blocks(name1, name2),
            on_success=lambda _: self._on_refresh_memory_map(),
            on_error=lambda e: self._set_status(f"Join memory blocks failed: {e}"),
            parent=self,
            event="ghidra_join_memory_blocks",
            logger=_logger,
            level="info",
            name1=name1,
            name2=name2,
        )

    # ------------------------------------------------------------------
    # Segments / Program Info
    # ------------------------------------------------------------------

    def _on_refresh_segments(self) -> None:
        """Refresh the segments table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_segments(),
            on_success=self._apply_segments,
            on_error=lambda e: self._set_status(f"Refresh segments failed: {e}"),
            parent=self,
            event="ghidra_get_segments",
            logger=_logger,
        )

    def _apply_segments(self, result: object) -> None:
        """Apply segment data to the segments table.

        Args:
            result: Segment list from the bridge.
        """
        segments = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._segments_table.setRowCount(0)
        for seg in segments:
            row = self._segments_table.rowCount()
            self._segments_table.insertRow(row)
            self._segments_table.setItem(row, 0, QTableWidgetItem(str(seg.get("name", ""))))
            start = int(cast("int", seg.get("start", 0)))
            end = int(cast("int", seg.get("end", 0)))
            size = int(cast("int", seg.get("size", 0)))
            self._segments_table.setItem(row, 1, QTableWidgetItem(f"0x{start:X}"))
            self._segments_table.setItem(row, 2, QTableWidgetItem(f"0x{end:X}"))
            self._segments_table.setItem(row, 3, QTableWidgetItem(str(size)))
            self._segments_table.setItem(row, 4, QTableWidgetItem("R" if seg.get("read", False) else ""))
            self._segments_table.setItem(row, 5, QTableWidgetItem("W" if seg.get("write", False) else ""))
            self._segments_table.setItem(row, 6, QTableWidgetItem("X" if seg.get("execute", False) else ""))
            self._segments_table.setItem(row, 7, QTableWidgetItem(str(seg.get("type", ""))))
            self._segments_table.setItem(row, 8, QTableWidgetItem(str(seg.get("source_name", ""))))

    def _on_refresh_program_info(self) -> None:
        """Refresh program information from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_program_info(),
            on_success=self._apply_program_info,
            on_error=lambda e: self._set_status(f"Refresh program info failed: {e}"),
            parent=self,
            event="ghidra_get_program_info",
            logger=_logger,
        )

    def _apply_program_info(self, result: object) -> None:
        """Apply program info to the info table.

        Accepts either a plain ``dict`` or a dataclass instance; anything else
        is reported as an error row rather than silently serialising bound
        method references from ``dir()``.

        Args:
            result: Program info dict or dataclass from the bridge.
        """
        self._program_info_table.setRowCount(0)

        info: dict[str, object]
        if isinstance(result, dict):
            info = cast("dict[str, object]", result)
        elif dataclasses.is_dataclass(result) and not isinstance(result, type):
            info = dataclasses.asdict(result)
        else:
            self._program_info_table.insertRow(0)
            self._program_info_table.setItem(0, 0, QTableWidgetItem("error"))
            self._program_info_table.setItem(
                0,
                1,
                QTableWidgetItem(f"program_info returned unexpected type: {type(result).__name__}"),
            )
            self._set_status(f"Program info has unexpected shape: {type(result).__name__}")
            return

        for key, value in info.items():
            row = self._program_info_table.rowCount()
            self._program_info_table.insertRow(row)
            self._program_info_table.setItem(row, 0, QTableWidgetItem(str(key)))
            self._program_info_table.setItem(row, 1, QTableWidgetItem(str(value)))

    def _on_update_metadata(self) -> None:
        """Update program metadata (name and image base)."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._meta_name_input.text().strip() or None
        base_text = self._meta_base_input.text().strip()
        image_base = self._parse_address(base_text) if base_text else None
        if name is None and image_base is None:
            self._set_status("No metadata to update")
            return
        run_bridge_coroutine_logged(
            bridge.set_program_metadata(name=name, image_base=image_base),
            on_success=lambda _: self._set_status("Metadata updated"),
            on_error=lambda e: self._set_status(f"Update metadata failed: {e}"),
            parent=self,
            event="ghidra_set_program_metadata",
            logger=_logger,
            level="info",
            program_name=name,
            image_base=image_base,
        )

    # ------------------------------------------------------------------
    # Call Graph
    # ------------------------------------------------------------------

    def _on_build_call_graph(self) -> None:
        """Build a call graph for the address in the call graph tab."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._cg_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for call graph")
            return
        depth = self._cg_depth_spin.value()
        direction = self._cg_direction_combo.currentText()
        self._call_graph_tree.clear()
        run_bridge_coroutine_logged(
            bridge.get_call_tree(addr, direction=direction, depth=depth),
            on_success=self._apply_call_graph,
            on_error=lambda e: self._set_status(f"Build call graph failed: {e}"),
            parent=self,
            event="ghidra_get_call_tree",
            logger=_logger,
            address=hex(addr),
            direction=direction,
            depth=depth,
        )

    def _apply_call_graph(self, result: object) -> None:
        """Apply call graph data to the call graph tree.

        Args:
            result: Call graph data from the bridge.
        """
        self._call_graph_tree.clear()
        if result is None:
            return
        if isinstance(result, dict):
            self._populate_call_graph_dict(cast("dict[str, object]", result), None)
        elif isinstance(result, list):
            nodes = cast("list[dict[str, object]]", result)
            for node in nodes:
                node_name = str(node.get("name", "") or node.get("function", ""))
                node_addr = int(cast("int", node.get("address", 0)))
                item = QTreeWidgetItem([node_name, f"0x{node_addr:X}"])
                self._call_graph_tree.addTopLevelItem(item)

    def _populate_call_graph_dict(self, data: dict[str, object], parent: QTreeWidgetItem | None) -> None:
        """Recursively populate the call graph tree from a nested dict.

        Args:
            data: Node data dictionary with 'name', 'address', and optional 'children'.
            parent: Parent tree item, or None for root nodes.
        """
        name = str(data.get("name", "") or data.get("function", ""))
        addr = data.get("address", 0)
        addr_str = f"0x{addr:X}" if isinstance(addr, int) else str(addr)
        item = QTreeWidgetItem([name, addr_str])
        if parent is None:
            self._call_graph_tree.addTopLevelItem(item)
        else:
            tree_add_child(parent, item)
        children = data.get("children", data.get("callees", []))
        if isinstance(children, list):
            child_list = cast("list[object]", children)
            for child in child_list:
                if isinstance(child, dict):
                    self._populate_call_graph_dict(cast("dict[str, object]", child), item)

    def _on_show_callers(self) -> None:
        """Show callers for the address in the call graph tab."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._cg_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for callers")
            return
        run_bridge_coroutine_logged(
            bridge.get_callers(addr),
            on_success=self._apply_callers,
            on_error=lambda e: self._set_status(f"Get callers failed: {e}"),
            parent=self,
            event="ghidra_get_callers",
            logger=_logger,
            address=hex(addr),
        )

    def _apply_callers(self, result: object) -> None:
        """Apply callers data to the call graph tree.

        Args:
            result: Caller list from the bridge.
        """
        self._call_graph_tree.clear()
        callers = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        for caller in callers:
            caller_name = str(caller.get("caller_function", ""))
            caller_addr = int(cast("int", caller.get("caller_address", 0)))
            item = QTreeWidgetItem([caller_name, f"0x{caller_addr:X}"])
            self._call_graph_tree.addTopLevelItem(item)

    def _on_show_slice(self) -> None:
        """Show a program slice from the address in the call graph tab."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._cg_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for slice")
            return
        run_bridge_coroutine_logged(
            bridge.get_slice(addr),
            on_success=self._apply_slice,
            on_error=lambda e: self._set_status(f"Get slice failed: {e}"),
            parent=self,
            event="ghidra_get_slice",
            logger=_logger,
            address=hex(addr),
        )

    def _apply_slice(self, result: object) -> None:
        """Apply program slice data to the call graph tree.

        Args:
            result: Slice data from the bridge.
        """
        self._call_graph_tree.clear()
        if not isinstance(result, dict):
            return
        slice_data = cast("dict[str, object]", result)
        addrs_raw = slice_data.get("slice_addresses", [])
        addrs = cast("list[int]", addrs_raw) if isinstance(addrs_raw, list) else []
        for addr_val in addrs:
            addr_int = int(addr_val)
            item = QTreeWidgetItem([f"0x{addr_int:X}", f"0x{addr_int:X}"])
            self._call_graph_tree.addTopLevelItem(item)

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------

    def _on_add_comment(self) -> None:
        """Add a comment at the specified address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._cmt_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for comment")
            return
        cmt_type = self._cmt_type_combo.currentText()
        cmt_text = self._cmt_text_input.toPlainText().strip()
        if not cmt_text:
            self._set_status("Comment text required")
            return
        run_bridge_coroutine_logged(
            bridge.add_comment(addr, cmt_text, cmt_type),
            on_success=lambda _: self._set_status("Comment added"),
            on_error=lambda e: self._set_status(f"Add comment failed: {e}"),
            parent=self,
            event="ghidra_add_comment",
            logger=_logger,
            level="info",
            address=hex(addr),
            comment_type=cmt_type,
            comment_length=len(cmt_text),
        )

    def _on_refresh_comments(self) -> None:
        """Refresh comments for the address range from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._cmt_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for refresh comments")
            return
        run_bridge_coroutine_logged(
            bridge.get_comments(addr),
            on_success=self._apply_comments,
            on_error=lambda e: self._set_status(f"Refresh comments failed: {e}"),
            parent=self,
            event="ghidra_get_comments",
            logger=_logger,
            address=hex(addr),
        )

    def _on_load_all_comments(self) -> None:
        """Load every comment in the program in one RPC, batching the table update."""
        bridge = self._require_connected()
        if bridge is None:
            return
        self._load_all_cmt_btn.setEnabled(False)
        self._set_status("Loading all comments...")
        run_bridge_coroutine_logged(
            bridge.get_all_comments(),
            on_success=self._apply_all_comments_success,
            on_error=self._on_load_all_comments_error,
            parent=self,
            event="ghidra_get_all_comments",
            logger=_logger,
        )

    def _apply_all_comments_success(self, result: object) -> None:
        """Apply the bulk get_all_comments result, re-enabling the button when done.

        Args:
            result: Comment list from the bridge.
        """
        try:
            self._apply_comments(result)
            count = self._comments_table.rowCount()
            self._set_status(f"Loaded {count} comments")
        finally:
            self._load_all_cmt_btn.setEnabled(True)

    def _on_load_all_comments_error(self, exc: object) -> None:
        """Re-enable the button and surface a load_all_comments failure.

        Args:
            exc: Exception from the bridge call.
        """
        self._load_all_cmt_btn.setEnabled(True)
        self._set_status(f"Load all comments failed: {exc}")

    def _apply_comments(self, result: object) -> None:
        """Apply comment data to the comments table using a batched populate.

        Args:
            result: Comment list from the bridge.
        """
        comments = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._comments_table.setUpdatesEnabled(False)
        try:
            self._comments_table.setRowCount(len(comments))
            for row, cmt in enumerate(comments):
                addr = int(cast("int", cmt.get("address", 0)))
                self._comments_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
                self._comments_table.setItem(row, 1, QTableWidgetItem(str(cmt.get("type", ""))))
                self._comments_table.setItem(row, 2, QTableWidgetItem(str(cmt.get("comment", ""))))
        finally:
            self._comments_table.setUpdatesEnabled(True)

    # ------------------------------------------------------------------
    # Symbols / Namespaces / Equates / Relocations / External Functions
    # ------------------------------------------------------------------

    def _on_search_symbols(self) -> None:
        """Search symbols by name and optional type filter."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._sym_name_input.text().strip()
        sym_type = self._sym_type_combo.currentText() or None
        run_bridge_coroutine_logged(
            bridge.search_symbols(name, sym_type),
            on_success=self._apply_symbols,
            on_error=lambda e: self._set_status(f"Symbol search failed: {e}"),
            parent=self,
            event="ghidra_search_symbols",
            logger=_logger,
            symbol_name=name,
            symbol_type=sym_type,
        )

    def _apply_symbols(self, result: object) -> None:
        """Apply symbol search results to the symbols table.

        Args:
            result: Symbol list from the bridge.
        """
        symbols = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._symbols_table.setRowCount(0)
        for sym in symbols:
            row = self._symbols_table.rowCount()
            self._symbols_table.insertRow(row)
            self._symbols_table.setItem(row, 0, QTableWidgetItem(str(sym.get("name", ""))))
            addr = int(cast("int", sym.get("address", 0)))
            self._symbols_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}"))
            self._symbols_table.setItem(row, 2, QTableWidgetItem(str(sym.get("type", ""))))
            self._symbols_table.setItem(row, 3, QTableWidgetItem(str(sym.get("namespace", ""))))

    def _on_create_namespace(self) -> None:
        """Create a new namespace in Ghidra."""
        bridge = self._require_connected()
        if bridge is None:
            return
        name = self._ns_name_input.text().strip()
        if not name:
            self._set_status("Namespace name required")
            return
        parent = self._ns_parent_input.text().strip() or None
        run_bridge_coroutine_logged(
            bridge.create_namespace(name, parent),
            on_success=lambda _: self._on_refresh_namespaces(),
            on_error=lambda e: self._set_status(f"Create namespace failed: {e}"),
            parent=self,
            event="ghidra_create_namespace",
            logger=_logger,
            level="info",
            namespace_name=name,
            namespace_parent=parent,
        )

    def _on_refresh_namespaces(self) -> None:
        """Refresh the namespaces table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_namespaces(),
            on_success=self._apply_namespaces,
            on_error=lambda e: self._set_status(f"Refresh namespaces failed: {e}"),
            parent=self,
            event="ghidra_get_namespaces",
            logger=_logger,
        )

    def _apply_namespaces(self, result: object) -> None:
        """Apply namespace data to the namespaces table.

        Args:
            result: Namespace list from the bridge.
        """
        namespaces = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._namespaces_table.setRowCount(0)
        for ns in namespaces:
            row = self._namespaces_table.rowCount()
            self._namespaces_table.insertRow(row)
            self._namespaces_table.setItem(row, 0, QTableWidgetItem(str(ns.get("name", ""))))
            self._namespaces_table.setItem(row, 1, QTableWidgetItem(str(ns.get("path", ""))))

    def _on_create_equate(self) -> None:
        """Create a new equate in Ghidra."""
        bridge = self._require_connected()
        if bridge is None:
            return
        addr = self._parse_address(self._eq_addr_input.text())
        if addr is None:
            self._set_status("Invalid address for equate")
            return
        value_text = self._eq_value_input.text().strip()
        value = self._parse_address(value_text)
        if value is None:
            self._set_status("Invalid equate value")
            return
        name = self._eq_name_input.text().strip()
        if not name:
            self._set_status("Equate name required")
            return
        run_bridge_coroutine_logged(
            bridge.create_equate(addr, value, name),
            on_success=lambda _: self._on_refresh_equates(),
            on_error=lambda e: self._set_status(f"Create equate failed: {e}"),
            parent=self,
            event="ghidra_create_equate",
            logger=_logger,
            level="info",
            address=hex(addr),
            value=value,
            name=name,
        )

    def _on_refresh_equates(self) -> None:
        """Refresh the equates table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_equates(),
            on_success=self._apply_equates,
            on_error=lambda e: self._set_status(f"Refresh equates failed: {e}"),
            parent=self,
            event="ghidra_get_equates",
            logger=_logger,
        )

    def _apply_equates(self, result: object) -> None:
        """Apply equate data to the equates table.

        Args:
            result: Equate list from the bridge.
        """
        equates = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._equates_table.setRowCount(0)
        for eq in equates:
            row = self._equates_table.rowCount()
            self._equates_table.insertRow(row)
            self._equates_table.setItem(row, 0, QTableWidgetItem(str(eq.get("name", ""))))
            self._equates_table.setItem(row, 1, QTableWidgetItem(str(eq.get("value", 0))))
            ref_count = int(cast("int", eq.get("references", 0)))
            self._equates_table.setItem(row, 2, QTableWidgetItem(str(ref_count)))

    def _on_refresh_relocations(self) -> None:
        """Refresh the relocations table from bridge."""
        bridge = self._require_connected()
        if bridge is None:
            return
        run_bridge_coroutine_logged(
            bridge.get_relocations(),
            on_success=self._apply_relocations,
            on_error=lambda e: self._set_status(f"Refresh relocations failed: {e}"),
            parent=self,
            event="ghidra_get_relocations",
            logger=_logger,
        )

    def _apply_relocations(self, result: object) -> None:
        """Apply relocation data to the relocations table.

        Args:
            result: Relocation list from the bridge.
        """
        relocations = cast("list[dict[str, object]]", result) if isinstance(result, list) else []
        self._relocations_table.setRowCount(0)
        for rel in relocations:
            row = self._relocations_table.rowCount()
            self._relocations_table.insertRow(row)
            addr = int(cast("int", rel.get("address", 0)))
            self._relocations_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._relocations_table.setItem(row, 1, QTableWidgetItem(str(rel.get("type", ""))))
            self._relocations_table.setItem(row, 2, QTableWidgetItem(str(rel.get("symbol", ""))))

    def _on_add_external_function(self) -> None:
        """Add an external function reference to the program."""
        bridge = self._require_connected()
        if bridge is None:
            return
        library = self._ext_lib_input.text().strip()
        func_name = self._ext_func_input.text().strip()
        if not library or not func_name:
            self._set_status("Library and function name required")
            return
        addr_text = self._ext_addr_input.text().strip()
        addr = self._parse_address(addr_text) if addr_text else None
        run_bridge_coroutine_logged(
            bridge.add_external_function(library, func_name, addr),
            on_success=lambda _: self._set_status(f"External function '{library}::{func_name}' added"),
            on_error=lambda e: self._set_status(f"Add external function failed: {e}"),
            parent=self,
            event="ghidra_add_external_function",
            logger=_logger,
            level="info",
            library=library,
            function_name=func_name,
            address=hex(addr) if addr is not None else None,
        )

    # ------------------------------------------------------------------
    # Scripting
    # ------------------------------------------------------------------

    def _on_run_script(self) -> None:
        """Run the script in the editor without parameters."""
        bridge = self._require_connected()
        if bridge is None:
            return
        script = self._script_editor.toPlainText().strip()
        if not script:
            self._set_status("Script is empty")
            return
        self._run_script_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.execute_script(script),
            on_success=self._apply_script_result,
            on_error=self._on_script_error,
            parent=self,
            event="ghidra_execute_script",
            logger=_logger,
            level="info",
            script_size=len(script),
        )

    def _on_run_script_with_params(self) -> None:
        """Run the script in the editor with JSON parameters."""
        bridge = self._require_connected()
        if bridge is None:
            return
        script = self._script_editor.toPlainText().strip()
        if not script:
            self._set_status("Script is empty")
            return
        params_text = self._script_params_input.text().strip()
        try:
            params: dict[str, object] = json.loads(params_text) if params_text else {}
        except json.JSONDecodeError as exc:
            _logger.warning(
                "ghidra_run_script_invalid_json_params",
                input_text=params_text,
                error=str(exc),
            )
            self._set_status(f"Invalid JSON params: {exc}")
            return
        self._run_script_params_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.execute_script_with_params(script, params),
            on_success=self._apply_script_result,
            on_error=self._on_script_error,
            parent=self,
            event="ghidra_execute_script_with_params",
            logger=_logger,
            level="info",
            script_size=len(script),
            param_count=len(params),
        )

    def _apply_script_result(self, result: object) -> None:
        """Apply script execution result to the output view.

        Args:
            result: Script output string or object from the bridge.
        """
        self._run_script_btn.setEnabled(True)
        self._run_script_params_btn.setEnabled(True)
        self._script_output.setPlainText(str(result) if result is not None else "")
        self._set_status("Script executed")

    def _on_script_error(self, exc: object) -> None:
        """Handle script execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._run_script_btn.setEnabled(True)
        self._run_script_params_btn.setEnabled(True)
        self._script_output.setPlainText(f"Error: {exc}")
        self._set_status(f"Script failed: {exc}")
        _logger.warning("ghidra_script_failed", error=str(exc))

    def _on_apply_decompiler_options(self) -> None:
        """Apply decompiler configuration options."""
        bridge = self._require_connected()
        if bridge is None:
            return
        simplification = self._decomp_simplification_input.text().strip() or None
        max_instructions = self._decomp_max_inst_spin.value()
        run_bridge_coroutine_logged(
            bridge.set_decompiler_options(simplification=simplification, max_instructions=max_instructions),
            on_success=lambda _: self._set_status("Decompiler options applied"),
            on_error=lambda e: self._set_status(f"Decompiler options failed: {e}"),
            parent=self,
            event="ghidra_set_decompiler_options",
            logger=_logger,
            level="info",
            simplification=simplification,
            max_instructions=max_instructions,
        )

    def _on_configure_analysis(self) -> None:
        """Configure an analysis pass by name, optionally forwarding a JSON options blob."""
        bridge = self._require_connected()
        if bridge is None:
            return
        analyzer_name = self._analyzer_name_input.text().strip()
        if not analyzer_name:
            self._set_status("Analyzer name required")
            return
        enabled = self._analyzer_enabled_check.isChecked()

        options_text = self._analyzer_options_input.toPlainText().strip()
        options: dict[str, object] | None = None
        if options_text:
            try:
                parsed = json.loads(options_text)
            except json.JSONDecodeError as exc:
                _logger.warning(
                    "ghidra_configure_analysis_invalid_json",
                    input_text=options_text,
                    error=str(exc),
                    line=exc.lineno,
                    column=exc.colno,
                )
                self._set_status(f"Analyzer options JSON error: {exc.msg} (line {exc.lineno}, col {exc.colno})")
                return
            if not isinstance(parsed, dict):
                self._set_status("Analyzer options must be a JSON object")
                return
            options = cast("dict[str, object]", parsed)

        run_bridge_coroutine_logged(
            bridge.configure_analysis(analyzer_name, enabled=enabled, options=options),
            on_success=lambda _: self._set_status(
                f"Analyzer '{analyzer_name}' configured (enabled={enabled}, options_keys={list((options or {}).keys())})",
            ),
            on_error=lambda e: self._set_status(f"Configure analysis failed: {e}"),
            parent=self,
            event="ghidra_configure_analysis",
            logger=_logger,
            level="info",
            analyzer=analyzer_name,
            enabled=enabled,
        )
