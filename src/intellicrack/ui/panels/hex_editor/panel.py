# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Main HexEditorPanel class assembling all mixin functionality."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.hex_editor.base import (
    CURSOR_CONTEXT_BYTES,
    HASH_ALGORITHMS,
    PREVIEW_BYTES,
    HexDocumentEvent_cls,
    format_size,
    hexcore,
    hexcore_available,
)
from intellicrack.ui.panels.hex_editor.bookmarks import BookmarksMixin
from intellicrack.ui.panels.hex_editor.calculator import CalculatorMixin
from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin
from intellicrack.ui.panels.hex_editor.data_inspector import DataInspectorMixin
from intellicrack.ui.panels.hex_editor.disassembly import DisassemblyMixin
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin
from intellicrack.ui.panels.hex_editor.highlighting import HighlightingMixin
from intellicrack.ui.panels.hex_editor.patches import PatchesMixin
from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor.process_memory import ProcessMemoryMixin
from intellicrack.ui.panels.hex_editor.sandbox import SandboxMixin
from intellicrack.ui.panels.hex_editor.scripting import ScriptingMixin
from intellicrack.ui.panels.hex_editor.search import SearchMixin
from intellicrack.ui.panels.hex_editor.sections import SectionsMixin
from intellicrack.ui.panels.hex_editor.signatures import SignaturesMixin
from intellicrack.ui.panels.hex_editor.statistics import StatisticsMixin
from intellicrack.ui.panels.hex_editor.templates import TemplatesMixin
from intellicrack.ui.panels.hex_editor.transforms import TransformsMixin
from intellicrack.ui.panels.hex_editor.widgets import (
    ByteDistributionWidget,
    EntropyGraphWidget,
)
from intellicrack.ui.panels.hex_editor.yara import YaraMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


_logger = get_logger(__name__)


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.bridges.hex_editor import HexEditorBridge
    from intellicrack.bridges.hex_state import HexDocumentState
    from intellicrack.core.hexpat.completer import HexPatCompleter
    from intellicrack.ui.panels.async_bridge import GenericCallableWorker
    from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor

_MODE_LABEL_WIDTH: Final[int] = 30
_SEARCH_MODE_WIDTH: Final[int] = 80
_ENCODING_COMBO_WIDTH: Final[int] = 120
_LOG_BTN_WIDTH: Final[int] = 70
_ZERO_MARGIN: Final[int] = 0
_STATS_MARGIN: Final[int] = 2
_STATS_SPACING: Final[int] = 4
_HASH_MARGIN: Final[int] = 4
_HASH_SPACING: Final[int] = 6


class HexEditorPanel(
    DataInspectorMixin,
    SearchMixin,
    StatisticsMixin,
    HashingMixin,
    DisassemblyMixin,
    YaraMixin,
    TransformsMixin,
    PatternEditorMixin,
    BookmarksMixin,
    PatchesMixin,
    SectionsMixin,
    TemplatesMixin,
    CalculatorMixin,
    ScriptingMixin,
    SignaturesMixin,
    HighlightingMixin,
    SandboxMixin,
    ComparisonMixin,
    ProcessMemoryMixin,
    AnalysisPanelBase,
):
    """Hex editor panel with integrated side panels.

    Combines the custom HexEditorWidget with data inspector,
    bookmarks, sections, imports, exports, strings, statistics,
    and template panels in a split layout.

    Attributes:
        context_push_requested: Signal emitted with context dict when hex data is pushed to AI chat.
    """

    context_push_requested: pyqtSignal = pyqtSignal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HexEditorPanel widget.

        Args:
            parent: Parent widget.
        """
        self._hex_widget: Any | None = None
        self.document: Any | None = None
        self.file_path: Path | None = None

        self._data_inspector_tree: QTreeWidget | None = None
        self._bookmarks_tree: QTreeWidget | None = None
        self.sections_tree: QTreeWidget | None = None
        self._imports_tree: QTreeWidget | None = None
        self._exports_tree: QTreeWidget | None = None
        self._strings_tree: QTreeWidget | None = None
        self._statistics_tree: QTreeWidget | None = None
        self._templates_tree: QTreeWidget | None = None
        self._template_combo: QComboBox | None = None
        self._patches_tree: QTreeWidget | None = None
        self._search_input: QLineEdit | None = None
        self._search_mode_combo: QComboBox | None = None
        self._offset_input: QLineEdit | None = None
        self._mode_label: QLabel | None = None
        self._file_info_label: QLabel | None = None
        self._encoding_combo: QComboBox | None = None
        self._undo_btn: QPushButton | None = None
        self._redo_btn: QPushButton | None = None
        self._side_tabs: QTabWidget | None = None

        self._search_results: list[tuple[int, int]] = []
        self._search_index: int = 0
        self._original_data_cache: dict[int, int] = {}
        self.state_holder: HexDocumentState | None = None
        self._bridge: HexEditorBridge | None = None
        self._find_next_btn: QPushButton | None = None
        self._find_prev_btn: QPushButton | None = None
        self._state_callback: Any | None = None
        self._search_status_label: QLabel | None = None
        self._selection_start: int = -1
        self._selection_end: int = -1

        self._pattern_frame: QFrame | None = None
        self._pattern_dsl_editor: PatternCodeEditor | None = None
        self._pattern_completer: HexPatCompleter | None = None
        self._pattern_json_preview: QPlainTextEdit | None = None
        self._pattern_library_tree: QTreeWidget | None = None
        self._pattern_error_display: QPlainTextEdit | None = None
        self._pattern_print_output: QPlainTextEdit | None = None
        self._pattern_status_label: QLabel | None = None
        self._pattern_visible: bool = False
        self._compiled_json: str = ""
        self._main_vsplit: QSplitter | None = None
        self._interpreter: Any | None = None
        self._pattern_registry: Any | None = None

        self._disasm_arch_combo: QComboBox | None = None
        self._disasm_mode_combo: QComboBox | None = None
        self._disasm_count_spin: QSpinBox | None = None
        self._disasm_follow_cursor: QCheckBox | None = None
        self._disasm_table: QTableWidget | None = None

        self._yara_rule_files: list[str] = []
        self._yara_file_count_label: QLabel | None = None
        self._yara_inline_editor: QPlainTextEdit | None = None
        self._yara_results_tree: QTreeWidget | None = None

        self._transform_node_combo: QComboBox | None = None
        self._transform_params_form: QFormLayout | None = None
        self._transform_params_widget: QWidget | None = None
        self._transform_preview_pane: QPlainTextEdit | None = None
        self._transform_pipeline_list: QListWidget | None = None
        self._transform_pipeline: Any = None
        self._transform_nodes_cache: list[Any] = []

        self._entropy_graph: EntropyGraphWidget | None = None
        self._byte_dist_widget: ByteDistributionWidget | None = None
        self._entropy_label: QLabel | None = None
        self._null_pct_label: QLabel | None = None
        self._printable_pct_label: QLabel | None = None
        self._control_pct_label: QLabel | None = None
        self._high_pct_label: QLabel | None = None
        self._classification_label: QLabel | None = None
        self._statistics_worker: GenericCallableWorker | None = None
        self._search_worker: GenericCallableWorker | None = None
        self._numeric_search_worker: GenericCallableWorker | None = None
        self._hash_algo_combo: QComboBox | None = None
        self._hash_result_label: QLabel | None = None
        self._numeric_search_frame: QFrame | None = None
        self._numeric_value_input: QLineEdit | None = None
        self._numeric_size_combo: QComboBox | None = None
        self._numeric_type_combo: QComboBox | None = None
        self._numeric_endian_combo: QComboBox | None = None
        self._numeric_align_spin: QSpinBox | None = None
        self._numeric_range_check: QCheckBox | None = None
        self._numeric_max_input: QLineEdit | None = None

        self._display_mode_combo: QComboBox | None = None
        self._alignment_combo: QComboBox | None = None
        self._color_mode_combo: QComboBox | None = None
        self._arith_op_combo: QComboBox | None = None
        self._arith_key_edit: QLineEdit | None = None
        self._arith_count_spin: QSpinBox | None = None

        super().__init__(parent)

    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add hex editor controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._add_tool_button(toolbar, "Open", self._on_open_file)
        self._add_secondary_button(toolbar, "Save", self._on_save)
        self._add_secondary_button(toolbar, "Save As", self._on_save_as)
        toolbar.addSeparator()

        self._mode_label = QLabel("OVR")
        self._mode_label.setFixedWidth(_MODE_LABEL_WIDTH)
        toolbar.addWidget(self._mode_label)
        toolbar.addSeparator()

        self._offset_input = self._add_toolbar_input(toolbar, "Offset (hex)", max_width=100)
        self._add_secondary_button(toolbar, "Go", self._on_goto_offset)
        toolbar.addSeparator()

        self._search_input = self._add_toolbar_input(toolbar, "Search...", max_width=180)

        self._search_mode_combo = QComboBox()
        self._search_mode_combo.addItems(["Hex", "Text", "Regex", "Numeric"])
        self._search_mode_combo.setFixedWidth(_SEARCH_MODE_WIDTH)
        toolbar.addWidget(self._search_mode_combo)

        self._add_secondary_button(toolbar, "Find", self._on_search)
        self._find_next_btn = self._add_secondary_button(toolbar, "Next", self._on_find_next)
        self._find_prev_btn = self._add_secondary_button(toolbar, "Prev", self._on_find_prev)
        self._search_status_label = QLabel("")
        self._search_status_label.setObjectName("search_status_label")
        toolbar.addWidget(self._search_status_label)
        toolbar.addSeparator()

        self._undo_btn = self._add_secondary_button(toolbar, "Undo", self._on_undo)
        self._redo_btn = self._add_secondary_button(toolbar, "Redo", self._on_redo)
        toolbar.addSeparator()

        self._encoding_combo = QComboBox()
        self._encoding_combo.setFixedWidth(_ENCODING_COMBO_WIDTH)
        self._populate_toolbar_encoding_combo(self._encoding_combo)
        toolbar.addWidget(self._encoding_combo)

        self._add_secondary_button(toolbar, "Send to AI", self._on_send_to_ai)
        toolbar.addSeparator()
        self._add_secondary_button(toolbar, "Pattern Editor", self._toggle_pattern_editor)
        toolbar.addSeparator()

        self._display_mode_combo = QComboBox()
        self._display_mode_combo.addItems(HexEditorWidget.DISPLAY_MODES)
        self._display_mode_combo.setToolTip("Display mode")
        self._display_mode_combo.currentTextChanged.connect(self._on_display_mode_changed)
        toolbar.addWidget(self._display_mode_combo)

        copy_as_btn = QPushButton("Copy As")
        copy_as_menu_obj = self._build_copy_as_menu()
        set_menu_fn = getattr(copy_as_btn, "setMenu", None)
        if callable(set_menu_fn):
            set_menu_fn(copy_as_menu_obj)
        toolbar.addWidget(copy_as_btn)

        self._alignment_combo = QComboBox()
        self._alignment_combo.addItems(["No Align", "512 (Sector)", "4096 (Page)", "8192", "65536"])
        self._alignment_combo.setToolTip("Alignment grid")
        self._alignment_combo.currentTextChanged.connect(self._on_alignment_changed)
        toolbar.addWidget(self._alignment_combo)

        snap_btn = QPushButton("Snap")
        snap_btn.setToolTip("Snap cursor to alignment boundary")
        snap_btn.clicked.connect(self._on_snap_alignment)
        toolbar.addWidget(snap_btn)

        self._color_mode_combo = QComboBox()
        self._color_mode_combo.addItems(["No Coloring", "Entropy Heatmap", "Byte Value", "Content Type"])
        self._color_mode_combo.setToolTip("Color mapping mode")
        self._color_mode_combo.currentTextChanged.connect(self._on_color_mode_changed)
        toolbar.addWidget(self._color_mode_combo)

        self._add_secondary_button(toolbar, "Process...", self._on_open_process_memory)

        self._file_info_label = QLabel("")
        toolbar.addWidget(self._file_info_label)

    def _create_content(self) -> QWidget:
        """Create the main content with hex widget, side panels, and pattern editor.

        Returns:
            QWidget: Vertical splitter containing hex editor area and pattern editor.
        """
        self._main_vsplit = QSplitter(Qt.Orientation.Vertical)

        hsplit = QSplitter(Qt.Orientation.Horizontal)

        self._hex_widget = HexEditorWidget()
        self._hex_widget.cursor_moved.connect(self._on_cursor_moved)
        self._hex_widget.data_changed.connect(self._on_data_changed)
        self._hex_widget.edit_mode_changed.connect(self._on_edit_mode_changed)
        self._hex_widget.about_to_modify.connect(self._cache_original_byte)
        self._hex_widget.selection_changed.connect(self._on_selection_changed)
        if self._encoding_combo is not None:
            self._encoding_combo.currentTextChanged.connect(self._on_encoding_changed)
        hsplit.addWidget(self._hex_widget)

        self._side_tabs = QTabWidget()
        self._build_side_panels()
        hsplit.addWidget(self._side_tabs)

        hsplit.setStretchFactor(0, 3)
        hsplit.setStretchFactor(1, 1)

        self._main_vsplit.addWidget(hsplit)

        self._pattern_frame = self._build_pattern_editor()
        self._pattern_frame.setVisible(False)
        self._main_vsplit.addWidget(self._pattern_frame)

        self._numeric_search_frame = self._build_numeric_search_panel()
        self._numeric_search_frame.setVisible(False)
        self._main_vsplit.addWidget(self._numeric_search_frame)

        if self._search_mode_combo is not None:
            self._search_mode_combo.currentTextChanged.connect(self._on_search_mode_changed)

        self._setup_search_signals()
        self._setup_shortcuts()

        return self._main_vsplit

    def _setup_shortcuts(self) -> None:
        """Configure keyboard shortcuts for the hex editor panel."""
        sc_find = QShortcut(QKeySequence("Ctrl+F"), self)
        sc_find.activated.connect(self._focus_search)
        sc_goto = QShortcut(QKeySequence("Ctrl+G"), self)
        sc_goto.activated.connect(self._focus_goto)
        sc_save = QShortcut(QKeySequence("Ctrl+S"), self)
        sc_save.activated.connect(self._on_save)
        sc_find_next = QShortcut(QKeySequence("F3"), self)
        sc_find_next.activated.connect(self._on_find_next)
        sc_find_prev = QShortcut(QKeySequence("Shift+F3"), self)
        sc_find_prev.activated.connect(self._on_find_prev)
        sc_pattern = QShortcut(QKeySequence("Ctrl+Shift+P"), self)
        sc_pattern.activated.connect(self._toggle_pattern_editor)
        sc_compile = QShortcut(QKeySequence("Ctrl+Shift+B"), self)
        sc_compile.activated.connect(self._on_pattern_compile)
        sc_apply_pattern = QShortcut(QKeySequence("Ctrl+Shift+Return"), self)
        sc_apply_pattern.activated.connect(self._on_pattern_apply)

    def _focus_search(self) -> None:
        """Focus the search input field."""
        if self._search_input is not None:
            self._search_input.setFocus()
            self._search_input.selectAll()

    def _focus_goto(self) -> None:
        """Focus the goto-offset input field."""
        if self._offset_input is not None:
            self._offset_input.setFocus()
            self._offset_input.selectAll()

    def _build_side_panels(self) -> None:
        """Create all side panel tabs."""
        if self._side_tabs is None:
            return

        self._side_tabs.addTab(self._build_inspector_tab(), "Inspector")
        self._side_tabs.addTab(self._build_bookmarks_tab(), "Bookmarks")

        self.sections_tree = self._make_tree(["Name", "VAddr", "VSize", "RawSize"])
        self._side_tabs.addTab(self.sections_tree, "Sections")

        self._imports_tree = self._make_tree(["Library", "Function", "Address"])
        self._side_tabs.addTab(self._imports_tree, "Imports")

        self._exports_tree = self._make_tree(["Name", "Address", "Ordinal"])
        self._side_tabs.addTab(self._exports_tree, "Exports")

        self._strings_tree = self._make_tree(["Offset", "Length", "String"])
        self._strings_tree.itemDoubleClicked.connect(self._on_string_double_clicked)
        self._side_tabs.addTab(self._strings_tree, "Strings")

        self._side_tabs.addTab(self._build_statistics_tab(), "Statistics")
        self._side_tabs.addTab(self._build_templates_tab(), "Templates")
        self._side_tabs.addTab(self._build_patches_tab(), "Patches")
        self._side_tabs.addTab(self._build_hashes_tab(), "Hashes")

        self._side_tabs.addTab(self._create_disassembly_tab(), "Disassembly")
        self._side_tabs.addTab(self._create_yara_tab(), "YARA")
        self._side_tabs.addTab(self._create_transforms_tab(), "Transforms")
        self._side_tabs.addTab(self._create_calculator_tab(), "Calculator")
        self._side_tabs.addTab(self._create_scripting_tab(), "Python")
        self._side_tabs.addTab(self._create_signatures_tab(), "Signatures")
        self._side_tabs.addTab(self._create_sandbox_tab(), "Sandbox")
        self._side_tabs.addTab(self._create_comparison_tab(), "Diff")

    def _build_inspector_tab(self) -> QWidget:
        """Build the inspector side-tab widget.

        Creates the data-inspector tree alongside the bit editor, text
        decoder and highlighting controls used for inspecting bytes at the
        cursor position.

        Returns:
            QWidget: Container widget for the inspector tab.
        """
        inspector_container = QWidget()
        insp_layout = QVBoxLayout(inspector_container)
        insp_layout.setContentsMargins(_ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN)
        self._data_inspector_tree = self._make_tree(["Type", "Value"])
        insp_layout.addWidget(self._data_inspector_tree)
        insp_layout.addWidget(self._create_bit_editor_group())
        insp_layout.addWidget(self._create_text_decode_group())
        insp_layout.addWidget(self._create_highlighting_controls())
        return inspector_container

    def _build_bookmarks_tab(self) -> QWidget:
        """Build the bookmarks side-tab widget.

        Creates the bookmarks tree and its add / remove action buttons.

        Returns:
            QWidget: Container widget for the bookmarks tab.
        """
        bookmarks_container = QWidget()
        bm_layout = QVBoxLayout(bookmarks_container)
        bm_layout.setContentsMargins(_ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN)
        self._bookmarks_tree = self._make_tree(["Offset", "Length", "Label"])
        bm_layout.addWidget(self._bookmarks_tree)
        bm_btn_layout = QHBoxLayout()
        add_bm_btn = QPushButton("Add")
        add_bm_btn.clicked.connect(self._on_add_bookmark)
        bm_btn_layout.addWidget(add_bm_btn)
        rm_bm_btn = QPushButton("Remove")
        rm_bm_btn.clicked.connect(self._on_remove_bookmark)
        bm_btn_layout.addWidget(rm_bm_btn)
        bm_layout.addLayout(bm_btn_layout)
        return bookmarks_container

    def _build_statistics_tab(self) -> QWidget:
        """Build the statistics side-tab widget.

        Creates the entropy graph, byte distribution widget, summary box,
        byte-frequency tree, and the refresh / digram-matrix action row.

        Returns:
            QWidget: Container widget for the statistics tab.
        """
        stats_container = QWidget()
        stats_layout = QVBoxLayout(stats_container)
        stats_layout.setContentsMargins(_STATS_MARGIN, _STATS_MARGIN, _STATS_MARGIN, _STATS_MARGIN)
        stats_layout.setSpacing(_STATS_SPACING)
        self._entropy_graph = EntropyGraphWidget()
        self._entropy_graph.block_clicked.connect(self.goto_offset)
        stats_layout.addWidget(self._entropy_graph)
        stats_layout.addLayout(self._build_byte_distribution_header())
        stats_layout.addWidget(self._byte_dist_widget)
        stats_layout.addWidget(self._build_statistics_summary_box())
        self._statistics_tree = self._make_tree(["Byte", "Count", "Percentage"])
        stats_layout.addWidget(self._statistics_tree)
        stats_btn_row = QHBoxLayout()
        stats_refresh_btn = QPushButton("Refresh")
        stats_refresh_btn.clicked.connect(self._on_refresh_statistics)
        stats_btn_row.addWidget(stats_refresh_btn)
        stats_digram_btn = QPushButton("Digram Matrix")
        stats_digram_btn.clicked.connect(self._on_show_digram_matrix)
        stats_btn_row.addWidget(stats_digram_btn)
        stats_layout.addLayout(stats_btn_row)
        return stats_container

    def _build_byte_distribution_header(self) -> QHBoxLayout:
        """Build the byte-distribution header row with a log-scale toggle.

        Initialises :attr:`_byte_dist_widget` as a side effect so the
        statistics tab can lay it out directly underneath the header row.

        Returns:
            QHBoxLayout: Header layout containing the label and toggle button.
        """
        dist_header = QHBoxLayout()
        dist_header.addWidget(QLabel("Byte Distribution"))
        log_btn = QPushButton("Log Scale")
        log_btn.setFixedWidth(_LOG_BTN_WIDTH)
        log_btn.setCheckable(True)
        self._byte_dist_widget = ByteDistributionWidget()
        dist_ref = self._byte_dist_widget

        def _on_log_toggled() -> None:
            dist_ref.toggle_log_scale()

        def _log_toggled_slot(_checked: int) -> None:
            _on_log_toggled()

        log_btn.toggled.connect(_log_toggled_slot)
        dist_header.addWidget(log_btn)
        return dist_header

    def _build_statistics_summary_box(self) -> QGroupBox:
        """Build the statistics-summary group box.

        Creates labels for overall entropy, null/printable/control/high
        byte percentages, and the classification descriptor.

        Returns:
            QGroupBox: Group box containing the populated summary form.
        """
        summary_box = QGroupBox("Summary")
        summary_form = QFormLayout(summary_box)
        self._entropy_label = QLabel("\u2014")
        summary_form.addRow("Overall entropy:", self._entropy_label)
        self._null_pct_label = QLabel("\u2014")
        summary_form.addRow("Null bytes:", self._null_pct_label)
        self._printable_pct_label = QLabel("\u2014")
        summary_form.addRow("Printable:", self._printable_pct_label)
        self._control_pct_label = QLabel("\u2014")
        summary_form.addRow("Control:", self._control_pct_label)
        self._high_pct_label = QLabel("\u2014")
        summary_form.addRow("High bytes:", self._high_pct_label)
        self._classification_label = QLabel("\u2014")
        summary_form.addRow("Classification:", self._classification_label)
        return summary_box

    def _build_templates_tab(self) -> QWidget:
        """Build the templates side-tab widget.

        Creates the templates combo box, apply / import / export / remove
        action buttons, auto-bookmark button, and the templates tree.

        Returns:
            QWidget: Container widget for the templates tab.
        """
        templates_container = QWidget()
        tmpl_layout = QVBoxLayout(templates_container)
        tmpl_layout.setContentsMargins(_ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN)
        tmpl_top = QHBoxLayout()
        self._template_combo = QComboBox()
        tmpl_top.addWidget(self._template_combo)
        tmpl_apply_btn = QPushButton("Apply")
        tmpl_apply_btn.clicked.connect(self._on_apply_template)
        tmpl_top.addWidget(tmpl_apply_btn)
        tmpl_layout.addLayout(tmpl_top)
        tmpl_btn_row = QHBoxLayout()
        tmpl_import_btn = QPushButton("Import JSON...")
        tmpl_import_btn.clicked.connect(self._on_import_template)
        tmpl_btn_row.addWidget(tmpl_import_btn)
        tmpl_export_btn = QPushButton("Export...")
        tmpl_export_btn.clicked.connect(self._on_export_template)
        tmpl_btn_row.addWidget(tmpl_export_btn)
        tmpl_remove_btn = QPushButton("Remove")
        tmpl_remove_btn.clicked.connect(self._on_remove_template)
        tmpl_btn_row.addWidget(tmpl_remove_btn)
        tmpl_layout.addLayout(tmpl_btn_row)
        tmpl_auto_bm_btn = QPushButton("Auto-Bookmark Structure")
        tmpl_auto_bm_btn.clicked.connect(self._on_auto_bookmark_structure)
        tmpl_layout.addWidget(tmpl_auto_bm_btn)
        self._templates_tree = self._make_tree(["Field", "Offset", "Size", "Value"])
        tmpl_layout.addWidget(self._templates_tree)
        return templates_container

    def _build_patches_tab(self) -> QWidget:
        """Build the patches side-tab widget.

        Creates the patches tree and the import / export action buttons.

        Returns:
            QWidget: Container widget for the patches tab.
        """
        patches_container = QWidget()
        patches_layout = QVBoxLayout(patches_container)
        patches_layout.setContentsMargins(_ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN, _ZERO_MARGIN)
        self._patches_tree = self._make_tree(["Offset", "Original", "New"])
        patches_layout.addWidget(self._patches_tree)
        patches_btn_layout = QHBoxLayout()
        export_patches_btn = QPushButton("Export Patches...")
        export_patches_btn.clicked.connect(self._on_export_patches)
        patches_btn_layout.addWidget(export_patches_btn)
        import_patches_btn = QPushButton("Import Patches...")
        import_patches_btn.clicked.connect(self._on_import_patches)
        patches_btn_layout.addWidget(import_patches_btn)
        patches_layout.addLayout(patches_btn_layout)
        return patches_container

    def _build_hashes_tab(self) -> QWidget:
        """Build the hashes side-tab widget.

        Creates the hash algorithm combo, calculate / custom CRC buttons,
        result display, selection-hashing button, and embeds the PE
        checksum group widget.

        Returns:
            QWidget: Container widget for the hashes tab.
        """
        hashes_container = QWidget()
        hashes_layout = QVBoxLayout(hashes_container)
        hashes_layout.setContentsMargins(_HASH_MARGIN, _HASH_MARGIN, _HASH_MARGIN, _HASH_MARGIN)
        hashes_layout.setSpacing(_HASH_SPACING)
        hash_row = QHBoxLayout()
        self._hash_algo_combo = QComboBox()
        self._hash_algo_combo.addItems(HASH_ALGORITHMS)
        hash_row.addWidget(self._hash_algo_combo)
        hash_calc_btn = QPushButton("Calculate")
        hash_calc_btn.clicked.connect(self._on_calculate_hash)
        hash_row.addWidget(hash_calc_btn)
        custom_crc_btn = QPushButton("Custom CRC...")
        custom_crc_btn.clicked.connect(self._on_custom_crc)
        hash_row.addWidget(custom_crc_btn)
        hashes_layout.addLayout(hash_row)
        self._hash_result_label = QLabel("")
        self._hash_result_label.setWordWrap(True)
        self._hash_result_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hashes_layout.addWidget(self._hash_result_label)
        hash_sel_btn = QPushButton("Hash Selection")
        hash_sel_btn.clicked.connect(self._on_hash_selection)
        hashes_layout.addWidget(hash_sel_btn)
        hashes_layout.addWidget(self._create_pe_checksum_group())
        hashes_layout.addStretch()
        return hashes_container

    @staticmethod
    def _make_tree(headers: list[str]) -> QTreeWidget:
        """Create a QTreeWidget with the given column headers.

        Args:
            headers: Column header labels.

        Returns:
            QTreeWidget: Configured QTreeWidget.
        """
        tree = QTreeWidget()
        tree.setHeaderLabels(headers)
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        return tree

    def load_file(self, file_path: Path | str) -> bool:
        """Load a binary file into the hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            bool: True if the file was loaded successfully.
        """
        if not hexcore_available or hexcore is None:
            show_warning(
                self,
                "Hex Core Not Available",
                "The intellicrack_hexcore Rust extension is not installed.\n"
                "Build it with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path

        try:
            doc_len = self._load_file_impl(path)
        except OSError as exc:
            _logger.exception("file_load_failed", path=str(path))
            show_warning(self, "Load Failed", f"Failed to open file:\n{exc}")
            return False
        if doc_len is None:
            return False
        _logger.info("file_loaded", path=str(path), size=doc_len)
        return True

    def _load_file_impl(self, path: Path) -> int | None:
        """Open ``path`` through hexcore and refresh all derived panels.

        Args:
            path: Filesystem path to load.

        Returns:
            int | None: Length of the loaded document in bytes, or ``None`` if
                the hexcore document could not be opened.
        """
        if hexcore is None:
            return None
        self.document = hexcore.HexDocument.open(str(path))
        self.file_path = path

        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(self.document)

        if self.document is None:
            return None
        doc_len: int = self.document.length()
        if self._file_info_label is not None:
            self._file_info_label.setText(f"  {path.name} ({format_size(doc_len)})")

        self._populate_template_combo()
        if self._encoding_combo is not None:
            self._encoding_combo.setCurrentIndex(0)
        self._auto_detect_file_type()
        self._populate_sections()
        self._populate_imports()
        self._populate_exports()
        self._populate_strings()
        self._update_statistics()
        self._original_data_cache.clear()
        self._search_results.clear()
        self._search_index = 0

        if self.state_holder is not None:
            self.state_holder.set_document(self.document, path, source="panel")

        return doc_len

    def _on_open_file(self) -> None:
        """Open a file selection dialog and load the chosen file."""
        file_path_result = QFileDialog.getOpenFileName(
            self,
            "Open Binary File",
            "",
            "All Files (*)",
        )
        file_path_str = file_path_result[0] if file_path_result else ""
        if file_path_str:
            self.load_file(file_path_str)

    def _on_save(self) -> None:
        """Save the current document."""
        if self.document is None:
            return
        _logger.info("panel_save_started")
        try:
            file_path = self.document.file_path()
            if file_path is not None:
                self.document.save(file_path)
            else:
                self._on_save_as()
                return
        except OSError as exc:
            _logger.exception("panel_save_failed", file_path=str(self.document.file_path()) if self.document else None)
            show_warning(self, "Save Failed", f"Failed to save:\n{exc}")
        else:
            self._on_data_changed()
            if self.state_holder is not None and file_path is not None:
                self.state_holder.notify_document_saved(str(file_path), source="panel")
            _logger.info("file_saved", path=file_path)

    def _on_save_as(self) -> None:
        """Save the current document to a new path."""
        if self.document is None:
            return
        result = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        save_path = result[0] if result else ""
        if save_path:
            _logger.info("panel_save_as_started", path=save_path)
            try:
                self.document.save(save_path)
            except OSError as exc:
                _logger.exception("panel_save_as_failed", path=save_path)
                show_warning(self, "Save Failed", f"Failed to save:\n{exc}")
            else:
                self.file_path = Path(save_path)
                self._on_data_changed()
                if self.state_holder is not None:
                    self.state_holder.notify_document_saved(save_path, source="panel")
                _logger.info("file_saved_as", path=save_path)

    def _on_goto_offset(self) -> None:
        """Navigate to the offset entered in the toolbar input."""
        if self._offset_input is None or self._hex_widget is None:
            return
        text = self._offset_input.text().strip()
        if not text:
            return
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if not callable(goto_fn):
            return
        try:
            offset = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            _logger.warning("invalid_offset_input", text=text)
        else:
            goto_fn(offset)

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        _logger.info("panel_goto_offset", offset=offset)
        if self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def _on_cursor_moved(self, offset: int) -> None:
        """Handle cursor movement to update side panels.

        Args:
            offset: New cursor byte offset.
        """
        self._update_data_inspector(offset)
        self._on_cursor_moved_disasm(offset)

    def _on_data_changed(self) -> None:
        """Handle data modification events."""
        if self.document is not None and self._file_info_label is not None:
            modified_mark = " *" if self.document.is_modified() else ""
            name = self.file_path.name if self.file_path is not None else "untitled"
            size = self.document.length()
            self._file_info_label.setText(f"  {name}{modified_mark} ({format_size(size)})")
        self._update_patches()
        self.refresh_pattern_highlights()

    def _on_edit_mode_changed(self, mode: str) -> None:
        """Handle edit mode toggle.

        Args:
            mode: New mode string ("overwrite" or "insert").
        """
        if self._mode_label is not None:
            self._mode_label.setText("INS" if mode == "insert" else "OVR")

    def _on_send_to_ai(self) -> None:
        """Emit context for AI analysis from the current hex editor state."""
        if self.document is None:
            return

        context: dict[str, Any] = {
            "file_path": str(self.file_path) if self.file_path else None,
            "size": self.document.length(),
        }
        context["modified"] = self.document.is_modified()

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
        context["cursor"] = cursor_offset

        try:
            read_start = max(0, cursor_offset - CURSOR_CONTEXT_BYTES)
            read_len = min(PREVIEW_BYTES, self.document.length() - read_start)
            raw = self.document.read(read_start, read_len) if read_len > 0 else None
        except (AttributeError, ValueError):
            _logger.debug("ai_context_bytes_read_failed")
        else:
            if raw is not None:
                context["bytes_at_cursor"] = " ".join(f"{b:02X}" for b in raw)
                context["bytes_offset"] = read_start

        try:
            inspection = self.document.inspect_at(cursor_offset)
        except (AttributeError, ValueError):
            _logger.debug("ai_context_inspection_failed")
        else:
            if isinstance(inspection, dict):
                context["inspection"] = {k: str(v) for k, v in cast("dict[str, object]", inspection).items()}

        _logger.info(
            "ai_context_push_requested",
            cursor=cursor_offset,
            has_bytes="bytes_at_cursor" in context,
            has_inspection="inspection" in context,
        )
        self.context_push_requested.emit(context)

    def _on_undo(self) -> None:
        """Undo the last edit operation."""
        if self.document is not None:
            self.document.undo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def _on_redo(self) -> None:
        """Redo the last undone operation."""
        if self.document is not None:
            self.document.redo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def set_bridge(self, bridge: HexEditorBridge) -> None:
        """Attach a ``HexEditorBridge`` for RPC-backed transforms.

        Called by the tools-panel wiring layer once the registry's hex editor
        bridge instance is available.  Mixins (transforms, comparison, etc.)
        route async operations through this bridge instead of duplicating
        logic in pure Python.

        Args:
            bridge: ``HexEditorBridge`` instance supplied by the tool registry.
        """
        _logger.info("panel_bridge_attached", bridge_type=type(bridge).__name__)
        self._bridge = bridge

    def set_state_holder(self, state_holder: HexDocumentState) -> None:
        """Attach a shared state holder for bridge-GUI synchronization.

        Args:
            state_holder: The shared HexDocumentState instance.
        """
        _logger.info("panel_state_holder_attached", holder_type=type(state_holder).__name__)
        self.state_holder = state_holder

        def on_state_event(event_type: object, data: dict[str, Any]) -> None:
            evt = HexDocumentEvent_cls
            if evt is None:
                return
            if event_type == evt.DOCUMENT_OPENED:
                file_path_str = data.get("file_path")
                if file_path_str:
                    if self.document is not None:
                        self.document = None
                    self.load_file(file_path_str)
            elif event_type == evt.CURSOR_MOVED:
                offset = data.get("offset", 0)
                if self._hex_widget is not None:
                    goto_fn = getattr(self._hex_widget, "goto_offset", None)
                    if callable(goto_fn):
                        goto_fn(offset)
                self._update_data_inspector(offset)
            elif event_type == evt.DATA_MODIFIED:
                if self._hex_widget is not None:
                    update_fn = getattr(self._hex_widget, "_update_viewport", None)
                    if callable(update_fn):
                        update_fn()
                self._on_data_changed()
            elif event_type == evt.SELECTION_CHANGED:
                start = data.get("start", -1)
                end = data.get("end", -1)
                if self._hex_widget is not None and start >= 0 and end >= 0:
                    widget = self._hex_widget
                    set_sel_fn = getattr(widget, "set_selection_range", None)
                    if callable(set_sel_fn):
                        set_sel_fn(start, end)
                    update_fn = getattr(widget, "_update_viewport", None)
                    if callable(update_fn):
                        update_fn()
            elif event_type == evt.TEMPLATE_REGISTERED:
                self._populate_template_combo()
            elif event_type == evt.HIGHLIGHT_RULE_ADDED:
                rule = data.get("rule")
                if isinstance(rule, dict):
                    self._apply_bridge_highlight_rule_added(cast("dict[str, Any]", rule))
            elif event_type == evt.HIGHLIGHT_RULE_REMOVED:
                rule_id = data.get("rule_id")
                if isinstance(rule_id, str):
                    self._apply_bridge_highlight_rule_removed(rule_id)

        self._state_callback = on_state_event
        state_holder.register_callback(on_state_event, source_id="panel")

        if self._bridge is not None:
            run_bridge_coroutine_logged(
                self._bridge.list_highlight_rules(),
                on_success=self.seed_highlights_from_bridge,
                on_error=None,
                parent=self,
                event="hex_editor_list_highlight_rules",
                logger=_logger,
            )

    def _on_selection_changed(self, start: int, end: int) -> None:
        """Handle selection range changes from the hex widget.

        Updates the data inspector, hash display, and stored selection
        range for use by sub-panels.  Propagates the new selection to
        the shared state holder and bridge so AI tools and CLI callers
        see the current GUI selection rather than stale data.

        Args:
            start: Selection start offset.
            end: Selection end offset.
        """
        self._selection_start = start
        self._selection_end = end
        if start >= 0:
            self._update_data_inspector(start)
        if start >= 0 and end >= 0:
            if self.state_holder is not None:
                self.state_holder.set_selection(start, end, source="panel")
            if self._bridge is not None:
                self._bridge.update_selection_from_gui(start, end)
        else:
            if self.state_holder is not None:
                self.state_holder.clear_selection(source="panel")
            if self._bridge is not None:
                self._bridge.update_selection_from_gui(-1, -1)

    @staticmethod
    def _populate_toolbar_encoding_combo(combo: QComboBox) -> None:
        """Populate the toolbar encoding combo from the hexcore registry.

        Each entry uses the human-readable description as the display
        label and stores the hexcore codec name as the item's user data
        so the ASCII-column renderer receives a codec name that both the
        Rust backend and Python ``bytes.decode`` accept.

        Args:
            combo: The combo box to populate.
        """
        combo.clear()
        encodings: list[tuple[str, str]] = []
        if hexcore_available and hexcore is not None:
            try:
                encodings = list(hexcore.HexDocument.list_encodings())
            except (AttributeError, TypeError, ValueError):
                _logger.exception("toolbar_list_encodings_failed")
                encodings = []
        if not encodings:
            encodings = [("utf-8", "UTF-8"), ("ascii", "ASCII (7-bit)")]
        for name, description in encodings:
            combo.addItem(description, userData=name)

    def _on_encoding_changed(self, _text: str) -> None:
        """Handle encoding combo box selection changes.

        Reads the hexcore codec name from the selected item's user data
        and forwards it unmodified to the hex widget so the ASCII column
        uses a codec name supported by the backend.

        Args:
            _text: The selected combo box display text (unused; the codec
                name is read from the item's user data).
        """
        if self._encoding_combo is None or self._hex_widget is None:
            return
        data = self._encoding_combo.currentData()
        encoding = data if isinstance(data, str) and data else "utf-8"
        set_encoding_fn = getattr(self._hex_widget, "set_encoding", None)
        if callable(set_encoding_fn):
            set_encoding_fn(encoding)

    def has_unsaved_changes(self) -> bool:
        """Check whether the current document has unsaved modifications.

        Returns:
            bool: True if unsaved changes exist.
        """
        if self.document is None:
            return False
        is_modified = getattr(self.document, "is_modified", None)
        return bool(is_modified()) if callable(is_modified) else False

    def save(self) -> bool:
        """Save the current document.

        Returns:
            bool: True if the save completed successfully.
        """
        if self.document is None:
            return False
        _logger.info("panel_save_public_called")
        try:
            self._on_save()
        except OSError:
            _logger.exception("save_document_failed")
            return False
        _logger.info("panel_save_public_completed")
        return True

    def _on_display_mode_changed(self, mode: str) -> None:
        """Handle display mode combo box changes.

        Args:
            mode: Selected display mode string.
        """
        if self._hex_widget is not None:
            set_mode_fn = getattr(self._hex_widget, "set_display_mode", None)
            if callable(set_mode_fn):
                set_mode_fn(mode)

    def _build_copy_as_menu(self) -> QMenu:
        """Build a popup menu for the Copy As button.

        Returns:
            QMenu: QMenu widget with format choices.
        """
        menu = QMenu(self)
        formats = [
            "hex",
            "c_array",
            "python",
            "base64",
            "rust_array",
            "csharp_array",
            "java_array",
            "javascript_array",
            "go_slice",
            "hex_string_no_spaces",
            "nasm_db",
            "markdown_table",
        ]
        for fmt in formats:
            action = menu.addAction(fmt)
            if action is not None:

                def _make_handler(f: str) -> Callable[[object], None]:
                    def _handler(_checked: object = None) -> None:
                        self._do_copy_as(f)

                    return _handler

                action.triggered.connect(_make_handler(fmt))
        return menu

    def _do_copy_as(self, fmt: str) -> None:
        """Copy the current selection in the specified format.

        Args:
            fmt: Output format name.
        """
        if self._hex_widget is None:
            return
        copy_fn = getattr(self._hex_widget, "copy_as", None)
        if not callable(copy_fn):
            return
        result = str(copy_fn(fmt))
        clipboard = QApplication.clipboard()
        if clipboard is None:
            _logger.warning("copy_as_no_clipboard", fmt=fmt)
            show_warning(self, "Clipboard Unavailable", "The system clipboard is not accessible. The selection could not be copied.")
            return
        try:
            clipboard.setText(result)
        except RuntimeError as exc:
            _logger.warning("copy_as_clipboard_write_failed", fmt=fmt, exc_info=True)
            show_warning(self, "Clipboard Write Failed", f"Could not write to the clipboard:\n{exc}")

    def _on_alignment_changed(self, text: str) -> None:
        """Handle alignment combo box changes.

        Args:
            text: Selected alignment text.
        """
        if text == "No Align":
            size = 0
        else:
            try:
                size = int(text.split("(", maxsplit=1)[0].strip().replace(",", ""))
            except ValueError:
                _logger.exception("alignment_size_parse_failed", text=text)
                size = 0
        if self._hex_widget is not None:
            set_align_fn = getattr(self._hex_widget, "set_alignment_grid_size", None)
            if callable(set_align_fn):
                set_align_fn(size)

    def _on_snap_alignment(self) -> None:
        """Snap the cursor to the nearest alignment boundary."""
        if self._hex_widget is None:
            return
        alignment = getattr(self._hex_widget, "_alignment_grid_size", 0)
        if alignment <= 0:
            return
        cursor = getattr(self._hex_widget, "_cursor_offset", 0)
        snapped = (cursor // alignment) * alignment
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if callable(goto_fn):
            goto_fn(snapped)

    def _on_color_mode_changed(self, text: str) -> None:
        """Handle color mode combo box changes.

        Args:
            text: Selected color mode text.
        """
        mode_map: dict[str, str] = {
            "No Coloring": "none",
            "Entropy Heatmap": "entropy",
            "Byte Value": "byte_value",
            "Content Type": "content_type",
        }
        mode = mode_map.get(text, "none")
        if self._hex_widget is not None:
            set_color = getattr(self._hex_widget, "set_color_mode", None)
            if callable(set_color):
                set_color(mode)

    def _refresh_bookmarks_tree(self) -> None:
        """Refresh the bookmarks tree after auto-bookmark operations."""
        if self._bookmarks_tree is None or self.document is None:
            return
        self._bookmarks_tree.clear()
        try:
            bookmarks: list[tuple[int, int, str, str]] = self.document.list_bookmarks()
            for offset, length, label, _color in bookmarks:
                item = QTreeWidgetItem([f"0x{offset:08X}", str(length), label])
                self._bookmarks_tree.addTopLevelItem(item)
        except (AttributeError, ValueError):
            _logger.debug("panel_refresh_bookmarks_list_failed", exc_info=True)

    def _cleanup(self) -> None:
        """Release resources when the panel is closed."""
        for worker in (self._statistics_worker, self._search_worker, self._numeric_search_worker):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()
                worker.wait(2000)
        self._statistics_worker = None
        self._search_worker = None
        self._numeric_search_worker = None

        if self.state_holder is not None and self._state_callback is not None:
            self.state_holder.unregister_callback(self._state_callback)
        self._state_callback = None

        self.document = None
        self.file_path = None
        self._original_data_cache.clear()
        self._search_results.clear()
        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(None)
        _logger.debug("hex_editor_panel_cleanup")
