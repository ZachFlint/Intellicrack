# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Main HexEditorPanel class assembling all mixin functionality."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QKeySequence, QShortcut, QStandardItemModel
from PyQt6.QtWidgets import (
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
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.hex_editor._base import (
    CURSOR_CONTEXT_BYTES,
    ENCODING_ENTRIES,
    HASH_ALGORITHMS,
    PREVIEW_BYTES,
    HexDocumentEvent_cls,
    format_size,
    hexcore,
    hexcore_available,
    logger,
)
from intellicrack.ui.panels.hex_editor._bookmarks import BookmarksMixin
from intellicrack.ui.panels.hex_editor._data_inspector import DataInspectorMixin
from intellicrack.ui.panels.hex_editor._disassembly import DisassemblyMixin
from intellicrack.ui.panels.hex_editor._hashing import HashingMixin
from intellicrack.ui.panels.hex_editor._patches import PatchesMixin
from intellicrack.ui.panels.hex_editor._pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor._search import NumericSearchWorker, SearchMixin, SearchWorker
from intellicrack.ui.panels.hex_editor._sections import SectionsMixin
from intellicrack.ui.panels.hex_editor._statistics import StatisticsMixin, StatisticsWorker
from intellicrack.ui.panels.hex_editor._templates import TemplatesMixin
from intellicrack.ui.panels.hex_editor._transforms import TransformsMixin
from intellicrack.ui.panels.hex_editor._widgets import (
    ByteDistributionWidget,
    EntropyGraphWidget,
)
from intellicrack.ui.panels.hex_editor._yara import YaraMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from intellicrack.bridges.hex_state import HexDocumentState

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
    AnalysisPanelBase,
):
    """
    Hex editor panel with integrated side panels.

    Combines the custom HexEditorWidget with data inspector,
    bookmarks, sections, imports, exports, strings, statistics,
    and template panels in a split layout.

    Args:
        parent: Parent widget.

    Attributes:
        context_push_requested: Signal emitted with context dict when hex data is pushed to AI chat.
    """

    context_push_requested: pyqtSignal = pyqtSignal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        self._hex_widget: Any | None = None
        self._document: Any | None = None
        self._file_path: Path | None = None

        self._data_inspector_tree: QTreeWidget | None = None
        self._bookmarks_tree: QTreeWidget | None = None
        self._sections_tree: QTreeWidget | None = None
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
        self._state_holder: HexDocumentState | None = None
        self._find_next_btn: QPushButton | None = None
        self._find_prev_btn: QPushButton | None = None
        self._state_callback: Any | None = None
        self._search_status_label: QLabel | None = None
        self._selection_start: int = -1
        self._selection_end: int = -1

        self._pattern_frame: QFrame | None = None
        self._pattern_dsl_editor: QPlainTextEdit | None = None
        self._pattern_json_preview: QPlainTextEdit | None = None
        self._pattern_library_tree: QTreeWidget | None = None
        self._pattern_error_display: QPlainTextEdit | None = None
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
        self._statistics_worker: StatisticsWorker | None = None
        self._search_worker: SearchWorker | None = None
        self._numeric_search_worker: NumericSearchWorker | None = None
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

        super().__init__(parent)

    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """
        Add hex editor controls to the toolbar.

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
        for enc_entry in ENCODING_ENTRIES:
            self._encoding_combo.addItem(enc_entry)
            if enc_entry.startswith("---"):
                idx = self._encoding_combo.count() - 1
                model = self._encoding_combo.model()
                if isinstance(model, QStandardItemModel):
                    item = model.item(idx)
                    if item is not None:
                        item.setEnabled(False)
        toolbar.addWidget(self._encoding_combo)

        self._add_secondary_button(toolbar, "Send to AI", self._on_send_to_ai)
        toolbar.addSeparator()
        self._add_secondary_button(toolbar, "Pattern Editor", self._toggle_pattern_editor)

        self._file_info_label = QLabel("")
        toolbar.addWidget(self._file_info_label)

    def _create_content(self) -> QWidget:
        """
        Create the main content with hex widget, side panels, and pattern editor.

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

        self._data_inspector_tree = self._make_tree(["Type", "Value"])
        self._side_tabs.addTab(self._data_inspector_tree, "Inspector")

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
        self._side_tabs.addTab(bookmarks_container, "Bookmarks")

        self._sections_tree = self._make_tree(["Name", "VAddr", "VSize", "RawSize"])
        self._side_tabs.addTab(self._sections_tree, "Sections")

        self._imports_tree = self._make_tree(["Library", "Function", "Address"])
        self._side_tabs.addTab(self._imports_tree, "Imports")

        self._exports_tree = self._make_tree(["Name", "Address", "Ordinal"])
        self._side_tabs.addTab(self._exports_tree, "Exports")

        self._strings_tree = self._make_tree(["Offset", "Length", "String"])
        self._strings_tree.itemDoubleClicked.connect(self._on_string_double_clicked)
        self._side_tabs.addTab(self._strings_tree, "Strings")

        stats_container = QWidget()
        stats_layout = QVBoxLayout(stats_container)
        stats_layout.setContentsMargins(_STATS_MARGIN, _STATS_MARGIN, _STATS_MARGIN, _STATS_MARGIN)
        stats_layout.setSpacing(_STATS_SPACING)
        self._entropy_graph = EntropyGraphWidget()
        self._entropy_graph.block_clicked.connect(self.goto_offset)
        stats_layout.addWidget(self._entropy_graph)
        dist_header = QHBoxLayout()
        dist_header.addWidget(QLabel("Byte Distribution"))
        log_btn = QPushButton("Log Scale")
        log_btn.setFixedWidth(_LOG_BTN_WIDTH)
        log_btn.setCheckable(True)
        self._byte_dist_widget = ByteDistributionWidget()
        dist_ref = self._byte_dist_widget

        def _on_log_toggled(_checked: bool) -> None:
            dist_ref.toggle_log_scale()

        log_btn.toggled.connect(_on_log_toggled)
        dist_header.addWidget(log_btn)
        stats_layout.addLayout(dist_header)
        stats_layout.addWidget(self._byte_dist_widget)
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
        stats_layout.addWidget(summary_box)
        self._statistics_tree = self._make_tree(["Byte", "Count", "Percentage"])
        stats_layout.addWidget(self._statistics_tree)
        self._side_tabs.addTab(stats_container, "Statistics")

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
        self._templates_tree = self._make_tree(["Field", "Offset", "Size", "Value"])
        tmpl_layout.addWidget(self._templates_tree)
        self._side_tabs.addTab(templates_container, "Templates")

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
        self._side_tabs.addTab(patches_container, "Patches")

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
        hashes_layout.addStretch()
        self._side_tabs.addTab(hashes_container, "Hashes")

        self._side_tabs.addTab(self._create_disassembly_tab(), "Disassembly")
        self._side_tabs.addTab(self._create_yara_tab(), "YARA")
        self._side_tabs.addTab(self._create_transforms_tab(), "Transforms")

    @staticmethod
    def _make_tree(headers: list[str]) -> QTreeWidget:
        """
        Create a QTreeWidget with the given column headers.

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
        """
        Load a binary file into the hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            bool: True if the file was loaded successfully.
        """
        if not hexcore_available or hexcore is None:
            QMessageBox.warning(
                self,
                "Hex Core Not Available",
                "The intellicrack_hexcore Rust extension is not installed.\n"
                "Build it with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path

        try:
            self._document = hexcore.HexDocument.open(str(path))
            self._file_path = path

            if self._hex_widget is not None:
                set_doc = getattr(self._hex_widget, "set_document", None)
                if callable(set_doc):
                    set_doc(self._document)

            if self._document is None:
                return False
            doc_len: int = self._document.length()
            if self._file_info_label is not None:
                self._file_info_label.setText(f"  {path.name} ({format_size(doc_len)})")

            self._populate_template_combo()
            self._auto_detect_file_type()
            self._populate_sections()
            self._populate_imports()
            self._populate_exports()
            self._populate_strings()
            self._update_statistics()
            self._original_data_cache.clear()
            self._search_results.clear()
            self._search_index = 0

            if self._state_holder is not None:
                self._state_holder.set_document(self._document, path, source="panel")

        except OSError as exc:
            logger.warning("file_load_failed", path=str(path), error=str(exc))
            QMessageBox.warning(self, "Load Failed", f"Failed to open file:\n{exc}")
            return False
        else:
            logger.info("file_loaded", path=str(path), size=doc_len)
            return True

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
        if self._document is None:
            return
        try:
            file_path = self._document.file_path()
            if file_path is not None:
                self._document.save(file_path)
            else:
                self._on_save_as()
                return
        except OSError as exc:
            QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")
        else:
            self._on_data_changed()
            logger.info("file_saved", path=file_path)

    def _on_save_as(self) -> None:
        """Save the current document to a new path."""
        if self._document is None:
            return
        result = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        save_path = result[0] if result else ""
        if save_path:
            try:
                self._document.save(save_path)
            except OSError as exc:
                QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")
            else:
                self._file_path = Path(save_path)
                self._on_data_changed()
                logger.info("file_saved_as", path=save_path)

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
            logger.debug("invalid_offset_input", text=text)
        else:
            goto_fn(offset)

    def goto_offset(self, offset: int) -> None:
        """
        Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        if self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def _on_cursor_moved(self, offset: int) -> None:
        """
        Handle cursor movement to update side panels.

        Args:
            offset: New cursor byte offset.
        """
        self._update_data_inspector(offset)
        self._on_cursor_moved_disasm(offset)

    def _on_data_changed(self) -> None:
        """Handle data modification events."""
        if self._document is not None and self._file_info_label is not None:
            modified_mark = " *" if self._document.is_modified() else ""
            name = self._file_path.name if self._file_path is not None else "untitled"
            size = self._document.length()
            self._file_info_label.setText(f"  {name}{modified_mark} ({format_size(size)})")
        self._update_patches()

    def _on_edit_mode_changed(self, mode: str) -> None:
        """
        Handle edit mode toggle.

        Args:
            mode: New mode string ("overwrite" or "insert").
        """
        if self._mode_label is not None:
            self._mode_label.setText("INS" if mode == "insert" else "OVR")

    def _on_send_to_ai(self) -> None:
        """Emit context for AI analysis from the current hex editor state."""
        if self._document is None:
            return

        context: dict[str, Any] = {
            "file_path": str(self._file_path) if self._file_path else None,
            "size": self._document.length(),
        }
        context["modified"] = self._document.is_modified()

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
        context["cursor"] = cursor_offset

        try:
            read_start = max(0, cursor_offset - CURSOR_CONTEXT_BYTES)
            read_len = min(PREVIEW_BYTES, self._document.length() - read_start)
            raw = self._document.read(read_start, read_len) if read_len > 0 else None
        except (AttributeError, ValueError):
            logger.debug("ai_context_bytes_read_failed")
        else:
            if raw is not None:
                context["bytes_at_cursor"] = " ".join(f"{b:02X}" for b in raw)
                context["bytes_offset"] = read_start

        try:
            inspection = self._document.inspect_at(cursor_offset)
        except (AttributeError, ValueError):
            logger.debug("ai_context_inspection_failed")
        else:
            if isinstance(inspection, dict):
                context["inspection"] = {k: str(v) for k, v in cast("dict[str, object]", inspection).items()}

        self.context_push_requested.emit(context)

    def _on_undo(self) -> None:
        """Undo the last edit operation."""
        if self._document is not None:
            self._document.undo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def _on_redo(self) -> None:
        """Redo the last undone operation."""
        if self._document is not None:
            self._document.redo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def set_state_holder(self, state_holder: HexDocumentState) -> None:
        """
        Attach a shared state holder for bridge-GUI synchronization.

        Args:
            state_holder: The shared HexDocumentState instance.
        """
        self._state_holder = state_holder

        def on_state_event(event_type: Any, data: dict[str, Any]) -> None:
            evt = HexDocumentEvent_cls
            if evt is None:
                return
            if event_type == evt.DOCUMENT_OPENED:
                file_path_str = data.get("file_path")
                if file_path_str and self._document is None:
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
                    widget._selection_start = start
                    widget._selection_end = end
                    update_fn = getattr(widget, "_update_viewport", None)
                    if callable(update_fn):
                        update_fn()
            elif event_type == evt.TEMPLATE_REGISTERED:
                self._populate_template_combo()

        self._state_callback = on_state_event
        state_holder.register_callback(on_state_event, source_id="panel")

    def _on_selection_changed(self, start: int, end: int) -> None:
        """
        Handle selection range changes from the hex widget.

        Updates the data inspector, hash display, and stored selection
        range for use by sub-panels.

        Args:
            start: Selection start offset.
            end: Selection end offset.
        """
        self._selection_start = start
        self._selection_end = end
        if start >= 0:
            self._update_data_inspector(start)

    def _on_encoding_changed(self, text: str) -> None:
        """
        Handle encoding combo box selection changes.

        Skips separator entries and forwards the encoding name to the
        hex widget for ASCII column rendering.

        Args:
            text: The selected combo box text.
        """
        if text.startswith("---"):
            return
        if self._hex_widget is not None:
            self._hex_widget.set_encoding(text.lower().replace("-", ""))

    def has_unsaved_changes(self) -> bool:
        """
        Check whether the current document has unsaved modifications.

        Returns:
            bool: True if unsaved changes exist.
        """
        if self._document is None:
            return False
        is_modified = getattr(self._document, "is_modified", None)
        return bool(is_modified()) if callable(is_modified) else False

    def save(self) -> bool:
        """
        Save the current document.

        Returns:
            bool: True if the save completed successfully.
        """
        if self._document is None:
            return False
        try:
            self._on_save()
        except OSError:
            return False
        return True

    def _cleanup(self) -> None:
        """Release resources when the panel is closed."""
        for worker in (self._statistics_worker, self._search_worker, self._numeric_search_worker):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()
                worker.wait(2000)
        self._statistics_worker = None
        self._search_worker = None
        self._numeric_search_worker = None

        if self._state_holder is not None and self._state_callback is not None:
            self._state_holder.unregister_callback(self._state_callback)
        self._state_callback = None

        self._document = None
        self._file_path = None
        self._original_data_cache.clear()
        self._search_results.clear()
        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(None)
        logger.debug("hex_editor_panel_cleanup")
