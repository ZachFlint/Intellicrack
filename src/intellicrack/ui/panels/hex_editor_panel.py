# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Hex editor panel with data inspector, bookmarks, and structure templates.

Provides a complete hex editing environment combining the custom
HexEditorWidget with side panels for data inspection, bookmarks,
sections, imports, exports, strings, statistics, and templates.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


try:
    import pefile

    _pefile_available: bool = True
except ImportError:
    pefile = None
    _pefile_available = False


_logger = get_logger("ui.panels.hex_editor_panel")

_hexcore: Any = None
_hexcore_available: bool = False

try:
    import intellicrack_hexcore as _hexcore_mod

    _hexcore = _hexcore_mod
    _hexcore_available = True
except ImportError:
    _logger.debug("hexcore_import_unavailable")


_KB = 1024
_MB = _KB * _KB
_GB = _MB * _KB


def _format_size(size: int) -> str:
    """Format a byte size as a human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        Formatted size string (e.g. "1.5 MB").
    """
    if size < _KB:
        return f"{size} B"
    if size < _MB:
        return f"{size / _KB:.1f} KB"
    if size < _GB:
        return f"{size / _MB:.1f} MB"
    return f"{size / _GB:.2f} GB"


class HexEditorPanel(AnalysisPanelBase):
    """Hex editor panel with integrated side panels.

    Combines the custom HexEditorWidget with data inspector,
    bookmarks, sections, imports, exports, strings, statistics,
    and template panels in a split layout.

    Attributes:
        _hex_widget: The core hex editor rendering widget.
        _document: Active HexDocument instance.
        _file_path: Path to the currently loaded file.
        _side_tabs: Tab widget for side panels.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the hex editor panel.

        Args:
            parent: Parent widget.
        """
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
        self._mode_label.setFixedWidth(30)
        toolbar.addWidget(self._mode_label)
        toolbar.addSeparator()

        self._offset_input = self._add_toolbar_input(toolbar, "Offset (hex)", max_width=100)
        self._add_secondary_button(toolbar, "Go", self._on_goto_offset)
        toolbar.addSeparator()

        self._search_input = self._add_toolbar_input(toolbar, "Search...", max_width=180)

        self._search_mode_combo = QComboBox()
        self._search_mode_combo.addItems(["Hex", "Text", "Regex"])
        self._search_mode_combo.setFixedWidth(70)
        toolbar.addWidget(self._search_mode_combo)

        self._add_secondary_button(toolbar, "Find", self._on_search)
        toolbar.addSeparator()

        self._undo_btn = self._add_secondary_button(toolbar, "Undo", self._on_undo)
        self._redo_btn = self._add_secondary_button(toolbar, "Redo", self._on_redo)
        toolbar.addSeparator()

        self._encoding_combo = QComboBox()
        self._encoding_combo.addItems(["ASCII", "UTF-8", "UTF-16LE", "UTF-16BE"])
        self._encoding_combo.setFixedWidth(90)
        toolbar.addWidget(self._encoding_combo)

        self._file_info_label = QLabel("")
        toolbar.addWidget(self._file_info_label)

    def _create_content(self) -> QWidget:
        """Create the main content with hex widget and side panels.

        Returns:
            Splitter widget containing hex editor and side panels.
        """
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._hex_widget = HexEditorWidget()
        self._hex_widget.cursor_moved.connect(self._on_cursor_moved)
        self._hex_widget.data_changed.connect(self._on_data_changed)
        self._hex_widget.edit_mode_changed.connect(self._on_edit_mode_changed)
        splitter.addWidget(self._hex_widget)

        self._side_tabs = QTabWidget()
        self._build_side_panels()
        splitter.addWidget(self._side_tabs)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        return splitter

    def _build_side_panels(self) -> None:
        """Create all side panel tabs."""
        if self._side_tabs is None:
            return

        self._data_inspector_tree = self._make_tree(["Type", "Value"])
        self._side_tabs.addTab(self._data_inspector_tree, "Inspector")

        bookmarks_container = QWidget()
        bm_layout = QVBoxLayout(bookmarks_container)
        bm_layout.setContentsMargins(0, 0, 0, 0)
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
        self._side_tabs.addTab(self._strings_tree, "Strings")

        self._statistics_tree = self._make_tree(["Byte", "Count", "Percentage"])
        self._side_tabs.addTab(self._statistics_tree, "Statistics")

        templates_container = QWidget()
        tmpl_layout = QVBoxLayout(templates_container)
        tmpl_layout.setContentsMargins(0, 0, 0, 0)
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

        self._patches_tree = self._make_tree(["Offset", "Original", "New"])
        self._side_tabs.addTab(self._patches_tree, "Patches")

    @staticmethod
    def _make_tree(headers: list[str]) -> QTreeWidget:
        """Create a QTreeWidget with the given column headers.

        Args:
            headers: Column header labels.

        Returns:
            Configured QTreeWidget.
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
            True if the file was loaded successfully.
        """
        if not _hexcore_available or _hexcore is None:
            QMessageBox.warning(
                self,
                "Hex Core Not Available",
                "The intellicrack_hexcore Rust extension is not installed.\n"
                "Build it with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path

        try:
            self._document = _hexcore.HexDocument.open(str(path))
            self._file_path = path

            if self._hex_widget is not None:
                set_doc = getattr(self._hex_widget, "set_document", None)
                if callable(set_doc):
                    set_doc(self._document)

            if self._document is None:
                return False
            doc_len: int = self._document.length()
            if self._file_info_label is not None:
                self._file_info_label.setText(f"  {path.name} ({_format_size(doc_len)})")

            self._populate_template_combo()
            self._populate_sections()
            self._populate_imports()
            self._populate_exports()
            self._update_statistics()

            _logger.info("file_loaded", path=str(path), size=doc_len)

        except Exception as exc:
            _logger.warning("file_load_failed", path=str(path), error=str(exc))
            QMessageBox.warning(self, "Load Failed", f"Failed to open file:\n{exc}")
            return False
        else:
            return True

    def _on_cursor_moved(self, offset: int) -> None:
        """Handle cursor movement to update side panels.

        Args:
            offset: New cursor byte offset.
        """
        self._update_data_inspector(offset)

    def _on_data_changed(self) -> None:
        """Handle data modification events."""
        if self._document is not None and self._file_info_label is not None:
            modified_mark = " *" if self._document.is_modified() else ""
            name = self._file_path.name if self._file_path is not None else "untitled"
            size = self._document.length()
            self._file_info_label.setText(f"  {name}{modified_mark} ({_format_size(size)})")

    def _on_edit_mode_changed(self, mode: str) -> None:
        """Handle edit mode toggle.

        Args:
            mode: New mode string ("overwrite" or "insert").
        """
        if self._mode_label is not None:
            self._mode_label.setText("INS" if mode == "insert" else "OVR")

    def _update_data_inspector(self, offset: int) -> None:
        """Update the data inspector tree for the given offset.

        Args:
            offset: Byte offset to inspect.
        """
        if self._data_inspector_tree is None or self._document is None:
            return

        self._data_inspector_tree.clear()
        try:
            result = self._document.inspect_at(offset)
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)

            display_order = [
                "int8", "uint8", "ascii_char", "utf8_char",
                "int16_le", "uint16_le", "int16_be", "uint16_be",
                "int32_le", "uint32_le", "int32_be", "uint32_be",
                "float32_le", "float32_be",
                "int64_le", "uint64_le", "int64_be", "uint64_be",
                "float64_le", "float64_be",
                "unix_timestamp", "dos_date", "dos_time", "filetime",
            ]

            for key in display_order:
                if key in typed_result:
                    item = QTreeWidgetItem([key, str(typed_result[key])])
                    self._data_inspector_tree.addTopLevelItem(item)

            for key, val in sorted(typed_result.items()):
                if key not in display_order:
                    item = QTreeWidgetItem([key, str(val)])
                    self._data_inspector_tree.addTopLevelItem(item)

        except Exception as exc:
            _logger.debug("inspector_update_failed", error=str(exc))

    def _on_open_file(self) -> None:
        """Open a file selection dialog and load the chosen file."""
        file_path_result = QFileDialog.getOpenFileName(
            self, "Open Binary File", "", "All Files (*)",
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
                self._on_data_changed()
                _logger.info("file_saved", path=file_path)
            else:
                self._on_save_as()
        except Exception as exc:
            QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")

    def _on_save_as(self) -> None:
        """Save the current document to a new path."""
        if self._document is None:
            return
        result = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        save_path = result[0] if result else ""
        if save_path:
            try:
                self._document.save(save_path)
                self._file_path = Path(save_path)
                self._on_data_changed()
                _logger.info("file_saved_as", path=save_path)
            except Exception as exc:
                QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")

    def _on_goto_offset(self) -> None:
        """Navigate to the offset entered in the toolbar input."""
        if self._offset_input is None or self._hex_widget is None:
            return
        text = self._offset_input.text().strip()
        if not text:
            return
        try:
            offset = int(text, 16) if text.lower().startswith("0x") else int(text)
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)
        except ValueError:
            _logger.debug("invalid_offset_input", text=text)

    def _on_search(self) -> None:
        """Execute a search based on current mode and input."""
        if self._document is None or self._search_input is None or self._search_mode_combo is None:
            return

        query = self._search_input.text().strip()
        if not query:
            return

        mode = self._search_mode_combo.currentText()
        results: list[tuple[int, int]] = []

        try:
            if mode == "Hex":
                raw_results = self._document.search_hex(query, 100)
                results = [(r[0], r[1]) for r in raw_results]
            elif mode == "Text":
                encoding = "utf-8"
                if self._encoding_combo is not None:
                    enc_text = self._encoding_combo.currentText()
                    encoding = enc_text.lower().replace("-", "")
                raw_results = self._document.search_text(query, encoding, True, 100)
                results = [(r[0], r[1]) for r in raw_results]
            elif mode == "Regex":
                raw_results = self._document.search_regex(query, 100)
                results = [(r[0], r[1]) for r in raw_results]

            if results and self._hex_widget is not None:
                goto_fn = getattr(self._hex_widget, "goto_offset", None)
                if callable(goto_fn):
                    goto_fn(results[0][0])

                highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
                if callable(highlight_fn):
                    highlights = [(off, length, "#FFAA00") for off, length in results]
                    highlight_fn(highlights)

            _logger.info("search_completed", mode=mode, result_count=len(results))

        except Exception as exc:
            _logger.debug("search_failed", error=str(exc))

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

    def _on_apply_template(self) -> None:
        """Apply the selected struct template at the current cursor offset."""
        if self._document is None or self._template_combo is None or self._templates_tree is None:
            return

        template_name = self._template_combo.currentText()
        if not template_name:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            result = self._document.apply_template(template_name, cursor_offset)
            self._templates_tree.clear()

            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            _logger.info("template_applied", template=template_name)

        except Exception as exc:
            _logger.debug("template_apply_failed", error=str(exc))

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Populate the templates tree with parsed field data.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._templates_tree is None:
            return

        for field_data in fields:
            item = QTreeWidgetItem([
                str(field_data.get("name", "")),
                str(field_data.get("offset", "")),
                str(field_data.get("size", "")),
                str(field_data.get("display_value", "")),
            ])
            self._templates_tree.addTopLevelItem(item)

            children_raw = field_data.get("children")
            if not isinstance(children_raw, list):
                continue
            children = cast("list[dict[str, object]]", children_raw)
            for child in children:
                child_item = QTreeWidgetItem([
                    str(child.get("name", "")),
                    str(child.get("offset", "")),
                    str(child.get("size", "")),
                    str(child.get("display_value", "")),
                ])
                item.addChild(child_item)

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Apply highlight overlays for template field regions.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._hex_widget is None:
            return

        highlights: list[tuple[int, int, str]] = []
        for field_data in fields:
            f_offset = field_data.get("offset")
            f_size = field_data.get("size")
            if isinstance(f_offset, int) and isinstance(f_size, int):
                highlights.append((f_offset, f_size, "#44FF44"))

        highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
        if callable(highlight_fn):
            highlight_fn(highlights)

    def _on_add_bookmark(self) -> None:
        """Add a bookmark at the current cursor position."""
        if self._document is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        self._document.add_bookmark(cursor_offset, 1, "Bookmark", "#FFFF00")
        self._refresh_bookmarks()

    def _on_remove_bookmark(self) -> None:
        """Remove the selected bookmark."""
        if self._document is None or self._bookmarks_tree is None:
            return

        current = self._bookmarks_tree.currentItem()
        if current is None:
            return

        index = self._bookmarks_tree.indexOfTopLevelItem(current)
        if index >= 0:
            self._document.remove_bookmark(index)
            self._refresh_bookmarks()

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks tree from the document."""
        if self._bookmarks_tree is None or self._document is None:
            return

        self._bookmarks_tree.clear()
        bookmarks = self._document.list_bookmarks()
        for bm in bookmarks:
            offset_str = f"0x{bm[0]:08X}"
            length_str = str(bm[1])
            label = str(bm[2])
            item = QTreeWidgetItem([offset_str, length_str, label])
            self._bookmarks_tree.addTopLevelItem(item)

    def _populate_template_combo(self) -> None:
        """Populate the template combo box with available templates."""
        if self._template_combo is None or self._document is None:
            return

        self._template_combo.clear()
        templates = self._document.list_templates()
        for name, _description in templates:
            self._template_combo.addItem(str(name))

    def _populate_sections(self) -> None:
        """Populate the sections tree using pefile."""
        if self._sections_tree is None or self._file_path is None:
            return

        self._sections_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
            sections = getattr(pe, "sections", None)
            if sections is not None:
                for section in sections:
                    name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    vaddr = f"0x{section.VirtualAddress:08X}"
                    vsize = f"0x{section.Misc_VirtualSize:08X}"
                    rawsize = f"0x{section.SizeOfRawData:08X}"
                    item = QTreeWidgetItem([name, vaddr, vsize, rawsize])
                    self._sections_tree.addTopLevelItem(item)
            pe.close()
        except Exception as exc:
            _logger.debug("sections_parse_failed", error=str(exc))

    def _populate_imports(self) -> None:
        """Populate the imports tree using pefile."""
        if self._imports_tree is None or self._file_path is None:
            return

        self._imports_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available_for_imports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
            dir_entry: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry.get("IMAGE_DIRECTORY_ENTRY_IMPORT", 1)])
            import_dir = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
            if import_dir is not None:
                for entry in import_dir:
                    dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
                    for imp in entry.imports:
                        func_name = imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal {imp.ordinal}"
                        addr = f"0x{imp.address:08X}" if imp.address else "N/A"
                        item = QTreeWidgetItem([dll_name, func_name, addr])
                        self._imports_tree.addTopLevelItem(item)
            pe.close()
        except Exception as exc:
            _logger.debug("imports_parse_failed", error=str(exc))

    def _populate_exports(self) -> None:
        """Populate the exports tree using pefile."""
        if self._exports_tree is None or self._file_path is None:
            return

        self._exports_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available_for_exports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
            dir_entry_exp: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry_exp.get("IMAGE_DIRECTORY_ENTRY_EXPORT", 0)])
            export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if export_dir is not None:
                symbols = getattr(export_dir, "symbols", None)
                if symbols is not None:
                    for exp in symbols:
                        name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal {exp.ordinal}"
                        addr = f"0x{exp.address:08X}" if exp.address else "N/A"
                        ordinal = str(exp.ordinal) if exp.ordinal is not None else "N/A"
                        item = QTreeWidgetItem([name, addr, ordinal])
                        self._exports_tree.addTopLevelItem(item)
            pe.close()
        except Exception as exc:
            _logger.debug("exports_parse_failed", error=str(exc))

    def _update_statistics(self) -> None:
        """Update the byte statistics tree."""
        if self._statistics_tree is None or self._document is None:
            return

        self._statistics_tree.clear()

        try:
            stats = self._document.byte_statistics()
            total = sum(s[1] for s in stats)
            if total == 0:
                return

            entropy = 0.0
            for _byte_val, count in stats:
                if count > 0:
                    prob = count / total
                    entropy -= prob * math.log2(prob)

            for byte_val, count in stats:
                if count > 0:
                    pct = f"{(count / total) * 100:.2f}%"
                    item = QTreeWidgetItem([f"0x{byte_val:02X}", str(count), pct])
                    self._statistics_tree.addTopLevelItem(item)

            entropy_item = QTreeWidgetItem(["Entropy", f"{entropy:.4f}", "bits/byte"])
            self._statistics_tree.insertTopLevelItem(0, entropy_item)

        except Exception as exc:
            _logger.debug("statistics_update_failed", error=str(exc))

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        if self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def _cleanup(self) -> None:
        """Release resources when the panel is closed."""
        self._document = None
        self._file_path = None
        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(None)
        _logger.debug("hex_editor_panel_cleanup")
