# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""YARA scanning mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any, Final, cast

from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import (
    YARA_MATCH_DISPLAY_BYTES,
    YaraScanner_cls,
    logger,
    yara_scanner_available,
)
from intellicrack.ui.resources.theme_manager import ThemeManager


_YARA_MATCH_DARK: Final[str] = "#AA44FF"
_YARA_MATCH_LIGHT: Final[str] = "#7B1FA2"


def _get_yara_match_color() -> str:
    """Return a theme-appropriate highlight color for YARA matches.

    Returns:
        str: Hex color string suitable for the active theme.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return _YARA_MATCH_DARK
    return _YARA_MATCH_LIGHT


class YaraMixin:
    """Mixin providing YARA scanning for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _yara_rule_files: list[str]
    _yara_file_count_label: QLabel | None
    _yara_inline_editor: QPlainTextEdit | None
    _yara_results_tree: QTreeWidget | None

    def goto_offset(self, offset: int) -> None: ...

    def _create_yara_tab(self) -> QWidget:
        """Create the YARA scanner side panel tab widget.

        Returns:
            QWidget: Container widget with YARA rule input and results tree.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        file_row = QHBoxLayout()
        select_files_btn = QPushButton("Select Rule Files...")
        select_files_btn.clicked.connect(self._on_yara_select_files)
        file_row.addWidget(select_files_btn)
        self._yara_file_count_label = QLabel("No files selected")
        file_row.addWidget(self._yara_file_count_label)
        file_row.addStretch()
        layout.addLayout(file_row)

        self._yara_inline_editor = QPlainTextEdit()
        yara_font = self._yara_inline_editor.font()
        yara_font.setFamily("Consolas")
        yara_font.setPointSize(9)
        self._yara_inline_editor.setFont(yara_font)
        self._yara_inline_editor.setToolTip("Enter inline YARA rule source. If empty, compiled rule files are used instead.")
        self._yara_inline_editor.setMaximumHeight(140)
        layout.addWidget(self._yara_inline_editor)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self._on_yara_scan)
        layout.addWidget(scan_btn)

        self._yara_results_tree = QTreeWidget()
        self._yara_results_tree.setHeaderLabels(["Rule", "Offset", "Identifier", "Match Data"])
        self._yara_results_tree.setAlternatingRowColors(enable=True)
        self._yara_results_tree.itemDoubleClicked.connect(self._on_yara_result_double_clicked)
        layout.addWidget(self._yara_results_tree)

        return container

    def _on_yara_select_files(self) -> None:
        """Open a file dialog to select YARA rule files."""
        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileNames(
            parent,
            "Select YARA Rule Files",
            "",
            "YARA Rules (*.yar *.yara);;All Files (*)",
        )
        files = result[0] if result else []
        if files:
            self._yara_rule_files = list(files)
            if self._yara_file_count_label is not None:
                self._yara_file_count_label.setText(f"{len(self._yara_rule_files)} file(s) selected")

    def _on_yara_scan(self) -> None:
        """Compile YARA rules and scan the current document."""
        if self.document is None or self._yara_results_tree is None:
            return

        if not yara_scanner_available or YaraScanner_cls is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(
                parent,
                "YARA Unavailable",
                "YARA is not installed. Install with: pip install yara-python",
            )
            return

        scanner = YaraScanner_cls()
        if not scanner.available:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(
                parent,
                "YARA Unavailable",
                "YARA is not installed. Install with: pip install yara-python",
            )
            return

        inline_source = ""
        if self._yara_inline_editor is not None:
            inline_source = self._yara_inline_editor.toPlainText().strip()

        matches: Any = None
        try:
            if inline_source:
                compiled_rules = scanner.compile_source(inline_source)
            elif self._yara_rule_files:
                compiled_rules = scanner.compile_rules(self._yara_rule_files)
            else:
                return

            doc_len: int = self.document.length()
            raw: object = self.document.read(0, doc_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return

            matches = scanner.scan_data(data, compiled_rules)

        except (RuntimeError, OSError, ValueError) as exc:
            logger.debug("yara_scan_failed", error=str(exc))
            return

        if matches is None:
            return

        self._yara_results_tree.clear()
        all_match_offsets: list[tuple[int, int]] = []

        for match in matches:
            rule_item = QTreeWidgetItem([match.rule_name, "", "", ""])
            self._yara_results_tree.addTopLevelItem(rule_item)
            for string_match in match.strings:
                match_hex = " ".join(f"{b:02X}" for b in string_match.data[:YARA_MATCH_DISPLAY_BYTES])
                child = QTreeWidgetItem([
                    "",
                    f"0x{string_match.offset:08X}",
                    string_match.identifier,
                    match_hex,
                ])
                rule_item.addChild(child)
                all_match_offsets.append((string_match.offset, len(string_match.data)))
            rule_item.setExpanded(aexpand=True)

        if all_match_offsets and self._hex_widget is not None:
            highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
            if callable(highlight_fn):
                color = _get_yara_match_color()
                highlights = [(off, length, color) for off, length in all_match_offsets]
                highlight_fn(highlights, "yara")

        logger.debug("yara_scan_complete", match_count=len(matches))

    def _on_yara_result_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the YARA match offset when a result child is double-clicked.

        Args:
            item: The double-clicked tree widget item.
            column: The double-clicked column index.
        """
        _ = column
        if item.parent() is None:
            return
        offset_text = item.text(1)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            pass
        else:
            self.goto_offset(offset)
