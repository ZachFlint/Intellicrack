# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""YARA scanning mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.dialogs_helpers import show_warning
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor.base import YARA_MATCH_DISPLAY_BYTES
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


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
    _bridge: HexEditorBridge | None

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to the given byte offset.

        Args:
            offset: Absolute byte offset within the active document.
        """

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
        self._yara_results_tree.setAlternatingRowColors(True)
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
        """Compile YARA rules and scan the current document via the bridge.

        Routes the request through :meth:`HexEditorBridge.yara_scan` (or :meth:`HexEditorBridge.yara_scan_files` when no inline source is
        present) via :func:`run_bridge_coroutine_logged`. Results and errors are delivered back via signal callbacks so the Qt main thread
        is never blocked while compiling rules or scanning very large documents.
        """
        if self.document is None or self._yara_results_tree is None:
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            parent = self if isinstance(self, QWidget) else None
            show_warning(
                parent,
                "Hex Editor Bridge Unavailable",
                "The hex editor bridge is not attached to this panel.",
            )
            return

        inline_source = ""
        if self._yara_inline_editor is not None:
            inline_source = self._yara_inline_editor.toPlainText().strip()

        parent_obj = self if isinstance(self, QWidget) else None
        if inline_source:
            _logger.info(
                "yara_scan_dispatched",
                source_mode="inline",
                source_length=len(inline_source),
            )
            run_bridge_coroutine_logged(
                bridge.yara_scan(inline_source),
                on_success=self._on_yara_scan_success,
                on_error=self._on_yara_scan_error,
                parent=parent_obj,
                event="hex_editor_yara_scan",
                logger=_logger,
                source_length=len(inline_source),
            )
            return

        if self._yara_rule_files:
            rule_paths_arg = ",".join(self._yara_rule_files)
            _logger.info(
                "yara_scan_dispatched",
                source_mode="files",
                rule_count=len(self._yara_rule_files),
            )
            run_bridge_coroutine_logged(
                bridge.yara_scan_files(rule_paths_arg),
                on_success=self._on_yara_scan_success,
                on_error=self._on_yara_scan_error,
                parent=parent_obj,
                event="hex_editor_yara_scan_files",
                logger=_logger,
                file_count=len(self._yara_rule_files),
            )

    @staticmethod
    def _append_yara_match_strings(rule_item: QTreeWidgetItem, match: dict[str, Any]) -> list[tuple[int, int]]:
        """Append child rows for each ``strings`` entry in a YARA match dict.

        Args:
            rule_item: Tree item representing the parent rule that the
                children should be attached to.
            match: One element of the bridge's match list, expected to
                contain a ``strings`` list of ``{identifier, offset,
                data}`` dicts where ``data`` is a hex-encoded string.

        Returns:
            list[tuple[int, int]]: List of ``(offset, length)`` pairs
                for each string match successfully appended; the caller
                uses these to drive hex-widget highlighting.
        """
        offsets: list[tuple[int, int]] = []
        raw_strings: object = match.get("strings")
        if not isinstance(raw_strings, list):
            return offsets
        preview_chars = YARA_MATCH_DISPLAY_BYTES * 2
        for raw_entry in cast("list[object]", raw_strings):
            if not isinstance(raw_entry, dict):
                continue
            entry = cast("dict[str, Any]", raw_entry)
            offset_raw: Any = entry.get("offset")
            if offset_raw is None:
                continue
            try:
                offset_int = int(offset_raw)
            except (TypeError, ValueError):
                _logger.warning(
                    "hex_editor_yara_match_invalid_offset",
                    input_text=str(offset_raw),
                    rule_name=str(match.get("rule", "")),
                )
                continue
            identifier = str(entry.get("identifier", ""))
            data_hex = str(entry.get("data", ""))
            preview = data_hex[:preview_chars]
            match_hex = " ".join(preview[i : i + 2].upper() for i in range(0, len(preview), 2))
            child = QTreeWidgetItem(
                [
                    "",
                    f"0x{offset_int:08X}",
                    identifier,
                    match_hex,
                ],
            )
            rule_item.addChild(child)
            offsets.append((offset_int, len(data_hex) // 2))
        return offsets

    def _on_yara_scan_success(self, result: object) -> None:
        """Render bridge YARA matches into the results tree.

        Args:
            result: ``list[dict]`` payload returned by the bridge. Each
                dict contains ``rule``, ``tags``, ``meta``,
                ``namespace``, and ``strings`` keys; ``strings`` is a
                list of ``{identifier, offset, data}`` dicts where
                ``data`` is a hex-encoded string.
        """
        if self._yara_results_tree is None:
            return
        if not isinstance(result, list):
            _logger.warning("yara_unexpected_result_type", result_type=type(result).__name__)
            return

        matches = cast("list[dict[str, Any]]", result)
        self._yara_results_tree.clear()
        all_match_offsets: list[tuple[int, int]] = []

        for match in matches:
            rule_name = str(match.get("rule", ""))
            rule_item = QTreeWidgetItem([rule_name, "", "", ""])
            self._yara_results_tree.addTopLevelItem(rule_item)
            all_match_offsets.extend(self._append_yara_match_strings(rule_item, match))
            rule_item.setExpanded(True)

        if all_match_offsets and self._hex_widget is not None:
            highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
            if callable(highlight_fn):
                color = _get_yara_match_color()
                highlights = [(off, length, color) for off, length in all_match_offsets]
                highlight_fn(highlights, "yara")

        _logger.info("yara_scan_complete", match_count=len(matches))

    @staticmethod
    def _on_yara_scan_error(exc: object) -> None:
        """Log a YARA scan failure raised by the bridge.

        Args:
            exc: Exception object emitted by the bridge worker.
        """
        _logger.warning("yara_scan_failed", error_type=type(exc).__name__, error=str(exc))

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
            _logger.warning("hex_editor_yara_result_invalid_offset", input_text=offset_text)
        else:
            self.goto_offset(offset)
