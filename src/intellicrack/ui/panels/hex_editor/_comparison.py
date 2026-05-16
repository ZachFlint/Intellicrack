# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""File comparison mixin for the hex editor panel."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtWidgets import (
    QFileDialog,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, run_bridge_coroutine


_logger = get_logger(__name__)


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


def execute_diff(bridge: HexEditorBridge, path_a: str, path_b: str) -> dict[str, Any]:
    """Run a byte-level file comparison through the hex-editor bridge.

    Args:
        bridge: HexEditorBridge instance providing ``compare_files``.
        path_a: Path to the first file.
        path_b: Path to the second file.

    Returns:
        dict[str, Any]: Diff result enriched with ``path_a`` / ``path_b`` keys.

    Raises:
        TypeError: If the bridge returns a non-dict result.
    """
    raw: object = run_bridge_coroutine(bridge.compare_files(path_a, path_b))
    if not isinstance(raw, dict):
        msg = "compare_files returned non-dict result"
        raise TypeError(msg)
    result: dict[str, Any] = raw
    result.setdefault("path_a", path_a)
    result.setdefault("path_b", path_b)
    return result


class ComparisonMixin:
    """Mixin providing file comparison and diff display for the hex editor panel."""

    document: Any | None
    file_path: Path | None
    _hex_widget: Any | None
    _diff_results_tree: QTreeWidget | None
    _diff_summary_label: QLabel | None
    _diff_worker: GenericCallableWorker | None
    _diff_temp_path: Path | None

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        hex_widget = getattr(self, "_hex_widget", None)
        if hex_widget is not None:
            goto_fn = getattr(hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def _create_comparison_tab(self) -> QWidget:
        """Create the Diff side panel tab widget.

        Returns:
            QWidget: Container with compare button, results tree,
                and summary label.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        compare_btn = QPushButton("Compare With...")
        compare_btn.clicked.connect(self._on_compare)
        layout.addWidget(compare_btn)

        self._diff_summary_label = QLabel("")
        layout.addWidget(self._diff_summary_label)

        self._diff_results_tree = QTreeWidget()
        self._diff_results_tree.setHeaderLabels(["Offset", "Length", "Type", "Details"])
        self._diff_results_tree.setRootIsDecorated(show=False)
        self._diff_results_tree.setAlternatingRowColors(True)
        self._diff_results_tree.itemDoubleClicked.connect(self._on_diff_item_double_clicked)
        layout.addWidget(self._diff_results_tree)

        self._diff_worker = None
        self._diff_temp_path = None
        return container

    def _on_compare(self) -> None:
        """Open a file dialog and begin diffing the current document against the selected file."""
        if self.document is None:
            return

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            _logger.warning("diff_bridge_unavailable")
            return

        parent = self if isinstance(self, QWidget) else None
        dialog_result = QFileDialog.getOpenFileName(parent, "Compare With", "", "All Files (*)")
        compare_path = dialog_result[0] if dialog_result else ""
        if not compare_path:
            return

        if self._diff_worker is not None and self._diff_worker.isRunning():
            return

        self._cleanup_diff_temp()

        if self.file_path is not None and Path(self.file_path).exists():
            path_a = str(self.file_path)
        else:
            try:
                doc_len: int = self.document.length()
                raw_a: object = self.document.read(0, doc_len)
                if isinstance(raw_a, list):
                    data_a = bytes(cast("list[int]", raw_a))
                elif isinstance(raw_a, bytearray):
                    data_a = bytes(raw_a)
                elif isinstance(raw_a, bytes):
                    data_a = raw_a
                else:
                    return
            except (AttributeError, ValueError):
                _logger.exception("diff_doc_read_failed")
                return

            try:
                with tempfile.NamedTemporaryFile(prefix="intellicrack_diff_", delete=False) as tmp:
                    tmp.write(data_a)
                    path_a = tmp.name
            except OSError:
                _logger.exception("diff_temp_write_failed")
                return
            self._diff_temp_path = Path(path_a)

        if self._diff_summary_label is not None:
            self._diff_summary_label.setText("Computing diff...")

        worker = GenericCallableWorker(execute_diff, bridge, path_a, compare_path)
        _: object = worker.call_finished.connect(self._on_diff_finished_obj)
        _ = worker.call_error.connect(self._on_diff_error_obj)
        self._diff_worker = worker
        worker.start()

    def _on_diff_finished_obj(self, result: object) -> None:
        """Forward worker results to the typed diff handler.

        Args:
            result: Raw object emitted by ``GenericCallableWorker.call_finished``.
        """
        if isinstance(result, dict):
            typed: dict[str, Any] = cast("dict[str, Any]", result)
            self._on_diff_finished(typed)

    def _on_diff_error_obj(self, exc: object) -> None:
        """Forward worker exceptions to the typed diff error handler.

        Args:
            exc: Exception object emitted by ``GenericCallableWorker.call_error``.
        """
        self._on_diff_error(str(exc))

    def _cleanup_diff_temp(self) -> None:
        """Delete any leftover diff snapshot tempfile from a prior comparison."""
        path = self._diff_temp_path
        if path is None:
            return
        self._diff_temp_path = None
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            _logger.warning("diff_temp_unlink_failed", path=str(path))

    def _on_diff_finished(self, result: dict[str, Any]) -> None:
        """Handle completed diff computation and populate the results tree.

        Args:
            result: Diff result dict with regions, total_differences, etc.
        """
        self._cleanup_diff_temp()

        if self._diff_results_tree is None:
            return

        self._diff_results_tree.clear()

        regions = result.get("regions", [])
        total = result.get("total_differences", 0)
        identical = result.get("files_identical", False)

        if self._diff_summary_label is not None:
            if identical:
                self._diff_summary_label.setText("Files are identical")
            else:
                self._diff_summary_label.setText(
                    f"{len(regions)} region(s), {total} byte(s) differ  [{result.get('size_a', 0)} vs {result.get('size_b', 0)} bytes]",
                )

        for region in regions:
            offset = region.get("offset", 0)
            length = region.get("length", 0)
            rtype = region.get("type", "unknown")
            details = f"Bytes {offset:#010x} - {offset + length:#010x}"
            item = QTreeWidgetItem([
                f"0x{offset:08X}",
                str(length),
                rtype,
                details,
            ])
            self._diff_results_tree.addTopLevelItem(item)

        _logger.info("diff_complete", regions=len(regions), total_diffs=total)

    def _on_diff_error(self, error: str) -> None:
        """Handle diff computation failure.

        Args:
            error: Error message from the diff worker.
        """
        self._cleanup_diff_temp()

        if self._diff_summary_label is not None:
            self._diff_summary_label.setText(f"Diff failed: {error}")
        _logger.warning("diff_failed", error=error)

    def _on_diff_item_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the offset of a double-clicked diff region.

        Args:
            item: The clicked tree item.
            column: The clicked column index.
        """
        _ = column
        offset_text = item.text(0)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            _logger.exception("diff_offset_parse_failed", offset_text=offset_text)
            return
        self.goto_offset(offset)
