# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""File comparison mixin for the hex editor panel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final, cast, override

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import logger


_DIFF_CHUNK_SIZE: Final[int] = 65536


class DiffWorker(QThread):
    """Background worker for binary file comparison.

    Computes byte-level differences between two files in a background
    thread to avoid blocking the GUI on large files.

    Args:
        data_a: First file contents.
        data_b: Second file contents.
        path_a: Display path for first file.
        path_b: Display path for second file.
        parent: Parent QObject.

    Attributes:
        diff_finished: Emitted with result dict containing diff regions.
        diff_error: Emitted with error message string on failure.
    """

    diff_finished: pyqtSignal = pyqtSignal(dict)
    diff_error: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        data_a: bytes,
        data_b: bytes,
        path_a: str,
        path_b: str,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the DiffWorker with two file buffers.

        Args:
            data_a: First file contents.
            data_b: Second file contents.
            path_a: Display path for first file.
            path_b: Display path for second file.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._data_a = data_a
        self._data_b = data_b
        self._path_a = path_a
        self._path_b = path_b

    @override
    def run(self) -> None:
        """Execute the diff computation in the background thread."""
        try:
            result = self._compute_diff()
            self.diff_finished.emit(result)
        except (ValueError, OSError) as exc:
            self.diff_error.emit(str(exc))

    def _compute_diff(self) -> dict[str, Any]:
        """Compare two byte sequences and identify differing regions.

        Scans both arrays in parallel, grouping consecutive differing
        bytes into contiguous regions for efficient display.

        Returns:
            dict[str, Any]: Dict with regions list, total_differences,
                files_identical flag, and file paths.
        """
        a = self._data_a
        b = self._data_b
        min_len = min(len(a), len(b))
        max_len = max(len(a), len(b))

        regions: list[dict[str, Any]] = []
        diff_start = -1
        total_diffs = 0

        for i in range(min_len):
            if a[i] != b[i]:
                if diff_start < 0:
                    diff_start = i
            elif diff_start >= 0:
                length = i - diff_start
                regions.append({
                    "offset": diff_start,
                    "length": length,
                    "type": "modified",
                })
                total_diffs += length
                diff_start = -1

        if diff_start >= 0:
            length = min_len - diff_start
            regions.append({
                "offset": diff_start,
                "length": length,
                "type": "modified",
            })
            total_diffs += length

        if len(a) != len(b):
            extra_start = min_len
            extra_len = max_len - min_len
            region_type = "extra_in_a" if len(a) > len(b) else "extra_in_b"
            regions.append({
                "offset": extra_start,
                "length": extra_len,
                "type": region_type,
            })
            total_diffs += extra_len

        return {
            "regions": regions,
            "total_differences": total_diffs,
            "files_identical": total_diffs == 0,
            "path_a": self._path_a,
            "path_b": self._path_b,
            "size_a": len(a),
            "size_b": len(b),
        }


class ComparisonMixin:
    """Mixin providing file comparison and diff display for the hex editor panel."""

    document: Any | None
    file_path: Path | None
    _hex_widget: Any | None
    _diff_results_tree: QTreeWidget | None
    _diff_summary_label: QLabel | None
    _diff_worker: DiffWorker | None

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
        self._diff_results_tree.setAlternatingRowColors(enable=True)
        self._diff_results_tree.itemDoubleClicked.connect(self._on_diff_item_double_clicked)
        layout.addWidget(self._diff_results_tree)

        self._diff_worker = None
        return container

    def _on_compare(self) -> None:
        """Open a file dialog and begin diffing the current document against the selected file."""
        if self.document is None:
            return

        parent = self if isinstance(self, QWidget) else None
        result = QFileDialog.getOpenFileName(parent, "Compare With", "", "All Files (*)")
        compare_path = result[0] if result else ""
        if not compare_path:
            return

        try:
            data_b = Path(compare_path).read_bytes()
        except OSError as exc:
            logger.warning("diff_file_read_failed", path=compare_path, error=str(exc))
            return

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
        except (AttributeError, ValueError) as exc:
            logger.warning("diff_doc_read_failed", error=str(exc))
            return

        if self._diff_worker is not None and self._diff_worker.isRunning():
            return

        if self._diff_summary_label is not None:
            self._diff_summary_label.setText("Computing diff...")

        path_a = str(self.file_path) if self.file_path else "current"
        worker = DiffWorker(data_a, data_b, path_a, compare_path)
        worker.diff_finished.connect(self._on_diff_finished)
        worker.diff_error.connect(self._on_diff_error)
        self._diff_worker = worker
        worker.start()

    def _on_diff_finished(self, result: dict[str, Any]) -> None:
        """Handle completed diff computation and populate the results tree.

        Args:
            result: Diff result dict with regions, total_differences, etc.
        """
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

        logger.info("diff_complete", regions=len(regions), total_diffs=total)

    def _on_diff_error(self, error: str) -> None:
        """Handle diff computation failure.

        Args:
            error: Error message from the diff worker.
        """
        if self._diff_summary_label is not None:
            self._diff_summary_label.setText(f"Diff failed: {error}")
        logger.warning("diff_failed", error=error)

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
            return
        self.goto_offset(offset)
