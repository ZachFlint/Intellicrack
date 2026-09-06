# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""File comparison mixin for the hex editor panel."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from PyQt6.QtCore import Qt
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
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, run_bridge_coroutine, worker_is_running


_logger = get_logger(__name__)

MATCH_DIFF_TYPE = "match"


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from intellicrack.bridges.hex_editor import HexEditorBridge


class DiffRow(NamedTuple):
    """One rendered row of the diff results tree.

    Attributes:
        offset: Offset cell text, carrying both sides when they diverge.
        length: Length cell text, carrying both sides when they diverge.
        diff_type: The region's diff type as reported by the engine.
        details: Human-readable byte span for the region.
        navigate_offset: Offset in the open document to jump to on activation.
    """

    offset: str
    length: str
    diff_type: str
    details: str
    navigate_offset: int


def _span(offset: int, length: int) -> str:
    """Render a half-open byte span.

    Args:
        offset: Start offset of the span.
        length: Number of bytes in the span.

    Returns:
        str: The span as ``0xSTART - 0xEND``.
    """
    return f"{offset:#010x} - {offset + length:#010x}"


def diff_region_rows(regions: Sequence[Mapping[str, Any]]) -> list[DiffRow]:
    """Build the tree rows for the differing regions of an engine diff result.

    The engine reports every region it walked, including the ``match`` runs
    that are byte-identical on both sides; those are dropped here so the tree
    and its count both mean differences. An inserted or deleted run has a
    different offset and length on each side, so both are shown whenever they
    diverge rather than collapsing to one side's value.

    Args:
        regions: The ``regions`` list from a ``diff_files``/``diff_bytes``
            result.

    Returns:
        list[DiffRow]: One row per differing region, in engine order.
    """
    rows: list[DiffRow] = []
    for region in regions:
        diff_type = str(region.get("diff_type", "unknown"))
        if diff_type.strip().casefold() == MATCH_DIFF_TYPE:
            continue

        offset_a = int(region.get("offset_a", 0))
        offset_b = int(region.get("offset_b", 0))
        length = int(region.get("length", 0))
        length_a = int(region.get("length_a", length))
        length_b = int(region.get("length_b", length))

        offset_text = f"0x{offset_a:08X}" if offset_a == offset_b else f"0x{offset_a:08X} / 0x{offset_b:08X}"
        length_text = str(length_a) if length_a == length_b else f"{length_a} → {length_b}"
        details = (
            f"Bytes {_span(offset_a, length_a)}"
            if offset_a == offset_b and length_a == length_b
            else f"A {_span(offset_a, length_a)}  |  B {_span(offset_b, length_b)}"
        )
        rows.append(
            DiffRow(
                offset=offset_text,
                length=length_text,
                diff_type=diff_type,
                details=details,
                navigate_offset=offset_a,
            ),
        )
    return rows


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
        self._diff_results_tree.setRootIsDecorated(False)
        self._diff_results_tree.setAlternatingRowColors(True)
        self._diff_results_tree.itemDoubleClicked.connect(self._on_diff_item_double_clicked)
        layout.addWidget(self._diff_results_tree)

        self._diff_worker = None
        self._diff_temp_path = None
        return container

    def _read_document_for_diff(self) -> bytes | None:
        """Read the full document into bytes for the diff comparison.

        Returns:
            bytes | None: Document contents as ``bytes``, or ``None`` when the
                document is missing or the underlying read returned an
                unrecognized payload type.
        """
        document: Any = self.document
        if document is None:
            return None
        doc_len: int = document.length()
        raw_a: object = document.read(0, doc_len)
        if isinstance(raw_a, list):
            return bytes(cast("list[int]", raw_a))
        if isinstance(raw_a, bytearray):
            return bytes(raw_a)
        return raw_a if isinstance(raw_a, bytes) else None

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

        if worker_is_running(self._diff_worker):
            return

        self._cleanup_diff_temp()

        if self.file_path is not None and Path(self.file_path).exists():
            path_a = str(self.file_path)
        else:
            try:
                data_a = self._read_document_for_diff()
            except (AttributeError, ValueError):
                _logger.exception("diff_doc_read_failed")
                return
            if data_a is None:
                return

            try:
                _logger.info(
                    "diff_temp_write_begin",
                    size=len(data_a),
                    prefix="intellicrack_diff_",
                )
                with tempfile.NamedTemporaryFile(prefix="intellicrack_diff_", delete=False) as tmp:
                    tmp.write(data_a)
                    path_a = tmp.name
            except OSError:
                _logger.exception("diff_temp_write_failed", size=len(data_a))
                return
            self._diff_temp_path = Path(path_a)
            _logger.info("diff_temp_write_complete", path=path_a, size=len(data_a))

        if self._diff_summary_label is not None:
            self._diff_summary_label.setText("Computing diff...")

        _logger.info(
            "diff_compare_started",
            path_a=path_a,
            path_b=compare_path,
            used_tempfile=self._diff_temp_path is not None,
        )

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
            _logger.warning("diff_temp_already_absent", path=str(path))
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

        regions = cast("Sequence[Mapping[str, Any]]", result.get("regions", []))
        total = result.get("total_differences", 0)
        identical = bool(result.get("files_identical"))
        rows = [] if identical else diff_region_rows(regions)

        if self._diff_summary_label is not None:
            if identical:
                self._diff_summary_label.setText("Files are identical")
            else:
                self._diff_summary_label.setText(
                    f"{len(rows)} region(s), {total} byte(s) differ  [{result.get('size_a', 0)} vs {result.get('size_b', 0)} bytes]",
                )

        for row in rows:
            item = QTreeWidgetItem([row.offset, row.length, row.diff_type, row.details])
            item.setData(0, Qt.ItemDataRole.UserRole, row.navigate_offset)
            self._diff_results_tree.addTopLevelItem(item)

        _logger.info("diff_complete", regions=len(rows), total_diffs=total)

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
        stored: object = item.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(stored, int):
            _logger.warning("diff_row_carries_no_offset", offset_text=item.text(0))
            return
        self.goto_offset(stored)
