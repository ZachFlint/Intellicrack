# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Statistics mixin for the hex editor panel."""

from __future__ import annotations

import dataclasses
import math
from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QLabel, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor._base import (
    BYTE_TYPE_DIST_MIN_LEN,
    BYTE_VALUES_COUNT,
    ENTROPY_BLOCK_SIZE,
)
from intellicrack.ui.panels.hex_editor._widgets import (
    DigramMatrixDialog,
)


_logger = get_logger(__name__)


if TYPE_CHECKING:
    from intellicrack.ui.panels.hex_editor._widgets import (
        ByteDistributionWidget,
        EntropyGraphWidget,
    )


@dataclasses.dataclass(frozen=True, slots=True)
class _StatisticsResult:
    """Container for statistics computed on a background thread.

    Attributes:
        byte_stats: List of (byte_value, count) tuples from the document.
        total: Total byte count across all byte values.
        entropy: Shannon entropy in bits per byte.
        entropy_values: Per-block entropy values, or None if unavailable.
        entropy_block_size: Block size used for per-block entropy.
        dist_counts: 256-element byte frequency distribution, or None.
        type_dist: Byte type distribution tuple, or None.
        classification: Per-block content classification list, or None.
        classification_block_size: Block size used for classification.
    """

    byte_stats: list[tuple[int, int]]
    total: int
    entropy: float
    entropy_values: list[float] | None
    entropy_block_size: int
    dist_counts: list[int] | None
    type_dist: tuple[int, ...] | None
    classification: list[int] | None
    classification_block_size: int


def compute_statistics(document: object, entropy_block_size: int) -> _StatisticsResult:
    """Compute Shannon entropy, byte distribution, and content classification.

    Args:
        document: Hex document object exposing ``byte_statistics`` and
            optionally ``entropy_map``, ``byte_distribution_full``,
            ``byte_type_distribution``, and ``content_classification``.
        entropy_block_size: Block size in bytes used for per-block entropy
            and classification calculations.

    Returns:
        _StatisticsResult: Bundle of all computed statistics.
    """
    doc: Any = document
    stats: list[tuple[int, int]] = list(doc.byte_statistics())
    total: int = sum(s[1] for s in stats)

    entropy: float = 0.0
    if total > 0:
        for _byte_val, count in stats:
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)

    return _StatisticsResult(
        byte_stats=stats,
        total=total,
        entropy=entropy,
        entropy_values=_compute_entropy_map(document, entropy_block_size),
        entropy_block_size=entropy_block_size,
        dist_counts=_compute_byte_distribution(document),
        type_dist=_compute_type_distribution(document),
        classification=_compute_classification(document, entropy_block_size),
        classification_block_size=entropy_block_size,
    )


def _compute_entropy_map(document: object, block_size: int) -> list[float] | None:
    """Compute per-block entropy values from the document.

    Args:
        document: Hex document object.
        block_size: Block size in bytes for entropy calculation.

    Returns:
        list[float] | None: Per-block entropy values, or None if unavailable.
    """
    entropy_map_fn: Any = getattr(document, "entropy_map", None)
    if not callable(entropy_map_fn):
        return None
    try:
        raw_map: list[float] = cast("list[float]", entropy_map_fn(block_size))
        return [float(v) for v in raw_map] if raw_map else []
    except (AttributeError, ValueError, TypeError):
        _logger.exception("entropy_map_failed")
        return None


def _compute_byte_distribution(document: object) -> list[int] | None:
    """Compute the 256-element byte frequency distribution.

    Args:
        document: Hex document object.

    Returns:
        list[int] | None: Byte frequency counts, or None if unavailable.
    """
    dist_fn: Any = getattr(document, "byte_distribution_full", None)
    if not callable(dist_fn):
        return None
    try:
        raw_dist: list[int] = cast("list[int]", dist_fn())
        return [int(v) for v in raw_dist] if raw_dist else [0] * BYTE_VALUES_COUNT
    except (AttributeError, ValueError, TypeError):
        _logger.exception("byte_distribution_failed")
        return None


def _compute_type_distribution(document: object) -> tuple[int, ...] | None:
    """Compute byte type distribution counts.

    Args:
        document: Hex document object.

    Returns:
        tuple[int, ...] | None: Byte type counts, or None if unavailable.
    """
    type_fn: Any = getattr(document, "byte_type_distribution", None)
    if not callable(type_fn):
        return None
    try:
        raw_type: tuple[int, ...] = cast("tuple[int, ...]", type_fn())
        return tuple(int(v) for v in raw_type)
    except (AttributeError, ValueError, TypeError):
        _logger.exception("byte_type_distribution_failed")
        return None


def _compute_classification(document: object, block_size: int) -> list[int] | None:
    """Compute per-block content classification.

    Args:
        document: Hex document object.
        block_size: Block size in bytes used for the classification.

    Returns:
        list[int] | None: Classification values per block, or None if unavailable.
    """
    class_fn: Any = getattr(document, "content_classification", None)
    if not callable(class_fn):
        return None
    try:
        raw_class: list[int] = cast("list[int]", class_fn(block_size))
        return [int(v) for v in raw_class] if raw_class else None
    except (AttributeError, ValueError, TypeError):
        _logger.exception("content_classification_failed")
        return None


class StatisticsMixin:
    """Mixin providing statistics and analysis for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _statistics_tree: QTreeWidget | None
    _entropy_graph: EntropyGraphWidget | None
    _byte_dist_widget: ByteDistributionWidget | None
    _entropy_label: QLabel | None
    _null_pct_label: QLabel | None
    _printable_pct_label: QLabel | None
    _control_pct_label: QLabel | None
    _high_pct_label: QLabel | None
    _classification_label: QLabel | None
    _statistics_worker: GenericCallableWorker | None

    def _update_statistics(self) -> None:
        """Update the statistics tab with entropy graph, histogram, and byte tree.

        Launches a background worker to compute entropy, byte distribution, byte type distribution, and content classification without
        blocking the Qt main thread.  UI widgets display "Computing..." status text until the worker completes.
        """
        if self.document is None:
            return

        worker_attr: GenericCallableWorker | None = getattr(self, "_statistics_worker", None)
        if worker_attr is not None and worker_attr.isRunning():
            _logger.warning("statistics_update_skipped", reason="worker active")
            return

        if worker_attr is not None:
            worker_attr.deleteLater()

        if self._statistics_tree is not None:
            self._statistics_tree.clear()

        self._set_statistics_computing()

        doc_length: int = -1
        length_attr: Any = getattr(self.document, "length", None)
        if callable(length_attr):
            try:
                raw_length: Any = length_attr()
                doc_length = int(raw_length)
            except (TypeError, ValueError, AttributeError) as exc:
                _logger.debug(
                    "statistics_doc_length_unavailable",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
        _logger.info(
            "statistics_update_started",
            doc_length=doc_length,
            block_size=ENTROPY_BLOCK_SIZE,
        )

        parent_obj: QThread | None = self if isinstance(self, QThread) else None
        worker = GenericCallableWorker(
            compute_statistics,
            self.document,
            ENTROPY_BLOCK_SIZE,
            parent=parent_obj,
        )
        _: object = worker.call_finished.connect(self._on_statistics_computed)
        _ = worker.call_error.connect(self._on_statistics_error)
        self._statistics_worker = worker
        worker.start()

    def _set_statistics_computing(self) -> None:
        """Set all statistics labels to the in-progress status text."""
        computing_text: str = "Computing..."
        if self._entropy_label is not None:
            self._entropy_label.setText(computing_text)
        if self._null_pct_label is not None:
            self._null_pct_label.setText(computing_text)
        if self._printable_pct_label is not None:
            self._printable_pct_label.setText(computing_text)
        if self._control_pct_label is not None:
            self._control_pct_label.setText(computing_text)
        if self._high_pct_label is not None:
            self._high_pct_label.setText(computing_text)
        if self._classification_label is not None:
            self._classification_label.setText(computing_text)

    def _on_statistics_computed(self, result: object) -> None:
        """Apply computed statistics results to the UI widgets.

        Called on the main thread when the background worker completes
        successfully.

        Args:
            result: The _StatisticsResult from the background worker.
        """
        if not isinstance(result, _StatisticsResult):
            return

        if result.total == 0:
            self._set_statistics_empty()
            return

        self._apply_byte_tree(result)
        self._apply_entropy_label(result)
        self._apply_entropy_graph(result)
        self._apply_byte_distribution(result)
        self._apply_byte_type_distribution(result)
        self._apply_content_classification(result)

    def _on_statistics_error(self, exc: object) -> None:
        """Handle a statistics worker failure.

        Called on the main thread when the background worker encounters
        an error.

        Args:
            exc: The exception from the background worker.
        """
        _logger.warning("statistics_update_failed", error=str(exc), error_type=type(exc).__name__)
        error_text: str = "\u2014"
        if self._entropy_label is not None:
            self._entropy_label.setText(error_text)
        if self._null_pct_label is not None:
            self._null_pct_label.setText(error_text)
        if self._printable_pct_label is not None:
            self._printable_pct_label.setText(error_text)
        if self._control_pct_label is not None:
            self._control_pct_label.setText(error_text)
        if self._high_pct_label is not None:
            self._high_pct_label.setText(error_text)
        if self._classification_label is not None:
            self._classification_label.setText(error_text)

    def _set_statistics_empty(self) -> None:
        """Reset all statistics labels to the empty em-dash default."""
        dash: str = "\u2014"
        if self._entropy_label is not None:
            self._entropy_label.setText(dash)
        if self._null_pct_label is not None:
            self._null_pct_label.setText(dash)
        if self._printable_pct_label is not None:
            self._printable_pct_label.setText(dash)
        if self._control_pct_label is not None:
            self._control_pct_label.setText(dash)
        if self._high_pct_label is not None:
            self._high_pct_label.setText(dash)
        if self._classification_label is not None:
            self._classification_label.setText(dash)

    def _apply_byte_tree(self, result: _StatisticsResult) -> None:
        """Populate the statistics tree widget with byte frequency data.

        Args:
            result: The computed statistics result.
        """
        if self._statistics_tree is None:
            return
        entropy_item = QTreeWidgetItem(["Entropy", f"{result.entropy:.4f}", "bits/byte"])
        self._statistics_tree.addTopLevelItem(entropy_item)
        for byte_val, count in result.byte_stats:
            if count > 0:
                pct = f"{(count / result.total) * 100:.2f}%"
                item = QTreeWidgetItem([f"0x{byte_val:02X}", str(count), pct])
                self._statistics_tree.addTopLevelItem(item)

    def _apply_entropy_label(self, result: _StatisticsResult) -> None:
        """Set the entropy summary label text.

        Args:
            result: The computed statistics result.
        """
        if self._entropy_label is not None:
            self._entropy_label.setText(f"{result.entropy:.4f} bits/byte")

    def _apply_entropy_graph(self, result: _StatisticsResult) -> None:
        """Update the entropy graph widget with per-block data.

        Args:
            result: The computed statistics result.
        """
        if result.entropy_values is not None and self._entropy_graph is not None:
            self._entropy_graph.set_data(result.entropy_values, result.entropy_block_size)

    def _apply_byte_distribution(self, result: _StatisticsResult) -> None:
        """Update the byte distribution histogram widget.

        Args:
            result: The computed statistics result.
        """
        if result.dist_counts is not None and self._byte_dist_widget is not None:
            self._byte_dist_widget.set_data(result.dist_counts)

    def _apply_byte_type_distribution(self, result: _StatisticsResult) -> None:
        """Apply byte type distribution percentages to labels.

        Args:
            result: The computed statistics result.
        """
        if result.type_dist is None:
            return
        if len(result.type_dist) < BYTE_TYPE_DIST_MIN_LEN:
            return
        null_c: int = int(result.type_dist[0])
        printable_c: int = int(result.type_dist[1])
        control_c: int = int(result.type_dist[2])
        high_c: int = int(result.type_dist[3])
        total_b: int = max(null_c + printable_c + control_c + high_c, 1)
        if self._null_pct_label is not None:
            self._null_pct_label.setText(f"{null_c / total_b * 100:.1f}% ({null_c})")
        if self._printable_pct_label is not None:
            self._printable_pct_label.setText(f"{printable_c / total_b * 100:.1f}% ({printable_c})")
        if self._control_pct_label is not None:
            self._control_pct_label.setText(f"{control_c / total_b * 100:.1f}% ({control_c})")
        if self._high_pct_label is not None:
            self._high_pct_label.setText(f"{high_c / total_b * 100:.1f}% ({high_c})")

    def _apply_content_classification(self, result: _StatisticsResult) -> None:
        """Apply content classification summary to the label.

        Args:
            result: The computed statistics result.
        """
        if result.classification is None:
            return
        if not result.classification:
            return
        class_names: dict[int, str] = {0: "null", 1: "text", 2: "structured", 3: "encrypted", 4: "code"}
        counts: dict[str, int] = {}
        for c_val in result.classification:
            label: str = class_names.get(int(c_val), "unknown")
            counts[label] = counts.get(label, 0) + 1
        parts: list[str] = [f"{k}: {v}" for k, v in counts.items()]
        if self._classification_label is not None:
            self._classification_label.setText(", ".join(parts))

    def _on_refresh_statistics(self) -> None:
        """Manually trigger a statistics refresh."""
        self._update_statistics()

    def _on_show_digram_matrix(self) -> None:
        """Open a dialog displaying the 256x256 byte digram matrix."""
        if self.document is None:
            return

        digram_fn: Any = getattr(self.document, "digram_matrix", None)
        if not callable(digram_fn):
            _logger.debug("digram_matrix_not_available")
            return

        try:
            digram_result: Any = digram_fn()
            raw_matrix: list[int] = [int(v) for v in digram_result]
        except (AttributeError, ValueError, TypeError):
            _logger.exception("digram_matrix_failed")
            return

        parent = self if isinstance(self, QWidget) else None
        dlg = DigramMatrixDialog(raw_matrix, parent)
        dlg.exec()
