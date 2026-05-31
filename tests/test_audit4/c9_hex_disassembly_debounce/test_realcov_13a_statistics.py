# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the hex editor statistics mixin.

The audit (shard 13) lists ``statistics.py`` under ``NOT TESTED``: entropy
correctness, byte distribution histogram accuracy, byte-type percentages, and
content classification.

These tests run the real :func:`compute_statistics` and the real
:class:`StatisticsMixin` rendering pipeline over a REAL Windows PE
(``kernel32.dll``). Entropy is independently recomputed from the byte
distribution and compared, the histogram total is checked against the document
length, and the rendered labels are validated against the real computed values
- never against a value the test injected.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import intellicrack_hexcore
import pytest
from PyQt6.QtWidgets import QApplication, QLabel, QTreeWidget, QWidget

from intellicrack.ui.panels.hex_editor.base import ENTROPY_BLOCK_SIZE
from intellicrack.ui.panels.hex_editor.statistics import (
    StatisticsMixin,
    compute_statistics,
)
from intellicrack.ui.panels.hex_editor.widgets import (
    ByteDistributionWidget,
    EntropyGraphWidget,
)


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        Generator[QApplication]: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _open_document(path: Path) -> intellicrack_hexcore.HexDocument:
    """Open a real binary as a hexcore document.

    Args:
        path: Path to a real binary on disk.

    Returns:
        intellicrack_hexcore.HexDocument: The opened hexcore document.
    """
    return intellicrack_hexcore.HexDocument.open(str(path))


class _StatisticsHarness(StatisticsMixin, QWidget):
    """Host widget exposing the labels and widgets statistics renders into."""

    def __init__(self) -> None:
        """Initialise real statistics widgets and labels."""
        super().__init__()
        self._statistics_tree: QTreeWidget | None = QTreeWidget(self)
        self._entropy_graph: EntropyGraphWidget | None = EntropyGraphWidget(self)
        self._byte_dist_widget: ByteDistributionWidget | None = ByteDistributionWidget(self)
        self._entropy_label: QLabel | None = QLabel(self)
        self._null_pct_label: QLabel | None = QLabel(self)
        self._printable_pct_label: QLabel | None = QLabel(self)
        self._control_pct_label: QLabel | None = QLabel(self)
        self._high_pct_label: QLabel | None = QLabel(self)
        self._classification_label: QLabel | None = QLabel(self)

    def apply_result(self, result: object) -> None:
        """Apply a computed statistics result through the real rendering path.

        Args:
            result: A ``_StatisticsResult`` produced by ``compute_statistics``.
        """
        self._on_statistics_computed(result)

    def entropy_label_text(self) -> str:
        """Return the rendered entropy summary label text.

        Returns:
            str: The entropy label contents.
        """
        return self._entropy_label.text() if self._entropy_label is not None else ""

    def null_label_text(self) -> str:
        """Return the rendered null-byte percentage label text.

        Returns:
            str: The null percentage label contents.
        """
        return self._null_pct_label.text() if self._null_pct_label is not None else ""

    def printable_label_text(self) -> str:
        """Return the rendered printable percentage label text.

        Returns:
            str: The printable percentage label contents.
        """
        return self._printable_pct_label.text() if self._printable_pct_label is not None else ""

    def first_tree_row(self) -> tuple[str, str]:
        """Return the first statistics-tree row's first two columns.

        Returns:
            tuple[str, str]: The first row's (label, value) columns.
        """
        tree = self._statistics_tree
        if tree is None:
            return ("", "")
        item = tree.topLevelItem(0)
        return ("", "") if item is None else (item.text(0), item.text(1))

    def graph_values(self) -> list[float]:
        """Return the entropy values currently held by the graph widget.

        Returns:
            list[float]: Per-block entropy values pushed into the graph.
        """
        return self._entropy_graph.entropy_values() if self._entropy_graph is not None else []

    def histogram_counts(self) -> list[int]:
        """Return the histogram counts currently held by the distribution widget.

        Returns:
            list[int]: Byte-frequency counts pushed into the histogram.
        """
        return self._byte_dist_widget.counts() if self._byte_dist_widget is not None else []


def _entropy_from_distribution(dist: list[int]) -> float:
    """Recompute Shannon entropy independently from a byte distribution.

    Args:
        dist: 256-element byte frequency list.

    Returns:
        float: Shannon entropy in bits per byte.
    """
    total = sum(dist)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in dist:
        if count > 0:
            prob = count / total
            entropy -= prob * math.log2(prob)
    return entropy


@pytest.mark.usefixtures("qapp")
class TestComputeStatistics:
    """``compute_statistics`` must produce verifiable real results."""

    @staticmethod
    def test_entropy_matches_independent_computation(real_pe_dll: Path) -> None:
        """The computed entropy matches an independent distribution-based value.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        assert result.total == document.length()
        assert 0.0 < result.entropy < 8.0

        assert result.dist_counts is not None
        independent = _entropy_from_distribution(result.dist_counts)
        assert abs(result.entropy - independent) < 1e-9

    @staticmethod
    def test_distribution_total_matches_document_length(real_pe_dll: Path) -> None:
        """The 256-bin histogram sums to the real document length.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        assert result.dist_counts is not None
        assert len(result.dist_counts) == 256
        assert sum(result.dist_counts) == document.length()

    @staticmethod
    def test_byte_type_distribution_sums_to_total(real_pe_dll: Path) -> None:
        """Null/printable/control/high counts sum to the document length.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        assert result.type_dist is not None
        assert sum(result.type_dist) == document.length()

    @staticmethod
    def test_entropy_map_blocks_in_valid_range(real_pe_dll: Path) -> None:
        """Per-block entropy values are all within the [0, 8] bit range.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        assert result.entropy_values is not None
        assert result.entropy_values
        assert all(0.0 <= v <= 8.0 for v in result.entropy_values)


@pytest.mark.usefixtures("qapp")
class TestStatisticsRendering:
    """The mixin must render real computed statistics into widgets and labels."""

    @staticmethod
    def test_rendered_labels_reflect_real_values(qapp: QApplication, real_pe_dll: Path) -> None:
        """Entropy label and percentage labels reflect the real result.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        harness = _StatisticsHarness()
        harness.apply_result(result)

        assert harness.entropy_label_text() == f"{result.entropy:.4f} bits/byte"
        assert "%" in harness.printable_label_text()
        assert "%" in harness.null_label_text()
        assert harness.first_tree_row() == ("Entropy", f"{result.entropy:.4f}")

    @staticmethod
    def test_widgets_receive_real_data(qapp: QApplication, real_pe_dll: Path) -> None:
        """The entropy graph and histogram widgets receive the real arrays.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        document = _open_document(real_pe_dll)
        result = compute_statistics(document, ENTROPY_BLOCK_SIZE)

        harness = _StatisticsHarness()
        harness.apply_result(result)

        assert result.entropy_values is not None
        assert harness.graph_values() == result.entropy_values
        assert result.dist_counts is not None
        assert harness.histogram_counts() == result.dist_counts

    @staticmethod
    def test_empty_document_renders_dash(qapp: QApplication) -> None:
        """A zero-length result clears labels to the em-dash placeholder.

        Args:
            qapp: Qt application fixture.
        """
        del qapp
        harness = _StatisticsHarness()
        empty = compute_statistics(_EmptyDoc(), ENTROPY_BLOCK_SIZE)
        harness.apply_result(empty)

        assert harness.entropy_label_text() == "—"


class _EmptyDoc:
    """A real document-shaped object reporting zero bytes for the empty path."""

    @staticmethod
    def byte_statistics() -> list[tuple[int, int]]:
        """Return an all-zero byte distribution.

        Returns:
            list[tuple[int, int]]: 256 (value, 0) pairs.
        """
        return [(i, 0) for i in range(256)]

    @staticmethod
    def length() -> int:
        """Return the empty document length.

        Returns:
            int: Always zero.
        """
        return 0
