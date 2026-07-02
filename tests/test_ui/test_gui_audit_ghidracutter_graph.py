# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression tests for the shared CFG graph view components.

Covers three findings against ``intellicrack.ui.panels.graph_view``:

* M14 -- ``CFGGraphScene.load_graph`` must pin the scene rectangle to the
  current graph's ``itemsBoundingRect`` so a small graph loaded after a large
  one fits to its own bounds rather than the stale (only-growing) implicit rect.
* M16 -- ``NumericSortTreeItem`` must order the Address (hex) and Size (decimal)
  columns numerically, not lexicographically (``0x9`` before ``0x1000``,
  ``20`` before ``100``).
* graph block width -- ``BasicBlockItem`` must size its width from
  ``QFontMetricsF.horizontalAdvance`` of the widest line using the real font,
  not a fixed ``len(text) * 7`` pixels-per-character estimate.
"""

from __future__ import annotations

from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFontMetricsF
from PyQt6.QtWidgets import QTreeWidget

from intellicrack.ui.panels.graph_view import (
    _BLOCK_MIN_WIDTH,
    _BLOCK_PADDING,
    BasicBlockItem,
    CFGGraphScene,
    NumericSortTreeItem,
)
from intellicrack.ui.resources.font_manager import FontManager


_FUNC_COLUMNS = ["Name", "Address", "Size"]

_ADDR_COLUMN = 1
_SIZE_COLUMN = 2


def _linear_chain(count: int, base: int = 0x400000, stride: int = 0x100) -> list[dict[str, Any]]:
    """Build a linear chain of ``count`` basic blocks for layout testing.

    Args:
        count: Number of blocks in the chain.
        base: Address of the first block.
        stride: Address increment between consecutive blocks.

    Returns:
        list[dict[str, Any]]: r2 ``agj``-style block dicts, each jumping to the next.
    """
    blocks: list[dict[str, Any]] = []
    for i in range(count):
        addr = base + i * stride
        block: dict[str, Any] = {"offset": addr, "ops": [{"disasm": "nop"}]}
        if i + 1 < count:
            block["jump"] = base + (i + 1) * stride
        blocks.append(block)
    return blocks


@pytest.mark.usefixtures("qapp")
class TestSceneRectFollowsCurrentGraph:
    """M14: load_graph must reset the scene rect to the current graph bounds."""

    @staticmethod
    def test_small_graph_after_large_shrinks_scene_rect() -> None:
        """A 2-block graph loaded after a 24-block graph must not keep the large rect.

        Regression: ``load_graph`` never called ``setSceneRect``, so the scene's
        implicit rectangle (which only grows) stayed at the large graph's union.
        ``fit_to_view`` then fitted the small graph against the stale union,
        rendering it as a tiny cluster. The fix pins ``sceneRect`` to
        ``itemsBoundingRect`` on every load. If the fix is reverted the small
        rect equals the large rect and both assertions below fail.
        """
        scene = CFGGraphScene()

        scene.load_graph(_linear_chain(24))
        large_rect = scene.sceneRect()
        assert large_rect.height() > 0

        scene.load_graph(_linear_chain(2))
        small_rect = scene.sceneRect()

        assert small_rect == scene.itemsBoundingRect(), "scene rect must equal the current graph's itemsBoundingRect after load_graph"
        assert small_rect.height() < large_rect.height(), (
            f"small graph rect height {small_rect.height()} must shrink below the "
            f"large graph rect height {large_rect.height()}, not keep the stale union"
        )

    @staticmethod
    def test_empty_graph_clears_scene_rect() -> None:
        """Loading an empty block list after a real graph must clear the scene rect.

        Otherwise a subsequent ``fit_to_view`` would fit against the previous
        graph's stale bounds.
        """
        scene = CFGGraphScene()
        scene.load_graph(_linear_chain(6))
        assert not scene.sceneRect().isEmpty()

        scene.load_graph([])
        assert scene.sceneRect().isEmpty(), "empty graph must reset scene rect to a null rectangle"


@pytest.mark.usefixtures("qapp")
class TestNumericSortTreeItem:
    """M16: Address and Size columns must sort numerically, not lexicographically."""

    @staticmethod
    def _build_tree(rows: list[tuple[str, str, str]]) -> QTreeWidget:
        """Create a sortable function tree populated with NumericSortTreeItem rows.

        Args:
            rows: (name, address_hex, size_decimal) tuples for each function row.

        Returns:
            QTreeWidget: Tree widget with sorting enabled and the rows inserted.
        """
        tree = QTreeWidget()
        tree.setColumnCount(len(_FUNC_COLUMNS))
        tree.setHeaderLabels(_FUNC_COLUMNS)
        tree.setSortingEnabled(True)
        for name, addr, size in rows:
            tree.addTopLevelItem(NumericSortTreeItem([name, addr, size]))
        return tree

    @staticmethod
    def _column_order(tree: QTreeWidget, column: int) -> list[str]:
        """Read the top-level items' text for one column in current row order.

        Args:
            tree: The tree widget to read.
            column: Column index to extract.

        Returns:
            list[str]: Cell text for each top-level row, top to bottom.
        """
        values: list[str] = []
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            assert item is not None
            values.append(item.text(column))
        return values

    def test_address_column_sorts_numerically(self) -> None:
        """0x9 must sort before 0x1000 (lexicographic order would invert this)."""
        tree = self._build_tree([
            ("big", "0x1000", "16"),
            ("small", "0x9", "16"),
        ])
        tree.sortItems(_ADDR_COLUMN, Qt.SortOrder.AscendingOrder)
        ordered = self._column_order(tree, _ADDR_COLUMN)
        assert ordered == ["0x9", "0x1000"], f"expected numeric address order, got {ordered}"

    def test_size_column_sorts_numerically(self) -> None:
        """20 must sort before 100 (lexicographic order would place 100 first)."""
        tree = self._build_tree([
            ("a", "0x1000", "100"),
            ("b", "0x2000", "20"),
        ])
        tree.sortItems(_SIZE_COLUMN, Qt.SortOrder.AscendingOrder)
        ordered = self._column_order(tree, _SIZE_COLUMN)
        assert ordered == ["20", "100"], f"expected numeric size order, got {ordered}"

    def test_descending_address_order(self) -> None:
        """Descending sort must place the largest address first, numerically."""
        tree = self._build_tree([
            ("a", "0x9", "1"),
            ("b", "0x1000", "1"),
            ("c", "0x80", "1"),
        ])
        tree.sortItems(_ADDR_COLUMN, Qt.SortOrder.DescendingOrder)
        ordered = self._column_order(tree, _ADDR_COLUMN)
        assert ordered == ["0x1000", "0x80", "0x9"], f"expected descending numeric order, got {ordered}"


@pytest.mark.usefixtures("qapp")
class TestBlockWidthFromFontMetrics:
    """Graph block width must derive from real font metrics, not len * 7 pixels."""

    @staticmethod
    def test_width_matches_font_metrics_advance() -> None:
        """A long disassembly line yields a width equal to its measured advance.

        Regression: width used ``max(len(disasm)) * 7`` fixed pixels-per-char, so
        wide fonts or HiDPI displays clipped long instructions. The fix measures
        the widest line with ``QFontMetricsF.horizontalAdvance`` using the item's
        actual code font. This test recomputes the expected advance with the same
        font and asserts an exact match, which the old ``len * 7`` formula fails.
        """
        long_disasm = "movaps xmmword ptr [rbp - 0x1a0], xmm0"
        block_address = 0x401000
        ops: list[dict[str, Any]] = [{"disasm": long_disasm}]
        item = BasicBlockItem(block_address, ops)

        fm = FontManager.get_instance()
        body_metrics = QFontMetricsF(fm.get_code_font(8))
        header_metrics = QFontMetricsF(fm.get_code_font_bold(8))
        content_width = max(
            body_metrics.horizontalAdvance(long_disasm),
            header_metrics.horizontalAdvance(f"0x{block_address:X}"),
        )
        expected_width = max(float(_BLOCK_MIN_WIDTH), content_width + _BLOCK_PADDING * 2)

        assert item.rect().width() == pytest.approx(expected_width), (
            f"block width {item.rect().width()} must equal font-metric width {expected_width}"
        )

        # The pre-fix code sized the block as a raw ``len(disasm) * 7`` estimate
        # with no padding; the metric-based width adds ``_BLOCK_PADDING * 2``, so
        # the two differ font-independently even when the fallback advance is 7px.
        legacy_width = len(long_disasm) * 7
        assert item.rect().width() != pytest.approx(float(legacy_width)), "block width must not use the raw len*7 estimate"

    @staticmethod
    def test_longer_line_produces_wider_block() -> None:
        """Width must grow monotonically with the measured advance of the widest line."""
        short_item = BasicBlockItem(0x401000, [{"disasm": "ret"}])
        long_item = BasicBlockItem(
            0x401000,
            [{"disasm": "mov rax, qword ptr [rbx + rcx*8 + 0x12345678]"}],
        )
        assert long_item.rect().width() > short_item.rect().width()
        assert long_item.rect().width() > _BLOCK_MIN_WIDTH
