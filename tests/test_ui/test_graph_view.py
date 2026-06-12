# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the CFG graph view components.

Validates BasicBlockItem rendering, EdgeItem construction,
CFGGraphScene layout computation, and CFGGraphView interaction
using real r2 agj-format block data.
"""

from __future__ import annotations

from typing import Any

import pytest
from PyQt6.QtCore import QPointF
from PyQt6.QtGui import QPainter, QTransform
from PyQt6.QtWidgets import QGraphicsItem, QGraphicsView

from intellicrack.ui.panels.graph_view import (
    BasicBlockItem,
    CFGGraphScene,
    CFGGraphView,
    EdgeItem,
)


BLOCK_ADDR_ENTRY = 0x401000
BLOCK_ADDR_TRUE = 0x401020
BLOCK_ADDR_FALSE = 0x401040
BLOCK_ADDR_RET = 0x401060

BLOCK_MIN_WIDTH = 200
FLOAT_EPSILON = 1e-6

EXPECTED_SAMPLE_BLOCK_COUNT = 4
EXPECTED_LINEAR_BLOCK_COUNT = 2
EXPECTED_LINEAR_LAYERS = 3
EXPECTED_BRANCH_LAYERS = 2

LAYOUT_BLOCK_ADDR_A = 0x1000
LAYOUT_BLOCK_ADDR_B = 0x1010
LAYOUT_BLOCK_ADDR_C = 0x1020

SAMPLE_BLOCKS: list[dict[str, Any]] = [
    {
        "offset": BLOCK_ADDR_ENTRY,
        "ops": [
            {"offset": 0x401000, "disasm": "push rbp"},
            {"offset": 0x401001, "disasm": "mov rbp, rsp"},
            {"offset": 0x401004, "disasm": "cmp eax, 0"},
            {"offset": 0x401007, "disasm": "je 0x401040"},
        ],
        "jump": BLOCK_ADDR_TRUE,
        "fail": BLOCK_ADDR_FALSE,
    },
    {
        "offset": BLOCK_ADDR_TRUE,
        "ops": [
            {"offset": 0x401020, "disasm": "mov eax, 1"},
            {"offset": 0x401025, "disasm": "jmp 0x401060"},
        ],
        "jump": BLOCK_ADDR_RET,
    },
    {
        "offset": BLOCK_ADDR_FALSE,
        "ops": [
            {"offset": 0x401040, "disasm": "xor eax, eax"},
            {"offset": 0x401043, "disasm": "jmp 0x401060"},
        ],
        "jump": BLOCK_ADDR_RET,
    },
    {
        "offset": BLOCK_ADDR_RET,
        "ops": [
            {"offset": 0x401060, "disasm": "pop rbp"},
            {"offset": 0x401061, "disasm": "ret"},
        ],
    },
]

LINEAR_BLOCKS: list[dict[str, Any]] = [
    {
        "offset": LAYOUT_BLOCK_ADDR_A,
        "ops": [{"offset": LAYOUT_BLOCK_ADDR_A, "disasm": "nop"}],
        "jump": LAYOUT_BLOCK_ADDR_B,
    },
    {
        "offset": LAYOUT_BLOCK_ADDR_B,
        "ops": [{"offset": LAYOUT_BLOCK_ADDR_B, "disasm": "ret"}],
    },
]


@pytest.mark.usefixtures("qapp")
class TestBasicBlockItem:
    """Tests for BasicBlockItem rendering and geometry."""

    @staticmethod
    def test_block_address_stored() -> None:
        """Verify block_address attribute is set correctly."""
        ops: list[dict[str, Any]] = [{"disasm": "nop"}]
        item = BasicBlockItem(BLOCK_ADDR_ENTRY, ops)
        assert item.block_address == BLOCK_ADDR_ENTRY

    @staticmethod
    def test_rect_dimensions_cover_instructions() -> None:
        """Verify rectangle height grows with instruction count."""
        ops_short: list[dict[str, Any]] = [{"disasm": "nop"}]
        ops_long: list[dict[str, Any]] = [{"disasm": f"instruction_{i}"} for i in range(10)]
        item_short = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, ops_short)
        item_long = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, ops_long)
        assert item_long.rect().height() > item_short.rect().height()

    @staticmethod
    def test_min_width_enforced() -> None:
        """Verify minimum width is applied for short instructions."""
        ops: list[dict[str, Any]] = [{"disasm": "nop"}]
        item = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, ops)
        assert item.rect().width() >= BLOCK_MIN_WIDTH

    @staticmethod
    def test_width_grows_for_long_instructions() -> None:
        """Verify width grows beyond minimum to accommodate long disassembly text.

        The production formula is: text_width = max_disasm_chars * 7,
        width = max(BLOCK_MIN_WIDTH, text_width + BLOCK_PADDING * 2).
        For a 47-character instruction: text_width=329, width=349.
        For a 3-character "nop": text_width=21, width=200 (clamped to minimum).
        The long-instruction item must be strictly wider than both the minimum
        and the short-instruction item, proving the scaling path is active.
        """
        long_disasm = "mov rax, qword ptr [rbx + rcx*8 + 0x12345678]"
        short_disasm = "nop"
        long_ops: list[dict[str, Any]] = [{"disasm": long_disasm}]
        short_ops: list[dict[str, Any]] = [{"disasm": short_disasm}]
        long_item = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, long_ops)
        short_item = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, short_ops)

        long_char_count = len(long_disasm)
        short_char_count = len(short_disasm)
        chars_per_pixel: int = 7
        block_padding: int = 10

        expected_long_width = max(BLOCK_MIN_WIDTH, long_char_count * chars_per_pixel + block_padding * 2)
        expected_short_width = max(BLOCK_MIN_WIDTH, short_char_count * chars_per_pixel + block_padding * 2)

        assert long_item.rect().width() == expected_long_width, (
            f"long instruction width {long_item.rect().width()} != expected {expected_long_width}"
        )
        assert short_item.rect().width() == expected_short_width, (
            f"short instruction width {short_item.rect().width()} != expected {expected_short_width}"
        )
        assert long_item.rect().width() > BLOCK_MIN_WIDTH, (
            f"long instruction width {long_item.rect().width()} must exceed BLOCK_MIN_WIDTH={BLOCK_MIN_WIDTH}"
        )
        assert long_item.rect().width() > short_item.rect().width(), (
            f"long width {long_item.rect().width()} must exceed short width {short_item.rect().width()}"
        )

    @staticmethod
    def test_empty_ops_handled() -> None:
        """Verify an empty ops list produces a block with the exact header+padding height.

        With zero instructions the height formula yields:
        _HEADER_HEIGHT + 0 * _LINE_HEIGHT + _BLOCK_PADDING = 22 + 0 + 10 = 32.
        A single-instruction block must be strictly taller (22 + 1*16 + 10 = 48),
        proving the instruction-count dimension is not dead code.
        """
        header_height: int = 22
        line_height: int = 16
        block_padding: int = 10
        expected_empty_height = header_height + 0 * line_height + block_padding

        item_empty = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, [])
        item_one_op = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, [{"disasm": "nop"}])

        assert item_empty.block_address == LAYOUT_BLOCK_ADDR_A
        assert item_empty.rect().height() == expected_empty_height, (
            f"empty-ops height {item_empty.rect().height()} != expected {expected_empty_height}"
        )
        assert item_one_op.rect().height() > item_empty.rect().height(), (
            "single-instruction block must be taller than zero-instruction block"
        )

    @staticmethod
    def test_selectable_flag_set() -> None:
        """Verify the item has the selectable flag enabled."""
        ops: list[dict[str, Any]] = [{"disasm": "ret"}]
        item = BasicBlockItem(LAYOUT_BLOCK_ADDR_A, ops)
        flags = item.flags()
        assert flags & QGraphicsItem.GraphicsItemFlag.ItemIsSelectable


@pytest.mark.usefixtures("qapp")
class TestEdgeItem:
    """Tests for EdgeItem edge construction and typing."""

    @staticmethod
    def test_true_edge_type() -> None:
        """Verify true branch edge type is stored."""
        edge = EdgeItem(QPointF(0, 0), QPointF(100, 100), "true")
        assert edge.edge_type == "true"

    @staticmethod
    def test_false_edge_type() -> None:
        """Verify false branch edge type is stored."""
        edge = EdgeItem(QPointF(0, 0), QPointF(100, 100), "false")
        assert edge.edge_type == "false"

    @staticmethod
    def test_unconditional_edge_default() -> None:
        """Verify default edge type is unconditional."""
        edge = EdgeItem(QPointF(0, 0), QPointF(100, 100))
        assert edge.edge_type == "unconditional"

    @staticmethod
    def test_path_is_set() -> None:
        """Verify the QPainterPath is non-empty."""
        edge = EdgeItem(QPointF(50, 0), QPointF(50, 200), "true")
        path = edge.path()
        assert not path.isEmpty()

    @staticmethod
    def test_pen_is_set() -> None:
        """Verify the edge has a pen with non-zero width."""
        edge = EdgeItem(QPointF(0, 0), QPointF(100, 100), "false")
        assert edge.pen().widthF() > 0


@pytest.mark.usefixtures("qapp")
class TestCFGGraphScene:
    """Tests for CFGGraphScene layout and block parsing."""

    @staticmethod
    def test_load_graph_creates_blocks() -> None:
        """Verify load_graph creates BasicBlockItem for each block."""
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        assert len(scene.block_items) == len(SAMPLE_BLOCKS)

    @staticmethod
    def test_load_graph_stores_correct_addresses() -> None:
        """Verify block items are keyed by correct addresses."""
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        expected = {BLOCK_ADDR_ENTRY, BLOCK_ADDR_TRUE, BLOCK_ADDR_FALSE, BLOCK_ADDR_RET}
        assert set(scene.block_items.keys()) == expected

    @staticmethod
    def test_load_graph_positions_blocks() -> None:
        """Verify blocks receive non-origin positions after layout.

        At least two distinct block positions must exist: the entry block and
        the return block must be on different Y levels because the layout
        algorithm assigns layers top-to-bottom.
        """
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        entry_y = scene.block_items[BLOCK_ADDR_ENTRY].pos().y()
        ret_y = scene.block_items[BLOCK_ADDR_RET].pos().y()
        assert ret_y > entry_y, f"return block (y={ret_y}) must be below entry block (y={entry_y}) in layered layout"

    @staticmethod
    def test_load_graph_creates_edges() -> None:
        """Verify exactly 4 edges are created for SAMPLE_BLOCKS directed connections.

        SAMPLE_BLOCKS defines these directed edges:
          entry -> true_branch  (true/conditional)
          entry -> false_branch (false/conditional)
          true_branch -> ret    (unconditional)
          false_branch -> ret   (unconditional)
        Total: exactly 4 EdgeItem instances. Any fewer means a creation path is broken.
        """
        expected_edge_count = 4
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        edge_count = sum(isinstance(item, EdgeItem) for item in scene.items())
        assert edge_count == expected_edge_count, f"expected exactly {expected_edge_count} edges for SAMPLE_BLOCKS, got {edge_count}"

    @staticmethod
    def test_conditional_creates_true_and_false_edges() -> None:
        """Verify conditional blocks produce true and false edge types."""
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        edge_types = {item.edge_type for item in scene.items() if isinstance(item, EdgeItem)}
        assert "true" in edge_types
        assert "false" in edge_types

    @staticmethod
    def test_load_empty_graph() -> None:
        """Verify load_graph handles empty block list gracefully."""
        scene = CFGGraphScene()
        scene.load_graph([])
        assert len(scene.block_items) == 0

    @staticmethod
    def test_load_graph_clears_previous() -> None:
        """Verify load_graph clears previous blocks before loading new."""
        scene = CFGGraphScene()
        scene.load_graph(SAMPLE_BLOCKS)
        assert len(scene.block_items) == EXPECTED_SAMPLE_BLOCK_COUNT
        scene.load_graph(LINEAR_BLOCKS)
        assert len(scene.block_items) == EXPECTED_LINEAR_BLOCK_COUNT

    @staticmethod
    def test_compute_layers_linear() -> None:
        """Verify linear block chain produces sequential layers."""
        block_map: dict[int, dict[str, Any]] = {
            LAYOUT_BLOCK_ADDR_A: {"jump": LAYOUT_BLOCK_ADDR_B},
            LAYOUT_BLOCK_ADDR_B: {"jump": LAYOUT_BLOCK_ADDR_C},
            LAYOUT_BLOCK_ADDR_C: {},
        }
        layers = CFGGraphScene._compute_layers(block_map)
        assert len(layers) == EXPECTED_LINEAR_LAYERS
        assert layers[0] == [LAYOUT_BLOCK_ADDR_A]
        assert layers[1] == [LAYOUT_BLOCK_ADDR_B]
        assert layers[2] == [LAYOUT_BLOCK_ADDR_C]

    @staticmethod
    def test_compute_layers_branching() -> None:
        """Verify conditional branch places targets in same layer."""
        block_map: dict[int, dict[str, Any]] = {
            LAYOUT_BLOCK_ADDR_A: {"jump": LAYOUT_BLOCK_ADDR_B, "fail": LAYOUT_BLOCK_ADDR_C},
            LAYOUT_BLOCK_ADDR_B: {},
            LAYOUT_BLOCK_ADDR_C: {},
        }
        layers = CFGGraphScene._compute_layers(block_map)
        assert len(layers) == EXPECTED_BRANCH_LAYERS
        assert LAYOUT_BLOCK_ADDR_A in layers[0]
        layer1 = set(layers[1])
        assert LAYOUT_BLOCK_ADDR_B in layer1
        assert LAYOUT_BLOCK_ADDR_C in layer1

    @staticmethod
    def test_compute_layers_empty() -> None:
        """Verify empty block map returns empty layers."""
        layers = CFGGraphScene._compute_layers({})
        assert layers == {}

    @staticmethod
    def test_blocks_with_missing_ops_key() -> None:
        """Verify blocks without ops key are handled."""
        scene = CFGGraphScene()
        blocks: list[dict[str, Any]] = [{"offset": LAYOUT_BLOCK_ADDR_A}]
        scene.load_graph(blocks)
        assert LAYOUT_BLOCK_ADDR_A in scene.block_items

    @staticmethod
    def test_blocks_with_non_list_ops() -> None:
        """Verify blocks with non-list ops value are handled."""
        scene = CFGGraphScene()
        blocks: list[dict[str, Any]] = [{"offset": LAYOUT_BLOCK_ADDR_A, "ops": "invalid"}]
        scene.load_graph(blocks)
        assert LAYOUT_BLOCK_ADDR_A in scene.block_items


@pytest.mark.usefixtures("qapp")
class TestCFGGraphView:
    """Tests for CFGGraphView widget interaction."""

    @staticmethod
    def test_construction() -> None:
        """Verify CFGGraphView is constructed with the required rendering properties.

        The constructor must set:
          - Antialiasing render hint (smooth edge bezier curves)
          - ScrollHandDrag drag mode (pan with mouse)
          - AnchorUnderMouse transformation anchor (zoom toward cursor)
          - Background brush color matching the theme background
        Failure to set any of these properties means the view will render
        or behave incorrectly for users, and this test will go red.
        """
        view = CFGGraphView()

        assert view.scene() is not None, "scene must not be None after construction"
        assert view.renderHints() & QPainter.RenderHint.Antialiasing, "Antialiasing render hint must be set for smooth edge rendering"
        assert view.dragMode() == QGraphicsView.DragMode.ScrollHandDrag, f"drag mode must be ScrollHandDrag, got {view.dragMode()}"
        assert view.transformationAnchor() == QGraphicsView.ViewportAnchor.AnchorUnderMouse, (
            f"transformation anchor must be AnchorUnderMouse, got {view.transformationAnchor()}"
        )
        bg_color = view.backgroundBrush().color()
        assert bg_color.isValid(), "background brush color must be a valid QColor"
        assert bg_color.alpha() > 0, "background brush color must not be fully transparent"

    @staticmethod
    def test_graph_scene_accessor() -> None:
        """Verify graph_scene returns a CFGGraphScene instance."""
        view = CFGGraphView()
        scene = view.graph_scene()
        assert isinstance(scene, CFGGraphScene)

    @staticmethod
    def test_fit_to_view_no_error() -> None:
        """Verify fit_to_view adjusts the view transform when the graph is loaded.

        After loading SAMPLE_BLOCKS the scene rectangle is non-empty.  Calling
        fit_to_view must invoke fitInView, which changes the view transform from
        the identity to a scaled version.  If fit_to_view is a no-op or the
        fitInView call is removed, the transform stays at identity and this test
        goes red.
        """
        view = CFGGraphView()
        view.graph_scene().load_graph(SAMPLE_BLOCKS)

        qt_scene = view.scene()
        assert qt_scene is not None, "scene must not be None after loading graph"
        scene_rect = qt_scene.sceneRect()
        assert not scene_rect.isEmpty(), "scene rect must be non-empty after loading SAMPLE_BLOCKS"

        identity = QTransform()
        view.fit_to_view()
        transform_after = view.transform()

        assert transform_after != identity, (
            "fit_to_view must scale the view transform to fit a non-empty scene; identity transform means fitInView was not called"
        )

    @staticmethod
    def test_fit_to_view_empty_scene() -> None:
        """Verify fit_to_view is safe on an empty scene and leaves transform at identity.

        With no blocks loaded the scene rectangle is empty (null QRectF).
        Qt's fitInView is a no-op for an empty rect, so the view transform must
        remain at or near identity.  If fit_to_view raises or mutates the
        transform unexpectedly on an empty scene, this test goes red.
        """
        view = CFGGraphView()
        identity = QTransform()

        view.fit_to_view()

        transform_after = view.transform()
        assert transform_after == identity, f"empty-scene fit_to_view must leave transform at identity; got {transform_after}"

    @staticmethod
    def test_load_and_display_full_graph() -> None:
        """Verify loading sample blocks populates the scene with the correct item mix.

        SAMPLE_BLOCKS defines 4 basic blocks with 4 directed edges (entry->true,
        entry->false, true->ret, false->ret).  The scene must contain exactly
        4 ``BasicBlockItem`` instances and at least 4 ``EdgeItem`` instances.
        """
        view = CFGGraphView()
        view.graph_scene().load_graph(SAMPLE_BLOCKS)
        all_items = view.scene().items()
        block_items = [i for i in all_items if isinstance(i, BasicBlockItem)]
        edge_items = [i for i in all_items if isinstance(i, EdgeItem)]
        assert len(block_items) == EXPECTED_SAMPLE_BLOCK_COUNT, (
            f"expected {EXPECTED_SAMPLE_BLOCK_COUNT} BasicBlockItems, got {len(block_items)}"
        )
        assert len(edge_items) >= 4, f"expected at least 4 EdgeItems for 4 directed edges, got {len(edge_items)}"
