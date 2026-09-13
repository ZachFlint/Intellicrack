# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the S20-D10 Ghidra CFG rendering fix.

Before this fix, ``ui/panels/graph_view.py`` only understood the Cutter/Rizin
``agj``/``afbj`` block shape (blocks keyed by ``offset``, edges from ``jump``/
``fail``). Ghidra's ``get_basic_blocks`` bridge method returns a different
shape (blocks keyed by ``start``, edges via ``destinations``/
``destination_edges``), so every Ghidra block fell back to the default
``block.get("offset", 0)`` of ``0``, collapsing every distinct basic block
onto scene key ``0`` and producing exactly the observed bug: a CFG showing a
single block labeled ``"0x0"`` with no edges, regardless of how many real
basic blocks and branches the function actually had.

These tests build ``CFGGraphScene`` with the exact Ghidra ``get_basic_blocks``
block shape -- three real basic blocks with real 64-bit addresses and real
``destination_edges`` flow-type data, mirroring the audit's own
``S20_CFG_CHECK`` ground truth of 3 basic blocks for ``FUN_140027780`` -- and
assert on the real, populated ``CFGGraphScene.block_items`` mapping and real
``EdgeItem`` instances added to the scene. No part of the scene or its block
map is mocked or stubbed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.graph_view import CFGGraphScene, EdgeItem


if TYPE_CHECKING:
    from collections.abc import Generator


_ENTRY_ADDR: Final[int] = 0x140027780
_TRUE_BRANCH_ADDR: Final[int] = 0x140027790
_MERGE_ADDR: Final[int] = 0x1400277A0

_EXPECTED_BLOCK_COUNT: Final[int] = 3
_EXPECTED_EDGE_COUNT: Final[int] = 3
_EXPECTED_EDGE_TYPES: Final[tuple[str, ...]] = ("false", "true", "unconditional")


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test module.

    Qt requires exactly one QApplication instance per process; this fixture
    creates one for the module (or reuses an existing instance) so
    ``CFGGraphScene`` and its ``BasicBlockItem``/``EdgeItem`` children can be
    constructed without conflicting on the singleton.

    Yields:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _ghidra_shaped_blocks() -> list[dict[str, Any]]:
    """Build a 3-block Ghidra ``get_basic_blocks`` payload for a synthetic if/merge function.

    Mirrors the shape ``GhidraBridge.get_basic_blocks`` now returns: each
    block carries ``start``/``end`` (no ``offset``), and edges are carried
    through ``destination_edges`` (no top-level ``jump``/``fail``). The
    entry block conditionally branches to the true-branch block and falls
    through to the merge block; the true-branch block then falls through to
    the merge block, which has no successors (a return block).

    Returns:
        list[dict[str, Any]]: Basic block dicts in the exact
        ``get_basic_blocks`` result shape.
    """
    return [
        {
            "start": _ENTRY_ADDR,
            "end": _ENTRY_ADDR + 0xF,
            "sources": [],
            "destinations": [_TRUE_BRANCH_ADDR, _MERGE_ADDR],
            "destination_edges": [
                {
                    "address": _TRUE_BRANCH_ADDR,
                    "is_conditional": True,
                    "is_fallthrough": False,
                    "is_call": False,
                },
                {
                    "address": _MERGE_ADDR,
                    "is_conditional": False,
                    "is_fallthrough": True,
                    "is_call": False,
                },
            ],
        },
        {
            "start": _TRUE_BRANCH_ADDR,
            "end": _TRUE_BRANCH_ADDR + 0xF,
            "sources": [_ENTRY_ADDR],
            "destinations": [_MERGE_ADDR],
            "destination_edges": [
                {
                    "address": _MERGE_ADDR,
                    "is_conditional": False,
                    "is_fallthrough": True,
                    "is_call": False,
                },
            ],
        },
        {
            "start": _MERGE_ADDR,
            "end": _MERGE_ADDR + 0xF,
            "sources": [_ENTRY_ADDR, _TRUE_BRANCH_ADDR],
            "destinations": [],
            "destination_edges": [],
        },
    ]


class TestGhidraBlockAddressing:
    """S20-D10: Ghidra-shaped blocks are keyed by their real start address."""

    def test_three_ghidra_blocks_keep_distinct_real_addresses(self, qapp: QApplication) -> None:
        """Three Ghidra basic blocks produce three distinct, non-zero scene keys.

        Before the fix, every block here would collapse onto scene key ``0``
        (the ``block.get("offset", 0)`` fallback) because none of them carry
        an ``offset`` key, reproducing the audit's observed single
        ``"0x0"`` block for a function verified to have 3 real basic blocks.

        Args:
            qapp: Session/module QApplication fixture.
        """
        del qapp
        scene = CFGGraphScene()
        scene.load_graph(_ghidra_shaped_blocks())

        assert len(scene.block_items) == _EXPECTED_BLOCK_COUNT
        assert 0 not in scene.block_items, "no block may collapse onto the offset-fallback key 0"
        assert set(scene.block_items) == {_ENTRY_ADDR, _TRUE_BRANCH_ADDR, _MERGE_ADDR}

        entry_item = scene.block_items[_ENTRY_ADDR]
        assert entry_item.block_address == _ENTRY_ADDR


class TestGhidraDestinationEdges:
    """S20-D10: Ghidra ``destination_edges`` render as real scene edges."""

    def test_destination_edges_render_with_correct_branch_types(self, qapp: QApplication) -> None:
        """All 3 destination edges are added to the scene with the right branch coloring.

        The entry block's conditional destination renders as a ``"true"``
        edge and its fallthrough destination as ``"false"`` (since the same
        block also has a conditional edge); the true-branch block's sole
        fallthrough destination renders as ``"unconditional"`` (it has no
        sibling conditional edge to pair against). Before the fix, Ghidra
        blocks carried no ``jump``/``fail`` keys, so ``_create_edges`` built
        zero edges for them regardless of how many real successors existed.

        Args:
            qapp: Session/module QApplication fixture.
        """
        del qapp
        scene = CFGGraphScene()
        scene.load_graph(_ghidra_shaped_blocks())

        edge_items = [item for item in scene.items() if isinstance(item, EdgeItem)]
        assert len(edge_items) == _EXPECTED_EDGE_COUNT

        assert tuple(sorted(item.edge_type for item in edge_items)) == _EXPECTED_EDGE_TYPES

    def test_entry_block_is_laid_out_above_every_block_it_reaches(self, qapp: QApplication) -> None:
        """The entry block, never a destination of any other block, is laid out at the top of the scene.

        Exercises the Ghidra branch of ``_compute_layers`` (the loop that walks
        ``destination_edges`` to build the ``successors``/``referenced`` sets
        for blocks with no ``jump``/``fail`` keys): only a block that is never
        referenced as someone else's destination becomes a layer-0 root, and
        :meth:`CFGGraphScene._position_layers` always gives layer 0 the
        smallest y-offset. Before the fix, every block here collapsed onto a
        single scene item at key 0, so this real, on-screen y-ordering could
        not exist at all.

        Args:
            qapp: Session/module QApplication fixture.
        """
        del qapp
        scene = CFGGraphScene()
        scene.load_graph(_ghidra_shaped_blocks())

        entry_y = scene.block_items[_ENTRY_ADDR].pos().y()
        true_branch_y = scene.block_items[_TRUE_BRANCH_ADDR].pos().y()
        merge_y = scene.block_items[_MERGE_ADDR].pos().y()

        assert entry_y < true_branch_y, "the entry block must be laid out above the block it conditionally branches to"
        assert entry_y < merge_y, "the entry block must be laid out above the block it falls through to"
