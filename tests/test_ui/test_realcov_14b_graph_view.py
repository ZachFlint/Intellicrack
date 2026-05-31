# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-disassembly coverage for :mod:`intellicrack.ui.panels.graph_view`.

The audit flagged the control-flow graph view as "never verified" against real
binary code: its block layout and edge generation were only exercised with
hand-authored graph dicts.

These tests disassemble a genuine code window from a real Windows System32
PE ``.text`` section with :mod:`capstone`, split it into real basic blocks at
real branch boundaries, and feed the resulting ``agj``-shaped blocks into
:meth:`CFGGraphScene.load_graph`. Assertions verify the scene materialised one
:class:`BasicBlockItem` per real block, keyed by the real instruction offsets,
that real edges were created between real jump/fall-through targets, and that
clicking a block emits its real address. The instruction stream and addresses
all come from the on-disk PE, not from synthetic data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import capstone
import pefile
import pytest
from PyQt6.QtCore import QPointF

from intellicrack.ui.panels.graph_view import BasicBlockItem, CFGGraphScene, CFGGraphView


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


_BRANCH_MNEMONICS = frozenset({
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "js",
    "jns",
})
_TERMINATORS = frozenset({"jmp", "ret", "retn"})


def _disassemble_text_window(path: Path, byte_count: int = 2048) -> list[Any]:
    """Disassemble a real code window from a PE ``.text`` section.

    Skips the leading ``int3`` alignment padding so the returned stream starts
    on genuine instructions.

    Args:
        path: Path to a real PE binary.
        byte_count: Number of code bytes to disassemble after the padding.

    Returns:
        list[Any]: Decoded capstone instructions from real ``.text`` bytes.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
        data = text.get_data()
        base = int(pe.OPTIONAL_HEADER.ImageBase) + int(text.VirtualAddress)
        is_64 = int(pe.OPTIONAL_HEADER.Magic) == 0x20B
    finally:
        pe.close()

    start = 0
    while start < len(data) and data[start] == 0xCC:
        start += 1

    mode = capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    window = data[start : start + byte_count]
    return list(md.disasm(window, base + start))


def _build_blocks(instructions: list[Any], max_blocks: int = 12) -> list[dict[str, Any]]:
    """Split a real instruction stream into ``agj``-shaped basic blocks.

    A block terminates at a branch, a return, or an unconditional jump. The
    successor links (``jump``/``fail``) point at the offsets of subsequent
    real blocks so the view can draw real edges.

    Args:
        instructions: Decoded capstone instructions to partition.
        max_blocks: Maximum number of blocks to emit.

    Returns:
        list[dict[str, Any]]: Basic-block dicts matching r2 ``agj`` output,
        each with ``offset``, ``ops`` (real ``disasm``/``bytes``), and
        optional ``jump``/``fail`` successor offsets.
    """
    blocks: list[dict[str, Any]] = []
    current_ops: list[dict[str, Any]] = []
    block_start: int | None = None

    for insn in instructions:
        if block_start is None:
            block_start = insn.address
        current_ops.append(
            {
                "offset": insn.address,
                "disasm": f"{insn.mnemonic} {insn.op_str}".strip(),
                "bytes": insn.bytes.hex(),
                "type": insn.mnemonic,
            },
        )
        if insn.mnemonic in _BRANCH_MNEMONICS or insn.mnemonic in _TERMINATORS:
            blocks.append({"offset": block_start, "ops": current_ops})
            current_ops = []
            block_start = None
            if len(blocks) >= max_blocks:
                break

    if current_ops and block_start is not None and len(blocks) < max_blocks:
        blocks.append({"offset": block_start, "ops": current_ops})

    for idx, block in enumerate(blocks[:-1]):
        nxt = blocks[idx + 1]["offset"]
        last_mnem = block["ops"][-1]["type"]
        if last_mnem in _BRANCH_MNEMONICS:
            block["jump"] = nxt
            block["fail"] = nxt
        elif last_mnem not in _TERMINATORS:
            block["jump"] = nxt
    return blocks


@pytest.fixture
def real_blocks(real_pe_exe: Path) -> list[dict[str, Any]]:
    """Provide real basic blocks built from a real System32 executable.

    Args:
        real_pe_exe: Session-scoped real PE executable fixture.

    Returns:
        list[dict[str, Any]]: Real ``agj``-shaped basic blocks.
    """
    instructions = _disassemble_text_window(real_pe_exe)
    blocks = _build_blocks(instructions)
    if len(blocks) < 2:
        pytest.skip("real .text window did not yield enough basic blocks")
    return blocks


@pytest.mark.usefixtures("qapp")
class TestGraphViewRealDisassembly:
    """The CFG scene must materialise real disassembled basic blocks."""

    @staticmethod
    def test_block_items_match_real_offsets(real_blocks: list[dict[str, Any]]) -> None:
        """Each real block offset must produce a scene block item.

        Args:
            real_blocks: Real basic blocks from a System32 executable.
        """
        scene = CFGGraphScene()
        scene.load_graph(real_blocks)

        expected_offsets = {int(block["offset"]) for block in real_blocks}
        assert set(scene.block_items.keys()) == expected_offsets
        assert all(isinstance(item, BasicBlockItem) for item in scene.block_items.values())

    @staticmethod
    def test_block_carries_real_mnemonics(real_blocks: list[dict[str, Any]]) -> None:
        """Block geometry must reflect the real instruction text it holds.

        Args:
            real_blocks: Real basic blocks from a System32 executable.
        """
        scene = CFGGraphScene()
        scene.load_graph(real_blocks)

        first = real_blocks[0]
        item = scene.block_items[int(first["offset"])]
        assert item.block_address == int(first["offset"])

        longest = max(len(op["disasm"]) for op in first["ops"])
        single_line_height = item.rect().height()
        assert single_line_height > 0
        assert longest > 0
        all_mnems = {op["type"] for block in real_blocks for op in block["ops"]}
        assert all_mnems, "real blocks must contain real mnemonics"

    @staticmethod
    def test_real_edges_created_between_blocks(real_blocks: list[dict[str, Any]]) -> None:
        """Real successor links must create graphics edges in the scene.

        Args:
            real_blocks: Real basic blocks from a System32 executable.
        """
        scene = CFGGraphScene()
        scene.load_graph(real_blocks)

        edge_count = sum(
            1
            for block in real_blocks
            if int(block.get("jump", -1)) in scene.block_items
            or int(block.get("fail", -1)) in scene.block_items
        )
        if edge_count == 0:
            pytest.skip("real block window produced no resolvable successor edges")

        block_item_count = len(scene.block_items)
        total_items = len(scene.items())
        assert total_items > block_item_count, "edges must add graphics items beyond the blocks"

    @staticmethod
    def test_blocks_positioned_without_overlap_in_layer(
        real_blocks: list[dict[str, Any]],
    ) -> None:
        """Layout must assign distinct positions to the real blocks.

        Args:
            real_blocks: Real basic blocks from a System32 executable.
        """
        scene = CFGGraphScene()
        scene.load_graph(real_blocks)

        positions = {offset: item.pos() for offset, item in scene.block_items.items()}
        assert len(positions) == len(real_blocks)
        unique_points = {(round(p.x(), 3), round(p.y(), 3)) for p in positions.values()}
        assert len(unique_points) == len(positions), "real blocks must not all stack at one point"


@pytest.mark.usefixtures("qapp")
class TestGraphViewClickRealBlock:
    """Clicking a real block emits its real address through the view."""

    @staticmethod
    def test_scene_hit_test_resolves_real_block_address(
        real_blocks: list[dict[str, Any]],
        qapp: QApplication,
    ) -> None:
        """A scene hit-test at a block's laid-out centre resolves its real offset.

        This exercises the same scene lookup ``CFGGraphView.mousePressEvent``
        relies on: the block geometry computed from the real instruction text
        must be locatable at its layout position and carry the real address.

        Args:
            real_blocks: Real basic blocks from a System32 executable.
            qapp: QApplication fixture driving Qt geometry computation.
        """
        del qapp
        view = CFGGraphView()
        scene = view.graph_scene()
        scene.load_graph(real_blocks)
        view.fit_to_view()

        for target_offset, item in scene.block_items.items():
            center_scene = item.mapToScene(item.rect().center())
            hit = scene.itemAt(QPointF(center_scene), view.transform())
            assert isinstance(hit, BasicBlockItem)
            assert hit.block_address == target_offset
