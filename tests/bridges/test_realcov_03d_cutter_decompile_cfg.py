# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-backend regression tests for CutterBridge decompilation and CFG rendering.

Covers two defects found against a real rizin 0.9.1 backend:

* S15-D01: ``CutterBridge.decompile`` ran the nonexistent ``pdc`` command
  (rizin 0.9.1 ships no native decompiler) and then fell back to ``pdg``
  without ever configuring ``ghidra.sleighhome``, so every call failed with
  "No sleigh specification for <language id>" and the Decompiler tab stayed
  blank. The fix drops ``pdc``, resolves and configures
  ``ghidra.sleighhome`` from the resolved backend's install directory, and
  uses an extended timeout for the SLEIGH-loading first ``pdg`` call.
* S15-D02: ``CutterBridge.get_function_graph`` issued ``agj @ addr``, which
  returns empty output against rizin 0.9.1, so the CFG tab always rendered
  an empty graph. The fix builds the graph from ``afbj`` (basic-block JSON,
  which real gates in this same suite already prove returns real data) plus
  a ``pdj`` call per block for the block's real disassembled instructions.

Every assertion here is anchored to output computed by a genuine rizin
process against a real, on-disk PE (``kernel32.dll``), never a canned or
mocked ``rzpipe``/``r2pipe`` response. Tests carry the ``spawns_process``
marker (each fixture spawns an external rizin subprocess) and skip outright
when no rizin/radare2 binary is discoverable on ``PATH``, matching the
real-backend gating already established in ``test_realcov_03c_cutter.py``.

Both defects are specific to the rizin 0.9.1 backend the application ships
(``agj`` returns empty and ``pdg`` requires the bundled rz-ghidra plugin),
neither of which reproduces against the radare2 5.9.8 build inside the CI
container. The five behavioral tests -- the two decompiler tests and the
three positive CFG tests -- are therefore registered as ``host_native`` (in
``tests/_helpers/host_native.py``) so they run against the real host rizin
where reverting either fix genuinely turns them red; the two backend-agnostic
``ToolError`` guard tests keep running inside the container.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest
import pytest_asyncio

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = [pytest.mark.spawns_process, pytest.mark.asyncio]


async def _make_bridge_or_skip() -> CutterBridge:
    """Build a bridge whose backend is available, or skip the test.

    Returns:
        CutterBridge: A fresh bridge with a confirmed rizin/radare2 backend.
    """
    bridge = CutterBridge()
    if not await bridge.is_available():
        pytest.skip("rizin/radare2 backend not discoverable on PATH")
    return bridge


@pytest_asyncio.fixture
async def pe_bridge(real_pe_dll: Path) -> AsyncIterator[CutterBridge]:
    """Load and quick-analyze a real System32 PE DLL with the real backend.

    Args:
        real_pe_dll: Session fixture resolving ``kernel32.dll`` from System32.

    Yields:
        CutterBridge: Bridge with ``kernel32.dll`` loaded and analyzed.
    """
    bridge = await _make_bridge_or_skip()
    try:
        await bridge.load_binary(real_pe_dll)
        await bridge.analyze("quick")
        yield bridge
    finally:
        await bridge.shutdown()


async def _first_sized_function(bridge: CutterBridge, *, min_blocks: int = 1) -> int:
    """Return the address of an analyzed function with at least ``min_blocks`` real basic blocks.

    Scans the real analyzed function list (largest functions first, since
    ``kernel32.dll``'s earliest-discovered functions are sometimes tiny
    thunks) so both single-block and multi-block callers reliably find a
    genuine candidate instead of depending on incidental function order.

    Args:
        bridge: Analyzed bridge to query.
        min_blocks: Minimum number of real basic blocks the returned
            function's control flow graph must contain.

    Returns:
        int: Address of a real analyzed function meeting the block-count
        requirement.
    """
    funcs = await bridge.get_functions()
    candidates = sorted((f for f in funcs if f.size > 8), key=lambda f: f.size, reverse=True)
    for func in candidates[:200]:
        blocks = await bridge.get_basic_blocks(func.address)
        if len(blocks) >= min_blocks:
            return func.address
    pytest.skip(f"analysis produced no function with at least {min_blocks} real basic block(s) among the first 200 candidates")


class TestRealDecompileGhidra:
    """S15-D01: rz-ghidra ``pdg``-based decompilation produces real C-like output."""

    async def test_decompile_produces_c_like_tokens(self, pe_bridge: CutterBridge) -> None:
        """Decompiling a real, non-thunk function yields genuine C-like pseudocode.

        Falsifiable: before the fix this call either raised ``ToolError``
        (the "No sleigh specification" ``pdg`` failure, or the dead ``pdc``
        path) or, if the not-available check missed a failure-text variant,
        returned non-C content. A correct fix returns pseudocode containing
        real braces, a return statement, and a C-like type keyword -- none
        of which appear in an empty string or an error message.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address = await _first_sized_function(pe_bridge)
        result = await pe_bridge.decompile(address)
        assert "{" in result
        assert "}" in result
        assert "return" in result
        assert any(token in result for token in ("undefined", "int", "void", "char", "uint")), (
            f"decompiled output has no recognizable C-like type keyword: {result!r}"
        )

    async def test_decompile_is_deterministic_and_addresses_function(self, pe_bridge: CutterBridge) -> None:
        """Decompiling the same function twice returns identical, non-empty pseudocode.

        Two independent ``pdg`` round trips against the same address must
        agree byte-for-byte; a corrupted pipe, a timeout that silently
        truncated output, or nondeterministic SLEIGH state would desync
        the two calls.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address = await _first_sized_function(pe_bridge)
        first = await pe_bridge.decompile(address)
        second = await pe_bridge.decompile(address)
        assert first.strip()
        assert first == second

    async def test_decompile_without_binary_raises_tool_error(self) -> None:
        """``decompile`` on a bridge with no loaded binary raises ``ToolError`` rather than hanging or crashing."""
        bridge = await _make_bridge_or_skip()
        with pytest.raises(ToolError):
            await bridge.decompile(0x1000)


class TestRealCfgBasicBlocks:
    """S15-D02: CFG graph data is built from real ``afbj`` basic blocks, not the broken ``agj``."""

    async def test_get_function_graph_returns_multiple_real_blocks_with_edges(self, pe_bridge: CutterBridge) -> None:
        """A multi-block function's CFG has at least two blocks joined by a real jump/fail edge.

        Falsifiable: before the fix ``get_function_graph`` issued
        ``agj @ addr``, which returns empty output against this rizin 0.9.1
        backend, so ``blocks`` would be ``[]`` and every assertion below
        would fail. The corrected implementation returns real per-block
        addresses and at least one edge whose target lands on another real
        block in the same function.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address = await _first_sized_function(pe_bridge, min_blocks=2)
        blocks = await pe_bridge.get_function_graph(address)
        assert len(blocks) >= 2, f"expected >=2 basic blocks for a multi-block function, got {len(blocks)}"

        offsets = {block["offset"] for block in blocks}
        assert len(offsets) == len(blocks), "block offsets must be real, unique addresses"
        assert all(isinstance(offset, int) and offset > 0 for offset in offsets)

        edge_targets = {block[key] for block in blocks for key in ("jump", "fail") if block.get(key) is not None}
        assert edge_targets, "expected at least one jump/fail edge among multiple real basic blocks"
        assert edge_targets & offsets, "at least one edge target must land on another block of the same function"

    async def test_get_function_graph_blocks_carry_real_disassembly(self, pe_bridge: CutterBridge) -> None:
        """Every basic block's ``ops`` list carries real disassembled instruction text.

        The panel's ``CFGGraphScene.load_graph`` renders each op's
        ``disasm`` field directly, so a block with an empty or missing
        ``ops`` list would render as a blank rectangle even though the
        block itself was located correctly.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address = await _first_sized_function(pe_bridge)
        blocks = await pe_bridge.get_function_graph(address)
        assert blocks

        first_block: dict[str, Any] = blocks[0]
        ops = cast("list[dict[str, Any]]", first_block["ops"])
        assert ops, "first basic block must carry at least one disassembled instruction"
        assert all(isinstance(op, dict) and str(op.get("disasm", "")).strip() for op in ops), (
            f"every op in a basic block must carry non-empty real disassembly text: {ops!r}"
        )

    async def test_get_function_graph_offsets_match_get_basic_blocks_oracle(self, pe_bridge: CutterBridge) -> None:
        """CFG block offsets are identical to the independently-gated ``get_basic_blocks`` addresses.

        ``get_basic_blocks`` already resolves to real ``afbj`` data (proven
        by ``test_realcov_03c_cutter.py::TestRealDisassembly::test_basic_blocks_real``),
        so it is an independent oracle for the set of real basic-block
        addresses a function contains. ``get_function_graph`` must report
        the exact same address set, not a subset, superset, or a
        differently-sourced (and possibly empty) result.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address = await _first_sized_function(pe_bridge, min_blocks=2)
        graph_blocks = await pe_bridge.get_function_graph(address)
        basic_blocks = await pe_bridge.get_basic_blocks(address)

        graph_offsets = {block["offset"] for block in graph_blocks}
        oracle_offsets = {block.address for block in basic_blocks}
        assert graph_offsets == oracle_offsets

    async def test_get_function_graph_without_analysis_raises_tool_error(self, real_pe_dll: Path) -> None:
        """``get_function_graph`` raises ``ToolError`` when the binary was loaded but never analyzed.

        Args:
            real_pe_dll: Session fixture resolving a real System32 DLL.
        """
        bridge = await _make_bridge_or_skip()
        try:
            await bridge.load_binary(real_pe_dll)
            with pytest.raises(ToolError):
                await bridge.get_function_graph(0x1000)
        finally:
            await bridge.shutdown()
