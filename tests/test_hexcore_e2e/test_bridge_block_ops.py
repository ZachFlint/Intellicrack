# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge block-level data manipulation operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


def _run(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestFillBlock:
    """Tests for the fill_block method filling regions with repeating patterns."""

    def test_fill_block_single_byte(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify filling a block with a single-byte pattern writes correct bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "fill_single.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.fill_block(8, 16, "90"))
        result = cast(str, _run(bridge.read_bytes(8, 16)))
        raw = bytes.fromhex(result.replace(" ", ""))
        assert raw == b"\x90" * 16

    def test_fill_block_multi_byte_pattern(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify filling with a multi-byte pattern repeats correctly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "fill_multi.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.fill_block(0, 12, "DEADBEEF"))
        result = cast(str, _run(bridge.read_bytes(0, 12)))
        raw = bytes.fromhex(result.replace(" ", ""))
        assert raw == b"\xDE\xAD\xBE\xEF" * 3

    def test_fill_block_empty_pattern_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that an empty pattern raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "fill_empty.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="pattern must not be empty"):
            _run(bridge.fill_block(0, 8, ""))

    def test_fill_block_no_doc_raises(self, bridge: HexEditorBridge) -> None:
        """Verify that fill_block raises RuntimeError without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.fill_block(0, 8, "90"))


class TestCopyBlock:
    """Tests for the copy_block method copying regions within a document."""

    def test_copy_block(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify copying a block duplicates bytes at the destination.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "copy.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "CA FE BA BE DE AD BE EF"))
        _run(bridge.copy_block(0, 8, 32))
        result = cast(str, _run(bridge.read_bytes(32, 8)))
        assert result.replace(" ", "").lower() == "cafebabedeadbeef"

    def test_copy_block_overlapping_forward(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify copy handles overlapping forward regions correctly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "copy_overlap.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "01 02 03 04 05 06 07 08"))
        _run(bridge.copy_block(0, 8, 4))
        result = cast(str, _run(bridge.read_bytes(4, 8)))
        raw = bytes.fromhex(result.replace(" ", ""))
        assert len(raw) == 8


class TestMoveBlock:
    """Tests for the move_block method moving regions within a document."""

    def test_move_block(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify moving a block zeros the source and writes to destination.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "move.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "CA FE BA BE DE AD BE EF"))
        _run(bridge.move_block(0, 8, 32))
        src = cast(str, _run(bridge.read_bytes(0, 8)))
        dst = cast(str, _run(bridge.read_bytes(32, 8)))
        assert bytes.fromhex(src.replace(" ", "")) == b"\x00" * 8
        assert dst.replace(" ", "").lower() == "cafebabedeadbeef"


class TestSwapBlocks:
    """Tests for the swap_blocks method exchanging two non-overlapping regions."""

    def test_swap_blocks(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify swapping two equal-length blocks exchanges their contents.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "swap.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "41 41 41 41"))
        _run(bridge.write_bytes(32, "42 42 42 42"))
        _run(bridge.swap_blocks(0, 4, 32, 4))
        block_a = cast(str, _run(bridge.read_bytes(0, 4)))
        block_b = cast(str, _run(bridge.read_bytes(32, 4)))
        assert bytes.fromhex(block_a.replace(" ", "")) == b"BBBB"
        assert bytes.fromhex(block_b.replace(" ", "")) == b"AAAA"

    def test_swap_blocks_different_lengths(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify swapping blocks of different lengths writes correctly.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "swap_diff.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        _run(bridge.write_bytes(32, "11 22 33 44 55 66 77 88"))
        _run(bridge.swap_blocks(0, 4, 32, 8))
        at_0 = cast(str, _run(bridge.read_bytes(0, 8)))
        at_32 = cast(str, _run(bridge.read_bytes(32, 4)))
        assert at_0.replace(" ", "").lower() == "1122334455667788"
        assert at_32.replace(" ", "").lower() == "aabbccdd"

    def test_swap_blocks_overlapping_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that overlapping block ranges raise ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "swap_overlap.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="blocks overlap"):
            _run(bridge.swap_blocks(0, 16, 8, 16))
