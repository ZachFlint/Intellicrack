# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge single-bit get/set/toggle operations."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


_T = TypeVar("_T")


def _run(coro: Coroutine[object, object, _T]) -> _T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        _T: The result of the coroutine.
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


class TestGetBit:
    """Tests for the get_bit method reading individual bit values."""

    def test_get_bit_returns_correct_values(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify get_bit returns correct bit values for 0xA5 (10100101).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bits.bin"
        f.write_bytes(b"\xa5" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        assert _run(bridge.get_bit(0, 0)) is True
        assert _run(bridge.get_bit(0, 1)) is False
        assert _run(bridge.get_bit(0, 2)) is True
        assert _run(bridge.get_bit(0, 3)) is False
        assert _run(bridge.get_bit(0, 4)) is False
        assert _run(bridge.get_bit(0, 5)) is True
        assert _run(bridge.get_bit(0, 6)) is False
        assert _run(bridge.get_bit(0, 7)) is True

    def test_bit_index_out_of_range_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that bit_index=8 raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bitrange.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="bit_index must be 0-7"):
            _run(bridge.get_bit(0, 8))

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify that get_bit raises RuntimeError without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_bit(0, 0))


class TestSetBit:
    """Tests for the set_bit method setting or clearing individual bits."""

    def test_set_bit_sets_bit(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_bit(value=True) sets bit 3, producing 0x08.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "setbit.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_bit(0, 3, value=True))
        result = _run(bridge.read_bytes(0, 1))
        assert bytes.fromhex(result.replace(" ", "")) == b"\x08"

    def test_set_bit_clears_bit(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_bit(value=False) clears bit 3, producing 0xF7 from 0xFF.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "clearbit.bin"
        f.write_bytes(b"\xff" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))
        _run(bridge.set_bit(0, 3, value=False))
        result = _run(bridge.read_bytes(0, 1))
        assert bytes.fromhex(result.replace(" ", "")) == b"\xf7"

    def test_bit_index_negative_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that bit_index=-1 raises ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "negbit.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="bit_index must be 0-7"):
            _run(bridge.set_bit(0, -1, value=True))


class TestToggleBit:
    """Tests for the toggle_bit method flipping individual bits."""

    def test_toggle_bit_flips(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify toggling bit 7 of 0x00 produces 0x80 and returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "toggle.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        new_val = _run(bridge.toggle_bit(0, 7))
        assert new_val is True
        result = _run(bridge.read_bytes(0, 1))
        assert bytes.fromhex(result.replace(" ", "")) == b"\x80"

    def test_toggle_bit_flips_back(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify toggling bit 0 of 0xFF produces 0xFE and returns False.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "toggle_back.bin"
        f.write_bytes(b"\xff" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))
        new_val = _run(bridge.toggle_bit(0, 0))
        assert new_val is False
        result = _run(bridge.read_bytes(0, 1))
        assert bytes.fromhex(result.replace(" ", "")) == b"\xfe"
