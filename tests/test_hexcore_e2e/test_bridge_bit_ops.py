# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge single-bit get/set/toggle operations.

These tests drive the real Rust-backed ``HexDocument`` through the bridge
against on-disk binaries. The expected bit values come from an independent
little-endian bit oracle (``(byte >> i) & 1``), not from the bridge's own
output, so an off-by-one in bit indexing, a wrong endianness, or a
misinterpreted byte offset is caught field by field. Determinism is asserted
by reading the same bit repeatedly, and every byte value in a multi-byte
buffer is verified across all eight bit positions.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


# A buffer whose bytes exercise every bit position and several distinct
# patterns, so a wrong byte/offset mapping cannot pass by coincidence.
_PATTERN: bytes = bytes([0xA5, 0x00, 0xFF, 0x01, 0x80, 0x7F, 0x3C, 0xC3])


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
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


def _expected_bit(byte: int, bit_index: int) -> bool:
    """Return the little-endian bit oracle value for ``byte`` at ``bit_index``.

    Args:
        byte: The byte value (0-255).
        bit_index: Bit position with 0 = LSB, 7 = MSB.

    Returns:
        bool: ``True`` when the bit is set.
    """
    return bool((byte >> bit_index) & 1)


def _read_byte(bridge: HexEditorBridge, offset: int) -> int:
    """Read a single byte back from the bridge as an integer.

    Args:
        bridge: An initialized HexEditorBridge with an open document.
        offset: Byte offset to read.

    Returns:
        int: The byte value at ``offset``.
    """
    hex_str: str = _run(bridge.read_bytes(offset, 1))
    raw = bytes.fromhex(hex_str.replace(" ", ""))
    assert len(raw) == 1
    return raw[0]


class TestGetBit:
    """Tests for the get_bit method reading individual bit values."""

    def test_every_bit_of_known_byte_matches_lsb0_oracle(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify all eight bits of 0xA5 follow the LSB-0 layout (10100101).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bits.bin"
        f.write_bytes(b"\xa5" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        observed = [_run(bridge.get_bit(0, i)) for i in range(8)]
        expected = [_expected_bit(0xA5, i) for i in range(8)]
        assert observed == expected
        assert observed == [True, False, True, False, False, True, False, True]

    def test_all_bytes_all_bits_match_oracle_across_offsets(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify each byte/offset maps to the correct bit, ruling out off-by-one.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "pattern.bin"
        f.write_bytes(_PATTERN)
        _run(bridge.open_file(str(f)))

        for offset, byte in enumerate(_PATTERN):
            for bit_index in range(8):
                assert _run(bridge.get_bit(offset, bit_index)) is _expected_bit(byte, bit_index), (
                    f"offset={offset} byte={byte:#04x} bit={bit_index}"
                )

    def test_get_bit_is_deterministic_across_repeated_calls(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify repeated reads of the same bit return an identical value.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "det.bin"
        f.write_bytes(b"\xa5" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        first = [_run(bridge.get_bit(0, i)) for i in range(8)]
        for _ in range(5):
            assert [_run(bridge.get_bit(0, i)) for i in range(8)] == first

    @pytest.mark.parametrize("bad_index", [8, 9, -1, -8, 64])
    def test_bit_index_out_of_range_raises(self, bridge: HexEditorBridge, tmp_path: Path, bad_index: int) -> None:
        """Verify out-of-range bit indices raise ValueError consistently.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            bad_index: An invalid bit index outside the 0-7 range.
        """
        f = tmp_path / "bitrange.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="bit_index must be 0-7"):
            _run(bridge.get_bit(0, bad_index))

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify that get_bit raises RuntimeError without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_bit(0, 0))


class TestSetBit:
    """Tests for the set_bit method setting or clearing individual bits."""

    def test_set_each_bit_individually_builds_full_byte(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify setting bits 0..7 one at a time yields 0x01,0x02,...,0x80.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "setbits.bin"
        f.write_bytes(b"\x00" * 8)
        _run(bridge.open_file(str(f)))

        for bit_index in range(8):
            assert _run(bridge.set_bit(bit_index, bit_index, value=True)) is True
            assert _read_byte(bridge, bit_index) == (1 << bit_index)
            # get_bit must agree with the just-written byte.
            assert _run(bridge.get_bit(bit_index, bit_index)) is True

    def test_clear_bit_in_full_byte_zeroes_only_that_bit(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify clearing bit 3 of 0xFF yields 0xF7 and leaves others set.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "clearbit.bin"
        f.write_bytes(b"\xff" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        assert _run(bridge.set_bit(0, 3, value=False)) is True
        assert _read_byte(bridge, 0) == 0xF7
        assert _run(bridge.get_bit(0, 3)) is False
        for other in (0, 1, 2, 4, 5, 6, 7):
            assert _run(bridge.get_bit(0, other)) is True

    def test_set_bit_is_idempotent(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify setting an already-set bit leaves the byte unchanged.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "idem.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        _run(bridge.set_bit(0, 5, value=True))
        _run(bridge.set_bit(0, 5, value=True))
        assert _read_byte(bridge, 0) == 0x20

    @pytest.mark.parametrize("bad_index", [8, -1, 16])
    def test_bit_index_out_of_range_raises(self, bridge: HexEditorBridge, tmp_path: Path, bad_index: int) -> None:
        """Verify set_bit rejects out-of-range indices with ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            bad_index: An invalid bit index outside the 0-7 range.
        """
        f = tmp_path / "negbit.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="bit_index must be 0-7"):
            _run(bridge.set_bit(0, bad_index, value=True))


class TestToggleBit:
    """Tests for the toggle_bit method flipping individual bits."""

    def test_toggle_sets_bit_and_returns_new_value(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify toggling bit 7 of 0x00 produces 0x80 and returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "toggle.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))

        assert _run(bridge.toggle_bit(0, 7)) is True
        assert _read_byte(bridge, 0) == 0x80
        assert _run(bridge.get_bit(0, 7)) is True

    def test_toggle_clears_bit_and_returns_new_value(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify toggling bit 0 of 0xFF produces 0xFE and returns False.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "toggle_back.bin"
        f.write_bytes(b"\xff" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        assert _run(bridge.toggle_bit(0, 0)) is False
        assert _read_byte(bridge, 0) == 0xFE
        assert _run(bridge.get_bit(0, 0)) is False

    def test_double_toggle_restores_byte_and_alternates_return(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify two toggles of the same bit restore the byte and alternate the result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "double.bin"
        f.write_bytes(b"\xa5" + b"\x00" * 63)
        _run(bridge.open_file(str(f)))

        # 0xA5 bit 1 is clear -> first toggle sets it (True), second clears it (False).
        assert _run(bridge.toggle_bit(0, 1)) is True
        assert _read_byte(bridge, 0) == 0xA7
        assert _run(bridge.toggle_bit(0, 1)) is False
        assert _read_byte(bridge, 0) == 0xA5

    @pytest.mark.parametrize("bad_index", [8, -1])
    def test_bit_index_out_of_range_raises(self, bridge: HexEditorBridge, tmp_path: Path, bad_index: int) -> None:
        """Verify toggle_bit rejects out-of-range indices with ValueError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
            bad_index: An invalid bit index outside the 0-7 range.
        """
        f = tmp_path / "togbad.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(ValueError, match="bit_index must be 0-7"):
            _run(bridge.toggle_bit(0, bad_index))

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify that toggle_bit raises RuntimeError without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.toggle_bit(0, 0))
