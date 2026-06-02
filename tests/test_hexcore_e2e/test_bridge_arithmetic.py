# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge bitwise arithmetic operations on selections.

Every test drives the real ``HexEditorBridge`` against the real
``intellicrack_hexcore`` native transform backend end to end: bytes are
written to a real on-disk document, a selection is made, the arithmetic
transform is applied through the bridge, and the result is read back out
of the document. Expected values are computed by an independent
bit-level oracle (plain Python ``int`` bit operations), never by
re-invoking the production transform or freezing its output.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


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


def _rol8(value: int, count: int) -> int:
    """Rotate an 8-bit value left by ``count`` bits (independent oracle).

    Args:
        value: Byte value in ``[0, 255]``.
        count: Number of bit positions to rotate.

    Returns:
        int: The rotated byte value.
    """
    count %= 8
    return ((value << count) | (value >> (8 - count))) & 0xFF if count else value & 0xFF


def _ror8(value: int, count: int) -> int:
    """Rotate an 8-bit value right by ``count`` bits (independent oracle).

    Args:
        value: Byte value in ``[0, 255]``.
        count: Number of bit positions to rotate.

    Returns:
        int: The rotated byte value.
    """
    count %= 8
    return ((value >> count) | (value << (8 - count))) & 0xFF if count else value & 0xFF


def _setup_and_apply(
    bridge: HexEditorBridge,
    tmp_path: Path,
    hex_data: str,
    operation: str,
    key_hex: str = "",
    count: int = 1,
) -> tuple[bytes, dict[str, Any]]:
    """Write hex data, select it, apply arithmetic, return bytes and metadata.

    The bytes are read back through the bridge after the transform so the
    full write -> select -> transform -> read round trip through the native
    backend is exercised.

    Args:
        bridge: An initialized HexEditorBridge.
        tmp_path: Temporary directory path.
        hex_data: Hex string of data to write (space-separated).
        operation: Arithmetic operation name.
        key_hex: Key/mask hex string.
        count: Bit count for shift/rotate.

    Returns:
        tuple[bytes, dict[str, Any]]: Resulting selection bytes and the
        operation metadata dict returned by the bridge.
    """
    tokens = hex_data.split()
    data_len = len(tokens)
    f = tmp_path / f"arith_{operation}.bin"
    f.write_bytes(b"\x00" * 64)
    _run(bridge.open_file(str(f)))
    _run(bridge.write_bytes(0, hex_data))
    _run(bridge.select_range(0, data_len - 1))
    metadata = _run(bridge.apply_arithmetic_to_selection(operation, key_hex=key_hex, count=count))
    result_hex = _run(bridge.read_bytes(0, data_len))
    return bytes.fromhex(result_hex.replace(" ", "")), metadata


class TestSetupHelperFidelity:
    """Tests that the round-trip helper faithfully drives the native backend.

    These tests pin the helper itself: they prove that what it writes is
    what the document holds, that the transform mutates the document (not
    just the returned copy), and that surrounding bytes are untouched.
    """

    def test_helper_round_trip_is_lossless_without_transform(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A NOT of all-zero input yields all-ones, proving the read path returns transformed document state.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "00 00 00 00", "not")
        assert result == bytes([0xFF, 0xFF, 0xFF, 0xFF])

    def test_transform_mutates_document_not_just_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """The transform is persisted in the document and leaves trailing bytes untouched.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "persist.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "10 20 30 40 99 99"))
        _run(bridge.select_range(0, 3))
        _run(bridge.apply_arithmetic_to_selection("xor", key_hex="FF"))
        whole = bytes.fromhex(_run(bridge.read_bytes(0, 6)).replace(" ", ""))
        assert whole == bytes([0x10 ^ 0xFF, 0x20 ^ 0xFF, 0x30 ^ 0xFF, 0x40 ^ 0xFF, 0x99, 0x99])


class TestXorOperation:
    """Tests for XOR arithmetic on selections."""

    def test_xor_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify XOR with single-byte key produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "FF 00 AA 55", "xor", key_hex="FF")
        assert result == bytes([0xFF ^ 0xFF, 0x00 ^ 0xFF, 0xAA ^ 0xFF, 0x55 ^ 0xFF])

    def test_xor_multi_byte_key(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify XOR with a multi-byte key repeats cyclically.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        key = [0xFF, 0x00]
        result, _ = _setup_and_apply(bridge, tmp_path, "01 02 03 04 05 06 07 08", "xor", key_hex="FF00")
        expected = bytes(p ^ key[i % len(key)] for i, p in enumerate(plain))
        assert result == expected

    def test_xor_with_zero_key_is_identity(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """XOR with a 0x00 key leaves every byte unchanged.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "DE AD BE EF", "xor", key_hex="00")
        assert result == bytes([0xDE, 0xAD, 0xBE, 0xEF])


class TestAndOperation:
    """Tests for AND arithmetic on selections."""

    def test_and_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify AND with mask produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "FF F0 0F 00", "and", key_hex="0F")
        assert result == bytes([0xFF & 0x0F, 0xF0 & 0x0F, 0x0F & 0x0F, 0x00 & 0x0F])


class TestOrOperation:
    """Tests for OR arithmetic on selections."""

    def test_or_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify OR with mask produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "00 0F F0 FF", "or", key_hex="F0")
        assert result == bytes([0x00 | 0xF0, 0x0F | 0xF0, 0xF0 | 0xF0, 0xFF | 0xF0])


class TestNotOperation:
    """Tests for NOT (bitwise inversion) on selections."""

    def test_not_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify NOT inverts all bits.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "00 FF AA 55", "not")
        assert result == bytes([0x00 ^ 0xFF, 0xFF ^ 0xFF, 0xAA ^ 0xFF, 0x55 ^ 0xFF])


class TestShiftOperations:
    """Tests for shift-left and shift-right arithmetic on selections."""

    def test_shift_left_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHL by 1 shifts each byte left within 8 bits.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0x01, 0x02, 0x04, 0x80]
        result, _ = _setup_and_apply(bridge, tmp_path, "01 02 04 80", "shl", count=1)
        assert result == bytes((p << 1) & 0xFF for p in plain)

    def test_shift_left_by_three(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHL by 3 drops the high bits and zero-fills the low bits.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0x01, 0x11, 0xFF, 0x40]
        result, _ = _setup_and_apply(bridge, tmp_path, "01 11 FF 40", "shl", count=3)
        assert result == bytes((p << 3) & 0xFF for p in plain)

    def test_shift_right_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHR by 1 shifts each byte right (logical, zero fill).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0x80, 0x40, 0x02, 0x01]
        result, _ = _setup_and_apply(bridge, tmp_path, "80 40 02 01", "shr", count=1)
        assert result == bytes(p >> 1 for p in plain)

    def test_shift_right_by_four(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHR by 4 isolates the high nibble of each byte.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0xF0, 0xAB, 0x0F, 0xFF]
        result, _ = _setup_and_apply(bridge, tmp_path, "F0 AB 0F FF", "shr", count=4)
        assert result == bytes(p >> 4 for p in plain)


class TestRotateOperations:
    """Tests for rotate-left and rotate-right arithmetic on selections."""

    def test_rotate_left_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROL by 1 wraps the MSB to LSB.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "80", "rol", count=1)
        assert result == bytes([_rol8(0x80, 1)])

    def test_rotate_left_by_three(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROL by 3 wraps the top three bits around to the bottom.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0xB0, 0x01, 0xFF, 0x12]
        result, _ = _setup_and_apply(bridge, tmp_path, "B0 01 FF 12", "rol", count=3)
        assert result == bytes(_rol8(p, 3) for p in plain)

    def test_rotate_right_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROR by 1 wraps the LSB to MSB.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, _ = _setup_and_apply(bridge, tmp_path, "01", "ror", count=1)
        assert result == bytes([_ror8(0x01, 1)])

    def test_rotate_right_by_five(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROR by 5 matches the independent 8-bit rotation oracle.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        plain = [0x01, 0x80, 0xC3, 0x7E]
        result, _ = _setup_and_apply(bridge, tmp_path, "01 80 C3 7E", "ror", count=5)
        assert result == bytes(_ror8(p, 5) for p in plain)


class TestArithmeticEdgeCases:
    """Tests for arithmetic operation edge cases and error handling."""

    def test_no_selection_raises(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that arithmetic without a selection raises RuntimeError.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "no_sel.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        with pytest.raises(RuntimeError, match="no selection active"):
            _run(bridge.apply_arithmetic_to_selection("xor", key_hex="FF"))

    def test_unknown_operation_raises_tool_error(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify an unsupported operation name raises ToolError, not a silent identity.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "bad_op.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        _run(bridge.select_range(0, 3))
        with pytest.raises(ToolError, match="unknown arithmetic transform"):
            _run(bridge.apply_arithmetic_to_selection("mul", key_hex="02"))

    def test_single_byte_selection_boundary(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """A one-byte selection transforms exactly that byte and reports length 1.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result, metadata = _setup_and_apply(bridge, tmp_path, "5A", "not")
        assert result == bytes([0x5A ^ 0xFF])
        assert metadata == {"offset": 0, "length": 1, "operation": "not"}

    def test_returns_operation_metadata(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify arithmetic returns the exact offset, length, and operation metadata.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "meta.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        _run(bridge.select_range(0, 3))
        result = _run(bridge.apply_arithmetic_to_selection("not"))
        assert result == {"offset": 0, "length": 4, "operation": "not"}
