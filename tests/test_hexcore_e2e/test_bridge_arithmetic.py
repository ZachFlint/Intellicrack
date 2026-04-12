# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge bitwise arithmetic operations on selections."""

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


def _setup_and_apply(
    bridge: HexEditorBridge,
    tmp_path: Any,
    hex_data: str,
    operation: str,
    key_hex: str = "",
    count: int = 1,
) -> bytes:
    """Write hex data, select it, apply arithmetic, and return result bytes.

    Args:
        bridge: An initialized HexEditorBridge.
        tmp_path: Temporary directory path.
        hex_data: Hex string of data to write (space-separated).
        operation: Arithmetic operation name.
        key_hex: Key/mask hex string.
        count: Bit count for shift/rotate.

    Returns:
        bytes: Resulting bytes after the operation.
    """
    tokens = hex_data.split()
    data_len = len(tokens)
    f = tmp_path / f"arith_{operation}.bin"
    f.write_bytes(b"\x00" * 64)
    _run(bridge.open_file(str(f)))
    _run(bridge.write_bytes(0, hex_data))
    _run(bridge.select_range(0, data_len - 1))
    _run(bridge.apply_arithmetic_to_selection(operation, key_hex=key_hex, count=count))
    result_hex = cast(str, _run(bridge.read_bytes(0, data_len)))
    return bytes.fromhex(result_hex.replace(" ", ""))


class TestXorOperation:
    """Tests for XOR arithmetic on selections."""

    def test_xor_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify XOR with single-byte key produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "FF 00 AA 55", "xor", key_hex="FF")
        assert result == bytes([0x00, 0xFF, 0x55, 0xAA])

    def test_xor_multi_byte_key(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify XOR with a multi-byte key repeats cyclically.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "01 02 03 04 05 06 07 08", "xor", key_hex="FF00")
        expected = bytes([0x01 ^ 0xFF, 0x02 ^ 0x00, 0x03 ^ 0xFF, 0x04 ^ 0x00,
                          0x05 ^ 0xFF, 0x06 ^ 0x00, 0x07 ^ 0xFF, 0x08 ^ 0x00])
        assert result == expected


class TestAndOperation:
    """Tests for AND arithmetic on selections."""

    def test_and_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify AND with mask produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "FF F0 0F 00", "and", key_hex="0F")
        assert result == bytes([0x0F, 0x00, 0x0F, 0x00])


class TestOrOperation:
    """Tests for OR arithmetic on selections."""

    def test_or_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify OR with mask produces correct result.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "00 0F F0 FF", "or", key_hex="F0")
        assert result == bytes([0xF0, 0xFF, 0xF0, 0xFF])


class TestNotOperation:
    """Tests for NOT (bitwise inversion) on selections."""

    def test_not_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify NOT inverts all bits.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "00 FF AA 55", "not")
        assert result == bytes([0xFF, 0x00, 0x55, 0xAA])


class TestShiftOperations:
    """Tests for shift-left and shift-right arithmetic on selections."""

    def test_shift_left_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHL by 1 shifts each byte left.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "01 02 04 80", "shl", count=1)
        assert result == bytes([0x02, 0x04, 0x08, 0x00])

    def test_shift_right_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify SHR by 1 shifts each byte right.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "80 40 02 01", "shr", count=1)
        assert result == bytes([0x40, 0x20, 0x01, 0x00])


class TestRotateOperations:
    """Tests for rotate-left and rotate-right arithmetic on selections."""

    def test_rotate_left_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROL by 1 wraps the MSB to LSB.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "80", "rol", count=1)
        assert result == bytes([0x01])

    def test_rotate_right_selection(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify ROR by 1 wraps the LSB to MSB.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        result = _setup_and_apply(bridge, tmp_path, "01", "ror", count=1)
        assert result == bytes([0x80])


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

    def test_returns_operation_metadata(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that arithmetic returns a dict with offset, length, operation keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "meta.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        _run(bridge.write_bytes(0, "AA BB CC DD"))
        _run(bridge.select_range(0, 3))
        result = cast("dict[str, Any]", _run(bridge.apply_arithmetic_to_selection("not")))
        assert "offset" in result
        assert "length" in result
        assert "operation" in result
        assert result["operation"] == "not"
        assert result["length"] == 4
