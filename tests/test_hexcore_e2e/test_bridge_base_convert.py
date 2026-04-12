# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge numeric base conversion and type representation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, TypeVar

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine


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


class TestBaseConvertAutoDetect:
    """Tests for base_convert with auto-detection of input format."""

    def test_decimal_input(self) -> None:
        """Verify decimal input produces correct hex, binary, and octal."""
        result = _run(HexEditorBridge.base_convert("255"))
        assert result["hex"] == "0xff"
        assert result["binary"] == "0b11111111"
        assert result["octal"] == "0o377"

    def test_hex_input_auto(self) -> None:
        """Verify 0xFF auto-detects as hex and converts to decimal 255."""
        result = _run(HexEditorBridge.base_convert("0xFF"))
        assert result["decimal"] == "255"

    def test_binary_input_auto(self) -> None:
        """Verify 0b1010 auto-detects as binary and converts to decimal 10."""
        result = _run(HexEditorBridge.base_convert("0b1010"))
        assert result["decimal"] == "10"

    def test_octal_input_auto(self) -> None:
        """Verify 0o77 auto-detects as octal and converts to decimal 63."""
        result = _run(HexEditorBridge.base_convert("0o77"))
        assert result["decimal"] == "63"


class TestBaseConvertExplicit:
    """Tests for base_convert with explicit base specification."""

    def test_explicit_hex_base(self) -> None:
        """Verify explicit hex base parses FF correctly."""
        result = _run(HexEditorBridge.base_convert("FF", from_base="hex"))
        assert result["decimal"] == "255"


class TestBaseConvertTypeRepresentations:
    """Tests for integer width and floating-point representations."""

    def test_int8_representation(self) -> None:
        """Verify 128 shows as -128 in signed int8."""
        result = _run(HexEditorBridge.base_convert("128"))
        assert result["int8"] == "-128"

    def test_uint32_representation(self) -> None:
        """Verify 4294967295 shows correctly in uint32 and int32."""
        result = _run(HexEditorBridge.base_convert("4294967295"))
        assert result["uint32_le"] == "4294967295"
        assert result["int32_le"] == "-1"

    def test_float32_representation(self) -> None:
        """Verify 1065353216 (IEEE 754 for 1.0f) shows as 1.0 in float32."""
        result = _run(HexEditorBridge.base_convert("1065353216"))
        assert result["float32_le"] == "1.0"


class TestBaseConvertEdgeCases:
    """Tests for base_convert edge cases."""

    def test_result_has_base_keys(self) -> None:
        """Verify result always contains decimal, hex, octal, binary keys."""
        result = _run(HexEditorBridge.base_convert("42"))
        assert "decimal" in result
        assert "hex" in result
        assert "octal" in result
        assert "binary" in result

    def test_zero_value(self) -> None:
        """Verify zero converts correctly across all representations."""
        result = _run(HexEditorBridge.base_convert("0"))
        assert result["decimal"] == "0"
        assert result["hex"] == "0x0"
        assert result["octal"] == "0o0"
        assert result["binary"] == "0b0"
