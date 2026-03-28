# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the four copy_as formats not covered by test_bridge_copy_as.py."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


def _run(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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


_PAYLOAD_ALL_LOW: bytes = b"\x01\x02\x7f"
_PAYLOAD_HIGH: bytes = b"\x80\xff\xde"
_PAYLOAD_MIXED: bytes = b"\x41\xde\x7f\x80"

_SEL_START = 0
_SEL_END_ALL_LOW = len(_PAYLOAD_ALL_LOW) - 1
_SEL_END_HIGH = len(_PAYLOAD_HIGH) - 1
_SEL_END_MIXED = len(_PAYLOAD_MIXED) - 1


def _open_and_select(
    bridge: Any,
    tmp_path: Path,
    payload: bytes,
    filename: str,
    sel_end: int,
) -> None:
    """Write payload to disk, open it in the bridge, and set a selection.

    Args:
        bridge: An initialized HexEditorBridge fixture.
        tmp_path: Pytest temporary directory.
        payload: Bytes to write and select.
        filename: Name of the temp file to create.
        sel_end: Inclusive end index of the selection (0-based).
    """
    f = tmp_path / filename
    f.write_bytes(payload)
    _run(bridge.open_file(str(f)))
    _run(bridge.select_range(_SEL_START, sel_end))


class TestCopyAsCsharpArray:
    """Tests for copy_as('csharp_array') formatting."""

    def test_csharp_array_starts_with_new_byte_array(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that csharp_array output starts with 'new byte[] {'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "cs_low.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("csharp_array"))
        assert result.startswith("new byte[] {")

    def test_csharp_array_ends_with_closing_brace(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that csharp_array output ends with '}'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "cs_end.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("csharp_array"))
        assert result.endswith("}")

    def test_csharp_array_contains_correct_hex_values(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that csharp_array output contains the correct 0xNN tokens for each byte.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "cs_vals.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("csharp_array"))
        assert "0x01" in result
        assert "0x02" in result
        assert "0x7F" in result


class TestCopyAsJavaArray:
    """Tests for copy_as('java_array') formatting."""

    def test_java_array_starts_with_new_byte_array(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that java_array output starts with 'new byte[] {'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "java_low.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("java_array"))
        assert result.startswith("new byte[] {")

    def test_java_array_high_bytes_get_cast_prefix(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that java_array casts bytes > 0x7F with a '(byte)' prefix.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_HIGH, "java_high.bin", _SEL_END_HIGH)
        result: str = _run(bridge.copy_as("java_array"))
        assert "(byte)0x80" in result
        assert "(byte)0xFF" in result
        assert "(byte)0xDE" in result

    def test_java_array_low_bytes_have_no_cast(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that java_array does not cast bytes <= 0x7F.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "java_nocast.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("java_array"))
        assert "(byte)0x01" not in result
        assert "(byte)0x02" not in result
        assert "(byte)0x7F" not in result
        assert "0x01" in result

    def test_java_array_mixed_payload_has_cast_only_for_high_byte(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that java_array only casts bytes > 0x7F in a mixed payload.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_MIXED, "java_mix.bin", _SEL_END_MIXED)
        result: str = _run(bridge.copy_as("java_array"))
        assert "(byte)0xDE" in result
        assert "(byte)0x80" in result
        assert "(byte)0x41" not in result
        assert "(byte)0x7F" not in result


class TestCopyAsJavascriptArray:
    """Tests for copy_as('javascript_array') formatting."""

    def test_javascript_array_starts_with_new_uint8array(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that javascript_array output starts with 'new Uint8Array(['.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "js_low.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("javascript_array"))
        assert result.startswith("new Uint8Array([")

    def test_javascript_array_ends_with_closing_bracket_paren(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that javascript_array output ends with '])'.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "js_end.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("javascript_array"))
        assert result.endswith("])")

    def test_javascript_array_contains_correct_hex_values(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that javascript_array output contains all expected 0xNN tokens.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "js_vals.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("javascript_array"))
        assert "0x01" in result
        assert "0x02" in result
        assert "0x7F" in result


class TestCopyAsNasmDb:
    """Tests for copy_as('nasm_db') formatting."""

    def test_nasm_db_starts_with_db(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that nasm_db output starts with 'db '.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "nasm.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("nasm_db"))
        assert result.startswith("db ")

    def test_nasm_db_contains_correct_hex_values(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that nasm_db output contains the expected 0xNN tokens.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _open_and_select(bridge, tmp_path, _PAYLOAD_ALL_LOW, "nasm_vals.bin", _SEL_END_ALL_LOW)
        result: str = _run(bridge.copy_as("nasm_db"))
        assert "0x01" in result
        assert "0x02" in result
        assert "0x7F" in result
