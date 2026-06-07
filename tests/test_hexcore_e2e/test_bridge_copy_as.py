# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge copy_as formatting."""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


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


_SELECTION_START = 0
_SELECTION_END = 3


def _load_and_select(bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Write known bytes to disk, open them in bridge, and set a selection.

    Args:
        bridge: An initialized HexEditorBridge fixture.
        tmp_path: Pytest temporary directory.
    """
    payload = b"\xde\xad\xbe\xef"
    f = tmp_path / "copyas.bin"
    f.write_bytes(payload)
    _run(bridge.open_file(str(f)))
    _run(bridge.select_range(_SELECTION_START, _SELECTION_END))


class TestBridgeCopyAs:
    """Tests covering all copy_as output formats."""

    def test_copy_as_hex_contains_spaces(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that the hex format produces space-separated byte tokens.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("hex"))
        assert " " in result
        tokens = result.split(" ")
        assert all(len(t) == 2 for t in tokens)

    def test_copy_as_hex_expected_value(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that hex format output matches the known byte values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("hex"))
        assert result == "DE AD BE EF"

    def test_copy_as_c_array_has_curly_braces(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that c_array format output contains the exact expected byte literals.

        The format must enclose the bytes in curly braces AND produce hex literals
        that decode back to the original input bytes.  A shape-only check (braces
        present) cannot catch a corrupted encoding where the bytes inside are wrong.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("c_array"))
        assert result.startswith("{")
        assert result.endswith("}")
        inner = result[1:-1].strip()
        hex_tokens = [t.strip().rstrip(",") for t in inner.split(",") if t.strip()]
        assert len(hex_tokens) == 4, f"Expected 4 byte literals, got {len(hex_tokens)}: {hex_tokens}"
        decoded = bytes(int(t, 16) for t in hex_tokens)
        assert decoded == b"\xde\xad\xbe\xef", f"c_array decoded to wrong bytes: {decoded!r}"

    def test_copy_as_python_starts_with_b_quote(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that python format output encodes the exact original bytes.

        The format must produce a valid Python bytes literal.  Verifying both the
        structural prefix/suffix AND that the escape sequences inside match the
        expected bytes ensures that a corrupted encoding would be caught.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("python"))
        assert result.startswith('b"')
        assert result.endswith('"')
        inner = result[2:-1]
        assert "\\xde" in inner or "\\xDE" in inner.upper(), f"Expected \\xde in python format inner: {inner!r}"
        assert "\\xad" in inner or "\\xAD" in inner.upper(), f"Expected \\xad in python format inner: {inner!r}"
        assert "\\xbe" in inner or "\\xBE" in inner.upper(), f"Expected \\xbe in python format inner: {inner!r}"
        assert "\\xef" in inner or "\\xEF" in inner.upper(), f"Expected \\xef in python format inner: {inner!r}"

    def test_copy_as_rust_array_has_square_brackets(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that rust_array format output encodes the exact original bytes.

        The result must be enclosed in square brackets AND the hex literals inside
        must decode back to the input bytes.  A shape-only check cannot detect
        wrong byte values inside the brackets.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("rust_array"))
        assert result.startswith("[")
        assert result.endswith("]")
        inner = result[1:-1].strip()
        hex_tokens = [t.strip().rstrip(",") for t in inner.split(",") if t.strip()]
        assert len(hex_tokens) == 4, f"Expected 4 byte literals in rust_array, got {len(hex_tokens)}: {hex_tokens}"
        decoded = bytes(int(t, 16) for t in hex_tokens)
        assert decoded == b"\xde\xad\xbe\xef", f"rust_array decoded to wrong bytes: {decoded!r}"

    def test_copy_as_go_slice_has_byte_prefix(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that go_slice format output encodes the exact original bytes.

        The result must begin with ``[]byte{`` and the hex literals inside must
        decode back to the input bytes.  A prefix-only check cannot detect wrong
        byte values inside the Go slice literal.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("go_slice"))
        assert result.startswith("[]byte{")
        assert result.endswith("}")
        inner = result[len("[]byte{") : -1].strip()
        hex_tokens = [t.strip().rstrip(",") for t in inner.split(",") if t.strip()]
        assert len(hex_tokens) == 4, f"Expected 4 byte literals in go_slice, got {len(hex_tokens)}: {hex_tokens}"
        decoded = bytes(int(t, 16) for t in hex_tokens)
        assert decoded == b"\xde\xad\xbe\xef", f"go_slice decoded to wrong bytes: {decoded!r}"

    def test_copy_as_base64_is_decodable(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that base64 format output decodes back to the original bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("base64"))
        decoded = base64.b64decode(result)
        assert decoded == b"\xde\xad\xbe\xef"

    def test_copy_as_hex_string_no_spaces_has_no_spaces(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that hex_string_no_spaces format contains no whitespace.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("hex_string_no_spaces"))
        assert " " not in result
        assert result == "DEADBEEF"

    def test_copy_as_markdown_table_has_header(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that markdown_table format has correct headers and encodes all selected bytes.

        Verifies that the table contains the expected column headers AND that the
        data rows collectively contain the correct hex values for all four of the
        known input bytes (DE AD BE EF).  The bridge may produce one row per byte
        or multiple bytes per row; either way the full hex representation must
        appear somewhere in the data section.  A header-only check cannot detect
        a corrupted data encoding.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("markdown_table"))
        assert "| Offset |" in result
        assert "| Hex |" in result
        assert "| ASCII |" in result

        lines = [ln.strip() for ln in result.splitlines() if "|" in ln]
        data_rows = [ln for ln in lines if "---" not in ln and "Offset" not in ln]
        assert len(data_rows) >= 1, f"markdown_table has no data rows: {result!r}"

        all_data = " ".join(data_rows).upper()
        for expected_hex, byte_val in [("DE", 0xDE), ("AD", 0xAD), ("BE", 0xBE), ("EF", 0xEF)]:
            assert expected_hex in all_data, (
                f"Expected hex value '{expected_hex}' (0x{byte_val:02X}) not found anywhere in markdown_table data rows: {data_rows!r}"
            )
