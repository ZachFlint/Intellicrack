# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge copy_as formatting."""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


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


_SELECTION_START = 0
_SELECTION_END = 3


def _load_and_select(bridge: Any, tmp_path: Path) -> None:
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

    def test_copy_as_hex_contains_spaces(self, bridge: Any, tmp_path: Path) -> None:
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

    def test_copy_as_hex_expected_value(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that hex format output matches the known byte values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("hex"))
        assert result == "DE AD BE EF"

    def test_copy_as_c_array_has_curly_braces(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that c_array format wraps the bytes in curly braces.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("c_array"))
        assert result.startswith("{")
        assert result.endswith("}")

    def test_copy_as_python_starts_with_b_quote(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that python format output starts with the bytes literal prefix.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("python"))
        assert result.startswith('b"')
        assert result.endswith('"')

    def test_copy_as_rust_array_has_square_brackets(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that rust_array format output is enclosed in square brackets.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("rust_array"))
        assert result.startswith("[")
        assert result.endswith("]")

    def test_copy_as_go_slice_has_byte_prefix(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that go_slice format output begins with the Go byte-slice literal.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("go_slice"))
        assert result.startswith("[]byte{")

    def test_copy_as_base64_is_decodable(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that base64 format output decodes back to the original bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("base64"))
        decoded = base64.b64decode(result)
        assert decoded == b"\xde\xad\xbe\xef"

    def test_copy_as_hex_string_no_spaces_has_no_spaces(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that hex_string_no_spaces format contains no whitespace.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("hex_string_no_spaces"))
        assert " " not in result
        assert result == "DEADBEEF"

    def test_copy_as_markdown_table_has_header(self, bridge: Any, tmp_path: Path) -> None:
        """Verify that markdown_table format contains the expected column headers.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        _load_and_select(bridge, tmp_path)
        result: str = _run(bridge.copy_as("markdown_table"))
        assert "| Offset |" in result
        assert "| Hex |" in result
        assert "| ASCII |" in result
