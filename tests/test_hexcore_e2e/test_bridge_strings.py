# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge string extraction from binary data."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


pytest.importorskip(
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


class TestGetStrings:
    """Tests for the get_strings method extracting text from binary data."""

    def test_extract_ascii_strings(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify ASCII string extraction finds the embedded test string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded ASCII and UTF-16 strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="ascii"))
        contents = [r["content"] for r in results]
        assert any("Hello World" in c for c in contents)

    def test_extract_utf16_strings(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify UTF-16 string extraction finds the embedded test string.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="utf16"))
        contents = [r["content"] for r in results]
        assert any("Test String" in c for c in contents)

    def test_extract_both_encodings(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify ascii+utf16 extraction finds strings from both encodings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, encoding="ascii+utf16"))
        contents = [r["content"] for r in results]
        assert any("Hello World" in c for c in contents)
        assert any("Test String" in c for c in contents)

    def test_min_length_filter(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify min_length parameter filters out shorter strings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=10, encoding="ascii"))
        for r in results:
            assert len(r["content"]) >= 10

    def test_max_results_limit(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify max_results limits the number of returned strings.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4, max_results=1))
        assert len(results) <= 1

    def test_string_dict_structure(self, bridge: HexEditorBridge, string_test_data: Path) -> None:
        """Verify each string result dict has the required keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            string_test_data: Path to a file with embedded strings.
        """
        _run(bridge.open_file(str(string_test_data)))
        results: list[dict[str, Any]] = _run(bridge.get_strings(min_length=4))
        assert results
        for r in results:
            assert "offset" in r
            assert "length" in r
            assert "encoding" in r
            assert "content" in r

    def test_empty_doc_returns_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify string extraction on a zero-length file returns empty list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        _run(bridge.open_file(str(f)))
        results: list[dict[str, Any]] = _run(bridge.get_strings())
        assert results == []

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify get_strings raises RuntimeError without an open document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.get_strings())
