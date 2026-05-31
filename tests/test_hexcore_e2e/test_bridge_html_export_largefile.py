# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge annotated HTML export and large file memory controls."""

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


class TestHTMLExport:
    """Tests for annotated HTML hex dump export."""

    def test_html_export_returns_valid_html(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify export returns a string containing HTML doctype and closing tag.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "html.bin"
        f.write_bytes(b"\xaa\xbb\xcc\xdd" * 16)
        _run(bridge.open_file(str(f)))
        html = _run(bridge.export_annotated_html())
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_html_export_contains_hex_data(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify exported HTML contains hex values from the file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "html_data.bin"
        f.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 60)
        _run(bridge.open_file(str(f)))
        html = _run(bridge.export_annotated_html())
        assert "DE" in html
        assert "AD" in html
        assert "BE" in html
        assert "EF" in html

    def test_html_export_range(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify export with start/end only renders the requested range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "html_range.bin"
        f.write_bytes(bytes(range(256)))
        _run(bridge.open_file(str(f)))
        html = _run(bridge.export_annotated_html(start=16, end=32))
        assert "00000010" in html
        assert "00000000" not in html

    def test_html_export_with_bookmarks(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify exported HTML includes bookmark labels in the legend.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "html_bm.bin"
        f.write_bytes(b"\x00" * 128)
        _run(bridge.open_file(str(f)))
        _run(bridge.add_bookmark(0, 16, "TestBookmark", "#FF0000"))
        html = _run(bridge.export_annotated_html())
        assert "TestBookmark" in html

    def test_html_export_bytes_per_row(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify bytes_per_row=8 causes row offsets to increment by 8.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "html_bpr.bin"
        f.write_bytes(b"\x00" * 32)
        _run(bridge.open_file(str(f)))
        html = _run(bridge.export_annotated_html(bytes_per_row=8))
        assert "00000000" in html
        assert "00000008" in html

    def test_html_escapes_special_chars(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify HTML special characters in ASCII column are escaped.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        data = bytearray(64)
        data[0] = 0x26
        data[1] = 0x3C
        data[2] = 0x3E
        f = tmp_path / "html_esc.bin"
        f.write_bytes(bytes(data))
        _run(bridge.open_file(str(f)))
        html = _run(bridge.export_annotated_html())
        assert "&amp;" in html
        assert "&lt;" in html
        assert "&gt;" in html

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify export_annotated_html raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.export_annotated_html())


class TestLargeFileControls:
    """Tests for large file memory management controls."""

    def test_set_chunk_size(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_chunk_size returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "chunk.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.set_chunk_size(65536))
        assert result is True

    def test_get_memory_usage(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify get_memory_usage returns a dict with required keys.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "mem.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.get_memory_usage())
        assert "usage_bytes" in result
        assert "chunk_size" in result
        assert "memory_budget" in result

    def test_set_memory_budget(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify set_memory_budget returns True.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "budget.bin"
        f.write_bytes(b"\x00" * 64)
        _run(bridge.open_file(str(f)))
        result = _run(bridge.set_memory_budget(1024 * 1024))
        assert result is True
