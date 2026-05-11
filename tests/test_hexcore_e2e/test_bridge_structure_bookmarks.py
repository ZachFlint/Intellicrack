# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge PE/ELF structure bookmark generation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


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


class TestPEStructureBookmarks:
    """Tests for PE structure bookmark auto-generation."""

    def test_pe_structure_creates_bookmarks(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify PE structure detection produces header and section bookmarks.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        bookmarks = _run(bridge.generate_structure_bookmarks())
        labels = [b["label"] for b in bookmarks]
        assert any("DOS Header" in lbl for lbl in labels)
        assert any("PE Signature" in lbl for lbl in labels)
        assert any("COFF Header" in lbl for lbl in labels)
        assert any("Optional Header" in lbl for lbl in labels)
        assert any("Section" in lbl for lbl in labels)

    def test_pe_bookmarks_have_colors(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify each PE bookmark has a color key with distinct color values.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        bookmarks = _run(bridge.generate_structure_bookmarks())
        assert bookmarks
        colors: set[str] = set()
        for bm in bookmarks:
            assert "color" in bm
            assert bm["color"].startswith("#")
            colors.add(bm["color"])
        assert len(colors) >= 2


class TestELFStructureBookmarks:
    """Tests for ELF structure bookmark auto-generation."""

    def test_elf_structure_creates_bookmarks(self, bridge: HexEditorBridge, elf_binary_with_loads: Path) -> None:
        """Verify ELF structure detection produces header and program header bookmarks.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            elf_binary_with_loads: Path to an ELF binary with PT_LOAD segments.
        """
        _run(bridge.open_file(str(elf_binary_with_loads)))
        bookmarks = _run(bridge.generate_structure_bookmarks())
        labels = [b["label"] for b in bookmarks]
        assert any("ELF Header" in lbl for lbl in labels)
        assert any("Program Header" in lbl for lbl in labels)


class TestStructureBookmarkEdgeCases:
    """Tests for edge cases in structure bookmark generation."""

    def test_unknown_format_returns_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify that an unrecognized binary format returns no bookmarks.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        f = tmp_path / "random.bin"
        f.write_bytes(b"\x00" * 128)
        _run(bridge.open_file(str(f)))
        bookmarks = _run(bridge.generate_structure_bookmarks())
        assert bookmarks == []

    def test_bookmarks_added_to_document(self, bridge: HexEditorBridge, pe_binary_full: Path) -> None:
        """Verify generated bookmarks appear in the document bookmark list.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary_full: Path to a PE binary with full Optional Header.
        """
        _run(bridge.open_file(str(pe_binary_full)))
        generated = _run(bridge.generate_structure_bookmarks())
        assert generated
        doc_bookmarks = _run(bridge.list_bookmarks())
        assert len(doc_bookmarks) >= len(generated)

    def test_no_document_raises(self, bridge: HexEditorBridge) -> None:
        """Verify generate_structure_bookmarks raises RuntimeError without a document.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.generate_structure_bookmarks())
