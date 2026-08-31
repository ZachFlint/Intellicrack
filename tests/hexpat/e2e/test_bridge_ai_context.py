# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge get_context_for_ai output structure."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any


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


_EXPECTED_TOP_LEVEL_KEYS = {
    "file_path",
    "size",
    "modified",
    "cursor",
    "selection",
}


class TestBridgeAIContext:
    """Tests covering the structure and content of get_context_for_ai."""

    def test_get_context_for_ai_contains_expected_top_level_keys(
        self,
        loaded_bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Verify AI context carries exact values for all five document-info fields.

        The oracle for size is pe_binary.stat().st_size (the file written by the
        fixture). The PE is opened unmodified so modified must be False, cursor
        must be 0 (initial position), and selection must be None. file_path must
        match the string form of pe_binary. A mutation dropping or miscomputing
        any field would fail the corresponding assertion.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            pe_binary: Path to the PE binary used by loaded_bridge.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        expected_size: int = pe_binary.stat().st_size
        assert ctx["size"] == expected_size, f"size must equal file size {expected_size}; got {ctx['size']!r}"
        assert ctx["modified"] is False, f"unmodified document must have modified=False; got {ctx['modified']!r}"
        assert ctx["cursor"] == 0, f"initial cursor must be 0; got {ctx['cursor']!r}"
        assert ctx["selection"] is None, f"no selection set so selection must be None; got {ctx['selection']!r}"
        assert ctx["file_path"] == str(pe_binary), f"file_path must match opened path; got {ctx['file_path']!r}"

    def test_get_context_for_ai_bytes_at_cursor_is_hex_string(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that bytes_at_cursor is a non-empty hex string.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        assert "bytes_at_cursor" in ctx
        bac: str = ctx["bytes_at_cursor"]
        assert isinstance(bac, str)
        assert bac
        tokens = bac.split(" ")
        for token in tokens:
            assert len(token) == 2
            int(token, 16)

    def test_get_context_for_ai_bookmarks_is_list(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the bookmarks field in the AI context is an empty list when no bookmarks exist.

        The loaded_bridge fixture adds no bookmarks, so the document's bookmark store
        is empty. A mutation that initialises bookmarks to None or a non-empty
        sentinel would fail this exact equality check.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        assert ctx["bookmarks"] == [], f"no bookmarks added so bookmarks must be []; got {ctx['bookmarks']!r}"

    def test_get_context_for_ai_bookmarks_contain_expected_fields_when_present(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that each bookmark in the AI context carries correct offset, length, label values.

        Adds a single bookmark with known parameters and checks that the
        AI context round-trips the exact values through the native store
        and the bridge serialization path.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        _run(loaded_bridge.add_bookmark(0, 2, "MZ_magic", "#FF0000"))
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        bms: list[dict[str, Any]] = ctx["bookmarks"]
        assert bms, "expected at least one bookmark in AI context"
        first: dict[str, Any] = bms[0]
        assert first["offset"] == 0, f"expected offset 0, got {first['offset']!r}"
        assert first["length"] == 2, f"expected length 2, got {first['length']!r}"
        assert first["label"] == "MZ_magic", f"expected label 'MZ_magic', got {first['label']!r}"

    def test_get_context_for_ai_size_is_positive(
        self,
        loaded_bridge: HexEditorBridge,
        pe_binary: Path,
    ) -> None:
        """Verify that the size field in the AI context equals the on-disk file size.

        The oracle is pe_binary.stat().st_size, independent of the bridge. A
        mutation returning 0, -1, or a truncated size would fail this exact
        equality check.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
            pe_binary: Path to the PE binary used by loaded_bridge.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        expected_size: int = pe_binary.stat().st_size
        assert ctx["size"] == expected_size, f"size must equal file size {expected_size}; got {ctx['size']!r}"

    def test_get_context_for_ai_file_path_matches_opened_file(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify that file_path in AI context matches the opened file path.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai())
        assert ctx["file_path"] == str(pe_binary)

    def test_get_context_for_ai_cursor_reflects_goto_offset(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify that the cursor field reflects the offset set by goto_offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(16))
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai())
        assert ctx["cursor"] == 16
