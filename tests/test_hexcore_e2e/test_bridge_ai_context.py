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


_EXPECTED_TOP_LEVEL_KEYS = {
    "file_path",
    "size",
    "modified",
    "cursor",
    "selection",
}


class TestBridgeAIContext:
    """Tests covering the structure and content of get_context_for_ai."""

    def test_get_context_for_ai_contains_expected_top_level_keys(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the AI context dict has the required document info keys.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        for key in _EXPECTED_TOP_LEVEL_KEYS:
            assert key in ctx, f"missing key: {key}"

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
        """Verify that the bookmarks field in the AI context is a list.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        assert "bookmarks" in ctx
        assert isinstance(ctx["bookmarks"], list)

    def test_get_context_for_ai_bookmarks_contain_expected_fields_when_present(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that each bookmark in the AI context has offset, length, label.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        _run(loaded_bridge.add_bookmark(0, 2, "MZ_magic", "#FF0000"))
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        bms: list[dict[str, Any]] = ctx["bookmarks"]
        assert bms
        for bm in bms:
            assert "offset" in bm
            assert "length" in bm
            assert "label" in bm

    def test_get_context_for_ai_size_is_positive(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify that the size field in the AI context is a positive integer.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        assert isinstance(ctx["size"], int)
        assert ctx["size"] > 0

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
