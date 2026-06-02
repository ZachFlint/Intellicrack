# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge get_context_for_ai output structure."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


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

    def test_get_context_for_ai_top_level_values_match_freshly_opened_pe(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify every top-level AI-context value matches the freshly opened PE.

        The PE fixture is written to disk by the conftest builder, so the
        filesystem (``Path.stat().st_size``) is an oracle independent of the
        bridge for the document size. A freshly opened file has not been
        modified, the cursor sits at offset zero, and no selection is active,
        so each value is asserted exactly rather than merely checked for
        presence.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai())

        assert set(ctx) >= _EXPECTED_TOP_LEVEL_KEYS
        expected_size = pe_binary.stat().st_size
        assert expected_size == 1024
        assert ctx["file_path"] == str(pe_binary)
        assert ctx["size"] == expected_size
        assert ctx["modified"] is False
        assert ctx["cursor"] == 0
        assert ctx["selection"] is None

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

    def test_get_context_for_ai_bytes_at_cursor_matches_pe_dos_header(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify the cursor window renders the PE DOS header bytes exactly.

        The cursor sits at offset zero on a freshly opened file. The conftest
        builder always writes ``MZ`` (0x4D 0x5A) as the first two bytes of the
        DOS header, so the first two hex tokens of ``bytes_at_cursor`` must be
        ``4D 5A`` and ``bytes_offset`` must be zero. The full rendered window is
        cross-checked against the on-disk bytes read independently from the file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai(include_bytes=256))

        assert ctx["bytes_offset"] == 0
        raw_on_disk = pe_binary.read_bytes()[:256]
        expected_hex = " ".join(f"{b:02X}" for b in raw_on_disk)
        assert ctx["bytes_at_cursor"] == expected_hex
        assert ctx["bytes_at_cursor"].split(" ")[:2] == ["4D", "5A"]

    def test_get_context_for_ai_bookmarks_match_added_bookmark_exactly(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify the bookmark list reflects the exact bookmark that was added.

        A single bookmark is added at offset 0, length 2, label ``MZ_magic``.
        The AI context must surface exactly that bookmark with its offset,
        length, and label intact, and report a total count of one with no
        truncation. Field values are the independent oracle: they are the same
        literals passed to ``add_bookmark``, validating that the bridge does
        not silently transform or drop bookmark data.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        _run(loaded_bridge.add_bookmark(0, 2, "MZ_magic", "#FF0000"))
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())

        bms: list[dict[str, Any]] = ctx["bookmarks"]
        assert isinstance(bms, list)
        assert len(bms) == 1
        assert bms[0] == {"offset": 0, "length": 2, "label": "MZ_magic"}
        assert ctx["bookmark_count_total"] == 1
        assert ctx["bookmark_truncated"] is False

    def test_get_context_for_ai_bookmarks_empty_when_none_added(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify the AI context reports an empty, untruncated bookmark list.

        A freshly opened document has no bookmarks, so the list must be empty,
        the total count zero, and the truncation flag false.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai())
        assert ctx["bookmarks"] == []
        assert ctx["bookmark_count_total"] == 0
        assert ctx["bookmark_truncated"] is False

    def test_get_context_for_ai_bookmarks_sorted_and_truncated_at_limit(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify bookmarks are sorted by offset and capped at the bookmark limit.

        Three bookmarks are added out of offset order. With ``bookmark_limit=2``
        the context must surface the two lowest-offset bookmarks in ascending
        order, report the true total of three, and flag truncation. The
        independent oracle is the known set of offsets and the requested cap.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        _run(loaded_bridge.add_bookmark(32, 4, "third", "#00FF00"))
        _run(loaded_bridge.add_bookmark(0, 2, "first", "#FF0000"))
        _run(loaded_bridge.add_bookmark(16, 1, "second", "#0000FF"))

        ctx: dict[str, Any] = _run(loaded_bridge.get_context_for_ai(bookmark_limit=2))

        bms: list[dict[str, Any]] = ctx["bookmarks"]
        assert [bm["offset"] for bm in bms] == [0, 16]
        assert [bm["label"] for bm in bms] == ["first", "second"]
        assert ctx["bookmark_count_total"] == 3
        assert ctx["bookmark_truncated"] is True

    def test_get_context_for_ai_negative_bookmark_limit_raises(self, loaded_bridge: HexEditorBridge) -> None:
        """Verify a negative bookmark limit raises ValueError, not a swallowed error.

        Args:
            loaded_bridge: Bridge with a PE file already loaded.
        """
        with pytest.raises(ValueError, match="bookmark_limit must be non-negative"):
            _run(loaded_bridge.get_context_for_ai(bookmark_limit=-1))

    def test_get_context_for_ai_size_equals_document_length(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify size equals the actual on-disk document length.

        The on-disk file size (read via ``Path.stat``) is an oracle independent
        of the bridge. The conftest PE builder always produces a 1024-byte file,
        so both the filesystem size and the literal 1024 must agree with the
        ``size`` reported in the AI context.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai())
        assert ctx["size"] == pe_binary.stat().st_size == 1024

    def test_get_context_for_ai_size_with_no_document_is_zero(self, bridge: HexEditorBridge) -> None:
        """Verify size is zero and metadata is empty when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture (no file opened).
        """
        ctx: dict[str, Any] = _run(bridge.get_context_for_ai())
        assert ctx["size"] == 0
        assert ctx["file_path"] is None
        assert ctx["modified"] is False
        assert ctx["selection"] is None
        assert "bytes_at_cursor" not in ctx

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
