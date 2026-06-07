# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexEditorBridge.get_document_info() return values."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore")

_REQUIRED_KEYS: frozenset[str] = frozenset({"file_path", "size", "modified", "cursor", "selection"})


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


class TestDocumentInfoNoDocument:
    """Tests covering get_document_info when no file is open."""

    def test_no_document_file_path_is_none(self, bridge: HexEditorBridge) -> None:
        """Verify file_path is None when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["file_path"] is None

    def test_no_document_size_is_zero(self, bridge: HexEditorBridge) -> None:
        """Verify size is 0 when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["size"] == 0

    def test_no_document_modified_is_false(self, bridge: HexEditorBridge) -> None:
        """Verify modified is False when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["modified"] is False

    def test_no_document_cursor_is_zero(self, bridge: HexEditorBridge) -> None:
        """Verify cursor is 0 when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["cursor"] == 0

    def test_no_document_selection_is_none(self, bridge: HexEditorBridge) -> None:
        """Verify selection is None when no document is open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["selection"] is None

    def test_no_document_all_required_keys_present(self, bridge: HexEditorBridge) -> None:
        """Verify all required keys are present even with no document open.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert _REQUIRED_KEYS.issubset(info.keys())


class TestDocumentInfoWithFile:
    """Tests covering get_document_info after a file has been opened."""

    def test_open_pe_file_path_matches(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify file_path matches the opened PE file path.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["file_path"] == str(pe_binary)

    def test_open_pe_size_is_1024(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify size equals the on-disk PE file size (1024 bytes).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["size"] == pe_binary.stat().st_size

    def test_open_pe_modified_is_false(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify modified is False immediately after opening a file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["modified"] is False

    def test_write_bytes_sets_modified_true(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify modified becomes True after writing bytes.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.write_bytes(0, "AA"))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["modified"] is True

    def test_goto_offset_updates_cursor(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify cursor field reflects the offset set by goto_offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(256))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["cursor"] == 256

    def test_select_range_sets_selection(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify selection reflects the range set by select_range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.select_range(10, 20))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["selection"] == [10, 20]

    def test_all_required_keys_present_with_file(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify all required keys are present after opening a file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert _REQUIRED_KEYS.issubset(info.keys())

    def test_multiple_operations_info_consistency(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify info remains self-consistent after a sequence of operations.

        Opens a file, moves cursor, selects a range, and confirms info fields
        all agree with the operations performed.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(64))
        _run(bridge.select_range(32, 96))
        _run(bridge.write_bytes(0, "CC"))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["file_path"] is not None
        assert info["size"] > 0
        assert info["cursor"] == 64
        assert info["selection"] == [32, 96]
        assert info["modified"] is True

    def test_size_matches_actual_file_size(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify size in document info exactly matches the file's on-disk size.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        expected_size = pe_binary.stat().st_size
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["size"] == expected_size

    def test_undo_after_write_may_clear_modified(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify undo after a single write may restore unmodified state.

        After writing and then undoing, the document may report modified as
        False if the hexcore undo stack tracks modification accurately.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        original_byte_hex: str = _run(bridge.read_bytes(0, 1))
        _run(bridge.write_bytes(0, "AA"))
        assert _run(bridge.get_document_info())["modified"] is True
        undone: bool = _run(bridge.undo())
        if undone:
            after_undo_hex: str = _run(bridge.read_bytes(0, 1))
            assert after_undo_hex == original_byte_hex
