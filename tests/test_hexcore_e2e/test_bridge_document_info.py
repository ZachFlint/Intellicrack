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

    def test_no_document_full_state_is_empty_and_consistent(self, bridge: HexEditorBridge) -> None:
        """Verify the entire no-document state dict equals the exact empty-document contract.

        When no file is open the bridge must report a fully-specified, internally
        consistent empty state: exactly the five required keys, file_path None,
        size 0, modified False, cursor 0, and selection None. Asserting the dict
        as a whole (not one field) makes the test fail if any single field
        regresses or an unexpected key is added.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info == {
            "file_path": None,
            "size": 0,
            "modified": False,
            "cursor": 0,
            "selection": None,
        }
        assert set(info.keys()) == _REQUIRED_KEYS

    def test_no_document_state_stable_across_repeated_calls(self, bridge: HexEditorBridge) -> None:
        """Verify repeated get_document_info calls with no document return identical state.

        The empty-document report must be deterministic and side-effect free:
        calling it twice in a row yields byte-for-byte equal dicts.

        Args:
            bridge: An initialized HexEditorBridge fixture.
        """
        first: dict[str, Any] = _run(bridge.get_document_info())
        second: dict[str, Any] = _run(bridge.get_document_info())
        assert first == second
        assert first["file_path"] is None
        assert first["size"] == 0
        assert first["modified"] is False
        assert first["cursor"] == 0
        assert first["selection"] is None


class TestDocumentInfoErrorPaths:
    """Tests covering get_document_info behavior around open failures."""

    def test_open_missing_file_raises_oserror_and_state_stays_empty(self, bridge: HexEditorBridge, tmp_path: Path) -> None:
        """Verify opening a missing path raises OSError and leaves the empty-document state intact.

        Drives a real open against a path that does not exist on disk; the Rust
        core must surface an OSError, and the bridge must not partially mutate its
        document state, so a subsequent get_document_info still reports the exact
        empty contract.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            tmp_path: Pytest temporary directory.
        """
        missing: Path = tmp_path / "definitely_absent.bin"
        assert not missing.exists()
        with pytest.raises(OSError, match=r"os error"):
            _run(bridge.open_file(str(missing)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info == {
            "file_path": None,
            "size": 0,
            "modified": False,
            "cursor": 0,
            "selection": None,
        }


class TestDocumentInfoWithFile:
    """Tests covering get_document_info after a file has been opened."""

    def test_open_pe_reports_full_pristine_state(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify the complete document-info dict after opening a pristine PE file.

        Asserts the whole dict at once against an independent oracle: file_path is
        the canonical opened path, size equals the on-disk byte count, modified is
        False, cursor is 0 and selection None for a freshly opened file.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        expected_size: int = pe_binary.stat().st_size
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info == {
            "file_path": str(pe_binary),
            "size": expected_size,
            "modified": False,
            "cursor": 0,
            "selection": None,
        }

    def test_open_pe_size_is_1024(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify size equals the on-disk PE file size (1024 bytes).

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["size"] == pe_binary.stat().st_size
        assert info["size"] == 1024

    def test_write_bytes_sets_modified_true_and_persists_exact_byte(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify a write flips modified to True and the written byte is exactly readable.

        Reads the original first byte (independent oracle), overwrites it with a
        distinct value, then asserts both that modified became True and that the
        document now reads back the exact new byte rather than the original.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        original_hex: str = _run(bridge.read_bytes(0, 1))
        assert original_hex.upper() == "4D"
        _run(bridge.write_bytes(0, "AA"))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info["modified"] is True
        assert _run(bridge.read_bytes(0, 1)).upper() == "AA"

    def test_goto_offset_updates_cursor_at_boundaries(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify cursor reflects goto_offset at zero, mid-file, and the last valid offset.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        size: int = pe_binary.stat().st_size
        _run(bridge.open_file(str(pe_binary)))
        for target in (0, 256, size - 1):
            _run(bridge.goto_offset(target))
            info: dict[str, Any] = _run(bridge.get_document_info())
            assert info["cursor"] == target

    def test_select_range_sets_exact_selection_pair(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify selection reflects the exact [start, end] range set by select_range.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.select_range(10, 20))
        info: dict[str, Any] = _run(bridge.get_document_info())
        selection: object = info["selection"]
        assert isinstance(selection, list)
        assert selection == [10, 20]

    def test_multiple_operations_full_state_is_consistent(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify the entire info dict after a sequence of cursor, selection, and write ops.

        Opens a file, moves the cursor, selects a range, writes a byte, then
        asserts the full dict against an independent oracle so every tracked
        field is gated simultaneously.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        expected_size: int = pe_binary.stat().st_size
        _run(bridge.open_file(str(pe_binary)))
        _run(bridge.goto_offset(64))
        _run(bridge.select_range(32, 96))
        _run(bridge.write_bytes(0, "CC"))
        info: dict[str, Any] = _run(bridge.get_document_info())
        assert info == {
            "file_path": str(pe_binary),
            "size": expected_size,
            "modified": True,
            "cursor": 64,
            "selection": [32, 96],
        }

    def test_undo_after_write_restores_original_byte(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Verify undo after a single write restores the exact original byte.

        Captures the original byte as an independent oracle, writes a distinct
        value, confirms the document reports modified, then undoes and asserts the
        byte is byte-for-byte restored.

        Args:
            bridge: An initialized HexEditorBridge fixture.
            pe_binary: Path to the PE binary fixture.
        """
        _run(bridge.open_file(str(pe_binary)))
        original_byte_hex: str = _run(bridge.read_bytes(0, 1))
        _run(bridge.write_bytes(0, "AA"))
        assert _run(bridge.get_document_info())["modified"] is True
        undone: bool = _run(bridge.undo())
        assert undone is True
        after_undo_hex: str = _run(bridge.read_bytes(0, 1))
        assert after_undo_hex == original_byte_hex
