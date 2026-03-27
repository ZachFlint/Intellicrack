# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument undo/redo stack and modification tracking."""

from __future__ import annotations

from typing import Any


class TestUndoRedo:
    """Tests covering the undo/redo stack behaviour under write operations."""

    def test_can_undo_false_on_fresh_doc(self, empty_doc: Any) -> None:
        """Verify that a newly created document has no undo history.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert not empty_doc.can_undo()

    def test_can_redo_false_on_fresh_doc(self, empty_doc: Any) -> None:
        """Verify that a newly created document has no redo history.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert not empty_doc.can_redo()

    def test_write_enables_can_undo(self, sample_doc_from_bytes: Any) -> None:
        """Verify that performing a write operation enables undo.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xFF")
        assert sample_doc_from_bytes.can_undo()

    def test_undo_restores_previous_data(self, sample_doc_from_bytes: Any) -> None:
        """Verify that undo() reverts the document to the state before the write.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        original = sample_doc_from_bytes.read(0, 4)
        sample_doc_from_bytes.write_bytes(0, b"\x00\x00\x00\x00")
        assert sample_doc_from_bytes.read(0, 4) == b"\x00\x00\x00\x00"
        result = sample_doc_from_bytes.undo()
        assert result is True
        assert sample_doc_from_bytes.read(0, 4) == original

    def test_redo_restores_written_data(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that redo() re-applies the undone write.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        write_payload = b"\xAA\xBB\xCC\xDD"
        sample_doc_from_bytes.write_bytes(0, write_payload)
        sample_doc_from_bytes.undo()
        assert sample_doc_from_bytes.can_redo()
        result = sample_doc_from_bytes.redo()
        assert result is True
        assert sample_doc_from_bytes.read(0, 4) == write_payload

    def test_multiple_undo_steps(self, sample_doc_from_bytes: Any) -> None:
        """Verify that successive undo calls walk back multiple operations.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        original_0 = sample_doc_from_bytes.read(0, 1)
        original_1 = sample_doc_from_bytes.read(1, 1)

        sample_doc_from_bytes.write_bytes(0, b"\x11")
        sample_doc_from_bytes.write_bytes(1, b"\x22")

        assert sample_doc_from_bytes.read(0, 1) == b"\x11"
        assert sample_doc_from_bytes.read(1, 1) == b"\x22"

        sample_doc_from_bytes.undo()
        assert sample_doc_from_bytes.read(1, 1) == original_1

        sample_doc_from_bytes.undo()
        assert sample_doc_from_bytes.read(0, 1) == original_0

    def test_new_write_after_undo_clears_redo_stack(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that writing after an undo invalidates the redo history.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xAA")
        sample_doc_from_bytes.undo()
        assert sample_doc_from_bytes.can_redo()
        sample_doc_from_bytes.write_bytes(0, b"\xBB")
        assert not sample_doc_from_bytes.can_redo()

    def test_can_redo_true_after_undo(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that can_redo() is True immediately after an undo operation.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xCC")
        sample_doc_from_bytes.undo()
        assert sample_doc_from_bytes.can_redo()

    def test_undo_returns_false_when_stack_empty(self, empty_doc: Any) -> None:
        """Verify that undo() returns False when there is nothing to undo.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert empty_doc.undo() is False

    def test_redo_returns_false_when_stack_empty(self, empty_doc: Any) -> None:
        """Verify that redo() returns False when there is nothing to redo.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        assert empty_doc.redo() is False


class TestModificationTracking:
    """Tests covering is_modified() state transitions."""

    def test_is_modified_false_on_fresh_open(
        self, sample_doc: Any
    ) -> None:
        """Verify that a freshly opened file-backed document is not modified.

        Args:
            sample_doc: HexDocument loaded from disk fixture.
        """
        assert not sample_doc.is_modified()

    def test_is_modified_true_after_write(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify that a write marks the document as modified.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xFF")
        assert sample_doc_from_bytes.is_modified()

    def test_is_modified_tracks_through_undo_redo(
        self, sample_doc_from_bytes: Any
    ) -> None:
        """Verify is_modified() reflects undo/redo transitions accurately.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.write_bytes(0, b"\xAB")
        assert sample_doc_from_bytes.is_modified()

        sample_doc_from_bytes.undo()

        sample_doc_from_bytes.redo()
        assert sample_doc_from_bytes.is_modified()
