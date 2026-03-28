# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument bookmark CRUD operations."""

from __future__ import annotations

from typing import Any


class TestBookmarks:
    """Tests covering add, list, remove, and persistence of bookmarks."""

    def test_list_bookmarks_empty_on_fresh_doc(self, empty_doc: Any) -> None:
        """Verify that a freshly created document has no bookmarks.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        bookmarks = empty_doc.list_bookmarks()
        assert bookmarks == []

    def test_add_bookmark_returns_index(self, sample_doc_from_bytes: Any) -> None:
        """Verify that add_bookmark() returns a non-negative integer index.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx = sample_doc_from_bytes.add_bookmark(0, 4, "header", "#FF0000")
        assert isinstance(idx, int)
        assert idx >= 0

    def test_list_bookmarks_contains_added_bookmark(self, sample_doc_from_bytes: Any) -> None:
        """Verify that a freshly added bookmark appears in list_bookmarks().

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(8, 16, "section", "#00FF00")
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 1

    def test_bookmark_fields_match(self, sample_doc_from_bytes: Any) -> None:
        """Verify that the stored bookmark tuple contains the correct field values.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        offset = 32
        length = 8
        label = "magic_bytes"
        color = "#0000FF"
        sample_doc_from_bytes.add_bookmark(offset, length, label, color)
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 1
        bm = bookmarks[0]
        assert bm[0] == offset
        assert bm[1] == length
        assert bm[2] == label
        assert bm[3] == color

    def test_add_multiple_bookmarks_preserves_order(self, sample_doc_from_bytes: Any) -> None:
        """Verify that multiple bookmarks are stored and returned in insertion order.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        entries: list[tuple[int, int, str, str]] = [
            (0, 4, "first", "#FF0000"),
            (10, 2, "second", "#00FF00"),
            (20, 8, "third", "#0000FF"),
        ]
        for offset, length, label, color in entries:
            sample_doc_from_bytes.add_bookmark(offset, length, label, color)

        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 3
        for i, (offset, length, label, color) in enumerate(entries):
            assert bookmarks[i][0] == offset
            assert bookmarks[i][1] == length
            assert bookmarks[i][2] == label
            assert bookmarks[i][3] == color

    def test_remove_bookmark_by_index(self, sample_doc_from_bytes: Any) -> None:
        """Verify that remove_bookmark() removes the bookmark at the given index.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx = sample_doc_from_bytes.add_bookmark(0, 4, "to_remove", "#FFFFFF")
        result = sample_doc_from_bytes.remove_bookmark(idx)
        assert result is True
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        labels = [bm[2] for bm in bookmarks]
        assert "to_remove" not in labels

    def test_remove_bookmark_returns_false_for_invalid_index(self, sample_doc_from_bytes: Any) -> None:
        """Verify that remove_bookmark() returns False for an out-of-range index.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        result = sample_doc_from_bytes.remove_bookmark(9999)
        assert result is False

    def test_bookmark_survives_write_operation(self, sample_doc_from_bytes: Any) -> None:
        """Verify that writing to the document does not remove existing bookmarks.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 4, "persistent", "#AABBCC")
        sample_doc_from_bytes.write_bytes(50, b"\xde\xad")
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 1
        assert bookmarks[0][2] == "persistent"

    def test_remove_one_of_multiple_bookmarks_leaves_others(self, sample_doc_from_bytes: Any) -> None:
        """Verify that removing one bookmark from a set leaves the remaining ones intact.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx_a = sample_doc_from_bytes.add_bookmark(0, 1, "alpha", "#111111")
        sample_doc_from_bytes.add_bookmark(10, 2, "beta", "#222222")
        sample_doc_from_bytes.add_bookmark(20, 3, "gamma", "#333333")

        sample_doc_from_bytes.remove_bookmark(idx_a)

        bookmarks = sample_doc_from_bytes.list_bookmarks()
        labels = [bm[2] for bm in bookmarks]
        assert "alpha" not in labels
        assert "beta" in labels
        assert "gamma" in labels
