# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument bookmark CRUD operations."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from intellicrack_hexcore import HexDocument


class TestBookmarks:
    """Tests covering add, list, remove, and persistence of bookmarks."""

    def test_list_bookmarks_empty_on_fresh_doc(self, empty_doc: HexDocument) -> None:
        """A fresh document yields a concrete empty ``list``, not any empty iterable.

        Asserting the exact ``list`` type (not merely ``== []``) catches a
        regression where ``list_bookmarks`` returns a lazy generator, a tuple,
        or ``None`` - all of which could compare equal-ish to or be falsy like
        an empty list yet break callers that index or re-iterate. Adding one
        bookmark and re-listing proves the empty result was the genuine
        "no bookmarks" state and that the same accessor transitions to a
        populated 4-tuple list, not a permanently-empty stub.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        bookmarks = empty_doc.list_bookmarks()
        assert type(bookmarks) is list, f"list_bookmarks must return a concrete list; got {type(bookmarks).__name__}"
        assert bookmarks == [], f"a fresh document must have no bookmarks; got {bookmarks!r}"

        empty_doc.add_bookmark(0, 1, "first", "#FF0000")
        populated = empty_doc.list_bookmarks()
        assert type(populated) is list, "list_bookmarks must still return a list after an add"
        assert populated == [(0, 1, "first", "#FF0000")], f"the same accessor must surface the added bookmark; got {populated!r}"

    def test_add_bookmark_returns_index(self, sample_doc_from_bytes: HexDocument) -> None:
        """Returned indices are distinct identifiers usable to remove the right bookmark.

        A non-negative ``int`` alone is meaningless: a defect that returns ``0``
        for every bookmark, or returns a list-length that no longer maps to a
        stored entry, would pass a bare type/range check yet make the index
        useless. This drives three distinct bookmarks in, asserts the three
        returned indices are pairwise distinct, then removes the *middle*
        bookmark by its returned index and proves exactly that bookmark - and
        no other - disappeared. The independent oracle is the labels recorded
        at insertion time, compared against the labels surviving the targeted
        removal.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx_alpha = sample_doc_from_bytes.add_bookmark(0, 4, "alpha", "#FF0000")
        idx_beta = sample_doc_from_bytes.add_bookmark(8, 2, "beta", "#00FF00")
        idx_gamma = sample_doc_from_bytes.add_bookmark(16, 8, "gamma", "#0000FF")

        for idx in (idx_alpha, idx_beta, idx_gamma):
            assert type(idx) is int, f"add_bookmark must return an int index; got {type(idx).__name__}"
            assert idx >= 0, f"index must be non-negative; got {idx}"
        assert len({idx_alpha, idx_beta, idx_gamma}) == 3, (
            f"each bookmark must receive a distinct index; got {idx_alpha}, {idx_beta}, {idx_gamma}"
        )

        assert sample_doc_from_bytes.remove_bookmark(idx_beta) is True, "removing the middle bookmark by its returned index must succeed"

        surviving = sample_doc_from_bytes.list_bookmarks()
        labels = [bm[2] for bm in surviving]
        assert labels == ["alpha", "gamma"], f"only the targeted middle bookmark may be removed; surviving labels {labels!r}"

    def test_list_bookmarks_contains_added_bookmark(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that a freshly added bookmark appears in list_bookmarks().

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(8, 16, "section", "#00FF00")
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 1

    def test_bookmark_fields_match(self, sample_doc_from_bytes: HexDocument) -> None:
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

    def test_add_multiple_bookmarks_preserves_order(self, sample_doc_from_bytes: HexDocument) -> None:
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

    def test_remove_bookmark_by_index(self, sample_doc_from_bytes: HexDocument) -> None:
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

    def test_remove_bookmark_returns_false_for_invalid_index(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that remove_bookmark() returns False for an out-of-range index.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        result = sample_doc_from_bytes.remove_bookmark(9999)
        assert result is False

    def test_bookmark_survives_write_operation(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that writing to the document does not remove existing bookmarks.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 4, "persistent", "#AABBCC")
        sample_doc_from_bytes.write_bytes(50, b"\xde\xad")
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert len(bookmarks) == 1
        assert bookmarks[0][2] == "persistent"

    def test_remove_one_of_multiple_bookmarks_leaves_others(self, sample_doc_from_bytes: HexDocument) -> None:
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
