# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument bookmark CRUD operations."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument


class TestBookmarks:
    """Tests covering add, list, remove, and persistence of bookmarks."""

    def test_list_bookmarks_empty_on_fresh_doc(self, empty_doc: HexDocument) -> None:
        """Verify that a freshly created document has no bookmarks.

        Args:
            empty_doc: Empty HexDocument fixture.
        """
        bookmarks = empty_doc.list_bookmarks()
        assert bookmarks == []

    def test_add_bookmark_returns_index(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that add_bookmark() returns the correct insertion index and stores the bookmark.

        The first add on an empty bookmark list must return index 0.  The stored
        bookmark at that index must carry exactly the label that was passed in,
        proving the native push completed successfully.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx = sample_doc_from_bytes.add_bookmark(0, 4, "header", "#FF0000")
        assert idx == 0
        bookmarks = sample_doc_from_bytes.list_bookmarks()
        assert bookmarks[idx][2] == "header"

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


class TestBookmarkObjectApi:
    """Tests covering the Bookmark object surface of the document API.

    The exported Bookmark class is only meaningful if the document accepts and
    returns instances of it. These gate that round trip, and that the older
    scalar/tuple methods keep observing the same underlying store.
    """

    def test_add_bookmark_object_stores_instance(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify add_bookmark_object() accepts a Bookmark and stores its values.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        bookmark = hexcore.Bookmark(16, 4, "entry_point", "#ABCDEF")
        idx: int = sample_doc_from_bytes.add_bookmark_object(bookmark)
        assert idx == 0

        stored = sample_doc_from_bytes.get_bookmark(idx)
        assert stored is not None
        assert stored.offset == 16
        assert stored.length == 4
        assert stored.label == "entry_point"
        assert stored.color == "#ABCDEF"

    def test_get_bookmarks_returns_bookmark_instances(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify get_bookmarks() returns Bookmark objects, not tuples.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(4, 2, "tuple_added", "#101010")
        bookmarks = sample_doc_from_bytes.get_bookmarks()

        assert len(bookmarks) == 1
        assert isinstance(bookmarks[0], hexcore.Bookmark)
        assert bookmarks[0].label == "tuple_added"

    def test_object_and_tuple_views_agree(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify get_bookmarks() and list_bookmarks() describe the same store.

        Bookmarks are added through both entry points so neither API can be
        reading a private collection of its own.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 4, "first", "#AAAAAA")
        sample_doc_from_bytes.add_bookmark(64, 8, "second", "#BBBBBB")

        objects = sample_doc_from_bytes.get_bookmarks()
        tuples = sample_doc_from_bytes.list_bookmarks()

        assert len(objects) == len(tuples) == 2
        for obj, tup in zip(objects, tuples, strict=True):
            assert (obj.offset, obj.length, obj.label, obj.color) == tup

    def test_bookmark_added_as_object_is_visible_to_tuple_api(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify a Bookmark added as an object appears in the legacy tuple listing.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark_object(hexcore.Bookmark(128, 12, "obj", "#C0FFEE"))
        assert sample_doc_from_bytes.list_bookmarks() == [(128, 12, "obj", "#C0FFEE")]

    def test_get_bookmark_out_of_range_returns_none(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify get_bookmark() returns None for an index past the end.

        Args:
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 1, "only", "#010101")
        assert sample_doc_from_bytes.get_bookmark(1) is None

    def test_update_bookmark_replaces_in_place(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify update_bookmark() replaces one entry without disturbing others.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 1, "keep_before", "#111111")
        target = sample_doc_from_bytes.add_bookmark(10, 2, "replace_me", "#222222")
        sample_doc_from_bytes.add_bookmark(20, 3, "keep_after", "#333333")

        replaced: bool = sample_doc_from_bytes.update_bookmark(
            target,
            hexcore.Bookmark(99, 7, "replaced", "#444444"),
        )
        assert replaced is True

        bookmarks = sample_doc_from_bytes.get_bookmarks()
        assert [b.label for b in bookmarks] == ["keep_before", "replaced", "keep_after"]
        assert (bookmarks[1].offset, bookmarks[1].length, bookmarks[1].color) == (99, 7, "#444444")

    def test_update_bookmark_out_of_range_returns_false(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify update_bookmark() reports failure for an invalid index and changes nothing.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        sample_doc_from_bytes.add_bookmark(0, 1, "untouched", "#555555")

        replaced: bool = sample_doc_from_bytes.update_bookmark(
            5,
            hexcore.Bookmark(1, 1, "ghost", "#666666"),
        )
        assert replaced is False
        assert [b.label for b in sample_doc_from_bytes.get_bookmarks()] == ["untouched"]

    def test_mutated_bookmark_requires_update_to_persist(
        self,
        hexcore: types.ModuleType,
        sample_doc_from_bytes: HexDocument,
    ) -> None:
        """Verify get_bookmarks() hands back detached copies until update_bookmark() is called.

        Mutating a returned Bookmark must not silently rewrite document state;
        the change only lands once it is written back.

        Args:
            hexcore: The native module fixture.
            sample_doc_from_bytes: In-memory HexDocument from open_bytes.
        """
        idx = sample_doc_from_bytes.add_bookmark_object(hexcore.Bookmark(0, 4, "original", "#777777"))

        detached = sample_doc_from_bytes.get_bookmarks()[0]
        detached.label = "mutated"
        assert sample_doc_from_bytes.get_bookmarks()[0].label == "original"

        sample_doc_from_bytes.update_bookmark(idx, detached)
        assert sample_doc_from_bytes.get_bookmarks()[0].label == "mutated"
