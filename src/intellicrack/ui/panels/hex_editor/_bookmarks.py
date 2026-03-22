# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bookmarks mixin for the hex editor panel."""

from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem


class BookmarksMixin:
    """Mixin providing bookmark management for the hex editor panel."""

    _document: Any | None
    _hex_widget: Any | None
    _bookmarks_tree: QTreeWidget | None

    def _on_add_bookmark(self) -> None:
        """Add a bookmark at the current cursor position."""
        if self._document is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        self._document.add_bookmark(cursor_offset, 1, "Bookmark", "#FFFF00")
        self._refresh_bookmarks()

    def _on_remove_bookmark(self) -> None:
        """Remove the selected bookmark."""
        if self._document is None or self._bookmarks_tree is None:
            return

        current = self._bookmarks_tree.currentItem()
        if current is None:
            return

        index = self._bookmarks_tree.indexOfTopLevelItem(current)
        if index >= 0:
            self._document.remove_bookmark(index)
            self._refresh_bookmarks()

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks tree from the document."""
        if self._bookmarks_tree is None or self._document is None:
            return

        self._bookmarks_tree.clear()
        bookmarks = self._document.list_bookmarks()
        for bm in bookmarks:
            offset_str = f"0x{bm[0]:08X}"
            length_str = str(bm[1])
            label = str(bm[2])
            item = QTreeWidgetItem([offset_str, length_str, label])
            self._bookmarks_tree.addTopLevelItem(item)
