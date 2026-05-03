# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bookmarks mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QColorDialog, QInputDialog, QTreeWidget, QTreeWidgetItem, QWidget


if TYPE_CHECKING:
    from intellicrack.bridges.hex_state import HexDocumentState


class BookmarksMixin:
    """Mixin providing bookmark management for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _bookmarks_tree: QTreeWidget | None
    state_holder: HexDocumentState | None

    def _notify_state_data_modified(self, offset: int, length: int, *, source: str) -> None:
        """Forward a panel-side bookmark change extent to the shared HexDocumentState.

        Bridge subscribers (AI tools, peer GUIs) only learn about document
        state mutations through ``HexDocumentState.notify_data_modified``.
        Panel-driven bookmark operations must publish the same event so those
        consumers do not analyse stale annotated state after a GUI operation.

        Args:
            offset: Start byte offset of the affected range.
            length: Number of bytes that were affected.
            source: Caller identifier used by the loop-guard filter; must
                be unique per bookmark op so subscribers registered with
                a different source still receive the event.
        """
        state_holder = getattr(self, "state_holder", None)
        if state_holder is None:
            return
        notify = getattr(state_holder, "notify_data_modified", None)
        if not callable(notify):
            return
        notify(offset, length, source=source)

    def _on_add_bookmark(self) -> None:
        """Add a bookmark at the current cursor position with user-specified attributes."""
        if self.document is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        parent = self if isinstance(self, QWidget) else None
        name, ok = QInputDialog.getText(
            parent,
            "Add Bookmark",
            "Bookmark name:",
            text=f"Bookmark @ 0x{cursor_offset:08X}",
        )
        if not ok or not name:
            return

        color = QColorDialog.getColor(QColor("#FFFF00"), parent, "Bookmark Color")
        if not color.isValid():
            return

        self.document.add_bookmark(cursor_offset, 1, name, color.name())
        self._notify_state_data_modified(cursor_offset, 1, source="hex-editor.bookmarks.add")
        self._refresh_bookmarks()

    def _on_remove_bookmark(self) -> None:
        """Remove the selected bookmark."""
        if self.document is None or self._bookmarks_tree is None:
            return

        current = self._bookmarks_tree.currentItem()
        if current is None:
            return

        index = self._bookmarks_tree.indexOfTopLevelItem(current)
        if index >= 0:
            bookmarks = self.document.list_bookmarks()
            if index < len(bookmarks):
                bm_offset: int = int(bookmarks[index][0])
                bm_length: int = int(bookmarks[index][1])
            else:
                bm_offset = 0
                bm_length = 1
            self.document.remove_bookmark(index)
            self._notify_state_data_modified(bm_offset, bm_length, source="hex-editor.bookmarks.remove")
            self._refresh_bookmarks()

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks tree from the document."""
        if self._bookmarks_tree is None or self.document is None:
            return

        self._bookmarks_tree.clear()
        bookmarks = self.document.list_bookmarks()
        for bm in bookmarks:
            offset_str = f"0x{bm[0]:08X}"
            length_str = str(bm[1])
            label = str(bm[2])
            item = QTreeWidgetItem([offset_str, length_str, label])
            self._bookmarks_tree.addTopLevelItem(item)
