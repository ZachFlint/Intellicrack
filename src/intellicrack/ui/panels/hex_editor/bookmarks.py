# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bookmarks mixin for the hex editor panel."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QColorDialog, QInputDialog, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.bridges.hex_editor import read_bookmark_sidecar, write_bookmark_sidecar
from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from intellicrack.bridges.hex_state import HexDocumentState
    from intellicrack.core.types import BookmarkLike


class BookmarksMixin:
    """Mixin providing bookmark management for the hex editor panel."""

    _document: Any | None
    document: Any | None
    _hex_widget: Any | None
    _bookmarks_tree: QTreeWidget | None
    state_holder: HexDocumentState | None
    file_path: Path | None
    goto_offset: Callable[[int, int], None]

    def _notify_state_data_modified(self, offset: int, length: int, *, source: str) -> None:
        """Publish bookmark-affected byte extents through ``HexDocumentState``.

        Bridge subscribers (AI tools, peer GUIs) only see document mutations via
        ``notify_data_modified``. Panel bookmark edits must emit the same event
        so consumers do not keep stale annotated state after a GUI change.

        Args:
            offset: Start byte offset of the affected range.
            length: Number of bytes that were affected.
            source: Loop-guard id unique per bookmark op so other subscribers
                still receive the event while this caller is filtered.
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

        _logger.info(
            "bookmark_add_started",
            offset=cursor_offset,
            bookmark_name=name,
            color=color.name(),
        )

        try:
            self.document.add_bookmark(cursor_offset, 1, name, color.name())
        except (RuntimeError, OSError, ValueError, IndexError, TypeError):
            _logger.exception("bookmark_add_failed", offset=cursor_offset, bookmark_name=name)
            return
        _logger.info("bookmark_added", offset=cursor_offset, bookmark_name=name, color=color.name())

        self._notify_state_data_modified(cursor_offset, 1, source="hex-editor.bookmarks.add")
        self._persist_bookmarks_sidecar()
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
            _logger.info("bookmark_remove_started", index=index)
            try:
                bookmarks: list[BookmarkLike] = self.document.get_bookmarks()
            except (RuntimeError, OSError):
                _logger.exception("bookmark_list_failed", context="remove_bookmark_lookup")
                return

            if index < len(bookmarks):
                bm_offset: int = int(bookmarks[index].offset)
                bm_length: int = int(bookmarks[index].length)
            else:
                bm_offset = 0
                bm_length = 1

            try:
                self.document.remove_bookmark(index)
            except (RuntimeError, OSError, IndexError, ValueError):
                _logger.exception("bookmark_remove_failed", index=index)
                return
            _logger.info("bookmark_removed", index=index, offset=bm_offset, length=bm_length)

            self._notify_state_data_modified(bm_offset, bm_length, source="hex-editor.bookmarks.remove")
            self._persist_bookmarks_sidecar()
            self._refresh_bookmarks()

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks tree from the document."""
        if self._bookmarks_tree is None or self.document is None:
            return

        self._bookmarks_tree.clear()
        try:
            bookmarks: list[BookmarkLike] = self.document.get_bookmarks()
        except (RuntimeError, OSError):
            _logger.exception("bookmark_list_failed", context="refresh_bookmarks")
            return

        for bm in bookmarks:
            offset_str = f"0x{bm.offset:08X}"
            length_str = str(bm.length)
            label = str(bm.label)
            item = QTreeWidgetItem([offset_str, length_str, label])
            self._bookmarks_tree.addTopLevelItem(item)
        _logger.debug("bookmarks_refreshed", count=len(bookmarks))

    def _on_bookmark_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the bookmark's offset when its row is double-clicked.

        Mirrors :meth:`intellicrack.ui.panels.hex_editor.sections.SectionsMixin._on_string_double_clicked`:
        reads the offset (and, when present, the byte-length) encoded in the
        row and moves the hex cursor/selection there.

        Args:
            item: The double-clicked tree item.
            column: The clicked column index (unused; the offset and length
                columns are read directly regardless of which column was
                clicked).
        """
        _ = column
        offset_text = item.text(0)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            _logger.warning("hex_editor_bookmark_invalid_offset", input_text=offset_text)
            return

        length_text = item.text(1)
        try:
            length = int(length_text)
        except ValueError:
            length = 0

        goto_fn = getattr(self, "goto_offset", None)
        if callable(goto_fn):
            goto_fn(offset, length)

    def _persist_bookmarks_sidecar(self) -> None:
        """Write the current document's bookmarks to its JSON sidecar file.

        No-op when there is no open document or its source file path is unknown (e.g. a document that was never saved to disk).
        """
        if self.document is None or self.file_path is None:
            return
        try:
            bookmarks: list[BookmarkLike] = self.document.get_bookmarks()
        except (RuntimeError, OSError):
            _logger.exception("bookmark_list_failed", context="persist_bookmarks_sidecar")
            return
        entries = [{"offset": bm.offset, "length": bm.length, "label": bm.label, "color": bm.color} for bm in bookmarks]
        write_bookmark_sidecar(self.file_path, entries)

    def _load_bookmarks_sidecar(self) -> None:
        """Restore bookmarks for the just-opened document from its JSON sidecar file.

        Called once per :meth:`load_file` after the hexcore document is opened and :attr:`file_path` is set, so bookmarks created in a
        previous session on the same file survive a reload. No-op when there is no open document, no known file path, or no sidecar file
        exists yet for it.
        """
        if self.document is None or self.file_path is None:
            return
        entries = read_bookmark_sidecar(self.file_path)
        for entry in entries:
            try:
                self.document.add_bookmark(entry["offset"], entry["length"], entry["label"], entry["color"])
            except (RuntimeError, OSError, ValueError, IndexError, TypeError):
                _logger.exception("bookmark_sidecar_restore_entry_failed", entry=entry)
        if entries:
            _logger.debug("bookmarks_restored_from_sidecar", count=len(entries), path=str(self.file_path))
