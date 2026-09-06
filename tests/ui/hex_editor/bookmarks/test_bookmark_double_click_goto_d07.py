# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-D07: double-clicking a bookmark row navigates to it.

``HexEditorPanel._build_bookmarks_tab`` (``ui/panels/hex_editor/panel.py``)
wires ``self._bookmarks_tree.itemDoubleClicked`` to
``BookmarksMixin._on_bookmark_double_clicked``, which parses the row's hex
offset column and forwards it to ``self.goto_offset`` -> the real hex
widget's ``goto_offset``, moving its cursor. The re-live audit could not
drive this live end to end (the side pane was clipped off-screen at the
audited window width -- a separate finding), but flagged the wiring as
"code-verified, live-drive blocked."

This test drives the real, unmodified signal connection against a real
``intellicrack_hexcore`` document loaded from a real PE binary: it adds a
bookmark directly on the document (the same mutation ``_on_add_bookmark``
performs), refreshes the real bookmarks tree, then emits the tree's own
``itemDoubleClicked`` signal on that row -- not a direct method call -- so a
regression that disconnects or removes the wiring itself (not just the
handler body) is caught.

Reverting the ``itemDoubleClicked.connect(self._on_bookmark_double_clicked)``
line in ``_build_bookmarks_tab`` turns this RED: emitting the signal no
longer reaches the handler, so the hex widget's cursor stays wherever it
was left instead of moving to the bookmark's offset.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


_BOOKMARK_OFFSET: Final[int] = 0x40
_BOOKMARK_LENGTH: Final[int] = 4
_BOOKMARK_LABEL: Final[str] = "D07Target"
_BOOKMARK_COLOR: Final[str] = "#00AAFF"
_START_OFFSET: Final[int] = 0


class TestBookmarkDoubleClickNavigatesRealCursor:
    """Double-clicking a bookmark row must move the real hex widget cursor to its offset."""

    @staticmethod
    def test_double_click_signal_moves_cursor_to_bookmark_offset(qapp: QApplication, real_pe_dll: Path) -> None:
        """Emitting the tree's real ``itemDoubleClicked`` signal navigates the hex cursor.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (session-scoped, read-only).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True, "load_file must succeed against a real PE"
            assert panel.document is not None
            assert panel._bookmarks_tree is not None
            assert panel._hex_widget is not None

            doc_len: int = panel.document.length()
            assert doc_len > _BOOKMARK_OFFSET + _BOOKMARK_LENGTH, "fixture must be large enough for the bookmark offset"

            panel.document.add_bookmark(_BOOKMARK_OFFSET, _BOOKMARK_LENGTH, _BOOKMARK_LABEL, _BOOKMARK_COLOR)
            panel._refresh_bookmarks_tree()
            qapp.processEvents()

            item = panel._bookmarks_tree.topLevelItem(0)
            assert item is not None, "the added bookmark must appear as a tree row"
            assert item.text(0) == f"0x{_BOOKMARK_OFFSET:08X}", f"row offset column mismatch: {item.text(0)!r}"

            panel._hex_widget.goto_offset(_START_OFFSET)
            qapp.processEvents()
            assert panel._hex_widget._cursor_offset == _START_OFFSET, "setup precondition: cursor must start at 0"

            panel._bookmarks_tree.itemDoubleClicked.emit(item, 0)
            qapp.processEvents()

            assert panel._hex_widget._cursor_offset == _BOOKMARK_OFFSET, (
                f"double-clicking the bookmark row must move the cursor to 0x{_BOOKMARK_OFFSET:X}, "
                f"got 0x{panel._hex_widget._cursor_offset:X} -- the itemDoubleClicked wiring is broken"
            )
        finally:
            panel._cleanup()

    @staticmethod
    def test_double_click_on_multiple_rows_navigates_each_independently(qapp: QApplication, real_pe_dll: Path) -> None:
        """Double-clicking distinct bookmark rows must each navigate to their own offset.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (session-scoped, read-only).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True
            assert panel.document is not None
            assert panel._bookmarks_tree is not None
            assert panel._hex_widget is not None

            second_offset = _BOOKMARK_OFFSET + 0x200
            doc_len: int = panel.document.length()
            assert doc_len > second_offset, "fixture must be large enough for both bookmark offsets"

            panel.document.add_bookmark(_BOOKMARK_OFFSET, _BOOKMARK_LENGTH, "First", "#FF0000")
            panel.document.add_bookmark(second_offset, _BOOKMARK_LENGTH, "Second", "#00FF00")
            panel._refresh_bookmarks_tree()
            qapp.processEvents()

            assert panel._bookmarks_tree.topLevelItemCount() == 2

            first_item = panel._bookmarks_tree.topLevelItem(0)
            second_item = panel._bookmarks_tree.topLevelItem(1)
            assert first_item is not None
            assert second_item is not None

            panel._bookmarks_tree.itemDoubleClicked.emit(second_item, 0)
            qapp.processEvents()
            assert panel._hex_widget._cursor_offset == second_offset

            panel._bookmarks_tree.itemDoubleClicked.emit(first_item, 0)
            qapp.processEvents()
            assert panel._hex_widget._cursor_offset == _BOOKMARK_OFFSET
        finally:
            panel._cleanup()
