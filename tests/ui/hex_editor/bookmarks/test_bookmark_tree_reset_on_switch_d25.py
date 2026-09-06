# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-D25: opening a new file clears stale bookmark rows.

``HexEditorPanel._load_file_impl`` (``ui/panels/hex_editor/panel.py:826-827``)
calls ``_load_bookmarks_sidecar`` followed by ``_refresh_bookmarks_tree`` on
every ``load_file``, including switching from one already-open file to a
different one. ``_refresh_bookmarks_tree`` clears the tree
(``self._bookmarks_tree.clear()``) before repopulating it from the
newly-opened document's own bookmarks. Without that call firing on every
open (not just the first), the Bookmarks side-tab would keep showing the
previously opened file's rows after switching documents -- a stale,
misleading view of a different binary's annotations.

This test drives the real ``load_file`` path twice in a row against two
distinct real PE binaries (``kernel32.dll`` then a real system executable),
adding a bookmark to the first file only, and asserts the tree reflects
the second (bookmark-free) file's document rather than carrying over the
first file's row.

Reverting the ``_refresh_bookmarks_tree`` (or the underlying
``_bookmarks_tree.clear()``) call on the second ``load_file`` turns this
RED: the tree keeps showing file A's bookmark row after file B has been
opened.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


class TestBookmarksTreeResetsOnFileSwitch:
    """Opening file B after file A must reset the Bookmarks tree to file B's own state."""

    @staticmethod
    def test_tree_is_cleared_when_switching_to_a_bookmark_free_file(
        qapp: QApplication,
        real_pe_dll: Path,
        real_pe_exe: Path,
    ) -> None:
        """Loading file B must clear file A's bookmark rows, not merge or keep them.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (file A).
            real_pe_exe: Path to a real system PE executable fixture (file B).
        """
        panel = HexEditorPanel()
        try:
            assert panel.load_file(real_pe_dll) is True
            assert panel.document is not None
            assert panel._bookmarks_tree is not None

            panel.document.add_bookmark(0x10, 1, "OnlyInFileA", "#0000FF")
            panel._refresh_bookmarks_tree()
            qapp.processEvents()
            assert panel._bookmarks_tree.topLevelItemCount() == 1, "setup precondition: file A must show its own bookmark"

            assert panel.load_file(real_pe_exe) is True, "switching to a distinct real PE file must succeed"
            qapp.processEvents()

            assert panel._bookmarks_tree.topLevelItemCount() == 0, (
                f"opening {real_pe_exe.name} after adding a bookmark to {real_pe_dll.name} must reset the "
                f"Bookmarks tree, but it still shows {panel._bookmarks_tree.topLevelItemCount()} stale row(s)"
            )
        finally:
            panel._cleanup()

    @staticmethod
    def test_switching_back_and_forth_never_leaks_the_other_files_rows(
        qapp: QApplication,
        real_pe_dll: Path,
        real_pe_exe: Path,
    ) -> None:
        """Bookmarks added to each file must stay scoped to that file's own tree view.

        Drives the reset in both directions (A -> B and B -> A) on two
        independent panel instances -- rather than three consecutive
        ``load_file`` calls on one panel -- so the assertion is not
        entangled with the lifetime of the first ``load_file``'s
        background string-extraction worker.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (file A).
            real_pe_exe: Path to a real system PE executable fixture (file B).
        """
        panel_ab = HexEditorPanel()
        try:
            assert panel_ab.load_file(real_pe_dll) is True
            assert panel_ab.document is not None
            assert panel_ab._bookmarks_tree is not None
            panel_ab.document.add_bookmark(0x20, 1, "InFileA", "#FF00FF")
            panel_ab._refresh_bookmarks_tree()
            qapp.processEvents()
            assert panel_ab._bookmarks_tree.topLevelItemCount() == 1

            assert panel_ab.load_file(real_pe_exe) is True
            qapp.processEvents()
            assert panel_ab._bookmarks_tree.topLevelItemCount() == 0, "switching A -> B must clear file A's bookmark row from the tree"
        finally:
            panel_ab._cleanup()

        panel_ba = HexEditorPanel()
        try:
            assert panel_ba.load_file(real_pe_exe) is True
            assert panel_ba.document is not None
            assert panel_ba._bookmarks_tree is not None
            panel_ba.document.add_bookmark(0x30, 1, "InFileB", "#00FFFF")
            panel_ba._refresh_bookmarks_tree()
            qapp.processEvents()
            assert panel_ba._bookmarks_tree.topLevelItemCount() == 1
            item = panel_ba._bookmarks_tree.topLevelItem(0)
            assert item is not None
            assert item.text(2) == "InFileB", f"file B's tree must show its own bookmark, got {item.text(2)!r}"

            assert panel_ba.load_file(real_pe_dll) is True
            qapp.processEvents()
            assert panel_ba._bookmarks_tree.topLevelItemCount() == 0, (
                "switching B -> A must clear file B's bookmark row from the tree, "
                f"got {panel_ba._bookmarks_tree.topLevelItemCount()} row(s)"
            )
        finally:
            panel_ba._cleanup()
