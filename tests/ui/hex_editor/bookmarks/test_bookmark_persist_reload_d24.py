# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-D24: bookmarks survive closing and reopening a file.

``HexEditorPanel._load_file_impl`` (``ui/panels/hex_editor/panel.py:826-827``)
calls ``BookmarksMixin._load_bookmarks_sidecar`` right after opening the
hexcore document, restoring any bookmarks a previous session persisted to
that file's ``.icbm.json`` JSON sidecar (written by
``_persist_bookmarks_sidecar`` / ``write_bookmark_sidecar`` in
``bridges/hex_editor.py``). Without that call (or without the write side),
every bookmark a user creates is lost the moment the file is closed and
reopened.

This test drives the real, unmodified persistence round trip against a
real ``intellicrack_hexcore`` document backed by a real PE binary copied
into a writable temp directory (System32 originals are read-only, and the
sidecar is written alongside the target file): add a bookmark, persist it,
close the panel, open a second, independent panel on the SAME path, and
assert the restored document reports the bookmark.

Reverting either half of the D24 fix turns this RED: with no
``_persist_bookmarks_sidecar`` call the ``.icbm.json`` sidecar is never
written, and with no ``_load_bookmarks_sidecar`` call in
``_load_file_impl`` the reopened document's ``get_bookmarks()`` comes back
empty even though the sidecar exists on disk.
"""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.bridges.hex_editor import bookmark_sidecar_path
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


_BOOKMARK_OFFSET: Final[int] = 0x120
_BOOKMARK_LENGTH: Final[int] = 2
_BOOKMARK_LABEL: Final[str] = "D24Survivor"
_BOOKMARK_COLOR: Final[str] = "#FFAA00"


def _copy_to_writable(source: Path, dest_dir: Path) -> Path:
    """Copy a real binary fixture into a writable temp directory.

    A bookmark sidecar is written next to the target file, and the
    original System32 fixtures are read-only, so every persistence test
    operates on a private writable copy rather than the shared fixture.

    Args:
        source: Real binary fixture to copy.
        dest_dir: Writable destination directory (a pytest ``tmp_path``).

    Returns:
        Path: Path to the writable copy.
    """
    dest = dest_dir / source.name
    shutil.copyfile(source, dest)
    return dest


class TestBookmarkPersistsAcrossFileReload:
    """A bookmark added and persisted must survive closing and reopening the same file."""

    @staticmethod
    def test_reopened_document_reports_the_persisted_bookmark(
        qapp: QApplication,
        real_pe_dll: Path,
        tmp_path: Path,
    ) -> None:
        """A bookmark added on one panel instance is visible after a fresh ``load_file`` on another.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (copied to a writable location).
            tmp_path: Pytest-provided writable temp directory.
        """
        del qapp
        target = _copy_to_writable(real_pe_dll, tmp_path)

        panel_a = HexEditorPanel()
        try:
            assert panel_a.load_file(target) is True
            assert panel_a.document is not None
            doc_len: int = panel_a.document.length()
            assert doc_len > _BOOKMARK_OFFSET + _BOOKMARK_LENGTH

            panel_a.document.add_bookmark(_BOOKMARK_OFFSET, _BOOKMARK_LENGTH, _BOOKMARK_LABEL, _BOOKMARK_COLOR)
            panel_a._persist_bookmarks_sidecar()

            sidecar = bookmark_sidecar_path(target)
            assert sidecar.is_file(), "adding and persisting a bookmark must write the .icbm.json sidecar"
        finally:
            panel_a._cleanup()

        panel_b = HexEditorPanel()
        try:
            assert panel_b.load_file(target) is True, "reload of the same target path must succeed"
            assert panel_b.document is not None

            bookmarks = panel_b.document.get_bookmarks()
            matches = [bm for bm in bookmarks if bm.offset == _BOOKMARK_OFFSET and bm.label == _BOOKMARK_LABEL]
            assert len(matches) >= 1, (
                f"reopening {target} must restore the persisted bookmark "
                f"(offset=0x{_BOOKMARK_OFFSET:X}, label={_BOOKMARK_LABEL!r}); got "
                f"{[(bm.offset, bm.label) for bm in bookmarks]}"
            )
        finally:
            panel_b._cleanup()

    @staticmethod
    def test_bookmarks_tree_is_populated_from_the_sidecar_on_reload(
        qapp: QApplication,
        real_pe_dll: Path,
        tmp_path: Path,
    ) -> None:
        """The Bookmarks side-tab tree must reflect the sidecar-restored bookmark, not just the document.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real ``kernel32.dll`` fixture (copied to a writable location).
            tmp_path: Pytest-provided writable temp directory.
        """
        target = _copy_to_writable(real_pe_dll, tmp_path)

        panel_a = HexEditorPanel()
        try:
            assert panel_a.load_file(target) is True
            assert panel_a.document is not None
            panel_a.document.add_bookmark(_BOOKMARK_OFFSET, _BOOKMARK_LENGTH, _BOOKMARK_LABEL, _BOOKMARK_COLOR)
            panel_a._persist_bookmarks_sidecar()
        finally:
            panel_a._cleanup()

        panel_b = HexEditorPanel()
        try:
            assert panel_b.load_file(target) is True
            qapp.processEvents()
            assert panel_b._bookmarks_tree is not None

            rows = [panel_b._bookmarks_tree.topLevelItem(i) for i in range(panel_b._bookmarks_tree.topLevelItemCount())]
            offsets = [item.text(0) for item in rows if item is not None]
            assert f"0x{_BOOKMARK_OFFSET:08X}" in offsets, (
                f"Bookmarks tree after reload must contain 0x{_BOOKMARK_OFFSET:08X}; got {offsets}"
            )
        finally:
            panel_b._cleanup()
