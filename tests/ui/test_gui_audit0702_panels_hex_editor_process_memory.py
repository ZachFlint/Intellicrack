# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding in ``process_memory``.

``TestRegionsTableColumnSizing`` (M53): the process-memory regions table must
size its ``Base Address`` / ``Size`` / ``Protection`` / ``State`` columns to
their content instead of keeping Qt's default ~100px interactive width, so
long addresses and sizes are not clipped.
"""

from __future__ import annotations

from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QHeaderView

from intellicrack.ui.panels.hex_editor.process_memory import ProcessMemoryDialog


_COL_BASE = 0
_COL_SIZE = 1
_COL_PROT = 2
_COL_STATE = 3


def _make_dialog(qapp: QApplication) -> ProcessMemoryDialog:
    """Build a real, unshown ``ProcessMemoryDialog`` with no bridge attached.

    Args:
        qapp: The shared QApplication fixture.

    Returns:
        ProcessMemoryDialog: A dialog instance ready for widget inspection.
    """
    _ = qapp
    return ProcessMemoryDialog(parent=None, bridge=None)


class TestRegionsTableColumnSizing:
    """M53: regions table columns resize to content and are not clipped."""

    def test_m53_header_resize_mode_is_resize_to_contents(self, qapp: QApplication) -> None:
        """Every column's resize mode must be ``ResizeToContents``.

        Pre-fix the header was left at Qt's default ``Interactive`` mode for
        every section, since no ``setSectionResizeMode`` call existed
        anywhere in the file.

        Args:
            qapp: The shared QApplication fixture.
        """
        dlg = _make_dialog(qapp)
        try:
            header = dlg._regions_table.horizontalHeader()
            assert header is not None
            for column in (_COL_BASE, _COL_SIZE, _COL_PROT, _COL_STATE):
                assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                    f"column {column} is not in ResizeToContents mode"
                )
        finally:
            dlg.deleteLater()

    def test_m53_stretch_last_section_enabled(self, qapp: QApplication) -> None:
        """The last (State) column must stretch to fill remaining width.

        Pre-fix ``setStretchLastSection`` was never called, so the header
        default of ``False`` left trailing dialog width unused by any column.

        Args:
            qapp: The shared QApplication fixture.
        """
        dlg = _make_dialog(qapp)
        try:
            header = dlg._regions_table.horizontalHeader()
            assert header is not None
            assert header.stretchLastSection() is True
        finally:
            dlg.deleteLater()

    def test_m53_base_address_column_not_clipped_after_populate(self, qapp: QApplication) -> None:
        """A full-width 16-digit base address must fit inside its column.

        Pre-fix the Base Address column kept the header's default ~100px
        interactive width; ``0x{base:016X}`` (18 characters) is wider than
        that default at any normal dialog font, so the rendered column would
        be narrower than the text it must display.

        Args:
            qapp: The shared QApplication fixture.
        """
        dlg = _make_dialog(qapp)
        try:
            base = 0x00007FF6A1230000
            size = 0x140000
            dlg._populate_regions([(base, size, 0x20, 0x1000)])
            QApplication.processEvents()

            table = dlg._regions_table
            fm = QFontMetrics(table.font())
            text = f"0x{base:016X}"
            text_width = fm.horizontalAdvance(text)
            column_width = table.columnWidth(_COL_BASE)

            assert column_width >= text_width, (
                f"Base Address column ({column_width}px) is narrower than its text ({text_width}px) and clips '{text}'"
            )
        finally:
            dlg.deleteLater()

    def test_m53_size_column_not_clipped_after_populate_with_large_value(self, qapp: QApplication) -> None:
        """A large ``0xHEX (decimal)`` size string must fit inside its column.

        Pre-fix the Size column kept the header's default ~100px interactive
        width. ``f"0x{size:X} ({size})"`` for a large process-memory region
        (e.g. ``0x7FFFFFFFFFFF (140737488355327)``, 33 characters) is far
        wider than that default, so the text would be clipped/elided.

        Args:
            qapp: The shared QApplication fixture.
        """
        dlg = _make_dialog(qapp)
        try:
            base = 0x7FF600000000
            size = 140737488355327
            dlg._populate_regions([(base, size, 0x40, 0x1000)])
            QApplication.processEvents()

            table = dlg._regions_table
            fm = QFontMetrics(table.font())
            text = f"0x{size:X} ({size})"
            text_width = fm.horizontalAdvance(text)
            column_width = table.columnWidth(_COL_SIZE)

            assert column_width >= text_width, (
                f"Size column ({column_width}px) is narrower than its text ({text_width}px) and clips '{text}'"
            )
        finally:
            dlg.deleteLater()
