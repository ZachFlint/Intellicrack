# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for S20-D16 (Analysis Output share): results-table column truncation.

At the fresh-launch tool-pane width the strings table's "Value" column was
observed cut to "Va..." even though ``_create_table`` sets
``QHeaderView.ResizeMode.ResizeToContents`` on every column. The root cause
was the *additional* ``Stretch`` override applied to selected "variable
length" columns: a ``Stretch`` section is defined to always fill exactly the
remaining viewport width, so it can never overflow and can never trigger the
table's own horizontal scrollbar -- when its ResizeToContents siblings
already consumed most of a narrow tool pane, the Stretch column was forced
down to Qt's bare default minimum section size.

The fix removes the ``Stretch`` override entirely (every column stays
``ResizeToContents``), adds a font-derived ``setMinimumSectionSize`` floor so
a short or still-empty column can never shrink below legible text, and lets
the table's own horizontal scrollbar (already ``ScrollBarAsNeeded`` by
default on a ``QAbstractScrollArea``) reach columns whose real content
outgrows the viewport instead of truncating them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.core.types import BridgeAnalysisSummary, StringInfo
from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_empty_table_columns_still_respect_a_readable_floor(qapp: QApplication) -> None:
    """A short header on an unpopulated table must not shrink below the font-derived floor.

    ``QHeaderView.setMinimumSectionSize`` clamps every section -- including
    ``ResizeToContents`` ones -- to at least the given width, regardless of
    how little content (here, no rows at all) a column has to size itself
    from. The Sections table's two-character "VA" header is the shortest in
    the panel, making it the tightest real-world case.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    panel = BridgeAnalysisPanel()
    try:
        panel.resize(900, 400)
        panel.show()
        qapp.processEvents()

        table = panel._sections_table
        va_column_width = table.columnWidth(1)
        assert va_column_width >= panel._min_column_width, (
            f"sections table 'VA' column width {va_column_width}px is narrower than the "
            f"font-derived readable floor ({panel._min_column_width}px) -- a short header "
            "with no rows populated yet must not be squeezed illegibly narrow"
        )
    finally:
        panel.hide()
        panel.deleteLater()
        qapp.processEvents()


def test_long_value_content_scrolls_horizontally_instead_of_truncating(qapp: QApplication) -> None:
    """A long 'Value' cell must keep its natural width and scroll, not get crushed to the viewport.

    Reproduces the S20-D16 repro directly: a narrow panel (well under the
    ~530px fresh-launch tool pane) with one string row whose value is long
    enough that the "Value" column cannot fit inside the viewport alongside
    its siblings. Post-fix the column keeps its real content width and the
    table's horizontal scrollbar becomes usable; pre-fix (``Stretch`` on the
    "Value" column) the column would instead be force-fit to the leftover
    viewport width and the scrollbar would never engage.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    panel = BridgeAnalysisPanel()
    try:
        panel.resize(320, 400)
        panel.show()
        qapp.processEvents()

        long_value = "A" * 120
        summary = BridgeAnalysisSummary(
            binary_name="notepad.exe",
            strings=[StringInfo(address=0x00401000, value=long_value, encoding="ascii", section=".rdata")],
            imports=[],
            exports=[],
            sections=[],
            functions=[],
            format_info="PE",
            architecture="x86_64",
            source_bridges=["pe"],
            analysis_notes=[],
            complete=True,
        )
        panel.set_analysis(summary)
        qapp.processEvents()

        table = panel._strings_table
        value_column_width = table.columnWidth(1)
        assert value_column_width > panel.width(), (
            f"strings table 'Value' column width {value_column_width}px did not grow past the "
            f"120-char panel-width ({panel.width()}px) -- the column was force-fit to the "
            "viewport instead of keeping its real content width"
        )

        hbar = table.horizontalScrollBar()
        assert hbar is not None
        assert hbar.maximum() > 0, (
            "strings table horizontalScrollBar().maximum() is 0 -- the long 'Value' content was "
            "squeezed to fit the viewport (Stretch-mode behavior) instead of keeping its natural "
            "width and letting the table scroll to reach it"
        )
    finally:
        panel.hide()
        panel.deleteLater()
        qapp.processEvents()
