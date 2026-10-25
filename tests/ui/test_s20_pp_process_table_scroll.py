# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for process table column sizing.

Verifies that ``ProcessTab``'s system-process table does not force-stretch a column to fill
the available width, which would squeeze wide content down to an illegible sliver. Every
column keeps its natural content width, and the table's own horizontal scrollbar takes over
when the columns do not fit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QHeaderView, QMainWindow

from intellicrack.ui.panels.process_panel.process_tab import ProcessTab


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_COL_NAME = 1
_WIDE_NAME = "N" * 200


def test_process_table_header_disables_stretch_last_section(qapp: QApplication) -> None:
    """The system-process table's header must not force-stretch its last column.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    tab = ProcessTab()
    header = getattr(tab, "_process_table").horizontalHeader()
    assert header is not None
    assert header.stretchLastSection() is False
    assert header.sectionResizeMode(_COL_NAME) == QHeaderView.ResizeMode.ResizeToContents


def test_process_table_scrolls_horizontally_instead_of_squeezing_columns(
    qapp: QApplication,
) -> None:
    """A table whose natural column widths exceed the viewport must scroll, not squash.

    Populates the table with a long process name, hosts it in a narrow window,
    and asserts the table's horizontal scrollbar has real range -- proving Qt
    kept the column at its natural width rather than collapsing it to fit.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    tab = ProcessTab()
    getattr(tab, "_populate_process_table")(
        [
            {
                "pid": 1234,
                "name": _WIDE_NAME,
                "parent_pid": 4,
                "architecture": "x64",
                "memory_mb": 12.5,
                "thread_count": 3,
            },
        ],
    )

    window = QMainWindow()
    window.setCentralWidget(tab)
    window.resize(250, 300)
    window.show()
    qapp.processEvents()

    table = getattr(tab, "_process_table")
    hbar = table.horizontalScrollBar()
    assert hbar is not None
    assert hbar.maximum() > 0, "table should require horizontal scrolling for its natural column widths"

    window.close()
    qapp.processEvents()
