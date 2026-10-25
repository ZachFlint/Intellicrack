# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the x64dbg panel's stop reset and scrollable layout.

Stopping a debug session must clear the disassembly view and registers table, so the panel never
shows the previous debuggee's stale data or implies a process is still attached.

The panel's native content (Disassembly/Registers row plus the bottom-tab tables) is taller than most
docked areas. It must be hosted in a QScrollArea that can scroll vertically, so the bottom rows are
never silently clipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QScrollArea, QTableWidgetItem

from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


@pytest.mark.usefixtures("qapp")
def test_stop_success_clears_disassembly_and_registers(qapp: QApplication) -> None:
    """After a stop succeeds, the disassembly view and registers table must be empty."""
    panel = X64DbgPanel()
    try:
        panel._disasm_view.setPlainText("0x0000000140001000  48 89 5C 24 08          mov [rsp+8], rbx")
        panel._reg_table.setRowCount(0)
        row = panel._reg_table.rowCount()
        panel._reg_table.insertRow(row)
        panel._reg_table.setItem(row, 0, QTableWidgetItem("rax"))
        panel._reg_table.setItem(row, 1, QTableWidgetItem("0x0000000000001234"))
        qapp.processEvents()

        assert panel._disasm_view.toPlainText()
        assert panel._reg_table.rowCount() > 0

        panel._on_stop_success()
        qapp.processEvents()

        assert not panel._disasm_view.toPlainText(), "disassembly view must be cleared once debugging stops"
        assert panel._reg_table.rowCount() == 0, "registers table must be cleared once debugging stops"
    finally:
        panel.close()
        qapp.processEvents()


@pytest.mark.usefixtures("qapp")
def test_content_is_hosted_in_a_scrollable_area(qapp: QApplication) -> None:
    """The panel's native content must be wrapped in a QScrollArea that can scroll vertically."""
    panel = X64DbgPanel()
    try:
        scroll = panel._content_scroll_area
        assert isinstance(scroll, QScrollArea), "panel content must be hosted in a QScrollArea"
        assert scroll.verticalScrollBarPolicy() != Qt.ScrollBarPolicy.ScrollBarAlwaysOff, "vertical scrolling must not be disabled"
        assert scroll.widgetResizable() is True
        assert scroll.widget() is not None
    finally:
        panel.close()
        qapp.processEvents()
