# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for S20-D17 (Process share): panel action rows use OverflowToolBar.

Verifies that ``ProcessTab``'s System Processes sub-tab builds its action row
on :class:`intellicrack.ui.overflow_toolbar.OverflowToolBar` rather than a
plain ``QToolBar``, and that a button clipped by a narrow width stays
reachable through the toolbar's populated overflow menu instead of being
permanently unreachable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QMainWindow

from intellicrack.ui.overflow_toolbar import OverflowToolBar
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_system_processes_toolbar_is_overflow_capable(qapp: QApplication) -> None:
    """The System Processes sub-tab's action row must be an OverflowToolBar.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    tab = ProcessTab()
    system_page = getattr(tab, "_tabs").widget(0)
    toolbar = system_page.findChild(OverflowToolBar)
    assert toolbar is not None, "System Processes toolbar must be an OverflowToolBar instance"


def test_system_processes_toolbar_surfaces_clipped_button_via_overflow_menu(
    qapp: QApplication,
) -> None:
    """A button pushed off-screen at a narrow width must stay reachable via the overflow menu.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    tab = ProcessTab()
    window = QMainWindow()
    window.setCentralWidget(tab)
    window.resize(200, 400)
    window.show()
    qapp.processEvents()

    system_page = getattr(tab, "_tabs").widget(0)
    toolbar = system_page.findChild(OverflowToolBar)
    assert toolbar is not None
    toolbar.populate_overflow_menu()
    qapp.processEvents()

    texts = {action.text() for action in toolbar.overflow_menu.actions()}
    assert "Terminate" in texts or "DLL Inject" in texts, f"expected a clipped action button in overflow menu, got {texts}"

    window.close()
    qapp.processEvents()
