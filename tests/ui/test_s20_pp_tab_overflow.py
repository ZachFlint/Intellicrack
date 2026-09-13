# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for S20-D16 (Process share): nested QTabWidget overflow degrade.

Verifies that :func:`intellicrack.ui.panels.process_panel.tab_overflow.install_tab_overflow`
makes a tab bar elide overflowing labels instead of clipping them mid-glyph and installs a
corner dropdown that lists every tab by name and jumps directly to it, and that the Process
panel's own top-level tab widget (the outermost of the three nested tab levels flagged in
S20-D16) has this installed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTabWidget, QWidget

from intellicrack.ui.panels.process_panel.base import ProcessPanel
from intellicrack.ui.panels.process_panel.tab_overflow import install_tab_overflow


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_install_tab_overflow_elides_and_keeps_scroll_buttons(qapp: QApplication) -> None:
    """The tab bar must elide overflowing labels and keep scroll-button paging.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "Alpha")
    tabs.addTab(QWidget(), "A Very Long Tab Label Indeed")
    install_tab_overflow(tabs)

    bar = tabs.tabBar()
    assert bar is not None
    assert bar.elideMode() == Qt.TextElideMode.ElideRight
    assert bar.usesScrollButtons() is True


def test_install_tab_overflow_adds_corner_navigation_button(qapp: QApplication) -> None:
    """A corner widget must be installed so hidden tabs stay directly reachable.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "One")
    tabs.addTab(QWidget(), "Two")
    button = install_tab_overflow(tabs)

    assert tabs.cornerWidget(Qt.Corner.TopRightCorner) is button
    assert button.menu() is not None


def test_overflow_menu_lists_every_tab_and_navigates_on_trigger(qapp: QApplication) -> None:
    """The corner menu must list every tab by name and jump to it when triggered.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "Processes")
    tabs.addTab(QWidget(), "Memory")
    tabs.addTab(QWidget(), "Threads")
    button = install_tab_overflow(tabs)
    menu = button.menu()
    assert menu is not None

    menu.aboutToShow.emit()
    labels = [action.text() for action in menu.actions()]
    assert labels == ["Processes", "Memory", "Threads"]

    assert tabs.currentIndex() == 0
    menu.actions()[2].trigger()
    assert tabs.currentIndex() == 2


def test_process_panel_top_level_tabs_have_overflow_installed(qapp: QApplication) -> None:
    """ProcessPanel's own top-level tab widget must have the overflow degrade installed.

    This is the outermost of the three nested tab levels named in S20-D16
    (Processes/Memory/Threads/Modules/System).

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    panel = ProcessPanel()
    tab_widget = getattr(panel, "_tab_widget")
    assert isinstance(tab_widget, QTabWidget)
    assert tab_widget.cornerWidget(Qt.Corner.TopRightCorner) is not None
    bar = tab_widget.tabBar()
    assert bar is not None
    assert bar.elideMode() == Qt.TextElideMode.ElideRight
