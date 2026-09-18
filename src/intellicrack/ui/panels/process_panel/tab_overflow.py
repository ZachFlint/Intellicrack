# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Overflow-aware degrade helper for nested :class:`QTabWidget` tab bars.

The Process panel nests three tab levels (top-level Processes/Memory/Threads/Modules/System, the Processes tab's System
Processes/Tracked/Process Info sub-tabs, and the System tab's Registry Value Keys/Data sub-tabs). A plain :class:`QTabWidget` tab bar that
cannot fit every label falls back to Qt's built-in scroll arrows, which page one sliver of a tab at a time and give no indication of what
the remaining tabs are named (S20-D16). :func:`install_tab_overflow` keeps those scroll arrows for keyboard/mouse paging but adds a corner
dropdown that lists every tab by name and jumps straight to it, and switches the bar to elide long labels instead of letting Qt clip them
mid-glyph.
"""

from __future__ import annotations

from functools import partial
from typing import Final

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMenu, QTabWidget, QToolButton


_OVERFLOW_BUTTON_TEXT: Final[str] = "⋮"


def _jump_to_tab(tabs: QTabWidget, target: int, *_signal_args: object) -> None:
    """Switch ``tabs`` to ``target``, absorbing any arguments a signal appends.

    Bound as ``functools.partial(_jump_to_tab, tabs, target)`` and connected
    directly to ``QAction.triggered``, which always emits its ``checked: bool``
    argument positionally. Because ``partial`` fixes ``tabs`` and ``target`` as
    the first two positional arguments before the signal supplies any of its
    own, the emitted ``checked`` value can only ever land in ``*_signal_args``
    -- it has no positional slot left to silently override ``target`` with.

    Args:
        tabs: The tab widget to switch.
        target: Tab index to switch to, bound at menu-build time for this
            entry.
        *_signal_args: Positional arguments emitted by the connected signal.
            Unused; present only so the signal's own arguments are absorbed
            here rather than shifting into ``target``.
    """
    tabs.setCurrentIndex(target)


def install_tab_overflow(tabs: QTabWidget) -> QToolButton:
    """Make a tab widget's bar elide overflowing labels and gain a jump-to-tab menu.

    Args:
        tabs: The tab widget whose bar should degrade usably when it cannot
            display every tab at the panel's current width.

    Returns:
        QToolButton: The corner button installed for direct tab navigation,
        so callers (and tests) can inspect or trigger its menu.
    """
    bar = tabs.tabBar()
    if bar is not None:
        bar.setElideMode(Qt.TextElideMode.ElideRight)
        bar.setUsesScrollButtons(True)
        bar.setExpanding(False)

    button = QToolButton(tabs)
    button.setObjectName("tab_overflow_button")
    button.setText(_OVERFLOW_BUTTON_TEXT)
    button.setToolTip("Show all tabs")
    button.setAutoRaise(True)
    button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

    menu = QMenu(button)
    button.setMenu(menu)

    def _populate_menu() -> None:
        """Rebuild the jump-to-tab menu from the tab widget's current tabs."""
        menu.clear()
        for index in range(tabs.count()):
            action = QAction(tabs.tabText(index), menu)
            action.setCheckable(True)
            action.setChecked(index == tabs.currentIndex())
            action.setEnabled(tabs.isTabEnabled(index))
            action.triggered.connect(partial(_jump_to_tab, tabs, index))
            menu.addAction(action)

    menu.aboutToShow.connect(_populate_menu)
    tabs.setCornerWidget(button, Qt.Corner.TopRightCorner)
    return button
