# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the Ghidra share of S20-D14/S20-D16/S20-D17 -- clipped tab bars.

``GhidraPanel._create_code_tabs`` and ``GhidraPanel._create_data_tabs``
(src/intellicrack/ui/panels/ghidra_panel.py) build the Decompiled/
Disassembly/PCode/CFG code-tab strip and the 18-tab bottom detail strip. At
narrow widths Qt's own ``QTabBar`` overflow degrades to pixel-wide scroll
arrows with no indication of what the remaining tabs are named, which the
audit records as unusable (S20-D14/S20-D16/S20-D17).

The fix reuses the Process panel's already-established
``install_tab_overflow`` helper
(``intellicrack.ui.panels.process_panel.tab_overflow``) on both tab widgets:
it adds a corner ``QToolButton`` whose menu lists every tab by name and jumps
straight to it on one click, regardless of how the tab bar itself renders.

Every assertion drives the real corner button and menu installed on a live,
fully constructed ``GhidraPanel`` under an offscreen ``QApplication`` -- no
mocked widgets, no reimplementation of the menu-population logic under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMenu, QTabWidget, QToolButton

from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def panel(qapp: object) -> Iterator[GhidraPanel]:
    """Provide a fully constructed ``GhidraPanel`` and tear it down afterward.

    Args:
        qapp: The session ``QApplication`` fixture (from ``tests/ui/conftest.py``),
            required before any ``QWidget`` can be constructed.

    Yields:
        GhidraPanel: A live panel instance with every tab built.
    """
    del qapp
    instance = GhidraPanel()
    try:
        yield instance
    finally:
        instance.deleteLater()


def _corner_menu(tabs: QTabWidget) -> QMenu:
    """Return the populated corner overflow menu installed on ``tabs``.

    Args:
        tabs: The tab widget whose corner overflow menu should be inspected.

    Returns:
        QMenu: The corner button's menu, populated by triggering its
        ``aboutToShow`` signal exactly as Qt does before actually opening it.
    """
    corner = tabs.cornerWidget(Qt.Corner.TopRightCorner)
    assert isinstance(corner, QToolButton), (
        f"{tabs.objectName() or tabs} has no corner overflow QToolButton -- clipped tabs beyond the visible tab bar are unreachable"
    )
    menu = corner.menu()
    assert isinstance(menu, QMenu)
    menu.aboutToShow.emit()
    return menu


class TestGhidraTabBarsHaveAnOverflowMenu:
    """Both Ghidra tab strips must expose every tab through a corner overflow menu."""

    @staticmethod
    def test_code_tabs_overflow_menu_lists_every_tab(panel: GhidraPanel) -> None:
        """The code-tab strip's corner menu must list exactly one entry per tab.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._code_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        assert len(menu.actions()) == tabs.count(), (
            f"code-tabs overflow menu has {len(menu.actions())} entries, expected {tabs.count()} (one per tab)"
        )

    @staticmethod
    def test_code_tabs_overflow_menu_jumps_to_the_selected_tab(panel: GhidraPanel) -> None:
        """Triggering a code-tab overflow menu entry must switch to that tab.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._code_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        target_index = tabs.count() - 1
        tabs.setCurrentIndex(0)
        assert tabs.currentIndex() == 0

        menu.actions()[target_index].trigger()

        assert tabs.currentIndex() == target_index, (
            f"triggering the overflow menu entry for tab {target_index} ('{tabs.tabText(target_index)}') did not switch the code tabs to it"
        )

    @staticmethod
    def test_data_tabs_overflow_menu_lists_every_tab(panel: GhidraPanel) -> None:
        """The bottom detail strip's corner menu must list exactly one entry per tab.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        assert len(menu.actions()) == tabs.count(), (
            f"data-tabs overflow menu has {len(menu.actions())} entries, expected {tabs.count()} (one per tab)"
        )

    @staticmethod
    def test_data_tabs_overflow_menu_jumps_to_the_selected_tab(panel: GhidraPanel) -> None:
        """Triggering a data-tab overflow menu entry must switch to that tab.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        target_index = tabs.count() - 1
        tabs.setCurrentIndex(0)
        assert tabs.currentIndex() == 0

        menu.actions()[target_index].trigger()

        assert tabs.currentIndex() == target_index, (
            f"triggering the overflow menu entry for tab {target_index} ('{tabs.tabText(target_index)}') did not switch the data tabs to it"
        )

    @staticmethod
    def test_data_tabs_keep_elide_none_after_the_overflow_menu_is_installed(panel: GhidraPanel) -> None:
        """Installing the corner overflow menu must not reintroduce label eliding on the data tabs.

        ``install_tab_overflow`` sets its own tab bar to
        ``Qt.TextElideMode.ElideRight``, which conflicts with this pane's
        established contract (``tests/ui/test_ghidra_panel_data_tabs_overflow.py``)
        that labels are never elided, only reachable via scroll buttons or
        this corner menu. ``GhidraPanel._create_data_tabs`` must restore
        ``ElideNone`` after installing the overflow menu.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        tab_bar = tabs.tabBar()
        assert tab_bar is not None
        assert tab_bar.elideMode() == Qt.TextElideMode.ElideNone, (
            f"_data_tabs tab bar elideMode()={tab_bar.elideMode()!r} -- install_tab_overflow's "
            "ElideRight default was not restored to this pane's established ElideNone contract"
        )
