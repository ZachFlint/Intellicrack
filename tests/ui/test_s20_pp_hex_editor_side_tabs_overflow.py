# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the Hex Editor share of S20-D16/S20-D17 -- clipped side-tab bar.

``HexEditorPanel._create_content`` (src/intellicrack/ui/panels/hex_editor/panel.py)
builds ``self._side_tabs`` with 19 tabs (Inspector through VA Mapping) hosted in
a narrow horizontal splitter pane beside the hex view. Pre-fix, the tab bar only
carried ``ElideNone``/``setExpanding(False)``/``setUsesScrollButtons(True)``, so
at the audit's ~530px docked width a user could only page through the bar one
scroll-chevron click at a time with no indication of what the remaining tabs
were named, matching the S20-D16 sweep's "multi-level sub-tab bars ... clipped
off the right edge" finding.

The fix reuses the Process panel's already-established ``install_tab_overflow``
helper (``intellicrack.ui.panels.process_panel.tab_overflow``), which every
``ProcessPanel`` sub-tab and (per ``tests/ui/test_s20_g1_tab_overflow_menu.py``)
both ``GhidraPanel`` tab strips already rely on: it adds a corner
``QToolButton`` whose menu lists every tab by name and jumps straight to it on
one click, regardless of how the tab bar itself renders. Because
``install_tab_overflow`` also sets ``ElideRight`` on the tab bar, and this
panel's own established contract (this file and
``tests/ui/test_gui_audit0702_panels_hex_editor_panel.py``) is ``ElideNone`` so
labels are never truncated, the fix restores ``ElideNone`` immediately after
installing the overflow menu -- mirroring ``GhidraPanel._create_data_tabs``.

Every assertion drives the real corner button and menu installed on a live,
fully constructed ``HexEditorPanel`` under an offscreen ``QApplication`` -- no
mocked widgets, no reimplementation of the menu-population logic under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMenu, QTabWidget, QToolButton

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def panel(qapp: object) -> Iterator[HexEditorPanel]:
    """Provide a fully constructed ``HexEditorPanel`` and tear it down afterward.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture (from
            ``tests/ui/conftest.py``), required before any ``QWidget`` can be
            constructed.

    Yields:
        HexEditorPanel: A live panel instance with every side tab built.
    """
    del qapp
    instance = HexEditorPanel()
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
        f"{tabs.objectName() or tabs} has no corner overflow QToolButton -- clipped side tabs beyond the visible tab bar are unreachable"
    )
    menu = corner.menu()
    assert isinstance(menu, QMenu)
    menu.aboutToShow.emit()
    return menu


class TestHexEditorSideTabsHaveAnOverflowMenu:
    """The hex editor's side-tab strip must expose every tab through a corner overflow menu."""

    @staticmethod
    def test_side_tabs_widget_has_every_expected_tab(panel: HexEditorPanel) -> None:
        """``_side_tabs`` must be populated with more than one tab to exercise overflow.

        Args:
            panel: A live ``HexEditorPanel`` fixture instance.
        """
        tabs = panel._side_tabs
        assert isinstance(tabs, QTabWidget)
        assert tabs.count() > 1, "expected more than one side tab to exercise overflow reachability"

    @staticmethod
    def test_side_tabs_overflow_menu_lists_every_tab(panel: HexEditorPanel) -> None:
        """The side-tab strip's corner menu must list exactly one entry per tab.

        Args:
            panel: A live ``HexEditorPanel`` fixture instance.
        """
        tabs = panel._side_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        assert len(menu.actions()) == tabs.count(), (
            f"side-tabs overflow menu has {len(menu.actions())} entries, expected {tabs.count()} (one per tab)"
        )

    @staticmethod
    def test_side_tabs_overflow_menu_jumps_to_the_selected_tab(panel: HexEditorPanel) -> None:
        """Triggering a side-tab overflow menu entry must switch to that tab.

        Args:
            panel: A live ``HexEditorPanel`` fixture instance.
        """
        tabs = panel._side_tabs
        assert tabs is not None
        menu = _corner_menu(tabs)
        target_index = tabs.count() - 1
        tabs.setCurrentIndex(0)
        assert tabs.currentIndex() == 0

        menu.actions()[target_index].trigger()

        assert tabs.currentIndex() == target_index, (
            f"triggering the overflow menu entry for tab {target_index} ('{tabs.tabText(target_index)}') did not switch the side tabs to it"
        )

    @staticmethod
    def test_side_tabs_keep_elide_none_after_the_overflow_menu_is_installed(panel: HexEditorPanel) -> None:
        """Installing the corner overflow menu must not reintroduce label eliding on the side tabs.

        ``install_tab_overflow`` sets its own tab bar to
        ``Qt.TextElideMode.ElideRight``, which conflicts with this pane's
        established contract that labels are never elided, only reachable via
        scroll buttons or this corner menu. ``HexEditorPanel._create_content``
        must restore ``ElideNone`` after installing the overflow menu.

        Args:
            panel: A live ``HexEditorPanel`` fixture instance.
        """
        tabs = panel._side_tabs
        assert tabs is not None
        tab_bar = tabs.tabBar()
        assert tab_bar is not None
        assert tab_bar.elideMode() == Qt.TextElideMode.ElideNone, (
            f"_side_tabs tab bar elideMode()={tab_bar.elideMode()!r} -- install_tab_overflow's "
            "ElideRight default was not restored to this pane's established ElideNone contract"
        )
