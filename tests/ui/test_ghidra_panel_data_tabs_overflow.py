# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the Ghidra panel's bottom data-tabs overflow defect.

``GhidraPanel._create_data_tabs`` (src/intellicrack/ui/panels/ghidra_panel.py)
builds ``self._data_tabs`` with 18 tabs (Strings through Analysis Extras) in a
narrow bottom pane of a vertical splitter. Left at Qt's defaults, the tab
bar's text-eliding shrinks tab labels unpredictably as the widget narrows
instead of exposing the scroll-button chevrons, so tabs toward the end of
the row (Memory, Data Types, Program Tree, Analysis Extras) become hard or
impossible to reach.

The fix mirrors the established idiom already used for the hex panel's side
tabs (``HexEditorPanel._create_content``,
src/intellicrack/ui/panels/hex_editor/panel.py:400-404): the tab bar gets
``setElideMode(Qt.TextElideMode.ElideNone)`` so labels are never truncated and
``setExpanding(False)`` so tabs keep their natural width instead of stretching
to fill the bar, the tab widget gets ``setUsesScrollButtons(True)`` so
overflow is always reachable via scroll chevrons, and the tab widget carries a
minimum height so the bar cannot be squeezed away to nothing by the
surrounding splitter. On the PyQt6 build this repo pins, ``usesScrollButtons``
and ``elideMode`` already default to the values this fix sets (verified
against both the native and ``Fusion`` styles), so ``expanding`` -- whose Qt
default of ``True`` does differ from the fix -- is the assertion that
actually falsifies on a revert; see
``TestDataTabsOverflowIsReachable.test_data_tab_bar_is_configured_for_reachable_overflow``
for the full explanation.

Every assertion below reads live Qt state off a real, fully constructed
``GhidraPanel`` under an offscreen ``QApplication`` -- no mocked widgets, no
restated tab-count literal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTabWidget

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


class TestDataTabsOverflowIsReachable:
    """The bottom data-tabs bar must expose every tab via predictable overflow."""

    @staticmethod
    def test_data_tabs_widget_exists(panel: GhidraPanel) -> None:
        """``_data_tabs`` must be a live, populated ``QTabWidget``.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        assert isinstance(panel._data_tabs, QTabWidget)
        assert panel._data_tabs.count() > 0

    @staticmethod
    def test_every_data_tab_index_is_selectable(panel: GhidraPanel) -> None:
        """Every tab index 0..count-1 must be selectable and expose a non-empty widget.

        Regression: with no overflow configuration, Qt's default tab-bar
        elision can still leave every index individually selectable via
        ``setCurrentIndex`` (elision only affects the drawn label, not
        index validity), so this check alone would not catch the defect --
        it is paired with the overflow-configuration check below, which is
        what the reported clipping actually depends on.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        count = tabs.count()
        assert count > 1, "expected more than one data tab to exercise overflow reachability"

        for index in range(count):
            tabs.setCurrentIndex(index)
            assert tabs.currentIndex() == index, f"tab index {index} did not become current"
            current_widget = tabs.currentWidget()
            assert current_widget is not None, f"tab index {index} has no widget"

    @staticmethod
    def test_data_tab_bar_is_configured_for_reachable_overflow(panel: GhidraPanel) -> None:
        """The data-tabs bar must use scroll buttons, never elide, and not auto-expand tabs.

        Regression: reverting the ``setUsesScrollButtons(True)`` /
        ``setElideMode(Qt.TextElideMode.ElideNone)`` / ``setExpanding(False)``
        block in ``GhidraPanel._create_data_tabs`` drops back to Qt's own
        ``QTabBar`` defaults. On this PyQt6 build (both the native and
        ``Fusion`` styles) ``usesScrollButtons`` and ``elideMode`` already
        default to the fixed values this fix sets, so those two checks alone
        would not fail on a revert -- ``expanding`` is the one property whose
        Qt default (``True``, letting tabs stretch to fill the bar instead of
        keeping their natural width) actually differs from the fix and is
        what falsifies this test when ``setExpanding(False)`` is removed.
        All three assertions stay in place to pin the full documented
        contract, matching the hex-panel side-tabs idiom this mirrors.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None

        assert tabs.usesScrollButtons() is True, (
            "_data_tabs.usesScrollButtons() is False -- overflow tabs are not reachable via predictable scroll chevrons"
        )

        tab_bar = tabs.tabBar()
        assert tab_bar is not None
        assert tab_bar.elideMode() == Qt.TextElideMode.ElideNone, (
            f"_data_tabs tab bar elideMode()={tab_bar.elideMode()!r} -- labels can still be "
            "truncated instead of triggering scroll-button overflow"
        )
        assert tab_bar.expanding() is False, (
            "_data_tabs tab bar expanding() is True -- Qt's default (True) lets tabs stretch "
            "to fill the bar instead of keeping their natural width for scroll-button overflow"
        )

    @staticmethod
    def test_data_tabs_widget_has_a_nonzero_minimum_height(panel: GhidraPanel) -> None:
        """The data-tabs widget must carry a minimum height so its bar cannot collapse to 0.

        Regression: without an explicit minimum, the vertical splitter that
        hosts ``_data_tabs`` can squeeze the whole pane toward zero height,
        hiding the tab bar (and its scroll buttons) entirely regardless of
        the elide/scroll-button configuration.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        assert tabs.minimumHeight() > 0, (
            f"_data_tabs.minimumHeight()={tabs.minimumHeight()} -- the bottom splitter pane can collapse the tab bar away entirely"
        )
