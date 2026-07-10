# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ToolOutputPanel detach and reattach functionality.

Verifies tab detachment into floating windows, reattachment back
to the tab bar, handling of invalid indices, bulk tab operations,
detached state queries, tab search by title, and tab bar configuration.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget

from intellicrack.ui.panel_dock import DetachedPanelWindow
from intellicrack.ui.tools import ToolOutputPanel


_TAB_A: str = "TabA"
_TAB_B: str = "TabB"
_TAB_C: str = "TabC"
_TAB_FOO: str = "Foo"
_TAB_BAR: str = "Bar"
_TAB_MISSING: str = "Missing"
_EXPECTED_THREE_TABS: int = 3


def _add_plain_tab(panel: ToolOutputPanel, title: str) -> QWidget:
    """Add a plain QWidget tab to the panel's tab widget.

    Args:
        panel: The ToolOutputPanel to add the tab to.
        title: Tab title text.

    Returns:
        QWidget: The widget added as the tab content.
    """
    widget = QWidget()
    panel.tab_widget.addTab(widget, title)
    return widget


@pytest.mark.usefixtures("qapp")
class TestDetachTab:
    """Tests for detaching tabs into floating windows."""

    @staticmethod
    def test_detach_tab() -> None:
        """Verify detaching a tab decreases count and returns a window."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)
        assert panel.tab_widget.count() == 1

        window = panel.detach_tab(0)

        assert window is not None
        assert isinstance(window, DetachedPanelWindow)
        assert panel.tab_widget.count() == 0

    @staticmethod
    def test_reattach_panel() -> None:
        """Verify detach then reattach restores the tab count."""
        panel = ToolOutputPanel()
        widget = _add_plain_tab(panel, _TAB_A)
        assert panel.tab_widget.count() == 1

        window = panel.detach_tab(0)
        assert window is not None
        assert panel.tab_widget.count() == 0

        panel._reattach_panel(widget, _TAB_A)

        assert panel.tab_widget.count() == 1
        assert panel.tab_widget.tabText(0) == _TAB_A

    @staticmethod
    def test_detach_invalid_index_negative() -> None:
        """Verify detach_tab(-1) returns None."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)

        result = panel.detach_tab(-1)

        assert result is None

    @staticmethod
    def test_detach_invalid_index_overflow() -> None:
        """Verify detach_tab(999) returns None."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)

        result = panel.detach_tab(999)

        assert result is None


@pytest.mark.usefixtures("qapp")
class TestDetachCurrentTab:
    """Tests for detaching the currently active tab."""

    @staticmethod
    def test_detach_current_tab() -> None:
        """Verify detach_current_tab() detaches the active tab."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)
        _add_plain_tab(panel, _TAB_B)
        panel.tab_widget.setCurrentIndex(1)

        window = panel.detach_current_tab()

        assert window is not None
        assert isinstance(window, DetachedPanelWindow)
        assert window.panel_title == _TAB_B
        assert panel.tab_widget.count() == 1

    @staticmethod
    def test_detach_current_tab_empty() -> None:
        """Verify detach_current_tab() returns None when no tabs exist."""
        panel = ToolOutputPanel()

        result = panel.detach_current_tab()

        assert result is None


@pytest.mark.usefixtures("qapp")
class TestCloseOtherAndAllTabs:
    """Tests for bulk tab close operations."""

    @staticmethod
    def test_close_other_tabs() -> None:
        """Verify closing other tabs keeps only the specified index."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)
        widget_b = _add_plain_tab(panel, _TAB_B)
        _add_plain_tab(panel, _TAB_C)
        assert panel.tab_widget.count() == _EXPECTED_THREE_TABS

        panel._close_other_tabs(1)

        assert panel.tab_widget.count() == 1
        assert panel.tab_widget.widget(0) is widget_b

    @staticmethod
    def test_close_all_tabs() -> None:
        """Verify closing all tabs results in zero tabs."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)
        _add_plain_tab(panel, _TAB_B)
        _add_plain_tab(panel, _TAB_C)
        assert panel.tab_widget.count() == _EXPECTED_THREE_TABS

        panel._close_all_tabs()

        assert panel.tab_widget.count() == 0


@pytest.mark.usefixtures("qapp")
class TestDetachedState:
    """Tests for querying detached panel state."""

    @staticmethod
    def test_get_detached_state() -> None:
        """Verify get_detached_state returns titles of detached tabs."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_A)
        _add_plain_tab(panel, _TAB_B)

        panel.detach_tab(0)
        panel.detach_tab(0)

        state = panel.get_detached_state()
        assert _TAB_A in state
        assert _TAB_B in state
        assert len(state) == 2


@pytest.mark.usefixtures("qapp")
class TestFindTabByTitle:
    """Tests for finding tabs by title text."""

    @staticmethod
    def test_find_tab_by_title() -> None:
        """Verify find_tab_by_title returns correct index for existing tab."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_FOO)
        _add_plain_tab(panel, _TAB_BAR)

        assert panel.find_tab_by_title(_TAB_BAR) == 1

    @staticmethod
    def test_find_tab_by_title_missing() -> None:
        """Verify find_tab_by_title returns -1 for non-existent tab."""
        panel = ToolOutputPanel()
        _add_plain_tab(panel, _TAB_FOO)
        _add_plain_tab(panel, _TAB_BAR)

        assert panel.find_tab_by_title(_TAB_MISSING) == -1


@pytest.mark.usefixtures("qapp")
class TestTabBarConfiguration:
    """Tests for tab bar widget configuration."""

    @staticmethod
    def test_tab_bar_movable() -> None:
        """Verify tab bar has isMovable() == True."""
        panel = ToolOutputPanel()
        tab_bar = panel.tab_widget.tabBar()
        assert tab_bar is not None
        assert tab_bar.isMovable() is True

    @staticmethod
    def test_tab_context_menu_policy() -> None:
        """Verify tab bar contextMenuPolicy() is CustomContextMenu."""
        panel = ToolOutputPanel()
        tab_bar = panel.tab_widget.tabBar()
        assert tab_bar is not None
        assert tab_bar.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu
