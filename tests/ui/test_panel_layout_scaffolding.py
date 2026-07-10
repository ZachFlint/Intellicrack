# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the shared analysis-panel layout scaffolding.

Exercises the real widgets produced by :mod:`intellicrack.ui.panels.base_panel`
and :mod:`intellicrack.ui.overflow_toolbar`: that panel toolbars are
overflow-aware, that a scroll-wrapped control cluster genuinely scrolls instead
of clipping when its viewport is narrower than the content, that grouped tool
menus build connected actions, that a clipped dropdown button is re-exposed as
an overflow submenu, and that the theme stylesheet enforces a minimum width on
combo boxes and spin boxes so their contents are not chopped off.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QToolBar,
    QToolButton,
    QWidget,
)

from intellicrack.ui.overflow_toolbar import OverflowToolBar
from intellicrack.ui.panels.base_panel import AnalysisPanelBase, ToolMenuEntry
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


_MIN_COMBO_SPIN_WIDTH = 90
_MIN_GRABBABLE_HANDLE = 6
_UNGRABBABLE_HANDLE_QSS = "QSplitter::handle:vertical { height: 2px; }"


def _rendered_vertical_handle_height(stylesheet: str) -> int:
    """Render a two-pane vertical splitter under ``stylesheet`` and measure its handle.

    Args:
        stylesheet: The Qt style sheet to apply to the splitter.

    Returns:
        int: The laid-out height in pixels of the drag handle between the two panes.
    """
    splitter = QSplitter(Qt.Orientation.Vertical)
    splitter.addWidget(QWidget())
    splitter.addWidget(QWidget())
    splitter.setStyleSheet(stylesheet)
    splitter.resize(300, 400)
    splitter.show()
    QApplication.processEvents()
    handle = splitter.handle(1)
    assert handle is not None, "a two-pane splitter must expose a drag handle at index 1"
    height = handle.height()
    splitter.hide()
    return height


@pytest.mark.usefixtures("qapp")
class TestOverflowToolbarWiring:
    """Panel toolbars must be overflow-aware so no control becomes unreachable."""

    @staticmethod
    def test_panel_toolbar_is_overflow_toolbar() -> None:
        """The base panel must build its toolbar as an OverflowToolBar, not a plain QToolBar."""
        panel = AnalysisPanelBase()
        toolbar = panel.findChild(OverflowToolBar)
        assert toolbar is not None, "panel toolbar must be an OverflowToolBar so clipped buttons stay reachable"

    @staticmethod
    def test_clipped_dropdown_button_becomes_overflow_submenu() -> None:
        """A clipped grouped dropdown button must be re-exposed as a submenu, not an inert entry."""
        toolbar = OverflowToolBar("t")
        button = QToolButton()
        button.setText("Group")
        button.setObjectName("tool_menu_button")
        menu = QMenu(button)
        inner = QAction("Inner Action", menu)
        menu.addAction(inner)
        button.setMenu(menu)

        added = toolbar._add_tool_button_proxy(button, QAction(toolbar))

        assert added is True
        submenu_titles = [action.menu().title() for action in toolbar.overflow_menu.actions() if action.menu() is not None]
        assert "Group" in submenu_titles, "clipped dropdown button must appear as a titled overflow submenu"

    @staticmethod
    def test_tool_button_without_menu_is_not_proxied() -> None:
        """A dropdown button with no menu has nothing to expose and must be rejected."""
        toolbar = OverflowToolBar("t")
        button = QToolButton()
        button.setText("Empty")

        added = toolbar._add_tool_button_proxy(button, QAction(toolbar))

        assert added is False


@pytest.mark.usefixtures("qapp")
class TestMakeScrollable:
    """A scroll-wrapped control cluster must scroll rather than clip when squeezed."""

    @staticmethod
    def test_scroll_area_wraps_inner_and_is_resizable() -> None:
        """_make_scrollable must return a resizable QScrollArea owning the supplied inner widget."""
        inner = QWidget()
        scroll = AnalysisPanelBase._make_scrollable(inner)
        assert isinstance(scroll, QScrollArea)
        assert scroll.widget() is inner
        assert scroll.widgetResizable()

    @staticmethod
    def test_content_wider_than_viewport_becomes_horizontally_scrollable() -> None:
        """When content is wider than the viewport, a horizontal scrollbar must appear instead of clipping."""
        inner = QWidget()
        layout = QHBoxLayout(inner)
        wide_field = QLineEdit()
        wide_field.setMinimumWidth(600)
        layout.addWidget(wide_field)

        scroll = AnalysisPanelBase._make_scrollable(inner)
        scroll.resize(160, 100)
        scroll.show()
        QApplication.processEvents()

        hbar = scroll.horizontalScrollBar()
        assert hbar is not None
        assert hbar.maximum() > 0, "narrow viewport must scroll to reach the 600px-min content, not clip it"
        scroll.hide()


@pytest.mark.usefixtures("qapp")
class TestAddToolMenu:
    """Grouped tool menus must build connected, individually-enableable actions."""

    @staticmethod
    def test_entries_become_actions_with_initial_enabled_state() -> None:
        """Each entry must produce a keyed QAction honouring its initial enabled flag."""
        toolbar = QToolBar()
        actions = AnalysisPanelBase._add_tool_menu(
            toolbar,
            "Group",
            [
                ToolMenuEntry("Alpha", lambda: None),
                ToolMenuEntry("Beta", lambda: None, enabled=False),
            ],
        )
        assert set(actions) == {"Alpha", "Beta"}
        assert actions["Alpha"].isEnabled()
        assert not actions["Beta"].isEnabled()

    @staticmethod
    def test_dropdown_button_added_with_object_name_and_menu() -> None:
        """A single object-named dropdown button carrying the entries' menu must be added to the toolbar."""
        toolbar = QToolBar()
        actions = AnalysisPanelBase._add_tool_menu(
            toolbar,
            "Group",
            [ToolMenuEntry("Alpha", lambda: None)],
        )
        menu_buttons = [b for b in toolbar.findChildren(QToolButton) if b.objectName() == "tool_menu_button"]
        assert len(menu_buttons) == 1
        assert menu_buttons[0].text() == "Group"
        button_menu = menu_buttons[0].menu()
        assert button_menu is not None
        assert actions["Alpha"] in button_menu.actions()

    @staticmethod
    def test_triggering_action_invokes_handler() -> None:
        """Triggering a menu action must invoke the exact handler passed for that entry."""
        toolbar = QToolBar()
        calls: list[str] = []
        actions = AnalysisPanelBase._add_tool_menu(
            toolbar,
            "Group",
            [
                ToolMenuEntry("Alpha", lambda: calls.append("Alpha")),
                ToolMenuEntry("Beta", lambda: calls.append("Beta")),
            ],
        )
        actions["Beta"].trigger()
        assert calls == ["Beta"], "the triggered action must call only its own handler"


@pytest.mark.usefixtures("qapp")
class TestThemeMinimumWidths:
    """The theme stylesheet must floor combo/spin widths so numeric values are not clipped."""

    @staticmethod
    @pytest.mark.parametrize("theme", [THEME_DARK, THEME_LIGHT])
    def test_combobox_has_minimum_width(theme: str) -> None:
        """A themed combo box must report a minimum width hint of at least the stylesheet floor."""
        stylesheet = ThemeManager().get_stylesheet(theme)
        combo = QComboBox()
        combo.setStyleSheet(stylesheet)
        combo.ensurePolished()
        assert combo.minimumSizeHint().width() >= _MIN_COMBO_SPIN_WIDTH

    @staticmethod
    @pytest.mark.parametrize("theme", [THEME_DARK, THEME_LIGHT])
    def test_spinbox_has_minimum_width(theme: str) -> None:
        """A themed spin box must report a minimum width hint of at least the stylesheet floor."""
        stylesheet = ThemeManager().get_stylesheet(theme)
        spin = QSpinBox()
        spin.setStyleSheet(stylesheet)
        spin.ensurePolished()
        assert spin.minimumSizeHint().width() >= _MIN_COMBO_SPIN_WIDTH


@pytest.mark.usefixtures("qapp")
class TestSplitterHandleGrabbable:
    """Themed splitter handles must be thick enough to grab and drag, not a 2px sliver."""

    @staticmethod
    def test_environment_honours_qss_handle_sizing() -> None:
        """A deliberately 2px-styled handle must render thin, proving this gate can detect a regression."""
        control = _rendered_vertical_handle_height(_UNGRABBABLE_HANDLE_QSS)
        assert control < _MIN_GRABBABLE_HANDLE, "environment must honour QSS handle sizing, else this gate cannot catch a 2px regression"

    @staticmethod
    @pytest.mark.parametrize("theme", [THEME_DARK, THEME_LIGHT])
    def test_themed_vertical_handle_is_grabbable(theme: str) -> None:
        """The themed vertical splitter handle must render tall enough to grab and drag."""
        themed = _rendered_vertical_handle_height(ThemeManager().get_stylesheet(theme))
        assert themed >= _MIN_GRABBABLE_HANDLE, f"{theme} vertical splitter handle rendered {themed}px; too thin to grab and drag"
