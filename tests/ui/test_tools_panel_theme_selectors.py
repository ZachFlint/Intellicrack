# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate that the function-list and xref QSS rules reach the widgets they style.

``FunctionListPanel`` builds its list from a ``QListWidget`` named
``function_list`` and ``XRefPanel`` builds its display from a ``QTreeWidget``
named ``xref_display``. A Qt type selector only matches the named class or one
of its subclasses, so a rule written as ``QPlainTextEdit#function_list`` is
silently ignored and the widget renders with the generic list or tree rule
instead. These tests apply every shipped theme through ``ThemeManager`` to the
real panels and assert on what Qt actually resolved: the selector class in the
stylesheet is a real base of the widget, the resolved palette and frame width
match the declarations in the QSS, and a selected row keeps its readable text
colour.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

import pytest
from PyQt6.QtGui import QColor, QImage, QPalette
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QWidget

from intellicrack.ui.resources.theme_manager import (
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ThemeManager,
)
from intellicrack.ui.tools import FunctionListPanel, XRefPanel


if TYPE_CHECKING:
    from collections.abc import Generator


_THEMES: tuple[str, ...] = (THEME_DARK, THEME_LIGHT, THEME_DARK2, THEME_LIGHT2)
_OBJECT_NAMES: tuple[str, ...] = ("function_list", "xref_display")
_PANEL_WIDTH: int = 360
_PANEL_HEIGHT: int = 220
_RGB_MASK: int = 0xFFFFFF
_HEX_COLOR: str = r"#[0-9a-fA-F]{6}"
_COLOR_DECLARATION: re.Pattern[str] = re.compile(rf"(?<![\w-])color\s*:\s*({_HEX_COLOR})\s*;")
_BACKGROUND_DECLARATION: re.Pattern[str] = re.compile(rf"(?<![\w-])background-color\s*:\s*({_HEX_COLOR})\s*;")


class _ViewRule(NamedTuple):
    """Declarations of the ``Class#object_name`` rule found in a theme stylesheet.

    Attributes:
        selector_class: The Qt class named by the selector.
        text_color: The ``color`` declared by the rule.
        background: The ``background-color`` declared by the rule.
    """

    selector_class: str
    text_color: QColor
    background: QColor


class _ThemedView(NamedTuple):
    """A real panel and its item view with a theme applied.

    Attributes:
        panel: The panel that owns the view.
        view: The item view carrying the object name under test.
        stylesheet: The stylesheet text of the applied theme.
        rule: The rule the stylesheet declares for the view's object name.
    """

    panel: QWidget
    view: QAbstractItemView
    stylesheet: str
    rule: _ViewRule


def _declared_color(body: str, pattern: re.Pattern[str]) -> QColor:
    """Read one hex colour declaration out of a rule body.

    Args:
        body: The text between a rule's braces.
        pattern: The declaration pattern whose first group is the hex colour.

    Returns:
        QColor: The declared colour.
    """
    match = pattern.search(body)
    assert match is not None, f"declaration {pattern.pattern!r} missing from rule body {body!r}"
    return QColor(match.group(1))


def _view_rule(stylesheet: str, object_name: str) -> _ViewRule:
    """Find the single ``Class#object_name`` rule in a stylesheet.

    Args:
        stylesheet: Theme stylesheet text.
        object_name: Object name the rule selects.

    Returns:
        _ViewRule: The class named by the selector and the declared colours.
    """
    pattern = re.compile(rf"^(Q[A-Za-z]+)#{object_name}\s*\{{([^}}]*)\}}", re.MULTILINE)
    matches = pattern.findall(stylesheet)
    assert len(matches) == 1, f"expected exactly one #{object_name} rule, found {len(matches)}"
    selector_class, body = matches[0]
    return _ViewRule(
        selector_class=selector_class,
        text_color=_declared_color(body, _COLOR_DECLARATION),
        background=_declared_color(body, _BACKGROUND_DECLARATION),
    )


def _selected_item_color(stylesheet: str, view_class: str) -> QColor | None:
    """Find the text colour the generic selected-item rule gives an item view.

    Args:
        stylesheet: Theme stylesheet text.
        view_class: Qt class name of the item view, e.g. ``"QListWidget"``.

    Returns:
        QColor | None: The ``color`` declared by the ``view_class::item:selected``
        rule, or ``None`` when the rule leaves the text colour alone.
    """
    pattern = re.compile(rf"^{view_class}::item:selected\b[^{{]*\{{([^}}]*)\}}", re.MULTILINE)
    matches = pattern.findall(stylesheet)
    assert len(matches) == 1, f"expected exactly one {view_class}::item:selected rule, found {len(matches)}"
    color = _COLOR_DECLARATION.search(matches[0])
    return QColor(color.group(1)) if color is not None else None


def _count_pixels(image: QImage, color: QColor) -> int:
    """Count the pixels of an image that are exactly one colour.

    Args:
        image: Image to scan.
        color: Colour to count, compared on its RGB value.

    Returns:
        int: Number of matching pixels.
    """
    target = color.rgb() & _RGB_MASK
    return sum(1 for y in range(image.height()) for x in range(image.width()) if image.pixel(x, y) & _RGB_MASK == target)


def _build_view(object_name: str) -> tuple[QWidget, QAbstractItemView]:
    """Build the real panel that owns an object name and fill it with a row.

    Args:
        object_name: ``"function_list"`` or ``"xref_display"``.

    Returns:
        tuple[QWidget, QAbstractItemView]: The panel and its item view.
    """
    if object_name == "function_list":
        function_panel = FunctionListPanel()
        function_panel.set_functions([("main", 0x401000), ("helper", 0x401100)])
        return function_panel, function_panel.list_widget
    xref_panel = XRefPanel()
    xref_panel.set_xrefs([(0x401000, "call main"), (0x401100, "jmp helper")], [(0x402000, "call imported")])
    return xref_panel, xref_panel.xref_display


@pytest.fixture(params=_THEMES)
def theme(request: pytest.FixtureRequest) -> str:
    """Parametrize a test over every shipped theme.

    Args:
        request: Pytest fixture request carrying the current theme name.

    Returns:
        str: The theme name to apply.
    """
    return str(request.param)


@pytest.fixture(params=_OBJECT_NAMES)
def object_name(request: pytest.FixtureRequest) -> str:
    """Parametrize a test over the two item views whose rules are under test.

    Args:
        request: Pytest fixture request carrying the current object name.

    Returns:
        str: The object name of the item view.
    """
    return str(request.param)


@pytest.fixture
def themed_view(qapp: QApplication, theme: str, object_name: str) -> Generator[_ThemedView]:
    """Apply a theme through ThemeManager and build the real panel under it.

    Args:
        qapp: The session ``QApplication``.
        theme: Theme name to apply.
        object_name: Object name of the item view under test.

    Yields:
        _ThemedView: The polished view with the stylesheet and rule it is checked against.
    """
    del qapp
    ThemeManager.reset_instance()
    manager = ThemeManager.get_instance()
    assert manager.apply_theme(theme) is True
    stylesheet = manager.get_stylesheet(theme)
    panel, view = _build_view(object_name)
    view.ensurePolished()
    yield _ThemedView(panel=panel, view=view, stylesheet=stylesheet, rule=_view_rule(stylesheet, object_name))
    panel.close()
    panel.deleteLater()


class TestFunctionAndXrefThemeSelectors:
    """The ``function_list`` and ``xref_display`` rules style the widgets that carry those names."""

    @staticmethod
    def test_view_carries_the_object_name(themed_view: _ThemedView, object_name: str) -> None:
        """The widget the panel builds is named exactly what the stylesheet selects.

        Args:
            themed_view: The themed panel and its item view.
            object_name: Object name the stylesheet rule selects.
        """
        assert themed_view.view.objectName() == object_name

    @staticmethod
    def test_selector_class_is_a_base_of_the_widget(themed_view: _ThemedView) -> None:
        """Qt applies a type selector only to the named class or its subclasses.

        Args:
            themed_view: The themed panel and its item view.
        """
        selector_class = themed_view.rule.selector_class
        assert themed_view.view.inherits(selector_class), (
            f"{selector_class}#{themed_view.view.objectName()} can never match a {type(themed_view.view).__name__}"
        )

    @staticmethod
    def test_resolved_palette_matches_the_rule(themed_view: _ThemedView) -> None:
        """Qt resolves the rule's text and background colours onto the widget palette.

        Args:
            themed_view: The themed panel and its item view.
        """
        palette = themed_view.view.palette()
        assert palette.color(QPalette.ColorRole.Text) == themed_view.rule.text_color
        assert palette.color(QPalette.ColorRole.Base) == themed_view.rule.background

    @staticmethod
    def test_rule_removes_the_generic_frame(themed_view: _ThemedView) -> None:
        """The rule's ``border: none`` replaces the generic 1px list and tree border.

        Args:
            themed_view: The themed panel and its item view.
        """
        assert themed_view.view.frameWidth() == 0

    @staticmethod
    def test_selected_row_keeps_the_generic_selection_text_colour(themed_view: _ThemedView) -> None:
        """A selected row is drawn with the selection text colour, not the rule's colour.

        The light themes set the selected text colour in the generic
        ``::item:selected`` rule; the dark themes leave it to the palette's
        highlighted-text colour. Either way the row must show that colour, and
        where the generic rule sets one the rule's own function colour must not
        leak into the selected row.

        Args:
            themed_view: The themed panel and its item view.
        """
        view = themed_view.view
        model = view.model()
        assert model is not None
        index = model.index(0, 0)
        view.setCurrentIndex(index)
        themed_view.panel.resize(_PANEL_WIDTH, _PANEL_HEIGHT)
        themed_view.panel.show()
        QApplication.processEvents()
        viewport = view.viewport()
        assert viewport is not None
        row = viewport.grab().toImage().copy(view.visualRect(index))

        selected = _selected_item_color(themed_view.stylesheet, type(view).__name__)
        expected = selected if selected is not None else view.palette().color(QPalette.ColorRole.HighlightedText)
        assert _count_pixels(row, expected) > 0, f"selected row never shows {expected.name()}"
        if selected is not None and selected != themed_view.rule.text_color:
            assert _count_pixels(row, themed_view.rule.text_color) == 0
