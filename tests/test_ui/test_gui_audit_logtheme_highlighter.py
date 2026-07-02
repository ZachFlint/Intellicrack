# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for syntax-highlighter theming and comment scanning.

Covers two GUI audit findings:

- Token theming: highlighter token formats were hard-coded VS-Code-dark, so the
  operator color ``#D4D4D4`` was invisible on the light background and numbers
  were low contrast. Token colors must now resolve through the active theme and
  stay readable in both light and dark themes, and re-resolve on theme switch.
- Comment scanner: the ``//`` line-comment rule and the ``/* */`` block scanner
  were independent, so a line such as ``x = 1; // note /* text`` made the block
  scanner treat the commented ``/*`` as an unterminated block start and
  mis-highlight following lines. The scanner must ignore ``/*`` that appears
  after a ``//`` line comment on the same line.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QColor, QTextDocument

import intellicrack.ui.highlighter as highlighter_module
from intellicrack.ui.highlighter import (
    CSyntaxHighlighter,
    HexPatSyntaxHighlighter,
    JavaScriptSyntaxHighlighter,
)
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.usefixtures("qapp")

_MIN_CONTRAST_RATIO: float = 3.0
_SRGB_LINEAR_THRESHOLD: float = 0.03928
_INVISIBLE_ON_LIGHT: QColor = QColor(0xD4, 0xD4, 0xD4)
_BLOCK_COMMENT_STATE: int = getattr(highlighter_module, "_BLOCK_STATE_BLOCK_COMMENT")


def _linearize(value: int) -> float:
    """Linearize a single 8-bit sRGB channel for luminance math.

    Args:
        value: Channel value in the range 0-255.

    Returns:
        float: The linearized channel value in the range 0.0-1.0.
    """
    channel = value / 255.0
    if channel <= _SRGB_LINEAR_THRESHOLD:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def _relative_luminance(color: QColor) -> float:
    """Compute the WCAG relative luminance of a color.

    Args:
        color: The color to measure.

    Returns:
        float: Relative luminance in the range 0.0-1.0.
    """
    return 0.2126 * _linearize(color.red()) + 0.7152 * _linearize(color.green()) + 0.0722 * _linearize(color.blue())


def _contrast_ratio(foreground: QColor, background: QColor) -> float:
    """Compute the WCAG contrast ratio between two colors.

    Args:
        foreground: Foreground (text) color.
        background: Background color.

    Returns:
        float: Contrast ratio in the range 1.0-21.0.
    """
    lum_fg = _relative_luminance(foreground)
    lum_bg = _relative_luminance(background)
    lighter = max(lum_fg, lum_bg)
    darker = min(lum_fg, lum_bg)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.fixture
def theme_manager() -> Iterator[ThemeManager]:
    """Yield the theme manager singleton and restore its theme afterward.

    Yields:
        ThemeManager: The application theme manager singleton.
    """
    manager = ThemeManager.get_instance()
    original = manager.requested_theme
    try:
        yield manager
    finally:
        manager.apply_theme(original)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_operator_and_number_tokens_are_readable(theme_manager: ThemeManager, theme: str) -> None:
    """Operator and number token colors keep adequate contrast in each theme.

    Catches the regression where the hard-coded ``#D4D4D4`` operator color was
    invisible on the light background and numbers were low contrast.

    Args:
        theme_manager: The theme manager singleton fixture.
        theme: The theme name to apply for this parametrization.
    """
    theme_manager.apply_theme(theme)
    background = theme_manager.get_analysis_colors()["background"]
    document = QTextDocument()
    highlighter = CSyntaxHighlighter(document)

    assert _contrast_ratio(highlighter.token_color("operator"), background) >= _MIN_CONTRAST_RATIO
    assert _contrast_ratio(highlighter.token_color("number"), background) >= _MIN_CONTRAST_RATIO


def test_operator_token_is_not_the_invisible_light_gray(theme_manager: ThemeManager) -> None:
    """Under the light theme the operator token is not the old invisible gray.

    Args:
        theme_manager: The theme manager singleton fixture.
    """
    theme_manager.apply_theme("light")
    document = QTextDocument()
    highlighter = CSyntaxHighlighter(document)
    assert highlighter.token_color("operator") != _INVISIBLE_ON_LIGHT


def test_theme_switch_re_resolves_token_colors(theme_manager: ThemeManager) -> None:
    """Switching themes re-resolves the operator token to a different color.

    Args:
        theme_manager: The theme manager singleton fixture.
    """
    theme_manager.apply_theme("dark")
    document = QTextDocument()
    highlighter = CSyntaxHighlighter(document)
    dark_operator = QColor(highlighter.token_color("operator"))

    theme_manager.apply_theme("light")
    light_operator = QColor(highlighter.token_color("operator"))
    assert light_operator != dark_operator


@pytest.mark.parametrize(
    "factory",
    [CSyntaxHighlighter, JavaScriptSyntaxHighlighter, HexPatSyntaxHighlighter],
)
def test_line_comment_hides_block_comment_open(
    theme_manager: ThemeManager,
    factory: type[CSyntaxHighlighter | JavaScriptSyntaxHighlighter | HexPatSyntaxHighlighter],
) -> None:
    """A ``/*`` after a ``//`` line comment does not open a block comment.

    Catches the regression where ``x = 1; // note /* text`` left the block
    scanner in an open-block-comment state and mis-highlighted following lines.

    Args:
        theme_manager: The theme manager singleton fixture.
        factory: The highlighter class under test.
    """
    theme_manager.apply_theme("dark")
    document = QTextDocument()
    highlighter = factory(document)
    document.setPlainText("x = 1; // note /* text\nnext line")
    highlighter.rehighlight()

    first_block = document.findBlockByNumber(0)
    second_block = document.findBlockByNumber(1)
    assert first_block.userState() != _BLOCK_COMMENT_STATE
    assert second_block.userState() != _BLOCK_COMMENT_STATE


def test_real_block_comment_still_spans_lines(theme_manager: ThemeManager) -> None:
    """A genuine unterminated ``/*`` still opens a multi-line block comment.

    Confirms the line-comment guard does not suppress real block comments.

    Args:
        theme_manager: The theme manager singleton fixture.
    """
    theme_manager.apply_theme("dark")
    document = QTextDocument()
    highlighter = CSyntaxHighlighter(document)
    document.setPlainText("y = 5; /* open\nstill inside")
    highlighter.rehighlight()

    first_block = document.findBlockByNumber(0)
    second_block = document.findBlockByNumber(1)
    assert first_block.userState() == _BLOCK_COMMENT_STATE
    assert second_block.userState() == _BLOCK_COMMENT_STATE
