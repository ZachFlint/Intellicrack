# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the GUI audit finding H32 in ``hex_editor.scripting``.

H32: ``_PythonSyntaxHighlighter._build_rules()`` hardcoded a VSCode "Dark+"
palette (``#569CD6``, ``#4EC9B0``, ``#B5CEA8``, ``#C586C0``, ``#CE9178``,
``#6A9955``) for keyword/builtin/number/decorator/string/comment tokens and
never consulted :class:`ThemeManager`, so several tokens -- most severely
numeric literals -- were nearly invisible against the light theme's white
``QPlainTextEdit`` background, and the highlighter never reacted to a live
theme switch.

These tests drive the real :class:`_PythonSyntaxHighlighter` attached to a
real ``QTextDocument`` under an offscreen ``QApplication`` and read back the
actual character formats Qt applied, rather than inspecting private rule
tables. They fail against the pre-fix code because:

* the hardcoded light-theme-adjacent colours never matched
  ``ThemeManager.get_analysis_colors()`` values (which differ from theme to
  theme), so the theme-driven-colour assertions would fail outright;
* the pre-fix light-theme number colour (the hardcoded ``#B5CEA8``) is
  near-invisible against a white background, so the contrast assertion
  would fail;
* with no ``theme_changed`` subscription, switching the live theme left the
  rendered colours unchanged, so the re-resolution assertion would fail.
"""

from __future__ import annotations

from PyQt6.QtGui import QColor, QTextDocument
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.hex_editor.scripting import _PythonSyntaxHighlighter
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


_CODE_SAMPLE: str = (
    "class Example:\n"
    "    @staticmethod\n"
    "    def compute(value):\n"
    "        total = len(value) + 0x1A2B\n"
    "        # inline comment\n"
    "        return 'done'\n"
)


def _restore_theme() -> None:
    """Restore the shared theme manager to the default dark theme."""
    ThemeManager.get_instance().apply_theme(THEME_DARK)


def _make_highlighted_document(qapp: QApplication) -> QTextDocument:
    """Build a real document with the sample code highlighted.

    Args:
        qapp: The shared offscreen QApplication fixture.

    Returns:
        QTextDocument: A document holding ``_CODE_SAMPLE`` with a live
        :class:`_PythonSyntaxHighlighter` attached and applied.
    """
    _ = qapp
    document = QTextDocument()
    highlighter = _PythonSyntaxHighlighter(document)
    document.setPlainText(_CODE_SAMPLE)
    highlighter.rehighlight()
    QApplication.processEvents()
    return document


def _char_color(document: QTextDocument, index: int) -> QColor:
    """Return the foreground colour Qt applied to the character at ``index``.

    Args:
        document: The highlighted document to inspect.
        index: Zero-based character offset within the document's plain text.

    Returns:
        QColor: The resolved foreground colour of that character, as set by
        the syntax highlighter's applied :class:`QTextCharFormat`.
    """
    block = document.findBlock(index)
    layout = block.layout()
    if layout is None:
        return QColor()
    offset = index - block.position()
    for fmt_range in layout.formats():
        if fmt_range.start <= offset < fmt_range.start + fmt_range.length:
            return fmt_range.format.foreground().color()
    return QColor()


def _luminance(color: QColor) -> float:
    """Compute the perceptual luminance of a colour.

    Args:
        color: The colour to measure.

    Returns:
        float: Luminance in the 0-255 range using ITU-R BT.601 weights.
    """
    return 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()


class TestH32ThemeAwareTokenColors:
    """H32: token colours are resolved from ThemeManager, not hardcoded."""

    def test_h32_number_literal_matches_theme_operand_immediate(self, qapp: QApplication) -> None:
        """The ``0x1A2B`` numeric literal is coloured with the theme's operand_immediate colour.

        Pre-fix the number format was hardcoded to ``QColor("#B5CEA8")``
        regardless of theme; this asserts the rendered colour tracks
        ``ThemeManager.get_analysis_colors()["operand_immediate"]`` in both
        themes, which only holds once the fix resolves colours live.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        try:
            for theme in (THEME_DARK, THEME_LIGHT):
                ThemeManager.get_instance().apply_theme(theme)
                document = _make_highlighted_document(qapp)
                index = _CODE_SAMPLE.index("0x1A2B")
                expected = ThemeManager.get_instance().get_analysis_colors()["operand_immediate"]
                actual = _char_color(document, index)
                assert actual == expected, (
                    f"number literal colour {actual.getRgb()} does not match {theme} operand_immediate {expected.getRgb()}"
                )
        finally:
            _restore_theme()

    def test_h32_keyword_builtin_decorator_string_comment_match_theme_palette(self, qapp: QApplication) -> None:
        """Every remaining token category resolves to its theme-palette colour.

        Verifies ``class``/``def``/``return`` (keywords), ``len`` (builtin),
        ``@staticmethod`` (decorator), ``'done'`` (string), and the inline
        comment all pick up the live theme's semantic colours instead of the
        VSCode Dark+ constants.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            document = _make_highlighted_document(qapp)
            colors = ThemeManager.get_instance().get_analysis_colors()

            keyword_index = _CODE_SAMPLE.index("class")
            builtin_index = _CODE_SAMPLE.index("len")
            decorator_index = _CODE_SAMPLE.index("@staticmethod")
            string_index = _CODE_SAMPLE.index("'done'")
            comment_index = _CODE_SAMPLE.index("# inline comment")

            assert _char_color(document, keyword_index) == colors["mnemonic_jump"]
            assert _char_color(document, builtin_index) == colors["operand_register"]
            assert _char_color(document, decorator_index) == colors["warning"]
            assert _char_color(document, string_index) == colors["mnemonic_ret"]
            assert _char_color(document, comment_index) == colors["muted"]
        finally:
            _restore_theme()

    def test_h32_light_theme_number_contrast_is_adequate(self, qapp: QApplication) -> None:
        """The light-theme number colour must contrast with a white editor background.

        Pre-fix the hardcoded ``#B5CEA8`` pale-green number colour computed
        to roughly a 1.7:1 contrast ratio against white and was effectively
        unreadable; the theme-resolved light colour must clear a real
        readability threshold.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            document = _make_highlighted_document(qapp)
            index = _CODE_SAMPLE.index("0x1A2B")
            number_color = _char_color(document, index)
            white_bg = QColor(255, 255, 255)
            contrast = abs(_luminance(number_color) - _luminance(white_bg))
            assert contrast > 80, (
                f"number literal colour {number_color.getRgb()} has luminance contrast {contrast:.1f} "
                "against a white background, which is too low to be readable"
            )
        finally:
            _restore_theme()

    def test_h32_theme_switch_re_resolves_and_rehighlights(self, qapp: QApplication) -> None:
        """A live theme switch after construction re-resolves and repaints token colours.

        Proves the highlighter subscribes to ``ThemeManager.theme_changed``:
        without the subscription the already-highlighted document would keep
        its original colours regardless of a later ``apply_theme`` call.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        try:
            ThemeManager.get_instance().apply_theme(THEME_DARK)
            document = _make_highlighted_document(qapp)
            index = _CODE_SAMPLE.index("0x1A2B")
            dark_color = _char_color(document, index)

            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            QApplication.processEvents()
            light_color = _char_color(document, index)

            assert light_color != dark_color, "number colour did not change after a live theme switch"
            assert light_color == ThemeManager.get_instance().get_analysis_colors()["operand_immediate"]

            ThemeManager.get_instance().apply_theme(THEME_DARK)
            QApplication.processEvents()
            assert _char_color(document, index) == dark_color, "colour did not re-resolve back to the dark theme value"
        finally:
            _restore_theme()
