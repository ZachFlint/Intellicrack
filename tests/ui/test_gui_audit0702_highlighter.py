# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for block-comment and template-literal tracking in ``highlighter``.

Covers two highlighter defects in :mod:`intellicrack.ui.highlighter`:

- Block comments: ``_scan_block_comments`` must track string literals. A raw ``/*`` regex with no awareness of
  string literals treats a ``/*`` inside a double/single/backtick-quoted string
  (e.g. a Windows path fragment or a truncated URL extracted from a stripped
  binary) as a block-comment opener. With no matching ``*/`` on the same line,
  the highlighter's block state stays "inside a block comment" and every subsequent line is
  mis-highlighted until an unrelated ``*/`` is found.
- Template literals: ``JavaScriptSyntaxHighlighter`` must track backtick template literals across
  blocks. A single-line regex rule alone loses the string coloring on the second and later lines of a
  literal that spans multiple lines (routine in Frida scripts), and keyword-like tokens inside it (e.g. ``if``)
  must stay string content rather than being highlighted as JavaScript keywords.
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

    from PyQt6.QtGui import QTextBlock


pytestmark = pytest.mark.usefixtures("qapp")

_BLOCK_COMMENT_FLAG: int = getattr(highlighter_module, "_BLOCK_COMMENT_FLAG")
_TEMPLATE_LITERAL_FLAG: int = getattr(highlighter_module, "_TEMPLATE_LITERAL_FLAG")

_C_STRING_WITH_SLASH_STAR: str = 'char *msg = "C:/temp/*"; int x = 1;\nint y = 2;\nint z = 3;'
_JS_STRING_WITH_SLASH_STAR: str = 'const msg = "C:/temp/*"; let x = 1;\nlet y = 2;\nlet z = 3;'
_HEXPAT_STRING_WITH_SLASH_STAR: str = 'str msg = "C:/temp/*"; u8 x = 1;\nu8 y = 0;\nu8 z = 0;'


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


def _format_color_at(block: QTextBlock, position: int) -> QColor | None:
    """Return the foreground color painted at ``position`` within ``block``.

    Args:
        block: The text block whose layout format ranges are inspected.
        position: Character offset within the block's text to look up.

    Returns:
        QColor | None: The foreground color of the format range covering
            ``position``, or ``None`` when no range covers it.
    """
    layout = block.layout()
    if layout is None:
        return None
    return next(
        (
            format_range.format.foreground().color()
            for format_range in layout.formats()
            if format_range.start <= position < format_range.start + format_range.length
        ),
        None,
    )


class TestH22BlockCommentExcludesStringLiterals:
    """A ``/*`` inside a string literal must not open a block comment."""

    @pytest.mark.parametrize(
        ("factory", "text"),
        [
            (CSyntaxHighlighter, _C_STRING_WITH_SLASH_STAR),
            (JavaScriptSyntaxHighlighter, _JS_STRING_WITH_SLASH_STAR),
            (HexPatSyntaxHighlighter, _HEXPAT_STRING_WITH_SLASH_STAR),
        ],
        ids=["c", "javascript", "hexpat"],
    )
    def test_h22_slash_star_inside_string_does_not_open_block_comment(
        self,
        theme_manager: ThemeManager,
        factory: type[CSyntaxHighlighter | JavaScriptSyntaxHighlighter | HexPatSyntaxHighlighter],
        text: str,
    ) -> None:
        """A ``/*`` inside a quoted string never sets the block-comment flag.

        A scanner built on a raw
        ``self._comment_start.match(text)`` with no quote tracking, run against
        this same three-line text, would produce block states ``[1, 1, 1]``: the
        ``/*`` inside ``"C:/temp/*"`` is treated as an opener, has no
        matching ``*/`` on that line, so the block-comment state is set and
        carried into every following line. The scanner tracks string
        state via ``_block_comment_start_index`` and must leave every
        block's state clear of ``_BLOCK_COMMENT_FLAG``.

        Args:
            theme_manager: The theme manager singleton fixture.
            factory: The highlighter class under test.
            text: A three-line source snippet whose first line contains a
                string literal with an embedded ``/*`` and no closing ``*/``.
        """
        theme_manager.apply_theme("dark")
        document = QTextDocument()
        highlighter = factory(document)
        document.setPlainText(text)
        highlighter.rehighlight()

        states = [document.findBlockByNumber(i).userState() for i in range(3)]
        assert all(state & _BLOCK_COMMENT_FLAG == 0 for state in states), (
            f"'/*' inside a string literal opened a block comment: block states {states}"
        )

    def test_h22_real_block_comment_after_string_still_spans_and_closes(
        self,
        theme_manager: ThemeManager,
    ) -> None:
        """An unquoted ``/*`` after a string with an embedded ``/*`` still tracks correctly.

        Proves string exclusion does not disable block-comment
        tracking outright: the embedded ``/*`` inside ``"C:/temp/*"`` is
        ignored, but the real ``/*`` later on the same line still opens a
        comment that spans the middle line and closes at its ``*/``.

        Args:
            theme_manager: The theme manager singleton fixture.
        """
        theme_manager.apply_theme("dark")
        document = QTextDocument()
        highlighter = CSyntaxHighlighter(document)
        text = 'char *msg = "C:/temp/*"; /* real comment\nstill inside\nclosed here */ int z = 3;\nnormal();'
        document.setPlainText(text)
        highlighter.rehighlight()

        states = [document.findBlockByNumber(i).userState() for i in range(4)]
        assert (states[0] & _BLOCK_COMMENT_FLAG) != 0, "the real '/* real comment' did not open a block comment"
        assert (states[1] & _BLOCK_COMMENT_FLAG) != 0, "the block comment did not span the middle line"
        assert (states[2] & _BLOCK_COMMENT_FLAG) == 0, "the block comment did not close at 'closed here */'"
        assert (states[3] & _BLOCK_COMMENT_FLAG) == 0, "trailing code after the comment stayed marked as commented"


class TestM18TemplateLiteralsTrackAcrossBlocks:
    """Multi-line JS/Frida template literals must track across blocks."""

    def test_m18_multiline_template_literal_tracks_across_blocks(
        self,
        theme_manager: ThemeManager,
    ) -> None:
        """A template literal spanning two blocks paints both as string, not keyword.

        A single-line-only backtick rule run against this same text would leave the first block's
        backtick-opened tail unformatted (the regex requires both delimiters on one line, so it
        never matches), and the second block's ``if`` token would be painted with the keyword color,
        because nothing tracks the open literal across the block boundary. The fixed
        ``_highlight_template_literals`` must
        carry ``_TEMPLATE_LITERAL_FLAG`` into the second block and repaint
        the still-open literal's prefix (``if broken`` plus the closing
        backtick) with the string color, overriding the keyword format
        ``_apply_rules`` applied first.

        Args:
            theme_manager: The theme manager singleton fixture.
        """
        theme_manager.apply_theme("dark")
        document = QTextDocument()
        highlighter = JavaScriptSyntaxHighlighter(document)
        text = "const payload = `line one\nif broken`;\nconst after = 1;"
        document.setPlainText(text)
        highlighter.rehighlight()

        first_block = document.findBlockByNumber(0)
        second_block = document.findBlockByNumber(1)
        third_block = document.findBlockByNumber(2)

        assert (first_block.userState() & _TEMPLATE_LITERAL_FLAG) != 0, (
            "block state did not carry the unterminated template literal into the next block"
        )
        assert (second_block.userState() & _TEMPLATE_LITERAL_FLAG) == 0, (
            "the closing backtick on the second line did not clear the template-literal state"
        )
        assert (third_block.userState() & _TEMPLATE_LITERAL_FLAG) == 0

        string_color = highlighter.token_color("string")
        keyword_color = highlighter.token_color("keyword")
        assert string_color != keyword_color, "test premise: string and keyword roles resolve to different colors"

        if_color = _format_color_at(second_block, 0)
        assert if_color == string_color, (
            f"'if' inside the still-open template literal is painted {if_color}, "
            f"expected the string color {string_color} rather than the JS keyword color {keyword_color}"
        )

    def test_m18_single_line_template_literal_still_highlighted(
        self,
        theme_manager: ThemeManager,
    ) -> None:
        """A template literal that opens and closes on one line stays fully string-colored.

        Guards against a regression where the cross-block tracking stops
        repainting a literal that never crosses a block boundary.

        Args:
            theme_manager: The theme manager singleton fixture.
        """
        theme_manager.apply_theme("dark")
        document = QTextDocument()
        highlighter = JavaScriptSyntaxHighlighter(document)
        text = "const single = `hello ${x} world`;"
        document.setPlainText(text)
        highlighter.rehighlight()

        block = document.findBlockByNumber(0)
        assert (block.userState() & _TEMPLATE_LITERAL_FLAG) == 0, "a closed literal must not leave the flag set"

        string_color = highlighter.token_color("string")
        backtick_index = text.index("`")
        inside_color = _format_color_at(block, backtick_index + 2)
        assert inside_color == string_color, f"single-line template literal body is not string-colored: {inside_color}"
