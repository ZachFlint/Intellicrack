# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the R05 chat-input placeholder clipping fix.

``_ChatTextEdit`` previously called ``setPlaceholderText`` with the long hint
"Type a message... (Enter to send, Shift+Enter for newline)". Qt's built-in
``QTextEdit`` placeholder is drawn as a single hard-clipped line, so at any
width narrower than the full hint the tail -- "...Shift+Enter for newline)"
-- was cut off and never visible.

The fix removes the native ``setPlaceholderText`` call and has
``_ChatTextEdit`` paint its own placeholder, word-wrapped to the viewport
width via a real ``QTextLayout``, only while the document is empty and the
widget is unfocused. This gate builds the real
:class:`~intellicrack.ui.chat.ChatInput` (and, through it, the real
``_ChatTextEdit``) under an offscreen ``QApplication``, resizes it narrow
enough that the hint cannot possibly fit on one line, forces a real layout
pass, and asserts the custom placeholder layout wraps to more than one line
and that its bounding rectangle never spills past the viewport's right edge.

Reverting ``_ChatTextEdit`` to the plain single-line ``setPlaceholderText``
draw removes the ``placeholder_layout`` method entirely, so the "more than
one line" and "no horizontal overflow" assertions below have nothing to call
and the gate fails outright (``AttributeError``), turning it RED.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QWidget

from intellicrack.ui.chat import _CHAT_INPUT_PLACEHOLDER, ChatInput


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

_NARROW_WIDTH = 180
_NARROW_HEIGHT = 90


def test_placeholder_wraps_to_multiple_lines_within_viewport(qapp: QApplication) -> None:
    """A narrow chat input wraps its placeholder hint across multiple lines.

    Resizes the real ``ChatInput`` well below the pixel width the full hint
    needs on one line, then asks the real ``_ChatTextEdit`` for the layout it
    would paint. The wrapped layout must use more than one line, and every
    line's bounding rectangle must stay inside the viewport -- the last word
    on each line lands inside the visible area rather than being clipped at
    the right edge.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    host = QWidget()
    host.resize(800, 200)
    chat_input = ChatInput(host)
    try:
        host.show()
        chat_input.resize(_NARROW_WIDTH, _NARROW_HEIGHT)
        chat_input.show()
        chat_input.ensurePolished()
        qapp.processEvents()

        text_edit = chat_input._text_edit
        viewport = text_edit.viewport()
        assert viewport is not None
        assert viewport.width() > 0, "the text edit never received real geometry"

        metrics_single_line_width = text_edit.fontMetrics().horizontalAdvance(_CHAT_INPUT_PLACEHOLDER)
        assert metrics_single_line_width > viewport.width(), (
            "the test viewport must be narrower than the full hint for this gate to be meaningful"
        )

        layout, bounding_rect = text_edit.placeholder_layout()
        line_count = layout.lineCount()

        assert line_count > 1, f"placeholder should wrap to multiple lines in a {viewport.width()}px viewport, got {line_count}"
        assert bounding_rect.right() <= viewport.rect().right() + 1, (
            f"placeholder bounding rect right edge {bounding_rect.right()} overflows viewport "
            f"right edge {viewport.rect().right()}; the last word is being clipped"
        )
        assert bounding_rect.left() >= 0

        for i in range(line_count):
            line = layout.lineAt(i)
            assert line.naturalTextWidth() <= viewport.width() + 1, (
                f"line {i} natural width {line.naturalTextWidth()} exceeds viewport width {viewport.width()}"
            )
    finally:
        host.close()
        host.deleteLater()


def test_native_placeholder_text_is_not_set(qapp: QApplication) -> None:
    """The text edit must not carry Qt's own single-line placeholder text.

    Guards against a fix that draws the wrapped placeholder but leaves the
    plain ``setPlaceholderText`` call in place, which would make Qt paint its
    clipped single-line placeholder underneath the custom one.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    chat_input = ChatInput()
    try:
        assert not chat_input._text_edit.placeholderText()
    finally:
        chat_input.deleteLater()


def test_input_carries_full_hint_as_tooltip(qapp: QApplication) -> None:
    """The text edit exposes the complete hint through its tooltip as a secondary net.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    chat_input = ChatInput()
    try:
        assert chat_input._text_edit.toolTip() == _CHAT_INPUT_PLACEHOLDER
    finally:
        chat_input.deleteLater()


def test_placeholder_not_drawn_when_document_has_text(qapp: QApplication) -> None:
    """The custom placeholder must not be shown once the user has typed something.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    chat_input = ChatInput()
    try:
        text_edit = chat_input._text_edit
        assert text_edit._should_show_placeholder() is True
        text_edit.setPlainText("hello")
        assert text_edit._should_show_placeholder() is False
    finally:
        chat_input.deleteLater()


def test_placeholder_not_drawn_when_focused(qapp: QApplication) -> None:
    """The custom placeholder must not be shown while the widget has focus.

    Showing a parentless top-level widget can hand initial keyboard focus to
    the first widget in tab order, so focus is explicitly cleared first to
    pin down the unfocused starting state before asserting the focused one.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    chat_input = ChatInput()
    try:
        chat_input.show()
        qapp.processEvents()
        text_edit = chat_input._text_edit
        text_edit.clearFocus()
        qapp.processEvents()

        assert text_edit.hasFocus() is False
        assert text_edit._should_show_placeholder() is True
        text_edit.setFocus()
        qapp.processEvents()
        assert text_edit.hasFocus() is True
        assert text_edit._should_show_placeholder() is False
    finally:
        chat_input.close()
        chat_input.deleteLater()
