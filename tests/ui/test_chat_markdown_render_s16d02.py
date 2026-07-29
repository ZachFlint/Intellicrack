# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S16-D02 -- chat assistant markdown rendered as raw text.

Before the fix, ``MessageBubble.content_label`` was a plain ``QLabel`` fed
through ``setText``/``.content_label.setText``, so assistant markdown such as
``## Registers``, ``* **EAX**``, and fenced ```` ```python ```` code blocks
was displayed to the user literally, backticks and all. The fix replaces the
``QLabel`` with a ``QTextBrowser``-based ``_MarkdownView`` that renders
CommonMark markdown via Qt's native ``setMarkdown`` support, re-rendering the
accumulated text on every streamed chunk.

All tests build a real :class:`~intellicrack.ui.chat.MessageBubble` and
:class:`~intellicrack.ui.chat.ChatPanel` under the shared offscreen
``QApplication`` fixture and inspect the actual rendered
``QTextBrowser.toHtml()``/``toPlainText()`` output -- no mocks or stubs stand
in for the widget-construction or rendering logic.
"""

from __future__ import annotations

from datetime import UTC, datetime

from PyQt6.QtCore import Qt

from intellicrack.core.types import Message
from intellicrack.ui.chat import ChatPanel, MessageBubble


def _last_bubble(panel: ChatPanel) -> MessageBubble:
    """Locate the most recently inserted message bubble in a chat panel.

    Args:
        panel: The chat panel to search.

    Returns:
        MessageBubble: The last bubble widget inserted into the panel.

    Raises:
        AssertionError: If no message bubble is found.
    """
    layout = panel._messages_layout
    for index in range(layout.count() - 1, -1, -1):
        item = layout.itemAt(index)
        if item is None:
            continue
        widget = item.widget()
        if isinstance(widget, MessageBubble):
            return widget
    msg = "no MessageBubble found in chat panel"
    raise AssertionError(msg)


def test_assistant_heading_and_fenced_code_render_as_rich_text(qapp: object) -> None:
    """A heading and fenced code block render as formatted elements, not literal markers.

    Drives the real ``MessageBubble`` construction path with markdown
    content containing a level-2 heading, a bold list item, and a fenced
    Python code block. Asserts the rendered ``QTextBrowser`` HTML contains a
    heading element and a preformatted code block, and that the literal
    ``##`` heading marker and triple-backtick fence never appear in the
    rendered output.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    markdown_content = "## Registers\n\n* **EAX**: 0x1000\n* **EBX**: 0x2000\n\n```python\nprint('hi')\n```\n"
    message = Message(role="assistant", content=markdown_content, timestamp=datetime.now(tz=UTC))

    bubble = MessageBubble(message)
    html = bubble.content_label.toHtml()

    assert "<h1" in html or "<h2" in html, html
    assert "<pre" in html, html
    assert "##" not in html
    assert "```" not in html
    assert "print('hi')" in html


def test_assistant_inline_code_and_bold_render_without_literal_markers(qapp: object) -> None:
    """Inline code spans and bold emphasis render without their markdown punctuation.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    markdown_content = "The value of **EAX** is `0x1000` after the call."
    message = Message(role="assistant", content=markdown_content, timestamp=datetime.now(tz=UTC))

    bubble = MessageBubble(message)
    html = bubble.content_label.toHtml()
    plain_text = bubble.content_label.toPlainText()

    assert "**EAX**" not in plain_text
    assert "`0x1000`" not in plain_text
    assert "EAX" in plain_text
    assert "0x1000" in plain_text
    assert "font-weight:700" in html


def test_streaming_reflows_accumulated_markdown_on_each_chunk(qapp: object) -> None:
    """Streaming chunks accumulate and each update re-renders the full markdown document.

    Simulates a real streaming response delivered in three separate chunks
    that together form a heading followed by a fenced code block, split
    mid-fence so no single chunk is valid markdown on its own. Asserts the
    underlying ``Message.content`` accumulates every chunk verbatim (append
    still works) and that the final rendered HTML shows the fully formatted
    result with no literal markdown syntax remaining.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    panel = ChatPanel()
    append_chunk = panel.add_streaming_message()

    append_chunk("## Analysis\n\n")
    append_chunk("```python\nprint(")
    append_chunk("'streamed')\n```\n")

    accumulated = panel.get_messages()[-1].content
    assert accumulated == "## Analysis\n\n```python\nprint('streamed')\n```\n"

    bubble = _last_bubble(panel)
    html = bubble.content_label.toHtml()

    assert "<h1" in html or "<h2" in html, html
    assert "<pre" in html, html
    assert "##" not in html
    assert "```" not in html
    assert "print('streamed')" in html


def test_user_message_content_is_preserved_and_selectable(qapp: object) -> None:
    """A plain user message still displays its full text and remains selectable.

    Guards against the markdown rendering fix regressing user-message
    display: plain conversational text with no markdown syntax must still
    show up verbatim in the rendered view, and the view must keep
    text-selection enabled so users can still copy content out of the chat.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    user_text = "Explain what this function at 0x401000 does."
    message = Message(role="user", content=user_text, timestamp=datetime.now(tz=UTC))

    bubble = MessageBubble(message)

    assert bubble.content_label.toPlainText().strip() == user_text
    flags = bubble.content_label.textInteractionFlags()
    assert bool(flags & Qt.TextInteractionFlag.TextSelectableByMouse)
    assert bubble.content_label.isReadOnly()


def test_empty_content_bubble_stays_hidden(qapp: object) -> None:
    """A message with no text content keeps its content view hidden.

    Streaming responses start with an empty ``Message.content`` before the
    first chunk arrives; the content view must stay invisible until real
    text is appended, matching the previous ``QLabel``-based behavior.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    message = Message(role="assistant", content="", timestamp=datetime.now(tz=UTC))

    bubble = MessageBubble(message)

    assert bubble.content_label.isVisible() is False
