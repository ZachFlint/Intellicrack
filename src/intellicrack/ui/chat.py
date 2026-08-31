# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Chat panel widget for the Intellicrack UI.

This module provides the chat interface for interacting with the AI orchestrator, displaying conversation history and tool call information.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPainter, QPalette, QTextLayout, QTextOption
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.types import Message, ToolCall, ToolResult
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from PyQt6.QtGui import QFocusEvent, QKeyEvent, QPaintEvent, QResizeEvent

_logger = get_logger(__name__)

_MAX_ARGS_DISPLAY_LEN = 100
_BUBBLE_MARGIN_H: Final[int] = 12
_BUBBLE_MARGIN_V: Final[int] = 8
_TOOL_MARGIN_H: Final[int] = 8
_TOOL_MARGIN_V: Final[int] = 6
_INPUT_MARGIN: Final[int] = 8
_INPUT_MAX_HEIGHT: Final[int] = 100
_SEND_BTN_WIDTH: Final[int] = 80
_SEND_BTN_HEIGHT: Final[int] = 40
_HEADER_HEIGHT: Final[int] = 40
_HEADER_MARGIN_H: Final[int] = 12
_MSG_AREA_MARGIN: Final[int] = 12
_MAX_RESULT_DISPLAY_LEN = 200
_CHAT_INPUT_PLACEHOLDER: Final[str] = "Type a message... (Enter to send, Shift+Enter for newline)"


class _MarkdownView(QTextBrowser):
    """Read-only rich-text view that renders CommonMark markdown content.

    Replaces a plain ``QLabel`` for message bubble content so headings, bold and italic text, lists, inline code, and fenced code blocks
    render as formatted rich text instead of literal markdown syntax. The view has no frame or internal scrollbars and auto-sizes its height
    to the rendered document so it behaves like a word-wrapping label inside the bubble's ``QVBoxLayout``.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the markdown view.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setReadOnly(True)
        self.setOpenExternalLinks(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setLineWrapMode(QTextBrowser.LineWrapMode.WidgetWidth)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet("background: transparent; border: none;")
        document = self.document()
        if document is not None:
            document.setDocumentMargin(0)
            layout = document.documentLayout()
            if layout is not None:
                layout.documentSizeChanged.connect(self._update_height)

    def set_markdown_content(self, text: str) -> None:
        """Render the given text as CommonMark markdown.

        Args:
            text: Markdown-formatted message content.
        """
        self.setMarkdown(text)
        self._reflow_to_viewport_width()
        self._update_height()

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Reflow the document to the new viewport width and resize to fit.

        Args:
            a0: The incoming resize event, or ``None`` if Qt delivered no event.
        """
        self._reflow_to_viewport_width()
        super().resizeEvent(a0)
        self._update_height()

    def _reflow_to_viewport_width(self) -> None:
        """Set the document's text width to the current viewport width."""
        document = self.document()
        viewport = self.viewport()
        if document is not None and viewport is not None:
            document.setTextWidth(viewport.width())

    def _update_height(self) -> None:
        """Fix the widget's height to the rendered document's height."""
        document = self.document()
        if document is None:
            return
        margins = self.contentsMargins()
        frame_width = self.frameWidth() * 2
        height = int(document.size().height()) + margins.top() + margins.bottom() + frame_width
        self.setFixedHeight(max(height, 1))


class MessageBubble(QFrame):
    """A single message bubble in the chat.

    Displays a message from the user, assistant, or tool with
    appropriate styling and formatting.

    Attributes:
        content_label: Markdown-rendering view displaying the message
            content; updated directly by streaming consumers to append
            incremental chunks.
    """

    content_label: _MarkdownView

    def __init__(
        self,
        message: Message,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the MessageBubble with the given message.

        Args:
            message: The message to display.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._message = message
        self.content_label = _MarkdownView()
        self.content_label.set_markdown_content(self._message.content)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the message bubble UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_BUBBLE_MARGIN_H, _BUBBLE_MARGIN_V, _BUBBLE_MARGIN_H, _BUBBLE_MARGIN_V)
        layout.setSpacing(4)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        role_label = QLabel(self._get_role_display())
        role_label.setFont(FontManager.get_instance().get_ui_font_bold(9))

        time_label = QLabel(self._message.timestamp.strftime("%H:%M"))
        time_label.setObjectName("timestamp_label")

        header_layout.addWidget(role_label)
        header_layout.addStretch()
        header_layout.addWidget(time_label)
        layout.addLayout(header_layout)

        self.content_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.LinksAccessibleByMouse,
        )
        self.content_label.setFont(FontManager.get_instance().get_ui_font(10))
        self.content_label.setVisible(bool(self._message.content))
        layout.addWidget(self.content_label)

        if self._message.tool_calls:
            for call in self._message.tool_calls:
                call_widget = self._create_tool_call_widget(call)
                layout.addWidget(call_widget)

        if self._message.tool_results:
            for result in self._message.tool_results:
                result_widget = self._create_tool_result_widget(result)
                layout.addWidget(result_widget)

        self._apply_style()

    def _get_role_display(self) -> str:
        """Get display text for message role.

        Returns:
            str: Role display string with emoji.
        """
        role_map = {
            "user": "You",
            "assistant": "Intellicrack",
            "system": "System",
            "tool": "Tool",
        }
        return role_map.get(self._message.role, self._message.role.title())

    def _apply_style(self) -> None:
        """Apply styling based on message role."""
        self.setProperty("role", self._message.role)
        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)

    @staticmethod
    def _create_tool_call_widget(call: ToolCall) -> QFrame:
        """Create a widget displaying a tool call.

        Args:
            call: The tool call to display.

        Returns:
            QFrame: Widget showing the tool call.
        """
        frame = QFrame()
        frame.setObjectName("tool_call_frame")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(_TOOL_MARGIN_H, _TOOL_MARGIN_V, _TOOL_MARGIN_H, _TOOL_MARGIN_V)
        layout.setSpacing(2)

        header = QLabel(f"Tool: {call.tool_name}.{call.function_name}")
        header.setFont(FontManager.get_instance().get_code_font_bold(9))
        header.setObjectName("tool_call_header")
        layout.addWidget(header)

        if call.arguments:
            full_args_text = ", ".join(f"{k}={v!r}" for k, v in call.arguments.items())
            args_text = full_args_text
            if len(args_text) > _MAX_ARGS_DISPLAY_LEN:
                args_text = f"{args_text[: _MAX_ARGS_DISPLAY_LEN - 3]}..."
            args_label = QLabel(args_text)
            args_label.setFont(FontManager.get_instance().get_code_font(8))
            args_label.setObjectName("tool_call_args")
            args_label.setWordWrap(True)
            if args_text != full_args_text:
                args_label.setToolTip(full_args_text)
            layout.addWidget(args_label)

        return frame

    @staticmethod
    def _create_tool_result_widget(result: ToolResult) -> QFrame:
        """Create a widget displaying a tool result.

        Args:
            result: The tool result to display.

        Returns:
            QFrame: Widget showing the tool result.
        """
        frame = QFrame()
        frame.setObjectName("tool_result_success" if result.success else "tool_result_error")

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(_TOOL_MARGIN_H, _TOOL_MARGIN_V, _TOOL_MARGIN_H, _TOOL_MARGIN_V)
        layout.setSpacing(2)

        status = "Success" if result.success else "Failed"
        header = QLabel(f"Result: {status} ({result.duration_ms:.1f}ms)")
        header.setFont(FontManager.get_instance().get_code_font(9))
        header.setObjectName("result_header_success" if result.success else "result_header_error")
        layout.addWidget(header)

        if result.error:
            error_label = QLabel(result.error)
            error_label.setFont(FontManager.get_instance().get_code_font(8))
            error_label.setObjectName("error_text")
            error_label.setWordWrap(True)
            layout.addWidget(error_label)
        elif result.result is not None:
            full_result_text = str(result.result)
            result_text = full_result_text
            if len(result_text) > _MAX_RESULT_DISPLAY_LEN:
                result_text = f"{result_text[: _MAX_RESULT_DISPLAY_LEN - 3]}..."
            result_label = QLabel(result_text)
            result_label.setFont(FontManager.get_instance().get_code_font(8))
            result_label.setObjectName("result_text")
            result_label.setWordWrap(True)
            if result_text != full_result_text:
                result_label.setToolTip(full_result_text)
            layout.addWidget(result_label)

        return frame


class _ChatTextEdit(QTextEdit):
    """Multi-line chat input that submits on Enter.

    Pressing Enter (or the numeric keypad Enter) emits :attr:`submitted` so the
    composed message is sent, while Shift+Enter inserts a newline for composing
    multi-line messages.

    Qt's built-in ``QTextEdit`` placeholder is drawn as a single hard-clipped
    line, which truncates a long hint instead of wrapping it. This widget
    paints its own placeholder, word-wrapped to the viewport width, so the
    full hint stays visible when the widget is narrow.

    Attributes:
        submitted: Qt signal emitted when the user presses Enter without the
            Shift modifier.
    """

    submitted = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the chat text edit.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.textChanged.connect(self._refresh_placeholder)

    @override
    def keyPressEvent(self, e: QKeyEvent | None) -> None:
        """Send on Enter, insert a newline on Shift+Enter.

        Args:
            e: The incoming key event, or ``None`` if Qt delivered no event.
        """
        if e is None:
            super().keyPressEvent(e)
            return

        is_enter = e.key() in {Qt.Key.Key_Return, Qt.Key.Key_Enter}
        shift_held = bool(e.modifiers() & Qt.KeyboardModifier.ShiftModifier)
        if is_enter and not shift_held:
            e.accept()
            self.submitted.emit()
            return

        super().keyPressEvent(e)

    @override
    def focusInEvent(self, e: QFocusEvent | None) -> None:
        """Hide the custom placeholder once the widget gains focus.

        Args:
            e: The incoming focus event, or ``None`` if Qt delivered no event.
        """
        super().focusInEvent(e)
        self._refresh_placeholder()

    @override
    def focusOutEvent(self, e: QFocusEvent | None) -> None:
        """Show the custom placeholder again once the widget loses focus.

        Args:
            e: The incoming focus event, or ``None`` if Qt delivered no event.
        """
        super().focusOutEvent(e)
        self._refresh_placeholder()

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Re-lay-out the wrapped placeholder for the new viewport width.

        Args:
            a0: The incoming resize event, or ``None`` if Qt delivered no event.
        """
        super().resizeEvent(a0)
        self._refresh_placeholder()

    @override
    def paintEvent(self, e: QPaintEvent | None) -> None:
        """Paint the text edit, then the word-wrapped placeholder if applicable.

        The placeholder is drawn only while the document is empty and the
        widget does not have focus, matching when Qt would normally show its
        own (single-line, hard-clipped) placeholder text.

        Args:
            e: The incoming paint event, or ``None`` if Qt delivered no event.
        """
        super().paintEvent(e)
        if not self._should_show_placeholder():
            return

        viewport = self.viewport()
        if viewport is None:
            return

        layout, bounding_rect = self.placeholder_layout()
        painter = QPainter(viewport)
        try:
            painter.setFont(self.font())
            painter.setPen(self.palette().color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text))
            layout.draw(painter, QPointF(bounding_rect.x(), bounding_rect.y()))
        finally:
            painter.end()

    def _should_show_placeholder(self) -> bool:
        """Report whether the custom placeholder should currently be drawn.

        Returns:
            bool: ``True`` when the document is empty and the widget is unfocused.
        """
        document = self.document()
        is_empty = document is None or document.isEmpty()
        return is_empty and not self.hasFocus()

    def placeholder_layout(self) -> tuple[QTextLayout, QRectF]:
        """Build a word-wrapped layout of the placeholder hint for the current viewport width.

        Each line is wrapped no wider than the viewport (minus the document's
        own margin on each side), matching how the visible text area wraps
        typed content.

        Returns:
            tuple[QTextLayout, QRectF]: The positioned layout and the bounding
            rectangle, in viewport coordinates, that its wrapped lines occupy.
        """
        document = self.document()
        margin = document.documentMargin() if document is not None else 0.0
        viewport = self.viewport()
        viewport_width = float(viewport.width()) if viewport is not None else 0.0
        available_width = max(viewport_width - (2 * margin), 1.0)

        layout = QTextLayout(_CHAT_INPUT_PLACEHOLDER, self.font())
        text_option = QTextOption()
        text_option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        layout.setTextOption(text_option)
        layout.beginLayout()
        y = 0.0
        max_line_width = 0.0
        while True:
            line = layout.createLine()
            if not line.isValid():
                break
            line.setLineWidth(available_width)
            line.setPosition(QPointF(0.0, y))
            y += line.height()
            max_line_width = max(max_line_width, line.naturalTextWidth())
        layout.endLayout()

        bounding_rect = QRectF(margin, margin, max_line_width, y)
        return layout, bounding_rect

    def _refresh_placeholder(self) -> None:
        """Repaint the viewport so the custom placeholder appears or disappears."""
        viewport = self.viewport()
        if viewport is not None:
            viewport.update()


class ChatInput(QFrame):
    """Chat input widget with send button.

    Provides a text input area and send button for composing
    messages to send to the AI.

    Attributes:
        message_submitted: Qt signal for message submitted.
    """

    message_submitted = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ChatInput widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the chat input UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(_INPUT_MARGIN, _INPUT_MARGIN, _INPUT_MARGIN, _INPUT_MARGIN)
        layout.setSpacing(8)

        self._text_edit = _ChatTextEdit()
        self._text_edit.setObjectName("chat_input_textedit")
        self._text_edit.setFont(FontManager.get_instance().get_ui_font(10))
        self._text_edit.setMaximumHeight(_INPUT_MAX_HEIGHT)
        self._text_edit.setToolTip(_CHAT_INPUT_PLACEHOLDER)
        self._text_edit.submitted.connect(self._on_send)
        layout.addWidget(self._text_edit)

        self._send_button = QPushButton("Send")
        self._send_button.setObjectName("chat_send_button")
        self._send_button.setFont(FontManager.get_instance().get_ui_font_bold(10))
        self._send_button.setFixedSize(_SEND_BTN_WIDTH, _SEND_BTN_HEIGHT)
        self._send_button.clicked.connect(self._on_send)
        layout.addWidget(self._send_button)

        self.setObjectName("chat_input_bar")

    def _on_send(self) -> None:
        """Handle send button click."""
        if text := self._text_edit.toPlainText().strip():
            _logger.debug("user_message_submitted", length=len(text))
            self.message_submitted.emit(text)
            self._text_edit.clear()

    def set_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the input.

        Args:
            enabled: Whether input should be enabled.
        """
        self._text_edit.setEnabled(enabled)
        self._send_button.setEnabled(enabled)

    def clear(self) -> None:
        """Clear the input text."""
        self._text_edit.clear()

    def set_focus(self) -> None:
        """Set focus to the text input."""
        self._text_edit.setFocus()

    def set_text(self, text: str) -> None:
        """Set the input text content.

        Args:
            text: Text to set in the input field.
        """
        self._text_edit.setPlainText(text)


class ChatPanel(QFrame):
    """Main chat panel widget.

    Contains the message history scroll area and input widget.
    Manages displaying conversation messages and collecting user input.

    Attributes:
        message_submitted: Qt signal for message submitted.
    """

    message_submitted = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ChatPanel widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._messages: list[Message] = []
        self._streaming_message: Message | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the chat panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("chat_header")
        header.setFixedHeight(_HEADER_HEIGHT)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(_HEADER_MARGIN_H, 0, _HEADER_MARGIN_H, 0)

        title = QLabel("Chat")
        title.setFont(FontManager.get_instance().get_ui_font_bold(11))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._clear_button = QPushButton("Clear")
        self._clear_button.setObjectName("secondary_button")
        self._clear_button.clicked.connect(self.clear_messages)
        header_layout.addWidget(self._clear_button)

        layout.addWidget(header)

        self._scroll_area = QScrollArea()
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll_area.setObjectName("chat_scroll_area")

        self._messages_container = QWidget()
        self._messages_layout = QVBoxLayout(self._messages_container)
        self._messages_layout.setContentsMargins(_MSG_AREA_MARGIN, _MSG_AREA_MARGIN, _MSG_AREA_MARGIN, _MSG_AREA_MARGIN)
        self._messages_layout.setSpacing(12)
        self._messages_layout.addStretch()

        self._scroll_area.setWidget(self._messages_container)
        layout.addWidget(self._scroll_area)

        self._input = ChatInput()
        self._input.message_submitted.connect(self.message_submitted.emit)
        layout.addWidget(self._input)

        self.setObjectName("chat_panel")

    def _append_bubble(self, message: Message) -> None:
        """Record a message and insert its bubble ahead of the trailing stretch.

        Args:
            message: Message to record and render.
        """
        self._messages.append(message)

        bubble = MessageBubble(message)
        self._messages_layout.insertWidget(
            self._messages_layout.count() - 1,
            bubble,
        )

    def add_message(self, message: Message) -> None:
        """Add a message to the chat.

        Args:
            message: Message to add.
        """
        self._append_bubble(message)
        _logger.debug(
            "chat_message_added",
            role=message.role,
            has_tool_calls=message.tool_calls is not None,
            has_tool_results=message.tool_results is not None,
        )

        self._scroll_to_bottom()

    def restore_messages(self, messages: Sequence[Message]) -> None:
        """Replace the visible conversation with a previously saved history.

        Renders through the same bubble construction live turns use, so a
        restored session is indistinguishable from one built up
        interactively, and scrolls once at the end rather than once per
        message.

        Args:
            messages: Ordered conversation history to display.
        """
        self.clear_messages()
        for message in messages:
            self._append_bubble(message)

        _logger.info("chat_messages_restored", count=len(messages))
        self._scroll_to_bottom()

    def add_streaming_message(self) -> Callable[[str], None]:
        """Create a streaming message and return the append function.

        The created :class:`Message` is tracked as the panel's active
        streaming message until :meth:`finalize_streaming_message` folds the
        orchestrator's completed response into it, so a turn that streams its
        text never gets a second, duplicate bubble for the same content
        (S16 duplicate-assistant-bubble fix).

        Returns:
            Callable[[str], None]: Function to call with each text chunk.
        """
        _logger.debug("streaming_message_started", message_count=len(self._messages))
        message = Message(
            role="assistant",
            content="",
            timestamp=datetime.now(tz=UTC),
        )
        self._messages.append(message)
        self._streaming_message = message

        bubble = MessageBubble(message)
        self._messages_layout.insertWidget(
            self._messages_layout.count() - 1,
            bubble,
        )

        content_label = bubble.content_label

        def append_chunk(chunk: str) -> None:
            """Append a streamed token chunk to the bubble and scroll into view.

            Args:
                chunk: Incremental text fragment from the streaming response.
            """
            message.content += chunk
            content_label.set_markdown_content(message.content)
            content_label.setVisible(bool(message.content))
            self._scroll_to_bottom()

        return append_chunk

    def finalize_streaming_message(self, message: Message) -> None:
        """Fold a completed assistant message into the active streaming bubble.

        A turn's streamed text already reached the panel chunk-by-chunk via
        the append function :meth:`add_streaming_message` returned, so
        ``message.content`` is not applied here -- the tracked message's
        content, built incrementally, is already authoritative. This only
        merges the metadata the streaming path could not carry: tool calls,
        tool results, and any thinking content the provider reported.

        Calling this with no active streaming message (``add_streaming_message``
        was never invoked for the current turn) falls back to
        :meth:`add_message` so the completed message is still rendered.

        Args:
            message: The orchestrator's completed message for this turn.
        """
        if self._streaming_message is None:
            self.add_message(message)
            return

        if message.tool_calls:
            self._streaming_message.tool_calls = message.tool_calls
        if message.tool_results:
            self._streaming_message.tool_results = message.tool_results
        if message.thinking_content:
            self._streaming_message.thinking_content = message.thinking_content

        _logger.debug(
            "streaming_message_finalized",
            content_length=len(self._streaming_message.content),
            has_tool_calls=self._streaming_message.tool_calls is not None,
        )

    def clear_messages(self) -> None:
        """Clear all messages from the chat."""
        count = len(self._messages)
        self._messages.clear()
        _logger.info("chat_messages_cleared", count=count)

        while self._messages_layout.count() > 1:
            item = self._messages_layout.takeAt(0)
            if item is not None:
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()

    def set_input_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the input widget.

        Args:
            enabled: Whether input should be enabled.
        """
        self._input.set_enabled(enabled=enabled)

    def _scroll_to_bottom(self) -> None:
        """Scroll the message area to the bottom.

        The scroll is deferred to the next GUI event-loop iteration so the layout can recompute the scrollbar's maximum after a freshly
        inserted message bubble is laid out; scrolling synchronously would use a stale maximum and leave the newest bubble partially off-
        screen.
        """
        QTimer.singleShot(0, self._apply_scroll_to_bottom)

    def _apply_scroll_to_bottom(self) -> None:
        """Move the vertical scrollbar to its current maximum."""
        scrollbar = self._scroll_area.verticalScrollBar()
        if scrollbar is not None:
            scrollbar.setValue(scrollbar.maximum())

    def get_messages(self) -> list[Message]:
        """Get all messages in the chat.

        Returns:
            list[Message]: List of messages.
        """
        return self._messages.copy()

    def set_focus_input(self) -> None:
        """Set focus to the input widget."""
        self._input.set_focus()

    def insert_context_text(self, text: str) -> None:
        """Insert context text into the chat input field.

        Replaces the current input content with the provided text
        and sets focus to the input widget for immediate editing
        or submission.

        Args:
            text: Context text to insert.
        """
        _logger.info("chat_insert_context_text", length=len(text))
        self._input.set_text(text)
        self._input.set_focus()
