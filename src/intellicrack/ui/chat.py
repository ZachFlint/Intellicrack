# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Chat panel widget for the Intellicrack UI.

This module provides the chat interface for interacting with the AI orchestrator, displaying conversation history and tool call information.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.types import Message, ToolCall, ToolResult
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable

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


class MessageBubble(QFrame):
    """A single message bubble in the chat.

    Displays a message from the user, assistant, or tool with
    appropriate styling and formatting.

    Attributes:
        content_label: QLabel displaying the message content; updated
            directly by streaming consumers to append incremental chunks.
    """

    content_label: QLabel

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
        self.content_label = QLabel(self._message.content)
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

        self.content_label.setWordWrap(True)
        self.content_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
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
            args_text = ", ".join(f"{k}={v!r}" for k, v in call.arguments.items())
            if len(args_text) > _MAX_ARGS_DISPLAY_LEN:
                args_text = f"{args_text[: _MAX_ARGS_DISPLAY_LEN - 3]}..."
            args_label = QLabel(args_text)
            args_label.setFont(FontManager.get_instance().get_code_font(8))
            args_label.setObjectName("tool_call_args")
            args_label.setWordWrap(True)
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
            result_text = str(result.result)
            if len(result_text) > _MAX_RESULT_DISPLAY_LEN:
                result_text = f"{result_text[: _MAX_RESULT_DISPLAY_LEN - 3]}..."
            result_label = QLabel(result_text)
            result_label.setFont(FontManager.get_instance().get_code_font(8))
            result_label.setObjectName("result_text")
            result_label.setWordWrap(True)
            layout.addWidget(result_label)

        return frame


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

        self._text_edit = QTextEdit()
        self._text_edit.setFont(FontManager.get_instance().get_ui_font(10))
        self._text_edit.setMaximumHeight(_INPUT_MAX_HEIGHT)
        self._text_edit.setPlaceholderText("Type a message...")
        self._text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d30;
                border: 1px solid #3e3e42;
                border-radius: 8px;
                padding: 8px;
                color: #d4d4d4;
            }
            QTextEdit:focus {
                border: 1px solid #007acc;
            }
        """)
        layout.addWidget(self._text_edit)

        self._send_button = QPushButton("Send")
        self._send_button.setFont(FontManager.get_instance().get_ui_font_bold(10))
        self._send_button.setFixedSize(_SEND_BTN_WIDTH, _SEND_BTN_HEIGHT)
        self._send_button.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                border: none;
                border-radius: 6px;
                color: white;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #0d5289;
            }
            QPushButton:disabled {
                background-color: #3e3e42;
                color: #888888;
            }
        """)
        self._send_button.clicked.connect(self._on_send)
        layout.addWidget(self._send_button)

        self.setStyleSheet("""
            QFrame {
                background-color: #252526;
                border-top: 1px solid #3e3e42;
            }
        """)

    def _on_send(self) -> None:
        """Handle send button click."""
        text = self._text_edit.toPlainText().strip()
        if text:
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
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the chat panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(_HEADER_HEIGHT)
        header.setStyleSheet("""
            QFrame {
                background-color: #2d2d30;
                border-bottom: 1px solid #3e3e42;
            }
        """)
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

    def add_message(self, message: Message) -> None:
        """Add a message to the chat.

        Args:
            message: Message to add.
        """
        self._messages.append(message)
        _logger.debug(
            "chat_message_added",
            role=message.role,
            has_tool_calls=message.tool_calls is not None,
            has_tool_results=message.tool_results is not None,
        )

        bubble = MessageBubble(message)
        self._messages_layout.insertWidget(
            self._messages_layout.count() - 1,
            bubble,
        )

        self._scroll_to_bottom()

    def add_streaming_message(self) -> Callable[[str], None]:
        """Create a streaming message and return the append function.

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

        bubble = MessageBubble(message)
        self._messages_layout.insertWidget(
            self._messages_layout.count() - 1,
            bubble,
        )

        content_label = bubble.content_label

        def append_chunk(chunk: str) -> None:
            message.content += chunk
            content_label.setText(message.content)
            content_label.setVisible(bool(message.content))
            self._scroll_to_bottom()

        return append_chunk

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
        """Scroll the message area to the bottom."""
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
        self._input.set_text(text)
        self._input.set_focus()
