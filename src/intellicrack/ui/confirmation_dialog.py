"""Tool confirmation dialog for Intellicrack.

This module provides a dialog for confirming tool calls before execution,
allowing users to review and approve or deny potentially destructive operations.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..core.logging import get_logger


if TYPE_CHECKING:
    from ..core.types import ToolCall

_logger = get_logger("ui.confirmation_dialog")


class ToolConfirmationDialog(QDialog):
    """Dialog for confirming tool calls.

    Displays the tool name, function, and arguments for user review
    before executing potentially destructive operations.

    Attributes:
        _call: The tool call to confirm.
        _approved: Whether the user approved the call.
        _remember_similar: Whether to remember choice for similar operations.
    """

    def __init__(
        self,
        call: ToolCall,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the confirmation dialog.

        Args:
            call: The tool call to confirm.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._call = call
        self._approved = False
        self._remember_similar = False
        _logger.debug(
            "tool_confirmation_dialog_opened",
            extra={"tool": call.tool_name, "function": call.function_name},
        )
        self._setup_ui()

    @property
    def approved(self) -> bool:
        """Get whether the call was approved.

        Returns:
            True if user approved, False otherwise.
        """
        return self._approved

    @property
    def remember_similar(self) -> bool:
        """Get whether to remember choice for similar operations.

        Returns:
            True if user wants to remember choice.
        """
        return self._remember_similar

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle("Confirm Tool Call")
        self.setMinimumSize(500, 400)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header_label = QLabel("AI wants to execute the following tool:")
        header_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #d4d4d4;
            }
        """)
        layout.addWidget(header_label)

        tool_label = QLabel(f"{self._call.tool_name}.{self._call.function_name}")
        tool_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #569cd6;
                padding: 8px;
                background-color: #252526;
                border-radius: 4px;
            }
        """)
        layout.addWidget(tool_label)

        args_label = QLabel("Arguments:")
        args_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #d4d4d4;
                margin-top: 8px;
            }
        """)
        layout.addWidget(args_label)

        self._args_text = QTextEdit()
        self._args_text.setReadOnly(True)
        self._args_text.setMinimumHeight(150)
        self._args_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ce9178;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }
        """)
        try:
            formatted_args = json.dumps(self._call.arguments, indent=2, default=str)
        except (TypeError, ValueError):
            formatted_args = str(self._call.arguments)
        self._args_text.setPlainText(formatted_args)
        layout.addWidget(self._args_text)

        warning_label = QLabel("This operation may modify data or have side effects. Review the details above before proceeding.")
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("""
            QLabel {
                font-size: 11px;
                color: #ce9178;
                padding: 8px;
                background-color: #332200;
                border-radius: 4px;
            }
        """)
        layout.addWidget(warning_label)

        self._remember_checkbox = QCheckBox("Remember for similar operations this session")
        self._remember_checkbox.setStyleSheet("""
            QCheckBox {
                color: #d4d4d4;
                font-size: 11px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """)
        layout.addWidget(self._remember_checkbox)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        button_layout.addStretch()

        deny_btn = QPushButton("Deny")
        deny_btn.setMinimumWidth(100)
        deny_btn.setStyleSheet("""
            QPushButton {
                background-color: #6e2e2e;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e3e3e;
            }
            QPushButton:pressed {
                background-color: #5e2e2e;
            }
        """)
        deny_btn.clicked.connect(self._on_deny)
        button_layout.addWidget(deny_btn)

        approve_btn = QPushButton("Approve")
        approve_btn.setMinimumWidth(100)
        approve_btn.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #0d5a8c;
            }
        """)
        approve_btn.clicked.connect(self._on_approve)
        approve_btn.setDefault(True)
        button_layout.addWidget(approve_btn)

        layout.addLayout(button_layout)

        self.setStyleSheet("""
            QDialog {
                background-color: #2d2d30;
            }
        """)

    def _on_approve(self) -> None:
        """Handle approve button click."""
        self._approved = True
        self._remember_similar = self._remember_checkbox.isChecked()
        _logger.info(
            "tool_call_approved",
            extra={
                "tool": self._call.tool_name,
                "function": self._call.function_name,
                "remember": self._remember_similar,
            },
        )
        self.accept()

    def _on_deny(self) -> None:
        """Handle deny button click."""
        self._approved = False
        self._remember_similar = self._remember_checkbox.isChecked()
        _logger.info(
            "tool_call_denied",
            extra={
                "tool": self._call.tool_name,
                "function": self._call.function_name,
                "remember": self._remember_similar,
            },
        )
        self.reject()
