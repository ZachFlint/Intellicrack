# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool confirmation dialog for Intellicrack.

This module provides a dialog for confirming tool calls before execution, allowing users to review and approve or deny potentially
destructive operations.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from PyQt6.QtCore import pyqtSignal
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

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import ToolCall

_logger = get_logger(__name__)

_RememberKey = tuple[str, str]


class ToolConfirmationDialog(QDialog):
    """Dialog for confirming tool calls.

    Displays the tool name, function, and arguments for user review before executing potentially destructive operations.

    Emits ``decision_made(approved: bool, remember_similar: bool)`` when the user accepts or rejects the call. Callers may connect to this
    signal to react to the decision instead of polling properties after ``exec()``.

    When the user checks "Remember for similar operations this session", the decision is cached at class scope keyed by ``(tool_name,
    function_name)``. Subsequent dialog instances for the same tool/function pair short-circuit via :meth:`exec`: they replay the cached
    decision through ``decision_made`` and finish immediately without presenting UI.
    """

    decision_made = pyqtSignal(bool, bool)

    _remembered_decisions: ClassVar[dict[_RememberKey, bool]] = {}

    def __init__(
        self,
        call: ToolCall,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the ToolConfirmationDialog with the given tool call.

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
            tool=call.tool_name,
            function=call.function_name,
        )
        self._setup_ui()

    @classmethod
    def remembered_decision(cls, call: ToolCall) -> bool | None:
        """Return the remembered decision for ``call``, if any.

        Args:
            call: The tool call to look up.

        Returns:
            bool | None: ``True`` for remembered approval, ``False`` for
            remembered denial, or ``None`` when no decision is cached for the
            ``(tool_name, function_name)`` pair.
        """
        return cls._remembered_decisions.get((call.tool_name, call.function_name))

    @classmethod
    def clear_remembered_decisions(cls) -> None:
        """Clear all session-remembered decisions.

        Intended for end-of-session teardown and test isolation.
        """
        cls._remembered_decisions.clear()

    @classmethod
    def store_decision(cls, call: ToolCall, *, approved: bool) -> None:
        """Persist a remembered decision for the session.

        Args:
            call: The tool call whose decision is being remembered.
            approved: ``True`` if the user approved, ``False`` if denied.
        """
        cls._remembered_decisions[call.tool_name, call.function_name] = approved

    @property
    def approved(self) -> bool:
        """Get whether the call was approved.

        Returns:
            bool: True if user approved, False otherwise.
        """
        return self._approved

    @property
    def remember_similar(self) -> bool:
        """Get whether to remember choice for similar operations.

        Returns:
            bool: True if user wants to remember choice.
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
        header_label.setStyleSheet(
            """
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #d4d4d4;
            }
        """
           ,
        )
        layout.addWidget(header_label)

        tool_label = QLabel(f"{self._call.tool_name}.{self._call.function_name}")
        tool_label.setStyleSheet(
            """
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #569cd6;
                padding: 8px;
                background-color: #252526;
                border-radius: 4px;
            }
        """
           ,
        )
        layout.addWidget(tool_label)

        args_label = QLabel("Arguments:")
        args_label.setStyleSheet(
            """
            QLabel {
                font-size: 12px;
                color: #d4d4d4;
                margin-top: 8px;
            }
        """
           ,
        )
        layout.addWidget(args_label)

        self._args_text = QTextEdit()
        self._args_text.setReadOnly(True)
        self._args_text.setMinimumHeight(150)
        self._args_text.setStyleSheet(
            """
            QTextEdit {
                background-color: #1e1e1e;
                color: #ce9178;
                border: 1px solid #3e3e42;
                border-radius: 4px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                padding: 8px;
            }
        """
           ,
        )
        try:
            formatted_args = json.dumps(self._call.arguments, indent=2, default=str)
        except (TypeError, ValueError):
            _logger.debug("tool_call_args_format_failed")
            formatted_args = str(self._call.arguments)
        self._args_text.setPlainText(formatted_args)
        layout.addWidget(self._args_text)

        warning_label = QLabel("This operation may modify data or have side effects. Review the details above before proceeding.")
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet(
            """
            QLabel {
                font-size: 11px;
                color: #ce9178;
                padding: 8px;
                background-color: #332200;
                border-radius: 4px;
            }
        """
           ,
        )
        layout.addWidget(warning_label)

        self._remember_checkbox = QCheckBox("Remember for similar operations this session")
        self._remember_checkbox.setStyleSheet(
            """
            QCheckBox {
                color: #d4d4d4;
                font-size: 11px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """
           ,
        )
        layout.addWidget(self._remember_checkbox)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        button_layout.addStretch()

        deny_btn = QPushButton("Deny")
        deny_btn.setMinimumWidth(100)
        deny_btn.setStyleSheet(
            """
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
        """
           ,
        )
        deny_btn.clicked.connect(self._on_deny)
        button_layout.addWidget(deny_btn)

        approve_btn = QPushButton("Approve")
        approve_btn.setMinimumWidth(100)
        approve_btn.setStyleSheet(
            """
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
        """
           ,
        )
        approve_btn.clicked.connect(self._on_approve)
        approve_btn.setDefault(True)
        button_layout.addWidget(approve_btn)

        layout.addLayout(button_layout)

        self.setStyleSheet(
            """
            QDialog {
                background-color: #2d2d30;
            }
        """
           ,
        )

    def exec(self) -> int:
        """Show the dialog modally, honoring any remembered decision.

        If the user previously approved or denied this ``(tool_name,
        function_name)`` with the "remember for similar operations" checkbox
        set, no UI is shown: the cached decision is replayed via the
        ``decision_made`` signal and the dialog finishes immediately with the
        same accepted/rejected result code as a normal execution.

        Returns:
            int: ``QDialog.DialogCode.Accepted`` on approval, otherwise
            ``QDialog.DialogCode.Rejected``.
        """
        cached = self.remembered_decision(self._call)
        if cached is None:
            return super().exec()
        self._approved = cached
        self._remember_similar = True
        result_code = QDialog.DialogCode.Accepted if cached else QDialog.DialogCode.Rejected
        self.setResult(result_code.value)
        _logger.info(
            "tool_call_decision_remembered",
            tool=self._call.tool_name,
            function=self._call.function_name,
            approved=cached,
        )
        self._emit_decision(approved=cached, remember=True)
        return result_code.value

    def set_remember_similar(self, *, value: bool) -> None:
        """Set the "remember for similar operations" checkbox programmatically.

        Args:
            value: ``True`` to enable remembering, ``False`` to disable.
        """
        self._remember_checkbox.setChecked(value)

    def make_decision(self, *, approved: bool) -> None:
        """Apply an approve/deny decision and emit the corresponding signal.

        This is the single entry point used by both the Approve and Deny
        button slots. It captures the current "remember similar" checkbox
        state, persists it to the class-level cache when set, emits
        ``decision_made``, and finalises the dialog with ``accept()`` or
        ``reject()``.

        Args:
            approved: ``True`` when the user approved the call, ``False`` when
                the user denied it.
        """
        self._approved = approved
        self._remember_similar = self._remember_checkbox.isChecked()
        if self._remember_similar:
            self.store_decision(self._call, approved=approved)
        if approved:
            _logger.info(
                "tool_call_approved",
                tool=self._call.tool_name,
                function=self._call.function_name,
                remember=self._remember_similar,
            )
        else:
            _logger.warning(
                "tool_call_denied",
                tool=self._call.tool_name,
                function=self._call.function_name,
                remember=self._remember_similar,
            )
        self._emit_decision(approved=approved, remember=self._remember_similar)
        if approved:
            self.accept()
        else:
            self.reject()

    def _on_approve(self) -> None:
        """Handle approve button click."""
        self.make_decision(approved=True)

    def _on_deny(self) -> None:
        """Handle deny button click."""
        self.make_decision(approved=False)

    def _emit_decision(self, *, approved: bool, remember: bool) -> None:
        """Emit the ``decision_made`` signal with explicit keyword semantics.

        Args:
            approved: Whether the user approved the call.
            remember: Whether the decision should be remembered for the session.
        """
        self.decision_made.emit(approved, remember)
