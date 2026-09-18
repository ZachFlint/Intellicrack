# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool confirmation dialog for Intellicrack.

This module provides a dialog for confirming tool calls before execution, allowing users to review and approve or deny potentially
destructive operations.

A remembered answer is keyed by ``(tool_name, function_name, generation)``.
The generation is what makes the answer honest for an externally-sourced tool:
a third-party server can change what a tool does between one turn and the
next, so an answer given about the old definition must not silently carry over
to the new one. Bridge tools ship with the application and carry no
generation, so their answers are keyed on the pair alone exactly as before.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.mcp.consent import ApprovalScope


if TYPE_CHECKING:
    from intellicrack.core.types import ToolCall
    from intellicrack.mcp.consent import ApprovalStore

_logger = get_logger(__name__)

_RememberKey = tuple[str, str, str | None]

_NO_GENERATION = ""


class _ApprovalStoreHolder:
    """Holder for the persistent store backing the ``always`` scope.

    Attributes:
        instance: The store every dialog writes an ``always`` answer to, or
            ``None`` when nothing has installed one, in which case the
            ``always`` option is not offered.
    """

    instance: ApprovalStore | None = None


_store_holder = _ApprovalStoreHolder()


class ToolConfirmationDialog(QDialog):
    """Dialog for confirming tool calls.

    Displays the tool name, function, originating source, and arguments for user review before executing potentially destructive
    operations.

    Emits ``decision_made(approved: bool, remember_similar: bool)`` when the user accepts or rejects the call. Callers may connect to this
    signal to react to the decision instead of polling properties after ``exec()``.

    The user chooses how long their answer applies: just this once, for the
    rest of the session, or always. A session answer is cached at class scope;
    an ``always`` answer is written to the installed approval store and
    survives a restart. Either way the key carries the tool's generation, so a
    server that changes its tool definitions invalidates what was remembered
    about the old ones. Subsequent dialog instances for a remembered key
    short-circuit via :meth:`exec`: they replay the cached decision through
    ``decision_made`` and finish immediately without presenting UI.
    """

    decision_made = pyqtSignal(bool, bool)

    _remembered_decisions: ClassVar[dict[_RememberKey, bool]] = {}

    def __init__(
        self,
        call: ToolCall,
        parent: QWidget | None = None,
        *,
        generation: str | None = None,
        source_label: str | None = None,
    ) -> None:
        """Initialize the ToolConfirmationDialog with the given tool call.

        Args:
            call: The tool call to confirm.
            parent: Parent widget.
            generation: Digest of the source's current tool definitions, for
                an externally-sourced tool. ``None`` for a bridge tool.
            source_label: Human-readable origin of the tool, e.g.
                ``"MCP server 'files'"``. ``None`` for a bridge tool.
        """
        super().__init__(parent)
        self._call = call
        self._generation = generation
        self._source_label = source_label
        self._approved = False
        self._remember_similar = False
        self._scope = ApprovalScope.ONCE
        _logger.debug(
            "tool_confirmation_dialog_opened",
            tool=call.tool_name,
            function=call.function_name,
            generation=generation,
        )
        self._setup_ui()

    @classmethod
    def set_approval_store(cls, store: ApprovalStore | None) -> None:
        """Install the store that persists ``always`` answers.

        Until one is installed the dialog does not offer ``always`` at all,
        rather than offering it and quietly downgrading the answer to a
        session-scoped one.

        Args:
            store: The store to write persistent answers to, or ``None`` to
                remove the current one.
        """
        _store_holder.instance = store

    @staticmethod
    def _generation_key(generation: str | None) -> str | None:
        """Normalize a generation into its remembered-key component.

        Args:
            generation: The source's generation, or ``None``.

        Returns:
            str | None: The generation, or ``None`` for a source that has none.
        """
        return generation or None

    @classmethod
    def remembered_decision(cls, call: ToolCall, generation: str | None = None) -> bool | None:
        """Return the remembered decision for ``call``, if any.

        The session cache is consulted first, then the persistent store.

        Args:
            call: The tool call to look up.
            generation: Digest of the source's current tool definitions, or
                ``None`` for a bridge tool.

        Returns:
            bool | None: ``True`` for remembered approval, ``False`` for
            remembered denial, or ``None`` when no decision is cached for the
            ``(tool_name, function_name, generation)`` triple.
        """
        key = cls._generation_key(generation)
        cached = cls._remembered_decisions.get((call.tool_name, call.function_name, key))
        if cached is not None:
            return cached
        store = _store_holder.instance
        if store is None:
            return None
        return store.decision(call.tool_name, call.function_name, key or _NO_GENERATION)

    @classmethod
    def clear_remembered_decisions(cls) -> None:
        """Clear all session-remembered decisions.

        Intended for end-of-session teardown and test isolation. Persistent ``always`` answers are left alone, which is what makes them
        persistent.
        """
        cls._remembered_decisions.clear()
        store = _store_holder.instance
        if store is not None:
            store.clear_session()

    @classmethod
    def clear_decisions_for_source(cls, namespace: str) -> None:
        """Forget every decision remembered for one tool source.

        Called when a source's tool definitions change, so an answer given
        about the previous definitions is never replayed against the new ones.

        Args:
            namespace: The source's tool namespace, e.g. ``mcp-files``.
        """
        for key in [key for key in cls._remembered_decisions if key[0] == namespace]:
            del cls._remembered_decisions[key]
        store = _store_holder.instance
        if store is not None:
            store.invalidate_namespace(namespace)
        _logger.info("tool_decisions_cleared_for_source", namespace=namespace)

    @classmethod
    def store_decision(
        cls,
        call: ToolCall,
        *,
        approved: bool,
        generation: str | None = None,
        scope: ApprovalScope = ApprovalScope.SESSION,
    ) -> None:
        """Persist a remembered decision for the requested duration.

        Args:
            call: The tool call whose decision is being remembered.
            approved: ``True`` if the user approved, ``False`` if denied.
            generation: Digest of the source's current tool definitions, or
                ``None`` for a bridge tool.
            scope: How long the answer applies. ``ONCE`` records nothing.
        """
        if scope is ApprovalScope.ONCE:
            return
        key = cls._generation_key(generation)
        cls._remembered_decisions[call.tool_name, call.function_name, key] = approved
        if scope is not ApprovalScope.ALWAYS:
            return
        store = _store_holder.instance
        if store is None:
            _logger.warning("tool_decision_not_persisted", tool=call.tool_name, function=call.function_name)
            return
        store.remember(
            call.tool_name,
            call.function_name,
            key or _NO_GENERATION,
            approved=approved,
            scope=ApprovalScope.ALWAYS,
        )

    @property
    def approved(self) -> bool:
        """Whether the call was approved.

        Returns:
            bool: True if user approved, False otherwise.
        """
        return self._approved

    @property
    def remember_similar(self) -> bool:
        """Whether to remember the choice for similar operations.

        Returns:
            bool: True if the chosen scope outlives this single call.
        """
        return self._remember_similar

    @property
    def scope(self) -> ApprovalScope:
        """How long the user's answer applies.

        Returns:
            ApprovalScope: The scope the user selected.
        """
        return self._scope

    def _build_scope_group(self) -> QGroupBox:
        """Build the approval-scope selector.

        Returns:
            QGroupBox: The group box holding the scope radio buttons.
        """
        group = QGroupBox("Apply this answer to")
        group.setObjectName("confirm_scope_group")
        layout = QVBoxLayout(group)

        self._scope_buttons = QButtonGroup(self)
        self._once_button = QRadioButton("Just this call")
        self._once_button.setObjectName("confirm_scope_once")
        self._once_button.setChecked(True)
        self._scope_buttons.addButton(self._once_button)
        layout.addWidget(self._once_button)

        self._session_button = QRadioButton("Every similar call for the rest of this session")
        self._session_button.setObjectName("confirm_scope_session")
        self._scope_buttons.addButton(self._session_button)
        layout.addWidget(self._session_button)

        self._always_button = QRadioButton("Always, including after Intellicrack restarts")
        self._always_button.setObjectName("confirm_scope_always")
        self._always_button.setEnabled(_store_holder.instance is not None)
        if self._generation is not None:
            self._always_button.setToolTip(
                "Forgotten automatically if this server changes what its tools do.",
            )
        self._scope_buttons.addButton(self._always_button)
        layout.addWidget(self._always_button)

        return group

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle("Confirm Tool Call")
        self.setMinimumSize(560, 480)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        header_label = QLabel("AI wants to execute the following tool:")
        header_label.setObjectName("confirm_header")
        layout.addWidget(header_label)

        tool_label = QLabel(f"{self._call.tool_name}.{self._call.function_name}")
        tool_label.setObjectName("confirm_tool")
        layout.addWidget(tool_label)

        if self._source_label:
            source_label = QLabel(f"Provided by {self._source_label}")
            source_label.setObjectName("confirm_source")
            source_label.setWordWrap(True)
            layout.addWidget(source_label)

        args_label = QLabel("Arguments:")
        args_label.setObjectName("confirm_args_label")
        layout.addWidget(args_label)

        self._args_text = QTextEdit()
        self._args_text.setObjectName("confirm_args_text")
        self._args_text.setReadOnly(True)
        self._args_text.setMinimumHeight(150)
        self._args_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        try:
            formatted_args = json.dumps(self._call.arguments, indent=2, default=str)
        except (TypeError, ValueError):
            _logger.debug(
                "tool_call_args_format_failed",
                tool=self._call.tool_name,
                function=self._call.function_name,
            )
            formatted_args = str(self._call.arguments)
        self._args_text.setPlainText(formatted_args)
        layout.addWidget(self._args_text)

        warning_label = QLabel("This operation may modify data or have side effects. Review the details above before proceeding.")
        warning_label.setObjectName("confirm_warning")
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)

        layout.addWidget(self._build_scope_group())

        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        button_layout.addStretch()

        deny_btn = QPushButton("Deny")
        deny_btn.setObjectName("confirm_deny_button")
        deny_btn.setMinimumWidth(100)
        deny_btn.clicked.connect(self._on_deny)
        button_layout.addWidget(deny_btn)

        approve_btn = QPushButton("Approve")
        approve_btn.setObjectName("confirm_approve_button")
        approve_btn.setMinimumWidth(100)
        approve_btn.clicked.connect(self._on_approve)
        approve_btn.setDefault(True)
        button_layout.addWidget(approve_btn)

        layout.addLayout(button_layout)

    def exec(self) -> int:
        """Show the dialog modally, honoring any remembered decision.

        If the user previously approved or denied this ``(tool_name,
        function_name, generation)`` triple with a scope that outlives the
        call, no UI is shown: the cached decision is replayed via the
        ``decision_made`` signal and the dialog finishes immediately with the
        same accepted/rejected result code as a normal execution.

        Returns:
            int: ``QDialog.DialogCode.Accepted`` on approval, otherwise
            ``QDialog.DialogCode.Rejected``.
        """
        cached = self.remembered_decision(self._call, self._generation)
        if cached is None:
            return super().exec()
        self._approved = cached
        self._remember_similar = True
        self._scope = ApprovalScope.SESSION
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
        """Set the session-scope option programmatically.

        Args:
            value: ``True`` to remember the answer for this session,
                ``False`` to apply it to this call only.
        """
        if value:
            self._session_button.setChecked(True)
        else:
            self._once_button.setChecked(True)

    def set_scope(self, scope: ApprovalScope) -> None:
        """Select an approval scope programmatically.

        Args:
            scope: The scope to select. ``ALWAYS`` is ignored when no
                persistent store is installed, since nothing could honour it.
        """
        if scope is ApprovalScope.ALWAYS and _store_holder.instance is not None:
            self._always_button.setChecked(True)
        elif scope is ApprovalScope.SESSION:
            self._session_button.setChecked(True)
        else:
            self._once_button.setChecked(True)

    def _selected_scope(self) -> ApprovalScope:
        """Read the scope the user selected.

        Returns:
            ApprovalScope: The selected scope.
        """
        if self._always_button.isChecked():
            return ApprovalScope.ALWAYS
        if self._session_button.isChecked():
            return ApprovalScope.SESSION
        return ApprovalScope.ONCE

    def make_decision(self, *, approved: bool) -> None:
        """Apply an approve/deny decision and emit the corresponding signal.

        This is the single entry point used by both the Approve and Deny
        button slots. It captures the selected scope, persists the answer for
        that scope, emits ``decision_made``, and finalises the dialog with
        ``accept()`` or ``reject()``.

        Args:
            approved: ``True`` when the user approved the call, ``False`` when
                the user denied it.
        """
        self._approved = approved
        self._scope = self._selected_scope()
        self._remember_similar = self._scope is not ApprovalScope.ONCE
        if self._remember_similar:
            self.store_decision(self._call, approved=approved, generation=self._generation, scope=self._scope)
        if approved:
            _logger.info(
                "tool_call_approved",
                tool=self._call.tool_name,
                function=self._call.function_name,
                remember=self._remember_similar,
                scope=self._scope.value,
            )
        else:
            _logger.warning(
                "tool_call_denied",
                tool=self._call.tool_name,
                function=self._call.function_name,
                remember=self._remember_similar,
                scope=self._scope.value,
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
            remember: Whether the decision should be remembered beyond this call.
        """
        self.decision_made.emit(approved, remember)
