# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Consent dialog shown before a local Model Context Protocol server is started.

A configured server is a program on the operator's machine that Intellicrack is about to run with their own account and their own
privileges. This dialog is the last point at which they can say no, so it shows them exactly what will run: the command, every argument in
full, the working directory, and the names of the environment entries it will receive.

Nothing here is truncated, elided, or reflowed away. A long argument is the one most worth reading, and an argument the operator cannot see
is one they cannot refuse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.mcp.consent import describe_launch, scan_command_for_dangerous_patterns
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Sequence

    from PyQt6.QtGui import QTextDocument

    from intellicrack.mcp.config import McpServerConfig
    from intellicrack.mcp.consent import DangerousPattern


_logger = get_logger(__name__)


_DIALOG_WIDTH: Final[int] = 780
_DIALOG_HEIGHT: Final[int] = 620
_COMMAND_VIEW_MIN_HEIGHT: Final[int] = 340
_BUTTON_MIN_WIDTH: Final[int] = 120
_CODE_FONT_POINT_SIZE: Final[int] = 9

_FLAG_BACKGROUND: Final[QColor] = QColor(255, 176, 0, 96)
"""Amber wash behind a flagged fragment.

Alpha-blended so it reads against both the light and the dark theme without the dialog having to know which one is active.
"""


class _DangerousPatternHighlighter(QSyntaxHighlighter):
    """Marks the fragments the consent scan flagged, wherever they appear.

    The rendered description already lists the findings at the end. Painting them in the command itself is what stops a flagged argument
    from being read past in a wall of monospace text.
    """

    def __init__(self, document: QTextDocument | None, patterns: Sequence[DangerousPattern]) -> None:
        """Initialize the highlighter.

        Args:
            document: The document to highlight.
            patterns: The findings from the consent scan.
        """
        super().__init__(document)
        self._tokens = sorted({pattern.token for pattern in patterns if pattern.token.strip()}, key=len, reverse=True)
        self._format = QTextCharFormat()
        self._format.setBackground(_FLAG_BACKGROUND)
        self._format.setFontWeight(700)

    @override
    def highlightBlock(self, text: str | None) -> None:
        """Paint every flagged fragment found in one line.

        Args:
            text: The line being highlighted, or ``None``.
        """
        if not text:
            return
        for token in self._tokens:
            start = text.find(token)
            while start >= 0:
                self.setFormat(start, len(token), self._format)
                start = text.find(token, start + len(token))


class McpServerConsentDialog(QDialog):
    """Asks the operator to approve launching one local MCP server.

    Emits ``decision_made(approved: bool, trusted: bool)`` when answered.
    ``trusted`` reports the "trust this server" checkbox, which is a separate
    and stronger grant than approving the launch: it decides whether the
    server's own claims about its tools are believed during classification,
    so it is off by default and stays off unless the operator ticks it.
    """

    decision_made = pyqtSignal(bool, bool)

    def __init__(
        self,
        config: McpServerConfig,
        description: str,
        findings: Sequence[DangerousPattern],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the consent dialog.

        Args:
            config: The server about to be launched.
            description: The rendered launch description, from
                :func:`~intellicrack.mcp.consent.describe_launch`.
            findings: Patterns the consent scan flagged.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._description = description
        self._findings = list(findings)
        self._approved = False
        self._trusted = False
        _logger.info(
            "mcp_consent_dialog_opened",
            server_id=config.server_id,
            finding_count=len(self._findings),
        )
        self._setup_ui()

    @classmethod
    def for_config(
        cls,
        config: McpServerConfig,
        env: dict[str, str],
        parent: QWidget | None = None,
    ) -> McpServerConsentDialog:
        """Build a dialog by rendering the launch description itself.

        Args:
            config: The server about to be launched.
            env: The fully resolved environment the child would receive.
            parent: Parent widget.

        Returns:
            McpServerConsentDialog: The dialog, ready to execute.

        Raises:
            ValueError: If the server has no launch description, which means
                it is not a local server and needs no launch consent.
        """
        if config.stdio is None:
            message = f"server '{config.server_id}' is not a local server"
            raise ValueError(message)
        return cls(
            config,
            describe_launch(config.stdio, env),
            scan_command_for_dangerous_patterns(config.stdio.command, config.stdio.args),
            parent,
        )

    @property
    def approved(self) -> bool:
        """Whether the operator approved the launch.

        Returns:
            bool: ``True`` when approved.
        """
        return self._approved

    @property
    def trusted(self) -> bool:
        """Whether the operator also marked the server trusted.

        Returns:
            bool: ``True`` when the trust checkbox was ticked.
        """
        return self._trusted

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle(f"Start MCP server '{self._config.server_id}'?")
        self.setMinimumSize(_DIALOG_WIDTH, _DIALOG_HEIGHT)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header = QLabel(f"Intellicrack wants to start the MCP server '{self._config.server_id}'.")
        header.setObjectName("mcp_consent_header")
        header.setWordWrap(True)
        layout.addWidget(header)

        if self._findings:
            warning = QLabel(
                f"{len(self._findings)} part(s) of this command matched Intellicrack's list of risky patterns. They are highlighted below.",
            )
            warning.setObjectName("mcp_consent_warning")
            warning.setWordWrap(True)
            layout.addWidget(warning)

        self._command_view = QPlainTextEdit()
        self._command_view.setObjectName("mcp_consent_command")
        self._command_view.setReadOnly(True)
        self._command_view.setMinimumHeight(_COMMAND_VIEW_MIN_HEIGHT)
        self._command_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._command_view.setFont(FontManager.get_instance().get_code_font(_CODE_FONT_POINT_SIZE))
        self._command_view.setPlainText(self._description)
        self._highlighter = _DangerousPatternHighlighter(self._command_view.document(), self._findings)
        layout.addWidget(self._command_view)

        self._trust_checkbox = QCheckBox(
            "Trust this server: believe what it says about its own tools, so tools it marks read-only skip confirmation",
        )
        self._trust_checkbox.setObjectName("mcp_consent_trust")
        self._trust_checkbox.setChecked(False)
        layout.addWidget(self._trust_checkbox)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)
        button_layout.addStretch()

        cancel_button = QPushButton("Cancel")
        cancel_button.setObjectName("mcp_consent_cancel")
        cancel_button.setMinimumWidth(_BUTTON_MIN_WIDTH)
        cancel_button.clicked.connect(self._on_cancel)
        cancel_button.setDefault(True)
        button_layout.addWidget(cancel_button)

        approve_button = QPushButton("Start server")
        approve_button.setObjectName("mcp_consent_approve")
        approve_button.setMinimumWidth(_BUTTON_MIN_WIDTH)
        approve_button.clicked.connect(self._on_approve)
        button_layout.addWidget(approve_button)

        layout.addLayout(button_layout)

    def make_decision(self, *, approved: bool) -> None:
        """Apply an answer and finalise the dialog.

        Args:
            approved: ``True`` when the operator approved the launch.
        """
        self._approved = approved
        self._trusted = approved and self._trust_checkbox.isChecked()
        if approved:
            _logger.info("mcp_consent_approved", server_id=self._config.server_id, trusted=self._trusted)
        else:
            _logger.warning("mcp_consent_refused", server_id=self._config.server_id)
        self.decision_made.emit(self._approved, self._trusted)
        if approved:
            self.accept()
        else:
            self.reject()

    def _on_approve(self) -> None:
        """Handle the start-server button."""
        self.make_decision(approved=True)

    def _on_cancel(self) -> None:
        """Handle the cancel button."""
        self.make_decision(approved=False)
