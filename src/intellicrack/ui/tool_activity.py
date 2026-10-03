# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The tool calls running now, shown beside the conversation with their progress and a way to cancel each one.

A row appears when a call starts, follows the progress the call reports -- a bar filling towards the total when the tool gives one, a
busy bar when it does not, and the tool's own message, already cleaned -- and disappears when the call's result arrives. Cancel asks
for that one call to be stopped; the turn goes on with the call ending as cancelled. The panel is hidden while nothing is running.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.tool_progress import ToolProgress
    from intellicrack.core.types import ToolCall, ToolResult


_PERCENT: Final[int] = 100

_ROW_PROPERTY: Final[str] = "toolActivityRow"
"""Dynamic property the theme stylesheets match to style a running-call row.

Each row's object name embeds its call id, so the rows are styled by this shared property rather than by name.
"""


class _RunningCallRow(QFrame):
    """One running call: its name, its progress and a Cancel button."""

    def __init__(self, call: ToolCall, on_cancel: Callable[[str], None], parent: QWidget | None = None) -> None:
        """Build the row for one call.

        Args:
            call: The call.
            on_cancel: Called with the call's id when Cancel is pressed.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setObjectName(f"tool_activity_row_{call.id}")
        self.setProperty(_ROW_PROPERTY, "true")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        top = QHBoxLayout()
        self.title = QLabel(f"Running {call.function_name}")
        self.title.setObjectName("tool_activity_title")
        top.addWidget(self.title, 1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("tool_activity_cancel")
        self.cancel_button.setToolTip("Stop this call; the model is told it was cancelled and the turn goes on.")
        call_id = call.id

        def _cancel() -> None:
            """Ask for this call to be cancelled."""
            self.cancel_button.setEnabled(False)
            self.cancel_button.setText("Cancelling...")
            on_cancel(call_id)

        self.cancel_button.clicked.connect(_cancel)
        top.addWidget(self.cancel_button)
        layout.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setObjectName("tool_activity_bar")
        self.bar.setRange(0, 0)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar)
        self.message = QLabel("")
        self.message.setObjectName("tool_activity_message")
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

    def show_progress(self, progress: ToolProgress) -> None:
        """Show how far the call has got.

        Args:
            progress: The latest report.
        """
        fraction = progress.fraction
        if fraction is None:
            self.bar.setRange(0, 0)
        else:
            self.bar.setRange(0, _PERCENT)
            self.bar.setValue(round(fraction * _PERCENT))
        self.message.setText(progress.describe())


class ToolActivityPanel(QFrame):
    """Lists the tool calls running now.

    Emits ``cancel_requested(call_id)`` when the operator cancels a call.
    """

    cancel_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Build an empty, hidden panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setObjectName("tool_activity")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(2)
        self._rows: dict[str, _RunningCallRow] = {}
        self.setVisible(False)

    def started(self, call: ToolCall) -> None:
        """Add a row for a call that has started.

        Args:
            call: The call.
        """
        if call.id in self._rows:
            return
        row = _RunningCallRow(call, self.cancel_requested.emit, self)
        self._rows[call.id] = row
        self._layout.addWidget(row)
        self.setVisible(True)

    def progressed(self, progress: ToolProgress) -> None:
        """Show a running call's latest progress.

        Args:
            progress: The report.
        """
        row = self._rows.get(progress.call_id)
        if row is not None:
            row.show_progress(progress)

    def finished(self, result: ToolResult) -> None:
        """Remove the row of a call whose result has arrived.

        Args:
            result: The call's result.
        """
        row = self._rows.pop(result.call_id, None)
        if row is None:
            return
        self._layout.removeWidget(row)
        row.deleteLater()
        self.setVisible(bool(self._rows))

    def clear(self) -> None:
        """Remove every row, as when the turn ends."""
        for row in self._rows.values():
            self._layout.removeWidget(row)
            row.deleteLater()
        self._rows.clear()
        self.setVisible(False)

    @property
    def running(self) -> list[str]:
        """The ids of the calls shown as running.

        Returns:
            list[str]: The call ids.
        """
        return list(self._rows)
