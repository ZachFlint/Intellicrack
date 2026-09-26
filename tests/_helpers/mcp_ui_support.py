# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Support for driving the real MCP dialogs from the UI gates.

The MCP dialogs are modal: once one is executing, the test's own code does not
run again until it closes. :class:`DialogWatcher` is how a gate still acts on
one -- it polls from a Qt timer, which fires inside the dialog's nested event
loop, finds each newly visible dialog of the class it watches, and hands it to
the gate's action exactly as an operator's click would reach it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtWidgets import QApplication, QDialog

from intellicrack.mcp.config import McpServerConfig, McpTransportKind, StdioServerSpec


if TYPE_CHECKING:
    from collections.abc import Callable


INTERACTIVE_SERVER_SCRIPT = Path(__file__).resolve().parent / "mcp_interactive_server.py"
"""The interactive fixture server, run as a real stdio subprocess."""

_POLL_INTERVAL_MS = 50


def interactive_server_config(server_id: str, *, enabled: bool = True, timeout_s: float = 30.0) -> McpServerConfig:
    """Build a stdio configuration pointed at the interactive fixture server.

    Args:
        server_id: Identifier for the server.
        enabled: Whether the server is switched on.
        timeout_s: Per-call timeout.

    Returns:
        McpServerConfig: The configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(INTERACTIVE_SERVER_SCRIPT),))
    return McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=spec, enabled=enabled, request_timeout_s=timeout_s)


class DialogWatcher(QObject):
    """Acts once on every dialog of one class that becomes visible."""

    def __init__(self, kind: type[QDialog], action: Callable[[QDialog], None]) -> None:
        """Start watching.

        Args:
            kind: The dialog class to watch for.
            action: Called with each newly visible dialog of that class.
        """
        super().__init__()
        self._kind = kind
        self._action = action
        self.seen: list[QDialog] = []
        self._timer = QTimer(self)
        self._timer.setInterval(_POLL_INTERVAL_MS)
        _ = self._timer.timeout.connect(self._poll)
        self._timer.start()

    def _poll(self) -> None:
        """Hand every newly visible dialog to the action."""
        for widget in QApplication.allWidgets():
            if isinstance(widget, self._kind) and widget.isVisible() and widget not in self.seen:
                self.seen.append(widget)
                self._action(widget)

    def visible(self) -> list[QDialog]:
        """List the watched dialogs currently on screen.

        Returns:
            list[QDialog]: The visible dialogs of the watched class.
        """
        return [widget for widget in QApplication.allWidgets() if isinstance(widget, self._kind) and widget.isVisible()]

    def stop(self) -> None:
        """Stop watching."""
        self._timer.stop()
