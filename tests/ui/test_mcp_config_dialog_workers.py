# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the MCP settings dialog's background-worker lifetime.

A ``QThread`` destroyed while its OS thread is still running aborts the
process. That defect shipped once already in the provider settings dialog and
took CI's test job down with it, so every way this dialog can be dismissed has
to let go of a running worker rather than destroy it.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeyEvent
from PyQt6.QtWidgets import QWidget

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigStore
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.panels.async_bridge import worker_is_running


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_WORKER_SECONDS = 20.0


def _dialog(tmp_path: Path, parent: QWidget) -> McpConfigDialog:
    """Build the settings dialog over real, empty stores.

    Args:
        tmp_path: Directory backing the configuration and trust stores.
        parent: Parent widget owning the dialog.

    Returns:
        McpConfigDialog: A constructed dialog with no servers configured.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    trust = TrustStore(tmp_path / "trust.json")

    def prompt(_config: object, _rendered: str, _findings: object) -> bool:
        """Refuse every launch; no server is started by these gates.

        Args:
            _config: The server being launched.
            _rendered: The rendered launch description.
            _findings: Dangerous patterns found in the command.

        Returns:
            bool: Always ``False``.
        """
        return False

    resolver = McpSecretResolver(CredentialStore())
    manager = McpConnectionManager(store, resolver, McpConsentGate(trust, prompt))
    return McpConfigDialog(manager, resolver, parent)


async def _slow_work() -> str:
    """Occupy a worker for longer than the dialog will be open.

    Returns:
        str: Never observed by these gates.
    """
    await asyncio.sleep(_WORKER_SECONDS)
    return "done"


class TestWorkerLifetimeOnDismissal:
    """Every dismissal path lets go of a running worker."""

    @pytest.fixture
    def parent(self, qtbot: QtBot) -> QWidget:
        """Provide a parent widget registered with the bot.

        Args:
            qtbot: pytest-qt bot.

        Returns:
            QWidget: A parent widget.
        """
        widget = QWidget()
        qtbot.addWidget(widget)
        return widget

    def test_close_releases_a_running_worker(self, tmp_path: Path, parent: QWidget) -> None:
        """Closing the dialog detaches a worker that is still running.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        dialog = _dialog(tmp_path, parent)
        dialog._start_worker(_slow_work(), lambda _result: None, lambda _error: None)
        assert len(dialog._workers) == 1
        worker = dialog._workers[0]

        dialog.close()

        assert dialog._workers == [], "the dialog still holds a worker after closing"
        if worker_is_running(worker):
            assert worker.parent() is None, "a running worker was left parented to a closed dialog"

    def test_reject_releases_a_running_worker(self, tmp_path: Path, parent: QWidget) -> None:
        """Rejecting the dialog detaches a worker that is still running.

        ``QDialog.reject`` routes through ``done``, which hides the dialog
        without sending a close event, so a dialog that only cleans up in
        ``closeEvent`` still holds a live thread here.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        dialog = _dialog(tmp_path, parent)
        dialog._start_worker(_slow_work(), lambda _result: None, lambda _error: None)
        assert len(dialog._workers) == 1

        dialog.reject()

        assert dialog._workers == [], "reject() left a running worker attached to the dialog"

    def test_escape_key_releases_a_running_worker(self, tmp_path: Path, parent: QWidget) -> None:
        """Pressing Escape detaches a worker that is still running.

        Escape is the dismissal a user reaches for without thinking, and Qt
        wires it straight to ``reject``.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        dialog = _dialog(tmp_path, parent)
        dialog._start_worker(_slow_work(), lambda _result: None, lambda _error: None)
        assert len(dialog._workers) == 1

        event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)
        dialog.keyPressEvent(event)

        assert dialog._workers == [], "Escape left a running worker attached to the dialog"
