# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 33: MCP Settings shows each server's own log messages and sets the level it is asked for.

The gate runs the real settings dialog over a real connection manager and a real ``MCPServer`` that logs from inside a tool. The
selected server's messages are shown beside its captured stderr and follow new ones as they arrive; choosing a level in the dialog
applies it to the running server at once and is saved with the configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtWidgets import QComboBox, QDialogButtonBox, QListView, QPlainTextEdit, QWidget

from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore
from intellicrack.mcp.server_logs import McpServerLogBook
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from tests._helpers.mcp_features_server import CHATTER_TOOL
from tests._helpers.mcp_features_support import Era, approve_every_launch, features_config, private_resolver


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.config import McpServerConfig


_BRIDGE_TIMEOUT_S: Final[float] = 60.0
_WAIT_MS: Final[int] = 20_000


def _manager(tmp_path: Path, book: McpServerLogBook) -> McpConnectionManager:
    """Build a manager over the fixture server, asking it for ``info`` and up, whose logging goes to a log book.

    Args:
        tmp_path: Per-test directory.
        book: The log book.

    Returns:
        McpConnectionManager: The manager, its configuration loaded.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=(features_config(Era.MODERN, log_level="info"),)))

    def hooks(config: McpServerConfig) -> McpClientHooks:
        """Offer logging through the log book.

        Args:
            config: The server.

        Returns:
            McpClientHooks: The hooks.
        """
        return McpClientHooks(logging=book.callback_for(config.server_id))

    gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), approve_every_launch)
    manager = McpConnectionManager(store, private_resolver(tmp_path), gate, hooks_factory=hooks)
    _ = manager.reload()
    return manager


def _open(manager: McpConnectionManager, tmp_path: Path, parent: QWidget, book: McpServerLogBook) -> McpConfigDialog:
    """Open the settings dialog with the fixture server selected.

    Args:
        manager: The manager.
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        book: The log book.

    Returns:
        McpConfigDialog: The dialog.
    """
    resolver = private_resolver(tmp_path)
    dialog = McpConfigDialog(manager, resolver, parent, approvals=ApprovalStore(tmp_path / "approvals.json"), log_book=book)
    dialog.show()
    view = dialog.findChild(QListView, "mcp_server_list")
    assert view is not None
    model = view.model()
    assert model is not None
    view.setCurrentIndex(model.index(0, 0))
    return dialog


def _save(dialog: McpConfigDialog) -> None:
    """Press Save.

    Args:
        dialog: The dialog.
    """
    box = dialog.findChild(QDialogButtonBox)
    assert box is not None
    save = box.button(QDialogButtonBox.StandardButton.Save)
    assert save is not None
    save.click()


def test_settings_show_server_logs_and_set_their_level(qtbot: QtBot, tmp_path: Path) -> None:
    """The dialog lists the server's messages, follows new ones, and applies and saves a chosen level.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
    """
    book = McpServerLogBook()
    manager = _manager(tmp_path, book)
    _ = run_bridge_coroutine(manager.start_server("features"), timeout_s=_BRIDGE_TIMEOUT_S)
    connection = manager.connection("features")
    assert connection is not None
    parent = QWidget()
    qtbot.addWidget(parent)
    try:
        _ = run_bridge_coroutine(connection.call_tool(CHATTER_TOOL, {"count": 1}), timeout_s=_BRIDGE_TIMEOUT_S)
        qtbot.waitUntil(lambda: len(book.records("features")) == len(("info", "warning", "error")), timeout=_WAIT_MS)

        dialog = _open(manager, tmp_path, parent, book)
        server_log = dialog.findChild(QPlainTextEdit, "mcp_server_log_view")
        combo = dialog.findChild(QComboBox, "mcp_log_level_combo")
        assert server_log is not None
        assert combo is not None
        qtbot.waitUntil(lambda: "WARNING [fixture] warning 0" in server_log.toPlainText(), timeout=_WAIT_MS)
        assert "DEBUG" not in server_log.toPlainText()
        assert combo.currentData() == "info"

        combo.setCurrentIndex(combo.findData("error"))
        qtbot.waitUntil(lambda: connection.log_level == "error", timeout=_WAIT_MS)
        _ = run_bridge_coroutine(connection.call_tool(CHATTER_TOOL, {"count": 1}), timeout_s=_BRIDGE_TIMEOUT_S)
        qtbot.waitUntil(lambda: server_log.toPlainText().count("ERROR [fixture]") == len(("before", "after")), timeout=_WAIT_MS)
        assert server_log.toPlainText().count("WARNING [fixture]") == 1

        _save(dialog)
        saved = McpConfigStore(tmp_path / "mcp.json").load().servers
        assert [config.log_level for config in saved] == ["error"]
        dialog.close()
    finally:
        _ = run_bridge_coroutine(manager.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
