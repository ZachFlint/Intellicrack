# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 36: MCP Settings shows each server's negotiated protocol version and both sides' capabilities.

The gate runs the real settings dialog over a real connection manager and a real ``MCPServer`` on each protocol generation, with
Intellicrack offering roots and log messages. The status tab names the version the connection negotiated, what the server declared it
offers, and what Intellicrack declared to it on that version.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QDialog, QLabel, QListView, QWidget

from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore
from intellicrack.mcp.roots import McpRootSet
from intellicrack.mcp.server_logs import McpServerLogBook
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, approve_every_launch, features_config, private_resolver
from tests._helpers.mcp_http_process import running_server


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.config import McpServerConfig


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_BRIDGE_TIMEOUT_S: Final[float] = 60.0
_WAIT_MS: Final[int] = 20_000


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_status_tab_names_the_version_and_both_sides_capabilities(qtbot: QtBot, tmp_path: Path, era: Era) -> None:
    """The selected running server's status names its protocol version, its capabilities and Intellicrack's declaration.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        era: The protocol generation.
    """
    roots = McpRootSet()
    book = McpServerLogBook()

    def hooks(config: McpServerConfig) -> McpClientHooks:
        """Offer roots and log messages.

        Args:
            config: The server.

        Returns:
            McpClientHooks: The hooks.
        """
        return McpClientHooks(list_roots=roots.callback_for(config, lambda _server_id: None), logging=book.callback_for(config.server_id))

    with ExitStack() as stack:
        port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        store = McpConfigStore(tmp_path / "mcp.json")
        store.save(McpConfigDocument(servers=(features_config(era, port=port),)))
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), approve_every_launch)
        manager = McpConnectionManager(store, private_resolver(tmp_path), gate, hooks_factory=hooks)
        _ = manager.reload()
        _ = run_bridge_coroutine(manager.start_server("features"), timeout_s=_BRIDGE_TIMEOUT_S)
        parent = QWidget()
        qtbot.addWidget(parent)
        dialog = McpConfigDialog(manager, private_resolver(tmp_path), parent, approvals=ApprovalStore(tmp_path / "approvals.json"))
        try:
            dialog.show()
            view = dialog.findChild(QListView, "mcp_server_list")
            assert view is not None
            model = view.model()
            assert model is not None
            view.setCurrentIndex(model.index(0, 0))
            label = dialog.findChild(QLabel, "mcp_status_label")
            assert label is not None
            qtbot.waitUntil(lambda: "Protocol version:" in label.text(), timeout=_WAIT_MS)
            lines = label.text().splitlines()
            assert f"Protocol version: {era.value}" in lines
            offered = "logging; prompts (listChanged); resources (subscribe, listChanged); tools (listChanged)"
            assert f"Server offers: {offered if era is Era.MODERN else 'logging; prompts; resources; tools'}" in lines
            assert f"Intellicrack declared: {'roots (listChanged)' if era is Era.LEGACY else 'roots'}" in lines
        finally:
            dialog.done(QDialog.DialogCode.Rejected.value)
            _ = run_bridge_coroutine(manager.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
