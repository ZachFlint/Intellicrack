# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 7: the operator can see and change a server's sandbox, and is told plainly what it does not enforce.

The gates drive the real MCP settings dialog over a real configuration file: they read what the sandbox editor shows for a configured
server, change every sandbox field through its widget, press Save, and read the file back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QCheckBox, QDialogButtonBox, QLabel, QListView, QPlainTextEdit, QWidget

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpSandboxSpec, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore, deny_all_launches
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.ui.mcp_config import SANDBOX_NETWORK_NOTICE, McpConfigDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


def _widget[W: QWidget](root: QWidget, kind: type[W], name: str) -> W:
    """Find one named widget.

    Args:
        root: The widget to search.
        kind: The widget class.
        name: The object name.

    Returns:
        W: The widget.
    """
    found = root.findChild(kind, name)
    assert found is not None, f"no {kind.__name__} named {name!r}"
    return found


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget that outlives the dialog.

    Args:
        qtbot: The Qt test driver.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


@pytest.fixture
def settings(tmp_path: Path, parent: QWidget) -> tuple[McpConfigDialog, McpConfigStore, Path]:
    """Open the settings dialog over one sandboxed server.

    Args:
        tmp_path: Per-test directory.
        parent: The dialog's parent widget.

    Returns:
        tuple[McpConfigDialog, McpConfigStore, Path]: The dialog, its configuration store and the test directory.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    sandbox = McpSandboxSpec(
        enabled=True,
        allow_write=(str(tmp_path / "work"),),
        allowed_domains=("api.example.com",),
        inherit_env=("NODE_OPTIONS",),
    )
    config = McpServerConfig(
        server_id="boxed",
        kind=McpTransportKind.STDIO,
        stdio=StdioServerSpec(command="npx", args=("-y", "@example/server")),
        sandbox=sandbox,
    )
    store.save(McpConfigDocument(servers=(config,)))
    resolver = McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
    manager = McpConnectionManager(store, resolver, McpConsentGate(TrustStore(tmp_path / "trust.json"), deny_all_launches))
    _ = manager.reload()
    dialog = McpConfigDialog(manager, resolver, parent, approvals=ApprovalStore(tmp_path / "approvals.json"))
    dialog.show()
    view = _widget(dialog, QListView, "mcp_server_list")
    model = view.model()
    assert model is not None
    view.setCurrentIndex(model.index(0, 0))
    return dialog, store, tmp_path


def test_editor_shows_the_configured_sandbox(settings: tuple[McpConfigDialog, McpConfigStore, Path]) -> None:
    """Every sandbox setting of the selected server is on screen.

    Args:
        settings: The dialog and its store.
    """
    dialog, _, root = settings

    assert _widget(dialog, QCheckBox, "mcp_sandbox_enabled").isChecked()
    assert _widget(dialog, QPlainTextEdit, "mcp_sandbox_allow_write").toPlainText() == str(root / "work")
    assert _widget(dialog, QPlainTextEdit, "mcp_sandbox_allowed_domains").toPlainText() == "api.example.com"
    assert _widget(dialog, QPlainTextEdit, "mcp_sandbox_inherit_env").toPlainText() == "NODE_OPTIONS"
    assert not _widget(dialog, QCheckBox, "mcp_sandbox_write_existing").isChecked()


def test_editor_says_allowed_domains_are_not_enforced(settings: tuple[McpConfigDialog, McpConfigStore, Path]) -> None:
    """The statement that network access is not restricted sits beside the domain list.

    Args:
        settings: The dialog and its store.
    """
    dialog, _, _ = settings

    notice = _widget(dialog, QLabel, "mcp_sandbox_network_notice")
    assert notice.text() == SANDBOX_NETWORK_NOTICE
    assert notice.text().startswith("Not enforced.")
    assert "can still connect to any host" in notice.text()


def test_sandbox_edits_are_saved(settings: tuple[McpConfigDialog, McpConfigStore, Path]) -> None:
    """Changing each sandbox field and pressing Save writes exactly those settings.

    Args:
        settings: The dialog and its store.
    """
    dialog, store, root = settings

    _widget(dialog, QPlainTextEdit, "mcp_sandbox_allow_write").setPlainText(f"{root / 'work'}\n{root / 'scratch'}\n")
    _widget(dialog, QPlainTextEdit, "mcp_sandbox_allowed_domains").setPlainText("registry.npmjs.org")
    _widget(dialog, QPlainTextEdit, "mcp_sandbox_inherit_env").setPlainText("NODE_OPTIONS\nHTTPS_PROXY")
    _widget(dialog, QCheckBox, "mcp_sandbox_write_existing").setChecked(True)
    box = dialog.findChild(QDialogButtonBox)
    assert box is not None
    save = box.button(QDialogButtonBox.StandardButton.Save)
    assert save is not None
    save.click()

    saved = store.load().server("boxed")
    assert saved is not None
    assert saved.sandbox == McpSandboxSpec(
        enabled=True,
        allow_write=(str(root / "work"), str(root / "scratch")),
        allowed_domains=("registry.npmjs.org",),
        inherit_env=("NODE_OPTIONS", "HTTPS_PROXY"),
        write_existing=True,
    )


def test_turning_the_sandbox_off_is_saved(settings: tuple[McpConfigDialog, McpConfigStore, Path]) -> None:
    """Clearing the sandbox box and saving leaves the server unsandboxed.

    Args:
        settings: The dialog and its store.
    """
    dialog, store, _ = settings

    _widget(dialog, QCheckBox, "mcp_sandbox_enabled").setChecked(False)
    box = dialog.findChild(QDialogButtonBox)
    assert box is not None
    save = box.button(QDialogButtonBox.StandardButton.Save)
    assert save is not None
    save.click()

    saved = store.load().server("boxed")
    assert saved is not None
    assert saved.sandbox.enabled is False
