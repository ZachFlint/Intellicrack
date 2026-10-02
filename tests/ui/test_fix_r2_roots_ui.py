# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 32: the running application offers servers the active session's folders, and MCP Settings edits them.

The service gate assembles the real MCP service over private configuration, trust, approval and credential files, makes a stored
session with a loaded binary and an operator folder current in the real orchestrator, and starts a real ``MCPServer`` on each protocol
generation. The server is offered the target's folder and the operator's; a folder added to the session is kept on the session, and a
2025-11-25 server is told its roots changed. The dialog gate edits one server's roots and the session's folders on the Roots tab, sees
what the server would be offered, and saves both.
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from typing import TYPE_CHECKING, Final

import pytest
from mcp_types import TextContent
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QListView, QListWidget, QPlainTextEdit, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BinaryInfo, ToolName
from intellicrack.credentials import store as credential_store_module
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import (
    config as mcp_config_module,
    consent as mcp_consent_module,
)
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore, McpRootsSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore
from intellicrack.mcp.roots import McpRootSet, root_uri
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_service import McpService
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_async
from tests._helpers.mcp_features_server import ROOTS_CHANGES_TOOL, ROOTS_TOOL
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, approve_every_launch, features_config, private_resolver
from tests._helpers.mcp_http_process import running_server
from tests._helpers.mcp_ui_support import DialogWatcher
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.connection import McpConnection


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_BRIDGE_TIMEOUT_S: Final[float] = 60.0
_WAIT_MS: Final[int] = 30_000


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the MCP configuration, trust and approval files at a private directory.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Redirects the files.

    Returns:
        Path: The directory.
    """
    directory = tmp_path / "config"
    directory.mkdir()

    def config_file(filename: str) -> Path:
        """Resolve a configuration file inside the private directory.

        Args:
            filename: The file name.

        Returns:
            Path: Its path.
        """
        return directory / filename

    monkeypatch.setattr(mcp_config_module, "get_config_file", config_file)
    monkeypatch.setattr(mcp_consent_module, "get_config_file", config_file)
    return directory


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget that outlives the dialogs.

    Args:
        qtbot: The Qt test driver.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


def _binary(path: Path) -> BinaryInfo:
    """Describe a loaded binary.

    Args:
        path: Where it is.

    Returns:
        BinaryInfo: Its description.
    """
    return BinaryInfo(
        path=path,
        name=path.name,
        size=0,
        sha256="0" * 64,
        file_type="PE",
        architecture="x64",
        is_64bit=True,
        entry_point=0,
        sections=[],
        imports=[],
        exports=[],
    )


def _roots_seen(connection: McpConnection) -> list[str]:
    """Ask the server which roots it was given.

    Args:
        connection: The connection.

    Returns:
        list[str]: The roots' URIs.
    """
    return [str(entry["uri"]) for entry in json.loads(_text(connection, ROOTS_TOOL))]


def _text(connection: McpConnection, tool: str) -> str:
    """Call a fixture tool from the GUI thread and read its text.

    Args:
        connection: The connection.
        tool: The tool.

    Returns:
        str: Its text result.
    """
    result = run_bridge_coroutine(connection.call_tool(tool, {}), timeout_s=_BRIDGE_TIMEOUT_S)
    [block] = result.content
    assert isinstance(block, TextContent)
    return block.text


def _start(qtbot: QtBot, service: McpService) -> McpConnection:
    """Start the fixture server through the service, approving its launch as the operator would.

    Args:
        qtbot: The Qt test driver.
        service: The service.

    Returns:
        McpConnection: The ready connection.
    """
    _ = service.manager.reload()
    outcome: list[object] = []

    def approve(dialog: QDialog) -> None:
        """Approve the launch.

        Args:
            dialog: The consent dialog.
        """
        assert isinstance(dialog, McpServerConsentDialog)
        dialog.make_decision(approved=True)

    watcher = DialogWatcher(McpServerConsentDialog, approve)
    try:
        run_bridge_coroutine_async(service.manager.start_server("features"), outcome.append, outcome.append)
        qtbot.waitUntil(lambda: bool(outcome), timeout=_WAIT_MS)
    finally:
        watcher.stop()
    connection = service.manager.connection("features")
    assert connection is not None
    assert connection.is_ready, outcome
    return connection


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_service_offers_the_session_and_announces_its_changes(
    qtbot: QtBot,
    tmp_path: Path,
    home: Path,
    parent: QWidget,
    era: Era,
) -> None:
    """A running server is offered the session's folders; a folder added later is kept on the session and announced on 2025-11-25.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        home: The private configuration directory.
        parent: Parent widget.
        era: The protocol generation.
    """
    target = tmp_path / "Target Dir" / "app.exe"
    notes = tmp_path / "notes"
    added = tmp_path / "added later"
    other = tmp_path / "second" / "lib.dll"
    store = SessionStore(db_path=tmp_path / "sessions.db")
    stored = Session.create(provider="openai", model="m")
    stored.add_binary(_binary(target))
    _ = stored.set_root_folders([str(notes)])
    store.save(stored)
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=store, auto_save=False),
    )
    with ExitStack() as stack:
        stack.enter_context(installed_keyring(private_file_keyring(tmp_path / "keyring.json")))
        port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        McpConfigStore(home / "mcp.json").save(McpConfigDocument(servers=(features_config(era, port=port),)))
        credentials = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
        service = McpService(orchestrator.tool_registry, credentials, orchestrator, parent)
        try:
            session = run_bridge_coroutine(orchestrator.load_session(stored.id), timeout_s=_BRIDGE_TIMEOUT_S)
            service.sync_session_state()
            connection = _start(qtbot, service)
            assert _roots_seen(connection) == [root_uri(str(target.parent)), root_uri(str(notes))]

            _ = service.roots.set_folders([str(notes), str(added)])
            assert session.root_folders == [str(notes), str(added)]
            expected_notices = "1" if era is Era.LEGACY else "0"
            qtbot.waitUntil(lambda: _text(connection, ROOTS_CHANGES_TOOL) == expected_notices, timeout=_WAIT_MS)

            session.add_binary(_binary(other))
            service.sync_session_state()
            assert _roots_seen(connection) == [root_uri(str(path)) for path in (target.parent, other.parent, notes, added)]
        finally:
            _ = run_bridge_coroutine(service.stop(), timeout_s=_BRIDGE_TIMEOUT_S)


def test_loading_a_binary_offers_its_folder(
    qtbot: QtBot,
    tmp_path: Path,
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A binary the main window finishes loading has its folder offered as a root at once.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        home: The private configuration directory.
        monkeypatch: Gives the window a private credential store.
    """
    del home
    target = tmp_path / "first" / "app.exe"
    loaded = tmp_path / "second" / "lib.dll"
    loaded.parent.mkdir()
    loaded.write_bytes(b"MZ" + bytes(510))
    store = SessionStore(db_path=tmp_path / "sessions.db")
    stored = Session.create(provider="openai", model="m")
    stored.add_binary(_binary(target))
    store.save(stored)
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=store, auto_save=False),
    )
    orchestrator.tool_registry.register_bridge(ToolName.HEX_EDITOR, HexEditorBridge())
    with installed_keyring(private_file_keyring(tmp_path / "keyring.json")):
        credentials = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
        monkeypatch.setattr(credential_store_module, "get_credential_store", lambda: credentials)
        config = Config(tools_directory=tools_dir, logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
        window = MainWindow(config, orchestrator)
        qtbot.addWidget(window)
        service = window._mcp_service
        assert service is not None
        try:
            session = run_bridge_coroutine(orchestrator.load_session(stored.id), timeout_s=_BRIDGE_TIMEOUT_S)
            service.sync_session_state()
            assert [root.path for root in service.roots.session] == [str(target.parent)]
            binary = _binary(loaded)
            session.add_binary(binary)
            window._on_binary_loaded(binary)
            assert [root.path for root in service.roots.session] == [str(target.parent), str(loaded.parent)]
        finally:
            _ = run_bridge_coroutine(service.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
            window.close()


def _dialog(tmp_path: Path, parent: QWidget, roots: McpRootSet) -> McpConfigDialog:
    """Open MCP Settings over a stored configuration, with the fixture server selected.

    Args:
        tmp_path: Per-test directory.
        parent: Parent widget.
        roots: The session's roots.

    Returns:
        McpConfigDialog: The dialog.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=(features_config(Era.MODERN),)))
    gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), approve_every_launch)
    manager = McpConnectionManager(store, private_resolver(tmp_path), gate)
    _ = manager.reload()
    dialog = McpConfigDialog(
        manager,
        private_resolver(tmp_path),
        parent,
        approvals=ApprovalStore(tmp_path / "approvals.json"),
        roots=roots,
    )
    dialog.show()
    view = dialog.findChild(QListView, "mcp_server_list")
    assert view is not None
    model = view.model()
    assert model is not None
    view.setCurrentIndex(model.index(0, 0))
    return dialog


def _child[W: QWidget](dialog: QWidget, kind: type[W], name: str) -> W:
    """Find a named child widget.

    Args:
        dialog: The dialog.
        kind: The widget's class.
        name: Its object name.

    Returns:
        W: The widget.
    """
    widget = dialog.findChild(kind, name)
    assert widget is not None, name
    return widget


def _texts(widget: QListWidget) -> list[str]:
    """Read every row of a list.

    Args:
        widget: The list.

    Returns:
        list[str]: The rows' text.
    """
    return [item.text() for item in (widget.item(row) for row in range(widget.count())) if item is not None]


def test_roots_tab_edits_a_servers_roots_and_the_sessions_folders(tmp_path: Path, parent: QWidget) -> None:
    """Hiding a session folder, adding the server's own and the session's, shows what it is offered, and Save keeps all of it.

    Args:
        tmp_path: Per-test directory.
        parent: Parent widget.
    """
    target = tmp_path / "t" / "app.exe"
    notes = tmp_path / "notes"
    own = tmp_path / "own"
    later = tmp_path / "later"
    roots = McpRootSet()
    _ = roots.set_session(target=str(target), binaries=[str(target)], folders=[str(notes)])
    dialog = _dialog(tmp_path, parent, roots)
    try:
        session_list = _child(dialog, QListWidget, "mcp_roots_session_list")
        effective = _child(dialog, QListWidget, "mcp_roots_effective")
        assert _child(dialog, QCheckBox, "mcp_roots_enabled").isChecked()
        assert [text.splitlines()[1] for text in _texts(effective)] == [root_uri(str(target.parent)), root_uri(str(notes))]

        notes_item = session_list.item(1)
        assert notes_item is not None
        notes_item.setCheckState(Qt.CheckState.Unchecked)
        _child(dialog, QPlainTextEdit, "mcp_roots_folders").setPlainText(str(own))
        _child(dialog, QPlainTextEdit, "mcp_session_folders").setPlainText(f"{notes}\n{later}")
        assert [text.splitlines()[1] for text in _texts(effective)] == [root_uri(str(path)) for path in (target.parent, later, own)]
        assert _texts(effective)[0].startswith("Target binary folder: t")

        box = dialog.findChild(QDialogButtonBox)
        assert box is not None
        save = box.button(QDialogButtonBox.StandardButton.Save)
        assert save is not None
        save.click()
        [saved] = McpConfigStore(tmp_path / "mcp.json").load().servers
        assert saved.roots == McpRootsSpec(folders=(str(own),), exclude=(str(notes),))
        assert roots.folders == (str(notes), str(later))
        assert [root.path for root in roots.roots_for(saved)] == [str(path) for path in (target.parent, later, own)]
    finally:
        dialog.done(QDialog.DialogCode.Rejected.value)


def test_roots_off_offers_nothing(tmp_path: Path, parent: QWidget) -> None:
    """Turning roots off for a server lists nothing offered and saves the setting.

    Args:
        tmp_path: Per-test directory.
        parent: Parent widget.
    """
    roots = McpRootSet()
    _ = roots.set_session(target=str(tmp_path / "t" / "app.exe"), binaries=(), folders=())
    dialog = _dialog(tmp_path, parent, roots)
    try:
        _child(dialog, QCheckBox, "mcp_roots_enabled").setChecked(False)
        assert _texts(_child(dialog, QListWidget, "mcp_roots_effective")) == ["Nothing: this server is not told about any folder."]
        assert not _child(dialog, QListWidget, "mcp_roots_session_list").isEnabled()
        box = dialog.findChild(QDialogButtonBox)
        assert box is not None
        save = box.button(QDialogButtonBox.StandardButton.Save)
        assert save is not None
        save.click()
        [saved] = McpConfigStore(tmp_path / "mcp.json").load().servers
        assert saved.roots.enabled is False
    finally:
        dialog.done(QDialog.DialogCode.Rejected.value)
