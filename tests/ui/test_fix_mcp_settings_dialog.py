# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the MCP settings dialog.

The dialog is driven through its real widgets over a real configuration file,
a real connection manager on the real background loop, and, where a server has
to run, the SDK's own server over a real stdio pipe. The gates cover what the
operator can see and change: the sign-in state, edits across several servers,
whether a running server is really offering its tools, renaming a running
server, trust and remembered answers, and a server's prompt templates.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from typing import TYPE_CHECKING

import psutil
import pytest
from mcp.shared.auth import OAuthToken
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLineEdit,
    QListView,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QWidget,
)

from intellicrack.core.types import ToolCall
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.auth import KeyringTokenStorage, issuer_for, sign_out
from intellicrack.mcp.config import HttpServerSpec, McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalScope, ApprovalStore, McpConsentGate, TrustState, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from tests._helpers.mcp_ui_support import INTERACTIVE_SERVER_SCRIPT, DialogWatcher, interactive_server_config


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.consent import DangerousPattern


_WAIT_MS = 60_000
_BRIDGE_TIMEOUT_S = 60.0
_PUBLISHED_TOOLS = 2


def _approve(_config: McpServerConfig, _description: str, _findings: list[DangerousPattern]) -> bool:
    """Approve every launch.

    Args:
        _config: The server being launched.
        _description: The rendered launch description.
        _findings: Flagged patterns.

    Returns:
        bool: Always ``True``.
    """
    return True


class _Settings:
    """A settings dialog over real stores, and the pieces behind it."""

    def __init__(self, tmp_path: Path, parent: QWidget, servers: tuple[McpServerConfig, ...]) -> None:
        """Write the configuration and build the dialog.

        Args:
            tmp_path: Directory backing every store.
            parent: Parent widget.
            servers: The servers to configure.
        """
        self.config_path = tmp_path / "mcp.json"
        self.store = McpConfigStore(self.config_path)
        self.store.save(McpConfigDocument(servers=servers))
        self.trust = TrustStore(tmp_path / "trust.json")
        self.approvals = ApprovalStore(tmp_path / "approvals.json")
        self.resolver = McpSecretResolver(CredentialStore())
        self.manager = McpConnectionManager(self.store, self.resolver, McpConsentGate(self.trust, _approve))
        _ = self.manager.reload()
        self.parent = parent
        self.dialog: McpConfigDialog | None = None

    def open(self) -> McpConfigDialog:
        """Build the dialog the way the service does before showing it.

        Returns:
            McpConfigDialog: The dialog.
        """
        dialog = McpConfigDialog(self.manager, self.resolver, self.parent, approvals=self.approvals)
        dialog.refresh_auth_state()
        dialog.show()
        self.dialog = dialog
        return dialog

    def start(self, server_id: str) -> None:
        """Start one server through the manager.

        Args:
            server_id: The server to start.
        """
        _ = run_bridge_coroutine(self.manager.start_server(server_id), timeout_s=_BRIDGE_TIMEOUT_S)

    def saved(self) -> McpConfigDocument:
        """Read the configuration back from disk.

        Returns:
            McpConfigDocument: What was saved.
        """
        return McpConfigStore(self.config_path).load()

    def close(self) -> None:
        """Stop every server."""
        _ = run_bridge_coroutine(self.manager.stop(), timeout_s=_BRIDGE_TIMEOUT_S)


def _stdio(server_id: str, command: str, *, enabled: bool = False) -> McpServerConfig:
    """Build a local server configuration that is never started.

    Args:
        server_id: Identifier for the server.
        command: The launch command.
        enabled: Whether it is switched on.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(server_id=server_id, kind=McpTransportKind.STDIO, stdio=StdioServerSpec(command=command), enabled=enabled)


def _select(dialog: McpConfigDialog, server_id: str) -> None:
    """Select one server in the list, as a click would.

    Args:
        dialog: The dialog.
        server_id: The server to select.
    """
    view = dialog.findChild(QListView, "mcp_server_list")
    assert view is not None
    model = view.model()
    assert model is not None
    for row in range(model.rowCount()):
        index = model.index(row, 0)
        if str(model.data(index)).startswith(f"{server_id} - "):
            view.setCurrentIndex(index)
            return
    pytest.fail(f"server {server_id!r} is not listed")


def _caption(dialog: McpConfigDialog, server_id: str) -> str:
    """Read the list caption shown for one server.

    Args:
        dialog: The dialog.
        server_id: The server to read.

    Returns:
        str: The caption.
    """
    view = dialog.findChild(QListView, "mcp_server_list")
    assert view is not None
    model = view.model()
    assert model is not None
    for row in range(model.rowCount()):
        caption = str(model.data(model.index(row, 0)))
        if caption.startswith(f"{server_id} - "):
            return caption
    return ""


def _widget[W: QWidget](dialog: QWidget, kind: type[W], name: str) -> W:
    """Find one named widget.

    Args:
        dialog: The dialog to search.
        kind: The widget class.
        name: The widget's object name.

    Returns:
        W: The widget.
    """
    widget = dialog.findChild(kind, name)
    assert widget is not None, f"no {kind.__name__} named {name!r}"
    return widget


def _save(dialog: McpConfigDialog) -> None:
    """Press Save.

    Args:
        dialog: The dialog.
    """
    box = dialog.findChild(QDialogButtonBox)
    assert box is not None
    button = box.button(QDialogButtonBox.StandardButton.Save)
    assert button is not None
    button.click()


def _server_processes() -> list[psutil.Process]:
    """List this process's descendants running the interactive fixture server.

    Returns:
        list[psutil.Process]: The running server processes.
    """
    found: list[psutil.Process] = []
    for child in psutil.Process(os.getpid()).children(recursive=True):
        try:
            if any(str(INTERACTIVE_SERVER_SCRIPT) in part for part in child.cmdline()):
                found.append(child)
        except psutil.Error:
            continue
    return found


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget.

    Args:
        qtbot: pytest-qt bot.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


@pytest.fixture
def warnings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every warning box title instead of showing it.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[str]: The titles, in order.
    """
    titles: list[str] = []

    def record(_parent: object, title: str, _message: str, *_rest: object) -> QMessageBox.StandardButton:
        """Record one warning.

        Args:
            _parent: The parent widget.
            title: The box title.
            _message: The box text.
            *_rest: Remaining arguments.

        Returns:
            QMessageBox.StandardButton: ``Ok``.
        """
        titles.append(title)
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", record)
    return titles


class TestSignOutFollowsTheSelection:
    """The sign-out button reflects the selected server's stored credentials."""

    @pytest.fixture
    def signed_in(self, tmp_path: Path, parent: QWidget) -> Iterator[tuple[_Settings, str]]:
        """Configure an HTTP server with a stored access token.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.

        Yields:
            tuple[_Settings, str]: The settings and the server id.
        """
        server_id = f"remote-{uuid.uuid4().hex[:8]}"
        spec = HttpServerSpec(url="http://127.0.0.1:9/mcp")
        http = McpServerConfig(server_id=server_id, kind=McpTransportKind.HTTP, http=spec)
        settings = _Settings(tmp_path, parent, (_stdio("local", "cmd-local"), http))
        credentials = CredentialStore()
        storage = KeyringTokenStorage(credentials, server_id, issuer_for(spec))
        asyncio.run(storage.set_tokens(OAuthToken(access_token="token-value", token_type="Bearer")))
        try:
            yield settings, server_id
        finally:
            _ = asyncio.run(sign_out(credentials, server_id, issuer_for(spec)))

    def test_selecting_a_signed_in_server_enables_sign_out(self, qtbot: QtBot, signed_in: tuple[_Settings, str]) -> None:
        """Selecting the signed-in server enables the button; selecting a local one disables it.

        Args:
            qtbot: pytest-qt bot.
            signed_in: The settings and the signed-in server id.
        """
        settings, server_id = signed_in
        dialog = settings.open()
        button = _widget(dialog, QPushButton, "mcp_sign_out")
        _select(dialog, server_id)
        qtbot.waitUntil(button.isEnabled, timeout=_WAIT_MS)
        _select(dialog, "local")
        qtbot.waitUntil(lambda: not button.isEnabled(), timeout=_WAIT_MS)


class TestEditsSurviveAcrossServers:
    """Edits are kept per server, selection alone is not an edit, and Save writes them all."""

    def test_switching_keeps_edits_and_save_writes_every_server(self, tmp_path: Path, parent: QWidget) -> None:
        """Edits to two servers both survive switching and both reach the file.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (_stdio("alpha", "cmd-alpha"), _stdio("beta", "cmd-beta")))
        dialog = settings.open()
        command = _widget(dialog, QLineEdit, "mcp_stdio_command")

        _select(dialog, "alpha")
        command.setText("edited-alpha")
        _select(dialog, "beta")
        assert command.text() == "cmd-beta"
        command.setText("edited-beta")
        _select(dialog, "alpha")
        assert command.text() == "edited-alpha", "switching servers discarded the unsaved edit"

        _save(dialog)
        saved = settings.saved()
        alpha = saved.server("alpha")
        beta = saved.server("beta")
        assert alpha is not None
        assert alpha.stdio is not None
        assert beta is not None
        assert beta.stdio is not None
        assert alpha.stdio.command == "edited-alpha"
        assert beta.stdio.command == "edited-beta", "Save wrote only the selected server"

    def test_selecting_is_not_an_edit(self, tmp_path: Path, parent: QWidget, warnings: list[str]) -> None:
        """Browsing the servers and closing reports no unsaved changes.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
            warnings: Recorded warning titles.
        """
        settings = _Settings(tmp_path, parent, (_stdio("alpha", "cmd-alpha"), _stdio("beta", "cmd-beta")))
        dialog = settings.open()
        _select(dialog, "alpha")
        _select(dialog, "beta")
        _ = dialog.close()
        assert "Unsaved changes" not in warnings, "merely selecting servers was reported as an unsaved change"


class TestRunningStateMatchesWhatIsOffered:
    """A server shown running is one whose tools the model is really offered."""

    def test_added_server_starts_enabled_and_offers_its_tools(self, qtbot: QtBot, tmp_path: Path, parent: QWidget) -> None:
        """A server added in the dialog and started is switched on and offers what it publishes.

        Args:
            qtbot: pytest-qt bot.
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, ())
        dialog = settings.open()
        try:
            _widget(dialog, QPushButton, "mcp_add_server").click()
            _widget(dialog, QLineEdit, "mcp_stdio_command").setText(sys.executable)
            _widget(dialog, QPlainTextEdit, "mcp_stdio_args").setPlainText(str(INTERACTIVE_SERVER_SCRIPT))
            _widget(dialog, QPushButton, "mcp_start_server").click()
            qtbot.waitUntil(lambda: "running" in _caption(dialog, "server-1"), timeout=_WAIT_MS)
            assert _caption(dialog, "server-1") == f"server-1 - running, {_PUBLISHED_TOOLS} tools"
            saved = settings.saved().server("server-1")
            assert saved is not None
            assert saved.enabled, "the started server was left switched off"
            assert _widget(dialog, QCheckBox, "mcp_server_enabled").isChecked()
        finally:
            settings.close()

    def test_switching_a_running_server_off_stops_it(self, qtbot: QtBot, tmp_path: Path, parent: QWidget) -> None:
        """Saving a running server as switched off stops it, rather than showing it running.

        Args:
            qtbot: pytest-qt bot.
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (interactive_server_config("live"),))
        settings.start("live")
        dialog = settings.open()
        try:
            _select(dialog, "live")
            assert "running" in _caption(dialog, "live")
            _widget(dialog, QCheckBox, "mcp_server_enabled").setChecked(False)
            _save(dialog)
            qtbot.waitUntil(lambda: settings.manager.connection("live") is None, timeout=_WAIT_MS)
            qtbot.waitUntil(lambda: "running" not in _caption(dialog, "live"), timeout=_WAIT_MS)
        finally:
            settings.close()


class TestRenamingARunningServer:
    """Renaming a running server stops the process started under its old id."""

    def test_rename_stops_the_old_process(self, qtbot: QtBot, tmp_path: Path, parent: QWidget) -> None:
        """After renaming and saving, no process runs under the old id.

        Args:
            qtbot: pytest-qt bot.
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (interactive_server_config("old"),))
        settings.start("old")
        settings.trust.set_state("old", TrustState.TRUSTED)
        dialog = settings.open()
        try:
            assert _server_processes(), "the server never started, so this proves nothing"
            _select(dialog, "old")
            _widget(dialog, QLineEdit, "mcp_server_id").setText("new")
            _save(dialog)
            qtbot.waitUntil(lambda: settings.manager.connection("old") is None, timeout=_WAIT_MS)
            qtbot.waitUntil(lambda: not _server_processes(), timeout=_WAIT_MS)
            assert settings.trust.state("old") is TrustState.UNTRUSTED, "the old id kept the trust given to the renamed server"
        finally:
            settings.close()


class TestTrustCanBeChanged:
    """Trust and consent decisions can be granted, withdrawn, blocked and reset from the dialog."""

    def test_trust_buttons_change_the_recorded_state(self, tmp_path: Path, parent: QWidget) -> None:
        """Each button records its decision, and reset forgets the approved launch too.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (_stdio("srv", "cmd-srv"),))
        settings.trust.set_launch_digest("srv", "digest")
        dialog = settings.open()
        tabs = dialog.findChild(QTabWidget)
        assert tabs is not None
        assert "Trust and approvals" in [tabs.tabText(index) for index in range(tabs.count())]
        _select(dialog, "srv")

        _widget(dialog, QPushButton, "mcp_trust_grant").click()
        assert settings.trust.state("srv") is TrustState.TRUSTED
        _widget(dialog, QPushButton, "mcp_trust_revoke").click()
        assert settings.trust.state("srv") is TrustState.UNTRUSTED
        _widget(dialog, QPushButton, "mcp_trust_block").click()
        assert settings.trust.state("srv") is TrustState.DENIED
        _widget(dialog, QPushButton, "mcp_trust_reset").click()
        assert settings.trust.state("srv") is TrustState.UNTRUSTED
        assert settings.trust.launch_digest("srv") is None

    def test_review_launch_records_the_answer(self, qtbot: QtBot, tmp_path: Path, parent: QWidget) -> None:
        """Reviewing a launch shows the exact command and records the operator's approval and trust.

        Args:
            qtbot: pytest-qt bot.
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (interactive_server_config("srv", enabled=False),))
        dialog = settings.open()
        _select(dialog, "srv")
        shown: list[str] = []

        def approve_with_trust(consent: QDialog) -> None:
            """Read the launch shown, tick trust and approve.

            Args:
                consent: The consent dialog.
            """
            shown.append(_widget(consent, QPlainTextEdit, "mcp_consent_command").toPlainText())
            _widget(consent, QCheckBox, "mcp_consent_trust").setChecked(True)
            _widget(consent, QPushButton, "mcp_consent_approve").click()

        watcher = DialogWatcher(McpServerConsentDialog, approve_with_trust)
        try:
            _widget(dialog, QPushButton, "mcp_trust_review").click()
            qtbot.waitUntil(lambda: settings.trust.launch_digest("srv") is not None, timeout=_WAIT_MS)
        finally:
            watcher.stop()
        assert shown
        assert str(INTERACTIVE_SERVER_SCRIPT) in shown[0]
        assert settings.trust.state("srv") is TrustState.TRUSTED


class TestRememberedAnswers:
    """Remembered tool-call answers are listed and can be forgotten."""

    @pytest.fixture
    def remembered(self, tmp_path: Path, parent: QWidget) -> Iterator[_Settings]:
        """Configure one persisted and one session answer.

        Args:
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.

        Yields:
            _Settings: The settings.
        """
        settings = _Settings(tmp_path, parent, (_stdio("srv", "cmd-srv"),))
        ToolConfirmationDialog.set_approval_store(settings.approvals)
        settings.approvals.remember("mcp-srv", "mcp-srv.echo", "g1", approved=True, scope=ApprovalScope.ALWAYS)
        ToolConfirmationDialog.store_decision(
            ToolCall(id="c1", tool_name="ghidra", function_name="rename_function", arguments={}),
            approved=False,
            scope=ApprovalScope.SESSION,
        )
        try:
            yield settings
        finally:
            ToolConfirmationDialog.clear_remembered_decisions()
            ToolConfirmationDialog.set_approval_store(None)

    def test_answers_are_listed_and_forgotten(self, remembered: _Settings) -> None:
        """Both answers are listed; forgetting one removes it everywhere, forgetting all empties the list.

        Args:
            remembered: The settings holding the answers.
        """
        dialog = remembered.open()
        _select(dialog, "srv")
        listing = _widget(dialog, QListWidget, "mcp_approvals_list")
        texts = [item.text() for row in range(listing.count()) if (item := listing.item(row)) is not None]
        assert "mcp-srv.mcp-srv.echo - allowed, always" in texts
        assert "ghidra.rename_function - refused, this session" in texts

        for row in range(listing.count()):
            item = listing.item(row)
            if item is not None and item.text().startswith("mcp-srv."):
                listing.setCurrentItem(item)
        _widget(dialog, QPushButton, "mcp_approvals_forget").click()
        assert remembered.approvals.entries() == []

        _widget(dialog, QPushButton, "mcp_approvals_forget_all").click()
        assert ToolConfirmationDialog.session_decisions() == []
        assert listing.count() == 1
        first = listing.item(0)
        assert first is not None
        assert first.data(Qt.ItemDataRole.UserRole) is None


class TestPromptTemplates:
    """A running server's prompt templates can be listed, filled in and attached."""

    def test_prompt_is_fetched_and_attached(self, qtbot: QtBot, tmp_path: Path, parent: QWidget) -> None:
        """The filled-in prompt is fetched from the server and handed to the conversation.

        Args:
            qtbot: pytest-qt bot.
            tmp_path: Pytest-provided temporary directory.
            parent: Parent widget.
        """
        settings = _Settings(tmp_path, parent, (interactive_server_config("srv"),))
        settings.start("srv")
        dialog = settings.open()
        attached: list[str] = []
        _ = dialog.prompt_attached.connect(attached.append)
        try:
            _select(dialog, "srv")
            _widget(dialog, QPushButton, "mcp_list_prompts").click()
            listing = _widget(dialog, QListWidget, "mcp_prompt_list")
            qtbot.waitUntil(lambda: listing.count() == 1, timeout=_WAIT_MS)
            first = listing.item(0)
            assert first is not None
            assert first.text() == "Review"
            listing.setCurrentRow(0)
            _widget(dialog, QLineEdit, "mcp_prompt_argument_target").setText("the loader")
            _widget(dialog, QPushButton, "mcp_attach_prompt").click()
            qtbot.waitUntil(lambda: bool(attached), timeout=_WAIT_MS)
        finally:
            settings.close()
        assert "Review the loader, paying attention to everything." in attached[0]
        assert attached[0].startswith("[user]")
