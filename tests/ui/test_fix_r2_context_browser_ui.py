# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 35: the chat browses a running server's resources and prompts, completes their arguments, and inserts them.

The service gate assembles the real MCP service over private configuration, trust, approval and credential files, starts a real
``MCPServer`` on each protocol generation, and opens the browser the chat's button opens. It lists the server's resources and templates,
completes a template variable and a prompt argument from the server as they are typed, reads a resource and fetches a prompt into the
chat's input, subscribes to a resource and, when the server announces the update, the chat tells the operator. The window gate checks
the chat's button opens the browser.
"""

from __future__ import annotations

from contextlib import ExitStack
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QStringListModel
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QWidget,
)

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.credentials import store as credential_store_module
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import (
    config as mcp_config_module,
    consent as mcp_consent_module,
)
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_context_browser import McpContextBrowser
from intellicrack.ui.mcp_service import McpService
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_async
from tests._helpers.mcp_features_server import ADDED_RESOURCE, GREET_PROMPT, NOTES_RESOURCE, REPORT_TEMPLATE, TOUCH_TOOL
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, features_config
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


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credentials: CredentialStore) -> Path:
    """Point the MCP files and the credential store at private ones.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Redirects the look-ups.
        credentials: The private credential store.

    Returns:
        Path: The directory holding the MCP files.
    """
    home = tmp_path / "config"
    home.mkdir()

    def config_file(filename: str) -> Path:
        """Resolve a configuration file inside the private directory.

        Args:
            filename: The file name.

        Returns:
            Path: Its path.
        """
        return home / filename

    monkeypatch.setattr(mcp_config_module, "get_config_file", config_file)
    monkeypatch.setattr(mcp_consent_module, "get_config_file", config_file)
    monkeypatch.setattr(credential_store_module, "get_credential_store", lambda: credentials)
    return home


def _orchestrator(tmp_path: Path) -> Orchestrator:
    """Build a real orchestrator over a private session store.

    Args:
        tmp_path: Per-test directory.

    Returns:
        Orchestrator: The orchestrator.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(exist_ok=True)
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
    )


def _child[W: QWidget](parent: QWidget, kind: type[W], name: str) -> W:
    """Find a named child widget.

    Args:
        parent: Where to look.
        kind: The widget's class.
        name: Its object name.

    Returns:
        W: The widget.
    """
    widget = parent.findChild(kind, name)
    assert widget is not None, name
    return widget


def _select(qtbot: QtBot, view: QListWidget, text: str) -> None:
    """Select the first row containing a text, once it is listed.

    Args:
        qtbot: The Qt test driver.
        view: The list.
        text: Text the row contains.
    """

    def row() -> int:
        """Find the row.

        Returns:
            int: Its index, or -1.
        """
        return next((index for index in range(view.count()) if (item := view.item(index)) is not None and text in item.text()), -1)

    qtbot.waitUntil(lambda: row() >= 0, timeout=_WAIT_MS)
    view.setCurrentRow(row())


def _suggested(field: QLineEdit) -> list[str]:
    """Read the completions offered under a field.

    Args:
        field: The field.

    Returns:
        list[str]: The suggestions.
    """
    completer = field.completer()
    model = completer.model() if completer is not None else None
    return model.stringList() if isinstance(model, QStringListModel) else []


def _exercise_resources(qtbot: QtBot, browser: McpContextBrowser, chat: ChatPanel, connection: McpConnection) -> None:
    """Complete a template variable, read and insert a resource, subscribe to it, and see the server's update announced.

    Args:
        qtbot: The Qt test driver.
        browser: The open browser.
        chat: The chat panel.
        connection: The fixture server's connection.
    """
    resources = _child(browser, QListWidget, "mcp_context_resources")
    _select(qtbot, resources, REPORT_TEMPLATE)
    name = _child(browser, QLineEdit, "mcp_context_argument_name")
    qtbot.keyClicks(name, "al")
    qtbot.waitUntil(lambda: _suggested(name) == ["alpha", "alpine"], timeout=_WAIT_MS)

    _select(qtbot, resources, NOTES_RESOURCE)
    _child(browser, QPushButton, "mcp_context_read").click()
    preview = _child(browser, QPlainTextEdit, "mcp_context_resource_preview")
    qtbot.waitUntil(lambda: "remember the target" in preview.toPlainText(), timeout=_WAIT_MS)
    _child(browser, QPushButton, "mcp_context_insert_resource").click()
    assert "remember the target" in _child(chat, QTextEdit, "chat_input_textedit").toPlainText()

    subscribe = _child(browser, QPushButton, "mcp_context_subscribe")
    qtbot.waitUntil(subscribe.isEnabled, timeout=_WAIT_MS)
    subscribe.click()
    qtbot.waitUntil(lambda: NOTES_RESOURCE in connection.subscriptions, timeout=_WAIT_MS)
    qtbot.wait(500)
    _ = run_bridge_coroutine(connection.call_tool(TOUCH_TOOL, {"uri": NOTES_RESOURCE}), timeout_s=_BRIDGE_TIMEOUT_S)
    qtbot.waitUntil(lambda: f"resource_updated {NOTES_RESOURCE}" in chat.notice, timeout=_WAIT_MS)
    progress = _child(browser, QLabel, "mcp_context_progress")
    qtbot.waitUntil(lambda: "listed them again" in progress.text(), timeout=_WAIT_MS)
    _select(qtbot, resources, ADDED_RESOURCE)


def _exercise_prompts(qtbot: QtBot, browser: McpContextBrowser) -> None:
    """Complete a prompt argument and fetch the prompt into the preview.

    Args:
        qtbot: The Qt test driver.
        browser: The open browser.
    """
    prompts = _child(browser, QListWidget, "mcp_context_prompts")
    _select(qtbot, prompts, GREET_PROMPT)
    person = _child(browser, QLineEdit, "mcp_context_argument_person")
    qtbot.keyClicks(person, "a")
    qtbot.waitUntil(lambda: _suggested(person) == ["ada", "alan"], timeout=_WAIT_MS)
    person.setText("grace")
    _child(browser, QPushButton, "mcp_context_preview_prompt").click()
    prompt_preview = _child(browser, QPlainTextEdit, "mcp_context_prompt_preview")
    qtbot.waitUntil(lambda: "Greet grace in a plain way." in prompt_preview.toPlainText(), timeout=_WAIT_MS)


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_browser_completes_reads_inserts_and_subscribes(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    era: Era,
) -> None:
    """The browser lists, completes, reads, fetches and inserts; a subscribed resource's update reaches the chat's notice.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        monkeypatch: Isolates the configuration and credentials.
        era: The protocol generation.
    """
    with ExitStack() as stack, installed_keyring(private_file_keyring(tmp_path / "keyring.json")):
        credentials = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
        home = _isolate(tmp_path, monkeypatch, credentials)
        port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        McpConfigStore(home / "mcp.json").save(McpConfigDocument(servers=(features_config(era, port=port),)))
        parent = QWidget()
        qtbot.addWidget(parent)
        chat = ChatPanel(parent)
        orchestrator = _orchestrator(tmp_path)
        service = McpService(orchestrator.tool_registry, credentials, orchestrator, parent)
        service.set_attachment_handler(chat.insert_context_text)
        service.set_context_notice_handler(lambda event: chat.show_notice(f"{event.server_id}: {event.change.value} {event.uri or ''}"))
        outcome: list[object] = []
        watcher = DialogWatcher(McpServerConsentDialog, lambda dialog: dialog.make_decision(approved=True))
        try:
            _ = service.manager.reload()
            run_bridge_coroutine_async(service.manager.start_server("features"), outcome.append, outcome.append)
            qtbot.waitUntil(lambda: bool(outcome), timeout=_WAIT_MS)
            connection = service.manager.connection("features")
            assert connection is not None
            assert connection.is_ready, outcome
            browser = service.open_context_browser(parent)
            assert isinstance(browser, McpContextBrowser)
            assert _child(browser, QComboBox, "mcp_context_server").currentData() == "features"
            _exercise_resources(qtbot, browser, chat, connection)
            _exercise_prompts(qtbot, browser)
            browser.done(QDialog.DialogCode.Rejected.value)
        finally:
            watcher.stop()
            _ = run_bridge_coroutine(service.stop(), timeout_s=_BRIDGE_TIMEOUT_S)


def test_chat_button_opens_the_browser(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The chat's resources-and-prompts button opens the browser, and a server's announced changes appear in the chat.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        monkeypatch: Isolates the configuration and credentials.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring.json")):
        _ = _isolate(tmp_path, monkeypatch, CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
        window = MainWindow(Config(tools_directory=tmp_path / "tools", data_directory=tmp_path / "data"), _orchestrator(tmp_path))
        qtbot.addWidget(window)
        try:
            chat = window.findChild(ChatPanel)
            assert chat is not None
            _child(chat, QPushButton, "chat_mcp_context").click()
            qtbot.waitUntil(
                lambda: any(isinstance(widget, McpContextBrowser) and not widget.isHidden() for widget in QApplication.topLevelWidgets()),
                timeout=_WAIT_MS,
            )
            [browser] = [widget for widget in QApplication.topLevelWidgets() if isinstance(widget, McpContextBrowser)]
            assert "No running server" in _child(browser, QLabel, "mcp_context_progress").text()
            browser.done(QDialog.DialogCode.Rejected.value)
            service = window._mcp_service
            assert service is not None
            service._on_context_event(McpContextEvent("features", McpContextChange.RESOURCE_UPDATED, NOTES_RESOURCE))
            service._on_context_event(McpContextEvent("features", McpContextChange.PROMPTS_LISTED))
            qtbot.waitUntil(lambda: "list of prompts" in chat.notice, timeout=_WAIT_MS)
            assert chat.notice.splitlines() == [
                f"MCP server 'features' says {NOTES_RESOURCE} changed.",
                "MCP server 'features' changed its list of prompts.",
            ]
        finally:
            window.close()
