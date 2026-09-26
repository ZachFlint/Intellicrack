# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the MCP service that wires the client into the running application.

The service is assembled for real -- configuration, trust and approval files in
a temporary directory, the real orchestrator and session store, the real
background loop -- and the servers it starts are the SDK's own over real stdio
pipes. The gates cover the two threads it joins: nothing the GUI thread owns
is changed from the loop, the registry the loop iterates is changed only on
the loop, shutting down stops everything including a start still in progress,
and the settings dialog does not outlive its use.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import time
import webbrowser
from typing import TYPE_CHECKING

import psutil
import pytest
from mcp.client.auth import OAuthClientProvider
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolCall
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import (
    config as mcp_config_module,
    consent as mcp_consent_module,
)
from intellicrack.mcp.config import HttpServerSpec, McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.consent import ApprovalScope, TrustState
from intellicrack.mcp.errors import McpConsentDeniedError
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_service import McpService
from intellicrack.ui.panels.async_bridge import ensure_loop, run_bridge_coroutine, run_bridge_coroutine_async
from tests._helpers.mcp_ui_support import INTERACTIVE_SERVER_SCRIPT, DialogWatcher, interactive_server_config


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QDialog
    from pytestqt.qtbot import QtBot

    from intellicrack.core.config import Config
    from intellicrack.core.session import Session


_BRIDGE_TIMEOUT_S = 60.0
_WAIT_MS = 30_000
_LOOP_BUSY_S = 2.0
_SETTLE_MS = 3_000
_STOP_BUDGET_S = 5.0
_PROMPT_START_MS = 10_000


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


def _on_loop(action: Callable[[], None]) -> None:
    """Run a plain callable on the background loop's thread and wait for it.

    Args:
        action: What to run there.
    """

    async def body() -> None:
        """Run the action once the loop has taken the call."""
        await asyncio.sleep(0)
        action()

    _ = run_bridge_coroutine(body(), timeout_s=_BRIDGE_TIMEOUT_S)


@pytest.fixture
def mcp_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the MCP configuration, trust and approval files at a temporary directory.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        Path: The directory holding the files.
    """
    home = tmp_path / "config"
    home.mkdir()

    def config_file(filename: str) -> Path:
        """Resolve a configuration file inside the temporary directory.

        Args:
            filename: The file name.

        Returns:
            Path: Its path.
        """
        return home / filename

    monkeypatch.setattr(mcp_config_module, "get_config_file", config_file)
    monkeypatch.setattr(mcp_consent_module, "get_config_file", config_file)
    return home


def _configure(home: Path, *servers: McpServerConfig) -> None:
    """Write the MCP configuration the service will load.

    Args:
        home: The directory holding the files.
        *servers: The servers to configure.
    """
    McpConfigStore(home / "mcp.json").save(McpConfigDocument(servers=servers))


@pytest.fixture
def orchestrator(tmp_path: Path) -> tuple[Orchestrator, SessionManager]:
    """Build a real orchestrator over a real session store.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        tuple[Orchestrator, SessionManager]: The orchestrator and its sessions.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    sessions = SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False)
    return (
        Orchestrator(provider_registry=ProviderRegistry(), tool_registry=ToolRegistry(tools_dir=tools_dir), session_manager=sessions),
        sessions,
    )


def _load_session(orchestrator: Orchestrator, sessions: SessionManager) -> Session:
    """Create a session on disk and make it the orchestrator's current one.

    Args:
        orchestrator: The orchestrator.
        sessions: Its session manager.

    Returns:
        Session: The loaded session.
    """
    created = run_bridge_coroutine(sessions.create("openai", "gpt-test"), timeout_s=_BRIDGE_TIMEOUT_S)
    assert created is not None
    loaded = run_bridge_coroutine(orchestrator.load_session(created.id), timeout_s=_BRIDGE_TIMEOUT_S)
    assert loaded is not None
    return loaded


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget for the service's dialogs.

    Args:
        qtbot: pytest-qt bot.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


@pytest.fixture
def service(mcp_home: Path, orchestrator: tuple[Orchestrator, SessionManager], parent: QWidget) -> Iterator[McpService]:
    """Assemble the real MCP service.

    Args:
        mcp_home: The directory holding the MCP files.
        orchestrator: The orchestrator and its sessions.
        parent: Parent widget.

    Yields:
        McpService: The service, stopped again afterwards.
    """
    del mcp_home
    built = McpService(orchestrator[0].tool_registry, CredentialStore(), orchestrator[0], parent)
    try:
        yield built
    finally:
        _ = run_bridge_coroutine(built.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
        ToolConfirmationDialog.clear_remembered_decisions()


def _reject(dialog: QDialog) -> None:
    """Close a dialog as the Close button would.

    Args:
        dialog: The dialog.
    """
    dialog.reject()


class TestSettingsDialogLifetime:
    """Opening the settings leaves nothing behind and changes the registry only on the loop."""

    def test_each_opening_is_destroyed(self, service: McpService, parent: QWidget, mcp_home: Path) -> None:
        """After the dialog closes it is destroyed rather than kept as a hidden child.

        Args:
            service: The MCP service.
            parent: Parent widget.
            mcp_home: The directory holding the MCP files.
        """
        _configure(mcp_home)
        watcher = DialogWatcher(McpConfigDialog, _reject)
        try:
            for _opening in range(3):
                service.open_settings(parent)
        finally:
            watcher.stop()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        assert len(watcher.seen) == 3
        assert parent.findChildren(McpConfigDialog) == [], "closed settings dialogs were kept alive"

    def test_registration_runs_on_the_loop(
        self,
        qtbot: QtBot,
        service: McpService,
        parent: QWidget,
        mcp_home: Path,
        orchestrator: tuple[Orchestrator, SessionManager],
    ) -> None:
        """While the loop is busy the registry is untouched; it changes once the loop runs the registration.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
            parent: Parent widget.
            mcp_home: The directory holding the MCP files.
            orchestrator: The orchestrator and its sessions.
        """
        _configure(mcp_home, interactive_server_config("reg", enabled=False))
        _ = service.manager.reload()
        registry = orchestrator[0].tool_registry.external_tools
        assert registry.get("mcp-reg") is None
        busy = threading.Event()

        def occupy() -> None:
            """Hold the loop's thread, as a long synchronous step would."""
            busy.set()
            time.sleep(_LOOP_BUSY_S)

        _ = ensure_loop().call_soon_threadsafe(occupy)
        assert busy.wait(_BRIDGE_TIMEOUT_S)
        watcher = DialogWatcher(McpConfigDialog, _reject)
        try:
            service.open_settings(parent)
        finally:
            watcher.stop()
        assert registry.get("mcp-reg") is None, "the registry was changed from the GUI thread while the loop was using it"
        qtbot.waitUntil(lambda: registry.get("mcp-reg") is not None, timeout=_WAIT_MS)


class TestGuiStateChangesOnTheGuiThread:
    """Reports from the loop reach GUI-thread state only through the GUI thread."""

    def test_generation_change_clears_answers_on_the_gui_thread(self, qtbot: QtBot, service: McpService) -> None:
        """A changed tool listing discards remembered answers once the GUI thread handles it.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
        """
        call = ToolCall(id="c1", tool_name="mcp-gen", function_name="mcp-gen.echo", arguments={})
        ToolConfirmationDialog.store_decision(call, approved=True, generation="g1", scope=ApprovalScope.SESSION)
        gate = service.manager.consent

        def change() -> None:
            """Publish two generations from the loop's thread."""
            _ = gate.note_generation("gen", "g1")
            _ = gate.note_generation("gen", "g2")

        _on_loop(change)
        assert ToolConfirmationDialog.remembered_decision(call, "g1") is True, "remembered answers were changed from the loop's thread"
        qtbot.waitUntil(lambda: ToolConfirmationDialog.remembered_decision(call, "g1") is None, timeout=_WAIT_MS)

    def test_server_state_reaches_the_session_on_the_gui_thread(
        self,
        qtbot: QtBot,
        service: McpService,
        mcp_home: Path,
        orchestrator: tuple[Orchestrator, SessionManager],
    ) -> None:
        """A server's new state is written onto the session by the GUI thread.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
            mcp_home: The directory holding the MCP files.
            orchestrator: The orchestrator and its sessions.
        """
        _configure(mcp_home, interactive_server_config("state", enabled=False))
        _ = service.manager.reload()
        session = _load_session(*orchestrator)
        service.sync_session_state()
        assert session.clear_mcp_server_state("state")

        _on_loop(lambda: service._on_server_changed("state"))
        assert "state" not in session.mcp_servers, "the session was changed from the loop's thread"
        qtbot.waitUntil(lambda: "state" in session.mcp_servers, timeout=_WAIT_MS)
        assert session.mcp_servers["state"].health == "disabled"

    def test_new_session_is_given_every_server(
        self,
        service: McpService,
        mcp_home: Path,
        orchestrator: tuple[Orchestrator, SessionManager],
    ) -> None:
        """A session that becomes active is given every configured server's state.

        Args:
            service: The MCP service.
            mcp_home: The directory holding the MCP files.
            orchestrator: The orchestrator and its sessions.
        """
        _configure(mcp_home, interactive_server_config("one", enabled=False), interactive_server_config("two", enabled=False))
        _ = service.manager.reload()
        session = _load_session(*orchestrator)
        assert session.mcp_servers == {}
        service.sync_session_state()
        assert sorted(session.mcp_servers) == ["one", "two"]


class TestShutdown:
    """Stopping MCP stops everything, including a start still waiting on the operator."""

    def test_stop_abandons_a_start_waiting_for_consent(
        self,
        qtbot: QtBot,
        service: McpService,
        mcp_home: Path,
        orchestrator: tuple[Orchestrator, SessionManager],
    ) -> None:
        """Stopping ends a start that waits on the operator: nothing is asked, launched or registered afterwards.

        The prompts are left unanswered, as they are when the application
        closes with a consent dialog still pending. Stopping must not wait
        them out, and the start they held up must finish without launching
        or registering anything.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
            mcp_home: The directory holding the MCP files.
            orchestrator: The orchestrator and its sessions.
        """
        _configure(mcp_home, interactive_server_config("first"), interactive_server_config("second"))
        registry = orchestrator[0].tool_registry.external_tools
        started: list[object] = []
        run_bridge_coroutine_async(service.start(), started.append, started.append)
        time.sleep(1.5)
        began = time.monotonic()
        _ = run_bridge_coroutine(service.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
        stop_took = time.monotonic() - began

        def approve(dialog: QDialog) -> None:
            """Approve a launch, as an operator arriving late would.

            Args:
                dialog: The consent dialog.
            """
            dialog.accept()

        watcher = DialogWatcher(McpServerConsentDialog, approve)
        try:
            qtbot.waitUntil(lambda: bool(started), timeout=_PROMPT_START_MS)
            qtbot.wait(_SETTLE_MS)
        finally:
            watcher.stop()
        assert stop_took < _STOP_BUDGET_S, f"stopping waited {stop_took:.1f}s for prompts nobody would answer"
        assert watcher.seen == [], "a consent prompt was shown after MCP had stopped"
        assert _server_processes() == [], "a server was started after MCP had stopped"
        assert all(service.manager.connection(server_id) is None for server_id in ("first", "second"))
        assert registry.get("mcp-first") is None, "the stopped service registered its tools after stopping"

    def test_nothing_is_asked_after_stop(self, qtbot: QtBot, service: McpService) -> None:
        """After stopping, a launch is refused without a prompt and without marking the server denied.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
        """
        _ = run_bridge_coroutine(service.stop(), timeout_s=_BRIDGE_TIMEOUT_S)
        watcher = DialogWatcher(McpServerConsentDialog, _reject)
        gate = service.manager.consent
        errors: list[object] = []
        try:
            run_bridge_coroutine_async(gate.ensure_launch_consent(interactive_server_config("late"), {}), errors.append, errors.append)
            qtbot.waitUntil(lambda: bool(errors), timeout=_WAIT_MS)
        finally:
            watcher.stop()
        assert isinstance(errors[0], McpConsentDeniedError)
        assert watcher.seen == [], "the operator was asked about a launch after MCP stopped"
        assert gate.trust.state("late") is TrustState.UNTRUSTED


class TestSignInNotice:
    """The operator is told when a browser was opened for an OAuth sign-in."""

    def test_opening_the_sign_in_page_shows_a_notice(self, qtbot: QtBot, service: McpService, monkeypatch: pytest.MonkeyPatch) -> None:
        """The OAuth handler the service builds opens the page and then shows a notice naming the server.

        Args:
            qtbot: pytest-qt bot.
            service: The MCP service.
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setenv("BROWSER", sys.executable)
        monkeypatch.setattr(webbrowser, "_tryorder", None)
        monkeypatch.setattr(webbrowser, "_browsers", {})
        config = McpServerConfig(
            server_id="remote",
            kind=McpTransportKind.HTTP,
            http=HttpServerSpec(url="http://127.0.0.1:9/mcp"),
            enabled=True,
        )
        auth = service._build_auth(config)
        assert isinstance(auth, OAuthClientProvider)
        handler = auth.context.redirect_handler
        assert handler is not None
        loopback = auth._loopback
        assert loopback is not None
        url = "http://127.0.0.1:9/authorize?client_id=intellicrack&state=notice-test"

        async def redirect() -> None:
            """Send the operator to the sign-in page the way the SDK's flow does, with the redirect listener open."""
            _ = loopback.open()
            try:
                await handler(url)
            finally:
                loopback.close()

        _ = run_bridge_coroutine(redirect(), timeout_s=_BRIDGE_TIMEOUT_S)
        qtbot.waitUntil(lambda: bool(service.sign_in_notices), timeout=_WAIT_MS)
        notice = service.sign_in_notices[0]
        assert notice.isVisible()
        assert not notice.isModal()
        assert "'remote'" in notice.text()
        assert url in notice.informativeText()


class TestSessionRecordedByTheWindow:
    """The main window records MCP state onto a session it restores."""

    def test_loaded_session_gets_mcp_state(
        self,
        qtbot: QtBot,
        mcp_home: Path,
        real_config: Config,
        orchestrator: tuple[Orchestrator, SessionManager],
    ) -> None:
        """Loading a session through the window writes every server's state onto it.

        Args:
            qtbot: pytest-qt bot.
            mcp_home: The directory holding the MCP files.
            real_config: A real configuration over temporary directories.
            orchestrator: The orchestrator and its sessions.
        """
        _configure(mcp_home, McpServerConfig(server_id="restored", kind=McpTransportKind.STDIO, stdio=StdioServerSpec(command="unused")))
        window = MainWindow(real_config, orchestrator[0])
        qtbot.addWidget(window)
        assert window._mcp_service is not None
        _ = window._mcp_service.manager.reload()
        session = _load_session(*orchestrator)
        assert session.mcp_servers == {}
        window._on_session_loaded(session.id, session)
        assert "restored" in session.mcp_servers, "a restored session was given no MCP state"
        assert session.mcp_servers["restored"].health == "disabled"
