# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 19: the settings dialog prices tools through the tool source, confirmations answer at once, and stopping MCP leaves the GUI's store alone.

The settings dialog lists a real server's tools at the prices the real tool source gives. The main window's confirmation hands the
operator's answer to the waiting call from the dialog's ``decision_made`` signal, while the dialog is still finishing. Stopping the MCP
service on its background loop withdraws the approval store only once the GUI thread runs, and only if nothing has replaced it.
"""

from __future__ import annotations

import asyncio
import re
import threading
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QListView, QListWidget, QWidget

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolCall
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import (
    config as mcp_config_module,
    consent as mcp_consent_module,
)
from intellicrack.mcp.config import McpConfigDocument, McpConfigStore
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import McpToolSource
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.mcp_service import McpService
from intellicrack.ui.panels.async_bridge import ensure_loop, run_bridge_coroutine
from tests._helpers.mcp_agent_harness import approve_every_launch
from tests._helpers.mcp_ui_support import DialogWatcher, interactive_server_config
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from collections.abc import Coroutine, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QDialog
    from pytestqt.qtbot import QtBot

    from intellicrack.mcp.policy import ToolCost


_BRIDGE_TIMEOUT_S: Final[float] = 60.0
_DELIVERY_WAIT_S: Final[float] = 5.0
_WAIT_MS: Final[int] = 30_000
_GENERATION: Final[str] = "generation-1"
_TOKENS: Final[re.Pattern[str]] = re.compile(r"\((\d+) tokens\)$")


@pytest.fixture
def private_credentials(tmp_path: Path) -> Iterator[CredentialStore]:
    """Provide a credential store over a private keyring and a private ``.env``.

    Args:
        tmp_path: Per-test directory.

    Yields:
        CredentialStore: The store.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring.json")):
        yield CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))


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


def _orchestrator(tmp_path: Path) -> Orchestrator:
    """Build a real orchestrator over a real session store.

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


def _on_loop[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine on the background loop without running the GUI thread's events meanwhile.

    Args:
        coro: The coroutine.

    Returns:
        T: Its result.
    """
    return asyncio.run_coroutine_threadsafe(coro, ensure_loop()).result(_BRIDGE_TIMEOUT_S)


class _PricingSource(McpToolSource):
    """The real tool source, noting each server it is asked to price.

    Attributes:
        priced: The servers priced, in order.
    """

    priced: list[str]

    def __init__(self, manager: McpConnectionManager, registry: ToolRegistry) -> None:
        """Wrap the real source.

        Args:
            manager: The connection manager.
            registry: The tool registry.
        """
        super().__init__(manager, registry)
        self.priced = []

    def costs(self, server_id: str) -> list[ToolCost]:
        """Price a server's tools the real way, noting that it was asked.

        Args:
            server_id: The server.

        Returns:
            list[ToolCost]: The real costs.
        """
        self.priced.append(server_id)
        return super().costs(server_id)


def test_settings_list_prices_tools_through_the_tool_source(
    qtbot: QtBot,
    tmp_path: Path,
    parent: QWidget,
    private_credentials: CredentialStore,
) -> None:
    """The settings dialog shows each running server's tools at the prices the tool source gives.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        parent: The dialog's parent.
        private_credentials: A private credential store.
    """
    store = McpConfigStore(tmp_path / "mcp.json")
    store.save(McpConfigDocument(servers=(interactive_server_config("play"),)))
    resolver = McpSecretResolver(private_credentials)
    manager = McpConnectionManager(store, resolver, McpConsentGate(TrustStore(tmp_path / "trust.json"), approve_every_launch))
    _ = manager.reload()
    source = _PricingSource(manager, _orchestrator(tmp_path).tool_registry)
    _ = run_bridge_coroutine(manager.start_server("play"), timeout_s=_BRIDGE_TIMEOUT_S)
    try:
        dialog = McpConfigDialog(manager, resolver, parent, approvals=ApprovalStore(tmp_path / "approvals.json"), tool_source=source)
        dialog.show()
        view = dialog.findChild(QListView, "mcp_server_list")
        assert view is not None
        model = view.model()
        assert model is not None
        view.setCurrentIndex(model.index(0, 0))
        tools = dialog.findChild(QListWidget, "mcp_tools_list")
        assert tools is not None
        qtbot.waitUntil(lambda: tools.count() > 0, timeout=_WAIT_MS)
        listed: dict[str, int] = {}
        for row in range(tools.count()):
            item = tools.item(row)
            assert item is not None
            match = _TOKENS.search(item.text())
            assert match is not None, item.text()
            listed[str(item.data(Qt.ItemDataRole.UserRole))] = int(match.group(1))
        expected = {cost.canonical_name.rsplit(".", 1)[-1]: cost.total_tokens for cost in source.costs("play")}
        assert "play" in source.priced[:-1]
        assert listed == expected
        dialog.close()
    finally:
        _ = run_bridge_coroutine(manager.stop(), timeout_s=_BRIDGE_TIMEOUT_S)


@pytest.fixture
def window(qtbot: QtBot, tmp_path: Path) -> Iterator[MainWindow]:
    """Build a real main window over a real orchestrator.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.

    Yields:
        MainWindow: The window.
    """
    del qtbot
    config = Config(tools_directory=tmp_path / "tools", logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
    built = MainWindow(config, _orchestrator(tmp_path))
    try:
        yield built
    finally:
        built.close()
        ToolConfirmationDialog.clear_remembered_decisions()


async def _new_future() -> asyncio.Future[bool]:
    """Create a future on the running loop, as a waiting tool call does.

    Returns:
        asyncio.Future[bool]: The future.
    """
    await asyncio.sleep(0)
    return asyncio.get_running_loop().create_future()


@pytest.mark.parametrize("approved", [True, False], ids=["approve", "deny"])
def test_confirmation_answer_reaches_the_call_as_the_operator_decides(window: MainWindow, *, approved: bool) -> None:
    """The waiting call has the operator's answer by the time the dialog reports the decision, before the dialog has closed.

    Args:
        window: The main window.
        approved: The answer the operator gives.
    """
    loop = ensure_loop()
    future = _on_loop(_new_future())
    delivered_first: list[bool] = []

    def settled_within_wait(*_decision: bool) -> None:
        """Wait, briefly, for the waiting call to have its answer, as the decision is reported.

        Args:
            *_decision: The decision the dialog reports.
        """
        done = threading.Event()
        _ = loop.call_soon_threadsafe(future.add_done_callback, lambda _future: done.set())
        delivered_first.append(done.wait(_DELIVERY_WAIT_S))

    def answer(dialog: QDialog) -> None:
        """Answer the confirmation as the operator would.

        Args:
            dialog: The confirmation dialog.
        """
        assert isinstance(dialog, ToolConfirmationDialog)
        _ = dialog.decision_made.connect(settled_within_wait)
        dialog.make_decision(approved=approved)

    watcher = DialogWatcher(ToolConfirmationDialog, answer)
    try:
        call = ToolCall(id="call-1", tool_name="frida", function_name="frida.attach", arguments={"pid": 4242})
        window.confirmation_requested.emit((call, future, loop))
    finally:
        watcher.stop()
    assert delivered_first == [True]
    assert _on_loop(asyncio.wait_for(asyncio.shield(future), _BRIDGE_TIMEOUT_S)) is approved


def test_dismissed_confirmation_is_a_denial(window: MainWindow) -> None:
    """Closing the confirmation without answering denies the call.

    Args:
        window: The main window.
    """
    loop = ensure_loop()
    future = _on_loop(_new_future())
    watcher = DialogWatcher(ToolConfirmationDialog, lambda dialog: dialog.reject())
    try:
        call = ToolCall(id="call-2", tool_name="frida", function_name="frida.attach", arguments={"pid": 4242})
        window.confirmation_requested.emit((call, future, loop))
    finally:
        watcher.stop()
    assert _on_loop(asyncio.wait_for(asyncio.shield(future), _BRIDGE_TIMEOUT_S)) is False


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent: QWidget, private_credentials: CredentialStore) -> Iterator[McpService]:
    """Assemble the real MCP service over private configuration, trust and approval files.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Points the MCP files at the per-test directory.
        parent: Parent widget.
        private_credentials: A private credential store.

    Yields:
        McpService: The service.
    """
    home = tmp_path / "config"
    home.mkdir()

    def config_file(filename: str) -> Path:
        """Resolve a configuration file inside the per-test directory.

        Args:
            filename: The file name.

        Returns:
            Path: Its path.
        """
        return home / filename

    monkeypatch.setattr(mcp_config_module, "get_config_file", config_file)
    monkeypatch.setattr(mcp_consent_module, "get_config_file", config_file)
    orchestrator = _orchestrator(tmp_path)
    built = McpService(orchestrator.tool_registry, private_credentials, orchestrator, parent)
    try:
        yield built
    finally:
        ToolConfirmationDialog.set_approval_store(None)


def test_stop_withdraws_the_approval_store_on_the_gui_thread(qtbot: QtBot, service: McpService) -> None:
    """Stopping on the background loop leaves the store in place until the GUI thread runs, then withdraws it.

    Args:
        qtbot: The Qt test driver.
        service: The MCP service.
    """
    assert ToolConfirmationDialog.can_remember_always(_GENERATION)
    _on_loop(service.stop())
    assert ToolConfirmationDialog.can_remember_always(_GENERATION)
    qtbot.waitUntil(lambda: not ToolConfirmationDialog.can_remember_always(_GENERATION), timeout=_WAIT_MS)


def test_stop_leaves_a_store_installed_since(service: McpService, tmp_path: Path) -> None:
    """A store another owner installed after this service's stays installed when this service stops.

    Args:
        service: The MCP service.
        tmp_path: Per-test directory.
    """
    replacement = ApprovalStore(tmp_path / "replacement.json")
    ToolConfirmationDialog.set_approval_store(replacement)
    _on_loop(service.stop())
    QApplication.processEvents()
    assert ToolConfirmationDialog.can_remember_always(_GENERATION)
