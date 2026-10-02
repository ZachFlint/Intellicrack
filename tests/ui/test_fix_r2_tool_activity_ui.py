# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 34: the chat shows a running MCP call's live progress, and its Cancel button stops that call while the turn goes on.

The gate runs the real main window over the real agent loop, a loopback model endpoint that asks for one call to a real ``MCPServer``'s
slow tool, and that server on 2026-07-28 over stdio and 2025-11-25 over SSE. The turn starts on the window's orchestrator; the running call appears
beside the chat with the server's progress and in the status bar; pressing its Cancel button cancels it on the server, the call ends
as cancelled by the operator, the row goes away and the turn finishes.
"""

from __future__ import annotations

from contextlib import AsyncExitStack, ExitStack
from typing import TYPE_CHECKING, Any, Final

import pytest
from mcp_types import TextContent
from PyQt6.QtWidgets import QLabel, QPushButton

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import OPERATOR_CANCELLED_ERROR
from intellicrack.core.types import ConfirmationLevel
from intellicrack.credentials import store as credential_store_module
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import (
    config as mcp_config_module,
    consent as mcp_consent_module,
)
from intellicrack.mcp.config import to_canonical_name
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.ui.app import MainWindow
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_async
from intellicrack.ui.tool_activity import ToolActivityPanel
from tests._helpers.mcp_agent_harness import DIALECT_SCRIPTS, AgentStack, agent_stack
from tests._helpers.mcp_features_server import CANCELLATIONS_TOOL, SLOW_TOOL
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, features_config
from tests._helpers.mcp_http_process import running_server
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.core.types import ToolResult
    from tests._helpers.scripted_http_server import RecordedRequest, ScriptedResponse


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_DIALECT: Final[ApiDialect] = ApiDialect.CHAT_COMPLETIONS
_BRIDGE_TIMEOUT_S: Final[float] = 90.0
_WAIT_MS: Final[int] = 60_000


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credentials: CredentialStore) -> None:
    """Point the window's MCP files and credential store at private ones.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Redirects the look-ups.
        credentials: The private credential store.
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


def _server_cancellations(agents: AgentStack) -> str:
    """Ask the fixture server how many calls it saw cancelled.

    Args:
        agents: The running stack.

    Returns:
        str: The count.
    """
    connection = agents.manager.connection("features")
    assert connection is not None
    result = run_bridge_coroutine(connection.call_tool(CANCELLATIONS_TOOL, {}), timeout_s=_BRIDGE_TIMEOUT_S)
    [block] = result.content
    assert isinstance(block, TextContent)
    return block.text


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_chat_shows_progress_and_cancels_one_call(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, era: Era) -> None:
    """The running call shows the server's progress; its Cancel button stops it on the server and the turn finishes.

    The window is configured not to ask for confirmation, so the call starts at once instead of waiting on a modal
    confirmation dialog that nothing in this test answers.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        monkeypatch: Isolates the window's configuration and credentials.
        era: The protocol generation.
    """
    script = DIALECT_SCRIPTS[_DIALECT]
    responses: list[dict[str, Any] | Callable[[RecordedRequest], ScriptedResponse]] = [
        script.tool_call(to_canonical_name("features", SLOW_TOOL), {"steps": 2000, "delay": 0.05}),
        script.final(),
    ]
    with ExitStack() as sync_stack, installed_keyring(private_file_keyring(tmp_path / "keyring.json")):
        _isolate(tmp_path, monkeypatch, CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
        port = sync_stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        async_stack = AsyncExitStack()
        agents = run_bridge_coroutine(
            async_stack.enter_async_context(agent_stack(tmp_path / "agent", _DIALECT, (features_config(era, port=port),), responses)),
            timeout_s=_BRIDGE_TIMEOUT_S,
        )
        config = Config(
            tools_directory=tmp_path / "tools",
            data_directory=tmp_path / "data",
            confirmation_level=ConfirmationLevel.NONE,
        )
        window = MainWindow(config, agents.orchestrator)
        qtbot.addWidget(window)
        agents.orchestrator.set_mcp_tool_source(agents.source)
        results: list[ToolResult] = []
        statuses: list[str] = []
        window.tool_result_received.connect(results.append)
        window.status_update.connect(statuses.append)
        try:
            chat = window.findChild(ChatPanel)
            assert chat is not None
            activity = chat.findChild(ToolActivityPanel, "tool_activity")
            assert activity is not None
            turn: list[object] = []
            run_bridge_coroutine_async(agents.orchestrator.process_user_input("call the tool"), turn.append, turn.append)
            qtbot.waitUntil(
                lambda: not activity.isHidden() and activity.findChild(QLabel, "tool_activity_message") is not None,
                timeout=_WAIT_MS,
            )
            message = activity.findChild(QLabel, "tool_activity_message")
            assert message is not None
            qtbot.waitUntil(lambda: message.text().startswith(("1/2000", "2/2000", "3/2000")), timeout=_WAIT_MS)
            assert any(status.startswith("Running: ") and "/2000: step " in status for status in statuses)
            cancel = activity.findChild(QPushButton, "tool_activity_cancel")
            assert cancel is not None
            cancel.click()
            qtbot.waitUntil(lambda: bool(results) and activity.isHidden() and bool(turn), timeout=_WAIT_MS)
            assert turn == [None]
            [result] = results
            assert (result.success, result.error) == (False, OPERATOR_CANCELLED_ERROR)
            assert activity.running == []
            assert _server_cancellations(agents) == "1"
        finally:
            window.close()
            run_bridge_coroutine(async_stack.aclose(), timeout_s=_BRIDGE_TIMEOUT_S)
