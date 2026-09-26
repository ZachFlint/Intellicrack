# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for how the operator's answers travel between the dialogs and the MCP client.

A question the client stops waiting for -- because it timed out or because
whoever asked was cancelled -- must leave the screen, and an answer arriving
after that must change nothing. The answers themselves are read from the
dialogs' own signals. Everything runs on the real background loop against real
dialogs, and the eliciting server is the SDK's own, over a real stdio pipe.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QCheckBox, QDialog, QLineEdit, QPushButton, QWidget

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import ConsentAnswer, McpConsentGate, TrustState, TrustStore
from intellicrack.mcp.errors import McpConsentDeniedError
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.ui.mcp_bridge import QtMcpPrompts
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async
from tests._helpers.mcp_interactive_server import ASK_TOOL_NAME
from tests._helpers.mcp_ui_support import DialogWatcher, interactive_server_config


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_SHORT_TIMEOUT_S = 0.8
_FORCE_CLOSE_AFTER_S = 8.0
_WAIT_MS = 30_000
_ENFORCE_INTERVAL_MS = 100


class _Outcome:
    """Collects what a background coroutine produced."""

    def __init__(self) -> None:
        """Start empty."""
        self.values: list[object] = []
        self.errors: list[object] = []

    @property
    def done(self) -> bool:
        """Whether the coroutine has finished either way.

        Returns:
            bool: ``True`` once a value or an error arrived.
        """
        return bool(self.values or self.errors)


def _run(coro: Coroutine[object, object, object], outcome: _Outcome) -> None:
    """Run a coroutine on the real background loop, collecting its outcome.

    Args:
        coro: The coroutine to run.
        outcome: Where its result or error is recorded.
    """
    run_bridge_coroutine_async(coro, outcome.values.append, outcome.errors.append)


class _ForceClose:
    """Closes dialogs left open past a deadline, and remembers that it had to."""

    def __init__(self, kind: type[QDialog]) -> None:
        """Arm the watcher.

        Args:
            kind: The dialog class to watch.
        """
        self.forced = 0
        self.started: float | None = None
        self.watcher = DialogWatcher(kind, self._note)
        self._timer = QTimer()
        self._timer.setInterval(_ENFORCE_INTERVAL_MS)
        _ = self._timer.timeout.connect(self.enforce)
        self._timer.start()

    def _note(self, dialog: QDialog) -> None:
        """Remember when a dialog appeared.

        Args:
            dialog: The dialog that appeared.
        """
        del dialog
        self.started = time.monotonic()

    def enforce(self) -> None:
        """Close any watched dialog that stayed open past the deadline.

        Runs from a timer, which fires inside a modal dialog's own event loop
        where the test's code cannot.
        """
        if self.started is None or time.monotonic() - self.started < _FORCE_CLOSE_AFTER_S:
            return
        for dialog in self.watcher.visible():
            self.forced += 1
            dialog.reject()

    def close(self) -> None:
        """Stop watching."""
        self._timer.stop()
        self.watcher.stop()


@pytest.fixture
def parent(qtbot: QtBot) -> QWidget:
    """Provide a parent widget for the dialogs.

    Args:
        qtbot: pytest-qt bot.

    Returns:
        QWidget: The parent.
    """
    widget = QWidget()
    qtbot.addWidget(widget)
    return widget


class TestConsentQuestionIsWithdrawn:
    """A consent question nobody waits for any more leaves the screen."""

    def test_timed_out_consent_dialog_is_closed(self, qtbot: QtBot, parent: QWidget) -> None:
        """When consent times out the dialog closes by itself and the launch is refused.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
        """
        prompts = QtMcpPrompts(parent, consent_timeout_s=_SHORT_TIMEOUT_S)
        guard = _ForceClose(McpServerConsentDialog)
        outcome = _Outcome()
        try:
            _run(prompts.request_launch_consent(interactive_server_config("srv"), "launch", []), outcome)

            qtbot.waitUntil(lambda: outcome.done and not guard.watcher.visible(), timeout=_WAIT_MS)
        finally:
            guard.close()
        assert guard.watcher.seen, "the consent dialog was never shown, so this proves nothing"
        assert guard.forced == 0, "the consent dialog stayed open after the request timed out"
        assert outcome.values == [ConsentAnswer(approved=False)]

    def test_cancelled_request_closes_its_dialog(self, qtbot: QtBot, parent: QWidget) -> None:
        """Cancelling the connection attempt closes the dialog it opened.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
        """
        prompts = QtMcpPrompts(parent)
        guard = _ForceClose(McpServerConsentDialog)
        outcome = _Outcome()

        async def ask_then_cancel() -> bool:
            """Ask, wait for the dialog to be up, then cancel the asker.

            Returns:
                bool: Whether the ask ended in cancellation.
            """
            task = asyncio.create_task(prompts.request_launch_consent(interactive_server_config("srv"), "launch", []))
            await asyncio.sleep(1.0)
            _ = task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return True
            return False

        try:
            _run(ask_then_cancel(), outcome)

            qtbot.waitUntil(lambda: outcome.done and not guard.watcher.visible(), timeout=_WAIT_MS)
        finally:
            guard.close()
        assert guard.watcher.seen, "the consent dialog was never shown, so this proves nothing"
        assert guard.forced == 0, "the consent dialog stayed open after its request was cancelled"
        assert outcome.values == [True]

    def test_timeout_neither_trusts_nor_denies(self, qtbot: QtBot, parent: QWidget, tmp_path: Path) -> None:
        """An unanswered consent refuses the launch without recording a verdict about the server.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
            tmp_path: Pytest-provided temporary directory.
        """
        prompts = QtMcpPrompts(parent, consent_timeout_s=_SHORT_TIMEOUT_S)
        trust = TrustStore(tmp_path / "trust.json")
        gate = McpConsentGate(trust, prompts.request_launch_consent)
        guard = _ForceClose(McpServerConsentDialog)
        outcome = _Outcome()
        try:
            _run(gate.ensure_launch_consent(interactive_server_config("srv"), {}), outcome)

            qtbot.waitUntil(lambda: outcome.done, timeout=_WAIT_MS)
        finally:
            guard.close()
        assert len(outcome.errors) == 1
        assert isinstance(outcome.errors[0], McpConsentDeniedError)
        assert trust.state("srv") is TrustState.UNTRUSTED, "an unanswered prompt recorded a verdict about the server"
        assert trust.launch_digest("srv") is None


class TestConsentAnswerComesFromTheDialog:
    """The operator's full answer, trust included, reaches the gate through the dialog's signal."""

    def test_approval_with_trust_is_recorded(self, qtbot: QtBot, parent: QWidget, tmp_path: Path) -> None:
        """Approving with the trust box ticked records both the launch and the trust.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
            tmp_path: Pytest-provided temporary directory.
        """
        prompts = QtMcpPrompts(parent)
        trust = TrustStore(tmp_path / "trust.json")
        gate = McpConsentGate(trust, prompts.request_launch_consent)

        def approve_with_trust(dialog: QDialog) -> None:
            """Tick the trust box and approve.

            Args:
                dialog: The consent dialog.
            """
            box = dialog.findChild(QCheckBox, "mcp_consent_trust")
            button = dialog.findChild(QPushButton, "mcp_consent_approve")
            assert box is not None
            assert button is not None
            box.setChecked(True)
            button.click()

        watcher = DialogWatcher(McpServerConsentDialog, approve_with_trust)
        outcome = _Outcome()
        try:
            _run(gate.ensure_launch_consent(interactive_server_config("srv"), {}), outcome)
            qtbot.waitUntil(lambda: outcome.done, timeout=_WAIT_MS)
        finally:
            watcher.stop()
        assert outcome.errors == []
        assert trust.state("srv") is TrustState.TRUSTED
        assert trust.launch_digest("srv") is not None

    def test_never_start_blocks_the_server(self, qtbot: QtBot, parent: QWidget, tmp_path: Path) -> None:
        """The never-start button records a denial the next start respects without asking.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
            tmp_path: Pytest-provided temporary directory.
        """
        prompts = QtMcpPrompts(parent)
        trust = TrustStore(tmp_path / "trust.json")
        gate = McpConsentGate(trust, prompts.request_launch_consent)

        def block(dialog: QDialog) -> None:
            """Press the never-start button.

            Args:
                dialog: The consent dialog.
            """
            button = dialog.findChild(QPushButton, "mcp_consent_block")
            assert button is not None
            button.click()

        watcher = DialogWatcher(McpServerConsentDialog, block)
        outcome = _Outcome()
        try:
            _run(gate.ensure_launch_consent(interactive_server_config("srv"), {}), outcome)
            qtbot.waitUntil(lambda: outcome.done, timeout=_WAIT_MS)
        finally:
            watcher.stop()
        assert isinstance(outcome.errors[0], McpConsentDeniedError)
        assert trust.state("srv") is TrustState.DENIED


class TestElicitationThroughTheDialog:
    """A server's question is answered through the real dialog, or withdrawn when abandoned."""

    def test_answer_typed_in_the_dialog_reaches_the_server(self, qtbot: QtBot, parent: QWidget, tmp_path: Path) -> None:
        """The name typed into the dialog comes back in the tool's result.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
            tmp_path: Pytest-provided temporary directory.
        """
        prompts = QtMcpPrompts(parent)

        def answer(dialog: QDialog) -> None:
            """Type a name and send it.

            Args:
                dialog: The elicitation dialog.
            """
            field = dialog.findChild(QLineEdit, "mcp_elicit_field_name")
            send = dialog.findChild(QPushButton, "mcp_elicit_accept")
            assert field is not None
            assert send is not None
            field.setText("ada")
            send.click()

        watcher = DialogWatcher(McpElicitationDialog, answer)
        outcome = _Outcome()
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), lambda _c, _d, _f: True)
        connection = McpConnection(
            interactive_server_config("srv"),
            McpSecretResolver(CredentialStore()),
            consent=gate,
            elicitation_callback=prompts.elicitation_for("srv"),
        )

        async def call() -> str:
            """Call the eliciting tool.

            Returns:
                str: The tool's text result.
            """
            await connection.connect()
            try:
                result = await connection.call_tool(ASK_TOOL_NAME, {})
            finally:
                await connection.disconnect()
            return "".join(getattr(block, "text", "") for block in result.content)

        try:
            _run(call(), outcome)
            qtbot.waitUntil(lambda: outcome.done, timeout=_WAIT_MS * 2)
        finally:
            watcher.stop()
        assert outcome.errors == []
        assert outcome.values == ["hello ada"]

    def test_timed_out_elicitation_dialog_is_closed(self, qtbot: QtBot, parent: QWidget, tmp_path: Path) -> None:
        """An elicitation nobody answers is declined and its dialog closes by itself.

        Args:
            qtbot: pytest-qt bot.
            parent: Parent widget.
            tmp_path: Pytest-provided temporary directory.
        """
        prompts = QtMcpPrompts(parent, elicitation_timeout_s=_SHORT_TIMEOUT_S)
        guard = _ForceClose(McpElicitationDialog)
        outcome = _Outcome()
        gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), lambda _c, _d, _f: True)
        connection = McpConnection(
            interactive_server_config("srv"),
            McpSecretResolver(CredentialStore()),
            consent=gate,
            elicitation_callback=prompts.elicitation_for("srv"),
        )

        async def call() -> str:
            """Call the eliciting tool.

            Returns:
                str: The tool's text result.
            """
            await connection.connect()
            try:
                result = await connection.call_tool(ASK_TOOL_NAME, {})
            finally:
                await connection.disconnect()
            return "".join(getattr(block, "text", "") for block in result.content)

        try:
            _run(call(), outcome)

            qtbot.waitUntil(lambda: outcome.done and not guard.watcher.visible(), timeout=_WAIT_MS * 2)
        finally:
            guard.close()
        assert guard.watcher.seen, "the elicitation dialog was never shown, so this proves nothing"
        assert guard.forced == 0, "the elicitation dialog stayed open after the request timed out"
        assert outcome.values == ["operator answered decline"]
