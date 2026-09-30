# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, items 13 and 45: an answer reaches its asker the moment it is given, however many questions are open, and never after a timeout.

Two servers ask for launch consent at once, on the real background loop, through the real consent dialogs. The operator answers the
first question while the second is still on screen, and the first asker must have its answer before the second dialog closes. A dialog
left open past its timeout is answered too late, and that answer must change nothing.

Every interaction runs from Qt timers, because a dialog run with ``exec()`` -- the behaviour these gates exist to rule out -- would hold
the test's own code until it closed.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QPushButton, QWidget

from intellicrack.mcp.consent import ConsentAnswer, McpConsentGate, TrustState, TrustStore
from intellicrack.mcp.errors import McpConsentDeniedError
from intellicrack.ui.mcp_bridge import QtMcpPrompts
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async
from tests._helpers.mcp_ui_support import DialogWatcher, interactive_server_config


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path

    import pytest
    from pytestqt.qtbot import QtBot


_TICK_MS: Final[int] = 50
_WAIT_MS: Final[int] = 30_000
_FIRST_ANSWER_BUDGET_S: Final[float] = 5.0
_FORCE_CLOSE_AFTER_S: Final[float] = 20.0
_SHORT_TIMEOUT_S: Final[float] = 0.8


class _Outcome:
    """What one background coroutine produced.

    Attributes:
        values: Its result, once it returned.
        errors: Its error, once it raised.
    """

    values: list[object]
    errors: list[object]

    def __init__(self) -> None:
        """Start empty."""
        self.values = []
        self.errors = []

    @property
    def done(self) -> bool:
        """Whether the coroutine has finished either way.

        Returns:
            bool: ``True`` once a value or an error arrived.
        """
        return bool(self.values or self.errors)


def _run(coro: Coroutine[object, object, object], outcome: _Outcome) -> None:
    """Run a coroutine on the real background loop.

    Args:
        coro: The coroutine.
        outcome: Where its result or error is recorded.
    """
    run_bridge_coroutine_async(coro, outcome.values.append, outcome.errors.append)


def _approve(dialog: QWidget) -> None:
    """Press a consent dialog's approve button.

    Args:
        dialog: The dialog.
    """
    button = dialog.findChild(QPushButton, "mcp_consent_approve")
    assert button is not None
    button.click()


class _StackedOperator:
    """Asks a second question once the first is on screen, answers the first, and checks its asker heard back before the second closes.

    Attributes:
        first_heard_while_second_open: Whether the first asker had its answer while the second dialog was still on screen.
        first_answered_at: When the first dialog was answered.
        forced: Whether the dialogs had to be closed because the first answer never arrived.
    """

    first_heard_while_second_open: bool
    first_answered_at: float | None
    forced: bool

    def __init__(self, first: _Outcome, ask_second: Callable[[], None]) -> None:
        """Start watching for consent dialogs.

        Args:
            first: The outcome of the first question.
            ask_second: Asks the second question.
        """
        self.first_heard_while_second_open = False
        self.first_answered_at = None
        self.forced = False
        self._first = first
        self._ask_second = ask_second
        self._second_asked = False
        self._started = time.monotonic()
        self.watcher = DialogWatcher(McpServerConsentDialog, lambda _dialog: None)
        self._timer = QTimer()
        self._timer.setInterval(_TICK_MS)
        _ = self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        """Advance the script by one step; runs inside whatever event loop is current."""
        seen = self.watcher.seen
        if not self._second_asked:
            if seen and seen[0].isVisible():
                self._second_asked = True
                self._ask_second()
            return
        if self.first_answered_at is None:
            if len(seen) == 2 and all(dialog.isVisible() for dialog in seen):
                self.first_answered_at = time.monotonic()
                _approve(seen[0])
            elif time.monotonic() - self._started > _FORCE_CLOSE_AFTER_S:
                self._force()
            return
        second = seen[1]
        if self._first.done and second.isVisible():
            self.first_heard_while_second_open = True
            _approve(second)
        elif time.monotonic() - self.first_answered_at > _FIRST_ANSWER_BUDGET_S and second.isVisible():
            _approve(second)
        elif time.monotonic() - self._started > _FORCE_CLOSE_AFTER_S:
            self._force()

    def _force(self) -> None:
        """Close every consent dialog still open, so a regression fails instead of hanging."""
        self.forced = True
        for dialog in self.watcher.visible():
            dialog.reject()

    def stop(self) -> None:
        """Stop the script."""
        self._timer.stop()
        self.watcher.stop()


def test_first_answer_arrives_while_a_second_question_is_open(qtbot: QtBot) -> None:
    """With a second consent dialog opened over the first, the first one's approval reaches its asker before the second is answered.

    Args:
        qtbot: The Qt test driver.
    """
    parent = QWidget()
    qtbot.addWidget(parent)
    prompts = QtMcpPrompts(parent)
    first, second = _Outcome(), _Outcome()

    def ask_second() -> None:
        _run(prompts.request_launch_consent(interactive_server_config("two"), "launch two", []), second)

    operator = _StackedOperator(first, ask_second)
    try:
        _run(prompts.request_launch_consent(interactive_server_config("one"), "launch one", []), first)
        qtbot.waitUntil(lambda: first.done and second.done, timeout=_WAIT_MS)
    finally:
        operator.stop()

    assert not operator.forced
    assert operator.first_heard_while_second_open, "the first answer waited for the second dialog to close"
    assert first.values == [ConsentAnswer(approved=True)]
    assert second.values == [ConsentAnswer(approved=True)]


def test_answer_after_the_timeout_changes_nothing(qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An approval that arrives once the question has timed out neither starts the server nor records trust.

    Args:
        qtbot: The Qt test driver.
        tmp_path: Per-test directory.
        monkeypatch: Keeps the timed-out dialog from being closed, so it can be answered late.
    """
    parent = QWidget()
    qtbot.addWidget(parent)
    monkeypatch.setattr(QtMcpPrompts, "_close_withdrawn", staticmethod(lambda _payload: None))
    prompts = QtMcpPrompts(parent, consent_timeout_s=_SHORT_TIMEOUT_S)
    trust = TrustStore(tmp_path / "trust.json")
    gate = McpConsentGate(trust, prompts.request_launch_consent)
    watcher = DialogWatcher(McpServerConsentDialog, lambda _dialog: None)
    outcome = _Outcome()
    try:
        _run(gate.ensure_launch_consent(interactive_server_config("late"), {}), outcome)
        qtbot.waitUntil(lambda: outcome.done and bool(watcher.seen), timeout=_WAIT_MS)
        [dialog] = watcher.seen
        _approve(dialog)
        qtbot.wait(_TICK_MS * 10)
    finally:
        watcher.stop()

    assert len(outcome.errors) == 1
    assert isinstance(outcome.errors[0], McpConsentDeniedError)
    assert trust.state("late") is TrustState.UNTRUSTED
    assert trust.launch_digest("late") is None
