# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for audit defect S16-D12 in ``SessionManagerDialog``.

Pre-fix, ``SessionManagerDialog._load_selected_session`` only emitted the
``session_loaded`` Qt signal and accepted the dialog -- it never pulled the
saved session's chat history or active binary back into the live UI. A
listener that only reacted to the emitted session id (mirroring the
production ``MainWindow`` wiring in ``app.py``, which clears the chat panel
before the load completes and never repopulates it afterward) was left with
an empty chat panel and no active binary even though the session file on
disk genuinely contained both.

This test builds a real session with non-empty chat history and an active
binary through a real ``SessionManager``/``SessionStore`` (temp SQLite),
saves it, then drives a fresh ``SessionManagerDialog`` -- wired to a fake
``MainWindow``-shaped parent exposing the same ``_chat_panel`` /
``_orchestrator`` / ``_on_binary_loaded`` surface the real ``MainWindow``
exposes -- through the real "Load Session" flow and asserts the restored
state actually lands in the live ``ChatPanel`` widget and the fake window's
binary-activation hook. No mocks stand in for the behaviour under test: the
chat panel is a real ``ChatPanel``, the binary hook is a small real method
(not a recording stub), and persistence goes through the real SQLite-backed
store.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget

from intellicrack.core.session import Session, SessionManager
from intellicrack.core.types import BinaryInfo, Message, ProviderName
from intellicrack.ui import session_manager as session_manager_module
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.session_manager import SessionManagerDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.core.orchestrator import Orchestrator


pytestmark = pytest.mark.usefixtures("qapp")


@pytest.fixture(autouse=True)
def _isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect the on-disk sidecar sessions directory into ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(SessionManagerDialog, "SESSIONS_DIR", tmp_path / "sidecar_sessions")


class _FakeMainWindow(QWidget):
    """Minimal QWidget mirroring the exact shape ``MainWindow`` exposes to the dialog.

    Exposes ``_orchestrator`` (adopted by ``SessionManagerDialog`` at its
    real production call site, ``app.py``'s ``_on_load_session``),
    ``_chat_panel`` (a real ``ChatPanel``, the same widget
    ``MainWindow.message_received`` feeds via ``add_message``), and
    ``_on_binary_loaded`` (a real, minimal re-implementation of
    ``MainWindow._on_binary_loaded``'s state-tracking half: recording the
    activated binary's path on ``current_binary``, exactly as the production
    method does before it goes on to touch tool buttons and the hex editor).

    Attributes:
        current_binary: Path of the most recently activated binary, or
            ``None`` when no binary has been activated.
    """

    current_binary: Path | None

    def __init__(self, orchestrator: Orchestrator) -> None:
        """Initialise the fake main window with a live orchestrator and a real chat panel.

        Args:
            orchestrator: Orchestrator instance to expose as ``_orchestrator``.
        """
        super().__init__()
        self._orchestrator = orchestrator
        self._chat_panel = ChatPanel(self)
        self.current_binary = None

    def _on_binary_loaded(self, result: object) -> None:
        """Record the activated binary's path, mirroring ``MainWindow._on_binary_loaded``.

        Args:
            result: The ``BinaryInfo`` restored for the loaded session.
        """
        if isinstance(result, BinaryInfo):
            self.current_binary = result.path


def _build_saved_session(manager: SessionManager, tmp_path: Path) -> Session:
    """Create, populate, and persist a session with chat history and an active binary.

    Args:
        manager: Real session manager backed by a temp SQLite store.
        tmp_path: Pytest temporary directory fixture, used for the binary path.

    Returns:
        Session: The persisted session, with two messages and one active binary.
    """
    session = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "test-model", "Restorable Session"))
    assert isinstance(session, Session)

    session.add_message(Message(role="user", content="What does this binary do?"))
    session.add_message(Message(role="assistant", content="It looks like a license-check routine."))

    binary_path = tmp_path / "target.exe"
    binary_path.write_bytes(b"MZ\x90\x00")
    session.add_binary(
        BinaryInfo(
            path=binary_path,
            name="target.exe",
            size=binary_path.stat().st_size,
            sha256="a" * 64,
            file_type="PE",
            architecture="x86_64",
            is_64bit=True,
            entry_point=0x1000,
            sections=[],
            imports=[],
            exports=[],
        ),
    )

    run_bridge_coroutine(manager.save())
    return session


def _row_for_session(dialog: SessionManagerDialog, session_id: str) -> int:
    """Find the session table row whose ``UserRole`` data is ``session_id``.

    Args:
        dialog: The session-manager dialog.
        session_id: Session identifier to locate.

    Returns:
        int: The matching row index.
    """
    table = dialog._session_table
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and item.data(Qt.ItemDataRole.UserRole) == session_id:
            return row
    pytest.fail(f"no table row found for session id {session_id!r}")


def _close_dialog_deterministically(dialog: SessionManagerDialog) -> None:
    """Tear down ``dialog`` deterministically instead of leaving it to GC-timed cleanup.

    ``dialog`` is constructed with a real Qt ``parent`` (mirroring the
    production ``SessionManagerDialog(parent=self)`` call site), so it is
    intentionally *not* separately registered with ``qtbot.addWidget`` --
    doing so would let both the widget's C++ parent-child ownership cascade
    and pytest-qt's own registered-widget cleanup each try to destroy the
    same dialog, which raises ``RuntimeError: wrapped C/C++ object ... has
    been deleted`` when the second attempt runs against an already-deleted
    object. This drains any bridge worker thread still parented under the
    dialog (so a queued cross-thread ``call_finished``/``call_error`` signal
    cannot fire against it after its C++ object is gone), closes it, and
    flushes pending deferred-delete events so destruction is ordered before
    the test function returns.

    Args:
        dialog: The dialog under test to close and drain.
    """
    drain_bridge_workers_for(dialog)
    dialog.close()
    app = QApplication.instance()
    if app is not None:
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        app.processEvents()


def test_load_session_restores_chat_history_and_active_binary(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_orchestrator: Orchestrator,
) -> None:
    """Loading a saved session must push its chat history and active binary into the live UI.

    Builds a session with two chat messages and an active binary through the
    real orchestrator-backed ``SessionManager``, then creates a *fresh* UI
    (empty ``ChatPanel``, no active binary) via a dialog constructed exactly
    the way the real production call site constructs it
    (``SessionManagerDialog(parent=self)``, adopting ``parent._orchestrator``).
    Selecting the saved session and confirming "Load Session" must leave the
    fresh chat panel populated with the saved messages, in order, and the
    fake window's ``current_binary`` set to the saved binary's path -- proving
    the restore-to-UI calls actually ran rather than only emitting
    ``session_loaded`` with no observable UI effect.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture (isolates the blocking modal confirm).
        real_orchestrator: Real Orchestrator fixture with a SQLite-backed session manager.
    """
    manager = real_orchestrator._sessions
    saved = _build_saved_session(manager, tmp_path)

    # A fresh UI: no active session, empty chat panel, no binary activated.
    parent = _FakeMainWindow(real_orchestrator)
    qtbot.addWidget(parent)
    assert parent._chat_panel.get_messages() == []
    assert parent.current_binary is None

    dialog = SessionManagerDialog(parent=parent)
    assert dialog._current_session_id is None, "fresh UI must start with no active session"
    dialog._session_table.selectRow(_row_for_session(dialog, saved.id))

    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "question",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes),
    )

    with qtbot.waitSignal(dialog.session_loaded, timeout=5_000) as blocker:
        dialog._load_selected_session()
    assert blocker.args == [saved.id]

    restored_messages = parent._chat_panel.get_messages()
    assert [(m.role, m.content) for m in restored_messages] == [
        ("user", "What does this binary do?"),
        ("assistant", "It looks like a license-check routine."),
    ], "chat panel was not repopulated with the saved session's message history"

    assert parent.current_binary == saved.binaries[0].path, "active binary from the saved session was not restored into the live UI"

    assert real_orchestrator.current_session is not None
    assert real_orchestrator.current_session.id == saved.id, (
        "orchestrator's own current_session pointer must follow the loaded session, not stay stale"
    )

    _close_dialog_deterministically(dialog)


def test_load_session_surfaces_error_for_stale_selection(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_orchestrator: Orchestrator,
) -> None:
    """A row selected for a session no longer in the listed sessions must surface a clear, synchronous error.

    Simulates a stale table selection: the session was listed when the
    dialog was constructed but is no longer present in ``self._sessions``
    by the time "Load Session" is confirmed (for example, a concurrent
    delete that has not yet been reflected by a table refresh) -- the same
    "not found" case a genuinely malformed/missing session file would hit.
    ``_load_session_via_manager`` guards against this synchronously, before
    dispatching anything to the bridge event loop, so the warning must
    already be present the instant ``_load_selected_session`` returns --
    no waiting on an async round trip is involved or required.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture (isolates the blocking modals).
        real_orchestrator: Real Orchestrator fixture with a SQLite-backed session manager.
    """
    manager = real_orchestrator._sessions
    saved = _build_saved_session(manager, tmp_path)

    parent = _FakeMainWindow(real_orchestrator)
    qtbot.addWidget(parent)

    dialog = SessionManagerDialog(parent=parent)
    dialog._session_table.selectRow(_row_for_session(dialog, saved.id))

    # The row is still selected and still shows the (now stale) session,
    # but it has dropped out of the listed sessions the load guard checks.
    dialog._sessions = [s for s in dialog._sessions if s["id"] != saved.id]

    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "question",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes),
    )
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "warning",
        staticmethod(lambda *args, **_k: warnings.append(args)),
    )

    loaded_ids: list[str] = []
    dialog.session_loaded.connect(loaded_ids.append)

    dialog._load_selected_session()

    assert warnings, "a stale/unknown session selection must surface a warning synchronously, without touching the bridge loop"
    assert not loaded_ids, "session_loaded must not fire for a session that failed to load"
    assert dialog.result() != QDialog.DialogCode.Accepted, "dialog must not accept() after a failed load"
    assert parent._chat_panel.get_messages() == [], "chat panel must stay untouched when the load fails"

    _close_dialog_deterministically(dialog)
