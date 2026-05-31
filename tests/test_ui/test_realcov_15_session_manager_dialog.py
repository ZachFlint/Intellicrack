# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :class:`SessionManagerDialog`.

The session-manager dialog was previously untested. These tests back it with
a real :class:`SessionManager` over a real SQLite :class:`SessionStore`,
create real sessions through the manager, and then exercise the dialog's
load/delete flows end-to-end:

* The session table is populated from the real store via ``list_sessions``.
* Loading the selected session emits ``session_loaded`` with the real id.
* Deleting the selected session emits ``session_deleted`` and actually
  removes the row from the backing SQLite database.

Only the blocking modal confirmation (``QMessageBox.question``) is isolated --
it cannot run headlessly and is not the capability under test. The deletion
itself runs through the real ``SessionManager.delete`` / ``SessionStore``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.types import ProviderName
from intellicrack.ui import session_manager as session_manager_module
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.session_manager import SessionManagerDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


def _make_manager(tmp_path: Path) -> SessionManager:
    """Build a real :class:`SessionManager` over a temp SQLite store.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        SessionManager: Manager backed by a fresh SQLite database.
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    return SessionManager(store=store, auto_save=False)


def _create_session(manager: SessionManager, name: str) -> Session:
    """Create and persist a session through the manager's bridge loop.

    Args:
        manager: The session manager.
        name: Human-readable session name.

    Returns:
        Session: The created session.
    """
    session = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "test-model", name))
    assert isinstance(session, Session)
    return session


def _select_first_row(dialog: SessionManagerDialog) -> None:
    """Select the first row of the dialog's session table.

    Args:
        dialog: The session-manager dialog.
    """
    table = dialog._session_table
    assert table.rowCount() > 0
    table.selectRow(0)


def test_dialog_lists_real_sessions(qtbot: QtBot, tmp_path: Path) -> None:
    """The dialog table is populated from the real store.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    manager = _make_manager(tmp_path)
    created = _create_session(manager, "Alpha Session")

    dialog = SessionManagerDialog(session_manager=manager)
    qtbot.addWidget(dialog)

    table = dialog._session_table
    assert table.rowCount() == 1
    name_item = table.item(0, 0)
    assert name_item is not None
    assert name_item.data(Qt.ItemDataRole.UserRole) == created.id
    dialog.close()


def test_load_emits_session_loaded_signal(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loading the selected session emits ``session_loaded`` with the real id.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the modal confirm).
    """
    manager = _make_manager(tmp_path)
    created = _create_session(manager, "Loadable Session")

    dialog = SessionManagerDialog(session_manager=manager)
    qtbot.addWidget(dialog)
    _select_first_row(dialog)

    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "question",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes),
    )

    with qtbot.waitSignal(dialog.session_loaded, timeout=2_000) as blocker:
        dialog._load_selected_session()

    assert blocker.args == [created.id]


def test_delete_removes_session_from_real_store(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting emits ``session_deleted`` and removes the row from SQLite.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the modal confirm).
    """
    manager = _make_manager(tmp_path)
    keep = _create_session(manager, "Keep Session")
    doomed = _create_session(manager, "Doomed Session")
    assert len(manager.list_sessions()) == 2

    dialog = SessionManagerDialog(session_manager=manager)
    qtbot.addWidget(dialog)

    table = dialog._session_table
    doomed_row = next(
        row
        for row in range(table.rowCount())
        if (item := table.item(row, 0)) is not None and item.data(Qt.ItemDataRole.UserRole) == doomed.id
    )
    table.selectRow(doomed_row)

    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "question",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes),
    )

    with qtbot.waitSignal(dialog.session_deleted, timeout=2_000) as blocker:
        dialog._delete_session()

    assert blocker.args == [doomed.id]
    remaining_ids = {meta.id for meta in manager.list_sessions()}
    assert doomed.id not in remaining_ids
    assert keep.id in remaining_ids
    dialog.close()
