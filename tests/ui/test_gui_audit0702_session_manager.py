# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``session_manager``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``test_h19_*`` (H19): session deletion must dispatch through the
  non-blocking bridge worker instead of blocking the GUI thread inside
  ``run_bridge_coroutine``'s ``future.result(timeout=None)``.
* ``test_h20_*`` (H20): session import must dispatch through the same
  non-blocking worker rather than blocking the GUI thread for the duration
  of the SQLite write.
* ``test_h29_*`` (H29): the dialog's only production call site
  (``SessionManagerDialog(parent=self)``) must adopt the parent's live
  ``Orchestrator`` session manager and active session instead of silently
  falling back to the empty on-disk sidecar store, and the
  ``SessionManagerDialog.from_orchestrator`` factory must wire the same
  state directly.
* ``test_m17_*`` (M17): tag add/remove persistence must dispatch through
  the non-blocking bridge worker instead of blocking the GUI thread.

The threading gates (H19, H20, M17) prove non-blocking dispatch by wiring a
``SessionManager`` subclass whose persistence method sleeps for a
measurable delay before delegating to the real implementation, then
asserting the GUI-thread call that triggers persistence returns long
before that delay elapses. Blocking pre-fix code (``run_bridge_coroutine``)
would make the same call site wait for the full delay before returning.

All tests drive real ``SessionManagerDialog``, ``SessionManager``, and
``SessionStore`` (backed by a real temporary SQLite database) instances
under an offscreen ``QApplication``. No mocks stand in for the behaviour
under test.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox, QWidget

from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.types import ProviderName
from intellicrack.ui import session_manager as session_manager_module
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.session_manager import SessionManagerDialog


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.core.orchestrator import Orchestrator


pytestmark = pytest.mark.usefixtures("qapp")

_DELAY_S: float = 1.0
"""Injected delay, in seconds, added to the delayed manager subclasses below."""

_RETURN_THRESHOLD_S: float = 0.4
"""Ceiling, in seconds, a non-blocking GUI-thread call site must return within.

Well under ``_DELAY_S`` so a call site that still blocks on the delayed
coroutine's result is guaranteed to exceed it, while QThread start-up
overhead alone stays far below it.
"""

_WAIT_TIMEOUT_MS: int = int((_DELAY_S + 3.0) * 1000)
"""Timeout, in milliseconds, for waiting on the delayed operation to finish."""


@pytest.fixture(autouse=True)
def _isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect the on-disk sidecar sessions directory into ``tmp_path``.

    Prevents every test in this module from touching the real
    per-user config directory that ``SessionManagerDialog.SESSIONS_DIR``
    defaults to.

    Args:
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(SessionManagerDialog, "SESSIONS_DIR", tmp_path / "sidecar_sessions")


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


def _write_import_json(path: Path, session_id: str, name: str) -> None:
    """Write a minimal session export JSON file suitable for import.

    Matches the wrapped ``{"session": {...}}`` format produced by
    ``SessionStore.export_to_json`` and consumed by
    ``SessionStore.import_from_json``.

    Args:
        path: Destination file path.
        session_id: Session identifier to embed.
        name: Human-readable session name to embed.
    """
    now = datetime.now(tz=UTC).isoformat()
    payload = {
        "export_version": "1.0",
        "exported_at": now,
        "session": {
            "id": session_id,
            "name": name,
            "created_at": now,
            "updated_at": now,
            "provider": ProviderName.OLLAMA.value,
            "model": "test-model",
            "tags": [],
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


class _DelayedDeleteManager(SessionManager):
    """``SessionManager`` whose ``delete`` sleeps before delegating.

    Makes the blocking-vs-non-blocking distinction directly observable: a
    caller that blocks the calling thread on the coroutine's result takes
    at least ``_DELAY_S`` to return, while a caller that dispatches to the
    non-blocking bridge worker returns almost immediately.
    """

    async def delete(self, session_id: str) -> bool:
        """Delete ``session_id`` after an injected delay.

        Args:
            session_id: Session identifier to delete.

        Returns:
            bool: True if deleted.
        """
        await asyncio.sleep(_DELAY_S)
        return await super().delete(session_id)


class _DelayedImportManager(SessionManager):
    """``SessionManager`` whose ``import_json`` sleeps before delegating."""

    async def import_json(self, path: Path, *, replace: bool = False) -> Session:
        """Import ``path`` after an injected delay.

        Args:
            path: Path to the JSON file.
            replace: Whether to replace an existing session with the same ID.

        Returns:
            Session: Imported Session instance.
        """
        await asyncio.sleep(_DELAY_S)
        return await super().import_json(path, replace=replace)


class _DelayedUpdateManager(SessionManager):
    """``SessionManager`` whose ``update`` sleeps before delegating."""

    async def update(self, session: Session) -> None:
        """Update ``session`` after an injected delay.

        Args:
            session: Session to update.
        """
        await asyncio.sleep(_DELAY_S)
        await super().update(session)


class _FakeMainWindow(QWidget):
    """Minimal QWidget exposing an ``_orchestrator`` attribute.

    Mirrors the exact shape ``MainWindow`` exposes to
    ``SessionManagerDialog(parent=self)`` at the dialog's only production
    call site (``app.py``'s ``_on_load_session``), without constructing the
    full ``MainWindow``.
    """

    def __init__(self, orchestrator: Orchestrator) -> None:
        """Initialise the fake main window with a live orchestrator.

        Args:
            orchestrator: Orchestrator instance to expose as ``_orchestrator``.
        """
        super().__init__()
        self._orchestrator = orchestrator


def test_h19_delete_returns_before_blocking_and_completes_via_worker(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deleting a session must not block the GUI thread on the SQLite write.

    Pre-fix, ``_delete_session`` routed through
    ``run_bridge_coroutine(self._manager.delete(session_id))`` -- the
    documented blocking variant that calls ``future.result(timeout=None)``
    on the calling (GUI) thread -- so the call would not return until the
    injected ``_DELAY_S`` inside ``_DelayedDeleteManager.delete`` elapsed.
    Post-fix, ``_delete_session_via_manager`` dispatches through
    ``run_bridge_coroutine_logged`` -> ``run_bridge_coroutine_async``, which
    starts a ``BridgeCallWorker`` QThread and returns immediately; the
    deletion completes later and is observed through the ``session_deleted``
    signal.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the blocking modal confirm).
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    manager = _DelayedDeleteManager(store=store, auto_save=False)
    doomed = _create_session(manager, "Doomed Session")

    dialog = SessionManagerDialog(session_manager=manager, current_session_id="not-the-doomed-session")
    qtbot.addWidget(dialog)
    dialog._session_table.selectRow(_row_for_session(dialog, doomed.id))

    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "question",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Yes),
    )

    emitted: list[str] = []
    dialog.session_deleted.connect(emitted.append)

    start = time.perf_counter()
    dialog._delete_session()
    elapsed = time.perf_counter() - start

    assert elapsed < _RETURN_THRESHOLD_S, (
        f"_delete_session blocked the GUI thread for {elapsed:.3f}s waiting on the "
        f"{_DELAY_S}s delayed coroutine instead of dispatching to the non-blocking bridge worker"
    )
    assert not emitted, "deletion completed synchronously; the injected delay was not honoured"

    qtbot.waitUntil(lambda: bool(emitted), timeout=_WAIT_TIMEOUT_MS)
    assert emitted == [doomed.id]

    remaining_ids = {meta.id for meta in manager.list_sessions()}
    assert doomed.id not in remaining_ids
    dialog.close()


def test_h20_import_returns_before_blocking_and_completes_via_worker(
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Importing a session must not block the GUI thread on the SQLite write.

    Pre-fix, ``_import_via_manager`` routed through
    ``run_bridge_coroutine(manager.import_json(path, replace=replace))`` --
    the blocking variant -- so the call would not return until the injected
    ``_DELAY_S`` inside ``_DelayedImportManager.import_json`` elapsed.
    Post-fix, it dispatches through ``run_bridge_coroutine_logged`` and
    returns immediately; completion is observed through the "Import
    Complete" ``QMessageBox.information`` call made by
    ``_on_import_via_manager_succeeded``.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the file picker and info dialog).
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    manager = _DelayedImportManager(store=store, auto_save=False)

    import_path = tmp_path / "imported_session.json"
    import_id = "imported-session-id"
    _write_import_json(import_path, import_id, "Imported Session")

    dialog = SessionManagerDialog(session_manager=manager)
    qtbot.addWidget(dialog)
    assert dialog._sessions == []

    monkeypatch.setattr(
        session_manager_module.QFileDialog,
        "getOpenFileName",
        staticmethod(lambda *_a, **_k: (str(import_path), "")),
    )
    info_calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        session_manager_module.QMessageBox,
        "information",
        staticmethod(lambda *args, **_k: info_calls.append(args)),
    )

    start = time.perf_counter()
    dialog._import_session()
    elapsed = time.perf_counter() - start

    assert elapsed < _RETURN_THRESHOLD_S, (
        f"_import_session blocked the GUI thread for {elapsed:.3f}s waiting on the "
        f"{_DELAY_S}s delayed coroutine instead of dispatching to the non-blocking bridge worker"
    )
    assert not info_calls, "import completed synchronously; the injected delay was not honoured"
    assert import_id not in {s["id"] for s in dialog._sessions}

    qtbot.waitUntil(lambda: bool(info_calls), timeout=_WAIT_TIMEOUT_MS)

    imported_ids = {meta.id for meta in manager.list_sessions()}
    assert import_id in imported_ids
    assert import_id in {s["id"] for s in dialog._sessions}, "dialog did not reload sessions after import completed"
    dialog.close()


def test_m17_tag_add_returns_before_blocking_and_persists_via_worker(
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Adding a tag must not block the GUI thread on the SQLite write.

    Pre-fix, ``_on_tags_changed`` routed through
    ``run_bridge_coroutine(manager.update(session))`` -- the blocking
    variant -- so the tag-chip click handler would not return until the
    injected ``_DELAY_S`` inside ``_DelayedUpdateManager.update`` elapsed.
    Post-fix, it dispatches through ``run_bridge_coroutine_logged`` and
    returns immediately; the persisted tag is only observable in the
    backing SQLite store once the delayed write actually completes.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temporary directory.
    """
    store = SessionStore(db_path=tmp_path / "sessions.db")
    manager = _DelayedUpdateManager(store=store, auto_save=False)
    session = _create_session(manager, "Tagged Session")

    dialog = SessionManagerDialog(session_manager=manager, current_session=session)
    qtbot.addWidget(dialog)
    assert dialog._tag_chips.session() is session
    assert dialog._tag_chips._add_btn.isEnabled()

    dialog._tag_chips._tag_input.setText("urgent")

    start = time.perf_counter()
    dialog._tag_chips._on_add_clicked()
    elapsed = time.perf_counter() - start

    assert elapsed < _RETURN_THRESHOLD_S, (
        f"tag-add handler blocked the GUI thread for {elapsed:.3f}s waiting on the "
        f"{_DELAY_S}s delayed coroutine instead of dispatching to the non-blocking bridge worker"
    )
    assert "urgent" in session.tags, "in-memory tag mutation must still happen synchronously"

    def _persisted() -> bool:
        """Poll whether the delayed write landed the tag in SQLite.

        Returns:
            bool: True once the stored session's tags include ``"urgent"``.
        """
        try:
            stored = manager.store.load(session.id)
        except sqlite3.OperationalError:
            return False
        return stored is not None and "urgent" in stored.tags

    assert not _persisted(), "tag was already persisted synchronously; the injected delay was not honoured"
    qtbot.waitUntil(_persisted, timeout=_WAIT_TIMEOUT_MS)
    dialog.close()


def test_h29_parent_orchestrator_wires_live_manager_and_active_session(
    qtbot: QtBot,
    real_orchestrator: Orchestrator,
) -> None:
    """``SessionManagerDialog(parent=self)`` must adopt the parent's live orchestrator state.

    Pre-fix, the dialog's only production call site
    (``app.py``'s ``_on_load_session``: ``SessionManagerDialog(parent=self)``)
    left ``self._manager``/``self._current_session``/``self._current_session_id``
    at their ``None`` defaults, so the dialog fell back to the empty on-disk
    sidecar store instead of the orchestrator's live, SQLite-backed
    ``SessionManager``, the active-session delete-protection guard never
    fired (it compared against ``None``), and the tags editor stayed
    permanently disabled. Post-fix, ``_adopt_parent_orchestrator`` reads
    ``parent._orchestrator`` and wires all three.

    Args:
        qtbot: pytest-qt bot fixture.
        real_orchestrator: Real Orchestrator fixture with a SQLite-backed session manager.
    """
    manager = real_orchestrator._sessions
    active = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "active-model", "Active Session"))
    other = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "other-model", "Other Session"))
    assert isinstance(active, Session)
    assert isinstance(other, Session)
    real_orchestrator._current_session = active

    parent = _FakeMainWindow(real_orchestrator)
    qtbot.addWidget(parent)

    dialog = SessionManagerDialog(parent=parent)
    qtbot.addWidget(dialog)

    assert dialog._manager is manager, "dialog did not adopt the orchestrator's live SessionManager"
    assert dialog._current_session is active
    assert dialog._current_session_id == active.id

    live_ids = {meta.id for meta in manager.list_sessions()}
    dialog_ids = {s["id"] for s in dialog._sessions}
    assert dialog_ids == live_ids, "dialog sessions were not loaded from the live SessionManager"
    assert {active.id, other.id} <= dialog_ids

    assert dialog._tag_chips.session() is active
    assert dialog._tag_chips._add_btn.isEnabled(), "tag editor stayed disabled despite a wired active session"

    dialog._session_table.selectRow(_row_for_session(dialog, active.id))
    assert not dialog._delete_btn.isEnabled(), "delete-protection guard did not disable Delete for the active session"

    dialog._session_table.selectRow(_row_for_session(dialog, other.id))
    assert dialog._delete_btn.isEnabled(), "Delete stayed disabled for a non-active session"

    dialog.close()


def test_h29_from_orchestrator_factory_wires_manager_and_active_session(
    qtbot: QtBot,
    real_orchestrator: Orchestrator,
) -> None:
    """``SessionManagerDialog.from_orchestrator`` wires the live manager and active session.

    This factory method did not exist pre-fix; callers had no way to build
    a dialog explicitly bound to an orchestrator's live session state other
    than manually threading through ``session_manager``/``current_session``.

    Args:
        qtbot: pytest-qt bot fixture.
        real_orchestrator: Real Orchestrator fixture with a SQLite-backed session manager.
    """
    manager = real_orchestrator._sessions
    active = run_bridge_coroutine(manager.create(ProviderName.OLLAMA, "active-model", "Active Session"))
    assert isinstance(active, Session)
    real_orchestrator._current_session = active

    dialog = SessionManagerDialog.from_orchestrator(real_orchestrator)
    qtbot.addWidget(dialog)

    assert dialog._manager is manager
    assert dialog._current_session is active
    assert dialog._current_session_id == active.id
    assert {s["id"] for s in dialog._sessions} == {meta.id for meta in manager.list_sessions()}
    dialog.close()
