# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the tag chips, the sidecar-store paths and the manager flows of the session manager dialog.

Every test drives the production widgets with real objects: a genuine ``TagChipsWidget`` and its flow layout, a real ``SessionManagerDialog``
backed either by sidecar JSON files written under ``tmp_path`` or by a real ``SessionManager`` over a SQLite ``SessionStore``, a real
``ChatPanel`` as the restore target and the real asynchronous bridge worker behind the manager-backed flows. Qt's static dialog functions are
replaced by plain functions that record what the user would have seen and return a chosen answer. Expected values come from the file
formats, the Python standard library or hand arithmetic, and exported and imported files are checked by parsing them with ``json``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtCore import QRect, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpacerItem,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QWidget,
)

from intellicrack.core.session import Session, SessionManager, SessionMetadata, SessionStore
from intellicrack.core.types import BinaryInfo, Message
from intellicrack.providers import ids as provider_ids
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for, run_bridge_coroutine
from intellicrack.ui.session_manager import NewSessionDialog, SessionManagerDialog, TagChipsWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_Entry = tuple[str, str, str]
_Log = list[_Entry]

_WAIT_MS: int = 10_000
_CHIP_MARGIN: int = 4
_CHIP_GAP: int = 6
_NARROW_WIDTH: int = 20
_TALL_HEIGHT: int = 200
_SPACER_SIZE: int = 5
_PREVIEW_LIMIT: int = 100
_CREATED: str = "2020-03-01T10:00:00+00:00"
_UPDATED: str = "2020-03-05T12:34:56+00:00"
_MINUTE_FORMAT: str = "%Y-%m-%d %H:%M"
_USER_ROLE = Qt.ItemDataRole.UserRole
_JSON_FILTER: str = "JSON Files (*.json);;All Files (*)"


class _ScriptedManager(SessionManager):
    """``SessionManager`` whose listing, deletion and loading can be told to fail or to return chosen rows.

    Attributes:
        listing: Metadata rows ``list_sessions`` returns instead of the store's rows, or ``None`` to use the store.
        fail_listing: Whether ``list_sessions`` raises ``TypeError``.
        fail_delete: Whether ``delete`` raises ``RuntimeError("disk on fire")``.
        fail_load: Whether ``load`` raises ``RuntimeError("cannot open")``.
    """

    listing: list[SessionMetadata] | None
    fail_listing: bool
    fail_delete: bool
    fail_load: bool

    def __init__(self, store: SessionStore) -> None:
        """Create the manager with auto-save off.

        Args:
            store: Store the manager persists to.
        """
        super().__init__(store=store, auto_save=False)
        self.listing = None
        self.fail_listing = False
        self.fail_delete = False
        self.fail_load = False

    @override
    def list_sessions(self, limit: int = 100) -> list[SessionMetadata]:
        """List sessions, or fail or substitute rows as scripted.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            list[SessionMetadata]: The scripted rows, or the store's rows.

        Raises:
            TypeError: When ``fail_listing`` is set.
        """
        if self.fail_listing:
            message = "listing unavailable"
            raise TypeError(message)
        if self.listing is not None:
            return list(self.listing)
        return super().list_sessions(limit)

    @override
    async def delete(self, session_id: str) -> bool:
        """Delete a session, or fail as scripted.

        Args:
            session_id: Session identifier.

        Returns:
            bool: Whether a row was deleted.

        Raises:
            RuntimeError: When ``fail_delete`` is set.
        """
        if self.fail_delete:
            message = "disk on fire"
            raise RuntimeError(message)
        return await super().delete(session_id)

    @override
    async def load(self, session_id: str) -> Session | None:
        """Load a session, or fail as scripted.

        Args:
            session_id: Session identifier.

        Returns:
            Session | None: The loaded session, or ``None`` when it is missing.

        Raises:
            RuntimeError: When ``fail_load`` is set.
        """
        if self.fail_load:
            message = "cannot open"
            raise RuntimeError(message)
        return await super().load(session_id)


class _RejectingSession(Session):
    """``Session`` whose ``add_tag`` always rejects the tag, as a session with stricter validation would."""

    @override
    def add_tag(self, tag: str) -> bool:
        """Reject every tag.

        Args:
            tag: Tag the caller wanted to add.

        Returns:
            bool: Never returns normally.

        Raises:
            ValueError: Always, naming the rejected tag.
        """
        message = f"rejected {tag}"
        raise ValueError(message)


def _widget[T](owner: object, name: str, kind: type[T]) -> T:
    """Read a private attribute of ``owner`` and check its type.

    Args:
        owner: Object holding the attribute.
        name: Attribute name.
        kind: Type the attribute must have.

    Returns:
        T: The attribute value.
    """
    value: object = getattr(owner, name)
    assert isinstance(value, kind)
    return value


def _method(owner: object, name: str) -> Callable[..., object]:
    """Read a private method of ``owner``.

    Args:
        owner: Object (or class) holding the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method.
    """
    method: Callable[..., object] = getattr(owner, name)
    return method


def _attach(owner: object, name: str, value: object) -> None:
    """Set a data attribute on ``owner``.

    Args:
        owner: Object to modify.
        name: Attribute name.
        value: Attribute value.
    """
    setattr(owner, name, value)


def _table(dialog: SessionManagerDialog) -> QTableWidget:
    """Return the dialog's session table.

    Args:
        dialog: Dialog under test.

    Returns:
        QTableWidget: The session table.
    """
    return _widget(dialog, "_session_table", QTableWidget)


def _ids(dialog: SessionManagerDialog) -> list[str]:
    """Read the session ids of the table rows, top to bottom.

    Args:
        dialog: Dialog under test.

    Returns:
        list[str]: Session id stored on each row's name cell.
    """
    table = _table(dialog)
    found: list[str] = []
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        assert item is not None
        found.append(str(item.data(_USER_ROLE)))
    return found


def _rows(dialog: SessionManagerDialog) -> list[tuple[str, ...]]:
    """Read the cell text of every table row.

    Args:
        dialog: Dialog under test.

    Returns:
        list[tuple[str, ...]]: Name, created, modified and message-count text for each row.
    """
    table = _table(dialog)
    rows: list[tuple[str, ...]] = []
    for row in range(table.rowCount()):
        cells: list[str] = []
        for column in range(table.columnCount()):
            item = table.item(row, column)
            assert item is not None
            cells.append(item.text())
        rows.append(tuple(cells))
    return rows


def _row_of(dialog: SessionManagerDialog, session_id: str) -> int:
    """Find the table row that carries ``session_id``.

    Args:
        dialog: Dialog under test.
        session_id: Session identifier to find.

    Returns:
        int: Row index.
    """
    table = _table(dialog)
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and item.data(_USER_ROLE) == session_id:
            return row
    pytest.fail(f"no table row for session {session_id!r}")


def _select(dialog: SessionManagerDialog, session_id: str) -> None:
    """Select the table row of ``session_id``.

    Args:
        dialog: Dialog under test.
        session_id: Session identifier to select.
    """
    _table(dialog).selectRow(_row_of(dialog, session_id))


def _write_sidecar(directory: Path, stem: str, payload: object) -> Path:
    """Write a sidecar session file.

    Args:
        directory: Sidecar directory.
        stem: File name without the ``.json`` suffix.
        payload: Value serialized as the file's JSON.

    Returns:
        Path: The written file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{stem}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _sidecar_payload(session_id: str, name: str) -> dict[str, object]:
    """Build a minimal well-formed sidecar session.

    Args:
        session_id: Session identifier.
        name: Session display name.

    Returns:
        dict[str, object]: The sidecar payload.
    """
    return {
        "id": session_id,
        "name": name,
        "created_at": _CREATED,
        "updated_at": _UPDATED,
        "provider": provider_ids.OLLAMA,
        "model": "test-model",
        "message_count": 0,
    }


def _kinds(log: _Log, kind: str) -> list[tuple[str, str]]:
    """Pick the recorded dialogs of one kind.

    Args:
        log: Recorded dialogs.
        kind: ``warning``, ``information`` or ``question``.

    Returns:
        list[tuple[str, str]]: Title and text of each matching dialog.
    """
    return [(title, text) for entry_kind, title, text in log if entry_kind == kind]


def _session(tags: tuple[str, ...] = ()) -> Session:
    """Create an in-memory session carrying ``tags``.

    Args:
        tags: Tags to add.

    Returns:
        Session: The session.
    """
    session = Session.create(provider_ids.OLLAMA, "test-model", "Chip Session")
    for tag in tags:
        added = session.add_tag(tag)
        assert added
    return session


def _create(manager: SessionManager, name: str) -> Session:
    """Create and persist a session through the manager.

    Args:
        manager: Session manager.
        name: Session display name.

    Returns:
        Session: The created session.
    """
    session = run_bridge_coroutine(manager.create(provider_ids.OLLAMA, "test-model", name))
    assert isinstance(session, Session)
    return session


def _chips(session: Session | None, qtbot: QtBot) -> TagChipsWidget:
    """Build a tag chips widget registered for cleanup.

    Args:
        session: Session the widget edits, or ``None``.
        qtbot: pytest-qt bot.

    Returns:
        TagChipsWidget: The widget.
    """
    chips = TagChipsWidget(session)
    qtbot.addWidget(chips)
    return chips


@pytest.fixture(autouse=True)
def sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the dialog's sidecar directory at ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Path: The sidecar directory, which does not exist yet.
    """
    directory = tmp_path / "sidecar_sessions"
    monkeypatch.setattr(SessionManagerDialog, "SESSIONS_DIR", directory)
    return directory


@pytest.fixture
def shown(monkeypatch: pytest.MonkeyPatch) -> _Log:
    """Replace the message-box statics with plain recording functions that answer Yes.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        _Log: Kind, title and text of every message box the code under test opened.
    """
    log: _Log = []

    def _recorder(kind: str) -> Callable[..., QMessageBox.StandardButton]:
        """Build a replacement static function for one message-box kind.

        Args:
            kind: Kind recorded with each call.

        Returns:
            Callable[..., QMessageBox.StandardButton]: Function answering Yes.
        """

        def _record(_parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            """Record the dialog and answer Yes.

            Args:
                _parent: Parent widget.
                title: Dialog title.
                text: Dialog text.
                *_args: Ignored extra arguments.
                **_kwargs: Ignored extra keyword arguments.

            Returns:
                QMessageBox.StandardButton: Always ``Yes``.
            """
            log.append((kind, title, text))
            return QMessageBox.StandardButton.Yes

        return _record

    for kind in ("warning", "information", "question", "critical"):
        monkeypatch.setattr(QMessageBox, kind, _recorder(kind))
    return log


@pytest.fixture
def decline(shown: _Log, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every confirmation question answer No while still recording it.

    Args:
        shown: Recorded dialogs.
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _answer_no(_parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Record the question and answer No.

        Args:
            _parent: Parent widget.
            title: Dialog title.
            text: Dialog text.
            *_args: Ignored extra arguments.
            **_kwargs: Ignored extra keyword arguments.

        Returns:
            QMessageBox.StandardButton: Always ``No``.
        """
        shown.append(("question", title, text))
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", _answer_no)


@pytest.fixture
def wait_for(qtbot: QtBot, shown: _Log) -> Callable[[_Entry], _Log]:
    """Build a function that waits until the code under test has opened a given message box.

    Args:
        qtbot: pytest-qt bot.
        shown: Recorded dialogs.

    Returns:
        Callable[[_Entry], _Log]: Function taking a ``(kind, title, text)`` entry and returning the log once it appears.
    """

    def _wait(entry: _Entry) -> _Log:
        """Spin the event loop until ``entry`` was recorded.

        Args:
            entry: Kind, title and text to wait for.

        Returns:
            _Log: The recorded dialogs.
        """
        qtbot.waitUntil(lambda: entry in shown, timeout=_WAIT_MS)
        return shown

    return _wait


@pytest.fixture
def file_picker(monkeypatch: pytest.MonkeyPatch) -> Callable[[str, str], list[tuple[object, ...]]]:
    """Build a function that replaces one ``QFileDialog`` picker with a plain function choosing a fixed path.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        Callable[[str, str], list[tuple[object, ...]]]: Function taking the picker name and the chosen path and returning the
        positional arguments of every call.
    """

    def _install(method: str, chosen: str) -> list[tuple[object, ...]]:
        """Install the replacement picker.

        Args:
            method: ``getOpenFileName`` or ``getSaveFileName``.
            chosen: Path the picker reports.

        Returns:
            list[tuple[object, ...]]: Positional arguments of each call, filled as the picker is used.
        """
        calls: list[tuple[object, ...]] = []

        def _pick(*args: object, **_kwargs: object) -> tuple[str, str]:
            """Report the fixed path.

            Args:
                *args: Dialog arguments, recorded.
                **_kwargs: Ignored keyword arguments.

            Returns:
                tuple[str, str]: The chosen path and an empty filter.
            """
            calls.append(args)
            return (chosen, "")

        monkeypatch.setattr(QFileDialog, method, _pick)
        return calls

    return _install


@pytest.fixture
def manager(tmp_path: Path) -> Generator[SessionManager]:
    """Provide a real session manager over a temporary SQLite store and close it afterwards.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        SessionManager: Manager with auto-save off.
    """
    session_manager = SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False)
    try:
        yield session_manager
    finally:
        run_bridge_coroutine(session_manager.close())


@pytest.fixture
def scripted(tmp_path: Path) -> Generator[_ScriptedManager]:
    """Provide a scriptable session manager over a temporary SQLite store and close it afterwards.

    Args:
        tmp_path: Pytest temporary directory.

    Yields:
        _ScriptedManager: Manager with auto-save off and no scripted failures.
    """
    session_manager = _ScriptedManager(SessionStore(db_path=tmp_path / "sessions.db"))
    try:
        yield session_manager
    finally:
        run_bridge_coroutine(session_manager.close())


@pytest.fixture
def make_dialog(qtbot: QtBot) -> Generator[Callable[..., SessionManagerDialog]]:
    """Provide a factory for session manager dialogs whose workers are joined at teardown.

    Args:
        qtbot: pytest-qt bot.

    Yields:
        Callable[..., SessionManagerDialog]: Factory accepting the keyword arguments ``manager``, ``current_session_id``, ``parent`` and
        ``current_session``.
    """
    created: list[SessionManagerDialog] = []

    def _make(
        *,
        manager: SessionManager | None = None,
        current_session_id: str | None = None,
        parent: QWidget | None = None,
        current_session: Session | None = None,
    ) -> SessionManagerDialog:
        """Build and register a dialog.

        Args:
            manager: Session manager to wire, or ``None`` for the sidecar store.
            current_session_id: Identifier of the active session.
            parent: Parent widget.
            current_session: Active in-memory session.

        Returns:
            SessionManagerDialog: The dialog.
        """
        dialog = SessionManagerDialog(
            session_manager=manager,
            current_session_id=current_session_id,
            parent=parent,
            current_session=current_session,
        )
        if parent is None:
            qtbot.addWidget(dialog)
        created.append(dialog)
        return dialog

    try:
        yield _make
    finally:
        for dialog in created:
            if sip.isdeleted(dialog):
                continue
            drain_bridge_workers_for(dialog)
            if dialog.parent() is not None:
                dialog.close()


def test_flow_layout_ignores_none_and_counts_real_items(qtbot: QtBot) -> None:
    """Adding ``None`` to the flow layout leaves its item count unchanged, adding an item raises it by one.

    Product change that fails it: flow layout ``addItem`` (session_manager.py:107) drop the ``None`` guard so ``None`` is appended.

    Args:
        qtbot: pytest-qt bot.
    """
    chips = _chips(_session(("alpha", "beta")), qtbot)
    layout = _widget(chips, "_chips_layout", QLayout)
    before = layout.count()
    assert before == len(["alpha", "beta"])
    layout.addItem(None)
    assert layout.count() == before
    layout.addItem(QSpacerItem(_SPACER_SIZE, _SPACER_SIZE))
    assert layout.count() == before + 1


def test_flow_layout_set_geometry_stores_rect_wraps_chips_and_skips_spacers(qtbot: QtBot) -> None:
    """``setGeometry`` stores the rectangle and places chips on their own rows when too narrow, ignoring widget-less items.

    A spacer is placed first, so a layout that counted it would push the first chip away from the top-left corner. The width is
    narrower than any chip, so every chip after the first wraps to a new row one chip height plus the vertical gap lower.

    Product change that fails it: ``_do_layout`` (session_manager.py:229) replace ``continue`` with ``pass`` so the spacer takes part in
    the layout.

    Args:
        qtbot: pytest-qt bot.
    """
    session = _session()
    chips = _chips(session, qtbot)
    layout = _widget(chips, "_chips_layout", QLayout)
    layout.addItem(QSpacerItem(_SPACER_SIZE, _SPACER_SIZE))
    for tag in ("alpha", "beta"):
        added = session.add_tag(tag)
        assert added
    chips.set_session(session)

    area = QRect(0, 0, _NARROW_WIDTH, _TALL_HEIGHT)
    layout.setGeometry(area)

    first, second = chips.findChildren(QPushButton, "tagChip")
    assert layout.geometry() == area
    assert (first.x(), first.y()) == (_CHIP_MARGIN, _CHIP_MARGIN)
    assert (second.x(), second.y()) == (_CHIP_MARGIN, _CHIP_MARGIN + first.height() + _CHIP_GAP)


def test_flow_layout_minimum_size_is_widest_chip_plus_margins(qtbot: QtBot) -> None:
    """The minimum size covers the widest and tallest chip item plus the margins on both sides.

    The longer tag is added first, so a loop that kept only the last item would report the narrower chip.

    Product change that fails it: ``minimumSize`` (session_manager.py:204) replace ``expandedTo`` with ``boundedTo``.

    Args:
        qtbot: pytest-qt bot.
    """
    chips = _chips(_session(("a-rather-long-tag-name", "x")), qtbot)
    layout = _widget(chips, "_chips_layout", QLayout)
    items = [layout.itemAt(index) for index in range(layout.count())]
    sizes = [item.minimumSize() for item in items if item is not None]
    assert len({size.width() for size in sizes}) > 1

    size = layout.minimumSize()

    assert size.width() == max(s.width() for s in sizes) + 2 * _CHIP_MARGIN
    assert size.height() == max(s.height() for s in sizes) + 2 * _CHIP_MARGIN


def test_chip_widget_rejected_tag_warns_and_keeps_input(qtbot: QtBot, shown: _Log) -> None:
    """A tag the session rejects raises a warning with the session's message and stays in the input box.

    Product change that fails it: ``_on_add_clicked`` (session_manager.py:395) remove the ``return`` so the input is cleared.

    Args:
        qtbot: pytest-qt bot.
        shown: Recorded dialogs.
    """
    session = _RejectingSession.create(provider_ids.OLLAMA, "test-model", "Strict")
    chips = _chips(session, qtbot)
    added: list[str] = []
    changed: list[list[str]] = []
    chips.tag_added.connect(added.append)
    chips.tags_changed.connect(changed.append)
    tag_input = _widget(chips, "_tag_input", QLineEdit)
    tag_input.setText("  reserved  ")

    _widget(chips, "_add_btn", QPushButton).click()

    assert _kinds(shown, "warning") == [("Invalid Tag", "rejected reserved")]
    assert tag_input.text() == "  reserved  "
    assert (added, changed) == ([], [])
    assert chips.findChildren(QPushButton, "tagChip") == []


def test_chip_widget_duplicate_tag_clears_input_without_chip_or_signal(qtbot: QtBot) -> None:
    """Adding a tag the session already has clears the input but creates no chip and emits nothing.

    Product change that fails it: ``_on_add_clicked`` (session_manager.py:397) replace ``if added:`` with ``if True:``.

    Args:
        qtbot: pytest-qt bot.
    """
    session = _session(("dup",))
    chips = _chips(session, qtbot)
    added: list[str] = []
    chips.tag_added.connect(added.append)
    tag_input = _widget(chips, "_tag_input", QLineEdit)
    tag_input.setText("dup")

    _widget(chips, "_add_btn", QPushButton).click()

    assert not tag_input.text()
    assert added == []
    assert session.tags == ["dup"]
    assert len(chips.findChildren(QPushButton, "tagChip")) == len(["dup"])


def test_chip_click_for_tag_removed_elsewhere_keeps_chip_and_emits_nothing(qtbot: QtBot) -> None:
    """Clicking a chip whose tag the session no longer holds changes nothing.

    Product change that fails it: ``_on_chip_clicked`` (session_manager.py:414) remove the ``return`` so the chip is dropped anyway.

    Args:
        qtbot: pytest-qt bot.
    """
    session = _session(("keep",))
    chips = _chips(session, qtbot)
    removed: list[str] = []
    chips.tag_removed.connect(removed.append)
    chip = chips.findChild(QPushButton, "tagChip")
    assert chip is not None
    session.tags.remove("keep")

    chip.click()

    assert removed == []
    assert chips.findChildren(QPushButton, "tagChip") == [chip]


def test_chip_click_after_session_cleared_does_nothing(qtbot: QtBot) -> None:
    """A click on a stale chip after the widget lost its session neither raises nor touches the old session.

    Product change that fails it: ``_on_chip_clicked`` (session_manager.py:411) remove the ``return`` so ``None.remove_tag`` raises.

    Args:
        qtbot: pytest-qt bot.
    """
    session = _session(("x",))
    chips = _chips(session, qtbot)
    removed: list[str] = []
    chips.tag_removed.connect(removed.append)
    chip = chips.findChild(QPushButton, "tagChip")
    assert chip is not None
    chips.set_session(None)

    chip.click()

    assert removed == []
    assert session.tags == ["x"]
    assert chips.session() is None


def test_chip_click_for_tag_without_chip_still_removes_tag_and_signals(qtbot: QtBot) -> None:
    """A tag added to the session behind the widget's back is removed and reported even though it has no chip.

    Product change that fails it: ``_on_chip_clicked`` (session_manager.py:416) replace ``if chip_btn is not None:`` with ``if True:``.

    Args:
        qtbot: pytest-qt bot.
    """
    session = _session(("a",))
    chips = _chips(session, qtbot)
    removed: list[str] = []
    changed: list[list[str]] = []
    chips.tag_removed.connect(removed.append)
    chips.tags_changed.connect(changed.append)
    added = session.add_tag("b")
    assert added

    _method(chips, "_on_chip_clicked")("b")

    assert session.tags == ["a"]
    assert removed == ["b"]
    assert changed == [["a"]]
    assert len(chips.findChildren(QPushButton, "tagChip")) == len(["a"])


def test_dialog_without_manager_edits_tags_without_persisting(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path) -> None:
    """With only a live session wired, adding a tag changes the session and writes nothing.

    Product change that fails it: ``_on_tags_changed`` (session_manager.py:685) change the guard to ``if session is None`` so the
    missing manager is dereferenced.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    session = _session()
    dialog = make_dialog(current_session=session)
    chips = _widget(dialog, "_tag_chips", TagChipsWidget)
    _widget(chips, "_tag_input", QLineEdit).setText("urgent")

    _widget(chips, "_add_btn", QPushButton).click()

    assert session.tags == ["urgent"]
    assert list(sessions_dir.iterdir()) == []


def test_elided_detail_shows_full_text_when_label_has_no_width() -> None:
    """A label with zero width shows the whole text, a narrow one elides it, and both keep the full text as tooltip.

    Product change that fails it: ``_set_elided_detail`` (session_manager.py:713) replace ``width > 0`` with ``True``.
    """
    label = QLabel()
    text = "a-very-long-model-identifier-v2"
    set_detail = _method(SessionManagerDialog, "_set_elided_detail")

    label.resize(0, 0)
    assert label.width() == 0
    set_detail(label, text)
    assert label.text() == text
    assert label.toolTip() == text

    label.resize(_NARROW_WIDTH, _NARROW_WIDTH)
    set_detail(label, text)
    assert label.text() != text
    assert len(label.text()) < len(text)
    assert label.toolTip() == text


def test_sidecar_listing_reads_normalizes_and_sorts_files(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path) -> None:
    """Sidecar files are listed newest first with ids, names and dates filled in, and unreadable entries are skipped.

    Covers a file without id or name (the file stem is used), a text date that is not a date (replaced by the current time), dates that
    are not text (shown as a dash and sorted last), invalid JSON, a directory named like a session file and a non-JSON file.

    Product change that fails it: ``_read_session_file`` (session_manager.py:853) set ``session_data["id"] = "x"`` instead of the stem.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    newest = {**_sidecar_payload("newest-id", "Newest"), "message_count": 7}
    older = {**_sidecar_payload("older-id", "Older"), "created_at": "2020-01-01T00:00:00+00:00", "updated_at": "2020-02-01T00:00:00+00:00"}
    bad_time = {"id": "badtime-id", "name": "Bad Time", "created_at": "2020-01-01T00:00:00+00:00", "updated_at": "yesterday-ish"}
    numeric = {"id": "numeric-id", "name": "Numeric", "created_at": 12345, "updated_at": 67890}
    _write_sidecar(sessions_dir, "newest", newest)
    _write_sidecar(sessions_dir, "older", older)
    _write_sidecar(sessions_dir, "badtime", bad_time)
    _write_sidecar(sessions_dir, "bare", {})
    _write_sidecar(sessions_dir, "numeric", numeric)
    (sessions_dir / "broken.json").write_text("{not json", encoding="utf-8")
    (sessions_dir / "folder.json").mkdir()
    (sessions_dir / "ignored.txt").write_text("{}", encoding="utf-8")
    before = datetime.now(tz=UTC)

    dialog = make_dialog()

    after = datetime.now(tz=UTC)
    ids = _ids(dialog)
    assert ids[:3] == ["badtime-id", "newest-id", "older-id"]
    assert sorted(ids[3:]) == ["bare", "numeric-id"]
    by_id = dict(zip(ids, _rows(dialog), strict=True))
    assert by_id["newest-id"] == ("Newest", "2020-03-01 10:00", "2020-03-05 12:34", "7")
    assert by_id["older-id"] == ("Older", "2020-01-01 00:00", "2020-02-01 00:00", "0")
    assert by_id["bare"] == ("bare", "-", "-", "0")
    assert by_id["numeric-id"] == ("Numeric", "-", "-", "0")
    name, created, modified, count = by_id["badtime-id"]
    assert (name, created, count) == ("Bad Time", "2020-01-01 00:00", "0")
    assert modified in {before.strftime(_MINUTE_FORMAT), after.strftime(_MINUTE_FORMAT)}


def test_sidecar_listing_skips_files_holding_non_object_json(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path) -> None:
    """A sidecar file whose JSON is not an object is skipped like any other unreadable file.

    Suspected defect: ``_read_session_file`` (session_manager.py:852) assumes a dict, so an array makes ``session_data["id"] = ...`` raise
    ``TypeError`` that ``_load_sessions_from_disk`` does not catch and the dialog cannot be opened.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "good", {"id": "good", "name": "Good"})
    _write_sidecar(sessions_dir, "array", [1, 2])

    dialog = make_dialog()

    assert _ids(dialog) == ["good"]


def test_sidecar_listing_tolerates_naive_timestamp_beside_missing_one(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """A sidecar with a timezone-less ``updated_at`` can be listed next to one with no timestamp at all.

    Suspected defect: ``_load_sessions_from_disk._sort_key`` (session_manager.py:907) returns the naive datetime for one file and a
    timezone-aware sentinel for the other, so sorting raises ``TypeError: can't compare offset-naive and offset-aware datetimes`` and the
    dialog cannot be opened.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "naive", {"id": "naive", "name": "Naive", "updated_at": "2020-03-01T10:00:00"})
    _write_sidecar(sessions_dir, "bare", {})

    dialog = make_dialog()

    assert sorted(_ids(dialog)) == ["bare", "naive"]


def test_refresh_after_sidecar_directory_vanished_lists_nothing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """Refreshing after the sidecar directory was removed empties the table and does not recreate the directory.

    Product change that fails it: ``_load_sessions_from_disk`` (session_manager.py:882) replace ``return`` with
    ``self.SESSIONS_DIR.mkdir()``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    path = _write_sidecar(sessions_dir, "only", _sidecar_payload("only", "Only"))
    dialog = make_dialog()
    assert _ids(dialog) == ["only"]
    path.unlink()
    sessions_dir.rmdir()

    _widget(dialog, "_refresh_btn", QPushButton).click()

    assert _ids(dialog) == []
    assert not sessions_dir.exists()


def test_manager_listing_failure_falls_back_to_sidecar_files(
    scripted: _ScriptedManager,
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """When the manager cannot list sessions, the dialog lists the sidecar files instead.

    Product change that fails it: ``_load_sessions`` (session_manager.py:794) narrow the handler to ``except KeyError``.

    Args:
        scripted: Scriptable session manager.
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "fallback", _sidecar_payload("fallback-id", "Fallback"))
    scripted.fail_listing = True

    dialog = make_dialog(manager=scripted)

    assert _ids(dialog) == ["fallback-id"]
    assert _rows(dialog)[0][0] == "Fallback"


def test_manager_rows_with_text_dates_and_foreign_objects(
    scripted: _ScriptedManager,
    make_dialog: Callable[..., SessionManagerDialog],
) -> None:
    """Text timestamps are shown truncated in the table and in full in the details, and non-metadata rows become placeholders.

    Product change that fails it: ``_load_sessions`` (session_manager.py:812) replace ``created_at[:16]`` with ``created_at``.

    Args:
        scripted: Scriptable session manager.
        make_dialog: Dialog factory.
    """
    scripted.listing = [
        SessionMetadata(
            id="text-dates",
            name="Text Dates",
            created_at=cast("datetime", "2026-03-04T05:06:07+00:00"),
            updated_at=cast("datetime", "2026-03-05T08:09:10+00:00"),
            provider=provider_ids.OLLAMA,
            model="m",
            message_count=3,
        ),
        cast("SessionMetadata", "foreign-row"),
        cast("SessionMetadata", ""),
    ]
    dialog = make_dialog(manager=scripted)

    rows = _rows(dialog)
    assert rows[0] == ("Text Dates", "2026-03-04T05:06", "2026-03-05T08:09", "3")
    assert _ids(dialog) == ["text-dates", "foreign-row", "unknown"]
    assert [row[0] for row in rows[1:]] == ["Unknown Session", "Unknown Session"]
    _select(dialog, "text-dates")
    assert _widget(dialog, "_created_label", QLabel).text() == "2026-03-04T05:06:07+00:00"
    assert _widget(dialog, "_modified_label", QLabel).text() == "2026-03-05T08:09:10+00:00"


def test_update_details_formats_text_dates_binaries_and_recent_messages(make_dialog: Callable[..., SessionManagerDialog]) -> None:
    """The details panel shows text dates as given, lists binaries and previews the last three messages shortened.

    Of the last three entries one is not a message, one is longer than the preview limit and one has an empty body and no role.

    Product change that fails it: ``_update_details`` (session_manager.py:1031) replace the ``...`` suffix with an empty string.

    Args:
        make_dialog: Dialog factory.
    """
    dialog = make_dialog()
    long_body = "x" * (_PREVIEW_LIMIT + 50)
    session: dict[str, object] = {
        "id": "sid",
        "name": "My Sess",
        "created_at": "2026-01-02 03:04",
        "updated_at": "later",
        "provider": "prov",
        "model": "mod",
        "message_count": 4,
        "binaries": ["a.exe", "b.exe"],
        "messages": [{"role": "user", "content": "hi"}, 5, {"role": "assistant", "content": long_body}, {"content": ""}],
    }

    _method(dialog, "_update_details")(session)

    assert _widget(dialog, "_id_label", QLabel).text() == "sid"
    assert _widget(dialog, "_created_label", QLabel).text() == "2026-01-02 03:04"
    assert _widget(dialog, "_modified_label", QLabel).text() == "later"
    assert _widget(dialog, "_provider_label", QLabel).toolTip() == "prov"
    assert _widget(dialog, "_model_label", QLabel).toolTip() == "mod"
    assert _widget(dialog, "_messages_label", QLabel).text() == "4"
    assert _widget(dialog, "_binaries_label", QLabel).text() == "a.exe, b.exe"
    preview = _widget(dialog, "_preview_text", QTextEdit)
    assert preview.toPlainText().splitlines() == [
        "Session: My Sess",
        "Provider: prov",
        "Model: mod",
        "",
        "Binaries analyzed:",
        "  - a.exe",
        "  - b.exe",
        "",
        "Total messages: 4",
        "",
        "Recent messages:",
        f"  [assistant]: {'x' * _PREVIEW_LIMIT}...",
        "  [unknown]: ",
    ]


def test_update_details_without_dates_binaries_or_messages_shows_placeholders(make_dialog: Callable[..., SessionManagerDialog]) -> None:
    """Missing or mistyped fields show dashes and ``N/A`` and no recent-message section.

    Product change that fails it: ``_update_details`` (session_manager.py:992) replace the ``"-"`` placeholder with an empty string.

    Args:
        make_dialog: Dialog factory.
    """
    dialog = make_dialog()
    session: dict[str, object] = {"id": "x", "name": "Bare", "created_at": None, "updated_at": 42, "provider": None, "messages": []}

    _method(dialog, "_update_details")(session)

    assert _widget(dialog, "_created_label", QLabel).text() == "-"
    assert _widget(dialog, "_modified_label", QLabel).text() == "-"
    assert _widget(dialog, "_provider_label", QLabel).toolTip() == "-"
    assert _widget(dialog, "_messages_label", QLabel).text() == "0"
    assert _widget(dialog, "_binaries_label", QLabel).text() == "-"
    preview = _widget(dialog, "_preview_text", QTextEdit)
    assert preview.toPlainText().splitlines() == [
        "Session: Bare",
        "Provider: N/A",
        "Model: N/A",
        "",
        "Binaries analyzed:",
        "",
        "Total messages: 0",
    ]


def test_selection_change_ignores_missing_name_item_and_unknown_id(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """A selection change for a row without a name cell, or whose id is not in the list, leaves the details alone.

    Product change that fails it: ``_on_selection_changed`` (session_manager.py:956) remove the ``name_item is None`` check.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "sel", _sidecar_payload("sel", "Selected"))
    dialog = make_dialog()
    table = _table(dialog)
    id_label = _widget(dialog, "_id_label", QLabel)
    load_button = _widget(dialog, "_load_btn", QPushButton)
    _select(dialog, "sel")
    assert id_label.text() == "sel"
    assert load_button.isEnabled()

    taken = table.takeItem(0, 0)
    assert taken is not None
    table.itemSelectionChanged.emit()
    assert id_label.text() == "sel"

    ghost = QTableWidgetItem("Ghost")
    ghost.setData(_USER_ROLE, "ghost")
    table.setItem(0, 0, ghost)
    load_button.setEnabled(False)
    table.itemSelectionChanged.emit()
    assert not load_button.isEnabled()
    assert id_label.text() == "sel"


def test_double_click_loads_the_session_under_the_cursor(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path) -> None:
    """Double-clicking a listed session restores it: the dialog announces the id and closes with acceptance.

    Product change that fails it: ``_on_double_click`` (session_manager.py:976) replace the body with ``return``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "dbl", _sidecar_payload("dbl-id", "Double"))
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "dbl-id")
    item = _table(dialog).item(_row_of(dialog, "dbl-id"), 0)
    assert item is not None

    _table(dialog).itemDoubleClicked.emit(item)

    assert loaded == ["dbl-id"]
    assert dialog.result() == QDialog.DialogCode.Accepted.value


def test_load_without_selection_does_nothing(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Loading with no row selected opens no dialog and announces nothing.

    Product change that fails it: ``_load_selected_session`` (session_manager.py:1054) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)

    _method(dialog, "_load_selected_session")()

    assert shown == []
    assert loaded == []


def test_load_with_missing_name_cell_does_nothing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Loading when the selected row has lost its name cell asks nothing and announces nothing.

    Product change that fails it: ``_load_selected_session`` (session_manager.py:1058) remove the ``name_item is None`` check.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "one")
    taken = _table(dialog).takeItem(0, 0)
    assert taken is not None

    _method(dialog, "_load_selected_session")()

    assert shown == []
    assert loaded == []


def test_load_of_active_session_is_refused_with_notice(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Loading the session that is already active shows a notice and neither asks for confirmation nor loads.

    Product change that fails it: ``_load_selected_session`` (session_manager.py:1062) replace ``==`` with ``!=``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "act", _sidecar_payload("act-id", "Active"))
    dialog = make_dialog(current_session_id="act-id")
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "act-id")

    _method(dialog, "_load_selected_session")()

    assert shown == [("information", "Session Active", "This session is already active.")]
    assert loaded == []


@pytest.mark.usefixtures("decline")
def test_load_declined_by_user_does_nothing(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Answering No to the load confirmation keeps the dialog open and announces nothing.

    Product change that fails it: ``_load_selected_session`` (session_manager.py:1077) replace ``!=`` with ``==``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "one")

    _method(dialog, "_load_selected_session")()

    assert _kinds(shown, "question") == [("Load Session", "Load this session? Current session progress will be saved.")]
    assert loaded == []
    assert dialog.result() != QDialog.DialogCode.Accepted.value


def test_sidecar_load_restores_valid_messages_into_chat_panel(
    qtbot: QtBot,
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """Loading a sidecar session replaces the chat panel's history with its valid messages, in order.

    The file holds a message with a good timestamp, one without a timestamp, one with an unparseable timestamp, one with an unknown role,
    one with a non-text body and one entry that is not an object; only the first three are restored.

    Product change that fails it: ``_load_session_from_disk`` (session_manager.py:1207) replace ``messages.append(message)`` with ``pass``.

    Args:
        qtbot: pytest-qt bot.
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    payload = _sidecar_payload("restore-me", "Restore Me")
    payload["messages"] = [
        {"role": "user", "content": "first question", "timestamp": "2020-01-02T03:04:05+00:00"},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "second question", "timestamp": "not-a-timestamp"},
        {"role": "narrator", "content": "unknown role"},
        {"role": "user", "content": 123},
        "stray-string",
    ]
    _write_sidecar(sessions_dir, "restore-me", payload)
    parent = QWidget()
    qtbot.addWidget(parent)
    chat = ChatPanel(parent)
    chat.add_message(Message(role="user", content="stale bubble"))
    _attach(parent, "_chat_panel", chat)
    dialog = make_dialog(parent=parent)
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "restore-me")
    before = datetime.now(tz=UTC)

    _method(dialog, "_load_selected_session")()

    after = datetime.now(tz=UTC)
    restored = chat.get_messages()
    assert loaded == ["restore-me"]
    assert [(message.role, message.content) for message in restored] == [
        ("user", "first question"),
        ("assistant", "first answer"),
        ("user", "second question"),
    ]
    assert restored[0].timestamp == datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert all(before <= message.timestamp <= after for message in restored[1:])
    assert dialog.result() == QDialog.DialogCode.Accepted.value


def test_sidecar_load_with_non_list_messages_restores_empty_history(
    qtbot: QtBot,
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """A sidecar whose ``messages`` is not a list still loads, with an empty history.

    Product change that fails it: ``_load_session_from_disk`` (session_manager.py:1208) replace ``elif messages_raw is not None:`` with
    ``elif False:`` and iterate the text.

    Args:
        qtbot: pytest-qt bot.
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    payload = _sidecar_payload("garbled", "Garbled")
    payload["messages"] = "garbage"
    _write_sidecar(sessions_dir, "garbled", payload)
    parent = QWidget()
    qtbot.addWidget(parent)
    chat = ChatPanel(parent)
    chat.add_message(Message(role="user", content="stale bubble"))
    _attach(parent, "_chat_panel", chat)
    dialog = make_dialog(parent=parent)
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "garbled")

    _method(dialog, "_load_selected_session")()

    assert loaded == ["garbled"]
    assert chat.get_messages() == []


def test_sidecar_load_tolerates_parent_without_chat_or_binary_hooks(
    qtbot: QtBot,
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    tmp_path: Path,
) -> None:
    """Restoring into a parent whose chat panel lacks the message methods and which has no binary hook does not fail.

    Product change that fails it: ``_restore_session_to_ui`` (session_manager.py:1336) replace ``if callable(clear_messages):`` with
    ``if True:``.

    Args:
        qtbot: pytest-qt bot.
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        tmp_path: Pytest temporary directory.
    """
    payload = _sidecar_payload("plain", "Plain")
    payload["messages"] = [{"role": "user", "content": "hello"}]
    payload["binaries"] = [{"path": str(tmp_path / "target.exe"), "name": "target.exe"}]
    _write_sidecar(sessions_dir, "plain", payload)
    parent = QWidget()
    qtbot.addWidget(parent)
    _attach(parent, "_chat_panel", QLabel(parent))
    dialog = make_dialog(parent=parent)
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "plain")

    _method(dialog, "_load_selected_session")()

    assert loaded == ["plain"]
    assert dialog.result() == QDialog.DialogCode.Accepted.value


def test_sidecar_load_of_vanished_session_warns(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Loading a selected session that is no longer in the listing warns and announces nothing.

    Product change that fails it: ``_load_session_from_disk`` (session_manager.py:1198) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "gone", _sidecar_payload("gone-id", "Gone"))
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, "gone-id")
    _attach(dialog, "_sessions", [])

    _method(dialog, "_load_selected_session")()

    assert _kinds(shown, "warning") == [("Load Failed", "Session not found: gone-id")]
    assert loaded == []


@pytest.mark.parametrize("role", ["user", "assistant", "system", "tool"])
def test_message_from_disk_dict_accepts_every_role_and_parses_timestamp(role: str) -> None:
    """Each of the four roles is accepted and the ISO timestamp is parsed.

    Product change that fails it: ``_message_from_disk_dict`` (session_manager.py:1234) drop ``"tool"`` from the accepted roles.

    Args:
        role: Message role under test.
    """
    data: dict[str, object] = {"role": role, "content": "body", "timestamp": "2020-01-02T03:04:05+00:00"}

    result = _method(SessionManagerDialog, "_message_from_disk_dict")(data)

    assert isinstance(result, Message)
    assert (result.role, result.content) == (role, "body")
    assert result.timestamp == datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC)


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({"timestamp": "not-a-timestamp"}, id="unparseable"),
        pytest.param({}, id="missing"),
        pytest.param({"timestamp": 12}, id="not-text"),
    ],
)
def test_message_from_disk_dict_uses_current_time_without_valid_timestamp(extra: dict[str, object]) -> None:
    """A missing or invalid timestamp is replaced by the current time.

    Product change that fails it: ``_message_from_disk_dict`` (session_manager.py:1237) initialize ``timestamp`` to ``datetime.min``.

    Args:
        extra: Timestamp field(s) added to an otherwise valid message.
    """
    data: dict[str, object] = {"role": "user", "content": "body", **extra}
    before = datetime.now(tz=UTC)

    result = _method(SessionManagerDialog, "_message_from_disk_dict")(data)

    after = datetime.now(tz=UTC)
    assert isinstance(result, Message)
    assert before <= result.timestamp <= after


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"role": "narrator", "content": "x"}, id="unknown-role"),
        pytest.param({"role": "user", "content": 5}, id="non-text-content"),
        pytest.param({"content": "orphan"}, id="missing-role"),
    ],
)
def test_message_from_disk_dict_rejects_invalid_entries(data: dict[str, object]) -> None:
    """Entries without a valid role and text content are rejected.

    Product change that fails it: ``_message_from_disk_dict`` (session_manager.py:1234) replace ``or`` with ``and``.

    Args:
        data: Message dictionary as stored in a sidecar file.
    """
    assert _method(SessionManagerDialog, "_message_from_disk_dict")(data) is None


def _full_binary(path: str, name: str) -> dict[str, object]:
    """Build a complete sidecar binary entry.

    Args:
        path: Binary path text.
        name: Binary file name.

    Returns:
        dict[str, object]: The entry.
    """
    return {
        "path": path,
        "name": name,
        "size": 4096,
        "sha256": "ab" * 32,
        "file_type": "PE",
        "architecture": "x86_64",
        "is_64bit": True,
        "entry_point": 0x1000,
    }


def test_active_binary_defaults_to_last_entry_and_honors_explicit_index() -> None:
    """The active binary is the last entry unless ``active_binary_index`` selects another, with every field carried over.

    Product change that fails it: ``_active_binary_from_disk_session`` (session_manager.py:1265) replace ``len(binaries) - 1`` with ``0``.
    """
    first = _full_binary("C:/tools/first.exe", "first.exe")
    second = _full_binary("C:/tools/second.exe", "second.exe")
    pick = _method(SessionManagerDialog, "_active_binary_from_disk_session")

    last = pick({"binaries": [first, second]})
    explicit = pick({"binaries": [first, second], "active_binary_index": 0})

    assert isinstance(last, BinaryInfo)
    assert isinstance(explicit, BinaryInfo)
    assert last == BinaryInfo(
        path=Path("C:/tools/second.exe"),
        name="second.exe",
        size=4096,
        sha256="ab" * 32,
        file_type="PE",
        architecture="x86_64",
        is_64bit=True,
        entry_point=0x1000,
        sections=[],
        imports=[],
        exports=[],
    )
    assert explicit.name == "first.exe"


def test_binary_info_from_disk_dict_defaults_missing_or_mistyped_fields() -> None:
    """Fields that are missing or of the wrong type fall back to neutral values.

    Product change that fails it: ``_binary_info_from_disk_dict`` (session_manager.py:1304) default ``file_type`` to ``""``.
    """
    data: dict[str, object] = {
        "path": "C:/x/a.exe",
        "name": "a.exe",
        "size": "big",
        "sha256": 7,
        "file_type": None,
        "architecture": 3,
        "is_64bit": 1,
        "entry_point": "x",
    }

    result = _method(SessionManagerDialog, "_binary_info_from_disk_dict")(data)

    assert result == BinaryInfo(
        path=Path("C:/x/a.exe"),
        name="a.exe",
        size=0,
        sha256="",
        file_type="unknown",
        architecture="unknown",
        is_64bit=False,
        entry_point=0,
        sections=[],
        imports=[],
        exports=[],
    )


@pytest.mark.parametrize(
    "session_data",
    [
        pytest.param({}, id="no-binaries-key"),
        pytest.param({"binaries": "text"}, id="not-a-list"),
        pytest.param({"binaries": []}, id="empty-list"),
        pytest.param({"binaries": [_full_binary("C:/a.exe", "a.exe")], "active_binary_index": 5}, id="index-too-high"),
        pytest.param({"binaries": [_full_binary("C:/a.exe", "a.exe")], "active_binary_index": -1}, id="negative-index"),
        pytest.param({"binaries": ["text"]}, id="entry-not-an-object"),
        pytest.param({"binaries": [{"name": "a.exe"}]}, id="missing-path"),
        pytest.param({"binaries": [{"path": "C:/a.exe"}]}, id="missing-name"),
        pytest.param({"binaries": [{"path": 5, "name": "a.exe"}]}, id="non-text-path"),
    ],
)
def test_active_binary_is_none_for_unusable_session_data(session_data: dict[str, object]) -> None:
    """Session data without a usable active binary yields ``None``.

    Product change that fails it: ``_active_binary_from_disk_session`` (session_manager.py:1266) replace ``0 <= index`` with ``-1 <= index``.

    Args:
        session_data: Sidecar session dictionary.
    """
    assert _method(SessionManagerDialog, "_active_binary_from_disk_session")(session_data) is None


def test_delete_without_selection_does_nothing(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Deleting with no row selected asks nothing and removes nothing.

    Product change that fails it: ``_delete_session`` (session_manager.py:1355) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "keep", _sidecar_payload("keep-id", "Keep"))
    dialog = make_dialog()

    _method(dialog, "_delete_session")()

    assert shown == []
    assert path.exists()


def test_delete_with_missing_name_cell_does_nothing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Deleting when the selected row has lost its name cell asks nothing and removes nothing.

    Product change that fails it: ``_delete_session`` (session_manager.py:1359) remove the ``name_item is None`` check.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "keep", _sidecar_payload("keep-id", "Keep"))
    dialog = make_dialog()
    _select(dialog, "keep-id")
    taken = _table(dialog).takeItem(0, 0)
    assert taken is not None

    _method(dialog, "_delete_session")()

    assert shown == []
    assert path.exists()


def test_delete_of_active_session_is_refused(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """The active session cannot be deleted: a warning is shown, no question is asked and the file stays.

    Product change that fails it: ``_delete_session`` (session_manager.py:1364) replace ``==`` with ``!=``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "act", _sidecar_payload("act-id", "Active"))
    dialog = make_dialog(current_session_id="act-id")
    deleted: list[str] = []
    dialog.session_deleted.connect(deleted.append)
    _select(dialog, "act-id")

    _method(dialog, "_delete_session")()

    assert shown == [("warning", "Cannot Delete", "Cannot delete the currently active session.")]
    assert deleted == []
    assert path.exists()


@pytest.mark.usefixtures("decline")
def test_delete_declined_by_user_keeps_file(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Answering No to the delete confirmation keeps the session file and announces nothing.

    Product change that fails it: ``_delete_session`` (session_manager.py:1379) replace ``!=`` with ``==``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "doomed", _sidecar_payload("doomed-id", "Doomed"))
    dialog = make_dialog()
    deleted: list[str] = []
    dialog.session_deleted.connect(deleted.append)
    _select(dialog, "doomed-id")

    _method(dialog, "_delete_session")()

    assert _kinds(shown, "question") == [("Delete Session", "Delete session 'Doomed'?\n\nThis action cannot be undone.")]
    assert deleted == []
    assert path.exists()
    assert _ids(dialog) == ["doomed-id"]


def test_delete_sidecar_session_removes_file_announces_and_refreshes(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
) -> None:
    """Confirming the deletion of a sidecar session removes its file, announces the id and drops the row.

    Product change that fails it: ``_delete_session_from_disk`` (session_manager.py:1469) replace ``session_file.unlink()`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    doomed = _write_sidecar(sessions_dir, "doomed-id", _sidecar_payload("doomed-id", "Doomed"))
    kept = _write_sidecar(sessions_dir, "kept-id", _sidecar_payload("kept-id", "Kept"))
    dialog = make_dialog()
    deleted: list[str] = []
    dialog.session_deleted.connect(deleted.append)
    _select(dialog, "doomed-id")

    _method(dialog, "_delete_session")()

    assert deleted == ["doomed-id"]
    assert not doomed.exists()
    assert kept.exists()
    assert _ids(dialog) == ["kept-id"]


def test_delete_sidecar_session_that_cannot_be_unlinked_warns_and_keeps_row(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """When the session file cannot be removed the user gets a warning and the row stays.

    The listed file is replaced by a directory of the same name after the table was built, which cannot be unlinked.

    Product change that fails it: ``_delete_session_from_disk`` (session_manager.py:1481) replace ``return False`` with ``return True``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "stuck", _sidecar_payload("stuck", "Stuck"))
    dialog = make_dialog()
    deleted: list[str] = []
    dialog.session_deleted.connect(deleted.append)
    _select(dialog, "stuck")
    path.unlink()
    path.mkdir()

    _method(dialog, "_delete_session")()

    warnings = _kinds(shown, "warning")
    assert [title for title, _text in warnings] == ["Delete Failed"]
    assert warnings[0][1].startswith("Failed to delete session file:\n")
    assert deleted == []
    assert path.is_dir()
    assert _ids(dialog) == ["stuck"]


def test_delete_sidecar_for_missing_file_reports_success(make_dialog: Callable[..., SessionManagerDialog], shown: _Log) -> None:
    """Deleting a sidecar session whose file is already gone counts as success without any warning.

    Product change that fails it: ``_delete_session_from_disk`` (session_manager.py:1485) replace ``return True`` with ``return False``.

    Args:
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
    """
    dialog = make_dialog()

    assert _method(dialog, "_delete_session_from_disk")("never-existed") is True
    assert shown == []


def test_delete_row_the_manager_no_longer_has_warns(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
) -> None:
    """Deleting a listed session that the store already lost warns that it could not be deleted.

    Product change that fails it: ``_on_delete_session_succeeded`` (session_manager.py:1419) replace ``if not deleted:`` with
    ``if deleted:``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
    """
    _create(manager, "Stays")
    gone = _create(manager, "Gone")
    run_bridge_coroutine(manager.close())
    dialog = make_dialog(manager=manager)
    deleted: list[str] = []
    dialog.session_deleted.connect(deleted.append)
    assert manager.store.delete(gone.id)
    _select(dialog, gone.id)

    _method(dialog, "_delete_session")()

    wait_for(("warning", "Delete Failed", "Session could not be deleted."))
    assert deleted == []


def test_delete_failure_in_manager_warns_with_error_text(
    scripted: _ScriptedManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
) -> None:
    """A deletion that raises in the manager is reported with the error text.

    Product change that fails it: ``_on_delete_session_failed`` (session_manager.py:1441) drop ``{error_obj}`` from the message.

    Args:
        scripted: Scriptable session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
    """
    session = _create(scripted, "Victim")
    run_bridge_coroutine(scripted.close())
    scripted.fail_delete = True
    dialog = make_dialog(manager=scripted)
    _select(dialog, session.id)

    _method(dialog, "_delete_session")()

    wait_for(("warning", "Delete Failed", "Failed to delete session:\ndisk on fire"))


def test_load_session_missing_from_store_warns_not_found(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
) -> None:
    """Loading a listed session the store has since lost warns that it was not found and announces nothing.

    Product change that fails it: ``_on_load_session_succeeded`` (session_manager.py:1148) replace ``result is None`` with
    ``result is not None``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
    """
    gone = _create(manager, "Gone")
    run_bridge_coroutine(manager.close())
    dialog = make_dialog(manager=manager)
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    assert manager.store.delete(gone.id)
    _select(dialog, gone.id)

    _method(dialog, "_load_selected_session")()

    wait_for(("warning", "Load Failed", f"Session not found: {gone.id}"))
    assert loaded == []


def test_load_failure_in_manager_warns_with_error_text(
    scripted: _ScriptedManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
) -> None:
    """A load that raises in the manager is reported with the error text and announces nothing.

    Product change that fails it: ``_on_load_session_failed`` (session_manager.py:1178) drop ``{error_obj}`` from the message.

    Args:
        scripted: Scriptable session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
    """
    session = _create(scripted, "Unreadable")
    run_bridge_coroutine(scripted.close())
    scripted.fail_load = True
    dialog = make_dialog(manager=scripted)
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    _select(dialog, session.id)

    _method(dialog, "_load_selected_session")()

    wait_for(("warning", "Load Failed", "Failed to load session:\ncannot open"))
    assert loaded == []


def test_load_result_without_message_list_is_reported_malformed(make_dialog: Callable[..., SessionManagerDialog], shown: _Log) -> None:
    """A load result whose ``messages`` is not a list is reported as malformed and the dialog stays open.

    Product change that fails it: ``_on_load_session_succeeded`` (session_manager.py:1154) replace ``not isinstance`` with ``isinstance``.

    Args:
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
    """
    dialog = make_dialog()
    loaded: list[str] = []
    dialog.session_loaded.connect(loaded.append)

    _method(dialog, "_on_load_session_succeeded")("odd-id", object())

    assert shown == [("warning", "Load Failed", "Session file is malformed: odd-id")]
    assert loaded == []
    assert dialog.result() != QDialog.DialogCode.Accepted.value


def test_manager_dispatchers_do_nothing_without_a_manager(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """The manager-backed load, delete and import entry points are no-ops on a dialog that has no manager.

    Product change that fails it: ``_delete_session_via_manager`` (session_manager.py:1399) replace ``return`` with
    ``self._on_session_deleted(session_id)``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    path = _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    loaded: list[str] = []
    deleted: list[str] = []
    dialog.session_loaded.connect(loaded.append)
    dialog.session_deleted.connect(deleted.append)

    _method(dialog, "_load_session_via_manager")("one")
    _method(dialog, "_delete_session_via_manager")("one")
    _method(dialog, "_import_via_manager")(path)

    assert (loaded, deleted, shown) == ([], [], [])
    assert path.exists()


def test_export_without_selection_asks_to_select(make_dialog: Callable[..., SessionManagerDialog], shown: _Log) -> None:
    """Exporting with no row selected asks the user to select a session.

    Product change that fails it: ``_export_session`` (session_manager.py:1493) replace ``if not selected_rows:`` with
    ``if selected_rows:``.

    Args:
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
    """
    dialog = make_dialog()

    _method(dialog, "_export_session")()

    assert shown == [("information", "Export Session", "Please select a session to export.")]


def test_export_with_missing_name_cell_does_nothing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Exporting when the selected row has lost its name cell shows nothing.

    Product change that fails it: ``_export_session`` (session_manager.py:1503) remove the ``name_item is None`` check.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    _select(dialog, "one")
    taken = _table(dialog).takeItem(0, 0)
    assert taken is not None

    _method(dialog, "_export_session")()

    assert shown == []


def test_export_of_row_without_session_data_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Exporting a row whose id is not in the listing warns that the session data is missing.

    Product change that fails it: ``_export_session`` (session_manager.py:1509) replace ``session_data is None`` with
    ``session_data is not None``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    _select(dialog, "one")
    ghost = QTableWidgetItem("Ghost")
    ghost.setData(_USER_ROLE, "ghost")
    _table(dialog).setItem(0, 0, ghost)

    _method(dialog, "_export_session")()

    assert shown == [("warning", "Export Failed", "Could not find session data.")]


def test_export_cancelled_picker_writes_nothing(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path, shown: _Log) -> None:
    """Cancelling the save picker exports nothing and shows no message.

    Product change that fails it: ``_export_session`` (session_manager.py:1525) replace ``if path:`` with ``if True:``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    dialog = make_dialog()
    _select(dialog, "one")

    _method(dialog, "_export_session")()

    assert shown == []
    assert sorted(path.name for path in sessions_dir.iterdir()) == ["one.json"]


def test_export_writes_json_file_and_suggests_sanitized_name(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Exporting writes the session as JSON with ISO dates, messages and extras, and suggests a file-safe name.

    Product change that fails it: ``_prepare_export_data`` (session_manager.py:1614) drop the ``patches`` copy.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs a save-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    payload = _sidecar_payload("exp-id", "Report: v1/final*")
    payload["message_count"] = 2
    payload["binaries"] = ["a.exe"]
    payload["messages"] = [{"role": "user", "content": "q"}, {"role": "assistant", "content": "a"}]
    payload["tool_states"] = {"ida": {"state": "ok"}}
    payload["patches"] = [{"address": 4096}]
    _write_sidecar(sessions_dir, "exp", payload)
    target = tmp_path / "out.json"
    calls = file_picker("getSaveFileName", str(target))
    dialog = make_dialog()
    _select(dialog, "exp-id")
    before = datetime.now(tz=UTC)

    _method(dialog, "_export_session")()

    after = datetime.now(tz=UTC)
    assert [call[1:] for call in calls] == [("Export Session", "Report_ v1_final_.json", _JSON_FILTER)]
    exported = cast("dict[str, object]", json.loads(target.read_text(encoding="utf-8")))
    exported_at = datetime.fromisoformat(str(exported.pop("exported_at")))
    assert before <= exported_at <= after
    assert exported == {
        "id": "exp-id",
        "name": "Report: v1/final*",
        "provider": provider_ids.OLLAMA,
        "model": "test-model",
        "message_count": 2,
        "binaries": ["a.exe"],
        "export_version": "1.0",
        "created_at": _CREATED,
        "updated_at": _UPDATED,
        "messages": [{"role": "user", "content": "q"}, {"role": "assistant", "content": "a"}],
        "tool_states": {"ida": {"state": "ok"}},
        "patches": [{"address": 4096}],
    }
    assert shown == [("information", "Export Complete", f"Session exported to:\n{target}")]


def test_export_to_unwritable_path_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """An export whose destination cannot be written warns and does not claim success.

    Product change that fails it: ``_export_session`` (session_manager.py:1528) narrow the handler to ``except TypeError``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs a save-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one", "One"))
    folder = tmp_path / "a_folder"
    folder.mkdir()
    file_picker("getSaveFileName", str(folder))
    dialog = make_dialog()
    _select(dialog, "one")

    _method(dialog, "_export_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Export Failed")]
    assert shown[0][2].startswith("Failed to export session:\n")


def test_prepare_export_data_serializes_dates_messages_and_extras() -> None:
    """Dates become ISO text, text dates are kept, message objects are flattened to their attributes and extras pass through.

    Product change that fails it: ``_prepare_export_data`` (session_manager.py:1607) replace ``msg_item.__dict__`` with ``{}``.
    """
    created = datetime(2020, 3, 1, 10, 0, tzinfo=UTC)
    message = Message(role="assistant", content="yo", timestamp=created)
    data: dict[str, object] = {
        "id": "i",
        "name": "n",
        "provider": "p",
        "model": "m",
        "message_count": 3,
        "binaries": ["b"],
        "created_at": created,
        "updated_at": "free text",
        "messages": [{"role": "user", "content": "hi"}, message, 17],
        "tool_states": {"ida": 1},
        "patches": [2],
    }
    before = datetime.now(tz=UTC)

    result = cast("dict[str, object]", _method(SessionManagerDialog, "_prepare_export_data")(data))

    after = datetime.now(tz=UTC)
    exported_at = datetime.fromisoformat(str(result.pop("exported_at")))
    assert before <= exported_at <= after
    assert result == {
        "id": "i",
        "name": "n",
        "provider": "p",
        "model": "m",
        "message_count": 3,
        "binaries": ["b"],
        "export_version": "1.0",
        "created_at": "2020-03-01T10:00:00+00:00",
        "updated_at": "free text",
        "messages": [{"role": "user", "content": "hi"}, vars(message)],
        "tool_states": {"ida": 1},
        "patches": [2],
    }


def test_prepare_export_data_omits_absent_and_blank_fields() -> None:
    """Blank dates, a non-list ``messages`` and absent extras are left out of the export.

    Product change that fails it: ``_prepare_export_data`` (session_manager.py:1590) replace ``elif created_at:`` with ``else:``.
    """
    data: dict[str, object] = {"created_at": None, "updated_at": "", "messages": "not-a-list"}

    result = cast("dict[str, object]", _method(SessionManagerDialog, "_prepare_export_data")(data))

    result.pop("exported_at")
    assert result == {
        "id": None,
        "name": None,
        "provider": None,
        "model": None,
        "message_count": 0,
        "binaries": [],
        "export_version": "1.0",
    }


def test_import_with_cancelled_picker_does_nothing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
) -> None:
    """Cancelling the open picker imports nothing and shows no message.

    Product change that fails it: ``_import_session`` (session_manager.py:1631) replace ``if not path_str:`` with ``if False:``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
    """
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert shown == []
    assert list(sessions_dir.iterdir()) == []


def test_import_sidecar_with_invalid_json_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing a file that is not valid JSON into the sidecar store warns and stores nothing.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1796) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "broken.json"
    source.write_text("{oops", encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Import Failed")]
    assert shown[0][2].startswith("Invalid JSON file:\n")
    assert list(sessions_dir.iterdir()) == []


def test_import_sidecar_from_unreadable_path_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing from a path that cannot be read into the sidecar store warns and stores nothing.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1797) narrow the handler to ``except FileNotFoundError``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    folder = tmp_path / "a_folder"
    folder.mkdir()
    file_picker("getOpenFileName", str(folder))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Import Failed")]
    assert shown[0][2].startswith("Failed to read file:\n")
    assert list(sessions_dir.iterdir()) == []


def test_import_sidecar_with_non_object_json_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing a JSON array into the sidecar store warns about the format and stores nothing.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1802) replace ``not isinstance(raw_data, dict)`` with
    ``isinstance(raw_data, dict)``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "array.json"
    source.write_text("[1, 2]", encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert shown == [("warning", "Import Failed", "Invalid session file format.")]
    assert list(sessions_dir.iterdir()) == []


def test_import_sidecar_without_id_uses_file_stem_and_lists_session(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """A file without id and name is stored under its stem, stamped with the import time and listed.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1811) set ``import_data["name"]`` to an empty string.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "renamed_import.json"
    source.write_text(json.dumps({"notes": "hi"}), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()
    before = datetime.now(tz=UTC)

    _method(dialog, "_import_session")()

    after = datetime.now(tz=UTC)
    stored = cast("dict[str, object]", json.loads((sessions_dir / "renamed_import.json").read_text(encoding="utf-8")))
    imported_at = datetime.fromisoformat(str(stored.pop("imported_at")))
    assert before <= imported_at <= after
    assert stored == {"notes": "hi", "id": "renamed_import", "name": "renamed_import"}
    assert shown == [("information", "Import Complete", f"Session imported from:\n{source}")]
    assert _ids(dialog) == ["renamed_import"]


@pytest.mark.usefixtures("decline")
def test_import_sidecar_duplicate_declined_keeps_existing(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Declining the replace prompt for a duplicate id leaves the stored session untouched.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1815) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    existing = _write_sidecar(sessions_dir, "dup", {"id": "dup", "name": "Original"})
    source = tmp_path / "incoming.json"
    source.write_text(json.dumps({"id": "dup", "name": "Replacement"}), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert _kinds(shown, "question") == [("Session Exists", "A session with ID 'dup' already exists.\n\nDo you want to replace it?")]
    assert json.loads(existing.read_text(encoding="utf-8")) == {"id": "dup", "name": "Original"}
    assert _kinds(shown, "information") == []


def test_import_sidecar_duplicate_confirmed_replaces_session(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Confirming the replace prompt for a duplicate id overwrites the stored session and refreshes the list.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1814) replace ``not self._confirm_replace(candidate_id)`` with
    ``self._confirm_replace(candidate_id)``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    existing = _write_sidecar(sessions_dir, "dup", {"id": "dup", "name": "Original"})
    source = tmp_path / "incoming.json"
    source.write_text(json.dumps({"id": "dup", "name": "Replacement"}), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    stored = cast("dict[str, object]", json.loads(existing.read_text(encoding="utf-8")))
    assert (stored["id"], stored["name"]) == ("dup", "Replacement")
    assert [row[0] for row in _rows(dialog)] == ["Replacement"]


def test_import_sidecar_write_failure_warns(
    make_dialog: Callable[..., SessionManagerDialog],
    sessions_dir: Path,
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """When the session file cannot be written the user is warned and no success message appears.

    A directory already occupies the file name the imported session would be stored under.

    Product change that fails it: ``_import_to_disk`` (session_manager.py:1824) replace ``return`` with ``pass``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    sessions_dir.mkdir()
    (sessions_dir / "blocked.json").mkdir()
    source = tmp_path / "incoming.json"
    source.write_text(json.dumps({"id": "blocked", "name": "Blocked"}), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog()

    _method(dialog, "_import_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Import Failed")]
    assert shown[0][2].startswith("Failed to write session file:\n")


def test_import_via_manager_missing_file_warns(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing a file that does not exist warns that it was not found and stores nothing.

    Product change that fails it: ``_peek_session_id`` (session_manager.py:1757) replace ``return False, None`` with ``return True, None``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    missing = tmp_path / "missing.json"
    file_picker("getOpenFileName", str(missing))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()

    assert shown == [("warning", "Import Failed", f"File not found:\n{missing}")]
    assert manager.list_sessions() == []


def test_import_via_manager_invalid_json_warns(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing a file that is not valid JSON warns and stores nothing.

    Product change that fails it: ``_peek_session_id`` (session_manager.py:1761) replace ``return False, None`` with ``return True, None``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "broken.json"
    source.write_text("{oops", encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Import Failed")]
    assert shown[0][2].startswith("Invalid JSON file:\n")
    assert manager.list_sessions() == []


def test_import_via_manager_unreadable_path_warns(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing from a path that cannot be read warns and stores nothing.

    Product change that fails it: ``_peek_session_id`` (session_manager.py:1765) replace ``return False, None`` with ``return True, None``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    folder = tmp_path / "a_folder"
    folder.mkdir()
    file_picker("getOpenFileName", str(folder))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()

    assert [(kind, title) for kind, title, _text in shown] == [("warning", "Import Failed")]
    assert shown[0][2].startswith("Failed to read file:\n")
    assert manager.list_sessions() == []


def test_import_via_manager_non_object_json_warns(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Importing a JSON array warns about the format and stores nothing.

    Product change that fails it: ``_peek_session_id`` (session_manager.py:1769) replace ``return False, None`` with ``return True, None``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "array.json"
    source.write_text("[]", encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()

    assert shown == [("warning", "Import Failed", "Invalid session file format.")]
    assert manager.list_sessions() == []


@pytest.mark.parametrize(
    ("payload", "expected_id"),
    [
        pytest.param({"session": {"id": "wrapped-id"}}, "wrapped-id", id="wrapped"),
        pytest.param({"id": "flat-id"}, "flat-id", id="flat"),
        pytest.param({"session": 5}, None, id="inner-not-an-object"),
        pytest.param({"id": 7}, None, id="id-not-text"),
        pytest.param({"session": {"name": "no id"}}, None, id="inner-without-id"),
    ],
)
def test_peek_session_id_reads_wrapped_and_flat_files(
    make_dialog: Callable[..., SessionManagerDialog],
    tmp_path: Path,
    payload: dict[str, object],
    expected_id: str | None,
) -> None:
    """The session id is read from the wrapped or the flat layout, and is ``None`` when absent or not text.

    Product change that fails it: ``_peek_session_id`` (session_manager.py:1772) replace ``outer.get("session", outer)`` with ``outer``.

    Args:
        make_dialog: Dialog factory.
        tmp_path: Pytest temporary directory.
        payload: File content.
        expected_id: Identifier the file is expected to yield.
    """
    path = tmp_path / "peek.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    dialog = make_dialog()

    assert _method(dialog, "_peek_session_id")(path) == (True, expected_id)


@pytest.mark.usefixtures("decline")
def test_import_via_manager_duplicate_declined_keeps_stored_session(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    shown: _Log,
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Declining the replace prompt for a stored id leaves the stored session as it was.

    Product change that fails it: ``_import_via_manager`` (session_manager.py:1661) replace ``return`` with ``pass``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    session = _create(manager, "Original Name")
    run_bridge_coroutine(manager.close())
    source = tmp_path / "export.json"
    run_bridge_coroutine(manager.export_json(session.id, source))
    renamed = cast("dict[str, dict[str, object]]", json.loads(source.read_text(encoding="utf-8")))
    renamed["session"]["name"] = "Renamed By Import"
    source.write_text(json.dumps(renamed), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()
    drain_bridge_workers_for(dialog)

    assert _kinds(shown, "question") == [
        ("Session Exists", f"A session with ID '{session.id}' already exists.\n\nDo you want to replace it?"),
    ]
    stored = manager.store.load(session.id)
    assert stored is not None
    assert stored.name == "Original Name"
    assert _kinds(shown, "information") == []


def test_import_via_manager_duplicate_confirmed_replaces_stored_session(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """Confirming the replace prompt for a stored id replaces the stored session with the file's content.

    Product change that fails it: ``_import_via_manager`` (session_manager.py:1662) replace ``replace = True`` with ``replace = False``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    session = _create(manager, "Original Name")
    run_bridge_coroutine(manager.close())
    source = tmp_path / "export.json"
    run_bridge_coroutine(manager.export_json(session.id, source))
    renamed = cast("dict[str, dict[str, object]]", json.loads(source.read_text(encoding="utf-8")))
    renamed["session"]["name"] = "Renamed By Import"
    source.write_text(json.dumps(renamed), encoding="utf-8")
    file_picker("getOpenFileName", str(source))
    dialog = make_dialog(manager=manager)

    _method(dialog, "_import_session")()

    wait_for(("information", "Import Complete", f"Session imported from:\n{source}"))
    stored = manager.store.load(session.id)
    assert stored is not None
    assert stored.name == "Renamed By Import"
    assert [row[0] for row in _rows(dialog)] == ["Renamed By Import"]


def test_import_via_manager_stale_listing_reports_conflict_as_invalid_file(
    manager: SessionManager,
    make_dialog: Callable[..., SessionManagerDialog],
    wait_for: Callable[[_Entry], _Log],
    file_picker: Callable[[str, str], list[tuple[object, ...]]],
    tmp_path: Path,
) -> None:
    """When the id was stored after the dialog listed sessions, the manager's conflict error is shown as an invalid session file.

    Product change that fails it: ``_on_import_via_manager_failed`` (session_manager.py:1701) replace ``isinstance(error_obj, ValueError)``
    with ``isinstance(error_obj, KeyError)``.

    Args:
        manager: Real session manager.
        make_dialog: Dialog factory.
        wait_for: Waits for a message box to be recorded.
        file_picker: Installs an open-picker replacement.
        tmp_path: Pytest temporary directory.
    """
    dialog = make_dialog(manager=manager)
    session = _create(manager, "Late Arrival")
    run_bridge_coroutine(manager.close())
    source = tmp_path / "export.json"
    run_bridge_coroutine(manager.export_json(session.id, source))
    file_picker("getOpenFileName", str(source))

    _method(dialog, "_import_session")()

    wait_for(("warning", "Import Failed", "Invalid session file:\nsession already exists"))


def test_import_failure_slot_words_each_error_kind(make_dialog: Callable[..., SessionManagerDialog], shown: _Log, tmp_path: Path) -> None:
    """The import failure handler words a missing file, a bad session file and any other error differently.

    Product change that fails it: ``_on_import_via_manager_failed`` (session_manager.py:1700) replace ``{path}`` with ``{error_obj}``.

    Args:
        make_dialog: Dialog factory.
        shown: Recorded dialogs.
        tmp_path: Pytest temporary directory.
    """
    dialog = make_dialog()
    source = tmp_path / "import.json"
    handle = _method(dialog, "_on_import_via_manager_failed")

    handle(source, FileNotFoundError("gone"))
    handle(source, ValueError("bad shape"))
    handle(source, RuntimeError("kaput"))

    assert shown == [
        ("warning", "Import Failed", f"File not found:\n{source}"),
        ("warning", "Import Failed", "Invalid session file:\nbad shape"),
        ("warning", "Import Failed", "Failed to import session:\nkaput"),
    ]


def test_get_selected_session_id_follows_selection(make_dialog: Callable[..., SessionManagerDialog], sessions_dir: Path) -> None:
    """The selected id is ``None`` without a selection or without a name cell and the row's id otherwise.

    Product change that fails it: ``get_selected_session_id`` (session_manager.py:1862) return ``None`` instead of ``session_id``.

    Args:
        make_dialog: Dialog factory.
        sessions_dir: Sidecar directory.
    """
    _write_sidecar(sessions_dir, "one", _sidecar_payload("one-id", "One"))
    _write_sidecar(sessions_dir, "two", _sidecar_payload("two-id", "Two"))
    dialog = make_dialog()
    assert dialog.get_selected_session_id() is None

    _select(dialog, "two-id")
    assert dialog.get_selected_session_id() == "two-id"

    taken = _table(dialog).takeItem(_row_of(dialog, "two-id"), 0)
    assert taken is not None
    assert dialog.get_selected_session_id() is None


def test_new_session_dialog_defaults_and_strips_inputs() -> None:
    """The new-session dialog suggests a timestamped name and returns the entered texts without surrounding blanks.

    Product change that fails it: ``get_description`` (session_manager.py:1926) drop ``.strip()``.
    """
    before = datetime.now(tz=UTC)
    dialog = NewSessionDialog()
    after = datetime.now(tz=UTC)
    try:
        suggestions = {f"Session {moment.strftime(_MINUTE_FORMAT)}" for moment in (before, after)}
        assert dialog.get_session_name() in suggestions
        assert dialog.windowTitle() == "New Session"
        assert not dialog.get_description()

        _widget(dialog, "_name_input", QLineEdit).setText("  My Session  ")
        _widget(dialog, "_description_input", QLineEdit).setText("  some notes  ")

        assert dialog.get_session_name() == "My Session"
        assert dialog.get_description() == "some notes"
    finally:
        dialog.close()
        dialog.deleteLater()


@pytest.mark.parametrize(
    ("button", "result"),
    [
        pytest.param(QDialogButtonBox.StandardButton.Ok, QDialog.DialogCode.Accepted, id="ok"),
        pytest.param(QDialogButtonBox.StandardButton.Cancel, QDialog.DialogCode.Rejected, id="cancel"),
    ],
)
def test_new_session_dialog_buttons_accept_or_reject(button: QDialogButtonBox.StandardButton, result: QDialog.DialogCode) -> None:
    """Ok accepts the new-session dialog and Cancel rejects it.

    Product change that fails it: ``_on_accepted`` (session_manager.py:1910) replace ``self.accept()`` with ``self.reject()``.

    Args:
        button: Standard button to click.
        result: Dialog result the button must produce.
    """
    dialog = NewSessionDialog()
    try:
        box = dialog.findChild(QDialogButtonBox)
        assert box is not None
        target = box.button(button)
        assert target is not None

        target.click()

        assert dialog.result() == result.value
    finally:
        dialog.close()
        dialog.deleteLater()
