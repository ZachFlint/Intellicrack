# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C7 (F-0003): hex editor bookmarks notify state holder.

These tests guard against the regression where :meth:`BookmarksMixin._on_add_bookmark`
and :meth:`BookmarksMixin._on_remove_bookmark` mutated the document's bookmark
metadata without calling :meth:`HexDocumentState.notify_data_modified`. Bridge
subscribers (AI tools, peer GUIs) only learn about document state changes
through the state-holder event bus; if the panel adds or removes a bookmark
without firing ``notify_data_modified``, those subscribers analyse stale
annotated state after a GUI bookmark operation.

The add-path tests drive the *real* production handler
:meth:`BookmarksMixin._on_add_bookmark` end to end, faking only the two Qt modal
dialogs (``QInputDialog.getText`` and ``QColorDialog.getColor``) at the external
GUI transport boundary. Everything else - the cursor-offset read, the hardcoded
length, the ``source`` literal, the ``add_bookmark`` document mutation, and the
``notify_data_modified`` dispatch - is produced by production code, not the
test harness. The expected ``(offset, length, source)`` is recomputed
independently from the stubbed cursor position and the documented behaviour of
the handler so the assertions cannot be satisfied by data the test injected
into the notify call.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, override

import pytest
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication, QTreeWidget, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor import bookmarks as bookmarks_module
from intellicrack.ui.panels.hex_editor.bookmarks import BookmarksMixin


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack_hexcore import HexDocument


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


_DOC_LEN: Final[int] = 64
_BM_OFFSET: Final[int] = 8
_BM_LENGTH: Final[int] = 1
_BM_LABEL: Final[str] = "TestMark"
_BM_COLOR: Final[str] = "#FFFF00"
_ADD_SOURCE: Final[str] = "hex-editor.bookmarks.add"


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _make_doc() -> HexDocument:
    """Build a fresh in-memory :class:`HexDocument` for a test.

    Returns:
        HexDocument: New 64-byte document populated with bytes 0..63.
    """
    doc: HexDocument = hexcore_mod.HexDocument.open_bytes(bytes(range(_DOC_LEN)))
    return doc


class _RecordingState(HexDocumentState):
    """A real :class:`HexDocumentState` that records every notification dispatch.

    Subclasses the production state holder so the panel sees the
    canonical type, but overrides ``_notify`` to record the ``(event,
    data, source)`` triple for each dispatch. The underlying production
    pipeline is preserved so loop-guard semantics, lock acquisition, and
    re-entrancy bookkeeping behave identically to production.
    """

    def __init__(self) -> None:
        """Initialise the state holder and the empty recording list."""
        super().__init__()
        self.dispatched: list[tuple[HexDocumentEvent, dict[str, Any], str]] = []

    @override
    def _notify(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        *,
        source: str = "",
    ) -> None:
        """Record the dispatch then forward to the production dispatcher.

        Args:
            event_type: The state-holder event being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller for loop-guard filtering.
        """
        self.dispatched.append((event_type, dict(data), source))
        super()._notify(event_type, data, source=source)

    def data_modified_events(self) -> list[tuple[dict[str, Any], str]]:
        """Return DATA_MODIFIED (payload, source) tuples in dispatch order.

        Returns:
            list[tuple[dict[str, Any], str]]: Payload + source for every
                DATA_MODIFIED event ever published on this state holder.
        """
        return [(data, src) for evt, data, src in self.dispatched if evt is HexDocumentEvent.DATA_MODIFIED]


class _RaisingState(HexDocumentState):
    """A real :class:`HexDocumentState` whose ``notify_data_modified`` always raises.

    Used to prove the panel never dispatches a bookmark notification when no
    usable state holder is attached: if the production guard were removed and
    the handler dispatched anyway, the raise would surface as a test failure.
    """

    @override
    def notify_data_modified(
        self,
        offset: int,
        length: int,
        *,
        source: str = "",
    ) -> None:
        """Fail loudly: this state holder must never receive a dispatch.

        Args:
            offset: Start offset of the modification.
            length: Number of bytes affected.
            source: Identifier of the caller for loop-guard filtering.

        Raises:
            AssertionError: Always, because no notify must reach this holder.
        """
        msg = f"notify_data_modified must not be called (offset={offset}, length={length}, source={source!r})"
        raise AssertionError(msg)


class _StubHexWidget:
    """Minimal stand-in for the hex view widget exposing a cursor offset.

    The production add handler reads ``_cursor_offset`` to decide where to
    anchor a new bookmark.
    """

    def __init__(self, cursor_offset: int) -> None:
        """Initialise the stub with a fixed cursor offset.

        Args:
            cursor_offset: Byte offset reported as the current cursor position.
        """
        self._cursor_offset: int = cursor_offset


class _BookmarksHarness(BookmarksMixin, QWidget):
    """Minimal :class:`QWidget` subclass exposing :class:`BookmarksMixin` for tests.

    The harness wires the mixin's required attributes to a real
    :class:`HexDocument`, a real :class:`HexDocumentState`, a stub hex
    widget reporting a fixed cursor offset, and an in-process
    :class:`QTreeWidget` for the bookmarks list. The production handlers
    :meth:`_on_add_bookmark` and :meth:`_on_remove_bookmark` are driven
    directly; only the two Qt modal dialogs in :meth:`_on_add_bookmark`
    are faked at the external GUI boundary.
    """

    def __init__(
        self,
        document: HexDocument,
        state_holder: HexDocumentState | None,
        *,
        cursor_offset: int = _BM_OFFSET,
    ) -> None:
        """Initialise the harness with the document and shared state holder.

        Args:
            document: Real :class:`HexDocument` used as the panel's document.
            state_holder: Real :class:`HexDocumentState` published to so the
                test can inspect the resulting ``DATA_MODIFIED`` events, or
                None to exercise the absent-state-holder path.
            cursor_offset: Byte offset reported by the stub hex widget; the
                production add handler anchors the bookmark here.
        """
        super().__init__()
        self.document: HexDocument = document
        self._document: HexDocument = document
        self.state_holder: HexDocumentState | None = state_holder
        self._bookmarks_tree: QTreeWidget | None = QTreeWidget(self)
        self._bookmarks_tree.setColumnCount(3)
        self._hex_widget: _StubHexWidget = _StubHexWidget(cursor_offset)

    def invoke_on_add_bookmark_for_test(self) -> None:
        """Drive the real ``_on_add_bookmark`` handler.

        The two Qt dialogs are expected to be faked by the caller before
        invoking this method.
        """
        self._on_add_bookmark()

    def remove_bookmark_at(self, index: int) -> None:
        """Remove the bookmark at ``index`` via the mixin path, then notify.

        Selects the corresponding row in the tree widget so
        ``_on_remove_bookmark`` picks it up through ``currentItem()``.

        Args:
            index: Zero-based bookmark index to remove.
        """
        tree = self._bookmarks_tree
        assert tree is not None, "test harness always sets _bookmarks_tree"
        tree.setCurrentItem(tree.topLevelItem(index))
        self.remove_bookmark_for_test()

    def refresh_bookmarks_for_test(self) -> None:
        """Delegate to the protected refresh method, exposed for test accessibility."""
        self._refresh_bookmarks()

    def remove_bookmark_for_test(self) -> None:
        """Delegate to the protected remove method, exposed for test accessibility."""
        self._on_remove_bookmark()


def _patch_add_dialogs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    color: str,
) -> None:
    """Fake the two Qt modal dialogs used by ``_on_add_bookmark``.

    Only the external GUI transport boundary is replaced; the production
    handler body still computes the cursor offset, the length, the source
    literal, performs the ``add_bookmark`` mutation, and dispatches the
    notification.

    Args:
        monkeypatch: Pytest monkeypatch fixture for the duration of one test.
        name: Bookmark label the faked text dialog returns (accepted).
        color: Hex colour string the faked colour dialog returns as a valid
            :class:`QColor`.
    """

    def _fake_get_text(*args: object, **kwargs: object) -> tuple[str, bool]:
        """Return an accepted bookmark name from the text dialog.

        Args:
            *args: Positional dialog arguments, ignored.
            **kwargs: Keyword dialog arguments, ignored.

        Returns:
            tuple[str, bool]: The bookmark name and an accepted flag.
        """
        del args, kwargs
        return name, True

    def _fake_get_color(*args: object, **kwargs: object) -> QColor:
        """Return a valid colour from the colour dialog.

        Args:
            *args: Positional dialog arguments, ignored.
            **kwargs: Keyword dialog arguments, ignored.

        Returns:
            QColor: A valid colour parsed from the requested hex string.
        """
        del args, kwargs
        return QColor(color)

    monkeypatch.setattr(bookmarks_module.QInputDialog, "getText", staticmethod(_fake_get_text))
    monkeypatch.setattr(bookmarks_module.QColorDialog, "getColor", staticmethod(_fake_get_color))


@pytest.mark.usefixtures("qapp")
class TestAddBookmarkNotifies:
    """Verify that the real add-bookmark handler fires ``notify_data_modified``."""

    @staticmethod
    def test_add_bookmark_publishes_data_modified(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Drive the real ``_on_add_bookmark`` and assert exactly one DATA_MODIFIED fires.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()

        events = state.data_modified_events()
        assert len(events) == 1, f"expected exactly one DATA_MODIFIED event after _on_add_bookmark, got {len(events)}"
        bookmarks = doc.list_bookmarks()
        assert len(bookmarks) == 1, f"_on_add_bookmark must persist exactly one bookmark, got {len(bookmarks)}"

    @staticmethod
    def test_add_bookmark_offset_and_length_match_bookmark(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert the DATA_MODIFIED payload carries the cursor offset and length 1.

        The expected offset is the stub hex widget's cursor offset (recomputed
        independently of the notify call), and the expected length is the
        documented hardcoded value of 1. Both are also cross-checked against the
        bookmark the handler persisted in the document.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        cursor_offset = 23
        expected_length = 1
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=cursor_offset)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after _on_add_bookmark"
        payload, _source = events[0]
        assert payload["offset"] == cursor_offset, f"expected offset={cursor_offset} (cursor), got {payload['offset']}"
        assert payload["length"] == expected_length, f"expected length={expected_length}, got {payload['length']}"

        bookmarks = doc.list_bookmarks()
        assert bookmarks, "_on_add_bookmark must persist the bookmark in the document"
        bm_offset, bm_length = int(bookmarks[0][0]), int(bookmarks[0][1])
        assert bm_offset == cursor_offset, f"persisted bookmark offset {bm_offset} must equal cursor {cursor_offset}"
        assert bm_length == expected_length, f"persisted bookmark length {bm_length} must equal {expected_length}"
        assert payload["offset"] == bm_offset, "notify offset must match the persisted bookmark offset"
        assert payload["length"] == bm_length, "notify length must match the persisted bookmark length"

    @staticmethod
    def test_add_bookmark_source_literal_uses_bookmarks_namespace(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert the production source literal starts with ``hex-editor.bookmarks.``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after _on_add_bookmark"
        _payload, source = events[0]
        assert source == _ADD_SOURCE, f"_on_add_bookmark must dispatch with source {_ADD_SOURCE!r}; got {source!r}"
        assert source.startswith("hex-editor.bookmarks."), f"source must use the hex-editor.bookmarks namespace; got {source!r}"
        assert source not in {"panel", "bridge"}, f"source must not collide with panel/bridge loop-guard ids; got {source!r}"

    @staticmethod
    def test_panel_loop_guarded_subscriber_receives_add_event(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Register a panel-like subscriber and assert it receives the real add notify.

        A subscriber registered with ``source_id="panel"`` must NOT be
        filtered out by the loop guard when the production add handler fires
        with ``source="hex-editor.bookmarks.add"``. The event observed here
        originates entirely in ``_on_add_bookmark``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = HexDocumentState()
        received: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def _panel_callback(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
            """Record a delivered state event.

            Args:
                evt: The state-holder event delivered to this subscriber.
                data: The event payload.
            """
            received.append((evt, data))

        state.register_callback(_panel_callback, source_id="panel")

        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)
        harness.invoke_on_add_bookmark_for_test()

        data_events = [(evt, data) for evt, data in received if evt is HexDocumentEvent.DATA_MODIFIED]
        assert data_events, "panel-loop-guarded subscriber must receive DATA_MODIFIED when a bookmark is added"
        _evt, payload = data_events[0]
        assert payload["source"] == _ADD_SOURCE, f"delivered event must carry the production add source; got {payload['source']!r}"
        assert payload["offset"] == _BM_OFFSET, f"delivered event must carry the cursor offset; got {payload['offset']}"

    @staticmethod
    def test_add_bookmark_no_dispatch_when_state_holder_absent(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert the real add handler persists the bookmark and dispatches nothing when no state holder is attached.

        The handler runs end to end with ``state_holder=None``: the bookmark
        must still be created in the document (proving the handler body
        executed) and no exception may escape. The notify guard itself is then
        proven falsifiable by first attaching a :class:`_RaisingState` (a real
        holder whose ``notify_data_modified`` always raises) and confirming the
        helper does dispatch to it, then clearing the holder to None and
        confirming the helper short-circuits silently.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        doc = _make_doc()
        harness = _BookmarksHarness(doc, None, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()

        bookmarks = doc.list_bookmarks()
        assert len(bookmarks) == 1, f"_on_add_bookmark must persist the bookmark even without a state holder, got {len(bookmarks)}"
        bm_offset, bm_length = int(bookmarks[0][0]), int(bookmarks[0][1])
        assert bm_offset == _BM_OFFSET, f"persisted bookmark offset {bm_offset} must equal cursor {_BM_OFFSET}"
        assert bm_length == 1, f"persisted bookmark length {bm_length} must equal 1"

        notify = getattr(harness, "_notify_state_data_modified")

        harness.state_holder = _RaisingState()
        with pytest.raises(AssertionError, match="notify_data_modified must not be called"):
            notify(_BM_OFFSET, 1, source=_ADD_SOURCE)

        harness.state_holder = None
        notify(_BM_OFFSET, 1, source=_ADD_SOURCE)


@pytest.mark.usefixtures("qapp")
class TestRemoveBookmarkNotifies:
    """Verify that removing a bookmark fires ``notify_data_modified``."""

    @staticmethod
    def test_remove_bookmark_publishes_data_modified(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Add then remove a bookmark and assert exactly one DATA_MODIFIED fires on removal.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert len(events) == 1, f"expected exactly one DATA_MODIFIED event after remove_bookmark, got {len(events)}"

    @staticmethod
    def test_remove_bookmark_offset_and_length_match_removed_bookmark(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert the DATA_MODIFIED payload on removal carries the removed bookmark's extent.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        bm_offset = 16
        harness = _BookmarksHarness(doc, state, cursor_offset=bm_offset)
        _patch_add_dialogs(monkeypatch, name="RemoveMe", color="#FF0000")

        harness.invoke_on_add_bookmark_for_test()
        expected_offset, expected_length = int(doc.list_bookmarks()[0][0]), int(doc.list_bookmarks()[0][1])
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after remove_bookmark"
        payload, _source = events[0]
        assert payload["offset"] == expected_offset, f"expected offset={expected_offset}, got {payload['offset']}"
        assert payload["length"] == expected_length, f"expected length={expected_length}, got {payload['length']}"

    @staticmethod
    def test_remove_bookmark_source_literal_uses_bookmarks_namespace(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert the remove source literal starts with ``hex-editor.bookmarks.``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture to fake the Qt dialogs.
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        _patch_add_dialogs(monkeypatch, name=_BM_LABEL, color=_BM_COLOR)

        harness.invoke_on_add_bookmark_for_test()
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after remove_bookmark"
        _payload, source = events[0]
        assert source == "hex-editor.bookmarks.remove", f"_on_remove_bookmark must dispatch with the remove source; got {source!r}"
        assert source.startswith("hex-editor.bookmarks."), f"source must use the hex-editor.bookmarks namespace; got {source!r}"
        assert source not in {"panel", "bridge"}, f"source must not collide with panel/bridge loop-guard ids; got {source!r}"

    @staticmethod
    def test_panel_loop_guarded_subscriber_receives_remove_event(qapp: QApplication) -> None:
        """Register a panel-like subscriber and assert it receives the remove notify.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = HexDocumentState()
        received: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def _panel_callback(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
            """Record a delivered state event.

            Args:
                evt: The state-holder event delivered to this subscriber.
                data: The event payload.
            """
            received.append((evt, data))

        state.register_callback(_panel_callback, source_id="panel")

        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)

        doc.add_bookmark(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)
        harness.refresh_bookmarks_for_test()
        received.clear()

        harness.remove_bookmark_at(0)

        data_events = [(evt, data) for evt, data in received if evt is HexDocumentEvent.DATA_MODIFIED]
        assert data_events, "panel-loop-guarded subscriber must receive DATA_MODIFIED when a bookmark is removed"

    @staticmethod
    def test_remove_bookmark_no_op_when_no_current_selection(qapp: QApplication) -> None:
        """Assert no error and no notify when no tree item is selected.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state, cursor_offset=_BM_OFFSET)
        harness.refresh_bookmarks_for_test()

        harness.remove_bookmark_for_test()

        assert state.data_modified_events() == [], "no DATA_MODIFIED must fire when remove_bookmark is called with no selection"


@pytest.mark.usefixtures("qapp")
class TestBookmarksModuleSourceContainsNotifyMarkers:
    """Static guard: the bookmarks module must reference the notify helper.

    Prevents the regression from sneaking back in via a refactor that
    removes the notify calls without replacing them with the bridge's own
    dispatch.
    """

    @staticmethod
    def test_bookmarks_module_references_notify_helper() -> None:
        """Verify the panel source references ``_notify_state_data_modified``."""
        source = Path(bookmarks_module.__file__).read_text(encoding="utf-8")
        required_substrings = [
            "_notify_state_data_modified",
            "hex-editor.bookmarks.add",
            "hex-editor.bookmarks.remove",
        ]
        missing = [needle for needle in required_substrings if needle not in source]
        assert not missing, (
            f"Bookmarks mixin must publish DATA_MODIFIED for every mutation; missing notify markers: {missing}. Both _on_add_bookmark and _on_remove_bookmark must call self._notify_state_data_modified(offset, length, source=...)."
        )
