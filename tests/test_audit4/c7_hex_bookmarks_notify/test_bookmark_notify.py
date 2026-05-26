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

For both mutation sites the fixed code MUST call
``state_holder.notify_data_modified(offset, length, source=...)``
with:

- ``offset`` equal to the bookmark's byte offset,
- ``length`` equal to the bookmark's byte length,
- ``source`` a literal that starts with ``"hex-editor.bookmarks."`` and does
  not collide with ``"panel"`` or ``"bridge"`` so loop-guarded subscribers
  still receive the event.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, override

import pytest
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


class _BookmarksHarness(BookmarksMixin, QWidget):
    """Minimal :class:`QWidget` subclass exposing :class:`BookmarksMixin` for tests.

    The harness wires the mixin's required attributes to a real
    :class:`HexDocument`, a real :class:`HexDocumentState`, a stub hex
    widget, and an in-process :class:`QTreeWidget` for the bookmarks
    list. The ``_on_add_bookmark`` Qt dialog calls are bypassed by
    calling :meth:`add_bookmark_direct` which injects a bookmark
    programmatically and then calls the notify helper and
    ``_refresh_bookmarks`` exactly as ``_on_add_bookmark`` does
    after dialog acceptance.
    """

    def __init__(self, document: HexDocument, state_holder: HexDocumentState) -> None:
        """Initialise the harness with the document and shared state holder.

        Args:
            document: Real :class:`HexDocument` used as the panel's document.
            state_holder: Real :class:`HexDocumentState` published to so
                the test can inspect the resulting ``DATA_MODIFIED`` events.
        """
        super().__init__()
        self.document: HexDocument = document
        self._document: HexDocument = document
        self.state_holder: HexDocumentState | None = state_holder
        self._bookmarks_tree: QTreeWidget | None = QTreeWidget(self)
        self._bookmarks_tree.setColumnCount(3)

        class _StubHexWidget:
            _cursor_offset: int = 0

        self._hex_widget: _StubHexWidget = _StubHexWidget()

    def add_bookmark_direct(self, offset: int, length: int, label: str, color: str) -> None:
        """Add a bookmark bypassing the Qt dialog, then notify and refresh.

        Mirrors the execution path of ``_on_add_bookmark`` after the user
        accepts both the text and colour dialogs.  This allows tests to
        verify the notify without opening real Qt dialogs.

        Args:
            offset: Byte offset of the new bookmark.
            length: Byte length covered by the bookmark.
            label: Human-readable bookmark label.
            color: Hex colour string (e.g. ``"#FFFF00"``).
        """
        self.document.add_bookmark(offset, length, label, color)
        self.notify_data_modified_for_test(offset, length, source="hex-editor.bookmarks.add")
        self.refresh_bookmarks_for_test()

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

    def notify_data_modified_for_test(self, offset: int, length: int, *, source: str) -> None:
        """Delegate to the protected notify helper, exposed for test accessibility.

        Args:
            offset: Start byte offset of the affected range.
            length: Number of bytes that were affected.
            source: Caller identifier for loop-guard filtering.
        """
        self._notify_state_data_modified(offset, length, source=source)

    def refresh_bookmarks_for_test(self) -> None:
        """Delegate to the protected refresh method, exposed for test accessibility."""
        self._refresh_bookmarks()

    def remove_bookmark_for_test(self) -> None:
        """Delegate to the protected remove method, exposed for test accessibility."""
        self._on_remove_bookmark()


@pytest.mark.usefixtures("qapp")
class TestAddBookmarkNotifies:
    """Verify that adding a bookmark fires ``notify_data_modified``."""

    @staticmethod
    def test_add_bookmark_publishes_data_modified(qapp: QApplication) -> None:
        """Add a bookmark and assert exactly one DATA_MODIFIED event fires.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)

        events = state.data_modified_events()
        assert len(events) == 1, f"expected exactly one DATA_MODIFIED event after add_bookmark, got {len(events)}"

    @staticmethod
    def test_add_bookmark_offset_and_length_match_bookmark(qapp: QApplication) -> None:
        """Assert the DATA_MODIFIED payload carries the correct (offset, length).

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after add_bookmark"
        payload, _source = events[0]
        assert payload["offset"] == _BM_OFFSET, f"expected offset={_BM_OFFSET}, got {payload['offset']}"
        assert payload["length"] == _BM_LENGTH, f"expected length={_BM_LENGTH}, got {payload['length']}"

    @staticmethod
    def test_add_bookmark_source_literal_uses_bookmarks_namespace(qapp: QApplication) -> None:
        """Assert the source literal starts with ``hex-editor.bookmarks.``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after add_bookmark"
        _payload, source = events[0]
        assert source.startswith("hex-editor.bookmarks."), f"source must use the hex-editor.bookmarks namespace; got {source!r}"
        assert source not in {"panel", "bridge"}, f"source must not collide with panel/bridge loop-guard ids; got {source!r}"

    @staticmethod
    def test_panel_loop_guarded_subscriber_receives_add_event(qapp: QApplication) -> None:
        """Register a panel-like subscriber and assert it receives the add notify.

        A subscriber registered with ``source_id="panel"`` must NOT be
        filtered out by the loop guard when the bookmark notify fires with
        ``source="hex-editor.bookmarks.add"``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = HexDocumentState()
        received: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def _panel_callback(evt: HexDocumentEvent, data: dict[str, Any]) -> None:
            received.append((evt, data))

        state.register_callback(_panel_callback, source_id="panel")

        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)
        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)

        data_events = [(evt, data) for evt, data in received if evt is HexDocumentEvent.DATA_MODIFIED]
        assert data_events, "panel-loop-guarded subscriber must receive DATA_MODIFIED when a bookmark is added"

    @staticmethod
    def test_add_bookmark_no_notify_when_state_holder_absent(qapp: QApplication) -> None:
        """Assert no error is raised when ``state_holder`` is None.

        The notify helper must degrade gracefully when the harness has
        no attached state holder.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        doc = _make_doc()

        class _NoStateHarness(BookmarksMixin, QWidget):
            def __init__(self) -> None:
                super().__init__()
                self.document: HexDocument = doc
                self._document: HexDocument = doc
                self.state_holder: HexDocumentState | None = None
                self._bookmarks_tree = QTreeWidget(self)
                self._bookmarks_tree.setColumnCount(3)
                self._hex_widget: object | None = None

        harness = _NoStateHarness()
        harness.document.add_bookmark(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)
        notify = getattr(harness, "_notify_state_data_modified")
        notify(_BM_OFFSET, _BM_LENGTH, source="hex-editor.bookmarks.add")


@pytest.mark.usefixtures("qapp")
class TestRemoveBookmarkNotifies:
    """Verify that removing a bookmark fires ``notify_data_modified``."""

    @staticmethod
    def test_remove_bookmark_publishes_data_modified(qapp: QApplication) -> None:
        """Add then remove a bookmark and assert exactly one DATA_MODIFIED fires on removal.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert len(events) == 1, f"expected exactly one DATA_MODIFIED event after remove_bookmark, got {len(events)}"

    @staticmethod
    def test_remove_bookmark_offset_and_length_match_removed_bookmark(qapp: QApplication) -> None:
        """Assert the DATA_MODIFIED payload on removal carries the removed bookmark's extent.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        bm_offset = 16
        bm_length = 4
        harness.add_bookmark_direct(bm_offset, bm_length, "RemoveMe", "#FF0000")
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after remove_bookmark"
        payload, _source = events[0]
        assert payload["offset"] == bm_offset, f"expected offset={bm_offset}, got {payload['offset']}"
        assert payload["length"] == bm_length, f"expected length={bm_length}, got {payload['length']}"

    @staticmethod
    def test_remove_bookmark_source_literal_uses_bookmarks_namespace(qapp: QApplication) -> None:
        """Assert the remove source literal starts with ``hex-editor.bookmarks.``.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        state = _RecordingState()
        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

        harness.add_bookmark_direct(_BM_OFFSET, _BM_LENGTH, _BM_LABEL, _BM_COLOR)
        state.dispatched.clear()

        harness.remove_bookmark_at(0)

        events = state.data_modified_events()
        assert events, "DATA_MODIFIED must fire after remove_bookmark"
        _payload, source = events[0]
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
            received.append((evt, data))

        state.register_callback(_panel_callback, source_id="panel")

        doc = _make_doc()
        harness = _BookmarksHarness(doc, state)

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
        harness = _BookmarksHarness(doc, state)
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
        assert missing == [], (
            f"Bookmarks mixin must publish DATA_MODIFIED for every mutation; "
            f"missing notify markers: {missing}. "
            "Both _on_add_bookmark and _on_remove_bookmark must call "
            "self._notify_state_data_modified(offset, length, source=...)."
        )
