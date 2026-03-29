# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocumentState event and callback management.

Covers all 12 event types, callback registration/unregistration, loop-guard
source-id filtering, reentrancy guard, and thread-safety.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intellicrack.bridges.hex_state import (
    HexDocumentEvent,
    HexDocumentState,
    StateCallbackFn,
)


type _StateTrigger = Callable[[HexDocumentState], None]

type _EventList = list[tuple[HexDocumentEvent, dict[str, Any]]]


def _make_collector() -> tuple[_EventList, StateCallbackFn]:
    """Build a fresh event collector and its bound callback.

    Returns:
        tuple[_EventList, StateCallbackFn]: A
            (events_list, callback) pair.  The list is appended to by
            the callback on every invocation.
    """
    events: _EventList = []

    def on_event(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        events.append((event_type, data))

    return events, on_event


class TestStateInitialization:
    """Verify that a freshly constructed HexDocumentState has correct defaults."""

    def test_document_is_none(self) -> None:
        """New state has no document."""
        state = HexDocumentState()
        assert state.document is None

    def test_file_path_is_none(self) -> None:
        """New state has no file path."""
        state = HexDocumentState()
        assert state.file_path is None

    def test_cursor_offset_is_zero(self) -> None:
        """New state cursor starts at offset zero."""
        state = HexDocumentState()
        assert state.cursor_offset == 0

    def test_selection_is_none(self) -> None:
        """New state has no selection."""
        state = HexDocumentState()
        assert state.selection is None


class TestDocumentEvents:
    """Tests for DOCUMENT_OPENED and DOCUMENT_CLOSED events via set_document."""

    def test_set_document_fires_document_opened(self) -> None:
        """set_document with a non-None object fires DOCUMENT_OPENED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        dummy_doc = object()
        state.set_document(dummy_doc, Path("/nonexistent/test.bin"))

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DOCUMENT_OPENED

    def test_set_document_opened_contains_file_path(self) -> None:
        """DOCUMENT_OPENED event data contains the string file path."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        p = Path("/nonexistent/sample.bin")
        state.set_document(object(), p)

        assert events[0][1]["file_path"] == str(p)

    def test_set_document_none_fires_document_closed(self) -> None:
        """set_document(None, None) fires DOCUMENT_CLOSED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_document(None, None)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DOCUMENT_CLOSED

    def test_set_document_resets_cursor(self) -> None:
        """set_document resets cursor_offset to 0."""
        state = HexDocumentState()
        state.set_cursor(999)
        state.set_document(object(), None)
        assert state.cursor_offset == 0

    def test_set_document_resets_selection(self) -> None:
        """set_document clears any existing selection."""
        state = HexDocumentState()
        state.set_selection(10, 20)
        state.set_document(object(), None)
        assert state.selection is None

    def test_set_document_reflects_on_property(self) -> None:
        """Document property returns the object passed to set_document."""
        state = HexDocumentState()
        dummy = object()
        state.set_document(dummy, None)
        assert state.document is dummy

    def test_set_document_file_path_property(self) -> None:
        """file_path property reflects the Path passed to set_document."""
        state = HexDocumentState()
        p = Path("/nonexistent/abc.bin")
        state.set_document(object(), p)
        assert state.file_path == p


class TestCursorEvents:
    """Tests for CURSOR_MOVED events emitted by set_cursor."""

    def test_set_cursor_fires_cursor_moved(self) -> None:
        """set_cursor fires exactly one CURSOR_MOVED event."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(42)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.CURSOR_MOVED

    def test_set_cursor_event_data_offset(self) -> None:
        """CURSOR_MOVED event data contains the correct offset."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(42)

        assert events[0][1]["offset"] == 42

    def test_cursor_offset_property_updated(self) -> None:
        """cursor_offset property reflects the value passed to set_cursor."""
        state = HexDocumentState()
        state.set_cursor(1024)
        assert state.cursor_offset == 1024

    def test_set_cursor_zero(self) -> None:
        """set_cursor(0) still fires CURSOR_MOVED with offset=0."""
        state = HexDocumentState()
        state.set_cursor(100)
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(0)

        assert events[0][1]["offset"] == 0
        assert state.cursor_offset == 0


class TestSelectionEvents:
    """Tests for SELECTION_CHANGED events from set_selection and clear_selection."""

    def test_set_selection_fires_selection_changed(self) -> None:
        """set_selection fires SELECTION_CHANGED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_selection(10, 50)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.SELECTION_CHANGED

    def test_set_selection_event_data(self) -> None:
        """SELECTION_CHANGED event data contains correct start and end."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_selection(10, 50)

        assert events[0][1]["start"] == 10
        assert events[0][1]["end"] == 50

    def test_selection_property_updated(self) -> None:
        """Selection property reflects the range passed to set_selection."""
        state = HexDocumentState()
        state.set_selection(5, 15)
        assert state.selection == (5, 15)

    def test_clear_selection_fires_selection_changed(self) -> None:
        """clear_selection fires SELECTION_CHANGED."""
        state = HexDocumentState()
        state.set_selection(5, 15)
        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_selection()

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.SELECTION_CHANGED

    def test_clear_selection_event_data_sentinel(self) -> None:
        """clear_selection fires SELECTION_CHANGED with start=-1 and end=-1."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_selection()

        assert events[0][1]["start"] == -1
        assert events[0][1]["end"] == -1

    def test_clear_selection_property_is_none(self) -> None:
        """Selection property is None after clear_selection."""
        state = HexDocumentState()
        state.set_selection(1, 2)
        state.clear_selection()
        assert state.selection is None


class TestDataModifiedEvent:
    """Tests for DATA_MODIFIED events from notify_data_modified."""

    def test_notify_data_modified_fires_event(self) -> None:
        """notify_data_modified fires DATA_MODIFIED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_data_modified(100, 32)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DATA_MODIFIED

    def test_notify_data_modified_event_data(self) -> None:
        """DATA_MODIFIED event data contains correct offset and length."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_data_modified(100, 32)

        assert events[0][1]["offset"] == 100
        assert events[0][1]["length"] == 32


class TestDocumentSavedEvent:
    """Tests for DOCUMENT_SAVED events from notify_document_saved."""

    def test_notify_document_saved_fires_event(self) -> None:
        """notify_document_saved fires DOCUMENT_SAVED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_document_saved("/nonexistent/out.bin")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DOCUMENT_SAVED

    def test_notify_document_saved_event_data(self) -> None:
        """DOCUMENT_SAVED event data contains the correct path string."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_document_saved("/nonexistent/out.bin")

        assert events[0][1]["path"] == "/nonexistent/out.bin"


class TestTemplateEvents:
    """Tests for TEMPLATE_REGISTERED and TEMPLATE_REMOVED events."""

    def test_notify_template_registered_fires_event(self) -> None:
        """notify_template_registered fires TEMPLATE_REGISTERED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_template_registered("pe_struct")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.TEMPLATE_REGISTERED

    def test_notify_template_registered_event_data(self) -> None:
        """TEMPLATE_REGISTERED event data contains the correct template_name."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_template_registered("pe_struct")

        assert events[0][1]["template_name"] == "pe_struct"

    def test_notify_template_removed_fires_event(self) -> None:
        """notify_template_removed fires TEMPLATE_REMOVED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_template_removed("pe_struct")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.TEMPLATE_REMOVED

    def test_notify_template_removed_event_data(self) -> None:
        """TEMPLATE_REMOVED event data contains the correct template_name."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_template_removed("pe_struct")

        assert events[0][1]["template_name"] == "pe_struct"


class TestHighlightEvents:
    """Tests for HIGHLIGHT_RULE_ADDED and HIGHLIGHT_RULE_REMOVED events."""

    def test_notify_highlight_rule_added_fires_event(self) -> None:
        """notify_highlight_rule_added fires HIGHLIGHT_RULE_ADDED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        rule: dict[str, Any] = {
            "id": "rule-1",
            "condition_type": "value",
            "condition_params": {"value": 0xFF},
            "color": "#FF0000",
        }
        state.notify_highlight_rule_added(rule)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.HIGHLIGHT_RULE_ADDED

    def test_notify_highlight_rule_added_event_data(self) -> None:
        """HIGHLIGHT_RULE_ADDED event data contains the exact rule dict."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        rule: dict[str, Any] = {
            "id": "rule-1",
            "condition_type": "value",
            "condition_params": {"value": 0xFF},
            "color": "#FF0000",
        }
        state.notify_highlight_rule_added(rule)

        assert events[0][1]["rule"] is rule

    def test_notify_highlight_rule_removed_fires_event(self) -> None:
        """notify_highlight_rule_removed fires HIGHLIGHT_RULE_REMOVED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_highlight_rule_removed("rule-1")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED

    def test_notify_highlight_rule_removed_event_data(self) -> None:
        """HIGHLIGHT_RULE_REMOVED event data contains the correct rule_id."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_highlight_rule_removed("rule-1")

        assert events[0][1]["rule_id"] == "rule-1"


class TestDisplayModeEvent:
    """Tests for DISPLAY_MODE_CHANGED events from notify_display_mode_changed."""

    def test_notify_display_mode_changed_fires_event(self) -> None:
        """notify_display_mode_changed fires DISPLAY_MODE_CHANGED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_display_mode_changed("hex16_le")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DISPLAY_MODE_CHANGED

    def test_notify_display_mode_changed_event_data(self) -> None:
        """DISPLAY_MODE_CHANGED event data contains the correct mode string."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_display_mode_changed("hex16_le")

        assert events[0][1]["mode"] == "hex16_le"


class TestPatternExecutedEvent:
    """Tests for PATTERN_EXECUTED events from notify_pattern_executed."""

    def test_notify_pattern_executed_fires_event(self) -> None:
        """notify_pattern_executed fires PATTERN_EXECUTED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_pattern_executed("pe.hexpat", 12)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.PATTERN_EXECUTED

    def test_notify_pattern_executed_event_data(self) -> None:
        """PATTERN_EXECUTED event data contains pattern_name and field_count."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_pattern_executed("pe.hexpat", 12)

        assert events[0][1]["pattern_name"] == "pe.hexpat"
        assert events[0][1]["field_count"] == 12


class TestCallbackManagement:
    """Tests for callback registration, unregistration, and multi-callback delivery."""

    def test_unregistered_callback_not_called(self) -> None:
        """A callback removed via unregister_callback receives no further events."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        state.unregister_callback(cb)

        state.set_cursor(99)

        assert len(events) == 0

    def test_multiple_callbacks_all_fire(self) -> None:
        """All registered callbacks receive the same event."""
        state = HexDocumentState()
        events_a, cb_a = _make_collector()
        events_b, cb_b = _make_collector()

        state.register_callback(cb_a)
        state.register_callback(cb_b)
        state.set_cursor(7)

        assert len(events_a) == 1
        assert len(events_b) == 1
        assert events_a[0][0] == HexDocumentEvent.CURSOR_MOVED
        assert events_b[0][0] == HexDocumentEvent.CURSOR_MOVED

    def test_remaining_callback_fires_after_partial_unregister(self) -> None:
        """After removing one of two callbacks, the remaining one still fires."""
        state = HexDocumentState()
        events_a, cb_a = _make_collector()
        events_b, cb_b = _make_collector()

        state.register_callback(cb_a)
        state.register_callback(cb_b)
        state.unregister_callback(cb_a)
        state.set_cursor(55)

        assert len(events_a) == 0
        assert len(events_b) == 1

    def test_register_same_callback_twice_fires_twice(self) -> None:
        """Registering the same callback twice results in two invocations per event."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        state.register_callback(cb)

        state.set_cursor(3)

        assert len(events) == 2


class TestLoopGuard:
    """Tests for source_id loop-guard filtering in _notify."""

    def test_callback_with_matching_source_id_skipped(self) -> None:
        """A callback registered with source_id='gui' is not called when source='gui'."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb, source_id="gui")

        state.set_cursor(10, source="gui")

        assert len(events) == 0

    def test_callback_with_different_source_id_called(self) -> None:
        """A callback registered with source_id='bridge' is called when source='gui'."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb, source_id="bridge")

        state.set_cursor(10, source="gui")

        assert len(events) == 1

    def test_callback_with_empty_source_id_always_called(self) -> None:
        """A callback registered with no source_id is always called regardless of source."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(5, source="gui")

        assert len(events) == 1

    def test_source_id_filter_independent_of_event_type(self) -> None:
        """Loop-guard filtering applies to all event types, not just CURSOR_MOVED."""
        state = HexDocumentState()
        events_filtered, cb_filtered = _make_collector()
        events_other, cb_other = _make_collector()

        state.register_callback(cb_filtered, source_id="panel")
        state.register_callback(cb_other, source_id="bridge")

        state.notify_data_modified(0, 16, source="panel")

        assert len(events_filtered) == 0
        assert len(events_other) == 1

    def test_empty_source_string_does_not_match_nonempty_source_id(self) -> None:
        """An event with source='' does not skip callbacks with non-empty source_id."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb, source_id="gui")

        state.set_cursor(20, source="")

        assert len(events) == 1


class TestReentrancyGuard:
    """Tests for the _notify_guard reentrancy protection."""

    def test_reentrant_notify_does_not_cause_infinite_loop(self) -> None:
        """A callback that triggers another notify does not recurse infinitely."""
        state = HexDocumentState()
        call_count = 0

        def reentrant_cb(_event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            state.set_cursor(call_count + 1)

        state.register_callback(reentrant_cb)
        state.set_cursor(1)

        assert call_count == 1

    def test_guard_released_after_normal_dispatch(self) -> None:
        """_notify_guard is released after dispatch so subsequent calls work."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(1)
        state.set_cursor(2)

        assert len(events) == 2
        assert events[0][1]["offset"] == 1
        assert events[1][1]["offset"] == 2


class TestThreadSafety:
    """Tests for thread-safe callback registration and concurrent state operations."""

    def test_register_callbacks_from_multiple_threads(self) -> None:
        """Callbacks registered concurrently from many threads are all invoked."""
        state = HexDocumentState()
        all_events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []
        lock = threading.Lock()

        def make_cb() -> StateCallbackFn:
            def cb(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
                with lock:
                    all_events.append((event_type, data))

            return cb

        num_threads = 20
        callbacks = [make_cb() for _ in range(num_threads)]
        errors: list[Exception] = []

        def register(cb: StateCallbackFn) -> None:
            try:
                state.register_callback(cb)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=register, args=(cb,)) for cb in callbacks]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

        state.set_cursor(42)

        assert len(all_events) == num_threads
        assert all(e[0] == HexDocumentEvent.CURSOR_MOVED for e in all_events)

    def test_concurrent_set_cursor_does_not_raise(self) -> None:
        """Concurrent set_cursor calls from many threads complete without errors."""
        state = HexDocumentState()
        errors: list[Exception] = []
        lock = threading.Lock()

        def do_set_cursor(offset: int) -> None:
            try:
                state.set_cursor(offset)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=do_set_cursor, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_unregister_while_concurrent_notify_does_not_raise(self) -> None:
        """Unregistering callbacks while events are being dispatched is safe."""
        state = HexDocumentState()
        errors: list[Exception] = []
        lock = threading.Lock()
        _, cb = _make_collector()
        state.register_callback(cb)

        def spam_events() -> None:
            for i in range(100):
                try:
                    state.set_cursor(i)
                except Exception as exc:
                    with lock:
                        errors.append(exc)

        def unregister() -> None:
            try:
                state.unregister_callback(cb)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        t1 = threading.Thread(target=spam_events)
        t2 = threading.Thread(target=unregister)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors


def _trigger_document_opened(s: HexDocumentState) -> None:
    s.set_document(object(), None)


def _trigger_document_closed(s: HexDocumentState) -> None:
    s.set_document(None, None)


def _trigger_cursor_moved(s: HexDocumentState) -> None:
    s.set_cursor(1)


def _trigger_selection_changed(s: HexDocumentState) -> None:
    s.set_selection(0, 10)


def _trigger_data_modified(s: HexDocumentState) -> None:
    s.notify_data_modified(0, 8)


def _trigger_document_saved(s: HexDocumentState) -> None:
    s.notify_document_saved("/nonexistent/x.bin")


def _trigger_template_registered(s: HexDocumentState) -> None:
    s.notify_template_registered("t")


def _trigger_template_removed(s: HexDocumentState) -> None:
    s.notify_template_removed("t")


def _trigger_highlight_rule_added(s: HexDocumentState) -> None:
    s.notify_highlight_rule_added({"id": "r1"})


def _trigger_highlight_rule_removed(s: HexDocumentState) -> None:
    s.notify_highlight_rule_removed("r1")


def _trigger_display_mode_changed(s: HexDocumentState) -> None:
    s.notify_display_mode_changed("hex8")


def _trigger_pattern_executed(s: HexDocumentState) -> None:
    s.notify_pattern_executed("pe.hexpat", 3)


@pytest.mark.parametrize(
    ("event_type", "trigger"),
    [
        (HexDocumentEvent.DOCUMENT_OPENED, _trigger_document_opened),
        (HexDocumentEvent.DOCUMENT_CLOSED, _trigger_document_closed),
        (HexDocumentEvent.CURSOR_MOVED, _trigger_cursor_moved),
        (HexDocumentEvent.SELECTION_CHANGED, _trigger_selection_changed),
        (HexDocumentEvent.DATA_MODIFIED, _trigger_data_modified),
        (HexDocumentEvent.DOCUMENT_SAVED, _trigger_document_saved),
        (HexDocumentEvent.TEMPLATE_REGISTERED, _trigger_template_registered),
        (HexDocumentEvent.TEMPLATE_REMOVED, _trigger_template_removed),
        (HexDocumentEvent.HIGHLIGHT_RULE_ADDED, _trigger_highlight_rule_added),
        (HexDocumentEvent.HIGHLIGHT_RULE_REMOVED, _trigger_highlight_rule_removed),
        (HexDocumentEvent.DISPLAY_MODE_CHANGED, _trigger_display_mode_changed),
        (HexDocumentEvent.PATTERN_EXECUTED, _trigger_pattern_executed),
    ],
)
def test_all_12_event_types_delivered(
    event_type: HexDocumentEvent,
    trigger: _StateTrigger,
) -> None:
    """Every HexDocumentEvent value is delivered to a registered callback.

    Args:
        event_type: The expected HexDocumentEvent value.
        trigger: A callable accepting a HexDocumentState that fires the event.
    """
    state = HexDocumentState()
    events, cb = _make_collector()
    state.register_callback(cb)

    trigger(state)

    assert len(events) >= 1
    assert events[-1][0] == event_type
