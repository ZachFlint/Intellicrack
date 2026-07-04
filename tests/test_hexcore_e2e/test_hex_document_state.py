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
    NOTIFY_MAX_DEPTH,
    HexDocumentEvent,
    HexDocumentState,
    StateCallbackFn,
)


type _StateTrigger = Callable[[HexDocumentState], None]

type _EventList = list[tuple[HexDocumentEvent, dict[str, Any]]]


class _DummyDoc:
    """Minimal concrete implementation of HexDocumentFull for state tests.

    Implements all methods required by the HexDocumentFull Protocol with
    stub bodies.  State tests only use this as a non-None document sentinel;
    no real document operations are performed.
    """

    def read(self, offset: int, length: int) -> list[int]:
        """Return an empty byte list (stub).

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to read.

        Returns:
            list[int]: Empty list.
        """
        _ = (self, offset, length)
        return []

    def length(self) -> int:
        """Return zero length (stub).

        Returns:
            int: Always zero.
        """
        _ = self
        return 0

    def write(self, offset: int, data: bytes) -> None:
        """No-op write (stub).

        Args:
            offset: Byte offset to write at.
            data: Bytes to write.
        """
        _ = (self, offset, data)

    def list_templates(self) -> list[tuple[str, str]]:
        """Return an empty template list (stub).

        Returns:
            list[tuple[str, str]]: Empty list.
        """
        _ = self
        return []

    def list_templates_detailed(self) -> list[object]:
        """Return an empty detailed template list (stub).

        Returns:
            list[object]: Empty list.
        """
        _ = self
        return []

    def register_json_template(self, name: str, json_str: str) -> None:
        """No-op register (stub).

        Args:
            name: Template name.
            json_str: JSON string.
        """
        _ = (self, name, json_str)

    def remove_template(self, name: str) -> None:
        """No-op remove (stub).

        Args:
            name: Template name.
        """
        _ = (self, name)

    def export_template_json(self, name: str) -> str:
        """Return an empty JSON string (stub).

        Args:
            name: Template name.

        Returns:
            str: Empty string.
        """
        _ = (self, name)
        return ""

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Return an empty inspection dict (stub).

        Args:
            offset: Byte offset to inspect.

        Returns:
            dict[str, object]: Empty dict.
        """
        _ = (self, offset)
        return {}


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

        dummy_doc = _DummyDoc()
        state.set_document(dummy_doc, Path("/nonexistent/test.bin"))

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.DOCUMENT_OPENED

    def test_set_document_opened_contains_file_path(self) -> None:
        """DOCUMENT_OPENED event data contains the string file path."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        p = Path("/nonexistent/sample.bin")
        state.set_document(_DummyDoc(), p)

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
        state.set_document(_DummyDoc(), None)
        assert state.cursor_offset == 0

    def test_set_document_resets_selection(self) -> None:
        """set_document clears any existing selection."""
        state = HexDocumentState()
        state.set_selection(10, 20)
        state.set_document(_DummyDoc(), None)
        assert state.selection is None

    def test_set_document_reflects_on_property(self) -> None:
        """Document property returns the object passed to set_document."""
        state = HexDocumentState()
        dummy = _DummyDoc()
        state.set_document(dummy, None)
        assert state.document is dummy

    def test_set_document_file_path_property(self) -> None:
        """file_path property reflects the Path passed to set_document."""
        state = HexDocumentState()
        p = Path("/nonexistent/abc.bin")
        state.set_document(_DummyDoc(), p)
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
    """Tests for the per-thread reentrancy queue and depth cap."""

    def test_reentrant_notify_terminates_at_depth_cap(self) -> None:
        """A callback that triggers another notify is queued and capped.

        Re-entrant emissions are queued and drained after the outer
        dispatch finishes (so downstream events still reach observers),
        but a runaway chain is bounded by ``NOTIFY_MAX_DEPTH`` so
        infinite loops cannot happen.
        """
        state = HexDocumentState()
        call_count = 0

        def reentrant_cb(_event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            state.set_cursor(call_count + 1)

        state.register_callback(reentrant_cb)
        state.set_cursor(1)

        assert call_count == NOTIFY_MAX_DEPTH

    def test_dispatch_state_released_after_normal_dispatch(self) -> None:
        """Per-thread dispatch state is released so subsequent calls work."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.set_cursor(1)
        state.set_cursor(2)

        assert len(events) == 2
        assert events[0][1]["offset"] == 1
        assert events[1][1]["offset"] == 2


class TestCallbackErrorPaths:
    """Tests for error handling in callback dispatch."""

    def test_raising_callback_does_not_propagate_exception(self) -> None:
        """A callback that raises ValueError is caught; the caller is unaffected.

        The production _dispatch_one catches RuntimeError, TypeError,
        ValueError, and OSError. This test confirms ValueError from a
        callback never escapes set_cursor to the caller.
        """
        state = HexDocumentState()
        good_events: list[HexDocumentEvent] = []
        deliberate_failure = "deliberate failure"

        def bad_cb(_event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            raise ValueError(deliberate_failure)

        def good_cb(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            good_events.append(event_type)

        state.register_callback(bad_cb)
        state.register_callback(good_cb)
        state.set_cursor(42)

        assert good_events == [HexDocumentEvent.CURSOR_MOVED]

    def test_raising_callback_does_not_block_subsequent_callbacks(self) -> None:
        """All callbacks after a raising one still receive the event.

        Verifies that the try/except in _dispatch_one is per-callback, not
        per-dispatch, so a single bad callback cannot silence the rest.
        """
        state = HexDocumentState()
        received: list[str] = []
        first_fail_msg = "first callback fails"

        def cb_a(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise RuntimeError(first_fail_msg)

        def cb_b(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            received.append("b")

        def cb_c(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            received.append("c")

        state.register_callback(cb_a)
        state.register_callback(cb_b)
        state.register_callback(cb_c)
        state.set_cursor(1)

        assert received == ["b", "c"]

    def test_raising_callback_cursor_offset_still_updated(self) -> None:
        """State mutation completes even if a callback raises.

        set_cursor updates _cursor_offset before dispatching. If dispatch
        triggers a caught callback exception, the offset must already be
        committed and visible through the property.
        """
        state = HexDocumentState()
        io_failure_msg = "io failure"

        def bad_cb(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise OSError(io_failure_msg)

        state.register_callback(bad_cb)
        state.set_cursor(999)

        assert state.cursor_offset == 999

    def test_raising_callback_that_also_mutates_state_still_drains_queue(self) -> None:
        """A callback that raises AND queues a reentrant mutation is fully processed.

        The callback calls set_selection (which is queued by the reentrancy
        guard because dispatch is already active), then raises OSError. The
        test verifies three independent properties:

        1. The raising callback's exception does not escape to the caller.
        2. The reentrant SELECTION_CHANGED event is still drained and delivered
           to the observer after the outer CURSOR_MOVED dispatch finishes.
        3. state.selection reflects the queued set_selection call, confirming
           that the state mutation (which happens before _notify inside
           set_selection) is committed even though the callback raised.
        """
        state = HexDocumentState()
        received_events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def mutate_and_raise(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(100, 200)
                deliberate_mid_dispatch_raise = "deliberate mid-dispatch raise"
                raise TypeError(deliberate_mid_dispatch_raise)

        def observer(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            received_events.append((event_type, dict(data)))

        state.register_callback(mutate_and_raise)
        state.register_callback(observer)

        state.set_cursor(77)

        assert received_events[0][0] == HexDocumentEvent.CURSOR_MOVED
        assert received_events[0][1]["offset"] == 77
        assert received_events[1][0] == HexDocumentEvent.SELECTION_CHANGED
        assert received_events[1][1]["start"] == 100
        assert received_events[1][1]["end"] == 200
        assert state.cursor_offset == 77
        assert state.selection == (100, 200)

    def test_mid_dispatch_state_mutation_is_queued_and_delivered_in_causal_order(self) -> None:
        """A callback that mutates state during dispatch queues the event causally.

        When a CURSOR_MOVED callback calls set_selection, the reentrancy guard
        queues the SELECTION_CHANGED emission. After the outer CURSOR_MOVED
        dispatch completes, the guard drains the queue, delivering
        SELECTION_CHANGED to all observers.

        Assertions that would catch a real regression:
        - Exactly two events reach the observer: CURSOR_MOVED then
          SELECTION_CHANGED (causal order, not reversed).
        - CURSOR_MOVED payload carries the exact offset passed to set_cursor.
        - SELECTION_CHANGED payload carries the exact start/end passed inside
          the callback to set_selection.
        - state.selection is set to the value passed mid-dispatch; it does NOT
          remain None (the mutation commits before _notify is called).
        - state.cursor_offset equals the value from the outer set_cursor call.
        """
        state = HexDocumentState()
        received_events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def mutating_cb(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(50, 150)

        def observer(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            received_events.append((event_type, dict(data)))

        state.register_callback(mutating_cb)
        state.register_callback(observer)

        state.set_cursor(256)

        assert len(received_events) == 2
        first_event, first_data = received_events[0]
        second_event, second_data = received_events[1]
        assert first_event == HexDocumentEvent.CURSOR_MOVED
        assert first_data["offset"] == 256
        assert second_event == HexDocumentEvent.SELECTION_CHANGED
        assert second_data["start"] == 50
        assert second_data["end"] == 150
        assert state.cursor_offset == 256
        assert state.selection == (50, 150)

    def test_mid_dispatch_mutation_does_not_re_enter_mutating_callback_again(self) -> None:
        """A mid-dispatch mutation does not cause the mutating callback to fire again.

        When mutating_cb calls set_selection, the SELECTION_CHANGED event is
        queued (reentrancy guard is active). When the queue is drained,
        mutating_cb receives SELECTION_CHANGED. Because event_type is
        SELECTION_CHANGED (not CURSOR_MOVED), it does not call set_selection
        again. The test asserts the total call count of mutating_cb is exactly
        two: one for CURSOR_MOVED, one for SELECTION_CHANGED. This falsifies
        any regression where the guard fails to queue the reentrant event and
        instead dispatches it immediately (which would allow unbounded
        recursion through mutating_cb).
        """
        state = HexDocumentState()
        call_log: list[HexDocumentEvent] = []

        def mutating_cb(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            call_log.append(event_type)
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(10, 20)

        state.register_callback(mutating_cb)

        state.set_cursor(1)

        assert call_log == [HexDocumentEvent.CURSOR_MOVED, HexDocumentEvent.SELECTION_CHANGED]
        assert state.cursor_offset == 1
        assert state.selection == (10, 20)

    def test_concurrent_set_document_does_not_deadlock(self) -> None:
        """Concurrent set_document calls from multiple threads complete without deadlock.

        Spawns threads each calling set_document alternately with a real
        document and None. All threads must finish within the join timeout,
        and no RuntimeError may propagate.
        """
        state = HexDocumentState()
        errors: list[Exception] = []
        lock = threading.Lock()

        def do_set(i: int) -> None:
            try:
                if i % 2 == 0:
                    state.set_document(_DummyDoc(), None)
                else:
                    state.set_document(None, None)
            except RuntimeError as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=do_set, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        still_alive = [t for t in threads if t.is_alive()]
        assert not still_alive, f"{len(still_alive)} thread(s) did not finish — possible deadlock"
        assert not errors

    def test_uncaught_exception_type_propagates_from_dispatch(self) -> None:
        """An exception type outside the guarded set escapes set_cursor to the caller.

        _dispatch_one guards only RuntimeError, TypeError, ValueError, and
        OSError. A ZeroDivisionError is not in that set and must propagate
        through _notify / set_cursor to the caller. This test falsifies any
        regression that widens the guard to catch all exceptions.
        """
        state = HexDocumentState()

        def divzero_cb(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            _ = 1 // 0

        state.register_callback(divzero_cb)
        with pytest.raises(ZeroDivisionError):
            state.set_cursor(5)

    def test_all_four_guarded_exception_types_are_caught(self) -> None:
        """Each of the four guarded exception types is individually swallowed.

        Exercises RuntimeError, TypeError, ValueError, and OSError in four
        separate states. For each, an observer registered after the raising
        callback must receive exactly one CURSOR_MOVED with the correct
        offset. This falsifies any regression that removes one type from the
        guard tuple.
        """
        guarded_msg = "guarded"

        def make_raiser(cls: type[Exception]) -> StateCallbackFn:
            def raiser(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
                raise cls(guarded_msg)

            return raiser

        exc_types: list[type[Exception]] = [RuntimeError, TypeError, ValueError, OSError]
        for exc_cls in exc_types:
            state = HexDocumentState()
            received: list[dict[str, Any]] = []

            def make_observer(buf: list[dict[str, Any]]) -> StateCallbackFn:
                def observer(_et: HexDocumentEvent, d: dict[str, Any]) -> None:
                    buf.append(dict(d))

                return observer

            state.register_callback(make_raiser(exc_cls))
            state.register_callback(make_observer(received))
            state.set_cursor(321)

            assert len(received) == 1, f"{exc_cls.__name__} caused observer to be skipped"
            assert received[0]["offset"] == 321, f"{exc_cls.__name__} payload wrong"

    def test_multiple_raising_callbacks_all_precede_a_good_callback(self) -> None:
        """Three consecutive raising callbacks do not suppress a fourth good one.

        Registers cb_a (RuntimeError), cb_b (ValueError), cb_c (OSError), then
        cb_d (records event). All three raising callbacks fire before cb_d.
        cb_d must still receive exactly one CURSOR_MOVED with offset=88.
        This falsifies any implementation that aborts the callback list on
        first exception rather than continuing per-callback.
        """
        state = HexDocumentState()
        received: list[dict[str, Any]] = []
        msg_a = "a fails"
        msg_b = "b fails"
        msg_c = "c fails"

        def cb_a(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise RuntimeError(msg_a)

        def cb_b(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise ValueError(msg_b)

        def cb_c(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise OSError(msg_c)

        def cb_d(_et: HexDocumentEvent, d: dict[str, Any]) -> None:
            received.append(dict(d))

        state.register_callback(cb_a)
        state.register_callback(cb_b)
        state.register_callback(cb_c)
        state.register_callback(cb_d)
        state.set_cursor(88)

        assert len(received) == 1
        assert received[0]["offset"] == 88

    def test_raising_during_queue_drain_does_not_abort_remaining_drain(self) -> None:
        """A callback that raises during queue-drain does not abort subsequent queue items.

        Setup: mutator_cb responds to CURSOR_MOVED by queueing two state
        mutations (set_selection then notify_template_registered), then raises
        TypeError. Both queued events must still be delivered to the observer
        even though the mutator raised during the first drained event.

        Specifically:
        - observer receives CURSOR_MOVED (outer dispatch).
        - mutator_cb runs for CURSOR_MOVED, queues SELECTION_CHANGED and
          TEMPLATE_REGISTERED via two calls, then raises.
        - Queue drain runs: SELECTION_CHANGED dispatches (mutator_cb runs for
          it without raising because event_type != CURSOR_MOVED; observer
          records it), then TEMPLATE_REGISTERED dispatches (both callbacks
          run; observer records it).
        - Final observer log: [CURSOR_MOVED, SELECTION_CHANGED, TEMPLATE_REGISTERED].
        - state.selection == (7, 14) and state.cursor_offset == 128.
        """
        state = HexDocumentState()
        observer_log: list[HexDocumentEvent] = []

        drain_raise_msg = "deliberate drain-phase raise"

        def mutator_cb(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(7, 14)
                state.notify_template_registered("drain_test")
                raise TypeError(drain_raise_msg)

        def observer(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            observer_log.append(event_type)

        state.register_callback(mutator_cb)
        state.register_callback(observer)
        state.set_cursor(128)

        assert observer_log == [
            HexDocumentEvent.CURSOR_MOVED,
            HexDocumentEvent.SELECTION_CHANGED,
            HexDocumentEvent.TEMPLATE_REGISTERED,
        ]
        assert state.cursor_offset == 128
        assert state.selection == (7, 14)

    def test_raising_callback_event_data_is_exact_and_unmodified(self) -> None:
        """Event data dict passed to a non-raising callback after a raising one is exact.

        Verifies that catching an exception from an earlier callback does not
        corrupt or replace the data dict delivered to subsequent callbacks.
        The observer callback must receive the exact same offset=512 that was
        passed to set_cursor, not a default or zero value.
        """
        state = HexDocumentState()
        observed_data: list[dict[str, Any]] = []
        corrupt_msg = "corrupt nothing"

        def bad_cb(_et: HexDocumentEvent, _d: dict[str, Any]) -> None:
            raise ValueError(corrupt_msg)

        def good_cb(_et: HexDocumentEvent, d: dict[str, Any]) -> None:
            observed_data.append(dict(d))

        state.register_callback(bad_cb)
        state.register_callback(good_cb)
        state.set_cursor(512)

        assert len(observed_data) == 1
        assert observed_data[0] == {"offset": 512}

    def test_mid_dispatch_mutation_via_multiple_events_all_reach_observer(self) -> None:
        """A callback that queues three distinct mutations during dispatch delivers all.

        When a CURSOR_MOVED callback calls set_selection, notify_data_modified,
        and notify_display_mode_changed (in that order), the reentrancy guard
        queues all three. After the outer CURSOR_MOVED completes, the guard
        drains SELECTION_CHANGED, DATA_MODIFIED, then DISPLAY_MODE_CHANGED
        in causal order. The observer must receive exactly four events in order
        with correct payloads, falsifying any partial-drain or wrong-order
        regression.
        """
        state = HexDocumentState()
        log: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def trigger_three(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(3, 9)
                state.notify_data_modified(0, 4)
                state.notify_display_mode_changed("hex16_le")

        def observer(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            log.append((event_type, dict(data)))

        state.register_callback(trigger_three)
        state.register_callback(observer)
        state.set_cursor(64)

        assert len(log) == 4
        assert log[0] == (HexDocumentEvent.CURSOR_MOVED, {"offset": 64})
        assert log[1] == (HexDocumentEvent.SELECTION_CHANGED, {"start": 3, "end": 9})
        assert log[2][0] == HexDocumentEvent.DATA_MODIFIED
        assert log[2][1]["offset"] == 0
        assert log[2][1]["length"] == 4
        assert log[3] == (HexDocumentEvent.DISPLAY_MODE_CHANGED, {"mode": "hex16_le"})
        assert state.cursor_offset == 64
        assert state.selection == (3, 9)


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
            except RuntimeError as exc:
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
            except RuntimeError as exc:
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
                except RuntimeError as exc:
                    with lock:
                        errors.append(exc)

        def unregister() -> None:
            try:
                state.unregister_callback(cb)
            except RuntimeError as exc:
                with lock:
                    errors.append(exc)

        t1 = threading.Thread(target=spam_events)
        t2 = threading.Thread(target=unregister)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors


class TestClearAll:
    """Tests for the clear_all batch-reset method."""

    def test_clear_all_fires_highlight_rule_removed_for_each_stored_rule(self) -> None:
        """clear_all emits HIGHLIGHT_RULE_REMOVED for every stored rule.

        Two rules ("r-alpha", "r-beta") are stored via set_highlight_rule before
        clear_all is called. The observer must receive exactly two
        HIGHLIGHT_RULE_REMOVED events, one per rule id, before any
        DOCUMENT_CLOSED. Falsifies any regression that skips the per-rule
        removal notification.
        """
        state = HexDocumentState()
        state.set_document(_DummyDoc(), None)
        state.set_highlight_rule("r-alpha", {"id": "r-alpha", "color": "#FF0000"})
        state.set_highlight_rule("r-beta", {"id": "r-beta", "color": "#00FF00"})

        events, cb = _make_collector()
        state.register_callback(cb)
        state.clear_all()

        rule_removed = [e for e in events if e[0] == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED]
        removed_ids = {e[1]["rule_id"] for e in rule_removed}

        assert removed_ids == {"r-alpha", "r-beta"}

    def test_clear_all_fires_document_closed_when_document_was_open(self) -> None:
        """clear_all emits DOCUMENT_CLOSED exactly once when a document is open.

        An open document followed by clear_all must produce exactly one
        DOCUMENT_CLOSED event. Falsifies a regression that omits the
        DOCUMENT_CLOSED notification from clear_all.
        """
        state = HexDocumentState()
        state.set_document(_DummyDoc(), None)

        events, cb = _make_collector()
        state.register_callback(cb)
        state.clear_all()

        closed = [e for e in events if e[0] == HexDocumentEvent.DOCUMENT_CLOSED]
        assert len(closed) == 1

    def test_clear_all_does_not_fire_document_closed_when_no_document(self) -> None:
        """clear_all emits no DOCUMENT_CLOSED when no document was attached.

        Calling clear_all on a fresh state (no document) must not emit any
        DOCUMENT_CLOSED event. Falsifies a regression that emits the event
        unconditionally.
        """
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_all()

        closed = [e for e in events if e[0] == HexDocumentEvent.DOCUMENT_CLOSED]
        assert not closed

    def test_clear_all_resets_all_state_properties(self) -> None:
        """clear_all resets document, file_path, cursor, and selection to defaults.

        After setting all state fields, clear_all must leave:
        - document == None
        - file_path == None
        - cursor_offset == 0
        - selection == None
        This falsifies any regression that forgets to reset one of the fields.
        """
        state = HexDocumentState()
        p = Path("/nonexistent/clear_test.bin")
        state.set_document(_DummyDoc(), p)
        state.set_cursor(500)
        state.set_selection(10, 20)

        state.clear_all()

        assert state.document is None
        assert state.file_path is None
        assert state.cursor_offset == 0
        assert state.selection is None

    def test_clear_all_clears_stored_highlight_rules(self) -> None:
        """clear_all empties the highlight rules dict.

        After adding two highlight rules and calling clear_all, get_highlight_rules
        must return an empty dict. Falsifies any regression that leaves stale
        entries in the rule map.
        """
        state = HexDocumentState()
        state.set_highlight_rule("rule-1", {"id": "rule-1", "color": "#AABBCC"})
        state.set_highlight_rule("rule-2", {"id": "rule-2", "color": "#112233"})

        state.clear_all()

        assert state.get_highlight_rules() == {}

    def test_clear_all_rule_removed_precedes_document_closed_in_event_order(self) -> None:
        """clear_all emits HIGHLIGHT_RULE_REMOVED events before DOCUMENT_CLOSED.

        The production clear_all loop fires HIGHLIGHT_RULE_REMOVED for each
        rule, then conditionally fires DOCUMENT_CLOSED. This test asserts that
        the last event is DOCUMENT_CLOSED and all preceding events are
        HIGHLIGHT_RULE_REMOVED. Falsifies any regression that changes the
        ordering contract.
        """
        state = HexDocumentState()
        state.set_document(_DummyDoc(), None)
        state.set_highlight_rule("x", {"id": "x", "color": "#000000"})

        events, cb = _make_collector()
        state.register_callback(cb)
        state.clear_all()

        assert len(events) == 2
        assert events[0][0] == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED
        assert events[0][1]["rule_id"] == "x"
        assert events[1][0] == HexDocumentEvent.DOCUMENT_CLOSED


class TestCurrentStateSnapshot:
    """Tests for the get_current_state atomic snapshot method."""

    def test_get_current_state_default_values(self) -> None:
        """get_current_state on a fresh instance returns correct defaults.

        The exact expected dict is known independently from the __init__
        docstring and property contracts. Falsifies any regression that changes
        a default field value or omits a key.
        """
        state = HexDocumentState()
        snapshot = state.get_current_state()

        assert snapshot["document"] is None
        assert snapshot["file_path"] is None
        assert snapshot["cursor_offset"] == 0
        assert snapshot["selection"] is None
        assert snapshot["highlight_rules"] == {}
        assert snapshot["display_mode"] == "hex8"

    def test_get_current_state_reflects_mutations(self) -> None:
        """get_current_state returns values updated by state mutations.

        After set_cursor(256), set_selection(10, 20), set_display_mode_state,
        and set_highlight_rule, the snapshot must reflect each exact value.
        Falsifies a regression where the snapshot returns stale pre-mutation
        values.
        """
        state = HexDocumentState()
        dummy = _DummyDoc()
        p = Path("/nonexistent/snap.bin")
        state.set_document(dummy, p)
        state.set_cursor(256)
        state.set_selection(10, 20)
        state.set_display_mode_state("hex16_le")
        state.set_highlight_rule("snap-rule", {"id": "snap-rule", "color": "#FACADE"})

        snapshot = state.get_current_state()

        assert snapshot["document"] is dummy
        assert snapshot["file_path"] == str(p)
        assert snapshot["cursor_offset"] == 256
        assert snapshot["selection"] == (10, 20)
        assert snapshot["display_mode"] == "hex16_le"
        assert "snap-rule" in snapshot["highlight_rules"]
        assert snapshot["highlight_rules"]["snap-rule"]["color"] == "#FACADE"

    def test_get_current_state_returns_copy_of_highlight_rules(self) -> None:
        """Mutating the snapshot dict does not affect the live state.

        get_current_state documents that highlight_rules is a copy. Modifying
        the returned dict must not change what a subsequent snapshot returns.
        Falsifies any regression that returns a direct reference to the
        internal dict.
        """
        state = HexDocumentState()
        state.set_highlight_rule("live-rule", {"id": "live-rule", "color": "#ABCDEF"})

        snapshot = state.get_current_state()
        snapshot["highlight_rules"]["injected"] = {"id": "injected", "color": "#000000"}

        second_snapshot = state.get_current_state()
        assert "injected" not in second_snapshot["highlight_rules"]
        assert "live-rule" in second_snapshot["highlight_rules"]


class TestAdditionalEventTypes:
    """Tests for the three event types not covered by test_all_12_event_types_delivered."""

    def test_notify_va_mapping_changed_fires_event(self) -> None:
        """notify_va_mapping_changed fires VA_MAPPING_CHANGED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_va_mapping_changed(3)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.VA_MAPPING_CHANGED

    def test_notify_va_mapping_changed_event_data(self) -> None:
        """VA_MAPPING_CHANGED event data contains the correct mapping_count."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_va_mapping_changed(7)

        assert events[0][1]["mapping_count"] == 7

    def test_notify_alignment_grid_changed_fires_event(self) -> None:
        """notify_alignment_grid_changed fires ALIGNMENT_GRID_CHANGED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_alignment_grid_changed(16)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.ALIGNMENT_GRID_CHANGED

    def test_notify_alignment_grid_changed_event_data(self) -> None:
        """ALIGNMENT_GRID_CHANGED event data contains the correct size."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_alignment_grid_changed(16)

        assert events[0][1]["size"] == 16

    def test_notify_alignment_grid_changed_zero_disables_grid(self) -> None:
        """ALIGNMENT_GRID_CHANGED with size=0 is delivered and records size=0."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_alignment_grid_changed(0)

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.ALIGNMENT_GRID_CHANGED
        assert events[0][1]["size"] == 0

    def test_notify_color_mode_changed_fires_event(self) -> None:
        """notify_color_mode_changed fires COLOR_MODE_CHANGED."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_color_mode_changed("entropy")

        assert len(events) == 1
        assert events[0][0] == HexDocumentEvent.COLOR_MODE_CHANGED

    def test_notify_color_mode_changed_event_data(self) -> None:
        """COLOR_MODE_CHANGED event data contains the correct mode string."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_color_mode_changed("entropy")

        assert events[0][1]["mode"] == "entropy"

    def test_notify_color_mode_changed_none_mode(self) -> None:
        """COLOR_MODE_CHANGED is delivered with mode='none' (color mapping disabled)."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.notify_color_mode_changed("none")

        assert len(events) == 1
        assert events[0][1]["mode"] == "none"


def _trigger_document_opened(s: HexDocumentState) -> None:
    """Fire DOCUMENT_OPENED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.set_document(_DummyDoc(), None)


def _trigger_document_closed(s: HexDocumentState) -> None:
    """Fire DOCUMENT_CLOSED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.set_document(None, None)


def _trigger_cursor_moved(s: HexDocumentState) -> None:
    """Fire CURSOR_MOVED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.set_cursor(1)


def _trigger_selection_changed(s: HexDocumentState) -> None:
    """Fire SELECTION_CHANGED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.set_selection(0, 10)


def _trigger_data_modified(s: HexDocumentState) -> None:
    """Fire DATA_MODIFIED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_data_modified(0, 8)


def _trigger_document_saved(s: HexDocumentState) -> None:
    """Fire DOCUMENT_SAVED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_document_saved("/nonexistent/x.bin")


def _trigger_template_registered(s: HexDocumentState) -> None:
    """Fire TEMPLATE_REGISTERED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_template_registered("t")


def _trigger_template_removed(s: HexDocumentState) -> None:
    """Fire TEMPLATE_REMOVED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_template_removed("t")


def _trigger_highlight_rule_added(s: HexDocumentState) -> None:
    """Fire HIGHLIGHT_RULE_ADDED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_highlight_rule_added({"id": "r1"})


def _trigger_highlight_rule_removed(s: HexDocumentState) -> None:
    """Fire HIGHLIGHT_RULE_REMOVED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_highlight_rule_removed("r1")


def _trigger_display_mode_changed(s: HexDocumentState) -> None:
    """Fire DISPLAY_MODE_CHANGED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
    s.notify_display_mode_changed("hex8")


def _trigger_pattern_executed(s: HexDocumentState) -> None:
    """Fire PATTERN_EXECUTED on the given state.

    Args:
        s: HexDocumentState to trigger the event on.
    """
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
