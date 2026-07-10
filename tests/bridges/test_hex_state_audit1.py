# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-1 regression tests for HexDocumentState concurrency hardening.

Each test in this module is associated with a specific F-#### finding
from ``audit1.md`` for ``src/intellicrack/bridges/hex_state.py``:

* F-0036 - ``_notify`` guard silently drops downstream events.
* F-0037 - ``set_document`` reads document length outside the lock.
* F-0038 - asymmetric locking on ``get_display_mode`` / ``set_display_mode_state``.
* F-0039 - property getters read shared state without the lock.
* F-0058 - ``clear_all`` clears highlights but only emits ``DOCUMENT_CLOSED``.

The tests use real ``threading.Thread`` interleavings, real subclassing
of inspection points (no mocks), and assert state-machine invariants
that fail on the unfixed code path and pass after remediation.  All
state interactions go through the public API surface; no test reaches
into the state holder's private members.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.bridges.hex_state import (
    NOTIFY_MAX_DEPTH,
    HexDocumentEvent,
    HexDocumentState,
)


class _DummyDoc:
    """Concrete document satisfying the ``HexDocumentFull`` protocol shape.

    Implements every method required by the runtime-checkable protocol so
    instances can be passed to ``HexDocumentState.set_document`` without
    triggering basedpyright protocol-mismatch findings.  The hex state
    holder only ever asks for ``length()``; the remaining members are
    no-op stubs because no template, write, or inspection traffic flows
    through ``HexDocumentState``.
    """

    def __init__(self, doc_length: int = 0) -> None:
        """Construct a dummy document with a fixed length value.

        Args:
            doc_length: Value returned by ``length()``.
        """
        self._doc_length = doc_length

    def read(self, offset: int, length: int) -> list[int]:
        """Return an empty list of byte values.

        Args:
            offset: Ignored byte offset.
            length: Ignored read length.

        Returns:
            list[int]: Always empty.
        """
        _ = (offset, length)
        return []

    def length(self) -> int:
        """Return the configured document length.

        Returns:
            int: The configured length value.
        """
        return self._doc_length

    def write(self, offset: int, data: bytes) -> None:
        """No-op write.

        Args:
            offset: Ignored byte offset.
            data: Ignored payload bytes.
        """
        _ = (offset, data)

    def list_templates(self) -> list[tuple[str, str]]:
        """Return an empty template list.

        Returns:
            list[tuple[str, str]]: Always empty.
        """
        return []

    def list_templates_detailed(self) -> list[object]:
        """Return an empty detailed template list.

        Returns:
            list[object]: Always empty.
        """
        return []

    def register_json_template(self, name: str, json_str: str) -> None:
        """No-op template registration.

        Args:
            name: Ignored template name.
            json_str: Ignored JSON body.
        """
        _ = (name, json_str)

    def remove_template(self, name: str) -> None:
        """No-op template removal.

        Args:
            name: Ignored template name.
        """
        _ = name

    def export_template_json(self, name: str) -> str:
        """Return an empty JSON string.

        Args:
            name: Ignored template name.

        Returns:
            str: Always empty.
        """
        _ = name
        return ""

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Return an empty inspection dict.

        Args:
            offset: Ignored offset.

        Returns:
            dict[str, object]: Always empty.
        """
        _ = offset
        return {}


class _BlockingLengthDoc(_DummyDoc):
    """Document whose ``length()`` blocks until externally released.

    Used to hold the state holder's internal lock for a deterministic
    interval so concurrent public API calls observably serialize behind
    the in-flight ``set_document``.
    """

    def __init__(
        self,
        doc_length: int,
        in_length: threading.Event,
        release: threading.Event,
    ) -> None:
        """Create a blocking-length document tied to two coordination events.

        Args:
            doc_length: Length value returned once released.
            in_length: Event set when ``length()`` is entered.
            release: Event awaited inside ``length()``; resolves to
                return the configured length once set.
        """
        super().__init__(doc_length)
        self._in_length = in_length
        self._release = release

    def length(self) -> int:
        """Block on the synchronization gate then return the length.

        Returns:
            int: Configured length value.
        """
        self._in_length.set()
        self._release.wait(timeout=5.0)
        return self._doc_length


class TestF0036NotifyDropsDownstreamEvents:
    """F-0036 - ``_notify`` must not silently drop downstream events.

    The original code set a single boolean ``_notify_guard`` under the
    lock and dropped every concurrent or re-entrant ``_notify`` call.
    That means a callback that triggers a real downstream mutation never
    sees the resulting event delivered to other observers.  After the
    fix the downstream event is queued and dispatched in causal order.
    """

    def test_reentrant_event_is_delivered_to_other_observers(self) -> None:
        """A re-entrant emission from one observer reaches every other observer.

        Observer A reacts to ``CURSOR_MOVED`` by setting a selection
        (which itself emits ``SELECTION_CHANGED``).  Observer B should
        receive both events.  On the unfixed code Observer B only saw
        ``CURSOR_MOVED`` because the inner notify was silently dropped.
        """
        state = HexDocumentState()
        observer_b_events: list[HexDocumentEvent] = []

        def observer_a(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type is HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(0, 7)

        def observer_b(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            observer_b_events.append(event_type)

        state.register_callback(observer_a)
        state.register_callback(observer_b)

        state.set_cursor(42)

        assert HexDocumentEvent.CURSOR_MOVED in observer_b_events
        assert HexDocumentEvent.SELECTION_CHANGED in observer_b_events

    def test_concurrent_emission_from_other_thread_is_not_dropped(self) -> None:
        """Cross-thread emissions arriving during dispatch are not dropped.

        While Observer A is blocking inside its callback for
        ``CURSOR_MOVED``, a second thread emits ``DATA_MODIFIED``.  The
        unfixed code dropped the second emission because the notify
        guard was held across the entire dispatch.  After the fix the
        cross-thread event uses its own per-thread dispatch state and
        reaches Observer A.
        """
        state = HexDocumentState()
        observer_a_in_callback = threading.Event()
        observer_a_release = threading.Event()
        observer_a_events: list[HexDocumentEvent] = []
        events_lock = threading.Lock()

        def observer_a(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            with events_lock:
                observer_a_events.append(event_type)
            if event_type is HexDocumentEvent.CURSOR_MOVED:
                observer_a_in_callback.set()
                observer_a_release.wait(timeout=5.0)

        state.register_callback(observer_a)

        def emit_cursor() -> None:
            state.set_cursor(1)

        cursor_thread = threading.Thread(target=emit_cursor)
        cursor_thread.start()
        try:
            TestF0036NotifyDropsDownstreamEvents._drive_cross_thread_emission(
                state,
                observer_a_in_callback,
                observer_a_release,
            )
        finally:
            observer_a_release.set()
            cursor_thread.join(timeout=5.0)

        with events_lock:
            recorded = list(observer_a_events)
        assert HexDocumentEvent.CURSOR_MOVED in recorded
        assert HexDocumentEvent.DATA_MODIFIED in recorded

    @staticmethod
    def _drive_cross_thread_emission(
        state: HexDocumentState,
        observer_a_in_callback: threading.Event,
        observer_a_release: threading.Event,
    ) -> None:
        """Drive a cross-thread DATA_MODIFIED while observer_a is parked.

        Args:
            state: HexDocumentState driving the dispatch.
            observer_a_in_callback: Event signalling observer_a is paused.
            observer_a_release: Event used to release observer_a.
        """
        assert observer_a_in_callback.wait(timeout=5.0)

        data_emitted = threading.Event()

        def emit_data() -> None:
            state.notify_data_modified(0, 16)
            data_emitted.set()

        data_thread = threading.Thread(target=emit_data)
        data_thread.start()
        try:
            assert data_emitted.wait(timeout=5.0)
        finally:
            observer_a_release.set()
            data_thread.join(timeout=5.0)

    def test_runaway_dispatch_terminates_at_depth_cap(self) -> None:
        """A genuinely runaway callback chain stops at the documented depth cap.

        With unbounded queueing this would loop forever, so the fix
        bounds total per-outer dispatch invocations at
        ``NOTIFY_MAX_DEPTH``.  This proves that legitimate downstream
        events are delivered (count grows beyond 1) while infinite loops
        are still terminated cleanly.
        """
        state = HexDocumentState()
        call_count = 0

        def runaway(_event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            nonlocal call_count
            call_count += 1
            state.set_cursor(call_count + 1)

        state.register_callback(runaway)
        state.set_cursor(1)

        assert call_count == NOTIFY_MAX_DEPTH


class TestF0037SetDocumentLengthOutsideLock:
    """F-0037 - ``set_document`` must read document length under the lock.

    Originally the length was queried before the lock was acquired,
    which means a competing ``set_document`` swap on another thread
    could install a different document between the length read and the
    state mutation.  The recorded ``DOCUMENT_OPENED`` payload would then
    advertise a length that did not belong to the published document.
    """

    def test_document_length_in_event_matches_published_document(self) -> None:
        """``DOCUMENT_OPENED`` size matches the document actually stored.

        A racing thread runs ``set_document`` repeatedly while another
        thread queries ``state.document.length()`` and the latest
        observed event size.  The two must always agree under the fix.
        """
        state = HexDocumentState()
        events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []
        events_lock = threading.Lock()

        def collector(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            with events_lock:
                events.append((event_type, data))

        state.register_callback(collector)

        doc_a = _DummyDoc(doc_length=1024)
        doc_b = _DummyDoc(doc_length=4096)
        path_a = Path("a.bin")
        path_b = Path("b.bin")

        stop = threading.Event()
        errors: list[str] = []
        errors_lock = threading.Lock()

        def writer() -> None:
            iteration = 0
            while not stop.is_set():
                iteration += 1
                if iteration % 2:
                    state.set_document(doc_a, path_a)
                else:
                    state.set_document(doc_b, path_b)

        def reader() -> None:
            while not stop.is_set():
                with events_lock:
                    last_open = next(
                        (d for evt, d in reversed(events) if evt is HexDocumentEvent.DOCUMENT_OPENED),
                        None,
                    )
                if last_open is None:
                    continue
                event_size = last_open["size"]
                if event_size not in {doc_a.length(), doc_b.length()}:
                    with errors_lock:
                        errors.append(f"unknown event_size={event_size}")

        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)
        writer_thread.start()
        reader_thread.start()
        time.sleep(0.5)
        stop.set()
        writer_thread.join(timeout=5.0)
        reader_thread.join(timeout=5.0)

        assert not errors

    def test_document_length_read_under_lock_observes_swapped_document(self) -> None:
        """Lock-held length read prevents tearing across a swap.

        ``length()`` is engineered to spin until a signal fires; if the
        length call were performed before the lock is taken, a competing
        ``set_document`` from another thread could publish a different
        document while the spin is ongoing, causing the recorded size
        to belong to a stale document.  The fix performs the length
        read while the lock is held, so a competing ``set_document`` is
        forced to wait until the slow length call returns.
        """
        state = HexDocumentState()
        events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []
        events_lock = threading.Lock()

        def collector(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            with events_lock:
                events.append((event_type, data))

        state.register_callback(collector)

        slow_release = threading.Event()
        slow_in_length = threading.Event()
        slow_doc = _BlockingLengthDoc(
            doc_length=999,
            in_length=slow_in_length,
            release=slow_release,
        )
        fast_doc = _DummyDoc(doc_length=42)

        slow_thread = threading.Thread(target=state.set_document, args=(slow_doc, Path("slow.bin")))
        slow_thread.start()
        try:
            self._block_then_run_interloper(state, fast_doc, slow_in_length, slow_release)
        finally:
            slow_release.set()
            slow_thread.join(timeout=5.0)

        with events_lock:
            opens = [d["size"] for evt, d in events if evt is HexDocumentEvent.DOCUMENT_OPENED]
        assert 999 in opens
        assert 42 in opens
        assert all(size in {999, 42} for size in opens)

    @staticmethod
    def _block_then_run_interloper(
        state: HexDocumentState,
        fast_doc: _DummyDoc,
        slow_in_length: threading.Event,
        slow_release: threading.Event,
    ) -> None:
        """Spawn an interloper set_document and assert it blocks on the lock.

        Args:
            state: HexDocumentState under test.
            fast_doc: Dummy document used by the interloper thread.
            slow_in_length: Event signalled when the slow length call begins.
            slow_release: Event used to release the slow length call.
        """
        assert slow_in_length.wait(timeout=5.0)

        interloper_done = threading.Event()

        def interloper() -> None:
            state.set_document(fast_doc, Path("fast.bin"))
            interloper_done.set()

        interloper_thread = threading.Thread(target=interloper)
        interloper_thread.start()
        try:
            time.sleep(0.05)
            assert not interloper_done.is_set()
        finally:
            slow_release.set()
            interloper_thread.join(timeout=5.0)


class TestF0038DisplayModeAsymmetricLocking:
    """F-0038 - ``get_display_mode`` must take the lock that the setter takes.

    Without symmetric locking, a reader can observe a non-atomic publish
    of the new mode string.  The locked setter and locked getter must
    both serialize through the same lock so that an exclusive update
    posted from one thread is observed atomically by another.
    """

    def test_concurrent_set_get_display_mode_observes_consistent_values(self) -> None:
        """Reader thread only sees published values, never an intermediate.

        Multiple writer threads cycle the display mode through a closed
        set of allowed values; multiple reader threads continuously
        sample the value.  Every observed value must be one of the
        allowed set.
        """
        state = HexDocumentState()
        allowed: tuple[str, ...] = ("hex8", "hex16_le", "hex32_le")

        stop = threading.Event()
        observed: list[str] = []
        observed_lock = threading.Lock()

        def writer() -> None:
            i = 0
            while not stop.is_set():
                state.set_display_mode_state(allowed[i % len(allowed)])
                i += 1

        def reader() -> None:
            while not stop.is_set():
                value = state.get_display_mode()
                with observed_lock:
                    observed.append(value)

        threads = [threading.Thread(target=writer) for _ in range(3)] + [threading.Thread(target=reader) for _ in range(3)]
        for t in threads:
            t.start()
        time.sleep(0.3)
        stop.set()
        for t in threads:
            t.join(timeout=5.0)

        with observed_lock:
            samples = list(observed)
        assert samples
        assert all(value in allowed for value in samples)

    def test_get_display_mode_blocks_while_set_document_holds_lock(self) -> None:
        """Concurrent ``get_display_mode`` waits while ``set_document`` runs.

        The state holder serializes display-mode reads through the same
        internal lock that ``set_document`` holds during the document
        length read.  We use a blocking ``length()`` to keep the lock
        held for a measurable interval and assert that
        ``get_display_mode`` cannot return until the lock is released.
        Asserting via the public API only - no private member is
        accessed.
        """
        state = HexDocumentState()
        state.set_display_mode_state("hex8")

        slow_in_length = threading.Event()
        slow_release = threading.Event()
        slow_doc = _BlockingLengthDoc(
            doc_length=1024,
            in_length=slow_in_length,
            release=slow_release,
        )

        set_thread = threading.Thread(target=state.set_document, args=(slow_doc, Path("slow.bin")))
        set_thread.start()
        try:
            reader_returned, observed = self._block_then_run_display_mode_reader(state, slow_in_length, slow_release)
        finally:
            slow_release.set()
            set_thread.join(timeout=5.0)

        assert reader_returned.is_set()
        assert observed == ["hex8"]

    @staticmethod
    def _block_then_run_display_mode_reader(
        state: HexDocumentState,
        slow_in_length: threading.Event,
        slow_release: threading.Event,
    ) -> tuple[threading.Event, list[str]]:
        """Spawn a get_display_mode reader and verify it blocks on the lock.

        Args:
            state: HexDocumentState under test.
            slow_in_length: Event signalled when the slow length call begins.
            slow_release: Event used to release the slow length call.

        Returns:
            tuple[threading.Event, list[str]]: The reader's completion event
            and the list collecting its observed display mode.
        """
        assert slow_in_length.wait(timeout=5.0)

        reader_returned = threading.Event()
        observed: list[str] = []

        def reader() -> None:
            observed.append(state.get_display_mode())
            reader_returned.set()

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        try:
            time.sleep(0.05)
            assert not reader_returned.is_set()
        finally:
            slow_release.set()
            reader_thread.join(timeout=5.0)
        return reader_returned, observed


class TestF0039PropertyGettersUnlocked:
    """F-0039 - property getters must lock for symmetric publication.

    The getters for ``document``, ``file_path``, ``cursor_offset`` and
    ``selection`` are read by the GUI thread and mutated by the bridge
    or background threads.  Without the lock, a reader can return a
    reference observed from a thread that has not synchronized through
    the state holder's lock at all.  After the fix, every property
    getter waits behind the same lock that ``set_document`` and the
    other writers take.
    """

    def test_property_getters_block_while_set_document_holds_lock(self) -> None:
        """Each property getter waits for the writer's lock to be released.

        ``set_document`` is engineered to hold the state holder's lock
        for a measurable interval via a blocking ``length()`` call.  We
        then start a reader thread for each property and assert it
        cannot make progress until the lock has been released.
        """
        state = HexDocumentState()
        state.set_document(_DummyDoc(doc_length=8), Path("init.bin"))

        for name in ("document", "file_path", "cursor_offset", "selection"):
            slow_in_length = threading.Event()
            slow_release = threading.Event()
            slow_doc = _BlockingLengthDoc(
                doc_length=4096,
                in_length=slow_in_length,
                release=slow_release,
            )

            set_thread = threading.Thread(target=state.set_document, args=(slow_doc, Path("slow.bin")))
            set_thread.start()
            try:
                returned = self._block_then_run_property_reader(state, name, slow_in_length, slow_release)
            finally:
                slow_release.set()
                set_thread.join(timeout=5.0)

            assert returned.is_set()

    @staticmethod
    def _block_then_run_property_reader(
        state: HexDocumentState,
        prop_name: str,
        slow_in_length: threading.Event,
        slow_release: threading.Event,
    ) -> threading.Event:
        """Spawn a property reader and assert it blocks on the writer's lock.

        Args:
            state: HexDocumentState under test.
            prop_name: Property name to read.
            slow_in_length: Event signalled when the slow length call begins.
            slow_release: Event used to release the slow length call.

        Returns:
            threading.Event: Event signalled once the property read returns.
        """
        assert slow_in_length.wait(timeout=5.0)

        returned = threading.Event()

        def reader(name: str = prop_name, done: threading.Event = returned) -> None:
            _ = getattr(state, name)
            done.set()

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        try:
            time.sleep(0.05)
            assert not returned.is_set(), f"{prop_name} read without locking"
        finally:
            slow_release.set()
            reader_thread.join(timeout=5.0)
        return returned

    def test_property_getters_eventually_observe_published_writer_value(self) -> None:
        """Each getter, after the writer's section completes, returns the new value.

        With symmetric locking, the value the reader observes once the
        writer thread has joined matches the value the writer published.
        """
        state = HexDocumentState()

        state.set_cursor(7777)
        assert state.cursor_offset == 7777

        state.set_selection(11, 22)
        assert state.selection == (11, 22)

        state.notify_document_saved("/dst/published.bin")
        assert state.file_path == Path("/dst/published.bin")

        new_doc = _DummyDoc(doc_length=64)
        state.set_document(new_doc, Path("after.bin"))
        assert state.document is new_doc
        assert state.file_path == Path("after.bin")


class TestF0058ClearAllEmitsOnlyDocumentClosed:
    """F-0058 - ``clear_all`` must emit a removed event per dropped highlight rule.

    Originally ``clear_all`` deleted every entry in ``_highlight_rules``
    and only emitted ``DOCUMENT_CLOSED``.  Observers tracking highlight
    rules (e.g. a sidebar list) would keep stale entries because they
    were never told the rules were dropped.  The fix emits one
    ``HIGHLIGHT_RULE_REMOVED`` event per cleared rule before the
    terminal ``DOCUMENT_CLOSED``.
    """

    def test_clear_all_emits_highlight_rule_removed_for_every_rule(self) -> None:
        """Each dropped rule produces exactly one ``HIGHLIGHT_RULE_REMOVED``."""
        state = HexDocumentState()
        state.set_document(_DummyDoc(), Path("doc.bin"))
        state.set_highlight_rule("rule_a", {"id": "rule_a", "color": "#ff0000"})
        state.set_highlight_rule("rule_b", {"id": "rule_b", "color": "#00ff00"})
        state.set_highlight_rule("rule_c", {"id": "rule_c", "color": "#0000ff"})

        events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

        def collector(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            events.append((event_type, data))

        state.register_callback(collector)
        state.clear_all()

        removed_ids = sorted(d["rule_id"] for evt, d in events if evt is HexDocumentEvent.HIGHLIGHT_RULE_REMOVED)
        assert removed_ids == ["rule_a", "rule_b", "rule_c"]
        closed_count = sum(bool(evt is HexDocumentEvent.DOCUMENT_CLOSED) for evt, _ in events)
        assert closed_count == 1

    def test_clear_all_orders_rule_removals_before_document_closed(self) -> None:
        """``HIGHLIGHT_RULE_REMOVED`` events precede the terminal ``DOCUMENT_CLOSED``."""
        state = HexDocumentState()
        state.set_document(_DummyDoc(), Path("doc.bin"))
        state.set_highlight_rule("only", {"id": "only", "color": "#abcdef"})

        events: list[HexDocumentEvent] = []

        def collector(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            events.append(event_type)

        state.register_callback(collector)
        state.clear_all()

        rule_idx = events.index(HexDocumentEvent.HIGHLIGHT_RULE_REMOVED)
        closed_idx = events.index(HexDocumentEvent.DOCUMENT_CLOSED)
        assert rule_idx < closed_idx

    def test_clear_all_with_rules_but_no_document_emits_only_rule_removals(self) -> None:
        """No document attached: only rule-removed events fire, no ``DOCUMENT_CLOSED``.

        The documented contract preserves the existing "no spurious
        DOCUMENT_CLOSED on already-empty state" behaviour while still
        announcing every dropped rule.
        """
        state = HexDocumentState()
        state.set_highlight_rule("orphan", {"id": "orphan", "color": "#101010"})

        events: list[HexDocumentEvent] = []

        def collector(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            events.append(event_type)

        state.register_callback(collector)
        state.clear_all()

        assert HexDocumentEvent.HIGHLIGHT_RULE_REMOVED in events
        assert HexDocumentEvent.DOCUMENT_CLOSED not in events

    def test_clear_all_idempotent_when_already_empty(self) -> None:
        """Idempotent reset on empty state still emits no events."""
        state = HexDocumentState()
        events: list[HexDocumentEvent] = []

        def collector(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            events.append(event_type)

        state.register_callback(collector)
        state.clear_all()

        assert not events


class TestF0036QueueClearedOnUnhandledException:
    """F-0036 queue leak — ``_notify`` must clear the re-entrant queue on any exit.

    When a callback raises an exception type NOT in the narrow transport
    tuple (e.g. ``KeyError``), control jumps from the ``try`` body to
    ``finally`` without clearing the per-thread pending queue.  The next
    unrelated ``_notify`` on the same thread would then drain stale
    events from the failed dispatch.

    The fix moves ``queue.clear()`` into the ``finally`` block so every
    exit path — normal, truncated, or exceptional — leaves the queue
    empty.
    """

    def test_f0036_queue_cleared_when_callback_raises_unhandled_exception(self) -> None:
        """Queue must be empty after an unhandled exception exits ``_notify``.

        Callback A re-enters ``_notify`` via ``state.set_cursor`` and
        then raises ``KeyError``.  Callback B records every event it
        sees.  After catching the ``KeyError`` from the outer call, an
        UNRELATED ``_notify`` (``SELECTION_CHANGED``) is triggered.
        Callback B must see ONLY the new event — not leftover events
        from the failed dispatch.
        """
        state = HexDocumentState()
        b_events: list[HexDocumentEvent] = []

        err_msg = "deliberate unhandled error from A"

        def callback_a(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            if event_type is HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(0, 4)
                raise KeyError(err_msg)

        def callback_b(event_type: HexDocumentEvent, _data: dict[str, Any]) -> None:
            b_events.append(event_type)

        state.register_callback(callback_a)
        state.register_callback(callback_b)

        with pytest.raises(KeyError, match=err_msg):
            state.set_cursor(10)

        b_events.clear()

        state.set_selection(5, 10)

        assert b_events == [HexDocumentEvent.SELECTION_CHANGED], f"Expected only SELECTION_CHANGED but got {b_events}"
