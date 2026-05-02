# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit-1 regression tests for ``intellicrack.bridges.hex_state`` concurrency hardening.

Covers:
    * F-0036 - ``_notify`` guard silently dropping downstream events.
    * F-0037 - ``set_document`` reading document length outside the lock.
    * F-0038 - asymmetric locking on display-mode getter/setter.
    * F-0039 - property getters reading shared state without the lock.
    * F-0058 - ``clear_all`` wiping highlights without emitting per-rule
      ``HIGHLIGHT_RULE_REMOVED`` events.

Tests use real ``threading`` primitives (``Event``, ``Lock``, ``Thread``)
to provoke deterministic interleavings; no mocks, monkey-patches, or
patched-out internals are required for any assertion below.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.hex_state import (
    HexDocumentEvent,
    HexDocumentState,
    StateCallbackFn,
)


if TYPE_CHECKING:
    from collections.abc import Callable


_LOCK_BLOCK_PROBE_SECONDS: Final[float] = 0.25
"""Deadline for verifying that a getter blocks on the internal lock.

If a property getter does *not* acquire the lock the call returns
immediately; if it does, the call must wait for the foreign holder to
release.  ``0.25`` seconds is long enough to distinguish the two
behaviours on a loaded CI runner without significantly slowing the
suite.
"""

_LOCK_ACQUIRE_TIMEOUT: Final[float] = 5.0
"""Hard-stop timeout for joining helper threads inside concurrency tests."""


type _Event = tuple[HexDocumentEvent, dict[str, Any]]


class _DummyDoc:
    """Minimal ``HexDocumentFull``-shaped sentinel used by state-only tests.

    Only ``length`` is interesting for hex-state behaviour; the remaining
    methods exist so the object satisfies the structural protocol.
    """

    def __init__(self, length: int = 0) -> None:
        """Initialize with a fixed reported length.

        Args:
            length: Bytes the ``length()`` method should report.
        """
        self._length = length

    def read(self, offset: int, length: int) -> list[int]:
        """Return an empty byte list.

        Args:
            offset: Unused.
            length: Unused.

        Returns:
            list[int]: Always an empty list.
        """
        _ = (offset, length)
        return []

    def length(self) -> int:
        """Return the configured length.

        Returns:
            int: The length value passed at construction time.
        """
        return self._length

    def write(self, offset: int, data: bytes) -> None:
        """Discard the write request.

        Args:
            offset: Unused.
            data: Unused.
        """
        _ = (offset, data)


def _make_collector() -> tuple[list[_Event], StateCallbackFn]:
    """Build a fresh event collector and its bound callback.

    Returns:
        tuple[list[_Event], StateCallbackFn]: A pair of (events_list, callback).
            Each invocation appends ``(event_type, dict(data))`` to the list
            so later mutations of the original payload do not retroactively
            change the captured snapshot.
    """
    events: list[_Event] = []

    def on_event(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        events.append((event_type, dict(data)))

    return events, on_event


# ---------------------------------------------------------------------------
# F-0036 - _notify must not silently drop events emitted from a callback.
# ---------------------------------------------------------------------------


class TestF0036NotifyDoesNotDropDownstreamEvents:
    """Re-entrant notifications must be queued and dispatched, not dropped."""

    def test_callback_emitting_during_dispatch_delivers_downstream_event(self) -> None:
        """An event emitted from inside a callback is delivered to all observers.

        Under the original ``_notify_guard`` implementation any
        ``self._notify(...)`` invoked from inside a callback returned
        immediately because the guard flag was set, silently swallowing
        the secondary event.  After the fix the secondary event is
        appended to the per-instance pending queue and dispatched once
        the active callback chain finishes.
        """
        state = HexDocumentState()

        def reentrant_observer(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            _ = data
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(10, 20)

        events, recorder = _make_collector()
        state.register_callback(reentrant_observer)
        state.register_callback(recorder)

        state.set_cursor(5)

        event_types = [evt for evt, _ in events]
        assert HexDocumentEvent.CURSOR_MOVED in event_types
        assert HexDocumentEvent.SELECTION_CHANGED in event_types, "Downstream SELECTION_CHANGED event was silently dropped by _notify guard"

    def test_chain_of_three_reentrant_emissions_all_delivered(self) -> None:
        """Three-deep chain of callback-triggered emissions are all observed."""
        state = HexDocumentState()
        events, recorder = _make_collector()

        def chained(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            _ = data
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(1, 2)
            elif event_type == HexDocumentEvent.SELECTION_CHANGED and data.get("start") == 1:
                state.notify_data_modified(0, 1)

        state.register_callback(chained)
        state.register_callback(recorder)

        state.set_cursor(7)

        types_seen = [evt for evt, _ in events]
        assert HexDocumentEvent.CURSOR_MOVED in types_seen
        assert HexDocumentEvent.SELECTION_CHANGED in types_seen
        assert HexDocumentEvent.DATA_MODIFIED in types_seen, "Third-level downstream event was dropped by reentrancy guard"

    def test_pending_event_payload_preserved_intact(self) -> None:
        """Queued downstream events keep their payload exactly as emitted."""
        state = HexDocumentState()
        events, recorder = _make_collector()

        def reentrant(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
            _ = data
            if event_type == HexDocumentEvent.CURSOR_MOVED:
                state.set_selection(123, 456)

        state.register_callback(reentrant)
        state.register_callback(recorder)
        state.set_cursor(0)

        selection_events = [data for evt, data in events if evt == HexDocumentEvent.SELECTION_CHANGED]
        assert selection_events, "No SELECTION_CHANGED event was delivered"
        assert selection_events[0]["start"] == 123
        assert selection_events[0]["end"] == 456


# ---------------------------------------------------------------------------
# F-0037 - set_document must read document length while holding the lock.
# ---------------------------------------------------------------------------


class _LengthProbeDoc:
    """Document whose ``length()`` records the state's view of ``self``.

    Used to detect whether ``set_document`` performs the
    ``document.length()`` call while ``self._document`` has already been
    swapped to this instance (the post-fix behaviour) or while the slot
    still holds the previous value (the pre-fix bug).
    """

    def __init__(self, state: HexDocumentState, reported_length: int) -> None:
        """Initialize with the state to probe and a fixed length.

        Args:
            state: The ``HexDocumentState`` whose ``document`` slot will
                be inspected on each ``length()`` call.
            reported_length: Value to return from ``length``.
        """
        self._state = state
        self._reported_length = reported_length
        self.observed_documents_during_length: list[object] = []
        self.observed_locked_during_length: list[bool] = []

    def read(self, offset: int, length: int) -> list[int]:
        """Return an empty byte list.

        Args:
            offset: Unused.
            length: Unused.

        Returns:
            list[int]: Always an empty list.
        """
        _ = (offset, length)
        return []

    def length(self) -> int:
        """Record state observations and return the configured length.

        Returns:
            int: The reported length value.
        """
        self.observed_documents_during_length.append(self._state._document)
        acquired = self._state._lock.acquire(blocking=False)
        self.observed_locked_during_length.append(not acquired)
        if acquired:
            self._state._lock.release()
        return self._reported_length

    def write(self, offset: int, data: bytes) -> None:
        """Discard the write request.

        Args:
            offset: Unused.
            data: Unused.
        """
        _ = (offset, data)


class TestF0037SetDocumentLengthReadHoldsLock:
    """``set_document`` must read ``document.length()`` while holding the lock."""

    def test_length_called_with_lock_held_and_document_already_installed(self) -> None:
        """``length()`` is observed after the document has been installed under the lock.

        Under the unfixed code path ``length()`` is called *before* the
        lock is acquired and *before* ``self._document`` is updated, so
        the document slot still holds the previous value during the call
        and the lock is released.  After the fix ``length()`` runs while
        the lock is held and after the new document has been written
        into the slot.
        """
        state = HexDocumentState()
        probe = _LengthProbeDoc(state, reported_length=4096)

        state.set_document(probe, Path("/nonexistent/probe.bin"))

        assert probe.observed_documents_during_length, "length() was never invoked"
        observed_doc = probe.observed_documents_during_length[0]
        assert observed_doc is probe, "set_document must install the new document before reading its length"
        assert probe.observed_locked_during_length[0] is True, "set_document must hold the internal lock while reading document.length()"

    def test_concurrent_set_document_serialised_during_length(self) -> None:
        """Two concurrent ``set_document`` calls cannot interleave length and assignment.

        ``BlockingLengthDoc.length`` waits on a synchronisation event;
        a second thread tries to call ``set_document(None, None)``.
        With the lock held during length, the second call must block
        until the first ``set_document`` completes.  Without the fix the
        second call slips through, races the first thread's
        notification, and the observable event order becomes
        non-deterministic.
        """

        class _BlockingLengthDoc:
            def __init__(self) -> None:
                self.in_length = threading.Event()
                self.release_length = threading.Event()

            def read(self, offset: int, length: int) -> list[int]:
                _ = (offset, length)
                return []

            def length(self) -> int:
                self.in_length.set()
                self.release_length.wait(timeout=_LOCK_ACQUIRE_TIMEOUT)
                return 1024

            def write(self, offset: int, data: bytes) -> None:
                _ = (offset, data)

        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)
        blocker = _BlockingLengthDoc()

        def opener() -> None:
            state.set_document(blocker, Path("/nonexistent/block.bin"))

        thread_open = threading.Thread(target=opener, name="opener")
        thread_open.start()
        try:
            assert blocker.in_length.wait(timeout=_LOCK_ACQUIRE_TIMEOUT)
            close_returned = threading.Event()

            def closer() -> None:
                state.set_document(None, None)
                close_returned.set()

            thread_close = threading.Thread(target=closer, name="closer")
            thread_close.start()
            try:
                progressed = close_returned.wait(timeout=_LOCK_BLOCK_PROBE_SECONDS)
                assert not progressed, "set_document(None, None) progressed while another set_document held the lock"
            finally:
                blocker.release_length.set()
                thread_close.join(timeout=_LOCK_ACQUIRE_TIMEOUT)
                assert not thread_close.is_alive()
        finally:
            blocker.release_length.set()
            thread_open.join(timeout=_LOCK_ACQUIRE_TIMEOUT)
            assert not thread_open.is_alive()

        opened = [data for evt, data in events if evt == HexDocumentEvent.DOCUMENT_OPENED]
        closed = [data for evt, data in events if evt == HexDocumentEvent.DOCUMENT_CLOSED]
        assert len(opened) == 1
        assert opened[0]["size"] == 1024
        assert len(closed) == 1


# ---------------------------------------------------------------------------
# F-0038 - get_display_mode and set_display_mode_state must lock symmetrically.
# ---------------------------------------------------------------------------


class TestF0038DisplayModeGetterAcquiresLock:
    """``get_display_mode`` must acquire the same lock used by the setter."""

    def test_get_display_mode_blocks_while_lock_is_held_externally(self) -> None:
        """Calling ``get_display_mode`` while the lock is held must block.

        We acquire the internal lock from a helper thread, then call
        ``get_display_mode`` from the test thread.  The unfixed
        implementation reads ``self._display_mode`` without locking and
        returns immediately; the fixed implementation must wait for the
        helper to release the lock.
        """
        state = HexDocumentState()

        with state._lock:
            barrier = threading.Event()
            result_holder: list[str] = []

            def reader() -> None:
                result_holder.append(state.get_display_mode())
                barrier.set()

            t = threading.Thread(target=reader, name="display-mode-reader")
            t.start()
            completed = barrier.wait(timeout=_LOCK_BLOCK_PROBE_SECONDS)
            assert not completed, "get_display_mode returned while the internal lock was held; asymmetric locking re-introduced"

        t.join(timeout=_LOCK_ACQUIRE_TIMEOUT)
        assert not t.is_alive()
        assert result_holder == [state.get_display_mode()]


# ---------------------------------------------------------------------------
# F-0039 - property getters must lock symmetrically with their setters.
# ---------------------------------------------------------------------------


class TestF0039PropertyGettersAcquireLock:
    """``document``, ``file_path``, ``cursor_offset``, and ``selection`` lock-symmetrically."""

    @pytest.mark.parametrize(
        ("attr_name", "reader"),
        [
            ("document", lambda s: s.document),
            ("file_path", lambda s: s.file_path),
            ("cursor_offset", lambda s: s.cursor_offset),
            ("selection", lambda s: s.selection),
        ],
    )
    def test_property_getter_blocks_while_lock_is_held_externally(
        self,
        attr_name: str,
        reader: Callable[[HexDocumentState], object],
    ) -> None:
        """Each property getter must acquire the lock that its writers acquire.

        Args:
            attr_name: Name of the property under test, used only for the
                diagnostic assertion message.
            reader: Function that performs the property read on the
                supplied state instance.
        """
        state = HexDocumentState()

        with state._lock:
            done = threading.Event()
            captured: list[object] = []

            def consume() -> None:
                captured.append(reader(state))
                done.set()

            t = threading.Thread(target=consume, name=f"reader-{attr_name}")
            t.start()
            progressed = done.wait(timeout=_LOCK_BLOCK_PROBE_SECONDS)
            assert not progressed, (
                f"{attr_name} property returned while the internal lock was held; "
                "getter is not lock-symmetric with the corresponding setter"
            )

        t.join(timeout=_LOCK_ACQUIRE_TIMEOUT)
        assert not t.is_alive()
        assert len(captured) == 1


# ---------------------------------------------------------------------------
# F-0058 - clear_all must emit HIGHLIGHT_RULE_REMOVED for each dropped rule.
# ---------------------------------------------------------------------------


class TestF0058ClearAllEmitsHighlightRemoval:
    """``clear_all`` must notify observers of every cleared highlight rule."""

    def test_clear_all_emits_one_highlight_removed_event_per_rule(self) -> None:
        """Each highlight rule cleared by ``clear_all`` triggers a removal event.

        Without the fix ``clear_all`` would clear the internal rules
        dict but only emit a terminal ``DOCUMENT_CLOSED`` event, leaving
        observers with stale highlight caches that cannot be reconciled
        against the canonical state.
        """
        state = HexDocumentState()
        rule_a: dict[str, Any] = {
            "id": "rule-a",
            "condition_type": "value",
            "condition_params": {"value": 0xFF},
            "color": "#FF0000",
        }
        rule_b: dict[str, Any] = {
            "id": "rule-b",
            "condition_type": "range",
            "condition_params": {"start": 0, "end": 16},
            "color": "#00FF00",
        }
        state.set_highlight_rule("rule-a", rule_a)
        state.set_highlight_rule("rule-b", rule_b)
        state.set_document(_DummyDoc(length=32), Path("/nonexistent/with-rules.bin"))

        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_all()

        removed_events = [data for evt, data in events if evt == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED]
        removed_ids = sorted(data["rule_id"] for data in removed_events)
        assert removed_ids == ["rule-a", "rule-b"], (
            f"clear_all must emit HIGHLIGHT_RULE_REMOVED for every cleared rule; observed removed_ids={removed_ids}"
        )

    def test_clear_all_emits_removal_events_before_document_closed(self) -> None:
        """Highlight removals are dispatched before the terminal DOCUMENT_CLOSED."""
        state = HexDocumentState()
        state.set_highlight_rule(
            "single",
            {
                "id": "single",
                "condition_type": "value",
                "condition_params": {"value": 0x00},
                "color": "#000000",
            },
        )
        state.set_document(_DummyDoc(length=8), Path("/nonexistent/order.bin"))

        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_all()

        ordered_types = [evt for evt, _ in events]
        assert HexDocumentEvent.HIGHLIGHT_RULE_REMOVED in ordered_types
        assert HexDocumentEvent.DOCUMENT_CLOSED in ordered_types
        removed_index = ordered_types.index(HexDocumentEvent.HIGHLIGHT_RULE_REMOVED)
        closed_index = ordered_types.index(HexDocumentEvent.DOCUMENT_CLOSED)
        assert removed_index < closed_index, "HIGHLIGHT_RULE_REMOVED events must be emitted before DOCUMENT_CLOSED"

    def test_clear_all_with_no_rules_emits_no_removal_events(self) -> None:
        """``clear_all`` is silent on highlight removal when no rules are stored."""
        state = HexDocumentState()
        state.set_document(_DummyDoc(length=4), Path("/nonexistent/noruled.bin"))

        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_all()

        removed = [evt for evt, _ in events if evt == HexDocumentEvent.HIGHLIGHT_RULE_REMOVED]
        assert removed == []

    def test_clear_all_idempotent_when_already_empty(self) -> None:
        """Calling ``clear_all`` on an already-empty state emits no events."""
        state = HexDocumentState()
        events, cb = _make_collector()
        state.register_callback(cb)

        state.clear_all()
        state.clear_all()

        assert events == []

    def test_clear_all_purges_internal_highlight_dict(self) -> None:
        """After ``clear_all`` the highlight rule dict is empty."""
        state = HexDocumentState()
        state.set_highlight_rule(
            "to-clear",
            {
                "id": "to-clear",
                "condition_type": "value",
                "condition_params": {"value": 0x10},
                "color": "#101010",
            },
        )
        state.clear_all()
        assert state.get_highlight_rules() == {}


# ---------------------------------------------------------------------------
# Smoke check that the genuine concurrency tests do not deadlock.
# ---------------------------------------------------------------------------


def test_concurrent_setter_getter_pairs_complete_within_deadline() -> None:
    """Hammer the locked setters and getters; assert the run finishes fast.

    Five worker threads alternate between writing display-mode / cursor
    / selection state and reading the symmetric getters.  The test only
    asserts that the threads converge inside a generous deadline -- the
    real protection against a regression here is provided by the
    targeted locking tests above.
    """
    state = HexDocumentState()
    deadline = time.monotonic() + 1.5
    iterations = [0]
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            local = 0
            while time.monotonic() < deadline:
                state.set_display_mode_state(f"hex8-{index}")
                state.set_cursor(local)
                state.set_selection(local, local + 1)
                _ = state.get_display_mode()
                _ = state.cursor_offset
                _ = state.selection
                _ = state.document
                _ = state.file_path
                local += 1
            iterations[0] += local
        except (RuntimeError, AssertionError, TypeError, ValueError) as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,), name=f"audit1-w{i}") for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), "audit1 concurrency smoke test deadlocked"
    assert not errors, f"audit1 smoke test raised: {errors[0]!r}"
    assert iterations[0] > 0
