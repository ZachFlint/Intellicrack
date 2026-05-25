# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared hex document state manager for bridge-GUI synchronization.

Provides an observer-based state holder that bridges the HexEditorBridge (AI/programmatic control) and the HexEditorPanel (GUI display) by
maintaining the canonical document reference, cursor position, selection, and file path, and notifying registered listeners of state
changes.
"""

from __future__ import annotations

import enum
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import HexDocumentFull


_logger = get_logger(__name__)


NOTIFY_MAX_DEPTH: int = 64
"""Maximum number of reentrant ``_notify`` events drained per outer dispatch.

Re-entrant emissions triggered from inside a callback are queued and dispatched after the outer dispatch loop finishes (preserving causal
ordering across observers).  The cap aborts genuinely runaway callback chains while still allowing legitimate downstream events to flow.
"""


class HexDocumentEvent(enum.Enum):
    """Event types emitted by HexDocumentState.

    Attributes:
        DOCUMENT_OPENED: A new document was loaded.
        DOCUMENT_CLOSED: The current document was closed.
        CURSOR_MOVED: The cursor position changed.
        SELECTION_CHANGED: The selection range changed.
        DATA_MODIFIED: Document bytes were modified.
        DOCUMENT_SAVED: The document was saved to disk.
        TEMPLATE_REGISTERED: A template was registered at runtime.
        TEMPLATE_REMOVED: A template was removed.
        HIGHLIGHT_RULE_ADDED: A byte highlight rule was added.
        HIGHLIGHT_RULE_REMOVED: A byte highlight rule was removed.
        DISPLAY_MODE_CHANGED: The hex display mode changed.
        PATTERN_EXECUTED: A .hexpat pattern was executed against the document.
        VA_MAPPING_CHANGED: Virtual address mappings were added or removed.
        ALIGNMENT_GRID_CHANGED: The alignment grid size changed.
        COLOR_MODE_CHANGED: The byte color-mapping mode changed.
    """

    DOCUMENT_OPENED = "document_opened"
    DOCUMENT_CLOSED = "document_closed"
    CURSOR_MOVED = "cursor_moved"
    SELECTION_CHANGED = "selection_changed"
    DATA_MODIFIED = "data_modified"
    DOCUMENT_SAVED = "document_saved"
    TEMPLATE_REGISTERED = "template_registered"
    TEMPLATE_REMOVED = "template_removed"
    HIGHLIGHT_RULE_ADDED = "highlight_rule_added"
    HIGHLIGHT_RULE_REMOVED = "highlight_rule_removed"
    DISPLAY_MODE_CHANGED = "display_mode_changed"
    PATTERN_EXECUTED = "pattern_executed"
    VA_MAPPING_CHANGED = "va_mapping_changed"
    ALIGNMENT_GRID_CHANGED = "alignment_grid_changed"
    COLOR_MODE_CHANGED = "color_mode_changed"


StateCallbackFn = Callable[[HexDocumentEvent, dict[str, Any]], None]


@dataclass(slots=True)
class _CallbackEntry:
    """Internal storage for a registered callback with its source_id.

    Attributes:
        fn: The callback callable.
        source_id: Identifier for loop-guard filtering.
    """

    fn: StateCallbackFn
    source_id: str


@dataclass(slots=True)
class _PendingEvent:
    """Internal storage for a queued reentrant event.

    Attributes:
        event_type: The event type to dispatch.
        data: Event-specific payload dictionary.
        source: Identifier of the originating caller for loop-guard filtering.
    """

    event_type: HexDocumentEvent
    data: dict[str, Any]
    source: str


class HexDocumentState:
    """Thread-safe shared state holder for a hex document.

    Maintains the canonical document instance, cursor offset, selection range, and file path. Registered callbacks are notified on state
    changes, enabling the bridge and GUI to stay in sync without direct coupling. Instances own the active document slot, the associated
    file path, cursor offset, selection range, the callback registry, a threading lock and per-thread re-entrancy state used during
    notification, plus default highlight rules and display mode used by the GUI.
    """

    def __init__(self) -> None:
        """Initialize the HexDocumentState instance."""
        self._document: HexDocumentFull | None = None
        self._file_path: Path | None = None
        self._cursor_offset: int = 0
        self._selection: tuple[int, int] | None = None
        self._callbacks: list[_CallbackEntry] = []
        self._lock = threading.Lock()
        self._dispatch_state: threading.local = threading.local()
        self._highlight_rules: dict[str, dict[str, Any]] = {}
        self._display_mode: str = "hex8"
        _logger.info(
            "hex_document_state_initialized",
            display_mode=self._display_mode,
        )

    @property
    def document(self) -> HexDocumentFull | None:
        """Get the active HexDocument instance.

        Acquires the internal lock so concurrent writers cannot publish a
        torn reference observed by this getter.

        Returns:
            HexDocumentFull | None: Active HexDocument or None if no document is open.
        """
        with self._lock:
            return self._document

    @property
    def file_path(self) -> Path | None:
        """Get the path to the currently loaded file.

        Acquires the internal lock so concurrent writers cannot publish a
        torn reference observed by this getter.

        Returns:
            Path | None: File path or None if no file is loaded.
        """
        with self._lock:
            return self._file_path

    @property
    def cursor_offset(self) -> int:
        """Get the current cursor offset.

        Acquires the internal lock so concurrent writers cannot publish a
        partially-updated value observed by this getter.

        Returns:
            int: Current byte offset of the cursor.
        """
        with self._lock:
            return self._cursor_offset

    @property
    def selection(self) -> tuple[int, int] | None:
        """Get the current selection range.

        Acquires the internal lock so concurrent writers cannot publish a
        torn reference observed by this getter.

        Returns:
            tuple[int, int] | None: Tuple of (start, end) offsets or None if no selection.
        """
        with self._lock:
            return self._selection

    def get_current_state(self) -> dict[str, Any]:
        """Get a consistent snapshot of all document state.

        Takes the lock to ensure an atomic read of all fields.

        Returns:
            dict[str, Any]: Dict with document, file_path, cursor_offset,
                selection, highlight_rules, display_mode.
        """
        with self._lock:
            return {
                "document": self._document,
                "file_path": str(self._file_path) if self._file_path else None,
                "cursor_offset": self._cursor_offset,
                "selection": self._selection,
                "highlight_rules": dict(self._highlight_rules),
                "display_mode": self._display_mode,
            }

    def register_callback(
        self,
        callback: StateCallbackFn,
        source_id: str = "",
    ) -> None:
        """Register an observer callback for state change notifications.

        Args:
            callback: Callable receiving (event_type, data) arguments.
            source_id: Identifier for the source to enable loop-guard
                filtering. Notifications triggered by a source are not
                re-delivered to that same source.
        """
        with self._lock:
            self._callbacks.append(_CallbackEntry(callback, source_id))
        _logger.debug("callback_registered", source_id=source_id)

    def unregister_callback(self, callback: StateCallbackFn) -> None:
        """Remove a previously registered callback.

        Args:
            callback: The callback to remove.
        """
        with self._lock:
            self._callbacks = [entry for entry in self._callbacks if entry.fn is not callback]

    def set_document(
        self,
        document: HexDocumentFull | None,
        file_path: Path | None,
        *,
        source: str = "",
    ) -> None:
        """Set or clear the active document.

        The mutation of ``_document``, ``_file_path``, ``_cursor_offset``,
        and ``_selection`` is performed atomically under the internal
        lock so concurrent callers cannot observe partially-updated
        state.  The document length is read while the lock is held so
        the recorded ``DOCUMENT_OPENED`` ``size`` payload always belongs
        to the document that has just been published.

        Args:
            document: HexDocument instance, or None to close.
            file_path: Path to the opened file, or None.
            source: Identifier of the caller for loop-guard filtering.
        """
        doc_len = 0
        with self._lock:
            self._document = document
            self._file_path = file_path
            self._cursor_offset = 0
            self._selection = None
            if document is not None:
                length_fn = getattr(document, "length", None)
                if callable(length_fn):
                    doc_len = length_fn()
        if document is not None:
            self._notify(
                HexDocumentEvent.DOCUMENT_OPENED,
                {"file_path": str(file_path) if file_path else None, "size": doc_len},
                source=source,
            )
        else:
            self._notify(HexDocumentEvent.DOCUMENT_CLOSED, {}, source=source)

    def set_cursor(self, offset: int, *, source: str = "") -> None:
        """Update the cursor position.

        Args:
            offset: New cursor byte offset.
            source: Identifier of the caller for loop-guard filtering.
        """
        with self._lock:
            self._cursor_offset = offset
        self._notify(
            HexDocumentEvent.CURSOR_MOVED,
            {"offset": offset},
            source=source,
        )

    def set_selection(
        self,
        start: int,
        end: int,
        *,
        source: str = "",
    ) -> None:
        """Update the selection range.

        Args:
            start: Selection start offset.
            end: Selection end offset (inclusive).
            source: Identifier of the caller for loop-guard filtering.
        """
        with self._lock:
            self._selection = (start, end)
        self._notify(
            HexDocumentEvent.SELECTION_CHANGED,
            {"start": start, "end": end},
            source=source,
        )

    def clear_selection(self, *, source: str = "") -> None:
        """Clear the current selection.

        Args:
            source: Identifier of the caller for loop-guard filtering.
        """
        with self._lock:
            self._selection = None
        self._notify(
            HexDocumentEvent.SELECTION_CHANGED,
            {"start": -1, "end": -1},
            source=source,
        )

    def clear_all(self, *, source: str = "") -> None:
        """Clear every document-related slot atomically.

        Used by bridge ``shutdown`` to fully reset state including the
        document, file path, cursor, selection, and highlight rules.
        Every previously stored highlight rule is announced via a
        dedicated ``HIGHLIGHT_RULE_REMOVED`` event so observers tracking
        the rule list can drop their entries; a ``DOCUMENT_CLOSED`` is
        then emitted only when a document was previously attached.  Both
        observations are required so a sidebar list does not silently
        retain stale rules after a reset.

        Args:
            source: Identifier of the caller for loop-guard filtering.
        """
        with self._lock:
            had_document = self._document is not None
            removed_rule_ids = list(self._highlight_rules.keys())
            self._document = None
            self._file_path = None
            self._cursor_offset = 0
            self._selection = None
            self._highlight_rules.clear()
        for rule_id in removed_rule_ids:
            self._notify(
                HexDocumentEvent.HIGHLIGHT_RULE_REMOVED,
                {"rule_id": rule_id},
                source=source,
            )
        if had_document:
            self._notify(HexDocumentEvent.DOCUMENT_CLOSED, {}, source=source)

    def get_highlight_rules(self) -> dict[str, dict[str, Any]]:
        """Get a copy of all stored highlight rules.

        Returns:
            dict[str, dict[str, Any]]: Copy of the highlight rules dict keyed by rule ID.
        """
        with self._lock:
            return dict(self._highlight_rules)

    def set_highlight_rule(self, rule_id: str, rule: dict[str, Any]) -> None:
        """Store a highlight rule in state.

        Args:
            rule_id: Unique identifier for the rule.
            rule: Rule dict with id, condition_type, condition_params, color.
        """
        with self._lock:
            self._highlight_rules[rule_id] = rule

    def remove_highlight_rule_state(self, rule_id: str) -> bool:
        """Remove a highlight rule from state.

        Args:
            rule_id: The rule ID to remove.

        Returns:
            bool: True if the rule was found and removed, False otherwise.
        """
        with self._lock:
            if rule_id in self._highlight_rules:
                del self._highlight_rules[rule_id]
                return True
            return False

    def get_display_mode(self) -> str:
        """Get the stored display mode.

        Acquires the internal lock so the returned value is the most
        recently published display mode and never an intermediate
        torn reference racing against ``set_display_mode_state``.

        Returns:
            str: Current display mode string.
        """
        with self._lock:
            return self._display_mode

    def set_display_mode_state(self, mode: str) -> None:
        """Store the display mode in state.

        Named with ``_state`` suffix to avoid collision with the notification
        method ``notify_display_mode_changed``.

        Args:
            mode: Display mode string (e.g. ``"hex8"``, ``"hex16_le"``).
        """
        with self._lock:
            self._display_mode = mode

    def notify_data_modified(
        self,
        offset: int,
        length: int,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that document data was modified.

        Args:
            offset: Start offset of the modification.
            length: Number of bytes affected.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.DATA_MODIFIED,
            {"offset": offset, "length": length},
            source=source,
        )

    def notify_document_saved(self, path: str, *, source: str = "") -> None:
        """Notify observers that the document was saved.

        The ``_file_path`` assignment is performed under the internal
        lock so concurrent readers of :attr:`file_path` never observe a
        torn update.

        Args:
            path: Path where the document was saved.
            source: Identifier of the caller for loop-guard filtering.
        """
        with self._lock:
            self._file_path = Path(path)
        self._notify(
            HexDocumentEvent.DOCUMENT_SAVED,
            {"path": path},
            source=source,
        )

    def notify_template_registered(
        self,
        template_name: str,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that a template was registered.

        Args:
            template_name: Name of the registered template.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.TEMPLATE_REGISTERED,
            {"template_name": template_name},
            source=source,
        )

    def notify_template_removed(
        self,
        template_name: str,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that a template was removed.

        Args:
            template_name: Name of the removed template.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.TEMPLATE_REMOVED,
            {"template_name": template_name},
            source=source,
        )

    def notify_highlight_rule_added(
        self,
        rule: dict[str, Any],
        *,
        source: str = "",
    ) -> None:
        """Notify observers that a highlight rule was added.

        Args:
            rule: Rule dict with id, condition_type, condition_params, color.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.HIGHLIGHT_RULE_ADDED,
            {"rule": rule},
            source=source,
        )

    def notify_highlight_rule_removed(
        self,
        rule_id: str,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that a highlight rule was removed.

        Args:
            rule_id: ID of the removed rule.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.HIGHLIGHT_RULE_REMOVED,
            {"rule_id": rule_id},
            source=source,
        )

    def notify_display_mode_changed(
        self,
        mode: str,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that the hex display mode changed.

        Args:
            mode: New display mode string (e.g. ``"hex8"``, ``"hex16_le"``).
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.DISPLAY_MODE_CHANGED,
            {"mode": mode},
            source=source,
        )

    def notify_pattern_executed(
        self,
        pattern_name: str,
        field_count: int,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that a .hexpat pattern was executed.

        Args:
            pattern_name: Name of the executed pattern.
            field_count: Number of top-level fields produced.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.PATTERN_EXECUTED,
            {"pattern_name": pattern_name, "field_count": field_count},
            source=source,
        )

    def notify_va_mapping_changed(
        self,
        mapping_count: int,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that virtual address mappings changed.

        Args:
            mapping_count: Number of active VA mappings after the change.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.VA_MAPPING_CHANGED,
            {"mapping_count": mapping_count},
            source=source,
        )

    def notify_alignment_grid_changed(
        self,
        size: int,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that the alignment grid size changed.

        Args:
            size: New alignment grid size in bytes, or 0 for disabled.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.ALIGNMENT_GRID_CHANGED,
            {"size": size},
            source=source,
        )

    def notify_color_mode_changed(
        self,
        mode: str,
        *,
        source: str = "",
    ) -> None:
        """Notify observers that the byte color-mapping mode changed.

        Args:
            mode: New color mode string (e.g. ``"none"``, ``"entropy"``).
            source: Identifier of the caller for loop-guard filtering.
        """
        self._notify(
            HexDocumentEvent.COLOR_MODE_CHANGED,
            {"mode": mode},
            source=source,
        )

    def _get_thread_queue(self) -> deque[_PendingEvent]:
        """Return this thread's pending-event queue, lazily initialising it.

        Returns:
            deque[_PendingEvent]: The current thread's reentrant-event queue.
        """
        queue: deque[_PendingEvent] | None = getattr(self._dispatch_state, "queue", None)
        if queue is None:
            queue = deque()
            self._dispatch_state.queue = queue
        return queue

    def _is_dispatching(self) -> bool:
        """Return whether the current thread is mid-dispatch.

        Returns:
            bool: True if a ``_notify`` invocation is active on this thread.
        """
        return bool(getattr(self._dispatch_state, "active", False))

    def _set_dispatching(self, *, active: bool) -> None:
        """Mark the current thread's dispatch state.

        Args:
            active: True when entering the outer dispatch loop, False when
                leaving it.
        """
        self._dispatch_state.active = active

    def _drain_dispatch_queue(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        source: str,
        queue: deque[_PendingEvent],
    ) -> int:
        """Dispatch the initial event then drain any queued reentrant events.

        Args:
            event_type: The initial event type being dispatched.
            data: Initial event payload.
            source: Identifier of the originating caller.
            queue: Per-thread pending event queue to drain.

        Returns:
            int: Number of events left in the queue after hitting the
            dispatch cap.
        """
        self._dispatch_one(event_type, data, source)
        dispatched = 1
        while queue and dispatched < NOTIFY_MAX_DEPTH:
            pending = queue.popleft()
            self._dispatch_one(pending.event_type, pending.data, pending.source)
            dispatched += 1
        return len(queue)

    def _dispatch_one(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        source: str,
    ) -> None:
        """Deliver a single event to every registered callback.

        Args:
            event_type: The event type being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller used for the
                loop-guard filter.
        """
        with self._lock:
            callbacks = list(self._callbacks)
        for entry in callbacks:
            if entry.source_id and entry.source_id == source:
                continue
            try:
                entry.fn(event_type, data)
            except (RuntimeError, TypeError, ValueError, OSError):
                _logger.warning(
                    "callback_error",
                    event_type_value=event_type.value,
                    source_id=entry.source_id,
                    callback_repr=repr(entry.fn),
                    exc_info=True,
                )

    def _notify(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        *,
        source: str = "",
    ) -> None:
        """Dispatch a state change notification to all registered callbacks.

        Re-entrant calls on the same thread are queued and drained in
        causal order after the outer dispatch finishes.  Concurrent
        cross-thread emissions proceed independently because the
        re-entrancy state is per-thread; the underlying callback list is
        snapshot under the lock so registrations are race-free.  A
        runaway callback chain is bounded by ``NOTIFY_MAX_DEPTH`` so an
        observer that keeps re-emitting cannot loop forever, but
        legitimate downstream events still flow.

        Args:
            event_type: The event type being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller.
        """
        if self._is_dispatching():
            queue = self._get_thread_queue()
            queue.append(_PendingEvent(event_type=event_type, data=data, source=source))
            return

        queue = self._get_thread_queue()
        self._set_dispatching(active=True)
        truncated_count = 0
        try:
            truncated_count = self._drain_dispatch_queue(event_type, data, source, queue)
        finally:
            if truncated_count:
                _logger.warning(
                    "notify_drain_truncated",
                    pending=truncated_count,
                    cap=NOTIFY_MAX_DEPTH,
                )
            queue.clear()
            self._set_dispatching(active=False)
