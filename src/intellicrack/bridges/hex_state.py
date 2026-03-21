# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared hex document state manager for bridge-GUI synchronization.

Provides an observer-based state holder that bridges the HexEditorBridge
(AI/programmatic control) and the HexEditorPanel (GUI display) by
maintaining the canonical document reference, cursor position, selection,
and file path, and notifying registered listeners of state changes.
"""

from __future__ import annotations

import enum
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

from ..core.logging import get_logger


_logger = get_logger("bridges.hex_state")


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


StateCallbackFn = Callable[[HexDocumentEvent, dict[str, Any]], None]


class _CallbackEntry:
    """Internal storage for a registered callback with its source_id.

    Args:
        fn: The callback callable.
        source_id: Identifier for loop-guard filtering.
    """

    __slots__ = ("fn", "source_id")

    def __init__(
        self,
        fn: StateCallbackFn,
        source_id: str,
    ) -> None:
        self.fn = fn
        self.source_id = source_id


class HexDocumentState:
    """Thread-safe shared state holder for a hex document.

    Maintains the canonical document instance, cursor offset, selection
    range, and file path.  Registered callbacks are notified on state
    changes, enabling the bridge and GUI to stay in sync without direct
    coupling.
    """

    def __init__(self) -> None:
        self._document: Any | None = None
        self._file_path: Path | None = None
        self._cursor_offset: int = 0
        self._selection: tuple[int, int] | None = None
        self._callbacks: list[_CallbackEntry] = []
        self._lock = threading.Lock()
        self._notify_guard: bool = False

    @property
    def document(self) -> Any | None:
        """Get the active HexDocument instance.

        Returns:
            Any | None: Active HexDocument or None if no document is open.
        """
        return self._document

    @property
    def file_path(self) -> Path | None:
        """Get the path to the currently loaded file.

        Returns:
            Path | None: File path or None if no file is loaded.
        """
        return self._file_path

    @property
    def cursor_offset(self) -> int:
        """Get the current cursor offset.

        Returns:
            int: Current byte offset of the cursor.
        """
        return self._cursor_offset

    @property
    def selection(self) -> tuple[int, int] | None:
        """Get the current selection range.

        Returns:
            tuple[int, int] | None: Tuple of (start, end) offsets or None if no selection.
        """
        return self._selection

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
        document: Any | None,
        file_path: Path | None,
        *,
        source: str = "",
    ) -> None:
        """Set or clear the active document.

        Args:
            document: HexDocument instance, or None to close.
            file_path: Path to the opened file, or None.
            source: Identifier of the caller for loop-guard filtering.
        """
        self._document = document
        self._file_path = file_path
        self._cursor_offset = 0
        self._selection = None
        if document is not None:
            doc_len = 0
            length_fn = getattr(document, "length", None)
            if callable(length_fn):
                doc_len = length_fn()
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
        self._selection = None
        self._notify(
            HexDocumentEvent.SELECTION_CHANGED,
            {"start": -1, "end": -1},
            source=source,
        )

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

        Args:
            path: Path where the document was saved.
            source: Identifier of the caller for loop-guard filtering.
        """
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

    def _notify(
        self,
        event_type: HexDocumentEvent,
        data: dict[str, Any],
        *,
        source: str = "",
    ) -> None:
        """Dispatch a state change notification to all registered callbacks.

        Uses a reentrancy guard to prevent infinite notification loops.
        Callbacks whose source_id matches the source are skipped.

        Args:
            event_type: The event type being emitted.
            data: Event-specific payload dictionary.
            source: Identifier of the originating caller.
        """
        if self._notify_guard:
            return
        self._notify_guard = True
        try:
            with self._lock:
                callbacks = list(self._callbacks)
            for entry in callbacks:
                if entry.source_id and entry.source_id == source:
                    continue
                try:
                    entry.fn(event_type, data)
                except Exception:
                    _logger.warning(
                        "callback_error",
                        event_type_value=event_type.value,
                        source_id=entry.source_id,
                        exc_info=True,
                    )
        finally:
            self._notify_guard = False
