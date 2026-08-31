# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Ownership, identity and mutual exclusion for the documents a session holds open.

``HexDocument`` is a frozen PyO3 class holding its own reader-writer lock, so
concurrent use of one document is what the engine is built for rather than an
error. What this module adds on top is the identity a session needs -- a handle,
a label, an origin -- and one further guarantee the engine does not make: that a
caller can find out a document is busy instead of stalling behind whoever has
it. :meth:`DocumentSlot.borrow` takes a timed reentrant lock for mutations and
reports :class:`BusyError` when the wait expires; :meth:`DocumentSlot.read`
takes nothing, because serialising reads that the engine already runs
concurrently would only reimpose a queue.

Each slot also carries its own bookkeeping generation counter, advanced by
:meth:`DocumentSlot.bump` after *any* mutating operation -- a bookmark edit or
a template registration bumps it exactly as a byte edit does. It exists so a
client polling :meth:`DocumentSlot.info`/:class:`DocumentInfo` can tell that
*something* about the document changed since the last listing, and is
reported to clients as ``DocumentInfo.generation``.

It is deliberately a different number from the engine's own content
generation counter (``HexDocument.generation()``, advanced only by an actual
byte-content edit -- see ``touch()`` in the Rust crate). That engine counter,
not this slot counter, is what a decoded byte window is paired with: a
window's ``"generation"`` field in the HTTP API comes from
``HexDocument.read_window()`` and moves only when the bytes underneath it
actually could have changed. Do not compare the two counters against each
other or assume they stay numerically aligned; they answer different
questions and are allowed to drift apart the moment a non-content mutation
(a bookmark, a VA mapping, a template, a save) touches the document.
"""

from __future__ import annotations

import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack_hexcore import HexDocument


__all__ = ["BusyError", "DocumentInfo", "DocumentSlot", "Registry", "RegistryError"]

_HANDLE_BYTES: Final = 9
_WAIT_FOREVER: Final = -1.0
_INFO_TIMEOUT: Final = 0.25


class RegistryError(LookupError):
    """Raised when a handle does not name a document this session holds open."""


class BusyError(RuntimeError):
    """Raised when a document could not be acquired before its timeout expired."""


@dataclass(frozen=True, slots=True)
class DocumentInfo:
    """Everything a client needs to describe one open document.

    Attributes:
        handle: Opaque session-scoped identifier for the document.
        label: Human readable name shown on the document's tab.
        origin: Name of the catalogued operation that produced the document.
        path: Backing file path, or ``None`` for an in-memory document.
        length: Current size of the document in bytes.
        modified: Whether the document has unsaved changes.
        can_undo: Whether the undo stack holds at least one entry.
        can_redo: Whether the redo stack holds at least one entry.
        generation: The slot's own bookkeeping counter, advanced by every
            mutating operation regardless of whether it touched document
            bytes. This is not the engine's content generation counter that
            byte windows are paired with; see the module docstring.
    """

    handle: str
    label: str
    origin: str
    path: str | None
    length: int
    modified: bool
    can_undo: bool
    can_redo: bool
    generation: int


class DocumentSlot:
    """One open document together with the lock that serialises writes to it.

    The lock guards mutations only. It used to guard everything, because
    ``HexDocument`` was a ``#[pyclass]`` whose mutating methods took an exclusive
    PyO3 borrow, so two threads touching one document at once got
    ``RuntimeError: Already borrowed`` no matter what either of them was doing.
    The engine now carries its own reader-writer lock, so reads are safe to make
    concurrently and :meth:`read` takes nothing at all -- which is the point,
    since serialising them meant two entropy scans of the same document queued
    behind each other for no reason.

    What the lock still buys is the busy answer. A mutation holds the document
    long enough to matter, so :meth:`borrow` keeps its timed acquire and callers
    can report that the document is busy instead of stalling.
    """

    def __init__(self, handle: str, document: HexDocument, origin: str, label: str) -> None:
        """Wrap a freshly created document in a lockable, identified slot.

        Args:
            handle: Opaque identifier minted by the owning registry.
            document: Live document to take ownership of.
            origin: Name of the catalogued operation that produced the document.
            label: Human readable name shown on the document's tab.
        """
        self._handle = handle
        self._document = document
        self._origin = origin
        self._label = label
        self._lock = threading.RLock()
        self._meta = threading.Lock()
        self._generation = 0
        self._cached = self._probe()

    @property
    def handle(self) -> str:
        """Opaque session-scoped identifier for this document.

        Returns:
            str: The handle assigned when the document was registered.
        """
        return self._handle

    @contextmanager
    def borrow(self, *, timeout: float = _WAIT_FOREVER) -> Generator[HexDocument]:
        """Hold this slot's document exclusively for the duration of a block.

        Args:
            timeout: Seconds to wait for exclusive access. Any negative value
                waits indefinitely.

        Yields:
            HexDocument: The document, guaranteed not to be in use by another
            thread for as long as the block runs.

        Raises:
            BusyError: If the document was still in use when the wait expired.
        """
        wait = timeout if timeout >= 0.0 else _WAIT_FOREVER
        if not self._lock.acquire(timeout=wait):
            message = f"document {self._handle} is busy with another operation"
            raise BusyError(message)
        try:
            yield self._document
        finally:
            self._lock.release()

    @contextmanager
    def read(self) -> Generator[HexDocument]:
        """Use this slot's document for an operation that does not change it.

        No lock is taken. The engine serialises a read against a concurrent
        write itself, and lets concurrent reads proceed together, so acquiring
        anything here would only reimpose the queueing this exists to remove.
        A read therefore never has to report the document as busy.

        Yields:
            HexDocument: The document, which other threads may be reading at the
            same time and which a writer may change between two separate calls.
        """
        yield self._document

    def bump(self) -> int:
        """Advance this slot's own bookkeeping counter after a mutating operation.

        This counter is unrelated to the engine's content generation counter
        that byte windows are paired with -- see the module docstring. It
        advances for every mutating operation the dispatcher runs, including
        ones that only touch auxiliary state such as bookmarks or templates.

        Returns:
            int: The new value of this slot's bookkeeping counter.
        """
        with self._meta:
            self._generation += 1
            return self._generation

    def info(self) -> DocumentInfo:
        """Describe the document's current state.

        Reading the state requires the document itself, so a slot that is busy
        with a long analysis would otherwise stall every listing. When the
        document cannot be acquired promptly the most recent successful reading
        is returned instead, which keeps document listings responsive while a
        background job runs.

        Returns:
            DocumentInfo: Current state, or the last known state if the document
            is presently in use elsewhere.
        """
        if not self._lock.acquire(timeout=_INFO_TIMEOUT):
            with self._meta:
                return self._cached
        try:
            current = self._probe()
        finally:
            self._lock.release()
        with self._meta:
            self._cached = current
            return current

    def _probe(self) -> DocumentInfo:
        """Read live state directly from the document.

        The caller must already hold the borrow lock, except during construction
        where the document is not yet reachable from any other thread.

        Returns:
            DocumentInfo: Freshly read state.
        """
        with self._meta:
            generation = self._generation
        return DocumentInfo(
            handle=self._handle,
            label=self._label,
            origin=self._origin,
            path=self._document.file_path(),
            length=self._document.length(),
            modified=self._document.is_modified(),
            can_undo=self._document.can_undo(),
            can_redo=self._document.can_redo(),
            generation=generation,
        )


class Registry:
    """The set of documents one session has open, keyed by opaque handle."""

    def __init__(self) -> None:
        """Create a registry holding no documents."""
        self._lock = threading.Lock()
        self._slots: dict[str, DocumentSlot] = {}

    def create(self, document: HexDocument, *, origin: str, label: str) -> DocumentInfo:
        """Take ownership of a document and mint a handle for it.

        Args:
            document: Live document to register.
            origin: Name of the catalogued operation that produced the document.
            label: Human readable name shown on the document's tab.

        Returns:
            DocumentInfo: State of the newly registered document.
        """
        with self._lock:
            handle = secrets.token_urlsafe(_HANDLE_BYTES)
            while handle in self._slots:
                handle = secrets.token_urlsafe(_HANDLE_BYTES)
            slot = DocumentSlot(handle, document, origin, label)
            self._slots[handle] = slot
        return slot.info()

    def slot(self, handle: str) -> DocumentSlot:
        """Look up the slot a handle names.

        Args:
            handle: Handle previously returned by :meth:`create`.

        Returns:
            DocumentSlot: The slot holding that document.

        Raises:
            RegistryError: If no open document carries that handle.
        """
        with self._lock:
            found = self._slots.get(handle)
        if found is None:
            message = f"no open document with handle {handle!r}"
            raise RegistryError(message)
        return found

    def close(self, handle: str) -> bool:
        """Drop a document from the registry.

        Any thread already inside :meth:`DocumentSlot.borrow` keeps its
        reference and finishes normally; the document is released once the last
        reference goes away.

        Args:
            handle: Handle of the document to close.

        Returns:
            bool: ``True`` if a document was closed, ``False`` if the handle was
            already unknown.
        """
        with self._lock:
            return self._slots.pop(handle, None) is not None

    def snapshot(self) -> tuple[DocumentInfo, ...]:
        """Describe every currently open document.

        Returns:
            tuple[DocumentInfo, ...]: One entry per open document, in the order
            the documents were registered.
        """
        with self._lock:
            slots = tuple(self._slots.values())
        return tuple(slot.info() for slot in slots)

    def shutdown(self) -> None:
        """Release every document the registry still holds."""
        with self._lock:
            self._slots.clear()
