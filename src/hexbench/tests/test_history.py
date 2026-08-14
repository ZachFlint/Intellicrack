# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Undo and redo, checked against the engine's own digest of the document.

An undo test that only counts steps proves nothing: a stack can pop the right
number of times and still leave the bytes wrong. Every claim here is therefore
anchored to ``compute_hash``, which the engine computes over the document's real
contents, and the digest is read again after each individual edit. That second
reading is what stops the final comparison from being vacuous -- if an edit ever
silently failed to change anything, ``test_interleaved_edits_undo_back_to_the_
original_digest`` would fail on the guard rather than pass on the restore.

Everything runs through :meth:`~hexbench.tests._support.Session.call`, so the
registry's generation counter and the dispatcher's mutating-operation handling
are exercised alongside the engine, and the state each operation reports is
cross-checked against the state the registry reports for the same document.

Assertions are made through the package's shared vocabulary in
:class:`hexbench.tests._support.Assertions`, which every case here inherits and
which documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ._recipes import SAMPLE
from ._support import HexbenchTestCase


if TYPE_CHECKING:
    from hexbench.codec import JsonValue
    from hexbench.registry import DocumentInfo


_ALGORITHM: Final = "sha256"
"""Digest the engine is asked for whenever this module compares contents."""

_EDITS: Final[tuple[tuple[str, dict[str, JsonValue]], ...]] = (
    ("insert_bytes", {"offset": 8, "data": "00112233"}),
    ("delete_bytes", {"offset": 64, "length": 6}),
    ("fill_block", {"offset": 128, "length": 12, "pattern": "cc"}),
    ("write_bytes", {"offset": 32, "data": "deadbeef"}),
)
"""Interleaved edits applied in order, each of which must change the document."""

_EDIT_COUNT: Final = len(_EDITS)
"""How many undo steps the sequence in :data:`_EDITS` is expected to cost."""

_SINGLE_EDIT: Final[tuple[str, dict[str, JsonValue]]] = _EDITS[-1]
"""One edit, used where a test needs history exactly one entry deep."""

_LATER_EDIT: Final[tuple[str, dict[str, JsonValue]]] = ("write_bytes", {"offset": 96, "data": "0102"})
"""A second, distinct edit used to show that editing discards the redo stack."""

_FILE_EDIT_OFFSET: Final = 0x200
"""Offset written to in the copy of the interpreter, well inside its headers."""

_FILE_EDIT_DATA: Final = "5a5a5a5a"
"""Bytes written into the copy of the interpreter before undoing them."""

_UNDO_LIMIT: Final = 64
"""Ceiling on the undo loop so a broken engine fails instead of hanging."""

_EXTRA_UNDOS: Final = 3
"""How many times undo is called past the bottom of the stack."""

_NO_STEPS: Final = 0
"""The number of undo steps a document with no history can take."""

_TRUE: Final = True
"""Named so a comparison against the engine's answer is not a bare literal."""

_FALSE: Final = False
"""Named so a comparison against the engine's answer is not a bare literal."""


class _HistoryCase(HexbenchTestCase):
    """A session plus the shared assertion vocabulary.

    The ``equal``/``unequal``/``truthy``/``falsy`` helpers come from
    :class:`~hexbench.tests._support.Assertions`, which every case in the
    package inherits.
    """

    def info(self, handle: str) -> DocumentInfo:
        """Read the registry's own view of a document.

        Args:
            handle: Document to describe.

        Returns:
            DocumentInfo: The state the registry reports.
        """
        return self.session.registry.slot(handle).info()

    def digest(self, handle: str) -> str:
        """Ask the engine to hash a document's current contents.

        Args:
            handle: Document to hash.

        Returns:
            str: Hexadecimal digest of everything the document currently holds.

        Raises:
            TypeError: If the engine returns something other than text, which
                would mean the hashing operation had changed shape.
        """
        value = self.session.call("compute_hash", {"algorithm": _ALGORITHM}, handle=handle).value
        if not isinstance(value, str):
            message = f"compute_hash returned {type(value).__name__} instead of a digest string"
            raise TypeError(message)
        return value

    def flag(self, name: str, handle: str) -> JsonValue:
        """Run a nullary predicate against a document.

        Args:
            name: Operation name, such as ``can_undo``.
            handle: Document to run it against.

        Returns:
            JsonValue: Whatever the engine returned, unconverted.
        """
        return self.session.call(name, handle=handle).value

    def apply(self, edit: tuple[str, dict[str, JsonValue]], handle: str) -> None:
        """Apply one edit to a document.

        Args:
            edit: Operation name and its arguments.
            handle: Document to edit.
        """
        name, arguments = edit
        self.session.call(name, arguments, handle=handle)

    def rewind(self, handle: str) -> int:
        """Undo until the stack is empty, counting the steps taken.

        Args:
            handle: Document to rewind.

        Returns:
            int: Number of undo operations that reported success.
        """
        steps = 0
        while steps < _UNDO_LIMIT and self.session.call("undo", handle=handle).value is True:
            steps += 1
        return steps


class FreshDocumentHistory(_HistoryCase):
    """What the history operations report before anything has been edited."""

    def test_a_new_document_reports_no_history_in_either_direction(self) -> None:
        """Both predicates and both registry flags say the stacks are empty."""
        handle = self.session.sample_document().handle
        self.equal(self.flag("can_undo", handle), _FALSE)
        self.equal(self.flag("can_redo", handle), _FALSE)
        state = self.info(handle)
        self.falsy(state.can_undo)
        self.falsy(state.can_redo)
        self.falsy(state.modified)

    def test_undo_and_redo_both_refuse_an_empty_stack(self) -> None:
        """Neither operation claims to have done anything, and nothing changes."""
        handle = self.session.sample_document().handle
        before = self.digest(handle)
        self.equal(self.session.call("undo", handle=handle).value, _FALSE)
        self.equal(self.session.call("redo", handle=handle).value, _FALSE)
        self.equal(self.digest(handle), before)
        self.equal(self.info(handle).length, len(SAMPLE.data))

    def test_rewinding_an_untouched_document_takes_no_steps(self) -> None:
        """The undo loop terminates immediately rather than spinning."""
        handle = self.session.sample_document().handle
        self.equal(self.rewind(handle), _NO_STEPS)


class UndoTransitions(_HistoryCase):
    """Moving down the undo stack, including past its bottom."""

    def test_an_edit_makes_the_document_undoable_and_modified(self) -> None:
        """One edit flips both the undo flag and the modified flag."""
        handle = self.session.sample_document().handle
        self.apply(_SINGLE_EDIT, handle)
        self.equal(self.flag("can_undo", handle), _TRUE)
        state = self.info(handle)
        self.truthy(state.can_undo)
        self.truthy(state.modified)
        self.falsy(state.can_redo)

    def test_undo_past_the_bottom_of_the_stack_returns_false(self) -> None:
        """Each edit costs one undo, and every call after that reports failure."""
        handle = self.session.sample_document().handle
        original = self.digest(handle)
        for edit in _EDITS:
            self.apply(edit, handle)
        self.equal(self.rewind(handle), _EDIT_COUNT)
        for _ in range(_EXTRA_UNDOS):
            self.equal(self.session.call("undo", handle=handle).value, _FALSE)
        self.equal(self.flag("can_undo", handle), _FALSE)
        self.equal(self.digest(handle), original)
        self.equal(self.info(handle).length, len(SAMPLE.data))

    def test_undo_restores_the_length_an_insert_changed(self) -> None:
        """An insert grows the document and undoing it shrinks it back exactly."""
        handle = self.session.sample_document().handle
        inserted = bytes.fromhex("00112233")
        self.session.call("insert_bytes", {"offset": 0, "data": inserted.hex()}, handle=handle)
        self.equal(self.info(handle).length, len(SAMPLE.data) + len(inserted))
        self.equal(self.session.call("undo", handle=handle).value, _TRUE)
        self.equal(self.info(handle).length, len(SAMPLE.data))

    def test_undo_clears_the_modified_flag_once_the_stack_empties(self) -> None:
        """A fully rewound document is reported as unmodified again."""
        handle = self.session.sample_document().handle
        for edit in _EDITS:
            self.apply(edit, handle)
        self.truthy(self.info(handle).modified)
        self.rewind(handle)
        self.falsy(self.info(handle).modified)


class RedoTransitions(_HistoryCase):
    """Moving back up the stack, and the conditions that discard it."""

    def test_redo_replays_exactly_what_undo_removed(self) -> None:
        """The digest after redo matches the digest before the undo."""
        handle = self.session.sample_document().handle
        original = self.digest(handle)
        self.apply(_SINGLE_EDIT, handle)
        edited = self.digest(handle)
        self.unequal(edited, original)
        self.equal(self.session.call("undo", handle=handle).value, _TRUE)
        self.equal(self.digest(handle), original)
        self.equal(self.flag("can_redo", handle), _TRUE)
        self.equal(self.session.call("redo", handle=handle).value, _TRUE)
        self.equal(self.digest(handle), edited)

    def test_redo_past_the_top_of_the_stack_returns_false(self) -> None:
        """Once everything undone has been replayed, redo reports failure."""
        handle = self.session.sample_document().handle
        self.apply(_SINGLE_EDIT, handle)
        self.equal(self.session.call("undo", handle=handle).value, _TRUE)
        self.equal(self.session.call("redo", handle=handle).value, _TRUE)
        self.equal(self.session.call("redo", handle=handle).value, _FALSE)
        self.equal(self.flag("can_redo", handle), _FALSE)

    def test_a_new_edit_discards_the_redo_stack(self) -> None:
        """Editing after an undo makes the undone edit unreachable."""
        handle = self.session.sample_document().handle
        self.apply(_SINGLE_EDIT, handle)
        self.equal(self.session.call("undo", handle=handle).value, _TRUE)
        self.equal(self.flag("can_redo", handle), _TRUE)
        self.apply(_LATER_EDIT, handle)
        self.equal(self.flag("can_redo", handle), _FALSE)
        self.equal(self.session.call("redo", handle=handle).value, _FALSE)


class InterleavedEdits(_HistoryCase):
    """The sequence the whole module exists to check."""

    def test_interleaved_edits_undo_back_to_the_original_digest(self) -> None:
        """Insert, delete, fill and write, then rewind to the starting contents."""
        handle = self.session.sample_document().handle
        original = self.digest(handle)
        seen = [original]
        for edit in _EDITS:
            self.apply(edit, handle)
            current = self.digest(handle)
            self.unequal(current, seen[-1])
            seen.append(current)
        self.equal(len(set(seen)), len(seen))
        self.equal(self.rewind(handle), _EDIT_COUNT)
        self.equal(self.digest(handle), original)
        self.equal(self.info(handle).length, len(SAMPLE.data))
        self.falsy(self.info(handle).modified)

    def test_the_whole_sequence_can_be_replayed_after_rewinding(self) -> None:
        """Redoing every step reproduces the digest the last edit produced."""
        handle = self.session.sample_document().handle
        for edit in _EDITS:
            self.apply(edit, handle)
        final = self.digest(handle)
        self.equal(self.rewind(handle), _EDIT_COUNT)
        replayed = 0
        while replayed < _UNDO_LIMIT and self.session.call("redo", handle=handle).value is True:
            replayed += 1
        self.equal(replayed, _EDIT_COUNT)
        self.equal(self.digest(handle), final)

    def test_a_document_opened_over_a_real_binary_undoes_the_same_way(self) -> None:
        """The interpreter copy, a genuine PE, rewinds to its on-disk contents."""
        handle = self.session.executable_document().handle
        original = self.digest(handle)
        length = self.info(handle).length
        self.session.call("write_bytes", {"offset": _FILE_EDIT_OFFSET, "data": _FILE_EDIT_DATA}, handle=handle)
        self.unequal(self.digest(handle), original)
        self.equal(self.session.call("undo", handle=handle).value, _TRUE)
        self.equal(self.digest(handle), original)
        self.equal(self.info(handle).length, length)


class HistoryGenerations(_HistoryCase):
    """How undo and redo move the counter clients cache their windows against."""

    def test_undo_and_redo_each_advance_the_generation_counter(self) -> None:
        """Both are catalogued as mutating, so both invalidate cached windows."""
        handle = self.session.sample_document().handle
        start = self.info(handle).generation
        self.apply(_SINGLE_EDIT, handle)
        after_edit = self.info(handle).generation
        self.equal(after_edit, start + 1)
        self.session.call("undo", handle=handle)
        after_undo = self.info(handle).generation
        self.equal(after_undo, after_edit + 1)
        self.session.call("redo", handle=handle)
        self.equal(self.info(handle).generation, after_undo + 1)

    def test_reading_the_history_predicates_leaves_the_counter_alone(self) -> None:
        """``can_undo`` and ``can_redo`` are reads and must not look like edits."""
        handle = self.session.sample_document().handle
        self.apply(_SINGLE_EDIT, handle)
        before = self.info(handle).generation
        self.flag("can_undo", handle)
        self.flag("can_redo", handle)
        self.equal(self.info(handle).generation, before)
