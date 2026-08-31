# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Editing a real binary and getting the same bytes back out again.

Every assertion here is checked against something that is not the engine. Sizes
are compared with :meth:`pathlib.Path.stat`, digests with :mod:`hashlib`, and
each block edit with the same edit applied to a :class:`bytearray` in Python. An
engine that reported its own edits back consistently but wrongly would pass a
test written against ``read`` alone; it cannot pass one written against a model
built outside it.

The subject is a copy of the running interpreter. That is a genuine PE with a
real ``MZ`` signature rather than a fixture committed beside the tests, so this
directory stays free of binary blobs and can be deleted whole.

Everything runs through :meth:`hexbench.tests._support.Session.call`, which is
the dispatcher the HTTP layer uses, so the codec's hexadecimal spelling of a
``bytes`` argument and the registry's locking are exercised alongside the engine
rather than bypassed.

Two failure modes are pinned deliberately. An offset at or past the end of the
document must raise :class:`IndexError` from ``read_byte``, ``get_bit``,
``set_bit`` and ``toggle_bit`` -- that was recently fixed in the crate, and a
regression to a panic, a silent clamp or a plain :class:`ValueError` would make
the grid's end-of-document handling wrong. A bit index above seven must stay a
:class:`ValueError`, because the two conditions mean different things to a
client and are reported with different HTTP statuses.

Assertions are made through the ``require_*`` functions in
:mod:`hexbench.tests._support`, which raise :class:`AssertionError` directly;
that module documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Final

from ._support import (
    HexbenchTestCase,
    SupportError,
    require_equal,
    require_false,
    require_raises,
    require_true,
    require_unequal,
)


if TYPE_CHECKING:
    from pathlib import Path

    from hexbench.dispatch import InvocationResult


_DOS_SIGNATURE: Final[bytes] = b"MZ"
"""Signature every PE image opens with, which the interpreter copy must carry."""

_DIGEST_ALGORITHM: Final = "sha256"
"""Algorithm both the engine and :mod:`hashlib` are asked for."""

_EDIT_OFFSET: Final = 0x100
"""Offset the executable round trip writes at, inside the DOS stub padding."""

_EDIT_PAYLOAD: Final[bytes] = b"\xde\xad\xbe\xef"
"""Bytes the executable round trip writes."""

_SAVED_NAME: Final = "roundtrip-saved.bin"
"""Leaf name of the file the edited executable is saved to."""

_SAVED_AS_NAME: Final = "roundtrip-saved-as.bin"
"""Leaf name of the file ``save_as`` writes."""

_MODEL_LENGTH: Final = 256
"""Length of the synthetic document the block and bit edits run against."""

_MODEL_DATA: Final[bytes] = bytes(range(_MODEL_LENGTH))
"""The synthetic document: every byte value once, so its index names its value."""

_INSERT_OFFSET: Final = 100
"""Offset the insertion test splices its payload in at."""

_INSERT_PAYLOAD: Final[bytes] = b"\x01\x02\x03\x04\x05"
"""Bytes the insertion test splices in."""

_DELETE_OFFSET: Final = 64
"""Offset the deletion test removes bytes from."""

_DELETE_LENGTH: Final = 7
"""Number of bytes the deletion test removes."""

_SEAM_MARGIN: Final = 6
"""Bytes read either side of an edit to check the joins line up."""

_FILL_OFFSET: Final = 10
"""Offset the fill test starts at."""

_FILL_LENGTH: Final = 5
"""Number of bytes the fill test covers."""

_FILL_PATTERN: Final[bytes] = b"\xcc"
"""Single-byte pattern the fill test repeats."""

_COPY_SOURCE: Final = 0
"""Offset the copy test reads its block from."""

_COPY_LENGTH: Final = 8
"""Length of the block the copy and move tests carry."""

_COPY_DESTINATION: Final = 100
"""Offset the copy test writes its block to."""

_MOVE_SOURCE: Final = 200
"""Offset the move test lifts its block from."""

_MOVE_DESTINATION: Final = 20
"""Offset the move test drops its block at."""

_MOVE_VACATED: Final[bytes] = b"\x00"
"""Byte the engine leaves behind where a moved block used to sit."""

_SWAP_FIRST: Final = 0
"""Offset of the first block the swap test exchanges."""

_SWAP_SECOND: Final = 128
"""Offset of the second block the swap test exchanges."""

_SWAP_LENGTH: Final = 4
"""Length of both blocks the swap test exchanges."""

_UNEQUAL_SWAP_LENGTH: Final = 8
"""Length that makes the second swap block disagree with the first."""

_BITS_PER_BYTE: Final = 8
"""Number of bit indices the engine accepts for one byte."""

_OVER_WIDE_BIT_INDEX: Final = 8
"""First bit index past the end of a byte, which must be rejected."""

_BYTE_MASK: Final = 0xFF
"""Mask keeping a computed byte inside the range the engine can store."""

_BIT_OFFSETS: Final[tuple[int, ...]] = (0x00, 0x01, 0x55, 0x7F, 0xAA, 0xFF)
"""Offsets whose values in the synthetic document span every bit pattern of interest."""

_BIT_EDIT_OFFSET: Final = 0x3C
"""Offset the bit mutation tests write to."""

_CLEARED_BYTE: Final = 0
"""What a byte holds once every one of its bits has been cleared in turn."""


def _raw_of(result: InvocationResult) -> bytes:
    """Read the untruncated binary payload an invocation carried out of band.

    The JSON rendering of a ``bytes`` result is capped at four kilobytes, so a
    test that compared byte strings through it would silently stop comparing
    once a document grew. The dispatcher keeps the whole value alongside, and
    this is the only place these tests read bytes from.

    Args:
        result: The invocation result to read.

    Returns:
        bytes: The complete payload the engine returned.

    Raises:
        SupportError: If the operation returned no binary payload at all.
    """
    raw = result.raw
    if raw is None:
        message = f"{result.operation} returned no untruncated payload to compare against"
        raise SupportError(message)
    return raw


def _text_of(result: InvocationResult) -> str:
    """Read a textual result, insisting the engine returned text.

    Args:
        result: The invocation result to read.

    Returns:
        str: The string the engine returned.

    Raises:
        SupportError: If the result is not a string.
    """
    value = result.value
    if not isinstance(value, str):
        message = f"{result.operation} returned {type(value).__name__} where text was expected"
        raise SupportError(message)
    return value


def _count_of(result: InvocationResult) -> int:
    """Read an integer result, insisting the engine returned a number.

    Args:
        result: The invocation result to read.

    Returns:
        int: The integer the engine returned.

    Raises:
        SupportError: If the result is not an integer.
    """
    value = result.value
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"{result.operation} returned {type(value).__name__} where an integer was expected"
        raise SupportError(message)
    return value


class _DocumentCase(HexbenchTestCase):
    """Shared reading helpers for the tests in this module."""

    def read_span(self, handle: str, offset: int, length: int) -> bytes:
        """Read one span of a document through the dispatcher.

        Args:
            handle: Document to read from.
            offset: First byte to read.
            length: Number of bytes to read.

        Returns:
            bytes: Exactly the bytes the engine holds at that span.
        """
        return _raw_of(self.session.call("read", {"offset": offset, "length": length}, handle=handle))

    def length_of(self, handle: str) -> int:
        """Ask a document how long it currently is.

        Args:
            handle: Document to measure.

        Returns:
            int: The document's length in bytes.
        """
        return _count_of(self.session.call("length", {}, handle=handle))

    def contents(self, handle: str) -> bytes:
        """Read a whole document.

        Args:
            handle: Document to read.

        Returns:
            bytes: Every byte the document holds.
        """
        return self.read_span(handle, 0, self.length_of(handle))

    def byte_at(self, handle: str, offset: int) -> int:
        """Read one byte through ``read_byte``.

        Args:
            handle: Document to read from.
            offset: Byte to read.

        Returns:
            int: The byte value, from 0 to 255.
        """
        return _count_of(self.session.call("read_byte", {"offset": offset}, handle=handle))

    def flag_of(self, handle: str, name: str) -> object:
        """Read a boolean-returning operation without decoding it further.

        Args:
            handle: Document to interrogate.
            name: Operation to call.

        Returns:
            object: Whatever the operation returned, for an identity comparison.
        """
        return self.session.call(name, {}, handle=handle).value

    def model_document(self) -> str:
        """Register a fresh document over :data:`_MODEL_DATA`.

        Returns:
            str: Handle of the new document.
        """
        return self.session.open_bytes(_MODEL_DATA).handle


class ExecutableRoundTrip(_DocumentCase):
    """A real PE opened, measured, edited, saved and reopened."""

    subject: Path
    handle: str

    def setUp(self) -> None:
        """Copy the running interpreter and open it as a document."""
        super().setUp()
        self.subject = self.session.executable()
        self.handle = self.session.executable_document().handle

    def test_length_matches_the_size_on_disk(self) -> None:
        """The engine's length agrees with the filesystem, byte for byte."""
        require_equal(self.length_of(self.handle), self.subject.stat().st_size, "length of the interpreter copy")

    def test_document_opens_with_the_dos_signature(self) -> None:
        """The subject really is a PE image and not an empty or truncated file."""
        require_equal(self.read_span(self.handle, 0, len(_DOS_SIGNATURE)), _DOS_SIGNATURE, "first two bytes")

    def test_a_fresh_document_reports_no_modifications(self) -> None:
        """Opening a file must not by itself mark it dirty or lose its path."""
        require_false(self.flag_of(self.handle, "is_modified"), "is_modified on a freshly opened file")
        require_equal(self.flag_of(self.handle, "file_path"), str(self.subject), "file_path on a freshly opened file")

    def test_write_is_readable_and_marks_the_document_modified(self) -> None:
        """A write shows up in a later read and flips the modified flag."""
        self.session.call("write_bytes", {"offset": _EDIT_OFFSET, "data": _EDIT_PAYLOAD.hex()}, handle=self.handle)
        require_equal(self.read_span(self.handle, _EDIT_OFFSET, len(_EDIT_PAYLOAD)), _EDIT_PAYLOAD, "bytes read back after a write")
        require_true(self.flag_of(self.handle, "is_modified"), "is_modified after a write")

    def test_saved_copy_reopens_carrying_the_edit(self) -> None:
        """The edit survives a save and a reopen, and the file keeps its size."""
        original = self.subject.stat().st_size
        self.session.call("write_bytes", {"offset": _EDIT_OFFSET, "data": _EDIT_PAYLOAD.hex()}, handle=self.handle)
        saved = self.session.path(_SAVED_NAME)
        self.session.call("save", {"path": str(saved)}, handle=self.handle)

        require_equal(saved.stat().st_size, original, "size of the saved file")
        written = saved.read_bytes()[_EDIT_OFFSET : _EDIT_OFFSET + len(_EDIT_PAYLOAD)]
        require_equal(written, _EDIT_PAYLOAD, "edited bytes as they sit on disk")

        reopened = self.session.open_path(saved).handle
        require_equal(self.read_span(reopened, _EDIT_OFFSET, len(_EDIT_PAYLOAD)), _EDIT_PAYLOAD, "edit after reopening")
        require_equal(self.read_span(reopened, 0, len(_DOS_SIGNATURE)), _DOS_SIGNATURE, "signature after reopening")
        require_false(self.flag_of(reopened, "is_modified"), "is_modified on the reopened copy")

    def test_save_as_writes_the_same_file_save_would(self) -> None:
        """``save_as`` is the second spelling of ``save`` and must not differ."""
        self.session.call("write_bytes", {"offset": _EDIT_OFFSET, "data": _EDIT_PAYLOAD.hex()}, handle=self.handle)
        first = self.session.path(_SAVED_NAME)
        second = self.session.path(_SAVED_AS_NAME)
        self.session.call("save", {"path": str(first)}, handle=self.handle)
        self.session.call("save_as", {"path": str(second)}, handle=self.handle)
        require_equal(second.read_bytes(), first.read_bytes(), "file written by save_as")

    def test_engine_digest_matches_hashlib_over_the_unmodified_file(self) -> None:
        """``compute_hash`` agrees with an oracle that never touches the engine."""
        expected = hashlib.sha256(self.subject.read_bytes()).hexdigest()
        digest = _text_of(self.session.call("compute_hash", {"algorithm": _DIGEST_ALGORITHM}, handle=self.handle))
        require_equal(digest, expected, "sha256 of the unmodified interpreter copy")

    def test_engine_digest_matches_hashlib_over_the_saved_file(self) -> None:
        """The digest of a document reopened after a save matches the file's own."""
        self.session.call("write_bytes", {"offset": _EDIT_OFFSET, "data": _EDIT_PAYLOAD.hex()}, handle=self.handle)
        saved = self.session.path(_SAVED_NAME)
        self.session.call("save", {"path": str(saved)}, handle=self.handle)

        reopened = self.session.open_path(saved).handle
        digest = _text_of(self.session.call("compute_hash", {"algorithm": _DIGEST_ALGORITHM}, handle=reopened))
        require_equal(digest, hashlib.sha256(saved.read_bytes()).hexdigest(), "sha256 of the saved file")
        require_unequal(digest, hashlib.sha256(self.subject.read_bytes()).hexdigest(), "sha256 after an edit")


class LengthChangingEdits(_DocumentCase):
    """Insertions and deletions move the end of the document by exactly the delta."""

    def test_insert_grows_the_document_by_the_payload_length(self) -> None:
        """An insertion adds its payload and nothing else."""
        handle = self.model_document()
        before = self.length_of(handle)
        self.session.call("insert_bytes", {"offset": _INSERT_OFFSET, "data": _INSERT_PAYLOAD.hex()}, handle=handle)
        after = self.length_of(handle)

        require_equal(after - before, len(_INSERT_PAYLOAD), "growth caused by an insertion")
        expected = _MODEL_DATA[:_INSERT_OFFSET] + _INSERT_PAYLOAD + _MODEL_DATA[_INSERT_OFFSET:]
        require_equal(self.contents(handle), expected, "document after an insertion")

    def test_insert_reads_correctly_across_both_seams(self) -> None:
        """The bytes either side of an insertion are the ones that were there before."""
        handle = self.model_document()
        self.session.call("insert_bytes", {"offset": _INSERT_OFFSET, "data": _INSERT_PAYLOAD.hex()}, handle=handle)
        expected = _MODEL_DATA[:_INSERT_OFFSET] + _INSERT_PAYLOAD + _MODEL_DATA[_INSERT_OFFSET:]

        start = _INSERT_OFFSET - _SEAM_MARGIN
        span = _SEAM_MARGIN + len(_INSERT_PAYLOAD) + _SEAM_MARGIN
        require_equal(self.read_span(handle, start, span), expected[start : start + span], "bytes across both seams")

    def test_delete_shrinks_the_document_by_the_removed_length(self) -> None:
        """A deletion removes its span and nothing else."""
        handle = self.model_document()
        before = self.length_of(handle)
        self.session.call("delete_bytes", {"offset": _DELETE_OFFSET, "length": _DELETE_LENGTH}, handle=handle)
        after = self.length_of(handle)

        require_equal(before - after, _DELETE_LENGTH, "shrinkage caused by a deletion")
        expected = _MODEL_DATA[:_DELETE_OFFSET] + _MODEL_DATA[_DELETE_OFFSET + _DELETE_LENGTH :]
        require_equal(self.contents(handle), expected, "document after a deletion")

    def test_delete_reads_correctly_across_the_seam(self) -> None:
        """The byte after a deletion is the first byte the deletion did not take."""
        handle = self.model_document()
        self.session.call("delete_bytes", {"offset": _DELETE_OFFSET, "length": _DELETE_LENGTH}, handle=handle)
        expected = _MODEL_DATA[:_DELETE_OFFSET] + _MODEL_DATA[_DELETE_OFFSET + _DELETE_LENGTH :]

        start = _DELETE_OFFSET - _SEAM_MARGIN
        span = _SEAM_MARGIN * 2
        require_equal(self.read_span(handle, start, span), expected[start : start + span], "bytes across the seam")
        survivor = _MODEL_DATA[_DELETE_OFFSET + _DELETE_LENGTH]
        require_equal(self.byte_at(handle, _DELETE_OFFSET), survivor, "byte that closed the gap")

    def test_insert_then_delete_of_the_same_span_restores_the_document(self) -> None:
        """Undoing an insertion by deleting it leaves the original bytes."""
        handle = self.model_document()
        self.session.call("insert_bytes", {"offset": _INSERT_OFFSET, "data": _INSERT_PAYLOAD.hex()}, handle=handle)
        self.session.call("delete_bytes", {"offset": _INSERT_OFFSET, "length": len(_INSERT_PAYLOAD)}, handle=handle)
        require_equal(self.contents(handle), _MODEL_DATA, "document after an insertion and its deletion")


class BlockEdits(_DocumentCase):
    """Block operations checked against the same edit applied to a bytearray."""

    def test_fill_block_matches_the_model(self) -> None:
        """Filling repeats the pattern across the span and leaves the rest alone."""
        handle = self.model_document()
        self.session.call(
            "fill_block",
            {"offset": _FILL_OFFSET, "length": _FILL_LENGTH, "pattern": _FILL_PATTERN.hex()},
            handle=handle,
        )
        model = bytearray(_MODEL_DATA)
        repeated = _FILL_PATTERN * _FILL_LENGTH
        model[_FILL_OFFSET : _FILL_OFFSET + _FILL_LENGTH] = repeated[:_FILL_LENGTH]

        require_equal(self.contents(handle), bytes(model), "document after a fill")
        require_equal(self.length_of(handle), _MODEL_LENGTH, "length after a fill")

    def test_copy_block_matches_the_model(self) -> None:
        """Copying duplicates the block and leaves the source in place."""
        handle = self.model_document()
        self.session.call(
            "copy_block",
            {"src_offset": _COPY_SOURCE, "length": _COPY_LENGTH, "dst_offset": _COPY_DESTINATION},
            handle=handle,
        )
        model = bytearray(_MODEL_DATA)
        model[_COPY_DESTINATION : _COPY_DESTINATION + _COPY_LENGTH] = model[_COPY_SOURCE : _COPY_SOURCE + _COPY_LENGTH]

        require_equal(self.contents(handle), bytes(model), "document after a copy")
        source = _MODEL_DATA[_COPY_SOURCE : _COPY_SOURCE + _COPY_LENGTH]
        require_equal(self.read_span(handle, _COPY_SOURCE, _COPY_LENGTH), source, "source block after a copy")

    def test_move_block_matches_the_model(self) -> None:
        """Moving carries the block and vacates the ground it came from."""
        handle = self.model_document()
        self.session.call(
            "move_block",
            {"src_offset": _MOVE_SOURCE, "length": _COPY_LENGTH, "dst_offset": _MOVE_DESTINATION},
            handle=handle,
        )
        model = bytearray(_MODEL_DATA)
        carried = model[_MOVE_SOURCE : _MOVE_SOURCE + _COPY_LENGTH]
        model[_MOVE_DESTINATION : _MOVE_DESTINATION + _COPY_LENGTH] = carried
        model[_MOVE_SOURCE : _MOVE_SOURCE + _COPY_LENGTH] = _MOVE_VACATED * _COPY_LENGTH

        require_equal(self.contents(handle), bytes(model), "document after a move")
        require_equal(self.length_of(handle), _MODEL_LENGTH, "length after a move")

    def test_swap_blocks_matches_the_model(self) -> None:
        """Swapping exchanges two equal blocks and touches nothing between them."""
        handle = self.model_document()
        self.session.call(
            "swap_blocks",
            {"offset_a": _SWAP_FIRST, "len_a": _SWAP_LENGTH, "offset_b": _SWAP_SECOND, "len_b": _SWAP_LENGTH},
            handle=handle,
        )
        model = bytearray(_MODEL_DATA)
        first = bytes(model[_SWAP_FIRST : _SWAP_FIRST + _SWAP_LENGTH])
        second = bytes(model[_SWAP_SECOND : _SWAP_SECOND + _SWAP_LENGTH])
        model[_SWAP_FIRST : _SWAP_FIRST + _SWAP_LENGTH] = second
        model[_SWAP_SECOND : _SWAP_SECOND + _SWAP_LENGTH] = first

        require_equal(self.contents(handle), bytes(model), "document after a swap")

    def test_swap_blocks_refuses_unequal_lengths(self) -> None:
        """An unequal swap is a client error, and it must not half-apply."""
        handle = self.model_document()
        arguments = {"offset_a": _SWAP_FIRST, "len_a": _SWAP_LENGTH, "offset_b": _SWAP_SECOND, "len_b": _UNEQUAL_SWAP_LENGTH}
        require_raises(ValueError, "swap_blocks with unequal lengths", lambda: self.session.call("swap_blocks", arguments, handle=handle))
        require_equal(self.contents(handle), _MODEL_DATA, "document after a refused swap")


class BitEdits(_DocumentCase):
    """Bit accessors agree with the arithmetic a client would do on the byte."""

    def test_get_bit_agrees_with_read_byte_for_every_bit(self) -> None:
        """Bit ``n`` of a byte is the engine's ``get_bit`` at index ``n``."""
        handle = self.model_document()
        for offset in _BIT_OFFSETS:
            value = self.byte_at(handle, offset)
            require_equal(value, _MODEL_DATA[offset], f"byte at {offset:#04x}")
            for index in range(_BITS_PER_BYTE):
                observed = self.session.call("get_bit", {"offset": offset, "bit_index": index}, handle=handle).value
                require_equal(observed, bool(value >> index & 1), f"bit {index} of the byte at {offset:#04x}")

    def test_set_bit_writes_the_bit_read_byte_reports(self) -> None:
        """Setting and clearing each bit moves exactly that bit of the byte.

        The expectation is carried forward rather than recomputed from the
        original value: clearing bit two of ``0x3C`` genuinely changes the byte,
        so a model that reset every iteration would be asserting against a value
        the document no longer holds.
        """
        handle = self.model_document()
        current = _MODEL_DATA[_BIT_EDIT_OFFSET]
        for index in range(_BITS_PER_BYTE):
            self.session.call("set_bit", {"offset": _BIT_EDIT_OFFSET, "bit_index": index, "value": True}, handle=handle)
            current |= 1 << index
            require_equal(self.byte_at(handle, _BIT_EDIT_OFFSET), current, f"byte after setting bit {index}")

            self.session.call("set_bit", {"offset": _BIT_EDIT_OFFSET, "bit_index": index, "value": False}, handle=handle)
            current &= ~(1 << index) & _BYTE_MASK
            require_equal(self.byte_at(handle, _BIT_EDIT_OFFSET), current, f"byte after clearing bit {index}")
        require_equal(current, _CLEARED_BYTE, "byte once every bit has been cleared")

    def test_toggle_bit_returns_the_bit_it_just_wrote(self) -> None:
        """Toggling inverts the bit, reports the new value, and undoes itself."""
        handle = self.model_document()
        original = _MODEL_DATA[_BIT_EDIT_OFFSET]
        for index in range(_BITS_PER_BYTE):
            flipped = self.session.call("toggle_bit", {"offset": _BIT_EDIT_OFFSET, "bit_index": index}, handle=handle).value
            require_equal(flipped, not bool(original >> index & 1), f"value reported by toggling bit {index}")
            require_equal(self.byte_at(handle, _BIT_EDIT_OFFSET), original ^ (1 << index), f"byte after toggling bit {index}")

            restored = self.session.call("toggle_bit", {"offset": _BIT_EDIT_OFFSET, "bit_index": index}, handle=handle).value
            require_equal(restored, bool(original >> index & 1), f"value reported by toggling bit {index} back")
            require_equal(self.byte_at(handle, _BIT_EDIT_OFFSET), original, f"byte after toggling bit {index} back")

    def test_read_byte_past_the_end_raises_index_error(self) -> None:
        """The first offset outside the document is out of bounds; the last one inside is not."""
        handle = self.model_document()
        require_equal(self.byte_at(handle, _MODEL_LENGTH - 1), _MODEL_DATA[-1], "last byte inside the document")
        require_raises(
            IndexError,
            "read_byte one past the end",
            lambda: self.session.call("read_byte", {"offset": _MODEL_LENGTH}, handle=handle),
        )

    def test_bit_accessors_past_the_end_raise_index_error(self) -> None:
        """Reading, setting and toggling a bit outside the document all fail alike."""
        handle = self.model_document()
        require_raises(
            IndexError,
            "get_bit one past the end",
            lambda: self.session.call("get_bit", {"offset": _MODEL_LENGTH, "bit_index": 0}, handle=handle),
        )
        require_raises(
            IndexError,
            "set_bit one past the end",
            lambda: self.session.call("set_bit", {"offset": _MODEL_LENGTH, "bit_index": 0, "value": True}, handle=handle),
        )
        require_raises(
            IndexError,
            "toggle_bit one past the end",
            lambda: self.session.call("toggle_bit", {"offset": _MODEL_LENGTH, "bit_index": 0}, handle=handle),
        )

    def test_bit_index_above_seven_raises_value_error(self) -> None:
        """A bit index out of range is a different failure from an offset out of range."""
        handle = self.model_document()
        require_raises(
            ValueError,
            "get_bit with a ninth bit index",
            lambda: self.session.call("get_bit", {"offset": 0, "bit_index": _OVER_WIDE_BIT_INDEX}, handle=handle),
        )
        require_raises(
            ValueError,
            "toggle_bit with a ninth bit index",
            lambda: self.session.call("toggle_bit", {"offset": 0, "bit_index": _OVER_WIDE_BIT_INDEX}, handle=handle),
        )
        require_raises(
            ValueError,
            "set_bit with a ninth bit index",
            lambda: self.session.call("set_bit", {"offset": 0, "bit_index": _OVER_WIDE_BIT_INDEX, "value": True}, handle=handle),
        )
        require_equal(self.contents(handle), _MODEL_DATA, "document after three refused bit edits")
