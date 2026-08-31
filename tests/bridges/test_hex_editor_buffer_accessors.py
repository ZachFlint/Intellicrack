# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""The hex bridge's packed-buffer path into the engine's analysis accessors.

``entropy_map``, ``byte_distribution_full`` and ``digram_matrix`` each have a
``*_bytes`` counterpart that returns the same numbers packed little-endian
instead of as a Python list, which spares PyO3 building sixty-five thousand
integer objects for one digram matrix. The bridge prefers those and decodes
them, so what this module has to establish is that decoding produces exactly
what the list form does -- a struct format that named the wrong width, or the
wrong endianness, would yield plausible numbers rather than an error.

Three of the tests compare the two forms element by element against a real PE
on disk. They are paired with a discriminator, because on their own they would
pass just as well if the bridge had quietly kept taking the list path: a
document that answers the buffer accessor with numbers the list accessor does
not report proves which one the bridge actually read.

The last test drives the width check. A payload that is not a whole number of
elements wide means the engine packed something other than what was asked for,
and the decoder must say so rather than truncate to a plausible answer.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore native module not built")


_BLOCK_SIZE: Final[int] = 64
"""Entropy block size used throughout, small enough to yield several blocks."""

_BYTE_VALUES: Final[int] = 256
"""Length of the byte-frequency distribution."""

_DIGRAM_CELLS: Final[int] = 65536
"""Cells in the 256x256 digram matrix."""

_SENTINEL_BYTE: Final[int] = 0x41
"""Byte value the discriminator plants an impossible count against."""

_SENTINEL_COUNT: Final[int] = 999_999_999
"""A count no document in this suite could genuinely produce."""

_TRUNCATED_WIDTH: Final[int] = 4
"""Bytes of a payload that should have been a multiple of eight."""


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive a coroutine to completion on the current event loop.

    Args:
        coro: Coroutine to run.

    Returns:
        T: Whatever the coroutine returned.
    """
    return asyncio.get_event_loop().run_until_complete(coro)


class _BufferOverrideDoc:
    """A real document whose packed accessors answer with planted numbers.

    Every attribute other than the one being overridden is delegated to the
    genuine document, so the bridge is talking to the real engine for
    everything else. The override exists to tell the two code paths apart: the
    list accessor still reports the document's true numbers, so a result
    carrying the planted ones can only have come through the buffer.
    """

    def __init__(self, inner: object, payload: bytes) -> None:
        """Wrap a document and fix what its packed accessors return.

        Args:
            inner: The genuine document to delegate to.
            payload: Bytes every packed accessor should answer with.
        """
        self._inner = inner
        self._payload = payload

    def __getattr__(self, name: str) -> object:
        """Delegate everything not overridden to the genuine document.

        Args:
            name: Attribute being looked up.

        Returns:
            object: The corresponding attribute of the wrapped document.
        """
        return getattr(self._inner, name)

    def byte_distribution_bytes(self) -> bytes:
        """Answer the packed byte-distribution accessor with the planted payload.

        Returns:
            bytes: The payload this wrapper was built with.
        """
        return self._payload

    def digram_matrix_bytes(self) -> bytes:
        """Answer the packed digram accessor with the planted payload.

        Returns:
            bytes: The payload this wrapper was built with.
        """
        return self._payload

    def entropy_map_bytes(self, block_size: int) -> bytes:
        """Answer the packed entropy accessor with the planted payload.

        Args:
            block_size: Requested block size, which the planted payload ignores.

        Returns:
            bytes: The payload this wrapper was built with.
        """
        del block_size
        return self._payload


def _planted_distribution() -> bytes:
    """Pack a byte distribution no real document could produce.

    Returns:
        bytes: 256 little-endian counts, all zero but for one impossible entry.
    """
    counts = [0] * _BYTE_VALUES
    counts[_SENTINEL_BYTE] = _SENTINEL_COUNT
    return struct.pack(f"<{_BYTE_VALUES}Q", *counts)


class TestPackedAccessorsAgreeWithTheListForm:
    """The decoded buffer must equal the list the engine builds itself."""

    def test_entropy_map_matches_the_list_accessor(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Every block's entropy survives the little-endian double round trip.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        document = bridge.document
        assert document is not None
        expected = list(document.entropy_map(_BLOCK_SIZE))
        observed = _run(bridge.get_entropy_map(_BLOCK_SIZE))
        assert observed == expected
        assert len(observed) > 1

    def test_byte_distribution_matches_the_list_accessor(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """All 256 counts survive, and they still add up to the file length.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        document = bridge.document
        assert document is not None
        expected = list(document.byte_distribution_full())
        observed = _run(bridge.get_byte_distribution())
        assert observed == expected
        assert len(observed) == _BYTE_VALUES
        assert sum(observed) == pe_binary.stat().st_size

    def test_digram_matrix_matches_the_list_accessor(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """All 65536 cells survive, and the totals agree with the pair count.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        document = bridge.document
        assert document is not None
        expected = list(document.digram_matrix())
        result = _run(bridge.get_digram_matrix(top_k=0))
        assert result["matrix"] == expected
        assert len(result["matrix"]) == _DIGRAM_CELLS
        assert result["total_pairs"] == pe_binary.stat().st_size - 1


class TestTheBridgeReadsTheBufferAndNotTheList:
    """The discriminator, without which the comparisons above prove nothing."""

    def test_a_planted_distribution_buffer_is_what_the_bridge_reports(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """The counts that come back are the planted ones, not the document's own.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        document = bridge.document
        assert document is not None
        genuine = list(document.byte_distribution_full())
        bridge.document = _BufferOverrideDoc(document, _planted_distribution())
        observed = _run(bridge.get_byte_distribution())
        assert observed[_SENTINEL_BYTE] == _SENTINEL_COUNT
        assert observed != genuine
        assert sum(observed) == _SENTINEL_COUNT

    def test_the_engine_really_exposes_the_packed_accessors(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """The buffer branch is reachable at all, so the tests above took it.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        for accessor in ("entropy_map_bytes", "byte_distribution_bytes", "digram_matrix_bytes"):
            assert hasattr(bridge.document, accessor), f"{accessor} is missing, so the bridge silently used the list accessor"


class TestAMisshapenBufferIsRefused:
    """A payload of the wrong width must fail loudly rather than decode."""

    def test_a_truncated_distribution_buffer_raises(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """Four bytes cannot be a whole number of eight-byte counts.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge.document = _BufferOverrideDoc(bridge.document, b"\x00" * _TRUNCATED_WIDTH)
        with pytest.raises(ValueError, match="byte_distribution_bytes"):
            _run(bridge.get_byte_distribution())

    def test_a_truncated_entropy_buffer_raises(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """The same check guards the entropy buffer, which packs doubles.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge.document = _BufferOverrideDoc(bridge.document, b"\x00" * _TRUNCATED_WIDTH)
        with pytest.raises(ValueError, match="entropy_map_bytes"):
            _run(bridge.get_entropy_map(_BLOCK_SIZE))

    def test_a_truncated_digram_buffer_raises(self, bridge: HexEditorBridge, pe_binary: Path) -> None:
        """The refusal names the digram accessor, so that path reads the buffer too.

        The matrix is too large to plant sentinel counts across the way the
        distribution test does, so the misshapen payload doubles as this
        accessor's discriminator: only the buffer branch could have produced a
        complaint about ``digram_matrix_bytes``.

        Args:
            bridge: An initialised bridge connected to the real engine.
            pe_binary: A genuine PE image on disk.
        """
        _run(bridge.open_file(str(pe_binary)))
        bridge.document = _BufferOverrideDoc(bridge.document, b"\x00" * _TRUNCATED_WIDTH)
        with pytest.raises(ValueError, match="digram_matrix_bytes"):
            _run(bridge.get_digram_matrix(top_k=0))
