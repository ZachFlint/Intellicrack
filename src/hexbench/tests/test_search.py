# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Every search the engine offers, over a document whose contents are known.

The subject is built here rather than found: :data:`PLANTED` lays a needle down
at three offsets, an unsigned integer at one, a binary32 at another and a
UTF-16LE run at a third, separated by a filler byte that cannot be mistaken for
any of them. Because the builder records where it put each value, an expectation
in this module is a fact about the document rather than a number copied out of
an earlier run.

Each search is checked twice over. It must find the planted offsets, and it must
agree exactly with a scan performed in Python against the same bytes -- see
:func:`_scan_bytes` and its siblings, none of which call the engine. Agreeing
with the planted offsets alone would let a search that also reported spurious
hits pass; agreeing with an independent full scan will not.

The last class is the one this module exists for. ``search_*`` returns
``(offset, length)`` pairs and throws the matched bytes away, so a hex editor
cannot paint a hit from the search result -- it has to go back to the document
and read the span again. That re-read is the ``/api/documents/<handle>/window``
route, and
:meth:`SearchHitWindows.test_window_returns_the_bytes_every_hit_names` drives it
for every hit of every search and compares what comes back with the bytes that
were planted. If the window route ever became off by one, clamped wrongly, or
served a stale generation, the grid would highlight the wrong bytes and this is
the test that would say so.

Assertions are made through the ``require_*`` functions in
:mod:`hexbench.tests._support`, which raise :class:`AssertionError` directly;
that module documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ._support import (
    HexbenchTestCase,
    SupportError,
    json_object,
    require_equal,
    require_greater,
    require_unequal,
)


if TYPE_CHECKING:
    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult


_FILLER: Final[bytes] = b"\xee"
"""Byte the planted document is padded with, chosen to match no planted value."""

_LEAD: Final = 16
"""Filler bytes before the first planted value."""

_GAP: Final = 16
"""Filler bytes between consecutive planted values."""

_TRAIL: Final = 32
"""Filler bytes after the last planted value."""

_NEEDLE: Final[bytes] = b"HEXBENCH"
"""Byte string planted three times, searched for as bytes, hex, text and regex."""

_NEEDLE_REGEX: Final = "HEX[A-Z]+CH"
"""Pattern matching :data:`_NEEDLE` and nothing else in the planted document."""

_ABSENT_NEEDLE: Final[bytes] = b"NOTPLANTED"
"""Byte string deliberately left out of the planted document."""

_WIDE_TEXT: Final = "WIDEMARK"
"""String planted as UTF-16LE, for the encoded text search."""

_WIDE_ENCODING: Final = "utf-16le"
"""Engine encoding name :data:`_WIDE_TEXT` is planted with."""

_TEXT_ENCODING: Final = "utf-8"
"""Engine encoding name the plain text searches use."""

_NUMERIC_VALUE: Final = 0x2A6B4C1D
"""Unsigned integer planted once, little endian."""

_NUMERIC_SIZE: Final = 4
"""Width in bytes of every integer search in this module."""

_NUMERIC_MARGIN: Final = 1
"""Half-width of the bracket ``search_numeric_range`` is given."""

_FLOAT_VALUE: Final = 1.5
"""Binary32 value planted once, little endian."""

_FLOAT_SIZE: Final = 4
"""Width in bytes of the planted float."""

_FLOAT_TOLERANCE: Final = 0.0001
"""Tolerance handed to ``search_numeric_float``, and used by its oracle."""

_ALIGNMENT: Final = 1
"""Stride the numeric searches scan at, so no planted value can be stepped over."""

_MAX_RESULTS: Final = 64
"""Result cap comfortably above the number of planted hits."""

_NEEDLE_PLANTINGS: Final = 3
"""How many times :data:`_NEEDLE` appears in the planted document."""

_CAPPED_RESULTS: Final = 2
"""Result cap deliberately below :data:`_NEEDLE_PLANTINGS`."""

_NOTHING_CHECKED: Final = 0
"""Number of re-read hits that would mean the window test proved nothing."""

_LITTLE_ENDIAN: Final = "little"
"""Byte order name for an integer laid down least significant byte first."""

_BIG_ENDIAN: Final = "big"
"""Byte order name for an integer laid down most significant byte first."""

_FLOAT_FORMAT: Final = "<f"
"""Struct format of the planted binary32 value."""

_PAIR_LENGTH: Final = 2
"""Number of members in a search hit: its offset and its length."""

_STATUS_OK: Final = 200
"""Status the window route answers a legitimate read with."""

_OFFSET_KEY: Final = "offset"
"""Window response member naming the first byte actually read."""

_LENGTH_KEY: Final = "length"
"""Window response member naming how many bytes were actually read."""

_DATA_KEY: Final = "data"
"""Window response member carrying the bytes as hexadecimal."""

_NO_HITS: Final[list[tuple[int, int]]] = []
"""What a search that matches nothing must return."""


@dataclass(frozen=True, slots=True)
class Planted:
    """The searched document, together with where each planted value sits.

    Attributes:
        data: The complete document contents.
        needle_offsets: Every offset :data:`_NEEDLE` was written at.
        numeric_offset: Offset of :data:`_NUMERIC_VALUE` as a little-endian
            unsigned integer of :data:`_NUMERIC_SIZE` bytes.
        float_offset: Offset of :data:`_FLOAT_VALUE` as a little-endian binary32.
        wide_offset: Offset of :data:`_WIDE_TEXT` encoded as UTF-16LE.
    """

    data: bytes
    needle_offsets: tuple[int, ...]
    numeric_offset: int
    float_offset: int
    wide_offset: int


def _build_planted() -> Planted:
    """Lay out the searched document and record where every value landed.

    Returns:
        Planted: The document and the offsets of its planted values.
    """
    body = bytearray(_FILLER * _LEAD)
    first = len(body)
    body += _NEEDLE
    body += _FILLER * _GAP

    numeric_offset = len(body)
    body += _NUMERIC_VALUE.to_bytes(_NUMERIC_SIZE, _LITTLE_ENDIAN)
    body += _FILLER * _GAP

    second = len(body)
    body += _NEEDLE
    body += _FILLER * _GAP

    float_offset = len(body)
    body += struct.pack(_FLOAT_FORMAT, _FLOAT_VALUE)
    body += _FILLER * _GAP

    wide_offset = len(body)
    body += _WIDE_TEXT.encode(_WIDE_ENCODING)
    body += _FILLER * _GAP

    third = len(body)
    body += _NEEDLE
    body += _FILLER * _TRAIL

    return Planted(
        data=bytes(body),
        needle_offsets=(first, second, third),
        numeric_offset=numeric_offset,
        float_offset=float_offset,
        wide_offset=wide_offset,
    )


PLANTED: Final[Planted] = _build_planted()
"""The document every search in this module runs against."""

_NUMERIC_BIG_ENDIAN_VALUE: Final = int.from_bytes(_NUMERIC_VALUE.to_bytes(_NUMERIC_SIZE, _LITTLE_ENDIAN), _BIG_ENDIAN)
"""The planted bytes read the other way round, so the big-endian search has a real target."""


def _scan_bytes(pattern: bytes) -> list[tuple[int, int]]:
    """Find every occurrence of a byte string in the planted document.

    Args:
        pattern: Bytes to look for.

    Returns:
        list[tuple[int, int]]: Offset and length of each occurrence, ascending.
    """
    found: list[tuple[int, int]] = []
    position = PLANTED.data.find(pattern)
    while position != -1:
        found.append((position, len(pattern)))
        position = PLANTED.data.find(pattern, position + 1)
    return found


def _scan_regex(pattern: str) -> list[tuple[int, int]]:
    """Find every match of a pattern in the planted document.

    Args:
        pattern: Regular expression, in the spelling the engine is given.

    Returns:
        list[tuple[int, int]]: Offset and length of each match, ascending.
    """
    compiled = re.compile(pattern.encode(_TEXT_ENCODING))
    return [(match.start(), match.end() - match.start()) for match in compiled.finditer(PLANTED.data)]


def _scan_integer(value: int, *, signed: bool, big_endian: bool) -> list[tuple[int, int]]:
    """Find every occurrence of an integer laid out as the engine would lay it out.

    Args:
        value: Integer to look for.
        signed: Whether the integer is two's complement.
        big_endian: Whether the most significant byte comes first.

    Returns:
        list[tuple[int, int]]: Offset and length of each occurrence, ascending.
    """
    order = _BIG_ENDIAN if big_endian else _LITTLE_ENDIAN
    return _scan_bytes(value.to_bytes(_NUMERIC_SIZE, order, signed=signed))


def _scan_integer_range(low: int, high: int) -> list[tuple[int, int]]:
    """Find every unsigned little-endian integer inside a closed range.

    Args:
        low: Smallest value that counts as a hit.
        high: Largest value that counts as a hit.

    Returns:
        list[tuple[int, int]]: Offset and length of each hit, ascending.
    """
    limit = len(PLANTED.data) - _NUMERIC_SIZE + 1
    windows = ((start, int.from_bytes(PLANTED.data[start : start + _NUMERIC_SIZE], _LITTLE_ENDIAN)) for start in range(limit))
    return [(start, _NUMERIC_SIZE) for start, observed in windows if low <= observed <= high]


def _scan_float(value: float, tolerance: float) -> list[tuple[int, int]]:
    """Find every binary32 within a tolerance of a value.

    Args:
        value: Number to look for.
        tolerance: Largest absolute difference that still counts as a hit.

    Returns:
        list[tuple[int, int]]: Offset and length of each hit, ascending.
    """
    limit = len(PLANTED.data) - _FLOAT_SIZE + 1
    windows = ((start, struct.unpack_from(_FLOAT_FORMAT, PLANTED.data, start)[0]) for start in range(limit))
    return [(start, _FLOAT_SIZE) for start, observed in windows if abs(observed - value) <= tolerance]


def _needle_hits() -> list[tuple[int, int]]:
    """Describe where the needle was planted, in search-result form.

    Returns:
        list[tuple[int, int]]: Offset and length of each planting, ascending.
    """
    return [(offset, len(_NEEDLE)) for offset in PLANTED.needle_offsets]


def _pairs_of(result: InvocationResult) -> list[tuple[int, int]]:
    """Read a search result as a list of offset and length pairs.

    Args:
        result: The invocation result to read.

    Returns:
        list[tuple[int, int]]: The hits the engine reported, in the order given.

    Raises:
        SupportError: If the result is not a list of two-member integer lists.
    """
    value = result.value
    if not isinstance(value, list):
        message = f"{result.operation} returned {type(value).__name__} where a list of hits was expected"
        raise SupportError(message)
    hits: list[tuple[int, int]] = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != _PAIR_LENGTH:
            message = f"{result.operation} returned {entry!r} where an offset and length pair was expected"
            raise SupportError(message)
        offset, length = entry
        if not isinstance(offset, int) or not isinstance(length, int):
            message = f"{result.operation} returned a hit with non-integer members: {entry!r}"
            raise SupportError(message)
        hits.append((offset, length))
    return hits


@dataclass(frozen=True, slots=True)
class SearchCase:
    """One search, its arguments, and the bytes every hit must re-read as.

    Attributes:
        name: Operation name as it appears in the catalogue.
        arguments: Raw JSON arguments keyed by parameter name.
        matched: The byte string each hit must turn out to name. Every search
            here looks for one determinate value, so a hit that re-reads as
            anything else is wrong even if the search and the re-read happen to
            agree with each other.
    """

    name: str
    arguments: dict[str, JsonValue]
    matched: bytes


def _search_cases() -> tuple[SearchCase, ...]:
    """Enumerate every search operation together with arguments that hit.

    Returns:
        tuple[SearchCase, ...]: One case per search the engine exposes.
    """
    numeric = _NUMERIC_VALUE.to_bytes(_NUMERIC_SIZE, _LITTLE_ENDIAN)
    return (
        SearchCase("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS}, _NEEDLE),
        SearchCase("search_hex", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS}, _NEEDLE),
        SearchCase(
            "search_text",
            {
                "text": _NEEDLE.decode(_TEXT_ENCODING),
                "encoding": _TEXT_ENCODING,
                "case_sensitive": True,
                "max_results": _MAX_RESULTS,
            },
            _NEEDLE,
        ),
        SearchCase(
            "search_text_encoded",
            {"text": _WIDE_TEXT, "encoding": _WIDE_ENCODING, "case_sensitive": True, "max_results": _MAX_RESULTS},
            _WIDE_TEXT.encode(_WIDE_ENCODING),
        ),
        SearchCase("search_regex", {"pattern": _NEEDLE_REGEX, "max_results": _MAX_RESULTS}, _NEEDLE),
        SearchCase(
            "search_numeric",
            {
                "value": _NUMERIC_VALUE,
                "size": _NUMERIC_SIZE,
                "signed": False,
                "big_endian": False,
                "alignment": _ALIGNMENT,
                "max_results": _MAX_RESULTS,
            },
            numeric,
        ),
        SearchCase(
            "search_numeric_float",
            {
                "value": _FLOAT_VALUE,
                "size": _FLOAT_SIZE,
                "big_endian": False,
                "tolerance": _FLOAT_TOLERANCE,
                "alignment": _ALIGNMENT,
                "max_results": _MAX_RESULTS,
            },
            struct.pack(_FLOAT_FORMAT, _FLOAT_VALUE),
        ),
        SearchCase(
            "search_numeric_range",
            {
                "value_range": [_NUMERIC_VALUE - _NUMERIC_MARGIN, _NUMERIC_VALUE + _NUMERIC_MARGIN],
                "size": _NUMERIC_SIZE,
                "signed": False,
                "big_endian": False,
                "alignment": _ALIGNMENT,
                "max_results": _MAX_RESULTS,
            },
            numeric,
        ),
    )


class _PlantedCase(HexbenchTestCase):
    """Base case holding the planted document open for the duration of a test."""

    handle: str

    def setUp(self) -> None:
        """Register a fresh document over :data:`PLANTED`."""
        super().setUp()
        self.handle = self.session.open_bytes(PLANTED.data).handle

    def hits(self, name: str, arguments: dict[str, JsonValue]) -> list[tuple[int, int]]:
        """Run one search against the planted document.

        Args:
            name: Search operation as it appears in the catalogue.
            arguments: Raw JSON arguments keyed by parameter name.

        Returns:
            list[tuple[int, int]]: The hits the engine reported.
        """
        return _pairs_of(self.session.call(name, arguments, handle=self.handle))


class PlantedSearches(_PlantedCase):
    """Each search finds what was planted, and finds nothing that was not."""

    def test_search_bytes_finds_every_planting(self) -> None:
        """A raw byte search reports all three needles and no other span."""
        found = self.hits("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS})
        require_equal(found, _needle_hits(), "search_bytes against the planted offsets")
        require_equal(found, _scan_bytes(_NEEDLE), "search_bytes against a Python scan")

    def test_search_bytes_reports_nothing_for_an_absent_pattern(self) -> None:
        """A pattern that was never planted must produce an empty result."""
        require_equal(_scan_bytes(_ABSENT_NEEDLE), _NO_HITS, "the absent pattern really is absent")
        found = self.hits("search_bytes", {"pattern": _ABSENT_NEEDLE.hex(), "max_results": _MAX_RESULTS})
        require_equal(found, _NO_HITS, "search_bytes for an absent pattern")

    def test_search_hex_agrees_with_search_bytes(self) -> None:
        """The hexadecimal spelling of a pattern finds the same spans as the bytes."""
        found = self.hits("search_hex", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS})
        require_equal(found, _needle_hits(), "search_hex against the planted offsets")

    def test_search_text_respects_case_when_asked_to(self) -> None:
        """A case-sensitive text search will not match a differently cased needle."""
        lowered = _NEEDLE.decode(_TEXT_ENCODING).lower()
        require_equal(_scan_bytes(lowered.encode(_TEXT_ENCODING)), _NO_HITS, "the lowercase needle really is absent")
        arguments: dict[str, JsonValue] = {
            "text": lowered,
            "encoding": _TEXT_ENCODING,
            "case_sensitive": True,
            "max_results": _MAX_RESULTS,
        }
        require_equal(self.hits("search_text", arguments), _NO_HITS, "case-sensitive search for the lowercase needle")

    def test_search_text_ignores_case_when_asked_to(self) -> None:
        """A case-insensitive text search matches the needle whatever case it is given in."""
        arguments: dict[str, JsonValue] = {
            "text": _NEEDLE.decode(_TEXT_ENCODING).lower(),
            "encoding": _TEXT_ENCODING,
            "case_sensitive": False,
            "max_results": _MAX_RESULTS,
        }
        require_equal(self.hits("search_text", arguments), _needle_hits(), "case-insensitive search for the needle")

    def test_search_text_encoded_finds_the_wide_run(self) -> None:
        """The UTF-16LE planting is found at its offset, two bytes per character."""
        arguments: dict[str, JsonValue] = {
            "text": _WIDE_TEXT,
            "encoding": _WIDE_ENCODING,
            "case_sensitive": True,
            "max_results": _MAX_RESULTS,
        }
        encoded = _WIDE_TEXT.encode(_WIDE_ENCODING)
        found = self.hits("search_text_encoded", arguments)
        require_equal(found, [(PLANTED.wide_offset, len(encoded))], "search_text_encoded against the planted offset")
        require_equal(found, _scan_bytes(encoded), "search_text_encoded against a Python scan")

    def test_search_regex_finds_the_needles(self) -> None:
        """A pattern search agrees with :mod:`re` over the same bytes."""
        found = self.hits("search_regex", {"pattern": _NEEDLE_REGEX, "max_results": _MAX_RESULTS})
        require_equal(found, _needle_hits(), "search_regex against the planted offsets")
        require_equal(found, _scan_regex(_NEEDLE_REGEX), "search_regex against the re module")

    def test_search_numeric_finds_the_planted_integer(self) -> None:
        """The little-endian integer is found exactly where it was written."""
        arguments: dict[str, JsonValue] = {
            "value": _NUMERIC_VALUE,
            "size": _NUMERIC_SIZE,
            "signed": False,
            "big_endian": False,
            "alignment": _ALIGNMENT,
            "max_results": _MAX_RESULTS,
        }
        found = self.hits("search_numeric", arguments)
        require_equal(found, [(PLANTED.numeric_offset, _NUMERIC_SIZE)], "search_numeric against the planted offset")
        require_equal(found, _scan_integer(_NUMERIC_VALUE, signed=False, big_endian=False), "search_numeric against a Python scan")

    def test_search_numeric_reads_the_same_bytes_the_other_way_round(self) -> None:
        """Big-endian searching finds the planting only under its byte-reversed value."""
        require_unequal(_NUMERIC_BIG_ENDIAN_VALUE, _NUMERIC_VALUE, "the byte-reversed value")
        arguments: dict[str, JsonValue] = {
            "value": _NUMERIC_BIG_ENDIAN_VALUE,
            "size": _NUMERIC_SIZE,
            "signed": False,
            "big_endian": True,
            "alignment": _ALIGNMENT,
            "max_results": _MAX_RESULTS,
        }
        found = self.hits("search_numeric", arguments)
        require_equal(found, [(PLANTED.numeric_offset, _NUMERIC_SIZE)], "big-endian search for the reversed value")
        expected = _scan_integer(_NUMERIC_BIG_ENDIAN_VALUE, signed=False, big_endian=True)
        require_equal(found, expected, "big-endian search against a Python scan")

        arguments["value"] = _NUMERIC_VALUE
        missed = _scan_integer(_NUMERIC_VALUE, signed=False, big_endian=True)
        require_equal(self.hits("search_numeric", arguments), missed, "big-endian search for the little-endian value")

    def test_search_numeric_float_finds_the_planted_float(self) -> None:
        """The binary32 planting is found, and no other window is within tolerance."""
        arguments: dict[str, JsonValue] = {
            "value": _FLOAT_VALUE,
            "size": _FLOAT_SIZE,
            "big_endian": False,
            "tolerance": _FLOAT_TOLERANCE,
            "alignment": _ALIGNMENT,
            "max_results": _MAX_RESULTS,
        }
        found = self.hits("search_numeric_float", arguments)
        require_equal(found, [(PLANTED.float_offset, _FLOAT_SIZE)], "search_numeric_float against the planted offset")
        require_equal(found, _scan_float(_FLOAT_VALUE, _FLOAT_TOLERANCE), "search_numeric_float against a Python scan")

    def test_search_numeric_range_brackets_the_planted_integer(self) -> None:
        """A range that straddles the planted value finds it and nothing else."""
        low = _NUMERIC_VALUE - _NUMERIC_MARGIN
        high = _NUMERIC_VALUE + _NUMERIC_MARGIN
        arguments: dict[str, JsonValue] = {
            "value_range": [low, high],
            "size": _NUMERIC_SIZE,
            "signed": False,
            "big_endian": False,
            "alignment": _ALIGNMENT,
            "max_results": _MAX_RESULTS,
        }
        found = self.hits("search_numeric_range", arguments)
        require_equal(found, [(PLANTED.numeric_offset, _NUMERIC_SIZE)], "search_numeric_range against the planted offset")
        require_equal(found, _scan_integer_range(low, high), "search_numeric_range against a Python scan")


class SearchResultCaps(_PlantedCase):
    """``max_results`` is a real cap, not a hint."""

    def test_byte_search_stops_at_the_cap(self) -> None:
        """Asking for fewer hits than exist returns exactly that many, from the front."""
        planted = _needle_hits()
        require_greater(len(planted), _CAPPED_RESULTS, "plantings available to be capped")

        capped = self.hits("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _CAPPED_RESULTS})
        require_equal(capped, planted[:_CAPPED_RESULTS], "search_bytes under a cap")

    def test_text_and_regex_searches_stop_at_the_cap(self) -> None:
        """The cap applies to the text and pattern searches on the same terms."""
        planted = _needle_hits()
        text: dict[str, JsonValue] = {
            "text": _NEEDLE.decode(_TEXT_ENCODING),
            "encoding": _TEXT_ENCODING,
            "case_sensitive": True,
            "max_results": _CAPPED_RESULTS,
        }
        require_equal(self.hits("search_text", text), planted[:_CAPPED_RESULTS], "search_text under a cap")
        capped = self.hits("search_regex", {"pattern": _NEEDLE_REGEX, "max_results": _CAPPED_RESULTS})
        require_equal(capped, planted[:_CAPPED_RESULTS], "search_regex under a cap")

    def test_raising_the_cap_uncovers_the_remaining_hits(self) -> None:
        """A cap at and above the number planted returns all of them."""
        planted = _needle_hits()
        exact = self.hits("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _NEEDLE_PLANTINGS})
        generous = self.hits("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS})
        require_equal(exact, planted, "search_bytes capped at exactly the number planted")
        require_equal(generous, planted, "search_bytes capped well above the number planted")


class SearchHitWindows(_PlantedCase):
    """The window route can serve back the bytes a search threw away."""

    def window_bytes(self, offset: int, length: int) -> bytes:
        """Read a span through the route the grid uses.

        Args:
            offset: First byte to read.
            length: Number of bytes to read.

        Returns:
            bytes: Exactly the bytes the route served for that span.

        Raises:
            SupportError: If the route refused the read, clamped it, or answered
                with a payload that is not the documented shape.
        """
        response = self.session.get(
            f"/api/documents/{self.handle}/window",
            query={_OFFSET_KEY: str(offset), _LENGTH_KEY: str(length)},
        )
        if response.status != _STATUS_OK:
            message = f"window {offset}+{length} answered {response.status}: {response.body[:200]!r}"
            raise SupportError(message)
        payload = json_object(response)
        served = payload.get(_DATA_KEY)
        if not isinstance(served, str):
            message = f"window {offset}+{length} carried {type(served).__name__} instead of hexadecimal text"
            raise SupportError(message)
        if payload.get(_OFFSET_KEY) != offset or payload.get(_LENGTH_KEY) != length:
            message = f"window {offset}+{length} was clamped to {payload.get(_OFFSET_KEY)}+{payload.get(_LENGTH_KEY)}"
            raise SupportError(message)
        return bytes.fromhex(served)

    def test_window_returns_the_bytes_every_hit_names(self) -> None:
        """Re-reading each hit yields the planted bytes the search discarded.

        This is the whole reason the grid re-reads: a search hands back spans and
        keeps none of the content, so the bytes drawn under a highlight come from
        this route and nowhere else.

        Each re-read is checked twice: against the document the test planted, and
        against the value that search was looking for. The second check is what
        makes the pair meaningful. Comparing the re-read only with the document
        would still pass if the search and the window route were wrong by the
        same offset, since both would then be describing the same wrong span.
        """
        checked = 0
        for case in _search_cases():
            found = self.hits(case.name, case.arguments)
            require_unequal(found, _NO_HITS, f"{case.name} found nothing to re-read")
            for offset, length in found:
                served = self.window_bytes(offset, length)
                planted = PLANTED.data[offset : offset + length]
                require_equal(served, planted, f"window re-read of the {case.name} hit at {offset}")
                require_equal(served, case.matched, f"value {case.name} said it found at {offset}")
                checked += 1
        require_greater(checked, _NOTHING_CHECKED, "hits re-read through the window route")

    def test_window_returns_the_needle_itself_for_a_byte_search(self) -> None:
        """Named explicitly: every needle hit re-reads as the needle."""
        for offset, length in self.hits("search_bytes", {"pattern": _NEEDLE.hex(), "max_results": _MAX_RESULTS}):
            require_equal(self.window_bytes(offset, length), _NEEDLE, f"window re-read of the needle at {offset}")

    def test_window_does_not_serve_the_needle_from_a_neighbouring_offset(self) -> None:
        """The route reads the span it was given, so an off-by-one would show here."""
        first = PLANTED.needle_offsets[0]
        require_equal(self.window_bytes(first, len(_NEEDLE)), _NEEDLE, "window read at the needle's own offset")
        require_unequal(self.window_bytes(first + 1, len(_NEEDLE)), _NEEDLE, "window read one byte late")
        require_equal(self.window_bytes(first - 1, 1), _FILLER, "window read one byte early")
