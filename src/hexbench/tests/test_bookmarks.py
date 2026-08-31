# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bookmarks: the engine's side, the codec's side, and the join between them.

``Bookmark`` is the only structured value that crosses the wire in both
directions. It arrives as a JSON object, is decoded into a real ``Bookmark``
before the engine ever sees it, and comes back either as an object or as ``None``
from ``get_bookmark``. Both directions are checked here, and the field names are
never transcribed: :data:`FIELD_ORDER` is read out of the codec's own encoding of
a bookmark, so renaming a field in the engine changes what these tests compare
rather than leaving them agreeing with a stale list.

The engine offers two views of the same collection -- ``get_bookmarks``, which
yields objects, and ``list_bookmarks``, which yields positional tuples. Every
mutation here is checked through both, since a bookmark that updates in one view
and not the other is exactly the sort of defect a single-view test would miss.

Assertions are made through the package's shared vocabulary in
:class:`hexbench.tests._support.Assertions`, which every case here inherits and
which documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

from intellicrack_hexcore import Bookmark

from hexbench.catalog import ValueKind
from hexbench.codec import DecodeError, decode_argument, encode_result
from hexbench.dispatch import operation_for

from ._support import HexbenchTestCase


if TYPE_CHECKING:
    from collections.abc import Mapping

    from hexbench.catalog import Parameter
    from hexbench.codec import JsonValue
    from hexbench.registry import DocumentInfo


_ADD_OBJECT: Final = "add_bookmark_object"
"""Operation whose single parameter carries a whole bookmark."""

_PROBE_OFFSET: Final = 0
"""Offset of the throwaway bookmark used only to read the codec's field names."""

_PROBE_LENGTH: Final = 0
"""Length of the throwaway bookmark used only to read the codec's field names."""

_PROBE_TEXT: Final = ""
"""Text of the throwaway bookmark used only to read the codec's field names."""


def _bookmark_fields() -> tuple[str, ...]:
    """Read the bookmark field names, in order, out of the codec itself.

    Returns:
        tuple[str, ...]: The keys the codec puts on an encoded bookmark, in the
        order it emits them.

    Raises:
        TypeError: If the codec no longer encodes a bookmark as an object, which
            would mean this module is comparing against the wrong shape.
    """
    encoded = encode_result(Bookmark(_PROBE_OFFSET, _PROBE_LENGTH, _PROBE_TEXT, _PROBE_TEXT))
    if not isinstance(encoded, dict):
        message = f"the codec encoded a bookmark as {type(encoded).__name__} rather than an object"
        raise TypeError(message)
    return tuple(encoded)


FIELD_ORDER: Final[tuple[str, ...]] = _bookmark_fields()
"""Bookmark field names, derived from the codec rather than transcribed here."""

_FIRST: Final[dict[str, JsonValue]] = {"offset": 16, "length": 4, "label": "header", "color": "#ff8800"}
"""The first bookmark every test in this module adds."""

_SECOND: Final[dict[str, JsonValue]] = {"offset": 64, "length": 8, "label": "table", "color": "#3388ff"}
"""A second bookmark, distinct from the first in every field."""

_THIRD: Final[dict[str, JsonValue]] = {"offset": 200, "length": 2, "label": "tail", "color": "#22cc55"}
"""A third bookmark, used where removal has to be seen to renumber."""

_REVISED: Final[dict[str, JsonValue]] = {"offset": 96, "length": 12, "label": "renamed", "color": "#0000ff"}
"""Replacement contents for an existing bookmark."""

_RECOLOURED: Final[dict[str, JsonValue]] = {**_FIRST, "color": "#010203"}
"""The first bookmark with one field changed, to show the codec notices."""

_MISSING_FIELD: Final[dict[str, JsonValue]] = {"offset": 1, "length": 1, "label": "incomplete"}
"""A bookmark payload with its colour left out."""

_ABSENT_FIELD: Final = "color"
"""The field :data:`_MISSING_FIELD` omits."""

_FIRST_INDEX: Final = 0
"""Index the first bookmark added to a document is given."""

_SECOND_INDEX: Final = 1
"""Index the second bookmark added to a document is given."""

_THIRD_INDEX: Final = 2
"""Index the third bookmark added to a document is given."""

_UNKNOWN_INDEX: Final = 97
"""An index no test ever fills, used to drive the not-found paths."""

_TRUE: Final = True
"""Named so a comparison against the engine's answer is not a bare literal."""

_FALSE: Final = False
"""Named so a comparison against the engine's answer is not a bare literal."""


def _positional(payload: Mapping[str, JsonValue]) -> list[JsonValue]:
    """Render a bookmark payload the way ``list_bookmarks`` reports it.

    Args:
        payload: Bookmark contents keyed by field name.

    Returns:
        list[JsonValue]: The same fields in :data:`FIELD_ORDER`, which is how the
        codec renders the positional tuple the engine returns.
    """
    return [payload[field] for field in FIELD_ORDER]


def _parameter() -> Parameter:
    """Describe the catalogued parameter a whole bookmark travels in.

    Returns:
        Parameter: The single parameter of ``add_bookmark_object``.
    """
    return operation_for(_ADD_OBJECT).parameters[0]


class _BookmarkCase(HexbenchTestCase):
    """A session plus the shared assertion vocabulary.

    The ``equal``/``unequal``/``contains``/``is_none`` helpers come from
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

    def add(self, payload: Mapping[str, JsonValue], handle: str) -> JsonValue:
        """Add one bookmark as a whole object.

        Args:
            payload: Bookmark contents keyed by field name.
            handle: Document to add it to.

        Returns:
            JsonValue: The index the engine assigned.
        """
        return self.session.call(_ADD_OBJECT, {"bookmark": dict(payload)}, handle=handle).value

    def objects(self, handle: str) -> JsonValue:
        """Read every bookmark as an object.

        Args:
            handle: Document to read.

        Returns:
            JsonValue: What ``get_bookmarks`` returned, encoded for a client.
        """
        return self.session.call("get_bookmarks", handle=handle).value

    def tuples(self, handle: str) -> JsonValue:
        """Read every bookmark as a positional tuple.

        Args:
            handle: Document to read.

        Returns:
            JsonValue: What ``list_bookmarks`` returned, encoded for a client.
        """
        return self.session.call("list_bookmarks", handle=handle).value

    def one(self, index: int, handle: str) -> JsonValue:
        """Read a single bookmark by index.

        Args:
            index: Position to read.
            handle: Document to read from.

        Returns:
            JsonValue: The bookmark as an object, or ``None`` past the end.
        """
        return self.session.call("get_bookmark", {"index": index}, handle=handle).value

    def populated(self, *payloads: Mapping[str, JsonValue]) -> str:
        """Open a sample document already carrying the given bookmarks.

        Args:
            *payloads: Bookmarks to add, in order.

        Returns:
            str: Handle of the new document.
        """
        handle = self.session.sample_document().handle
        for index, payload in enumerate(payloads):
            self.equal(self.add(payload, handle), index)
        return handle


class BookmarkRoundTrip(_BookmarkCase):
    """Adding a bookmark and reading the very same fields back out."""

    def test_add_bookmark_object_round_trips_through_get_bookmark(self) -> None:
        """Every field survives the trip into the engine and back out again."""
        handle = self.populated(_FIRST)
        self.equal(self.one(_FIRST_INDEX, handle), _FIRST)

    def test_add_bookmark_agrees_with_add_bookmark_object(self) -> None:
        """The four-argument form and the object form store the same thing."""
        handle = self.session.sample_document().handle
        self.equal(self.session.call("add_bookmark", dict(_FIRST), handle=handle).value, _FIRST_INDEX)
        self.equal(self.add(_SECOND, handle), _SECOND_INDEX)
        self.equal(self.one(_FIRST_INDEX, handle), _FIRST)
        self.equal(self.one(_SECOND_INDEX, handle), _SECOND)

    def test_list_bookmarks_agrees_with_get_bookmarks(self) -> None:
        """The tuple view and the object view describe the same collection."""
        handle = self.populated(_FIRST, _SECOND)
        self.equal(self.objects(handle), [_FIRST, _SECOND])
        self.equal(self.tuples(handle), [_positional(_FIRST), _positional(_SECOND)])

    def test_get_bookmark_returns_null_past_the_end(self) -> None:
        """The optional half of the return type is reachable and encodes as null."""
        empty = self.session.sample_document().handle
        self.is_none(self.one(_FIRST_INDEX, empty))
        handle = self.populated(_FIRST)
        self.unequal(self.one(_FIRST_INDEX, handle), None)
        self.is_none(self.one(_UNKNOWN_INDEX, handle))


class BookmarkMutation(_BookmarkCase):
    """Updating and removing bookmarks, seen through both views."""

    def test_update_bookmark_is_observable_through_get_bookmarks(self) -> None:
        """The revised bookmark replaces its predecessor and disturbs no other."""
        handle = self.populated(_FIRST, _SECOND)
        self.equal(self.session.call("update_bookmark", {"index": _FIRST_INDEX, "bookmark": dict(_REVISED)}, handle=handle).value, _TRUE)
        self.equal(self.objects(handle), [_REVISED, _SECOND])
        self.equal(self.one(_FIRST_INDEX, handle), _REVISED)
        self.equal(self.tuples(handle), [_positional(_REVISED), _positional(_SECOND)])

    def test_update_bookmark_rejects_an_unknown_index(self) -> None:
        """A miss reports failure and leaves the collection exactly as it was."""
        handle = self.populated(_FIRST, _SECOND)
        before = self.objects(handle)
        arguments: dict[str, JsonValue] = {"index": _UNKNOWN_INDEX, "bookmark": dict(_REVISED)}
        self.equal(self.session.call("update_bookmark", arguments, handle=handle).value, _FALSE)
        self.equal(self.objects(handle), before)

    def test_remove_bookmark_renumbers_the_survivors(self) -> None:
        """Dropping the middle entry moves the last one down into its index."""
        handle = self.populated(_FIRST, _SECOND, _THIRD)
        self.equal(self.one(_THIRD_INDEX, handle), _THIRD)
        self.equal(self.session.call("remove_bookmark", {"index": _SECOND_INDEX}, handle=handle).value, _TRUE)
        self.equal(self.objects(handle), [_FIRST, _THIRD])
        self.equal(self.one(_SECOND_INDEX, handle), _THIRD)
        self.is_none(self.one(_THIRD_INDEX, handle))

    def test_remove_bookmark_rejects_an_unknown_index(self) -> None:
        """A miss reports failure and removes nothing."""
        handle = self.populated(_FIRST)
        self.equal(self.session.call("remove_bookmark", {"index": _UNKNOWN_INDEX}, handle=handle).value, _FALSE)
        self.equal(self.objects(handle), [_FIRST])

    def test_bookmark_edits_advance_the_generation_without_editing_the_bytes(self) -> None:
        """Clients must refresh, yet the document itself stays unmodified."""
        handle = self.session.sample_document().handle
        start = self.info(handle).generation
        self.add(_FIRST, handle)
        after = self.info(handle)
        self.equal(after.generation, start + 1)
        self.equal(after.modified, _FALSE)
        self.equal(after.can_undo, _FALSE)


class BookmarkCodec(_BookmarkCase):
    """The JSON conversion on its own, without the engine in the way."""

    def test_the_catalogue_routes_a_bookmark_through_the_bookmark_kind(self) -> None:
        """The parameter these tests decode against really is the bookmark one."""
        parameter = _parameter()
        self.equal(parameter.kind, ValueKind.BOOKMARK)
        self.equal(parameter.name, "bookmark")

    def test_the_codec_round_trips_a_bookmark_through_json_text(self) -> None:
        """Serialising, transporting and decoding returns the same four fields."""
        parameter = _parameter()
        transported: JsonValue = json.loads(json.dumps(_FIRST))
        decoded = decode_argument(parameter, transported)
        if not isinstance(decoded, Bookmark):
            self.fail(f"the codec produced {type(decoded).__name__} instead of a bookmark")
        self.equal(decoded.offset, _FIRST["offset"])
        self.equal(decoded.length, _FIRST["length"])
        self.equal(decoded.label, _FIRST["label"])
        self.equal(decoded.color, _FIRST["color"])
        self.equal(encode_result(decoded), _FIRST)

    def test_the_codec_keeps_bookmarks_that_differ_apart(self) -> None:
        """A single changed field survives the round trip as a difference."""
        parameter = _parameter()
        original = encode_result(decode_argument(parameter, dict(_FIRST)))
        recoloured = encode_result(decode_argument(parameter, dict(_RECOLOURED)))
        self.equal(original, _FIRST)
        self.equal(recoloured, _RECOLOURED)
        self.unequal(original, recoloured)

    def test_the_codec_round_trips_a_bookmark_the_engine_produced(self) -> None:
        """A bookmark read back out of a document decodes into an equal one."""
        parameter = _parameter()
        handle = self.populated(_SECOND)
        encoded = self.one(_FIRST_INDEX, handle)
        decoded = decode_argument(parameter, encoded)
        if not isinstance(decoded, Bookmark):
            self.fail(f"the codec produced {type(decoded).__name__} instead of a bookmark")
        self.equal(encode_result(decoded), encoded)
        self.equal(encode_result(decoded), _SECOND)

    def test_the_codec_rejects_a_bookmark_missing_a_field(self) -> None:
        """An incomplete object is refused, and the message names what is absent."""
        parameter = _parameter()
        complaint = self.refusal(DecodeError, "an incomplete bookmark", lambda: decode_argument(parameter, dict(_MISSING_FIELD)))
        self.contains(_ABSENT_FIELD, complaint, "the refusal names the missing field")

    def test_the_codec_rejects_a_bookmark_that_is_not_an_object(self) -> None:
        """A list cannot stand in for a bookmark, however many fields it has."""
        parameter = _parameter()
        complaint = self.refusal(DecodeError, "a list standing in for a bookmark", lambda: decode_argument(parameter, _positional(_FIRST)))
        self.contains(parameter.name, complaint, "the refusal names the parameter")

    def test_the_optional_bookmark_result_encodes_as_null(self) -> None:
        """``get_bookmark`` may return nothing, and nothing must survive encoding."""
        self.is_none(encode_result(None))
