# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The patch ledger, the export formats, and the three importers.

Four behaviours are pinned here because a client that assumed otherwise would be
wrong in a way nothing else would catch.

The ledger is unmerged. ``get_patches`` reports one entry per write, so two
writes to the same offset produce two entries that overlap, while
``export_patches_json`` reports the settled result and produces one. The patches
panel prints a warning about that overlap; these tests are what keeps the
warning truthful.

BPS and UPS have two exporters each, one taking the source bytes and one taking
a path to them, and the pair must not disagree. They are also the two importers
that replace the entire document: after either one the undo stack is gone, the
backing path is forgotten, and the registry's generation counter has advanced,
which is the signal the browser uses to throw away every cached window it holds.
The IPS importer does none of that, and the contrast is asserted rather than
assumed.

Finally, an export larger than the codec's inline cap must still be recoverable.
The JSON route truncates the payload -- deliberately, because a multi-megabyte
patch has no business being pasted into a result panel -- and marks it
``truncated``. The ``?raw=1`` sidecar serves the whole thing. If the two ever
came back the same size, a client would have quietly saved a truncated patch
file and called it a patch.

The IPS importer is exercised with :data:`hexbench.tests._recipes.IPS_PATCH`,
which is built byte by byte from the published format rather than by asking the
engine to export one, so the importer is shown to read something it did not
write.

Assertions are made through the ``require_*`` functions in
:mod:`hexbench.tests._support`, which raise :class:`AssertionError` directly;
that module documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ._recipes import IPS_PATCH, IPS_PAYLOAD, IPS_TARGET_OFFSET
from ._support import (
    HexbenchTestCase,
    SupportError,
    decode_tagged_bytes,
    json_object,
    require_absent,
    require_equal,
    require_false,
    require_greater,
    require_member,
    require_prefix,
    require_raises,
    require_true,
    require_unequal,
)


if TYPE_CHECKING:
    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult


_BASE_DATA: Final[bytes] = bytes(range(256)) * 8
"""The document every patch in this module is computed against."""

_FIRST_OFFSET: Final = 0x40
"""Offset written to twice, to produce an overlapping pair in the ledger."""

_FIRST_WRITE: Final[bytes] = b"\xaa\xbb"
"""The earlier of the two writes to :data:`_FIRST_OFFSET`."""

_SECOND_WRITE: Final[bytes] = b"\xcc\xdd"
"""The later of the two writes to :data:`_FIRST_OFFSET`, which settles the bytes."""

_THIRD_OFFSET: Final = 0x100
"""Offset written to once, so the ledger holds a non-overlapping entry too."""

_THIRD_WRITE: Final[bytes] = b"\x11\x22\x33\x44"
"""The write at :data:`_THIRD_OFFSET`."""

_LEDGER_ENTRIES: Final = 3
"""Entries the unmerged ledger must hold after the three writes above."""

_SETTLED_REGIONS: Final = 2
"""Distinct regions the merged JSON export must describe after the same writes."""

_EXPORT_FORMATS: Final[tuple[str, ...]] = (
    "export_patches_ips",
    "export_patches_ips32",
    "export_patches_cod",
    "export_patches_json",
)
"""The four exports that need neither the source bytes nor a path to them."""

_BINARY_EXPORTS: Final[tuple[str, ...]] = ("export_patches_ips", "export_patches_ips32", "export_patches_cod")
"""The self-contained exports whose payload is bytes rather than text."""

_HEADERED_EXPORTS: Final[tuple[str, ...]] = ("export_patches_ips", "export_patches_ips32")
"""The binary exports whose format has a magic prefix, so an empty patch is still bytes."""

_HEADERLESS_EXPORT: Final = "export_patches_cod"
"""The binary export that is nothing but records, so an empty patch is no bytes at all."""

_TEXT_EXPORT: Final = "export_patches_json"
"""The self-contained export whose payload is text."""

_EMPTY_JSON_PATCH: Final = "[]"
"""What the JSON export renders when there is nothing to record."""

_OFFSET_MEMBER: Final = '"offset"'
"""Member naming a region's offset in the JSON export, once per settled region."""

_EMPTY_PAYLOAD: Final[bytes] = b""
"""What an export must not produce when there is something to record."""

_SINGLE_MENTION: Final = 1
"""How often the settled bytes appear in a merged export."""

_NO_MENTION: Final = 0
"""How often the superseded bytes appear in a merged export."""

_SOURCE_NAME: Final = "patch-source.bin"
"""Leaf name of the staged copy of :data:`_BASE_DATA`."""

_BACKING_NAME: Final = "patch-target.bin"
"""Leaf name of the file a document is opened over for the history tests."""

_LARGE_LENGTH: Final = 1 << 14
"""Length of the document used to force an export past the codec's inline cap."""

_LARGE_RUN: Final[bytes] = b"\xff" * (1 << 13)
"""A single long write, so one export easily exceeds anything held inline."""

_OCTET_TYPE: Final = "application/octet-stream"
"""Content type the raw sidecar must answer with."""

_STATUS_OK: Final = 200
"""Status both routes answer a legitimate export with."""

_RAW_QUERY: Final[dict[str, str]] = {"raw": "1"}
"""Query that asks the operation route for the untruncated payload."""

_TRUNCATED_KEY: Final = "truncated"
"""Tagged-bytes member saying the inline payload is incomplete."""

_LENGTH_KEY: Final = "length"
"""Tagged-bytes member carrying the payload's true length."""

_VALUE_KEY: Final = "value"
"""Invocation result member carrying the JSON rendering of the return value."""

_RAW_LENGTH_KEY: Final = "raw_length"
"""Invocation result member carrying the size of the out-of-band payload."""

_RAW_AVAILABLE_KEY: Final = "raw_available"
"""Invocation result member saying an out-of-band payload exists."""

_GENERATION_KEY: Final = "generation"
"""Document member advanced by every mutating operation."""

_CAN_UNDO_KEY: Final = "can_undo"
"""Document member saying the undo stack holds at least one entry."""

_PATH_KEY: Final = "path"
"""Document member naming the file a document is backed by."""

_PAIR_LENGTH: Final = 2
"""Number of members in a ledger entry: its offset and its bytes."""


def _raw_of(result: InvocationResult) -> bytes:
    """Read the untruncated binary payload an invocation carried out of band.

    Args:
        result: The invocation result to read.

    Returns:
        bytes: The complete payload the engine returned.

    Raises:
        SupportError: If the operation returned no binary payload at all.
    """
    raw = result.raw
    if raw is None:
        message = f"{result.operation} returned no untruncated payload"
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


def _payload_of(result: InvocationResult) -> bytes:
    """Read an export's payload whether the format is binary or textual.

    Args:
        result: The invocation result to read.

    Returns:
        bytes: The exported patch as bytes.
    """
    if result.raw is None:
        return _text_of(result).encode()
    return _raw_of(result)


def _object_member(payload: dict[str, JsonValue], key: str) -> dict[str, JsonValue]:
    """Read one member of a JSON object, insisting it is itself an object.

    Args:
        payload: Object to read from.
        key: Member to read.

    Returns:
        dict[str, JsonValue]: The member.

    Raises:
        SupportError: If the member is missing or is not an object.
    """
    value = payload.get(key)
    if not isinstance(value, dict):
        message = f"member {key!r} carried {type(value).__name__} where an object was expected"
        raise SupportError(message)
    return value


def _int_member(payload: dict[str, JsonValue], key: str) -> int:
    """Read one member of a JSON object, insisting it is an integer.

    Args:
        payload: Object to read from.
        key: Member to read.

    Returns:
        int: The member.

    Raises:
        SupportError: If the member is missing or is not an integer.
    """
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        message = f"member {key!r} carried {type(value).__name__} where an integer was expected"
        raise SupportError(message)
    return value


def _ledger_of(result: InvocationResult) -> list[tuple[int, bytes]]:
    """Read ``get_patches`` as a list of offset and payload pairs.

    Args:
        result: The invocation result to read.

    Returns:
        list[tuple[int, bytes]]: The ledger, in the order the engine gave it.

    Raises:
        SupportError: If the result is not a list of offset and byte-string pairs.
    """
    value = result.value
    if not isinstance(value, list):
        message = f"get_patches returned {type(value).__name__} where a list was expected"
        raise SupportError(message)
    entries: list[tuple[int, bytes]] = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != _PAIR_LENGTH:
            message = f"get_patches returned {entry!r} where an offset and payload pair was expected"
            raise SupportError(message)
        offset, payload = entry
        if not isinstance(offset, int):
            message = f"get_patches returned a non-integer offset: {offset!r}"
            raise SupportError(message)
        entries.append((offset, decode_tagged_bytes(payload)))
    return entries


def _patched(base: bytes, offset: int, payload: bytes) -> bytes:
    """Apply one overwrite to a byte string, without changing its length.

    Args:
        base: Bytes to patch.
        offset: First byte to overwrite.
        payload: Replacement bytes.

    Returns:
        bytes: The patched copy.
    """
    return base[:offset] + payload + base[offset + len(payload) :]


def _settled_bytes() -> bytes:
    """Describe what :meth:`_PatchCase.edited_document` must contain when it is done.

    Returns:
        bytes: The base document with the later write winning at each offset.
    """
    return _patched(_patched(_BASE_DATA, _FIRST_OFFSET, _SECOND_WRITE), _THIRD_OFFSET, _THIRD_WRITE)


class _PatchCase(HexbenchTestCase):
    """Shared reading and editing helpers for the tests in this module."""

    def read_all(self, handle: str) -> bytes:
        """Read a whole document through the dispatcher.

        Args:
            handle: Document to read.

        Returns:
            bytes: Every byte the document holds.
        """
        length = self.session.registry.slot(handle).info().length
        return _raw_of(self.session.call("read", {"offset": 0, "length": length}, handle=handle))

    def write(self, handle: str, offset: int, payload: bytes) -> None:
        """Overwrite bytes in a document.

        Args:
            handle: Document to edit.
            offset: First byte to overwrite.
            payload: Replacement bytes.
        """
        self.session.call("write_bytes", {"offset": offset, "data": payload.hex()}, handle=handle)

    def edited_document(self) -> str:
        """Open :data:`_BASE_DATA` and apply the three writes the ledger tests use.

        Returns:
            str: Handle of the edited document.
        """
        handle = self.session.open_bytes(_BASE_DATA).handle
        self.write(handle, _FIRST_OFFSET, _FIRST_WRITE)
        self.write(handle, _FIRST_OFFSET, _SECOND_WRITE)
        self.write(handle, _THIRD_OFFSET, _THIRD_WRITE)
        return handle

    def document_json(self, handle: str) -> dict[str, JsonValue]:
        """Read one document's state over the HTTP surface.

        Args:
            handle: Document to describe.

        Returns:
            dict[str, JsonValue]: The document description the API renders.
        """
        return json_object(self.session.get(f"/api/documents/{handle}"))

    def staged_source(self) -> str:
        """Write :data:`_BASE_DATA` into the scratch directory.

        Returns:
            str: Absolute path of the staged file.
        """
        path = self.session.path(_SOURCE_NAME)
        path.write_bytes(_BASE_DATA)
        return str(path)


class PatchLedger(_PatchCase):
    """``get_patches`` records writes, it does not reconcile them."""

    def test_two_writes_to_one_offset_stay_two_entries(self) -> None:
        """Overlapping writes are both reported, in the order they were made."""
        handle = self.edited_document()
        ledger = _ledger_of(self.session.call("get_patches", {}, handle=handle))

        require_equal(len(ledger), _LEDGER_ENTRIES, "entries in the unmerged ledger")
        require_equal(ledger[0], (_FIRST_OFFSET, _FIRST_WRITE), "first ledger entry")
        require_equal(ledger[1], (_FIRST_OFFSET, _SECOND_WRITE), "second ledger entry, at the same offset")
        require_equal(ledger[2], (_THIRD_OFFSET, _THIRD_WRITE), "third ledger entry")

    def test_the_overlapping_entries_do_not_describe_the_document(self) -> None:
        """Replaying the ledger blindly would write bytes the document does not hold."""
        handle = self.edited_document()
        ledger = _ledger_of(self.session.call("get_patches", {}, handle=handle))
        superseded = ledger[0][1]
        contents = self.read_all(handle)

        require_equal(contents, _settled_bytes(), "document after the three writes")
        settled = contents[_FIRST_OFFSET : _FIRST_OFFSET + len(_FIRST_WRITE)]
        require_unequal(settled, superseded, "bytes at the twice-written offset")

    def test_the_json_export_merges_what_the_ledger_leaves_apart(self) -> None:
        """The settled export describes two regions where the ledger holds three entries."""
        handle = self.edited_document()
        exported = _text_of(self.session.call("export_patches_json", {}, handle=handle))

        require_equal(exported.count(_SECOND_WRITE.hex()), _SINGLE_MENTION, "mentions of the settled bytes")
        require_equal(exported.count(_FIRST_WRITE.hex()), _NO_MENTION, "mentions of the superseded bytes")
        require_equal(exported.count(_OFFSET_MEMBER), _SETTLED_REGIONS, "regions in the merged export")
        require_member(f"{_OFFSET_MEMBER}: {_FIRST_OFFSET}", exported, "the twice-written offset in the merged export")
        require_member(f"{_OFFSET_MEMBER}: {_THIRD_OFFSET}", exported, "the once-written offset in the merged export")

    def test_an_unedited_document_has_an_empty_ledger(self) -> None:
        """A document nobody has written to records no patches at all."""
        handle = self.session.open_bytes(_BASE_DATA).handle
        require_equal(_ledger_of(self.session.call("get_patches", {}, handle=handle)), [], "ledger of an unedited document")


class ExportFormats(_PatchCase):
    """Every export produces a payload, and every payload carries the settled edits."""

    def test_all_four_self_contained_exports_are_non_empty(self) -> None:
        """IPS, IPS32, COD and JSON all render the edits without a source image."""
        handle = self.edited_document()
        for name in _EXPORT_FORMATS:
            payload = _payload_of(self.session.call(name, {}, handle=handle))
            require_unequal(payload, _EMPTY_PAYLOAD, f"payload produced by {name}")

    def test_the_binary_exports_contain_the_settled_bytes(self) -> None:
        """The payload of each binary format holds the bytes that actually won."""
        handle = self.edited_document()
        for name in _BINARY_EXPORTS:
            payload = _raw_of(self.session.call(name, {}, handle=handle))
            require_member(_SECOND_WRITE, payload, f"settled bytes inside the {name} payload")
            require_member(_THIRD_WRITE, payload, f"second region inside the {name} payload")

    def test_the_text_export_spells_the_settled_bytes_as_hexadecimal(self) -> None:
        """The JSON format carries the same edits, written out rather than embedded."""
        handle = self.edited_document()
        exported = _text_of(self.session.call(_TEXT_EXPORT, {}, handle=handle))
        require_member(_SECOND_WRITE.hex(), exported, "settled bytes inside the JSON export")
        require_member(_THIRD_WRITE.hex(), exported, "second region inside the JSON export")

    def test_a_headerless_export_of_an_unedited_document_is_empty(self) -> None:
        """COD is a bare record list, so no edits means no bytes; the others keep a header."""
        handle = self.session.open_bytes(_BASE_DATA).handle
        headerless = _raw_of(self.session.call(_HEADERLESS_EXPORT, {}, handle=handle))
        require_equal(headerless, _EMPTY_PAYLOAD, "COD export of an unedited document")
        for name in _HEADERED_EXPORTS:
            payload = _raw_of(self.session.call(name, {}, handle=handle))
            require_unequal(payload, _EMPTY_PAYLOAD, f"header kept by {name} for an unedited document")
        rendered = _text_of(self.session.call(_TEXT_EXPORT, {}, handle=handle))
        require_equal(rendered, _EMPTY_JSON_PATCH, "JSON export of an unedited document")


class IpsImport(_PatchCase):
    """A patch built to the published format, not by the engine, still applies."""

    def test_hand_built_patch_reproduces_its_target(self) -> None:
        """Importing the patch turns the base document into exactly the target."""
        handle = self.session.open_bytes(_BASE_DATA).handle
        expected = _patched(_BASE_DATA, IPS_TARGET_OFFSET, IPS_PAYLOAD)
        require_unequal(expected, _BASE_DATA, "target the hand-built patch describes")

        self.session.call("import_patches_ips", {"data": IPS_PATCH.hex()}, handle=handle)

        contents = self.read_all(handle)
        require_equal(contents, expected, "document after importing the hand-built patch")
        landed = contents[IPS_TARGET_OFFSET : IPS_TARGET_OFFSET + len(IPS_PAYLOAD)]
        require_equal(landed, IPS_PAYLOAD, "bytes the hand-built patch wrote")

    def test_import_leaves_the_document_the_same_length(self) -> None:
        """An IPS record that overwrites must not grow or shrink the document."""
        handle = self.session.open_bytes(_BASE_DATA).handle
        self.session.call("import_patches_ips", {"data": IPS_PATCH.hex()}, handle=handle)
        require_equal(len(self.read_all(handle)), len(_BASE_DATA), "length after an overwriting import")


class BpsRoundTrip(_PatchCase):
    """BPS exports agree with each other and reimport into the document they describe."""

    def test_both_exporters_produce_the_same_patch(self) -> None:
        """Handing over the source bytes and naming a file holding them agree."""
        handle = self.edited_document()
        from_data = _raw_of(self.session.call("export_patches_bps", {"source_data": _BASE_DATA.hex()}, handle=handle))
        from_path = _raw_of(self.session.call("export_patches_bps_from_path", {"source_path": self.staged_source()}, handle=handle))

        require_unequal(from_data, _EMPTY_PAYLOAD, "BPS patch exported from the source bytes")
        require_equal(from_path, from_data, "BPS patch exported from a source path")

    def test_the_patch_reimports_into_a_fresh_document(self) -> None:
        """A fresh copy of the base becomes the edited document, byte for byte."""
        donor = self.edited_document()
        patch = _raw_of(self.session.call("export_patches_bps", {"source_data": _BASE_DATA.hex()}, handle=donor))

        fresh = self.session.open_bytes(_BASE_DATA).handle
        self.session.call("import_patches_bps", {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}, handle=fresh)
        require_equal(self.read_all(fresh), _settled_bytes(), "document rebuilt from a BPS patch")

    def test_a_patch_refuses_a_source_it_was_not_built_from(self) -> None:
        """The checksum in the patch is checked, so the wrong source is rejected."""
        donor = self.edited_document()
        patch = _raw_of(self.session.call("export_patches_bps", {"source_data": _BASE_DATA.hex()}, handle=donor))

        fresh = self.session.open_bytes(_BASE_DATA).handle
        arguments = {"patch_data": patch.hex(), "source_data": bytes(len(_BASE_DATA)).hex()}
        require_raises(
            ValueError,
            "BPS import against the wrong source",
            lambda: self.session.call("import_patches_bps", arguments, handle=fresh),
        )


class UpsRoundTrip(_PatchCase):
    """UPS exports agree with each other and reimport into the document they describe."""

    def test_both_exporters_produce_the_same_patch(self) -> None:
        """Handing over the source bytes and naming a file holding them agree."""
        handle = self.edited_document()
        from_data = _raw_of(self.session.call("export_patches_ups", {"source_data": _BASE_DATA.hex()}, handle=handle))
        from_path = _raw_of(self.session.call("export_patches_ups_from_path", {"source_path": self.staged_source()}, handle=handle))

        require_unequal(from_data, _EMPTY_PAYLOAD, "UPS patch exported from the source bytes")
        require_equal(from_path, from_data, "UPS patch exported from a source path")

    def test_the_patch_reimports_into_a_fresh_document(self) -> None:
        """A fresh copy of the base becomes the edited document, byte for byte."""
        donor = self.edited_document()
        patch = _raw_of(self.session.call("export_patches_ups", {"source_data": _BASE_DATA.hex()}, handle=donor))

        fresh = self.session.open_bytes(_BASE_DATA).handle
        self.session.call("import_patches_ups", {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}, handle=fresh)
        require_equal(self.read_all(fresh), _settled_bytes(), "document rebuilt from a UPS patch")

    def test_the_two_formats_are_not_interchangeable(self) -> None:
        """A UPS patch is not a BPS patch, and the importer says so rather than guessing."""
        donor = self.edited_document()
        patch = _raw_of(self.session.call("export_patches_ups", {"source_data": _BASE_DATA.hex()}, handle=donor))

        fresh = self.session.open_bytes(_BASE_DATA).handle
        arguments = {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}
        require_raises(
            ValueError,
            "BPS import of a UPS patch",
            lambda: self.session.call("import_patches_bps", arguments, handle=fresh),
        )


class ImportResetsHistory(_PatchCase):
    """Importing BPS or UPS replaces the document, so everything about it changes."""

    def backed_document(self) -> str:
        """Open a document over a real file and make one edit to it.

        Returns:
            str: Handle of the edited, file-backed document.
        """
        path = self.session.path(_BACKING_NAME)
        path.write_bytes(_BASE_DATA)
        handle = self.session.open_path(path).handle
        self.write(handle, _FIRST_OFFSET, _FIRST_WRITE)
        return handle

    def donor_patch(self, exporter: str) -> bytes:
        """Build a patch describing the settled edits, from a separate document.

        Args:
            exporter: Name of the export operation to use.

        Returns:
            bytes: The exported patch.
        """
        donor = self.edited_document()
        return _raw_of(self.session.call(exporter, {"source_data": _BASE_DATA.hex()}, handle=donor))

    def test_bps_import_clears_undo_forgets_the_path_and_moves_the_generation(self) -> None:
        """Every cached window a client holds is invalidated, and undo cannot cross the import."""
        handle = self.backed_document()
        patch = self.donor_patch("export_patches_bps")

        before = self.document_json(handle)
        require_true(before[_CAN_UNDO_KEY], "can_undo before the import")
        require_equal(before[_PATH_KEY], str(self.session.path(_BACKING_NAME)), "path before the import")
        earlier = _int_member(before, _GENERATION_KEY)

        self.session.call("import_patches_bps", {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}, handle=handle)

        after = self.document_json(handle)
        require_false(after[_CAN_UNDO_KEY], "can_undo after the import")
        require_absent(after[_PATH_KEY], "path after the import")
        require_greater(_int_member(after, _GENERATION_KEY), earlier, "generation after the import")

    def test_bps_import_discards_the_edit_it_replaced(self) -> None:
        """The document afterwards is the patch's target, not the target plus prior edits."""
        handle = self.backed_document()
        patch = self.donor_patch("export_patches_bps")
        self.session.call("import_patches_bps", {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}, handle=handle)
        require_equal(self.read_all(handle), _settled_bytes(), "document after a replacing import")

    def test_ups_import_clears_undo_and_forgets_the_path_too(self) -> None:
        """The UPS importer replaces the document on the same terms as the BPS one."""
        handle = self.backed_document()
        patch = self.donor_patch("export_patches_ups")

        before = self.document_json(handle)
        require_true(before[_CAN_UNDO_KEY], "can_undo before the import")
        earlier = _int_member(before, _GENERATION_KEY)

        self.session.call("import_patches_ups", {"patch_data": patch.hex(), "source_data": _BASE_DATA.hex()}, handle=handle)

        after = self.document_json(handle)
        require_false(after[_CAN_UNDO_KEY], "can_undo after the import")
        require_absent(after[_PATH_KEY], "path after the import")
        require_greater(_int_member(after, _GENERATION_KEY), earlier, "generation after the import")

    def test_ips_import_does_not_reset_history(self) -> None:
        """The IPS importer edits in place, so undo still reaches back past it."""
        handle = self.backed_document()
        self.session.call("import_patches_ips", {"data": IPS_PATCH.hex()}, handle=handle)

        after = self.document_json(handle)
        require_true(after[_CAN_UNDO_KEY], "can_undo after an IPS import")
        require_equal(after[_PATH_KEY], str(self.session.path(_BACKING_NAME)), "path after an IPS import")


class RawExportSidecar(_PatchCase):
    """A patch too large to render inline is still downloadable in full."""

    def large_export_document(self) -> str:
        """Open a document and make one edit big enough to overflow the inline cap.

        Returns:
            str: Handle of the edited document.
        """
        handle = self.session.open_bytes(bytes(_LARGE_LENGTH)).handle
        self.write(handle, 0, _LARGE_RUN)
        return handle

    def test_the_raw_route_returns_more_bytes_than_the_json_route(self) -> None:
        """The sidecar is the whole patch; the inline copy is a marked-up prefix of it."""
        handle = self.large_export_document()

        rendered = json_object(self.session.post_operation("export_patches_ips", {}, handle=handle))
        tagged = _object_member(rendered, _VALUE_KEY)
        inline = decode_tagged_bytes(tagged)

        sidecar = self.session.post_operation("export_patches_ips", {}, handle=handle, query=_RAW_QUERY)
        require_equal(sidecar.status, _STATUS_OK, "status of the raw sidecar")
        require_equal(sidecar.content_type, _OCTET_TYPE, "content type of the raw sidecar")

        require_true(tagged[_TRUNCATED_KEY], "truncation flag on the inline payload")
        require_greater(len(sidecar.body), len(inline), "bytes served by the raw sidecar")
        require_equal(len(sidecar.body), _int_member(tagged, _LENGTH_KEY), "length the inline payload advertises")
        require_equal(len(sidecar.body), _int_member(rendered, _RAW_LENGTH_KEY), "length the result advertises")
        require_true(rendered[_RAW_AVAILABLE_KEY], "raw availability flag on the result")

    def test_the_inline_copy_is_a_prefix_of_the_full_patch(self) -> None:
        """Truncation takes bytes off the end, so a saved sidecar is not a different patch."""
        handle = self.large_export_document()

        rendered = json_object(self.session.post_operation("export_patches_ips", {}, handle=handle))
        inline = decode_tagged_bytes(_object_member(rendered, _VALUE_KEY))
        sidecar = self.session.post_operation("export_patches_ips", {}, handle=handle, query=_RAW_QUERY)

        require_prefix(sidecar.body, inline, "the inline payload against the full patch")
        direct = _raw_of(self.session.call("export_patches_ips", {}, handle=handle))
        require_equal(sidecar.body, direct, "sidecar bytes against the dispatcher's own payload")

    def test_the_full_patch_still_reimports(self) -> None:
        """The sidecar bytes are a working patch, not merely a longer blob."""
        handle = self.large_export_document()
        sidecar = self.session.post_operation("export_patches_ips", {}, handle=handle, query=_RAW_QUERY)

        fresh = self.session.open_bytes(bytes(_LARGE_LENGTH)).handle
        self.session.call("import_patches_ips", {"data": sidecar.body.hex()}, handle=fresh)
        rebuilt = self.read_all(fresh)
        require_equal(rebuilt, self.read_all(handle), "document rebuilt from the sidecar patch")
        require_equal(rebuilt[: len(_LARGE_RUN)], _LARGE_RUN, "the long run inside the rebuilt document")
