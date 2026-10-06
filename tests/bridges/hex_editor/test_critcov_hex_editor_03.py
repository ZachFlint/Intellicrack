# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the third slice of ``intellicrack.bridges.hex_editor``.

The slice spans the bit-editing, selection, search, analysis, template, pattern, bookmark, transform and patch-export mixins plus the
bookmark sidecar helpers. Every test drives the real ``HexEditorBridge`` against an in-memory ``intellicrack_hexcore.HexDocument`` or files
under ``tmp_path``. Expectations are derived independently: literal bytes worked out by hand (single-bit masks, XOR and Base64 results),
``struct`` packing for numeric searches, ``zlib.crc32`` plus the BPS/UPS container layout for exported patches, ``math.ldexp`` for a
denormal IEEE-754 double, and plain ``json`` for sidecar contents.
"""

from __future__ import annotations

import base64
import gc
import json
import math
import struct
import zlib
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest

from intellicrack.bridges import hex_editor as hex_editor_module
from intellicrack.bridges.hex_editor import HexEditorBridge, read_bookmark_sidecar, write_bookmark_sidecar
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator
    from pathlib import Path

    from intellicrack.core.types import HexDocumentFull


_NO_DOCUMENT = "no document open"
_TEMPLATE_NAME = "TestStruct"
_TEMPLATE_JSON = json.dumps({
    "name": _TEMPLATE_NAME,
    "description": "Two-field structure for critical coverage",
    "default_endianness": "little",
    "category": "critcov",
    "fields": [
        {"name": "magic", "field_type": {"type": "UInt16"}, "description": "Magic number"},
        {"name": "version", "field_type": {"type": "UInt32"}, "description": "Version number"},
    ],
})
_BASE64_PIPELINE = json.dumps([{"name": "base64_encode", "params": {}}])
_XOR_FF_PIPELINE = json.dumps([{"name": "xor_single", "params": {"key": "ff"}}])

type _Row = tuple[int, int, str, str]


class _EventLog:
    """Observer collecting every event a ``HexDocumentState`` delivers to it."""

    def __init__(self) -> None:
        """Start with an empty event list."""
        self.events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def __call__(self, event: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record one delivered event.

        Args:
            event: Event type delivered by the state holder.
            data: Payload delivered with the event.
        """
        self.events.append((event, data))


def _method(owner: object, name: str) -> Callable[..., object]:
    """Look up an attribute of ``owner`` that must be callable.

    Args:
        owner: Object or class owning the attribute.
        name: Attribute name.

    Returns:
        Callable[..., object]: The bound or static callable.

    Raises:
        TypeError: If the attribute is not callable.
    """
    value: object = getattr(owner, name)
    if not callable(value):
        msg = f"{owner!r}.{name} is not callable"
        raise TypeError(msg)
    return value


def _set_flag(owner: object, name: str, *, value: bool) -> None:
    """Assign a private boolean flag on ``owner``.

    Args:
        owner: Object whose flag is assigned.
        name: Attribute name.
        value: New flag value.
    """
    setattr(owner, name, value)


async def _call_by_name(bridge: HexEditorBridge, name: str, args: tuple[object, ...], kwargs: dict[str, object]) -> object:
    """Await the async bridge method called ``name``.

    Args:
        bridge: Bridge owning the method.
        name: Method name.
        args: Positional arguments.
        kwargs: Keyword arguments.

    Returns:
        object: The coroutine's result.
    """
    return await cast("Awaitable[object]", _method(bridge, name)(*args, **kwargs))


def _open_bytes(bridge: HexEditorBridge, data: bytes) -> intellicrack_hexcore.HexDocument:
    """Attach an in-memory ``HexDocument`` holding ``data`` to ``bridge``.

    Args:
        bridge: Bridge receiving the document.
        data: Document contents.

    Returns:
        intellicrack_hexcore.HexDocument: The attached document.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(data)
    bridge.document = document
    return document


def _adopt_bytes(bridge: HexEditorBridge, data: bytes, path: Path) -> intellicrack_hexcore.HexDocument:
    """Adopt an in-memory ``HexDocument`` into ``bridge`` as if it had been opened from ``path``.

    Args:
        bridge: Bridge receiving the document.
        data: Document contents.
        path: Path recorded as the bridge's target file.

    Returns:
        intellicrack_hexcore.HexDocument: The adopted document.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(data)
    bridge.adopt_document(cast("HexDocumentFull", document), path)
    return document


def _observe(bridge: HexEditorBridge) -> tuple[HexDocumentState, _EventLog]:
    """Attach a fresh state holder with a recording observer to ``bridge``.

    Args:
        bridge: Bridge receiving the state holder.

    Returns:
        tuple[HexDocumentState, _EventLog]: The state holder and the observer log.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    bridge.set_state_holder(holder)
    return holder, log


def _document_bytes(document: intellicrack_hexcore.HexDocument) -> bytes:
    """Read the whole content of ``document``.

    Args:
        document: Document to read.

    Returns:
        bytes: Every byte of the document.
    """
    return bytes(document.read(0, document.length()))


def _sidecar_for(target: Path) -> Path:
    """Compute the bookmark sidecar location documented for ``target``.

    Args:
        target: Binary file the bookmarks belong to.

    Returns:
        Path: ``target`` with ``.icbm.json`` appended to its full name.
    """
    return target.with_name(target.name + ".icbm.json")


def _listing(directory: Path) -> list[Path]:
    """List the entries of a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[Path]: Entries in directory order.
    """
    return list(directory.iterdir())


def _crc_le(data: bytes) -> bytes:
    """Encode the CRC-32 of ``data`` as four little-endian bytes.

    Args:
        data: Bytes to checksum.

    Returns:
        bytes: The little-endian CRC-32.
    """
    return struct.pack("<I", zlib.crc32(data))


@pytest.fixture
def hex_bridge() -> Iterator[HexEditorBridge]:
    """Provide an uninitialized ``HexEditorBridge`` and release any document afterwards.

    Yields:
        HexEditorBridge: A bridge with no document attached.
    """
    bridge = HexEditorBridge()
    try:
        yield bridge
    finally:
        bridge.document = None
        gc.collect()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "args", "kwargs"),
    [
        pytest.param("set_bit", (0, 0), {"value": True}, id="set_bit"),
        pytest.param("search_regex", ("a",), {}, id="search_regex"),
        pytest.param("search_numeric", (1.0,), {}, id="search_numeric"),
        pytest.param("get_entropy_map", (), {}, id="get_entropy_map"),
        pytest.param("get_byte_distribution", (), {}, id="get_byte_distribution"),
        pytest.param("get_byte_type_distribution", (), {}, id="get_byte_type_distribution"),
        pytest.param("get_digram_matrix", (), {}, id="get_digram_matrix"),
        pytest.param("apply_template", ("IMAGE_DOS_HEADER",), {}, id="apply_template"),
        pytest.param("register_template", (_TEMPLATE_JSON,), {}, id="register_template"),
        pytest.param("export_template", ("IMAGE_DOS_HEADER",), {}, id="export_template"),
        pytest.param("add_bookmark", (0,), {}, id="add_bookmark"),
        pytest.param("remove_bookmark", (0,), {}, id="remove_bookmark"),
        pytest.param("export_patches", ("ips",), {}, id="export_patches"),
    ],
)
async def test_operations_refuse_to_run_without_a_document(
    hex_bridge: HexEditorBridge,
    name: str,
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> None:
    """Each operation raises ``RuntimeError`` rather than touching state when no document is open.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the bridge method.
        args: Positional arguments for the method.
        kwargs: Keyword arguments for the method.
    """
    assert hex_bridge.document is None

    with pytest.raises(RuntimeError, match=_NO_DOCUMENT):
        await _call_by_name(hex_bridge, name, args, kwargs)


@pytest.mark.asyncio
async def test_set_bit_sets_and_clears_one_bit_and_notifies_observers(hex_bridge: HexEditorBridge) -> None:
    """Setting then clearing bit 3 of a zero byte yields ``0x08`` then ``0x00`` and announces each change.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x00\x00\x00")
    _, log = _observe(hex_bridge)

    assert await hex_bridge.set_bit(2, 3, value=True) is True
    after_set = _document_bytes(document)
    assert await hex_bridge.set_bit(2, 3, value=False) is True
    after_clear = _document_bytes(document)

    assert after_set == b"\x00\x00\x08"
    assert after_clear == b"\x00\x00\x00"
    modified = (HexDocumentEvent.DATA_MODIFIED, {"offset": 2, "length": 1, "source": "bridge"})
    assert log.events == [modified, modified]


@pytest.mark.asyncio
async def test_toggle_bit_flips_one_bit_reports_the_new_value_and_notifies_observers(hex_bridge: HexEditorBridge) -> None:
    """Toggling bit 0 of ``0x0F`` twice gives ``0x0E`` (bit now clear) then ``0x0F`` (bit set again).

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x0f")
    _, log = _observe(hex_bridge)

    first = await hex_bridge.toggle_bit(0, 0)
    after_first = _document_bytes(document)
    second = await hex_bridge.toggle_bit(0, 0)
    after_second = _document_bytes(document)

    assert (first, after_first) == (False, b"\x0e")
    assert (second, after_second) == (True, b"\x0f")
    modified = (HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 1, "source": "bridge"})
    assert log.events == [modified, modified]


@pytest.mark.asyncio
async def test_select_range_publishes_the_selection_to_the_state_holder(hex_bridge: HexEditorBridge) -> None:
    """Selecting a range stores it on the bridge, on the shared state, and announces it to observers.

    Args:
        hex_bridge: Bridge under test.
    """
    holder, log = _observe(hex_bridge)

    assert await hex_bridge.select_range(5, 9) is True

    assert await hex_bridge.get_selection() == (5, 9)
    assert holder.selection == (5, 9)
    assert log.events == [(HexDocumentEvent.SELECTION_CHANGED, {"start": 5, "end": 9})]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        pytest.param(3, 7, (3, 7), id="both-set"),
        pytest.param(0, 0, (0, 0), id="zero-is-a-valid-offset"),
        pytest.param(-1, -1, None, id="both-cleared"),
        pytest.param(3, -1, None, id="end-cleared"),
        pytest.param(-1, 7, None, id="start-cleared"),
    ],
)
async def test_update_selection_from_gui_stores_a_range_or_clears_it(
    hex_bridge: HexEditorBridge,
    start: int,
    end: int,
    expected: tuple[int, int] | None,
) -> None:
    """A GUI selection with any negative bound clears the stored selection; otherwise it is stored verbatim.

    Args:
        hex_bridge: Bridge under test.
        start: Start offset reported by the GUI.
        end: End offset reported by the GUI.
        expected: Selection the bridge must report afterwards.
    """
    await hex_bridge.select_range(1, 2)

    hex_bridge.update_selection_from_gui(start, end)

    assert await hex_bridge.get_selection() == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data", "value", "size", "endianness", "alignment", "tolerance", "max_results", "offsets"),
    [
        pytest.param(struct.pack("<fff", 1.5, 2.25, 1.5), 1.5, 4, "little", 4, 1e-6, 100, [0, 8], id="float32-little"),
        pytest.param(struct.pack("<fff", 1.5, 2.25, 1.5), 1.5, 4, "little", 4, 1e-6, 1, [0], id="float32-capped"),
        pytest.param(bytes(4) + struct.pack(">f", 1.5), 1.5, 4, "big", 4, 1e-6, 100, [4], id="float32-big"),
        pytest.param(struct.pack(">f", 1.5), 1.5, 4, "little", 4, 1e-6, 100, [], id="float32-big-read-as-little"),
        pytest.param(bytes(8) + struct.pack("<d", 3.25), 3.25, 8, "little", 8, 1e-6, 100, [8], id="float64-little"),
        pytest.param(struct.pack("<f", 1.5004), 1.5, 4, "little", 4, 1e-3, 100, [0], id="within-tolerance"),
        pytest.param(struct.pack("<f", 1.5004), 1.5, 4, "little", 4, 1e-4, 100, [], id="outside-tolerance"),
    ],
)
async def test_search_numeric_float_finds_packed_floats(
    hex_bridge: HexEditorBridge,
    data: bytes,
    value: float,
    size: int,
    endianness: str,
    alignment: int,
    tolerance: float,
    max_results: int,
    offsets: list[int],
) -> None:
    """Float searches match IEEE-754 values packed with ``struct`` honoring size, byte order, alignment, tolerance and cap.

    Args:
        hex_bridge: Bridge under test.
        data: Document contents.
        value: Value searched for.
        size: Byte width of the float (4 or 8).
        endianness: Byte order of the search.
        alignment: Search step in bytes.
        tolerance: Allowed absolute difference.
        max_results: Maximum number of matches.
        offsets: Offsets the search must report.
    """
    _open_bytes(hex_bridge, data)

    matches = await hex_bridge.search_numeric(
        value,
        size=size,
        value_type="float",
        endianness=endianness,
        alignment=alignment,
        max_results=max_results,
        tolerance=tolerance,
    )

    assert matches == [{"offset": offset, "length": size} for offset in offsets]


@pytest.mark.asyncio
@pytest.mark.parametrize("block_size", [0, -4096])
async def test_entropy_map_rejects_a_non_positive_block_size(hex_bridge: HexEditorBridge, block_size: int) -> None:
    """A zero or negative block size is refused with a message naming the offending value.

    Args:
        hex_bridge: Bridge under test.
        block_size: Invalid block size.
    """
    _open_bytes(hex_bridge, b"abcd")

    with pytest.raises(ValueError, match=f"block_size must be positive, got {block_size}"):
        await hex_bridge.get_entropy_map(block_size)


@pytest.mark.asyncio
async def test_digram_matrix_rejects_a_negative_top_k(hex_bridge: HexEditorBridge) -> None:
    """A negative ``top_k`` is refused before any matrix is computed.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"ABAB")

    with pytest.raises(ValueError, match="top_k must be non-negative, got -1"):
        await hex_bridge.get_digram_matrix(top_k=-1)


@pytest.mark.asyncio
async def test_disassemble_reports_a_missing_disassembler_module(hex_bridge: HexEditorBridge, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the disassembler module flagged unavailable, ``disassemble`` raises instead of returning nothing.

    Args:
        hex_bridge: Bridge under test.
        monkeypatch: Restores the module availability flag afterwards.
    """
    _open_bytes(hex_bridge, b"\x90\x90\x90\x90")
    monkeypatch.setattr(hex_editor_module, "_disasm_available", False)

    with pytest.raises(RuntimeError, match="disassembler module not available"):
        await hex_bridge.disassemble(0, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [4, 100], ids=["at-end", "past-end"])
async def test_disassemble_returns_nothing_at_or_beyond_the_document_end(hex_bridge: HexEditorBridge, offset: int) -> None:
    """Disassembling from an offset with no bytes left yields an empty listing.

    Args:
        hex_bridge: Bridge under test.
        offset: Offset at or beyond the end of the four-byte document.
    """
    _open_bytes(hex_bridge, b"\x90\x90\x90\x90")

    assert await hex_bridge.disassemble(offset, 5) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
async def test_base_convert_rejects_a_blank_value(blank: str) -> None:
    """A value that is empty after stripping is refused with a clear message.

    Args:
        blank: Empty or whitespace-only input.
    """
    with pytest.raises(ValueError, match="value must not be empty"):
        await HexEditorBridge.base_convert(blank)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "0x100000000",
            {
                "decimal": "4294967296",
                "hex": "0x100000000",
                "octal": "0o40000000000",
                "binary": "0b1" + "0" * 32,
                "uint64_le": "4294967296",
                "int64_le": "4294967296",
                "float64_le": str(math.ldexp(1.0, -1042)),
            },
            id="above-32-bits",
        ),
        pytest.param(
            "0x10000000000000000",
            {
                "decimal": "18446744073709551616",
                "hex": "0x10000000000000000",
                "octal": "0o2" + "0" * 21,
                "binary": "0b1" + "0" * 64,
            },
            id="above-64-bits",
        ),
        pytest.param(
            "-5",
            {"decimal": "-5", "hex": "-0x5", "octal": "-0o5", "binary": "-0b101"},
            id="negative",
        ),
    ],
)
async def test_base_convert_omits_fixed_width_views_a_value_does_not_fit(text: str, expected: dict[str, str]) -> None:
    """Values beyond a width (or negative) get no unsigned, signed or float view of that width.

    Args:
        text: Value passed to the converter.
        expected: Exact set of representations expected.
    """
    assert await HexEditorBridge.base_convert(text) == expected


@pytest.mark.asyncio
async def test_template_listings_are_empty_when_the_hexcore_flag_is_cleared(hex_bridge: HexEditorBridge) -> None:
    """Without a document and without the hexcore backend both template listings return the empty sentinel.

    Args:
        hex_bridge: Bridge under test.
    """
    _set_flag(hex_bridge, "_hexcore_available", value=False)

    assert await hex_bridge.list_templates() == []
    assert await hex_bridge.list_templates_detailed() == []


@pytest.mark.asyncio
async def test_template_listings_without_a_document_come_from_a_throwaway_document(hex_bridge: HexEditorBridge) -> None:
    """With no document open the listings mirror a freshly constructed backend document's registry.

    Args:
        hex_bridge: Bridge under test.
    """
    reference = intellicrack_hexcore.HexDocument()

    simple = await hex_bridge.list_templates()
    detailed = await hex_bridge.list_templates_detailed()

    assert simple == [{"name": name, "description": description} for name, description in reference.list_templates()]
    assert detailed == [
        {"name": name, "description": description, "category": category, "field_count": count}
        for name, description, category, count in reference.list_templates_detailed()
    ]
    assert "IMAGE_DOS_HEADER" in {entry["name"] for entry in simple}
    assert hex_bridge.document is None


@pytest.mark.asyncio
async def test_registered_template_is_listed_and_applied_without_a_state_holder(hex_bridge: HexEditorBridge) -> None:
    """A JSON template registered through the bridge parses a packed record into named fields at their offsets.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, struct.pack("<HI", 0xABCD, 0x12345678))

    name = await hex_bridge.register_template(_TEMPLATE_JSON)
    fields = await hex_bridge.apply_template(_TEMPLATE_NAME)

    assert name == _TEMPLATE_NAME
    assert _TEMPLATE_NAME in {entry[0] for entry in document.list_templates()}
    assert [(f["name"], f["offset"], f["size"]) for f in fields] == [("magic", 0, 2), ("version", 2, 4)]


@pytest.mark.asyncio
async def test_remove_template_without_a_document_reports_false(hex_bridge: HexEditorBridge) -> None:
    """Removing a template with no document open is a quiet no-op returning ``False``.

    Args:
        hex_bridge: Bridge under test.
    """
    assert await hex_bridge.remove_template("IMAGE_DOS_HEADER") is False


@pytest.mark.asyncio
async def test_remove_template_reports_whether_a_template_was_removed(hex_bridge: HexEditorBridge) -> None:
    """Removing an unknown template returns ``False``; removing a registered one returns ``True`` and drops it.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x00" * 8)
    await hex_bridge.register_template(_TEMPLATE_JSON)

    unknown = await hex_bridge.remove_template("__NoSuchTemplate__")
    present_before = _TEMPLATE_NAME in {entry[0] for entry in document.list_templates()}
    removed = await hex_bridge.remove_template(_TEMPLATE_NAME)
    present_after = _TEMPLATE_NAME in {entry[0] for entry in document.list_templates()}

    assert unknown is False
    assert (present_before, removed, present_after) == (True, True, False)


@pytest.mark.asyncio
async def test_export_template_returns_the_registered_definition_as_json(hex_bridge: HexEditorBridge) -> None:
    """An exported template carries the name, category, byte order and field list it was registered with.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"\x00" * 8)
    await hex_bridge.register_template(_TEMPLATE_JSON)

    parsed = cast("dict[str, Any]", json.loads(await hex_bridge.export_template(_TEMPLATE_NAME)))

    assert parsed["name"] == _TEMPLATE_NAME
    assert parsed["category"] == "critcov"
    assert parsed["default_endianness"] == "little"
    assert [field["name"] for field in parsed["fields"]] == ["magic", "version"]


@pytest.mark.asyncio
async def test_generate_structure_bookmarks_ignores_a_document_shorter_than_a_header(hex_bridge: HexEditorBridge) -> None:
    """A two-byte document starting with ``MZ`` is too short to inspect, so no bookmark is created.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"MZ")

    assert await hex_bridge.generate_structure_bookmarks() == []
    assert document.list_bookmarks() == []


@pytest.mark.asyncio
async def test_compile_pattern_reports_a_missing_compiler(hex_bridge: HexEditorBridge) -> None:
    """With the HexPat compiler flagged unavailable, compilation raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    _set_flag(hex_bridge, "_hexpat_available", value=False)

    with pytest.raises(RuntimeError, match="hexpat_compiler not available"):
        await hex_bridge.compile_pattern("struct Header { u8 tag; };")


@pytest.mark.asyncio
async def test_execute_pattern_file_announces_the_file_stem_and_field_count(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Running a pattern file notifies observers with the file's stem and the number of fields produced.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    _open_bytes(hex_bridge, b"\x01\x02\x03\x04")
    _, log = _observe(hex_bridge)
    pattern = tmp_path / "fields.hexpat"
    pattern.write_text("u8 first @ 0x00; u8 second @ 0x01;", encoding="utf-8")

    fields = await hex_bridge.execute_pattern_file(str(pattern))

    assert {"first", "second"} <= {field["name"] for field in fields}
    assert log.events == [(HexDocumentEvent.PATTERN_EXECUTED, {"pattern_name": "fields", "field_count": len(fields)})]


def test_read_bookmark_sidecar_returns_nothing_for_invalid_json(tmp_path: Path) -> None:
    """A sidecar that is not JSON is treated as empty rather than raising.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "sample.bin"
    _sidecar_for(target).write_text("{not json", encoding="utf-8")

    assert read_bookmark_sidecar(target) == []


def test_read_bookmark_sidecar_returns_nothing_when_the_json_is_not_a_list(tmp_path: Path) -> None:
    """A sidecar whose top-level JSON value is an object is rejected as a whole.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "sample.bin"
    _sidecar_for(target).write_text('{"offset": 1, "length": 1, "label": "x", "color": "#000"}', encoding="utf-8")

    assert read_bookmark_sidecar(target) == []


def test_read_bookmark_sidecar_keeps_only_well_formed_entries(tmp_path: Path) -> None:
    """Non-object, incomplete and non-numeric entries are skipped while valid ones are kept and normalized.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "sample.bin"
    payload: list[object] = [
        5,
        {"offset": "16", "length": 2, "label": "kept", "color": "#fff"},
        {"offset": 1},
        {"offset": "zz", "length": 1, "label": "bad", "color": "#000"},
        {"offset": None, "length": 1, "label": "none", "color": "#000"},
        {"offset": 32, "length": 4, "label": "also kept", "color": "#abc"},
    ]
    _sidecar_for(target).write_text(json.dumps(payload), encoding="utf-8")

    assert read_bookmark_sidecar(target) == [
        {"offset": 16, "length": 2, "label": "kept", "color": "#fff"},
        {"offset": 32, "length": 4, "label": "also kept", "color": "#abc"},
    ]


def test_write_bookmark_sidecar_tolerates_an_unwritable_location(tmp_path: Path) -> None:
    """Writing a sidecar next to a target in a missing directory is swallowed and creates nothing.

    Args:
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "no_such_directory" / "sample.bin"

    write_bookmark_sidecar(target, [{"offset": 0, "length": 1, "label": "x", "color": "#000"}])

    assert _listing(tmp_path) == []


@pytest.mark.asyncio
async def test_list_bookmarks_is_empty_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """Listing bookmarks with no document open returns an empty list instead of raising.

    Args:
        hex_bridge: Bridge under test.
    """
    assert await hex_bridge.list_bookmarks() == []


@pytest.mark.asyncio
async def test_remove_bookmark_rewrites_the_sidecar_without_the_removed_entry(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Removing a bookmark deletes it from the document and rewrites the target's sidecar with what remains.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "target.bin"
    document = _adopt_bytes(hex_bridge, b"\x00" * 8, target)
    await hex_bridge.add_bookmark(0, 2, "first", "#111111")
    await hex_bridge.add_bookmark(4, 1, "second", "#222222")
    sidecar = _sidecar_for(target)
    before = cast("list[dict[str, Any]]", json.loads(sidecar.read_text(encoding="utf-8")))

    removed = await hex_bridge.remove_bookmark(0)

    rows: list[_Row] = document.list_bookmarks()
    after = cast("list[dict[str, Any]]", json.loads(sidecar.read_text(encoding="utf-8")))
    assert [entry["label"] for entry in before] == ["first", "second"]
    assert removed is True
    assert rows == [(4, 1, "second", "#222222")]
    assert after == [{"offset": 4, "length": 1, "label": "second", "color": "#222222"}]


@pytest.mark.asyncio
async def test_remove_bookmark_with_an_unknown_index_leaves_the_sidecar_alone(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A removal that matches no bookmark returns ``False`` and does not rewrite the sidecar.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    target = tmp_path / "target.bin"
    document = _adopt_bytes(hex_bridge, b"\x00" * 8, target)
    await hex_bridge.add_bookmark(0, 2, "only", "#111111")
    sidecar = _sidecar_for(target)
    sidecar.write_text("sentinel", encoding="utf-8")

    removed = await hex_bridge.remove_bookmark(99)

    rows: list[_Row] = document.list_bookmarks()
    assert removed is False
    assert rows == [(0, 2, "only", "#111111")]
    assert sidecar.read_text(encoding="utf-8") == "sentinel"


@pytest.mark.asyncio
async def test_remove_bookmark_without_a_target_path_writes_no_sidecar(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Removing a bookmark from a document with no backing file succeeds without creating any sidecar.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    document = _open_bytes(hex_bridge, b"\x00" * 8)
    await hex_bridge.add_bookmark(0, 2, "memory", "#111111")

    removed = await hex_bridge.remove_bookmark(0)

    rows: list[_Row] = document.list_bookmarks()
    assert removed is True
    assert rows == []
    assert _listing(tmp_path) == []


@pytest.mark.asyncio
async def test_apply_transform_accepts_non_string_parameters(hex_bridge: HexEditorBridge) -> None:
    """A list-valued parameter is forwarded untouched while a hex string is decoded, and the result is written in place.

    ``xor_rolling`` starts its key at ``0x10`` and adds the increment ``3`` per byte, so three zero bytes become
    ``10 13 16``.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x00\x00\x00\x00")

    result = await hex_bridge.apply_transform("xor_rolling", 0, 3, json.dumps({"key": "10", "increment": [3]}))

    assert result == "101316"
    assert _document_bytes(document) == b"\x10\x13\x16\x00"


@pytest.mark.asyncio
async def test_apply_transform_leaves_the_document_untouched_for_a_non_hex_string_parameter(hex_bridge: HexEditorBridge) -> None:
    """A parameter that is not valid hex is passed on as text, the backend refuses it, and nothing is written.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"abcd")

    with pytest.raises((TypeError, ValueError)):
        await hex_bridge.apply_transform("xor_single", 0, 4, json.dumps({"key": "zz"}))

    assert _document_bytes(document) == b"abcd"


@pytest.mark.asyncio
async def test_apply_transform_refuses_an_in_place_result_of_a_different_length(hex_bridge: HexEditorBridge) -> None:
    """Base64 turns three bytes into four, which cannot replace a three-byte range; read-only mode still returns it.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"abcdef")

    with pytest.raises(ValueError, match="produced 4 bytes for a 3-byte range"):
        await hex_bridge.apply_transform("base64_encode", 0, 3)
    preview = await hex_bridge.apply_transform("base64_encode", 0, 3, in_place=False)

    assert _document_bytes(document) == b"abcdef"
    assert preview == b"YWJj".hex()


@pytest.mark.asyncio
async def test_apply_pipeline_refuses_an_in_place_result_of_a_different_length(hex_bridge: HexEditorBridge) -> None:
    """A Base64 pipeline over three bytes yields four and is refused in place without touching the document.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"abcdef")

    with pytest.raises(ValueError, match="pipeline produced 4 bytes for a 3-byte range"):
        await hex_bridge.apply_pipeline(_BASE64_PIPELINE, 0, 3)

    assert _document_bytes(document) == b"abcdef"


@pytest.mark.asyncio
async def test_apply_pipeline_writes_the_result_in_place_and_notifies_observers(hex_bridge: HexEditorBridge) -> None:
    """XOR-ing bytes ``01 02 03`` with ``ff`` writes ``fe fd fc`` at the offset and announces the modified range.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x00\x01\x02\x03\x04")
    _, log = _observe(hex_bridge)

    result = await hex_bridge.apply_pipeline(_XOR_FF_PIPELINE, 1, 3)

    assert result == "fefdfc"
    assert _document_bytes(document) == b"\x00\xfe\xfd\xfc\x04"
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 1, "length": 3, "source": "bridge"})]


@pytest.mark.asyncio
async def test_list_transforms_is_empty_when_the_pipeline_flag_is_cleared(hex_bridge: HexEditorBridge) -> None:
    """The transform catalogue is returned while the pipeline is available and is empty once it is flagged unavailable.

    Args:
        hex_bridge: Bridge under test.
    """
    available = await hex_bridge.list_transforms()
    _set_flag(hex_bridge, "_pipeline_available", value=False)
    unavailable = await hex_bridge.list_transforms()

    assert "xor_single" in {entry["name"] for entry in available}
    assert unavailable == []


@pytest.mark.asyncio
async def test_export_patches_rejects_an_unknown_format(hex_bridge: HexEditorBridge) -> None:
    """A format outside ``ips``, ``ips32``, ``bps`` and ``ups`` raises ``ToolError`` naming it.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"\x00" * 4)

    with pytest.raises(ToolError, match=r"unsupported patch format.*'zip'"):
        await hex_bridge.export_patches("zip")


@pytest.mark.asyncio
@pytest.mark.parametrize("patch_format", ["bps", "ups"])
async def test_export_patches_requires_an_original_path_for_diff_formats(hex_bridge: HexEditorBridge, patch_format: str) -> None:
    """BPS and UPS patches are diffs against a source file, so omitting the original path raises ``ToolError``.

    Args:
        hex_bridge: Bridge under test.
        patch_format: Diff-based patch format.
    """
    _open_bytes(hex_bridge, b"\x00" * 4)

    with pytest.raises(ToolError, match="requires original_path"):
        await hex_bridge.export_patches(patch_format)


@pytest.mark.asyncio
async def test_export_patches_dispatches_bps_to_the_bps_encoder(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A ``BPS`` export carries the BPS magic, both sizes, and checksums of the source, target and patch itself.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    source = b"ABCDEFGH"
    target = b"ABCDXFGH"
    original = tmp_path / "original.bin"
    original.write_bytes(source)
    _open_bytes(hex_bridge, target)

    patch = base64.b64decode(await hex_bridge.export_patches("BPS", original_path=str(original)))

    assert patch[:7] == b"BPS1\x88\x88\x80"
    assert patch[-12:-8] == _crc_le(source)
    assert patch[-8:-4] == _crc_le(target)
    assert patch[-4:] == _crc_le(patch[:-4])


@pytest.mark.asyncio
async def test_export_patches_dispatches_ups_to_the_ups_encoder(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A ``ups`` export is the UPS magic, both sizes, one XOR record for the changed byte and three checksums.

    The sizes ``8`` encode as ``0x88``; the single difference sits at relative offset ``4`` (``0x84``) and ``0x45 ^ 0x58`` is ``0x1D``,
    followed by the record terminator ``0x00``.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    source = b"ABCDEFGH"
    target = b"ABCDXFGH"
    original = tmp_path / "original.bin"
    original.write_bytes(source)
    _open_bytes(hex_bridge, target)

    patch = base64.b64decode(await hex_bridge.export_patches("ups", original_path=str(original)))

    assert patch[:-12] == b"UPS1\x88\x88\x84\x1d\x00"
    assert patch[-12:-8] == _crc_le(source)
    assert patch[-8:-4] == _crc_le(target)
    assert patch[-4:] == _crc_le(patch[:-4])
