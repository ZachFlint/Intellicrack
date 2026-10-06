# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the patch, VA, export, PE and scan slice of ``intellicrack.bridges.hex_editor``.

Every test drives the real ``HexEditorBridge`` against a real in-memory or on-disk
``intellicrack_hexcore.HexDocument``. Patch files are encoded by hand from the IPS, BPS and
UPS format definitions (big-endian IPS records, the BPS/UPS variable-length integer, CRC-32
footers computed with ``zlib``), YARA rules are matched against bytes whose match offsets
are known by construction, and process memory is read back from a ``ctypes`` buffer whose
address and contents the test owns.
"""

from __future__ import annotations

import base64
import ctypes
import gc
import json
import os
import struct
import zlib
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest

from intellicrack.bridges import hex_editor as hex_editor_module
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterator
    from pathlib import Path


_SOURCE = b"0123456789ABCDEF"
_TARGET = b"0123456789abcdEF"
_GROWN_TARGET = b"0123456789-grown-tail"
_NEEDLE = b"NEEDLE"
_YARA_RULE = 'rule HasNeedle : alpha { meta: author = "critcov" strings: $a = "NEEDLE" condition: $a }'
_PROCESS_MARKER = b"critcov-process-memory-0123456789"
_OBSERVER_ID = "critcov-observer"

type _PatchBuilder = Callable[[bytes, bytes], bytes]


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


@contextmanager
def _module_flag(name: str, *, value: bool) -> Generator[None]:
    """Hold a module-level availability flag of the hex editor module at ``value``.

    Args:
        name: Name of the boolean flag inside ``intellicrack.bridges.hex_editor``.
        value: Value the flag holds while the context is active.

    Yields:
        None: Control while the flag holds ``value``; the original value is restored afterwards.
    """
    original: object = getattr(hex_editor_module, name)
    setattr(hex_editor_module, name, value)
    try:
        yield
    finally:
        setattr(hex_editor_module, name, original)


def _method(owner: object, name: str) -> Callable[..., object]:
    """Look up an attribute of ``owner`` that must be callable.

    Args:
        owner: Object owning the attribute.
        name: Attribute name.

    Returns:
        Callable[..., object]: The bound callable.

    Raises:
        TypeError: If the attribute is not callable.
    """
    value: object = getattr(owner, name)
    if not callable(value):
        msg = f"{owner!r}.{name} is not callable"
        raise TypeError(msg)
    return value


async def _call_async(owner: object, name: str, *args: object) -> object:
    """Await the coroutine returned by an async bridge method looked up by name.

    Args:
        owner: Object owning the method.
        name: Method name.
        *args: Positional arguments for the method.

    Returns:
        object: The coroutine's result.
    """
    return await cast("Awaitable[object]", _method(owner, name)(*args))


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


def _doc_bytes(document: intellicrack_hexcore.HexDocument) -> bytes:
    """Read the whole content of ``document``.

    Args:
        document: Document to read.

    Returns:
        bytes: Every byte of the document.
    """
    return bytes(document.read(0, document.length()))


def _observe(bridge: HexEditorBridge) -> _EventLog:
    """Attach a fresh state holder with a recording observer to ``bridge``.

    Args:
        bridge: Bridge that receives the state holder.

    Returns:
        _EventLog: Observer recording every event the bridge announces.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id=_OBSERVER_ID)
    bridge.set_state_holder(holder)
    return log


def _b64(raw: bytes) -> str:
    """Base64-encode ``raw`` the way the bridge expects patch payloads.

    Args:
        raw: Bytes to encode.

    Returns:
        str: ASCII base64 text.
    """
    return base64.b64encode(raw).decode("ascii")


def _crc(data: bytes) -> int:
    """Compute the CRC-32 of ``data`` as an unsigned 32-bit integer.

    Args:
        data: Bytes to checksum.

    Returns:
        int: The CRC-32 value.
    """
    return zlib.crc32(data) & 0xFFFFFFFF


def _varint(value: int) -> bytes:
    """Encode ``value`` as the BPS/UPS variable-length integer.

    Seven payload bits per byte, least significant group first; the final byte has bit 7
    set, and every non-final group subtracts one so each value has a single encoding.

    Args:
        value: Non-negative integer.

    Returns:
        bytes: The encoded integer.
    """
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(0x80 | low)
            return bytes(out)
        out.append(low)
        value -= 1


def _seal(body: bytes, source: bytes, target: bytes) -> bytes:
    """Append the shared BPS/UPS footer: source CRC, target CRC and patch CRC, all little-endian.

    Args:
        body: Patch bytes preceding the footer.
        source: Source file the patch applies to.
        target: Target file the patch produces.

    Returns:
        bytes: The complete patch.
    """
    with_crcs = body + struct.pack("<II", _crc(source), _crc(target))
    return with_crcs + struct.pack("<I", _crc(with_crcs))


def _build_bps(source: bytes, target: bytes) -> bytes:
    """Encode a BPS patch from ``source`` to ``target`` with SourceRead and TargetRead actions.

    Args:
        source: Source file contents.
        target: Target file contents.

    Returns:
        bytes: The BPS patch.
    """
    common = 0
    while common < min(len(source), len(target)) and source[common] == target[common]:
        common += 1
    body = bytearray(b"BPS1") + _varint(len(source)) + _varint(len(target)) + _varint(0)
    if common:
        body += _varint(((common - 1) << 2) | 0)
    rest = target[common:]
    if rest:
        body += _varint(((len(rest) - 1) << 2) | 1) + rest
    return _seal(bytes(body), source, target)


def _build_ups(source: bytes, target: bytes) -> bytes:
    """Encode a UPS patch from ``source`` to ``target`` as zero-terminated XOR hunks.

    Args:
        source: Source file contents.
        target: Target file contents.

    Returns:
        bytes: The UPS patch.
    """
    size = max(len(source), len(target))
    xor = bytes(a ^ b for a, b in zip(source.ljust(size, b"\x00"), target.ljust(size, b"\x00"), strict=True))
    body = bytearray(b"UPS1") + _varint(len(source)) + _varint(len(target))
    resume = 0
    index = 0
    while index < size:
        if xor[index] == 0:
            index += 1
            continue
        end = index
        while end < size and xor[end] != 0:
            end += 1
        body += _varint(index - resume) + xor[index:end] + b"\x00"
        resume = end + 1
        index = end + 1
    return _seal(bytes(body), source, target)


def _ips_record(offset: int, payload: bytes) -> bytes:
    """Encode one standard IPS record: 24-bit offset, 16-bit size, payload.

    Args:
        offset: Target offset.
        payload: Replacement bytes.

    Returns:
        bytes: The encoded record.
    """
    return offset.to_bytes(3, "big") + len(payload).to_bytes(2, "big") + payload


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
async def test_import_patches_requires_an_open_document(hex_bridge: HexEditorBridge) -> None:
    """A patch cannot be imported while no document is open.

    Args:
        hex_bridge: Bridge under test.
    """
    payload = _b64(b"PATCH" + _ips_record(0, b"\x01") + b"EOF")

    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.import_patches(payload)


@pytest.mark.asyncio
async def test_import_patches_rejects_a_payload_shorter_than_a_magic(hex_bridge: HexEditorBridge) -> None:
    """A three-byte payload is rejected before any format is chosen and the document is untouched.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _SOURCE)

    with pytest.raises(ToolError, match="unrecognized patch magic: payload shorter than 4 bytes"):
        await hex_bridge.import_patches(_b64(b"PAT"))

    assert _doc_bytes(document) == _SOURCE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "head_hex"),
    [
        pytest.param(b"PATC", "50415443", id="four-byte-near-miss"),
        pytest.param(b"XXXXXXXX", "5858585858", id="ascii-garbage"),
        pytest.param(b"\x00\x01\x02\x03\x04\x05", "0001020304", id="binary-garbage"),
    ],
)
async def test_import_patches_reports_the_leading_bytes_of_an_unknown_format(
    hex_bridge: HexEditorBridge,
    raw: bytes,
    head_hex: str,
) -> None:
    """An unrecognized payload is rejected with its first five bytes (or fewer) in hex.

    Args:
        hex_bridge: Bridge under test.
        raw: Decoded patch payload.
        head_hex: Expected hex rendering of the first five bytes of ``raw``.
    """
    document = _open_bytes(hex_bridge, _SOURCE)

    with pytest.raises(ToolError, match=f"unrecognized patch magic: 0x{head_hex}$"):
        await hex_bridge.import_patches(_b64(raw))

    assert _doc_bytes(document) == _SOURCE


@pytest.mark.asyncio
async def test_import_patches_applies_ips_records_and_announces_the_change(hex_bridge: HexEditorBridge) -> None:
    """Two IPS records overwrite their offsets and observers hear about the whole document being modified.

    Args:
        hex_bridge: Bridge under test.
    """
    log = _observe(hex_bridge)
    document = _open_bytes(hex_bridge, bytes(16))
    patch = b"PATCH" + _ips_record(2, b"\xaa\xbb") + _ips_record(10, b"\xcc") + b"EOF"
    expected = bytearray(16)
    expected[2:4] = b"\xaa\xbb"
    expected[10] = 0xCC

    count = await hex_bridge.import_patches(_b64(patch))

    assert count == 2
    assert _doc_bytes(document) == bytes(expected)
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": 16, "source": "bridge"})]


@pytest.mark.asyncio
async def test_import_patches_applies_bps_against_the_original_file_and_announces_the_change(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
) -> None:
    """A BPS payload is reconstructed from the original file, not from the (different) document contents.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(_SOURCE)
    log = _observe(hex_bridge)
    document = _open_bytes(hex_bridge, b"\xff" * len(_SOURCE))

    count = await hex_bridge.import_patches(_b64(_build_bps(_SOURCE, _TARGET)), str(original))

    assert count == 1
    assert _doc_bytes(document) == _TARGET
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": len(_TARGET), "source": "bridge"})]


@pytest.mark.asyncio
async def test_import_patches_applies_ups_using_the_document_as_the_source(hex_bridge: HexEditorBridge) -> None:
    """Without an original path a UPS payload is applied to the current document contents.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _SOURCE)

    count = await hex_bridge.import_patches(_b64(_build_ups(_SOURCE, _TARGET)))

    assert count == 1
    assert _doc_bytes(document) == _TARGET


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("builder", "expected"),
    [
        pytest.param(_build_bps, "invalid BPS patch: source CRC mismatch", id="bps"),
        pytest.param(_build_ups, "invalid UPS patch: source CRC mismatch", id="ups"),
    ],
)
async def test_import_patches_rejects_a_patch_built_for_a_different_source(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
    builder: _PatchBuilder,
    expected: str,
) -> None:
    """A BPS or UPS patch whose source checksum does not match the supplied original is refused.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        builder: Encoder producing the patch for ``_SOURCE`` to ``_TARGET``.
        expected: Message the resulting ``ToolError`` must carry.
    """
    wrong_original = tmp_path / "wrong.bin"
    wrong_original.write_bytes(b"X" * len(_SOURCE))
    document = _open_bytes(hex_bridge, b"\xff" * len(_SOURCE))

    with pytest.raises(ToolError, match=expected):
        await hex_bridge.import_patches(_b64(builder(_SOURCE, _TARGET)), str(wrong_original))

    assert _doc_bytes(document) == b"\xff" * len(_SOURCE)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["import_patches_bps", "import_patches_ups"])
async def test_explicit_patch_import_requires_an_open_document(hex_bridge: HexEditorBridge, name: str) -> None:
    """The format-specific import methods refuse to run without a document.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the import method.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await _call_async(hex_bridge, name, _b64(b"BPS1"), "unused.bin")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "builder"),
    [
        pytest.param("import_patches_bps", _build_bps, id="bps"),
        pytest.param("import_patches_ups", _build_ups, id="ups"),
    ],
)
async def test_explicit_patch_import_replaces_the_document_and_announces_the_new_size(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
    name: str,
    builder: _PatchBuilder,
) -> None:
    """A patch that grows the file replaces the document and observers hear the new length.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
        name: Name of the import method.
        builder: Encoder producing the patch for ``_SOURCE`` to ``_GROWN_TARGET``.
    """
    original = tmp_path / "original.bin"
    original.write_bytes(_SOURCE)
    log = _observe(hex_bridge)
    document = _open_bytes(hex_bridge, bytes(4))

    result = await _call_async(hex_bridge, name, _b64(builder(_SOURCE, _GROWN_TARGET)), str(original))

    assert result == {"target_size": len(_GROWN_TARGET)}
    assert _doc_bytes(document) == _GROWN_TARGET
    assert log.events == [(HexDocumentEvent.DATA_MODIFIED, {"offset": 0, "length": len(_GROWN_TARGET), "source": "bridge"})]


@pytest.mark.asyncio
async def test_open_process_memory_reports_an_unavailable_backend_and_keeps_the_document(hex_bridge: HexEditorBridge) -> None:
    """With the native module flagged unavailable the call fails and the open document is left alone.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _SOURCE)

    with _module_flag("_hexcore_available", value=False), pytest.raises(RuntimeError, match="hexcore native module not available"):
        await hex_bridge.open_process_memory(os.getpid(), 0x1000, 16)

    assert hex_bridge.document is document
    assert _doc_bytes(document) == _SOURCE


@pytest.mark.asyncio
async def test_open_process_memory_publishes_the_region_to_the_state_holder(hex_bridge: HexEditorBridge) -> None:
    """Opening a region with no prior document reads the owned buffer and announces the new document.

    Args:
        hex_bridge: Bridge under test.
    """
    log = _observe(hex_bridge)
    buffer = ctypes.create_string_buffer(_PROCESS_MARKER)
    address = ctypes.addressof(buffer)
    pid = os.getpid()

    result = await hex_bridge.open_process_memory(pid, address, len(_PROCESS_MARKER))

    assert result == {"pid": pid, "address": address, "size": len(_PROCESS_MARKER), "document_length": len(_PROCESS_MARKER)}
    assert hex_bridge.document is not None
    assert bytes(hex_bridge.document.read(0, len(_PROCESS_MARKER))) == _PROCESS_MARKER
    assert log.events == [(HexDocumentEvent.DOCUMENT_OPENED, {"file_path": None, "size": len(_PROCESS_MARKER)})]


@pytest.mark.asyncio
async def test_open_process_memory_closes_the_previous_document_first(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Switching from a file to a process region announces the close, then the open, and clears file state.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "previous.bin"
    backing.write_bytes(_SOURCE)
    await hex_bridge.open_file(str(backing))
    hex_bridge.update_cursor_from_gui(5)
    await hex_bridge.select_range(1, 4)
    log = _observe(hex_bridge)
    buffer = ctypes.create_string_buffer(_PROCESS_MARKER)
    pid = os.getpid()

    await hex_bridge.open_process_memory(pid, ctypes.addressof(buffer), len(_PROCESS_MARKER))

    assert hex_bridge.document is not None
    assert bytes(hex_bridge.document.read(0, len(_PROCESS_MARKER))) == _PROCESS_MARKER
    assert hex_bridge.state.target_path is None
    assert hex_bridge.state.binary_loaded is True
    assert hex_bridge.state.process_attached is True
    assert hex_bridge.state.target_pid == pid
    assert await hex_bridge.get_cursor_position() == 0
    assert await hex_bridge.get_selection() is None
    assert log.events == [
        (HexDocumentEvent.DOCUMENT_CLOSED, {}),
        (HexDocumentEvent.DOCUMENT_OPENED, {"file_path": None, "size": len(_PROCESS_MARKER)}),
    ]


@pytest.mark.asyncio
async def test_open_process_memory_replaces_the_previous_document_without_a_state_holder(
    hex_bridge: HexEditorBridge,
    tmp_path: Path,
) -> None:
    """Without a state holder the previous document is still dropped and the file path forgotten.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "previous.bin"
    backing.write_bytes(_SOURCE)
    await hex_bridge.open_file(str(backing))
    buffer = ctypes.create_string_buffer(_PROCESS_MARKER)

    await hex_bridge.open_process_memory(os.getpid(), ctypes.addressof(buffer), len(_PROCESS_MARKER))

    assert hex_bridge.state.target_path is None
    assert hex_bridge.document is not None
    assert hex_bridge.document.length() == len(_PROCESS_MARKER)
    assert bytes(hex_bridge.document.read(0, len(_PROCESS_MARKER))) == _PROCESS_MARKER


@pytest.mark.asyncio
async def test_set_va_base_announces_the_running_mapping_count(hex_bridge: HexEditorBridge) -> None:
    """Each added mapping is stored in file-offset order and observers hear the new total.

    Args:
        hex_bridge: Bridge under test.
    """
    log = _observe(hex_bridge)
    document = _open_bytes(hex_bridge, bytes(0x100))

    assert await hex_bridge.set_va_base(0x40, 0x401000, 0x10) is True
    assert await hex_bridge.set_va_base(0x10, 0x400000, 0x20) is True

    assert document.list_va_mappings() == [(0x10, 0x400000, 0x20), (0x40, 0x401000, 0x10)]
    assert log.events == [
        (HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 1}),
        (HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 2}),
    ]


@pytest.mark.asyncio
async def test_remove_va_mapping_requires_an_open_document(hex_bridge: HexEditorBridge) -> None:
    """Removing a mapping without a document is an error.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.remove_va_mapping(0)


@pytest.mark.asyncio
async def test_remove_va_mapping_drops_the_entry_and_announces_only_real_removals(hex_bridge: HexEditorBridge) -> None:
    """Removing index 0 deletes the lowest mapping and announces the remaining count; a bad index changes nothing.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, bytes(0x100))
    document.add_va_mapping(0x10, 0x400000, 0x20)
    document.add_va_mapping(0x40, 0x401000, 0x10)
    log = _observe(hex_bridge)

    removed = await hex_bridge.remove_va_mapping(0)
    missing = await hex_bridge.remove_va_mapping(5)

    assert removed is True
    assert missing is False
    assert document.list_va_mappings() == [(0x40, 0x401000, 0x10)]
    assert log.events == [(HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 1})]


@pytest.mark.asyncio
async def test_auto_detect_va_mappings_is_empty_for_a_document_shorter_than_a_magic(hex_bridge: HexEditorBridge) -> None:
    """A three-byte document cannot hold a four-byte magic, so nothing is detected even with an MZ prefix.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"MZ\x00")

    assert await hex_bridge.auto_detect_va_mappings() == []


@pytest.mark.asyncio
async def test_offset_translation_is_none_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """Both address translations answer ``None`` when no document is open.

    Args:
        hex_bridge: Bridge under test.
    """
    assert await hex_bridge.file_offset_to_va(0x10) is None
    assert await hex_bridge.va_to_file_offset(0x400000) is None


@pytest.mark.asyncio
async def test_annotated_html_lists_each_bookmark_label_once(hex_bridge: HexEditorBridge) -> None:
    """Two bookmarks sharing a label produce a single legend entry for the first one.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, bytes(range(16)))
    document.add_bookmark(0, 2, "dup", "#FF0000")
    document.add_bookmark(8, 2, "dup", "#00FF00")
    document.add_bookmark(4, 2, "other", "#0000FF")

    html_text = await hex_bridge.export_annotated_html()

    assert html_text.count("<span class='legend-item'") == 2
    assert "dup (0x0)</span>" in html_text
    assert "other (0x4)</span>" in html_text
    assert "(0x8)" not in html_text


@pytest.mark.asyncio
async def test_memory_usage_is_all_zero_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """With no document the usage report is three zeros instead of an error.

    Args:
        hex_bridge: Bridge under test.
    """
    assert await hex_bridge.get_memory_usage() == {"usage_bytes": 0, "chunk_size": 0, "memory_budget": 0}


@pytest.mark.asyncio
@pytest.mark.parametrize("budget", [0, -5])
async def test_set_memory_budget_rejects_a_non_positive_budget(hex_bridge: HexEditorBridge, budget: int) -> None:
    """A zero or negative budget is a value error even though no document is open.

    Args:
        hex_bridge: Bridge under test.
        budget: Rejected budget in bytes.
    """
    with pytest.raises(ValueError, match="memory budget must be a positive integer"):
        await hex_bridge.set_memory_budget(budget)


@pytest.mark.asyncio
async def test_set_memory_budget_requires_an_open_document(hex_bridge: HexEditorBridge) -> None:
    """A valid budget still needs a document to apply to.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.set_memory_budget(1 << 20)


@pytest.mark.asyncio
async def test_pe_sections_are_empty_when_the_coff_header_is_truncated(hex_bridge: HexEditorBridge) -> None:
    """A PE whose COFF header is cut short yields an empty section list instead of an error.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytearray(0x4E)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    _open_bytes(hex_bridge, bytes(data))

    assert await hex_bridge.get_pe_sections() == []


@pytest.mark.asyncio
async def test_pe_imports_and_exports_are_empty_while_pefile_is_unavailable(hex_bridge: HexEditorBridge, real_pe_dll: Path) -> None:
    """With ``pefile`` flagged unavailable both listings are empty, and they return rows once it is available again.

    Args:
        hex_bridge: Bridge under test.
        real_pe_dll: Path to a real System32 DLL that has imports and exports.
    """
    hex_bridge.document = intellicrack_hexcore.HexDocument.open(str(real_pe_dll))

    with _module_flag("_pefile_available", value=False):
        assert await hex_bridge.get_pe_imports() == []
        assert await hex_bridge.get_pe_exports() == []

    assert await hex_bridge.get_pe_imports()
    assert await hex_bridge.get_pe_exports()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "argument"),
    [
        pytest.param("yara_scan", "rule Anything { condition: true }", id="yara_scan"),
        pytest.param("yara_scan_files", "unused.yar", id="yara_scan_files"),
    ],
)
async def test_yara_scans_report_a_missing_scanner_module(hex_bridge: HexEditorBridge, name: str, argument: str) -> None:
    """With the YARA scanner flagged unavailable both scan entry points raise a clear error.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the scan method.
        argument: Rule source or rule path handed to it.
    """
    _open_bytes(hex_bridge, b"xx" + _NEEDLE)

    with _module_flag("_yara_bridge_available", value=False), pytest.raises(RuntimeError, match="yara_scanner module not available"):
        await _call_async(hex_bridge, name, argument)


@pytest.mark.asyncio
async def test_yara_scan_files_requires_an_open_document(hex_bridge: HexEditorBridge) -> None:
    """Scanning with rule files needs a document.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await hex_bridge.yara_scan_files("unused.yar")


@pytest.mark.asyncio
async def test_yara_scan_reads_the_document_when_it_has_no_file_on_disk(hex_bridge: HexEditorBridge) -> None:
    """An in-memory document is scanned from its bytes and every occurrence is reported with its offset.

    Args:
        hex_bridge: Bridge under test.
    """
    data = b"xx" + _NEEDLE + b"xx " + _NEEDLE
    _open_bytes(hex_bridge, data)

    matches = await hex_bridge.yara_scan(_YARA_RULE)

    assert matches == [
        {
            "rule": "HasNeedle",
            "tags": ["alpha"],
            "meta": {"author": "critcov"},
            "namespace": "default",
            "strings": [
                {"identifier": "$a", "offset": data.index(_NEEDLE), "data": _NEEDLE.hex()},
                {"identifier": "$a", "offset": data.rindex(_NEEDLE), "data": _NEEDLE.hex()},
            ],
        },
    ]


@pytest.mark.asyncio
async def test_yara_scan_files_reads_the_document_when_it_has_no_file_on_disk(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Rules loaded from a file are matched against the in-memory document bytes.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    rules = tmp_path / "critcov_rules.yar"
    rules.write_text('rule FileRule { strings: $s = "NEEDLE" condition: $s }', encoding="utf-8")
    data = b"abc" + _NEEDLE + b"def"
    _open_bytes(hex_bridge, data)

    matches = await hex_bridge.yara_scan_files(str(rules))

    assert matches == [
        {
            "rule": "FileRule",
            "tags": [],
            "meta": {},
            "namespace": "critcov_rules",
            "strings": [{"identifier": "$s", "offset": data.index(_NEEDLE), "data": _NEEDLE.hex()}],
        },
    ]


@pytest.mark.asyncio
async def test_die_scan_rejects_a_database_that_is_not_valid_json(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A signature file that is not JSON is reported as a value error naming the file.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    database = tmp_path / "broken.json"
    database.write_text("{not json", encoding="utf-8")
    _open_bytes(hex_bridge, _SOURCE)

    with pytest.raises(ValueError, match="is not valid JSON"):
        await hex_bridge.scan_die_signatures(str(database))


@pytest.mark.asyncio
async def test_die_scan_rejects_an_entry_that_is_not_an_object(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """The first non-object entry aborts the scan with its index and JSON type.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    database = tmp_path / "entries.json"
    database.write_text(json.dumps([{"name": "fine", "patterns": []}, 7]), encoding="utf-8")
    _open_bytes(hex_bridge, _SOURCE)

    with pytest.raises(TypeError, match=r"entry #1 is not a JSON object \(got int\)"):
        await hex_bridge.scan_die_signatures(str(database))


@pytest.mark.asyncio
async def test_die_scan_skips_entries_whose_patterns_are_not_a_list(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Entries with a number or null as ``patterns`` are skipped while a later valid entry still matches.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    database = tmp_path / "patterns.json"
    entries = [
        {"name": "numeric", "type": "packer", "version": "1", "patterns": 5},
        {"name": "null", "type": "packer", "version": "1", "patterns": None},
        {"name": "keep", "type": "packer", "version": "2", "patterns": [{"pattern": "4D 5A", "offset": "any"}]},
    ]
    database.write_text(json.dumps(entries), encoding="utf-8")
    _open_bytes(hex_bridge, b"\x00MZ\x00")

    results = await hex_bridge.scan_die_signatures(str(database))

    assert results == [{"name": "keep", "type": "packer", "version": "2", "offset": 1, "details": "Full scan match at 0x1"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["scan_clamav_signatures", "scan_custom_signatures"])
async def test_signature_scans_require_an_open_document(hex_bridge: HexEditorBridge, name: str) -> None:
    """The ClamAV and custom signature scans refuse to run without a document.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the scan method.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        await _call_async(hex_bridge, name, "unused.db")


@pytest.mark.asyncio
async def test_custom_signature_scan_skips_bad_hex_and_bad_offsets(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Entries with a non-hex pattern or a non-numeric offset are ignored; valid ones report their offsets.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    signatures = tmp_path / "signatures.json"
    entries = [
        {"name": "bad-hex", "pattern": "ZZ", "type": "t"},
        {"name": "bad-offset", "pattern": "41", "offset": "nonsense", "type": "t"},
        {"name": "hit-any", "pattern": "43 44", "type": "marker"},
        {"name": "hit-fixed", "pattern": "45 46", "offset": "0x4", "type": "marker"},
    ]
    signatures.write_text(json.dumps(entries), encoding="utf-8")
    _open_bytes(hex_bridge, b"ABCDEFGH")

    results = await hex_bridge.scan_custom_signatures(str(signatures))

    assert results == [
        {"name": "hit-any", "type": "marker", "version": "", "offset": 2, "details": "Full scan match at 0x2"},
        {"name": "hit-fixed", "type": "marker", "version": "", "offset": 4, "details": "Fixed offset match at 0x4"},
    ]
