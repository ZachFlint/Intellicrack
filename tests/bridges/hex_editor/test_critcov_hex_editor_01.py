# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the first slice of ``intellicrack.bridges.hex_editor``.

Every test builds its input byte by byte from the relevant format definition (IPS and
IPS32 records, PE, ELF and Mach-O headers, UTF-16LE text) under ``tmp_path`` or in an
in-memory ``intellicrack_hexcore.HexDocument`` and drives the real ``HexEditorBridge``.
Expectations are derived independently: literal values worked out from the format
specifications, a reference implementation of the Windows checksum, regular expressions
for printable runs, ``collections.Counter`` for digram counts, and the third-party
``pefile`` parser as a checksum oracle for a real System32 DLL.
"""

from __future__ import annotations

import gc
import re
import shutil
import struct
from collections import Counter
from itertools import pairwise
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

import intellicrack_hexcore
import pefile
import pytest

from intellicrack.bridges import hex_editor as hex_editor_module
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.color_defaults import PE_STRUCTURE_COLORS, STRUCTURE_COLORS, STRUCTURE_HEADER_COLOR
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator


_DIGRAM_TABLE_SIZE = 65536
_NEVER_OFFSET = 10**9
_PE_LFANEW = 0x80
_PE_OPT_OFFSET = _PE_LFANEW + 4 + 20
_MACHO_LE32 = b"\xce\xfa\xed\xfe"
_MACHO_LE64 = b"\xcf\xfa\xed\xfe"
_MACHO_FAT = b"\xca\xfe\xba\xbe"
_LC_SEGMENT = 0x01
_LC_UUID = 0x1B
_UTF16 = "utf-16le"

type _Row = tuple[int, int, str, str]


class _ProgressLike(Protocol):
    """Structural view of the bridge's private sandbox progress tracker."""

    instance_id: str
    copy_succeeded: bool


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


class _SyncSandboxBridge(HexEditorBridge):
    """Bridge subclass whose sandbox ``create`` and ``copy_to`` hooks are plain synchronous callables.

    ``copy_to`` performs a genuine file copy so a test can assert that the instance
    identifier returned by ``create`` reached the copy step and that the bytes arrived.
    """

    def create(self, *, sandbox_type: str) -> dict[str, Any]:
        """Return a provisioned-instance record naming the requested sandbox type.

        Args:
            sandbox_type: Sandbox flavor requested by the bridge under test.

        Returns:
            dict[str, Any]: Instance record whose identifier embeds ``sandbox_type``.
        """
        return {"instance_id": f"{sandbox_type}-instance-7", "type": sandbox_type, "status": "running"}

    def copy_to(self, *, instance_id: str, source: str, dest: str) -> dict[str, Any]:
        """Copy ``source`` next to ``dest`` under a name carrying ``instance_id``.

        Args:
            instance_id: Identifier previously returned by ``create``.
            source: Host-side file to copy.
            dest: Intended destination path.

        Returns:
            dict[str, Any]: Copy outcome record.
        """
        target = Path(dest).with_name(f"{instance_id}-{Path(dest).name}")
        shutil.copyfile(source, target)
        return {"instance_id": instance_id, "dest": str(target), "status": "copied"}


def _method(owner: object, name: str) -> Callable[..., object]:
    """Look up a private attribute of ``owner`` that must be callable.

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


def _listing(directory: Path) -> list[Path]:
    """List the entries of a directory.

    Args:
        directory: Directory to list.

    Returns:
        list[Path]: Entries in directory order.
    """
    return list(directory.iterdir())


async def _await_object(awaitable: object) -> object:
    """Await the coroutine returned by an async bridge method looked up by name.

    Args:
        awaitable: Coroutine object returned by the call.

    Returns:
        object: The coroutine's result.
    """
    return await cast("Awaitable[object]", awaitable)


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


def _bookmark_rows(document: intellicrack_hexcore.HexDocument) -> list[_Row]:
    """Read the bookmarks stored on ``document`` as plain tuples.

    Args:
        document: Document to read.

    Returns:
        list[_Row]: ``(offset, length, label, color)`` per bookmark in insertion order.
    """
    return document.list_bookmarks()


def _returned_rows(bookmarks: list[dict[str, Any]]) -> list[_Row]:
    """Convert bookmark dicts returned by the bridge into plain tuples.

    Args:
        bookmarks: Dicts returned by ``generate_structure_bookmarks``.

    Returns:
        list[_Row]: ``(offset, length, label, color)`` per bookmark.
    """
    return [(int(b["offset"]), int(b["length"]), str(b["label"]), str(b["color"])) for b in bookmarks]


def _build_pe(
    sections: list[tuple[str, int, int, int, int]],
    *,
    opt_size: int = 112,
    pe64: bool = True,
    image_base: int = 0x140000000,
) -> bytes:
    """Assemble a 1 KiB PE image from the PE/COFF specification.

    Args:
        sections: ``(name, virtual_size, virtual_address, raw_size, raw_offset)`` per section.
        opt_size: ``SizeOfOptionalHeader`` to declare; ``0`` omits the optional header.
        pe64: Whether the optional header is PE32+ rather than PE32.
        image_base: ``ImageBase`` stored in the optional header.

    Returns:
        bytes: The PE image.
    """
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, _PE_LFANEW)
    data[_PE_LFANEW : _PE_LFANEW + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, _PE_LFANEW + 4, 0x8664, len(sections), 0, 0, 0, opt_size, 0x22)
    if opt_size:
        struct.pack_into("<H", data, _PE_OPT_OFFSET, 0x20B if pe64 else 0x10B)
        if pe64:
            struct.pack_into("<Q", data, _PE_OPT_OFFSET + 24, image_base)
        else:
            struct.pack_into("<I", data, _PE_OPT_OFFSET + 28, image_base)
    for index, (name, virtual_size, virtual_address, raw_size, raw_offset) in enumerate(sections):
        base = _PE_OPT_OFFSET + opt_size + index * 40
        data[base : base + 8] = name.encode("ascii").ljust(8, b"\x00")
        struct.pack_into("<IIIIIIHHI", data, base + 8, virtual_size, virtual_address, raw_size, raw_offset, 0, 0, 0, 0, 0x60000020)
    return bytes(data)


def _build_elf(
    *,
    is_64: bool,
    program_headers: list[tuple[int, int, int, int]],
    section_count: int = 0,
    section_offset: int = 0,
) -> bytes:
    """Assemble a 512-byte little-endian ELF image from the ELF specification.

    Args:
        is_64: Whether to emit ELF64 rather than ELF32.
        program_headers: ``(p_type, p_offset, p_vaddr, p_filesz)`` per program header.
        section_count: ``e_shnum`` to declare.
        section_offset: ``e_shoff`` to declare.

    Returns:
        bytes: The ELF image.
    """
    data = bytearray(512)
    data[:4] = b"\x7fELF"
    data[4] = 2 if is_64 else 1
    data[5] = 1
    data[6] = 1
    count = len(program_headers)
    if is_64:
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0, 64, section_offset, 0, 64, 56, count, 64, section_count, 0)
        for index, (p_type, p_offset, p_vaddr, p_filesz) in enumerate(program_headers):
            struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, p_type, 5, p_offset, p_vaddr, p_vaddr, p_filesz, p_filesz, 0x1000)
    else:
        struct.pack_into("<HHIIIIIHHHHHH", data, 16, 2, 3, 1, 0, 52, section_offset, 0, 52, 32, count, 40, section_count, 0)
        for index, (p_type, p_offset, p_vaddr, p_filesz) in enumerate(program_headers):
            struct.pack_into("<IIIIIIII", data, 52 + index * 32, p_type, p_offset, p_vaddr, p_vaddr, p_filesz, p_filesz, 5, 0x1000)
    return bytes(data)


def _macho32_segment(vmaddr: int, vmsize: int, fileoff: int, filesize: int) -> bytes:
    """Encode a 56-byte little-endian ``LC_SEGMENT`` load command.

    Args:
        vmaddr: Virtual address of the segment.
        vmsize: Size of the segment in memory.
        fileoff: File offset of the segment contents.
        filesize: Size of the segment contents in the file.

    Returns:
        bytes: The load command.
    """
    return struct.pack("<II16sIIIIIIII", _LC_SEGMENT, 56, b"__TEXT", vmaddr, vmsize, fileoff, filesize, 7, 5, 0, 0)


def _macho32_uuid() -> bytes:
    """Encode a 24-byte little-endian ``LC_UUID`` load command.

    Returns:
        bytes: The load command.
    """
    return struct.pack("<II16s", _LC_UUID, 24, b"\x11" * 16)


def _build_macho32(
    commands: list[bytes],
    *,
    ncmds: int | None = None,
    sizeofcmds: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    """Assemble a 32-bit little-endian Mach-O image from the Mach-O specification.

    Args:
        commands: Encoded load commands, concatenated after the 28-byte header.
        ncmds: ``ncmds`` to declare; defaults to ``len(commands)``.
        sizeofcmds: ``sizeofcmds`` to declare; defaults to the encoded byte length.
        trailing: Extra bytes appended after the load commands.

    Returns:
        bytes: The Mach-O image.
    """
    body = b"".join(commands)
    declared_count = len(commands) if ncmds is None else ncmds
    declared_size = len(body) if sizeofcmds is None else sizeofcmds
    return _MACHO_LE32 + struct.pack("<IIIIII", 7, 3, 2, declared_count, declared_size, 0) + body + trailing


def _ips_record(offset: int, payload: bytes) -> bytes:
    """Encode one standard IPS record: 24-bit offset, 16-bit size, payload.

    Args:
        offset: Target offset.
        payload: Replacement bytes.

    Returns:
        bytes: The encoded record.
    """
    return offset.to_bytes(3, "big") + len(payload).to_bytes(2, "big") + payload


def _reference_pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Compute the PE image checksum by zeroing the field and folding an unbounded sum.

    Args:
        data: Full image bytes.
        checksum_offset: Offset of the 32-bit ``CheckSum`` field.

    Returns:
        int: Ones'-complement 16-bit sum of the image plus its length.
    """
    work = bytearray(data)
    work[checksum_offset : checksum_offset + 4] = b"\x00" * len(work[checksum_offset : checksum_offset + 4])
    pair_count = len(work) // 2
    total = sum(struct.unpack(f"<{pair_count}H", bytes(work[: pair_count * 2])))
    if len(work) % 2:
        total += work[-1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total + len(data)


def _pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Call the bridge's static checksum routine.

    Args:
        data: Full image bytes.
        checksum_offset: Offset of the ``CheckSum`` field.

    Returns:
        int: The bridge's checksum value.
    """
    return cast("int", _method(HexEditorBridge, "_compute_pe_checksum_static")(data, checksum_offset))


def _extract_strings(
    data: bytes,
    min_length: int,
    max_results: int,
    *,
    include_ascii: bool,
    include_utf16: bool,
) -> list[_Row]:
    """Run the bridge's pure-Python string scanner and flatten its rows.

    Args:
        data: Bytes to scan.
        min_length: Minimum run length.
        max_results: Maximum number of rows.
        include_ascii: Whether to scan for ASCII runs.
        include_utf16: Whether to scan for UTF-16LE runs.

    Returns:
        list[_Row]: ``(offset, length, encoding, content)`` per match.
    """
    scan = _method(HexEditorBridge, "_extract_strings_fallback")
    rows = cast("list[dict[str, Any]]", scan(data, min_length, max_results, include_ascii=include_ascii, include_utf16=include_utf16))
    return [(int(r["offset"]), int(r["length"]), str(r["encoding"]), str(r["content"])) for r in rows]


def _new_progress() -> _ProgressLike:
    """Create the bridge's private sandbox progress tracker.

    Returns:
        _ProgressLike: A fresh tracker with no instance and no completed copy.
    """
    return cast("_ProgressLike", _method(hex_editor_module, "_SandboxCopyProgress")())


def _nonzero(counts: list[int]) -> dict[int, int]:
    """Reduce a digram table to its populated cells.

    Args:
        counts: Row-major 256x256 table.

    Returns:
        dict[int, int]: Cell index to count for every non-zero cell.
    """
    return {index: count for index, count in enumerate(counts) if count}


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
async def test_initialize_reports_unavailable_backend(hex_bridge: HexEditorBridge) -> None:
    """With the hexcore flag cleared, initialization leaves the bridge disconnected with a clear error.

    Args:
        hex_bridge: Bridge under test.
    """
    _set_flag(hex_bridge, "_hexcore_available", value=False)

    await hex_bridge.initialize()

    assert hex_bridge.state.connected is False
    assert hex_bridge.state.tool_running is False
    assert hex_bridge.state.last_error == "intellicrack_hexcore backend unavailable"
    assert await hex_bridge.is_available() is False


def test_get_interpreter_raises_when_interpreter_module_unavailable(hex_bridge: HexEditorBridge) -> None:
    """Requesting the HexPat interpreter without interpreter support raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    _set_flag(hex_bridge, "_hexpat_interpreter_available", value=False)

    with pytest.raises(RuntimeError, match="hexpat interpreter not available"):
        _method(hex_bridge, "_get_interpreter")()


def test_get_pattern_registry_raises_when_interpreter_module_unavailable(hex_bridge: HexEditorBridge) -> None:
    """Requesting the pattern registry without interpreter support raises ``RuntimeError``.

    Args:
        hex_bridge: Bridge under test.
    """
    _set_flag(hex_bridge, "_hexpat_interpreter_available", value=False)

    with pytest.raises(RuntimeError, match="pattern registry not available"):
        _method(hex_bridge, "_get_pattern_registry")()


def test_ai_context_helpers_leave_context_untouched_without_document(hex_bridge: HexEditorBridge) -> None:
    """Every AI-context population helper is a no-op when no document is open.

    Args:
        hex_bridge: Bridge under test.
    """
    context: dict[str, Any] = {}

    _method(hex_bridge, "_populate_ai_cursor_window")(context, 0, 16)
    _method(hex_bridge, "_populate_ai_inspection")(context, 0)
    _method(hex_bridge, "_populate_ai_selection")(context, 16)
    _method(hex_bridge, "_populate_ai_bookmarks")(context, 8)

    assert context == {}


@pytest.mark.asyncio
async def test_context_for_ai_reports_empty_window_when_cursor_is_past_end(hex_bridge: HexEditorBridge) -> None:
    """A cursor beyond the document end yields an empty byte window anchored at offset zero.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, bytes(range(10)))
    hex_bridge.update_cursor_from_gui(100)

    context = await hex_bridge.get_context_for_ai(include_bytes=16)

    assert context["size"] == 10
    assert isinstance(context["bytes_at_cursor"], str)
    assert not context["bytes_at_cursor"]
    assert context["bytes_offset"] == 0


@pytest.mark.asyncio
async def test_context_for_ai_normalizes_a_reversed_selection(hex_bridge: HexEditorBridge) -> None:
    """A selection stored end-first is ordered and capped to ``include_bytes`` in the AI context.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, bytes(range(16)))
    await hex_bridge.select_range(5, 2)

    context = await hex_bridge.get_context_for_ai(include_bytes=3)

    assert context["selected_bytes"] == "02 03 04"
    assert context["selection_range"] == [2, 5]


@pytest.mark.asyncio
async def test_sandbox_create_and_copy_drives_synchronous_hooks(tmp_path: Path) -> None:
    """Synchronous ``create`` and ``copy_to`` hooks are run and the created instance id reaches the copy.

    Args:
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"sandbox payload")
    sandbox = _SyncSandboxBridge()
    progress = _new_progress()

    await _await_object(
        _method(HexEditorBridge, "_sandbox_create_and_copy")(
            sandbox,
            "qemu",
            str(source),
            str(tmp_path / "landed.bin"),
            progress,
            sandbox.create,
        ),
    )

    assert progress.instance_id == "qemu-instance-7"
    assert progress.copy_succeeded is True
    assert (tmp_path / "qemu-instance-7-landed.bin").read_bytes() == b"sandbox payload"


@pytest.mark.asyncio
async def test_sandbox_create_and_copy_completes_when_bridge_has_no_copy_hook(tmp_path: Path) -> None:
    """A sandbox bridge without ``copy_to`` still finishes: the instance is recorded and nothing is copied.

    Args:
        tmp_path: Pytest temporary directory.
    """
    source = tmp_path / "payload.bin"
    source.write_bytes(b"sandbox payload")
    provisioner = _SyncSandboxBridge()
    copy_less = HexEditorBridge()
    progress = _new_progress()

    await _await_object(
        _method(HexEditorBridge, "_sandbox_create_and_copy")(
            copy_less,
            "windows",
            str(source),
            str(tmp_path / "landed.bin"),
            progress,
            provisioner.create,
        ),
    )

    assert progress.instance_id == "windows-instance-7"
    assert progress.copy_succeeded is True
    assert _listing(tmp_path) == [source]


def test_entropy_from_distribution_handles_empty_and_uniform_histograms() -> None:
    """An empty histogram has zero entropy and a uniform 256-bin histogram has exactly eight bits."""
    entropy = _method(HexEditorBridge, "_entropy_from_distribution")

    assert entropy([0] * 256, 0) == pytest.approx(0.0)
    assert entropy([1] * 256, 256) == pytest.approx(8.0)


@pytest.mark.parametrize("name", ["_compute_byte_distribution_python", "_compute_digram_matrix_python"])
def test_python_statistics_fallbacks_require_a_document(hex_bridge: HexEditorBridge, name: str) -> None:
    """The pure-Python statistics fallbacks refuse to run without an open document.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the fallback method.
    """
    with pytest.raises(RuntimeError, match="no document open"):
        _method(hex_bridge, name)()


def test_digram_matrix_counts_adjacent_byte_pairs(hex_bridge: HexEditorBridge) -> None:
    """Each adjacent byte pair increments exactly its ``(first << 8) | second`` cell.

    Args:
        hex_bridge: Bridge under test.
    """
    data = b"ABABC"
    _open_bytes(hex_bridge, data)

    counts = cast("list[int]", _method(hex_bridge, "_compute_digram_matrix_python")())

    assert len(counts) == _DIGRAM_TABLE_SIZE
    assert _nonzero(counts) == {0x4142: 2, 0x4241: 1, 0x4243: 1}


def test_digram_matrix_of_a_single_byte_document_is_all_zero(hex_bridge: HexEditorBridge) -> None:
    """A one-byte document has no pairs, so the whole table stays zero.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"\x41")

    counts = cast("list[int]", _method(hex_bridge, "_compute_digram_matrix_python")())

    assert counts == [0] * _DIGRAM_TABLE_SIZE


def test_digram_matrix_counts_the_pair_straddling_a_chunk_boundary(hex_bridge: HexEditorBridge) -> None:
    """A document longer than one 64 KiB chunk still counts the pair spanning the chunk edge.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytes((i * 31 + (i >> 8)) & 0xFF for i in range(65536 + 5))
    _open_bytes(hex_bridge, data)
    expected = Counter(((first << 8) | second) for first, second in pairwise(data))

    counts = cast("list[int]", _method(hex_bridge, "_compute_digram_matrix_python")())

    assert sum(counts) == len(data) - 1
    assert _nonzero(counts) == dict(expected)


def _disk_path(bridge: HexEditorBridge) -> Path | None:
    """Call the bridge's unmodified-document path resolver.

    Args:
        bridge: Bridge under test.

    Returns:
        Path | None: The resolved path or ``None``.
    """
    return cast("Path | None", _method(bridge, "_document_disk_path_if_unmodified")())


def test_document_disk_path_is_none_when_no_document_is_open(hex_bridge: HexEditorBridge) -> None:
    """Without a document there is no backing path to report.

    Args:
        hex_bridge: Bridge under test.
    """
    assert _disk_path(hex_bridge) is None


def test_document_disk_path_is_none_once_backing_file_is_deleted(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """The backing path is reported while the file exists and withdrawn once it is deleted.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "empty.bin"
    backing.write_bytes(b"")
    hex_bridge.document = intellicrack_hexcore.HexDocument.open(str(backing))

    before = _disk_path(hex_bridge)
    backing.unlink()
    after = _disk_path(hex_bridge)

    assert before is not None
    assert before.resolve() == backing.resolve()
    assert after is None


def test_document_disk_path_is_withdrawn_after_an_edit(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Editing the document makes the on-disk file stale, so no path is offered.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    backing = tmp_path / "sample.bin"
    backing.write_bytes(b"abcdef")
    document = intellicrack_hexcore.HexDocument.open(str(backing))
    hex_bridge.document = document

    unmodified = _disk_path(hex_bridge)
    document.write_bytes(0, b"Z")
    modified = _disk_path(hex_bridge)

    assert unmodified is not None
    assert unmodified.resolve() == backing.resolve()
    assert modified is None


@pytest.mark.asyncio
async def test_get_pe_sections_is_empty_for_a_pe_with_no_sections(hex_bridge: HexEditorBridge) -> None:
    """A PE that declares zero sections reports an empty section list.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, _build_pe([]))

    assert await hex_bridge.get_pe_sections() == []


def test_walk_pe_imports_returns_empty_list_when_pe_data_was_released(real_pe_dll: Path) -> None:
    """Walking imports of a PE whose backing data was already released yields an empty list.

    Args:
        real_pe_dll: Path to a real System32 DLL with an import table.
    """
    pe = pefile.PE(name=str(real_pe_dll), fast_load=True)
    pe.close()

    assert _method(HexEditorBridge, "_walk_pe_imports")(pe) == []


def test_walk_pe_exports_returns_empty_list_when_pe_data_was_released(real_pe_dll: Path) -> None:
    """Walking exports of a PE whose backing data was already released yields an empty list.

    Args:
        real_pe_dll: Path to a real System32 DLL with an export table.
    """
    pe = pefile.PE(name=str(real_pe_dll), fast_load=True)
    pe.close()

    assert _method(HexEditorBridge, "_walk_pe_exports")(pe) == []


def test_open_pe_for_inspection_returns_none_for_a_missing_file(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """A disk path that no longer exists makes the PE open fail softly with ``None``.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    opened = _method(hex_bridge, "_open_pe_for_inspection")(tmp_path / "missing.exe", error_event="critcov_missing_file")

    assert opened is None


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", ["get_pe_imports", "get_pe_exports"])
async def test_pe_introspection_returns_empty_list_for_an_unparseable_pe(hex_bridge: HexEditorBridge, method_name: str) -> None:
    """A document with an MZ prefix but no valid NT headers yields an empty list, as documented.

    Args:
        hex_bridge: Bridge under test.
        method_name: Name of the PE introspection method.
    """
    _open_bytes(hex_bridge, b"MZ" + bytes(62))

    assert await _await_object(_method(hex_bridge, method_name)()) == []


@pytest.mark.asyncio
async def test_resolve_patch_source_reads_document_or_original_file(hex_bridge: HexEditorBridge, tmp_path: Path) -> None:
    """Without an original path the document bytes are the patch source; with one, the file bytes are.

    Args:
        hex_bridge: Bridge under test.
        tmp_path: Pytest temporary directory.
    """
    _open_bytes(hex_bridge, b"current document")
    original = tmp_path / "original.bin"
    original.write_bytes(b"original on disk")
    resolve = _method(hex_bridge, "_resolve_patch_source")

    assert await _await_object(resolve(None)) == b"current document"
    assert await _await_object(resolve(str(original))) == b"original on disk"


def test_build_ips_rejects_an_empty_record() -> None:
    """An IPS record cannot carry zero bytes because size zero is the RLE marker."""
    with pytest.raises(OverflowError, match="IPS patch at offset 16 is empty"):
        _method(HexEditorBridge, "_build_ips_from_patches")([(16, b"")], ips32=False)


def test_apply_ips_patches_writes_literal_and_run_length_records(hex_bridge: HexEditorBridge) -> None:
    """Literal and RLE records of a standard IPS stream land at their offsets.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, bytes(32))
    rle_record = (8).to_bytes(3, "big") + (0).to_bytes(2, "big") + (4).to_bytes(2, "big") + b"\x7e"
    raw = b"PATCH" + _ips_record(2, b"ABC") + rle_record + b"EOF"
    expected = bytearray(32)
    expected[2:5] = b"ABC"
    expected[8:12] = b"\x7e" * 4

    applied = _method(hex_bridge, "_apply_ips_patches")(raw)

    assert applied == 2
    assert document.read(0, 32) == bytes(expected)


def test_apply_ips_patches_handles_the_ips32_variant(hex_bridge: HexEditorBridge) -> None:
    """IPS32 streams use 32-bit offsets and the ``EEOF`` terminator.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, bytes(32))
    literal = (0x10).to_bytes(4, "big") + (2).to_bytes(2, "big") + b"\xde\xad"
    rle = (0x18).to_bytes(4, "big") + (0).to_bytes(2, "big") + (3).to_bytes(2, "big") + b"\x55"
    raw = b"IPS32" + literal + rle + b"EEOF"
    expected = bytearray(32)
    expected[0x10:0x12] = b"\xde\xad"
    expected[0x18:0x1B] = b"\x55" * 3

    applied = _method(hex_bridge, "_apply_ips_patches")(raw)

    assert applied == 2
    assert document.read(0, 32) == bytes(expected)


def test_apply_ips_patches_counts_records_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """With no document open the stream is still validated and its records counted.

    Args:
        hex_bridge: Bridge under test.
    """
    raw = b"PATCH" + _ips_record(0, b"A") + _ips_record(9, b"BC") + b"EOF"

    assert _method(hex_bridge, "_apply_ips_patches")(raw) == 2


def test_apply_ips_patches_rejects_an_unknown_header(hex_bridge: HexEditorBridge) -> None:
    """A stream starting with neither ``PATCH`` nor ``IPS32`` is rejected.

    Args:
        hex_bridge: Bridge under test.
    """
    with pytest.raises(RuntimeError, match="invalid IPS patch header"):
        _method(hex_bridge, "_apply_ips_patches")(b"BADHDR" + b"EOF")


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        pytest.param(
            b"PATCH" + b"\x00\x00\x01",
            "truncated record header at byte 5 (need 5, have 3)",
            id="short-header",
        ),
        pytest.param(
            b"IPS32" + b"\x00\x00\x00\x01\x00",
            "truncated record header at byte 5 (need 6, have 5)",
            id="short-ips32-header",
        ),
        pytest.param(
            b"PATCH" + (2).to_bytes(3, "big") + (0).to_bytes(2, "big") + (4).to_bytes(2, "big"),
            "truncated RLE record at byte 10 (need 3, have 2)",
            id="short-rle",
        ),
        pytest.param(
            b"PATCH" + (2).to_bytes(3, "big") + (4).to_bytes(2, "big") + b"AB",
            "truncated record data at byte 10 (need 4, have 2)",
            id="short-data",
        ),
        pytest.param(b"PATCH" + _ips_record(0, b"A"), "missing EOF terminator", id="missing-eof"),
        pytest.param(
            b"IPS32" + (0).to_bytes(4, "big") + (1).to_bytes(2, "big") + b"Z",
            "missing EEOF terminator",
            id="missing-eeof",
        ),
        pytest.param(b"PATCH", "missing EOF terminator", id="header-only"),
    ],
)
def test_apply_ips_patches_rejects_malformed_streams(hex_bridge: HexEditorBridge, raw: bytes, message: str) -> None:
    """Truncated records and missing terminators raise ``RuntimeError`` naming the defect.

    Args:
        hex_bridge: Bridge under test.
        raw: Malformed IPS stream.
        message: Expected fragment of the error message.
    """
    with pytest.raises(RuntimeError, match=re.escape(message)):
        _method(hex_bridge, "_apply_ips_patches")(raw)


@pytest.mark.parametrize(
    ("name", "args", "message"),
    [
        pytest.param("_read_doc_bytes", (0, 4), "no document open", id="read-doc-bytes"),
        pytest.param("_read_all_doc_bytes", (), "no document open", id="read-all-doc-bytes"),
        pytest.param(
            "_invoke_native_transform",
            ("xor", 0, 1, dict[str, bytes](), "xor"),
            "document closed before native transform invocation",
            id="native-transform",
        ),
    ],
)
def test_document_readers_raise_without_a_document(
    hex_bridge: HexEditorBridge,
    name: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """Helpers that need a document raise ``RuntimeError`` when none is attached.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the helper method.
        args: Positional arguments to pass.
        message: Expected error message.
    """
    with pytest.raises(RuntimeError, match=message):
        _method(hex_bridge, name)(*args)


@pytest.mark.parametrize(
    ("operation", "data", "key", "count", "expected"),
    [
        pytest.param("xor", b"\x0f\xf0\xaa", b"\xff\x0f", 0, b"\xf0\xff\x55", id="xor-cycles-key"),
        pytest.param("or", b"\x01\x10", b"\x0f", 0, b"\x0f\x1f", id="or"),
        pytest.param("not", b"\x0f\x00\xff", b"", 0, b"\xf0\xff\x00", id="not"),
        pytest.param("shl", b"\xab\x01", b"", 4, b"\xb0\x10", id="shl"),
        pytest.param("shr", b"\xab\x10", b"", 4, b"\x0a\x01", id="shr"),
        pytest.param("rol", b"\x81\x01", b"", 3, b"\x0c\x08", id="rol"),
        pytest.param("rol", b"\x81\x01", b"", 11, b"\x0c\x08", id="rol-count-wraps-modulo-eight"),
        pytest.param("ror", b"\x81\x08", b"", 3, b"\x30\x01", id="ror"),
    ],
)
def test_arithmetic_fallback_applies_each_operation(operation: str, data: bytes, key: bytes, count: int, expected: bytes) -> None:
    """Each pure-Python arithmetic operation produces the hand-computed bytes.

    Args:
        operation: Operation name.
        data: Input bytes.
        key: Key or mask bytes.
        count: Shift or rotate count.
        expected: Hand-computed output.
    """
    result = _method(HexEditorBridge, "_apply_arithmetic_fallback")(bytearray(data), operation, key, count)

    assert bytes(cast("bytearray", result)) == expected


def test_arithmetic_fallback_rejects_an_unknown_operation() -> None:
    """An operation with no pure-Python implementation raises ``ToolError``."""
    with pytest.raises(ToolError, match="unknown arithmetic transform"):
        _method(HexEditorBridge, "_apply_arithmetic_fallback")(bytearray(b"\x01"), "bogus", b"", 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "args"),
    [
        pytest.param("_detect_macho_va_mappings", (_MACHO_LE32,), id="macho"),
        pytest.param("_detect_pe_va_mappings", (), id="pe"),
        pytest.param("_detect_elf_va_mappings", (), id="elf"),
    ],
)
async def test_va_detectors_return_empty_list_without_a_document(hex_bridge: HexEditorBridge, name: str, args: tuple[object, ...]) -> None:
    """Each format-specific VA detector returns ``[]`` when no document is open.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the detector.
        args: Positional arguments to pass.
    """
    assert await _await_object(_method(hex_bridge, name)(*args)) == []


@pytest.mark.asyncio
async def test_pe_va_detection_is_empty_when_nt_signature_is_wrong(hex_bridge: HexEditorBridge) -> None:
    """An MZ file whose ``e_lfanew`` does not point at the PE signature has no VA mappings.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytearray(_build_pe([(".text", 0x300, 0x1000, 0x200, 0x200)]))
    data[_PE_LFANEW : _PE_LFANEW + 4] = b"XXXX"
    document = _open_bytes(hex_bridge, bytes(data))

    assert await hex_bridge.auto_detect_va_mappings() == []
    assert document.list_va_mappings() == []


@pytest.mark.asyncio
async def test_pe_va_detection_is_empty_when_headers_end_after_the_signature(hex_bridge: HexEditorBridge) -> None:
    """A PE cut off right after its signature has no readable COFF header and yields no mappings.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytearray(0x44)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    document = _open_bytes(hex_bridge, bytes(data))

    assert await hex_bridge.auto_detect_va_mappings() == []
    assert document.list_va_mappings() == []


@pytest.mark.asyncio
async def test_pe_va_detection_is_empty_when_e_lfanew_points_past_the_end(hex_bridge: HexEditorBridge) -> None:
    """A corrupt ``e_lfanew`` beyond end-of-file means no PE signature, so the result is an empty list.

    Args:
        hex_bridge: Bridge under test.
    """
    data = bytearray(0x80)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x1000)
    _open_bytes(hex_bridge, bytes(data))

    assert await hex_bridge.auto_detect_va_mappings() == []


@pytest.mark.asyncio
async def test_pe_va_detection_maps_headers_and_sections_and_notifies_observers(hex_bridge: HexEditorBridge) -> None:
    """A valid PE32+ yields a header mapping plus one mapping per section, registered and announced.

    Args:
        hex_bridge: Bridge under test.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    hex_bridge.set_state_holder(holder)
    document = _open_bytes(hex_bridge, _build_pe([(".text", 0x300, 0x1000, 0x200, 0x200)]))

    mappings = await hex_bridge.auto_detect_va_mappings()

    assert mappings == [
        {"file_offset": 0, "virtual_address": 0x140000000, "length": 0x80},
        {"file_offset": 0x200, "virtual_address": 0x140001000, "length": 0x300},
    ]
    assert document.list_va_mappings() == [(0, 0x140000000, 0x80), (0x200, 0x140001000, 0x300)]
    assert log.events == [(HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 2})]


@pytest.mark.asyncio
@pytest.mark.parametrize("is_64", [False, True], ids=["elf32", "elf64"])
async def test_elf_va_detection_maps_only_load_segments_and_notifies_observers(hex_bridge: HexEditorBridge, *, is_64: bool) -> None:
    """Only ``PT_LOAD`` program headers become VA mappings; other segment types are skipped.

    Args:
        hex_bridge: Bridge under test.
        is_64: Whether the ELF image is 64-bit.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    hex_bridge.set_state_holder(holder)
    note = (4, 0x74, 0, 0x20)
    load = (1, 0x40, 0x08048040, 0x34)
    document = _open_bytes(hex_bridge, _build_elf(is_64=is_64, program_headers=[note, load]))

    mappings = await hex_bridge.auto_detect_va_mappings()

    assert mappings == [{"file_offset": 0x40, "virtual_address": 0x08048040, "length": 0x34}]
    assert document.list_va_mappings() == [(0x40, 0x08048040, 0x34)]
    assert log.events == [(HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 1})]


@pytest.mark.asyncio
async def test_elf_va_detection_is_empty_for_a_truncated_header(hex_bridge: HexEditorBridge) -> None:
    """An ELF cut off after its identification bytes has no readable header fields and yields no mappings.

    Args:
        hex_bridge: Bridge under test.
    """
    _open_bytes(hex_bridge, b"\x7fELF\x01\x01\x01" + bytes(9))

    assert await hex_bridge.auto_detect_va_mappings() == []


@pytest.mark.asyncio
async def test_macho_va_detection_maps_segments_and_skips_other_commands(hex_bridge: HexEditorBridge) -> None:
    """A 32-bit Mach-O maps its ``LC_SEGMENT`` command and ignores ``LC_UUID``.

    Args:
        hex_bridge: Bridge under test.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    hex_bridge.set_state_holder(holder)
    document = _open_bytes(hex_bridge, _build_macho32([_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), _macho32_uuid()]))

    mappings = await hex_bridge.auto_detect_va_mappings()

    assert mappings == [{"file_offset": 0x100, "virtual_address": 0x1000, "length": 0x1800}]
    assert document.list_va_mappings() == [(0x100, 0x1000, 0x1800)]
    assert log.events == [(HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 1})]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("commands", "ncmds"),
    [
        pytest.param([_macho32_segment(0x1000, 0x2000, 0x100, 0x1800)], 2, id="table-exhausted"),
        pytest.param([_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), struct.pack("<II", _LC_UUID, 4)], 2, id="undersized-command"),
        pytest.param([_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), struct.pack("<II", _LC_UUID, 0x100)], 2, id="oversized-command"),
    ],
)
async def test_macho_va_detection_stops_at_a_damaged_load_command_table(
    hex_bridge: HexEditorBridge,
    commands: list[bytes],
    ncmds: int,
) -> None:
    """Mappings found before a damaged load command are kept and the walk stops there.

    Args:
        hex_bridge: Bridge under test.
        commands: Encoded load commands.
        ncmds: Declared command count (larger than the table when exhausted).
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    hex_bridge.set_state_holder(holder)
    document = _open_bytes(hex_bridge, _build_macho32(commands, ncmds=ncmds))

    mappings = await hex_bridge.auto_detect_va_mappings()

    assert mappings == [{"file_offset": 0x100, "virtual_address": 0x1000, "length": 0x1800}]
    assert document.list_va_mappings() == [(0x100, 0x1000, 0x1800)]
    assert log.events == [(HexDocumentEvent.VA_MAPPING_CHANGED, {"mapping_count": 1})]


@pytest.mark.asyncio
async def test_macho_va_detection_is_empty_and_silent_for_a_truncated_header(hex_bridge: HexEditorBridge) -> None:
    """A Mach-O cut off before its command counts yields no mappings and no observer event.

    Args:
        hex_bridge: Bridge under test.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="critcov-observer")
    hex_bridge.set_state_holder(holder)
    _open_bytes(hex_bridge, _MACHO_LE64 + bytes(12))

    assert await hex_bridge.auto_detect_va_mappings() == []
    assert log.events == []


@pytest.mark.asyncio
async def test_macho_va_detection_skips_universal_binaries(hex_bridge: HexEditorBridge) -> None:
    """A universal (FAT) Mach-O has no single VA layout, so no mapping is produced.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _MACHO_FAT + bytes(28))

    assert await hex_bridge.auto_detect_va_mappings() == []
    assert document.list_va_mappings() == []


def test_ascii_strings_fallback_finds_printable_runs() -> None:
    """Printable runs of at least the minimum length are reported, including one touching the end."""
    data = b"\x00\x01Hello\x00ab\x00World Wide\n\xff\xfeTAIL!"
    oracle = [(m.start(), len(m.group()), "ascii", m.group().decode("ascii")) for m in re.finditer(rb"[\t\n\r\x20-\x7e]{4,}", data)]

    rows = _extract_strings(data, 4, 100, include_ascii=True, include_utf16=False)

    assert rows == [(2, 5, "ascii", "Hello"), (11, 11, "ascii", "World Wide\n"), (24, 5, "ascii", "TAIL!")]
    assert rows == oracle


def test_ascii_strings_fallback_honors_the_result_cap() -> None:
    """Scanning stops at ``max_results`` and returns the earliest matches."""
    data = b"\x00\x01Hello\x00ab\x00World Wide\n\xff\xfeTAIL!"

    rows = _extract_strings(data, 4, 2, include_ascii=True, include_utf16=False)

    assert rows == [(2, 5, "ascii", "Hello"), (11, 11, "ascii", "World Wide\n")]


def test_ascii_strings_fallback_drops_a_short_trailing_run() -> None:
    """A run shorter than the minimum at the very end of the data is not reported."""
    rows = _extract_strings(b"Hello\x00ab", 4, 100, include_ascii=True, include_utf16=False)

    assert rows == [(0, 5, "ascii", "Hello")]


def test_utf16_strings_fallback_finds_even_and_odd_aligned_runs() -> None:
    """UTF-16LE runs are found whether they start on an even or an odd byte offset."""
    data = b"\xff\xff" + "Test".encode(_UTF16) + b"\xff\xff" + b"\x01" + "Odd!".encode(_UTF16) + b"\xff\xff"

    rows = _extract_strings(data, 4, 100, include_ascii=False, include_utf16=True)

    assert rows == [(2, 8, _UTF16, "Test"), (13, 8, _UTF16, "Odd!")]


def test_utf16_strings_fallback_reports_a_run_that_reaches_the_end() -> None:
    """A UTF-16LE run ending exactly at the end of the data is still reported."""
    data = b"\xff\xff" + "Tail".encode(_UTF16)

    rows = _extract_strings(data, 4, 100, include_ascii=False, include_utf16=True)

    assert rows == [(2, 8, _UTF16, "Tail")]


def test_utf16_strings_fallback_drops_a_short_run_at_the_end() -> None:
    """A UTF-16LE run shorter than the minimum at the end of the data is not reported."""
    data = b"\xff\xff" + "Hi".encode(_UTF16)

    assert _extract_strings(data, 4, 100, include_ascii=False, include_utf16=True) == []


def test_utf16_strings_fallback_honors_the_result_cap() -> None:
    """With a cap of one, only the earliest UTF-16LE run is returned."""
    data = b"\xff\xff" + "Aaaa".encode(_UTF16) + b"\xff\xff" + "Bbbb".encode(_UTF16) + b"\xff\xff"

    rows = _extract_strings(data, 4, 1, include_ascii=False, include_utf16=True)

    assert rows == [(2, 8, _UTF16, "Aaaa")]


@pytest.mark.parametrize(
    ("name", "args"),
    [
        pytest.param("_bookmark_macho_structure", (_MACHO_LE32,), id="macho"),
        pytest.param("_bookmark_pe_structure", (), id="pe"),
        pytest.param("_bookmark_elf_structure", (), id="elf"),
    ],
)
def test_structure_bookmarkers_return_empty_list_without_a_document(
    hex_bridge: HexEditorBridge,
    name: str,
    args: tuple[object, ...],
) -> None:
    """Each structure bookmarker returns ``[]`` when no document is open.

    Args:
        hex_bridge: Bridge under test.
        name: Name of the bookmarker.
        args: Positional arguments to pass.
    """
    assert _method(hex_bridge, name)(*args) == []


def test_add_bookmark_and_rollback_without_a_document(hex_bridge: HexEditorBridge) -> None:
    """Without a document a bookmark is only described, and rolling back indices does nothing.

    Args:
        hex_bridge: Bridge under test.
    """
    bookmarks: list[dict[str, Any]] = []
    indices: list[int] = []

    _method(hex_bridge, "_add_bm")(bookmarks, indices, 4, 8, "Label", "#112233")
    rollback_result = _method(hex_bridge, "_rollback_bookmark_indices")([3])

    assert bookmarks == [{"offset": 4, "length": 8, "label": "Label", "color": "#112233"}]
    assert indices == []
    assert rollback_result is None


def test_rollback_with_no_recorded_indices_keeps_existing_bookmarks(hex_bridge: HexEditorBridge) -> None:
    """Rolling back an empty index list leaves the document's bookmarks alone.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, bytes(8))
    document.add_bookmark(0, 1, "keep", "#000000")

    _method(hex_bridge, "_rollback_bookmark_indices")([])

    assert _bookmark_rows(document) == [(0, 1, "keep", "#000000")]


@pytest.mark.asyncio
async def test_structure_bookmarks_for_a_universal_macho_mark_only_the_magic(hex_bridge: HexEditorBridge) -> None:
    """A universal Mach-O gets a single bookmark over its four-byte magic.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _MACHO_FAT + bytes(28))
    expected = [(0, 4, "Mach-O FAT magic", STRUCTURE_HEADER_COLOR)]

    created = await hex_bridge.generate_structure_bookmarks()

    assert _returned_rows(created) == expected
    assert _bookmark_rows(document) == expected


@pytest.mark.asyncio
async def test_structure_bookmarks_label_each_macho_load_command(hex_bridge: HexEditorBridge) -> None:
    """A 32-bit Mach-O is bookmarked as header, ``LC_SEGMENT`` and a generic ``LC_0x1B`` command.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _build_macho32([_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), _macho32_uuid()]))
    expected = [
        (0, 28, "Mach-O Header", STRUCTURE_COLORS[0]),
        (28, 56, "LC_SEGMENT #0", STRUCTURE_COLORS[1]),
        (84, 24, "LC_0x1B #1", STRUCTURE_COLORS[2]),
    ]

    created = await hex_bridge.generate_structure_bookmarks()

    assert _returned_rows(created) == expected
    assert _bookmark_rows(document) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("commands", "ncmds", "labels"),
    [
        pytest.param(
            [_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), _macho32_uuid()],
            3,
            ["Mach-O Header", "LC_SEGMENT #0", "LC_0x1B #1"],
            id="table-exhausted",
        ),
        pytest.param(
            [_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), struct.pack("<II", _LC_UUID, 4)],
            2,
            ["Mach-O Header", "LC_SEGMENT #0"],
            id="undersized-command",
        ),
        pytest.param(
            [_macho32_segment(0x1000, 0x2000, 0x100, 0x1800), struct.pack("<II", _LC_UUID, 0x100)],
            2,
            ["Mach-O Header", "LC_SEGMENT #0"],
            id="oversized-command",
        ),
    ],
)
async def test_structure_bookmarks_stop_at_a_damaged_macho_command_table(
    hex_bridge: HexEditorBridge,
    commands: list[bytes],
    ncmds: int,
    labels: list[str],
) -> None:
    """Bookmarks made before a damaged load command are kept and no further commands are bookmarked.

    Args:
        hex_bridge: Bridge under test.
        commands: Encoded load commands.
        ncmds: Declared command count.
        labels: Labels expected, in order.
    """
    document = _open_bytes(hex_bridge, _build_macho32(commands, ncmds=ncmds))

    created = await hex_bridge.generate_structure_bookmarks()

    assert [row[2] for row in _returned_rows(created)] == labels
    assert [row[2] for row in _bookmark_rows(document)] == labels


@pytest.mark.asyncio
async def test_structure_bookmarks_roll_back_when_the_macho_table_is_unreadable(hex_bridge: HexEditorBridge) -> None:
    """If a load command cannot be read, the header bookmark already added is rolled back.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _build_macho32([], ncmds=1, sizeofcmds=100, trailing=b"\x01\x00\x00\x00"))

    created = await hex_bridge.generate_structure_bookmarks()

    assert created == []
    assert _bookmark_rows(document) == []


@pytest.mark.asyncio
async def test_structure_bookmarks_skip_the_optional_header_when_it_has_zero_size(hex_bridge: HexEditorBridge) -> None:
    """A PE declaring no optional header is bookmarked without an ``Optional Header`` entry.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, _build_pe([(".rsrc", 0x100, 0x1000, 0x100, 0x200)], opt_size=0))
    expected = [
        (0, 64, "DOS Header", PE_STRUCTURE_COLORS[0]),
        (0x80, 4, "PE Signature", PE_STRUCTURE_COLORS[1]),
        (0x84, 20, "COFF Header", PE_STRUCTURE_COLORS[1]),
        (0x98, 40, "Section: .rsrc", PE_STRUCTURE_COLORS[3]),
    ]

    created = await hex_bridge.generate_structure_bookmarks()

    assert _returned_rows(created) == expected
    assert _bookmark_rows(document) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("is_64", "program_headers", "section_count", "section_offset", "expected"),
    [
        pytest.param(
            False,
            [(1, 0, 0, 0x80), (4, 0x74, 0, 0x20)],
            1,
            116,
            [
                (0, 52, "ELF Header", STRUCTURE_COLORS[0]),
                (52, 32, "Program Header 0", STRUCTURE_COLORS[1]),
                (84, 32, "Program Header 1", STRUCTURE_COLORS[1]),
                (116, 40, "Section Header 0", STRUCTURE_COLORS[2]),
            ],
            id="elf32",
        ),
        pytest.param(
            True,
            [(1, 0, 0, 0x80)],
            2,
            120,
            [
                (0, 64, "ELF Header", STRUCTURE_COLORS[0]),
                (64, 56, "Program Header 0", STRUCTURE_COLORS[1]),
                (120, 64, "Section Header 0", STRUCTURE_COLORS[2]),
                (184, 64, "Section Header 1", STRUCTURE_COLORS[2]),
            ],
            id="elf64",
        ),
    ],
)
async def test_structure_bookmarks_cover_elf_header_program_and_section_headers(
    hex_bridge: HexEditorBridge,
    *,
    is_64: bool,
    program_headers: list[tuple[int, int, int, int]],
    section_count: int,
    section_offset: int,
    expected: list[_Row],
) -> None:
    """ELF images are bookmarked with the header, each program header and each section header.

    Args:
        hex_bridge: Bridge under test.
        is_64: Whether the ELF image is 64-bit.
        program_headers: Program headers to encode.
        section_count: Declared section header count.
        section_offset: Declared section header table offset.
        expected: Bookmarks expected, in order.
    """
    image = _build_elf(is_64=is_64, program_headers=program_headers, section_count=section_count, section_offset=section_offset)
    document = _open_bytes(hex_bridge, image)

    created = await hex_bridge.generate_structure_bookmarks()

    assert _returned_rows(created) == expected
    assert _bookmark_rows(document) == expected


@pytest.mark.asyncio
async def test_structure_bookmarks_for_a_truncated_elf_are_empty(hex_bridge: HexEditorBridge) -> None:
    """An ELF cut off after its identification bytes yields no bookmarks and leaves none behind.

    Args:
        hex_bridge: Bridge under test.
    """
    document = _open_bytes(hex_bridge, b"\x7fELF\x02\x01\x01" + bytes(9))

    created = await hex_bridge.generate_structure_bookmarks()

    assert created == []
    assert _bookmark_rows(document) == []


@pytest.mark.parametrize(
    ("data", "checksum_offset", "expected"),
    [
        pytest.param(b"\x01\x00\x02\x00\x03\x00", _NEVER_OFFSET, 12, id="plain-words"),
        pytest.param(b"\x01\x00\x07", _NEVER_OFFSET, 11, id="odd-length-tail"),
        pytest.param(b"\x01\x00\x02\x00\xaa\xbb\xcc\xdd", 4, 11, id="checksum-dword-skipped"),
        pytest.param(b"\xff" * 131076, _NEVER_OFFSET, 196611, id="carry-folds-inside-the-word-loop"),
        pytest.param(b"\xff" * 131075, _NEVER_OFFSET, 131330, id="carry-folds-after-the-odd-tail-byte"),
    ],
)
def test_pe_checksum_matches_hand_computed_and_reference_values(data: bytes, checksum_offset: int, expected: int) -> None:
    """The checksum equals the literal worked out by hand and an independent reference sum.

    Args:
        data: Image bytes.
        checksum_offset: Offset of the checksum dword.
        expected: Hand-computed checksum.
    """
    assert _pe_checksum(data, checksum_offset) == expected
    assert _reference_pe_checksum(data, checksum_offset) == expected


def test_pe_checksum_ignores_the_stored_checksum_field() -> None:
    """Changing only the four checksum-field bytes does not change the computed checksum."""
    base = bytes(range(64))
    changed = base[:20] + b"\xde\xad\xbe\xef" + base[24:]

    assert _pe_checksum(base, 20) == _pe_checksum(changed, 20)


def test_pe_checksum_matches_pefile_for_a_real_dll(real_pe_dll: Path) -> None:
    """The checksum of a real System32 DLL equals the one the ``pefile`` library generates.

    Args:
        real_pe_dll: Path to a real System32 DLL.
    """
    data = real_pe_dll.read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    checksum_offset = e_lfanew + 4 + 20 + 64
    oracle = pefile.PE(data=data, fast_load=True)
    try:
        expected = oracle.generate_checksum()
    finally:
        oracle.close()

    assert _pe_checksum(data, checksum_offset) == expected
