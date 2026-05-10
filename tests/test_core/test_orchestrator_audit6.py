# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit 6 CORE-C regression tests for ``intellicrack.core.orchestrator``.

These tests target the four findings owned by work unit CORE-C:

* F-0003 - ``_extract_imports`` / ``_extract_exports`` silently dropped
  Mach-O binaries because no isinstance branch handled
  :class:`lief.MachO.Binary`.
* F-0015 - ``_extract_imports`` for ELF binaries enumerated only PLT
  relocations and missed every imported data symbol or eagerly bound
  function.
* F-0012 - ``_is_destructive_operation`` used substring matching, which
  produced false positives (``frida.get_hooks``) and false negatives
  (``sandbox.destroy``, ``sandbox.snapshot_restore``,
  ``process.terminate``).
* F-0013 - :meth:`Orchestrator.shutdown` and :meth:`Orchestrator.cancel`
  raced pending confirmation futures, leaving them orphaned and able to
  hang teardown indefinitely.

Each test exercises the actual defect: it constructs real Mach-O / ELF
fixtures with :mod:`lief`, invokes the production extraction helpers, and
drives a real ``asyncio`` event loop through the cancellation paths.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Final, cast

import lief
import pytest

from intellicrack.core.orchestrator import (
    BRIDGE_DESTRUCTIVE_METHODS,
    Orchestrator,
    PendingConfirmation,
    classify_tool_call,
    extract_exports,
    extract_imports,
)
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolCall, ToolName
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    _LiefParseFn = Callable[
        [str],
        lief.PE.Binary | lief.OAT.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None,
    ]


def _lief_parse(path: str) -> object:
    """Type-narrowed wrapper around :func:`lief.parse`.

    Mirrors the cast :mod:`intellicrack.core.orchestrator` performs so the
    test module does not propagate ``Unknown`` types into basedpyright's
    strict-mode analysis.

    Args:
        path: Filesystem path passed straight to :func:`lief.parse`.

    Returns:
        object: The parsed binary instance, or ``None`` if lief could not
        identify the format. Callers narrow with ``isinstance``.
    """
    parser = cast("_LiefParseFn", vars(lief)["parse"])
    return parser(path)


_MIN_ELF_IMPORTS: Final[int] = 3
_MIN_MACHO_IMPORTS: Final[int] = 1
_MIN_MACHO_EXPORTS: Final[int] = 1
_ELF_HEADER_SIZE: Final[int] = 64
_ELF_PHDR_SIZE: Final[int] = 56
_ELF_PHDR_COUNT: Final[int] = 2
_ELF_SHDR_SIZE: Final[int] = 64
_ELF_SHDR_COUNT: Final[int] = 6
_ELF_DYN_ENTRY_SIZE: Final[int] = 16
_ELF_DYN_ENTRY_COUNT: Final[int] = 7
_ELF_SYMTAB_ENTRY_SIZE: Final[int] = 24
_MACHO_HEADER_SIZE: Final[int] = 32
_MACHO_SEGCMD_SIZE: Final[int] = 72
_MACHO_SYMCMD_SIZE: Final[int] = 24
_MACHO_NLIST_SIZE: Final[int] = 16


def _build_elf_dynstr_and_dynsym(libc_name_holder: list[int]) -> tuple[bytes, bytes]:
    """Pack the ELF dynamic string and symbol tables.

    Args:
        libc_name_holder: Single-element output container that the caller
            uses to retrieve the ``DT_NEEDED`` string offset for libc.

    Returns:
        tuple[bytes, bytes]: ``(dynstr_bytes, dynsym_bytes)``.
    """
    dynstr = bytearray(b"\x00")

    def _add(value: bytes) -> int:
        offset = len(dynstr)
        dynstr.extend(value + b"\x00")
        return offset

    name_imp_func = _add(b"audit6_imported_func")
    name_imp_data = _add(b"audit6_imported_data")
    name_imp_weak = _add(b"audit6_third_import")
    name_export = _add(b"audit6_exported_symbol")
    libc_name_holder.append(_add(b"libc.so.6"))

    sym_undef = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym_imp_func = struct.pack("<IBBHQQ", name_imp_func, (1 << 4) | 2, 0, 0, 0, 0)
    sym_imp_data = struct.pack("<IBBHQQ", name_imp_data, (1 << 4) | 1, 0, 0, 0, 0)
    sym_imp_weak = struct.pack("<IBBHQQ", name_imp_weak, (2 << 4) | 2, 0, 0, 0, 0)
    sym_export = struct.pack("<IBBHQQ", name_export, (1 << 4) | 2, 0, 1, 0x1000, 16)
    dynsym = sym_undef + sym_imp_func + sym_imp_data + sym_imp_weak + sym_export
    return bytes(dynstr), dynsym


def _build_elf_hash_table(nsyms: int) -> bytes:
    """Pack a SysV-style ELF hash table covering ``nsyms`` symbols.

    Args:
        nsyms: Number of dynamic symbols (including the undef slot).

    Returns:
        bytes: The packed ``.hash`` section.
    """
    nbucket = 1
    bucket = struct.pack("<I", 1)
    chain = struct.pack(f"<{nsyms}I", 0, 2, 3, 4, 0)
    return struct.pack("<II", nbucket, nsyms) + bucket + chain


def _build_elf_shstr() -> tuple[bytes, dict[str, int]]:
    """Build the ELF section-header string table.

    Returns:
        tuple[bytes, dict[str, int]]: The packed string table and a map
        from section name to its byte offset within that table.
    """
    shstr = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in (".dynsym", ".dynstr", ".hash", ".dynamic", ".shstrtab"):
        offsets[name] = len(shstr)
        shstr.extend(name.encode() + b"\x00")
    return bytes(shstr), offsets


def _pack_elf_section_table(
    shstr_offsets: dict[str, int],
    layout: dict[str, int],
) -> bytes:
    """Build the ELF section header table.

    Args:
        shstr_offsets: Section-name byte offsets returned by
            :func:`_build_elf_shstr`.
        layout: File offsets and sizes for ``dynsym``, ``dynstr``, ``hash``,
            ``dynamic`` and ``shstrtab``.

    Returns:
        bytes: The packed section header table.
    """
    sh_null = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh_dynsym = struct.pack(
        "<IIQQQQIIQQ",
        shstr_offsets[".dynsym"],
        11,
        0x2,
        layout["dynsym_offset"],
        layout["dynsym_offset"],
        layout["dynsym_size"],
        2,
        1,
        8,
        _ELF_SYMTAB_ENTRY_SIZE,
    )
    sh_dynstr = struct.pack(
        "<IIQQQQIIQQ",
        shstr_offsets[".dynstr"],
        3,
        0x2,
        layout["dynstr_offset"],
        layout["dynstr_offset"],
        layout["dynstr_size"],
        0,
        0,
        1,
        0,
    )
    sh_hash = struct.pack(
        "<IIQQQQIIQQ",
        shstr_offsets[".hash"],
        5,
        0x2,
        layout["hash_offset"],
        layout["hash_offset"],
        layout["hash_size"],
        1,
        0,
        8,
        4,
    )
    sh_dynamic = struct.pack(
        "<IIQQQQIIQQ",
        shstr_offsets[".dynamic"],
        6,
        0x3,
        layout["dynamic_offset"],
        layout["dynamic_offset"],
        layout["dynamic_size"],
        2,
        0,
        8,
        _ELF_DYN_ENTRY_SIZE,
    )
    sh_shstrtab = struct.pack(
        "<IIQQQQIIQQ",
        shstr_offsets[".shstrtab"],
        3,
        0,
        0,
        layout["shstr_offset"],
        layout["shstr_size"],
        0,
        0,
        1,
        0,
    )
    return sh_null + sh_dynsym + sh_dynstr + sh_hash + sh_dynamic + sh_shstrtab


def _pack_elf_dynamic_entries(layout: dict[str, int], libc_name_offset: int) -> bytes:
    """Pack the ELF ``.dynamic`` table.

    Args:
        layout: File offsets and sizes for the dynamic-link sections.
        libc_name_offset: Byte offset of the ``libc.so.6`` string within
            ``.dynstr``.

    Returns:
        bytes: The packed dynamic table.
    """
    return (
        struct.pack("<qQ", 4, layout["hash_offset"])
        + struct.pack("<qQ", 5, layout["dynstr_offset"])
        + struct.pack("<qQ", 6, layout["dynsym_offset"])
        + struct.pack("<qQ", 10, layout["dynstr_size"])
        + struct.pack("<qQ", 11, _ELF_SYMTAB_ENTRY_SIZE)
        + struct.pack("<qQ", 1, libc_name_offset)
        + struct.pack("<qQ", 0, 0)
    )


def _pack_elf_header(sht_offset: int) -> bytes:
    """Pack the ELF64 header for the audit6 fixture.

    Args:
        sht_offset: File offset of the section header table.

    Returns:
        bytes: A 64-byte ELF header.
    """
    e_ident = bytes(
        [0x7F, ord("E"), ord("L"), ord("F"), 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    return e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0,
        _ELF_HEADER_SIZE,
        sht_offset,
        0,
        _ELF_HEADER_SIZE,
        _ELF_PHDR_SIZE,
        _ELF_PHDR_COUNT,
        _ELF_SHDR_SIZE,
        _ELF_SHDR_COUNT,
        5,
    )


def _compute_elf_layout(
    dynsym_size: int,
    dynstr_size: int,
    hash_size: int,
    dynamic_size: int,
    shstr_size: int,
) -> dict[str, int]:
    """Compute ELF section file offsets and sizes.

    Args:
        dynsym_size: Size of the ``.dynsym`` section in bytes.
        dynstr_size: Size of the ``.dynstr`` section in bytes.
        hash_size: Size of the ``.hash`` section in bytes.
        dynamic_size: Size of the ``.dynamic`` section in bytes.
        shstr_size: Size of the ``.shstrtab`` section in bytes.

    Returns:
        dict[str, int]: Mapping of layout keys to byte offsets/sizes plus
        ``sht_offset`` (8-byte-aligned section header table offset) and
        ``sht_pad`` (padding to that offset).
    """
    cursor = _ELF_HEADER_SIZE + _ELF_PHDR_SIZE * _ELF_PHDR_COUNT
    layout = {
        "dynsym_offset": cursor,
        "dynsym_size": dynsym_size,
    }
    cursor += dynsym_size
    layout["dynstr_offset"] = cursor
    layout["dynstr_size"] = dynstr_size
    cursor += dynstr_size
    layout["hash_offset"] = cursor
    layout["hash_size"] = hash_size
    cursor += hash_size
    layout["dynamic_offset"] = cursor
    layout["dynamic_size"] = dynamic_size
    cursor += dynamic_size
    layout["shstr_offset"] = cursor
    layout["shstr_size"] = shstr_size
    cursor += shstr_size
    sht_offset = ((cursor + 7) // 8) * 8
    layout["sht_offset"] = sht_offset
    layout["sht_pad"] = sht_offset - cursor
    return layout


def _build_elf_fixture_bytes() -> bytes:
    """Hand-assemble a minimal ELF64 shared object with imports and exports.

    The layout matches the SysV ELF spec: a 64-bit ELF header, a
    ``PT_LOAD`` plus a ``PT_DYNAMIC`` program header, a section table
    containing ``.dynsym``, ``.dynstr``, ``.hash``, ``.dynamic`` and
    ``.shstrtab`` sections, and a dynamic table holding ``DT_HASH``,
    ``DT_STRTAB``, ``DT_SYMTAB``, ``DT_NEEDED`` and ``DT_NULL`` entries.
    Three imported symbols (function, object, weak function) and one
    exported function are emitted so the regression assertions can
    distinguish dynsym coverage from PLT-only coverage.

    Returns:
        bytes: A complete, parseable ELF64 dynamic shared object.
    """
    libc_holder: list[int] = []
    dynstr_bytes, dynsym = _build_elf_dynstr_and_dynsym(libc_holder)
    nsyms = len(dynsym) // _ELF_SYMTAB_ENTRY_SIZE
    hash_table = _build_elf_hash_table(nsyms)
    shstr_bytes, shstr_offsets = _build_elf_shstr()
    dynamic_size = _ELF_DYN_ENTRY_COUNT * _ELF_DYN_ENTRY_SIZE
    layout = _compute_elf_layout(
        len(dynsym),
        len(dynstr_bytes),
        len(hash_table),
        dynamic_size,
        len(shstr_bytes),
    )
    sht_offset = layout["sht_offset"]

    p_load = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0,
        0,
        sht_offset,
        sht_offset,
        0x1000,
    )
    p_dynamic = struct.pack(
        "<IIQQQQQQ",
        2,
        4,
        layout["dynamic_offset"],
        layout["dynamic_offset"],
        layout["dynamic_offset"],
        dynamic_size,
        dynamic_size,
        8,
    )

    return (
        _pack_elf_header(sht_offset)
        + p_load
        + p_dynamic
        + dynsym
        + dynstr_bytes
        + hash_table
        + _pack_elf_dynamic_entries(layout, libc_holder[0])
        + shstr_bytes
        + b"\x00" * layout["sht_pad"]
        + _pack_elf_section_table(shstr_offsets, layout)
    )


def _build_elf_fixture(path: Path) -> lief.ELF.Binary:
    """Write the hand-assembled ELF fixture to disk and re-parse it.

    Args:
        path: Filesystem location to write the ELF file to.

    Returns:
        lief.ELF.Binary: The parsed binary instance.

    Raises:
        TypeError: If the produced bytes do not parse back into a
            :class:`lief.ELF.Binary` (indicates a fixture-construction bug).
    """
    path.write_bytes(_build_elf_fixture_bytes())
    parsed = _lief_parse(str(path))
    if not isinstance(parsed, lief.ELF.Binary):
        message = f"Failed to round-trip ELF fixture at {path}"
        raise TypeError(message)
    return parsed


def _pack_macho_segment(
    name: bytes,
    vmaddr: int,
    vmsize: int,
    fileoff: int,
    filesize: int,
    maxprot: int,
    initprot: int,
) -> bytes:
    """Pack an ``LC_SEGMENT_64`` load command.

    Args:
        name: Segment name (will be NUL-padded to 16 bytes).
        vmaddr: Virtual address.
        vmsize: Virtual size.
        fileoff: File offset.
        filesize: File size.
        maxprot: Maximum protection bits.
        initprot: Initial protection bits.

    Returns:
        bytes: A 72-byte ``LC_SEGMENT_64`` load command.
    """
    return struct.pack(
        "<II16sQQQQiiII",
        0x19,
        _MACHO_SEGCMD_SIZE,
        name.ljust(16, b"\x00"),
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        0,
        0,
    )


def _pack_macho_symtab_command(symoff: int, nsyms: int, stroff: int, strsize: int) -> bytes:
    """Pack an ``LC_SYMTAB`` load command.

    Args:
        symoff: File offset of the symbol table.
        nsyms: Number of symbols.
        stroff: File offset of the string table.
        strsize: Size of the string table in bytes.

    Returns:
        bytes: A 24-byte ``LC_SYMTAB`` load command.
    """
    return struct.pack("<IIIIII", 0x02, _MACHO_SYMCMD_SIZE, symoff, nsyms, stroff, strsize)


def _pack_macho_nlist(strx: int, n_type: int, n_sect: int, n_desc: int, n_value: int) -> bytes:
    """Pack a 64-bit Mach-O ``nlist_64`` symbol-table entry.

    Args:
        strx: String table index.
        n_type: ``n_type`` byte.
        n_sect: ``n_sect`` byte.
        n_desc: ``n_desc`` halfword.
        n_value: ``n_value`` quadword.

    Returns:
        bytes: A 16-byte ``nlist_64``.
    """
    return struct.pack("<IBBHQ", strx, n_type, n_sect, n_desc, n_value)


def _macho_layout(string_table: bytes, nsyms: int) -> tuple[int, int, int, int, int]:
    """Compute Mach-O fixture file offsets and segment sizes.

    Args:
        string_table: The packed Mach-O string table.
        nsyms: Number of symbol-table entries.

    Returns:
        tuple[int, int, int, int, int]: ``(text_seg_size, sym_off, str_off,
        str_size, linkedit_size)``.
    """
    total_load_cmd_size = _MACHO_SEGCMD_SIZE * 2 + _MACHO_SYMCMD_SIZE
    text_seg_size = _MACHO_HEADER_SIZE + total_load_cmd_size
    sym_off = text_seg_size
    str_off = sym_off + nsyms * _MACHO_NLIST_SIZE
    str_size = len(string_table)
    file_size = str_off + str_size
    linkedit_size = file_size - text_seg_size
    return text_seg_size, sym_off, str_off, str_size, linkedit_size


def _build_macho_fixture_bytes() -> bytes:
    """Hand-assemble a minimal Mach-O64 dylib with imports and exports.

    The lief Mach-O Builder requires an existing template, so the test
    builds the bytes directly with :mod:`struct`. The layout follows the
    Mach-O reference (``loader.h``): a 64-bit header, an ``LC_SEGMENT_64``
    for ``__TEXT``, an ``LC_SEGMENT_64`` for ``__LINKEDIT`` (which is where
    the symbol and string tables must live for lief to honour them), and
    an ``LC_SYMTAB`` describing two symbols (one imported, one exported).

    Returns:
        bytes: A complete, parseable Mach-O64 dylib payload.
    """
    string_table = b"\x00_audit6_macho_export\x00_audit6_macho_import\x00"
    nsyms = 2
    text_seg_size, sym_off, str_off, str_size, linkedit_size = _macho_layout(string_table, nsyms)
    total_load_cmd_size = _MACHO_SEGCMD_SIZE * 2 + _MACHO_SYMCMD_SIZE

    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        6,
        3,
        total_load_cmd_size,
        0,
        0,
    )
    text_seg = _pack_macho_segment(b"__TEXT", 0, text_seg_size, 0, text_seg_size, 7, 7)
    linkedit_seg = _pack_macho_segment(
        b"__LINKEDIT",
        text_seg_size,
        linkedit_size,
        text_seg_size,
        linkedit_size,
        1,
        1,
    )
    symtab = _pack_macho_symtab_command(sym_off, nsyms, str_off, str_size)
    sym_export = _pack_macho_nlist(string_table.find(b"_audit6_macho_export"), 0x0F, 1, 0, 0x1000)
    sym_import = _pack_macho_nlist(string_table.find(b"_audit6_macho_import"), 0x01, 0, 0x0100, 0)

    return header + text_seg + linkedit_seg + symtab + sym_export + sym_import + string_table


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    """Build an :class:`Orchestrator` with isolated tmp_path dependencies.

    Args:
        tmp_path: Pytest-provided per-test temporary directory.

    Returns:
        Orchestrator: A fresh orchestrator bound to that directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )


def test_extract_imports_macho_returns_dyld_symbols(tmp_path: Path) -> None:
    """Verify F-0003: Mach-O imports are no longer silently dropped.

    On clean ``main`` ``_extract_imports`` had no isinstance branch for
    ``lief.MachO.Binary`` and returned ``[]`` for every Mach-O. The fix
    walks ``binary.imported_symbols`` so dyld-resolved imports surface.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    macho_path = tmp_path / "audit6_fixture.dylib"
    macho_path.write_bytes(_build_macho_fixture_bytes())
    binary = _lief_parse(str(macho_path))
    assert isinstance(binary, lief.MachO.Binary), "Mach-O fixture failed to parse"

    imports = extract_imports(binary)
    assert len(imports) >= _MIN_MACHO_IMPORTS, f"expected Mach-O imports, got {imports}"
    names = {imp.function for imp in imports}
    assert "_audit6_macho_import" in names


def test_extract_exports_macho_returns_trie_entries(tmp_path: Path) -> None:
    """Verify F-0003: Mach-O exports are no longer silently dropped.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    macho_path = tmp_path / "audit6_fixture.dylib"
    macho_path.write_bytes(_build_macho_fixture_bytes())
    binary = _lief_parse(str(macho_path))
    assert isinstance(binary, lief.MachO.Binary), "Mach-O fixture failed to parse"

    exports = extract_exports(binary)
    assert len(exports) >= _MIN_MACHO_EXPORTS, f"expected Mach-O exports, got {exports}"
    names = {exp.name for exp in exports}
    assert "_audit6_macho_export" in names


def test_extract_imports_elf_includes_non_plt_dynamic_symbols(tmp_path: Path) -> None:
    """Verify F-0015: ELF imports include all dynamic symbols, not just PLT.

    The pre-fix code iterated ``binary.pltgot_relocations`` only, which
    missed lazily-bound functions on ``BIND_NOW`` binaries and every
    imported data symbol. The fix walks ``imported_symbols`` instead.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    elf_path = tmp_path / "audit6_fixture.so"
    binary = _build_elf_fixture(elf_path)

    imports = extract_imports(binary)
    names = {imp.function for imp in imports}
    assert "audit6_imported_func" in names
    assert "audit6_imported_data" in names
    assert "audit6_third_import" in names
    assert len(imports) >= _MIN_ELF_IMPORTS


def test_extract_exports_elf_uses_dynamic_symbols(tmp_path: Path) -> None:
    """Verify ELF exports continue to be resolved via dynamic symbols.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    elf_path = tmp_path / "audit6_fixture.so"
    binary = _build_elf_fixture(elf_path)

    exports = extract_exports(binary)
    names = {exp.name for exp in exports}
    assert "audit6_exported_symbol" in names


def test_classify_tool_call_read_only_with_hook_substring() -> None:
    """Verify F-0012: ``frida.get_hooks`` is no longer flagged destructive.

    The old substring matcher contained ``"hook"`` and therefore flagged
    every method whose name contained the string ``"hook"`` -- including
    the read-only enumerator ``frida.get_hooks``. The new exact-match
    classifier returns ``"read_only"``.
    """
    call = ToolCall(id="t-1", tool_name="frida", function_name="frida.get_hooks", arguments={})
    assert classify_tool_call(call) == "read_only"


def test_classify_tool_call_sandbox_destroy_destructive() -> None:
    """Verify F-0012: ``sandbox.destroy`` is now correctly destructive.

    The pre-fix substring set did not contain ``"destroy"``, so this real
    destructive op silently bypassed confirmation. The new explicit set
    classifies it correctly.
    """
    call = ToolCall(id="t-2", tool_name="sandbox", function_name="sandbox.destroy", arguments={})
    assert classify_tool_call(call) == "destructive"


def test_classify_tool_call_sandbox_snapshot_restore_destructive() -> None:
    """Verify F-0012: ``sandbox.snapshot_restore`` is destructive."""
    call = ToolCall(
        id="t-3",
        tool_name="sandbox",
        function_name="sandbox.snapshot_restore",
        arguments={},
    )
    assert classify_tool_call(call) == "destructive"


def test_classify_tool_call_process_terminate_destructive() -> None:
    """Verify F-0012: ``process.terminate`` (the kill-process verb) is destructive.

    The audit cited ``process.kill_process`` as a missed destructive op.
    The actual function name in the production bridge is
    ``process.terminate``; both verbs are state-changing. Here we cover
    the real one.
    """
    call = ToolCall(
        id="t-4",
        tool_name="process",
        function_name="process.terminate",
        arguments={},
    )
    assert classify_tool_call(call) == "destructive"


def test_classify_tool_call_unknown_bridge_fails_safe() -> None:
    """Verify unknown bridges classify as ``unknown`` (safe-default destructive)."""
    call = ToolCall(id="t-5", tool_name="not_a_real_bridge", function_name="anything", arguments={})
    assert classify_tool_call(call) == "unknown"


def test_orchestrator_is_destructive_operation_treats_unknown_as_destructive(
    tmp_path: Path,
) -> None:
    """Verify ``is_destructive_operation`` fails safe on unknown bridges.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    call = ToolCall(id="u-1", tool_name="not_real", function_name="some_method", arguments={})
    assert orch.is_destructive_operation(call) is True


def test_bridge_destructive_methods_cover_all_registered_bridges() -> None:
    """Verify every :class:`ToolName` that ships in the bridge layer is mapped.

    Newly added bridges that are not catalogued here would be classified
    as ``"unknown"``. We assert every registered :class:`ToolName` has
    an entry so the safe-default branch only ever fires for genuinely
    unrecognised tools (e.g. user typos).
    """
    expected = {
        ToolName.FRIDA,
        ToolName.GHIDRA,
        ToolName.X64DBG,
        ToolName.SANDBOX,
        ToolName.PROCESS,
        ToolName.HEX_EDITOR,
        ToolName.CUTTER,
    }
    assert expected.issubset(BRIDGE_DESTRUCTIVE_METHODS.keys())


@pytest.mark.asyncio
async def test_cancel_marshals_pending_confirmation_future(tmp_path: Path) -> None:
    """Verify F-0013: ``cancel`` cancels in-flight confirmation futures.

    Pre-fix, ``cancel`` called ``future.set_result(False)``, which masked
    cancellation as "user declined" and left no signal to distinguish
    cancellation from a real decline. The fix calls ``future.cancel()``
    so the awaiter receives ``CancelledError`` and translates it to
    ``False`` in :meth:`Orchestrator.request_confirmation`.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)

    loop = asyncio.get_running_loop()
    awaited_future: asyncio.Future[bool] = loop.create_future()

    def _callback(_call: ToolCall) -> asyncio.Future[bool]:
        """Return the test-supplied future for every confirmation request.

        Args:
            _call: The tool call that triggered the confirmation request.

        Returns:
            asyncio.Future[bool]: The shared future the test will operate on.
        """
        return awaited_future

    orch.set_async_confirmation_callback(_callback)

    call = ToolCall(
        id="c-1",
        tool_name="frida",
        function_name="frida.write_memory",
        arguments={},
    )
    confirm_task = asyncio.create_task(orch.request_confirmation(call))
    await asyncio.sleep(0)
    pending = orch.pending_confirmation
    assert pending is not None
    assert pending.future is awaited_future

    await orch.cancel()

    result = await asyncio.wait_for(confirm_task, timeout=1.0)
    assert result is False
    assert orch.pending_confirmation is None
    assert not orch.pending_confirmations
    assert awaited_future.cancelled()


@pytest.mark.asyncio
async def test_shutdown_cancels_pending_confirmation_without_hanging(tmp_path: Path) -> None:
    """Verify F-0013: ``shutdown`` cancels pending futures and never hangs.

    Pre-fix, ``shutdown`` did not explicitly marshal pending confirmation
    futures. If the user closed the window with a confirmation dialog
    open, the orchestrator coroutine awaiting the future would block
    forever and ``shutdown`` would deadlock waiting for tools to drain.
    The fix calls the internal marshal helper first so every awaiter
    unwinds before further teardown.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)

    loop = asyncio.get_running_loop()
    awaited_future: asyncio.Future[bool] = loop.create_future()

    def _callback(_call: ToolCall) -> asyncio.Future[bool]:
        """Return the shared future for every confirmation invocation.

        Args:
            _call: The tool call requesting confirmation.

        Returns:
            asyncio.Future[bool]: The shared future under test.
        """
        return awaited_future

    orch.set_async_confirmation_callback(_callback)

    call = ToolCall(
        id="c-2",
        tool_name="sandbox",
        function_name="sandbox.destroy",
        arguments={},
    )
    confirm_task = asyncio.create_task(orch.request_confirmation(call))
    await asyncio.sleep(0)
    assert orch.pending_confirmation is not None

    await asyncio.wait_for(orch.shutdown(), timeout=2.0)

    result = await asyncio.wait_for(confirm_task, timeout=1.0)
    assert result is False
    assert awaited_future.cancelled()
    assert not orch.pending_confirmations
    assert orch.shutdown_complete


@pytest.mark.asyncio
async def test_request_confirmation_after_shutdown_returns_false(tmp_path: Path) -> None:
    """Verify confirmation requests after shutdown short-circuit.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    await orch.shutdown()

    def _callback(_call: ToolCall) -> asyncio.Future[bool]:
        """Return a fresh, unset future for each confirmation request.

        Args:
            _call: The tool call requesting confirmation.

        Returns:
            asyncio.Future[bool]: An unset future created on the running
            event loop.
        """
        return asyncio.get_running_loop().create_future()

    orch.set_async_confirmation_callback(_callback)

    call = ToolCall(
        id="c-3",
        tool_name="frida",
        function_name="frida.write_memory",
        arguments={},
    )
    result = await orch.request_confirmation(call)
    assert result is False


@pytest.mark.asyncio
async def test_cancel_is_idempotent_when_no_pending_confirmation(tmp_path: Path) -> None:
    """Verify ``cancel`` is safe when no confirmation is pending.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    await orch.cancel()
    assert orch.pending_confirmation is None
    assert not orch.pending_confirmations


def test_orchestrator_destructive_op_for_frida_get_hooks_is_false(tmp_path: Path) -> None:
    """End-to-end: ``frida.get_hooks`` no longer triggers confirmation.

    This is the public-API analogue of
    :func:`test_classify_tool_call_read_only_with_hook_substring` - it
    drives the same defect through :meth:`Orchestrator.is_destructive_operation`
    so the regression suite covers the live integration path.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    call = ToolCall(id="e2e-1", tool_name="frida", function_name="frida.get_hooks", arguments={})
    assert orch.is_destructive_operation(call) is False


def test_orchestrator_destructive_op_for_sandbox_destroy_is_true(tmp_path: Path) -> None:
    """End-to-end: ``sandbox.destroy`` now triggers destructive confirmation.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    call = ToolCall(id="e2e-2", tool_name="sandbox", function_name="sandbox.destroy", arguments={})
    assert orch.is_destructive_operation(call) is True


def test_orchestrator_destructive_op_for_sandbox_snapshot_restore_is_true(tmp_path: Path) -> None:
    """End-to-end: ``sandbox.snapshot_restore`` now triggers destructive confirmation.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch = _make_orchestrator(tmp_path)
    call = ToolCall(
        id="e2e-3",
        tool_name="sandbox",
        function_name="sandbox.snapshot_restore",
        arguments={},
    )
    assert orch.is_destructive_operation(call) is True


def test_pending_confirmation_dataclass_fields() -> None:
    """Verify :class:`PendingConfirmation` exposes both the call and the future."""
    loop = asyncio.new_event_loop()
    try:
        future: asyncio.Future[bool] = loop.create_future()
        call = ToolCall(id="d-1", tool_name="frida", function_name="frida.write_memory", arguments={})
        pending = PendingConfirmation(call=call, future=future)
        assert pending.call is call
        assert pending.future is future
    finally:
        loop.close()
