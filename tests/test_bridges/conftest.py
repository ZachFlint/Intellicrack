# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Shared fixtures for audit1 hex_editor regression tests.

Provides reusable ``HexEditorBridge`` and minimal-binary fixtures that
mirror the ones in ``tests/test_hexcore_e2e/conftest.py`` so the audit1
suite can run as an independent pytest target. All fixtures depending
on the Rust native module use ``importorskip`` so the suite is skipped
when ``intellicrack_hexcore`` is not built.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    import types
    from collections.abc import Iterator
    from pathlib import Path


hexcore_mod: Any = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native module not built",
)


PE_DOS_HEADER_SIZE = 128
PE_LFANEW_OFFSET = 0x3C
PE_SIGNATURE_OFFSET = 0x80
PE_COFF_MACHINE_AMD64 = 0x8664
PE_NUM_SECTIONS = 1
PE_OPTIONAL_HEADER_SIZE = 240
PE_SECTION_NAME = b".text\x00\x00\x00"
PE_SECTION_VSIZE = 0x200
PE_SECTION_VADDR = 0x1000
PE_SECTION_RAW_SIZE = 0x200
PE_SECTION_RAW_OFFSET = 0x200
PE_SECTION_CHARACTERISTICS = 0x60000020

ELF_CLASS64 = 2
ELF_DATA_LSB = 1
ELF_VERSION_CURRENT = 1
ELF_TYPE_EXEC = 3
ELF_MACHINE_X86_64 = 0x3E
ELF_ENTRY_ADDR = 0x1000
ELF_PHOFF = 0x40


def _build_pe_binary() -> bytes:
    """Construct a minimal valid PE binary with one .text section.

    Returns:
        bytes: A byte string containing a valid PE structure.
    """
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<H", data, 2, 0x0090)
    struct.pack_into("<I", data, PE_LFANEW_OFFSET, PE_SIGNATURE_OFFSET)

    pe = PE_SIGNATURE_OFFSET
    data[pe : pe + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe + 4, PE_COFF_MACHINE_AMD64)
    struct.pack_into("<H", data, pe + 6, PE_NUM_SECTIONS)
    struct.pack_into("<I", data, pe + 8, 0)
    struct.pack_into("<H", data, pe + 16, 0)
    struct.pack_into("<H", data, pe + 20, PE_OPTIONAL_HEADER_SIZE)

    sec = pe + 24 + PE_OPTIONAL_HEADER_SIZE
    data[sec : sec + 8] = PE_SECTION_NAME
    struct.pack_into("<I", data, sec + 8, PE_SECTION_VSIZE)
    struct.pack_into("<I", data, sec + 12, PE_SECTION_VADDR)
    struct.pack_into("<I", data, sec + 16, PE_SECTION_RAW_SIZE)
    struct.pack_into("<I", data, sec + 20, PE_SECTION_RAW_OFFSET)
    struct.pack_into("<I", data, sec + 36, PE_SECTION_CHARACTERISTICS)

    data[PE_SECTION_RAW_OFFSET : PE_SECTION_RAW_OFFSET + 4] = b"\xcc\xcc\xcc\xcc"
    return bytes(data)


def _build_elf_binary() -> bytes:
    """Construct a minimal valid ELF64 binary header.

    Returns:
        bytes: A byte string containing a valid ELF64 header.
    """
    data = bytearray(256)
    data[:4] = b"\x7fELF"
    data[4] = ELF_CLASS64
    data[5] = ELF_DATA_LSB
    data[6] = ELF_VERSION_CURRENT
    struct.pack_into("<H", data, 16, ELF_TYPE_EXEC)
    struct.pack_into("<H", data, 18, ELF_MACHINE_X86_64)
    struct.pack_into("<I", data, 20, ELF_VERSION_CURRENT)
    struct.pack_into("<Q", data, 24, ELF_ENTRY_ADDR)
    struct.pack_into("<Q", data, 32, ELF_PHOFF)
    return bytes(data)


@pytest.fixture
def hexcore() -> types.ModuleType:
    """Return the imported intellicrack_hexcore module.

    Returns:
        types.ModuleType: The native module.
    """
    return hexcore_mod


@pytest.fixture
def pe_binary(tmp_path: Path) -> Path:
    """Write a minimal PE binary to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the PE file.
    """
    p = tmp_path / "audit1_test.exe"
    p.write_bytes(_build_pe_binary())
    return p


@pytest.fixture
def elf_binary(tmp_path: Path) -> Path:
    """Write a minimal ELF64 binary to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the ELF file.
    """
    p = tmp_path / "audit1_test.elf"
    p.write_bytes(_build_elf_binary())
    return p


@pytest.fixture
def bridge() -> Iterator[HexEditorBridge]:
    """Create, initialize, and tear down a real ``HexEditorBridge``.

    Each test gets a dedicated, freshly created event loop that is set as the
    current loop, used to drive ``initialize()``/``shutdown()``, and closed on
    teardown. This guarantees no test inherits a closed or foreign loop and no
    bridge state leaks across tests. The fixture asserts the bridge actually
    connected to the real ``intellicrack_hexcore`` backend before yielding, so a
    broken ``initialize()`` fails fast at setup rather than producing confusing
    downstream failures.

    Yields:
        HexEditorBridge: A bridge whose ``state.connected`` is ``True``.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    b = HexEditorBridge()
    try:
        loop.run_until_complete(b.initialize())
        assert b.state.connected is True, "HexEditorBridge.initialize() did not connect the hexcore backend"
        assert b.state.tool_running is True, "HexEditorBridge.initialize() did not mark the backend as running"
        assert b.document is None, "freshly initialized bridge must have no document attached"
        yield b
    finally:
        loop.run_until_complete(b.shutdown())
        asyncio.set_event_loop(None)
        loop.close()
