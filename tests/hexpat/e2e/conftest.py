# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Shared fixtures for hexcore E2E tests.

Provides reusable fixtures for HexDocument, HexEditorBridge, HexPat
interpreter, and minimal binary file builders (PE, ELF, Mach-O, ZIP).
All fixtures that depend on the Rust native module use importorskip
so that the entire suite is skipped when hexcore is not built.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import struct
import zipfile
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


if TYPE_CHECKING:
    import types
    from collections.abc import Coroutine
    from pathlib import Path

    from intellicrack_hexcore import HexDocument


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

MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_CPU_X86_64 = 0x01000007
MACHO_FILETYPE_EXECUTE = 2
MACHO_NUM_CMDS = 0
MACHO_SIZEOF_CMDS = 0

ZIP_CONTENT_NAME = "hello.txt"
ZIP_CONTENT_DATA = b"Hello, World!"


@pytest.fixture
def hexcore() -> types.ModuleType:
    """Return the imported intellicrack_hexcore module.

    Returns:
        types.ModuleType: The intellicrack_hexcore native module.
    """
    return hexcore_mod


@pytest.fixture
def empty_doc(hexcore: types.ModuleType) -> HexDocument:
    """Create a fresh, empty HexDocument.

    Args:
        hexcore: The native module fixture.

    Returns:
        HexDocument: A new HexDocument instance (zero length).
    """
    return hexcore.HexDocument()


@pytest.fixture
def sample_bytes() -> bytes:
    """Provide a known 256-byte test payload.

    Returns:
        bytes: 256 bytes from 0x00 through 0xFF.
    """
    return bytes(range(256))


@pytest.fixture
def sample_doc(hexcore: types.ModuleType, tmp_path: Path, sample_bytes: bytes) -> HexDocument:
    """Create a HexDocument loaded with known 256-byte test data.

    Args:
        hexcore: The native module fixture.
        tmp_path: Pytest temporary directory.
        sample_bytes: The 256-byte payload fixture.

    Returns:
        HexDocument: HexDocument loaded from a temp file containing sample_bytes.
    """
    f = tmp_path / "sample.bin"
    f.write_bytes(sample_bytes)
    return hexcore.HexDocument.open(str(f))


@pytest.fixture
def sample_doc_from_bytes(hexcore: types.ModuleType, sample_bytes: bytes) -> HexDocument:
    """Create a HexDocument from in-memory bytes (no file on disk).

    Args:
        hexcore: The native module fixture.
        sample_bytes: The 256-byte payload fixture.

    Returns:
        HexDocument: HexDocument created via open_bytes.
    """
    return hexcore.HexDocument.open_bytes(sample_bytes)


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


def _build_macho_binary() -> bytes:
    """Construct a minimal valid 64-bit Mach-O header.

    Returns:
        bytes: A byte string containing a valid Mach-O 64-bit header.
    """
    data = bytearray(256)
    struct.pack_into("<I", data, 0, MACHO_MAGIC_64)
    struct.pack_into("<I", data, 4, MACHO_CPU_X86_64)
    struct.pack_into("<I", data, 8, 0)
    struct.pack_into("<I", data, 12, MACHO_FILETYPE_EXECUTE)
    struct.pack_into("<I", data, 16, MACHO_NUM_CMDS)
    struct.pack_into("<I", data, 20, MACHO_SIZEOF_CMDS)
    struct.pack_into("<I", data, 24, 0)
    struct.pack_into("<I", data, 28, 0)
    return bytes(data)


def _build_zip_binary(directory: Path) -> Path:
    """Construct a minimal valid ZIP file in the given directory.

    Args:
        directory: Directory in which to write the ZIP file.

    Returns:
        Path: Path to the created ZIP file.
    """
    zip_path = directory / "test.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ZIP_CONTENT_NAME, ZIP_CONTENT_DATA.decode("ascii"))
    return zip_path


PE_FULL_OPT_HEADER_MAGIC_PE32 = 0x10B
PE_FULL_IMAGE_BASE = 0x00400000
PE_FULL_NUM_SECTIONS = 2
PE_FULL_TEXT_VADDR = 0x1000
PE_FULL_TEXT_RAW_OFFSET = 0x200
PE_FULL_TEXT_SIZE = 0x200
PE_FULL_DATA_VADDR = 0x2000
PE_FULL_DATA_RAW_OFFSET = 0x400
PE_FULL_DATA_SIZE = 0x100
PE_FULL_CHECKSUM_FIELD_OFFSET = 64

ELF_LOAD_PHENTSIZE = 56
ELF_LOAD_PHNUM = 2
ELF_LOAD1_OFFSET = 0x1000
ELF_LOAD1_VADDR = 0x400000
ELF_LOAD1_FILESZ = 0x200
ELF_LOAD2_OFFSET = 0x2000
ELF_LOAD2_VADDR = 0x401000
ELF_LOAD2_FILESZ = 0x100

STRING_TEST_SIZE = 512
STRING_TEST_ASCII_OFFSET = 0x10
STRING_TEST_UTF16_OFFSET = 0x80
STRING_TEST_ASCII_CONTENT = "Hello World!"
STRING_TEST_UTF16_CONTENT = "Test String"

PT_LOAD_TYPE = 1


def _build_pe_binary_full() -> bytes:
    """Construct a PE binary with Optional Header magic, ImageBase, and two sections.

    Returns:
        bytes: A byte string containing a PE32 with .text and .data sections.
    """
    total_size = PE_FULL_DATA_RAW_OFFSET + PE_FULL_DATA_SIZE
    data = bytearray(total_size)
    data[:2] = b"MZ"
    struct.pack_into("<H", data, 2, 0x0090)
    struct.pack_into("<I", data, PE_LFANEW_OFFSET, PE_SIGNATURE_OFFSET)

    pe = PE_SIGNATURE_OFFSET
    data[pe : pe + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe + 4, PE_COFF_MACHINE_AMD64)
    struct.pack_into("<H", data, pe + 6, PE_FULL_NUM_SECTIONS)
    struct.pack_into("<I", data, pe + 8, 0)
    struct.pack_into("<H", data, pe + 16, 0)
    struct.pack_into("<H", data, pe + 20, PE_OPTIONAL_HEADER_SIZE)

    opt = pe + 24
    struct.pack_into("<H", data, opt, PE_FULL_OPT_HEADER_MAGIC_PE32)
    struct.pack_into("<I", data, opt + 28, PE_FULL_IMAGE_BASE)
    struct.pack_into("<I", data, opt + PE_FULL_CHECKSUM_FIELD_OFFSET, 0)

    sec_table = opt + PE_OPTIONAL_HEADER_SIZE

    data[sec_table : sec_table + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sec_table + 8, PE_FULL_TEXT_SIZE)
    struct.pack_into("<I", data, sec_table + 12, PE_FULL_TEXT_VADDR)
    struct.pack_into("<I", data, sec_table + 16, PE_FULL_TEXT_SIZE)
    struct.pack_into("<I", data, sec_table + 20, PE_FULL_TEXT_RAW_OFFSET)
    struct.pack_into("<I", data, sec_table + 36, PE_SECTION_CHARACTERISTICS)

    sec2 = sec_table + 40
    data[sec2 : sec2 + 8] = b".data\x00\x00\x00"
    struct.pack_into("<I", data, sec2 + 8, PE_FULL_DATA_SIZE)
    struct.pack_into("<I", data, sec2 + 12, PE_FULL_DATA_VADDR)
    struct.pack_into("<I", data, sec2 + 16, PE_FULL_DATA_SIZE)
    struct.pack_into("<I", data, sec2 + 20, PE_FULL_DATA_RAW_OFFSET)
    struct.pack_into("<I", data, sec2 + 36, 0xC0000040)

    data[PE_FULL_TEXT_RAW_OFFSET : PE_FULL_TEXT_RAW_OFFSET + 4] = b"\xcc\xcc\xcc\xcc"
    data[PE_FULL_DATA_RAW_OFFSET : PE_FULL_DATA_RAW_OFFSET + 4] = b"\x00\x01\x02\x03"
    return bytes(data)


def _build_elf_binary_with_loads() -> bytes:
    """Construct an ELF64 binary with two PT_LOAD program headers.

    Returns:
        bytes: A byte string containing a valid ELF64 with two PT_LOAD segments.
    """
    phdr_table_offset = ELF_PHOFF
    min_size = max(
        phdr_table_offset + ELF_LOAD_PHENTSIZE * ELF_LOAD_PHNUM,
        ELF_LOAD2_OFFSET + ELF_LOAD2_FILESZ,
    )
    data = bytearray(min_size)

    data[:4] = b"\x7fELF"
    data[4] = ELF_CLASS64
    data[5] = ELF_DATA_LSB
    data[6] = ELF_VERSION_CURRENT
    struct.pack_into("<H", data, 16, ELF_TYPE_EXEC)
    struct.pack_into("<H", data, 18, ELF_MACHINE_X86_64)
    struct.pack_into("<I", data, 20, ELF_VERSION_CURRENT)
    struct.pack_into("<Q", data, 24, ELF_ENTRY_ADDR)
    struct.pack_into("<Q", data, 32, phdr_table_offset)
    struct.pack_into("<H", data, 54, ELF_LOAD_PHENTSIZE)
    struct.pack_into("<H", data, 56, ELF_LOAD_PHNUM)

    phdr1 = phdr_table_offset
    struct.pack_into("<I", data, phdr1, PT_LOAD_TYPE)
    struct.pack_into("<I", data, phdr1 + 4, 0x5)
    struct.pack_into("<Q", data, phdr1 + 8, ELF_LOAD1_OFFSET)
    struct.pack_into("<Q", data, phdr1 + 16, ELF_LOAD1_VADDR)
    struct.pack_into("<Q", data, phdr1 + 24, ELF_LOAD1_VADDR)
    struct.pack_into("<Q", data, phdr1 + 32, ELF_LOAD1_FILESZ)
    struct.pack_into("<Q", data, phdr1 + 40, ELF_LOAD1_FILESZ)
    struct.pack_into("<Q", data, phdr1 + 48, 0x1000)

    phdr2 = phdr_table_offset + ELF_LOAD_PHENTSIZE
    struct.pack_into("<I", data, phdr2, PT_LOAD_TYPE)
    struct.pack_into("<I", data, phdr2 + 4, 0x6)
    struct.pack_into("<Q", data, phdr2 + 8, ELF_LOAD2_OFFSET)
    struct.pack_into("<Q", data, phdr2 + 16, ELF_LOAD2_VADDR)
    struct.pack_into("<Q", data, phdr2 + 24, ELF_LOAD2_VADDR)
    struct.pack_into("<Q", data, phdr2 + 32, ELF_LOAD2_FILESZ)
    struct.pack_into("<Q", data, phdr2 + 40, ELF_LOAD2_FILESZ)
    struct.pack_into("<Q", data, phdr2 + 48, 0x1000)

    for i in range(ELF_LOAD1_FILESZ):
        if ELF_LOAD1_OFFSET + i < len(data):
            data[ELF_LOAD1_OFFSET + i] = i & 0xFF
    for i in range(ELF_LOAD2_FILESZ):
        if ELF_LOAD2_OFFSET + i < len(data):
            data[ELF_LOAD2_OFFSET + i] = (0xFF - i) & 0xFF

    return bytes(data)


def _build_string_test_data() -> bytes:
    """Construct a 512-byte buffer with embedded ASCII and UTF-16LE strings.

    Returns:
        bytes: Buffer with known strings at predictable offsets.
    """
    data = bytearray(STRING_TEST_SIZE)
    rng_seed = 42
    for i in range(STRING_TEST_SIZE):
        rng_seed = (rng_seed * 1103515245 + 12345) & 0x7FFFFFFF
        data[i] = (rng_seed >> 16) & 0xFF

    ascii_bytes = STRING_TEST_ASCII_CONTENT.encode("ascii")
    data[STRING_TEST_ASCII_OFFSET : STRING_TEST_ASCII_OFFSET + len(ascii_bytes)] = ascii_bytes

    utf16_bytes = STRING_TEST_UTF16_CONTENT.encode("utf-16-le")
    data[STRING_TEST_UTF16_OFFSET : STRING_TEST_UTF16_OFFSET + len(utf16_bytes)] = utf16_bytes

    return bytes(data)


def _build_sig_db_files(directory: Path) -> Path:
    """Write test signature database files to a directory.

    Args:
        directory: Target directory for signature files.

    Returns:
        Path: The directory containing the created files.
    """
    die_db = [
        {
            "name": "MZ Executable",
            "type": "PE",
            "version": "1.0",
            "patterns": [{"pattern": "4D5A", "offset": "ep"}],
        },
    ]
    (directory / "die_test.json").write_text(json.dumps(die_db), encoding="utf-8")

    known_data = b"MZ" + b"\x00" * 62
    md5_hash = hashlib.md5(known_data).hexdigest()  # noqa: S324
    hdb_line = f"{md5_hash}:{len(known_data)}:TestSig.HDB\n"
    (directory / "test.hdb").write_text(hdb_line, encoding="utf-8")

    ndb_line = "TestSig.NDB:0:*:4D5A\n"
    (directory / "test.ndb").write_text(ndb_line, encoding="utf-8")

    custom_db = [
        {"name": "MZ EP Match", "pattern": "4D5A", "offset": "ep", "type": "pe_detect"},
        {"name": "Any Byte Match", "pattern": "DEADBEEF", "offset": "any", "type": "marker"},
        {"name": "Fixed Offset Match", "pattern": "00010203", "offset": "0", "type": "header"},
    ]
    (directory / "custom.json").write_text(json.dumps(custom_db), encoding="utf-8")

    return directory


@pytest.fixture
def pe_binary_full(tmp_path: Path) -> Path:
    """Write a PE binary with full Optional Header to disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the enhanced PE file.
    """
    p = tmp_path / "test_full.exe"
    p.write_bytes(_build_pe_binary_full())
    return p


@pytest.fixture
def elf_binary_with_loads(tmp_path: Path) -> Path:
    """Write an ELF64 binary with two PT_LOAD segments to disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the ELF file with program headers.
    """
    p = tmp_path / "test_loads.elf"
    p.write_bytes(_build_elf_binary_with_loads())
    return p


@pytest.fixture
def string_test_data(tmp_path: Path) -> Path:
    """Write a 512-byte file with embedded test strings to disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the string test data file.
    """
    p = tmp_path / "strings.bin"
    p.write_bytes(_build_string_test_data())
    return p


@pytest.fixture
def sig_db_dir(tmp_path: Path) -> Path:
    """Create a directory of test signature database files.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the directory containing signature files.
    """
    sig_dir = tmp_path / "sig_db"
    sig_dir.mkdir()
    return _build_sig_db_files(sig_dir)


@pytest.fixture
def pe_binary(tmp_path: Path) -> Path:
    """Write a minimal PE binary to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the PE file.
    """
    p = tmp_path / "test.exe"
    p.write_bytes(_build_pe_binary())
    return p


@pytest.fixture
def pe_bytes() -> bytes:
    """Return minimal PE binary data as bytes.

    Returns:
        bytes: PE binary content.
    """
    return _build_pe_binary()


@pytest.fixture
def elf_binary(tmp_path: Path) -> Path:
    """Write a minimal ELF64 binary to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the ELF file.
    """
    p = tmp_path / "test.elf"
    p.write_bytes(_build_elf_binary())
    return p


@pytest.fixture
def elf_bytes() -> bytes:
    """Return minimal ELF64 binary data as bytes.

    Returns:
        bytes: ELF binary content.
    """
    return _build_elf_binary()


@pytest.fixture
def macho_binary(tmp_path: Path) -> Path:
    """Write a minimal Mach-O binary to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the Mach-O file.
    """
    p = tmp_path / "test.macho"
    p.write_bytes(_build_macho_binary())
    return p


@pytest.fixture
def macho_bytes() -> bytes:
    """Return minimal Mach-O binary data as bytes.

    Returns:
        bytes: Mach-O binary content.
    """
    return _build_macho_binary()


@pytest.fixture
def zip_binary(tmp_path: Path) -> Path:
    """Write a minimal ZIP file to disk and return its path.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the ZIP file.
    """
    return _build_zip_binary(tmp_path)


@pytest.fixture
def zip_bytes(tmp_path: Path) -> bytes:
    """Return minimal ZIP file content as bytes.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        bytes: ZIP file content.
    """
    return _build_zip_binary(tmp_path).read_bytes()


@pytest.fixture
def bridge() -> HexEditorBridge:
    """Create and initialize a HexEditorBridge instance.

    Returns:
        HexEditorBridge: An initialized HexEditorBridge.
    """
    b = HexEditorBridge()
    run_async(b.initialize())
    return b


@pytest.fixture
def loaded_bridge(bridge: HexEditorBridge, pe_binary: Path) -> HexEditorBridge:
    """Create a HexEditorBridge with a PE file already loaded.

    Args:
        bridge: An initialized HexEditorBridge fixture.
        pe_binary: Path to the PE binary fixture.

    Returns:
        HexEditorBridge: The bridge with the PE file opened.
    """
    run_async(bridge.open_file(str(pe_binary)))
    return bridge


@pytest.fixture
def hexpat_interpreter() -> HexPatInterpreter:
    """Create a HexPatInterpreter instance.

    Returns:
        HexPatInterpreter: A fresh HexPatInterpreter.
    """
    return HexPatInterpreter()


@pytest.fixture
def pattern_data() -> bytes:
    """Provide a 512-byte structured test buffer for pattern testing.

    The buffer contains known values at specific offsets for predictable
    field extraction in HexPat pattern tests.

    Returns:
        bytes: A 512-byte buffer with embedded test values.
    """
    data = bytearray(512)
    struct.pack_into("<H", data, 0, 0x1234)
    struct.pack_into("<I", data, 2, 0xDEADBEEF)
    struct.pack_into("<Q", data, 6, 0xCAFEBABE12345678)
    struct.pack_into("<f", data, 14, math.pi)
    struct.pack_into("<d", data, 18, math.e)
    data[26:30] = b"TEST"
    struct.pack_into("<i", data, 30, -42)
    struct.pack_into("<h", data, 34, -1000)
    data[36] = 0xFF
    data[37] = 0x00
    data[38:42] = b"\x01\x02\x03\x04"
    struct.pack_into("<I", data, 42, 100)
    struct.pack_into(">I", data, 46, 0xAABBCCDD)
    return bytes(data)


@pytest.fixture
def event_loop() -> asyncio.AbstractEventLoop:
    """Provide or reuse an asyncio event loop for async bridge tests.

    Returns:
        asyncio.AbstractEventLoop: An asyncio event loop.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def run_async(coro: Coroutine[object, object, object]) -> object:
    """Run an async coroutine synchronously for test convenience.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        object: The result of the coroutine.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
