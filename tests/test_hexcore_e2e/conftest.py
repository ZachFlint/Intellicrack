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
import struct
import zipfile
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


if TYPE_CHECKING:
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

MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_CPU_X86_64 = 0x01000007
MACHO_FILETYPE_EXECUTE = 2
MACHO_NUM_CMDS = 0
MACHO_SIZEOF_CMDS = 0

ZIP_CONTENT_NAME = "hello.txt"
ZIP_CONTENT_DATA = b"Hello, World!"


@pytest.fixture
def hexcore() -> Any:
    """Return the imported intellicrack_hexcore module.

    Returns:
        Any: The intellicrack_hexcore native module.
    """
    return hexcore_mod


@pytest.fixture
def empty_doc(hexcore: Any) -> Any:
    """Create a fresh, empty HexDocument.

    Args:
        hexcore: The native module fixture.

    Returns:
        Any: A new HexDocument instance (zero length).
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
def sample_doc(hexcore: Any, tmp_path: Path, sample_bytes: bytes) -> Any:
    """Create a HexDocument loaded with known 256-byte test data.

    Args:
        hexcore: The native module fixture.
        tmp_path: Pytest temporary directory.
        sample_bytes: The 256-byte payload fixture.

    Returns:
        Any: HexDocument loaded from a temp file containing sample_bytes.
    """
    f = tmp_path / "sample.bin"
    f.write_bytes(sample_bytes)
    return hexcore.HexDocument.open(str(f))


@pytest.fixture
def sample_doc_from_bytes(hexcore: Any, sample_bytes: bytes) -> Any:
    """Create a HexDocument from in-memory bytes (no file on disk).

    Args:
        hexcore: The native module fixture.
        sample_bytes: The 256-byte payload fixture.

    Returns:
        Any: HexDocument created via open_bytes.
    """
    return hexcore.HexDocument.open_bytes(sample_bytes)


def _build_pe_binary() -> bytes:
    """Construct a minimal valid PE binary with one .text section.

    Returns:
        bytes: A byte string containing a valid PE structure.
    """
    data = bytearray(1024)
    data[0:2] = b"MZ"
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

    data[PE_SECTION_RAW_OFFSET : PE_SECTION_RAW_OFFSET + 4] = b"\xCC\xCC\xCC\xCC"
    return bytes(data)


def _build_elf_binary() -> bytes:
    """Construct a minimal valid ELF64 binary header.

    Returns:
        bytes: A byte string containing a valid ELF64 header.
    """
    data = bytearray(256)
    data[0:4] = b"\x7fELF"
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
def bridge() -> Any:
    """Create and initialize a HexEditorBridge instance.

    Returns:
        Any: An initialized HexEditorBridge.
    """
    b = HexEditorBridge()
    asyncio.get_event_loop().run_until_complete(b.initialize())
    return b


@pytest.fixture
def loaded_bridge(bridge: Any, pe_binary: Path) -> Any:
    """Create a HexEditorBridge with a PE file already loaded.

    Args:
        bridge: An initialized HexEditorBridge fixture.
        pe_binary: Path to the PE binary fixture.

    Returns:
        Any: The bridge with the PE file opened.
    """
    asyncio.get_event_loop().run_until_complete(
        bridge.open_file(str(pe_binary))
    )
    return bridge


@pytest.fixture
def hexpat_interpreter() -> Any:
    """Create a HexPatInterpreter instance.

    Returns:
        Any: A fresh HexPatInterpreter.
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
    struct.pack_into("<f", data, 14, 3.14)
    struct.pack_into("<d", data, 18, 2.71828)
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
def event_loop() -> Any:
    """Provide or reuse an asyncio event loop for async bridge tests.

    Returns:
        Any: An asyncio event loop.
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


def run_async(coro: Any) -> Any:
    """Run an async coroutine synchronously for test convenience.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        Any: The result of the coroutine.
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
