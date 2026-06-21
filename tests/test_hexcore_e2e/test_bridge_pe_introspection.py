# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""End-to-end tests for the new HexEditorBridge PE introspection methods.

Validates that ``get_pe_sections``, ``get_pe_imports``, and
``get_pe_exports`` return shape-stable dicts when the bridge is operating
against PE32 and PE32+ binaries. The tests use both synthesized in-tree
PE bytes (so the suite passes deterministically anywhere) and, on
Windows, a couple of real system DLLs so the helpers are exercised
against the kind of binaries the orchestrator and AI tool surface
will actually feed them.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.bridges.pe_format import (
    PE32_OPTIONAL_HEADER_SIZE,
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_DATA_DIRECTORY_ENTRY_SIZE,
    PE_DOS_HEADER_SIZE,
    PE_DOS_LFANEW_OFFSET,
    PE_DOS_SIGNATURE,
    PE_OPTIONAL_HEADER_MAGIC_PE32,
    PE_OPTIONAL_HEADER_MAGIC_PE32PLUS,
    PE_SECTION_HEADER_SIZE,
    PE_SIGNATURE,
)
from intellicrack.core.types import ToolName


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from intellicrack.bridges.hex_editor import HexEditorBridge


_pefile = pytest.importorskip("pefile", reason="pefile not installed")


_IMAGE_FILE_MACHINE_AMD64: Final[int] = 0x8664
_IMAGE_FILE_MACHINE_I386: Final[int] = 0x014C
_DEFAULT_CHARACTERISTICS: Final[int] = 0x2102
_DEFAULT_IMAGE_BASE_PE32: Final[int] = 0x00400000
_DEFAULT_IMAGE_BASE_PE64: Final[int] = 0x00007FF600000000
_NUM_DATA_DIRECTORIES: Final[int] = 16
_TEXT_VIRTUAL_ADDRESS: Final[int] = 0x1000
_TEXT_VIRTUAL_SIZE: Final[int] = 0x100
_TEXT_RAW_SIZE: Final[int] = 0x200
_TEXT_RAW_OFFSET: Final[int] = 0x400
_TEXT_CHARACTERISTICS: Final[int] = 0x60000020
_RDATA_VIRTUAL_ADDRESS: Final[int] = 0x2000
_RDATA_VIRTUAL_SIZE: Final[int] = 0x200
_RDATA_RAW_SIZE: Final[int] = 0x200
_RDATA_RAW_OFFSET: Final[int] = 0x600
_RDATA_CHARACTERISTICS: Final[int] = 0x40000040


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously.

    Args:
        coro: An awaitable coroutine object.

    Returns:
        T: The result of the coroutine.
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


def _build_section_header(
    *,
    name: bytes,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> bytes:
    """Build an ``IMAGE_SECTION_HEADER`` (40 bytes).

    Args:
        name: Section name (up to 8 bytes, NUL-padded).
        virtual_size: Section ``Misc.VirtualSize``.
        virtual_address: Section RVA.
        raw_size: ``SizeOfRawData``.
        raw_offset: ``PointerToRawData`` (file offset).
        characteristics: ``IMAGE_SCN_*`` flags.

    Returns:
        bytes: Section header buffer of exactly
            ``PE_SECTION_HEADER_SIZE`` bytes.
    """
    name_field = name.ljust(8, b"\x00")[:8]
    return name_field + struct.pack(
        "<IIIIIIHHI",
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _build_optional_header(*, is_pe64: bool, image_base: int) -> bytes:
    """Build a PE32 or PE32+ Optional Header followed by 16 data directories.

    Args:
        is_pe64: ``True`` for PE32+ (64-bit), ``False`` for PE32.
        image_base: ``ImageBase`` value to embed.

    Returns:
        bytes: Optional Header followed by 16 zero data directory
            entries.
    """
    base_size = PE32PLUS_OPTIONAL_HEADER_SIZE if is_pe64 else PE32_OPTIONAL_HEADER_SIZE
    buf = bytearray(base_size)
    if is_pe64:
        struct.pack_into("<H", buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32PLUS)
        struct.pack_into("<Q", buf, 24, image_base)
    else:
        struct.pack_into("<H", buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32)
        struct.pack_into("<I", buf, 28, image_base)
    return bytes(buf) + (b"\x00" * (PE_DATA_DIRECTORY_ENTRY_SIZE * _NUM_DATA_DIRECTORIES))


def _build_coff_header(
    *,
    machine: int,
    number_of_sections: int,
    size_of_optional_header: int,
) -> bytes:
    """Build a COFF File Header (20 bytes).

    Args:
        machine: ``IMAGE_FILE_MACHINE_*`` value.
        number_of_sections: Section count.
        size_of_optional_header: Optional Header size in bytes.

    Returns:
        bytes: COFF header buffer of exactly ``PE_COFF_HEADER_SIZE`` bytes.
    """
    return struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        0,
        0,
        0,
        size_of_optional_header,
        _DEFAULT_CHARACTERISTICS,
    )


def _build_pe_image_with_two_sections(*, is_pe64: bool) -> bytes:
    """Build a deterministic PE image with two sections (.text and .rdata).

    Pads out to ``raw_offset + raw_size`` for the last section so the
    bridge's section-table walk operates on a real, fully addressable
    buffer.

    Args:
        is_pe64: ``True`` for PE32+, ``False`` for PE32.

    Returns:
        bytes: Complete byte buffer that begins with the DOS header
            and contains every byte through the .rdata raw range.
    """
    e_lfanew = PE_DOS_HEADER_SIZE
    machine = _IMAGE_FILE_MACHINE_AMD64 if is_pe64 else _IMAGE_FILE_MACHINE_I386
    image_base = _DEFAULT_IMAGE_BASE_PE64 if is_pe64 else _DEFAULT_IMAGE_BASE_PE32

    optional_header = _build_optional_header(is_pe64=is_pe64, image_base=image_base)
    coff_header = _build_coff_header(
        machine=machine,
        number_of_sections=2,
        size_of_optional_header=len(optional_header),
    )
    text_section = _build_section_header(
        name=b".text",
        virtual_size=_TEXT_VIRTUAL_SIZE,
        virtual_address=_TEXT_VIRTUAL_ADDRESS,
        raw_size=_TEXT_RAW_SIZE,
        raw_offset=_TEXT_RAW_OFFSET,
        characteristics=_TEXT_CHARACTERISTICS,
    )
    rdata_section = _build_section_header(
        name=b".rdata",
        virtual_size=_RDATA_VIRTUAL_SIZE,
        virtual_address=_RDATA_VIRTUAL_ADDRESS,
        raw_size=_RDATA_RAW_SIZE,
        raw_offset=_RDATA_RAW_OFFSET,
        characteristics=_RDATA_CHARACTERISTICS,
    )

    dos_header = bytearray(PE_DOS_HEADER_SIZE)
    dos_header[0:2] = PE_DOS_SIGNATURE
    struct.pack_into("<I", dos_header, PE_DOS_LFANEW_OFFSET, e_lfanew)

    nt_headers = PE_SIGNATURE + coff_header + optional_header + text_section + rdata_section

    final_size = _RDATA_RAW_OFFSET + _RDATA_RAW_SIZE
    buffer = bytearray(final_size)
    buffer[:PE_DOS_HEADER_SIZE] = dos_header
    buffer[PE_DOS_HEADER_SIZE : PE_DOS_HEADER_SIZE + len(nt_headers)] = nt_headers
    return bytes(buffer)


@pytest.fixture
def pe32_two_sections(tmp_path: Path) -> Path:
    """Write a deterministic PE32 binary with .text and .rdata to disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the synthesised PE32 image.
    """
    p = tmp_path / "two_sections_pe32.exe"
    p.write_bytes(_build_pe_image_with_two_sections(is_pe64=False))
    return p


@pytest.fixture
def pe32plus_two_sections(tmp_path: Path) -> Path:
    """Write a deterministic PE32+ binary with .text and .rdata to disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the synthesised PE32+ image.
    """
    p = tmp_path / "two_sections_pe32plus.exe"
    p.write_bytes(_build_pe_image_with_two_sections(is_pe64=True))
    return p


def _system_dll_path(name: str) -> Path | None:
    """Locate a Windows system DLL on the current platform.

    Args:
        name: DLL filename (e.g. ``"kernel32.dll"``).

    Returns:
        Path | None: Path to the DLL when running on Windows and the
            file exists; otherwise ``None``.
    """
    if sys.platform != "win32":
        return None
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    candidate = Path(system_root) / "System32" / name
    return candidate if candidate.is_file() else None


@pytest.fixture
def kernel32_dll() -> Path:
    r"""Locate ``kernel32.dll`` on Windows or skip the test.

    Returns:
        Path: Path to ``C:\Windows\System32\kernel32.dll``.
    """
    path = _system_dll_path("kernel32.dll")
    if path is None:
        pytest.skip("kernel32.dll not available on this platform")
    return path


@pytest.fixture
def notepad_exe() -> Path:
    r"""Locate ``notepad.exe`` on Windows or skip the test.

    Returns:
        Path: Path to ``C:\Windows\System32\notepad.exe``.
    """
    path = _system_dll_path("notepad.exe")
    if path is None:
        pytest.skip("notepad.exe not available on this platform")
    return path


class TestGetPeSectionsSyntheticPe32:
    """Validate ``get_pe_sections`` against a synthesised PE32 image."""

    def test_returns_two_sections(self, bridge: HexEditorBridge, pe32_two_sections: Path) -> None:
        """Verify both .text and .rdata sections are returned.

        Args:
            bridge: HexEditorBridge fixture.
            pe32_two_sections: Path to the synthesised PE32 fixture.
        """
        _run(bridge.open_file(str(pe32_two_sections)))
        sections = _run(bridge.get_pe_sections())
        assert len(sections) == 2
        assert sections[0]["name"] == ".text"
        assert sections[1]["name"] == ".rdata"

    def test_section_fields_round_trip(
        self,
        bridge: HexEditorBridge,
        pe32_two_sections: Path,
    ) -> None:
        """Verify each section dict carries the embedded layout fields.

        Args:
            bridge: HexEditorBridge fixture.
            pe32_two_sections: Path to the synthesised PE32 fixture.
        """
        _run(bridge.open_file(str(pe32_two_sections)))
        sections = _run(bridge.get_pe_sections())
        text = sections[0]
        rdata = sections[1]
        assert text["virtual_address"] == _TEXT_VIRTUAL_ADDRESS
        assert text["virtual_size"] == _TEXT_VIRTUAL_SIZE
        assert text["raw_size"] == _TEXT_RAW_SIZE
        assert text["raw_offset"] == _TEXT_RAW_OFFSET
        assert text["characteristics"] == _TEXT_CHARACTERISTICS
        assert rdata["virtual_address"] == _RDATA_VIRTUAL_ADDRESS
        assert rdata["raw_offset"] == _RDATA_RAW_OFFSET
        assert rdata["characteristics"] == _RDATA_CHARACTERISTICS


class TestGetPeSectionsSyntheticPe32Plus:
    """Validate ``get_pe_sections`` against a synthesised PE32+ image."""

    def test_returns_two_sections(
        self,
        bridge: HexEditorBridge,
        pe32plus_two_sections: Path,
    ) -> None:
        """Verify PE32+ images yield the same shape as PE32.

        Args:
            bridge: HexEditorBridge fixture.
            pe32plus_two_sections: Path to the synthesised PE32+ fixture.
        """
        _run(bridge.open_file(str(pe32plus_two_sections)))
        sections = _run(bridge.get_pe_sections())
        assert len(sections) == 2
        assert sections[0]["name"] == ".text"
        assert sections[1]["name"] == ".rdata"
        assert sections[0]["virtual_address"] == _TEXT_VIRTUAL_ADDRESS
        assert sections[1]["virtual_address"] == _RDATA_VIRTUAL_ADDRESS


class TestGetPeSectionsBridgeContract:
    """Validate ``get_pe_sections`` honours its no-document and non-PE contracts."""

    def test_no_document_open_raises(self, bridge: HexEditorBridge) -> None:
        """Verify the bridge raises ``RuntimeError`` when no document is open.

        Args:
            bridge: HexEditorBridge fixture (initialized but unloaded).
        """
        with pytest.raises(RuntimeError):
            _run(bridge.get_pe_sections())

    def test_non_pe_returns_empty(
        self,
        bridge: HexEditorBridge,
        elf_binary: Path,
    ) -> None:
        """Verify ELF files yield an empty list rather than raising.

        Args:
            bridge: HexEditorBridge fixture.
            elf_binary: Path to a minimal ELF64 file.
        """
        _run(bridge.open_file(str(elf_binary)))
        sections = _run(bridge.get_pe_sections())
        assert sections == []


class TestGetPeImportsSyntheticPe:
    """Validate ``get_pe_imports`` returns an empty list for a no-imports image."""

    def test_empty_when_no_import_directory(
        self,
        bridge: HexEditorBridge,
        pe32_two_sections: Path,
    ) -> None:
        """Verify the synthesised PE (no imports) yields an empty list.

        Args:
            bridge: HexEditorBridge fixture.
            pe32_two_sections: Path to the synthesised PE32 fixture.
        """
        _run(bridge.open_file(str(pe32_two_sections)))
        imports = _run(bridge.get_pe_imports())
        assert imports == []

    def test_empty_for_non_pe(self, bridge: HexEditorBridge, elf_binary: Path) -> None:
        """Verify ELF files yield an empty import list.

        Args:
            bridge: HexEditorBridge fixture.
            elf_binary: Path to a minimal ELF64 file.
        """
        _run(bridge.open_file(str(elf_binary)))
        imports = _run(bridge.get_pe_imports())
        assert imports == []


class TestGetPeExportsSyntheticPe:
    """Validate ``get_pe_exports`` returns an empty list for a no-exports image."""

    def test_empty_when_no_export_directory(
        self,
        bridge: HexEditorBridge,
        pe32_two_sections: Path,
    ) -> None:
        """Verify the synthesised PE (no exports) yields an empty list.

        Args:
            bridge: HexEditorBridge fixture.
            pe32_two_sections: Path to the synthesised PE32 fixture.
        """
        _run(bridge.open_file(str(pe32_two_sections)))
        exports = _run(bridge.get_pe_exports())
        assert exports == []

    def test_empty_for_non_pe(self, bridge: HexEditorBridge, elf_binary: Path) -> None:
        """Verify ELF files yield an empty export list.

        Args:
            bridge: HexEditorBridge fixture.
            elf_binary: Path to a minimal ELF64 file.
        """
        _run(bridge.open_file(str(elf_binary)))
        exports = _run(bridge.get_pe_exports())
        assert exports == []


class TestPeIntrospectionRealBinaries:
    """Validate the PE introspection methods against real Windows system binaries."""

    def test_kernel32_sections(self, bridge: HexEditorBridge, kernel32_dll: Path) -> None:
        """Verify ``get_pe_sections`` parses every section in kernel32.dll.

        Args:
            bridge: HexEditorBridge fixture.
            kernel32_dll: Path to ``kernel32.dll``.
        """
        _run(bridge.open_file(str(kernel32_dll)))
        sections = _run(bridge.get_pe_sections())
        assert sections, "kernel32.dll should have at least one section"
        names = {entry["name"] for entry in sections}
        assert ".text" in names

    def test_kernel32_exports_resolve_known_symbol(
        self,
        bridge: HexEditorBridge,
        kernel32_dll: Path,
    ) -> None:
        """Verify ``get_pe_exports`` resolves at least one well-known symbol.

        Args:
            bridge: HexEditorBridge fixture.
            kernel32_dll: Path to ``kernel32.dll``.
        """
        _run(bridge.open_file(str(kernel32_dll)))
        exports = _run(bridge.get_pe_exports())
        assert exports, "kernel32.dll should expose exports"
        names = {entry["name"] for entry in exports if isinstance(entry["name"], str)}
        assert "CreateFileW" in names

    def test_notepad_imports_include_kernel32(
        self,
        bridge: HexEditorBridge,
        notepad_exe: Path,
    ) -> None:
        """Verify ``get_pe_imports`` reports the kernel32 dependency for notepad.exe.

        On Windows 11 notepad imports kernel32 through ``api-ms-win-core-*`` API-set
        forwarders rather than ``KERNEL32.dll`` directly; either form proves the
        bridge parsed the real import table and surfaced the kernel32 dependency.

        Args:
            bridge: HexEditorBridge fixture.
            notepad_exe: Path to ``notepad.exe``.
        """
        _run(bridge.open_file(str(notepad_exe)))
        imports = _run(bridge.get_pe_imports())
        assert imports, "notepad.exe should import at least one symbol"
        dlls = {str(entry["dll"]).lower() for entry in imports}
        has_kernel32 = "kernel32.dll" in dlls or any(dll.startswith("api-ms-win-core-") for dll in dlls)
        assert has_kernel32, f"expected kernel32.dll or a kernel32 API-set in notepad imports, got: {sorted(dlls)}"


class TestToolDefinitionsRegistration:
    """Verify the new bridge methods are advertised in the tool definition."""

    def test_get_pe_sections_in_tool_definitions(self, bridge: HexEditorBridge) -> None:
        """Verify ``hex_editor.get_pe_sections`` is exposed.

        Args:
            bridge: HexEditorBridge fixture.
        """
        names = {fn.name for fn in bridge.tool_definition.functions}
        assert "hex_editor.get_pe_sections" in names

    def test_get_pe_imports_in_tool_definitions(self, bridge: HexEditorBridge) -> None:
        """Verify ``hex_editor.get_pe_imports`` is exposed.

        Args:
            bridge: HexEditorBridge fixture.
        """
        names = {fn.name for fn in bridge.tool_definition.functions}
        assert "hex_editor.get_pe_imports" in names

    def test_get_pe_exports_in_tool_definitions(self, bridge: HexEditorBridge) -> None:
        """Verify ``hex_editor.get_pe_exports`` is exposed.

        Args:
            bridge: HexEditorBridge fixture.
        """
        names = {fn.name for fn in bridge.tool_definition.functions}
        assert "hex_editor.get_pe_exports" in names

    def test_bridge_dispatches_via_getattr(self, bridge: HexEditorBridge) -> None:
        """Verify each new method is reachable via the registry's ``getattr`` dispatch.

        Args:
            bridge: HexEditorBridge fixture.
        """
        for fn in ("get_pe_sections", "get_pe_imports", "get_pe_exports"):
            attr = getattr(bridge, fn, None)
            assert callable(attr), f"{fn} must be callable for ToolRegistry dispatch"

    def test_tool_name_remains_hex_editor(self, bridge: HexEditorBridge) -> None:
        """Verify the bridge still advertises the ``hex_editor`` tool name.

        Args:
            bridge: HexEditorBridge fixture.
        """
        assert bridge.tool_definition.tool_name is ToolName.HEX_EDITOR


class TestSectionTableSize:
    """Sanity-check the synthesised PE size assumptions used by the fixtures."""

    @staticmethod
    def test_section_header_size_matches_constant() -> None:
        """Verify the helper's section header is exactly ``PE_SECTION_HEADER_SIZE`` bytes."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0,
            virtual_address=0,
            raw_size=0,
            raw_offset=0,
            characteristics=0,
        )
        assert len(sec) == PE_SECTION_HEADER_SIZE

    @staticmethod
    def test_optional_header_size_matches_constants() -> None:
        """Verify the optional header sizes match the canonical PE constants."""
        pe32_opt = _build_optional_header(is_pe64=False, image_base=_DEFAULT_IMAGE_BASE_PE32)
        pe64_opt = _build_optional_header(is_pe64=True, image_base=_DEFAULT_IMAGE_BASE_PE64)
        expected_pe32 = PE32_OPTIONAL_HEADER_SIZE + _NUM_DATA_DIRECTORIES * PE_DATA_DIRECTORY_ENTRY_SIZE
        expected_pe64 = PE32PLUS_OPTIONAL_HEADER_SIZE + _NUM_DATA_DIRECTORIES * PE_DATA_DIRECTORY_ENTRY_SIZE
        assert len(pe32_opt) == expected_pe32
        assert len(pe64_opt) == expected_pe64


def test_get_pe_sections_signature(bridge: HexEditorBridge, pe32_two_sections: Path) -> None:
    """Verify ``get_pe_sections`` is async and parses the real section table.

    Asserts the method is a coroutine function (so a synchronous rewrite
    fails) and then drives it end-to-end against the synthesised PE32
    image. The expected section names are recomputed independently with
    :mod:`pefile` so a parser that returns garbage or an empty list fails.

    Args:
        bridge: HexEditorBridge fixture.
        pe32_two_sections: Path to the synthesised PE32 fixture.
    """
    assert inspect.iscoroutinefunction(bridge.get_pe_sections)

    pe = _pefile.PE(str(pe32_two_sections), fast_load=True)
    try:
        expected_names = [section.Name.rstrip(b"\x00").decode("ascii") for section in pe.sections]
    finally:
        pe.close()

    _run(bridge.open_file(str(pe32_two_sections)))
    sections = _run(bridge.get_pe_sections())
    assert [entry["name"] for entry in sections] == expected_names


def test_get_pe_imports_signature(bridge: HexEditorBridge, pe32_two_sections: Path) -> None:
    """Verify ``get_pe_imports`` is async and parses the real import table.

    Asserts the method is a coroutine function and then drives it
    end-to-end against the synthesised PE32 image. The synthesised image
    carries no import directory; :mod:`pefile` independently confirms it
    exposes no ``DIRECTORY_ENTRY_IMPORT`` so the bridge must return ``[]``.

    Args:
        bridge: HexEditorBridge fixture.
        pe32_two_sections: Path to the synthesised PE32 fixture.
    """
    assert inspect.iscoroutinefunction(bridge.get_pe_imports)

    pe = _pefile.PE(str(pe32_two_sections), fast_load=True)
    try:
        pe.parse_data_directories(directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        assert not hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
    finally:
        pe.close()

    _run(bridge.open_file(str(pe32_two_sections)))
    imports = _run(bridge.get_pe_imports())
    assert imports == []


def test_get_pe_exports_signature(bridge: HexEditorBridge, pe32_two_sections: Path) -> None:
    """Verify ``get_pe_exports`` is async and parses the real export table.

    Asserts the method is a coroutine function and then drives it
    end-to-end against the synthesised PE32 image. The synthesised image
    carries no export directory; :mod:`pefile` independently confirms it
    exposes no ``DIRECTORY_ENTRY_EXPORT`` so the bridge must return ``[]``.

    Args:
        bridge: HexEditorBridge fixture.
        pe32_two_sections: Path to the synthesised PE32 fixture.
    """
    assert inspect.iscoroutinefunction(bridge.get_pe_exports)

    pe = _pefile.PE(str(pe32_two_sections), fast_load=True)
    try:
        pe.parse_data_directories(directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        assert not hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
    finally:
        pe.close()

    _run(bridge.open_file(str(pe32_two_sections)))
    exports = _run(bridge.get_pe_exports())
    assert exports == []
