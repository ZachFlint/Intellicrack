# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-binary validation for ``intellicrack.bridges.pe_format`` helpers.

The pre-existing ``test_pe_format.py`` suite exercises every public
helper against hand-assembled ``struct.pack`` buffers. Those buffers
prove the helpers' arithmetic but cannot prove fidelity against the
compiler-inserted padding, alignment slack, populated data directories,
and full section tables that real Windows DLLs, the committed ELF, and
the committed Mach-O fixtures carry.

This module drives the same pure-byte helpers
(:func:`read_dos_e_lfanew`, :func:`unpack_coff_header`,
:func:`is_pe64_optional_header`, :func:`unpack_optional_header_image_base`,
:func:`iterate_section_headers`, :func:`get_data_directory_offset`,
:func:`read_data_directory_entry`, :func:`rva_to_file_offset`,
:func:`detect_format`, :func:`detect_format_and_arch`) against genuine
binaries resolved at runtime and cross-checks every result against an
independent oracle (:mod:`pefile` for PE, recorded format constants for
ELF / Mach-O).
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any, Literal, cast

import pefile

from intellicrack.bridges.pe_format import (
    ELF_CLASS_64,
    ELF_E_MACHINE_END,
    ELF_E_MACHINE_OFFSET,
    ELF_EI_CLASS_OFFSET,
    ELF_EI_DATA_OFFSET,
    ELF_EM_X86_64,
    ELF_MAGIC,
    MACHO_CPU_TYPE_X86_64,
    PE_DOS_SIGNATURE,
    PE_MACHINE_AMD64,
    PE_OPTIONAL_HEADER_MAGIC_PE32PLUS,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SIGNATURE,
    detect_format,
    detect_format_and_arch,
    get_data_directory_offset,
    is_pe64_optional_header,
    iterate_section_headers,
    optional_header_size_for,
    pe_machine_to_arch,
    read_data_directory_entry,
    read_dos_e_lfanew,
    rva_to_file_offset,
    unpack_coff_header,
    unpack_optional_header_image_base,
)


if TYPE_CHECKING:
    from pathlib import Path

_IMAGE_DIRECTORY_ENTRY_IMPORT = 1
_PE_COFF_HEADER_SIZE = 20


def _pefile_coff_fields(path: Path) -> tuple[int, int, int, int]:
    """Read COFF fields from a real PE via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        tuple[int, int, int, int]: ``(e_lfanew, machine, number_of_sections,
            size_of_optional_header)`` as reported by pefile.
    """
    pe = cast("Any", pefile.PE(str(path), fast_load=True))
    try:
        return (
            int(pe.DOS_HEADER.e_lfanew),
            int(pe.FILE_HEADER.Machine),
            int(pe.FILE_HEADER.NumberOfSections),
            int(pe.FILE_HEADER.SizeOfOptionalHeader),
        )
    finally:
        pe.close()


def _pefile_optional_fields(path: Path) -> tuple[int, int]:
    """Read optional-header magic and ImageBase via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        tuple[int, int]: ``(optional_header_magic, image_base)``.
    """
    pe = cast("Any", pefile.PE(str(path), fast_load=True))
    try:
        return int(pe.OPTIONAL_HEADER.Magic), int(pe.OPTIONAL_HEADER.ImageBase)
    finally:
        pe.close()


def _pefile_section_tuples(path: Path) -> list[tuple[str, int, int, int]]:
    """Read the section table via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        list[tuple[str, int, int, int]]: ``(name, virtual_address,
            raw_offset, raw_size)`` for each section.
    """
    pe = cast("Any", pefile.PE(str(path), fast_load=True))
    try:
        return [
            (
                bytes(section.Name).split(b"\x00", 1)[0].decode("ascii", errors="replace"),
                int(section.VirtualAddress),
                int(section.PointerToRawData),
                int(section.SizeOfRawData),
            )
            for section in pe.sections
        ]
    finally:
        pe.close()


def _pefile_import_directory_entry(path: Path) -> tuple[int, int]:
    """Read the import data-directory RVA and size via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        tuple[int, int]: ``(virtual_address, size)`` of the import
            data-directory entry.
    """
    pe = cast("Any", pefile.PE(str(path), fast_load=True))
    try:
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_IMPORT]
        return int(entry.VirtualAddress), int(entry.Size)
    finally:
        pe.close()


def _pefile_offset_from_rva(path: Path, rva: int) -> int:
    """Translate an RVA to a file offset via the pefile oracle.

    Args:
        path: Path to a real PE binary.
        rva: Relative virtual address to translate.

    Returns:
        int: The file offset pefile reports for ``rva``.
    """
    pe = cast("Any", pefile.PE(str(path), fast_load=True))
    try:
        return int(pe.get_offset_from_rva(rva))
    finally:
        pe.close()


def _walk_real_sections(data: bytes) -> list[dict[str, int | str]]:
    """Parse the full section table out of a real PE byte buffer.

    Args:
        data: Whole-file bytes of a real PE binary.

    Returns:
        list[dict[str, int | str]]: Parsed section-header dicts.
    """
    e_lfanew = read_dos_e_lfanew(data)
    _machine, num_sections, opt_size, _chars = unpack_coff_header(data, e_lfanew + 4)
    sections_offset = e_lfanew + 4 + _PE_COFF_HEADER_SIZE + opt_size
    return list(iterate_section_headers(data, sections_offset, num_sections))


def _import_directory_rva(data: bytes) -> int:
    """Read the import-directory RVA from a real PE byte buffer.

    Args:
        data: Whole-file bytes of a real PE binary.

    Returns:
        int: The import data-directory virtual address.
    """
    e_lfanew = read_dos_e_lfanew(data)
    opt_off = e_lfanew + PE_OPTIONAL_HEADER_OFFSET
    is_pe64 = is_pe64_optional_header(data, opt_off)
    import_off = get_data_directory_offset(
        e_lfanew,
        is_pe64=is_pe64,
        entry_index=_IMAGE_DIRECTORY_ENTRY_IMPORT,
    )
    rva, _size = read_data_directory_entry(data, import_off)
    return rva


class TestPeFormatHelpersAgainstRealDlls:
    """Validate PE byte helpers against real System32 DLLs via a pefile oracle."""

    def test_e_lfanew_matches_pefile(self, real_pe_dll: Path) -> None:
        """Verify ``read_dos_e_lfanew`` matches pefile's NT-headers offset.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        assert data[:2] == PE_DOS_SIGNATURE
        expected, _machine, _nsec, _opt = _pefile_coff_fields(real_pe_dll)
        assert read_dos_e_lfanew(data) == expected

    def test_coff_header_matches_pefile(self, real_pe_dlls: list[Path]) -> None:
        """Verify COFF machine / section-count / opt-header-size match pefile.

        Args:
            real_pe_dlls: Paths to real System32 DLL fixtures.
        """
        for dll in real_pe_dlls:
            data = dll.read_bytes()
            e_lfanew = read_dos_e_lfanew(data)
            assert data[e_lfanew : e_lfanew + 4] == PE_SIGNATURE, dll
            machine, num_sections, opt_size, _chars = unpack_coff_header(data, e_lfanew + 4)
            _lfanew, exp_machine, exp_nsec, exp_opt = _pefile_coff_fields(dll)
            assert machine == exp_machine, dll
            assert num_sections == exp_nsec, dll
            assert opt_size == exp_opt, dll

    def test_bitness_and_image_base_match_pefile(self, real_pe_dlls: list[Path]) -> None:
        """Verify PE32+ detection and ImageBase match pefile for real DLLs.

        Args:
            real_pe_dlls: Paths to real System32 DLL fixtures.
        """
        for dll in real_pe_dlls:
            data = dll.read_bytes()
            e_lfanew = read_dos_e_lfanew(data)
            opt_off = e_lfanew + PE_OPTIONAL_HEADER_OFFSET
            is_pe64 = is_pe64_optional_header(data, opt_off)
            image_base = unpack_optional_header_image_base(data, opt_off, is_pe64=is_pe64)
            magic, expected_base = _pefile_optional_fields(dll)
            expected_64 = magic == PE_OPTIONAL_HEADER_MAGIC_PE32PLUS
            assert is_pe64 is expected_64, dll
            assert image_base == expected_base, dll

    def test_section_table_matches_pefile(self, real_pe_dll: Path) -> None:
        """Verify the iterated section table matches pefile name-for-name.

        Real system DLLs carry eight or more sections (``.text``,
        ``.rdata``, ``.data``, ``.pdata``, ``.rsrc``, ``.reloc``, plus
        toolchain-specific extras) with non-trivial alignment slack -
        none of which the synthetic two-section buffer exercises.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        sections = _walk_real_sections(data)
        expected = _pefile_section_tuples(real_pe_dll)

        assert len(sections) == len(expected)
        actual = [
            (
                str(s["name"]),
                int(s["virtual_address"]),
                int(s["raw_offset"]),
                int(s["raw_size"]),
            )
            for s in sections
        ]
        assert actual == expected
        assert ".text" in {name for name, *_ in actual}

    def test_import_directory_offset_and_entry_match_pefile(self, real_pe_dll: Path) -> None:
        """Verify import data-directory arithmetic resolves the real entry.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        e_lfanew = read_dos_e_lfanew(data)
        opt_off = e_lfanew + PE_OPTIONAL_HEADER_OFFSET
        is_pe64 = is_pe64_optional_header(data, opt_off)
        import_off = get_data_directory_offset(
            e_lfanew,
            is_pe64=is_pe64,
            entry_index=_IMAGE_DIRECTORY_ENTRY_IMPORT,
        )
        rva, size = read_data_directory_entry(data, import_off)

        expected_rva, expected_size = _pefile_import_directory_entry(real_pe_dll)
        assert rva == expected_rva
        assert size == expected_size
        assert rva > 0, "real system DLL must declare an import directory"

    def test_rva_to_file_offset_matches_pefile(self, real_pe_dll: Path) -> None:
        """Verify RVA translation lands at pefile's reported file offset.

        Resolves the import-directory RVA to a file offset using the real
        section table and checks it against pefile's own
        ``get_offset_from_rva``.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        sections = _walk_real_sections(data)
        rva = _import_directory_rva(data)

        file_offset = rva_to_file_offset(sections, rva)
        assert file_offset is not None

        expected_offset = _pefile_offset_from_rva(real_pe_dll, rva)
        assert file_offset == expected_offset

    def test_optional_header_size_matches_layout(self, real_pe_dll: Path) -> None:
        """Verify standard optional-header size is consistent with bitness.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        e_lfanew = read_dos_e_lfanew(data)
        opt_off = e_lfanew + PE_OPTIONAL_HEADER_OFFSET
        is_pe64 = is_pe64_optional_header(data, opt_off)
        standard_size = optional_header_size_for(is_pe64=is_pe64)
        _machine, _n, declared_size, _c = unpack_coff_header(data, e_lfanew + 4)
        assert declared_size >= standard_size


class TestDetectFormatAgainstRealBinaries:
    """Validate magic-byte and architecture detection against real binaries."""

    def test_real_pe_detection(self, real_pe_dlls: list[Path]) -> None:
        """Verify real DLLs report PE x86_64 64-bit.

        Args:
            real_pe_dlls: Paths to real System32 DLL fixtures.
        """
        for dll in real_pe_dlls:
            data = dll.read_bytes()
            assert detect_format(data) == "pe", dll
            fmt, arch, is_64 = detect_format_and_arch(data)
            assert fmt == "pe", dll
            assert arch == "x86_64", dll
            assert is_64 is True, dll

    def test_real_pe_machine_round_trip(self, real_pe_dll: Path) -> None:
        """Verify the real COFF machine maps through ``pe_machine_to_arch``.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
        """
        data = real_pe_dll.read_bytes()
        e_lfanew = read_dos_e_lfanew(data)
        machine = int(struct.unpack_from("<H", data, e_lfanew + 4)[0])
        assert machine == PE_MACHINE_AMD64
        arch, is_64 = pe_machine_to_arch(machine)
        assert arch == "x86_64"
        assert is_64 is True

    def test_real_elf_detection(self, real_elf_binary: Path) -> None:
        """Verify the committed ELF fixture detects as ELF x86_64.

        Args:
            real_elf_binary: Path to the committed real ELF fixture.
        """
        data = real_elf_binary.read_bytes()
        assert detect_format(data) == "elf"
        fmt, arch, is_64 = detect_format_and_arch(data)
        assert fmt == "elf"
        assert arch == "x86_64"
        assert is_64 is True

    def test_real_macho_detection(self, real_macho_binary: Path) -> None:
        """Verify the committed Mach-O fixture detects as Mach-O x86_64.

        Args:
            real_macho_binary: Path to the committed real Mach-O fixture.
        """
        data = real_macho_binary.read_bytes()
        assert detect_format(data) == "macho"
        fmt, arch, is_64 = detect_format_and_arch(data)
        assert fmt == "macho"
        assert arch == "x86_64"
        assert is_64 is True

    def test_real_binaries_have_distinct_formats(
        self,
        real_pe_dll: Path,
        real_elf_binary: Path,
        real_macho_binary: Path,
    ) -> None:
        """Verify the three real-binary families are classified distinctly.

        Args:
            real_pe_dll: Path to a real System32 DLL fixture.
            real_elf_binary: Path to the committed real ELF fixture.
            real_macho_binary: Path to the committed real Mach-O fixture.
        """
        formats = {
            detect_format(real_pe_dll.read_bytes()),
            detect_format(real_elf_binary.read_bytes()),
            detect_format(real_macho_binary.read_bytes()),
        }
        assert formats == {"pe", "elf", "macho"}


class TestElfArchDetectionAgainstRealBinary:
    """Cross-check ELF arch detection against the real fixture's header fields."""

    def test_elf_header_fields_drive_detection(self, real_elf_binary: Path) -> None:
        """Verify detection agrees with the real ELF's raw header fields.

        Independently reads ``EI_CLASS`` (offset 4), ``EI_DATA``
        (offset 5) and ``e_machine`` (offset 0x12) from the genuine ELF,
        confirms those fields encode an ELFCLASS64 little-endian x86-64
        binary, then asserts the public :func:`detect_format_and_arch`
        decoder reports the same architecture and bitness.

        Args:
            real_elf_binary: Path to the committed real ELF fixture.
        """
        data = real_elf_binary.read_bytes()
        assert data[:4] == ELF_MAGIC
        big_endian = 2
        byte_order: Literal["little", "big"] = "big" if data[ELF_EI_DATA_OFFSET] == big_endian else "little"
        e_machine = int.from_bytes(data[ELF_E_MACHINE_OFFSET:ELF_E_MACHINE_END], byte_order)
        assert e_machine == ELF_EM_X86_64
        assert data[ELF_EI_CLASS_OFFSET] == ELF_CLASS_64

        fmt, arch, is_64 = detect_format_and_arch(data)
        assert fmt == "elf"
        assert arch == "x86_64"
        assert is_64 is True


class TestMachoArchDetectionAgainstRealBinary:
    """Cross-check Mach-O arch detection against the real fixture's header."""

    def test_macho_header_fields_drive_detection(self, real_macho_binary: Path) -> None:
        """Verify detection agrees with the real Mach-O's raw header fields.

        Independently reads the magic (which fixes endianness and
        bitness) and the ``cputype`` field, confirms they encode a
        little-endian 64-bit x86-64 image, then asserts the public
        :func:`detect_format_and_arch` decoder reports the same
        architecture and bitness.

        Args:
            real_macho_binary: Path to the committed real Mach-O fixture.
        """
        data = real_macho_binary.read_bytes()
        little_endian_64 = b"\xcf\xfa\xed\xfe"
        assert data[:4] == little_endian_64
        cpu_type = int.from_bytes(data[4:8], "little")
        assert cpu_type == MACHO_CPU_TYPE_X86_64

        fmt, arch, is_64 = detect_format_and_arch(data)
        assert fmt == "macho"
        assert arch == "x86_64"
        assert is_64 is True
