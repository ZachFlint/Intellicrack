# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the shared PE format parsing helpers.

The fixtures in this module assemble real PE32 and PE32+ byte buffers
from raw ``struct.pack`` calls so the helpers exercise the same code
paths as the bridge call sites without needing on-disk binaries or
mocks. Every assertion validates a structural invariant that the
upstream callers (x64dbg.py, hex_editor.py, _templates.py) rely on.
"""

from __future__ import annotations

import struct

import pytest

from intellicrack.bridges._pe_format import (
    ELF_CLASS_64,
    ELF_E_MACHINE_OFFSET,
    ELF_EI_CLASS_OFFSET,
    ELF_EI_DATA_OFFSET,
    ELF_EM_386,
    ELF_EM_AARCH64,
    ELF_EM_ARM,
    ELF_EM_MIPS,
    ELF_EM_PPC,
    ELF_EM_PPC64,
    ELF_EM_RISCV,
    ELF_EM_X86_64,
    ELF_MAGIC,
    MACHO_CPU_TYPE_ARM,
    MACHO_CPU_TYPE_ARM64,
    MACHO_CPU_TYPE_PPC,
    MACHO_CPU_TYPE_PPC64,
    MACHO_CPU_TYPE_X86,
    MACHO_CPU_TYPE_X86_64,
    MACHO_MAGIC_BE32,
    MACHO_MAGIC_BE64,
    MACHO_MAGIC_LE32,
    MACHO_MAGIC_LE64,
    PE32_OPTIONAL_HEADER_SIZE,
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_COFF_HEADER_SIZE,
    PE_DATA_DIRECTORY_ENTRY_SIZE,
    PE_DOS_HEADER_SIZE,
    PE_DOS_LFANEW_OFFSET,
    PE_DOS_SIGNATURE,
    PE_DOS_SIGNATURE_INT,
    PE_MACHINE_AMD64,
    PE_MACHINE_ARM,
    PE_MACHINE_ARM64,
    PE_MACHINE_ARMNT,
    PE_MACHINE_I386,
    PE_MACHINE_IA64,
    PE_MACHINE_MIPS,
    PE_MACHINE_MIPS16,
    PE_MACHINE_POWERPC,
    PE_MACHINE_POWERPCFP,
    PE_MACHINE_RISCV32,
    PE_MACHINE_RISCV64,
    PE_MACHINE_RISCV128,
    PE_OPTIONAL_HEADER_MAGIC_PE32,
    PE_OPTIONAL_HEADER_MAGIC_PE32PLUS,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SECTION_CHARACTERISTIC_EXECUTE,
    PE_SECTION_CHARACTERISTIC_READ,
    PE_SECTION_CHARACTERISTIC_WRITE,
    PE_SECTION_HEADER_SIZE,
    PE_SIGNATURE,
    PE_SIGNATURE_INT,
    ZIP_MAGIC,
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
    unpack_section_header,
)


_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_I386 = 0x014C
_DEFAULT_CHARACTERISTICS = 0x2102
_DEFAULT_IMAGE_BASE_PE32 = 0x00400000
_DEFAULT_IMAGE_BASE_PE64 = 0x00007FF600000000


def _build_dos_header(e_lfanew: int) -> bytes:
    """Build a 64-byte DOS header buffer with the given e_lfanew value.

    Args:
        e_lfanew: NT-headers pointer value to embed at offset 0x3C.

    Returns:
        bytes: DOS header buffer of exactly ``PE_DOS_HEADER_SIZE`` bytes.
    """
    buf = bytearray(PE_DOS_HEADER_SIZE)
    buf[0:2] = PE_DOS_SIGNATURE
    struct.pack_into("<I", buf, PE_DOS_LFANEW_OFFSET, e_lfanew)
    return bytes(buf)


def _build_coff_header(
    *,
    machine: int,
    number_of_sections: int,
    size_of_optional_header: int,
    characteristics: int = _DEFAULT_CHARACTERISTICS,
) -> bytes:
    """Build a COFF File Header (20 bytes) with the given fields.

    Args:
        machine: ``IMAGE_FILE_MACHINE_*`` value.
        number_of_sections: Section count.
        size_of_optional_header: Optional Header size in bytes.
        characteristics: ``IMAGE_FILE_*`` flags.

    Returns:
        bytes: COFF header buffer of exactly ``PE_COFF_HEADER_SIZE``
            bytes.
    """
    return struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        0,
        0,
        0,
        size_of_optional_header,
        characteristics,
    )


def _build_section_header(
    *,
    name: bytes,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> bytes:
    """Build an IMAGE_SECTION_HEADER (40 bytes) with the given fields.

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


def _build_optional_header(
    *,
    is_pe64: bool,
    image_base: int,
    num_data_directories: int = 16,
) -> bytes:
    """Build a PE32 or PE32+ Optional Header followed by data directories.

    Args:
        is_pe64: ``True`` for PE32+ (64-bit), ``False`` for PE32.
        image_base: ``ImageBase`` value to embed.
        num_data_directories: Number of trailing data directory entries
            to append (each ``PE_DATA_DIRECTORY_ENTRY_SIZE`` bytes,
            zero-initialised).

    Returns:
        bytes: Optional Header followed by ``num_data_directories``
            empty data directory entries.
    """
    base_size = PE32PLUS_OPTIONAL_HEADER_SIZE if is_pe64 else PE32_OPTIONAL_HEADER_SIZE
    buf = bytearray(base_size)
    if is_pe64:
        struct.pack_into("<H", buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32PLUS)
        struct.pack_into("<Q", buf, 24, image_base)
    else:
        struct.pack_into("<H", buf, 0, PE_OPTIONAL_HEADER_MAGIC_PE32)
        struct.pack_into("<I", buf, 28, image_base)
    return bytes(buf) + (b"\x00" * (PE_DATA_DIRECTORY_ENTRY_SIZE * num_data_directories))


def _build_pe_image(
    *,
    is_pe64: bool,
    sections: list[bytes],
    image_base: int,
    machine: int | None = None,
) -> tuple[bytes, int]:
    """Build a complete-enough PE image buffer for the helpers.

    Args:
        is_pe64: ``True`` to emit PE32+, ``False`` for PE32.
        sections: Pre-built section header bytes (40 each).
        image_base: ``ImageBase`` to embed in the Optional Header.
        machine: Override the COFF Machine field. Defaults to AMD64
            for ``is_pe64=True`` and I386 otherwise.

    Returns:
        tuple[bytes, int]: ``(buffer, e_lfanew)`` — the full image
            buffer and the NT-headers offset embedded in its DOS
            header.
    """
    e_lfanew = PE_DOS_HEADER_SIZE
    optional_header = _build_optional_header(is_pe64=is_pe64, image_base=image_base)
    coff_machine = machine if machine is not None else (_IMAGE_FILE_MACHINE_AMD64 if is_pe64 else _IMAGE_FILE_MACHINE_I386)
    coff = _build_coff_header(
        machine=coff_machine,
        number_of_sections=len(sections),
        size_of_optional_header=len(optional_header),
    )
    nt_headers = PE_SIGNATURE + coff + optional_header + b"".join(sections)
    return _build_dos_header(e_lfanew) + nt_headers, e_lfanew


class TestReadDosELfanew:
    """Validate :func:`read_dos_e_lfanew` against assembled DOS headers."""

    def test_returns_value_at_0x3c(self) -> None:
        """Verify the function reads the u32 at offset 0x3C."""
        buf = _build_dos_header(0x80)
        assert read_dos_e_lfanew(buf) == 0x80

    def test_zero_e_lfanew(self) -> None:
        """Verify zero is returned when ``e_lfanew`` is zero."""
        buf = _build_dos_header(0)
        assert read_dos_e_lfanew(buf) == 0

    def test_short_buffer_raises_struct_error(self) -> None:
        """Verify a buffer shorter than 0x40 raises :class:`struct.error`."""
        with pytest.raises(struct.error):
            read_dos_e_lfanew(b"MZ")


class TestUnpackCoffHeader:
    """Validate :func:`unpack_coff_header` against synthetic COFF headers."""

    def test_amd64_unpack(self) -> None:
        """Verify all four COFF fields round-trip for an AMD64 header."""
        coff = _build_coff_header(
            machine=_IMAGE_FILE_MACHINE_AMD64,
            number_of_sections=5,
            size_of_optional_header=PE32PLUS_OPTIONAL_HEADER_SIZE,
            characteristics=0x2022,
        )
        machine, num_sections, opt_size, characteristics = unpack_coff_header(coff, 0)
        assert machine == _IMAGE_FILE_MACHINE_AMD64
        assert num_sections == 5
        assert opt_size == PE32PLUS_OPTIONAL_HEADER_SIZE
        assert characteristics == 0x2022

    def test_i386_unpack(self) -> None:
        """Verify a 32-bit COFF header decodes correctly."""
        coff = _build_coff_header(
            machine=_IMAGE_FILE_MACHINE_I386,
            number_of_sections=3,
            size_of_optional_header=PE32_OPTIONAL_HEADER_SIZE,
        )
        machine, num_sections, opt_size, _characteristics = unpack_coff_header(coff, 0)
        assert machine == _IMAGE_FILE_MACHINE_I386
        assert num_sections == 3
        assert opt_size == PE32_OPTIONAL_HEADER_SIZE

    def test_offset_into_larger_buffer(self) -> None:
        """Verify the helper honors a non-zero offset."""
        prefix = b"\xff" * 16
        coff = _build_coff_header(
            machine=_IMAGE_FILE_MACHINE_I386,
            number_of_sections=2,
            size_of_optional_header=PE32_OPTIONAL_HEADER_SIZE,
        )
        buf = prefix + coff
        machine, num_sections, opt_size, _characteristics = unpack_coff_header(buf, len(prefix))
        assert machine == _IMAGE_FILE_MACHINE_I386
        assert num_sections == 2
        assert opt_size == PE32_OPTIONAL_HEADER_SIZE


class TestIsPe64OptionalHeader:
    """Validate :func:`is_pe64_optional_header` for both PE32 and PE32+."""

    def test_pe32_returns_false(self) -> None:
        """Verify a PE32 magic value returns ``False``."""
        opt = _build_optional_header(is_pe64=False, image_base=_DEFAULT_IMAGE_BASE_PE32)
        assert is_pe64_optional_header(opt, 0) is False

    def test_pe32plus_returns_true(self) -> None:
        """Verify a PE32+ magic value returns ``True``."""
        opt = _build_optional_header(is_pe64=True, image_base=_DEFAULT_IMAGE_BASE_PE64)
        assert is_pe64_optional_header(opt, 0) is True

    def test_unknown_magic_returns_false(self) -> None:
        """Verify an unrecognised magic value yields ``False``."""
        buf = struct.pack("<H", 0x107) + b"\x00" * 200
        assert is_pe64_optional_header(buf, 0) is False


class TestOptionalHeaderSizeFor:
    """Validate :func:`optional_header_size_for` returns the canonical sizes."""

    def test_pe32(self) -> None:
        """Verify PE32 returns 96 bytes."""
        assert optional_header_size_for(is_pe64=False) == PE32_OPTIONAL_HEADER_SIZE

    def test_pe32plus(self) -> None:
        """Verify PE32+ returns 112 bytes."""
        assert optional_header_size_for(is_pe64=True) == PE32PLUS_OPTIONAL_HEADER_SIZE


class TestGetDataDirectoryOffset:
    """Validate :func:`get_data_directory_offset` arithmetic."""

    def test_pe32_export_directory(self) -> None:
        """Verify entry index 0 points to the right offset for PE32."""
        offset = get_data_directory_offset(0, is_pe64=False, entry_index=0)
        assert offset == PE_OPTIONAL_HEADER_OFFSET + PE32_OPTIONAL_HEADER_SIZE

    def test_pe64_export_directory(self) -> None:
        """Verify entry index 0 points to the right offset for PE32+."""
        offset = get_data_directory_offset(0, is_pe64=True, entry_index=0)
        assert offset == PE_OPTIONAL_HEADER_OFFSET + PE32PLUS_OPTIONAL_HEADER_SIZE

    def test_tls_directory_index_9(self) -> None:
        """Verify TLS directory (entry index 9) computation matches legacy arithmetic."""
        legacy_pe64 = 24 + (1 * 112 + (1 - 1) * 96) + 72
        helper_pe64 = get_data_directory_offset(0, is_pe64=True, entry_index=9)
        assert helper_pe64 == legacy_pe64

        legacy_pe32 = 24 + (0 * 112 + (1 - 0) * 96) + 72
        helper_pe32 = get_data_directory_offset(0, is_pe64=False, entry_index=9)
        assert helper_pe32 == legacy_pe32

    def test_resource_directory_index_2(self) -> None:
        """Verify Resource directory (entry index 2) computation matches legacy arithmetic."""
        legacy_pe64 = 24 + (1 * 112 + (1 - 1) * 96) + 16
        helper_pe64 = get_data_directory_offset(0, is_pe64=True, entry_index=2)
        assert helper_pe64 == legacy_pe64

    def test_with_buffer_offset(self) -> None:
        """Verify a non-zero ``nt_headers_offset`` shifts the result by exactly that amount."""
        offset_zero = get_data_directory_offset(0, is_pe64=True, entry_index=4)
        offset_at_e_lfanew = get_data_directory_offset(0x80, is_pe64=True, entry_index=4)
        assert offset_at_e_lfanew == offset_zero + 0x80


class TestReadDataDirectoryEntry:
    """Validate :func:`read_data_directory_entry` decodes 8-byte entries."""

    def test_round_trip(self) -> None:
        """Verify packed RVA/Size pairs round-trip through the reader."""
        entry = struct.pack("<II", 0x1000, 0x40)
        rva, size = read_data_directory_entry(entry, 0)
        assert rva == 0x1000
        assert size == 0x40

    def test_zero_entry(self) -> None:
        """Verify zero entries return ``(0, 0)``."""
        entry = b"\x00" * 8
        rva, size = read_data_directory_entry(entry, 0)
        assert rva == 0
        assert size == 0

    def test_offset_into_array(self) -> None:
        """Verify the helper indexes correctly into a multi-entry array."""
        entries = struct.pack("<II", 0xAA, 0xBB) + struct.pack("<II", 0xCC, 0xDD)
        rva, size = read_data_directory_entry(entries, PE_DATA_DIRECTORY_ENTRY_SIZE)
        assert rva == 0xCC
        assert size == 0xDD


class TestUnpackOptionalHeaderImageBase:
    """Validate :func:`unpack_optional_header_image_base` for both bitnesses."""

    def test_pe32_image_base(self) -> None:
        """Verify PE32 reads ``ImageBase`` from offset +28 as ``u32``."""
        opt = _build_optional_header(is_pe64=False, image_base=_DEFAULT_IMAGE_BASE_PE32)
        assert unpack_optional_header_image_base(opt, 0, is_pe64=False) == _DEFAULT_IMAGE_BASE_PE32

    def test_pe64_image_base(self) -> None:
        """Verify PE32+ reads ``ImageBase`` from offset +24 as ``u64``."""
        opt = _build_optional_header(is_pe64=True, image_base=_DEFAULT_IMAGE_BASE_PE64)
        assert unpack_optional_header_image_base(opt, 0, is_pe64=True) == _DEFAULT_IMAGE_BASE_PE64


class TestUnpackSectionHeader:
    """Validate :func:`unpack_section_header` decodes every field."""

    def test_text_section_decodes(self) -> None:
        """Verify a typical .text section round-trips through the unpacker."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        result = unpack_section_header(sec, 0)
        assert result["name"] == ".text"
        assert result["virtual_size"] == 0x1000
        assert result["virtual_address"] == 0x1000
        assert result["raw_size"] == 0x1000
        assert result["raw_offset"] == 0x400
        characteristics = result["characteristics"]
        assert isinstance(characteristics, int)
        assert characteristics & PE_SECTION_CHARACTERISTIC_READ
        assert characteristics & PE_SECTION_CHARACTERISTIC_EXECUTE
        assert not (characteristics & PE_SECTION_CHARACTERISTIC_WRITE)

    def test_data_section_writable(self) -> None:
        """Verify a .data section reports writable characteristics."""
        sec = _build_section_header(
            name=b".data",
            virtual_size=0x200,
            virtual_address=0x2000,
            raw_size=0x200,
            raw_offset=0x1400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_WRITE,
        )
        result = unpack_section_header(sec, 0)
        assert result["name"] == ".data"
        characteristics = result["characteristics"]
        assert isinstance(characteristics, int)
        assert characteristics & PE_SECTION_CHARACTERISTIC_WRITE

    def test_section_with_padded_name(self) -> None:
        """Verify NUL-padded names are decoded without padding in the result."""
        sec = _build_section_header(
            name=b"AB",
            virtual_size=0,
            virtual_address=0,
            raw_size=0,
            raw_offset=0,
            characteristics=0,
        )
        result = unpack_section_header(sec, 0)
        assert result["name"] == "AB"

    def test_offset_into_section_table(self) -> None:
        """Verify the helper honors a non-zero offset within a multi-section buffer."""
        sec_a = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        sec_b = _build_section_header(
            name=b".rdata",
            virtual_size=0x100,
            virtual_address=0x2000,
            raw_size=0x200,
            raw_offset=0x1400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ,
        )
        buf = sec_a + sec_b
        second = unpack_section_header(buf, PE_SECTION_HEADER_SIZE)
        assert second["name"] == ".rdata"
        assert second["virtual_address"] == 0x2000


class TestIterateSectionHeaders:
    """Validate :func:`iterate_section_headers` yields each entry exactly once."""

    def test_yields_all_sections(self) -> None:
        """Verify all requested sections are produced."""
        sec_a = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        sec_b = _build_section_header(
            name=b".rdata",
            virtual_size=0x100,
            virtual_address=0x2000,
            raw_size=0x200,
            raw_offset=0x1400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ,
        )
        buf = sec_a + sec_b
        sections = list(iterate_section_headers(buf, 0, 2))
        assert len(sections) == 2
        assert sections[0]["name"] == ".text"
        assert sections[1]["name"] == ".rdata"

    def test_zero_count_yields_nothing(self) -> None:
        """Verify a count of zero produces no entries."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=0,
        )
        assert list(iterate_section_headers(sec, 0, 0)) == []

    def test_negative_count_yields_nothing(self) -> None:
        """Verify a negative count produces no entries."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0,
            virtual_address=0,
            raw_size=0,
            raw_offset=0,
            characteristics=0,
        )
        assert list(iterate_section_headers(sec, 0, -1)) == []

    def test_truncated_buffer_stops_early(self) -> None:
        """Verify the iterator stops when the buffer is too short."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=0,
        )
        truncated = sec[:30]
        assert list(iterate_section_headers(truncated, 0, 1)) == []

    def test_partial_truncation(self) -> None:
        """Verify only the fully-parseable entries are emitted."""
        sec_a = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=0,
        )
        sec_b = _build_section_header(
            name=b".rdata",
            virtual_size=0,
            virtual_address=0,
            raw_size=0,
            raw_offset=0,
            characteristics=0,
        )
        buf = sec_a + sec_b[:20]
        sections = list(iterate_section_headers(buf, 0, 2))
        assert len(sections) == 1
        assert sections[0]["name"] == ".text"


class TestRvaToFileOffset:
    """Validate :func:`rva_to_file_offset` translates RVAs through the section table."""

    def test_address_inside_text_section(self) -> None:
        """Verify an RVA inside .text resolves to the correct file offset."""
        sections: list[dict[str, int | str]] = [
            {
                "name": ".text",
                "virtual_size": 0x1000,
                "virtual_address": 0x1000,
                "raw_size": 0x1000,
                "raw_offset": 0x400,
                "pointer_to_relocations": 0,
                "pointer_to_linenumbers": 0,
                "number_of_relocations": 0,
                "number_of_linenumbers": 0,
                "characteristics": 0,
            },
        ]
        assert rva_to_file_offset(sections, 0x1500) == 0x900

    def test_address_at_section_start(self) -> None:
        """Verify an RVA exactly at the section's start maps to ``raw_offset``."""
        sections: list[dict[str, int | str]] = [
            {
                "name": ".text",
                "virtual_size": 0x1000,
                "virtual_address": 0x1000,
                "raw_size": 0x1000,
                "raw_offset": 0x400,
                "pointer_to_relocations": 0,
                "pointer_to_linenumbers": 0,
                "number_of_relocations": 0,
                "number_of_linenumbers": 0,
                "characteristics": 0,
            },
        ]
        assert rva_to_file_offset(sections, 0x1000) == 0x400

    def test_address_outside_any_section(self) -> None:
        """Verify an RVA outside every section returns ``None``."""
        sections: list[dict[str, int | str]] = [
            {
                "name": ".text",
                "virtual_size": 0x1000,
                "virtual_address": 0x1000,
                "raw_size": 0x1000,
                "raw_offset": 0x400,
                "pointer_to_relocations": 0,
                "pointer_to_linenumbers": 0,
                "number_of_relocations": 0,
                "number_of_linenumbers": 0,
                "characteristics": 0,
            },
        ]
        assert rva_to_file_offset(sections, 0x5000) is None

    def test_picks_correct_section_among_many(self) -> None:
        """Verify the helper selects the correct section in a multi-section table."""
        sections: list[dict[str, int | str]] = [
            {
                "name": ".text",
                "virtual_size": 0x1000,
                "virtual_address": 0x1000,
                "raw_size": 0x1000,
                "raw_offset": 0x400,
                "pointer_to_relocations": 0,
                "pointer_to_linenumbers": 0,
                "number_of_relocations": 0,
                "number_of_linenumbers": 0,
                "characteristics": 0,
            },
            {
                "name": ".rdata",
                "virtual_size": 0x200,
                "virtual_address": 0x2000,
                "raw_size": 0x200,
                "raw_offset": 0x1400,
                "pointer_to_relocations": 0,
                "pointer_to_linenumbers": 0,
                "number_of_relocations": 0,
                "number_of_linenumbers": 0,
                "characteristics": 0,
            },
        ]
        assert rva_to_file_offset(sections, 0x2050) == 0x1450


class TestMagicConstants:
    """Validate the canonical magic-byte / signature constants.

    These values must match the Microsoft PE/COFF specification exactly
    because every bridge that consolidates onto :mod:`_pe_format`
    compares unpacked bytes (or unpacked little-endian integers)
    against them.
    """

    def test_dos_signature_bytes_value(self) -> None:
        """Verify the DOS signature is the literal ``b'MZ'``."""
        assert PE_DOS_SIGNATURE == b"MZ"

    def test_dos_signature_int_value(self) -> None:
        """Verify the DOS signature integer matches the spec value 0x5A4D."""
        assert PE_DOS_SIGNATURE_INT == 0x5A4D

    def test_dos_signature_int_round_trips_bytes(self) -> None:
        """Verify ``PE_DOS_SIGNATURE_INT`` equals the little-endian decode of ``PE_DOS_SIGNATURE``."""
        assert int.from_bytes(PE_DOS_SIGNATURE, "little") == PE_DOS_SIGNATURE_INT

    def test_pe_signature_bytes_value(self) -> None:
        r"""Verify the PE signature is the literal ``b'PE\x00\x00'``."""
        assert PE_SIGNATURE == b"PE\x00\x00"

    def test_pe_signature_int_value(self) -> None:
        """Verify the PE signature integer matches the spec value 0x00004550."""
        assert PE_SIGNATURE_INT == 0x00004550

    def test_pe_signature_int_round_trips_bytes(self) -> None:
        """Verify ``PE_SIGNATURE_INT`` equals the little-endian decode of ``PE_SIGNATURE``."""
        assert int.from_bytes(PE_SIGNATURE, "little") == PE_SIGNATURE_INT

    def test_dos_lfanew_offset_value(self) -> None:
        """Verify ``e_lfanew`` lives at offset 0x3C in the DOS header."""
        assert PE_DOS_LFANEW_OFFSET == 0x3C

    def test_dos_header_size_value(self) -> None:
        """Verify the DOS header is 64 bytes (0x40)."""
        assert PE_DOS_HEADER_SIZE == 0x40

    def test_optional_header_offset_value(self) -> None:
        """Verify the Optional Header offset within NT headers is 24 (0x18).

        That is, 4 bytes of PE signature plus 20 bytes of COFF File Header.
        """
        assert PE_OPTIONAL_HEADER_OFFSET == 0x18
        assert PE_OPTIONAL_HEADER_OFFSET == 4 + PE_COFF_HEADER_SIZE

    def test_optional_header_magic_pe32plus_value(self) -> None:
        """Verify the PE32+ optional-header magic equals 0x20B."""
        assert PE_OPTIONAL_HEADER_MAGIC_PE32PLUS == 0x20B

    def test_optional_header_magic_pe32_value(self) -> None:
        """Verify the PE32 optional-header magic equals 0x10B."""
        assert PE_OPTIONAL_HEADER_MAGIC_PE32 == 0x10B

    def test_pe_signature_int_unpacks_from_signature_bytes(self) -> None:
        """Verify ``struct.unpack_from('<I', PE_SIGNATURE)`` matches ``PE_SIGNATURE_INT``."""
        assert struct.unpack_from("<I", PE_SIGNATURE)[0] == PE_SIGNATURE_INT

    def test_dos_signature_int_unpacks_from_signature_bytes(self) -> None:
        """Verify ``struct.unpack_from('<H', PE_DOS_SIGNATURE)`` matches ``PE_DOS_SIGNATURE_INT``."""
        assert struct.unpack_from("<H", PE_DOS_SIGNATURE)[0] == PE_DOS_SIGNATURE_INT


class TestEndToEndPe32:
    """Round-trip tests on a synthesised complete PE32 image buffer."""

    def test_full_walk_matches_inputs(self) -> None:
        """Verify a full PE32 walk reproduces every embedded value."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=False,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE32,
        )
        expected_opt_size = PE32_OPTIONAL_HEADER_SIZE + 16 * PE_DATA_DIRECTORY_ENTRY_SIZE

        # Step 1: DOS -> e_lfanew
        assert read_dos_e_lfanew(image[:PE_DOS_HEADER_SIZE]) == e_lfanew

        # Step 2: COFF File Header
        assert image[e_lfanew : e_lfanew + 4] == PE_SIGNATURE
        machine, num_sections, opt_size, _flags = unpack_coff_header(image, e_lfanew + 4)
        assert machine == _IMAGE_FILE_MACHINE_I386
        assert num_sections == 1
        assert opt_size == expected_opt_size

        # Step 3: Optional Header
        opt_offset = e_lfanew + 4 + PE_COFF_HEADER_SIZE
        assert is_pe64_optional_header(image, opt_offset) is False
        assert unpack_optional_header_image_base(image, opt_offset, is_pe64=False) == _DEFAULT_IMAGE_BASE_PE32

        # Step 4: Section walk
        sections_offset = opt_offset + opt_size
        sections = list(iterate_section_headers(image, sections_offset, num_sections))
        assert len(sections) == 1
        assert sections[0]["name"] == ".text"
        assert sections[0]["virtual_address"] == 0x1000

        # Step 5: RVA->file offset
        assert rva_to_file_offset(sections, 0x1100) == 0x500


class TestEndToEndPe32Plus:
    """Round-trip tests on a synthesised complete PE32+ image buffer."""

    def test_full_walk_matches_inputs(self) -> None:
        """Verify a full PE32+ walk reproduces every embedded value."""
        sec = _build_section_header(
            name=b".rdata",
            virtual_size=0x500,
            virtual_address=0x2000,
            raw_size=0x600,
            raw_offset=0x1400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=True,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE64,
        )

        expected_opt_size = PE32PLUS_OPTIONAL_HEADER_SIZE + 16 * PE_DATA_DIRECTORY_ENTRY_SIZE
        assert read_dos_e_lfanew(image[:PE_DOS_HEADER_SIZE]) == e_lfanew
        machine, num_sections, opt_size, _flags = unpack_coff_header(image, e_lfanew + 4)
        assert machine == _IMAGE_FILE_MACHINE_AMD64
        assert num_sections == 1
        assert opt_size == expected_opt_size

        opt_offset = e_lfanew + 4 + PE_COFF_HEADER_SIZE
        assert is_pe64_optional_header(image, opt_offset) is True
        assert unpack_optional_header_image_base(image, opt_offset, is_pe64=True) == _DEFAULT_IMAGE_BASE_PE64

        sections_offset = opt_offset + opt_size
        sections = list(iterate_section_headers(image, sections_offset, num_sections))
        assert sections[0]["name"] == ".rdata"
        assert sections[0]["raw_size"] == 0x600
        assert rva_to_file_offset(sections, 0x2010) == 0x1410

    def test_data_directory_offset_matches_legacy(self) -> None:
        """Verify Data Directory addressing matches the legacy x64dbg arithmetic."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x100,
            virtual_address=0x1000,
            raw_size=0x100,
            raw_offset=0x400,
            characteristics=0,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=True,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE64,
        )

        for entry_index in (0, 1, 2, 9, 12):
            helper_offset = get_data_directory_offset(e_lfanew, is_pe64=True, entry_index=entry_index)
            legacy_offset = e_lfanew + 24 + 112 + entry_index * 8
            assert helper_offset == legacy_offset, f"entry index {entry_index}"

            rva, size = read_data_directory_entry(image, helper_offset)
            assert rva == 0
            assert size == 0


class TestPeMachineToArch:
    """Validate :func:`pe_machine_to_arch` against the documented machine table."""

    def test_amd64_maps_to_x86_64_64bit(self) -> None:
        """Verify AMD64 (0x8664) maps to ``("x86_64", True)``."""
        assert pe_machine_to_arch(PE_MACHINE_AMD64) == ("x86_64", True)

    def test_i386_maps_to_x86_32bit(self) -> None:
        """Verify I386 (0x014C) maps to ``("x86", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_I386) == ("x86", False)

    def test_arm_maps_to_arm_32bit(self) -> None:
        """Verify ARM (0x01C0) maps to ``("arm", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_ARM) == ("arm", False)

    def test_armnt_maps_to_arm_32bit(self) -> None:
        """Verify ARMNT (0x01C4) maps to ``("arm", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_ARMNT) == ("arm", False)

    def test_arm64_maps_to_arm64_64bit(self) -> None:
        """Verify ARM64 (0xAA64) maps to ``("arm64", True)``."""
        assert pe_machine_to_arch(PE_MACHINE_ARM64) == ("arm64", True)

    def test_ia64_maps_to_ia64_64bit(self) -> None:
        """Verify IA64 (0x0200) maps to ``("ia64", True)``."""
        assert pe_machine_to_arch(PE_MACHINE_IA64) == ("ia64", True)

    def test_mips_maps_to_mips_32bit(self) -> None:
        """Verify MIPS (0x0166) maps to ``("mips", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_MIPS) == ("mips", False)

    def test_mips16_maps_to_mips_32bit(self) -> None:
        """Verify MIPS16 (0x0266) maps to ``("mips", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_MIPS16) == ("mips", False)

    def test_powerpc_maps_to_ppc_32bit(self) -> None:
        """Verify POWERPC (0x01F0) maps to ``("ppc", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_POWERPC) == ("ppc", False)

    def test_powerpcfp_maps_to_ppc_32bit(self) -> None:
        """Verify POWERPCFP (0x01F1) maps to ``("ppc", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_POWERPCFP) == ("ppc", False)

    def test_riscv32_maps_to_riscv_32bit(self) -> None:
        """Verify RISCV32 (0x5032) maps to ``("riscv", False)``."""
        assert pe_machine_to_arch(PE_MACHINE_RISCV32) == ("riscv", False)

    def test_riscv64_maps_to_riscv64_64bit(self) -> None:
        """Verify RISCV64 (0x5064) maps to ``("riscv64", True)``."""
        assert pe_machine_to_arch(PE_MACHINE_RISCV64) == ("riscv64", True)

    def test_riscv128_maps_to_riscv128_64bit(self) -> None:
        """Verify RISCV128 (0x5128) maps to ``("riscv128", True)``."""
        assert pe_machine_to_arch(PE_MACHINE_RISCV128) == ("riscv128", True)

    def test_unknown_machine_returns_unknown_false(self) -> None:
        """Verify an unrecognised machine value returns ``("unknown", False)``."""
        assert pe_machine_to_arch(0xDEAD) == ("unknown", False)

    def test_zero_machine_returns_unknown_false(self) -> None:
        """Verify ``IMAGE_FILE_MACHINE_UNKNOWN`` (0) returns ``("unknown", False)``."""
        assert pe_machine_to_arch(0x0000) == ("unknown", False)

    def test_real_pe32_buffer_round_trip(self) -> None:
        """Verify the helper agrees with a parsed real-shape PE32 image."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x1000,
            virtual_address=0x1000,
            raw_size=0x1000,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=False,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE32,
        )
        machine, _num_sections, _opt_size, _flags = unpack_coff_header(image, e_lfanew + 4)
        arch, is_64bit = pe_machine_to_arch(machine)
        assert arch == "x86"
        assert is_64bit is False

    def test_real_pe32plus_buffer_round_trip(self) -> None:
        """Verify the helper agrees with a parsed real-shape PE32+ image."""
        sec = _build_section_header(
            name=b".rdata",
            virtual_size=0x500,
            virtual_address=0x2000,
            raw_size=0x600,
            raw_offset=0x1400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=True,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE64,
        )
        machine, _num_sections, _opt_size, _flags = unpack_coff_header(image, e_lfanew + 4)
        arch, is_64bit = pe_machine_to_arch(machine)
        assert arch == "x86_64"
        assert is_64bit is True

    def test_arm64_buffer_round_trip(self) -> None:
        """Verify a synthesised ARM64 PE image round-trips through ``pe_machine_to_arch``."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x100,
            virtual_address=0x1000,
            raw_size=0x100,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        image, e_lfanew = _build_pe_image(
            is_pe64=True,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE64,
            machine=PE_MACHINE_ARM64,
        )
        machine, _num_sections, _opt_size, _flags = unpack_coff_header(image, e_lfanew + 4)
        arch, is_64bit = pe_machine_to_arch(machine)
        assert arch == "arm64"
        assert is_64bit is True


def _build_elf_header(
    *,
    is_64: bool,
    big_endian: bool,
    e_machine: int,
) -> bytes:
    """Build a minimal ELF header buffer with the given identification fields.

    The returned buffer covers the full ``e_ident`` array and the
    ``e_machine`` field, which is everything the format-detection
    helpers inspect.

    Args:
        is_64: ``True`` to set ``EI_CLASS=ELFCLASS64``, ``False`` for
            ``ELFCLASS32``.
        big_endian: ``True`` to set ``EI_DATA=ELFDATA2MSB`` and pack
            ``e_machine`` big-endian; ``False`` for little-endian.
        e_machine: ELF ``e_machine`` value to embed at offset 0x12.

    Returns:
        bytes: A 64-byte buffer that begins with the ELF magic, has
            ``EI_CLASS`` / ``EI_DATA`` populated, and carries
            ``e_machine`` at the canonical offset.
    """
    buf = bytearray(64)
    buf[0:4] = ELF_MAGIC
    buf[ELF_EI_CLASS_OFFSET] = ELF_CLASS_64 if is_64 else 1
    buf[ELF_EI_DATA_OFFSET] = 2 if big_endian else 1
    fmt = ">H" if big_endian else "<H"
    struct.pack_into(fmt, buf, ELF_E_MACHINE_OFFSET, e_machine)
    return bytes(buf)


def _build_macho_header(*, magic: bytes, cpu_type: int) -> bytes:
    """Build a minimal Mach-O header buffer with the given magic and ``cputype``.

    Args:
        magic: One of the four Mach-O magic byte sequences. Determines
            both the bitness and the endianness used to pack
            ``cpu_type``.
        cpu_type: Mach-O ``cputype`` to embed immediately after the
            magic.

    Returns:
        bytes: A 32-byte buffer that begins with the magic and carries
            ``cpu_type`` packed in the matching byte order.
    """
    buf = bytearray(32)
    buf[0:4] = magic
    big_endian = magic in {MACHO_MAGIC_BE32, MACHO_MAGIC_BE64}
    fmt = ">I" if big_endian else "<I"
    struct.pack_into(fmt, buf, 4, cpu_type)
    return bytes(buf)


class TestDetectFormat:
    """Validate :func:`detect_format` against every supported magic."""

    def test_pe_magic(self) -> None:
        """Verify ``MZ`` magic returns ``"pe"``."""
        assert detect_format(b"MZ\x90\x00") == "pe"

    def test_pe_magic_minimal_buffer(self) -> None:
        """Verify ``MZ`` magic returns ``"pe"`` even with only two bytes."""
        assert detect_format(b"MZ") == "pe"

    def test_elf_magic(self) -> None:
        r"""Verify ``\x7fELF`` magic returns ``"elf"``."""
        assert detect_format(b"\x7fELF\x02\x01") == "elf"

    def test_macho_magic_be32(self) -> None:
        """Verify Mach-O 32-bit big-endian magic returns ``"macho"``."""
        assert detect_format(MACHO_MAGIC_BE32) == "macho"

    def test_macho_magic_le32(self) -> None:
        """Verify Mach-O 32-bit little-endian magic returns ``"macho"``."""
        assert detect_format(MACHO_MAGIC_LE32) == "macho"

    def test_macho_magic_be64(self) -> None:
        """Verify Mach-O 64-bit big-endian magic returns ``"macho"``."""
        assert detect_format(MACHO_MAGIC_BE64) == "macho"

    def test_macho_magic_le64(self) -> None:
        """Verify Mach-O 64-bit little-endian magic returns ``"macho"``."""
        assert detect_format(MACHO_MAGIC_LE64) == "macho"

    def test_zip_magic(self) -> None:
        """Verify ZIP local-file-header magic returns ``"zip"``."""
        assert detect_format(ZIP_MAGIC) == "zip"

    def test_zip_magic_with_trailing_bytes(self) -> None:
        """Verify ZIP magic still resolves when followed by other data."""
        assert detect_format(ZIP_MAGIC + b"\x00" * 32) == "zip"

    def test_raw_unknown_magic(self) -> None:
        """Verify unrecognised four bytes resolve to ``"raw"``."""
        assert detect_format(b"\x00\x00\x00\x00") == "raw"

    def test_raw_too_short(self) -> None:
        """Verify an empty buffer resolves to ``"raw"``."""
        assert detect_format(b"") == "raw"

    def test_raw_one_byte(self) -> None:
        """Verify a single byte resolves to ``"raw"`` (insufficient for any magic)."""
        assert detect_format(b"\x7f") == "raw"

    def test_raw_three_bytes(self) -> None:
        """Verify three bytes that do not contain ``MZ`` resolve to ``"raw"``."""
        assert detect_format(b"\x7fEL") == "raw"


class TestDetectFormatAndArch:
    """Validate :func:`detect_format_and_arch` across PE / ELF / Mach-O / ZIP / raw inputs."""

    def test_pe32_i386(self) -> None:
        """Verify a PE32 image with I386 machine returns ``("pe", "x86", False)``."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x100,
            virtual_address=0x1000,
            raw_size=0x100,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        image, _e_lfanew = _build_pe_image(
            is_pe64=False,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE32,
            machine=_IMAGE_FILE_MACHINE_I386,
        )
        assert detect_format_and_arch(image) == ("pe", "x86", False)

    def test_pe32plus_amd64(self) -> None:
        """Verify a PE32+ image with AMD64 machine returns ``("pe", "x86_64", True)``."""
        sec = _build_section_header(
            name=b".text",
            virtual_size=0x100,
            virtual_address=0x1000,
            raw_size=0x100,
            raw_offset=0x400,
            characteristics=PE_SECTION_CHARACTERISTIC_READ | PE_SECTION_CHARACTERISTIC_EXECUTE,
        )
        image, _e_lfanew = _build_pe_image(
            is_pe64=True,
            sections=[sec],
            image_base=_DEFAULT_IMAGE_BASE_PE64,
            machine=_IMAGE_FILE_MACHINE_AMD64,
        )
        assert detect_format_and_arch(image) == ("pe", "x86_64", True)

    def test_pe_dos_only_returns_unknown_arch(self) -> None:
        """Verify a bare-DOS ``MZ`` buffer returns ``("pe", "unknown", False)``."""
        buf = bytearray(PE_DOS_HEADER_SIZE)
        buf[0:2] = PE_DOS_SIGNATURE
        struct.pack_into("<I", buf, PE_DOS_LFANEW_OFFSET, 0)
        result = detect_format_and_arch(bytes(buf))
        assert result == ("pe", "unknown", False)

    def test_pe_invalid_signature_returns_unknown_arch(self) -> None:
        """Verify a PE buffer with a corrupted NT signature reports ``arch="unknown"``."""
        buf = bytearray(PE_DOS_HEADER_SIZE + 32)
        buf[0:2] = PE_DOS_SIGNATURE
        struct.pack_into("<I", buf, PE_DOS_LFANEW_OFFSET, PE_DOS_HEADER_SIZE)
        buf[PE_DOS_HEADER_SIZE : PE_DOS_HEADER_SIZE + 4] = b"XX\x00\x00"
        result = detect_format_and_arch(bytes(buf))
        assert result == ("pe", "unknown", False)

    def test_elf32_i386(self) -> None:
        """Verify an ELFCLASS32 little-endian header with EM_386 returns ``("elf", "x86", False)``."""
        buf = _build_elf_header(is_64=False, big_endian=False, e_machine=ELF_EM_386)
        assert detect_format_and_arch(buf) == ("elf", "x86", False)

    def test_elf64_x86_64(self) -> None:
        """Verify an ELFCLASS64 little-endian header with EM_X86_64 returns ``("elf", "x86_64", True)``."""
        buf = _build_elf_header(is_64=True, big_endian=False, e_machine=ELF_EM_X86_64)
        assert detect_format_and_arch(buf) == ("elf", "x86_64", True)

    def test_elf64_aarch64(self) -> None:
        """Verify an ELFCLASS64 header with EM_AARCH64 returns ``("elf", "arm64", True)``."""
        buf = _build_elf_header(is_64=True, big_endian=False, e_machine=ELF_EM_AARCH64)
        assert detect_format_and_arch(buf) == ("elf", "arm64", True)

    def test_elf32_arm(self) -> None:
        """Verify an ELFCLASS32 header with EM_ARM returns ``("elf", "arm", False)``."""
        buf = _build_elf_header(is_64=False, big_endian=False, e_machine=ELF_EM_ARM)
        assert detect_format_and_arch(buf) == ("elf", "arm", False)

    def test_elf64_mips_big_endian(self) -> None:
        """Verify a 64-bit big-endian ELF with EM_MIPS returns ``("elf", "mips64", True)``."""
        buf = _build_elf_header(is_64=True, big_endian=True, e_machine=ELF_EM_MIPS)
        assert detect_format_and_arch(buf) == ("elf", "mips64", True)

    def test_elf32_ppc(self) -> None:
        """Verify a 32-bit ELF with EM_PPC returns ``("elf", "ppc", False)``."""
        buf = _build_elf_header(is_64=False, big_endian=True, e_machine=ELF_EM_PPC)
        assert detect_format_and_arch(buf) == ("elf", "ppc", False)

    def test_elf64_ppc64(self) -> None:
        """Verify a 64-bit ELF with EM_PPC64 returns ``("elf", "ppc64", True)``."""
        buf = _build_elf_header(is_64=True, big_endian=True, e_machine=ELF_EM_PPC64)
        assert detect_format_and_arch(buf) == ("elf", "ppc64", True)

    def test_elf64_riscv(self) -> None:
        """Verify a 64-bit ELF with EM_RISCV returns ``("elf", "riscv64", True)``."""
        buf = _build_elf_header(is_64=True, big_endian=False, e_machine=ELF_EM_RISCV)
        assert detect_format_and_arch(buf) == ("elf", "riscv64", True)

    def test_elf32_riscv(self) -> None:
        """Verify a 32-bit ELF with EM_RISCV returns ``("elf", "riscv", False)``."""
        buf = _build_elf_header(is_64=False, big_endian=False, e_machine=ELF_EM_RISCV)
        assert detect_format_and_arch(buf) == ("elf", "riscv", False)

    def test_elf_unknown_machine(self) -> None:
        """Verify an ELF header with an unrecognised ``e_machine`` reports ``arch="unknown"``."""
        buf = _build_elf_header(is_64=False, big_endian=False, e_machine=0xFFFE)
        assert detect_format_and_arch(buf) == ("elf", "unknown", False)

    def test_macho_le64_x86_64(self) -> None:
        """Verify a 64-bit little-endian Mach-O with x86_64 cputype returns ``("macho", "x86_64", True)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_LE64, cpu_type=MACHO_CPU_TYPE_X86_64)
        assert detect_format_and_arch(buf) == ("macho", "x86_64", True)

    def test_macho_le32_x86(self) -> None:
        """Verify a 32-bit little-endian Mach-O with x86 cputype returns ``("macho", "x86", False)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_LE32, cpu_type=MACHO_CPU_TYPE_X86)
        assert detect_format_and_arch(buf) == ("macho", "x86", False)

    def test_macho_be64_arm64(self) -> None:
        """Verify a 64-bit big-endian Mach-O with arm64 cputype returns ``("macho", "arm64", True)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_BE64, cpu_type=MACHO_CPU_TYPE_ARM64)
        assert detect_format_and_arch(buf) == ("macho", "arm64", True)

    def test_macho_be32_arm(self) -> None:
        """Verify a 32-bit big-endian Mach-O with arm cputype returns ``("macho", "arm", False)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_BE32, cpu_type=MACHO_CPU_TYPE_ARM)
        assert detect_format_and_arch(buf) == ("macho", "arm", False)

    def test_macho_le64_ppc64(self) -> None:
        """Verify a 64-bit Mach-O with PPC64 cputype returns ``("macho", "ppc64", True)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_LE64, cpu_type=MACHO_CPU_TYPE_PPC64)
        assert detect_format_and_arch(buf) == ("macho", "ppc64", True)

    def test_macho_le32_ppc(self) -> None:
        """Verify a 32-bit Mach-O with PPC cputype returns ``("macho", "ppc", False)``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_LE32, cpu_type=MACHO_CPU_TYPE_PPC)
        assert detect_format_and_arch(buf) == ("macho", "ppc", False)

    def test_macho_unknown_cputype(self) -> None:
        """Verify a Mach-O header with an unrecognised ``cputype`` reports ``arch="unknown"``."""
        buf = _build_macho_header(magic=MACHO_MAGIC_LE64, cpu_type=0xDEADBEEF)
        assert detect_format_and_arch(buf) == ("macho", "unknown", True)

    def test_zip_buffer(self) -> None:
        """Verify a ZIP buffer reports ``("zip", "unknown", False)``."""
        buf = ZIP_MAGIC + b"\x00" * 60
        assert detect_format_and_arch(buf) == ("zip", "unknown", False)

    def test_raw_buffer(self) -> None:
        """Verify an unrecognised buffer reports ``("raw", "unknown", False)``."""
        assert detect_format_and_arch(b"\x00" * 64) == ("raw", "unknown", False)

    def test_empty_buffer(self) -> None:
        """Verify an empty buffer reports ``("raw", "unknown", False)``."""
        assert detect_format_and_arch(b"") == ("raw", "unknown", False)
