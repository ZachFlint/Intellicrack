# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Pure-byte PE format parsing helpers shared across bridges.

This module exposes I/O-free primitives that operate on raw PE byte
buffers. Each call site (live process memory via x64dbg, sync PyO3
``HexDocument`` reads via the hex editor bridge, ``int.from_bytes`` reads
in the UI templates panel) keeps its own byte-fetch wrapper and feeds
the resulting buffer into the helpers below.

The helpers cover the structural pieces shared across PE parsers:
- DOS header ``e_lfanew`` extraction
- COFF File Header unpack (Machine, NumberOfSections, SizeOfOptionalHeader, Characteristics)
- Optional Header bitness detection (PE32 vs PE32+)
- Optional Header ``ImageBase`` extraction
- Data Directory offset arithmetic and entry unpack
- Section header unpack and iteration
- RVA-to-file-offset translation via the section table

The module deliberately does not own architecture-string normalisation
or magic-byte format detection; those are handled separately and may be
added to this same module in a follow-up unit. Names below are chosen
to leave room for those additions without collision.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


type SectionHeaderDict = dict[str, int | str]
"""Shape of dicts returned by :func:`unpack_section_header` and :func:`iterate_section_headers`.

Keys map to either an ``int`` numeric field or the ``str`` ``name`` field.
"""


PE_DOS_LFANEW_OFFSET: Final[int] = 0x3C
"""Offset of ``e_lfanew`` (the NT-headers pointer) inside the DOS header."""

PE_DOS_HEADER_SIZE: Final[int] = 0x40
"""Size of the IMAGE_DOS_HEADER structure."""

PE_SIGNATURE: Final[bytes] = b"PE\x00\x00"
"""IMAGE_NT_HEADERS signature bytes."""

PE_DOS_SIGNATURE: Final[bytes] = b"MZ"
"""IMAGE_DOS_HEADER signature bytes."""

PE_COFF_HEADER_SIZE: Final[int] = 20
"""Size of the IMAGE_FILE_HEADER (COFF header) structure."""

PE_OPTIONAL_HEADER_OFFSET: Final[int] = 24
"""Offset of the Optional Header inside the NT headers (4 byte signature + 20 byte COFF header)."""

PE32_OPTIONAL_HEADER_SIZE: Final[int] = 96
"""Size of the IMAGE_OPTIONAL_HEADER32 structure (excluding data directories)."""

PE32PLUS_OPTIONAL_HEADER_SIZE: Final[int] = 112
"""Size of the IMAGE_OPTIONAL_HEADER64 structure (excluding data directories)."""

PE_OPTIONAL_HEADER_MAGIC_PE32: Final[int] = 0x10B
"""IMAGE_OPTIONAL_HEADER.Magic value indicating PE32 (32-bit)."""

PE_OPTIONAL_HEADER_MAGIC_PE32PLUS: Final[int] = 0x20B
"""IMAGE_OPTIONAL_HEADER.Magic value indicating PE32+ (64-bit)."""

PE_OPTIONAL_HEADER_MAGIC_ROM: Final[int] = 0x107
"""IMAGE_OPTIONAL_HEADER.Magic value indicating a ROM image."""

PE_SECTION_HEADER_SIZE: Final[int] = 40
"""Size of the IMAGE_SECTION_HEADER structure."""

PE_DATA_DIRECTORY_ENTRY_SIZE: Final[int] = 8
"""Size of an IMAGE_DATA_DIRECTORY entry (RVA u32 + Size u32)."""

PE_SECTION_CHARACTERISTIC_EXECUTE: Final[int] = 0x20000000
"""IMAGE_SCN_MEM_EXECUTE."""

PE_SECTION_CHARACTERISTIC_READ: Final[int] = 0x40000000
"""IMAGE_SCN_MEM_READ."""

PE_SECTION_CHARACTERISTIC_WRITE: Final[int] = 0x80000000
"""IMAGE_SCN_MEM_WRITE."""


PE_MACHINE_I386: Final[int] = 0x014C
"""IMAGE_FILE_MACHINE_I386 (Intel 386)."""

PE_MACHINE_AMD64: Final[int] = 0x8664
"""IMAGE_FILE_MACHINE_AMD64 (x64 / x86-64)."""

PE_MACHINE_ARM: Final[int] = 0x01C0
"""IMAGE_FILE_MACHINE_ARM (ARM little-endian)."""

PE_MACHINE_ARMNT: Final[int] = 0x01C4
"""IMAGE_FILE_MACHINE_ARMNT (ARM Thumb-2 little-endian)."""

PE_MACHINE_ARM64: Final[int] = 0xAA64
"""IMAGE_FILE_MACHINE_ARM64 (ARM64 little-endian)."""

PE_MACHINE_IA64: Final[int] = 0x0200
"""IMAGE_FILE_MACHINE_IA64 (Intel Itanium)."""

PE_MACHINE_MIPS: Final[int] = 0x0166
"""IMAGE_FILE_MACHINE_R4000 (MIPS little-endian)."""

PE_MACHINE_MIPS16: Final[int] = 0x0266
"""IMAGE_FILE_MACHINE_MIPS16."""

PE_MACHINE_POWERPC: Final[int] = 0x01F0
"""IMAGE_FILE_MACHINE_POWERPC (Power PC little-endian)."""

PE_MACHINE_POWERPCFP: Final[int] = 0x01F1
"""IMAGE_FILE_MACHINE_POWERPCFP (Power PC with floating point support)."""

PE_MACHINE_RISCV32: Final[int] = 0x5032
"""IMAGE_FILE_MACHINE_RISCV32 (RISC-V 32-bit)."""

PE_MACHINE_RISCV64: Final[int] = 0x5064
"""IMAGE_FILE_MACHINE_RISCV64 (RISC-V 64-bit)."""

PE_MACHINE_RISCV128: Final[int] = 0x5128
"""IMAGE_FILE_MACHINE_RISCV128 (RISC-V 128-bit)."""


_PE_MACHINE_ARCH_TABLE: Final[dict[int, tuple[str, bool]]] = {
    PE_MACHINE_I386: ("x86", False),
    PE_MACHINE_AMD64: ("x86_64", True),
    PE_MACHINE_ARM: ("arm", False),
    PE_MACHINE_ARMNT: ("arm", False),
    PE_MACHINE_ARM64: ("arm64", True),
    PE_MACHINE_IA64: ("ia64", True),
    PE_MACHINE_MIPS: ("mips", False),
    PE_MACHINE_MIPS16: ("mips", False),
    PE_MACHINE_POWERPC: ("ppc", False),
    PE_MACHINE_POWERPCFP: ("ppc", False),
    PE_MACHINE_RISCV32: ("riscv", False),
    PE_MACHINE_RISCV64: ("riscv64", True),
    PE_MACHINE_RISCV128: ("riscv128", True),
}
"""Lookup table mapping ``IMAGE_FILE_MACHINE_*`` values to ``(arch, is_64bit)``.

Architecture strings follow the canonical convention used by
:meth:`GhidraBridge._detect_architecture` and the orchestrator's
``_ARCH_KEYWORDS`` map: ``x86_64`` for AMD64, ``x86`` for I386,
``arm`` / ``arm64`` for AArch32 / AArch64, ``ia64`` for Itanium,
``mips`` (32-bit MIPS), ``ppc`` (32-bit PowerPC), and
``riscv`` / ``riscv64`` / ``riscv128`` for the three RISC-V variants.
Callers that need a different convention (for example ``"x64"`` instead
of ``"x86_64"``) translate the helper's output at the call site.
"""


def pe_machine_to_arch(machine: int) -> tuple[str, bool]:
    """Translate an ``IMAGE_FILE_MACHINE_*`` value to an architecture tuple.

    The architecture string follows the canonical convention shared with
    :meth:`GhidraBridge._detect_architecture` and the orchestrator's
    ``_ARCH_KEYWORDS`` map (``x86_64``, ``x86``, ``arm``, ``arm64``,
    ``ia64``, ``mips``, ``ppc``, ``riscv``, ``riscv64``, ``riscv128``).
    Unknown / unrecognised machine values return ``("unknown", False)``.

    Args:
        machine: Win32 ``IMAGE_FILE_MACHINE_*`` constant value as
            extracted from the COFF File Header's Machine field.

    Returns:
        tuple[str, bool]: ``(arch, is_64bit)`` where ``arch`` is the
        canonical architecture name and ``is_64bit`` reflects the bit
        width of the architecture (``True`` for AMD64 / ARM64 / IA64 /
        RISC-V 64+128, ``False`` for everything else including
        unknown).
    """
    return _PE_MACHINE_ARCH_TABLE.get(machine, ("unknown", False))


def read_dos_e_lfanew(data: bytes) -> int:
    """Read ``e_lfanew`` (NT-headers pointer) from a DOS header buffer.

    The caller is responsible for ensuring ``data`` is large enough; a
    short buffer propagates a :class:`struct.error` from
    :func:`struct.unpack_from`.

    Args:
        data: Buffer that begins with the DOS header. Must contain at
            least ``PE_DOS_LFANEW_OFFSET + 4`` bytes.

    Returns:
        int: ``e_lfanew`` value (the file offset of the NT headers).
    """
    return int(struct.unpack_from("<I", data, PE_DOS_LFANEW_OFFSET)[0])


def unpack_coff_header(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Unpack the COFF File Header at ``offset`` into a typed tuple.

    The COFF header begins immediately after the 4-byte PE signature
    inside the NT headers. ``offset`` must point at the Machine field
    (i.e. ``e_lfanew + 4`` for a typical PE on disk, or the
    buffer-local offset when the caller has already read past the
    signature).

    A short buffer propagates a :class:`struct.error` from
    :func:`struct.unpack_from`.

    Args:
        data: Buffer containing the COFF header.
        offset: Byte offset within ``data`` of the Machine field (the
            first field of the COFF header).

    Returns:
        tuple[int, int, int, int]: ``(machine, number_of_sections,
        size_of_optional_header, characteristics)``. Machine and
        characteristics are ``u16``/``u16``, NumberOfSections is the
        ``u16`` count, and SizeOfOptionalHeader is the ``u16``
        Optional Header byte count.
    """
    (
        machine,
        number_of_sections,
        _time_date_stamp,
        _pointer_to_symbol_table,
        _number_of_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, offset)
    return int(machine), int(number_of_sections), int(size_of_optional_header), int(characteristics)


def is_pe64_optional_header(data: bytes, optional_header_offset: int) -> bool:
    """Determine whether an Optional Header at ``optional_header_offset`` is PE32+.

    Reads the 16-bit ``Magic`` field at the start of the Optional Header
    and compares against ``PE_OPTIONAL_HEADER_MAGIC_PE32PLUS``.

    A short buffer propagates a :class:`struct.error` from
    :func:`struct.unpack_from`.

    Args:
        data: Buffer containing the Optional Header bytes.
        optional_header_offset: Byte offset within ``data`` of the
            Optional Header (i.e. of the ``Magic`` field).

    Returns:
        bool: ``True`` if the header is PE32+ (64-bit), ``False`` if
        it is PE32 (32-bit) or any other value (including ROM images).
    """
    magic = int(struct.unpack_from("<H", data, optional_header_offset)[0])
    return magic == PE_OPTIONAL_HEADER_MAGIC_PE32PLUS


def optional_header_size_for(*, is_pe64: bool) -> int:
    """Return the standard Optional Header size for the given bitness.

    The value matches the Microsoft PE specification's
    ``IMAGE_OPTIONAL_HEADER32`` / ``IMAGE_OPTIONAL_HEADER64`` layouts
    excluding the trailing data-directory array.

    Args:
        is_pe64: ``True`` for PE32+ (64-bit), ``False`` for PE32.

    Returns:
        int: ``PE32PLUS_OPTIONAL_HEADER_SIZE`` (112) for PE32+, or
        ``PE32_OPTIONAL_HEADER_SIZE`` (96) for PE32.
    """
    return PE32PLUS_OPTIONAL_HEADER_SIZE if is_pe64 else PE32_OPTIONAL_HEADER_SIZE


def get_data_directory_offset(nt_headers_offset: int, *, is_pe64: bool, entry_index: int) -> int:
    """Compute the file/buffer offset of a Data Directory entry.

    The Data Directory begins at ``nt_headers_offset +
    PE_OPTIONAL_HEADER_OFFSET + optional_header_size_for(is_pe64=...)``,
    where ``PE_OPTIONAL_HEADER_OFFSET`` (24) already accounts for the
    4-byte PE signature plus the 20-byte COFF File Header. Each entry
    occupies ``PE_DATA_DIRECTORY_ENTRY_SIZE`` bytes (RVA u32 + Size
    u32).

    Args:
        nt_headers_offset: Buffer offset of the NT headers (i.e. of the
            PE signature bytes). Pass ``0`` when the buffer starts at
            the NT headers, or ``e_lfanew`` when the buffer starts at
            the DOS header.
        is_pe64: ``True`` for PE32+ images, ``False`` for PE32.
        entry_index: Zero-based Data Directory index. Standard indices
            are 0=Export, 1=Import, 2=Resource, 3=Exception, 4=Security,
            5=BaseReloc, 6=Debug, 9=TLS, 12=IAT.

    Returns:
        int: Buffer offset of the requested Data Directory entry.
    """
    optional_header_size = optional_header_size_for(is_pe64=is_pe64)
    data_directory_base = nt_headers_offset + PE_OPTIONAL_HEADER_OFFSET + optional_header_size
    return data_directory_base + entry_index * PE_DATA_DIRECTORY_ENTRY_SIZE


def read_data_directory_entry(data: bytes, offset: int) -> tuple[int, int]:
    """Read an IMAGE_DATA_DIRECTORY entry (RVA + Size) from a buffer.

    A short buffer propagates a :class:`struct.error` from
    :func:`struct.unpack_from`.

    Args:
        data: Buffer containing the directory entry.
        offset: Byte offset of the entry within ``data``. Typically
            obtained via :func:`get_data_directory_offset`.

    Returns:
        tuple[int, int]: ``(virtual_address, size)`` as unsigned 32-bit
        integers. Both fields are zero when the directory entry is
        unused.
    """
    rva, size = struct.unpack_from("<II", data, offset)
    return int(rva), int(size)


def unpack_optional_header_image_base(data: bytes, optional_header_offset: int, *, is_pe64: bool) -> int:
    """Read ``ImageBase`` from an Optional Header.

    The field is at offset ``28`` for PE32 (``u32``) and ``24`` for
    PE32+ (``u64``).

    A short buffer propagates a :class:`struct.error` from
    :func:`struct.unpack_from`.

    Args:
        data: Buffer containing the Optional Header.
        optional_header_offset: Byte offset of the Optional Header
            within ``data``.
        is_pe64: ``True`` to read as PE32+ (``u64`` at +24), ``False``
            to read as PE32 (``u32`` at +28).

    Returns:
        int: The image base virtual address.
    """
    if is_pe64:
        return int(struct.unpack_from("<Q", data, optional_header_offset + 24)[0])
    return int(struct.unpack_from("<I", data, optional_header_offset + 28)[0])


def unpack_section_header(data: bytes, offset: int) -> SectionHeaderDict:
    """Unpack a single IMAGE_SECTION_HEADER into a dict.

    The dict contains every numeric field in the section header plus
    the decoded ``name`` (with trailing NULs stripped). Field names use
    the Microsoft PE specification's terminology. A short buffer
    propagates a :class:`struct.error` from :func:`struct.unpack_from`.

    Args:
        data: Buffer containing the section header.
        offset: Byte offset of the section header within ``data``.

    Returns:
        SectionHeaderDict: Section header fields:

        - ``name``: ``str`` - ASCII name (8-byte field, NUL-stripped).
        - ``virtual_size``: ``int`` - ``Misc.VirtualSize``.
        - ``virtual_address``: ``int`` - ``VirtualAddress`` (RVA).
        - ``raw_size``: ``int`` - ``SizeOfRawData``.
        - ``raw_offset``: ``int`` - ``PointerToRawData`` (file offset).
        - ``pointer_to_relocations``: ``int``.
        - ``pointer_to_linenumbers``: ``int``.
        - ``number_of_relocations``: ``int``.
        - ``number_of_linenumbers``: ``int``.
        - ``characteristics``: ``int`` - ``IMAGE_SCN_*`` flags.
    """
    name_bytes = data[offset : offset + 8]
    name = name_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    (
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        characteristics,
    ) = struct.unpack_from("<IIIIIIHHI", data, offset + 8)
    return {
        "name": name,
        "virtual_size": int(virtual_size),
        "virtual_address": int(virtual_address),
        "raw_size": int(raw_size),
        "raw_offset": int(raw_offset),
        "pointer_to_relocations": int(pointer_to_relocations),
        "pointer_to_linenumbers": int(pointer_to_linenumbers),
        "number_of_relocations": int(number_of_relocations),
        "number_of_linenumbers": int(number_of_linenumbers),
        "characteristics": int(characteristics),
    }


def iterate_section_headers(
    data: bytes,
    sections_offset: int,
    count: int,
) -> Iterator[SectionHeaderDict]:
    """Yield section-header dicts for ``count`` consecutive entries.

    Stops early when the buffer is too short to contain another full
    section header rather than raising; callers receive only fully
    parseable entries.

    Args:
        data: Buffer containing the section table.
        sections_offset: Byte offset of the first section header.
        count: Number of section headers to yield. Negative or zero
            counts yield no entries.

    Yields:
        SectionHeaderDict: One dict per section as produced by
            :func:`unpack_section_header`.
    """
    if count <= 0:
        return
    for i in range(count):
        entry_offset = sections_offset + i * PE_SECTION_HEADER_SIZE
        if entry_offset + PE_SECTION_HEADER_SIZE > len(data):
            return
        yield unpack_section_header(data, entry_offset)


def rva_to_file_offset(
    sections: Iterable[SectionHeaderDict],
    rva: int,
) -> int | None:
    """Translate a Relative Virtual Address into a file offset.

    Walks the supplied section table and returns the file offset that
    corresponds to ``rva`` if any section's virtual range covers it.
    Returns ``None`` when no section maps the RVA (for example, the
    PE headers themselves before the first section, or addresses
    outside any section).

    Args:
        sections: Iterable of section dicts as produced by
            :func:`unpack_section_header` or
            :func:`iterate_section_headers`. Each dict must contain
            ``virtual_address``, ``virtual_size``, ``raw_size``, and
            ``raw_offset``.
        rva: Relative Virtual Address to translate.

    Returns:
        int | None: File offset of ``rva`` within the matching section,
        or ``None`` if no section maps it.
    """
    for section in sections:
        virtual_address = section.get("virtual_address")
        if not isinstance(virtual_address, int):
            continue
        virtual_size = section.get("virtual_size")
        raw_size = section.get("raw_size")
        raw_offset = section.get("raw_offset")
        if not isinstance(virtual_size, int) or not isinstance(raw_size, int) or not isinstance(raw_offset, int):
            continue
        section_extent = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + section_extent:
            return raw_offset + (rva - virtual_address)
    return None


__all__: list[str] = [
    "PE32PLUS_OPTIONAL_HEADER_SIZE",
    "PE32_OPTIONAL_HEADER_SIZE",
    "PE_COFF_HEADER_SIZE",
    "PE_DATA_DIRECTORY_ENTRY_SIZE",
    "PE_DOS_HEADER_SIZE",
    "PE_DOS_LFANEW_OFFSET",
    "PE_DOS_SIGNATURE",
    "PE_MACHINE_AMD64",
    "PE_MACHINE_ARM",
    "PE_MACHINE_ARM64",
    "PE_MACHINE_ARMNT",
    "PE_MACHINE_I386",
    "PE_MACHINE_IA64",
    "PE_MACHINE_MIPS",
    "PE_MACHINE_MIPS16",
    "PE_MACHINE_POWERPC",
    "PE_MACHINE_POWERPCFP",
    "PE_MACHINE_RISCV32",
    "PE_MACHINE_RISCV64",
    "PE_MACHINE_RISCV128",
    "PE_OPTIONAL_HEADER_MAGIC_PE32",
    "PE_OPTIONAL_HEADER_MAGIC_PE32PLUS",
    "PE_OPTIONAL_HEADER_MAGIC_ROM",
    "PE_OPTIONAL_HEADER_OFFSET",
    "PE_SECTION_CHARACTERISTIC_EXECUTE",
    "PE_SECTION_CHARACTERISTIC_READ",
    "PE_SECTION_CHARACTERISTIC_WRITE",
    "PE_SECTION_HEADER_SIZE",
    "PE_SIGNATURE",
    "SectionHeaderDict",
    "get_data_directory_offset",
    "is_pe64_optional_header",
    "iterate_section_headers",
    "optional_header_size_for",
    "pe_machine_to_arch",
    "read_data_directory_entry",
    "read_dos_e_lfanew",
    "rva_to_file_offset",
    "unpack_coff_header",
    "unpack_optional_header_image_base",
    "unpack_section_header",
]
