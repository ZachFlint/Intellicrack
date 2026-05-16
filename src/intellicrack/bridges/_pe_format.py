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
- Magic-byte file-format detection (PE / ELF / Mach-O / ZIP / raw)
- Combined format-and-architecture detection across PE / ELF / Mach-O

The architecture-string convention used by :func:`detect_format_and_arch`
is the canonical set ``"x86"`` / ``"x86_64"`` / ``"arm"`` / ``"arm64"``
/ ``"mips"`` / ``"mips64"`` / ``"ppc"`` / ``"ppc64"`` / ``"riscv"`` /
``"riscv64"`` / ``"unknown"``, matching ``bridges/ghidra.py`` and
``core/orchestrator.py``. Callers that want a different shape (for
example the capstone ``("x86", "32")`` tuple) wrap the helper output
locally.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Final, Literal


if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


FormatName = Literal["pe", "elf", "macho", "zip", "raw"]
"""Canonical magic-byte file-format names returned by :func:`detect_format`."""

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

PE_SIGNATURE_INT: Final[int] = 0x00004550
"""IMAGE_NT_HEADERS signature as a little-endian ``u32``.

Equal to ``int.from_bytes(PE_SIGNATURE, 'little')``. Use this form when comparing against a value already unpacked with
``struct.unpack_from('<I', ...)``.
"""

PE_DOS_SIGNATURE: Final[bytes] = b"MZ"
"""IMAGE_DOS_HEADER signature bytes."""

PE_DOS_SIGNATURE_INT: Final[int] = 0x5A4D
"""IMAGE_DOS_HEADER signature as a little-endian ``u16``.

Equal to ``int.from_bytes(PE_DOS_SIGNATURE, 'little')``. Use this form
when comparing against a value already unpacked with
``struct.unpack_from('<H', ...)``.
"""

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


ELF_MAGIC: Final[bytes] = b"\x7fELF"
"""Four-byte ELF identification magic at offset 0 of every ELF binary."""

ELF_EI_CLASS_OFFSET: Final[int] = 4
"""Offset of the ``EI_CLASS`` byte inside the ELF identification array."""

ELF_EI_DATA_OFFSET: Final[int] = 5
"""Offset of the ``EI_DATA`` (endianness) byte inside the ELF identification array."""

ELF_E_MACHINE_OFFSET: Final[int] = 0x12
"""Offset of the ``e_machine`` u16 field inside the ELF header."""

ELF_E_MACHINE_END: Final[int] = 0x14
"""End offset (exclusive) of the ``e_machine`` u16 field; equal to ``ELF_E_MACHINE_OFFSET + 2``."""

ELF_CLASS_64: Final[int] = 2
"""``EI_CLASS`` value indicating an ELFCLASS64 binary."""

ELF_DATA_BIG_ENDIAN: Final[int] = 2
"""``EI_DATA`` value indicating big-endian byte order."""

ELF_EM_386: Final[int] = 0x03
"""ELF ``e_machine`` value for Intel 80386."""

ELF_EM_X86_64: Final[int] = 0x3E
"""ELF ``e_machine`` value for AMD x86-64."""

ELF_EM_ARM: Final[int] = 0x28
"""ELF ``e_machine`` value for ARM."""

ELF_EM_AARCH64: Final[int] = 0xB7
"""ELF ``e_machine`` value for ARM AArch64."""

ELF_EM_MIPS: Final[int] = 0x08
"""ELF ``e_machine`` value for MIPS."""

ELF_EM_PPC: Final[int] = 0x14
"""ELF ``e_machine`` value for PowerPC 32-bit."""

ELF_EM_PPC64: Final[int] = 0x15
"""ELF ``e_machine`` value for PowerPC 64-bit."""

ELF_EM_RISCV: Final[int] = 0xF3
"""ELF ``e_machine`` value for RISC-V."""

MACHO_MAGIC_BE32: Final[bytes] = b"\xfe\xed\xfa\xce"
"""Mach-O 32-bit big-endian magic (``MH_MAGIC``)."""

MACHO_MAGIC_LE32: Final[bytes] = b"\xce\xfa\xed\xfe"
"""Mach-O 32-bit little-endian magic (``MH_CIGAM``)."""

MACHO_MAGIC_BE64: Final[bytes] = b"\xfe\xed\xfa\xcf"
"""Mach-O 64-bit big-endian magic (``MH_MAGIC_64``)."""

MACHO_MAGIC_LE64: Final[bytes] = b"\xcf\xfa\xed\xfe"
"""Mach-O 64-bit little-endian magic (``MH_CIGAM_64``)."""

_MACHO_MAGICS: Final[frozenset[bytes]] = frozenset(
    {MACHO_MAGIC_BE32, MACHO_MAGIC_LE32, MACHO_MAGIC_BE64, MACHO_MAGIC_LE64},
)
"""Every Mach-O magic byte sequence (32-bit and 64-bit, little- and big-endian)."""

_MACHO_MAGICS_64: Final[frozenset[bytes]] = frozenset({MACHO_MAGIC_BE64, MACHO_MAGIC_LE64})
"""Mach-O magics that identify a 64-bit image."""

_MACHO_MAGICS_BE: Final[frozenset[bytes]] = frozenset({MACHO_MAGIC_BE32, MACHO_MAGIC_BE64})
"""Mach-O magics whose header fields are stored big-endian."""

MACHO_HEADER_MIN_SIZE: Final[int] = 8
"""Minimum bytes required to read the Mach-O magic and ``cputype`` fields."""

MACHO_CPU_TYPE_X86: Final[int] = 0x07
"""Mach-O ``cputype`` value for Intel x86."""

MACHO_CPU_TYPE_X86_64: Final[int] = 0x01000007
"""Mach-O ``cputype`` value for x86-64 (CPU_ARCH_ABI64 | CPU_TYPE_X86)."""

MACHO_CPU_TYPE_ARM: Final[int] = 0x0C
"""Mach-O ``cputype`` value for ARM."""

MACHO_CPU_TYPE_ARM64: Final[int] = 0x0100000C
"""Mach-O ``cputype`` value for ARM64 (CPU_ARCH_ABI64 | CPU_TYPE_ARM)."""

MACHO_CPU_TYPE_PPC: Final[int] = 0x12
"""Mach-O ``cputype`` value for PowerPC."""

MACHO_CPU_TYPE_PPC64: Final[int] = 0x01000012
"""Mach-O ``cputype`` value for 64-bit PowerPC."""

ZIP_MAGIC: Final[bytes] = b"\x50\x4b\x03\x04"
"""ZIP local-file-header magic (``PK\\x03\\x04``)."""

_PE_DETECT_MIN_SIZE: Final[int] = 2
"""Minimum bytes required to compare the two-byte ``MZ`` magic."""

_FOUR_BYTE_MAGIC_SIZE: Final[int] = 4
"""Minimum bytes required to compare any of the four-byte file-format magics (ELF, Mach-O, ZIP)."""

_PE_HEADER_AFTER_LFANEW: Final[int] = 6
"""Bytes required after ``e_lfanew`` to read the PE signature plus the Machine field."""

_MACHO_CPU_TYPE_ARCH_TABLE: Final[dict[int, tuple[str, bool]]] = {
    MACHO_CPU_TYPE_X86_64: ("x86_64", True),
    MACHO_CPU_TYPE_X86: ("x86", False),
    MACHO_CPU_TYPE_ARM64: ("arm64", True),
    MACHO_CPU_TYPE_ARM: ("arm", False),
    MACHO_CPU_TYPE_PPC64: ("ppc64", True),
    MACHO_CPU_TYPE_PPC: ("ppc", False),
}
"""Lookup table mapping Mach-O ``cputype`` values to ``(arch, is_64bit)``.

Architecture strings follow the canonical convention shared with
:func:`pe_machine_to_arch` and :meth:`GhidraBridge._detect_architecture`.
"""


def detect_format(data: bytes) -> FormatName:
    r"""Identify a binary format from the first few bytes of ``data``.

    Performs only magic-byte comparison; no further structural parsing
    or validation. Buffers shorter than the magic of every supported
    format fall through to ``"raw"``. The PE branch matches solely on
    the two-byte ``MZ`` DOS magic so live-process callers (which read
    only the DOS header before fetching the NT headers) reach the same
    answer as on-disk callers.

    Args:
        data: Raw header bytes from a file or process memory. Only the
            first four bytes are inspected.

    Returns:
        FormatName: ``"pe"`` for ``MZ`` (DOS / PE / NE / LE),
        ``"elf"`` for ``\x7fELF``, ``"macho"`` for any of the four
        Mach-O magics, ``"zip"`` for ``PK\x03\x04``, otherwise
        ``"raw"``.
    """
    data_len = len(data)
    if data_len >= _PE_DETECT_MIN_SIZE and data[:2] == PE_DOS_SIGNATURE:
        return "pe"
    if data_len < _FOUR_BYTE_MAGIC_SIZE:
        return "raw"
    head4 = data[:4]
    if head4 == ELF_MAGIC:
        return "elf"
    if head4 in _MACHO_MAGICS:
        return "macho"
    if head4 == ZIP_MAGIC:
        return "zip"
    return "raw"


def _detect_pe_arch(data: bytes) -> tuple[str, bool] | None:
    """Resolve PE architecture from a buffer that begins with a DOS header.

    Args:
        data: Buffer beginning with the DOS header. Must contain the
            full DOS header, the NT signature, and the COFF Machine
            field for a successful parse.

    Returns:
        tuple[str, bool] | None: ``(arch, is_64bit)`` per
        :func:`pe_machine_to_arch`, or ``None`` when the headers do
        not parse as a valid PE.
    """
    if len(data) <= PE_DOS_LFANEW_OFFSET + 3:
        return None
    pe_offset = read_dos_e_lfanew(data)
    if pe_offset <= 0 or len(data) < pe_offset + _PE_HEADER_AFTER_LFANEW:
        return None
    if data[pe_offset : pe_offset + 4] != PE_SIGNATURE:
        return None
    machine = int(struct.unpack_from("<H", data, pe_offset + 4)[0])
    return pe_machine_to_arch(machine)


def _detect_elf_arch(data: bytes) -> tuple[str, bool]:
    """Resolve ELF architecture from a buffer that begins with the ELF header.

    The endianness of ``e_machine`` follows ``EI_DATA`` at offset 5;
    when the buffer is too short to inspect ``EI_DATA`` the parser
    falls back to little-endian. Bitness comes from ``EI_CLASS`` at
    offset 4.

    Args:
        data: Buffer beginning with the four-byte ELF magic. Must
            contain at least ``ELF_E_MACHINE_END`` bytes for the
            ``e_machine`` field to be parseable.

    Returns:
        tuple[str, bool]: ``(arch, is_64bit)``. Falls back to
        ``("unknown", is_64bit)`` for unrecognised ``e_machine`` values
        and ``("unknown", False)`` when the header is too short.
    """
    if len(data) < ELF_E_MACHINE_END:
        return "unknown", False
    is_64 = len(data) > ELF_EI_CLASS_OFFSET and data[ELF_EI_CLASS_OFFSET] == ELF_CLASS_64
    byte_order: Literal["little", "big"] = (
        "big" if len(data) > ELF_EI_DATA_OFFSET and data[ELF_EI_DATA_OFFSET] == ELF_DATA_BIG_ENDIAN else "little"
    )
    e_machine = int.from_bytes(data[ELF_E_MACHINE_OFFSET:ELF_E_MACHINE_END], byte_order)
    if e_machine == ELF_EM_X86_64:
        return "x86_64", True
    if e_machine == ELF_EM_386:
        return "x86", False
    if e_machine == ELF_EM_ARM:
        return "arm", False
    if e_machine == ELF_EM_AARCH64:
        return "arm64", True
    if e_machine == ELF_EM_MIPS:
        return ("mips64", True) if is_64 else ("mips", False)
    if e_machine == ELF_EM_PPC:
        return "ppc", False
    if e_machine == ELF_EM_PPC64:
        return "ppc64", True
    if e_machine == ELF_EM_RISCV:
        return ("riscv64", True) if is_64 else ("riscv", False)
    return "unknown", is_64


def _detect_macho_arch(data: bytes) -> tuple[str, bool]:
    """Resolve Mach-O architecture from a buffer that begins with the magic.

    Endianness and bitness derive from which of the four Mach-O magic
    values appear in the first four bytes. The ``cputype`` field follows
    immediately and is decoded with the matching byte order.

    Args:
        data: Buffer beginning with one of the four Mach-O magic
            sequences. Must contain at least ``MACHO_HEADER_MIN_SIZE``
            bytes for the ``cputype`` field to be parseable.

    Returns:
        tuple[str, bool]: ``(arch, is_64bit)``. Falls back to
        ``("unknown", is_64bit)`` for unrecognised ``cputype`` values
        and ``("unknown", False)`` when the header is too short.
    """
    if len(data) < MACHO_HEADER_MIN_SIZE:
        return "unknown", False
    macho_magic = data[:4]
    is_64 = macho_magic in _MACHO_MAGICS_64
    byte_order: Literal["little", "big"] = "big" if macho_magic in _MACHO_MAGICS_BE else "little"
    cpu_type = int.from_bytes(data[4:8], byte_order)
    return _MACHO_CPU_TYPE_ARCH_TABLE.get(cpu_type, ("unknown", is_64))


def detect_format_and_arch(data: bytes) -> tuple[str, str, bool]:
    r"""Identify file format, architecture, and bitness from header bytes.

    Composes :func:`detect_format` with format-specific architecture
    decoders for PE / ELF / Mach-O. For PE buffers without a valid
    ``PE\x00\x00`` signature at ``e_lfanew``, the architecture is
    reported as ``"unknown"`` while the format remains ``"pe"`` so
    callers can distinguish a bare-DOS ``MZ`` image from a fully
    formed PE. For ZIP and raw inputs both arch and bitness reflect
    that the buffer is not an executable image (``"unknown"``,
    ``False``).

    The architecture string convention is the canonical set used by
    :meth:`GhidraBridge._detect_architecture` and the orchestrator's
    ``_ARCH_KEYWORDS`` map: ``"x86"``, ``"x86_64"``, ``"arm"``,
    ``"arm64"``, ``"ia64"``, ``"mips"``, ``"mips64"``, ``"ppc"``,
    ``"ppc64"``, ``"riscv"``, ``"riscv64"``, ``"riscv128"``, or
    ``"unknown"``. Callers that need a different shape (for example the
    capstone ``("x86", "32")`` tuple form) wrap the return value
    locally.

    Args:
        data: Raw header bytes from a file or process memory.

    Returns:
        tuple[str, str, bool]: ``(format, arch, is_64bit)``. ``format``
        is one of the :data:`FormatName` literals. ``arch`` is the
        canonical architecture name, or ``"unknown"`` when the format
        does not encode an architecture or the machine code is
        unrecognised. ``is_64bit`` is ``True`` when the architecture
        is a 64-bit one, otherwise ``False``.
    """
    fmt = detect_format(data)
    if fmt == "pe":
        pe_result = _detect_pe_arch(data)
        if pe_result is None:
            return "pe", "unknown", False
        arch, is_64 = pe_result
        return "pe", arch, is_64
    if fmt == "elf":
        arch, is_64 = _detect_elf_arch(data)
        return "elf", arch, is_64
    if fmt == "macho":
        arch, is_64 = _detect_macho_arch(data)
        return "macho", arch, is_64
    return fmt, "unknown", False


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
    "ELF_CLASS_64",
    "ELF_DATA_BIG_ENDIAN",
    "ELF_EI_CLASS_OFFSET",
    "ELF_EI_DATA_OFFSET",
    "ELF_EM_386",
    "ELF_EM_AARCH64",
    "ELF_EM_ARM",
    "ELF_EM_MIPS",
    "ELF_EM_PPC",
    "ELF_EM_PPC64",
    "ELF_EM_RISCV",
    "ELF_EM_X86_64",
    "ELF_E_MACHINE_END",
    "ELF_E_MACHINE_OFFSET",
    "ELF_MAGIC",
    "MACHO_CPU_TYPE_ARM",
    "MACHO_CPU_TYPE_ARM64",
    "MACHO_CPU_TYPE_PPC",
    "MACHO_CPU_TYPE_PPC64",
    "MACHO_CPU_TYPE_X86",
    "MACHO_CPU_TYPE_X86_64",
    "MACHO_HEADER_MIN_SIZE",
    "MACHO_MAGIC_BE32",
    "MACHO_MAGIC_BE64",
    "MACHO_MAGIC_LE32",
    "MACHO_MAGIC_LE64",
    "PE32PLUS_OPTIONAL_HEADER_SIZE",
    "PE32_OPTIONAL_HEADER_SIZE",
    "PE_COFF_HEADER_SIZE",
    "PE_DATA_DIRECTORY_ENTRY_SIZE",
    "PE_DOS_HEADER_SIZE",
    "PE_DOS_LFANEW_OFFSET",
    "PE_DOS_SIGNATURE",
    "PE_DOS_SIGNATURE_INT",
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
    "PE_SIGNATURE_INT",
    "ZIP_MAGIC",
    "FormatName",
    "SectionHeaderDict",
    "detect_format",
    "detect_format_and_arch",
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
