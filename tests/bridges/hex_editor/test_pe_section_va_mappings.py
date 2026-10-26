# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""PE section VA mappings cover exactly the bytes the loader reads from the file.

``HexEditorBridge.auto_detect_va_mappings`` registers one mapping per PE section
with the real Rust ``HexDocument``, whose lookups take the first mapping in
file-offset order that contains the offset. These tests build PE32+ images
from the PE/COFF layout and check the engine's answers for every section shape
a packer or linker produces.
"""

from __future__ import annotations

import asyncio
import struct
from typing import Final

from intellicrack_hexcore import HexDocument

from intellicrack.bridges.hex_editor import HexEditorBridge


_E_LFANEW: Final = 0x80
_OPTIONAL_HEADER_SIZE: Final = 240
_OPTIONAL_HEADER: Final = _E_LFANEW + 4 + 20
_SECTION_TABLE: Final = _OPTIONAL_HEADER + _OPTIONAL_HEADER_SIZE
_IMAGE_BASE: Final = 0x1_4000_0000
_PE32_PLUS_MAGIC: Final = 0x20B
_AMD64: Final = 0x8664


def _pe_image(size: int, sections: list[tuple[str, int, int, int, int]]) -> bytes:
    """Assemble a PE32+ image of ``size`` bytes with the given section table.

    Args:
        size: Total file size in bytes.
        sections: ``(name, virtual_size, virtual_address, raw_size, raw_offset)`` per section.

    Returns:
        bytes: The image.
    """
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, _E_LFANEW)
    data[_E_LFANEW : _E_LFANEW + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, _E_LFANEW + 4, _AMD64, len(sections), 0, 0, 0, _OPTIONAL_HEADER_SIZE, 0x22)
    struct.pack_into("<H", data, _OPTIONAL_HEADER, _PE32_PLUS_MAGIC)
    struct.pack_into("<Q", data, _OPTIONAL_HEADER + 24, _IMAGE_BASE)
    for index, (name, virtual_size, virtual_address, raw_size, raw_offset) in enumerate(sections):
        entry = _SECTION_TABLE + index * 40
        data[entry : entry + 8] = name.encode("ascii").ljust(8, b"\x00")
        struct.pack_into("<IIIIIIHHI", data, entry + 8, virtual_size, virtual_address, raw_size, raw_offset, 0, 0, 0, 0, 0x60000020)
    return bytes(data)


def _detect(image: bytes) -> tuple[HexDocument, list[dict[str, int]]]:
    """Open ``image`` in a fresh bridge and run VA auto-detection on it.

    Args:
        image: PE bytes.

    Returns:
        tuple[HexDocument, list[dict[str, int]]]: The document and the mappings the bridge reported.
    """
    bridge = HexEditorBridge()
    document = HexDocument.open_bytes(image)
    bridge.document = document
    mappings = asyncio.run(bridge.auto_detect_va_mappings())
    return document, mappings


def test_virtual_only_section_does_not_shadow_the_next_section() -> None:
    """A packer's virtual-only section is unmapped, so offsets resolve to the section that holds them.

    ``.UPX0`` has no raw data and a nominal raw offset of 0, the layout UPX
    writes. Mapping it would cover offset 0x400 ahead of ``.UPX1`` and send
    both directions of the lookup into the wrong section.
    """
    image = _pe_image(0x800, [(".UPX0", 0x9000, 0x1000, 0, 0), (".UPX1", 0x400, 0xA000, 0x400, 0x400)])

    document, mappings = _detect(image)

    assert mappings == [
        {"file_offset": 0, "virtual_address": _IMAGE_BASE, "length": _E_LFANEW},
        {"file_offset": 0x400, "virtual_address": _IMAGE_BASE + 0xA000, "length": 0x400},
    ]
    assert document.file_offset_to_va(0x400) == _IMAGE_BASE + 0xA000
    assert document.file_offset_to_va(0x7FF) == _IMAGE_BASE + 0xA3FF
    assert document.va_to_file_offset(_IMAGE_BASE + 0xA010) == 0x410
    assert document.va_to_file_offset(_IMAGE_BASE + 0x1400) is None


def test_section_maps_raw_bytes_cut_to_virtual_size_and_file_end() -> None:
    """Each section maps its raw bytes, cut to a smaller virtual size and to the end of the file.

    ``.text`` has more raw bytes than its virtual size, so only the virtual
    size is file-backed; ``.data`` has a zero virtual size, so all its raw
    bytes are; ``.rsrc`` has raw data running past the end of the file, so
    only the bytes the file holds are.
    """
    image = _pe_image(
        0x700,
        [
            (".text", 0x100, 0x1000, 0x200, 0x200),
            (".data", 0, 0x2000, 0x100, 0x400),
            (".rsrc", 0x1000, 0x3000, 0x400, 0x600),
        ],
    )

    document, mappings = _detect(image)

    assert mappings[1:] == [
        {"file_offset": 0x200, "virtual_address": _IMAGE_BASE + 0x1000, "length": 0x100},
        {"file_offset": 0x400, "virtual_address": _IMAGE_BASE + 0x2000, "length": 0x100},
        {"file_offset": 0x600, "virtual_address": _IMAGE_BASE + 0x3000, "length": 0x100},
    ]
    assert document.file_offset_to_va(0x2FF) == _IMAGE_BASE + 0x10FF
    assert document.file_offset_to_va(0x300) is None
    assert document.file_offset_to_va(0x6FF) == _IMAGE_BASE + 0x30FF
    assert document.va_to_file_offset(_IMAGE_BASE + 0x3100) is None
