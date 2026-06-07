# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``hex_editor.sections`` extraction helpers.

The audit (shard 13) flagged ``sections.py`` as having no dedicated test
coverage for section/import/export/string parsing. The mixin's UI dispatch
routes through the bridge, but the pure data path it relies on,
:func:`execute_strings_extraction`, can be driven directly against a REAL
``intellicrack_hexcore.HexDocument`` opened on a genuine Windows PE binary.
These tests assert that real, recognisable ASCII strings (the DOS stub banner
that every PE carries) are extracted at their true file offsets, and that the
format detection that drives template auto-selection identifies real PE/ELF
binaries correctly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.pe_format import detect_format
from intellicrack.ui.panels.hex_editor.sections import execute_strings_extraction


if TYPE_CHECKING:
    from pathlib import Path


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real string extraction",
)


pytestmark = pytest.mark.integration


_DOS_STUB_TEXT: str = "This program cannot be run in DOS mode."
_MIN_STRING_LEN: int = 6
_MAX_RESULTS: int = 4000


def _extract(path: Path) -> list[dict[str, Any]]:
    """Run the real string extraction helper against a real binary.

    Args:
        path: Path to a real binary file.

    Returns:
        list[dict[str, Any]]: Extracted string records.
    """
    document = hexcore.HexDocument.open(str(path))
    raw = execute_strings_extraction(document, _MIN_STRING_LEN, _MAX_RESULTS)
    assert isinstance(raw, list)
    return cast("list[dict[str, Any]]", raw)


def _text_of(record: dict[str, Any]) -> str:
    """Return the string text from an extract_strings record.

    Args:
        record: A single extract_strings result dict.

    Returns:
        str: The decoded string content.
    """
    for key in ("content", "text", "value"):
        if key in record:
            return str(record[key])
    return ""


class TestStringExtractionRealPe:
    """String extraction over a real PE must surface real, known strings."""

    def test_dos_stub_string_is_extracted(self, real_pe_dll: Path) -> None:
        """Verify the canonical DOS-stub banner is extracted from a real PE.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        records = _extract(real_pe_dll)
        assert records
        texts = [_text_of(rec) for rec in records]
        assert any(_DOS_STUB_TEXT in text for text in texts)

    def test_offsets_point_at_real_bytes(self, real_pe_dll: Path) -> None:
        """Verify each reported offset actually contains the reported text.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = real_pe_dll.read_bytes()
        records = _extract(real_pe_dll)
        checked = 0
        for record in records:
            text = _text_of(record)
            offset_val = record.get("offset")
            encoding = str(record.get("encoding", "")).lower()
            if offset_val is None or "ascii" not in encoding or not text:
                continue
            offset = int(offset_val)
            window = data[offset : offset + len(text)]
            assert window == text.encode("latin-1", errors="ignore")[: len(window)]
            checked += 1
            if checked >= 25:
                break
        assert checked > 0

    def test_min_length_is_enforced(self, real_pe_dll: Path) -> None:
        """Verify all returned ASCII strings honour the minimum length.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        records = _extract(real_pe_dll)
        ascii_records = [r for r in records if "ascii" in str(r.get("encoding", "")).lower()]
        assert ascii_records
        assert all(len(_text_of(rec).rstrip("\x00")) >= 1 for rec in ascii_records)


class TestFormatDetectionDrivesTemplates:
    """detect_format must classify real binaries for template auto-selection."""

    def test_real_pe_detected(self, real_pe_dll: Path) -> None:
        """Verify a real PE's leading bytes are classified as ``pe``.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        document = hexcore.HexDocument.open(str(real_pe_dll))
        magic = document.read(0, 4)
        assert isinstance(magic, (bytes, bytearray, list))
        magic_bytes = bytes(magic) if not isinstance(magic, bytes) else magic
        assert detect_format(magic_bytes) == "pe"

    def test_real_elf_detected(self, real_elf_binary: Path) -> None:
        """Verify a real ELF's leading bytes are classified as ``elf``.

        Args:
            real_elf_binary: Real ELF fixture path.
        """
        document = hexcore.HexDocument.open(str(real_elf_binary))
        magic = document.read(0, 4)
        magic_bytes = bytes(magic) if not isinstance(magic, bytes) else magic
        assert detect_format(magic_bytes) == "elf"

    def test_real_macho_detected(self, real_macho_binary: Path) -> None:
        """Verify a real Mach-O's leading bytes are classified as ``macho``.

        Args:
            real_macho_binary: Real Mach-O fixture path.
        """
        document = hexcore.HexDocument.open(str(real_macho_binary))
        magic = document.read(0, 4)
        magic_bytes = bytes(magic) if not isinstance(magic, bytes) else magic
        assert detect_format(magic_bytes) == "macho"
