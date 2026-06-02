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


def _extract(path: Path, min_length: int = _MIN_STRING_LEN) -> list[dict[str, Any]]:
    """Run the real string extraction helper against a real binary.

    Args:
        path: Path to a real binary file.
        min_length: Minimum string length to forward to the backend.

    Returns:
        list[dict[str, Any]]: Extracted string records.
    """
    document = hexcore.HexDocument.open(str(path))
    raw = execute_strings_extraction(document, min_length, _MAX_RESULTS)
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


def _length_of(record: dict[str, Any]) -> int:
    r"""Return the backend-reported codepoint length of an extract_strings record.

    The hexcore backend reports the matched run length in codepoints in the
    ``length`` field. This is the authoritative measure the minimum-length
    filter is applied against (the ``content`` field may carry trailing
    delimiter bytes such as ``$`` or ``\r\n``), so the test uses it as the
    independent oracle for enforcement.

    Args:
        record: A single extract_strings result dict.

    Returns:
        int: The reported codepoint length for the record.
    """
    raw = record.get("length")
    assert isinstance(raw, int), f"extract_strings record is missing an integer 'length': {record!r}"
    return raw


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
        """Verify every returned string honours the configured minimum length.

        Drives the real extractor at two distinct floors (6 and 12) and uses
        the backend-reported ``length`` field as the independent oracle. Every
        record at each floor must report ``length >= floor`` (the actual
        enforcement, not a degenerate ``>= 1``), at least one record must sit
        exactly on the boundary to prove the floor is the binding constraint,
        and raising the floor must strictly drop the short matches that the
        lower floor admitted.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        low_floor = 6
        high_floor = 12

        low_records = _extract(real_pe_dll, low_floor)
        high_records = _extract(real_pe_dll, high_floor)
        assert low_records
        assert high_records

        low_lengths = [_length_of(rec) for rec in low_records]
        high_lengths = [_length_of(rec) for rec in high_records]

        assert min(low_lengths) >= low_floor
        assert min(high_lengths) >= high_floor

        assert min(low_lengths) == low_floor, "no record sits on the low floor, so enforcement is unproven"

        short_at_low = sum(1 for length in low_lengths if low_floor <= length < high_floor)
        assert short_at_low > 0, "the low floor admitted no sub-12 strings, so the boundary test is vacuous"
        assert all(length >= high_floor for length in high_lengths)


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
