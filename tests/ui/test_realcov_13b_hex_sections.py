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

Finding [08-F20] required that ``test_min_length_is_enforced`` assert the
EXACT minimum-length threshold, not a vacuous lower bound. The fix imports the
production constant ``_STRINGS_MIN_LENGTH`` from ``sections.py``, gates its
value against the independently-known expected constant (4), and drives the
real extraction call with that exact threshold so that any regression in the
constant or in the parameter-forwarding path causes the test to go red.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.pe_format import detect_format
from intellicrack.ui.panels.hex_editor.sections import (
    _STRINGS_MIN_LENGTH,
    execute_strings_extraction,
)


if TYPE_CHECKING:
    from pathlib import Path


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real string extraction",
)


pytestmark = pytest.mark.integration


_DOS_STUB_TEXT: str = "This program cannot be run in DOS mode."

_EXPECTED_STRINGS_MIN_LENGTH: int = 4
"""Independently-known correct value for the production ``_STRINGS_MIN_LENGTH`` constant.

This value is the independently authoritative minimum string length as
specified by the sections module design. It is not derived from the
production code at test time; it is a constant the test author records
here so that any unilateral change to the production constant is caught.
"""

_MAX_RESULTS: int = 4000

_STRICT_MIN_LENGTH: int = 20
"""A stricter min_length used to verify the parameter is forwarded by the bridge.

When ``execute_strings_extraction`` is called with this value, the result set
must be a strict subset of the result set from the looser threshold and every
returned string must have length >= 20. Any failure here means the
``min_length`` argument is not reaching the hexcore ``extract_strings`` call.
"""

_FORWARDING_MAX_RESULTS: int = 9000
"""A result cap large enough to NOT cap the strict-threshold call (~ 6 k for kernel32.dll).

kernel32.dll yields ~ 35 k strings at min_length=4 and ~ 6 k at min_length=20.
Using 9 000 as the cap means the strict call returns its full un-capped result
set while the loose call is still capped at 9 000. The count comparison is then
strictly conclusive: if min_length is ignored, both calls return 9 000.
"""


def _extract_with_min(path: Path, min_length: int, max_results: int = _MAX_RESULTS) -> list[dict[str, Any]]:
    """Run the real string extraction helper with a given minimum length.

    Args:
        path: Path to a real binary file.
        min_length: Minimum printable-character run length to include.
        max_results: Upper bound on returned entries.

    Returns:
        list[dict[str, Any]]: Extracted string records from the hexcore backend.
    """
    document = hexcore.HexDocument.open(str(path))
    raw = execute_strings_extraction(document, min_length, max_results)
    assert isinstance(raw, list)
    return cast("list[dict[str, Any]]", raw)


def _text_of(record: dict[str, Any]) -> str:
    """Return the string text from an extract_strings record.

    Args:
        record: A single extract_strings result dict.

    Returns:
        str: The decoded string content.
    """
    return next(
        (str(record[key]) for key in ("content", "text", "value") if key in record),
        "",
    )


class TestProductionConstantValue:
    """Gate the exact value of the production ``_STRINGS_MIN_LENGTH`` constant.

    This class exists solely to catch any unilateral change to the constant
    that would alter the application's string-filtering behaviour. The expected
    value ``_EXPECTED_STRINGS_MIN_LENGTH`` is an independently-recorded oracle.
    """

    def test_strings_min_length_constant_is_four(self) -> None:
        """Assert the production minimum-length constant equals its specified value.

        The constant ``_STRINGS_MIN_LENGTH`` in ``sections.py`` must equal 4.
        This is the canonical minimum printable-character run that drives
        ``_populate_strings`` in the UI. If someone changes the constant, this
        test goes red before any downstream breakage occurs.
        """
        assert _STRINGS_MIN_LENGTH == _EXPECTED_STRINGS_MIN_LENGTH, (
            f"sections._STRINGS_MIN_LENGTH changed: expected {_EXPECTED_STRINGS_MIN_LENGTH}, got {_STRINGS_MIN_LENGTH}"
        )


class TestStringExtractionRealPe:
    """String extraction over a real PE must surface real, known strings."""

    def test_dos_stub_string_is_extracted(self, real_pe_dll: Path) -> None:
        """Verify the canonical DOS-stub banner is extracted from a real PE.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        records = _extract_with_min(real_pe_dll, _STRINGS_MIN_LENGTH)
        assert records
        texts = [_text_of(rec) for rec in records]
        assert any(_DOS_STUB_TEXT in text for text in texts), (
            f"Expected to find '{_DOS_STUB_TEXT}' in extracted strings from {real_pe_dll.name}; "
            f"got {len(records)} records but none contained the DOS stub banner"
        )

    def test_offsets_point_at_real_bytes(self, real_pe_dll: Path) -> None:
        """Verify each reported offset actually contains the reported text.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        data = real_pe_dll.read_bytes()
        records = _extract_with_min(real_pe_dll, _STRINGS_MIN_LENGTH)
        checked = 0
        for record in records:
            text = _text_of(record)
            offset_val = record.get("offset")
            encoding = str(record.get("encoding", "")).lower()
            if offset_val is None or "ascii" not in encoding or not text:
                continue
            offset = int(offset_val)
            window = data[offset : offset + len(text)]
            assert window == text.encode("latin-1", errors="ignore")[: len(window)], (
                f"Offset 0x{offset:X}: reported text {text!r} does not match file bytes {window!r}"
            )
            checked += 1
            if checked >= 25:
                break
        assert checked > 0, "No ASCII-encoded records with valid offsets found in real PE"

    def test_min_length_is_enforced(self, real_pe_dll: Path) -> None:
        """Verify all returned strings honour the exact production minimum-length threshold.

        ``execute_strings_extraction`` is invoked with the PRODUCTION constant
        ``_STRINGS_MIN_LENGTH`` (4) so this test mirrors exactly what
        ``_populate_strings`` does at runtime. Every ASCII record returned must
        have at least ``_STRINGS_MIN_LENGTH`` meaningful characters; a shorter
        result proves the hexcore backend is ignoring the ``min_length`` keyword
        argument or the bridge is silently rewriting it.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        records = _extract_with_min(real_pe_dll, _STRINGS_MIN_LENGTH)
        ascii_records = [r for r in records if "ascii" in str(r.get("encoding", "")).lower()]
        assert ascii_records, "Expected at least one ASCII string record from a real PE DLL"
        violations: list[tuple[int, str]] = [
            (len(_text_of(rec).rstrip("\x00")), _text_of(rec))
            for rec in ascii_records
            if len(_text_of(rec).rstrip("\x00")) < _STRINGS_MIN_LENGTH
        ]
        assert not violations, (
            f"extract_strings returned {len(violations)} ASCII string(s) shorter than "
            f"the requested min_length={_STRINGS_MIN_LENGTH} "
            f"(production _STRINGS_MIN_LENGTH={_STRINGS_MIN_LENGTH}): "
            + ", ".join(f"len={length!r} text={text!r}" for length, text in violations[:5])
        )

    def test_min_length_parameter_is_forwarded(self, real_pe_dll: Path) -> None:
        """Verify that stricter min_length thresholds actually reduce the result set.

        Calls ``execute_strings_extraction`` twice with ``_FORWARDING_MAX_RESULTS``
        (9 000) as the cap: once with the production threshold
        (``_STRINGS_MIN_LENGTH = 4``) and once with a much stricter threshold
        (``_STRICT_MIN_LENGTH = 20``). The strict call returns its full un-capped
        result set (~ 6 k for kernel32.dll) while the loose call is capped at
        9 000. The count comparison is therefore conclusive: if ``min_length``
        is ignored, both calls return 9 000.

        Additionally every ASCII record in the strict set must report a
        byte-length (the ``length`` field in the hexcore record) of at least
        ``_STRICT_MIN_LENGTH``. For ASCII strings, byte-length equals
        character-length, so this directly validates the threshold enforcement.

        Args:
            real_pe_dll: Real PE DLL fixture path.
        """
        loose_records = _extract_with_min(real_pe_dll, _STRINGS_MIN_LENGTH, _FORWARDING_MAX_RESULTS)
        strict_records = _extract_with_min(real_pe_dll, _STRICT_MIN_LENGTH, _FORWARDING_MAX_RESULTS)

        assert len(strict_records) < len(loose_records), (
            f"Stricter min_length={_STRICT_MIN_LENGTH} did not reduce the result count: "
            f"loose={len(loose_records)}, strict={len(strict_records)}. "
            "This means min_length is not forwarded to extract_strings."
        )

        ascii_strict = [r for r in strict_records if "ascii" in str(r.get("encoding", "")).lower()]
        for record in ascii_strict:
            byte_length = int(record.get("length", 0))
            assert byte_length >= _STRICT_MIN_LENGTH, (
                f"extract_strings with min_length={_STRICT_MIN_LENGTH} returned an ASCII "
                f"string with byte_length={byte_length}: {_text_of(record)!r}"
            )


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
        magic_bytes = magic if isinstance(magic, bytes) else bytes(magic)
        assert detect_format(magic_bytes) == "pe"

    def test_real_elf_detected(self, real_elf_binary: Path) -> None:
        """Verify a real ELF's leading bytes are classified as ``elf``.

        Args:
            real_elf_binary: Real ELF fixture path.
        """
        document = hexcore.HexDocument.open(str(real_elf_binary))
        magic = document.read(0, 4)
        magic_bytes = magic if isinstance(magic, bytes) else bytes(magic)
        assert detect_format(magic_bytes) == "elf"

    def test_real_macho_detected(self, real_macho_binary: Path) -> None:
        """Verify a real Mach-O's leading bytes are classified as ``macho``.

        Args:
            real_macho_binary: Real Mach-O fixture path.
        """
        document = hexcore.HexDocument.open(str(real_macho_binary))
        magic = document.read(0, 4)
        magic_bytes = magic if isinstance(magic, bytes) else bytes(magic)
        assert detect_format(magic_bytes) == "macho"
