# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit7 U01 regression tests for the UTF-16LE scanner (F-0040).

These tests pin the strict ASCII-printable semantics of
``HexEditorBridge._scan_utf16le_runs`` against the prior over-permissive
behaviour, which delegated to :meth:`str.isprintable` and therefore
accepted code units such as ``U+2070`` (superscript zero), ``U+00A3``
(GBP sign), or ``U+2200`` (for-all). The fixed scanner accepts only the
strict ASCII-printable range ``0x20..0x7E`` plus the explicit whitespace
controls (``0x09``, ``0x0A``, ``0x0D``), matching the ``strings(1)``
convention. The tests exercise the scanner through the bridge's public
pure-Python fallback ``_extract_strings_fallback``, which is the same
code path :meth:`HexEditorBridge.get_strings` invokes when the native
backend is unavailable.
"""

from __future__ import annotations

from typing import Any, Protocol, cast

from intellicrack.bridges.hex_editor import HexEditorBridge


_PAD = b"\x00" * 32


class _FallbackScanner(Protocol):
    """Static call signature for the bridge's pure-Python string scanner."""

    def __call__(
        self,
        data: bytes,
        min_length: int,
        max_results: int,
        *,
        include_ascii: bool,
        include_utf16: bool,
    ) -> list[dict[str, Any]]:
        """Scan ``data`` for ASCII and/or UTF-16LE printable runs.

        Args:
            data: Bytes to scan.
            min_length: Minimum number of code units per run.
            max_results: Maximum number of matches to return.
            include_ascii: Include ASCII matches when True.
            include_utf16: Include UTF-16LE matches when True.

        Returns:
            list[dict[str, Any]]: Match dicts with offset, length,
            encoding and content keys.
        """
        ...


def _utf16le_runs(data: bytes, *, min_length: int = 4) -> list[dict[str, Any]]:
    """Run the bridge fallback scanner with UTF-16-only filtering.

    Args:
        data: Bytes to scan.
        min_length: Minimum number of code units required for a run.

    Returns:
        list[dict[str, Any]]: UTF-16LE match dicts produced by the
        bridge's pure-Python fallback scanner.
    """
    scanner = cast("_FallbackScanner", getattr(HexEditorBridge, "_extract_strings_fallback"))
    matches = scanner(
        data,
        min_length,
        64,
        include_ascii=False,
        include_utf16=True,
    )
    return [m for m in matches if m["encoding"] == "utf-16le"]


def test_ascii_hello_utf16le_aligned_detected() -> None:
    """ASCII ``Hello`` encoded UTF-16LE at offset 0 is detected.

    Ensures the strict ASCII-printable filter still accepts the
    canonical ASCII range when each code unit is encoded as two
    little-endian bytes with a ``0x00`` high byte.
    """
    payload = "Hello".encode("utf-16le")
    data = payload + _PAD
    matches = _utf16le_runs(data, min_length=4)
    assert len(matches) == 1
    match = matches[0]
    assert match["offset"] == 0
    assert match["length"] == len(payload)
    assert match["encoding"] == "utf-16le"
    assert match["content"] == "Hello"


def test_ascii_hello_utf16le_misaligned_detected() -> None:
    """ASCII ``Hello`` encoded UTF-16LE starting at offset 1 is detected.

    The scanner runs even-aligned and odd-aligned passes so that
    embedded UTF-16LE strings whose first byte is not 16-bit aligned
    within the container are still recovered.
    """
    payload = "Hello".encode("utf-16le")
    data = b"\xff" + payload + _PAD
    matches = _utf16le_runs(data, min_length=4)
    assert len(matches) == 1
    match = matches[0]
    assert match["offset"] == 1
    assert match["length"] == len(payload)
    assert match["content"] == "Hello"


def test_superscript_zero_run_rejected() -> None:
    """A run of ``U+2070`` (superscript zero) is rejected.

    Pre-fix, :meth:`str.isprintable` returned True for ``U+2070`` and
    the scanner emitted a spurious UTF-16LE run for any run of
    superscript-digit code units. With the strict ASCII filter, no
    match must be produced.
    """
    payload = ("⁰" * 16).encode("utf-16le")
    data = _PAD + payload + _PAD
    matches = _utf16le_runs(data, min_length=4)
    assert matches == []


def test_currency_and_math_symbol_run_rejected() -> None:
    """Long runs of currency and math symbols are rejected.

    Mixes ``U+00A3`` (GBP sign) and ``U+221E`` (infinity). Both were
    accepted by the pre-fix :meth:`str.isprintable` test and both must
    be rejected by the strict ASCII-printable filter on both the
    even-aligned and odd-aligned passes.
    """
    mixed = ("£" * 8 + "∞" * 8).encode("utf-16le")
    data = _PAD + mixed + _PAD
    matches = _utf16le_runs(data, min_length=4)
    assert matches == []


def test_mixed_payload_returns_only_ascii_run() -> None:
    """A buffer that mixes ASCII and non-ASCII code units yields only the ASCII run.

    Lays out an ASCII UTF-16LE string, a separating null pair, then a
    long superscript-digit run, then another null pair, then a second
    ASCII UTF-16LE string. Only the two ASCII runs must be returned;
    the superscript run must be silently dropped.
    """
    ascii_one = "Hello".encode("utf-16le")
    ascii_two = "World".encode("utf-16le")
    noise = ("⁰" * 16).encode("utf-16le")
    sep = b"\x00\x00"
    data = ascii_one + sep + noise + sep + ascii_two + _PAD
    matches = _utf16le_runs(data, min_length=4)
    contents = sorted(m["content"] for m in matches)
    assert contents == ["Hello", "World"]
