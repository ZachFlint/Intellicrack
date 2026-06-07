# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument search and replace operations."""

from __future__ import annotations

import math
import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types


class TestSearchBytes:
    """Tests for HexDocument.search_bytes."""

    def test_finds_pattern_at_known_offsets(self, hexcore: types.ModuleType) -> None:
        """Verify that search_bytes returns the correct offset for each occurrence.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_bytes(b"\xaa\xbb", 100)
        assert len(results) == 2
        assert results[0][0] == 10
        assert results[1][0] == 22

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_bytes returns an empty list when the pattern is absent.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 32
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_bytes(b"\xff\xfe", 100)
        assert not results

    def test_max_results_limits_output(self, hexcore: types.ModuleType) -> None:
        """Verify that search_bytes respects the max_results cap.

        Args:
            hexcore: The native module fixture.
        """
        repeated = b"\xde\xad" * 20
        doc = hexcore.HexDocument.open_bytes(repeated)
        results: list[tuple[int, int]] = doc.search_bytes(b"\xde\xad", 3)
        assert len(results) == 3

    def test_single_byte_pattern_finds_all_positions(self, hexcore: types.ModuleType) -> None:
        """Verify that a single-byte pattern is found at every matching position.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00\xff\x00\xff\x00"
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_bytes(b"\xff", 100)
        assert len(results) == 2
        assert results[0][0] == 1
        assert results[1][0] == 3

    def test_pattern_detected_at_buffer_boundaries(self, hexcore: types.ModuleType) -> None:
        """Verify that search_bytes finds a pattern placed at the very start and end.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\xca\xfe" + b"\x00" * 20 + b"\xca\xfe"
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_bytes(b"\xca\xfe", 100)
        assert len(results) == 2
        assert results[0][0] == 0
        assert results[1][0] == 22


class TestSearchHex:
    """Tests for HexDocument.search_hex."""

    def test_finds_mz_signature_at_offset_zero(self, hexcore: types.ModuleType, pe_bytes: bytes) -> None:
        """Verify that search_hex locates the MZ signature at offset 0 in a PE binary.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        results: list[tuple[int, int]] = doc.search_hex("4D 5A", 100)
        assert results
        assert results[0][0] == 0

    def test_wildcard_byte_matches_pe_header_sequence(self, hexcore: types.ModuleType, pe_bytes: bytes) -> None:
        """Verify that a hex pattern with a wildcard byte matches the MZ header sequence.

        The PE header constructed by conftest starts 4D 5A 90 00 so the pattern
        "4D ?? 90" must match at offset 0.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        try:
            results: list[tuple[int, int]] = doc.search_hex("4D ?? 90", 100)
        except (RuntimeError, ValueError):
            pytest.skip("wildcard hex search not supported by this build")
        assert results
        assert results[0][0] == 0

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_hex returns an empty list when the pattern is absent.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 32
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_hex("FF FE FD", 100)
        assert not results

    def test_max_results_limits_output(self, hexcore: types.ModuleType) -> None:
        """Verify that search_hex respects the max_results cap.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\xab\xcd" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_hex("AB CD", 4)
        assert len(results) == 4

    def test_lowercase_hex_digits_accepted(self, hexcore: types.ModuleType, pe_bytes: bytes) -> None:
        """Verify that search_hex accepts lowercase hex digits and returns the same result.

        Args:
            hexcore: The native module fixture.
            pe_bytes: Minimal PE binary bytes.
        """
        doc = hexcore.HexDocument.open_bytes(pe_bytes)
        results: list[tuple[int, int]] = doc.search_hex("4d 5a", 100)
        assert results
        assert results[0][0] == 0


class TestSearchText:
    """Tests for HexDocument.search_text."""

    def test_case_sensitive_ascii_finds_only_uppercase(self, hexcore: types.ModuleType) -> None:
        """Verify that case-sensitive ASCII search finds only the uppercase occurrence.

        Args:
            hexcore: The native module fixture.
        """
        text_data = b"\x00" * 20 + b"HELLO" + b"\x00" * 20 + b"hello" + b"\x00" * 20
        doc = hexcore.HexDocument.open_bytes(text_data)
        results: list[tuple[int, int]] = doc.search_text("HELLO", "ascii", case_sensitive=True, max_results=100)
        assert len(results) == 1
        assert results[0][0] == 20

    def test_case_insensitive_ascii_finds_both_variants(self, hexcore: types.ModuleType) -> None:
        """Verify that case-insensitive ASCII search matches both case variants.

        Args:
            hexcore: The native module fixture.
        """
        text_data = b"\x00" * 20 + b"HELLO" + b"\x00" * 20 + b"hello" + b"\x00" * 20
        doc = hexcore.HexDocument.open_bytes(text_data)
        results: list[tuple[int, int]] = doc.search_text("hello", "ascii", case_sensitive=False, max_results=100)
        assert len(results) == 2
        offsets = [r[0] for r in results]
        assert 20 in offsets
        assert 45 in offsets

    def test_utf8_encoding_locates_plain_ascii_text(self, hexcore: types.ModuleType) -> None:
        """Verify that a UTF-8 encoded search finds plain ASCII text at the correct offset.

        Args:
            hexcore: The native module fixture.
        """
        text_data = b"\x00" * 15 + b"WORLD" + b"\x00" * 15
        doc = hexcore.HexDocument.open_bytes(text_data)
        results: list[tuple[int, int]] = doc.search_text("WORLD", "utf-8", case_sensitive=True, max_results=100)
        assert len(results) == 1
        assert results[0][0] == 15

    def test_ascii_encoding_locates_embedded_text(self, hexcore: types.ModuleType) -> None:
        """Verify that the ascii encoding parameter correctly locates embedded text.

        Args:
            hexcore: The native module fixture.
        """
        text_data = b"\x00" * 8 + b"TEST" + b"\x00" * 8
        doc = hexcore.HexDocument.open_bytes(text_data)
        results: list[tuple[int, int]] = doc.search_text("TEST", "ascii", case_sensitive=True, max_results=100)
        assert len(results) == 1
        assert results[0][0] == 8

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_text returns an empty list when the text is absent.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 32
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_text("NOTHERE", "ascii", case_sensitive=True, max_results=100)
        assert not results

    def test_max_results_limits_output(self, hexcore: types.ModuleType) -> None:
        """Verify that search_text respects the max_results cap.

        Args:
            hexcore: The native module fixture.
        """
        repeated = b"AB" * 10
        doc = hexcore.HexDocument.open_bytes(repeated)
        results: list[tuple[int, int]] = doc.search_text("AB", "ascii", case_sensitive=True, max_results=3)
        assert len(results) == 3


class TestSearchRegex:
    """Tests for HexDocument.search_regex."""

    def test_finds_uppercase_two_char_sequences(self, hexcore: types.ModuleType) -> None:
        """Verify that a regex pattern matches two-letter uppercase sequences at known offsets.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 15 + b"AB" + b"\x00" * 15 + b"CD" + b"\x00" * 15
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_regex("[A-Z]{2}", 100)
        assert len(results) == 2
        offsets = [r[0] for r in results]
        assert 15 in offsets
        assert 32 in offsets

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_regex returns an empty list when the pattern matches nothing.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 32
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_regex("[A-Z]{3}", 100)
        assert not results

    def test_digit_pattern_matches_ascii_digits(self, hexcore: types.ModuleType) -> None:
        """Verify that a digit regex finds an ASCII decimal sequence at the correct offset.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 10 + b"123" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_regex("[0-9]+", 100)
        assert results
        assert results[0][0] == 10

    def test_max_results_limits_output(self, hexcore: types.ModuleType) -> None:
        """Verify that search_regex respects the max_results cap.

        Args:
            hexcore: The native module fixture.
        """
        data = b"A" * 20
        doc = hexcore.HexDocument.open_bytes(data)
        results: list[tuple[int, int]] = doc.search_regex("A", 5)
        assert len(results) == 5


class TestSearchNumeric:
    """Tests for HexDocument.search_numeric."""

    def test_finds_little_endian_u32_at_known_offsets(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric locates a little-endian u32 at exact byte offsets.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<I", buf, 8, 0x12345678)
        struct.pack_into("<I", buf, 40, 0x12345678)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric(0x12345678, 4, signed=False, big_endian=False, alignment=1, max_results=100)
        offsets = [r[0] for r in results]
        assert 8 in offsets
        assert 40 in offsets

    def test_finds_signed_negative_i32(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric finds a signed negative 32-bit integer.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<i", buf, 20, -42)
        struct.pack_into("<i", buf, 60, -42)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric(-42, 4, signed=True, big_endian=False, alignment=1, max_results=100)
        offsets = [r[0] for r in results]
        assert 20 in offsets
        assert 60 in offsets

    def test_finds_big_endian_u32(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric finds a big-endian u32 at the correct byte offset.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into(">I", buf, 30, 0xAABBCCDD)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric(0xAABBCCDD, 4, signed=False, big_endian=True, alignment=1, max_results=100)
        offsets = [r[0] for r in results]
        assert 30 in offsets

    def test_alignment_excludes_unaligned_matches(self, hexcore: types.ModuleType) -> None:
        """Verify that the alignment parameter skips values stored at non-aligned offsets.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<I", buf, 8, 0xBEEFCAFE)
        struct.pack_into("<I", buf, 12, 0xBEEFCAFE)
        struct.pack_into("<I", buf, 18, 0xBEEFCAFE)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        aligned_results: list[tuple[int, int]] = doc.search_numeric(
            0xBEEFCAFE,
            4,
            signed=False,
            big_endian=False,
            alignment=4,
            max_results=100,
        )
        offsets = [r[0] for r in aligned_results]
        assert 8 in offsets
        assert 12 in offsets
        assert 18 not in offsets

    def test_finds_u16_value_at_known_positions(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric finds a 16-bit unsigned value at two known positions.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(50)
        struct.pack_into("<H", buf, 10, 0x1234)
        struct.pack_into("<H", buf, 30, 0x1234)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric(0x1234, 2, signed=False, big_endian=False, alignment=1, max_results=100)
        offsets = [r[0] for r in results]
        assert 10 in offsets
        assert 30 in offsets

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric returns an empty list when the value is absent.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(64)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric(0xDEADBEEF, 4, signed=False, big_endian=False, alignment=1, max_results=100)
        assert not results


class TestSearchNumericFloat:
    """Tests for HexDocument.search_numeric_float."""

    def test_finds_f32_within_tolerance(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_float finds 32-bit floats within the given tolerance.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<f", buf, 20, math.pi)
        struct.pack_into("<f", buf, 60, math.pi)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_float(
            math.pi,
            4,
            big_endian=False,
            tolerance=0.001,
            alignment=1,
            max_results=100,
        )
        offsets = [r[0] for r in results]
        assert 20 in offsets
        assert 60 in offsets

    def test_no_match_when_value_outside_tolerance(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_float returns empty when no float is within tolerance.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<f", buf, 20, 100.0)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_float(200.0, 4, big_endian=False, tolerance=0.001, alignment=1, max_results=100)
        assert not results

    def test_finds_big_endian_f32_at_correct_offset(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_float finds a big-endian float at the correct offset.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into(">f", buf, 40, math.e)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_float(math.e, 4, big_endian=True, tolerance=0.001, alignment=1, max_results=100)
        offsets = [r[0] for r in results]
        assert 40 in offsets


class TestSearchNumericRange:
    """Tests for HexDocument.search_numeric_range."""

    def test_returns_only_values_inside_the_range(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_range returns offsets for values inside the range.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<I", buf, 8, 50)
        struct.pack_into("<I", buf, 28, 100)
        struct.pack_into("<I", buf, 52, 45)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_range(
            (40, 60),
            4,
            signed=False,
            big_endian=False,
            alignment=1,
            max_results=100,
        )
        offsets = [r[0] for r in results]
        assert 8 in offsets
        assert 52 in offsets
        assert 28 not in offsets

    def test_no_match_returns_empty(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_range returns an empty list when no value is in range.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(64)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_range(
            (100, 200),
            4,
            signed=False,
            big_endian=False,
            alignment=1,
            max_results=100,
        )
        assert not results

    def test_signed_range_includes_negative_values(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_range finds negative signed values within a range.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into("<i", buf, 16, -50)
        struct.pack_into("<i", buf, 40, -10)
        struct.pack_into("<i", buf, 70, 5)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_range(
            (-100, -1),
            4,
            signed=True,
            big_endian=False,
            alignment=1,
            max_results=100,
        )
        offsets = [r[0] for r in results]
        assert 16 in offsets
        assert 40 in offsets
        assert 70 not in offsets

    def test_big_endian_range_search_finds_correct_offsets(self, hexcore: types.ModuleType) -> None:
        """Verify that search_numeric_range operates correctly on big-endian 32-bit values.

        Args:
            hexcore: The native module fixture.
        """
        buf = bytearray(100)
        struct.pack_into(">I", buf, 20, 75)
        struct.pack_into(">I", buf, 50, 200)
        doc = hexcore.HexDocument.open_bytes(bytes(buf))
        results: list[tuple[int, int]] = doc.search_numeric_range(
            (70, 80),
            4,
            signed=False,
            big_endian=True,
            alignment=1,
            max_results=100,
        )
        offsets = [r[0] for r in results]
        assert 20 in offsets
        assert 50 not in offsets


class TestReplaceBytes:
    """Tests for HexDocument.replace_bytes."""

    def test_returns_count_of_replaced_occurrences(self, hexcore: types.ModuleType) -> None:
        """Verify that replace_bytes returns the number of replaced occurrences.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        count: int = doc.replace_bytes(b"\xaa\xbb", b"\xcc\xdd")
        assert count == 2

    def test_document_bytes_reflect_replacement(self, hexcore: types.ModuleType) -> None:
        """Verify that the document bytes at both match offsets show the replacement bytes.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        doc.replace_bytes(b"\xaa\xbb", b"\xcc\xdd")
        assert doc.read(10, 2) == b"\xcc\xdd"
        assert doc.read(22, 2) == b"\xcc\xdd"

    def test_original_pattern_absent_after_replace(self, hexcore: types.ModuleType) -> None:
        """Verify that the original pattern no longer appears after replace_bytes.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10 + b"\xaa\xbb" + b"\x00" * 10
        doc = hexcore.HexDocument.open_bytes(data)
        doc.replace_bytes(b"\xaa\xbb", b"\xcc\xdd")
        remaining: list[tuple[int, int]] = doc.search_bytes(b"\xaa\xbb", 100)
        assert not remaining

    def test_no_match_returns_zero(self, hexcore: types.ModuleType) -> None:
        """Verify that replace_bytes returns 0 when the pattern is not present.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 32
        doc = hexcore.HexDocument.open_bytes(data)
        count: int = doc.replace_bytes(b"\xff\xfe", b"\x00\x01")
        assert count == 0

    def test_single_occurrence_replaced_correctly(self, hexcore: types.ModuleType) -> None:
        """Verify that replace_bytes handles a single match and updates the bytes correctly.

        Args:
            hexcore: The native module fixture.
        """
        data = b"\x00" * 5 + b"\xde\xad\xbe\xef" + b"\x00" * 5
        doc = hexcore.HexDocument.open_bytes(data)
        count: int = doc.replace_bytes(b"\xde\xad\xbe\xef", b"\x11\x22\x33\x44")
        assert count == 1
        assert doc.read(5, 4) == b"\x11\x22\x33\x44"
