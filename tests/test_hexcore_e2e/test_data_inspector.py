# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument inspect_at() data inspector method."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    import types

    from intellicrack_hexcore import HexDocument
_EXPECTED_KEYS: frozenset[str] = frozenset({
    "uint8",
    "int8",
    "uint16_le",
    "uint16_be",
    "uint32_le",
    "uint32_be",
    "uint64_le",
    "uint64_be",
    "int16_le",
    "int16_be",
    "int32_le",
    "int32_be",
    "int64_le",
    "int64_be",
})


class TestInspectAtBasic:
    """Tests for basic structure of the inspect_at() return value.

    Verifies that inspect_at() returns a dict and that the dict contains
    all standard data-type interpretation keys.
    """

    def test_inspect_at_returns_dict(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() returns a dict object.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert isinstance(result, dict)

    def test_inspect_at_has_uint8_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'uint8' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "uint8" in result

    def test_inspect_at_has_int8_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'int8' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "int8" in result

    def test_inspect_at_has_uint16_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'uint16_le' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "uint16_le" in result

    def test_inspect_at_has_uint32_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'uint32_le' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "uint32_le" in result

    def test_inspect_at_has_uint32_be_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'uint32_be' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "uint32_be" in result

    def test_inspect_at_has_uint64_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'uint64_le' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "uint64_le" in result

    def test_inspect_at_has_float32_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'float32_le' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "float32_le" in result

    def test_inspect_at_has_float64_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains the 'float64_le' key.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        assert "float64_le" in result

    def test_inspect_at_contains_all_expected_keys(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() result contains all keys defined in _EXPECTED_KEYS.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        for key in _EXPECTED_KEYS:
            assert key in result, f"Missing expected key: {key!r}"

    def test_inspect_at_all_values_are_strings(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that all values in the inspect_at() dict are strings.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(0)
        for key, value in result.items():
            assert isinstance(value, str), f"Key '{key}' has non-string value: {value!r}"


class TestInspectAtValues:
    """Tests for exact value correctness of inspect_at() on known data.

    Uses a 64-byte buffer with precisely placed integer and float values to
    verify that each interpretation key produces the correct decoded string.
    """

    @pytest.fixture
    def known_doc(self, hexcore: types.ModuleType) -> HexDocument:
        """Build a 64-byte document with known values at specific offsets.

        Args:
            hexcore: The native hexcore module fixture.

        Returns:
            HexDocument: A HexDocument containing 64 bytes of controlled test data.
        """
        data = bytearray(64)
        struct.pack_into("<I", data, 0, 0xDEADBEEF)
        struct.pack_into("<f", data, 16, 1.0)
        struct.pack_into("<d", data, 24, 1.0)
        data[32] = 42
        struct.pack_into("<H", data, 40, 0x1234)
        struct.pack_into(">H", data, 42, 0x5678)
        return hexcore.HexDocument.open_bytes(bytes(data))

    def test_uint8_at_zero_byte_in_known_data(self, hexcore: types.ModuleType) -> None:
        """Verify that inspect_at(0) on bytes(range(256)) gives uint8='0' for the first byte.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(range(256)))
        result = doc.inspect_at(0)
        assert result["uint8"] == "0"

    def test_uint8_at_offset_255(self, hexcore: types.ModuleType) -> None:
        """Verify that inspect_at(255) on bytes(range(256)) gives uint8='255' for the last byte.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes(range(256)))
        result = doc.inspect_at(255)
        assert result["uint8"] == "255"

    def test_uint32_le_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(0) gives uint32_le='3735928559' for 0xDEADBEEF at offset 0.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(0)
        assert result["uint32_le"] == str(0xDEADBEEF)

    def test_uint32_be_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(0) gives the byte-swapped uint32_be for 0xDEADBEEF bytes.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(0)
        expected = struct.unpack(">I", struct.pack("<I", 0xDEADBEEF))[0]
        assert result["uint32_be"] == str(expected)

    def test_uint8_at_known_byte(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(32) gives uint8='42' for the byte set to 42.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(32)
        assert result["uint8"] == "42"

    def test_uint16_le_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(40) gives uint16_le='4660' for 0x1234 stored little-endian.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(40)
        assert result["uint16_le"] == str(0x1234)

    def test_uint16_be_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(42) gives uint16_be='22136' for 0x5678 stored big-endian.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(42)
        assert result["uint16_be"] == str(0x5678)

    def test_float32_le_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(16) gives float32_le near 1.0 for IEEE 754 1.0 float.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(16)
        f32_str = result["float32_le"]
        parsed = float(f32_str)
        assert abs(parsed - 1.0) < 1e-5

    def test_float64_le_known_value(self, known_doc: HexDocument) -> None:
        """Verify that inspect_at(24) gives float64_le near 1.0 for IEEE 754 double 1.0.

        Args:
            known_doc: The 64-byte document with known values.
        """
        result = known_doc.inspect_at(24)
        f64_str = result["float64_le"]
        parsed = float(f64_str)
        assert abs(parsed - 1.0) < 1e-10


class TestInspectAtEdge:
    """Tests for inspect_at() at boundary and near-boundary offsets.

    Verifies that the last byte offset is valid, and that offsets near the
    end of the document where multi-byte types cannot be fully read still
    return a result dict without raising an exception.
    """

    def test_inspect_at_last_valid_offset(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() at the last byte offset returns a dict without error.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        doc_length = sample_doc_from_bytes.length()
        result = sample_doc_from_bytes.inspect_at(doc_length - 1)
        assert isinstance(result, dict)
        assert "uint8" in result

    def test_inspect_at_near_end_partial_types(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() near the end still returns a dict for partial multi-byte types.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result = sample_doc_from_bytes.inspect_at(253)
        assert isinstance(result, dict)
        assert "uint8" in result

    def test_inspect_at_mid_document_offset(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify that inspect_at() at a mid-document offset returns a non-empty dict.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        result: dict[str, str] = sample_doc_from_bytes.inspect_at(128)
        assert isinstance(result, dict)
        assert result

    def test_inspect_at_offset_zero_uint8_value(self, hexcore: types.ModuleType) -> None:
        """Verify that inspect_at(0) on a single-byte document returns uint8 for that byte.

        Args:
            hexcore: The native hexcore module fixture.
        """
        doc = hexcore.HexDocument.open_bytes(bytes([0x7F]))
        result = doc.inspect_at(0)
        assert result["uint8"] == "127"
