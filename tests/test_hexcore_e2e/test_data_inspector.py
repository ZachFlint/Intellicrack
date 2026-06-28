# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexDocument inspect_at() data inspector method."""

from __future__ import annotations

import math
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
    """Tests for exact decoded values returned by inspect_at() on known bytes.

    All assertions use bytes(range(256)) at offset 0 as input. Oracle values
    are derived independently via struct.unpack on the same byte slice so each
    gate falsifies a specific decoding mutation in the Rust implementation.
    """

    def test_inspect_at_returns_dict(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify inspect_at(0) decodes uint8=0 and int8=0 for the 0x00 byte.

        The first byte of bytes(range(256)) is 0x00. The independent oracle via
        struct.unpack gives unsigned 0 and signed 0. A mutation returning a wrong
        value or swapping signedness would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint8"] == str(struct.unpack("B", data[0:1])[0])
        assert result["int8"] == str(struct.unpack("b", data[0:1])[0])

    def test_inspect_at_has_uint8_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes uint8 to '0' for the 0x00 byte.

        struct.unpack('B', b'\x00') == 0 is the independent oracle. A mutation
        returning a non-zero uint8 for byte 0x00 would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint8"] == str(struct.unpack("B", data[0:1])[0])

    def test_inspect_at_has_int8_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes int8 to '0' for the 0x00 byte.

        struct.unpack('b', b'\x00') == 0. A mutation using wrong sign extension
        for byte 0x00 would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["int8"] == str(struct.unpack("b", data[0:1])[0])

    def test_inspect_at_has_uint16_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes uint16_le to '256' for bytes [0x00, 0x01].

        struct.unpack('<H', b'\x00\x01') == 256. A big-endian mutation returning
        1 instead of 256 would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint16_le"] == str(struct.unpack("<H", data[0:2])[0])

    def test_inspect_at_has_uint32_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes uint32_le to '50462976' for bytes [0x00..0x03].

        struct.unpack('<I', b'\x00\x01\x02\x03') == 50462976. A big-endian
        mutation returning 66051 instead would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint32_le"] == str(struct.unpack("<I", data[0:4])[0])

    def test_inspect_at_has_uint32_be_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes uint32_be to '66051' for bytes [0x00..0x03].

        struct.unpack('>I', b'\x00\x01\x02\x03') == 66051. A little-endian
        mutation returning 50462976 instead would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint32_be"] == str(struct.unpack(">I", data[0:4])[0])

    def test_inspect_at_has_uint64_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        r"""Verify inspect_at(0) decodes uint64_le to '506097522914230528' for bytes [0x00..0x07].

        struct.unpack('<Q', b'\x00\x01\x02\x03\x04\x05\x06\x07') == 506097522914230528.
        A big-endian mutation returning 283686952306183 would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        assert result["uint64_le"] == str(struct.unpack("<Q", data[0:8])[0])

    def test_inspect_at_has_float32_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify inspect_at(0) decodes float32_le to a value matching the struct.unpack oracle.

        struct.unpack('<f', bytes(range(4))) yields a finite positive float. The
        result string is parsed back to float and compared numerically so a
        wrong-endian or wrong-type mutation in the Rust decoder is caught.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        oracle: float = struct.unpack("<f", data[0:4])[0]
        result = sample_doc_from_bytes.inspect_at(0)
        assert math.isclose(float(result["float32_le"]), oracle, rel_tol=1e-6)

    def test_inspect_at_has_float64_le_key(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify inspect_at(0) decodes float64_le to a value matching the struct.unpack oracle.

        struct.unpack('<d', bytes(range(8))) yields a finite positive double. A
        wrong-endian or float32-instead-of-float64 mutation would fail this gate.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        oracle: float = struct.unpack("<d", data[0:8])[0]
        result = sample_doc_from_bytes.inspect_at(0)
        assert math.isclose(float(result["float64_le"]), oracle, rel_tol=1e-12)

    def test_inspect_at_contains_all_expected_keys(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify inspect_at(0) returns exact values for all 14 integer-type keys in _EXPECTED_KEYS.

        Every expected value is derived via struct.unpack on bytes(range(256))[0:N].
        A mutation misencoding any one of the 14 integer types would fail the
        corresponding per-key assertion.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        expected_values: dict[str, str] = {
            "uint8": str(struct.unpack("B", data[0:1])[0]),
            "int8": str(struct.unpack("b", data[0:1])[0]),
            "uint16_le": str(struct.unpack("<H", data[0:2])[0]),
            "uint16_be": str(struct.unpack(">H", data[0:2])[0]),
            "uint32_le": str(struct.unpack("<I", data[0:4])[0]),
            "uint32_be": str(struct.unpack(">I", data[0:4])[0]),
            "uint64_le": str(struct.unpack("<Q", data[0:8])[0]),
            "uint64_be": str(struct.unpack(">Q", data[0:8])[0]),
            "int16_le": str(struct.unpack("<h", data[0:2])[0]),
            "int16_be": str(struct.unpack(">h", data[0:2])[0]),
            "int32_le": str(struct.unpack("<i", data[0:4])[0]),
            "int32_be": str(struct.unpack(">i", data[0:4])[0]),
            "int64_le": str(struct.unpack("<q", data[0:8])[0]),
            "int64_be": str(struct.unpack(">q", data[0:8])[0]),
        }
        for key, expected_val in expected_values.items():
            assert result[key] == expected_val, f"key {key!r}: expected {expected_val!r}, got {result.get(key)!r}"

    def test_inspect_at_all_values_are_strings(self, sample_doc_from_bytes: HexDocument) -> None:
        """Verify inspect_at(0) returns parseable numeric values for float32_le and float64_le.

        The oracle derives the expected floats via struct.unpack. Parsed floats must
        agree within relative tolerance to catch wrong-endian or wrong-width mutations.
        Integer keys are cross-checked against their struct.unpack oracle values.

        Args:
            sample_doc_from_bytes: HexDocument loaded from bytes(range(256)).
        """
        data = bytes(range(256))
        result = sample_doc_from_bytes.inspect_at(0)
        f32_oracle: float = struct.unpack("<f", data[0:4])[0]
        f64_oracle: float = struct.unpack("<d", data[0:8])[0]
        assert math.isclose(float(result["float32_le"]), f32_oracle, rel_tol=1e-6)
        assert math.isclose(float(result["float64_le"]), f64_oracle, rel_tol=1e-12)
        assert result["uint8"] == str(struct.unpack("B", data[0:1])[0])
        assert result["uint16_le"] == str(struct.unpack("<H", data[0:2])[0])
        assert result["uint32_le"] == str(struct.unpack("<I", data[0:4])[0])
        assert result["uint64_le"] == str(struct.unpack("<Q", data[0:8])[0])


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
