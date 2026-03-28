# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat DataReader typed read methods."""

from __future__ import annotations

import struct

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError


def _reader(data: bytes) -> DataReader:
    """Build a DataReader from raw bytes.

    Args:
        data: The raw binary data to wrap.

    Returns:
        DataReader: A DataReader backed by the supplied bytes.
    """
    return DataReader.from_bytes(data)


class TestDataReaderBasic:
    """Tests for basic unsigned integer read methods in little-endian mode."""

    def test_read_u8(self) -> None:
        """read_u8 reads a single unsigned byte."""
        r = _reader(bytes([0xAB]))
        assert r.read_u8(0) == 0xAB

    def test_read_u8_at_offset(self) -> None:
        """read_u8 reads from the correct offset."""
        r = _reader(bytes([0x00, 0xFF]))
        assert r.read_u8(1) == 0xFF

    def test_read_u16_little_endian(self) -> None:
        """read_u16 in little-endian produces the correct value."""
        data = struct.pack("<H", 0x1234)
        r = _reader(data)
        assert r.read_u16(0, "little") == 0x1234

    def test_read_u16_big_endian(self) -> None:
        """read_u16 in big-endian produces the correct value."""
        data = struct.pack(">H", 0x1234)
        r = _reader(data)
        assert r.read_u16(0, "big") == 0x1234

    def test_read_u32_little_endian(self) -> None:
        """read_u32 in little-endian produces the correct value."""
        data = struct.pack("<I", 0xDEADBEEF)
        r = _reader(data)
        assert r.read_u32(0, "little") == 0xDEADBEEF

    def test_read_u32_big_endian(self) -> None:
        """read_u32 in big-endian produces the correct value."""
        data = struct.pack(">I", 0xDEADBEEF)
        r = _reader(data)
        assert r.read_u32(0, "big") == 0xDEADBEEF

    def test_read_u64_little_endian(self) -> None:
        """read_u64 in little-endian produces the correct value."""
        data = struct.pack("<Q", 0xCAFEBABE12345678)
        r = _reader(data)
        assert r.read_u64(0, "little") == 0xCAFEBABE12345678

    def test_read_u64_big_endian(self) -> None:
        """read_u64 in big-endian produces the correct value."""
        data = struct.pack(">Q", 0xCAFEBABE12345678)
        r = _reader(data)
        assert r.read_u64(0, "big") == 0xCAFEBABE12345678

    def test_size_property(self) -> None:
        """DataReader.size returns the total data length."""
        data = bytes(256)
        r = _reader(data)
        assert r.size == 256

    def test_read_raw_bytes(self) -> None:
        """DataReader.read returns the exact byte slice."""
        data = bytes([0, 1, 2, 3, 4, 5])
        r = _reader(data)
        assert r.read(1, 3) == bytes([1, 2, 3])


class TestDataReaderSigned:
    """Tests for signed integer read methods."""

    def test_read_s8_positive(self) -> None:
        """read_s8 reads a positive signed byte."""
        r = _reader(struct.pack("b", 100))
        assert r.read_s8(0) == 100

    def test_read_s8_negative(self) -> None:
        """read_s8 reads a negative signed byte."""
        r = _reader(struct.pack("b", -1))
        assert r.read_s8(0) == -1

    def test_read_s8_min(self) -> None:
        """read_s8 reads the minimum signed byte value -128."""
        r = _reader(struct.pack("b", -128))
        assert r.read_s8(0) == -128

    def test_read_s16_negative_little_endian(self) -> None:
        """read_s16 reads a negative signed 16-bit integer in little-endian."""
        r = _reader(struct.pack("<h", -1000))
        assert r.read_s16(0, "little") == -1000

    def test_read_s16_negative_big_endian(self) -> None:
        """read_s16 reads a negative signed 16-bit integer in big-endian."""
        r = _reader(struct.pack(">h", -1000))
        assert r.read_s16(0, "big") == -1000

    def test_read_s32_negative_little_endian(self) -> None:
        """read_s32 reads a negative signed 32-bit integer in little-endian."""
        r = _reader(struct.pack("<i", -100000))
        assert r.read_s32(0, "little") == -100000

    def test_read_s64_negative_little_endian(self) -> None:
        """read_s64 reads a negative signed 64-bit integer in little-endian."""
        r = _reader(struct.pack("<q", -(2**62)))
        assert r.read_s64(0, "little") == -(2**62)

    def test_read_s128_negative_little_endian(self) -> None:
        """read_s128 reads a negative signed 128-bit integer."""
        val = -(2**100)
        raw = val.to_bytes(16, byteorder="little", signed=True)
        r = _reader(raw)
        assert r.read_s128(0, "little") == val


class TestDataReaderFloat:
    """Tests for IEEE 754 float and double read methods."""

    def test_read_float_value(self) -> None:
        """read_float reads a 32-bit IEEE 754 float correctly."""
        data = struct.pack("<f", 3.14)
        r = _reader(data)
        assert abs(r.read_float(0, "little") - 3.14) < 1e-4

    def test_read_float_big_endian(self) -> None:
        """read_float in big-endian reads the same float as little-endian when data is big-endian."""
        data = struct.pack(">f", 2.71828)
        r = _reader(data)
        assert abs(r.read_float(0, "big") - 2.71828) < 1e-4

    def test_read_double_value(self) -> None:
        """read_double reads a 64-bit IEEE 754 double correctly."""
        data = struct.pack("<d", 1.23456789012345)
        r = _reader(data)
        assert abs(r.read_double(0, "little") - 1.23456789012345) < 1e-10

    def test_read_double_big_endian(self) -> None:
        """read_double in big-endian reads correctly from big-endian data."""
        data = struct.pack(">d", -9.87654321)
        r = _reader(data)
        assert abs(r.read_double(0, "big") - (-9.87654321)) < 1e-6


class TestDataReaderBounds:
    """Tests for out-of-bounds read detection."""

    def test_read_past_end_raises(self) -> None:
        """read() raises HexPatRuntimeError when range exceeds data size."""
        r = _reader(bytes(4))
        with pytest.raises(HexPatRuntimeError):
            r.read(3, 2)

    def test_read_u32_past_end_raises(self) -> None:
        """read_u32 raises HexPatRuntimeError when read would overflow data."""
        r = _reader(bytes(3))
        with pytest.raises(HexPatRuntimeError):
            r.read_u32(0, "little")

    def test_read_negative_offset_raises(self) -> None:
        """read() raises HexPatRuntimeError for a negative offset."""
        r = _reader(bytes(8))
        with pytest.raises(HexPatRuntimeError):
            r.read(-1, 1)

    def test_read_at_exact_end_raises(self) -> None:
        """read() raises HexPatRuntimeError when offset equals data length."""
        r = _reader(bytes(4))
        with pytest.raises(HexPatRuntimeError):
            r.read(4, 1)

    def test_read_zero_bytes_at_start_succeeds(self) -> None:
        """read() with length 0 at offset 0 returns empty bytes without error."""
        r = _reader(bytes(4))
        assert r.read(0, 0) == b""

    def test_read_full_extent_succeeds(self) -> None:
        """read() of the entire data range succeeds without error."""
        data = bytes(range(16))
        r = _reader(data)
        result = r.read(0, 16)
        assert result == data


class TestDataReaderEndianSwitch:
    """Tests for switching endianness between reads."""

    def test_u16_little_vs_big_differ(self) -> None:
        """The same bytes read as little-endian and big-endian produce different values."""
        data = bytes([0x12, 0x34])
        r = _reader(data)
        le_val = r.read_u16(0, "little")
        be_val = r.read_u16(0, "big")
        assert le_val == 0x3412
        assert be_val == 0x1234
        assert le_val != be_val

    def test_u32_little_vs_big_differ(self) -> None:
        """u32 read as little-endian and big-endian from same bytes differ."""
        data = bytes([0x01, 0x02, 0x03, 0x04])
        r = _reader(data)
        assert r.read_u32(0, "little") == 0x04030201
        assert r.read_u32(0, "big") == 0x01020304

    def test_read_string_null_terminated(self) -> None:
        """read_string returns the text before the null byte and correct consumed count."""
        data = b"Hello\x00extra"
        r = _reader(data)
        text, consumed = r.read_string(0)
        assert text == "Hello"
        assert consumed == 6

    def test_read_char_ascii(self) -> None:
        """read_char returns a single ASCII character."""
        r = _reader(b"A")
        assert r.read_char(0) == "A"

    def test_read_bool_nonzero_is_true(self) -> None:
        """read_bool returns True for a non-zero byte."""
        r = _reader(bytes([1]))
        assert r.read_bool(0) is True

    def test_read_bool_zero_is_false(self) -> None:
        """read_bool returns False for a zero byte."""
        r = _reader(bytes([0]))
        assert r.read_bool(0) is False

    def test_find_sequence_across_data(self) -> None:
        """find_sequence locates a 4-byte pattern in the data."""
        data = bytes(20) + b"\xde\xad\xbe\xef" + bytes(20)
        r = _reader(data)
        idx = r.find_sequence(b"\xde\xad\xbe\xef")
        assert idx == 20

    def test_find_sequence_not_present_returns_minus_one(self) -> None:
        """find_sequence returns -1 when the pattern is not present."""
        r = _reader(bytes(32))
        assert r.find_sequence(b"\xff\xff\xff\xff") == -1
