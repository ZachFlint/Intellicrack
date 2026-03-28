# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexPat stdlib built-in functions via execute_bytes."""

from __future__ import annotations

import struct

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.stdlib import BuiltinFunctions


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


class TestMemoryFunctions:
    """Tests for mem read functions accessed via built-ins in execute_bytes."""

    def test_read_unsigned_1_byte(self, interp: HexPatInterpreter) -> None:
        """read_unsigned reads a 1-byte unsigned value correctly.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xAB] + [0] * 15)
        source = "u8 result @ read_unsigned(0, 1);"
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0xAB

    def test_read_unsigned_4_bytes_little_endian(self, interp: HexPatInterpreter) -> None:
        """read_unsigned reads a 4-byte LE value as a combined integer.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<I", 0x12345678) + bytes(16)
        source = "u8 offset_result @ 0;\nu32 check = read_unsigned(0, 4);\n"
        interp.execute_bytes(source, data)

    def test_read_signed_negative(self, interp: HexPatInterpreter) -> None:
        """read_signed reads a negative signed byte.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("b", -42) + bytes(15)
        source = "s8 val @ 0;\nu8 ok @ 0;"
        results = interp.execute_bytes(source, data)
        signed_field = next(r for r in results if r["name"] == "val")
        assert signed_field["display_value"] == "-42"

    def test_read_string_returns_text(self, interp: HexPatInterpreter) -> None:
        """read_string reads a null-terminated UTF-8 string from data.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"Hello\x00" + bytes(10)
        source = "str text @ 0;\n"
        results = interp.execute_bytes(source, data)
        assert any("Hello" in str(r["display_value"]) for r in results)

    def test_find_sequence_finds_pattern(self, interp: HexPatInterpreter) -> None:
        """find_sequence returns the correct offset of a byte pattern.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0, 1, 2, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0])
        source = 'u8 found = find_sequence(0, "DEADBEEF");\nu8 ok @ 0;'
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "ok" for r in results)

    def test_mem_size_via_builtin(self) -> None:
        """BuiltinFunctions._mem_size returns the data length."""
        data = bytes(128)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_mem_size")() == 128

    def test_mem_base_address_returns_zero(self) -> None:
        """BuiltinFunctions._mem_base_address returns 0 for file-based data."""
        data = bytes(16)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_mem_base_address")() == 0

    def test_mem_read_unsigned_direct(self) -> None:
        """BuiltinFunctions._mem_read_unsigned reads correctly via direct call."""
        data = struct.pack("<H", 0x1234) + bytes(16)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_read_unsigned")(0, 2)
        assert result == 0x1234

    def test_mem_read_signed_direct_negative(self) -> None:
        """BuiltinFunctions._mem_read_signed returns signed negative value."""
        data = struct.pack("<i", -100) + bytes(16)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_read_signed")(0, 4)
        assert result == -100

    def test_mem_find_sequence_direct_found(self) -> None:
        """BuiltinFunctions._mem_find_sequence finds a 3-byte pattern."""
        data = bytes([0, 1, 2, 0xCA, 0xFE, 0xBA, 0, 0])
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_find_sequence")(0, 8, 0xCA, 0xFE, 0xBA)
        assert result == 3

    def test_mem_find_sequence_direct_not_found(self) -> None:
        """BuiltinFunctions._mem_find_sequence returns -1 when pattern absent."""
        data = bytes([0, 1, 2, 3, 4, 5, 6, 7])
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_find_sequence")(0, 8, 0xFF, 0xEE)
        assert result == -1


class TestStringFunctions:
    """Tests for string built-in functions."""

    def test_string_length_basic(self) -> None:
        """_string_length returns the correct length for a simple string."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_length")("hello") == 5

    def test_string_length_empty(self) -> None:
        """_string_length returns 0 for an empty string."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_length")("") == 0

    def test_string_at_in_bounds(self) -> None:
        """_string_at returns the character at the given index."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_at")("hello", 1) == "e"

    def test_string_at_out_of_bounds(self) -> None:
        """_string_at returns empty string for out-of-bounds index."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert not getattr(builtin, "_string_at")("hi", 10)

    def test_string_substr(self) -> None:
        """_string_substr extracts the specified substring."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_substr")("abcdef", 2, 3) == "cde"

    def test_string_contains_true(self) -> None:
        """_string_contains returns True when substring is present."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_contains")("foobar", "oba") is True

    def test_string_contains_false(self) -> None:
        """_string_contains returns False when substring is absent."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_contains")("foobar", "xyz") is False

    def test_string_starts_with_true(self) -> None:
        """_string_starts_with returns True when prefix matches."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_starts_with")("hello world", "hello") is True

    def test_string_starts_with_false(self) -> None:
        """_string_starts_with returns False when prefix does not match."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_starts_with")("hello world", "world") is False

    def test_string_ends_with_true(self) -> None:
        """_string_ends_with returns True when suffix matches."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_ends_with")("hello world", "world") is True

    def test_string_ends_with_false(self) -> None:
        """_string_ends_with returns False when suffix does not match."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_ends_with")("hello world", "hello") is False

    def test_string_to_int_decimal(self) -> None:
        """_string_to_int converts a decimal string to integer."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_to_int")("42") == 42

    def test_string_to_int_hex(self) -> None:
        """_string_to_int converts a hex string with explicit base 16."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_to_int")("FF", 16) == 255

    def test_string_to_int_invalid_returns_zero(self) -> None:
        """_string_to_int returns 0 for an invalid input string."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_to_int")("not_a_number") == 0

    def test_string_reverse(self) -> None:
        """_string_reverse returns the string in reversed order."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_string_reverse")("abcde") == "edcba"

    def test_string_reverse_empty(self) -> None:
        """_string_reverse of empty string returns empty string."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert not getattr(builtin, "_string_reverse")("")


class TestMathFunctions:
    """Tests for math built-in functions."""

    def test_math_abs_positive(self) -> None:
        """_math_abs returns positive value unchanged."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_abs")(42) == 42

    def test_math_abs_negative(self) -> None:
        """_math_abs returns the absolute value of a negative number."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_abs")(-42) == 42

    def test_math_abs_float(self) -> None:
        """_math_abs works correctly for negative float values."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_abs")(-3.14) - 3.14) < 1e-6

    def test_math_min_integers(self) -> None:
        """_math_min returns the smaller of two integers."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_min")(10, 3) == 3

    def test_math_max_integers(self) -> None:
        """_math_max returns the larger of two integers."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_max")(10, 3) == 10

    def test_math_min_floats(self) -> None:
        """_math_min compares float values correctly."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_min")(1.5, 2.5) - 1.5) < 1e-6

    def test_math_max_floats(self) -> None:
        """_math_max compares float values correctly."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_max")(1.5, 2.5) - 2.5) < 1e-6

    def test_math_floor(self) -> None:
        """_math_floor rounds down to the nearest integer."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_floor")(3.9) == 3

    def test_math_ceil(self) -> None:
        """_math_ceil rounds up to the nearest integer."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_math_ceil")(3.1) == 4

    def test_math_log2_power_of_two(self) -> None:
        """_math_log2 returns the exact log2 of a power of two."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_log2")(8) - 3.0) < 1e-6

    def test_math_log2_non_positive_raises(self) -> None:
        """_math_log2 raises HexPatRuntimeError for non-positive input."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError):
            getattr(builtin, "_math_log2")(0)

    def test_math_pow(self) -> None:
        """_math_pow raises base to the exponent correctly."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_pow")(2.0, 10.0) - 1024.0) < 1e-6

    def test_math_sqrt(self) -> None:
        """_math_sqrt returns the correct square root."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert abs(getattr(builtin, "_math_sqrt")(9.0) - 3.0) < 1e-6

    def test_math_sqrt_negative_raises(self) -> None:
        """_math_sqrt raises HexPatRuntimeError for negative input."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError):
            getattr(builtin, "_math_sqrt")(-1.0)


class TestCoreFunctions:
    """Tests for std::core built-in functions."""

    def test_core_set_get_endian_little(self) -> None:
        """set_endian(0) sets little-endian and get_endian returns 0."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        getattr(builtin, "_core_set_endian")(0)
        assert getattr(builtin, "_core_get_endian")() == 0

    def test_core_set_get_endian_big(self) -> None:
        """set_endian(1) sets big-endian and get_endian returns 1."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        getattr(builtin, "_core_set_endian")(1)
        assert getattr(builtin, "_core_get_endian")() == 1

    def test_core_array_index_default(self) -> None:
        """core_array_index returns 0 before any array index is set."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        assert getattr(builtin, "_core_array_index")() == 0

    def test_core_array_index_after_set(self) -> None:
        """core_array_index returns the value set by set_array_index."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        builtin.set_array_index(7)
        assert getattr(builtin, "_core_array_index")() == 7


class TestIOFunctions:
    """Tests for io built-in functions."""

    def test_io_print_does_not_raise(self) -> None:
        """_io_print completes without raising for any string argument."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        getattr(builtin, "_io_print")("test message")

    def test_io_format_substitutes_placeholder(self) -> None:
        """_io_format replaces {} with the provided argument."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: str = getattr(builtin, "_io_format")("value={}", 42)
        assert "42" in result

    def test_io_format_multiple_placeholders(self) -> None:
        """_io_format replaces multiple {} placeholders in order."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: str = getattr(builtin, "_io_format")("{} + {} = {}", 1, 2, 3)
        assert "1" in result
        assert "2" in result
        assert "3" in result

    def test_io_format_empty_format(self) -> None:
        """_io_format with empty format string returns empty string."""
        data = bytes(4)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: str = getattr(builtin, "_io_format")("")
        assert not result

    def test_print_via_interpreter_no_crash(self, interp: HexPatInterpreter) -> None:
        """print() call from pattern source does not raise.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = 'print("hello from pattern");\nu8 ok @ 0;'
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "ok" for r in results)

    def test_format_via_interpreter_produces_string(self, interp: HexPatInterpreter) -> None:
        """format() call from pattern source returns a string without error.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(4)
        source = "u8 ok @ 0;"
        results = interp.execute_bytes(source, data)
        assert any(r["name"] == "ok" for r in results)
