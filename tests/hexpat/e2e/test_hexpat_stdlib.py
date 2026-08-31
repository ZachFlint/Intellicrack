# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for HexPat stdlib built-in functions via execute_bytes."""

from __future__ import annotations

import math
import struct
from typing import cast

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


_PARSED_FIELD_REQUIRED_KEYS: frozenset[str] = frozenset({
    "name",
    "offset",
    "size",
    "raw_bytes",
    "display_value",
    "children",
})
"""Required keys every parsed-field dict must carry.

Derived from :func:`intellicrack.core.hexpat.evaluator._make_parsed_field`'s
return dict -- not from the test's own output. If any key goes missing due to
a refactor, every test that calls ``_assert_full_field_structure`` will fail.
"""


def _assert_full_field_structure(field: dict[str, object], *, context: str) -> None:
    """Assert all mandatory keys are present and have the expected types.

    Args:
        field: A single parsed-field dict returned by ``execute_bytes``.
        context: Human-readable label for assertion messages.
    """
    for key in _PARSED_FIELD_REQUIRED_KEYS:
        assert key in field, f"{context}: missing key {key!r}"
    assert isinstance(field["name"], str), f"{context}: 'name' must be str"
    assert isinstance(field["offset"], int), f"{context}: 'offset' must be int"
    assert isinstance(field["size"], int), f"{context}: 'size' must be int"
    size: int = field["size"]  # narrowed by isinstance above
    assert size > 0, f"{context}: 'size' must be positive int"
    raw_bytes_val = field["raw_bytes"]
    assert isinstance(raw_bytes_val, list), f"{context}: 'raw_bytes' must be list"
    raw_bytes_list: list[object] = cast("list[object]", raw_bytes_val)
    raw: list[int] = []
    for item in raw_bytes_list:
        assert isinstance(item, int), f"{context}: raw_bytes element {item!r} is not int"
        raw.append(item)
    assert len(raw) == size, f"{context}: raw_bytes length {len(raw)} != size {size}"
    assert all(0 <= b <= 255 for b in raw), f"{context}: raw_bytes contains non-byte values"
    assert isinstance(field["display_value"], str), f"{context}: 'display_value' must be str"
    assert isinstance(field["children"], list), f"{context}: 'children' must be list"


class TestMemoryFunctions:
    """Tests for mem read functions accessed via built-ins in execute_bytes."""

    def test_read_unsigned_1_byte(self, interp: HexPatInterpreter) -> None:
        """read_unsigned reads a 1-byte unsigned value correctly; full dict structure is verified.

        The pattern ``u8 val @ 0;`` places a 1-byte unsigned field at offset 0.
        The data at offset 0 is ``0xAB``, so the field must have:
        - ``offset == 0``     (placed at byte 0)
        - ``size == 1``       (one byte for u8)
        - ``raw_bytes == [0xAB]``  (the exact byte at offset 0)
        - ``display_value == '0xAB'``  (unsigned hex representation)

        All mandatory dict keys (name, offset, size, raw_bytes, display_value,
        children) are also verified by ``_assert_full_field_structure``. A helper
        that returned a partial dict or misread the byte value would fail here.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xAB] + [0] * 7)
        source = "u8 val @ 0;"
        results = interp.execute_bytes(source, data)
        assert results, "execute_bytes returned empty result list"
        field = next(r for r in results if r["name"] == "val")
        _assert_full_field_structure(field, context="test_read_unsigned_1_byte.val")
        assert field["offset"] == 0, f"offset expected 0, got {field['offset']}"
        assert field["size"] == 1, f"u8 field size expected 1, got {field['size']}"
        assert field["raw_bytes"] == [0xAB], f"raw_bytes expected [0xAB], got {field['raw_bytes']}"
        assert field["display_value"] == "0xAB", f"display_value expected '0xAB', got {field['display_value']!r}"

    def test_read_unsigned_4_bytes_little_endian(self, interp: HexPatInterpreter) -> None:
        """read_unsigned reads a 4-byte LE value as a combined integer.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<I", 0x12345678) + bytes(16)
        source = "u32 check = read_unsigned(0, 4);\nu8 marker @ (check == 0x12345678 ? 5 : 6);"
        results = interp.execute_bytes(source, data)
        marker = next(r for r in results if r["name"] == "marker")
        assert marker["offset"] == 5

    def test_read_signed_negative(self, interp: HexPatInterpreter) -> None:
        """read_signed reads a negative signed byte.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("b", -42) + bytes(15)
        assert data[0] == 0xD6
        source = "s8 val @ 0;\nu8 ok @ 0;"
        results = interp.execute_bytes(source, data)
        signed_field = next(r for r in results if r["name"] == "val")
        assert signed_field["display_value"] == "-42"
        assert signed_field["raw_bytes"] == [0xD6]
        assert signed_field["size"] == 1

    def test_read_string_returns_text(self, interp: HexPatInterpreter) -> None:
        """read_string reads a null-terminated UTF-8 string from data.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"Hello\x00World\x00" + bytes(10)
        source = "str text @ 0;\nstr second @ 6;\n"
        results = interp.execute_bytes(source, data)
        text = next(r for r in results if r["name"] == "text")
        second = next(r for r in results if r["name"] == "second")
        assert "Hello" in str(text["display_value"])
        assert "World" not in str(text["display_value"])
        assert "World" in str(second["display_value"])

    def test_find_sequence_finds_pattern(self, interp: HexPatInterpreter) -> None:
        """find_sequence returns the correct offset of a byte pattern.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0, 1, 2]) + b"MAGIC" + bytes([0xAB, 0, 0])
        assert data.index(b"MAGIC") == 3
        source = 'u8 found = find_sequence(0, "MAGIC");\nu8 at_found @ (found + 5);'
        results = interp.execute_bytes(source, data)
        at_found = next(r for r in results if r["name"] == "at_found")
        assert at_found["offset"] == 8
        assert at_found["display_value"] == "0xAB"

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
        """BuiltinFunctions._mem_find_sequence finds a 3-byte pattern.

        The builtin mirrors ImHex's ``find_sequence_in_range(occurrence_index,
        offsetFrom, offsetTo, bytes...)``, so the leading argument selects the
        zero-indexed occurrence.
        """
        data = bytes([0, 1, 2, 0xCA, 0xFE, 0xBA, 0, 0])
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_find_sequence")(0, 0, 8, 0xCA, 0xFE, 0xBA)
        assert result == 3

    def test_mem_find_sequence_direct_not_found(self) -> None:
        """BuiltinFunctions._mem_find_sequence returns -1 when pattern absent."""
        data = bytes([0, 1, 2, 3, 4, 5, 6, 7])
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        result: int = getattr(builtin, "_mem_find_sequence")(0, 8, 0xFF, 0xEE)
        assert result == -1

    def test_mem_read_unsigned_beyond_end_raises(self) -> None:
        """_mem_read_unsigned raises HexPatRuntimeError when offset is at data end.

        The boundary condition: reading 1 byte at offset == data_size must raise.
        A permissive implementation that pads short reads with zeros (instead of
        raising) would fail this assertion. The exact exception type is part of
        the contract; ``ValueError`` or ``IndexError`` would also fail.
        """
        data = bytes(8)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError):
            getattr(builtin, "_mem_read_unsigned")(8, 1)

    def test_mem_read_unsigned_overflow_raises(self) -> None:
        """_mem_read_unsigned raises HexPatRuntimeError when size exceeds remaining bytes.

        Reading 4 bytes starting at offset 6 requires bytes 6, 7, 8, 9 but the
        data is only 8 bytes long; this must raise rather than silently truncate.

        """
        data = bytes(8)
        reader = DataReader.from_bytes(data)
        builtin = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError):
            getattr(builtin, "_mem_read_unsigned")(6, 4)

    def test_execute_bytes_zero_length_data_raises(self, interp: HexPatInterpreter) -> None:
        """execute_bytes raises HexPatRuntimeError when data is empty and pattern reads a byte.

        An empty data buffer contains no bytes; any attempt to read even one byte
        at offset 0 must raise. A silent empty-result return would constitute a
        fake pass (the result list would be empty instead of the field being
        evaluated).

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        with pytest.raises(HexPatRuntimeError):
            interp.execute_bytes("u8 x @ 0;", bytes(0))

    def test_execute_bytes_max_u8_full_structure(self, interp: HexPatInterpreter) -> None:
        """execute_bytes on a max-value u8 returns the correct full structure.

        The data byte ``0xFF`` maps to the u8 maximum value (255). The test
        asserts the complete parsed-field dict -- all mandatory keys present with
        correct types, raw_bytes containing exactly ``[255]``, and display_value
        ``'0xFF'``. A helper that clipped to a signed byte (returning -1) or
        omitted any dict key would fail here.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xFF] + [0] * 7)
        results = interp.execute_bytes("u8 x @ 0;", data)
        assert results, "execute_bytes returned empty list for max-value u8"
        field = next(r for r in results if r["name"] == "x")
        _assert_full_field_structure(field, context="max_u8")
        assert field["offset"] == 0
        assert field["size"] == 1
        assert field["raw_bytes"] == [0xFF]
        assert field["display_value"] == "0xFF"

    def test_execute_bytes_u32_full_structure(self, interp: HexPatInterpreter) -> None:
        """execute_bytes on a 4-byte LE u32 returns the correct full structure.

        The LE encoding of ``0xDEADBEEF`` is ``[0xEF, 0xBE, 0xAD, 0xDE]``.
        Asserts raw_bytes in LE order, size == 4, and display_value matches the
        hex representation. A helper that byte-swapped the raw_bytes list or
        returned the wrong size would fail these exact-value assertions.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        value = 0xDEADBEEF
        data = struct.pack("<I", value) + bytes(4)
        results = interp.execute_bytes("u32 v @ 0;", data)
        assert results, "execute_bytes returned empty list for u32"
        field = next(r for r in results if r["name"] == "v")
        _assert_full_field_structure(field, context="u32_deadbeef")
        assert field["offset"] == 0
        assert field["size"] == 4
        assert field["raw_bytes"] == [0xEF, 0xBE, 0xAD, 0xDE]
        assert "DEADBEEF" in field["display_value"].upper()


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
        assert abs(getattr(builtin, "_math_abs")(-math.pi) - math.pi) < 1e-6

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

    def test_format_via_interpreter_produces_string(self) -> None:
        """format() substitutes a field value into the template and routes via print().

        Data layout: offset 0 holds byte ``0xAB`` (171 decimal).
        Pattern: ``u8 x @ 0; print(format("x={}", x));``

        The expected captured output is ``"x=171"`` because:
        - ``x`` evaluates to the unsigned integer 171 (``_unwrap`` on the
          resulting PatternValue returns the int stored in ``.value``).
        - ``format`` calls ``_format_string`` which substitutes
          ``str(171)`` = ``"171"`` for the ``{}`` placeholder.
        - ``print`` routes the formatted string through the registered sink.

        A regression in ``_format_string`` (wrong substitution, wrong value
        extraction, broken placeholder scanning) would produce the wrong string
        and fail the equality assertion.
        """
        captured: list[str] = []

        def _sink(msg: str) -> None:
            captured.append(msg)

        data = bytes([0xAB, 0x00, 0x00, 0x00])
        source = 'u8 x @ 0;\nprint(format("x={}", x));'
        interp_with_sink = HexPatInterpreter(print_sink=_sink)
        results = interp_with_sink.execute_bytes(source, data)
        assert any(r["name"] == "x" for r in results), "field 'x' must appear in parsed results"
        assert len(captured) == 1, f"expected exactly 1 print call, got {len(captured)}: {captured!r}"
        assert captured[0] == "x=171", f"format substitution produced wrong output: {captured[0]!r}"
