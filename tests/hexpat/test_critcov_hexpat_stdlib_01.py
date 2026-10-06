# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the HexPat built-in function library.

Pattern-language sources are run through the real preprocessor, lexer, parser
and evaluator, wired to the real ``BuiltinFunctions`` object exactly as the
interpreter wires it. The value a built-in produced is read back from the
variable the pattern bound it to. Expected values come from the standard
library (``struct``, ``math``, ``zlib``, ``time``), from published CRC
catalogue check values, from bit arithmetic done on strings, and from the
layout in the vendored ``std/time.pat`` and ``std/math.pat``. Built-ins whose
argument shapes the pattern language cannot spell (raw ``bytes`` payloads,
a reflection provider carrying a bit-offset hook, a data reader whose backing
store comes up short) are reached through the registered built-in table or the
public setters of the real ``BuiltinFunctions`` object.
"""

from __future__ import annotations

import dataclasses
import functools
import math
import operator
import struct
import time
import zlib
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.hexpat import stdlib as stdlib_module
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import BuiltinCallable, EvalScope, HexPatEvaluator, PatternValue
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions
from intellicrack.core.hexpat.type_system import TypeRegistry


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import BinaryIO

    from intellicrack.core.hexpat.ast_nodes import DeclNode, StmtNode


_SEQUENCE_DATA: bytes = b"\x01\x02xx\x01\x02yy\x01\x02"
_TEXT_DATA: bytes = b"foo-bar-foo-baz-foo"
_BIT_DATA: bytes = bytes([
    0xB4,
    0x69,
    0xF0,
    0x0F,
    0xAA,
    0x55,
    0x12,
    0x34,
    0x56,
    0x78,
    0x9A,
    0xBC,
    0xDE,
    0xF0,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
])
_CRC_CHECK: bytes = b"123456789"
_ACCUMULATE_VALUES: tuple[int, ...] = (37, 100, 11, 5)
_EPOCH_BILLION: int = 1_000_000_000
_TIME_LAYOUT: str = "<BBBBBHBHB5x"


def _wire(source: str, data: bytes) -> tuple[HexPatEvaluator, list[DeclNode | StmtNode], BuiltinFunctions]:
    """Build an evaluator wired to the standard library exactly as the interpreter wires it.

    Args:
        source: The pattern source to preprocess, lex and parse.
        data: The bytes the evaluator and the built-ins read from.

    Returns:
        tuple[HexPatEvaluator, list[DeclNode | StmtNode], BuiltinFunctions]: The
        evaluator, the parsed program it has not yet evaluated and the
        built-in library registered into the evaluator's scope.
    """
    processed, pragma = HexPatPreprocessor().process(source)
    program = HexPatParser(HexPatLexer(processed).tokenize()).parse()
    reader = DataReader.from_bytes(data)
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_array_index_provider(evaluator.current_array_index)
    stdlib.set_endian_listener(evaluator.set_default_endian)
    stdlib.set_reflection_provider(evaluator.reflection_provider())
    stdlib.register_all(evaluator.scope)
    return evaluator, program, stdlib


def _release_files(stdlib: BuiltinFunctions) -> None:
    """Close every file handle a built-in library still holds.

    Args:
        stdlib: The built-in library whose open handles are released.
    """
    handles: dict[int, BinaryIO] = getattr(stdlib, "_file_handles")
    for handle in handles.values():
        handle.close()
    handles.clear()


def _execute(source: str, data: bytes = b"") -> tuple[HexPatEvaluator, BuiltinFunctions]:
    """Evaluate a pattern and release any file the pattern left open.

    Args:
        source: The pattern source to run.
        data: The bytes the pattern reads from.

    Returns:
        tuple[HexPatEvaluator, BuiltinFunctions]: The evaluator that ran the
        pattern and the built-in library it used.
    """
    evaluator, program, stdlib = _wire(source, data)
    try:
        evaluator.evaluate(program)
    finally:
        _release_files(stdlib)
    return evaluator, stdlib


def _bound(evaluator: HexPatEvaluator, name: str) -> object:
    """Read back the value a pattern bound to a variable.

    Args:
        evaluator: The evaluator that ran the pattern.
        name: The variable name.

    Returns:
        object: The raw value held by the variable.
    """
    bound = evaluator.scope.get(name)
    assert bound is not None, f"'{name}' was never bound"
    return bound.value


def _eval(expression: str, data: bytes = b"") -> object:
    """Evaluate one pattern-language expression and return its value.

    Args:
        expression: The expression, for example ``std::math::abs(-7)``.
        data: The bytes the expression reads from.

    Returns:
        object: The raw value of the expression.
    """
    evaluator, _stdlib = _execute(f"auto result = {expression};", data)
    return _bound(evaluator, "result")


def _failure(source: str, data: bytes = b"") -> str:
    """Run a pattern that must raise a runtime error and return its message.

    Args:
        source: The pattern source to run.
        data: The bytes the pattern reads from.

    Returns:
        str: The message of the raised ``HexPatRuntimeError``.
    """
    with pytest.raises(HexPatRuntimeError) as excinfo:
        _execute(source, data)
    return excinfo.value.message


def _assert_empty_string(value: object) -> None:
    """Assert that a value is the empty string and not merely falsey.

    Args:
        value: The value to check.
    """
    assert isinstance(value, str)
    assert not value


def _builtin_table(data: bytes = b"") -> tuple[BuiltinFunctions, EvalScope]:
    """Register the real built-in library into a fresh scope.

    Args:
        data: The bytes the library reads from.

    Returns:
        tuple[BuiltinFunctions, EvalScope]: The library and the scope holding
        its registered callables.
    """
    stdlib = BuiltinFunctions(DataReader.from_bytes(data))
    scope = EvalScope()
    stdlib.register_all(scope)
    return stdlib, scope


def _call(scope: EvalScope, name: str, *args: object) -> object:
    """Invoke a registered built-in the way the evaluator does.

    Args:
        scope: The scope the built-ins were registered into.
        name: The registered built-in name, for example ``std::file::write``.
        *args: The positional arguments handed to the built-in.

    Returns:
        object: Whatever the built-in returned.
    """
    entry = scope.get(name)
    assert entry is not None, f"'{name}' is not registered"
    assert isinstance(entry.value, BuiltinCallable)
    return entry.value.fn(*args)


def _section_bytes(stdlib: BuiltinFunctions, handle: int) -> bytes:
    """Read the bytes held by a custom memory section.

    Args:
        stdlib: The built-in library that owns the section.
        handle: The section handle.

    Returns:
        bytes: A copy of the section's contents.
    """
    sections: dict[int, object] = getattr(stdlib, "_sections")
    payload: bytearray = getattr(sections[handle], "data")
    return bytes(payload)


def _bit_slice(data: bytes, byte_offset: int, bit_offset: int, bit_size: int) -> int:
    """Extract a bit range by slicing the binary text of the bytes.

    Args:
        data: The bytes to read from.
        byte_offset: The byte the range starts in.
        bit_offset: The bit within that byte, counted from the most significant bit.
        bit_size: The number of bits to extract.

    Returns:
        int: The extracted bits read as one big-endian unsigned integer.
    """
    text = "".join(f"{byte:08b}" for byte in data[byte_offset:])
    return int(text[bit_offset : bit_offset + bit_size], 2)


def _packed_time(tm: time.struct_time) -> int:
    """Pack a ``struct_time`` into the ``std::time::Time`` layout as a little-endian u128.

    Args:
        tm: The broken-down time to pack.

    Returns:
        int: The 16-byte value: sec, min, hour, mday, mon, u16 year, wday,
        u16 yday, isdst and five bytes of padding.
    """
    layout = struct.pack(
        _TIME_LAYOUT,
        tm.tm_sec,
        tm.tm_min,
        tm.tm_hour,
        tm.tm_mday,
        tm.tm_mon,
        tm.tm_year,
        tm.tm_wday,
        tm.tm_yday,
        1 if tm.tm_isdst > 0 else 0,
    )
    return int.from_bytes(layout, "little")


def _dataclass_provider(evaluator: HexPatEvaluator) -> object:
    """Build the library's own reflection-provider dataclass from the evaluator's live callbacks.

    Args:
        evaluator: The evaluator whose reflection callbacks populate the provider.

    Returns:
        object: An instance of the library's reflection-provider dataclass.
    """
    provider_type: Callable[..., object] = getattr(stdlib_module, "_ReflectionProvider")
    live = evaluator.reflection_provider()
    return provider_type(**{field.name: getattr(live, field.name) for field in dataclasses.fields(live)})


def _hook_returning_five(_provider: object) -> int:
    """Report a bit offset of five.

    Args:
        _provider: The provider instance the hook is bound to.

    Returns:
        int: The constant five.
    """
    return 5


def _hook_returning_text(_provider: object) -> str:
    """Report a bit offset that is not an integer.

    Args:
        _provider: The provider instance the hook is bound to.

    Returns:
        str: A non-integer value.
    """
    return "five"


def _provider_with_hook(hook: Callable[[object], object]) -> object:
    """Derive a provider from the library's reflection dataclass that carries a bit-offset hook.

    Args:
        hook: The function installed as the ``current_bit_offset`` method.

    Returns:
        object: An instance of the derived provider class.
    """
    base: type[object] = getattr(stdlib_module, "_ReflectionProvider")
    derived = type("BitOffsetProvider", (base,), {"current_bit_offset": hook})
    instance: object = derived()
    return instance


class TestReflectionWiring:
    """Installing, replacing and removing the evaluator-backed reflection provider."""

    def test_dataclass_provider_is_installed_as_given(self) -> None:
        """A provider that already is the library's dataclass is stored without copying."""
        evaluator, program, stdlib = _wire("u8 v @ 0;\nauto text = std::core::formatted_value(v);", bytes([7]))
        provider = _dataclass_provider(evaluator)
        stdlib.set_reflection_provider(provider)
        evaluator.evaluate(program)
        assert getattr(stdlib, "_reflection") is provider
        assert _bound(evaluator, "text") == "0x7"

    def test_none_provider_unwires_reflection(self) -> None:
        """Passing ``None`` removes the provider, so reflection built-ins fail loudly."""
        evaluator, program, stdlib = _wire("u8 v @ 0;\nauto text = std::core::formatted_value(v);", bytes([7]))
        stdlib.set_reflection_provider(None)
        with pytest.raises(HexPatRuntimeError) as excinfo:
            evaluator.evaluate(program)
        assert excinfo.value.message == "std::core::formatted_value requires evaluator metadata not yet wired"

    def test_bit_offset_is_zero_without_a_provider_hook(self) -> None:
        """The evaluator's provider has no bit-offset hook, so the offset is zero."""
        assert _eval("std::mem::current_bit_offset()", bytes(4)) == 0

    @pytest.mark.parametrize(
        ("hook", "expected"),
        [(_hook_returning_five, 5), (_hook_returning_text, 0)],
        ids=["integer-hook-result", "non-integer-hook-result"],
    )
    def test_bit_offset_hook_result_is_used_only_when_an_integer(
        self,
        hook: Callable[[object], object],
        expected: int,
    ) -> None:
        """A provider exposing ``current_bit_offset`` answers the built-in when it returns an int.

        Args:
            hook: The bit-offset hook installed on the derived provider.
            expected: The offset the pattern must observe.
        """
        evaluator, program, stdlib = _wire("auto bit = std::mem::current_bit_offset();", bytes(4))
        stdlib.set_reflection_provider(_provider_with_hook(hook))
        evaluator.evaluate(program)
        assert _bound(evaluator, "bit") == expected


class TestMemoryReads:
    """``std::mem`` string, sequence and bit-field reads."""

    def test_read_string_stops_at_first_nul(self) -> None:
        """The decoded string ends at the first NUL byte inside the requested range."""
        data = b"abc\x00defg"
        assert _eval("std::mem::read_string(0, 8)", data) == data[:8].split(b"\x00")[0].decode("utf-8")
        assert _eval("std::mem::read_string(4, 4)", data) == "defg"

    @pytest.mark.parametrize(
        ("arguments", "expected"),
        [
            ("0, 0, 10", 0),
            ("1, 0, 10", 4),
            ("2, 0, 10", 8),
            ("2, 0, 9", -1),
            ("3, 0, 10", -1),
            ("0, 1, 10", 4),
            ("-1, 0, 10", -1),
        ],
        ids=["first", "second", "third", "span-past-range-end", "missing-fourth", "range-start-skips-first", "negative-index"],
    )
    def test_find_sequence_selects_nth_occurrence_inside_range(self, arguments: str, expected: int) -> None:
        """The Nth occurrence whose whole span fits in the range is returned, else ``-1``.

        Args:
            arguments: Occurrence index, range start and range end.
            expected: The offset the search must return.
        """
        assert [i for i in range(len(_SEQUENCE_DATA)) if _SEQUENCE_DATA.startswith(b"\x01\x02", i)] == [0, 4, 8]
        assert _eval(f"std::mem::find_sequence_in_range({arguments}, 0x01, 0x02)", _SEQUENCE_DATA) == expected

    def test_find_sequence_needs_a_pattern_and_masks_bytes(self) -> None:
        """Fewer than four arguments find nothing and pattern values are reduced to bytes."""
        assert _eval("std::mem::find_sequence_in_range(0, 0, 10)", _SEQUENCE_DATA) == -1
        assert _eval("std::mem::find_sequence_in_range(0, 0, 10, 0x101, 0x102)", _SEQUENCE_DATA) == 0

    @pytest.mark.parametrize(
        ("arguments", "needle", "expected"),
        [
            ("0, 0, 19", "foo", 0),
            ("1, 0, 19", "foo", 8),
            ("2, 0, 19", "foo", 16),
            ("2, 0, 18", "foo", -1),
            ("3, 0, 19", "foo", -1),
            ("0, 1, 19", "foo", 8),
            ("-1, 0, 19", "foo", -1),
            ("0, 0, 19", "", -1),
            ("0, 0, 19", "zzz", -1),
        ],
        ids=[
            "first",
            "second",
            "third",
            "span-past-range-end",
            "missing-fourth",
            "range-start-skips-first",
            "negative-index",
            "empty-needle",
            "absent",
        ],
    )
    def test_find_string_selects_nth_occurrence_inside_range(self, arguments: str, needle: str, expected: int) -> None:
        """String search returns the Nth in-range occurrence of the UTF-8 needle, else ``-1``.

        Args:
            arguments: Occurrence index, range start and range end.
            needle: The string searched for.
            expected: The offset the search must return.
        """
        assert [i for i in range(len(_TEXT_DATA)) if _TEXT_DATA.startswith(b"foo", i)] == [0, 8, 16]
        assert _eval(f'std::mem::find_string_in_range({arguments}, "{needle}")', _TEXT_DATA) == expected

    def test_find_string_needs_a_needle(self) -> None:
        """Fewer than four arguments find nothing."""
        assert _eval("std::mem::find_string_in_range(0, 0, 19)", _TEXT_DATA) == -1

    @pytest.mark.parametrize(
        ("byte_offset", "bit_offset", "bit_size"),
        [(0, 2, 5), (0, 0, 8), (1, 5, 10), (2, 7, 1), (0, 0, 128), (3, 3, 128), (6, 4, 3)],
        ids=["inside-one-byte", "whole-byte", "across-bytes", "single-bit", "u128-aligned", "u128-unaligned-to-end", "mid-stream"],
    )
    def test_read_bits_extracts_msb_first_range(self, byte_offset: int, bit_offset: int, bit_size: int) -> None:
        """The first bit read is the most significant bit of the returned value.

        Args:
            byte_offset: Byte the range starts in.
            bit_offset: Bit within that byte, from the most significant bit.
            bit_size: Number of bits read.
        """
        expected = _bit_slice(_BIT_DATA, byte_offset, bit_offset, bit_size)
        assert _eval(f"std::mem::read_bits({byte_offset}, {bit_offset}, {bit_size})", _BIT_DATA) == expected

    @pytest.mark.parametrize(
        ("arguments", "message"),
        [
            ("0, 0", "std::mem::read_bits requires (byte_offset, bit_offset, bit_size)"),
            ("0, 0, 0", "std::mem::read_bits: bit_size must be positive"),
            ("0, 0, -3", "std::mem::read_bits: bit_size must be positive"),
            ("0, 0, 129", "std::mem::read_bits: bit_size must not exceed 128"),
            ("0, 8, 1", "std::mem::read_bits: bit_offset must be in [0, 7]"),
            ("0, -1, 1", "std::mem::read_bits: bit_offset must be in [0, 7]"),
        ],
        ids=["too-few-arguments", "zero-size", "negative-size", "oversize", "offset-above-seven", "negative-offset"],
    )
    def test_read_bits_rejects_bad_arguments(self, arguments: str, message: str) -> None:
        """Wrong argument counts and out-of-range bit parameters are runtime errors.

        Args:
            arguments: The argument list passed to ``read_bits``.
            message: The expected error message.
        """
        assert _failure(f"auto result = std::mem::read_bits({arguments});", _BIT_DATA) == message

    def test_read_bits_reports_a_short_read(self) -> None:
        """A backing store that returns fewer bytes than were sized is a runtime error."""
        backing = bytes([0xAA, 0xBB])
        reader = DataReader(lambda offset, length: backing[offset : offset + length][:1], 8)
        stdlib = BuiltinFunctions(reader)
        scope = EvalScope()
        stdlib.register_all(scope)
        with pytest.raises(HexPatRuntimeError) as excinfo:
            _call(scope, "std::mem::read_bits", 1, 0, 16)
        assert excinfo.value.message == "std::mem::read_bits: short read at byte 0x1 (needed 2 bytes, got 1)"


class TestMemorySections:
    """``std::mem`` custom sections: create, resize, copy and delete."""

    def test_copies_between_binary_and_sections_zero_extend_destination(self) -> None:
        """Copies from the binary and from another section land at the right addresses."""
        data = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        source = (
            'auto sec_a = std::mem::create_section("a");\n'
            'auto sec_b = std::mem::create_section("b");\n'
            "std::mem::copy_to_section(0, 1, sec_a, 0, 4);\n"
            "std::mem::copy_to_section(sec_a, 2, sec_b, 0, 2);\n"
            "std::mem::copy_to_section(0, 0, sec_b, 3, 2);\n"
            "auto size_a = std::mem::get_section_size(sec_a);\n"
            "auto size_b = std::mem::get_section_size(sec_b);\n"
        )
        evaluator, stdlib = _execute(source, data)
        assert (_bound(evaluator, "sec_a"), _bound(evaluator, "sec_b")) == (1, 2)
        assert _section_bytes(stdlib, 1) == data[1:5]
        assert _section_bytes(stdlib, 2) == data[3:5] + b"\x00" + data[0:2]
        assert (_bound(evaluator, "size_a"), _bound(evaluator, "size_b")) == (4, 5)

    @pytest.mark.parametrize(
        ("statements", "message"),
        [
            (
                "std::mem::copy_to_section(0, 0, 1);",
                "std::mem::copy_to_section requires (from_section, from_address, to_section, to_address, size)",
            ),
            ("std::mem::copy_to_section(0, 0, sec_a, 0, -1);", "std::mem::copy_to_section: size must be non-negative"),
            ("std::mem::copy_to_section(7, 0, sec_a, 0, 1);", "std::mem::copy_to_section: unknown source section 7"),
            ("std::mem::copy_to_section(sec_a, 3, sec_a, 0, 2);", "std::mem::copy_to_section: source range out of bounds"),
            ("std::mem::copy_to_section(sec_a, -1, sec_a, 0, 1);", "std::mem::copy_to_section: source range out of bounds"),
            ("std::mem::copy_to_section(0, 0, 9, 0, 1);", "std::mem::copy_to_section: unknown destination section 9"),
        ],
        ids=["too-few-arguments", "negative-size", "unknown-source", "range-past-end", "negative-address", "unknown-destination"],
    )
    def test_copy_to_section_errors(self, statements: str, message: str) -> None:
        """Bad copy requests are runtime errors naming the problem.

        Args:
            statements: The failing statement, run after a four-byte section is filled.
            message: The expected error message.
        """
        prelude = 'auto sec_a = std::mem::create_section("a");\nstd::mem::copy_to_section(0, 0, sec_a, 0, 4);\n'
        assert _failure(prelude + statements, bytes([1, 2, 3, 4, 5, 6])) == message

    def test_copy_to_section_accepts_a_range_ending_at_the_section_end(self) -> None:
        """A source range that ends exactly at the end of the section is allowed."""
        data = bytes([0x11, 0x22, 0x33, 0x44])
        source = (
            'auto sec_a = std::mem::create_section("a");\n'
            'auto sec_b = std::mem::create_section("b");\n'
            "std::mem::copy_to_section(0, 0, sec_a, 0, 4);\n"
            "std::mem::copy_to_section(sec_a, 2, sec_b, 0, 2);\n"
        )
        _evaluator, stdlib = _execute(source, data)
        assert _section_bytes(stdlib, 2) == data[2:4]

    def test_copy_value_to_section_copies_the_pattern_bytes(self) -> None:
        """A placed value's bytes are copied to the destination address, padding the gap with zeros."""
        data = bytes([0x01, 0x02, 0xAB, 0xCD, 0x05, 0x06])
        source = 'auto sec_a = std::mem::create_section("a");\nu16 word @ 2;\nstd::mem::copy_value_to_section(word, sec_a, 3);\n'
        _evaluator, stdlib = _execute(source, data)
        assert _section_bytes(stdlib, 1) == b"\x00\x00\x00" + data[2:4]

    @pytest.mark.parametrize(
        ("statements", "message"),
        [
            ("std::mem::copy_value_to_section(1, 2);", "std::mem::copy_value_to_section requires (value, to_section, to_address)"),
            ("std::mem::copy_value_to_section(5, sec_a, 0);", "std::mem::copy_value_to_section: value has no binary footprint"),
            ("std::mem::copy_value_to_section(word, 9, 0);", "std::mem::copy_value_to_section: unknown destination section 9"),
        ],
        ids=["too-few-arguments", "no-binary-footprint", "unknown-destination"],
    )
    def test_copy_value_to_section_errors(self, statements: str, message: str) -> None:
        """Bad value copies are runtime errors naming the problem.

        Args:
            statements: The failing statement, run after a section and a placed word exist.
            message: The expected error message.
        """
        prelude = 'auto sec_a = std::mem::create_section("a");\nu16 word @ 0;\n'
        assert _failure(prelude + statements, bytes([1, 2, 3, 4])) == message

    def test_copy_value_to_section_rejects_a_raw_argument(self) -> None:
        """A first argument that is not a pattern value has no binary footprint."""
        _stdlib, scope = _builtin_table(bytes([1, 2, 3, 4]))
        _call(scope, "std::mem::create_section", "a")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            _call(scope, "std::mem::copy_value_to_section", 5, 1, 0)
        assert excinfo.value.message == "std::mem::copy_value_to_section: value has no binary footprint"

    def test_delete_section_releases_the_handle(self) -> None:
        """A deleted section cannot be deleted or sized again."""
        source = 'auto sec_a = std::mem::create_section("a");\nstd::mem::delete_section(sec_a);\n'
        assert _failure(source + "std::mem::delete_section(sec_a);") == "std::mem::delete_section: unknown section handle 1"
        assert _failure(source + "std::mem::get_section_size(sec_a);") == "std::mem::get_section_size: unknown section handle"

    @pytest.mark.parametrize(
        ("statement", "message"),
        [
            ("std::mem::delete_section();", "std::mem::delete_section requires a section handle"),
            ("std::mem::delete_section(5);", "std::mem::delete_section: unknown section handle 5"),
            ("std::mem::get_section_size();", "std::mem::get_section_size: unknown section handle"),
            ("std::mem::get_section_size(3);", "std::mem::get_section_size: unknown section handle"),
            ("std::mem::set_section_size(1);", "std::mem::set_section_size requires (section, size)"),
            ("std::mem::set_section_size(4, 2);", "std::mem::set_section_size: unknown section handle"),
        ],
        ids=["delete-no-argument", "delete-unknown", "size-no-argument", "size-unknown", "resize-too-few-arguments", "resize-unknown"],
    )
    def test_section_handle_errors(self, statement: str, message: str) -> None:
        """Missing or unknown section handles are runtime errors.

        Args:
            statement: The failing statement.
            message: The expected error message.
        """
        assert _failure(statement) == message

    def test_set_section_size_rejects_a_negative_size(self) -> None:
        """A negative size is refused."""
        source = 'auto sec_a = std::mem::create_section("a");\nstd::mem::set_section_size(sec_a, -1);'
        assert _failure(source) == "std::mem::set_section_size: size must be non-negative"

    def test_set_section_size_truncates_and_zero_extends(self) -> None:
        """Shrinking drops the tail and growing again appends zeros, never the old bytes."""
        data = bytes([0x10, 0x20, 0x30, 0x40, 0x50, 0x60])
        source = (
            'auto sec_a = std::mem::create_section("a");\n'
            "std::mem::copy_to_section(0, 0, sec_a, 0, 6);\n"
            "std::mem::set_section_size(sec_a, 2);\n"
            "auto shrunk = std::mem::get_section_size(sec_a);\n"
            "std::mem::set_section_size(sec_a, 4);\n"
            "auto grown = std::mem::get_section_size(sec_a);\n"
        )
        evaluator, stdlib = _execute(source, data)
        assert (_bound(evaluator, "shrunk"), _bound(evaluator, "grown")) == (2, 4)
        assert _section_bytes(stdlib, 1) == data[:2] + b"\x00\x00"


class TestStringBuiltins:
    """``std::string`` fallbacks for missing arguments and number parsing."""

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ('std::string::at("abc")', ""),
            ('std::string::substr("abcdef", 1)', ""),
            ('std::string::contains("abc")', False),
            ('std::string::starts_with("abc")', False),
            ('std::string::ends_with("abc")', False),
            ("std::string::to_int()", 0),
            ('std::string::to_int("11", 1)', 0),
            ('std::string::to_int("11", 37)', 0),
        ],
        ids=["at", "substr", "contains", "starts-with", "ends-with", "to-int-no-arguments", "to-int-base-one", "to-int-base-37"],
    )
    def test_missing_arguments_and_bad_bases_use_neutral_results(self, expression: str, expected: object) -> None:
        """Calls without enough arguments, or with an unsupported base, return an empty or zero result.

        Args:
            expression: The pattern-language expression evaluated.
            expected: The neutral value it must produce.
        """
        value = _eval(expression)
        assert value == expected
        assert type(value) is type(expected)

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ('std::string::to_int("11", 2)', 3),
            ('std::string::to_int("0x1F", 0)', 31),
            ('std::string::to_int("z", 36)', 35),
            ('std::string::to_int("10", 36)', 36),
            ('std::string::to_int("12", 2)', 0),
        ],
        ids=["binary", "auto-detect-base", "highest-digit", "base-36", "invalid-digit"],
    )
    def test_to_int_accepts_the_documented_base_range(self, expression: str, expected: int) -> None:
        """Base 0 and every radix from 2 to 36 parse; malformed text yields zero.

        Args:
            expression: The pattern-language expression evaluated.
            expected: The integer ``to_int`` must produce.
        """
        assert _eval(expression) == expected

    def test_parse_float_converts_trimmed_text(self) -> None:
        """Surrounding whitespace is ignored and exponents are understood."""
        assert _eval('std::string::parse_float(" 2.5 ")') == pytest.approx(2.5)
        assert _eval('std::string::parse_float("1e3")') == pytest.approx(1000.0)

    @pytest.mark.parametrize(
        ("expression", "message"),
        [
            ("std::string::parse_float()", "std::string::parse_float requires a string argument"),
            ('std::string::parse_float("abc")', "std::string::parse_float: cannot parse 'abc' as float"),
        ],
        ids=["no-argument", "not-a-number"],
    )
    def test_parse_float_errors(self, expression: str, message: str) -> None:
        """Missing and malformed input are runtime errors.

        Args:
            expression: The failing pattern-language expression.
            message: The expected error message.
        """
        assert _failure(f"auto result = {expression};") == message


class TestMathBuiltins:
    """``std::math`` defaults, values, domain checks and ``accumulate``."""

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("std::math::abs()", 0),
            ("std::math::min()", 0),
            ("std::math::max()", 0),
            ("std::math::min(5)", 5),
            ("std::math::max(5)", 5),
            ("std::math::round()", 0),
            ("std::math::trunc()", 0),
            ("std::math::log()", 0.0),
            ("std::math::log2()", 0.0),
            ("std::math::log10()", 0.0),
            ("std::math::pow(2)", 0.0),
            ("std::math::sqrt()", 0.0),
            ("std::math::cbrt()", 0.0),
            ("std::math::exp()", math.exp(0.0)),
            ("std::math::sin()", math.sin(0.0)),
            ("std::math::cos()", math.cos(0.0)),
            ("std::math::tan()", math.tan(0.0)),
            ("std::math::asin()", math.asin(0.0)),
            ("std::math::acos()", math.acos(0.0)),
            ("std::math::atan()", math.atan(0.0)),
            ("std::math::atan2(1)", 0.0),
            ("std::math::sinh()", math.sinh(0.0)),
            ("std::math::cosh()", math.cosh(0.0)),
            ("std::math::tanh()", math.tanh(0.0)),
            ("std::math::asinh()", math.asinh(0.0)),
            ("std::math::acosh()", 0.0),
            ("std::math::atanh()", math.atanh(0.0)),
        ],
        ids=[
            "abs",
            "min",
            "max",
            "min-one-argument",
            "max-one-argument",
            "round",
            "trunc",
            "log",
            "log2",
            "log10",
            "pow",
            "sqrt",
            "cbrt",
            "exp",
            "sin",
            "cos",
            "tan",
            "asin",
            "acos",
            "atan",
            "atan2",
            "sinh",
            "cosh",
            "tanh",
            "asinh",
            "acosh",
            "atanh",
        ],
    )
    def test_calls_without_arguments_evaluate_at_zero(self, expression: str, expected: float) -> None:
        """A missing argument behaves as zero, or yields zero where the function is undefined at zero.

        Args:
            expression: The pattern-language expression evaluated.
            expected: The value the function takes at zero.
        """
        assert _eval(expression) == expected

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("std::math::round(2.6)", 3),
            ("std::math::round(-2.6)", -3),
            ("std::math::round(2.4)", 2),
            ("std::math::trunc(2.7)", 2),
            ("std::math::trunc(-2.7)", -2),
        ],
        ids=["round-up", "round-negative", "round-down", "trunc-positive", "trunc-negative"],
    )
    def test_round_and_trunc_return_integers(self, expression: str, expected: int) -> None:
        """Rounding goes to the nearest integer and truncation goes toward zero.

        Args:
            expression: The pattern-language expression evaluated.
            expected: The integer result.
        """
        value = _eval(expression)
        assert value == expected
        assert isinstance(value, int)

    @pytest.mark.parametrize(
        ("name", "argument"),
        [
            ("sin", 1.0),
            ("cos", 1.0),
            ("tan", 1.0),
            ("asin", 0.5),
            ("acos", 0.5),
            ("atan", 1.0),
            ("sinh", 1.0),
            ("cosh", 1.0),
            ("tanh", 1.0),
            ("asinh", 1.0),
            ("acosh", 2.0),
            ("atanh", 0.5),
            ("exp", 1.0),
            ("log10", 1000.0),
            ("asin", 1.0),
            ("asin", -1.0),
            ("acos", 1.0),
            ("acos", -1.0),
            ("acosh", 1.0),
        ],
        ids=[
            "sin",
            "cos",
            "tan",
            "asin",
            "acos",
            "atan",
            "sinh",
            "cosh",
            "tanh",
            "asinh",
            "acosh",
            "atanh",
            "exp",
            "log10",
            "asin-upper-bound",
            "asin-lower-bound",
            "acos-upper-bound",
            "acos-lower-bound",
            "acosh-lower-bound",
        ],
    )
    def test_unary_functions_match_the_math_module(self, name: str, argument: float) -> None:
        """Each unary built-in agrees with the same-named ``math`` function, including at domain edges.

        Args:
            name: The ``std::math`` function name, also the ``math`` attribute.
            argument: The value passed to the function.
        """
        expected: float = getattr(math, name)(argument)
        assert _eval(f"std::math::{name}({argument!r})") == expected

    def test_natural_log_and_its_alias_agree(self) -> None:
        """``log`` and ``ln`` both compute the natural logarithm."""
        assert _eval("std::math::log(7.5)") == math.log(7.5)
        assert _eval("std::math::ln(7.5)") == math.log(7.5)

    def test_atan2_orders_its_arguments_y_then_x(self) -> None:
        """The first argument is ``y`` and the second is ``x``."""
        assert _eval("std::math::atan2(1.0, -1.0)") == math.atan2(1.0, -1.0)

    @pytest.mark.parametrize(
        ("argument", "expected"),
        [(27.0, 3.0), (-8.0, -2.0), (0.0, 0.0)],
        ids=["positive", "negative-keeps-sign", "zero"],
    )
    def test_cbrt_preserves_sign(self, argument: float, expected: float) -> None:
        """The real cube root is returned for positive, negative and zero inputs.

        Args:
            argument: The value passed to ``cbrt``.
            expected: The exact real cube root.
        """
        assert _eval(f"std::math::cbrt({argument!r})") == pytest.approx(expected)

    @pytest.mark.parametrize(("x", "y"), [(7.5, 2.0), (-7.5, 2.0)], ids=["positive-dividend", "negative-dividend"])
    def test_fmod_takes_the_sign_of_the_dividend(self, x: float, y: float) -> None:
        """``fmod`` matches ``math.fmod`` for either sign of the dividend.

        Args:
            x: The dividend.
            y: The divisor.
        """
        assert _eval(f"std::math::fmod({x!r}, {y!r})") == math.fmod(x, y)

    @pytest.mark.parametrize(
        ("expression", "message"),
        [
            ("std::math::log(0)", "ln of non-positive value"),
            ("std::math::ln(-1)", "ln of non-positive value"),
            ("std::math::log10(0)", "log10 of non-positive value"),
            ("std::math::log10(-2.5)", "log10 of non-positive value"),
            ("std::math::fmod(1.0)", "fmod requires two arguments"),
            ("std::math::fmod(1.0, 0)", "fmod divisor is zero"),
            ("std::math::asin(1.5)", "asin argument out of domain"),
            ("std::math::asin(-1.5)", "asin argument out of domain"),
            ("std::math::acos(1.5)", "acos argument out of domain"),
            ("std::math::acos(-1.5)", "acos argument out of domain"),
            ("std::math::acosh(0.5)", "acosh argument out of domain"),
            ("std::math::atanh(1.0)", "atanh argument out of domain"),
            ("std::math::atanh(-1.0)", "atanh argument out of domain"),
            ("std::math::atanh(2.0)", "atanh argument out of domain"),
        ],
        ids=[
            "log-zero",
            "ln-negative",
            "log10-zero",
            "log10-negative",
            "fmod-one-argument",
            "fmod-zero-divisor",
            "asin-above",
            "asin-below",
            "acos-above",
            "acos-below",
            "acosh-below-one",
            "atanh-at-one",
            "atanh-at-minus-one",
            "atanh-above",
        ],
    )
    def test_domain_violations_are_runtime_errors(self, expression: str, message: str) -> None:
        """Arguments outside a function's domain raise instead of returning NaN or raising ``ValueError``.

        Args:
            expression: The failing pattern-language expression.
            message: The expected error message.
        """
        assert _failure(f"auto result = {expression};") == message

    @pytest.mark.parametrize(
        ("operation", "label"),
        [(0, "add"), (1, "multiply"), (2, "modulo"), (3, "min"), (4, "max")],
        ids=["add", "multiply", "modulo", "min", "max"],
    )
    def test_accumulate_folds_each_operation(self, operation: int, label: str) -> None:
        """Every ``AccumulateOperation`` tag folds the u16 values left to right.

        Args:
            operation: The operation tag from ``std::math::AccumulateOperation``.
            label: Which fold the tag selects.
        """
        data = struct.pack("<4H", *_ACCUMULATE_VALUES)
        folds: dict[str, int] = {
            "add": sum(_ACCUMULATE_VALUES),
            "multiply": math.prod(_ACCUMULATE_VALUES),
            "modulo": functools.reduce(operator.mod, _ACCUMULATE_VALUES),
            "min": min(_ACCUMULATE_VALUES),
            "max": max(_ACCUMULATE_VALUES),
        }
        assert len(set(folds.values())) == len(folds)
        assert _eval(f"std::math::accumulate(0, 8, 2, 0, {operation}, 2)", data) == folds[label]

    def test_accumulate_defaults_to_addition_and_honors_endianness(self) -> None:
        """Without an operation the values are added, and the endian tag selects the byte order."""
        data = struct.pack("<4H", *_ACCUMULATE_VALUES)
        total = sum(_ACCUMULATE_VALUES)
        assert _eval("std::math::accumulate(0, 8, 2)", data) == total
        assert _eval("std::math::accumulate(0, 8, 2, 0)", data) == total
        assert _eval("std::math::accumulate(0, 8, 2, 0, 0)", data) == total
        big_total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, 8, 2))
        assert big_total != total
        assert _eval("std::math::accumulate(0, 8, 2, 0, 0, 1)", data) == big_total

    def test_accumulate_empty_and_partial_ranges_are_zero(self) -> None:
        """A range holding no complete value folds to zero."""
        data = bytes(range(1, 9))
        assert _eval("std::math::accumulate(4, 4, 2)", data) == 0
        assert _eval("std::math::accumulate(5, 2, 2)", data) == 0
        assert _eval("std::math::accumulate(0, 1, 2)", data) == 0

    def test_accumulate_accepts_sixteen_byte_values(self) -> None:
        """A 16-byte value size is allowed and reads one little-endian u128."""
        data = bytes(range(1, 17))
        assert _eval("std::math::accumulate(0, 16, 16)", data) == int.from_bytes(data, "little")

    @pytest.mark.parametrize(
        ("expression", "data", "message"),
        [
            ("std::math::accumulate(0, 4)", bytes(8), "std::math::accumulate requires offsetFrom, offsetTo and valueSize"),
            ("std::math::accumulate(0, 4, 0)", bytes(8), "std::math::accumulate valueSize must be between 1 and 16"),
            ("std::math::accumulate(0, 17, 17)", bytes(32), "std::math::accumulate valueSize must be between 1 and 16"),
            ("std::math::accumulate(0, 4, 1, 0, 2)", bytes([9, 4, 0, 3]), "std::math::accumulate encountered a zero divisor"),
            ("std::math::accumulate(0, 4, 1, 0, 9)", bytes([1, 2, 3, 4]), "std::math::accumulate unknown operation tag: 9"),
        ],
        ids=["too-few-arguments", "zero-value-size", "oversize-value", "modulo-by-zero", "unknown-operation"],
    )
    def test_accumulate_errors(self, expression: str, data: bytes, message: str) -> None:
        """Bad arguments and a zero divisor are runtime errors.

        Args:
            expression: The failing pattern-language expression.
            data: The bytes the expression reads.
            message: The expected error message.
        """
        assert _failure(f"auto result = {expression};", data) == message


class TestHashBuiltins:
    """``std::hash`` CRC built-ins against catalogue check values and ``zlib``."""

    @pytest.mark.parametrize(
        ("function", "parameters", "expected"),
        [
            ("crc8", "0x00, 0x07, 0x00, 0, 0", 0xF4),
            ("crc16", "0x0000, 0x8005, 0x0000, 1, 1", 0xBB3D),
            ("crc16", "0xFFFF, 0x1021, 0x0000, 0, 0", 0x29B1),
            ("crc32", "0xFFFFFFFF, 0x04C11DB7, 0xFFFFFFFF, 1, 1", zlib.crc32(_CRC_CHECK)),
            ("crc64", "0x0000000000000000, 0x42F0E1EBA9EA3693, 0x0000000000000000, 0, 0", 0x6C40DF5F0B497347),
            ("crc64", "0xFFFFFFFFFFFFFFFF, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, 1, 1", 0x995DC9BBDF1939FA),
        ],
        ids=["crc8-smbus", "crc16-arc", "crc16-ccitt-false", "crc32-iso-hdlc", "crc64-ecma-182", "crc64-xz"],
    )
    def test_crc_matches_the_catalogue_check_value(self, function: str, parameters: str, expected: int) -> None:
        """The CRC of ``123456789`` matches the published check value for each parameter set.

        Args:
            function: The ``std::hash`` function name.
            parameters: Init, polynomial, xor-out and the two reflect flags.
            expected: The catalogue check value for that CRC model.
        """
        source = f"u8 buf[9] @ 0;\nauto result = std::hash::{function}(buf, {parameters});"
        evaluator, _stdlib = _execute(source, _CRC_CHECK)
        assert _bound(evaluator, "result") == expected

    @pytest.mark.parametrize("function", ["crc8", "crc16", "crc32", "crc64"])
    def test_crc_without_six_arguments_is_zero(self, function: str) -> None:
        """Fewer than six arguments yield zero rather than an error.

        Args:
            function: The ``std::hash`` function name.
        """
        assert _eval(f"std::hash::{function}(1, 2)") == 0

    @pytest.mark.parametrize(
        ("pattern", "payload"),
        [
            ('"123456789"', _CRC_CHECK),
            ("0x12345678", bytes.fromhex("12345678")),
            ("0x100", bytes.fromhex("0100")),
            ("0", b"\x00"),
        ],
        ids=["string", "integer", "integer-two-bytes", "zero"],
    )
    def test_crc32_hashes_literal_patterns_as_their_bytes(self, pattern: str, payload: bytes) -> None:
        """A string literal hashes as UTF-8 and an integer as its minimal big-endian bytes.

        Args:
            pattern: The literal passed as the hashed pattern.
            payload: The bytes that literal must be hashed as.
        """
        expression = f"std::hash::crc32({pattern}, 0xFFFFFFFF, 0x04C11DB7, 0xFFFFFFFF, 1, 1)"
        assert _eval(expression) == zlib.crc32(payload)

    def test_crc_of_an_unhashable_literal_is_the_initial_register(self) -> None:
        """A float literal contributes no bytes, so without reflection the CRC is the init value."""
        assert _eval("std::hash::crc32(1.5, 0x12345678, 0x04C11DB7, 0, 0, 0)") == 0x12345678

    def test_crc_accepts_raw_and_boxed_payloads(self) -> None:
        """Raw ``bytes``, raw ``str`` and a boxed ``bytes`` pattern all hash as their bytes."""
        _stdlib, scope = _builtin_table()
        parameters = (0xFFFFFFFF, 0x04C11DB7, 0xFFFFFFFF, 1, 1)
        expected = zlib.crc32(_CRC_CHECK)
        for payload in (_CRC_CHECK, _CRC_CHECK.decode("ascii"), PatternValue(value=_CRC_CHECK)):
            result = _call(scope, "std::hash::crc32", payload, *parameters)
            assert isinstance(result, PatternValue)
            assert result.value == expected


class TestTimeBuiltins:
    """``std::time`` conversion to and from the packed ``std::time::Time`` value."""

    def test_epoch_reports_the_current_time(self) -> None:
        """The epoch is the current whole-second Unix time."""
        before = int(time.time())
        stamp = _eval("std::time::epoch()")
        after = int(time.time())
        assert isinstance(stamp, int)
        assert before <= stamp <= after

    @pytest.mark.parametrize(
        ("epoch", "layout"),
        [
            (0, (0, 0, 0, 1, 1, 1970, 3, 1, 0)),
            (_EPOCH_BILLION, (40, 46, 1, 9, 9, 2001, 6, 252, 0)),
        ],
        ids=["unix-epoch", "billionth-second"],
    )
    def test_to_utc_packs_the_time_layout(self, epoch: int, layout: tuple[int, ...]) -> None:
        """UTC conversion packs sec, min, hour, mday, mon, year, wday, yday and isdst little-endian.

        Args:
            epoch: Seconds since the Unix epoch.
            layout: The calendar fields of that instant, with Monday as weekday zero.
        """
        expected = int.from_bytes(struct.pack(_TIME_LAYOUT, *layout), "little")
        assert _eval(f"std::time::to_utc({epoch})") == expected
        assert _eval(f"std::time::to_utc({epoch})") == _packed_time(time.gmtime(epoch))

    def test_to_local_matches_the_local_calendar(self) -> None:
        """Local conversion packs the same fields ``time.localtime`` reports."""
        expected = _packed_time(time.localtime(_EPOCH_BILLION))
        assert _eval(f"std::time::to_local({_EPOCH_BILLION})") == expected

    @pytest.mark.parametrize("function", ["to_local", "to_utc"])
    def test_conversions_fall_back_to_zero(self, function: str) -> None:
        """No argument, or an epoch the platform cannot represent, gives zero.

        Args:
            function: The ``std::time`` conversion name.
        """
        assert _eval(f"std::time::{function}()") == 0
        assert _eval(f"std::time::{function}({10**30})") == 0

    @pytest.mark.parametrize(
        ("year", "yday", "isdst", "packed_year", "packed_yday", "packed_isdst"),
        [
            (70000, 70000, 5, 0xFFFF, 0xFFFF, 1),
            (-5, -3, -1, 0, 0, 0),
            (1999, 365, 0, 1999, 365, 0),
        ],
        ids=["clamped-high", "clamped-low", "in-range"],
    )
    def test_pack_clamps_year_and_day_of_year(
        self,
        year: int,
        yday: int,
        isdst: int,
        packed_year: int,
        packed_yday: int,
        packed_isdst: int,
    ) -> None:
        """Year and day of year are clamped to 16 bits and the DST flag is a single bit.

        Args:
            year: The broken-down year.
            yday: The broken-down day of year.
            isdst: The broken-down DST flag.
            packed_year: The year the packed value must carry.
            packed_yday: The day of year the packed value must carry.
            packed_isdst: The DST byte the packed value must carry.
        """
        pack: Callable[[time.struct_time], int] = getattr(BuiltinFunctions, "_pack_time_struct")
        tm = time.struct_time((year, 2, 3, 4, 5, 6, 1, yday, isdst))
        expected = int.from_bytes(struct.pack(_TIME_LAYOUT, 6, 5, 4, 3, 2, packed_year, 1, packed_yday, packed_isdst), "little")
        assert pack(tm) == expected

    def test_format_renders_a_packed_time(self) -> None:
        """A packed UTC time formats through ``strftime`` back to its calendar fields."""
        stamp = f"std::time::to_utc({_EPOCH_BILLION})"
        assert _eval(f'std::time::format("%Y-%m-%d %H:%M:%S", {stamp})') == "2001-09-09 01:46:40"
        fmt = "%A %B %j"
        assert _eval(f'std::time::format("{fmt}", {stamp})') == time.strftime(fmt, time.gmtime(_EPOCH_BILLION))

    @pytest.mark.parametrize("expression", ["std::time::format()", 'std::time::format("%Y")'], ids=["no-arguments", "no-time"])
    def test_format_needs_a_format_and_a_time(self, expression: str) -> None:
        """Fewer than two arguments format to an empty string.

        Args:
            expression: The pattern-language expression evaluated.
        """
        _assert_empty_string(_eval(expression))

    def test_format_of_an_impossible_month_is_empty(self) -> None:
        """A packed month outside 1 to 12 cannot be formatted and yields an empty string."""
        packed = int.from_bytes(struct.pack(_TIME_LAYOUT, 0, 0, 0, 1, 13, 2001, 0, 1, 0), "little")
        _assert_empty_string(_eval(f'std::time::format("%Y", 0x{packed:X})'))


class TestFileBuiltins:
    """``std::file`` open, read, write, seek and close against real files."""

    def test_create_write_seek_read_round_trip(self, tmp_path: Path) -> None:
        """A created file is written, repositioned and read back, and the bytes reach the disk.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "created.bin"
        source = (
            f'auto handle = std::file::open("{target.as_posix()}", 3);\n'
            'std::file::write(handle, "0123456789");\n'
            "std::file::seek(handle, 5);\n"
            "auto tail = std::file::read(handle, 3);\n"
            "std::file::close(handle);\n"
        )
        evaluator, _stdlib = _execute(source)
        assert _bound(evaluator, "handle") == 1
        assert _bound(evaluator, "tail") == "567"
        assert target.read_bytes() == b"0123456789"

    def test_write_mode_overwrites_in_place(self, tmp_path: Path) -> None:
        """Write mode keeps the existing bytes and overwrites from the start.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "existing.bin"
        target.write_bytes(b"ABCDEFGH")
        source = f'auto handle = std::file::open("{target.as_posix()}", 2);\nstd::file::write(handle, "xy");\nstd::file::close(handle);\n'
        _execute(source)
        assert target.read_bytes() == b"xyCDEFGH"

    def test_create_mode_truncates_an_existing_file(self, tmp_path: Path) -> None:
        """Create mode empties an existing file before writing.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "existing.bin"
        target.write_bytes(b"old content")
        source = f'auto handle = std::file::open("{target.as_posix()}", 3);\nstd::file::write(handle, "new");\nstd::file::close(handle);\n'
        _execute(source)
        assert target.read_bytes() == b"new"

    def test_read_mode_decodes_utf8_and_stops_at_end_of_file(self, tmp_path: Path) -> None:
        """Invalid UTF-8 becomes the replacement character and reading past the end gives an empty string.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "text.bin"
        target.write_bytes(b"ab\xffcd")
        source = (
            f'auto handle = std::file::open("{target.as_posix()}", 1);\n'
            "auto text = std::file::read(handle, 5);\n"
            "auto rest = std::file::read(handle, 5);\n"
            "std::file::close(handle);\n"
        )
        evaluator, _stdlib = _execute(source)
        assert _bound(evaluator, "text") == b"ab\xffcd".decode("utf-8", errors="replace")
        assert "�" in str(_bound(evaluator, "text"))
        _assert_empty_string(_bound(evaluator, "rest"))

    def test_write_accepts_each_payload_shape(self, tmp_path: Path) -> None:
        """Boxed bytes, raw bytes, boxed text and raw text are written; a boxed integer writes nothing.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "payloads.bin"
        stdlib, scope = _builtin_table()
        try:
            opened = _call(scope, "std::file::open", target.as_posix(), 3)
            _call(scope, "std::file::write", opened, PatternValue(value=b"\x00\xff"))
            _call(scope, "std::file::write", opened, b"raw")
            _call(scope, "std::file::write", opened, PatternValue(value="é"))
            _call(scope, "std::file::write", opened, PatternValue(value=7))
            _call(scope, "std::file::write", opened, "plain")
            _call(scope, "std::file::close", opened)
        finally:
            _release_files(stdlib)
        assert target.read_bytes() == b"\x00\xffraw" + "é".encode() + b"plain"

    def test_calls_missing_arguments_leave_the_handle_usable(self, tmp_path: Path) -> None:
        """Short ``read``, ``write``, ``seek`` and ``close`` calls do nothing and keep the file open.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "short.bin"
        source = (
            f'auto handle = std::file::open("{target.as_posix()}", 3);\n'
            "auto empty = std::file::read(handle);\n"
            "auto wrote = std::file::write(handle);\n"
            "auto moved = std::file::seek(handle);\n"
            "auto closed = std::file::close();\n"
            'std::file::write(handle, "ok");\n'
            "std::file::close(handle);\n"
        )
        evaluator, _stdlib = _execute(source)
        _assert_empty_string(_bound(evaluator, "empty"))
        assert _bound(evaluator, "wrote") is None
        assert _bound(evaluator, "moved") is None
        assert _bound(evaluator, "closed") is None
        assert target.read_bytes() == b"ok"

    def test_closing_an_unknown_handle_is_ignored(self) -> None:
        """Closing a handle that was never opened is not an error."""
        assert _eval("std::file::close(42)") is None

    def test_closed_handle_is_forgotten(self, tmp_path: Path) -> None:
        """After ``close`` the handle is unknown to every other file built-in.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "closed.bin"
        source = f'auto handle = std::file::open("{target.as_posix()}", 3);\nstd::file::close(handle);\nstd::file::read(handle, 1);\n'
        assert _failure(source) == "std::file: unknown handle 1"

    @pytest.mark.parametrize(
        "statement",
        ["std::file::read(99, 1)", 'std::file::write(99, "x")', "std::file::seek(99, 0)"],
        ids=["read", "write", "seek"],
    )
    def test_unknown_handles_are_runtime_errors(self, statement: str) -> None:
        """Reading, writing or seeking an unopened handle is a runtime error.

        Args:
            statement: The failing call.
        """
        assert _failure(f"{statement};") == "std::file: unknown handle 99"

    def test_open_requires_a_path_and_mode(self) -> None:
        """A single argument is not enough to open a file."""
        assert _failure('auto handle = std::file::open("only-path");') == "std::file::open requires (path, mode)"

    def test_open_refuses_relative_paths(self) -> None:
        """Only absolute paths may be opened."""
        message = _failure('auto handle = std::file::open("relative.bin", 1);')
        assert message == "std::file::open requires an absolute path, got 'relative.bin'"

    @pytest.mark.parametrize("mode", [0, 4, 9])
    def test_open_refuses_unknown_modes(self, tmp_path: Path, mode: int) -> None:
        """Only modes 1 (read), 2 (write) and 3 (create) are accepted.

        Args:
            tmp_path: Per-test directory.
            mode: The unsupported mode tag.
        """
        target = tmp_path / "mode.bin"
        message = _failure(f'auto handle = std::file::open("{target.as_posix()}", {mode});')
        assert message == f"std::file::open unknown mode {mode}"

    @pytest.mark.parametrize("mode", [1, 2], ids=["read", "write"])
    def test_open_of_a_missing_file_reports_the_os_failure(self, tmp_path: Path, mode: int) -> None:
        """Read and write modes need an existing file, and the failure names the path.

        Args:
            tmp_path: Per-test directory.
            mode: The file mode tag.
        """
        path_text = (tmp_path / "missing.bin").as_posix()
        message = _failure(f'auto handle = std::file::open("{path_text}", {mode});')
        assert message.startswith(f"std::file::open failed for {path_text!r}: ")

    def test_open_enforces_the_handle_limit(self, tmp_path: Path) -> None:
        """Once the limit of live handles is reached opening fails until one is closed.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "limit.bin"
        target.write_bytes(b"x")
        limit: int = getattr(stdlib_module, "_MAX_OPEN_FILES")
        stdlib, scope = _builtin_table()
        try:
            for _ in range(limit):
                _call(scope, "std::file::open", target.as_posix(), 1)
            with pytest.raises(HexPatRuntimeError) as excinfo:
                _call(scope, "std::file::open", target.as_posix(), 1)
            assert excinfo.value.message == "std::file::open exceeded maximum open-handle limit"
            _call(scope, "std::file::close", 1)
            reopened = _call(scope, "std::file::open", target.as_posix(), 1)
            assert isinstance(reopened, PatternValue)
            assert reopened.value == limit + 1
        finally:
            _release_files(stdlib)

    def test_write_to_a_read_only_handle_fails(self, tmp_path: Path) -> None:
        """Writing through a handle opened for reading is a runtime error.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "readonly.bin"
        target.write_bytes(b"data")
        source = f'auto handle = std::file::open("{target.as_posix()}", 1);\nstd::file::write(handle, "x");\n'
        assert _failure(source).startswith("std::file::write failed")
        assert target.read_bytes() == b"data"

    def test_seek_to_a_negative_offset_fails(self, tmp_path: Path) -> None:
        """A negative absolute offset is refused by the operating system and reported.

        Args:
            tmp_path: Per-test directory.
        """
        target = tmp_path / "seek.bin"
        target.write_bytes(b"data")
        source = f'auto handle = std::file::open("{target.as_posix()}", 1);\nstd::file::seek(handle, -1);\n'
        assert _failure(source).startswith("std::file::seek failed")

    def test_read_from_a_write_only_handle_fails(self, tmp_path: Path) -> None:
        """A handle that cannot be read raises a runtime error instead of returning text.

        Args:
            tmp_path: Per-test directory.
        """
        stdlib, scope = _builtin_table()
        handles: dict[int, BinaryIO] = getattr(stdlib, "_file_handles")
        with (tmp_path / "write_only.bin").open("wb") as writer:
            handles[7] = writer
            try:
                with pytest.raises(HexPatRuntimeError) as excinfo:
                    _call(scope, "std::file::read", 7, 1)
            finally:
                handles.clear()
        assert excinfo.value.message.startswith("std::file::read failed")
