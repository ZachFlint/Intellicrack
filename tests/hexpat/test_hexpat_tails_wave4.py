# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave 4 HexPat engine tail coverage gates.

Tests error-class span/data_span exact values, function-like macro expansion,
eval-depth and pattern-limit limit errors, and CRC stdlib against binascii
and documented CRC catalog check vectors.
"""

from __future__ import annotations

import binascii

import pytest

import intellicrack.core.hexpat.stdlib as _hexpat_stdlib
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatParseError, HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import PatternValue
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions


_REFLECT: bool = True
_NO_REFLECT: bool = False
_CRC32_ISO_INIT: int = 0xFFFFFFFF
_CRC32_ISO_POLY: int = 0x04C11DB7
_CRC32_ISO_XOROUT: int = 0xFFFFFFFF


class TestHexPatParseErrorSpan:
    """Verify exact span tuple and message content on HexPatParseError."""

    def test_span_returns_exact_tuple_when_all_positions_known(self) -> None:
        """Span returns (line, column, end_line, end_column) when all four positions are provided."""
        err = HexPatParseError("bad token", line=3, column=7, end_line=3, end_column=15)
        assert err.span == (3, 7, 3, 15)

    def test_span_is_none_when_end_positions_absent(self) -> None:
        """Span is None when end_line and end_column are not supplied."""
        err = HexPatParseError("bad token", line=3, column=7)
        assert err.span is None

    def test_span_is_none_when_start_line_is_zero(self) -> None:
        """Span is None when line equals zero even if end positions are provided."""
        err = HexPatParseError("bad token", line=0, column=0, end_line=1, end_column=5)
        assert err.span is None

    def test_span_message_includes_location_annotation(self) -> None:
        """str(err) contains the exact [span L:C-L:C] annotation when span is set."""
        err = HexPatParseError("unexpected token", line=2, column=4, end_line=2, end_column=10)
        assert "[span 2:4-2:10]" in str(err)

    def test_start_and_end_attributes_are_individually_correct(self) -> None:
        """Each position attribute is stored independently and correctly."""
        err = HexPatParseError("err", line=5, column=1, end_line=7, end_column=8)
        assert err.line == 5
        assert err.column == 1
        assert err.end_line == 7
        assert err.end_column == 8

    def test_span_with_multiline_range(self) -> None:
        """Span captures a multiline error range as (start_line, start_col, end_line, end_col)."""
        err = HexPatParseError("unclosed block", line=10, column=3, end_line=15, end_column=1)
        assert err.span == (10, 3, 15, 1)

    def test_span_is_none_when_only_end_line_supplied(self) -> None:
        """Span is None when end_column is missing even if end_line is present."""
        err = HexPatParseError("err", line=1, column=1, end_line=2)
        assert err.span is None


class TestHexPatRuntimeErrorDataSpan:
    """Verify exact data_span tuple and message content on HexPatRuntimeError."""

    def test_data_span_returns_exact_pair_when_conditions_met(self) -> None:
        """data_span returns (offset, end_offset) when offset > 0 and end_offset > offset."""
        err = HexPatRuntimeError("oob", offset=0x10, end_offset=0x20)
        assert err.data_span == (0x10, 0x20)

    def test_data_span_is_none_when_offset_is_zero(self) -> None:
        """data_span is None when offset equals zero."""
        err = HexPatRuntimeError("oob", offset=0, end_offset=0x10)
        assert err.data_span is None

    def test_data_span_is_none_when_end_offset_not_strictly_greater(self) -> None:
        """data_span is None when end_offset equals offset rather than exceeding it."""
        err = HexPatRuntimeError("oob", offset=0x10, end_offset=0x10)
        assert err.data_span is None

    def test_data_span_is_none_when_end_offset_absent(self) -> None:
        """data_span is None when end_offset is not supplied at construction."""
        err = HexPatRuntimeError("oob", offset=0x10)
        assert err.data_span is None

    def test_data_span_message_includes_hex_range_annotation(self) -> None:
        """str(err) contains both hex offset values in the annotation when data_span is set."""
        err = HexPatRuntimeError("truncated read", offset=0x100, end_offset=0x108)
        msg_str = str(err)
        assert "0x100" in msg_str
        assert "0x108" in msg_str

    def test_offset_and_end_offset_attributes_accessible(self) -> None:
        """Offset and end_offset are stored as distinct instance attributes."""
        err = HexPatRuntimeError("err", offset=42, end_offset=50)
        assert err.offset == 42
        assert err.end_offset == 50

    def test_data_span_minimum_valid_range(self) -> None:
        """data_span returns (1, 2) for the smallest valid range (offset=1, end_offset=2)."""
        err = HexPatRuntimeError("min range", offset=1, end_offset=2)
        assert err.data_span == (1, 2)

    def test_data_span_is_none_when_end_offset_less_than_offset(self) -> None:
        """data_span is None when end_offset is less than offset."""
        err = HexPatRuntimeError("inverted", offset=0x20, end_offset=0x10)
        assert err.data_span is None


class TestFunctionLikeMacroExpansion:
    """Verify exact function-like #define macro expansion in the preprocessor."""

    def test_two_param_macro_exact_expansion(self) -> None:
        """ADD(a,b) expands to ((a) + (b)) substituting the exact argument text."""
        pp = HexPatPreprocessor()
        source = "#define ADD(a, b) ((a) + (b))\nu32 x = ADD(3, 4);"
        out, _ = pp.process(source)
        assert "((3) + (4))" in out
        assert "ADD" not in out

    def test_single_param_macro_exact_expansion(self) -> None:
        """SQR(x) expands to ((x) * (x)) with the argument substituted exactly."""
        pp = HexPatPreprocessor()
        source = "#define SQR(x) ((x) * (x))\nu32 y = SQR(5);"
        out, _ = pp.process(source)
        assert "((5) * (5))" in out

    def test_macro_name_in_string_literal_is_not_expanded(self) -> None:
        """Macro name inside a double-quoted string literal is preserved verbatim."""
        pp = HexPatPreprocessor()
        source = '#define FOO(x) bar\nstr s = "FOO(hello)";'
        out, _ = pp.process(source)
        assert '"FOO(hello)"' in out

    def test_three_param_macro_substitutes_all_args_in_position(self) -> None:
        """Three-parameter macro places each argument in its declared position exactly."""
        pp = HexPatPreprocessor()
        source = "#define TRIPLE(a, b, c) (a + b + c)\nu32 r = TRIPLE(1, 2, 3);"
        out, _ = pp.process(source)
        assert "(1 + 2 + 3)" in out

    def test_macro_with_expression_argument_preserved_literally(self) -> None:
        """Macro argument containing arithmetic is substituted as literal text."""
        pp = HexPatPreprocessor()
        source = "#define ID(x) x\nu32 v = ID(2 + 3);"
        out, _ = pp.process(source)
        assert "2 + 3" in out

    def test_macro_redefinition_uses_latest_body(self) -> None:
        """Redefining a function-like macro replaces the previous expansion body."""
        pp = HexPatPreprocessor()
        source = "#define X(a) a * 2\n#define X(a) a * 10\nu32 v = X(5);"
        out, _ = pp.process(source)
        assert "5 * 10" in out

    def test_macro_define_line_is_removed_from_output(self) -> None:
        """The #define line itself does not appear in the preprocessed output."""
        pp = HexPatPreprocessor()
        source = "#define WRAP(x) (x)\nu32 q = WRAP(7);"
        out, _ = pp.process(source)
        assert "#define" not in out


class TestEvalDepthLimit:
    """Verify that exceeding eval_depth raises HexPatRuntimeError with the exact message."""

    def test_eval_depth_one_exceeded_by_two_level_nesting(self) -> None:
        """eval_depth 1 is exceeded when Outer contains Inner, raising exact depth message."""
        interp = HexPatInterpreter()
        data = bytes(32)
        source = "#pragma eval_depth 1\nstruct Inner { u8 x; };\nstruct Outer { Inner i; };\nOuter o @ 0;"
        with pytest.raises(HexPatRuntimeError, match="maximum evaluation depth 1 exceeded"):
            interp.execute_bytes(source, data)

    def test_eval_depth_three_permits_two_level_nesting(self) -> None:
        """eval_depth 3 does not raise for 2-level nesting; result contains the outer field."""
        interp = HexPatInterpreter()
        data = bytes(32)
        source = "#pragma eval_depth 3\nstruct Inner { u8 x; };\nstruct Outer { Inner i; };\nOuter o @ 0;"
        results = interp.execute_bytes(source, data)
        assert len(results) == 1
        assert results[0]["name"] == "o"

    def test_eval_depth_two_exceeded_by_four_level_nesting(self) -> None:
        """eval_depth 2 is exceeded by D->C->B->A (third entry triggers depth 3 > 2)."""
        interp = HexPatInterpreter()
        data = bytes(32)
        source = "#pragma eval_depth 2\nstruct A { u8 v; };\nstruct B { A a; };\nstruct C { B b; };\nstruct D { C c; };\nD d @ 0;"
        with pytest.raises(HexPatRuntimeError, match="maximum evaluation depth 2 exceeded"):
            interp.execute_bytes(source, data)


class TestPatternLimitError:
    """Verify that exceeding pattern_limit raises HexPatRuntimeError with the exact message."""

    def test_pattern_limit_one_exceeded_by_second_placement(self) -> None:
        """pattern_limit 1 is exceeded on the second placement; exact error message is raised."""
        interp = HexPatInterpreter()
        data = bytes(16)
        source = "#pragma pattern_limit 1\nu8 a @ 0;\nu8 b @ 1;"
        with pytest.raises(HexPatRuntimeError, match="pattern limit 1 exceeded"):
            interp.execute_bytes(source, data)

    def test_pattern_limit_two_permits_exactly_two_placements(self) -> None:
        """pattern_limit 2 allows two placements with exact display values 0xAA and 0xBB."""
        interp = HexPatInterpreter()
        data = bytes([0xAA, 0xBB] + [0] * 14)
        source = "#pragma pattern_limit 2\nu8 a @ 0;\nu8 b @ 1;"
        results = interp.execute_bytes(source, data)
        assert len(results) == 2
        assert results[0]["display_value"] == "0xAA"
        assert results[1]["display_value"] == "0xBB"

    def test_pattern_limit_three_exceeded_by_fourth_placement(self) -> None:
        """pattern_limit 3 is exceeded by the fourth placement with exact error message."""
        interp = HexPatInterpreter()
        data = bytes(16)
        source = "#pragma pattern_limit 3\nu8 a @ 0;\nu8 b @ 1;\nu8 c @ 2;\nu8 d @ 3;"
        with pytest.raises(HexPatRuntimeError, match="pattern limit 3 exceeded"):
            interp.execute_bytes(source, data)


class TestReflectBits:
    """Verify _reflect_bits against hand-computed known values via getattr access."""

    def test_reflect_0xa0_width8_gives_0x05(self) -> None:
        """_reflect_bits(0xA0, 8) == 0x05 because 10100000 reversed is 00000101."""
        fn = getattr(_hexpat_stdlib, "_reflect_bits")
        assert fn(0xA0, 8) == 0x05

    def test_reflect_0x01_width8_gives_0x80(self) -> None:
        """_reflect_bits(0x01, 8) == 0x80 because LSB becomes MSB."""
        fn = getattr(_hexpat_stdlib, "_reflect_bits")
        assert fn(0x01, 8) == 0x80

    def test_reflect_0xff_width8_unchanged(self) -> None:
        """_reflect_bits(0xFF, 8) == 0xFF because all-ones is symmetric."""
        fn = getattr(_hexpat_stdlib, "_reflect_bits")
        assert fn(0xFF, 8) == 0xFF

    def test_reflect_single_bit_identity(self) -> None:
        """_reflect_bits(1, 1) == 1 because a single bit is its own reverse."""
        fn = getattr(_hexpat_stdlib, "_reflect_bits")
        assert fn(1, 1) == 1

    def test_reflect_0x00_width8_unchanged(self) -> None:
        """_reflect_bits(0x00, 8) == 0x00 because all-zeros is symmetric."""
        fn = getattr(_hexpat_stdlib, "_reflect_bits")
        assert fn(0x00, 8) == 0x00


class TestCRCCompute:
    """Verify _crc_compute against binascii.crc32 and documented CRC catalog check vectors."""

    def test_crc32_iso_hdlc_known_check_vector(self) -> None:
        """CRC-32/ISO-HDLC of b'123456789' equals the well-known check value 0xCBF43926."""
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"123456789",
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert result == 0xCBF43926

    def test_crc32_iso_hdlc_matches_binascii_crc32_arbitrary_bytes(self) -> None:
        """_crc_compute with ISO-HDLC parameters matches binascii.crc32 for arbitrary data."""
        data = b"\xde\xad\xbe\xef\x00\x01\x02\x03"
        expected = binascii.crc32(data) & 0xFFFFFFFF
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            data,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert result == expected

    def test_crc32_iso_hdlc_empty_bytes_matches_binascii(self) -> None:
        """CRC-32/ISO-HDLC of b'' matches binascii.crc32(b'')."""
        expected = binascii.crc32(b"") & 0xFFFFFFFF
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"",
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert result == expected

    def test_crc32_iso_hdlc_single_byte_matches_binascii(self) -> None:
        """CRC-32/ISO-HDLC of a single byte matches binascii.crc32 for that byte."""
        data = b"\xff"
        expected = binascii.crc32(data) & 0xFFFFFFFF
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            data,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert result == expected

    def test_crc32_iso_hdlc_longer_string_matches_binascii(self) -> None:
        """CRC-32/ISO-HDLC of a longer string matches binascii.crc32."""
        data = b"Hello, World!"
        expected = binascii.crc32(data) & 0xFFFFFFFF
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            data,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert result == expected

    def test_crc32_mpeg2_no_reflect_known_check_vector(self) -> None:
        """CRC-32/MPEG-2 (no reflection) of b'123456789' equals documented check 0x0376E6E7."""
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"123456789",
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            0x00000000,
            reflect_in=_NO_REFLECT,
            reflect_out=_NO_REFLECT,
            width_bits=32,
        )
        assert result == 0x0376E6E7

    def test_crc8_smbus_known_check_vector(self) -> None:
        """CRC-8/SMBUS of b'123456789' equals documented check value 0xF4."""
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"123456789",
            0x00,
            0x07,
            0x00,
            reflect_in=_NO_REFLECT,
            reflect_out=_NO_REFLECT,
            width_bits=8,
        )
        assert result == 0xF4

    def test_crc16_arc_known_check_vector(self) -> None:
        """CRC-16/ARC of b'123456789' equals documented check value 0xBB3D."""
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"123456789",
            0x0000,
            0x8005,
            0x0000,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=16,
        )
        assert result == 0xBB3D

    def test_crc32_result_is_masked_to_32_bits(self) -> None:
        """CRC-32 result is always masked to 32 bits (never exceeds 0xFFFFFFFF)."""
        fn = getattr(_hexpat_stdlib, "_crc_compute")
        result = fn(
            b"\xff" * 64,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert 0 <= result <= 0xFFFFFFFF


class TestCRCBuiltinMethods:
    """Verify BuiltinFunctions CRC hash methods route through _crc_compute correctly."""

    def test_hash_crc32_method_bytes_payload(self) -> None:
        """_hash_crc32 with a bytes-value PatternValue matches _crc_compute for the same data."""
        payload = b"\x01\x02\x03\x04"
        stdlib = BuiltinFunctions(DataReader.from_bytes(b"\x00" * 8))
        pv = PatternValue(value=payload, offset=0, size=0)
        result = getattr(stdlib, "_hash_crc32")(
            pv,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            _REFLECT,
            _REFLECT,
        )
        crc_fn = getattr(_hexpat_stdlib, "_crc_compute")
        expected = crc_fn(
            payload,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert isinstance(result.value, int)
        assert result.value == expected

    def test_hash_crc8_method_bytes_payload(self) -> None:
        """_hash_crc8 with a bytes-value PatternValue matches _crc_compute for the same data."""
        payload = b"hello"
        stdlib = BuiltinFunctions(DataReader.from_bytes(b"\x00" * 8))
        pv = PatternValue(value=payload, offset=0, size=0)
        result = getattr(stdlib, "_hash_crc8")(
            pv,
            0x00,
            0x07,
            0x00,
            _NO_REFLECT,
            _NO_REFLECT,
        )
        crc_fn = getattr(_hexpat_stdlib, "_crc_compute")
        expected = crc_fn(
            payload,
            0x00,
            0x07,
            0x00,
            reflect_in=_NO_REFLECT,
            reflect_out=_NO_REFLECT,
            width_bits=8,
        )
        assert isinstance(result.value, int)
        assert result.value == expected

    def test_hash_crc16_method_bytes_payload(self) -> None:
        """_hash_crc16 with a bytes-value PatternValue matches _crc_compute for the same data."""
        payload = b"\xab\xcd\xef"
        stdlib = BuiltinFunctions(DataReader.from_bytes(b"\x00" * 8))
        pv = PatternValue(value=payload, offset=0, size=0)
        result = getattr(stdlib, "_hash_crc16")(
            pv,
            0x0000,
            0x8005,
            0x0000,
            _REFLECT,
            _REFLECT,
        )
        crc_fn = getattr(_hexpat_stdlib, "_crc_compute")
        expected = crc_fn(
            payload,
            0x0000,
            0x8005,
            0x0000,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=16,
        )
        assert isinstance(result.value, int)
        assert result.value == expected

    def test_hash_crc32_reads_from_data_reader_when_size_positive(self) -> None:
        """_hash_crc32 reads from the DataReader when PatternValue.size > 0."""
        payload = b"\x01\x02\x03\x04"
        stdlib = BuiltinFunctions(DataReader.from_bytes(payload + b"\x00" * 4))
        pv = PatternValue(value=0, offset=0, size=4)
        result = getattr(stdlib, "_hash_crc32")(
            pv,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            _REFLECT,
            _REFLECT,
        )
        crc_fn = getattr(_hexpat_stdlib, "_crc_compute")
        expected = crc_fn(
            payload,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            reflect_in=_REFLECT,
            reflect_out=_REFLECT,
            width_bits=32,
        )
        assert isinstance(result.value, int)
        assert result.value == expected

    def test_hash_crc32_returns_zero_pattern_value_when_too_few_args(self) -> None:
        """_hash_crc32 returns PatternValue(value=0) when fewer than 6 arguments are passed."""
        stdlib = BuiltinFunctions(DataReader.from_bytes(b"\x00"))
        result = getattr(stdlib, "_hash_crc32")(PatternValue(value=b"data"), 0)
        assert result.value == 0
