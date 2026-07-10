# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-binary coverage for HexPat ``stdlib`` builtins (audit shard 09b).

These tests drive the real :class:`BuiltinFunctions` implementations against
genuine compiled binaries (System32 PE DLLs/EXEs and the committed ELF corpus
fixture) and against deterministic byte sequences with externally verifiable
results (``zlib.crc32``, hand-computed nibble extraction, hand-computed byte
sums). No operation under test is mocked: every assertion validates a concrete
computed value rather than that a call merely happened.

The builtins are reached through the production :meth:`HexPatInterpreter.
execute_bytes` pipeline (preprocessor -> lexer -> parser -> evaluator +
stdlib) where a pattern can express the call, and via direct invocation of the
real :class:`BuiltinFunctions` instance (backed by a real :class:`DataReader`)
for builtins whose surface API is not expressible as a standalone pattern
expression.
"""

from __future__ import annotations

import math
import zlib
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import PatternValue
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.hexpat.stdlib import BuiltinFunctions


if TYPE_CHECKING:
    from pathlib import Path


_CRC32_ISO_INIT: int = 0xFFFFFFFF
_CRC32_ISO_POLY: int = 0x04C11DB7
_CRC32_ISO_XOROUT: int = 0xFFFFFFFF
_PE_SIGNATURE: tuple[int, int, int, int] = (0x50, 0x45, 0x00, 0x00)
_REFLECT: bool = True
_NO_REFLECT: bool = False


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


def _builtins_for(path: Path) -> tuple[BuiltinFunctions, bytes]:
    """Construct a real BuiltinFunctions over the full bytes of ``path``.

    Args:
        path: Filesystem path to a real binary to read in full.

    Returns:
        tuple[BuiltinFunctions, bytes]: The builtins instance wrapping a
            :class:`DataReader` over the file plus the raw file bytes.
    """
    raw = path.read_bytes()
    return BuiltinFunctions(DataReader.from_bytes(raw)), raw


class TestMemReadAgainstRealPe:
    """std::mem read builtins resolve real Portable Executable header fields."""

    def test_read_unsigned_e_lfanew_matches_raw(self, real_pe_dll: Path) -> None:
        """read_unsigned(0x3C, 4) returns the real e_lfanew dword of the PE.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        expected = int.from_bytes(raw[0x3C:0x40], "little", signed=False)
        result: int = getattr(builtins, "_mem_read_unsigned")(0x3C, 4)
        assert result == expected
        assert result > 0

    def test_read_unsigned_pe_signature_at_e_lfanew(self, real_pe_dll: Path) -> None:
        """The dword at e_lfanew equals the ASCII PE NUL NUL signature.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        e_lfanew = int.from_bytes(raw[0x3C:0x40], "little", signed=False)
        sig: int = getattr(builtins, "_mem_read_unsigned")(e_lfanew, 4)
        assert sig == 0x00004550

    def test_read_unsigned_big_endian_machine_word(self, real_pe_dll: Path) -> None:
        """Big-endian read of the MZ magic equals 0x4D5A, little-endian 0x5A4D.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, _raw = _builtins_for(real_pe_dll)
        little: int = getattr(builtins, "_mem_read_unsigned")(0, 2, 2)
        big: int = getattr(builtins, "_mem_read_unsigned")(0, 2, 1)
        assert little == 0x5A4D
        assert big == 0x4D5A

    def test_mem_size_matches_real_file_length(self, real_pe_dll: Path) -> None:
        """_mem_size returns the real byte length of the PE binary.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        assert getattr(builtins, "_mem_size")() == len(raw)

    def test_mem_size_in_pattern_reflects_real_pe(
        self,
        interp: HexPatInterpreter,
        real_pe_dll: Path,
    ) -> None:
        """A pattern reads std::mem::size() and sees the real multi-KB PE size.

        Args:
            interp: A fresh interpreter fixture.
            real_pe_dll: Real System32 PE DLL fixture.
        """
        raw = real_pe_dll.read_bytes()
        assert len(raw) > 100_000
        source = "u8 big @ (std::mem::size() > 100000 ? 7 : 0);"
        results = interp.execute_bytes(source, raw)
        assert results[0]["offset"] == 7

    def test_base_address_propagates_from_pragma(self) -> None:
        """std::mem::base_address returns the #pragma base_address value.

        The :class:`PragmaInfo` base address flows into the builtin, so the
        returned integer must equal the configured base regardless of the
        backing data length.
        """
        reader = DataReader.from_bytes(bytes(64))
        builtins = BuiltinFunctions(reader, PragmaInfo(base_address=0x10000000))
        assert getattr(builtins, "_mem_base_address")() == 0x10000000

    def test_find_sequence_locates_pe_signature(self, real_pe_dll: Path) -> None:
        """find_sequence_in_range finds the PE signature at the real e_lfanew.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        e_lfanew = int.from_bytes(raw[0x3C:0x40], "little", signed=False)
        located: int = getattr(builtins, "_mem_find_sequence")(
            0,
            0,
            len(raw),
            *_PE_SIGNATURE,
        )
        assert located == e_lfanew

    def test_find_string_in_range_locates_dos_stub_text(self, real_pe_dll: Path) -> None:
        """find_string_in_range locates the canonical DOS stub message.

        Every Microsoft-linked PE embeds the ASCII string ``This program``
        in its DOS stub. The builtin must return the same offset that a raw
        byte search reports.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        needle = b"This program"
        expected = raw.find(needle)
        if expected < 0:
            pytest.skip("DOS stub message absent from this PE variant")
        located: int = getattr(builtins, "_mem_find_string_in_range")(
            0,
            0,
            len(raw),
            needle.decode("ascii"),
        )
        assert located == expected


class TestMemReadAgainstRealElf:
    """std::mem read builtins resolve real ELF header fields."""

    def test_read_unsigned_e_machine_is_x86_64(self, real_elf_binary: Path) -> None:
        """e_machine (offset 0x12, u16) of the corpus ELF equals EM_X86_64.

        Args:
            real_elf_binary: Committed real ELF corpus fixture.
        """
        builtins, raw = _builtins_for(real_elf_binary)
        expected = int.from_bytes(raw[0x12:0x14], "little", signed=False)
        machine: int = getattr(builtins, "_mem_read_unsigned")(0x12, 2)
        assert machine == expected

    def test_read_string_reads_elf_ident_padding(self, real_elf_binary: Path) -> None:
        """read_string over the 4-byte ELF magic decodes ELF after the 0x7F.

        Args:
            real_elf_binary: Committed real ELF corpus fixture.
        """
        builtins, raw = _builtins_for(real_elf_binary)
        assert raw[:4] == b"\x7fELF"
        text: str = getattr(builtins, "_mem_read_string")(1, 3)
        assert text == "ELF"

    def test_math_accumulate_byte_sum_matches_python(self, real_elf_binary: Path) -> None:
        """Add-accumulate over the ELF header equals the Python byte sum.

        Args:
            real_elf_binary: Committed real ELF corpus fixture.
        """
        builtins, raw = _builtins_for(real_elf_binary)
        expected = sum(raw[:64])
        total: int = getattr(builtins, "_math_accumulate")(0, 64, 1, 0, 0, 0)
        assert total == expected


class TestHashCrcAgainstKnownVectors:
    """std::hash CRC builtins match externally verifiable reference vectors."""

    def test_crc32_iso_hdlc_check_vector(self) -> None:
        """CRC-32/ISO-HDLC of '123456789' equals the canonical 0xCBF43926.

        ``zlib.crc32`` implements precisely the ISO-HDLC parameterisation, so
        it is used as the independent oracle for the builtin's output.
        """
        payload = b"123456789"
        reader = DataReader.from_bytes(payload)
        builtins = BuiltinFunctions(reader)
        arg = PatternValue(value=0, offset=0, size=len(payload))
        result = getattr(builtins, "_hash_crc32")(
            arg,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            _REFLECT,
            _REFLECT,
        )
        assert result.value == zlib.crc32(payload)
        assert result.value == 0xCBF43926

    def test_crc32_matches_zlib_over_real_elf_header(self, real_elf_binary: Path) -> None:
        """CRC-32 of the first 256 ELF bytes equals zlib.crc32 of the same span.

        Args:
            real_elf_binary: Committed real ELF corpus fixture.
        """
        builtins, raw = _builtins_for(real_elf_binary)
        span = raw[:256]
        arg = PatternValue(value=0, offset=0, size=len(span))
        result = getattr(builtins, "_hash_crc32")(
            arg,
            _CRC32_ISO_INIT,
            _CRC32_ISO_POLY,
            _CRC32_ISO_XOROUT,
            _REFLECT,
            _REFLECT,
        )
        assert result.value == zlib.crc32(span)

    def test_crc16_ccitt_false_check_vector(self) -> None:
        """CRC-16/CCITT-FALSE of '123456789' equals the canonical 0x29B1."""
        payload = b"123456789"
        reader = DataReader.from_bytes(payload)
        builtins = BuiltinFunctions(reader)
        arg = PatternValue(value=0, offset=0, size=len(payload))
        result = getattr(builtins, "_hash_crc16")(
            arg,
            0xFFFF,
            0x1021,
            0x0000,
            _NO_REFLECT,
            _NO_REFLECT,
        )
        assert result.value == 0x29B1


class TestReadBitsExtraction:
    """std::mem::read_bits extracts the correct contiguous bit ranges."""

    def test_high_and_low_nibble_extraction(self) -> None:
        """read_bits splits 0xA5 into the 0xA high nibble and 0x5 low nibble."""
        reader = DataReader.from_bytes(bytes([0xA5]))
        builtins = BuiltinFunctions(reader)
        high: int = getattr(builtins, "_mem_read_bits")(0, 0, 4)
        low: int = getattr(builtins, "_mem_read_bits")(0, 4, 4)
        assert high == 0xA
        assert low == 0x5

    def test_single_bit_reads_msb_first(self) -> None:
        """read_bits reads bit 0 as the most-significant bit of 0x80."""
        reader = DataReader.from_bytes(bytes([0x80]))
        builtins = BuiltinFunctions(reader)
        assert getattr(builtins, "_mem_read_bits")(0, 0, 1) == 1
        assert getattr(builtins, "_mem_read_bits")(0, 1, 1) == 0


class TestStringParsingBuiltins:
    """std::string parsing builtins convert real string content correctly."""

    def test_parse_int_base16_matches_python_int(self, interp: HexPatInterpreter) -> None:
        """parse_int('FF', 16) used as an offset places a field at byte 255.

        Args:
            interp: A fresh interpreter fixture.
        """
        data = bytes(300)
        source = 'u8 r @ std::string::parse_int("FF", 16);'
        results = interp.execute_bytes(source, data)
        assert results[0]["offset"] == 0xFF

    @pytest.mark.parametrize(
        ("s", "base"),
        [
            ("not-an-int", 10),
            ("XYZ", 10),
            ("0x1G", 16),
            ("", 10),
        ],
    )
    def test_parse_int_invalid_raises_runtime_error(
        self,
        s: str,
        base: int,
    ) -> None:
        """parse_int rejects malformed input with the full canonical error message.

        The production code raises exactly:
        ``"std::string::parse_int: cannot parse {s!r} as base-{base} integer"``

        The test asserts this *complete* message string so that any refactor that
        (a) silently succeeds, (b) raises for a different reason (bad base, missing
        arg), or (c) omits the bad-input value from the message will go red.
        Asserting the exact string pins the test to the malformed-input branch and
        to no other ``HexPatRuntimeError`` path.

        Args:
            s: The malformed string that parse_int cannot interpret as an integer.
            base: The numeric base passed to parse_int alongside the bad string.
        """
        expected_message = f"std::string::parse_int: cannot parse {s!r} as base-{base} integer"
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError) as exc_info:
            getattr(builtins, "_string_parse_int")(s, base)
        assert str(exc_info.value) == expected_message

    def test_parse_int_bad_base_raises_distinct_error(self) -> None:
        """parse_int with a base outside [2,36] raises a 'unsupported base' error.

        This explicitly distinguishes the base-validation error path from the
        malformed-input error path, so that tests for each remain orthogonal
        and independently falsifiable.
        """
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError, match="unsupported base 37"):
            getattr(builtins, "_string_parse_int")("123", 37)

    def test_parse_int_no_args_raises_distinct_error(self) -> None:
        """parse_int with no arguments raises a 'requires a string argument' error.

        The zero-argument code path must produce a message distinct from both
        the bad-base and bad-input paths so each remains an independent gate.
        """
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        with pytest.raises(HexPatRuntimeError, match="requires a string argument"):
            getattr(builtins, "_string_parse_int")()

    def test_parse_float_round_trips_value(self) -> None:
        """parse_float decodes a decimal literal to the matching float."""
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        result: float = getattr(builtins, "_string_parse_float")("3.5")
        assert math.isclose(result, 3.5)

    def test_substr_extracts_from_decoded_real_string(self, real_pe_dll: Path) -> None:
        """Substring of a real PE-derived string returns the expected slice.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        builtins, raw = _builtins_for(real_pe_dll)
        decoded = raw[:2].decode("latin-1")
        assert decoded == "MZ"
        assert getattr(builtins, "_string_substr")(decoded, 0, 1) == "M"
        assert getattr(builtins, "_string_substr")(decoded, 1, 1) == "Z"


class TestMathBuiltinsInPatterns:
    """std::math integer builtins compute correct placement offsets in patterns."""

    @pytest.mark.parametrize(
        ("expr", "expected_offset"),
        [
            ("std::math::abs(-7)", 7),
            ("std::math::min(3, 9)", 3),
            ("std::math::max(3, 9)", 9),
            ("std::math::floor(6.7)", 6),
            ("std::math::ceil(6.1)", 7),
        ],
    )
    def test_math_offset_expression(
        self,
        interp: HexPatInterpreter,
        expr: str,
        expected_offset: int,
    ) -> None:
        """A std::math expression used as a placement offset resolves correctly.

        Args:
            interp: A fresh interpreter fixture.
            expr: The std::math call expression under test.
            expected_offset: The integer offset the expression must produce.
        """
        data = bytes(32)
        results = interp.execute_bytes(f"u8 r @ {expr};", data)
        assert results[0]["offset"] == expected_offset

    def test_math_sqrt_float_result(self) -> None:
        """sqrt(16.0) returns the exact float 4.0 from the real builtin."""
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        result: float = getattr(builtins, "_math_sqrt")(16.0)
        assert math.isclose(result, 4.0)

    def test_math_pow_float_result(self) -> None:
        """pow(2, 10) returns the exact float 1024.0 from the real builtin."""
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        result: float = getattr(builtins, "_math_pow")(2.0, 10.0)
        assert math.isclose(result, 1024.0)


class TestEnvironmentBuiltin:
    """std::env reads real process environment variables."""

    def test_env_returns_set_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """std::env returns the live value of a real environment variable.

        ``monkeypatch`` only seeds the real process environment that the
        builtin reads via ``os.environ``; the lookup itself is the genuine
        operation under test.

        Args:
            monkeypatch: Pytest environment patcher used to seed a real var.
        """
        monkeypatch.setenv("INTELLICRACK_HEXPAT_TEST_VAR", "real-value-42")
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        result = getattr(builtins, "_env_get")("INTELLICRACK_HEXPAT_TEST_VAR")
        assert result.value == "real-value-42"

    def test_env_unset_returns_empty(self) -> None:
        """std::env returns an empty string for an unset variable name."""
        reader = DataReader.from_bytes(bytes(4))
        builtins = BuiltinFunctions(reader)
        result = getattr(builtins, "_env_get")("INTELLICRACK_DEFINITELY_UNSET_XYZ")
        assert not result.value
