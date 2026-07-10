# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Integration tests for the HexPat interpreter against real binary data."""

from __future__ import annotations

import math
import struct
from typing import cast

import pytest

from intellicrack.core.hexpat.errors import HexPatError, HexPatRuntimeError
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Create a fresh HexPatInterpreter instance for each test.

    Returns:
        HexPatInterpreter: A new interpreter instance.
    """
    return HexPatInterpreter()


class TestPrimitiveReads:
    """Tests for reading primitive data types from binary data."""

    def test_u8(self, interp: HexPatInterpreter) -> None:
        """Verify reading a single unsigned 8-bit integer.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytes([0xFF])
        results = interp.execute_bytes("u8 v @ 0;", data)
        assert results[0]["display_value"] == "0xFF"
        assert results[0]["size"] == 1

    def test_u16_little_endian(self, interp: HexPatInterpreter) -> None:
        """Verify reading a little-endian unsigned 16-bit integer.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<H", 0x1234)
        results = interp.execute_bytes("u16 v @ 0;", data)
        assert results[0]["display_value"] == "0x1234"

    def test_u32_big_endian(self, interp: HexPatInterpreter) -> None:
        """Verify reading a big-endian unsigned 32-bit integer.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack(">I", 0x12345678)
        results = interp.execute_bytes("be u32 v @ 0;", data)
        assert results[0]["display_value"] == "0x12345678"

    def test_s32_negative(self, interp: HexPatInterpreter) -> None:
        """Verify reading a negative signed 32-bit integer.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<i", -42)
        results = interp.execute_bytes("s32 v @ 0;", data)
        assert results[0]["display_value"] == "-42"

    def test_float(self, interp: HexPatInterpreter) -> None:
        """Verify reading a 32-bit floating point value.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<f", math.pi)
        results = interp.execute_bytes("float v @ 0;", data)
        assert results[0]["display_value"].startswith("3.14")

    def test_double(self, interp: HexPatInterpreter) -> None:
        """Verify reading a 64-bit double precision value.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<d", math.e)
        results = interp.execute_bytes("double v @ 0;", data)
        assert "2.718" in results[0]["display_value"]

    def test_bool_true(self, interp: HexPatInterpreter) -> None:
        """Verify reading a boolean with a truthy byte value.

        Args:
            interp: Fresh interpreter fixture.
        """
        results = interp.execute_bytes("bool v @ 0;", bytes([1]))
        assert results[0]["display_value"] == "true"

    def test_bool_false(self, interp: HexPatInterpreter) -> None:
        """Verify reading a boolean with a zero byte value.

        Args:
            interp: Fresh interpreter fixture.
        """
        results = interp.execute_bytes("bool v @ 0;", bytes([0]))
        assert results[0]["display_value"] == "false"

    def test_char(self, interp: HexPatInterpreter) -> None:
        """Verify reading a single character value.

        Args:
            interp: Fresh interpreter fixture.
        """
        results = interp.execute_bytes("char v @ 0;", b"A")
        assert results[0]["display_value"] == "'A'"

    def test_u64(self, interp: HexPatInterpreter) -> None:
        """Verify reading an unsigned 64-bit integer.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<Q", 0xDEADBEEFCAFEBABE)
        results = interp.execute_bytes("u64 v @ 0;", data)
        assert results[0]["display_value"] == "0xDEADBEEFCAFEBABE"

    def test_out_of_bounds_raises(self, interp: HexPatInterpreter) -> None:
        """Verify that reading past data boundaries raises a runtime error.

        Args:
            interp: Fresh interpreter fixture.
        """
        with pytest.raises(HexPatRuntimeError, match="out of bounds"):
            interp.execute_bytes("u32 v @ 0;", bytes([0, 1]))


class TestStructs:
    """Tests for struct type definitions and field layout."""

    def test_simple_struct(self, interp: HexPatInterpreter) -> None:
        """Verify parsing a flat struct with two fields.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<HI", 0x1234, 0xDEADBEEF)
        source = "struct S { u16 a; u32 b; }; S s @ 0;"
        results = interp.execute_bytes(source, data)
        assert results[0]["name"] == "s"
        kids = results[0]["children"]
        assert kids[0]["name"] == "a"
        assert kids[0]["display_value"] == "0x1234"
        assert kids[1]["name"] == "b"
        assert kids[1]["display_value"] == "0xDEADBEEF"

    def test_nested_struct(self, interp: HexPatInterpreter) -> None:
        """Verify parsing a struct containing another struct as a field.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<HHI", 0x1111, 0x2222, 0xAABBCCDD)
        source = """
            struct Inner { u16 x; u16 y; };
            struct Outer { Inner i; u32 z; };
            Outer o @ 0;
        """
        results = interp.execute_bytes(source, data)
        outer = results[0]
        assert outer["children"][0]["name"] == "i"
        assert len(outer["children"][0]["children"]) == 2
        assert outer["children"][1]["display_value"] == "0xAABBCCDD"

    def test_struct_with_padding(self, interp: HexPatInterpreter) -> None:
        """Verify that padding bytes are correctly skipped in struct layout.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<H", 0x1234) + bytes(6) + struct.pack("<I", 0xBEEF)
        source = "struct S { u16 a; padding[6]; u32 b; }; S s @ 0;"
        results = interp.execute_bytes(source, data)
        kids = results[0]["children"]
        assert kids[0]["display_value"] == "0x1234"
        assert kids[1]["name"] == "_padding"
        assert kids[1]["size"] == 6
        assert kids[2]["display_value"] == "0xBEEF"

    def test_multiple_placements(self, interp: HexPatInterpreter) -> None:
        """Verify placing multiple variables at explicit offsets.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<II", 0xAAAA, 0xBBBB)
        source = "u32 a @ 0; u32 b @ 4;"
        results = interp.execute_bytes(source, data)
        assert len(results) == 2
        assert results[0]["offset"] == 0
        assert results[1]["offset"] == 4


class TestEnums:
    """Tests for enum type definitions and value resolution."""

    def test_enum_named_value(self, interp: HexPatInterpreter) -> None:
        """Verify that an enum resolves to its named member.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytes([2])
        source = "enum Color : u8 { Red = 0, Green = 1, Blue = 2 }; Color c @ 0;"
        results = interp.execute_bytes(source, data)
        assert "Blue" in results[0]["display_value"]
        assert "0x2" in results[0]["display_value"]

    def test_enum_unknown_value(self, interp: HexPatInterpreter) -> None:
        """Verify that an unmatched enum value displays as unknown.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytes([99])
        source = "enum E : u8 { A = 1, B = 2 }; E e @ 0;"
        results = interp.execute_bytes(source, data)
        assert "<unknown>" in results[0]["display_value"]

    def test_enum_auto_increment(self, interp: HexPatInterpreter) -> None:
        """Verify that enum members auto-increment from zero when unspecified.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytes([2])
        source = "enum E : u8 { A, B, C }; E e @ 0;"
        results = interp.execute_bytes(source, data)
        assert "C" in results[0]["display_value"]


class TestConditionals:
    """Tests for conditional field inclusion based on runtime values."""

    def test_if_true_branch(self, interp: HexPatInterpreter) -> None:
        """Verify that the true branch of an if-statement includes its field.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytearray(8)
        data[0] = 1
        struct.pack_into("<I", data, 1, 0xDEAD)
        source = """
            struct S { u8 flag; if (flag == 1) { u32 val; } };
            S s @ 0;
        """
        results = interp.execute_bytes(source, bytes(data))
        kids = results[0]["children"]
        assert len(kids) == 2
        assert kids[1]["name"] == "val"

    def test_if_false_branch(self, interp: HexPatInterpreter) -> None:
        """Verify that the else branch is used when the condition is false.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytearray(8)
        data[0] = 0
        struct.pack_into("<H", data, 1, 0xBEEF)
        source = """
            struct S { u8 flag; if (flag == 1) { u32 a; } else { u16 b; } };
            S s @ 0;
        """
        results = interp.execute_bytes(source, bytes(data))
        kids = results[0]["children"]
        assert kids[1]["name"] == "b"
        assert kids[1]["display_value"] == "0xBEEF"

    def test_enum_conditional(self, interp: HexPatInterpreter) -> None:
        """Verify conditional branching using an enum field value.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytearray(8)
        data[0] = 2
        struct.pack_into("<I", data, 1, 0xCAFE)
        source = """
            enum T : u8 { A=1, B=2, C=3 };
            struct S { T t; if (t == 2) { u32 d; } };
            S s @ 0;
        """
        results = interp.execute_bytes(source, bytes(data))
        kids = results[0]["children"]
        assert len(kids) == 2
        assert kids[1]["name"] == "d"
        assert kids[1]["display_value"] == "0xCAFE"


class TestBitfields:
    """Tests for bitfield definitions and bit-level extraction."""

    def test_bitfield_extraction(self, interp: HexPatInterpreter) -> None:
        """Verify extracting individual bit-width fields from a byte.

        For data=0xB5 (0b10110101) with right_to_left bit ordering (default),
        the fields are extracted from LSB upward:
          a (1 bit, pos 0): (0xB5 >> 0) & 0x1 = 1
          b (1 bit, pos 1): (0xB5 >> 1) & 0x1 = 0
          c (2 bits, pos 2): (0xB5 >> 2) & 0x3 = 1
          d (4 bits, pos 4): (0xB5 >> 4) & 0xF = 11 = 0xB

        Args:
            interp: Fresh interpreter fixture.
        """
        raw_byte = 0b10110101
        data = bytes([raw_byte])
        source = "bitfield F { a : 1; b : 1; c : 2; d : 4; }; F f @ 0;"
        results = interp.execute_bytes(source, data)
        kids = results[0]["children"]
        assert len(kids) == 4

        expected_a = (raw_byte >> 0) & 0x1
        expected_b = (raw_byte >> 1) & 0x1
        expected_c = (raw_byte >> 2) & 0x3
        expected_d = (raw_byte >> 4) & 0xF

        assert kids[0]["name"] == "a"
        assert kids[0]["display_value"] == f"0x{expected_a:X} (1 bits)"
        assert kids[1]["name"] == "b"
        assert kids[1]["display_value"] == f"0x{expected_b:X} (1 bits)"
        assert kids[2]["name"] == "c"
        assert kids[2]["display_value"] == f"0x{expected_c:X} (2 bits)"
        assert kids[3]["name"] == "d"
        assert kids[3]["display_value"] == f"0x{expected_d:X} (4 bits)"


class TestArrays:
    """Tests for fixed-size array declarations."""

    def test_fixed_array(self, interp: HexPatInterpreter) -> None:
        """Verify parsing a fixed-length u32 array inside a struct.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<III", 100, 200, 300)
        source = "struct S { u32 vals[3]; }; S s @ 0;"
        results = interp.execute_bytes(source, data)
        arr = results[0]["children"][0]
        assert arr["name"] == "vals"
        assert len(arr["children"]) == 3

    def test_u8_array(self, interp: HexPatInterpreter) -> None:
        """Verify parsing a top-level u8 array placement.

        Each element is decoded independently as an unsigned 8-bit integer.
        The expected display values are independently computed via hex formatting.

        Args:
            interp: Fresh interpreter fixture.
        """
        raw_values = [10, 20, 30, 40]
        data = bytes(raw_values)
        source = "u8 arr[4] @ 0;"
        results = interp.execute_bytes(source, data)
        assert results[0]["size"] == 4
        kids = results[0]["children"]
        assert len(kids) == 4
        for i, raw_val in enumerate(raw_values):
            expected_display = f"0x{raw_val:X}"
            assert kids[i]["display_value"] == expected_display
            assert kids[i]["size"] == 1


class TestAtOffset:
    """Tests for fields placed at dynamic offsets derived from other fields."""

    def test_field_at_offset(self, interp: HexPatInterpreter) -> None:
        """Verify a field placed at an offset read from another field.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = bytearray(16)
        struct.pack_into("<I", data, 0, 8)
        struct.pack_into("<I", data, 8, 0xBEEF)
        source = """
            struct S {
                u32 ptr;
                u32 target @ ptr;
            };
            S s @ 0;
        """
        results = interp.execute_bytes(source, bytes(data))
        kids = results[0]["children"]
        assert kids[1]["offset"] == 8
        assert kids[1]["display_value"] == "0xBEEF"


class TestEndianness:
    """Tests for explicit endianness prefixes on types."""

    def test_le_prefix(self, interp: HexPatInterpreter) -> None:
        """Verify the explicit little-endian prefix reads correctly.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<I", 0x12345678)
        results = interp.execute_bytes("le u32 v @ 0;", data)
        assert results[0]["display_value"] == "0x12345678"

    def test_be_prefix(self, interp: HexPatInterpreter) -> None:
        """Verify the explicit big-endian prefix reads correctly.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack(">I", 0x12345678)
        results = interp.execute_bytes("be u32 v @ 0;", data)
        assert results[0]["display_value"] == "0x12345678"

    def test_mixed_endianness_in_struct(self, interp: HexPatInterpreter) -> None:
        """Verify mixing little-endian and big-endian fields in one struct.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<H", 0x1234) + struct.pack(">H", 0x5678)
        source = "struct S { le u16 a; be u16 b; }; S s @ 0;"
        results = interp.execute_bytes(source, data)
        kids = results[0]["children"]
        assert kids[0]["display_value"] == "0x1234"
        assert kids[1]["display_value"] == "0x5678"


class TestOutputFormat:
    """Tests for the structure and content of parsed field output dicts."""

    def test_parsed_field_keys(self, interp: HexPatInterpreter) -> None:
        """Verify that parsed fields contain correct values for all required keys.

        Oracle: 42 = 0x2A; independently computed with format(42, 'X').

        Args:
            interp: Fresh interpreter fixture.
        """
        raw_byte = 42
        results = interp.execute_bytes("u8 v @ 0;", bytes([raw_byte]))
        field = results[0]
        assert field["name"] == "v"
        assert field["offset"] == 0
        assert field["size"] == 1
        assert field["raw_bytes"] == [raw_byte]
        assert field["display_value"] == f"0x{raw_byte:X}"
        assert field["children"] == []
        assert not field["description"]

    def test_raw_bytes_is_list_of_int(self, interp: HexPatInterpreter) -> None:
        """Verify that raw_bytes is a list of integers matching the data.

        Args:
            interp: Fresh interpreter fixture.
        """
        results = interp.execute_bytes("u16 v @ 0;", bytes([0xAB, 0xCD]))
        raw_value: object = results[0]["raw_bytes"]
        assert isinstance(raw_value, list)
        raw = cast("list[object]", raw_value)
        assert all(isinstance(b, int) for b in raw)
        assert raw == [0xAB, 0xCD]

    def test_children_is_list(self, interp: HexPatInterpreter) -> None:
        """Verify that children of a struct field are returned as a list.

        Args:
            interp: Fresh interpreter fixture.
        """
        data = struct.pack("<HH", 1, 2)
        results = interp.execute_bytes("struct S{u16 a;u16 b;}; S s @ 0;", data)
        children_value: object = results[0]["children"]
        assert isinstance(children_value, list)
        children = cast("list[object]", children_value)
        assert len(children) == 2


class TestRealBinaryFormats:
    """Tests for parsing real-world binary format headers."""

    def test_pe_dos_header(self, interp: HexPatInterpreter, pe_header_bytes: bytes) -> None:
        """Verify parsing a PE DOS header with magic and e_lfanew fields.

        Args:
            interp: Fresh interpreter fixture.
            pe_header_bytes: Synthesized PE header byte buffer fixture.
        """
        source = """
            struct DOSHeader {
                u16 e_magic;
                u16 e_cblp;
                padding[56];
                u32 e_lfanew;
            };
            DOSHeader h @ 0;
        """
        results = interp.execute_bytes(source, pe_header_bytes)
        kids = results[0]["children"]
        assert kids[0]["display_value"] == "0x5A4D"
        assert kids[3]["display_value"] == "0x50"

    def test_elf_header(self, interp: HexPatInterpreter, elf_header_bytes: bytes) -> None:
        """Verify parsing an ELF64 header including ident, type, and entry.

        Args:
            interp: Fresh interpreter fixture.
            elf_header_bytes: Synthesized ELF64 header byte buffer fixture.
        """
        source = """
            enum ElfClass : u8 { NONE=0, ELF32=1, ELF64=2 };
            enum ElfData : u8 { NONE=0, LSB=1, MSB=2 };
            struct ElfIdent {
                u8 magic[4];
                ElfClass ei_class;
                ElfData ei_data;
                u8 ei_version;
                padding[9];
            };
            struct Elf64 {
                ElfIdent ident;
                u16 e_type;
                u16 e_machine;
                u32 e_version;
                u64 e_entry;
                u64 e_phoff;
            };
            Elf64 hdr @ 0;
        """
        results = interp.execute_bytes(source, elf_header_bytes)
        ident = results[0]["children"][0]
        assert "ELF64" in ident["children"][1]["display_value"]
        assert "LSB" in ident["children"][2]["display_value"]
        entry = results[0]["children"][4]
        assert entry["display_value"] == "0x1000"

    def test_bmp_header(self, interp: HexPatInterpreter, bmp_header_bytes: bytes) -> None:
        """Verify parsing a BMP file header and info header.

        Args:
            interp: Fresh interpreter fixture.
            bmp_header_bytes: Synthesized BMP file byte buffer fixture.
        """
        source = """
            enum Compression : u32 { BI_RGB, BI_RLE8, BI_RLE4 };
            struct FileHeader { u8 bfType[2]; u32 bfSize; u16 r1; u16 r2; u32 bfOffBits; };
            struct InfoHeader {
                u32 biSize; s32 biWidth; s32 biHeight; u16 biPlanes;
                u16 biBitCount; Compression biCompression;
            };
            struct BMP { FileHeader fh; InfoHeader ih; };
            BMP bmp @ 0;
        """
        results = interp.execute_bytes(source, bmp_header_bytes)
        fh = results[0]["children"][0]
        ih = results[0]["children"][1]
        assert int(fh["children"][1]["display_value"], 16) == 58
        assert ih["children"][1]["display_value"] == "1"
        assert "BI_RGB" in ih["children"][5]["display_value"]

    def test_zip_local_header(self, interp: HexPatInterpreter, zip_local_header_bytes: bytes) -> None:
        """Verify parsing a ZIP local file header signature and fields.

        Args:
            interp: Fresh interpreter fixture.
            zip_local_header_bytes: Synthesized ZIP local header fixture.
        """
        source = """
            struct ZipLocal {
                u32 signature;
                u16 version;
                u16 flags;
                u16 compression;
                u16 mod_time;
                u16 mod_date;
                u32 crc32;
                u32 compressed_size;
                u32 uncompressed_size;
                u16 filename_length;
                u16 extra_length;
            };
            ZipLocal z @ 0;
        """
        results = interp.execute_bytes(source, zip_local_header_bytes)
        kids = results[0]["children"]
        assert kids[0]["display_value"] == "0x4034B50"
        assert kids[1]["display_value"] == "0x14"
        assert kids[9]["display_value"] == "0x8"


class TestErrorHandling:
    """Tests for error handling on invalid input and edge cases."""

    def test_unknown_type_raises(self, interp: HexPatInterpreter) -> None:
        """Verify that referencing an undefined type raises an error.

        Args:
            interp: Fresh interpreter fixture.
        """
        with pytest.raises(HexPatError):
            interp.execute_bytes("UnknownType v @ 0;", bytes(4))

    def test_syntax_error_raises(self, interp: HexPatInterpreter) -> None:
        """Verify that malformed source code raises a parse error.

        Args:
            interp: Fresh interpreter fixture.
        """
        with pytest.raises(HexPatError):
            interp.execute_bytes("struct { }", bytes(4))

    def test_empty_source(self, interp: HexPatInterpreter) -> None:
        """Verify that empty source code produces no results.

        Args:
            interp: Fresh interpreter fixture.
        """
        results = interp.execute_bytes("", bytes(4))
        assert results == []

    def test_empty_data(self, interp: HexPatInterpreter) -> None:
        """Verify that reading from empty data raises a runtime error.

        Args:
            interp: Fresh interpreter fixture.
        """
        with pytest.raises(HexPatRuntimeError):
            interp.execute_bytes("u32 v @ 0;", b"")
