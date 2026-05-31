# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""Real-data E2E coverage for the HexPat evaluator, interpreter, and data reader.

These tests address coverage gaps documented in the Shard 09 hexpat back-end
audit. They drive the full preprocessor -> lexer -> parser -> evaluator pipeline
via :meth:`HexPatInterpreter.execute_bytes` and assert on concrete decoded
values rather than mere field presence.

Where a real compiled binary is available (a System32 PE on Windows, or the
committed ELF/Mach-O corpus fixtures), the pattern is run against the genuine
file bytes and validated against fields independently computed with
:mod:`struct`, so the test proves the evaluator decodes authentic binary
structures correctly.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.interpreter import HexPatInterpreter


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def interp() -> HexPatInterpreter:
    """Provide a fresh HexPatInterpreter.

    Returns:
        HexPatInterpreter: A fresh interpreter instance.
    """
    return HexPatInterpreter()


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed-field dict by name within an execute_bytes result list.

    Args:
        results: Parsed field dicts produced by ``execute_bytes``.
        name: The field name to locate.

    Returns:
        dict[str, Any]: The matching field dict.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"field '{name}' not in {[r['name'] for r in results]}"
    return found


class TestBitfieldExtraction:
    """Bit-field member extraction, ordering, and mask correctness."""

    def test_right_to_left_extracts_low_bits_first(self, interp: HexPatInterpreter) -> None:
        """Default right_to_left ordering reads low-order bits into the first member.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xAA]) + bytes(8)
        source = "bitfield Flags {\n    low : 3;\n    high : 5;\n};\nFlags f @ 0;"
        results = interp.execute_bytes(source, data)
        bf = _field(results, "f")
        assert bf["size"] == 1
        assert bf["raw_bytes"] == [0xAA]
        children = {c["name"]: c["display_value"] for c in bf["children"]}
        assert children["low"] == "0x2 (3 bits)"
        assert children["high"] == "0x15 (5 bits)"

    def test_left_to_right_extracts_high_bits_first(self, interp: HexPatInterpreter) -> None:
        """left_to_right ordering reads high-order bits into the first member.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0xAA]) + bytes(8)
        source = (
            '[[bitfield_order("left_to_right")]]\n'
            "bitfield Flags {\n    first : 3;\n    second : 5;\n};\nFlags f @ 0;"
        )
        results = interp.execute_bytes(source, data)
        bf = _field(results, "f")
        children = {c["name"]: c["display_value"] for c in bf["children"]}
        assert children["first"] == "0x5 (3 bits)"
        assert children["second"] == "0xA (5 bits)"

    def test_bit_orders_disagree_on_same_byte(self, interp: HexPatInterpreter) -> None:
        """The two bit orders decode the same byte to different member values.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0b11010010]) + bytes(8)
        rtl_src = "bitfield B {\n    a : 4;\n    b : 4;\n};\nB v @ 0;"
        ltr_src = '[[bitfield_order("left_to_right")]]\nbitfield B {\n    a : 4;\n    b : 4;\n};\nB v @ 0;'
        rtl = {c["name"]: c["display_value"] for c in _field(interp.execute_bytes(rtl_src, data), "v")["children"]}
        ltr = {c["name"]: c["display_value"] for c in _field(interp.execute_bytes(ltr_src, data), "v")["children"]}
        assert rtl["a"] == "0x2 (4 bits)"
        assert rtl["b"] == "0xD (4 bits)"
        assert ltr["a"] == "0xD (4 bits)"
        assert ltr["b"] == "0x2 (4 bits)"
        assert rtl != ltr


class TestPointerDereference:
    """Pointer storage reads its address from data and dereferences the pointee."""

    def test_pointer_dereferences_primitive_pointee(self, interp: HexPatInterpreter) -> None:
        """A u8 pointer reads its address then decodes the byte at that address.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(512)
        struct.pack_into("<Q", data, 0, 0x40)
        data[0x40] = 0xC3
        source = "u8 *ptr @ 0;"
        results = interp.execute_bytes(source, bytes(data))
        ptr = results[0]
        assert ptr["size"] == 8
        assert ptr["display_value"].startswith("*")
        assert ptr["children"], "pointer must dereference a pointee child"
        pointee = ptr["children"][0]
        assert pointee["offset"] == 0x40
        assert pointee["raw_bytes"] == [0xC3]
        assert pointee["display_value"] == "0xC3"

    def test_pointer_dereferences_struct_pointee(self, interp: HexPatInterpreter) -> None:
        """A struct pointer dereferences a full struct at the decoded address.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytearray(512)
        struct.pack_into("<Q", data, 0, 0x80)
        data[0x80] = 0x11
        data[0x81] = 0x22
        source = "struct Pair {\n    u8 a;\n    u8 b;\n};\nPair *p @ 0;"
        results = interp.execute_bytes(source, bytes(data))
        pointee = results[0]["children"][0]
        assert pointee["offset"] == 0x80
        child_vals = {c["name"]: c["display_value"] for c in pointee["children"]}
        assert child_vals["a"] == "0x11"
        assert child_vals["b"] == "0x22"


class TestUnionMemberDecoding:
    """Union members overlay the same bytes and each decode them independently."""

    def test_u32_and_byte_array_decode_same_region(self, interp: HexPatInterpreter) -> None:
        """A u32 member and a u8[4] member both interpret the identical bytes.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x78, 0x56, 0x34, 0x12]) + bytes(12)
        source = "union View {\n    u32 word;\n    u8 octets[4];\n};\nView v @ 0;"
        results = interp.execute_bytes(source, data)
        union = _field(results, "v")
        assert union["size"] == 4
        word = next(c for c in union["children"] if c["name"] == "word")
        octets = next(c for c in union["children"] if c["name"] == "octets")
        assert word["offset"] == 0
        assert octets["offset"] == 0
        assert word["display_value"] == "0x12345678"
        octet_vals = [c["raw_bytes"][0] for c in octets["children"]]
        assert octet_vals == [0x78, 0x56, 0x34, 0x12]

    def test_union_size_is_max_not_sum(self, interp: HexPatInterpreter) -> None:
        """A union sizes to its largest member, not the sum of all members.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(16)
        source = "union U {\n    u8 a;\n    u16 b;\n    u64 c;\n};\nU u @ 0;"
        results = interp.execute_bytes(source, data)
        union = _field(results, "u")
        assert union["size"] == 8


class TestTemplateSubstitution:
    """Template type parameters produce distinct memory layouts per argument."""

    def test_distinct_template_args_yield_distinct_layouts(self, interp: HexPatInterpreter) -> None:
        """A struct templated on a type lays out differently for wide vs narrow args.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes(range(32))
        source = (
            "struct Wide { u32 v; };\n"
            "struct Narrow { u8 v; };\n"
            "struct Box<T> {\n    T value;\n    u8 tail;\n};\n"
            "Box<Wide> big @ 0;\n"
            "Box<Narrow> small @ 0;"
        )
        results = interp.execute_bytes(source, data)
        big = _field(results, "big")
        small = _field(results, "small")
        assert big["size"] == 5
        assert small["size"] == 2
        big_tail = next(c for c in big["children"] if c["name"] == "tail")
        small_tail = next(c for c in small["children"] if c["name"] == "tail")
        assert big_tail["offset"] == 4
        assert small_tail["offset"] == 1


class TestStructInheritance:
    """Derived structs include parent fields ahead of their own."""

    def test_derived_struct_includes_parent_fields(self, interp: HexPatInterpreter) -> None:
        """A derived struct lays out parent fields first, then its own.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x10, 0x20, 0x30, 0x40]) + bytes(8)
        source = (
            "struct Base {\n    u8 base_a;\n    u8 base_b;\n};\n"
            "struct Derived : Base {\n    u8 own_c;\n};\n"
            "Derived d @ 0;"
        )
        results = interp.execute_bytes(source, data)
        derived = _field(results, "d")
        assert derived["size"] == 3
        layout = [(c["name"], c["offset"], c["display_value"]) for c in derived["children"]]
        assert ("base_a", 0, "0x10") in layout
        assert ("base_b", 1, "0x20") in layout
        assert ("own_c", 2, "0x30") in layout


class TestUsingAliases:
    """Type aliases expand to array/primitive layouts when instantiated."""

    def test_array_alias_layout(self, interp: HexPatInterpreter) -> None:
        """A ``using`` alias for an array type instantiates with correct element layout.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = struct.pack("<II", 0xAAAA, 0xBBBB) + bytes(8)
        source = "using Quad = u32[2];\nQuad q @ 0;"
        results = interp.execute_bytes(source, data)
        quad = _field(results, "q")
        assert quad["size"] == 8
        assert len(quad["children"]) == 2
        assert quad["children"][0]["offset"] == 0
        assert quad["children"][1]["offset"] == 4
        assert quad["children"][0]["display_value"] == "0xAAAA"
        assert quad["children"][1]["display_value"] == "0xBBBB"


class TestReflectionAnnotations:
    """Field annotations surface in the parsed-field result dictionaries."""

    def test_comment_annotation_populates_description(self, interp: HexPatInterpreter) -> None:
        """A ``[[comment(...)]]`` annotation appears as the field description.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = bytes([0x42]) + bytes(8)
        source = 'u8 tagged @ 0 [[comment("important byte")]];'
        results = interp.execute_bytes(source, data)
        tagged = _field(results, "tagged")
        assert tagged["description"] == "important byte"
        assert tagged["display_value"] == "0x42"


class TestStringEncodingE2E:
    """String fields decode null-terminated and multi-byte encoded data."""

    def test_null_terminated_strings_stop_at_terminator(self, interp: HexPatInterpreter) -> None:
        """Adjacent null-terminated strings decode independently at their offsets.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = b"alpha\x00beta\x00" + bytes(8)
        source = "str first @ 0;\nstr second @ 6;"
        results = interp.execute_bytes(source, data)
        first = _field(results, "first")
        second = _field(results, "second")
        assert "alpha" in str(first["display_value"])
        assert "beta" not in str(first["display_value"])
        assert "beta" in str(second["display_value"])

    def test_char16_decodes_utf16_unit(self, interp: HexPatInterpreter) -> None:
        """A char16 field decodes a single UTF-16LE code unit.

        Args:
            interp: A fresh HexPatInterpreter fixture.
        """
        data = "OK".encode("utf-16-le") + bytes(8)
        source = "char16 c @ 0;"
        results = interp.execute_bytes(source, data)
        assert "O" in str(results[0]["display_value"])


class TestRealPeBinaryParsing:
    """Parse genuine System32 PE bytes and validate against struct-computed fields."""

    def test_dos_and_pe_headers_decode_from_real_dll(self, interp: HexPatInterpreter, real_pe_dll: Path) -> None:
        """Decode the DOS magic and e_lfanew of a real DLL and confirm the PE signature.

        Args:
            interp: A fresh HexPatInterpreter fixture.
            real_pe_dll: Path to a real System32 PE DLL.
        """
        data = real_pe_dll.read_bytes()
        expected_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        assert data[expected_lfanew : expected_lfanew + 4] == b"PE\x00\x00"

        source = (
            "struct DosHeader {\n"
            "    char magic[2];\n"
            "    u16 cblp;\n"
            "};\n"
            "DosHeader dos @ 0;\n"
            "u32 e_lfanew @ 0x3C;\n"
            "char pe_sig[2] @ e_lfanew;"
        )
        results = interp.execute_bytes(source, data)
        dos = _field(results, "dos")
        magic_child = next(c for c in dos["children"] if c["name"] == "magic")
        assert magic_child["raw_bytes"] == [ord("M"), ord("Z")]

        lfanew = _field(results, "e_lfanew")
        assert lfanew["offset"] == 0x3C
        assert int(lfanew["display_value"], 16) == expected_lfanew

        pe_sig = _field(results, "pe_sig")
        assert pe_sig["offset"] == expected_lfanew
        assert pe_sig["raw_bytes"] == [ord("P"), ord("E")]

    def test_coff_machine_field_matches_struct_decode(self, interp: HexPatInterpreter, real_pe_dll: Path) -> None:
        """The COFF machine word read by the pattern equals the struct-computed value.

        Args:
            interp: A fresh HexPatInterpreter fixture.
            real_pe_dll: Path to a real System32 PE DLL.
        """
        data = real_pe_dll.read_bytes()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        machine_offset = e_lfanew + 4
        expected_machine = struct.unpack_from("<H", data, machine_offset)[0]

        source = (
            "u32 e_lfanew @ 0x3C;\n"
            "u16 machine @ (e_lfanew + 4);\n"
            f"u8 verify @ (machine == {expected_machine} ? 1 : 2);"
        )
        results = interp.execute_bytes(source, data)
        machine = _field(results, "machine")
        assert machine["offset"] == machine_offset
        assert int(machine["display_value"], 16) == expected_machine
        verify = _field(results, "verify")
        assert verify["offset"] == 1


class TestRealElfBinaryParsing:
    """Parse the committed real ELF corpus fixture via the evaluator."""

    def test_elf_header_fields_decode_from_real_binary(self, interp: HexPatInterpreter, real_elf_binary: Path) -> None:
        """Decode ELF magic, class, data, and machine fields from a real ELF binary.

        Args:
            interp: A fresh HexPatInterpreter fixture.
            real_elf_binary: Path to the committed real ELF fixture.
        """
        data = real_elf_binary.read_bytes()
        assert data[:4] == b"\x7fELF"
        expected_class = data[4]
        expected_data_enc = data[5]
        expected_machine = struct.unpack_from("<H", data, 18)[0]

        source = (
            "struct ElfIdent {\n"
            "    char magic[4];\n"
            "    u8 ei_class;\n"
            "    u8 ei_data;\n"
            "};\n"
            "ElfIdent ident @ 0;\n"
            "u16 e_machine @ 18;"
        )
        results = interp.execute_bytes(source, data)
        ident = _field(results, "ident")
        magic = next(c for c in ident["children"] if c["name"] == "magic")
        assert magic["raw_bytes"] == [0x7F, ord("E"), ord("L"), ord("F")]
        ei_class = next(c for c in ident["children"] if c["name"] == "ei_class")
        ei_data = next(c for c in ident["children"] if c["name"] == "ei_data")
        assert int(ei_class["display_value"], 16) == expected_class
        assert int(ei_data["display_value"], 16) == expected_data_enc
        machine = _field(results, "e_machine")
        assert int(machine["display_value"], 16) == expected_machine


class TestDataReaderRealBinary:
    """DataReader read methods validated directly against real binary bytes."""

    def test_read_string_finds_real_dll_internal_name(self, real_pe_dll: Path) -> None:
        """read_string decodes a real ASCII section name found in a real DLL.

        Args:
            real_pe_dll: Path to a real System32 PE DLL.
        """
        data = real_pe_dll.read_bytes()
        reader = DataReader.from_bytes(data)
        text_offset = reader.find_sequence(b".text\x00")
        assert text_offset != -1, "real PE must contain a .text section name"
        decoded, consumed = reader.read_string(text_offset)
        assert decoded == ".text"
        assert consumed == len(b".text\x00")

    def test_find_sequence_locates_pe_signature_in_real_dll(self, real_pe_dll: Path) -> None:
        """find_sequence locates the PE signature at the struct-computed offset.

        Args:
            real_pe_dll: Path to a real System32 PE DLL.
        """
        data = real_pe_dll.read_bytes()
        reader = DataReader.from_bytes(data)
        expected = struct.unpack_from("<I", data, 0x3C)[0]
        found = reader.find_sequence(b"PE\x00\x00")
        assert found == expected

    def test_read_u16_machine_matches_struct(self, real_pe_dll: Path) -> None:
        """DataReader.read_u16 of the COFF machine equals the struct-decoded value.

        Args:
            real_pe_dll: Path to a real System32 PE DLL.
        """
        data = real_pe_dll.read_bytes()
        reader = DataReader.from_bytes(data)
        e_lfanew = reader.read_u32(0x3C, "little")
        expected = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        assert reader.read_u16(e_lfanew + 4, "little") == expected


class TestDataReaderStringEdges:
    """Edge cases for DataReader string and boundary reads against real-shaped data."""

    def test_read_string_multibyte_utf8(self) -> None:
        """read_string decodes a multi-byte UTF-8 string and counts bytes consumed."""
        payload = "caféé".encode()
        reader = DataReader.from_bytes(payload + b"\x00trailing")
        decoded, consumed = reader.read_string(0)
        assert decoded == "caféé"
        assert consumed == len(payload) + 1

    def test_read_string_unterminated_returns_full_chunk(self) -> None:
        """read_string with no NUL returns the whole scanned range as text."""
        reader = DataReader.from_bytes(b"no terminator here")
        decoded, consumed = reader.read_string(0)
        assert decoded == "no terminator here"
        assert consumed == len(b"no terminator here")

    def test_find_sequence_returns_first_of_overlapping(self) -> None:
        """find_sequence returns the first occurrence among overlapping matches."""
        data = b"\xaa\xaa\xaa\xaa\x00"
        reader = DataReader.from_bytes(data)
        assert reader.find_sequence(b"\xaa\xaa") == 0

    def test_find_sequence_at_offset_zero(self) -> None:
        """find_sequence locates a pattern positioned at the very start."""
        reader = DataReader.from_bytes(b"\xde\xad\xbe\xef" + bytes(8))
        assert reader.find_sequence(b"\xde\xad\xbe\xef") == 0

    def test_read_at_exact_boundary_succeeds(self) -> None:
        """A read whose end equals the data size succeeds without raising."""
        reader = DataReader.from_bytes(bytes(range(8)))
        assert reader.read(4, 4) == bytes([4, 5, 6, 7])

    def test_read_fixed_string_strips_trailing_nuls(self) -> None:
        """read_fixed_string decodes a padded fixed field with trailing NULs removed."""
        reader = DataReader.from_bytes(b"NAME\x00\x00\x00\x00")
        assert reader.read_fixed_string(0, 8) == "NAME"
