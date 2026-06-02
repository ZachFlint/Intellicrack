# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat DSL compiler (lexer, parser, codegen pipeline).

Every compiled template is validated two ways: the exact JSON template
structure emitted by ``HexPatCompiler`` is asserted field-by-field against
known-correct reference values, and -- wherever the construct is materialisable
-- the compiled template is registered into the real Rust ``intellicrack_hexcore``
runtime and applied to a hand-built binary payload so that the parse output
(offsets, sizes, raw bytes, decoded values) is verified end to end. The Rust
runtime is the independent oracle: it is a different implementation from the
Python codegen, so a regression in either layer is caught.
"""

from __future__ import annotations

import json
import struct
from typing import Any

import pytest


pytest.importorskip(
    "intellicrack.core.hexpat_compiler",
    reason="hexpat_compiler not available",
)
pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore native runtime not built",
)

import intellicrack_hexcore as hexcore

from intellicrack.core.hexpat_compiler import (
    HexPatCompiler,
    HexPatError,
    HexPatLexer,
    TokenType,
)


_SIMPLE_STRUCT = """\
struct Header {
    u32 magic;
    u16 version;
    u8 flags;
};
"""

_MULTI_FIELD_STRUCT = """\
struct MultiField {
    u8 byte_val;
    u16 short_val;
    u32 int_val;
    u64 long_val;
};
"""

_ARRAY_STRUCT = """\
struct WithArray {
    u32 count;
    u8 data[4];
};
"""

_ENUM_ONLY = """\
enum Format : u8 {
    PNG = 0x89,
    JPEG = 0xFF,
};
struct Wrapper {
    Format kind;
};
"""

_UNION_STRUCT = """\
union Value {
    u32 as_int;
    float as_float;
};
struct Container {
    Value val;
};
"""

_BITFIELD_STRUCT = """\
bitfield Flags {
    bit0 : 1;
    bit1 : 1;
    reserved : 6;
};
struct WithFlags {
    u8 raw;
};
"""

_ENDIAN_STRUCT = """\
struct Endian {
    le u16 little_val;
    be u32 big_val;
};
"""

_OUTER_STRUCT = """\
struct Outer {
    Inner pos;
    u32 extra;
};
"""

_INNER_STRUCT = """\
struct Inner {
    u8 x;
    u8 y;
};
"""


def _apply(template_sources: list[str], main_name: str, data: bytes, offset: int = 0) -> list[dict[str, Any]]:
    """Compile templates, register them in the Rust runtime, and apply the main one.

    Each source is compiled with :class:`HexPatCompiler` and registered into a
    fresh ``intellicrack_hexcore.HexDocument`` backed by ``data``. The named
    main template is then applied at ``offset``, returning the runtime's parsed
    field records. The runtime is an independent oracle implemented in Rust, so
    the returned values verify that the compiler's JSON template is faithfully
    consumable end to end.

    Args:
        template_sources: HexPat DSL source strings to compile and register, in
            dependency order (referenced templates first).
        main_name: Name of the registered template to apply.
        data: Raw binary payload the template is applied against.
        offset: Byte offset to begin parsing at.

    Returns:
        list[dict[str, Any]]: Parsed field records produced by the runtime.
    """
    doc = hexcore.HexDocument.open_bytes(data)
    for source in template_sources:
        doc.register_json_template(HexPatCompiler.compile(source))
    result: list[dict[str, Any]] = doc.apply_template(main_name, offset)
    return result


class TestHexPatCompilerCompile:
    """Tests for HexPatCompiler.compile() / compile_to_dict() output and runtime behaviour."""

    def test_compile_simple_struct_full_json_structure(self) -> None:
        """Compiling a simple struct emits the exact JSON template structure."""
        parsed: dict[str, Any] = json.loads(HexPatCompiler.compile(_SIMPLE_STRUCT))
        assert parsed == {
            "name": "Header",
            "description": "Header (compiled from HexPat DSL)",
            "default_endianness": "little",
            "fields": [
                {"name": "magic", "field_type": {"type": "UInt32"}, "description": ""},
                {"name": "version", "field_type": {"type": "UInt16"}, "description": ""},
                {"name": "flags", "field_type": {"type": "UInt8"}, "description": ""},
            ],
        }

    def test_compile_simple_struct_parses_real_bytes(self) -> None:
        """The compiled simple-struct template parses a real little-endian payload correctly."""
        data = struct.pack("<IHB", 0xDEADBEEF, 0x0102, 0x07)
        fields = _apply([_SIMPLE_STRUCT], "Header", data)
        assert [(f["name"], f["offset"], f["size"]) for f in fields] == [
            ("magic", 0, 4),
            ("version", 4, 2),
            ("flags", 6, 1),
        ]
        assert fields[0]["display_value"] == "3735928559 (0xDEADBEEF)"
        assert fields[1]["display_value"] == "258 (0x0102)"
        assert fields[2]["display_value"] == "7 (0x07)"
        assert fields[0]["raw_bytes"] == struct.pack("<I", 0xDEADBEEF)

    def test_compile_to_dict_full_top_level_structure(self) -> None:
        """compile_to_dict exposes the full template dict with exact key values."""
        result = HexPatCompiler.compile_to_dict(_SIMPLE_STRUCT)
        assert result["name"] == "Header"
        assert result["description"] == "Header (compiled from HexPat DSL)"
        assert result["default_endianness"] == "little"
        assert [f["name"] for f in result["fields"]] == ["magic", "version", "flags"]
        assert "types" not in result
        assert "author" not in result
        assert "magic_detection" not in result

    def test_compile_multi_field_struct_types_and_parse(self) -> None:
        """A struct with u8/u16/u32/u64 compiles all four types and parses contiguously."""
        result = HexPatCompiler.compile_to_dict(_MULTI_FIELD_STRUCT)
        assert [(f["name"], f["field_type"]["type"]) for f in result["fields"]] == [
            ("byte_val", "UInt8"),
            ("short_val", "UInt16"),
            ("int_val", "UInt32"),
            ("long_val", "UInt64"),
        ]
        data = struct.pack("<BHIQ", 0x7F, 0xABCD, 0x11223344, 0x1122334455667788)
        fields = _apply([_MULTI_FIELD_STRUCT], "MultiField", data)
        assert [(f["name"], f["offset"], f["size"]) for f in fields] == [
            ("byte_val", 0, 1),
            ("short_val", 1, 2),
            ("int_val", 3, 4),
            ("long_val", 7, 8),
        ]
        assert fields[0]["display_value"] == "127 (0x7F)"
        assert fields[1]["display_value"] == "43981 (0xABCD)"
        assert fields[2]["display_value"] == "287454020 (0x11223344)"
        assert fields[3]["display_value"] == "1234605616436508552 (0x1122334455667788)"

    def test_compile_array_field_structure_and_parse(self) -> None:
        """An array field compiles to an Array type and parses every element."""
        result = HexPatCompiler.compile_to_dict(_ARRAY_STRUCT)
        data_field = next(f for f in result["fields"] if f["name"] == "data")
        assert data_field["field_type"] == {
            "type": "Array",
            "params": {"element_type": {"type": "UInt8"}, "count": 4},
        }
        payload = struct.pack("<I", 4) + bytes([0xAA, 0xBB, 0xCC, 0xDD])
        fields = _apply([_ARRAY_STRUCT], "WithArray", payload)
        count_field = next(f for f in fields if f["name"] == "count")
        array_field = next(f for f in fields if f["name"] == "data")
        assert count_field["display_value"] == "4 (0x00000004)"
        assert array_field["offset"] == 4
        assert array_field["size"] == 4
        children = array_field["children"]
        assert [(c["name"], c["offset"], c["display_value"]) for c in children] == [
            ("[0]", 4, "170 (0xAA)"),
            ("[1]", 5, "187 (0xBB)"),
            ("[2]", 6, "204 (0xCC)"),
            ("[3]", 7, "221 (0xDD)"),
        ]

    def test_compile_enum_values_and_resolves_name(self) -> None:
        """An enum compiles concrete values and the runtime resolves a matching byte to its name."""
        result = HexPatCompiler.compile_to_dict(_ENUM_ONLY)
        assert result["name"] == "Wrapper"
        assert result["types"]["Format"] == {
            "kind": "enum",
            "backing_type": {"type": "UInt8"},
            "values": [("PNG", 0x89), ("JPEG", 0xFF)],
        }
        json_values = json.loads(HexPatCompiler.compile(_ENUM_ONLY))["types"]["Format"]["values"]
        assert json_values == [["PNG", 0x89], ["JPEG", 0xFF]]
        png_fields = _apply([_ENUM_ONLY], "Wrapper", bytes([0x89]))
        assert png_fields[0]["name"] == "kind"
        assert png_fields[0]["display_value"] == "PNG (137, 0x89)"
        jpeg_fields = _apply([_ENUM_ONLY], "Wrapper", bytes([0xFF]))
        assert jpeg_fields[0]["display_value"] == "JPEG (255, 0xFF)"

    def test_compile_union_overlays_fields(self) -> None:
        """A union compiles both overlay members; the same bytes decode as int and float."""
        result = HexPatCompiler.compile_to_dict(_UNION_STRUCT)
        assert result["name"] == "Container"
        assert result["types"]["Value"] == {
            "kind": "union",
            "fields": [
                {"name": "as_int", "field_type": {"type": "UInt32"}, "description": ""},
                {"name": "as_float", "field_type": {"type": "Float32"}, "description": ""},
            ],
        }
        raw = struct.pack("<f", 1.5)
        (expected_int,) = struct.unpack("<I", raw)
        assert expected_int == 0x3FC00000
        assert struct.pack("<I", expected_int) == raw

    def test_compile_bitfield_entries(self) -> None:
        """A bitfield compiles each entry with its exact name and bit width."""
        result = HexPatCompiler.compile_to_dict(_BITFIELD_STRUCT)
        assert result["name"] == "WithFlags"
        assert result["types"]["Flags"] == {
            "kind": "bitfield",
            "fields": [("bit0", 1), ("bit1", 1), ("reserved", 6)],
        }
        assert sum(width for _name, width in result["types"]["Flags"]["fields"]) == 8
        json_fields = json.loads(HexPatCompiler.compile(_BITFIELD_STRUCT))["types"]["Flags"]["fields"]
        assert json_fields == [["bit0", 1], ["bit1", 1], ["reserved", 6]]

    def test_compile_endianness_changes_decoded_value(self) -> None:
        """le/be prefixes compile to endianness metadata that flips the decoded integer."""
        result = HexPatCompiler.compile_to_dict(_ENDIAN_STRUCT)
        fields_by_name = {f["name"]: f for f in result["fields"]}
        assert fields_by_name["little_val"]["endianness"] == "little"
        assert fields_by_name["big_val"]["endianness"] == "big"
        data = bytes([0x34, 0x12]) + bytes([0x00, 0x00, 0x00, 0x05])
        parsed = _apply([_ENDIAN_STRUCT], "Endian", data)
        by_name = {f["name"]: f for f in parsed}
        assert by_name["little_val"]["display_value"] == "4660 (0x1234)"
        assert by_name["big_val"]["display_value"] == "5 (0x00000005)"

    def test_compile_nested_struct_resolves_and_parses(self) -> None:
        """An Inner StructRef inside Outer compiles and the runtime nests the children."""
        result = HexPatCompiler.compile_to_dict(_OUTER_STRUCT)
        assert result["name"] == "Outer"
        assert result["fields"][0] == {
            "name": "pos",
            "field_type": {"type": "StructRef", "params": "Inner"},
            "description": "",
        }
        assert result["fields"][1]["field_type"] == {"type": "UInt32"}
        data = bytes([0x11, 0x22]) + struct.pack("<I", 0x99887766)
        parsed = _apply([_INNER_STRUCT, _OUTER_STRUCT], "Outer", data)
        pos = parsed[0]
        assert pos["name"] == "pos"
        assert pos["offset"] == 0
        assert [(c["name"], c["offset"], c["display_value"]) for c in pos["children"]] == [
            ("x", 0, "17 (0x11)"),
            ("y", 1, "34 (0x22)"),
        ]
        assert parsed[1]["name"] == "extra"
        assert parsed[1]["offset"] == 2
        assert parsed[1]["display_value"] == "2575857510 (0x99887766)"

    def test_compile_syntax_error_missing_semicolon_raises_with_diagnostics(self) -> None:
        """A missing semicolon raises HexPatError with a precise position and message."""
        with pytest.raises(HexPatError) as exc_info:
            HexPatCompiler.compile("struct Bad { u8 x }")
        err = exc_info.value
        assert err.message == "Expected ';', got '}'"
        assert err.line == 1
        assert err.column == 19
        assert str(err) == "<input>:1:19: Expected ';', got '}'"

    def test_compile_empty_source_raises_no_struct(self) -> None:
        """Empty source raises HexPatError reporting that no struct was found."""
        with pytest.raises(HexPatError) as exc_info:
            HexPatCompiler.compile("")
        err = exc_info.value
        assert err.message == "no struct declaration found"
        assert str(err) == "no struct declaration found"

    def test_compile_if_else_eq_partitions_on_value(self) -> None:
        """if/else on equality emits inverted Eq/Ne conditionals that partition the input."""
        source = "struct S { u8 flag; if (flag == 1) { u32 a; } else { u16 b; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 3
        if_params = fields[1]["field_type"]["params"]
        else_params = fields[2]["field_type"]["params"]
        assert if_params["condition_field"] == "flag"
        assert if_params["condition_value"] == 1
        assert if_params["condition_op"] == "Eq"
        assert [f["name"] for f in if_params["fields"]] == ["a"]
        assert else_params["condition_op"] == "Ne"
        assert [f["name"] for f in else_params["fields"]] == ["b"]

        true_branch = _apply([source], "S", bytes([1]) + struct.pack("<I", 0xCAFEBABE))
        assert [(f["name"], f["display_value"]) for f in true_branch] == [
            ("flag", "1 (0x01)"),
            ("a", "3405691582 (0xCAFEBABE)"),
        ]
        false_branch = _apply([source], "S", bytes([2]) + struct.pack("<H", 0xBEEF))
        assert [(f["name"], f["display_value"]) for f in false_branch] == [
            ("flag", "2 (0x02)"),
            ("b", "48879 (0xBEEF)"),
        ]

    def test_compile_if_else_bitmask_partitions_on_bit(self) -> None:
        """if/else on a bit-mask emits BitAnd / BitAndZero that select the right branch.

        The runtime ``BitAndZero`` opcode evaluates ``(field & mask) == 0`` and
        is the exact inverse of ``BitAnd`` (``(field & mask) != 0``), so a set
        bit selects the true branch and a clear bit selects the else branch.
        """
        source = "struct S { u8 flags; if (flags & 4) { u32 a; } else { u16 b; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 3
        if_params = fields[1]["field_type"]["params"]
        else_params = fields[2]["field_type"]["params"]
        assert if_params["condition_op"] == "BitAnd"
        assert if_params["condition_value"] == 4
        assert else_params["condition_op"] == "BitAndZero"
        assert else_params["condition_value"] == 4

        bit_set = _apply([source], "S", bytes([0x04]) + struct.pack("<I", 0x11223344))
        assert [(f["name"], f["display_value"]) for f in bit_set] == [
            ("flags", "4 (0x04)"),
            ("a", "287454020 (0x11223344)"),
        ]
        bit_clear = _apply([source], "S", bytes([0x02]) + struct.pack("<H", 0xABCD))
        assert [(f["name"], f["display_value"]) for f in bit_clear] == [
            ("flags", "2 (0x02)"),
            ("b", "43981 (0xABCD)"),
        ]

    def test_compile_if_only_bitmask_selects_or_omits_branch(self) -> None:
        """An if-only bit-mask emits a single BitAnd that includes the field iff the bit is set."""
        source = "struct S { u8 flags; if (flags & 8) { u32 a; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 2
        if_params = fields[1]["field_type"]["params"]
        assert if_params["condition_op"] == "BitAnd"
        assert if_params["condition_value"] == 8
        assert [f["name"] for f in if_params["fields"]] == ["a"]

        bit_set = _apply([source], "S", bytes([0x08]) + struct.pack("<I", 0xDEADC0DE))
        assert [(f["name"], f["display_value"]) for f in bit_set] == [
            ("flags", "8 (0x08)"),
            ("a", "3735929054 (0xDEADC0DE)"),
        ]
        bit_clear = _apply([source], "S", bytes([0x01]) + struct.pack("<I", 0))
        assert [f["name"] for f in bit_clear] == ["flags"]


class TestHexPatLexerTokenization:
    """Tests for HexPatLexer.tokenize() producing exact token sequences and positions."""

    def test_tokenize_full_sequence_with_positions(self) -> None:
        """Tokenizing a struct yields the complete ordered token sequence with positions."""
        tokens = HexPatLexer("struct Foo { u8 bar; };").tokenize()
        actual = [(t.type, t.value, t.line, t.column) for t in tokens]
        assert actual == [
            (TokenType.STRUCT, "struct", 1, 1),
            (TokenType.IDENTIFIER, "Foo", 1, 8),
            (TokenType.LBRACE, "{", 1, 12),
            (TokenType.U8, "u8", 1, 14),
            (TokenType.IDENTIFIER, "bar", 1, 17),
            (TokenType.SEMICOLON, ";", 1, 20),
            (TokenType.RBRACE, "}", 1, 22),
            (TokenType.SEMICOLON, ";", 1, 23),
            (TokenType.EOF, "", 1, 24),
        ]

    def test_tokenize_terminates_with_single_eof(self) -> None:
        """The stream ends with exactly one EOF token and no EOF appears earlier."""
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        assert tokens[-1].type == TokenType.EOF
        assert [t.type for t in tokens].count(TokenType.EOF) == 1

    def test_tokenize_keyword_vs_identifier_classification(self) -> None:
        """The lexer classifies the struct keyword and type keyword distinctly from identifiers."""
        tokens = HexPatLexer("struct Foo { u8 bar; };").tokenize()
        types = [t.type for t in tokens]
        assert types.count(TokenType.STRUCT) == 1
        assert types.count(TokenType.U8) == 1
        identifiers = [t.value for t in tokens if t.type == TokenType.IDENTIFIER]
        assert identifiers == ["Foo", "bar"]
        assert "struct" not in identifiers
        assert "u8" not in identifiers

    def test_tokenize_identifiers_in_order_and_context(self) -> None:
        """Identifier tokens are captured in source order at their exact positions."""
        tokens = HexPatLexer("struct Foo { u8 bar; };").tokenize()
        identifier_tokens = [(t.value, t.line, t.column) for t in tokens if t.type == TokenType.IDENTIFIER]
        assert identifier_tokens == [("Foo", 1, 8), ("bar", 1, 17)]

    def test_tokenize_hex_number_value_and_position(self) -> None:
        """A hex literal becomes a NUMBER token carrying the decimal value at its column."""
        source = "struct S { u8 x; }; u8 v = 0xFF;"
        tokens = HexPatLexer(source).tokenize()
        number_tokens = [t for t in tokens if t.type == TokenType.NUMBER]
        assert len(number_tokens) == 1
        number = number_tokens[0]
        assert number.value == "255"
        assert int(number.value, 0) == 0xFF
        assert number.line == 1
        assert number.column == 28
        prev_token = tokens[tokens.index(number) - 1]
        assert prev_token.type == TokenType.ASSIGN

    def test_tokenize_line_numbers_for_every_token(self) -> None:
        """Every token reports the line on which its source text begins."""
        source = "struct S {\n    u8 x;\n};"
        tokens = HexPatLexer(source).tokenize()
        actual = [(t.type, t.line, t.column) for t in tokens]
        assert actual == [
            (TokenType.STRUCT, 1, 1),
            (TokenType.IDENTIFIER, 1, 8),
            (TokenType.LBRACE, 1, 10),
            (TokenType.U8, 2, 5),
            (TokenType.IDENTIFIER, 2, 8),
            (TokenType.SEMICOLON, 2, 9),
            (TokenType.RBRACE, 3, 1),
            (TokenType.SEMICOLON, 3, 2),
            (TokenType.EOF, 3, 3),
        ]
