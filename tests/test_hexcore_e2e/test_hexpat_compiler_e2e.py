# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat DSL compiler (lexer, parser, codegen pipeline)."""

from __future__ import annotations

import json

import pytest


pytest.importorskip(
    "intellicrack.core.hexpat_compiler",
    reason="hexpat_compiler not available",
)

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
    u8 data[16];
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

_NESTED_STRUCT = """\
struct Inner {
    u8 x;
    u8 y;
};
struct Outer {
    Inner pos;
    u32 extra;
};
"""


class TestHexPatCompilerCompile:
    """Tests for HexPatCompiler.compile() returning JSON strings."""

    def test_compile_simple_struct_returns_json_string(self) -> None:
        """Compiling a simple struct returns a valid JSON string.

        Returns:
            None
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_compile_simple_struct_has_name_key(self) -> None:
        """Compiled simple struct JSON contains the struct name.

        Returns:
            None
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert parsed["name"] == "Header"

    def test_compile_simple_struct_has_fields_key(self) -> None:
        """Compiled simple struct JSON contains a fields list.

        Returns:
            None
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert "fields" in parsed
        assert isinstance(parsed["fields"], list)

    def test_compile_simple_struct_field_count(self) -> None:
        """Compiled simple struct produces the expected number of fields.

        Returns:
            None
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert len(parsed["fields"]) == 3

    def test_compile_to_dict_returns_dict(self) -> None:
        """compile_to_dict returns a Python dict directly.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_SIMPLE_STRUCT)
        assert isinstance(result, dict)

    def test_compile_to_dict_expected_keys(self) -> None:
        """compile_to_dict result contains all expected top-level keys.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_SIMPLE_STRUCT)
        assert "name" in result
        assert "fields" in result
        assert "description" in result
        assert "default_endianness" in result

    def test_compile_multi_field_struct(self) -> None:
        """Struct with u8, u16, u32, u64 fields compiles all four fields.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_MULTI_FIELD_STRUCT)
        assert len(result["fields"]) == 4
        names = [f["name"] for f in result["fields"]]
        assert names == ["byte_val", "short_val", "int_val", "long_val"]

    def test_compile_array_field(self) -> None:
        """Struct with an array field compiles the array with correct element count.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_ARRAY_STRUCT)
        data_field = next(f for f in result["fields"] if f["name"] == "data")
        assert data_field["field_type"]["type"] == "Array"
        assert data_field["field_type"]["params"]["count"] == 16

    def test_compile_enum(self) -> None:
        """Enum declaration compiles without error and the wrapper struct appears.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_ENUM_ONLY)
        assert result["name"] == "Wrapper"

    def test_compile_union(self) -> None:
        """Union declaration compiles without error.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_UNION_STRUCT)
        assert result["name"] == "Container"

    def test_compile_bitfield(self) -> None:
        """Bitfield declaration compiles without error.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_BITFIELD_STRUCT)
        assert result["name"] == "WithFlags"

    def test_compile_endianness_annotations(self) -> None:
        """Fields with le/be prefixes compile with correct endianness metadata.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_ENDIAN_STRUCT)
        fields_by_name = {f["name"]: f for f in result["fields"]}
        assert fields_by_name["little_val"]["endianness"] == "little"
        assert fields_by_name["big_val"]["endianness"] == "big"

    def test_compile_nested_struct(self) -> None:
        """Source with two struct declarations compiles without error.

        Returns:
            None
        """
        result = HexPatCompiler.compile_to_dict(_NESTED_STRUCT)
        assert isinstance(result, dict)
        assert "name" in result
        assert "fields" in result

    def test_compile_syntax_error_missing_semicolon_raises(self) -> None:
        """Source with a missing semicolon raises HexPatError.

        Returns:
            None
        """
        bad_source = "struct Bad { u8 x }"
        with pytest.raises(HexPatError):
            HexPatCompiler.compile(bad_source)

    def test_compile_empty_source_raises_no_struct(self) -> None:
        """Empty source raises HexPatError because no struct is present.

        Returns:
            None
        """
        with pytest.raises(HexPatError):
            HexPatCompiler.compile("")


class TestHexPatLexerTokenization:
    """Tests for HexPatLexer.tokenize() producing correct token sequences."""

    def test_tokenize_simple_struct_produces_tokens(self) -> None:
        """Tokenizing a simple struct produces a non-empty token list.

        Returns:
            None
        """
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        assert len(tokens) > 0

    def test_tokenize_includes_eof_token(self) -> None:
        """The token list always ends with an EOF token.

        Returns:
            None
        """
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        assert tokens[-1].type == TokenType.EOF

    def test_tokenize_struct_keyword_present(self) -> None:
        """Tokenizing a struct source yields at least one STRUCT token.

        Returns:
            None
        """
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        types = [t.type for t in tokens]
        assert TokenType.STRUCT in types

    def test_tokenize_identifier_names_captured(self) -> None:
        """Identifier tokens capture the correct source text.

        Returns:
            None
        """
        source = "struct Foo { u8 bar; };"
        tokens = HexPatLexer(source).tokenize()
        identifiers = [t.value for t in tokens if t.type == TokenType.IDENTIFIER]
        assert "Foo" in identifiers
        assert "bar" in identifiers

    def test_tokenize_hex_number(self) -> None:
        """Hex number literals are tokenized as NUMBER tokens with their raw value.

        Returns:
            None
        """
        source = "struct S { u8 x; }; u8 v = 0xFF;"
        tokens = HexPatLexer(source).tokenize()
        numbers = [t.value for t in tokens if t.type == TokenType.NUMBER]
        assert "0xFF" in numbers

    def test_tokenize_line_numbers_advance_correctly(self) -> None:
        """Token line numbers reflect newlines in the source.

        Returns:
            None
        """
        source = "struct S {\n    u8 x;\n};"
        tokens = HexPatLexer(source).tokenize()
        rbrace_tok = next(t for t in tokens if t.type == TokenType.RBRACE)
        assert rbrace_tok.line >= 3
