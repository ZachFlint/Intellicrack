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
        """Compiling a simple struct returns a JSON string with exact name and field names.

        Verifies that the JSON output encodes the correct struct name and field
        names so that a regression in the codegen name extraction would be caught.
        The ``name`` key must equal ``"Header"`` and ``fields[*]["name"]`` must
        equal ``["magic", "version", "flags"]`` in order.
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert parsed["name"] == "Header"
        field_names = [f["name"] for f in parsed["fields"]]
        assert field_names == ["magic", "version", "flags"], f"Field names mismatch: {field_names!r}"

    def test_compile_simple_struct_has_name_key(self) -> None:
        """Compiled simple struct JSON contains the struct name."""
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert parsed["name"] == "Header"

    def test_compile_simple_struct_has_fields_key(self) -> None:
        """Compiled simple struct JSON contains a fields list with correct types.

        Each field must carry a ``field_type`` dict with a ``type`` key matching
        the expected primitive type name: ``magic`` → ``UInt32``, ``version`` →
        ``UInt16``, ``flags`` → ``UInt8``.
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert "fields" in parsed
        assert isinstance(parsed["fields"], list)
        fields_by_name = {f["name"]: f for f in parsed["fields"]}
        assert fields_by_name["magic"]["field_type"]["type"] == "UInt32", (
            f"magic must be UInt32, got {fields_by_name['magic']['field_type']!r}"
        )
        assert fields_by_name["version"]["field_type"]["type"] == "UInt16", (
            f"version must be UInt16, got {fields_by_name['version']['field_type']!r}"
        )
        assert fields_by_name["flags"]["field_type"]["type"] == "UInt8", (
            f"flags must be UInt8, got {fields_by_name['flags']['field_type']!r}"
        )

    def test_compile_simple_struct_field_count(self) -> None:
        """Compiled simple struct produces exactly 3 fields with the expected names.

        A count-only assertion would not catch a rename or reorder; the ordered
        name list is verified so any mutation is detected.
        """
        result = HexPatCompiler.compile(_SIMPLE_STRUCT)
        parsed = json.loads(result)
        assert len(parsed["fields"]) == 3
        names = [f["name"] for f in parsed["fields"]]
        assert names == ["magic", "version", "flags"], f"Field names mismatch: {names!r}"

    def test_compile_to_dict_returns_dict(self) -> None:
        """compile_to_dict returns a Python dict with the correct struct name.

        The return type check alone does not gate the compiler output content.
        Verifying the ``name`` key ensures the codegen extracted the struct name
        correctly, so a silent name-extraction regression would cause this test
        to go red.
        """
        result = HexPatCompiler.compile_to_dict(_SIMPLE_STRUCT)
        assert isinstance(result, dict)
        assert result.get("name") == "Header", f"Expected name 'Header', got {result.get('name')!r}"

    def test_compile_to_dict_expected_keys(self) -> None:
        """compile_to_dict result contains all expected top-level keys with correct values.

        Verifies both key presence AND the exact value for each field that has a
        deterministic output from the simple struct with no #pragma overrides.
        """
        result = HexPatCompiler.compile_to_dict(_SIMPLE_STRUCT)
        assert "name" in result
        assert "fields" in result
        assert "description" in result
        assert "default_endianness" in result
        assert result["name"] == "Header"
        assert result["default_endianness"] == "little", (
            f"Default endianness must be 'little' when no #pragma endian is set: {result['default_endianness']!r}"
        )
        assert isinstance(result["description"], str)
        assert len(result["description"]) > 0, f"description must be a non-empty string: {result['description']!r}"
        assert len(result["fields"]) == 3

    def test_compile_multi_field_struct(self) -> None:
        """Struct with u8, u16, u32, u64 fields compiles all four fields."""
        result = HexPatCompiler.compile_to_dict(_MULTI_FIELD_STRUCT)
        assert len(result["fields"]) == 4
        names = [f["name"] for f in result["fields"]]
        assert names == ["byte_val", "short_val", "int_val", "long_val"]

    def test_compile_array_field(self) -> None:
        """Struct with an array field compiles the array with correct element count."""
        result = HexPatCompiler.compile_to_dict(_ARRAY_STRUCT)
        data_field = next(f for f in result["fields"] if f["name"] == "data")
        assert data_field["field_type"]["type"] == "Array"
        assert data_field["field_type"]["params"]["count"] == 16

    def test_compile_enum(self) -> None:
        """Enum declaration compiles and the types section contains the enum's values.

        The ``types`` dict must contain a ``"Format"`` entry with ``kind == "enum"``,
        the correct backing type ``"UInt8"``, and the exact ``(name, value)`` pairs
        for ``PNG`` (0x89) and ``JPEG`` (0xFF).  A name-only check would not catch
        a value regression in ``_gen_enum_values``.
        """
        result = HexPatCompiler.compile_to_dict(_ENUM_ONLY)
        assert result["name"] == "Wrapper"
        types = result.get("types", {})
        assert "Format" in types, f"types must contain 'Format': {list(types.keys())!r}"
        fmt = types["Format"]
        assert fmt["kind"] == "enum", f"Format kind must be 'enum', got {fmt['kind']!r}"
        assert fmt["backing_type"]["type"] == "UInt8", f"Format backing_type must be UInt8, got {fmt['backing_type']!r}"
        values_map = dict(fmt["values"])
        assert values_map.get("PNG") == 0x89, f"PNG must be 0x89, got {values_map.get('PNG')!r}"
        assert values_map.get("JPEG") == 0xFF, f"JPEG must be 0xFF, got {values_map.get('JPEG')!r}"

    def test_compile_union(self) -> None:
        """Union declaration compiles and the types section contains the union's fields.

        The ``types`` dict must contain a ``"Value"`` entry with ``kind == "union"``
        and exactly two fields: ``as_int`` (``UInt32``) and ``as_float`` (``Float32``).
        A name-only check would not catch a union-field extraction regression.
        """
        result = HexPatCompiler.compile_to_dict(_UNION_STRUCT)
        assert result["name"] == "Container"
        types = result.get("types", {})
        assert "Value" in types, f"types must contain 'Value': {list(types.keys())!r}"
        val = types["Value"]
        assert val["kind"] == "union", f"Value kind must be 'union', got {val['kind']!r}"
        union_fields_by_name = {f["name"]: f for f in val["fields"]}
        assert "as_int" in union_fields_by_name, "Value union must have 'as_int' field"
        assert "as_float" in union_fields_by_name, "Value union must have 'as_float' field"
        assert union_fields_by_name["as_int"]["field_type"]["type"] == "UInt32", (
            f"as_int must be UInt32, got {union_fields_by_name['as_int']['field_type']!r}"
        )
        assert union_fields_by_name["as_float"]["field_type"]["type"] == "Float32", (
            f"as_float must be Float32, got {union_fields_by_name['as_float']['field_type']!r}"
        )

    def test_compile_bitfield(self) -> None:
        """Bitfield declaration compiles and the types section contains the bitfield's entries.

        The ``types`` dict must contain a ``"Flags"`` entry with ``kind == "bitfield"``
        and exactly three entries: ``bit0`` (width 1), ``bit1`` (width 1), ``reserved``
        (width 6) in that order.  A name-only check would not catch a bit-width regression.
        """
        result = HexPatCompiler.compile_to_dict(_BITFIELD_STRUCT)
        assert result["name"] == "WithFlags"
        types = result.get("types", {})
        assert "Flags" in types, f"types must contain 'Flags': {list(types.keys())!r}"
        flags = types["Flags"]
        assert flags["kind"] == "bitfield", f"Flags kind must be 'bitfield', got {flags['kind']!r}"
        entries = flags["fields"]
        assert len(entries) == 3, f"Flags must have 3 entries, got {len(entries)}"
        entries_map = dict(entries)
        assert entries_map.get("bit0") == 1, f"bit0 must have width 1, got {entries_map.get('bit0')!r}"
        assert entries_map.get("bit1") == 1, f"bit1 must have width 1, got {entries_map.get('bit1')!r}"
        assert entries_map.get("reserved") == 6, f"reserved must have width 6, got {entries_map.get('reserved')!r}"

    def test_compile_endianness_annotations(self) -> None:
        """Fields with le/be prefixes compile with correct endianness metadata."""
        result = HexPatCompiler.compile_to_dict(_ENDIAN_STRUCT)
        fields_by_name = {f["name"]: f for f in result["fields"]}
        assert fields_by_name["little_val"]["endianness"] == "little"
        assert fields_by_name["big_val"]["endianness"] == "big"

    def test_compile_nested_struct(self) -> None:
        """Source with two struct declarations compiles the first struct as main, the second under types.

        The compiler designates the first-declared struct as the main template,
        so ``Inner`` (fields ``x`` and ``y``, both ``UInt8``) is the main struct.
        The second struct ``Outer`` is emitted under ``types`` with kind
        ``struct``; its ``pos`` field must be a ``StructRef`` referencing
        ``"Inner"`` and its ``extra`` field must be ``UInt32``.  A presence-only
        check would not catch a StructRef resolution regression.
        """
        result = HexPatCompiler.compile_to_dict(_NESTED_STRUCT)
        assert isinstance(result, dict)
        assert result.get("name") == "Inner", f"Inner must be the main struct: {result.get('name')!r}"
        main_fields_by_name = {f["name"]: f for f in result["fields"]}
        assert main_fields_by_name["x"]["field_type"]["type"] == "UInt8"
        assert main_fields_by_name["y"]["field_type"]["type"] == "UInt8"

        types = result.get("types", {})
        assert "Outer" in types, f"types must contain 'Outer': {list(types.keys())!r}"
        outer = types["Outer"]
        assert outer["kind"] == "struct", f"Outer kind must be 'struct', got {outer['kind']!r}"
        outer_fields_by_name = {f["name"]: f for f in outer["fields"]}
        pos_type = outer_fields_by_name["pos"]["field_type"]
        assert pos_type["type"] == "StructRef", f"pos must be StructRef, got {pos_type['type']!r}"
        assert pos_type["params"] == "Inner", f"pos StructRef must reference 'Inner', got {pos_type['params']!r}"
        assert outer_fields_by_name["extra"]["field_type"]["type"] == "UInt32"

    def test_compile_syntax_error_missing_semicolon_raises(self) -> None:
        """Source with a missing semicolon raises HexPatError with a non-empty message.

        Checking only the exception type does not gate error-message quality.
        The message must be a non-empty string so that a silent empty-message
        regression is caught.
        """
        bad_source = "struct Bad { u8 x }"
        with pytest.raises(HexPatError) as exc_info:
            HexPatCompiler.compile(bad_source)
        assert exc_info.value.message, "HexPatError message must not be empty for a syntax error"
        assert len(exc_info.value.message) > 0

    def test_compile_empty_source_raises_no_struct(self) -> None:
        """Empty source raises HexPatError with a message mentioning the absence of a struct.

        The "no struct declaration found" message is the canonical error text
        from HexPatCodegen.generate(); verifying a substring ensures the error
        path was reached rather than a different failure mode.
        """
        with pytest.raises(HexPatError) as exc_info:
            HexPatCompiler.compile("")
        assert exc_info.value.message, "HexPatError message must not be empty for empty source"
        assert "struct" in exc_info.value.message.lower(), f"Empty-source error message must mention 'struct': {exc_info.value.message!r}"

    def test_compile_if_else_eq_emits_paired_conditionals(self) -> None:
        """if/else on equality emits a pair of Conditional fields with inverted ops."""
        source = "struct S { u8 flag; if (flag == 1) { u32 a; } else { u16 b; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 3
        if_field = fields[1]["field_type"]["params"]
        else_field = fields[2]["field_type"]["params"]
        assert if_field["condition_op"] == "Eq"
        assert else_field["condition_op"] == "Ne"

    def test_compile_if_else_bitmask_emits_bitand_paired_with_bitandzero(self) -> None:
        """if/else on a bit-mask test emits BitAnd / BitAndZero paired Conditional fields.

        The runtime BitAndZero opcode evaluates ``(field & mask) == 0`` and is
        the natural inverse of ``BitAnd`` (``(field & mask) != 0``).
        """
        source = "struct S { u8 flags; if (flags & 4) { u32 a; } else { u16 b; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 3
        if_field = fields[1]["field_type"]["params"]
        else_field = fields[2]["field_type"]["params"]
        assert if_field["condition_op"] == "BitAnd"
        assert if_field["condition_value"] == 4
        assert else_field["condition_op"] == "BitAndZero"
        assert else_field["condition_value"] == 4

    def test_compile_if_only_bitmask_emits_single_bitand_conditional(self) -> None:
        """An ``if`` block without an ``else`` on a bit-mask still emits a single BitAnd."""
        source = "struct S { u8 flags; if (flags & 8) { u32 a; } };"
        result = HexPatCompiler.compile_to_dict(source)
        fields = result["fields"]
        assert len(fields) == 2
        if_field = fields[1]["field_type"]["params"]
        assert if_field["condition_op"] == "BitAnd"
        assert if_field["condition_value"] == 8


_SIMPLE_STRUCT_TOKENS_ORACLE: tuple[TokenType, ...] = (
    TokenType.STRUCT,
    TokenType.IDENTIFIER,
    TokenType.LBRACE,
    TokenType.U32,
    TokenType.IDENTIFIER,
    TokenType.SEMICOLON,
    TokenType.U16,
    TokenType.IDENTIFIER,
    TokenType.SEMICOLON,
    TokenType.U8,
    TokenType.IDENTIFIER,
    TokenType.SEMICOLON,
    TokenType.RBRACE,
    TokenType.SEMICOLON,
    TokenType.EOF,
)
"""Expected ordered token-type sequence for _SIMPLE_STRUCT.

This oracle is derived independently from the source text, not from running the
lexer.  Any mutation of the lexer's keyword/punctuation handling that changes the
sequence will cause the test to go red.
"""


class TestHexPatLexerTokenization:
    """Tests for HexPatLexer.tokenize() producing correct token sequences."""

    def test_tokenize_simple_struct_produces_tokens(self) -> None:
        """Tokenizing a simple struct produces the exact expected token sequence.

        The oracle ``_SIMPLE_STRUCT_TOKENS_ORACLE`` is derived independently from
        the source; a length-only assertion would not catch a token-type regression.
        """
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        assert len(tokens) > 0
        actual_types = tuple(t.type for t in tokens)
        assert actual_types == _SIMPLE_STRUCT_TOKENS_ORACLE, (
            f"Token sequence mismatch.\n  expected: {_SIMPLE_STRUCT_TOKENS_ORACLE}\n  actual:   {actual_types}"
        )

    def test_tokenize_includes_eof_token(self) -> None:
        """The token list always ends with an EOF token with an empty string value."""
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        assert tokens[-1].type == TokenType.EOF
        assert not tokens[-1].value, f"EOF token value must be empty string, got {tokens[-1].value!r}"

    def test_tokenize_struct_keyword_present(self) -> None:
        """Tokenizing a struct source yields exactly one STRUCT token at position 0."""
        tokens = HexPatLexer(_SIMPLE_STRUCT).tokenize()
        struct_tokens = [t for t in tokens if t.type == TokenType.STRUCT]
        assert len(struct_tokens) == 1, f"Expected exactly 1 STRUCT token, got {len(struct_tokens)}"
        assert tokens[0].type == TokenType.STRUCT, f"STRUCT token must be the first token, but first token is {tokens[0].type!r}"

    def test_tokenize_identifier_names_captured(self) -> None:
        """Identifier tokens capture the correct source text in the correct order.

        The source ``struct Foo {{ u8 bar; }};`` produces identifiers
        ``["Foo", "bar"]`` in that order.  Presence-only checks would not
        catch a positional swap.
        """
        source = "struct Foo { u8 bar; };"
        tokens = HexPatLexer(source).tokenize()
        identifiers = [t.value for t in tokens if t.type == TokenType.IDENTIFIER]
        assert identifiers == ["Foo", "bar"], f"Expected identifiers ['Foo', 'bar'] in order, got {identifiers!r}"

    def test_tokenize_hex_number(self) -> None:
        """Hex number literals are tokenized as NUMBER tokens with the correct parsed value.

        ``0xFF`` appears at a known position; verifying the exact token index
        makes the test sensitive to lexer position regressions.
        """
        source = "struct S { u8 v = 0xFF; };"
        tokens = HexPatLexer(source).tokenize()
        number_tokens = [t for t in tokens if t.type == TokenType.NUMBER]
        assert len(number_tokens) == 1, f"Expected exactly 1 NUMBER token, got {len(number_tokens)}"
        assert int(number_tokens[0].value, 0) == 0xFF, f"Number token value must equal 0xFF, got {number_tokens[0].value!r}"

    def test_tokenize_line_numbers_advance_correctly(self) -> None:
        r"""Token line numbers reflect newlines in the source.

        The source ``struct S {\n    u8 x;\n};`` places the struct keyword on
        line 1, the ``u8`` keyword on line 2, and the closing brace on line 3.
        Exact line assertions are used rather than ``>= N`` to catch off-by-one
        regressions.
        """
        source = "struct S {\n    u8 x;\n};"
        tokens = HexPatLexer(source).tokenize()
        struct_tok = next(t for t in tokens if t.type == TokenType.STRUCT)
        u8_tok = next(t for t in tokens if t.type == TokenType.U8)
        rbrace_tok = next(t for t in tokens if t.type == TokenType.RBRACE)
        assert struct_tok.line == 1, f"struct must be on line 1, got {struct_tok.line}"
        assert u8_tok.line == 2, f"u8 must be on line 2, got {u8_tok.line}"
        assert rbrace_tok.line == 3, f"}} must be on line 3, got {rbrace_tok.line}"
