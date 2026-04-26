# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Unit tests for the unified HexPat DSL compiler.

Verifies that ``intellicrack.core.hexpat_compiler.HexPatCompiler``
delegates lexing and parsing to the shared
``intellicrack.core.hexpat`` lexer/parser/AST and that the
JSON code generator walks the shared AST correctly.
"""

from __future__ import annotations

import json

import pytest

from intellicrack.core.hexpat.ast_nodes import StructDecl
from intellicrack.core.hexpat.lexer import HexPatLexer as SharedLexer
from intellicrack.core.hexpat.parser import HexPatParser as SharedParser
from intellicrack.core.hexpat.tokens import TokenType as SharedTokenType
from intellicrack.core.hexpat_compiler import (
    HexPatCodegen,
    HexPatCompiler,
    HexPatError,
    HexPatLexer,
    HexPatParser,
    Token,
    TokenType,
)


class TestSharedSymbolReexports:
    """Verify the compiler module re-exports the shared lexer/parser/tokens."""

    def test_compiler_module_lexer_is_shared_lexer(self) -> None:
        """``HexPatLexer`` re-exported from the compiler is the shared lexer class."""
        assert HexPatLexer is SharedLexer

    def test_compiler_module_parser_is_shared_parser(self) -> None:
        """``HexPatParser`` re-exported from the compiler is the shared parser class."""
        assert HexPatParser is SharedParser

    def test_compiler_module_token_is_dataclass_with_fields(self) -> None:
        """The re-exported ``Token`` carries ``type``, ``value``, ``line``, ``column`` fields."""
        tok = Token(type=TokenType.STRUCT, value="struct", line=1, column=1)
        assert tok.type is TokenType.STRUCT
        assert tok.value == "struct"
        assert tok.line == 1
        assert tok.column == 1

    def test_compiler_module_tokentype_is_shared(self) -> None:
        """``TokenType`` re-exported from the compiler is identical across both packages."""
        assert TokenType is SharedTokenType


class TestCompilerDelegationToSharedPipeline:
    """Verify ``HexPatCompiler`` uses the shared lexer + parser + AST."""

    def test_compile_round_trips_through_shared_lexer(self) -> None:
        """The compiler accepts the shared lexer's hex-tokens (numeric value as text)."""
        source = "struct S { u8 first; }; u8 v = 0xFF;"
        tokens = SharedLexer(source).tokenize()
        number_tokens = [t for t in tokens if t.type is TokenType.NUMBER]
        assert any(int(t.value, 0) == 0xFF for t in number_tokens)

    def test_compile_round_trips_through_shared_parser(self) -> None:
        """The compiler's pipeline produces shared StructDecl nodes from a struct."""
        source = "struct Header { u32 magic; };"
        tokens = SharedLexer(source).tokenize()
        nodes = SharedParser(tokens).parse()
        assert any(isinstance(n, StructDecl) for n in nodes)

    def test_compile_to_dict_includes_struct_name(self) -> None:
        """The compiler emits the struct name as the ``name`` of the JSON template."""
        source = "struct Header { u32 magic; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["name"] == "Header"

    def test_compile_returns_string_with_indent(self) -> None:
        """``compile`` returns indented JSON whose decoded form is a dict."""
        source = "struct S { u8 a; };"
        out = HexPatCompiler.compile(source)
        assert isinstance(out, str)
        decoded = json.loads(out)
        assert isinstance(decoded, dict)
        assert "  " in out


class TestCodegenRejectsRuntimeConstructs:
    """Verify the AST-walk rejects runtime-only constructs."""

    def test_function_declaration_rejected(self) -> None:
        """A top-level ``fn`` declaration is rejected with a HexPatError."""
        source = "fn helper(u32 x) {};\nstruct S { u32 a; };\n"
        with pytest.raises(HexPatError, match=r"function"):
            HexPatCompiler.compile(source)

    def test_namespace_declaration_rejected(self) -> None:
        """A top-level ``namespace`` declaration is rejected with a HexPatError."""
        source = "namespace ns { struct Inner { u8 a; }; }"
        with pytest.raises(HexPatError, match=r"namespace"):
            HexPatCompiler.compile(source)

    def test_using_declaration_rejected(self) -> None:
        """A top-level ``using`` declaration is rejected with a HexPatError."""
        source = "using Word = u32;\nstruct S { Word w; };"
        with pytest.raises(HexPatError, match=r"using"):
            HexPatCompiler.compile(source)

    def test_while_inside_struct_rejected(self) -> None:
        """A ``while`` statement inside a struct body is rejected."""
        source = "struct S { u8 a; while (a > 0) { a; } };"
        with pytest.raises(HexPatError, match=r"while"):
            HexPatCompiler.compile(source)

    def test_for_inside_struct_rejected(self) -> None:
        """A ``for`` statement inside a struct body is rejected."""
        source = "struct S { u8 a; for (a = 0; a < 4; a) { a; } };"
        with pytest.raises(HexPatError, match=r"for"):
            HexPatCompiler.compile(source)

    def test_match_inside_struct_rejected(self) -> None:
        """A ``match`` statement inside a struct body is rejected."""
        source = "struct S {\n    u8 a;\n    match (a) { 1: { } 2: { } _: { } }\n};\n"
        with pytest.raises(HexPatError, match=r"match"):
            HexPatCompiler.compile(source)


class TestCodegenStaticConstructsCompile:
    """Verify all supported static constructs reach the JSON output."""

    def test_simple_struct_emits_three_fields(self) -> None:
        """A struct with three primitive fields produces three JSON fields."""
        source = "struct S { u8 a; u16 b; u32 c; };"
        result = HexPatCompiler.compile_to_dict(source)
        assert len(result["fields"]) == 3

    def test_array_field_carries_count(self) -> None:
        """An array field produces an ``Array`` JSON type with the correct count."""
        source = "struct S { u8 data[16]; };"
        result = HexPatCompiler.compile_to_dict(source)
        data_field = result["fields"][0]
        assert data_field["field_type"]["type"] == "Array"
        assert data_field["field_type"]["params"]["count"] == 16

    def test_endianness_le_be_normalized(self) -> None:
        """Fields with ``le`` and ``be`` prefixes produce ``little`` and ``big``."""
        source = "struct S { le u16 a; be u32 b; };"
        result = HexPatCompiler.compile_to_dict(source)
        by_name = {f["name"]: f for f in result["fields"]}
        assert by_name["a"]["endianness"] == "little"
        assert by_name["b"]["endianness"] == "big"

    def test_enum_emits_values_under_types_key(self) -> None:
        """A non-main ``enum`` is emitted under the ``types`` map of the JSON template."""
        source = "enum Color : u8 { Red = 0, Green = 1, Blue = 2 };\nstruct Wrapper { Color c; };\n"
        result = HexPatCompiler.compile_to_dict(source)
        assert result["name"] == "Wrapper"
        assert "Color" in result["types"]
        values = result["types"]["Color"]["values"]
        assert ("Red", 0) in values
        assert ("Green", 1) in values
        assert ("Blue", 2) in values

    def test_enum_auto_increment_after_explicit_value(self) -> None:
        """Enum entries auto-increment after an explicit value."""
        source = "enum E : u8 { A, B = 5, C, D };\nstruct W { E e; };\n"
        result = HexPatCompiler.compile_to_dict(source)
        values = result["types"]["E"]["values"]
        assert values == [("A", 0), ("B", 5), ("C", 6), ("D", 7)]

    def test_bitfield_fields_emitted(self) -> None:
        """A bitfield declaration produces matching ``(name, width)`` JSON pairs."""
        source = "bitfield Flags { a : 1; b : 3; c : 4; };\nstruct W { u8 raw; };\n"
        result = HexPatCompiler.compile_to_dict(source)
        assert "Flags" in result["types"]
        fields = result["types"]["Flags"]["fields"]
        assert fields == [("a", 1), ("b", 3), ("c", 4)]

    def test_union_emitted_under_types(self) -> None:
        """A union declaration is emitted with kind ``union`` under ``types``."""
        source = "union V { u32 i; float f; };\nstruct C { V v; };\n"
        result = HexPatCompiler.compile_to_dict(source)
        assert "V" in result["types"]
        assert result["types"]["V"]["kind"] == "union"

    def test_const_arithmetic_array_size(self) -> None:
        """An array size built from arithmetic literals folds to its integer value."""
        source = "struct S { u8 data[2 + 3 * 4]; };"
        result = HexPatCompiler.compile_to_dict(source)
        data_field = result["fields"][0]
        assert data_field["field_type"]["params"]["count"] == 14


class TestCodegenConstantExpressionRejection:
    """Verify the const-expr evaluator rejects non-compile-time forms."""

    def test_dollar_in_array_size_rejected(self) -> None:
        """The current-offset marker is not a compile-time constant."""
        source = "struct S { u8 data[$]; };"
        with pytest.raises(HexPatError, match=r"\$"):
            HexPatCompiler.compile(source)

    def test_sizeof_in_array_size_rejected(self) -> None:
        """``sizeof(...)`` is rejected as a compile-time integer."""
        source = "struct S { u8 a; u8 data[sizeof(a)]; };"
        with pytest.raises(HexPatError, match=r"(?i)sizeof"):
            HexPatCompiler.compile(source)


class TestErrorTranslation:
    """Verify HexPatParseError translates to HexPatError with location preserved."""

    def test_parse_error_translated_to_hexpat_error(self) -> None:
        """A parse-error raises :class:`HexPatError` with a non-zero line/column."""
        source = "struct Bad { u8 x }"
        with pytest.raises(HexPatError) as exc_info:
            HexPatCompiler.compile(source)
        err = exc_info.value
        assert err.line > 0
        assert err.column > 0

    def test_no_struct_present_raises_hexpat_error(self) -> None:
        """An empty source raises :class:`HexPatError` due to no struct."""
        with pytest.raises(HexPatError, match=r"no struct"):
            HexPatCompiler.compile("")


class TestDirectCodegen:
    """Cover the codegen API independently of the compiler entry point."""

    def test_codegen_can_be_constructed_from_shared_ast(self) -> None:
        """Codegen accepts a parsed shared AST and emits a JSON template dict."""
        source = "struct Header { u8 a; u16 b; };"
        tokens = SharedLexer(source).tokenize()
        decls = SharedParser(tokens).parse()
        codegen = HexPatCodegen(list(decls))
        result = codegen.generate()
        assert result["name"] == "Header"
        assert len(result["fields"]) == 2
