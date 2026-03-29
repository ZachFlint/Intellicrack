# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint

"""E2E tests for the HexPat pattern language parser AST output."""

from __future__ import annotations

import pytest


pytest.importorskip("intellicrack.core.hexpat.parser", reason="hexpat parser not available")

from intellicrack.core.hexpat.ast_nodes import (
    BitfieldDecl,
    DeclNode,
    EnumDecl,
    FieldDecl,
    FunctionDecl,
    NamespaceDecl,
    PlacementStmt,
    StmtNode,
    StructDecl,
    UnionDecl,
    UsingDecl,
    VarDecl,
)
from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser


def _parse(source: str) -> list[DeclNode | StmtNode]:
    """Lex and parse a HexPat source string into AST nodes.

    Args:
        source: HexPat DSL source text to parse.

    Returns:
        Ordered list of top-level AST nodes produced by the parser.
    """
    tokens = HexPatLexer(source).tokenize()
    return HexPatParser(tokens).parse()


class TestStructParsing:
    """Tests for struct declaration parsing."""

    def test_parse_struct_declaration_type(self) -> None:
        """Parsing a struct source yields a StructDecl as the first node.

        Returns:
            None
        """
        nodes = _parse("struct Header { u32 magic; };")
        assert len(nodes) >= 1
        assert isinstance(nodes[0], StructDecl)

    def test_parse_struct_name(self) -> None:
        """Parsed StructDecl carries the correct name attribute.

        Returns:
            None
        """
        nodes = _parse("struct Header { u32 magic; };")
        decl = nodes[0]
        assert isinstance(decl, StructDecl)
        assert decl.name == "Header"

    def test_parse_struct_body_contains_field_decls(self) -> None:
        """Struct body contains FieldDecl nodes for each declared field.

        Returns:
            None
        """
        nodes = _parse("struct S { u8 a; u16 b; u32 c; };")
        decl = nodes[0]
        assert isinstance(decl, StructDecl)
        field_nodes = [n for n in decl.body if isinstance(n, FieldDecl)]
        assert len(field_nodes) == 3

    def test_parse_struct_field_names(self) -> None:
        """Each FieldDecl in the struct body carries the correct field name.

        Returns:
            None
        """
        nodes = _parse("struct S { u8 first; u16 second; };")
        decl = nodes[0]
        assert isinstance(decl, StructDecl)
        names = [n.name for n in decl.body if isinstance(n, FieldDecl)]
        assert names == ["first", "second"]

    def test_parse_struct_with_parent(self) -> None:
        """Struct with inheritance sets the parent attribute on StructDecl.

        Returns:
            None
        """
        nodes = _parse("struct Child : Parent { u8 x; };")
        decl = nodes[0]
        assert isinstance(decl, StructDecl)
        assert decl.parent == "Parent"

    def test_parse_struct_without_parent_is_none(self) -> None:
        """Struct without inheritance has parent set to None.

        Returns:
            None
        """
        nodes = _parse("struct S { u8 x; };")
        decl = nodes[0]
        assert isinstance(decl, StructDecl)
        assert decl.parent is None


class TestUnionParsing:
    """Tests for union declaration parsing."""

    def test_parse_union_declaration_type(self) -> None:
        """Parsing a union source yields a UnionDecl as the first node.

        Returns:
            None
        """
        nodes = _parse("union Value { u32 as_int; float as_float; };")
        assert isinstance(nodes[0], UnionDecl)

    def test_parse_union_name(self) -> None:
        """Parsed UnionDecl carries the correct name attribute.

        Returns:
            None
        """
        nodes = _parse("union MyUnion { u8 a; u32 b; };")
        decl = nodes[0]
        assert isinstance(decl, UnionDecl)
        assert decl.name == "MyUnion"

    def test_parse_union_body_has_fields(self) -> None:
        """Union body contains FieldDecl nodes for each declared member.

        Returns:
            None
        """
        nodes = _parse("union U { u8 a; u16 b; };")
        decl = nodes[0]
        assert isinstance(decl, UnionDecl)
        fields = [n for n in decl.body if isinstance(n, FieldDecl)]
        assert len(fields) == 2


class TestEnumParsing:
    """Tests for enum declaration parsing."""

    def test_parse_enum_declaration_type(self) -> None:
        """Parsing an enum source yields an EnumDecl as the first node.

        Returns:
            None
        """
        nodes = _parse("enum Color : u8 { Red = 0, Green = 1, Blue = 2 };")
        assert isinstance(nodes[0], EnumDecl)

    def test_parse_enum_name(self) -> None:
        """Parsed EnumDecl carries the correct name attribute.

        Returns:
            None
        """
        nodes = _parse("enum Color : u8 { Red = 0 };")
        decl = nodes[0]
        assert isinstance(decl, EnumDecl)
        assert decl.name == "Color"

    def test_parse_enum_has_entries(self) -> None:
        """Parsed EnumDecl contains the declared entries.

        Returns:
            None
        """
        nodes = _parse("enum Format : u8 { PNG = 0x89, JPEG = 0xFF };")
        decl = nodes[0]
        assert isinstance(decl, EnumDecl)
        assert len(decl.entries) == 2
        entry_names = [e.name for e in decl.entries]
        assert "PNG" in entry_names
        assert "JPEG" in entry_names


class TestBitfieldParsing:
    """Tests for bitfield declaration parsing."""

    def test_parse_bitfield_declaration_type(self) -> None:
        """Parsing a bitfield source yields a BitfieldDecl as the first node.

        Returns:
            None
        """
        nodes = _parse("bitfield Flags { bit0 : 1; bit1 : 1; reserved : 6; };")
        assert isinstance(nodes[0], BitfieldDecl)

    def test_parse_bitfield_name(self) -> None:
        """Parsed BitfieldDecl carries the correct name attribute.

        Returns:
            None
        """
        nodes = _parse("bitfield B { a : 4; b : 4; };")
        decl = nodes[0]
        assert isinstance(decl, BitfieldDecl)
        assert decl.name == "B"

    def test_parse_bitfield_entries(self) -> None:
        """Parsed BitfieldDecl entries match the declared bit-field names.

        Returns:
            None
        """
        nodes = _parse("bitfield Flags { bit0 : 1; bit1 : 1; reserved : 6; };")
        decl = nodes[0]
        assert isinstance(decl, BitfieldDecl)
        assert len(decl.entries) == 3
        names = [e.name for e in decl.entries]
        assert names == ["bit0", "bit1", "reserved"]


class TestPlacementAndOtherDecls:
    """Tests for placement statements, functions, variables, using, and namespaces."""

    def test_parse_placement_statement(self) -> None:
        """A placement statement (type name @ offset) yields a PlacementStmt.

        Returns:
            None
        """
        nodes = _parse("struct H { u32 x; }; H h @ 0x00;")
        placement = next((n for n in nodes if isinstance(n, PlacementStmt)), None)
        assert placement is not None
        assert placement.name == "h"

    def test_parse_function_declaration(self) -> None:
        """A fn declaration yields a FunctionDecl node.

        Returns:
            None
        """
        nodes = _parse("fn compute(u8 x) -> u32 { return 0; };")
        assert any(isinstance(n, FunctionDecl) for n in nodes)

    def test_parse_function_name(self) -> None:
        """Parsed FunctionDecl carries the correct function name.

        Returns:
            None
        """
        nodes = _parse("fn my_func() { };")
        decl = next(n for n in nodes if isinstance(n, FunctionDecl))
        assert decl.name == "my_func"

    def test_parse_variable_declaration(self) -> None:
        """A const variable declaration yields a VarDecl node.

        Returns:
            None
        """
        nodes = _parse("const u32 MAGIC = 0xDEAD;")
        assert any(isinstance(n, VarDecl) for n in nodes)

    def test_parse_variable_name(self) -> None:
        """Parsed VarDecl carries the correct variable name.

        Returns:
            None
        """
        nodes = _parse("const u32 MAGIC = 0xDEAD;")
        decl = next(n for n in nodes if isinstance(n, VarDecl))
        assert decl.name == "MAGIC"

    def test_parse_using_alias(self) -> None:
        """A using declaration yields a UsingDecl node.

        Returns:
            None
        """
        nodes = _parse("using MyType = u32;")
        assert any(isinstance(n, UsingDecl) for n in nodes)

    def test_parse_using_alias_name(self) -> None:
        """Parsed UsingDecl carries the correct alias name.

        Returns:
            None
        """
        nodes = _parse("using MyType = u32;")
        decl = next(n for n in nodes if isinstance(n, UsingDecl))
        assert decl.alias == "MyType"

    def test_parse_namespace_declaration(self) -> None:
        """A namespace declaration yields a NamespaceDecl node.

        Returns:
            None
        """
        nodes = _parse("namespace Std { struct String { u32 len; } }")
        assert any(isinstance(n, NamespaceDecl) for n in nodes)

    def test_parse_namespace_name(self) -> None:
        """Parsed NamespaceDecl carries the correct namespace name.

        Returns:
            None
        """
        nodes = _parse("namespace Std { struct S { u8 x; } }")
        decl = next(n for n in nodes if isinstance(n, NamespaceDecl))
        assert decl.name == "Std"

    def test_parse_multiple_top_level_declarations(self) -> None:
        """Multiple top-level declarations each produce their own AST node.

        Returns:
            None
        """
        source = """\
struct A { u8 x; };
struct B { u16 y; };
enum E : u8 { V = 1 };
"""
        nodes = _parse(source)
        struct_count = sum(bool(isinstance(n, StructDecl))
                       for n in nodes)
        enum_count = sum(bool(isinstance(n, EnumDecl))
                     for n in nodes)
        assert struct_count == 2
        assert enum_count == 1

    def test_parse_syntax_error_raises(self) -> None:
        """Malformed source raises HexPatParseError.

        Returns:
            None
        """
        with pytest.raises(HexPatParseError):
            _parse("struct Broken { u8 x }")

    def test_parse_empty_source_returns_empty_list(self) -> None:
        """Parsing empty source returns an empty node list.

        Returns:
            None
        """
        nodes = _parse("")
        assert nodes == []
