# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Parser-level AST coverage for HexPat grammar constructs.

These tests drive the real :class:`HexPatLexer` -> :class:`HexPatParser`
pipeline and inspect the concrete AST node structure produced, rather than
relying on the downstream evaluator to observe behaviour indirectly. They
cover grammar paths that the evaluator-only e2e suites never validate at the
parser level: double-bracket annotations, declaration-site template
parameters, while-condition arrays, nested namespaces, operator precedence
nesting, and typed/padding bitfield entries.

All inputs are minimal but real HexPat source strings exercising the exact
grammar productions named in the parser source; the assertions are made
against the structural AST fields (``annotations``, ``template_params``,
``while_condition``, ``type_hint``, ``is_padding`` etc.) that the parser
populates.
"""

from __future__ import annotations

from intellicrack.core.hexpat.ast_nodes import (
    ArrayType,
    BinaryExpr,
    BitfieldDecl,
    FieldDecl,
    IdentifierExpr,
    NamespaceDecl,
    StructDecl,
    TernaryExpr,
    UnaryExpr,
    UsingDecl,
    VarDecl,
)
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser


def _parse(source: str) -> list[object]:
    """Tokenize and parse source into top-level AST nodes.

    Args:
        source: HexPat source text to parse.

    Returns:
        list[object]: The parsed top-level declaration and statement nodes.
    """
    tokens = HexPatLexer(source).tokenize()
    return list(HexPatParser(tokens).parse())


class TestAnnotationParsing:
    """Cover ``_parse_annotations``/``_try_parse_annotations`` (F002)."""

    def test_bare_annotation_attaches_to_struct(self) -> None:
        """A single bare ``[[ name ]]`` annotation produces a (name, None) pair."""
        nodes = _parse("[[ color ]] struct S { u8 x; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        assert struct.annotations == (("color", None),)

    def test_annotation_with_expression_argument(self) -> None:
        """An annotation argument is parsed into an expression node."""
        nodes = _parse("[[ format(formatter) ]] struct S { u8 x; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        assert len(struct.annotations) == 1
        name, expr = struct.annotations[0]
        assert name == "format"
        assert isinstance(expr, IdentifierExpr)
        assert expr.name == "formatter"

    def test_multiple_annotations_with_mixed_arguments(self) -> None:
        """A comma-separated annotation list yields one entry per annotation."""
        nodes = _parse("[[ a, b(1 + 2) ]] struct S { u8 x; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        assert len(struct.annotations) == 2
        first_name, first_expr = struct.annotations[0]
        second_name, second_expr = struct.annotations[1]
        assert first_name == "a"
        assert first_expr is None
        assert second_name == "b"
        assert isinstance(second_expr, BinaryExpr)
        assert second_expr.op == "+"


class TestTemplateParamParsing:
    """Cover ``_parse_template_params``/``_parse_template_param`` (F003)."""

    def test_single_type_parameter(self) -> None:
        """``struct Foo<T>`` records one non-auto, un-hinted template param."""
        nodes = _parse("struct Foo<T> { T x; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        assert len(struct.template_params) == 1
        param = struct.template_params[0]
        assert param.name == "T"
        assert param.is_auto is False
        assert param.type_hint is None

    def test_auto_and_type_hinted_parameters(self) -> None:
        """``<auto N, TypeHint Name>`` distinguishes auto vs type-hinted params."""
        nodes = _parse("struct Foo<auto N, TypeHint Name> { u8 x; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        assert len(struct.template_params) == 2
        auto_param, hinted_param = struct.template_params
        assert auto_param.name == "N"
        assert auto_param.is_auto is True
        assert auto_param.type_hint is None
        assert hinted_param.name == "Name"
        assert hinted_param.is_auto is False
        assert hinted_param.type_hint == "TypeHint"

    def test_using_alias_with_template_params(self) -> None:
        """A templated ``using`` alias records its declaration-site params.

        HexPat pointer types are written prefix (``*T``), so the templated
        alias target uses that form.
        """
        nodes = _parse("using Ptr<T> = *T;")
        alias = nodes[0]
        assert isinstance(alias, UsingDecl)
        assert alias.alias == "Ptr"
        assert len(alias.template_params) == 1
        assert alias.template_params[0].name == "T"


class TestArrayParsing:
    """Cover the while-condition array path in ``_parse_type`` (F004)."""

    def test_field_with_while_condition_array(self) -> None:
        """``u8 items[while(...)]`` yields a field whose while_condition is set."""
        nodes = _parse("struct S { u8 items[while($ < 10)]; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        field = struct.body[0]
        assert isinstance(field, FieldDecl)
        assert field.while_condition is not None
        assert field.array_size is None
        assert isinstance(field.while_condition, BinaryExpr)
        assert field.while_condition.op == "<"

    def test_array_type_node_while_condition(self) -> None:
        """A type-position while-array produces an ArrayType with while_condition."""
        nodes = _parse("using Dyn = u8[while($ < 4)];")
        alias = nodes[0]
        assert isinstance(alias, UsingDecl)
        array_type = alias.target
        assert isinstance(array_type, ArrayType)
        assert array_type.size is None
        assert array_type.while_condition is not None

    def test_fixed_size_array_has_no_while_condition(self) -> None:
        """A fixed-size array records its size and leaves while_condition None."""
        nodes = _parse("struct S { u8 items[4]; };")
        struct = nodes[0]
        assert isinstance(struct, StructDecl)
        field = struct.body[0]
        assert isinstance(field, FieldDecl)
        assert field.while_condition is None
        assert field.array_size is not None


class TestNestedNamespaceParsing:
    """Cover nested namespace bodies in ``_parse_namespace`` (F005)."""

    def test_nested_namespace_contains_inner_struct(self) -> None:
        """A namespace nested inside another exposes its own struct body.

        Declarations inside a namespace body are not semicolon-separated in the
        HexPat grammar, so the inner struct is written without a trailing ``;``.
        """
        nodes = _parse("namespace A { namespace B { struct S { u8 x; } } }")
        outer = nodes[0]
        assert isinstance(outer, NamespaceDecl)
        assert outer.name == "A"
        assert len(outer.body) == 1
        inner = outer.body[0]
        assert isinstance(inner, NamespaceDecl)
        assert inner.name == "B"
        assert len(inner.body) == 1
        struct = inner.body[0]
        assert isinstance(struct, StructDecl)
        assert struct.name == "S"

    def test_namespace_body_mixes_struct_and_enum(self) -> None:
        """A namespace can hold both struct and enum declarations."""
        nodes = _parse("namespace PE { struct Header { u32 magic; } enum Kind : u8 { EXE = 1 } }")
        namespace = nodes[0]
        assert isinstance(namespace, NamespaceDecl)
        kinds = [type(node).__name__ for node in namespace.body]
        assert "StructDecl" in kinds
        assert "EnumDecl" in kinds


class TestExpressionPrecedence:
    """Cover Pratt precedence nesting in ``_parse_expression`` (F007)."""

    def test_addition_binds_looser_than_multiplication(self) -> None:
        """``1 + 2 * 3`` nests the multiplication under the addition's right."""
        nodes = _parse("u8 x = 1 + 2 * 3;")
        decl = nodes[0]
        assert isinstance(decl, VarDecl)
        root = decl.initializer
        assert isinstance(root, BinaryExpr)
        assert root.op == "+"
        assert isinstance(root.right, BinaryExpr)
        assert root.right.op == "*"

    def test_ternary_expression_structure(self) -> None:
        """A ternary expression parses into a TernaryExpr node."""
        nodes = _parse("u8 x = a ? b : c;")
        decl = nodes[0]
        assert isinstance(decl, VarDecl)
        assert isinstance(decl.initializer, TernaryExpr)

    def test_unary_negation_structure(self) -> None:
        """A leading minus parses into a UnaryExpr with operator '-'."""
        nodes = _parse("u8 x = -a;")
        decl = nodes[0]
        assert isinstance(decl, VarDecl)
        assert isinstance(decl.initializer, UnaryExpr)
        assert decl.initializer.op == "-"


class TestBitfieldEntryParsing:
    """Cover typed and padding bitfield entries in ``_parse_bitfield_entry`` (F008)."""

    def test_signed_unsigned_type_hints(self) -> None:
        """Primitive type hints on bitfield entries are recorded verbatim."""
        nodes = _parse("bitfield Flags { s8 signed_f : 4; u8 unsigned_f : 4; };")
        bitfield = nodes[0]
        assert isinstance(bitfield, BitfieldDecl)
        entries = {entry.name: entry for entry in bitfield.entries}
        assert entries["signed_f"].type_hint == "s8"
        assert entries["unsigned_f"].type_hint == "u8"
        assert entries["signed_f"].is_padding is False

    def test_padding_entry_flagged(self) -> None:
        """A ``padding : N`` entry sets is_padding and uses the padding name."""
        nodes = _parse("bitfield Flags { a : 2; padding : 6; };")
        bitfield = nodes[0]
        assert isinstance(bitfield, BitfieldDecl)
        padding_entries = [entry for entry in bitfield.entries if entry.is_padding]
        assert len(padding_entries) == 1
        assert padding_entries[0].name == "padding"
