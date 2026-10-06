# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the second half of the HexPat evaluator.

Drives the real preprocessor, lexer, parser and evaluator with small pattern
sources over byte buffers built in the tests. Expected values are computed
independently from those bytes or from the pattern-language rules and cover
subscripts, assignments and compound assignments, ``sizeof`` over every kind
of type, integer, float, enum and bitfield casts, template instantiation,
annotation descriptions, the evaluator's own built-in functions and the
truthiness and match-equality helpers. Constructs the parser cannot emit
(``sizeof``, ``addressof`` and ``typenameof`` as plain callees, placements
inside composite bodies, primitive template arguments) are exercised with real
AST nodes handed to the public ``HexPatEvaluator.evaluate`` entry point.
"""

from __future__ import annotations

import math
import struct
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.ast_nodes import (
    BinaryExpr,
    CastExpr,
    FunctionCallExpr,
    IdentifierExpr,
    MemberAccessExpr,
    NamedType,
    NumberLiteral,
    PlacementStmt,
    PrimitiveType,
    SizeofExpr,
    StringLiteral,
    StructDecl,
    TernaryExpr,
    UnionDecl,
)
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError, HexPatTypeError
from intellicrack.core.hexpat.evaluator import HexPatEvaluator
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.hexpat.type_system import TypeRegistry


if TYPE_CHECKING:
    from intellicrack.core.hexpat.ast_nodes import DeclNode, ExprNode, StmtNode, TypeNode
    from intellicrack.core.hexpat.interpreter import HexPatInterpreter


_ENUMS: str = "enum Small : u8 {\n    A = 1\n};\nenum Signed : s8 {\n    N\n};"
_NINE_BITS: str = "bitfield Nine {\n    a : 4;\n    b : 5;\n};"
_READ_DATA: bytes = bytes([0xAA, 0xBB, 0x34, 0x12, 0xFE, 0xFF])
_SEARCH_DATA: bytes = b"xxabyyab"
_STRING_DATA: bytes = b"\x00\x00hi\x00"


def _padded(data: bytes | None) -> bytes:
    """Pad probe data to 64 bytes so every probe offset is readable.

    Args:
        data: The leading bytes of the buffer, or ``None`` for all zeros.

    Returns:
        bytes: The leading bytes followed by zeros up to 64 bytes in total.
    """
    leading = data if data is not None else b""
    return leading + bytes(max(0, 64 - len(leading)))


def _field(results: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Find a parsed-field dict by name.

    Args:
        results: Parsed field dicts produced by the evaluator.
        name: The field name to locate.

    Returns:
        dict[str, Any]: The matching field dict.
    """
    found = next((r for r in results if r["name"] == name), None)
    assert found is not None, f"field '{name}' not in {[r['name'] for r in results]}"
    return found


def _holds(interp: HexPatInterpreter, prelude: str, condition: str, data: bytes | None = None) -> bool:
    """Evaluate a pattern-language condition by placing a probe byte at one of two offsets.

    Args:
        interp: The interpreter used to run the pattern.
        prelude: Pattern source executed before the probe placement.
        condition: A pattern-language expression whose truthiness is observed.
        data: The leading bytes to evaluate against; the buffer is padded to 64 bytes.

    Returns:
        bool: True when the condition was truthy (probe placed at offset 3),
        False when it was falsy (probe placed at offset 5).
    """
    results = interp.execute_bytes(f"{prelude}\nu8 probe @ {condition} ? 3 : 5;", _padded(data))
    probe = _field(results, "probe")
    assert probe["offset"] in {3, 5}
    return bool(probe["offset"] == 3)


def _offset_of(interp: HexPatInterpreter, prelude: str, expression: str, data: bytes | None = None) -> int:
    """Evaluate an integer expression by placing a probe byte at the offset it yields.

    Args:
        interp: The interpreter used to run the pattern.
        prelude: Pattern source executed before the probe placement.
        expression: A pattern-language expression that yields an offset below 64.
        data: The leading bytes to evaluate against; the buffer is padded to 64 bytes.

    Returns:
        int: The offset at which the probe byte was placed.
    """
    results = interp.execute_bytes(f"{prelude}\nu8 probe @ {expression};", _padded(data))
    return int(_field(results, "probe")["offset"])


def _parse(source: str) -> list[DeclNode | StmtNode]:
    """Lex and parse pattern source without preprocessing.

    Args:
        source: The pattern source to parse.

    Returns:
        list[DeclNode | StmtNode]: The parsed top-level program.
    """
    return HexPatParser(HexPatLexer(source).tokenize()).parse()


def _evaluate_ast(program: list[DeclNode | StmtNode], data: bytes) -> list[dict[str, Any]]:
    """Evaluate a program with a default pragma and an empty type registry.

    Args:
        program: The top-level AST nodes to evaluate.
        data: The bytes the evaluator reads from.

    Returns:
        list[dict[str, Any]]: The parsed-field dicts produced by the evaluator.
    """
    evaluator = HexPatEvaluator(DataReader.from_bytes(data), TypeRegistry(), PragmaInfo())
    return evaluator.evaluate(program)


def _num(value: int) -> NumberLiteral:
    """Build an integer literal node.

    Args:
        value: The literal's value.

    Returns:
        NumberLiteral: The literal node.
    """
    return NumberLiteral(value=value, line=1, column=1)


def _text(value: str) -> StringLiteral:
    """Build a string literal node.

    Args:
        value: The literal's value.

    Returns:
        StringLiteral: The literal node.
    """
    return StringLiteral(value=value, line=1, column=1)


def _name(identifier: str) -> IdentifierExpr:
    """Build an identifier reference node.

    Args:
        identifier: The referenced name.

    Returns:
        IdentifierExpr: The identifier node.
    """
    return IdentifierExpr(name=identifier, line=1, column=1)


def _call(function: str, *arguments: ExprNode) -> FunctionCallExpr:
    """Build a call of a plain identifier with the given arguments.

    Args:
        function: The name of the callee identifier.
        *arguments: The argument expressions.

    Returns:
        FunctionCallExpr: The call node.
    """
    return FunctionCallExpr(callee=_name(function), arguments=arguments, line=1, column=1)


def _binary(op: str, left: ExprNode, right: ExprNode) -> BinaryExpr:
    """Build a binary expression node.

    Args:
        op: The operator string.
        left: The left operand.
        right: The right operand.

    Returns:
        BinaryExpr: The binary node.
    """
    return BinaryExpr(op=op, left=left, right=right, line=1, column=1)


def _prim(name: str) -> PrimitiveType:
    """Build a primitive type node.

    Args:
        name: The primitive type name.

    Returns:
        PrimitiveType: A primitive type node without an endianness override.
    """
    return PrimitiveType(name=name, endianness=None, line=1, column=1)


def _named(name: str, *template_args: ExprNode) -> NamedType:
    """Build an unqualified named type node.

    Args:
        name: The type name.
        *template_args: Template argument expressions.

    Returns:
        NamedType: The named type node.
    """
    return NamedType(name=name, namespace=None, line=1, column=1, template_args=template_args)


def _place(
    type_node: TypeNode,
    name: str,
    *,
    at_offset: ExprNode | None = None,
    array_size: ExprNode | None = None,
    while_condition: ExprNode | None = None,
) -> PlacementStmt:
    """Build a placement statement.

    Args:
        type_node: The type being placed.
        name: The placed variable name.
        at_offset: Optional explicit offset expression.
        array_size: Optional fixed array length expression.
        while_condition: Optional while-terminated array condition.

    Returns:
        PlacementStmt: The placement statement.
    """
    return PlacementStmt(
        type_node=type_node,
        name=name,
        at_offset=at_offset,
        annotations=(),
        in_section=None,
        array_size=array_size,
        while_condition=while_condition,
        is_pointer=False,
        line=1,
        column=1,
    )


def _branch(condition: ExprNode, name: str) -> PlacementStmt:
    """Build a byte placement at offset 3 when ``condition`` is truthy and at offset 5 otherwise.

    Args:
        condition: The condition expression observed.
        name: The placed variable name.

    Returns:
        PlacementStmt: The placement statement.
    """
    chooser = TernaryExpr(condition=condition, true_expr=_num(3), false_expr=_num(5), line=1, column=1)
    return _place(_prim("u8"), name, at_offset=chooser)


class TestSubscripts:
    """Array and string subscripts."""

    def test_struct_array_element_member_is_reachable(self, interp: HexPatInterpreter) -> None:
        """A subscripted struct element exposes that element's own members.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "struct Pair {\n    u8 key;\n    u8 val;\n};\nPair pairs[3] @ 0;"
        data = bytes([1, 2, 3, 4, 5, 6])
        assert _offset_of(interp, prelude, "pairs[1].val", data) == 4
        assert _offset_of(interp, prelude, "pairs[2].key", data) == 5

    def test_computed_index_selects_element(self, interp: HexPatInterpreter) -> None:
        """The index is an expression evaluated before the element lookup.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "u8 vals[4] @ 0;\nu32 i = 1;"
        assert _offset_of(interp, prelude, "vals[i + 2]", bytes([10, 11, 12, 13])) == 13

    def test_string_subscript_yields_character(self, interp: HexPatInterpreter) -> None:
        """Indexing a decoded string yields the one-character string at that position.

        Args:
            interp: A fresh interpreter.
        """
        data = b"hey\x00"
        assert _holds(interp, "str word @ 0;", 'word[0] == "h" && word[2] == "y"', data) is True
        assert _holds(interp, "str word @ 0;", 'word[1] == "h"', data) is False

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ("str word @ 0;\nu8 probe @ word[3];", "array index 3 out of range"),
            ("str word @ 0;\nu8 probe @ word[-1];", "array index -1 out of range"),
            ("u8 vals[2] @ 0;\nu8 probe @ vals[2];", "array index 2 out of range"),
            ("u8 vals[2] @ 0;\nu8 probe @ vals[1.5];", "array index must be an integer"),
            ('u8 vals[2] @ 0;\nu8 probe @ vals["a"];', "array index must be an integer"),
        ],
        ids=["string-past-end", "string-negative", "array-past-end", "float-index", "string-index"],
    )
    def test_bad_subscripts_raise_at_the_bracket(self, interp: HexPatInterpreter, source: str, message: str) -> None:
        """Out-of-range and non-integer indexes raise at the opening bracket.

        Args:
            interp: A fresh interpreter.
            source: Pattern source containing the bad subscript on line 2.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, _padded(b"hey\x00"))
        assert excinfo.value.message == message
        assert (excinfo.value.line, excinfo.value.column) == (2, 16)


class TestAssignments:
    """Assignment to the cursor, variables and struct members."""

    def test_cursor_moves_with_compound_assignment(self, interp: HexPatInterpreter) -> None:
        """``$ += n`` and ``$ -= n`` move the placement cursor forward and back.

        Args:
            interp: A fresh interpreter.
        """
        source = "$ += 4;\nu8 first;\n$ -= 2;\nu8 second;"
        results = interp.execute_bytes(source, bytes(range(16)))
        assert [(r["name"], r["offset"], r["raw_bytes"]) for r in results] == [("first", 4, [4]), ("second", 3, [3])]

    @pytest.mark.parametrize(
        ("operator", "initial", "operand", "expected"),
        [
            ("+=", 10, 3, 13),
            ("-=", 10, 3, 7),
            ("*=", 10, 3, 30),
            ("/=", 10, 3, 3),
            ("%=", 10, 3, 1),
            ("&=", 12, 10, 8),
            ("|=", 12, 10, 14),
            ("^=", 12, 10, 6),
            ("<<=", 3, 2, 12),
            (">>=", 12, 2, 3),
        ],
    )
    def test_compound_assignment_applies_the_base_operator(
        self,
        interp: HexPatInterpreter,
        operator: str,
        initial: int,
        operand: int,
        expected: int,
    ) -> None:
        """Each compound operator applies its base operator to the variable's current value.

        Args:
            interp: A fresh interpreter.
            operator: The compound assignment operator under test.
            initial: The variable's initial value.
            operand: The right-hand side.
            expected: The value the variable must hold afterwards.
        """
        prelude = f"u32 x = {initial};\nx {operator} {operand};"
        assert _offset_of(interp, prelude, "x") == expected

    def test_compound_assignment_on_floats_keeps_fractions(self, interp: HexPatInterpreter) -> None:
        """Float variables compound with true division, not integer division.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "float f = 1.5;\nf += 1;\nf /= 2;"
        assert _holds(interp, prelude, "f == 1.25") is True

    def test_assignment_to_unbound_name_defines_it(self, interp: HexPatInterpreter) -> None:
        """Assigning to a name that was never declared binds it in the current scope.

        Args:
            interp: A fresh interpreter.
        """
        assert _offset_of(interp, "fresh = 7;", "fresh") == 7

    def test_assignment_to_struct_member_updates_that_member(self, interp: HexPatInterpreter) -> None:
        """Plain and compound assignment through ``obj.member`` rewrite the placed member.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "struct Rec {\n    u8 a;\n    u8 b;\n};\nRec r @ 0;\nr.a = 9;\nr.b += 2;"
        assert _offset_of(interp, prelude, "r.a + r.b", bytes([4, 5])) == 9 + (5 + 2)

    def test_unsupported_assignment_target(self, interp: HexPatInterpreter) -> None:
        """Assigning to a subscript is rejected at the assignment operator.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("u8 vals[2] @ 0;\nvals[1] = 5;", bytes(8))
        assert excinfo.value.message == "unsupported assignment target"
        assert (excinfo.value.line, excinfo.value.column) == (2, 9)

    @pytest.mark.parametrize(
        ("source", "operator", "column"),
        [
            ('text = "a";\ntext += "b";', "+=", 6),
            ('u32 n = 5;\nn -= "x";', "-=", 3),
        ],
        ids=["string-target", "string-operand"],
    )
    def test_compound_assignment_rejects_non_numeric_operands(
        self,
        interp: HexPatInterpreter,
        source: str,
        operator: str,
        column: int,
    ) -> None:
        """Compound assignment needs numbers on both sides and reports the operator position.

        Args:
            interp: A fresh interpreter.
            source: Pattern source whose second line holds the bad compound assignment.
            operator: The compound operator named in the error message.
            column: The expected 1-based column of the operator on line 2.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(8))
        assert excinfo.value.message == f"compound assignment '{operator}' not supported for these types"
        assert (excinfo.value.line, excinfo.value.column) == (2, column)


class TestSizeof:
    """``sizeof`` over expressions, aliases, pointers and every composite kind."""

    def test_member_expression_reports_member_size(self, interp: HexPatInterpreter) -> None:
        """``sizeof`` of an expression measures the value the expression yields.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "struct Rec {\n    u8 a;\n    u16 b;\n};\nRec r @ 0;"
        assert _offset_of(interp, prelude, "sizeof(r.b)") == 2
        assert _offset_of(interp, prelude, "sizeof(r.a)") == 1

    @pytest.mark.parametrize(
        ("prelude", "expression", "expected"),
        [
            ("using Word = u16;", "sizeof(Word)", 2),
            ("using Word = u16;\nusing Wider = Word;", "sizeof(Wider)", 2),
            ("", "sizeof(*u8)", 8),
            ("#pragma pointer_size 4", "sizeof(*u8)", 4),
            ("", "sizeof(NoSuchType)", 0),
        ],
        ids=["alias", "alias-chain", "pointer", "pointer-pragma", "unknown-type"],
    )
    def test_alias_pointer_and_unknown_type_sizes(self, interp: HexPatInterpreter, prelude: str, expression: str, expected: int) -> None:
        """Aliases resolve to their primitive, pointers use the pragma size and unknown types measure zero.

        Args:
            interp: A fresh interpreter.
            prelude: Pattern source executed before the probe.
            expression: The ``sizeof`` expression under test.
            expected: The expected size in bytes.
        """
        assert _offset_of(interp, prelude, expression) == expected

    def test_struct_size_includes_parent_and_skips_locals(self, interp: HexPatInterpreter) -> None:
        """A derived struct adds the parent's size and local variables add nothing.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "struct Base {\n    u16 a;\n};\nstruct Child : Base {\n    u8 b;\n    u64 scratch = 0;\n};"
        assert _offset_of(interp, prelude, "sizeof(Child)") == 2 + 1

    @pytest.mark.parametrize(
        ("pragma", "expected"),
        [("", 3 * 2 + 8 + 1), ("#pragma pointer_size 4\n", 3 * 2 + 4 + 1)],
        ids=["default-pointer", "four-byte-pointer"],
    )
    def test_struct_size_counts_arrays_and_pointers(self, interp: HexPatInterpreter, pragma: str, expected: int) -> None:
        """Fixed arrays multiply the element size and pointer fields use the pointer size.

        Args:
            interp: A fresh interpreter.
            pragma: Optional pragma line placed before the declaration.
            expected: The expected size in bytes.
        """
        prelude = f"{pragma}struct Table {{\n    u16 entries[3];\n    u8 *link;\n    u8 tail;\n}};"
        assert _offset_of(interp, prelude, "sizeof(Table)") == expected

    @pytest.mark.parametrize(
        ("condition", "expected"),
        [("1", 1 + 4), ("0", 1 + 1), ("kind == 1", 1)],
        ids=["true-branch", "false-branch", "undetermined-contributes-zero"],
    )
    def test_struct_size_follows_static_conditions(self, interp: HexPatInterpreter, condition: str, expected: int) -> None:
        """Conditional fields count the statically selected branch, or nothing when the condition cannot be evaluated.

        Args:
            interp: A fresh interpreter.
            condition: The condition guarding the conditional field.
            expected: The expected size in bytes.
        """
        prelude = (
            f"struct Opt {{\n    u8 kind;\n    if ({condition}) {{\n        u32 wide;\n    }} else {{\n        u8 narrow;\n    }}\n}};"
        )
        assert _offset_of(interp, prelude, "sizeof(Opt)") == expected

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("u8 a;\n    u16 b[3];", 6),
            ("u8 a;\n    u64 skipped = 0;", 1),
            ("u8 a;\n    if (1) {\n        u32 wide;\n    }", 4),
            ("u8 a;\n    if (0) {\n        u32 wide;\n    } else {\n        u16 two;\n    }", 2),
            ("u8 a;\n    u8 *link;", 8),
        ],
        ids=["array-member", "local-variable-ignored", "true-conditional", "false-conditional", "pointer-member"],
    )
    def test_union_size_is_the_largest_member(self, interp: HexPatInterpreter, body: str, expected: int) -> None:
        """A union is as large as its largest alternative; local variables are not alternatives.

        Args:
            interp: A fresh interpreter.
            body: The union body source.
            expected: The expected size in bytes.
        """
        prelude = f"union Un {{\n    {body}\n}};"
        assert _offset_of(interp, prelude, "sizeof(Un)") == expected

    @pytest.mark.parametrize(
        ("declaration", "type_name", "expected"),
        [
            ("enum Kind : u16 {\n    A,\n    B\n};", "Kind", 2),
            ("bitfield Mixed {\n    low : 3;\n    high : 6;\n};", "Mixed", 2),
            ("bitfield Byte {\n    all : 8;\n};", "Byte", 1),
            ("bitfield Wide {\n    all : 17;\n};", "Wide", 3),
        ],
        ids=["enum-backing-size", "bitfield-nine-bits", "bitfield-eight-bits", "bitfield-seventeen-bits"],
    )
    def test_enum_and_bitfield_sizes(self, interp: HexPatInterpreter, declaration: str, type_name: str, expected: int) -> None:
        """Enums take their backing size and bitfields round their bit total up to whole bytes.

        Args:
            interp: A fresh interpreter.
            declaration: The enum or bitfield declaration source.
            type_name: The declared type measured by ``sizeof``.
            expected: The expected size in bytes.
        """
        assert _offset_of(interp, declaration, f"sizeof({type_name})") == expected

    def test_placement_statements_in_composite_bodies_are_sized(self) -> None:
        """Placements inside struct and union bodies contribute unless they carry an explicit offset."""
        holder = StructDecl(
            name="Holder",
            parent=None,
            body=(
                _place(_prim("u16"), "a"),
                _place(_prim("u8"), "b", array_size=_num(3)),
                _place(_prim("u8"), "c", while_condition=_num(0)),
                _place(_prim("u32"), "d", at_offset=_num(0)),
            ),
            annotations=(),
            line=1,
            column=1,
        )
        pick = UnionDecl(
            name="Pick",
            body=(
                _place(_prim("u16"), "x"),
                _place(_prim("u8"), "y", array_size=_num(4)),
                _place(_prim("u64"), "z", at_offset=_num(0)),
            ),
            annotations=(),
            line=1,
            column=1,
        )
        program: list[DeclNode | StmtNode] = [
            holder,
            pick,
            _place(_prim("u8"), "holder_probe", at_offset=SizeofExpr(target=_named("Holder"), line=1, column=1)),
            _place(_prim("u8"), "pick_probe", at_offset=SizeofExpr(target=_named("Pick"), line=1, column=1)),
        ]
        results = _evaluate_ast(program, bytes(16))
        assert [(r["name"], r["offset"]) for r in results] == [("holder_probe", 2 + 3), ("pick_probe", 4)]


class TestCasts:
    """Casts to integers, floats, enums, bitfields, aliases and pass-through targets."""

    @pytest.mark.parametrize(
        ("cast", "expected"),
        [
            ("(Small)(300)", 300 - 256),
            ("(Small)(-1)", 255),
            ("(Signed)(200)", 200 - 256),
            ("(Signed)(255)", -1),
            ("(Signed)(-129)", 127),
        ],
    )
    def test_enum_cast_wraps_to_backing_width(self, interp: HexPatInterpreter, cast: str, expected: int) -> None:
        """Casting to an enum coerces the value to the enum's backing primitive.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
            expected: The wrapped value of the backing type.
        """
        assert _holds(interp, _ENUMS, f"{cast} == {expected}") is True
        assert _holds(interp, _ENUMS, f"{cast} == {expected + 1}") is False

    @pytest.mark.parametrize(
        ("cast", "expected"),
        [
            ("(Nine)(0x12345)", "0x2345"),
            ("(Nine)(-1)", "0xFFFF"),
            ("(Nine)(2.9)", "2"),
            ("(Nine)(null)", "null"),
        ],
        ids=["wide-value-masked", "negative-masked", "float-truncated", "null-stays-null"],
    )
    def test_bitfield_cast_masks_to_declared_width(self, interp: HexPatInterpreter, cast: str, expected: str) -> None:
        """Casting to a nine-bit bitfield keeps the low two bytes it occupies.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
            expected: The expected result as pattern-language source.
        """
        assert _holds(interp, _NINE_BITS, f"{cast} == {expected}") is True

    @pytest.mark.parametrize("cast", ["(Rec)(7)", "(auto)(7)"], ids=["struct-target", "auto-target"])
    def test_struct_and_auto_casts_pass_value_through(self, interp: HexPatInterpreter, cast: str) -> None:
        """A cast to a struct or to ``auto`` leaves the value unchanged.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
        """
        assert _holds(interp, "struct Rec {\n    u8 a;\n};", f"{cast} == 7") is True

    def test_alias_cast_uses_aliased_primitive(self, interp: HexPatInterpreter) -> None:
        """A cast to an alias wraps to the aliased primitive's width and signedness.

        Args:
            interp: A fresh interpreter.
        """
        assert _offset_of(interp, "using Word = u16;", "(Word)(65540)") == 65540 - 65536
        assert _holds(interp, "using Delta = s8;", "(Delta)(200) == -56") is True

    @pytest.mark.parametrize(
        ("cast", "expected"),
        [
            ("(s16)(0xFFFF)", -1),
            ("(s32)(0x80000000)", -(2**31)),
            ("(s8)(127)", 127),
            ("(s8)(128)", -128),
            ("(s64)(0xFFFFFFFFFFFFFFFF)", -1),
        ],
    )
    def test_signed_cast_wraps_twos_complement(self, interp: HexPatInterpreter, cast: str, expected: int) -> None:
        """Signed casts reinterpret the low bits as two's complement.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
            expected: The expected signed value.
        """
        assert _holds(interp, "", f"{cast} == {expected}") is True

    @pytest.mark.parametrize(
        ("cast", "expected"),
        [
            ("(u16)(-1)", 0xFFFF),
            ("(u8)(2.9)", 2),
            ("(u8)(-2.9)", 254),
            ("(u32)(4294967297)", 1),
        ],
    )
    def test_unsigned_cast_wraps_and_truncates_floats_toward_zero(self, interp: HexPatInterpreter, cast: str, expected: int) -> None:
        """Unsigned casts keep the low bits and truncate floats toward zero.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
            expected: The expected unsigned value.
        """
        assert _holds(interp, "", f"{cast} == {expected}") is True

    @pytest.mark.parametrize(
        "condition",
        [
            'std::core::formatted_value((u8)(true)) == "0x1"',
            'std::core::formatted_value((s8)(true)) == "1"',
            'std::core::formatted_value((float)(true)) == "1"',
        ],
        ids=["unsigned", "signed", "float"],
    )
    def test_bool_cast_becomes_a_number(self, interp: HexPatInterpreter, condition: str) -> None:
        """Casting ``true`` to a numeric type yields the number one, not a boolean.

        Args:
            interp: A fresh interpreter.
            condition: The formatted-value comparison that must hold.
        """
        assert _holds(interp, "", condition) is True

    @pytest.mark.parametrize(
        ("prelude", "condition"),
        [
            ("char c @ 0;", "(u8)(c) == 0x41"),
            ("", '(u16)("AB") == 65'),
        ],
        ids=["placed-char", "string-literal"],
    )
    def test_character_cast_uses_first_character_code(self, interp: HexPatInterpreter, prelude: str, condition: str) -> None:
        """Casting a character or string to an integer yields the code of its first character.

        Args:
            interp: A fresh interpreter.
            prelude: Pattern source executed before the probe.
            condition: The comparison that must hold.
        """
        assert _holds(interp, prelude, condition, b"A") is True

    @pytest.mark.parametrize("cast", ["(u8)(null)", "(s16)(null)"])
    def test_null_cast_stays_null(self, interp: HexPatInterpreter, cast: str) -> None:
        """Casting null to an integer type leaves it null.

        Args:
            interp: A fresh interpreter.
            cast: The cast expression under test.
        """
        assert _holds(interp, "", f"{cast} == null") is True

    @pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf], ids=["nan", "positive-infinity", "negative-infinity"])
    def test_non_finite_float_cast_is_rejected(self, interp: HexPatInterpreter, value: float) -> None:
        """Casting NaN or an infinity to an integer type is a runtime error at the cast.

        Args:
            interp: A fresh interpreter.
            value: The non-finite float stored in the data.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("float f @ 0;\nu8 probe @ (u32)(f);", _padded(struct.pack("<f", value)))
        assert excinfo.value.message == "cannot convert non-finite float to integer type 'u32'"
        assert (excinfo.value.line, excinfo.value.column) == (2, 12)


class TestTemplates:
    """Generic struct instantiation and template-argument binding."""

    def test_cast_inside_template_follows_bound_alias(self, interp: HexPatInterpreter) -> None:
        """A cast to a template parameter wraps to the primitive the argument names.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "using Word = u16;\nstruct Box<T> {\n    T val;\n    u32 narrowed = (T)(65540);\n};\nBox<Word> b @ 0;\nu8 probe @ b.narrowed;"
        )
        results = interp.execute_bytes(source, _padded(bytes([0x34, 0x12])))
        box = _field(results, "b")
        assert [(c["name"], c["size"], c["display_value"]) for c in box["children"]] == [("val", 2, "0x1234")]
        assert _field(results, "probe")["offset"] == 65540 - 65536

    def test_primitive_template_argument_binds_as_a_primitive_type(self) -> None:
        """A primitive-name template argument is bound as a primitive type node."""
        declaration = _parse("struct Box<T> {\n    T val;\n    u32 narrowed = (T)(300);\n};")
        instance = _place(_named("Box", _name("u8")), "b")
        probe = _place(
            _prim("u8"),
            "probe",
            at_offset=MemberAccessExpr(object_expr=_name("b"), member="narrowed", line=1, column=1),
        )
        results = _evaluate_ast([*declaration, instance, probe], bytes([0x7B]) + bytes(63))
        box = _field(results, "b")
        assert (box["size"], [(c["name"], c["size"], c["display_value"]) for c in box["children"]]) == (1, [("val", 1, "0x7B")])
        assert _field(results, "probe")["offset"] == 300 - 256

    def test_non_type_template_argument_is_accepted(self, interp: HexPatInterpreter) -> None:
        """A numeric template argument does not stop the generic struct from being placed.

        Args:
            interp: A fresh interpreter.
        """
        source = "struct Phantom<auto N> {\n    u8 a;\n};\nPhantom<4> p @ 0;"
        phantom = _field(interp.execute_bytes(source, bytes([0x21]) + bytes(7)), "p")
        assert (phantom["display_value"], phantom["size"]) == ("Phantom", 1)
        assert [(c["name"], c["display_value"]) for c in phantom["children"]] == [("a", "0x21")]

    def test_value_template_parameter_sizes_an_array(self, interp: HexPatInterpreter) -> None:
        """A numeric template argument is visible to the struct body as its parameter name.

        Args:
            interp: A fresh interpreter.
        """
        source = "struct Fixed<auto N> {\n    u8 data[N];\n};\nFixed<4> f @ 0;"
        fixed = _field(interp.execute_bytes(source, bytes([1, 2, 3, 4, 5, 6, 7, 8])), "f")
        assert fixed["size"] == 4
        assert [c["raw_bytes"] for c in fixed["children"][0]["children"]] == [[1], [2], [3], [4]]

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ("enum Kind : u8 {\n    A\n};\nKind<Other> k @ 0;", "template type 'Kind' takes 0 parameters but 1 were supplied"),
            ("struct One<T> {\n    u8 a;\n};\nOne<A, B> o @ 0;", "template type 'One' takes 1 parameter but 2 were supplied"),
            ("struct Two<A, B> {\n    u8 a;\n};\nTwo<X> t @ 0;", "template type 'Two' takes 2 parameters but 1 were supplied"),
        ],
        ids=["non-generic-type", "singular-parameter", "plural-parameters"],
    )
    def test_template_argument_count_mismatch_is_a_type_error(self, interp: HexPatInterpreter, source: str, message: str) -> None:
        """Supplying the wrong number of template arguments raises at the type reference.

        Args:
            interp: A fresh interpreter.
            source: Pattern source whose last line instantiates the type wrongly.
            message: The expected error message.
        """
        with pytest.raises(HexPatTypeError) as excinfo:
            interp.execute_bytes(source, bytes(8))
        assert excinfo.value.message == message
        assert (excinfo.value.line, excinfo.value.column) == (source.count("\n") + 1, 1)

    def test_qualified_template_type_falls_back_to_bare_name(self, interp: HexPatInterpreter) -> None:
        """A qualified generic type that is not registered under its path resolves through its bare name.

        Args:
            interp: A fresh interpreter.
        """
        source = "struct Box<T> {\n    T val;\n};\nusing Word = u16;\nnowhere::Box<Word> b @ 0;"
        box = _field(interp.execute_bytes(source, _padded(bytes([0x34, 0x12]))), "b")
        assert (box["display_value"], box["size"]) == ("Box", 2)
        assert [(c["name"], c["offset"], c["display_value"]) for c in box["children"]] == [("val", 0, "0x1234")]

    def test_unknown_qualified_template_type_is_an_error(self, interp: HexPatInterpreter) -> None:
        """A qualified generic type that exists nowhere is reported with its full qualified name.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatTypeError) as excinfo:
            interp.execute_bytes("ns::Mystery<Other> x @ 0;", bytes(8))
        assert excinfo.value.message == "unknown type 'ns::Mystery'"
        assert (excinfo.value.line, excinfo.value.column) == (1, 1)


class TestAnnotations:
    """Description extraction from placement annotations."""

    @pytest.mark.parametrize(
        ("annotations", "expected"),
        [
            ('hidden, comment("note")', "note"),
            ('tag(7), comment("fmt")', "fmt"),
            ('comment(5), comment("later")', "later"),
            ("comment(5)", ""),
        ],
        ids=["valueless-first", "other-annotation-first", "non-string-comment-skipped", "only-non-string-comment"],
    )
    def test_description_is_the_first_string_comment(self, interp: HexPatInterpreter, annotations: str, expected: str) -> None:
        """Only a ``comment`` annotation whose value is a string supplies the description.

        Args:
            interp: A fresh interpreter.
            annotations: The annotation list placed after the offset.
            expected: The expected description.
        """
        results = interp.execute_bytes(f"u8 a @ 0 [[{annotations}]];", bytes(4))
        assert _field(results, "a")["description"] == expected


class TestBuiltinFunctions:
    """The built-in functions the evaluator registers ahead of the standard library."""

    def test_sizeof_and_addressof_describe_a_placed_value(self) -> None:
        """The plain-callee ``sizeof`` and ``addressof`` report a value's size and offset, or zero without arguments."""
        program: list[DeclNode | StmtNode] = [
            _place(_prim("u32"), "x", at_offset=_num(8)),
            _place(_prim("u8"), "size_probe", at_offset=_call("sizeof", _name("x"))),
            _place(_prim("u8"), "address_probe", at_offset=_call("addressof", _name("x"))),
            _place(_prim("u8"), "bare_size", at_offset=_binary("+", _num(5), _call("sizeof"))),
            _place(_prim("u8"), "bare_address", at_offset=_binary("+", _num(7), _call("addressof"))),
        ]
        results = _evaluate_ast(program, bytes(32))
        assert {r["name"]: r["offset"] for r in results} == {
            "x": 8,
            "size_probe": 4,
            "address_probe": 8,
            "bare_size": 5,
            "bare_address": 7,
        }

    def test_typenameof_reports_the_type_name_or_unknown(self) -> None:
        """The plain-callee ``typenameof`` names a cast's primitive type and falls back to ``unknown``."""
        cast_u16 = CastExpr(target_type=_prim("u16"), expr=_num(5), line=1, column=1)
        cast_s8 = CastExpr(target_type=_prim("s8"), expr=_num(5), line=1, column=1)
        program: list[DeclNode | StmtNode] = [
            _branch(_binary("==", _call("typenameof", cast_u16), _text("u16")), "typed"),
            _branch(_binary("==", _call("typenameof", cast_s8), _text("u16")), "mismatch"),
            _branch(_binary("==", _call("typenameof", _num(5)), _text("unknown")), "untyped"),
            _branch(_binary("==", _call("typenameof"), _text("unknown")), "bare"),
        ]
        results = _evaluate_ast(program, bytes(16))
        assert {r["name"]: r["offset"] for r in results} == {"typed": 3, "mismatch": 5, "untyped": 3, "bare": 3}

    @pytest.mark.parametrize(
        ("statement", "message"),
        [
            ("assert(0);", "assertion failed"),
            ('assert(1 == 2, "boom");', "boom"),
            ("assert(0, null);", "assertion failed"),
            ("assert(0, 42);", "42"),
        ],
        ids=["default-message", "custom-message", "null-message", "numeric-message"],
    )
    def test_failed_assert_raises_with_its_message(self, interp: HexPatInterpreter, statement: str, message: str) -> None:
        """A falsy assertion aborts evaluation with the supplied message or the default.

        Args:
            interp: A fresh interpreter.
            statement: The assertion statement under test.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(statement, bytes(8))
        assert excinfo.value.message == message

    def test_passing_assert_yields_null(self, interp: HexPatInterpreter) -> None:
        """A truthy assertion, or one without arguments, evaluates to null.

        Args:
            interp: A fresh interpreter.
        """
        assert _holds(interp, "", "assert(1) == null && assert() == null") is True

    @pytest.mark.parametrize(
        "condition",
        [
            "read_unsigned(2, 2) == 0x1234",
            "read_unsigned(2) == 0",
            'read_unsigned("x", 2) == 0',
            "read_unsigned(2, 1.5) == 0",
            "read_signed(4, 2) == -2",
            "read_signed(0, 1) == -86",
            "read_signed(4) == 0",
            'read_signed("x", 2) == 0',
            'read_signed(4, "x") == 0',
        ],
    )
    def test_read_builtins_decode_little_endian_integers(self, interp: HexPatInterpreter, condition: str) -> None:
        """``read_unsigned`` and ``read_signed`` decode little-endian bytes and answer zero for bad arguments.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold over the fixed data.
        """
        assert _holds(interp, "", condition, _READ_DATA) is True

    @pytest.mark.parametrize(
        "condition",
        ['read_string(2) == "hi"', 'read_string() == ""', 'read_string("x") == ""'],
        ids=["decodes-string", "no-argument", "non-integer-offset"],
    )
    def test_read_string_decodes_until_nul(self, interp: HexPatInterpreter, condition: str) -> None:
        """``read_string`` decodes a NUL-terminated string and answers an empty string for bad arguments.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold over the fixed data.
        """
        assert _holds(interp, "", condition, _STRING_DATA) is True

    @pytest.mark.parametrize(
        "condition",
        [
            'find_sequence(0, "ab") == 2',
            'find_sequence(3, "ab") == 6',
            'find_sequence(7, "ab") == -1',
            "find_sequence(0) == -1",
            "find_sequence(0, 5) == -1",
            'find_sequence("x", "ab") == -1',
        ],
        ids=["first-match", "start-after-first", "no-later-match", "missing-sequence", "integer-sequence", "string-offset"],
    )
    def test_find_sequence_reports_absolute_offsets(self, interp: HexPatInterpreter, condition: str) -> None:
        """``find_sequence`` returns the absolute offset of a match, or -1 when none or the arguments are invalid.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold over the fixed data.
        """
        assert _holds(interp, "", condition, _SEARCH_DATA) is True

    @pytest.mark.parametrize(
        "condition",
        [
            "min(7, 3, 9) == 3",
            "min(2.5, 4) == 2.5",
            'min("x", 5, null) == 5',
            "min() == 0",
            'min("x") == 0',
            "max(3, 9, 4) == 9",
            "max(-2, -7) == -2",
            "max(1.5, 1) == 1.5",
            'max("z", 8) == 8',
            "max() == 0",
            "max(null) == 0",
        ],
    )
    def test_min_and_max_consider_only_numbers(self, interp: HexPatInterpreter, condition: str) -> None:
        """``min`` and ``max`` pick among numeric arguments and answer zero when there are none.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold.
        """
        assert _holds(interp, "", condition) is True

    @pytest.mark.parametrize(
        "condition",
        ["abs(-5) == 5", "abs(5) == 5", "abs(-2.5) == 2.5", 'abs("x") == 0', "abs() == 0"],
    )
    def test_abs_takes_the_magnitude_of_a_number(self, interp: HexPatInterpreter, condition: str) -> None:
        """``abs`` returns the magnitude of an integer or float and zero for anything else.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold.
        """
        assert _holds(interp, "", condition) is True

    @pytest.mark.parametrize(
        "condition",
        ['strlen("hello") == 5', 'strlen("") == 0', "strlen(5) == 0", "strlen() == 0"],
    )
    def test_strlen_measures_strings_only(self, interp: HexPatInterpreter, condition: str) -> None:
        """``strlen`` counts the characters of a string and answers zero for non-strings.

        Args:
            interp: A fresh interpreter.
            condition: The comparison that must hold.
        """
        assert _holds(interp, "", condition) is True


class TestValueSemantics:
    """Truthiness and match-arm equality."""

    @pytest.mark.parametrize(
        ("condition", "expected"),
        [
            ("null", False),
            ("0.0", False),
            ("2.5", True),
            ('""', False),
            ('"x"', True),
        ],
        ids=["null", "zero-float", "float", "empty-string", "string"],
    )
    def test_truthiness_of_non_integer_values(self, interp: HexPatInterpreter, condition: str, *, expected: bool) -> None:
        """Null, zero floats and empty strings are falsy; other floats and strings are truthy.

        Args:
            interp: A fresh interpreter.
            condition: The literal used as the ternary condition.
            expected: Whether the condition is expected to be truthy.
        """
        assert _holds(interp, "", condition) is expected

    def test_match_compares_null_and_bool_subjects(self, interp: HexPatInterpreter) -> None:
        """Null matches only null and a boolean matches an equal boolean pattern.

        Args:
            interp: A fresh interpreter.
        """
        prelude = (
            "u32 hit = 0;\n"
            "match (null) {\n    null: { hit = hit + 1; }\n}\n"
            "match (true) {\n    true: { hit = hit + 2; }\n}\n"
            "match (null) {\n    0: { hit = hit + 8; }\n    _: { hit = hit + 4; }\n}"
        )
        assert _offset_of(interp, prelude, "hit") == 1 + 2 + 4

    def test_match_compares_strings_and_rejects_mixed_types(self, interp: HexPatInterpreter) -> None:
        """Strings match equal strings and never match a number.

        Args:
            interp: A fresh interpreter.
        """
        prelude = (
            "u32 hit = 0;\n"
            'match ("ab") {\n    "cd": { hit = hit + 1; }\n    "ab": { hit = hit + 2; }\n}\n'
            'match (5) {\n    "5": { hit = hit + 4; }\n    _: { hit = hit + 8; }\n}'
        )
        assert _offset_of(interp, prelude, "hit") == 2 + 8
