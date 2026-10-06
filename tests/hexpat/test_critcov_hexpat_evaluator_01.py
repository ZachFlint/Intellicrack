# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the HexPat evaluator.

Drives the real preprocessor, lexer, parser and evaluator with small pattern
sources over byte buffers built in the tests. Expected values are computed
independently from those bytes (``struct``, ``int.from_bytes``) or from the
pattern-language rules, and cover namespaces, ``using`` aliases, the
``std::core`` reflection hooks, struct-body control flow, while-sized arrays,
pointer fields, wide and signed primitives and the evaluator's error paths.
Constructs the parser cannot emit are exercised with real AST nodes handed to
the public ``HexPatEvaluator.evaluate`` entry point.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.hexpat.ast_nodes import (
    ArrayType,
    NamedType,
    PlacementStmt,
    PointerType,
    PrimitiveType,
    StructDecl,
)
from intellicrack.core.hexpat.data_reader import DataReader
from intellicrack.core.hexpat.errors import HexPatRuntimeError, HexPatTypeError
from intellicrack.core.hexpat.evaluator import HexPatEvaluator, PatternValue
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.hexpat.preprocessor import HexPatPreprocessor
from intellicrack.core.hexpat.stdlib import BuiltinFunctions
from intellicrack.core.hexpat.type_system import HexPatType, TypeRegistry


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.hexpat.ast_nodes import DeclNode, StmtNode, TypeNode
    from intellicrack.core.hexpat.interpreter import HexPatInterpreter


_ANNOTATED_TYPES: str = (
    "[[first(1), tag(11)]]\n"
    "struct Hdr { u8 a; };\n"
    "[[tag(12)]]\n"
    "union Un { u8 a; };\n"
    "[[tag(13), flag]]\n"
    "enum Color : u8 { Red = 1, Green = 2 };\n"
    "[[tag(14)]]\n"
    "bitfield Flags { low : 4; high : 4; };\n"
)


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
        data: The bytes to evaluate against; 64 zero bytes when omitted.

    Returns:
        bool: True when the condition was truthy (probe placed at offset 3),
        False when it was falsy (probe placed at offset 5).
    """
    payload = data if data is not None else bytes(64)
    results = interp.execute_bytes(f"{prelude}\nu8 probe @ {condition} ? 3 : 5;", payload)
    probe = _field(results, "probe")
    assert probe["offset"] in {3, 5}
    return bool(probe["offset"] == 3)


def _build(source: str, data: bytes) -> tuple[HexPatEvaluator, list[DeclNode | StmtNode]]:
    """Build an evaluator wired to the standard library exactly as the interpreter wires it.

    Args:
        source: The pattern source to preprocess, lex and parse.
        data: The bytes the evaluator reads from.

    Returns:
        tuple[HexPatEvaluator, list[DeclNode | StmtNode]]: The evaluator and the
        parsed program it has not yet evaluated.
    """
    processed, pragma = HexPatPreprocessor().process(source)
    program = HexPatParser(HexPatLexer(processed).tokenize()).parse()
    reader = DataReader.from_bytes(data)
    evaluator = HexPatEvaluator(reader, TypeRegistry(), pragma)
    stdlib = BuiltinFunctions(reader, pragma)
    stdlib.set_array_index_provider(evaluator.current_array_index)
    stdlib.set_endian_listener(evaluator.set_default_endian)
    stdlib.set_reflection_provider(evaluator.reflection_provider())
    stdlib.register_all(evaluator.scope)
    return evaluator, program


def _evaluate_ast(program: list[DeclNode | StmtNode], data: bytes) -> list[dict[str, Any]]:
    """Evaluate a hand-built AST with a default pragma and an empty type registry.

    Args:
        program: The top-level AST nodes to evaluate.
        data: The bytes the evaluator reads from.

    Returns:
        list[dict[str, Any]]: The parsed-field dicts produced by the evaluator.
    """
    evaluator = HexPatEvaluator(DataReader.from_bytes(data), TypeRegistry(), PragmaInfo())
    return evaluator.evaluate(program)


def _primitive(name: str, line: int = 1, column: int = 1) -> PrimitiveType:
    """Build a primitive type node.

    Args:
        name: The primitive type name.
        line: Source line recorded on the node.
        column: Source column recorded on the node.

    Returns:
        PrimitiveType: A primitive type node without an endianness override.
    """
    return PrimitiveType(name=name, endianness=None, line=line, column=column)


def _placement(type_node: TypeNode, name: str) -> PlacementStmt:
    """Build a plain placement statement with no explicit offset, array or annotations.

    Args:
        type_node: The type being placed.
        name: The placed variable name.

    Returns:
        PlacementStmt: A placement statement at the current cursor.
    """
    return PlacementStmt(
        type_node=type_node,
        name=name,
        at_offset=None,
        annotations=(),
        in_section=None,
        array_size=None,
        while_condition=None,
        is_pointer=False,
        line=1,
        column=1,
    )


def _typed(name: str, value: int = 0) -> PatternValue:
    """Build a pattern value whose type info names a registered user type.

    Args:
        name: The type name recorded on the pattern's type info.
        value: The integer value carried by the pattern.

    Returns:
        PatternValue: A pattern value referencing ``name`` through its type info.
    """
    return PatternValue(value=value, type_info=HexPatType(name=name, size=1, signed=False, endian=None))


@dataclass(frozen=True)
class _StoragePointer(PointerType):
    """A real pointer type node carrying the optional ``storage_type`` hint the evaluator honors.

    Attributes:
        storage_type: Name of the primitive used to decode the pointer address.
    """

    storage_type: str = "u16"


class TestWideAndSignedPrimitives:
    """Decode 128-bit, signed and non-finite primitives against independent decodes."""

    def test_u128_decodes_both_byte_orders(self, interp: HexPatInterpreter) -> None:
        """A u128 placement matches ``int.from_bytes`` in little and big endian.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes(range(1, 17)) + bytes(16)
        little_value = int.from_bytes(data[:16], "little")
        big_value = int.from_bytes(data[:16], "big")
        results = interp.execute_bytes("u128 little_value @ 0;\nbe u128 big_value @ 0;", data)
        little = _field(results, "little_value")
        big = _field(results, "big_value")
        assert little["size"] == 16
        assert little["raw_bytes"] == list(data[:16])
        assert little["display_value"] == f"0x{little_value:X}"
        assert big["display_value"] == f"0x{big_value:X}"
        assert little_value != big_value

    def test_signed_primitives_use_twos_complement(self, interp: HexPatInterpreter) -> None:
        """s16, s64 and s128 placements decode negative values as signed decimals.

        Args:
            interp: A fresh interpreter.
        """
        data = (
            struct.pack("<h", -2)
            + bytes(6)
            + struct.pack("<q", -300)
            + (-5).to_bytes(16, "little", signed=True)
            + struct.pack(">h", -2)
            + bytes(30)
        )
        source = "s16 a @ 0;\ns64 b @ 8;\ns128 c @ 16;\nbe s16 d @ 32;"
        results = interp.execute_bytes(source, data)
        assert [(r["name"], r["size"], r["display_value"]) for r in results] == [
            ("a", 2, "-2"),
            ("b", 8, "-300"),
            ("c", 16, "-5"),
            ("d", 2, "-2"),
        ]

    def test_float_specials_render_as_names(self, interp: HexPatInterpreter) -> None:
        """NaN and both infinities render as ``NaN``, ``+Inf`` and ``-Inf``.

        Args:
            interp: A fresh interpreter.
        """
        data = struct.pack("<fff", math.nan, math.inf, -math.inf)
        results = interp.execute_bytes("float a @ 0;\nfloat b @ 4;\nfloat c @ 8;", data)
        assert [r["display_value"] for r in results] == ["NaN", "+Inf", "-Inf"]

    def test_placement_without_offset_follows_cursor(self, interp: HexPatInterpreter) -> None:
        """Placements without ``@`` start where the previous placement ended.

        Args:
            interp: A fresh interpreter.
        """
        results = interp.execute_bytes("u8 first;\nu16 second;\nu8 third;", bytes([1, 2, 3, 4, 5, 6]))
        assert [(r["name"], r["offset"], r["size"]) for r in results] == [
            ("first", 0, 1),
            ("second", 1, 2),
            ("third", 3, 1),
        ]
        assert _field(results, "second")["display_value"] == f"0x{struct.unpack_from('<H', bytes([2, 3]))[0]:X}"


class TestTypeAliases:
    """``using`` aliases to primitives and named types."""

    def test_primitive_alias_field_layout(self, interp: HexPatInterpreter) -> None:
        """A field typed through a primitive alias reads the aliased width.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes([0x34, 0x12, 0x07]) + bytes(8)
        word = _field(interp.execute_bytes("using Word = u16;\nWord w @ 0;", data), "w")
        assert word["size"] == 2
        assert word["raw_bytes"] == [0x34, 0x12]
        assert word["display_value"] == f"0x{struct.unpack_from('<H', data)[0]:X}"

    def test_named_alias_to_struct(self, interp: HexPatInterpreter) -> None:
        """An alias to an unqualified struct name instantiates that struct.

        Args:
            interp: A fresh interpreter.
        """
        source = "struct Rec { u8 k; u8 m; };\nusing Same = Rec;\nSame r @ 0;"
        rec = _field(interp.execute_bytes(source, bytes([9, 8]) + bytes(6)), "r")
        assert rec["display_value"] == "Rec"
        assert rec["size"] == 2
        assert [(c["name"], c["display_value"]) for c in rec["children"]] == [("k", "0x9"), ("m", "0x8")]

    def test_primitive_alias_binds_decoded_value(self, interp: HexPatInterpreter) -> None:
        """A variable placed through a primitive alias holds the decoded number.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes([0x34, 0x12]) + bytes(14)
        assert _holds(interp, "using Word = u16;\nWord w @ 0;", "w == 0x1234", data) is True

    def test_str_alias_consumes_string_length(self, interp: HexPatInterpreter) -> None:
        """A string placed through a ``str`` alias consumes the same bytes as a direct ``str``.

        Args:
            interp: A fresh interpreter.
        """
        data = b"abc\x00" + bytes(12)
        results = interp.execute_bytes("using Text = str;\nText t @ 0;\nstr direct @ 0;", data)
        direct = _field(results, "direct")
        aliased = _field(results, "t")
        assert direct["size"] == len(b"abc\x00")
        assert direct["display_value"] == "abc"
        assert aliased["size"] == direct["size"]
        assert aliased["display_value"] == direct["display_value"]


class TestNamespaces:
    """Namespace declarations, qualified type names and qualified expressions."""

    def test_namespace_declares_alias_struct_enum_and_function(self, interp: HexPatInterpreter) -> None:
        """Members of a namespace resolve through ``ns::`` in types and calls.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "namespace net {\n"
            "    using Port = u16;\n"
            "    struct Hdr {\n"
            "        Port port;\n"
            "        u8 flags;\n"
            "    }\n"
            "    enum Kind : u8 {\n"
            "        First = 1,\n"
            "        Second\n"
            "    }\n"
            "    fn doubled(u32 x) {\n"
            "        return x * 2;\n"
            "    }\n"
            "}\n"
            "net::Hdr h @ 0;\n"
            "net::Port pp @ 0;\n"
            "net::Kind k @ 2;\n"
            "u8 probe @ net::doubled(3);\n"
        )
        data = bytes([0x34, 0x12, 0x02]) + bytes(61)
        results = interp.execute_bytes(source, data)
        header = _field(results, "h")
        assert header["size"] == 3
        assert [(c["name"], c["offset"], c["display_value"]) for c in header["children"]] == [
            ("port", 0, "0x1234"),
            ("flags", 2, "0x2"),
        ]
        port = _field(results, "pp")
        assert (port["size"], port["display_value"]) == (2, "0x1234")
        kind = _field(results, "k")
        assert (kind["offset"], kind["size"], kind["display_value"]) == (2, 1, "Second (0x2)")
        assert _field(results, "probe")["offset"] == 3 * 2

    def test_nested_namespaces_and_qualified_aliases(self, interp: HexPatInterpreter) -> None:
        """Nested namespaces expose their types, aliases and functions through full paths.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "namespace outer {\n"
            "    namespace inner {\n"
            "        struct Leaf {\n"
            "            u8 a;\n"
            "            u8 b;\n"
            "        }\n"
            "        using Pair = u8[2];\n"
            "        fn answer() {\n"
            "            return 41;\n"
            "        }\n"
            "    }\n"
            "    using Alias = outer::inner::Leaf;\n"
            "}\n"
            "outer::Alias x @ 0;\n"
            "Alias y @ 2;\n"
            "outer::inner::Pair p @ 4;\n"
            "u8 probe @ outer::inner::answer();\n"
        )
        data = bytes([3, 4, 5, 6, 7, 8]) + bytes(58)
        results = interp.execute_bytes(source, data)
        for name, first, second in (("x", 3, 4), ("y", 5, 6)):
            leaf = _field(results, name)
            assert leaf["display_value"] == "Leaf"
            assert leaf["size"] == 2
            assert [(c["name"], c["display_value"]) for c in leaf["children"]] == [("a", f"0x{first:X}"), ("b", f"0x{second:X}")]
        pair = _field(results, "p")
        assert pair["size"] == 2
        assert [c["raw_bytes"] for c in pair["children"]] == [[7], [8]]
        assert _field(results, "probe")["offset"] == 41

    def test_unknown_qualifier_falls_back_to_unqualified_name(self, interp: HexPatInterpreter) -> None:
        """A qualified type name that is not registered resolves through its bare name.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "namespace shapes {\n"
            "    using Pair = u8[2];\n"
            "}\n"
            "struct Plain {\n"
            "    u8 a;\n"
            "    u8 b;\n"
            "};\n"
            "shapes::Pair p @ 0;\n"
            "other::Pair q @ 2;\n"
            "ghost::Plain z @ 4;\n"
        )
        results = interp.execute_bytes(source, bytes([1, 2, 3, 4, 5, 6]) + bytes(10))
        assert [c["raw_bytes"] for c in _field(results, "p")["children"]] == [[1], [2]]
        assert [c["raw_bytes"] for c in _field(results, "q")["children"]] == [[3], [4]]
        plain = _field(results, "z")
        assert plain["display_value"] == "Plain"
        assert [(c["name"], c["offset"]) for c in plain["children"]] == [("a", 4), ("b", 5)]

    def test_string_valued_namespace_resolves_qualified_scope_entry(self, interp: HexPatInterpreter) -> None:
        """A string-valued namespace expression looks up ``<value>::<member>`` in scope.

        Args:
            interp: A fresh interpreter.
        """
        prelude = 'fn pick() {\n    return "std::mem";\n}'
        assert _holds(interp, prelude, "pick()::size() == 64") is True
        assert _holds(interp, prelude, "pick()::size() == 63") is False

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ("namespace ns {\n    fn f() {\n        return 1;\n    }\n}\nu8 p @ ns::missing;", "namespace has no member 'missing'"),
            ("struct S { u8 a; };\nS s @ 0;\nu8 p @ s.a::zzz;", "namespace has no member 'zzz'"),
        ],
        ids=["string-valued-namespace", "integer-valued-namespace"],
    )
    def test_missing_namespace_member_is_an_error(self, interp: HexPatInterpreter, source: str, message: str) -> None:
        """Looking up a member that does not exist raises a runtime error.

        Args:
            interp: A fresh interpreter.
            source: Pattern source containing the bad lookup.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == message

    def test_enum_errors_in_declarations(self, interp: HexPatInterpreter) -> None:
        """An unresolvable enum backing type and a non-integer entry value are type errors.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatTypeError) as backing:
            interp.execute_bytes("enum Bad : Unknown { A };", bytes(4))
        assert backing.value.message == "enum 'Bad': cannot resolve backing type"
        assert (backing.value.line, backing.value.column) == (1, 1)
        with pytest.raises(HexPatTypeError) as value:
            interp.execute_bytes('enum Odd : u8 { A = "x" };', bytes(4))
        assert value.value.message == "enum 'Odd' entry 'A': value must be integer"
        assert (value.value.line, value.value.column) == (1, 17)


class TestReflectionBuiltins:
    """The ``std::core`` reflection hooks wired by the evaluator."""

    def test_plain_values_carry_no_attributes_or_members(self, interp: HexPatInterpreter) -> None:
        """Scalars and casts expose no annotations or members.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "u8 v @ 0;"
        assert _holds(interp, prelude, 'std::core::has_attribute(v, "anything")') is False
        assert _holds(interp, prelude, 'std::core::has_attribute((u8)(5), "anything")') is False
        assert _holds(interp, prelude, "std::core::member_count(v) == 0") is True
        assert _holds(interp, prelude, 'std::core::has_member(v, "x")') is False

    @pytest.mark.parametrize(
        ("prelude", "condition"),
        [
            ("", 'std::core::formatted_value((s8)(200)) == "-56"'),
            ("", 'std::core::formatted_value((u8)(300)) == "0x2C"'),
            ("", 'std::core::formatted_value(null) == "null"'),
            ("", 'std::core::formatted_value(print) == "<function>"'),
            ("fn noop() {\n    return;\n}", 'std::core::formatted_value(noop) == "<function>"'),
        ],
        ids=["signed-cast", "unsigned-cast", "null", "builtin-function", "user-function"],
    )
    def test_formatted_value_follows_type_info(self, interp: HexPatInterpreter, prelude: str, condition: str) -> None:
        """``formatted_value`` renders signed, unsigned, null and function values.

        Args:
            interp: A fresh interpreter.
            prelude: Pattern source executed before the probe.
            condition: The comparison that must hold.
        """
        assert _holds(interp, prelude, condition) is True

    def test_custom_palette_drives_field_colors(self, interp: HexPatInterpreter) -> None:
        """An installed palette rotates through placements and masks entries to 32 bits.

        Args:
            interp: A fresh interpreter.
        """
        source = "std::core::set_pattern_palette_colors(0x1AABBCCDD, 0x11223344);\nu8 a @ 0;\nu8 b @ 1;\nu8 c @ 2;"
        results = interp.execute_bytes(source, bytes(8))
        assert [r["color"] for r in results] == ["#AABBCCDD", "#11223344", "#AABBCCDD"]

    def test_empty_palette_call_keeps_installed_palette(self, interp: HexPatInterpreter) -> None:
        """Installing an empty palette leaves the current palette untouched.

        Args:
            interp: A fresh interpreter.
        """
        source = "std::core::set_pattern_palette_colors(0x11223344);\nstd::core::set_pattern_palette_colors();\nu8 a @ 0;"
        assert interp.execute_bytes(source, bytes(8))[0]["color"] == "#11223344"

    def test_reset_palette_restores_default_rotation(self, interp: HexPatInterpreter) -> None:
        """Resetting the palette restarts the default colors from the first entry.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes(8)
        default_first = interp.execute_bytes("u8 a @ 0;", data)[0]["color"]
        source = "std::core::set_pattern_palette_colors(0x11223344);\nu8 a @ 0;\nstd::core::reset_pattern_palette();\nu8 b @ 1;"
        results = interp.execute_bytes(source, data)
        assert results[0]["color"] == "#11223344"
        assert results[1]["color"] == default_first
        assert default_first != "#11223344"

    def test_setters_record_overrides_on_the_pattern(self) -> None:
        """Color, display-name and comment setters store overrides keyed by the pattern."""
        source = 'u8 v @ 0;\nstd::core::set_pattern_color(v, 0x11223344);\nstd::core::set_display_name(v, "renamed");\nstd::core::set_pattern_comment(v, "note");'
        evaluator, program = _build(source, bytes(8))
        evaluator.evaluate(program)
        pattern = evaluator.scope.get("v")
        assert pattern is not None
        overrides: dict[int, dict[str, object]] = getattr(evaluator, "_reflection_overrides")
        assert overrides == {id(pattern): {"color": 0x11223344, "display_name": "renamed", "comment": "note"}}

    def test_execute_function_calls_user_function_by_name(self, interp: HexPatInterpreter) -> None:
        """``execute_function`` dispatches to a declared function with forwarded arguments.

        Args:
            interp: A fresh interpreter.
        """
        source = 'fn twice(u32 x) {\n    return x * 2;\n}\nu8 p @ std::core::execute_function("twice", 4);'
        assert _field(interp.execute_bytes(source, bytes(16)), "p")["offset"] == 8

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ('std::core::execute_function("nope");', "std::core::execute_function: undefined function 'nope'"),
            ('u8 v @ 0;\nstd::core::execute_function("v");', "std::core::execute_function: 'v' is not a callable function"),
        ],
        ids=["undefined", "not-callable"],
    )
    def test_execute_function_rejects_bad_targets(self, interp: HexPatInterpreter, source: str, message: str) -> None:
        """Unknown names and non-function values are runtime errors.

        Args:
            interp: A fresh interpreter.
            source: Pattern source containing the bad call.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == message

    def test_has_attribute_sees_struct_annotation_on_placed_variable(self, interp: HexPatInterpreter) -> None:
        """A placed struct variable reflects the annotations of its declared type.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "[[tag(5)]]\nstruct Tagged {\n    u8 a;\n};\nTagged t @ 0;"
        assert _holds(interp, prelude, 'std::core::has_attribute(t, "tag")') is True
        assert _holds(interp, prelude, 'std::core::get_attribute_argument(t, "tag", 0) == 5') is True

    def test_is_valid_enum_on_placed_enum_field(self, interp: HexPatInterpreter) -> None:
        """A placed enum field is valid exactly when its value is a declared member.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "enum Color : u8 {\n    Red = 1,\n    Green = 2\n};\nColor good @ 0;\nColor bad @ 1;"
        data = bytes([2, 7]) + bytes(14)
        assert _holds(interp, prelude, "std::core::is_valid_enum(good) && !std::core::is_valid_enum(bad)", data) is True


class TestReflectionProvider:
    """The evaluator's reflection provider driven directly with type-named pattern values."""

    @pytest.mark.parametrize(
        ("type_name", "expected"),
        [("Hdr", 11), ("Un", 12), ("Color", 13), ("Flags", 14)],
        ids=["struct", "union", "enum", "bitfield"],
    )
    def test_annotations_resolve_for_every_user_type_kind(self, type_name: str, expected: int) -> None:
        """Struct, union, enum and bitfield annotations are found and evaluated.

        Args:
            type_name: The registered type the pattern value names.
            expected: The numeric argument of that type's ``tag`` annotation.
        """
        evaluator, program = _build(_ANNOTATED_TYPES, bytes(8))
        evaluator.evaluate(program)
        provider = evaluator.reflection_provider()
        assert provider.has_attribute(_typed(type_name), "tag") is True
        assert provider.has_attribute(_typed(type_name), "absent") is False
        assert provider.get_attribute_argument(_typed(type_name), "tag", 0).value == expected

    def test_later_annotation_is_found_after_earlier_ones(self) -> None:
        """Annotation lookup skips non-matching entries before the requested one."""
        evaluator, program = _build(_ANNOTATED_TYPES, bytes(8))
        evaluator.evaluate(program)
        provider = evaluator.reflection_provider()
        assert provider.get_attribute_argument(_typed("Hdr"), "first", 0).value == 1

    @pytest.mark.parametrize(
        ("type_name", "attribute", "index", "message"),
        [
            ("Color", "flag", 0, "std::core::get_attribute_argument: 'flag' has no value"),
            ("Hdr", "tag", 1, "std::core::get_attribute_argument: index 1 out of range"),
            ("Hdr", "nothere", 0, "std::core::get_attribute_argument: attribute 'nothere' not found"),
            ("u8", "tag", 0, "std::core::get_attribute_argument: attribute 'tag' not found"),
        ],
        ids=["no-value", "bad-index", "missing", "primitive-type"],
    )
    def test_get_attribute_argument_errors(self, type_name: str, attribute: str, index: int, message: str) -> None:
        """Bad attribute lookups raise runtime errors naming the problem.

        Args:
            type_name: The registered type the pattern value names.
            attribute: The annotation name requested.
            index: The argument index requested.
            message: The expected error message.
        """
        evaluator, program = _build(_ANNOTATED_TYPES, bytes(8))
        evaluator.evaluate(program)
        with pytest.raises(HexPatRuntimeError) as excinfo:
            evaluator.reflection_provider().get_attribute_argument(_typed(type_name), attribute, index)
        assert excinfo.value.message == message

    def test_is_valid_enum_checks_declared_members(self) -> None:
        """Only integer values that equal a declared member of the named enum are valid."""
        evaluator, program = _build(_ANNOTATED_TYPES, bytes(8))
        evaluator.evaluate(program)
        provider = evaluator.reflection_provider()
        assert provider.is_valid_enum(_typed("Color", 2)) is True
        assert provider.is_valid_enum(_typed("Color", 3)) is False
        assert (
            provider.is_valid_enum(PatternValue(value="Green", type_info=HexPatType(name="Color", size=1, signed=False, endian=None)))
            is False
        )
        assert provider.is_valid_enum(_typed("Hdr", 1)) is False
        assert provider.is_valid_enum(PatternValue(value=2)) is False

    def test_member_helpers_count_structural_members(self) -> None:
        """Member count and membership follow the pattern's members mapping."""
        evaluator, _ = _build("", bytes(8))
        provider = evaluator.reflection_provider()
        holder = PatternValue(value=None, members={"a": PatternValue(value=1), "b": PatternValue(value=2)})
        assert provider.member_count(holder) == 2
        assert provider.has_member(holder, "a") is True
        assert provider.has_member(holder, "zz") is False
        assert provider.member_count(PatternValue(value=1)) == 0

    def test_formatted_value_renders_bytes_as_hex(self) -> None:
        """A bytes-valued pattern formats as its lowercase hex digits."""
        evaluator, _ = _build("", bytes(8))
        assert evaluator.reflection_provider().formatted_value(PatternValue(value=b"\x01\xab\xff")) == "01abff"


class TestEndianAndDirectOperators:
    """Default-endian updates and defensive operator checks."""

    def test_set_default_endian_ignores_unknown_values(self) -> None:
        """Only ``little`` and ``big`` change the default byte order."""
        data = bytes([0x34, 0x12]) + bytes(6)
        kept, kept_program = _build("u16 v @ 0;", data)
        kept.set_default_endian("middle")
        assert _field(kept.evaluate(kept_program), "v")["display_value"] == f"0x{struct.unpack_from('<H', data)[0]:X}"
        changed, changed_program = _build("u16 v @ 0;", data)
        changed.set_default_endian("big")
        assert _field(changed.evaluate(changed_program), "v")["display_value"] == f"0x{struct.unpack_from('>H', data)[0]:X}"

    def test_numeric_operator_table_rejects_unknown_operator(self) -> None:
        """An operator outside the table raises a runtime error carrying its position."""
        apply_op: Callable[[str, float, float, int, int], int | float | bool] = getattr(HexPatEvaluator, "_apply_numeric_op")
        with pytest.raises(HexPatRuntimeError) as excinfo:
            apply_op("**", 2, 3, 7, 9)
        assert excinfo.value.message == "unsupported operator '**' for numeric types"
        assert (excinfo.value.line, excinfo.value.column) == (7, 9)

    def test_builtin_results_are_boxed_or_rejected(self) -> None:
        """Host scalars box into pattern values, pattern values pass through, other types fail."""
        box: Callable[[object], PatternValue] = getattr(HexPatEvaluator, "_box_builtin_result")
        existing = PatternValue(value=1)
        assert box(existing) is existing
        assert box(5).value == 5
        with pytest.raises(HexPatRuntimeError) as excinfo:
            box([1, 2])
        assert excinfo.value.message == "builtin returned unsupported value type: list"


class TestExpressions:
    """Expression evaluation: operators, null handling, subscripts and introspection."""

    @pytest.mark.parametrize(
        "condition",
        [
            '"ab" + "cd" == "abcd"',
            '"ab" == "ab"',
            '"ab" != "cd"',
            "null == null",
            "5 != null",
            "3 ^^ 0",
        ],
    )
    def test_string_null_and_logical_xor_conditions_hold(self, interp: HexPatInterpreter, condition: str) -> None:
        """String, null and logical-xor operators yield true where the language says they do.

        Args:
            interp: A fresh interpreter.
            condition: An expression that must be truthy.
        """
        assert _holds(interp, "", condition) is True

    @pytest.mark.parametrize(
        "condition",
        [
            '"ab" == "cd"',
            '"ab" != "ab"',
            "null != null",
            "5 == null",
            "3 ^^ 4",
            "0 ^^ 0",
        ],
    )
    def test_string_null_and_logical_xor_conditions_fail(self, interp: HexPatInterpreter, condition: str) -> None:
        """String, null and logical-xor operators yield false where the language says they do.

        Args:
            interp: A fresh interpreter.
            condition: An expression that must be falsy.
        """
        assert _holds(interp, "", condition) is False

    @pytest.mark.parametrize(
        ("source", "message", "column"),
        [
            ("u8 p @ null < 1;", "operator '<' not supported for these types", 13),
            ('u8 p @ "a" * "b";', "operator '*' not supported for these types", 12),
            ('u8 p @ "a" < "b";', "operator '<' not supported for these types", 12),
        ],
        ids=["null-less-than", "string-multiply", "string-less-than"],
    )
    def test_unsupported_binary_operands_raise(self, interp: HexPatInterpreter, source: str, message: str, column: int) -> None:
        """Operators that do not apply to the operand types raise at the operator position.

        Args:
            interp: A fresh interpreter.
            source: Pattern source containing the bad expression.
            message: The expected error message.
            column: The expected 1-based column of the operator.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == message
        assert (excinfo.value.line, excinfo.value.column) == (1, column)

    @pytest.mark.parametrize(
        ("source", "operator"),
        [('u8 p @ -"abc";', "-"), ("u8 p @ ~1.5;", "~")],
        ids=["negate-string", "invert-float"],
    )
    def test_unsupported_unary_operands_raise(self, interp: HexPatInterpreter, source: str, operator: str) -> None:
        """Unary operators reject operand types they do not apply to.

        Args:
            interp: A fresh interpreter.
            source: Pattern source containing the bad expression.
            operator: The operator named in the error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == f"unsupported unary operator '{operator}'"
        assert (excinfo.value.line, excinfo.value.column) == (1, 8)

    def test_undefined_variable_raises_at_identifier(self, interp: HexPatInterpreter) -> None:
        """An unknown identifier raises with its source position.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("u8 p @ nope;", bytes(16))
        assert excinfo.value.message == "undefined variable 'nope'"
        assert (excinfo.value.line, excinfo.value.column) == (1, 8)

    def test_calling_a_non_function_raises(self, interp: HexPatInterpreter) -> None:
        """Calling a plain variable raises at the call position.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("u8 v @ 0;\nu8 p @ v();", bytes(16))
        assert excinfo.value.message == "callee is not callable"
        assert (excinfo.value.line, excinfo.value.column) == (2, 9)

    def test_missing_struct_member_raises_at_member_access(self, interp: HexPatInterpreter) -> None:
        """Reading a member a struct does not have raises at the dot.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes("struct S { u8 a; };\nS s @ 0;\nu8 p @ s.nothing;", bytes(16))
        assert excinfo.value.message == "object has no member 'nothing'"
        assert (excinfo.value.line, excinfo.value.column) == (3, 9)

    def test_typenameof_and_addressof(self, interp: HexPatInterpreter) -> None:
        """``typenameof`` reports cast types and ``addressof`` reports placement offsets.

        Args:
            interp: A fresh interpreter.
        """
        prelude = "struct S { u8 a; u16 b; };\nu8 v @ 5;\nS s @ 8;"
        assert _holds(interp, prelude, 'typenameof((u16)(5)) == "u16" && typenameof(v) == "unknown"') is True
        assert _holds(interp, prelude, "addressof(v) == 5 && addressof(s.b) == 9") is True

    def test_while_sized_array_stops_at_condition_and_supports_subscripts(self, interp: HexPatInterpreter) -> None:
        """A while-sized array ends where its condition fails and exposes its elements.

        Args:
            interp: A fresh interpreter.
        """
        data = b"abc\x00zz" + bytes(10)
        prelude = "u8 chars[while(std::mem::read_unsigned(std::core::array_index(), 1) != 0)] @ 0;"
        chars = _field(interp.execute_bytes(prelude, data), "chars")
        assert chars["size"] == 3
        assert chars["display_value"] == "[3]"
        assert [c["raw_bytes"] for c in chars["children"]] == [[ord("a")], [ord("b")], [ord("c")]]
        assert _holds(interp, prelude, f"chars[2] == {ord('c')}", data) is True

    def test_nested_array_alias_elements_are_addressable(self, interp: HexPatInterpreter) -> None:
        """Elements of an array of aliased arrays are reachable with chained subscripts.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes([10, 20, 30, 40]) + bytes(12)
        prelude = "using Row = u8[2];\nRow grid[2] @ 0;"
        assert _holds(interp, prelude, "grid[1][0] == 30 && grid[0][1] == 20", data) is True

    def test_plain_alias_array_field_inside_struct(self, interp: HexPatInterpreter) -> None:
        """A struct field typed through an array alias exposes its elements.

        Args:
            interp: A fresh interpreter.
        """
        data = bytes([10, 20]) + bytes(14)
        prelude = "using Pair = u8[2];\nstruct Holder {\n    Pair q;\n};\nHolder h @ 0;"
        assert _holds(interp, prelude, "h.q[1] == 20", data) is True


class TestFunctionCalls:
    """User-function arity, defaults and bare returns."""

    def test_default_missing_and_bare_return_values(self, interp: HexPatInterpreter) -> None:
        """Defaults fill omitted parameters, missing ones are null and ``return;`` yields null.

        Args:
            interp: A fresh interpreter.
        """
        prelude = (
            "fn pick(u32 a, u32 b = 5) {\n    return a + b;\n}\n"
            "fn lonely(u32 a, u32 b) {\n    return b;\n}\n"
            "fn nothing() {\n    return;\n}\n"
            "u8 with_default @ pick(1);"
        )
        results = interp.execute_bytes(prelude, bytes(16))
        assert _field(results, "with_default")["offset"] == 1 + 5
        assert _holds(interp, prelude, "lonely(4) == null") is True
        assert _holds(interp, prelude, "nothing() == null") is True

    @pytest.mark.parametrize(
        ("declaration", "call", "message"),
        [
            ("fn pick(u32 a, u32 b = 5) {\n    return a + b;\n}", "pick(1, 2, 3)", "function 'pick' takes 2 arguments but 3 were given"),
            ("fn solo(u32 a) {\n    return a;\n}", "solo(1, 2)", "function 'solo' takes 1 argument but 2 were given"),
            ("fn none() {\n    return 0;\n}", "none(1)", "function 'none' takes 0 arguments but 1 were given"),
        ],
        ids=["plural", "singular", "zero"],
    )
    def test_too_many_arguments_raise(self, interp: HexPatInterpreter, declaration: str, call: str, message: str) -> None:
        """Passing more arguments than parameters raises at the declaration.

        Args:
            interp: A fresh interpreter.
            declaration: The function declaration source.
            call: The offending call expression.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(f"{declaration}\nu8 x @ {call};", bytes(16))
        assert excinfo.value.message == message
        assert (excinfo.value.line, excinfo.value.column) == (1, 1)


class TestStructBodyControlFlow:
    """Statements, loops and control-flow signals evaluated inside struct bodies."""

    def test_struct_body_runs_variables_loops_match_and_try(self, interp: HexPatInterpreter) -> None:
        """Local variables, while, for, match, try/catch and expression statements all run in a struct body.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "struct Calc {\n"
            "    u8 n;\n"
            "    u32 i = 0;\n"
            "    u32 total = 0;\n"
            "    while (i < n) {\n"
            "        total = total + 2;\n"
            "        i = i + 1;\n"
            "    }\n"
            "    for (u32 j = 0; j < 3; j = j + 1) {\n"
            "        total = total + 100;\n"
            "    }\n"
            "    match (n) {\n"
            "        3: { total = total + 1000; }\n"
            "        _: { total = total + 5; }\n"
            "    }\n"
            "    try {\n"
            "        total = total + missing_variable;\n"
            "    } catch {\n"
            "        total = total + 10000;\n"
            "    }\n"
            "    total = total + 7;\n"
            "};\n"
            "Calc c @ 0;\n"
        )
        data = bytes([3]) + bytes(63)
        expected_total = 3 * 2 + 3 * 100 + 1000 + 10000 + 7
        assert _holds(interp, source, f"c.total == {expected_total}", data) is True
        assert _field(interp.execute_bytes(source, data), "c")["size"] == 1

    def test_for_loop_forms_without_init_condition_or_update(self, interp: HexPatInterpreter) -> None:
        """For loops accept missing init, condition and update clauses and still terminate.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "u32 total = 0;\n"
            "for (; total < 3; total = total + 1) { }\n"
            "for (u32 a = 0;; a = a + 1) {\n"
            "    if (a == 4) { break; }\n"
            "    total = total + 10;\n"
            "}\n"
            "for (u32 m = 0; m < 2;) {\n"
            "    m = m + 1;\n"
            "    total = total + 100;\n"
            "}\n"
        )
        assert _holds(interp, source, f"total == {3 + 4 * 10 + 2 * 100}") is True

    def test_break_and_continue_in_struct_body_reach_the_enclosing_loop(self, interp: HexPatInterpreter) -> None:
        """``continue`` skips one placement and ``break`` ends the loop that placed the struct.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "struct Item {\n"
            "    u8 v;\n"
            "    if (v == 0) {\n"
            "        continue;\n"
            "    }\n"
            "    if (v == 9) {\n"
            "        break;\n"
            "    }\n"
            "};\n"
            "u32 i = 0;\n"
            "u32 placed = 0;\n"
            "while (i < 4) {\n"
            "    i = i + 1;\n"
            "    Item it @ i - 1;\n"
            "    placed = placed + 1;\n"
            "}\n"
            "u8 probe @ placed;\n"
        )
        results = interp.execute_bytes(source, bytes([1, 0, 2, 9, 5]) + bytes(11))
        assert [(r["name"], r["offset"]) for r in results] == [("it", 0), ("it", 2), ("probe", 2)]

    def test_return_in_struct_body_returns_from_the_calling_function(self, interp: HexPatInterpreter) -> None:
        """A ``return`` inside a struct body ends the function that placed the struct.

        Args:
            interp: A fresh interpreter.
        """
        prelude = (
            "struct Early {\n    u8 v;\n    return v + 1;\n};\n"
            "struct Quit {\n    u8 v;\n    return;\n};\n"
            "fn via_value() {\n    Early e @ 0;\n    return 99;\n}\n"
            "fn via_null() {\n    Quit q @ 0;\n    return 99;\n}\n"
            "u8 value_probe @ via_value();"
        )
        data = bytes([5]) + bytes(63)
        assert _field(interp.execute_bytes(prelude, data), "value_probe")["offset"] == 5 + 1
        assert _holds(interp, prelude, "via_null() == null", data) is True

    def test_auto_fields_consume_nothing(self, interp: HexPatInterpreter) -> None:
        """``auto`` declarations place nothing wherever they appear.

        Args:
            interp: A fresh interpreter.
        """
        source = (
            "struct S {\n    u8 a;\n    auto skipped;\n    u8 b;\n};\n"
            "S s @ 0;\n"
            "auto top_auto @ 0;\n"
            "auto many[3] @ 0;\n"
            "auto grow[while(1)] @ 0;\n"
            "if (1) {\n    auto from_if;\n}\n"
            "u8 after @ 3;\n"
        )
        results = interp.execute_bytes(source, bytes([1, 2, 3, 4]) + bytes(4))
        assert [(r["name"], r["size"]) for r in results] == [("s", 2), ("many", 0), ("grow", 0), ("after", 1)]
        assert [c["name"] for c in _field(results, "s")["children"]] == ["a", "b"]
        assert _field(results, "many")["display_value"] == "[0]"


class TestPointerFields:
    """Pointer fields declared inside struct bodies."""

    def test_pointer_fields_dereference_and_bind_address(self, interp: HexPatInterpreter) -> None:
        """Struct pointer fields read their address, dereference the pointee and bind the address.

        Args:
            interp: A fresh interpreter.
        """
        data = bytearray(0x40)
        struct.pack_into("<Q", data, 0, 0x30)
        struct.pack_into("<Q", data, 0x10, 0x31)
        data[8] = 0x77
        data[0x30] = 0xAB
        data[0x31] = 0xCD
        source = (
            "struct Ref {\n    u8 *p;\n    u8 *q @ 0x10;\n    u8 tail;\n};\n"
            "Ref r @ 0;\n"
            'u8 probe @ r.p == 48 && typenameof(r.p) == "u64" ? 3 : 5;\n'
        )
        results = interp.execute_bytes(source, bytes(data))
        ref = _field(results, "r")
        assert ref["size"] == 9
        first, second, tail = ref["children"]
        assert (first["name"], first["offset"], first["size"], first["display_value"]) == ("p", 0, 8, "*0x30")
        assert (first["children"][0]["name"], first["children"][0]["offset"], first["children"][0]["raw_bytes"]) == ("*p", 0x30, [0xAB])
        assert (second["name"], second["offset"], second["display_value"]) == ("q", 0x10, "*0x31")
        assert second["children"][0]["raw_bytes"] == [0xCD]
        assert (tail["name"], tail["offset"], tail["display_value"]) == ("tail", 8, "0x77")
        assert _field(results, "probe")["offset"] == 3

    def test_pointer_size_pragma_and_big_endian_field(self, interp: HexPatInterpreter) -> None:
        """A four-byte big-endian pointer field decodes its address in the requested order.

        Args:
            interp: A fresh interpreter.
        """
        data = bytearray(0x20)
        struct.pack_into(">I", data, 0, 0x10)
        data[0x10] = 0x5A
        source = "#pragma pointer_size 4\nstruct Ref {\n    be u8 *p;\n};\nRef r @ 0;"
        ref = _field(interp.execute_bytes(source, bytes(data)), "r")
        pointer = ref["children"][0]
        assert (ref["size"], pointer["size"], pointer["display_value"]) == (4, 4, "*0x10")
        assert (pointer["children"][0]["offset"], pointer["children"][0]["raw_bytes"]) == (0x10, [0x5A])


class TestStructAndArrayLimits:
    """Depth and element limits plus array fields with explicit offsets."""

    def test_union_nesting_beyond_eval_depth_is_rejected(self, interp: HexPatInterpreter) -> None:
        """Instantiating a union inside a union exceeds ``eval_depth 1``.

        Args:
            interp: A fresh interpreter.
        """
        source = "#pragma eval_depth 1\nunion Inner { u8 a; };\nunion Outer { Inner i @ 3; };\nOuter o @ 0;"
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == "maximum evaluation depth 1 exceeded (at data offset 0x3)"

    @pytest.mark.parametrize(
        ("source", "message"),
        [
            ("#pragma array_limit 3\nu8 forever[while(1)] @ 0;", "array limit 3 exceeded (at data offset 0x3)"),
            ("#pragma array_limit 2\nu8 big[5] @ 0;", "array limit 2 exceeded (at data offset 0x2)"),
        ],
        ids=["while-array", "sized-array"],
    )
    def test_array_limit_is_enforced(self, interp: HexPatInterpreter, source: str, message: str) -> None:
        """Arrays longer than the pragma limit raise at the first excess element.

        Args:
            interp: A fresh interpreter.
            source: Pattern source with an array limit and an oversized array.
            message: The expected error message.
        """
        with pytest.raises(HexPatRuntimeError) as excinfo:
            interp.execute_bytes(source, bytes(16))
        assert excinfo.value.message == message

    def test_array_field_with_explicit_offset_does_not_advance_cursor(self, interp: HexPatInterpreter) -> None:
        """A struct array field placed with ``@`` leaves the cursor where it was.

        Args:
            interp: A fresh interpreter.
        """
        source = "struct S {\n    u8 arr[2] @ 8;\n    u8 after;\n};\nS s @ 0;"
        data = bytes([0x11]) + bytes(7) + bytes([0xA1, 0xA2]) + bytes(6)
        record = _field(interp.execute_bytes(source, data), "s")
        arr, after = record["children"]
        assert [c["raw_bytes"] for c in arr["children"]] == [[0xA1], [0xA2]]
        assert (arr["offset"], after["offset"], after["raw_bytes"]) == (8, 0, [0x11])


class TestTypeResolutionErrors:
    """Unknown type names and invalid bitfield definitions."""

    def test_unknown_type_suggests_similar_builtins(self, interp: HexPatInterpreter) -> None:
        """An unknown type name that resembles a builtin lists the suggestion.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatTypeError) as excinfo:
            interp.execute_bytes("flo x @ 0;", bytes(8))
        assert excinfo.value.message == "unknown type 'flo' (did you mean one of: float?)"
        assert (excinfo.value.line, excinfo.value.column) == (1, 1)

    def test_unknown_template_type_has_no_suggestions(self, interp: HexPatInterpreter) -> None:
        """An unknown templated type reports the plain unknown-type message.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatTypeError) as excinfo:
            interp.execute_bytes("Mystery<Other> x @ 0;", bytes(8))
        assert excinfo.value.message == "unknown type 'Mystery'"

    def test_bitfield_width_must_be_integer(self, interp: HexPatInterpreter) -> None:
        """A non-integer bitfield width is a type error at the entry.

        Args:
            interp: A fresh interpreter.
        """
        with pytest.raises(HexPatTypeError) as excinfo:
            interp.execute_bytes('bitfield Bad { a : "wide"; };\nBad b @ 0;', bytes(8))
        assert excinfo.value.message == "bitfield 'Bad' entry 'a': width must be integer"
        assert (excinfo.value.line, excinfo.value.column) == (1, 16)

    @pytest.mark.parametrize(
        ("header", "first", "second"),
        [
            ('#pragma bitfield_order left_to_right\n[[bitfield_order("sideways")]]', "0x5 (3 bits)", "0xA (5 bits)"),
            ('[[comment("c"), bitfield_order("left_to_right")]]', "0x5 (3 bits)", "0xA (5 bits)"),
            ("[[bitfield_order]]", "0x2 (3 bits)", "0x15 (5 bits)"),
        ],
        ids=["invalid-value-uses-pragma", "later-annotation-wins", "valueless-annotation-ignored"],
    )
    def test_bitfield_order_annotation_resolution(self, interp: HexPatInterpreter, header: str, first: str, second: str) -> None:
        """Only a valid ``bitfield_order`` value overrides the pragma or the default order.

        Args:
            interp: A fresh interpreter.
            header: Pragma and annotation lines placed before the bitfield.
            first: The expected display of the first entry for byte 0xAA.
            second: The expected display of the second entry for byte 0xAA.
        """
        source = f"{header}\nbitfield F {{ first : 3; second : 5; }};\nF f @ 0;"
        children = _field(interp.execute_bytes(source, bytes([0xAA]) + bytes(8)), "f")["children"]
        assert [c["display_value"] for c in children] == [first, second]


class TestHandBuiltAst:
    """AST shapes the parser cannot emit, evaluated through the public evaluator entry point."""

    def test_unknown_primitive_name_is_a_type_error(self) -> None:
        """A primitive node with an unregistered name raises at the node position."""
        program: list[DeclNode | StmtNode] = [_placement(_primitive("u7", line=3, column=5), "x")]
        with pytest.raises(HexPatTypeError) as excinfo:
            _evaluate_ast(program, bytes(8))
        assert excinfo.value.message == "unknown primitive type 'u7'"
        assert (excinfo.value.line, excinfo.value.column) == (3, 5)

    def test_padding_primitive_cannot_be_read(self) -> None:
        """A primitive node naming the sizeless ``padding`` type cannot be decoded."""
        program: list[DeclNode | StmtNode] = [_placement(_primitive("padding"), "x")]
        with pytest.raises(HexPatTypeError) as excinfo:
            _evaluate_ast(program, bytes(8))
        assert excinfo.value.message == "unrecognised primitive type 'padding'"

    def test_array_without_size_or_condition_has_no_elements(self) -> None:
        """An array node with neither a size nor a while condition places zero elements."""
        array = ArrayType(element=_primitive("u8"), size=None, while_condition=None, line=1, column=1)
        program: list[DeclNode | StmtNode] = [_placement(array, "empty")]
        (result,) = _evaluate_ast(program, bytes(8))
        assert (result["name"], result["size"], result["display_value"], result["children"]) == ("empty", 0, "[0]", [])

    def test_placement_in_struct_body_becomes_a_child(self) -> None:
        """A placement statement inside a struct body is collected as a child, not a top-level result."""
        holder = StructDecl(
            name="Holder",
            parent=None,
            body=(_placement(_primitive("u8"), "inner"),),
            annotations=(),
            line=1,
            column=1,
        )
        named = NamedType(name="Holder", namespace=None, line=1, column=1)
        program: list[DeclNode | StmtNode] = [holder, _placement(named, "h")]
        data = bytes([0x42]) + bytes(7)
        results = _evaluate_ast(program, data)
        assert [r["name"] for r in results] == ["h"]
        (child,) = results[0]["children"]
        assert (child["name"], child["offset"], child["raw_bytes"]) == ("inner", 0, [0x42])
        assert results[0]["size"] == 1

    @pytest.mark.parametrize(
        ("storage", "pointer_size"),
        [("u16", 2), ("no_such_primitive", 8)],
        ids=["explicit-storage", "unresolvable-storage-uses-pointer-size"],
    )
    def test_pointer_storage_hint(self, storage: str, pointer_size: int) -> None:
        """A pointer's storage hint selects the address width, falling back to the pointer size.

        Args:
            storage: The primitive named by the pointer node's storage hint.
            pointer_size: The expected storage width in bytes.
        """
        data = struct.pack("<Q", 0x18) + bytes(16) + bytes([0xEE]) + bytes(7)
        pointer = _StoragePointer(pointee=_primitive("u8"), line=1, column=1, storage_type=storage)
        program: list[DeclNode | StmtNode] = [_placement(pointer, "ptr")]
        (result,) = _evaluate_ast(program, data)
        assert (result["size"], result["display_value"]) == (pointer_size, "*0x18")
        (pointee,) = result["children"]
        assert (pointee["offset"], pointee["raw_bytes"]) == (0x18, [0xEE])
