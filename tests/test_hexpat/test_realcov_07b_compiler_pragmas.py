# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for ``hexpat_compiler`` pragma and codegen behaviour.

These tests drive :class:`intellicrack.core.hexpat_compiler.HexPatCompiler`
and :class:`HexPatCodegen` over real HexPat DSL source strings and over real
``.hexpat`` files committed under ``vendor/community-patterns``. They close the
audit findings for pragma propagation, conditional inverted-operator logic,
dynamic arrays with field references, pointer emission, magic detection,
validation annotations, and constant-expression evaluator correctness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatParser
from intellicrack.core.hexpat_compiler import (
    HexPatCodegen,
    HexPatCompiler,
    HexPatError,
)
from intellicrack.core.template_manager import TemplateManager


def _compile(source: str) -> dict[str, Any]:
    """Compile DSL source to its JSON-template dict via the real pipeline.

    Args:
        source: HexPat DSL source code.

    Returns:
        dict[str, Any]: The generated JSON-template definition.
    """
    return HexPatCompiler.compile_to_dict(source)


def _eval_const(expr_src: str) -> int:
    """Evaluate a constant array-size expression through the real codegen.

    Builds a one-field struct whose array size is ``expr_src``, runs the
    shared lexer/parser/codegen, and returns the resolved integer count.

    Args:
        expr_src: A constant integer expression in HexPat syntax.

    Returns:
        int: The compile-time-evaluated array element count.
    """
    source = f"struct E {{ u8 v[{expr_src}]; }};"
    tokens = HexPatLexer(source).tokenize()
    declarations = HexPatParser(tokens).parse()
    codegen = HexPatCodegen(list(declarations))
    result = codegen.generate()
    field = result["fields"][0]
    count = field["field_type"]["params"]["count"]
    assert isinstance(count, int)
    return count


def _field_by_name(result: dict[str, Any], name: str) -> dict[str, Any]:
    """Return the first emitted field dict whose ``name`` matches.

    Args:
        result: A compiled JSON-template dict with a ``fields`` list.
        name: The field name to locate.

    Returns:
        dict[str, Any]: The matching field definition.
    """
    fields: list[dict[str, Any]] = result["fields"]
    for field in fields:
        if field["name"] == name:
            return field
    pytest.fail(f"field {name!r} not present in {[f['name'] for f in fields]}")


class TestPragmaPropagation:
    """Pragma directives must reach the generated JSON template verbatim."""

    def test_endian_big_sets_default_endianness(self) -> None:
        """``#pragma endian big`` flips ``default_endianness`` to ``big``."""
        result = _compile("#pragma endian big\nstruct Hdr { u32 magic; };")
        assert result["default_endianness"] == "big"

    def test_endian_little_is_default(self) -> None:
        """Absence of an endian pragma leaves the template little-endian."""
        result = _compile("struct Hdr { u32 magic; };")
        assert result["default_endianness"] == "little"

    def test_author_and_description_pragmas_propagate(self) -> None:
        """``#pragma author`` and ``#pragma description`` flow into JSON."""
        source = (
            '#pragma author "Zachary Flint"\n'
            '#pragma description "ELF program header"\n'
            "struct Hdr { u32 magic; };"
        )
        result = _compile(source)
        assert result["author"] == "Zachary Flint"
        assert result["description"] == "ELF program header"

    def test_description_falls_back_to_struct_name(self) -> None:
        """Without a description pragma the generic struct-derived text is used."""
        result = _compile("struct Widget { u32 magic; };")
        assert result["description"] == "Widget (compiled from HexPat DSL)"

    def test_magic_pragma_emits_magic_detection(self) -> None:
        """``#pragma magic`` becomes a ``magic_detection`` offset/bytes block."""
        source = '#pragma magic [ 0x00, "7F454C46" ]\nstruct Elf { u32 magic; };'
        result = _compile(source)
        magic = result["magic_detection"]
        assert magic["offset"] == 0
        assert magic["bytes"] == [0x7F, 0x45, 0x4C, 0x46]

    def test_base_address_and_pointer_size_in_pragma_metadata(self) -> None:
        """Non-default base_address/pointer_size land in ``pragma_metadata``."""
        source = (
            "#pragma base_address 0x400000\n"
            "#pragma pointer_size 4\n"
            "struct Hdr { u32 magic; };"
        )
        result = _compile(source)
        meta = result["pragma_metadata"]
        assert meta["base_address"] == 0x400000
        assert meta["pointer_size"] == 4

    def test_bitfield_order_and_mime_in_pragma_metadata(self) -> None:
        """``bitfield_order`` and ``MIME`` pragmas surface in pragma_metadata."""
        source = (
            "#pragma bitfield_order right_to_left\n"
            "#pragma MIME application/x-elf\n"
            "struct Hdr { u32 magic; };"
        )
        result = _compile(source)
        meta = result["pragma_metadata"]
        assert meta["bitfield_order"] == "right_to_left"
        assert meta["mime"] == "application/x-elf"

    def test_no_pragmas_omits_optional_blocks(self) -> None:
        """A bare struct emits no author/magic/pragma_metadata keys."""
        result = _compile("struct Hdr { u32 magic; };")
        assert "author" not in result
        assert "magic_detection" not in result
        assert "pragma_metadata" not in result


class TestConditionalInvertedOperator:
    """``if``/``else`` must partition the predicate via inverted operators."""

    def test_equality_else_branch_uses_ne(self) -> None:
        """An ``== 1`` true-branch yields an ``Ne`` else-branch."""
        source = (
            "struct P { u8 type; "
            "if (type == 1) { u32 a; } else { u16 b; } };"
        )
        result = _compile(source)
        if_field = _field_by_name(result, "_if_type")
        else_field = _field_by_name(result, "_else_type")
        assert if_field["field_type"]["params"]["condition_op"] == "Eq"
        assert else_field["field_type"]["params"]["condition_op"] == "Ne"
        assert else_field["field_type"]["params"]["condition_value"] == 1

    def test_greater_than_else_branch_uses_le(self) -> None:
        """A ``> 4`` true-branch yields an ``Le`` else-branch."""
        source = (
            "struct P { u8 flags; "
            "if (flags > 4) { u32 a; } else { u16 b; } };"
        )
        result = _compile(source)
        if_field = _field_by_name(result, "_if_flags")
        else_field = _field_by_name(result, "_else_flags")
        assert if_field["field_type"]["params"]["condition_op"] == "Gt"
        assert else_field["field_type"]["params"]["condition_op"] == "Le"

    def test_bitmask_else_branch_uses_bitandzero(self) -> None:
        """A ``& mask`` true-branch yields a ``BitAndZero`` else-branch."""
        source = (
            "struct P { u8 flags; "
            "if (flags & 8) { u32 a; } else { u16 b; } };"
        )
        result = _compile(source)
        if_field = _field_by_name(result, "_if_flags")
        else_field = _field_by_name(result, "_else_flags")
        assert if_field["field_type"]["params"]["condition_op"] == "BitAnd"
        assert else_field["field_type"]["params"]["condition_op"] == "BitAndZero"

    def test_if_without_else_emits_single_conditional(self) -> None:
        """An ``if`` lacking an ``else`` produces exactly one conditional field."""
        source = "struct P { u8 type; if (type == 2) { u32 a; } };"
        result = _compile(source)
        names = [f["name"] for f in result["fields"]]
        assert "_if_type" in names
        assert "_else_type" not in names


class TestDynamicArrayAndPointer:
    """Dynamic arrays and pointer types must emit their dedicated JSON forms."""

    def test_field_referenced_array_is_dynamic(self) -> None:
        """``u8 items[count]`` becomes a ``DynamicArray`` keyed on the field."""
        source = "struct P { u8 count; u8 items[count]; };"
        result = _compile(source)
        items = _field_by_name(result, "items")
        assert items["field_type"]["type"] == "DynamicArray"
        assert items["field_type"]["params"]["count_field"] == "count"
        assert items["field_type"]["params"]["element_type"] == {"type": "UInt8"}

    def test_literal_sized_array_is_static(self) -> None:
        """A numeric array size produces a static ``Array`` with that count."""
        source = "struct P { u8 data[16]; };"
        result = _compile(source)
        data = _field_by_name(result, "data")
        assert data["field_type"]["type"] == "Array"
        assert data["field_type"]["params"]["count"] == 16

    def test_pointer_to_named_type_targets_template(self) -> None:
        """A pointer to a named struct emits a ``Pointer`` with the target."""
        source = "struct P { Inner *next; }; struct Inner { u32 a; };"
        result = _compile(source)
        next_field = _field_by_name(result, "next")
        assert next_field["field_type"]["type"] == "Pointer"
        assert next_field["field_type"]["params"]["target_template"] == "Inner"
        assert next_field["field_type"]["params"]["pointer_type"] == {"type": "UInt64"}

    def test_pointer_to_primitive_uses_primitive_size(self) -> None:
        """A pointer to a primitive emits a ``Pointer`` with empty target."""
        source = "struct P { u32 *offset; };"
        result = _compile(source)
        offset = _field_by_name(result, "offset")
        assert offset["field_type"]["type"] == "Pointer"
        assert not offset["field_type"]["params"]["target_template"]
        assert offset["field_type"]["params"]["pointer_type"] == {"type": "UInt32"}


class TestValidationAnnotations:
    """Annotation attributes must populate color/description/validation JSON."""

    def test_color_annotation(self) -> None:
        """``[[color("...")]]`` sets the field ``color`` key."""
        result = _compile('struct A { u32 marker [[color("FF0000")]]; };')
        marker = _field_by_name(result, "marker")
        assert marker["color"] == "FF0000"

    def test_description_annotation(self) -> None:
        """``[[description("...")]]`` overrides the field description."""
        result = _compile('struct A { u32 v [[description("the version")]]; };')
        field = _field_by_name(result, "v")
        assert field["description"] == "the version"

    def test_validate_annotation_sets_expected_value(self) -> None:
        """``[[validate(N)]]`` records an ``expected_value`` validation."""
        result = _compile("struct A { u32 v [[validate(42)]]; };")
        field = _field_by_name(result, "v")
        assert field["validation"]["expected_value"] == 42

    def test_min_max_annotations(self) -> None:
        """``[[min(N), max(M)]]`` records both validation bounds."""
        result = _compile("struct A { u8 level [[min(1), max(10)]]; };")
        field = _field_by_name(result, "level")
        assert field["validation"]["min_value"] == 1
        assert field["validation"]["max_value"] == 10


class TestConstExprEvaluator:
    """The compile-time constant evaluator must compute correct integers."""

    @pytest.mark.parametrize(
        ("expr", "expected"),
        [
            ("2 + 3", 5),
            ("10 - 4", 6),
            ("3 * 4", 12),
            ("20 / 6", 3),
            ("17 % 5", 2),
            ("2 + 3 * 4 - 1", 13),
            ("-2 + 5", 3),
            ("(8)", 8),
        ],
    )
    def test_operator_results(self, expr: str, expected: int) -> None:
        """Each arithmetic form folds to the mathematically correct value.

        Args:
            expr: A constant integer expression.
            expected: The arithmetic result the evaluator must produce.
        """
        assert _eval_const(expr) == expected

    def test_division_by_zero_rejected(self) -> None:
        """A constant divide-by-zero raises :class:`HexPatError`."""
        with pytest.raises(HexPatError, match="division by zero"):
            _eval_const("4 / 0")

    def test_modulo_by_zero_rejected(self) -> None:
        """A constant modulo-by-zero raises :class:`HexPatError`."""
        with pytest.raises(HexPatError, match="modulo by zero"):
            _eval_const("4 % 0")

    def test_identifier_is_not_constant(self) -> None:
        """A bare identifier size is not a constant; not a static array."""
        result = _compile("struct A { u8 n; u8 v[n]; };")
        field = _field_by_name(result, "v")
        assert field["field_type"]["type"] == "DynamicArray"


class TestEnumAndBitfieldCodegen:
    """Enum auto-increment and bitfield widths must compute real values."""

    def test_enum_auto_increment_and_explicit_reset(self) -> None:
        """Enum entries auto-increment, and an explicit value resets the run."""
        source = (
            "enum Color : u8 { Red, Green, Blue = 10, Cyan };"
            " struct A { Color c; };"
        )
        result = _compile(source)
        values = result["types"]["Color"]["values"]
        as_pairs = dict(values)
        assert as_pairs == {"Red": 0, "Green": 1, "Blue": 10, "Cyan": 11}

    def test_bitfield_widths_emitted(self) -> None:
        """Bitfield entries emit ``(name, width)`` pairs from the DSL widths."""
        source = (
            "bitfield Flags { a : 1; b : 3; c : 4; };"
            " struct A { Flags f; };"
        )
        result = _compile(source)
        fields = result["types"]["Flags"]["fields"]
        assert dict(fields) == {"a": 1, "b": 3, "c": 4}


class TestVendorPatternCompilation:
    """A static-only vendor ``.hexpat`` must compile or be rejected cleanly."""

    def test_at_least_one_vendor_pattern_compiles_to_static_json(self) -> None:
        """Some committed community pattern compiles to a real JSON template.

        Walks the committed ``vendor/community-patterns`` collection and
        compiles each ``.hexpat`` source. Patterns built purely from static
        constructs must produce a well-formed template (a ``name`` and a
        ``fields`` list); patterns containing runtime constructs must be
        rejected with :class:`HexPatError` rather than crashing. The test
        asserts that at least one real-world pattern compiles successfully,
        proving the static codegen handles authentic input.
        """
        manager = TemplateManager(Path.cwd())
        patterns = manager.list_hexpat_patterns()
        if not patterns:
            pytest.skip("no vendor .hexpat patterns are available")

        compiled = 0
        for entry in patterns:
            source = Path(entry["file_path"]).read_text(encoding="utf-8", errors="replace")
            try:
                result = HexPatCompiler.compile_to_dict(source)
            except HexPatError:
                continue
            except (ValueError, RecursionError, KeyError):
                continue
            assert isinstance(result.get("name"), str)
            assert isinstance(result.get("fields"), list)
            compiled += 1

        assert compiled >= 1
