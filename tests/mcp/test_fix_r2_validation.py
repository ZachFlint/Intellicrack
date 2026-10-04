# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 18: schema validation and reduction survive hostile shapes, run in linear time, and read patterns as ECMA-262.

The gates feed the real validator and the real schema passes the shapes the audit broke them with: a pattern nesting hundreds of groups,
an array of ten thousand items under ``uniqueItems``, a schema six thousand levels deep, a ``$ref`` inside ``dependencies``, a
``$dynamicRef``, and a recursive definition reduced for Gemini. Patterns are checked against what ECMA-262 says they match.
"""

from __future__ import annotations

import time
from typing import Any, Final, cast

import pytest
from mcp_types import Tool

from intellicrack.bridges.json_schema import gemini_function_parameters, inline_refs, to_gemini_subset, to_strict_subset
from intellicrack.core.types import ToolFunction
from intellicrack.mcp.catalog import build_catalog
from intellicrack.mcp.validation import pattern_hazard, validate_against_schema


_DEEP: Final[int] = 6000
_BEYOND_C_RECURSION: Final[int] = 12_000
_UNIQUE_ITEMS: Final[int] = 10_000
_UNIQUE_BUDGET_S: Final[float] = 1.0


def _nested_arrays(levels: int) -> list[object]:
    """Build an array nesting ``levels`` empty arrays, one inside the next.

    Args:
        levels: How many arrays to nest.

    Returns:
        list[object]: The outermost array.
    """
    outer: list[object] = []
    cursor = outer
    for _ in range(levels):
        inner: list[object] = []
        cursor.append(inner)
        cursor = inner
    return outer


def _deep_schema(levels: int) -> dict[str, Any]:
    """Build an object schema nesting ``levels`` objects, with no reference anywhere.

    Args:
        levels: How many objects to nest.

    Returns:
        dict[str, Any]: The schema.
    """
    node: dict[str, Any] = {"type": "string"}
    for _ in range(levels):
        node = {"type": "object", "properties": {"n": node}}
    return node


def _has_key(value: object, key: str) -> bool:
    """Report whether a key appears anywhere in a JSON value.

    Args:
        value: The value.
        key: The key.

    Returns:
        bool: ``True`` when some object in ``value`` has ``key``.
    """
    pending: list[object] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            members = cast("dict[str, object]", current)
            if key in members:
                return True
            pending.extend(members.values())
        elif isinstance(current, list):
            pending.extend(cast("list[object]", current))
    return False


class TestNestedPatternGroups:
    """A pattern nesting hundreds of groups is refused, not a crash."""

    @pytest.mark.parametrize("groups", [249, 300, 900])
    def test_deeply_nested_groups_are_refused_without_error(self, groups: int) -> None:
        """Validation completes and the pattern is reported as refused rather than raising ``RecursionError``.

        Args:
            groups: How many groups nest.
        """
        pattern = "(" * groups + "a" + ")" * groups

        assert pattern_hazard(pattern) is not None
        assert validate_against_schema("b", {"type": "string", "pattern": pattern}) == []


class TestUniqueItems:
    """``uniqueItems`` is linear, deep-safe and exact about JSON equality."""

    def test_ten_thousand_items_are_checked_quickly(self) -> None:
        """Ten thousand distinct objects are checked in well under a second, and one duplicate is found."""
        items: list[object] = [{"id": index, "tags": [index, str(index)]} for index in range(_UNIQUE_ITEMS)]
        started = time.perf_counter()
        clean = validate_against_schema(items, {"type": "array", "uniqueItems": True})
        elapsed = time.perf_counter() - started

        assert clean == []
        assert elapsed < _UNIQUE_BUDGET_S
        assert validate_against_schema([*items, {"tags": [7, "7"], "id": 7}], {"uniqueItems": True}) != []

    @pytest.mark.parametrize(
        ("items", "duplicated"),
        [
            ([1, 1.0], True),
            ([1, True], False),
            ([0, False], False),
            ([{"a": 1, "b": 2}, {"b": 2, "a": 1}], True),
            ([[1, 2], [2, 1]], False),
            (["1", 1], False),
            ([None, None], True),
        ],
    )
    def test_equality_is_json_equality(self, items: list[object], *, duplicated: bool) -> None:
        """Numbers compare by value, booleans stay apart from numbers, objects ignore member order, arrays do not.

        Args:
            items: The array.
            duplicated: Whether two of its items are the same JSON value.
        """
        assert bool(validate_against_schema(items, {"uniqueItems": True})) is duplicated

    def test_deeply_nested_items_are_compared(self) -> None:
        """Two identical arrays nested twelve thousand deep, past any platform's C recursion limit, are found equal."""
        assert (
            validate_against_schema([_nested_arrays(_BEYOND_C_RECURSION), _nested_arrays(_BEYOND_C_RECURSION)], {"uniqueItems": True}) != []
        )


class TestReferences:
    """References in every place a schema can hold them are expanded."""

    def test_ref_inside_dependencies_is_inlined(self) -> None:
        """A schema under the legacy ``dependencies`` keyword loses its ``$ref``; a name list there is kept."""
        schema = {
            "type": "object",
            "properties": {"card": {"type": "string"}, "billing": {"type": "string"}},
            "dependencies": {"card": {"$ref": "#/$defs/Billing"}, "billing": ["card"]},
            "$defs": {"Billing": {"required": ["billing"]}},
        }

        inlined = inline_refs(schema)

        assert not _has_key(inlined, "$ref")
        assert inlined["dependencies"] == {"card": {"required": ["billing"]}, "billing": ["card"]}

    def test_dynamic_ref_and_anchors_are_resolved(self) -> None:
        """``$dynamicRef`` to a ``$dynamicAnchor``, and ``$ref`` to an ``$anchor``, are expanded like any other reference."""
        schema = {
            "type": "object",
            "properties": {"tree": {"$dynamicRef": "#node"}, "leaf": {"$ref": "#leaf"}},
            "$defs": {
                "node": {"$dynamicAnchor": "node", "type": "object", "properties": {"name": {"type": "string"}}},
                "leaf": {"$anchor": "leaf", "type": "integer"},
            },
        }

        inlined = inline_refs(schema)

        assert not _has_key(inlined, "$dynamicRef")
        assert not _has_key(inlined, "$ref")
        assert inlined["properties"]["tree"]["properties"] == {"name": {"type": "string"}}
        assert inlined["properties"]["leaf"]["type"] == "integer"


class TestDeepSchemas:
    """A schema six thousand levels deep, twelve thousand containers, is handled by every pass, not a ``RecursionError``.

    Python 3.13 stops C recursion at 3000 levels on Windows and 10000 elsewhere, so the schema is deeper than any pass that recursed in
    C, such as :func:`json.dumps`, could go on either.
    """

    def test_every_pass_completes(self) -> None:
        """Inlining, strict reduction, Gemini reduction and validation all finish."""
        schema = _deep_schema(_DEEP)

        assert _has_key(inline_refs(schema), "properties")
        assert to_strict_subset(schema)[1] is False
        assert to_gemini_subset(schema)["type"] == "OBJECT"
        assert validate_against_schema({"n": {"n": 1}}, schema) != []

    def test_the_tool_listing_completes(self) -> None:
        """A tool whose schema nests twelve thousand objects, inside the size bound, is listed."""
        nested: object = {}
        for _ in range(_BEYOND_C_RECURSION):
            nested = {"n": nested}

        catalog = build_catalog([Tool(name="deep", description="d", input_schema={"type": "object", "properties": {"n": nested}})], "srv")

        assert catalog.tool_count == 1


def test_collapsed_recursion_is_sent_to_gemini_as_json_schema() -> None:
    """A recursive definition leaves an untyped node once it collapses, which Gemini's ``Schema`` cannot carry, so it is sent as JSON Schema."""
    schema = {
        "type": "object",
        "properties": {"root": {"$ref": "#/$defs/Node"}},
        "required": ["root"],
        "$defs": {"Node": {"type": "object", "properties": {"name": {"type": "string"}, "child": {"$ref": "#/$defs/Node"}}}},
    }

    chosen = gemini_function_parameters(ToolFunction("walk", "Walk a tree.", [], "", input_schema=schema))

    assert chosen is not None
    assert chosen[0] == "parametersJsonSchema"


class TestEcmaPatterns:
    """A schema pattern means what ECMA-262 says it means."""

    @pytest.mark.parametrize(
        ("pattern", "text"),
        [
            ("^abc$", "abc\n"),
            (r"^\d+$", chr(0x661) + chr(0x662)),
            (r"^\w+$", f"{chr(233)}t{chr(233)}"),
            ("^.$", chr(0x2028)),
            ("^.$", "\r"),
            ("^[]$", ""),
        ],
        ids=["dollar-before-newline", "arabic-digits", "accented-letters", "line-separator", "carriage-return", "empty-class"],
    )
    def test_python_only_matches_are_refused(self, pattern: str, text: str) -> None:
        """Text Python's dialect would match but ECMA-262's does not is a violation.

        Args:
            pattern: The schema pattern.
            text: The value.
        """
        assert validate_against_schema(text, {"type": "string", "pattern": pattern}) != []

    @pytest.mark.parametrize(
        ("pattern", "text"),
        [
            (r"^\s$", chr(0xFEFF)),
            ("^[^]$", "\n"),
            (r"^\cJ$", "\n"),
            (r"^\u{1F600}$", "\U0001f600"),
            (r"^a\/b$", "a/b"),
            (r"^[\d-]+$", "1-2"),
            (r"^\S+$", "abc"),
        ],
        ids=[
            "bom-is-whitespace",
            "any-character-class",
            "control-escape",
            "code-point-escape",
            "escaped-slash",
            "class-escape-dash",
            "non-space",
        ],
    )
    def test_ecma_constructs_match(self, pattern: str, text: str) -> None:
        """Text ECMA-262 matches is accepted, including constructs Python has no syntax for.

        Args:
            pattern: The schema pattern.
            text: The value.
        """
        assert validate_against_schema(text, {"type": "string", "pattern": pattern}) == []
