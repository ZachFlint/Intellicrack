# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Offline schema-correctness tests over the real bridge tool definitions.

Runs every concrete bridge's ``tool_definition`` through both schema
generation paths -- ``intellicrack.providers.base`` (what providers send to
the wire) and ``intellicrack.bridges.schemas`` (the orchestrator's pre-send
validation path) -- for all three cloud formats. Asserts that every array
property carries a typed ``items`` definition and every object element schema
carries non-empty ``properties``.

This is the coverage that the live tool-calling tests lack: they exercise a
synthetic string-only tool, so they never push an array parameter through a
schema. A bridge that declares an array without a valid element type, or a
builder that stops emitting ``items``, would be caught here without any API
key or network access -- the exact defect class that broke Gemini in
production.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, cast

import pytest

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.schemas import (
    to_anthropic_schema,
    to_google_schema,
    to_openai_schema,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolDefinition
from intellicrack.providers.base import (
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
)


def _bridge_definitions() -> list[ToolDefinition]:
    """Instantiate every concrete bridge and collect its tool definition.

    Returns:
        list[ToolDefinition]: One ToolDefinition per concrete bridge.
    """
    return [
        CutterBridge().tool_definition,
        FridaBridge().tool_definition,
        GhidraBridge().tool_definition,
        HexEditorBridge().tool_definition,
        ProcessBridge().tool_definition,
        SandboxBridge().tool_definition,
        X64DbgBridge().tool_definition,
    ]


_BRIDGE_DEFINITIONS: list[ToolDefinition] = _bridge_definitions()

_EXPECTED_TOP_LEVEL_ARRAYS: int = sum(
    1
    for definition in _BRIDGE_DEFINITIONS
    for function in definition.functions
    for param in function.parameters
    if param.type == "array"
)

_SchemaBuilder = Callable[[ToolDefinition], list[Any]]
_PropsExtractor = Callable[[Any], Mapping[str, Any]]

_BUILDERS: list[tuple[str, _SchemaBuilder, _PropsExtractor]] = [
    ("base.anthropic", create_anthropic_tool_schema, lambda s: s["input_schema"]["properties"]),
    ("base.openai", create_openai_tool_schema, lambda s: s["function"]["parameters"]["properties"]),
    ("base.google", create_google_tool_schema, lambda s: s["parameters"]["properties"]),
    ("schemas.anthropic", to_anthropic_schema, lambda s: s["input_schema"]["properties"]),
    ("schemas.openai", to_openai_schema, lambda s: s["function"]["parameters"]["properties"]),
    ("schemas.google", to_google_schema, lambda s: s["parameters"]["properties"]),
]


def _assert_array_items(prop: Mapping[str, Any], path: str) -> int:
    """Recursively assert array/object schema correctness for a property.

    Args:
        prop: A JSON Schema property dict (provider-cased).
        path: Dotted location used in assertion messages.

    Returns:
        int: The number of array properties validated under this property.
    """
    prop_type = str(prop.get("type", "")).upper()
    if prop_type == "ARRAY":
        items_obj = prop.get("items")
        assert isinstance(items_obj, Mapping), f"{path}: array property missing items"
        items = cast("Mapping[str, Any]", items_obj)
        item_type = str(items.get("type", "")).upper()
        assert item_type, f"{path}: array items missing type"
        if item_type == "OBJECT":
            props_obj = items.get("properties")
            assert isinstance(props_obj, Mapping), f"{path}: object array items missing properties"
            nested = cast("Mapping[str, Any]", props_obj)
            assert nested, f"{path}: object array items has empty properties"
            return 1 + sum(_assert_array_items(sub, f"{path}.items.{key}") for key, sub in nested.items())
        return 1 + _assert_array_items(items, f"{path}.items")
    if prop_type == "OBJECT":
        props_obj = prop.get("properties")
        if isinstance(props_obj, Mapping):
            nested = cast("Mapping[str, Any]", props_obj)
            return sum(_assert_array_items(sub, f"{path}.{key}") for key, sub in nested.items())
    return 0


@pytest.mark.parametrize(
    ("label", "builder", "extract"),
    _BUILDERS,
    ids=[entry[0] for entry in _BUILDERS],
)
def test_real_bridge_schemas_emit_valid_array_items(
    label: str,
    builder: _SchemaBuilder,
    extract: _PropsExtractor,
) -> None:
    """Every real-bridge array schema must carry valid, typed items.

    Args:
        label: Human-readable builder identifier for assertion messages.
        builder: Schema builder under test.
        extract: Callable pulling the properties map from one declaration.
    """
    validated_arrays = 0
    for definition in _BRIDGE_DEFINITIONS:
        for declaration in builder(definition):
            properties = extract(declaration)
            for name, prop in properties.items():
                validated_arrays += _assert_array_items(prop, f"{label}:{definition.tool_name.value}:{name}")

    assert validated_arrays >= _EXPECTED_TOP_LEVEL_ARRAYS, (
        f"{label}: validated {validated_arrays} arrays but the bridges declare "
        f"{_EXPECTED_TOP_LEVEL_ARRAYS} top-level array parameters"
    )


def test_bridges_declare_array_parameters() -> None:
    """Guard against the suite becoming vacuous if arrays disappear."""
    assert _EXPECTED_TOP_LEVEL_ARRAYS > 0, "Expected at least one array parameter across the bridges"
