# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on what every bridge tool actually puts on the wire.

Provider identity became an open string and schema generation moved behind
per-dialect adapters. Both changes sit underneath all 715 bridge tool
functions, none of which were supposed to change shape, so the risk is a
silent narrowing: a field dropped, a property filtered away, a name rendered
in a form the endpoint rejects.

Every gate here renders the real bridge definitions -- no fixtures, no doubles
-- and asserts a property that fails if the rendering regresses. Two of them
were written because it already had: ``_strictify`` and ``_geminify``
recursed into the ``properties`` map as though the property names were schema
keywords and dropped every argument, and ``build_schema_property`` emitted a
default only when it was scalar, silently discarding the empty-list defaults
six sandbox parameters declare.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.json_schema import build_schema_property, to_gemini_subset, to_strict_subset
from intellicrack.bridges.schemas import to_anthropic_schema, to_google_schema, to_openai_schema
from intellicrack.providers.tool_names import from_wire_name, from_wire_pair, is_valid_wire_name, to_wire_name, to_wire_pair


if TYPE_CHECKING:
    from intellicrack.bridges.base import ToolBridgeBase
    from intellicrack.core.types import ToolDefinition, ToolFunction


_BRIDGE_CLASSES: tuple[tuple[str, str], ...] = (
    ("intellicrack.bridges.process", "ProcessBridge"),
    ("intellicrack.bridges.frida_bridge", "FridaBridge"),
    ("intellicrack.bridges.ghidra", "GhidraBridge"),
    ("intellicrack.bridges.cutter", "CutterBridge"),
    ("intellicrack.bridges.x64dbg", "X64DbgBridge"),
    ("intellicrack.bridges.sandbox_bridge", "SandboxBridge"),
    ("intellicrack.bridges.hex_editor", "HexEditorBridge"),
)

_MIN_EXPECTED_FUNCTIONS = 700
"""Floor on the bridge function count, so a collapsed registry cannot pass vacuously."""

_OPENAI_NAME_LIMIT = 64
"""Longest function name the OpenAI function-name rule accepts."""


@pytest.fixture(scope="module")
def bridge_definitions() -> list[ToolDefinition]:
    """Instantiate every shipped bridge and collect its tool definition.

    Bridges are constructed directly rather than through
    ``ToolRegistry.initialize``, which also starts local tools; the schemas
    come from ``tool_definition`` either way.

    Returns:
        list[ToolDefinition]: One definition per bridge, namespace-sorted.
    """
    definitions: list[ToolDefinition] = []
    for module_path, class_name in _BRIDGE_CLASSES:
        module = importlib.import_module(module_path)
        bridge_class: type[ToolBridgeBase] = getattr(module, class_name)
        definitions.append(bridge_class().tool_definition)
    definitions.sort(key=lambda item: item.tool_name)
    return definitions


@pytest.fixture(scope="module")
def bridge_functions(bridge_definitions: list[ToolDefinition]) -> list[ToolFunction]:
    """Flatten every bridge definition into its individual tool functions.

    Args:
        bridge_definitions: The shipped bridge definitions.

    Returns:
        list[ToolFunction]: Every function across every bridge.
    """
    return [function for definition in bridge_definitions for function in definition.functions]


def test_every_bridge_function_reaches_every_dialect(
    bridge_definitions: list[ToolDefinition],
    bridge_functions: list[ToolFunction],
) -> None:
    """No dialect may silently drop a bridge function.

    Args:
        bridge_definitions: The shipped bridge definitions.
        bridge_functions: Every function across every bridge.
    """
    assert len(bridge_functions) >= _MIN_EXPECTED_FUNCTIONS

    openai = [entry for definition in bridge_definitions for entry in to_openai_schema(definition)]
    anthropic = [entry for definition in bridge_definitions for entry in to_anthropic_schema(definition)]
    google = [
        declaration
        for definition in bridge_definitions
        for entry in to_google_schema(definition)
        for declaration in ([entry] if "name" in entry else entry.get("functionDeclarations", []))
    ]

    assert len(openai) == len(bridge_functions)
    assert len(anthropic) == len(bridge_functions)
    assert len(google) == len(bridge_functions)


def test_rendered_names_satisfy_the_provider_name_rule(bridge_definitions: list[ToolDefinition]) -> None:
    """Every rendered function name must be one the endpoints accept.

    Canonical names are dotted, and neither OpenAI nor Anthropic accepts a
    ``.`` in a function name, so each dialect must render the mapped wire
    form. A name that arrives dotted is rejected by the endpoint, which is a
    failure no offline shape check would otherwise catch.

    Args:
        bridge_definitions: The shipped bridge definitions.
    """
    rendered: list[str] = []
    for definition in bridge_definitions:
        rendered.extend(entry["function"]["name"] for entry in to_openai_schema(definition))
        rendered.extend(entry["name"] for entry in to_anthropic_schema(definition))
        for entry in to_google_schema(definition):
            declarations: list[Any] = [entry] if "name" in entry else list(entry.get("functionDeclarations", []))
            rendered.extend(str(declaration["name"]) for declaration in declarations)

    assert rendered
    offenders = [name for name in rendered if not is_valid_wire_name(name) or len(name) > _OPENAI_NAME_LIMIT]
    assert offenders == []


def test_every_wire_name_round_trips_to_its_canonical_name(bridge_functions: list[ToolFunction]) -> None:
    """A dispatched tool call must resolve back to the function that was sent.

    Args:
        bridge_functions: Every function across every bridge.
    """
    failures: list[tuple[str, str, str]] = []
    for function in bridge_functions:
        wire = to_wire_name(function.name)
        recovered = from_wire_name(wire)
        if recovered != function.name:
            failures.append((function.name, wire, recovered))

        namespace, member = to_wire_pair(function.name)
        recovered_pair = from_wire_pair(namespace, member)
        if recovered_pair != function.name:
            failures.append((function.name, f"{namespace}/{member}", recovered_pair))

    assert failures == []


def test_declared_list_defaults_survive_rendering(bridge_functions: list[ToolFunction]) -> None:
    """A parameter whose default is a list must still advertise it.

    Several sandbox parameters default to an empty list. A truthiness or
    scalar-only check drops those, narrowing the advertised schema of tools
    that work today, which is exactly the regression this gate exists for.

    Args:
        bridge_functions: Every function across every bridge.
    """
    listed = [parameter for function in bridge_functions for parameter in function.parameters if isinstance(parameter.default, list)]
    assert listed, "no parameter declares a list default; this gate would pass vacuously"

    for parameter in listed:
        rendered = build_schema_property(parameter)
        assert "default" in rendered
        assert rendered["default"] == parameter.default


def test_strict_and_gemini_reductions_keep_every_property() -> None:
    """Both reducing dialects must preserve the arguments a tool declares.

    ``properties`` maps a caller-chosen name to a subschema. A reduction that
    walks it as though the names were schema keywords filters every one of
    them away and sends an object with no arguments at all.
    """
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"$ref": "#/$defs/Path"},
            "depth": {"type": "integer", "description": "how far to walk"},
            "mode": {"type": ["string", "null"], "enum": ["fast", "full"]},
            "nested": {
                "type": "object",
                "properties": {"inner": {"type": "boolean"}},
                "required": ["inner"],
            },
        },
        "required": ["path"],
        "$defs": {"Path": {"type": "string", "description": "a filesystem path"}},
    }

    strict, faithful = to_strict_subset(schema)
    assert faithful
    assert set(strict["properties"]) == {"path", "depth", "mode", "nested"}
    assert strict["properties"]["path"]["description"] == "a filesystem path"
    assert set(strict["required"]) == {"path", "depth", "mode", "nested"}
    assert strict["additionalProperties"] is False
    assert set(strict["properties"]["nested"]["properties"]) == {"inner"}
    assert "null" in strict["properties"]["depth"]["type"]

    gemini = to_gemini_subset(schema)
    assert set(gemini["properties"]) == {"path", "depth", "mode", "nested"}
    assert gemini["type"] == "OBJECT"
    assert gemini["properties"]["path"]["type"] == "STRING"
    assert gemini["properties"]["depth"]["type"] == "INTEGER"
    assert set(gemini["properties"]["nested"]["properties"]) == {"inner"}
    assert "$ref" not in str(gemini)
