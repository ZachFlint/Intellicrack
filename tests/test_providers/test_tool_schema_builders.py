# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for centralized tool schema builder functions.

Validates create_openai_tool_schema, create_anthropic_tool_schema,
and create_google_tool_schema produce correct provider-specific formats.
"""

from __future__ import annotations

from typing import Final

import pytest

from intellicrack.core.types import (
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.base import (
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
)


_EXPECTED_DEFAULT_TIMEOUT: Final[int] = 30
_EXPECTED_MULTI_FUNC_COUNT: Final[int] = 2
_FUNC_NAME_ANALYZE: Final[str] = "ghidra.analyze"
_FUNC_NAME_DECOMPILE: Final[str] = "ghidra.decompile"
_FUNC_DESC_ANALYZE: Final[str] = "Analyze a binary"
_ENUM_VALUES: Final[list[str]] = ["json", "text", "xml"]


def _make_tool(
    *,
    with_enum: bool = False,
    with_default: bool = False,
    multi_function: bool = False,
) -> ToolDefinition:
    """Build a ToolDefinition with configurable parameter features.

    Args:
        with_enum: Include an enum-constrained parameter.
        with_default: Include a parameter with a default value.
        multi_function: Include two functions instead of one.

    Returns:
        A ToolDefinition for testing.
    """
    params: list[ToolParameter] = [
        ToolParameter(
            name="target",
            type="string",
            description="Target binary path",
            required=True,
        ),
        ToolParameter(
            name="verbose",
            type="boolean",
            description="Enable verbose output",
            required=False,
        ),
    ]
    if with_enum:
        params.append(
            ToolParameter(
                name="format",
                type="string",
                description="Output format",
                required=False,
                enum=_ENUM_VALUES,
            )
        )
    if with_default:
        params.append(
            ToolParameter(
                name="timeout",
                type="integer",
                description="Timeout in seconds",
                required=False,
                default=_EXPECTED_DEFAULT_TIMEOUT,
            )
        )

    functions = [
        ToolFunction(
            name=_FUNC_NAME_ANALYZE,
            description=_FUNC_DESC_ANALYZE,
            parameters=params,
            returns="Analysis results",
        ),
    ]
    if multi_function:
        functions.append(
            ToolFunction(
                name=_FUNC_NAME_DECOMPILE,
                description="Decompile a function",
                parameters=[
                    ToolParameter(
                        name="address",
                        type="string",
                        description="Function address",
                        required=True,
                    ),
                ],
                returns="Decompiled source",
            ),
        )

    return ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="Ghidra analysis tool",
        functions=functions,
    )


def _make_empty_tool() -> ToolDefinition:
    """Build a ToolDefinition with no functions.

    Returns:
        An empty ToolDefinition.
    """
    return ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="Empty tool",
        functions=[],
    )


def test_openai_basic_schema_structure() -> None:
    """Verify the OpenAI wrapper has type=function and nested function dict."""
    tool = _make_tool()
    schemas = create_openai_tool_schema(tool)

    assert len(schemas) == 1
    schema = schemas[0]
    assert schema["type"] == "function"
    func = schema["function"]
    assert func["name"] == _FUNC_NAME_ANALYZE
    assert func["description"] == _FUNC_DESC_ANALYZE


def test_openai_parameters_structure() -> None:
    """Verify parameters dict has type=object, properties, and required."""
    tool = _make_tool()
    schemas = create_openai_tool_schema(tool)
    params = schemas[0]["function"]["parameters"]

    assert params["type"] == "object"
    assert "target" in params["properties"]
    assert "verbose" in params["properties"]
    assert "target" in params["required"]
    assert "verbose" not in params["required"]


def test_openai_property_types() -> None:
    """Verify property type strings are lowercase (standard JSON Schema)."""
    tool = _make_tool()
    schemas = create_openai_tool_schema(tool)
    props = schemas[0]["function"]["parameters"]["properties"]

    assert props["target"].get("type") == "string"
    assert props["verbose"].get("type") == "boolean"


def test_openai_enum_values_included() -> None:
    """Verify enum constraint flows through to the schema."""
    tool = _make_tool(with_enum=True)
    schemas = create_openai_tool_schema(tool)
    props = schemas[0]["function"]["parameters"]["properties"]

    assert "enum" in props["format"]
    assert props["format"]["enum"] == _ENUM_VALUES


def test_openai_default_values_included() -> None:
    """Verify default values flow through _build_schema_property."""
    tool = _make_tool(with_default=True)
    schemas = create_openai_tool_schema(tool)
    props = schemas[0]["function"]["parameters"]["properties"]

    assert "default" in props["timeout"]
    assert props["timeout"]["default"] == _EXPECTED_DEFAULT_TIMEOUT


def test_openai_multi_function_produces_multiple_schemas() -> None:
    """Verify each function in a ToolDefinition yields a separate schema."""
    tool = _make_tool(multi_function=True)
    schemas = create_openai_tool_schema(tool)

    assert len(schemas) == _EXPECTED_MULTI_FUNC_COUNT
    names = [s["function"]["name"] for s in schemas]
    assert _FUNC_NAME_ANALYZE in names
    assert _FUNC_NAME_DECOMPILE in names


def test_openai_empty_functions_returns_empty() -> None:
    """Verify a ToolDefinition with no functions yields an empty list."""
    assert create_openai_tool_schema(_make_empty_tool()) == []


def test_anthropic_basic_schema_structure() -> None:
    """Verify Anthropic format uses input_schema (not function wrapper)."""
    tool = _make_tool()
    schemas = create_anthropic_tool_schema(tool)

    assert len(schemas) == 1
    schema = schemas[0]
    assert schema["name"] == _FUNC_NAME_ANALYZE
    assert schema["description"] == _FUNC_DESC_ANALYZE
    assert "input_schema" in schema
    assert "type" not in schema


def test_anthropic_input_schema_parameters() -> None:
    """Verify input_schema has correct properties and required."""
    tool = _make_tool()
    schemas = create_anthropic_tool_schema(tool)
    input_schema = schemas[0]["input_schema"]

    assert input_schema["type"] == "object"
    assert "target" in input_schema["properties"]
    assert "target" in input_schema["required"]
    assert "verbose" not in input_schema["required"]


def test_anthropic_default_values_included() -> None:
    """Verify default values flow through for Anthropic format."""
    tool = _make_tool(with_default=True)
    schemas = create_anthropic_tool_schema(tool)
    props = schemas[0]["input_schema"]["properties"]

    assert props["timeout"].get("default") == _EXPECTED_DEFAULT_TIMEOUT


def test_google_basic_schema_structure() -> None:
    """Verify Google format has name, description, parameters (no function wrapper)."""
    tool = _make_tool()
    schemas = create_google_tool_schema(tool)

    assert len(schemas) == 1
    schema = schemas[0]
    assert schema["name"] == _FUNC_NAME_ANALYZE
    assert schema["description"] == _FUNC_DESC_ANALYZE
    assert "parameters" in schema
    assert "type" not in schema
    assert "function" not in schema


def test_google_uppercase_types() -> None:
    """Verify Google format converts types to uppercase."""
    tool = _make_tool()
    schemas = create_google_tool_schema(tool)
    params = schemas[0]["parameters"]

    assert params["type"] == "OBJECT"
    props = params["properties"]
    assert props["target"].get("type") == "STRING"
    assert props["verbose"].get("type") == "BOOLEAN"


def test_google_enum_values_included() -> None:
    """Verify enum constraint flows through with uppercase types."""
    tool = _make_tool(with_enum=True)
    schemas = create_google_tool_schema(tool)
    props = schemas[0]["parameters"]["properties"]

    assert props["format"].get("type") == "STRING"
    assert props["format"].get("enum") == _ENUM_VALUES


def test_google_default_values_included() -> None:
    """Verify default values flow through for Google format."""
    tool = _make_tool(with_default=True)
    schemas = create_google_tool_schema(tool)
    props = schemas[0]["parameters"]["properties"]

    assert props["timeout"].get("type") == "INTEGER"
    assert props["timeout"].get("default") == _EXPECTED_DEFAULT_TIMEOUT


def test_google_required_parameters() -> None:
    """Verify required list only contains required params."""
    tool = _make_tool()
    schemas = create_google_tool_schema(tool)
    required = schemas[0]["parameters"]["required"]

    assert "target" in required
    assert "verbose" not in required


def test_google_multi_function_produces_multiple_declarations() -> None:
    """Verify each function yields a separate declaration."""
    tool = _make_tool(multi_function=True)
    schemas = create_google_tool_schema(tool)

    assert len(schemas) == _EXPECTED_MULTI_FUNC_COUNT
    names = [s["name"] for s in schemas]
    assert _FUNC_NAME_ANALYZE in names
    assert _FUNC_NAME_DECOMPILE in names


def test_google_no_function_wrapper() -> None:
    """Verify Google declarations don't have OpenAI's type=function wrapper."""
    tool = _make_tool()
    schemas = create_google_tool_schema(tool)
    schema = schemas[0]

    assert "type" not in schema
    assert "function" not in schema


def test_google_empty_functions_returns_empty() -> None:
    """Verify a ToolDefinition with no functions yields an empty list."""
    assert create_google_tool_schema(_make_empty_tool()) == []


def test_consistency_all_formats_produce_same_count() -> None:
    """All three builders must yield the same number of schemas."""
    tool = _make_tool(multi_function=True)

    openai = create_openai_tool_schema(tool)
    anthropic = create_anthropic_tool_schema(tool)
    google = create_google_tool_schema(tool)

    assert len(openai) == len(anthropic) == len(google) == _EXPECTED_MULTI_FUNC_COUNT


def test_consistency_all_formats_preserve_function_names() -> None:
    """All formats must preserve the original function names."""
    tool = _make_tool(multi_function=True)

    openai_names = [s["function"]["name"] for s in create_openai_tool_schema(tool)]
    anthropic_names = [s["name"] for s in create_anthropic_tool_schema(tool)]
    google_names = [s["name"] for s in create_google_tool_schema(tool)]

    expected = {_FUNC_NAME_ANALYZE, _FUNC_NAME_DECOMPILE}
    assert set(openai_names) == expected
    assert set(anthropic_names) == expected
    assert set(google_names) == expected


def test_consistency_all_formats_include_defaults() -> None:
    """All formats must include default values when present."""
    tool = _make_tool(with_default=True)

    openai_props = create_openai_tool_schema(tool)[0]["function"]["parameters"]["properties"]
    anthropic_props = create_anthropic_tool_schema(tool)[0]["input_schema"]["properties"]
    google_props = create_google_tool_schema(tool)[0]["parameters"]["properties"]

    for props in (openai_props, anthropic_props, google_props):
        assert props["timeout"].get("default") == _EXPECTED_DEFAULT_TIMEOUT


@pytest.mark.parametrize(
    ("param_type", "expected_google_type"),
    [
        ("string", "STRING"),
        ("integer", "INTEGER"),
        ("boolean", "BOOLEAN"),
        ("number", "NUMBER"),
        ("array", "ARRAY"),
    ],
)
def test_google_uppercase_conversion(
    param_type: str,
    expected_google_type: str,
) -> None:
    """Google format must uppercase all JSON Schema type names."""
    tool = ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="Test",
        functions=[
            ToolFunction(
                name="test.func",
                description="Test function",
                parameters=[
                    ToolParameter(
                        name="param",
                        type=param_type,
                        description="A parameter",
                    ),
                ],
                returns="Result",
            ),
        ],
    )
    schemas = create_google_tool_schema(tool)
    prop_type = schemas[0]["parameters"]["properties"]["param"].get("type")
    assert prop_type == expected_google_type
