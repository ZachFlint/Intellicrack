# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for bridges.schemas module - JSON Schema generation for LLM tool calling."""

from __future__ import annotations

from typing import Final

import pytest

from intellicrack.bridges.schemas import (
    ValidationError,
    build_schema_parameters,
    build_schema_property,
    get_all_schemas_for_provider,
    get_schema_for_provider,
    normalize_type,
    to_anthropic_schema,
    to_google_schema,
    to_ollama_schema,
    to_openai_schema,
    to_openrouter_schema,
    validate_and_convert,
    validate_tool_definition,
    validate_tool_function,
    validate_tool_parameter,
)
from intellicrack.core.types import (
    ProviderName,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)


_FUNC_NAME: Final[str] = "binary.analyze"
_FUNC_DESC: Final[str] = "Analyze binary"
_PARAM_DESC: Final[str] = "A parameter"
_TOOL_DESC: Final[str] = "Binary analysis tool"
_ENUM_LIST: Final[list[str]] = ["a", "b", "c"]
_MULTI_COUNT: Final[int] = 2


def _param(
    name: str = "target",
    param_type: str = "string",
    description: str = _PARAM_DESC,
    *,
    required: bool = True,
    enum: list[str] | None = None,
    default: str | float | bool | None = None,
) -> ToolParameter:
    """Build a ToolParameter with defaults for concise test setup.

    Args:
        name: Parameter name.
        param_type: JSON Schema type string.
        description: Parameter description.
        required: Whether the parameter is required.
        enum: Optional list of allowed values.
        default: Optional default value.

    Returns:
        ToolParameter: Configured ToolParameter instance.
    """
    return ToolParameter(
        name=name,
        type=param_type,
        description=description,
        required=required,
        enum=enum,
        default=default,
    )


def _func(
    name: str = _FUNC_NAME,
    description: str = _FUNC_DESC,
    params: list[ToolParameter] | None = None,
) -> ToolFunction:
    """Build a ToolFunction with defaults for concise test setup.

    Args:
        name: Function name in tool.function format.
        description: Function description.
        params: Optional parameter list.

    Returns:
        ToolFunction: Configured ToolFunction instance.
    """
    return ToolFunction(
        name=name,
        description=description,
        parameters=params or [_param()],
        returns="Analysis result",
    )


def _tool(
    functions: list[ToolFunction] | None = None,
) -> ToolDefinition:
    """Build a ToolDefinition with defaults for concise test setup.

    Args:
        functions: Optional function list.

    Returns:
        ToolDefinition: Configured ToolDefinition instance.
    """
    return ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description=_TOOL_DESC,
        functions=functions or [_func()],
    )


@pytest.mark.parametrize(
    ("input_type", "expected"),
    [
        ("string", "string"),
        ("integer", "integer"),
        ("boolean", "boolean"),
        ("number", "number"),
        ("array", "array"),
        ("object", "object"),
        ("null", "null"),
        ("str", "string"),
        ("int", "integer"),
        ("float", "number"),
        ("bool", "boolean"),
        ("list", "array"),
        ("dict", "object"),
        ("None", "string"),
        ("NoneType", "string"),
        ("STRING", "string"),
        ("  string  ", "string"),
        ("unknown_type", "string"),
    ],
)
def test_normalize_type(input_type: str, expected: str) -> None:
    """Verify type normalization for various inputs.

    Args:
        input_type: Raw type string input.
        expected: Expected normalized JSON Schema type.
    """
    assert normalize_type(input_type) == expected


def test_build_schema_property_basic() -> None:
    """Verify basic property has type and description."""
    prop = build_schema_property(_param())
    assert prop.get("type") == "string"
    assert prop.get("description") == _PARAM_DESC
    assert "enum" not in prop
    assert "default" not in prop


def test_build_schema_property_with_enum() -> None:
    """Verify enum values are included when present."""
    prop = build_schema_property(_param(enum=list(_ENUM_LIST)))
    assert prop.get("enum") == _ENUM_LIST


def test_build_schema_property_with_default() -> None:
    """Verify default value is included when present."""
    prop = build_schema_property(_param(required=False, default="x"))
    assert prop.get("default") == "x"


def test_build_schema_property_uppercase() -> None:
    """Verify uppercase type names for Google format."""
    prop = build_schema_property(_param(param_type="string"), uppercase_types=True)
    assert prop.get("type") == "STRING"


def test_build_schema_property_uppercase_integer() -> None:
    """Verify uppercase INTEGER for Google format."""
    prop = build_schema_property(_param(param_type="integer"), uppercase_types=True)
    assert prop.get("type") == "INTEGER"


def test_build_schema_property_empty_enum_excluded() -> None:
    """Verify empty enum list is not added to property."""
    prop = build_schema_property(_param(enum=[]))
    assert "enum" not in prop


def test_build_schema_parameters_empty() -> None:
    """Verify empty parameter list produces empty schema."""
    result = build_schema_parameters([])
    assert result["type"] == "object"
    assert result["properties"] == {}
    assert result["required"] == []


def test_build_schema_parameters_required_only() -> None:
    """Verify required parameters appear in required list."""
    params = [_param(name="a"), _param(name="b")]
    result = build_schema_parameters(params)
    assert "a" in result["properties"]
    assert "b" in result["properties"]
    assert result["required"] == ["a", "b"]


def test_build_schema_parameters_optional_only() -> None:
    """Verify optional parameters produce empty required list."""
    params = [_param(name="opt", required=False, default="x")]
    result = build_schema_parameters(params)
    assert result["required"] == []


def test_build_schema_parameters_mixed() -> None:
    """Verify mixed required/optional parameters."""
    params = [
        _param(name="req", required=True),
        _param(name="opt", required=False),
    ]
    result = build_schema_parameters(params)
    assert result["required"] == ["req"]


def test_build_schema_parameters_google_uppercase() -> None:
    """Verify Google format uses OBJECT and uppercase types."""
    params = [_param(name="x", param_type="string")]
    result = build_schema_parameters(params, uppercase_types=True)
    assert result["type"] == "OBJECT"
    assert result["properties"]["x"].get("type") == "STRING"


def test_validate_parameter_valid() -> None:
    """Verify valid parameter produces no errors."""
    errors = validate_tool_parameter(_param(), "func")
    assert len(errors) == 0


def test_validate_parameter_empty_name() -> None:
    """Verify empty name produces error."""
    errors = validate_tool_parameter(_param(name=""), "func")
    assert any("empty" in e.message.lower() for e in errors)


def test_validate_parameter_invalid_name() -> None:
    """Verify invalid identifier produces error."""
    errors = validate_tool_parameter(_param(name="123bad"), "func")
    assert any("invalid" in e.message.lower() for e in errors)


def test_validate_parameter_empty_description() -> None:
    """Verify empty description produces warning."""
    errors = validate_tool_parameter(_param(description=""), "func")
    warnings = [e for e in errors if e.severity == "warning"]
    assert any("description" in w.message.lower() for w in warnings)


def test_validate_parameter_required_with_default() -> None:
    """Verify required param with default produces warning."""
    errors = validate_tool_parameter(_param(required=True, default="val"), "func")
    warnings = [e for e in errors if e.severity == "warning"]
    assert any("required" in w.message.lower() for w in warnings)


def test_validate_parameter_empty_enum() -> None:
    """Verify empty enum list produces error."""
    errors = validate_tool_parameter(_param(enum=[]), "func")
    assert any("enum" in e.message.lower() for e in errors)


def test_validate_parameter_default_not_in_enum() -> None:
    """Verify default not in enum produces error."""
    errors = validate_tool_parameter(_param(required=False, enum=["a", "b"], default="c"), "func")
    assert any("not in enum" in e.message.lower() for e in errors)


def test_validate_parameter_valid_enum_with_default() -> None:
    """Verify valid default in enum produces no error."""
    errors = validate_tool_parameter(_param(required=False, enum=["a", "b"], default="a"), "func")
    error_level = [e for e in errors if e.severity == "error"]
    assert not error_level


def test_validate_function_valid() -> None:
    """Verify valid function produces no errors."""
    errors = validate_tool_function(_func())
    error_level = [e for e in errors if e.severity == "error"]
    assert not error_level


def test_validate_function_empty_name() -> None:
    """Verify empty function name produces error."""
    errors = validate_tool_function(_func(name=""))
    assert any("empty" in e.message.lower() for e in errors)


def test_validate_function_no_dot_warning() -> None:
    """Verify name without dot produces warning."""
    errors = validate_tool_function(_func(name="nodot"))
    warnings = [e for e in errors if e.severity == "warning"]
    assert any("pattern" in w.message.lower() for w in warnings)


def test_validate_function_empty_description() -> None:
    """Verify empty description produces warning."""
    errors = validate_tool_function(_func(description=""))
    warnings = [e for e in errors if e.severity == "warning"]
    assert any("description" in w.message.lower() for w in warnings)


def test_validate_function_duplicate_params() -> None:
    """Verify duplicate parameter names produce error."""
    f = _func(params=[_param(name="dup"), _param(name="dup")])
    errors = validate_tool_function(f)
    assert any("duplicate" in e.message.lower() for e in errors)


def test_validate_definition_valid() -> None:
    """Verify valid tool definition produces no errors."""
    errors = validate_tool_definition(_tool())
    error_level = [e for e in errors if e.severity == "error"]
    assert not error_level


def test_validate_definition_empty_description() -> None:
    """Verify empty description produces warning."""
    t = ToolDefinition(tool_name=ToolName.GHIDRA, description="", functions=[_func()])
    errors = validate_tool_definition(t)
    assert any("description" in e.message.lower() for e in errors)


def test_validate_definition_no_functions() -> None:
    """Verify zero functions produces error."""
    t = ToolDefinition(tool_name=ToolName.GHIDRA, description="desc", functions=[])
    errors = validate_tool_definition(t)
    assert any("at least one" in e.message.lower() for e in errors)


def test_validate_definition_duplicate_functions() -> None:
    """Verify duplicate function names produce error."""
    t = _tool(functions=[_func(name="binary.f"), _func(name="binary.f")])
    errors = validate_tool_definition(t)
    assert any("duplicate" in e.message.lower() for e in errors)


def test_validation_error_str_error() -> None:
    """Verify error-level string format."""
    err = ValidationError("bad", "loc", "error")
    assert str(err) == "[ERROR] loc: bad"


def test_validation_error_str_warning() -> None:
    """Verify warning-level string format."""
    err = ValidationError("warn", "loc", "warning")
    assert str(err) == "[WARNING] loc: warn"


def test_to_anthropic_schema_single() -> None:
    """Verify single function produces one Anthropic schema."""
    schemas = to_anthropic_schema(_tool())
    assert len(schemas) == 1
    s = schemas[0]
    assert s["name"] == _FUNC_NAME
    assert "input_schema" in s
    assert s["input_schema"]["type"] == "object"


def test_to_anthropic_schema_multi() -> None:
    """Verify multiple functions produce multiple schemas."""
    t = _tool(functions=[_func(name="binary.a"), _func(name="binary.b")])
    schemas = to_anthropic_schema(t)
    assert len(schemas) == _MULTI_COUNT


def test_to_openai_schema_single() -> None:
    """Verify single function produces one OpenAI schema."""
    schemas = to_openai_schema(_tool())
    assert len(schemas) == 1
    s = schemas[0]
    assert s["type"] == "function"
    assert s["function"]["name"] == _FUNC_NAME
    assert "parameters" in s["function"]


def test_to_openai_schema_multi() -> None:
    """Verify multiple functions produce multiple schemas."""
    t = _tool(functions=[_func(name="binary.a"), _func(name="binary.b")])
    schemas = to_openai_schema(t)
    assert len(schemas) == _MULTI_COUNT


def test_to_google_schema_single() -> None:
    """Verify single function produces one Google schema with OBJECT type."""
    schemas = to_google_schema(_tool())
    assert len(schemas) == 1
    s = schemas[0]
    assert s["name"] == _FUNC_NAME
    assert s["parameters"]["type"] == "OBJECT"
    assert s["parameters"]["properties"]["target"].get("type") == "STRING"


def test_to_google_schema_multi() -> None:
    """Verify multiple functions produce multiple schemas."""
    t = _tool(functions=[_func(name="binary.a"), _func(name="binary.b")])
    schemas = to_google_schema(t)
    assert len(schemas) == _MULTI_COUNT


def test_ollama_matches_openai() -> None:
    """Verify Ollama format matches OpenAI format."""
    t = _tool()
    assert to_ollama_schema(t) == to_openai_schema(t)


def test_openrouter_matches_openai() -> None:
    """Verify OpenRouter format matches OpenAI format."""
    t = _tool()
    assert to_openrouter_schema(t) == to_openai_schema(t)


@pytest.mark.parametrize("provider", list(ProviderName))
def test_get_schema_for_provider_all(provider: ProviderName) -> None:
    """Verify schema generation works for every provider.

    Args:
        provider: The LLM provider to test.
    """
    result = get_schema_for_provider(_tool(), provider)
    assert len(result) == 1


def test_get_schema_for_provider_google_uppercase() -> None:
    """Verify Google provider uses OBJECT type."""
    tool = _tool()
    typed_result = to_google_schema(tool)
    assert typed_result[0]["parameters"]["type"] == "OBJECT"
    result = get_schema_for_provider(tool, ProviderName.GOOGLE)
    assert result == [dict(s) for s in typed_result]


def test_get_schema_for_provider_anthropic_input_schema() -> None:
    """Verify Anthropic provider uses input_schema key."""
    tool = _tool()
    typed_result = to_anthropic_schema(tool)
    assert typed_result[0]["input_schema"]["type"] == "object"
    result = get_schema_for_provider(tool, ProviderName.ANTHROPIC)
    assert result == [dict(s) for s in typed_result]


def test_get_schema_for_provider_openai_function_type() -> None:
    """Verify OpenAI provider uses function type."""
    tool = _tool()
    typed_result = to_openai_schema(tool)
    assert typed_result[0]["type"] == "function"
    result = get_schema_for_provider(tool, ProviderName.OPENAI)
    assert result == [dict(s) for s in typed_result]


def test_get_all_schemas_empty() -> None:
    """Verify empty tool list produces empty schema list."""
    result = get_all_schemas_for_provider([], ProviderName.OPENAI)
    assert result == []


def test_get_all_schemas_multiple() -> None:
    """Verify multiple tools are flattened into one list."""
    tools = [_tool(), _tool()]
    result = get_all_schemas_for_provider(tools, ProviderName.OPENAI)
    assert len(result) == _MULTI_COUNT


def test_validate_and_convert_valid() -> None:
    """Verify valid tool converts with no error-level issues."""
    schemas, errors = validate_and_convert(_tool(), ProviderName.OPENAI)
    assert len(schemas) == 1
    error_level = [e for e in errors if e.severity == "error"]
    assert not error_level


def test_validate_and_convert_invalid() -> None:
    """Verify invalid tool returns empty schemas."""
    t = ToolDefinition(tool_name=ToolName.GHIDRA, description="d", functions=[])
    schemas, errors = validate_and_convert(t, ProviderName.OPENAI)
    assert schemas == []
    assert len(errors) > 0


def test_validate_and_convert_warnings_still_convert() -> None:
    """Verify warnings-only tool still converts successfully."""
    t = ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="",
        functions=[_func()],
    )
    schemas, errors = validate_and_convert(t, ProviderName.OPENAI)
    assert len(schemas) == 1
    assert len(errors) > 0
