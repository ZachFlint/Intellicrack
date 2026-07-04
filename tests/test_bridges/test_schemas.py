# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for bridges.schemas module - JSON Schema generation for LLM tool calling."""

from __future__ import annotations

import math
from typing import Any, Final, cast

import jsonschema
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

_OPENAI_FORMAT_PROVIDERS: Final[frozenset[ProviderName]] = frozenset({
    ProviderName.OPENAI,
    ProviderName.OLLAMA,
    ProviderName.OPENROUTER,
    ProviderName.HUGGINGFACE,
    ProviderName.GROK,
    ProviderName.LOCAL_TRANSFORMERS,
})


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
    """Verify basic string property is a Draft-7 compliant schema that correctly validates instances.

    The independent oracle is the jsonschema Draft7Validator: it validates the
    property dict against the JSON Schema meta-schema via ``check_schema`` and
    then uses the produced schema as a validator for real inputs.  If
    ``build_schema_property`` emits a structurally invalid schema (wrong key
    names, wrong type string encoding, missing required keys) the meta-schema
    check raises ``SchemaError`` or the instance validation raises
    ``ValidationError``, surfacing the regression without re-implementing the
    production logic.
    """
    prop = build_schema_property(_param())

    assert prop.get("type") == "string"
    assert prop.get("description") == _PARAM_DESC
    assert "enum" not in prop
    assert "default" not in prop
    assert set(prop.keys()) == {"type", "description"}

    jsonschema.Draft7Validator.check_schema(prop)

    instance_schema: dict[str, object] = {
        "type": "object",
        "properties": {"target": prop},
        "required": ["target"],
    }
    jsonschema.validate({"target": "/bin/ls"}, instance_schema)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'string'"):
        jsonschema.validate({"target": 0xDEAD}, instance_schema)

    with pytest.raises(jsonschema.ValidationError, match="'target' is a required property"):
        jsonschema.validate({}, instance_schema)


@pytest.mark.parametrize(
    ("json_type", "items_type", "valid_instance", "invalid_instance", "invalid_match"),
    [
        ("integer", "string", 42, "not-an-int", "is not of type 'integer'"),
        ("boolean", "string", True, 1, "is not of type 'boolean'"),
        ("number", "string", math.pi, "pi", "is not of type 'number'"),
        ("object", "string", {"k": "v"}, "not-an-object", "is not of type 'object'"),
        ("array", "integer", [10, 20, 30], "not-an-array", "is not of type 'array'"),
        ("null", "string", None, "not-null", "is not of type 'null'"),
    ],
)
def test_build_schema_property_all_types_draft7_compliant(
    json_type: str,
    items_type: str,
    valid_instance: object,
    invalid_instance: object,
    invalid_match: str,
) -> None:
    """Verify every JSON Schema type produces a Draft-7 compliant property that enforces type constraints.

    The independent oracle is jsonschema.Draft7Validator.check_schema which
    validates the property dict against the JSON Schema Draft-7 meta-schema.
    If build_schema_property produces an invalid type string (e.g. capitalised
    or abbreviated), check_schema raises SchemaError and the test fails.  The
    subsequent validate() calls confirm the schema actively enforces the correct
    type: a conforming instance passes and a non-conforming instance raises
    jsonschema.ValidationError with the expected message fragment.  Removing or
    corrupting the ``type`` key in build_schema_property would make check_schema
    pass but the enforcement assertions fail, and vice versa.

    Args:
        json_type: The JSON Schema type string to test.
        items_type: The items type for array parameters (ignored for non-array).
        valid_instance: An instance that must validate successfully.
        invalid_instance: An instance that must fail validation.
        invalid_match: Substring expected in the ValidationError message.
    """
    param = ToolParameter(
        name="x",
        type=json_type,
        description="Test parameter",
        required=True,
        items_type=items_type,
    )
    prop = build_schema_property(param)

    assert prop.get("type") == json_type, f"Expected type={json_type!r}, got {prop.get('type')!r}"
    assert prop.get("description") == "Test parameter"

    if json_type == "array":
        assert "items" in prop, "Array property must include 'items' key"
        items = prop["items"]
        assert isinstance(items, dict)
        assert items.get("type") == items_type, f"Array items type must be {items_type!r}, got {items.get('type')!r}"
        jsonschema.Draft7Validator.check_schema(items)

    jsonschema.Draft7Validator.check_schema(prop)

    parent_schema: dict[str, object] = {
        "type": "object",
        "properties": {"x": prop},
        "required": ["x"],
    }
    jsonschema.validate({"x": valid_instance}, parent_schema)

    with pytest.raises(jsonschema.ValidationError, match=invalid_match):
        jsonschema.validate({"x": invalid_instance}, parent_schema)


def test_build_schema_property_array_items_type_enforced() -> None:
    """Verify that the items sub-schema inside an array property enforces element types.

    If build_schema_property fails to propagate items_type into the ``items``
    sub-schema, an array of wrong-typed elements would silently pass validation.
    The independent oracle is jsonschema.validate: it validates each element
    against the ``items`` sub-schema and raises ValidationError when an element
    violates the type constraint.  Removing the ``items`` key or setting the
    wrong type in _build_array_items makes the second validate() call pass
    instead of raising, which is the regression signal.
    """
    param = ToolParameter(
        name="section_rvas",
        type="array",
        description="RVA list for PE sections",
        required=True,
        items_type="integer",
    )
    prop = build_schema_property(param)

    assert prop.get("type") == "array"
    assert "items" in prop
    items_schema = prop["items"]
    assert isinstance(items_schema, dict)
    assert items_schema.get("type") == "integer"

    jsonschema.Draft7Validator.check_schema(prop)

    parent: dict[str, object] = {
        "type": "object",
        "properties": {"section_rvas": prop},
        "required": ["section_rvas"],
    }
    jsonschema.validate({"section_rvas": [0x1000, 0x2000, 0x3000]}, parent)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'integer'"):
        jsonschema.validate({"section_rvas": [".text", ".data"]}, parent)


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
    """Verify empty parameter list produces a Draft-7 compliant parameters schema.

    The schema must:
    - Conform to the JSON Schema Draft-7 meta-schema (tested via jsonschema).
    - Accept an empty argument object ``{}`` (the correct call-args for a
      zero-parameter tool function - providers such as Anthropic and OpenAI
      pass ``{}`` for tools with no parameters).
    - Reject non-object argument shapes (string, integer, null) that would
      cause the LLM provider to reject the tool call at parse time.
    - Carry exactly the three keys ``type``, ``properties``, and ``required``
      that tool-calling providers expect; no extra keys, no missing keys.

    The independent oracle is jsonschema.Draft7Validator.check_schema: it
    validates the produced schema dict against the official JSON Schema Draft-7
    meta-schema.  If build_schema_parameters emits wrong key names, wrong type
    literals, or an invalid structure, check_schema raises SchemaError before
    the provider receives the schema, surfacing the defect.  The validate()
    calls confirm the schema actively enforces object type: non-object values
    are rejected with the provider-visible error message fragment.
    """
    result = build_schema_parameters([])

    assert result["type"] == "object"
    assert result["properties"] == {}
    assert result["required"] == []
    assert set(result.keys()) == {"type", "properties", "required"}

    jsonschema.Draft7Validator.check_schema(result)

    jsonschema.validate({}, result)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'object'"):
        jsonschema.validate("not-an-object", result)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'object'"):
        jsonschema.validate(42, result)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'object'"):
        jsonschema.validate(None, result)


def test_build_schema_parameters_realistic_tool_call_payload() -> None:
    """Verify a multi-type parameters schema matches the shape real LLM providers receive.

    This test drives a real Ghidra-style decompile function parameter set through
    build_schema_parameters, confirms the produced schema passes Draft-7 meta-schema
    validation, then validates a realistic LLM tool-call payload against it.

    The independent oracle is jsonschema.Draft7Validator.  Correct required-field
    enforcement, per-type constraints, enum constraints, and array items are all
    verified by validating known-correct and known-incorrect call payloads.  If any
    production code path silently drops a parameter, corrupts a type string, or omits
    the required list, one of the assertions below will fail.
    """
    params: list[ToolParameter] = [
        _param(name="binary_path", param_type="string", description="Path to the target binary"),
        _param(name="function_address", param_type="integer", description="Entry point RVA"),
        _param(name="max_depth", param_type="integer", description="Decompile depth limit"),
        _param(name="include_comments", param_type="boolean", description="Include inline comments", required=False, default=False),
        _param(name="confidence_threshold", param_type="number", description="Minimum confidence", required=False),
        _param(name="output_format", param_type="string", description="Output format", required=True, enum=["c", "pseudocode", "asm"]),
    ]

    schema = build_schema_parameters(params)

    assert schema["type"] == "object"
    required_list: object = schema["required"]
    assert isinstance(required_list, list)
    assert sorted(required_list) == sorted(["binary_path", "function_address", "max_depth", "output_format"])

    properties: object = schema["properties"]
    assert isinstance(properties, dict)
    assert set(properties.keys()) == {
        "binary_path",
        "function_address",
        "max_depth",
        "include_comments",
        "confidence_threshold",
        "output_format",
    }

    assert properties["binary_path"].get("type") == "string"
    assert properties["function_address"].get("type") == "integer"
    assert properties["max_depth"].get("type") == "integer"
    assert properties["include_comments"].get("type") == "boolean"
    assert properties["include_comments"].get("default") is False
    assert properties["confidence_threshold"].get("type") == "number"
    assert properties["output_format"].get("type") == "string"
    assert properties["output_format"].get("enum") == ["c", "pseudocode", "asm"]

    jsonschema.Draft7Validator.check_schema(schema)

    valid_payload: dict[str, object] = {
        "binary_path": "/opt/samples/target.exe",
        "function_address": 0x00401000,
        "max_depth": 10,
        "include_comments": True,
        "confidence_threshold": 0.75,
        "output_format": "c",
    }
    jsonschema.validate(valid_payload, schema)

    minimal_payload: dict[str, object] = {
        "binary_path": "/opt/samples/target.exe",
        "function_address": 0x00401000,
        "max_depth": 5,
        "output_format": "pseudocode",
    }
    jsonschema.validate(minimal_payload, schema)

    with pytest.raises(jsonschema.ValidationError, match="is a required property"):
        jsonschema.validate({"binary_path": "/opt/samples/target.exe"}, schema)

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'integer'"):
        jsonschema.validate(
            {
                "binary_path": "/opt/samples/target.exe",
                "function_address": "0x00401000",
                "max_depth": 5,
                "output_format": "c",
            },
            schema,
        )

    with pytest.raises(jsonschema.ValidationError, match="is not one of"):
        jsonschema.validate(
            {
                "binary_path": "/opt/samples/target.exe",
                "function_address": 0x00401000,
                "max_depth": 5,
                "output_format": "decompiled",
            },
            schema,
        )

    with pytest.raises(jsonschema.ValidationError, match="is not of type 'number'"):
        jsonschema.validate(
            {
                "binary_path": "/opt/samples/target.exe",
                "function_address": 0x00401000,
                "max_depth": 5,
                "output_format": "asm",
                "confidence_threshold": "high",
            },
            schema,
        )


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
    """Verify schema generation works for every provider and routes to the correct format.

    The format discriminators mirror the dispatch logic in ``get_schema_for_provider``:
    ANTHROPIC → ``input_schema`` key (Anthropic format, no ``type: function``);
    GOOGLE → ``parameters.type == 'OBJECT'`` (Google format, uppercase type);
    all others → ``type == 'function'`` (OpenAI-compatible format). The explicit
    check on HUGGINGFACE, GROK, and LOCAL_TRANSFORMERS verifies each one does NOT
    receive Anthropic format, catching a routing regression where a new provider
    branch is accidentally wired to ``to_anthropic_schema``.

    Args:
        provider: The LLM provider to test.
    """
    result = get_schema_for_provider(_tool(), provider)
    assert len(result) == 1
    schema = result[0]

    if provider == ProviderName.ANTHROPIC:
        assert "input_schema" in schema, f"ANTHROPIC must use Anthropic format with 'input_schema' key; got keys: {list(schema.keys())}"
        assert schema.get("type") != "function", "ANTHROPIC format must NOT have type='function' at top level"
    elif provider == ProviderName.GOOGLE:
        params: dict[str, Any] = cast(dict[str, Any], schema.get("parameters") or {})
        assert params.get("type") == "OBJECT", f"GOOGLE must have parameters.type='OBJECT' (uppercase); got {params.get('type')!r}"
        assert "input_schema" not in schema, "GOOGLE must NOT use Anthropic input_schema format"
    else:
        assert provider in _OPENAI_FORMAT_PROVIDERS, (
            f"Unhandled provider {provider!r}; add it to _OPENAI_FORMAT_PROVIDERS or a dedicated branch"
        )
        assert schema.get("type") == "function", (
            f"{provider.value!r} must use OpenAI format with type='function'; got type={schema.get('type')!r}"
        )
        assert "input_schema" not in schema, (
            f"{provider.value!r} must NOT use Anthropic format ('input_schema' found); "
            "HUGGINGFACE, GROK, LOCAL_TRANSFORMERS, OLLAMA, OPENROUTER all route to OpenAI schema"
        )


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
