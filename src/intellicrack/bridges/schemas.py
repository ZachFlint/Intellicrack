# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""JSON Schema generation for LLM tool calling.

This module provides centralized schema generation for converting Intellicrack
tool definitions to provider-specific formats for LLM function calling.
Supports Anthropic, OpenAI, Google Gemini, Ollama, and OpenRouter.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Never, TypedDict

from ..core.types import (
    ProviderName,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)


def _assert_never(value: Never) -> Never:
    """Assert that a code path is never reached.

    Used for exhaustive enum matching to ensure all cases are handled.

    Args:
        value: A value of type Never (should be impossible to call).

    Raises:
        AssertionError: Always raised if this function is somehow called.
    """
    msg = f"Unexpected value: {value!r}"
    raise AssertionError(msg)


VALID_JSON_SCHEMA_TYPES: frozenset[str] = frozenset({
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "object",
    "null",
})

PYTHON_TO_JSON_TYPES: dict[str, str] = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
    "None": "null",
    "NoneType": "null",
}

GOOGLE_TYPE_MAP: dict[str, str] = {
    "string": "STRING",
    "integer": "INTEGER",
    "number": "NUMBER",
    "boolean": "BOOLEAN",
    "array": "ARRAY",
    "object": "OBJECT",
    "null": "NULL",
}


class JSONSchemaProperty(TypedDict, total=False):
    """JSON Schema property definition for tool parameters."""

    type: str
    description: str
    enum: list[str]
    default: str | int | float | bool | None


class JSONSchemaParameters(TypedDict):
    """JSON Schema parameters object for tool functions."""

    type: Literal["object", "OBJECT"]
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


class GoogleSchemaProperty(TypedDict, total=False):
    """Google Gemini schema property with uppercase types."""

    type: str
    description: str
    enum: list[str]
    default: str | int | float | bool | None


class GoogleSchemaParameters(TypedDict):
    """Google Gemini schema parameters with OBJECT type."""

    type: Literal["OBJECT"]
    properties: dict[str, GoogleSchemaProperty]
    required: list[str]


class AnthropicToolSchema(TypedDict):
    """Anthropic Claude tool schema format."""

    name: str
    description: str
    input_schema: JSONSchemaParameters


class OpenAIFunctionSchema(TypedDict):
    """OpenAI function definition within a tool."""

    name: str
    description: str
    parameters: JSONSchemaParameters


class OpenAIToolSchema(TypedDict):
    """OpenAI tool schema format."""

    type: Literal["function"]
    function: OpenAIFunctionSchema


class GoogleFunctionDeclaration(TypedDict):
    """Google Gemini function declaration format."""

    name: str
    description: str
    parameters: GoogleSchemaParameters


class ValidationError:
    """Represents a validation error in a tool definition."""

    def __init__(
        self,
        message: str,
        location: str,
        severity: Literal["error", "warning"] = "error",
    ) -> None:
        """Initialize validation error.

        Args:
            message: Error description.
            location: Where the error occurred (e.g., "func.param").
            severity: Error severity level.
        """
        self.message = message
        self.location = location
        self.severity = severity

    def __str__(self) -> str:
        """Return string representation.

        Returns:
            Formatted string showing severity, location, and message.
        """
        return f"[{self.severity.upper()}] {self.location}: {self.message}"


def normalize_type(param_type: str) -> str:
    """Normalize a parameter type to JSON Schema type.

    Handles Python type names and ensures consistent type strings.

    Args:
        param_type: The type string to normalize.

    Returns:
        Normalized JSON Schema type string.
    """
    param_type_lower = param_type.lower().strip()
    if param_type_lower in PYTHON_TO_JSON_TYPES:
        return PYTHON_TO_JSON_TYPES[param_type_lower]
    if param_type_lower in VALID_JSON_SCHEMA_TYPES:
        return param_type_lower
    return "string"


def build_schema_property(
    param: ToolParameter,
    uppercase_types: bool = False,
) -> JSONSchemaProperty | GoogleSchemaProperty:
    """Build a JSON Schema property from a ToolParameter.

    Args:
        param: The tool parameter to convert.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaProperty or GoogleSchemaProperty dict.
    """
    param_type = normalize_type(param.type)
    if uppercase_types:
        param_type = GOOGLE_TYPE_MAP.get(param_type, param_type.upper())

    prop: JSONSchemaProperty = {
        "type": param_type,
        "description": param.description,
    }

    if param.enum is not None and len(param.enum) > 0:
        prop["enum"] = param.enum

    if param.default is not None:
        prop["default"] = param.default

    return prop


def _build_json_schema_parameters(
    params: list[ToolParameter],
) -> JSONSchemaParameters:
    """Build JSON Schema parameters for Anthropic/OpenAI/Ollama/OpenRouter.

    Args:
        params: List of tool parameters.

    Returns:
        JSONSchemaParameters dict with lowercase types.
    """
    properties: dict[str, JSONSchemaProperty] = {}
    required: list[str] = []

    for param in params:
        prop = build_schema_property(param, uppercase_types=False)
        properties[param.name] = prop
        if param.required:
            required.append(param.name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


def _build_google_schema_parameters(
    params: list[ToolParameter],
) -> GoogleSchemaParameters:
    """Build Google Gemini schema parameters with uppercase types.

    Args:
        params: List of tool parameters.

    Returns:
        GoogleSchemaParameters dict with uppercase types.
    """
    properties: dict[str, GoogleSchemaProperty] = {}
    required: list[str] = []

    for param in params:
        param_type = normalize_type(param.type)
        google_type = GOOGLE_TYPE_MAP.get(param_type, param_type.upper())

        prop: GoogleSchemaProperty = {
            "type": google_type,
            "description": param.description,
        }
        if param.enum is not None and len(param.enum) > 0:
            prop["enum"] = param.enum
        if param.default is not None:
            prop["default"] = param.default

        properties[param.name] = prop
        if param.required:
            required.append(param.name)

    return {
        "type": "OBJECT",
        "properties": properties,
        "required": required,
    }


def build_schema_parameters(
    params: list[ToolParameter],
    uppercase_types: bool = False,
) -> JSONSchemaParameters | GoogleSchemaParameters:
    """Build complete parameter schema from list of parameters.

    Args:
        params: List of tool parameters.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaParameters or GoogleSchemaParameters dict.
    """
    if uppercase_types:
        return _build_google_schema_parameters(params)
    return _build_json_schema_parameters(params)


def validate_tool_parameter(
    param: ToolParameter,
    func_name: str,
) -> list[ValidationError]:
    """Validate a single tool parameter.

    Args:
        param: The parameter to validate.
        func_name: Name of the containing function for error context.

    Returns:
        List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []
    location = f"{func_name}.{param.name}"

    if not param.name:
        errors.append(
            ValidationError(
                "Parameter name cannot be empty",
                location,
            )
        )
    elif not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", param.name):
        errors.append(
            ValidationError(
                f"Invalid parameter name '{param.name}' (must be valid identifier)",
                location,
            )
        )

    normalized_type = normalize_type(param.type)
    if normalized_type not in VALID_JSON_SCHEMA_TYPES:
        errors.append(
            ValidationError(
                f"Invalid type '{param.type}' (normalized to '{normalized_type}')",
                location,
                "warning",
            )
        )

    if not param.description:
        errors.append(
            ValidationError(
                "Parameter description should not be empty",
                location,
                "warning",
            )
        )

    if param.required and param.default is not None:
        errors.append(
            ValidationError(
                "Required parameter should not have a default value",
                location,
                "warning",
            )
        )

    if param.enum is not None:
        if len(param.enum) == 0:
            errors.append(
                ValidationError(
                    "Enum list cannot be empty",
                    location,
                )
            )
        elif param.default is not None and param.default not in param.enum:
            errors.append(
                ValidationError(
                    f"Default value '{param.default}' not in enum {param.enum}",
                    location,
                )
            )

    return errors


def validate_tool_function(func: ToolFunction) -> list[ValidationError]:
    """Validate a tool function definition.

    Args:
        func: The function to validate.

    Returns:
        List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []

    if not func.name:
        errors.append(
            ValidationError(
                "Function name cannot be empty",
                "function",
            )
        )
    elif "." not in func.name:
        errors.append(
            ValidationError(
                f"Function name '{func.name}' should follow 'tool.function' pattern",
                func.name,
                "warning",
            )
        )

    if not func.description:
        errors.append(
            ValidationError(
                "Function description should not be empty",
                func.name or "function",
                "warning",
            )
        )

    param_names: set[str] = set()
    for param in func.parameters:
        if param.name in param_names:
            errors.append(
                ValidationError(
                    f"Duplicate parameter name '{param.name}'",
                    func.name or "function",
                )
            )
        param_names.add(param.name)
        errors.extend(validate_tool_parameter(param, func.name))

    return errors


def validate_tool_definition(tool: ToolDefinition) -> list[ValidationError]:
    """Validate a complete tool definition.

    Args:
        tool: The tool definition to validate.

    Returns:
        List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []

    if not tool.description:
        errors.append(
            ValidationError(
                "Tool description should not be empty",
                str(tool.tool_name),
                "warning",
            )
        )

    if len(tool.functions) == 0:
        errors.append(
            ValidationError(
                "Tool must have at least one function",
                str(tool.tool_name),
            )
        )

    func_names: set[str] = set()
    for func in tool.functions:
        if func.name in func_names:
            errors.append(
                ValidationError(
                    f"Duplicate function name '{func.name}'",
                    str(tool.tool_name),
                )
            )
        func_names.add(func.name)
        errors.extend(validate_tool_function(func))

    return errors


def to_anthropic_schema(tool: ToolDefinition) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic Claude's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        List of tools in Anthropic's format.
    """
    tools: list[AnthropicToolSchema] = []

    for func in tool.functions:
        params = _build_json_schema_parameters(func.parameters)
        tool_schema: AnthropicToolSchema = {
            "name": func.name,
            "description": func.description,
            "input_schema": params,
        }
        tools.append(tool_schema)

    return tools


def to_openai_schema(tool: ToolDefinition) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        List of tools in OpenAI's format.
    """
    tools: list[OpenAIToolSchema] = []

    for func in tool.functions:
        params = _build_json_schema_parameters(func.parameters)
        tool_schema: OpenAIToolSchema = {
            "type": "function",
            "function": {
                "name": func.name,
                "description": func.description,
                "parameters": params,
            },
        }
        tools.append(tool_schema)

    return tools


def to_google_schema(tool: ToolDefinition) -> list[GoogleFunctionDeclaration]:
    """Convert ToolDefinition to Google Gemini's tool format.

    Google Gemini uses uppercase type names (STRING, INTEGER, OBJECT, etc.).

    Args:
        tool: The tool definition to convert.

    Returns:
        List of function declarations in Google's format.
    """
    function_declarations: list[GoogleFunctionDeclaration] = []

    for func in tool.functions:
        params = _build_google_schema_parameters(func.parameters)
        func_decl: GoogleFunctionDeclaration = {
            "name": func.name,
            "description": func.description,
            "parameters": params,
        }
        function_declarations.append(func_decl)

    return function_declarations


def to_ollama_schema(tool: ToolDefinition) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to Ollama's tool format.

    Ollama uses OpenAI-compatible function calling format.

    Args:
        tool: The tool definition to convert.

    Returns:
        List of tools in Ollama/OpenAI format.
    """
    return to_openai_schema(tool)


def to_openrouter_schema(tool: ToolDefinition) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenRouter's tool format.

    OpenRouter uses OpenAI-compatible function calling format.

    Args:
        tool: The tool definition to convert.

    Returns:
        List of tools in OpenRouter/OpenAI format.
    """
    return to_openai_schema(tool)


def get_schema_for_provider(
    tool: ToolDefinition,
    provider: ProviderName,
) -> list[dict[str, Any]]:
    """Convert tool definition to provider-specific schema format.

    This is the high-level API for schema conversion. Use this when you
    need to convert a tool definition for a specific provider.

    Args:
        tool: The tool definition to convert.
        provider: The target LLM provider.

    Returns:
        List of tool schemas in the provider's format.
    """
    if provider == ProviderName.ANTHROPIC:
        return [dict(s) for s in to_anthropic_schema(tool)]
    if provider == ProviderName.OPENAI:
        return [dict(s) for s in to_openai_schema(tool)]
    if provider == ProviderName.GOOGLE:
        return [dict(s) for s in to_google_schema(tool)]
    if provider == ProviderName.OLLAMA:
        return [dict(s) for s in to_ollama_schema(tool)]
    if provider == ProviderName.OPENROUTER:
        return [dict(s) for s in to_openrouter_schema(tool)]
    if provider == ProviderName.HUGGINGFACE:
        return [dict(s) for s in to_openai_schema(tool)]
    if provider == ProviderName.GROK:
        return [dict(s) for s in to_openai_schema(tool)]
    if provider == ProviderName.LOCAL_TRANSFORMERS:
        return [dict(s) for s in to_openai_schema(tool)]
    _assert_never(provider)


def get_all_schemas_for_provider(
    tools: list[ToolDefinition],
    provider: ProviderName,
) -> list[dict[str, Any]]:
    """Convert multiple tool definitions to provider schemas.

    Args:
        tools: List of tool definitions to convert.
        provider: The target LLM provider.

    Returns:
        Flattened list of all tool schemas in the provider's format.
    """
    all_schemas: list[dict[str, Any]] = []
    for tool in tools:
        schemas = get_schema_for_provider(tool, provider)
        all_schemas.extend(schemas)
    return all_schemas


def validate_and_convert(
    tool: ToolDefinition,
    provider: ProviderName,
) -> tuple[list[dict[str, Any]], list[ValidationError]]:
    """Validate a tool definition and convert to provider schema.

    Combines validation and conversion in a single call.

    Args:
        tool: The tool definition to validate and convert.
        provider: The target LLM provider.

    Returns:
        Tuple of (schemas, validation_errors).
        Schemas will be empty if there are error-level validation errors.
    """
    errors = validate_tool_definition(tool)
    has_errors = any(e.severity == "error" for e in errors)

    if has_errors:
        return [], errors

    schemas = get_schema_for_provider(tool, provider)
    return schemas, errors
