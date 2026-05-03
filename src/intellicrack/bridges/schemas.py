# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""JSON Schema generation for LLM tool calling.

This module provides centralized schema generation for converting Intellicrack tool definitions to provider-specific formats for LLM
function calling. Supports Anthropic, OpenAI, Google Gemini, Ollama, and OpenRouter.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Never, TypedDict

from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ProviderName,
    ToolDefinition,
    ToolFunction,
    ToolParameter,
)


_logger = get_logger(__name__)


def _assert_never(value: Never) -> Never:
    """Assert that a code path is never reached.

    Used for exhaustive enum matching to ensure all cases are handled.

    Args:
        value: A value of type Never (should be impossible to call).

    Returns:
        Never: This function never returns; it always raises ``AssertionError``.

    Raises:
        AssertionError: Always raised if this function is somehow called.
    """
    msg = f"Unexpected value: {value!r}"
    _logger.error(
        "assert_never_triggered",
        unexpected_value=repr(value),
        unexpected_type=type(value).__name__,
    )
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
    default: str | int | float | bool | list[str | int | float | bool] | None


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
    default: str | int | float | bool | list[str | int | float | bool] | None


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
    """Represents a validation error in a tool definition.

    Stores the human-readable description, the dotted path where the issue was detected, and the severity that downstream reporting uses to
    decide whether the tool definition should be rejected.
    """

    def __init__(
        self,
        message: str,
        location: str,
        severity: Literal["error", "warning"] = "error",
    ) -> None:
        """Initialize the ValidationError with the given details.

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
            str: Formatted string showing severity, location, and message.
        """
        return f"[{self.severity.upper()}] {self.location}: {self.message}"


def is_recognized_type(param_type: str) -> bool:
    """Check whether a parameter type string is a recognised type alias.

    A type is recognised when its lower-cased / whitespace-stripped form
    matches a key in ``PYTHON_TO_JSON_TYPES`` or a member of
    ``VALID_JSON_SCHEMA_TYPES``. Types outside this set (parameterised
    generics like ``list[int]``, optional unions like ``int|None``,
    arbitrary class names) are rejected because they cannot be advertised
    to LLM providers without information loss.

    Args:
        param_type: The type string to test.

    Returns:
        bool: True when the type is one of the recognised aliases.
    """
    param_type_lower = param_type.lower().strip()
    return param_type_lower in PYTHON_TO_JSON_TYPES or param_type_lower in VALID_JSON_SCHEMA_TYPES


def normalize_type(param_type: str) -> str:
    """Normalize a parameter type string to a JSON Schema type.

    Recognised inputs (Python aliases such as ``int``/``str``/``list``
    or JSON Schema names such as ``integer``/``string``/``array``) are
    returned as their JSON Schema equivalents. Unrecognised inputs fall
    back to ``"string"`` and emit a ``schema_type_fallback`` warning so
    the offending type cannot be silently downgraded without leaving an
    audit trail. Callers that need to decide between
    ``raise``/``warn``/``coerce`` should pre-check with
    :func:`is_recognized_type`.

    Args:
        param_type: The type string to normalize.

    Returns:
        str: A JSON Schema type drawn from ``VALID_JSON_SCHEMA_TYPES``.
    """
    param_type_lower = param_type.lower().strip()
    if param_type_lower in PYTHON_TO_JSON_TYPES:
        return PYTHON_TO_JSON_TYPES[param_type_lower]
    if param_type_lower in VALID_JSON_SCHEMA_TYPES:
        return param_type_lower
    _logger.warning(
        "schema_type_fallback",
        param_type=param_type,
        normalized="string",
    )
    return "string"


def build_schema_property(
    param: ToolParameter,
    *,
    uppercase_types: bool = False,
) -> JSONSchemaProperty | GoogleSchemaProperty:
    """Build a JSON Schema property from a ToolParameter.

    Args:
        param: The tool parameter to convert.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaProperty | GoogleSchemaProperty: JSONSchemaProperty or GoogleSchemaProperty dict.
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
        JSONSchemaParameters: JSONSchemaParameters dict with lowercase types.
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
        GoogleSchemaParameters: GoogleSchemaParameters dict with uppercase types.
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
    *,
    uppercase_types: bool = False,
) -> JSONSchemaParameters | GoogleSchemaParameters:
    """Build complete parameter schema from list of parameters.

    Args:
        params: List of tool parameters.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaParameters | GoogleSchemaParameters: JSONSchemaParameters or GoogleSchemaParameters dict.
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
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []
    location = f"{func_name}.{param.name}"

    if not param.name:
        errors.append(
            ValidationError(
                "Parameter name cannot be empty",
                location,
            ),
        )
    elif not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", param.name):
        errors.append(
            ValidationError(
                f"Invalid parameter name '{param.name}' (must be valid identifier)",
                location,
            ),
        )

    if not is_recognized_type(param.type):
        normalized_type = normalize_type(param.type)
        errors.append(
            ValidationError(
                f"Invalid type '{param.type}' (normalized to '{normalized_type}')",
                location,
                "warning",
            ),
        )

    if not param.description:
        errors.append(
            ValidationError(
                "Parameter description should not be empty",
                location,
                "warning",
            ),
        )

    if param.required and param.default is not None:
        errors.append(
            ValidationError(
                "Required parameter should not have a default value",
                location,
                "warning",
            ),
        )

    if param.enum is not None:
        if len(param.enum) == 0:
            errors.append(
                ValidationError(
                    "Enum list cannot be empty",
                    location,
                ),
            )
        elif param.default is not None and param.default not in param.enum:
            errors.append(
                ValidationError(
                    f"Default value '{param.default}' not in enum {param.enum}",
                    location,
                ),
            )

    return errors


def validate_tool_function(func: ToolFunction) -> list[ValidationError]:
    """Validate a tool function definition.

    Args:
        func: The function to validate.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []

    if not func.name:
        errors.append(
            ValidationError(
                "Function name cannot be empty",
                "function",
            ),
        )
    elif "." not in func.name:
        errors.append(
            ValidationError(
                f"Function name '{func.name}' should follow 'tool.function' pattern",
                func.name,
                "warning",
            ),
        )

    if not func.description:
        errors.append(
            ValidationError(
                "Function description should not be empty",
                func.name or "function",
                "warning",
            ),
        )

    param_names: set[str] = set()
    for param in func.parameters:
        if param.name in param_names:
            errors.append(
                ValidationError(
                    f"Duplicate parameter name '{param.name}'",
                    func.name or "function",
                ),
            )
        param_names.add(param.name)
        errors.extend(validate_tool_parameter(param, func.name))

    return errors


def validate_tool_definition(tool: ToolDefinition) -> list[ValidationError]:
    """Validate a complete tool definition.

    Args:
        tool: The tool definition to validate.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []

    if not tool.description:
        errors.append(
            ValidationError(
                "Tool description should not be empty",
                str(tool.tool_name),
                "warning",
            ),
        )

    if len(tool.functions) == 0:
        errors.append(
            ValidationError(
                "Tool must have at least one function",
                str(tool.tool_name),
            ),
        )

    func_names: set[str] = set()
    for func in tool.functions:
        if func.name in func_names:
            errors.append(
                ValidationError(
                    f"Duplicate function name '{func.name}'",
                    str(tool.tool_name),
                ),
            )
        func_names.add(func.name)
        errors.extend(validate_tool_function(func))

    return errors


def to_anthropic_schema(tool: ToolDefinition) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic Claude's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[AnthropicToolSchema]: List of tools in Anthropic's format.
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
        list[OpenAIToolSchema]: List of tools in OpenAI's format.
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
        list[GoogleFunctionDeclaration]: List of function declarations in Google's format.
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
        list[OpenAIToolSchema]: List of tools in Ollama/OpenAI format.
    """
    return to_openai_schema(tool)


def to_openrouter_schema(tool: ToolDefinition) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenRouter's tool format.

    OpenRouter uses OpenAI-compatible function calling format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[OpenAIToolSchema]: List of tools in OpenRouter/OpenAI format.
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
        list[dict[str, Any]]: List of tool schemas in the provider's format.
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
        list[dict[str, Any]]: Flattened list of all tool schemas in the provider's format.
    """
    all_schemas: list[dict[str, Any]] = []
    for tool in tools:
        schemas = get_schema_for_provider(tool, provider)
        all_schemas.extend(schemas)
    return all_schemas


def validate_tool_for_provider(
    tool: ToolDefinition,
    provider: ProviderName,
) -> list[ValidationError]:
    """Validate a tool definition for a specific provider without allocating schema dicts.

    This is the cheap path used by the orchestrator at the top of every
    agent loop iteration: it walks the tool definition, normalises every
    parameter type once (so unknown types surface as
    ``schema_type_fallback`` warnings), and confirms the chosen provider
    has a code path in ``get_schema_for_provider``. It deliberately does
    not allocate the per-provider dict trees that ``get_schema_for_provider``
    would build because the orchestrator hands the raw ``ToolDefinition``
    list to ``_call_llm`` and each provider re-converts on its own.

    Args:
        tool: The tool definition to validate.
        provider: The target LLM provider.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors = validate_tool_definition(tool)
    if provider not in set(ProviderName):
        errors.append(
            ValidationError(
                f"Provider '{provider}' has no schema converter",
                str(tool.tool_name),
                "error",
            ),
        )
    has_errors = any(e.severity == "error" for e in errors)
    if has_errors:
        _logger.warning(
            "tool_validation_failed",
            tool=str(tool.tool_name),
            provider=str(provider),
            error_count=len(errors),
        )
    return errors


def validate_and_convert(
    tool: ToolDefinition,
    provider: ProviderName,
) -> tuple[list[dict[str, Any]], list[ValidationError]]:
    """Validate a tool definition and convert to provider schema.

    Combines validation and conversion in a single call. This builds the
    provider-specific dict tree, so callers that only need validation
    diagnostics should prefer ``validate_tool_for_provider`` to avoid the
    allocation cost.

    Args:
        tool: The tool definition to validate and convert.
        provider: The target LLM provider.

    Returns:
        tuple[list[dict[str, Any]], list[ValidationError]]: Tuple of (schemas, validation_errors).
        Schemas will be empty if there are error-level validation errors.
    """
    errors = validate_tool_definition(tool)
    has_errors = any(e.severity == "error" for e in errors)

    if has_errors:
        _logger.warning(
            "tool_validation_failed",
            tool=str(tool.tool_name),
            error_count=len(errors),
        )
        return [], errors

    schemas = get_schema_for_provider(tool, provider)
    _logger.debug(
        "schema_converted",
        tool=str(tool.tool_name),
        provider=str(provider),
        schema_count=len(schemas),
    )
    return schemas, errors
