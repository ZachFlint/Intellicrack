# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Validation and dialect dispatch for LLM tool schemas.

Schema *generation* now lives in one place per wire format: the dialect
adapters under :mod:`intellicrack.providers.dialects`, which every provider
and every entry point here delegates to. That consolidation resolved a real
disagreement -- two OpenAI schema builders existed and only one applied the
provider-safe wire-name mapping, so the same tool could be advertised under
two different names depending on which path built it.

What remains here is validation: the cheap per-tool checks the orchestrator
runs at the top of every agent loop iteration, plus the reserved-namespace rule
that stops an externally-sourced tool from claiming a bridge namespace.

Dispatch is keyed by :class:`~intellicrack.providers.capabilities.ApiDialect`
rather than by provider, because a provider is now an arbitrary string id while
the set of wire formats stays closed.
"""

from __future__ import annotations

import re
from typing import Any, Literal, TypedDict, cast

from intellicrack.bridges.json_schema import (
    GOOGLE_TYPE_MAP,
    PYTHON_TO_JSON_TYPES,
    VALID_JSON_SCHEMA_TYPES,
    GoogleSchemaParameters,
    GoogleSchemaProperty,
    JSONSchemaParameters,
    JSONSchemaProperty,
    build_google_schema_parameters,
    build_json_schema_parameters,
    build_schema_property,
    is_recognized_type,
    normalize_type,
)
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.dialects import adapter_for
from intellicrack.providers.presets import preset_for
from intellicrack.providers.tool_names import is_valid_wire_name, to_wire_name


_logger = get_logger(__name__)


RESERVED_TOOL_NAMESPACES: frozenset[str] = frozenset(member.value for member in ToolName)
"""Namespaces owned by Intellicrack's own bridges.

An externally-sourced tool may not claim one of these: the dispatch boundary
resolves a namespace against the bridge registry first, so a tool calling
itself ``ghidra`` would shadow the real Ghidra bridge rather than sit beside
it.
"""


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
        return build_google_schema_parameters(params)
    return build_json_schema_parameters(params)


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

    if normalize_type(param.type) == "array":
        if not is_recognized_type(param.items_type):
            errors.append(
                ValidationError(
                    f"Array parameter has unrecognized items_type '{param.items_type}'",
                    location,
                    "warning",
                ),
            )
        elif normalize_type(param.items_type) == "object" and not param.item_properties:
            errors.append(
                ValidationError(
                    "Array of objects requires item_properties; providers such as "
                    "Google Gemini reject object schemas with empty properties",
                    location,
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

    if func.input_schema is not None:
        errors.extend(validate_raw_input_schema(func.input_schema, func.name or "function"))
        return errors

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


def validate_raw_input_schema(schema: dict[str, Any], location: str) -> list[ValidationError]:
    """Validate a function's raw JSON Schema override.

    A raw schema is authoritative and bypasses the ``ToolParameter`` model
    entirely, so the checks here are the structural ones every dialect needs:
    the schema has to describe an object, and its ``properties`` and
    ``required`` entries have to be the right shape. Composition keywords are
    not rejected -- Messages and Chat Completions accept them, and the
    Responses and Gemini reductions handle them -- but a ``required`` entry
    naming no declared property is reported, because the endpoint will treat
    it as a schema error rather than as a permissive default.

    Args:
        schema: The raw schema supplied on the function.
        location: Dotted path used for error context.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors: list[ValidationError] = []
    declared_type = schema.get("type")
    if declared_type is not None and declared_type != "object":
        errors.append(
            ValidationError(
                f"Raw input_schema must describe an object, not {declared_type!r}",
                location,
            ),
        )

    properties = schema.get("properties")
    if properties is not None and not is_json_object(properties):
        errors.append(
            ValidationError(
                "Raw input_schema 'properties' must be an object",
                location,
            ),
        )
        return errors

    required = schema.get("required")
    if required is None:
        return errors
    if not is_json_array(required):
        errors.append(
            ValidationError(
                "Raw input_schema 'required' must be an array",
                location,
            ),
        )
        return errors

    declared: dict[str, Any] = properties if is_json_object(properties) else {}
    entries: list[Any] = required
    errors.extend(
        ValidationError(
            f"Raw input_schema requires '{name}', which it does not declare in 'properties'",
            location,
        )
        for name in entries
        if isinstance(name, str) and name not in declared
    )
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


def _one_entry_per_function(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Unwrap Gemini's grouped declarations so every dialect yields one entry per function.

    Chat Completions, Responses and Messages already render one tool entry per
    function. Gemini groups every declaration under a single
    ``functionDeclarations`` tool, which is how its request body wants them but
    not what a schema getter promises its caller.

    Args:
        entries: Tool entries as a dialect adapter rendered them.

    Returns:
        list[dict[str, Any]]: The same schemas, one entry per function.
    """
    flattened: list[dict[str, Any]] = []
    for entry in entries:
        grouped = entry.get("functionDeclarations")
        if is_json_array(grouped):
            flattened.extend(member for member in grouped if is_json_object(member))
        else:
            flattened.append(entry)
    return flattened


def _schemas_for(tool: ToolDefinition, dialect: ApiDialect) -> list[dict[str, Any]]:
    """Build one tool's schemas through the adapter that owns the wire format.

    Args:
        tool: The tool definition to convert.
        dialect: The target wire format.

    Returns:
        list[dict[str, Any]]: Tool schemas in the dialect's format, one entry
        per function.
    """
    adapter = adapter_for(dialect)
    return _one_entry_per_function(adapter.build_tool_schemas([tool], adapter.default_capabilities()))


def to_anthropic_schema(tool: ToolDefinition) -> list[AnthropicToolSchema]:
    """Convert ToolDefinition to Anthropic Claude's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[AnthropicToolSchema]: List of tools in Anthropic's format.
    """
    return [cast("AnthropicToolSchema", schema) for schema in _schemas_for(tool, ApiDialect.MESSAGES)]


def to_openai_schema(tool: ToolDefinition) -> list[OpenAIToolSchema]:
    """Convert ToolDefinition to OpenAI's tool format.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[OpenAIToolSchema]: List of tools in OpenAI's format.
    """
    return [cast("OpenAIToolSchema", schema) for schema in _schemas_for(tool, ApiDialect.CHAT_COMPLETIONS)]


def to_google_schema(tool: ToolDefinition) -> list[GoogleFunctionDeclaration]:
    """Convert ToolDefinition to Google Gemini's tool format.

    Google Gemini uses uppercase type names (STRING, INTEGER, OBJECT, etc.)
    and groups every declaration under a single ``functionDeclarations`` tool,
    which this helper unwraps so callers keep receiving one entry per function.

    Args:
        tool: The tool definition to convert.

    Returns:
        list[GoogleFunctionDeclaration]: List of function declarations in Google's format.
    """
    return [cast("GoogleFunctionDeclaration", entry) for entry in _schemas_for(tool, ApiDialect.GEMINI)]


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


def get_schema_for_dialect(
    tool: ToolDefinition,
    dialect: ApiDialect,
) -> list[dict[str, Any]]:
    """Convert a tool definition to one wire format's schema.

    This is the high-level API for schema conversion. Dispatch is keyed by
    dialect rather than by provider, so an arbitrary provider instance gets a
    correct schema as soon as it states which wire format it speaks.

    Args:
        tool: The tool definition to convert.
        dialect: The target wire format.

    Returns:
        list[dict[str, Any]]: List of tool schemas in the dialect's format.
    """
    return _schemas_for(tool, dialect)


def get_all_schemas_for_dialect(
    tools: list[ToolDefinition],
    dialect: ApiDialect,
) -> list[dict[str, Any]]:
    """Convert multiple tool definitions to one wire format's schemas.

    Args:
        tools: List of tool definitions to convert, in priority order. The
            returned list preserves that order exactly.
        dialect: The target wire format.

    Returns:
        list[dict[str, Any]]: Flattened list of all tool schemas in the
        dialect's format.
    """
    adapter = adapter_for(dialect)
    return _one_entry_per_function(adapter.build_tool_schemas(tools, adapter.default_capabilities()))


def validate_tool_for_dialect(
    tool: ToolDefinition,
    dialect: ApiDialect,
) -> list[ValidationError]:
    """Validate a tool definition for one wire format without allocating schemas.

    This is the cheap path used by the orchestrator at the top of every agent
    loop iteration: it walks the tool definition, normalises every parameter
    type once (so unknown types surface as ``schema_type_fallback`` warnings)
    and confirms every function name survives the round trip to its wire form.
    It deliberately does not allocate the per-dialect dict trees that
    :func:`get_schema_for_dialect` would build, because the orchestrator hands
    the raw ``ToolDefinition`` list to ``_call_llm`` and each provider
    re-converts on its own.

    The provider-has-a-converter check that used to live here is gone: every
    dialect has an adapter by construction, and provider identity no longer
    constrains which schemas can be built.

    Args:
        tool: The tool definition to validate.
        dialect: The target wire format.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    errors = validate_tool_definition(tool)
    for func in tool.functions:
        wire_name = to_wire_name(func.name)
        if not is_valid_wire_name(wire_name):
            errors.append(
                ValidationError(
                    f"Wire name '{wire_name}' derived from function '{func.name}' violates the "
                    "provider tool-name rule ^[A-Za-z0-9_-]{1,64}$",
                    func.name,
                    "error",
                ),
            )
    has_errors = any(e.severity == "error" for e in errors)
    if has_errors:
        _logger.warning(
            "tool_validation_failed",
            tool=tool.tool_name,
            dialect=dialect.value,
            error_count=len(errors),
        )
    return errors


def dialect_for_provider(provider: str) -> ApiDialect:
    """Resolve the wire format a provider instance speaks.

    Provider identity is open, so a provider the presets do not know is
    assumed to speak Chat Completions: that is the format an arbitrary
    OpenAI-compatible endpoint serves, and it is what the configuration UI
    probes such an endpoint with. A preset that declares no dialect at all
    resolves the same way, which covers the in-process local-inference
    provider: it never reaches an HTTP wire, but callers still ask it for
    schemas and expect the OpenAI-compatible shape.

    Args:
        provider: The provider instance id.

    Returns:
        ApiDialect: The wire format that provider speaks.
    """
    preset = preset_for(provider)
    if preset is None or preset.dialect is None:
        return ApiDialect.CHAT_COMPLETIONS
    return preset.dialect


def get_schema_for_provider(
    tool: ToolDefinition,
    provider: str,
) -> list[dict[str, Any]]:
    """Convert a tool definition to one provider's schema.

    Convenience over :func:`get_schema_for_dialect` for callers that hold a
    provider id rather than a dialect. Dispatch is still keyed by dialect;
    this resolves the provider to its wire format first.

    Args:
        tool: The tool definition to convert.
        provider: The provider instance id to build schemas for.

    Returns:
        list[dict[str, Any]]: List of tool schemas in that provider's format.
    """
    return get_schema_for_dialect(tool, dialect_for_provider(provider))


def get_all_schemas_for_provider(
    tools: list[ToolDefinition],
    provider: str,
) -> list[dict[str, Any]]:
    """Convert multiple tool definitions to one provider's schemas.

    Args:
        tools: List of tool definitions to convert, in priority order. The
            returned list preserves that order exactly.
        provider: The provider instance id to build schemas for.

    Returns:
        list[dict[str, Any]]: Flattened list of all tool schemas in that
        provider's format.
    """
    return get_all_schemas_for_dialect(tools, dialect_for_provider(provider))


def validate_tool_for_provider(
    tool: ToolDefinition,
    provider: str,
) -> list[ValidationError]:
    """Validate a tool definition for one provider without allocating schemas.

    Args:
        tool: The tool definition to validate.
        provider: The provider instance id to validate against.

    Returns:
        list[ValidationError]: List of validation errors (empty if valid).
    """
    return validate_tool_for_dialect(tool, dialect_for_provider(provider))


def validate_external_tool_namespace(tool_name: str) -> ValidationError | None:
    """Reject an externally-sourced tool that claims a bridge namespace.

    The dispatch boundary resolves a namespace against the bridge registry
    before it reaches the external-executor registry, so an external tool
    calling itself ``ghidra`` would shadow the real Ghidra bridge instead of
    sitting beside it.

    Args:
        tool_name: The namespace the external tool claims.

    Returns:
        ValidationError | None: An error when the namespace is reserved,
        otherwise ``None``.
    """
    if tool_name in RESERVED_TOOL_NAMESPACES:
        return ValidationError(
            f"Namespace '{tool_name}' is reserved for an Intellicrack bridge and cannot be claimed by an external tool",
            tool_name,
            "error",
        )
    return None


def validate_and_convert(
    tool: ToolDefinition,
    dialect: ApiDialect,
) -> tuple[list[dict[str, Any]], list[ValidationError]]:
    """Validate a tool definition and convert it to one wire format's schemas.

    Combines validation and conversion in a single call. This builds the
    dialect-specific dict tree, so callers that only need validation
    diagnostics should prefer :func:`validate_tool_for_dialect` to avoid the
    allocation cost.

    Args:
        tool: The tool definition to validate and convert.
        dialect: The target wire format.

    Returns:
        tuple[list[dict[str, Any]], list[ValidationError]]: Tuple of (schemas, validation_errors).
        Schemas will be empty if there are error-level validation errors.
    """
    errors = validate_tool_definition(tool)
    has_errors = any(e.severity == "error" for e in errors)

    if has_errors:
        _logger.warning(
            "tool_validation_failed",
            tool=tool.tool_name,
            error_count=len(errors),
        )
        return [], errors

    schemas = get_schema_for_dialect(tool, dialect)
    _logger.debug(
        "schema_converted",
        tool=tool.tool_name,
        dialect=dialect.value,
        schema_count=len(schemas),
    )
    return schemas, errors


__all__ = [
    "GOOGLE_TYPE_MAP",
    "PYTHON_TO_JSON_TYPES",
    "RESERVED_TOOL_NAMESPACES",
    "VALID_JSON_SCHEMA_TYPES",
    "AnthropicToolSchema",
    "GoogleFunctionDeclaration",
    "GoogleSchemaParameters",
    "GoogleSchemaProperty",
    "JSONSchemaParameters",
    "JSONSchemaProperty",
    "OpenAIFunctionSchema",
    "OpenAIToolSchema",
    "ValidationError",
    "build_schema_parameters",
    "build_schema_property",
    "dialect_for_provider",
    "get_all_schemas_for_dialect",
    "get_all_schemas_for_provider",
    "get_schema_for_dialect",
    "get_schema_for_provider",
    "is_recognized_type",
    "normalize_type",
    "to_anthropic_schema",
    "to_google_schema",
    "to_ollama_schema",
    "to_openai_schema",
    "to_openrouter_schema",
    "validate_and_convert",
    "validate_external_tool_namespace",
    "validate_raw_input_schema",
    "validate_tool_definition",
    "validate_tool_for_dialect",
    "validate_tool_for_provider",
    "validate_tool_function",
    "validate_tool_parameter",
]
