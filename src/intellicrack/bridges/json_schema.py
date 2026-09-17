# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Reductions of raw JSON Schema to what each API dialect actually accepts.

An externally-sourced tool describes its arguments with real JSON Schema
(2020-12): ``$ref``, ``$defs``, ``anyOf``, keyword composition. Intellicrack's
own ``ToolParameter`` model cannot express any of that, so a raw schema rides
through untouched -- but the three dialects that receive it disagree sharply on
what they will accept.

Anthropic Messages and OpenAI Chat Completions take 2020-12 as-is. OpenAI
Responses enforces strict mode, which forbids ``$ref`` indirection, demands
every property be listed in ``required`` and demands ``additionalProperties:
false`` on every object. Google Gemini takes a small, uppercase-typed subset.

Each reduction here is total: it either produces a schema the dialect accepts,
or it reports that it could not, so the caller can fall back rather than send
something the endpoint will reject.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, Literal, TypedDict

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import ToolFunction, ToolParameter


_logger = get_logger(__name__)

MAX_INLINE_DEPTH: Final[int] = 32
"""Maximum ``$ref`` expansion depth before a schema is treated as recursive."""

_DEF_CONTAINERS: Final[tuple[str, ...]] = ("$defs", "definitions")

_STRICT_ALLOWED_KEYWORDS: Final[frozenset[str]] = frozenset({
    "type",
    "description",
    "enum",
    "properties",
    "required",
    "items",
    "additionalProperties",
    "anyOf",
    "title",
})
"""Keywords OpenAI strict mode accepts; everything else is dropped."""

_STRICT_REJECTED_KEYWORDS: Final[frozenset[str]] = frozenset({
    "oneOf",
    "allOf",
    "not",
    "patternProperties",
    "unevaluatedProperties",
    "dependentSchemas",
    "if",
    "then",
    "else",
})
"""Keywords whose meaning strict mode cannot preserve, forcing ``strict: false``."""

_GEMINI_ALLOWED_KEYWORDS: Final[frozenset[str]] = frozenset({
    "type",
    "format",
    "description",
    "nullable",
    "enum",
    "items",
    "properties",
    "required",
    "minItems",
    "maxItems",
    "anyOf",
})
"""Keywords Gemini's ``Schema`` accepts."""

_GEMINI_TYPE_NAMES: Final[frozenset[str]] = frozenset({
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "object",
})
"""JSON Schema types Gemini can express; ``null`` becomes ``nullable`` instead."""


def _lookup_ref(root: dict[str, Any], ref: str) -> dict[str, Any] | None:
    """Resolve a local JSON pointer against a schema's definition containers.

    Args:
        root: The schema the pointer is relative to.
        ref: The ``$ref`` value, e.g. ``"#/$defs/Point"``.

    Returns:
        dict[str, Any] | None: The referenced schema, or ``None`` when the
        pointer is remote, malformed or unresolvable.
    """
    if not ref.startswith("#/"):
        return None
    segments = [segment.replace("~1", "/").replace("~0", "~") for segment in ref[2:].split("/") if segment]
    if not segments:
        return None
    current: object = root
    for segment in segments:
        if not isinstance(current, dict):
            return None
        container: dict[str, Any] = current
        if segment not in container:
            return None
        current = container[segment]
    return current if isinstance(current, dict) else None


def _inline_node(node: object, root: dict[str, Any], depth: int) -> object:
    """Recursively inline every local ``$ref`` within one schema node.

    Args:
        node: The node to rewrite.
        root: The schema the pointers are relative to.
        depth: Remaining expansion depth.

    Returns:
        object: A new node with local references inlined. A reference that
        cannot be resolved within ``depth`` expansions collapses to a
        permissive empty schema, which every dialect accepts.
    """
    if isinstance(node, list):
        items: list[Any] = node
        return [_inline_node(item, root, depth) for item in items]
    if not isinstance(node, dict):
        return node

    mapping: dict[str, Any] = node
    ref = mapping.get("$ref")
    if isinstance(ref, str):
        if depth <= 0:
            _logger.warning("json_schema_ref_depth_exceeded", ref=ref)
            return {}
        target = _lookup_ref(root, ref)
        if target is None:
            _logger.warning("json_schema_ref_unresolved", ref=ref)
            return {}
        merged: dict[str, Any] = {key: value for key, value in mapping.items() if key != "$ref"}
        expanded = _inline_node(target, root, depth - 1)
        if isinstance(expanded, dict):
            expanded_mapping: dict[str, Any] = expanded
            combined = dict(expanded_mapping)
            combined.update(merged)
            return combined
        return expanded

    return {key: _inline_node(value, root, depth) for key, value in mapping.items() if key not in _DEF_CONTAINERS}


def inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Expand every local ``$ref`` and drop the definition containers.

    Recursion is bounded at :data:`MAX_INLINE_DEPTH` expansions; a schema that
    refers to itself more deeply than that collapses its deepest references to
    a permissive empty schema rather than expanding forever.

    Args:
        schema: The raw schema to expand.

    Returns:
        dict[str, Any]: A new schema with no ``$ref`` and no ``$defs``.
    """
    inlined = _inline_node(schema, schema, MAX_INLINE_DEPTH)
    return inlined if isinstance(inlined, dict) else {}


def _widen_with_null(node: dict[str, Any]) -> dict[str, Any]:
    """Make a property schema accept ``null`` so strict mode can require it.

    OpenAI strict mode requires every property to appear in ``required``. A
    property the tool declared optional therefore has to stay expressible as
    absent, which strict mode models as an explicit ``null``.

    Args:
        node: The property schema to widen.

    Returns:
        dict[str, Any]: A new schema that also accepts ``null``.
    """
    widened = dict(node)
    declared = widened.get("type")
    if isinstance(declared, str):
        widened["type"] = [declared, "null"] if declared != "null" else declared
        return widened
    if isinstance(declared, list):
        types: list[Any] = declared
        names = [str(entry) for entry in types]
        if "null" not in names:
            names.append("null")
        widened["type"] = names
        return widened
    options = widened.get("anyOf")
    if isinstance(options, list):
        branches: list[Any] = options
        widened["anyOf"] = [*branches, {"type": "null"}]
    return widened


def _strictify(node: object) -> tuple[object, bool]:
    """Reduce one schema node to OpenAI strict mode.

    Args:
        node: The node to reduce.

    Returns:
        tuple[object, bool]: The reduced node and whether strict mode can
        faithfully represent it.
    """
    if isinstance(node, list):
        entries: list[Any] = node
        reduced_list: list[object] = []
        faithful = True
        for entry in entries:
            reduced_entry, entry_ok = _strictify(entry)
            reduced_list.append(reduced_entry)
            faithful = faithful and entry_ok
        return reduced_list, faithful
    if not isinstance(node, dict):
        return node, True

    mapping: dict[str, Any] = node
    faithful = True
    if _STRICT_REJECTED_KEYWORDS.intersection(mapping):
        _logger.debug("json_schema_strict_unsupported_keyword", keywords=sorted(_STRICT_REJECTED_KEYWORDS.intersection(mapping)))
        faithful = False

    reduced: dict[str, Any] = {}
    for key, value in mapping.items():
        if key not in _STRICT_ALLOWED_KEYWORDS:
            continue
        reduced_value, value_ok = _strictify(value)
        reduced[key] = reduced_value
        faithful = faithful and value_ok

    properties = reduced.get("properties")
    if isinstance(properties, dict):
        property_map: dict[str, Any] = properties
        declared_required = mapping.get("required")
        required_names = {str(name) for name in declared_required} if isinstance(declared_required, list) else set()
        rebuilt: dict[str, Any] = {}
        for name, prop in property_map.items():
            if isinstance(prop, dict) and name not in required_names:
                prop_mapping: dict[str, Any] = prop
                rebuilt[name] = _widen_with_null(prop_mapping)
            else:
                rebuilt[name] = prop
        reduced["properties"] = rebuilt
        reduced["required"] = list(rebuilt)
        reduced["additionalProperties"] = False
        reduced.setdefault("type", "object")

    return reduced, faithful


def to_strict_subset(schema: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Reduce a raw schema to the subset OpenAI Responses strict mode accepts.

    References are inlined first, since strict mode rejects ``$ref``
    indirection outright. Every object then gains
    ``additionalProperties: false`` and a ``required`` list naming every one of
    its properties, with properties the tool declared optional widened to
    accept ``null`` so their optionality survives.

    Args:
        schema: The raw schema to reduce.

    Returns:
        tuple[dict[str, Any], bool]: The reduced schema, and whether strict
        mode can faithfully represent it. A ``False`` flag means the caller
        must send ``strict: false`` alongside the schema rather than claim a
        guarantee the schema does not actually carry.
    """
    reduced, faithful = _strictify(inline_refs(schema))
    if not isinstance(reduced, dict):
        return {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, False
    return reduced, faithful


def _gemini_type(declared: object) -> tuple[str | None, bool]:
    """Map a JSON Schema ``type`` to Gemini's uppercase type and nullability.

    Args:
        declared: The ``type`` value, a string or a list of strings.

    Returns:
        tuple[str | None, bool]: The uppercase Gemini type name (``None`` when
        no supported type is named) and whether ``null`` was among the types.
    """
    names: list[str]
    if isinstance(declared, str):
        names = [declared]
    elif isinstance(declared, list):
        entries: list[Any] = declared
        names = [str(entry) for entry in entries]
    else:
        return None, False

    nullable = "null" in names
    for name in names:
        lowered = name.lower()
        if lowered in _GEMINI_TYPE_NAMES:
            return lowered.upper(), nullable
    return None, nullable


def _geminify(node: object) -> object:
    """Reduce one schema node to Gemini's supported subset.

    Args:
        node: The node to reduce.

    Returns:
        object: The reduced node.
    """
    if isinstance(node, list):
        entries: list[Any] = node
        return [_geminify(entry) for entry in entries]
    if not isinstance(node, dict):
        return node

    mapping: dict[str, Any] = node
    reduced: dict[str, Any] = {}
    for key, value in mapping.items():
        if key not in _GEMINI_ALLOWED_KEYWORDS:
            continue
        if key == "type":
            continue
        reduced[key] = _geminify(value)

    gemini_type, nullable = _gemini_type(mapping.get("type"))
    if gemini_type is not None:
        reduced["type"] = gemini_type
    if nullable:
        reduced["nullable"] = True

    if reduced.get("type") == "ARRAY" and "items" not in reduced:
        reduced["items"] = {"type": "STRING"}
    if reduced.get("type") == "OBJECT":
        properties = reduced.get("properties")
        if not isinstance(properties, dict) or not properties:
            reduced["properties"] = {}
    return reduced


def to_gemini_subset(schema: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw schema to the subset Google Gemini accepts.

    References are inlined, unsupported keywords are dropped, types are
    uppercased, a ``null`` member of a type union becomes ``nullable`` and
    arrays and objects are given the ``items`` and ``properties`` that Gemini
    rejects a schema for omitting.

    Args:
        schema: The raw schema to reduce.

    Returns:
        dict[str, Any]: The reduced schema, always a Gemini ``OBJECT``.
    """
    reduced = _geminify(inline_refs(schema))
    if not isinstance(reduced, dict):
        return {"type": "OBJECT", "properties": {}, "required": []}
    result: dict[str, Any] = reduced
    result.setdefault("type", "OBJECT")
    if result["type"] == "OBJECT":
        result.setdefault("properties", {})
        result.setdefault("required", [])
    return result


def normalize_object_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Ensure a raw argument schema is a well-formed JSON Schema object.

    Providers reject a function whose parameter schema is not an object with a
    ``properties`` map, so a tool that supplied a bare or partial schema is
    completed here rather than at the endpoint.

    Args:
        schema: The raw schema to normalize.

    Returns:
        dict[str, Any]: A copy carrying ``type``, ``properties`` and
        ``required``.
    """
    normalized = dict(schema)
    normalized.setdefault("type", "object")
    if normalized["type"] == "object":
        properties = normalized.get("properties")
        if not isinstance(properties, dict):
            normalized["properties"] = {}
        required = normalized.get("required")
        if not isinstance(required, list):
            normalized["required"] = []
    return normalized


class JSONSchemaProperty(TypedDict, total=False):
    """JSON Schema property definition for tool parameters."""

    type: str
    description: str
    enum: list[str]
    default: str | int | float | bool | list[str | int | float | bool] | None
    items: JSONSchemaProperty
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


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
    items: JSONSchemaProperty
    properties: dict[str, JSONSchemaProperty]
    required: list[str]


class GoogleSchemaParameters(TypedDict):
    """Google Gemini schema parameters with OBJECT type."""

    type: Literal["OBJECT"]
    properties: dict[str, GoogleSchemaProperty]
    required: list[str]


VALID_JSON_SCHEMA_TYPES: Final[frozenset[str]] = frozenset({
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "object",
    "null",
})

PYTHON_TO_JSON_TYPES: Final[dict[str, str]] = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "dict": "object",
}

GOOGLE_TYPE_MAP: Final[dict[str, str]] = {
    "string": "STRING",
    "integer": "INTEGER",
    "number": "NUMBER",
    "boolean": "BOOLEAN",
    "array": "ARRAY",
    "object": "OBJECT",
    "null": "NULL",
}


def is_recognized_type(param_type: str) -> bool:
    """Check whether a parameter type string is a recognised type alias.

    A type is recognised when its lower-cased / whitespace-stripped form
    matches a key in :data:`PYTHON_TO_JSON_TYPES` or a member of
    :data:`VALID_JSON_SCHEMA_TYPES`. Types outside this set (parameterised
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
        str: A JSON Schema type drawn from :data:`VALID_JSON_SCHEMA_TYPES`.
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


def _build_array_items(
    param: ToolParameter,
    *,
    uppercase_types: bool,
) -> JSONSchemaProperty:
    """Build the JSON Schema ``items`` definition for an array parameter.

    Strict providers such as Google Gemini reject array schemas that omit
    ``items``; object element schemas additionally require non-empty
    ``properties``. This helper emits a typed element schema, recursing into
    ``param.item_properties`` for object elements.

    Args:
        param: The array parameter whose element schema is built.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaProperty: Schema describing a single array element.
    """
    element_type = normalize_type(param.items_type)
    cased_type = GOOGLE_TYPE_MAP.get(element_type, element_type.upper()) if uppercase_types else element_type
    items: JSONSchemaProperty = {"type": cased_type}
    if element_type == "object" and param.item_properties:
        properties: dict[str, JSONSchemaProperty] = {}
        required: list[str] = []
        for nested in param.item_properties:
            properties[nested.name] = build_schema_property(nested, uppercase_types=uppercase_types)
            if nested.required:
                required.append(nested.name)
        items["properties"] = properties
        items["required"] = required
    return items


def build_schema_property(
    param: ToolParameter,
    *,
    uppercase_types: bool = False,
) -> JSONSchemaProperty:
    """Build a JSON Schema property from a ToolParameter.

    Args:
        param: The tool parameter to convert.
        uppercase_types: If True, use uppercase type names (for Google).

    Returns:
        JSONSchemaProperty: JSONSchemaProperty dict; type strings are
            uppercased when ``uppercase_types`` is set (Google format).
    """
    normalized = normalize_type(param.type)
    param_type = GOOGLE_TYPE_MAP.get(normalized, normalized.upper()) if uppercase_types else normalized

    prop: JSONSchemaProperty = {
        "type": param_type,
        "description": param.description,
    }

    if normalized == "array":
        prop["items"] = _build_array_items(param, uppercase_types=uppercase_types)

    if param.enum is not None and len(param.enum) > 0:
        prop["enum"] = param.enum

    if param.default is not None:
        prop["default"] = param.default

    return prop


def build_json_schema_parameters(
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
        properties[param.name] = build_schema_property(param, uppercase_types=False)
        if param.required:
            required.append(param.name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


def build_google_schema_parameters(
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
        properties[param.name] = build_schema_property(param, uppercase_types=True)
        if param.required:
            required.append(param.name)

    return {
        "type": "OBJECT",
        "properties": properties,
        "required": required,
    }


def function_parameters(func: ToolFunction, *, uppercase_types: bool = False) -> dict[str, Any]:
    """Build one function's argument schema, honouring a raw schema override.

    A function carrying :attr:`~intellicrack.core.types.ToolFunction.input_schema`
    is authoritative: its raw JSON Schema is passed through (normalized only
    to guarantee a well-formed object, and reduced to Gemini's subset when
    ``uppercase_types`` is set) and its ``parameters`` list is ignored. Bridge
    functions, which carry no raw schema, build from ``parameters`` exactly as
    they always have.

    Args:
        func: The tool function whose argument schema is built.
        uppercase_types: If True, emit Google Gemini's uppercase type names.

    Returns:
        dict[str, Any]: The function's argument schema.
    """
    if func.input_schema is not None:
        raw = normalize_object_schema(func.input_schema)
        return to_gemini_subset(raw) if uppercase_types else raw
    built = build_google_schema_parameters(func.parameters) if uppercase_types else build_json_schema_parameters(func.parameters)
    return dict(built)
