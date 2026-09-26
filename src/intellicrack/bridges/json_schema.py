# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Reductions of raw JSON Schema to what each API dialect actually accepts.

An externally-sourced tool describes its arguments with real JSON Schema (2020-12): ``$ref``, ``$defs``, ``anyOf``, keyword composition.
Intellicrack's own ``ToolParameter`` model cannot express any of that, so a raw schema rides through untouched -- but the three dialects
that receive it disagree sharply on what they will accept.

Anthropic Messages and OpenAI Chat Completions take 2020-12 as-is. OpenAI Responses strict mode accepts only a documented subset: every
object must list all of its properties in ``required`` and carry ``additionalProperties: false``, free-form objects and map-style
``additionalProperties`` are not expressible, and the schema is bounded in nesting depth, property count and enumeration size. Google
Gemini's ``Schema`` takes a small, uppercase-typed subset and rejects an ``OBJECT`` that declares no properties.

Each reduction here is total: it either produces a schema the dialect accepts, or it reports that it could not, so the caller can fall back
rather than send something the endpoint will reject.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, TypedDict

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import ToolFunction, ToolParameter


_logger = get_logger(__name__)

MAX_INLINE_DEPTH: Final[int] = 32
"""Maximum ``$ref`` expansion depth before a schema is treated as recursive."""

MAX_REF_REENTRY: Final[int] = 3
"""Most times one reference may be expanded again inside its own expansion.

A recursive definition is unrolled this many levels and then collapses to a permissive schema. Without the limit a definition that refers
to itself twice doubles at every level, so thirty-two levels would produce four billion nodes.
"""

MAX_INLINE_NODES: Final[int] = 10_000
"""Most schema nodes one inlining visits before further references collapse.

Bounds the work, and the output, of a reference graph that fans out without recursing: a chain of definitions each referring to the next
twice is exponential even though no definition refers to itself.
"""

_DEF_CONTAINERS: Final[frozenset[str]] = frozenset({"$defs", "definitions"})

_INLINE_MAP_KEYWORDS: Final[frozenset[str]] = frozenset({"properties", "patternProperties", "dependentSchemas"})
"""Keywords whose value maps a caller-chosen name to a subschema; the names are data and are never filtered."""

_INLINE_LIST_KEYWORDS: Final[frozenset[str]] = frozenset({"anyOf", "oneOf", "allOf", "prefixItems"})
"""Keywords whose value is a list of subschemas."""

_INLINE_SCHEMA_KEYWORDS: Final[frozenset[str]] = frozenset({
    "items",
    "additionalItems",
    "additionalProperties",
    "unevaluatedItems",
    "unevaluatedProperties",
    "contains",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
})
"""Keywords whose value is one subschema (``items`` may also be a draft-4 list of them)."""

STRICT_MAX_OBJECT_PROPERTIES: Final[int] = 5000
"""Most object properties a strict-mode schema may declare in total."""

STRICT_MAX_NESTING: Final[int] = 10
"""Deepest object nesting strict mode accepts, counting the root object as the first level."""

STRICT_MAX_ENUM_VALUES: Final[int] = 1000
"""Most enumeration values a strict-mode schema may declare across all its enumerations."""

STRICT_MAX_STRING_CHARS: Final[int] = 120_000
"""Longest combined length of property names, enumeration values and constants strict mode accepts."""

STRICT_LARGE_ENUM_VALUES: Final[int] = 250
"""Size above which one string enumeration is additionally bounded by :data:`STRICT_MAX_LARGE_ENUM_CHARS`."""

STRICT_MAX_LARGE_ENUM_CHARS: Final[int] = 15_000
"""Longest combined length of one string enumeration holding more than :data:`STRICT_LARGE_ENUM_VALUES` values."""

_STRICT_TYPES: Final[frozenset[str]] = frozenset({"string", "number", "boolean", "integer", "object", "array", "null"})
"""Types strict mode accepts."""

_STRICT_FORMATS: Final[frozenset[str]] = frozenset({
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "uuid",
})
"""String formats strict mode accepts."""

_STRICT_CONSTRAINT_KEYWORDS: Final[frozenset[str]] = frozenset({
    "pattern",
    "multipleOf",
    "maximum",
    "exclusiveMaximum",
    "minimum",
    "exclusiveMinimum",
    "minItems",
    "maxItems",
})
"""Assertion keywords strict mode accepts and enforces."""

_STRICT_DESCRIPTIVE_KEYWORDS: Final[frozenset[str]] = frozenset({"title", "description"})
"""Annotation keywords strict mode accepts and that are carried over."""

_STRICT_STRUCTURAL_KEYWORDS: Final[frozenset[str]] = frozenset({
    "type",
    "enum",
    "const",
    "format",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "anyOf",
    "nullable",
})
"""Keywords the strict reduction interprets itself rather than copying."""

_ANNOTATION_ONLY_KEYWORDS: Final[frozenset[str]] = frozenset({
    "default",
    "examples",
    "$comment",
    "$schema",
    "$id",
    "$anchor",
    "deprecated",
    "readOnly",
    "writeOnly",
})
"""Keywords that assert nothing, so dropping them loses no constraint."""

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

_SCHEMA_MAP_KEYWORDS: Final[frozenset[str]] = frozenset({"properties"})
"""Keywords whose value maps a caller-chosen name to a subschema.

A reduction recurses into the values of these and leaves the names alone. The names are the tool's own property names, not schema
vocabulary, so filtering them against a keyword allowlist would delete every argument the tool declares.
"""

_SCHEMA_LIST_KEYWORDS: Final[frozenset[str]] = frozenset({"anyOf", "oneOf", "allOf", "prefixItems"})
"""Keywords whose value is a list of subschemas."""

_SCHEMA_KEYWORDS: Final[frozenset[str]] = frozenset({"items", "additionalProperties", "not", "if", "then", "else"})
"""Keywords whose value is itself a single subschema."""

_GEMINI_TYPE_NAMES: Final[frozenset[str]] = frozenset({
    "string",
    "integer",
    "number",
    "boolean",
    "array",
    "object",
})
"""JSON Schema types Gemini can express; ``null`` becomes ``nullable`` instead."""

GeminiParametersField = Literal["parameters", "parametersJsonSchema"]
"""The ``FunctionDeclaration`` field a Gemini argument schema is sent in."""


def _lookup_ref(root: dict[str, Any], ref: str) -> dict[str, Any] | None:
    """Resolve a local JSON pointer against a schema's definition containers.

    Args:
        root: The schema the pointer is relative to.
        ref: The ``$ref`` value, e.g. ``"#/$defs/Point"``, or ``"#"`` for
            the root itself.

    Returns:
        dict[str, Any] | None: The referenced schema, or ``None`` when the
        pointer is remote, malformed or unresolvable.
    """
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        return None
    segments = [segment.replace("~1", "/").replace("~0", "~") for segment in ref[2:].split("/") if segment]
    if not segments:
        return None
    current: object = root
    for segment in segments:
        if not is_json_object(current) or segment not in current:
            return None
        current = current[segment]
    return current if is_json_object(current) else None


@dataclass(slots=True)
class _InlineState:
    """Bookkeeping for one :func:`inline_refs` pass.

    Attributes:
        root: The schema every pointer is relative to.
        remaining: Schema nodes that may still be visited before further
            references collapse.
        active: How many times each reference is currently being expanded
            on the path from the root to the node being rewritten.
        collapsed: References that were replaced by a permissive schema.
    """

    root: dict[str, Any]
    remaining: int = MAX_INLINE_NODES
    active: dict[str, int] = field(default_factory=dict[str, int])
    collapsed: list[str] = field(default_factory=list[str])


def _inline_schema(node: object, state: _InlineState, depth: int) -> object:
    """Inline every local ``$ref`` within one schema node.

    Args:
        node: The schema node to rewrite; a boolean schema passes through.
        state: The pass's bookkeeping.
        depth: Remaining expansion depth.

    Returns:
        object: A new node with local references inlined.
    """
    if not is_json_object(node):
        return copy.deepcopy(node)
    state.remaining -= 1
    ref = node.get("$ref")
    if isinstance(ref, str):
        return _expand_ref(node, ref, state, depth)
    return _inline_members(node, state, depth)


def _inline_members(node: dict[str, Any], state: _InlineState, depth: int) -> dict[str, Any]:
    """Rewrite the keywords of one schema node, recursing only into subschemas.

    Values of data keywords such as ``enum``, ``const`` and ``default`` are
    copied verbatim, and the names in a ``properties`` map are kept whatever
    they are, including ``definitions`` or ``$defs``. Only the definition
    containers of the schema node itself are dropped.

    Args:
        node: The schema node whose keywords are rewritten.
        state: The pass's bookkeeping.
        depth: Remaining expansion depth.

    Returns:
        dict[str, Any]: The rewritten node.
    """
    result: dict[str, Any] = {}
    for key, value in node.items():
        if key in _DEF_CONTAINERS or key == "$ref":
            continue
        if key in _INLINE_MAP_KEYWORDS and is_json_object(value):
            result[key] = {name: _inline_schema(member, state, depth) for name, member in value.items()}
        elif (key in _INLINE_LIST_KEYWORDS or key in _INLINE_SCHEMA_KEYWORDS) and is_json_array(value):
            result[key] = [_inline_schema(member, state, depth) for member in value]
        elif key in _INLINE_SCHEMA_KEYWORDS:
            result[key] = _inline_schema(value, state, depth)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _expand_ref(node: dict[str, Any], ref: str, state: _InlineState, depth: int) -> object:
    """Replace one ``$ref`` node by its target, merged with its sibling keywords.

    Args:
        node: The schema node carrying the reference.
        ref: The reference it carries.
        state: The pass's bookkeeping.
        depth: Remaining expansion depth.

    Returns:
        object: The expanded node. A reference that is unresolvable, too
        deep, re-entered too often or past the node budget keeps only its
        sibling keywords, which is the permissive reading every dialect
        accepts.
    """
    siblings = _inline_members(node, state, depth)
    reentries = state.active.get(ref, 0)
    if depth <= 0 or reentries >= MAX_REF_REENTRY or state.remaining <= 0:
        state.collapsed.append(ref)
        return siblings
    target = _lookup_ref(state.root, ref)
    if target is None:
        _logger.warning("json_schema_ref_unresolved", ref=ref)
        state.collapsed.append(ref)
        return siblings
    state.active[ref] = reentries + 1
    try:
        expanded = _inline_schema(target, state, depth - 1)
    finally:
        state.active[ref] = reentries
    return dict(expanded) | siblings if is_json_object(expanded) else expanded


def _inline_with_report(schema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Expand every local ``$ref`` and report which references collapsed.

    Args:
        schema: The raw schema to expand.

    Returns:
        tuple[dict[str, Any], list[str]]: The expanded schema, and every
        reference that was replaced by its permissive sibling keywords.
    """
    state = _InlineState(root=schema)
    inlined = _inline_schema(schema, state, MAX_INLINE_DEPTH)
    if state.collapsed:
        _logger.warning(
            "json_schema_ref_collapsed",
            count=len(state.collapsed),
            refs=sorted(set(state.collapsed))[:8],
            node_budget_exhausted=state.remaining <= 0,
        )
    return (inlined if is_json_object(inlined) else {}), state.collapsed


def inline_refs(schema: dict[str, Any]) -> dict[str, Any]:
    """Expand every local ``$ref`` and drop the definition containers.

    Expansion is bounded three ways: at most :data:`MAX_INLINE_DEPTH` nested
    expansions, at most :data:`MAX_REF_REENTRY` re-expansions of a reference
    inside itself, and at most :data:`MAX_INLINE_NODES` visited nodes. A
    reference past any bound collapses to its sibling keywords, a permissive
    schema, so the work and the output stay linear in those bounds however
    the definitions refer to one another.

    Args:
        schema: The raw schema to expand.

    Returns:
        dict[str, Any]: A new schema with no ``$ref`` and no ``$defs``.
    """
    inlined, _ = _inline_with_report(schema)
    return inlined


def _type_names(declared: object) -> list[str]:
    """List the type names a ``type`` keyword declares.

    Args:
        declared: The ``type`` value.

    Returns:
        list[str]: The declared names; empty when none are declared.
    """
    if isinstance(declared, str):
        return [declared]
    if is_json_array(declared):
        return [str(entry) for entry in declared]
    return []


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
    names = _type_names(widened.get("type"))
    if names and "const" not in widened:
        if "null" not in names:
            widened["type"] = [*names, "null"]
        allowed = widened.get("enum")
        if is_json_array(allowed) and None not in allowed:
            widened["enum"] = [*allowed, None]
        return widened
    options = widened.get("anyOf")
    if is_json_array(options) and "const" not in widened and "enum" not in widened:
        if not any(is_json_object(option) and option.get("type") == "null" for option in options):
            widened["anyOf"] = [*options, {"type": "null"}]
        return widened
    description = widened.pop("description", None)
    wrapped: dict[str, Any] = {"anyOf": [widened, {"type": "null"}]}
    if description is not None:
        wrapped["description"] = description
    return wrapped


@dataclass(slots=True)
class _StrictState:
    """Bookkeeping for one strict-mode reduction.

    Attributes:
        properties: Object properties declared so far.
        enum_values: Enumeration values declared so far.
        string_chars: Combined length of names, enumeration values and
            constants declared so far.
        problems: Every reason the schema is not strict-mode compliant.
    """

    properties: int = 0
    enum_values: int = 0
    string_chars: int = 0
    problems: list[str] = field(default_factory=list[str])


def _strict_enumeration(values: list[Any], state: _StrictState) -> None:
    """Account one enumeration against the strict-mode size limits.

    Args:
        values: The enumeration's values.
        state: The reduction's bookkeeping.
    """
    state.enum_values += len(values)
    strings = [value for value in values if isinstance(value, str)]
    total = sum(len(value) for value in strings)
    state.string_chars += total
    if len(strings) > STRICT_LARGE_ENUM_VALUES and total > STRICT_MAX_LARGE_ENUM_CHARS:
        state.problems.append(f"string enum of {len(strings)} values totals {total} characters")


def _strict_keyword(key: str, value: object, reduced: dict[str, Any], state: _StrictState) -> None:
    """Carry one non-structural keyword into a strict-mode node.

    Args:
        key: The keyword.
        value: Its value.
        reduced: The strict-mode node being built.
        state: The reduction's bookkeeping.
    """
    if key in _ANNOTATION_ONLY_KEYWORDS:
        return
    if key in _STRICT_DESCRIPTIVE_KEYWORDS or key in _STRICT_CONSTRAINT_KEYWORDS:
        reduced[key] = copy.deepcopy(value)
        return
    state.problems.append(f"keyword {key!r} is not supported")


def _strict_object(node: dict[str, Any], reduced: dict[str, Any], state: _StrictState, level: int) -> None:
    """Close one object schema the way strict mode requires.

    Args:
        node: The source object schema.
        reduced: The strict-mode node being built.
        state: The reduction's bookkeeping.
        level: This object's nesting level, the root object being ``1``.
    """
    if level > STRICT_MAX_NESTING:
        state.problems.append(f"objects nest {level} levels deep")
    properties = node.get("properties")
    declared: dict[str, Any] = properties if is_json_object(properties) else {}
    additional = node.get("additionalProperties")
    if properties is not None and not is_json_object(properties):
        state.problems.append("properties is not an object")
    if additional is not None and not isinstance(additional, bool):
        state.problems.append("map-style additionalProperties cannot be expressed")
    elif not declared and additional is not False:
        state.problems.append("free-form object cannot be expressed")

    declared_required = node.get("required")
    required_names: set[str] = {str(name) for name in declared_required} if is_json_array(declared_required) else set()
    state.properties += len(declared)
    state.string_chars += sum(len(name) for name in declared)
    rebuilt: dict[str, Any] = {}
    for name, member in declared.items():
        reduced_member = _strict_node(member, state, level)
        rebuilt[name] = reduced_member if name in required_names else _widen_with_null(reduced_member)
    reduced["properties"] = rebuilt
    reduced["required"] = list(rebuilt)
    reduced["additionalProperties"] = False
    reduced.setdefault("type", "object")


def _strict_node(node: object, state: _StrictState, nesting: int) -> dict[str, Any]:
    """Reduce one schema node to OpenAI strict mode, recording every non-compliance.

    Args:
        node: The node to reduce.
        state: The reduction's bookkeeping.
        nesting: How many objects enclose this node.

    Returns:
        dict[str, Any]: The reduced node.
    """
    if not is_json_object(node):
        state.problems.append("boolean schema cannot be expressed")
        return {}

    reduced: dict[str, Any] = {}
    for key, value in node.items():
        if key not in _STRICT_STRUCTURAL_KEYWORDS:
            _strict_keyword(key, value, reduced, state)

    declared_type = node.get("type")
    names = _type_names(declared_type)
    if "type" in node:
        if not names or any(name not in _STRICT_TYPES for name in names):
            state.problems.append(f"type {declared_type!r} is not supported")
        reduced["type"] = declared_type if isinstance(declared_type, str) else names

    if "enum" in node:
        allowed = node["enum"]
        if is_json_array(allowed):
            _strict_enumeration(allowed, state)
            reduced["enum"] = copy.deepcopy(allowed)
        else:
            state.problems.append("enum is not an array")
    if "const" in node:
        constant = node["const"]
        if isinstance(constant, str):
            state.string_chars += len(constant)
        reduced["const"] = copy.deepcopy(constant)

    if "format" in node:
        declared_format = node["format"]
        if isinstance(declared_format, str) and declared_format in _STRICT_FORMATS:
            reduced["format"] = declared_format
        else:
            state.problems.append(f"format {declared_format!r} is not supported")

    if "anyOf" in node:
        options = node["anyOf"]
        if is_json_array(options) and options:
            reduced["anyOf"] = [_strict_node(option, state, nesting) for option in options]
        else:
            state.problems.append("anyOf is not a non-empty array")

    if "items" in node:
        items = node["items"]
        if is_json_object(items):
            reduced["items"] = _strict_node(items, state, nesting)
        else:
            state.problems.append("items is not a single schema")
    elif "array" in names:
        state.problems.append("array without items cannot be expressed")

    is_object = "object" in names or (not names and ("properties" in node or "additionalProperties" in node))
    if is_object:
        _strict_object(node, reduced, state, nesting + 1)
    elif "properties" in node or "additionalProperties" in node or "required" in node:
        state.problems.append("object keywords on a non-object schema")

    if not names and not is_object and "anyOf" not in node and "enum" not in node and "const" not in node:
        state.problems.append("schema accepts any value")

    if node.get("nullable") is True:
        return _widen_with_null(reduced)
    return reduced


def to_strict_subset(schema: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Reduce a raw schema to the subset OpenAI Responses strict mode accepts.

    References are inlined first. Every object then gains
    ``additionalProperties: false`` and a ``required`` list naming every one of
    its properties, with properties the tool declared optional widened to
    accept ``null`` so their optionality survives.

    A schema strict mode cannot express -- a free-form object, a map-style
    ``additionalProperties``, an unsupported keyword or format, a recursive
    reference that had to collapse, a root that is not an object, or one past
    the documented nesting, property, enumeration or string-size limits -- is
    returned unchanged with ``False``, so the caller sends the tool's own
    schema with ``strict: false`` instead of claiming a guarantee the
    reduction does not carry.

    Args:
        schema: The raw schema to reduce.

    Returns:
        tuple[dict[str, Any], bool]: The strict-mode schema and ``True``, or
        a copy of ``schema`` and ``False`` when it is not expressible in
        strict mode.
    """
    state = _StrictState()
    inlined, collapsed = _inline_with_report(schema)
    if collapsed:
        state.problems.append(f"{len(collapsed)} recursive or unresolvable references collapsed")
    if "anyOf" in inlined:
        state.problems.append("root schema uses anyOf")
    if _type_names(inlined.get("type")) != ["object"]:
        state.problems.append("root schema is not an object")
    reduced = _strict_node(inlined, state, 0)
    if state.properties > STRICT_MAX_OBJECT_PROPERTIES:
        state.problems.append(f"{state.properties} object properties exceed {STRICT_MAX_OBJECT_PROPERTIES}")
    if state.enum_values > STRICT_MAX_ENUM_VALUES:
        state.problems.append(f"{state.enum_values} enum values exceed {STRICT_MAX_ENUM_VALUES}")
    if state.string_chars > STRICT_MAX_STRING_CHARS:
        state.problems.append(f"{state.string_chars} schema string characters exceed {STRICT_MAX_STRING_CHARS}")
    if state.problems:
        _logger.debug("json_schema_strict_unsupported", problems=state.problems[:8])
        return copy.deepcopy(schema), False
    return reduced, True


def _gemini_type(declared: object) -> tuple[str | None, bool]:
    """Map a JSON Schema ``type`` to Gemini's uppercase type and nullability.

    Args:
        declared: The ``type`` value, a string or a list of strings.

    Returns:
        tuple[str | None, bool]: The uppercase Gemini type name (``None`` when
        no supported type is named) and whether ``null`` was among the types.
    """
    names = _type_names(declared)
    nullable = "null" in names
    for name in names:
        lowered = name.lower()
        if lowered in _GEMINI_TYPE_NAMES:
            return lowered.upper(), nullable
    return None, nullable


def _geminify(node: object) -> object:
    """Reduce one schema node to Gemini's supported subset.

    An ``OBJECT`` that declares no properties is left without a
    ``properties`` key rather than given an empty one, which Gemini rejects;
    :func:`gemini_function_parameters` decides how such a schema is sent.

    Args:
        node: The node to reduce.

    Returns:
        object: The reduced node.
    """
    if is_json_array(node):
        return [_geminify(entry) for entry in node]
    if not is_json_object(node):
        return node

    reduced: dict[str, Any] = {}
    for key, value in node.items():
        if key not in _GEMINI_ALLOWED_KEYWORDS or key == "type":
            continue
        if key in _SCHEMA_MAP_KEYWORDS:
            if is_json_object(value) and value:
                reduced[key] = {name: _geminify(member) for name, member in value.items()}
            continue
        if key in _SCHEMA_KEYWORDS or key in _SCHEMA_LIST_KEYWORDS:
            reduced[key] = _geminify(value)
            continue
        reduced[key] = value

    gemini_type, nullable = _gemini_type(node.get("type"))
    if gemini_type is not None:
        reduced["type"] = gemini_type
    if nullable:
        reduced["nullable"] = True

    if reduced.get("type") == "ARRAY" and "items" not in reduced:
        reduced["items"] = {"type": "STRING"}
    return reduced


def to_gemini_subset(schema: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw schema to the subset Google Gemini accepts.

    References are inlined, unsupported keywords are dropped, types are
    uppercased, a ``null`` member of a type union becomes ``nullable`` and
    arrays are given the ``items`` Gemini rejects a schema for omitting.

    Args:
        schema: The raw schema to reduce.

    Returns:
        dict[str, Any]: The reduced schema, always a Gemini ``OBJECT``. It
        carries ``properties`` only when it declares at least one.
    """
    reduced = _geminify(inline_refs(schema))
    if not is_json_object(reduced):
        return {"type": "OBJECT", "required": []}
    result = reduced
    result.setdefault("type", "OBJECT")
    if result["type"] == "OBJECT":
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
        if not is_json_object(properties):
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

    Every declared default is emitted, including a list default such as the
    empty list several sandbox parameters carry. That is what reached each
    provider before schema generation was consolidated here, so dropping one
    would silently narrow the advertised schema of tools working today.

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


def _gemini_has_open_object(node: object, *, is_root: bool) -> bool:
    """Report whether a reduced Gemini schema nests an ``OBJECT`` with no properties.

    Args:
        node: The reduced schema node.
        is_root: Whether ``node`` is the function's parameter object itself.

    Returns:
        bool: ``True`` when some nested ``OBJECT`` declares no properties,
        which Gemini's ``Schema`` rejects.
    """
    if is_json_array(node):
        return any(_gemini_has_open_object(entry, is_root=False) for entry in node)
    if not is_json_object(node):
        return False
    if not is_root and node.get("type") == "OBJECT" and not node.get("properties"):
        return True
    properties = node.get("properties")
    members: list[object] = list(properties.values()) if is_json_object(properties) else []
    members.extend(node[key] for key in ("items", "anyOf") if key in node)
    return any(_gemini_has_open_object(member, is_root=False) for member in members)


def gemini_function_parameters(func: ToolFunction) -> tuple[GeminiParametersField, dict[str, Any]] | None:
    """Choose how one function's arguments are declared to Gemini.

    Gemini rejects an ``OBJECT`` schema whose ``properties`` is empty or
    missing (``should be non-empty for OBJECT type``), both for the parameter
    object itself and for any object nested in it. A function that takes no
    arguments therefore declares no parameters at all. A schema whose objects
    are open-ended -- a nested free-form object, or a root that accepts
    arbitrary keys -- cannot be written as a ``Schema``, so it is sent in
    ``parametersJsonSchema``, which takes JSON Schema as-is. Everything else
    goes in ``parameters`` as the uppercase-typed subset.

    Args:
        func: The tool function being declared.

    Returns:
        tuple[GeminiParametersField, dict[str, Any]] | None: The declaration
        field and the schema to put in it, or ``None`` when the function
        takes no arguments and the field must be omitted.
    """
    reduced = function_parameters(func, uppercase_types=True)
    if not reduced.get("properties"):
        additional = func.input_schema.get("additionalProperties") if func.input_schema is not None else None
        if additional is None or additional is False:
            return None
        return "parametersJsonSchema", function_parameters(func)
    if _gemini_has_open_object(reduced, is_root=True):
        return "parametersJsonSchema", function_parameters(func)
    return "parameters", reduced
