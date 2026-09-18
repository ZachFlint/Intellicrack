# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""JSON Schema validation for structured tool output.

A server that publishes an ``outputSchema`` has made a promise about what its
tools return. This module checks the promise, so a result that quietly does
not match is reported as a protocol violation rather than handed to the model
as if it were what the tool advertised.

The checker covers the JSON Schema 2020-12 assertion vocabulary that tool
output schemas actually use: types, enumerations, object and array shape,
numeric and string bounds, and the boolean combinators. ``$ref`` is resolved
first through :func:`intellicrack.bridges.json_schema.inline_refs`, which is
the same expansion the provider boundary applies, so a schema validates here
exactly as it is understood everywhere else in Intellicrack.

Annotation-only keywords -- ``title``, ``description``, ``default``,
``examples``, ``format``, ``$comment`` -- assert nothing and are skipped, which
is what the specification calls for.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from intellicrack.bridges.json_schema import inline_refs
from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence


_logger = get_logger(__name__)


MAX_VALIDATION_DEPTH: Final[int] = 64
"""Deepest nesting the checker descends before giving up on a branch."""

MAX_VIOLATIONS: Final[int] = 32
"""Most violations collected before reporting stops, so one badly-shaped
result cannot produce an unbounded error message.
"""

_TYPE_CHECKS: Final[dict[str, str]] = {
    "null": "null",
    "boolean": "a boolean",
    "object": "an object",
    "array": "an array",
    "number": "a number",
    "integer": "an integer",
    "string": "a string",
}

_NUMERIC_EPSILON: Final[float] = 1e-9

_ENUM_PREVIEW_VALUES: Final[int] = 8
"""How many allowed values an enumeration violation names before eliding."""


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    """One way an instance failed its schema.

    Attributes:
        path: JSON-pointer-like location of the offending value, e.g.
            ``$.items[2].name``.
        message: What the schema required and what was found instead.
    """

    path: str
    message: str

    def __str__(self) -> str:
        """Render the violation as one readable line.

        Returns:
            str: ``<path>: <message>``.
        """
        return f"{self.path}: {self.message}"


def _json_type_of(value: object) -> str:
    """Name the JSON type of a decoded value.

    Args:
        value: The value to classify.

    Returns:
        str: One of the JSON Schema type names, or ``"unknown"`` for a value
        that did not come from JSON.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if is_json_array(value):
        return "array"
    if is_json_object(value):
        return "object"
    return "unknown"


def _matches_type(value: object, declared: str) -> bool:
    """Check a value against one declared JSON Schema type.

    Args:
        value: The value to check.
        declared: The schema's type name.

    Returns:
        bool: ``True`` when the value satisfies the type. An integral float
        satisfies ``integer``, which is what the specification requires.
    """
    actual = _json_type_of(value)
    if declared == "number":
        return actual in {"integer", "number"}
    if declared == "integer":
        return actual == "integer" or (actual == "number" and isinstance(value, float) and value.is_integer())
    return actual == declared


def _check_type(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the ``type`` keyword.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation when the type does not match.
    """
    declared = schema.get("type")
    if declared is None:
        return
    names = [declared] if isinstance(declared, str) else [item for item in declared if isinstance(item, str)]
    if not names or any(_matches_type(value, name) for name in names):
        return
    expected = " or ".join(_TYPE_CHECKS.get(name, name) for name in names)
    yield SchemaViolation(path=path, message=f"expected {expected}, found {_TYPE_CHECKS.get(_json_type_of(value), 'an unsupported value')}")


def _check_enumeration(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the ``enum`` and ``const`` keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed keyword.
    """
    if "const" in schema and value != schema["const"]:
        yield SchemaViolation(path=path, message=f"must equal {schema['const']!r}")
    allowed = schema.get("enum")
    if is_json_array(allowed) and value not in allowed:
        rendered = ", ".join(repr(item) for item in allowed[:_ENUM_PREVIEW_VALUES])
        suffix = ", ..." if len(allowed) > _ENUM_PREVIEW_VALUES else ""
        yield SchemaViolation(path=path, message=f"must be one of [{rendered}{suffix}]")


def _check_number(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the numeric bound keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed bound.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return
    number = float(value)
    bounds: tuple[tuple[str, str], ...] = (
        ("minimum", "at least"),
        ("maximum", "at most"),
        ("exclusiveMinimum", "greater than"),
        ("exclusiveMaximum", "less than"),
    )
    for keyword, phrasing in bounds:
        limit = schema.get(keyword)
        if isinstance(limit, bool) or not isinstance(limit, int | float):
            continue
        boundary = float(limit)
        failed = (
            (keyword == "minimum" and number < boundary)
            or (keyword == "maximum" and number > boundary)
            or (keyword == "exclusiveMinimum" and number <= boundary)
            or (keyword == "exclusiveMaximum" and number >= boundary)
        )
        if failed:
            yield SchemaViolation(path=path, message=f"must be {phrasing} {limit}")

    divisor = schema.get("multipleOf")
    if not isinstance(divisor, bool) and isinstance(divisor, int | float) and float(divisor) > 0:
        remainder = math.fmod(number, float(divisor))
        if min(abs(remainder), abs(abs(remainder) - abs(float(divisor)))) > _NUMERIC_EPSILON:
            yield SchemaViolation(path=path, message=f"must be a multiple of {divisor}")


def _check_string(value: object, schema: Mapping[str, Any], path: str) -> Iterator[SchemaViolation]:
    """Check the string bound and pattern keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.

    Yields:
        SchemaViolation: One violation per failed keyword.
    """
    if not isinstance(value, str):
        return
    minimum = schema.get("minLength")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must be at least {minimum} characters")
    maximum = schema.get("maxLength")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must be at most {maximum} characters")
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        try:
            compiled = re.compile(pattern)
        except re.error:
            _logger.debug("json_schema_pattern_invalid", pattern=pattern[:128])
            return
        if compiled.search(value) is None:
            yield SchemaViolation(path=path, message=f"must match {pattern!r}")


def _check_array(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the array shape keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed keyword or element.
    """
    if not is_json_array(value):
        return
    minimum = schema.get("minItems")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must have at least {minimum} items")
    maximum = schema.get("maxItems")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must have at most {maximum} items")
    if schema.get("uniqueItems") is True and _has_duplicates(value):
        yield SchemaViolation(path=path, message="items must be unique")

    prefix = schema.get("prefixItems")
    prefix_schemas = list(prefix) if is_json_array(prefix) else []
    for index, element in enumerate(value):
        if index < len(prefix_schemas):
            yield from _validate(element, prefix_schemas[index], f"{path}[{index}]", depth - 1)
            continue
        items = schema.get("items")
        if items is not None:
            yield from _validate(element, items, f"{path}[{index}]", depth - 1)


def _has_duplicates(items: Sequence[object]) -> bool:
    """Report whether a JSON array holds two equal elements.

    Equality is JSON equality, so unhashable values are compared directly
    rather than through a set.

    Args:
        items: The array elements.

    Returns:
        bool: ``True`` when any two elements are equal.
    """
    seen: list[object] = []
    for item in items:
        if any(item == existing for existing in seen):
            return True
        seen.append(item)
    return False


def _check_object(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the object shape keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed keyword or property.
    """
    if not is_json_object(value):
        return
    required = schema.get("required")
    if is_json_array(required):
        for name in required:
            if isinstance(name, str) and name not in value:
                yield SchemaViolation(path=path, message=f"missing required property {name!r}")

    minimum = schema.get("minProperties")
    if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
        yield SchemaViolation(path=path, message=f"must have at least {minimum} properties")
    maximum = schema.get("maxProperties")
    if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
        yield SchemaViolation(path=path, message=f"must have at most {maximum} properties")

    properties = schema.get("properties")
    declared = properties if is_json_object(properties) else {}
    patterns = schema.get("patternProperties")
    declared_patterns = patterns if is_json_object(patterns) else {}

    for name, item in value.items():
        matched = False
        if name in declared:
            matched = True
            yield from _validate(item, declared[name], f"{path}.{name}", depth - 1)
        for expression, sub_schema in declared_patterns.items():
            if _pattern_matches(expression, name):
                matched = True
                yield from _validate(item, sub_schema, f"{path}.{name}", depth - 1)
        if matched:
            continue
        additional = schema.get("additionalProperties")
        if additional is False:
            yield SchemaViolation(path=path, message=f"unexpected property {name!r}")
        elif additional is not None and additional is not True:
            yield from _validate(item, additional, f"{path}.{name}", depth - 1)


def _pattern_matches(expression: str, name: str) -> bool:
    """Test one ``patternProperties`` key against a property name.

    Args:
        expression: The regular expression from the schema.
        name: The property name.

    Returns:
        bool: ``True`` when the expression matches, ``False`` when it does
        not or cannot be compiled.
    """
    try:
        return re.compile(expression).search(name) is not None
    except re.error:
        _logger.debug("json_schema_property_pattern_invalid", pattern=expression[:128])
        return False


def _check_combinators(value: object, schema: Mapping[str, Any], path: str, depth: int) -> Iterator[SchemaViolation]:
    """Check the boolean combinator keywords.

    Args:
        value: The value to check.
        schema: The schema node.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Yields:
        SchemaViolation: One violation per failed combinator.
    """
    all_of = schema.get("allOf")
    if is_json_array(all_of):
        for branch in all_of:
            yield from _validate(value, branch, path, depth - 1)

    any_of = schema.get("anyOf")
    if is_json_array(any_of) and any_of and all(_validate(value, branch, path, depth - 1) for branch in any_of):
        yield SchemaViolation(path=path, message="does not match any accepted shape")

    one_of = schema.get("oneOf")
    if is_json_array(one_of) and one_of:
        matches = sum(1 for branch in one_of if not _validate(value, branch, path, depth - 1))
        if matches != 1:
            yield SchemaViolation(path=path, message=f"must match exactly one accepted shape, matched {matches}")

    negated = schema.get("not")
    if negated is not None and not _validate(value, negated, path, depth - 1):
        yield SchemaViolation(path=path, message="matches a shape the schema forbids")

    condition = schema.get("if")
    if condition is not None:
        branch = schema.get("then") if not _validate(value, condition, path, depth - 1) else schema.get("else")
        if branch is not None:
            yield from _validate(value, branch, path, depth - 1)


def _validate(value: object, schema: object, path: str, depth: int) -> list[SchemaViolation]:
    """Validate one value against one schema node.

    Args:
        value: The value to check.
        schema: The schema node, which may be a boolean schema.
        path: Location of ``value``.
        depth: Remaining recursion budget.

    Returns:
        list[SchemaViolation]: Every violation found, capped at
        :data:`MAX_VIOLATIONS`.
    """
    if schema is True or schema is None:
        return []
    if schema is False:
        return [SchemaViolation(path=path, message="no value is accepted here")]
    if not is_json_object(schema):
        return []
    if depth <= 0:
        _logger.warning("json_schema_validation_depth_exceeded", path=path)
        return []

    violations: list[SchemaViolation] = []
    for check in (
        _check_type(value, schema, path),
        _check_enumeration(value, schema, path),
        _check_number(value, schema, path),
        _check_string(value, schema, path),
        _check_array(value, schema, path, depth),
        _check_object(value, schema, path, depth),
        _check_combinators(value, schema, path, depth),
    ):
        for violation in check:
            violations.append(violation)
            if len(violations) >= MAX_VIOLATIONS:
                return violations
    return violations


def validate_against_schema(value: object, schema: Mapping[str, Any]) -> list[SchemaViolation]:
    """Validate a decoded JSON value against a JSON Schema.

    Local ``$ref`` pointers are expanded first, so a schema built from
    ``$defs`` validates as written.

    Args:
        value: The decoded JSON value to check.
        schema: The schema to check it against.

    Returns:
        list[SchemaViolation]: Every violation found, empty when the value
        conforms.
    """
    expanded = inline_refs(dict(schema))
    return _validate(value, expanded, "$", MAX_VALIDATION_DEPTH)
