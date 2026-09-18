# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Type narrowing for decoded JSON payloads.

Every value that arrives from :func:`json.loads`, an HTTP response body or a raw JSON Schema is statically an :class:`object`. A bare
``isinstance(value, dict)`` narrows it to ``dict[Unknown, Unknown]``, because the check proves nothing about the key or value types, and
that partial unknown then propagates through every expression downstream.

JSON itself does carry that guarantee: an object always has string keys, and its members are always JSON values. The predicates here state
that guarantee once, as :data:`typing.TypeIs`, so a caller narrows straight to a usable type in both the positive and the negative branch
and nothing downstream is unknown.
"""

from __future__ import annotations

from typing import Any, TypeIs


JsonObject = dict[str, Any]
"""A decoded JSON object.

Keys are always strings; values are JSON values.
"""

JsonArray = list[Any]
"""A decoded JSON array."""


def is_json_object(value: object) -> TypeIs[JsonObject]:
    """Check whether a decoded JSON value is an object.

    Args:
        value: The value to test, typically straight out of a decoded payload.

    Returns:
        TypeIs[JsonObject]: True when ``value`` is a mapping, narrowing it to
        :data:`JsonObject` for the caller.
    """
    return isinstance(value, dict)


def is_json_array(value: object) -> TypeIs[JsonArray]:
    """Check whether a decoded JSON value is an array.

    Args:
        value: The value to test, typically straight out of a decoded payload.

    Returns:
        TypeIs[JsonArray]: True when ``value`` is a list, narrowing it to
        :data:`JsonArray` for the caller.
    """
    return isinstance(value, list)


def as_json_object(value: object) -> JsonObject | None:
    """Return a decoded JSON value as an object, or ``None`` if it is not one.

    Args:
        value: The value to convert.

    Returns:
        JsonObject | None: ``value`` narrowed to a JSON object, or ``None``
        when it is any other kind of JSON value.
    """
    return value if is_json_object(value) else None


def as_json_array(value: object) -> JsonArray | None:
    """Return a decoded JSON value as an array, or ``None`` if it is not one.

    Args:
        value: The value to convert.

    Returns:
        JsonArray | None: ``value`` narrowed to a JSON array, or ``None`` when
        it is any other kind of JSON value.
    """
    return value if is_json_array(value) else None


def json_object_at(container: JsonObject, key: str) -> JsonObject | None:
    """Read one key of a JSON object, requiring the member to be an object.

    Args:
        container: The JSON object to read from.
        key: The member name.

    Returns:
        JsonObject | None: The member narrowed to a JSON object, or ``None``
        when the key is absent or the member is another kind of value.
    """
    return as_json_object(container.get(key))


def json_array_at(container: JsonObject, key: str) -> JsonArray | None:
    """Read one key of a JSON object, requiring the member to be an array.

    Args:
        container: The JSON object to read from.
        key: The member name.

    Returns:
        JsonArray | None: The member narrowed to a JSON array, or ``None``
        when the key is absent or the member is another kind of value.
    """
    return as_json_array(container.get(key))


def json_str_at(container: JsonObject, key: str) -> str | None:
    """Read one key of a JSON object, requiring the member to be a string.

    Args:
        container: The JSON object to read from.
        key: The member name.

    Returns:
        str | None: The member when it is a string, or ``None`` when the key
        is absent or the member is another kind of value.
    """
    value = container.get(key)
    return value if isinstance(value, str) else None


__all__ = [
    "JsonArray",
    "JsonObject",
    "as_json_array",
    "as_json_object",
    "is_json_array",
    "is_json_object",
    "json_array_at",
    "json_object_at",
    "json_str_at",
]
