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

import json
from typing import TYPE_CHECKING, Any, TypeIs


if TYPE_CHECKING:
    from collections.abc import Callable


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


def map_json_strings(value: object, rename: Callable[[str], str]) -> object:
    """Apply a string mapping to every object key and every string in a JSON value.

    The walk is iterative, so a value nested far deeper than the interpreter's
    recursion limit is mapped as surely as a flat one.

    Args:
        value: The JSON value to map.
        rename: Maps one string, key or member, to its replacement.

    Returns:
        object: A new value of the same shape. When two keys of one object map
        to the same string, the later member wins at the earlier position.
    """
    root: list[object] = [None]
    pending: list[tuple[object, dict[str, object] | list[object], str | int]] = [(value, root, 0)]
    while pending:
        source, target, slot = pending.pop()
        mapped: object
        if isinstance(source, str):
            mapped = rename(source)
        elif is_json_object(source):
            members: dict[str, object] = {}
            for key, member in source.items():
                renamed = rename(key)
                members[renamed] = None
                pending.append((member, members, renamed))
            mapped = members
        elif is_json_array(source):
            items: list[object] = [None] * len(source)
            pending.extend((member, items, index) for index, member in enumerate(source))
            mapped = items
        else:
            mapped = source
        if isinstance(target, dict):
            target[str(slot)] = mapped
        else:
            target[int(slot)] = mapped
    return root[0]


def copy_json(value: object) -> object:
    """Copy a JSON value, however deeply it nests.

    :func:`copy.deepcopy` recurses once per level and fails past the
    interpreter's recursion limit; this walk is iterative.

    Args:
        value: The JSON value to copy.

    Returns:
        object: A new value equal to ``value`` sharing no container with it.
    """
    return map_json_strings(value, _unchanged)


def _unchanged(text: str) -> str:
    """Return a string as it is.

    Args:
        text: The string.

    Returns:
        str: ``text``.
    """
    return text


def json_equality_key(value: object) -> str:
    """Build the text under which JSON Schema equality becomes string equality.

    JSON Schema compares numbers by value, so ``1`` and ``1.0`` are equal,
    but keeps booleans apart from numbers, so ``true`` and ``1`` are not;
    arrays compare in order and objects without regard to member order.
    Python's own ``==`` gets the booleans wrong, and neither lists nor dicts
    can be hashed. The key is canonical JSON text -- members sorted by name,
    integral numbers written as integers -- so equal keys mean equal JSON
    values, and since a string hashes, comparing ``n`` values for duplicates
    takes ``n`` steps rather than ``n`` squared. Both the walk and the key
    are flat, so no nesting depth is too deep.

    Args:
        value: The JSON value.

    Returns:
        str: Its key.
    """
    results: list[str] = []
    stack: list[tuple[object, bool]] = [(value, False)]
    while stack:
        current, built = stack.pop()
        if is_json_array(current):
            if not built:
                stack.append((current, True))
                stack.extend((member, False) for member in reversed(current))
                continue
            count = len(current)
            members = results[len(results) - count :] if count else []
            del results[len(results) - count :]
            results.append(f"[{','.join(members)}]")
        elif is_json_object(current):
            names = sorted(current)
            if not built:
                stack.append((current, True))
                stack.extend((current[name], False) for name in reversed(names))
                continue
            count = len(names)
            members = results[len(results) - count :] if count else []
            del results[len(results) - count :]
            results.append("{" + ",".join(f"{json.dumps(name)}:{member}" for name, member in zip(names, members, strict=True)) + "}")
        elif isinstance(current, bool):
            results.append("true" if current else "false")
        elif isinstance(current, int):
            results.append(str(current))
        elif isinstance(current, float):
            results.append(str(int(current)) if current.is_integer() else repr(current))
        elif isinstance(current, str):
            results.append(json.dumps(current))
        else:
            results.append("null" if current is None else f"!{current!r}")
    return results[0]


__all__ = [
    "JsonArray",
    "JsonObject",
    "as_json_array",
    "as_json_object",
    "copy_json",
    "is_json_array",
    "is_json_object",
    "json_array_at",
    "json_equality_key",
    "json_object_at",
    "json_str_at",
    "map_json_strings",
]
