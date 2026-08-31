# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Translation between JSON request payloads and native argument values.

Browser clients can only send JSON, while the extension module expects real
``bytes``, tuples and integers. This module converts in both directions, driven
by the :class:`~hexbench.catalog.ValueKind` recorded for each parameter, and
converts results back into a JSON-safe shape that preserves binary payloads as
hexadecimal rather than lossily decoding them as text.
"""

from __future__ import annotations

import binascii
import math
from typing import Final, cast

from intellicrack_hexcore import Bookmark

from hexbench.catalog import Parameter, ValueKind


__all__ = ["DecodeError", "JsonValue", "decode_argument", "decode_arguments", "encode_result"]

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
"""Any value that can arrive from, or be sent to, a JSON client."""

_MAX_INLINE_BYTES: Final = 4096
_BYTES_TAG: Final = "__bytes__"
_MAX_OCTET: Final = 255
_PAIR_LENGTH: Final = 2
_BOOKMARK_FIELDS: Final = ("offset", "length", "label", "color")
_TRUE_WORDS: Final = frozenset({"true", "1", "yes", "on"})
_FALSE_WORDS: Final = frozenset({"false", "0", "no", "off"})


class DecodeError(ValueError):
    """Raised when a JSON payload cannot be converted to a native argument."""


def _decode_bytes(value: JsonValue, parameter: str) -> bytes:
    """Convert a JSON payload into a byte string.

    Accepts either a hexadecimal string, optionally whitespace separated, or a
    list of integers in the range 0-255.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        bytes: The decoded bytes.

    Raises:
        DecodeError: If the payload is not valid hexadecimal or a byte list.
    """
    if isinstance(value, str):
        compact = "".join(value.split())
        if not compact:
            return b""
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            message = f"{parameter}: expected hexadecimal bytes, got {value!r} ({exc})"
            raise DecodeError(message) from exc
    if isinstance(value, list):
        octets: list[int] = []
        for index, item in enumerate(value):
            if not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= _MAX_OCTET:
                message = f"{parameter}[{index}]: expected an integer in 0-255, got {item!r}"
                raise DecodeError(message)
            octets.append(item)
        return bytes(octets)
    message = f"{parameter}: expected a hex string or a list of byte values, got {type(value).__name__}"
    raise DecodeError(message)


def _decode_int(value: JsonValue, parameter: str) -> int:
    """Convert a JSON payload into an integer.

    Accepts JSON numbers and strings, the latter allowing ``0x`` and ``0b``
    prefixes so masks and addresses can be typed in their natural base.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        int: The decoded integer.

    Raises:
        DecodeError: If the payload is not an integer in any accepted form.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            message = f"{parameter}: expected an integer, got the fractional value {value!r}"
            raise DecodeError(message)
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            message = f"{parameter}: expected an integer, got an empty string"
            raise DecodeError(message)
        try:
            return int(text, 0)
        except ValueError as exc:
            message = f"{parameter}: expected an integer, got {value!r}"
            raise DecodeError(message) from exc
    message = f"{parameter}: expected an integer, got {type(value).__name__}"
    raise DecodeError(message)


def _decode_float(value: JsonValue, parameter: str) -> float:
    """Convert a JSON payload into a floating point number.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        float: The decoded float.

    Raises:
        DecodeError: If the payload is not a finite number.
    """
    if isinstance(value, bool):
        message = f"{parameter}: expected a number, got a boolean"
        raise DecodeError(message)
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        try:
            result = float(value.strip())
        except ValueError as exc:
            message = f"{parameter}: expected a number, got {value!r}"
            raise DecodeError(message) from exc
    else:
        message = f"{parameter}: expected a number, got {type(value).__name__}"
        raise DecodeError(message)
    if not math.isfinite(result):
        message = f"{parameter}: expected a finite number, got {result!r}"
        raise DecodeError(message)
    return result


def _decode_bool(value: JsonValue, parameter: str) -> bool:
    """Convert a JSON payload into a boolean.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        bool: The decoded boolean.

    Raises:
        DecodeError: If the payload is not a boolean or a recognised spelling.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().casefold()
        if text in _TRUE_WORDS:
            return True
        if text in _FALSE_WORDS:
            return False
    message = f"{parameter}: expected a boolean, got {value!r}"
    raise DecodeError(message)


def _decode_text(value: JsonValue, parameter: str) -> str:
    """Convert a JSON payload into a string.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        str: The decoded string.

    Raises:
        DecodeError: If the payload is not a string.
    """
    if isinstance(value, str):
        return value
    message = f"{parameter}: expected a string, got {type(value).__name__}"
    raise DecodeError(message)


def _decode_pair(value: JsonValue, parameter: str, kind: ValueKind) -> tuple[int, int] | tuple[bool, bool]:
    """Convert a JSON payload into a two element tuple.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.
        kind: Whether the pair holds integers or booleans.

    Returns:
        tuple[int, int] | tuple[bool, bool]: The decoded pair.

    Raises:
        DecodeError: If the payload is not a two element sequence.
    """
    if not isinstance(value, list) or len(value) != _PAIR_LENGTH:
        message = f"{parameter}: expected a two element list, got {value!r}"
        raise DecodeError(message)
    first, second = value[0], value[1]
    if kind is ValueKind.INT_PAIR:
        return (_decode_int(first, f"{parameter}[0]"), _decode_int(second, f"{parameter}[1]"))
    return (_decode_bool(first, f"{parameter}[0]"), _decode_bool(second, f"{parameter}[1]"))


def _decode_bytes_map(value: JsonValue, parameter: str) -> dict[str, bytes]:
    """Convert a JSON object into a mapping of names to byte strings.

    Args:
        value: Raw JSON value.
        parameter: Parameter name, used in error messages.

    Returns:
        dict[str, bytes]: The decoded mapping.

    Raises:
        DecodeError: If the payload is not a JSON object.
    """
    if not isinstance(value, dict):
        message = f"{parameter}: expected an object of hex encoded values, got {type(value).__name__}"
        raise DecodeError(message)
    return {key: _decode_bytes(item, f"{parameter}[{key!r}]") for key, item in value.items()}


def _decode_bookmark(value: JsonValue, parameter: str) -> Bookmark:
    """Convert a JSON object into a bookmark.

    Args:
        value: Raw JSON value, expected to carry ``offset``, ``length``,
            ``label`` and ``color``.
        parameter: Parameter name, used in error messages.

    Returns:
        Bookmark: The constructed bookmark.

    Raises:
        DecodeError: If the payload is not an object with the four fields.
    """
    if not isinstance(value, dict):
        message = f"{parameter}: expected a bookmark object, got {type(value).__name__}"
        raise DecodeError(message)
    missing = [field for field in _BOOKMARK_FIELDS if field not in value]
    if missing:
        message = f"{parameter}: bookmark is missing {', '.join(missing)}"
        raise DecodeError(message)
    return Bookmark(
        _decode_int(value["offset"], f"{parameter}.offset"),
        _decode_int(value["length"], f"{parameter}.length"),
        _decode_text(value["label"], f"{parameter}.label"),
        _decode_text(value["color"], f"{parameter}.color"),
    )


def decode_argument(parameter: Parameter, value: JsonValue) -> object:
    """Convert one JSON value into the native argument the extension expects.

    Propagates :class:`DecodeError` from the per-kind decoder when the value
    does not match the parameter's kind.

    Args:
        parameter: Catalogued parameter describing the target type.
        value: Raw JSON value supplied by the client.

    Returns:
        object: The native argument value.
    """
    match parameter.kind:
        case ValueKind.INT:
            return _decode_int(value, parameter.name)
        case ValueKind.FLOAT:
            return _decode_float(value, parameter.name)
        case ValueKind.BOOL:
            return _decode_bool(value, parameter.name)
        case ValueKind.TEXT:
            return _decode_text(value, parameter.name)
        case ValueKind.BYTES:
            return _decode_bytes(value, parameter.name)
        case ValueKind.INT_PAIR | ValueKind.BOOL_PAIR:
            return _decode_pair(value, parameter.name, parameter.kind)
        case ValueKind.BYTES_MAP:
            return _decode_bytes_map(value, parameter.name)
        case ValueKind.BOOKMARK:
            return _decode_bookmark(value, parameter.name)


def decode_arguments(parameters: tuple[Parameter, ...], payload: dict[str, JsonValue]) -> list[object]:
    """Convert a JSON argument object into a positional argument list.

    Args:
        parameters: Ordered catalogued parameters for the operation.
        payload: Client supplied mapping of parameter name to raw JSON value.

    Returns:
        list[object]: Positional arguments in declaration order.

    Raises:
        DecodeError: If a parameter is missing, unexpected, or fails conversion.
    """
    missing = [parameter.name for parameter in parameters if parameter.name not in payload]
    if missing:
        message = f"missing required argument(s): {', '.join(missing)}"
        raise DecodeError(message)
    unexpected = sorted(set(payload) - {parameter.name for parameter in parameters})
    if unexpected:
        message = f"unexpected argument(s): {', '.join(unexpected)}"
        raise DecodeError(message)
    return [decode_argument(parameter, payload[parameter.name]) for parameter in parameters]


def encode_result(value: object) -> JsonValue:
    """Convert a native return value into a JSON-safe structure.

    Byte strings are tagged and hex encoded so the client can render them
    faithfully, and large payloads are truncated with the full length retained
    so the GUI can report how much was elided rather than silently showing less.

    Args:
        value: Native value returned by the extension module.

    Returns:
        JsonValue: A structure composed only of JSON-representable types.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, Bookmark):
        return {field: getattr(value, field) for field in _BOOKMARK_FIELDS}
    if isinstance(value, memoryview):
        return _encode_bytes(value.tobytes())
    if isinstance(value, (bytes, bytearray)):
        return _encode_bytes(bytes(value))
    if isinstance(value, (list, tuple)):
        return [encode_result(item) for item in cast("list[object] | tuple[object, ...]", value)]
    if isinstance(value, dict):
        return {str(key): encode_result(item) for key, item in cast("dict[object, object]", value).items()}
    return repr(value)


def _encode_bytes(raw: bytes) -> dict[str, JsonValue]:
    """Tag and hex encode a byte string for transport to the client.

    Args:
        raw: Complete byte string to encode.

    Returns:
        dict[str, JsonValue]: Tagged object carrying the hex payload, the full
        length, and whether the payload was truncated.
    """
    head = raw[:_MAX_INLINE_BYTES]
    return {
        _BYTES_TAG: binascii.hexlify(head).decode("ascii"),
        "length": len(raw),
        "truncated": len(raw) > _MAX_INLINE_BYTES,
    }
