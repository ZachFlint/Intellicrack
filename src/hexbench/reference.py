# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Facts about the engine that its signatures do not carry.

The catalogue knows that ``transform_data`` accepts a ``dict[str, bytes]``, but
not that ``aes_ecb_encrypt`` wants a sixteen, twenty-four or thirty-two byte
``key`` and an optional ``padding`` spelled as literal ASCII. It knows that
``list_process_memory_regions`` yields four integers per region, but not that two
of them are raw Win32 bit flags. Everything in this module is that second kind
of knowledge: constants and per-name argument shapes the GUI needs to build a
usable form instead of a bare text box.

Only :func:`raw_capable_operations` is different. It is derived from the
catalogue rather than written down, because which operations return binary is a
property of the compiled engine and must never drift from it.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from hexbench.catalog import build_catalog


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from hexbench.codec import JsonValue


__all__ = [
    "TransformParameter",
    "as_json",
    "classification_codes",
    "custom_crc_widths",
    "diff_types",
    "hash_algorithms",
    "memory_state_flags",
    "page_protection_flags",
    "raw_capable_operations",
    "transform_parameters",
]

_BYTES_RETURN: Final = "bytes"
_ANY_WIDTH: Final[tuple[int, ...]] = ()
_ONE_BYTE: Final[tuple[int, ...]] = (1,)
_AES_KEY_WIDTHS: Final[tuple[int, ...]] = (16, 24, 32)
_NO_CHOICES: Final[tuple[str, ...]] = ()
_PADDING_CHOICES: Final[tuple[str, ...]] = ("pkcs7", "none", "zero", "iso10126")

_FIRST_BYTE_NOTE: Final = "Only the first byte is used."
_REPEATING_NOTE: Final = "Repeated across the selection; must not be empty."
_SHIFT_NOTE: Final = "Bit count 0-7; a larger value is rejected."
_ROTATE_NOTE: Final = "Bit count, taken modulo 8."


@dataclass(frozen=True, slots=True)
class TransformParameter:
    """One entry of the ``params`` mapping a transform expects.

    Attributes:
        key: Name of the entry in the ``params`` mapping.
        required: Whether omitting the entry is an error.
        byte_widths: Accepted lengths of the raw value, empty when any non-empty
            length is accepted.
        choices: Complete set of accepted values for an enumerated parameter,
            spelled exactly as the ASCII bytes must be supplied, empty when the
            parameter is not enumerated.
        default_hex: Hexadecimal value applied when an optional entry is
            omitted, or ``None`` when the parameter is required.
        note: Constraint the byte widths alone do not express.
    """

    key: str
    required: bool
    byte_widths: tuple[int, ...]
    choices: tuple[str, ...]
    default_hex: str | None
    note: str


def _required(key: str, widths: tuple[int, ...], note: str) -> TransformParameter:
    """Describe a mandatory transform parameter.

    Args:
        key: Name of the entry in the ``params`` mapping.
        widths: Accepted lengths of the raw value.
        note: Constraint the byte widths alone do not express.

    Returns:
        TransformParameter: The described parameter.
    """
    return TransformParameter(key=key, required=True, byte_widths=widths, choices=_NO_CHOICES, default_hex=None, note=note)


_NO_PARAMETERS: Final[tuple[TransformParameter, ...]] = ()

_XOR_SINGLE_KEY: Final = _required("key", _ONE_BYTE, _FIRST_BYTE_NOTE)
_XOR_REPEATING_KEY: Final = _required("key", _ANY_WIDTH, _REPEATING_NOTE)
_MASK_PATTERN: Final = _required("pattern", _ANY_WIDTH, _REPEATING_NOTE)
_AES_KEY: Final = _required("key", _AES_KEY_WIDTHS, "AES-128, AES-192 or AES-256 key material.")

_AES_PADDING: Final = TransformParameter(
    key="padding",
    required=False,
    byte_widths=_ANY_WIDTH,
    choices=_PADDING_CHOICES,
    default_hex="706b637337",
    note="Supplied as the literal ASCII bytes of the mode name.",
)

_ROLLING_INCREMENT: Final = TransformParameter(
    key="increment",
    required=False,
    byte_widths=_ONE_BYTE,
    choices=_NO_CHOICES,
    default_hex="01",
    note="Added to the key after each byte, wrapping at 256.",
)

_TRANSFORM_PARAMETERS: Final[Mapping[str, tuple[TransformParameter, ...]]] = MappingProxyType({
    "xor_single": (_XOR_SINGLE_KEY,),
    "xor_repeating": (_XOR_REPEATING_KEY,),
    "xor_rolling": (_XOR_SINGLE_KEY, _ROLLING_INCREMENT),
    "rot_n": (_required("shift", _ONE_BYTE, "Alphabet rotation, taken modulo 26; letters only."),),
    "aes_ecb_encrypt": (_AES_KEY, _AES_PADDING),
    "aes_ecb_decrypt": (_AES_KEY, _AES_PADDING),
    "base64_encode": _NO_PARAMETERS,
    "base64_decode": _NO_PARAMETERS,
    "zlib_inflate": _NO_PARAMETERS,
    "zlib_deflate": _NO_PARAMETERS,
    "bit_shift_left": (_required("count", _ONE_BYTE, _SHIFT_NOTE),),
    "bit_shift_right": (_required("count", _ONE_BYTE, _SHIFT_NOTE),),
    "bit_rotate_left": (_required("count", _ONE_BYTE, _ROTATE_NOTE),),
    "bit_rotate_right": (_required("count", _ONE_BYTE, _ROTATE_NOTE),),
    "bit_invert": _NO_PARAMETERS,
    "byte_reverse": _NO_PARAMETERS,
    "byte_swap_16": _NO_PARAMETERS,
    "byte_swap_32": _NO_PARAMETERS,
    "byte_swap_64": _NO_PARAMETERS,
    "remove_nulls": _NO_PARAMETERS,
    "mask_and": (_MASK_PATTERN,),
    "mask_or": (_MASK_PATTERN,),
    "mask_xor": (_MASK_PATTERN,),
})

_HASH_ALGORITHMS: Final[tuple[str, ...]] = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-256",
    "sha3-512",
    "blake2b",
    "blake2s",
    "xxhash32",
    "xxhash64",
    "xxh3",
    "siphash64",
    "siphash128",
    "adler32",
    "crc8",
    "crc16",
    "crc32",
    "crc64",
    "fnv1-32",
    "fnv1-64",
    "fnv1a-32",
    "fnv1a-64",
)

_CUSTOM_CRC_WIDTHS: Final[tuple[int, ...]] = (8, 16, 32, 64)

_PAGE_PROTECTION_FLAGS: Final[Mapping[int, str]] = MappingProxyType({
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
    0x100: "PAGE_GUARD",
    0x200: "PAGE_NOCACHE",
    0x400: "PAGE_WRITECOMBINE",
})

_MEMORY_STATE_FLAGS: Final[Mapping[int, str]] = MappingProxyType({
    0x1000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x10000: "MEM_FREE",
})

_CLASSIFICATION_CODES: Final[Mapping[int, str]] = MappingProxyType({
    0: "Zero filled",
    1: "Plaintext-like",
    2: "Moderate structure",
    3: "High entropy, above 7.0 bits per byte",
    4: "Mixed entropy, 4.5 to 7.0 bits per byte",
})

_DIFF_TYPES: Final[Mapping[str, str]] = MappingProxyType({
    "match": "Both inputs carry identical bytes across the region.",
    "modified": "Both inputs cover the region but their bytes differ.",
    "inserted_a": "The region is present only in the first input.",
    "inserted_b": "The region is present only in the second input.",
})


def transform_parameters() -> Mapping[str, tuple[TransformParameter, ...]]:
    """Describe the ``params`` mapping every transform accepts.

    Returns:
        Mapping[str, tuple[TransformParameter, ...]]: Read-only mapping from
        transform name to its ordered parameters, covering all twenty-three
        transforms the engine implements.
    """
    return _TRANSFORM_PARAMETERS


def hash_algorithms() -> tuple[str, ...]:
    """List the digest algorithms the hashing operations accept.

    Algorithm names are matched case-insensitively by the engine, and several
    carry additional aliases; the canonical spelling is returned here.

    Returns:
        tuple[str, ...]: Canonical algorithm names.
    """
    return _HASH_ALGORITHMS


def custom_crc_widths() -> tuple[int, ...]:
    """List the register widths ``compute_hash_custom_crc`` accepts.

    Returns:
        tuple[int, ...]: Accepted widths in bits; any other value is rejected.
    """
    return _CUSTOM_CRC_WIDTHS


def page_protection_flags() -> Mapping[int, str]:
    """Name the Win32 page protection bits reported for a memory region.

    A region's protection value combines exactly one access constant with any
    number of the modifier bits, so callers should decompose it rather than look
    the whole value up.

    Returns:
        Mapping[int, str]: Read-only mapping from bit value to constant name.
    """
    return _PAGE_PROTECTION_FLAGS


def memory_state_flags() -> Mapping[int, str]:
    """Name the Win32 memory state constants reported for a memory region.

    Returns:
        Mapping[int, str]: Read-only mapping from constant value to name.
    """
    return _MEMORY_STATE_FLAGS


def classification_codes() -> Mapping[int, str]:
    """Explain the per-block codes ``content_classification`` returns.

    Returns:
        Mapping[int, str]: Read-only mapping from code byte to its meaning.
    """
    return _CLASSIFICATION_CODES


def diff_types() -> Mapping[str, str]:
    """Explain the region kinds the difference operations report.

    Returns:
        Mapping[str, str]: Read-only mapping from ``diff_type`` value to its
        meaning.
    """
    return _DIFF_TYPES


@lru_cache(maxsize=1)
def raw_capable_operations() -> frozenset[str]:
    """List the operations whose result is binary rather than structured data.

    Derived from the catalogue so it cannot drift from the compiled engine.
    Results of these operations must be offered as an undecorated download,
    because the JSON encoding truncates long byte strings and would otherwise
    silently corrupt a patch export or a classification map.

    Returns:
        frozenset[str]: Names of every operation returning ``bytes``.
    """
    return frozenset(operation.name for operation in build_catalog() if operation.returns == _BYTES_RETURN)


def _json_strings(values: Sequence[str]) -> list[JsonValue]:
    """Widen a sequence of strings into a JSON array.

    Args:
        values: Strings to place in the array.

    Returns:
        list[JsonValue]: The same strings as JSON values.
    """
    return list(values)


def _transform_json() -> JsonValue:
    """Render the transform parameter tables as JSON.

    Returns:
        JsonValue: Mapping from transform name to a list of parameter objects.
    """
    rendered: dict[str, JsonValue] = {}
    for name, parameters in _TRANSFORM_PARAMETERS.items():
        rendered[name] = [
            {
                "key": parameter.key,
                "required": parameter.required,
                "byte_widths": list(parameter.byte_widths),
                "choices": list(parameter.choices),
                "default_hex": parameter.default_hex,
                "note": parameter.note,
            }
            for parameter in parameters
        ]
    return rendered


def as_json() -> JsonValue:
    """Render every reference table in one JSON-safe structure.

    Returns:
        JsonValue: Object carrying the transform parameter tables, the hash
        algorithm list, the Win32 memory constants, the classification codes,
        the difference region kinds and the binary-returning operation names.
    """
    rendered: dict[str, JsonValue] = {
        "transforms": _transform_json(),
        "hash_algorithms": list(_HASH_ALGORITHMS),
        "custom_crc_widths": list(_CUSTOM_CRC_WIDTHS),
        "page_protection_flags": {str(value): name for value, name in _PAGE_PROTECTION_FLAGS.items()},
        "memory_state_flags": {str(value): name for value, name in _MEMORY_STATE_FLAGS.items()},
        "classification_codes": {str(code): meaning for code, meaning in _CLASSIFICATION_CODES.items()},
        "diff_types": dict(_DIFF_TYPES),
        "raw_capable_operations": _json_strings(sorted(raw_capable_operations())),
    }
    return rendered
