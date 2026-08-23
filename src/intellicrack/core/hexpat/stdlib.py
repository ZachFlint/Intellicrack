# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Python implementations of builtin:: namespace functions.

The standard library .pat files define public APIs (std::mem, std::string,
etc.) that internally call low-level builtin:: functions. This module provides
those builtin:: implementations backed by DataReader for binary access.
"""

from __future__ import annotations

import math
import os
import random as _random
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NoReturn

from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import BuiltinCallable, PatternValue
from intellicrack.core.hexpat.parse_helpers import safe_call, safe_int_from_str
from intellicrack.core.hexpat.pragma import PragmaInfo
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, BinaryIO

    from intellicrack.core.hexpat.data_reader import DataReader
    from intellicrack.core.hexpat.evaluator import EvalScope


_logger = get_logger(__name__)

_MAX_OPEN_FILES: int = 32
_ENDIAN_NATIVE: int = 0
_ENDIAN_BIG: int = 1
_ENDIAN_LITTLE: int = 2

_FILE_MODE_READ: int = 1
_FILE_MODE_WRITE: int = 2
_FILE_MODE_CREATE: int = 3

_ACCUMULATE_ADD: int = 0
_ACCUMULATE_MULTIPLY: int = 1
_ACCUMULATE_MODULO: int = 2
_ACCUMULATE_MIN: int = 3
_ACCUMULATE_MAX: int = 4

_FORMAT_FIELD_RE: re.Pattern[str] = re.compile(r"\{([^{}]*)\}")


def _create_rng() -> _random.Random:
    """Return a new non-cryptographic PRNG instance used by ``std::random``.

    The hexpat ``std::random`` is documented to use Mersenne Twister and must
    support deterministic seeding via ``set_seed``. This factory isolates the
    instantiation of the generator so that callers receive a ready-to-seed
    instance. The returned object is explicitly not cryptographically secure;
    it exists solely to fulfil the ``std::random`` pattern-language API.

    Returns:
        _random.Random: A freshly constructed pattern-language PRNG.
    """
    rng_cls: type[_random.Random] = vars(_random)["Random"]
    return rng_cls()


class _PrintSinkRegistry:
    """Module-level registry holding the optional ``std::print`` callback."""

    sink: Callable[[str], None] | None = None


@dataclass
class _MemorySection:
    """An in-memory custom section managed by ``std::mem::create_section``.

    Pattern-language code can allocate, resize, and copy bytes into custom
    sections. The interpreter currently keeps these sections in process memory
    for the lifetime of the evaluation; they are not persisted to the host
    binary.

    Attributes:
        name: Human-readable section identifier supplied by the caller.
        data: Mutable byte buffer backing the section.
    """

    name: str
    data: bytearray


def set_print_sink(sink: Callable[[str], None] | None) -> None:
    """Register a callback receiving formatted output from ``std::print``.

    Args:
        sink: A callable accepting a single formatted string, or ``None`` to
            disable routing to an external sink. The callback is invoked in
            addition to the standard structured log entry.
    """
    _PrintSinkRegistry.sink = sink


def _reflect_bits(value: int, width_bits: int) -> int:
    """Reverse the bit order within a fixed-width integer.

    Args:
        value: The integer value whose bits should be reflected.
        width_bits: The width of the bit field to reflect.

    Returns:
        int: The value with its low ``width_bits`` bits reversed.
    """
    result: int = 0
    for bit in range(width_bits):
        if value & (1 << bit):
            result |= 1 << (width_bits - 1 - bit)
    return result


def _crc_compute(
    data: bytes,
    init: int,
    poly: int,
    xorout: int,
    *,
    reflect_in: bool,
    reflect_out: bool,
    width_bits: int,
) -> int:
    """Compute a generic CRC over the given byte string.

    Args:
        data: The input byte string to hash.
        init: The initial CRC register value.
        poly: The CRC generator polynomial in normal form.
        xorout: The value XORed into the final CRC register before return.
        reflect_in: Whether input bytes should be bit-reflected.
        reflect_out: Whether the final CRC register should be bit-reflected.
        width_bits: The CRC width in bits.

    Returns:
        int: The final CRC value masked to ``width_bits``.
    """
    mask: int = (1 << width_bits) - 1
    top_bit: int = 1 << (width_bits - 1)
    crc: int = init & mask
    for byte in data:
        processed: int = _reflect_bits(byte, 8) if reflect_in else byte
        crc ^= processed << (width_bits - 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if crc & top_bit else (crc << 1) & mask
    if reflect_out:
        crc = _reflect_bits(crc, width_bits)
    return (crc ^ xorout) & mask


@dataclass
class _ReflectionProvider:
    """Optional provider dataclass for evaluator-backed reflection metadata.

    The evaluator wires each attribute below to a concrete callable that
    surfaces pattern-node metadata (attributes, members, formatted values,
    palette controls, and user-defined function dispatch) to ``std::core``
    builtins. When any field is ``None`` the corresponding builtin raises
    ``HexPatRuntimeError`` so patterns that reach an un-wired hook fail loud
    rather than silently.

    Attributes:
        has_attribute: Callback answering ``std::core::has_attribute``.
        get_attribute_argument: Callback answering ``std::core::get_attribute_argument``.
        member_count: Callback answering ``std::core::member_count``.
        has_member: Callback answering ``std::core::has_member``.
        formatted_value: Callback answering ``std::core::formatted_value``.
        is_valid_enum: Callback answering ``std::core::is_valid_enum``.
        set_pattern_color: Callback implementing ``std::core::set_pattern_color``.
        set_display_name: Callback implementing ``std::core::set_display_name``.
        set_pattern_comment: Callback implementing ``std::core::set_pattern_comment``.
        set_pattern_palette_colors: Callback implementing ``std::core::set_pattern_palette_colors``.
        reset_pattern_palette: Callback implementing ``std::core::reset_pattern_palette``.
        execute_function: Callback dispatching ``std::core::execute_function``.
    """

    has_attribute: Callable[[PatternValue, str], bool] | None = None
    get_attribute_argument: Callable[[PatternValue, str, int], PatternValue] | None = None
    member_count: Callable[[PatternValue], int] | None = None
    has_member: Callable[[PatternValue, str], bool] | None = None
    formatted_value: Callable[[PatternValue], str] | None = None
    is_valid_enum: Callable[[PatternValue], bool] | None = None
    set_pattern_color: Callable[[PatternValue, int], None] | None = None
    set_display_name: Callable[[PatternValue, str], None] | None = None
    set_pattern_comment: Callable[[PatternValue, str], None] | None = None
    set_pattern_palette_colors: Callable[[list[int]], None] | None = None
    reset_pattern_palette: Callable[[], None] | None = None
    execute_function: Callable[[str, list[PatternValue]], PatternValue] | None = None


class BuiltinFunctions:
    """Implements the builtin:: namespace functions in Python.

    Registered into the evaluator's global scope so that the real
    std/*.pat library files can call them transparently.
    """

    def __init__(
        self,
        data_reader: DataReader,
        pragma: PragmaInfo | None = None,
    ) -> None:
        """Initialize the StdLib with a data reader for binary access.

        Args:
            data_reader: The DataReader wrapping the target binary.
            pragma: Parsed ``#pragma`` directives controlling default endian,
                base address, and other interpreter-wide configuration. When
                ``None``, defaults match the dataclass defaults of
                :class:`PragmaInfo` (little-endian, base address 0).
        """
        self._data: DataReader = data_reader
        self._pragma: PragmaInfo = pragma if pragma is not None else PragmaInfo()
        endian_seed = self._pragma.endian if self._pragma.endian in {"little", "big"} else "little"
        self._endian: str = endian_seed
        self._array_index: int = 0
        self._sections: dict[int, _MemorySection] = {}
        self._next_section_handle: int = 1
        self._file_handles: dict[int, BinaryIO] = {}
        self._file_next_handle: int = 1
        self._rng: _random.Random = _create_rng()
        self._reflection: _ReflectionProvider | None = None
        self._endian_listener: Callable[[str], None] | None = None
        self._array_index_listener: Callable[[], int] | None = None
        _logger.debug(
            "hexpat_builtins_initialized",
            data_size=data_reader.size,
            default_endian=self._endian,
            base_address=self._pragma.base_address,
        )

    @staticmethod
    def _unwrap(arg: object) -> int | float | str:
        """Extract the raw value from a PatternValue argument.

        Args:
            arg: A PatternValue or raw value.

        Returns:
            int | float | str: The unwrapped raw value as a primitive.
        """
        if isinstance(arg, PatternValue):
            val = arg.value
            return val if isinstance(val, (int, float, str)) else 0
        return arg if isinstance(arg, (int, float, str)) else 0

    @staticmethod
    def _unwrap_bytes(arg: object) -> bytes:
        """Extract a bytes payload from a PatternValue or primitive argument.

        Args:
            arg: A PatternValue carrying bytes/str, or a primitive value.

        Returns:
            bytes: The raw byte content. Strings are encoded as UTF-8.
        """
        if isinstance(arg, PatternValue):
            val = arg.value
            if isinstance(val, bytes):
                return val
            return val.encode("utf-8") if isinstance(val, str) else b""
        if isinstance(arg, bytes):
            return arg
        return arg.encode("utf-8") if isinstance(arg, str) else b""

    def set_array_index(self, index: int) -> None:
        """Set the current array iteration index.

        Args:
            index: The current array element index.
        """
        self._array_index = index

    def set_array_index_provider(self, provider: Callable[[], int] | None) -> None:
        """Register a callback that returns the active array iteration index.

        The HexPat evaluator owns the active array index across nested
        ``placement[idx]`` traversals. Wiring this provider lets
        ``std::core::array_index()`` reflect the live evaluator state instead
        of the last value pushed via :meth:`set_array_index`.

        Args:
            provider: Zero-argument callable returning the current index, or
                ``None`` to clear the wiring and fall back to the value most
                recently passed to :meth:`set_array_index`.
        """
        self._array_index_listener = provider

    def set_endian_listener(self, listener: Callable[[str], None] | None) -> None:
        """Register a callback receiving endian transitions from ``std::core::set_endian``.

        Args:
            listener: A callable receiving the resolved endian string
                (``"little"`` or ``"big"``) whenever a pattern calls
                ``std::core::set_endian``, or ``None`` to clear the wiring.
        """
        self._endian_listener = listener

    @property
    def endian(self) -> str:
        """The active default endian, kept in sync with ``set_endian``.

        Returns:
            str: ``"little"`` or ``"big"`` reflecting the current default.
        """
        return self._endian

    def set_reflection_provider(self, provider: object | None) -> None:
        """Register an evaluator-backed reflection provider.

        The provider is duck-typed against :class:`_ReflectionProvider`: any
        object exposing the documented optional callable attributes is
        accepted. The evaluator supplies a concrete provider via
        :meth:`HexPatEvaluator.reflection_provider`.

        Args:
            provider: An object implementing the reflection protocol, or
                ``None`` to remove any previously installed provider.
        """
        if provider is None:
            self._reflection = None
            return
        if isinstance(provider, _ReflectionProvider):
            self._reflection = provider
            return
        adapted = _ReflectionProvider(
            has_attribute=getattr(provider, "has_attribute", None),
            get_attribute_argument=getattr(provider, "get_attribute_argument", None),
            member_count=getattr(provider, "member_count", None),
            has_member=getattr(provider, "has_member", None),
            formatted_value=getattr(provider, "formatted_value", None),
            is_valid_enum=getattr(provider, "is_valid_enum", None),
            set_pattern_color=getattr(provider, "set_pattern_color", None),
            set_display_name=getattr(provider, "set_display_name", None),
            set_pattern_comment=getattr(provider, "set_pattern_comment", None),
            set_pattern_palette_colors=getattr(provider, "set_pattern_palette_colors", None),
            reset_pattern_palette=getattr(provider, "reset_pattern_palette", None),
            execute_function=getattr(provider, "execute_function", None),
        )
        self._reflection = adapted

    def _resolve_endian(self, tag: int) -> Literal["little", "big"]:
        """Resolve a hexpat endian tag to a byteorder string.

        ``Native`` falls back to the active default endian, which the
        interpreter seeds from ``#pragma endian`` and which
        ``std::core::set_endian`` may subsequently overwrite.

        Args:
            tag: The hexpat endian enum value (0=Native, 1=Big, 2=Little).

        Returns:
            Literal["little", "big"]: The byteorder suitable for ``int.from_bytes``.
        """
        if tag == _ENDIAN_BIG:
            return "big"
        if tag == _ENDIAN_LITTLE:
            return "little"
        return "big" if self._endian == "big" else "little"

    def register_all(self, scope: EvalScope) -> None:
        """Register all builtin functions into the given scope.

        Args:
            scope: The evaluator scope to register functions in.
        """
        builtins: dict[str, Any] = {
            "builtin::std::mem::read_unsigned": self._mem_read_unsigned,
            "builtin::std::mem::read_signed": self._mem_read_signed,
            "builtin::std::mem::read_string": self._mem_read_string,
            "builtin::std::mem::read_bits": self._mem_read_bits,
            "builtin::std::mem::find_sequence_in_range": self._mem_find_sequence,
            "builtin::std::mem::find_string_in_range": self._mem_find_string_in_range,
            "builtin::std::mem::size": self._mem_size,
            "builtin::std::mem::base_address": self._mem_base_address,
            "builtin::std::mem::current_bit_offset": self._mem_current_bit_offset,
            "builtin::std::mem::create_section": self._mem_create_section,
            "builtin::std::mem::delete_section": self._mem_delete_section,
            "builtin::std::mem::get_section_size": self._mem_get_section_size,
            "builtin::std::mem::set_section_size": self._mem_set_section_size,
            "builtin::std::mem::copy_to_section": self._mem_copy_to_section,
            "builtin::std::mem::copy_value_to_section": self._mem_copy_value_to_section,
            "builtin::std::mem::read_struct_field": self._read_struct_field,
            "std::mem::read_unsigned": self._mem_read_unsigned,
            "std::mem::read_signed": self._mem_read_signed,
            "std::mem::read_string": self._mem_read_string,
            "std::mem::read_bits": self._mem_read_bits,
            "std::mem::find_sequence_in_range": self._mem_find_sequence,
            "std::mem::find_string_in_range": self._mem_find_string_in_range,
            "std::mem::size": self._mem_size,
            "std::mem::base_address": self._mem_base_address,
            "std::mem::current_bit_offset": self._mem_current_bit_offset,
            "std::mem::create_section": self._mem_create_section,
            "std::mem::delete_section": self._mem_delete_section,
            "std::mem::get_section_size": self._mem_get_section_size,
            "std::mem::set_section_size": self._mem_set_section_size,
            "std::mem::copy_to_section": self._mem_copy_to_section,
            "std::mem::copy_value_to_section": self._mem_copy_value_to_section,
            "std::mem::read_struct_field": self._read_struct_field,
            "builtin::std::string::length": self._string_length,
            "builtin::std::string::at": self._string_at,
            "builtin::std::string::substr": self._string_substr,
            "builtin::std::string::contains": self._string_contains,
            "builtin::std::string::starts_with": self._string_starts_with,
            "builtin::std::string::ends_with": self._string_ends_with,
            "builtin::std::string::parse_int": self._string_parse_int,
            "builtin::std::string::to_int": self._string_to_int,
            "builtin::std::string::parse_float": self._string_parse_float,
            "builtin::std::string::reverse": self._string_reverse,
            "std::string::length": self._string_length,
            "std::string::at": self._string_at,
            "std::string::substr": self._string_substr,
            "std::string::contains": self._string_contains,
            "std::string::starts_with": self._string_starts_with,
            "std::string::ends_with": self._string_ends_with,
            "std::string::parse_int": self._string_parse_int,
            "std::string::to_int": self._string_to_int,
            "std::string::parse_float": self._string_parse_float,
            "std::string::reverse": self._string_reverse,
            "builtin::std::math::abs": self._math_abs,
            "builtin::std::math::min": self._math_min,
            "builtin::std::math::max": self._math_max,
            "builtin::std::math::floor": self._math_floor,
            "builtin::std::math::ceil": self._math_ceil,
            "builtin::std::math::round": self._math_round,
            "builtin::std::math::trunc": self._math_trunc,
            "builtin::std::math::log": self._math_log,
            "builtin::std::math::ln": self._math_log,
            "builtin::std::math::log2": self._math_log2,
            "builtin::std::math::log10": self._math_log10,
            "builtin::std::math::pow": self._math_pow,
            "builtin::std::math::sqrt": self._math_sqrt,
            "builtin::std::math::cbrt": self._math_cbrt,
            "builtin::std::math::exp": self._math_exp,
            "builtin::std::math::fmod": self._math_fmod,
            "builtin::std::math::sin": self._math_sin,
            "builtin::std::math::cos": self._math_cos,
            "builtin::std::math::tan": self._math_tan,
            "builtin::std::math::asin": self._math_asin,
            "builtin::std::math::acos": self._math_acos,
            "builtin::std::math::atan": self._math_atan,
            "builtin::std::math::atan2": self._math_atan2,
            "builtin::std::math::sinh": self._math_sinh,
            "builtin::std::math::cosh": self._math_cosh,
            "builtin::std::math::tanh": self._math_tanh,
            "builtin::std::math::asinh": self._math_asinh,
            "builtin::std::math::acosh": self._math_acosh,
            "builtin::std::math::atanh": self._math_atanh,
            "builtin::std::math::accumulate": self._math_accumulate,
            "std::math::abs": self._math_abs,
            "std::math::min": self._math_min,
            "std::math::max": self._math_max,
            "std::math::floor": self._math_floor,
            "std::math::ceil": self._math_ceil,
            "std::math::round": self._math_round,
            "std::math::trunc": self._math_trunc,
            "std::math::log": self._math_log,
            "std::math::ln": self._math_log,
            "std::math::log2": self._math_log2,
            "std::math::log10": self._math_log10,
            "std::math::pow": self._math_pow,
            "std::math::sqrt": self._math_sqrt,
            "std::math::cbrt": self._math_cbrt,
            "std::math::exp": self._math_exp,
            "std::math::fmod": self._math_fmod,
            "std::math::sin": self._math_sin,
            "std::math::cos": self._math_cos,
            "std::math::tan": self._math_tan,
            "std::math::asin": self._math_asin,
            "std::math::acos": self._math_acos,
            "std::math::atan": self._math_atan,
            "std::math::atan2": self._math_atan2,
            "std::math::sinh": self._math_sinh,
            "std::math::cosh": self._math_cosh,
            "std::math::tanh": self._math_tanh,
            "std::math::asinh": self._math_asinh,
            "std::math::acosh": self._math_acosh,
            "std::math::atanh": self._math_atanh,
            "std::math::accumulate": self._math_accumulate,
            "builtin::std::hash::crc8": self._hash_crc8,
            "builtin::std::hash::crc16": self._hash_crc16,
            "builtin::std::hash::crc32": self._hash_crc32,
            "builtin::std::hash::crc64": self._hash_crc64,
            "std::hash::crc8": self._hash_crc8,
            "std::hash::crc16": self._hash_crc16,
            "std::hash::crc32": self._hash_crc32,
            "std::hash::crc64": self._hash_crc64,
            "builtin::std::time::epoch": self._time_epoch,
            "builtin::std::time::to_local": self._time_to_local,
            "builtin::std::time::to_utc": self._time_to_utc,
            "builtin::std::time::format": self._time_format,
            "std::time::epoch": self._time_epoch,
            "std::time::to_local": self._time_to_local,
            "std::time::to_utc": self._time_to_utc,
            "std::time::format": self._time_format,
            "builtin::std::file::open": self._file_open,
            "builtin::std::file::close": self._file_close,
            "builtin::std::file::read": self._file_read,
            "builtin::std::file::write": self._file_write,
            "builtin::std::file::seek": self._file_seek,
            "builtin::std::file::size": self._file_size,
            "builtin::std::file::resize": self._file_resize,
            "builtin::std::file::flush": self._file_flush,
            "builtin::std::file::remove": self._file_remove,
            "builtin::std::file::create_directories": self._file_create_directories,
            "std::file::open": self._file_open,
            "std::file::close": self._file_close,
            "std::file::read": self._file_read,
            "std::file::write": self._file_write,
            "std::file::seek": self._file_seek,
            "std::file::size": self._file_size,
            "std::file::resize": self._file_resize,
            "std::file::flush": self._file_flush,
            "std::file::remove": self._file_remove,
            "std::file::create_directories": self._file_create_directories,
            "builtin::std::random::set_seed": self._random_set_seed,
            "builtin::std::random::generate": self._random_generate,
            "std::random::set_seed": self._random_set_seed,
            "std::random::generate": self._random_generate,
            "builtin::std::env": self._env_get,
            "builtin::std::sizeof_pack": self._sizeof_pack,
            "std::env": self._env_get,
            "std::sizeof_pack": self._sizeof_pack,
            "builtin::std::core::set_endian": self._core_set_endian,
            "builtin::std::core::get_endian": self._core_get_endian,
            "builtin::std::core::array_index": self._core_array_index,
            "builtin::std::core::has_attribute": self._core_has_attribute,
            "builtin::std::core::get_attribute_argument": self._core_get_attribute_argument,
            "builtin::std::core::member_count": self._core_member_count,
            "builtin::std::core::has_member": self._core_has_member,
            "builtin::std::core::formatted_value": self._core_formatted_value,
            "builtin::std::core::is_valid_enum": self._core_is_valid_enum,
            "builtin::std::core::set_pattern_color": self._core_set_pattern_color,
            "builtin::std::core::set_display_name": self._core_set_display_name,
            "builtin::std::core::set_pattern_comment": self._core_set_pattern_comment,
            "builtin::std::core::set_pattern_palette_colors": self._core_set_pattern_palette_colors,
            "builtin::std::core::reset_pattern_palette": self._core_reset_pattern_palette,
            "builtin::std::core::execute_function": self._core_execute_function,
            "std::core::set_endian": self._core_set_endian,
            "std::core::get_endian": self._core_get_endian,
            "std::core::array_index": self._core_array_index,
            "std::core::has_attribute": self._core_has_attribute,
            "std::core::get_attribute_argument": self._core_get_attribute_argument,
            "std::core::member_count": self._core_member_count,
            "std::core::has_member": self._core_has_member,
            "std::core::formatted_value": self._core_formatted_value,
            "std::core::is_valid_enum": self._core_is_valid_enum,
            "std::core::set_pattern_color": self._core_set_pattern_color,
            "std::core::set_display_name": self._core_set_display_name,
            "std::core::set_pattern_comment": self._core_set_pattern_comment,
            "std::core::set_pattern_palette_colors": self._core_set_pattern_palette_colors,
            "std::core::reset_pattern_palette": self._core_reset_pattern_palette,
            "std::core::execute_function": self._core_execute_function,
            "builtin::std::io::print": self._io_print,
            "builtin::std::io::format": self._io_format,
            "builtin::std::print": self._io_print,
            "builtin::std::format": self._io_format,
            "builtin::std::error": self._io_error,
            "builtin::std::warning": self._io_warning,
            "std::print": self._io_print,
            "std::format": self._io_format,
            "std::error": self._io_error,
            "std::warning": self._io_warning,
            "print": self._io_print,
            "format": self._io_format,
            "error": self._io_error,
            "warning": self._io_warning,
        }

        for name, func in builtins.items():
            scope.define(name, PatternValue(value=BuiltinCallable(fn=func, name=name)))

    def _mem_read_unsigned(self, *args: object) -> int:
        """Read an unsigned integer from binary data.

        Args:
            *args: ``(offset: int, size: int, endian: int = 0)`` where ``size``
                is the byte count (1, 2, 4, 8, 16) and ``endian`` is the hexpat
                endian tag (0=Native, 1=Big, 2=Little).

        Returns:
            int: The unsigned integer value.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        size = int(self._unwrap(args[1])) if len(args) > 1 else 1
        endian_tag = int(self._unwrap(args[2])) if len(args) > 2 else _ENDIAN_NATIVE
        raw = self._data.read(offset, size)
        byteorder = self._resolve_endian(endian_tag)
        return int.from_bytes(raw, byteorder=byteorder, signed=False)

    def _mem_read_signed(self, *args: object) -> int:
        """Read a signed integer from binary data.

        Args:
            *args: ``(offset: int, size: int, endian: int = 0)`` where ``size``
                is the byte count and ``endian`` is the hexpat endian tag
                (0=Native, 1=Big, 2=Little).

        Returns:
            int: The signed integer value.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        size = int(self._unwrap(args[1])) if len(args) > 1 else 1
        endian_tag = int(self._unwrap(args[2])) if len(args) > 2 else _ENDIAN_NATIVE
        raw = self._data.read(offset, size)
        byteorder = self._resolve_endian(endian_tag)
        return int.from_bytes(raw, byteorder=byteorder, signed=True)

    def _mem_read_string(self, *args: object) -> str:
        """Read a string from binary data.

        Args:
            *args: ``(offset: int, length: int)``.

        Returns:
            str: The decoded string.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        length = int(self._unwrap(args[1])) if len(args) > 1 else 256
        raw = self._data.read(offset, length)
        null_idx = raw.find(b"\x00")
        if null_idx >= 0:
            raw = raw[:null_idx]
        return raw.decode("utf-8", errors="replace")

    def _mem_find_sequence(self, *args: object) -> int:
        """Find a byte sequence in a range of binary data.

        Args:
            *args: ``(occurrence_index: int, offsetFrom: int, offsetTo: int,
                pattern_bytes...)``. The Nth occurrence (zero-indexed) whose
                full span fits in ``[offsetFrom, offsetTo)`` is returned.

        Returns:
            int: The absolute byte offset of the selected occurrence, or ``-1``
                when fewer than ``occurrence_index + 1`` matches exist.
        """
        if len(args) < 4:
            return -1
        occurrence_index = int(self._unwrap(args[0]))
        offset_from = int(self._unwrap(args[1]))
        offset_to = int(self._unwrap(args[2]))
        pattern_args = [self._unwrap(a) for a in args[3:]]
        pattern = bytes(int(b) & 0xFF for b in pattern_args)
        if not pattern or occurrence_index < 0:
            return -1
        pos = offset_from
        found_count = 0
        while True:
            result = self._data.find_sequence(pattern, pos)
            if result < 0:
                return -1
            if result + len(pattern) > offset_to:
                return -1
            if found_count == occurrence_index:
                return result
            found_count += 1
            pos = result + 1

    def _mem_size(self, *_args: object) -> int:
        """Get the total size of the binary data.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            int: The data size in bytes.
        """
        return self._data.size

    def _mem_base_address(self, *_args: object) -> int:
        """Get the base address as configured by ``#pragma base_address``.

        The result is the integer base address recorded in the active
        :class:`PragmaInfo`. Patterns combine this with ``$`` and computed
        offsets to map between file offsets and absolute addresses.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            int: The base address.
        """
        return int(self._pragma.base_address)

    def _mem_read_bits(self, *args: object) -> int:
        """Read an arbitrary-width unsigned bitfield from the binary.

        Bits are extracted starting at ``bit_offset`` within the byte at
        ``byte_offset``, advancing toward higher byte addresses. The returned
        value packs the requested bits into an unsigned integer with the
        first-read bit in the most-significant position.

        Args:
            *args: ``(byte_offset: int, bit_offset: int, bit_size: int)``.

        Returns:
            int: The unsigned integer composed from the requested bit range.

        Raises:
            HexPatRuntimeError: When the requested bit-size is non-positive,
                unrealistically large, or the read would walk off the data.
        """
        if len(args) < 3:
            msg = "std::mem::read_bits requires (byte_offset, bit_offset, bit_size)"
            raise HexPatRuntimeError(msg)
        byte_offset = int(self._unwrap(args[0]))
        bit_offset = int(self._unwrap(args[1]))
        bit_size = int(self._unwrap(args[2]))
        if bit_size <= 0:
            msg = "std::mem::read_bits: bit_size must be positive"
            raise HexPatRuntimeError(msg)
        if bit_size > 128:
            msg = "std::mem::read_bits: bit_size must not exceed 128"
            raise HexPatRuntimeError(msg)
        if bit_offset < 0 or bit_offset > 7:
            msg = "std::mem::read_bits: bit_offset must be in [0, 7]"
            raise HexPatRuntimeError(msg)
        bits_total = bit_offset + bit_size
        bytes_needed = (bits_total + 7) // 8
        raw = self._data.read(byte_offset, bytes_needed)
        if len(raw) < bytes_needed:
            msg = f"std::mem::read_bits: short read at byte 0x{byte_offset:X} (needed {bytes_needed} bytes, got {len(raw)})"
            raise HexPatRuntimeError(msg)
        big_value = int.from_bytes(raw, byteorder="big", signed=False)
        shift = (bytes_needed * 8) - bit_offset - bit_size
        mask = (1 << bit_size) - 1
        return (big_value >> shift) & mask

    def _mem_find_string_in_range(self, *args: object) -> int:
        """Locate the Nth occurrence of ``needle`` in a byte range.

        Args:
            *args: ``(occurrence_index: int, offsetFrom: int, offsetTo: int,
                needle: str | bytes)``. The needle is encoded as UTF-8 when
                supplied as a string.

        Returns:
            int: The absolute byte offset of the matching occurrence, or ``-1``
                when fewer matches exist.
        """
        if len(args) < 4:
            return -1
        occurrence_index = int(self._unwrap(args[0]))
        offset_from = int(self._unwrap(args[1]))
        offset_to = int(self._unwrap(args[2]))
        needle = self._unwrap_bytes(args[3])
        if not needle or occurrence_index < 0:
            return -1
        pos = offset_from
        found_count = 0
        while True:
            result = self._data.find_sequence(needle, pos)
            if result < 0:
                return -1
            if result + len(needle) > offset_to:
                return -1
            if found_count == occurrence_index:
                return result
            found_count += 1
            pos = result + 1

    def _mem_current_bit_offset(self, *_args: object) -> int:
        """Return the current bit offset within an active bitfield read.

        Bit-level reflection is provided by the evaluator's reflection
        provider when one is wired. For tree-walking evaluations not nested
        inside a bitfield read the offset is always ``0``.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            int: The bit offset (``0``-``7``).
        """
        if self._reflection is not None:
            hook = getattr(self._reflection, "current_bit_offset", None)
            if callable(hook):
                hook_result = hook()
                return hook_result if isinstance(hook_result, int) else 0
        return 0

    def _mem_create_section(self, *args: object) -> PatternValue:
        """Allocate a fresh in-memory section and return its handle.

        Args:
            *args: ``(name: str)``.

        Returns:
            PatternValue: A PatternValue carrying the section handle.
        """
        name = str(self._unwrap(args[0])) if args else ""
        handle = self._next_section_handle
        self._next_section_handle += 1
        self._sections[handle] = _MemorySection(name=name, data=bytearray())
        return PatternValue(value=handle)

    def _mem_delete_section(self, *args: object) -> PatternValue:
        """Release the storage backing a previously created section.

        Args:
            *args: ``(section: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the supplied handle is unknown.
        """
        if not args:
            msg = "std::mem::delete_section requires a section handle"
            raise HexPatRuntimeError(msg)
        handle = int(self._unwrap(args[0]))
        if self._sections.pop(handle, None) is None:
            msg = f"std::mem::delete_section: unknown section handle {handle}"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=None)

    def _mem_get_section_size(self, *args: object) -> PatternValue:
        """Return the byte size of a custom section.

        Args:
            *args: ``(section: int)``.

        Returns:
            PatternValue: A PatternValue carrying the section size.

        Raises:
            HexPatRuntimeError: When the supplied handle is unknown.
        """
        section = self._section_for(args[0]) if args else None
        if section is None:
            msg = "std::mem::get_section_size: unknown section handle"
            _logger.warning("mem_get_section_size_unknown_handle")
            raise HexPatRuntimeError(msg)
        return PatternValue(value=len(section.data))

    def _mem_set_section_size(self, *args: object) -> PatternValue:
        """Resize a custom section, zero-extending or truncating its bytes.

        Args:
            *args: ``(section: int, size: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the supplied handle is unknown or the
                requested size is negative.
        """
        if len(args) < 2:
            msg = "std::mem::set_section_size requires (section, size)"
            raise HexPatRuntimeError(msg)
        section = self._section_for(args[0])
        if section is None:
            msg = "std::mem::set_section_size: unknown section handle"
            raise HexPatRuntimeError(msg)
        new_size = int(self._unwrap(args[1]))
        if new_size < 0:
            msg = "std::mem::set_section_size: size must be non-negative"
            raise HexPatRuntimeError(msg)
        current = len(section.data)
        if new_size > current:
            section.data.extend(b"\x00" * (new_size - current))
        else:
            del section.data[new_size:]
        return PatternValue(value=None)

    def _mem_copy_to_section(self, *args: object) -> PatternValue:
        """Copy bytes from the main binary or another section into a section.

        Args:
            *args: ``(from_section: int, from_address: int, to_section: int,
                to_address: int, size: int)``. ``from_section`` of ``0`` reads
                from the main binary; non-zero handles read from the matching
                custom section.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When either section handle is unknown or the
                source range is out of bounds.
        """
        if len(args) < 5:
            msg = "std::mem::copy_to_section requires (from_section, from_address, to_section, to_address, size)"
            raise HexPatRuntimeError(msg)
        from_handle = int(self._unwrap(args[0]))
        from_address = int(self._unwrap(args[1]))
        to_handle = int(self._unwrap(args[2]))
        to_address = int(self._unwrap(args[3]))
        size = int(self._unwrap(args[4]))
        if size < 0:
            msg = "std::mem::copy_to_section: size must be non-negative"
            raise HexPatRuntimeError(msg)
        if from_handle == 0:
            payload = self._data.read(from_address, size)
        else:
            src = self._sections.get(from_handle)
            if src is None:
                msg = f"std::mem::copy_to_section: unknown source section {from_handle}"
                raise HexPatRuntimeError(msg)
            if from_address < 0 or from_address + size > len(src.data):
                msg = "std::mem::copy_to_section: source range out of bounds"
                raise HexPatRuntimeError(msg)
            payload = bytes(src.data[from_address : from_address + size])
        self._write_section(to_handle, to_address, payload, "copy_to_section")
        return PatternValue(value=None)

    def _mem_copy_value_to_section(self, *args: object) -> PatternValue:
        """Copy a pattern's raw bytes into a custom section.

        Args:
            *args: ``(value, to_section: int, to_address: int)`` where
                ``value`` is a :class:`PatternValue` referencing a region of
                the main binary.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the destination section is unknown or
                the source value lacks a binary footprint.
        """
        if len(args) < 3:
            msg = "std::mem::copy_value_to_section requires (value, to_section, to_address)"
            raise HexPatRuntimeError(msg)
        value_arg = args[0]
        to_handle = int(self._unwrap(args[1]))
        to_address = int(self._unwrap(args[2]))
        if not isinstance(value_arg, PatternValue) or value_arg.size <= 0:
            msg = "std::mem::copy_value_to_section: value has no binary footprint"
            raise HexPatRuntimeError(msg)
        payload = self._data.read(value_arg.offset, value_arg.size)
        self._write_section(to_handle, to_address, payload, "copy_value_to_section")
        return PatternValue(value=None)

    def _write_section(
        self,
        handle: int,
        address: int,
        payload: bytes,
        op: str,
    ) -> None:
        """Write ``payload`` into a section, zero-extending when needed.

        Args:
            handle: Destination section handle.
            address: Byte offset within the destination section.
            payload: Bytes to splice into the destination.
            op: Builtin name embedded in error messages for diagnostics.

        Raises:
            HexPatRuntimeError: When the destination handle is unknown.
        """
        dst = self._sections.get(handle)
        if dst is None:
            msg = f"std::mem::{op}: unknown destination section {handle}"
            raise HexPatRuntimeError(msg)
        end = address + len(payload)
        if end > len(dst.data):
            dst.data.extend(b"\x00" * (end - len(dst.data)))
        dst.data[address:end] = payload

    def _section_for(self, arg: object) -> _MemorySection | None:
        """Resolve a section-handle argument to its backing storage.

        Args:
            arg: A pattern-value or primitive carrying the section handle.

        Returns:
            _MemorySection | None: The backing section, or ``None`` when the
            handle is unknown.
        """
        handle = int(self._unwrap(arg))
        return self._sections.get(handle)

    def _string_length(self, *args: object) -> int:
        """Get the length of a string.

        Args:
            *args: ``(s: str)``.

        Returns:
            int: The string length.
        """
        return len(str(self._unwrap(args[0]))) if args else 0

    def _string_at(self, *args: object) -> str:
        """Get a character at an index.

        Args:
            *args: ``(s: str, index: int)``.

        Returns:
            str: The character at the given index, or an empty string when the
                index is out of bounds.
        """
        if len(args) < 2:
            return ""
        s = str(self._unwrap(args[0]))
        idx = int(self._unwrap(args[1]))
        return s[idx] if 0 <= idx < len(s) else ""

    def _string_substr(self, *args: object) -> str:
        """Extract a substring.

        Args:
            *args: ``(s: str, start: int, length: int)``.

        Returns:
            str: The extracted substring.
        """
        if len(args) < 3:
            return ""
        s = str(self._unwrap(args[0]))
        start = int(self._unwrap(args[1]))
        length = int(self._unwrap(args[2]))
        return s[start : start + length]

    def _string_contains(self, *args: object) -> bool:
        """Check if a string contains a substring.

        Args:
            *args: ``(s: str, sub: str)``.

        Returns:
            bool: True if the substring is found.
        """
        if len(args) < 2:
            return False
        return str(self._unwrap(args[1])) in str(self._unwrap(args[0]))

    def _string_starts_with(self, *args: object) -> bool:
        """Check if a string starts with a prefix.

        Args:
            *args: ``(s: str, prefix: str)``.

        Returns:
            bool: True if the string starts with the prefix.
        """
        if len(args) < 2:
            return False
        return str(self._unwrap(args[0])).startswith(str(self._unwrap(args[1])))

    def _string_ends_with(self, *args: object) -> bool:
        """Check if a string ends with a suffix.

        Args:
            *args: ``(s: str, suffix: str)``.

        Returns:
            bool: True if the string ends with the suffix.
        """
        if len(args) < 2:
            return False
        return str(self._unwrap(args[0])).endswith(str(self._unwrap(args[1])))

    def _string_parse_int(self, *args: object) -> int:
        """Parse a string as an integer, raising on malformed input.

        Args:
            *args: ``(s: str, base: int)``.

        Returns:
            int: The parsed integer value.

        Raises:
            HexPatRuntimeError: When the input cannot be parsed in the
                requested base or the base is outside the supported range.
        """
        if not args:
            msg = "std::string::parse_int requires a string argument"
            raise HexPatRuntimeError(msg)
        s = str(self._unwrap(args[0])).strip()
        base = int(self._unwrap(args[1])) if len(args) > 1 else 10
        if base != 0 and (base < 2 or base > 36):
            msg = f"std::string::parse_int: unsupported base {base}"
            raise HexPatRuntimeError(msg)
        try:
            result = int(s, base)
        except ValueError as exc:
            _logger.exception("hexpat_string_parse_int_failed", input=s, base=base)
            msg = f"std::string::parse_int: cannot parse {s!r} as base-{base} integer"
            raise HexPatRuntimeError(msg) from exc
        return result

    def _string_to_int(self, *args: object) -> int:
        """Convert a string to an integer, returning 0 on malformed input.

        Unlike :meth:`_string_parse_int`, which raises on bad input, this
        lenient variant mirrors C-style ``strtol`` semantics and yields ``0``
        when the string cannot be interpreted in the requested base.

        Args:
            *args: ``(s: str, base: int)``. ``base`` defaults to 10 and accepts
                0 (auto-detect) or any radix in ``[2, 36]``.

        Returns:
            int: The parsed integer value, or ``0`` when the input is invalid.
        """
        if not args:
            return 0
        s = str(self._unwrap(args[0])).strip()
        base = int(self._unwrap(args[1])) if len(args) > 1 else 10
        if base != 0 and (base < 2 or base > 36):
            return 0
        try:
            return int(s, base)
        except ValueError:
            return 0

    def _string_parse_float(self, *args: object) -> float:
        """Parse a string as a floating-point value.

        Args:
            *args: ``(s: str)``.

        Returns:
            float: The parsed float value.

        Raises:
            HexPatRuntimeError: When the input cannot be parsed as a float.
        """
        if not args:
            msg = "std::string::parse_float requires a string argument"
            raise HexPatRuntimeError(msg)
        s = str(self._unwrap(args[0])).strip()
        try:
            result = float(s)
        except ValueError as exc:
            _logger.exception("hexpat_string_parse_float_failed", input=s)
            msg = f"std::string::parse_float: cannot parse {s!r} as float"
            raise HexPatRuntimeError(msg) from exc
        return result

    def _string_reverse(self, *args: object) -> str:
        """Reverse a string.

        Args:
            *args: ``(s: str)``.

        Returns:
            str: The reversed string.
        """
        return str(self._unwrap(args[0]))[::-1] if args else ""

    def _math_abs(self, *args: object) -> int | float:
        """Compute the absolute value.

        Args:
            *args: ``(x: int | float)``.

        Returns:
            int | float: The absolute value.
        """
        if not args:
            return 0
        val = self._unwrap(args[0])
        return abs(val) if isinstance(val, float) else abs(int(val))

    def _math_min(self, *args: object) -> int | float:
        """Return the minimum of two values.

        Args:
            *args: ``(a: int | float, b: int | float)``.

        Returns:
            int | float: The smaller value.
        """
        if len(args) < 2:
            return int(self._unwrap(args[0])) if args else 0
        a, b = self._unwrap(args[0]), self._unwrap(args[1])
        if isinstance(a, float) or isinstance(b, float):
            return min(float(a), float(b))
        return min(int(a), int(b))

    def _math_max(self, *args: object) -> int | float:
        """Return the maximum of two values.

        Args:
            *args: ``(a: int | float, b: int | float)``.

        Returns:
            int | float: The larger value.
        """
        if len(args) < 2:
            return int(self._unwrap(args[0])) if args else 0
        a, b = self._unwrap(args[0]), self._unwrap(args[1])
        if isinstance(a, float) or isinstance(b, float):
            return max(float(a), float(b))
        return max(int(a), int(b))

    def _math_floor(self, *args: object) -> int:
        """Compute the floor of a value.

        Args:
            *args: ``(x: float)``.

        Returns:
            int: The floor as an integer.
        """
        return math.floor(float(self._unwrap(args[0]))) if args else 0

    def _math_ceil(self, *args: object) -> int:
        """Compute the ceiling of a value.

        Args:
            *args: ``(x: float)``.

        Returns:
            int: The ceiling as an integer.
        """
        return math.ceil(float(self._unwrap(args[0]))) if args else 0

    def _math_round(self, *args: object) -> int:
        """Round a value to the nearest integer using banker's rounding.

        Args:
            *args: ``(x: float)``.

        Returns:
            int: The rounded integer value.
        """
        return round(float(self._unwrap(args[0]))) if args else 0

    def _math_trunc(self, *args: object) -> int:
        """Truncate a value toward zero.

        Args:
            *args: ``(x: float)``.

        Returns:
            int: The truncated integer value.
        """
        return math.trunc(float(self._unwrap(args[0]))) if args else 0

    def _math_log(self, *args: object) -> float:
        """Compute the natural logarithm.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The natural log of ``x``.

        Raises:
            HexPatRuntimeError: If the value is non-positive.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val <= 0:
            msg = "ln of non-positive value"
            raise HexPatRuntimeError(msg)
        return math.log(val)

    def _math_log2(self, *args: object) -> float:
        """Compute the base-2 logarithm.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The log base 2 value.

        Raises:
            HexPatRuntimeError: If the value is non-positive.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val <= 0:
            msg = "log2 of non-positive value"
            raise HexPatRuntimeError(msg)
        return math.log2(val)

    def _math_log10(self, *args: object) -> float:
        """Compute the base-10 logarithm.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The log base 10 value.

        Raises:
            HexPatRuntimeError: If the value is non-positive.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val <= 0:
            msg = "log10 of non-positive value"
            raise HexPatRuntimeError(msg)
        return math.log10(val)

    def _math_pow(self, *args: object) -> float:
        """Compute a power.

        Args:
            *args: ``(base: float, exp: float)``.

        Returns:
            float: Base raised to the power of exp.
        """
        if len(args) < 2:
            return 0.0
        return math.pow(float(self._unwrap(args[0])), float(self._unwrap(args[1])))

    def _math_sqrt(self, *args: object) -> float:
        """Compute the square root.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The square root.

        Raises:
            HexPatRuntimeError: If the value is negative.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val < 0:
            msg = "sqrt of negative value"
            raise HexPatRuntimeError(msg)
        return math.sqrt(val)

    def _math_cbrt(self, *args: object) -> float:
        """Compute the cube root, preserving the sign of negative inputs.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The cube root.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        return -((-val) ** (1.0 / 3.0)) if val < 0 else val ** (1.0 / 3.0)

    def _math_exp(self, *args: object) -> float:
        """Compute e raised to the given power.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``e ** x``.
        """
        return math.exp(float(self._unwrap(args[0]))) if args else 1.0

    def _math_fmod(self, *args: object) -> float:
        """Compute the floating-point remainder of the division.

        Args:
            *args: ``(x: float, y: float)``.

        Returns:
            float: The value ``fmod(x, y)``.

        Raises:
            HexPatRuntimeError: When fewer than two arguments are supplied or
                the divisor is zero.
        """
        if len(args) < 2:
            msg = "fmod requires two arguments"
            raise HexPatRuntimeError(msg)
        x = float(self._unwrap(args[0]))
        y = float(self._unwrap(args[1]))
        if math.isclose(y, 0.0, abs_tol=0.0):
            msg = "fmod divisor is zero"
            raise HexPatRuntimeError(msg)
        return math.fmod(x, y)

    def _math_sin(self, *args: object) -> float:
        """Compute the sine of the given radians value.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``sin(x)``.
        """
        return math.sin(float(self._unwrap(args[0]))) if args else 0.0

    def _math_cos(self, *args: object) -> float:
        """Compute the cosine of the given radians value.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``cos(x)``.
        """
        return math.cos(float(self._unwrap(args[0]))) if args else 1.0

    def _math_tan(self, *args: object) -> float:
        """Compute the tangent of the given radians value.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``tan(x)``.
        """
        return math.tan(float(self._unwrap(args[0]))) if args else 0.0

    def _math_asin(self, *args: object) -> float:
        """Compute the arc sine in radians.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``asin(x)``.

        Raises:
            HexPatRuntimeError: When ``x`` is outside ``[-1, 1]``.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val < -1.0 or val > 1.0:
            msg = "asin argument out of domain"
            raise HexPatRuntimeError(msg)
        return math.asin(val)

    def _math_acos(self, *args: object) -> float:
        """Compute the arc cosine in radians.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``acos(x)``.

        Raises:
            HexPatRuntimeError: When ``x`` is outside ``[-1, 1]``.
        """
        if not args:
            return math.pi / 2.0
        val = float(self._unwrap(args[0]))
        if val < -1.0 or val > 1.0:
            msg = "acos argument out of domain"
            raise HexPatRuntimeError(msg)
        return math.acos(val)

    def _math_atan(self, *args: object) -> float:
        """Compute the arc tangent in radians.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``atan(x)``.
        """
        return math.atan(float(self._unwrap(args[0]))) if args else 0.0

    def _math_atan2(self, *args: object) -> float:
        """Compute the two-argument arc tangent in radians.

        Args:
            *args: ``(y: float, x: float)``.

        Returns:
            float: The value ``atan2(y, x)``.
        """
        if len(args) < 2:
            return 0.0
        return math.atan2(float(self._unwrap(args[0])), float(self._unwrap(args[1])))

    def _math_sinh(self, *args: object) -> float:
        """Compute the hyperbolic sine.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``sinh(x)``.
        """
        return math.sinh(float(self._unwrap(args[0]))) if args else 0.0

    def _math_cosh(self, *args: object) -> float:
        """Compute the hyperbolic cosine.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``cosh(x)``.
        """
        return math.cosh(float(self._unwrap(args[0]))) if args else 1.0

    def _math_tanh(self, *args: object) -> float:
        """Compute the hyperbolic tangent.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``tanh(x)``.
        """
        return math.tanh(float(self._unwrap(args[0]))) if args else 0.0

    def _math_asinh(self, *args: object) -> float:
        """Compute the inverse hyperbolic sine.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``asinh(x)``.
        """
        return math.asinh(float(self._unwrap(args[0]))) if args else 0.0

    def _math_acosh(self, *args: object) -> float:
        """Compute the inverse hyperbolic cosine.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``acosh(x)``.

        Raises:
            HexPatRuntimeError: When ``x`` is less than 1.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val < 1.0:
            msg = "acosh argument out of domain"
            raise HexPatRuntimeError(msg)
        return math.acosh(val)

    def _math_atanh(self, *args: object) -> float:
        """Compute the inverse hyperbolic tangent.

        Args:
            *args: ``(x: float)``.

        Returns:
            float: The value ``atanh(x)``.

        Raises:
            HexPatRuntimeError: When ``x`` is outside ``(-1, 1)``.
        """
        if not args:
            return 0.0
        val = float(self._unwrap(args[0]))
        if val <= -1.0 or val >= 1.0:
            msg = "atanh argument out of domain"
            raise HexPatRuntimeError(msg)
        return math.atanh(val)

    def _math_accumulate(self, *args: object) -> int:
        """Fold a memory range using a numeric accumulation operation.

        Args:
            *args: ``(offsetFrom: int, offsetTo: int, valueSize: int,
                section: int, operation: int, endian: int)``. The range is read
                in ``valueSize``-byte chunks and combined according to the
                ``operation`` tag (0=Add, 1=Multiply, 2=Modulo, 3=Min, 4=Max).

        Returns:
            int: The folded integer result.

        Raises:
            HexPatRuntimeError: When arguments are missing or invalid.
        """
        if len(args) < 3:
            msg = "std::math::accumulate requires offsetFrom, offsetTo and valueSize"
            raise HexPatRuntimeError(msg)
        offset_from = int(self._unwrap(args[0]))
        offset_to = int(self._unwrap(args[1]))
        value_size = int(self._unwrap(args[2]))
        operation = int(self._unwrap(args[4])) if len(args) > 4 else _ACCUMULATE_ADD
        endian_tag = int(self._unwrap(args[5])) if len(args) > 5 else _ENDIAN_NATIVE
        if value_size <= 0 or value_size > 16:
            msg = "std::math::accumulate valueSize must be between 1 and 16"
            raise HexPatRuntimeError(msg)
        if offset_to <= offset_from:
            return 0
        byteorder = self._resolve_endian(endian_tag)
        pos = offset_from
        accumulator: int | None = None
        while pos + value_size <= offset_to:
            raw = self._data.read(pos, value_size)
            chunk = int.from_bytes(raw, byteorder=byteorder, signed=False)
            if accumulator is None:
                accumulator = chunk
            elif operation == _ACCUMULATE_ADD:
                accumulator += chunk
            elif operation == _ACCUMULATE_MULTIPLY:
                accumulator *= chunk
            elif operation == _ACCUMULATE_MODULO:
                if chunk == 0:
                    msg = "std::math::accumulate encountered a zero divisor"
                    raise HexPatRuntimeError(msg)
                accumulator %= chunk
            elif operation == _ACCUMULATE_MIN:
                accumulator = min(accumulator, chunk)
            elif operation == _ACCUMULATE_MAX:
                accumulator = max(accumulator, chunk)
            else:
                msg = f"std::math::accumulate unknown operation tag: {operation}"
                raise HexPatRuntimeError(msg)
            pos += value_size
        if accumulator is None:
            return 0
        return accumulator

    def _hash_bytes_from_pattern(self, pattern_arg: object) -> bytes:
        """Materialise the byte range associated with a pattern argument.

        Args:
            pattern_arg: A PatternValue produced by the evaluator that carries
                an ``offset`` and ``size`` covering a contiguous byte span.

        Returns:
            bytes: The raw byte content covered by ``pattern_arg``.
        """
        if isinstance(pattern_arg, PatternValue):
            if pattern_arg.size > 0:
                return self._data.read(pattern_arg.offset, pattern_arg.size)
            val = pattern_arg.value
            if isinstance(val, bytes):
                return val
            if isinstance(val, str):
                return val.encode("utf-8")
            if isinstance(val, int):
                length = max(1, (val.bit_length() + 7) // 8)
                return val.to_bytes(length, byteorder="big", signed=False)
        return self._unwrap_bytes(pattern_arg)

    def _hash_crc8(self, *args: object) -> PatternValue:
        """Compute a CRC-8 hash over a pattern's bytes.

        Args:
            *args: ``(pattern, init, poly, xorout, reflect_in, reflect_out)``.

        Returns:
            PatternValue: A PatternValue containing the 8-bit CRC value.
        """
        if len(args) < 6:
            return PatternValue(value=0)
        data = self._hash_bytes_from_pattern(args[0])
        init = int(self._unwrap(args[1]))
        poly = int(self._unwrap(args[2]))
        xorout = int(self._unwrap(args[3]))
        reflect_in = bool(self._unwrap(args[4]))
        reflect_out = bool(self._unwrap(args[5]))
        return PatternValue(
            value=_crc_compute(
                data,
                init,
                poly,
                xorout,
                reflect_in=reflect_in,
                reflect_out=reflect_out,
                width_bits=8,
            ),
        )

    def _hash_crc16(self, *args: object) -> PatternValue:
        """Compute a CRC-16 hash over a pattern's bytes.

        Args:
            *args: ``(pattern, init, poly, xorout, reflect_in, reflect_out)``.

        Returns:
            PatternValue: A PatternValue containing the 16-bit CRC value.
        """
        if len(args) < 6:
            return PatternValue(value=0)
        data = self._hash_bytes_from_pattern(args[0])
        init = int(self._unwrap(args[1]))
        poly = int(self._unwrap(args[2]))
        xorout = int(self._unwrap(args[3]))
        reflect_in = bool(self._unwrap(args[4]))
        reflect_out = bool(self._unwrap(args[5]))
        return PatternValue(
            value=_crc_compute(
                data,
                init,
                poly,
                xorout,
                reflect_in=reflect_in,
                reflect_out=reflect_out,
                width_bits=16,
            ),
        )

    def _hash_crc32(self, *args: object) -> PatternValue:
        """Compute a CRC-32 hash over a pattern's bytes.

        Args:
            *args: ``(pattern, init, poly, xorout, reflect_in, reflect_out)``.

        Returns:
            PatternValue: A PatternValue containing the 32-bit CRC value.
        """
        if len(args) < 6:
            return PatternValue(value=0)
        data = self._hash_bytes_from_pattern(args[0])
        init = int(self._unwrap(args[1]))
        poly = int(self._unwrap(args[2]))
        xorout = int(self._unwrap(args[3]))
        reflect_in = bool(self._unwrap(args[4]))
        reflect_out = bool(self._unwrap(args[5]))
        return PatternValue(
            value=_crc_compute(
                data,
                init,
                poly,
                xorout,
                reflect_in=reflect_in,
                reflect_out=reflect_out,
                width_bits=32,
            ),
        )

    def _hash_crc64(self, *args: object) -> PatternValue:
        """Compute a CRC-64 hash over a pattern's bytes.

        Args:
            *args: ``(pattern, init, poly, xorout, reflect_in, reflect_out)``.

        Returns:
            PatternValue: A PatternValue containing the 64-bit CRC value.
        """
        if len(args) < 6:
            return PatternValue(value=0)
        data = self._hash_bytes_from_pattern(args[0])
        init = int(self._unwrap(args[1]))
        poly = int(self._unwrap(args[2]))
        xorout = int(self._unwrap(args[3]))
        reflect_in = bool(self._unwrap(args[4]))
        reflect_out = bool(self._unwrap(args[5]))
        return PatternValue(
            value=_crc_compute(
                data,
                init,
                poly,
                xorout,
                reflect_in=reflect_in,
                reflect_out=reflect_out,
                width_bits=64,
            ),
        )

    @staticmethod
    def _time_epoch(*_args: object) -> PatternValue:
        """Return the current Unix epoch time in seconds.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing the integer epoch seconds.
        """
        return PatternValue(value=int(time.time()))

    @staticmethod
    def _pack_time_struct(tm: time.struct_time) -> int:
        """Pack a ``struct_time`` into a hexpat ``TimeConverter`` u128 value.

        Args:
            tm: The ``time.struct_time`` instance to encode.

        Returns:
            int: A little-endian u128 encoding compatible with ``std::time::Time``.
        """
        year = max(0, min(tm.tm_year, 0xFFFF))
        yday = max(0, min(tm.tm_yday, 0xFFFF))
        packed_bytes = bytes([
            tm.tm_sec & 0xFF,
            tm.tm_min & 0xFF,
            tm.tm_hour & 0xFF,
            tm.tm_mday & 0xFF,
            tm.tm_mon & 0xFF,
            year & 0xFF,
            (year >> 8) & 0xFF,
            tm.tm_wday & 0xFF,
            yday & 0xFF,
            (yday >> 8) & 0xFF,
            1 if tm.tm_isdst > 0 else 0,
            0,
            0,
            0,
            0,
            0,
        ])
        return int.from_bytes(packed_bytes, byteorder="little", signed=False)

    def _time_to_local(self, *args: object) -> PatternValue:
        """Convert an epoch-seconds value to a packed local-time u128.

        Args:
            *args: ``(epoch_time: int)``.

        Returns:
            PatternValue: A PatternValue containing the packed local time.
        """
        if not args:
            return PatternValue(value=0)
        epoch = int(self._unwrap(args[0]))
        tm = safe_call(
            lambda: time.localtime(epoch),
            exceptions=(OverflowError, OSError, ValueError),
            context="hexpat_time_to_local",
            default=None,
        )
        if tm is None:
            return PatternValue(value=0)
        return PatternValue(value=self._pack_time_struct(tm))

    def _time_to_utc(self, *args: object) -> PatternValue:
        """Convert an epoch-seconds value to a packed UTC-time u128.

        Args:
            *args: ``(epoch_time: int)``.

        Returns:
            PatternValue: A PatternValue containing the packed UTC time.
        """
        if not args:
            return PatternValue(value=0)
        epoch = int(self._unwrap(args[0]))
        tm = safe_call(
            lambda: time.gmtime(epoch),
            exceptions=(OverflowError, OSError, ValueError),
            context="hexpat_time_to_utc",
            default=None,
        )
        if tm is None:
            return PatternValue(value=0)
        return PatternValue(value=self._pack_time_struct(tm))

    def _time_format(self, *args: object) -> PatternValue:
        """Format a packed time value according to a ``strftime`` string.

        Args:
            *args: ``(format_string: str, packed_time: int)``.

        Returns:
            PatternValue: A PatternValue containing the formatted timestamp.
        """
        if len(args) < 2:
            return PatternValue(value="")
        fmt = str(self._unwrap(args[0]))
        packed = int(self._unwrap(args[1]))
        raw = packed.to_bytes(16, byteorder="little", signed=False)
        sec = raw[0]
        minute = raw[1]
        hour = raw[2]
        mday = raw[3]
        mon = raw[4]
        year = int.from_bytes(raw[5:7], byteorder="little", signed=False)
        wday = raw[7]
        yday = int.from_bytes(raw[8:10], byteorder="little", signed=False)
        isdst = raw[10]
        try:
            tm = time.struct_time(
                (year, mon, mday, hour, minute, sec, wday, yday, 1 if isdst else 0),
            )
            formatted = time.strftime(fmt, tm)
        except (OverflowError, ValueError) as exc:
            _logger.warning(
                "hexpat_time_format_failed",
                fmt=fmt,
                year=year,
                mon=mon,
                mday=mday,
                exc_type=type(exc).__name__,
                error=str(exc),
            )
            return PatternValue(value="")
        return PatternValue(value=formatted)

    def _file_handle_for(self, arg: object) -> int:
        """Coerce a builtin argument into a registered file handle.

        Args:
            arg: The argument supplied by the pattern caller.

        Returns:
            int: The integer handle value.

        Raises:
            HexPatRuntimeError: When no file is associated with the handle.
        """
        handle = int(self._unwrap(arg))
        if handle not in self._file_handles:
            msg = f"std::file: unknown handle {handle}"
            raise HexPatRuntimeError(msg)
        return handle

    def _file_open(self, *args: object) -> PatternValue:
        """Open a file using a sandboxed absolute path.

        Args:
            *args: ``(path: str, mode: int)``.

        Returns:
            PatternValue: A PatternValue containing the new file handle.

        Raises:
            HexPatRuntimeError: When the path is not absolute, the mode is
                unsupported, the open-handle limit is exceeded, or the
                underlying filesystem call fails.
        """
        if len(args) < 2:
            msg = "std::file::open requires (path, mode)"
            raise HexPatRuntimeError(msg)
        path_str = str(self._unwrap(args[0]))
        mode_tag = int(self._unwrap(args[1]))
        path = Path(path_str)
        if not path.is_absolute():
            msg = f"std::file::open requires an absolute path, got {path_str!r}"
            raise HexPatRuntimeError(msg)
        if len(self._file_handles) >= _MAX_OPEN_FILES:
            msg = "std::file::open exceeded maximum open-handle limit"
            raise HexPatRuntimeError(msg)
        if mode_tag == _FILE_MODE_READ:
            open_mode = "rb"
        elif mode_tag == _FILE_MODE_WRITE:
            open_mode = "r+b"
        elif mode_tag == _FILE_MODE_CREATE:
            open_mode = "w+b"
        else:
            msg = f"std::file::open unknown mode {mode_tag}"
            raise HexPatRuntimeError(msg)
        _logger.info("hexpat_file_open_started", path=path_str, mode=open_mode)
        try:
            handle_obj: BinaryIO = path.open(open_mode)
        except OSError as exc:
            _logger.exception("hexpat_file_open_failed", path=path_str, mode=open_mode)
            msg = f"std::file::open failed for {path_str!r}: {exc}"
            raise HexPatRuntimeError(msg) from exc
        handle_id = self._file_next_handle
        self._file_next_handle += 1
        self._file_handles[handle_id] = handle_obj
        _logger.debug("hexpat_file_open_completed", path=path_str, handle=handle_id)
        return PatternValue(value=handle_id)

    def _file_close(self, *args: object) -> PatternValue:
        """Close a previously opened file handle.

        Args:
            *args: ``(handle: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.
        """
        if not args:
            return PatternValue(value=None)
        handle = int(self._unwrap(args[0]))
        fp = self._file_handles.pop(handle, None)
        if fp is not None:
            try:
                fp.close()
            except OSError as exc:
                _logger.warning("hexpat_file_close_error", handle=handle, error=str(exc))
        return PatternValue(value=None)

    def _file_read(self, *args: object) -> PatternValue:
        """Read ``size`` bytes from a file handle as a UTF-8 string.

        Args:
            *args: ``(handle: int, size: int)``.

        Returns:
            PatternValue: A PatternValue containing the decoded text.

        Raises:
            HexPatRuntimeError: When the read fails.
        """
        if len(args) < 2:
            return PatternValue(value="")
        handle = self._file_handle_for(args[0])
        size = int(self._unwrap(args[1]))
        _logger.debug("hexpat_file_read_started", handle=handle, size=size)
        try:
            data = self._file_handles[handle].read(size)
        except OSError as exc:
            _logger.exception("hexpat_file_read_failed", handle=handle, size=size)
            msg = f"std::file::read failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_read_completed", handle=handle, bytes_read=len(data))
        return PatternValue(value=data.decode("utf-8", errors="replace"))

    def _file_write(self, *args: object) -> PatternValue:
        """Write a payload to the given file handle.

        Args:
            *args: ``(handle: int, data: bytes | str)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the write fails.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        handle = self._file_handle_for(args[0])
        payload = self._unwrap_bytes(args[1])
        _logger.info("hexpat_file_write_started", handle=handle, size=len(payload))
        try:
            self._file_handles[handle].write(payload)
        except OSError as exc:
            _logger.exception("hexpat_file_write_failed", handle=handle, size=len(payload))
            msg = f"std::file::write failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.info("hexpat_file_write_completed", handle=handle, bytes_written=len(payload))
        return PatternValue(value=None)

    def _file_seek(self, *args: object) -> PatternValue:
        """Seek to an absolute byte offset within a file handle.

        Args:
            *args: ``(handle: int, offset: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the seek fails.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        handle = self._file_handle_for(args[0])
        offset = int(self._unwrap(args[1]))
        _logger.debug("hexpat_file_seek_started", handle=handle, offset=offset)
        try:
            self._file_handles[handle].seek(offset)
        except OSError as exc:
            _logger.exception("hexpat_file_seek_failed", handle=handle, offset=offset)
            msg = f"std::file::seek failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_seek_completed", handle=handle, offset=offset)
        return PatternValue(value=None)

    def _file_size(self, *args: object) -> PatternValue:
        """Query the size in bytes of an opened file.

        Args:
            *args: ``(handle: int)``.

        Returns:
            PatternValue: A PatternValue containing the file length.

        Raises:
            HexPatRuntimeError: When the size query fails.
        """
        if not args:
            return PatternValue(value=0)
        handle = self._file_handle_for(args[0])
        _logger.debug("hexpat_file_size_started", handle=handle)
        try:
            current = self._file_handles[handle].tell()
            self._file_handles[handle].seek(0, os.SEEK_END)
            length = self._file_handles[handle].tell()
            self._file_handles[handle].seek(current)
        except OSError as exc:
            _logger.exception("hexpat_file_size_failed", handle=handle)
            msg = f"std::file::size failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_size_completed", handle=handle, size=length)
        return PatternValue(value=length)

    def _file_resize(self, *args: object) -> PatternValue:
        """Truncate or extend a file to the given size.

        Args:
            *args: ``(handle: int, size: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the resize fails.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        handle = self._file_handle_for(args[0])
        size = int(self._unwrap(args[1]))
        _logger.info("hexpat_file_resize_started", handle=handle, new_size=size)
        try:
            self._file_handles[handle].truncate(size)
        except OSError as exc:
            _logger.exception("hexpat_file_resize_failed", handle=handle, new_size=size)
            msg = f"std::file::resize failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_resize_completed", handle=handle, new_size=size)
        return PatternValue(value=None)

    def _file_flush(self, *args: object) -> PatternValue:
        """Flush any pending writes on a file handle.

        Args:
            *args: ``(handle: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the flush fails.
        """
        if not args:
            return PatternValue(value=None)
        handle = self._file_handle_for(args[0])
        _logger.debug("hexpat_file_flush_started", handle=handle)
        try:
            self._file_handles[handle].flush()
        except OSError as exc:
            _logger.exception("hexpat_file_flush_failed", handle=handle)
            msg = f"std::file::flush failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_flush_completed", handle=handle)
        return PatternValue(value=None)

    def _file_remove(self, *args: object) -> PatternValue:
        """Close and delete the file backing a handle.

        Args:
            *args: ``(handle: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the removal fails.
        """
        if not args:
            return PatternValue(value=None)
        handle = self._file_handle_for(args[0])
        fp = self._file_handles.pop(handle)
        file_name = getattr(fp, "name", "")
        try:
            fp.close()
        except OSError as exc:
            _logger.warning("hexpat_file_close_error", handle=handle, error=str(exc))
        if file_name:
            _logger.info(
                "hexpat_file_remove",
                handle=handle,
                file_path=file_name,
            )
            try:
                Path(file_name).unlink(missing_ok=True)
            except OSError as exc:
                _logger.exception(
                    "hexpat_file_remove_failed",
                    handle=handle,
                    file_path=file_name,
                )
                msg = f"std::file::remove failed: {exc}"
                raise HexPatRuntimeError(msg) from exc
        return PatternValue(value=None)

    def _file_create_directories(self, *args: object) -> PatternValue:
        """Recursively create directories for an absolute path.

        Args:
            *args: ``(path: str)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the path is not absolute or creation fails.
        """
        if not args:
            return PatternValue(value=None)
        path_str = str(self._unwrap(args[0]))
        path = Path(path_str)
        if not path.is_absolute():
            msg = f"std::file::create_directories requires an absolute path, got {path_str!r}"
            raise HexPatRuntimeError(msg)
        _logger.info("hexpat_file_create_directories_started", path=path_str)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _logger.exception("hexpat_file_create_directories_failed", path=path_str)
            msg = f"std::file::create_directories failed: {exc}"
            raise HexPatRuntimeError(msg) from exc
        _logger.debug("hexpat_file_create_directories_completed", path=path_str)
        return PatternValue(value=None)

    def _random_set_seed(self, *args: object) -> PatternValue:
        """Reseed the pattern-language random number generator.

        Args:
            *args: ``(seed: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.
        """
        if not args:
            self._rng.seed()
            return PatternValue(value=None)
        seed = int(self._unwrap(args[0]))
        self._rng.seed(seed)
        return PatternValue(value=None)

    def _random_generate(self, *args: object) -> PatternValue:
        """Generate a random value using the requested distribution.

        Args:
            *args: ``(distribution: int, param1, param2)`` where distribution is
                a ``std::random::Distribution`` tag.

        Returns:
            PatternValue: A PatternValue carrying the produced value.

        Raises:
            HexPatRuntimeError: When the distribution tag is unknown or
                distribution parameters are invalid.
        """
        if not args:
            return PatternValue(value=0)
        distribution = int(self._unwrap(args[0]))
        param1 = float(self._unwrap(args[1])) if len(args) > 1 else 0.0
        param2 = float(self._unwrap(args[2])) if len(args) > 2 else 0.0
        if distribution == 0:
            lo = int(param1)
            hi = int(param2) if param2 >= param1 else lo
            return PatternValue(value=self._rng.randint(lo, hi))
        if distribution == 1:
            return PatternValue(value=self._rng.gauss(param1, param2))
        if distribution == 2:
            if param1 <= 0:
                msg = "std::random exponential lambda must be positive"
                raise HexPatRuntimeError(msg)
            return PatternValue(value=self._rng.expovariate(param1))
        if distribution == 3:
            if param1 <= 0 or param2 <= 0:
                msg = "std::random gamma parameters must be positive"
                raise HexPatRuntimeError(msg)
            return PatternValue(value=self._rng.gammavariate(param1, param2))
        if distribution == 4:
            if param1 <= 0 or param2 <= 0:
                msg = "std::random weibull parameters must be positive"
                raise HexPatRuntimeError(msg)
            return PatternValue(value=self._rng.weibullvariate(param1, param2))
        if distribution == 5:
            u = self._rng.random()
            return PatternValue(value=param1 - param2 * math.log(-math.log(max(u, 1e-300))))
        if distribution == 6:
            if param1 <= 0:
                msg = "std::random chi-squared n must be positive"
                raise HexPatRuntimeError(msg)
            total = 0.0
            n = int(param1)
            for _ in range(n):
                z = self._rng.gauss(0.0, 1.0)
                total += z * z
            return PatternValue(value=total)
        if distribution == 7:
            u = self._rng.random()
            return PatternValue(value=param1 + param2 * math.tan(math.pi * (u - 0.5)))
        if distribution == 10:
            return PatternValue(value=math.exp(self._rng.gauss(param1, param2)))
        if distribution == 11:
            return PatternValue(value=1 if self._rng.random() < param1 else 0)
        if distribution == 14:
            if not 0.0 < param1 < 1.0:
                msg = "std::random geometric probability must be in (0, 1)"
                raise HexPatRuntimeError(msg)
            u = self._rng.random()
            return PatternValue(
                value=math.floor(math.log(max(u, 1e-300)) / math.log(1.0 - param1)),
            )
        msg = f"std::random unsupported distribution tag {distribution}"
        raise HexPatRuntimeError(msg)

    @staticmethod
    def _env_get(*args: object) -> PatternValue:
        """Return an environment variable value by name.

        Args:
            *args: ``(name: str)``.

        Returns:
            PatternValue: A PatternValue containing the value, or an empty
                string when the variable is unset.
        """
        if not args:
            return PatternValue(value="")
        arg = args[0]
        if isinstance(arg, PatternValue):
            inner = arg.value
            name = inner if isinstance(inner, str) else str(inner)
        elif isinstance(arg, str):
            name = arg
        else:
            name = str(arg)
        return PatternValue(value=os.environ.get(name, ""))

    @staticmethod
    def _sizeof_pack(*args: object) -> PatternValue:
        """Return the number of elements in a parameter pack.

        Args:
            *args: The forwarded parameter pack.

        Returns:
            PatternValue: A PatternValue containing ``len(args)``.
        """
        return PatternValue(value=len(args))

    def _core_set_endian(self, *args: object) -> PatternValue:
        """Set the default endianness.

        Args:
            *args: ``(endian: int)`` where 0=Native, 1=Big, 2=Little. Native
                resets the default to whatever ``#pragma endian`` selected.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When the supplied endian tag is unrecognised.
        """
        if not args:
            return PatternValue(value=None)
        tag = int(self._unwrap(args[0]))
        if tag == _ENDIAN_BIG:
            new_endian = "big"
        elif tag == _ENDIAN_LITTLE:
            new_endian = "little"
        elif tag == _ENDIAN_NATIVE:
            new_endian = self._pragma.endian if self._pragma.endian in {"little", "big"} else "little"
        else:
            _logger.error("hexpat_set_endian_invalid_tag", endian_tag=tag)
            msg = f"std::core::set_endian: unsupported endian tag {tag}"
            raise HexPatRuntimeError(msg)
        if new_endian != self._endian:
            self._endian = new_endian
            if self._endian_listener is not None:
                self._endian_listener(new_endian)
        return PatternValue(value=None)

    def _core_get_endian(self, *_args: object) -> int:
        """Get the current endianness.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            int: 0 for little-endian, 1 for big-endian.
        """
        return 1 if self._endian == "big" else 0

    def _core_array_index(self, *_args: object) -> int:
        """Get the current array iteration index.

        When the evaluator has wired an array-index provider via
        :meth:`set_array_index_provider`, the live evaluator-owned index is
        returned. Otherwise the most recent value passed to
        :meth:`set_array_index` is returned.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            int: The current array index.
        """
        if self._array_index_listener is not None:
            return int(self._array_index_listener())
        return self._array_index

    @staticmethod
    def _require_pattern(arg: object, where: str) -> PatternValue:
        """Ensure the argument is a ``PatternValue`` suitable for reflection.

        Args:
            arg: The argument to validate.
            where: Human-readable context used in the error message.

        Returns:
            PatternValue: The validated PatternValue.

        Raises:
            HexPatRuntimeError: When ``arg`` is not a ``PatternValue``.
        """
        if not isinstance(arg, PatternValue):
            _logger.error(
                "hexpat_require_pattern_failed",
                context=where,
                actual_type=type(arg).__name__,
            )
            msg = f"{where} requires a pattern argument"
            raise HexPatRuntimeError(msg)
        return arg

    def _core_has_attribute(self, *args: object) -> PatternValue:
        """Check whether a pattern carries a named attribute.

        Args:
            *args: ``(pattern, attribute: str)``.

        Returns:
            PatternValue: A PatternValue wrapping the boolean result.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if len(args) < 2:
            return PatternValue(value=False)
        hook = self._reflection.has_attribute if self._reflection is not None else None
        if hook is None:
            msg = "std::core::has_attribute requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        pattern = self._require_pattern(args[0], "std::core::has_attribute")
        attribute = str(self._unwrap(args[1]))
        return PatternValue(value=hook(pattern, attribute))

    def _core_get_attribute_argument(self, *args: object) -> PatternValue:
        """Return the ``index``-th argument of a named attribute.

        Args:
            *args: ``(pattern, attribute: str, index: int)``.

        Returns:
            PatternValue: The reflected attribute argument.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if len(args) < 2:
            _logger.error(
                "hexpat_get_attribute_argument_invalid_args",
                arg_count=len(args),
            )
            msg = "std::core::get_attribute_argument requires (pattern, attribute, [index])"
            raise HexPatRuntimeError(msg)
        hook = self._reflection.get_attribute_argument if self._reflection is not None else None
        if hook is None:
            _logger.error("hexpat_get_attribute_argument_no_reflection_provider")
            msg = "std::core::get_attribute_argument requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        pattern = self._require_pattern(args[0], "std::core::get_attribute_argument")
        attribute = str(self._unwrap(args[1]))
        index = int(self._unwrap(args[2])) if len(args) > 2 else 0
        return hook(pattern, attribute, index)

    def _core_member_count(self, *args: object) -> PatternValue:
        """Return the number of members on a struct/union/bitfield/array.

        Args:
            *args: ``(pattern,)``.

        Returns:
            PatternValue: A PatternValue wrapping the member count.

        Raises:
            HexPatRuntimeError: When the pattern cannot be reflected upon.
        """
        if not args:
            return PatternValue(value=0)
        pattern = self._require_pattern(args[0], "std::core::member_count")
        if pattern.members:
            return PatternValue(value=len(pattern.members))
        hook = self._reflection.member_count if self._reflection is not None else None
        if hook is None:
            msg = "std::core::member_count requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=hook(pattern))

    def _core_has_member(self, *args: object) -> PatternValue:
        """Check whether a pattern exposes a named member.

        Args:
            *args: ``(pattern, name: str)``.

        Returns:
            PatternValue: A PatternValue wrapping the boolean result.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired and the
                pattern has no locally visible members.
        """
        if len(args) < 2:
            return PatternValue(value=False)
        pattern = self._require_pattern(args[0], "std::core::has_member")
        name = str(self._unwrap(args[1]))
        if pattern.members:
            return PatternValue(value=name in pattern.members)
        hook = self._reflection.has_member if self._reflection is not None else None
        if hook is None:
            msg = "std::core::has_member requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=hook(pattern, name))

    def _core_formatted_value(self, *args: object) -> PatternValue:
        """Return a formatter-produced string representation of a pattern.

        Args:
            *args: ``(pattern,)``.

        Returns:
            PatternValue: A PatternValue wrapping the formatted string.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if not args:
            return PatternValue(value="")
        pattern = self._require_pattern(args[0], "std::core::formatted_value")
        hook = self._reflection.formatted_value if self._reflection is not None else None
        if hook is None:
            msg = "std::core::formatted_value requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=hook(pattern))

    def _core_is_valid_enum(self, *args: object) -> PatternValue:
        """Check whether an enum-typed pattern matches a declared constant.

        Args:
            *args: ``(pattern,)``.

        Returns:
            PatternValue: A PatternValue wrapping the boolean result.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if not args:
            return PatternValue(value=False)
        pattern = self._require_pattern(args[0], "std::core::is_valid_enum")
        hook = self._reflection.is_valid_enum if self._reflection is not None else None
        if hook is None:
            msg = "std::core::is_valid_enum requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=hook(pattern))

    def _core_set_pattern_color(self, *args: object) -> PatternValue:
        """Assign an RGBA8 color annotation to a pattern.

        Args:
            *args: ``(pattern, color: int)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        hook = self._reflection.set_pattern_color if self._reflection is not None else None
        if hook is None:
            msg = "std::core::set_pattern_color requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        pattern = self._require_pattern(args[0], "std::core::set_pattern_color")
        color = int(self._unwrap(args[1]))
        hook(pattern, color)
        return PatternValue(value=None)

    def _core_set_display_name(self, *args: object) -> PatternValue:
        """Override the display name of a pattern.

        Args:
            *args: ``(pattern, name: str)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        hook = self._reflection.set_display_name if self._reflection is not None else None
        if hook is None:
            msg = "std::core::set_display_name requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        pattern = self._require_pattern(args[0], "std::core::set_display_name")
        name = str(self._unwrap(args[1]))
        hook(pattern, name)
        return PatternValue(value=None)

    def _core_set_pattern_comment(self, *args: object) -> PatternValue:
        """Attach a comment annotation to a pattern.

        Args:
            *args: ``(pattern, comment: str)``.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if len(args) < 2:
            return PatternValue(value=None)
        hook = self._reflection.set_pattern_comment if self._reflection is not None else None
        if hook is None:
            msg = "std::core::set_pattern_comment requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        pattern = self._require_pattern(args[0], "std::core::set_pattern_comment")
        comment = str(self._unwrap(args[1]))
        hook(pattern, comment)
        return PatternValue(value=None)

    def _core_set_pattern_palette_colors(self, *args: object) -> PatternValue:
        """Install a new RGBA8 color palette for subsequent pattern creation.

        Args:
            *args: The RGBA8 palette colors as 32-bit integers.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        hook = self._reflection.set_pattern_palette_colors if self._reflection is not None else None
        if hook is None:
            _logger.error("hexpat_set_pattern_palette_colors_no_reflection_provider")
            msg = "std::core::set_pattern_palette_colors requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        colors = [int(self._unwrap(a)) for a in args]
        hook(colors)
        return PatternValue(value=None)

    def _core_reset_pattern_palette(self, *_args: object) -> PatternValue:
        """Reset the palette rotation index to zero.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing ``None``.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        hook = self._reflection.reset_pattern_palette if self._reflection is not None else None
        if hook is None:
            _logger.error("hexpat_reset_pattern_palette_no_reflection_provider")
            msg = "std::core::reset_pattern_palette requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        hook()
        return PatternValue(value=None)

    def _core_execute_function(self, *args: object) -> PatternValue:
        """Invoke a named pattern function via the reflection provider.

        Args:
            *args: ``(function_name: str, *args)``.

        Returns:
            PatternValue: The value returned by the callee.

        Raises:
            HexPatRuntimeError: When no reflection provider is wired.
        """
        if not args:
            return PatternValue(value=None)
        hook = self._reflection.execute_function if self._reflection is not None else None
        if hook is None:
            msg = "std::core::execute_function requires evaluator metadata not yet wired"
            raise HexPatRuntimeError(msg)
        function_name = str(self._unwrap(args[0]))
        forwarded: list[PatternValue] = [a if isinstance(a, PatternValue) else PatternValue(value=self._unwrap(a)) for a in args[1:]]
        return hook(function_name, forwarded)

    def _io_print(self, *args: object) -> PatternValue:
        """Print a message to the log with ``std::format`` semantics.

        Args:
            *args: ``(format_str: str, ...values)``. The first argument is
                interpreted as a format string with ``{}``/``{n}``/``{:spec}``
                fields; remaining values substitute positionally.

        Returns:
            PatternValue: A PatternValue containing None.
        """
        sink = _PrintSinkRegistry.sink
        if not args:
            _logger.info("hexpat_print", output_length=0)
            if sink is not None:
                sink("")
            return PatternValue(value=None)
        formatted = self._format_string(args[0], list(args[1:]))
        _logger.info("hexpat_print", output=formatted)
        if sink is not None:
            sink(formatted)
        return PatternValue(value=None)

    def _io_format(self, *args: object) -> str:
        """Format a string with arguments using hexpat field substitution semantics.

        Args:
            *args: ``(format_str: str, ...values)``.

        Returns:
            str: The formatted string.
        """
        return self._format_string(args[0], list(args[1:])) if args else ""

    def _io_error(self, *args: object) -> NoReturn:
        """Raise a fatal pattern error.

        Args:
            *args: ``(message: str)``.

        Raises:
            HexPatRuntimeError: Always, carrying the supplied message.
        """
        message = str(self._unwrap(args[0])) if args else ""
        _logger.error("hexpat_io_error", error_message=message)
        raise HexPatRuntimeError(message)

    def _io_warning(self, *args: object) -> PatternValue:
        """Emit a non-fatal warning message to the log.

        Args:
            *args: ``(message: str)``.

        Returns:
            PatternValue: A PatternValue containing None.
        """
        message = str(self._unwrap(args[0])) if args else ""
        _logger.warning("hexpat_warning", output=message)
        sink = _PrintSinkRegistry.sink
        if sink is not None:
            sink(f"warning: {message}")
        return PatternValue(value=None)

    def _format_string(self, fmt_arg: object, values: list[object]) -> str:
        """Apply hexpat format-string semantics to a template and value list.

        Args:
            fmt_arg: The format string argument (or its ``PatternValue`` wrapper).
            values: The ordered positional substitution values.

        Returns:
            str: The rendered string with all fields expanded.
        """
        fmt = str(self._unwrap(fmt_arg))
        unwrapped: list[int | float | str] = [self._unwrap(v) for v in values]
        auto_index: int = 0

        def _replace(match: re.Match[str]) -> str:
            """Expand one format-string field from the positional value list.

            Args:
                match: Regex match for a single ``{...}`` format field.

            Returns:
                str: Formatted field text, the original match text on invalid
                index syntax, or an empty string for out-of-range indices.
            """
            nonlocal auto_index
            spec = match.group(1)
            index: int
            format_spec: str = ""
            if ":" in spec:
                head, _, format_spec = spec.partition(":")
            else:
                head = spec
            if not head:
                index = auto_index
                auto_index += 1
            else:
                parsed_index = safe_int_from_str(head, base=10, context="hexpat_format_string_index")
                if parsed_index is None:
                    _logger.warning(
                        "hexpat_format_invalid_index",
                        spec=spec,
                        head=head,
                    )
                    return match.group(0)
                index = parsed_index
            if index < 0 or index >= len(unwrapped):
                return ""
            value = unwrapped[index]
            if not format_spec:
                return str(value)
            try:
                return format(value, format_spec)
            except (TypeError, ValueError) as exc:
                _logger.warning(
                    "hexpat_format_spec_failed",
                    spec=spec,
                    format_spec=format_spec,
                    value_type=type(value).__name__,
                    error=str(exc),
                )
                return str(value)

        try:
            return _FORMAT_FIELD_RE.sub(_replace, fmt)
        except (IndexError, KeyError) as exc:
            _logger.warning(
                "hexpat_format_string_regex_failed",
                fmt=fmt,
                exc_type=type(exc).__name__,
                error=str(exc),
            )
            return fmt

    def _read_struct_field(self, *args: object) -> PatternValue:
        """Read a struct field as unsigned integer (internal helper).

        Args:
            *args: ``(offset: int, size: int)``.

        Returns:
            PatternValue: A PatternValue containing the unsigned integer value.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        size = int(self._unwrap(args[1])) if len(args) > 1 else 4
        if size <= 8:
            fmt_map = {1: "B", 2: "H", 4: "I", 8: "Q"}
            fmt_char = fmt_map.get(size, "I")
            prefix = "<" if self._endian == "little" else ">"
            raw = self._data.read(offset, size)
            result = struct.unpack(f"{prefix}{fmt_char}", raw)[0]
            if isinstance(result, int):
                return PatternValue(value=result)
            return PatternValue(value=int(result))
        raw = self._data.read(offset, size)
        byteorder: Literal["little", "big"] = "little" if self._endian == "little" else "big"
        return PatternValue(value=int.from_bytes(raw, byteorder=byteorder, signed=False))
