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
import struct
from typing import TYPE_CHECKING

from intellicrack.core.hexpat.errors import HexPatRuntimeError
from intellicrack.core.hexpat.evaluator import BuiltinCallable, PatternValue
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from typing import Any

    from intellicrack.core.hexpat.data_reader import DataReader
    from intellicrack.core.hexpat.evaluator import EvalScope


_logger = get_logger("core.hexpat.stdlib")


class BuiltinFunctions:
    """Implements the builtin:: namespace functions in Python.

    Registered into the evaluator's global scope so that the real
    std/*.pat library files can call them transparently.

    Args:
            data_reader: The DataReader wrapping the target binary.
    """

    def __init__(self, data_reader: DataReader) -> None:
        self._data: DataReader = data_reader
        self._endian: str = "little"
        self._array_index: int = 0

    @staticmethod
    def _unwrap(arg: object) -> int | float | str:
        """
        Extract the raw value from a PatternValue argument.

        Args:
            arg: A PatternValue or raw value.

        Returns:
            int | float | str: The unwrapped raw value as a primitive.
        """
        if isinstance(arg, PatternValue):
            val = arg.value
            if isinstance(val, (int, float, str)):
                return val
            return 0
        if isinstance(arg, (int, float, str)):
            return arg
        return 0

    def set_array_index(self, index: int) -> None:
        """
        Set the current array iteration index.

        Args:
            index: The current array element index.
        """
        self._array_index = index

    def register_all(self, scope: EvalScope) -> None:
        """
        Register all builtin functions into the given scope.

        Args:
            scope: The evaluator scope to register functions in.
        """
        builtins: dict[str, Any] = {
            "builtin::std::mem::read_unsigned": self._mem_read_unsigned,
            "builtin::std::mem::read_signed": self._mem_read_signed,
            "builtin::std::mem::read_string": self._mem_read_string,
            "builtin::std::mem::find_sequence_in_range": self._mem_find_sequence,
            "builtin::std::mem::size": self._mem_size,
            "builtin::std::mem::base_address": self._mem_base_address,
            "std::mem::read_unsigned": self._mem_read_unsigned,
            "std::mem::read_signed": self._mem_read_signed,
            "std::mem::read_string": self._mem_read_string,
            "std::mem::find_sequence_in_range": self._mem_find_sequence,
            "std::mem::size": self._mem_size,
            "std::mem::base_address": self._mem_base_address,
            "builtin::std::string::length": self._string_length,
            "builtin::std::string::at": self._string_at,
            "builtin::std::string::substr": self._string_substr,
            "builtin::std::string::contains": self._string_contains,
            "builtin::std::string::starts_with": self._string_starts_with,
            "builtin::std::string::ends_with": self._string_ends_with,
            "builtin::std::string::to_int": self._string_to_int,
            "builtin::std::string::reverse": self._string_reverse,
            "std::string::length": self._string_length,
            "std::string::at": self._string_at,
            "std::string::substr": self._string_substr,
            "std::string::contains": self._string_contains,
            "std::string::starts_with": self._string_starts_with,
            "std::string::ends_with": self._string_ends_with,
            "std::string::to_int": self._string_to_int,
            "std::string::reverse": self._string_reverse,
            "builtin::std::math::abs": self._math_abs,
            "builtin::std::math::min": self._math_min,
            "builtin::std::math::max": self._math_max,
            "builtin::std::math::floor": self._math_floor,
            "builtin::std::math::ceil": self._math_ceil,
            "builtin::std::math::log2": self._math_log2,
            "builtin::std::math::pow": self._math_pow,
            "builtin::std::math::sqrt": self._math_sqrt,
            "std::math::abs": self._math_abs,
            "std::math::min": self._math_min,
            "std::math::max": self._math_max,
            "std::math::floor": self._math_floor,
            "std::math::ceil": self._math_ceil,
            "std::math::log2": self._math_log2,
            "std::math::pow": self._math_pow,
            "std::math::sqrt": self._math_sqrt,
            "builtin::std::core::set_endian": self._core_set_endian,
            "builtin::std::core::get_endian": self._core_get_endian,
            "builtin::std::core::array_index": self._core_array_index,
            "std::core::set_endian": self._core_set_endian,
            "std::core::get_endian": self._core_get_endian,
            "std::core::array_index": self._core_array_index,
            "builtin::std::io::print": self._io_print,
            "builtin::std::io::format": self._io_format,
            "std::print": self._io_print,
            "std::format": self._io_format,
        }

        for name, func in builtins.items():
            scope.define(name, PatternValue(value=BuiltinCallable(fn=func, name=name)))

    def _mem_read_unsigned(self, *args: object) -> PatternValue:
        """
        Read an unsigned integer from binary data.

        Args:
            *args: (offset: int, size: int) where size is byte count (1,2,4,8,16).

        Returns:
            PatternValue: A PatternValue containing the unsigned integer value.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        size = int(self._unwrap(args[1])) if len(args) > 1 else 1
        raw = self._data.read(offset, size)
        byteorder = "little" if self._endian == "little" else "big"
        return PatternValue(value=int.from_bytes(raw, byteorder=byteorder, signed=False))

    def _mem_read_signed(self, *args: object) -> PatternValue:
        """
        Read a signed integer from binary data.

        Args:
            *args: (offset: int, size: int) where size is byte count.

        Returns:
            PatternValue: A PatternValue containing the signed integer value.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        size = int(self._unwrap(args[1])) if len(args) > 1 else 1
        raw = self._data.read(offset, size)
        byteorder = "little" if self._endian == "little" else "big"
        return PatternValue(value=int.from_bytes(raw, byteorder=byteorder, signed=True))

    def _mem_read_string(self, *args: object) -> PatternValue:
        """
        Read a string from binary data.

        Args:
            *args: (offset: int, length: int).

        Returns:
            PatternValue: A PatternValue containing the decoded string.
        """
        offset = int(self._unwrap(args[0])) if args else 0
        length = int(self._unwrap(args[1])) if len(args) > 1 else 256
        raw = self._data.read(offset, length)
        null_idx = raw.find(b"\x00")
        if null_idx >= 0:
            raw = raw[:null_idx]
        return PatternValue(value=raw.decode("utf-8", errors="replace"))

    def _mem_find_sequence(self, *args: object) -> PatternValue:
        """
        Find a byte sequence in a range of binary data.

        Args:
            *args: (start: int, end: int, pattern_bytes...).

        Returns:
            PatternValue: A PatternValue containing the offset of the first match, or -1.
        """
        if len(args) < 3:
            return PatternValue(value=-1)
        start = int(self._unwrap(args[0]))
        end = int(self._unwrap(args[1]))
        pattern_args = [self._unwrap(a) for a in args[2:]]
        pattern = bytes(int(b) & 0xFF for b in pattern_args)
        result = self._data.find_sequence(pattern, start)
        if result >= 0 and result + len(pattern) > end:
            return PatternValue(value=-1)
        return PatternValue(value=result)

    def _mem_size(self, *_args: object) -> PatternValue:
        """
        Get the total size of the binary data.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing the data size in bytes.
        """
        return PatternValue(value=self._data.size)

    @staticmethod
    def _mem_base_address(*_args: object) -> PatternValue:
        """
        Get the base address (always 0 for file-based analysis).

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing the base address.
        """
        return PatternValue(value=0)

    def _string_length(self, *args: object) -> PatternValue:
        """
        Get the length of a string.

        Args:
            *args: (s: str).

        Returns:
            PatternValue: A PatternValue containing the string length.
        """
        return PatternValue(value=len(str(self._unwrap(args[0]))) if args else 0)

    def _string_at(self, *args: object) -> PatternValue:
        """
        Get a character at an index.

        Args:
            *args: (s: str, index: int).

        Returns:
            PatternValue: A PatternValue containing the character at the given index.
        """
        if len(args) < 2:
            return PatternValue(value="")
        s = str(self._unwrap(args[0]))
        idx = int(self._unwrap(args[1]))
        if 0 <= idx < len(s):
            return PatternValue(value=s[idx])
        return PatternValue(value="")

    def _string_substr(self, *args: object) -> PatternValue:
        """
        Extract a substring.

        Args:
            *args: (s: str, start: int, length: int).

        Returns:
            PatternValue: A PatternValue containing the extracted substring.
        """
        if len(args) < 3:
            return PatternValue(value="")
        s = str(self._unwrap(args[0]))
        start = int(self._unwrap(args[1]))
        length = int(self._unwrap(args[2]))
        return PatternValue(value=s[start : start + length])

    def _string_contains(self, *args: object) -> PatternValue:
        """
        Check if a string contains a substring.

        Args:
            *args: (s: str, sub: str).

        Returns:
            PatternValue: A PatternValue containing True if the substring is found.
        """
        if len(args) < 2:
            return PatternValue(value=False)
        return PatternValue(value=str(self._unwrap(args[1])) in str(self._unwrap(args[0])))

    def _string_starts_with(self, *args: object) -> PatternValue:
        """
        Check if a string starts with a prefix.

        Args:
            *args: (s: str, prefix: str).

        Returns:
            PatternValue: A PatternValue containing True if the string starts with the prefix.
        """
        if len(args) < 2:
            return PatternValue(value=False)
        return PatternValue(value=str(self._unwrap(args[0])).startswith(str(self._unwrap(args[1]))))

    def _string_ends_with(self, *args: object) -> PatternValue:
        """
        Check if a string ends with a suffix.

        Args:
            *args: (s: str, suffix: str).

        Returns:
            PatternValue: A PatternValue containing True if the string ends with the suffix.
        """
        if len(args) < 2:
            return PatternValue(value=False)
        return PatternValue(value=str(self._unwrap(args[0])).endswith(str(self._unwrap(args[1]))))

    def _string_to_int(self, *args: object) -> PatternValue:
        """
        Parse a string as an integer.

        Args:
            *args: (s: str, base: int).

        Returns:
            PatternValue: A PatternValue containing the parsed integer value.
        """
        if not args:
            return PatternValue(value=0)
        s = str(self._unwrap(args[0]))
        base = int(self._unwrap(args[1])) if len(args) > 1 else 10
        try:
            result = int(s, base)
        except ValueError:
            return PatternValue(value=0)
        else:
            return PatternValue(value=result)

    def _string_reverse(self, *args: object) -> PatternValue:
        """
        Reverse a string.

        Args:
            *args: (s: str).

        Returns:
            PatternValue: A PatternValue containing the reversed string.
        """
        return PatternValue(value=str(self._unwrap(args[0]))[::-1] if args else "")

    def _math_abs(self, *args: object) -> PatternValue:
        """
        Compute the absolute value.

        Args:
            *args: (x: int | float).

        Returns:
            PatternValue: A PatternValue containing the absolute value.
        """
        if not args:
            return PatternValue(value=0)
        val = self._unwrap(args[0])
        if isinstance(val, float):
            return PatternValue(value=abs(val))
        return PatternValue(value=abs(int(val)))

    def _math_min(self, *args: object) -> PatternValue:
        """
        Return the minimum of two values.

        Args:
            *args: (a: int | float, b: int | float).

        Returns:
            PatternValue: A PatternValue containing the smaller value.
        """
        if len(args) < 2:
            return PatternValue(value=int(self._unwrap(args[0])) if args else 0)
        a, b = self._unwrap(args[0]), self._unwrap(args[1])
        if isinstance(a, float) or isinstance(b, float):
            return PatternValue(value=min(float(a), float(b)))
        return PatternValue(value=min(int(a), int(b)))

    def _math_max(self, *args: object) -> PatternValue:
        """
        Return the maximum of two values.

        Args:
            *args: (a: int | float, b: int | float).

        Returns:
            PatternValue: A PatternValue containing the larger value.
        """
        if len(args) < 2:
            return PatternValue(value=int(self._unwrap(args[0])) if args else 0)
        a, b = self._unwrap(args[0]), self._unwrap(args[1])
        if isinstance(a, float) or isinstance(b, float):
            return PatternValue(value=max(float(a), float(b)))
        return PatternValue(value=max(int(a), int(b)))

    def _math_floor(self, *args: object) -> PatternValue:
        """
        Compute the floor of a value.

        Args:
            *args: (x: float).

        Returns:
            PatternValue: A PatternValue containing the floor as an integer.
        """
        return PatternValue(value=math.floor(float(self._unwrap(args[0]))) if args else 0)

    def _math_ceil(self, *args: object) -> PatternValue:
        """
        Compute the ceiling of a value.

        Args:
            *args: (x: float).

        Returns:
            PatternValue: A PatternValue containing the ceiling as an integer.
        """
        return PatternValue(value=math.ceil(float(self._unwrap(args[0]))) if args else 0)

    def _math_log2(self, *args: object) -> PatternValue:
        """
        Compute the base-2 logarithm.

        Args:
            *args: (x: float).

        Returns:
            PatternValue: A PatternValue containing the log base 2 value.

        Raises:
            HexPatRuntimeError: If the value is non-positive.
        """
        if not args:
            return PatternValue(value=0.0)
        val = float(self._unwrap(args[0]))
        if val <= 0:
            msg = "log2 of non-positive value"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=math.log2(val))

    def _math_pow(self, *args: object) -> PatternValue:
        """
        Compute a power.

        Args:
            *args: (base: float, exp: float).

        Returns:
            PatternValue: A PatternValue containing base raised to the power of exp.
        """
        if len(args) < 2:
            return PatternValue(value=0.0)
        return PatternValue(value=math.pow(float(self._unwrap(args[0])), float(self._unwrap(args[1]))))

    def _math_sqrt(self, *args: object) -> PatternValue:
        """
        Compute the square root.

        Args:
            *args: (x: float).

        Returns:
            PatternValue: A PatternValue containing the square root.

        Raises:
            HexPatRuntimeError: If the value is negative.
        """
        if not args:
            return PatternValue(value=0.0)
        val = float(self._unwrap(args[0]))
        if val < 0:
            msg = "sqrt of negative value"
            raise HexPatRuntimeError(msg)
        return PatternValue(value=math.sqrt(val))

    def _core_set_endian(self, *args: object) -> PatternValue:
        """
        Set the default endianness.

        Args:
            *args: (endian: int) where 0=little, 1=big.

        Returns:
            PatternValue: A PatternValue containing None.
        """
        if args:
            self._endian = "big" if int(self._unwrap(args[0])) != 0 else "little"
        return PatternValue(value=None)

    def _core_get_endian(self, *_args: object) -> PatternValue:
        """
        Get the current endianness.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing 0 for little-endian, 1 for big-endian.
        """
        return PatternValue(value=1 if self._endian == "big" else 0)

    def _core_array_index(self, *_args: object) -> PatternValue:
        """
        Get the current array iteration index.

        Args:
            *_args: Unused arguments for API compatibility.

        Returns:
            PatternValue: A PatternValue containing the current array index.
        """
        return PatternValue(value=self._array_index)

    def _io_print(self, *args: object) -> PatternValue:
        """
        Print a message to the log.

        Args:
            *args: Values to print.

        Returns:
            PatternValue: A PatternValue containing None.
        """
        message = " ".join(str(self._unwrap(a)) for a in args)
        _logger.info("hexpat_print", output=message)
        return PatternValue(value=None)

    def _io_format(self, *args: object) -> PatternValue:
        """
        Format a string with arguments.

        Args:
            *args: (format_str: str, ...values).

        Returns:
            PatternValue: A PatternValue containing the formatted string.
        """
        if not args:
            return PatternValue(value="")
        fmt = str(self._unwrap(args[0]))
        fmt_args = [self._unwrap(a) for a in args[1:]]
        try:
            result = fmt
            for i, arg in enumerate(fmt_args):
                result = result.replace("{}", str(arg), 1)
                result = result.replace(f"{{{i}}}", str(arg))
        except (IndexError, KeyError):
            return PatternValue(value=fmt)
        else:
            return PatternValue(value=result)

    def _read_struct_field(self, *args: object) -> PatternValue:
        """
        Read a struct field as unsigned integer (internal helper).

        Args:
            *args: (offset: int, size: int).

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
        byteorder = "little" if self._endian == "little" else "big"
        return PatternValue(value=int.from_bytes(raw, byteorder=byteorder, signed=False))
