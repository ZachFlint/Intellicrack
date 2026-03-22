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
from intellicrack.core.hexpat.evaluator import PatternValue
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

    Attributes:
        data: The DataReader providing binary access.
    """

    def __init__(self, data_reader: DataReader) -> None:
        """Initialize with a data reader for binary access.

        Args:
            data_reader: The DataReader wrapping the target binary.
        """
        self._data: DataReader = data_reader
        self._endian: str = "little"
        self._array_index: int = 0

    def set_array_index(self, index: int) -> None:
        """Set the current array iteration index.

        Args:
            index: The current array element index.
        """
        self._array_index = index

    def register_all(self, scope: EvalScope) -> None:
        """Register all builtin functions into the given scope.

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
            scope.define(name, PatternValue(value=func))

    def _mem_read_unsigned(self, *args: Any) -> int:
        """Read an unsigned integer from binary data.

        Args:
            *args: (offset: int, size: int) where size is byte count (1,2,4,8,16).

        Returns:
            The unsigned integer value.

        Raises:
            HexPatRuntimeError: If the read is out of bounds.
        """
        offset = int(args[0]) if args else 0
        size = int(args[1]) if len(args) > 1 else 1
        raw = self._data.read(offset, size)
        byteorder = "little" if self._endian == "little" else "big"
        return int.from_bytes(raw, byteorder=byteorder, signed=False)

    def _mem_read_signed(self, *args: Any) -> int:
        """Read a signed integer from binary data.

        Args:
            *args: (offset: int, size: int) where size is byte count.

        Returns:
            The signed integer value.

        Raises:
            HexPatRuntimeError: If the read is out of bounds.
        """
        offset = int(args[0]) if args else 0
        size = int(args[1]) if len(args) > 1 else 1
        raw = self._data.read(offset, size)
        byteorder = "little" if self._endian == "little" else "big"
        return int.from_bytes(raw, byteorder=byteorder, signed=True)

    def _mem_read_string(self, *args: Any) -> str:
        """Read a string from binary data.

        Args:
            *args: (offset: int, length: int).

        Returns:
            The decoded string.

        Raises:
            HexPatRuntimeError: If the read is out of bounds.
        """
        offset = int(args[0]) if args else 0
        length = int(args[1]) if len(args) > 1 else 256
        raw = self._data.read(offset, length)
        null_idx = raw.find(b"\x00")
        if null_idx >= 0:
            raw = raw[:null_idx]
        return raw.decode("utf-8", errors="replace")

    def _mem_find_sequence(self, *args: Any) -> int:
        """Find a byte sequence in binary data.

        Args:
            *args: (start: int, end: int, pattern_bytes...).

        Returns:
            The offset of the first match, or -1 if not found.
        """
        if len(args) < 3:
            return -1
        start = int(args[0])
        pattern_args = args[2:]
        pattern = bytes(int(b) & 0xFF for b in pattern_args)
        return self._data.find_sequence(pattern, start)

    def _mem_size(self, *_args: Any) -> int:
        """Get the total size of the binary data.

        Returns:
            The data size in bytes.
        """
        return self._data.size

    @staticmethod
    def _mem_base_address(*_args: Any) -> int:
        """Get the base address (always 0 for file-based analysis).

        Returns:
            The base address.
        """
        return 0

    @staticmethod
    def _string_length(*args: Any) -> int:
        """Get the length of a string.

        Args:
            *args: (s: str).

        Returns:
            The string length.
        """
        return len(str(args[0])) if args else 0

    @staticmethod
    def _string_at(*args: Any) -> str:
        """Get a character at an index.

        Args:
            *args: (s: str, index: int).

        Returns:
            The character at the given index.
        """
        if len(args) < 2:
            return ""
        s = str(args[0])
        idx = int(args[1])
        if 0 <= idx < len(s):
            return s[idx]
        return ""

    @staticmethod
    def _string_substr(*args: Any) -> str:
        """Extract a substring.

        Args:
            *args: (s: str, start: int, length: int).

        Returns:
            The extracted substring.
        """
        if len(args) < 3:
            return ""
        s = str(args[0])
        start = int(args[1])
        length = int(args[2])
        return s[start : start + length]

    @staticmethod
    def _string_contains(*args: Any) -> bool:
        """Check if a string contains a substring.

        Args:
            *args: (s: str, sub: str).

        Returns:
            True if the substring is found.
        """
        if len(args) < 2:
            return False
        return str(args[1]) in str(args[0])

    @staticmethod
    def _string_starts_with(*args: Any) -> bool:
        """Check if a string starts with a prefix.

        Args:
            *args: (s: str, prefix: str).

        Returns:
            True if the string starts with the prefix.
        """
        if len(args) < 2:
            return False
        return str(args[0]).startswith(str(args[1]))

    @staticmethod
    def _string_ends_with(*args: Any) -> bool:
        """Check if a string ends with a suffix.

        Args:
            *args: (s: str, suffix: str).

        Returns:
            True if the string ends with the suffix.
        """
        if len(args) < 2:
            return False
        return str(args[0]).endswith(str(args[1]))

    @staticmethod
    def _string_to_int(*args: Any) -> int:
        """Parse a string as an integer.

        Args:
            *args: (s: str, base: int).

        Returns:
            The parsed integer value.
        """
        if not args:
            return 0
        s = str(args[0])
        base = int(args[1]) if len(args) > 1 else 10
        try:
            result = int(s, base)
        except ValueError:
            return 0
        else:
            return result

    @staticmethod
    def _string_reverse(*args: Any) -> str:
        """Reverse a string.

        Args:
            *args: (s: str).

        Returns:
            The reversed string.
        """
        return str(args[0])[::-1] if args else ""

    @staticmethod
    def _math_abs(*args: Any) -> int | float:
        """Compute the absolute value.

        Args:
            *args: (x: int | float).

        Returns:
            The absolute value.
        """
        if not args:
            return 0
        val = args[0]
        if isinstance(val, float):
            return abs(val)
        return abs(int(val))

    @staticmethod
    def _math_min(*args: Any) -> int | float:
        """Return the minimum of two values.

        Args:
            *args: (a: int | float, b: int | float).

        Returns:
            The smaller value.
        """
        if len(args) < 2:
            return int(args[0]) if args else 0
        a, b = args[0], args[1]
        if isinstance(a, float) or isinstance(b, float):
            return min(float(a), float(b))
        return min(int(a), int(b))

    @staticmethod
    def _math_max(*args: Any) -> int | float:
        """Return the maximum of two values.

        Args:
            *args: (a: int | float, b: int | float).

        Returns:
            The larger value.
        """
        if len(args) < 2:
            return int(args[0]) if args else 0
        a, b = args[0], args[1]
        if isinstance(a, float) or isinstance(b, float):
            return max(float(a), float(b))
        return max(int(a), int(b))

    @staticmethod
    def _math_floor(*args: Any) -> int:
        """Compute the floor of a value.

        Args:
            *args: (x: float).

        Returns:
            The floor as an integer.
        """
        return math.floor(float(args[0])) if args else 0

    @staticmethod
    def _math_ceil(*args: Any) -> int:
        """Compute the ceiling of a value.

        Args:
            *args: (x: float).

        Returns:
            The ceiling as an integer.
        """
        return math.ceil(float(args[0])) if args else 0

    @staticmethod
    def _math_log2(*args: Any) -> float:
        """Compute the base-2 logarithm.

        Args:
            *args: (x: float).

        Returns:
            The log base 2 value.

        Raises:
            HexPatRuntimeError: If the value is non-positive.
        """
        if not args:
            return 0.0
        val = float(args[0])
        if val <= 0:
            msg = "log2 of non-positive value"
            raise HexPatRuntimeError(msg)
        return math.log2(val)

    @staticmethod
    def _math_pow(*args: Any) -> float:
        """Compute a power.

        Args:
            *args: (base: float, exp: float).

        Returns:
            base raised to the power of exp.
        """
        if len(args) < 2:
            return 0.0
        return math.pow(float(args[0]), float(args[1]))

    @staticmethod
    def _math_sqrt(*args: Any) -> float:
        """Compute the square root.

        Args:
            *args: (x: float).

        Returns:
            The square root.

        Raises:
            HexPatRuntimeError: If the value is negative.
        """
        if not args:
            return 0.0
        val = float(args[0])
        if val < 0:
            msg = "sqrt of negative value"
            raise HexPatRuntimeError(msg)
        return math.sqrt(val)

    def _core_set_endian(self, *args: Any) -> None:
        """Set the default endianness.

        Args:
            *args: (endian: int) where 0=little, 1=big.
        """
        if args:
            self._endian = "big" if int(args[0]) != 0 else "little"

    def _core_get_endian(self, *_args: Any) -> int:
        """Get the current endianness.

        Returns:
            0 for little-endian, 1 for big-endian.
        """
        return 1 if self._endian == "big" else 0

    def _core_array_index(self, *_args: Any) -> int:
        """Get the current array iteration index.

        Returns:
            The current array index.
        """
        return self._array_index

    @staticmethod
    def _io_print(*args: Any) -> None:
        """Print a message to the log.

        Args:
            *args: Values to print.
        """
        message = " ".join(str(a) for a in args)
        _logger.info("hexpat_print", output=message)

    @staticmethod
    def _io_format(*args: Any) -> str:
        """Format a string with arguments.

        Args:
            *args: (format_str: str, ...values).

        Returns:
            The formatted string.
        """
        if not args:
            return ""
        fmt = str(args[0])
        fmt_args = args[1:]
        try:
            result = fmt
            for i, arg in enumerate(fmt_args):
                result = result.replace("{}", str(arg), 1)
                result = result.replace(f"{{{i}}}", str(arg))
        except (IndexError, KeyError):
            return fmt
        else:
            return result

    def _read_struct_field(self, *args: Any) -> int:
        """Read a struct field as unsigned integer (internal helper).

        Args:
            *args: (offset: int, size: int).

        Returns:
            The unsigned integer value.
        """
        offset = int(args[0]) if args else 0
        size = int(args[1]) if len(args) > 1 else 4
        if size <= 8:
            fmt_map = {1: "B", 2: "H", 4: "I", 8: "Q"}
            fmt_char = fmt_map.get(size, "I")
            prefix = "<" if self._endian == "little" else ">"
            raw = self._data.read(offset, size)
            result = struct.unpack(f"{prefix}{fmt_char}", raw)[0]
            if isinstance(result, int):
                return result
            return int(result)
        raw = self._data.read(offset, size)
        byteorder = "little" if self._endian == "little" else "big"
        return int.from_bytes(raw, byteorder=byteorder, signed=False)
