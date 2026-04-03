# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Error types for the HexPat pattern language interpreter pipeline."""

from __future__ import annotations


class HexPatError(Exception):
    """Base error for the HexPat interpreter.

    Args:
        message: Human-readable error description.
        line: Source line number where the error occurred.
        column: Source column number where the error occurred.
        file: Source file path where the error occurred.
    """

    def __init__(
        self,
        message: str,
        line: int = 0,
        column: int = 0,
        file: str = "",
    ) -> None:
        self.message: str = message
        self.line: int = line
        self.column: int = column
        self.file: str = file
        location_parts: list[str] = []
        if file:
            location_parts.append(file)
        if line > 0:
            location_parts.append(str(line))
            if column > 0:
                location_parts.append(str(column))
        location: str = ":".join(location_parts)
        super().__init__(f"{location}: {message}" if location else message)


class HexPatPreprocessorError(HexPatError):
    """Error during preprocessing (#include, #define, #pragma)."""


class HexPatParseError(HexPatError):
    """Error during parsing (syntax errors)."""


class HexPatTypeError(HexPatError):
    """Error during type resolution."""


class HexPatRuntimeError(HexPatError):
    """Error during pattern evaluation against binary data.

    Args:
        message: Human-readable error description.
        line: Source line number where the error occurred.
        column: Source column number where the error occurred.
        file: Source file path where the error occurred.
        offset: Byte offset in the binary data.
    """

    def __init__(
        self,
        message: str,
        line: int = 0,
        column: int = 0,
        file: str = "",
        offset: int = 0,
    ) -> None:
        self.offset: int = offset
        if offset > 0:
            message = f"{message} (at data offset 0x{offset:X})"
        super().__init__(message, line, column, file)
