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
        """Initialize the HexPatError with location and message details.

        Args:
            message: Human-readable error description.
            line: Source line number where the error occurred.
            column: Source column number where the error occurred.
            file: Source file path where the error occurred.
        """
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
    """Error during parsing (syntax errors).

    Args:
        message: Human-readable error description.
        line: Source line number where the error occurred (start line).
        column: Source column number where the error occurred (start column).
        file: Source file path where the error occurred.
        end_line: Optional end line number for the error span.
        end_column: Optional end column number for the error span.
    """

    def __init__(
        self,
        message: str,
        line: int = 0,
        column: int = 0,
        file: str = "",
        end_line: int | None = None,
        end_column: int | None = None,
    ) -> None:
        """Initialize the HexPatParseError with location, message, and optional span.

        Args:
            message: Human-readable error description.
            line: Source line number where the error occurred (start line).
            column: Source column number where the error occurred (start column).
            file: Source file path where the error occurred.
            end_line: Optional end line number for the error span.
            end_column: Optional end column number for the error span.
        """
        self.end_line: int | None = end_line
        self.end_column: int | None = end_column
        if end_line is not None and end_column is not None and line > 0 and column > 0:
            message = f"{message} [span {line}:{column}-{end_line}:{end_column}]"
        super().__init__(message, line, column, file)

    @property
    def span(self) -> tuple[int, int, int, int] | None:
        """Return the full source span as a tuple if available.

        Returns:
            A tuple ``(line, column, end_line, end_column)`` when both start
            and end positions are known, otherwise ``None``.
        """
        if self.end_line is not None and self.end_column is not None and self.line > 0 and self.column > 0:
            return (self.line, self.column, self.end_line, self.end_column)
        return None


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
        end_offset: Optional end byte offset for the error data span.
    """

    def __init__(
        self,
        message: str,
        line: int = 0,
        column: int = 0,
        file: str = "",
        offset: int = 0,
        end_offset: int | None = None,
    ) -> None:
        """Initialize the HexPatRuntimeError with location, message, and data span.

        Args:
            message: Human-readable error description.
            line: Source line number where the error occurred.
            column: Source column number where the error occurred.
            file: Source file path where the error occurred.
            offset: Byte offset in the binary data.
            end_offset: Optional end byte offset for the error data span.
        """
        self.offset: int = offset
        self.end_offset: int | None = end_offset
        if offset > 0:
            if end_offset is not None and end_offset > offset:
                message = f"{message} (at data offset 0x{offset:X}-0x{end_offset:X})"
            else:
                message = f"{message} (at data offset 0x{offset:X})"
        super().__init__(message, line, column, file)

    @property
    def data_span(self) -> tuple[int, int] | None:
        """Return the byte range for the runtime error if available.

        Returns:
            A tuple ``(offset, end_offset)`` when both start and end byte
            offsets are known, otherwise ``None``.
        """
        if self.end_offset is not None and self.offset > 0 and self.end_offset > self.offset:
            return (self.offset, self.end_offset)
        return None
