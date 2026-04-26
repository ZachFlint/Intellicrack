# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the shared text-mode hex-dump formatter.

Exercises ``intellicrack.ui.format_hex_dump`` against real byte
sequences to validate addressing, padding, ASCII filtering, and the
optional address prefix used by the x64dbg console output.
"""

from __future__ import annotations

from intellicrack.ui import format_hex_dump


_BYTES_PER_LINE: int = 16


class TestFormatHexDumpBasic:
    """Tests covering the canonical 16-byte-per-line layout."""

    @staticmethod
    def test_empty_input_returns_empty_string() -> None:
        """Empty data yields an empty string with no trailing newline."""
        result = format_hex_dump(b"", 0)
        assert isinstance(result, str)
        assert len(result) == 0

    @staticmethod
    def test_empty_input_with_prefix_returns_empty_string() -> None:
        """Empty data ignores the prefix and returns an empty string."""
        result = format_hex_dump(b"", 0, address_prefix="0x")
        assert isinstance(result, str)
        assert len(result) == 0

    @staticmethod
    def test_single_byte_layout() -> None:
        """A one-byte buffer renders one line with proper padding."""
        result = format_hex_dump(b"A", 0)
        assert result == "00000000  41                                                A"

    @staticmethod
    def test_full_line_layout() -> None:
        """Sixteen bytes produce exactly one fully populated row."""
        data = bytes(range(0x20, 0x30))
        result = format_hex_dump(data, 0x1000)
        expected_hex = " ".join(f"{b:02X}" for b in data)
        expected_ascii = " !\"#$%&'()*+,-./"
        expected = f"00001000  {expected_hex:<48s}  {expected_ascii}"
        assert result == expected

    @staticmethod
    def test_two_lines_layout() -> None:
        """Seventeen bytes wrap to two lines with the correct address bump."""
        data = bytes(range(17))
        lines = format_hex_dump(data, 0).splitlines()
        assert len(lines) == 2
        assert lines[0].startswith("00000000  ")
        assert lines[1].startswith(f"{_BYTES_PER_LINE:08X}  ")


class TestFormatHexDumpAsciiFiltering:
    """Tests covering the printable-ASCII filter."""

    _ASCII_COL_OFFSET: int = len("00000000") + len("  ") + 48 + len("  ")

    @classmethod
    def _ascii_column(cls, line: str) -> str:
        """Extract the ASCII column from a single hex-dump line.

        Args:
            line: One rendered hex-dump line.

        Returns:
            str: The ASCII representation column.
        """
        return line[cls._ASCII_COL_OFFSET :]

    @classmethod
    def test_non_printable_low_bytes_become_dot(cls) -> None:
        """Bytes below 0x20 render as '.' in the ASCII column."""
        result = format_hex_dump(bytes(range(8)), 0)
        assert cls._ascii_column(result) == "........"

    @classmethod
    def test_del_byte_is_filtered(cls) -> None:
        """0x7F (DEL) is treated as non-printable and rendered as '.'."""
        result = format_hex_dump(b"\x7e\x7f", 0)
        assert cls._ascii_column(result) == "~."

    @classmethod
    def test_high_bit_bytes_become_dot(cls) -> None:
        """Bytes >= 0x80 render as '.' in the ASCII column."""
        result = format_hex_dump(bytes([0x80, 0xFF, ord("Z")]), 0)
        assert cls._ascii_column(result) == "..Z"

    @classmethod
    def test_space_is_printable(cls) -> None:
        """0x20 (space) renders as a literal space, not a dot."""
        result = format_hex_dump(b" ", 0)
        assert cls._ascii_column(result) == " "


class TestFormatHexDumpAddressing:
    """Tests covering the address column rendering."""

    @staticmethod
    def test_default_has_no_prefix() -> None:
        """The default rendering matches the Frida panel format (no '0x')."""
        line = format_hex_dump(b"\x00", 0xDEADBEEF)
        assert line.startswith("DEADBEEF  ")

    @staticmethod
    def test_address_prefix_is_emitted() -> None:
        """When ``address_prefix='0x'`` each line starts with '0x'."""
        line = format_hex_dump(b"\x00", 0x401000, address_prefix="0x")
        assert line.startswith("0x00401000  ")

    @staticmethod
    def test_address_advances_per_line() -> None:
        """Each subsequent line increases the address by 16."""
        data = bytes(48)
        lines = format_hex_dump(data, 0x100, address_prefix="0x").splitlines()
        assert lines[0].startswith("0x00000100  ")
        assert lines[1].startswith("0x00000110  ")
        assert lines[2].startswith("0x00000120  ")

    @staticmethod
    def test_arbitrary_prefix_is_passed_through() -> None:
        """The helper does not constrain the prefix to '0x'."""
        line = format_hex_dump(b"\x00", 0, address_prefix=">> ")
        assert line.startswith(">> 00000000  ")


class TestFormatHexDumpPadding:
    """Tests covering hex-column padding for trailing partial chunks."""

    @staticmethod
    def test_partial_last_line_pads_hex_column() -> None:
        """A trailing chunk shorter than 16 bytes pads the hex column to 48 chars."""
        data = b"AB"
        line = format_hex_dump(data, 0)
        hex_col = line[len("00000000  ") : len("00000000  ") + 48]
        assert hex_col == "41 42" + " " * (48 - len("41 42"))
