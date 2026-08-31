# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared text-mode hex-dump formatter for UI panels.

Provides a single canonical implementation of the 16-byte-per-line hex plus ASCII dump rendering used by the Frida and x64dbg panels for
their console-style memory readouts. The richer ``HexEditorWidget`` QPainter renderer is intentionally untouched because it operates on a
different domain (live widget painting rather than plain-text output).
"""

from __future__ import annotations

from typing import Final


_BYTES_PER_LINE: Final[int] = 16
_HEX_FIELD_WIDTH: Final[int] = 48
_PRINTABLE_LOW: Final[int] = 32
_PRINTABLE_HIGH: Final[int] = 127


def format_hex_dump(data: bytes, base_address: int, *, address_prefix: str = "") -> str:
    """Format raw bytes as a 16-byte-per-line hex+ASCII dump.

    Each line contains the absolute address followed by up to sixteen
    hexadecimal byte values and the printable-ASCII representation of
    that chunk. Bytes outside the ``[0x20, 0x7F)`` printable range are
    shown as ``.``.

    Args:
        data: Raw bytes to render.
        base_address: Address corresponding to ``data[0]``; subsequent
            line addresses are computed as ``base_address + offset``.
        address_prefix: Optional prefix prepended to each address column
            (for example ``"0x"``). Defaults to an empty string.

    Returns:
        str: The formatted hex dump joined by newlines. Returns an empty
        string when ``data`` is empty.
    """
    lines: list[str] = []
    for offset in range(0, len(data), _BYTES_PER_LINE):
        chunk = data[offset : offset + _BYTES_PER_LINE]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if _PRINTABLE_LOW <= b < _PRINTABLE_HIGH else "." for b in chunk)
        addr = base_address + offset
        lines.append(f"{address_prefix}{addr:08X}  {hex_part:<{_HEX_FIELD_WIDTH}s}  {ascii_part}")
    return "\n".join(lines)
