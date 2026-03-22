# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.

"""Shared PragmaInfo dataclass for the HexPat interpreter pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PragmaInfo:
    """Collected #pragma directives from a .hexpat source file.

    Attributes:
        endian: Default byte order — ``"little"``, ``"big"``, or None.
        mime: Expected MIME type of the target binary, or None.
        magic: Sequence of (offset, bytes) magic byte checks.
        base_address: Base address added to all data offsets.
        eval_depth: Maximum recursion depth for pattern evaluation.
        array_limit: Maximum number of elements in any single array.
        pattern_limit: Maximum total number of patterns placed.
        author: Author name from the pragma, or None.
        description: Description from the pragma, or None.
    """

    endian: str | None = None
    mime: str | None = None
    magic: tuple[tuple[int, bytes], ...] = ()
    base_address: int = 0
    eval_depth: int = 32
    array_limit: int = 0x10000
    pattern_limit: int = 0x40000
    author: str | None = None
    description: str | None = None
