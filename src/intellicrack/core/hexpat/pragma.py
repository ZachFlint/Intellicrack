# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
# This file is part of Intellicrack. See LICENSE for details.
"""Shared PragmaInfo dataclass for the HexPat interpreter pipeline."""

from __future__ import annotations

from dataclasses import dataclass


DEFAULT_EVAL_DEPTH: int = 512
"""Default maximum recursion depth for pattern evaluation.

Empirical tooling experience with common .hexpat patterns from the upstream vendor pattern collection shows that ``parent``-relative and
mutually-recursive struct definitions routinely exceed a depth of 32 (the upstream default). For example, ``tiff.hexpat`` explicitly bumps
the limit to 100 and several others configure it well into the thousands. A default of 512 leaves ample headroom for real-world patterns
while still terminating accidental unbounded recursion in finite time. Patterns that need a different limit can override it by adding
``#pragma eval_depth <n>`` to the source.
"""

DEFAULT_ARRAY_LIMIT: int = 0x10000
"""Default maximum number of elements in any single array."""

DEFAULT_PATTERN_LIMIT: int = 0x40000
"""Default maximum total number of placed patterns."""

DEFAULT_POINTER_SIZE: int = 8
"""Default pointer size in bytes (8 = 64-bit target)."""


@dataclass(frozen=True)
class PragmaInfo:
    """Collected #pragma directives from a .hexpat source file.

    Attributes:
        endian: Default byte order — ``"little"``, ``"big"``, or None.
        mime: Expected MIME type of the target binary, or None.
        magic: Sequence of (offset, bytes) magic byte checks.
        base_address: Base address added to all data offsets.
        eval_depth: Maximum recursion depth for pattern evaluation. Defaults to
            :data:`DEFAULT_EVAL_DEPTH` which is calibrated to handle common
            ``parent``-relative and recursive patterns without aborting.
        array_limit: Maximum number of elements in any single array.
        pattern_limit: Maximum total number of patterns placed.
        author: Author name from the pragma, or None.
        description: Description from the pragma, or None.
        pointer_size: Size of a pointer in bytes (4 for 32-bit, 8 for 64-bit).
        bitfield_order: Bitfield bit ordering — ``"left_to_right"`` or
            ``"right_to_left"``, or None for the default.
    """

    endian: str | None = None
    mime: str | None = None
    magic: tuple[tuple[int, bytes], ...] = ()
    base_address: int = 0
    eval_depth: int = DEFAULT_EVAL_DEPTH
    array_limit: int = DEFAULT_ARRAY_LIMIT
    pattern_limit: int = DEFAULT_PATTERN_LIMIT
    author: str | None = None
    description: str | None = None
    pointer_size: int = DEFAULT_POINTER_SIZE
    bitfield_order: str | None = None
