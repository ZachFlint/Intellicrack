# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""HexPat .hexpat pattern language interpreter package.

Provides a full interpreter for HexPat's pattern language that executes .hexpat files against binary data and outputs ParsedField-compatible
dicts for display in the hex editor template tree.
"""

from __future__ import annotations

from intellicrack.core.hexpat.errors import HexPatError, HexPatRuntimeError
from intellicrack.core.hexpat.interpreter import HexPatInterpreter
from intellicrack.core.hexpat.pattern_registry import PatternMetadata, PatternRegistry


__all__: list[str] = [
    "HexPatError",
    "HexPatInterpreter",
    "HexPatRuntimeError",
    "PatternMetadata",
    "PatternRegistry",
]
