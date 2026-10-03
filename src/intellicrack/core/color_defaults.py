# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Default colours shared by the non-UI layers and the UI theme system.

The hex-editor bridge and the HexPat evaluator hand colours to callers as plain ``#RRGGBB`` strings: bookmark and highlight defaults that are
part of the tool schema, structure-bookmark colours returned in bridge responses, the colour rotation for parsed pattern fields, and the
palette of the exported HTML hex dump. Those layers must not import Qt or the UI package, so their defaults live here, in one module with no
imports beyond the standard library. :class:`~intellicrack.ui.resources.theme_manager.ThemeManager` reads the same constants for the dark
theme's hex-mark entries, so the bridge contract and the themed UI defaults cannot drift apart.

Every value here is a contract: tool definitions advertise them, bridge responses carry them, and saved bookmarks persist them. Changing one
changes what tools and sessions observe.
"""

from __future__ import annotations

from typing import Final


DEFAULT_BOOKMARK_COLOR: Final[str] = "#FFFF00"
"""Colour given to a bookmark when the caller does not choose one."""

DEFAULT_HIGHLIGHT_COLOR: Final[str] = "#FFFF00"
"""Colour given to a byte highlight rule when the caller does not choose one."""

STRUCTURE_HEADER_COLOR: Final[str] = "#FF6B6B"
"""Colour of the leading file header bookmark (DOS, ELF, Mach-O)."""

STRUCTURE_TABLE_COLOR: Final[str] = "#4ECDC4"
"""Colour of header tables that follow the file header (PE/COFF headers, program headers, load commands)."""

STRUCTURE_SECTION_COLOR: Final[str] = "#45B7D1"
"""Colour of section-level structures (optional header, section headers)."""

STRUCTURE_SECTION_ALT_COLOR: Final[str] = "#96CEB4"
"""Second section colour, used for individual PE section entries."""

STRUCTURE_COLORS: Final[tuple[str, str, str]] = (
    STRUCTURE_HEADER_COLOR,
    STRUCTURE_TABLE_COLOR,
    STRUCTURE_SECTION_COLOR,
)
"""Header, table and section colours in the order the structure bookmarkers index them."""

PE_STRUCTURE_COLORS: Final[tuple[str, str, str, str]] = (
    STRUCTURE_HEADER_COLOR,
    STRUCTURE_TABLE_COLOR,
    STRUCTURE_SECTION_COLOR,
    STRUCTURE_SECTION_ALT_COLOR,
)
"""DOS header, signature/COFF, optional header and section colours for PE files."""

SECTION_CYCLE_COLORS: Final[tuple[str, ...]] = (
    STRUCTURE_SECTION_COLOR,
    STRUCTURE_SECTION_ALT_COLOR,
    "#FFEAA7",
    "#DDA0DD",
    "#98D8C8",
)
"""Rotation used when each section of a file gets its own bookmark colour."""

UNSAFE_COLOR_FALLBACK: Final[str] = "#888888"
"""Neutral colour substituted for a bookmark colour that is not a plain ``#RRGGBB`` / ``#RRGGBBAA`` value."""

HTML_EXPORT_BACKGROUND: Final[str] = "#1e1e2e"
"""Page background of the exported HTML hex dump."""

HTML_EXPORT_TEXT: Final[str] = "#cdd6f4"
"""Body and hex-column text colour of the exported HTML hex dump."""

HTML_EXPORT_OFFSET: Final[str] = "#89b4fa"
"""Offset-column text colour of the exported HTML hex dump."""

HTML_EXPORT_ASCII: Final[str] = "#a6e3a1"
"""ASCII-column text colour of the exported HTML hex dump."""

HEXPAT_FIELD_COLORS: Final[tuple[str, ...]] = (
    "#E06C75",
    "#61AFEF",
    "#98C379",
    "#E5C07B",
    "#C678DD",
    "#56B6C2",
    "#BE5046",
    "#D19A66",
    "#7EC8E3",
    "#C3E88D",
)
"""Rotation the HexPat evaluator assigns to parsed pattern fields that declare no colour of their own."""
