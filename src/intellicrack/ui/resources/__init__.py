# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Resource management modules for Intellicrack UI.

This package provides asset loading, icon management, font handling,
and theme management for the Intellicrack application.
"""

from __future__ import annotations

from .font_manager import FontManager
from .icon_manager import IconManager
from .resource_helper import get_assets_path, get_resource_path
from .theme_manager import ThemeManager


__all__: list[str] = [
    "FontManager",
    "IconManager",
    "ThemeManager",
    "get_assets_path",
    "get_resource_path",
]
