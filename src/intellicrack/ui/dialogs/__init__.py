# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Dialog components for Intellicrack UI.

This package provides dialog widgets including the splash screen and other modal dialogs.
"""

from __future__ import annotations

from .splash_screen import SplashScreen


__all__: list[str] = [
    "SplashScreen",
]
