# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Process management panel package for Intellicrack.

Provides a comprehensive process inspection and manipulation panel with bridge integration for all Win32 process capabilities.
"""

from __future__ import annotations

from intellicrack.ui.panels.process_panel.base import ProcessPanel


__all__: list[str] = ["ProcessPanel"]
