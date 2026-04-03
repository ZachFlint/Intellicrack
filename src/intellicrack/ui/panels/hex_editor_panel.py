# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Backward-compatible re-export of HexEditorPanel.

The implementation has moved to the hex_editor package.
"""

from __future__ import annotations

from intellicrack.ui.panels.hex_editor import HexEditorPanel


__all__: list[str] = ["HexEditorPanel"]
