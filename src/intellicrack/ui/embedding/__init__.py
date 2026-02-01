"""Win32 window embedding infrastructure for external tools.

This module provides Win32 API wrappers and Qt widgets for embedding
external applications (HxD, x64dbg, Cutter, Ghidra, radare2) into
Intellicrack's UI.
"""

from __future__ import annotations

from intellicrack.ui.embedding.cutter_widget import CutterWidget
from intellicrack.ui.embedding.embedded_widget import EmbeddedToolWidget
from intellicrack.ui.embedding.ghidra_widget import GhidraWidget
from intellicrack.ui.embedding.hxd_widget import HxDIntegration, HxDWidget
from intellicrack.ui.embedding.radare2_widget import Radare2Widget
from intellicrack.ui.embedding.win32_helper import Win32WindowHelper
from intellicrack.ui.embedding.x64dbg_widget import X64DbgWidget


__all__ = [
    "CutterWidget",
    "EmbeddedToolWidget",
    "GhidraWidget",
    "HxDIntegration",
    "HxDWidget",
    "Radare2Widget",
    "Win32WindowHelper",
    "X64DbgWidget",
]
