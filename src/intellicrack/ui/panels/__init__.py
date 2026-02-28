# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""UI panels for Intellicrack analysis displays.

This module provides specialized panels for licensing analysis,
stack viewing, script management, Frida instrumentation, process
management, binary hex viewing, sandbox control, and native tool
panels (Ghidra, x64dbg, radare2) within the main application.
"""

from __future__ import annotations

from intellicrack.ui.panels.binary_panel import BinaryPanel
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.licensing_panel import LicensingAnalysisPanel
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.radare2_panel import Radare2Panel
from intellicrack.ui.panels.sandbox_panel import SandboxPanel
from intellicrack.ui.panels.script_manager import ScriptManagerPanel, ScriptTypeInfo
from intellicrack.ui.panels.stack_viewer import (
    FridaStackSource,
    StackFrame,
    StackViewerPanel,
    X64DbgStackSource,
)
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


__all__ = [
    "BinaryPanel",
    "FridaPanel",
    "FridaStackSource",
    "GhidraPanel",
    "LicensingAnalysisPanel",
    "ProcessPanel",
    "Radare2Panel",
    "SandboxPanel",
    "ScriptManagerPanel",
    "ScriptTypeInfo",
    "StackFrame",
    "StackViewerPanel",
    "X64DbgPanel",
    "X64DbgStackSource",
]
