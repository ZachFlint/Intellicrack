# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""UI panels for Intellicrack analysis displays.

This module provides specialized panels for bridge analysis,
stack viewing, script management, Frida instrumentation, process
management, binary hex viewing, sandbox control, and native tool
panels (Ghidra, x64dbg, Cutter) within the main application.
"""

from __future__ import annotations

from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.binary_panel import BinaryPanel
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.hxd_panel import HxDPanel
from intellicrack.ui.panels.process_panel import ProcessPanel
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
    "AnalysisPanelBase",
    "BinaryPanel",
    "BridgeAnalysisPanel",
    "CutterPanel",
    "FridaPanel",
    "FridaStackSource",
    "GhidraPanel",
    "HxDPanel",
    "ProcessPanel",
    "SandboxPanel",
    "ScriptManagerPanel",
    "ScriptTypeInfo",
    "StackFrame",
    "StackViewerPanel",
    "X64DbgPanel",
    "X64DbgStackSource",
]
