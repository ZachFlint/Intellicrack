# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool bridges for external reverse engineering tools.

This package provides bridge interfaces for controlling external tools including Ghidra, x64dbg, Frida, Cutter/Rizin, and direct
binary/process manipulation.
"""

from __future__ import annotations

from intellicrack.bridges.base import (
    BinaryOperationsBridge,
    BridgeCapabilities,
    BridgeState,
    DebuggerBridge,
    DisassemblyLine,
    DynamicAnalysisBridge,
    InstrumentationBridge,
    MemorySearchResult,
    StackFrame,
    StaticAnalysisBridge,
    ToolBridgeBase,
    WatchpointInfo,
)
from intellicrack.bridges.binary import BinaryBridge
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.installer import ToolInstaller
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.x64dbg import X64DbgBridge


__all__: list[str] = [
    "BinaryBridge",
    "BinaryOperationsBridge",
    "BridgeCapabilities",
    "BridgeState",
    "CutterBridge",
    "DebuggerBridge",
    "DisassemblyLine",
    "DynamicAnalysisBridge",
    "FridaBridge",
    "GhidraBridge",
    "HexEditorBridge",
    "InstrumentationBridge",
    "MemorySearchResult",
    "ProcessBridge",
    "SandboxBridge",
    "StackFrame",
    "StaticAnalysisBridge",
    "ToolBridgeBase",
    "ToolInstaller",
    "WatchpointInfo",
    "X64DbgBridge",
]
