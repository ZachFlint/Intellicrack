# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool bridges for external reverse engineering tools.

This package provides bridge interfaces for controlling external tools
including Ghidra, x64dbg, Frida, Cutter/Rizin, and direct binary/process
manipulation.

Heavy bridge submodules are loaded lazily through PEP 562
``__getattr__`` -- the wiring lives in :mod:`intellicrack.bridges.lazy`
to keep this ``__init__`` focused on docstrings and re-exports. Cheap
symbols from :mod:`intellicrack.bridges.base` remain eagerly imported
because every dependent module needs them and they have no transitive
imports beyond the standard library.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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
from intellicrack.bridges.lazy import resolve as _resolve_lazy


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge
    from intellicrack.bridges.frida_bridge import FridaBridge
    from intellicrack.bridges.ghidra import GhidraBridge
    from intellicrack.bridges.hex_editor import HexEditorBridge
    from intellicrack.bridges.installer import ToolInstaller
    from intellicrack.bridges.process import ProcessBridge
    from intellicrack.bridges.sandbox_bridge import SandboxBridge
    from intellicrack.bridges.x64dbg import X64DbgBridge

__all__: list[str] = [
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


def __getattr__(name: str) -> type[ToolBridgeBase | ToolInstaller]:
    """Resolve a lazy export from :data:`intellicrack.bridges.lazy.LAZY_EXPORTS`.

    Delegates to :func:`intellicrack.bridges.lazy.resolve`, which
    raises ``AttributeError`` for unregistered names.

    Args:
        name: Attribute name being requested from the package.

    Returns:
        type[ToolBridgeBase | ToolInstaller]: The resolved bridge or
            installer class.
    """
    return _resolve_lazy(name, globals())


def __dir__() -> list[str]:
    """Return the package's public attributes including lazy exports.

    Returns:
        list[str]: Sorted list of public attributes plus lazy exports.
    """
    return sorted(set(__all__) | set(globals()))
