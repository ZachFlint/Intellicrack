# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tool bridges for external reverse engineering tools.

This package provides bridge interfaces for controlling external tools
including Ghidra, x64dbg, Frida, Cutter/Rizin, and direct binary/process
manipulation.

Heavy bridge submodules (each pulling in optional dependencies such as
``frida``, ``r2pipe``, ``ghidra-bridge``, the Win32 ctypes layer, or the
``hexcore`` Rust extension) are loaded lazily through PEP 562
``__getattr__``. Cheap symbols from :mod:`intellicrack.bridges.base`
remain eagerly imported because every dependent module needs them and
they have no transitive imports beyond the standard library.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

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


_LAZY_EXPORTS: Final[dict[str, tuple[str, str]]] = {
    "CutterBridge": ("intellicrack.bridges.cutter", "CutterBridge"),
    "FridaBridge": ("intellicrack.bridges.frida_bridge", "FridaBridge"),
    "GhidraBridge": ("intellicrack.bridges.ghidra", "GhidraBridge"),
    "HexEditorBridge": ("intellicrack.bridges.hex_editor", "HexEditorBridge"),
    "ProcessBridge": ("intellicrack.bridges.process", "ProcessBridge"),
    "SandboxBridge": ("intellicrack.bridges.sandbox_bridge", "SandboxBridge"),
    "ToolInstaller": ("intellicrack.bridges.installer", "ToolInstaller"),
    "X64DbgBridge": ("intellicrack.bridges.x64dbg", "X64DbgBridge"),
}


def __getattr__(name: str) -> type[ToolBridgeBase | ToolInstaller]:
    """Lazily import heavy bridge submodules on first attribute access.

    Implements PEP 562 module-level ``__getattr__`` so that importing
    ``intellicrack.bridges`` does not transitively load
    :mod:`frida`, :mod:`r2pipe`, the Win32 ``ctypes`` layer, or the
    Rust ``hexcore`` extension. Each lazy class is resolved through
    :data:`_LAZY_EXPORTS` and cached on the package module so future
    look-ups bypass this hook.

    Args:
        name: Attribute name being requested from the package.

    Returns:
        type[ToolBridgeBase | ToolInstaller]: The resolved bridge or
            installer class.

    Raises:
        AttributeError: If ``name`` is not in :data:`_LAZY_EXPORTS`.
    """
    if name in _LAZY_EXPORTS:
        module_path, attr_name = _LAZY_EXPORTS[name]
        import importlib

        module = importlib.import_module(module_path)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    msg = f"module 'intellicrack.bridges' has no attribute {name!r}"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """Return module attributes including the lazy exports.

    Returns:
        list[str]: Sorted list of public attributes plus lazy exports.
    """
    return sorted(set(__all__) | set(globals()))
