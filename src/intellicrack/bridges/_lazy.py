# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Lazy import wiring for the :mod:`intellicrack.bridges` package.

Implements PEP 562 module-level ``__getattr__`` so that importing ``intellicrack.bridges`` does not transitively load heavy bridge
submodules (each pulling in optional dependencies such as :mod:`frida`, :mod:`r2pipe`, the Win32 ``ctypes`` layer, or the Rust ``hexcore``
extension). Each lazy class is resolved through :data:`LAZY_EXPORTS` and cached on the package module so future look-ups bypass this hook.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Final, cast

from intellicrack.bridges.base import ToolBridgeBase


if TYPE_CHECKING:
    from intellicrack.bridges.installer import ToolInstaller


LAZY_EXPORTS: Final[dict[str, tuple[str, str]]] = {
    "CutterBridge": ("intellicrack.bridges.cutter", "CutterBridge"),
    "FridaBridge": ("intellicrack.bridges.frida_bridge", "FridaBridge"),
    "GhidraBridge": ("intellicrack.bridges.ghidra", "GhidraBridge"),
    "HexEditorBridge": ("intellicrack.bridges.hex_editor", "HexEditorBridge"),
    "ProcessBridge": ("intellicrack.bridges.process", "ProcessBridge"),
    "SandboxBridge": ("intellicrack.bridges.sandbox_bridge", "SandboxBridge"),
    "ToolInstaller": ("intellicrack.bridges.installer", "ToolInstaller"),
    "X64DbgBridge": ("intellicrack.bridges.x64dbg", "X64DbgBridge"),
}


def resolve(name: str, package_globals: dict[str, object]) -> type[ToolBridgeBase | ToolInstaller]:
    """Resolve a lazy export by name and cache it on the package globals.

    Args:
        name: Attribute name being requested from
            :mod:`intellicrack.bridges`.
        package_globals: The ``globals()`` dict of the calling package
            module; the resolved class is cached here so subsequent
            attribute look-ups bypass ``__getattr__`` entirely.

    Returns:
        type[ToolBridgeBase | ToolInstaller]: The resolved bridge or
        installer class.

    Raises:
        AttributeError: If ``name`` is not in :data:`LAZY_EXPORTS`.
        TypeError: If the resolved attribute is not a class compatible
            with :class:`ToolBridgeBase` or :class:`ToolInstaller`.
    """
    if name not in LAZY_EXPORTS:
        msg = f"module 'intellicrack.bridges' has no attribute {name!r}"
        raise AttributeError(msg)
    module_path, attr_name = LAZY_EXPORTS[name]
    module = importlib.import_module(module_path)
    raw_value: object = getattr(module, attr_name)
    is_bridge = isinstance(raw_value, type) and issubclass(raw_value, ToolBridgeBase)
    is_installer = isinstance(raw_value, type) and attr_name == "ToolInstaller"
    if not (is_bridge or is_installer):
        msg = f"lazy export {name!r} from {module_path!r} is not a bridge or installer class"
        raise TypeError(msg)
    value = cast("type[ToolBridgeBase | ToolInstaller]", raw_value)
    package_globals[name] = value
    return value
