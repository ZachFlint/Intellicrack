# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate: x64dbg detection must resolve to the installation root.

A real x64dbg snapshot ships its debugger binaries under
``release/x64/x64dbg.exe`` and ``release/x32/x32dbg.exe`` - never at the
installation root. :class:`~intellicrack.bridges.x64dbg.X64DbgBridge`
initialises from the installation *root* (the directory that contains
``release/``) because it computes ``root / "release" / "x64" / "x64dbg.exe"``.

Previously ``TOOL_REGISTRY[X64DBG].executables`` listed bare
``["x64dbg.exe", "x96dbg.exe"]``. The ``common_paths`` probe therefore looked
for ``<root>/x64dbg.exe`` (which never exists in a real install) and the
nested tools-directory search matched ``release/x96dbg.exe`` and returned the
``release/`` sub-directory - one level too deep. Feeding that path to the
bridge produced ``release/release/x64/x64dbg.exe`` (missing), so the bridge
never connected, never deployed its plugin, and every ``load`` raised
"x64dbg bridge plugin not deployed ... installation not configured".

These tests build a realistic install tree and assert the finder returns the
root and the bridge connects from it. They fail on the pre-fix registry entry.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from intellicrack.bridges.installer import TOOL_REGISTRY, FoundTool, ToolInstaller
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolName


if TYPE_CHECKING:
    from pathlib import Path


def _make_x64dbg_install(root: Path) -> Path:
    """Create a realistic x64dbg snapshot layout under ``root``.

    Mirrors an extracted x64dbg release: the launcher lives at
    ``release/x96dbg.exe`` while the actual debuggers live at
    ``release/x64/x64dbg.exe`` and ``release/x32/x32dbg.exe``.

    Args:
        root: Directory to populate as an x64dbg installation root.

    Returns:
        Path: The same ``root``, now containing the ``release/`` tree.
    """
    x64 = root / "release" / "x64"
    x32 = root / "release" / "x32"
    x64.mkdir(parents=True)
    x32.mkdir(parents=True)
    (x64 / "x64dbg.exe").write_bytes(b"MZ")
    (x32 / "x32dbg.exe").write_bytes(b"MZ")
    (root / "release" / "x96dbg.exe").write_bytes(b"MZ")
    return root


class TestX64dbgInstallRootDetection:
    """The finder must return the install root, not the ``release/`` sub-dir."""

    @staticmethod
    def test_registry_executables_reflect_real_nested_layout() -> None:
        """Every declared x64dbg executable resolves under the install root.

        A bare ``x64dbg.exe`` entry (the pre-fix value) does not exist at a real
        install root and is what broke ``common_paths`` detection.
        """
        info = TOOL_REGISTRY[ToolName.X64DBG]
        assert info.executables, "x64dbg must declare at least one executable"
        for exe in info.executables:
            assert "/" in exe or "\\" in exe, (
                f"x64dbg executable {exe!r} is bare; real debuggers live under "
                "release/x64 or release/x32, so a root-level name never matches"
            )
        assert any("x64dbg.exe" in exe for exe in info.executables)
        assert any("x32dbg.exe" in exe for exe in info.executables)

    @staticmethod
    def test_find_tool_returns_install_root_from_tools_dir(tmp_path: Path) -> None:
        """find_tool resolves the nested tools-dir install to its root.

        The bridge contract is ``root / release / x64 / x64dbg.exe`` must exist
        under the returned path. The pre-fix nested search returned the
        ``release/`` directory, making that join point at a missing file.

        Args:
            tmp_path: Pytest-provided temporary directory (the tools root).
        """
        install_root = _make_x64dbg_install(tmp_path / "x64dbg")

        installer = ToolInstaller(tmp_path)
        found = asyncio.run(installer.find_tool(ToolName.X64DBG))

        assert found is not None, "x64dbg install present but find_tool returned None"
        assert found == install_root, f"find_tool returned {found}, expected root {install_root}"
        assert (found / "release" / "x64" / "x64dbg.exe").is_file(), (
            "find_tool returned a path from which the bridge cannot locate x64dbg.exe"
        )

    @staticmethod
    def test_find_tool_detailed_reports_root_path(tmp_path: Path) -> None:
        """find_tool_detailed reports a filesystem FoundTool anchored at the root.

        Args:
            tmp_path: Pytest-provided temporary directory (the tools root).
        """
        install_root = _make_x64dbg_install(tmp_path / "x64dbg")

        installer = ToolInstaller(tmp_path)
        detailed = asyncio.run(installer.find_tool_detailed(ToolName.X64DBG))

        assert isinstance(detailed, FoundTool)
        assert detailed.kind == "filesystem"
        assert detailed.path == install_root

    @staticmethod
    def test_bridge_connects_from_finder_resolved_path(tmp_path: Path) -> None:
        """The finder's path drives the bridge to a connected state.

        This reproduces the reported failure end to end: resolve the install
        with the finder, hand the result to the bridge, and require the bridge
        to register the installation as present. With the pre-fix registry the
        finder yields ``release/`` and ``state.connected`` stays False.

        Args:
            tmp_path: Pytest-provided temporary directory (the tools root).
        """
        _make_x64dbg_install(tmp_path / "x64dbg")

        installer = ToolInstaller(tmp_path)
        resolved = asyncio.run(installer.find_tool(ToolName.X64DBG))
        assert resolved is not None

        bridge = X64DbgBridge()
        asyncio.run(bridge.initialize(resolved))

        assert bridge.x64dbg_path == resolved
        assert bridge.state.connected is True, (
            "bridge failed to recognise the x64dbg installation; the resolved path does not point at the installation root"
        )
