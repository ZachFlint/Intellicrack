# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for the per-tool custom install-path override.

The Tool Settings GUI writes a per-tool ``"path"`` into
``.intellicrack/tools.json``. These tests exercise the real
``ToolInstaller.find_tool_detailed`` search against a real filesystem and
prove that a configured install path is honoured before the built-in
common-path / PATH / tools-directory search, and that removing the
configured path makes the same lookup stop resolving from that location.

The only boundary substitution is redirecting
``intellicrack.bridges.installer.get_config_file`` to a temporary
``.intellicrack`` directory (the same symbol production reads through); the
function under test, ``find_tool_detailed``, runs unmodified against real
files on disk.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import FoundTool, ToolInstaller
from intellicrack.core.types import ToolName


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


_TIMEOUT_SECONDS = 60


def _make_x64dbg_install(root: Path) -> Path:
    """Create a real x64dbg install tree with correctly-named executables.

    Mirrors the layout the registry expects for ``ToolName.X64DBG``:
    ``release/x64/x64dbg.exe`` and ``release/x32/x32dbg.exe``.

    Args:
        root: Directory under which the install tree is created.

    Returns:
        Path: The install directory (``root``) containing the executables.
    """
    x64_dir = root / "release" / "x64"
    x32_dir = root / "release" / "x32"
    x64_dir.mkdir(parents=True, exist_ok=True)
    x32_dir.mkdir(parents=True, exist_ok=True)
    (x64_dir / "x64dbg.exe").write_bytes(b"MZ\x00\x00real-x64dbg")
    (x32_dir / "x32dbg.exe").write_bytes(b"MZ\x00\x00real-x32dbg")
    return root


def _write_tools_json(config_dir: Path, entries: dict[str, dict[str, object]]) -> Path:
    """Write a ``tools.json`` in the same shape the GUI persists.

    Args:
        config_dir: The ``.intellicrack`` directory receiving the file.
        entries: Mapping of tool id to its persisted settings dict.

    Returns:
        Path: Path to the written ``tools.json`` file.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "tools.json"
    with config_file.open("w", encoding="utf-8") as handle:
        json.dump(entries, handle, indent=2)
    return config_file


def _redirect_config_dir(monkeypatch: pytest.MonkeyPatch, config_dir: Path) -> None:
    """Point ``installer.get_config_file`` at a temporary ``.intellicrack`` dir.

    Uses the real symbol the production reader resolves through, so no part of
    ``find_tool_detailed`` or ``_read_configured_tool_path`` is mocked.

    Args:
        monkeypatch: pytest fixture used to install the redirect.
        config_dir: Temporary ``.intellicrack`` directory to resolve into.
    """

    def _fake_get_config_file(filename: str) -> Path:
        return config_dir / filename

    monkeypatch.setattr(installer_mod, "get_config_file", _fake_get_config_file)


def test_configured_path_resolves_before_builtin_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured x64dbg path is honoured and returned exactly.

    The install lives in a non-standard location that is neither a hardcoded
    common path nor under the installer's tools directory, so the only way the
    lookup can resolve it is via the configured-path override.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: pytest fixture used to redirect the config directory.
    """
    custom_dir = _make_x64dbg_install(tmp_path / "custom" / "MyDebuggers" / "x64dbg-portable")
    tools_directory = tmp_path / "empty_tools"
    config_dir = tmp_path / ".intellicrack"

    _write_tools_json(
        config_dir,
        {
            "x64dbg": {
                "enabled": True,
                "path": str(custom_dir),
                "auto_install": False,
                "startup_timeout_seconds": _TIMEOUT_SECONDS,
            },
        },
    )
    _redirect_config_dir(monkeypatch, config_dir)

    installer = ToolInstaller(tools_directory)
    found = asyncio.run(installer.find_tool_detailed(ToolName.X64DBG))

    assert isinstance(found, FoundTool)
    assert found.kind == "filesystem"
    assert found.path == custom_dir

    path_only = asyncio.run(installer.find_tool(ToolName.X64DBG))
    assert path_only == custom_dir


def test_configured_path_missing_executable_falls_through(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured path without the expected executable does not resolve.

    Points the override at a directory that exists but lacks
    ``release/x64/x64dbg.exe`` / ``release/x32/x32dbg.exe``. The override must
    be skipped and the lookup must not report the empty configured directory.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: pytest fixture used to redirect the config directory.
    """
    empty_configured = tmp_path / "custom" / "not-really-x64dbg"
    empty_configured.mkdir(parents=True, exist_ok=True)
    tools_directory = tmp_path / "empty_tools"
    config_dir = tmp_path / ".intellicrack"

    _write_tools_json(
        config_dir,
        {
            "x64dbg": {
                "enabled": True,
                "path": str(empty_configured),
                "auto_install": False,
                "startup_timeout_seconds": _TIMEOUT_SECONDS,
            },
        },
    )
    _redirect_config_dir(monkeypatch, config_dir)

    installer = ToolInstaller(tools_directory)
    found = asyncio.run(installer.find_tool_detailed(ToolName.X64DBG))

    assert found is None or found.path != empty_configured


def test_without_configured_path_does_not_resolve_custom_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative anchor: the custom location is invisible without the override.

    The real x64dbg tree exists in the same non-standard location as the
    positive test, but ``tools.json`` carries no path for x64dbg. The built-in
    search (common paths, PATH, tools directory) has no reason to reach the
    custom location, proving the configured-path branch is what did the work in
    the positive test.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: pytest fixture used to redirect the config directory.
    """
    custom_dir = _make_x64dbg_install(tmp_path / "custom" / "MyDebuggers" / "x64dbg-portable")
    tools_directory = tmp_path / "empty_tools"
    config_dir = tmp_path / ".intellicrack"

    _write_tools_json(
        config_dir,
        {
            "x64dbg": {
                "enabled": True,
                "path": "",
                "auto_install": False,
                "startup_timeout_seconds": _TIMEOUT_SECONDS,
            },
        },
    )
    _redirect_config_dir(monkeypatch, config_dir)

    installer = ToolInstaller(tools_directory)
    found = asyncio.run(installer.find_tool_detailed(ToolName.X64DBG))

    assert found is None or found.path != custom_dir
