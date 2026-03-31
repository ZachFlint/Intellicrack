# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for x64dbg plugin deployment utilities."""

from __future__ import annotations

import shutil
import time
from typing import TYPE_CHECKING

from intellicrack.bridges.installer import deploy_x64dbg_plugin


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


DUMMY_PE = b"\x4d\x5a" + b"\x00" * 62
DUMMY_PE_32 = b"\x4d\x5a" + b"\x00" * 30
DUMMY_ALTERNATE = b"\xff" * 64


def _make_x64dbg_tree(root: Path) -> Path:
    """Create a minimal x64dbg directory layout.

    Args:
        root: Parent directory for the x64dbg installation.

    Returns:
        Path: Path to the x64dbg root.
    """
    x64dbg = root / "x64dbg"
    (x64dbg / "release" / "x64" / "plugins").mkdir(parents=True)
    (x64dbg / "release" / "x32" / "plugins").mkdir(parents=True)
    return x64dbg


def _make_plugin_source(
    tools_dir: Path,
    filename: str,
    content: bytes,
    subdir: str = "bin",
) -> Path:
    """Write a fake plugin binary into the plugin source tree.

    Args:
        tools_dir: Tools directory that contains ``x64dbg_plugin/``.
        filename: Plugin filename (e.g. ``intellicrack_bridge_x64.dp64``).
        content: Binary content to write.
        subdir: Sub-directory within x64dbg_plugin.

    Returns:
        Path: Path to the written file.
    """
    plugin_dir = tools_dir / "x64dbg_plugin" / subdir
    plugin_dir.mkdir(parents=True, exist_ok=True)
    binary = plugin_dir / filename
    binary.write_bytes(content)
    return binary


class TestFindPluginSourceViaDeployment:
    """Indirect tests for plugin source discovery via deploy_x64dbg_plugin."""

    @staticmethod
    def test_finds_binary_in_bin_directory(tmp_path: Path) -> None:
        """Deploy succeeds when source is in bin/ directory."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE, "bin")

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True
        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.read_bytes() == DUMMY_PE

    @staticmethod
    def test_finds_binary_in_build_plugins(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build/plugins/."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32,
            subdir="build/plugins",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True
        target = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        assert target.read_bytes() == DUMMY_PE_32

    @staticmethod
    def test_finds_binary_in_build_release(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build/Release/."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            DUMMY_PE,
            subdir="build/Release",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_finds_binary_in_arch_specific_build(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build_x64/plugins/."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            DUMMY_PE,
            subdir="build_x64/plugins",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_finds_binary_in_arch_specific_release(tmp_path: Path) -> None:
        """Deploy succeeds when source is in build_x32/Release/."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x32.dp32",
            DUMMY_PE_32,
            subdir="build_x32/Release",
        )

        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is True

    @staticmethod
    def test_priority_bin_over_build(tmp_path: Path) -> None:
        """Prefer bin/ over build/plugins/ when both exist."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", b"\x01" * 64, "bin")
        _make_plugin_source(
            tmp_path,
            "intellicrack_bridge_x64.dp64",
            b"\x02" * 64,
            subdir="build/plugins",
        )

        deploy_x64dbg_plugin(x64dbg, tmp_path)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.read_bytes() == b"\x01" * 64


class TestDeployX64dbgPlugin:
    """Tests for deploy_x64dbg_plugin."""

    @staticmethod
    def test_returns_false_when_plugin_dir_missing(tmp_path: Path) -> None:
        """Return False when x64dbg_plugin directory does not exist."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is False

    @staticmethod
    def test_returns_false_when_no_binaries_exist(tmp_path: Path) -> None:
        """Return False when plugin directory exists but has no binaries."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        (tmp_path / "x64dbg_plugin").mkdir()
        assert deploy_x64dbg_plugin(x64dbg, tmp_path) is False

    @staticmethod
    def test_deploys_dp64_binary(tmp_path: Path) -> None:
        """Deploy a .dp64 binary to x64 plugins directory."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        assert target.is_file()
        assert target.read_bytes() == DUMMY_PE

    @staticmethod
    def test_deploys_dp32_binary(tmp_path: Path) -> None:
        """Deploy a .dp32 binary to x32 plugins directory."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", DUMMY_PE_32)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        target = x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32"
        assert target.is_file()
        assert target.read_bytes() == DUMMY_PE_32

    @staticmethod
    def test_deploys_both_architectures(tmp_path: Path) -> None:
        """Deploy both x64 and x32 plugins when both sources exist."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", DUMMY_PE_32)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert (x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64").is_file()
        assert (x64dbg / "release" / "x32" / "plugins" / "intellicrack_bridge_x32.dp32").is_file()

    @staticmethod
    def test_skips_copy_when_target_is_newer(tmp_path: Path) -> None:
        """Skip copy when the target file has a newer mtime than source."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"

        time.sleep(0.05)
        target.write_bytes(DUMMY_ALTERNATE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert target.read_bytes() == DUMMY_ALTERNATE

    @staticmethod
    def test_overwrites_when_source_is_newer(tmp_path: Path) -> None:
        """Overwrite target when source has a newer mtime."""
        x64dbg = _make_x64dbg_tree(tmp_path)

        target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        target.write_bytes(DUMMY_ALTERNATE)

        time.sleep(0.05)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert target.read_bytes() == DUMMY_PE

    @staticmethod
    def test_creates_plugins_directory_if_missing(tmp_path: Path) -> None:
        """Create the plugins directory when it does not yet exist."""
        x64dbg = tmp_path / "x64dbg"
        x64dbg.mkdir()
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)

        assert result is True
        assert (x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64").is_file()

    @staticmethod
    def test_gracefully_handles_copy_failure(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Return False and log warning when copy raises OSError."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", DUMMY_PE)

        def _fail(_src: object, _dst: object, **_kw: object) -> object:
            raise OSError

        monkeypatch.setattr(shutil, "copy2", _fail)

        result = deploy_x64dbg_plugin(x64dbg, tmp_path)
        assert result is False
