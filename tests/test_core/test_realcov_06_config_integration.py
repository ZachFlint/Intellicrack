# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data integration coverage for :mod:`intellicrack.core.config`.

These tests exercise the genuine save/load/round-trip pipeline against real
on-disk TOML and real filesystem directory creation, then feed the reloaded
config into real application components: the :class:`Config` directory creation
contract, the actual project ``ToolRegistry`` (so a reloaded config drives real
tool wiring), and the real ``get_project_root`` / ``get_config_dir`` filesystem
layout. Nothing is mocked; assertions are over real serialised values and real
directories.
"""

from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import (
    Config,
    get_config_dir,
    get_config_file,
    get_project_root,
)
from intellicrack.core.types import ConfirmationLevel, ProviderName, ToolName


if TYPE_CHECKING:
    from pathlib import Path

_CUSTOM_TIMEOUT = 222
_CUSTOM_PORT = 5099


def _build_real_config(tmp_path: Path) -> Config:
    """Build a real default config rooted under ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory used for the config's data,
            tools, and logs directories.

    Returns:
        Config: A real, fully-populated configuration instance.
    """
    config = Config.default()
    config.tools_directory = tmp_path / "tools"
    config.logs_directory = tmp_path / "logs"
    config.data_directory = tmp_path / "data"
    return config


def test_config_save_edit_reload_preserves_real_values(tmp_path: Path) -> None:
    """Save, hand-edit the real TOML, reload, and confirm every value persists.

    Args:
        tmp_path: Pytest temporary directory for the config file and dirs.
    """
    pytest.importorskip("tomli_w")
    config = _build_real_config(tmp_path)
    config.default_provider = ProviderName.OPENAI
    config.confirmation_level = ConfirmationLevel.ALL
    config.providers[ProviderName.ANTHROPIC].timeout_seconds = _CUSTOM_TIMEOUT
    config.tools[ToolName.GHIDRA].port = _CUSTOM_PORT

    config_path = tmp_path / "config.toml"
    config.save(config_path)
    assert config_path.is_file()

    on_disk = tomllib.loads(config_path.read_text(encoding="utf-8"))
    assert on_disk["general"]["default_provider"] == "openai"
    assert on_disk["general"]["confirmation_level"] == "all"
    assert on_disk["providers"]["anthropic"]["timeout_seconds"] == _CUSTOM_TIMEOUT
    assert on_disk["tools"]["ghidra"]["port"] == _CUSTOM_PORT

    reloaded = Config.load(config_path)
    assert reloaded.default_provider == ProviderName.OPENAI
    assert reloaded.confirmation_level == ConfirmationLevel.ALL
    assert reloaded.get_provider_config(ProviderName.ANTHROPIC).timeout_seconds == _CUSTOM_TIMEOUT
    assert reloaded.get_tool_config(ToolName.GHIDRA).port == _CUSTOM_PORT


def test_reloaded_config_creates_real_directories(tmp_path: Path) -> None:
    """A reloaded config creates the real directories it references on disk.

    Args:
        tmp_path: Pytest temporary directory for the config file and dirs.
    """
    pytest.importorskip("tomli_w")
    config = _build_real_config(tmp_path)
    config_path = tmp_path / "config.toml"
    config.save(config_path)

    reloaded = Config.load(config_path)
    assert not (tmp_path / "tools").exists()
    reloaded.ensure_directories()
    assert (tmp_path / "tools").is_dir()
    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "data").is_dir()


def test_reloaded_config_drives_real_tool_registry(tmp_path: Path) -> None:
    """A reloaded config initializes the real application ``ToolRegistry``.

    Disables one tool on disk, reloads, confirms the real enablement state, and
    wires the reloaded ``tools_directory`` into a real ``ToolRegistry`` so the
    registry's real directory contract reflects the loaded configuration.

    Args:
        tmp_path: Pytest temporary directory for the config file and dirs.
    """
    pytest.importorskip("tomli_w")
    tool_registry_mod = pytest.importorskip("intellicrack.core.tools")
    config = _build_real_config(tmp_path)
    config.tools[ToolName.X64DBG].enabled = False
    config_path = tmp_path / "config.toml"
    config.save(config_path)

    reloaded = Config.load(config_path)
    reloaded.ensure_directories()
    assert reloaded.is_tool_enabled(ToolName.GHIDRA) is True
    assert reloaded.is_tool_enabled(ToolName.X64DBG) is False

    registry = tool_registry_mod.ToolRegistry(reloaded.tools_directory)
    assert registry.tools_directory == reloaded.tools_directory
    assert registry.tools_directory.is_dir()
    available = registry.get_available_tools()
    assert isinstance(available, list)


def test_project_root_layout_matches_real_filesystem() -> None:
    """``get_project_root``/``get_config_dir`` describe the real on-disk layout."""
    root = get_project_root()
    assert root.is_dir()
    assert (root / "src" / "intellicrack").is_dir()
    assert (root / "pyproject.toml").is_file()

    config_dir = get_config_dir()
    assert config_dir.parent == root
    assert config_dir.name == ".intellicrack"

    providers_file = get_config_file("providers.json")
    assert providers_file.parent == config_dir
    assert providers_file.name == "providers.json"


def test_committed_project_config_loads_if_present() -> None:
    """If a real committed ``config.toml`` exists, it loads into a usable Config.

    The repository may or may not ship a checked-in ``.intellicrack/config.toml``.
    When present, it must parse with the real loader and yield queryable
    provider/tool configs; when absent, the test documents that and skips.
    """
    config_path = get_config_dir() / "config.toml"
    if not config_path.is_file():
        pytest.skip(f"No committed project config at {config_path}")
    config = Config.load(config_path)
    anthropic = config.get_provider_config(ProviderName.ANTHROPIC)
    assert isinstance(anthropic.enabled, bool)
    assert len(config.tools) > 0
