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
from typing import TYPE_CHECKING, Any

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


def _build_bridge_map(
    ghidra_mod: object,
    process_mod: object,
    frida_mod: object,
    cutter_mod: object,
) -> dict[ToolName, type[Any]]:
    """Assemble a mapping of ToolName to bridge constructor for testable tools.

    Args:
        ghidra_mod: Imported ``intellicrack.bridges.ghidra`` module.
        process_mod: Imported ``intellicrack.bridges.process`` module.
        frida_mod: Imported ``intellicrack.bridges.frida_bridge`` module.
        cutter_mod: Imported ``intellicrack.bridges.cutter`` module.

    Returns:
        dict[ToolName, type[Any]]: Mapping from tool name to bridge class.
    """
    return {
        ToolName.GHIDRA: getattr(ghidra_mod, "GhidraBridge"),
        ToolName.PROCESS: getattr(process_mod, "ProcessBridge"),
        ToolName.FRIDA: getattr(frida_mod, "FridaBridge"),
        ToolName.CUTTER: getattr(cutter_mod, "CutterBridge"),
    }


def _assert_toml_enabled_fields(
    config_path: Path,
    disabled_tools: frozenset[ToolName],
    expected_enabled: frozenset[ToolName],
) -> None:
    """Assert the on-disk TOML serialises ``enabled`` correctly for each tool.

    Args:
        config_path: Path to the saved TOML config file.
        disabled_tools: Tools expected to have ``enabled=False`` in the TOML.
        expected_enabled: Tools expected to have ``enabled=True`` in the TOML.
    """
    on_disk = tomllib.loads(config_path.read_text(encoding="utf-8"))
    tools_section: dict[str, dict[str, object]] = on_disk.get("tools", {})
    for tool in disabled_tools:
        raw = tools_section.get(tool.value, {})
        assert raw.get("enabled") is False, (
            f"TOML did not serialise enabled=False for {tool.value}"
        )
    for tool in expected_enabled:
        raw = tools_section.get(tool.value, {})
        assert raw.get("enabled", True) is True, (
            f"TOML serialised enabled=False for {tool.value} which should be enabled"
        )


def test_reloaded_config_drives_real_tool_registry(tmp_path: Path) -> None:
    """Reloaded config enabled/disabled state filters real ``ToolRegistry`` population.

    Explicitly disables two tools before saving, reloads the TOML, verifies the
    on-disk serialised ``enabled`` field matches the pre-save intent (independent
    oracle via raw ``tomllib`` parse), then builds a real ``ToolRegistry`` that
    only registers bridges for tools the reloaded config reports as enabled.
    Asserts ``get_available_tools`` returns exactly the config-enabled set and
    never includes the disabled tools.

    Falsifiability: if ``Config._to_dict`` omits the ``enabled=False`` field for
    any disabled tool, ``Config.parse_tools`` will reload that tool with its
    default ``enabled=True``, causing ``is_tool_enabled`` to return ``True`` for
    that tool.  The loop below will then register a bridge for it, so
    ``get_available_tools`` will include it, making the ``frozenset`` equality
    assertion fail against ``expected_enabled`` (which was computed from the
    pre-save intent and excludes that tool).

    Args:
        tmp_path: Pytest temporary directory for the config file and dirs.
    """
    pytest.importorskip("tomli_w")
    tool_registry_mod = pytest.importorskip("intellicrack.core.tools")
    ghidra_mod = pytest.importorskip("intellicrack.bridges.ghidra")
    process_mod = pytest.importorskip("intellicrack.bridges.process")
    frida_mod = pytest.importorskip("intellicrack.bridges.frida_bridge")
    cutter_mod = pytest.importorskip("intellicrack.bridges.cutter")

    config = _build_real_config(tmp_path)
    disabled_tools: frozenset[ToolName] = frozenset({ToolName.X64DBG, ToolName.FRIDA})
    for tool in disabled_tools:
        config.tools[tool].enabled = False

    expected_enabled: frozenset[ToolName] = frozenset(
        t for t in config.tools if t not in disabled_tools
    )

    config_path = tmp_path / "config.toml"
    config.save(config_path)
    _assert_toml_enabled_fields(config_path, disabled_tools, expected_enabled)

    reloaded = Config.load(config_path)
    reloaded.ensure_directories()

    assert reloaded.is_tool_enabled(ToolName.X64DBG) is False
    assert reloaded.is_tool_enabled(ToolName.FRIDA) is False
    assert reloaded.is_tool_enabled(ToolName.GHIDRA) is True
    assert reloaded.is_tool_enabled(ToolName.PROCESS) is True
    assert reloaded.is_tool_enabled(ToolName.CUTTER) is True

    bridge_map = _build_bridge_map(ghidra_mod, process_mod, frida_mod, cutter_mod)
    registry = tool_registry_mod.ToolRegistry(reloaded.tools_directory)
    for tool_name, bridge_cls in bridge_map.items():
        if reloaded.is_tool_enabled(tool_name):
            registry.register_bridge(tool_name, bridge_cls())

    available = frozenset(registry.get_available_tools())
    assert available == expected_enabled, (
        f"Registry available set {available} != config-enabled set {expected_enabled}"
    )
    for tool in disabled_tools:
        assert tool not in available, (
            f"Disabled tool {tool.value} appeared in get_available_tools() "
            "despite being disabled in the reloaded config"
        )


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
