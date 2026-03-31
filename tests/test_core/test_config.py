# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.config module - configuration management."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest

from intellicrack.core.config import (
    Config,
    LogConfig,
    ProviderConfig,
    SandboxConfig,
    SessionConfig,
    ToolConfig,
    UIConfig,
    get_config_dir,
    get_config_file,
    get_project_root,
)
from intellicrack.core.types import ConfirmationLevel, ProviderName, ToolName


_DEFAULT_TIMEOUT: Final[int] = 120
_DEFAULT_RETRIES: Final[int] = 3
_DEFAULT_FONT_SIZE: Final[int] = 11
_SANDBOX_TIMEOUT: Final[int] = 300
_SANDBOX_MEM: Final[int] = 2048
_SESSION_INTERVAL: Final[int] = 300
_SESSION_RETENTION: Final[int] = 7
_LOG_MAX_SIZE: Final[int] = 10
_LOG_BACKUP_COUNT: Final[int] = 5
_LOG_RETENTION: Final[int] = 14
_TOOL_STARTUP: Final[int] = 60
_CUSTOM_FONT_SIZE: Final[int] = 14
_CUSTOM_RETENTION: Final[int] = 30


def test_provider_config_defaults() -> None:
    """Verify ProviderConfig defaults."""
    pc = ProviderConfig()
    assert pc.enabled is True
    assert pc.api_base is None
    assert pc.default_model is None
    assert pc.timeout_seconds == _DEFAULT_TIMEOUT
    assert pc.max_retries == _DEFAULT_RETRIES


def test_tool_config_defaults() -> None:
    """Verify ToolConfig defaults."""
    tc = ToolConfig()
    assert tc.enabled is True
    assert tc.path is None
    assert tc.auto_install is True
    assert tc.startup_timeout_seconds == _TOOL_STARTUP


def test_sandbox_config_defaults() -> None:
    """Verify SandboxConfig defaults."""
    sc = SandboxConfig()
    assert sc.enabled is True
    assert sc.timeout_seconds == _SANDBOX_TIMEOUT
    assert sc.memory_limit_mb == _SANDBOX_MEM
    assert sc.network_enabled is False


def test_ui_config_defaults() -> None:
    """Verify UIConfig defaults."""
    uc = UIConfig()
    assert uc.theme == "dark"
    assert uc.font_family == "JetBrains Mono"
    assert uc.font_size == _DEFAULT_FONT_SIZE
    assert uc.show_tool_calls is True


def test_session_config_defaults() -> None:
    """Verify SessionConfig defaults."""
    sc = SessionConfig()
    assert sc.auto_save is True
    assert sc.save_interval_seconds == _SESSION_INTERVAL
    assert sc.retention_days == _SESSION_RETENTION


def test_log_config_defaults() -> None:
    """Verify LogConfig defaults."""
    lc = LogConfig()
    assert lc.level == "INFO"
    assert lc.file_enabled is True
    assert lc.console_enabled is True
    assert lc.max_file_size_mb == _LOG_MAX_SIZE
    assert lc.backup_count == _LOG_BACKUP_COUNT
    assert lc.retention_days == _LOG_RETENTION
    assert lc.json_file is True


def test_config_default() -> None:
    """Verify Config.default() creates valid config with all providers and tools."""
    config = Config.default()
    assert config.default_provider == ProviderName.ANTHROPIC
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert ProviderName.ANTHROPIC in config.providers
    assert ProviderName.OPENAI in config.providers
    assert ToolName.GHIDRA in config.tools
    assert ToolName.X64DBG in config.tools


def test_config_ensure_directories(tmp_path: Path) -> None:
    """Verify ensure_directories creates all configured directories.

    Args:
        tmp_path: Pytest temporary directory.
    """
    config = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    config.ensure_directories()
    assert (tmp_path / "tools").is_dir()
    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "data").is_dir()


def test_config_get_provider_config() -> None:
    """Verify get_provider_config returns correct config."""
    config = Config.default()
    pc = config.get_provider_config(ProviderName.ANTHROPIC)
    assert pc.enabled is True


def test_config_get_provider_config_unknown() -> None:
    """Verify get_provider_config returns default for unknown provider."""
    config = Config(providers={})
    pc = config.get_provider_config(ProviderName.GROK)
    assert pc.enabled is True


def test_config_get_tool_config() -> None:
    """Verify get_tool_config returns correct config."""
    config = Config.default()
    tc = config.get_tool_config(ToolName.GHIDRA)
    assert tc.enabled is True


def test_config_is_provider_enabled() -> None:
    """Verify is_provider_enabled check."""
    config = Config.default()
    assert config.is_provider_enabled(ProviderName.ANTHROPIC) is True


def test_config_is_tool_enabled() -> None:
    """Verify is_tool_enabled check."""
    config = Config.default()
    assert config.is_tool_enabled(ToolName.GHIDRA) is True


def test_config_to_dict_round_trip() -> None:
    """Verify _to_dict produces serializable dict with expected keys."""
    config = Config.default()
    d = config.to_dict()
    assert "general" in d
    assert "providers" in d
    assert "tools" in d
    assert "sandbox" in d
    assert "ui" in d
    assert "session" in d
    assert "log" in d
    assert d["general"]["default_provider"] == "anthropic"


def test_config_from_dict_empty() -> None:
    """Verify _from_dict with empty dict uses all defaults."""
    config = Config.from_dict({})
    assert config.default_provider == ProviderName.ANTHROPIC
    assert len(config.providers) > 0
    assert len(config.tools) > 0


def test_config_from_dict_custom_general() -> None:
    """Verify _from_dict parses custom general section."""
    data: dict[str, Any] = {
        "general": {
            "default_provider": "openai",
            "confirmation_level": "none",
        },
    }
    config = Config.from_dict(data)
    assert config.default_provider == ProviderName.OPENAI
    assert config.confirmation_level == ConfirmationLevel.NONE


def test_config_from_dict_invalid_provider_fallback() -> None:
    """Verify _from_dict falls back for invalid provider name."""
    data: dict[str, Any] = {
        "general": {"default_provider": "nonexistent"},
    }
    config = Config.from_dict(data)
    assert config.default_provider == ProviderName.ANTHROPIC


def test_config_from_dict_invalid_confirmation_fallback() -> None:
    """Verify _from_dict falls back for invalid confirmation level."""
    data: dict[str, Any] = {
        "general": {"confirmation_level": "badvalue"},
    }
    config = Config.from_dict(data)
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE


def test_config_parse_providers_unknown_skipped() -> None:
    """Verify _parse_providers skips unknown provider names."""
    providers_data: dict[str, Any] = {
        "anthropic": {"enabled": False},
        "unknown_provider": {"enabled": True},
    }
    result = Config.parse_providers(providers_data)
    assert result[ProviderName.ANTHROPIC].enabled is False
    assert ProviderName.GROK not in result or result.get(ProviderName.GROK, ProviderConfig()).enabled


def test_config_parse_tools_unknown_skipped() -> None:
    """Verify _parse_tools skips unknown tool names."""
    tools_data: dict[str, Any] = {
        "ghidra": {"enabled": False},
        "unknown_tool": {"enabled": True},
    }
    result = Config.parse_tools(tools_data)
    assert result[ToolName.GHIDRA].enabled is False


def test_config_parse_tools_with_path() -> None:
    """Verify _parse_tools handles path field."""
    tools_data: dict[str, Any] = {
        "ghidra": {"path": "/opt/ghidra"},
    }
    result = Config.parse_tools(tools_data)
    assert result[ToolName.GHIDRA].path == Path("/opt/ghidra")


def test_config_parse_sub_configs_defaults() -> None:
    """Verify _parse_sub_configs returns defaults for empty data."""
    sandbox, ui, session, log = Config.parse_sub_configs({})
    assert sandbox.enabled is True
    assert ui.theme == "dark"
    assert session.auto_save is True
    assert log.level == "INFO"


def test_config_parse_sub_configs_custom() -> None:
    """Verify _parse_sub_configs applies custom values."""
    data: dict[str, Any] = {
        "sandbox": {"network_enabled": True},
        "ui": {"theme": "light", "font_size": _CUSTOM_FONT_SIZE},
        "session": {"retention_days": _CUSTOM_RETENTION},
        "log": {"level": "DEBUG"},
    }
    sandbox, ui, session, log = Config.parse_sub_configs(data)
    assert sandbox.network_enabled is True
    assert ui.theme == "light"
    assert ui.font_size == _CUSTOM_FONT_SIZE
    assert session.retention_days == _CUSTOM_RETENTION
    assert log.level == "DEBUG"


def test_config_load_from_toml(tmp_path: Path) -> None:
    """Verify Config.load reads and parses a TOML file.

    Args:
        tmp_path: Pytest temporary directory.
    """
    toml_content = b"""
[general]
default_provider = "openai"

[sandbox]
network_enabled = true

[ui]
theme = "light"
"""
    toml_path = tmp_path / "config.toml"
    toml_path.write_bytes(toml_content)

    config = Config.load(toml_path)
    assert config.default_provider == ProviderName.OPENAI
    assert config.sandbox.network_enabled is True
    assert config.ui.theme == "light"


def test_config_save_and_reload(tmp_path: Path) -> None:
    """Verify save and reload produce equivalent configuration.

    Args:
        tmp_path: Pytest temporary directory.
    """
    pytest.importorskip("tomli_w")

    config = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        default_provider=ProviderName.OPENAI,
    )

    save_path = tmp_path / "saved.toml"
    config.save(save_path)
    assert save_path.exists()

    reloaded = Config.load(save_path)
    assert reloaded.default_provider == ProviderName.OPENAI
    assert str(reloaded.tools_directory) == str(config.tools_directory)


def test_get_project_root_returns_repo_root() -> None:
    """Verify get_project_root returns a directory containing 'src'."""
    root = get_project_root()
    assert root.is_dir()
    assert (root / "src").is_dir()


def test_get_config_dir_is_under_project_root() -> None:
    """Verify get_config_dir returns <project_root>/.intellicrack."""
    config_dir = get_config_dir()
    assert config_dir.name == ".intellicrack"
    assert config_dir.parent == get_project_root()


def test_get_config_file_joins_filename() -> None:
    """Verify get_config_file joins the filename under the config directory."""
    path = get_config_file("providers.json")
    assert path.name == "providers.json"
    assert path.parent == get_config_dir()
