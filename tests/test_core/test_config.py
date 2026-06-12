# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.config module - configuration management."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, TypedDict, cast

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


class _GeneralSection(TypedDict):
    """Subset of the ``general`` section emitted by ``Config._to_dict``."""

    default_provider: str
    confirmation_level: str
    tools_directory: str
    logs_directory: str
    data_directory: str


class _ConfigSerialised(TypedDict):
    """Subset of the full configuration dictionary tests inspect by key."""

    general: _GeneralSection
    providers: dict[str, dict[str, bool | int | str]]
    tools: dict[str, dict[str, bool | int | str]]
    sandbox: dict[str, bool | int]
    ui: dict[str, bool | int | str]
    session: dict[str, bool | int]
    log: dict[str, bool | int | str]


def _config_to_dict(config: Config) -> _ConfigSerialised:
    """Return the config's serialised dictionary via ``getattr``.

    Args:
        config: The Config instance to serialise.

    Returns:
        _ConfigSerialised: Typed view of the configuration dictionary.
    """
    serialise = cast(Callable[[], _ConfigSerialised], getattr(config, "_to_dict"))
    return serialise()


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
    assert uc.theme == "system"
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


_EXPECTED_PROVIDERS: Final[frozenset[ProviderName]] = frozenset({
    ProviderName.ANTHROPIC,
    ProviderName.OPENAI,
    ProviderName.GOOGLE,
    ProviderName.OLLAMA,
    ProviderName.OPENROUTER,
    ProviderName.HUGGINGFACE,
    ProviderName.GROK,
    ProviderName.LOCAL_TRANSFORMERS,
})

_EXPECTED_TOOLS: Final[frozenset[ToolName]] = frozenset({
    ToolName.GHIDRA,
    ToolName.X64DBG,
    ToolName.FRIDA,
    ToolName.CUTTER,
    ToolName.PROCESS,
})


def test_config_default() -> None:
    """Verify Config.default() creates config with exactly the expected providers and tools.

    Checks that no provider or tool is silently added or dropped,
    that default_provider and confirmation_level hold their documented values,
    and that every entry has the correct enabled state from _default_providers
    and _default_tools. Also verifies that overriding a default-enabled entry
    to disabled makes is_provider_enabled / is_tool_enabled return False - the
    negative case that catches any fallback-to-default regression.
    """
    config = Config.default()
    assert config.default_provider == ProviderName.ANTHROPIC
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE

    assert set(config.providers.keys()) == _EXPECTED_PROVIDERS, (
        f"Providers mismatch: got {set(config.providers.keys())}, expected {_EXPECTED_PROVIDERS}"
    )
    assert set(config.tools.keys()) == _EXPECTED_TOOLS, f"Tools mismatch: got {set(config.tools.keys())}, expected {_EXPECTED_TOOLS}"

    for pname in _EXPECTED_PROVIDERS:
        assert config.providers[pname].enabled is True, f"Provider {pname} should be enabled by default"

    for tname in _EXPECTED_TOOLS:
        assert config.tools[tname].enabled is True, f"Tool {tname} should be enabled by default"

    assert config.providers[ProviderName.OLLAMA].api_base == "http://localhost:11434"
    assert config.providers[ProviderName.OPENROUTER].api_base == "https://openrouter.ai/api/v1"
    assert config.providers[ProviderName.HUGGINGFACE].api_base == "https://api-inference.huggingface.co"
    assert config.providers[ProviderName.GROK].api_base == "https://api.x.ai/v1"
    assert config.providers[ProviderName.LOCAL_TRANSFORMERS].default_model == "microsoft/Phi-3-mini-4k-instruct"
    assert config.providers[ProviderName.LOCAL_TRANSFORMERS].timeout_seconds == 600
    assert config.providers[ProviderName.LOCAL_TRANSFORMERS].max_retries == 1

    assert config.tools[ToolName.GHIDRA].port == 4768
    assert config.tools[ToolName.GHIDRA].startup_timeout_seconds == 120
    assert config.tools[ToolName.X64DBG].startup_timeout_seconds == 30
    assert config.tools[ToolName.FRIDA].startup_timeout_seconds == 10
    assert config.tools[ToolName.PROCESS].auto_install is False

    config.providers[ProviderName.ANTHROPIC] = ProviderConfig(enabled=False)
    assert config.is_provider_enabled(ProviderName.ANTHROPIC) is False, (
        "Overriding a default-enabled provider to disabled must return False, not fall back to ProviderConfig default"
    )

    config.tools[ToolName.GHIDRA] = ToolConfig(enabled=False)
    assert config.is_tool_enabled(ToolName.GHIDRA) is False, (
        "Overriding a default-enabled tool to disabled must return False, not fall back to ToolConfig default"
    )

    config_unknown_provider = Config(providers={})
    unknown_pc = config_unknown_provider.get_provider_config(ProviderName.GROK)
    assert unknown_pc.enabled is True, "Missing provider falls back to ProviderConfig() default of enabled=True"
    assert unknown_pc.timeout_seconds == _DEFAULT_TIMEOUT
    assert unknown_pc.max_retries == _DEFAULT_RETRIES
    assert unknown_pc.api_base is None
    assert unknown_pc.default_model is None

    config_unknown_tool = Config(tools={})
    unknown_tc = config_unknown_tool.get_tool_config(ToolName.CUTTER)
    assert unknown_tc.enabled is True, "Missing tool falls back to ToolConfig() default of enabled=True"
    assert unknown_tc.auto_install is True
    assert unknown_tc.startup_timeout_seconds == _TOOL_STARTUP
    assert unknown_tc.path is None
    assert unknown_tc.port is None


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
    """Verify get_provider_config returns the exact stored config for a known provider.

    Covers the positive path (known, enabled provider returns its full stored
    config) and the negative path (a provider explicitly set to disabled returns
    enabled=False rather than the default ProviderConfig).
    """
    config = Config.default()

    anthropic_pc = config.get_provider_config(ProviderName.ANTHROPIC)
    assert anthropic_pc.enabled is True
    assert anthropic_pc.timeout_seconds == _DEFAULT_TIMEOUT
    assert anthropic_pc.max_retries == _DEFAULT_RETRIES
    assert anthropic_pc.api_base is None

    ollama_pc = config.get_provider_config(ProviderName.OLLAMA)
    assert ollama_pc.enabled is True
    assert ollama_pc.api_base == "http://localhost:11434"
    assert ollama_pc.timeout_seconds == 300

    disabled_config = ProviderConfig(enabled=False, timeout_seconds=10, max_retries=1)
    config_with_disabled = Config(
        providers={ProviderName.OPENAI: disabled_config},
    )
    disabled_pc = config_with_disabled.get_provider_config(ProviderName.OPENAI)
    assert disabled_pc.enabled is False
    assert disabled_pc.timeout_seconds == 10
    assert disabled_pc.max_retries == 1


def test_config_get_provider_config_unknown() -> None:
    """Verify get_provider_config returns default for unknown provider."""
    config = Config(providers={})
    pc = config.get_provider_config(ProviderName.GROK)
    assert pc.enabled is True


def test_config_get_tool_config() -> None:
    """Verify get_tool_config returns the exact stored config for a known tool.

    Covers the positive path (known, enabled tool returns its full stored
    config) and the negative path (a tool explicitly set to disabled returns
    enabled=False with the exact field values from its stored ToolConfig).
    """
    config = Config.default()

    ghidra_tc = config.get_tool_config(ToolName.GHIDRA)
    assert ghidra_tc.enabled is True
    assert ghidra_tc.auto_install is True
    assert ghidra_tc.startup_timeout_seconds == 120
    assert ghidra_tc.port == 4768

    process_tc = config.get_tool_config(ToolName.PROCESS)
    assert process_tc.enabled is True
    assert process_tc.auto_install is False
    assert process_tc.startup_timeout_seconds == 5

    disabled_tool = ToolConfig(enabled=False, auto_install=False, startup_timeout_seconds=7, port=9999)
    config_with_disabled = Config(
        tools={ToolName.X64DBG: disabled_tool},
    )
    disabled_tc = config_with_disabled.get_tool_config(ToolName.X64DBG)
    assert disabled_tc.enabled is False
    assert disabled_tc.auto_install is False
    assert disabled_tc.startup_timeout_seconds == 7
    assert disabled_tc.port == 9999


def test_config_is_provider_enabled() -> None:
    """Verify is_provider_enabled returns True for enabled and False for disabled providers.

    The default config enables all providers. A Config built with an explicitly
    disabled ProviderConfig must return False - not fall back to the ProviderConfig
    default of enabled=True. An absent provider (empty providers dict) returns the
    ProviderConfig default of True because get_provider_config returns ProviderConfig().
    """
    config = Config.default()
    assert config.is_provider_enabled(ProviderName.ANTHROPIC) is True
    assert config.is_provider_enabled(ProviderName.OPENAI) is True
    assert config.is_provider_enabled(ProviderName.GROK) is True

    config_disabled = Config(
        providers={
            ProviderName.ANTHROPIC: ProviderConfig(enabled=False),
            ProviderName.OPENAI: ProviderConfig(enabled=True),
        },
    )
    assert config_disabled.is_provider_enabled(ProviderName.ANTHROPIC) is False
    assert config_disabled.is_provider_enabled(ProviderName.OPENAI) is True

    config_empty = Config(providers={})
    assert config_empty.is_provider_enabled(ProviderName.GOOGLE) is True


def test_config_is_tool_enabled() -> None:
    """Verify is_tool_enabled returns True for enabled and False for disabled tools.

    The default config enables all tools. A Config built with an explicitly
    disabled ToolConfig must return False - not fall back to the ToolConfig
    default of enabled=True. An absent tool (empty tools dict) returns the
    ToolConfig default of True because get_tool_config returns ToolConfig().
    """
    config = Config.default()
    assert config.is_tool_enabled(ToolName.GHIDRA) is True
    assert config.is_tool_enabled(ToolName.X64DBG) is True
    assert config.is_tool_enabled(ToolName.FRIDA) is True

    config_disabled = Config(
        tools={
            ToolName.GHIDRA: ToolConfig(enabled=False),
            ToolName.FRIDA: ToolConfig(enabled=True),
        },
    )
    assert config_disabled.is_tool_enabled(ToolName.GHIDRA) is False
    assert config_disabled.is_tool_enabled(ToolName.FRIDA) is True

    config_empty = Config(tools={})
    assert config_empty.is_tool_enabled(ToolName.CUTTER) is True


def test_config_to_dict_round_trip() -> None:
    """Verify _to_dict serialises every section with correct values for the default config.

    All fields that are not None/False/empty are required to appear with exact
    string/int/bool values so that a disabled provider or a wrong port number
    would be caught.
    """
    config = Config.default()
    d = _config_to_dict(config)

    general = d["general"]
    assert general["default_provider"] == "anthropic"
    assert general["confirmation_level"] == "destructive"

    providers = d["providers"]
    assert isinstance(providers, dict)
    assert "anthropic" in providers
    assert providers["anthropic"]["enabled"] is True
    assert providers["anthropic"]["timeout_seconds"] == _DEFAULT_TIMEOUT
    assert providers["anthropic"]["max_retries"] == _DEFAULT_RETRIES

    assert "ollama" in providers
    assert providers["ollama"]["api_base"] == "http://localhost:11434"
    assert providers["ollama"]["enabled"] is True

    assert "local_transformers" in providers
    assert providers["local_transformers"]["default_model"] == "microsoft/Phi-3-mini-4k-instruct"
    assert providers["local_transformers"]["timeout_seconds"] == 600
    assert providers["local_transformers"]["max_retries"] == 1

    tools = d["tools"]
    assert isinstance(tools, dict)
    assert "ghidra" in tools
    assert tools["ghidra"]["enabled"] is True
    assert tools["ghidra"]["port"] == 4768
    assert tools["ghidra"]["startup_timeout_seconds"] == 120

    assert "process" in tools
    assert tools["process"]["auto_install"] is False

    sandbox = d["sandbox"]
    assert sandbox["enabled"] is True
    assert sandbox["timeout_seconds"] == _SANDBOX_TIMEOUT
    assert sandbox["memory_limit_mb"] == _SANDBOX_MEM
    assert sandbox["network_enabled"] is False

    ui = d["ui"]
    assert ui["theme"] == "system"
    assert ui["font_family"] == "JetBrains Mono"
    assert ui["font_size"] == _DEFAULT_FONT_SIZE
    assert ui["show_tool_calls"] is True

    session = d["session"]
    assert session["auto_save"] is True
    assert session["save_interval_seconds"] == _SESSION_INTERVAL
    assert session["retention_days"] == _SESSION_RETENTION

    log = d["log"]
    assert log["level"] == "INFO"
    assert log["file_enabled"] is True
    assert log["console_enabled"] is True
    assert log["max_file_size_mb"] == _LOG_MAX_SIZE
    assert log["backup_count"] == _LOG_BACKUP_COUNT
    assert log["retention_days"] == _LOG_RETENTION
    assert log["json_file"] is True


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
    """Verify parse_providers skips unknown names and preserves defaults for unprovided providers.

    The unknown key must not appear as any ProviderName in the result.
    Unprovided known providers (GROK, OPENAI, etc.) must retain the
    _default_providers() values - specifically enabled=True - which confirms
    the function merges into the defaults rather than producing a sparse dict.
    """
    providers_data: dict[str, Any] = {
        "anthropic": {"enabled": False},
        "unknown_provider": {"enabled": True},
    }
    result = Config.parse_providers(providers_data)
    assert result[ProviderName.ANTHROPIC].enabled is False

    unknown_values: list[str] = [pn.value for pn in result]
    assert "unknown_provider" not in unknown_values, "Unknown provider key must not appear in the parsed result"

    assert ProviderName.GROK in result, "GROK must be present as a default provider"
    assert result[ProviderName.GROK].enabled is True, "Unprovided GROK must retain default enabled=True"
    assert result[ProviderName.GROK].api_base == "https://api.x.ai/v1", "Unprovided GROK must retain its default api_base"

    assert ProviderName.OPENAI in result
    assert result[ProviderName.OPENAI].enabled is True

    assert set(result.keys()) == _EXPECTED_PROVIDERS, "parse_providers must return exactly the expected provider set"


def test_config_parse_tools_unknown_skipped() -> None:
    """Verify parse_tools skips unknown names and preserves defaults for unprovided tools.

    The unknown key must not appear as any ToolName in the result.
    Unprovided known tools (FRIDA, X64DBG, etc.) must retain the
    _default_tools() values - specifically enabled=True - which confirms
    the function merges into the defaults rather than producing a sparse dict.
    """
    tools_data: dict[str, Any] = {
        "ghidra": {"enabled": False},
        "unknown_tool": {"enabled": True},
    }
    result = Config.parse_tools(tools_data)
    assert result[ToolName.GHIDRA].enabled is False

    unknown_values: list[str] = [tn.value for tn in result]
    assert "unknown_tool" not in unknown_values, "Unknown tool key must not appear in the parsed result"

    assert ToolName.FRIDA in result, "FRIDA must be present as a default tool"
    assert result[ToolName.FRIDA].enabled is True, "Unprovided FRIDA must retain default enabled=True"
    assert result[ToolName.FRIDA].startup_timeout_seconds == 10

    assert ToolName.X64DBG in result
    assert result[ToolName.X64DBG].enabled is True

    assert set(result.keys()) == _EXPECTED_TOOLS, "parse_tools must return exactly the expected tool set"


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
    assert ui.theme == "system"
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
