# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.config module - configuration management."""

from __future__ import annotations

import tomllib
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

    Covers the happy path (all three dirs created) and confirms the method is
    idempotent (calling it twice does not raise).

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

    config.ensure_directories()
    assert (tmp_path / "tools").is_dir()
    assert (tmp_path / "logs").is_dir()
    assert (tmp_path / "data").is_dir()


def test_config_ensure_directories_nested(tmp_path: Path) -> None:
    """Verify ensure_directories creates deeply nested directories.

    The production implementation uses mkdir(parents=True, exist_ok=True) which
    must create any missing parent directories.  A two-level deep path is used
    to ensure the parents=True flag is exercised.

    Args:
        tmp_path: Pytest temporary directory.
    """
    config = Config(
        tools_directory=tmp_path / "a" / "b" / "tools",
        logs_directory=tmp_path / "a" / "b" / "logs",
        data_directory=tmp_path / "a" / "b" / "data",
    )
    config.ensure_directories()
    assert (tmp_path / "a" / "b" / "tools").is_dir()
    assert (tmp_path / "a" / "b" / "logs").is_dir()
    assert (tmp_path / "a" / "b" / "data").is_dir()


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
    """Verify get_provider_config returns a fresh default ProviderConfig for an absent provider.

    The returned default must have enabled=True, api_base=None, default_model=None,
    timeout_seconds==_DEFAULT_TIMEOUT, and max_retries==_DEFAULT_RETRIES — identical
    to a plain ProviderConfig() construction. Calling the method twice must return
    independent results with equal field values (determinism and independence).
    """
    config = Config(providers={})
    pc1 = config.get_provider_config(ProviderName.GROK)
    pc2 = config.get_provider_config(ProviderName.GROK)

    assert pc1.enabled is True
    assert pc1.api_base is None
    assert pc1.default_model is None
    assert pc1.timeout_seconds == _DEFAULT_TIMEOUT
    assert pc1.max_retries == _DEFAULT_RETRIES

    assert pc2.enabled is True
    assert pc2.api_base is None
    assert pc2.default_model is None
    assert pc2.timeout_seconds == _DEFAULT_TIMEOUT
    assert pc2.max_retries == _DEFAULT_RETRIES


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


def test_config_huggingface_default_model_is_curated() -> None:
    """Verify HuggingFace ships a non-empty curated default_model.

    Regression guard for the "broken HuggingFace default model" bug: the
    provider's HfApi catalog is sorted by download count, which surfaces
    small non-conversational models unrelated to what the router can
    actually serve for chat. Without a curated default_model, callers have
    nothing to prefer over that raw downloads-sorted order, so this must
    never be empty or None.
    """
    config = Config.default()
    hf_config = config.get_provider_config(ProviderName.HUGGINGFACE)
    assert hf_config.default_model is not None
    assert hf_config.default_model.strip()


def test_config_preferred_model_index_prefers_curated_default() -> None:
    """Verify preferred_model_index selects the curated default over raw index 0.

    Simulates a downloads-sorted discovery catalog (as HuggingFace's
    ``list_models`` returns) where the curated default_model is not the
    most-downloaded entry. Selection must land on the configured default's
    position, not index 0 - the pre-fix behavior that caused the bug.
    """
    config = Config(
        providers={
            ProviderName.HUGGINGFACE: ProviderConfig(default_model="org/curated-chat-model"),
        },
    )
    downloads_sorted_catalog = [
        "org/tiny-warm-model",
        "org/another-popular-model",
        "org/curated-chat-model",
        "org/yet-another-model",
    ]

    index = config.preferred_model_index(ProviderName.HUGGINGFACE, downloads_sorted_catalog)

    assert index != 0
    assert downloads_sorted_catalog[index] == "org/curated-chat-model"


def test_config_preferred_model_index_falls_back_to_zero() -> None:
    """Verify preferred_model_index falls back to index 0 without a usable default.

    Covers both fallback paths: no default_model configured, and a
    default_model that is not present in the discovered catalog. Also
    covers an empty catalog, which must not raise.
    """
    catalog = ["org/model-a", "org/model-b"]

    config_no_default = Config(providers={ProviderName.HUGGINGFACE: ProviderConfig()})
    assert config_no_default.preferred_model_index(ProviderName.HUGGINGFACE, catalog) == 0

    config_unmatched_default = Config(
        providers={ProviderName.HUGGINGFACE: ProviderConfig(default_model="org/not-in-catalog")},
    )
    assert config_unmatched_default.preferred_model_index(ProviderName.HUGGINGFACE, catalog) == 0

    assert config_no_default.preferred_model_index(ProviderName.HUGGINGFACE, []) == 0


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
    """Verify from_dict({}) produces a Config that equals Config.default() field-by-field.

    An empty dict must produce exactly the same provider set, tool set, and
    all sub-config values as Config.default().  This gates against any silent
    divergence between the two construction paths.
    """
    config = Config.from_dict({})
    default = Config.default()

    assert config.default_provider == default.default_provider
    assert config.confirmation_level == default.confirmation_level
    assert set(config.providers.keys()) == set(default.providers.keys())
    assert set(config.tools.keys()) == set(default.tools.keys())

    for pname in _EXPECTED_PROVIDERS:
        cp = config.providers[pname]
        dp = default.providers[pname]
        assert cp.enabled == dp.enabled, f"providers[{pname}].enabled mismatch"
        assert cp.api_base == dp.api_base, f"providers[{pname}].api_base mismatch"
        assert cp.default_model == dp.default_model, f"providers[{pname}].default_model mismatch"
        assert cp.timeout_seconds == dp.timeout_seconds, f"providers[{pname}].timeout_seconds mismatch"
        assert cp.max_retries == dp.max_retries, f"providers[{pname}].max_retries mismatch"

    for tname in _EXPECTED_TOOLS:
        ct = config.tools[tname]
        dt = default.tools[tname]
        assert ct.enabled == dt.enabled, f"tools[{tname}].enabled mismatch"
        assert ct.auto_install == dt.auto_install, f"tools[{tname}].auto_install mismatch"
        assert ct.startup_timeout_seconds == dt.startup_timeout_seconds, f"tools[{tname}].startup_timeout_seconds mismatch"
        assert ct.port == dt.port, f"tools[{tname}].port mismatch"

    assert config.sandbox.enabled == default.sandbox.enabled
    assert config.sandbox.timeout_seconds == default.sandbox.timeout_seconds
    assert config.sandbox.memory_limit_mb == default.sandbox.memory_limit_mb
    assert config.sandbox.network_enabled == default.sandbox.network_enabled

    assert config.ui.theme == default.ui.theme
    assert config.ui.font_family == default.ui.font_family
    assert config.ui.font_size == default.ui.font_size
    assert config.ui.show_tool_calls == default.ui.show_tool_calls

    assert config.session.auto_save == default.session.auto_save
    assert config.session.save_interval_seconds == default.session.save_interval_seconds
    assert config.session.retention_days == default.session.retention_days

    assert config.log.level == default.log.level
    assert config.log.file_enabled == default.log.file_enabled
    assert config.log.console_enabled == default.log.console_enabled
    assert config.log.max_file_size_mb == default.log.max_file_size_mb
    assert config.log.backup_count == default.log.backup_count
    assert config.log.retention_days == default.log.retention_days
    assert config.log.json_file == default.log.json_file


def test_config_from_dict_custom_general() -> None:
    """Verify from_dict with a custom general section parses that section while defaulting all others.

    Only the general section is overridden; all other sections must equal Config.default().
    This confirms that supplying a partial dict does not corrupt unrelated sections.
    """
    data: dict[str, Any] = {
        "general": {
            "default_provider": "openai",
            "confirmation_level": "none",
        },
    }
    config = Config.from_dict(data)
    assert config.default_provider == ProviderName.OPENAI
    assert config.confirmation_level == ConfirmationLevel.NONE

    default = Config.default()
    assert set(config.providers.keys()) == set(default.providers.keys()), "providers must be unchanged"
    assert set(config.tools.keys()) == set(default.tools.keys()), "tools must be unchanged"
    assert config.sandbox.enabled == default.sandbox.enabled
    assert config.sandbox.timeout_seconds == default.sandbox.timeout_seconds
    assert config.sandbox.memory_limit_mb == default.sandbox.memory_limit_mb
    assert config.sandbox.network_enabled == default.sandbox.network_enabled
    assert config.ui.theme == default.ui.theme
    assert config.ui.font_family == default.ui.font_family
    assert config.ui.font_size == default.ui.font_size
    assert config.session.auto_save == default.session.auto_save
    assert config.session.save_interval_seconds == default.session.save_interval_seconds
    assert config.log.level == default.log.level
    assert config.log.file_enabled == default.log.file_enabled


def test_config_from_dict_invalid_provider_fallback() -> None:
    """Verify from_dict falls back to ANTHROPIC for an unrecognised provider name.

    The fallback must be exactly ProviderName.ANTHROPIC (not None or any other
    provider).  Calling from_dict with the same bad value twice must produce
    the same fallback both times (determinism).
    """
    data: dict[str, Any] = {
        "general": {"default_provider": "nonexistent_provider_xyz"},
    }
    config1 = Config.from_dict(data)
    config2 = Config.from_dict(data)
    assert config1.default_provider == ProviderName.ANTHROPIC
    assert config2.default_provider == ProviderName.ANTHROPIC
    assert config1.default_provider is not None


def test_config_from_dict_invalid_confirmation_fallback() -> None:
    """Verify from_dict falls back to DESTRUCTIVE for an unrecognised confirmation level.

    The fallback must be exactly ConfirmationLevel.DESTRUCTIVE.  Calling from_dict
    with the same bad value twice must produce the same fallback both times (determinism).
    """
    data: dict[str, Any] = {
        "general": {"confirmation_level": "invalid_level_xyz"},
    }
    config1 = Config.from_dict(data)
    config2 = Config.from_dict(data)
    assert config1.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert config2.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert config1.confirmation_level is not None


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
    """Verify parse_tools handles path field and preserves all other tool fields at defaults.

    The path field must be parsed to a Path object.  All other GHIDRA fields
    (enabled, auto_install, startup_timeout_seconds, port) must retain their
    documented default values from _default_tools(), confirming that specifying
    one field does not silently zero out the others.
    """
    tools_data: dict[str, Any] = {
        "ghidra": {"path": "/opt/ghidra"},
    }
    result = Config.parse_tools(tools_data)
    assert result[ToolName.GHIDRA].path == Path("/opt/ghidra")
    assert result[ToolName.GHIDRA].enabled is True
    assert result[ToolName.GHIDRA].auto_install is True
    assert result[ToolName.GHIDRA].startup_timeout_seconds == 120
    assert result[ToolName.GHIDRA].port == 4768


def test_config_parse_sub_configs_defaults() -> None:
    """Verify parse_sub_configs returns complete defaults for empty data.

    Every field of every sub-config must match the documented default value.
    A one-field-per-sub-config check would miss regressions in the other fields.
    """
    sandbox, ui, session, log = Config.parse_sub_configs({})
    assert sandbox.enabled is True
    assert sandbox.timeout_seconds == _SANDBOX_TIMEOUT
    assert sandbox.memory_limit_mb == _SANDBOX_MEM
    assert sandbox.network_enabled is False

    assert ui.theme == "system"
    assert ui.font_family == "JetBrains Mono"
    assert ui.font_size == _DEFAULT_FONT_SIZE
    assert ui.show_tool_calls is True

    assert session.auto_save is True
    assert session.save_interval_seconds == _SESSION_INTERVAL
    assert session.retention_days == _SESSION_RETENTION

    assert log.level == "INFO"
    assert log.file_enabled is True
    assert log.console_enabled is True
    assert log.max_file_size_mb == _LOG_MAX_SIZE
    assert log.backup_count == _LOG_BACKUP_COUNT
    assert log.retention_days == _LOG_RETENTION
    assert log.json_file is True


def test_config_parse_sub_configs_custom() -> None:
    """Verify parse_sub_configs applies custom values while defaulting unspecified fields.

    Each sub-config specifies one custom field; all other fields must still match
    the documented defaults.  This confirms partial overrides do not corrupt
    unspecified fields.
    """
    data: dict[str, Any] = {
        "sandbox": {"network_enabled": True},
        "ui": {"theme": "light", "font_size": _CUSTOM_FONT_SIZE},
        "session": {"retention_days": _CUSTOM_RETENTION},
        "log": {"level": "DEBUG"},
    }
    sandbox, ui, session, log = Config.parse_sub_configs(data)

    assert sandbox.network_enabled is True
    assert sandbox.enabled is True
    assert sandbox.timeout_seconds == _SANDBOX_TIMEOUT
    assert sandbox.memory_limit_mb == _SANDBOX_MEM

    assert ui.theme == "light"
    assert ui.font_size == _CUSTOM_FONT_SIZE
    assert ui.font_family == "JetBrains Mono"
    assert ui.show_tool_calls is True

    assert session.retention_days == _CUSTOM_RETENTION
    assert session.auto_save is True
    assert session.save_interval_seconds == _SESSION_INTERVAL

    assert log.level == "DEBUG"
    assert log.file_enabled is True
    assert log.console_enabled is True
    assert log.max_file_size_mb == _LOG_MAX_SIZE
    assert log.backup_count == _LOG_BACKUP_COUNT
    assert log.retention_days == _LOG_RETENTION
    assert log.json_file is True


def test_config_load_from_toml(tmp_path: Path) -> None:
    """Verify Config.load reads and parses a TOML file.

    Covers: valid TOML file (multi-section parse), missing file (FileNotFoundError),
    and malformed TOML (tomllib.TOMLDecodeError).

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
    assert config.sandbox.timeout_seconds == _SANDBOX_TIMEOUT
    assert config.sandbox.memory_limit_mb == _SANDBOX_MEM
    assert config.ui.font_family == "JetBrains Mono"

    missing_path = tmp_path / "does_not_exist.toml"
    with pytest.raises(FileNotFoundError):
        Config.load(missing_path)

    bad_toml_path = tmp_path / "bad.toml"
    bad_toml_path.write_bytes(b"[general\ndefault_provider = 'openai'")
    with pytest.raises(tomllib.TOMLDecodeError):
        Config.load(bad_toml_path)


def test_config_save_and_reload(tmp_path: Path) -> None:
    """Verify save and reload produce an equivalent configuration across all sections.

    Covers: general (default_provider, confirmation_level, directories), providers
    (ANTHROPIC timeout, OLLAMA api_base, LOCAL_TRANSFORMERS model), tools (GHIDRA
    port/timeout, PROCESS auto_install=False), and all four sub-configs with
    non-default values.

    Args:
        tmp_path: Pytest temporary directory.
    """
    pytest.importorskip("tomli_w")

    config = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        default_provider=ProviderName.OPENAI,
        confirmation_level=ConfirmationLevel.NONE,
        sandbox=SandboxConfig(network_enabled=True, timeout_seconds=60, memory_limit_mb=512),
        ui=UIConfig(theme="dark", font_size=_CUSTOM_FONT_SIZE),
        session=SessionConfig(retention_days=_CUSTOM_RETENTION),
        log=LogConfig(level="DEBUG", backup_count=2),
    )

    save_path = tmp_path / "saved.toml"
    config.save(save_path)
    assert save_path.exists()

    reloaded = Config.load(save_path)

    assert reloaded.default_provider == ProviderName.OPENAI
    assert reloaded.confirmation_level == ConfirmationLevel.NONE
    assert str(reloaded.tools_directory) == str(config.tools_directory)
    assert str(reloaded.logs_directory) == str(config.logs_directory)
    assert str(reloaded.data_directory) == str(config.data_directory)

    assert reloaded.providers[ProviderName.ANTHROPIC].timeout_seconds == _DEFAULT_TIMEOUT
    assert reloaded.providers[ProviderName.ANTHROPIC].max_retries == _DEFAULT_RETRIES
    assert reloaded.providers[ProviderName.OLLAMA].api_base == "http://localhost:11434"
    assert reloaded.providers[ProviderName.LOCAL_TRANSFORMERS].default_model == "microsoft/Phi-3-mini-4k-instruct"

    assert reloaded.tools[ToolName.GHIDRA].port == 4768
    assert reloaded.tools[ToolName.GHIDRA].startup_timeout_seconds == 120
    assert reloaded.tools[ToolName.PROCESS].auto_install is False

    assert reloaded.sandbox.network_enabled is True
    assert reloaded.sandbox.timeout_seconds == 60
    assert reloaded.sandbox.memory_limit_mb == 512

    assert reloaded.ui.theme == "dark"
    assert reloaded.ui.font_size == _CUSTOM_FONT_SIZE

    assert reloaded.session.retention_days == _CUSTOM_RETENTION

    assert reloaded.log.level == "DEBUG"
    assert reloaded.log.backup_count == 2


def test_get_project_root_returns_repo_root() -> None:
    """Verify get_project_root returns the repository root.

    The root must exist, contain a ``src`` sub-directory, a ``pyproject.toml``
    file at the top level (present in this repo), and either a ``.git``
    directory or a ``pyproject.toml`` (both are reliable repo-root markers).
    """
    root = get_project_root()
    assert root.is_dir()
    assert root.is_absolute()
    assert (root / "src").is_dir()
    assert (root / "pyproject.toml").is_file(), "pyproject.toml must be at project root"


def test_get_config_dir_is_under_project_root() -> None:
    """Verify get_config_dir returns <project_root>/.intellicrack.

    The returned path must be absolute, have the correct name,
    and be a direct child of the project root.
    """
    config_dir = get_config_dir()
    assert config_dir.is_absolute()
    assert config_dir.name == ".intellicrack"
    assert config_dir.parent == get_project_root()


def test_get_config_file_joins_filename() -> None:
    """Verify get_config_file joins the filename under the config directory.

    The returned path must be absolute, have the requested name as its final
    component, and sit directly inside get_config_dir().
    """
    path = get_config_file("providers.json")
    assert path.is_absolute()
    assert path.name == "providers.json"
    assert path.parent == get_config_dir()
    assert str(path.parent) == str(get_config_dir())
