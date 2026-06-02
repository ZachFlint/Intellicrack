# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.config module - configuration management."""

from __future__ import annotations

import importlib
import os
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, TypedDict, cast

import pytest
import structlog

import intellicrack.core.config as config_module
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


if TYPE_CHECKING:
    from types import ModuleType


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

# Independently-known default counts and structural facts. These mirror the
# documented specification (the docstrings on the dataclasses and the
# _default_providers / _default_tools factories), not values captured from a
# live run. They act as the oracle for default Config structure.
_EXPECTED_PROVIDER_COUNT: Final[int] = 8
_EXPECTED_TOOL_COUNT: Final[int] = 5
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
_GHIDRA_STARTUP_TIMEOUT: Final[int] = 120
_GHIDRA_PORT: Final[int] = 4768
_X64DBG_STARTUP_TIMEOUT: Final[int] = 30
_OLLAMA_API_BASE: Final[str] = "http://localhost:11434"
_OLLAMA_TIMEOUT: Final[int] = 300
_TOP_LEVEL_SECTIONS: Final[frozenset[str]] = frozenset({"general", "providers", "tools", "sandbox", "ui", "session", "log"})
_TOMLI_W_BLOCKED_MSG: Final[str] = "tomli_w blocked for test"


def test_provider_config_defaults() -> None:
    """Verify every ProviderConfig default field matches the documented spec."""
    pc = ProviderConfig()
    assert pc.enabled is True
    assert pc.api_base is None
    assert pc.default_model is None
    assert pc.timeout_seconds == _DEFAULT_TIMEOUT
    assert pc.max_retries == _DEFAULT_RETRIES


def test_tool_config_defaults() -> None:
    """Verify every ToolConfig default field matches the documented spec."""
    tc = ToolConfig()
    assert tc.enabled is True
    assert tc.path is None
    assert tc.auto_install is True
    assert tc.startup_timeout_seconds == _TOOL_STARTUP
    assert tc.port is None


def test_sandbox_config_defaults() -> None:
    """Verify every SandboxConfig default field matches the documented spec."""
    sc = SandboxConfig()
    assert sc.enabled is True
    assert sc.timeout_seconds == _SANDBOX_TIMEOUT
    assert sc.memory_limit_mb == _SANDBOX_MEM
    assert sc.network_enabled is False


def test_ui_config_defaults() -> None:
    """Verify every UIConfig default field matches the documented spec."""
    uc = UIConfig()
    assert uc.theme == "system"
    assert uc.font_family == "JetBrains Mono"
    assert uc.font_size == _DEFAULT_FONT_SIZE
    assert uc.show_tool_calls is True


def test_session_config_defaults() -> None:
    """Verify every SessionConfig default field matches the documented spec."""
    sc = SessionConfig()
    assert sc.auto_save is True
    assert sc.save_interval_seconds == _SESSION_INTERVAL
    assert sc.retention_days == _SESSION_RETENTION


def test_log_config_defaults() -> None:
    """Verify every LogConfig default field matches the documented spec."""
    lc = LogConfig()
    assert lc.level == "INFO"
    assert lc.file_enabled is True
    assert lc.console_enabled is True
    assert lc.max_file_size_mb == _LOG_MAX_SIZE
    assert lc.backup_count == _LOG_BACKUP_COUNT
    assert lc.retention_days == _LOG_RETENTION
    assert lc.json_file is True


def test_config_default() -> None:
    """Verify Config.default() builds the full documented provider/tool structure."""
    config = Config.default()

    assert config.default_provider == ProviderName.ANTHROPIC
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE

    # Exact provider/tool membership and count, not mere key presence.
    assert set(config.providers) == set(_EXPECTED_PROVIDERS)
    assert len(config.providers) == _EXPECTED_PROVIDER_COUNT
    assert set(config.tools) == set(_EXPECTED_TOOLS)
    assert len(config.tools) == _EXPECTED_TOOL_COUNT

    # Provider-specific configuration values that distinguish providers.
    ollama = config.providers[ProviderName.OLLAMA]
    assert ollama.api_base == _OLLAMA_API_BASE
    assert ollama.timeout_seconds == _OLLAMA_TIMEOUT
    transformers = config.providers[ProviderName.LOCAL_TRANSFORMERS]
    assert transformers.default_model == "microsoft/Phi-3-mini-4k-instruct"
    assert transformers.max_retries == 1

    # Tool-specific configuration values that distinguish tools.
    ghidra = config.tools[ToolName.GHIDRA]
    assert ghidra.port == _GHIDRA_PORT
    assert ghidra.startup_timeout_seconds == _GHIDRA_STARTUP_TIMEOUT
    assert config.tools[ToolName.PROCESS].auto_install is False

    # Every top-level section is present in the serialised form.
    serialised = _config_to_dict(config)
    assert set(serialised) == set(_TOP_LEVEL_SECTIONS)


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


def test_config_ensure_directories_nested_parents(tmp_path: Path) -> None:
    """Verify ensure_directories creates missing intermediate parent directories.

    Args:
        tmp_path: Pytest temporary directory.
    """
    config = Config(
        tools_directory=tmp_path / "a" / "b" / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    config.ensure_directories()
    assert (tmp_path / "a" / "b" / "tools").is_dir()


def test_config_ensure_directories_idempotent(tmp_path: Path) -> None:
    """Verify ensure_directories preserves existing content and does not raise.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    sentinel = tools_dir / "sentinel.txt"
    sentinel.write_text("keep-me", encoding="utf-8")

    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    config.ensure_directories()
    config.ensure_directories()

    assert tools_dir.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "keep-me"


def test_config_ensure_directories_file_collision(tmp_path: Path) -> None:
    """Verify ensure_directories raises when a target path is an existing file.

    Args:
        tmp_path: Pytest temporary directory.
    """
    collision = tmp_path / "tools"
    collision.write_text("not-a-directory", encoding="utf-8")

    config = Config(
        tools_directory=collision,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    with pytest.raises((FileExistsError, NotADirectoryError)):
        config.ensure_directories()


def test_config_get_provider_config() -> None:
    """Verify get_provider_config returns the ANTHROPIC-specific stored config."""
    config = Config.default()
    pc = config.get_provider_config(ProviderName.ANTHROPIC)

    # Identity: returns the exact stored instance, not a fresh default.
    assert pc is config.providers[ProviderName.ANTHROPIC]
    assert pc.enabled is True
    assert pc.api_base is None
    assert pc.default_model is None
    assert pc.timeout_seconds == _DEFAULT_TIMEOUT
    assert pc.max_retries == _DEFAULT_RETRIES

    # Distinct from another provider's stored config.
    ollama = config.get_provider_config(ProviderName.OLLAMA)
    assert ollama is not pc
    assert ollama.api_base == _OLLAMA_API_BASE


def test_config_get_provider_config_unknown() -> None:
    """Verify get_provider_config returns a fresh independent default when absent."""
    config = Config(providers={})

    first = config.get_provider_config(ProviderName.GROK)
    second = config.get_provider_config(ProviderName.GROK)

    # Each lookup of a missing provider yields a brand-new default instance.
    assert first is not second
    assert first == ProviderConfig()
    assert second == ProviderConfig()

    # Mutating one fallback must not bleed into the next (no shared cache).
    first.enabled = False
    assert config.get_provider_config(ProviderName.GROK).enabled is True


def test_config_get_tool_config() -> None:
    """Verify get_tool_config returns the GHIDRA-specific stored config."""
    config = Config.default()
    tc = config.get_tool_config(ToolName.GHIDRA)

    assert tc is config.tools[ToolName.GHIDRA]
    assert tc.enabled is True
    assert tc.auto_install is True
    assert tc.startup_timeout_seconds == _GHIDRA_STARTUP_TIMEOUT
    assert tc.port == _GHIDRA_PORT

    # GHIDRA's port and timeout differ from X64DBG's, proving tool specificity.
    x64dbg = config.get_tool_config(ToolName.X64DBG)
    assert x64dbg.port is None
    assert x64dbg.startup_timeout_seconds == _X64DBG_STARTUP_TIMEOUT
    assert x64dbg.startup_timeout_seconds != tc.startup_timeout_seconds


def test_config_is_provider_enabled_distinguishes_states() -> None:
    """Verify is_provider_enabled reflects per-provider enabled flags."""
    config = Config(
        providers={
            ProviderName.ANTHROPIC: ProviderConfig(enabled=False),
            ProviderName.OPENAI: ProviderConfig(enabled=True),
        },
    )
    assert config.is_provider_enabled(ProviderName.ANTHROPIC) is False
    assert config.is_provider_enabled(ProviderName.OPENAI) is True

    # A default config reports ANTHROPIC enabled.
    assert Config.default().is_provider_enabled(ProviderName.ANTHROPIC) is True


def test_config_is_tool_enabled_distinguishes_states() -> None:
    """Verify is_tool_enabled reflects per-tool enabled flags."""
    config = Config(
        tools={
            ToolName.GHIDRA: ToolConfig(enabled=False),
            ToolName.X64DBG: ToolConfig(enabled=True),
        },
    )
    assert config.is_tool_enabled(ToolName.GHIDRA) is False
    assert config.is_tool_enabled(ToolName.X64DBG) is True

    assert Config.default().is_tool_enabled(ToolName.GHIDRA) is True


def test_config_to_dict_from_dict_full_round_trip() -> None:
    """Verify _to_dict and from_dict preserve every section field for field."""
    original = Config(
        default_provider=ProviderName.OPENAI,
        confirmation_level=ConfirmationLevel.ALL,
        providers={
            ProviderName.ANTHROPIC: ProviderConfig(
                enabled=False,
                api_base="https://proxy.example/v1",
                default_model="claude-custom",
                timeout_seconds=99,
                max_retries=7,
            ),
        },
        tools={
            ToolName.GHIDRA: ToolConfig(
                enabled=False,
                path=Path("/opt/ghidra"),
                auto_install=False,
                startup_timeout_seconds=42,
                port=4768,
            ),
        },
        sandbox=SandboxConfig(enabled=False, timeout_seconds=11, memory_limit_mb=64, network_enabled=True),
        ui=UIConfig(theme="dark", font_family="Consolas", font_size=_CUSTOM_FONT_SIZE, show_tool_calls=False),
        session=SessionConfig(auto_save=False, save_interval_seconds=17, retention_days=_CUSTOM_RETENTION),
        log=LogConfig(
            level="DEBUG",
            file_enabled=False,
            console_enabled=False,
            max_file_size_mb=3,
            backup_count=9,
            retention_days=21,
            json_file=False,
        ),
    )

    serialised = cast(dict[str, Any], _config_to_dict(original))
    restored = Config.from_dict(serialised)

    assert restored.default_provider == original.default_provider
    assert restored.confirmation_level == original.confirmation_level

    restored_anthropic = restored.providers[ProviderName.ANTHROPIC]
    assert restored_anthropic == original.providers[ProviderName.ANTHROPIC]

    restored_ghidra = restored.tools[ToolName.GHIDRA]
    assert restored_ghidra == original.tools[ToolName.GHIDRA]

    assert restored.sandbox == original.sandbox
    assert restored.ui == original.ui
    assert restored.session == original.session
    assert restored.log == original.log


def test_config_from_dict_empty_matches_default() -> None:
    """Verify Config.from_dict({}) reproduces the full Config.default() structure."""
    config = Config.from_dict({})
    default = Config.default()

    assert config.default_provider == default.default_provider
    assert config.confirmation_level == default.confirmation_level
    assert config.providers == default.providers
    assert config.tools == default.tools
    assert config.sandbox == default.sandbox
    assert config.ui == default.ui
    assert config.session == default.session
    assert config.log == default.log


def test_config_from_dict_custom_general_preserves_other_defaults() -> None:
    """Verify a custom general section leaves all other sections at their defaults."""
    data: dict[str, Any] = {
        "general": {
            "default_provider": "openai",
            "confirmation_level": "none",
        },
    }
    config = Config.from_dict(data)
    default = Config.default()

    assert config.default_provider == ProviderName.OPENAI
    assert config.confirmation_level == ConfirmationLevel.NONE

    # Unspecified sections fall back to documented defaults.
    assert config.sandbox == default.sandbox
    assert config.ui == default.ui
    assert config.session == default.session
    assert config.log == default.log
    assert config.providers == default.providers
    assert config.tools == default.tools


def test_config_from_dict_invalid_provider_fallback() -> None:
    """Verify an invalid provider name falls back to ANTHROPIC and logs a warning."""
    data: dict[str, Any] = {
        "general": {"default_provider": "nonexistent"},
    }
    with structlog.testing.capture_logs() as logs:
        config = Config.from_dict(data)

    assert config.default_provider == ProviderName.ANTHROPIC

    warnings = [entry for entry in logs if entry.get("event") == "config_invalid_provider_name"]
    assert len(warnings) == 1
    assert warnings[0]["log_level"] == "warning"
    assert warnings[0]["value"] == "nonexistent"
    assert warnings[0]["fallback"] == "anthropic"


def test_config_from_dict_invalid_confirmation_fallback() -> None:
    """Verify an invalid confirmation level falls back to DESTRUCTIVE and logs a warning."""
    data: dict[str, Any] = {
        "general": {"confirmation_level": "badvalue"},
    }
    with structlog.testing.capture_logs() as logs:
        config = Config.from_dict(data)

    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE

    warnings = [entry for entry in logs if entry.get("event") == "config_invalid_confirmation_level"]
    assert len(warnings) == 1
    assert warnings[0]["log_level"] == "warning"
    assert warnings[0]["value"] == "badvalue"
    assert warnings[0]["fallback"] == "destructive"


def test_config_parse_providers_unknown_skipped() -> None:
    """Verify parse_providers applies known overrides and skips unknown keys with a warning."""
    providers_data: dict[str, Any] = {
        "anthropic": {"enabled": False, "timeout_seconds": 45},
        "unknown_provider": {"enabled": True},
    }
    with structlog.testing.capture_logs() as logs:
        result = Config.parse_providers(providers_data)

    # Result keyset is exactly the known providers; nothing was added.
    assert set(result) == set(_EXPECTED_PROVIDERS)
    assert len(result) == _EXPECTED_PROVIDER_COUNT

    # Override applied to the known provider.
    assert result[ProviderName.ANTHROPIC].enabled is False
    assert result[ProviderName.ANTHROPIC].timeout_seconds == 45

    # Untouched known provider keeps its default.
    assert result[ProviderName.OPENAI].enabled is True
    assert result[ProviderName.OPENAI].timeout_seconds == _DEFAULT_TIMEOUT

    skipped = [entry for entry in logs if entry.get("event") == "config_unknown_provider_skipped"]
    assert len(skipped) == 1
    assert skipped[0]["value"] == "unknown_provider"


def test_config_parse_tools_unknown_skipped() -> None:
    """Verify parse_tools applies known overrides and skips unknown keys with a warning."""
    tools_data: dict[str, Any] = {
        "ghidra": {"enabled": False},
        "unknown_tool": {"enabled": True},
    }
    with structlog.testing.capture_logs() as logs:
        result = Config.parse_tools(tools_data)

    assert set(result) == set(_EXPECTED_TOOLS)
    assert len(result) == _EXPECTED_TOOL_COUNT

    assert result[ToolName.GHIDRA].enabled is False
    # GHIDRA's non-overridden fields keep their documented defaults.
    assert result[ToolName.GHIDRA].port == _GHIDRA_PORT
    assert result[ToolName.GHIDRA].startup_timeout_seconds == _GHIDRA_STARTUP_TIMEOUT
    # An untouched tool keeps its full default.
    assert result[ToolName.FRIDA].enabled is True

    skipped = [entry for entry in logs if entry.get("event") == "config_unknown_tool_skipped"]
    assert len(skipped) == 1
    assert skipped[0]["value"] == "unknown_tool"


def test_config_parse_tools_with_path() -> None:
    """Verify parse_tools converts a string path to Path and keeps other defaults."""
    tools_data: dict[str, Any] = {
        "ghidra": {"path": "/opt/ghidra"},
    }
    result = Config.parse_tools(tools_data)
    ghidra = result[ToolName.GHIDRA]

    assert ghidra.path == Path("/opt/ghidra")
    # Non-path fields remain at the GHIDRA defaults.
    assert ghidra.enabled is True
    assert ghidra.auto_install is True
    assert ghidra.startup_timeout_seconds == _GHIDRA_STARTUP_TIMEOUT
    assert ghidra.port == _GHIDRA_PORT


def test_config_parse_tools_invalid_path_type_falls_back() -> None:
    """Verify a non-string path value is rejected and logged, keeping the default."""
    tools_data: dict[str, Any] = {
        "ghidra": {"path": 12345},
    }
    with structlog.testing.capture_logs() as logs:
        result = Config.parse_tools(tools_data)

    # The invalid path is not accepted; the GHIDRA default (None) is preserved.
    assert result[ToolName.GHIDRA].path is None

    warnings = [entry for entry in logs if entry.get("event") == "config_invalid_tool_path"]
    assert len(warnings) == 1
    assert warnings[0]["tool"] == "ghidra"
    assert warnings[0]["value"] == repr(12345)


def test_config_parse_sub_configs_defaults() -> None:
    """Verify parse_sub_configs returns fully-default sub-configs for empty data."""
    sandbox, ui, session, log = Config.parse_sub_configs({})

    assert sandbox == SandboxConfig()
    assert ui == UIConfig()
    assert session == SessionConfig()
    assert log == LogConfig()


def test_config_parse_sub_configs_custom() -> None:
    """Verify parse_sub_configs applies custom values and defaults unspecified fields."""
    data: dict[str, Any] = {
        "sandbox": {"network_enabled": True},
        "ui": {"theme": "light", "font_size": _CUSTOM_FONT_SIZE},
        "session": {"retention_days": _CUSTOM_RETENTION},
        "log": {"level": "DEBUG"},
    }
    sandbox, ui, session, log = Config.parse_sub_configs(data)

    # Custom overrides applied.
    assert sandbox.network_enabled is True
    assert ui.theme == "light"
    assert ui.font_size == _CUSTOM_FONT_SIZE
    assert session.retention_days == _CUSTOM_RETENTION
    assert log.level == "DEBUG"

    # Unspecified fields fall back to documented defaults.
    assert sandbox.enabled is True
    assert sandbox.timeout_seconds == _SANDBOX_TIMEOUT
    assert sandbox.memory_limit_mb == _SANDBOX_MEM
    assert ui.font_family == "JetBrains Mono"
    assert ui.show_tool_calls is True
    assert session.auto_save is True
    assert session.save_interval_seconds == _SESSION_INTERVAL
    assert log.file_enabled is True
    assert log.console_enabled is True
    assert log.max_file_size_mb == _LOG_MAX_SIZE
    assert log.backup_count == _LOG_BACKUP_COUNT
    assert log.retention_days == _LOG_RETENTION
    assert log.json_file is True


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
    # Unspecified sections remain at defaults after a real TOML load.
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert config.log.level == "INFO"


def test_config_load_missing_file_raises(tmp_path: Path) -> None:
    """Verify Config.load raises FileNotFoundError for a non-existent path.

    Args:
        tmp_path: Pytest temporary directory.
    """
    missing = tmp_path / "does-not-exist.toml"
    with pytest.raises(FileNotFoundError):
        Config.load(missing)


def test_config_load_malformed_toml_raises(tmp_path: Path) -> None:
    """Verify Config.load surfaces a TOML decode error for malformed content.

    Args:
        tmp_path: Pytest temporary directory.
    """
    bad = tmp_path / "bad.toml"
    bad.write_bytes(b"[general\ndefault_provider = ")
    with pytest.raises(tomllib.TOMLDecodeError):
        Config.load(bad)


def test_config_save_and_reload(tmp_path: Path) -> None:
    """Verify save then load round-trips every non-default field exactly.

    Args:
        tmp_path: Pytest temporary directory.
    """
    pytest.importorskip("tomli_w")

    original = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        default_provider=ProviderName.OPENAI,
        confirmation_level=ConfirmationLevel.ALL,
        providers={
            ProviderName.OPENAI: ProviderConfig(
                enabled=True,
                api_base="https://proxy.example/v1",
                default_model="gpt-custom",
                timeout_seconds=88,
                max_retries=2,
            ),
        },
        tools={
            ToolName.GHIDRA: ToolConfig(
                enabled=False,
                path=tmp_path / "ghidra",
                auto_install=False,
                startup_timeout_seconds=33,
                port=5000,
            ),
        },
        sandbox=SandboxConfig(enabled=False, timeout_seconds=15, memory_limit_mb=128, network_enabled=True),
        ui=UIConfig(theme="dark", font_family="Consolas", font_size=_CUSTOM_FONT_SIZE, show_tool_calls=False),
        session=SessionConfig(auto_save=False, save_interval_seconds=22, retention_days=_CUSTOM_RETENTION),
        log=LogConfig(
            level="WARNING",
            file_enabled=False,
            console_enabled=True,
            max_file_size_mb=7,
            backup_count=8,
            retention_days=20,
            json_file=False,
        ),
    )

    save_path = tmp_path / "saved.toml"
    original.save(save_path)
    assert save_path.exists()

    reloaded = Config.load(save_path)

    assert reloaded.default_provider == ProviderName.OPENAI
    assert reloaded.confirmation_level == ConfirmationLevel.ALL
    assert str(reloaded.tools_directory) == str(original.tools_directory)
    assert str(reloaded.logs_directory) == str(original.logs_directory)
    assert str(reloaded.data_directory) == str(original.data_directory)

    assert reloaded.providers[ProviderName.OPENAI] == original.providers[ProviderName.OPENAI]
    assert reloaded.tools[ToolName.GHIDRA] == original.tools[ToolName.GHIDRA]
    assert reloaded.sandbox == original.sandbox
    assert reloaded.ui == original.ui
    assert reloaded.session == original.session
    assert reloaded.log == original.log


def test_config_save_without_tomli_w_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify save raises ImportError when the tomli_w writer is unavailable.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture used to hide the optional dependency.
    """
    real_import_module = importlib.import_module

    def _blocked_import_module(name: str, package: str | None = None) -> ModuleType:
        if name == "tomli_w":
            raise ImportError(_TOMLI_W_BLOCKED_MSG)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", _blocked_import_module)

    config = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    with pytest.raises(ImportError, match="tomli_w"):
        config.save(tmp_path / "out.toml")


def test_get_project_root_returns_repo_root() -> None:
    """Verify get_project_root returns the repository root with its marker files."""
    root = get_project_root()
    assert root.is_dir()
    assert (root / "src").is_dir()
    # Marker files that uniquely identify the Intellicrack repository root.
    assert (root / "pyproject.toml").is_file()
    assert (root / "src" / "intellicrack" / "core" / "config.py").is_file()
    # The package this very module imports lives under the detected root.
    module_file = config_module.__file__
    assert module_file is not None
    assert Path(module_file).resolve().is_relative_to(root)


def test_get_config_dir_is_under_project_root() -> None:
    """Verify get_config_dir returns a writable <project_root>/.intellicrack directory."""
    config_dir = get_config_dir()
    assert config_dir.name == ".intellicrack"
    assert config_dir.parent == get_project_root()
    assert config_dir.is_absolute()


def test_get_config_dir_is_writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the resolved config directory can actually hold a written file.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture used to relocate the project root.
    """
    monkeypatch.setattr(config_module, "get_project_root", lambda: tmp_path)

    config_dir = config_module.get_config_dir()
    assert config_dir == tmp_path / ".intellicrack"

    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_module.get_config_file("providers.json")
    target.write_text('{"k": 1}', encoding="utf-8")
    assert target.read_text(encoding="utf-8") == '{"k": 1}'
    assert target.parent == config_dir


def test_get_config_file_joins_filename() -> None:
    """Verify get_config_file returns an absolute path under the config directory."""
    path = get_config_file("providers.json")
    assert path.name == "providers.json"
    assert path.parent == get_config_dir()
    assert path.is_absolute()
    # The OS-native separator is used in the rendered path.
    assert os.sep in str(path)
