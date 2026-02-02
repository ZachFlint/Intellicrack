"""Configuration management for Intellicrack.

This module provides the complete configuration system including loading
from TOML files, saving, and default configurations for all components.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .logging import get_logger
from .types import ConfirmationLevel, ProviderName, ToolName


_logger = get_logger("core.config")


_ERR_TOMLI_W_REQUIRED = "tomli_w is required for saving config"


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider.

    Attributes:
        enabled: Whether this provider is enabled.
        api_base: Custom API base URL if any.
        default_model: Default model to use for this provider.
        timeout_seconds: Request timeout in seconds.
        max_retries: Maximum number of retry attempts.
    """

    enabled: bool = True
    api_base: str | None = None
    default_model: str | None = None
    timeout_seconds: int = 120
    max_retries: int = 3


@dataclass
class ToolConfig:
    """Configuration for a single tool.

    Attributes:
        enabled: Whether this tool is enabled.
        path: Custom path to tool installation.
        auto_install: Whether to auto-install if not found.
        startup_timeout_seconds: Timeout for tool startup.
    """

    enabled: bool = True
    path: Path | None = None
    auto_install: bool = True
    startup_timeout_seconds: int = 60


@dataclass
class SandboxConfig:
    """Windows Sandbox configuration.

    Attributes:
        enabled: Whether sandbox is enabled.
        timeout_seconds: Maximum execution time in sandbox.
        memory_limit_mb: Memory limit in megabytes.
        network_enabled: Whether networking is enabled in sandbox.
    """

    enabled: bool = True
    timeout_seconds: int = 300
    memory_limit_mb: int = 2048
    network_enabled: bool = False


@dataclass
class UIConfig:
    """User interface configuration.

    Attributes:
        theme: UI theme name.
        font_family: Font family for code display.
        font_size: Font size in points.
        show_tool_calls: Whether to show tool calls in chat.
    """

    theme: str = "dark"
    font_family: str = "JetBrains Mono"
    font_size: int = 11
    show_tool_calls: bool = True


@dataclass
class SessionConfig:
    """Session persistence configuration.

    Attributes:
        auto_save: Whether to auto-save sessions.
        save_interval_seconds: Interval between auto-saves.
        retention_days: Number of days to retain sessions.
    """

    auto_save: bool = True
    save_interval_seconds: int = 300
    retention_days: int = 7


@dataclass
class LogConfig:
    """Logging configuration.

    Attributes:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        file_enabled: Whether to log to file.
        console_enabled: Whether to log to console.
        max_file_size_mb: Maximum log file size in megabytes.
        backup_count: Number of backup log files to keep.
        retention_days: Number of days to retain log files before cleanup.
        json_file: Whether to output JSON formatted logs to file.
    """

    level: str = "INFO"
    file_enabled: bool = True
    console_enabled: bool = True
    max_file_size_mb: int = 10
    backup_count: int = 5
    retention_days: int = 14
    json_file: bool = True


def _default_providers() -> dict[ProviderName, ProviderConfig]:
    """Create default provider configurations.

    Returns:
        Dictionary mapping provider names to their default configurations.
    """
    return {
        ProviderName.ANTHROPIC: ProviderConfig(
            enabled=True,
            default_model="claude-sonnet-4-20250514",
            timeout_seconds=120,
            max_retries=3,
        ),
        ProviderName.OPENAI: ProviderConfig(
            enabled=True,
            default_model="gpt-4o",
            timeout_seconds=120,
            max_retries=3,
        ),
        ProviderName.GOOGLE: ProviderConfig(
            enabled=True,
            default_model="gemini-2.0-flash",
            timeout_seconds=120,
            max_retries=3,
        ),
        ProviderName.OLLAMA: ProviderConfig(
            enabled=True,
            api_base="http://localhost:11434",
            timeout_seconds=300,
            max_retries=3,
        ),
        ProviderName.OPENROUTER: ProviderConfig(
            enabled=True,
            api_base="https://openrouter.ai/api/v1",
            timeout_seconds=120,
            max_retries=3,
        ),
        ProviderName.LOCAL_TRANSFORMERS: ProviderConfig(
            enabled=True,
            default_model="microsoft/Phi-3-mini-4k-instruct",
            timeout_seconds=600,
            max_retries=1,
        ),
    }


def _default_tools() -> dict[ToolName, ToolConfig]:
    """Create default tool configurations.

    Returns:
        Dictionary mapping tool names to their default configurations.
    """
    return {
        ToolName.GHIDRA: ToolConfig(
            enabled=True,
            auto_install=True,
            startup_timeout_seconds=120,
        ),
        ToolName.X64DBG: ToolConfig(
            enabled=True,
            auto_install=True,
            startup_timeout_seconds=30,
        ),
        ToolName.FRIDA: ToolConfig(
            enabled=True,
            auto_install=True,
            startup_timeout_seconds=10,
        ),
        ToolName.RADARE2: ToolConfig(
            enabled=True,
            auto_install=True,
            startup_timeout_seconds=10,
        ),
        ToolName.PROCESS: ToolConfig(
            enabled=True,
            auto_install=False,
            startup_timeout_seconds=5,
        ),
        ToolName.BINARY: ToolConfig(
            enabled=True,
            auto_install=False,
            startup_timeout_seconds=5,
        ),
    }


@dataclass
class Config:
    """Complete application configuration.

    Attributes:
        tools_directory: Directory for auto-installed tools.
        logs_directory: Directory for log files.
        data_directory: Directory for session data and caches.
        default_provider: Default LLM provider to use.
        confirmation_level: When to require user confirmation.
        providers: Configuration for each LLM provider.
        tools: Configuration for each tool.
        sandbox: Sandbox configuration.
        ui: UI configuration.
        session: Session configuration.
        log: Logging configuration.
    """

    tools_directory: Path = field(default_factory=lambda: Path("D:/Intellicrack/tools"))
    logs_directory: Path = field(default_factory=lambda: Path("D:/Intellicrack/logs"))
    data_directory: Path = field(default_factory=lambda: Path("D:/Intellicrack/data"))

    default_provider: ProviderName = ProviderName.ANTHROPIC
    confirmation_level: ConfirmationLevel = ConfirmationLevel.DESTRUCTIVE

    providers: dict[ProviderName, ProviderConfig] = field(default_factory=_default_providers)
    tools: dict[ToolName, ToolConfig] = field(default_factory=_default_tools)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    log: LogConfig = field(default_factory=LogConfig)

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load configuration from TOML file.

        Args:
            path: Path to the TOML configuration file.

        Returns:
            Loaded Config instance with defaults for missing values.
        """
        _logger.debug("config_load_started", extra={"path": str(path)})
        with path.open("rb") as f:
            data = tomllib.load(f)

        config = cls._from_dict(data)
        _logger.info(
            "config_loaded",
            extra={
                "path": str(path),
                "providers_count": len(config.providers),
                "tools_count": len(config.tools),
            },
        )
        return config

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Config:  # noqa: PLR0914
        """Create Config from dictionary.

        Args:
            data: Dictionary with configuration values.

        Returns:
            Config instance with values from dict and defaults for missing.
        """
        general = data.get("general", {})

        tools_dir = general.get("tools_directory", "D:/Intellicrack/tools")
        logs_dir = general.get("logs_directory", "D:/Intellicrack/logs")
        data_dir = general.get("data_directory", "D:/Intellicrack/data")

        default_provider_str = general.get("default_provider", "anthropic")
        try:
            default_provider = ProviderName(default_provider_str)
        except ValueError:
            _logger.warning(
                "config_invalid_provider_name",
                extra={"value": default_provider_str, "fallback": ProviderName.ANTHROPIC.value},
            )
            default_provider = ProviderName.ANTHROPIC

        confirmation_str = general.get("confirmation_level", "destructive")
        try:
            confirmation_level = ConfirmationLevel(confirmation_str)
        except ValueError:
            _logger.warning(
                "config_invalid_confirmation_level",
                extra={"value": confirmation_str, "fallback": ConfirmationLevel.DESTRUCTIVE.value},
            )
            confirmation_level = ConfirmationLevel.DESTRUCTIVE

        providers = _default_providers()
        providers_data = data.get("providers", {})
        for name_str, prov_data in providers_data.items():
            try:
                provider_name = ProviderName(name_str)
            except ValueError:
                _logger.warning(
                    "config_unknown_provider_skipped",
                    extra={"value": name_str},
                )
                continue

            if provider_name in providers:
                prov_base = providers[provider_name]
                providers[provider_name] = ProviderConfig(
                    enabled=prov_data.get("enabled", prov_base.enabled),
                    api_base=prov_data.get("api_base", prov_base.api_base),
                    default_model=prov_data.get("default_model", prov_base.default_model),
                    timeout_seconds=prov_data.get("timeout_seconds", prov_base.timeout_seconds),
                    max_retries=prov_data.get("max_retries", prov_base.max_retries),
                )

        tools = _default_tools()
        tools_data = data.get("tools", {})
        for name_str, tool_data in tools_data.items():
            try:
                tool_name = ToolName(name_str)
            except ValueError:
                _logger.warning(
                    "config_unknown_tool_skipped",
                    extra={"value": name_str},
                )
                continue

            if tool_name in tools:
                tool_base = tools[tool_name]
                path_str = tool_data.get("path")
                tool_path = Path(path_str) if path_str else tool_base.path
                tools[tool_name] = ToolConfig(
                    enabled=tool_data.get("enabled", tool_base.enabled),
                    path=tool_path,
                    auto_install=tool_data.get("auto_install", tool_base.auto_install),
                    startup_timeout_seconds=tool_data.get("startup_timeout_seconds", tool_base.startup_timeout_seconds),
                )

        sandbox_data = data.get("sandbox", {})
        sandbox = SandboxConfig(
            enabled=sandbox_data.get("enabled", True),
            timeout_seconds=sandbox_data.get("timeout_seconds", 300),
            memory_limit_mb=sandbox_data.get("memory_limit_mb", 2048),
            network_enabled=sandbox_data.get("network_enabled", False),
        )

        ui_data = data.get("ui", {})
        ui = UIConfig(
            theme=ui_data.get("theme", "dark"),
            font_family=ui_data.get("font_family", "JetBrains Mono"),
            font_size=ui_data.get("font_size", 11),
            show_tool_calls=ui_data.get("show_tool_calls", True),
        )

        session_data = data.get("session", {})
        session = SessionConfig(
            auto_save=session_data.get("auto_save", True),
            save_interval_seconds=session_data.get("save_interval_seconds", 300),
            retention_days=session_data.get("retention_days", 7),
        )

        log_data = data.get("log", {})
        log = LogConfig(
            level=log_data.get("level", "INFO"),
            file_enabled=log_data.get("file_enabled", True),
            console_enabled=log_data.get("console_enabled", True),
            max_file_size_mb=log_data.get("max_file_size_mb", 10),
            backup_count=log_data.get("backup_count", 5),
            retention_days=log_data.get("retention_days", 14),
            json_file=log_data.get("json_file", True),
        )

        return cls(
            tools_directory=Path(tools_dir),
            logs_directory=Path(logs_dir),
            data_directory=Path(data_dir),
            default_provider=default_provider,
            confirmation_level=confirmation_level,
            providers=providers,
            tools=tools,
            sandbox=sandbox,
            ui=ui,
            session=session,
            log=log,
        )

    def save(self, path: Path) -> None:
        """Save configuration to TOML file.

        Args:
            path: Path to write the TOML configuration file.

        Raises:
            ImportError: If tomli_w is not installed.
        """
        _logger.debug("config_save_started", extra={"path": str(path)})
        try:
            import tomli_w  # noqa: PLC0415
        except ImportError as err:
            _logger.exception("config_save_failed", extra={"reason": "tomli_w_not_installed"})
            raise ImportError(_ERR_TOMLI_W_REQUIRED) from err

        data = self._to_dict()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            tomli_w.dump(data, f)
        _logger.info("config_saved", extra={"path": str(path)})

    def _to_dict(self) -> dict[str, Any]:
        """Convert Config to dictionary for TOML serialization.

        Returns:
            Dictionary representation of the configuration.
        """
        data: dict[str, Any] = {
            "general": {
                "tools_directory": str(self.tools_directory),
                "logs_directory": str(self.logs_directory),
                "data_directory": str(self.data_directory),
                "default_provider": self.default_provider.value,
                "confirmation_level": self.confirmation_level.value,
            },
            "providers": {},
            "tools": {},
            "sandbox": {
                "enabled": self.sandbox.enabled,
                "timeout_seconds": self.sandbox.timeout_seconds,
                "memory_limit_mb": self.sandbox.memory_limit_mb,
                "network_enabled": self.sandbox.network_enabled,
            },
            "ui": {
                "theme": self.ui.theme,
                "font_family": self.ui.font_family,
                "font_size": self.ui.font_size,
                "show_tool_calls": self.ui.show_tool_calls,
            },
            "session": {
                "auto_save": self.session.auto_save,
                "save_interval_seconds": self.session.save_interval_seconds,
                "retention_days": self.session.retention_days,
            },
            "log": {
                "level": self.log.level,
                "file_enabled": self.log.file_enabled,
                "console_enabled": self.log.console_enabled,
                "max_file_size_mb": self.log.max_file_size_mb,
                "backup_count": self.log.backup_count,
                "retention_days": self.log.retention_days,
                "json_file": self.log.json_file,
            },
        }

        for prov_name, prov_config in self.providers.items():
            prov_dict: dict[str, Any] = {
                "enabled": prov_config.enabled,
                "timeout_seconds": prov_config.timeout_seconds,
                "max_retries": prov_config.max_retries,
            }
            if prov_config.api_base:
                prov_dict["api_base"] = prov_config.api_base
            if prov_config.default_model:
                prov_dict["default_model"] = prov_config.default_model
            data["providers"][prov_name.value] = prov_dict

        for tool_name, tool_config in self.tools.items():
            tool_dict: dict[str, Any] = {
                "enabled": tool_config.enabled,
                "auto_install": tool_config.auto_install,
                "startup_timeout_seconds": tool_config.startup_timeout_seconds,
            }
            if tool_config.path:
                tool_dict["path"] = str(tool_config.path)
            data["tools"][tool_name.value] = tool_dict

        return data

    @classmethod
    def default(cls) -> Config:
        """Create default configuration.

        Returns:
            Config instance with all default values.
        """
        return cls()

    def ensure_directories(self) -> None:
        """Create all configured directories if they don't exist."""
        for directory in (self.tools_directory, self.logs_directory, self.data_directory):
            directory.mkdir(parents=True, exist_ok=True)
            _logger.info(
                "config_directory_ensured",
                extra={"path": str(directory)},
            )

    def get_provider_config(self, provider: ProviderName) -> ProviderConfig:
        """Get configuration for a specific provider.

        Args:
            provider: The provider to get configuration for.

        Returns:
            ProviderConfig for the specified provider.
        """
        return self.providers.get(provider, ProviderConfig())

    def get_tool_config(self, tool: ToolName) -> ToolConfig:
        """Get configuration for a specific tool.

        Args:
            tool: The tool to get configuration for.

        Returns:
            ToolConfig for the specified tool.
        """
        return self.tools.get(tool, ToolConfig())

    def is_provider_enabled(self, provider: ProviderName) -> bool:
        """Check if a provider is enabled.

        Args:
            provider: The provider to check.

        Returns:
            True if the provider is enabled.
        """
        config = self.get_provider_config(provider)
        return config.enabled

    def is_tool_enabled(self, tool: ToolName) -> bool:
        """Check if a tool is enabled.

        Args:
            tool: The tool to check.

        Returns:
            True if the tool is enabled.
        """
        config = self.get_tool_config(tool)
        return config.enabled
