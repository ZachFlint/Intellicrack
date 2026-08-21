# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration, logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
import time
from dataclasses import dataclass
from itertools import starmap
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPainter, QPixmap
from PyQt6.QtWidgets import QApplication, QSplashScreen

from intellicrack._metadata import __version__
from intellicrack.core.elevation import maybe_elevate
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ToolError


_logger = get_logger(__name__)


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from structlog.stdlib import BoundLogger

    from intellicrack.core.config import Config, LogConfig
    from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
    from intellicrack.core.process_manager import ProcessManager
    from intellicrack.core.script_gen import (
        ScriptGenerator,
        ScriptManager,
        ScriptValidator,
    )
    from intellicrack.core.session import SessionManager, SessionStore
    from intellicrack.core.template_manager import TemplateManager
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.types import HexDocumentFull, ProviderName
    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.base import LLMProviderBase
    from intellicrack.providers.discovery import ModelDiscovery
    from intellicrack.providers.registry import ProviderRegistry
    from intellicrack.ui.app import MainWindow
    from intellicrack.ui.dialogs import SplashScreen
    from intellicrack.ui.resources.icon_manager import IconManager
    from intellicrack.ui.resources.theme_manager import ThemeManager


class _SetupLoggingFn(Protocol):
    """Callable protocol matching :func:`intellicrack.core.logging.setup_logging`.

    Defined as a Protocol so the ``log_dir`` parameter can be supplied either positionally or via keyword without losing type fidelity at
    the call site inside :func:`_load_startup_config`.
    """

    def __call__(self, config: LogConfig, log_dir: Path | None = ...) -> None:
        """Invoke the wrapped ``setup_logging`` function.

        Args:
            config: Log configuration to apply.
            log_dir: Optional directory for log files. Defaults to ``None``,
                in which case ``setup_logging`` falls back to its portable
                default (``Path.cwd() / "logs"``).
        """


_EARLY_SPLASH_BG: Final[str] = "#1e1e2e"
_EARLY_SPLASH_WIDTH: Final[int] = 600
_EARLY_SPLASH_HEIGHT: Final[int] = 400
_EARLY_SPLASH_ASSET: Final[str] = "splash.png"
_APP_VERSION: str = __version__
_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_PROVIDER_CONNECT_TIMEOUT: float = 10.0
_SHUTDOWN_ORCHESTRATOR_TIMEOUT: float = 5.0
_SHUTDOWN_SESSION_TIMEOUT: float = 3.0
_SHUTDOWN_PROCESS_TIMEOUT: float = 10.0


@dataclass(frozen=True)
class _CLIOptions:
    """Parsed CLI options that override configuration values.

    Attributes:
        log_level: Explicit log level override, or None to use config value.
        disable_console_log: When True, disable the console log sink.
        disable_file_log: When True, disable the file log sink.
        config_path: Explicit path to a TOML configuration file, or None to
            use the project-local config directory.
        disable_elevation: When True, do not attempt to relaunch with
            administrator privileges (``--no-elevate``).
        already_elevated: When True, this process was started by a prior UAC
            relaunch and must not attempt to elevate again (``--elevated``).
    """

    log_level: str | None = None
    disable_console_log: bool = False
    disable_file_log: bool = False
    config_path: Path | None = None
    disable_elevation: bool = False
    already_elevated: bool = False


def _parse_args() -> tuple[_CLIOptions, list[str]]:
    """Parse CLI arguments into typed options.

    Returns:
        tuple[_CLIOptions, list[str]]: Tuple of parsed CLI options and remaining arguments
            (passed through to QApplication).
    """
    parser = argparse.ArgumentParser(
        prog="intellicrack",
        description="Intellicrack - Advanced Binary Analysis Platform",
    )
    _ = parser.add_argument(
        "--version",
        action="version",
        version=f"Intellicrack {_APP_VERSION}",
    )

    verbosity_group = parser.add_mutually_exclusive_group()
    _ = verbosity_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG level logging (maximum verbosity)",
    )
    _ = verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Enable WARNING level logging (reduced output)",
    )
    _ = verbosity_group.add_argument(
        "--log-level",
        choices=list(_VALID_LOG_LEVELS),
        default=None,
        metavar="LEVEL",
        help="Set explicit log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    _ = parser.add_argument(
        "--no-console-log",
        action="store_true",
        default=False,
        help="Disable console log output",
    )
    _ = parser.add_argument(
        "--no-file-log",
        action="store_true",
        default=False,
        help="Disable file log output",
    )
    _ = parser.add_argument(
        "--config",
        dest="config",
        default=None,
        metavar="PATH",
        help="Path to a TOML configuration file (overrides the default project-local location)",
    )
    _ = parser.add_argument(
        "--no-elevate",
        action="store_true",
        default=False,
        help="Do not attempt to relaunch with administrator privileges (Windows)",
    )
    _ = parser.add_argument(
        "--elevated",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    namespace, remaining = parser.parse_known_args()
    ns_dict: dict[str, object] = vars(namespace)

    resolved_level: str | None = None
    if ns_dict.get("verbose"):
        resolved_level = "DEBUG"
    elif ns_dict.get("quiet"):
        resolved_level = "WARNING"
    elif ns_dict.get("log_level") is not None:
        resolved_level = str(ns_dict["log_level"])

    raw_config = ns_dict.get("config")
    resolved_config_path: Path | None = Path(str(raw_config)).expanduser() if raw_config is not None else None

    return (
        _CLIOptions(
            log_level=resolved_level,
            disable_console_log=bool(ns_dict.get("no_console_log")),
            disable_file_log=bool(ns_dict.get("no_file_log")),
            config_path=resolved_config_path,
            disable_elevation=bool(ns_dict.get("no_elevate")),
            already_elevated=bool(ns_dict.get("elevated")),
        ),
        remaining,
    )


def _apply_cli_overrides(config: Config, cli: _CLIOptions) -> None:
    """Apply CLI flag overrides to the loaded config in-place.

    Args:
        config: Config instance whose log sub-config will be mutated.
        cli: Parsed CLI options with any overrides.
    """
    if cli.log_level is not None:
        config.log.level = cli.log_level
    if cli.disable_console_log:
        config.log.console_enabled = False
    if cli.disable_file_log:
        config.log.file_enabled = False
    if not config.log.console_enabled and not config.log.file_enabled:
        _logger.warning("all_log_output_disabled")


def _import_config_module() -> tuple[type[Config], Callable[[], Path]]:
    """Import the Config class and ``get_config_dir`` helper dynamically.

    Returns:
        tuple[type[Config], Callable[[], Path]]: Tuple of (Config class,
            callable returning the project-local configuration directory).
    """
    mod = importlib.import_module("intellicrack.core.config")
    return (
        cast("type[Config]", mod.Config),
        cast("Callable[[], Path]", mod.get_config_dir),
    )


def _import_logging_funcs() -> tuple[Callable[[str], BoundLogger], _SetupLoggingFn]:
    """Import logging functions dynamically.

    Returns:
        tuple[Callable[[str], BoundLogger], _SetupLoggingFn]: Tuple of (get_logger function, setup_logging function).
    """
    mod = importlib.import_module("intellicrack.core.logging")
    return cast(
        "tuple[Callable[[str], BoundLogger], _SetupLoggingFn]",
        (mod.get_logger, mod.setup_logging),
    )


def _import_process_manager() -> type[ProcessManager]:
    """Import the ProcessManager class dynamically.

    Returns:
        type[ProcessManager]: The ProcessManager class.
    """
    mod = importlib.import_module("intellicrack.core.process_manager")
    return cast("type[ProcessManager]", mod.ProcessManager)


def _import_qt_app() -> type[QApplication]:
    """Import QApplication dynamically.

    Returns:
        type[QApplication]: The QApplication class.
    """
    mod = importlib.import_module("PyQt6.QtWidgets")
    return cast("type[QApplication]", mod.QApplication)


def _import_splash_screen() -> type[SplashScreen]:
    """Import SplashScreen dynamically.

    Returns:
        type[SplashScreen]: The SplashScreen class.
    """
    mod = importlib.import_module("intellicrack.ui.dialogs")
    return cast("type[SplashScreen]", mod.SplashScreen)


def _import_theme_icon_managers() -> tuple[type[ThemeManager], type[IconManager]]:
    """Import theme and icon manager classes dynamically.

    Returns:
        tuple[type[ThemeManager], type[IconManager]]: Tuple of (ThemeManager class, IconManager class).
    """
    mod = importlib.import_module("intellicrack.ui.resources")
    return cast(
        "tuple[type[ThemeManager], type[IconManager]]",
        (mod.ThemeManager, mod.IconManager),
    )


def _import_orchestrator() -> type[Orchestrator]:
    """Import the Orchestrator class dynamically.

    Returns:
        type[Orchestrator]: The Orchestrator class.
    """
    mod = importlib.import_module("intellicrack.core.orchestrator")
    return cast("type[Orchestrator]", mod.Orchestrator)


def _import_orchestrator_config() -> type[OrchestratorConfig]:
    """Import the OrchestratorConfig class dynamically.

    Returns:
        type[OrchestratorConfig]: The OrchestratorConfig class.
    """
    mod = importlib.import_module("intellicrack.core.orchestrator")
    return cast("type[OrchestratorConfig]", mod.OrchestratorConfig)


def _import_session_classes() -> tuple[type[SessionManager], type[SessionStore]]:
    """Import session management classes dynamically.

    Returns:
        tuple[type[SessionManager], type[SessionStore]]: Tuple of (SessionManager class, SessionStore class).
    """
    mod = importlib.import_module("intellicrack.core.session")
    return (
        cast("type[SessionManager]", mod.SessionManager),
        cast("type[SessionStore]", mod.SessionStore),
    )


def _import_tool_registry() -> type[ToolRegistry]:
    """Import the ToolRegistry class dynamically.

    Returns:
        type[ToolRegistry]: The ToolRegistry class.
    """
    mod = importlib.import_module("intellicrack.core.tools")
    return cast("type[ToolRegistry]", mod.ToolRegistry)


def _import_credential_loader() -> type[CredentialLoader]:
    """Import the CredentialLoader class dynamically.

    Returns:
        type[CredentialLoader]: The CredentialLoader class.
    """
    mod = importlib.import_module("intellicrack.credentials.env_loader")
    return cast("type[CredentialLoader]", mod.CredentialLoader)


def _resolve_env_path() -> Path:
    """Resolve the ``.env`` credential file path via the config module.

    Delegates to :func:`intellicrack.core.config.get_env_file` so the path is
    anchored to the deployment root (beside the executable in a frozen build,
    the repository root in development) rather than the current working
    directory.

    Returns:
        Path: Absolute path to the project-local ``.env`` file.
    """
    mod = importlib.import_module("intellicrack.core.config")
    return cast("Callable[[], Path]", mod.get_env_file)()


def _get_provider_registry() -> ProviderRegistry:
    """Get the global provider registry singleton instance.

    Returns:
        ProviderRegistry: The singleton ProviderRegistry instance.
    """
    mod = importlib.import_module("intellicrack.providers.registry")
    get_registry = cast("Callable[[], ProviderRegistry]", mod.get_provider_registry)
    return get_registry()


def _import_main_window() -> type[MainWindow]:
    """Import the MainWindow class dynamically.

    Returns:
        type[MainWindow]: The MainWindow class.
    """
    mod = importlib.import_module("intellicrack.ui.app")
    return cast("type[MainWindow]", mod.MainWindow)


def _log_import_time(logger: BoundLogger, module_name: str, elapsed: float) -> None:
    """Log the elapsed time for a module import.

    Args:
        logger: BoundLogger for timing output.
        module_name: Fully-qualified module name that was imported.
        elapsed: Elapsed time in seconds.
    """
    logger.debug("import_timing", imported_module=module_name, elapsed_s=round(elapsed, 3))


def _compute_early_dpi_scale(app: QApplication) -> float:
    """Return the primary screen's device pixel ratio for early splash sizing.

    Args:
        app: The active :class:`QApplication` instance.

    Returns:
        float: Device pixel ratio of the primary screen, or ``1.0`` when the
        screen cannot be queried.
    """
    screen = app.primaryScreen()
    return 1.0 if screen is None else float(screen.devicePixelRatio())


def _build_early_splash_pixmap(splash_asset: Path, width: int, height: int) -> QPixmap:
    """Compose the early splash pixmap from ``splash.png`` over a solid background.

    The full splash image is loaded and scaled (preserving aspect ratio) to fit
    inside ``width`` x ``height``, then centered on a background filled with
    :data:`_EARLY_SPLASH_BG`. When the asset is missing or fails to decode, the
    solid-colour background is returned unchanged so the early splash still
    appears.

    Args:
        splash_asset: Path to the splash image asset on disk.
        width: Target pixmap width in physical pixels.
        height: Target pixmap height in physical pixels.

    Returns:
        QPixmap: Composed pixmap sized exactly ``width`` x ``height``.
    """
    pixmap = QPixmap(width, height)
    pixmap.fill(QColor(_EARLY_SPLASH_BG))

    if not splash_asset.exists():
        return pixmap

    source = QPixmap(str(splash_asset))
    if source.isNull():
        return pixmap

    scaled = source.scaled(
        width,
        height,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )

    painter = QPainter(pixmap)
    try:
        offset_x = (width - scaled.width()) // 2
        offset_y = (height - scaled.height()) // 2
        painter.drawPixmap(offset_x, offset_y, scaled)
    finally:
        painter.end()

    return pixmap


def _show_early_splash_impl() -> tuple[QApplication, QSplashScreen]:
    """Build the QApplication and minimal splash screen.

    Imports PyQt6, configures high-DPI behaviour, creates the application,
    and shows a minimal splash screen rendered from the bundled
    ``splash.png`` asset (scaled to match the dynamic splash dimensions) or
    a solid-colour fallback. Propagates ``ImportError`` when PyQt6 cannot be
    imported, ``OSError`` when the splash asset cannot be loaded, and
    ``RuntimeError`` when Qt rejects the construction sequence.

    Returns:
        tuple[QApplication, QSplashScreen]: The Qt application and the early
        splash screen, both already displayed.
    """
    if QApplication.instance() is None:
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)

    app = QApplication(sys.argv)
    QApplication.setApplicationName("Intellicrack")
    QApplication.setApplicationVersion(_APP_VERSION)
    app.setStyle("Fusion")

    dpi_scale = _compute_early_dpi_scale(app)
    scaled_w = max(1, int(_EARLY_SPLASH_WIDTH * dpi_scale))
    scaled_h = max(1, int(_EARLY_SPLASH_HEIGHT * dpi_scale))

    splash_path = Path(__file__).resolve().parent / "assets" / _EARLY_SPLASH_ASSET
    early_pixmap = _build_early_splash_pixmap(splash_path, scaled_w, scaled_h)
    early_pixmap.setDevicePixelRatio(dpi_scale)

    early_splash = QSplashScreen(early_pixmap)
    early_splash.setWindowFlags(
        Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen,
    )
    early_splash.show()
    app.processEvents()
    return app, early_splash


def _show_early_splash() -> tuple[QApplication, QSplashScreen] | None:
    """Create QApplication and show a minimal splash screen for instant visual feedback.

    This runs before any heavy intellicrack imports (config, logging,
    process manager) so the user sees visual feedback immediately.
    Only imports PyQt6 and standard library modules.

    Returns:
        tuple[QApplication, QSplashScreen] | None: Tuple of (app, early_splash) or None on failure.
    """
    try:
        return _show_early_splash_impl()
    except (ImportError, OSError, RuntimeError) as exc:
        _logger.warning("early_splash_failed", error=str(exc), error_type=type(exc).__name__)
        return None


def _upgrade_to_full_splash_impl(
    app: QApplication,
    early_splash: QSplashScreen,
    logger: BoundLogger,
    theme: str,
) -> SplashScreen:
    """Import UI modules and build the full animated splash screen.

    Propagates ``ImportError`` when a UI module cannot be imported,
    ``OSError`` when a UI asset cannot be loaded, and ``RuntimeError`` when
    Qt rejects the construction sequence.

    Args:
        app: Qt application instance.
        early_splash: The minimal early splash screen to replace.
        logger: BoundLogger used for import-time telemetry.
        theme: Configured UI theme name ("dark", "light", or "system") to
            apply so the splash and main window honor the user's preference.

    Returns:
        SplashScreen: The full animated splash screen, already displayed.
    """
    t0 = time.perf_counter()
    theme_mgr_cls, icon_mgr_cls = _import_theme_icon_managers()
    _log_import_time(logger, "intellicrack.ui.resources", time.perf_counter() - t0)

    t0 = time.perf_counter()
    splash_cls = _import_splash_screen()
    _log_import_time(logger, "intellicrack.ui.dialogs", time.perf_counter() - t0)

    theme_manager = theme_mgr_cls.get_instance()
    theme_manager.apply_theme(theme)

    icon_manager = icon_mgr_cls.get_instance()
    qt_app_cls = _import_qt_app()
    qt_app_cls.setWindowIcon(icon_manager.get_app_icon())

    early_splash.close()

    splash = splash_cls(version=_APP_VERSION)
    splash.show_animated()
    app.processEvents()
    return splash


def _upgrade_to_full_splash(
    app: QApplication,
    early_splash: QSplashScreen,
    logger: BoundLogger,
    theme: str,
) -> SplashScreen | None:
    """Replace the early splash with the full animated splash screen.

    Imports the heavier UI resource modules (ThemeManager, IconManager,
    SplashScreen), applies the configured theme, closes the early splash,
    and shows the full animated splash.

    Args:
        app: Qt application instance.
        early_splash: The minimal early splash screen to replace.
        logger: BoundLogger for error reporting.
        theme: Configured UI theme name ("dark", "light", or "system").

    Returns:
        SplashScreen | None: Full animated splash screen, or None on failure.
    """
    try:
        return _upgrade_to_full_splash_impl(app, early_splash, logger, theme)
    except (ImportError, OSError, RuntimeError) as exc:
        logger.warning("full_splash_upgrade_failed", error=str(exc), exc_info=True)
        return None


async def _initialize_providers(
    registry: ProviderRegistry,
    credentials: CredentialLoader,
    logger: BoundLogger,
) -> None:
    """Initialize and connect LLM providers.

    Args:
        registry: Provider registry to populate.
        credentials: Credential loader for API keys.
        logger: BoundLogger instance.
    """
    types_mod = importlib.import_module("intellicrack.core.types")
    provider_name_enum = types_mod.ProviderName

    anthropic_mod = importlib.import_module("intellicrack.providers.anthropic")
    google_mod = importlib.import_module("intellicrack.providers.google")
    grok_mod = importlib.import_module("intellicrack.providers.grok")
    hf_mod = importlib.import_module("intellicrack.providers.huggingface")
    local_mod = importlib.import_module("intellicrack.providers.local_transformers")
    ollama_mod = importlib.import_module("intellicrack.providers.ollama")
    openai_mod = importlib.import_module("intellicrack.providers.openai")
    openrouter_mod = importlib.import_module("intellicrack.providers.openrouter")

    providers: list[tuple[ProviderName, type[LLMProviderBase]]] = cast(
        "list[tuple[ProviderName, type[LLMProviderBase]]]",
        [
            (provider_name_enum.ANTHROPIC, anthropic_mod.AnthropicProvider),
            (provider_name_enum.OPENAI, openai_mod.OpenAIProvider),
            (provider_name_enum.GOOGLE, google_mod.GoogleProvider),
            (provider_name_enum.OLLAMA, ollama_mod.OllamaProvider),
            (provider_name_enum.OPENROUTER, openrouter_mod.OpenRouterProvider),
            (provider_name_enum.HUGGINGFACE, hf_mod.HuggingFaceProvider),
            (provider_name_enum.GROK, grok_mod.GrokProvider),
            (provider_name_enum.LOCAL_TRANSFORMERS, local_mod.LocalTransformersProvider),
        ],
    )

    async def _init_one_impl(provider_name: ProviderName, provider_class: type[LLMProviderBase]) -> None:
        """Construct, optionally connect, and register a single provider.

        Propagates ``ImportError``, ``OSError``, ``RuntimeError``,
        ``ValueError``, ``TypeError``, and ``AttributeError`` so the caller
        wrapper can log a single ``provider_init_failed`` warning.

        Args:
            provider_name: Provider enum value used for log records and
                credential lookup.
            provider_class: Concrete :class:`LLMProviderBase` subclass to
                instantiate.
        """
        display_mod = importlib.import_module("intellicrack.providers.display_names")
        no_api_key_providers = display_mod.NO_API_KEY_PROVIDERS
        provider_credentials_cls = types_mod.ProviderCredentials
        provider_error_cls = types_mod.ProviderError

        provider = provider_class()
        creds = credentials.get_credentials(provider_name)
        if creds is None and provider_name in no_api_key_providers:
            creds = provider_credentials_cls()

        if creds is not None:
            try:
                await asyncio.wait_for(
                    provider.connect(creds),
                    timeout=_PROVIDER_CONNECT_TIMEOUT,
                )
                logger.info("provider_connected", provider=provider_name.value)
            except TimeoutError:
                logger.warning(
                    "provider_connect_timeout",
                    provider=provider_name.value,
                    timeout=_PROVIDER_CONNECT_TIMEOUT,
                )
            except provider_error_cls as exc:
                logger.warning(
                    "provider_connect_failed",
                    provider=provider_name.value,
                    error=str(exc),
                )
                if provider_name not in no_api_key_providers:
                    return
            registry.register(provider)
        else:
            logger.debug("no_credentials", provider=provider_name.value)
            registry.register(provider)

    async def _init_one(provider_name: ProviderName, provider_class: type[LLMProviderBase]) -> None:
        """Initialize one provider and log recoverable failures without aborting.

        Args:
            provider_name: Registry key for the provider being initialized.
            provider_class: Concrete provider class to construct and register.
        """
        try:
            await _init_one_impl(provider_name, provider_class)
        except (ImportError, OSError, RuntimeError, ValueError, TypeError, AttributeError) as e:
            logger.warning(
                "provider_init_failed",
                provider=provider_name.value,
                error=str(e),
                error_type=type(e).__name__,
                exc_info=True,
            )

    await asyncio.gather(*starmap(_init_one, providers))


def _resolve_config_path(cli_options: _CLIOptions, get_config_dir: Callable[[], Path]) -> Path | None:
    """Resolve the config file path from CLI options or the default directory.

    Args:
        cli_options: Parsed CLI options.
        get_config_dir: Callable returning the configured data directory.

    Returns:
        Path | None: Resolved path; ``None`` if the user supplied an explicit path that does not exist.
    """
    config_path = cli_options.config_path if cli_options.config_path is not None else get_config_dir() / "config.toml"
    if cli_options.config_path is not None and not config_path.exists():
        _logger.error("config_path_missing", config_path=str(config_path))
        return None
    return config_path


def _finalize_shutdown(loop: asyncio.AbstractEventLoop, process_manager: ProcessManager, logger: BoundLogger) -> None:
    """Run final async process cleanup and teardown the bridge loop.

    Args:
        loop: Event loop the application ran on.
        process_manager: ProcessManager instance providing ``cleanup_all_async``.
        logger: Structured logger for shutdown events.
    """
    try:
        loop.run_until_complete(
            asyncio.wait_for(
                process_manager.cleanup_all_async(),
                timeout=_SHUTDOWN_PROCESS_TIMEOUT,
            ),
        )
    except TimeoutError:
        logger.warning("final_process_cleanup_timeout")
    except (OSError, RuntimeError):
        logger.debug("final_process_cleanup_failed", exc_info=True)
    process_manager.uninstall_handlers()
    loop.close()


def _load_startup_config(cli_options: _CLIOptions) -> tuple[Config, BoundLogger, ProcessManager] | None:
    """Load configuration, start logging, and spin up the process manager.

    Args:
        cli_options: Parsed CLI options that may override config values.

    Returns:
        tuple[Config, BoundLogger, ProcessManager] | None: ``(config, logger, process_manager)``
            on success; ``None`` when the caller should exit with status 1 (e.g. bad ``--config``).
    """
    config_cls, get_config_dir = _import_config_module()
    _, setup_logging = _import_logging_funcs()
    pm_cls = _import_process_manager()

    config_path = _resolve_config_path(cli_options, get_config_dir)
    if config_path is None:
        return None
    config = config_cls.load(config_path) if config_path.exists() else config_cls.default()
    _apply_cli_overrides(config, cli_options)
    config.ensure_directories()

    setup_logging(config.log, log_dir=config.logs_directory)
    _logger.info("app_starting", version=_APP_VERSION, log_level=config.log.level)

    process_manager = pm_cls.get_instance()
    process_manager.install_handlers()
    _logger.debug("process_manager_initialized", handlers_installed=True)
    return config, _logger, process_manager


def main() -> int:
    """Run the Intellicrack application.

    Returns:
        int: Exit code (0 for success, non-zero for failure).
    """
    original_args = sys.argv[1:]
    cli_options, remaining_args = _parse_args()

    if maybe_elevate(
        disabled=cli_options.disable_elevation,
        already_attempted=cli_options.already_elevated,
        original_args=original_args,
        working_dir=str(Path.cwd()),
    ):
        return 0

    sys.argv = [sys.argv[0], *remaining_args]

    early_result = _show_early_splash()
    if early_result is None:
        return 1
    app, early_splash = early_result

    startup = _load_startup_config(cli_options)
    if startup is None:
        return 1
    config, logger, process_manager = startup

    splash = _upgrade_to_full_splash(app, early_splash, logger, config.ui.theme)
    if splash is None:
        process_manager.uninstall_handlers()
        return 1

    logger.info("splash_screen_shown")
    splash.set_progress(5, "Loading configuration...")
    app.processEvents()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        return loop.run_until_complete(
            _run_application(config, app, splash, process_manager, logger),
        )
    except (ImportError, OSError, RuntimeError) as exc:
        logger.warning(
            "application_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return 1
    finally:
        _finalize_shutdown(loop, process_manager, logger)


def _init_script_engine(
    config: Config,
    logger: BoundLogger,
) -> tuple[ScriptManager, ScriptValidator, ScriptGenerator]:
    """Initialize the script engine subsystem.

    Constructs the on-disk script directory, instantiates the
    :class:`~intellicrack.core.script_gen.ScriptManager`,
    :class:`~intellicrack.core.script_gen.ScriptValidator`, and
    :class:`~intellicrack.core.script_gen.ScriptGenerator` and returns
    all three so the caller can persist them on the application context.
    Holding ``ScriptGenerator`` for the lifetime of the application keeps
    its API surface available to AI/tool bridges that build script-
    generation prompts.

    Args:
        config: Application configuration.
        logger: BoundLogger instance.

    Returns:
        tuple[ScriptManager, ScriptValidator, ScriptGenerator]: Tuple of
            (script_manager, script_validator, script_generator).
    """
    script_gen_mod = importlib.import_module("intellicrack.core.script_gen")
    scripts_dir = config.data_directory / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_manager = cast("ScriptManager", script_gen_mod.ScriptManager(scripts_dir))
    script_validator = cast("ScriptValidator", script_gen_mod.ScriptValidator())
    script_generator = cast("ScriptGenerator", script_gen_mod.ScriptGenerator())
    logger.info("script_engine_initialized")
    return script_manager, script_validator, script_generator


def _init_template_manager(
    logger: BoundLogger,
) -> TemplateManager | None:
    """Initialize the hex editor template manager and bootstrap built-ins.

    Builds a :class:`~intellicrack.core.template_manager.TemplateManager`
    rooted under the project-local config directory, ensures the on-disk
    builtin/user template subdirectories exist, and exports every built-in
    template registered on a headless ``HexDocument`` to its JSON sidecar
    via :meth:`TemplateManager.bootstrap_builtins`.

    The bootstrap does not abort startup on failure: per-template export
    failures are surfaced through ``TemplateBootstrapError.failed_templates``
    and logged as a structured warning. If the native hex core cannot be
    imported (for example, because the Rust crate has not been built),
    ``None`` is returned and the caller continues without template
    persistence.

    Args:
        logger: BoundLogger instance.

    Returns:
        TemplateManager | None: The bootstrapped TemplateManager, or
            ``None`` when the native ``intellicrack_hexcore`` backend
            cannot supply a ``HexDocument`` to drive the bootstrap.
    """
    config_mod = importlib.import_module("intellicrack.core.config")
    template_mod = importlib.import_module("intellicrack.core.template_manager")

    template_manager_cls = cast("type[TemplateManager]", template_mod.TemplateManager)
    bootstrap_error_cls: type[Exception] = cast(
        "type[Exception]",
        template_mod.TemplateBootstrapError,
    )

    config_dir = cast("Path", config_mod.get_config_dir())
    template_manager = template_manager_cls(config_dir)
    template_manager.ensure_directories()

    try:
        hexcore_mod = importlib.import_module("intellicrack_hexcore")
    except ImportError:
        logger.warning(
            "template_manager_skipped_no_hexcore",
            reason="intellicrack_hexcore module not available",
        )
        return template_manager

    hex_document_cls = getattr(hexcore_mod, "HexDocument", None)
    if hex_document_cls is None:
        logger.warning(
            "template_manager_skipped_no_hex_document",
            reason="intellicrack_hexcore.HexDocument not available",
        )
        return template_manager

    open_bytes = getattr(hex_document_cls, "open_bytes", None)
    if not callable(open_bytes):
        logger.warning(
            "template_manager_skipped_no_open_bytes",
            reason="HexDocument.open_bytes factory not available",
        )
        return template_manager

    document = open_bytes(b"")
    try:
        template_manager.bootstrap_builtins(cast("HexDocumentFull", document))
    except bootstrap_error_cls as exc:
        logger.warning(
            "template_bootstrap_partial",
            error=str(exc),
            failed_count=len(template_manager.failed_templates),
            failed_paths=[str(path) for path, _ in template_manager.failed_templates],
        )
    else:
        logger.info("template_manager_initialized")

    return template_manager


async def _init_model_discovery(
    provider_registry: ProviderRegistry,
    config: Config,
    logger: BoundLogger,
) -> tuple[object, Path]:
    """Initialize the model discovery subsystem.

    Args:
        provider_registry: Provider registry for model queries.
        config: Application configuration.
        logger: BoundLogger instance.

    Returns:
        tuple[object, Path]: Tuple of (model_discovery, discovery_cache_path).
    """
    discovery_mod = importlib.import_module("intellicrack.providers.discovery")
    model_discovery = discovery_mod.ModelDiscovery(provider_registry)
    discovery_cache = config.data_directory / "model_discovery_cache.json"
    if discovery_cache.exists():
        load_cache = getattr(model_discovery, "load_cache", None)
        if callable(load_cache):
            await cast("Awaitable[None]", load_cache(discovery_cache))
    logger.info("model_discovery_initialized")
    return model_discovery, discovery_cache


async def init_model_discovery(
    provider_registry: ProviderRegistry,
    config: Config,
    logger: BoundLogger,
) -> tuple[object, Path]:
    """Initialize the model discovery subsystem.

    Args:
        provider_registry: Provider registry for model queries.
        config: Application configuration.
        logger: BoundLogger instance.

    Returns:
        tuple[object, Path]: Tuple of (model_discovery, discovery_cache_path).
    """
    logger.debug("init_model_discovery_invoked")
    return await _init_model_discovery(provider_registry, config, logger)


def init_script_engine(
    config: Config,
    logger: BoundLogger,
) -> tuple[ScriptManager, ScriptValidator, ScriptGenerator]:
    """Public wrapper around :func:`_init_script_engine`.

    Args:
        config: Application configuration.
        logger: BoundLogger instance.

    Returns:
        tuple[ScriptManager, ScriptValidator, ScriptGenerator]: Tuple of
            (script_manager, script_validator, script_generator).
    """
    return _init_script_engine(config, logger)


def init_template_manager(
    logger: BoundLogger,
) -> TemplateManager | None:
    """Public wrapper around :func:`_init_template_manager`.

    Args:
        logger: BoundLogger instance.

    Returns:
        TemplateManager | None: The bootstrapped TemplateManager, or
            ``None`` when the native ``intellicrack_hexcore`` backend is
            unavailable.
    """
    return _init_template_manager(logger)


def _clear_model_cache(logger: BoundLogger) -> None:
    """Clear the global model cache during shutdown.

    Args:
        logger: BoundLogger instance.
    """
    model_cache_mod = importlib.import_module("intellicrack.providers.model_loader")
    get_cache = getattr(model_cache_mod, "get_global_model_cache", None)
    if callable(get_cache):
        try:
            cache = get_cache()
            clear_fn = getattr(cache, "clear", None)
            if callable(clear_fn):
                clear_fn()
            logger.info("model_cache_cleared")
        except (ImportError, OSError, RuntimeError):
            logger.exception("model_cache_cleanup_skipped")


def _create_main_window(
    *,
    config: Config,
    orchestrator: Orchestrator,
    script_manager: ScriptManager,
    script_validator: ScriptValidator,
    script_generator: ScriptGenerator,
    template_manager: TemplateManager | None,
    model_discovery: object,
) -> MainWindow:
    """Construct the main window and wire startup-scoped services into it.

    Args:
        config: Application configuration.
        orchestrator: AI orchestrator owning provider/tool registries.
        script_manager: ScriptManager owning the on-disk scripts directory.
        script_validator: ScriptValidator used by the script panel.
        script_generator: ScriptGenerator API surface persisted on the window.
        template_manager: TemplateManager rooted under the user's config
            directory, or ``None`` when bootstrap could not run.
        model_discovery: ModelDiscovery instance for provider model lookups.

    Returns:
        MainWindow: The fully wired main window ready to show.
    """
    window = _import_main_window()(config, orchestrator)
    window.wire_script_manager(script_manager, script_validator)
    window.set_script_generator(script_generator)
    if template_manager is not None:
        window.set_template_manager(template_manager)
    window.set_model_discovery(cast("ModelDiscovery", model_discovery))
    _wire_preregistered_sandbox(window, orchestrator)
    return window


def _wire_preregistered_sandbox(window: MainWindow, orchestrator: Orchestrator) -> None:
    """Inject any pre-registered sandbox backend into the main window.

    When a plugin or CLI bootstrap constructs a ``SandboxBase`` and
    registers it on the orchestrator's tool registry (via
    :meth:`SandboxBridge.register_existing_sandbox`) before the GUI is
    created, this helper forwards the first such instance to
    :meth:`MainWindow.wire_sandbox_backend` so the sandbox tab, the chat
    workflow, and AI bridges all observe the externally supplied backend.
    Silent no-op when no pre-registered sandbox exists, which is the
    common case for a plain ``intellicrack`` GUI launch.

    Args:
        window: MainWindow whose tool panel should receive the backend.
        orchestrator: Orchestrator whose tool registry is inspected for a
            pre-registered ``SandboxBridge`` with existing instances.
    """
    tool_registry = getattr(orchestrator, "_tools", None)
    if tool_registry is None:
        return
    getter = getattr(tool_registry, "get_sandbox_bridge", None)
    if not callable(getter):
        return

    try:
        bridge = getter()
    except (RuntimeError, ImportError, AttributeError, ToolError):
        _logger.debug("preregistered_sandbox_bridge_lookup_failed", exc_info=True)
        return
    manager = getattr(bridge, "manager", None)
    if manager is None:
        return
    instances = list(getattr(manager, "instances", []))
    if not instances:
        return
    sandbox = getattr(instances[0], "sandbox", None)
    if sandbox is None:
        return
    window.wire_sandbox_backend(sandbox, manager)
    _logger.info(
        "preregistered_sandbox_wired_into_main_window",
        sandbox_type=type(sandbox).__name__,
        instance_count=len(instances),
    )


def _detach_qt_log_handler(logger: BoundLogger) -> None:
    """Remove the Qt-signaling log handler before the main window is destroyed.

    The handler's internal ``_HandlerBridge`` :class:`QObject` is destroyed
    automatically when Qt tears down the main window. Any subsequent log record
    that routes through the handler would attempt to emit a signal on a deleted
    C++ object and raise ``RuntimeError`` on every call. Detaching the handler
    here keeps the logging pipeline silent during the asyncio teardown phase.

    Args:
        logger: BoundLogger used for diagnostic output when the helper is
            unavailable (for example, when the log viewer module failed to
            import during startup).
    """
    try:
        handler_mod = importlib.import_module("intellicrack.ui.log_viewer")
        uninstall = getattr(handler_mod, "uninstall_qt_log_handler", None)
    except ImportError:
        logger.info("qt_log_handler_module_unavailable_during_shutdown")
        return
    if not callable(uninstall):
        return
    try:
        uninstall()
    except (RuntimeError, OSError, ValueError):
        logger.warning("qt_log_handler_uninstall_failed", exc_info=True)


async def _cancel_pending_bridge_tasks(logger: BoundLogger) -> None:
    """Cancel and drain bridge coroutines still pending on the main loop.

    Calls into :mod:`intellicrack.ui.panels.async_bridge` to cancel every task
    that ``run_bridge_coroutine`` scheduled on the current loop while Qt was
    blocking the main thread inside ``app.exec()``. A short yield via
    :func:`asyncio.sleep` lets the loop deliver ``CancelledError`` to each
    suspended coroutine so they can complete teardown before the loop is
    closed, eliminating the cascade of ``Task was destroyed but it is
    pending!`` warnings that would otherwise appear during shutdown.

    Args:
        logger: BoundLogger used for diagnostic output when the helper is
            unavailable.
    """
    try:
        bridge_mod = importlib.import_module("intellicrack.ui.panels.async_bridge")
        cancel_pending = getattr(bridge_mod, "cancel_pending_main_loop_tasks", None)
    except ImportError:
        logger.info("async_bridge_unavailable_during_shutdown")
        return
    if not callable(cancel_pending):
        return
    try:
        cancelled = int(cast("Callable[[], int]", cancel_pending)())
    except (RuntimeError, OSError, ValueError):
        logger.warning("async_bridge_task_cancel_failed", exc_info=True)
        return
    if cancelled:
        logger.info("pending_bridge_tasks_cancelled", count=cancelled)
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError:
            logger.warning("cancel_drain_interrupted", exc_info=True)


def _drain_and_stop_bridge_loop(logger: BoundLogger) -> None:
    """Drain in-flight bridge worker threads, then stop the persistent bridge loop.

    The async-bridge helpers dispatch work onto ``BridgeCallWorker`` /
    ``GenericCallableWorker`` ``QThread`` instances that run against the shared
    background event loop. Draining waits for any still-running worker to finish
    before :func:`shutdown_bridge_loop` stops the loop those workers depend on,
    so no worker is destroyed mid-flight and the loop is not torn down while a
    worker is still awaiting a coroutine scheduled on it.

    Args:
        logger: BoundLogger used to report how many workers were drained.
    """
    bridge_module = importlib.import_module("intellicrack.ui.panels.async_bridge")
    drain_fn = getattr(bridge_module, "drain_bridge_workers", None)
    if callable(drain_fn):
        drained = int(cast("Callable[[], int]", drain_fn)())
        if drained:
            logger.info("bridge_workers_drained", count=drained)
    shutdown_fn = getattr(bridge_module, "shutdown_bridge_loop", None)
    if callable(shutdown_fn):
        shutdown_fn()


async def _shutdown_application(
    *,
    logger: BoundLogger,
    provider_registry: ProviderRegistry,
    orchestrator: Orchestrator,
    session_manager: SessionManager,
    process_manager: ProcessManager,
    model_discovery: object,
    discovery_cache: Path,
) -> None:
    """Run the application shutdown sequence with bounded timeouts.

    Args:
        logger: BoundLogger for shutdown progress.
        provider_registry: Provider registry to disconnect.
        orchestrator: Orchestrator to shut down.
        session_manager: SessionManager to close.
        process_manager: ProcessManager whose tracked processes are
            cleaned up via :meth:`cleanup_all_async`.
        model_discovery: ModelDiscovery whose cache is persisted to
            ``discovery_cache`` if it exposes ``save_cache``.
        discovery_cache: Path of the model discovery cache file.
    """
    logger.info("shutdown_started")

    _detach_qt_log_handler(logger)
    await _cancel_pending_bridge_tasks(logger)

    save_cache = getattr(model_discovery, "save_cache", None)
    if callable(save_cache):
        await cast("Awaitable[None]", save_cache(discovery_cache))

    try:
        await asyncio.wait_for(
            provider_registry.disconnect_all(),
            timeout=_SHUTDOWN_ORCHESTRATOR_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("provider_disconnect_timeout")

    _clear_model_cache(logger)

    try:
        await asyncio.wait_for(orchestrator.shutdown(), timeout=_SHUTDOWN_ORCHESTRATOR_TIMEOUT)
    except TimeoutError:
        logger.warning("orchestrator_shutdown_timeout")

    try:
        await asyncio.wait_for(session_manager.close(), timeout=_SHUTDOWN_SESSION_TIMEOUT)
    except TimeoutError:
        logger.warning("session_close_timeout")

    try:
        await asyncio.wait_for(
            process_manager.cleanup_all_async(),
            timeout=_SHUTDOWN_PROCESS_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("process_cleanup_timeout")

    try:
        _drain_and_stop_bridge_loop(logger)
    except (ImportError, OSError, RuntimeError):
        logger.exception("bridge_loop_shutdown_failed")

    logger.info("shutdown_complete")


async def _run_application(
    config: Config,
    app: QApplication,
    splash: SplashScreen,
    process_manager: ProcessManager,
    logger: BoundLogger,
) -> int:
    """Run the main application logic.

    Args:
        config: Application configuration.
        app: Qt application instance.
        splash: Splash screen instance.
        process_manager: Process manager instance.
        logger: BoundLogger instance.

    Returns:
        int: Application exit code.
    """
    splash.set_progress(10, "Loading credentials...")
    app.processEvents()

    credential_loader = _import_credential_loader()(_resolve_env_path())

    splash.set_progress(20, "Initializing providers...")
    app.processEvents()

    provider_registry = _get_provider_registry()
    logger.info("provider_initialization_started")
    await _initialize_providers(provider_registry, credential_loader, logger)
    logger.info("provider_initialization_complete")

    splash.set_progress(50, "Initializing tools...")
    app.processEvents()

    tool_registry = _import_tool_registry()(config.tools_directory)
    await tool_registry.initialize()

    splash.set_progress(70, "Initializing session manager...")
    app.processEvents()

    session_mgr_cls, session_store_cls = _import_session_classes()
    session_manager = session_mgr_cls(session_store_cls(config.data_directory / "sessions.db"))

    splash.set_progress(85, "Creating orchestrator...")
    app.processEvents()

    orchestrator = _import_orchestrator()(
        provider_registry=provider_registry,
        tool_registry=tool_registry,
        session_manager=session_manager,
        config=_import_orchestrator_config()(confirmation_level=config.confirmation_level),
    )

    splash.set_progress(90, "Initializing script engine...")
    app.processEvents()

    script_manager, script_validator, script_generator = init_script_engine(config, logger)

    splash.set_progress(92, "Initializing template manager...")
    app.processEvents()

    template_manager = init_template_manager(logger)

    splash.set_progress(93, "Initializing model discovery...")
    app.processEvents()

    model_discovery, discovery_cache = await init_model_discovery(provider_registry, config, logger)

    splash.set_progress(95, "Initializing UI...")
    app.processEvents()

    window = _create_main_window(
        config=config,
        orchestrator=orchestrator,
        script_manager=script_manager,
        script_validator=script_validator,
        script_generator=script_generator,
        template_manager=template_manager,
        model_discovery=model_discovery,
    )

    splash.set_progress(100, "Ready")
    app.processEvents()
    splash.finish_animated(window)

    logger.info("ui_started")
    exit_code = app.exec()

    try:
        await _shutdown_application(
            logger=logger,
            provider_registry=provider_registry,
            orchestrator=orchestrator,
            session_manager=session_manager,
            process_manager=process_manager,
            model_discovery=model_discovery,
            discovery_cache=discovery_cache,
        )
    except (ImportError, OSError, RuntimeError) as exc:
        logger.warning(
            "shutdown_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return 1 if exit_code == 0 else exit_code
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
