# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration,
logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from logging import Logger

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config, LogConfig
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.process_manager import ProcessManager
    from intellicrack.core.session import SessionManager, SessionStore
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.discovery import ModelDiscovery
    from intellicrack.providers.registry import ProviderRegistry
    from intellicrack.ui.app import MainWindow
    from intellicrack.ui.dialogs import SplashScreen
    from intellicrack.ui.resources.icon_manager import IconManager
    from intellicrack.ui.resources.theme_manager import ThemeManager

from intellicrack._metadata import __version__


_APP_VERSION: str = __version__
_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_PROVIDER_CONNECT_TIMEOUT: float = 10.0
_SHUTDOWN_ORCHESTRATOR_TIMEOUT: float = 5.0
_SHUTDOWN_SESSION_TIMEOUT: float = 3.0
_SHUTDOWN_PROCESS_TIMEOUT: float = 10.0


@dataclass(frozen=True)
class _CLIOptions:
    """Parsed CLI options that override configuration values."""

    log_level: str | None = None
    disable_console_log: bool = False
    disable_file_log: bool = False


def _parse_args() -> tuple[_CLIOptions, list[str]]:
    """Parse CLI arguments into typed options.

    Returns:
        Tuple of parsed CLI options and remaining arguments
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

    namespace, remaining = parser.parse_known_args()
    ns_dict: dict[str, object] = vars(namespace)

    resolved_level: str | None = None
    if ns_dict.get("verbose"):
        resolved_level = "DEBUG"
    elif ns_dict.get("quiet"):
        resolved_level = "WARNING"
    elif ns_dict.get("log_level") is not None:
        resolved_level = str(ns_dict["log_level"])

    return (
        _CLIOptions(
            log_level=resolved_level,
            disable_console_log=bool(ns_dict.get("no_console_log")),
            disable_file_log=bool(ns_dict.get("no_file_log")),
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


def _import_config_class() -> type[Config]:
    """Import the Config class dynamically.

    Returns:
        The Config class.
    """
    mod = importlib.import_module("intellicrack.core.config")
    return cast("type[Config]", mod.Config)


def _import_logging_funcs() -> tuple[Callable[[str], Logger], Callable[[LogConfig], None]]:
    """Import logging functions dynamically.

    Returns:
        Tuple of (get_logger function, setup_logging function).
    """
    mod = importlib.import_module("intellicrack.core.logging")
    return cast(
        "tuple[Callable[[str], Logger], Callable[[LogConfig], None]]",
        (mod.get_logger, mod.setup_logging),
    )


def _import_process_manager() -> type[ProcessManager]:
    """Import the ProcessManager class dynamically.

    Returns:
        The ProcessManager class.
    """
    mod = importlib.import_module("intellicrack.core.process_manager")
    return cast("type[ProcessManager]", mod.ProcessManager)


def _import_qt_app() -> type[QApplication]:
    """Import QApplication dynamically.

    Returns:
        The QApplication class.
    """
    mod = importlib.import_module("PyQt6.QtWidgets")
    return cast("type[QApplication]", mod.QApplication)


def _import_splash_screen() -> type[SplashScreen]:
    """Import SplashScreen dynamically.

    Returns:
        The SplashScreen class.
    """
    mod = importlib.import_module("intellicrack.ui.dialogs")
    return cast("type[SplashScreen]", mod.SplashScreen)


def _import_theme_icon_managers() -> tuple[type[ThemeManager], type[IconManager]]:
    """Import theme and icon manager classes dynamically.

    Returns:
        Tuple of (ThemeManager class, IconManager class).
    """
    mod = importlib.import_module("intellicrack.ui.resources")
    return cast(
        "tuple[type[ThemeManager], type[IconManager]]",
        (mod.ThemeManager, mod.IconManager),
    )


def _import_orchestrator() -> type[Orchestrator]:
    """Import the Orchestrator class dynamically.

    Returns:
        The Orchestrator class.
    """
    mod = importlib.import_module("intellicrack.core.orchestrator")
    return cast("type[Orchestrator]", mod.Orchestrator)


def _import_session_classes() -> tuple[type[SessionManager], type[SessionStore]]:
    """Import session management classes dynamically.

    Returns:
        Tuple of (SessionManager class, SessionStore class).
    """
    mod = importlib.import_module("intellicrack.core.session")
    return (
        cast("type[SessionManager]", mod.SessionManager),
        cast("type[SessionStore]", mod.SessionStore),
    )


def _import_tool_registry() -> type[ToolRegistry]:
    """Import the ToolRegistry class dynamically.

    Returns:
        The ToolRegistry class.
    """
    mod = importlib.import_module("intellicrack.core.tools")
    return cast("type[ToolRegistry]", mod.ToolRegistry)


def _import_credential_loader() -> type[CredentialLoader]:
    """Import the CredentialLoader class dynamically.

    Returns:
        The CredentialLoader class.
    """
    mod = importlib.import_module("intellicrack.credentials.env_loader")
    return cast("type[CredentialLoader]", mod.CredentialLoader)


def _import_provider_registry() -> type[ProviderRegistry]:
    """Import the ProviderRegistry class dynamically.

    Returns:
        The ProviderRegistry class.
    """
    mod = importlib.import_module("intellicrack.providers.registry")
    return cast("type[ProviderRegistry]", mod.ProviderRegistry)


def _import_main_window() -> type[MainWindow]:
    """Import the MainWindow class dynamically.

    Returns:
        The MainWindow class.
    """
    mod = importlib.import_module("intellicrack.ui.app")
    return cast("type[MainWindow]", mod.MainWindow)


def _setup_qt_and_splash(
    logger: Logger,
) -> tuple[QApplication, SplashScreen] | None:
    """Set up Qt application with theme, icons, and splash screen.

    Args:
        logger: Logger for error reporting.

    Returns:
        Tuple of (app, splash) or None if imports failed.
    """
    try:
        qt_app_cls = _import_qt_app()
        splash_cls = _import_splash_screen()
        theme_mgr_cls, icon_mgr_cls = _import_theme_icon_managers()
    except ImportError as e:
        logger.exception("dependency_import_failed", extra={"error": str(e)})
        logger.warning("install_hint", extra={"command": "pixi install"})
        return None

    try:
        app = qt_app_cls(sys.argv)
        qt_app_cls.setApplicationName("Intellicrack")
        qt_app_cls.setApplicationVersion(_APP_VERSION)
        app.setStyle("Fusion")

        theme_manager = theme_mgr_cls.get_instance()
        theme_manager.apply_theme("dark")

        icon_manager = icon_mgr_cls.get_instance()
        qt_app_cls.setWindowIcon(icon_manager.get_app_icon())

        splash = splash_cls(version=_APP_VERSION)
        splash.show_animated()
        app.processEvents()
    except Exception as e:
        logger.exception("qt_initialization_failed", extra={"error": str(e)})
        return None
    else:
        return app, splash


async def _initialize_providers(
    registry: ProviderRegistry,
    credentials: CredentialLoader,
    logger: Logger,
) -> None:
    """Initialize and connect LLM providers.

    Args:
        registry: Provider registry to populate.
        credentials: Credential loader for API keys.
        logger: Logger instance.
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

    providers = [
        (provider_name_enum.ANTHROPIC, anthropic_mod.AnthropicProvider),
        (provider_name_enum.OPENAI, openai_mod.OpenAIProvider),
        (provider_name_enum.GOOGLE, google_mod.GoogleProvider),
        (provider_name_enum.OLLAMA, ollama_mod.OllamaProvider),
        (provider_name_enum.OPENROUTER, openrouter_mod.OpenRouterProvider),
        (provider_name_enum.HUGGINGFACE, hf_mod.HuggingFaceProvider),
        (provider_name_enum.GROK, grok_mod.GrokProvider),
        (provider_name_enum.LOCAL_TRANSFORMERS, local_mod.LocalTransformersProvider),
    ]

    async def _init_one(provider_name: Any, provider_class: Any) -> None:
        try:
            provider = provider_class()
            if creds := credentials.get_credentials(provider_name):
                try:
                    await asyncio.wait_for(
                        provider.connect(creds),
                        timeout=_PROVIDER_CONNECT_TIMEOUT,
                    )
                    logger.info("provider_connected", extra={"provider": provider_name.value})
                    registry.register(provider)
                except TimeoutError:
                    logger.warning(
                        "provider_connect_timeout",
                        extra={"provider": provider_name.value, "timeout": _PROVIDER_CONNECT_TIMEOUT},
                    )
            else:
                logger.debug("no_credentials", extra={"provider": provider_name.value})
                registry.register(provider)

        except Exception as e:
            logger.exception(
                "provider_init_failed",
                extra={
                    "provider": provider_name.value,
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )

    await asyncio.gather(*(_init_one(pn, pc) for pn, pc in providers))


def main() -> int:
    """Run the Intellicrack application.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    config_cls = _import_config_class()
    get_logger, setup_logging = _import_logging_funcs()
    pm_cls = _import_process_manager()

    cli_options, remaining_args = _parse_args()
    sys.argv = [sys.argv[0], *remaining_args]

    config_path = Path("config.toml")
    config = config_cls.load(config_path) if config_path.exists() else config_cls.default()

    _apply_cli_overrides(config, cli_options)
    config.ensure_directories()

    setup_logging(config.log)
    logger = get_logger("main")
    logger.info("app_starting", extra={"version": _APP_VERSION, "log_level": config.log.level})

    process_manager = pm_cls.get_instance()
    process_manager.install_handlers()
    logger.debug("process_manager_initialized", extra={"handlers_installed": True})

    result = _setup_qt_and_splash(logger)
    if result is None:
        process_manager.uninstall_handlers()
        return 1

    app, splash = result
    logger.info("splash_screen_shown")

    splash.set_progress(5, "Loading configuration...")
    app.processEvents()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        return loop.run_until_complete(
            _run_application(config, app, splash, process_manager, logger),
        )
    except Exception:
        logger.exception("startup_failed")
        return 1
    finally:
        try:
            loop.run_until_complete(
                asyncio.wait_for(
                    process_manager.cleanup_all_async(),
                    timeout=_SHUTDOWN_PROCESS_TIMEOUT,
                ),
            )
        except TimeoutError:
            logger.warning("final_process_cleanup_timeout")
        except Exception:
            logger.debug("final_process_cleanup_failed")
        process_manager.uninstall_handlers()
        loop.close()


def _init_script_engine(config: Config, logger: Logger) -> tuple[object, object]:
    """Initialize the script engine subsystem.

    Args:
        config: Application configuration.
        logger: Logger instance.

    Returns:
        Tuple of (script_manager, script_validator).
    """
    script_gen_mod = importlib.import_module("intellicrack.core.script_gen")
    scripts_dir = config.data_directory / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_gen_mod.ScriptGenerator()
    logger.info("script_engine_initialized")
    return script_gen_mod.ScriptManager(scripts_dir), script_gen_mod.ScriptValidator()


async def _init_model_discovery(
    provider_registry: ProviderRegistry,
    config: Config,
    logger: Logger,
) -> tuple[object, Path]:
    """Initialize the model discovery subsystem.

    Args:
        provider_registry: Provider registry for model queries.
        config: Application configuration.
        logger: Logger instance.

    Returns:
        Tuple of (model_discovery, discovery_cache_path).
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


def _clear_model_cache(logger: Logger) -> None:
    """Clear the global model cache during shutdown.

    Args:
        logger: Logger instance.
    """
    model_cache_mod = importlib.import_module("intellicrack.providers.model_loader")
    get_cache = getattr(model_cache_mod, "get_global_model_cache", None)
    if callable(get_cache):
        try:
            cache = get_cache()
            clear_fn = getattr(cache, "clear", None)
            if callable(clear_fn):
                clear_fn()
            logger.debug("model_cache_cleared")
        except Exception:
            logger.debug("model_cache_cleanup_skipped")


async def _run_application(
    config: Config,
    app: QApplication,
    splash: SplashScreen,
    process_manager: ProcessManager,
    logger: Logger,
) -> int:
    """Run the main application logic.

    Args:
        config: Application configuration.
        app: Qt application instance.
        splash: Splash screen instance.
        process_manager: Process manager instance.
        logger: Logger instance.

    Returns:
        Application exit code.
    """
    splash.set_progress(10, "Loading credentials...")
    app.processEvents()

    credential_loader = _import_credential_loader()(Path(".env"))

    splash.set_progress(20, "Initializing providers...")
    app.processEvents()

    provider_registry = _import_provider_registry()()
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
    )

    splash.set_progress(90, "Initializing script engine...")
    app.processEvents()

    script_manager, script_validator = _init_script_engine(config, logger)

    splash.set_progress(93, "Initializing model discovery...")
    app.processEvents()

    model_discovery, discovery_cache = await _init_model_discovery(provider_registry, config, logger)

    splash.set_progress(95, "Initializing UI...")
    app.processEvents()

    window = _import_main_window()(config, orchestrator)
    window.wire_script_manager(script_manager, script_validator)
    window.set_model_discovery(cast("ModelDiscovery", model_discovery))

    splash.set_progress(100, "Ready")
    app.processEvents()
    splash.finish_animated(window)

    logger.info("ui_started")
    exit_code = app.exec()

    logger.info("shutdown_started")
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

    logger.info("shutdown_complete")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
