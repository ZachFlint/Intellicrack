"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration,
logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from logging import Logger

    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.registry import ProviderRegistry

_APP_VERSION = "2.0.0"
_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


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
    parser.add_argument(
        "--version",
        action="version",
        version=f"Intellicrack {_APP_VERSION}",
    )

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG level logging (maximum verbosity)",
    )
    verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Enable WARNING level logging (reduced output)",
    )
    verbosity_group.add_argument(
        "--log-level",
        choices=list(_VALID_LOG_LEVELS),
        default=None,
        metavar="LEVEL",
        help="Set explicit log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    parser.add_argument(
        "--no-console-log",
        action="store_true",
        default=False,
        help="Disable console log output",
    )
    parser.add_argument(
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


def _apply_cli_overrides(config: object, cli: _CLIOptions) -> None:
    """Apply CLI flag overrides to the loaded config in-place.

    Args:
        config: Config instance whose log sub-config will be mutated.
        cli: Parsed CLI options with any overrides.
    """
    from intellicrack.core.config import Config  # noqa: PLC0415

    if not isinstance(config, Config):
        return

    if cli.log_level is not None:
        config.log.level = cli.log_level
    if cli.disable_console_log:
        config.log.console_enabled = False
    if cli.disable_file_log:
        config.log.file_enabled = False


def main() -> int:  # noqa: PLR0914
    """Run the Intellicrack application.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    from intellicrack.core.config import Config  # noqa: PLC0415
    from intellicrack.core.logging import get_logger, setup_logging  # noqa: PLC0415
    from intellicrack.core.process_manager import ProcessManager  # noqa: PLC0415

    cli_options, remaining_args = _parse_args()
    sys.argv = [sys.argv[0], *remaining_args]

    config_path = Path("config.toml")
    config = Config.load(config_path) if config_path.exists() else Config.default()

    _apply_cli_overrides(config, cli_options)

    setup_logging(config.log)
    logger = get_logger("main")
    logger.info(
        "app_starting",
        extra={"version": _APP_VERSION, "log_level": config.log.level},
    )

    process_manager = ProcessManager.get_instance()
    process_manager.install_handlers()
    logger.debug("process_manager_initialized", extra={"handlers_installed": True})

    try:
        from PyQt6.QtWidgets import QApplication  # noqa: PLC0415

        from intellicrack.core.orchestrator import Orchestrator  # noqa: PLC0415
        from intellicrack.core.session import SessionManager, SessionStore  # noqa: PLC0415
        from intellicrack.core.tools import ToolRegistry  # noqa: PLC0415
        from intellicrack.credentials.env_loader import CredentialLoader  # noqa: PLC0415
        from intellicrack.providers.registry import ProviderRegistry  # noqa: PLC0415
        from intellicrack.ui.app import MainWindow  # noqa: PLC0415

    except ImportError as e:
        print(f"Required dependencies not available: {e}")
        print("Install required packages with: pixi install")
        return 1

    app = QApplication(sys.argv)
    qt_app: type[QApplication] = QApplication
    qt_app.setApplicationName("Intellicrack")
    qt_app.setApplicationVersion(_APP_VERSION)
    app.setStyle("Fusion")

    from intellicrack.ui.dialogs import SplashScreen  # noqa: PLC0415
    from intellicrack.ui.resources import IconManager, ThemeManager  # noqa: PLC0415

    theme_manager = ThemeManager.get_instance()
    theme_manager.apply_theme("dark")

    icon_manager = IconManager.get_instance()
    qt_app.setWindowIcon(icon_manager.get_app_icon())

    splash = SplashScreen()
    splash.show()
    app.processEvents()

    splash.set_progress(5, "Loading configuration...")
    app.processEvents()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        splash.set_progress(10, "Loading credentials...")
        app.processEvents()

        env_path = Path(".env")
        credential_loader = CredentialLoader(env_path)

        splash.set_progress(20, "Initializing providers...")
        app.processEvents()

        provider_registry = ProviderRegistry()
        loop.run_until_complete(
            _initialize_providers(
                provider_registry,
                credential_loader,
                logger,
            )
        )

        splash.set_progress(50, "Initializing tools...")
        app.processEvents()

        tool_registry = ToolRegistry(config.tools_directory)
        loop.run_until_complete(tool_registry.initialize())

        splash.set_progress(70, "Initializing session manager...")
        app.processEvents()

        session_store = SessionStore(config.data_directory / "sessions.db")
        session_manager = SessionManager(session_store)

        splash.set_progress(85, "Creating orchestrator...")
        app.processEvents()

        orchestrator = Orchestrator(
            provider_registry=provider_registry,
            tool_registry=tool_registry,
            session_manager=session_manager,
        )

        splash.set_progress(95, "Initializing UI...")
        app.processEvents()

        window = MainWindow(config, orchestrator)

        splash.set_progress(100, "Ready")
        app.processEvents()

        splash.finish(window)
        window.show()

        logger.info("ui_started")
        exit_code = app.exec()

        logger.info("shutdown_started")
        loop.run_until_complete(orchestrator.shutdown())
        loop.run_until_complete(session_manager.close())
        loop.run_until_complete(process_manager.cleanup_all_async())

        logger.info("shutdown_complete")

    except Exception:
        logger.exception("startup_failed")
        return 1
    else:
        return exit_code

    finally:
        loop.run_until_complete(process_manager.cleanup_all_async())
        process_manager.uninstall_handlers()
        loop.close()


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
    from intellicrack.core.types import ProviderName  # noqa: PLC0415
    from intellicrack.providers.anthropic import AnthropicProvider  # noqa: PLC0415
    from intellicrack.providers.google import GoogleProvider  # noqa: PLC0415
    from intellicrack.providers.huggingface import HuggingFaceProvider  # noqa: PLC0415
    from intellicrack.providers.ollama import OllamaProvider  # noqa: PLC0415
    from intellicrack.providers.openai import OpenAIProvider  # noqa: PLC0415
    from intellicrack.providers.openrouter import OpenRouterProvider  # noqa: PLC0415

    providers = [
        (ProviderName.ANTHROPIC, AnthropicProvider),
        (ProviderName.OPENAI, OpenAIProvider),
        (ProviderName.GOOGLE, GoogleProvider),
        (ProviderName.OLLAMA, OllamaProvider),
        (ProviderName.OPENROUTER, OpenRouterProvider),
        (ProviderName.HUGGINGFACE, HuggingFaceProvider),
    ]

    for provider_name, provider_class in providers:
        try:
            provider = provider_class()
            creds = credentials.get_credentials(provider_name)

            if creds:
                await provider.connect(creds)
                logger.info("provider_connected", extra={"provider": provider_name.value})
            else:
                logger.debug("no_credentials", extra={"provider": provider_name.value})

            registry.register(provider)

        except Exception as e:
            logger.warning("provider_init_failed", extra={"provider": provider_name.value, "error": str(e)})


if __name__ == "__main__":
    sys.exit(main())
