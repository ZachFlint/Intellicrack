"""Main application entry point for Intellicrack.

This module bootstraps the application, initializing configuration,
logging, providers, tool bridges, and the GUI.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from logging import Logger

    from intellicrack.credentials.env_loader import CredentialLoader
    from intellicrack.providers.registry import ProviderRegistry


def main() -> int:  # noqa: PLR0914
    """Run the Intellicrack application.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    from intellicrack.core.config import Config  # noqa: PLC0415
    from intellicrack.core.logging import get_logger, setup_logging  # noqa: PLC0415
    from intellicrack.core.process_manager import ProcessManager  # noqa: PLC0415

    config_path = Path("config.toml")
    config = Config.load(config_path) if config_path.exists() else Config.default()

    setup_logging(config.log)
    logger = get_logger("main")
    logger.info("app_starting", extra={"version": "2.0.0"})

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
    qt_app.setApplicationVersion("2.0.0")
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
