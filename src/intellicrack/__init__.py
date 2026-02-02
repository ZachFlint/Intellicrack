"""Intellicrack: AI-powered reverse engineering orchestration platform.

This package provides a unified interface for controlling reverse engineering tools
(Ghidra, x64dbg, Frida, radare2) through natural language AI interaction.

The architecture consists of:
    - Core: Configuration, logging, types, session management, orchestration
    - Providers: LLM provider implementations (Anthropic, OpenAI, Google, Ollama, OpenRouter)
    - Bridges: Tool integrations (Ghidra, x64dbg, Frida, radare2, process control)
    - Sandbox: Windows Sandbox for isolated binary execution
    - UI: PyQt6-based graphical interface
    - Credentials: Secure API key management from .env files

Example:
    from intellicrack import main
    main()

    Or run as a module:
    python -m intellicrack
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING


_logger = logging.getLogger("intellicrack")

__version__ = "1.0.0"
__author__ = "Zachary Flint"
__email__ = "zach.flint2@gmail.com"  # noqa: RUF067

if TYPE_CHECKING:
    from intellicrack.core import (
        Config,
        Orchestrator,
        ScriptManager,
        SessionManager,
        ToolRegistry,
    )
    from intellicrack.main import main


def __getattr__(name: str) -> object:
    """Lazy import for main components.

    This allows importing frequently used components directly from
    the intellicrack namespace without loading all dependencies upfront.

    Args:
        name: The name of the attribute to retrieve.

    Returns:
        The requested module attribute.

    Raises:
        AttributeError: If the attribute is not found.
    """
    if name == "main":
        from intellicrack.main import main as _main  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _main
    if name == "Config":
        from intellicrack.core.config import Config as _Config  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _Config
    if name == "Orchestrator":
        from intellicrack.core.orchestrator import Orchestrator as _Orchestrator  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _Orchestrator
    if name == "SessionManager":
        from intellicrack.core.session import SessionManager as _SessionManager  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _SessionManager
    if name == "ToolRegistry":
        from intellicrack.core.tools import ToolRegistry as _ToolRegistry  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _ToolRegistry
    if name == "ScriptManager":
        from intellicrack.core.script_gen import ScriptManager as _ScriptManager  # noqa: PLC0415

        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return _ScriptManager

    msg = f"module {__name__!r} has no attribute {name!r}"
    _logger.debug("lazy_import_attribute_error", extra={"attribute": name})
    raise AttributeError(msg)


__all__: list[str] = [
    "Config",
    "Orchestrator",
    "ScriptManager",
    "SessionManager",
    "ToolRegistry",
    "__author__",
    "__email__",
    "__version__",
    "main",
]
