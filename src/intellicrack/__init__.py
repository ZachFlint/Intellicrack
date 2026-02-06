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

import importlib
import logging
from typing import TYPE_CHECKING


_logger = logging.getLogger("intellicrack")

__version__ = "1.0.0"
__author__ = "Zachary Flint"
__email__ = "zach.flint2@gmail.com"

if TYPE_CHECKING:
    from intellicrack.core import (
        Config,
        Orchestrator,
        ScriptManager,
        SessionManager,
        ToolRegistry,
    )
    from intellicrack.main import main

_LAZY_IMPORT_MAP: dict[str, tuple[str, str]] = {
    "main": ("intellicrack.main", "main"),
    "Config": ("intellicrack.core.config", "Config"),
    "Orchestrator": ("intellicrack.core.orchestrator", "Orchestrator"),
    "SessionManager": ("intellicrack.core.session", "SessionManager"),
    "ToolRegistry": ("intellicrack.core.tools", "ToolRegistry"),
    "ScriptManager": ("intellicrack.core.script_gen", "ScriptManager"),
}


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
    if name in _LAZY_IMPORT_MAP:
        module_path, attr_name = _LAZY_IMPORT_MAP[name]
        module = importlib.import_module(module_path)
        attr = getattr(module, attr_name)
        _logger.debug("lazy_import_resolved", extra={"attribute": name})
        return attr

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
