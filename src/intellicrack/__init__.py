# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Intellicrack: AI-powered reverse engineering orchestration platform.

This package provides a unified interface for controlling reverse engineering tools
(Ghidra, x64dbg, Frida, Cutter/Rizin) through natural language AI interaction.

The architecture consists of:
    - Core: Configuration, logging, types, session management, orchestration
    - Providers: LLM provider implementations (Anthropic, OpenAI, Google, Ollama, OpenRouter)
    - Bridges: Tool integrations (Ghidra, x64dbg, Frida, Cutter/Rizin, process control)
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
from typing import TYPE_CHECKING

import structlog

from intellicrack._metadata import (
    __author__,
    __copyright__,
    __email__,
    __license__,
    __summary__,
    __url__,
    __version__,
)


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
    """
    Lazy import for main components.

    This allows importing frequently used components directly from
    the intellicrack namespace without loading all dependencies upfront.

    Args:
        name: The name of the attribute to retrieve.

    Returns:
        object: The requested module attribute.

    Raises:
        AttributeError: If the attribute is not found.
    """
    attr: object
    if name == "main":
        attr = importlib.import_module("intellicrack.main").main
    elif name == "Config":
        attr = importlib.import_module("intellicrack.core.config").Config
    elif name == "Orchestrator":
        attr = importlib.import_module("intellicrack.core.orchestrator").Orchestrator
    elif name == "SessionManager":
        attr = importlib.import_module("intellicrack.core.session").SessionManager
    elif name == "ToolRegistry":
        attr = importlib.import_module("intellicrack.core.tools").ToolRegistry
    elif name == "ScriptManager":
        attr = importlib.import_module("intellicrack.core.script_gen").ScriptManager
    else:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)

    structlog.get_logger("intellicrack").debug("lazy_import_resolved", attribute=name)
    return attr


__all__: list[str] = [
    "Config",
    "Orchestrator",
    "ScriptManager",
    "SessionManager",
    "ToolRegistry",
    "__author__",
    "__copyright__",
    "__email__",
    "__license__",
    "__summary__",
    "__url__",
    "__version__",
    "main",
]
