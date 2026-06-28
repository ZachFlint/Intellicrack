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
    from intellicrack.main import main
    main()

    Or run as a module:
    python -m intellicrack
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ._metadata import (
        __author__,
        __copyright__,
        __email__,
        __license__,
        __summary__,
        __url__,
        __version__,
    )
    from .core import (
        Config,
        Orchestrator,
        ScriptManager,
        SessionManager,
        ToolRegistry,
    )
    from .main import main


def __getattr__(name: str) -> object:
    """Lazy import for main components.

    This allows importing frequently used components directly from
    the intellicrack namespace without loading all dependencies upfront.

    Args:
        name: The name of the attribute to retrieve.

    Returns:
        object: The requested module attribute.

    Raises:
        AttributeError: If the attribute is not found.
    """
    metadata_names = {
        "__author__",
        "__copyright__",
        "__email__",
        "__license__",
        "__summary__",
        "__url__",
        "__version__",
    }
    attr: object
    if name in metadata_names:
        attr = getattr(importlib.import_module("._metadata", __name__), name)
    elif name == "main":
        attr = importlib.import_module(".main", __name__).main
    elif name == "Config":
        attr = importlib.import_module(".core.config", __name__).Config
    elif name == "Orchestrator":
        attr = importlib.import_module(".core.orchestrator", __name__).Orchestrator
    elif name == "SessionManager":
        attr = importlib.import_module(".core.session", __name__).SessionManager
    elif name == "ToolRegistry":
        attr = importlib.import_module(".core.tools", __name__).ToolRegistry
    elif name == "ScriptManager":
        attr = importlib.import_module(".core.script_gen", __name__).ScriptManager
    else:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)

    if name not in metadata_names:
        get_logger = importlib.import_module(".core.logging", __name__).get_logger
        get_logger(__name__).debug("lazy_import_resolved", attribute=name)
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
