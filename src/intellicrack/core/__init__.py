# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Core module for Intellicrack.

This module contains the fundamental types, configuration, session management, and the main orchestrator that coordinates AI-driven tool
operations.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, cast

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
    get_env_file,
    get_project_root,
)
from intellicrack.core.logging import get_logger, setup_logging
from intellicrack.core.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    OrchestratorStats,
    PendingConfirmation,
)
from intellicrack.core.process_manager import (
    ProcessManager,
    ProcessType,
    TrackedProcess,
)
from intellicrack.core.script_gen import (
    BypassStrategy,
    Script,
    ScriptContext,
    ScriptGenerator,
    ScriptLanguage,
    ScriptManager,
    ScriptValidator,
)
from intellicrack.core.session import (
    Session,
    SessionManager,
    SessionMetadata,
    SessionStore,
)
from intellicrack.core.types import (
    BinaryInfo,
    BreakpointInfo,
    BridgeAnalysisSummary,
    ConfirmationLevel,
    CrossReference,
    ExportInfo,
    FunctionInfo,
    HookInfo,
    ImportInfo,
    MemoryRegion,
    Message,
    ModelInfo,
    ModuleInfo,
    ParameterInfo,
    PatchInfo,
    ProcessInfo,
    ProviderCredentials,
    ProviderName,
    SectionInfo,
    StringInfo,
    ThreadInfo,
    ToolCall,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
    ToolState,
    VariableInfo,
)


if TYPE_CHECKING:
    from intellicrack.core.tools import (
        ToolRegistry,
        ToolStatus,
    )


__all__: list[str] = [
    "BinaryInfo",
    "BreakpointInfo",
    "BridgeAnalysisSummary",
    "BypassStrategy",
    "Config",
    "ConfirmationLevel",
    "CrossReference",
    "ExportInfo",
    "FunctionInfo",
    "HookInfo",
    "ImportInfo",
    "LogConfig",
    "MemoryRegion",
    "Message",
    "ModelInfo",
    "ModuleInfo",
    "Orchestrator",
    "OrchestratorConfig",
    "OrchestratorStats",
    "ParameterInfo",
    "PatchInfo",
    "PendingConfirmation",
    "ProcessInfo",
    "ProcessManager",
    "ProcessType",
    "ProviderConfig",
    "ProviderCredentials",
    "ProviderName",
    "SandboxConfig",
    "Script",
    "ScriptContext",
    "ScriptGenerator",
    "ScriptLanguage",
    "ScriptManager",
    "ScriptValidator",
    "SectionInfo",
    "Session",
    "SessionConfig",
    "SessionManager",
    "SessionMetadata",
    "SessionStore",
    "StringInfo",
    "ThreadInfo",
    "ToolCall",
    "ToolConfig",
    "ToolDefinition",
    "ToolError",
    "ToolFunction",
    "ToolName",
    "ToolParameter",
    "ToolRegistry",
    "ToolResult",
    "ToolState",
    "ToolStatus",
    "TrackedProcess",
    "UIConfig",
    "VariableInfo",
    "get_config_dir",
    "get_config_file",
    "get_env_file",
    "get_logger",
    "get_project_root",
    "setup_logging",
]


def __getattr__(name: str) -> type[ToolRegistry | ToolStatus]:
    """Lazily resolve the tool-registry re-exports from :mod:`intellicrack.core.tools`.

    Importing :mod:`intellicrack.core.tools` at package-import time would
    pull the entire :mod:`intellicrack.bridges` layer in through a
    partially initialized :mod:`intellicrack.bridges.base`, closing an
    import cycle (``bridges`` -> ``bridges.base`` -> ``core`` ->
    ``core.tools`` -> ``bridges.base``). Deferring the import until
    ``ToolRegistry`` or ``ToolStatus`` is first accessed lets any
    ``intellicrack.bridges.<bridge>`` submodule be imported as the very
    first import in a fresh interpreter. The resolved class is cached on
    the package globals so subsequent look-ups bypass this hook.

    Args:
        name: Attribute name requested from :mod:`intellicrack.core`.

    Returns:
        type[ToolRegistry | ToolStatus]: The resolved registry class.

    Raises:
        AttributeError: If ``name`` is not a lazily exported tool symbol.
    """
    if name in {"ToolRegistry", "ToolStatus"}:
        module = importlib.import_module("intellicrack.core.tools")
        value = cast("type[ToolRegistry | ToolStatus]", getattr(module, name))
        globals()[name] = value
        return value
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """Return the package's public attributes including lazy tool exports.

    Returns:
        list[str]: Sorted union of ``__all__`` and the current globals.
    """
    return sorted(set(__all__) | set(globals()))
