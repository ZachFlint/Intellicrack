# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Core module for Intellicrack.

This module contains the fundamental types, configuration, session management, and the main orchestrator that coordinates AI-driven tool
operations.
"""

from __future__ import annotations

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
from intellicrack.core.tools import (
    ToolRegistry,
    ToolStatus,
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
    "get_logger",
    "get_project_root",
    "setup_logging",
]
