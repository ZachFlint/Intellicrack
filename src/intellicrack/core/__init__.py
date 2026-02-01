"""Core module for Intellicrack.

This module contains the fundamental types, configuration, session management,
and the main orchestrator that coordinates AI-driven tool operations.
"""

from __future__ import annotations

from .config import (
    Config,
    LogConfig,
    ProviderConfig,
    SandboxConfig,
    SessionConfig,
    ToolConfig,
    UIConfig,
)
from .logging import get_logger, setup_logging
from .orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    OrchestratorStats,
    PendingConfirmation,
)
from .process_manager import (
    ProcessManager,
    ProcessType,
    TrackedProcess,
)
from .script_gen import (
    BypassStrategy,
    GeneratedScript,
    Script,
    ScriptContext,
    ScriptGenerator,
    ScriptLanguage,
    ScriptManager,
    ScriptValidator,
)
from .session import (
    Session,
    SessionManager,
    SessionMetadata,
    SessionStore,
)
from .tools import (
    ToolRegistry,
    ToolStatus,
)
from .types import (
    BinaryInfo,
    BreakpointInfo,
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


__all__: list[str] = [  # noqa: RUF022
    # Config
    "Config",
    "LogConfig",
    "ProviderConfig",
    "SandboxConfig",
    "SessionConfig",
    "ToolConfig",
    "UIConfig",
    # Logging
    "get_logger",
    "setup_logging",
    # Orchestrator
    "Orchestrator",
    "OrchestratorConfig",
    "OrchestratorStats",
    "PendingConfirmation",
    # Script Infrastructure
    "BypassStrategy",
    "GeneratedScript",
    "Script",
    "ScriptContext",
    "ScriptGenerator",
    "ScriptLanguage",
    "ScriptManager",
    "ScriptValidator",
    # Session
    "Session",
    "SessionManager",
    "SessionMetadata",
    "SessionStore",
    # Process Manager
    "ProcessManager",
    "ProcessType",
    "TrackedProcess",
    # Tools
    "ToolRegistry",
    "ToolStatus",
    # Types
    "BinaryInfo",
    "BreakpointInfo",
    "ConfirmationLevel",
    "CrossReference",
    "ExportInfo",
    "FunctionInfo",
    "HookInfo",
    "ImportInfo",
    "MemoryRegion",
    "Message",
    "ModelInfo",
    "ModuleInfo",
    "ParameterInfo",
    "PatchInfo",
    "ProcessInfo",
    "ProviderCredentials",
    "ProviderName",
    "SectionInfo",
    "StringInfo",
    "ThreadInfo",
    "ToolCall",
    "ToolDefinition",
    "ToolError",
    "ToolFunction",
    "ToolName",
    "ToolParameter",
    "ToolResult",
    "ToolState",
    "VariableInfo",
]
