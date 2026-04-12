# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Main AI agent orchestrator for Intellicrack.

This module provides the central orchestration layer that coordinates between the user, LLM providers, and tool bridges to execute reverse
engineering workflows.
"""

from __future__ import annotations

import asyncio
import hashlib
import pathlib
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, cast
from uuid import uuid4

import structlog.contextvars

from intellicrack.bridges.schemas import (
    build_schema_parameters,
    get_all_schemas_for_provider,
    validate_and_convert,
)
from intellicrack.core.analysis_aggregator import AnalysisAggregator
from intellicrack.core.logging import get_logger, log_analysis_operation
from intellicrack.core.types import (
    CacheConfig,
    ConfirmationLevel,
    Message,
    PatchInfo,
    ProviderName,
    ThinkingConfig,
    ToolChoice,
    ToolError,
    ToolName,
    ToolResult,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from pathlib import Path
    from typing import Any

    from intellicrack.core.script_gen import ScriptManager
    from intellicrack.core.session import Session, SessionManager
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.types import (
        BinaryInfo,
        BridgeAnalysisSummary,
        ExportInfo,
        ImportInfo,
        SectionInfo,
        ToolCall,
        ToolDefinition,
    )
    from intellicrack.providers.base import LLMProvider
    from intellicrack.providers.registry import ProviderRegistry


_logger = get_logger("core.orchestrator")

OrchestratorState = Literal["idle", "processing", "waiting_confirmation", "cancelled"]


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator.

    Attributes:
        confirmation_level: When to ask for user confirmation.
        max_iterations: Maximum tool call iterations per request.
        timeout_seconds: Timeout for LLM requests.
        temperature: LLM temperature setting.
        max_tokens: Maximum tokens in LLM response.
        stream_responses: Whether to stream LLM responses.
        stream_mode: Streaming mode ("auto", "always", "never").
        tool_choice: How the model should select tools.
        thinking: Extended thinking configuration.
        cache: Prompt caching configuration.
    """

    confirmation_level: ConfirmationLevel = ConfirmationLevel.DESTRUCTIVE
    max_iterations: int = 20
    timeout_seconds: int = 120
    temperature: float = 0.7
    max_tokens: int = 4096
    stream_responses: bool = True
    stream_mode: Literal["auto", "always", "never"] = "auto"
    tool_choice: ToolChoice | None = None
    thinking: ThinkingConfig | None = None
    cache: CacheConfig | None = None


@dataclass
class PendingConfirmation:
    """A tool call waiting for user confirmation."""

    call: ToolCall
    future: asyncio.Future[bool]


@dataclass
class OrchestratorStats:
    """Statistics for orchestrator operations.

    Attributes:
        total_requests: Total user requests processed.
        total_tool_calls: Total tool calls executed.
        successful_tool_calls: Successful tool call count.
        failed_tool_calls: Failed tool call count.
        total_tokens_used: Approximate tokens used.
        average_response_time_ms: Average response time.
    """

    total_requests: int = 0
    total_tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    total_tokens_used: int = 0
    average_response_time_ms: float = 0.0
    _response_times: deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    def record_response_time(self, time_ms: float) -> None:
        """Record a response time and update rolling average.

        Maintains a bounded window of the last 1000 response times to
        prevent unbounded memory growth.

        Args:
            time_ms: Response time in milliseconds.
        """
        self._response_times.append(time_ms)
        self.average_response_time_ms = sum(self._response_times) / len(self._response_times)

    def to_dict(self) -> dict[str, Any]:
        """Convert statistics to dictionary for reporting.

        Returns:
            dict[str, Any]: Dictionary containing all statistics.
        """
        return {
            "total_requests": self.total_requests,
            "total_tool_calls": self.total_tool_calls,
            "successful_tool_calls": self.successful_tool_calls,
            "failed_tool_calls": self.failed_tool_calls,
            "total_tokens_used": self.total_tokens_used,
            "average_response_time_ms": self.average_response_time_ms,
        }


class Orchestrator:
    """Main AI agent orchestrator.

    Manages the conversation loop between the user, LLM, and tools.
    Coordinates tool execution and handles confirmations.

    Args:
        provider_registry: Registry of LLM providers used for routing chat requests.
        tool_registry: Registry of tool bridges available for execution.
        session_manager: Session state manager that persists conversation state.
        config: Optional configuration override; defaults to ``OrchestratorConfig()``.

    Attributes:
        DESTRUCTIVE_PATTERNS: Substrings identifying tool calls that modify state and require user confirmation.
    """

    DESTRUCTIVE_PATTERNS: tuple[str, ...] = (
        "write",
        "patch",
        "modify",
        "delete",
        "remove",
        "set_",
        "assemble",
        "inject",
        "intercept_return",
        "hook",
        "replace",
        "overwrite",
    )

    def __init__(
        self,
        provider_registry: ProviderRegistry,
        tool_registry: ToolRegistry,
        session_manager: SessionManager,
        config: OrchestratorConfig | None = None,
    ) -> None:
        """Initialize the orchestrator with registries and session manager.

        Args:
            provider_registry: Registry of LLM providers used for routing chat requests.
            tool_registry: Registry of tool bridges available for execution.
            session_manager: Session state manager that persists conversation state.
            config: Optional configuration override; defaults to ``OrchestratorConfig()``.
        """
        self._providers = provider_registry
        self._tools = tool_registry
        self._sessions = session_manager
        self._config = config or OrchestratorConfig()

        self._current_session: Session | None = None
        self._state: OrchestratorState = "idle"
        self._stats = OrchestratorStats()
        self._pending_confirmation: PendingConfirmation | None = None
        self._cancel_event = asyncio.Event()

        self._script_manager: ScriptManager | None = None
        self._shutdown_called: bool = False

        self._on_message: Callable[[Message], None] | None = None
        self._on_tool_call: Callable[[ToolCall], None] | None = None
        self._on_tool_result: Callable[[ToolResult], None] | None = None
        self._on_stream_chunk: Callable[[str], None] | None = None
        self._on_bridge_analysis: Callable[[BridgeAnalysisSummary], None] | None = None
        self._confirmation_callback: Callable[[ToolCall], bool] | None = None
        self._async_confirmation_callback: Callable[[ToolCall], asyncio.Future[bool]] | None = None

    @property
    def state(self) -> OrchestratorState:
        """Get current orchestrator state.

        Returns:
            OrchestratorState: Current state.
        """
        return self._state

    @property
    def current_session(self) -> Session | None:
        """Get current session.

        Returns:
            Session | None: Current session or None.
        """
        return self._current_session

    @property
    def stats(self) -> OrchestratorStats:
        """Get orchestrator statistics.

        Returns:
            OrchestratorStats: Statistics instance.
        """
        return self._stats

    @property
    def provider_registry(self) -> ProviderRegistry:
        """Get the provider registry.

        Returns:
            ProviderRegistry: The provider registry instance.
        """
        return self._providers

    def set_script_manager(self, manager: ScriptManager) -> None:
        """Set the script manager for recording tool execution results.

        Args:
            manager: The ScriptManager instance.
        """
        self._script_manager = manager

    async def start_session(
        self,
        provider: str | ProviderName,
        model: str,
        binary_path: Path | None = None,
    ) -> Session:
        """Start a new session.

        Args:
            provider: LLM provider to use.
            model: Model ID to use.
            binary_path: Optional binary to load.

        Returns:
            Session: New session instance.

        Raises:
            ValueError: If provider not available.
        """
        if isinstance(provider, str):
            provider = ProviderName(provider.lower())

        provider_instance = self._providers.get(provider)
        if provider_instance is None or not provider_instance.is_connected:
            _logger.warning(
                "provider_not_found",
                provider=provider.value,
                connected=getattr(provider_instance, "is_connected", None),
            )
            error_message = f"Provider not available: {provider.value}"
            raise ValueError(error_message)

        session = await self._sessions.create(
            provider=provider,
            model=model,
        )

        if binary_path is not None:
            binary_info = await self._load_binary(binary_path)
            session.binaries.append(binary_info)
            session.active_binary_index = 0

        self._current_session = session
        self._state = "idle"

        structlog.contextvars.bind_contextvars(
            session_id=session.id,
            provider=provider.value,
            model=model,
        )

        _logger.info(
            "session_started",
            session_id=session.id,
            provider=provider.value,
            model=model,
        )

        return session

    async def load_session(self, session_id: str) -> Session:
        """Load an existing session.

        Args:
            session_id: ID of session to load.

        Returns:
            Session: Loaded session.

        Raises:
            ValueError: If session not found.
        """
        session = await self._sessions.get(session_id)
        if session is None:
            error_message = f"Session not found: {session_id}"
            raise ValueError(error_message)

        self._current_session = session
        self._state = "idle"

        structlog.contextvars.bind_contextvars(
            session_id=session.id,
            provider=session.provider.value,
            model=session.model,
        )

        _logger.info("session_loaded", session_id=session_id)
        return session

    async def _load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file for analysis using lief.

        Parses PE/ELF/Mach-O headers to populate a BinaryInfo with
        sections, imports, exports, architecture, and hashes.

        Args:
            path: Path to the binary.

        Returns:
            BinaryInfo: Binary information.
        """
        _logger.debug("binary_load_started", path=str(path), state=self._state)
        info = await asyncio.to_thread(_parse_binary_with_lief, path)
        _logger.debug(
            "binary_load_completed",
            path=str(path),
            file_type=info.file_type,
            architecture=info.architecture,
        )
        return info

    async def process_user_input(self, text: str) -> None:
        """Process user input and generate response.

        This is the main agent loop:
        1. Add user message to session
        2. Send to LLM with tool definitions
        3. If LLM returns tool calls, execute them
        4. Send tool results back to LLM
        5. Repeat until LLM returns final text response
        6. Add assistant message to session

        Args:
            text: User's natural language input.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        self._state = "processing"
        self._cancel_event.clear()
        self._stats.total_requests += 1
        start_time = time.time()

        request_id = uuid4().hex[:12]
        structlog.contextvars.bind_contextvars(request_id=request_id)

        user_message = Message(
            role="user",
            content=text,
            timestamp=datetime.now(tz=UTC),
        )
        self._current_session.messages.append(user_message)

        if self._on_message:
            self._on_message(user_message)

        try:
            await self._run_agent_loop()
        except asyncio.CancelledError:
            _logger.info("request_cancelled", state=self._state)
            self._state = "cancelled"
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.record_response_time(elapsed_ms)

            if self._state != "cancelled":
                self._state = "idle"

            await self._sessions.update(self._current_session)

    async def _run_agent_loop(self) -> None:
        """Run the main agent loop until completion or cancellation.

        Raises:
            RuntimeError: If provider is not available.
            CancelledError: If the operation is cancelled.
        """
        if self._current_session is None:
            return

        if not self._providers.has_connected_provider():
            error_message = "No provider is connected"
            raise RuntimeError(error_message)

        provider = self._providers.get(self._current_session.provider)
        if provider is None or not provider.is_connected:
            error_message = f"Provider not available or disconnected: {self._current_session.provider.value}"
            raise RuntimeError(error_message)

        tool_definitions = self._tools.get_tool_definitions()
        self._validate_tool_schemas(tool_definitions, provider)
        context_window = await self._get_model_context_window(provider)
        iteration = 0

        while iteration < self._config.max_iterations:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError

            iteration += 1
            _logger.debug("agent_loop_iteration", iteration=iteration)

            messages = self._build_messages()
            messages = self.trim_messages_to_context_window(messages, context_window)

            response, tool_calls = await self._call_llm(
                provider=provider,
                messages=messages,
                tools=tool_definitions,
                is_final_response=self._is_final_response_expected(),
            )

            if response.content:
                self._current_session.messages.append(response)
                if self._on_message:
                    self._on_message(response)

            if not tool_calls:
                _logger.debug("agent_loop_complete", reason="no_tool_calls")
                break

            tool_results = await self._execute_tool_calls(tool_calls)

            tool_message = Message(
                role="tool",
                content="",
                tool_results=tool_results,
                timestamp=datetime.now(tz=UTC),
            )
            self._current_session.messages.append(tool_message)

            if all(not r.success for r in tool_results):
                _logger.warning("agent_loop_stopping", reason="all_tool_calls_failed")
                break

        if iteration >= self._config.max_iterations:
            _logger.warning("agent_loop_max_iterations", max_iterations=self._config.max_iterations)

    def _is_final_response_expected(self) -> bool:
        """Determine whether a final response is expected.

        Returns:
            bool: True if the next response is likely final.
        """
        if self._current_session is None:
            return False
        if not self._current_session.messages:
            return False
        return self._current_session.messages[-1].role == "tool"

    def _build_messages(self) -> list[Message]:
        """Build message list for LLM including system prompt.

        Returns:
            list[Message]: List of messages with system prompt prepended.
        """
        if self._current_session is None:
            return []

        system_prompt = self._generate_system_prompt()
        system_message = Message(
            role="system",
            content=system_prompt,
            timestamp=datetime.now(tz=UTC),
        )

        messages = [system_message, *self._current_session.messages]
        _logger.debug(
            "messages_built",
            message_count=len(messages),
            system_prompt_length=len(system_prompt),
        )
        return messages

    def _generate_system_prompt(self) -> str:
        """Generate system prompt for the LLM.

        Returns:
            str: System prompt describing available tools and capabilities.
        """
        if self._current_session is None:
            return ""

        prompt_parts = [
            "You are Intellicrack, an advanced AI-powered reverse engineering assistant specialized in analyzing software licensing protections.",
            "",
            "Your capabilities include:",
            "- Static analysis via Ghidra (decompilation, disassembly, cross-references)",
            "- Dynamic analysis via Frida (hooking, memory manipulation, tracing)",
            "- Debugging via x64dbg (breakpoints, stepping, register manipulation)",
            "- Binary analysis via Cutter/Rizin (disassembly, analysis, patching)",
            "- Process control (memory reading/writing, DLL injection)",
            "- Binary operations (loading, parsing, patching)",
            "- Sandbox execution (isolated testing, behavior monitoring, snapshot/restore)",
            "",
            "## Ghidra Tools",
            "",
            "### Core Analysis",
            "- `ghidra.load_binary` / `ghidra.analyze` - Load and analyze binaries",
            "- `ghidra.get_functions` / `ghidra.get_function` - List/inspect functions",
            "- `ghidra.decompile` / `ghidra.disassemble` - View code",
            "- `ghidra.get_xrefs_to` / `ghidra.get_xrefs_from` - Cross-references",
            "- `ghidra.search_strings` / `ghidra.search_bytes` - Search binary content",
            "- `ghidra.get_imports` / `ghidra.get_exports` - Import/export tables",
            "",
            "### Code Annotation",
            "- `ghidra.rename_function` - Rename functions",
            "- `ghidra.add_comment` - Add comments (EOL, PRE, POST, PLATE)",
            "- `ghidra.set_label` / `ghidra.get_labels` - Manage labels",
            "- `ghidra.create_bookmark` / `ghidra.get_bookmarks` - Analysis bookmarks",
            "",
            "### Function Management",
            "- `ghidra.create_function` / `ghidra.delete_function` - Define/remove functions",
            "- `ghidra.edit_function_signature` - Change return type, calling convention, name",
            "- `ghidra.set_function_variable_type` - Retype local variables",
            "",
            "### Type System",
            "- `ghidra.get_data_type` / `ghidra.set_data_type` - Data types at addresses",
            "- `ghidra.define_structure` / `ghidra.get_structures` - Struct definitions",
            "- `ghidra.apply_structure_at` - Apply struct at memory address",
            "",
            "### Navigation & Program Info",
            "- `ghidra.get_memory_map` / `ghidra.get_segments` - Memory layout",
            "- `ghidra.get_call_graph` - Function call tree to configurable depth",
            "- `ghidra.get_program_info` - Language, compiler, endianness, image base",
            "",
            "### Modification & State",
            "- `ghidra.write_bytes` - Patch bytes in program",
            "- `ghidra.undo` / `ghidra.redo` - Undo/redo changes",
            "",
            "### Escape Hatch",
            "- `ghidra.execute_script` - Run arbitrary Jython in Ghidra's JVM. Use this when no structured tool covers your need. You have access to all Ghidra APIs including currentProgram, getMemory(), getFunctionManager(), etc.",
            "",
            "## x64dbg Tools",
            "",
            "### Execution Control",
            "- `x64dbg.load` / `x64dbg.attach` / `x64dbg.detach` - Process management",
            "- `x64dbg.continue_execution` / `x64dbg.pause` - Run/pause",
            "- `x64dbg.step_into` / `x64dbg.step_over` / `x64dbg.step_out` - Stepping",
            "- `x64dbg.run_to` - Run to specific address",
            "- `x64dbg.execute_til_return` - Execute until function returns",
            "- `x64dbg.skip_instruction` - Skip current instruction",
            "- `x64dbg.set_ip` - Set instruction pointer directly",
            "",
            "### Breakpoints & Watchpoints",
            "- `x64dbg.set_breakpoint` / `x64dbg.remove_breakpoint` - Software/hardware BPs",
            "- `x64dbg.enable_breakpoint` / `x64dbg.disable_breakpoint` - Toggle BPs",
            "- `x64dbg.set_breakpoint_on_api` - BP on imported function (e.g. kernel32.CreateFileW)",
            "- `x64dbg.get_breakpoints` - List all BPs including GUI-set ones",
            "- `x64dbg.set_watchpoint` / `x64dbg.remove_watchpoint` / `x64dbg.get_watchpoints`",
            "",
            "### Inspection",
            "- `x64dbg.get_registers` - All register values",
            "- `x64dbg.disassemble` - Disassemble at address",
            "- `x64dbg.get_stack_trace` - Stack frames",
            "- `x64dbg.get_memory_regions` - Full process memory map",
            "- `x64dbg.get_threads` - Thread enumeration",
            "- `x64dbg.get_modules` - Loaded modules",
            "- `x64dbg.get_process_info` - Complete process info",
            "- `x64dbg.get_module_sections` - PE sections of loaded module",
            "- `x64dbg.get_module_exports` - Exports of loaded module",
            "",
            "### Memory Operations",
            "- `x64dbg.read_memory` / `x64dbg.write_memory` - Read/write process memory",
            "- `x64dbg.scan_memory` / `x64dbg.find_pattern` - Pattern search with wildcards",
            "- `x64dbg.allocate_memory` / `x64dbg.free_memory` - Allocate/free with protection",
            "- `x64dbg.dump_memory_to_file` - Dump region to disk",
            "- `x64dbg.assemble_at` - Assemble instruction at address",
            "",
            "### Annotation",
            "- `x64dbg.set_label` / `x64dbg.get_labels` - Debug labels",
            "- `x64dbg.set_comment` / `x64dbg.get_comments` - Debug comments",
            "",
            "### Tracing & Exceptions",
            "- `x64dbg.trace_start` / `x64dbg.trace_stop` - Conditional trace recording",
            "- `x64dbg.set_exception_config` - Configure exception handling (break/ignore/log)",
            "",
            "### Escape Hatch",
            "- `x64dbg.run_command` - Execute any x64dbg command directly",
            "",
            "## Cutter/Rizin Tools",
            "",
            "### Core Analysis",
            "- `cutter.load_binary` - Load a binary file into Rizin for analysis",
            "- `cutter.analyze` - Run analysis (quick, normal, deep) on loaded binary",
            "- `cutter.get_functions` - List all analyzed functions, optional regex filter",
            "- `cutter.get_function` - Get detailed function info at a specific address",
            "- `cutter.get_function_address` - Look up function address by name",
            "",
            "### Code Inspection",
            "- `cutter.decompile` - Decompile function at address to pseudocode",
            "- `cutter.disassemble` - Disassemble N instructions at an address",
            "- `cutter.get_xrefs_to` / `cutter.get_xrefs_from` - Cross-references",
            "- `cutter.seek` - Seek to a specific address in the binary",
            "",
            "### Search",
            "- `cutter.search_strings` - Search strings by regex pattern",
            "- `cutter.search_bytes` - Search for hex byte pattern (e.g. '48 8B 05')",
            "- `cutter.search_bytes_wildcard` - Search with wildcards (e.g. '48 8B ?? ??')",
            "",
            "### Data Tables",
            "- `cutter.get_imports` - Get imported functions",
            "- `cutter.get_exports` - Get exported functions",
            "- `cutter.get_sections` - Get binary sections",
            "",
            "### Annotation & Patching",
            "- `cutter.rename_function` - Rename a function at address",
            "- `cutter.add_comment` - Add comment at address (EOL, function, unique)",
            "- `cutter.write_bytes` - Write hex bytes at an address",
            "- `cutter.assemble_at` - Assemble instruction and write at address",
            "",
            "### Escape Hatch",
            "- `cutter.execute_command` - Execute any raw Rizin command directly",
            "",
            "## Sandbox Usage for Testing Patches",
            "",
            "When testing patched binaries:",
            "1. Use `sandbox.create` to spin up an isolated environment",
            "2. Use `sandbox.copy_to` to copy the patched binary",
            "3. Use `sandbox.run_binary` to execute with monitoring",
            "4. Analyze the ExecutionReport for:",
            "   - exit_code: Did it crash or succeed?",
            "   - file_changes: What files were created/modified?",
            "   - registry_changes: License-related registry modifications?",
            "   - network_activity: License server communications?",
            "   - process_activity: Spawned processes?",
            "5. Use `sandbox.snapshot_create` (QEMU) to save state before risky operations",
            "6. Use `sandbox.snapshot_restore` to revert if needed",
            "7. Use `sandbox.destroy` when done",
            "",
            "Always test patches in sandbox before considering them successful.",
            "",
            "## Cracking Workflow",
            "",
            "### Analysis Phase:",
            "1. `binary.load_file` - Load target binary",
            "2. `ghidra.load_binary` + `ghidra.analyze` - Static analysis",
            "3. `ghidra.search_strings` - Find license-related strings",
            "4. `ghidra.get_functions` - List functions",
            "5. `ghidra.decompile` - Decompile suspicious functions",
            "6. `ghidra.get_call_graph` - Trace call chains from license checks",
            "7. `ghidra.get_program_info` - Understand binary format and architecture",
            "",
            "### Dynamic Analysis Phase:",
            "1. `sandbox.create` - Create isolated environment",
            "2. `frida.spawn` or `x64dbg.load` - Attach to process",
            "3. `frida.hook_function` - Hook license checks",
            "4. `x64dbg.set_breakpoint_on_api` - Break on license-related API calls",
            "5. `x64dbg.trace_start` - Trace execution through validation logic",
            "6. `x64dbg.find_pattern` - Search for known protection signatures",
            "",
            "### Patching Phase:",
            "1. `ghidra.write_bytes` or `binary.write_bytes` - Apply patches",
            "2. `binary.save` - Save patched binary",
            "3. `sandbox.copy_to` + `sandbox.run_binary` - Test patch",
            "4. Verify licensing bypassed via ExecutionReport",
            "",
            "### Iteration:",
            "- If patch fails, analyze sandbox output",
            "- Adjust patches and re-test",
            "- Use `ghidra.undo` to revert failed patches",
            "- Use QEMU snapshots for complex multi-step patches",
            "",
            "### Advanced Techniques:",
            "- Use `ghidra.execute_script` for complex analysis not covered by structured tools",
            "- Use `x64dbg.run_command` for x64dbg operations not available as structured tools",
            "- Use `ghidra.define_structure` to model license data structures",
            "- Use `x64dbg.get_module_exports` to find license validation DLL exports",
            "- Use `x64dbg.skip_instruction` to test what happens when checks are skipped",
            "",
            "When analyzing software:",
            "1. First understand the protection mechanism through static analysis",
            "2. Use dynamic analysis to observe runtime behavior",
            "3. Identify key validation functions and decision points",
            "4. Propose bypass strategies (patching, hooking, keygen)",
            "5. Implement the bypass with appropriate tools",
            "6. Test in sandbox to verify the bypass works",
            "",
            "Always explain your reasoning and findings clearly.",
            "Use tools iteratively to build understanding before making changes.",
        ]

        if self._current_session.binaries:
            active_binary = self._current_session.binaries[self._current_session.active_binary_index]
            prompt_parts.extend([
                "",
                f"Current binary: {active_binary.name}",
                f"Path: {active_binary.path}",
                f"Type: {active_binary.file_type}",
                f"Architecture: {active_binary.architecture}",
                f"Entry point: 0x{active_binary.entry_point:X}",
            ])

        if self._current_session.patches:
            prompt_parts.extend([
                "",
                "Applied patches:",
            ])
            for patch in self._current_session.patches:
                status = "applied" if patch.applied else "pending"
                prompt_parts.append(f"- 0x{patch.address:X}: {patch.description} ({status})")

        return "\n".join(prompt_parts)

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token count for text.

        Args:
            text: Text to estimate tokens for.

        Returns:
            int: Estimated token count.
        """
        return len(text) // 4

    async def _get_model_context_window(self, provider: LLMProvider) -> int:
        """Retrieve the context window for the current model.

        Queries the provider's model list and finds the matching model ID.
        Falls back to 128000 if the model is not found.

        Args:
            provider: The LLM provider to query.

        Returns:
            int: Context window size in tokens.
        """
        if self._current_session is None:
            return 128000
        try:
            models = await provider.list_models()
            for model_info in models:
                if model_info.id == self._current_session.model:
                    return model_info.context_window
        except (OSError, RuntimeError, ValueError) as exc:
            _logger.debug("context_window_lookup_failed", error=str(exc))
        return 128000

    @staticmethod
    def trim_messages_to_context_window(
        messages: list[Message],
        context_window: int,
    ) -> list[Message]:
        """Remove oldest non-system messages until within context budget.

        Keeps 85% of the context window as the token budget to leave
        headroom for the response.

        Args:
            messages: List of messages to trim.
            context_window: Maximum context window in tokens.

        Returns:
            list[Message]: Trimmed list of messages.
        """
        budget = int(context_window * 0.85)
        total = sum(Orchestrator._estimate_tokens(m.content) for m in messages)
        while total > budget and len(messages) > 1:
            oldest_idx = next(
                (i for i, m in enumerate(messages) if m.role != "system"),
                -1,
            )
            if oldest_idx < 0:
                break
            removed = messages.pop(oldest_idx)
            removed_tokens = Orchestrator._estimate_tokens(removed.content)
            total -= removed_tokens
            _logger.debug(
                "message_trimmed_for_context",
                role=removed.role,
                tokens_freed=removed_tokens,
                remaining_tokens=total,
                budget=budget,
            )
        return messages

    async def _call_llm(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
        *,
        is_final_response: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Call the LLM and handle response.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            is_final_response: Whether a final response is expected.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        # Estimate input tokens
        input_tokens = sum(self._estimate_tokens(m.content) for m in messages)
        self._stats.total_tokens_used += input_tokens

        tools_available = bool(tools)
        use_streaming = self._should_use_streaming(
            tools_available=tools_available,
            is_final_response=is_final_response,
        )
        structlog.contextvars.bind_contextvars(llm_streaming=use_streaming)
        _logger.debug(
            "llm_call_started",
            model=self._current_session.model,
            input_tokens=input_tokens,
            streaming=use_streaming,
            tool_count=len(tools),
        )
        enable_cache = self._config.cache is not None and self._config.cache.enabled

        result: tuple[Message, list[ToolCall] | None]
        if use_streaming:
            result = await self._stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
                tool_choice=self._config.tool_choice,
                thinking=self._config.thinking,
                enable_cache=enable_cache,
            )
        else:
            result = await self._non_stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
                tool_choice=self._config.tool_choice,
                thinking=self._config.thinking,
                enable_cache=enable_cache,
            )

        response, tool_calls_result = result
        output_tokens = self._estimate_tokens(response.content)
        self._stats.total_tokens_used += output_tokens
        _logger.debug(
            "llm_call_completed",
            response_length=len(response.content),
            output_tokens=output_tokens,
            has_tool_calls=tool_calls_result is not None,
        )
        structlog.contextvars.unbind_contextvars("llm_streaming")

        return result

    def _should_use_streaming(
        self,
        *,
        tools_available: bool,
        is_final_response: bool,
    ) -> bool:
        """Decide whether to use streaming mode.

        Args:
            tools_available: Whether tools are available for this request.
            is_final_response: Whether a final response is expected.

        Returns:
            bool: True if streaming should be used.
        """
        if not self._config.stream_responses:
            return False
        if self._on_stream_chunk is None:
            return False

        mode = self._config.stream_mode
        if mode == "never":
            return False
        return True if mode == "always" else not tools_available or is_final_response

    async def _stream_response(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Stream a response from the LLM.

        After the stream completes, any tool calls accumulated by the
        provider during streaming are retrieved via
        ``provider.get_pending_tool_calls()``.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
            CancelledError: If the operation is cancelled.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        content_parts: list[str] = []

        async for chunk in provider.chat_stream(
            messages=messages,
            model=self._current_session.model,
            tools=tools,
            temperature=self._config.temperature,
            max_tokens=self._config.max_tokens,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
        ):
            if self._cancel_event.is_set():
                raise asyncio.CancelledError

            content_parts.append(chunk)
            if self._on_stream_chunk:
                self._on_stream_chunk(chunk)

        content = "".join(content_parts)

        pending_calls = provider.get_pending_tool_calls()
        tool_calls: list[ToolCall] | None = pending_calls or None

        _logger.debug(
            "llm_stream_completed",
            chunk_count=len(content_parts),
            content_length=len(content),
            tool_calls_count=len(pending_calls),
        )
        return Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls,
            timestamp=datetime.now(tz=UTC),
        ), tool_calls

    async def _non_stream_response(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Request a non-streaming response from the LLM.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            tool_choice: How the model should select tools.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        response, tool_calls = await provider.chat(
            messages=messages,
            model=self._current_session.model,
            tools=tools,
            temperature=self._config.temperature,
            max_tokens=self._config.max_tokens,
            tool_choice=tool_choice,
            thinking=thinking,
            enable_cache=enable_cache,
        )

        _logger.debug(
            "llm_response_parsed",
            content_length=len(response.content),
            tool_call_count=len(tool_calls) if tool_calls else 0,
        )

        return response, tool_calls

    async def _execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
    ) -> list[ToolResult]:
        """Execute a list of tool calls.

        Args:
            tool_calls: Tool calls to execute.

        Returns:
            list[ToolResult]: List of tool results.

        Raises:
            CancelledError: If the operation is cancelled.
        """
        results: list[ToolResult] = []

        for call in tool_calls:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError

            if self._on_tool_call:
                self._on_tool_call(call)

            if await self._should_confirm(call):
                confirmed = await self._request_confirmation(call)
                if not confirmed:
                    result = ToolResult(
                        call_id=call.id,
                        success=False,
                        result=None,
                        error="User declined confirmation",
                        duration_ms=0,
                    )
                    results.append(result)
                    continue

            result = await self._execute_single_tool_call(call)
            results.append(result)

            if self._on_tool_result:
                self._on_tool_result(result)

        return results

    async def _execute_single_tool_call(self, call: ToolCall) -> ToolResult:
        """Execute a single tool call.

        Args:
            call: The tool call to execute.

        Returns:
            ToolResult: Result of the tool execution.
        """
        start_time = time.time()
        self._stats.total_tool_calls += 1

        structlog.contextvars.bind_contextvars(
            tool_call_id=call.id,
            tool_name=call.tool_name,
            tool_function=call.function_name,
        )

        try:
            result = await self._tools.execute_tool_call(
                tool_name=call.tool_name,
                function_name=call.function_name,
                arguments=call.arguments,
            )

            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.successful_tool_calls += 1

            _logger.info(
                "tool_call_success",
                tool=call.tool_name,
                function=call.function_name,
                duration_ms=round(elapsed_ms, 2),
            )

            if self._script_manager is not None:
                self._script_manager.record_execution(
                    script_name=call.function_name,
                    tool_name=call.tool_name,
                    result=result,
                )

            return ToolResult(
                call_id=call.id,
                success=True,
                result=result,
                error=None,
                duration_ms=elapsed_ms,
            )

        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.failed_tool_calls += 1

            _logger.warning(
                "tool_call_failed",
                tool=call.tool_name,
                function=call.function_name,
                error=str(e),
            )

            return ToolResult(
                call_id=call.id,
                success=False,
                result=None,
                error=str(e),
                duration_ms=elapsed_ms,
            )
        finally:
            structlog.contextvars.unbind_contextvars("tool_call_id", "tool_name", "tool_function")

    @staticmethod
    def _validate_tool_schemas(
        tools: list[ToolDefinition],
        provider: LLMProvider,
    ) -> None:
        """Validate tool definitions against the provider's schema format.

        Logs warnings for any validation errors found. Uses
        ``validate_and_convert`` and ``get_all_schemas_for_provider``
        from the schemas module for provider-specific validation.

        Args:
            tools: Tool definitions to validate.
            provider: The LLM provider to validate against.
        """
        provider_name = provider.name
        for tool in tools:
            _schemas, errors = validate_and_convert(tool, provider_name)
            for err in errors:
                _logger.warning(
                    "tool_schema_validation_error",
                    tool=tool.tool_name.value,
                    error=str(err),
                    provider=provider_name.value,
                )
            for func in tool.functions:
                param_schema = build_schema_parameters(
                    func.parameters,
                    uppercase_types=(provider_name == ProviderName.GOOGLE),
                )
                _logger.debug(
                    "tool_function_params_built",
                    function=func.name,
                    param_count=len(func.parameters),
                    schema_keys=list(param_schema.keys()),
                )
        all_schemas = get_all_schemas_for_provider(tools, provider_name)
        _logger.debug(
            "tool_schemas_prepared",
            provider=provider_name.value,
            schema_count=len(all_schemas),
        )

    async def _should_confirm(self, call: ToolCall) -> bool:
        """Check if tool call requires user confirmation.

        Args:
            call: The tool call to check.

        Returns:
            bool: True if confirmation needed.
        """
        if self._config.confirmation_level == ConfirmationLevel.NONE:
            _logger.debug(
                "confirmation_skipped",
                function=call.function_name,
                reason="level_none",
            )
            return False
        if self._config.confirmation_level == ConfirmationLevel.ALL:
            _logger.debug(
                "confirmation_required",
                function=call.function_name,
                reason="level_all",
            )
            return True
        is_destructive = self._is_destructive_operation(call)
        _logger.debug(
            "confirmation_check",
            function=call.function_name,
            level=self._config.confirmation_level.value,
            is_destructive=is_destructive,
        )
        return is_destructive

    def _is_destructive_operation(self, call: ToolCall) -> bool:
        """Check if a tool call is destructive.

        Destructive operations include:
        - Writing to memory or files
        - Patching binaries
        - Executing code in target
        - Any modification operations

        Args:
            call: The tool call to check.

        Returns:
            bool: True if operation is destructive.
        """
        function_lower = call.function_name.lower()
        return any(pattern in function_lower for pattern in self.DESTRUCTIVE_PATTERNS)

    async def _request_confirmation(self, call: ToolCall) -> bool:
        """Request user confirmation for a tool call.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            bool: True if user confirmed, False otherwise.
        """
        self._state = "waiting_confirmation"

        if self._async_confirmation_callback:
            future = self._async_confirmation_callback(call)
            self._pending_confirmation = PendingConfirmation(call=call, future=future)

            try:
                return await future
            finally:
                self._pending_confirmation = None
                self._state = "processing"

        if self._confirmation_callback:
            result = await asyncio.to_thread(self._confirmation_callback, call)
            self._state = "processing"
            return result

        _logger.warning("confirmation_auto_declined", reason="no_callback")
        self._state = "processing"
        return False

    def confirm_pending(self, *, confirmed: bool) -> None:
        """Confirm or decline a pending operation.

        Args:
            confirmed: True to confirm, False to decline.
        """
        if self._pending_confirmation is not None and not self._pending_confirmation.future.done():
            self._pending_confirmation.future.set_result(confirmed)

    async def cancel(self) -> None:
        """Cancel current operation."""
        _logger.info("operation_cancelling", state=self._state)
        self._cancel_event.set()

        provider = self._providers.get(self._current_session.provider) if self._current_session else None
        if provider:
            provider_name = self._current_session.provider.value if self._current_session else "unknown"
            try:
                await provider.cancel_request()
                _logger.debug("cancel_provider_request_sent", provider=provider_name)
            except (OSError, RuntimeError) as exc:
                _logger.warning("cancel_provider_request_failed", provider=provider_name, error=str(exc))

        if self._pending_confirmation and not self._pending_confirmation.future.done():
            call_id = self._pending_confirmation.call.id
            try:
                declined = False
                self._pending_confirmation.future.set_result(declined)
                _logger.debug("cancel_pending_confirmation_declined", call_id=call_id)
            except (asyncio.InvalidStateError, RuntimeError) as exc:
                _logger.warning("cancel_pending_confirmation_failed", call_id=call_id, error=str(exc))

    async def add_binary(self, path: Path, *, run_bridge_analysis: bool = True) -> BinaryInfo:
        """Add a binary to the current session.

        Args:
            path: Path to the binary.
            run_bridge_analysis: Whether to run bridge analysis automatically.

        Returns:
            BinaryInfo: Binary information.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        binary_info = await self._load_binary(path)
        self._current_session.binaries.append(binary_info)
        self._current_session.active_binary_index = len(self._current_session.binaries) - 1

        if run_bridge_analysis:
            analysis = await self._run_bridge_analysis(binary_info)
            if analysis:
                self._current_session.add_bridge_analysis(path.name, analysis)
                if self._on_bridge_analysis:
                    self._on_bridge_analysis(analysis)

        await self._sessions.update(self._current_session)
        return binary_info

    async def _run_bridge_analysis(self, binary_info: BinaryInfo) -> BridgeAnalysisSummary | None:
        """Run bridge analysis aggregation on a binary.

        Args:
            binary_info: Loaded binary metadata.

        Returns:
            BridgeAnalysisSummary | None: Aggregated results or None on failure.
        """
        log_analysis_operation("bridge_analysis", binary_info.name)
        try:
            aggregator = AnalysisAggregator(self._tools)
            analysis = await aggregator.aggregate(binary_info.name, binary_info)
        except (OSError, RuntimeError, ValueError, ToolError) as e:
            _logger.warning("bridge_analysis_failed", binary=binary_info.name, error=str(e))
            return None
        else:
            _logger.info("bridge_analysis_completed", binary=binary_info.name)
            return analysis

    async def reanalyze_bridge_analysis(self, binary_name: str | None = None) -> BridgeAnalysisSummary | None:
        """Re-run bridge analysis on the active or specified binary.

        Args:
            binary_name: Optional binary name; uses active binary if not specified.

        Returns:
            BridgeAnalysisSummary | None: Refreshed results or None on failure.
        """
        if self._current_session is None:
            return None

        _logger.info("bridge_reanalysis_requested", binary_name=binary_name)
        if binary_name:
            for binary in self._current_session.binaries:
                if binary.name == binary_name:
                    return await self._run_bridge_analysis(binary)
        elif self._current_session.active_binary:
            analysis = await self._run_bridge_analysis(self._current_session.active_binary)
            if analysis:
                self._current_session.add_bridge_analysis(self._current_session.active_binary.name, analysis)
                if self._on_bridge_analysis:
                    self._on_bridge_analysis(analysis)
            return analysis

        return None

    def set_bridge_analysis_callback(self, callback: Callable[[BridgeAnalysisSummary], None] | None) -> None:
        """Set callback for bridge analysis completion.

        Args:
            callback: Function to call with analysis results.
        """
        self._on_bridge_analysis = callback

    async def set_active_binary(self, index: int) -> None:
        """Set the active binary by index.

        Args:
            index: Index of binary to activate.

        Raises:
            RuntimeError: If no active session.
            IndexError: If index out of range.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        if index < 0 or index >= len(self._current_session.binaries):
            error_message = f"Binary index out of range: {index}"
            raise IndexError(error_message)

        _logger.info("active_binary_changed", index=index)
        self._current_session.active_binary_index = index
        await self._sessions.update(self._current_session)

    async def add_patch(self, patch: PatchInfo) -> None:
        """Add a patch to the current session.

        Args:
            patch: Patch information.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        _logger.info("patch_added", address=hex(patch.address), description=patch.description)
        self._current_session.patches.append(patch)
        await self._sessions.update(self._current_session)

    def set_message_callback(self, callback: Callable[[Message], None]) -> None:
        """Set callback for new messages.

        Args:
            callback: Function to call with each new message.
        """
        self._on_message = callback

    def set_tool_call_callback(self, callback: Callable[[ToolCall], None]) -> None:
        """Set callback for tool calls.

        Args:
            callback: Function to call when tool is called.
        """
        self._on_tool_call = callback

    def set_tool_result_callback(self, callback: Callable[[ToolResult], None]) -> None:
        """Set callback for tool results.

        Args:
            callback: Function to call when tool returns result.
        """
        self._on_tool_result = callback

    def set_stream_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback for streaming response chunks.

        Args:
            callback: Function to call with each text chunk.
        """
        self._on_stream_chunk = callback

    def set_confirmation_callback(
        self,
        callback: Callable[[ToolCall], bool],
    ) -> None:
        """Set synchronous callback for confirmation requests.

        Args:
            callback: Function to call for confirmation, returns True to proceed.
        """
        self._confirmation_callback = callback

    def set_async_confirmation_callback(
        self,
        callback: Callable[[ToolCall], asyncio.Future[bool]],
    ) -> None:
        """Set async callback for confirmation requests.

        Args:
            callback: Function returning a Future that resolves to True/False.
        """
        self._async_confirmation_callback = callback

    async def get_tool_status(self) -> list[dict[str, Any]]:
        """Get status of all tools.

        Returns:
            list[dict[str, Any]]: List of tool status dictionaries.
        """
        _logger.debug("tool_status_queried")
        statuses = await self._tools.get_all_status()
        return [
            {
                "name": status.name.value,
                "available": status.available,
                "connected": status.connected,
                "version": status.version,
                "path": str(status.path) if status.path else None,
                "error": status.error,
            }
            for status in statuses
        ]

    def get_available_tool_names(self) -> list[str]:
        """Get names of all available tools.

        Returns:
            list[str]: List of available tool name strings.
        """
        return [t.value for t in self._tools.get_available_tools()]

    def get_current_bridge_analysis(self, binary_name: str) -> BridgeAnalysisSummary | None:
        """Get cached bridge analysis for a binary.

        Args:
            binary_name: Name of the binary.

        Returns:
            BridgeAnalysisSummary | None: Cached results if available, None otherwise.
        """
        if self._current_session is None:
            return None
        return self._current_session.get_bridge_analysis(binary_name)

    def get_typed_bridge(self, tool_name: str) -> object | None:
        """Get a typed bridge instance by tool name.

        Uses the ToolRegistry's typed getters for safe bridge access.

        Args:
            tool_name: Name of the tool bridge to retrieve.

        Returns:
            object | None: Typed bridge instance or None if not available.
        """
        getter_map: dict[str, str] = {
            "process": "get_process_bridge",
            "frida": "get_frida_bridge",
            "ghidra": "get_ghidra_bridge",
            "cutter": "get_cutter_bridge",
            "x64dbg": "get_x64dbg_bridge",
            "sandbox": "get_sandbox_bridge",
        }
        getter_name = getter_map.get(tool_name.lower())
        if getter_name is None:
            return None
        try:
            bridge: object | None = getattr(self._tools, getter_name)()
        except (ToolError, OSError, RuntimeError, AttributeError) as exc:
            _logger.debug("bridge_getter_failed", tool_name=tool_name, getter=getter_name, error=str(exc))
            return None
        else:
            return bridge

    async def initialize_tool(self, tool_name: str | ToolName) -> bool:
        """Initialize a specific tool.

        Args:
            tool_name: Name of the tool to initialize.

        Returns:
            bool: True if initialization succeeded.
        """
        _logger.info("tool_initialization_requested", tool_name=str(tool_name))
        if isinstance(tool_name, str):
            tool_name = ToolName(tool_name.lower())

        return await self._tools.initialize_tool(tool_name)

    async def save_session(self) -> None:
        """Save the current session.

        Delegates to the session manager to persist the current session state.
        """
        _logger.debug("session_save_requested")
        await self._sessions.save()

    def set_confirmation_level(self, level: ConfirmationLevel) -> None:
        """Set the confirmation level for tool calls.

        Args:
            level: The desired confirmation level.
        """
        self._config.confirmation_level = level

    async def get_system_status(self) -> dict[str, Any]:
        """Get comprehensive system status report.

        Returns:
            dict[str, Any]: Dictionary containing session, metrics, and tool status.
        """
        _logger.debug("system_status_queried")
        return {
            "state": self._state,
            "session_id": self.current_session.id if self.current_session else None,
            "metrics": self.stats.to_dict(),
            "tools": await self.get_tool_status(),
        }

    def configure_hooks(
        self,
        on_bridge_analysis: Callable[[BridgeAnalysisSummary], None] | None = None,
        on_confirmation: Callable[[ToolCall], bool] | None = None,
    ) -> None:
        """Configure event hooks.

        Args:
            on_bridge_analysis: Callback for bridge analysis completion.
            on_confirmation: Callback for confirmation requests.
        """
        if on_bridge_analysis:
            self.set_bridge_analysis_callback(on_bridge_analysis)
        if on_confirmation:
            self.set_confirmation_callback(on_confirmation)

    async def refresh_session_state(self) -> None:
        """Refresh the session state including bridge analysis."""
        _logger.debug("session_state_refreshing")
        await self.reanalyze_bridge_analysis()

    async def register_manual_patch(
        self,
        address: int,
        original_bytes: bytes,
        new_bytes: bytes,
        description: str,
    ) -> None:
        """Register a manually applied patch.

        Args:
            address: Patch address.
            original_bytes: Original bytes.
            new_bytes: New bytes.
            description: Description.
        """
        _logger.info("manual_patch_registered", address=hex(address), description=description)
        patch = PatchInfo(
            address=address,
            original_bytes=original_bytes,
            new_bytes=new_bytes,
            description=description,
            applied=True,
        )
        await self.add_patch(patch)

    def resolve_confirmation(self, *, approved: bool) -> None:
        """Resolve any pending confirmation request.

        Args:
            approved: Whether to approve the request.
        """
        self.confirm_pending(confirmed=approved)

    async def activate_binary_by_name(self, name: str) -> None:
        """Activate a binary by name.

        Args:
            name: Name of binary to activate.

        Raises:
            ValueError: If binary not found.
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        _logger.info("binary_activation_by_name", binary_name=name)
        for i, binary in enumerate(self._current_session.binaries):
            if binary.name == name:
                await self.set_active_binary(i)
                return

        error_message = f"Binary not found: {name}"
        raise ValueError(error_message)

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources."""
        if self._shutdown_called:
            _logger.debug("orchestrator_shutdown_already_called", state=self._state)
            return
        self._shutdown_called = True
        _logger.info("orchestrator_shutdown_started", state=self._state)

        try:
            await self.cancel()
        except (OSError, RuntimeError, asyncio.InvalidStateError) as exc:
            _logger.warning("shutdown_cancel_failed", state=self._state, error=str(exc))

        try:
            await self._tools.shutdown()
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning("shutdown_tools_cleanup_failed", state=self._state, error=str(exc))

        if self._current_session:
            try:
                await self._sessions.update(self._current_session)
            except (OSError, RuntimeError, ValueError) as exc:
                _logger.warning(
                    "shutdown_session_save_failed",
                    session_id=self._current_session.id,
                    state=self._state,
                    error=str(exc),
                )

        for provider_name in self._providers.list_registered():
            provider = self._providers.get(provider_name)
            if provider is None:
                continue
            unload = getattr(provider, "unload_model", None)
            if callable(unload):
                try:
                    unload_coro: Coroutine[object, object, None] = cast(
                        "Coroutine[object, object, None]",
                        unload(),
                    )
                    await unload_coro
                    _logger.debug("shutdown_provider_model_unloaded", provider=provider_name.value)
                except (OSError, RuntimeError, ValueError) as exc:
                    _logger.warning("shutdown_provider_unload_failed", provider=provider_name.value, error=str(exc))

        session_cleanup = getattr(self._sessions, "cleanup", None)
        if callable(session_cleanup):
            try:
                cleanup_coro: Coroutine[object, object, int] = cast(
                    "Coroutine[object, object, int]",
                    session_cleanup(),
                )
                deleted: int = await cleanup_coro
                _logger.info("shutdown_session_cleanup_completed", deleted=deleted)
            except (OSError, RuntimeError, ValueError) as exc:
                _logger.warning("shutdown_session_cleanup_failed", error=str(exc))

        self._current_session = None
        self._state = "idle"
        structlog.contextvars.clear_contextvars()
        _logger.info("orchestrator_shutdown_completed", state=self._state)


_ARCH_KEYWORDS: dict[str, str] = {
    "AMD64": "x86_64",
    "x86_64": "x86_64",
    "X86_64": "x86_64",
    "I386": "x86",
    "i386": "x86",
    "ARM64": "aarch64",
    "AARCH64": "aarch64",
    "ARM": "arm",
}


def _resolve_arch(raw: str) -> str:
    """Map a lief architecture string to a canonical name.

    Args:
        raw: String representation of the architecture enum.

    Returns:
        str: Canonical architecture name.
    """
    for keyword, canonical in _ARCH_KEYWORDS.items():
        if keyword in raw:
            return canonical
    return raw or "unknown"


def _extract_sections(binary: object) -> list[SectionInfo]:
    """Extract section info from a parsed lief binary.

    Args:
        binary: A lief.Binary (PE, ELF, or Mach-O).

    Returns:
        list[SectionInfo]: Extracted section metadata.
    """
    import lief

    from intellicrack.core.types import SectionInfo as _SectionInfo

    result: list[_SectionInfo] = []
    for sec in getattr(binary, "sections", []):
        entropy: float = float(sec.entropy) if hasattr(sec, "entropy") else 0.0
        characteristics = 0
        if isinstance(binary, lief.PE.Binary) and isinstance(sec, lief.PE.Section):
            characteristics = int(sec.characteristics)
        result.append(
            _SectionInfo(
                name=str(sec.name),
                virtual_address=int(sec.virtual_address),
                virtual_size=int(sec.size),
                raw_size=len(sec.content) if hasattr(sec, "content") else int(sec.size),
                characteristics=characteristics,
                entropy=entropy,
            ),
        )
    return result


def _extract_imports(binary: object) -> list[ImportInfo]:
    """Extract import info from a parsed lief binary.

    Args:
        binary: A lief.Binary (PE, ELF, or Mach-O).

    Returns:
        list[ImportInfo]: Extracted import metadata.
    """
    import lief

    from intellicrack.core.types import ImportInfo as _ImportInfo

    result: list[_ImportInfo] = []
    if isinstance(binary, lief.PE.Binary):
        for imp in binary.imports:
            dll_name = str(imp.name)
            for entry in imp.entries:
                entry_name = str(entry.name) if entry.name else ""
                result.append(
                    _ImportInfo(
                        dll=dll_name,
                        function=entry_name or f"ord_{entry.data}",
                        ordinal=int(entry.data) if not entry_name else None,
                        address=int(entry.iat_value),
                    ),
                )
    elif isinstance(binary, lief.ELF.Binary):
        for rel in binary.pltgot_relocations:
            sym_name = str(getattr(rel.symbol, "name", "")) if getattr(rel, "has_symbol", True) else ""
            if sym_name:
                result.append(
                    _ImportInfo(dll="", function=sym_name, ordinal=None, address=int(rel.address)),
                )
    return result


def _extract_exports(binary: object) -> list[ExportInfo]:
    """Extract export info from a parsed lief binary.

    Args:
        binary: A lief.Binary (PE, ELF, or Mach-O).

    Returns:
        list[ExportInfo]: Extracted export metadata.
    """
    import lief

    from intellicrack.core.types import ExportInfo as _ExportInfo

    result: list[_ExportInfo] = []
    if isinstance(binary, lief.PE.Binary) and binary.has_exports:
        for exp in binary.get_export().entries:
            exp_name = str(exp.name) if exp.name else ""
            result.append(
                _ExportInfo(
                    name=exp_name or f"ord_{exp.ordinal}",
                    ordinal=int(exp.ordinal),
                    address=int(exp.address),
                ),
            )
    elif isinstance(binary, lief.ELF.Binary):
        result.extend(_ExportInfo(name=str(sym.name), ordinal=0, address=int(sym.value)) for sym in binary.exported_symbols)
    return result


def _classify_binary(binary: object) -> tuple[str, str, bool, int]:
    """Determine file type, architecture, bitness, and entry point.

    Args:
        binary: A parsed lief binary object.

    Returns:
        tuple[str, str, bool, int]: (file_type, architecture, is_64bit, entry_point).
    """
    import lief

    if isinstance(binary, lief.PE.Binary):
        machine_str = str(getattr(binary.header, "machine", ""))
        opt = binary.optional_header
        return ("pe", _resolve_arch(machine_str), "AMD64" in machine_str, int(opt.addressof_entrypoint) + int(opt.imagebase))

    if isinstance(binary, lief.ELF.Binary):
        hdr = binary.header
        arch_str = str(getattr(hdr, "machine_type", ""))
        class_str = str(getattr(hdr, "identity_class", ""))
        return ("elf", _resolve_arch(arch_str), "64" in class_str, int(binary.entrypoint))

    if isinstance(binary, lief.MachO.Binary):
        cpu_str = str(getattr(binary.header, "cpu_type", ""))
        return ("macho", _resolve_arch(cpu_str), "64" in cpu_str, int(binary.entrypoint))

    return ("unknown", "unknown", False, 0)


def _parse_binary_with_lief(path: Path) -> BinaryInfo:
    """Parse a binary using lief and return a populated BinaryInfo.

    Handles PE, ELF, and Mach-O formats. Falls back to minimal
    metadata when lief cannot parse the file.

    Args:
        path: Filesystem path to the binary.

    Returns:
        BinaryInfo: Populated binary metadata.

    Raises:
        FileNotFoundError: If path does not exist.
    """
    import lief

    from intellicrack.core.types import BinaryInfo as _BinaryInfo

    resolved = pathlib.Path(path)
    if not resolved.exists():
        error_message = f"Binary not found: {path}"
        raise FileNotFoundError(error_message)

    raw = resolved.read_bytes()
    hashes = (
        hashlib.md5(raw, usedforsecurity=False).hexdigest(),
        hashlib.sha256(raw).hexdigest(),
    )
    lief_parse = cast(
        "Callable[[str], lief.PE.Binary | lief.OAT.Binary | lief.ELF.Binary | lief.MachO.Binary | lief.COFF.Binary | None]",
        vars(lief)["parse"],
    )
    binary = lief_parse(str(resolved))

    if binary is None:
        return _BinaryInfo(
            path=resolved,
            name=resolved.name,
            size=len(raw),
            md5=hashes[0],
            sha256=hashes[1],
            file_type="unknown",
            architecture="unknown",
            is_64bit=False,
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
        )

    meta = _classify_binary(binary)

    return _BinaryInfo(
        path=resolved,
        name=resolved.name,
        size=len(raw),
        md5=hashes[0],
        sha256=hashes[1],
        file_type=meta[0],
        architecture=meta[1],
        is_64bit=meta[2],
        entry_point=meta[3],
        sections=_extract_sections(binary),
        imports=_extract_imports(binary),
        exports=_extract_exports(binary),
    )
