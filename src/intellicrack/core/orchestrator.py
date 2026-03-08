# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Main AI agent orchestrator for Intellicrack.

This module provides the central orchestration layer that coordinates
between the user, LLM providers, and tool bridges to execute
reverse engineering workflows.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from ..bridges.schemas import (
    build_schema_parameters,
    get_all_schemas_for_provider,
    validate_and_convert,
)
from .analysis_aggregator import AnalysisAggregator
from .logging import get_logger, log_analysis_operation
from .types import (
    ConfirmationLevel,
    Message,
    PatchInfo,
    ProviderName,
    ToolName,
    ToolResult,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import Any

    from ..providers.base import LLMProvider
    from ..providers.registry import ProviderRegistry
    from .script_gen import ScriptManager
    from .session import Session, SessionManager
    from .tools import ToolRegistry
    from .types import BinaryInfo, BridgeAnalysisSummary, ToolCall, ToolDefinition


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
    """

    confirmation_level: ConfirmationLevel = ConfirmationLevel.DESTRUCTIVE
    max_iterations: int = 20
    timeout_seconds: int = 120
    temperature: float = 0.7
    max_tokens: int = 4096
    stream_responses: bool = True
    stream_mode: Literal["auto", "always", "never"] = "auto"


@dataclass
class PendingConfirmation:
    """A tool call waiting for user confirmation.

    Attributes:
        call: The tool call awaiting confirmation.
        future: Future to resolve when confirmation received.
    """

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
            Dictionary containing all statistics.
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

    Attributes:
        _providers: Registry of LLM providers.
        _tools: Registry of tool bridges.
        _sessions: Session state manager.
        _config: Orchestrator configuration.
        _current_session: Currently active session.
        _state: Current orchestrator state.
        _stats: Operation statistics.
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
        """Initialize the orchestrator.

        Args:
            provider_registry: Registry of LLM providers.
            tool_registry: Registry of tool bridges.
            session_manager: Session state manager.
            config: Optional configuration override.
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
            Current state.
        """
        return self._state

    @property
    def current_session(self) -> Session | None:
        """Get current session.

        Returns:
            Current session or None.
        """
        return self._current_session

    @property
    def stats(self) -> OrchestratorStats:
        """Get orchestrator statistics.

        Returns:
            Statistics instance.
        """
        return self._stats

    @property
    def provider_registry(self) -> ProviderRegistry:
        """Get the provider registry.

        Returns:
            The provider registry instance.
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
            New session instance.

        Raises:
            ValueError: If provider not available.
        """
        if isinstance(provider, str):
            provider = ProviderName(provider.lower())

        provider_instance = self._providers.get(provider)
        if provider_instance is None or not provider_instance.is_connected:
            _logger.warning(
                "provider_not_found",
                extra={"provider": provider.value, "connected": getattr(provider_instance, "is_connected", None)},
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

        _logger.info(
            "session_started",
            extra={"session_id": session.id, "provider": provider.value, "model": model},
        )

        return session

    async def load_session(self, session_id: str) -> Session:
        """Load an existing session.

        Args:
            session_id: ID of session to load.

        Returns:
            Loaded session.

        Raises:
            ValueError: If session not found.
        """
        session = await self._sessions.get(session_id)
        if session is None:
            error_message = f"Session not found: {session_id}"
            raise ValueError(error_message)

        self._current_session = session
        self._state = "idle"

        _logger.info("session_loaded", extra={"session_id": session_id})
        return session

    async def _load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file for analysis.

        Args:
            path: Path to the binary.

        Returns:
            Binary information.
        """
        _logger.debug("binary_load_started", extra={"path": str(path)})
        binary_bridge = self._tools.get_binary_bridge()
        info = await binary_bridge.load_file(path)
        _logger.debug(
            "binary_load_completed",
            extra={"path": str(path), "file_type": info.file_type, "architecture": info.architecture},
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

        user_message = Message(
            role="user",
            content=text,
            timestamp=datetime.now(),
        )
        self._current_session.messages.append(user_message)

        if self._on_message:
            self._on_message(user_message)

        try:
            await self._run_agent_loop()
        except asyncio.CancelledError:
            _logger.info("request_cancelled", extra={"state": self._state})
            self._state = "cancelled"
        finally:
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
        iteration = 0

        while iteration < self._config.max_iterations:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

            iteration += 1
            _logger.debug("agent_loop_iteration", extra={"iteration": iteration})

            messages = self._build_messages()

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
                _logger.debug("agent_loop_complete", extra={"reason": "no_tool_calls"})
                break

            tool_results = await self._execute_tool_calls(tool_calls)

            tool_message = Message(
                role="tool",
                content="",
                tool_results=tool_results,
                timestamp=datetime.now(),
            )
            self._current_session.messages.append(tool_message)

            if all(not r.success for r in tool_results):
                _logger.warning("agent_loop_stopping", extra={"reason": "all_tool_calls_failed"})
                break

        if iteration >= self._config.max_iterations:
            _logger.warning("agent_loop_max_iterations", extra={"max_iterations": self._config.max_iterations})

    def _is_final_response_expected(self) -> bool:
        """Determine whether a final response is expected.

        Returns:
            True if the next response is likely final.
        """
        if self._current_session is None:
            return False
        if not self._current_session.messages:
            return False
        return self._current_session.messages[-1].role == "tool"

    def _build_messages(self) -> list[Message]:
        """Build message list for LLM including system prompt.

        Returns:
            List of messages with system prompt prepended.
        """
        if self._current_session is None:
            return []

        system_prompt = self._generate_system_prompt()
        system_message = Message(
            role="system",
            content=system_prompt,
            timestamp=datetime.now(),
        )

        messages = [system_message, *self._current_session.messages]
        _logger.debug(
            "messages_built",
            extra={"message_count": len(messages), "system_prompt_length": len(system_prompt)},
        )
        return messages

    def _generate_system_prompt(self) -> str:
        """Generate system prompt for the LLM.

        Returns:
            System prompt describing available tools and capabilities.
        """
        if self._current_session is None:
            return ""

        prompt_parts = [
            "You are Intellicrack, an advanced AI-powered reverse engineering assistant "
            "specialized in analyzing software licensing protections.",
            "",
            "Your capabilities include:",
            "- Static analysis via Ghidra (decompilation, disassembly, cross-references)",
            "- Dynamic analysis via Frida (hooking, memory manipulation, tracing)",
            "- Debugging via x64dbg (breakpoints, stepping, register manipulation)",
            "- Binary analysis via radare2 (disassembly, analysis, patching)",
            "- Process control (memory reading/writing, DLL injection)",
            "- Binary operations (loading, parsing, patching)",
            "- Sandbox execution (isolated testing, behavior monitoring, snapshot/restore)",
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
            "",
            "### Dynamic Analysis Phase:",
            "1. `sandbox.create` - Create isolated environment",
            "2. `frida.spawn` or `x64dbg.load` - Attach to process",
            "3. `frida.hook_function` - Hook license checks",
            "4. Trace execution to find validation logic",
            "",
            "### Patching Phase:",
            "1. `binary.write_bytes` - Apply patches",
            "2. `binary.save` - Save patched binary",
            "3. `sandbox.copy_to` + `sandbox.run_binary` - Test patch",
            "4. Verify licensing bypassed via ExecutionReport",
            "",
            "### Iteration:",
            "- If patch fails, analyze sandbox output",
            "- Adjust patches and re-test",
            "- Use QEMU snapshots for complex multi-step patches",
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
            Estimated token count.
        """
        return len(text) // 4

    async def _call_llm(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
        is_final_response: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Call the LLM and handle response.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            is_final_response: Whether a final response is expected.

        Returns:
            Tuple of (response message, tool calls if any).

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
        _logger.debug(
            "llm_call_started",
            extra={
                "model": self._current_session.model,
                "input_tokens": input_tokens,
                "streaming": use_streaming,
                "tool_count": len(tools),
            },
        )
        result: tuple[Message, list[ToolCall] | None]
        if use_streaming:
            result = await self._stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
            )
        else:
            result = await self._non_stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
            )

        response, tool_calls_result = result
        output_tokens = self._estimate_tokens(response.content)
        self._stats.total_tokens_used += output_tokens
        _logger.debug(
            "llm_call_completed",
            extra={
                "response_length": len(response.content),
                "output_tokens": output_tokens,
                "has_tool_calls": tool_calls_result is not None,
            },
        )

        return result

    def _should_use_streaming(
        self,
        tools_available: bool,
        is_final_response: bool,
    ) -> bool:
        """Decide whether to use streaming mode.

        Args:
            tools_available: Whether tools are available for this request.
            is_final_response: Whether a final response is expected.

        Returns:
            True if streaming should be used.
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
    ) -> tuple[Message, list[ToolCall] | None]:
        """Stream a response from the LLM.

        After the stream completes, any tool calls accumulated by the
        provider during streaming are retrieved via
        ``provider.get_pending_tool_calls()``.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.

        Returns:
            Tuple of (response message, tool calls if any).

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
        ):
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

            content_parts.append(chunk)
            if self._on_stream_chunk:
                self._on_stream_chunk(chunk)

        content = "".join(content_parts)

        pending_calls = provider.get_pending_tool_calls()
        tool_calls: list[ToolCall] | None = pending_calls or None

        _logger.debug(
            "llm_stream_completed",
            extra={
                "chunk_count": len(content_parts),
                "content_length": len(content),
                "tool_calls_count": len(pending_calls),
            },
        )
        return Message(
            role="assistant",
            content=content,
            tool_calls=tool_calls,
            timestamp=datetime.now(),
        ), tool_calls

    async def _non_stream_response(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
    ) -> tuple[Message, list[ToolCall] | None]:
        """Request a non-streaming response from the LLM.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.

        Returns:
            Tuple of (response message, tool calls if any).

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
        )

        _logger.debug(
            "llm_response_parsed",
            extra={
                "content_length": len(response.content),
                "tool_call_count": len(tool_calls) if tool_calls else 0,
            },
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
            List of tool results.

        Raises:
            CancelledError: If the operation is cancelled.
        """
        results: list[ToolResult] = []

        for call in tool_calls:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

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
            Result of the tool execution.
        """
        start_time = time.time()
        self._stats.total_tool_calls += 1

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
                extra={
                    "tool": call.tool_name,
                    "function": call.function_name,
                    "duration_ms": round(elapsed_ms, 2),
                },
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

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.failed_tool_calls += 1

            _logger.exception(
                "tool_call_failed",
                extra={"tool": call.tool_name, "function": call.function_name},
            )

            return ToolResult(
                call_id=call.id,
                success=False,
                result=None,
                error=str(e),
                duration_ms=elapsed_ms,
            )

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
                    extra={
                        "tool": tool.tool_name.value,
                        "error": str(err),
                        "provider": provider_name.value,
                    },
                )
            for func in tool.functions:
                param_schema = build_schema_parameters(
                    func.parameters,
                    uppercase_types=(provider_name == ProviderName.GOOGLE),
                )
                _logger.debug(
                    "tool_function_params_built",
                    extra={
                        "function": func.name,
                        "param_count": len(func.parameters),
                        "schema_keys": list(param_schema.keys()),
                    },
                )
        all_schemas = get_all_schemas_for_provider(tools, provider_name)
        _logger.debug(
            "tool_schemas_prepared",
            extra={
                "provider": provider_name.value,
                "schema_count": len(all_schemas),
            },
        )

    async def _should_confirm(self, call: ToolCall) -> bool:
        """Check if tool call requires user confirmation.

        Args:
            call: The tool call to check.

        Returns:
            True if confirmation needed.
        """
        if self._config.confirmation_level == ConfirmationLevel.NONE:
            _logger.debug(
                "confirmation_skipped",
                extra={"function": call.function_name, "reason": "level_none"},
            )
            return False
        if self._config.confirmation_level == ConfirmationLevel.ALL:
            _logger.debug(
                "confirmation_required",
                extra={"function": call.function_name, "reason": "level_all"},
            )
            return True
        is_destructive = self._is_destructive_operation(call)
        _logger.debug(
            "confirmation_check",
            extra={
                "function": call.function_name,
                "level": self._config.confirmation_level.value,
                "is_destructive": is_destructive,
            },
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
            True if operation is destructive.
        """
        function_lower = call.function_name.lower()
        return any(pattern in function_lower for pattern in self.DESTRUCTIVE_PATTERNS)

    async def _request_confirmation(self, call: ToolCall) -> bool:
        """Request user confirmation for a tool call.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            True if user confirmed, False otherwise.
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

        _logger.warning("confirmation_auto_declined", extra={"reason": "no_callback"})
        self._state = "processing"
        return False

    def confirm_pending(self, confirmed: bool) -> None:
        """Confirm or decline a pending operation.

        Args:
            confirmed: True to confirm, False to decline.
        """
        if self._pending_confirmation is not None and not self._pending_confirmation.future.done():
            self._pending_confirmation.future.set_result(confirmed)

    async def cancel(self) -> None:
        """Cancel current operation."""
        _logger.info("operation_cancelling", extra={"state": self._state})
        self._cancel_event.set()

        provider = self._providers.get(self._current_session.provider) if self._current_session else None
        if provider:
            provider_name = self._current_session.provider.value if self._current_session else "unknown"
            try:
                await provider.cancel_request()
                _logger.debug("cancel_provider_request_sent", extra={"provider": provider_name})
            except Exception:
                _logger.exception("cancel_provider_request_failed", extra={"provider": provider_name})

        if self._pending_confirmation and not self._pending_confirmation.future.done():
            call_id = self._pending_confirmation.call.id
            try:
                self._pending_confirmation.future.set_result(False)
                _logger.debug("cancel_pending_confirmation_declined", extra={"call_id": call_id})
            except Exception:
                _logger.exception("cancel_pending_confirmation_failed", extra={"call_id": call_id})

    async def add_binary(self, path: Path, run_bridge_analysis: bool = True) -> BinaryInfo:
        """Add a binary to the current session.

        Args:
            path: Path to the binary.
            run_bridge_analysis: Whether to run bridge analysis automatically.

        Returns:
            Binary information.

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
            BridgeAnalysisSummary results or None on failure.
        """
        log_analysis_operation("bridge_analysis", binary_info.name)
        try:
            aggregator = AnalysisAggregator(self._tools)
            analysis = await aggregator.aggregate(binary_info.name, binary_info)
        except Exception as e:
            _logger.warning("bridge_analysis_failed", extra={"binary": binary_info.name, "error": str(e)})
            return None
        else:
            _logger.info("bridge_analysis_completed", extra={"binary": binary_info.name})
            return analysis

    async def reanalyze_bridge_analysis(self, binary_name: str | None = None) -> BridgeAnalysisSummary | None:
        """Re-run bridge analysis on the active or specified binary.

        Args:
            binary_name: Optional binary name; uses active binary if not specified.

        Returns:
            BridgeAnalysisSummary results or None.
        """
        if self._current_session is None:
            return None

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
            List of tool status dictionaries.
        """
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
            List of available tool name strings.
        """
        return [t.value for t in self._tools.get_available_tools()]

    def get_current_bridge_analysis(self, binary_name: str) -> BridgeAnalysisSummary | None:
        """Get cached bridge analysis for a binary.

        Args:
            binary_name: Name of the binary.

        Returns:
            BridgeAnalysisSummary if available, None otherwise.
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
            Typed bridge instance or None if not available.
        """
        getter_map: dict[str, str] = {
            "process": "get_process_bridge",
            "frida": "get_frida_bridge",
            "ghidra": "get_ghidra_bridge",
            "radare2": "get_radare2_bridge",
            "x64dbg": "get_x64dbg_bridge",
            "sandbox": "get_sandbox_bridge",
        }
        getter_name = getter_map.get(tool_name.lower())
        if getter_name is None:
            return None
        try:
            bridge: object | None = getattr(self._tools, getter_name)()
        except Exception:
            _logger.debug("bridge_getter_failed", exc_info=True, extra={"tool_name": tool_name, "getter": getter_name})
            return None
        else:
            return bridge

    async def initialize_tool(self, tool_name: str | ToolName) -> bool:
        """Initialize a specific tool.

        Args:
            tool_name: Name of the tool to initialize.

        Returns:
            True if initialization succeeded.
        """
        if isinstance(tool_name, str):
            tool_name = ToolName(tool_name.lower())

        return await self._tools.initialize_tool(tool_name)

    async def save_session(self) -> None:
        """Save the current session.

        Delegates to the session manager to persist the current session state.
        """
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
            Dictionary containing session, metrics, and tool status.
        """
        return {
            "state": self.state,
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
        patch = PatchInfo(
            address=address,
            original_bytes=original_bytes,
            new_bytes=new_bytes,
            description=description,
            applied=True,
        )
        await self.add_patch(patch)

    def resolve_confirmation(self, approved: bool) -> None:
        """Resolve any pending confirmation request.

        Args:
            approved: Whether to approve the request.
        """
        self.confirm_pending(approved)

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

        for i, binary in enumerate(self._current_session.binaries):
            if binary.name == name:
                await self.set_active_binary(i)
                return

        error_message = f"Binary not found: {name}"
        raise ValueError(error_message)

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources."""
        if self._shutdown_called:
            _logger.debug("orchestrator_shutdown_already_called", extra={"state": self._state})
            return
        self._shutdown_called = True
        _logger.info("orchestrator_shutdown_started", extra={"state": self._state})

        try:
            await self.cancel()
        except Exception:
            _logger.exception("shutdown_cancel_failed", extra={"state": self._state})

        try:
            await self._tools.shutdown()
        except Exception:
            _logger.exception("shutdown_tools_cleanup_failed", extra={"state": self._state})

        if self._current_session:
            try:
                await self._sessions.update(self._current_session)
            except Exception:
                _logger.exception(
                    "shutdown_session_save_failed",
                    extra={"session_id": self._current_session.id, "state": self._state},
                )

        self._current_session = None
        self._state = "idle"
        _logger.info("orchestrator_shutdown_completed", extra={"state": self._state})
