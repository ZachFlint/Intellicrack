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
import tiktoken

from intellicrack.bridges.schemas import (
    build_schema_parameters,
    validate_tool_for_provider,
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
    ToolChoiceMode,
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
        ToolFunction,
    )
    from intellicrack.providers.base import LLMProvider
    from intellicrack.providers.registry import ProviderRegistry


_logger = get_logger(__name__)


_TIKTOKEN_O200K: str = "o200k_base"
_TIKTOKEN_CL100K: str = "cl100k_base"

_PROVIDER_TOKEN_ENCODINGS: dict[ProviderName, str] = {
    ProviderName.OPENAI: _TIKTOKEN_O200K,
    ProviderName.ANTHROPIC: _TIKTOKEN_CL100K,
    ProviderName.GOOGLE: _TIKTOKEN_CL100K,
    ProviderName.OLLAMA: _TIKTOKEN_CL100K,
    ProviderName.OPENROUTER: _TIKTOKEN_CL100K,
    ProviderName.HUGGINGFACE: _TIKTOKEN_CL100K,
    ProviderName.GROK: _TIKTOKEN_CL100K,
    ProviderName.LOCAL_TRANSFORMERS: _TIKTOKEN_CL100K,
}

_DEFAULT_TOKEN_ENCODING: str = _TIKTOKEN_CL100K

_token_encoder_cache: dict[str, tiktoken.Encoding] = {}


def _get_token_encoder(provider: ProviderName | None) -> tiktoken.Encoding:
    """Resolve the tiktoken encoder for a provider.

    Selects ``o200k_base`` for OpenAI (current default for GPT-4o family) and
    ``cl100k_base`` for every other provider as a conservative shared default.
    Encodings are cached per-name to avoid the cost of re-loading the BPE
    tables on every call.

    Args:
        provider: Active LLM provider, or ``None`` to use the default encoding.

    Returns:
        tiktoken.Encoding: Encoder instance suitable for token counting.
    """
    encoding_name = _DEFAULT_TOKEN_ENCODING if provider is None else _PROVIDER_TOKEN_ENCODINGS.get(provider, _DEFAULT_TOKEN_ENCODING)
    encoder = _token_encoder_cache.get(encoding_name)
    if encoder is None:
        encoder = tiktoken.get_encoding(encoding_name)
        _token_encoder_cache[encoding_name] = encoder
    return encoder


def _count_tokens(text: str, provider: ProviderName | None) -> int:
    """Count tokens in ``text`` using a provider-aware tiktoken encoder.

    Args:
        text: String to count tokens in. Empty input returns ``0``.
        provider: Active LLM provider used to select the encoder, or ``None``
            to fall back to the conservative default encoding.

    Returns:
        int: Token count for ``text``.
    """
    if not text:
        return 0
    encoder = _get_token_encoder(provider)
    return len(encoder.encode(text, disallowed_special=()))


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
        context_window_override: Optional explicit context window size (in tokens) used when
            the provider cannot report one for the active model. When ``None`` the provider
            is required to return a context window; otherwise trimming is skipped.
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
    context_window_override: int | None = None


@dataclass(eq=False)
class PendingConfirmation:
    """A tool call waiting for user confirmation.

    Hashing falls back to :func:`id`-based identity (``eq=False``) so
    instances can live inside the orchestrator's pending-confirmation set
    even though :class:`ToolCall` is not hashable. Identity semantics are
    correct here because each pending confirmation is a unique instance.

    Attributes:
        call: The tool call awaiting confirmation.
        future: Future that resolves to ``True`` when the user approves the
            call, ``False`` when they decline, and is cancelled (raising
            :class:`asyncio.CancelledError` to the awaiter) when the
            orchestrator shuts down or a cancellation is signalled while a
            confirmation is pending.
    """

    call: ToolCall
    future: asyncio.Future[bool]


DestructiveClassification = Literal["destructive", "read_only", "unknown"]
"""Classification of a tool call's effect on external state.

``destructive`` operations modify external state (memory, files, processes, sandboxes) and require confirmation when the orchestrator is
configured for ``ConfirmationLevel.DESTRUCTIVE``. ``read_only`` operations only inspect state and never need confirmation. ``unknown``
indicates the bridge is not recognised; the orchestrator treats unknown operations as destructive to fail safe.
"""

_FRIDA_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "spawn",
        "attach",
        "attach_by_name",
        "detach",
        "resume",
        "resume_child",
        "write_memory",
        "allocate_memory",
        "protect_memory",
        "hook_function",
        "remove_hook",
        "intercept_return",
        "replace_function",
        "revert_hook",
        "flush_interceptor",
        "call_function",
        "call_system_function",
        "execute_script",
        "execute_persistent_script",
        "unload_script",
        "unload_all_scripts",
        "eternalize_script",
        "post_message",
        "rpc_call",
        "patch_code",
        "allocate_string",
        "load_module",
        "set_exception_handler",
        "stalker_follow",
        "stalker_unfollow",
        "stalker_add_call_probe",
        "stalker_remove_call_probe",
        "enable_child_gating",
        "disable_child_gating",
        "enable_crash_reporting",
        "disable_crash_reporting",
        "connect_device",
        "create_cancellable",
        "cancel",
        "inject_library_file",
        "inject_library_blob",
        "objc_hook_method",
        "java_hook_method",
        "java_deoptimize",
        "create_cmodule",
        "kernel_write",
        "kernel_alloc",
        "kernel_protect",
        "socket_listen",
        "socket_connect",
        "file_write_target",
        "sqlite_open",
        "sqlite_exec",
        "write_code",
        "cloak_add_thread",
        "cloak_remove_thread",
        "cloak_add_range",
        "cloak_remove_range",
        "monitor_path",
        "stop_monitor",
    },
)
"""Frida bridge methods that mutate process / runtime state."""

_GHIDRA_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "load_binary",
        "analyze",
        "rename_function",
        "add_comment",
        "set_data_type",
        "start_headless",
        "execute_script",
        "execute_script_with_params",
        "set_label",
        "create_bookmark",
        "create_function",
        "delete_function",
        "edit_function_signature",
        "set_function_variable_type",
        "define_structure",
        "apply_structure_at",
        "write_bytes",
        "undo",
        "redo",
        "import_debug_info",
        "add_reference",
        "delete_reference",
        "create_namespace",
        "create_equate",
        "create_data_type",
        "create_data",
        "configure_analysis",
        "set_decompiler_options",
        "create_memory_block",
        "set_color",
        "set_program_metadata",
        "add_external_function",
        "create_overlay_space",
        "add_bookmark",
        "remove_bookmark",
        "add_label",
        "remove_label",
        "add_thunk",
        "remove_thunk",
        "add_external_reference",
        "remove_external_reference",
    },
)
"""Ghidra bridge methods that mutate program / project state."""

_X64DBG_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "load",
        "attach",
        "detach",
        "run",
        "pause",
        "stop",
        "step_into",
        "step_over",
        "step_out",
        "step_count",
        "set_breakpoint",
        "remove_breakpoint",
        "enable_breakpoint",
        "disable_breakpoint",
        "set_breakpoint_on_api",
        "configure_breakpoint",
        "set_dll_breakpoint",
        "set_logging_breakpoint",
        "set_register",
        "write_memory",
        "set_watchpoint",
        "remove_watchpoint",
        "allocate_memory",
        "free_memory",
        "assemble_at",
        "run_command",
        "run_to",
        "execute_til_return",
        "skip_instruction",
        "set_ip",
        "set_label",
        "set_comment",
        "dump_memory_to_file",
        "trace_start",
        "trace_stop",
        "trace_into",
        "trace_over",
        "set_exception_config",
        "spawn",
        "patch_instruction",
        "nop_range",
        "save_database",
        "load_database",
        "clear_database",
        "restore_patch",
        "export_patches",
        "suspend_thread",
        "resume_thread",
        "switch_thread",
        "set_thread_name",
        "add_watch",
        "remove_watch",
        "animate_start",
        "animate_stop",
        "yara_scan",
        "script_load",
        "script_run",
        "script_cmd",
        "script_abort",
        "plugin_load",
        "plugin_unload",
        "close_handle",
        "patch_anti_debug",
        "reconstruct_imports",
        "goto_address",
        "break_on_tls_callbacks",
        "adjust_privilege",
    },
)
"""X64dbg bridge methods that mutate debugger / target state."""

_SANDBOX_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "create",
        "destroy",
        "run_binary",
        "execute",
        "copy_to",
        "copy_from",
        "snapshot_create",
        "snapshot_restore",
        "snapshot_delete",
        "cont",
        "pcap_start",
        "pcap_stop",
        "stop_pcap",
        "screenshot",
        "anti_evasion",
        "memory_dump",
        "extract_dropped_files",
        "set_vnc_password",
    },
)
"""Sandbox bridge methods that create, mutate, or terminate sandbox instances."""

_PROCESS_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "open",
        "close",
        "terminate",
        "suspend",
        "resume",
        "write_memory",
        "allocate",
        "free",
        "protect",
        "inject_dll",
        "adjust_token_privilege",
        "set_thread_context",
        "pipe_connect",
        "pipe_read",
        "pipe_write",
        "pipe_close",
        "device_open",
        "device_ioctl",
        "device_close",
        "create_section",
        "map_section",
        "unmap_section",
    },
)
"""Process bridge methods that mutate target process state or kernel objects."""

_HEX_EDITOR_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "open_file",
        "close_file",
        "write_bytes",
        "insert_bytes",
        "delete_bytes",
        "undo",
        "redo",
        "register_template",
        "remove_template",
        "save",
        "save_as",
        "select_range",
        "goto_offset",
        "replace_bytes",
        "save_to_sandbox",
        "test_in_sandbox",
        "apply_transform",
        "apply_pipeline",
        "open_process_memory",
        "import_patches",
        "export_patches",
        "add_bookmark",
        "remove_bookmark",
        "add_highlight_rule",
        "remove_highlight_rule",
        "set_display_mode",
        "fill_block",
        "copy_block",
        "move_block",
        "swap_blocks",
        "apply_arithmetic_to_selection",
        "set_bit",
        "toggle_bit",
        "set_va_base",
        "remove_va_mapping",
        "auto_detect_va_mappings",
        "generate_structure_bookmarks",
        "export_annotated_html",
        "export_annotated_pdf",
        "snap_to_alignment",
        "set_alignment_grid",
        "repair_pe_checksum",
        "run_python_script",
        "set_chunk_size",
        "set_memory_budget",
        "set_color_mode",
        "import_patches_bps",
        "export_patches_bps",
        "import_patches_ups",
        "export_patches_ups",
    },
)
"""Hex editor bridge methods that mutate document / editor state."""

_CUTTER_DESTRUCTIVE: frozenset[str] = frozenset(
    {
        "load_binary",
        "analyze",
        "rename_function",
        "add_comment",
        "add_flag",
        "add_zignature",
        "save_project",
        "open_project",
        "execute_command",
        "set_function_signature",
        "patch_bytes",
    },
)
"""Cutter bridge methods that mutate analysis state or invoke r2 commands."""

BRIDGE_DESTRUCTIVE_METHODS: dict[ToolName, frozenset[str]] = {
    ToolName.FRIDA: _FRIDA_DESTRUCTIVE,
    ToolName.GHIDRA: _GHIDRA_DESTRUCTIVE,
    ToolName.X64DBG: _X64DBG_DESTRUCTIVE,
    ToolName.SANDBOX: _SANDBOX_DESTRUCTIVE,
    ToolName.PROCESS: _PROCESS_DESTRUCTIVE,
    ToolName.HEX_EDITOR: _HEX_EDITOR_DESTRUCTIVE,
    ToolName.CUTTER: _CUTTER_DESTRUCTIVE,
}
"""Per-bridge whitelist of method names that mutate external state.

Each entry maps a :class:`ToolName` to the exact method-name leaves (the part after the ``"<tool>."`` prefix) that the orchestrator must
classify as destructive. Method names not present in the relevant set are read-only. Bridges absent from this map default to ``unknown``
classification, which the orchestrator treats as destructive so that newly added bridges fail safe until their methods are catalogued here.
"""


def _split_tool_function_name(call: ToolCall) -> tuple[str, str]:
    """Resolve a tool call to a ``(tool_name, method_leaf)`` pair.

    The orchestrator receives function names in either the ``"tool.method"``
    namespaced form (the canonical schema produced by :class:`ToolDefinition`)
    or as a bare ``"method"`` leaf. This helper normalises both shapes so the
    classifier can look up exact method names against
    :data:`BRIDGE_DESTRUCTIVE_METHODS`.

    Args:
        call: The :class:`ToolCall` whose function name and tool name should be
            normalised.

    Returns:
        tuple[str, str]: A ``(tool_name, method_leaf)`` pair. ``tool_name`` is
        the value from :attr:`ToolCall.tool_name` if present; otherwise it is
        derived from a ``"tool.method"`` style ``function_name``.
        ``method_leaf`` is the trailing identifier with no ``"."`` separator.
    """
    fn = call.function_name
    if "." in fn:
        prefix, _, leaf = fn.partition(".")
        tool_name = call.tool_name or prefix
        return tool_name, leaf
    return call.tool_name, fn


def classify_tool_call(call: ToolCall) -> DestructiveClassification:
    """Classify a tool call as ``destructive``, ``read_only`` or ``unknown``.

    Performs an exact lookup against :data:`BRIDGE_DESTRUCTIVE_METHODS`. The
    bridge name is resolved from :attr:`ToolCall.tool_name`, falling back to
    the prefix of a ``"tool.method"`` style ``function_name`` when the field
    is empty. Method names are looked up by their leaf (the segment after the
    ``"."``).

    Args:
        call: The :class:`ToolCall` to classify.

    Returns:
        DestructiveClassification: ``"destructive"`` when the bridge is known
        and the method is in its destructive set; ``"read_only"`` when the
        bridge is known and the method is not in its destructive set;
        ``"unknown"`` when the bridge name cannot be resolved to a registered
        :class:`ToolName`.
    """
    tool_name, method_leaf = _split_tool_function_name(call)
    if not tool_name:
        return "unknown"
    try:
        tool_enum = ToolName(tool_name.lower())
    except ValueError:
        _logger.warning("tool_name_not_registered", tool_name=tool_name)
        return "unknown"
    destructive_set = BRIDGE_DESTRUCTIVE_METHODS.get(tool_enum)
    if destructive_set is None:
        return "unknown"
    return "destructive" if method_leaf in destructive_set else "read_only"


@dataclass
class OrchestratorStats:
    """Statistics for orchestrator operations.

    Attributes:
        total_requests: Total user requests processed.
        total_tool_calls: Total tool calls executed.
        successful_tool_calls: Successful tool call count.
        failed_tool_calls: Failed tool call count.
        total_tokens_used: Approximate tokens used (heuristic estimate).
        provider_prompt_tokens: Real prompt-token totals reported by
            providers via :meth:`LLMProviderBase.get_pending_usage`.
        provider_completion_tokens: Real completion-token totals
            reported by providers via
            :meth:`LLMProviderBase.get_pending_usage`.
        provider_total_tokens: Real combined-token totals reported by
            providers via :meth:`LLMProviderBase.get_pending_usage`.
        thinking_blocks_collected: Number of extended-thinking blocks
            captured via :meth:`LLMProviderBase.get_pending_thinking`.
        average_response_time_ms: Average response time.
    """

    total_requests: int = 0
    total_tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    total_tokens_used: int = 0
    provider_prompt_tokens: int = 0
    provider_completion_tokens: int = 0
    provider_total_tokens: int = 0
    thinking_blocks_collected: int = 0
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
            "provider_prompt_tokens": self.provider_prompt_tokens,
            "provider_completion_tokens": self.provider_completion_tokens,
            "provider_total_tokens": self.provider_total_tokens,
            "thinking_blocks_collected": self.thinking_blocks_collected,
            "average_response_time_ms": self.average_response_time_ms,
        }


class Orchestrator:
    """Main AI agent orchestrator.

    Manages the conversation loop between the user, LLM, and tools.
    Coordinates tool execution and handles confirmations.

    Attributes:
        DESTRUCTIVE_PATTERNS: Legacy substring tuple kept for callers that
            iterate the public attribute. The orchestrator itself classifies
            tool calls via :func:`classify_tool_call`, which performs exact
            method-name lookup against :data:`BRIDGE_DESTRUCTIVE_METHODS`
            instead of substring matching.
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
        self._pending_confirmations: set[PendingConfirmation] = set()
        self._cancel_event = asyncio.Event()
        self._shutdown_event = asyncio.Event()

        self._script_manager: ScriptManager | None = None
        self._shutdown_called: bool = False

        self._on_message: Callable[[Message], None] | None = None
        self._on_tool_call: Callable[[ToolCall], None] | None = None
        self._on_tool_result: Callable[[ToolResult], None] | None = None
        self._on_stream_chunk: Callable[[str], None] | None = None
        self._on_bridge_analysis: Callable[[BridgeAnalysisSummary], None] | None = None
        self._confirmation_callback: Callable[[ToolCall], bool] | None = None
        self._async_confirmation_callback: Callable[[ToolCall], asyncio.Future[bool]] | None = None

        _logger.debug(
            "orchestrator_initialized",
            confirmation_level=self._config.confirmation_level.value,
            max_iterations=self._config.max_iterations,
        )

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

    @property
    def pending_confirmation(self) -> PendingConfirmation | None:
        """Return the most-recently registered pending confirmation, if any.

        Returns:
            PendingConfirmation | None: The latest entry registered via
            :meth:`_request_confirmation`, or ``None`` when no confirmation
            is currently outstanding.
        """
        return self._pending_confirmation

    @property
    def pending_confirmations(self) -> frozenset[PendingConfirmation]:
        """Return a snapshot of every outstanding confirmation.

        Returns:
            frozenset[PendingConfirmation]: An immutable snapshot of the
            pending-confirmation set. Mutating the orchestrator after the
            call will not affect the returned snapshot.
        """
        return frozenset(self._pending_confirmations)

    @property
    def shutdown_called(self) -> bool:
        """Return whether :meth:`shutdown` has been invoked at least once.

        Returns:
            bool: ``True`` once :meth:`shutdown` has run; ``False`` before.
        """
        return self._shutdown_called

    @property
    def shutdown_complete(self) -> bool:
        """Return whether the orchestrator's shutdown event has fired.

        Returns:
            bool: ``True`` when :meth:`shutdown` has marked the internal
            shutdown event; otherwise ``False``.
        """
        return self._shutdown_event.is_set()

    @staticmethod
    def is_destructive_operation(call: ToolCall) -> bool:
        """Determine whether a tool call requires destructive-op confirmation.

        Uses the explicit per-bridge classifier
        :func:`classify_tool_call`, which does exact method-name lookup
        against :data:`BRIDGE_DESTRUCTIVE_METHODS`. ``destructive`` and
        ``unknown`` classifications both require confirmation - unknown
        bridges fail safe so newly added integrations cannot bypass
        confirmation by virtue of not being catalogued. ``read_only``
        operations skip confirmation.

        Args:
            call: The tool call to evaluate.

        Returns:
            bool: ``True`` when the call is classified as destructive or
            unknown; ``False`` only when the call is explicitly classified
            as read-only.
        """
        classification = classify_tool_call(call)
        if classification == "unknown":
            _logger.warning(
                "destructive_classification_unknown",
                tool=call.tool_name,
                function=call.function_name,
                fail_safe="treating_as_destructive",
            )
            return True
        return classification == "destructive"

    async def request_confirmation(self, call: ToolCall) -> bool:
        """Request user confirmation for a tool call via the public API.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            bool: The confirmation outcome (``True`` confirmed, ``False``
            declined, cancelled, or no callback registered).
        """
        return await self._request_confirmation(call)

    def set_script_manager(self, manager: ScriptManager) -> None:
        """Set the script manager for recording tool execution results.

        Args:
            manager: The ScriptManager instance.
        """
        self._script_manager = manager

    def tag_current_session(self, tag: str) -> bool:
        """Add a tag to the current session.

        CLI-friendly companion to the tag-chips widget in the session
        manager dialog. Delegates to :meth:`Session.add_tag`, which
        normalises whitespace and rejects empty tags.

        Args:
            tag: Non-empty tag string to add.

        Returns:
            bool: True if the tag was newly added, False if it was
            already present on the session.

        Raises:
            RuntimeError: If no session is currently active.
        """
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("tag_current_session_no_active_session", tag=tag)
            raise RuntimeError(error_message)
        return self._current_session.add_tag(tag)

    def untag_current_session(self, tag: str) -> bool:
        """Remove a tag from the current session.

        CLI-friendly companion to the tag-chips widget in the session
        manager dialog. Delegates to :meth:`Session.remove_tag`.

        Args:
            tag: Tag string to remove. Leading/trailing whitespace is
                stripped to match the normalisation performed by
                :meth:`Session.add_tag`.

        Returns:
            bool: True if the tag was removed, False if it was not
            present on the session.

        Raises:
            RuntimeError: If no session is currently active.
        """
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("untag_current_session_no_active_session", tag=tag)
            raise RuntimeError(error_message)
        return self._current_session.remove_tag(tag)

    async def start_session(
        self,
        provider: str | ProviderName,
        model: str,
        binary_path: Path | None = None,
        name: str | None = None,
        description: str | None = None,
    ) -> Session:
        """Start a new session.

        Args:
            provider: LLM provider to use.
            model: Model ID to use.
            binary_path: Optional binary to load.
            name: Optional human-readable session name recorded on the new ``Session``.
            description: Optional free-form description persisted as ``Session.notes``.

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
            name=name,
        )
        if description:
            session.notes = description
            await self._sessions.save()

        if binary_path is not None:
            binary_info = await self._load_binary(binary_path)
            session.binaries.append(binary_info)
            session.active_binary_index = 0

        self._current_session = session
        self._tools.set_session(session)
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
        """Load an existing session and make it the current session.

        Delegates to :meth:`SessionManager.load` so the manager's ``_current``
        pointer is updated and the auto-save background task is started for
        this session, ensuring later edits persist without requiring an
        explicit ``save_session`` call.

        Args:
            session_id: ID of session to load.

        Returns:
            Session: Loaded session.

        Raises:
            ValueError: If session not found.
        """
        _logger.info("load_session_started", session_id=session_id)
        session = await self._sessions.load(session_id)
        if session is None:
            error_message = f"Session not found: {session_id}"
            raise ValueError(error_message)

        self._current_session = session
        self._tools.set_session(session)
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

        1. Send pre-flight ``user`` message + history to the LLM with tool
           definitions; the user message is **not** persisted to the session
           until the loop completes successfully.
        2. If LLM returns tool calls, execute them.
        3. Send tool results back to LLM.
        4. Repeat until LLM returns final text response.
        5. On successful completion, append the user message and any assistant
           / tool messages emitted during the loop to the session and persist.
        6. On cancellation or unhandled exception the session is **not**
           modified, leaving the persisted state consistent with the last
           successful turn.

        Args:
            text: User's natural language input.

        Raises:
            RuntimeError: If no active session.
            asyncio.CancelledError: If the request is cancelled. The cancellation
                is re-raised after the in-memory turn rollback so callers can
                differentiate cancellation from completion.
        """
        _logger.info("process_user_input_started", text_length=len(text), state=self._state)
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("process_user_input_no_active_session")
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

        if self._on_message:
            self._on_message(user_message)

        loop_messages: list[Message] = []
        loop_succeeded = False
        try:
            loop_succeeded = await self._run_user_turn(user_message=user_message, turn_messages=loop_messages)
        except asyncio.CancelledError:
            _logger.info("request_cancelled", state=self._state)
            self._state = "cancelled"
            raise
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.record_response_time(elapsed_ms)

            if self._state != "cancelled":
                self._state = "idle"

            if loop_succeeded:
                await self._sessions.update(self._current_session)

    async def _run_user_turn(
        self,
        *,
        user_message: Message,
        turn_messages: list[Message],
    ) -> bool:
        """Append ``user_message`` and run a single agent loop turn.

        Rolls back the in-memory session messages produced by the turn when the
        agent loop raises so a subsequent retry does not re-send a partial
        conversation. ``self._current_session`` must be non-``None`` when this
        helper is invoked; callers verify that precondition before delegating.
        ``asyncio.CancelledError`` propagates unchanged so the caller can
        update state and re-raise. Any other exception raised by
        ``_run_agent_loop`` propagates after the in-memory rollback runs.

        Args:
            user_message: The user message to append before running the loop.
            turn_messages: Mutable list collecting assistant/tool messages
                produced during the turn.

        Returns:
            bool: True when the agent loop completed successfully.

        Raises:
            RuntimeError: If ``self._current_session`` is ``None`` when the
                helper is invoked.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)
        loop_succeeded = False
        self._current_session.messages.append(user_message)
        try:
            await self._run_agent_loop(turn_messages=turn_messages)
            loop_succeeded = True
        finally:
            if not loop_succeeded:
                self._rollback_turn_messages(user_message=user_message, turn_messages=turn_messages)
        return loop_succeeded

    def _rollback_turn_messages(
        self,
        *,
        user_message: Message,
        turn_messages: list[Message],
    ) -> None:
        """Remove a failed turn's messages from the session in-memory.

        Strips the trailing user / assistant / tool messages added during a
        single agent turn so a subsequent retry does not re-send a partial
        conversation. The session is *not* persisted here -- the caller skips
        the post-loop ``SessionManager.update`` so the on-disk state remains
        the last successful turn.

        Args:
            user_message: The user message appended at the start of the turn.
            turn_messages: Assistant / tool messages produced by the agent
                loop during the failing turn (may be empty).
        """
        if self._current_session is None:
            return
        session_messages = self._current_session.messages
        for message in reversed(turn_messages):
            if session_messages and session_messages[-1] is message:
                session_messages.pop()
        if session_messages and session_messages[-1] is user_message:
            session_messages.pop()
        _logger.info(
            "turn_messages_rolled_back",
            user_message_removed=True,
            assistant_or_tool_removed=len(turn_messages),
        )

    async def _run_agent_loop(self, *, turn_messages: list[Message]) -> None:
        """Run the main agent loop until completion or cancellation.

        ``_validate_tool_schemas`` and ``_require_model_context_window`` are
        called at the top of the loop and raise ``ToolError`` when a tool
        definition is invalid for the active provider or no context window is
        known; those errors propagate to the caller and abort the turn before
        any LLM request is sent.

        Args:
            turn_messages: Mutable list that the loop appends every assistant
                and tool message it produces in this turn to. The caller uses
                it to roll back the session in-memory if the loop fails before
                completing.

        Raises:
            RuntimeError: If provider is not available.
            asyncio.CancelledError: If the operation is cancelled.
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
        context_window = await self._require_model_context_window(provider)
        iteration = 0
        force_no_tools_next = False

        while iteration < self._config.max_iterations:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError

            iteration += 1
            _logger.debug("agent_loop_iteration", iteration=iteration)

            messages = self._build_messages()
            messages = self.trim_messages_to_context_window(
                messages,
                context_window,
                provider=provider.name,
            )

            iteration_tool_choice_override: ToolChoice | None = ToolChoice(mode=ToolChoiceMode.NONE) if force_no_tools_next else None

            response, tool_calls = await self._call_llm(
                provider=provider,
                messages=messages,
                tools=tool_definitions,
                is_final_response=self._is_final_response_expected() or force_no_tools_next,
                tool_choice_override=iteration_tool_choice_override,
            )

            if response.content:
                self._current_session.messages.append(response)
                turn_messages.append(response)
                if self._on_message:
                    self._on_message(response)

            if force_no_tools_next:
                _logger.debug("agent_loop_complete", reason="post_failure_summary_emitted")
                break

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
            turn_messages.append(tool_message)

            if all(not r.success for r in tool_results):
                _logger.warning("agent_loop_all_tool_calls_failed", next_turn="summary_with_no_tools")
                force_no_tools_next = True

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

    def build_system_prompt(self) -> str:
        """Render the current system prompt.

        Public seam over :meth:`_generate_system_prompt` for callers (UI,
        tests, embedded clients) that need to inspect what the orchestrator
        will send to the LLM without going through ``process_user_input``.

        Returns:
            str: System prompt for the active session, or an empty string
                when no session is active.
        """
        return self._generate_system_prompt()

    def _generate_system_prompt(self) -> str:
        """Generate system prompt for the LLM.

        Returns:
            str: System prompt describing available tools and capabilities. The
                tools section is generated from the live :class:`ToolRegistry`
                so the prompt always reflects the bridges that are actually
                bound at request time -- it cannot drift to advertise tools
                that no longer exist or to omit tools that have been added.
        """
        if self._current_session is None:
            return ""

        prompt_parts: list[str] = [
            (
                "You are Intellicrack, an advanced AI-powered binary analysis assistant. You bridge external "
                "reverse-engineering tools (debuggers, disassemblers, sandboxes, instrumentation frameworks) "
                "into a single workspace and act through their tool APIs."
            ),
            "",
            (
                "Operate the toolset described below. Every function name, parameter, and description "
                "is generated from the live tool registry, so the list always reflects what is actually "
                "available in this session. Do not assume any tool not listed below exists."
            ),
        ]

        prompt_parts.extend(self._render_tool_catalog())

        prompt_parts.extend([
            "",
            "Workflow guidance:",
            "1. Inspect with read-only tools before modifying state.",
            "2. Prefer structured tools over raw escape-hatch commands when both exist.",
            "3. Cite the tool calls you intend to make and explain why.",
            "4. After each tool call, summarise the relevant results before deciding the next step.",
            "5. Stop and ask the user when you need a confirmation, an artefact, or a decision.",
        ])

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

    def _render_tool_catalog(self) -> list[str]:
        """Render the tool catalog as a list of prompt lines.

        The renderer queries :meth:`ToolRegistry.get_tool_definitions` and
        formats every advertised tool / function so the LLM sees an up-to-date
        list. When no bridges are registered the catalog renders an explicit
        ``(no tools available)`` marker rather than silently producing an
        empty section.

        Returns:
            list[str]: Prompt lines describing every registered tool.
        """
        try:
            tool_definitions = self._tools.get_tool_definitions()
        except (RuntimeError, ToolError) as exc:
            _logger.warning("system_prompt_tool_definitions_failed", error=str(exc))
            return ["", "## Available tools", "", "(tool registry unavailable; no callable tools)"]

        if not tool_definitions:
            return ["", "## Available tools", "", "(no tools available)"]

        lines: list[str] = ["", "## Available tools"]
        for definition in tool_definitions:
            lines.append("")
            tool_name_value = definition.tool_name.value if hasattr(definition.tool_name, "value") else str(definition.tool_name)
            description = (definition.description or "").strip()
            heading_suffix = f" - {description}" if description else ""
            lines.append(f"### {tool_name_value}{heading_suffix}")
            if not definition.functions:
                lines.append("(no functions advertised)")
                continue
            lines.extend(self._render_tool_function(func) for func in definition.functions)
        return lines

    @staticmethod
    def _render_tool_function(func: ToolFunction) -> str:
        """Format a single tool function entry for the system prompt.

        Args:
            func: Tool function to render.

        Returns:
            str: One-line summary in the form ``- name(params) -> return: description``.
        """
        params = ", ".join(f"{p.name}: {p.type}" for p in func.parameters)
        description = (func.description or "").strip()
        suffix = f" - {description}" if description else ""
        return f"- `{func.name}({params}) -> {func.returns}`{suffix}"

    @staticmethod
    def _estimate_tokens(text: str, provider: ProviderName | None = None) -> int:
        """Inner provider-aware token-count helper.

        Used across internal orchestrator paths (context-window trimming,
        per-call accounting) so subclasses can override token estimation in a
        single place and have both the public entry point and all internal
        bookkeeping pick up the change.

        Args:
            text: Text to count tokens for.
            provider: Active LLM provider, or ``None`` to use the default
                conservative encoding.

        Returns:
            int: Token count for ``text``.
        """
        return _count_tokens(text, provider)

    @staticmethod
    def estimate_tokens(text: str, provider: ProviderName | None = None) -> int:
        """Count tokens in ``text`` using a provider-aware tiktoken encoder.

        Public entry point that delegates to :meth:`_estimate_tokens`.
        OpenAI requests use the ``o200k_base`` encoding (matching the GPT-4o
        family) and every other provider uses ``cl100k_base`` as a
        conservative shared default that overcounts vs. each provider's
        real tokenizer rather than undercounts. This avoids the runaway
        prompt-size failures that the original ``len // 4`` heuristic
        produced on token-dense payloads (code, hex dumps, table output).

        Args:
            text: Text to count tokens for.
            provider: Active LLM provider, or ``None`` to use the default
                conservative encoding.

        Returns:
            int: Token count for ``text``.
        """
        return Orchestrator._estimate_tokens(text, provider)

    async def _get_model_context_window(self, provider: LLMProvider) -> int | None:
        """Resolve the context window for the active model.

        Resolution order:

        1. If ``OrchestratorConfig.context_window_override`` is set, that value is used.
        2. Otherwise the provider's ``list_models()`` result is searched for the active
           model and its reported ``context_window`` is returned.
        3. If neither source yields a usable value the method logs a warning identifying
           the provider and model, and returns ``None`` so callers can decide how to
           handle the missing value (the agent loop refuses to run via
           :meth:`_require_model_context_window`; callers that legitimately want to
           skip trimming may inspect ``None`` themselves).

        Args:
            provider: The LLM provider to query.

        Returns:
            int | None: Context window size in tokens, or ``None`` when neither an override
                nor a provider value is available.
        """
        if self._config.context_window_override is not None:
            return self._config.context_window_override

        if self._current_session is None:
            return None

        provider_name = provider.name.value
        model_id = self._current_session.model
        try:
            models = await provider.list_models()
        except (OSError, RuntimeError, ValueError) as exc:
            _logger.warning(
                "context_window_lookup_failed",
                provider=provider_name,
                model=model_id,
                error=str(exc),
            )
            return None

        for model_info in models:
            if model_info.id == model_id:
                return model_info.context_window

        _logger.warning(
            "context_window_unknown_model",
            provider=provider_name,
            model=model_id,
        )
        return None

    async def _require_model_context_window(self, provider: LLMProvider) -> int:
        """Resolve a non-null context window or refuse to run the loop.

        Wraps :meth:`_get_model_context_window` so the agent loop fails fast
        with a precise, actionable error when neither
        ``OrchestratorConfig.context_window_override`` nor the provider's
        ``list_models()`` result yields a usable context window. Sending
        unbounded history at that point would either silently truncate at
        the provider boundary or trigger a low-quality 400-class error;
        instead we ask the operator to set the override.

        Args:
            provider: The LLM provider to query.

        Returns:
            int: The resolved context window in tokens.

        Raises:
            ToolError: If neither the override nor the provider reports a
                context window for the active model.
        """
        context_window = await self._get_model_context_window(provider)
        if context_window is not None:
            return context_window

        model_id = self._current_session.model if self._current_session is not None else "<no session>"
        provider_name = provider.name.value
        _logger.warning("context_window_unknown", provider=provider_name, model=model_id)
        error_message = (
            f"No context window known for provider '{provider_name}' model '{model_id}'. "
            "Configure OrchestratorConfig.context_window_override (or fix the provider's "
            "list_models() to advertise context_window) before sending requests; refusing "
            "to send unbounded history."
        )
        raise ToolError(error_message)

    @staticmethod
    def trim_messages_to_context_window(
        messages: list[Message],
        context_window: int | None,
        *,
        provider: ProviderName | None = None,
    ) -> list[Message]:
        """Remove oldest non-system messages until within context budget.

        Keeps 85% of the context window as the token budget to leave headroom
        for the response. Token counting uses :func:`_count_tokens` which
        selects a provider-specific tiktoken encoding when ``provider`` is
        supplied and falls back to ``cl100k_base`` otherwise.

        ``context_window=None`` is treated as a hard error rather than a
        silent passthrough so callers cannot accidentally send unbounded
        history to a provider that does not report a window. Use the
        per-provider helper :meth:`_trim_messages_for_provider` from the
        agent loop, which always passes a resolved value.

        Args:
            messages: List of messages to trim. Mutated in place.
            context_window: Maximum context window in tokens. ``None`` raises
                ``ToolError`` instead of skipping trimming.
            provider: Active provider used to select the tiktoken encoding
                for token counting.

        Returns:
            list[Message]: Trimmed list of messages.

        Raises:
            ToolError: If ``context_window`` is ``None``.
        """
        if context_window is None:
            _logger.warning("trim_messages_context_window_unknown")
            error_message = (
                "Cannot trim messages: context window is unknown. Configure "
                "OrchestratorConfig.context_window_override or pass a real "
                "context_window value; refusing to send unbounded history."
            )
            raise ToolError(error_message)
        budget = int(context_window * 0.85)
        total = sum(Orchestrator._estimate_tokens(m.content, provider) for m in messages)
        while total > budget and len(messages) > 1:
            oldest_idx = next(
                (i for i, m in enumerate(messages) if m.role != "system"),
                -1,
            )
            if oldest_idx < 0:
                break
            removed = messages.pop(oldest_idx)
            removed_tokens = Orchestrator._estimate_tokens(removed.content, provider)
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
        tool_choice_override: ToolChoice | None = None,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Call the LLM and handle response.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            is_final_response: Whether a final response is expected.
            tool_choice_override: Optional per-call override that replaces
                ``self._config.tool_choice`` for this single invocation. Used by the agent
                loop to force a tool-free summarizing turn after every tool call in the
                prior iteration failed.

        Returns:
            tuple[Message, list[ToolCall] | None]: Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("call_llm_no_active_session")
            raise RuntimeError(error_message)

        provider_name = provider.name
        input_tokens = sum(Orchestrator._estimate_tokens(m.content, provider_name) for m in messages)
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
        effective_tool_choice: ToolChoice | None = tool_choice_override if tool_choice_override is not None else self._config.tool_choice

        result: tuple[Message, list[ToolCall] | None]
        if use_streaming:
            result = await self._stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
                tool_choice=effective_tool_choice,
                thinking=self._config.thinking,
                enable_cache=enable_cache,
            )
        else:
            result = await self._non_stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
                tool_choice=effective_tool_choice,
                thinking=self._config.thinking,
                enable_cache=enable_cache,
            )

        response, tool_calls_result = result
        output_tokens = Orchestrator._estimate_tokens(response.content, provider_name)
        self._stats.total_tokens_used += output_tokens
        self._record_provider_usage(provider=provider, response=response)
        _logger.debug(
            "llm_call_completed",
            response_length=len(response.content),
            output_tokens=output_tokens,
            has_tool_calls=tool_calls_result is not None,
        )
        structlog.contextvars.unbind_contextvars("llm_streaming")

        return result

    def _record_provider_usage(
        self,
        *,
        provider: LLMProvider,
        response: Message,
    ) -> None:
        """Drain pending usage and thinking buffers from the provider.

        Each provider exposes :meth:`LLMProviderBase.get_pending_usage`
        and :meth:`LLMProviderBase.get_pending_thinking` after every
        chat / chat-stream call.  This helper folds those values into
        :class:`OrchestratorStats` and copies the most recent thinking
        text onto ``response.thinking_content`` so the assistant
        message preserves the model's reasoning summary for downstream
        callbacks and persistence.

        Args:
            provider: LLM provider that just produced the response.
            response: Assistant message returned by the provider.
                Mutated in place to attach ``thinking_content`` when
                the provider reported any.
        """
        usage = provider.get_pending_usage()
        if usage is not None:
            self._stats.provider_prompt_tokens += usage.prompt_tokens
            self._stats.provider_completion_tokens += usage.completion_tokens
            self._stats.provider_total_tokens += usage.total_tokens
            _logger.debug(
                "provider_usage_recorded",
                provider=provider.name.value,
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
            )
        if thinking_blocks := provider.get_pending_thinking():
            self._stats.thinking_blocks_collected += len(thinking_blocks)
            if response.thinking_content is None:
                response.thinking_content = "\n\n".join(thinking_blocks)
            _logger.debug(
                "provider_thinking_recorded",
                provider=provider.name.value,
                blocks=len(thinking_blocks),
                total_chars=sum(len(t) for t in thinking_blocks),
            )

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
            asyncio.CancelledError: If the operation is cancelled.
        """
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("stream_response_no_active_session")
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
            _logger.error("non_stream_response_no_active_session")
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
            asyncio.CancelledError: If the operation is cancelled.
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

    async def _execute_single_tool_call_success(
        self,
        *,
        call: ToolCall,
        start_time: float,
    ) -> ToolResult:
        """Run a tool call and build the success ``ToolResult``.

        Propagates :class:`ToolError`, ``OSError``, ``RuntimeError``, and
        ``ValueError`` from the underlying tool so the caller can convert
        those failures into a failure ``ToolResult``.

        Args:
            call: The tool call to execute.
            start_time: ``time.time()`` reading captured before the call so the
                caller and this helper share a single elapsed-time origin.

        Returns:
            ToolResult: Success result.
        """
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
            return await self._execute_single_tool_call_success(call=call, start_time=start_time)

        except (ToolError, OSError, RuntimeError, ValueError) as e:
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

        Refuses to run the agent loop when any tool's schema would not be
        accepted by the provider. ``validate_tool_for_provider`` returns a
        mix of ``warning`` and ``error`` severities; only ``error`` entries
        gate the loop, but every diagnostic is logged so warnings remain
        observable. Raising here ensures invalid tool schemas surface on the
        first failed iteration instead of being silently forwarded to the
        provider, which would emit an opaque API error that callers cannot
        attribute back to the offending tool.

        Args:
            tools: Tool definitions to validate.
            provider: The LLM provider to validate against.

        Raises:
            ToolError: If any tool definition is invalid for the provider.
        """
        provider_name = provider.name
        broken: list[str] = []
        for tool in tools:
            errors = validate_tool_for_provider(tool, provider_name)
            for err in errors:
                if err.severity == "error":
                    _logger.error(
                        "tool_schema_validation_error",
                        tool=tool.tool_name.value,
                        location=err.location,
                        error=err.message,
                        provider=provider_name.value,
                    )
                    broken.append(f"{tool.tool_name.value}: {err}")
                else:
                    _logger.warning(
                        "tool_schema_validation_warning",
                        tool=tool.tool_name.value,
                        location=err.location,
                        error=err.message,
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

        if broken:
            joined = "; ".join(broken)
            error_message = (
                f"Tool schema validation failed for provider '{provider_name.value}': {joined}. "
                "Fix the offending bridge's tool definition before sending the request."
            )
            raise ToolError(error_message, tool_name=broken[0].split(":", 1)[0])

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
        is_destructive = self.is_destructive_operation(call)
        _logger.debug(
            "confirmation_check",
            function=call.function_name,
            level=self._config.confirmation_level.value,
            is_destructive=is_destructive,
        )
        return is_destructive

    async def _request_confirmation(self, call: ToolCall) -> bool:
        """Request user confirmation for a tool call.

        Registers the pending confirmation in :attr:`_pending_confirmations`
        so that :meth:`shutdown` and :meth:`cancel` can marshal it cleanly
        even when several confirmations overlap. A pending future cancelled
        from :meth:`cancel` raises :class:`asyncio.CancelledError` here, which
        is translated into a ``False`` return so the caller treats the call
        as declined and continues teardown without blocking.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            bool: ``True`` if the user confirmed, ``False`` if declined,
            cancelled, or no callback is registered.
        """
        if self._shutdown_called or self._shutdown_event.is_set():
            _logger.debug("confirmation_aborted_during_teardown", call_id=call.id)
            return False

        self._state = "waiting_confirmation"

        if self._async_confirmation_callback:
            future = self._async_confirmation_callback(call)
            pending = PendingConfirmation(call=call, future=future)
            self._pending_confirmation = pending
            self._pending_confirmations.add(pending)

            try:
                return await future
            except asyncio.CancelledError:
                _logger.warning("confirmation_future_cancelled", call_id=call.id)
                return False
            finally:
                self._pending_confirmations.discard(pending)
                if self._pending_confirmation is pending:
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
        """Confirm or decline the most recently registered pending operation.

        Resolves the latest entry registered in
        :attr:`_pending_confirmations`. If the future was already cancelled
        (for example, by :meth:`cancel` or :meth:`shutdown`), this is a no-op
        rather than raising :class:`asyncio.InvalidStateError`.

        Args:
            confirmed: ``True`` to confirm the operation, ``False`` to decline.
        """
        pending = self._pending_confirmation
        if pending is None or pending.future.done():
            return
        try:
            pending.future.set_result(confirmed)
        except asyncio.InvalidStateError:
            _logger.warning(
                "confirm_pending_invalid_state",
                call_id=pending.call.id,
                confirmed=confirmed,
            )

    async def cancel(self) -> None:
        """Cancel the current operation and marshal pending confirmations.

        Sets the cancel event, requests provider-side cancellation, then
        cancels every outstanding confirmation future tracked in
        :attr:`_pending_confirmations`. ``future.cancel()`` propagates an
        :class:`asyncio.CancelledError` to any awaiting
        :meth:`_request_confirmation`, which translates it back into a
        ``False`` return so callers do not see leaked exceptions and do not
        hang waiting for user input that will never arrive.
        """
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

        self._marshal_pending_confirmations(reason="cancel")

    def _marshal_pending_confirmations(self, *, reason: str) -> None:
        """Cancel every outstanding confirmation future.

        Iterates a snapshot of :attr:`_pending_confirmations` so that
        ``_request_confirmation``'s ``finally`` block (which mutates the set)
        can run without raising ``RuntimeError: Set changed size during
        iteration``. Each not-yet-resolved future is cancelled via
        :meth:`asyncio.Future.cancel`; the awaiting coroutine then receives
        :class:`asyncio.CancelledError` and translates it into a ``False``
        return per the contract in :meth:`_request_confirmation`. Already
        resolved futures are left untouched.

        Args:
            reason: Short identifier (``"cancel"``, ``"shutdown"``) recorded
                in structured logs for traceability.
        """
        pending_snapshot = tuple(self._pending_confirmations)
        for pending in pending_snapshot:
            future = pending.future
            call_id = pending.call.id
            if future.done():
                continue
            cancelled = future.cancel()
            _logger.debug(
                "pending_confirmation_marshalled",
                reason=reason,
                call_id=call_id,
                cancelled=cancelled,
            )

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
        _logger.info("orchestrator_add_binary_started", path=str(path), run_bridge_analysis=run_bridge_analysis)
        if self._current_session is None:
            error_message = "No active session"
            _logger.error("add_binary_no_active_session", path=str(path))
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
            _logger.error("set_active_binary_no_active_session", index=index)
            raise RuntimeError(error_message)

        if index < 0 or index >= len(self._current_session.binaries):
            error_message = f"Binary index out of range: {index}"
            _logger.error(
                "set_active_binary_index_out_of_range",
                index=index,
                binary_count=len(self._current_session.binaries),
            )
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
            _logger.error("add_patch_no_active_session")
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
        _logger.debug("orchestrator_message_callback_set")

    def set_tool_call_callback(self, callback: Callable[[ToolCall], None]) -> None:
        """Set callback for tool calls.

        Args:
            callback: Function to call when tool is called.
        """
        self._on_tool_call = callback
        _logger.debug("orchestrator_tool_call_callback_set")

    def set_tool_result_callback(self, callback: Callable[[ToolResult], None]) -> None:
        """Set callback for tool results.

        Args:
            callback: Function to call when tool returns result.
        """
        self._on_tool_result = callback
        _logger.debug("orchestrator_tool_result_callback_set")

    def set_stream_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback for streaming response chunks.

        Args:
            callback: Function to call with each text chunk.
        """
        self._on_stream_chunk = callback
        _logger.debug("orchestrator_stream_callback_set")

    def set_confirmation_callback(
        self,
        callback: Callable[[ToolCall], bool],
    ) -> None:
        """Set synchronous callback for confirmation requests.

        Args:
            callback: Function to call for confirmation, returns True to proceed.
        """
        self._confirmation_callback = callback
        _logger.debug("orchestrator_confirmation_callback_set")

    def set_async_confirmation_callback(
        self,
        callback: Callable[[ToolCall], asyncio.Future[bool]],
    ) -> None:
        """Set async callback for confirmation requests.

        Args:
            callback: Function returning a Future that resolves to True/False.
        """
        self._async_confirmation_callback = callback
        _logger.debug("orchestrator_async_confirmation_callback_set")

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
            "hex_editor": "get_hex_editor_bridge",
        }
        getter_name = getter_map.get(tool_name.lower())
        if getter_name is None:
            _logger.warning(
                "typed_bridge_unknown_tool",
                tool_name=tool_name,
                known_tools=sorted(getter_map),
            )
            return None
        try:
            bridge: object | None = getattr(self._tools, getter_name)()
        except (ToolError, OSError, RuntimeError, AttributeError) as exc:
            _logger.warning(
                "typed_bridge_getter_failed",
                tool_name=tool_name,
                getter=getter_name,
                error=str(exc),
            )
            return None
        else:
            _logger.debug("typed_bridge_resolved", tool_name=tool_name, has_bridge=bridge is not None)
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
        _logger.info("orchestrator_confirmation_level_set", level=str(level))

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
        _logger.debug(
            "orchestrator_configure_hooks",
            has_bridge_analysis=on_bridge_analysis is not None,
            has_confirmation=on_confirmation is not None,
        )
        if on_bridge_analysis:
            self.set_bridge_analysis_callback(on_bridge_analysis)
        if on_confirmation:
            self.set_confirmation_callback(on_confirmation)

    async def refresh_session_state(self) -> None:
        """Refresh cached bridge analysis for the active session.

        Re-runs :meth:`reanalyze_bridge_analysis` against the current session's active binary so stale bridge results are regenerated. Does
        not reload the session from disk or refresh any other session state.
        """
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
            _logger.error("activate_binary_by_name_no_active_session", binary_name=name)
            raise RuntimeError(error_message)

        _logger.info("binary_activation_by_name", binary_name=name)
        for i, binary in enumerate(self._current_session.binaries):
            if binary.name == name:
                await self.set_active_binary(i)
                return

        error_message = f"Binary not found: {name}"
        _logger.error("activate_binary_by_name_not_found", binary_name=name)
        raise ValueError(error_message)

    async def _run_shutdown_steps(self, *, errors: list[Exception]) -> None:
        """Execute every shutdown teardown step, collecting failures.

        Each step is guarded so a single failure does not skip the remaining
        steps; caught exceptions are appended to ``errors`` for the caller to
        bundle into an :class:`ExceptionGroup` after the outer ``finally``
        runs.

        Args:
            errors: Mutable list collecting exceptions raised by individual
                teardown steps. ``BaseException`` subclasses are intentionally
                not caught and propagate to the caller's ``finally`` clause.
        """
        self._marshal_pending_confirmations(reason="shutdown")
        await asyncio.sleep(0)

        try:
            await self.cancel()
        except Exception as exc:
            _logger.exception("shutdown_cancel_failed", state=self._state)
            errors.append(exc)

        try:
            await self._tools.shutdown()
        except Exception as exc:
            _logger.exception("shutdown_tools_cleanup_failed", state=self._state)
            errors.append(exc)

        if self._current_session:
            try:
                await self._sessions.update(self._current_session)
            except Exception as exc:
                _logger.exception(
                    "shutdown_session_save_failed",
                    session_id=self._current_session.id,
                    state=self._state,
                )
                errors.append(exc)

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
                    _logger.info("shutdown_provider_model_unloaded", provider=provider_name.value)
                except Exception as exc:
                    _logger.exception(
                        "shutdown_provider_unload_failed",
                        provider=provider_name.value,
                    )
                    errors.append(exc)

        session_cleanup = getattr(self._sessions, "cleanup", None)
        if callable(session_cleanup):
            try:
                cleanup_coro: Coroutine[object, object, int] = cast(
                    "Coroutine[object, object, int]",
                    session_cleanup(),
                )
                deleted: int = await cleanup_coro
                _logger.info("shutdown_session_cleanup_completed", deleted=deleted)
            except Exception as exc:
                _logger.exception("shutdown_session_cleanup_failed")
                errors.append(exc)

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources.

        Each teardown step is guarded by ``except Exception`` so one failing stage cannot
        leave other resources dangling. ``BaseException`` subclasses (notably
        ``asyncio.CancelledError`` and ``KeyboardInterrupt``) are intentionally not
        caught and propagate through the ``finally`` clause that clears final state. All
        caught exceptions are collected and, once every stage has had a chance to run,
        bundled into a single ``ExceptionGroup`` so callers learn about every teardown
        failure.

        Before any other teardown work, all in-flight confirmation futures are
        marshalled via :meth:`_marshal_pending_confirmations` so awaiters do
        not leak coroutines or hang waiting for input that will never arrive.

        Raises:
            ExceptionGroup: When one or more teardown steps raised non-cancellation
                exceptions, all collected failures are bundled into an ``ExceptionGroup``.
        """
        if self._shutdown_called:
            _logger.info("orchestrator_shutdown_already_called", state=self._state)
            return
        self._shutdown_called = True
        self._shutdown_event.set()
        _logger.info("orchestrator_shutdown_started", state=self._state)

        errors: list[Exception] = []

        try:
            await self._run_shutdown_steps(errors=errors)
        finally:
            self._current_session = None
            self._state = "idle"
            structlog.contextvars.clear_contextvars()
            _logger.info(
                "orchestrator_shutdown_completed",
                state=self._state,
                error_count=len(errors),
            )

        if errors:
            group_message = "orchestrator shutdown encountered failures"
            raise ExceptionGroup(group_message, errors)


_MACHO_N_EXT_BIT: int = 0x01
"""``N_EXT`` flag in a Mach-O ``nlist``'s ``n_type`` byte (external symbol)."""

_MACHO_N_TYPE_MASK: int = 0x0E
"""Mask isolating the type field within a Mach-O ``n_type`` byte."""

_MACHO_N_SECT: int = 0x0E
"""``n_type & N_TYPE`` value indicating the symbol is defined in a section."""

_MACHO_N_UNDF: int = 0x00
"""``n_type & N_TYPE`` value indicating the symbol is undefined (imported)."""

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
    return next(
        (canonical for keyword, canonical in _ARCH_KEYWORDS.items() if keyword in raw),
        raw or "unknown",
    )


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


def extract_imports(binary: object) -> list[ImportInfo]:
    """Extract import metadata from a parsed lief binary.

    Implements full coverage for the three formats Intellicrack ingests:

    * **PE** - walks every ``ImportEntry`` from every imported DLL.
    * **ELF** - enumerates every imported dynamic symbol (object and function),
      not just PLT/GOT relocations. This pulls in data symbols
      (``__environ``, ``stdout``) and lazy-bound functions that the previous
      ``pltgot_relocations`` scan missed entirely on stripped or
      ``BIND_NOW``-linked binaries.
    * **Mach-O** - walks ``imported_symbols`` so dyld-resolved imports
      (e.g. ``_printf``) appear in the import list. The enclosing dylib is
      resolved through the symbol's ``library`` attribute when ordinal-based
      two-level lookups expose it.

    Args:
        binary: A parsed ``lief.PE.Binary``, ``lief.ELF.Binary``, or
            ``lief.MachO.Binary`` instance.

    Returns:
        list[ImportInfo]: Imported entries with the full ``(dll, function,
        ordinal, address)`` tuple populated as far as the format reveals.
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
                        ordinal=None if entry_name else int(entry.data),
                        address=int(entry.iat_value),
                    ),
                )
    elif isinstance(binary, lief.ELF.Binary):
        for sym in binary.imported_symbols:
            sym_name = str(sym.name) if sym.name else ""
            if not sym_name:
                continue
            result.append(
                _ImportInfo(
                    dll="",
                    function=sym_name,
                    ordinal=None,
                    address=int(sym.value),
                ),
            )
    elif isinstance(binary, lief.MachO.Binary):
        seen_imports: set[str] = set()
        for sym in binary.imported_symbols:
            sym_name = str(sym.name) if sym.name else ""
            if not sym_name or sym_name in seen_imports:
                continue
            seen_imports.add(sym_name)
            library_obj = getattr(sym, "library", None)
            library_name = str(library_obj.name) if library_obj is not None and getattr(library_obj, "name", None) else ""
            ordinal_attr = getattr(sym, "library_ordinal", None)
            ordinal_value = int(ordinal_attr) if isinstance(ordinal_attr, int) else None
            result.append(
                _ImportInfo(
                    dll=library_name,
                    function=sym_name,
                    ordinal=ordinal_value,
                    address=int(sym.value),
                ),
            )
        for sym in binary.symbols:
            sym_name = str(sym.name) if sym.name else ""
            if not sym_name or sym_name in seen_imports:
                continue
            raw_type = int(getattr(sym, "raw_type", 0))
            if raw_type & _MACHO_N_EXT_BIT and (raw_type & _MACHO_N_TYPE_MASK) == _MACHO_N_UNDF:
                seen_imports.add(sym_name)
                library_obj = getattr(sym, "library", None)
                library_name = str(library_obj.name) if library_obj is not None and getattr(library_obj, "name", None) else ""
                ordinal_attr = getattr(sym, "library_ordinal", None)
                ordinal_value = int(ordinal_attr) if isinstance(ordinal_attr, int) else None
                result.append(
                    _ImportInfo(
                        dll=library_name,
                        function=sym_name,
                        ordinal=ordinal_value,
                        address=int(sym.value),
                    ),
                )
    return result


def extract_exports(binary: object) -> list[ExportInfo]:
    """Extract export metadata from a parsed lief binary.

    Implements full coverage for the three formats Intellicrack ingests:

    * **PE** - walks every ``ExportEntry`` from the export directory.
    * **ELF** - walks every dynamic symbol marked as exported.
    * **Mach-O** - walks ``exported_symbols``, which surfaces both classic
      ``__TEXT`` symbol-table exports and ``LC_DYLD_EXPORTS_TRIE`` /
      ``LC_DYLD_INFO`` trie-encoded exports that newer macOS dylibs publish.

    Args:
        binary: A parsed ``lief.PE.Binary``, ``lief.ELF.Binary``, or
            ``lief.MachO.Binary`` instance.

    Returns:
        list[ExportInfo]: Exported entries with ``(name, ordinal, address)``
        populated. Ordinals are ``0`` for ELF / Mach-O because those formats
        do not assign export ordinals.
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
        result.extend(_ExportInfo(name=str(sym.name), ordinal=0, address=int(sym.value)) for sym in binary.exported_symbols if sym.name)
    elif isinstance(binary, lief.MachO.Binary):
        seen_names: set[str] = set()
        for sym in binary.exported_symbols:
            sym_name = str(sym.name) if sym.name else ""
            if not sym_name or sym_name in seen_names:
                continue
            seen_names.add(sym_name)
            result.append(_ExportInfo(name=sym_name, ordinal=0, address=int(sym.value)))
        for sym in binary.symbols:
            sym_name = str(sym.name) if sym.name else ""
            if not sym_name or sym_name in seen_names:
                continue
            raw_type = int(getattr(sym, "raw_type", 0))
            if raw_type & _MACHO_N_EXT_BIT and (raw_type & _MACHO_N_TYPE_MASK) == _MACHO_N_SECT:
                seen_names.add(sym_name)
                result.append(_ExportInfo(name=sym_name, ordinal=0, address=int(sym.value)))
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
    sha256 = hashlib.sha256(raw).hexdigest()
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
            sha256=sha256,
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
        sha256=sha256,
        file_type=meta[0],
        architecture=meta[1],
        is_64bit=meta[2],
        entry_point=meta[3],
        sections=_extract_sections(binary),
        imports=extract_imports(binary),
        exports=extract_exports(binary),
    )
