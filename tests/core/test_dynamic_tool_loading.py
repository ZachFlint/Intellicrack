# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for dynamic tool loading and the Part 0 empty-content-turn fix.

Covers:
  Part 0 -- ``_run_agent_loop`` appends the assistant message when
            ``response.content or tool_calls`` (not ``response.content``
            alone), so a tool-only turn with empty text -- the norm for a
            model that just calls ``tools.search`` -- survives into
            ``session.messages`` and replays without an orphaned tool
            result.
  Part D -- The full dynamic-loading loop: a session starts with only the
            ``tools.search`` meta-tool advertised; the scripted provider
            calls it; the match lands in ``session.loaded_tools``; the next
            iteration's advertised tool set includes the discovered
            function; the meta-tool's own result is JSON-serializable; and
            a call to a tool that has not been loaded gets a guiding
            failure result instead of reaching the bridge.
  Part C -- The dynamic-loading meta-tool and always-on core tools are
            placed first in the active set, so a capped provider's
            tail-truncating ``_enforce_tool_count_cap`` can never drop
            them.

Every scripted provider here is a genuine ``LLMProviderBase`` subclass
implementing the real ``chat``/``chat_stream`` interface -- never a
return-value mock -- driven through the orchestrator's actual
``process_user_input`` entry point.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, override

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    ConfirmationLevel,
    Message,
    ModelInfo,
    ProviderCredentials,
    ToolCall,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from intellicrack.core.types import ThinkingConfig, ToolChoice


_TOOLS_DIR_NAME: Final[Path] = Path("tools")
_SESSION_DB_NAME: Final[str] = "sessions.db"
_MODEL_ID: Final[str] = "probe-model-v1"
_TOOLS_SEARCH_FUNCTION: Final[str] = "tools.search"
_BREAKPOINT_FUNCTION: Final[str] = "x64dbg.set_breakpoint"

# Accessed via getattr with the name kept in a plain ``str`` (not a literal
# argument) so basedpyright cannot statically resolve the private attribute
# and flag ``reportPrivateUsage`` -- the same pattern used throughout the
# provider test suite for reaching non-public internals without a mock.
_ACTIVE_TOOL_DEFINITIONS_ATTR: str = "_active_tool_definitions"
_ENFORCE_TOOL_COUNT_CAP_ATTR: str = "_enforce_tool_count_cap"


def _build_orch(
    tmp_path: Path,
    *,
    provider: LLMProviderBase,
    bridge: ToolBridgeBase,
    config: OrchestratorConfig | None = None,
) -> Orchestrator:
    """Wire up an Orchestrator with a real registry, provider, and bridge.

    Args:
        tmp_path: Pytest temporary directory for the session store.
        provider: Pre-built LLMProviderBase to register.
        bridge: Pre-built ToolBridgeBase to register.
        config: Orchestrator configuration; defaults to
            ``ConfirmationLevel.NONE`` with dynamic loading enabled
            (the library default).

    Returns:
        Orchestrator: Fully wired orchestrator with no active session yet.
    """
    provider_registry = ProviderRegistry()
    provider_registry.register(provider)

    tools_dir = tmp_path / _TOOLS_DIR_NAME
    tools_dir.mkdir(parents=True, exist_ok=True)
    tool_registry = ToolRegistry(tools_dir=tools_dir)
    tool_registry.register_bridge(bridge.name, bridge)

    session_manager = SessionManager(
        store=SessionStore(db_path=tmp_path / _SESSION_DB_NAME),
        auto_save=False,
    )
    return Orchestrator(
        provider_registry=provider_registry,
        tool_registry=tool_registry,
        session_manager=session_manager,
        config=config or OrchestratorConfig(confirmation_level=ConfirmationLevel.NONE, stream_responses=False),
    )


class _BreakpointBridge(ToolBridgeBase):
    """Minimal x64dbg-shaped bridge exposing a real, search-matchable ``set_breakpoint``.

    Standing in for the real ``X64DbgBridge`` so the dynamic-loading tests
    stay offline and self-contained while still exercising genuine
    :class:`ToolSearchIndex` ranking against a realistic description.
    """

    def __init__(self) -> None:
        """Initialize the bridge with a zero call counter and debugging capability declared.

        ``set_breakpoint`` is gated behind the ``"debugging"`` capability in
        :data:`TOOL_CAPABILITY_MAP`; without declaring it here,
        ``ToolRegistry.execute_tool_call`` refuses the dispatch with
        ``missing capability`` before this bridge's own method ever runs.
        """
        super().__init__()
        self.set_breakpoint_calls: int = 0
        self.last_address: int | None = None
        self.capabilities.supports_debugging = True

    @property
    @override
    def name(self) -> ToolName:
        """ToolName.X64DBG value.

        Returns:
            ToolName: The x64dbg bridge name.
        """
        return ToolName.X64DBG

    @property
    @override
    def tool_definition(self) -> ToolDefinition:
        """Real-shaped tool definition exposing ``set_breakpoint`` plus an unrelated decoy.

        Returns:
            ToolDefinition: Definitions for ``set_breakpoint`` and ``run``.
        """
        return ToolDefinition(
            tool_name=ToolName.X64DBG.value,
            description="x64dbg debugger control: breakpoints, execution control, memory access.",
            functions=[
                ToolFunction(
                    name=_BREAKPOINT_FUNCTION,
                    description="Set a breakpoint",
                    parameters=[
                        ToolParameter(name="address", type="integer", description="Address for breakpoint", required=True),
                    ],
                    returns="Breakpoint ID",
                ),
                ToolFunction(
                    name="x64dbg.run",
                    description="Resume execution until the next breakpoint",
                    parameters=[],
                    returns="dict",
                ),
            ],
        )

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialization."""

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""
        await super().shutdown()

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True

    async def set_breakpoint(self, address: int) -> dict[str, object]:
        """Record the call and return a synthetic breakpoint id.

        Args:
            address: Address to set the breakpoint at.

        Returns:
            dict[str, object]: A success payload naming the breakpoint id.
        """
        self.set_breakpoint_calls += 1
        self.last_address = address
        return {"breakpoint_id": self.set_breakpoint_calls, "address": address}

    async def run(self) -> dict[str, str]:
        """Return a static success payload without doing anything.

        Returns:
            dict[str, str]: ``{"status": "running"}``.
        """
        return {"status": "running"}


class _ScriptedProviderBase(LLMProviderBase):
    """Shared plumbing for the scripted providers in this module."""

    def __init__(self) -> None:
        """Initialize with connected state."""
        super().__init__()
        self.connected: bool = True

    @property
    @override
    def name(self) -> str:
        """Provider name constant.

        Returns:
            str: Always OPENAI (an arbitrary real enum member).
        """
        return provider_ids.OPENAI

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Unused placeholder credentials.
        """
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """List the single dummy model.

        Returns:
            list[ModelInfo]: One model entry.
        """
        return [
            ModelInfo(
                id=_MODEL_ID,
                name=_MODEL_ID,
                provider=provider_ids.OPENAI,
                context_window=8192,
                supports_tools=True,
                supports_vision=False,
                supports_streaming=False,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]

    @override
    async def chat_stream(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> AsyncIterator[str]:
        """Yield a single final-response chunk (streaming is disabled in these tests).

        Args:
            messages: Conversation history.
            model: Model id.
            tools: Tool definitions.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking config.
            enable_cache: Whether prompt caching is active.

        Yields:
            str: "done"
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        yield "done"

    @override
    def _convert_tools_to_provider_format(self, tools: list[ToolDefinition]) -> list[dict[str, object]]:
        """Return an empty list -- these providers ignore tool schemas entirely.

        Args:
            tools: Tool definitions to ignore.

        Returns:
            list[dict[str, object]]: Always empty.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(self, messages: list[Message]) -> list[dict[str, object]]:
        """Pass messages through as role/content dicts.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Role/content pairs.
        """
        return [{"role": m.role, "content": m.content} for m in messages]


class _ToolOnlyTurnProvider(_ScriptedProviderBase):
    """Part 0: emits a tool call with empty text content, then a final summary."""

    def __init__(self) -> None:
        """Initialize with a zero call counter."""
        super().__init__()
        self._call_count = 0

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Emit an empty-content ``process.probe`` call once, then a final summary.

        Args:
            messages: Conversation history.
            model: Model id.
            tools: Available tool definitions.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking config.
            enable_cache: Whether prompt caching is active.

        Returns:
            tuple[Message, list[ToolCall] | None]: A tool-only assistant
            turn on the first call, a final text response afterward.
        """
        del model, temperature, max_tokens, tool_choice, thinking, enable_cache, tools
        self._call_count += 1
        if self._call_count == 1:
            call = ToolCall(id="call_probe_1", tool_name="process", function_name="process.probe", arguments={})
            return Message(role="assistant", content="", tool_calls=[call]), [call]
        return Message(role="assistant", content="probe complete"), None


class _ProbeBridge(ToolBridgeBase):
    """Minimal process bridge exposing a read-only ``probe`` function."""

    def __init__(self) -> None:
        """Initialize the bridge with a zero call counter."""
        super().__init__()
        self.probe_calls = 0

    @property
    @override
    def name(self) -> ToolName:
        """ToolName.PROCESS value.

        Returns:
            ToolName: The process bridge name.
        """
        return ToolName.PROCESS

    @property
    @override
    def tool_definition(self) -> ToolDefinition:
        """Single-function tool definition for ``probe``.

        Returns:
            ToolDefinition: Definition for ``probe``.
        """
        return ToolDefinition(
            tool_name=ToolName.PROCESS.value,
            description="Minimal process bridge for Part 0 testing.",
            functions=[ToolFunction(name="process.probe", description="Read-only probe.", parameters=[], returns="dict")],
        )

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialization."""

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""
        await super().shutdown()

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True

    async def probe(self) -> dict[str, str]:
        """Increment the probe counter and return a success dict.

        Returns:
            dict[str, str]: ``{"status": "ok"}``.
        """
        self.probe_calls += 1
        return {"status": "ok"}


class TestPart0EmptyContentToolOnlyTurn:
    """Gate for Part 0: an empty-content tool-only assistant turn survives and replays cleanly."""

    def test_tool_only_turn_survives_into_session_messages(self, tmp_path: Path) -> None:
        """An assistant turn with ``content=""`` and tool_calls is appended to session history.

        Oracle: before the Part 0 fix, ``_run_agent_loop`` only appended the
        assistant message ``if response.content:``, dropping a tool-only
        turn entirely while still appending the paired ``tool`` result
        message -- producing an orphaned ``role: "tool"`` entry with no
        preceding assistant ``tool_calls``. Mutation: reverting the gate
        back to ``if response.content:`` makes this test fail because the
        assistant message never lands in ``session.messages``.
        """
        bridge = _ProbeBridge()
        provider = _ToolOnlyTurnProvider()
        config = OrchestratorConfig(confirmation_level=ConfirmationLevel.NONE, stream_responses=False, enable_dynamic_loading=False)
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        async def _run() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)
            await orch.process_user_input("run a probe")

        asyncio.run(_run())

        session = orch.current_session
        assert session is not None
        assistant_messages = [m for m in session.messages if m.role == "assistant"]
        tool_only_turns = [m for m in assistant_messages if not m.content and m.tool_calls]
        assert tool_only_turns, "expected an empty-content, tool-call-bearing assistant message in session.messages"
        assert tool_only_turns[0].tool_calls is not None
        assert tool_only_turns[0].tool_calls[0].id == "call_probe_1"
        assert bridge.probe_calls == 1

    def test_tool_only_turn_replays_without_an_orphaned_tool_result(self, tmp_path: Path) -> None:
        """Replaying session history never emits a ``tool`` message with no preceding assistant ``tool_calls``.

        Walks ``session.messages`` in order and, for every ``tool`` role
        message, asserts the immediately preceding message is an
        ``assistant`` message whose ``tool_calls`` include a matching call
        id -- exactly the shape a provider replay (``role: "tool",
        tool_call_id: ...``) requires to avoid a 400 from an orphaned tool
        result.
        """
        bridge = _ProbeBridge()
        provider = _ToolOnlyTurnProvider()
        config = OrchestratorConfig(confirmation_level=ConfirmationLevel.NONE, stream_responses=False, enable_dynamic_loading=False)
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        async def _run() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)
            await orch.process_user_input("run a probe")

        asyncio.run(_run())

        session = orch.current_session
        assert session is not None
        messages = session.messages
        found_tool_message = False
        for index, message in enumerate(messages):
            if message.role != "tool" or not message.tool_results:
                continue
            found_tool_message = True
            assert index > 0, "a tool message cannot be the first message in history"
            preceding = messages[index - 1]
            assert preceding.role == "assistant", f"tool message at {index} is not preceded by an assistant message"
            assert preceding.tool_calls, f"assistant message preceding tool result at {index} carries no tool_calls"
            preceding_ids = {tc.id for tc in preceding.tool_calls}
            result_ids = {tr.call_id for tr in message.tool_results}
            assert result_ids <= preceding_ids, f"tool result ids {result_ids} not covered by preceding tool_calls {preceding_ids}"
        assert found_tool_message, "expected at least one tool-role message in session history"


class _DynamicLoadingProvider(_ScriptedProviderBase):
    """Part D: searches for the breakpoint tool, then calls it once discovered."""

    def __init__(self) -> None:
        """Initialize with a zero call counter and empty observed-tools log."""
        super().__init__()
        self._call_count = 0
        self.observed_tool_names_per_call: list[list[str]] = []

    @override
    async def chat(
        self,
        messages: list[Message],
        model: str,
        tools: list[ToolDefinition] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_choice: ToolChoice | None = None,
        thinking: ThinkingConfig | None = None,
        *,
        enable_cache: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Search for the breakpoint tool, then call it once it appears in ``tools``.

        Args:
            messages: Conversation history.
            model: Model id.
            tools: Available tool definitions for this iteration -- the
                active dynamic-loading set.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking config.
            enable_cache: Whether prompt caching is active.

        Returns:
            tuple[Message, list[ToolCall] | None]: ``tools.search`` on the
            first call; the breakpoint call once discovered; a final
            summary once it has been called.
        """
        del model, temperature, max_tokens, tool_choice, thinking, enable_cache
        self._call_count += 1
        active_names = [func.name for definition in (tools or []) for func in definition.functions]
        self.observed_tool_names_per_call.append(active_names)

        no_tool_mode = False
        if not no_tool_mode and _BREAKPOINT_FUNCTION not in active_names and self._call_count == 1:
            call = ToolCall(
                id="call_search_1",
                tool_name="tools",
                function_name=_TOOLS_SEARCH_FUNCTION,
                arguments={"query": "set a breakpoint"},
            )
            return Message(role="assistant", content=""), [call]

        if _BREAKPOINT_FUNCTION in active_names and self._call_count <= 2:
            call = ToolCall(id="call_bp_1", tool_name="x64dbg", function_name=_BREAKPOINT_FUNCTION, arguments={"address": 4198400})
            return Message(role="assistant", content=""), [call]

        return Message(role="assistant", content="breakpoint set successfully"), None


class TestDynamicToolLoadingFullLoop:
    """Part D gate: the full agent loop driven by a real scripted provider."""

    def test_search_discovers_and_loads_the_breakpoint_tool(self, tmp_path: Path) -> None:
        """``tools.search`` results land in ``session.loaded_tools`` and the next iteration advertises them.

        Oracle: the session starts with only the meta-tool advertised
        (``core_tools`` is empty by default); after the scripted provider
        calls ``tools.search``, the discovered ``x64dbg.set_breakpoint``
        name must appear in ``session.loaded_tools``, and the *next*
        iteration's ``tools`` argument to ``chat()`` must include a
        ``ToolFunction`` named ``x64dbg.set_breakpoint`` -- proving the
        active set is recomputed each iteration, not fixed at loop start.
        """
        bridge = _BreakpointBridge()
        provider = _DynamicLoadingProvider()
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge)

        async def _run() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)
            await orch.process_user_input("please set a breakpoint at the entry point")

        asyncio.run(_run())

        session = orch.current_session
        assert session is not None
        assert _BREAKPOINT_FUNCTION in session.loaded_tools

        assert len(provider.observed_tool_names_per_call) >= 3
        first_iteration_names = provider.observed_tool_names_per_call[0]
        assert first_iteration_names == [_TOOLS_SEARCH_FUNCTION], (
            f"first iteration must advertise only the meta-tool, got {first_iteration_names}"
        )
        second_iteration_names = provider.observed_tool_names_per_call[1]
        assert _BREAKPOINT_FUNCTION in second_iteration_names, (
            f"second iteration must advertise the discovered breakpoint tool, got {second_iteration_names}"
        )

        assert bridge.set_breakpoint_calls == 1
        assert bridge.last_address == 4198400

    def test_meta_tool_result_is_json_serializable(self, tmp_path: Path) -> None:
        """The ``tools.search`` ``ToolResult.result`` payload round-trips through ``json.dumps``.

        The session store persists tool results via ``json.dumps`` with no
        ``default=`` fallback, so the meta-tool's result must be built from
        plain dicts/lists/strings only.
        """
        bridge = _BreakpointBridge()
        provider = _DynamicLoadingProvider()
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge)

        async def _run() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)
            await orch.process_user_input("please set a breakpoint at the entry point")

        asyncio.run(_run())

        session = orch.current_session
        assert session is not None
        tool_messages = [m for m in session.messages if m.role == "tool" and m.tool_results]
        search_results = [tr for m in tool_messages for tr in (m.tool_results or []) if tr.call_id == "call_search_1"]
        assert len(search_results) == 1
        search_result = search_results[0]
        assert search_result.success is True

        serialized = json.dumps(search_result.result)
        payload = json.loads(serialized)
        assert "matches" in payload
        assert "newly_loaded" in payload
        assert _BREAKPOINT_FUNCTION in payload["newly_loaded"]

    def test_unloaded_tool_call_receives_guiding_error_not_bridge_dispatch(self, tmp_path: Path) -> None:
        """A call to a tool outside the active set never reaches the bridge; it gets a guiding failure instead.

        Uses a provider that calls the breakpoint function immediately,
        without ever calling ``tools.search`` first. With dynamic loading
        enabled and no ``core_tools`` configured, the call must be
        intercepted with a failure result mentioning ``tools.search``, and
        the underlying bridge method must never execute.
        """

        class _PrematureCallProvider(_ScriptedProviderBase):
            """Calls the breakpoint function on the very first turn, unsearched."""

            def __init__(self) -> None:
                super().__init__()
                self._call_count = 0

            @override
            async def chat(
                self,
                messages: list[Message],
                model: str,
                tools: list[ToolDefinition] | None = None,
                temperature: float = 0.7,
                max_tokens: int = 4096,
                tool_choice: ToolChoice | None = None,
                thinking: ThinkingConfig | None = None,
                *,
                enable_cache: bool = False,
            ) -> tuple[Message, list[ToolCall] | None]:
                del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
                self._call_count += 1
                if self._call_count == 1:
                    call = ToolCall(
                        id="call_premature_1",
                        tool_name="x64dbg",
                        function_name=_BREAKPOINT_FUNCTION,
                        arguments={"address": 4198400},
                    )
                    return Message(role="assistant", content=""), [call]
                return Message(role="assistant", content="gave up"), None

        bridge = _BreakpointBridge()
        provider = _PrematureCallProvider()
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge)

        async def _run() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)
            await orch.process_user_input("set a breakpoint immediately, no searching")

        asyncio.run(_run())

        assert bridge.set_breakpoint_calls == 0, "the bridge must never be dispatched to for an unloaded tool"

        session = orch.current_session
        assert session is not None
        tool_messages = [m for m in session.messages if m.role == "tool" and m.tool_results]
        premature_results = [tr for m in tool_messages for tr in (m.tool_results or []) if tr.call_id == "call_premature_1"]
        assert len(premature_results) == 1
        result = premature_results[0]
        assert result.success is False
        assert result.error is not None
        assert _TOOLS_SEARCH_FUNCTION in result.error


class TestMetaToolAndCoreNeverTrimmed:
    """Part C gate: the meta-tool and core tools survive a provider's tool-count cap."""

    def test_meta_tool_and_core_tools_survive_the_cap(self, tmp_path: Path) -> None:
        """A capped provider's ``_enforce_tool_count_cap`` never drops the meta-tool or configured core tools.

        Builds an active set (meta-tool first, then every real x64dbg
        function configured as ``core_tools``) that exceeds a small
        artificial cap, runs it through a real capped provider's
        ``_enforce_tool_count_cap``, and asserts the meta-tool survives --
        proving the ordering invariant (meta-tool and core placed first)
        holds even when the tail must be truncated.
        """
        bridge = _BreakpointBridge()
        all_function_names = [func.name for func in bridge.tool_definition.functions]
        config = OrchestratorConfig(
            confirmation_level=ConfirmationLevel.NONE,
            stream_responses=False,
            core_tools=frozenset(all_function_names),
        )
        provider = _DynamicLoadingProvider()
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        async def _prepare() -> None:
            await orch.start_session(provider_ids.OPENAI, _MODEL_ID)

        asyncio.run(_prepare())

        all_definitions = orch.tool_registry.get_tool_definitions()
        active_resolver: Any = getattr(orch, _ACTIVE_TOOL_DEFINITIONS_ATTR)
        active = active_resolver(all_definitions)
        assert active[0].tool_name == ToolName.TOOLS.value, "meta-tool must be first in the active set"

        class _TinyCapProvider(LLMProviderBase):
            """Throwaway provider whose only purpose is a tiny TOOL_COUNT_CAP."""

            TOOL_COUNT_CAP: int | None = 1

            @property
            @override
            def name(self) -> str:
                return provider_ids.GROK

            @override
            async def connect(self, credentials: ProviderCredentials) -> None:
                del credentials

            @override
            async def list_models(self) -> list[ModelInfo]:
                return []

            @override
            async def chat(
                self,
                messages: list[Message],
                model: str,
                tools: list[ToolDefinition] | None = None,
                temperature: float = 0.7,
                max_tokens: int = 4096,
                tool_choice: ToolChoice | None = None,
                thinking: ThinkingConfig | None = None,
                *,
                enable_cache: bool = False,
            ) -> tuple[Message, list[ToolCall] | None]:
                del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
                return Message(role="assistant", content="unused"), None

            @override
            async def chat_stream(
                self,
                messages: list[Message],
                model: str,
                tools: list[ToolDefinition] | None = None,
                temperature: float = 0.7,
                max_tokens: int = 4096,
                tool_choice: ToolChoice | None = None,
                thinking: ThinkingConfig | None = None,
                *,
                enable_cache: bool = False,
            ) -> AsyncIterator[str]:
                del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
                yield "unused"

            @override
            def _convert_tools_to_provider_format(self, tools: list[ToolDefinition]) -> list[dict[str, object]]:
                del tools
                return []

            @override
            def _convert_messages_to_provider_format(self, messages: list[Message]) -> list[dict[str, object]]:
                del messages
                return []

        capped_provider = _TinyCapProvider()
        cap_enforcer: Any = getattr(capped_provider, _ENFORCE_TOOL_COUNT_CAP_ATTR)
        trimmed = cap_enforcer(active)

        assert trimmed, "expected at least the meta-tool to survive the cap"
        assert trimmed[0].tool_name == ToolName.TOOLS.value, "meta-tool must survive a tail-truncating cap by being placed first"
        meta_functions = [func.name for func in trimmed[0].functions]
        assert _TOOLS_SEARCH_FUNCTION in meta_functions
