# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for Orchestrator agent-loop guards (Group 06 Wave 5).

Covers:
  S7-04 — max_iterations guard: scripted provider runs to exhaustion;
           assert ``stats.total_tool_calls == max_iterations``.
  S7-05 — timeout_seconds guard (PD-009 RED-BY-DESIGN): orchestrator does
           not wrap the agent loop in ``asyncio.wait_for``; assert
           ``asyncio.TimeoutError`` propagates — DID NOT RAISE → test FAILS.
  S7-06 — Confirmation gate: ``ConfirmationLevel.DESTRUCTIVE`` + callback
           returns False → bridge never executed → ``stats.total_tool_calls == 0``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

import pytest

import intellicrack.core.orchestrator as _orch_mod
from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    ConfirmationLevel,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
    ToolCall,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolName,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from intellicrack.core.types import ThinkingConfig, ToolChoice


_TOOLS_DIR_NAME: Final[Path] = Path("tools")
_SESSION_DB_NAME: Final[str] = "sessions.db"


_MODEL_ID: Final[str] = "probe-model-v1"
_PROBE_CALL_ID_PREFIX: Final[str] = "guard-test-call-"
_TERMINATE_CALL_ID: Final[str] = "guard-test-terminate-1"
_TERMINATE_FUNCTION: Final[str] = "terminate"
_PROBE_FUNCTION: Final[str] = "probe"


class _FakeTiktokenEncoder:
    """Trivial word-count encoder that replaces tiktoken in offline test runs.

    The real ``tiktoken.get_encoding`` loads BPE data files that are absent in
    the offline test container.  This stand-in implements the single method that
    ``_count_tokens`` in orchestrator.py calls — ``encode(text, disallowed_special)``
    — returning one integer per whitespace-separated word.  The counts are
    realistic enough for the context-window trimming logic to operate without
    triggering a trim on the small message histories produced by the scripted
    providers in these tests.
    """

    def encode(self, text: str, **_kwargs: object) -> list[int]:
        """Return one integer per whitespace-separated word.

        Args:
            text: Input text to pseudo-tokenize.
            **_kwargs: Ignored keyword arguments (e.g. ``disallowed_special``).

        Returns:
            list[int]: One integer per whitespace-separated word.
        """
        return list(range(len(text.split())))


class _ProbeBridge(ToolBridgeBase):
    """Minimal process bridge for orchestrator-guard tests.

    Provides a ``probe()`` method (read-only; never requires confirmation)
    and a ``terminate()`` method (destructive; requires confirmation when
    ``ConfirmationLevel.DESTRUCTIVE`` is active).  Both are tracked so tests
    can assert call counts.
    """

    def __init__(self) -> None:
        """Initialize the bridge with zero-call counters."""
        super().__init__()
        self.probe_calls: int = 0
        self.terminate_calls: int = 0

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
        """Minimal tool definition for the process bridge.

        Returns:
            ToolDefinition: Definitions for ``probe`` and ``terminate``.
        """
        return ToolDefinition(
            tool_name=ToolName.PROCESS,
            description="Minimal process bridge for orchestrator-guard testing.",
            functions=[
                ToolFunction(
                    name="process.probe",
                    description="Read-only probe.",
                    parameters=[],
                    returns="dict",
                ),
                ToolFunction(
                    name="process.terminate",
                    description="Terminate a process.",
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

    async def probe(self) -> dict[str, str]:
        """Increment the probe counter and return a success dict.

        Returns:
            dict[str, str]: ``{"status": "ok"}``.
        """
        self.probe_calls += 1
        return {"status": "ok"}

    async def terminate(self) -> dict[str, str]:
        """Increment the terminate counter and return a success dict.

        Returns:
            dict[str, str]: ``{"status": "terminated"}``.
        """
        self.terminate_calls += 1
        return {"status": "terminated"}


class _ProbeProvider(LLMProviderBase):
    """Scripted provider that returns ``process.probe`` ToolCalls unconditionally.

    When the orchestrator passes ``ToolChoice(mode=ToolChoiceMode.NONE)``
    (the ``force_no_tools_next`` path after all tool calls fail), the provider
    returns a final text message instead.  This models the agent's end-of-loop
    behaviour so the orchestrator terminates gracefully after max_iterations.
    """

    def __init__(self) -> None:
        """Initialize with zero call count and connected state."""
        super().__init__()
        self.connected: bool = True
        self._call_count: int = 0

    @property
    @override
    def name(self) -> ProviderName:
        """Provider name constant.

        Returns:
            ProviderName: Always OPENAI.
        """
        return ProviderName.OPENAI

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
                provider=ProviderName.OPENAI,
                context_window=8192,
                supports_tools=True,
                supports_vision=False,
                supports_streaming=False,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]

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
        """Return a probe ToolCall or a final text depending on tool_choice.

        When ``tool_choice.mode == ToolChoiceMode.NONE`` (the forced-no-tools
        path) or there are no tool definitions available, this returns a final
        text message.  Otherwise it emits a ``process.probe`` ToolCall.

        Args:
            messages: Conversation history.
            model: Model id.
            tools: Available tool definitions.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.
            tool_choice: Tool selection directive from the orchestrator.
            thinking: Extended-thinking config.
            enable_cache: Whether prompt caching is active.

        Returns:
            tuple[Message, list[ToolCall] | None]: Either a ToolCall list
                or a final text response.
        """
        del model, temperature, max_tokens, thinking, enable_cache
        self._call_count += 1
        no_tool_mode = tool_choice is not None and tool_choice.mode == ToolChoiceMode.NONE
        if no_tool_mode or not tools:
            return Message(role="assistant", content="probe sequence complete"), None

        call = ToolCall(
            id=f"{_PROBE_CALL_ID_PREFIX}{self._call_count}",
            tool_name="process",
            function_name=_PROBE_FUNCTION,
            arguments={},
        )
        return Message(role="assistant", content=""), [call]

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
        """Yield a single final-response chunk.

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
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return an empty list — this provider ignores tool schemas.

        Args:
            tools: Tool definitions to ignore.

        Returns:
            list[dict[str, object]]: Always empty.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Pass messages through as role/content dicts.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Role/content pairs.
        """
        return [{"role": m.role, "content": m.content} for m in messages]


class _TerminateProvider(LLMProviderBase):
    """Scripted provider that returns a ``process.terminate`` ToolCall on the first call.

    On the first ``chat()`` invocation it emits a ``terminate`` ToolCall.  On
    subsequent calls (the forced-no-tools summary turn after all tool results
    failed) it returns a final text response.  Used by S7-06 to exercise the
    confirmation-denied path.
    """

    def __init__(self) -> None:
        """Initialize with zero call count and connected state."""
        super().__init__()
        self.connected: bool = True
        self._call_count: int = 0

    @property
    @override
    def name(self) -> ProviderName:
        """OPENAI provider name constant.

        Returns:
            ProviderName: Always OPENAI.
        """
        return ProviderName.OPENAI

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Unused credentials.
        """
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """List one dummy model.

        Returns:
            list[ModelInfo]: One model entry.
        """
        return [
            ModelInfo(
                id=_MODEL_ID,
                name=_MODEL_ID,
                provider=ProviderName.OPENAI,
                context_window=8192,
                supports_tools=True,
                supports_vision=False,
                supports_streaming=False,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]

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
        """Return a terminate ToolCall on call 1; text on subsequent calls.

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
            tuple[Message, list[ToolCall] | None]: ToolCall or final text.
        """
        del model, temperature, max_tokens, thinking, enable_cache
        self._call_count += 1
        no_tool_mode = tool_choice is not None and tool_choice.mode == ToolChoiceMode.NONE
        if self._call_count > 1 or no_tool_mode:
            return Message(role="assistant", content="terminate attempt finished"), None

        call = ToolCall(
            id=_TERMINATE_CALL_ID,
            tool_name="process",
            function_name=_TERMINATE_FUNCTION,
            arguments={},
        )
        return Message(role="assistant", content=""), [call]

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
        """Yield a single final-response chunk.

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
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return empty list.

        Args:
            tools: Tool definitions to ignore.

        Returns:
            list[dict[str, object]]: Always empty.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Pass messages through as role/content dicts.

        Args:
            messages: Messages to convert.

        Returns:
            list[dict[str, object]]: Role/content pairs.
        """
        return [{"role": m.role, "content": m.content} for m in messages]


def _build_orch(
    tmp_path: Path,
    *,
    provider: LLMProviderBase,
    bridge: ToolBridgeBase,
    config: OrchestratorConfig,
) -> Orchestrator:
    """Wire up an Orchestrator with the given provider and bridge.

    Args:
        tmp_path: Pytest temporary directory for the session store.
        provider: Pre-built LLMProviderBase to register.
        bridge: Pre-built ToolBridgeBase to register.
        config: Orchestrator configuration.

    Returns:
        Orchestrator: Fully wired orchestrator with an active session.
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
        config=config,
    )


class TestMaxIterationsGuard:
    """Gate for S7-04: agent loop terminates after exactly max_iterations tool calls."""

    def test_agent_loop_terminates_at_max_iterations(self, tmp_path: Path) -> None:
        """max_iterations=3 with always-probe provider yields exactly 3 tool calls.

        Oracle: the orchestrator increments ``OrchestratorStats.total_tool_calls``
        inside ``_execute_single_tool_call`` at the start of each real execution;
        with 3 loop iterations each yielding one successful probe call,
        ``stats.total_tool_calls`` must equal 3.  Mutation: removing the
        ``while iteration < max_iterations`` guard allows infinite iteration so
        the provider never runs out of probe responses — the test itself hangs
        rather than failing, but with a small max_iterations the loop terminates
        quickly with a count of 0 (no iteration) or > 3 (uncapped).
        """
        bridge = _ProbeBridge()
        provider = _ProbeProvider()
        config = OrchestratorConfig(
            max_iterations=3,
            stream_responses=False,
            confirmation_level=ConfirmationLevel.NONE,
        )
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        async def _run() -> None:
            await orch.start_session(ProviderName.OPENAI, _MODEL_ID)
            await orch.process_user_input("run probes")

        asyncio.run(_run())

        assert orch.stats.total_tool_calls == 3, f"Expected total_tool_calls==3 after max_iterations=3; got {orch.stats.total_tool_calls}"
        assert bridge.probe_calls == 3, f"Expected bridge.probe_calls==3; got {bridge.probe_calls}"


class TestTimeoutGuard:
    """Gate for S7-05: timeout_seconds not enforced (PD-009 RED-BY-DESIGN).

    The production agent loop in ``_run_agent_loop`` has no
    ``asyncio.wait_for`` wrapper around its ``while`` body. Consequently,
    the ``timeout_seconds`` field of ``OrchestratorConfig`` is stored but
    never consulted during the loop — the loop runs to completion regardless
    of elapsed time.

    This gate asserts the CORRECT contract: ``process_user_input`` must raise
    ``asyncio.TimeoutError`` when elapsed time exceeds ``timeout_seconds``.
    Since production never raises this error, the test's
    ``pytest.raises(asyncio.TimeoutError)`` block exits without the exception
    and pytest reports **DID NOT RAISE**.  The gate is permanently RED until
    the production code adds timeout enforcement.
    """

    def test_timeout_seconds_not_enforced_red_by_design(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """process_user_input raises asyncio.TimeoutError when timeout_seconds elapses.

        This test is RED-BY-DESIGN (PD-009): the orchestrator does not wrap
        the agent loop in ``asyncio.wait_for``, so the call completes normally
        and DID NOT RAISE, failing this gate.  Oracle: the correct contract
        as implied by ``OrchestratorConfig.timeout_seconds`` field documentation.
        Mutation: adding ``asyncio.wait_for(..., timeout=self._config.timeout_seconds)``
        around the agent loop turns this gate green.

        ``_get_token_encoder`` is replaced with ``_FakeTiktokenEncoder`` to
        avoid ``ModuleNotFoundError`` from offline tiktoken BPE files.  This
        stub isolates the timeout concern: the orchestrator's own loop logic is
        unchanged and the PD-009 defect is still the reason the gate is red.
        """

        def _fake_get_encoder(_p: ProviderName | None) -> _FakeTiktokenEncoder:
            del _p
            return _FakeTiktokenEncoder()

        monkeypatch.setattr(_orch_mod, "_get_token_encoder", _fake_get_encoder)
        bridge = _ProbeBridge()
        provider = _ProbeProvider()
        config = OrchestratorConfig(
            max_iterations=100,
            timeout_seconds=1,
            stream_responses=False,
            confirmation_level=ConfirmationLevel.NONE,
        )
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        async def _run() -> None:
            await orch.start_session(ProviderName.OPENAI, _MODEL_ID)
            with pytest.raises(asyncio.TimeoutError):
                await orch.process_user_input("this should time out")

        asyncio.run(_run())


class TestConfirmationGate:
    """Gate for S7-06: ConfirmationLevel.DESTRUCTIVE + denied callback → total_tool_calls==0."""

    def test_destructive_call_denied_skips_bridge_execution(self, tmp_path: Path) -> None:
        """Destructive tool call denied by confirmation callback leaves total_tool_calls at 0.

        The orchestrator checks ``is_destructive_operation`` for each tool call when
        ``ConfirmationLevel.DESTRUCTIVE`` is active.  ``process.terminate`` is in
        ``_PROCESS_DESTRUCTIVE``, so confirmation is required.  When the callback
        returns False, ``_execute_single_tool_call`` (which increments
        ``stats.total_tool_calls``) is never entered.

        Oracle: ``stats.total_tool_calls == 0`` after one denied terminate call and
        the forced-no-tools summary response.  Mutation: removing the
        ``if not confirmed: continue`` branch causes ``_execute_single_tool_call``
        to be called, setting ``total_tool_calls = 1`` and failing this assertion.
        """
        bridge = _ProbeBridge()
        provider = _TerminateProvider()
        config = OrchestratorConfig(
            max_iterations=5,
            stream_responses=False,
            confirmation_level=ConfirmationLevel.DESTRUCTIVE,
        )
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)
        orch.set_confirmation_callback(lambda _call: False)

        async def _run() -> None:
            await orch.start_session(ProviderName.OPENAI, _MODEL_ID)
            await orch.process_user_input("terminate something")

        asyncio.run(_run())

        assert orch.stats.total_tool_calls == 0, f"Expected total_tool_calls==0 when confirmation denied; got {orch.stats.total_tool_calls}"
        assert bridge.terminate_calls == 0, f"Expected bridge.terminate_calls==0; got {bridge.terminate_calls}"

    def test_destructive_call_approved_executes_bridge(self, tmp_path: Path) -> None:
        """Destructive call with callback returning True executes the bridge method.

        Oracle: ``stats.total_tool_calls == 1`` after one approved terminate call.
        Mutation: always denying confirmation (callback returns False) keeps
        ``total_tool_calls`` at 0 and fails this assertion.
        """
        bridge = _ProbeBridge()
        provider = _TerminateProvider()
        config = OrchestratorConfig(
            max_iterations=5,
            stream_responses=False,
            confirmation_level=ConfirmationLevel.DESTRUCTIVE,
        )
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)
        orch.set_confirmation_callback(lambda _call: True)

        async def _run() -> None:
            await orch.start_session(ProviderName.OPENAI, _MODEL_ID)
            await orch.process_user_input("terminate something approved")

        asyncio.run(_run())

        assert orch.stats.total_tool_calls == 1, f"Expected total_tool_calls==1 after approved terminate; got {orch.stats.total_tool_calls}"
        assert bridge.terminate_calls == 1, f"Expected bridge.terminate_calls==1; got {bridge.terminate_calls}"
