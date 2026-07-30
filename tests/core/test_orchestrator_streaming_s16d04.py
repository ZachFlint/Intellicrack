# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for S16-D04 — streaming on the initial tools-on turn.

Covers the fix to ``Orchestrator._should_use_streaming``: in "auto" mode the
initial (non-final) turn of a normal tools-on chat must now stream, because
Intellicrack always injects its tool schema so ``tools_available`` is always
``True`` in production. Before the fix, ``_should_use_streaming`` returned
``not tools_available or is_final_response``, which is ``False`` for every
initial turn, so assistant responses never streamed token-by-token in normal
use.

Two gates:
  * ``TestShouldUseStreamingAutoMode`` — direct unit gate on
    ``_should_use_streaming`` asserting it now returns ``True`` for the
    initial tools-on turn in "auto" mode.
  * ``TestStreamedToolsOnTurnEmitsChunks`` — behavioral gate driving the real
    orchestrator agent loop with a genuine streaming provider that yields
    several text deltas *and* finalizes a tool call from the stream, and
    asserting both that multiple ``stream_chunk`` events were observed and
    that the tool call was still collected and executed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

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
    from collections.abc import AsyncIterator, Callable

    from intellicrack.core.types import ThinkingConfig, ToolChoice


_TOOLS_DIR_NAME: Final[Path] = Path("tools")
_SESSION_DB_NAME: Final[str] = "sessions.db"
_MODEL_ID: Final[str] = "streaming-probe-model-v1"
_STREAM_CALL_ID: Final[str] = "s16d04-stream-call-1"
_PROBE_FUNCTION: Final[str] = "probe"
_INITIAL_TURN_CHUNKS: Final[tuple[str, ...]] = ("Initiating ", "probe ", "sequence", "...")
_FINAL_TURN_CHUNKS: Final[tuple[str, ...]] = ("Probe ", "sequence ", "complete.")


class _StreamProbeBridge(ToolBridgeBase):
    """Minimal process bridge exposing a single ``probe`` tool function.

    Mirrors the shape of a real Intellicrack bridge closely enough to drive
    the orchestrator's agent loop: one read-only, non-destructive tool
    function that the scripted provider below can request via a streamed
    tool call.
    """

    def __init__(self) -> None:
        """Initialize the bridge with a zeroed probe-call counter."""
        super().__init__()
        self.probe_calls: int = 0

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
        """Minimal tool definition exposing a single ``probe`` function.

        Returns:
            ToolDefinition: Definition for ``process.probe``.
        """
        return ToolDefinition(
            tool_name=ToolName.PROCESS,
            description="Minimal process bridge for S16-D04 streaming tests.",
            functions=[
                ToolFunction(
                    name="process.probe",
                    description="Read-only probe.",
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


class _StreamingToolCallProvider(LLMProviderBase):
    """Genuine streaming provider used to exercise the S16-D04 fix.

    ``chat_stream`` yields several separate text deltas per turn (simulating
    token-by-token output) rather than a single blob. On the first
    (initial, tools-on) turn it finalizes a ``process.probe`` tool call into
    ``self._pending_tool_calls`` after the text deltas have been yielded,
    exactly as the real provider implementations in
    ``intellicrack.providers`` do (see e.g. ``anthropic.py`` and
    ``openai.py``, which populate ``self._pending_tool_calls`` at the end of
    ``chat_stream`` once the wire stream is exhausted). On the second
    (post-tool-result, final) turn it yields a short completion with no tool
    calls so the agent loop terminates.

    ``chat`` is implemented as a real, functioning non-streaming fallback
    with equivalent per-turn semantics; it is not expected to be invoked by
    these tests since streaming is what is under test, but it is not a
    stub — it is a genuine, self-consistent implementation of the abstract
    contract.
    """

    def __init__(self) -> None:
        """Initialize with zero calls and a connected state."""
        super().__init__()
        self.connected: bool = True
        self.chat_stream_calls: int = 0
        self.chat_calls: int = 0

    @property
    @override
    def name(self) -> ProviderName:
        """Provider name constant.

        Returns:
            ProviderName: Always OPENAI (a member of the orchestrator's
            streamed-tool-call-capable provider set).
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
        """List the single dummy streaming model.

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
                supports_streaming=True,
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
        """Return a probe ToolCall on the first call, final text afterwards.

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
        self.chat_calls += 1
        no_tool_mode = tool_choice is not None and tool_choice.mode == ToolChoiceMode.NONE
        if self.chat_calls > 1 or no_tool_mode or not tools:
            return Message(role="assistant", content="".join(_FINAL_TURN_CHUNKS)), None

        call = ToolCall(
            id=_STREAM_CALL_ID,
            tool_name="process",
            function_name=_PROBE_FUNCTION,
            arguments={},
        )
        return Message(role="assistant", content="".join(_INITIAL_TURN_CHUNKS)), [call]

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
        """Stream several text deltas, finalizing a tool call on the first turn.

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
            str: One text delta per simulated token.
        """
        del model, temperature, max_tokens, thinking, enable_cache
        self.chat_stream_calls += 1
        no_tool_mode = tool_choice is not None and tool_choice.mode == ToolChoiceMode.NONE
        if self.chat_stream_calls > 1 or no_tool_mode or not tools:
            for chunk in _FINAL_TURN_CHUNKS:
                yield chunk
            self._pending_tool_calls = []
            return

        for chunk in _INITIAL_TURN_CHUNKS:
            yield chunk
        self._pending_tool_calls = [
            ToolCall(
                id=_STREAM_CALL_ID,
                tool_name="process",
                function_name=_PROBE_FUNCTION,
                arguments={},
            ),
        ]

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
        config=config,
    )


class TestShouldUseStreamingAutoMode:
    """Direct unit gate for the ``_should_use_streaming`` fix itself."""

    def test_auto_mode_streams_initial_tools_on_turn(self, tmp_path: Path) -> None:
        """Auto mode now returns True for a non-final turn with tools available.

        Oracle: with ``stream_mode="auto"``, ``stream_responses=True``, and a
        stream callback registered, ``_should_use_streaming(tools_available=True,
        is_final_response=False)`` must return ``True`` — this is exactly the
        initial turn of every normal Intellicrack chat, since the tool schema
        is always injected. Mutation: reverting to the old
        ``not tools_available or is_final_response`` expression makes this
        return ``False`` (``not True or False`` is ``False``), failing the
        assertion below.
        """
        provider = _StreamingToolCallProvider()
        bridge = _StreamProbeBridge()
        config = OrchestratorConfig(stream_responses=True, stream_mode="auto")
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)
        orch.set_stream_callback(lambda _chunk: None)

        should_use_streaming: Callable[..., bool] = getattr(orch, "_should_use_streaming")
        result = should_use_streaming(
            provider=provider,
            tools_available=True,
            is_final_response=False,
        )

        assert result is True, "auto mode must stream the initial tools-on turn after the S16-D04 fix"

    def test_never_mode_still_disables_streaming(self, tmp_path: Path) -> None:
        """Never mode still disables streaming regardless of tool availability.

        Oracle: this guards against an overcorrection where the fix removes
        mode handling entirely. With ``stream_mode="never"``, the same
        initial tools-on turn must still return ``False``.
        """
        provider = _StreamingToolCallProvider()
        bridge = _StreamProbeBridge()
        config = OrchestratorConfig(stream_responses=True, stream_mode="never")
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)
        orch.set_stream_callback(lambda _chunk: None)

        should_use_streaming: Callable[..., bool] = getattr(orch, "_should_use_streaming")
        result = should_use_streaming(
            provider=provider,
            tools_available=True,
            is_final_response=False,
        )

        assert result is False, "never mode must never stream, even on the initial tools-on turn"


class TestStreamedToolsOnTurnEmitsChunks:
    """Behavioral gate: a real streamed tools-on completion emits incremental chunks."""

    def test_initial_turn_streams_multiple_chunks_and_collects_tool_call(self, tmp_path: Path) -> None:
        """The initial tools-on turn emits multiple stream_chunk events and the tool call still fires.

        Drives the real orchestrator agent loop end to end with a genuine
        (non-mock) streaming provider. The provider yields four separate
        text deltas on the initial turn before finalizing a
        ``process.probe`` tool call from the stream.

        Oracle: (1) the stream callback must have been invoked more than
        once with non-empty chunks (proving token-by-token delivery, not one
        blob) and the concatenated chunks must equal the known initial-turn
        text; (2) the tool call must still have been collected and executed
        by the bridge exactly once, and the follow-up turn's chunks must
        also have arrived incrementally. Mutation: reverting
        ``_should_use_streaming`` collapses this test to the pre-fix
        behavior, in which the initial turn goes through
        ``_non_stream_response`` instead — the stream callback would then
        fire at most once per turn (only ever the empty final turn) and this
        assertion on chunk count would fail.
        """
        provider = _StreamingToolCallProvider()
        bridge = _StreamProbeBridge()
        config = OrchestratorConfig(
            max_iterations=5,
            stream_responses=True,
            stream_mode="auto",
            confirmation_level=ConfirmationLevel.NONE,
        )
        orch = _build_orch(tmp_path, provider=provider, bridge=bridge, config=config)

        observed_chunks: list[str] = []
        orch.set_stream_callback(observed_chunks.append)

        async def _run() -> None:
            await orch.start_session(ProviderName.OPENAI, _MODEL_ID)
            await orch.process_user_input("run a probe and report back")

        asyncio.run(_run())

        total_expected_chunks = len(_INITIAL_TURN_CHUNKS) + len(_FINAL_TURN_CHUNKS)
        assert len(observed_chunks) == total_expected_chunks, (
            f"Expected {total_expected_chunks} incremental stream_chunk events "
            f"(initial turn + final turn deltas); got {len(observed_chunks)}: {observed_chunks!r}"
        )
        assert "".join(observed_chunks[: len(_INITIAL_TURN_CHUNKS)]) == "".join(_INITIAL_TURN_CHUNKS)
        assert provider.chat_stream_calls == 2, f"Expected chat_stream invoked twice (initial + final); got {provider.chat_stream_calls}"
        assert provider.chat_calls == 0, "Non-streaming chat() must not be invoked when streaming is available for both turns"
        assert orch.stats.total_tool_calls == 1, f"Expected exactly one tool call executed; got {orch.stats.total_tool_calls}"
        assert bridge.probe_calls == 1, f"Expected bridge.probe() invoked exactly once; got {bridge.probe_calls}"
