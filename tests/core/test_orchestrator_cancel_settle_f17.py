# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for audit F17 -- lingering cancel state after Cancel.

Before the fix, ``Orchestrator.cancel()`` set ``_cancel_event`` unconditionally
and ``process_user_input``'s ``finally`` preserved ``_state == "cancelled"``;
the event was only cleared at the *start* of the next top-level request. Between
a Cancel and the next request, any async operation that consulted the cancel
guard raised ``asyncio.CancelledError`` -- surfacing as a spurious "async
operation cancelled" modal -- and the status bar stuck on "cancelled".

The fix (1) makes ``cancel()`` a no-op that clears any stray flag when nothing
is in flight, and (2) clears ``_cancel_event`` and resets ``_state`` to
``"idle"`` in the request ``finally`` as soon as the operation unwinds.

The tests drive the real ``Orchestrator`` and its real agent loop against a
self-contained real ``LLMProviderBase`` subclass -- no mocked cancellation. The
cancel flag is read reflectively (it has no public accessor) purely to assert
the settled state.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, override

import pytest

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import Message, ModelInfo, ProviderName
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from intellicrack.core.types import (
        ProviderCredentials,
        ThinkingConfig,
        ToolCall,
        ToolChoice,
        ToolDefinition,
    )


_MODEL_ID: str = "f17-model"
_CONTEXT_WINDOW: int = 32_000
_ENTER_TIMEOUT_S: float = 5.0


class _BlockingProvider(LLMProviderBase):
    """Real provider whose ``chat`` suspends until explicitly released.

    Lets a test hold a ``process_user_input`` turn open inside the provider
    call, so the turn can be cancelled while genuinely in flight (state
    ``"processing"``) rather than racing an instant completion.

    Attributes:
        entered: Set once ``chat`` has begun and is about to suspend.
        release: Awaited by ``chat``; the turn resumes when it is set.
        chat_call_count: Number of times ``chat`` ran to completion.
    """

    entered: asyncio.Event
    release: asyncio.Event
    chat_call_count: int

    def __init__(self) -> None:
        """Initialise the provider connected, with entry/release events."""
        super().__init__()
        self.connected = True
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.chat_call_count = 0

    @property
    @override
    def name(self) -> ProviderName:
        """The advertised provider name.

        Returns:
            ProviderName: The OpenAI provider identity.
        """
        return ProviderName.OPENAI

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Unused credentials placeholder.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return a single tool-capable model entry.

        Returns:
            list[ModelInfo]: One model advertising a usable context window.
        """
        return [
            ModelInfo(
                id=_MODEL_ID,
                name=_MODEL_ID,
                provider=ProviderName.OPENAI,
                context_window=_CONTEXT_WINDOW,
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
        """Signal entry, suspend until released, then return a plain reply.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Returns:
            tuple[Message, list[ToolCall] | None]: An assistant reply and no
                tool calls.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.entered.set()
        await self.release.wait()
        self.chat_call_count += 1
        return Message(role="assistant", content="ok"), None

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
        """Yield a single reply chunk after suspending until released.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Yields:
            str: The single reply content chunk.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.entered.set()
        await self.release.wait()
        self.chat_call_count += 1
        yield "ok"

    @override
    def _convert_tools_to_provider_format(self, tools: list[ToolDefinition]) -> list[dict[str, object]]:
        """Return an empty provider tool list.

        Args:
            tools: Tool definitions (unused).

        Returns:
            list[dict[str, object]]: Empty list.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(self, messages: list[Message]) -> list[dict[str, object]]:
        """Return a passthrough role/content representation.

        Args:
            messages: Conversation history.

        Returns:
            list[dict[str, object]]: Role/content dictionaries.
        """
        return [{"role": message.role, "content": message.content} for message in messages]


def _build_orchestrator(tmp_path: Path, provider: _BlockingProvider) -> Orchestrator:
    """Wire an orchestrator around the given provider with a real session store.

    Args:
        tmp_path: Pytest temporary directory for the session DB and tools dir.
        provider: The connected fake provider to register.

    Returns:
        Orchestrator: A non-streaming orchestrator ready to accept a session.
    """
    registry = ProviderRegistry()
    registry.register(provider)
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    session_manager = SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False)
    return Orchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=session_manager,
        config=OrchestratorConfig(stream_responses=False),
    )


def _cancel_flag_set(orch: Orchestrator) -> bool:
    """Read the orchestrator's protected cancel flag reflectively.

    The flag has no public accessor; this reads it only to assert the settled
    cancellation state.

    Args:
        orch: Orchestrator to inspect.

    Returns:
        bool: True if the internal cancel event is currently set.
    """
    event: asyncio.Event = getattr(orch, "_cancel_event")
    return event.is_set()


@pytest.mark.asyncio
async def test_idle_cancel_does_not_arm_flag(tmp_path: Path) -> None:
    """Cancelling while idle must not leave the cancel flag armed.

    Pre-fix, ``cancel()`` set the event unconditionally, so a Cancel clicked
    while nothing was running left the flag set and made the next guarded async
    operation raise a spurious "async operation cancelled". The fixed no-op path
    must leave the flag clear and the state idle.

    Args:
        tmp_path: Pytest temporary directory for the session store.
    """
    orch = _build_orchestrator(tmp_path, _BlockingProvider())

    assert orch.state == "idle"
    await orch.cancel()

    assert not _cancel_flag_set(orch), "idle-time Cancel armed the cancel flag (F17 regression)"
    assert orch.state == "idle"


@pytest.mark.asyncio
async def test_cancelled_turn_settles_state_and_clears_flag(tmp_path: Path) -> None:
    """A cancelled in-flight turn must settle to idle with the flag cleared.

    Holds a real ``process_user_input`` turn open inside the provider, cancels
    the turn while it is genuinely ``"processing"``, then asserts the request
    ``finally`` returned the orchestrator to ``"idle"`` with the cancel flag
    clear -- so a subsequently started operation cannot be aborted by a stale
    flag. Pre-fix the ``finally`` preserved ``"cancelled"``, so the state
    assertion is falsified by reverting the fix.

    Args:
        tmp_path: Pytest temporary directory for the session store.
    """
    provider = _BlockingProvider()
    orch = _build_orchestrator(tmp_path, provider)
    await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)

    turn = asyncio.create_task(orch.process_user_input("hold the line"))
    await asyncio.wait_for(provider.entered.wait(), timeout=_ENTER_TIMEOUT_S)
    assert orch.state == "processing", "turn was not in flight when cancellation was issued"

    turn.cancel()
    with pytest.raises(asyncio.CancelledError):
        await turn

    assert orch.state == "idle", "cancelled turn left the orchestrator stuck (F17 regression)"
    assert not _cancel_flag_set(orch), "cancelled turn left the cancel flag armed (F17 regression)"

    # A subsequent normal turn must run to completion, proving no stale flag
    # aborts it.
    provider.release.set()
    await orch.process_user_input("carry on")
    assert provider.chat_call_count >= 1
    assert orch.state == "idle"
