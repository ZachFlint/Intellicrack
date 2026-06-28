# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""P3-ORCH-SCRIPT: Orchestrator tail operations + ScriptManager gate tests.

Covers orchestrator section-7 tails (shutdown, list_sessions, delete_session,
mid-pipeline error propagation, JSON export/import round-trip) and ScriptManager
section-8 tails (list_scripts, delete_script) with real falsifiable gates.
Every assertion is verified against an independent oracle, never against a value
recomputed by the same production code.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final, Self, override

import pytest

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptManager
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderName,
    ToolDefinition,
)
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path
    from types import TracebackType

    from intellicrack.core.types import ThinkingConfig, ToolCall, ToolChoice


_MODEL_ID: Final[str] = "p3-model"
_DEFAULT_CONTEXT_WINDOW: Final[int] = 32_000
_EXPORT_VERSION: Final[str] = "1.0"


class _FakeProvider(LLMProviderBase):
    """Minimal connected LLM provider for orchestrator gate tests."""

    def __init__(
        self,
        provider_name: ProviderName = ProviderName.OPENAI,
        *,
        context_window: int | None = _DEFAULT_CONTEXT_WINDOW,
        chat_error_message: str | None = None,
    ) -> None:
        """Initialise the fake provider.

        Args:
            provider_name: Provider name to advertise.
            context_window: Context window reported by ``list_models``. ``None``
                means the model entry is omitted.
            chat_error_message: When set, ``chat`` raises a ``RuntimeError``
                with this message so mid-pipeline failure paths can be exercised.
        """
        super().__init__()
        self._provider_name = provider_name
        self._context_window = context_window
        self._chat_error_message = chat_error_message
        self.connected = True

    @property
    @override
    def name(self) -> ProviderName:
        """The configured provider name.

        Returns:
            ProviderName: Configured provider name.
        """
        return self._provider_name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider as connected.

        Args:
            credentials: Unused placeholder credentials.
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return a single model entry with the configured context window.

        Returns:
            list[ModelInfo]: Single-entry list or empty list when no context
                window is configured.
        """
        if self._context_window is None:
            return []
        return [
            ModelInfo(
                id=_MODEL_ID,
                name=_MODEL_ID,
                provider=self._provider_name,
                context_window=self._context_window,
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
        """Return a static response or raise the configured error.

        Args:
            messages: Conversation history.
            model: Model identifier.
            tools: Available tool definitions.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Returns:
            tuple[Message, list[ToolCall] | None]: Static assistant message
                and no tool calls.

        Raises:
            RuntimeError: When ``chat_error_message`` was configured.
        """
        del model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache, messages
        if self._chat_error_message is not None:
            raise RuntimeError(self._chat_error_message)
        return Message(role="assistant", content="p3-response"), None

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
        """Yield the static response content as one chunk.

        Args:
            messages: Conversation history.
            model: Model identifier.
            tools: Available tool definitions.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool selection directive.
            thinking: Extended thinking configuration.
            enable_cache: Whether to enable prompt caching.

        Yields:
            str: Single response chunk.

        Raises:
            RuntimeError: When ``chat_error_message`` was configured.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        if self._chat_error_message is not None:
            raise RuntimeError(self._chat_error_message)
        yield "p3-response"

    @override
    def _convert_tools_to_provider_format(
        self,
        tools: list[ToolDefinition],
    ) -> list[dict[str, object]]:
        """Return an empty tool list.

        Args:
            tools: Tool definitions (ignored).

        Returns:
            list[dict[str, object]]: Empty list.
        """
        del tools
        return []

    @override
    def _convert_messages_to_provider_format(
        self,
        messages: list[Message],
    ) -> list[dict[str, object]]:
        """Return messages as role/content dicts.

        Args:
            messages: Message list to convert.

        Returns:
            list[dict[str, object]]: Passthrough representation.
        """
        return [{"role": m.role, "content": m.content} for m in messages]


class _AutoStopSessionManager:
    """Async context manager that cancels the auto-save task on exit."""

    def __init__(self, manager: SessionManager) -> None:
        """Initialise with the session manager to clean up.

        Args:
            manager: SessionManager whose background task should be stopped.
        """
        self._manager = manager

    async def __aenter__(self) -> Self:
        """Enter the context.

        Returns:
            Self: This instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Cancel the auto-save task on exit.

        Args:
            exc_type: Exception class if raised.
            exc_val: Exception instance if raised.
            exc_tb: Traceback if raised.
        """
        del exc_type, exc_val, exc_tb
        await self._manager.stop_auto_save()


def _build_orchestrator(
    tmp_path: Path,
    *,
    provider: _FakeProvider | None = None,
) -> tuple[Orchestrator, SessionManager]:
    """Construct an orchestrator with isolated dependencies.

    Args:
        tmp_path: Pytest temporary directory for the session database.
        provider: Optional fake provider to register; a fresh default
            instance is created when omitted.

    Returns:
        tuple[Orchestrator, SessionManager]: Constructed orchestrator and
            its underlying session manager.
    """
    fake_provider = provider or _FakeProvider()
    provider_registry = ProviderRegistry()
    provider_registry.register(fake_provider)

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    tool_registry = ToolRegistry(tools_dir=tools_dir)

    db_path = tmp_path / "sessions.db"
    session_manager = SessionManager(
        store=SessionStore(db_path=db_path),
        auto_save=False,
    )

    orchestrator = Orchestrator(
        provider_registry=provider_registry,
        tool_registry=tool_registry,
        session_manager=session_manager,
        config=OrchestratorConfig(stream_responses=False),
    )
    return orchestrator, session_manager


def _make_session_manager(tmp_path: Path) -> SessionManager:
    """Create an isolated SessionManager for store-only tests.

    Args:
        tmp_path: Pytest temporary directory for the session database.

    Returns:
        SessionManager: Fresh session manager with no auto-save.
    """
    db_path = tmp_path / "sessions.db"
    return SessionManager(
        store=SessionStore(db_path=db_path),
        auto_save=False,
    )


@pytest.mark.asyncio
async def test_shutdown_clears_current_session(tmp_path: Path) -> None:
    """Shutdown sets ``_current_session`` to ``None`` and marks shutdown complete.

    Oracle: The exact attribute value ``orchestrator._current_session is None``
    after calling ``shutdown()``. Mutation caught: removing the assignment
    ``self._current_session = None`` from the ``finally`` block in
    ``Orchestrator.shutdown`` (line ~2778 in orchestrator.py).

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    orch, session_manager = _build_orchestrator(tmp_path)
    async with _AutoStopSessionManager(session_manager):
        await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)
        assert orch.current_session is not None

        await orch.shutdown()

        assert orch.current_session is None
        assert orch.shutdown_called is True
        assert orch.shutdown_complete is True


@pytest.mark.asyncio
async def test_list_sessions_returns_exact_ids_and_names(tmp_path: Path) -> None:
    """``list_sessions`` returns exactly the sessions created, with their names.

    Oracle: the set of (id, name) pairs in the list matches exactly what the
    two ``create`` calls returned.  Mutation caught: removing a ``list_all``
    row from the SELECT or returning the wrong session metadata.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    session_manager = _make_session_manager(tmp_path)
    async with _AutoStopSessionManager(session_manager):
        s1 = await session_manager.create(
            provider=ProviderName.OPENAI,
            model=_MODEL_ID,
            name="AlphaSession",
        )
        s2 = await session_manager.create(
            provider=ProviderName.ANTHROPIC,
            model=_MODEL_ID,
            name="BetaSession",
        )

        sessions = session_manager.list_sessions()

        session_ids = {s.id for s in sessions}
        session_names = {s.name for s in sessions}
        assert s1.id in session_ids
        assert s2.id in session_ids
        assert "AlphaSession" in session_names
        assert "BetaSession" in session_names
        assert len(sessions) == 2


@pytest.mark.asyncio
async def test_delete_session_removes_target_leaves_others_intact(tmp_path: Path) -> None:
    """``delete_session`` removes exactly the targeted session; others survive.

    Oracle: after deleting S1, the store returns ``None`` for S1's ID but a
    non-None Session for S2's ID.  Mutation caught: deleting the wrong row or
    deleting both rows.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    session_manager = _make_session_manager(tmp_path)
    async with _AutoStopSessionManager(session_manager):
        s1 = await session_manager.create(
            provider=ProviderName.OPENAI,
            model=_MODEL_ID,
            name="ToDelete",
        )
        s2 = await session_manager.create(
            provider=ProviderName.ANTHROPIC,
            model=_MODEL_ID,
            name="ToKeep",
        )

        deleted = await session_manager.delete(s1.id)

        assert deleted is True

        sessions_after = session_manager.list_sessions()
        ids_after = {s.id for s in sessions_after}
        assert s1.id not in ids_after
        assert s2.id in ids_after
        assert len(sessions_after) == 1
        assert sessions_after[0].name == "ToKeep"

        store_s1 = session_manager.store.load(s1.id)
        assert store_s1 is None

        store_s2 = session_manager.store.load(s2.id)
        assert store_s2 is not None
        assert store_s2.name == "ToKeep"


@pytest.mark.asyncio
async def test_mid_pipeline_error_propagates_exact_type_and_message(
    tmp_path: Path,
) -> None:
    """A RuntimeError raised mid-pipeline propagates with exact type and message.

    Oracle: ``pytest.raises(RuntimeError, match=...)`` where the ``match``
    pattern is the exact string injected into the fake provider.  Mutation
    caught: an except-and-swallow branch inside ``_run_agent_loop`` or
    ``process_user_input`` that absorbs the RuntimeError before it reaches
    the caller.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    error_text = "p3-injected-provider-failure-7f3a"
    failing_provider = _FakeProvider(chat_error_message=error_text)
    orch, session_manager = _build_orchestrator(tmp_path, provider=failing_provider)
    async with _AutoStopSessionManager(session_manager):
        await orch.start_session(provider=ProviderName.OPENAI, model=_MODEL_ID)

        with pytest.raises(RuntimeError, match=error_text):
            await orch.process_user_input("trigger the error")


@pytest.mark.asyncio
async def test_json_export_import_round_trips_exact_session_structure(
    tmp_path: Path,
) -> None:
    """JSON export then import produces a session with the exact same structure.

    Oracle: after importing, the session attributes ``id``, ``name``,
    ``provider``, ``model``, ``notes``, the first message's ``content`` and
    ``role``, and the ``export_version`` JSON key all match the values from the
    original session exactly.  Mutation caught: corrupting any field in
    ``export_to_json`` or ``import_from_json`` (e.g. swapping provider strings
    or dropping the message list during serialisation).

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    session_manager = _make_session_manager(tmp_path)
    async with _AutoStopSessionManager(session_manager):
        session = await session_manager.create(
            provider=ProviderName.OPENAI,
            model="p3-gpt-4o",
            name="RoundTripSession",
        )
        session.notes = "p3-round-trip-notes-unique"
        session.messages.append(
            Message(
                role="user",
                content="p3-unique-message-content",
                timestamp=datetime.now(tz=UTC),
            ),
        )
        await session_manager.update(session)

        export_path = tmp_path / "session_export.json"
        await session_manager.export_json(session.id, export_path)

        with export_path.open(encoding="utf-8") as fh:
            raw: dict[str, object] = json.load(fh)
        assert raw["export_version"] == _EXPORT_VERSION

        imported = await session_manager.import_json(export_path, replace=True)

        assert imported.id == session.id
        assert imported.name == "RoundTripSession"
        assert imported.provider == ProviderName.OPENAI
        assert imported.model == "p3-gpt-4o"
        assert imported.notes == "p3-round-trip-notes-unique"
        assert len(imported.messages) == 1
        assert imported.messages[0].role == "user"
        assert imported.messages[0].content == "p3-unique-message-content"


def test_list_scripts_returns_exact_registered_names(tmp_path: Path) -> None:
    """``list_scripts`` returns exactly the scripts registered with the manager.

    Oracle: ``sorted(mgr.list_scripts())`` equals the sorted list of the two
    specific names added.  Mutation caught: returning an empty list, returning
    an extra entry, or returning the wrong names.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    mgr = ScriptManager(tmp_path)
    alpha = Script(
        name="p3_alpha",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="Alpha script.",
    )
    beta = Script(
        name="p3_beta",
        script_type="frida",
        language=ScriptLanguage.JAVASCRIPT,
        content="console.log(1);",
        description="Beta script.",
    )
    mgr.add_script(alpha, validate=False)
    mgr.add_script(beta, validate=False)

    result = sorted(mgr.list_scripts())

    assert result == ["p3_alpha", "p3_beta"]


def test_delete_script_removes_named_leaves_others_intact(tmp_path: Path) -> None:
    """``delete_script`` removes exactly the named script; others remain.

    Oracle: after deleting ``p3_alpha``, ``list_scripts()`` contains only
    ``p3_beta`` and ``get_script("p3_alpha")`` returns ``None``.  Mutation
    caught: deleting the wrong script or deleting both scripts.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    mgr = ScriptManager(tmp_path)
    alpha = Script(
        name="p3_alpha",
        script_type="python",
        language=ScriptLanguage.PYTHON,
        content="x = 1",
        description="Alpha to delete.",
    )
    beta = Script(
        name="p3_beta",
        script_type="ghidra",
        language=ScriptLanguage.JAVA,
        content="// ghidra",
        description="Beta to keep.",
    )
    mgr.add_script(alpha, validate=False)
    mgr.add_script(beta, validate=False)

    result = mgr.delete_script("p3_alpha")

    assert result is True

    remaining = sorted(mgr.list_scripts())
    assert remaining == ["p3_beta"]
    assert mgr.get_script("p3_alpha") is None
    assert mgr.get_script("p3_beta") is not None

    not_found = mgr.delete_script("p3_alpha")
    assert not_found is False
