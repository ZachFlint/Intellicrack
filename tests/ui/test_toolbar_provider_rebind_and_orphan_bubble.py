# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the toolbar provider rebind, the orphan bubble, and the duplicate assistant bubble.

Toolbar rebind: a Provider/Model switch on the toolbar after the first message must affect the
subsequent completions. ``MainWindow._on_send`` must consult the toolbar selection on every turn,
not only while no session exists, and ``_ensure_active_session`` must not return early on a
session that is already active, so a later toolbar switch is never ignored until "New Session".

Orphan bubble: a turn's ``add_streaming_message()`` placeholder bubble must not stay empty when
the completion never streamed. The real reply arrives as a separate bubble through
``message_received`` -> ``add_message``, which would leave an orphan empty "Intellicrack" bubble
above the user's message on every turn.

Duplicate assistant bubble: on a turn whose text streams, the completed ``response`` message that
the orchestrator's agent loop appends and fires through ``message_received`` must not reach
``ChatPanel.add_message``, because that would duplicate the content ``_on_stream_chunk`` already
rendered into a live streaming bubble. ``MainWindow._on_message_received`` folds the completed
message into that bubble via ``ChatPanel.finalize_streaming_message`` instead of appending a
second one.

All three tests drive the real :class:`MainWindow` over a real :class:`Orchestrator` and real,
self-contained :class:`LLMProviderBase` subclasses -- no mocked provider calls or asserted-on
mocks. The toolbar and orphan-bubble tests disable streaming on the orchestrator config to exercise
the non-streaming completion path described above; the duplicate-bubble test forces streaming on
to exercise the streamed completion path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, override

import pytest

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import Message, ModelInfo, ProviderCredentials
from intellicrack.providers import ids as provider_ids
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot

    from intellicrack.core.types import ThinkingConfig, ToolCall, ToolChoice, ToolDefinition


_CONTEXT_WINDOW: int = 32_000
_WAIT_TIMEOUT_MS: int = 5_000


class _RecordingProvider(LLMProviderBase):
    """Real, connectable provider that records every model id it completes.

    ``self.calls`` collects the model identifiers passed to
    ``chat``/``chat_stream``, in call order -- the outbound request the
    orchestrator actually sent.
    """

    def __init__(self, provider_name: str, model_id: str) -> None:
        """Initialize the provider with its identity and advertised model.

        Args:
            provider_name: The provider identity this instance reports.
            model_id: The single model id this provider advertises and
                accepts completions for.
        """
        super().__init__()
        self._name = provider_name
        self._model_id = model_id
        self.calls: list[str] = []

    @property
    @override
    def name(self) -> str:
        """The configured provider identity.

        Returns:
            str: The configured provider identity.
        """
        return self._name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Provider credentials (accepted, not validated).
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return this provider's single advertised model.

        Returns:
            list[ModelInfo]: One model entry with a usable context window.
        """
        return [
            ModelInfo(
                id=self._model_id,
                name=self._model_id,
                provider=self._name,
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
        """Record ``model`` and return a real, non-empty assistant reply.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator -- the value
                under test.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Returns:
            tuple[Message, list[ToolCall] | None]: A reply identifying the
                provider/model that produced it, and no tool calls.
        """
        del messages, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.calls.append(model)
        return Message(role="assistant", content=f"reply from {self._name}:{model}"), None

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
        """Record ``model`` and yield a single reply chunk.

        Not exercised while ``OrchestratorConfig.stream_responses`` is
        ``False``, but implemented for interface completeness.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Yields:
            str: A single reply chunk identifying the provider/model.
        """
        del messages, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.calls.append(model)
        yield f"reply from {self._name}:{model}"

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


_STREAM_CHUNKS: Final[tuple[str, ...]] = ("Streaming ", "reply ", "chunks", ".")


class _StreamingProvider(LLMProviderBase):
    """Real, connectable provider whose ``chat_stream`` yields several deltas.

    Used to drive a genuine streamed turn end to end through the real ``ChatPanel`` and
    ``MainWindow`` signal wiring, so the duplicate assistant-bubble question is checked against
    actual application code rather than a mocked chat panel.
    """

    def __init__(self, provider_name: str, model_id: str) -> None:
        """Initialize the provider with its identity and advertised model.

        Args:
            provider_name: The provider identity this instance reports.
            model_id: The single model id this provider advertises and
                accepts completions for.
        """
        super().__init__()
        self._name = provider_name
        self._model_id = model_id
        self.chat_stream_calls: int = 0

    @property
    @override
    def name(self) -> str:
        """The configured provider identity.

        Returns:
            str: The configured provider identity.
        """
        return self._name

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Mark the provider connected.

        Args:
            credentials: Provider credentials (accepted, not validated).
        """
        self._credentials = credentials
        self.connected = True

    @override
    async def list_models(self) -> list[ModelInfo]:
        """Return this provider's single advertised model.

        Returns:
            list[ModelInfo]: One model entry with a usable context window.
        """
        return [
            ModelInfo(
                id=self._model_id,
                name=self._model_id,
                provider=self._name,
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
        """Return the concatenated stream text as a real non-streaming fallback.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Returns:
            tuple[Message, list[ToolCall] | None]: The full reply text and
                no tool calls.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        return Message(role="assistant", content="".join(_STREAM_CHUNKS)), None

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
        """Yield several real text deltas whose concatenation is the full reply.

        Args:
            messages: Conversation history forwarded by the orchestrator.
            model: Model id forwarded by the orchestrator.
            tools: Tool definitions forwarded by the orchestrator.
            temperature: Sampling temperature.
            max_tokens: Maximum response tokens.
            tool_choice: Tool-selection directive.
            thinking: Extended-thinking configuration.
            enable_cache: Whether prompt caching is enabled.

        Yields:
            str: One text delta per simulated token.
        """
        del messages, model, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        self.chat_stream_calls += 1
        for chunk in _STREAM_CHUNKS:
            yield chunk

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


def _build_window(
    tmp_path: Path,
    providers: list[LLMProviderBase],
    *,
    stream_responses: bool,
) -> MainWindow:
    """Construct a real, fully-wired MainWindow around ``providers``.

    Args:
        tmp_path: Pytest temporary directory to root the window's config,
            tool registry, and session store under.
        providers: Real provider instances to register and connect on the
            orchestrator's provider registry before the window is returned.
        stream_responses: Whether the orchestrator streams LLM responses.
            ``stream_mode`` is forced to ``"always"`` when this is ``True``
            so the streamed path is exercised deterministically regardless
            of tool availability, and left at the orchestrator's default
            (``"auto"``) otherwise.

    Returns:
        MainWindow: The constructed window.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    registry = ProviderRegistry()
    for provider in providers:
        registry.register(provider)
        run_bridge_coroutine(
            registry.connect_provider(
                provider.name,
                ProviderCredentials(api_key="test-key-not-a-secret"),  # pragma: allowlist secret
            ),
        )
    orchestrator_config = (
        OrchestratorConfig(stream_responses=True, stream_mode="always") if stream_responses else OrchestratorConfig(stream_responses=False)
    )
    orchestrator = Orchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
        config=orchestrator_config,
    )
    return MainWindow(config, orchestrator)


@pytest.fixture
def window_factory(
    qapp: QApplication,
    tmp_path: Path,
) -> Iterator[Callable[[list[LLMProviderBase]], MainWindow]]:
    """Yield a factory building a real, non-streaming MainWindow around given providers.

    Args:
        qapp: Qt application fixture (ensures Qt is initialised first).
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Callable[[list[LLMProviderBase]], MainWindow]: Factory that
        registers and connects the given real providers on a real
        ``Orchestrator`` (streaming disabled) and returns a real, unshown
        ``MainWindow`` wired to it. Every window built by the factory is
        closed on teardown.
    """
    del qapp
    created: list[MainWindow] = []

    def _build(providers: list[LLMProviderBase]) -> MainWindow:
        window = _build_window(tmp_path, providers, stream_responses=False)
        created.append(window)
        return window

    yield _build

    for window in created:
        window.close()


@pytest.fixture
def streaming_window_factory(
    qapp: QApplication,
    tmp_path: Path,
) -> Iterator[Callable[[list[LLMProviderBase]], MainWindow]]:
    """Yield a factory building a real, streaming-enabled MainWindow.

    Args:
        qapp: Qt application fixture (ensures Qt is initialised first).
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Callable[[list[LLMProviderBase]], MainWindow]: Factory that
        registers and connects the given real providers on a real
        ``Orchestrator`` (streaming forced on via ``stream_mode="always"``)
        and returns a real, unshown ``MainWindow`` wired to it. Every window
        built by the factory is closed on teardown.
    """
    del qapp
    created: list[MainWindow] = []

    def _build(providers: list[LLMProviderBase]) -> MainWindow:
        window = _build_window(tmp_path, providers, stream_responses=True)
        created.append(window)
        return window

    yield _build

    for window in created:
        window.close()


def test_toolbar_model_switch_rebinds_active_session(
    window_factory: Callable[[list[LLMProviderBase]], MainWindow],
    qtbot: QtBot,
) -> None:
    """Switching the toolbar Provider/Model must retarget the next completion.

    With two connected providers, the first send binds the session to provider A / model A.
    the session to provider A / model A. Switching the toolbar to provider B
    / model B and sending again must route the second completion to provider
    B with model B on the *same* session -- a rebind, not a new session.
    A regression here would be ``_ensure_active_session`` early-returning whenever a session already
    exists, so the second send silently keeps hitting provider A with model A.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        qtbot: pytest-qt bot fixture driving the Qt event loop while the
            persistent bridge loop delivers async results.
    """
    provider_a = _RecordingProvider(provider_ids.OPENAI, "model-a")
    provider_b = _RecordingProvider(provider_ids.ANTHROPIC, "model-b")
    window = window_factory([provider_a, provider_b])

    idx_a = window._provider_combo.findData(provider_ids.OPENAI)
    assert idx_a >= 0
    window._provider_combo.setCurrentIndex(idx_a)
    window.model_combo.setCurrentText("model-a")

    window._chat_panel.message_submitted.emit("first message")
    qtbot.waitUntil(lambda: len(provider_a.calls) == 1, timeout=_WAIT_TIMEOUT_MS)

    session = window._orchestrator.current_session
    assert session is not None, "first send did not create a session"
    session_id = session.id
    assert provider_a.calls == ["model-a"]
    assert provider_b.calls == []
    assert session.provider == provider_ids.OPENAI
    assert session.model == "model-a"

    idx_b = window._provider_combo.findData(provider_ids.ANTHROPIC)
    assert idx_b >= 0
    window._provider_combo.setCurrentIndex(idx_b)
    window.model_combo.setCurrentText("model-b")

    window._chat_panel.message_submitted.emit("second message")
    qtbot.waitUntil(lambda: len(provider_b.calls) == 1, timeout=_WAIT_TIMEOUT_MS)

    assert provider_b.calls == ["model-b"], "second send did not route to the newly selected provider/model"
    assert provider_a.calls == ["model-a"], "second send incorrectly re-hit the original provider (S16-D01 regression)"

    rebound_session = window._orchestrator.current_session
    assert rebound_session is not None
    assert rebound_session.id == session_id, "toolbar switch started a new session instead of rebinding the active one"
    assert rebound_session.provider == provider_ids.ANTHROPIC
    assert rebound_session.model == "model-b"


def test_non_stream_completion_leaves_single_assistant_bubble(
    window_factory: Callable[[list[LLMProviderBase]], MainWindow],
    qtbot: QtBot,
) -> None:
    """A non-streaming completion must leave exactly one assistant bubble.

    ``_on_user_message`` must not leave an empty streaming placeholder bubble behind for a send via
    ``add_streaming_message()`` when the non-streaming completion path never fills it. The real reply
    arrives as a second, separate bubble via ``message_received`` -> ``add_message``, and that would
    leave an empty orphan "Intellicrack" bubble ahead of the user's own message on every turn.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow.
        qtbot: pytest-qt bot fixture driving the Qt event loop while the
            persistent bridge loop delivers async results.
    """
    provider = _RecordingProvider(provider_ids.OPENAI, "solo-model")
    window = window_factory([provider])

    idx = window._provider_combo.findData(provider_ids.OPENAI)
    assert idx >= 0
    window._provider_combo.setCurrentIndex(idx)
    window.model_combo.setCurrentText("solo-model")

    window._chat_panel.message_submitted.emit("hello there")
    qtbot.waitUntil(lambda: len(provider.calls) == 1, timeout=_WAIT_TIMEOUT_MS)
    qtbot.waitUntil(lambda: len(window._chat_panel.get_messages()) >= 2, timeout=_WAIT_TIMEOUT_MS)

    messages = window._chat_panel.get_messages()
    roles = [message.role for message in messages]
    assert len(messages) == 2, f"expected exactly 2 chat bubbles (user + assistant), got {len(messages)}: {roles}"
    assert roles == ["user", "assistant"], f"an orphan bubble was left ahead of the user message: {roles}"
    assert messages[1].content == "reply from openai:solo-model", "assistant bubble does not carry the real reply content"


def test_streamed_completion_leaves_single_assistant_bubble(
    streaming_window_factory: Callable[[list[LLMProviderBase]], MainWindow],
    qtbot: QtBot,
) -> None:
    """A streamed completion must leave exactly one assistant bubble, not two.

    The streamed reply must not be duplicated. ``_on_stream_chunk`` lazily creates a streaming bubble
    via ``ChatPanel.add_streaming_message()`` and renders the reply into it chunk by chunk, while the
    orchestrator's agent loop also appends the completed ``response`` message and fires it through
    ``message_received`` once the stream finishes. ``message_received`` must not be wired directly to
    ``ChatPanel.add_message``, which builds a brand-new bubble for that same content and would turn
    every streamed turn into two assistant bubbles. ``MainWindow._on_message_received`` folds the
    completed message into the already-rendered streaming bubble via
    ``ChatPanel.finalize_streaming_message``, so exactly one assistant bubble remains, carrying the
    full streamed text.

    Args:
        streaming_window_factory: Factory yielding a real, auto-closed
            MainWindow with streaming forced on.
        qtbot: pytest-qt bot fixture driving the Qt event loop while the
            persistent bridge loop delivers async results.
    """
    provider = _StreamingProvider(provider_ids.OPENAI, "stream-model")
    window = streaming_window_factory([provider])

    idx = window._provider_combo.findData(provider_ids.OPENAI)
    assert idx >= 0
    window._provider_combo.setCurrentIndex(idx)
    window.model_combo.setCurrentText("stream-model")

    window._chat_panel.message_submitted.emit("stream this")
    qtbot.waitUntil(lambda: provider.chat_stream_calls == 1, timeout=_WAIT_TIMEOUT_MS)
    qtbot.waitUntil(
        lambda: len(window._chat_panel.get_messages()) >= 2 and window._stream_append is None,
        timeout=_WAIT_TIMEOUT_MS,
    )

    messages = window._chat_panel.get_messages()
    roles = [message.role for message in messages]
    assert len(messages) == 2, (
        f"expected exactly 2 chat bubbles (user + assistant) for a streamed turn, got {len(messages)}: {roles} "
        "-- a streamed turn produced a duplicate assistant bubble"
    )
    assert roles == ["user", "assistant"], roles
    assert messages[1].content == "".join(_STREAM_CHUNKS), "assistant bubble content diverged from the streamed text"
