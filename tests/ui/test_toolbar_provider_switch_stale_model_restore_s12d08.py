# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S12-D08 (toolbar provider switch, stale model restore).

Switching the toolbar's provider combo while the discovery cache is COLD for
the newly selected provider fell through ``_on_provider_changed`` to
``_on_refresh_models``. That method captured ``model_combo.currentText()`` as
the restore target -- at that instant the combo still displayed the OUTGOING
provider's model id. When the refresh completed, ``_on_models_refresh_finished``
restored that stale id via ``setCurrentText`` (the combo is editable), which
is indistinguishable from a user manually typing a custom model id. The
line edit's committed-text handler then logged
``model_combo_text_not_in_catalog`` and emitted a user-visible
"not present in provider catalog" warning for a value the user never typed.

The fix threads the target provider through the refresh (``provider_switch``)
so the restore target is the NEW provider's own remembered model
(:meth:`MainWindow._remembered_model_for`), reusing the same per-provider
memory the already-correct warm-cache fast path relies on
(:meth:`MainWindow._select_model_for_provider`), instead of the stale combo
text.

This test drives the real :class:`MainWindow` over a real
:class:`Orchestrator` and real, self-contained :class:`LLMProviderBase`
subclasses -- no mocked provider calls or asserted-on mocks -- through the
actual COLD-cache slow path (``ModelDiscovery`` with an empty cache), and
observes the outcome through the real ``status_update`` Qt signal and the
real ``structlog`` pipeline (not by asserting on a mock).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, override

import pytest
from PyQt6.QtCore import QSettings, QSignalBlocker

from intellicrack.core.config import Config, LogConfig
from intellicrack.core.logging import setup_logging
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import Message, ModelInfo, ProviderCredentials, ProviderName
from intellicrack.providers.base import LLMProviderBase
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import app as app_module
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
_TEST_ORG = "IntellicrackTest"
_TEST_APP = "ToolbarProviderSwitchStaleModelRestore"


def _make_test_settings(*_args: object) -> QSettings:
    """Return a ``QSettings`` bound to the isolated test store.

    Substituted for ``intellicrack.ui.app.QSettings`` so every settings access
    inside ``MainWindow`` -- regardless of the organisation/application names
    it passes -- resolves to the same temporary store the test can seed.

    Args:
        *_args: The organisation/application names the caller passed
            (ignored).

    Returns:
        QSettings: A settings instance for the isolated test store.
    """
    return QSettings(_TEST_ORG, _TEST_APP)


class _CatalogProvider(LLMProviderBase):
    """Real, connectable provider exposing a fixed, ordered model catalog.

    Only ``list_models`` is exercised by this test; ``chat``/``chat_stream``
    are implemented for interface completeness but never invoked.
    """

    def __init__(self, provider_name: ProviderName, model_ids: list[str]) -> None:
        """Initialize the provider with its identity and model catalog.

        Args:
            provider_name: The provider identity this instance reports.
            model_ids: Model ids this provider's catalog advertises, in the
                order ``list_models`` returns them.
        """
        super().__init__()
        self._name = provider_name
        self._model_ids = model_ids

    @property
    @override
    def name(self) -> ProviderName:
        """The configured provider identity.

        Returns:
            ProviderName: The configured provider identity.
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
        """Return this provider's fixed model catalog.

        Returns:
            list[ModelInfo]: One entry per configured model id, each with a
            usable context window.
        """
        return [
            ModelInfo(
                id=model_id,
                name=model_id,
                provider=self._name,
                context_window=_CONTEXT_WINDOW,
                supports_tools=True,
                supports_vision=False,
                supports_streaming=True,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            )
            for model_id in self._model_ids
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
        """Return a real, non-empty assistant reply (unexercised by this test).

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
            tuple[Message, list[ToolCall] | None]: A reply identifying the
                provider/model that produced it, and no tool calls.
        """
        del messages, tools, temperature, max_tokens, tool_choice, thinking, enable_cache
        return Message(role="assistant", content=f"reply from {self._name.value}:{model}"), None

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
        """Yield a single reply chunk (unexercised by this test).

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
        yield f"reply from {self._name.value}:{model}"

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


@pytest.fixture
def persist_settings(monkeypatch: pytest.MonkeyPatch) -> QSettings:
    """Isolate ``MainWindow`` settings access to a cleared temporary store.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        QSettings: The cleared test store, for direct seeding.
    """
    store = QSettings(_TEST_ORG, _TEST_APP)
    store.clear()
    store.sync()
    monkeypatch.setattr(app_module, "QSettings", _make_test_settings)
    return store


@pytest.fixture
def window_factory(
    qapp: QApplication,
    tmp_path: Path,
    persist_settings: QSettings,
) -> Iterator[Callable[[list[LLMProviderBase]], MainWindow]]:
    """Yield a factory building a real MainWindow around given providers.

    Args:
        qapp: Qt application fixture (ensures Qt is initialised first).
        tmp_path: Pytest temporary directory fixture.
        persist_settings: Cleared, isolated ``QSettings`` store (ensures the
            factory never touches the real per-user settings store).

    Yields:
        Callable[[list[LLMProviderBase]], MainWindow]: Factory that
        registers and connects the given real providers on a real
        ``Orchestrator`` (streaming disabled) and returns a real, unshown
        ``MainWindow`` wired to a COLD, empty ``ModelDiscovery`` cache.
        Every window built by the factory is closed on teardown.
    """
    del qapp
    _ = persist_settings
    created: list[MainWindow] = []

    def _build(providers: list[LLMProviderBase]) -> MainWindow:
        """Construct a real, fully-wired MainWindow around ``providers``.

        Args:
            providers: Real provider instances to register and connect on
                the orchestrator's provider registry before the window is
                returned.

        Returns:
            MainWindow: The constructed window, with an empty (COLD)
            ``ModelDiscovery`` cache wired in.
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
        orchestrator = Orchestrator(
            provider_registry=registry,
            tool_registry=ToolRegistry(tools_dir=tools_dir),
            session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db"), auto_save=False),
            config=OrchestratorConfig(stream_responses=False),
        )
        window = MainWindow(config, orchestrator)
        window.set_model_discovery(ModelDiscovery(registry))
        # Prevent the 250ms-delayed startup discovery timer from racing the
        # test's own provider-switch cold-path exercise: it would populate
        # the "COLD" cache out from under the assertions below.
        window._initial_discovery_triggered = True
        created.append(window)
        return window

    yield _build

    for window in created:
        window.close()


def _configure_logging(log_dir: Path) -> Path:
    """Wire real structlog JSON-Lines logging into ``log_dir``.

    Args:
        log_dir: Directory to receive ``intellicrack.log``.

    Returns:
        Path: The active log file path.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(
        LogConfig(
            level="DEBUG",
            file_enabled=True,
            console_enabled=False,
            json_file=True,
            max_file_size_mb=10,
            backup_count=1,
            retention_days=1,
        ),
        log_dir=log_dir,
    )
    return log_dir / "intellicrack.log"


def _read_log_events(log_file: Path) -> list[str]:
    """Parse JSON-Lines log records and return their ``event`` field.

    Args:
        log_file: Path to the JSON-Lines log file.

    Returns:
        list[str]: The ``event`` value of every parsed record, in file order.
    """
    for handler in logging.getLogger().handlers:
        handler.flush()
    events: list[str] = []
    if not log_file.exists():
        return events
    for line in log_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        event = record.get("event")
        if isinstance(event, str):
            events.append(event)
    return events


def test_cold_cache_provider_switch_restores_new_provider_model(
    window_factory: Callable[[list[LLMProviderBase]], MainWindow],
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    """Switching providers on a COLD discovery cache must not inject a stale id.

    Two providers are connected, each with its own model catalog and its own
    remembered model persisted from an earlier session. The toolbar starts on
    provider A showing A's remembered model. Switching to provider B forces
    the COLD-cache slow path (``_on_refresh_models`` via
    ``_on_provider_changed``) because ``ModelDiscovery``'s cache starts empty
    for every provider.

    Before the fix, the slow path captured A's model text as the restore
    target and reinjected it as free text once B's catalog loaded -- a value
    absent from B's catalog -- which the line edit's commit handler then
    flagged as a not-in-catalog warning. After the fix, the restore target is
    B's own remembered model, so the resulting selection belongs to B's
    catalog and committing it raises no warning.

    Args:
        window_factory: Factory yielding a real, auto-closed MainWindow with
            a COLD ``ModelDiscovery`` cache.
        qtbot: pytest-qt bot fixture driving the Qt event loop while the
            background refresh worker and persistent bridge loop deliver
            results.
        tmp_path: Pytest temporary directory fixture, used for the isolated
            log file.
    """
    log_file = _configure_logging(tmp_path / "logs")

    provider_a = _CatalogProvider(ProviderName.OPENAI, ["model-a1", "model-a2"])
    provider_b = _CatalogProvider(ProviderName.ANTHROPIC, ["model-b1", "model-b2"])

    settings = QSettings(_TEST_ORG, _TEST_APP)
    settings.setValue("last_model/openai", "model-a1")
    settings.setValue("last_model/anthropic", "model-b2")
    settings.sync()

    window = window_factory([provider_a, provider_b])

    idx_a = window._provider_combo.findData(ProviderName.OPENAI)
    assert idx_a >= 0
    with QSignalBlocker(window._provider_combo):
        window._provider_combo.setCurrentIndex(idx_a)
    with QSignalBlocker(window.model_combo):
        window.model_combo.clear()
        window.model_combo.addItems(["model-a1", "model-a2"])
        window.model_combo.setCurrentText("model-a1")

    assert window.model_discovery is not None
    assert window.model_discovery.cache.get(ProviderName.ANTHROPIC) is None, "cache must start COLD for provider B"

    idx_b = window._provider_combo.findData(ProviderName.ANTHROPIC)
    assert idx_b >= 0
    window._provider_combo.setCurrentIndex(idx_b)

    qtbot.waitUntil(lambda: window.model_combo.count() > 0, timeout=_WAIT_TIMEOUT_MS)
    qtbot.waitUntil(lambda: bool(window.model_combo.currentText()), timeout=_WAIT_TIMEOUT_MS)
    qtbot.waitUntil(window.model_combo.isEnabled, timeout=_WAIT_TIMEOUT_MS)

    restored_model = window.model_combo.currentText()
    assert restored_model in {"model-b1", "model-b2"}, (
        f"provider switch must restore a model from provider B's own catalog, got {restored_model!r} "
        "(the pre-fix defect restores the OUTGOING provider's stale model id as free text)"
    )
    assert restored_model == "model-b2", (
        "the restore target must be provider B's own remembered model (last_model/anthropic), "
        f"not the outgoing provider A's stale combo text; got {restored_model!r}"
    )

    status_recorder: list[str] = []
    window.status_update.connect(status_recorder.append)

    window._on_model_combo_text_committed()

    catalog_warnings = [msg for msg in status_recorder if "not present in provider catalog" in msg]
    assert not catalog_warnings, f"committing the restored model must not raise a not-in-catalog warning: {catalog_warnings}"

    log_events = _read_log_events(log_file)
    assert "model_combo_text_not_in_catalog" not in log_events, (
        f"a stale provider-switch restore must not log model_combo_text_not_in_catalog; events={log_events}"
    )
