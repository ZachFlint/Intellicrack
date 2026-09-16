# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""MainWindow gates: saved provider settings take effect without a restart.

Drives the real :class:`MainWindow` slots over a real :class:`Orchestrator` and
:class:`ProviderRegistry`, real provider classes, and a loopback provider
endpoint server that accepts a single API key. They fail when:

* accepting Provider Settings skips a provider that is not in the registry --
  for example one that could not be constructed at startup -- instead of
  constructing it from its registered class and connecting it;
* the saved timeout is not applied when Provider Settings reconnects a provider;
* one provider's rejected reconnect aborts the reconnect of every provider after it;
* the toolbar "Refresh Models" for an unconnected provider ignores the base URL
  saved in ``.env`` and queries the provider's default endpoint instead.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QSignalBlocker, QThread
from PyQt6.QtWidgets import QComboBox

from intellicrack.core.config import Config, get_env_file
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderName
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui.app import MainWindow
from tests._helpers.provider_endpoint_server import OPENAI_COMPATIBLE_MODELS_PATH, ProviderEndpointServer
from tests._helpers.provider_state import isolate_provider_environment, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication
    from pytestqt.qtbot import QtBot


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_ACCEPTED_KEY = "loopback-accepted-" + ("k" * 24)
_MODEL_ID = "loopback-model"
_CONNECT_TIMEOUT_MS = 15_000
_WORKER_JOIN_TIMEOUT_MS = 60_000


@pytest.fixture
def gateway() -> Iterator[ProviderEndpointServer]:
    """Provide a loopback provider endpoint server.

    Yields:
        ProviderEndpointServer: The running server.
    """
    with ProviderEndpointServer(accepted_key=_ACCEPTED_KEY, model_ids=[_MODEL_ID]) as server:
        yield server


@pytest.fixture
def window_factory(
    qapp: QCoreApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[[], MainWindow]]:
    """Yield a factory building real windows over a redirected state root.

    Teardown joins each window's model-refresh thread before closing the
    window: a gate that fails while a refresh is still running must report the
    failure rather than destroy a running ``QThread``, which aborts the process.

    Args:
        qapp: Qt application fixture.
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Callable[[], MainWindow]: Factory constructing a fresh window.
    """
    del qapp
    isolate_provider_environment(monkeypatch)
    created: list[MainWindow] = []
    with redirected_state_root(monkeypatch, tmp_path / "state"):

        def _build() -> MainWindow:
            tools_dir = tmp_path / "tools"
            tools_dir.mkdir(parents=True, exist_ok=True)
            config = Config(tools_directory=tools_dir, logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
            orchestrator = Orchestrator(
                provider_registry=ProviderRegistry(),
                tool_registry=ToolRegistry(tools_dir=tools_dir),
                session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
            )
            window = MainWindow(config, orchestrator)
            created.append(window)
            return window

        try:
            yield _build
        finally:
            for window in created:
                worker: object = getattr(window, "model_refresh_worker", None)
                if isinstance(worker, QThread):
                    assert worker.wait(_WORKER_JOIN_TIMEOUT_MS), "the model refresh thread did not finish"
                window.close()


def _registry(window: MainWindow) -> ProviderRegistry:
    """Return the window's provider registry.

    Args:
        window: The window under test.

    Returns:
        ProviderRegistry: The live registry.
    """
    return cast("ProviderRegistry", getattr(getattr(window, "_orchestrator"), "provider_registry"))


def _apply_provider_settings(window: MainWindow, settings: dict[str, dict[str, object]]) -> None:
    """Invoke the slot that applies accepted Provider Settings.

    Args:
        window: The window under test.
        settings: Settings exactly as ``ProviderConfigDialog.get_settings`` returns them.
    """
    cast("Callable[[dict[str, dict[str, object]]], None]", getattr(window, "_apply_provider_settings"))(settings)


def _is_connected(registry: ProviderRegistry, name: ProviderName) -> bool:
    """Report whether a registered provider is connected.

    Args:
        registry: The provider registry.
        name: The provider.

    Returns:
        bool: True when the provider is registered and connected.
    """
    provider = registry.get(name)
    return provider is not None and provider.is_connected


def _dialog_settings(*, api_key: str, api_base: str, timeout_seconds: int | None) -> dict[str, object]:
    """Build one provider's settings in the shape the Provider Settings dialog produces.

    Args:
        api_key: API key field value.
        api_base: Base URL field value.
        timeout_seconds: Timeout control value, ``None`` for the provider default.

    Returns:
        dict[str, object]: The provider's settings.
    """
    return {
        "enabled": True,
        "api_key": api_key,
        "default_model": "",
        "timeout_seconds": timeout_seconds,
        "max_retries": 3,
        "api_base": api_base,
        "organization_id": "",
    }


def test_accepting_settings_constructs_and_connects_a_provider_missing_from_the_registry(
    window_factory: Callable[[], MainWindow],
    gateway: ProviderEndpointServer,
    qtbot: QtBot,
) -> None:
    """A provider known only by its class is constructed, connected and given the saved timeout.

    Args:
        window_factory: Factory yielding real windows.
        gateway: Loopback server fixture.
        qtbot: pytest-qt bot.
    """
    window = window_factory()
    registry = _registry(window)
    registry.register_class(ProviderName.OPENAI, OpenAIProvider)
    assert registry.get(ProviderName.OPENAI) is None

    _apply_provider_settings(
        window,
        {"openai": _dialog_settings(api_key=_ACCEPTED_KEY, api_base=gateway.openai_compatible_base_url, timeout_seconds=44)},
    )

    qtbot.waitUntil(lambda: _is_connected(registry, ProviderName.OPENAI), timeout=_CONNECT_TIMEOUT_MS)
    probe = gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)[-1]
    assert probe.headers["authorization"] == f"Bearer {_ACCEPTED_KEY}"
    assert probe.headers["x-stainless-read-timeout"] == "44.0"


def test_rejected_reconnect_does_not_block_the_next_provider(
    window_factory: Callable[[], MainWindow],
    gateway: ProviderEndpointServer,
    qtbot: QtBot,
) -> None:
    """OpenAI's rejected key does not stop OpenRouter, listed after it, from reconnecting.

    Args:
        window_factory: Factory yielding real windows.
        gateway: Loopback server fixture.
        qtbot: pytest-qt bot.
    """
    window = window_factory()
    registry = _registry(window)
    registry.register(OpenAIProvider())
    registry.register(OpenRouterProvider())

    _apply_provider_settings(
        window,
        {
            "openai": _dialog_settings(api_key=f"sk-{'w' * 48}", api_base=gateway.openai_compatible_base_url, timeout_seconds=None),
            "openrouter": _dialog_settings(api_key=_ACCEPTED_KEY, api_base=gateway.openai_compatible_base_url, timeout_seconds=None),
        },
    )

    qtbot.waitUntil(lambda: _is_connected(registry, ProviderName.OPENROUTER), timeout=_CONNECT_TIMEOUT_MS)
    assert not _is_connected(registry, ProviderName.OPENAI)
    authorizations = [request.headers["authorization"] for request in gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)]
    assert authorizations == [f"Bearer sk-{'w' * 48}", f"Bearer {_ACCEPTED_KEY}"]


def test_toolbar_refresh_uses_saved_base_url_for_an_unconnected_provider(
    window_factory: Callable[[], MainWindow],
    gateway: ProviderEndpointServer,
    qtbot: QtBot,
) -> None:
    """Refresh Models for a disconnected OpenAI lists the gateway's models from the saved base URL.

    Args:
        window_factory: Factory yielding real windows.
        gateway: Loopback server fixture.
        qtbot: pytest-qt bot.
    """
    window = window_factory()
    _ = get_env_file().write_text(
        f'OPENAI_API_KEY={_ACCEPTED_KEY}\nOPENAI_API_BASE="{gateway.openai_compatible_base_url}"\n',
        encoding="utf-8",
    )
    provider_combo: object = getattr(window, "_provider_combo")
    assert isinstance(provider_combo, QComboBox)
    index = provider_combo.findData(ProviderName.OPENAI)
    assert index >= 0
    with QSignalBlocker(provider_combo):
        provider_combo.setCurrentIndex(index)

    cast("Callable[[], None]", getattr(window, "_on_refresh_models"))()

    qtbot.waitUntil(lambda: window.model_combo.findText(_MODEL_ID) >= 0, timeout=_CONNECT_TIMEOUT_MS)
    assert gateway.requests(OPENAI_COMPATIBLE_MODELS_PATH)[-1].headers["authorization"] == f"Bearer {_ACCEPTED_KEY}"
