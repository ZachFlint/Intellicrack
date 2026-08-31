# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for the session-persistence behaviour of ``MainWindow``.

Two user-facing behaviours are covered:

* Layout restore is opt-in. ``ui.restore_layout`` defaults to ``False`` (reset
  the GUI each launch); ``_restore_window_state`` must be a no-op in that mode
  and must restore the saved tab layout when the toggle is enabled.
* Provider/model selection persists per-provider in ``QSettings``.
  ``_persist_current_model`` records the toolbar selection,
  ``_select_model_for_provider`` prefers the remembered model over the
  provider's configured default, and ``_startup_provider`` re-activates the
  remembered provider when it is still connected.

Each test drives the real ``MainWindow`` against a temporary ``QSettings``
store so a regression in the persistence wiring fails the gate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSettings, QSignalBlocker

from intellicrack.core.config import Config, UIConfig
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import app as app_module
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from pathlib import Path


_TEST_ORG = "IntellicrackTest"
_TEST_APP = "LayoutModelPersist"


def _make_test_settings(*_args: object) -> QSettings:
    """Return a ``QSettings`` bound to the isolated test store.

    Substituted for ``intellicrack.ui.app.QSettings`` so every settings access
    inside ``MainWindow`` -- regardless of the organisation/application names it
    passes -- resolves to the same temporary store the tests can seed and
    inspect.

    Args:
        *_args: The organisation/application names the caller passed (ignored).

    Returns:
        QSettings: A settings instance for the test store.
    """
    return QSettings(_TEST_ORG, _TEST_APP)


class _RestoreRecorder:
    """Callable that records every ``restore_tab_state`` invocation."""

    def __init__(self) -> None:
        """Initialise the empty capture log."""
        self.states: list[dict[str, object]] = []

    def __call__(self, state: dict[str, object]) -> None:
        """Record one restore call.

        Args:
            state: The tab-state mapping passed by ``_restore_window_state``.
        """
        self.states.append(state)


@pytest.fixture
def persist_settings(monkeypatch: pytest.MonkeyPatch) -> QSettings:
    """Isolate ``MainWindow`` settings access to a cleared temporary store.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        QSettings: The cleared test store, for direct seeding and assertions.
    """
    store = QSettings(_TEST_ORG, _TEST_APP)
    store.clear()
    store.sync()
    monkeypatch.setattr(app_module, "QSettings", _make_test_settings)
    return store


def _build_window(tmp_path: Path, *, restore_layout: bool = False) -> MainWindow:
    """Construct a real :class:`MainWindow` on temporary registries.

    Args:
        tmp_path: Pytest temporary directory.
        restore_layout: Value for ``ui.restore_layout`` on the window's config.

    Returns:
        MainWindow: The constructed window.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
        ui=UIConfig(restore_layout=restore_layout),
    )
    orch = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    return MainWindow(config, orch)


def _select_provider(window: MainWindow, provider: ProviderName) -> None:
    """Make ``provider`` current in the toolbar combo without firing handlers.

    Args:
        window: The window whose provider combo to update.
        provider: The provider to select.
    """
    combo = getattr(window, "_provider_combo")
    idx = combo.findData(provider)
    assert idx >= 0, f"provider combo is missing {provider.value}"
    with QSignalBlocker(combo):
        combo.setCurrentIndex(idx)


class TestLayoutRestoreToggle:
    """``_restore_window_state`` honours the ``ui.restore_layout`` toggle."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_reset_mode_skips_restore(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        persist_settings: QSettings,
    ) -> None:
        """Verify saved tabs are NOT restored when restore_layout is False.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
            persist_settings: Cleared temporary settings store.
        """
        window = _build_window(tmp_path, restore_layout=False)
        try:
            recorder = _RestoreRecorder()
            monkeypatch.setattr(window.tool_panel, "restore_tab_state", recorder)

            persist_settings.setValue("tab_state/tab_names", ["Frida"])
            persist_settings.setValue("tab_state/active_index", 0)
            persist_settings.sync()

            getattr(window, "_restore_window_state")()

            assert recorder.states == []
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_enabled_mode_restores_saved_tabs(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        persist_settings: QSettings,
    ) -> None:
        """Verify the saved tab layout is restored when restore_layout is True.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
            persist_settings: Cleared temporary settings store.
        """
        # Build against the empty store first so the constructor's restore is a
        # no-op; the real restore would try to open a bridge-backed Frida tab.
        window = _build_window(tmp_path, restore_layout=True)
        try:
            recorder = _RestoreRecorder()
            monkeypatch.setattr(window.tool_panel, "restore_tab_state", recorder)

            persist_settings.setValue("tab_state/tab_names", ["Frida"])
            persist_settings.setValue("tab_state/active_index", 0)
            persist_settings.sync()

            getattr(window, "_restore_window_state")()

            assert len(recorder.states) == 1
            restored_names = recorder.states[0]["tab_names"]
            assert isinstance(restored_names, list)
            assert restored_names == ["Frida"]
        finally:
            window.close()


class TestModelPersistence:
    """Provider/model selection persists per-provider in QSettings."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_persist_records_provider_and_model(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify _persist_current_model stores the model keyed by provider.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        window = _build_window(tmp_path)
        try:
            _select_provider(window, ProviderName.ANTHROPIC)
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.addItems(["claude-x", "claude-y"])
                window.model_combo.setCurrentText("claude-y")

            getattr(window, "_persist_current_model")()

            assert getattr(MainWindow, "_remembered_model_for")(ProviderName.ANTHROPIC) == "claude-y"
            assert getattr(MainWindow, "_remembered_provider")() == ProviderName.ANTHROPIC
            assert persist_settings.value("last_model/anthropic") == "claude-y"
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_activated_signal_persists_selection(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify the model combo's ``activated`` signal is wired to persistence.

        A user dropdown pick emits ``activated``; the toolbar wiring must route
        that to ``_persist_current_model`` so the choice is stored. Emitting the
        signal exercises the real ``connect`` rather than calling the slot
        directly, so a broken connection fails this gate.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        _ = persist_settings
        window = _build_window(tmp_path)
        try:
            _select_provider(window, ProviderName.ANTHROPIC)
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.addItems(["claude-x", "claude-y"])
                window.model_combo.setCurrentIndex(1)

            window.model_combo.activated.emit(1)

            assert getattr(MainWindow, "_remembered_model_for")(ProviderName.ANTHROPIC) == "claude-y"
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_memory_is_per_provider(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify each provider retains its own last-used model independently.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        _ = persist_settings
        window = _build_window(tmp_path)
        try:
            _select_provider(window, ProviderName.ANTHROPIC)
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.setCurrentText("claude-y")
            getattr(window, "_persist_current_model")()

            _select_provider(window, ProviderName.OPENAI)
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.setCurrentText("gpt-4o")
            getattr(window, "_persist_current_model")()

            assert getattr(MainWindow, "_remembered_model_for")(ProviderName.ANTHROPIC) == "claude-y"
            assert getattr(MainWindow, "_remembered_model_for")(ProviderName.OPENAI) == "gpt-4o"
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_empty_model_is_not_persisted(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify a blank model field does not overwrite the stored model.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        window = _build_window(tmp_path)
        try:
            _select_provider(window, ProviderName.ANTHROPIC)
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.setCurrentText("claude-y")
            getattr(window, "_persist_current_model")()

            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.setCurrentText("")
            getattr(window, "_persist_current_model")()

            assert getattr(MainWindow, "_remembered_model_for")(ProviderName.ANTHROPIC) == "claude-y"
            _ = persist_settings
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_select_prefers_remembered_over_default(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify _select_model_for_provider restores the remembered model.

        The remembered model is at index 1, so a regression that falls back to
        the configured-default index (0) selects the wrong entry and fails.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        persist_settings.setValue("last_model/anthropic", "claude-y")
        persist_settings.sync()

        window = _build_window(tmp_path)
        try:
            models = ["claude-x", "claude-y"]
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.addItems(models)
                getattr(window, "_select_model_for_provider")(ProviderName.ANTHROPIC, models)

            assert window.model_combo.currentText() == "claude-y"
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_select_falls_back_to_first_without_memory(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify _select_model_for_provider uses index 0 with nothing stored.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        _ = persist_settings
        window = _build_window(tmp_path)
        try:
            models = ["claude-x", "claude-y"]
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.addItems(models)
                getattr(window, "_select_model_for_provider")(ProviderName.ANTHROPIC, models)

            assert window.model_combo.currentText() == "claude-x"
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_select_honors_remembered_absent_from_catalog(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify a remembered custom model id survives a catalog it is not in.

        The editable combo must display the remembered id even when the freshly
        discovered catalog no longer lists it, so a custom selection persists
        until the user changes it.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        persist_settings.setValue("last_model/anthropic", "org/custom-model")
        persist_settings.sync()

        window = _build_window(tmp_path)
        try:
            models = ["claude-x", "claude-y"]
            with QSignalBlocker(window.model_combo):
                window.model_combo.clear()
                window.model_combo.addItems(models)
                getattr(window, "_select_model_for_provider")(ProviderName.ANTHROPIC, models)

            assert window.model_combo.currentText() == "org/custom-model"
        finally:
            window.close()


class TestStartupProviderChoice:
    """``_startup_provider`` prefers the remembered provider when connected."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_prefers_remembered_when_connected(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify the remembered provider wins over the first connected one.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        persist_settings.setValue("last_provider", "openai")
        persist_settings.sync()

        window = _build_window(tmp_path)
        try:
            connected = [ProviderName.ANTHROPIC, ProviderName.OPENAI, ProviderName.GOOGLE]
            chosen = getattr(window, "_startup_provider")(connected)
            assert chosen == ProviderName.OPENAI
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_falls_back_when_remembered_not_connected(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify fallback to the first connected provider when memory is stale.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        persist_settings.setValue("last_provider", "grok")
        persist_settings.sync()

        window = _build_window(tmp_path)
        try:
            connected = [ProviderName.ANTHROPIC, ProviderName.OPENAI]
            chosen = getattr(window, "_startup_provider")(connected)
            assert chosen == ProviderName.ANTHROPIC
        finally:
            window.close()

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_falls_back_without_memory(
        tmp_path: Path,
        persist_settings: QSettings,
    ) -> None:
        """Verify fallback to the first connected provider with nothing stored.

        Args:
            tmp_path: Pytest temporary directory.
            persist_settings: Cleared temporary settings store.
        """
        _ = persist_settings
        window = _build_window(tmp_path)
        try:
            connected = [ProviderName.GOOGLE, ProviderName.ANTHROPIC]
            chosen = getattr(window, "_startup_provider")(connected)
            assert chosen == ProviderName.GOOGLE
        finally:
            window.close()
