# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable regression gates for the 2026-07-01 GUI audit app-shell fixes.

Each test fails against the pre-fix ``intellicrack.ui.app`` code path and passes
after remediation:

* H1 - ``_on_bridge_analysis_received`` marshals to the GUI thread and performs
  no direct widget mutation; the tab clear/redisplay lives in the GUI-thread
  slot ``_on_bridge_analysis_displayed``.
* Confirmation - ``_request_tool_confirmation`` shows the dialog by emitting a
  queued signal (``confirmation_requested``) instead of ``QTimer.singleShot``,
  which never fires on the orchestrator's asyncio-loop thread.
* M12 - a restored "Auto-approve: ON" toggle is applied to the orchestrator at
  startup so destructive tool calls are actually auto-approved.
* M13 - the model selection is preserved across Refresh Models by capturing it
  before the combo is cleared.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QSignalBlocker

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ConfirmationLevel, ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import app as app_module
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication


class _ToolPanelRecorder:
    """Records analysis-tab mutations so off-thread calls can be detected."""

    def __init__(self) -> None:
        """Initialise empty call logs."""
        self.clear_calls: list[str] = []
        self.display_calls: list[tuple[str, str]] = []

    def clear_analysis_tab(self, name: str) -> None:
        """Record a clear-tab call.

        Args:
            name: The tab name passed by the caller.
        """
        self.clear_calls.append(name)

    def display_analysis_result(self, name: str, text: str) -> None:
        """Record a display-result call.

        Args:
            name: The tab name passed by the caller.
            text: The text passed by the caller.
        """
        self.display_calls.append((name, text))


class _SignalRecorder:
    """Records ``emit`` payloads in place of a real ``pyqtSignal``."""

    def __init__(self) -> None:
        """Initialise an empty emission log."""
        self.emitted: list[object] = []

    def emit(self, payload: object) -> None:
        """Record an emitted payload.

        Args:
            payload: The value emitted by the caller.
        """
        self.emitted.append(payload)


class _AutoApproveButton:
    """Minimal auto-approve toggle double exposing ``isChecked``."""

    def __init__(self, *, checked: bool) -> None:
        """Store the checked state.

        Args:
            checked: Whether the toggle is checked.
        """
        self._checked = checked

    def isChecked(self) -> bool:  # noqa: N802 - Qt API name
        """Return the toggle state.

        Returns:
            bool: The stored checked state.
        """
        return self._checked


class _OrchestratorLevelRecorder:
    """Records ``set_confirmation_level`` calls."""

    def __init__(self) -> None:
        """Initialise an empty level log."""
        self.levels: list[ConfirmationLevel] = []

    def set_confirmation_level(self, level: ConfirmationLevel) -> None:
        """Record a confirmation-level change.

        Args:
            level: The level passed by the caller.
        """
        self.levels.append(level)


class _AnalysisCallbackHolder:
    """Holder exposing the attributes the bridge-analysis slots read."""

    def __init__(self) -> None:
        """Initialise the recorders."""
        self.tool_panel: _ToolPanelRecorder = _ToolPanelRecorder()
        self.bridge_analysis_received: _SignalRecorder = _SignalRecorder()


class _ConfirmationHolder:
    """Holder exposing ``confirmation_requested`` for the confirmation gate."""

    def __init__(self) -> None:
        """Initialise the emission recorder."""
        self.confirmation_requested: _SignalRecorder = _SignalRecorder()


class _AutoApproveHolder:
    """Holder exposing the attributes ``_apply_restored_auto_approve`` reads."""

    def __init__(self, *, checked: bool) -> None:
        """Build the holder with a toggle double and a level recorder.

        Args:
            checked: The auto-approve toggle state.
        """
        self._auto_approve_btn: _AutoApproveButton = _AutoApproveButton(checked=checked)
        self._orchestrator: _OrchestratorLevelRecorder = _OrchestratorLevelRecorder()


def test_h1_callback_only_emits_no_direct_widget_mutation() -> None:
    """H1: the worker-thread callback emits and never touches widgets directly."""
    holder = _AnalysisCallbackHolder()
    getattr(MainWindow, "_on_bridge_analysis_received")(cast("MainWindow", holder), "summary-payload")

    assert holder.bridge_analysis_received.emitted == ["summary-payload"]
    # Pre-fix these were called on the worker thread; post-fix they must not be.
    assert holder.tool_panel.clear_calls == []
    assert holder.tool_panel.display_calls == []


def test_h1_display_slot_performs_the_tab_update() -> None:
    """H1: the GUI-thread slot performs the clear/redisplay that moved out of the callback."""
    holder = _AnalysisCallbackHolder()
    getattr(MainWindow, "_on_bridge_analysis_displayed")(cast("MainWindow", holder), "summary-payload")

    assert holder.tool_panel.clear_calls == ["analysis"]
    assert holder.tool_panel.display_calls == [("analysis", "summary-payload")]


def test_confirmation_marshals_via_signal_not_singleshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirmation: dialog is shown via a queued signal, never ``QTimer.singleShot``.

    ``QTimer.singleShot`` on the orchestrator's asyncio-loop thread would never
    fire, hanging the awaiting coroutine.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    single_shot_calls: list[object] = []

    class _QTimerSpy:
        @staticmethod
        def singleShot(*args: object, **kwargs: object) -> None:  # noqa: N802 - Qt API name
            single_shot_calls.append((args, kwargs))

    monkeypatch.setattr(app_module, "QTimer", _QTimerSpy)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        holder = _ConfirmationHolder()
        future = getattr(MainWindow, "_request_tool_confirmation")(cast("MainWindow", holder), object())

        assert isinstance(future, asyncio.Future)
        assert not single_shot_calls
        assert len(holder.confirmation_requested.emitted) == 1
        payload = cast("tuple[object, object, object]", holder.confirmation_requested.emitted[0])
        assert isinstance(payload, tuple)
        assert len(payload) == 3
        assert payload[1] is future
        cast("asyncio.Future[bool]", future).cancel()
    finally:
        loop.close()
        asyncio.set_event_loop(None)


def test_m12_apply_restored_auto_approve_sets_level() -> None:
    """M12: the restore helper maps the toggle state to the orchestrator level."""
    on_holder = _AutoApproveHolder(checked=True)
    getattr(MainWindow, "_apply_restored_auto_approve")(cast("MainWindow", on_holder))
    assert getattr(on_holder, "_orchestrator").levels == [ConfirmationLevel.NONE]

    off_holder = _AutoApproveHolder(checked=False)
    getattr(MainWindow, "_apply_restored_auto_approve")(cast("MainWindow", off_holder))
    assert getattr(off_holder, "_orchestrator").levels == [ConfirmationLevel.DESTRUCTIVE]


class _FakeSettings:
    """QSettings double that reports auto-approve as enabled."""

    def __init__(self, *_args: object) -> None:
        """Accept and ignore the organisation/application names."""

    def value(self, key: str, defaultValue: object = None) -> object:  # noqa: N803 - Qt API name
        """Return ``True`` for the auto-approve key, else the default.

        Args:
            key: The settings key requested.
            defaultValue: The fallback value.

        Returns:
            object: ``True`` for ``"auto_approve"`` otherwise ``defaultValue``.
        """
        return True if key == "auto_approve" else defaultValue

    def setValue(self, *_args: object) -> None:  # noqa: N802 - Qt API name
        """Ignore persistence writes."""


def _build_window(tmp_path: Path) -> tuple[MainWindow, Orchestrator]:
    """Construct a real :class:`MainWindow` on temporary registries.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        tuple[MainWindow, Orchestrator]: The window and its orchestrator.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    orch = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )
    return MainWindow(config, orch), orch


@pytest.fixture
def window_factory(qapp: QCoreApplication, tmp_path: Path) -> Generator[MainWindow]:
    """Construct a real :class:`MainWindow` and tear it down afterwards.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Generator[MainWindow]: The constructed window.
    """
    del qapp
    window, _orch = _build_window(tmp_path)
    try:
        yield window
    finally:
        window.close()


def test_m12_restored_on_state_applied_to_orchestrator_at_startup(
    qapp: QCoreApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M12: constructing the window with auto_approve=ON leaves the orchestrator at NONE.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    del qapp
    monkeypatch.setattr(app_module, "QSettings", _FakeSettings)
    window, orch = _build_window(tmp_path)
    try:
        assert getattr(window, "_auto_approve_btn").isChecked() is True
        assert getattr(orch, "_config").confirmation_level == ConfirmationLevel.NONE
    finally:
        window.close()


class _ConnectableSignal:
    """Signal double exposing a no-op ``connect`` for worker wiring."""

    def connect(self, _slot: object) -> None:
        """Ignore the slot connection.

        Args:
            _slot: The slot the caller tried to connect.
        """


class _FakeRefreshWorker:
    """Model-refresh worker double that never starts a real thread."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        """Expose a connectable ``refresh_finished`` signal."""
        self.refresh_finished: _ConnectableSignal = _ConnectableSignal()

    def start(self) -> None:
        """No-op start."""


def _noop_async(*_args: object, **_kwargs: object) -> None:
    """Swallow a ``run_bridge_coroutine_async`` dispatch.

    Args:
        *_args: Ignored positional arguments.
        **_kwargs: Ignored keyword arguments.
    """


def test_m13_model_selection_preserved_across_refresh(
    window_factory: MainWindow,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M13: the selected model survives a Refresh Models cycle.

    Args:
        window_factory: MainWindow fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = window_factory
    monkeypatch.setattr(app_module, "ModelRefreshWorker", _FakeRefreshWorker)
    monkeypatch.setattr(app_module, "run_bridge_coroutine_async", _noop_async)

    # Populating the provider combo must not fire ``_on_provider_changed``,
    # which would open a modal "provider not configured" dialog and hang the
    # headless run; the behaviour under test is the model-combo restore.
    provider_combo = getattr(window, "_provider_combo")
    with QSignalBlocker(provider_combo):
        provider_combo.clear()
        provider_combo.addItem("Anthropic", ProviderName.ANTHROPIC)
        provider_combo.setCurrentIndex(0)

    with QSignalBlocker(window.model_combo):
        window.model_combo.clear()
        window.model_combo.addItems(["claude-x", "gpt-4o"])
        window.model_combo.setCurrentText("gpt-4o")

    getattr(window, "_on_refresh_models")()
    assert getattr(window, "_pending_model_restore") == "gpt-4o"
    assert window.model_combo.count() == 0

    # Order chosen so a broken restore would leave index 0 ("claude-x").
    getattr(window, "_on_models_refresh_finished")(success=True, models=["claude-x", "gpt-4o"], message="")
    assert window.model_combo.currentText() == "gpt-4o"
