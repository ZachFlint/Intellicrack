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
from contextlib import contextmanager
from typing import TYPE_CHECKING, cast, override

import pytest
from PyQt6.QtCore import QSettings, QSignalBlocker, QTimer
from PyQt6.QtWidgets import QPushButton

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BridgeAnalysisSummary, ConfirmationLevel, ProviderName, StringInfo
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import app as app_module
from intellicrack.ui.app import MainWindow
from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtCore import QCoreApplication


_ANALYSIS_STRING_ADDRESS: int = 0x140002100
_ANALYSIS_STRING_VALUE: str = "h1-display-slot-marker"

# A level that is neither the auto-approve override (NONE) nor the value the
# pre-fix code hardcoded for the off state (DESTRUCTIVE), so the off-case
# assertion falsifies a regression back to that hardcode.
_CONFIGURED_LEVEL: ConfirmationLevel = ConfirmationLevel.ALL


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


class _RealPanelHolder:
    """Holder exposing a real ``ToolOutputPanel`` to the GUI-thread slot."""

    def __init__(self, tool_panel: ToolOutputPanel) -> None:
        """Store the panel the slot will mutate.

        Args:
            tool_panel: Real output panel under test.
        """
        self.tool_panel: ToolOutputPanel = tool_panel


def _build_analysis_summary() -> BridgeAnalysisSummary:
    """Build a summary whose fields are individually observable in the panel.

    Returns:
        BridgeAnalysisSummary: Summary carrying one distinctive string row.
    """
    return BridgeAnalysisSummary(
        binary_name="h1-display-slot.exe",
        strings=[
            StringInfo(
                address=_ANALYSIS_STRING_ADDRESS,
                value=_ANALYSIS_STRING_VALUE,
                encoding="ascii",
                section=".rdata",
            ),
        ],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="PE32+",
        architecture="x86_64",
        source_bridges=["rizin"],
        analysis_notes=["h1 display slot gate"],
        complete=True,
    )


class _ConfirmationHolder:
    """Holder exposing ``confirmation_requested`` for the confirmation gate."""

    def __init__(self) -> None:
        """Initialise the emission recorder."""
        self.confirmation_requested: _SignalRecorder = _SignalRecorder()


class _ConfirmationConfigDouble:
    """Config double exposing the ``confirmation_level`` the slot reads."""

    def __init__(self, level: ConfirmationLevel) -> None:
        """Store the configured confirmation level.

        Args:
            level: The level ``_effective_confirmation_level`` returns while the
                auto-approve override is off.
        """
        self.confirmation_level: ConfirmationLevel = level


class _AutoApproveHolder:
    """Holder exposing the attributes ``_apply_restored_auto_approve`` reads.

    ``_apply_restored_auto_approve`` delegates through the real
    ``_apply_confirmation_level`` and ``_effective_confirmation_level`` helpers,
    so the holder binds those production functions rather than restating their
    logic: the gate exercises the same resolution the running window performs.
    """

    _apply_confirmation_level = getattr(MainWindow, "_apply_confirmation_level")
    _effective_confirmation_level = getattr(MainWindow, "_effective_confirmation_level")

    def __init__(self, *, checked: bool) -> None:
        """Build the holder with a real toggle button and a level recorder.

        Args:
            checked: The auto-approve toggle state.
        """
        button = QPushButton()
        button.setCheckable(True)
        button.setChecked(checked)
        self._auto_approve_btn: QPushButton = button
        self._config: _ConfirmationConfigDouble = _ConfirmationConfigDouble(_CONFIGURED_LEVEL)
        self._orchestrator: _OrchestratorLevelRecorder = _OrchestratorLevelRecorder()


def test_h1_callback_only_emits_no_direct_widget_mutation() -> None:
    """H1: the worker-thread callback emits and never touches widgets directly."""
    holder = _AnalysisCallbackHolder()
    getattr(MainWindow, "_on_bridge_analysis_received")(cast("MainWindow", holder), "summary-payload")

    assert holder.bridge_analysis_received.emitted == ["summary-payload"]
    # Pre-fix these were called on the worker thread; post-fix they must not be.
    assert holder.tool_panel.clear_calls == []
    assert holder.tool_panel.display_calls == []


@pytest.mark.usefixtures("qapp")
def test_h1_display_slot_performs_the_tab_update() -> None:
    """H1: the GUI-thread slot renders the summary into the real analysis panel.

    The panel update the worker-thread callback must not perform lives here.
    It is asserted against a real ``ToolOutputPanel`` rather than a recorder,
    so the gate covers the whole route the running application takes: the
    structured ``BridgeAnalysisSummary`` reaches ``BridgeAnalysisPanel``, its
    tables populate, and the Analysis tab is brought to the front.
    """
    panel = ToolOutputPanel()
    try:
        analysis_panel = panel.add_analysis_panel()
        holder = _RealPanelHolder(panel)
        summary = _build_analysis_summary()

        getattr(MainWindow, "_on_bridge_analysis_displayed")(cast("MainWindow", holder), summary)

        assert analysis_panel.get_current_analysis() is summary, "the summary never reached BridgeAnalysisPanel.set_analysis"
        strings_table = analysis_panel._strings_table
        assert strings_table.rowCount() == 1, f"expected one strings row, got {strings_table.rowCount()}"
        value_item = strings_table.item(0, 1)
        assert value_item is not None, "the summary's string row was never inserted into the strings table"
        assert value_item.text() == _ANALYSIS_STRING_VALUE, (
            f"the strings table rendered {value_item.text()!r} instead of the summary's string"
        )
        active_tab = panel.tab_widget.tabText(panel.tab_widget.currentIndex())
        assert active_tab == "Analysis", f"the Analysis tab was not activated; active tab is {active_tab!r}"
    finally:
        panel.close()


def test_confirmation_marshals_via_signal_not_singleshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirmation: dialog is shown via a queued signal, never ``QTimer.singleShot``.

    ``QTimer.singleShot`` on the orchestrator's asyncio-loop thread would never
    fire, hanging the awaiting coroutine.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    single_shot_calls: list[object] = []

    class _QTimerSpy(QTimer):
        """Real ``QTimer`` whose ``singleShot`` records instead of scheduling."""

        @override
        @staticmethod
        def singleShot(*args: object, **kwargs: object) -> None:
            """Record a scheduling attempt.

            Args:
                *args: Positional arguments the caller passed.
                **kwargs: Keyword arguments the caller passed.
            """
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


@pytest.mark.usefixtures("qapp")
def test_m12_apply_restored_auto_approve_sets_level() -> None:
    """M12: the restore helper maps the toggle state to the orchestrator level.

    Auto-approve is an override, not a second setting: a restored ON toggle
    suppresses every prompt (``NONE``), while a restored OFF toggle must hand
    the orchestrator the user's *configured* level rather than a hardcoded
    default. The off-case asserts the configured ``ALL`` flows through, which
    fails if the pre-fix hardcoded ``DESTRUCTIVE`` is ever reintroduced.
    """
    on_holder = _AutoApproveHolder(checked=True)
    getattr(MainWindow, "_apply_restored_auto_approve")(cast("MainWindow", on_holder))
    assert getattr(on_holder, "_orchestrator").levels == [ConfirmationLevel.NONE]

    off_holder = _AutoApproveHolder(checked=False)
    getattr(MainWindow, "_apply_restored_auto_approve")(cast("MainWindow", off_holder))
    assert getattr(off_holder, "_orchestrator").levels == [_CONFIGURED_LEVEL]


@contextmanager
def _redirected_settings_store(store_dir: Path) -> Generator[QSettings]:
    """Point every ``QSettings`` built by production code at a temporary store.

    The window constructs its own ``QSettings("Intellicrack", "MainWindow")``,
    so the only way to drive the restore path from a known state without a
    double is to relocate the backing store. The default format and the
    user-scope search path are switched to an INI file beneath ``store_dir``
    and restored afterwards, leaving the machine's real settings untouched.

    Args:
        store_dir: Directory to hold the temporary INI store.

    Yields:
        QSettings: A handle on the same relocated store the window will read.
    """
    previous_format = QSettings.defaultFormat()
    ini = QSettings.Format.IniFormat
    QSettings.setDefaultFormat(ini)
    QSettings.setPath(ini, QSettings.Scope.UserScope, str(store_dir))
    try:
        yield QSettings("Intellicrack", "MainWindow")
    finally:
        QSettings.setDefaultFormat(previous_format)


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
        MainWindow: The constructed window.
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
) -> None:
    """M12: constructing the window with auto_approve=ON leaves the orchestrator at NONE.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.
    """
    del qapp
    auto_approve_on: bool = True
    with _redirected_settings_store(tmp_path / "settings") as settings:
        settings.setValue("auto_approve", auto_approve_on)
        settings.sync()

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
