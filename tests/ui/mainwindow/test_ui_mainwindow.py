# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 U5 ui-mainwindow fixes.

Each test exercises one finding from audit5.md (ui-app-core) and is designed
to fail against the unfixed code path and pass after the corresponding
remediation in :mod:`intellicrack.ui.app` and :mod:`intellicrack.ui.xpu_status`.

Findings covered:

* F-0002 - "Save Patched Binary..." now resolves the hex editor through
  :meth:`ToolOutputPanel.get_embedded_tool` instead of ``get_panel``.
* F-0003 - Sandbox panel "active widget" lookup now goes through
  :meth:`ToolOutputPanel.get_panel` instead of ``get_active_tool_widget``.
* F-0004 - ``XPUStatusDialog`` is wired into the Help menu via the
  ``XPU Status...`` action triggering :meth:`MainWindow._on_xpu_status`.
* F-0006 - ``_on_view_scripts`` surfaces the script panel state through the
  application status bar.
* F-0007 / F-0008 - "Tool Status..." and "Configure Tools..." both flow the
  live tool registry to their dialogs and wire the dialog signals.
* F-0009 - ``_on_open_sandbox`` no longer constructs a throwaway
  ``SandboxConfigDialog`` purely to call ``is_sandbox_available``.
* F-0010 - ``_apply_provider_settings`` disconnects providers the user has
  disabled, in addition to reconnecting enabled ones.
* F-0011..F-0019 - Orphan signals on PreferencesDialog,
  SessionManagerDialog, ProviderConfigDialog, ModelSelectionDialog,
  SandboxConfigDialog, SandboxMonitorWidget, ToolConfigDialog,
  ToolSettingsWidget, and ToolOutputPanel are now wired to MainWindow slots.
* F-0023 - ``_on_browse_models_result`` constructs ``ModelSelectionDialog``
  with the active provider's name and discovery context.
* F-0025 - ``_on_provider_changed`` calls
  :meth:`ProviderRegistry.set_active` for connected providers.
* F-0026 - ``_refresh_system_status`` stops the periodic status timer after
  a configurable threshold of consecutive failures and reports through the
  status bar.
"""

from __future__ import annotations

import asyncio
import os
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTabWidget,
    QWidget,
)

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ModelInfo, ProviderError, ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import (
    app as app_module,
    preferences as preferences_module,
)
from intellicrack.ui.app import MainWindow
from intellicrack.ui.provider_config import (
    ModelSelectionDialog,
    ProviderConfigDialog,
)
from intellicrack.ui.sandbox_config import (
    SandboxConfigDialog,
    SandboxMonitorWidget,
)
from intellicrack.ui.session_manager import SessionManagerDialog
from intellicrack.ui.tool_config import ToolConfigDialog, ToolSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtCore import QCoreApplication
    from PyQt6.QtGui import QAction


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Return the singleton :class:`QApplication` for widget tests.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


def _no_exec(_self: object) -> int:
    """Stand in for a dialog's blocking modal ``exec``.

    Args:
        _self: The dialog instance (unused).

    Returns:
        int: Always ``0`` (``QDialog.DialogCode.Rejected``), so the slot's
        ``if dialog.exec():`` acceptance branch is skipped while the live
        ``.connect`` wiring established before ``exec`` is preserved.
    """
    return 0


# ---------------------------------------------------------------------------
# Helper widgets / doubles - intentionally minimal to avoid heavy bridging
# ---------------------------------------------------------------------------


class _RecordingHexPanel(QWidget):
    """Hex panel double recording ``save`` / ``save_as`` invocations."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize counters.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.save_called: int = 0
        self.save_as_called: int = 0

    def save(self) -> None:
        """Record a synchronous save."""
        self.save_called += 1

    def save_as(self) -> None:
        """Record a "save as" invocation."""
        self.save_as_called += 1


class _StubToolPanel(QWidget):
    """Lightweight surrogate for :class:`ToolOutputPanel`.

    Exposes only the accessors and dicts that the slots-under-test use,
    so we can drive ``MainWindow._on_save_patched_binary`` and other
    methods directly without spinning up the full panel tree.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the stub panel and its accessor dicts.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self.embedded_tools: dict[str, QWidget] = {}
        self.panels: dict[str, QWidget] = {}
        self.tab_widget = QTabWidget(self)

    def get_embedded_tool(self, tool_id: str) -> QWidget | None:
        """Return the embedded-tool widget registered under ``tool_id``.

        Args:
            tool_id: Embedded tool identifier.

        Returns:
            QWidget | None: The widget or ``None`` if absent.
        """
        return self.embedded_tools.get(tool_id.lower())

    def get_panel(self, panel_id: str) -> QWidget | None:
        """Return the panel widget registered under ``panel_id``.

        Args:
            panel_id: Panel identifier.

        Returns:
            QWidget | None: The widget or ``None`` if absent.
        """
        return self.panels.get(panel_id.lower())


class _DummyHolder:
    """Simple namespace used to drive bound-method-style slots.

    Slot methods on :class:`MainWindow` access only a few well-defined
    attributes (``tool_panel``, ``status_update``, ``_orchestrator`` and so
    on). Tests construct one of these with the minimum surface needed for
    the slot under test.

    All attributes that any slot reads are declared here with explicit types
    so that basedpyright can verify attribute assignments and accesses.
    ``current_binary`` is provided with a realistic path because
    :meth:`MainWindow._on_save_patched_binary` logs ``self.current_binary``
    before resolving the hex editor.
    """

    def __init__(self) -> None:
        """Initialise all attributes the slots-under-test may read."""
        self.current_binary: Path | None = Path("C:/targets/sample.exe")
        self.tool_panel: object = None
        self.status_update: _StatusEmissionRecorder = _StatusEmissionRecorder()
        self._provider_combo: _ProviderComboDouble | None = None
        self._orchestrator: object = None
        self._shutting_down: bool = False
        self._status_failure_count: int = 0
        self._status_refresh_in_flight: bool = False
        self._status_timer: _TimerDouble | None = None
        self.status_label: _StatusLabelDouble | None = None
        self._refresh_memory_status: object = None
        self._refresh_model_discovery_status: object = None

    @classmethod
    def for_save_binary(cls, stub_panel: object) -> _DummyHolder:
        """Create a holder for ``_on_save_patched_binary`` tests.

        Args:
            stub_panel: The stub tool panel.

        Returns:
            _DummyHolder: Holder with ``tool_panel`` set.
        """
        obj = cls()
        obj.tool_panel = stub_panel
        return obj

    @classmethod
    def for_view_scripts(cls, tool_panel: object, recorder: _StatusEmissionRecorder) -> _DummyHolder:
        """Create a holder for ``_on_view_scripts`` tests.

        Args:
            tool_panel: The stub tool panel.
            recorder: Status recorder.

        Returns:
            _DummyHolder: Holder with ``tool_panel`` and ``status_update`` set.
        """
        obj = cls()
        obj.tool_panel = tool_panel
        obj.status_update = recorder
        return obj

    @classmethod
    def for_provider_changed(
        cls,
        combo: _ProviderComboDouble,
        orchestrator: object,
        recorder: _StatusEmissionRecorder,
    ) -> _DummyHolder:
        """Create a holder for ``_on_provider_changed`` tests.

        Args:
            combo: Provider combo.
            orchestrator: Orchestrator double.
            recorder: Status recorder.

        Returns:
            _DummyHolder: Holder ready for provider-change slot invocations.
        """
        obj = cls()
        obj._provider_combo = combo
        obj._orchestrator = orchestrator
        obj.status_update = recorder
        return obj

    @classmethod
    def for_refresh_status(cls, failure_count: int, orchestrator: object) -> _DummyHolder:
        """Create a holder for ``_refresh_system_status`` tests.

        Args:
            failure_count: Initial ``_status_failure_count``.
            orchestrator: Orchestrator double.

        Returns:
            _DummyHolder: Holder ready for refresh-status slot invocations.
        """
        obj = cls()
        obj._shutting_down = False
        obj._orchestrator = orchestrator
        obj._status_failure_count = failure_count
        obj._status_timer = _TimerDouble()
        obj.status_label = _StatusLabelDouble()
        obj.status_update = _StatusEmissionRecorder()
        obj._refresh_memory_status = lambda: None
        obj._refresh_model_discovery_status = lambda: None
        return obj

    def get_failure_count(self) -> int:
        """Return ``_status_failure_count`` (public accessor for test assertions).

        Returns:
            int: Current failure count.
        """
        return self._status_failure_count

    def get_timer(self) -> _TimerDouble | None:
        """Return ``_status_timer`` (public accessor for test assertions).

        Returns:
            _TimerDouble | None: The timer double.
        """
        return self._status_timer

    def get_label(self) -> _StatusLabelDouble | None:
        """Return ``status_label`` (public accessor for test assertions).

        Returns:
            _StatusLabelDouble | None: The label double.
        """
        return self.status_label

    def _on_system_status_fetched(self, _result: object) -> None:
        """No-op success slot referenced by ``_refresh_system_status`` dispatch.

        Args:
            _result: The status payload (ignored by the dispatch gate).
        """

    def _on_system_status_error(self, _exc: object) -> None:
        """No-op error slot referenced by ``_refresh_system_status`` dispatch.

        Args:
            _exc: The error object (ignored by the dispatch gate).
        """


class _RecordingMessageBoxInfo:
    """Records :class:`QMessageBox.information` calls."""

    def __init__(self) -> None:
        """Initialise an empty call list."""
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self,
        _parent: QWidget,
        title: str,
        body: str,
        *_args: object,
        **_kwargs: object,
    ) -> int:
        """Record an information() call.

        Args:
            _parent: Parent widget passed by the caller (unused).
            title: Dialog title.
            body: Dialog body.
            *_args: Forwarded positional args.
            **_kwargs: Forwarded keyword args.

        Returns:
            int: Always the value of ``QMessageBox.StandardButton.Ok``.
        """
        self.calls.append((title, body))
        return int(QMessageBox.StandardButton.Ok)


class _StatusEmissionRecorder:
    """Records ``status_update`` emissions for assertion."""

    def __init__(self) -> None:
        """Initialise an empty emission list."""
        self.emissions: list[str] = []

    def emit(self, value: str) -> None:
        """Record an emission.

        Args:
            value: The status string emitted by the slot under test.
        """
        self.emissions.append(value)


class _NoopSignal:
    """Minimal Qt-signal surrogate that accepts :meth:`connect` calls.

    The production MainWindow slots call ``dialog.some_signal.connect(handler)``
    immediately after constructing a dialog.  Recording-stub dialogs need this
    attribute to exist as a callable with a ``connect`` method; they do not need
    to propagate the signal for the subset of tests that only verify constructor
    kwargs.
    """

    def connect(self, _handler: object) -> None:
        """Accept and discard a signal-handler connection.

        Args:
            _handler: The handler the caller wants to connect (unused).
        """


# ---------------------------------------------------------------------------
# F-0002 - Save Patched Binary resolves through embedded_tools
# ---------------------------------------------------------------------------


class TestSavePatchedBinaryFindsHexEditor:
    """``_on_save_patched_binary`` reaches the hex editor via embedded_tools."""

    @staticmethod
    def test_save_as_invoked_from_embedded_tools(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Pre-fix: pulled from ``panels`` (empty) and showed "No hex editor"; post-fix: pulled from ``embedded_tools``.

        Args:
            qapp: Qt application fixture (singleton).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        recording = _RecordingHexPanel()
        stub_panel = _StubToolPanel()
        stub_panel.embedded_tools["hex_editor"] = recording

        recorder = _RecordingMessageBoxInfo()
        monkeypatch.setattr(QMessageBox, "information", recorder)

        holder = _DummyHolder()
        holder.tool_panel = stub_panel
        getattr(MainWindow, "_on_save_patched_binary")(cast("MainWindow", holder))

        assert recording.save_as_called == 1
        assert recording.save_called == 0
        assert recorder.calls == []

    @staticmethod
    def test_no_hex_editor_yields_information_dialog(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When no hex editor is registered the user sees the "no hex editor" dialog.

        Args:
            qapp: Qt application fixture (singleton).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        stub_panel = _StubToolPanel()
        recorder = _RecordingMessageBoxInfo()
        monkeypatch.setattr(QMessageBox, "information", recorder)

        holder = _DummyHolder()
        holder.tool_panel = stub_panel
        getattr(MainWindow, "_on_save_patched_binary")(cast("MainWindow", holder))

        assert len(recorder.calls) == 1
        assert recorder.calls[0][0] == "Save"
        assert "No hex editor" in recorder.calls[0][1]


# ---------------------------------------------------------------------------
# F-0003 - sandbox lookup uses get_panel
# ---------------------------------------------------------------------------


class TestSandboxPanelLookupUsesPanels:
    """``_on_open_sandbox_panel`` resolves the sandbox widget via ``get_panel("sandbox")``."""

    @staticmethod
    def test_get_panel_called_with_sandbox_key(
        qapp: QCoreApplication,
    ) -> None:
        """``_on_open_sandbox_panel`` calls ``tool_panel.get_panel("sandbox")`` at runtime.

        The pre-fix code called ``get_active_tool_widget("sandbox")`` (a removed
        API); the post-fix code calls ``get_panel("sandbox")``.  This test
        exercises the live call path: a stub :class:`ToolPanel` records every
        ``get_panel`` invocation, and the test asserts that ``"sandbox"`` was
        actually requested.  A broken implementation that silently no-ops or
        calls the old API never writes ``"sandbox"`` to the ledger and fails here.

        Args:
            qapp: Qt application fixture (singleton).
        """
        del qapp

        get_panel_calls: list[str] = []

        class _StartablePanel(QWidget):
            """Stub sandbox panel widget exposing a ``start_tool`` method."""

            def start_tool(self) -> None:
                """No-op tool start."""

        class _RecordingPanel(QWidget):
            """Stub ToolPanel that records ``get_panel`` invocations."""

            def add_sandbox_tab(self) -> QWidget:
                """Return a stub panel widget for the sandbox tab.

                Returns:
                    QWidget: A minimal widget satisfying the slot's expectations.
                """
                return _StartablePanel()

            def get_panel(self, panel_id: str) -> QWidget | None:
                """Record the requested panel id and return ``None``.

                Args:
                    panel_id: The panel identifier the slot requests.

                Returns:
                    QWidget | None: Always ``None`` so the logging branch is skipped.
                """
                get_panel_calls.append(panel_id)
                return None

            @staticmethod
            def wire_sandbox_bridge(_bridge: object) -> None:
                """Accept a bridge and discard it.

                Args:
                    _bridge: The SandboxBridge instance (unused in this test).
                """

            @staticmethod
            def get_sandbox_bridge() -> None:
                """Return ``None`` (no sandbox bridge registered in this stub)."""

        class _SandboxHolder:
            tool_panel: _RecordingPanel = _RecordingPanel()

            @staticmethod
            def _get_or_create_sandbox_bridge() -> object:
                """Return a minimal bridge sentinel.

                Returns:
                    object: A plain object standing in for the real SandboxBridge.
                """
                return object()

            @staticmethod
            def _wire_sandbox_monitor_widgets(_widget: object) -> None:
                """Accept and discard the sandbox widget.

                Args:
                    _widget: Widget passed by ``_on_open_sandbox_panel``.
                """

        holder = _SandboxHolder()
        getattr(MainWindow, "_on_open_sandbox_panel")(cast("MainWindow", holder))

        assert "sandbox" in get_panel_calls, f"expected get_panel('sandbox') to be called; recorded calls: {get_panel_calls}"


# ---------------------------------------------------------------------------
# F-0004 - XPUStatusDialog wired into Help menu
# ---------------------------------------------------------------------------


class TestXPUStatusMenuWiring:
    """The Help menu exposes an action that opens :class:`XPUStatusDialog`."""

    @staticmethod
    def test_xpu_status_slot_constructs_dialog(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_xpu_status`` instantiates :class:`XPUStatusDialog` and execs it.

        Args:
            qapp: Qt application fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp

        construct_count: list[int] = []
        exec_count: list[int] = []

        class _RecordingXPUDialog(QDialog):
            def __init__(self, parent: QWidget | None = None) -> None:
                """Construct the recording double.

                Args:
                    parent: Parent widget.
                """
                super().__init__(parent)
                construct_count.append(len(construct_count))

            def exec(self) -> int:
                """Record the exec invocation.

                Returns:
                    int: Always zero.
                """
                exec_count.append(len(exec_count))
                return 0

        monkeypatch.setattr(app_module, "XPUStatusDialog", _RecordingXPUDialog)

        holder = QMainWindow()
        try:
            getattr(MainWindow, "_on_xpu_status")(cast("MainWindow", holder))
        finally:
            holder.close()

        assert len(construct_count) == 1
        assert len(exec_count) == 1


# ---------------------------------------------------------------------------
# F-0006 - _on_view_scripts surfaces script state through status bar
# ---------------------------------------------------------------------------


class _ScriptToolPanelWithDraft:
    """ToolPanel double that simulates an in-progress script."""

    def __init__(self) -> None:
        """Initialise the activation counter."""
        self.activated: int = 0

    def activate_scripts_tab(self) -> None:
        """Record an activation."""
        self.activated += 1

    def get_script_panel_state(
        self,
    ) -> tuple[str | None, tuple[str, str, str] | None]:
        """Return a state with a draft script.

        Returns:
            tuple[str | None, tuple[str, str, str] | None]: Selected ID and draft script.
        """
        return ("script-42", ("hello.py", "python", "print('hi')"))


class _ScriptToolPanelEmpty:
    """ToolPanel double that has no selected script and no draft."""

    @staticmethod
    def activate_scripts_tab() -> None:
        """No-op to satisfy the slot's call."""

    @staticmethod
    def get_script_panel_state() -> tuple[str | None, tuple[str, str, str] | None]:
        """Return an empty state.

        Returns:
            tuple[str | None, tuple[str, str, str] | None]: Empty state.
        """
        return (None, None)


class TestViewScriptsSurfacesState:
    """``_on_view_scripts`` propagates script panel state to the status bar."""

    @staticmethod
    def test_view_scripts_emits_status_with_script_name(qapp: QCoreApplication) -> None:
        """An active draft script is reported through ``status_update`` emit.

        Args:
            qapp: Qt application fixture.
        """
        del qapp
        recorder = _StatusEmissionRecorder()
        tool_panel = _ScriptToolPanelWithDraft()
        holder = _DummyHolder()
        holder.tool_panel = tool_panel
        holder.status_update = recorder
        getattr(MainWindow, "_on_view_scripts")(cast("MainWindow", holder))

        assert tool_panel.activated == 1
        assert any("hello.py" in msg for msg in recorder.emissions)

    @staticmethod
    def test_view_scripts_emits_no_selection_when_empty(qapp: QCoreApplication) -> None:
        """The "no selection" case emits a clearly-marked status message.

        Args:
            qapp: Qt application fixture.
        """
        del qapp
        recorder = _StatusEmissionRecorder()
        holder = _DummyHolder()
        holder.tool_panel = _ScriptToolPanelEmpty()
        holder.status_update = recorder
        getattr(MainWindow, "_on_view_scripts")(cast("MainWindow", holder))

        assert any("no script" in msg.lower() for msg in recorder.emissions)


# ---------------------------------------------------------------------------
# F-0007 / F-0008 - Tool Status / Configure Tools take registry
# ---------------------------------------------------------------------------


class _OrchestratorWithRegistry:
    """Minimal orchestrator double exposing only ``tool_registry``."""

    def __init__(self, tool_registry: object) -> None:
        """Store the supplied registry.

        Args:
            tool_registry: Registry to expose under ``self.tool_registry``.
        """
        self.tool_registry = tool_registry


class TestToolDialogsReceiveRegistry:
    """``_on_tool_status`` and ``_on_configure_tools`` flow the live registry.

    These tests replace the previous source-inspection gates with runtime
    behavioral gates: each test patches the dialog constructor in the
    ``app_module`` namespace and asserts that it is called with
    ``tool_registry=`` pointing to the holder's real registry object, not a
    surrogate.  A broken ``_on_tool_status`` that omits the keyword argument
    would produce a captured call whose kwargs lack ``tool_registry``, and the
    assertion would fail.
    """

    @staticmethod
    def test_tool_status_dialog_receives_registry(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_tool_status`` constructs ``ToolStatusDialog`` with the live registry.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        sentinel_registry = ToolRegistry(tools_dir=tools_dir)

        captured_kwargs: list[dict[str, object]] = []

        class _RecordingDialog(QDialog):
            def __init__(self, **kwargs: object) -> None:
                """Record constructor kwargs without calling a real Qt dialog.

                Args:
                    **kwargs: Keyword arguments passed by the caller.
                """
                if QApplication.instance() is None:
                    QApplication([])
                super().__init__()
                captured_kwargs.append(kwargs)

            def exec(self) -> int:
                """Return 0 without showing a real dialog.

                Returns:
                    int: Always 0.
                """
                return 0

        monkeypatch.setattr(app_module, "ToolStatusDialog", _RecordingDialog)

        class _HolderWithRegistry:
            _orchestrator: _OrchestratorWithRegistry = _OrchestratorWithRegistry(sentinel_registry)
            current_binary: Path | None = None

            @staticmethod
            def _show_tool_error(_name: str, _msg: str) -> None:
                """No-op error display.

                Args:
                    _name: Tool name (unused).
                    _msg: Error message (unused).
                """

        getattr(MainWindow, "_on_tool_status")(cast("MainWindow", _HolderWithRegistry()))

        assert len(captured_kwargs) == 1, f"ToolStatusDialog should be constructed once; got {len(captured_kwargs)}"
        assert "tool_registry" in captured_kwargs[0], (
            f"ToolStatusDialog must receive tool_registry= kwarg; got kwargs={list(captured_kwargs[0])}"
        )
        assert captured_kwargs[0]["tool_registry"] is sentinel_registry, "tool_registry must be the live registry object, not a surrogate"

    @staticmethod
    def test_configure_tools_dialog_receives_registry(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_configure_tools`` constructs ``ToolConfigDialog`` with the live registry.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        sentinel_registry = ToolRegistry(tools_dir=tools_dir)

        captured_kwargs: list[dict[str, object]] = []

        class _RecordingConfigDialog(QDialog):
            tool_updated: _NoopSignal = _NoopSignal()

            def __init__(self, **kwargs: object) -> None:
                """Record constructor kwargs.

                Args:
                    **kwargs: Keyword arguments passed by the caller.
                """
                if QApplication.instance() is None:
                    QApplication([])
                super().__init__()
                captured_kwargs.append(kwargs)

            def exec(self) -> int:
                """Return 0 without showing a real dialog.

                Returns:
                    int: Always 0.
                """
                return 0

        monkeypatch.setattr(app_module, "ToolConfigDialog", _RecordingConfigDialog)

        class _ToolsConfigDouble:
            tools_directory: Path = tmp_path / "tools"

        class _HolderForConfigTools:
            _orchestrator: _OrchestratorWithRegistry = _OrchestratorWithRegistry(sentinel_registry)
            _config: _ToolsConfigDouble = _ToolsConfigDouble()
            current_binary: Path | None = None

            @staticmethod
            def _on_tool_config_updated(_tool_id: object) -> None:
                """No-op handler for tool-config-updated signal.

                Args:
                    _tool_id: Tool identifier emitted by the signal (unused).
                """

        getattr(MainWindow, "_on_configure_tools")(cast("MainWindow", _HolderForConfigTools()))

        assert len(captured_kwargs) == 1, f"ToolConfigDialog should be constructed once; got {len(captured_kwargs)}"
        assert "tool_registry" in captured_kwargs[0], (
            f"ToolConfigDialog must receive tool_registry= kwarg; got kwargs={list(captured_kwargs[0])}"
        )
        assert captured_kwargs[0]["tool_registry"] is sentinel_registry, "tool_registry must be the live registry object, not a surrogate"

    @staticmethod
    def test_configure_tools_wires_status_changed(
        real_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real ``ToolSettingsWidget.status_changed`` emission reaches the live MainWindow slot.

        Drives ``_on_configure_tools`` on a real window (blocking ``exec``
        isolated), locates the genuine :class:`ToolSettingsWidget` children of
        the constructed :class:`ToolConfigDialog`, emits one widget's real
        ``status_changed(tool_id, available)`` signal, and asserts the connected
        ``_on_tool_status_changed`` slot ran by observing the genuine
        ``status_update`` side-effect. The slot maps ``available`` to the literal
        ``"available"``/``"unavailable"`` token, computed here independently from
        the production source, so a broken connection (or a slot that ignores the
        payload) leaves the expected message absent and fails the assertion.

        Args:
            real_window: Real MainWindow fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(ToolConfigDialog, "exec", _no_exec)

        statuses: list[str] = []
        real_window.status_update.connect(statuses.append)

        cast("Callable[[], None]", getattr(real_window, "_on_configure_tools"))()

        dialogs = real_window.findChildren(ToolConfigDialog)
        assert dialogs, "ToolConfigDialog was not constructed as a child of the window"
        widgets = dialogs[0].findChildren(ToolSettingsWidget)
        assert widgets, "ToolConfigDialog exposed no ToolSettingsWidget children to wire status_changed"

        available_flag = True
        unavailable_flag = False

        statuses.clear()
        widgets[0].status_changed.emit("ghidra", available_flag)
        assert any("ghidra available" in msg for msg in statuses), (
            f"status_changed emission did not reach _on_tool_status_changed; observed status emissions: {statuses}"
        )

        statuses.clear()
        widgets[0].status_changed.emit("ghidra", unavailable_flag)
        assert any("ghidra unavailable" in msg for msg in statuses), (
            f"status_changed payload (available=False) was not honoured by the slot; observed: {statuses}"
        )


# ---------------------------------------------------------------------------
# F-0009 - _on_open_sandbox does not construct throwaway dialog
# ---------------------------------------------------------------------------


class TestOpenSandboxAvoidsDialogProbe:
    """``_on_open_sandbox`` routes availability check through ``bridge.is_available``."""

    @staticmethod
    def test_open_sandbox_uses_bridge_is_available(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_open_sandbox`` awaits ``bridge.is_available`` and never probes through ``SandboxConfigDialog``.

        The slot's async body is driven to completion by a synchronous
        ``run_bridge_coroutine_async`` replacement that runs the produced
        coroutine and forwards the result to the ``on_success`` callback.
        A recording bridge counts every ``is_available`` await and ``create``
        await; with ``is_available`` returning ``False`` the production code
        must take the unavailable branch (warning + ``"No sandbox available"``
        status) and must *not* call ``create``. A regression that reintroduced
        the throwaway ``SandboxConfigDialog()`` availability probe would
        construct the recording dialog (caught here) or skip the bridge await
        entirely (``is_available_calls == 0``), failing the gate.

        Args:
            qapp: Qt application fixture (singleton).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp

        sandbox_dialog_constructed: list[int] = []
        is_available_calls: list[int] = []
        create_calls: list[int] = []
        warnings: list[str] = []

        class _RecordingSandboxDialog(QDialog):
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                """Record construction to detect the throwaway-dialog anti-pattern.

                Args:
                    *_args: Forwarded positional args.
                    **_kwargs: Forwarded keyword args.
                """
                if QApplication.instance() is None:
                    QApplication([])
                super().__init__()
                sandbox_dialog_constructed.append(1)

        class _RecordingBridge:
            """Sandbox bridge double recording availability/create awaits."""

            async def is_available(self) -> bool:
                """Record the availability probe and report unavailable.

                Returns:
                    bool: Always ``False`` so the create path is skipped.
                """
                is_available_calls.append(1)
                return False

            async def create(self) -> object:
                """Record a create await (must never happen when unavailable).

                Returns:
                    object: A placeholder instance descriptor.
                """
                create_calls.append(1)
                return {"instance_id": "should-not-happen"}

        def _run_bridge_sync(
            coro: Coroutine[object, object, object],
            on_success: Callable[[object], None] | None = None,
            on_error: Callable[[object], None] | None = None,
            _parent: object = None,
        ) -> None:
            """Run the slot's coroutine synchronously and fan out to callbacks.

            Synchronous stand-in for ``run_bridge_coroutine_async`` so the slot's
            async body is driven to completion deterministically in-test.

            Args:
                coro: Coroutine returned by the slot's ``open_sandbox``.
                on_success: Success callback invoked with the coroutine result.
                on_error: Error callback invoked with any raised exception.
                _parent: Parent widget (unused).
            """
            try:
                result = asyncio.run(coro)
            except (RuntimeError, OSError, ValueError) as exc:
                if on_error is not None:
                    on_error(exc)
                return
            if on_success is not None:
                on_success(result)

        def _record_warning(_parent: object, _title: str, body: str, *_a: object, **_kw: object) -> int:
            """Capture the unavailable-sandbox warning body.

            Args:
                _parent: Parent widget (unused).
                _title: Dialog title (unused).
                body: Dialog body text.
                *_a: Forwarded positional args.
                **_kw: Forwarded keyword args.

            Returns:
                int: Always ``QMessageBox.StandardButton.Ok``.
            """
            warnings.append(body)
            return int(QMessageBox.StandardButton.Ok)

        monkeypatch.setattr(app_module, "SandboxConfigDialog", _RecordingSandboxDialog)
        monkeypatch.setattr(app_module, "run_bridge_coroutine_async", _run_bridge_sync)
        monkeypatch.setattr(QMessageBox, "warning", _record_warning)

        recording_bridge = _RecordingBridge()
        status_recorder = _StatusEmissionRecorder()

        class _OpenSandboxHolder:
            status_update: _StatusEmissionRecorder = status_recorder
            _current_worker: object = None

            @staticmethod
            def _get_or_create_sandbox_bridge() -> _RecordingBridge:
                """Return the recording bridge instead of a real backend.

                Returns:
                    _RecordingBridge: The recording sandbox bridge.
                """
                return recording_bridge

        getattr(MainWindow, "_on_open_sandbox")(cast("MainWindow", _OpenSandboxHolder()))

        assert is_available_calls == [1], f"_on_open_sandbox must await bridge.is_available exactly once; got {is_available_calls}"
        assert not create_calls, f"create must not run when the sandbox is unavailable; got {create_calls}"
        assert not sandbox_dialog_constructed, "SandboxConfigDialog must never be constructed as an availability probe"
        assert any("No sandbox" in body or "sandbox environment" in body for body in warnings), (
            f"expected the unavailable-sandbox warning to fire; got {warnings}"
        )
        assert any("No sandbox available" in msg for msg in status_recorder.emissions), (
            f"expected 'No sandbox available' status emission; got {status_recorder.emissions}"
        )


# ---------------------------------------------------------------------------
# F-0010 - _apply_provider_settings disconnects disabled providers
# ---------------------------------------------------------------------------


class TestApplyProviderSettingsHandlesDisabled:
    """``_apply_provider_settings`` disconnects providers the user disabled.

    The behavioral gate: passing a settings dict with ``enabled=False`` for a
    connected provider causes the method to emit a status bar message that
    reports ``"1 disabled"``.  A broken implementation that silently skips the
    disconnect path would emit ``"0 disabled"`` instead, failing the assertion.
    """

    @staticmethod
    def test_disabled_provider_reflected_in_status_emission(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Disabling a connected provider produces a status bar message reporting it.

        Args:
            qapp: Qt application fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp

        class _FakeProvider:
            is_connected: bool = True

        class _FakeRegistry:
            def get(self, _name: ProviderName) -> _FakeProvider:
                """Return a connected provider stub.

                Args:
                    _name: Provider name (unused).

                Returns:
                    _FakeProvider: A provider advertising ``is_connected=True``.
                """
                return _FakeProvider()

        class _FakeOrchestratorForSettings:
            provider_registry: _FakeRegistry = _FakeRegistry()

        status_recorder = _StatusEmissionRecorder()

        class _SettingsHolder:
            _orchestrator: _FakeOrchestratorForSettings = _FakeOrchestratorForSettings()
            status_update: _StatusEmissionRecorder = status_recorder

            def _run_async(self, _coro: object) -> None:
                """Discard the async work for this test.

                Args:
                    _coro: Coroutine (unused; the status emission is sync).
                """

            @staticmethod
            def _on_provider_reconnect_finished(_result: object) -> None:
                """No-op handler for the provider-reconnect-finished signal.

                Args:
                    _result: Result from the reconnect worker (unused).
                """

            @staticmethod
            def _on_provider_reconnect_error(_error: object) -> None:
                """No-op handler for the provider-reconnect-error signal.

                Args:
                    _error: Error from the reconnect worker (unused).
                """

        # Patch the async dispatcher so it doesn't start a real QThread.
        def _discard_bridge_coro(
            coro: Coroutine[object, object, object],
            _on_success: Callable[[object], None] | None = None,
            _on_error: Callable[[object], None] | None = None,
            _parent: object = None,
        ) -> None:
            """Discard the reconnect coroutine without running it.

            Args:
                coro: Coroutine to close unrun.
                _on_success: Success callback (unused).
                _on_error: Error callback (unused).
                _parent: Parent widget (unused).
            """
            coro.close()

        monkeypatch.setattr(app_module, "run_bridge_coroutine_async", _discard_bridge_coro)

        settings: dict[str, dict[str, object]] = {
            "openai": {"enabled": False, "api_key": "", "api_base": "", "organization_id": ""},
        }
        getattr(MainWindow, "_apply_provider_settings")(cast("MainWindow", _SettingsHolder()), settings)

        assert status_recorder.emissions, "expected at least one status emission after _apply_provider_settings"
        last_emission = status_recorder.emissions[-1]
        assert "1 disabled" in last_emission, f"expected '1 disabled' in status emission for one disabled provider; got {last_emission!r}"


# ---------------------------------------------------------------------------
# F-0011..F-0019 - Orphan-signal wiring (consumer-side in app.py)
# ---------------------------------------------------------------------------


class TestOrphanSignalWiringRuntime:
    """Drive each orphan signal through a live dialog/widget and assert the slot ran.

    Every test constructs the genuine producer (dialog or widget) through the
    real :class:`MainWindow` slot (with only the blocking modal ``exec``
    isolated), emits the real Qt signal, and asserts an *observable* side-effect
    of the connected slot - a status-bar emission with an independently computed
    string, a replaced ``_config`` object, a combo selection, or a rebuilt
    manager instance. A broken connection (wrong target, dead branch, removed
    ``.connect``) produces no side-effect and fails the assertion, which the
    prior source-substring checks could not detect.
    """

    @staticmethod
    def test_preferences_settings_changed_reaches_slot(
        real_window: MainWindow,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real ``PreferencesDialog.settings_changed`` emission replaces ``_config``.

        ``_on_preferences_changed`` assigns ``self._config = new_config`` on
        receipt. Emitting the real signal with a freshly built :class:`Config`
        and asserting ``real_window._config is sentinel_config`` independently
        verifies the connection: object identity cannot be satisfied by a stale
        config, so a missing/wrong connection fails.

        Args:
            real_window: Real MainWindow fixture.
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(preferences_module.PreferencesDialog, "exec", _no_exec)

        cast("Callable[[], None]", getattr(real_window, "_on_preferences"))()

        dialogs = real_window.findChildren(preferences_module.PreferencesDialog)
        assert dialogs, "PreferencesDialog was not constructed as a child of the window"

        sentinel_config = Config(
            tools_directory=tmp_path / "tools2",
            logs_directory=tmp_path / "logs2",
            data_directory=tmp_path / "data2",
        )
        assert getattr(real_window, "_config") is not sentinel_config
        dialogs[0].settings_changed.emit(sentinel_config)
        assert getattr(real_window, "_config") is sentinel_config, (
            "settings_changed emission did not reach _on_preferences_changed (config was not replaced)"
        )

    @staticmethod
    def test_session_loaded_signal_reaches_slot(
        real_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real ``SessionManagerDialog.session_loaded`` emission reaches the load slot.

        ``_on_session_load_requested`` emits ``"Loading session <id>..."``. The
        ``session_deleted`` half is gated by the runtime companion module
        (``test_session_dialog_deleted_signal_reaches_slot``); this covers the
        ``session_loaded`` half with the same real-emission technique.

        Args:
            real_window: Real MainWindow fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(SessionManagerDialog, "exec", _no_exec)

        statuses: list[str] = []
        real_window.status_update.connect(statuses.append)

        cast("Callable[[], None]", getattr(real_window, "_on_load_session"))()

        dialogs = real_window.findChildren(SessionManagerDialog)
        assert dialogs, "SessionManagerDialog was not constructed as a child of the window"
        statuses.clear()
        dialogs[0].session_loaded.emit("sess-load-1")
        assert any("Loading session sess-load-1" in msg for msg in statuses), (
            f"session_loaded emission did not reach _on_session_load_requested; observed {statuses}"
        )

    @staticmethod
    def test_provider_dialog_signals_reach_slots(
        real_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Real ``provider_updated`` and ``active_provider_changed`` emissions reach their slots.

        ``_on_provider_dialog_updated`` emits ``"Provider configuration updated:
        openai"`` and ``_on_active_provider_changed`` emits ``"Active provider:
        openai"`` (the latter also parses ``"openai"`` through
        :class:`ProviderName`). Both messages are computed here independently.

        Args:
            real_window: Real MainWindow fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(ProviderConfigDialog, "exec", _no_exec)

        statuses: list[str] = []
        real_window.status_update.connect(statuses.append)

        cast("Callable[[], None]", getattr(real_window, "_on_configure_providers"))()

        dialogs = real_window.findChildren(ProviderConfigDialog)
        assert dialogs, "ProviderConfigDialog was not constructed as a child of the window"
        dialog = dialogs[0]

        statuses.clear()
        dialog.provider_updated.emit(ProviderName.OPENAI.value)
        assert any(f"Provider configuration updated: {ProviderName.OPENAI.value}" in msg for msg in statuses), (
            f"provider_updated emission did not reach _on_provider_dialog_updated; observed {statuses}"
        )

        statuses.clear()
        dialog.active_provider_changed.emit(ProviderName.OPENAI.value)
        assert any(f"Active provider: {ProviderName.OPENAI.value}" in msg for msg in statuses), (
            f"active_provider_changed emission did not reach _on_active_provider_changed; observed {statuses}"
        )

    @staticmethod
    def test_model_selection_signal_reaches_slot(
        real_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real ``ModelSelectionDialog.model_selected`` emission syncs the toolbar combo.

        ``_on_model_selected_from_browse`` routes to ``_sync_model_combo``, which
        adds the model id to ``model_combo`` and makes it current. The combo's
        ``currentText`` is an independent observable of the wiring.

        Args:
            real_window: Real MainWindow fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(ModelSelectionDialog, "exec", _no_exec)

        model_list = [
            ModelInfo(
                id="gpt-4o",
                name="GPT-4o",
                provider=ProviderName.OPENAI,
                context_window=128_000,
                supports_tools=True,
                supports_vision=True,
                supports_streaming=True,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]
        cast("Callable[[object], None]", getattr(real_window, "_on_browse_models_result"))(model_list)

        dialogs = real_window.findChildren(ModelSelectionDialog)
        assert dialogs, "ModelSelectionDialog was not constructed as a child of the window"

        selected_id = "model-selected-via-signal"
        dialogs[0].model_selected.emit(selected_id)
        assert real_window.model_combo.currentText() == selected_id, (
            f"model_selected emission did not sync the toolbar combo; current text={real_window.model_combo.currentText()!r}"
        )

    @staticmethod
    def test_sandbox_settings_updated_reaches_slot(
        real_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A real ``SandboxConfigDialog.settings_updated`` emission rebuilds the manager.

        ``_on_sandbox_settings_updated`` reads ``sender().get_settings()`` and
        routes through ``_apply_sandbox_settings``, which replaces
        ``self.sandbox_manager`` with a freshly built :class:`SandboxManager`.
        Asserting the manager object identity changed independently verifies the
        slot ran end-to-end (a missing connection leaves the original instance).

        Args:
            real_window: Real MainWindow fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(SandboxConfigDialog, "exec", _no_exec)

        cast("Callable[[], None]", getattr(real_window, "_on_configure_sandbox"))()

        dialogs = real_window.findChildren(SandboxConfigDialog)
        assert dialogs, "SandboxConfigDialog was not constructed as a child of the window"

        manager_before = getattr(real_window, "sandbox_manager")
        dialogs[0].settings_updated.emit()
        manager_after = getattr(real_window, "sandbox_manager")
        assert manager_after is not manager_before, (
            "settings_updated emission did not reach _on_sandbox_settings_updated (manager was not rebuilt)"
        )

    @staticmethod
    def test_sandbox_monitor_stopped_reaches_slot(
        real_window: MainWindow,
    ) -> None:
        """``_wire_sandbox_monitor_widgets`` connects ``sandbox_stopped`` to the live slot.

        A real :class:`SandboxMonitorWidget` is hosted under a container, wired
        via the production helper, then its ``sandbox_stopped`` signal is
        emitted. ``_on_sandbox_monitor_stopped`` emits ``"Sandbox stopped"`` and
        sets the toolbar button text to ``"Sandbox: OFF"`` - both independently
        observable side-effects.

        Args:
            real_window: Real MainWindow fixture.
        """
        statuses: list[str] = []
        real_window.status_update.connect(statuses.append)

        container = QWidget()
        try:
            monitor = SandboxMonitorWidget(parent=container)
            cast("Callable[[QWidget], None]", getattr(real_window, "_wire_sandbox_monitor_widgets"))(container)

            statuses.clear()
            monitor.sandbox_stopped.emit()
        finally:
            container.deleteLater()

        assert any("Sandbox stopped" in msg for msg in statuses), (
            f"sandbox_stopped emission did not reach _on_sandbox_monitor_stopped; observed {statuses}"
        )
        button_text = cast("str", getattr(real_window, "_sandbox_btn").text())
        assert button_text == "Sandbox: OFF", f"expected the sandbox button to read 'Sandbox: OFF'; got {button_text!r}"

    @staticmethod
    def test_embedded_tool_panel_signals_reach_slots(
        real_window: MainWindow,
    ) -> None:
        """Real ``ToolOutputPanel.embedded_tool_*`` emissions reach their MainWindow slots.

        ``_connect_signals`` wires the live panel's ``embedded_tool_started`` and
        ``embedded_tool_closed`` signals. Emitting them on the real panel must
        produce ``"<tool> started"`` / ``"<tool> closed"`` status messages, whose
        exact wording is computed here independently.

        Args:
            real_window: Real MainWindow fixture.
        """
        statuses: list[str] = []
        real_window.status_update.connect(statuses.append)
        panel = real_window.tool_panel

        statuses.clear()
        panel.embedded_tool_started.emit("ghidra")
        assert any("ghidra started" in msg for msg in statuses), (
            f"embedded_tool_started emission did not reach _on_embedded_tool_started; observed {statuses}"
        )

        statuses.clear()
        panel.embedded_tool_closed.emit("ghidra")
        assert any("ghidra closed" in msg for msg in statuses), (
            f"embedded_tool_closed emission did not reach _on_embedded_tool_closed; observed {statuses}"
        )


class _UIConfigDouble:
    """Minimal UI-config double exposing the ``theme`` attribute read by the slot."""

    def __init__(self, theme: str) -> None:
        """Store the theme name.

        Args:
            theme: UI theme name the slot compares for change detection.
        """
        self.theme = theme


class _ConfigDouble:
    """Config double exposing the ``ui.theme`` access the slot performs."""

    def __init__(self, theme: str) -> None:
        """Build a config double whose ``ui.theme`` returns ``theme``.

        Args:
            theme: UI theme name surfaced through :attr:`ui`.
        """
        self.ui = _UIConfigDouble(theme)


class _ThemeManagerRecorder:
    """Theme-manager double recording :meth:`apply_theme` invocations."""

    def __init__(self) -> None:
        """Initialise the applied-theme list."""
        self.applied: list[str] = []

    def apply_theme(self, theme: str) -> None:
        """Record the theme the slot requested.

        Args:
            theme: Theme name passed by the slot.
        """
        self.applied.append(theme)


class _PreferencesHolder:
    """Holder driving :meth:`MainWindow._on_preferences_changed` against a stub.

    The slot reads ``self._config.ui.theme`` and ``new_config.ui.theme`` to
    detect a theme change, so the held config is a :class:`_ConfigDouble`
    rather than a bare object.
    """

    def __init__(self) -> None:
        """Initialise tracking attributes."""
        self._config: object = _ConfigDouble("dark")
        self._theme_manager = _ThemeManagerRecorder()
        self.status_update = _StatusEmissionRecorder()
        self.cache_called: bool = False

    def _initialize_model_cache(self) -> None:
        """Record that the model cache initializer ran."""
        self.cache_called = True


class TestPreferencesAppliedSlotUpdatesConfig:
    """``_on_preferences_changed`` updates the held config without exec."""

    @staticmethod
    def test_preferences_changed_assigns_new_config(qapp: QCoreApplication) -> None:
        """The slot replaces ``_config`` with the emitted instance.

        Args:
            qapp: Qt application fixture.
        """
        del qapp
        sentinel = _ConfigDouble("dark")
        holder = _PreferencesHolder()
        getattr(MainWindow, "_on_preferences_changed")(cast("MainWindow", holder), cast("Config", sentinel))
        assert getattr(holder, "_config") is sentinel
        assert holder.cache_called is True


# ---------------------------------------------------------------------------
# F-0023 - ModelSelectionDialog gets provider context
# ---------------------------------------------------------------------------


class TestModelSelectionDialogGetsContext:
    """``_on_browse_models_result`` constructs the dialog with full context.

    The behavioral gate: the dialog constructor is intercepted and the kwargs
    are asserted to include ``provider_name``, ``current_model``, and
    ``discovery``.  A broken implementation that omits any of these would
    produce a captured-kwargs dict without the expected key, failing the test.
    """

    @staticmethod
    def test_dialog_constructed_with_provider_name_and_discovery(
        qapp: QCoreApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_on_browse_models_result`` passes ``provider_name`` and ``discovery`` to the dialog.

        Args:
            qapp: Qt application fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp

        captured_kwargs: list[dict[str, object]] = []

        class _RecordingModelDialog(QDialog):
            model_selected: _NoopSignal = _NoopSignal()

            def __init__(self, **kwargs: object) -> None:
                """Record constructor kwargs.

                Args:
                    **kwargs: Keyword arguments passed by the caller.
                """
                if QApplication.instance() is None:
                    QApplication([])
                super().__init__()
                captured_kwargs.append(kwargs)

            def exec(self) -> int:
                """Return 0.

                Returns:
                    int: Always 0.
                """
                return 0

            def get_selected_model(self) -> str | None:
                """Return None (no selection).

                Returns:
                    str | None: Always None.
                """
                return None

        monkeypatch.setattr(app_module, "ModelSelectionDialog", _RecordingModelDialog)

        class _FakeActiveProvider:
            name: ProviderName = ProviderName.OPENAI

        class _FakeProviderRegistry:
            active: _FakeActiveProvider = _FakeActiveProvider()

        class _FakeModelCombo(QComboBox):
            def __init__(self) -> None:
                """Initialize with no items."""
                if QApplication.instance() is None:
                    QApplication([])
                super().__init__()

            @override
            def currentText(self) -> str:
                """Return a model text.

                Returns:
                    str: Fixed model string.
                """
                return "gpt-4o"

        class _FakeOrchestratorForBrowse:
            provider_registry: _FakeProviderRegistry = _FakeProviderRegistry()

        class _BrowseHolder:
            _orchestrator: _FakeOrchestratorForBrowse = _FakeOrchestratorForBrowse()
            model_combo: _FakeModelCombo = _FakeModelCombo()
            model_discovery: object = object()
            status_update: _StatusEmissionRecorder = _StatusEmissionRecorder()

            @staticmethod
            def _on_model_selected_from_browse(_model_id: object) -> None:
                """No-op handler for the model-selected signal.

                Args:
                    _model_id: Model identifier emitted by the signal (unused).
                """

        model_list = [
            ModelInfo(
                id="gpt-4o",
                name="GPT-4o",
                provider=ProviderName.OPENAI,
                context_window=128_000,
                supports_tools=True,
                supports_vision=True,
                supports_streaming=True,
                input_cost_per_1m_tokens=None,
                output_cost_per_1m_tokens=None,
            ),
        ]

        getattr(MainWindow, "_on_browse_models_result")(cast("MainWindow", _BrowseHolder()), model_list)

        assert len(captured_kwargs) == 1, f"ModelSelectionDialog must be constructed once; got {len(captured_kwargs)}"
        kw = captured_kwargs[0]
        assert "provider_name" in kw, f"expected 'provider_name' kwarg; got keys {list(kw)}"
        assert kw["provider_name"] == ProviderName.OPENAI, f"expected provider_name=OPENAI; got {kw['provider_name']!r}"
        assert "current_model" in kw, f"expected 'current_model' kwarg; got keys {list(kw)}"
        assert "discovery" in kw, f"expected 'discovery' kwarg; got keys {list(kw)}"


# ---------------------------------------------------------------------------
# F-0025 - _on_provider_changed activates connected providers
# ---------------------------------------------------------------------------


class _ProviderDouble:
    """Provider double advertising a fixed connection state."""

    def __init__(self, *, is_connected: bool) -> None:
        """Initialise with the desired connection flag.

        Args:
            is_connected: Whether the double should advertise as connected.
        """
        self.is_connected = is_connected


class _RegistryDouble:
    """Registry double recording :meth:`set_active` calls."""

    def __init__(
        self,
        provider: _ProviderDouble | None,
        *,
        raise_provider_error: bool = False,
    ) -> None:
        """Initialise the registry double.

        Args:
            provider: Provider to return from :meth:`get`.
            raise_provider_error: When True, :meth:`set_active` raises.
        """
        self._provider = provider
        self._raise = raise_provider_error
        self.set_active_calls: list[ProviderName] = []

    def get(self, _name: ProviderName) -> _ProviderDouble | None:
        """Return the configured provider double.

        Args:
            _name: Requested provider (unused).

        Returns:
            _ProviderDouble | None: The configured stub provider.
        """
        return self._provider

    def set_active(self, name: ProviderName) -> None:
        """Record the call and optionally raise.

        Args:
            name: Provider name passed in.

        Raises:
            ProviderError: When the double was configured to raise.
        """
        self.set_active_calls.append(name)
        if self._raise:
            msg = "forced"
            raise ProviderError(msg, provider_name=name.value)


class _ProviderComboDouble(QComboBox):
    """Real :class:`QComboBox` seeded with a single provider entry.

    The production :meth:`MainWindow._on_provider_changed` wraps the combo in a
    ``QSignalBlocker`` on the disconnected-provider path, which requires a real
    :class:`QObject`. Subclassing :class:`QComboBox` keeps the native
    ``currentData`` / ``findData`` / ``setCurrentIndex`` / ``blockSignals``
    behaviour while letting the test seed the data the slot reads.
    """

    def __init__(self, value: object) -> None:
        """Seed the combo with a single item carrying ``value`` as item data.

        Args:
            value: Value the combo's ``currentData`` should return.
        """
        if QApplication.instance() is None:
            QApplication([])
        super().__init__()
        self.addItem(str(value), value)
        self.setCurrentIndex(0)


class _OrchestratorDouble:
    """Orchestrator double exposing only ``provider_registry``."""

    def __init__(self, registry: _RegistryDouble) -> None:
        """Initialise with the registry double.

        Args:
            registry: Registry double to expose.
        """
        self.provider_registry = registry


def _build_provider_holder(
    *,
    provider: _ProviderDouble | None,
    raise_provider_error: bool = False,
) -> tuple[_DummyHolder, _RegistryDouble, _StatusEmissionRecorder]:
    """Build a holder + registry + recorder triple for provider-change tests.

    Args:
        provider: Provider double the registry should return.
        raise_provider_error: When True, :meth:`set_active` raises ``ProviderError``.

    Returns:
        tuple[_DummyHolder, _RegistryDouble, _StatusEmissionRecorder]: Holder ready to
        be passed to :meth:`MainWindow._on_provider_changed`, the registry, and the
        status recorder.
    """
    registry = _RegistryDouble(provider, raise_provider_error=raise_provider_error)
    recorder = _StatusEmissionRecorder()
    holder = _DummyHolder.for_provider_changed(
        _ProviderComboDouble(ProviderName.OPENAI),
        _OrchestratorDouble(registry),
        recorder,
    )
    return holder, registry, recorder


class TestProviderChangedSetsActive:
    """``_on_provider_changed`` activates the new provider through registry."""

    @staticmethod
    def test_set_active_called_for_connected_provider() -> None:
        """A connected provider is made active via ``set_active``."""
        holder, registry, _ = _build_provider_holder(
            provider=_ProviderDouble(is_connected=True),
        )
        getattr(MainWindow, "_on_provider_changed")(cast("MainWindow", holder), 0)
        assert registry.set_active_calls == [ProviderName.OPENAI]

    @staticmethod
    def test_disconnected_provider_not_activated() -> None:
        """A disconnected provider is not activated; ``set_active`` is never called."""
        holder, registry, recorder = _build_provider_holder(
            provider=_ProviderDouble(is_connected=False),
        )

        def _cancel_prompt(_name: str) -> str:
            """Return the ``"cancel"`` selection sentinel.

            Args:
                _name: Provider name (unused).

            Returns:
                str: Always ``"cancel"``.
            """
            return "cancel"

        setattr(holder, "_prompt_provider_not_connected", _cancel_prompt)
        getattr(MainWindow, "_on_provider_changed")(cast("MainWindow", holder), 0)

        assert registry.set_active_calls == []
        assert any("not connected" in msg.lower() or "configure" in msg.lower() for msg in recorder.emissions)

    @staticmethod
    def test_disconnected_provider_prompt_configure_route() -> None:
        """Choosing 'Configure Now' opens the provider configuration dialog."""
        holder, registry, _ = _build_provider_holder(
            provider=_ProviderDouble(is_connected=False),
        )
        configure_calls: list[int] = []

        def _configure_prompt(_name: str) -> str:
            """Return the ``"configure"`` selection sentinel.

            Args:
                _name: Provider name (unused).

            Returns:
                str: Always ``"configure"``.
            """
            return "configure"

        def _record_configure() -> None:
            """Append a marker to ``configure_calls`` to confirm invocation."""
            configure_calls.append(1)

        setattr(holder, "_prompt_provider_not_connected", _configure_prompt)
        setattr(holder, "_on_configure_providers", _record_configure)
        getattr(MainWindow, "_on_provider_changed")(cast("MainWindow", holder), 0)

        assert registry.set_active_calls == []
        assert configure_calls == [1]

    @staticmethod
    def test_provider_error_does_not_propagate() -> None:
        """A ``ProviderError`` from ``set_active`` is logged, not raised."""
        holder, registry, _ = _build_provider_holder(
            provider=_ProviderDouble(is_connected=True),
            raise_provider_error=True,
        )
        getattr(MainWindow, "_on_provider_changed")(cast("MainWindow", holder), 0)
        assert registry.set_active_calls == [ProviderName.OPENAI]


# ---------------------------------------------------------------------------
# F-0026 - _refresh_system_status disables timer after threshold
# ---------------------------------------------------------------------------


class _TimerDouble:
    """QTimer double that records :meth:`stop` invocations."""

    def __init__(self) -> None:
        """Initialise the stop counter."""
        self.stopped: int = 0

    def stop(self) -> None:
        """Record one stop call."""
        self.stopped += 1


class _StatusLabelDouble:
    """QLabel double recording the most recent text passed to ``setText``.

    Routes the Qt camelCase API name through :meth:`__getattr__` to keep the
    class definition Python-idiomatic.
    """

    _qt_alias_map: ClassVar[dict[str, str]] = {"setText": "_set_text"}

    def __init__(self) -> None:
        """Initialise the text holder."""
        self.text: str = ""

    def _set_text(self, value: str) -> None:
        """Record the text.

        Args:
            value: Text to display.
        """
        self.text = value

    def __getattr__(self, name: str) -> object:
        """Route Qt-style camelCase attribute lookups to snake_case methods.

        Args:
            name: Attribute name requested by the production code.

        Returns:
            object: The bound method matching the Qt API call site.

        Raises:
            AttributeError: When the requested name has no mapping.
        """
        alias = self._qt_alias_map.get(name)
        if alias is None:
            raise AttributeError(name)
        return getattr(self, alias)


class _OrchestratorAlwaysOk:
    """Orchestrator double whose :meth:`get_system_status` returns a static dict."""

    @staticmethod
    async def get_system_status() -> dict[str, object]:
        """Return a fixed status dictionary.

        Returns:
            dict[str, object]: A status dict with state and session_id.
        """
        return {"state": "running", "session_id": "sess-1"}


def _build_refresh_holder(failure_count: int) -> _DummyHolder:
    """Build a holder ready for :meth:`MainWindow._refresh_system_status`.

    Args:
        failure_count: Initial value for ``_status_failure_count``.

    Returns:
        _DummyHolder: Configured holder.
    """
    return _DummyHolder.for_refresh_status(failure_count, _OrchestratorAlwaysOk())


class TestRefreshSystemStatusFailureThreshold:
    """``_refresh_system_status`` stops the timer after repeated failures."""

    @staticmethod
    def test_threshold_exceeded_stops_timer() -> None:
        """Successive error callbacks stop the timer once the threshold is reached.

        Drives the GUI-thread error slot ``_on_system_status_error`` (M2 moved
        the failure accounting off the blocking timer path into this slot).
        """
        holder = _build_refresh_holder(failure_count=0)
        threshold: int = getattr(app_module, "_STATUS_REFRESH_FAILURE_THRESHOLD")
        for _ in range(threshold):
            getattr(MainWindow, "_on_system_status_error")(cast("MainWindow", holder), RuntimeError("forced"))

        assert getattr(holder, "_status_failure_count") == threshold
        assert getattr(holder, "_status_refresh_in_flight") is False
        timer = getattr(holder, "_status_timer")
        assert timer is not None
        assert cast("_TimerDouble", timer).stopped == 1
        assert holder.status_label is not None
        assert "disabled" in holder.status_label.text.lower()

    @staticmethod
    def test_successful_refresh_resets_failure_count() -> None:
        """A fetched status payload resets the failure counter to zero.

        Drives the GUI-thread success slot ``_on_system_status_fetched``.
        """
        holder = _build_refresh_holder(failure_count=3)
        getattr(MainWindow, "_on_system_status_fetched")(
            cast("MainWindow", holder),
            {"state": "running", "session_id": "sess-1"},
        )
        assert getattr(holder, "_status_failure_count") == 0
        assert getattr(holder, "_status_refresh_in_flight") is False
        assert holder.status_label is not None
        assert "running" in holder.status_label.text

    @staticmethod
    def test_refresh_dispatches_async_and_never_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
        """M2 gate: the 30s timer path uses the async worker, never the blocking runner.

        Fails against the pre-fix code, which called the blocking
        ``run_bridge_coroutine`` on the GUI/timer thread.
        """
        dispatched: list[str] = []

        def _fail_blocking(*_args: object, **_kwargs: object) -> object:
            dispatched.append("blocking")
            msg = "blocking run_bridge_coroutine must not run on the status timer"
            raise AssertionError(msg)

        def _record_logged(coro: object, *_args: object, **_kwargs: object) -> None:
            dispatched.append("logged")
            if asyncio.iscoroutine(coro):
                coro.close()

        monkeypatch.setattr(app_module, "run_bridge_coroutine", _fail_blocking)
        monkeypatch.setattr(app_module, "run_bridge_coroutine_logged", _record_logged)

        holder = _build_refresh_holder(failure_count=0)
        getattr(MainWindow, "_refresh_system_status")(cast("MainWindow", holder))

        assert dispatched == ["logged"]
        assert getattr(holder, "_status_refresh_in_flight") is True


# ---------------------------------------------------------------------------
# Integration: real MainWindow construction wires Help menu and signals
# ---------------------------------------------------------------------------


@pytest.fixture
def real_window(qapp: QCoreApplication, tmp_path: Path) -> Generator[MainWindow]:
    """Construct a real :class:`MainWindow` using temporary registries.

    Args:
        qapp: Qt application fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Generator[MainWindow]: The MainWindow under test.
    """
    del qapp
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
    window = MainWindow(config, orch)
    try:
        yield window
    finally:
        window.close()


class TestMainWindowConstructionWiresMenu:
    """End-to-end verification that the wiring is reachable on a real window."""

    @staticmethod
    def test_help_menu_contains_xpu_status_action(real_window: MainWindow) -> None:
        """The constructed Help menu exposes an "XPU Status..." action.

        Args:
            real_window: MainWindow fixture.
        """
        menubar = real_window.menuBar()
        assert menubar is not None
        actions: list[QAction] = []
        for menu_action in menubar.actions():
            menu: QMenu | None = cast("QMenu | None", getattr(menu_action, "menu")())
            if menu is not None and menu_action.text().replace("&", "") == "Help":
                actions.extend(menu.actions())
        labels = [a.text() for a in actions]
        assert any("XPU Status" in lbl for lbl in labels)

    @staticmethod
    def test_status_failure_count_initialised(real_window: MainWindow) -> None:
        """The status failure counter is initialised on the constructed window.

        Args:
            real_window: MainWindow fixture.
        """
        assert hasattr(real_window, "_status_failure_count")
        assert getattr(real_window, "_status_failure_count") == 0

    @staticmethod
    def test_sandbox_monitor_wired_widgets_set_initialised(
        real_window: MainWindow,
    ) -> None:
        """``_sandbox_monitor_wired_widgets`` is initialised as an empty WeakSet.

        Args:
            real_window: MainWindow fixture.
        """
        assert hasattr(real_window, "_sandbox_monitor_wired_widgets")
        wired: weakref.WeakSet[object] = getattr(real_window, "_sandbox_monitor_wired_widgets")
        assert isinstance(wired, weakref.WeakSet)
        assert len(wired) == 0
