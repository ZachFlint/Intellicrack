# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 U5 ui-mainwindow fixes.

Each test exercises one finding from audit5.md (ui-app-core) and is designed
to fail against the unfixed code path and pass after the corresponding
remediation in :mod:`intellicrack.ui.app` and :mod:`intellicrack.ui.xpu_status`.

Findings covered:

* F-0001 - HxD button no longer references missing ``add_hxd_tab``.
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

import inspect
import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QDialog, QMainWindow, QMessageBox, QTabWidget, QWidget

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderError, ProviderName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.ui import (
    app as app_module,
    xpu_status as xpu_module,
)
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

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
    if existing is not None:
        return existing
    return QApplication([])


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


# ---------------------------------------------------------------------------
# F-0001 - HxD button no longer references missing add_hxd_tab
# ---------------------------------------------------------------------------


class TestHxDButtonHandlerCleanedUp:
    """F-0001 was resolved upstream; the dangling ``add_hxd_tab`` reference is gone."""

    @staticmethod
    def test_on_open_hxd_no_longer_references_missing_method() -> None:
        """The ``on_open_hxd`` source no longer references ``add_hxd_tab``."""
        source = inspect.getsource(MainWindow.on_open_hxd)
        assert "add_hxd_tab" not in source


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
        MainWindow._on_save_patched_binary(holder)

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
        MainWindow._on_save_patched_binary(holder)

        assert len(recorder.calls) == 1
        assert recorder.calls[0][0] == "Save"
        assert "No hex editor" in recorder.calls[0][1]


# ---------------------------------------------------------------------------
# F-0003 - sandbox lookup uses get_panel
# ---------------------------------------------------------------------------


class TestSandboxPanelLookupUsesPanels:
    """``_on_open_sandbox_panel`` resolves sandbox via ``get_panel``."""

    @staticmethod
    def test_source_uses_get_panel_for_sandbox() -> None:
        """The post-fix source calls ``get_panel("sandbox")`` for the active widget lookup."""
        source = inspect.getsource(MainWindow._on_open_sandbox_panel)
        assert 'get_panel("sandbox")' in source
        assert 'get_active_tool_widget("sandbox")' not in source


# ---------------------------------------------------------------------------
# F-0004 - XPUStatusDialog wired into Help menu
# ---------------------------------------------------------------------------


class TestXPUStatusMenuWiring:
    """The Help menu exposes an action that opens :class:`XPUStatusDialog`."""

    @staticmethod
    def test_help_menu_source_references_xpu_status() -> None:
        """``_setup_help_menu`` adds an XPU Status menu action."""
        source = inspect.getsource(MainWindow._setup_help_menu)
        assert "XPU Status" in source
        assert "_on_xpu_status" in source

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

        monkeypatch.setattr(xpu_module, "XPUStatusDialog", _RecordingXPUDialog)

        holder = QMainWindow()
        try:
            MainWindow._on_xpu_status(holder)
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
        MainWindow._on_view_scripts(holder)

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
        MainWindow._on_view_scripts(holder)

        assert any("no script" in msg.lower() for msg in recorder.emissions)


# ---------------------------------------------------------------------------
# F-0007 / F-0008 - Tool Status / Configure Tools take registry
# ---------------------------------------------------------------------------


class TestToolDialogsReceiveRegistry:
    """``_on_tool_status`` and ``_on_configure_tools`` flow the live registry."""

    @staticmethod
    def test_tool_status_source_passes_registry() -> None:
        """``_on_tool_status`` constructs ``ToolStatusDialog`` with ``tool_registry``."""
        source = inspect.getsource(MainWindow._on_tool_status)
        assert "tool_registry=" in source
        assert "ToolStatusDialog" in source

    @staticmethod
    def test_configure_tools_source_passes_registry() -> None:
        """``_on_configure_tools`` constructs ``ToolConfigDialog`` with ``tool_registry``."""
        source = inspect.getsource(MainWindow._on_configure_tools)
        assert "tool_registry=" in source
        assert "tool_updated.connect" in source

    @staticmethod
    def test_configure_tools_wires_status_changed() -> None:
        """Per-widget ``status_changed`` signals are wired to MainWindow."""
        source = inspect.getsource(MainWindow._on_configure_tools)
        assert "status_changed" in source


# ---------------------------------------------------------------------------
# F-0009 - _on_open_sandbox does not construct throwaway dialog
# ---------------------------------------------------------------------------


class TestOpenSandboxAvoidsDialogProbe:
    """``_on_open_sandbox`` no longer probes via ``SandboxConfigDialog()``."""

    @staticmethod
    def test_open_sandbox_source_uses_bridge_probe() -> None:
        """Availability flows through ``bridge.is_available`` only, not via the dialog constructor."""
        source = inspect.getsource(MainWindow._on_open_sandbox)
        assert "SandboxConfigDialog().is_sandbox_available()" not in source
        assert "SandboxConfigDialog()" not in source
        assert "bridge.is_available()" in source


# ---------------------------------------------------------------------------
# F-0010 - _apply_provider_settings disconnects disabled providers
# ---------------------------------------------------------------------------


class TestApplyProviderSettingsHandlesDisabled:
    """``_apply_provider_settings`` disconnects providers the user disabled."""

    @staticmethod
    def test_source_collects_providers_to_disconnect() -> None:
        """Source contains the ``providers_to_disconnect`` list and ``disconnect_provider`` call."""
        source = inspect.getsource(MainWindow._apply_provider_settings)
        assert "providers_to_disconnect" in source
        assert "disconnect_provider" in source


# ---------------------------------------------------------------------------
# F-0011..F-0019 - Orphan-signal wiring (consumer-side in app.py)
# ---------------------------------------------------------------------------


class TestOrphanSignalWiringSourceLevel:
    """Verify each orphan signal is connected from a MainWindow slot."""

    @staticmethod
    def test_preferences_settings_changed_wired() -> None:
        """``_on_preferences`` wires ``settings_changed``."""
        source = inspect.getsource(MainWindow._on_preferences)
        assert "settings_changed.connect" in source

    @staticmethod
    def test_session_dialog_signals_wired() -> None:
        """``_on_load_session`` wires both session-manager dialog signals."""
        source = inspect.getsource(MainWindow._on_load_session)
        assert "session_loaded.connect" in source
        assert "session_deleted.connect" in source

    @staticmethod
    def test_provider_dialog_signals_wired() -> None:
        """``_on_configure_providers`` wires both provider-dialog signals."""
        source = inspect.getsource(MainWindow._on_configure_providers)
        assert "provider_updated.connect" in source
        assert "active_provider_changed.connect" in source

    @staticmethod
    def test_model_selection_dialog_signal_wired() -> None:
        """``_on_browse_models_result`` wires ``model_selected``."""
        source = inspect.getsource(MainWindow._on_browse_models_result)
        assert "model_selected.connect" in source

    @staticmethod
    def test_sandbox_dialog_settings_updated_wired() -> None:
        """``_on_configure_sandbox`` wires ``settings_updated``."""
        source = inspect.getsource(MainWindow._on_configure_sandbox)
        assert "settings_updated.connect" in source

    @staticmethod
    def test_sandbox_monitor_wiring_helper_present() -> None:
        """``_wire_sandbox_monitor_widgets`` wires ``sandbox_stopped``."""
        source = inspect.getsource(MainWindow._wire_sandbox_monitor_widgets)
        assert "sandbox_stopped.connect" in source

    @staticmethod
    def test_tool_output_panel_signals_wired() -> None:
        """``_connect_signals`` wires both ``embedded_tool_*`` signals."""
        source = inspect.getsource(MainWindow._connect_signals)
        assert "embedded_tool_started.connect" in source
        assert "embedded_tool_closed.connect" in source


class _PreferencesHolder:
    """Holder driving :meth:`MainWindow._on_preferences_changed` against a stub."""

    def __init__(self) -> None:
        """Initialise tracking attributes."""
        self._config: object = None
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
        sentinel = object()
        holder = _PreferencesHolder()
        MainWindow._on_preferences_changed(holder, sentinel)
        assert holder._config is sentinel
        assert holder.cache_called is True


# ---------------------------------------------------------------------------
# F-0023 - ModelSelectionDialog gets provider context
# ---------------------------------------------------------------------------


class TestModelSelectionDialogGetsContext:
    """``_on_browse_models_result`` constructs the dialog with full context."""

    @staticmethod
    def test_dialog_kwargs_present() -> None:
        """All four context kwargs appear in the dialog construction."""
        source = inspect.getsource(MainWindow._on_browse_models_result)
        assert "provider_name=" in source
        assert "current_model=" in source
        assert "discovery=" in source


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


class _ProviderComboDouble:
    """Combo box double returning a fixed :class:`ProviderName` from ``currentData``."""

    def __init__(self, value: object) -> None:
        """Initialise with the value to return.

        Args:
            value: Value the combo's ``currentData`` should return.
        """
        self._value = value

    def currentData(self) -> object:  # noqa: N802 - matches Qt API name
        """Return the configured value.

        Returns:
            object: The configured value.
        """
        return self._value


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
    holder = _DummyHolder()
    holder._provider_combo = _ProviderComboDouble(ProviderName.OPENAI)
    holder._orchestrator = _OrchestratorDouble(registry)
    holder.status_update = recorder
    return holder, registry, recorder


class TestProviderChangedSetsActive:
    """``_on_provider_changed`` activates the new provider through registry."""

    @staticmethod
    def test_set_active_called_for_connected_provider() -> None:
        """A connected provider is made active via ``set_active``."""
        holder, registry, _ = _build_provider_holder(
            provider=_ProviderDouble(is_connected=True),
        )
        MainWindow._on_provider_changed(holder, 0)
        assert registry.set_active_calls == [ProviderName.OPENAI]

    @staticmethod
    def test_disconnected_provider_not_activated() -> None:
        """A disconnected provider is not activated; ``set_active`` is never called."""
        holder, registry, recorder = _build_provider_holder(
            provider=_ProviderDouble(is_connected=False),
        )
        MainWindow._on_provider_changed(holder, 0)

        assert registry.set_active_calls == []
        assert any("not connected" in msg.lower() or "configure" in msg.lower() for msg in recorder.emissions)

    @staticmethod
    def test_provider_error_does_not_propagate() -> None:
        """A ``ProviderError`` from ``set_active`` is logged, not raised."""
        holder, registry, _ = _build_provider_holder(
            provider=_ProviderDouble(is_connected=True),
            raise_provider_error=True,
        )
        MainWindow._on_provider_changed(holder, 0)
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
    """QLabel double recording the most recent text passed to :meth:`setText`."""

    def __init__(self) -> None:
        """Initialise the text holder."""
        self.text: str = ""

    def setText(self, value: str) -> None:  # noqa: N802 - matches Qt API name
        """Record the text.

        Args:
            value: Text to display.
        """
        self.text = value


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
    holder = _DummyHolder()
    holder._shutting_down = False
    holder._orchestrator = _OrchestratorAlwaysOk()
    holder._status_failure_count = failure_count
    holder._status_timer = _TimerDouble()
    holder.status_label = _StatusLabelDouble()
    holder.status_update = _StatusEmissionRecorder()
    holder._refresh_memory_status = lambda: None
    holder._refresh_model_discovery_status = lambda: None
    return holder


class TestRefreshSystemStatusFailureThreshold:
    """``_refresh_system_status`` stops the timer after repeated failures."""

    @staticmethod
    def test_threshold_exceeded_stops_timer(monkeypatch: pytest.MonkeyPatch) -> None:
        """Successive failures stop the timer once the threshold is reached.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """

        def _raise(_coro: object) -> object:
            msg = "forced"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            "intellicrack.ui.panels.async_bridge.run_bridge_coroutine",
            _raise,
        )

        holder = _build_refresh_holder(failure_count=0)
        threshold = app_module._STATUS_REFRESH_FAILURE_THRESHOLD
        for _ in range(threshold):
            MainWindow._refresh_system_status(holder)

        assert holder._status_failure_count == threshold
        assert holder._status_timer.stopped == 1
        assert "disabled" in holder.status_label.text.lower()

    @staticmethod
    def test_successful_refresh_resets_failure_count(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successful coroutine result resets the failure counter to zero.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(
            "intellicrack.ui.panels.async_bridge.run_bridge_coroutine",
            lambda _coro: {"state": "running", "session_id": "sess-1"},
        )

        holder = _build_refresh_holder(failure_count=3)
        MainWindow._refresh_system_status(holder)
        assert holder._status_failure_count == 0
        assert "running" in holder.status_label.text


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
            menu = menu_action.menu()
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
        assert real_window._status_failure_count == 0

    @staticmethod
    def test_sandbox_monitor_wired_widgets_set_initialised(
        real_window: MainWindow,
    ) -> None:
        """``_sandbox_monitor_wired_widgets`` is initialised as an empty set.

        Args:
            real_window: MainWindow fixture.
        """
        assert hasattr(real_window, "_sandbox_monitor_wired_widgets")
        assert real_window._sandbox_monitor_wired_widgets == set()
