# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 B1 ProcessPanel base fixes (F-0001, F-0002, F-0025).

Each test exercises one finding and would fail without the corresponding
remediation in ``intellicrack.ui.panels.process_panel.base``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ProcessInfo, ToolError
from intellicrack.ui.panels.process_panel.base import ProcessPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QWidget

    from intellicrack.ui.panels.process_panel.hint_overlay import AttachHintOverlay


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Ensure exactly one QApplication exists for these widget tests.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


def _process_events_until(
    qapp: QCoreApplication,
    predicate: Callable[[], bool],
    timeout_ms: int = 3000,
) -> bool:
    """Pump the Qt event loop until ``predicate()`` is truthy or timeout elapses.

    Args:
        qapp: The Qt application instance whose event loop to drive.
        predicate: Zero-argument callable returning a truthy value when done.
        timeout_ms: Maximum total milliseconds to wait.

    Returns:
        bool: True if the predicate became truthy within the timeout.
    """
    elapsed_ms = 0
    step_ms = 25
    while elapsed_ms < timeout_ms:
        if predicate():
            return True
        loop = QEventLoop()
        QTimer.singleShot(step_ms, loop.quit)
        loop.exec()
        qapp.processEvents()
        elapsed_ms += step_ms
    return predicate()


class _RecordingBridge(ProcessBridge):
    """ProcessBridge subclass that records calls and yields scripted results.

    Overrides methods exercised by ProcessPanel so their behaviour can be
    verified without a live Win32 backend.
    """

    def __init__(self) -> None:
        """Initialize the bridge with empty call records and default results."""
        super().__init__()
        self.arch_calls: list[int] = []
        self.arch_result: str = "x86_64"
        self.arch_should_raise: ToolError | None = None
        self.priv_calls: list[int | None] = []
        self.priv_result: list[dict[str, object]] = [
            {"name": "SeDebugPrivilege", "luid": 20, "enabled": True, "attributes": 2},
        ]
        self.priv_should_raise: ToolError | None = None
        self.list_calls: int = 0
        self.open_calls: list[int] = []
        self.close_calls: int = 0

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """Skip real Win32 initialization.

        Args:
            tool_path: Unused.
        """

    @override
    async def shutdown(self) -> None:
        """Skip real shutdown."""

    @override
    async def list_processes_detailed(
        self,
        filter_name: str | None = None,
    ) -> list[dict[str, int | str | float]]:
        """Return an empty list and record the call.

        Args:
            filter_name: Optional name filter (unused).

        Returns:
            list[dict[str, int | str | float]]: Always empty.
        """
        del filter_name
        self.list_calls += 1
        return []

    @override
    async def detect_architecture(self, pid: int) -> str:
        """Return scripted architecture or raise the scripted error.

        When ``arch_should_raise`` is non-None, the stored ``ToolError`` is
        propagated unchanged so callers observe the configured failure.

        Args:
            pid: Process ID to detect architecture for.

        Returns:
            str: ``arch_result`` unless ``arch_should_raise`` is set, in
            which case the scripted exception is raised instead.

        Raises:
            self.arch_should_raise: The stored ``ToolError`` instance is
                re-raised unchanged. The Raises entry uses the literal
                raise target so static analysis can correlate the body
                with the docstring.
        """
        self.arch_calls.append(pid)
        if self.arch_should_raise is not None:
            raise self.arch_should_raise
        return self.arch_result

    @override
    async def get_token_privileges(self, pid: int | None = None) -> list[dict[str, object]]:
        """Return scripted privilege list or raise the scripted error.

        When ``priv_should_raise`` is non-None, the stored ``ToolError`` is
        propagated unchanged so callers observe the configured failure.

        Args:
            pid: Process ID to query privileges for.

        Returns:
            list[dict[str, object]]: ``priv_result`` unless
            ``priv_should_raise`` is set, in which case the scripted
            exception is raised instead.

        Raises:
            self.priv_should_raise: The stored ``ToolError`` instance is
                re-raised unchanged. The Raises entry uses the literal
                raise target so static analysis can correlate the body
                with the docstring.
        """
        self.priv_calls.append(pid)
        if self.priv_should_raise is not None:
            raise self.priv_should_raise
        return self.priv_result

    @override
    async def open_process(self, pid: int, access: str = "all") -> bool:
        """Record attach and return True.

        Args:
            pid: PID to attach to.
            access: Access string (ignored).

        Returns:
            bool: Always True.
        """
        del access
        self.open_calls.append(pid)
        return True

    @override
    async def close(self) -> bool:
        """Record detach and return True.

        Returns:
            bool: Always True.
        """
        self.close_calls += 1
        return True

    @override
    async def get_process_info(self, pid: int | None = None) -> ProcessInfo | None:
        """Return None (no process info needed for these tests).

        Args:
            pid: Process ID (unused).

        Returns:
            ProcessInfo | None: Always None.
        """
        del pid
        return None

    @override
    async def get_environment(self, pid: int | None = None) -> dict[str, str]:
        """Return empty environment.

        Args:
            pid: Process ID (unused).

        Returns:
            dict[str, str]: Always empty.
        """
        del pid
        return {}

    @override
    async def suspend(self, pid: int | None = None) -> bool:
        """Stub suspend.

        Args:
            pid: Process ID (unused).

        Returns:
            bool: Always True.
        """
        del pid
        return True

    @override
    async def resume(self, pid: int | None = None) -> bool:
        """Stub resume.

        Args:
            pid: Process ID (unused).

        Returns:
            bool: Always True.
        """
        del pid
        return True

    @override
    async def terminate(self, pid: int | None = None) -> bool:
        """Stub terminate.

        Args:
            pid: Process ID (unused).

        Returns:
            bool: Always True.

        Raises:
            ValueError: When pid is None.
        """
        if pid is None:
            msg = "pid is required"
            raise ValueError(msg)
        return True

    def notify_privileges_changed(self) -> None:
        """Invoke the base bridge privilege-changed notification from test code.

        Provides a public entry point so tests do not access the protected
        ``_notify_privileges_changed`` method from outside the class hierarchy.
        """
        self._notify_privileges_changed()


@pytest.fixture
def panel(qapp: QCoreApplication) -> Generator[ProcessPanel]:
    """Create a fresh ProcessPanel and clean it up after each test.

    Args:
        qapp: Qt application fixture (ensures one QApplication exists).

    Yields:
        ProcessPanel: A ProcessPanel instance with no bridge wired.
    """
    del qapp
    widget = ProcessPanel()
    yield widget
    widget.deleteLater()


@pytest.fixture
def bridge() -> _RecordingBridge:
    """Create a recording bridge with default success behaviour.

    Returns:
        _RecordingBridge: Bridge subclass that records calls.
    """
    return _RecordingBridge()


def _simulate_attach(panel: ProcessPanel, pid: int) -> None:
    """Drive the panel through the attach state transition for ``pid``.

    Directly invokes ``_on_process_attached`` as the ProcessTab signal
    would in production, bypassing the full bridge open-process round-trip
    so tests focus only on the panel base behaviour.

    Args:
        panel: ProcessPanel to attach.
        pid: PID to attach to.
    """
    getattr(panel, "_on_process_attached")(pid)


def _simulate_detach(panel: ProcessPanel) -> None:
    """Drive the panel through the detach state transition.

    Args:
        panel: ProcessPanel to detach.
    """
    getattr(panel, "_on_process_detached")()


class TestF0001ArchLabelUpdatesOnAttach:
    """F-0001: ``_status_arch`` must update from the bridge after every attach."""

    def test_arch_label_is_dash_before_attach(self, panel: ProcessPanel) -> None:
        """Status arch label must be 'Arch: --' before any process is attached.

        Args:
            panel: ProcessPanel fixture.
        """
        assert getattr(panel, "_status_arch").text() == "Arch: --"

    def test_arch_label_updates_after_attach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Arch label must display the bridge-returned arch string after attach.

        Fails without the fix because ``_status_arch`` is never updated.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge with scripted arch result.
        """
        bridge.arch_result = "x86_64"
        panel.set_bridge(bridge)
        _simulate_attach(panel, 1234)

        success = _process_events_until(qapp, lambda: bridge.arch_calls != [])
        assert success, "detect_architecture was never called after attach"

        success = _process_events_until(qapp, lambda: getattr(panel, "_status_arch").text() != "Arch: --")
        assert success, "Arch label was not updated after attach"
        assert getattr(panel, "_status_arch").text() == "Arch: x86_64"

    def test_arch_label_resets_on_detach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Arch label must reset to 'Arch: --' after detach.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        bridge.arch_result = "x86"
        panel.set_bridge(bridge)
        _simulate_attach(panel, 999)
        _process_events_until(qapp, lambda: getattr(panel, "_status_arch").text() != "Arch: --")
        _simulate_detach(panel)
        assert getattr(panel, "_status_arch").text() == "Arch: --"

    def test_arch_label_shows_unknown_on_bridge_error(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Arch label must show 'Arch: Unknown' when the bridge raises on detect.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge configured to raise.
        """
        bridge.arch_should_raise = ToolError("access denied")
        panel.set_bridge(bridge)
        _simulate_attach(panel, 5678)

        success = _process_events_until(qapp, lambda: bridge.arch_calls != [])
        assert success
        success = _process_events_until(
            qapp,
            lambda: getattr(panel, "_status_arch").text() in {"Arch: Unknown", "Arch: --"},
        )
        assert success
        assert getattr(panel, "_status_arch").text() == "Arch: Unknown"

    def test_arch_bridge_called_with_attached_pid(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """``detect_architecture`` must be called with the exact attached PID.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        _simulate_attach(panel, 4242)
        _process_events_until(qapp, lambda: bridge.arch_calls != [])
        assert bridge.arch_calls[-1] == 4242


class TestF0002PrivilegeLabelRefreshesOnMutation:
    """F-0002: ``_status_priv`` must be read from ``get_token_privileges``, not a stale private attribute."""

    def test_priv_label_updates_after_attach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Privilege label must update from bridge after attach.

        Fails without the fix because ``_status_priv`` relied on the private
        ``_debug_privilege_enabled`` attribute which is set only at
        ``initialize()`` time and never refreshed.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge with SeDebugPrivilege enabled in result.
        """
        bridge.priv_result = [{"name": "SeDebugPrivilege", "luid": 20, "enabled": True, "attributes": 2}]
        panel.set_bridge(bridge)
        _simulate_attach(panel, 100)

        success = _process_events_until(qapp, lambda: bridge.priv_calls != [])
        assert success, "get_token_privileges was never called after attach"

        success = _process_events_until(qapp, lambda: "Debug" in getattr(panel, "_status_priv").text())
        assert success, f"Privilege label not updated to Debug; got: {getattr(panel, '_status_priv').text()}"

    def test_priv_label_standard_when_no_debug_priv(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Privilege label must show 'Standard' when SeDebugPrivilege transitions from enabled to absent.

        Drives the label to 'Debug' first via SeDebugPrivilege enabled, then fires a
        privileges_changed event with only SeChangeNotifyPrivilege so the label must
        transition back to 'Standard'.  The round-trip proves the async refresh path
        correctly responds to a privilege mutation rather than relying on the initial
        default value.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge configured to start with debug privilege enabled.
        """
        bridge.priv_result = [{"name": "SeDebugPrivilege", "luid": 20, "enabled": True, "attributes": 2}]
        panel.set_bridge(bridge)
        _simulate_attach(panel, 200)

        success = _process_events_until(qapp, lambda: "Debug" in getattr(panel, "_status_priv").text())
        assert success, f"Expected 'Debug' after attach with SeDebugPrivilege enabled; got: {getattr(panel, '_status_priv').text()}"

        initial_calls = len(bridge.priv_calls)
        bridge.priv_result = [{"name": "SeChangeNotifyPrivilege", "luid": 23, "enabled": True, "attributes": 2}]
        bridge.notify_privileges_changed()

        success = _process_events_until(qapp, lambda: len(bridge.priv_calls) > initial_calls)
        assert success, "get_token_privileges not called after privileges_changed event"

        success = _process_events_until(qapp, lambda: "Standard" in getattr(panel, "_status_priv").text())
        assert success, f"Expected 'Standard' after privilege mutation; got: {getattr(panel, '_status_priv').text()}"
        assert getattr(panel, "_status_priv").text() == "Privilege: Standard"

    def test_priv_label_refreshes_on_privileges_changed_event(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Privilege label must refresh when bridge fires ``privileges_changed``.

        Fails without the fix because the label was never subscribed to bridge
        privilege-mutation events.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        bridge.priv_result = [{"name": "SeDebugPrivilege", "luid": 20, "enabled": False, "attributes": 0}]
        panel.set_bridge(bridge)
        _simulate_attach(panel, 300)
        _process_events_until(qapp, lambda: bridge.priv_calls != [])
        initial_calls = len(bridge.priv_calls)

        bridge.priv_result = [{"name": "SeDebugPrivilege", "luid": 20, "enabled": True, "attributes": 2}]
        bridge.notify_privileges_changed()

        success = _process_events_until(qapp, lambda: len(bridge.priv_calls) > initial_calls)
        assert success, "get_token_privileges not called after privileges_changed event"

        success = _process_events_until(qapp, lambda: "Debug" in getattr(panel, "_status_priv").text())
        assert success, f"Privilege label not updated after event; got: {getattr(panel, '_status_priv').text()}"

    def test_priv_bridge_called_with_attached_pid(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """``get_token_privileges`` must be called with the attached PID.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        _simulate_attach(panel, 777)
        _process_events_until(qapp, lambda: bridge.priv_calls != [])
        assert bridge.priv_calls[-1] == 777

    def test_priv_label_resets_on_detach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Privilege label must reset to 'Privilege: Standard' after detach.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        bridge.priv_result = [{"name": "SeDebugPrivilege", "luid": 20, "enabled": True, "attributes": 2}]
        panel.set_bridge(bridge)
        _simulate_attach(panel, 888)
        _process_events_until(qapp, lambda: "Debug" in getattr(panel, "_status_priv").text())
        _simulate_detach(panel)
        assert getattr(panel, "_status_priv").text() == "Privilege: Standard"


class TestF0025ProcessButtonsGatedWhenUnattached:
    """F-0025: ``_update_controls_for_state`` must gate ProcessTab action buttons."""

    def test_suspend_disabled_when_unattached(self, panel: ProcessPanel, bridge: _RecordingBridge) -> None:
        """Suspend button must be disabled when no process is attached.

        Fails without the fix because ``_update_controls_for_state`` never
        touched the ProcessTab buttons.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_suspend_btn").isEnabled() is False

    def test_resume_disabled_when_unattached(self, panel: ProcessPanel, bridge: _RecordingBridge) -> None:
        """Resume button must be disabled when no process is attached.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_resume_btn").isEnabled() is False

    def test_detach_disabled_when_unattached(self, panel: ProcessPanel, bridge: _RecordingBridge) -> None:
        """Detach button must be disabled when no process is attached.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_detach_btn").isEnabled() is False

    def test_inject_disabled_when_unattached(self, panel: ProcessPanel, bridge: _RecordingBridge) -> None:
        """Inject button must be disabled when no process is attached.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_inject_btn").isEnabled() is False

    def test_action_buttons_enabled_after_attach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Suspend/Resume/Detach/Inject must enable after a successful attach.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        del qapp
        panel.set_bridge(bridge)
        _simulate_attach(panel, 555)

        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_suspend_btn").isEnabled() is True
        assert getattr(proc_tab, "_resume_btn").isEnabled() is True
        assert getattr(proc_tab, "_detach_btn").isEnabled() is True
        assert getattr(proc_tab, "_inject_btn").isEnabled() is True

    def test_action_buttons_disabled_after_detach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Suspend/Resume/Detach/Inject must disable after detach.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        del qapp
        panel.set_bridge(bridge)
        _simulate_attach(panel, 666)
        _simulate_detach(panel)

        proc_tab = getattr(panel, "_process_tab")
        assert getattr(proc_tab, "_suspend_btn").isEnabled() is False
        assert getattr(proc_tab, "_resume_btn").isEnabled() is False
        assert getattr(proc_tab, "_detach_btn").isEnabled() is False
        assert getattr(proc_tab, "_inject_btn").isEnabled() is False

    def test_attach_always_enabled_with_selection(
        self,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Attach button must be enabled when a process is selected.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        setattr(proc_tab, "_selected_pid", 9999)
        getattr(panel, "_update_controls_for_state")()
        assert getattr(proc_tab, "_attach_btn").isEnabled() is True

    def test_terminate_enabled_with_selection_not_attach(
        self,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Terminate must be enabled whenever a row is selected (not only when attached).

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        proc_tab = getattr(panel, "_process_tab")
        setattr(proc_tab, "_selected_pid", 1111)
        getattr(panel, "_update_controls_for_state")()
        assert getattr(proc_tab, "_terminate_btn").isEnabled() is True


def _overlays(panel: ProcessPanel) -> list[AttachHintOverlay]:
    """Return all of the panel's hint overlay widgets.

    Args:
        panel: ProcessPanel to inspect.

    Returns:
        list[AttachHintOverlay]: Every overlay, one per detail tab.
    """
    return list(getattr(panel, "_hint_overlays"))


def _attach_overlays(panel: ProcessPanel) -> list[AttachHintOverlay]:
    """Return the overlays for the attachment-gated detail tabs only.

    Args:
        panel: ProcessPanel to inspect.

    Returns:
        list[AttachHintOverlay]: Overlays for Memory, Threads, and Modules.
    """
    return list(getattr(panel, "_attach_overlays"))


def _system_overlay(panel: ProcessPanel) -> AttachHintOverlay:
    """Return the System tab overlay.

    Args:
        panel: ProcessPanel to inspect.

    Returns:
        AttachHintOverlay: The overlay covering the System tab.
    """
    return getattr(panel, "_system_overlay")


def _system_tab(panel: ProcessPanel) -> QWidget:
    """Return the System detail tab widget.

    Args:
        panel: ProcessPanel to inspect.

    Returns:
        QWidget: The System tab.
    """
    return getattr(panel, "_system_tab")


def _overlay_text(overlay: AttachHintOverlay) -> str:
    """Read the message text currently shown by an overlay.

    Args:
        overlay: An ``AttachHintOverlay`` instance.

    Returns:
        str: The overlay label's current text.
    """
    return str(getattr(overlay, "_label").text())


class TestAttachHintOverlay:
    """Gated detail tabs must surface an instructional overlay instead of silent dead tabs."""

    def test_one_overlay_per_detail_tab(self, panel: ProcessPanel) -> None:
        """Every gated detail tab must own exactly one overlay parented to it.

        Args:
            panel: ProcessPanel fixture.
        """
        detail_tabs = list(getattr(panel, "_detail_tabs"))
        overlays = _overlays(panel)
        assert len(overlays) == len(detail_tabs) == 4
        for overlay, tab in zip(overlays, detail_tabs, strict=True):
            assert overlay.parentWidget() is tab

    def test_overlays_show_no_bridge_message_before_bridge(self, panel: ProcessPanel) -> None:
        """A disconnected panel must show the no-bridge hint on all detail tabs.

        Fails without the fix because the gated tabs were left blank and
        non-interactive with no explanation.

        Args:
            panel: ProcessPanel fixture.
        """
        for overlay in _overlays(panel):
            assert overlay.isHidden() is False
            text = _overlay_text(overlay)
            assert "bridge unavailable" in text
            assert "Attach to a process first" not in text

    def test_attach_overlays_show_attach_message_when_detached(
        self,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """With a bridge but no attachment, per-process overlays must say to attach first.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        for overlay in _attach_overlays(panel):
            assert overlay.isHidden() is False
            assert "Attach to a process first" in _overlay_text(overlay)

    def test_overlays_hidden_after_attach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Attaching to a process must hide every overlay so the tabs are usable.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        del qapp
        panel.set_bridge(bridge)
        _simulate_attach(panel, 4242)
        for overlay in _overlays(panel):
            assert overlay.isHidden() is True

    def test_attach_overlays_reappear_after_detach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Detaching must restore the attach-first overlay on the per-process tabs.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        del qapp
        panel.set_bridge(bridge)
        _simulate_attach(panel, 4243)
        _simulate_detach(panel)
        for overlay in _attach_overlays(panel):
            assert overlay.isHidden() is False
            assert "Attach to a process first" in _overlay_text(overlay)


class TestSystemTabConnectionGating:
    """The System tab exposes system-wide operations and must be gated on connection, not attach."""

    def test_system_tab_disabled_and_hinted_when_disconnected(self, panel: ProcessPanel) -> None:
        """Without a bridge the System tab is disabled and shows the no-bridge hint.

        Args:
            panel: ProcessPanel fixture.
        """
        assert _system_tab(panel).isEnabled() is False
        overlay = _system_overlay(panel)
        assert overlay.isHidden() is False
        assert "bridge unavailable" in _overlay_text(overlay)

    def test_system_tab_enabled_when_detached(
        self,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """A connected-but-detached panel must enable the System tab and hide its overlay.

        Fails without the fix because the System tab was gated behind the
        ATTACHED state despite exposing system-wide (registry/pipe/system-info)
        operations that need only a connected bridge.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        assert _system_tab(panel).isEnabled() is True
        assert _system_overlay(panel).isHidden() is True

    def test_per_process_tabs_stay_gated_when_detached(
        self,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """Memory/Threads/Modules must remain disabled while only connected.

        Args:
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        panel.set_bridge(bridge)
        gated_tabs: list[QWidget] = list(getattr(panel, "_attach_gated_tabs"))
        for tab in gated_tabs:
            assert tab.isEnabled() is False

    def test_system_tab_enabled_after_attach(
        self,
        qapp: QCoreApplication,
        panel: ProcessPanel,
        bridge: _RecordingBridge,
    ) -> None:
        """The System tab remains enabled with its overlay hidden after attach.

        Args:
            qapp: Qt application.
            panel: ProcessPanel fixture.
            bridge: Recording bridge.
        """
        del qapp
        panel.set_bridge(bridge)
        _simulate_attach(panel, 7373)
        assert _system_tab(panel).isEnabled() is True
        assert _system_overlay(panel).isHidden() is True
