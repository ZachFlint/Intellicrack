# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings in ``process_panel.base``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``test_h10_*`` (H10): the bridge's privileges-changed callback must be a
  thread-safe Qt-signal relay, never the GUI handler itself. Invoking the
  registered callback from a background thread (exactly as
  ``ProcessBridge._notify_privileges_changed`` does from the persistent
  bridge event-loop thread) must not run ``_refresh_privilege_label``
  synchronously on that thread; the handler must only execute once the GUI
  thread's event loop delivers the queued signal.
* ``test_m26_*`` (M26): ``ProcessPanel`` teardown, and bridge replacement via
  ``set_bridge``, must release the OS handles (device, pipe, section) the
  current ``ProcessBridge`` tracked during the session by dispatching the
  bridge's real ``shutdown()`` coroutine, instead of leaking them.

All tests drive a real :class:`ProcessPanel` and a real :class:`ProcessBridge`
under an offscreen QApplication; no bridge or panel behaviour is mocked or
stubbed.
"""

from __future__ import annotations

import ctypes
import threading
import time
from typing import TYPE_CHECKING, Final, override

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import ProcessPanel


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication, QWidget


_MAX_WAIT_S: Final[float] = 3.0
_POLL_INTERVAL_S: Final[float] = 0.01
_JOIN_TIMEOUT_S: Final[float] = 5.0


def _pump_until(qapp: QApplication, predicate: Callable[[], bool]) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or time runs out.

    Args:
        qapp: The shared QApplication whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + _MAX_WAIT_S
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


class _ThreadRecordingProcessPanel(ProcessPanel):
    """``ProcessPanel`` subclass that records which thread refreshes privileges.

    Delegates to the real :meth:`ProcessPanel._refresh_privilege_label`
    immediately after recording the calling thread's identity, so the
    production refresh logic still executes unmodified; only the calling
    thread is observed.

    Attributes:
        refresh_privilege_threads: Thread identities that invoked
            ``_refresh_privilege_label``, in call order.
    """

    refresh_privilege_threads: list[int]

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the recording panel with an empty thread-id log.

        Args:
            parent: Parent widget, forwarded to ``ProcessPanel``.
        """
        self.refresh_privilege_threads = []
        super().__init__(parent)

    @override
    def _refresh_privilege_label(self) -> None:
        """Record the calling thread, then run the real refresh logic."""
        self.refresh_privilege_threads.append(threading.get_ident())
        super()._refresh_privilege_label()


class TestPrivilegesChangedThreadSafety:
    """H10: the bridge privileges-changed callback must be thread-safe."""

    def test_h10_set_bridge_registers_signal_relay_not_gui_handler(self, qapp: QApplication) -> None:
        """``set_bridge`` must register ``_emit_privileges_changed``, not the GUI handler.

        Pre-fix, ``set_bridge`` registered ``self._on_privileges_changed``
        directly with the bridge, so the bridge's background event-loop
        thread would invoke GUI-mutating logic in-place. The fix must
        register the Qt-signal-emitting relay instead.

        Args:
            qapp: The shared QApplication fixture.
        """
        del qapp
        panel = ProcessPanel()
        try:
            bridge = ProcessBridge()
            panel.set_bridge(bridge)

            assert panel._emit_privileges_changed in bridge._privileges_changed_callbacks, (
                "the thread-safe relay was not registered with the bridge"
            )
            assert panel._on_privileges_changed not in bridge._privileges_changed_callbacks, (
                "the GUI handler was registered directly with the bridge instead of the signal relay"
            )
        finally:
            panel.deleteLater()

    def test_h10_replacing_bridge_deregisters_relay_not_gui_handler(self, qapp: QApplication) -> None:
        """Replacing the bridge must remove the relay callback from the old bridge.

        Args:
            qapp: The shared QApplication fixture.
        """
        del qapp
        panel = ProcessPanel()
        try:
            old_bridge = ProcessBridge()
            panel.set_bridge(old_bridge)
            assert panel._emit_privileges_changed in old_bridge._privileges_changed_callbacks

            panel.set_bridge(ProcessBridge())
            assert panel._emit_privileges_changed not in old_bridge._privileges_changed_callbacks, (
                "the relay callback was not removed from the previous bridge"
            )
        finally:
            panel.deleteLater()

    def test_h10_background_notification_does_not_run_handler_synchronously(self, qapp: QApplication) -> None:
        """A background-thread bridge notification must not run the handler in-place.

        Simulates exactly what ``ProcessBridge._notify_privileges_changed``
        does when invoked from the persistent bridge event-loop thread (see
        ``adjust_token_privilege``): it calls every registered callback from
        a plain background ``threading.Thread``, never the Qt GUI thread.

        Pre-fix, the registered callback was ``_on_privileges_changed``
        itself, so ``_refresh_privilege_label`` (and the ``BridgeCallWorker``
        it constructs with ``parent=self``) would run synchronously on that
        background thread -- an invalid cross-thread Qt operation. This test
        asserts the handler has not run at all immediately after the
        background thread finishes, and only runs -- on the GUI thread --
        once the Qt event loop is pumped.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = _ThreadRecordingProcessPanel()
        try:
            bridge = ProcessBridge()
            panel.set_bridge(bridge)
            panel._attached_pid = 4321

            caller_thread_id: list[int] = []

            def _invoke_from_background() -> None:
                caller_thread_id.append(threading.get_ident())
                bridge._notify_privileges_changed()

            worker_thread = threading.Thread(target=_invoke_from_background, name="fake-bridge-event-loop")
            worker_thread.start()
            worker_thread.join(timeout=_JOIN_TIMEOUT_S)

            assert not worker_thread.is_alive(), "background notification thread did not finish"
            assert caller_thread_id, "background thread never invoked the bridge notification"
            assert caller_thread_id[0] != threading.get_ident(), "test setup error: notification ran on the GUI thread"

            assert panel.refresh_privilege_threads == [], (
                "the GUI handler ran synchronously on the background notification thread instead of being queued through a Qt signal"
            )

            delivered = _pump_until(qapp, lambda: bool(panel.refresh_privilege_threads))
            assert delivered, "the queued privileges-changed notification was never delivered to the GUI thread"
            assert panel.refresh_privilege_threads[0] == threading.get_ident(), (
                "privilege refresh executed on a thread other than the GUI thread that owns the panel"
            )
        finally:
            panel.deleteLater()


def _bridge_with_fake_handles(kernel32: ctypes.WinDLL) -> ProcessBridge:
    """Build a real ``ProcessBridge`` carrying fake tracked OS handles.

    Args:
        kernel32: A live ``kernel32`` DLL handle used to close the fake
            handles for real, exercising the same ``CloseHandle`` path
            ``ProcessBridge.shutdown`` uses in production.

    Returns:
        ProcessBridge: An uninitialized bridge with populated
            ``_device_handles``, ``_pipe_handles``, and ``_section_handles``
            tracking dicts.
    """
    bridge = ProcessBridge()
    bridge._kernel32 = kernel32
    bridge._device_handles[0x1001] = r"\\.\FakeDevice"
    bridge._pipe_handles[0x1002] = r"\\.\pipe\FakePipe"
    bridge._section_handles[0x1003] = "FakeSection"
    return bridge


class TestBridgeResourceTeardown:
    """M26: panel teardown and bridge replacement must release bridge handles."""

    def test_m26_cleanup_releases_bridge_tracked_os_handles(self, qapp: QApplication) -> None:
        """``stop_tool`` must dispatch ``bridge.shutdown()`` and clear tracked handles.

        Pre-fix, ``ProcessPanel._cleanup`` only called ``cleanup()`` on the
        process and threads tabs and never touched the bridge at all, so a
        device handle, pipe handle, and section handle opened through the
        System tab stayed in the bridge's tracking dicts (and the
        underlying Win32 handles stayed open) for the remaining lifetime of
        the bridge. This drives the real ``ProcessBridge.shutdown()``
        coroutine through the panel's teardown path and asserts every
        tracked dict is actually cleared.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = ProcessPanel()
        try:
            bridge = _bridge_with_fake_handles(ctypes.windll.kernel32)
            panel.set_bridge(bridge)

            assert panel.stop_tool()

            released = _pump_until(qapp, lambda: not (bridge._device_handles or bridge._pipe_handles or bridge._section_handles))
            assert released, "bridge.shutdown() was never dispatched from panel teardown"
            assert bridge._device_handles == {}, "device handle leaked past panel teardown"
            assert bridge._pipe_handles == {}, "pipe handle leaked past panel teardown"
            assert bridge._section_handles == {}, "section handle leaked past panel teardown"
        finally:
            panel.deleteLater()

    def test_m26_set_bridge_shuts_down_previous_bridges_handles(self, qapp: QApplication) -> None:
        """Replacing the bridge via ``set_bridge`` must shut down the old bridge's handles.

        Pre-fix, ``set_bridge`` silently dropped the reference to the
        previous bridge without releasing anything it tracked, leaking
        every open device/pipe/section handle held by the bridge being
        replaced. This asserts the previous bridge's tracked handles are
        actually cleared once the new bridge is installed.

        Args:
            qapp: The shared QApplication fixture.
        """
        panel = ProcessPanel()
        try:
            old_bridge = _bridge_with_fake_handles(ctypes.windll.kernel32)
            panel.set_bridge(old_bridge)

            new_bridge = ProcessBridge()
            panel.set_bridge(new_bridge)

            released = _pump_until(qapp, lambda: not old_bridge._device_handles)
            assert released, "the previous bridge's handles were never released on bridge swap"
            assert old_bridge._device_handles == {}, "previous bridge's device handle leaked across a bridge swap"
            assert old_bridge._pipe_handles == {}, "previous bridge's pipe handle leaked across a bridge swap"
            assert old_bridge._section_handles == {}, "previous bridge's section handle leaked across a bridge swap"
            assert panel.get_bridge() is new_bridge
        finally:
            panel.deleteLater()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
