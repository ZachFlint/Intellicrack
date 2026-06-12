# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Production-grade tests for audit4 B2: ProcessTab findings F-0013 through F-0018.

Each test class addresses one audit finding and is structured so that
the test would have failed against the original defective code and passes
on the fixed implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtCore import QTimer


# ---------------------------------------------------------------------------
# Test-only subclass that exposes controlled state access
# ---------------------------------------------------------------------------


def _fire_slot(_ms: int, slot: Callable[[], None]) -> None:
    """Invoke a QTimer.singleShot slot immediately for testing.

    Args:
        _ms: Timer interval (ignored in tests).
        slot: Slot callable to invoke immediately.
    """
    slot()


class _TestProcessTab(ProcessTab):
    """ProcessTab subclass for testing that exposes internal state via public methods.

    This avoids direct access to single-underscore private attributes from
    outside the class hierarchy, satisfying basedpyright's reportPrivateUsage
    check while still allowing tests to reach internal state. Instance
    counters refresh_tracked_calls and on_refresh_calls track calls to
    the overridden _refresh_tracked and _on_refresh methods.
    """

    def __init__(self, parent: None = None) -> None:
        """Initialize the test tab with call counters.

        Args:
            parent: Parent widget (always None in tests).
        """
        super().__init__(parent)
        self.refresh_tracked_calls: int = 0
        self.on_refresh_calls: int = 0

    def get_selected_pid_state(self) -> int | None:
        """Return the currently selected PID.

        Returns:
            int | None: The selected PID or None.
        """
        return self._selected_pid

    def set_selected_pid_state(self, pid: int | None) -> None:
        """Set the selected PID for testing.

        Args:
            pid: PID to set or None.
        """
        self._selected_pid = pid

    def get_attached_pid_state(self) -> int | None:
        """Return the currently attached PID.

        Returns:
            int | None: The attached PID or None.
        """
        return self._attached_pid

    def set_attached_pid_state(self, pid: int | None) -> None:
        """Set the attached PID for testing.

        Args:
            pid: PID to set or None.
        """
        self._attached_pid = pid

    def get_filter_debounce_timer(self) -> QTimer:
        """Return the filter debounce timer.

        Returns:
            QTimer: The debounce timer instance.
        """
        return self._filter_debounce_timer

    def get_filter_refresh_pending(self) -> bool:
        """Return whether a filter refresh is pending.

        Returns:
            bool: True if a filter refresh is pending.
        """
        return self._filter_refresh_pending

    def set_filter_refresh_in_flight(self, *, value: bool) -> None:
        """Set the in-flight refresh flag for testing.

        Args:
            value: Whether a refresh is in flight.
        """
        self._filter_refresh_in_flight = value

    def get_filter_refresh_in_flight(self) -> bool:
        """Return whether a filter refresh is currently in flight.

        Returns:
            bool: True if a refresh is in flight.
        """
        return self._filter_refresh_in_flight

    def _refresh_tracked(self) -> None:
        """Override to count calls instead of spawning a worker thread."""
        self.refresh_tracked_calls += 1

    def _on_refresh(self) -> None:
        """Override to count calls instead of calling the bridge."""
        self.on_refresh_calls += 1

    def invoke_on_filter_changed(self, text: str) -> None:
        """Invoke the filter changed handler for testing.

        Args:
            text: Filter text to pass.
        """
        self._on_filter_changed(text)

    def invoke_on_inject_dll(self) -> None:
        """Invoke the inject DLL handler for testing."""
        self._on_inject_dll()

    def invoke_on_attach(self) -> None:
        """Invoke the attach handler for testing."""
        self._on_attach()

    def invoke_on_suspend(self) -> None:
        """Invoke the suspend handler for testing."""
        self._on_suspend()

    def invoke_on_resume(self) -> None:
        """Invoke the resume handler for testing."""
        self._on_resume()

    def invoke_on_terminate(self) -> None:
        """Invoke the terminate handler for testing."""
        self._on_terminate()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def bridge() -> ProcessBridge:
    """Create an unattached ProcessBridge for use in tests.

    Returns:
        ProcessBridge: Uninitialized ProcessBridge instance.
    """
    return ProcessBridge()


@pytest.fixture
def tab(qapp: QApplication, bridge: ProcessBridge) -> Generator[_TestProcessTab]:
    """Create a _TestProcessTab with a bridge set, clean up after test.

    Args:
        qapp: QApplication session fixture.
        bridge: ProcessBridge fixture.

    Yields:
        Generator[_TestProcessTab]: The tab instance.
    """
    del qapp
    t = _TestProcessTab()
    t.set_bridge(bridge)
    yield t
    t.deleteLater()


# ---------------------------------------------------------------------------
# F-0013: inject button requires attachment before dispatching bridge call
# ---------------------------------------------------------------------------


class TestF0013InjectRequiresAttachment:
    """F-0013: _on_inject_dll must guard on _attached_pid and warn when unattached."""

    def test_inject_warns_when_no_process_attached(self, tab: _TestProcessTab) -> None:
        """Calling inject without attachment must show a "Not Attached" warning dialog and never dispatch the bridge.

        Three properties are verified against independent known-correct constants:
        1. Exactly one QMessageBox.warning call is made (the guard fires exactly once).
        2. The warning title is exactly "Not Attached".
        3. The warning message body mentions both "No process is currently attached" and
           "Attach to a process before injecting a DLL" — the exact strings present in the
           production guard at _on_inject_dll.
        4. run_bridge_coroutine_logged is never called, confirming the bridge inject path
           is not dispatched when the guard fires.

        Args:
            tab: _TestProcessTab fixture (bridge is set, no PID attached).
        """
        assert tab.get_attached_pid_state() is None

        warning_calls: list[tuple[object, ...]] = []
        bridge_dispatch_calls: list[object] = []

        def _capture_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(_args)
            return QMessageBox.StandardButton.Ok

        def _capture_bridge_dispatch(*_args: object, **_kwargs: object) -> None:
            bridge_dispatch_calls.append(_args)

        with (
            patch.object(QMessageBox, "warning", side_effect=_capture_warning),
            patch(
                "intellicrack.ui.panels.process_panel.process_tab.run_bridge_coroutine_logged",
                side_effect=_capture_bridge_dispatch,
            ),
        ):
            tab.invoke_on_inject_dll()

        assert len(warning_calls) == 1, (
            f"_on_inject_dll must show exactly one warning when no process is attached; got {len(warning_calls)}"
        )

        call_args = warning_calls[0]
        assert len(call_args) >= 3, (
            f"QMessageBox.warning must be called with at least 3 positional args (parent, title, message); got {len(call_args)}"
        )
        actual_title = str(call_args[1])
        actual_message = str(call_args[2])

        assert actual_title == "Not Attached", f"Warning title must be exactly 'Not Attached'; got {actual_title!r}"
        assert "No process is currently attached" in actual_message, (
            f"Warning message must contain 'No process is currently attached'; got {actual_message!r}"
        )
        assert "Attach to a process before injecting a DLL" in actual_message, (
            f"Warning message must contain 'Attach to a process before injecting a DLL'; got {actual_message!r}"
        )

        assert len(bridge_dispatch_calls) == 0, (
            "_on_inject_dll must not dispatch the bridge (run_bridge_coroutine_logged) when no process is attached"
        )

    def test_inject_does_not_warn_when_attached(self, tab: _TestProcessTab) -> None:
        """When a process is attached, inject must not show the no-attachment warning.

        After attaching (setting _attached_pid), the inject path should proceed
        to the file dialog, not immediately show a "Not Attached" warning.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_attached_pid_state(1234)
        warning_calls: list[tuple[Any, ...]] = []

        def _capture_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_calls.append(_args)
            return QMessageBox.StandardButton.No

        with (
            patch.object(QMessageBox, "warning", side_effect=_capture_warning),
            patch(
                "intellicrack.ui.panels.process_panel.process_tab.QFileDialog.getOpenFileName",
                return_value=("", ""),
            ),
        ):
            tab.invoke_on_inject_dll()

        for call_args in warning_calls:
            if len(call_args) >= 2:
                title = str(call_args[1])
                assert "not attached" not in title.lower(), "_on_inject_dll must not show 'Not Attached' warning when already attached"


# ---------------------------------------------------------------------------
# F-0014: filter uses trailing-edge debounce, not immediate bridge round-trip
# ---------------------------------------------------------------------------


class TestF0014FilterDebounce:
    """F-0014: _on_filter_changed must use a trailing-edge debounce timer."""

    def test_filter_change_arms_debounce_timer(self, tab: _TestProcessTab) -> None:
        """Typing a character must arm the debounce timer, not fire immediately.

        The old bug called _on_refresh (which calls the bridge) on every
        keystroke. The fix arms a QTimer with _FILTER_DEBOUNCE_MS delay.

        Args:
            tab: _TestProcessTab fixture.
        """
        timer = tab.get_filter_debounce_timer()
        assert not timer.isActive(), "debounce timer should start inactive"

        tab.invoke_on_filter_changed("notepad")

        assert timer.isActive(), "debounce timer must be active immediately after filter change"

    def test_filter_change_while_in_flight_marks_pending(self, tab: _TestProcessTab) -> None:
        """Filter change during an in-flight refresh must mark pending flag, not start timer.

        If a bridge refresh is in flight, the new keystroke should set
        _filter_refresh_pending=True so the next refresh picks up the latest
        filter text, rather than starting a second concurrent bridge call.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_filter_refresh_in_flight(value=True)
        timer = tab.get_filter_debounce_timer()
        timer.stop()

        tab.invoke_on_filter_changed("calc")

        assert not timer.isActive(), "debounce timer must NOT be started when a refresh is already in flight"
        assert tab.get_filter_refresh_pending(), "_filter_refresh_pending must be True when filter changes during in-flight refresh"

    def test_multiple_filter_changes_keep_timer_active(self, tab: _TestProcessTab) -> None:
        """Rapid keystrokes must keep the debounce timer active (not fire multiple times).

        Each call re-arms the timer; the timer must remain active (not fire)
        during rapid successive calls.

        Args:
            tab: _TestProcessTab fixture.
        """
        timer = tab.get_filter_debounce_timer()

        tab.invoke_on_filter_changed("a")
        tab.invoke_on_filter_changed("ab")
        tab.invoke_on_filter_changed("abc")

        assert timer.isActive(), "debounce timer must still be active after rapid successive filter changes"


# ---------------------------------------------------------------------------
# F-0015: _on_attach surfaces failure via error callback
# ---------------------------------------------------------------------------


class TestF0015AttachSurfacesFailure:
    """F-0015: _on_attach must route bridge failures to a user-visible warning dialog."""

    def test_attach_error_callback_shows_warning_dialog(
        self,
        tab: _TestProcessTab,
    ) -> None:
        """When the bridge raises during attach, a QMessageBox warning must appear.

        The old defect had no error callback — failures were silently dropped.
        The fix wires an _on_error handler that calls QMessageBox.warning.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_selected_pid_state(9999)
        warning_shown: list[bool] = []

        def _capture_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_shown.append(True)
            return QMessageBox.StandardButton.Ok

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            _on_success: object,
            on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_error):
                on_error(RuntimeError("simulated attach failure"))

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", side_effect=_capture_warning),
        ):
            tab.invoke_on_attach()

        assert len(warning_shown) > 0, "_on_attach error callback must show a QMessageBox warning on failure"

    def test_attach_success_sets_attached_pid(self, tab: _TestProcessTab) -> None:
        """When the bridge succeeds, _attached_pid must be set to the target PID.

        Args:
            tab: _TestProcessTab fixture.
        """
        target_pid = 7777
        tab.set_selected_pid_state(target_pid)

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_success):
                on_success(None)

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "information", return_value=None),
        ):
            tab.invoke_on_attach()

        assert tab.get_attached_pid_state() == target_pid, "_on_attach success callback must set _attached_pid to the attached PID"


# ---------------------------------------------------------------------------
# F-0016: suspend/resume have error callbacks
# ---------------------------------------------------------------------------


class TestF0016SuspendResumeHaveErrorCallbacks:
    """F-0016: suspend and resume must surface bridge errors via warning dialogs."""

    def test_suspend_error_callback_shows_warning(self, tab: _TestProcessTab) -> None:
        """_on_suspend must pass an error callback that shows a warning dialog.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_selected_pid_state(1111)
        warning_shown: list[bool] = []

        def _capture_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_shown.append(True)
            return QMessageBox.StandardButton.Ok

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            _on_success: object,
            on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_error):
                on_error(RuntimeError("suspend failed"))

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", side_effect=_capture_warning),
        ):
            tab.invoke_on_suspend()

        assert len(warning_shown) > 0, "_on_suspend must show a warning dialog when the bridge raises"

    def test_resume_error_callback_shows_warning(self, tab: _TestProcessTab) -> None:
        """_on_resume must pass an error callback that shows a warning dialog.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_selected_pid_state(2222)
        warning_shown: list[bool] = []

        def _capture_warning(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
            warning_shown.append(True)
            return QMessageBox.StandardButton.Ok

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            _on_success: object,
            on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_error):
                on_error(RuntimeError("resume failed"))

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", side_effect=_capture_warning),
        ):
            tab.invoke_on_resume()

        assert len(warning_shown) > 0, "_on_resume must show a warning dialog when the bridge raises"


# ---------------------------------------------------------------------------
# F-0017: _on_terminate refreshes both system list and Tracked sub-tab
# ---------------------------------------------------------------------------


class TestF0017TerminateRefreshesBothTabs:
    """F-0017: _on_terminate success must refresh both system list and Tracked sub-tab."""

    def test_terminate_success_triggers_tracked_refresh(
        self,
        tab: _TestProcessTab,
    ) -> None:
        """After termination succeeds, _refresh_tracked must be called.

        The old defect only refreshed the system process list. The fix
        schedules both _on_refresh and _refresh_tracked via QTimer.singleShot.

        The _TestProcessTab subclass overrides both methods to count calls,
        so this test verifies both are invoked after a successful termination.

        Args:
            tab: _TestProcessTab fixture.
        """
        tab.set_selected_pid_state(3333)

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_success):
                on_success(None)

        before_refresh_tracked = tab.refresh_tracked_calls
        before_on_refresh = tab.on_refresh_calls

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes),
            patch(
                "intellicrack.ui.panels.process_panel.process_tab.QTimer.singleShot",
                side_effect=_fire_slot,
            ),
        ):
            tab.invoke_on_terminate()

        assert tab.refresh_tracked_calls > before_refresh_tracked, "_on_terminate success must call _refresh_tracked"
        assert tab.on_refresh_calls > before_on_refresh, "_on_terminate success must call _on_refresh"


# ---------------------------------------------------------------------------
# F-0018: _on_terminate detaches panel state when terminated PID is attached
# ---------------------------------------------------------------------------


class TestF0018TerminateDetachesIfAttached:
    """F-0018: _on_terminate must clear _attached_pid and emit process_detached signal."""

    def test_terminate_attached_pid_clears_attached_state(
        self,
        tab: _TestProcessTab,
    ) -> None:
        """When the terminated PID is the currently attached PID, clear attachment.

        The old defect did not clear _attached_pid after terminating it,
        leaving stale state. The fix checks if the terminated PID equals
        _attached_pid and emits process_detached.

        Args:
            tab: _TestProcessTab fixture.
        """
        attached_pid = 5555
        tab.set_selected_pid_state(attached_pid)
        tab.set_attached_pid_state(attached_pid)

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_success):
                on_success(None)

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes),
            patch(
                "intellicrack.ui.panels.process_panel.process_tab.QTimer.singleShot",
                side_effect=_fire_slot,
            ),
        ):
            tab.invoke_on_terminate()

        assert tab.get_attached_pid_state() is None, "_on_terminate must set _attached_pid = None when the attached PID is terminated"

    def test_terminate_unattached_pid_does_not_clear_attachment(
        self,
        tab: _TestProcessTab,
    ) -> None:
        """When a non-attached PID is terminated, attachment state must not change.

        Terminating a different process than the one attached must leave
        _attached_pid intact and must NOT emit process_detached.

        Args:
            tab: _TestProcessTab fixture.
        """
        attached_pid = 4444
        other_pid = 8888
        tab.set_selected_pid_state(other_pid)
        tab.set_attached_pid_state(attached_pid)

        def _fake_run_bridge_coroutine_async(
            _coro: object,
            on_success: object,
            _on_error: object,
            _parent: object,
        ) -> None:
            if callable(on_success):
                on_success(None)

        with (
            patch(
                "intellicrack.ui.panels.async_bridge.run_bridge_coroutine_async",
                side_effect=_fake_run_bridge_coroutine_async,
            ),
            patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes),
            patch(
                "intellicrack.ui.panels.process_panel.process_tab.QTimer.singleShot",
                side_effect=_fire_slot,
            ),
        ):
            tab.invoke_on_terminate()

        assert tab.get_attached_pid_state() == attached_pid, "_on_terminate must not clear _attached_pid when a different PID is terminated"
