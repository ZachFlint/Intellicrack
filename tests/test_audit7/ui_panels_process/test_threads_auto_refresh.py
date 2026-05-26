# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for audit7 F-0012: ThreadsTab auto-refresh of thread combos.

The unit verifies that ``ThreadsTab`` exposes an auto-refresh toggle button
and a ``QTimer``-backed 3-second polling cycle, mirroring the pattern used
by ``ProcessTab``. The tests confirm that:

* A new auto-refresh button exists and is wired to the toggle slot.
* Activating auto-refresh starts a ``QTimer`` that calls ``_refresh_threads``
  more than once over a 7000 ms window.
* Newly created threads in the target process appear in the per-tab thread
  combos without a manual Refresh click.
* Disabling auto-refresh stops the timer so the call count plateaus.
* ``cleanup()`` stops the timer for panel teardown.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from PyQt6.QtCore import Qt

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ThreadInfo
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QComboBox, QPushButton
    from pytestqt.qtbot import QtBot


_ATTACHED_PID: int = 1234
_AUTO_REFRESH_WAIT_MS: int = 7000
_AUTO_REFRESH_INTERVAL_MS: int = 3000


class _TestThreadsTab(ThreadsTab):
    """ThreadsTab subclass exposing internal Qt members through public accessors.

    Tests must reach into protected state to assert timer/button behavior; the
    subclass exposes only what is needed, satisfying basedpyright's
    ``reportPrivateUsage`` check while keeping the public ``ThreadsTab``
    surface untouched.
    """

    def get_auto_refresh_button(self) -> QPushButton:
        """Return the Auto-Refresh toggle button.

        Returns:
            QPushButton: The toggle button instance.
        """
        return self._auto_refresh_btn

    def get_auto_refresh_timer(self) -> QTimer:
        """Return the auto-refresh QTimer.

        Returns:
            QTimer: The polling timer instance.
        """
        return self._auto_refresh_timer

    def get_reg_combo(self) -> QComboBox:
        """Return the registers-tab thread combo.

        Returns:
            QComboBox: Combo populated with TIDs for register selection.
        """
        return self._reg_combo

    def get_stack_combo(self) -> QComboBox:
        """Return the stack-walk-tab thread combo.

        Returns:
            QComboBox: Combo populated with TIDs for stack walking.
        """
        return self._stack_combo

    def get_seh_combo(self) -> QComboBox:
        """Return the SEH-tab thread combo.

        Returns:
            QComboBox: Combo populated with TIDs for SEH enumeration.
        """
        return self._seh_combo

    def get_fiber_combo(self) -> QComboBox:
        """Return the fiber-tab thread combo.

        Returns:
            QComboBox: Combo populated with TIDs for fiber data inspection.
        """
        return self._fiber_combo

    def get_tls_combo(self) -> QComboBox:
        """Return the TLS-tab thread combo.

        Returns:
            QComboBox: Combo populated with TIDs for TLS slot inspection.
        """
        return self._tls_thread_combo

    def invoke_auto_refresh_toggle(self, *, checked: bool) -> None:
        """Invoke the protected toggle handler for testing.

        Args:
            checked: Whether auto-refresh is being turned on.
        """
        self._on_auto_refresh_toggled(checked=checked)


class _RefreshCounter:
    """Counts invocations of ``run_bridge_coroutine_async`` and feeds evolving thread lists.

    Each call dispatches the next batch of ThreadInfo into the supplied
    success callback synchronously, simulating the bridge's behavior of
    discovering newly created threads on each polling cycle.
    """

    def __init__(self, batches: list[list[ThreadInfo]]) -> None:
        """Initialize the counter with successive thread batches.

        Args:
            batches: Sequence of ThreadInfo lists; one is consumed per call.
                After exhaustion the last batch is reused.
        """
        self._batches: list[list[ThreadInfo]] = batches
        self.calls: int = 0

    def __call__(
        self,
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None,
        _on_error: Callable[[object], None] | None,
        _parent: object,
    ) -> None:
        """Synchronously invoke the success callback with the next batch.

        Args:
            coro: The bridge coroutine, closed here to avoid asyncio warnings.
            on_success: Callback to receive the batch.
            _on_error: Error callback (unused).
            _parent: Owning QObject (unused).
        """
        coro.close()
        idx = min(self.calls, len(self._batches) - 1)
        self.calls += 1
        if on_success is not None:
            on_success(self._batches[idx])


def _make_threads(tids: list[int]) -> list[ThreadInfo]:
    """Build a list of ThreadInfo records for the given thread IDs.

    Args:
        tids: Thread IDs to materialize.

    Returns:
        list[ThreadInfo]: One ThreadInfo per supplied TID.
    """
    return [ThreadInfo(tid=t, start_address=0x401000, current_pc=0x401050, state="running") for t in tids]


def _combo_tids(combo: QComboBox) -> list[object]:
    """Collect all userData entries in a combo box.

    Args:
        combo: The QComboBox to enumerate.

    Returns:
        list[object]: User data values for each entry.
    """
    return [combo.itemData(i, Qt.ItemDataRole.UserRole) for i in range(combo.count())]


@pytest.fixture
def threads_tab(qapp: QApplication) -> Generator[_TestThreadsTab]:
    """Create a ThreadsTab wired to a ProcessBridge with an attached PID.

    Args:
        qapp: Session-scoped QApplication fixture.

    Yields:
        Generator[_TestThreadsTab]: A ready-to-use tab instance.
    """
    del qapp
    tab = _TestThreadsTab()
    bridge = ProcessBridge()
    tab.set_bridge(bridge)
    tab.set_attached_pid(_ATTACHED_PID)
    yield tab
    tab.cleanup()
    tab.deleteLater()


class TestF0012ThreadsTabAutoRefresh:
    """F-0012: ThreadsTab must auto-refresh its thread combos via a QTimer."""

    def test_auto_refresh_button_exists_and_is_checkable(self, threads_tab: _TestThreadsTab) -> None:
        """The toolbar must expose a checkable Auto-Refresh toggle button.

        Args:
            threads_tab: _TestThreadsTab fixture.
        """
        auto_btn = threads_tab.get_auto_refresh_button()
        assert auto_btn.isCheckable(), "Auto-Refresh button must be checkable"
        assert "Auto-Refresh" in auto_btn.text(), "Auto-Refresh button text must label the control"

    def test_toggling_on_starts_timer_and_increments_call_count(
        self,
        qtbot: QtBot,
        threads_tab: _TestThreadsTab,
    ) -> None:
        """Activating Auto-Refresh must start a QTimer that re-invokes ``_refresh_threads``.

        After waiting past two polling intervals, the bridge dispatcher must
        have been invoked more than once.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            threads_tab: _TestThreadsTab fixture.
        """
        qtbot.addWidget(threads_tab)
        threads_tab.show()

        batches = [
            _make_threads([100, 101]),
            _make_threads([100, 101, 102]),
            _make_threads([100, 101, 102, 103]),
        ]
        counter = _RefreshCounter(batches)

        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
            side_effect=counter,
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            assert threads_tab.get_auto_refresh_timer().isActive(), "QTimer must be active after toggle-on"
            qtbot.wait(_AUTO_REFRESH_WAIT_MS)
            calls_after_on = counter.calls

        assert calls_after_on > 1, (
            f"Auto-refresh must invoke _refresh_threads more than once in {_AUTO_REFRESH_WAIT_MS} ms (got {calls_after_on} call(s))"
        )

    def test_new_tids_propagate_to_combos_during_auto_refresh(
        self,
        qtbot: QtBot,
        threads_tab: _TestThreadsTab,
    ) -> None:
        """Newly created TIDs must appear in every thread combo without manual refresh.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            threads_tab: _TestThreadsTab fixture.
        """
        qtbot.addWidget(threads_tab)
        threads_tab.show()

        batches = [
            _make_threads([100, 101]),
            _make_threads([100, 101, 102]),
            _make_threads([100, 101, 102, 103]),
        ]
        counter = _RefreshCounter(batches)

        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
            side_effect=counter,
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            qtbot.wait(_AUTO_REFRESH_WAIT_MS)

        reg_tids = _combo_tids(threads_tab.get_reg_combo())
        stack_tids = _combo_tids(threads_tab.get_stack_combo())
        seh_tids = _combo_tids(threads_tab.get_seh_combo())
        fiber_tids = _combo_tids(threads_tab.get_fiber_combo())
        tls_tids = _combo_tids(threads_tab.get_tls_combo())

        assert 102 in reg_tids, "newly discovered TID 102 must appear in register combo"
        assert 102 in stack_tids, "newly discovered TID 102 must appear in stack combo"
        assert 102 in seh_tids, "newly discovered TID 102 must appear in SEH combo"
        assert 102 in fiber_tids, "newly discovered TID 102 must appear in fiber combo"
        assert 102 in tls_tids, "newly discovered TID 102 must appear in TLS combo"

    def test_toggling_off_stops_timer_and_plateaus_calls(
        self,
        qtbot: QtBot,
        threads_tab: _TestThreadsTab,
    ) -> None:
        """Disabling Auto-Refresh must stop the QTimer; call count must plateau.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            threads_tab: _TestThreadsTab fixture.
        """
        qtbot.addWidget(threads_tab)
        threads_tab.show()

        batches = [_make_threads([200, 201])]
        counter = _RefreshCounter(batches)

        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
            side_effect=counter,
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            qtbot.wait(_AUTO_REFRESH_WAIT_MS)
            calls_after_on = counter.calls

            threads_tab.invoke_auto_refresh_toggle(checked=False)
            assert not threads_tab.get_auto_refresh_timer().isActive(), "QTimer must be inactive after toggle-off"

            qtbot.wait(_AUTO_REFRESH_WAIT_MS)
            calls_after_off = counter.calls

        assert calls_after_off == calls_after_on, (
            f"After auto-refresh is disabled, call count must plateau (was {calls_after_on}, now {calls_after_off})"
        )

    def test_button_text_reflects_state(self, threads_tab: _TestThreadsTab) -> None:
        """The Auto-Refresh button label must reflect the on/off state.

        Args:
            threads_tab: _TestThreadsTab fixture.
        """
        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            assert threads_tab.get_auto_refresh_button().text() == "Auto-Refresh: ON"

            threads_tab.invoke_auto_refresh_toggle(checked=False)
            assert threads_tab.get_auto_refresh_button().text() == "Auto-Refresh: OFF"

    def test_cleanup_stops_timer(self, qtbot: QtBot, threads_tab: _TestThreadsTab) -> None:
        """``cleanup()`` must stop the auto-refresh timer.

        Args:
            qtbot: pytest-qt fixture.
            threads_tab: _TestThreadsTab fixture.
        """
        qtbot.addWidget(threads_tab)
        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            assert threads_tab.get_auto_refresh_timer().isActive()

            threads_tab.cleanup()
            assert not threads_tab.get_auto_refresh_timer().isActive(), "cleanup() must stop the auto-refresh timer"

    def test_uses_3000ms_interval(self, threads_tab: _TestThreadsTab) -> None:
        """The QTimer interval must be 3000 ms (matching ProcessTab).

        Args:
            threads_tab: _TestThreadsTab fixture.
        """
        with patch(
            "intellicrack.ui.panels.process_panel.threads_tab.run_bridge_coroutine_async",
        ):
            threads_tab.invoke_auto_refresh_toggle(checked=True)
            timer = threads_tab.get_auto_refresh_timer()
            assert timer.interval() == _AUTO_REFRESH_INTERVAL_MS, (
                f"Auto-refresh interval must be {_AUTO_REFRESH_INTERVAL_MS} ms (got {timer.interval()} ms)"
            )
