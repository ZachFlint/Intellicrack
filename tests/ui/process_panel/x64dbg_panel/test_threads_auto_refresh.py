# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for audit7 F-0012: ThreadsTab auto-refresh of thread combos.

The unit verifies that ``ThreadsTab`` exposes an auto-refresh toggle button
and a ``QTimer``-backed 3-second polling cycle, mirroring the pattern used
by ``ProcessTab``. The tests confirm that:

* A new auto-refresh button exists and is wired to the toggle slot.
* Activating auto-refresh starts a ``QTimer`` whose interval is exactly
  3000 ms AND whose timeout signal fires ``_refresh_threads`` at that rate.
* Newly created threads in the target process appear in the per-tab thread
  combos without a manual Refresh click.
* Disabling auto-refresh stops the timer so the call count plateaus.
* ``cleanup()`` stops the timer for panel teardown.

All tests use a ``_CountingThreadsTab`` subclass that overrides
``_refresh_threads`` to record invocations and push synthetic
``ThreadInfo`` batches into the UI. No mock library functions are used:
the override is a proper subclass method, not a replacement for the
bridge dispatcher.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

import pytest
from PyQt6.QtCore import Qt

from intellicrack.core.types import ThreadInfo
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QComboBox, QPushButton
    from pytestqt.qtbot import QtBot


# The production constant defined in threads_tab.py as _AUTO_REFRESH_INTERVAL_MS.
# This value is an independent specification: the requirement says ThreadsTab must
# mirror ProcessTab's 3000 ms polling cycle. It is NOT derived by reading the
# implementation constant; it is the externally mandated value.
_REQUIRED_INTERVAL_MS: int = 3000

# Observation window: long enough for at least two complete 3000 ms cycles.
# 7500 ms gives exactly 2 complete cycles with 1500 ms slack.
_OBSERVE_MS: int = 7500


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


class _CountingThreadsTab(ThreadsTab):
    """ThreadsTab subclass that counts ``_refresh_threads`` invocations.

    The override eliminates the need to reach into the async bridge dispatcher:
    it records each timer-driven call directly and optionally feeds a
    sequence of ``ThreadInfo`` batches into ``update_thread_list`` so that
    combo-population tests can assert exact TID membership.

    This is a proper subclass override, not a mock. The timer wiring
    (``QTimer.timeout -> _refresh_threads``) is established by the base class
    constructor and remains intact; only the body of ``_refresh_threads`` is
    replaced to avoid real async bridge calls in a unit-test context where no
    live process is attached.
    """

    refresh_call_count: int
    batches: list[list[ThreadInfo]]

    def __init__(self) -> None:
        """Initialize the counting tab with zeroed counters."""
        super().__init__()
        self.refresh_call_count = 0
        self.batches = []

    @override
    def _refresh_threads(self) -> None:
        """Count invocations and push synthetic thread data into the UI."""
        idx = min(self.refresh_call_count, len(self.batches) - 1) if self.batches else -1
        self.refresh_call_count += 1
        if idx >= 0:
            self.update_thread_list(self.batches[idx])

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

    def invoke_refresh_threads(self) -> None:
        """Invoke the overridden ``_refresh_threads`` for direct testing."""
        self._refresh_threads()


@pytest.fixture
def counting_tab(qapp: QApplication) -> Generator[_CountingThreadsTab]:
    """Create a ``_CountingThreadsTab`` ready for timer-based assertions.

    Args:
        qapp: Session-scoped QApplication fixture.

    Yields:
        _CountingThreadsTab: A ready-to-use tab instance.
    """
    del qapp
    tab = _CountingThreadsTab()
    yield tab
    tab.cleanup()
    tab.deleteLater()


class TestF0012ThreadsTabAutoRefresh:
    """F-0012: ThreadsTab must auto-refresh its thread combos via a QTimer."""

    def test_auto_refresh_button_exists_and_is_checkable(self, counting_tab: _CountingThreadsTab) -> None:
        """The toolbar must expose a checkable Auto-Refresh toggle button.

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        auto_btn = counting_tab.get_auto_refresh_button()
        assert auto_btn.isCheckable(), "Auto-Refresh button must be checkable"
        assert "Auto-Refresh" in auto_btn.text(), "Auto-Refresh button text must label the control"

    def test_toggling_on_starts_timer_and_increments_call_count(
        self,
        qtbot: QtBot,
        counting_tab: _CountingThreadsTab,
    ) -> None:
        """Activating Auto-Refresh starts a QTimer at exactly 3000 ms that fires _refresh_threads.

        Both the timer interval and the accumulated call count over a known
        observation window are verified here so that either a wrong interval
        or a broken ticker produces a red gate. A timer with interval N ms
        observed for W ms must fire at least W // N times (complete cycles).
        With ``_OBSERVE_MS=7500`` and ``_REQUIRED_INTERVAL_MS=3000`` the
        minimum is 2 and the maximum is 3 complete firings.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        qtbot.addWidget(counting_tab)
        counting_tab.show()

        counting_tab.invoke_auto_refresh_toggle(checked=True)

        timer = counting_tab.get_auto_refresh_timer()
        assert timer.isActive(), "QTimer must be active after toggle-on"
        assert timer.interval() == _REQUIRED_INTERVAL_MS, (
            f"QTimer interval must be exactly {_REQUIRED_INTERVAL_MS} ms; "
            f"got {timer.interval()} ms.  ProcessTab defines 3000 ms as the required polling rate."
        )

        qtbot.wait(_OBSERVE_MS)

        observed_calls: int = counting_tab.refresh_call_count
        min_expected: int = _OBSERVE_MS // _REQUIRED_INTERVAL_MS
        max_expected: int = min_expected + 1

        assert observed_calls >= min_expected, (
            f"_refresh_threads must be called at least {min_expected} time(s) in {_OBSERVE_MS} ms "
            f"at {_REQUIRED_INTERVAL_MS} ms interval; got {observed_calls} call(s).  "
            "Either the timer interval is wrong or the timeout signal is not connected."
        )
        assert observed_calls <= max_expected, (
            f"_refresh_threads must not be called more than {max_expected} time(s) in {_OBSERVE_MS} ms "
            f"at {_REQUIRED_INTERVAL_MS} ms interval; got {observed_calls} call(s).  "
            "Timer may be firing faster than the required 3000 ms rate."
        )

    def test_new_tids_propagate_to_combos_during_auto_refresh(
        self,
        qtbot: QtBot,
        counting_tab: _CountingThreadsTab,
    ) -> None:
        """Newly created TIDs must appear in every thread combo without manual refresh.

        The test loads the tab with three successive batches of thread data so
        that TID 102 (absent in batch 0, present in batches 1 and 2) is
        guaranteed to appear in every combo after the timer has fired at least
        twice during the ``_OBSERVE_MS`` window.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        qtbot.addWidget(counting_tab)
        counting_tab.show()

        counting_tab.batches = [
            _make_threads([100, 101]),
            _make_threads([100, 101, 102]),
            _make_threads([100, 101, 102, 103]),
        ]

        counting_tab.invoke_auto_refresh_toggle(checked=True)
        qtbot.wait(_OBSERVE_MS)
        counting_tab.invoke_auto_refresh_toggle(checked=False)

        reg_tids = _combo_tids(counting_tab.get_reg_combo())
        stack_tids = _combo_tids(counting_tab.get_stack_combo())
        seh_tids = _combo_tids(counting_tab.get_seh_combo())
        fiber_tids = _combo_tids(counting_tab.get_fiber_combo())
        tls_tids = _combo_tids(counting_tab.get_tls_combo())

        assert 102 in reg_tids, "newly discovered TID 102 must appear in register combo after auto-refresh"
        assert 102 in stack_tids, "newly discovered TID 102 must appear in stack combo after auto-refresh"
        assert 102 in seh_tids, "newly discovered TID 102 must appear in SEH combo after auto-refresh"
        assert 102 in fiber_tids, "newly discovered TID 102 must appear in fiber combo after auto-refresh"
        assert 102 in tls_tids, "newly discovered TID 102 must appear in TLS combo after auto-refresh"

    def test_toggling_off_stops_timer_and_plateaus_calls(
        self,
        qtbot: QtBot,
        counting_tab: _CountingThreadsTab,
    ) -> None:
        """Disabling Auto-Refresh must stop the QTimer; call count must plateau.

        The test verifies that after toggle-off the call count does not increase
        even after another full ``_OBSERVE_MS`` observation window elapses.

        Args:
            qtbot: pytest-qt fixture for event loop advancement.
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        qtbot.addWidget(counting_tab)
        counting_tab.show()

        counting_tab.invoke_auto_refresh_toggle(checked=True)
        qtbot.wait(_OBSERVE_MS)
        calls_after_on: int = counting_tab.refresh_call_count

        counting_tab.invoke_auto_refresh_toggle(checked=False)
        assert not counting_tab.get_auto_refresh_timer().isActive(), "QTimer must be inactive after toggle-off"

        qtbot.wait(_OBSERVE_MS)
        calls_after_off: int = counting_tab.refresh_call_count

        assert calls_after_off == calls_after_on, (
            f"After auto-refresh is disabled, call count must plateau "
            f"(was {calls_after_on}, now {calls_after_off}).  "
            "The timer must not fire while stopped."
        )

    def test_button_text_reflects_state(self, counting_tab: _CountingThreadsTab) -> None:
        """The Auto-Refresh button label and timer active-state must agree.

        The toggle handler must both update the visible label AND start or stop
        the QTimer. Asserting only the label string would allow a regression
        where the label changes but the timer is never started; asserting both
        together ensures the string and the functional behaviour cannot diverge.

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        counting_tab.invoke_auto_refresh_toggle(checked=True)
        assert counting_tab.get_auto_refresh_button().text() == "Auto-Refresh: ON", (
            "Button text must be 'Auto-Refresh: ON' when auto-refresh is enabled"
        )
        assert counting_tab.get_auto_refresh_timer().isActive(), "QTimer must be active when label shows 'Auto-Refresh: ON'"

        counting_tab.invoke_auto_refresh_toggle(checked=False)
        assert counting_tab.get_auto_refresh_button().text() == "Auto-Refresh: OFF", (
            "Button text must be 'Auto-Refresh: OFF' when auto-refresh is disabled"
        )
        assert not counting_tab.get_auto_refresh_timer().isActive(), "QTimer must be inactive when label shows 'Auto-Refresh: OFF'"

    def test_cleanup_stops_timer(self, qtbot: QtBot, counting_tab: _CountingThreadsTab) -> None:
        """``cleanup()`` must stop the auto-refresh timer.

        Args:
            qtbot: pytest-qt fixture.
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        qtbot.addWidget(counting_tab)
        counting_tab.invoke_auto_refresh_toggle(checked=True)
        assert counting_tab.get_auto_refresh_timer().isActive(), "Timer must be active before cleanup"

        counting_tab.cleanup()
        assert not counting_tab.get_auto_refresh_timer().isActive(), "cleanup() must stop the auto-refresh timer"

    def test_uses_3000ms_interval(self, counting_tab: _CountingThreadsTab) -> None:
        """The QTimer interval must be 3000 ms (matching ProcessTab's polling rate).

        This test checks the timer interval via ``QTimer.interval()`` after
        toggle-on, independently of the call-count assertion in
        ``test_toggling_on_starts_timer_and_increments_call_count``, to ensure
        that a change to the constant alone is caught by at least two distinct
        gates.

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        counting_tab.invoke_auto_refresh_toggle(checked=True)
        timer = counting_tab.get_auto_refresh_timer()
        assert timer.interval() == _REQUIRED_INTERVAL_MS, (
            f"Auto-refresh interval must be {_REQUIRED_INTERVAL_MS} ms (got {timer.interval()} ms). "
            "This must match ProcessTab's 3000 ms polling cycle."
        )
        counting_tab.invoke_auto_refresh_toggle(checked=False)

    def test_timer_not_active_before_toggle(self, counting_tab: _CountingThreadsTab) -> None:
        """The QTimer must not be active before Auto-Refresh is toggled on.

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        timer = counting_tab.get_auto_refresh_timer()
        assert not timer.isActive(), "QTimer must not be active before Auto-Refresh is enabled"

    def test_refresh_count_increments_after_direct_call(self, counting_tab: _CountingThreadsTab) -> None:
        """``_refresh_threads`` must increment ``refresh_call_count`` on each invocation.

        The test drives the before->after transition: count is 0 before any
        call, then exactly 1 after the first direct invocation, and exactly 2
        after a second.  This gates the counting mechanism used by all
        timer-driven tests above and ensures the override body is executed for
        each call rather than being silently skipped.

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        assert counting_tab.refresh_call_count == 0, "refresh_call_count must be 0 before any invocation"

        counting_tab.invoke_refresh_threads()
        assert counting_tab.refresh_call_count == 1, (
            f"refresh_call_count must be 1 after the first call; got {counting_tab.refresh_call_count}"
        )

        counting_tab.invoke_refresh_threads()
        assert counting_tab.refresh_call_count == 2, (
            f"refresh_call_count must be 2 after the second call; got {counting_tab.refresh_call_count}"
        )

    def test_combos_populate_after_update_thread_list(self, counting_tab: _CountingThreadsTab) -> None:
        """``update_thread_list`` must populate all thread combos with the supplied TIDs.

        The test drives the before->after transition: all combos are empty
        before the call, and after ``update_thread_list`` is invoked with a
        known batch every combo must contain exactly those TIDs in order.  The
        oracle is the input batch itself (the expected list is constructed
        independently of the combo-population path).

        Args:
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        for combo_name, combo in [
            ("reg_combo", counting_tab.get_reg_combo()),
            ("stack_combo", counting_tab.get_stack_combo()),
            ("seh_combo", counting_tab.get_seh_combo()),
            ("fiber_combo", counting_tab.get_fiber_combo()),
            ("tls_combo", counting_tab.get_tls_combo()),
        ]:
            assert combo.count() == 0, f"{combo_name} must be empty before update_thread_list"

        expected_tids: list[int] = [1001, 1002, 1003]
        counting_tab.update_thread_list(_make_threads(expected_tids))

        for combo_name, combo in [
            ("reg_combo", counting_tab.get_reg_combo()),
            ("stack_combo", counting_tab.get_stack_combo()),
            ("seh_combo", counting_tab.get_seh_combo()),
            ("fiber_combo", counting_tab.get_fiber_combo()),
            ("tls_combo", counting_tab.get_tls_combo()),
        ]:
            actual_tids = _combo_tids(combo)
            assert actual_tids == expected_tids, (
                f"{combo_name} must contain exactly {expected_tids} after update_thread_list; got {actual_tids}"
            )

    def test_exact_tids_in_combos_after_single_batch(
        self,
        qtbot: QtBot,
        counting_tab: _CountingThreadsTab,
    ) -> None:
        """After the first auto-refresh fire, all combos must contain exactly the batch TIDs.

        This test waits for just one refresh interval plus a short margin, so
        exactly one batch is consumed and the combo contents can be checked
        exhaustively against a known-correct list.

        Args:
            qtbot: pytest-qt fixture.
            counting_tab: ``_CountingThreadsTab`` fixture.
        """
        qtbot.addWidget(counting_tab)
        counting_tab.show()

        expected_tids: list[int] = [500, 501, 502]
        counting_tab.batches = [_make_threads(expected_tids)]

        counting_tab.invoke_auto_refresh_toggle(checked=True)

        # Wait just enough for one interval to fire (interval + margin).
        one_shot_wait: int = _REQUIRED_INTERVAL_MS + 500
        qtbot.wait(one_shot_wait)
        counting_tab.invoke_auto_refresh_toggle(checked=False)

        assert counting_tab.refresh_call_count >= 1, "At least one refresh must have fired"

        for combo_name, combo in [
            ("reg_combo", counting_tab.get_reg_combo()),
            ("stack_combo", counting_tab.get_stack_combo()),
            ("seh_combo", counting_tab.get_seh_combo()),
            ("fiber_combo", counting_tab.get_fiber_combo()),
            ("tls_combo", counting_tab.get_tls_combo()),
        ]:
            actual_tids = _combo_tids(combo)
            assert actual_tids == expected_tids, (
                f"{combo_name} must contain exactly {expected_tids} after one refresh batch; got {actual_tids}"
            )
