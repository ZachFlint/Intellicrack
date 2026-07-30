# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S14-D01: no UI path to add an attached/inspected process to Tracked.

Prior to this fix, the System Processes table had no context menu and the
Tracked tab had no way to register the process currently selected/attached
there, so ``ProcessManager.get_all_tracked()`` (backing
``TrackedRefreshWorker`` / the Tracked tab) could only ever show processes
spawned directly by the application via ``register()``. A user who attached
to or inspected an external process saw "0 tracked" with no affordance to
change that.

The fix adds a "Track This Process" context-menu action on
``ProcessTab._process_table`` that calls
``ProcessManager.register_external_pid`` for the right-clicked row's PID,
then jumps to and refreshes the Tracked tab. These tests drive the real
``ProcessTab`` widget end to end -- populate a row, trigger the context menu
(or its handler) exactly as a user right-click would, run the real
background ``TrackedRefreshWorker`` QThread, and assert the Tracked table
actually gains a row for that PID. No mocking of ``ProcessManager``: a real
singleton instance and real OS PID are used throughout.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtWidgets import QApplication, QMenu, QMessageBox, QTableWidgetItem

from intellicrack.core.process_manager import ProcessManager
from intellicrack.ui.panels.process_panel.process_tab import (
    _COL_NAME,
    _COL_PID,
    _TR_COL_NAME,
    _TR_COL_PID,
    _TR_COL_STATUS,
    ProcessTab,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

_MAX_WAIT_S: float = 5.0
_POLL_INTERVAL_S: float = 0.02
_TRACK_ACTION_TEXT: str = "Track This Process"


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a QApplication instance for this test module.

    Returns:
        QApplication: The application instance.
    """
    existing = QApplication.instance()
    return existing if isinstance(existing, QApplication) else QApplication([])


@pytest.fixture(autouse=True)
def _reset_process_manager() -> Generator[None]:
    """Isolate each test with a fresh ``ProcessManager`` singleton.

    Yields:
        None: Control passes to the test; teardown resets the singleton.
    """
    ProcessManager.reset_instance()
    yield
    ProcessManager.get_instance().uninstall_handlers()
    ProcessManager.reset_instance()


@pytest.fixture(autouse=True)
def _guard_modal_dialogs() -> Generator[None]:
    """Prevent any stray QMessageBox popup from hanging the headless test run.

    Yields:
        None: Control passes to the test with all modal dialog entry points patched.
    """
    with (
        patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
        patch.object(QMessageBox, "critical", return_value=QMessageBox.StandardButton.Ok),
        patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Ok),
        patch.object(QMessageBox, "information", return_value=QMessageBox.StandardButton.Ok),
    ):
        yield


@pytest.fixture
def tab(qapp: QApplication) -> Generator[ProcessTab]:
    """Create a real, shown ``ProcessTab`` with no bridge attached.

    Args:
        qapp: Module QApplication fixture.

    Yields:
        ProcessTab: A shown ``ProcessTab`` instance.
    """
    widget = ProcessTab()
    widget.show()
    qapp.processEvents()
    yield widget
    widget.cleanup()
    widget.deleteLater()
    qapp.processEvents()


def _pump_until(qapp: QApplication, predicate: Callable[[], bool]) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or time runs out.

    Args:
        qapp: The QApplication instance whose event loop is pumped.
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


def _populate_one_process_row(tab: ProcessTab, pid: int, name: str) -> None:
    """Insert a single row directly into the System Processes table.

    Args:
        tab: The ``ProcessTab`` whose ``_process_table`` gets a row.
        pid: PID to place in the PID column.
        name: Process name to place in the Name column.
    """
    table = tab._process_table
    table.setRowCount(0)
    table.insertRow(0)
    pid_item = QTableWidgetItem()
    pid_item.setData(Qt.ItemDataRole.DisplayRole, pid)
    table.setItem(0, _COL_PID, pid_item)
    table.setItem(0, _COL_NAME, QTableWidgetItem(name))


class TestSystemProcessTableHasTrackContextMenu:
    """The System Processes table must expose a right-click Track This Process action."""

    @staticmethod
    def test_context_menu_policy_is_custom(tab: ProcessTab) -> None:
        """The process table must opt into a custom (right-click) context menu.

        Pre-fix, the table used Qt's default ``NoContextMenu`` policy, so
        right-clicking a row did nothing at all.

        Args:
            tab: Real, shown ProcessTab fixture.
        """
        assert tab._process_table.contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu

    @staticmethod
    def test_right_click_menu_offers_track_this_process_and_invokes_handler(
        tab: ProcessTab,
        qapp: QApplication,
    ) -> None:
        """Right-clicking a populated row must show a menu that dispatches to the track handler.

        Patches ``QMenu.exec`` to return the "Track This Process" action
        immediately (avoiding a blocking modal event loop in the headless
        test) while exercising the real ``_on_process_context_menu`` ->
        ``_on_track_process`` -> ``ProcessManager.register_external_pid``
        call chain triggered by an actual right-click position.

        Args:
            tab: Real, shown ProcessTab fixture.
            qapp: Module QApplication fixture.
        """
        pid = os.getpid()
        _populate_one_process_row(tab, pid, "python.exe")
        qapp.processEvents()

        item = tab._process_table.item(0, _COL_PID)
        assert item is not None
        rect = tab._process_table.visualItemRect(item)
        pos = QPoint(rect.center().x(), rect.center().y())

        def _fake_exec(self: QMenu, _pos: object = None) -> object:
            for action in self.actions():
                if action.text() == _TRACK_ACTION_TEXT:
                    return action
            return None

        with patch.object(QMenu, "exec", _fake_exec):
            tab._on_process_context_menu(pos)

        manager = ProcessManager.get_instance()
        assert pid in getattr(manager, "_external_pids"), (
            "right-clicking the row and choosing 'Track This Process' must register the PID via register_external_pid"
        )


class TestTrackThisProcessSurfacesInTrackedTab:
    """Invoking the Track This Process handler must make the PID appear in the Tracked tab."""

    @staticmethod
    def test_track_process_handler_registers_pid_with_process_manager(tab: ProcessTab) -> None:
        """Calling the exact handler the context menu dispatches to must register the PID.

        Args:
            tab: Real, shown ProcessTab fixture.
        """
        pid = os.getpid()

        tab._on_track_process(pid, "inspected.exe")

        manager = ProcessManager.get_instance()
        external_pids = getattr(manager, "_external_pids")
        assert pid in external_pids
        assert external_pids[pid]["name"] == "inspected.exe"

    @staticmethod
    def test_track_process_then_refresh_tracked_populates_tracked_table(
        tab: ProcessTab,
        qapp: QApplication,
    ) -> None:
        """After tracking a PID, the Tracked tab table must show a row for it.

        This is the end-to-end falsifiable gate for S14-D01: pre-fix, no
        code path could add an externally inspected PID to the Tracked
        store, so the Tracked table stayed empty ("0 tracked") no matter
        what the user did. Post-fix, invoking the Track This Process
        handler and then refreshing the Tracked tab (as ``_on_track_process``
        itself also does) must produce a matching row.

        Args:
            tab: Real, shown ProcessTab fixture.
            qapp: Module QApplication fixture.
        """
        pid = os.getpid()

        tab._on_track_process(pid, "inspected.exe")

        populated = _pump_until(qapp, lambda: tab._tracked_table.rowCount() > 0)
        assert populated, "Tracked table stayed empty after tracking an inspected process"

        pids_in_table = {
            int(tab._tracked_table.item(row, _TR_COL_PID).data(Qt.ItemDataRole.DisplayRole))
            for row in range(tab._tracked_table.rowCount())
            if tab._tracked_table.item(row, _TR_COL_PID) is not None
        }
        assert pid in pids_in_table, f"tracked PID {pid} did not appear in the Tracked tab table"

        matching_row = next(
            row
            for row in range(tab._tracked_table.rowCount())
            if int(tab._tracked_table.item(row, _TR_COL_PID).data(Qt.ItemDataRole.DisplayRole)) == pid
        )
        name_item = tab._tracked_table.item(matching_row, _TR_COL_NAME)
        status_item = tab._tracked_table.item(matching_row, _TR_COL_STATUS)
        assert name_item is not None
        assert status_item is not None
        assert name_item.text() == "inspected.exe"
        assert status_item.text() == "Running"

    @staticmethod
    def test_track_process_switches_to_tracked_tab(tab: ProcessTab) -> None:
        """Tracking a process must switch the active sub-tab to Tracked so the row is visible.

        Args:
            tab: Real, shown ProcessTab fixture.
        """
        tab._tabs.setCurrentIndex(0)
        assert tab._tabs.currentIndex() == 0

        tab._on_track_process(os.getpid(), "inspected.exe")

        assert tab._tabs.currentIndex() == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
