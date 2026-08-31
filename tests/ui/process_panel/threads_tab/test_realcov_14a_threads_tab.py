# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.threads_tab``.

Audit shard 14 flagged the existing threads-tab tests for feeding the tab
hand-built ``ThreadInfo`` lists and never exercising the real
``ProcessBridge.get_threads`` enumeration. These tests instead attach a real
:class:`ProcessBridge` to the running interpreter process and drive
``ThreadsTab._refresh_threads`` so the thread table and per-tab thread combos
are populated from genuine Win32 thread enumeration. Every assertion checks
real, verifiable thread state (the live interpreter always has at least its
main thread, every TID is a positive integer, and the count label matches the
real enumeration).
"""

from __future__ import annotations

import ctypes
import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab
from tests._helpers.realcov_process_panel import (
    close_real_bridge,
    make_real_bridge_attached_to_self,
    pump_until,
    require_windows,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from intellicrack.bridges.process import ProcessBridge

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture
def qapp() -> Iterator[QApplication]:
    """Provide a live QApplication for widget construction.

    Yields:
        QApplication: The running application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def real_bridge() -> Iterator[ProcessBridge]:
    """Provide a real ProcessBridge attached to the current process.

    Yields:
        ProcessBridge: Bridge initialized and attached to this process.
    """
    require_windows()
    bridge = make_real_bridge_attached_to_self()
    try:
        yield bridge
    finally:
        close_real_bridge(bridge)


class _ThreadsTabProbe(ThreadsTab):
    """Test subclass exposing typed accessors to protected tab members."""

    def refresh(self) -> None:
        """Drive the real thread-list refresh."""
        self._refresh_threads()

    def row_count(self) -> int:
        """Return the thread-table row count.

        Returns:
            int: Number of rendered thread rows.
        """
        return self._thread_table.rowCount()

    def tids(self) -> set[int]:
        """Collect the TIDs currently rendered in the thread table.

        Returns:
            set[int]: The integer TIDs in column zero of every table row.
        """
        out: set[int] = set()
        for row in range(self._thread_table.rowCount()):
            item = self._thread_table.item(row, 0)
            if item is not None:
                out.add(int(item.text()))
        return out

    def count_label(self) -> str:
        """Return the thread-count label text.

        Returns:
            str: The label text such as ``"6 threads"``.
        """
        return self._thread_count.text()

    def reg_combo_count(self) -> int:
        """Return the number of entries in the register thread combo.

        Returns:
            int: Item count of the register combo.
        """
        return self._reg_combo.count()

    def combo_tid_sets(self) -> list[set[int]]:
        """Collect the TID payloads of every per-feature thread combo.

        Returns:
            list[set[int]]: One TID set per combo (register, stack, SEH,
                fiber, TLS).
        """
        combos = (
            self._reg_combo,
            self._stack_combo,
            self._seh_combo,
            self._fiber_combo,
            self._tls_thread_combo,
        )
        result: list[set[int]] = []
        for combo in combos:
            ids: set[int] = set()
            for i in range(combo.count()):
                data = combo.itemData(i)
                if isinstance(data, int):
                    ids.add(data)
            result.append(ids)
        return result


@pytest.fixture
def tab(qapp: QApplication, real_bridge: ProcessBridge) -> _ThreadsTabProbe:
    """Create a ThreadsTab probe wired to the real bridge and attached PID.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge attached to this process.

    Returns:
        _ThreadsTabProbe: A probe driving the real bridge against this process.
    """
    del qapp
    widget = _ThreadsTabProbe()
    widget.set_bridge(real_bridge)
    widget.set_attached_pid(os.getpid())
    return widget


def _current_thread_id() -> int:
    """Return the real OS thread ID of the calling thread on Windows.

    Returns:
        int: The Win32 ``GetCurrentThreadId`` result for this thread.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_thread_id = kernel32.GetCurrentThreadId
    get_current_thread_id.restype = ctypes.c_uint32
    return int(get_current_thread_id())


def test_thread_table_populated_from_real_enumeration(qapp: QApplication, tab: _ThreadsTabProbe) -> None:
    """Refresh must fill the thread table from real ``get_threads`` results.

    The running interpreter always owns at least one live OS thread, so the
    real enumeration must yield a non-empty table whose first column holds the
    genuine, positive thread IDs reported by Windows.

    Args:
        qapp: Qt application driving the event loop.
        tab: ThreadsTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated, "thread table was never populated from real get_threads()"

    row_count = tab.row_count()
    assert row_count >= 1

    tids = tab.tids()
    assert all(tid > 0 for tid in tids), "non-positive TID rendered"
    assert len(tids) == row_count, "duplicate TIDs rendered for distinct threads"


def test_thread_count_label_matches_real_rows(qapp: QApplication, tab: _ThreadsTabProbe) -> None:
    """The count label must equal the real number of enumerated threads.

    Args:
        qapp: Qt application driving the event loop.
        tab: ThreadsTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated

    assert tab.count_label() == f"{tab.row_count()} threads"


def test_thread_combos_populated_with_real_tids(qapp: QApplication, tab: _ThreadsTabProbe) -> None:
    """Per-feature thread combos must list every real TID from enumeration.

    The register, stack, SEH, fiber, and TLS sub-tabs share the thread list;
    after a real refresh each combo must hold the same genuine TIDs that the
    bridge reported, proving thread selection can target real threads.

    Args:
        qapp: Qt application driving the event loop.
        tab: ThreadsTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.reg_combo_count() > 0)
    assert populated, "register thread combo never populated from real threads"

    table_tids = tab.tids()
    for combo_tids in tab.combo_tid_sets():
        assert combo_tids == table_tids


def test_refresh_discovers_real_main_thread(qapp: QApplication, tab: _ThreadsTabProbe) -> None:
    """The current OS thread must appear among the enumerated real threads.

    The thread running pytest is a genuine OS thread of this process; its
    real TID must be present in the table the bridge populated.

    Args:
        qapp: Qt application driving the event loop.
        tab: ThreadsTab probe bound to the real bridge.
    """
    current_tid = _current_thread_id()

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated

    assert current_tid in tab.tids(), "real current thread TID missing from enumeration"
