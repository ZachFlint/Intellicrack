# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.process_tab``.

Audit shard 14 flagged the existing process-tab tests for overriding
``_refresh_tracked`` with a counter and never driving the real
``ProcessBridge.list_processes_detailed`` enumeration. These tests wire a real
:class:`ProcessBridge` and drive ``ProcessTab._on_refresh`` so the process
table is populated from the genuine system process snapshot. Assertions check
real, verifiable values: the running interpreter's own PID must appear, every
PID is a positive integer, and the name filter must restrict the rendered rows
to the requested image name enumerated from the real OS.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab
from tests._helpers.realcov_process_panel import (
    pump_until,
    require_windows,
    run_bridge_sync,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_COL_PID = 0
_COL_NAME = 1


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
    """Provide a real initialized ProcessBridge (no attach needed).

    Yields:
        ProcessBridge: Bridge initialized against the real Win32 backend.
    """
    require_windows()
    bridge = ProcessBridge()
    run_bridge_sync(bridge.initialize())
    try:
        yield bridge
    finally:
        run_bridge_sync(bridge.close())


class _ProcessTabProbe(ProcessTab):
    """Test subclass exposing typed accessors to protected tab members."""

    def refresh(self) -> None:
        """Drive the real system process-list refresh."""
        self._on_refresh()

    def set_filter(self, text: str) -> None:
        """Set the search-filter text used by the next refresh.

        Args:
            text: Image-name filter to apply.
        """
        self._search_input.setText(text)

    def row_count(self) -> int:
        """Return the process-table row count.

        Returns:
            int: Number of rendered process rows.
        """
        return self._process_table.rowCount()

    def count_label(self) -> str:
        """Return the process-count label text.

        Returns:
            str: The label text such as ``"449 processes"``.
        """
        return self._proc_count_label.text()

    def rendered_pids(self) -> set[int]:
        """Collect the PIDs rendered in the process table.

        Returns:
            set[int]: Integer PIDs from column zero of every row.
        """
        pids: set[int] = set()
        for row in range(self._process_table.rowCount()):
            item = self._process_table.item(row, _COL_PID)
            if item is not None:
                value = item.data(0)
                if isinstance(value, int):
                    pids.add(value)
        return pids

    def rendered_names(self) -> list[str]:
        """Collect the process names rendered in the name column.

        Returns:
            list[str]: One name per rendered row.
        """
        names: list[str] = []
        for row in range(self._process_table.rowCount()):
            item = self._process_table.item(row, _COL_NAME)
            if item is not None:
                names.append(item.text())
        return names


@pytest.fixture
def tab(qapp: QApplication, real_bridge: ProcessBridge) -> _ProcessTabProbe:
    """Create a ProcessTab probe wired to the real bridge.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge against the live system.

    Returns:
        _ProcessTabProbe: A probe driving real process enumeration.
    """
    del qapp
    widget = _ProcessTabProbe()
    widget.set_bridge(real_bridge)
    return widget


def test_process_table_populated_from_real_enumeration(qapp: QApplication, tab: _ProcessTabProbe) -> None:
    """Refresh must fill the table from real ``list_processes_detailed``.

    The live system always has many running processes; the rendered table must
    be non-empty and the running interpreter's own real PID must appear in it.

    Args:
        qapp: Qt application driving the event loop.
        tab: ProcessTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated, "process table never populated from real enumeration"

    pids = tab.rendered_pids()
    assert len(pids) >= 2
    assert all(pid >= 0 for pid in pids)
    assert os.getpid() in pids, "running interpreter PID missing from real snapshot"


def test_process_count_label_matches_real_rows(qapp: QApplication, tab: _ProcessTabProbe) -> None:
    """The count label must equal the number of enumerated process rows.

    Args:
        qapp: Qt application driving the event loop.
        tab: ProcessTab probe bound to the real bridge.
    """
    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated

    assert tab.count_label() == f"{tab.row_count()} processes"


def test_filter_restricts_to_real_named_process(qapp: QApplication, tab: _ProcessTabProbe) -> None:
    """A real image-name filter must restrict rows to that process name.

    Resolves this interpreter's real executable name, types it into the search
    box, and drives the refresh. Every rendered row must carry that image name,
    proving the filter flows through the real Win32 enumeration.

    Args:
        qapp: Qt application driving the event loop.
        tab: ProcessTab probe bound to the real bridge.
    """
    exe_name = Path(sys.executable).name
    tab.set_filter(exe_name)

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated, f"no rows for real filter {exe_name!r}"

    for name in tab.rendered_names():
        assert exe_name.lower() in name.lower()


def test_rendered_pids_match_real_bridge_snapshot(
    qapp: QApplication,
    real_bridge: ProcessBridge,
    tab: _ProcessTabProbe,
) -> None:
    """Rendered PIDs must be a subset of a fresh real bridge snapshot.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge against the live system.
        tab: ProcessTab probe bound to the real bridge.
    """
    snapshot = run_bridge_sync(real_bridge.list_processes_detailed())
    real_pids = {p.get("pid") for p in snapshot if isinstance(p.get("pid"), int)}
    assert os.getpid() in real_pids

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated
    assert os.getpid() in tab.rendered_pids()
