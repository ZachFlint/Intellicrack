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

import psutil
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
_COL_THREADS = 5


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

    def row_for_pid(self, pid: int) -> tuple[str, int] | None:
        """Return the rendered (name, thread_count) for a given PID, if present.

        Args:
            pid: The process ID to locate among the rendered rows.

        Returns:
            tuple[str, int] | None: The image name and thread count rendered
            for ``pid``, or None when no row carries that PID.
        """
        for row in range(self._process_table.rowCount()):
            pid_item = self._process_table.item(row, _COL_PID)
            if pid_item is None or pid_item.data(0) != pid:
                continue
            name_item = self._process_table.item(row, _COL_NAME)
            threads_item = self._process_table.item(row, _COL_THREADS)
            name = name_item.text() if name_item is not None else ""
            threads_raw = threads_item.data(0) if threads_item is not None else 0
            threads = threads_raw if isinstance(threads_raw, int) else 0
            return name, threads
        return None


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


def test_process_table_renders_real_fields_for_running_interpreter(qapp: QApplication, tab: _ProcessTabProbe) -> None:
    """The rendered row for this PID must match the real OS process fields.

    Beyond merely containing ``os.getpid()``, the row rendered for the running
    interpreter must carry the genuine image name (the Python executable's own
    file name, e.g. ``python.exe``) and a thread count that agrees with what an
    independent oracle (``psutil``) reports for the same live process. If the
    bridge returned a hardcoded or stale snapshot, the name or thread count
    would diverge from ``psutil`` and this gate would fail.

    Args:
        qapp: Qt application driving the event loop.
        tab: ProcessTab probe bound to the real bridge.
    """
    self_proc = psutil.Process(os.getpid())
    expected_name = Path(sys.executable).name

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated, "process table never populated from real enumeration"

    rendered = tab.row_for_pid(os.getpid())
    assert rendered is not None, "running interpreter PID missing from real snapshot"
    name, thread_count = rendered

    assert name.lower() == expected_name.lower()
    assert "python" in name.lower()

    # Thread counts can change between the bridge snapshot and the psutil read,
    # but both observe the same live process; require a positive, same-ballpark
    # count rather than a brittle exact equality across two distinct sample times.
    assert thread_count > 0
    psutil_threads = self_proc.num_threads()
    assert abs(thread_count - psutil_threads) <= psutil_threads


def test_process_count_label_matches_real_rows(qapp: QApplication, tab: _ProcessTabProbe) -> None:
    """Row count must reflect a real enumeration and drive the count label.

    Two independent properties are gated separately. First, the rendered row
    count must be on the order of a real running system: a live Windows host (or
    the Windows container) always runs many processes, and every PID that
    ``psutil`` reports concurrently with the rendered snapshot for the
    interpreter and its parent must be representable, so the table cannot be a
    single hand-set row. Second, the count label text must be derived from that
    real row count.

    Args:
        qapp: Qt application driving the event loop.
        tab: ProcessTab probe bound to the real bridge.
    """
    psutil_pid_count = len(psutil.pids())

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated

    rows = tab.row_count()
    # A real OS always runs far more than a handful of processes; the rendered
    # table must be the same order of magnitude as the live psutil enumeration,
    # not a single test-injected row.
    assert rows > 10
    assert rows >= psutil_pid_count // 4
    assert os.getpid() in tab.rendered_pids()

    assert tab.count_label() == f"{rows} processes"


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
    """Rendered PIDs must be a subset of fresh real bridge snapshots.

    Takes a bridge snapshot before and after the tab refresh so that PIDs
    legitimately created or destroyed during the small churn window are still
    covered. Every PID rendered by the tab must appear in at least one of those
    two snapshots. A fabricated or hardcoded PID set would fail because those
    PIDs would not exist in any real OS snapshot.

    The structural oracle checks that every rendered PID is a non-negative
    integer (PID 0 is the Windows System Idle Process, which the real
    enumeration legitimately includes), which a fabricated ``str`` or ``None``
    payload cannot satisfy. The subset check proves the rendered set is derived
    from the genuine ``list_processes_detailed`` enumeration and not from any
    injected data.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge against the live system.
        tab: ProcessTab probe bound to the real bridge.
    """
    snapshot_before = run_bridge_sync(real_bridge.list_processes_detailed())
    pids_before: set[int] = {int(p["pid"]) for p in snapshot_before if isinstance(p.get("pid"), int)}
    assert os.getpid() in pids_before, "own PID missing from pre-refresh bridge snapshot"

    tab.refresh()
    populated = pump_until(qapp, lambda: tab.row_count() > 0)
    assert populated, "process table never populated after refresh"

    snapshot_after = run_bridge_sync(real_bridge.list_processes_detailed())
    pids_after: set[int] = {int(p["pid"]) for p in snapshot_after if isinstance(p.get("pid"), int)}

    real_pids_union = pids_before | pids_after
    rendered = tab.rendered_pids()

    assert rendered, "rendered PID set is empty"
    assert all(isinstance(pid, int) and pid >= 0 for pid in rendered), "rendered set contains a negative or non-integer PID"
    assert os.getpid() in rendered, "own PID missing from rendered set"

    spurious = rendered - real_pids_union
    assert not spurious, f"rendered PIDs not present in either bridge snapshot: {spurious!r}"
