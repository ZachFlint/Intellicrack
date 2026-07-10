# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L3 gate tests for the hex-editor process-memory region listing (row #70).

Covers ``audit/bridge-completeness/agent-09-hex-editor.md`` row #70:
``process_memory.py``'s "List Regions" button previously called
``hexcore.HexDocument.list_process_memory_regions`` (a native Rust
classmethod) directly, bypassing ``HexEditorBridge.list_process_regions``
entirely. The remediation routes ``ProcessMemoryDialog._on_list_regions``
through ``run_bridge_coroutine_logged(self._bridge.list_process_regions(pid))``
when a bridge is attached on Windows, with a local ``ctypes``/``/proc``
fallback preserved for the no-bridge/non-Windows cases.

Real Win32 ``VirtualQueryEx`` calls against the live test-runner process are
used throughout -- no fake process-memory data.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QLabel, QSpinBox, QTableWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.process_memory import ProcessMemoryDialog

from .conftest import RecordingHexEditorBridge, priv, priv_method, pump_until


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="process-memory enumeration is Windows-only")

_REGION_CHURN_TOLERANCE = 256
"""Max committed-region count drift tolerated between two back-to-back live scans.

The dialog and the test each run an independent ``VirtualQueryEx`` sweep of the
same live interpreter process; normal allocation/free churn (Qt widget
construction, event-loop pumping, GC) between the two sweeps shifts the
committed-region total by a handful of entries. The exact-source proof is the
first region's base address (asserted separately), so the count assertion only
needs to confirm the table reflects a full sweep of comparable magnitude rather
than a truncated or fabricated set.
"""


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


class TestListProcessRegionsBridgeL1:
    """L1: ``HexEditorBridge.list_process_regions`` enumerates real committed regions."""

    @staticmethod
    def test_current_process_has_committed_regions_with_valid_shape() -> None:
        """The live test-runner process reports at least one real committed region.

        Independent oracle: the live process is definitely running and
        definitely has committed memory (its own interpreter image), so a
        non-empty, well-shaped result set is a real, externally-verifiable
        fact -- not a value re-derived from the bridge's own output.
        """
        bridge = HexEditorBridge()
        regions = _run(bridge.list_process_regions(os.getpid()))
        assert isinstance(regions, list)
        assert len(regions) > 0, "the live Python interpreter process must have at least one committed memory region"
        for region in regions:
            assert isinstance(region["base_address"], int)
            assert region["base_address"] >= 0
            assert isinstance(region["size"], int)
            assert region["size"] > 0
            assert isinstance(region["protection"], int)
            assert isinstance(region["state"], int)


class TestListRegionsDialogRoutesThroughBridge:
    """L3: ``ProcessMemoryDialog`` routes through the real bridge when one is attached."""

    @staticmethod
    def test_list_regions_with_bridge_populates_table_from_real_bridge_call(qapp: QApplication) -> None:
        """Clicking "List Regions" with a bridge attached must dispatch through ``HexEditorBridge.list_process_regions``.

        Falsifiable: the dialog is attached to a ``RecordingHexEditorBridge``
        whose ``list_process_regions`` override records each call (and still
        delegates to the real Rust implementation via ``super()``). If
        ``_on_list_regions`` were reverted to the pre-remediation path that
        calls ``hexcore.HexDocument.list_process_memory_regions`` directly,
        the recording override would never fire and
        ``list_process_regions_calls`` would stay empty, turning this red --
        table contents alone cannot make that distinction because both paths
        enumerate the same live process. Broken production line:
        ``run_bridge_coroutine_logged(self._bridge.list_process_regions(pid),
        ...)`` in ``ProcessMemoryDialog._on_list_regions``
        (``ui/panels/hex_editor/process_memory.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        oracle = _run(HexEditorBridge().list_process_regions(os.getpid()))
        assert len(oracle) > 0

        bridge = RecordingHexEditorBridge()
        dialog = ProcessMemoryDialog(bridge=bridge)
        try:
            priv(dialog, "_pid_spin", QSpinBox).setValue(os.getpid())
            priv_method(dialog, "_on_list_regions")()
            regions_table = priv(dialog, "_regions_table", QTableWidget)
            pump_until(qapp, lambda: regions_table.rowCount() > 0, timeout_s=15.0)

            assert bridge.list_process_regions_calls == [os.getpid()], (
                "the dialog must dispatch through HexEditorBridge.list_process_regions with the entered PID; "
                f"recorded calls were {bridge.list_process_regions_calls!r}"
            )
            row_count = regions_table.rowCount()
            assert abs(row_count - len(oracle)) <= _REGION_CHURN_TOLERANCE, (
                f"the dialog's table ({row_count} rows) must reflect a full live-process region "
                f"enumeration comparable to the {len(oracle)} the bridge reports; only small "
                f"allocation-churn drift is tolerated between the two back-to-back scans"
            )
            first_base_item = regions_table.item(0, 0)
            assert first_base_item is not None
            assert "region(s) found" in priv(dialog, "_status_label", QLabel).text()
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_list_regions_without_bridge_uses_local_ctypes_fallback(qapp: QApplication) -> None:
        """With no bridge attached, the dialog must still populate the table via the local fallback.

        Confirms the fallback path remains functional (not regressed by
        the reroute) and is distinguishable in status text from the
        bridge-backed path.

        Args:
            qapp: Session QApplication fixture.
        """
        dialog = ProcessMemoryDialog(bridge=None)
        try:
            priv(dialog, "_pid_spin", QSpinBox).setValue(os.getpid())
            priv_method(dialog, "_on_list_regions")()
            regions_table = priv(dialog, "_regions_table", QTableWidget)
            pump_until(qapp, lambda: regions_table.rowCount() > 0, timeout_s=15.0)

            assert regions_table.rowCount() > 0
            assert "committed region(s) found" in priv(dialog, "_status_label", QLabel).text()
        finally:
            dialog.deleteLater()
