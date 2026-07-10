# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 B3 ThreadsTab fixes (F-0011, F-0019).

Each test exercises one finding and would fail without the corresponding
remediation in ``intellicrack.ui.panels.process_panel.threads_tab``.

F-0011: ``_on_tls`` was reading the TID from the Fiber combo instead of
its own TLS-specific selector.  The fix adds ``_tls_thread_combo`` and wires
``_on_tls`` to read from it.

F-0019: ``_on_write_registers`` only ever parsed the Hex column.  Decimal
edits were silently discarded.  The fix tracks the last-edited column per
row and reads from it, syncing the other column on each edit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, override

import pytest
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer
from PyQt6.QtWidgets import QApplication, QComboBox, QMessageBox, QTableWidget, QTableWidgetItem

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel.threads_tab import ThreadsTab


if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture(scope="module")
def qapp() -> QCoreApplication:
    """Ensure exactly one QApplication exists for these widget tests.

    Returns:
        QCoreApplication: The running application instance.
    """
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


class _RecordingBridge(ProcessBridge):
    """ProcessBridge subclass that records TLS and set_thread_context calls.

    Provides deterministic async overrides so the UI behaviour can be
    verified without a live Win32 backend.
    """

    tls_calls: list[int]
    set_context_calls: list[tuple[int, dict[str, int]]]

    def __init__(self) -> None:
        """Initialize with empty call-recording lists."""
        super().__init__()
        self.tls_calls = []
        self.set_context_calls = []

    @override
    async def get_tls_values(
        self,
        tid: int,
        max_slots: int = 64,
    ) -> list[dict[str, object]]:
        """Record the TID and return an empty slot list.

        Args:
            tid: Thread ID whose TLS values are being requested.
            max_slots: Maximum number of TLS slots to return (unused).

        Returns:
            list[dict[str, object]]: Always empty; tests assert call recording.
        """
        del max_slots
        self.tls_calls.append(tid)
        return []

    @override
    async def set_thread_context(
        self,
        tid: int,
        registers: dict[str, int],
    ) -> bool:
        """Record the tid and register dict, return True.

        Args:
            tid: Thread ID to update.
            registers: Register name to integer value mapping.

        Returns:
            bool: Always True.
        """
        self.set_context_calls.append((tid, dict(registers)))
        return True


def _process_events_until(
    qapp: QCoreApplication,
    predicate: Callable[[], bool],
    timeout_ms: int = 3000,
) -> bool:
    """Pump the Qt event loop until ``predicate()`` is truthy or timeout.

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


def _accept_write_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch QMessageBox.warning in ThreadsTab to auto-accept.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(
        "intellicrack.ui.panels.process_panel.threads_tab.QMessageBox.warning",
        _yes,
    )


def _get_fiber_combo(tab: ThreadsTab) -> QComboBox:
    """Return the Fiber thread selector combo from ``tab`` without private access.

    Args:
        tab: ThreadsTab instance to query.

    Returns:
        QComboBox: The ``_fiber_combo`` widget.
    """
    return cast(QComboBox, getattr(tab, "_fiber_combo"))


def _get_tls_thread_combo(tab: ThreadsTab) -> QComboBox:
    """Return the TLS thread selector combo from ``tab`` without private access.

    Args:
        tab: ThreadsTab instance to query.

    Returns:
        QComboBox: The ``_tls_thread_combo`` widget.
    """
    return cast(QComboBox, getattr(tab, "_tls_thread_combo"))


def _get_reg_combo(tab: ThreadsTab) -> QComboBox:
    """Return the Register thread selector combo from ``tab``.

    Args:
        tab: ThreadsTab instance to query.

    Returns:
        QComboBox: The ``_reg_combo`` widget.
    """
    return cast(QComboBox, getattr(tab, "_reg_combo"))


def _get_reg_table(tab: ThreadsTab) -> QTableWidget:
    """Return the register table widget from ``tab``.

    Args:
        tab: ThreadsTab instance to query.

    Returns:
        QTableWidget: The ``_reg_table`` widget.
    """
    return cast(QTableWidget, getattr(tab, "_reg_table"))


def _get_reg_last_edited_col(tab: ThreadsTab) -> dict[int, int]:
    """Return the last-edited-column tracker dict from ``tab``.

    Args:
        tab: ThreadsTab instance to query.

    Returns:
        dict[int, int]: The ``_reg_last_edited_col`` mapping.
    """
    return cast(dict[int, int], getattr(tab, "_reg_last_edited_col"))


def _call_on_tls(tab: ThreadsTab) -> None:
    """Invoke ``tab._on_tls()`` without private access.

    Args:
        tab: ThreadsTab instance on which to trigger the TLS fetch.
    """
    on_tls = getattr(tab, "_on_tls")
    on_tls()


def _call_on_write_registers(tab: ThreadsTab) -> None:
    """Invoke ``tab._on_write_registers()`` without private access.

    Args:
        tab: ThreadsTab instance on which to trigger the register write.
    """
    on_write = getattr(tab, "_on_write_registers")
    on_write()


@pytest.fixture
def tab(qapp: QCoreApplication) -> ThreadsTab:
    """Create a fresh ThreadsTab for each test.

    Args:
        qapp: Qt application fixture.

    Returns:
        ThreadsTab: A new ThreadsTab instance.
    """
    del qapp
    return ThreadsTab()


@pytest.fixture
def bridge() -> _RecordingBridge:
    """Create a fresh recording bridge.

    Returns:
        _RecordingBridge: A bridge subclass that records calls.
    """
    return _RecordingBridge()


def _add_reg_row(tab: ThreadsTab, reg: str, hex_val: str, dec_val: str) -> None:
    """Append one register row without triggering the itemChanged sync.

    Args:
        tab: ThreadsTab whose register table to populate.
        reg: Register name string.
        hex_val: Hex representation to place in column 1.
        dec_val: Decimal representation to place in column 2.
    """
    reg_table = _get_reg_table(tab)
    block_on: bool = True
    reg_table.blockSignals(block_on)
    row = reg_table.rowCount()
    reg_table.insertRow(row)
    reg_table.setItem(row, 0, QTableWidgetItem(reg))
    reg_table.setItem(row, 1, QTableWidgetItem(hex_val))
    reg_table.setItem(row, 2, QTableWidgetItem(dec_val))
    block_off: bool = False
    reg_table.blockSignals(block_off)


# ---------------------------------------------------------------------------
# F-0011: _on_tls must read from _tls_thread_combo, not _fiber_combo
# ---------------------------------------------------------------------------


class TestF0011TlsUsesOwnSelector:
    """F-0011: ``_on_tls`` must read TID from ``_tls_thread_combo``, not ``_fiber_combo``."""

    def test_tls_uses_its_own_selector(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
        bridge: _RecordingBridge,
    ) -> None:
        """TLS request must use the TID from ``_tls_thread_combo``, not ``_fiber_combo``.

        Populates Fiber with TID=100 and TLS with TID=200.  After invoking
        ``_on_tls``, the bridge must receive 200, not 100.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
            bridge: Recording bridge.
        """
        tab.set_bridge(bridge)

        fiber_combo = _get_fiber_combo(tab)
        tls_combo = _get_tls_thread_combo(tab)

        fiber_combo.addItem("TID 100", 100)
        tls_combo.addItem("TID 200", 200)

        fiber_combo.setCurrentIndex(0)
        tls_combo.setCurrentIndex(0)

        _call_on_tls(tab)

        assert _process_events_until(qapp, lambda: len(bridge.tls_calls) >= 1), "_on_tls never reached the bridge"
        assert bridge.tls_calls[0] == 200, f"Expected TID 200 from _tls_thread_combo, got {bridge.tls_calls[0]}"

    def test_tls_thread_combo_independent_of_fiber_combo(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
        bridge: _RecordingBridge,
    ) -> None:
        """Changing the fiber combo must not affect which TID ``_on_tls`` sends.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
            bridge: Recording bridge.
        """
        tab.set_bridge(bridge)

        fiber_combo = _get_fiber_combo(tab)
        tls_combo = _get_tls_thread_combo(tab)

        fiber_combo.addItem("TID 999", 999)
        tls_combo.addItem("TID 42", 42)

        fiber_combo.setCurrentIndex(0)
        tls_combo.setCurrentIndex(0)

        _call_on_tls(tab)

        assert _process_events_until(qapp, lambda: len(bridge.tls_calls) >= 1)
        assert bridge.tls_calls[0] == 42, f"Expected TID 42 from _tls_thread_combo, got {bridge.tls_calls[0]}"

    def test_tls_and_fiber_combos_dispatch_to_separate_bridge_calls(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
        bridge: _RecordingBridge,
    ) -> None:
        """Each combo must dispatch its own TID — cross-wiring is detected by the bridge.

        Populates ``_fiber_combo`` with TID=777 and ``_tls_thread_combo`` with TID=888.
        After invoking ``_on_tls``, the bridge must have received exactly 888 (the TLS
        combo's value) and NOT 777 (the fiber combo's value).  A developer who wires
        ``_on_tls`` to read from ``_fiber_combo`` will cause bridge.tls_calls[0] == 777,
        failing the assertion.

        Documented falsifying mutation: in ``threads_tab.py`` ``_on_tls()``, change
        ``tid = self._tls_thread_combo.currentData()`` to
        ``tid = self._fiber_combo.currentData()`` — bridge.tls_calls[0] becomes 777,
        not 888, and the ``!= 777`` assertion fails.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
            bridge: Recording bridge.
        """
        tab.set_bridge(bridge)

        fiber_combo = _get_fiber_combo(tab)
        tls_combo = _get_tls_thread_combo(tab)

        fiber_combo.addItem("TID 777", 777)
        tls_combo.addItem("TID 888", 888)

        fiber_combo.setCurrentIndex(0)
        tls_combo.setCurrentIndex(0)

        _call_on_tls(tab)

        assert _process_events_until(qapp, lambda: len(bridge.tls_calls) >= 1), "_on_tls never delivered a TID to the bridge"
        received_tid = bridge.tls_calls[0]
        assert received_tid == 888, f"Expected TID 888 from _tls_thread_combo, got {received_tid}"
        assert received_tid != 777, "_on_tls read from _fiber_combo (got 777) instead of _tls_thread_combo"


# ---------------------------------------------------------------------------
# F-0019: _on_write_registers must honour the last-edited column
# ---------------------------------------------------------------------------


class TestF0019WriteRegistersReadsLastEditedColumn:
    """F-0019: ``_on_write_registers`` must read from the last-edited column."""

    def test_write_registers_reads_decimal_column(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Editing the Decimal column must cause that value to be written.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
            bridge: Recording bridge.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _accept_write_dialog(monkeypatch)
        tab.set_bridge(bridge)
        reg_combo = _get_reg_combo(tab)
        reg_combo.addItem("TID 1", 1)
        reg_combo.setCurrentIndex(0)
        _add_reg_row(tab, "RBX", "0x0", "0")

        reg_table = _get_reg_table(tab)
        dec_item = QTableWidgetItem("12345")
        reg_table.setItem(0, 2, dec_item)

        last_col = _get_reg_last_edited_col(tab)
        assert _process_events_until(qapp, lambda: last_col.get(0) == 2)

        _call_on_write_registers(tab)

        assert _process_events_until(qapp, lambda: len(bridge.set_context_calls) >= 1)
        _tid, regs = bridge.set_context_calls[0]
        assert regs["RBX"] == 12345, f"Expected 12345, got {regs['RBX']}"

    def test_write_registers_reads_hex_column(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
        bridge: _RecordingBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Editing the Hex column last must cause that value to be written.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
            bridge: Recording bridge.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _accept_write_dialog(monkeypatch)
        tab.set_bridge(bridge)
        reg_combo = _get_reg_combo(tab)
        reg_combo.addItem("TID 1", 1)
        reg_combo.setCurrentIndex(0)
        _add_reg_row(tab, "RCX", "0x0", "0")

        reg_table = _get_reg_table(tab)
        hex_item = QTableWidgetItem("0xdeadbeef")
        reg_table.setItem(0, 1, hex_item)

        last_col = _get_reg_last_edited_col(tab)
        assert _process_events_until(qapp, lambda: last_col.get(0) == 1)

        _call_on_write_registers(tab)

        assert _process_events_until(qapp, lambda: len(bridge.set_context_calls) >= 1)
        _tid, regs = bridge.set_context_calls[0]
        assert regs["RCX"] == 0xDEADBEEF, f"Expected 0xDEADBEEF, got {regs['RCX']:#x}"

    def test_decimal_edit_syncs_hex(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
    ) -> None:
        """Editing the Decimal column must update the Hex column to match.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
        """
        del qapp
        _add_reg_row(tab, "RDX", "0x0", "0")

        reg_table = _get_reg_table(tab)
        dec_item = QTableWidgetItem("255")
        reg_table.setItem(0, 2, dec_item)

        hex_item = reg_table.item(0, 1)
        assert hex_item is not None
        assert hex_item.text().lower() == "0xff", f"Expected Hex column to show '0xff', got '{hex_item.text()}'"

    def test_hex_edit_syncs_decimal(
        self,
        qapp: QCoreApplication,
        tab: ThreadsTab,
    ) -> None:
        """Editing the Hex column must update the Decimal column to match.

        Args:
            qapp: Qt application.
            tab: ThreadsTab fixture.
        """
        del qapp
        _add_reg_row(tab, "RSP", "0x0", "0")

        reg_table = _get_reg_table(tab)
        hex_item = QTableWidgetItem("0x100")
        reg_table.setItem(0, 1, hex_item)

        dec_item = reg_table.item(0, 2)
        assert dec_item is not None
        assert dec_item.text() == "256", f"Expected Decimal column to show '256', got '{dec_item.text()}'"
