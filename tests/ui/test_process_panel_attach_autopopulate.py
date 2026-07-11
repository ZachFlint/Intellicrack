# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for ProcessPanel attach-time auto-population.

Covers three Phase 3 P2 findings, all driven against a real, live
``ProcessBridge`` attached to the running test process itself
(``os.getpid()``) so the assertions exercise genuine Win32 calls
(``ReadProcessMemory``, ``CreateToolhelp32Snapshot``) rather than mocked
bridge output:

* Memory content read: the Read sub-tab's address field defaulted to empty
  text, so pressing Read before typing an address failed against an
  unreadable target. ``MemoryTab.set_attached_pid`` now prefills the field
  with the attached process's main-module base address (always a committed,
  readable region), and a Read against that default must return real bytes.
* Threads/Modules required a manual Refresh click after attach before they
  showed any rows. ``ProcessPanel._on_process_attached`` now triggers
  ``ThreadsTab.refresh()`` / ``ModulesTab.refresh()`` immediately, and
  ``ProcessPanel._on_tab_widget_changed`` triggers the same refresh when the
  Threads/Modules tab becomes the active tab while attached.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import ProcessPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication

_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.02


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async bridge coroutine to completion on a private event loop.

    Args:
        coro: The awaitable coroutine to execute.

    Returns:
        T: The resolved result of the coroutine.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


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


@pytest.fixture
def panel(qapp: QApplication) -> Generator[ProcessPanel]:
    """Create a ProcessPanel and tear it down through its real stop_tool path.

    Args:
        qapp: QApplication fixture from conftest.

    Yields:
        ProcessPanel: ProcessPanel widget.
    """
    p = ProcessPanel()
    yield p
    p.stop_tool()
    qapp.processEvents()
    p.deleteLater()
    qapp.processEvents()


@pytest.fixture
def attached_panel(panel: ProcessPanel, qapp: QApplication) -> ProcessPanel:
    """Attach ``panel`` to the live test process via a real, initialized bridge.

    Args:
        panel: Freshly constructed ProcessPanel fixture.
        qapp: QApplication fixture from conftest.

    Returns:
        ProcessPanel: The panel, attached to ``os.getpid()`` through a real
        ``ProcessBridge.open_process`` call.
    """
    live_bridge = ProcessBridge()
    _run(live_bridge.initialize())
    panel.set_bridge(live_bridge)

    pid = os.getpid()
    opened = _run(live_bridge.open_process(pid))
    assert opened, "real ProcessBridge.open_process must succeed against the live test process"

    panel._on_process_attached(pid)
    qapp.processEvents()
    return panel


class TestMemoryDefaultReadAddressIsReadable:
    """Memory -> Read must default to a committed, readable address on attach."""

    def test_attach_prefills_read_address_with_module_base(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """Attaching must populate the Read address field without user input.

        Pre-fix ``_read_addr`` stayed empty until the user typed something,
        so pressing Read immediately after attach either failed to parse
        (empty string) or -- if some other default were used -- could target
        an unreadable address. This asserts a real hex address string lands
        in the field once ``get_modules`` resolves.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        memory_tab = attached_panel._memory_tab
        populated = _pump_until(qapp, lambda: bool(memory_tab._read_addr.text()))
        assert populated, "Read address field was never auto-populated after attach"
        assert memory_tab._read_addr.text().startswith("0x")
        assert int(memory_tab._read_addr.text(), 16) != 0, "default read address must not be the null address"

    def test_read_against_the_default_address_returns_real_bytes(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """Pressing Read against the auto-populated default must succeed.

        Drives the real ``_on_read`` path (real ``ReadProcessMemory`` via
        the live bridge) against whatever address ``set_attached_pid``
        prefilled, proving the default is genuinely readable rather than
        merely non-empty.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        memory_tab = attached_panel._memory_tab
        populated = _pump_until(qapp, lambda: bool(memory_tab._read_addr.text()))
        assert populated, "Read address field was never auto-populated after attach"

        memory_tab._on_read()
        read_done = _pump_until(qapp, lambda: bool(memory_tab._read_output.toPlainText()))
        assert read_done, "Read against the default address never completed"

        output = memory_tab._read_output.toPlainText()
        assert not output.startswith("Error"), f"Read against the default address failed: {output!r}"
        assert not output.startswith("Invalid"), f"Read against the default address failed: {output!r}"


class TestThreadsAutoPopulateOnAttach:
    """Threads must populate immediately on attach, with no manual Refresh."""

    def test_attach_populates_thread_table_without_manual_refresh(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """The thread table must show rows after attach alone.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        threads_tab = attached_panel._threads_tab
        populated = _pump_until(qapp, lambda: threads_tab._thread_table.rowCount() > 0)
        assert populated, "Threads table stayed empty after attach without a manual Refresh click"
        assert threads_tab._thread_count.text() != "0 threads"

    def test_tab_activation_repopulates_threads_when_attached(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """Switching to the Threads tab while attached must (re)populate it.

        Simulates data going stale (e.g. cleared by an unrelated code path)
        and confirms ``ProcessPanel._on_tab_widget_changed`` refreshes the
        table purely from tab activation, independent of the attach-time
        trigger.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        threads_tab = attached_panel._threads_tab
        assert _pump_until(qapp, lambda: threads_tab._thread_table.rowCount() > 0)

        threads_tab._thread_table.setRowCount(0)
        assert threads_tab._thread_table.rowCount() == 0

        threads_index = attached_panel._tab_widget.indexOf(threads_tab)
        attached_panel._tab_widget.setCurrentIndex(threads_index)
        qapp.processEvents()

        repopulated = _pump_until(qapp, lambda: threads_tab._thread_table.rowCount() > 0)
        assert repopulated, "activating the Threads tab while attached did not repopulate the thread table"


class TestModulesAutoPopulateOnAttach:
    """Modules must populate immediately on attach, with no manual Refresh."""

    def test_attach_populates_module_tree_without_manual_refresh(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """The module tree must show entries after attach alone.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        modules_tab = attached_panel._modules_tab
        populated = _pump_until(qapp, lambda: modules_tab._mod_tree.topLevelItemCount() > 0)
        assert populated, "Modules tree stayed empty after attach without a manual Refresh click"
        assert modules_tab._mod_count.text() != "0 modules"

    def test_tab_activation_repopulates_modules_when_attached(self, attached_panel: ProcessPanel, qapp: QApplication) -> None:
        """Switching to the Modules tab while attached must (re)populate it.

        Args:
            attached_panel: ProcessPanel already attached to the live test process.
            qapp: Session QApplication fixture from conftest.
        """
        modules_tab = attached_panel._modules_tab
        assert _pump_until(qapp, lambda: modules_tab._mod_tree.topLevelItemCount() > 0)

        modules_tab._mod_tree.clear()
        assert modules_tab._mod_tree.topLevelItemCount() == 0

        modules_index = attached_panel._tab_widget.indexOf(modules_tab)
        attached_panel._tab_widget.setCurrentIndex(modules_index)
        qapp.processEvents()

        repopulated = _pump_until(qapp, lambda: modules_tab._mod_tree.topLevelItemCount() > 0)
        assert repopulated, "activating the Modules tab while attached did not repopulate the module tree"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
