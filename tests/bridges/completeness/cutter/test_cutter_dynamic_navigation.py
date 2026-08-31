# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge-completeness gate tests for the Cutter/Rizin dynamic & navigation slice.

Covers ``audit/bridge-completeness/agent-04-cutter-rizin-dynamic-navigation.md``
and its verifier. This slice's 37 NO-CONTROL rows were all L1/L2-complete
already (real bridge methods, real tool-defs); the remediation gap was
entirely Layer 3 (GUI). This file gates the three new panel modules that
close it:

* ``cutter_debugger_tab.py`` -- ``DebuggerTab`` (rows 1-15, 18, 20: attach,
  detach, breakpoints, stepping, continue, registers, memory read/write,
  memory regions, threads, modules).
* ``cutter_project_tab.py`` -- ``ProjectTab`` (rows 43-45: save/open/list
  project).
* ``cutter_search_tab.py`` -- ``SearchTab`` (rows 27-35: byte/wildcard/
  string/assembly/crypto/magic/value search plus byte/disassembly compare).

Every test drives the real Qt widget's button-click handler (not a
re-implementation of it) against a real ``CutterBridge`` backed by a
recording r2pipe double -- the genuine external boundary a live rizin child
process would occupy in this sandbox -- then pumps the Qt event loop until
the real background ``run_bridge_coroutine_logged`` worker thread delivers
its result, and asserts the exact rizin command issued and/or the exact
value rendered into the real Qt widget.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import (
    QComboBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
)

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.ui.panels.cutter_debugger_tab import DebuggerTab
from intellicrack.ui.panels.cutter_project_tab import ProjectTab
from intellicrack.ui.panels.cutter_search_tab import SearchTab
from tests.bridges.completeness.cutter.conftest import CommandRecorder, as_r2pipe


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.02


def _pump_until(app: QApplication, predicate: object, *, timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate()`` is truthy or the timeout elapses.

    Args:
        app: The live ``QApplication`` instance used to process pending events.
        predicate: Zero-argument callable checked after each pump iteration.
        timeout_s: Maximum time in seconds to keep pumping.

    Returns:
        bool: ``True`` if ``predicate()`` became truthy before the timeout,
        ``False`` otherwise.
    """
    assert callable(predicate)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


def _no_op_run_async(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None,
    on_error: Callable[[object], None] | None,
) -> None:
    """Discard a coroutine without scheduling it, matching ``RunAsyncFn``.

    Used in place of a lambda so ``ProjectTab.refresh``'s ``_run_async``
    parameter type is fully resolved by basedpyright instead of inferred as
    partially unknown.

    Args:
        coro: Coroutine that would normally be scheduled onto a worker thread.
        on_success: Deprecated success callback, retained for parity with the
            production ``RunAsyncFn`` signature.
        on_error: Deprecated error callback, retained for parity with the
            production ``RunAsyncFn`` signature.
    """
    coro.close()
    del on_success
    del on_error


def _attached_bridge(recorder: CommandRecorder, pid: int = 4242) -> CutterBridge:
    """Build a real ``CutterBridge`` in the attached state via the production ``attach()`` path.

    Args:
        recorder: Command recorder to install as the r2 pipe.
        pid: Process id to attach to.

    Returns:
        CutterBridge: A bridge with ``state.process_attached`` True.
    """
    bridge = CutterBridge()
    bridge.r2 = as_r2pipe(recorder)
    asyncio.run(bridge.attach(pid))
    recorder.commands.clear()
    return bridge


def _find_register_row(reg_table: QTableWidget, register_name: str) -> int:
    """Find the row index whose first-column text matches the given register name.

    Args:
        reg_table: The register ``QTableWidget`` to search.
        register_name: Register name to look up (e.g. ``"rax"``).

    Returns:
        int: The matching row index.

    Raises:
        AssertionError: If no row's first-column item matches, or a
            first-column cell is unexpectedly empty.
    """
    for row in range(reg_table.rowCount()):
        name_item = reg_table.item(row, 0)
        assert name_item is not None
        if name_item.text() == register_name:
            return row
    error_message = f"register {register_name!r} not found in table"
    raise AssertionError(error_message)


def _item_text(table: QTableWidget, row: int, column: int) -> str:
    """Return the text of a table cell, asserting the cell item is not ``None``.

    Args:
        table: The ``QTableWidget`` to read from.
        row: Row index of the cell.
        column: Column index of the cell.

    Returns:
        str: The cell's text content.
    """
    item = table.item(row, column)
    assert item is not None
    return item.text()


def _list_item_text(list_widget: QListWidget, row: int) -> str:
    """Return the text of a list-widget item, asserting the item is not ``None``.

    Args:
        list_widget: The ``QListWidget`` to read from.
        row: Row index of the item.

    Returns:
        str: The item's text content.
    """
    item = list_widget.item(row)
    assert item is not None
    return item.text()


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabAttachDetach:
    """L3 gate: rows 1-2 -- Attach/Detach buttons must invoke the real bridge methods."""

    @staticmethod
    def test_attach_button_issues_dp_command_and_updates_status(qapp: QApplication) -> None:
        """Clicking Attach with a PID must issue rizin's ``dp <pid>`` and update the status label.

        Falsifiable: if ``DebuggerTab._on_attach`` never called
        ``self._bridge.attach(pid)``, 'dp 4242' would never appear in the
        recorder and the status label would remain 'Not attached'. Broken
        production line: the ``run_bridge_coroutine_logged(self._bridge.attach(pid), ...)``
        call in ``DebuggerTab._on_attach`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dbj": "[]", "dmj": "[]", "dptj": "[]", "dmIj": "[]", "drj": "{}"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        pid_input = cast(QLineEdit, getattr(tab, "_pid_input"))
        status_label = cast(QLabel, getattr(tab, "_status_label"))
        on_attach = cast(Callable[[], None], getattr(tab, "_on_attach"))
        pid_input.setText("4242")

        on_attach()

        assert _pump_until(qapp, lambda: "dp 4242" in recorder.commands)
        assert "dp 4242" in recorder.commands
        assert _pump_until(qapp, lambda: status_label.text() == "Attached to PID 4242")
        assert bridge.state.process_attached is True

    @staticmethod
    def test_detach_button_issues_dp_dash_and_clears_tables(qapp: QApplication) -> None:
        """Clicking Detach must issue rizin's ``dp-`` and clear the register/breakpoint tables.

        Falsifiable: if ``_on_detach`` never called ``self._bridge.detach()``,
        'dp-' would never appear in the recorder and the tables would keep
        their prior rows. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.detach(), ...)`` call in
        ``DebuggerTab._on_detach`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "drj": '{"rax":1}',
        })
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        reg_table = cast(QTableWidget, getattr(tab, "_reg_table"))
        status_label = cast(QLabel, getattr(tab, "_status_label"))
        refresh_registers = cast(Callable[[], None], getattr(tab, "_refresh_registers"))
        on_detach = cast(Callable[[], None], getattr(tab, "_on_detach"))
        refresh_registers()
        assert _pump_until(qapp, lambda: reg_table.rowCount() > 0)

        on_detach()

        assert _pump_until(qapp, lambda: "dp-" in recorder.commands)
        assert "dp-" in recorder.commands
        assert _pump_until(qapp, lambda: reg_table.rowCount() == 0)
        assert status_label.text() == "Not attached"
        assert bridge.state.process_attached is False


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabBreakpoints:
    """L3 gate: rows 3-5 -- breakpoint Add/Remove controls and the breakpoints table."""

    @staticmethod
    def test_add_breakpoint_issues_db_command_and_refreshes_table(qapp: QApplication) -> None:
        """Clicking Add with an address must issue rizin's ``db <addr>`` and populate the breakpoints table.

        Falsifiable: if ``_on_add_breakpoint`` never called
        ``self._bridge.set_breakpoint``, 'db 4096' would never appear in the
        recorder and the breakpoints table would remain empty after the
        refresh. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.set_breakpoint(address, bp_type, condition), ...)``
        call in ``DebuggerTab._on_add_breakpoint`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dbj": '[{"addr":4096,"type":"software","enabled":true,"hits":0}]'})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        bp_addr_input = cast(QLineEdit, getattr(tab, "_bp_addr_input"))
        bp_type_combo = cast(QComboBox, getattr(tab, "_bp_type_combo"))
        bp_table = cast(QTableWidget, getattr(tab, "_bp_table"))
        on_add_breakpoint = cast(Callable[[], None], getattr(tab, "_on_add_breakpoint"))
        bp_addr_input.setText("0x1000")
        bp_type_combo.setCurrentText("software")

        on_add_breakpoint()

        assert _pump_until(qapp, lambda: "db 4096" in recorder.commands)
        assert "db 4096" in recorder.commands
        assert _pump_until(qapp, lambda: bp_table.rowCount() > 0)
        addr_item = bp_table.item(0, 0)
        assert addr_item is not None
        assert addr_item.text() == f"0x{4096:X}"

    @staticmethod
    def test_remove_breakpoint_issues_db_dash_command(qapp: QApplication) -> None:
        """Clicking Remove with an address must issue rizin's ``db- <addr>``.

        Falsifiable: if ``_on_remove_breakpoint`` never called
        ``self._bridge.remove_breakpoint``, 'db- 4096' would never appear in
        the recorder.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dbj": "[]"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        bp_addr_input = cast(QLineEdit, getattr(tab, "_bp_addr_input"))
        on_remove_breakpoint = cast(Callable[[], None], getattr(tab, "_on_remove_breakpoint"))
        bp_addr_input.setText("0x1000")

        on_remove_breakpoint()

        assert _pump_until(qapp, lambda: "db- 4096" in recorder.commands)
        assert "db- 4096" in recorder.commands


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabSteppingAndContinue:
    """L3 gate: rows 6-8 -- Step Into/Step Over/Continue buttons."""

    @staticmethod
    def test_step_into_issues_ds_and_updates_pc_status(qapp: QApplication) -> None:
        """Clicking Step Into must issue rizin's ``ds`` and reflect the returned PC in the status label.

        Falsifiable: if ``_on_step_into`` called ``step_over`` instead of
        ``step_into``, 'dso' would appear instead of 'ds', and this
        assertion (checking 'ds' is issued and 'dso' is not) would fail.
        Broken production line: ``self._bridge.step_into()`` call in
        ``DebuggerTab._on_step_into`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dr?PC": "0x401234", "dbj": "[]", "dmj": "[]", "dptj": "[]", "dmIj": "[]", "drj": "{}"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        status_label = cast(QLabel, getattr(tab, "_status_label"))
        on_step_into = cast(Callable[[], None], getattr(tab, "_on_step_into"))

        on_step_into()

        assert _pump_until(qapp, lambda: "ds" in recorder.commands)
        assert "ds" in recorder.commands
        assert "dso" not in recorder.commands
        assert _pump_until(qapp, lambda: status_label.text().startswith("PC = 0x401234"))

    @staticmethod
    def test_step_over_issues_dso(qapp: QApplication) -> None:
        """Clicking Step Over must issue rizin's ``dso``, not the step-into ``ds``.

        Falsifiable: same production line reasoning as step-into, mirrored
        for ``_on_step_over``/``step_over()``.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dr?PC": "0x401234", "dbj": "[]", "dmj": "[]", "dptj": "[]", "dmIj": "[]", "drj": "{}"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        on_step_over = cast(Callable[[], None], getattr(tab, "_on_step_over"))

        on_step_over()

        assert _pump_until(qapp, lambda: "dso" in recorder.commands)
        assert "dso" in recorder.commands

    @staticmethod
    def test_continue_issues_dc_and_sets_stopped_status(qapp: QApplication) -> None:
        """Clicking Continue must issue rizin's ``dc`` and set the status label to 'Stopped'.

        Falsifiable: if ``_on_continue`` never called ``self._bridge.run()``,
        'dc' would never be recorded and the status label would not read
        'Stopped'.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dbj": "[]", "dmj": "[]", "dptj": "[]", "dmIj": "[]", "drj": "{}"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        status_label = cast(QLabel, getattr(tab, "_status_label"))
        on_continue = cast(Callable[[], None], getattr(tab, "_on_continue"))

        on_continue()

        assert _pump_until(qapp, lambda: "dc" in recorder.commands)
        assert "dc" in recorder.commands
        assert _pump_until(qapp, lambda: status_label.text() == "Stopped")


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabRegisters:
    """L3 gate: rows 9-10 -- register table refresh and in-place register editing."""

    @staticmethod
    def test_refresh_registers_calls_drj_and_populates_table(qapp: QApplication) -> None:
        """The register table must issue rizin's ``drj`` and render the real rax value.

        Falsifiable: if ``_refresh_registers`` never called
        ``self._bridge.get_registers()``, 'drj' would never be recorded and
        the table would stay empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"drj": '{"rax": 305441741, "rip": 4198400}'})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        reg_table = cast(QTableWidget, getattr(tab, "_reg_table"))
        refresh_registers = cast(Callable[[], None], getattr(tab, "_refresh_registers"))

        refresh_registers()

        assert _pump_until(qapp, lambda: reg_table.rowCount() > 0)
        assert "drj" in recorder.commands
        rax_row = _find_register_row(reg_table, "rax")
        value_item = reg_table.item(rax_row, 1)
        assert value_item is not None
        assert value_item.text() == f"0x{305441741:X}"

    @staticmethod
    def test_edit_register_cell_issues_dr_set_command(qapp: QApplication) -> None:
        """Editing a register value cell must issue rizin's ``dr <reg>=<value>``.

        Falsifiable: if ``_on_register_edited`` never called
        ``self._bridge.set_register``, 'dr rax=291' would never be recorded.
        Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.set_register(reg_name, value), ...)``
        call in ``DebuggerTab._on_register_edited`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"drj": '{"rax": 1}'})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        reg_table = cast(QTableWidget, getattr(tab, "_reg_table"))
        refresh_registers = cast(Callable[[], None], getattr(tab, "_refresh_registers"))
        on_register_edited = cast(Callable[[int, int], None], getattr(tab, "_on_register_edited"))
        refresh_registers()
        assert _pump_until(qapp, lambda: reg_table.rowCount() > 0)
        recorder.commands.clear()

        rax_row = _find_register_row(reg_table, "rax")
        reg_table.setItem(rax_row, 1, QTableWidgetItem("0x123"))
        on_register_edited(rax_row, 1)

        assert _pump_until(qapp, lambda: "dr rax=291" in recorder.commands)
        assert "dr rax=291" in recorder.commands


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabMemory:
    """L3 gate: rows 11-12 -- memory Read/Write controls."""

    @staticmethod
    def test_read_memory_issues_p8_and_renders_hex_dump(qapp: QApplication) -> None:
        """Clicking Read must issue rizin's ``p8 <size> @ <addr>`` and render a hex dump containing the real bytes.

        Falsifiable: if ``_on_read_memory`` never called
        ``self._bridge.read_memory``, 'p8 4 @ 4096' would never be recorded
        and the dump view would stay empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"p8 4 @ 4096": "deadbeef"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        mem_addr_input = cast(QLineEdit, getattr(tab, "_mem_addr_input"))
        mem_size_input = cast(QLineEdit, getattr(tab, "_mem_size_input"))
        mem_dump = cast(QPlainTextEdit, getattr(tab, "_mem_dump"))
        on_read_memory = cast(Callable[[], None], getattr(tab, "_on_read_memory"))
        mem_addr_input.setText("0x1000")
        mem_size_input.setText("4")

        on_read_memory()

        assert _pump_until(qapp, lambda: "p8 4 @ 4096" in recorder.commands)
        assert "p8 4 @ 4096" in recorder.commands
        assert _pump_until(qapp, lambda: bool(mem_dump.toPlainText()))
        assert "de ad be ef" in mem_dump.toPlainText().lower()

    @staticmethod
    def test_write_memory_issues_wx_and_rereads(qapp: QApplication) -> None:
        """Clicking Write must issue rizin's ``wx <hex> @ <addr>`` and then re-read the region.

        Falsifiable: if ``_on_write_memory`` never called
        ``self._bridge.write_memory``, 'wx 90909090 @ 4096' would never be
        recorded. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.write_memory(address, data), ...)``
        call in ``DebuggerTab._on_write_memory`` (``cutter_debugger_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"wx 90909090 @ 4096": "", "p8 4 @ 4096": "90909090"})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        mem_addr_input = cast(QLineEdit, getattr(tab, "_mem_addr_input"))
        mem_size_input = cast(QLineEdit, getattr(tab, "_mem_size_input"))
        mem_write_input = cast(QLineEdit, getattr(tab, "_mem_write_input"))
        on_write_memory = cast(Callable[[], None], getattr(tab, "_on_write_memory"))
        mem_addr_input.setText("0x1000")
        mem_size_input.setText("4")
        mem_write_input.setText("90909090")

        on_write_memory()

        assert _pump_until(qapp, lambda: "wx 90909090 @ 4096" in recorder.commands)
        assert "wx 90909090 @ 4096" in recorder.commands
        assert _pump_until(qapp, lambda: "p8 4 @ 4096" in recorder.commands)


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabRegionsThreadsModules:
    """L3 gate: rows 13-15 -- memory regions, threads, and loaded-modules tables."""

    @staticmethod
    def test_refresh_regions_calls_dmj_and_populates_table(qapp: QApplication) -> None:
        """The memory-regions table must issue rizin's ``dmj`` and render the real base address.

        Falsifiable: if ``_refresh_regions`` never called
        ``self._bridge.get_memory_regions()``, 'dmj' would never be recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dmj": '[{"addr":4096,"addr_end":8192,"perm":"r-x","name":"target.exe"}]'})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        regions_table = cast(QTableWidget, getattr(tab, "_regions_table"))
        refresh_regions = cast(Callable[[], None], getattr(tab, "_refresh_regions"))

        refresh_regions()

        assert _pump_until(qapp, lambda: regions_table.rowCount() > 0)
        assert "dmj" in recorder.commands
        assert _item_text(regions_table, 0, 0) == f"0x{4096:X}"
        assert _item_text(regions_table, 0, 1) == str(4096)
        assert _item_text(regions_table, 0, 2) == "r-x"

    @staticmethod
    def test_refresh_threads_calls_dptj_and_populates_table(qapp: QApplication) -> None:
        """The threads table must issue rizin's ``dptj`` and render the real thread id.

        Falsifiable: if ``_refresh_threads`` never called
        ``self._bridge.get_threads()``, 'dptj' would never be recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"dptj": '[{"pid":777,"pc":4198400,"status":"running"}]'})
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        threads_table = cast(QTableWidget, getattr(tab, "_threads_table"))
        refresh_threads = cast(Callable[[], None], getattr(tab, "_refresh_threads"))

        refresh_threads()

        assert _pump_until(qapp, lambda: threads_table.rowCount() > 0)
        assert "dptj" in recorder.commands
        assert _item_text(threads_table, 0, 0) == "777"
        assert _item_text(threads_table, 0, 3) == "running"

    @staticmethod
    def test_refresh_modules_calls_dmij_and_populates_table(qapp: QApplication) -> None:
        """The modules table must issue rizin's ``dmIj`` and render the real module name.

        Falsifiable: if ``_refresh_modules`` never called
        ``self._bridge.get_modules()``, 'dmIj' would never be recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({
            "dmIj": '[{"name":"ntdll.dll","addr":1996488704,"size":2097152,"entry":1996490000}]',
        })
        bridge = _attached_bridge(recorder)

        tab = DebuggerTab()
        tab.set_bridge(bridge)
        modules_table = cast(QTableWidget, getattr(tab, "_modules_table"))
        refresh_modules = cast(Callable[[], None], getattr(tab, "_refresh_modules"))

        refresh_modules()

        assert _pump_until(qapp, lambda: modules_table.rowCount() > 0)
        assert "dmIj" in recorder.commands
        assert _item_text(modules_table, 0, 0) == "ntdll.dll"
        assert _item_text(modules_table, 0, 1) == f"0x{1996488704:X}"


@pytest.mark.usefixtures("qapp")
class TestProjectTabSaveOpenList:
    """L3 gate: rows 43-45 -- Save/Open/Refresh project controls."""

    @staticmethod
    def test_save_button_issues_ps_command_and_refreshes_list(qapp: QApplication) -> None:
        """Clicking Save with a project name must issue rizin's ``Ps <name>`` and then re-list projects.

        Falsifiable: if ``_on_save`` never called
        ``self._bridge.save_project``, 'Ps license_analysis' would never be
        recorded. Broken production line: the
        ``run_bridge_coroutine_logged(self._bridge.save_project(name), ...)``
        call in ``ProjectTab._on_save`` (``cutter_project_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"Ps license_analysis": "", "Pl": "license_analysis\n"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ProjectTab()
        tab.set_bridge(bridge)
        name_input = cast(QLineEdit, getattr(tab, "_name_input"))
        project_list = cast(QListWidget, getattr(tab, "_project_list"))
        on_save = cast(Callable[[], None], getattr(tab, "_on_save"))
        name_input.setText("license_analysis")

        on_save()

        assert _pump_until(qapp, lambda: "Ps license_analysis" in recorder.commands)
        assert "Ps license_analysis" in recorder.commands
        assert _pump_until(qapp, lambda: "Pl" in recorder.commands)
        assert _pump_until(qapp, lambda: project_list.count() > 0)
        assert _list_item_text(project_list, 0) == "license_analysis"

    @staticmethod
    def test_open_button_issues_po_command(qapp: QApplication) -> None:
        """Clicking Open with a project name must issue rizin's ``Po <name>``.

        Falsifiable: if ``_on_open`` never called
        ``self._bridge.open_project``, 'Po license_analysis' would never be
        recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"Po license_analysis": ""})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ProjectTab()
        tab.set_bridge(bridge)
        name_input = cast(QLineEdit, getattr(tab, "_name_input"))
        status_label = cast(QLabel, getattr(tab, "_status_label"))
        on_open = cast(Callable[[], None], getattr(tab, "_on_open"))
        name_input.setText("license_analysis")

        on_open()

        assert _pump_until(qapp, lambda: "Po license_analysis" in recorder.commands)
        assert "Po license_analysis" in recorder.commands
        assert _pump_until(qapp, lambda: status_label.text() == "Opened project 'license_analysis'")

    @staticmethod
    def test_refresh_lists_real_multiple_projects(qapp: QApplication) -> None:
        """Refresh must issue rizin's ``Pl`` and split its multi-line text output into real list entries.

        Falsifiable: if ``_on_refresh`` never called
        ``self._bridge.list_projects()`` or mis-parsed its line-based
        output, the list widget would not contain both real project names.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"Pl": "alpha_target\nbeta_target\n"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ProjectTab()
        tab.refresh(bridge, _no_op_run_async)
        project_list = cast(QListWidget, getattr(tab, "_project_list"))

        assert _pump_until(qapp, lambda: project_list.count() == 2)
        names: set[str] = {_list_item_text(project_list, i) for i in range(project_list.count())}
        assert names == {"alpha_target", "beta_target"}

    @staticmethod
    def test_double_click_project_opens_it(qapp: QApplication) -> None:
        """Double-clicking a listed project must open it via the real bridge call.

        Falsifiable: if ``_on_item_double_clicked`` never invoked
        ``_open_project``, 'Po beta_target' would never be recorded.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"Pl": "beta_target\n", "Po beta_target": ""})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = ProjectTab()
        tab.refresh(bridge, _no_op_run_async)
        project_list = cast(QListWidget, getattr(tab, "_project_list"))
        on_item_double_clicked = cast(Callable[[QListWidgetItem], None], getattr(tab, "_on_item_double_clicked"))
        assert _pump_until(qapp, lambda: project_list.count() == 1)
        recorder.commands.clear()

        item = project_list.item(0)
        assert item is not None
        on_item_double_clicked(item)

        assert _pump_until(qapp, lambda: "Po beta_target" in recorder.commands)
        assert "Po beta_target" in recorder.commands


@pytest.mark.usefixtures("qapp")
class TestSearchTabByteModes:
    """L3 gate: rows 27-28 -- byte pattern and wildcard byte pattern search modes."""

    @staticmethod
    def test_bytes_mode_issues_xj_with_clean_hex(qapp: QApplication) -> None:
        """Bytes mode must issue rizin's ``/xj`` with the exact hex pattern and render the matched address.

        Falsifiable: if ``_on_search`` dispatched a different bridge method
        for Bytes mode, '/xj 4889e5' would never be recorded and the result
        table would stay empty. Broken production line: the
        ``self._bridge.search_bytes(pattern)`` branch of
        ``SearchTab._on_search`` (``cutter_search_tab.py``).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/xj 4889e5": '[{"offset":4198400}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        asyncio.run(bridge.analyze("quick"))
        recorder.commands.clear()

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        pattern_input = cast(QLineEdit, getattr(tab, "_pattern_input"))
        results_table = cast(QTableWidget, getattr(tab, "_results_table"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Bytes")
        pattern_input.setText("48 89 e5")

        on_search()

        assert _pump_until(qapp, lambda: "/xj 4889e5" in recorder.commands)
        assert "/xj 4889e5" in recorder.commands
        assert _pump_until(qapp, lambda: results_table.rowCount() > 0)
        assert _item_text(results_table, 0, 0) == f"0x{4198400:X}"

    @staticmethod
    def test_wildcard_mode_translates_question_marks_to_dots(qapp: QApplication) -> None:
        """Wildcard Bytes mode must translate '??' into rizin's '..' wildcard syntax before issuing ``/xj``.

        Falsifiable: if the wildcard mode called plain ``search_bytes``
        (which does not translate wildcards) instead of
        ``search_bytes_wildcard``, the literal string '4889????' would be
        sent instead of '4889....', and this assertion would fail.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/xj 4889....": "[]"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)
        asyncio.run(bridge.analyze("quick"))
        recorder.commands.clear()

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        pattern_input = cast(QLineEdit, getattr(tab, "_pattern_input"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Wildcard Bytes")
        pattern_input.setText("48 89 ?? ??")

        on_search()

        assert _pump_until(qapp, lambda: "/xj 4889...." in recorder.commands)
        assert "/xj 4889...." in recorder.commands


@pytest.mark.usefixtures("qapp")
class TestSearchTabStringAssemblyModes:
    """L3 gate: rows 29-30 -- literal string search and assembly-pattern search modes."""

    @staticmethod
    def test_string_mode_encodes_text_as_utf8_hex(qapp: QApplication) -> None:
        """String mode must UTF-8-hex-encode the pattern before issuing ``/xj`` (injection-safe path).

        Falsifiable: if String mode dispatched the regex-based
        ``search_strings`` (``izj``) instead of ``search_string_live``
        (``/xj`` on encoded bytes), the exact hex-encoded command below
        would never be issued.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        expected_hex = "4f4b".lower()
        recorder = CommandRecorder({f"/xj {expected_hex}": '[{"offset":8192}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        pattern_input = cast(QLineEdit, getattr(tab, "_pattern_input"))
        results_table = cast(QTableWidget, getattr(tab, "_results_table"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("String")
        pattern_input.setText("OK")

        on_search()

        assert _pump_until(qapp, lambda: f"/xj {expected_hex}" in recorder.commands)
        assert f"/xj {expected_hex}" in recorder.commands
        assert _pump_until(qapp, lambda: results_table.rowCount() > 0)
        assert _item_text(results_table, 0, 0) == f"0x{8192:X}"

    @staticmethod
    def test_assembly_mode_issues_aj_with_raw_pattern(qapp: QApplication) -> None:
        """Assembly mode must issue rizin's ``/aj <pattern>`` verbatim.

        Falsifiable: if Assembly mode dispatched ``search_bytes`` instead of
        ``search_assembly_pattern``, '/aj mov eax, ebx' would never be
        recorded (a '/xj ...' command would appear instead).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/aj mov eax, ebx": '[{"offset":16}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        pattern_input = cast(QLineEdit, getattr(tab, "_pattern_input"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Assembly")
        pattern_input.setText("mov eax, ebx")

        on_search()

        assert _pump_until(qapp, lambda: "/aj mov eax, ebx" in recorder.commands)
        assert "/aj mov eax, ebx" in recorder.commands


@pytest.mark.usefixtures("qapp")
class TestSearchTabCryptoMagicValueModes:
    """L3 gate: rows 31-33 -- crypto-constant, magic-signature, and numeric-value search modes."""

    @staticmethod
    def test_crypto_mode_issues_cj_with_no_pattern_required(qapp: QApplication) -> None:
        """Crypto Constants mode must issue rizin's ``/cj`` even with the pattern field disabled/empty.

        Falsifiable: if Crypto mode required a non-empty pattern before
        dispatching (like Bytes mode does), '/cj' would never be issued for
        an empty pattern field.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/cj": '[{"offset":32,"name":"AES_SBOX"}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        results_table = cast(QTableWidget, getattr(tab, "_results_table"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Crypto Constants")

        on_search()

        assert _pump_until(qapp, lambda: "/cj" in recorder.commands)
        assert "/cj" in recorder.commands
        assert _pump_until(qapp, lambda: results_table.rowCount() > 0)
        assert _item_text(results_table, 0, 1) == "AES_SBOX"

    @staticmethod
    def test_magic_mode_issues_mj(qapp: QApplication) -> None:
        """Magic Signatures mode must issue rizin's ``/mj``.

        Falsifiable: if Magic mode dispatched ``search_crypto_constants``
        instead of ``search_magic``, '/mj' would never appear (only '/cj'
        would).

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/mj": "[]"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Magic Signatures")

        on_search()

        assert _pump_until(qapp, lambda: "/mj" in recorder.commands)
        assert "/mj" in recorder.commands

    @staticmethod
    def test_value_mode_issues_vj_sized_by_the_size_combo(qapp: QApplication) -> None:
        """Numeric Value mode must issue rizin's ``/vj<size> <value>`` using the selected value-size combo entry.

        Falsifiable: if the value-size combo box selection were not
        threaded through to ``search_value``'s ``size`` argument, '/vj8'
        (8-byte) would never be issued when '8' is selected -- the default
        '/vj4' would appear instead.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"/vj8 1234": '[{"offset":48}]'})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        mode_combo = cast(QComboBox, getattr(tab, "_mode_combo"))
        value_size_combo = cast(QComboBox, getattr(tab, "_value_size_combo"))
        pattern_input = cast(QLineEdit, getattr(tab, "_pattern_input"))
        results_table = cast(QTableWidget, getattr(tab, "_results_table"))
        on_search = cast(Callable[[], None], getattr(tab, "_on_search"))
        mode_combo.setCurrentText("Numeric Value")
        value_size_combo.setCurrentText("8")
        pattern_input.setText("1234")

        on_search()

        assert _pump_until(qapp, lambda: "/vj8 1234" in recorder.commands)
        assert "/vj8 1234" in recorder.commands
        assert _pump_until(qapp, lambda: results_table.rowCount() > 0)
        assert _item_text(results_table, 0, 0) == f"0x{48:X}"


@pytest.mark.usefixtures("qapp")
class TestSearchTabCompare:
    """L3 gate: rows 34-35 -- byte comparison and disassembly comparison controls."""

    @staticmethod
    def test_compare_bytes_issues_c_command_and_renders_output(qapp: QApplication) -> None:
        """Clicking Compare Bytes must issue rizin's ``c <hex> @ <addr>`` and render the returned diff text.

        Falsifiable: if ``_on_compare_bytes`` never called
        ``self._bridge.compare_bytes``, 'c 90909090 @ 4096' would never
        appear and the compare output view would stay empty.

        Args:
            qapp: Qt application fixture used to pump the event loop.
        """
        recorder = CommandRecorder({"c 90909090 @ 4096": "0x00001000 90909090 == 90909090"})
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        compare_addr_input = cast(QLineEdit, getattr(tab, "_compare_addr_input"))
        compare_hex_input = cast(QLineEdit, getattr(tab, "_compare_hex_input"))
        compare_output = cast(QPlainTextEdit, getattr(tab, "_compare_output"))
        on_compare_bytes = cast(Callable[[], None], getattr(tab, "_on_compare_bytes"))
        compare_addr_input.setText("0x1000")
        compare_hex_input.setText("90909090")

        on_compare_bytes()

        assert _pump_until(qapp, lambda: "c 90909090 @ 4096" in recorder.commands)
        assert "c 90909090 @ 4096" in recorder.commands
        assert _pump_until(qapp, lambda: bool(compare_output.toPlainText()))
        assert compare_output.toPlainText() == "0x00001000 90909090 == 90909090"

    @staticmethod
    def test_compare_disassembly_issues_disasm_and_json_diff_commands(qapp: QApplication, tmp_path: Path) -> None:
        """Clicking Compare Disasm must issue rizin's ``cD`` and ``cCj`` with the selected file path and address.

        Falsifiable: if ``_on_compare_disassembly`` never called
        ``self._bridge.compare_disassembly``, neither 'cD' nor 'cCj' would
        appear with the real file path substituted in.

        Args:
            qapp: Qt application fixture used to pump the event loop.
            tmp_path: Pytest-managed temporary directory for the compare target.
        """
        other_bin = tmp_path / "other.bin"
        recorder = CommandRecorder({
            f"cD {other_bin} @ 4096": "diff-line-1",
            f"cCj {other_bin} @ 4096": '{"match": true}',
        })
        bridge = CutterBridge()
        bridge.r2 = as_r2pipe(recorder)

        tab = SearchTab()
        tab.set_bridge(bridge)
        compare_addr_input = cast(QLineEdit, getattr(tab, "_compare_addr_input"))
        compare_file_input = cast(QLineEdit, getattr(tab, "_compare_file_input"))
        compare_output = cast(QPlainTextEdit, getattr(tab, "_compare_output"))
        on_compare_disassembly = cast(Callable[[], None], getattr(tab, "_on_compare_disassembly"))
        compare_addr_input.setText("0x1000")
        compare_file_input.setText(str(other_bin))

        on_compare_disassembly()

        assert _pump_until(qapp, lambda: f"cD {other_bin} @ 4096" in recorder.commands)
        assert f"cD {other_bin} @ 4096" in recorder.commands
        assert f"cCj {other_bin} @ 4096" in recorder.commands
        assert _pump_until(qapp, lambda: bool(compare_output.toPlainText()))
        assert "diff-line-1" in compare_output.toPlainText()
        assert '{"match": true}' in compare_output.toPlainText()
