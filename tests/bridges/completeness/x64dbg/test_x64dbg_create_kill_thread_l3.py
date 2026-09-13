# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Threads tab's Create/Kill thread controls.

``create_thread`` and ``kill_thread`` are new bridge methods (registered as
``x64dbg.create_thread``/``x64dbg.kill_thread``) with matching "Create"/
"Kill" controls on the Threads tab of ``x64dbg_panel.py``. This module
gates the full click-to-RPC round trip for each, including the
``thread_detail`` readback verification: ``create_thread`` must confirm
the new thread id actually appears, and ``kill_thread`` must confirm the
given thread id has actually disappeared rather than reporting success on
a kill that silently failed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLineEdit, QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_all",
        "reg_get",
        "reg_extended",
        "register_list",
        "bp_list",
        "thread_list",
        "module_list",
        "memmap",
        "watch_list",
        "wp_list",
        "stack_trace",
        "status",
    },
)


def _residual_response(command: str) -> dict[str, Any]:
    """Build a canned response for a residual post-refresh RPC.

    ``_refresh_state()`` (triggered after both handlers succeed) polls a
    fixed set of auxiliary RPCs unrelated to the behavior a given test is
    gating; this helper answers all of them uniformly so responders only
    need to special-case the command under test.

    Args:
        command: The RPC command name.

    Returns:
        dict[str, Any]: A successful envelope with an empty/paused payload.
    """
    if command == "status":
        return ok({"paused": True, "debugging": True})
    return ok({})


@pytest.fixture
def wired_panel(qapp: QApplication) -> tuple[X64DbgPanel, X64DbgBridge]:
    """Build a panel with a real bridge attached (no live plugin pipe).

    Sets ``_x64dbg_path``/``_state.connected`` directly so
    ``plugin_status["ready"]`` is true once :meth:`install_fake_pipe` marks
    the plugin deployed and the pipe connected; without this,
    ``_update_controls_state`` leaves every toolbar debug button disabled
    and a ``.click()`` in these tests would be a silent no-op.

    Args:
        qapp: Session QApplication fixture.

    Returns:
        tuple[X64DbgPanel, X64DbgBridge]: The panel and its attached bridge.
    """
    del qapp
    panel = X64DbgPanel()
    bridge = X64DbgBridge()
    setattr(bridge, "_x64dbg_path", Path("C:/tmp/x64dbg.exe"))
    setattr(getattr(bridge, "_state"), "connected", True)
    panel.set_bridge(bridge)
    return panel, bridge


class TestCreateThreadButtonDrivesCreateThreadRpc:
    """Clicking Create must drive ``bridge.create_thread(entry)`` and verify the new tid."""

    @staticmethod
    def test_create_thread_click_issues_createthread_then_verifies_new_tid(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Create must send ``createthread 0x402000, 0x0``, read ``$result``, and verify it.

        Falsifiable: if ``_on_create_thread`` read a different address
        widget, or ``X64DbgBridge.create_thread`` (``bridges/x64dbg.py``)
        queued a different console command, skipped the ``$result``
        readback, or never polled ``thread_detail`` to confirm the new
        thread actually appeared, the recorded command sequence would not
        contain ``createthread 0x402000, 0x0`` followed by a ``reg_get``
        call for ``$result`` and a ``thread_detail`` poll, and the console
        would never report the real returned tid.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        new_tid = 5678

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "createthread 0x402000, 0x0"
                return ok("")
            if command == "reg_get" and params == {"name": "$result"}:
                return ok(str(new_tid))
            if command == "thread_detail":
                return ok([{"threadId": new_tid, "suspended": False, "name": ""}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        addr_input = priv(panel, "_create_thread_addr_input", QLineEdit)
        create_btn = priv(panel, "_create_thread_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            addr_input.setText("0x402000")
            create_btn.click()
            pump_until(qapp, lambda: f"tid={new_tid}" in console_output.toPlainText())

            command_sequence = [c for c, _p in fake.sent if c in {"exec", "reg_get", "thread_detail"}]
            assert command_sequence.index("exec") < command_sequence.index("reg_get") < command_sequence.index("thread_detail")

            exec_cmds = [p["command"] for c, p in fake.sent if c == "exec" and p]
            assert "createthread 0x402000, 0x0" in exec_cmds
            assert f"tid={new_tid}" in console_output.toPlainText()
            assert create_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestKillThreadButtonDrivesKillThreadRpc:
    """Clicking Kill must drive ``bridge.kill_thread(tid)`` and verify the tid is gone."""

    @staticmethod
    def _seed_thread_row(panel: X64DbgPanel, tid: int) -> QTableWidget:
        """Insert a single row for ``tid`` into the panel's thread table and select it.

        ``get_threads`` enumerates real OS threads via the Windows Toolhelp
        API and cannot run against an unattached fixture bridge, so the
        thread table is seeded directly rather than through a live refresh.

        Args:
            panel: The panel whose thread table should be seeded.
            tid: Thread id to place in the first column of the new row.

        Returns:
            QTableWidget: The panel's thread table, with the new row selected.
        """
        thread_table = priv(panel, "_thread_table", QTableWidget)
        row = thread_table.rowCount()
        thread_table.insertRow(row)
        thread_table.setItem(row, 0, QTableWidgetItem(str(tid)))
        thread_table.setItem(row, 1, QTableWidgetItem("0"))
        thread_table.setItem(row, 2, QTableWidgetItem("Running"))
        thread_table.setCurrentCell(row, 0)
        return thread_table

    @staticmethod
    def test_kill_thread_click_issues_killthread_and_verifies_tid_gone(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Kill must send ``killthread 1234, 0`` and verify ``thread_detail`` no longer lists it.

        Falsifiable: if ``_on_kill_thread`` read a different table column,
        or ``X64DbgBridge.kill_thread`` (``bridges/x64dbg.py``) queued a
        different console command or never polled ``thread_detail`` for
        absence, the recorded command sequence would not match, and the
        console would never report the thread as killed.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        tid = 1234

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "killthread 1234, 0"
                return ok("")
            if command == "thread_detail":
                return ok([])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        TestKillThreadButtonDrivesKillThreadRpc._seed_thread_row(panel, tid)
        kill_btn = priv(panel, "_kill_thread_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            kill_btn.click()
            pump_until(qapp, lambda: f"Thread {tid} killed" in console_output.toPlainText())

            exec_cmds = [p["command"] for c, p in fake.sent if c == "exec" and p]
            assert "killthread 1234, 0" in exec_cmds
            assert any(c == "thread_detail" for c, _p in fake.sent)
            assert f"Thread {tid} killed" in console_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_kill_thread_that_did_not_take_reports_failure_not_fabricated_success(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A ``thread_detail`` that still lists the tid after ``killthread`` must surface as an error.

        Falsifiable: a naive implementation that returns ``{"success":
        True, ..., "verified": True}`` without checking ``thread_detail``
        would report success here even though the debugger's own thread
        listing proves the kill never took effect; this test only passes
        when ``kill_thread`` actually raises ``ToolError`` on the mismatch
        and the GUI surfaces it via ``_on_generic_error``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        tid = 1234

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "killthread 1234, 0"
                return ok("")
            if command == "thread_detail":
                return ok([{"threadId": tid, "suspended": False, "name": ""}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        TestKillThreadButtonDrivesKillThreadRpc._seed_thread_row(panel, tid)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            kill_btn = priv(panel, "_kill_thread_btn", QPushButton)
            kill_btn.click()
            pump_until(qapp, lambda: "Kill Thread failed" in console_output.toPlainText(), timeout_s=10.0)

            assert "Kill Thread failed" in console_output.toPlainText()
            assert f"Thread {tid} killed" not in console_output.toPlainText()
        finally:
            panel.deleteLater()
