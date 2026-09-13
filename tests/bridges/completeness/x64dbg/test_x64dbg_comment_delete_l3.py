# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Annotations tab's comment Delete control.

``delete_comment`` is a new bridge method (registered as
``x64dbg.delete_comment``) with a matching "Delete" button next to the
Comments table in ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip: the button handler must read the selected row's
address, dispatch ``commentdel`` followed by a ``cmt_list`` readback via
the real bridge coroutine, and drop the row once the plugin confirms the
comment is gone. It also gates the failure path where the plugin still
reports the comment after ``commentdel``, which must surface as a real
error rather than a fabricated success.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QPlainTextEdit, QPushButton, QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_COMMENT_ADDR = 0x401000
_COMMENT_TEXT = "gate test comment"

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_all",
        "reg_get",
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


class TestDeleteCommentButtonDrivesDeleteCommentRpc:
    """Clicking Delete must drive ``bridge.delete_comment(address)`` and verify absence."""

    @staticmethod
    def test_delete_comment_click_issues_commentdel_and_removes_the_row(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Delete must send ``commentdel 0x401000`` and drop the row once verified gone.

        Falsifiable: if ``_on_delete_comment`` read a different table
        column, or ``X64DbgBridge.delete_comment`` (``bridges/x64dbg.py``)
        queued a different console command or never read back
        ``cmt_list`` to confirm the comment was actually removed, the
        recorded ``exec`` command would not match ``commentdel
        0x401000`` exactly and the row would not disappear from the
        table.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        state = {"deleted": False}

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f"commentdel {hex(_COMMENT_ADDR)}"
                state["deleted"] = True
                return ok("")
            if command == "cmt_list":
                if state["deleted"]:
                    return ok([])
                return ok([{"address": hex(_COMMENT_ADDR), "text": _COMMENT_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        cmt_refresh_btn = priv(panel, "_cmt_refresh_btn", QPushButton)
        cmt_delete_btn = priv(panel, "_cmt_delete_btn", QPushButton)
        cmt_table = priv(panel, "_cmt_table", QTableWidget)

        try:
            cmt_refresh_btn.click()
            pump_until(qapp, lambda: cmt_table.rowCount() >= 1)
            cmt_table.setCurrentCell(0, 0)

            cmt_delete_btn.click()
            pump_until(qapp, lambda: cmt_table.rowCount() == 0)

            exec_cmds = [p["command"] for c, p in fake.sent if c == "exec" and p]
            assert exec_cmds == [f"commentdel {hex(_COMMENT_ADDR)}"]
            assert cmt_table.rowCount() == 0
            assert cmt_delete_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_delete_comment_that_did_not_take_reports_failure_not_fabricated_success(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A ``cmt_list`` that still reports the comment after ``commentdel`` must surface as an error.

        Falsifiable: a naive implementation that returns ``{"success":
        True, ..., "verified": False}`` without checking ``cmt_list``'s
        readback would report success here even though the plugin's own
        comment listing proves the delete never took effect; this test
        only passes when ``delete_comment`` actually raises ``ToolError``
        on the mismatch and the GUI surfaces it via ``_on_generic_error``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f"commentdel {hex(_COMMENT_ADDR)}"
                return ok("")
            if command == "cmt_list":
                return ok([{"address": hex(_COMMENT_ADDR), "text": _COMMENT_TEXT}])
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        cmt_refresh_btn = priv(panel, "_cmt_refresh_btn", QPushButton)
        cmt_delete_btn = priv(panel, "_cmt_delete_btn", QPushButton)
        cmt_table = priv(panel, "_cmt_table", QTableWidget)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            cmt_refresh_btn.click()
            pump_until(qapp, lambda: cmt_table.rowCount() >= 1)
            cmt_table.setCurrentCell(0, 0)

            cmt_delete_btn.click()
            pump_until(qapp, lambda: "Delete Comment failed" in console_output.toPlainText())

            assert "Delete Comment failed" in console_output.toPlainText()
            assert cmt_table.rowCount() == 1
            assert cmt_delete_btn.isEnabled()
        finally:
            panel.deleteLater()
