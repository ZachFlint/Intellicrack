# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate test for the x64dbg toolbar's "Undo" control.

``instr_undo`` drives x64dbg's ``InstrUndo`` command, which reverses the
most recently stepped instruction synchronously while the debugger stays
paused - unlike the run/step/trace family, it never waits on a new
"paused" event. This module gates the full click-to-RPC round trip: the
button handler must dispatch ``bridge.instr_undo()``, the bridge must
read the instruction pointer before and after sending exactly
``InstrUndo``, and the panel must render both values.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
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
    },
)


@pytest.fixture
def wired_panel(qapp: QApplication) -> tuple[X64DbgPanel, X64DbgBridge]:
    """Build a panel with a real bridge attached (no live plugin pipe).

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


class TestUndoButtonDrivesInstrUndoRpc:
    """Clicking "Undo" must drive ``bridge.instr_undo()``."""

    @staticmethod
    def test_undo_click_reads_ip_before_and_after_instrundo_in_order(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking "Undo" must read ``rip``, send exactly ``InstrUndo``, then read ``rip`` again.

        The fake pipe's ``reg_all`` responder answers ``0x401010`` on the
        first call and ``0x401000`` on the second, modelling the real
        before/after instruction-pointer change an ``InstrUndo`` causes.

        Falsifiable: if ``instr_undo`` read the registers in the wrong
        order, sent a different console command, or reported the wrong
        old/new IP pairing, the recorded command sequence would not show
        ``reg_all`` before ``exec``/``InstrUndo`` and another ``reg_all``
        after it, and the console would not report
        "Undo 0x401010 -> 0x401000".

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        reg_all_responses: Iterator[str] = iter(["0x401010", "0x401000"])

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "InstrUndo"
                return ok("")
            if command == "reg_all":
                rip = next(reg_all_responses, "0x401000")
                return ok({"rip": rip})
            if command == "disasm":
                return ok([])
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        undo_btn = priv(panel, "_undo_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            undo_btn.click()
            pump_until(qapp, lambda: "Undo 0x401010 -> 0x401000" in console_output.toPlainText())

            commands = [c for c, _ in fake.sent]
            exec_idx = commands.index("exec")
            first_reg_all = commands.index("reg_all")
            second_reg_all = commands.index("reg_all", exec_idx + 1)
            assert first_reg_all < exec_idx < second_reg_all, f"expected reg_all, exec, reg_all in order; got {commands!r}"
            exec_params = fake.sent[exec_idx][1]
            assert exec_params == {"command": "InstrUndo"}
            assert "Undo 0x401010 -> 0x401000" in console_output.toPlainText()
            assert undo_btn.isEnabled()
        finally:
            panel.deleteLater()
