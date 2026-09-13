# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate test for the x64dbg Breakpoints tab's default breakpoint opcode-type control.

``set_default_breakpoint_type`` is a fully implemented and registered bridge
method (``x64dbg.set_default_breakpoint_type``) with a matching "Set Default
Type" toolbar control in ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip for each of the three opcode styles x64dbg's
``SetBPXOptions``/``bptype`` command documents, pinning the exact outbound
command string. There is no readback/getter for this global default, so
unlike most breakpoint gates in this package, this one verifies only the
outbound command framing.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")


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


class TestSetDefaultBreakpointTypeButtonDrivesSetBpxOptionsRpc:
    """Clicking Set Default Type must send ``SetBPXOptions <opcode>`` exactly."""

    @staticmethod
    @pytest.mark.parametrize(
        ("label", "opcode"),
        [
            ("Short (CC)", "short"),
            ("Long (CD03)", "long"),
            ("UD2 (0F0B)", "ud2"),
        ],
    )
    def test_set_default_type_click_issues_exact_setbpxoptions_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
        label: str,
        opcode: str,
    ) -> None:
        """Selecting each opcode style and clicking must send ``SetBPXOptions <opcode>`` exactly.

        Falsifiable: if ``_on_set_default_breakpoint_type``
        (``ui/panels/x64dbg_panel.py``) ignored the combo selection and
        hardcoded one opcode value, the ``long``/``ud2`` sub-cases
        would record ``SetBPXOptions short`` instead of the expected
        command, and the console would not report the selected opcode.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
            label: Combo box display text to select.
            opcode: Expected opcode value forwarded to the bridge.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f"SetBPXOptions {opcode}"
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        bp_default_type_combo = priv(panel, "_bp_default_type_combo", QComboBox)
        set_default_bp_type_btn = priv(panel, "_set_default_bp_type_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            bp_default_type_combo.setCurrentText(label)
            set_default_bp_type_btn.click()
            pump_until(qapp, lambda: "Default breakpoint type set" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert f"SetBPXOptions {opcode}" in exec_cmds
            assert opcode in console_output.toPlainText()
            assert set_default_bp_type_btn.isEnabled()
        finally:
            panel.deleteLater()
