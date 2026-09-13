# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate test for the x64dbg Breakpoints tab's memory-range breakpoint control.

``set_memory_range_breakpoint`` is a fully implemented and registered bridge
method (``x64dbg.set_memory_range_breakpoint``) with a matching "Range BP"
toolbar control in ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip: the button handler must read the address, size,
access-type, and singleshot widgets, dispatch the exact ``SetMemoryRangeBPX``
console command via ``run_bridge_coroutine_logged``, and render the bridge's
verified result in the console output.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QPlainTextEdit, QPushButton

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
        "register_list",
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

    Sets ``_x64dbg_path``/``_state.connected`` directly so
    ``plugin_status["ready"]`` is true once :meth:`install_fake_pipe` marks
    the plugin deployed and the pipe connected.

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


class TestRangeBreakpointButtonDrivesSetMemoryRangeBreakpointRpc:
    """Clicking Range BP must send ``SetMemoryRangeBPX`` with exact argument framing."""

    @staticmethod
    def test_range_bp_click_issues_setmemoryrangebpx_with_write_singleshot_framing(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Range BP must send ``SetMemoryRangeBPX 0x401000, 0x100, wss`` exactly.

        Falsifiable: if ``X64DbgBridge.set_memory_range_breakpoint``
        (``bridges/x64dbg.py``) omitted the ``ss`` suffix for a checked
        Singleshot box, or hardcoded the access letter instead of using
        the access the panel's ``_on_add_range_breakpoint`` handler read
        from ``_bp_range_access_combo``, the recorded ``exec`` command
        would not match this exact string, and the console would not
        report a verified range breakpoint.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "SetMemoryRangeBPX 0x401000, 0x100, wss"
                return ok("")
            if command == "bp_list":
                return ok([{"address": "0x401000", "type": "memory"}])
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        bp_addr_input = priv(panel, "_bp_addr_input", QLineEdit)
        bp_range_size_input = priv(panel, "_bp_range_size_input", QLineEdit)
        bp_range_access_combo = priv(panel, "_bp_range_access_combo", QComboBox)
        bp_range_singleshot_check = priv(panel, "_bp_range_singleshot_check", QCheckBox)
        add_range_bp_btn = priv(panel, "_add_range_bp_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            bp_addr_input.setText("0x401000")
            bp_range_size_input.setText("0x100")
            bp_range_access_combo.setCurrentIndex(bp_range_access_combo.findData("write"))
            bp_range_singleshot_check.setChecked(True)
            add_range_bp_btn.click()
            pump_until(qapp, lambda: "Memory range breakpoint set" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "SetMemoryRangeBPX 0x401000, 0x100, wss" in exec_cmds
            assert "Memory range breakpoint set at 0x401000, size 0x100" in console_output.toPlainText()
            assert "(unverified)" not in console_output.toPlainText()
            assert add_range_bp_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_range_bp_with_non_numeric_size_does_not_dispatch(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An unparseable size must be rejected locally without any RPC dispatch.

        Falsifiable: if the ``int(size_text, ...)`` guard in
        ``_on_add_range_breakpoint`` were removed, this would either
        raise an uncaught ``ValueError`` or dispatch a malformed
        ``SetMemoryRangeBPX`` command instead of leaving the fake pipe
        untouched.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        bp_addr_input = priv(panel, "_bp_addr_input", QLineEdit)
        bp_range_size_input = priv(panel, "_bp_range_size_input", QLineEdit)
        add_range_bp_btn = priv(panel, "_add_range_bp_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            bp_addr_input.setText("0x401000")
            bp_range_size_input.setText("not-a-size")
            add_range_bp_btn.click()
            qapp.processEvents()

            assert fake.sent == []
            assert "Invalid size" in console_output.toPlainText()
        finally:
            panel.deleteLater()
