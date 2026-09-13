# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's breakpoint command-condition control.

``set_breakpoint_command_condition`` is a fully implemented and registered
bridge method (``x64dbg.set_breakpoint_command_condition``) with a matching
"Set Command Condition" control on the BP Config sub-tab in
``x64dbg_advanced_tab.py``. This module gates the full click-to-RPC round
trip for both the default software-breakpoint dispatch and the
type-branched dispatch for a breakpoint this bridge has already recorded as
memory - the exact class of defect the Stream-A audit flags for sibling
breakpoint-property setters that hardcode the software-only command family
instead of branching via ``_bp_command_for_type``.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")


@pytest.fixture
def wired_tab(qapp: QApplication) -> Iterator[tuple[X64DbgAdvancedTab, X64DbgBridge]]:
    """Build a real Advanced tab wired to a real (pipe-less) ``X64DbgBridge``.

    Args:
        qapp: Session QApplication fixture.

    Yields:
        tuple[X64DbgAdvancedTab, X64DbgBridge]: The tab and its bridge.
    """
    del qapp
    tab = X64DbgAdvancedTab()
    bridge = X64DbgBridge()
    tab.set_bridge(bridge)
    yield tab, bridge
    tab.deleteLater()


class TestSetBreakpointCommandConditionButtonDrivesTypeBranchedRpc:
    """Clicking Set Command Condition must branch its command family by breakpoint type."""

    @staticmethod
    def test_default_software_breakpoint_sends_software_command_condition_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An address this bridge never recorded must default to the software command.

        Falsifiable: if ``X64DbgBridge.set_breakpoint_command_condition``
        (``bridges/x64dbg.py``) did not resolve the breakpoint type via
        ``_resolve_breakpoint_type``, or the Advanced tab's
        ``_on_set_breakpoint_command_condition`` read a different
        address/condition widget, the recorded ``exec`` command would
        not match ``SetBreakpointCommandCondition 0x401000, "eax==1"``
        exactly.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == 'SetBreakpointCommandCondition 0x401000, "eax==1"'
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        cmdcond_input = priv(tab, "_bpcfg_cmdcond_input", QLineEdit)
        cmdcond_btn = priv(tab, "_bpcfg_cmdcond_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        cmdcond_input.setText("eax==1")
        cmdcond_btn.click()
        pump_until(qapp, lambda: "Command condition set" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert 'SetBreakpointCommandCondition 0x401000, "eax==1"' in exec_cmds
        assert "Command condition set at 0x401000" in status_label.text()
        assert cmdcond_btn.isEnabled()

    @staticmethod
    def test_memory_breakpoint_sends_memory_command_condition_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An address this bridge recorded as memory must branch to the memory command.

        Falsifiable: this is the case a hardcoded software-only command
        cannot pass. If ``set_breakpoint_command_condition`` sent
        ``SetBreakpointCommandCondition`` regardless of ``bp_type``,
        the recorded command would not match
        ``SetMemoryBreakpointCommandCondition 0x401000, "eax==1"``.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def seed_responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return ok("")
            if command == "bp_list":
                return ok([{"address": "0x401000", "type": "memory"}])
            msg = f"unexpected seed command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, seed_responder)
        run_bridge_coroutine(bridge.set_breakpoint(0x401000, bp_type="memory"))

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == 'SetMemoryBreakpointCommandCondition 0x401000, "eax==1"'
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        cmdcond_input = priv(tab, "_bpcfg_cmdcond_input", QLineEdit)
        cmdcond_btn = priv(tab, "_bpcfg_cmdcond_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        cmdcond_input.setText("eax==1")
        cmdcond_btn.click()
        pump_until(qapp, lambda: "Command condition set" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert 'SetMemoryBreakpointCommandCondition 0x401000, "eax==1"' in exec_cmds
        assert "Command condition set at 0x401000" in status_label.text()
        assert cmdcond_btn.isEnabled()
