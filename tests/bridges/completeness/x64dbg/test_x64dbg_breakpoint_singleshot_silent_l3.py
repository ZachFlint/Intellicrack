# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's breakpoint Singleshot/Silent flag controls.

``set_breakpoint_singleshot``/``set_breakpoint_silent`` are fully implemented
and registered bridge methods (``x64dbg.set_breakpoint_singleshot``/
``x64dbg.set_breakpoint_silent``) with matching "Apply Singleshot"/"Apply
Silent" controls on the BP Config sub-tab in ``x64dbg_advanced_tab.py``. This
module gates the full click-to-RPC round trip for both flags: the exact
bare-integer (``0``/``1``, never a quoted string or ``true``/``false``)
argument encoding, and the type-branched command dispatch for a breakpoint
this bridge has already recorded as hardware - the exact class of defect the
Stream-A audit flags for sibling breakpoint-property setters that hardcode
the software-only command family instead of branching via
``_bp_command_for_type``.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QCheckBox, QLabel, QLineEdit, QPushButton

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


class TestSingleshotAndSilentButtonsDriveTypeBranchedBareIntegerRpc:
    """Clicking Apply Singleshot/Silent must send the exact, type-branched, bare-integer command."""

    @staticmethod
    def test_software_breakpoint_checked_singleshot_sends_software_command_with_one(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A checked Singleshot box on a default breakpoint must send ``SetBreakpointSingleshoot 0x401000, 1``.

        Falsifiable: if ``X64DbgBridge.set_breakpoint_singleshot``
        (``bridges/x64dbg.py``) sent the flag as a quoted string or as
        ``true``/``false`` instead of a bare ``0``/``1``, or the
        Advanced tab's ``_on_set_breakpoint_singleshot`` ignored the
        checkbox state, this exact command would not be recorded.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "SetBreakpointSingleshoot 0x401000, 1"
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        singleshot_check = priv(tab, "_bpcfg_singleshot_check", QCheckBox)
        singleshot_btn = priv(tab, "_bpcfg_singleshot_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        singleshot_check.setChecked(True)
        singleshot_btn.click()
        pump_until(qapp, lambda: "Singleshot set" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "SetBreakpointSingleshoot 0x401000, 1" in exec_cmds
        assert "0x401000" in status_label.text()
        assert singleshot_btn.isEnabled()

    @staticmethod
    def test_hardware_breakpoint_checked_singleshot_sends_hardware_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A checked Singleshot box on a recorded hardware breakpoint must branch to the hardware command.

        Falsifiable: this is the case a hardcoded software-only command
        cannot pass. If ``set_breakpoint_singleshot`` sent
        ``SetBreakpointSingleshoot`` regardless of ``bp_type``, the
        recorded command would not match
        ``SetHardwareBreakpointSingleshoot 0x401000, 1``.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def seed_responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return ok("")
            if command == "bp_list":
                return ok([{"address": "0x401000", "type": "hardware"}])
            msg = f"unexpected seed command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, seed_responder)
        run_bridge_coroutine(bridge.set_breakpoint(0x401000, bp_type="hardware"))

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "SetHardwareBreakpointSingleshoot 0x401000, 1"
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        singleshot_check = priv(tab, "_bpcfg_singleshot_check", QCheckBox)
        singleshot_btn = priv(tab, "_bpcfg_singleshot_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        singleshot_check.setChecked(True)
        singleshot_btn.click()
        pump_until(qapp, lambda: "Singleshot set" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "SetHardwareBreakpointSingleshoot 0x401000, 1" in exec_cmds
        assert singleshot_btn.isEnabled()

    @staticmethod
    def test_software_breakpoint_unchecked_silent_sends_software_command_with_zero(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An unchecked Silent box on a default breakpoint must send ``SetBreakpointSilent 0x401000, 0``.

        Falsifiable: if the handler always forced ``enabled=True``
        regardless of the checkbox, or the bridge always sent ``1``
        regardless of ``enabled``, the recorded command would carry
        ``1`` instead of the expected ``0``.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "SetBreakpointSilent 0x401000, 0"
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        silent_check = priv(tab, "_bpcfg_silent_check", QCheckBox)
        silent_btn = priv(tab, "_bpcfg_silent_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        silent_check.setChecked(False)
        silent_btn.click()
        pump_until(qapp, lambda: "Silent set" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "SetBreakpointSilent 0x401000, 0" in exec_cmds
        assert "0x401000" in status_label.text()
        assert silent_btn.isEnabled()
