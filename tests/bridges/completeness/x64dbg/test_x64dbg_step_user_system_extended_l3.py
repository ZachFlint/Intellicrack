# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L3 gate tests for mode-restricted and exception-passthrough stepping.

``step_into_user_code``/``step_into_system_code`` drive x64dbg's
``StepUser``/``StepSystem`` commands, and ``step_extended`` drives the
``eStepInto``/``eStepOver``/``eStepOut``/``seStepInto``/``seStepOver``
family for exception-passthrough control. This module gates the full
click-to-RPC round trip for the toolbar controls and the bridge-level
rejection of the undocumented ``seStepOut`` combination.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
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


class TestStepUserButtonDrivesStepUserRpc:
    """Clicking "Step User" must drive ``bridge.step_into_user_code()``."""

    @staticmethod
    def test_step_user_click_issues_stepuser_exactly(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking "Step User" must send exactly ``StepUser`` and report the new IP.

        Falsifiable: if ``_on_step_into_user_code`` called a different
        bridge method, or ``X64DbgBridge.step_into_user_code`` routed the
        command through the dedicated ``step_into`` pipe RPC instead of a
        raw ``exec`` console command, the recorded ``exec`` command list
        would not contain ``StepUser`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "StepUser"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command == "reg_all":
                return ok({"rip": "0x402000"})
            if command == "disasm":
                return ok([])
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        step_user_btn = priv(panel, "_step_user_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            step_user_btn.click()
            pump_until(qapp, lambda: "Step user" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "StepUser" in exec_cmds
            assert "Step user -> 0x402000" in console_output.toPlainText()
            assert step_user_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestStepSystemButtonDrivesStepSystemRpc:
    """Clicking "Step System" must drive ``bridge.step_into_system_code()``."""

    @staticmethod
    def test_step_system_click_issues_stepsystem_exactly(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking "Step System" must send exactly ``StepSystem`` and report the new IP.

        Falsifiable: if ``_on_step_into_system_code`` called a different
        bridge method, or the bridge sent a different console command,
        the recorded ``exec`` command list would not contain
        ``StepSystem`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "StepSystem"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command == "reg_all":
                return ok({"rip": "0x7ffe1000"})
            if command == "disasm":
                return ok([])
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        step_system_btn = priv(panel, "_step_system_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            step_system_btn.click()
            pump_until(qapp, lambda: "Step system" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "StepSystem" in exec_cmds
            assert "Step system -> 0x7FFE1000" in console_output.toPlainText()
            assert step_system_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestStepExtButtonDrivesStepExtendedRpc:
    """Clicking "Step Ext" must drive ``bridge.step_extended(step_type, exception_mode, 1)``."""

    @staticmethod
    def test_step_ext_over_swallow_click_issues_sestepover_1_exactly(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting Over/Swallow Exception and clicking "Step Ext" must send exactly ``seStepOver 1``.

        Falsifiable: if the handler read the wrong combo, forwarded the
        wrong step_type/exception_mode, or ``step_extended`` built the
        command from a different lookup, the recorded ``exec`` command
        list would not contain ``seStepOver 1`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "seStepOver 1"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command == "reg_all":
                return ok({"rip": "0x403000"})
            if command == "disasm":
                return ok([])
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        step_ext_type_combo = priv(panel, "_step_ext_type_combo", QComboBox)
        step_ext_mode_combo = priv(panel, "_step_ext_mode_combo", QComboBox)
        step_ext_btn = priv(panel, "_step_ext_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            step_ext_type_combo.setCurrentText("Over")
            step_ext_mode_combo.setCurrentText("Swallow Exception")
            step_ext_btn.click()
            pump_until(qapp, lambda: "Step Ext" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "seStepOver 1" in exec_cmds
            assert "Step Ext -> 0x403000" in console_output.toPlainText()
            assert step_ext_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestStepExtendedRejectsUndocumentedSeStepOut:
    """L1: ``step_extended`` must reject ``step_type="out"`` with ``exception_mode="swallow"``."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_step_extended_out_swallow_raises_tool_error() -> None:
        """x64dbg has no ``seStepOut`` command, so this combination must raise ``ToolError``.

        Falsifiable: if the ``cmd is None`` guard in ``step_extended``
        were removed (or the lookup table fell back to a substitute
        command instead of omitting the ``("out", "swallow")`` entry),
        this call would either send a fabricated, non-existent console
        command or return normally instead of raising.
        """
        bridge = X64DbgBridge()

        with pytest.raises(ToolError, match="seStepOut"):
            await bridge.step_extended("out", "swallow", 1)
