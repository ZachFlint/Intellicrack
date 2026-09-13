# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg toolbar's "User Code" and "Run To Party" controls.

``run_to_user_code``/``run_to_party`` drive x64dbg's ``RunToUserCode``/
``RunToParty`` commands, which place temporary memory breakpoints across
matching pages rather than single-stepping to a known address - unlike
``run_to``, which polls for a specific target IP. This module gates the
full click-to-RPC round trip for both: the button handler must dispatch
the exact real bridge coroutine, the bridge must send the exact real
console command, and the panel must render the bridge's real result.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLineEdit, QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_get",
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


class TestRunToUserCodeButtonDrivesRunToUserCodeRpc:
    """Clicking "User Code" must drive ``bridge.run_to_user_code()``."""

    @staticmethod
    def test_user_code_click_issues_runtousercode_and_reports_reached_ip(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking "User Code" must send exactly ``RunToUserCode`` and report the reached IP.

        Falsifiable: if ``_on_run_to_user_code`` called a different bridge
        method, or ``X64DbgBridge.run_to_user_code`` sent a different
        console command, the recorded ``exec`` command list would not
        contain ``RunToUserCode`` exactly and the console would not report
        the IP read back from the scripted ``reg_all`` response.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "RunToUserCode"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command == "reg_all":
                return ok({"rip": "0x401234"})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        run_to_user_btn = priv(panel, "_run_to_user_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            run_to_user_btn.click()
            pump_until(qapp, lambda: "Ran to user code" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "RunToUserCode" in exec_cmds
            assert "Ran to user code, IP=0x401234" in console_output.toPlainText()
            assert run_to_user_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestRunToPartyButtonDrivesRunToPartyRpc:
    """Clicking "Run To Party" must drive ``bridge.run_to_party(party)``."""

    @staticmethod
    def test_run_to_party_click_issues_runtoparty_with_entered_party_and_reports_reached_ip(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking "Run To Party" with party=1 must send exactly ``RunToParty 1``.

        Falsifiable: if the handler read a different widget, dropped the
        entered party number, or the bridge built the command with a
        different party value, the recorded ``exec`` command list would
        not contain ``RunToParty 1`` exactly. This also pins the argument
        position: x64dbg's ``RunToParty`` takes a bare party *number*, not
        an expression, so a regression that sent ``RunToParty 0``
        regardless of the input field would fail this exact-string
        assertion.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "RunToParty 1"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command == "reg_all":
                return ok({"rip": "0x7ffe0000"})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        run_to_party_input = priv(panel, "_run_to_party_input", QLineEdit)
        run_to_party_btn = priv(panel, "_run_to_party_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            run_to_party_input.setText("1")
            run_to_party_btn.click()
            pump_until(qapp, lambda: "Ran to party 1" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "RunToParty 1" in exec_cmds
            assert "RunToParty 0" not in exec_cmds
            assert "Ran to party 1, IP=0x7ffe0000" in console_output.toPlainText()
            assert run_to_party_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_run_to_party_with_non_numeric_input_does_not_dispatch(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Non-numeric party input must be rejected locally without any RPC dispatch.

        Falsifiable: if the ``int(party_text)`` guard in
        ``_on_run_to_party`` were removed, this would either raise an
        uncaught ``ValueError`` or dispatch a malformed ``RunToParty``
        command instead of leaving the fake pipe untouched.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        run_to_party_input = priv(panel, "_run_to_party_input", QLineEdit)
        run_to_party_btn = priv(panel, "_run_to_party_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            run_to_party_input.setText("not-a-party")
            run_to_party_btn.click()
            qapp.processEvents()

            assert fake.sent == []
            assert "Invalid party" in console_output.toPlainText()
        finally:
            panel.deleteLater()
