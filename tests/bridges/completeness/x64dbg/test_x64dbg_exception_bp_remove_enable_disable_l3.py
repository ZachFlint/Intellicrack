# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Console tab's exception-breakpoint Remove/Enable/Disable controls.

``remove_exception_config``/``enable_exception_config``/``disable_exception_config``
are bridge methods (registered as ``x64dbg.remove_exception_config``/
``x64dbg.enable_exception_config``/``x64dbg.disable_exception_config``) with
matching "Remove"/"Enable"/"Disable" controls next to the exception row on
the Console tab in ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip for each, including the case where the exception
code field is left empty - the documented way to target all exception
breakpoints, which must omit the command argument entirely rather than
sending an empty-string or literal ``"None"`` argument.
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
    from collections.abc import Callable

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


def _assert_single_exec_command(expected: str) -> Callable[[str, dict[str, Any] | None], dict[str, Any]]:
    """Build a responder asserting the recorded ``exec`` command equals ``expected``.

    Args:
        expected: The exact command string the bridge must send.

    Returns:
        Callable[[str, dict[str, Any] | None], dict[str, Any]]: A
        responder callable usable with :func:`install_fake_pipe`.
    """

    def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            assert params is not None
            assert params.get("command") == expected
            return ok("")
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    return responder


class TestRemoveExceptionConfigButtonOmitsArgumentWhenCodeIsEmpty:
    """Clicking Remove must send a coded or bare command, never an empty-string argument."""

    @staticmethod
    def test_with_code_sends_exact_hex_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A filled-in exception code must send the exact ``DeleteExceptionBPX <hex>`` command.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("DeleteExceptionBPX 0xc0000005"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        remove_btn = priv(panel, "_exc_remove_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("0xC0000005")
            remove_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) removed" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "DeleteExceptionBPX 0xc0000005" in exec_cmds
            assert "Exception breakpoint(s) removed (0xc0000005)" in console_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_empty_code_field_sends_bare_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty exception-code field must send the argument-less "remove all" command.

        Falsifiable: an implementation that always appends ``""`` or the
        literal text ``"None"`` would send ``DeleteExceptionBPX`` with a
        trailing argument here instead of the bare, argument-less
        command the docs require for "all exception breakpoints".

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("DeleteExceptionBPX"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        remove_btn = priv(panel, "_exc_remove_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("")
            remove_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) removed" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "DeleteExceptionBPX" in exec_cmds
            assert "Exception breakpoint(s) removed (all)" in console_output.toPlainText()
        finally:
            panel.deleteLater()


class TestEnableExceptionConfigButtonOmitsArgumentWhenCodeIsEmpty:
    """Clicking Enable must send a coded or bare command, never an empty-string argument."""

    @staticmethod
    def test_with_code_sends_exact_hex_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A filled-in exception code must send the exact ``EnableExceptionBPX <hex>`` command.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("EnableExceptionBPX 0xc0000005"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        enable_btn = priv(panel, "_exc_enable_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("0xC0000005")
            enable_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) enabled" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "EnableExceptionBPX 0xc0000005" in exec_cmds
            assert "Exception breakpoint(s) enabled (0xc0000005)" in console_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_empty_code_field_sends_bare_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty exception-code field must send the argument-less "enable all" command.

        Falsifiable: an implementation that always appends ``""`` or the
        literal text ``"None"`` would send ``EnableExceptionBPX`` with a
        trailing argument here instead of the bare, argument-less
        command the docs require for "all exception breakpoints".

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("EnableExceptionBPX"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        enable_btn = priv(panel, "_exc_enable_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("")
            enable_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) enabled" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "EnableExceptionBPX" in exec_cmds
            assert "Exception breakpoint(s) enabled (all)" in console_output.toPlainText()
        finally:
            panel.deleteLater()


class TestDisableExceptionConfigButtonOmitsArgumentWhenCodeIsEmpty:
    """Clicking Disable must send a coded or bare command, never an empty-string argument."""

    @staticmethod
    def test_with_code_sends_exact_hex_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A filled-in exception code must send the exact ``DisableExceptionBPX <hex>`` command.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("DisableExceptionBPX 0xc0000005"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        disable_btn = priv(panel, "_exc_disable_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("0xC0000005")
            disable_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) disabled" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "DisableExceptionBPX 0xc0000005" in exec_cmds
            assert "Exception breakpoint(s) disabled (0xc0000005)" in console_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_empty_code_field_sends_bare_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty exception-code field must send the argument-less "disable all" command.

        Falsifiable: an implementation that always appends ``""`` or the
        literal text ``"None"`` would send ``DisableExceptionBPX`` with
        a trailing argument here instead of the bare, argument-less
        command the docs require for "all exception breakpoints".

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        fake = install_fake_pipe(bridge, _assert_single_exec_command("DisableExceptionBPX"))
        code_input = priv(panel, "_exc_code_input", QLineEdit)
        disable_btn = priv(panel, "_exc_disable_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            code_input.setText("")
            disable_btn.click()
            pump_until(qapp, lambda: "Exception breakpoint(s) disabled" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "DisableExceptionBPX" in exec_cmds
            assert "Exception breakpoint(s) disabled (all)" in console_output.toPlainText()
        finally:
            panel.deleteLater()
