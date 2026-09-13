# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's Enable/Disable DLL BP controls.

``enable_dll_breakpoint``/``disable_dll_breakpoint`` are bridge methods
(registered as ``x64dbg.enable_dll_breakpoint``/``x64dbg.disable_dll_breakpoint``)
with matching "Enable DLL BP"/"Disable DLL BP" controls on the BP Config
sub-tab in ``x64dbg_advanced_tab.py``. This module gates the full
click-to-RPC round trip for both a named DLL and the empty-field "all DLL
breakpoints" case - the latter must omit the argument entirely rather than
sending an empty-string or ``"None"`` argument, which would change the
command's real meaning per the x64dbg docs.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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


class TestEnableDllBreakpointButtonOmitsArgumentWhenNameIsEmpty:
    """Clicking Enable DLL BP must send a named or bare command, never an empty-string argument."""

    @staticmethod
    def test_named_dll_sends_quoted_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A filled-in DLL name must send the quoted per-DLL enable command.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab
        fake = install_fake_pipe(bridge, _assert_single_exec_command('LibrarianEnableBreakpoint "ntdll.dll"'))
        dll_input = priv(tab, "_bpcfg_dll_input", QLineEdit)
        enable_btn = priv(tab, "_bpcfg_dll_enable_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        dll_input.setText("ntdll.dll")
        enable_btn.click()
        pump_until(qapp, lambda: "DLL breakpoint(s) enabled" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert 'LibrarianEnableBreakpoint "ntdll.dll"' in exec_cmds
        assert "DLL breakpoint(s) enabled on ntdll.dll" in status_label.text()
        assert enable_btn.isEnabled()

    @staticmethod
    def test_empty_name_field_sends_bare_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty DLL name field must send the argument-less "enable all" command.

        Falsifiable: an implementation that always appends ``""`` or the
        literal text ``"None"`` would send
        ``LibrarianEnableBreakpoint ""`` or
        ``LibrarianEnableBreakpoint None`` here instead of the bare,
        argument-less command the docs require for "all DLL
        breakpoints".

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab
        fake = install_fake_pipe(bridge, _assert_single_exec_command("LibrarianEnableBreakpoint"))
        dll_input = priv(tab, "_bpcfg_dll_input", QLineEdit)
        enable_btn = priv(tab, "_bpcfg_dll_enable_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        dll_input.setText("")
        enable_btn.click()
        pump_until(qapp, lambda: "DLL breakpoint(s) enabled" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "LibrarianEnableBreakpoint" in exec_cmds
        assert "DLL breakpoint(s) enabled" in status_label.text()
        assert enable_btn.isEnabled()


class TestDisableDllBreakpointButtonOmitsArgumentWhenNameIsEmpty:
    """Clicking Disable DLL BP must send a named or bare command, never an empty-string argument."""

    @staticmethod
    def test_named_dll_sends_quoted_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A filled-in DLL name must send the quoted per-DLL disable command.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab
        fake = install_fake_pipe(bridge, _assert_single_exec_command('LibrarianDisableBreakpoint "ntdll.dll"'))
        dll_input = priv(tab, "_bpcfg_dll_input", QLineEdit)
        disable_btn = priv(tab, "_bpcfg_dll_disable_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        dll_input.setText("ntdll.dll")
        disable_btn.click()
        pump_until(qapp, lambda: "DLL breakpoint(s) disabled" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert 'LibrarianDisableBreakpoint "ntdll.dll"' in exec_cmds
        assert "DLL breakpoint(s) disabled on ntdll.dll" in status_label.text()
        assert disable_btn.isEnabled()

    @staticmethod
    def test_empty_name_field_sends_bare_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty DLL name field must send the argument-less "disable all" command.

        Falsifiable: an implementation that always appends ``""`` or the
        literal text ``"None"`` would send
        ``LibrarianDisableBreakpoint ""`` or
        ``LibrarianDisableBreakpoint None`` here instead of the bare,
        argument-less command the docs require for "all DLL
        breakpoints".

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab
        fake = install_fake_pipe(bridge, _assert_single_exec_command("LibrarianDisableBreakpoint"))
        dll_input = priv(tab, "_bpcfg_dll_input", QLineEdit)
        disable_btn = priv(tab, "_bpcfg_dll_disable_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        dll_input.setText("")
        disable_btn.click()
        pump_until(qapp, lambda: "DLL breakpoint(s) disabled" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "LibrarianDisableBreakpoint" in exec_cmds
        assert "DLL breakpoint(s) disabled" in status_label.text()
        assert disable_btn.isEnabled()
