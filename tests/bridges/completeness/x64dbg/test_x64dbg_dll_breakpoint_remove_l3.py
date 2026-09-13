# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's Remove DLL BP control.

``remove_dll_breakpoint`` is a bridge method (registered as
``x64dbg.remove_dll_breakpoint``) with a matching "Remove DLL BP" control on
the BP Config sub-tab in ``x64dbg_advanced_tab.py``. This module gates the
full click-to-RPC round trip, including the exact ``LibrarianRemoveBreakpoint``
quoting the x64dbg console command requires.
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


class TestRemoveDllBreakpointButtonSendsExactLibrarianCommand:
    """Clicking Remove DLL BP must send the exact quoted Librarian command."""

    @staticmethod
    def test_remove_dll_breakpoint_sends_quoted_command(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Remove DLL BP with a DLL name must send the exact quoted command.

        Falsifiable: if ``X64DbgBridge.remove_dll_breakpoint``
        (``bridges/x64dbg.py``) omitted the quotes around the DLL name,
        or the Advanced tab's ``_on_remove_dll_breakpoint`` read a
        different input widget, the recorded ``exec`` command would
        not match ``LibrarianRemoveBreakpoint "ws2_32.dll"`` exactly.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == 'LibrarianRemoveBreakpoint "ws2_32.dll"'
                return ok("")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        dll_input = priv(tab, "_bpcfg_dll_input", QLineEdit)
        remove_btn = priv(tab, "_bpcfg_dll_remove_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        dll_input.setText("ws2_32.dll")
        remove_btn.click()
        pump_until(qapp, lambda: "DLL breakpoint removed" in status_label.text())

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert 'LibrarianRemoveBreakpoint "ws2_32.dll"' in exec_cmds
        assert "DLL breakpoint removed on ws2_32.dll" in status_label.text()
        assert remove_btn.isEnabled()
