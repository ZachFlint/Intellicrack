# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Advanced tab's Reset Hit Count control.

``reset_breakpoint_hit_count`` is a bridge method (registered as
``x64dbg.reset_breakpoint_hit_count``) with a matching "Reset Hit Count"
control on the BP Config sub-tab in ``x64dbg_advanced_tab.py``. Unlike most of
this sub-tab's property setters, a hit-count reset can be verified against
the existing ``hitCount``/``hit_count`` field the plugin already reports
through ``bp_list`` - this module gates both the click-to-RPC round trip and
that readback verification, including the case where the debugger accepts
the reset command but the reported hit count does not actually change.
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


class TestResetHitCountButtonSendsCommandAndVerifiesReadback:
    """Clicking Reset Hit Count must send the reset command and verify it took."""

    @staticmethod
    def test_verified_reset_shows_success(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A reset that ``bp_list`` confirms must report success with ``verified=True``.

        Falsifiable: if ``X64DbgBridge.reset_breakpoint_hit_count``
        (``bridges/x64dbg.py``) sent the wrong command text, or the
        Advanced tab's ``_on_reset_breakpoint_hit_count`` read a
        different address widget, the recorded ``exec`` command would
        not match ``ResetBreakpointHitCount 0x401000, 0`` exactly and
        the status label would never show the success text.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "ResetBreakpointHitCount 0x401000, 0"
                return ok("")
            if command == "bp_list":
                return ok([{"address": "0x401000", "type": "software", "hitCount": 0}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        reset_btn = priv(tab, "_bpcfg_reset_hits_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        reset_btn.click()
        pump_until(qapp, lambda: bool(status_label.text()))

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        assert "ResetBreakpointHitCount 0x401000, 0" in exec_cmds
        assert status_label.text() == "[+] Hit count reset at 0x401000"
        assert reset_btn.isEnabled()

    @staticmethod
    def test_reset_that_did_not_take_reports_failure(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A stale ``hitCount`` reported by ``bp_list`` after the reset must surface as an error.

        Falsifiable: a naive implementation that returns
        ``{"success": True, ..., "verified": True}`` without checking
        ``bp_list``'s readback would report success here even though
        the debugger's own ``hitCount`` field (7) proves the reset
        never took effect; this test only passes when
        ``reset_breakpoint_hit_count`` actually raises ``ToolError`` on
        the mismatch and the GUI surfaces it via ``_on_bpcfg_error``.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def mutated_responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "ResetBreakpointHitCount 0x401000, 0"
                return ok("")
            if command == "bp_list":
                return ok([{"address": "0x401000", "type": "software", "hitCount": 7}])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, mutated_responder)
        addr_input = priv(tab, "_bpcfg_addr_input", QLineEdit)
        reset_btn = priv(tab, "_bpcfg_reset_hits_btn", QPushButton)
        status_label = priv(tab, "_bpcfg_status_label", QLabel)

        addr_input.setText("0x401000")
        reset_btn.click()
        pump_until(qapp, lambda: status_label.text().startswith("[-]"))

        assert "[-] reset_breakpoint_hit_count failed:" in status_label.text()
        assert reset_btn.isEnabled()
