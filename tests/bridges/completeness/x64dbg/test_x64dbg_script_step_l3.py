# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for single-stepping the x64dbg script engine (``DbgScriptStep``).

``script_step`` is a new bridge method (registered as
``x64dbg.script_step``) backed by a dedicated ``script_step`` plugin RPC
that calls the bridge SDK's ``DbgScriptStep()`` directly. x64dbg registers
no ``scriptstep`` console command (only ``scriptload``/``scriptcmd``/
``scriptrun``/``scriptexec``/``scriptdll``), so the generic ``exec`` RPC
cannot reach it - the only way to single-step a loaded script is the
dedicated pipe command this module gates. A matching "Step" button sits
in the Script sub-tab of ``x64dbg_advanced_tab.py``.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QLabel, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_SCRIPT_ISERROR_EXPR = "script.iserror()"


class TestScriptStepSendsDedicatedPipeCommand:
    """``script_step`` must use the dedicated ``script_step`` RPC, never the ``scriptstep`` console command."""

    @staticmethod
    def test_step_sends_script_step_then_queries_script_error_in_order() -> None:
        """Stepping must send ``script_step`` (no params) then the ``script.iserror()`` readback, in order.

        Falsifiable: if ``script_step`` sent ``exec`` with
        ``"scriptstep"`` instead of the dedicated ``script_step`` RPC
        (the non-existent console command this order explicitly
        forbids), ``fake.sent`` would never contain a ``script_step``
        entry and this assertion would fail.
        """
        bridge = X64DbgBridge()

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "script_step":
                assert params is None
                return ok("true")
            if command == "eval":
                assert params == {"expression": _SCRIPT_ISERROR_EXPR}
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        result = run_bridge_coroutine(bridge.script_step())

        assert result is not None
        assert result == {"success": True, "verified": True}
        commands = [c for c, _p in fake.sent]
        assert commands.index("script_step") < commands.index("eval")

    @staticmethod
    def test_step_with_script_iserror_set_raises_tool_error() -> None:
        """A non-zero ``script.iserror()`` after stepping must raise ``ToolError``, not a fabricated success.

        Falsifiable: a wrapper that claimed ``success: True``
        unconditionally (the pre-remediation pattern this package's
        sibling script-op tests gate for ``script_load``/``script_run``/
        ``script_abort``) would not raise here even though x64dbg's own
        error register proves the step failed.
        """
        bridge = X64DbgBridge()

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "script_step":
                assert params is None
                return ok("true")
            if command == "eval":
                assert params == {"expression": _SCRIPT_ISERROR_EXPR}
                return ok(1)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)

        with pytest.raises(ToolError, match="script_step verification failed"):
            run_bridge_coroutine(bridge.script_step())


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


class TestScriptStepButtonDispatchesRpc:
    """The Script tab's Step button must drive ``bridge.script_step()``."""

    @staticmethod
    def test_step_button_click_issues_script_step_and_reports_verified(
        wired_tab: tuple[X64DbgAdvancedTab, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Step must send ``script_step`` and report a verified success.

        Falsifiable: if the Step button were never wired to
        ``_on_script_step``/``bridge.script_step()`` (a DEAD-CONTROL),
        no ``script_step`` command would ever be recorded and the
        status label would never update.

        Args:
            wired_tab: Advanced tab/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        tab, bridge = wired_tab

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "script_step":
                assert params is None
                return ok("true")
            if command == "eval":
                assert params == {"expression": _SCRIPT_ISERROR_EXPR}
                return ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        step_btn = priv(tab, "_script_step_btn", QPushButton)
        status_label = priv(tab, "_script_status_label", QLabel)

        step_btn.click()
        pump_until(qapp, lambda: "script_step" in status_label.text())

        assert any(command == "script_step" for command, _params in fake.sent)
        assert "script_step succeeded (verified)" in status_label.text()
        assert step_btn.isEnabled()
