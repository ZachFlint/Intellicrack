# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Trace tab's Coverage Trace and Set Log File controls.

``trace_into_beyond_coverage``, ``trace_over_beyond_coverage``,
``trace_into_within_coverage``, ``trace_over_within_coverage``, and
``set_trace_log_file`` are fully implemented and registered bridge methods
with matching Trace-tab controls (``_trace_coverage_combo``/
``_trace_coverage_btn``/``_trace_logfile_input``/``_trace_logfile_btn``) in
``x64dbg_panel.py``. This module gates the full click-to-RPC round trip for
each: the button handler must read its input widget(s), dispatch the exact
real bridge coroutine via ``run_bridge_coroutine_logged``, and render the
bridge's real result in the trace output.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QLineEdit, QPlainTextEdit, QPushButton

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


class TestCoverageTraceButtonDrivesSelectedBridgeMethod:
    """Clicking Coverage Trace must drive the combo-selected coverage-trace bridge method."""

    @staticmethod
    def test_beyond_into_with_no_condition_sends_exact_command_and_no_trailing_condition(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting "Beyond (into)" with an empty condition must send the bare two-argument command.

        Falsifiable: if ``_on_trace_coverage`` always appended a trailing
        ``, "<condition>"`` regardless of whether a condition was typed,
        the recorded ``exec`` command would carry a spurious empty
        condition clause instead of matching
        ``TraceIntoBeyondTraceCoverage 0, 50000`` exactly. This also pins
        the argument order x64dbg's own docs specify for
        ``TraceIntoBeyondTraceCoverage``/``tibt`` (break condition first,
        step budget second) - reverting to a max-steps-first framing
        reddens this assertion.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "TraceIntoBeyondTraceCoverage 0, 50000"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        coverage_combo = priv(panel, "_trace_coverage_combo", QComboBox)
        coverage_btn = priv(panel, "_trace_coverage_btn", QPushButton)
        trace_cond_input = priv(panel, "_trace_cond_input", QLineEdit)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            trace_cond_input.setText("")
            coverage_combo.setCurrentIndex(0)
            assert coverage_combo.currentData() == "trace_into_beyond_coverage"
            coverage_btn.click()
            pump_until(qapp, lambda: "trace_into_beyond_coverage started" in trace_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "TraceIntoBeyondTraceCoverage 0, 50000" in exec_cmds
            assert "[+] trace_into_beyond_coverage started" in trace_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_within_over_with_condition_sends_exact_command_with_condition_first(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting "Within (over)" with a condition must send the condition-first command.

        Falsifiable: if the combo's userData mapped to the wrong bridge
        method, or the bridge built the command with the step budget
        before the condition, the recorded ``exec`` command would not
        match ``TraceOverIntoTraceCoverage "eax==1", 50000`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == 'TraceOverIntoTraceCoverage "eax==1", 50000'
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        coverage_combo = priv(panel, "_trace_coverage_combo", QComboBox)
        coverage_btn = priv(panel, "_trace_coverage_btn", QPushButton)
        trace_cond_input = priv(panel, "_trace_cond_input", QLineEdit)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            trace_cond_input.setText("eax==1")
            coverage_combo.setCurrentIndex(3)
            assert coverage_combo.currentData() == "trace_over_within_coverage"
            coverage_btn.click()
            pump_until(qapp, lambda: "trace_over_within_coverage started" in trace_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert 'TraceOverIntoTraceCoverage "eax==1", 50000' in exec_cmds
            assert "[+] trace_over_within_coverage started" in trace_output.toPlainText()
        finally:
            panel.deleteLater()


class TestSetLogFileButtonDrivesTraceSetLogFileRpc:
    """Clicking Set Log File must drive ``bridge.set_trace_log_file(path)``."""

    @staticmethod
    def test_set_log_file_click_sends_exact_quoted_path_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Set Log File must send ``TraceSetLogFile "<path>"`` with the typed path.

        Falsifiable: if ``_on_set_trace_log_file`` read a different
        widget, dropped the quoting, or called a different bridge method,
        the recorded ``exec`` command would not match the expected
        quoted-path command exactly, and the trace output would not
        confirm the path.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        path = "C:\\trace.log"

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == 'TraceSetLogFile "C:\\trace.log"'
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        logfile_input = priv(panel, "_trace_logfile_input", QLineEdit)
        logfile_btn = priv(panel, "_trace_logfile_btn", QPushButton)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            logfile_input.setText(path)
            logfile_btn.click()
            pump_until(qapp, lambda: "Trace log file set to" in trace_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert 'TraceSetLogFile "C:\\trace.log"' in exec_cmds
            assert f"[+] Trace log file set to {path}" in trace_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_set_log_file_with_empty_path_does_not_dispatch(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An empty Log File field must be rejected locally without any RPC dispatch.

        Falsifiable: if the empty-path guard in ``_on_set_trace_log_file``
        were removed, this would dispatch a malformed
        ``TraceSetLogFile ""`` command instead of leaving the fake pipe
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
        logfile_input = priv(panel, "_trace_logfile_input", QLineEdit)
        logfile_btn = priv(panel, "_trace_logfile_btn", QPushButton)

        try:
            logfile_input.setText("")
            logfile_btn.click()
            qapp.processEvents()

            assert fake.sent == []
        finally:
            panel.deleteLater()
