# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg toolbar's Step N, Animate Start/Stop, and Get Trace Record controls.

``step_count``, ``animate_start``, ``animate_stop``, and ``get_trace_record``
are fully implemented and registered bridge methods with matching toolbar
controls (``_step_count_btn``/``_animate_start_btn``/``_animate_stop_btn``/
``_trace_record_btn``) in ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip for each: the button handler must read its input
widget(s), dispatch the exact real bridge coroutine via
``run_bridge_coroutine_logged``, and render the bridge's real result in the
console/trace output.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtGui import QAction
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

    Sets ``_x64dbg_path``/``_state.connected`` directly so
    ``plugin_status["ready"]`` is true once :meth:`install_fake_pipe` marks
    the plugin deployed and the pipe connected; without this,
    ``_update_controls_state`` leaves every toolbar debug button
    (``_step_count_btn``, ``_animate_start_btn``, etc.) disabled and a
    ``.click()`` in these tests would be a silent no-op.

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


class TestStepCountButtonDrivesStepCountRpc:
    """Clicking Step N must drive ``bridge.step_count(count, step_type="into")``."""

    @staticmethod
    def test_step_n_click_issues_tic_with_entered_count_and_reports_result(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Step N must send ``tic 0, <count>`` and log the verified step count.

        Falsifiable: if ``_on_step_count`` read a different widget, built the
        wrong ``exec`` command, or forwarded the wrong ``step_type``, the
        recorded ``exec`` command would not match ``tic 0, 7`` exactly, and
        the console message would not report a verified 7-step result.
        Broken production line: ``cmd = f"tic 0, {count}" if step_type ==
        "into" else f"toc 0, {count}"`` in ``X64DbgBridge.step_count``
        (``bridges/x64dbg.py``) and ``self._bridge.step_count(count,
        step_type="into")`` in ``_on_step_count`` (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "tic 0, 7"
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        step_count_input = priv(panel, "_step_count_input", QLineEdit)
        step_count_btn = priv(panel, "_step_count_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            step_count_input.setText("7")
            step_count_btn.click()
            pump_until(qapp, lambda: "Stepped 7 time(s)" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "tic 0, 7" in exec_cmds
            assert "Stepped 7 time(s)" in console_output.toPlainText()
            assert step_count_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_step_n_with_non_numeric_input_does_not_dispatch(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Non-numeric Step N input must be rejected locally without any RPC dispatch.

        Falsifiable: if the ``int(count_text)`` guard in ``_on_step_count``
        were removed, this would either raise an uncaught ``ValueError`` or
        dispatch a malformed ``tic`` command instead of leaving the fake
        pipe untouched.

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
        step_count_input = priv(panel, "_step_count_input", QLineEdit)
        step_count_btn = priv(panel, "_step_count_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            step_count_input.setText("not-a-number")
            step_count_btn.click()
            qapp.processEvents()

            assert fake.sent == []
            assert "Invalid step count" in console_output.toPlainText()
        finally:
            panel.deleteLater()


class TestAnimateStartButtonDrivesAnimateStartRpc:
    """Clicking Animate Start must drive ``bridge.animate_start(step_type="into")``."""

    @staticmethod
    def test_animate_start_click_issues_animateinto_and_reports_verified(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Animate Start must send ``AnimateInto`` and report a verified start.

        Falsifiable: if ``_on_animate_start`` called a different bridge
        method, or the bridge sent a different console command than
        ``AnimateInto``, the recorded ``exec`` command list would not
        contain it, and the console would not report "Animation started"
        with no unverified suffix. Broken production line: ``cmd =
        "AnimateInto" if step_type == "into" else "AnimateOver"`` in
        ``X64DbgBridge.animate_start`` and ``self._bridge.animate_start(
        step_type="into")`` in ``_on_animate_start``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "AnimateInto"
                return ok("")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        animate_start_btn = priv(panel, "_animate_start_btn", QAction)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            animate_start_btn.trigger()
            pump_until(qapp, lambda: "Animation started" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "AnimateInto" in exec_cmds
            assert "Animation started" in console_output.toPlainText()
            assert "unverified" not in console_output.toPlainText()
            assert animate_start_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestAnimateStopButtonDrivesAnimateStopRpc:
    """Clicking Animate Stop must drive ``bridge.animate_stop()``."""

    @staticmethod
    def test_animate_stop_click_issues_animatestop_and_reports_verified(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Animate Stop must send ``AnimateStop`` and report a verified stop.

        Falsifiable: if ``_on_animate_stop`` were wired to any other bridge
        method, or the bridge sent a different console command than
        ``AnimateStop``, the recorded ``exec`` command list would not
        contain it, and the console would not report "Animation stopped"
        with no unverified suffix. Broken production line: ``await
        self._send_command("AnimateStop")`` in
        ``X64DbgBridge.animate_stop`` and ``self._bridge.animate_stop()``
        in ``_on_animate_stop`` (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "AnimateStop"
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        animate_stop_btn = priv(panel, "_animate_stop_btn", QAction)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            animate_stop_btn.trigger()
            pump_until(qapp, lambda: "Animation stopped" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "AnimateStop" in exec_cmds
            assert "Animation stopped" in console_output.toPlainText()
            assert "unverified" not in console_output.toPlainText()
            assert animate_stop_btn.isEnabled()
        finally:
            panel.deleteLater()


class TestGetTraceRecordButtonDrivesTraceRecordRpc:
    """Clicking Get Trace Record must drive ``bridge.get_trace_record(address)``."""

    @staticmethod
    def test_get_trace_record_click_queries_exact_address_and_reports_hit_count(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Get Trace Record must query ``trace_record`` at the entered address.

        Falsifiable: if ``_on_get_trace_record`` read a different address
        widget, or passed the wrong address to the bridge, the recorded
        ``trace_record`` params would not match this address exactly, and
        the trace-output line would not report the exact ``hitCount``
        returned by the fake plugin. Broken production line:
        ``self._bridge.get_trace_record(address)`` in
        ``_on_get_trace_record`` and ``await self._send_pipe_command(
        "trace_record", {"address": hex(address), "size": size})`` in
        ``X64DbgBridge.get_trace_record`` (``bridges/x64dbg.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        address = 0x404050

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "trace_record":
                assert params == {"address": hex(address), "size": 1}
                return ok({"address": hex(address), "hitCount": 42})
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        trace_record_addr_input = priv(panel, "_trace_record_addr_input", QLineEdit)
        trace_record_btn = priv(panel, "_trace_record_btn", QPushButton)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            trace_record_addr_input.setText(hex(address))
            trace_record_btn.click()
            pump_until(qapp, lambda: "hitCount=42" in trace_output.toPlainText())

            trace_calls = [p for c, p in fake.sent if c == "trace_record"]
            assert trace_calls == [{"address": hex(address), "size": 1}]
            assert f"0x{address:X}: hitCount=42" in trace_output.toPlainText()
            assert trace_record_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_get_trace_record_with_invalid_address_does_not_dispatch(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """An unparseable address must be rejected locally without any RPC dispatch.

        Falsifiable: if the address-parsing guard in
        ``_on_get_trace_record`` were removed, this would either raise an
        uncaught ``ValueError`` or dispatch a malformed request instead of
        leaving the fake pipe untouched.

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
        trace_record_addr_input = priv(panel, "_trace_record_addr_input", QLineEdit)
        trace_record_btn = priv(panel, "_trace_record_btn", QPushButton)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            trace_record_addr_input.setText("not-an-address")
            trace_record_btn.click()
            qapp.processEvents()

            assert fake.sent == []
            assert "Invalid address" in trace_output.toPlainText()
        finally:
            panel.deleteLater()


class TestEnableRecordingButtonArmsThePage:
    """The panel must be able to arm the page it then queries (S18-D03).

    ``get_trace_record`` reads a counter x64dbg only keeps for pages a
    trace record type has been set on, so a Trace tab offering the query
    and no way to arm the page could only ever print ``hitCount=0``.
    """

    @staticmethod
    def test_enable_recording_click_arms_the_queried_address_with_the_chosen_type(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Clicking Enable Recording must drive ``set_trace_record`` for that address.

        Falsifiable: if the handler read a different widget, dropped the
        combo's selection, or never dispatched, the recorded
        ``trace_record_set`` params would not carry this address and this
        record type, and the armed page would not be echoed to the trace
        output. Broken production line:
        ``self._bridge.set_trace_record(address, record_type)`` in
        ``_on_set_trace_record`` and ``await self._send_pipe_command(
        "trace_record_set", ...)`` in ``X64DbgBridge.set_trace_record``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        address = 0x404050
        page = 0x404000
        record_type = "byte"

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "trace_record_set":
                assert params == {"address": hex(address), "type": record_type}
                return ok(
                    {
                        "address": hex(address),
                        "page": hex(page),
                        "requested": record_type,
                        "type": record_type,
                        "applied": True,
                    },
                )
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        trace_record_addr_input = priv(panel, "_trace_record_addr_input", QLineEdit)
        trace_record_type_combo = priv(panel, "_trace_record_type_combo", QComboBox)
        trace_record_arm_btn = priv(panel, "_trace_record_arm_btn", QPushButton)
        trace_output = priv(panel, "_trace_output", QPlainTextEdit)

        try:
            trace_record_addr_input.setText(hex(address))
            trace_record_type_combo.setCurrentText(record_type)
            trace_record_arm_btn.click()
            pump_until(qapp, lambda: hex(page) in trace_output.toPlainText())

            arm_calls = [p for c, p in fake.sent if c == "trace_record_set"]
            assert arm_calls == [{"address": hex(address), "type": record_type}]
            assert f"'{record_type}' enabled on page {hex(page)}" in trace_output.toPlainText()
            assert trace_record_arm_btn.isEnabled()
        finally:
            panel.deleteLater()
