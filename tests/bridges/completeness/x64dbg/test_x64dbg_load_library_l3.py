# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Modules tab's Load DLL control.

``load_library`` is a new bridge method (registered as
``x64dbg.load_library``) with a matching "Load DLL..." button in the
Modules tab of ``x64dbg_panel.py``. This module gates the full
click-to-RPC round trip: the button handler must open a file dialog,
dispatch ``loadlib "<path>"`` followed by a ``$result`` readback via the
real bridge coroutine, and render the returned base address in the
console. It also gates the failure path where x64dbg reports a ``0``
(or unparseable) ``$result``, which must surface as a real error rather
than a fabricated success.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QFileDialog, QPlainTextEdit, QPushButton

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
        "status",
    },
)


@pytest.fixture
def wired_panel(qapp: QApplication) -> tuple[X64DbgPanel, X64DbgBridge]:
    """Build a panel with a real bridge attached (no live plugin pipe).

    Sets ``_x64dbg_path``/``_state.connected`` directly so
    ``plugin_status["ready"]`` is true once :meth:`install_fake_pipe` marks
    the plugin deployed and the pipe connected; without this,
    ``_update_controls_state`` leaves every toolbar debug button disabled
    and a ``.click()`` in these tests would be a silent no-op.

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


class TestLoadLibraryButtonDrivesLoadLibraryRpc:
    """Clicking "Load DLL..." must drive ``bridge.load_library(path)``."""

    @staticmethod
    def test_load_library_click_issues_loadlib_then_reg_get_and_reports_base_address(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Clicking Load DLL must send ``loadlib "<path>"`` then read back ``$result``.

        Falsifiable: if ``_on_load_library`` never called
        ``bridge.load_library``, or ``X64DbgBridge.load_library``
        (``bridges/x64dbg.py``) queued a different console command or
        skipped the ``$result`` readback, the recorded command sequence
        would not contain ``loadlib "<path>"`` immediately followed by a
        ``reg_get`` call carrying ``{"name": "$result"}``, and the
        console would never show the real returned base address.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Pytest temp directory fixture.
        """
        panel, bridge = wired_panel
        dll_path = tmp_path / "injected.dll"
        expected_base = "0x7ff800000000"

        def _fake_open_file(*_args: object, **_kwargs: object) -> tuple[str, str]:
            return (str(dll_path), "DLL Files (*.dll)")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", _fake_open_file)

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f'loadlib "{dll_path}"'
                return ok("")
            if command == "reg_get":
                assert params == {"name": "$result"}
                return ok(expected_base)
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        load_lib_btn = priv(panel, "_load_lib_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            load_lib_btn.click()
            pump_until(qapp, lambda: expected_base in console_output.toPlainText())

            command_sequence = [c for c, _p in fake.sent if c in {"exec", "reg_get"}]
            assert command_sequence.index("exec") < command_sequence.index("reg_get")

            exec_cmds = [p["command"] for c, p in fake.sent if c == "exec" and p]
            assert f'loadlib "{dll_path}"' in exec_cmds
            reg_get_calls = [p for c, p in fake.sent if c == "reg_get"]
            assert {"name": "$result"} in reg_get_calls
            assert expected_base in console_output.toPlainText()
            assert load_lib_btn.isEnabled()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_load_library_with_zero_result_reports_failure_not_fabricated_success(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A ``$result`` of ``0x0`` after ``loadlib`` must surface as a real error.

        Falsifiable: a naive implementation that returns ``{"success":
        True, ...}`` regardless of the ``$result`` readback would report
        success here even though x64dbg's own ``$result`` value (``0``)
        proves the load never took effect; this test only passes when
        ``load_library`` actually raises ``ToolError`` on a zero/
        unparseable result and the GUI surfaces it via
        ``_on_generic_error``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Pytest temp directory fixture.
        """
        panel, bridge = wired_panel
        dll_path = tmp_path / "missing.dll"

        def _fake_open_file(*_args: object, **_kwargs: object) -> tuple[str, str]:
            return (str(dll_path), "DLL Files (*.dll)")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", _fake_open_file)

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f'loadlib "{dll_path}"'
                return ok("")
            if command == "reg_get":
                assert params == {"name": "$result"}
                return ok("0x0")
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        load_lib_btn = priv(panel, "_load_lib_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            load_lib_btn.click()
            pump_until(qapp, lambda: "Load Library failed" in console_output.toPlainText())

            assert "Load Library failed" in console_output.toPlainText()
            assert "base_address" not in console_output.toPlainText()
            assert load_lib_btn.isEnabled()
        finally:
            panel.deleteLater()
