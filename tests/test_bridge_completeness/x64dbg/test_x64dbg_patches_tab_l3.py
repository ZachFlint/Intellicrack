# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Patches tab (rows 29-31 of the state-manipulation slice).

``get_patches``, ``restore_patch``, and ``export_patches`` were fully
implemented and registered bridge methods with no GUI surface at all
(NO-CONTROL). The remediation added a "Patches" tab to ``x64dbg_panel.py``
that lists applied patches, restores a selected patch, and exports the
patch set to a file, each backed by a real bridge coroutine dispatched via
``run_bridge_coroutine_logged``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QFileDialog, QPlainTextEdit, QPushButton, QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_PATCH_ADDR_1 = 0x401000
_PATCH_ADDR_2 = 0x401010

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


def _cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Read the text of a table cell, failing loudly if the cell is empty.

    Args:
        table: The table widget to read from.
        row: Row index.
        column: Column index.

    Returns:
        str: The cell's text.
    """
    item = table.item(row, column)
    assert item is not None, f"expected an item at ({row}, {column})"
    return item.text()


def _residual_response(command: str) -> dict[str, Any]:
    """Build a canned response for a residual post-refresh RPC.

    ``_refresh_state()`` (triggered after several handlers succeed) polls a
    fixed set of auxiliary RPCs unrelated to the behavior a given test is
    gating; this helper answers all of them uniformly so responders only
    need to special-case the command under test.

    Args:
        command: The RPC command name.

    Returns:
        dict[str, Any]: A successful envelope with an empty/paused payload.
    """
    if command == "status":
        return ok({"paused": True, "debugging": True})
    return ok({})


class TestPatchesTabExistsAndIsWired:
    """The Patches tab widgets must exist with their handlers connected."""

    @staticmethod
    def test_patch_table_and_buttons_exist(wired_panel: tuple[X64DbgPanel, X64DbgBridge]) -> None:
        """The panel must expose ``_patch_table`` plus refresh/restore/export buttons.

        Falsifiable: if the Patches tab were removed from ``_setup_tabs``,
        these attributes would not exist and ``hasattr`` would fail.

        Args:
            wired_panel: Panel/bridge pair fixture.
        """
        panel, _bridge = wired_panel
        try:
            assert hasattr(panel, "_patch_table")
            assert hasattr(panel, "_patch_refresh_btn")
            assert hasattr(panel, "_patch_restore_btn")
            assert hasattr(panel, "_patch_export_btn")
            assert priv(panel, "_patch_table", QTableWidget).columnCount() == 3
        finally:
            panel.deleteLater()

    @staticmethod
    def test_refresh_button_connected_to_handler(wired_panel: tuple[X64DbgPanel, X64DbgBridge]) -> None:
        """The Refresh button's ``clicked`` signal must have a connected slot.

        Args:
            wired_panel: Panel/bridge pair fixture.
        """
        panel, _bridge = wired_panel
        try:
            patch_refresh_btn = priv(panel, "_patch_refresh_btn", QPushButton)
            patch_restore_btn = priv(panel, "_patch_restore_btn", QPushButton)
            patch_export_btn = priv(panel, "_patch_export_btn", QPushButton)
            assert patch_refresh_btn.receivers(patch_refresh_btn.clicked) >= 1
            assert patch_restore_btn.receivers(patch_restore_btn.clicked) >= 1
            assert patch_export_btn.receivers(patch_export_btn.clicked) >= 1
        finally:
            panel.deleteLater()


class TestRefreshPatchesCallsGetPatchesAndPopulatesTable:
    """Clicking Refresh must drive ``bridge.get_patches()`` and render the real result."""

    @staticmethod
    def test_refresh_populates_table_with_real_patch_data(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """The patch table must contain the exact address/old-byte/new-byte values from ``get_patches``.

        Falsifiable: if ``_on_refresh_patches`` called a different bridge
        method, or ``_apply_patches`` dropped/mis-mapped a field, the exact
        cell-text assertions below fail. Broken production line:
        ``self._bridge.get_patches()`` in ``_on_refresh_patches`` and the
        ``entry.get("oldByte"/"newByte")`` mapping in ``_apply_patches``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_list":
                return ok(
                    [
                        {"address": hex(_PATCH_ADDR_1), "oldByte": "90", "newByte": "CC"},
                        {"address": hex(_PATCH_ADDR_2), "oldByte": "EB", "newByte": "90"},
                    ],
                )
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        patch_refresh_btn = priv(panel, "_patch_refresh_btn", QPushButton)
        patch_table = priv(panel, "_patch_table", QTableWidget)

        try:
            patch_refresh_btn.click()
            pump_until(qapp, lambda: patch_table.rowCount() >= 2)

            assert patch_table.rowCount() == 2
            rows = {_cell_text(patch_table, r, 0): r for r in range(patch_table.rowCount())}
            addr1_key = f"0x{_PATCH_ADDR_1:X}"
            addr2_key = f"0x{_PATCH_ADDR_2:X}"
            assert addr1_key in rows
            assert addr2_key in rows
            row1 = rows[addr1_key]
            assert _cell_text(patch_table, row1, 1) == "90"
            assert _cell_text(patch_table, row1, 2) == "CC"
            row2 = rows[addr2_key]
            assert _cell_text(patch_table, row2, 1) == "EB"
            assert _cell_text(patch_table, row2, 2) == "90"
        finally:
            panel.deleteLater()


class TestRestorePatchDrivesRestorePatchRpc:
    """Selecting a row and clicking Restore must drive ``bridge.restore_patch(address)``."""

    @staticmethod
    def test_restore_selected_row_sends_patch_restore_with_exact_address(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Restoring the selected row must issue ``patch_restore`` with that row's exact address.

        Falsifiable: if ``_on_restore_patch`` read the wrong row, or passed
        the row index instead of the stored address, the recorded RPC
        params would not match ``_PATCH_ADDR_2``. Broken production line:
        ``address = cast("int", addr_item.data(Qt.ItemDataRole.UserRole))``
        / ``self._bridge.restore_patch(address)`` in ``_on_restore_patch``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_list":
                return ok(
                    [
                        {"address": hex(_PATCH_ADDR_1), "oldByte": "90", "newByte": "CC"},
                        {"address": hex(_PATCH_ADDR_2), "oldByte": "EB", "newByte": "90"},
                    ],
                )
            if command == "patch_restore":
                assert params == {"address": hex(_PATCH_ADDR_2)}
                return ok(None)
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        patch_refresh_btn = priv(panel, "_patch_refresh_btn", QPushButton)
        patch_table = priv(panel, "_patch_table", QTableWidget)
        patch_restore_btn = priv(panel, "_patch_restore_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            patch_refresh_btn.click()
            pump_until(qapp, lambda: patch_table.rowCount() >= 2)

            target_row = next(
                r for r in range(patch_table.rowCount()) if _cell_text(patch_table, r, 0) == f"0x{_PATCH_ADDR_2:X}"
            )
            patch_table.setCurrentCell(target_row, 0)
            patch_restore_btn.click()

            pump_until(qapp, lambda: "Patch restored" in console_output.toPlainText())

            restore_calls = [p for c, p in fake.sent if c == "patch_restore"]
            assert restore_calls == [{"address": hex(_PATCH_ADDR_2)}]
        finally:
            panel.deleteLater()


class TestExportPatchesDrivesExportPatchesBridgeCall:
    """Clicking Export must call the real ``bridge.export_patches(path)`` and report success.

    ``QFileDialog.getSaveFileName`` is a native OS dialog that cannot run
    headless in the sandbox, so it is monkeypatched to return a
    deterministic path (the same accepted pattern used in
    ``tests/test_audit4/c13_hex_patches_route/test_patches_bridge_route.py``);
    everything downstream of the dialog -- button click, bridge dispatch,
    ``savedata`` command framing, and console rendering -- is real
    production code.
    """

    @staticmethod
    def test_export_button_click_issues_savedata_and_reports_path(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking Export must issue ``savedata "<path>"`` and log the exact export path.

        Falsifiable: if ``_on_export_patches`` called a different bridge
        method, or built the export path differently, the recorded
        ``exec`` command would not match ``export_path`` exactly. Broken
        production line: ``self._bridge.export_patches(path)`` in
        ``_on_export_patches`` and ``await self._send_command(f'savedata
        "{path}"')`` in ``X64DbgBridge.export_patches``.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture, used only to stub the
                native file-save dialog boundary.
        """
        panel, bridge = wired_panel
        export_path = tmp_path / "patches.1337"

        def _fake_save_dialog(*_args: object, **_kwargs: object) -> tuple[str, str]:
            return (str(export_path), "Patch Files (*.1337)")

        monkeypatch.setattr(QFileDialog, "getSaveFileName", _fake_save_dialog)

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f'savedata "{export_path!s}"'
                return ok("")
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        patch_export_btn = priv(panel, "_patch_export_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            patch_export_btn.click()
            pump_until(qapp, lambda: any(cmd == "exec" for cmd, _ in fake.sent))
            pump_until(qapp, lambda: "Patches exported" in console_output.toPlainText())

            assert f"Patches exported to {export_path!s}" in console_output.toPlainText()
        finally:
            panel.deleteLater()
