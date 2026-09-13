# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Debug Registers (DR0-DR3, DR6, DR7) table.

``get_debug_registers`` is a new bridge method (registered as
``x64dbg.get_debug_registers``) that reads each debug register through the
generic, allowlist-free ``reg_get`` RPC. Arming a hardware breakpoint
requires writing *both* the address register (e.g. ``dr0``) and the
matching enable bit in ``dr7`` - a caller that writes only the address
leaves the breakpoint silently disarmed, so this module gates that
dual write explicitly (the Stream-A DR7-enable-bit hazard).

A matching "Debug Registers" table in ``x64dbg_panel.py`` renders the
values and is wired into ``_refresh_state()`` alongside the GPR table.
Both tables route cell edits through the same ``_on_register_edited``
handler (``set_register``/``reg_set`` already accepts any register
mnemonic with no allowlist), so this module also gates that the shared
handler resolves its table from the emitting signal's sender rather than
a hardcoded widget - a regression here would silently edit the wrong
register when editing the Debug Registers table.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QTableWidget

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_DR0_BREAKPOINT_ADDR = 0x401000
_DR7_ARMED_L0 = 0x1

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_all",
        "reg_extended",
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


def _residual_response(command: str) -> dict[str, Any]:
    """Build a canned response for a residual post-refresh RPC.

    ``_refresh_state()`` polls several auxiliary RPCs unrelated to the
    debug-register behavior under test; this answers all of them
    uniformly so responders only need to special-case ``reg_get``.

    Args:
        command: The RPC command name.

    Returns:
        dict[str, Any]: A successful envelope with an empty/paused payload.
    """
    if command == "status":
        return ok({"paused": True, "debugging": True})
    if command == "reg_extended":
        return ok({"xmm": [], "ymm": [], "st": [], "mmx": [], "mxcsr": "0x00000000", "x87control": 0, "x87status": 0, "x87tag": 0})
    return ok({})


class TestGetDebugRegistersParsesHexValues:
    """``get_debug_registers`` must parse each ``reg_get`` hex string into a real int."""

    @staticmethod
    def test_dr7_value_parsed_from_hex_string() -> None:
        """A ``reg_get`` response of ``"0x1"`` for dr7 must surface as the int ``1``.

        Falsifiable: if ``get_debug_registers`` hardcoded ``0`` instead of
        parsing the plugin's response (or read the wrong key), ``dr7``
        would not equal ``1``.
        """
        bridge = X64DbgBridge()

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            assert command == "reg_get"
            assert params is not None
            name = params["name"]
            assert name in X64DbgBridge.DEBUG_REGISTER_NAMES
            return ok("0x1" if name == "dr7" else "0x0")

        install_fake_pipe(bridge, responder)
        result = run_bridge_coroutine(bridge.get_debug_registers())

        assert result is not None
        assert result["dr7"] == 1
        assert result["dr0"] == 0
        assert set(result) == set(X64DbgBridge.DEBUG_REGISTER_NAMES)

    @staticmethod
    def test_arming_dr0_writes_both_dr0_and_dr7_enable_bit_in_order() -> None:
        """Arming a DR0 breakpoint must write DR0 then the DR7 enable bit, in that order.

        Falsifiable: if only the DR0 write were issued (the hazard this
        order calls out - DR0 will not round-trip without the matching
        DR7 enable bit), the recorded ``reg_set`` sequence would not
        contain both writes, or would contain them out of order.
        """
        bridge = X64DbgBridge()
        sent_reg_sets: list[dict[str, Any]] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            assert command == "reg_set"
            assert params is not None
            sent_reg_sets.append(params)
            return ok("true")

        install_fake_pipe(bridge, responder)

        assert run_bridge_coroutine(bridge.set_register("dr0", _DR0_BREAKPOINT_ADDR)) is True
        assert run_bridge_coroutine(bridge.set_register("dr7", _DR7_ARMED_L0)) is True

        assert len(sent_reg_sets) == 2
        assert sent_reg_sets[0] == {"register": "dr0", "value": _DR0_BREAKPOINT_ADDR}
        assert sent_reg_sets[1] == {"register": "dr7", "value": _DR7_ARMED_L0}


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
    panel.set_bridge(bridge)
    return panel, bridge


class TestDebugRegisterTableWiring:
    """The Debug Registers table must populate from real data and route edits to the right register."""

    @staticmethod
    def test_refresh_state_populates_debug_register_table_with_real_values(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """``_refresh_state()`` must render the real ``dr0``..``dr7`` values, not placeholders.

        Falsifiable: if ``_refresh_debug_registers`` were never wired into
        ``_refresh_state`` (a DEAD-CONTROL table), the Debug Registers
        table would stay empty forever and this assertion would time out.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_get":
                assert params is not None
                name = params["name"]
                return ok("0x7" if name == "dr7" else "0x0")
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        dr_table = priv(panel, "_dr_table", QTableWidget)

        try:
            getattr(panel, "_refresh_state")()
            pump_until(qapp, lambda: dr_table.rowCount() >= len(X64DbgBridge.DEBUG_REGISTER_NAMES))

            rows = {}
            for row in range(dr_table.rowCount()):
                name_item = dr_table.item(row, 0)
                val_item = dr_table.item(row, 1)
                assert name_item is not None
                assert val_item is not None
                rows[name_item.text()] = val_item.text()

            assert rows["dr7"] == "0x0000000000000007"
            assert rows["dr0"] == "0x0000000000000000"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_editing_debug_register_cell_sets_the_debug_register_not_the_gpr_at_the_same_row(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Editing row 0 of the Debug Registers table must set ``dr0``, never the GPR table's row 0.

        ``_reg_table`` and ``_dr_table`` share the same
        ``_on_register_edited`` slot; both tables are populated with a
        register at row 0 here so a handler that still hardcoded
        ``self._reg_table`` internally (instead of resolving the sender)
        would read the GPR table's row-0 register name (``rax``) and
        dispatch ``set_register("rax", ...)`` instead of ``"dr0"`` -
        silently corrupting the wrong register.

        Falsifiable: reverting the shared edit handler to always read
        ``self._reg_table`` makes the recorded ``reg_set`` carry
        ``"rax"`` instead of ``"dr0"``, failing this assertion.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def seed_responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_all":
                return ok({"rax": "0x1111111111111111"})
            if command == "reg_get":
                assert params is not None
                return ok("0x0")
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected seed command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, seed_responder)
        reg_table = priv(panel, "_reg_table", QTableWidget)
        dr_table = priv(panel, "_dr_table", QTableWidget)

        try:
            getattr(panel, "_refresh_state")()
            pump_until(qapp, lambda: reg_table.rowCount() > 0 and dr_table.rowCount() > 0)

            dr0_row = next(
                row for row in range(dr_table.rowCount()) if (item := dr_table.item(row, 0)) is not None and item.text() == "dr0"
            )
            reg_row0_item = reg_table.item(0, 0)
            assert reg_row0_item is not None
            assert reg_row0_item.text() != "dr0", "test setup must place a different register at GPR row 0"

            sent_reg_sets: list[dict[str, Any]] = []

            def edit_responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
                assert command == "reg_set"
                assert params is not None
                sent_reg_sets.append(params)
                return ok("true")

            install_fake_pipe(bridge, edit_responder)

            val_item = dr_table.item(dr0_row, 1)
            assert val_item is not None
            val_item.setText("0x2000")

            pump_until(qapp, lambda: len(sent_reg_sets) >= 1)

            assert sent_reg_sets[0]["register"] == "dr0"
            assert sent_reg_sets[0]["value"] == 0x2000
        finally:
            panel.deleteLater()
