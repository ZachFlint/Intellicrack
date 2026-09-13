# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg FPU/SIMD (x87/MMX/XMM/YMM) register table.

``get_extended_registers``/``set_extended_register`` are new bridge
methods (registered as ``x64dbg.get_extended_registers`` /
``x64dbg.set_extended_register``) backed by the plugin's new
``reg_extended``/``reg_set_extended`` RPCs, which serialize/accept the
vector and x87 FPU state that the existing ``reg_all`` RPC never
exposes. A matching "FPU / SIMD" table in ``x64dbg_panel.py`` renders the
values and accepts edits as raw hex byte strings (not integers, since
XMM/YMM values exceed 64 bits) - a short write must be rejected client
side rather than silently truncated, since ``SetThreadContext`` would
otherwise receive a value the CPU never actually held.
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

_XMM0_HEX = bytes(range(16)).hex()
_XMM3_INITIAL_HEX = "aabbccddeeff0011" + "2233445566778899"
_XMM3_HALF_WIDTH_HEX = "1122334455667788"
_XMM3_NEW_HEX = _XMM3_HALF_WIDTH_HEX + "99aabbccddeeff00"
_X87CONTROL_VALUE = 0x027F

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


def _residual_response(command: str) -> dict[str, Any]:
    """Build a canned response for a residual post-refresh RPC.

    Args:
        command: The RPC command name.

    Returns:
        dict[str, Any]: A successful envelope with an empty/paused payload.
    """
    if command == "status":
        return ok({"paused": True, "debugging": True})
    return ok({})


def _extended_registers_payload(*, xmm3: str) -> dict[str, Any]:
    """Build a full ``reg_extended`` response payload.

    Args:
        xmm3: Hex string to place at the ``xmm`` index 3.

    Returns:
        dict[str, Any]: A payload shaped like the real plugin response.
    """
    xmm = ["0" * 32] * 16
    xmm[0] = _XMM0_HEX
    xmm[3] = xmm3
    return {
        "xmm": xmm,
        "ymm": ["0" * 64] * 16,
        "st": ["0" * 20] * 8,
        "mmx": ["0" * 16] * 8,
        "mxcsr": "0x0000000000001f80",
        "x87control": _X87CONTROL_VALUE,
        "x87status": 0,
        "x87tag": 0,
    }


class TestGetExtendedRegistersSurfacesRealData:
    """``get_extended_registers`` must surface the plugin's vector/FPU payload unchanged."""

    @staticmethod
    def test_xmm0_and_x87control_surfaced_unchanged() -> None:
        """A ``reg_extended`` response's ``xmm[0]`` and ``x87control`` must come back verbatim.

        Falsifiable: if ``get_extended_registers`` returned ``{}``
        instead of the parsed plugin response, neither value would be
        present.
        """
        bridge = X64DbgBridge()
        payload = _extended_registers_payload(xmm3=_XMM3_INITIAL_HEX)

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            assert command == "reg_extended"
            assert params is None
            return ok(payload)

        install_fake_pipe(bridge, responder)
        result = run_bridge_coroutine(bridge.get_extended_registers())

        assert result is not None
        assert result["xmm"][0] == _XMM0_HEX
        assert result["x87control"] == _X87CONTROL_VALUE


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


def _ext_reg_row(table: QTableWidget, name: str) -> int:
    """Find the row index of a named register in the FPU/SIMD table.

    Args:
        table: The FPU/SIMD table widget.
        name: Register display name, e.g. ``"xmm3"``.

    Returns:
        int: The matching row index.
    """
    return next(row for row in range(table.rowCount()) if (item := table.item(row, 0)) is not None and item.text() == name)


class TestExtendedRegisterTableWiring:
    """The FPU/SIMD table must render real data and reject undersized writes client-side."""

    @staticmethod
    def test_refresh_state_renders_xmm0_with_the_real_value(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """``_refresh_state()`` must render ``xmm0`` with the plugin's real hex value.

        Falsifiable: if ``_refresh_extended_registers`` were never wired
        into ``_refresh_state`` (a DEAD-CONTROL table), the FPU/SIMD
        table would stay empty forever and this assertion would time out.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        payload = _extended_registers_payload(xmm3=_XMM3_INITIAL_HEX)

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_extended":
                return ok(payload)
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        ext_table = priv(panel, "_ext_reg_table", QTableWidget)

        try:
            getattr(panel, "_refresh_state")()
            pump_until(qapp, lambda: ext_table.rowCount() > 0)

            xmm0_row = _ext_reg_row(ext_table, "xmm0")
            val_item = ext_table.item(xmm0_row, 1)
            assert val_item is not None
            assert val_item.text() == _XMM0_HEX
        finally:
            panel.deleteLater()

    @staticmethod
    def test_editing_xmm3_cell_dispatches_reg_set_extended_with_exact_name_and_value(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Editing the ``xmm3`` cell to a full-width hex string must dispatch the exact write.

        Falsifiable: if ``_on_extended_register_edited`` dropped the
        ``value`` key (or mis-keyed ``name``), the recorded
        ``reg_set_extended`` params would not equal
        ``{"name": "xmm3", "value": _XMM3_NEW_HEX}`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        payload = _extended_registers_payload(xmm3=_XMM3_INITIAL_HEX)

        def seed_responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_extended":
                return ok(payload)
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected seed command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, seed_responder)
        ext_table = priv(panel, "_ext_reg_table", QTableWidget)

        try:
            getattr(panel, "_refresh_state")()
            pump_until(qapp, lambda: ext_table.rowCount() > 0)
            xmm3_row = _ext_reg_row(ext_table, "xmm3")

            sent: list[dict[str, Any]] = []

            def edit_responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
                assert command == "reg_set_extended"
                assert params is not None
                sent.append(params)
                return ok(result=True)

            install_fake_pipe(bridge, edit_responder)

            val_item = ext_table.item(xmm3_row, 1)
            assert val_item is not None
            val_item.setText(_XMM3_NEW_HEX)

            pump_until(qapp, lambda: len(sent) >= 1)

            assert sent[0] == {"name": "xmm3", "value": _XMM3_NEW_HEX}
        finally:
            panel.deleteLater()

    @staticmethod
    def test_editing_xmm3_with_half_width_hex_is_rejected_client_side(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """A half-width hex string must never reach ``reg_set_extended`` and the cell must revert.

        A short write silently truncated (rather than rejected) would
        write a meaningless partial register value through
        ``SetThreadContext``. Falsifiable: if the width check in
        ``_on_extended_register_edited`` were removed, a
        ``reg_set_extended`` command would be sent for the undersized
        value and the cell would keep the short text.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel
        payload = _extended_registers_payload(xmm3=_XMM3_INITIAL_HEX)

        def seed_responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_extended":
                return ok(payload)
            if command in _RESIDUAL_REFRESH_RPCS:
                return _residual_response(command)
            msg = f"unexpected seed command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, seed_responder)
        ext_table = priv(panel, "_ext_reg_table", QTableWidget)

        try:
            getattr(panel, "_refresh_state")()
            pump_until(qapp, lambda: ext_table.rowCount() > 0)
            xmm3_row = _ext_reg_row(ext_table, "xmm3")

            sent: list[tuple[str, dict[str, Any] | None]] = []

            def reject_responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
                sent.append((command, params))
                msg = f"unexpected command: {command}"
                raise AssertionError(msg)

            fake = install_fake_pipe(bridge, reject_responder)

            val_item = ext_table.item(xmm3_row, 1)
            assert val_item is not None
            val_item.setText(_XMM3_HALF_WIDTH_HEX)

            pump_until(qapp, lambda: val_item.text() == _XMM3_INITIAL_HEX, timeout_s=2.0)

            assert val_item.text() == _XMM3_INITIAL_HEX
            assert not any(command == "reg_set_extended" for command, _params in fake.sent)
            assert sent == []
        finally:
            panel.deleteLater()
