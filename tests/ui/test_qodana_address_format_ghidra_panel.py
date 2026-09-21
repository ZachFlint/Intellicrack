# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the address formatting in ``ghidra_panel``.

Covers two 2026-09-20 Qodana ``PyStringFormatInspection`` findings in
``GhidraPanel``:

* ``_on_apply_structure``: the parsed ``addr`` (``int | None``) is read
  again inside an ``on_success`` closure handed to
  ``run_bridge_coroutine_logged``; the guard above the closure narrows it in
  the enclosing scope but static analysis cannot prove that survives into
  the closure. The handler now rebinds the narrowed value to an explicitly
  ``int``-typed local (``resolved_addr``).
* ``_on_write_bytes``: the same pattern for the parsed write address,
  rebound to ``resolved_addr`` before the invalid-hex log line, the
  requested-write log line, the bridge call, and the closure.

Both tests drive the real handler end-to-end -- real widget, real bridge
double (exposing ``state.is_ready()`` so ``_require_connected`` succeeds),
real lambda execution -- and assert on the exact rendered status text and
the exact address forwarded to the bridge.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import ghidra_panel as ghidra_panel_module
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.ghidra import GhidraBridge

pytestmark = pytest.mark.usefixtures("qapp")


class _RecordingGhidraBridge:
    """Stand-in bridge recording exactly which arguments each call forwarded."""

    def __init__(self) -> None:
        """Initialise a connected, ready bridge state and empty call log."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.calls: dict[str, tuple[object, ...]] = {}

    async def apply_structure_at(self, address: int, struct_name: str) -> dict[str, Any]:
        """Record an ``apply_structure_at`` call.

        Args:
            address: Target address.
            struct_name: Structure type name.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["apply_structure_at"] = (address, struct_name)
        return {}

    async def write_bytes(self, address: int, data: str) -> dict[str, Any]:
        """Record a ``write_bytes`` call.

        Args:
            address: Target address.
            data: Hex byte string.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["write_bytes"] = (address, data)
        return {}


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine so the success lambda runs in-thread.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Success callback, invoked synchronously with the result.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (event, logger, level, context).
    """
    del on_error, parent
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    finally:
        loop.close()
    if on_success is not None:
        cast("Any", on_success)(result)


def _make_panel(qapp: QApplication, bridge: _RecordingGhidraBridge) -> GhidraPanel:
    """Build a real ``GhidraPanel`` wired to a recording, ready bridge double.

    Args:
        qapp: The shared offscreen QApplication fixture.
        bridge: The recording bridge double to attach.

    Returns:
        GhidraPanel: A freshly constructed, bridge-attached panel.
    """
    _ = qapp
    panel = GhidraPanel()
    panel.set_bridge(cast("GhidraBridge", bridge))
    return panel


def test_apply_structure_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_apply_structure``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(ghidra_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingGhidraBridge()
    panel = _make_panel(qapp, bridge)
    panel._apply_struct_addr_input.setText("0x7000")
    panel._apply_struct_name_input.setText("IMAGE_DOS_HEADER")

    panel._on_apply_structure()

    assert bridge.calls["apply_structure_at"] == (0x7000, "IMAGE_DOS_HEADER")
    assert panel.status_label is not None
    assert panel.status_label.text() == "Structure 'IMAGE_DOS_HEADER' applied at 0x7000"


def test_write_bytes_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_write_bytes``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(ghidra_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingGhidraBridge()
    panel = _make_panel(qapp, bridge)
    panel._write_addr_input.setText("0x8000")
    panel._write_hex_input.setText("90 90 90 90")

    panel._on_write_bytes()

    assert bridge.calls["write_bytes"] == (0x8000, "90 90 90 90")
    assert panel.status_label is not None
    assert panel.status_label.text() == "Wrote 4 byte(s) at 0x8000"
