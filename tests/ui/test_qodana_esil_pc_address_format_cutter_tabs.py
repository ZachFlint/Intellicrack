# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the ESIL PC-address formatting in ``cutter_tabs``.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` finding on
``ESILConsoleTab._on_set_pc``: the parsed ``address`` (``int | None``) is
read again inside an ``on_success`` closure handed to
``run_bridge_coroutine_logged``; the guard above the closure narrows it in
the enclosing scope but static analysis cannot prove that survives into the
closure. The handler now rebinds the narrowed value to an explicitly
``int``-typed local (``resolved_address``) before the console echo, the
bridge call, and the closure.

This test drives ``_on_set_pc`` end-to-end -- real widget, real bridge
double, real lambda execution -- and asserts on the exact console output and
the exact address forwarded to the bridge.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.ui.panels import cutter_tabs as cutter_tabs_module
from intellicrack.ui.panels.cutter_tabs import ESILConsoleTab


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.cutter import CutterBridge

pytestmark = pytest.mark.usefixtures("qapp")


class _RecordingCutterBridge:
    """Stand-in bridge recording exactly which address ``esil_set_pc`` forwarded."""

    def __init__(self) -> None:
        """Initialise an empty call log."""
        self.calls: list[int] = []

    async def esil_set_pc(self, address: int) -> bool:
        """Record an ``esil_set_pc`` call.

        Args:
            address: The address to set as the ESIL program counter.

        Returns:
            bool: Always True.
        """
        self.calls.append(address)
        return True


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


def test_set_pc_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_set_pc``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr(cutter_tabs_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingCutterBridge()
    tab = ESILConsoleTab()
    tab._bridge = cast("CutterBridge", bridge)
    tab._addr_input.setText("0x6000")

    tab._on_set_pc()

    assert bridge.calls == [0x6000]
    lines = tab._output.toPlainText().splitlines()
    assert lines[0] == "> aepc 0x6000"
    assert lines[-1] == "[ok] PC set to 0x6000"
