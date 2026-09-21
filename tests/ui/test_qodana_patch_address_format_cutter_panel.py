# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the patch-address formatting in ``cutter_panel``.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` finding on
``CutterPanel._on_patch_dialog``: the parsed ``address`` (``int | None``) is
read again inside an ``on_success`` closure handed to
``run_bridge_coroutine_logged``; the guard above the closure narrows it in
the enclosing scope but static analysis cannot prove that survives into the
closure. The handler now rebinds the narrowed value to an explicitly
``int``-typed local (``resolved_address``) before the log call, the bridge
call, and the closure.

This test drives ``_on_patch_dialog`` end-to-end -- real widget, real bridge
double, real lambda execution -- through Qt's modal input dialogs (stubbed
via monkeypatch to return fixed values, the standard way to drive
``QInputDialog.getText`` without blocking on a real modal) and asserts on
the exact rendered status text and the exact address forwarded to the
bridge.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QInputDialog

from intellicrack.ui.panels import cutter_panel as cutter_panel_module
from intellicrack.ui.panels.cutter_panel import CutterPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.cutter import CutterBridge

pytestmark = pytest.mark.usefixtures("qapp")


class _RecordingCutterBridge:
    """Stand-in bridge recording exactly which arguments ``write_bytes`` forwarded."""

    def __init__(self) -> None:
        """Initialise an empty call log."""
        self.calls: list[tuple[int, str]] = []

    async def write_bytes(self, address: int, hex_data: str) -> bool:
        """Record a ``write_bytes`` call.

        Args:
            address: Patch address.
            hex_data: Space-separated hex byte string.

        Returns:
            bool: Always True.
        """
        self.calls.append((address, hex_data))
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


def test_patch_dialog_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_patch_dialog``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr(cutter_panel_module, "run_bridge_coroutine_logged", _drive)
    responses = iter([("0x5000", True), ("90 90 90", True)])
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *_a, **_k: next(responses)))
    bridge = _RecordingCutterBridge()
    panel = CutterPanel()
    panel.set_bridge(cast("CutterBridge", bridge))

    panel._on_patch_dialog()

    assert bridge.calls == [(0x5000, "90 90 90")]
    assert panel.status_label is not None
    assert panel.status_label.text() == "Patched @ 0x5000"
