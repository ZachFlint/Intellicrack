# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for ``X64DbgPanel._on_switch_thread``'s success sequencing.

Covers the 2026-09-20 Qodana ``PyNoneFunctionAssignmentInspection`` finding:
the success callback built the tuple ``(self._console_output.appendPlainText(...),
self._refresh_state())[0]`` purely to sequence two ``None``-returning calls
inside a single-expression ``lambda`` -- indexing into a tuple of ``None``
values to fake multi-statement execution. It is replaced with a proper
nested function whose body is two ordinary statements. This test proves the
replacement genuinely still runs *both* steps, in order, which the tuple
trick's own type-checker finding could not by itself guarantee to a reader:
a future edit that reintroduces a single-expression lambda and drops one of
the two calls (a real risk when "simplifying" a two-statement function back
down) is caught because either the console message or the state refresh
goes missing.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QTableWidgetItem

from intellicrack.ui.panels import x64dbg_panel as x64dbg_panel_module
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.x64dbg import X64DbgBridge

pytestmark = pytest.mark.usefixtures("qapp")

_TEST_TID = 4242


class _RecordingX64DbgBridge:
    """Stand-in bridge recording exactly which thread id ``switch_thread`` forwarded."""

    def __init__(self) -> None:
        """Initialise an empty call log and a ready plugin status."""
        self.calls: list[int] = []
        self.plugin_status: dict[str, object] = {"ready": True, "diagnostic": "", "plugin_deployed": True}

    async def switch_thread(self, tid: int) -> dict[str, Any]:
        """Record a ``switch_thread`` call.

        Args:
            tid: Thread id to switch to.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls.append(tid)
        return {}


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine so the success callback runs in-thread.

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


def test_switch_thread_success_prints_message_and_refreshes_state_in_order(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The success handler must both print the console message and call ``_refresh_state``.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr(x64dbg_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    panel = X64DbgPanel()
    panel.set_bridge(cast("X64DbgBridge", bridge))
    panel._thread_table.insertRow(0)
    panel._thread_table.setItem(0, 0, QTableWidgetItem(str(_TEST_TID)))
    panel._thread_table.setCurrentCell(0, 0)

    refresh_calls: list[None] = []
    monkeypatch.setattr(panel, "_refresh_state", lambda: refresh_calls.append(None))

    panel._on_switch_thread()

    assert bridge.calls == [_TEST_TID]
    lines = panel._console_output.toPlainText().splitlines()
    assert lines[-1] == f"[+] Switched to thread {_TEST_TID}"
    assert refresh_calls == [None], "the success handler must call _refresh_state() exactly once"


def test_switch_thread_with_no_selection_does_not_touch_bridge_or_refresh(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no thread row selected, the handler must return before the bridge/refresh.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr(x64dbg_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    panel = X64DbgPanel()
    panel.set_bridge(cast("X64DbgBridge", bridge))

    refresh_calls: list[None] = []
    monkeypatch.setattr(panel, "_refresh_state", lambda: refresh_calls.append(None))

    panel._on_switch_thread()

    assert bridge.calls == []
    assert refresh_calls == []
