# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.stack_viewer`.

Covers the 2026-07-02 audit findings for ``stack_viewer.py``:

* M30 -- ``set_x64dbg_bridge``/``set_frida_bridge`` attached a bridge to the
  underlying data source but never re-evaluated the status label or
  refreshed the panel. A Stack Viewer opened before a debugger/Frida session
  attached kept showing the construction-time "Not connected" label even
  after the bridge went live, until the user manually clicked Refresh,
  toggled Auto, or reselected the source combo. The fix calls
  ``self.refresh()`` (which internally calls ``_update_status()``) whenever
  the bridge being attached belongs to the currently active source.
* M36 -- ``StackFrameTable`` painted row colors directly via
  ``QTableWidgetItem.setForeground(QColor(...))`` from ``_get_stack_colors()``,
  which is only invoked inside ``set_frames()``. Nothing connected to
  ``ThemeManager.theme_changed``, so already-rendered rows kept stale colors
  (e.g. a dark-theme "function_unknown" grey with inadequate contrast) after
  a live theme switch, until the user forced a fresh ``set_frames()`` call.
  The fix caches the last-rendered frames and reconnects
  ``ThemeManager.theme_changed`` to a slot that re-invokes ``set_frames()``.

All tests drive real :class:`StackViewerPanel` / :class:`StackFrameTable`
instances under an offscreen ``QApplication``. Bridge-backed call sites use
lightweight stand-in bridges exposing only the attributes the stack sources
read (``state`` plus the coroutine-returning fetch method), following the
pattern used by the sibling ``x64dbg_panel`` / ``frida_panel`` GUI-audit gate
files, so the real dispatch/status logic runs deterministically without a
live debugger or Frida session.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtGui import QColor

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import stack_viewer
from intellicrack.ui.panels.stack_viewer import StackFrame, StackFrameTable, StackViewerPanel, _get_stack_colors
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.frida_bridge import FridaBridge
    from intellicrack.bridges.x64dbg import X64DbgBridge


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _ReadyX64DbgBridgeStub:
    """Stand-in x64dbg bridge exposing only what ``X64DbgStackSource`` reads.

    Reports a connected, tool-running :class:`BridgeState` (so
    ``is_connected()`` resolves True) and records whether its stack-trace
    coroutine was requested.
    """

    def __init__(self) -> None:
        """Initialise a connected, tool-running bridge state."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.coroutine_requested: bool = False

    def get_stack_trace(self) -> Coroutine[object, object, object]:
        """Return an inert coroutine and record that it was requested.

        Returns:
            Coroutine[object, object, object]: A real, never-awaited-by-us
            coroutine standing in for the bridge's stack trace fetch.
        """
        self.coroutine_requested = True
        return self._empty_stack()

    async def _empty_stack(self) -> list[object]:
        """Produce an empty raw stack trace.

        Returns:
            list[object]: An empty raw stack list.
        """
        return []


class _AttachedFridaBridgeStub:
    """Stand-in Frida bridge exposing only what ``FridaStackSource`` reads.

    Reports a connected, process-attached :class:`BridgeState` (so
    ``is_connected()`` resolves True) and records whether its backtrace
    coroutine was requested.
    """

    def __init__(self) -> None:
        """Initialise a connected, process-attached bridge state."""
        self.state = BridgeState(connected=True, tool_running=True, process_attached=True)
        self.coroutine_requested: bool = False

    def get_backtrace(self) -> Coroutine[object, object, object]:
        """Return an inert coroutine and record that it was requested.

        Returns:
            Coroutine[object, object, object]: A real, never-awaited-by-us
            coroutine standing in for the bridge's backtrace fetch.
        """
        self.coroutine_requested = True
        return self._empty_backtrace()

    async def _empty_backtrace(self) -> list[object]:
        """Produce an empty raw backtrace.

        Returns:
            list[object]: An empty raw backtrace list.
        """
        return []


def _inert_dispatch(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None = None,
    on_error: Callable[[object], None] | None = None,
    parent: object = None,
    *,
    event: str,
    logger: object,
    **context: object,
) -> None:
    """Stand in for ``run_bridge_coroutine_logged`` without running the coroutine.

    Closes the coroutine unrun so the panel's synchronous status/refresh
    bookkeeping can be asserted without a live background event loop.

    Args:
        coro: The bridge coroutine the call site produced; closed unrun.
        on_success: Success callback the call site passed (unused).
        on_error: Error callback the call site passed (unused).
        parent: Parent QObject the call site passed (unused).
        event: Structured-log event name the call site passed (unused).
        logger: Bound logger the call site passed (unused).
        **context: Additional structured-log context (unused).
    """
    del on_success, on_error, parent, event, logger, context
    coro.close()


@pytest.fixture
def panel(qapp: QApplication) -> Iterator[StackViewerPanel]:
    """Create a StackViewerPanel with its default sources for gate tests.

    Args:
        qapp: Session QApplication fixture ensuring Qt is initialised.

    Yields:
        StackViewerPanel: A freshly constructed panel.
    """
    del qapp
    widget = StackViewerPanel()
    yield widget
    widget.deleteLater()


def test_m30_set_x64dbg_bridge_refreshes_stale_status(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M30: attaching a ready x64dbg bridge while it is active refreshes the stale status label.

    Pre-fix, ``set_x64dbg_bridge`` only called ``source.set_bridge(bridge)``
    and never touched ``_update_status()``/``refresh()``, so the panel kept
    showing its construction-time "Not connected" label. Post-fix it calls
    ``self.refresh()`` (which calls ``_update_status()``) whenever the newly
    attached bridge belongs to the active source.

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _inert_dispatch)

    assert panel._active_source == "x64dbg", "test premise: x64dbg is the default active source"
    assert panel.status_label.text() == "Not connected"
    assert panel.status_label.property("status") == "idle"

    bridge_stub = _ReadyX64DbgBridgeStub()
    panel.set_x64dbg_bridge(cast("X64DbgBridge", bridge_stub))

    assert panel.status_label.text() == "Connected", (
        "status label must reflect the newly attached, ready x64dbg bridge without a manual refresh/reselect"
    )
    assert panel.status_label.property("status") == "success"
    assert bridge_stub.coroutine_requested is True, "attaching the active-source bridge must also trigger a real stack refresh"


def test_m30_set_frida_bridge_refreshes_stale_status(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M30: attaching an attached Frida bridge while it is active refreshes the stale status label.

    Mirrors the x64dbg case for ``set_frida_bridge``, which was fixed by the
    same pattern. The Frida source is made active first (via the source
    combo, exercising the real selection wiring), confirming the label reads
    "Not connected" before any bridge is attached.

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _inert_dispatch)

    panel._source_combo.setCurrentText("Frida")
    assert panel._active_source == "Frida"
    assert panel.status_label.text() == "Not connected"

    bridge_stub = _AttachedFridaBridgeStub()
    panel.set_frida_bridge(cast("FridaBridge", bridge_stub))

    assert panel.status_label.text() == "Connected", (
        "status label must reflect the newly attached, attached Frida bridge without a manual refresh/reselect"
    )
    assert panel.status_label.property("status") == "success"
    assert bridge_stub.coroutine_requested is True, "attaching the active-source bridge must also trigger a real stack refresh"


def test_m30_set_x64dbg_bridge_does_not_refresh_inactive_source(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M30: attaching an x64dbg bridge while Frida is active does not spuriously dispatch a refresh.

    The fix guards the follow-up refresh with ``self._active_source == "x64dbg"``. This asserts that
    guard is genuinely conditional rather than an unconditional refresh call.

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _inert_dispatch)

    panel._source_combo.setCurrentText("Frida")
    assert panel._active_source == "Frida"

    bridge_stub = _ReadyX64DbgBridgeStub()
    panel.set_x64dbg_bridge(cast("X64DbgBridge", bridge_stub))

    assert bridge_stub.coroutine_requested is False, "attaching a bridge for a non-active source must not trigger a refresh"


def test_m36_theme_switch_repaints_existing_stack_frame_colors(qapp: QApplication) -> None:
    """M36: switching the live theme re-paints already-rendered stack frame colors.

    Pre-fix, ``StackFrameTable`` never connected to ``ThemeManager.theme_changed``,
    so a row rendered once under dark theme kept its dark-theme
    ``QTableWidgetItem`` foreground colors after switching to light theme,
    until something forced a fresh ``set_frames()`` call. Post-fix the table
    caches the last frames and reconnects the signal to re-render them.

    Args:
        qapp: Session QApplication fixture; ``ThemeManager.apply_theme``
            requires a live ``QApplication`` instance to take effect.
    """
    del qapp
    table = StackFrameTable()
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        frame = StackFrame(
            index=0,
            return_address=0x7FFE0000,
            function_name="unknown",
            module_name="ntdll.dll",
            offset=0x10,
            frame_pointer=0x2000,
            stack_pointer=0x3000,
        )
        table.set_frames([frame])

        dark_colors = _get_stack_colors()
        assert table.item(0, 0) is not None
        assert table.item(0, 1) is not None
        assert table.item(0, 2) is not None
        assert table.item(0, 3) is not None
        assert table.item(0, 4) is not None
        assert table.item(0, 5) is not None
        assert table.item(0, 6) is not None
        assert table.item(0, 0).foreground().color() == dark_colors["index_highlight"] == QColor("#4ec9b0")
        assert table.item(0, 1).foreground().color() == dark_colors["address"] == QColor("#569cd6")
        assert table.item(0, 2).foreground().color() == dark_colors["function_unknown"] == QColor("#888888")
        assert table.item(0, 3).foreground().color() == dark_colors["module"] == QColor("#4ec9b0")
        assert table.item(0, 4).foreground().color() == dark_colors["offset"] == QColor("#b5cea8")
        assert table.item(0, 5).foreground().color() == dark_colors["pointer"] == QColor("#ce9178")
        assert table.item(0, 6).foreground().color() == dark_colors["pointer"] == QColor("#ce9178")

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)

        light_colors = _get_stack_colors()
        assert light_colors["function_unknown"] != dark_colors["function_unknown"], (
            "test premise: light/dark function_unknown colors must differ"
        )
        assert table.item(0, 0) is not None
        assert table.item(0, 1) is not None
        assert table.item(0, 2) is not None
        assert table.item(0, 3) is not None
        assert table.item(0, 4) is not None
        assert table.item(0, 5) is not None
        assert table.item(0, 6) is not None
        assert table.item(0, 0).foreground().color() == QColor("#0067c0"), (
            "index highlight color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 1).foreground().color() == QColor("#0451a5"), (
            "address color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 2).foreground().color() == QColor("#5a6370"), (
            "function_unknown color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 3).foreground().color() == QColor("#0067c0"), (
            "module color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 4).foreground().color() == QColor("#098658"), (
            "offset color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 5).foreground().color() == QColor("#a31515"), (
            "frame-pointer color must re-resolve to the light theme without a manual refresh"
        )
        assert table.item(0, 6).foreground().color() == QColor("#a31515"), (
            "stack-pointer color must re-resolve to the light theme without a manual refresh"
        )
    finally:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        table.deleteLater()


def test_m36_theme_switch_round_trip_restores_dark_colors_each_time(qapp: QApplication) -> None:
    """M36: the re-render slot fires on every theme change, not just once.

    Confirms the ``theme_changed`` connection is a durable subscription (not
    a one-shot) by switching dark -> light -> dark and checking the rendered
    color returns to the dark palette on the second switch, without any
    explicit call to ``set_frames`` after the first.

    Args:
        qapp: Session QApplication fixture; ``ThemeManager.apply_theme``
            requires a live ``QApplication`` instance to take effect.
    """
    del qapp
    table = StackFrameTable()
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        frame = StackFrame(index=1, return_address=0x1000, function_name="known_func", module_name="app.exe")
        table.set_frames([frame])

        func_item = table.item(0, 2)
        assert func_item is not None
        assert func_item.foreground().color() == QColor("#dcdcaa"), "dark function_known color expected before any switch"

        ThemeManager.get_instance().apply_theme(THEME_LIGHT)
        func_item_light = table.item(0, 2)
        assert func_item_light is not None
        assert func_item_light.foreground().color() == QColor("#795e26"), "light function_known color expected after first switch"

        ThemeManager.get_instance().apply_theme(THEME_DARK)
        func_item_dark_again = table.item(0, 2)
        assert func_item_dark_again is not None
        assert func_item_dark_again.foreground().color() == QColor("#dcdcaa"), (
            "dark function_known color must be restored on the second theme switch without a manual set_frames call"
        )
    finally:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        table.deleteLater()
