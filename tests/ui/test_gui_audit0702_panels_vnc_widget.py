# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the 2026-07-02 GUI audit findings in ``vnc_widget``.

* **H12** — ``VNCWidget.disconnect_from_server`` used to call the *blocking*
  ``run_bridge_coroutine(self.client.disconnect())`` with no timeout on the Qt
  GUI thread. ``RFBClient.disconnect()`` awaits ``self._writer.wait_closed()``,
  which can hang indefinitely against an unresponsive peer (e.g. a paused or
  crashed QEMU sandbox), freezing the whole application. The fix dispatches the
  teardown through the non-blocking ``run_bridge_coroutine_logged`` async
  worker path instead, matching every sibling bridge call in this module, and
  removes the blocking ``run_bridge_coroutine`` import entirely.
* **L3** — ``VNCWidget`` never subscribed to ``ThemeManager.theme_changed``, so
  the idle "VNC Display" placeholder kept rendering with stale theme colors
  until some unrelated event (resize, tab switch) forced a repaint. The fix
  connects ``ThemeManager.theme_changed`` to a new ``_on_theme_changed`` slot
  that calls ``self.update()``.

Both tests drive a real :class:`VNCWidget` under an offscreen QApplication; no
part of the widget under test is mocked.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import intellicrack.ui.panels.vnc_widget as vnc_widget_mod
from intellicrack.ui.panels.vnc_widget import VNCWidget
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import pytest
    from PyQt6.QtWidgets import QApplication


def test_h12_blocking_run_bridge_coroutine_no_longer_imported() -> None:
    """H12: the blocking ``run_bridge_coroutine`` symbol must not be importable.

    Pre-fix, ``vnc_widget`` imported ``run_bridge_coroutine`` (the blocking
    variant) alongside ``run_bridge_coroutine_logged`` specifically so
    ``disconnect_from_server`` could call it directly. That import is removed
    entirely as part of the fix, so the symbol no longer exists in the
    module's namespace at all.
    """
    assert not hasattr(vnc_widget_mod, "run_bridge_coroutine"), (
        "vnc_widget must not import the blocking run_bridge_coroutine helper; "
        "disconnect_from_server previously called it directly on the GUI thread"
    )


def test_h12_disconnect_dispatches_via_async_logged_runner(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """H12: disconnect_from_server must hand the coroutine to the async-logged runner.

    Args:
        qapp: Session QApplication fixture (ensures a Qt app exists).
        monkeypatch: Fixture used to patch the async runner.
    """
    _ = qapp
    widget = VNCWidget()

    logged_calls: list[Coroutine[object, object, object]] = []

    def _fake_logged(
        coro: Coroutine[object, object, object],
        on_success: object,
        on_error: object,
        parent: object,
        **_kwargs: object,
    ) -> None:
        """Record the dispatched coroutine and close it without awaiting.

        Args:
            coro: Bridge coroutine that would run on the worker.
            on_success: Success callback (unused here).
            on_error: Error callback (unused here).
            parent: Qt parent (unused here).
            **_kwargs: Structured logging context (ignored).
        """
        _ = (on_success, on_error, parent)
        logged_calls.append(coro)
        coro.close()

    monkeypatch.setattr(vnc_widget_mod, "run_bridge_coroutine_logged", _fake_logged)

    statuses: list[bool] = []
    widget.connection_status_changed.connect(statuses.append)

    widget.disconnect_from_server()

    assert len(logged_calls) == 1, "disconnect_from_server did not dispatch exactly one coroutine via the async-logged runner"
    assert statuses == [False], "disconnect_from_server must still surface the disconnected state on the GUI thread"


def test_h12_disconnect_is_non_blocking_even_when_peer_hangs(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """H12: disconnect_from_server must return promptly even if the peer never closes.

    Replaces the real ``RFBClient`` instance's ``disconnect`` coroutine with a
    stand-in that sleeps for longer than the assertion threshold, emulating an
    unresponsive VNC peer whose TCP close handshake never completes (dead
    network, paused/crashed sandbox VM). The pre-fix implementation called the
    blocking ``run_bridge_coroutine`` with no timeout, so the calling (GUI)
    thread would block for the full sleep duration; the fix dispatches the
    coroutine onto a background worker thread and returns immediately.

    Args:
        qapp: Session QApplication fixture (ensures a Qt app exists).
        monkeypatch: Fixture used to replace the real client's ``disconnect`` coroutine.
    """
    widget = VNCWidget()
    hang_s = 2.5

    async def _hanging_disconnect() -> None:
        """Emulate an unresponsive peer whose TCP close never completes."""
        await asyncio.sleep(hang_s)

    monkeypatch.setattr(widget.client, "disconnect", _hanging_disconnect)

    try:
        start = time.monotonic()
        widget.disconnect_from_server()
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, (
            f"disconnect_from_server blocked the calling thread for {elapsed:.2f}s waiting on a hung peer; "
            "the socket teardown must be dispatched asynchronously, not awaited inline on the GUI thread"
        )

        drain_deadline = time.monotonic() + hang_s + 1.0
        while time.monotonic() < drain_deadline:
            qapp.processEvents()
            time.sleep(0.02)
    finally:
        widget.deleteLater()


def _restore_theme(original_theme: str) -> None:
    """Restore the shared ``ThemeManager`` singleton to a prior theme.

    Args:
        original_theme: The resolved theme name to reapply.
    """
    ThemeManager.get_instance().apply_theme(original_theme)


def test_l3_theme_changed_signal_triggers_idle_widget_repaint(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """L3: emitting ThemeManager.theme_changed must call update() on an idle widget.

    Directly emits the real ``ThemeManager.theme_changed`` bound signal (the
    exact signal ``apply_theme`` emits on every theme switch) and asserts the
    widget's own ``update()`` is invoked in response. Pre-fix, ``VNCWidget``
    never connected to this signal, so nothing would call ``update()`` here;
    the idle "VNC Display" placeholder would keep painting whatever colors
    were resolved the last time some unrelated event forced a repaint.

    Args:
        qapp: Session QApplication fixture (ensures a Qt app exists).
        monkeypatch: Fixture used to instrument the widget's ``update`` method.
    """
    _ = qapp
    original_theme = ThemeManager.get_instance().current_theme
    try:
        widget = VNCWidget()
        try:
            update_calls: list[None] = []
            original_update = widget.update

            def _tracking_update() -> None:
                """Record the call, then perform the real Qt repaint scheduling."""
                update_calls.append(None)
                original_update()

            monkeypatch.setattr(widget, "update", _tracking_update)

            ThemeManager.get_instance().theme_changed.emit(THEME_LIGHT)

            assert update_calls, "VNCWidget.update() was not called after ThemeManager.theme_changed fired"
        finally:
            widget.deleteLater()
    finally:
        _restore_theme(original_theme)


def test_l3_apply_theme_repaints_placeholder_without_external_trigger(qapp: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """L3: a real ``ThemeManager.apply_theme`` switch must repaint the idle placeholder.

    Exercises the full production entry point (``ThemeManager.apply_theme``,
    which every theme-toggle action in the application calls) rather than
    emitting the signal directly, proving the wiring holds end to end for a
    widget that is idle (never connected, no update timer running) and has
    received no other event such as a resize.

    Args:
        qapp: Session QApplication fixture (ensures a Qt app exists).
        monkeypatch: Fixture used to instrument the widget's ``update`` method.
    """
    _ = qapp
    original_theme = ThemeManager.get_instance().current_theme
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        widget = VNCWidget()
        try:
            assert not widget.update_timer.isActive(), "test premise: widget must be idle (never connected)"

            update_calls: list[None] = []
            original_update = widget.update

            def _tracking_update() -> None:
                """Record the call, then perform the real Qt repaint scheduling."""
                update_calls.append(None)
                original_update()

            monkeypatch.setattr(widget, "update", _tracking_update)

            ThemeManager.get_instance().apply_theme(THEME_LIGHT)

            assert update_calls, "idle VNCWidget placeholder was not repainted after apply_theme switched the active theme"
        finally:
            widget.deleteLater()
    finally:
        _restore_theme(original_theme)
