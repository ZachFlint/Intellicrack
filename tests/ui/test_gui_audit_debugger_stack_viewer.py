# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.stack_viewer`.

Finding M1: ``StackViewerPanel.refresh`` fetched stack frames with the
blocking ``run_bridge_coroutine`` helper while being driven from a 500ms
GUI-thread ``QTimer``. That blocked the Qt event loop on every tick. The fixed
panel dispatches the bridge round-trip through the off-GUI-thread async worker
``run_bridge_coroutine_logged`` and guards against overlapping refreshes.

These tests fail against the pre-fix code because the pre-fix ``refresh``
called the blocking helper and never touched the async worker.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels import stack_viewer
from intellicrack.ui.panels.stack_viewer import StackViewerPanel, X64DbgStackSource


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    from PyQt6.QtWidgets import QApplication


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _CoroStackSource(X64DbgStackSource):
    """Real stack source returning a genuine coroutine for dispatch tests.

    Subclasses the production x64dbg source so it is type-compatible with the
    panel's source registry while producing a real awaitable, letting the tests
    verify the panel's dispatch mechanism without a live debugger backend.
    """

    def __init__(self) -> None:
        """Initialise the coroutine-returning stack source."""
        super().__init__()
        self.coroutine_requested: bool = False

    def is_connected(self) -> bool:
        """Report the source as connected.

        Returns:
            bool: Always True so the refresh path proceeds to dispatch.
        """
        return True

    def get_stack_coroutine(self) -> Coroutine[object, object, object]:
        """Return a real coroutine and record that it was requested.

        Returns:
            Coroutine[object, object, object]: A real awaitable stack fetch.
        """
        self.coroutine_requested = True
        return self._real_stack()

    async def _real_stack(self) -> list[object]:
        """Produce a real (empty) raw stack response.

        Returns:
            list[object]: An empty raw stack list.
        """
        return []


@pytest.fixture
def panel(qapp: QApplication) -> Iterator[StackViewerPanel]:
    """Create a StackViewerPanel for GUI-audit tests.

    Args:
        qapp: Session QApplication fixture ensuring Qt is initialised.

    Yields:
        StackViewerPanel: A freshly constructed panel with a coroutine source.
    """
    del qapp
    widget = StackViewerPanel()
    yield widget
    widget.deleteLater()


def test_m1_refresh_dispatches_async_worker_not_blocking(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M1: refresh dispatches via the async worker, not the blocking helper.

    Pre-fix ``refresh`` called ``run_bridge_coroutine`` (blocking) on the GUI
    thread. Post-fix it calls ``run_bridge_coroutine_logged`` (off-thread).

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    logged_events: list[str] = []
    blocking_calls: list[object] = []

    def _fake_logged(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        **context: object,
    ) -> None:
        del on_success, on_error, parent, logger, context
        logged_events.append(event)
        coro.close()

    def _fake_blocking(coro: Coroutine[object, object, object], *args: object, **kwargs: object) -> None:
        del args, kwargs
        blocking_calls.append(coro)
        coro.close()

    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _fake_logged)
    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine", _fake_blocking)

    source = _CoroStackSource()
    panel.add_source("x64dbg", source)

    panel.refresh()

    assert logged_events == ["stack_refresh"], "refresh must dispatch through the async worker"
    assert not blocking_calls, "refresh must not call the blocking coroutine helper on the timer path"
    assert source.coroutine_requested is True, "refresh must request the source's stack coroutine"


def test_m1_overlapping_refresh_skipped_while_in_flight(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M1: a second refresh is skipped while one is already in flight.

    The fake worker never completes the in-flight call, so the second refresh
    must be skipped. Pre-fix there was no in-flight guard.

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    logged_events: list[str] = []

    def _fake_logged_no_complete(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        **context: object,
    ) -> None:
        del on_success, on_error, parent, logger, context
        logged_events.append(event)
        coro.close()

    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _fake_logged_no_complete)

    panel.add_source("x64dbg", _CoroStackSource())

    panel.refresh()
    panel.refresh()

    assert logged_events == ["stack_refresh"], "an overlapping refresh must be skipped while one is in flight"


def test_m1_refresh_redispatches_after_completion(panel: StackViewerPanel, monkeypatch: pytest.MonkeyPatch) -> None:
    """M1: refresh dispatches again once the previous round-trip completes.

    The fake worker invokes the success callback with a real empty raw stack,
    clearing the in-flight guard so the next refresh dispatches.

    Args:
        panel: The StackViewerPanel under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    logged_events: list[str] = []

    def _fake_logged_complete(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        **context: object,
    ) -> None:
        del on_error, parent, logger, context
        logged_events.append(event)
        coro.close()
        if on_success is not None:
            on_success([])

    monkeypatch.setattr(stack_viewer, "run_bridge_coroutine_logged", _fake_logged_complete)

    panel.add_source("x64dbg", _CoroStackSource())

    panel.refresh()
    panel.refresh()

    assert logged_events == ["stack_refresh", "stack_refresh"], "refresh must redispatch after the prior call completes"
