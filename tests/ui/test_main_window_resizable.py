# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate: the main window must be freely shrinkable, not pinned to launch size.

A ``QMainWindow`` can never shrink below its central layout's aggregate minimum
size. If any embedded child advertises an oversized ``minimumSizeHint`` the whole
window becomes un-shrinkable, which stops the user snapping Intellicrack to half
of the screen alongside another application. This module drives the real
``MainWindow`` and asserts it can actually be resized down to a half-screen
footprint on both axes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.app import MainWindow

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_TARGET_W = 760
_TARGET_H = 620


@pytest.fixture
def window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Build, show, and tear down a real MainWindow for resize testing.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A shown MainWindow.
    """
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    win = MainWindow(real_config, real_orchestrator)
    win.show()
    qapp.processEvents()
    try:
        yield win
    finally:
        win.close()
        qapp.processEvents()


def _diagnostic(window: MainWindow) -> str:
    """Summarise the min-size drivers of the window for a failure message.

    Args:
        window: The main window under inspection.

    Returns:
        str: A compact report of each region's minimum size hint.
    """
    central = window.centralWidget()
    tp = window.tool_panel
    splitter = tp.main_splitter
    left = splitter.widget(0)
    right = splitter.widget(1)

    def wh(widget: object) -> tuple[int, int] | None:
        hint = getattr(widget, "minimumSizeHint", None)
        if hint is None:
            return None
        size = hint()
        return (size.width(), size.height())

    tabs = [(tp.tab_widget.tabText(i), wh(tp.tab_widget.widget(i))) for i in range(tp.tab_widget.count())]
    return (
        f"actual={(window.width(), window.height())} "
        f"win_min={wh(window)} central_min={wh(central)} "
        f"chat_min={wh(window._chat_panel)} tool_min={wh(tp)} "
        f"tabw_min={wh(tp.tab_widget)} tabs={tabs} "
        f"left_min={wh(left)} right_min={wh(right)}"
    )


def test_main_window_can_shrink_to_half_screen(window: MainWindow, qapp: QApplication) -> None:
    """Requesting a tiny size must clamp the window to no larger than a half-screen footprint.

    The window is asked to shrink far below any plausible minimum; its resulting
    clamped size is the true floor imposed by the central layout. That floor must
    fit within a half-screen footprint so the user can snap Intellicrack beside
    another application.
    """
    window.resize(200, 200)
    qapp.processEvents()
    report = _diagnostic(window)
    assert window.width() <= _TARGET_W, f"width floor too large to snap to half-screen: {report}"
    assert window.height() <= _TARGET_H, f"height floor too large to snap to half-screen: {report}"
