# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S20-D14/S20-D16 (shell half): the Chat pane must collapse and restore.

Before the fix, the main splitter's ``setChildrenCollapsible(False)`` made
the Chat pane un-collapsible, so it permanently occupied its minimum width
even while empty, crushing every embedded tool panel into the remaining
splitter space with no way to reclaim that width (S20-D14/S20-D16). This
test drives the real ``MainWindow`` splitter and asserts that toggling the
Chat pane collapses it to zero width, hands that freed width to the tool
panel, and that toggling again restores a nonzero Chat width -- proving the
pane is genuinely recoverable, not a one-way collapse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.app import MainWindow

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_SPLITTER_PANE_COUNT: int = 2
_WINDOW_WIDTH: int = 1600
_WINDOW_HEIGHT: int = 900
_LAYOUT_SETTLE_PASSES: int = 8


def _settle_layout() -> None:
    """Pump the Qt event loop until a cascaded splitter/child resize has fully propagated.

    A single ``processEvents()`` call reliably applies :meth:`QSplitter.setSizes`
    but, on the offscreen platform with no real window manager driving paint/
    resize cycles, a child widget's own ``width()`` can still report its
    pre-toggle value for one or more additional event-loop turns. Repeating
    the pump a bounded number of times lets that cascade finish before an
    assertion reads real widget geometry.
    """
    for _ in range(_LAYOUT_SETTLE_PASSES):
        QApplication.processEvents()


@pytest.fixture
def shell_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real, shown ``MainWindow`` sized for splitter-width assertions.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A shown, fixed-size ``MainWindow`` instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    window.resize(_WINDOW_WIDTH, _WINDOW_HEIGHT)
    window.show()
    _settle_layout()
    yield window
    window.close()


def test_toggle_chat_panel_collapses_to_zero_and_frees_width_to_tool_panel(
    shell_window: MainWindow,
) -> None:
    """Collapsing the Chat pane must zero its width and grow the tool panel by the same amount.

    Args:
        shell_window: A real, shown ``MainWindow``.
    """
    window = shell_window
    initial_sizes = window._splitter.sizes()
    assert len(initial_sizes) == _SPLITTER_PANE_COUNT
    initial_chat_width = window._chat_panel.width()
    initial_tool_width = window.tool_panel.width()
    assert initial_chat_width > 0, "test premise: Chat pane starts expanded"

    window._on_toggle_chat_panel()
    _settle_layout()

    collapsed_sizes = window._splitter.sizes()
    assert collapsed_sizes[0] == 0, f"expected the Chat pane collapsed to width 0, got splitter sizes {collapsed_sizes}"
    assert window._chat_panel.width() == 0, f"expected Chat pane widget width 0, got {window._chat_panel.width()}"
    assert window.tool_panel.width() > initial_tool_width, (
        f"expected the tool panel to receive the Chat pane's freed width; "
        f"before={initial_tool_width}px, after={window.tool_panel.width()}px"
    )


def test_toggle_chat_panel_is_restorable_after_collapse(shell_window: MainWindow) -> None:
    """A second toggle after collapsing must restore a nonzero Chat pane width.

    A pane the user can collapse but never get back is a regression in its
    own right (D14/D16): this asserts the toggle is genuinely a two-way
    control, not a one-shot collapse.

    Args:
        shell_window: A real, shown ``MainWindow``.
    """
    window = shell_window
    window._on_toggle_chat_panel()
    _settle_layout()
    assert window._splitter.sizes()[0] == 0, "test premise: Chat pane is collapsed"

    window._on_toggle_chat_panel()
    _settle_layout()

    restored_sizes = window._splitter.sizes()
    assert restored_sizes[0] > 0, f"expected the Chat pane restored to a nonzero width after toggling again, got sizes {restored_sizes}"
    assert window._chat_panel.width() > 0, f"expected Chat pane widget width > 0 after restore, got {window._chat_panel.width()}"
