# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the main window filling available screen geometry.

``MainWindow._apply_smart_window_size`` must not hard-code ``max_w, max_h = 1400, 900``.
On a monitor larger than that, a window capped at 1400x900 cuts off the toolbar at
"Hex Edit...", pushes the Ghidra/Frida/Process/Sandbox buttons and the
Auto-approve/Sandbox/Cancel toggles off the right edge, and pushes the Analysis-Output
tab row and the Functions/Cross-References sidebar off-screen, with no scrollbar anywhere
to reach them. This test drives the real ``MainWindow`` construction path with a
monkeypatched large screen geometry and asserts the window is sized to that geometry
(minus the documented margin), not to a fixed cap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.app import MainWindow

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_LARGE_AVAIL_W: int = 2560
_LARGE_AVAIL_H: int = 1440
_MARGIN_W: int = 6
_MARGIN_H: int = 8
_OLD_CAP_W: int = 1400
_OLD_CAP_H: int = 900


@pytest.mark.usefixtures("qapp")
def test_smart_window_size_fills_large_screen_geometry(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 2560x1440 available screen must size the window to that geometry, not a fixed 1400x900 cap.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
        real_config: Real Config fixture (``ui.restore_layout`` defaults False,
            so no persisted geometry interferes with this computation).
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    monkeypatch.setattr(
        MainWindow,
        "_resolve_screen_geometry",
        staticmethod(lambda: (0, 0, _LARGE_AVAIL_W, _LARGE_AVAIL_H)),
    )

    window = MainWindow(real_config, real_orchestrator)
    try:
        expected_w = _LARGE_AVAIL_W - _MARGIN_W
        expected_h = _LARGE_AVAIL_H - _MARGIN_H
        assert window.width() == expected_w, (
            f"expected the window to fill the available {_LARGE_AVAIL_W}px-wide screen "
            f"({expected_w}px after margin); got {window.width()}px -- still clamped to the old 1400 cap?"
        )
        assert window.height() == expected_h, (
            f"expected the window to fill the available {_LARGE_AVAIL_H}px-tall screen "
            f"({expected_h}px after margin); got {window.height()}px -- still clamped to the old 900 cap?"
        )
        assert window.width() > _OLD_CAP_W, f"window width {window.width()}px did not exceed the removed 1400px cap"
        assert window.height() > _OLD_CAP_H, f"window height {window.height()}px did not exceed the removed 900px cap"
    finally:
        window.close()


@pytest.mark.usefixtures("qapp")
def test_smart_window_size_floors_at_splitter_minimum_on_tiny_screen(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A screen narrower than the splitter panes' combined minimum must still floor sanely.

    Confirms that removing the 1400x900 cap keeps the graceful minimum-width floor for small
    screens.

    Args:
        qapp: Shared QApplication fixture required for Qt widget construction.
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    monkeypatch.setattr(
        MainWindow,
        "_resolve_screen_geometry",
        staticmethod(lambda: (0, 0, 400, 300)),
    )

    window = MainWindow(real_config, real_orchestrator)
    try:
        combined_pane_minimum = window._chat_panel.minimumWidth() + window.tool_panel.minimumWidth()
        assert window.width() >= combined_pane_minimum, (
            f"window width {window.width()}px is narrower than the splitter panes' combined minimum width ({combined_pane_minimum}px)"
        )
    finally:
        window.close()
