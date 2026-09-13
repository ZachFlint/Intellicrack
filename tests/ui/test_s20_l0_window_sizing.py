# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S20-D15: the main window must fill available screen geometry.

Before the fix, ``MainWindow._apply_smart_window_size`` hard-coded
``max_w, max_h = 1400, 900`` so on any monitor larger than that the window
opened cropped to 1400x900: the toolbar was cut off at "Hex Edit...", the
Ghidra/Frida/Process/Sandbox buttons and the Auto-approve/Sandbox/Cancel
toggles fell off the right edge, the Analysis-Output tab row and the entire
Functions/Cross-References sidebar were pushed off-screen, and there was no
scrollbar anywhere to reach them (S20-D15). This test drives the real
``MainWindow`` construction path with a monkeypatched large screen geometry
and asserts the window is sized to that geometry (minus the documented
margin), not the old fixed cap.
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
    """A 2560x1440 available screen must size the window to that geometry, not the old 1400x900 cap.

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

    Confirms the fix to remove the 1400x900 cap did not also remove the
    graceful minimum-width floor for small screens.

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
