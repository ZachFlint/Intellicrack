# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Integration tests for the Log Viewer entry points on :class:`MainWindow`."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.app import MainWindow
from intellicrack.ui.log_viewer import LogViewerWindow, get_qt_log_handler
from tests.test_ui.conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


pytestmark = pytest.mark.usefixtures("qapp", "qsettings_tmp")


def _make_main_window(
    config: Config,
    orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> MainWindow:
    """Construct a :class:`MainWindow` with a no-op sandbox manager.

    Args:
        config: Application config.
        orchestrator: Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture used to replace the
            sandbox manager.

    Returns:
        MainWindow: The constructed window.
    """
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    return MainWindow(config, orchestrator)


def test_main_window_installs_qt_log_handler(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify constructing :class:`MainWindow` installs the Qt log handler.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _make_main_window(real_config, real_orchestrator, monkeypatch)
    try:
        assert get_qt_log_handler() is not None
    finally:
        window.close()


def test_log_viewer_lazy_construction(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the viewer is not built until ``open_log_viewer`` is called.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _make_main_window(real_config, real_orchestrator, monkeypatch)
    try:
        _assert_viewer_is_single_instance(window)
    finally:
        window.close()


def _assert_viewer_is_single_instance(window: MainWindow) -> None:
    """Assert ``open_log_viewer`` constructs once and reuses the instance.

    Args:
        window: The main window under test.
    """
    assert window.log_viewer_window is None
    window.open_log_viewer()
    first = window.log_viewer_window
    assert isinstance(first, LogViewerWindow)
    window.open_log_viewer()
    assert window.log_viewer_window is first


def test_main_window_close_disposes_viewer(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the viewer is closed when the main window closes.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _make_main_window(real_config, real_orchestrator, monkeypatch)
    window.open_log_viewer()
    viewer = window.log_viewer_window
    assert viewer is not None
    window.close()
    assert window.log_viewer_window is None
    assert not viewer.isVisible()
