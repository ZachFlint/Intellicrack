# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Integration tests for the Log Viewer entry points on :class:`MainWindow`."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import get_stdlib_root_logger
from intellicrack.ui.app import MainWindow
from intellicrack.ui.log_viewer import LogViewerWindow, QtSignalingHandler, get_qt_log_handler
from tests.ui.conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


pytestmark = pytest.mark.usefixtures("qapp", "qsettings_tmp")


def _make_main_window(
    config: Config,
    orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> MainWindow:
    """Construct a :class:`MainWindow` with a no-op sandbox manager and tab-state restore suppressed.

    The :class:`MainWindow` constructor calls ``_restore_window_state`` which
    attempts to reopen previously-saved tabs.  In the test environment those
    tabs require bridges (e.g. ``HexEditorBridge``) that are not registered in
    the minimal orchestrator, causing a :class:`ToolError`.  Patching
    ``_restore_window_state`` to a no-op avoids this side-effect while leaving
    all other construction logic -- including ``install_qt_log_handler`` --
    intact.

    Args:
        config: Application config.
        orchestrator: Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture used to replace the
            sandbox manager and suppress tab-state restore.

    Returns:
        MainWindow: The constructed window.
    """
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    monkeypatch.setattr(MainWindow, "_restore_window_state", lambda _self: None)
    return MainWindow(config, orchestrator)


def _assert_handler_wired(handler: QtSignalingHandler) -> None:
    """Assert the handler is in the root logger and receives real log records.

    Args:
        handler: The installed :class:`QtSignalingHandler` to verify.
    """
    root = get_stdlib_root_logger()
    assert handler in root.handlers, "QtSignalingHandler must be attached to the stdlib root logger so it receives all records"

    received: list[object] = []

    def _append_record(rec: object) -> None:
        received.append(rec)

    handler.bridge.record_received.connect(_append_record)
    test_logger = logging.getLogger("intellicrack.test_app_integration_probe")
    test_logger.warning("__test_handler_wiring_probe__")
    assert received, "at least one record must have reached the handler after root-logger emission"
    messages = [str(r) for r in received]
    assert any("__test_handler_wiring_probe__" in msg for msg in messages), (
        "the specific test probe message must appear in the handler's received records"
    )


def test_main_window_installs_qt_log_handler(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify constructing :class:`MainWindow` wires the Qt log handler to the root logger.

    The handler must be a :class:`QtSignalingHandler` instance that is present
    in the stdlib root logger's handler list.  A test log record emitted after
    construction must be received by the handler's ``record_received`` signal,
    proving the handler is live and connected, not merely installed as a no-op.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _make_main_window(real_config, real_orchestrator, monkeypatch)
    try:
        handler = get_qt_log_handler()
        assert handler is not None, "MainWindow.__init__ must install the Qt log handler"
        assert isinstance(handler, QtSignalingHandler), f"installed handler must be QtSignalingHandler, got {type(handler).__name__}"
        _assert_handler_wired(handler)
    finally:
        window.close()


def _assert_viewer_lazy_and_visible(window: MainWindow) -> None:
    """Assert the log viewer is absent before first call, visible after, and reused on repeat calls.

    Args:
        window: :class:`MainWindow` under test.
    """
    assert window.log_viewer_window is None, "viewer must not exist before open_log_viewer() is called"
    window.open_log_viewer()
    first = window.log_viewer_window
    assert isinstance(first, LogViewerWindow), f"open_log_viewer must create a LogViewerWindow; got {type(first).__name__}"
    assert first.isVisible(), "LogViewerWindow must be visible immediately after open_log_viewer()"
    window.open_log_viewer()
    assert window.log_viewer_window is first, "second open_log_viewer() call must return the same cached instance, not a new window"


def test_log_viewer_lazy_construction(
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify the viewer is built lazily, is visible after construction, and is reused on repeat calls.

    The viewer must be ``None`` before the first ``open_log_viewer`` call.  After the
    call the window must be a visible :class:`LogViewerWindow` instance.  A second
    ``open_log_viewer`` must return the same object (reference identity), proving the
    implementation caches and reuses rather than creating a fresh instance each time.

    Args:
        real_config: Real Config fixture.
        real_orchestrator: Real Orchestrator fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    window = _make_main_window(real_config, real_orchestrator, monkeypatch)
    try:
        _assert_viewer_lazy_and_visible(window)
    finally:
        window.close()


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
