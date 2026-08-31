# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S13-D07 -- Load Binary dialog abnormally short.

``MainWindow._on_load_binary`` used to call the static
``QFileDialog.getOpenFileName`` convenience function, which opens the native
OS dialog. Native dialogs cannot be resized programmatically, and on this
platform the resulting dialog rendered abnormally short with the OK/Cancel
buttons and the filter combo clipped off the bottom.

The fix constructs a real ``QFileDialog`` instance with
``QFileDialog.Option.DontUseNativeDialog`` set and a sane minimum size before
calling ``exec()``. These tests drive the real ``_on_load_binary`` method (not
a reimplementation), monkeypatching only ``QFileDialog.exec`` so no modal
event loop actually blocks the test process, and capture the constructed
dialog instance to assert on its configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
import structlog.testing
from PyQt6.QtWidgets import QDialog, QFileDialog

from intellicrack.ui.app import MainWindow

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_MIN_HEIGHT_FLOOR: int = 600
_MIN_WIDTH_FLOOR: int = 900


@pytest.fixture
def main_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real, unshown ``MainWindow`` with a no-op sandbox manager.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance from the shared fixtures.
        real_orchestrator: Real Orchestrator instance from the shared fixtures.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed, unshown MainWindow instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


def _patch_exec_capture_and_reject(monkeypatch: pytest.MonkeyPatch, captured: list[QFileDialog]) -> None:
    """Patch ``QFileDialog.exec`` to record the instance and reject without a modal loop.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to install the patch.
        captured: List the constructed ``QFileDialog`` instance is appended to.
    """

    def _fake_exec(dialog_self: QFileDialog) -> int:
        captured.append(dialog_self)
        return QDialog.DialogCode.Rejected.value

    monkeypatch.setattr(QFileDialog, "exec", _fake_exec)


def _patch_exec_capture_and_accept(monkeypatch: pytest.MonkeyPatch, captured: list[QFileDialog], selected_path: str) -> None:
    """Patch ``QFileDialog.exec`` to record the instance and accept with a fixed selection.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to install the patch.
        captured: List the constructed ``QFileDialog`` instance is appended to.
        selected_path: Path string returned from ``selectedFiles()``.
    """

    def _fake_exec(dialog_self: QFileDialog) -> int:
        captured.append(dialog_self)
        return QDialog.DialogCode.Accepted.value

    def _fake_selected_files(dialog_self: QFileDialog) -> list[str]:
        del dialog_self
        return [selected_path]

    monkeypatch.setattr(QFileDialog, "exec", _fake_exec)
    monkeypatch.setattr(QFileDialog, "selectedFiles", _fake_selected_files)


@pytest.mark.usefixtures("qapp")
class TestLoadBinaryDialogMinSize:
    """S13-D07: the Load Binary dialog must be a sized non-native instance."""

    @staticmethod
    def test_dialog_is_non_native_with_min_size_floor(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The constructed dialog must disable the native backend and set a floor size.

        Args:
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured: list[QFileDialog] = []
        _patch_exec_capture_and_reject(monkeypatch, captured)

        main_window._on_load_binary()

        assert len(captured) == 1, "QFileDialog.exec was not invoked exactly once"
        dialog = captured[0]
        assert dialog.testOption(QFileDialog.Option.DontUseNativeDialog), (
            "DontUseNativeDialog option was not set -- dialog would use the native backend"
        )
        assert dialog.minimumHeight() >= _MIN_HEIGHT_FLOOR, (
            f"minimumHeight() {dialog.minimumHeight()} is below the {_MIN_HEIGHT_FLOOR}px floor"
        )
        assert dialog.minimumWidth() >= _MIN_WIDTH_FLOOR, f"minimumWidth() {dialog.minimumWidth()} is below the {_MIN_WIDTH_FLOOR}px floor"
        dialog.deleteLater()

    @staticmethod
    def test_dialog_preserves_caption_filter_and_mode(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The dialog must keep the original caption, filter string, and single-file mode.

        Args:
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured: list[QFileDialog] = []
        _patch_exec_capture_and_reject(monkeypatch, captured)

        main_window._on_load_binary()

        dialog = captured[0]
        assert dialog.windowTitle() == "Load Binary"
        assert dialog.fileMode() == QFileDialog.FileMode.ExistingFile
        combined_filters = ";;".join(dialog.nameFilters())
        assert "*.exe" in combined_filters
        assert "*.dll" in combined_filters
        assert "*.so" in combined_filters
        assert "*.dylib" in combined_filters
        assert "All Files" in combined_filters
        dialog.deleteLater()

    @staticmethod
    def test_cancel_logs_and_skips_load(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Rejecting the dialog must log the cancellation and never call ``_load_binary``.

        Args:
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        captured: list[QFileDialog] = []
        _patch_exec_capture_and_reject(monkeypatch, captured)
        loaded: list[Path] = []
        monkeypatch.setattr(main_window, "_load_binary", loaded.append)

        with structlog.testing.capture_logs() as logs:
            main_window._on_load_binary()

        assert loaded == []
        events = [entry["event"] for entry in logs]
        assert "load_binary_dialog_opened" in events
        assert "load_binary_dialog_cancelled" in events
        assert "load_binary_dialog_selection" not in events
        captured[0].deleteLater()

    @staticmethod
    def test_accept_logs_selection_and_calls_load_binary(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Accepting the dialog must log the selection and call ``_load_binary`` with it.

        Args:
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Pytest temporary directory fixture used to build a fake path.
        """
        selected = tmp_path / "sample.exe"
        captured: list[QFileDialog] = []
        _patch_exec_capture_and_accept(monkeypatch, captured, str(selected))
        loaded: list[Path] = []
        monkeypatch.setattr(main_window, "_load_binary", loaded.append)

        with structlog.testing.capture_logs() as logs:
            main_window._on_load_binary()

        assert loaded == [selected]
        events = [entry["event"] for entry in logs]
        assert "load_binary_dialog_opened" in events
        assert "load_binary_dialog_selection" in events
        assert "load_binary_dialog_cancelled" not in events
        captured[0].deleteLater()
