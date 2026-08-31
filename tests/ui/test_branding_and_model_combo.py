# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for branding and the toolbar model-combo readability fix.

* **Branding** -- the splash title and the About dialog must read
  "Intellicrack"/"INTELLICRACK" (never the capital-C "IntelliCrack").
* **Model combo (prior UX #3 residual)** -- a long model id must remain
  readable: the collapsed field carries a full-id tooltip and the combo uses an
  adjust-to-contents size policy rather than a fixed width that truncates.

Tests drive the real ``MainWindow`` / splash module; the About dialog text is
captured (not silently suppressed) to avoid blocking the offscreen event loop.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QComboBox, QMessageBox

from intellicrack.ui.app import MainWindow
from intellicrack.ui.dialogs import splash_screen

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_LONG_MODEL_ID: str = "huggingface/some-really-long-org-name/instruct-model-v3.5-flash-preview-2026"


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


def test_splash_title_reads_intellicrack() -> None:
    """The splash title constant must be the all-caps "INTELLICRACK"."""
    assert splash_screen._TITLE_TEXT == "INTELLICRACK"
    assert "IntelliCrack" not in splash_screen._TITLE_TEXT


@pytest.mark.usefixtures("qapp")
def test_about_dialog_uses_correct_branding(main_window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
    """The About dialog title and body must use "Intellicrack", never "IntelliCrack".

    Args:
        main_window: Real MainWindow under test.
        monkeypatch: Pytest monkeypatch fixture.
    """
    captured: list[tuple[str, str]] = []

    def _capture_about(_parent: object, title: str, text: str) -> None:
        captured.append((title, text))

    monkeypatch.setattr(QMessageBox, "about", staticmethod(_capture_about))
    main_window._on_about()

    assert captured, "About dialog was never invoked"
    title, text = captured[0]
    assert "Intellicrack" in title
    assert "Intellicrack" in text
    assert "IntelliCrack" not in title, "About title regressed to capital-C IntelliCrack"
    assert "IntelliCrack" not in text, "About body regressed to capital-C IntelliCrack"


@pytest.mark.usefixtures("qapp")
def test_model_combo_tooltip_shows_full_id(main_window: MainWindow) -> None:
    """A long model id must surface in full via the combo tooltip.

    Args:
        main_window: Real MainWindow under test.
    """
    assert main_window.model_combo.sizeAdjustPolicy() == QComboBox.SizeAdjustPolicy.AdjustToContents
    main_window.model_combo.addItem(_LONG_MODEL_ID)
    main_window.model_combo.setCurrentText(_LONG_MODEL_ID)

    assert main_window.model_combo.toolTip() == _LONG_MODEL_ID, (
        "the collapsed model combo does not expose the full id via a tooltip (truncation regression)"
    )
