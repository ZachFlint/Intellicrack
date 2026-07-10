# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Integration tests for the main window's overflow-aware toolbar.

Verifies that :class:`MainWindow` actually builds its toolbar from
:class:`OverflowToolBar` (not a plain ``QToolBar``) and that, when the window
is too narrow to show every control, the extension button's popup menu is
populated with proxy actions for the clipped toolbar items and that triggering
those proxies drives the underlying widgets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QToolButton

from intellicrack.ui.app import MainWindow
from intellicrack.ui.overflow_toolbar import OverflowToolBar

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_EXTENSION_BUTTON_OBJECT_NAME = "qt_toolbar_ext_button"


@pytest.fixture
def narrow_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Create a MainWindow narrow enough to force toolbar overflow.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance.
        real_orchestrator: Real Orchestrator instance.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Generator[MainWindow]: A shown MainWindow resized to clip its toolbar.
    """
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    window.resize(640, 600)
    window.show()
    qapp.processEvents()
    try:
        yield window
    finally:
        window.close()
        qapp.processEvents()


def _find_toolbar(window: MainWindow) -> OverflowToolBar:
    """Return the main window's overflow toolbar.

    Args:
        window: The main window under test.

    Returns:
        OverflowToolBar: The toolbar built by ``_setup_toolbar``.
    """
    toolbars = window.findChildren(OverflowToolBar)
    assert toolbars, "MainWindow does not use an OverflowToolBar for its main toolbar"
    return toolbars[0]


def test_main_window_uses_overflow_toolbar(narrow_window: MainWindow) -> None:
    """The main toolbar must be an :class:`OverflowToolBar`, not a plain ``QToolBar``.

    Args:
        narrow_window: A narrow, shown MainWindow fixture.
    """
    toolbar = _find_toolbar(narrow_window)
    assert isinstance(toolbar, OverflowToolBar)


def test_extension_button_hooked_in_app(narrow_window: MainWindow) -> None:
    """When the window is narrow, Qt creates the extension button and the toolbar hooks it.

    Args:
        narrow_window: A narrow, shown MainWindow fixture.
    """
    toolbar = _find_toolbar(narrow_window)
    candidates = toolbar.findChildren(QToolButton, _EXTENSION_BUTTON_OBJECT_NAME)
    assert candidates, "Qt did not create an extension button despite the narrow toolbar"
    assert toolbar.extension_button is candidates[0], "Extension button was not hooked by the toolbar"
    assert candidates[0].toolTip() == "Show hidden toolbar items"


def test_overflow_menu_populated_with_clipped_controls(
    qapp: QApplication,
    narrow_window: MainWindow,
) -> None:
    """The overflow menu must list proxy actions for the clipped toolbar controls.

    Args:
        qapp: QApplication instance required by Qt widgets.
        narrow_window: A narrow, shown MainWindow fixture.
    """
    toolbar = _find_toolbar(narrow_window)
    toolbar.populate_overflow_menu()
    qapp.processEvents()
    labels = [action.text() for action in toolbar.overflow_menu.actions() if action.text()]
    assert labels, "Overflow menu produced no actions"
    assert labels != ["(no hidden items)"], "Overflow menu reported nothing hidden on a deliberately narrow window"


def test_overflow_proxy_drives_underlying_button(
    qapp: QApplication,
    narrow_window: MainWindow,
) -> None:
    """Triggering a clipped tool's proxy action must invoke the real button's behavior.

    Locates a clipped, non-checkable tool button, records its ``clicked``
    signal, triggers the corresponding overflow proxy action, and asserts the
    underlying button fired exactly once.

    Args:
        qapp: QApplication instance required by Qt widgets.
        narrow_window: A narrow, shown MainWindow fixture.
    """
    toolbar = _find_toolbar(narrow_window)
    cancel_button = None
    for action in toolbar.actions():
        widget = toolbar.widgetForAction(action)
        if widget is not None and not widget.isVisible() and getattr(widget, "text", lambda: "")() == "Cancel":
            cancel_button = widget
            break
    assert cancel_button is not None, "Cancel button was not clipped; widen-test invariant broken"

    click_count = 0

    def _on_clicked() -> None:
        nonlocal click_count
        click_count += 1

    cancel_button.clicked.connect(_on_clicked)

    toolbar.populate_overflow_menu()
    proxy = next((a for a in toolbar.overflow_menu.actions() if a.text() == "Cancel"), None)
    assert proxy is not None, "Cancel proxy was not added to the overflow menu"
    proxy.trigger()
    qapp.processEvents()
    assert click_count == 1, f"Cancel proxy should have clicked the underlying button once, got {click_count}"
