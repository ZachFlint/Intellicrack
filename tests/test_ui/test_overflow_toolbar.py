# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for OverflowToolBar.

Verifies that Intellicrack's overflow-aware QToolBar replaces Qt's broken
built-in extension menu with a populated dropdown when the toolbar is
narrower than its actions require.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication, QComboBox, QLabel, QMainWindow, QPushButton, QToolButton

from intellicrack.ui.overflow_toolbar import OverflowToolBar


if TYPE_CHECKING:
    from collections.abc import Generator


_EXTENSION_BUTTON_OBJECT_NAME = "qt_toolbar_ext_button"


@pytest.fixture
def toolbar_window(qapp: QApplication) -> Generator[tuple[QMainWindow, OverflowToolBar]]:
    """Build a QMainWindow with an OverflowToolBar narrow enough to force overflow.

    Args:
        qapp: Session-scoped QApplication fixture.

    Yields:
        tuple[QMainWindow, OverflowToolBar]: The window and its toolbar with a row of
        QPushButton widgets exceeding the visible width.
    """
    window = QMainWindow()
    window.resize(320, 60)
    toolbar = OverflowToolBar("Main Toolbar")
    toolbar.setMovable(False)
    window.addToolBar(toolbar)
    provider_label = QLabel("Provider:")
    toolbar.addWidget(provider_label)
    provider_combo = QComboBox()
    provider_combo.addItems(["Anthropic", "OpenAI", "Local"])
    provider_combo.setMinimumWidth(120)
    toolbar.addWidget(provider_combo)
    for label in ("x64dbg", "Cutter", "HxD", "Hex Editor", "Ghidra", "Frida", "Process", "Sandbox"):
        btn = QPushButton(label)
        btn.setMinimumWidth(80)
        toolbar.addWidget(btn)
    window.show()
    qapp.processEvents()
    try:
        yield window, toolbar
    finally:
        window.close()
        qapp.processEvents()


def _find_extension_button(toolbar: OverflowToolBar) -> QToolButton:
    """Locate Qt's built-in extension button on the toolbar.

    Args:
        toolbar: The toolbar under test.

    Returns:
        QToolButton: Qt's extension button instance.
    """
    candidates = toolbar.findChildren(QToolButton, _EXTENSION_BUTTON_OBJECT_NAME)
    assert candidates, "Qt did not create the extension button on the toolbar"
    return cast(QToolButton, candidates[0])


def test_extension_button_is_hooked(
    toolbar_window: tuple[QMainWindow, OverflowToolBar],
) -> None:
    """The toolbar must locate Qt's extension button and install its hooks on it.

    Qt's :class:`QToolBarLayout` re-attaches its own internal menu to the
    extension button after every relayout, so the OverflowToolBar relies on
    its installed event filter (not on the button's ``menu()`` returning the
    overflow menu) to intercept activation. This test verifies the hook is
    in place: the toolbar has resolved the extension button, the button uses
    ``InstantPopup`` mode (the configuration our filter targets), and Qt's
    custom tooltip from the hook is present.

    Args:
        toolbar_window: The window/toolbar fixture.
    """
    _window, toolbar = toolbar_window
    ext = _find_extension_button(toolbar)
    assert toolbar.extension_button is ext, "Extension button not registered on toolbar"
    assert ext.popupMode() == QToolButton.ToolButtonPopupMode.InstantPopup
    assert ext.toolTip() == "Show hidden toolbar items"


def test_mouse_press_opens_overflow_menu_with_clipped_buttons(
    qapp: QApplication,
    toolbar_window: tuple[QMainWindow, OverflowToolBar],
) -> None:
    """A left-button press on the extension button must populate and open the overflow menu.

    Args:
        qapp: Session-scoped QApplication fixture.
        toolbar_window: The window/toolbar fixture.
    """
    _window, toolbar = toolbar_window
    ext = _find_extension_button(toolbar)
    menu = toolbar.overflow_menu
    captured_labels: list[str] = []

    def _on_about_to_show() -> None:
        captured_labels.extend(action.text() for action in menu.actions() if action.text() and action.text() != "(no hidden items)")

    menu.aboutToShow.connect(_on_about_to_show)
    press_local = QPoint(ext.width() // 2, ext.height() // 2)
    press_global = ext.mapToGlobal(press_local)
    press = QMouseEvent(
        QEvent.Type.MouseButtonPress,
        QPointF(press_local),
        QPointF(press_global),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    QApplication.sendEvent(ext, press)
    qapp.processEvents()
    menu.hide()
    qapp.processEvents()
    assert captured_labels, "Overflow menu did not open or had no actionable items"
    assert "Sandbox" in captured_labels or "Process" in captured_labels


def test_proxy_action_click_drives_underlying_button(
    qapp: QApplication,
    toolbar_window: tuple[QMainWindow, OverflowToolBar],
) -> None:
    """Triggering a proxy action in the overflow menu must click the underlying QPushButton.

    Args:
        qapp: Session-scoped QApplication fixture.
        toolbar_window: The window/toolbar fixture.
    """
    _window, toolbar = toolbar_window
    target_button: QPushButton | None = None
    for action in toolbar.actions():
        widget = toolbar.widgetForAction(action)
        if isinstance(widget, QPushButton) and widget.text() == "Sandbox":
            target_button = widget
            break
    assert target_button is not None, "Sandbox button was not found on the toolbar"
    click_count = 0

    def _on_clicked() -> None:
        nonlocal click_count
        click_count += 1

    target_button.clicked.connect(_on_clicked)

    toolbar.populate_overflow_menu()
    proxy = None
    for action in toolbar.overflow_menu.actions():
        if action.text() == "Sandbox":
            proxy = action
            break
    assert proxy is not None, "Sandbox proxy was not added to the overflow menu"
    proxy.trigger()
    qapp.processEvents()
    assert click_count == 1, f"Underlying Sandbox button should have been clicked once, got {click_count}"


def test_empty_notice_when_nothing_overflows(qapp: QApplication) -> None:
    """A wide toolbar with no overflow should populate the menu with the empty notice.

    Args:
        qapp: Session-scoped QApplication fixture.
    """
    window = QMainWindow()
    window.resize(1600, 60)
    toolbar = OverflowToolBar("Main Toolbar")
    window.addToolBar(toolbar)
    btn = QPushButton("Only")
    toolbar.addWidget(btn)
    window.show()
    qapp.processEvents()
    toolbar.populate_overflow_menu()
    texts = [a.text() for a in toolbar.overflow_menu.actions()]
    assert texts == ["(no hidden items)"]
    window.close()
    qapp.processEvents()
