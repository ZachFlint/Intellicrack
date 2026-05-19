# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Overflow-aware QToolBar for Intellicrack's main toolbar.

Qt's stock :class:`QToolBar` exposes a built-in extension arrow when items
exceed the visible width, but the popup menu it shows only renders text/icons
for plain :class:`QAction` entries. Items added through ``addWidget()`` are
backed by ``QWidgetAction`` instances whose default widgets cannot be
reparented into a :class:`QMenu`, so the popup ends up empty or collapsed to a
few pixels. In Intellicrack the entire Tools row is composed of
:class:`QPushButton` widgets, which is why the user-visible arrow does nothing
useful on overflow.

This module ships :class:`OverflowToolBar`, a drop-in :class:`QToolBar`
replacement that detects Qt's internal extension button, replaces its click
behavior, and shows a properly populated menu where each entry proxies clicks
back to the underlying widget (or to the original :class:`QAction` when no
widget proxy is needed).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from PyQt6.QtCore import QEvent, QObject, QPoint, Qt
from PyQt6.QtGui import QAction, QKeyEvent
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QLabel,
    QMenu,
    QPushButton,
    QToolBar,
    QToolButton,
    QWidget,
)

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from PyQt6.QtGui import QActionEvent, QResizeEvent


_ACTIVATION_KEYS: frozenset[int] = frozenset(
    {
        int(Qt.Key.Key_Space),
        int(Qt.Key.Key_Return),
        int(Qt.Key.Key_Enter),
    },
)


_logger = get_logger(__name__)


_EXTENSION_BUTTON_OBJECT_NAME = "qt_toolbar_ext_button"


class OverflowToolBar(QToolBar):
    """:class:`QToolBar` that exposes hidden widget actions through a popup.

    The toolbar installs itself onto Qt's extension button once it is created
    by the layout, disconnects Qt's default extension-popup slot, and replaces
    it with a custom :class:`QMenu` populated on demand. Each menu entry
    proxies activation back to the corresponding clipped widget (or directly
    triggers the underlying :class:`QAction` for non-widget actions), so users
    can reach every Tools-row button even when the window is too narrow to
    display all of them.
    """

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        """Initialize the overflow-aware toolbar.

        Args:
            title: Human-readable title for the toolbar (used by Qt for
                accessibility and dock-area context menus).
            parent: Parent widget for ownership, or ``None`` for a top-level
                attachment via :meth:`QMainWindow.addToolBar`.
        """
        super().__init__(title, parent)
        self._overflow_menu: QMenu = QMenu(self)
        self._overflow_menu.aboutToShow.connect(self._populate_overflow_menu)
        self._ext_button: QToolButton | None = None
        self._hooked: bool = False

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Hook Qt's extension button once it has been created by the layout.

        Args:
            a0: The resize event delivered by Qt.
        """
        super().resizeEvent(a0)
        self._hook_extension_button()

    @override
    def actionEvent(self, event: QActionEvent | None) -> None:
        """Re-attempt the extension hook after action changes.

        Args:
            event: Action event delivered by Qt when an action is added,
                removed, or modified.
        """
        super().actionEvent(event)
        self._hook_extension_button()

    @override
    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
        """Block accidental key activation that bypasses the replaced click slot.

        Args:
            a0: The watched object.
            a1: The intercepted event.

        Returns:
            bool: ``True`` if the event was consumed; otherwise the result of
            the superclass filter.
        """
        if a0 is None or a0 is not self._ext_button or a1 is None:
            return super().eventFilter(a0, a1)
        if a1.type() != QEvent.Type.KeyPress or not isinstance(a1, QKeyEvent):
            return super().eventFilter(a0, a1)
        if a1.key() not in _ACTIVATION_KEYS:
            return super().eventFilter(a0, a1)
        self._show_overflow_menu()
        return True

    def _hook_extension_button(self) -> None:
        """Locate and rewire Qt's extension button when it becomes available."""
        if self._hooked:
            return
        candidates = self.findChildren(QToolButton, _EXTENSION_BUTTON_OBJECT_NAME)
        if not candidates:
            return
        button = candidates[0]
        try:
            button.clicked.disconnect()
        except TypeError:
            _logger.debug("overflow_toolbar_no_existing_clicked_connections")
        button.clicked.connect(self._show_overflow_menu)
        button.installEventFilter(self)
        button.setToolTip("Show hidden toolbar items")
        self._ext_button = button
        self._hooked = True
        _logger.debug("overflow_toolbar_extension_button_hooked")

    def _show_overflow_menu(self) -> None:
        """Pop up the overflow menu beneath Qt's extension button."""
        button = self._ext_button
        if button is None:
            return
        anchor = button.mapToGlobal(button.rect().bottomLeft())
        self._overflow_menu.exec(anchor)

    def _populate_overflow_menu(self) -> None:
        """Rebuild the overflow menu from the toolbar's currently clipped items."""
        self._overflow_menu.clear()
        added_any = False
        for action in self.actions():
            if action.isSeparator():
                continue
            widget = self.widgetForAction(action)
            if widget is None:
                if not action.isVisible() and action.text():
                    self._overflow_menu.addAction(action)
                    added_any = True
                continue
            if widget.isVisible():
                continue
            if self._add_proxy_action(widget, action):
                added_any = True
        if not added_any:
            empty_notice = QAction("(no hidden items)", self._overflow_menu)
            empty_notice.setEnabled(False)
            self._overflow_menu.addAction(empty_notice)

    def _add_proxy_action(self, widget: QWidget, original: QAction) -> bool:
        """Create a proxy :class:`QAction` for a clipped widget.

        Args:
            widget: The clipped widget whose interaction should be exposed in
                the overflow menu.
            original: The :class:`QAction` that the toolbar associates with
                ``widget`` (used as a fallback source of text).

        Returns:
            bool: ``True`` when a proxy action was added to the menu;
            ``False`` when the widget has no actionable representation (for
            example, plain labels).
        """
        if isinstance(widget, QLabel):
            return False
        text = self._widget_text(widget, original)
        if not text:
            return False
        proxy = QAction(text, self._overflow_menu)
        tooltip = widget.toolTip()
        if tooltip:
            proxy.setToolTip(tooltip)
        proxy.setEnabled(widget.isEnabled())
        self._wire_proxy(proxy, widget)
        self._overflow_menu.addAction(proxy)
        return True

    @staticmethod
    def _widget_text(widget: QWidget, original: QAction) -> str:
        """Resolve the best human-readable label for a clipped widget.

        Args:
            widget: The clipped widget.
            original: The :class:`QAction` Qt associated with the widget.

        Returns:
            str: The label text to use for the proxy action.
        """
        if isinstance(widget, QPushButton):
            return widget.text() or original.text()
        if isinstance(widget, QComboBox):
            current = widget.currentText()
            return current or original.text() or widget.objectName() or "Combo"
        return original.text() or widget.objectName()

    def _wire_proxy(self, proxy: QAction, widget: QWidget) -> None:
        """Connect a proxy :class:`QAction` to the behavior of its source widget.

        Args:
            proxy: The proxy action displayed inside the overflow menu.
            widget: The source widget whose interaction the proxy should
                drive.
        """
        if isinstance(widget, QPushButton):
            if widget.isCheckable():
                proxy.setCheckable(True)
                proxy.setChecked(widget.isChecked())
                proxy.toggled.connect(widget.setChecked)
            else:
                proxy.triggered.connect(lambda *_args: widget.click())
        elif isinstance(widget, QComboBox):
            combo = widget

            def _combo_proxy_clicked(*_args: object) -> None:
                """Close the overflow menu and display the combo popup at a safe anchor."""
                self._overflow_menu.close()
                pos = combo.mapToGlobal(QPoint(0, combo.height()))
                screen = QApplication.screenAt(pos)
                if screen is not None:
                    rect = screen.availableGeometry()
                    pos = QPoint(
                        min(pos.x(), rect.right() - combo.width()),
                        min(pos.y(), rect.bottom() - 200),
                    )
                combo.showPopup()

            proxy.triggered.connect(_combo_proxy_clicked)
