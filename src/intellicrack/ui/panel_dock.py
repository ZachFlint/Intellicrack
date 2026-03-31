# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Detachable panel window for floating tool panels.

Provides a QMainWindow wrapper that hosts a panel widget detached from the main ToolOutputPanel tab container, allowing panels to float
independently, be moved to secondary monitors, and be re-docked back into the tab bar.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QByteArray, QSettings, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow,
    QPushButton,
    QToolBar,
    QWidget,
)

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent


_logger = get_logger("ui.panel_dock")

_TOOLBAR_HEIGHT: Final[int] = 32
_DEFAULT_DOCK_WIDTH: Final[int] = 800
_DEFAULT_DOCK_HEIGHT: Final[int] = 600


class DetachedPanelWindow(QMainWindow):
    """
    Floating window wrapper for a detached tool panel.

    Hosts a single panel widget as its central widget with a
    toolbar containing a re-dock button. Emitting
    ``reattach_requested`` returns the panel to the tab bar
    instead of destroying it on close.

    Args:
        panel: The panel widget to host.
        title: Window title and tab label for re-docking.
        parent: Parent widget.

    Attributes:
        reattach_requested: Signal emitted with (panel, title) when
            the user requests re-docking.
    """

    reattach_requested: pyqtSignal = pyqtSignal(QWidget, str)

    def __init__(
        self,
        panel: QWidget,
        title: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._panel: QWidget = panel
        self._title: str = title
        self._settings_key: str = f"DetachedPanel/{title.replace(' ', '_')}"

        self.setWindowTitle(f"Intellicrack - {title}")
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, on=False)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)
        self.addToolBar(toolbar)

        redock_btn = QPushButton("Re-dock")
        redock_btn.setObjectName("secondary_button")
        redock_btn.setToolTip("Return this panel to the main window tab bar")
        redock_btn.clicked.connect(self._on_redock)
        toolbar.addWidget(redock_btn)

        self.setCentralWidget(panel)
        self.resize(_DEFAULT_DOCK_WIDTH, _DEFAULT_DOCK_HEIGHT)
        self._restore_geometry()

    @property
    def panel(self) -> QWidget:
        """
        Get the hosted panel widget.

        Returns:
            QWidget: The panel widget.
        """
        return self._panel

    @property
    def panel_title(self) -> str:
        """
        Get the tab title for re-docking.

        Returns:
            str: The original tab title.
        """
        return self._title

    def _on_redock(self) -> None:
        """Handle re-dock button click."""
        self._save_geometry()
        self.reattach_requested.emit(self._panel, self._title)

    def _save_geometry(self) -> None:
        """Persist this window's geometry to QSettings."""
        settings = QSettings("Intellicrack", "DetachedPanels")
        settings.setValue(f"{self._settings_key}/geometry", self.saveGeometry())

    def _restore_geometry(self) -> None:
        """Restore this window's geometry from QSettings."""
        settings = QSettings("Intellicrack", "DetachedPanels")
        geometry = settings.value(f"{self._settings_key}/geometry")
        if isinstance(geometry, QByteArray):
            self.restoreGeometry(geometry)

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """
        Emit reattach signal instead of destroying the panel.

        Args:
            a0: The close event.
        """
        self._save_geometry()
        self.reattach_requested.emit(self._panel, self._title)
        if a0 is not None:
            a0.ignore()
