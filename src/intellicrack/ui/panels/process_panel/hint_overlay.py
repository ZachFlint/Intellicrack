# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Instructional overlay for gated process detail tabs.

Provides :class:`AttachHintOverlay`, a translucent panel shown on top of the Memory, Threads, Modules, and System tabs while the
ProcessPanel is not attached to a target process. It replaces the previously silent disabled tabs with a clear, always-legible instruction
telling the user to attach first.
"""

from __future__ import annotations

from typing import Final, override

from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


_OVERLAY_STYLE: Final[str] = (
    "#attach_hint_overlay{background-color:rgba(30,30,30,0.82);}"
    "#attach_hint_label{color:#d4d4d4;font-size:13px;font-weight:600;"
    "padding:16px 24px;border:1px solid #3e3e42;border-radius:6px;"
    "background-color:rgba(45,45,48,0.95);}"
)


class AttachHintOverlay(QWidget):
    """Translucent overlay directing the user to attach to a process.

    The overlay is parented to a detail tab and, when shown, covers the entire tab area with a centered message. Its stylesheet fixes the
    foreground and background colors so the text stays fully legible even while the parent tab is disabled. Geometry is kept in sync with
    the parent via an installed event filter so the overlay always fills the tab.
    """

    def __init__(self, parent: QWidget, message: str) -> None:
        """Initialize the overlay and bind it to its parent tab.

        Args:
            parent: The detail tab widget the overlay covers.
            message: Instructional text to display at the center of the tab.
        """
        super().__init__(parent)
        self.setObjectName("attach_hint_overlay")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, on=True)
        self.setStyleSheet(_OVERLAY_STYLE)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._label = QLabel(message)
        self._label.setObjectName("attach_hint_label")
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setWordWrap(True)
        layout.addWidget(self._label, alignment=Qt.AlignmentFlag.AlignCenter)

        parent.installEventFilter(self)
        self.setGeometry(parent.rect())
        self.raise_()

    def set_message(self, message: str) -> None:
        """Update the instructional text shown by the overlay.

        Args:
            message: New instructional text.
        """
        self._label.setText(message)

    @override
    def setVisible(self, visible: bool) -> None:
        """Show or hide the overlay, resyncing geometry and stacking on show.

        Args:
            visible: Whether the overlay should become visible.
        """
        if visible:
            parent = self.parentWidget()
            if parent is not None:
                self.setGeometry(parent.rect())
            self.raise_()
        super().setVisible(visible)

    @override
    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
        """Keep the overlay sized to its parent whenever the parent resizes.

        Args:
            a0: The watched object (the parent tab).
            a1: The intercepted event.

        Returns:
            bool: ``False`` so the event continues its normal processing.
        """
        if a1 is not None and a1.type() == QEvent.Type.Resize:
            parent = self.parentWidget()
            if parent is not None:
                self.setGeometry(parent.rect())
        return super().eventFilter(a0, a1)
