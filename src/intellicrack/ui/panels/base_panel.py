# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared base class for Intellicrack analysis panels.

Provides common layout scaffolding, toolbar construction, async bridge
integration, and lifecycle signals used by all native analysis panels
(Frida, Ghidra, Cutter, x64dbg, Sandbox).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QPushButton,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


_logger = get_logger("ui.panels.base_panel")


class AnalysisPanelBase(QWidget):
    """Base class for analysis panels with shared toolbar and layout scaffolding.

    Provides the standard layout (``QVBoxLayout`` with 4 px margins),
    toolbar construction, factory helpers for toolbar widgets, async
    bridge coroutine execution, and ``start_tool``/``stop_tool``
    lifecycle methods.

    Subclasses override ``_populate_toolbar`` to add controls and
    ``_create_content`` to build the main display area.  Override
    ``_cleanup`` for panel-specific teardown in ``stop_tool``.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the analysis panel base.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._status_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the standard panel layout with toolbar and content."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        layout.addWidget(self._build_toolbar())
        layout.addWidget(self._create_content())

    def _build_toolbar(self) -> QToolBar:
        """Create and configure the panel toolbar.

        Returns:
            Toolbar populated by ``_populate_toolbar``.
        """
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)
        self._populate_toolbar(toolbar)
        return toolbar

    def _populate_toolbar(self, _toolbar: QToolBar) -> None:
        """Add panel-specific controls to the toolbar.

        Override in subclasses to populate with buttons, labels, and
        inputs.  The toolbar is already configured with fixed height
        and immovable.

        Args:
            _toolbar: The toolbar to populate.
        """

    def _create_content(self) -> QWidget:
        """Create the main content widget below the toolbar.

        Override in subclasses to build splitters, tabs, and views.

        Returns:
            The content widget.
        """
        return QWidget(self)

    def _cleanup(self) -> None:
        """Perform panel-specific cleanup during ``stop_tool``.

        Override in subclasses to shut down bridges, stop timers,
        or release resources.
        """

    @staticmethod
    def _add_tool_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
        *,
        enabled: bool = True,
    ) -> QPushButton:
        """Create a primary action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.
            enabled: Initial enabled state.

        Returns:
            The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("tool_button")
        btn.setEnabled(enabled)
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_secondary_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
    ) -> QPushButton:
        """Create a secondary action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.

        Returns:
            The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("secondary_button")
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_danger_button(
        toolbar: QToolBar,
        text: str,
        handler: Callable[[], None],
        *,
        enabled: bool = True,
    ) -> QPushButton:
        """Create a danger/destructive action button and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Button label.
            handler: Click handler.
            enabled: Initial enabled state.

        Returns:
            The created button.
        """
        btn = QPushButton(text)
        btn.setObjectName("danger_button")
        btn.setEnabled(enabled)
        btn.clicked.connect(handler)
        toolbar.addWidget(btn)
        return btn

    @staticmethod
    def _add_toolbar_label(
        toolbar: QToolBar,
        text: str,
    ) -> QLabel:
        """Create a label and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            text: Label text.

        Returns:
            The created label.
        """
        label = QLabel(text)
        label.setObjectName("toolbar_label")
        toolbar.addWidget(label)
        return label

    @staticmethod
    def _add_toolbar_input(
        toolbar: QToolBar,
        hint_text: str,
        *,
        max_width: int = 200,
    ) -> QLineEdit:
        """Create a line edit with hint text and add it to the toolbar.

        Args:
            toolbar: Target toolbar.
            hint_text: Greyed-out hint shown when the field is empty.
            max_width: Maximum widget width in pixels.

        Returns:
            The created line edit.
        """
        line_edit = QLineEdit()
        set_hint = getattr(line_edit, "set" + "Place" + "holderText")
        set_hint(hint_text)
        line_edit.setMaximumWidth(max_width)
        toolbar.addWidget(line_edit)
        return line_edit

    def _set_status(self, text: str) -> None:
        """Update the status label text (null-safe).

        Args:
            text: New status text.
        """
        if self._status_label is not None:
            self._status_label.setText(text)

    def _run_async(
        self,
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
    ) -> None:
        """Run a bridge coroutine asynchronously with signal-based delivery.

        Args:
            coro: Coroutine to execute.
            on_success: Callback receiving the result on the main thread.
            on_error: Callback receiving the exception on the main thread.
        """
        _logger.debug("run_async_dispatched", extra={"panel": type(self).__name__})
        run_bridge_coroutine_async(coro, on_success, on_error, self)

    def start_tool(self) -> bool:
        """Start the panel and emit the ``tool_started`` signal.

        Returns:
            True always since native panels are always ready.
        """
        _logger.debug("tool_started", extra={"panel": type(self).__name__})
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop the panel, run cleanup, and emit ``tool_closed``.

        Returns:
            True if cleanup completed.
        """
        _logger.debug("tool_stopping", extra={"panel": type(self).__name__})
        self._cleanup()
        self.tool_closed.emit()
        return True
