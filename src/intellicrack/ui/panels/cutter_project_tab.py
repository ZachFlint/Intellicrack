# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Project/session management tab for the Cutter/Rizin analysis panel.

Provides a self-contained Qt widget exposing rizin's native project persistence
commands (``Ps``/``Po``/``Pl``) via the ``CutterBridge`` project surface
(``cutter.py:3412-3468``), allowing the user to save the current analysis
session as a named project, reopen a previously saved project, and browse the
list of projects available to the currently loaded binary.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Final

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_NAME_INPUT_MAX_WIDTH: Final[int] = 220

RunAsyncFn = Callable[
    [Coroutine[object, object, object], Callable[[object], None] | None, Callable[[object], None] | None],
    None,
]


class ProjectTab(QWidget):
    """Tab exposing rizin project save/open/list session management.

    Provides a project-name input with Save/Open buttons, a Refresh button
    that lists all projects known to the currently loaded binary, and a
    list widget where double-clicking an entry opens that project, all
    driven by the ``CutterBridge`` project methods.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ProjectTab with name input, action buttons, and a project list.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        action_row = QHBoxLayout()
        name_label = QLabel(self.tr("Name:"))
        name_label.setFont(fm.get_ui_font(9))
        action_row.addWidget(name_label)

        self._name_input = QLineEdit()
        self._name_input.setMaximumWidth(_NAME_INPUT_MAX_WIDTH)
        self._name_input.setPlaceholderText("Project name...")
        self._name_input.returnPressed.connect(self._on_save)
        action_row.addWidget(self._name_input)

        self._save_btn = QPushButton(self.tr("Save"))
        self._save_btn.setObjectName("tool_button")
        self._save_btn.clicked.connect(self._on_save)
        action_row.addWidget(self._save_btn)

        self._open_btn = QPushButton(self.tr("Open"))
        self._open_btn.setObjectName("tool_button")
        self._open_btn.clicked.connect(self._on_open)
        action_row.addWidget(self._open_btn)

        self._refresh_btn = QPushButton(self.tr("Refresh"))
        self._refresh_btn.setObjectName("secondary_button")
        self._refresh_btn.clicked.connect(self._on_refresh)
        action_row.addWidget(self._refresh_btn)

        action_row.addStretch()
        layout.addLayout(action_row)

        self._status_label = QLabel(self.tr("No bridge configured"))
        self._status_label.setFont(fm.get_ui_font(9))
        layout.addWidget(self._status_label)

        self._project_list = QListWidget()
        self._project_list.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._project_list)

    def set_bridge(self, bridge: CutterBridge) -> None:
        """Set the CutterBridge instance used for project operations.

        Args:
            bridge: The CutterBridge to use.
        """
        self._bridge = bridge
        self._status_label.setText(self.tr("Ready"))

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh the project list from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for parity with sibling tabs.
        """
        self._bridge = bridge
        self._on_refresh()

    def _on_save(self) -> None:
        """Save the current analysis session under the name in the name input."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return

        name = self._name_input.text().strip()
        if not name:
            self._status_label.setText(self.tr("Enter a project name"))
            return

        self._save_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.save_project(name),
            on_success=lambda _: self._on_save_success(name),
            on_error=lambda exc: self._on_save_error(name, exc),
            parent=self,
            event="cutter_save_project",
            logger=_logger,
            level="info",
            project_name=name,
        )

    def _on_save_success(self, name: str) -> None:
        """Handle successful project save.

        Args:
            name: The project name that was saved.
        """
        self._status_label.setText(f"Saved project '{name}'")
        _logger.info("cutter_project_saved", project_name=name)
        self._save_btn.setEnabled(True)
        self._on_refresh()

    def _on_save_error(self, name: str, exc: object) -> None:
        """Handle project save failure.

        Args:
            name: The project name that failed to save.
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Save failed: {exc}")
        _logger.warning("cutter_project_save_failed", project_name=name, error=str(exc))
        self._save_btn.setEnabled(True)

    def _on_open(self) -> None:
        """Open the project named in the name input."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return

        name = self._name_input.text().strip()
        if not name:
            self._status_label.setText(self.tr("Enter a project name"))
            return

        self._open_project(name)

    def _open_project(self, name: str) -> None:
        """Open a named project via the bridge.

        Args:
            name: Project name to open.
        """
        if self._bridge is None:
            return

        self._open_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.open_project(name),
            on_success=lambda _: self._on_open_success(name),
            on_error=lambda exc: self._on_open_error(name, exc),
            parent=self,
            event="cutter_open_project",
            logger=_logger,
            level="info",
            project_name=name,
        )

    def _on_open_success(self, name: str) -> None:
        """Handle successful project open.

        Args:
            name: The project name that was opened.
        """
        self._status_label.setText(f"Opened project '{name}'")
        _logger.info("cutter_project_opened", project_name=name)
        self._open_btn.setEnabled(True)
        self._name_input.setText(name)

    def _on_open_error(self, name: str, exc: object) -> None:
        """Handle project open failure.

        Args:
            name: The project name that failed to open.
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Open failed: {exc}")
        _logger.warning("cutter_project_open_failed", project_name=name, error=str(exc))
        self._open_btn.setEnabled(True)

    def _on_refresh(self) -> None:
        """List available projects and populate the project list widget."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return

        self._refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.list_projects(),
            on_success=self._apply_projects,
            on_error=self._on_refresh_error,
            parent=self,
            event="cutter_list_projects",
            logger=_logger,
        )

    def _apply_projects(self, result: object) -> None:
        """Populate the project list widget with the result of ``list_projects``.

        Args:
            result: List of project name strings from the bridge.
        """
        names: list[object] = [*result] if isinstance(result, list) else []

        self._project_list.clear()
        for name in names:
            if isinstance(name, str) and name:
                self._project_list.addItem(QListWidgetItem(name))

        self._status_label.setText(f"{len(names)} project(s)")
        _logger.debug("cutter_projects_listed", count=len(names))
        self._refresh_btn.setEnabled(True)

    def _on_refresh_error(self, exc: object) -> None:
        """Handle project list refresh failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"List failed: {exc}")
        _logger.warning("cutter_list_projects_failed", error=str(exc))
        self._refresh_btn.setEnabled(True)

    def _on_item_double_clicked(self, item: QListWidgetItem) -> None:
        """Open the double-clicked project list entry.

        Args:
            item: The list widget item that was double-clicked.
        """
        name = item.text().strip()
        if not name:
            return
        self._name_input.setText(name)
        self._open_project(name)
