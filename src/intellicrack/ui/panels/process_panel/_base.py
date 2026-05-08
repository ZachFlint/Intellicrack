# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Main ProcessPanel widget composing all tab modules.

Assembles the five top-level tabs (Processes, Memory, Threads, Modules, System), manages the status bar, bridge lifecycle, and attachment
state machine.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.process_panel._memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel._modules_tab import ModulesTab
from intellicrack.ui.panels.process_panel._process_tab import ProcessTab
from intellicrack.ui.panels.process_panel._system_tab import SystemTab
from intellicrack.ui.panels.process_panel._threads_tab import ThreadsTab


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QToolBar

    from intellicrack.bridges.process import ProcessBridge

_logger = get_logger(__name__)

_MARGIN: Final[int] = 4
_SPACING: Final[int] = 4
_STATUS_HEIGHT: Final[int] = 24


class _PanelState(enum.Enum):
    """Process panel attachment state."""

    DISCONNECTED = "disconnected"
    DETACHED = "detached"
    ATTACHED = "attached"


class ProcessPanel(AnalysisPanelBase):
    """Unified process management panel with bridge integration.

    Provides five top-level tabs covering all ProcessBridge capabilities,
    with a persistent status bar showing attachment state, PID, architecture,
    privilege status, and bridge connection.

    Attributes:
        process_selected: Signal emitted with PID when a process row is selected.
        process_attached: Signal emitted with PID when a process is attached.
        process_detached: Signal emitted when a process is detached.
    """

    process_selected: pyqtSignal = pyqtSignal(int)
    process_attached: pyqtSignal = pyqtSignal(int)
    process_detached: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ProcessPanel.

        Args:
            parent: Parent widget.
        """
        self._bridge: ProcessBridge | None = None
        self._state = _PanelState.DISCONNECTED
        self._attached_pid: int | None = None
        self._detail_tabs: list[QWidget] = []
        super().__init__(parent)

    def set_bridge(self, bridge: ProcessBridge) -> None:
        """Set the process bridge for all tabs.

        Args:
            bridge: ProcessBridge instance.
        """
        self._bridge = bridge
        self._process_tab.set_bridge(bridge)
        self._memory_tab.set_bridge(bridge)
        self._threads_tab.set_bridge(bridge)
        self._modules_tab.set_bridge(bridge)
        self._system_tab.set_bridge(bridge)
        self._state = _PanelState.DETACHED
        self._update_controls_for_state()
        _logger.info("process_bridge_set", bridge_type=type(bridge).__name__)

    def get_bridge(self) -> ProcessBridge | None:
        """Get the current bridge.

        Returns:
            ProcessBridge | None: The bridge or None.
        """
        return self._bridge

    def get_selected_pid(self) -> int | None:
        """Get the currently selected PID from the process tab.

        Returns:
            int | None: Selected PID or None.
        """
        return self._process_tab.get_selected_pid()

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add panel-level controls to the main toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self.status_label = self._add_toolbar_label(toolbar, "Process Panel")

    @override
    def _create_content(self) -> QWidget:
        """Create the main content with 5-tab layout and status bar.

        Returns:
            QWidget: Content widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(_SPACING)

        self._tab_widget = QTabWidget()

        self._process_tab = ProcessTab()
        self._process_tab.process_selected.connect(self._on_process_selected)
        self._process_tab.process_attached.connect(self._on_process_attached)
        self._process_tab.process_detached.connect(self._on_process_detached)
        self._tab_widget.addTab(self._process_tab, "Processes")

        self._memory_tab = MemoryTab()
        self._tab_widget.addTab(self._memory_tab, "Memory")

        self._threads_tab = ThreadsTab()
        self._tab_widget.addTab(self._threads_tab, "Threads")

        self._modules_tab = ModulesTab()
        self._tab_widget.addTab(self._modules_tab, "Modules")

        self._system_tab = SystemTab()
        self._tab_widget.addTab(self._system_tab, "System")
        self._threads_tab.attach_system_tab(self._system_tab)

        self._detail_tabs = [
            self._memory_tab,
            self._threads_tab,
            self._modules_tab,
            self._system_tab,
        ]

        layout.addWidget(self._tab_widget)

        self._status_bar = self._build_status_bar()
        layout.addWidget(self._status_bar)

        self._update_controls_for_state()

        return container

    def _build_status_bar(self) -> QFrame:
        """Build the persistent status bar at the bottom.

        Returns:
            QFrame: Status bar frame.
        """
        bar = QFrame()
        bar.setFixedHeight(_STATUS_HEIGHT)
        bar.setObjectName("status_bar")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(_MARGIN, 0, _MARGIN, 0)
        bar_layout.setSpacing(12)

        self._status_state = QLabel("Detached")
        self._status_state.setObjectName("toolbar_label")
        bar_layout.addWidget(self._status_state)

        self._status_pid = QLabel("PID: --")
        self._status_pid.setObjectName("toolbar_label")
        bar_layout.addWidget(self._status_pid)

        self._status_arch = QLabel("Arch: --")
        self._status_arch.setObjectName("toolbar_label")
        bar_layout.addWidget(self._status_arch)

        self._status_priv = QLabel("Privilege: Standard")
        self._status_priv.setObjectName("toolbar_label")
        bar_layout.addWidget(self._status_priv)

        self._status_bridge = QLabel("Bridge: Disconnected")
        self._status_bridge.setObjectName("toolbar_label")
        bar_layout.addWidget(self._status_bridge)

        bar_layout.addStretch()
        return bar

    def _on_process_selected(self, pid: int) -> None:
        """Handle process selection from the process tab.

        Args:
            pid: Selected process ID.
        """
        self.process_selected.emit(pid)

    def _on_process_attached(self, pid: int) -> None:
        """Handle successful process attachment.

        Args:
            pid: Attached process ID.
        """
        self._attached_pid = pid
        self._state = _PanelState.ATTACHED

        self._memory_tab.set_attached_pid(pid)
        self._threads_tab.set_attached_pid(pid)
        self._modules_tab.set_attached_pid(pid)
        self._system_tab.set_attached_pid(pid)

        self._update_controls_for_state()
        self._status_pid.setText(f"PID: {pid}")
        self.process_attached.emit(pid)
        self.tool_started.emit()
        _logger.info("panel_process_attached", pid=pid)

    def _on_process_detached(self) -> None:
        """Handle process detachment."""
        self._attached_pid = None
        self._state = _PanelState.DETACHED

        self._memory_tab.set_attached_pid(None)
        self._threads_tab.set_attached_pid(None)
        self._modules_tab.set_attached_pid(None)
        self._system_tab.set_attached_pid(None)

        self._update_controls_for_state()
        self._status_pid.setText("PID: --")
        self._status_arch.setText("Arch: --")
        self.process_detached.emit()
        _logger.info("panel_process_detached")

    def _update_controls_for_state(self) -> None:
        """Enable/disable tab widgets based on panel state."""
        if self._state == _PanelState.DISCONNECTED:
            self._status_state.setText("Disconnected")
            self._status_bridge.setText("Bridge: Disconnected")
            for tab in self._detail_tabs:
                tab.setEnabled(False)
        elif self._state == _PanelState.DETACHED:
            self._status_state.setText("Detached")
            self._status_bridge.setText("Bridge: Connected")
            for tab in self._detail_tabs:
                tab.setEnabled(False)
        elif self._state == _PanelState.ATTACHED:
            self._status_state.setText("Attached")
            self._status_bridge.setText("Bridge: Connected")
            for tab in self._detail_tabs:
                tab.setEnabled(True)

        if self._bridge is not None:
            debug_priv = getattr(self._bridge, "_debug_privilege_enabled", False)
            self._status_priv.setText(f"Privilege: {'Debug' if debug_priv else 'Standard'}")

    @override
    def _cleanup(self) -> None:
        """Stop timers and cancel pending workers."""
        self._process_tab.cleanup()

    @override
    def start_tool(self) -> bool:
        """Start the process panel and trigger initial refresh.

        Returns:
            bool: True always.
        """
        self._process_tab.start_refresh()
        self.tool_started.emit()
        return True

    @override
    def stop_tool(self) -> bool:
        """Stop the process panel.

        Returns:
            bool: True if cleanup succeeded.
        """
        self._cleanup()
        self.tool_closed.emit()
        return True
