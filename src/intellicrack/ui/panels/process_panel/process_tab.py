# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Process listing and management tab for the ProcessPanel.

Provides system process browsing, attachment, termination, and tracked process views with full bridge delegation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtCore import QModelIndex, QPoint, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager
from intellicrack.ui.panels.async_bridge import drain_bridge_workers_for, run_bridge_coroutine_logged
from intellicrack.ui.panels.process_panel.workers import TrackedRefreshWorker
from intellicrack.ui.panels.qt_compat import set_sorting_enabled


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge

_logger = get_logger(__name__)

_MARGIN: Final[int] = 0
_SPACING: Final[int] = 4
_TOOLBAR_HEIGHT: Final[int] = 32
_SEARCH_MAX_WIDTH: Final[int] = 250
_SPLIT_LEFT: Final[int] = 500
_SPLIT_RIGHT: Final[int] = 300
_SPLIT_MIN_HEIGHT: Final[int] = 80
_FILTER_DEBOUNCE_MS: Final[int] = 200

_PROC_COLUMNS: Final[list[str]] = ["PID", "Name", "Parent PID", "Architecture", "Memory (MB)", "Threads"]
_COL_PID: Final[int] = 0
_COL_NAME: Final[int] = 1
_COL_PPID: Final[int] = 2
_COL_ARCH: Final[int] = 3
_COL_MEM: Final[int] = 4
_COL_THREADS: Final[int] = 5

_TRACKED_COLUMNS: Final[list[str]] = ["PID", "Name", "Type", "Status", "Registered At"]
_TR_COL_PID: Final[int] = 0
_TR_COL_NAME: Final[int] = 1
_TR_COL_TYPE: Final[int] = 2
_TR_COL_STATUS: Final[int] = 3
_TR_COL_REG: Final[int] = 4


class ProcessTab(QWidget):
    """Tab for browsing, attaching, and managing system processes.

    Provides sub-tabs for system process list, tracked processes,
    and per-process info with environment variables.

    Attributes:
        process_selected: Signal emitted with PID when a process row is selected.
        process_attached: Signal emitted with PID when a process is attached.
        process_detached: Signal emitted when a process is detached.
    """

    process_selected: pyqtSignal = pyqtSignal(int)
    process_attached: pyqtSignal = pyqtSignal(int)
    process_detached: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ProcessTab.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: ProcessBridge | None = None
        self._selected_pid: int | None = None
        self._attached_pid: int | None = None
        self._tracked_worker: TrackedRefreshWorker | None = None
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.timeout.connect(self._on_refresh)
        self._tracked_timer = QTimer(self)
        self._tracked_timer.timeout.connect(self._refresh_tracked)
        self._filter_debounce_timer = QTimer(self)
        self._filter_debounce_timer.setSingleShot(True)
        self._filter_debounce_timer.timeout.connect(self._on_refresh)
        self._filter_refresh_pending: bool = False
        self._filter_refresh_in_flight: bool = False
        self._attached_dialog: QMessageBox | None = None
        self._setup_ui()

    def set_bridge(self, bridge: ProcessBridge) -> None:
        """Set the process bridge instance.

        Args:
            bridge: ProcessBridge for operations.
        """
        self._bridge = bridge

    def get_bridge(self) -> ProcessBridge | None:
        """Get the current bridge instance.

        Returns:
            ProcessBridge | None: The bridge or None.
        """
        return self._bridge

    def get_selected_pid(self) -> int | None:
        """Get the currently selected process ID.

        Returns:
            int | None: Selected PID or None.
        """
        return self._selected_pid

    def _setup_ui(self) -> None:
        """Build the tab layout with sub-tabs."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        self._tabs = QTabWidget()

        self._tabs.addTab(self._build_system_tab(), "System Processes")
        self._tabs.addTab(self._build_tracked_tab(), "Tracked")
        self._tabs.addTab(self._build_info_tab(), "Process Info")
        self._tabs.currentChanged.connect(self._on_tab_changed)

        layout.addWidget(self._tabs)

    def _build_system_tab(self) -> QWidget:
        """Build the system process list sub-tab.

        Returns:
            QWidget: The system processes tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter by name or PID...")
        self._search_input.setMaximumWidth(_SEARCH_MAX_WIDTH)
        self._search_input.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._search_input)
        toolbar.addSeparator()

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.setObjectName("tool_button")
        self._refresh_btn.clicked.connect(self._on_refresh)
        toolbar.addWidget(self._refresh_btn)

        self._auto_refresh_btn = QPushButton("Auto-Refresh: OFF")
        self._auto_refresh_btn.setCheckable(True)
        self._auto_refresh_btn.setObjectName("toggle_button")

        def _auto_slot(c: int) -> None:
            """Start or stop system-process auto-refresh from the toolbar toggle.

            Args:
                c: Qt ``toggled`` payload; nonzero enables periodic process refresh.
            """
            self._on_auto_refresh_toggled(checked=bool(c))

        self._auto_refresh_btn.toggled.connect(_auto_slot)
        toolbar.addWidget(self._auto_refresh_btn)
        toolbar.addSeparator()

        self._attach_btn = QPushButton("Attach")
        self._attach_btn.setObjectName("tool_button")
        self._attach_btn.clicked.connect(self._on_attach)
        toolbar.addWidget(self._attach_btn)

        self._detach_btn = QPushButton("Detach")
        self._detach_btn.setObjectName("tool_button")
        self._detach_btn.clicked.connect(self._on_detach)
        toolbar.addWidget(self._detach_btn)

        self._suspend_btn = QPushButton("Suspend")
        self._suspend_btn.setObjectName("tool_button")
        self._suspend_btn.clicked.connect(self._on_suspend)
        toolbar.addWidget(self._suspend_btn)

        self._resume_btn = QPushButton("Resume")
        self._resume_btn.setObjectName("tool_button")
        self._resume_btn.clicked.connect(self._on_resume)
        toolbar.addWidget(self._resume_btn)

        self._terminate_btn = QPushButton("Terminate")
        self._terminate_btn.setObjectName("danger_button")
        self._terminate_btn.clicked.connect(self._on_terminate)
        toolbar.addWidget(self._terminate_btn)

        self._inject_btn = QPushButton("DLL Inject")
        self._inject_btn.setObjectName("danger_button")
        self._inject_btn.clicked.connect(self._on_inject_dll)
        toolbar.addWidget(self._inject_btn)
        toolbar.addSeparator()

        self._proc_count_label = QLabel("0 processes")
        self._proc_count_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._proc_count_label)

        tab_layout.addWidget(toolbar)

        self._process_table = QTableWidget(0, len(_PROC_COLUMNS))
        self._process_table.setHorizontalHeaderLabels(_PROC_COLUMNS)
        self._process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._process_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._process_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        set_sorting_enabled(self._process_table, enable=True)
        sel = self._process_table.selectionModel()
        if sel is not None:
            sel.currentChanged.connect(self._on_selection_changed)
        self._process_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._process_table.customContextMenuRequested.connect(self._on_process_context_menu)
        proc_h = self._process_table.horizontalHeader()
        if proc_h is not None:
            proc_h.setSectionResizeMode(_COL_NAME, QHeaderView.ResizeMode.Stretch)

        tab_layout.addWidget(self._process_table)
        return tab

    def _build_tracked_tab(self) -> QWidget:
        """Build the tracked processes sub-tab.

        Returns:
            QWidget: The tracked processes widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        self._tracked_refresh_btn = QPushButton("Refresh")
        self._tracked_refresh_btn.setObjectName("tool_button")
        self._tracked_refresh_btn.clicked.connect(self._refresh_tracked)
        toolbar.addWidget(self._tracked_refresh_btn)

        self._tracked_auto_btn = QPushButton("Auto-Refresh: OFF")
        self._tracked_auto_btn.setCheckable(True)
        self._tracked_auto_btn.setObjectName("toggle_button")

        def _tracked_auto_slot(c: int) -> None:
            """Start or stop tracked-process auto-refresh from its toolbar toggle.

            Args:
                c: Qt ``toggled`` payload; nonzero enables periodic tracked refresh.
            """
            self._on_tracked_auto_toggled(checked=bool(c))

        self._tracked_auto_btn.toggled.connect(_tracked_auto_slot)
        toolbar.addWidget(self._tracked_auto_btn)
        toolbar.addSeparator()

        self._tracked_count_label = QLabel("0 tracked")
        self._tracked_count_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._tracked_count_label)

        tab_layout.addWidget(toolbar)

        self._tracked_table = QTableWidget(0, len(_TRACKED_COLUMNS))
        self._tracked_table.setHorizontalHeaderLabels(_TRACKED_COLUMNS)
        self._tracked_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tracked_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._tracked_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        set_sorting_enabled(self._tracked_table, enable=True)
        th = self._tracked_table.horizontalHeader()
        if th is not None:
            th.setSectionResizeMode(_TR_COL_NAME, QHeaderView.ResizeMode.Stretch)

        tab_layout.addWidget(self._tracked_table)
        return tab

    def _build_info_tab(self) -> QWidget:
        """Build the process info sub-tab.

        Returns:
            QWidget: The process info widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        tab_layout.setSpacing(_SPACING)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        self._info_tree = QTreeWidget()
        self._info_tree.setHeaderLabels(["Field", "Value"])
        self._info_tree.setMinimumHeight(_SPLIT_MIN_HEIGHT)
        info_h = self._info_tree.header()
        if info_h is not None:
            info_h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            info_h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self._info_tree)

        env_widget = QWidget()
        env_widget.setMinimumHeight(_SPLIT_MIN_HEIGHT)
        env_layout = QVBoxLayout(env_widget)
        env_layout.setContentsMargins(0, 0, 0, 0)
        env_layout.addWidget(QLabel("Environment Variables"))

        self._env_table = QTableWidget(0, 2)
        self._env_table.setHorizontalHeaderLabels(["Variable", "Value"])
        self._env_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._env_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        env_h = self._env_table.horizontalHeader()
        if env_h is not None:
            env_h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        env_layout.addWidget(self._env_table)
        splitter.addWidget(env_widget)

        splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        tab_layout.addWidget(splitter)
        return tab

    def _on_refresh(self) -> None:
        """Refresh the system process list via bridge."""
        if self._bridge is None:
            return

        self._filter_refresh_in_flight = True
        self._filter_refresh_pending = False
        self._refresh_btn.setEnabled(False)
        self._refresh_btn.setText("Refreshing...")
        current_filter = self._search_input.text().strip() or None

        def _on_success(result: object) -> None:
            """Repopulate the process table and re-arm a pending filter refresh.

            Args:
                result: Detailed process entry list from ``list_processes_detailed``.
            """
            self._filter_refresh_in_flight = False
            self._refresh_btn.setEnabled(True)
            self._refresh_btn.setText("Refresh")
            if not isinstance(result, list):
                if self._filter_refresh_pending:
                    self._filter_debounce_timer.start(_FILTER_DEBOUNCE_MS)
                return
            self._populate_process_table(cast("list[object]", result))
            if self._filter_refresh_pending:
                self._filter_debounce_timer.start(_FILTER_DEBOUNCE_MS)

        def _on_error(exc: object) -> None:
            """Restore the Refresh button and re-arm a pending filter on failure.

            Args:
                exc: Exception raised while calling ``list_processes_detailed``.
            """
            self._filter_refresh_in_flight = False
            self._refresh_btn.setEnabled(True)
            self._refresh_btn.setText("Refresh")
            _logger.warning("process_refresh_failed", error=str(exc))
            if self._filter_refresh_pending:
                self._filter_debounce_timer.start(_FILTER_DEBOUNCE_MS)

        run_bridge_coroutine_logged(
            self._bridge.list_processes_detailed(current_filter),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_list_processes_detailed",
            logger=_logger,
            filter=current_filter,
        )

    def _populate_process_table(self, processes: list[object]) -> None:
        """Populate the process table from bridge results.

        Args:
            processes: List of process detail dicts from the bridge.
        """
        set_sorting_enabled(self._process_table, enable=False)
        self._process_table.setRowCount(0)

        for proc in processes:
            if not isinstance(proc, dict):
                continue
            typed_proc = cast("dict[str, object]", proc)
            row = self._process_table.rowCount()
            self._process_table.insertRow(row)

            pid_raw = typed_proc.get("pid", 0)
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, pid_raw if isinstance(pid_raw, int) else 0)
            self._process_table.setItem(row, _COL_PID, pid_item)

            self._process_table.setItem(row, _COL_NAME, QTableWidgetItem(str(typed_proc.get("name", ""))))

            ppid_raw = typed_proc.get("parent_pid", 0)
            ppid_item = QTableWidgetItem()
            ppid_item.setData(Qt.ItemDataRole.DisplayRole, ppid_raw if isinstance(ppid_raw, int) else 0)
            self._process_table.setItem(row, _COL_PPID, ppid_item)

            self._process_table.setItem(
                row,
                _COL_ARCH,
                QTableWidgetItem(str(typed_proc.get("architecture", "Unknown"))),
            )

            mem_raw = typed_proc.get("memory_mb", 0.0)
            mem_item = QTableWidgetItem()
            mem_item.setData(
                Qt.ItemDataRole.DisplayRole,
                mem_raw if isinstance(mem_raw, (int, float)) else 0.0,
            )
            self._process_table.setItem(row, _COL_MEM, mem_item)

            tc_raw = typed_proc.get("thread_count", 0)
            tc_item = QTableWidgetItem()
            tc_item.setData(Qt.ItemDataRole.DisplayRole, tc_raw if isinstance(tc_raw, int) else 0)
            self._process_table.setItem(row, _COL_THREADS, tc_item)

        set_sorting_enabled(self._process_table, enable=True)
        self._proc_count_label.setText(f"{len(processes)} processes")

    def _on_filter_changed(self, _text: str) -> None:
        """Handle search filter changes with trailing-edge debounce.

        Cancels any pending debounce timer and re-arms it. If a bridge refresh
        is already in flight, marks the pending flag so the new filter fires
        immediately after the in-flight refresh completes.

        Args:
            _text: New filter text.
        """
        if self._filter_refresh_in_flight:
            self._filter_refresh_pending = True
            return
        self._filter_debounce_timer.stop()
        self._filter_debounce_timer.start(_FILTER_DEBOUNCE_MS)

    def _on_auto_refresh_toggled(self, *, checked: bool) -> None:
        """Toggle automatic process list refresh.

        Args:
            checked: Whether auto-refresh is enabled.
        """
        if checked:
            self._auto_refresh_btn.setText("Auto-Refresh: ON")
            self._auto_refresh_timer.start(3000)
        else:
            self._auto_refresh_btn.setText("Auto-Refresh: OFF")
            self._auto_refresh_timer.stop()

    def _on_selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        """Handle process table row selection.

        Args:
            current: New selection index.
            _previous: Previous selection index.
        """
        row = current.row()
        if row < 0:
            return
        pid_item = self._process_table.item(row, _COL_PID)
        if pid_item is None:
            return
        pid = int(pid_item.data(Qt.ItemDataRole.DisplayRole))
        self._selected_pid = pid
        self.process_selected.emit(pid)
        self._load_process_info(pid)

    def _on_process_context_menu(self, pos: QPoint) -> None:
        """Show a context menu with a Track This Process action for the system-process table.

        Args:
            pos: Position where the right-click occurred, in table viewport coordinates.
        """
        item = self._process_table.itemAt(pos)
        if item is None:
            return
        row = item.row()
        self._process_table.setCurrentCell(row, _COL_PID)

        pid_item = self._process_table.item(row, _COL_PID)
        if pid_item is None:
            return
        pid = int(pid_item.data(Qt.ItemDataRole.DisplayRole))
        name_item = self._process_table.item(row, _COL_NAME)
        name = name_item.text() if name_item is not None else f"PID-{pid}"

        menu = QMenu(self)
        track_action = menu.addAction(self.tr("Track This Process"))
        if track_action is None:
            return

        chosen = menu.exec(self._process_table.mapToGlobal(pos))
        if chosen is track_action:
            self._on_track_process(pid, name)

    def _on_track_process(self, pid: int, name: str) -> None:
        """Register a system process with ProcessManager and show it in the Tracked tab.

        Args:
            pid: Process ID to register via ``ProcessManager.register_external_pid``.
            name: Human-readable process name shown in the Tracked tab.
        """
        manager = ProcessManager.get_instance()
        try:
            manager.register_external_pid(pid, name)
        except ValueError as exc:
            _logger.warning("process_track_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Track Failed", f"Failed to track PID {pid}:\n{exc}")
            return

        _logger.info("process_tracked_from_panel", pid=pid, process_name=name)
        self._tabs.setCurrentIndex(1)
        self._refresh_tracked()

    def _on_attach(self) -> None:
        """Attach to the selected process via bridge."""
        if self._selected_pid is None or self._bridge is None:
            return

        pid = self._selected_pid

        def _on_success(result: object) -> None:
            """Record the attached PID, schedule auto-populate, and show a non-blocking confirmation.

            ``process_attached`` is emitted before the confirmation dialog is shown, so the auto-populate it triggers in sibling tabs
            (region/module/thread enumeration, dispatched through the existing bridge worker off the UI thread) is scheduled immediately
            instead of waiting for the dialog to be dismissed. The confirmation itself is shown non-modally so its OK/close controls stay
            responsive immediately, regardless of how long that background work takes to finish.

            Args:
                result: Open-process payload from ``open_process``; may include
                    a process ``name`` field for the confirmation dialog.
            """
            name: str = ""
            if isinstance(result, dict):
                name_val = cast("dict[str, object]", result).get("name", "")
                name = str(name_val) if name_val else ""
            self._attached_pid = pid
            label = f"Attached to PID {pid}" + (f" ({name})" if name else "")
            _logger.info("process_attached", pid=pid, process_name=name)
            self.process_attached.emit(pid)
            self._show_attached_confirmation(label)

        def _on_error(exc: object) -> None:
            """Log ``process_attach_failed`` and show Attach Failed with the target PID.

            Args:
                exc: Failure from ``open_process`` for the process selected in the table.
            """
            _logger.warning("process_attach_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Attach Failed", f"Failed to attach to PID {pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.open_process(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_open_process",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _show_attached_confirmation(self, label: str) -> None:
        """Show a non-modal "Attached" confirmation that never blocks the UI thread.

        Uses a non-modal ``QMessageBox`` instead of the blocking ``QMessageBox.information`` convenience function, so OK/close remain
        responsive immediately no matter how long the post-attach auto-populate work triggered alongside it takes to finish. The instance is
        retained on ``self`` so it is not garbage-collected while visible, and is released once the user dismisses it.

        Args:
            label: User-facing confirmation text.
        """
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Attached")
        box.setText(label)
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.setWindowModality(Qt.WindowModality.NonModal)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        def _on_finished(_result: int) -> None:
            """Release the retained dialog reference once it closes.

            Args:
                _result: Unused ``QDialog`` result code from ``finished``.
            """
            self._attached_dialog = None

        box.finished.connect(_on_finished)
        self._attached_dialog = box
        box.show()

    def _on_detach(self) -> None:
        """Detach from the current process via bridge."""
        if self._bridge is None:
            return

        def _on_success(_result: object) -> None:
            """Clear the attached PID and emit process_detached after close.

            Args:
                _result: Unused close result from ``close``.
            """
            self._attached_pid = None
            self.process_detached.emit()

        def _on_error(exc: object) -> None:
            """Log ``process_detach_failed`` and show Detach Failed with the bridge error text.

            Args:
                exc: Failure from ``close`` while releasing the attached process handle.
            """
            _logger.warning("process_detach_failed", error=str(exc))
            QMessageBox.warning(self, "Detach Failed", f"Failed to detach:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.close(),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_close",
            logger=_logger,
            level="info",
        )

    def _on_suspend(self) -> None:
        """Suspend the selected process."""
        if self._selected_pid is None or self._bridge is None:
            return
        pid = self._selected_pid

        def _on_error(exc: object) -> None:
            """Log ``process_suspend_failed`` and show Suspend Failed naming the PID.

            Args:
                exc: Failure from ``suspend`` for the selected process PID.
            """
            _logger.warning("process_suspend_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Suspend Failed", f"Failed to suspend PID {pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.suspend(pid),
            on_success=None,
            on_error=_on_error,
            parent=self,
            event="process_suspend",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_resume(self) -> None:
        """Resume the selected process."""
        if self._selected_pid is None or self._bridge is None:
            return
        pid = self._selected_pid

        def _on_error(exc: object) -> None:
            """Log ``process_resume_failed`` and show Resume Failed naming the PID.

            Args:
                exc: Failure from ``resume`` for the selected process PID.
            """
            _logger.warning("process_resume_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Resume Failed", f"Failed to resume PID {pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.resume(pid),
            on_success=None,
            on_error=_on_error,
            parent=self,
            event="process_resume",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_terminate(self) -> None:
        """Terminate the selected process with confirmation."""
        if self._selected_pid is None or self._bridge is None:
            return

        reply = QMessageBox.warning(
            self,
            "Terminate Process",
            f"Terminate process {self._selected_pid}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        pid = self._selected_pid

        def _on_success(_result: object) -> None:
            """Clear selection/attachment state and schedule process list refresh.

            Args:
                _result: Unused terminate result from ``terminate``.
            """
            _logger.info("process_terminated", pid=pid)
            self._selected_pid = None
            if self._attached_pid == pid:
                self._attached_pid = None
                self.process_detached.emit()
            QTimer.singleShot(500, self._on_refresh)
            QTimer.singleShot(500, self._refresh_tracked)

        def _on_error(exc: object) -> None:
            """Log ``process_terminate_failed`` and show Terminate Failed naming the PID.

            Args:
                exc: Failure from ``terminate`` for the selected process PID.
            """
            _logger.warning("process_terminate_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Terminate Failed", f"Failed to terminate PID {pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.terminate(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_terminate",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_inject_dll(self) -> None:
        """Inject a DLL into the attached process with file dialog."""
        if self._bridge is None:
            return

        if self._attached_pid is None:
            QMessageBox.warning(
                self,
                "Not Attached",
                "No process is currently attached. Attach to a process before injecting a DLL.",
            )
            return

        attached_pid = self._attached_pid

        path, _ = QFileDialog.getOpenFileName(self, "Select DLL", "", "DLL Files (*.dll)")
        if not path:
            return

        reply = QMessageBox.warning(
            self,
            "DLL Injection",
            f"Inject {path} into PID {attached_pid}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(_result: object) -> None:
            """Confirm successful DLL injection into the attached process.

            Args:
                _result: Unused inject result from ``inject_dll``.
            """
            _logger.info("dll_injected_from_panel", path=path, pid=attached_pid)
            QMessageBox.information(self, "Injected", f"Injected {path} into PID {attached_pid}.")

        def _on_error(exc: object) -> None:
            """Log ``dll_inject_failed`` and show Inject Failed with path and target PID.

            Args:
                exc: Failure from ``inject_dll`` for the chosen DLL path and attached PID.
            """
            _logger.warning("dll_inject_failed", path=path, pid=attached_pid, error=str(exc))
            QMessageBox.warning(self, "Inject Failed", f"Failed to inject {path} into PID {attached_pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.inject_dll(path),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_inject_dll",
            logger=_logger,
            level="info",
            dll_path=path,
            pid=attached_pid,
        )

    def _load_process_info(self, pid: int) -> None:
        """Load detailed process info and environment into info tab.

        Args:
            pid: Process ID to inspect.
        """
        if self._bridge is None:
            return

        def _on_info(result: object) -> None:
            """Populate the info tree with process fields and thread/module counts.

            Args:
                result: Process info object returned by ``get_process_info``.
            """
            self._info_tree.clear()
            if result is None:
                return
            for attr_name in ("pid", "name", "path", "command_line", "parent_pid"):
                val: object = getattr(result, attr_name, None)
                QTreeWidgetItem(self._info_tree, [attr_name, str(val)])

            threads_val: object = getattr(result, "threads", [])
            modules_val: object = getattr(result, "modules", [])
            threads_list = cast("list[object]", threads_val) if isinstance(threads_val, list) else []
            modules_list = cast("list[object]", modules_val) if isinstance(modules_val, list) else []
            QTreeWidgetItem(self._info_tree, ["thread_count", str(len(threads_list))])
            QTreeWidgetItem(self._info_tree, ["module_count", str(len(modules_list))])

        def _on_info_error(exc: object) -> None:
            """Log ``process_info_load_failed`` and show Info Load Failed for the PID.

            Args:
                exc: Failure from ``get_process_info`` while filling the info tree.
            """
            _logger.warning("process_info_load_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Info Load Failed", f"Failed to load info for PID {pid}:\n{exc}")

        run_bridge_coroutine_logged(
            self._bridge.get_process_info(pid),
            on_success=_on_info,
            on_error=_on_info_error,
            parent=self,
            event="process_get_process_info",
            logger=_logger,
            pid=pid,
        )

        def _on_env(result: object) -> None:
            """Fill the environment table with variable name and value rows.

            Args:
                result: Environment name-to-value mapping from ``get_environment``.
            """
            self._env_table.setRowCount(0)
            if not isinstance(result, dict):
                return
            typed_env = cast("dict[str, object]", result)
            for key, val in typed_env.items():
                row = self._env_table.rowCount()
                self._env_table.insertRow(row)
                self._env_table.setItem(row, 0, QTableWidgetItem(str(key)))
                self._env_table.setItem(row, 1, QTableWidgetItem(str(val)))

        def _on_env_error(exc: object) -> None:
            """Emit ``process_env_load_failed`` without dialoging; env table stays stale.

            Args:
                exc: Failure from ``get_environment`` while loading environment rows.
            """
            _logger.warning("process_env_load_failed", pid=pid, error=str(exc))

        run_bridge_coroutine_logged(
            self._bridge.get_environment(pid),
            on_success=_on_env,
            on_error=_on_env_error,
            parent=self,
            event="process_get_environment",
            logger=_logger,
            pid=pid,
        )

    def _on_tab_changed(self, index: int) -> None:
        """Handle sub-tab changes.

        Args:
            index: Newly selected tab index.
        """
        if index == 1:
            self._refresh_tracked()

    def _refresh_tracked(self) -> None:
        """Refresh the tracked processes table."""
        if self._tracked_worker is not None and self._tracked_worker.isRunning():
            return

        if self._tracked_worker is not None:
            self._tracked_worker.deleteLater()
            self._tracked_worker = None

        self._tracked_refresh_btn.setEnabled(False)
        self._tracked_refresh_btn.setText("Refreshing...")

        self._tracked_worker = TrackedRefreshWorker(self)
        self._tracked_worker.refresh_finished.connect(self._on_tracked_finished)
        self._tracked_worker.refresh_error.connect(self._on_tracked_error)
        self._tracked_worker.start()

    def _on_tracked_error(self, message: str) -> None:
        """Handle an error string emitted by the tracked-process refresh worker.

        Args:
            message: User-facing error string from ``TrackedRefreshWorker.refresh_error``.
        """
        self._tracked_refresh_btn.setEnabled(True)
        self._tracked_refresh_btn.setText("Refresh")
        _logger.warning("tracked_refresh_worker_error", error=message)

    def _on_tracked_finished(self, tracked_data: list[dict[str, str | int | None]]) -> None:
        """Handle tracked process data from worker.

        Args:
            tracked_data: List of tracked process dicts.
        """
        self._tracked_refresh_btn.setEnabled(True)
        self._tracked_refresh_btn.setText("Refresh")

        set_sorting_enabled(self._tracked_table, enable=False)
        self._tracked_table.setRowCount(0)

        for entry in tracked_data:
            pid = entry["pid"]
            row = self._tracked_table.rowCount()
            self._tracked_table.insertRow(row)

            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, pid if pid is not None else -1)
            self._tracked_table.setItem(row, _TR_COL_PID, pid_item)
            self._tracked_table.setItem(row, _TR_COL_NAME, QTableWidgetItem(str(entry.get("name", ""))))
            self._tracked_table.setItem(row, _TR_COL_TYPE, QTableWidgetItem(str(entry.get("process_type", ""))))
            self._tracked_table.setItem(row, _TR_COL_STATUS, QTableWidgetItem(str(entry.get("status", ""))))
            self._tracked_table.setItem(row, _TR_COL_REG, QTableWidgetItem(str(entry.get("registered_at", ""))))

        set_sorting_enabled(self._tracked_table, enable=True)
        self._tracked_count_label.setText(f"{len(tracked_data)} tracked")

    def _on_tracked_auto_toggled(self, *, checked: bool) -> None:
        """Toggle tracked auto-refresh.

        Args:
            checked: Whether auto-refresh is enabled.
        """
        if checked:
            self._tracked_auto_btn.setText("Auto-Refresh: ON")
            self._tracked_timer.start(3000)
        else:
            self._tracked_auto_btn.setText("Auto-Refresh: OFF")
            self._tracked_timer.stop()

    def cleanup(self) -> None:
        """Stop timers and join pending workers.

        Stops the auto-refresh, tracked-refresh, and filter-debounce timers, waits for the dedicated tracked-refresh worker, then joins
        every bridge-call worker still owned by this tab subtree (the process-list refresh plus the per-selection info / environment
        coroutines) via :func:`drain_bridge_workers_for`. Joining them here stops their result callbacks from touching this tab's tables and
        trees after the widget has been destroyed.
        """
        self._auto_refresh_timer.stop()
        self._tracked_timer.stop()
        self._filter_debounce_timer.stop()
        if self._tracked_worker is not None:
            if self._tracked_worker.isRunning():
                self._tracked_worker.wait(2000)
            self._tracked_worker.deleteLater()
        self._tracked_worker = None
        _ = drain_bridge_workers_for(self)

    def start_refresh(self) -> None:
        """Trigger an initial process list refresh."""
        self._on_refresh()

    def set_action_buttons_enabled(
        self,
        *,
        attach: bool,
        detach: bool,
        suspend: bool,
        resume: bool,
        terminate: bool,
        inject: bool,
    ) -> None:
        """Enable or disable the process action toolbar buttons.

        Args:
            attach: Whether the Attach button is enabled.
            detach: Whether the Detach button is enabled.
            suspend: Whether the Suspend button is enabled.
            resume: Whether the Resume button is enabled.
            terminate: Whether the Terminate button is enabled.
            inject: Whether the DLL Inject button is enabled.
        """
        self._attach_btn.setEnabled(attach)
        self._detach_btn.setEnabled(detach)
        self._suspend_btn.setEnabled(suspend)
        self._resume_btn.setEnabled(resume)
        self._terminate_btn.setEnabled(terminate)
        self._inject_btn.setEnabled(inject)
