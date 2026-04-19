# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Thread inspection tab for the ProcessPanel.

Provides thread list, register context, stack walk, SEH chain, and fiber/TLS inspection with full bridge delegation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge
    from intellicrack.core.types import ThreadInfo
    from intellicrack.ui.panels.process_panel._system_tab import SystemTab

_logger = get_logger("ui.panels.process.threads_tab")

_MARGIN: Final[int] = 0
_SPACING: Final[int] = 4
_TOOLBAR_HEIGHT: Final[int] = 32


class ThreadsTab(QWidget):
    """Tab for thread inspection and manipulation.

    Provides sub-tabs for thread list, register context, stack walk,
    SEH chain enumeration, and fiber/TLS data.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ThreadsTab.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: ProcessBridge | None = None
        self._attached_pid: int | None = None
        self._threads: list[ThreadInfo] = []
        self._system_tab: SystemTab | None = None
        self._setup_ui()

    def attach_system_tab(self, system_tab: SystemTab) -> None:
        """Register the sibling SystemTab so the TEB thread combo can be refreshed.

        Args:
            system_tab: SystemTab instance owned by the same ProcessPanel.
        """
        self._system_tab = system_tab

    def set_bridge(self, bridge: ProcessBridge) -> None:
        """Set the process bridge.

        Args:
            bridge: ProcessBridge instance.
        """
        self._bridge = bridge

    def get_bridge(self) -> ProcessBridge | None:
        """Get the current bridge.

        Returns:
            ProcessBridge | None: The bridge or None.
        """
        return self._bridge

    def set_attached_pid(self, pid: int | None) -> None:
        """Set the currently attached process ID.

        Args:
            pid: Process ID or None if detached.
        """
        self._attached_pid = pid

    def update_thread_list(self, threads: list[ThreadInfo]) -> None:
        """Update the thread list and combo boxes with new data.

        Args:
            threads: List of ThreadInfo from the bridge.
        """
        self._threads = threads
        for combo in (self._reg_combo, self._stack_combo, self._seh_combo, self._fiber_combo):
            combo.clear()
            for t in threads:
                combo.addItem(f"TID {t.tid}", t.tid)

    def _setup_ui(self) -> None:
        """Build the threads tab layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_thread_list(), "Thread List")
        self._tabs.addTab(self._build_registers(), "Registers")
        self._tabs.addTab(self._build_stack_walk(), "Stack Walk")
        self._tabs.addTab(self._build_seh_chain(), "Exception Handlers")
        self._tabs.addTab(self._build_fiber_tls(), "Fibers/TLS")
        layout.addWidget(self._tabs)

    def _build_thread_list(self) -> QWidget:
        """Build the thread list sub-tab.

        Returns:
            QWidget: Thread list widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("tool_button")
        refresh_btn.clicked.connect(self._refresh_threads)
        toolbar.addWidget(refresh_btn)

        suspend_btn = QPushButton("Suspend Process")
        suspend_btn.setObjectName("tool_button")
        suspend_btn.setToolTip("Suspend the attached process (all threads)")
        suspend_btn.clicked.connect(self._on_suspend_thread)
        toolbar.addWidget(suspend_btn)

        resume_btn = QPushButton("Resume Process")
        resume_btn.setObjectName("tool_button")
        resume_btn.setToolTip("Resume the attached process (all threads)")
        resume_btn.clicked.connect(self._on_resume_thread)
        toolbar.addWidget(resume_btn)

        self._thread_count = QLabel("0 threads")
        self._thread_count.setObjectName("toolbar_label")
        toolbar.addWidget(self._thread_count)

        tab_layout.addWidget(toolbar)

        columns = ["TID", "Priority", "State", "Start Address"]
        self._thread_table = QTableWidget(0, len(columns))
        self._thread_table.setHorizontalHeaderLabels(columns)
        self._thread_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._thread_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        th = self._thread_table.horizontalHeader()
        if th is not None:
            th.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._thread_table)
        return tab

    def _build_registers(self) -> QWidget:
        """Build the register context sub-tab.

        Returns:
            QWidget: Registers widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Thread:"))
        self._reg_combo = QComboBox()
        self._reg_combo.setMinimumWidth(120)
        toolbar.addWidget(self._reg_combo)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("tool_button")
        refresh_btn.clicked.connect(self._refresh_registers)
        toolbar.addWidget(refresh_btn)

        write_btn = QPushButton("Write Registers")
        write_btn.setObjectName("danger_button")
        write_btn.clicked.connect(self._on_write_registers)
        toolbar.addWidget(write_btn)

        tab_layout.addWidget(toolbar)

        self._reg_table = QTableWidget(0, 3)
        self._reg_table.setHorizontalHeaderLabels(["Register", "Hex Value", "Decimal"])
        self._reg_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        rh = self._reg_table.horizontalHeader()
        if rh is not None:
            rh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._reg_table)
        return tab

    def _build_stack_walk(self) -> QWidget:
        """Build the stack walk sub-tab.

        Returns:
            QWidget: Stack walk widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Thread:"))
        self._stack_combo = QComboBox()
        self._stack_combo.setMinimumWidth(120)
        toolbar.addWidget(self._stack_combo)

        walk_btn = QPushButton("Walk Stack")
        walk_btn.setObjectName("tool_button")
        walk_btn.clicked.connect(self._on_stack_walk)
        toolbar.addWidget(walk_btn)

        tab_layout.addWidget(toolbar)

        columns = ["#", "Return Address", "Function", "Module", "Offset"]
        self._stack_table = QTableWidget(0, len(columns))
        self._stack_table.setHorizontalHeaderLabels(columns)
        self._stack_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        sh = self._stack_table.horizontalHeader()
        if sh is not None:
            sh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._stack_table)
        return tab

    def _build_seh_chain(self) -> QWidget:
        """Build the SEH chain sub-tab.

        Returns:
            QWidget: SEH chain widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Thread:"))
        self._seh_combo = QComboBox()
        self._seh_combo.setMinimumWidth(120)
        toolbar.addWidget(self._seh_combo)

        enum_btn = QPushButton("Enumerate")
        enum_btn.setObjectName("tool_button")
        enum_btn.clicked.connect(self._on_seh_enumerate)
        toolbar.addWidget(enum_btn)

        tab_layout.addWidget(toolbar)

        columns = ["Address", "Handler Address", "Next"]
        self._seh_table = QTableWidget(0, len(columns))
        self._seh_table.setHorizontalHeaderLabels(columns)
        self._seh_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        seh_h = self._seh_table.horizontalHeader()
        if seh_h is not None:
            seh_h.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._seh_table)
        return tab

    def _build_fiber_tls(self) -> QWidget:
        """Build the fiber/TLS data sub-tab.

        Returns:
            QWidget: Fiber/TLS widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Thread:"))
        self._fiber_combo = QComboBox()
        self._fiber_combo.setMinimumWidth(120)
        toolbar.addWidget(self._fiber_combo)

        fiber_btn = QPushButton("Get Fiber Data")
        fiber_btn.setObjectName("tool_button")
        fiber_btn.clicked.connect(self._on_fiber)
        toolbar.addWidget(fiber_btn)

        tls_btn = QPushButton("Get TLS Values")
        tls_btn.setObjectName("tool_button")
        tls_btn.clicked.connect(self._on_tls)
        toolbar.addWidget(tls_btn)

        tab_layout.addWidget(toolbar)

        self._fiber_table = QTableWidget(0, 2)
        self._fiber_table.setHorizontalHeaderLabels(["Field", "Value"])
        fh = self._fiber_table.horizontalHeader()
        if fh is not None:
            fh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._fiber_table)

        tab_layout.addWidget(QLabel("TLS Slots"))

        self._tls_table = QTableWidget(0, 2)
        self._tls_table.setHorizontalHeaderLabels(["Index", "Value"])
        tlsh = self._tls_table.horizontalHeader()
        if tlsh is not None:
            tlsh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._tls_table)
        return tab

    def _get_selected_tid(self) -> int | None:
        """Get TID from the currently selected thread table row.

        Returns:
            int | None: Thread ID or None.
        """
        sel = self._thread_table.selectionModel()
        if sel is None:
            return None
        indexes = sel.selectedRows()
        if not indexes:
            return None
        row = indexes[0].row()
        item = self._thread_table.item(row, 0)
        if item is None:
            return None
        return int(item.data(Qt.ItemDataRole.DisplayRole))

    def _refresh_threads(self) -> None:
        """Refresh the thread list from bridge."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            typed_result = cast("list[object]", result)
            self._thread_table.setRowCount(0)
            for t in typed_result:
                row = self._thread_table.rowCount()
                self._thread_table.insertRow(row)
                tid_item = QTableWidgetItem()
                tid_raw: object = getattr(t, "tid", 0)
                tid_item.setData(Qt.ItemDataRole.DisplayRole, tid_raw if isinstance(tid_raw, int) else 0)
                self._thread_table.setItem(row, 0, tid_item)
                pri_item = QTableWidgetItem()
                pri_raw: object = getattr(t, "priority", 0)
                pri_item.setData(Qt.ItemDataRole.DisplayRole, pri_raw if isinstance(pri_raw, int) else 0)
                self._thread_table.setItem(row, 1, pri_item)
                self._thread_table.setItem(row, 2, QTableWidgetItem(str(getattr(t, "state", "unknown"))))
                start_raw: object = getattr(t, "start_address", 0)
                start_addr = start_raw if isinstance(start_raw, int) else 0
                self._thread_table.setItem(row, 3, QTableWidgetItem(f"0x{start_addr:X}"))
            self._thread_count.setText(f"{len(typed_result)} threads")
            thread_list = cast("list[ThreadInfo]", result)
            self.update_thread_list(thread_list)
            if self._system_tab is not None:
                self._system_tab.update_thread_list(thread_list)

        run_bridge_coroutine_async(self._bridge.get_threads(self._attached_pid), _on_success, None, self)

    def _on_suspend_thread(self) -> None:
        """Suspend every thread in the attached process."""
        if self._bridge is None or self._attached_pid is None:
            return
        run_bridge_coroutine_async(self._bridge.suspend(self._attached_pid), None, None, self)

    def _on_resume_thread(self) -> None:
        """Resume every thread in the attached process."""
        if self._bridge is None or self._attached_pid is None:
            return
        run_bridge_coroutine_async(self._bridge.resume(self._attached_pid), None, None, self)

    def _refresh_registers(self) -> None:
        """Refresh register context for the selected thread."""
        if self._bridge is None:
            return
        tid = self._reg_combo.currentData()
        if not isinstance(tid, int):
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._reg_table.setRowCount(0)
            for reg_name, value in typed_result.items():
                int_val = value if isinstance(value, int) else 0
                row = self._reg_table.rowCount()
                self._reg_table.insertRow(row)
                self._reg_table.setItem(row, 0, QTableWidgetItem(str(reg_name)))
                self._reg_table.setItem(row, 1, QTableWidgetItem(f"0x{int_val:X}"))
                self._reg_table.setItem(row, 2, QTableWidgetItem(str(int_val)))

        run_bridge_coroutine_async(self._bridge.get_thread_context(tid), _on_success, None, self)

    def _on_write_registers(self) -> None:
        """Write modified registers back to the thread."""
        if self._bridge is None:
            return
        tid = self._reg_combo.currentData()
        if not isinstance(tid, int):
            return

        reply = QMessageBox.warning(
            self,
            "Write Registers",
            f"Write modified registers to thread {tid}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        regs: dict[str, int] = {}
        for row in range(self._reg_table.rowCount()):
            name_item = self._reg_table.item(row, 0)
            val_item = self._reg_table.item(row, 1)
            if name_item is not None and val_item is not None:
                try:
                    regs[name_item.text()] = int(val_item.text(), 16)
                except ValueError:
                    continue

        run_bridge_coroutine_async(self._bridge.set_thread_context(tid, regs), None, None, self)

    def _on_stack_walk(self) -> None:
        """Walk the stack of the selected thread."""
        if self._bridge is None:
            return
        tid = self._stack_combo.currentData()
        if not isinstance(tid, int):
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._stack_table.setRowCount(0)
            for frame in cast("list[object]", result):
                if not isinstance(frame, dict):
                    continue
                typed_frame = cast("dict[str, object]", frame)
                row = self._stack_table.rowCount()
                self._stack_table.insertRow(row)
                idx_raw = typed_frame.get("index", 0)
                idx_item = QTableWidgetItem()
                idx_item.setData(Qt.ItemDataRole.DisplayRole, idx_raw if isinstance(idx_raw, int) else 0)
                self._stack_table.setItem(row, 0, idx_item)
                ret_raw = typed_frame.get("return_address", 0)
                ret_addr = ret_raw if isinstance(ret_raw, int) else 0
                self._stack_table.setItem(row, 1, QTableWidgetItem(f"0x{ret_addr:X}"))
                self._stack_table.setItem(row, 2, QTableWidgetItem(str(typed_frame.get("symbol_name", ""))))
                self._stack_table.setItem(row, 3, QTableWidgetItem(str(typed_frame.get("module_name", ""))))
                disp_raw = typed_frame.get("displacement", 0)
                disp = disp_raw if isinstance(disp_raw, int) else 0
                self._stack_table.setItem(row, 4, QTableWidgetItem(f"0x{disp:X}"))

        run_bridge_coroutine_async(self._bridge.stack_walk(tid), _on_success, None, self)

    def _on_seh_enumerate(self) -> None:
        """Enumerate SEH chain for the selected thread."""
        if self._bridge is None:
            return
        tid = self._seh_combo.currentData()
        if not isinstance(tid, int):
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._seh_table.setRowCount(0)
            for entry in cast("list[object]", result):
                if not isinstance(entry, dict):
                    continue
                typed_entry = cast("dict[str, object]", entry)
                row = self._seh_table.rowCount()
                self._seh_table.insertRow(row)
                addr_raw = typed_entry.get("address", 0)
                addr_val = addr_raw if isinstance(addr_raw, int) else 0
                handler_raw = typed_entry.get("handler_address", 0)
                handler_val = handler_raw if isinstance(handler_raw, int) else 0
                next_raw = typed_entry.get("next", 0)
                next_val = next_raw if isinstance(next_raw, int) else 0
                self._seh_table.setItem(row, 0, QTableWidgetItem(f"0x{addr_val:X}"))
                self._seh_table.setItem(row, 1, QTableWidgetItem(f"0x{handler_val:X}"))
                self._seh_table.setItem(row, 2, QTableWidgetItem(f"0x{next_val:X}"))

        run_bridge_coroutine_async(self._bridge.get_seh_chain(tid), _on_success, None, self)

    def _on_fiber(self) -> None:
        """Get fiber data for the selected thread."""
        if self._bridge is None:
            return
        tid = self._fiber_combo.currentData()
        if not isinstance(tid, int):
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._fiber_table.setRowCount(0)
            for key, val in typed_result.items():
                row = self._fiber_table.rowCount()
                self._fiber_table.insertRow(row)
                self._fiber_table.setItem(row, 0, QTableWidgetItem(str(key)))
                val_str = f"0x{val:X}" if isinstance(val, int) else str(val)
                self._fiber_table.setItem(row, 1, QTableWidgetItem(val_str))

        run_bridge_coroutine_async(self._bridge.get_fiber_data(tid), _on_success, None, self)

    def _on_tls(self) -> None:
        """Get TLS slot values for the selected thread."""
        if self._bridge is None:
            return
        tid = self._fiber_combo.currentData()
        if not isinstance(tid, int):
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._tls_table.setRowCount(0)
            for slot in cast("list[object]", result):
                if not isinstance(slot, dict):
                    continue
                typed_slot = cast("dict[str, object]", slot)
                row = self._tls_table.rowCount()
                self._tls_table.insertRow(row)
                idx_raw = typed_slot.get("index", 0)
                idx_item = QTableWidgetItem()
                idx_item.setData(Qt.ItemDataRole.DisplayRole, idx_raw if isinstance(idx_raw, int) else 0)
                self._tls_table.setItem(row, 0, idx_item)
                tls_raw = typed_slot.get("value", 0)
                tls_val = tls_raw if isinstance(tls_raw, int) else 0
                self._tls_table.setItem(row, 1, QTableWidgetItem(f"0x{tls_val:X}"))

        run_bridge_coroutine_async(self._bridge.get_tls_values(tid), _on_success, None, self)
