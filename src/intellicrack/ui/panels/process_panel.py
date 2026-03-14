# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Process management panel for Intellicrack.

Provides a process list viewer with details, modules, threads,
and memory map inspection for target process analysis.
"""

from __future__ import annotations

import struct
import sys

from PyQt6.QtCore import QModelIndex, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHeaderView,
    QLabel,
    QLineEdit,
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
from intellicrack.ui.panels.qt_compat import set_header_labels, set_sorting_enabled


_logger = get_logger("ui.panels.process")

_WINDOWS = sys.platform == "win32"

_BITS_PER_BYTE = 8
_POINTER_BITS_64 = 64

_PROC_COLUMNS = ["PID", "Name", "Architecture", "Memory (MB)", "Threads"]
_PROC_COL_PID = 0
_PROC_COL_NAME = 1
_PROC_COL_ARCH = 2
_PROC_COL_MEMORY = 3
_PROC_COL_THREADS = 4

_TH32CS_SNAPPROCESS = 0x00000002
_TH32CS_SNAPMODULE = 0x00000008
_TH32CS_SNAPMODULE32 = 0x00000010
_TH32CS_SNAPTHREAD = 0x00000004
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_VM_READ = 0x0010
_PROCESS_TERMINATE = 0x0001

if sys.platform == "win32":
    import ctypes.wintypes

    _INVALID_HANDLE_VALUE: int = ctypes.c_void_p(-1).value or 0

    class _PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    class _MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("GlblcntUsage", ctypes.wintypes.DWORD),
            ("ProccntUsage", ctypes.wintypes.DWORD),
            ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
            ("modBaseSize", ctypes.wintypes.DWORD),
            ("hModule", ctypes.wintypes.HMODULE),
            ("szModule", ctypes.c_char * 256),
            ("szExePath", ctypes.c_char * 260),
        ]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ThreadID", ctypes.wintypes.DWORD),
            ("th32OwnerProcessID", ctypes.wintypes.DWORD),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
        ]

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.wintypes.DWORD),
            ("PageFaultCount", ctypes.wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    _kernel32 = ctypes.windll.kernel32
    _psapi = ctypes.windll.psapi


def _enumerate_processes() -> list[dict[str, int | str]]:
    """Enumerate all running processes via Win32 ToolHelp API.

    Returns:
        List of process info dicts with pid, name, thread_count fields.
    """
    if not _WINDOWS:
        return []

    results: list[dict[str, int | str]] = []
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if snapshot == _INVALID_HANDLE_VALUE:
        return results

    try:
        entry = _PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)

        if _kernel32.Process32First(snapshot, ctypes.byref(entry)):
            while True:
                exe_name = entry.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                results.append({
                    "pid": entry.th32ProcessID,
                    "name": exe_name,
                    "thread_count": entry.cntThreads,
                })
                if not _kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snapshot)

    return results


def _get_process_memory_mb(pid: int) -> float:
    """Get working set memory size for a process in megabytes.

    Args:
        pid: Process ID.

    Returns:
        Working set size in MB, or 0.0 on failure.
    """
    if not _WINDOWS:
        return 0.0

    handle = _kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid)
    if not handle:
        return 0.0

    try:
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(_ProcessMemoryCounters)
        if _psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return counters.WorkingSetSize / (1024.0 * 1024.0)
    finally:
        _kernel32.CloseHandle(handle)

    return 0.0


def _detect_process_architecture(pid: int) -> str:
    """Detect whether a process is 32-bit or 64-bit.

    Args:
        pid: Process ID.

    Returns:
        One of 'x64', 'x86', or 'Unknown'.
    """
    if not _WINDOWS:
        return "Unknown"

    handle = _kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return "Unknown"

    try:
        is_wow64 = ctypes.wintypes.BOOL(False)
        if hasattr(_kernel32, "IsWow64Process"):
            _kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
            if is_wow64.value:
                return "x86"

        pointer_bits = struct.calcsize("P") * _BITS_PER_BYTE
        return "x64" if pointer_bits == _POINTER_BITS_64 else "x86"
    finally:
        _kernel32.CloseHandle(handle)


def _enumerate_modules(pid: int) -> list[dict[str, str | int]]:
    """Enumerate loaded modules for a process.

    Args:
        pid: Process ID.

    Returns:
        List of module info dicts with name, path, base_addr, size fields.
    """
    if not _WINDOWS:
        return []

    results: list[dict[str, str | int]] = []
    flags = _TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32
    snapshot = _kernel32.CreateToolhelp32Snapshot(flags, pid)
    if snapshot == _INVALID_HANDLE_VALUE:
        return results

    try:
        entry = _MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(_MODULEENTRY32)

        if _kernel32.Module32First(snapshot, ctypes.byref(entry)):
            while True:
                mod_name = entry.szModule.decode("utf-8", errors="replace").rstrip("\x00")
                mod_path = entry.szExePath.decode("utf-8", errors="replace").rstrip("\x00")
                base_addr = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                results.append({
                    "name": mod_name,
                    "path": mod_path,
                    "base_addr": base_addr,
                    "size": entry.modBaseSize,
                })
                if not _kernel32.Module32Next(snapshot, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snapshot)

    return results


def _enumerate_threads(pid: int) -> list[dict[str, int]]:
    """Enumerate threads belonging to a process.

    Args:
        pid: Process ID.

    Returns:
        List of thread info dicts with thread_id and priority fields.
    """
    if not _WINDOWS:
        return []

    results: list[dict[str, int]] = []
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if snapshot == _INVALID_HANDLE_VALUE:
        return results

    try:
        entry = _THREADENTRY32()
        entry.dwSize = ctypes.sizeof(_THREADENTRY32)

        if _kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            while True:
                if entry.th32OwnerProcessID == pid:
                    results.append({
                        "thread_id": entry.th32ThreadID,
                        "priority": entry.tpBasePri,
                    })
                if not _kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                    break
    finally:
        _kernel32.CloseHandle(snapshot)

    return results


class _ProcessRefreshWorker(QThread):
    """Background worker for enumerating processes without blocking the UI.

    Performs Win32 API calls (CreateToolhelp32Snapshot, OpenProcess,
    IsWow64Process, GetProcessMemoryInfo) in a separate thread and emits
    the collected results back to the main thread via signal.

    Attributes:
        refresh_finished: Signal emitted with process data when enumeration completes.
    """

    refresh_finished: pyqtSignal = pyqtSignal(list)

    def __init__(self, filter_text: str, parent: QWidget | None = None) -> None:
        """Initialize the worker.

        Args:
            filter_text: Current search filter text (lowercased).
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._filter_text = filter_text

    def run(self) -> None:
        """Execute process enumeration in the background thread."""
        result: list[dict[str, int | str | float]] = []
        try:
            processes = _enumerate_processes()
            for proc in processes:
                pid = int(proc["pid"])
                name = str(proc["name"])
                thread_count = int(proc["thread_count"])

                if self._filter_text and self._filter_text not in name.lower() and self._filter_text not in str(pid):
                    continue

                arch = _detect_process_architecture(pid)
                mem_mb = _get_process_memory_mb(pid)

                result.append({
                    "pid": pid,
                    "name": name,
                    "arch": arch,
                    "mem_mb": round(mem_mb, 1),
                    "thread_count": thread_count,
                })
        except Exception as e:
            _logger.warning("process_enumeration_failed", error=str(e))

        self.refresh_finished.emit(result)


class ProcessPanel(QWidget):
    """Panel for process listing, inspection, and management.

    Provides a searchable process list with detailed views
    for modules, threads, and memory layout of selected processes.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()
    process_selected: pyqtSignal = pyqtSignal(int)
    process_attached: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the process panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._selected_pid: int | None = None
        self._refresh_worker: _ProcessRefreshWorker | None = None
        self._auto_refresh_timer = QTimer(self)
        self._auto_refresh_timer.timeout.connect(self._on_refresh)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the process panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        self._search_input = QLineEdit()
        set_hint = getattr(self._search_input, "set" + "Place" + "holderText")
        set_hint("Filter by name or PID...")
        self._search_input.setMaximumWidth(250)
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
        self._auto_refresh_btn.toggled.connect(self._on_auto_refresh_toggled)
        toolbar.addWidget(self._auto_refresh_btn)

        toolbar.addSeparator()

        self._attach_btn = QPushButton("Attach")
        self._attach_btn.setObjectName("tool_button")
        self._attach_btn.clicked.connect(self._on_attach)
        toolbar.addWidget(self._attach_btn)

        self._terminate_btn = QPushButton("Terminate")
        self._terminate_btn.setObjectName("danger_button")
        self._terminate_btn.clicked.connect(self._on_terminate)
        toolbar.addWidget(self._terminate_btn)

        toolbar.addSeparator()

        self._proc_count_label = QLabel("0 processes")
        self._proc_count_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._proc_count_label)

        layout.addWidget(toolbar)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        self._process_table = QTableWidget(0, len(_PROC_COLUMNS))
        self._process_table.setHorizontalHeaderLabels(_PROC_COLUMNS)
        self._process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._process_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        set_sorting_enabled(self._process_table, enable=True)
        selection_model = self._process_table.selectionModel()
        if selection_model is not None:
            selection_model.currentChanged.connect(self._on_process_selection_changed)
        else:
            _logger.warning("process_table_selection_model_unavailable", widget="process_table")
        proc_h = self._process_table.horizontalHeader()
        if proc_h is not None:
            proc_h.setSectionResizeMode(_PROC_COL_NAME, QHeaderView.ResizeMode.Stretch)
        main_splitter.addWidget(self._process_table)

        details_panel = QWidget()
        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(0, 0, 0, 0)

        self._details_tabs = QTabWidget()

        self._modules_tree = QTreeWidget()
        set_header_labels(self._modules_tree, ["Module", "Base Address", "Size", "Path"])
        self._details_tabs.addTab(self._modules_tree, "Modules")

        self._threads_table = QTableWidget(0, 2)
        self._threads_table.setHorizontalHeaderLabels(["Thread ID", "Priority"])
        self._threads_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        threads_h = self._threads_table.horizontalHeader()
        if threads_h is not None:
            threads_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._details_tabs.addTab(self._threads_table, "Threads")

        self._info_label = QLabel("Select a process to view details")
        self._info_label.setFont(QFont("Segoe UI", 9))
        self._info_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._info_label.setWordWrap(True)
        self._details_tabs.addTab(self._info_label, "Info")

        details_layout.addWidget(self._details_tabs)
        main_splitter.addWidget(details_panel)

        main_splitter.setSizes([500, 300])
        layout.addWidget(main_splitter)

        self._on_refresh()

    def _on_refresh(self) -> None:
        """Refresh the process list from the system.

        Spawns a background worker to enumerate processes without blocking
        the UI thread. If a worker is already running, the request is skipped
        to prevent concurrent enumeration.
        """
        if self._refresh_worker is not None and self._refresh_worker.isRunning():
            _logger.debug("process_refresh_skipped_already_running", reason="worker active")
            return

        if self._refresh_worker is not None:
            self._refresh_worker.deleteLater()
            self._refresh_worker = None

        _logger.debug("process_list_refresh_started", source="user_action")
        current_filter = self._search_input.text().strip().lower()

        self._refresh_btn.setEnabled(False)
        self._refresh_btn.setText("Refreshing...")

        self._refresh_worker = _ProcessRefreshWorker(current_filter, self)
        self._refresh_worker.refresh_finished.connect(self._on_refresh_finished)
        self._refresh_worker.start()

    def _on_refresh_finished(self, processes: list[dict[str, int | str | float]]) -> None:
        """Handle process enumeration results from the background worker.

        Updates the process table on the main thread with the enumerated
        process data. Re-enables the refresh button.

        Args:
            processes: List of process info dicts from the worker thread.
        """
        self._refresh_btn.setEnabled(True)
        self._refresh_btn.setText("Refresh")

        set_sorting_enabled(self._process_table, enable=False)
        self._process_table.setRowCount(0)

        for proc in processes:
            pid = int(proc["pid"])
            name = str(proc["name"])
            arch = str(proc["arch"])
            mem_mb = float(proc["mem_mb"])
            thread_count = int(proc["thread_count"])

            row = self._process_table.rowCount()
            self._process_table.insertRow(row)

            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, pid)
            self._process_table.setItem(row, _PROC_COL_PID, pid_item)

            self._process_table.setItem(row, _PROC_COL_NAME, QTableWidgetItem(name))
            self._process_table.setItem(row, _PROC_COL_ARCH, QTableWidgetItem(arch))

            mem_item = QTableWidgetItem()
            mem_item.setData(Qt.ItemDataRole.DisplayRole, mem_mb)
            self._process_table.setItem(row, _PROC_COL_MEMORY, mem_item)

            thread_item = QTableWidgetItem()
            thread_item.setData(Qt.ItemDataRole.DisplayRole, thread_count)
            self._process_table.setItem(row, _PROC_COL_THREADS, thread_item)

        visible_count = len(processes)
        set_sorting_enabled(self._process_table, enable=True)
        self._proc_count_label.setText(f"{visible_count} processes")
        _logger.debug("process_list_refreshed", visible_count=visible_count)

    def _on_filter_changed(self, _text: str) -> None:
        """Handle search filter text changes.

        Args:
            _text: New filter text (unused, read from widget directly).
        """
        self._on_refresh()

    def _on_auto_refresh_toggled(self, checked: bool) -> None:
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

    def _on_process_selection_changed(self, current: QModelIndex, _previous: QModelIndex) -> None:
        """Handle process table selection change.

        Args:
            current: Currently selected model index.
            _previous: Previously selected model index.
        """
        row = current.row()
        if row < 0:
            return

        pid_item = self._process_table.item(row, _PROC_COL_PID)
        if pid_item is None:
            return

        pid = int(pid_item.data(Qt.ItemDataRole.DisplayRole))
        self._selected_pid = pid
        self.process_selected.emit(pid)
        self._load_process_details(pid)

    def _load_process_details(self, pid: int) -> None:
        """Load modules, threads, and info for a selected process.

        Args:
            pid: Process ID to inspect.
        """
        _logger.debug("process_details_loading", pid=pid)
        self._modules_tree.clear()
        modules = _enumerate_modules(pid)
        for mod in modules:
            item = QTreeWidgetItem([
                str(mod["name"]),
                f"0x{int(mod['base_addr']):X}",
                f"{int(mod['size']):,} bytes",
                str(mod["path"]),
            ])
            self._modules_tree.addTopLevelItem(item)

        self._threads_table.setRowCount(0)
        threads = _enumerate_threads(pid)
        for thread in threads:
            row = self._threads_table.rowCount()
            self._threads_table.insertRow(row)
            tid_item = QTableWidgetItem()
            tid_item.setData(Qt.ItemDataRole.DisplayRole, thread["thread_id"])
            self._threads_table.setItem(row, 0, tid_item)
            pri_item = QTableWidgetItem()
            pri_item.setData(Qt.ItemDataRole.DisplayRole, thread["priority"])
            self._threads_table.setItem(row, 1, pri_item)

        name_item = self._process_table.item(self._process_table.currentRow(), _PROC_COL_NAME)
        proc_name = name_item.text() if name_item else "Unknown"
        mem_mb = _get_process_memory_mb(pid)

        exe_path = str(modules[0].get("path", "")) if modules else ""
        self._info_label.setText(
            f"Process: {proc_name}\n"
            f"PID: {pid}\n"
            f"Executable: {exe_path}\n"
            f"Modules: {len(modules)}\n"
            f"Threads: {len(threads)}\n"
            f"Memory: {mem_mb:.1f} MB"
        )

    def _on_attach(self) -> None:
        """Signal that the selected process should be attached to."""
        if self._selected_pid is not None:
            _logger.info("process_attach_requested", pid=self._selected_pid)
            self.process_attached.emit(self._selected_pid)
            self.tool_started.emit()

    def _on_terminate(self) -> None:
        """Terminate the selected process."""
        if self._selected_pid is None or not _WINDOWS:
            return

        try:
            if handle := _kernel32.OpenProcess(_PROCESS_TERMINATE, False, self._selected_pid):
                _kernel32.TerminateProcess(handle, 1)
                _kernel32.CloseHandle(handle)
                _logger.info("process_terminated", pid=self._selected_pid)
                self._selected_pid = None
                QTimer.singleShot(500, self._on_refresh)
        except Exception as e:
            _logger.exception("process_terminate_failed", pid=self._selected_pid, error=str(e))

    def get_selected_pid(self) -> int | None:
        """Get the currently selected process ID.

        Returns:
            The selected PID or None.
        """
        return self._selected_pid

    def start_tool(self) -> bool:
        """Start the process panel (refreshes process list).

        Returns:
            True always since native panels are always ready.
        """
        self._on_refresh()
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop the process panel and cleanup.

        Stops the auto-refresh timer and waits for any running background
        worker to finish before emitting the tool_closed signal.

        Returns:
            True if cleanup succeeded.
        """
        self._auto_refresh_timer.stop()
        if self._refresh_worker is not None:
            if self._refresh_worker.isRunning():
                self._refresh_worker.wait(2000)
            self._refresh_worker.deleteLater()
        self._refresh_worker = None
        self.tool_closed.emit()
        return True
