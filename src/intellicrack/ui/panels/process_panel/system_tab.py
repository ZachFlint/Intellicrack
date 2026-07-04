# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""System inspection tab for the ProcessPanel.

Provides token/privilege, window, service, PEB/TEB, pipe, mitigation, and advanced (registry, resources, raw query) inspection with bridge
delegation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge
    from intellicrack.core.types import ThreadInfo

_logger = get_logger(__name__)

_MARGIN: Final[int] = 0
_NOT_ATTACHED_MSG: Final[str] = "Not attached to any process"
_SPACING: Final[int] = 4
_TOOLBAR_HEIGHT: Final[int] = 32


class SystemTab(QWidget):
    """Tab for system-level process inspection and operations.

    Provides sub-tabs for token/privileges, windows, services, PEB/TEB, pipes, mitigations, and advanced operations (registry, resources,
    raw query).
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SystemTab.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: ProcessBridge | None = None
        self._attached_pid: int | None = None
        self._pipe_handles: dict[str, int] = {}
        self._device_handles: dict[int, str] = {}
        self._section_handles: dict[int, str] = {}
        self._section_views: dict[int, int] = {}
        self._setup_ui()

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
            pid: Process ID or None.
        """
        self._attached_pid = pid

    def update_thread_list(self, threads: list[ThreadInfo]) -> None:
        """Update thread combo boxes with new data.

        Args:
            threads: List of ThreadInfo from the bridge.
        """
        self._teb_combo.clear()
        for t in threads:
            self._teb_combo.addItem(f"TID {t.tid}", t.tid)

    def _require_attached_pid(self, action: str) -> int | None:
        """Return the attached PID, surfacing a user-visible notice when unattached.

        Centralises the guard pattern used by every PID-dependent action so future
        methods cannot silently fail when no process is attached.

        Args:
            action: Short identifier of the calling action used for structured logging
                and for the title of the user-visible warning dialog.

        Returns:
            int | None: The attached PID, or None if no process is currently attached.
                When None is returned, a warning dialog has already been shown and the
                raw-output widget has been updated with the not-attached notice.
        """
        if self._attached_pid is None:
            _logger.warning("system_tab_action_without_pid", action=action)
            self._raw_output.setPlainText(_NOT_ATTACHED_MSG)
            QMessageBox.warning(self, action, _NOT_ATTACHED_MSG)
            return None
        return self._attached_pid

    def _show_error(self, title: str, exc: object, *, log_event: str) -> None:
        """Surface a bridge error to the user via a warning dialog and structured log.

        Mirrors the user-facing error-handling pattern used by ``ModulesTab`` so the
        operator sees failures rather than having them silently dropped into the log.

        Args:
            title: Title for the warning dialog, also used to convey the action context
                to the user (for example, ``"Query Mitigations"``).
            exc: The exception or error object reported by the bridge layer.
            log_event: Structured log event name identifying the failing action.
        """
        message = str(exc)
        _logger.warning("system_tab_bridge_error", log_event=log_event, error=message, title=title)
        QMessageBox.warning(self, title, message)

    def _setup_ui(self) -> None:
        """Build the system tab layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_token_tab(), "Token/Privileges")
        self._tabs.addTab(self._build_windows_tab(), "Windows")
        self._tabs.addTab(self._build_services_tab(), "Services")
        self._tabs.addTab(self._build_peb_teb_tab(), "PEB/TEB")
        self._tabs.addTab(self._build_pipes_tab(), "Pipes")
        self._tabs.addTab(self._build_mitigations_tab(), "Mitigations")
        self._tabs.addTab(self._build_handles_tab(), "Handles")
        self._tabs.addTab(self._build_processes_tab(), "System Processes")
        self._tabs.addTab(self._build_objects_tab(), "Kernel Objects")
        self._tabs.addTab(self._build_advanced_tab(), "Advanced")
        layout.addWidget(self._tabs)

    def _build_token_tab(self) -> QWidget:
        """Build the token/privileges sub-tab.

        Returns:
            QWidget: Token tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        query_btn = QPushButton("Query Privileges")
        query_btn.setObjectName("tool_button")
        query_btn.clicked.connect(self._refresh_privileges)
        toolbar.addWidget(query_btn)

        debug_btn = QPushButton("Enable Debug Privilege")
        debug_btn.setObjectName("danger_button")
        debug_btn.clicked.connect(self._on_enable_debug)
        toolbar.addWidget(debug_btn)

        dup_token_btn = QPushButton("Duplicate Token")
        dup_token_btn.setObjectName("tool_button")
        dup_token_btn.setToolTip("Duplicate the process's primary token via DuplicateTokenEx")
        dup_token_btn.clicked.connect(self._on_duplicate_token)
        toolbar.addWidget(dup_token_btn)

        toolbar.addWidget(QLabel("Privilege:"))
        self._remove_priv_name = QLineEdit()
        self._remove_priv_name.setMaximumWidth(200)
        self._remove_priv_name.setPlaceholderText("SeShutdownPrivilege")
        toolbar.addWidget(self._remove_priv_name)

        remove_priv_btn = QPushButton("Remove Privilege")
        remove_priv_btn.setObjectName("danger_button")
        remove_priv_btn.clicked.connect(self._on_remove_privilege)
        toolbar.addWidget(remove_priv_btn)

        tab_layout.addWidget(toolbar)

        self._priv_table = QTableWidget(0, 4)
        self._priv_table.setHorizontalHeaderLabels(["Privilege Name", "LUID", "Enabled", "Attributes"])
        self._priv_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        ph = self._priv_table.horizontalHeader()
        if ph is not None:
            ph.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._priv_table)

        self._token_status = QLabel("")
        self._token_status.setObjectName("toolbar_label")
        tab_layout.addWidget(self._token_status)
        return tab

    def _build_windows_tab(self) -> QWidget:
        """Build the windows enumeration sub-tab.

        Returns:
            QWidget: Windows tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        enum_btn = QPushButton("Enumerate Windows")
        enum_btn.setObjectName("tool_button")
        enum_btn.clicked.connect(self._refresh_windows)
        toolbar.addWidget(enum_btn)

        tab_layout.addWidget(toolbar)

        self._win_table = QTableWidget(0, 4)
        self._win_table.setHorizontalHeaderLabels(["HWND", "Title", "Class Name", "Visible"])
        self._win_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        wh = self._win_table.horizontalHeader()
        if wh is not None:
            wh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            wh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        tab_layout.addWidget(self._win_table)
        return tab

    def _build_services_tab(self) -> QWidget:
        """Build the services enumeration sub-tab.

        Returns:
            QWidget: Services tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        enum_btn = QPushButton("Enumerate Services")
        enum_btn.setObjectName("tool_button")
        enum_btn.clicked.connect(self._refresh_services)
        toolbar.addWidget(enum_btn)

        toolbar.addSeparator()

        enum_all_btn = QPushButton("Enumerate All Services")
        enum_all_btn.setObjectName("tool_button")
        enum_all_btn.setToolTip("Enumerate every Win32 service registered with the Service Control Manager")
        enum_all_btn.clicked.connect(self._on_enumerate_all_services)
        toolbar.addWidget(enum_all_btn)

        self._svc_active_only = QCheckBox("Active only")
        self._svc_active_only.setToolTip("Limit the system-wide enumeration to services that are currently running")
        toolbar.addWidget(self._svc_active_only)

        tab_layout.addWidget(toolbar)

        self._svc_table = QTableWidget(0, 5)
        self._svc_table.setHorizontalHeaderLabels(["Name", "Display Name", "State", "PID", "Type"])
        self._svc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        svh = self._svc_table.horizontalHeader()
        if svh is not None:
            svh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._svc_table)
        return tab

    def _build_peb_teb_tab(self) -> QWidget:
        """Build the PEB/TEB inspection sub-tab.

        Returns:
            QWidget: PEB/TEB tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        peb_btn = QPushButton("Read PEB")
        peb_btn.setObjectName("tool_button")
        peb_btn.clicked.connect(self._on_read_peb)
        toolbar.addWidget(peb_btn)

        teb_btn = QPushButton("Read TEB")
        teb_btn.setObjectName("tool_button")
        teb_btn.clicked.connect(self._on_read_teb)
        toolbar.addWidget(teb_btn)

        toolbar.addWidget(QLabel("Thread:"))
        self._teb_combo = QComboBox()
        self._teb_combo.setMinimumWidth(120)
        toolbar.addWidget(self._teb_combo)

        tab_layout.addWidget(toolbar)

        self._peb_tree = QTreeWidget()
        self._peb_tree.setHeaderLabels(["Field", "Value"])
        pth = self._peb_tree.header()
        if pth is not None:
            pth.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._peb_tree)
        return tab

    def _build_pipes_tab(self) -> QWidget:
        """Build the named pipes sub-tab.

        Returns:
            QWidget: Pipes tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("Pipe:"))
        self._pipe_name = QLineEdit()
        self._pipe_name.setMaximumWidth(300)
        self._pipe_name.setPlaceholderText("\\\\.\\pipe\\MyPipe")
        toolbar.addWidget(self._pipe_name)

        connect_btn = QPushButton("Connect")
        connect_btn.setObjectName("tool_button")
        connect_btn.clicked.connect(self._on_pipe_connect)
        toolbar.addWidget(connect_btn)

        close_btn = QPushButton("Close")
        close_btn.setObjectName("tool_button")
        close_btn.clicked.connect(self._on_pipe_close)
        toolbar.addWidget(close_btn)

        tab_layout.addWidget(toolbar)

        self._pipe_table = QTableWidget(0, 2)
        self._pipe_table.setHorizontalHeaderLabels(["Pipe Name", "Handle"])
        pih = self._pipe_table.horizontalHeader()
        if pih is not None:
            pih.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._pipe_table)

        io_toolbar = QToolBar()
        io_toolbar.setMovable(False)
        io_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        io_toolbar.addWidget(QLabel("Read Size:"))
        self._pipe_read_size = QSpinBox()
        self._pipe_read_size.setRange(1, 0x100000)
        self._pipe_read_size.setValue(4096)
        io_toolbar.addWidget(self._pipe_read_size)

        read_btn = QPushButton("Read")
        read_btn.setObjectName("tool_button")
        read_btn.clicked.connect(self._on_pipe_read)
        io_toolbar.addWidget(read_btn)

        write_btn = QPushButton("Write")
        write_btn.setObjectName("tool_button")
        write_btn.clicked.connect(self._on_pipe_write)
        io_toolbar.addWidget(write_btn)

        tab_layout.addWidget(io_toolbar)

        tab_layout.addWidget(QLabel("Data (hex bytes):"))
        self._pipe_io_data = QPlainTextEdit()
        self._pipe_io_data.setPlaceholderText("Enter hex bytes to write (e.g., 90 90 CC 48 8B 05)... reads render here")
        self._pipe_io_data.setMaximumHeight(120)
        tab_layout.addWidget(self._pipe_io_data)

        self._pipe_io_status = QLabel("")
        self._pipe_io_status.setObjectName("toolbar_label")
        tab_layout.addWidget(self._pipe_io_status)
        return tab

    def _build_mitigations_tab(self) -> QWidget:
        """Build the mitigation policies sub-tab.

        Returns:
            QWidget: Mitigations tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        query_btn = QPushButton("Query Mitigations")
        query_btn.setObjectName("tool_button")
        query_btn.clicked.connect(self._refresh_mitigations)
        toolbar.addWidget(query_btn)

        kernel_dbg_btn = QPushButton("Detect Kernel Debugger")
        kernel_dbg_btn.setObjectName("tool_button")
        kernel_dbg_btn.setToolTip("Query NtQueryInformationProcess(ProcessDebugPort) for an attached kernel debugger")
        kernel_dbg_btn.clicked.connect(self._on_detect_kernel_debugger)
        toolbar.addWidget(kernel_dbg_btn)

        summary_btn = QPushButton("Summary Policy")
        summary_btn.setObjectName("tool_button")
        summary_btn.setToolTip(
            "Query a flat DEP/ASLR/CFG/SEHOP mitigation summary for the attached process (or this process when detached)",
        )
        summary_btn.clicked.connect(self._on_mitigation_summary)
        toolbar.addWidget(summary_btn)

        extension_btn = QPushButton("Extension Policy")
        extension_btn.setObjectName("tool_button")
        extension_btn.setToolTip(
            "Query the extension-point disable mitigation policy for the attached process (or this process when detached)",
        )
        extension_btn.clicked.connect(self._on_extension_policy)
        toolbar.addWidget(extension_btn)

        self._kernel_dbg_status = QLabel("")
        self._kernel_dbg_status.setObjectName("toolbar_label")
        toolbar.addWidget(self._kernel_dbg_status)

        tab_layout.addWidget(toolbar)

        self._mit_table = QTableWidget(0, 3)
        self._mit_table.setHorizontalHeaderLabels(["Policy", "Enabled", "Flags"])
        self._mit_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        mh = self._mit_table.horizontalHeader()
        if mh is not None:
            mh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._mit_table)
        return tab

    def _build_advanced_tab(self) -> QWidget:
        """Build the advanced operations sub-tab with nested tabs.

        Returns:
            QWidget: Advanced tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)

        nested = QTabWidget()
        nested.addTab(self._build_registry_section(), "Registry")
        nested.addTab(self._build_resources_section(), "Resources")
        nested.addTab(self._build_raw_query_section(), "Raw Query")

        tab_layout.addWidget(nested)
        return tab

    def _build_registry_section(self) -> QWidget:
        """Build the registry sub-section of the advanced tab.

        Returns:
            QWidget: Registry section widget.
        """
        reg_tab = QWidget()
        reg_layout = QVBoxLayout(reg_tab)
        reg_layout.setContentsMargins(0, 0, 0, 0)
        reg_layout.setSpacing(_SPACING)

        reg_toolbar = QToolBar()
        reg_toolbar.setMovable(False)
        reg_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        reg_toolbar.addWidget(QLabel("Key:"))
        self._reg_key = QLineEdit()
        self._reg_key.setMinimumWidth(300)
        self._reg_key.setPlaceholderText("HKLM\\SOFTWARE\\...")
        reg_toolbar.addWidget(self._reg_key)

        reg_toolbar.addWidget(QLabel("Value:"))
        self._reg_value_name = QLineEdit()
        self._reg_value_name.setMaximumWidth(150)
        reg_toolbar.addWidget(self._reg_value_name)

        read_val_btn = QPushButton("Read Value")
        read_val_btn.setObjectName("tool_button")
        read_val_btn.clicked.connect(self._on_reg_read)
        reg_toolbar.addWidget(read_val_btn)

        enum_keys_btn = QPushButton("Enum Keys")
        enum_keys_btn.setObjectName("tool_button")
        enum_keys_btn.clicked.connect(self._on_reg_enum_keys)
        reg_toolbar.addWidget(enum_keys_btn)

        enum_vals_btn = QPushButton("Enum Values")
        enum_vals_btn.setObjectName("tool_button")
        enum_vals_btn.clicked.connect(self._on_reg_enum_values)
        reg_toolbar.addWidget(enum_vals_btn)

        reg_layout.addWidget(reg_toolbar)

        typed_toolbar = QToolBar()
        typed_toolbar.setMovable(False)
        typed_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        typed_toolbar.addWidget(QLabel("Hive:"))
        self._reg_hive = QComboBox()
        self._reg_hive.addItems(["HKLM", "HKCU", "HKCR", "HKU", "HKCC"])
        typed_toolbar.addWidget(self._reg_hive)

        typed_toolbar.addWidget(QLabel("Key Path:"))
        self._reg_typed_key = QLineEdit()
        self._reg_typed_key.setMinimumWidth(240)
        self._reg_typed_key.setPlaceholderText("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
        typed_toolbar.addWidget(self._reg_typed_key)

        typed_toolbar.addWidget(QLabel("Value:"))
        self._reg_typed_value = QLineEdit()
        self._reg_typed_value.setMaximumWidth(150)
        self._reg_typed_value.setPlaceholderText("ProductName")
        typed_toolbar.addWidget(self._reg_typed_value)

        read_typed_btn = QPushButton("Read (Typed)")
        read_typed_btn.setObjectName("tool_button")
        read_typed_btn.setToolTip("Read a registry value with explicit hive/key/value inputs, reporting the Windows REG_* type name")
        read_typed_btn.clicked.connect(self._on_read_registry_typed)
        typed_toolbar.addWidget(read_typed_btn)

        reg_layout.addWidget(typed_toolbar)

        self._reg_tree = QTreeWidget()
        self._reg_tree.setHeaderLabels(["Key/Value", "Data"])
        rth = self._reg_tree.header()
        if rth is not None:
            rth.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        reg_layout.addWidget(self._reg_tree)

        return reg_tab

    def _build_resources_section(self) -> QWidget:
        """Build the resources sub-section of the advanced tab.

        Returns:
            QWidget: Resources section widget.
        """
        res_tab = QWidget()
        res_layout = QVBoxLayout(res_tab)
        res_layout.setContentsMargins(0, 0, 0, 0)
        res_layout.setSpacing(_SPACING)

        res_toolbar = QToolBar()
        res_toolbar.setMovable(False)
        res_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        gui_btn = QPushButton("Get GUI Resources")
        gui_btn.setObjectName("tool_button")
        gui_btn.clicked.connect(self._on_gui_resources)
        res_toolbar.addWidget(gui_btn)

        job_btn = QPushButton("Get Job Info")
        job_btn.setObjectName("tool_button")
        job_btn.clicked.connect(self._on_job_info)
        res_toolbar.addWidget(job_btn)

        res_layout.addWidget(res_toolbar)

        self._res_tree = QTreeWidget()
        self._res_tree.setHeaderLabels(["Field", "Value"])
        res_layout.addWidget(self._res_tree)

        return res_tab

    def _build_raw_query_section(self) -> QWidget:
        """Build the raw query sub-section of the advanced tab.

        Returns:
            QWidget: Raw query section widget.
        """
        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        raw_layout.setContentsMargins(0, 0, 0, 0)
        raw_layout.setSpacing(_SPACING)

        raw_toolbar = QToolBar()
        raw_toolbar.setMovable(False)
        raw_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        raw_toolbar.addWidget(QLabel("Info Class:"))
        self._raw_class = QSpinBox()
        self._raw_class.setRange(0, 255)
        raw_toolbar.addWidget(self._raw_class)

        raw_toolbar.addWidget(QLabel("Buffer:"))
        self._raw_buf_size = QSpinBox()
        self._raw_buf_size.setRange(1024, 0x4000000)
        self._raw_buf_size.setValue(65536)
        raw_toolbar.addWidget(self._raw_buf_size)

        query_btn_raw = QPushButton("Query")
        query_btn_raw.setObjectName("tool_button")
        query_btn_raw.clicked.connect(self._on_raw_query)
        raw_toolbar.addWidget(query_btn_raw)

        raw_layout.addWidget(raw_toolbar)

        self._raw_output = QPlainTextEdit()
        self._raw_output.setReadOnly(True)
        self._raw_output.setObjectName("code_display")
        raw_layout.addWidget(self._raw_output)

        return raw_tab

    def _build_handles_tab(self) -> QWidget:
        """Build the system handle-enumeration sub-tab.

        Returns:
            QWidget: Handles tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("PID Filter:"))
        self._handles_pid = QLineEdit()
        self._handles_pid.setMaximumWidth(120)
        self._handles_pid.setPlaceholderText("all")
        toolbar.addWidget(self._handles_pid)

        raw_btn = QPushButton("Enumerate (Raw)")
        raw_btn.setObjectName("tool_button")
        raw_btn.setToolTip("Enumerate handles exposing the raw numeric object-type index")
        raw_btn.clicked.connect(self._on_enumerate_handles)
        toolbar.addWidget(raw_btn)

        typed_btn = QPushButton("Enumerate (Typed)")
        typed_btn.setObjectName("tool_button")
        typed_btn.setToolTip("Enumerate handles resolving each object-type index to a human-readable type name")
        typed_btn.clicked.connect(self._on_enum_handles)
        toolbar.addWidget(typed_btn)

        self._handles_status = QLabel("")
        self._handles_status.setObjectName("toolbar_label")
        toolbar.addWidget(self._handles_status)

        tab_layout.addWidget(toolbar)

        self._handles_table = QTableWidget(0, 5)
        self._handles_table.setHorizontalHeaderLabels(["PID", "Handle", "Type", "Granted Access", "Object Address"])
        self._handles_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hh = self._handles_table.horizontalHeader()
        if hh is not None:
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._handles_table)
        return tab

    def _build_processes_tab(self) -> QWidget:
        """Build the system-wide process-enumeration sub-tab.

        Returns:
            QWidget: System processes tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        enum_btn = QPushButton("Enumerate")
        enum_btn.setObjectName("tool_button")
        enum_btn.setToolTip("Enumerate every running process via a Toolhelp32 snapshot")
        enum_btn.clicked.connect(self._on_enumerate_system_processes)
        toolbar.addWidget(enum_btn)

        self._proc_status = QLabel("")
        self._proc_status.setObjectName("toolbar_label")
        toolbar.addWidget(self._proc_status)

        tab_layout.addWidget(toolbar)

        self._proc_table = QTableWidget(0, 4)
        self._proc_table.setHorizontalHeaderLabels(["PID", "Name", "Parent PID", "Thread Count"])
        self._proc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        prh = self._proc_table.horizontalHeader()
        if prh is not None:
            prh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._proc_table)
        return tab

    def _build_objects_tab(self) -> QWidget:
        """Build the kernel-objects sub-tab hosting device I/O and section groups.

        Returns:
            QWidget: Kernel objects tab widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)
        tab_layout.addWidget(self._build_device_group())
        tab_layout.addWidget(self._build_section_group())
        return tab

    def _build_device_group(self) -> QGroupBox:
        """Build the device I/O group box (open, IOCTL, close).

        Returns:
            QGroupBox: Device I/O group box.
        """
        group = QGroupBox("Device I/O")
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(_SPACING, _SPACING, _SPACING, _SPACING)
        group_layout.setSpacing(_SPACING)

        open_toolbar = QToolBar()
        open_toolbar.setMovable(False)
        open_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)
        open_toolbar.addWidget(QLabel("Device Path:"))
        self._device_path = QLineEdit()
        self._device_path.setMinimumWidth(220)
        self._device_path.setPlaceholderText("\\\\.\\MyDriver")
        open_toolbar.addWidget(self._device_path)
        open_btn = QPushButton("Open")
        open_btn.setObjectName("tool_button")
        open_btn.clicked.connect(self._on_device_open)
        open_toolbar.addWidget(open_btn)
        close_btn = QPushButton("Close")
        close_btn.setObjectName("tool_button")
        close_btn.setToolTip("Close the device handle selected in the table below")
        close_btn.clicked.connect(self._on_device_close)
        open_toolbar.addWidget(close_btn)
        group_layout.addWidget(open_toolbar)

        self._device_table = QTableWidget(0, 2)
        self._device_table.setHorizontalHeaderLabels(["Device Path", "Handle"])
        self._device_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        dth = self._device_table.horizontalHeader()
        if dth is not None:
            dth.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        group_layout.addWidget(self._device_table)

        ioctl_toolbar = QToolBar()
        ioctl_toolbar.setMovable(False)
        ioctl_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)
        ioctl_toolbar.addWidget(QLabel("IOCTL:"))
        self._ioctl_code = QLineEdit()
        self._ioctl_code.setMaximumWidth(140)
        self._ioctl_code.setPlaceholderText("0x0022E004")
        ioctl_toolbar.addWidget(self._ioctl_code)
        ioctl_toolbar.addWidget(QLabel("Input (hex):"))
        self._ioctl_input = QLineEdit()
        self._ioctl_input.setMaximumWidth(180)
        self._ioctl_input.setPlaceholderText("deadbeef")
        ioctl_toolbar.addWidget(self._ioctl_input)
        ioctl_toolbar.addWidget(QLabel("Output Size:"))
        self._ioctl_output_size = QSpinBox()
        self._ioctl_output_size.setRange(1, 0x100000)
        self._ioctl_output_size.setValue(4096)
        ioctl_toolbar.addWidget(self._ioctl_output_size)
        send_btn = QPushButton("Send IOCTL")
        send_btn.setObjectName("tool_button")
        send_btn.setToolTip("Send the IOCTL to the device handle selected in the table above")
        send_btn.clicked.connect(self._on_device_ioctl)
        ioctl_toolbar.addWidget(send_btn)
        group_layout.addWidget(ioctl_toolbar)

        self._device_output = QPlainTextEdit()
        self._device_output.setReadOnly(True)
        self._device_output.setObjectName("code_display")
        self._device_output.setMaximumHeight(120)
        group_layout.addWidget(self._device_output)

        self._device_status = QLabel("")
        self._device_status.setObjectName("toolbar_label")
        group_layout.addWidget(self._device_status)
        return group

    def _build_section_group(self) -> QGroupBox:
        """Build the section-object group box (create, map, unmap).

        Returns:
            QGroupBox: Section objects group box.
        """
        group = QGroupBox("Section Objects")
        group_layout = QVBoxLayout(group)
        group_layout.setContentsMargins(_SPACING, _SPACING, _SPACING, _SPACING)
        group_layout.setSpacing(_SPACING)

        create_toolbar = QToolBar()
        create_toolbar.setMovable(False)
        create_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)
        create_toolbar.addWidget(QLabel("Size:"))
        self._section_size = QSpinBox()
        self._section_size.setRange(1, 0x10000000)
        self._section_size.setValue(4096)
        create_toolbar.addWidget(self._section_size)
        create_toolbar.addWidget(QLabel("Name:"))
        self._section_name = QLineEdit()
        self._section_name.setMaximumWidth(180)
        self._section_name.setPlaceholderText("optional (anonymous when blank)")
        create_toolbar.addWidget(self._section_name)
        create_btn = QPushButton("Create Section")
        create_btn.setObjectName("tool_button")
        create_btn.clicked.connect(self._on_create_section)
        create_toolbar.addWidget(create_btn)
        group_layout.addWidget(create_toolbar)

        self._section_table = QTableWidget(0, 3)
        self._section_table.setHorizontalHeaderLabels(["Handle", "Name", "Size"])
        self._section_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        sth = self._section_table.horizontalHeader()
        if sth is not None:
            sth.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        group_layout.addWidget(self._section_table)

        map_toolbar = QToolBar()
        map_toolbar.setMovable(False)
        map_toolbar.setFixedHeight(_TOOLBAR_HEIGHT)
        map_toolbar.addWidget(QLabel("Map Size:"))
        self._map_size = QSpinBox()
        self._map_size.setRange(1, 0x10000000)
        self._map_size.setValue(4096)
        map_toolbar.addWidget(self._map_size)
        map_btn = QPushButton("Map")
        map_btn.setObjectName("tool_button")
        map_btn.setToolTip("Map the section selected in the table above into this process")
        map_btn.clicked.connect(self._on_map_section)
        map_toolbar.addWidget(map_btn)
        unmap_btn = QPushButton("Unmap")
        unmap_btn.setObjectName("tool_button")
        unmap_btn.setToolTip("Unmap the view selected in the table below and release its section handle")
        unmap_btn.clicked.connect(self._on_unmap_section)
        map_toolbar.addWidget(unmap_btn)
        group_layout.addWidget(map_toolbar)

        self._views_table = QTableWidget(0, 2)
        self._views_table.setHorizontalHeaderLabels(["Base Address", "Section Handle"])
        self._views_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        vth = self._views_table.horizontalHeader()
        if vth is not None:
            vth.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        group_layout.addWidget(self._views_table)

        self._section_status = QLabel("")
        self._section_status.setObjectName("toolbar_label")
        group_layout.addWidget(self._section_status)
        return group

    @staticmethod
    def _selected_int(table: QTableWidget, column: int) -> int | None:
        """Return the integer parsed from the selected row of ``table`` at ``column``.

        Args:
            table: Table to read the current selection from.
            column: Column index whose cell text is parsed via ``int(text, 0)``.

        Returns:
            int | None: Parsed integer, or None when no row is selected or the
                target cell is missing or non-numeric.
        """
        sel = table.selectionModel()
        if sel is None:
            return None
        indexes = sel.selectedRows()
        if not indexes:
            return None
        item = table.item(indexes[0].row(), column)
        if item is None:
            return None
        try:
            return int(item.text(), 0)
        except ValueError:
            return None

    @staticmethod
    def _remove_table_row_by_int(table: QTableWidget, column: int, value: int) -> None:
        """Remove the first row whose ``column`` cell parses to ``value``.

        Args:
            table: Table to mutate.
            column: Column index whose cell text is parsed via ``int(text, 0)``.
            value: Integer value identifying the row to remove.
        """
        for row in range(table.rowCount()):
            item = table.item(row, column)
            if item is None:
                continue
            try:
                parsed = int(item.text(), 0)
            except ValueError:
                continue
            if parsed == value:
                table.removeRow(row)
                return

    def _parse_optional_pid(self, text: str, action: str) -> tuple[bool, int | None]:
        """Parse an optional PID-filter string.

        Args:
            text: Raw PID text; an empty string means no filter (all processes).
            action: Action title used for the validation warning dialog and log.

        Returns:
            tuple[bool, int | None]: ``(ok, pid)`` where ``ok`` is False when the
                text was non-empty but could not be parsed as an integer, and
                ``pid`` is the parsed PID or None when the filter is empty.
        """
        stripped = text.strip()
        if not stripped:
            return True, None
        try:
            return True, int(stripped, 0)
        except ValueError:
            _logger.warning("system_tab_invalid_pid_filter", action=action, raw=stripped)
            QMessageBox.warning(self, action, f"Invalid PID: {stripped}")
            return False, None

    def _render_services(self, result: object) -> None:
        """Render a service-enumeration result list into the services table.

        Args:
            result: Raw payload returned by the bridge coroutine.
        """
        if not isinstance(result, list):
            return
        self._svc_table.setRowCount(0)
        for svc in cast("list[object]", result):
            if not isinstance(svc, dict):
                continue
            typed_svc = cast("dict[str, object]", svc)
            row = self._svc_table.rowCount()
            self._svc_table.insertRow(row)
            self._svc_table.setItem(row, 0, QTableWidgetItem(str(typed_svc.get("name", ""))))
            self._svc_table.setItem(row, 1, QTableWidgetItem(str(typed_svc.get("display_name", ""))))
            self._svc_table.setItem(row, 2, QTableWidgetItem(str(typed_svc.get("state", ""))))
            self._svc_table.setItem(row, 3, QTableWidgetItem(str(typed_svc.get("pid", 0))))
            self._svc_table.setItem(row, 4, QTableWidgetItem(str(typed_svc.get("service_type", 0))))

    def _render_handles(self, result: object, type_key: str) -> None:
        """Render a handle-enumeration result list into the handles table.

        Args:
            result: Raw payload returned by the bridge coroutine.
            type_key: Dict key holding the value shown in the Type column
                (``"object_type_index"`` for the raw enumeration or
                ``"type_name"`` for the type-resolved enumeration).
        """
        if not isinstance(result, list):
            self._handles_status.setText("No results")
            return
        typed_result = cast("list[object]", result)
        self._handles_table.setRowCount(0)
        for entry in typed_result:
            if not isinstance(entry, dict):
                continue
            typed_entry = cast("dict[str, object]", entry)
            row = self._handles_table.rowCount()
            self._handles_table.insertRow(row)
            self._handles_table.setItem(row, 0, QTableWidgetItem(str(typed_entry.get("pid", 0))))
            handle_raw = typed_entry.get("handle_value", 0)
            handle_val = handle_raw if isinstance(handle_raw, int) else 0
            self._handles_table.setItem(row, 1, QTableWidgetItem(f"0x{handle_val:X}"))
            self._handles_table.setItem(row, 2, QTableWidgetItem(str(typed_entry.get(type_key, ""))))
            access_raw = typed_entry.get("granted_access", 0)
            access_val = access_raw if isinstance(access_raw, int) else 0
            self._handles_table.setItem(row, 3, QTableWidgetItem(f"0x{access_val:X}"))
            obj_raw = typed_entry.get("object_address", 0)
            obj_val = obj_raw if isinstance(obj_raw, int) else 0
            self._handles_table.setItem(row, 4, QTableWidgetItem(f"0x{obj_val:X}"))
        self._handles_status.setText(f"{self._handles_table.rowCount()} handles")

    def _render_policy_dict(self, result: object) -> None:
        """Render a flat policy dict into the mitigation table as key/value rows.

        Args:
            result: Raw payload returned by the bridge coroutine.
        """
        if not isinstance(result, dict):
            return
        typed_result = cast("dict[str, object]", result)
        self._mit_table.setRowCount(0)
        for key, val in typed_result.items():
            row = self._mit_table.rowCount()
            self._mit_table.insertRow(row)
            self._mit_table.setItem(row, 0, QTableWidgetItem(str(key)))
            if isinstance(val, bool):
                display = "Yes" if val else "No"
            elif isinstance(val, int):
                display = f"0x{val:X}"
            else:
                display = str(val)
            self._mit_table.setItem(row, 1, QTableWidgetItem(display))
            self._mit_table.setItem(row, 2, QTableWidgetItem(""))

    def _on_enumerate_all_services(self) -> None:
        """Enumerate every Win32 service registered with the Service Control Manager."""
        if self._bridge is None:
            return
        active = self._svc_active_only.isChecked()

        def _on_success(result: object) -> None:
            self._render_services(result)

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate All Services Error", exc, log_event="system_tab_enumerate_services_failed")

        run_bridge_coroutine_logged(
            self._bridge.enumerate_services(active=active),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_enumerate_services",
            logger=_logger,
            active=active,
        )

    def _on_enumerate_handles(self) -> None:
        """Enumerate open handles exposing the raw numeric object-type index."""
        if self._bridge is None:
            return
        ok, pid = self._parse_optional_pid(self._handles_pid.text(), "Enumerate Handles")
        if not ok:
            return

        def _on_success(result: object) -> None:
            self._render_handles(result, "object_type_index")

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate Handles Error", exc, log_event="system_tab_enumerate_handles_failed")

        run_bridge_coroutine_logged(
            self._bridge.enumerate_handles(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_enumerate_handles",
            logger=_logger,
            pid=pid,
        )

    def _on_enum_handles(self) -> None:
        """Enumerate open handles with each object-type index resolved to a type name."""
        if self._bridge is None:
            return
        ok, pid = self._parse_optional_pid(self._handles_pid.text(), "Enumerate Handles")
        if not ok:
            return

        def _on_success(result: object) -> None:
            self._render_handles(result, "type_name")

        def _on_error(exc: object) -> None:
            self._show_error("Resolve Handle Types Error", exc, log_event="system_tab_enum_handles_failed")

        run_bridge_coroutine_logged(
            self._bridge.enum_handles(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_enum_handles",
            logger=_logger,
            pid=pid,
        )

    def _on_enumerate_system_processes(self) -> None:
        """Enumerate every running process and render the full system list."""
        if self._bridge is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            typed_result = cast("list[object]", result)
            self._proc_table.setRowCount(0)
            for entry in typed_result:
                if not isinstance(entry, dict):
                    continue
                typed_entry = cast("dict[str, object]", entry)
                row = self._proc_table.rowCount()
                self._proc_table.insertRow(row)
                self._proc_table.setItem(row, 0, QTableWidgetItem(str(typed_entry.get("pid", 0))))
                self._proc_table.setItem(row, 1, QTableWidgetItem(str(typed_entry.get("name", ""))))
                self._proc_table.setItem(row, 2, QTableWidgetItem(str(typed_entry.get("parent_pid", 0))))
                self._proc_table.setItem(row, 3, QTableWidgetItem(str(typed_entry.get("thread_count", 0))))
            self._proc_status.setText(f"{self._proc_table.rowCount()} processes")

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate System Processes Error", exc, log_event="system_tab_enumerate_system_processes_failed")

        run_bridge_coroutine_logged(
            self._bridge.enumerate_system_processes(),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_enumerate_system_processes",
            logger=_logger,
        )

    def _on_mitigation_summary(self) -> None:
        """Query the flat DEP/ASLR/CFG/SEHOP mitigation summary policy."""
        if self._bridge is None:
            return
        pid = self._attached_pid

        def _on_success(result: object) -> None:
            self._render_policy_dict(result)

        def _on_error(exc: object) -> None:
            self._show_error("Summary Policy Error", exc, log_event="system_tab_mitigation_summary_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_mitigation_policy(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_mitigation_policy",
            logger=_logger,
            pid=pid,
        )

    def _on_extension_policy(self) -> None:
        """Query the extension-point disable mitigation policy."""
        if self._bridge is None:
            return
        pid = self._attached_pid

        def _on_success(result: object) -> None:
            self._render_policy_dict(result)

        def _on_error(exc: object) -> None:
            self._show_error("Extension Policy Error", exc, log_event="system_tab_extension_policy_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_extension_policy(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_extension_policy",
            logger=_logger,
            pid=pid,
        )

    def _on_read_registry_typed(self) -> None:
        """Read a registry value with explicit hive, key path, and value inputs."""
        if self._bridge is None:
            return
        hive = self._reg_hive.currentText()
        key_path = self._reg_typed_key.text().strip()
        value_name = self._reg_typed_value.text().strip()
        if not key_path or not value_name:
            QMessageBox.warning(self, "Read Registry (Typed)", "Key path and value name are required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._reg_tree.clear()
            for k, v in typed_result.items():
                QTreeWidgetItem(self._reg_tree, [str(k), str(v)])

        def _on_error(exc: object) -> None:
            self._show_error("Read Registry (Typed) Error", exc, log_event="system_tab_read_registry_typed_failed")

        run_bridge_coroutine_logged(
            self._bridge.read_registry(hive, key_path, value_name),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_read_registry",
            logger=_logger,
            hive=hive,
            key_path=key_path,
            value_name=value_name,
        )

    def _on_device_open(self) -> None:
        """Open a device path for IOCTL communication and track its handle."""
        if self._bridge is None:
            return
        device_path = self._device_path.text().strip()
        if not device_path:
            QMessageBox.warning(self, "Open Device", "Device path is required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            self._device_handles[result] = device_path
            row = self._device_table.rowCount()
            self._device_table.insertRow(row)
            self._device_table.setItem(row, 0, QTableWidgetItem(device_path))
            self._device_table.setItem(row, 1, QTableWidgetItem(f"0x{result:X}"))
            self._device_status.setText(f"Opened {device_path} (handle 0x{result:X})")

        def _on_error(exc: object) -> None:
            self._show_error("Open Device Error", exc, log_event="system_tab_device_open_failed")

        run_bridge_coroutine_logged(
            self._bridge.device_open(device_path),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_device_open",
            logger=_logger,
            level="info",
            device_path=device_path,
        )

    def _on_device_ioctl(self) -> None:
        """Send an IOCTL to the selected device handle and render the hex output."""
        if self._bridge is None:
            return
        handle = self._selected_int(self._device_table, 1)
        if handle is None or handle not in self._device_handles:
            QMessageBox.warning(self, "Send IOCTL", "Select an open device first")
            return

        code_text = self._ioctl_code.text().strip()
        try:
            ioctl_code = int(code_text, 0)
        except ValueError:
            QMessageBox.warning(self, "Send IOCTL", f"Invalid IOCTL code: {code_text}")
            return

        input_text = self._ioctl_input.text().strip().replace(" ", "")
        input_data: str | None = input_text or None
        output_size = self._ioctl_output_size.value()

        def _on_success(result: object) -> None:
            hex_out = result if isinstance(result, str) else ""
            spaced = " ".join(hex_out[i : i + 2] for i in range(0, len(hex_out), 2))
            self._device_output.setPlainText(spaced)
            self._device_status.setText(f"IOCTL returned {len(hex_out) // 2} bytes")

        def _on_error(exc: object) -> None:
            self._show_error("Send IOCTL Error", exc, log_event="system_tab_device_ioctl_failed")

        run_bridge_coroutine_logged(
            self._bridge.device_ioctl(handle, ioctl_code, input_data, output_size),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_device_ioctl",
            logger=_logger,
            level="info",
            handle=hex(handle),
            ioctl_code=hex(ioctl_code),
            output_size=output_size,
        )

    def _on_device_close(self) -> None:
        """Close the selected device handle and drop it from the tracking table."""
        if self._bridge is None:
            return
        handle = self._selected_int(self._device_table, 1)
        if handle is None or handle not in self._device_handles:
            QMessageBox.warning(self, "Close Device", "Select an open device first")
            return

        target = handle

        def _on_success(_result: object) -> None:
            self._device_handles.pop(target, None)
            self._remove_table_row_by_int(self._device_table, 1, target)
            self._device_status.setText(f"Closed handle 0x{target:X}")

        def _on_error(exc: object) -> None:
            self._show_error("Close Device Error", exc, log_event="system_tab_device_close_failed")

        run_bridge_coroutine_logged(
            self._bridge.device_close(target),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_device_close",
            logger=_logger,
            level="info",
            handle=hex(target),
        )

    def _on_create_section(self) -> None:
        """Create a section object and track its handle in the section table."""
        if self._bridge is None:
            return
        size = self._section_size.value()
        name_text = self._section_name.text().strip()
        section_name: str | None = name_text or None

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            self._section_handles[result] = name_text
            row = self._section_table.rowCount()
            self._section_table.insertRow(row)
            self._section_table.setItem(row, 0, QTableWidgetItem(f"0x{result:X}"))
            self._section_table.setItem(row, 1, QTableWidgetItem(name_text))
            self._section_table.setItem(row, 2, QTableWidgetItem(str(size)))
            self._section_status.setText(f"Created section handle 0x{result:X}")

        def _on_error(exc: object) -> None:
            self._show_error("Create Section Error", exc, log_event="system_tab_create_section_failed")

        run_bridge_coroutine_logged(
            self._bridge.create_section(size, section_name),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_create_section",
            logger=_logger,
            level="info",
            size=size,
            section_name=section_name,
        )

    def _on_map_section(self) -> None:
        """Map the selected section into this process and track the view base."""
        if self._bridge is None:
            return
        handle = self._selected_int(self._section_table, 0)
        if handle is None or handle not in self._section_handles:
            QMessageBox.warning(self, "Map Section", "Select a created section first")
            return

        size = self._map_size.value()
        target = handle

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            self._section_views[result] = target
            row = self._views_table.rowCount()
            self._views_table.insertRow(row)
            self._views_table.setItem(row, 0, QTableWidgetItem(f"0x{result:X}"))
            self._views_table.setItem(row, 1, QTableWidgetItem(f"0x{target:X}"))
            self._section_status.setText(f"Mapped section at 0x{result:X}")

        def _on_error(exc: object) -> None:
            self._show_error("Map Section Error", exc, log_event="system_tab_map_section_failed")

        run_bridge_coroutine_logged(
            self._bridge.map_section(target, size),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_map_section",
            logger=_logger,
            level="info",
            handle=hex(target),
            size=size,
        )

    def _on_unmap_section(self) -> None:
        """Unmap the selected view and release the owning section handle."""
        if self._bridge is None:
            return
        base = self._selected_int(self._views_table, 0)
        if base is None or base not in self._section_views:
            QMessageBox.warning(self, "Unmap Section", "Select a mapped view first")
            return

        target_base = base
        owning_handle = self._section_views.get(target_base)

        def _on_success(_result: object) -> None:
            self._section_views.pop(target_base, None)
            self._remove_table_row_by_int(self._views_table, 0, target_base)
            if owning_handle is not None:
                self._section_handles.pop(owning_handle, None)
                self._remove_table_row_by_int(self._section_table, 0, owning_handle)
            self._section_status.setText(f"Unmapped view at 0x{target_base:X}")

        def _on_error(exc: object) -> None:
            self._show_error("Unmap Section Error", exc, log_event="system_tab_unmap_section_failed")

        run_bridge_coroutine_logged(
            self._bridge.unmap_section(target_base),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_unmap_section",
            logger=_logger,
            level="info",
            base_address=hex(target_base),
        )

    def _refresh_privileges(self) -> None:
        """Query token privileges for the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Query Privileges")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._priv_table.setRowCount(0)
            for priv in cast("list[object]", result):
                if not isinstance(priv, dict):
                    continue
                typed_priv = cast("dict[str, object]", priv)
                row = self._priv_table.rowCount()
                self._priv_table.insertRow(row)
                self._priv_table.setItem(row, 0, QTableWidgetItem(str(typed_priv.get("name", ""))))
                luid_hi_raw = typed_priv.get("luid_high", 0)
                luid_hi = luid_hi_raw if isinstance(luid_hi_raw, int) else 0
                luid_lo_raw = typed_priv.get("luid_low", 0)
                luid_lo = luid_lo_raw if isinstance(luid_lo_raw, int) else 0
                luid_str = f"{luid_hi:08X}:{luid_lo:08X}"
                self._priv_table.setItem(row, 1, QTableWidgetItem(luid_str))
                self._priv_table.setItem(row, 2, QTableWidgetItem("Yes" if typed_priv.get("enabled") else "No"))
                self._priv_table.setItem(row, 3, QTableWidgetItem(str(typed_priv.get("attributes", 0))))

        def _on_error(exc: object) -> None:
            self._show_error("Query Privileges Error", exc, log_event="system_tab_privileges_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_token_privileges(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_token_privileges",
            logger=_logger,
            pid=pid,
        )

    def _on_enable_debug(self) -> None:
        """Enable SeDebugPrivilege on the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Enable Debug Privilege")
        if pid is None:
            return

        def _on_success(_result: object) -> None:
            _logger.info(
                "sedebug_privilege_enabled",
                pid=pid,
                privilege="SeDebugPrivilege",
            )

        def _on_error(exc: object) -> None:
            self._show_error("Enable Debug Privilege Error", exc, log_event="system_tab_enable_debug_failed")

        run_bridge_coroutine_logged(
            self._bridge.adjust_token_privilege("SeDebugPrivilege", enable=True, pid=pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_adjust_token_privilege",
            logger=_logger,
            level="info",
            pid=pid,
            privilege="SeDebugPrivilege",
            enabled=True,
        )

    def _on_duplicate_token(self) -> None:
        """Duplicate the primary token of the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Duplicate Token")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            _logger.info("process_token_duplicated", pid=pid, handle=hex(result))
            self._token_status.setText(f"Duplicated token handle: 0x{result:X}")

        def _on_error(exc: object) -> None:
            self._show_error("Duplicate Token Error", exc, log_event="system_tab_duplicate_token_failed")

        run_bridge_coroutine_logged(
            self._bridge.duplicate_token(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_duplicate_token",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_remove_privilege(self) -> None:
        """Remove a named privilege from the attached process's token."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Remove Privilege")
        if pid is None:
            return

        privilege_name = self._remove_priv_name.text().strip()
        if not privilege_name:
            QMessageBox.warning(self, "Remove Privilege", "Privilege name is required")
            return

        reply = QMessageBox.warning(
            self,
            "Remove Privilege",
            f"Remove {privilege_name} from process {pid}'s token?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(result: object) -> None:
            removed = bool(result)
            _logger.info("process_privilege_removed", pid=pid, privilege=privilege_name, removed=removed)
            self._token_status.setText(f"Removed {privilege_name}" if removed else f"{privilege_name} was not present")

        def _on_error(exc: object) -> None:
            self._show_error("Remove Privilege Error", exc, log_event="system_tab_remove_privilege_failed")

        run_bridge_coroutine_logged(
            self._bridge.remove_privilege(pid, privilege_name),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_remove_privilege",
            logger=_logger,
            level="info",
            pid=pid,
            privilege=privilege_name,
        )

    def _refresh_windows(self) -> None:
        """Enumerate windows for the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Enumerate Windows")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._win_table.setRowCount(0)
            for win in cast("list[object]", result):
                if not isinstance(win, dict):
                    continue
                typed_win = cast("dict[str, object]", win)
                row = self._win_table.rowCount()
                self._win_table.insertRow(row)
                hwnd_raw = typed_win.get("hwnd", 0)
                hwnd_val = hwnd_raw if isinstance(hwnd_raw, int) else 0
                self._win_table.setItem(row, 0, QTableWidgetItem(f"0x{hwnd_val:X}"))
                self._win_table.setItem(row, 1, QTableWidgetItem(str(typed_win.get("title", ""))))
                class_name = str(typed_win.get("class_name", ""))
                class_name_item = QTableWidgetItem(class_name)
                class_name_item.setToolTip(class_name)
                self._win_table.setItem(row, 2, class_name_item)
                self._win_table.setItem(row, 3, QTableWidgetItem("Yes" if typed_win.get("visible") else "No"))

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate Windows Error", exc, log_event="system_tab_windows_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_windows(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_windows",
            logger=_logger,
            pid=pid,
        )

    def _refresh_services(self) -> None:
        """Enumerate services for the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Enumerate Services")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            self._render_services(result)

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate Services Error", exc, log_event="system_tab_services_failed")

        run_bridge_coroutine_logged(
            self._bridge.list_services(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_list_services",
            logger=_logger,
            pid=pid,
        )

    def _on_read_peb(self) -> None:
        """Read PEB for the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Read PEB")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._peb_tree.clear()
            for key, val in typed_result.items():
                val_str = f"0x{val:X}" if isinstance(val, int) else str(val)
                QTreeWidgetItem(self._peb_tree, [str(key), val_str])

        def _on_error(exc: object) -> None:
            self._show_error("Read PEB Error", exc, log_event="system_tab_read_peb_failed")

        run_bridge_coroutine_logged(
            self._bridge.read_peb(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_read_peb",
            logger=_logger,
            pid=pid,
        )

    def _on_read_teb(self) -> None:
        """Read TEB for the selected thread."""
        if self._bridge is None:
            return
        tid = self._teb_combo.currentData()
        if not isinstance(tid, int):
            QMessageBox.warning(self, "Read TEB", "No thread selected")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._peb_tree.clear()
            for key, val in typed_result.items():
                val_str = f"0x{val:X}" if isinstance(val, int) else str(val)
                QTreeWidgetItem(self._peb_tree, [str(key), val_str])

        def _on_error(exc: object) -> None:
            self._show_error("Read TEB Error", exc, log_event="system_tab_read_teb_failed")

        run_bridge_coroutine_logged(
            self._bridge.read_teb(tid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_read_teb",
            logger=_logger,
            tid=tid,
        )

    def _on_pipe_connect(self) -> None:
        """Connect to a named pipe."""
        if self._bridge is None:
            return
        name = self._pipe_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Connect Pipe", "Pipe name is required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, int):
                return
            _logger.info(
                "named_pipe_connected",
                pipe_name=name,
                handle=hex(result),
            )
            self._pipe_handles[name] = result
            row = self._pipe_table.rowCount()
            self._pipe_table.insertRow(row)
            self._pipe_table.setItem(row, 0, QTableWidgetItem(name))
            self._pipe_table.setItem(row, 1, QTableWidgetItem(f"0x{result:X}"))

        def _on_error(exc: object) -> None:
            self._show_error("Connect Pipe Error", exc, log_event="system_tab_pipe_connect_failed")

        run_bridge_coroutine_logged(
            self._bridge.pipe_connect(name),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_pipe_connect",
            logger=_logger,
            level="info",
            pipe_name=name,
        )

    def _selected_pipe(self) -> tuple[str, int] | None:
        """Resolve the pipe name and handle currently selected in the pipe table.

        The handle is read directly from the selected row's own handle
        cell rather than looked up by name, so that reconnecting to a
        pipe with the same name (which produces a second row with a
        different handle) can never resolve the wrong row's handle.

        Returns:
            tuple[str, int] | None: The ``(pipe_name, handle)`` pair for the
            selected row, or ``None`` if no row is selected or the row's
            handle cell cannot be parsed.
        """
        sel = self._pipe_table.selectionModel()
        if sel is None:
            return None
        indexes = sel.selectedRows()
        if not indexes:
            return None
        row = indexes[0].row()
        name_item = self._pipe_table.item(row, 0)
        handle_item = self._pipe_table.item(row, 1)
        if name_item is None or handle_item is None:
            return None
        pipe_name = name_item.text()
        try:
            handle = int(handle_item.text(), 16)
        except ValueError:
            return None
        return (pipe_name, handle)

    def _on_pipe_close(self) -> None:
        """Close the selected pipe."""
        if self._bridge is None:
            return
        selected = self._selected_pipe()
        if selected is None:
            return
        pipe_name, handle = selected

        def _on_success(_result: object) -> None:
            _logger.info(
                "named_pipe_closed",
                pipe_name=pipe_name,
                handle=hex(handle),
            )
            self._pipe_handles.pop(pipe_name, None)
            target_row = -1
            for r in range(self._pipe_table.rowCount()):
                row_name_item = self._pipe_table.item(r, 0)
                row_handle_item = self._pipe_table.item(r, 1)
                if row_name_item is None or row_handle_item is None:
                    continue
                if row_name_item.text() != pipe_name:
                    continue
                try:
                    row_handle = int(row_handle_item.text(), 16)
                except ValueError:
                    continue
                if row_handle == handle:
                    target_row = r
                    break
            if target_row >= 0:
                self._pipe_table.removeRow(target_row)

        def _on_error(exc: object) -> None:
            message = str(exc)
            _logger.warning(
                "system_tab_pipe_close_failed",
                pipe_name=pipe_name,
                error=message,
            )
            QMessageBox.warning(self, "Close Pipe Error", f"{pipe_name}: {message}")

        run_bridge_coroutine_logged(
            self._bridge.pipe_close(handle),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_pipe_close",
            logger=_logger,
            level="info",
            pipe_name=pipe_name,
            handle=hex(handle),
        )

    def _on_pipe_read(self) -> None:
        """Read data from the selected named pipe and render it as hex."""
        if self._bridge is None:
            return
        selected = self._selected_pipe()
        if selected is None:
            QMessageBox.warning(self, "Read Pipe", "Select a connected pipe first")
            return
        pipe_name, handle = selected
        size = self._pipe_read_size.value()

        def _on_success(result: object) -> None:
            if not isinstance(result, str):
                return
            _logger.info(
                "named_pipe_read",
                pipe_name=pipe_name,
                handle=hex(handle),
                bytes_read=len(result) // 2,
            )
            spaced = " ".join(result[i : i + 2] for i in range(0, len(result), 2))
            self._pipe_io_data.setPlainText(spaced)
            self._pipe_io_status.setText(f"Read {len(result) // 2} bytes from {pipe_name}")

        def _on_error(exc: object) -> None:
            self._show_error("Read Pipe Error", exc, log_event="system_tab_pipe_read_failed")

        run_bridge_coroutine_logged(
            self._bridge.pipe_read(handle, size),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_pipe_read",
            logger=_logger,
            level="info",
            pipe_name=pipe_name,
            handle=hex(handle),
            size=size,
        )

    def _on_pipe_write(self) -> None:
        """Write hex-encoded data from the input field to the selected named pipe."""
        if self._bridge is None:
            return
        selected = self._selected_pipe()
        if selected is None:
            QMessageBox.warning(self, "Write Pipe", "Select a connected pipe first")
            return
        pipe_name, handle = selected

        hex_text = self._pipe_io_data.toPlainText().strip().replace("\n", " ")
        try:
            data = bytes.fromhex(hex_text.replace(" ", ""))
        except ValueError:
            self._pipe_io_status.setText("Invalid hex data")
            return

        def _on_success(result: object) -> None:
            written = result if isinstance(result, int) else 0
            _logger.info(
                "named_pipe_written",
                pipe_name=pipe_name,
                handle=hex(handle),
                bytes_written=written,
            )
            self._pipe_io_status.setText(f"Wrote {written} bytes to {pipe_name}")

        def _on_error(exc: object) -> None:
            self._show_error("Write Pipe Error", exc, log_event="system_tab_pipe_write_failed")

        run_bridge_coroutine_logged(
            self._bridge.pipe_write(handle, data),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_pipe_write",
            logger=_logger,
            level="info",
            pipe_name=pipe_name,
            handle=hex(handle),
            data_size=len(data),
        )

    def _refresh_mitigations(self) -> None:
        """Query mitigation policies for the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Query Mitigations")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._mit_table.setRowCount(0)
            for mit_name, val in typed_result.items():
                row = self._mit_table.rowCount()
                self._mit_table.insertRow(row)
                self._mit_table.setItem(row, 0, QTableWidgetItem(str(mit_name)))
                if isinstance(val, dict):
                    typed_val = cast("dict[str, object]", val)
                    self._mit_table.setItem(row, 1, QTableWidgetItem("Yes" if typed_val.get("enabled") else "No"))
                    self._mit_table.setItem(row, 2, QTableWidgetItem(str(typed_val.get("flags", ""))))
                else:
                    self._mit_table.setItem(row, 1, QTableWidgetItem(str(val)))

        def _on_error(exc: object) -> None:
            self._show_error("Query Mitigations Error", exc, log_event="system_tab_mitigations_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_mitigation_policies(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_mitigation_policies",
            logger=_logger,
            pid=pid,
        )

    def _on_detect_kernel_debugger(self) -> None:
        """Detect whether a kernel debugger is attached to the attached process."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Detect Kernel Debugger")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            detected = bool(result)
            _logger.info("kernel_debugger_detection_completed", pid=pid, detected=detected)
            self._kernel_dbg_status.setText("Kernel debugger detected" if detected else "No kernel debugger detected")

        def _on_error(exc: object) -> None:
            self._show_error("Detect Kernel Debugger Error", exc, log_event="system_tab_detect_kernel_debugger_failed")

        run_bridge_coroutine_logged(
            self._bridge.detect_kernel_debugger(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_detect_kernel_debugger",
            logger=_logger,
            pid=pid,
        )

    def _on_reg_read(self) -> None:
        """Read a registry value."""
        if self._bridge is None:
            return
        key = self._reg_key.text().strip()
        name = self._reg_value_name.text().strip()
        if not key or not name:
            QMessageBox.warning(self, "Read Registry Value", "Registry key and value name are required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._reg_tree.clear()
            for k, v in typed_result.items():
                QTreeWidgetItem(self._reg_tree, [str(k), str(v)])

        def _on_error(exc: object) -> None:
            self._show_error("Read Registry Value Error", exc, log_event="system_tab_reg_read_failed")

        run_bridge_coroutine_logged(
            self._bridge.reg_read_value(key, name),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_reg_read_value",
            logger=_logger,
            key=key,
            value_name=name,
        )

    def _on_reg_enum_keys(self) -> None:
        """Enumerate registry subkeys."""
        if self._bridge is None:
            return
        key = self._reg_key.text().strip()
        if not key:
            QMessageBox.warning(self, "Enumerate Registry Keys", "Registry key path is required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._reg_tree.clear()
            for subkey in cast("list[object]", result):
                QTreeWidgetItem(self._reg_tree, [str(subkey), ""])

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate Registry Keys Error", exc, log_event="system_tab_reg_enum_keys_failed")

        run_bridge_coroutine_logged(
            self._bridge.reg_enum_keys(key),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_reg_enum_keys",
            logger=_logger,
            key=key,
        )

    def _on_reg_enum_values(self) -> None:
        """Enumerate registry values."""
        if self._bridge is None:
            return
        key = self._reg_key.text().strip()
        if not key:
            QMessageBox.warning(self, "Enumerate Registry Values", "Registry key path is required")
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._reg_tree.clear()
            for val_name in cast("list[object]", result):
                QTreeWidgetItem(self._reg_tree, [str(val_name), ""])

        def _on_error(exc: object) -> None:
            self._show_error("Enumerate Registry Values Error", exc, log_event="system_tab_reg_enum_values_failed")

        run_bridge_coroutine_logged(
            self._bridge.reg_enum_values(key),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_reg_enum_values",
            logger=_logger,
            key=key,
        )

    def _on_gui_resources(self) -> None:
        """Query GUI resource counts."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Get GUI Resources")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._res_tree.clear()
            for k, v in typed_result.items():
                QTreeWidgetItem(self._res_tree, [str(k), str(v)])

        def _on_error(exc: object) -> None:
            self._show_error("Get GUI Resources Error", exc, log_event="system_tab_gui_resources_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_gui_resources(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_gui_resources",
            logger=_logger,
            pid=pid,
        )

    def _on_job_info(self) -> None:
        """Query job object info."""
        if self._bridge is None:
            return
        pid = self._require_attached_pid("Get Job Info")
        if pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._res_tree.clear()
            for k, v in typed_result.items():
                QTreeWidgetItem(self._res_tree, [str(k), str(v)])

        def _on_error(exc: object) -> None:
            self._show_error("Get Job Info Error", exc, log_event="system_tab_job_info_failed")

        run_bridge_coroutine_logged(
            self._bridge.get_job_info(pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_job_info",
            logger=_logger,
            pid=pid,
        )

    def _on_raw_query(self) -> None:
        """Execute a raw NtQuerySystemInformation call."""
        if self._bridge is None:
            return
        info_class = self._raw_class.value()
        buf_size = self._raw_buf_size.value()

        def _on_success(result: object) -> None:
            data: bytes | None = None
            if isinstance(result, str):
                try:
                    data = bytes.fromhex(result)
                except ValueError:
                    _logger.debug(
                        "raw_query_hex_parse_failed",
                        length=len(result),
                        info_class=info_class,
                        exc_info=True,
                    )
                    self._raw_output.setPlainText(result)
                    return
            elif isinstance(result, (bytes, bytearray)):
                data = bytes(result)
            if data is None:
                self._raw_output.setPlainText(str(result))
                return
            hex_lines: list[str] = []
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                hex_lines.append(f"{i:08X}  {hex_str}")
            self._raw_output.setPlainText("\n".join(hex_lines))

        def _on_error(exc: object) -> None:
            self._show_error("Raw Query Error", exc, log_event="system_tab_raw_query_failed")

        run_bridge_coroutine_logged(
            self._bridge.query_system_info(info_class, buf_size),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_query_system_info",
            logger=_logger,
            info_class=info_class,
            buffer_size=buf_size,
        )
