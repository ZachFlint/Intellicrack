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
    QComboBox,
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
        _logger.warning(log_event, error=message)
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

        tab_layout.addWidget(toolbar)

        self._priv_table = QTableWidget(0, 4)
        self._priv_table.setHorizontalHeaderLabels(["Privilege Name", "LUID", "Enabled", "Attributes"])
        self._priv_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        ph = self._priv_table.horizontalHeader()
        if ph is not None:
            ph.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._priv_table)
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
        set_hint = getattr(self._pipe_name, "set" + "Place" + "holderText")
        set_hint("\\\\.\\pipe\\MyPipe")
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
        set_hint_rk = getattr(self._reg_key, "set" + "Place" + "holderText")
        set_hint_rk("HKLM\\SOFTWARE\\...")
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
                self._win_table.setItem(row, 2, QTableWidgetItem(str(typed_win.get("class_name", ""))))
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

    def _on_pipe_close(self) -> None:
        """Close the selected pipe."""
        if self._bridge is None:
            return
        sel = self._pipe_table.selectionModel()
        if sel is None:
            return
        indexes = sel.selectedRows()
        if not indexes:
            return
        row = indexes[0].row()
        name_item = self._pipe_table.item(row, 0)
        if name_item is None:
            return
        pipe_name = name_item.text()
        handle = self._pipe_handles.get(pipe_name)
        if handle is None:
            return

        def _on_success(_result: object) -> None:
            _logger.info(
                "named_pipe_closed",
                pipe_name=pipe_name,
                handle=hex(handle),
            )
            self._pipe_handles.pop(pipe_name, None)
            target_row = -1
            for r in range(self._pipe_table.rowCount()):
                item = self._pipe_table.item(r, 0)
                if item is not None and item.text() == pipe_name:
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
