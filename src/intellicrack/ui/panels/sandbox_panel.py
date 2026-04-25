# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox management panel for Intellicrack.

Provides sandbox creation, configuration, binary execution, snapshot management, and execution report viewing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import (
    get_current_tree_item,
    set_header_labels,
    set_max_block_count,
)
from intellicrack.ui.panels.vnc_widget import VNCWidget
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.sandbox_bridge import SandboxBridge
    from intellicrack.sandbox.base import ExecutionReport, SandboxBase
    from intellicrack.sandbox.manager import SandboxManager, SandboxType

_logger = get_logger(__name__)

_EXEC_MARGIN: Final[int] = 4
_EXEC_SPACING: Final[int] = 4
_SPLIT_LEFT: Final[int] = 200
_SPLIT_RIGHT: Final[int] = 400


class SandboxPanel(AnalysisPanelBase):
    """Panel for sandbox environment management and binary execution.

    Provides controls for creating and managing sandboxed environments,
    executing binaries with monitoring, taking/restoring snapshots,
    and reviewing execution reports (file, registry, network activity).

    Attributes:
        execution_completed: Signal emitted with execution ID when a sandboxed binary run finishes.
        sandbox_created: Signal emitted with sandbox instance ID when a new sandbox is created.
    """

    execution_completed: pyqtSignal = pyqtSignal(str)
    sandbox_created: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SandboxPanel widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._sandbox: SandboxBase | None = None
        self._sandbox_manager: SandboxManager | None = None
        self._bridge: SandboxBridge | None = None
        self.sandbox_id: str | None = None
        self._pending_binary: Path = Path()
        self._pending_args: list[str] = []
        self._pending_snapshot_id: str = "unknown"
        self._pending_snapshot_label: str | None = None
        self._vnc_widget: VNCWidget | None = None
        self._pcap_capture_id: str | None = None
        self._pending_copy_in_dest: str = ""
        self._pending_copy_in_source: str = ""
        self._pending_copy_out_source: str = ""
        self._pending_copy_out_dest: str = ""
        self._status_poll_timer = QTimer(self)
        self._status_poll_timer.timeout.connect(self._poll_status)

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add sandbox-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._status_indicator = self._add_toolbar_label(toolbar, "Inactive")
        fm = FontManager.get_instance()
        self._status_indicator.setFont(fm.get_ui_font_bold(9))

        toolbar.addSeparator()

        self.create_btn = self._add_tool_button(toolbar, "Create", self._on_create)
        self.destroy_btn = self._add_danger_button(toolbar, "Destroy", self._on_destroy, enabled=False)
        self.restart_btn = self._add_tool_button(toolbar, "Restart", self._on_restart, enabled=False)

        toolbar.addSeparator()

        self.snapshot_btn = self._add_tool_button(toolbar, "Take Snapshot", self._on_take_snapshot, enabled=False)
        self.restore_btn = self._add_tool_button(toolbar, "Restore Snapshot", self._on_restore_snapshot, enabled=False)

        toolbar.addSeparator()

        self._add_toolbar_label(toolbar, "Type:")

        self.sandbox_type_combo = QComboBox()
        self.sandbox_type_combo.addItems(["Windows Sandbox", "QEMU"])
        self.sandbox_type_combo.setMinimumWidth(120)
        toolbar.addWidget(self.sandbox_type_combo)

        toolbar.addSeparator()

        self.screenshot_btn = self._add_tool_button(toolbar, "Screenshot", self._on_screenshot, enabled=False)
        self.pcap_btn = self._add_tool_button(toolbar, "PCAP Start", self._on_pcap_toggle, enabled=False)
        self.memdump_btn = self._add_tool_button(toolbar, "Mem Dump", self._on_memory_dump, enabled=False)
        self.extract_files_btn = self._add_tool_button(
            toolbar,
            "Extract Files",
            self._on_extract_files,
            enabled=False,
        )

        toolbar.addSeparator()

        self.yara_btn = self._add_tool_button(toolbar, "YARA Scan", self._on_yara_scan, enabled=False)
        self.iocs_btn = self._add_tool_button(toolbar, "Extract IOCs", self._on_extract_iocs, enabled=False)
        self.timeline_btn = self._add_tool_button(toolbar, "Timeline", self._on_timeline, enabled=False)
        self.behaviors_btn = self._add_tool_button(
            toolbar,
            "Behaviors",
            self._on_detect_behaviors,
            enabled=False,
        )

        toolbar.addSeparator()

        self.copy_in_btn = self._add_tool_button(toolbar, "Copy In", self._on_copy_in, enabled=False)
        self.copy_out_btn = self._add_tool_button(toolbar, "Copy Out", self._on_copy_out, enabled=False)

        toolbar.addSeparator()

        self.continue_btn = self._add_tool_button(toolbar, "Continue VM", self._on_continue_vm, enabled=False)
        self.delete_snap_btn = self._add_tool_button(
            toolbar,
            "Delete Snap",
            self._on_delete_snapshot,
            enabled=False,
        )

    @override
    def _create_content(self) -> QWidget:
        """Create the sandbox management content area.

        Returns:
            QWidget: Splitter with execution controls and output tabs.
        """
        fm = FontManager.get_instance()
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        exec_container = QWidget()
        exec_layout = QVBoxLayout(exec_container)
        exec_layout.setContentsMargins(_EXEC_MARGIN, _EXEC_MARGIN, _EXEC_MARGIN, _EXEC_MARGIN)
        exec_layout.setSpacing(_EXEC_SPACING)

        exec_header = QLabel("Binary Execution")
        exec_header.setFont(fm.get_heading_font(10))
        exec_layout.addWidget(exec_header)

        path_row = QHBoxLayout()
        path_label = QLabel("Binary:")
        path_label.setObjectName("toolbar_label")
        path_row.addWidget(path_label)

        self._binary_path_input = QLineEdit()
        self._binary_path_input.setFont(fm.get_code_font(9))
        path_row.addWidget(self._binary_path_input)

        self._browse_btn = QPushButton("Browse...")
        self._browse_btn.setObjectName("secondary_button")
        self._browse_btn.clicked.connect(self._on_browse_binary)
        path_row.addWidget(self._browse_btn)
        exec_layout.addLayout(path_row)

        args_row = QHBoxLayout()
        args_label = QLabel("Arguments:")
        args_label.setObjectName("toolbar_label")
        args_row.addWidget(args_label)

        self._args_input = QLineEdit()
        self._args_input.setFont(fm.get_code_font(9))
        args_row.addWidget(self._args_input)

        self._run_btn = QPushButton("Run in Sandbox")
        self._run_btn.setObjectName("tool_button")
        self._run_btn.setEnabled(False)
        self._run_btn.clicked.connect(self._on_run_binary)
        args_row.addWidget(self._run_btn)
        exec_layout.addLayout(args_row)

        cmd_row = QHBoxLayout()
        cmd_label = QLabel("Command:")
        cmd_label.setObjectName("toolbar_label")
        cmd_row.addWidget(cmd_label)

        self._cmd_input = QLineEdit()
        self._cmd_input.setFont(fm.get_code_font(9))
        self._cmd_input.setPlaceholderText("Execute command in sandbox...")
        cmd_row.addWidget(self._cmd_input)

        self._exec_cmd_btn = QPushButton("Execute")
        self._exec_cmd_btn.setObjectName("tool_button")
        self._exec_cmd_btn.setEnabled(False)
        self._exec_cmd_btn.clicked.connect(self._on_execute_command)
        cmd_row.addWidget(self._exec_cmd_btn)
        exec_layout.addLayout(cmd_row)

        main_splitter.addWidget(exec_container)

        output_tabs = QTabWidget()

        self._console_output = QPlainTextEdit()
        self._console_output.setFont(fm.get_code_font(9))
        self._console_output.setReadOnly(ro=True)
        set_max_block_count(self._console_output, 10000)
        output_tabs.addTab(self._console_output, "Console")

        self._file_changes_tree = QTreeWidget()
        set_header_labels(self._file_changes_tree, ["Operation", "Path", "Details"])
        output_tabs.addTab(self._file_changes_tree, "File Changes")

        self._registry_changes_tree = QTreeWidget()
        set_header_labels(self._registry_changes_tree, ["Operation", "Key", "Value"])
        output_tabs.addTab(self._registry_changes_tree, "Registry Changes")

        self._network_tree = QTreeWidget()
        set_header_labels(self._network_tree, ["Protocol", "Destination", "Port", "Data Size"])
        output_tabs.addTab(self._network_tree, "Network Activity")

        self._snapshots_tree = QTreeWidget()
        set_header_labels(self._snapshots_tree, ["ID", "Name", "Created"])
        output_tabs.addTab(self._snapshots_tree, "Snapshots")

        vnc_w = VNCWidget()
        self._vnc_widget = vnc_w

        def _vnc_status_slot(c: int) -> None:
            self._on_vnc_status_changed(connected=bool(c))

        vnc_w.connection_status_changed.connect(_vnc_status_slot)
        output_tabs.addTab(vnc_w, "VM Display")

        self._api_calls_tree = QTreeWidget()
        set_header_labels(self._api_calls_tree, ["Timestamp", "Process", "API", "Module", "Args", "Return"])
        output_tabs.addTab(self._api_calls_tree, "API Calls")

        self._dll_loads_tree = QTreeWidget()
        set_header_labels(self._dll_loads_tree, ["Timestamp", "Process", "DLL Path", "Base Addr", "Size"])
        output_tabs.addTab(self._dll_loads_tree, "DLL Loads")

        self._services_tree = QTreeWidget()
        set_header_labels(self._services_tree, ["Operation", "Name", "Binary Path", "Start Type", "Time"])
        output_tabs.addTab(self._services_tree, "Services")

        self._kernel_objects_tree = QTreeWidget()
        set_header_labels(self._kernel_objects_tree, ["Type", "Name", "Process", "Operation", "Timestamp"])
        output_tabs.addTab(self._kernel_objects_tree, "Kernel Objects")

        self._injections_tree = QTreeWidget()
        set_header_labels(self._injections_tree, ["Type", "Source", "Target", "APIs", "Timestamp"])
        output_tabs.addTab(self._injections_tree, "Injections")

        self._resources_tree = QTreeWidget()
        set_header_labels(
            self._resources_tree,
            ["Timestamp", "CPU%", "Mem MB", "Disk R", "Disk W", "Net S", "Net R"],
        )
        output_tabs.addTab(self._resources_tree, "Resources")

        self._clipboard_tree = QTreeWidget()
        set_header_labels(self._clipboard_tree, ["Timestamp", "Op", "Format", "Preview", "Size"])
        output_tabs.addTab(self._clipboard_tree, "Clipboard")

        self._timeline_tree = QTreeWidget()
        set_header_labels(self._timeline_tree, ["Timestamp", "Category", "Summary"])
        output_tabs.addTab(self._timeline_tree, "Timeline")

        self._iocs_tree = QTreeWidget()
        set_header_labels(self._iocs_tree, ["Type", "Value", "Source", "Context"])
        output_tabs.addTab(self._iocs_tree, "IOCs")

        self._behaviors_tree = QTreeWidget()
        set_header_labels(
            self._behaviors_tree,
            ["Signature", "Category", "Severity", "MITRE", "Description"],
        )
        output_tabs.addTab(self._behaviors_tree, "Behaviors")

        self._instances_tree = QTreeWidget()
        set_header_labels(self._instances_tree, ["ID", "Type", "Status", "Created", "Last Used", "Binary"])
        output_tabs.addTab(self._instances_tree, "Instances")

        main_splitter.addWidget(output_tabs)

        main_splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Stop the status poll timer, disconnect VNC, and shut down the sandbox."""
        self._disconnect_vnc_display()
        self._status_poll_timer.stop()
        if self._bridge is not None and self.sandbox_id is not None:
            try:
                run_bridge_coroutine(self._bridge.destroy(self.sandbox_id))
            except (RuntimeError, ConnectionError, OSError):
                _logger.warning(
                    "sandbox_cleanup_destroy_skipped",
                    sandbox_id=self.sandbox_id,
                    exc_info=True,
                )

    def set_bridge(self, bridge: SandboxBridge) -> None:
        """Set the sandbox bridge for all operations.

        Args:
            bridge: The SandboxBridge instance.
        """
        self._bridge = bridge
        _logger.info("sandbox_bridge_set", bridge_type=type(bridge).__name__)

    def get_bridge(self) -> SandboxBridge | None:
        """Get the current sandbox bridge.

        Returns:
            SandboxBridge | None: The attached bridge or None.
        """
        return self._bridge

    def set_sandbox(self, sandbox: SandboxBase) -> None:
        """Set the sandbox backend instance (deprecated).

        Args:
            sandbox: The SandboxBase implementation to use.
        """
        self._sandbox = sandbox
        _logger.warning("sandbox_set_deprecated", note="Use set_bridge() instead")

    def set_sandbox_manager(self, manager: SandboxManager) -> None:
        """Set the sandbox manager (deprecated).

        Args:
            manager: The SandboxManager instance.
        """
        self._sandbox_manager = manager
        _logger.warning("sandbox_manager_set_deprecated", note="Use set_bridge() instead")

    def get_sandbox(self) -> SandboxBase | None:
        """Get the current sandbox backend (deprecated).

        Returns:
            SandboxBase | None: The attached sandbox or None.
        """
        _logger.warning("get_sandbox_deprecated", note="Use get_bridge() instead")
        return self._sandbox

    def _log(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        self._console_output.appendPlainText(message)

    def _set_sandbox_controls_active(self, *, active: bool) -> None:
        """Enable or disable controls based on sandbox state.

        Args:
            active: True to enable sandbox-active controls.
        """
        self.create_btn.setEnabled(not active)
        self.destroy_btn.setEnabled(active)
        self.restart_btn.setEnabled(active)
        self._run_btn.setEnabled(active)
        self.snapshot_btn.setEnabled(active)
        self.restore_btn.setEnabled(active)
        self.screenshot_btn.setEnabled(active)
        self.pcap_btn.setEnabled(active)
        self.memdump_btn.setEnabled(active)
        self.extract_files_btn.setEnabled(active)
        self.yara_btn.setEnabled(active)
        self.iocs_btn.setEnabled(active)
        self.timeline_btn.setEnabled(active)
        self.behaviors_btn.setEnabled(active)
        self.copy_in_btn.setEnabled(active)
        self.copy_out_btn.setEnabled(active)
        self.continue_btn.setEnabled(active)
        self.delete_snap_btn.setEnabled(active)
        self._exec_cmd_btn.setEnabled(active)

    def _selected_sandbox_type(self) -> SandboxType:
        """Get the sandbox type from the combo box selection.

        Returns:
            SandboxType: Sandbox type literal: ``"windows"`` or ``"qemu"``.
        """
        combo_text = self.sandbox_type_combo.currentText()
        return "qemu" if combo_text == "QEMU" else "windows"

    def _on_create(self) -> None:
        """Create a new sandbox environment."""
        if self._bridge is None:
            self._log("[!] No sandbox bridge configured")
            _logger.warning("sandbox_create_failed_no_bridge")
            return

        sandbox_type = self._selected_sandbox_type()
        _logger.debug("sandbox_create_via_bridge", sandbox_type=sandbox_type)
        self.create_btn.setEnabled(False)
        self._run_async(
            self._bridge.create(sandbox_type=sandbox_type),
            on_success=self._on_bridge_create_success,
            on_error=self._on_create_error,
        )

    def _on_bridge_create_success(self, result: object) -> None:
        """Handle successful sandbox creation via bridge.

        Args:
            result: Dictionary with instance_id and status from bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            self.sandbox_id = str(typed.get("instance_id", "active"))
        else:
            self.sandbox_id = "active"
        self._on_create_success(None)

    def _on_create_success(self, _result: object) -> None:
        """Handle successful sandbox creation.

        Args:
            _result: Bridge call result (unused).
        """
        if self.sandbox_id is None:
            self.sandbox_id = "active"
        self._log("[+] Sandbox created")
        self._status_indicator.setText("Active")
        self._set_sandbox_controls_active(active=True)
        self.create_btn.setEnabled(False)
        self._status_poll_timer.start(5000)
        self.sandbox_created.emit(self.sandbox_id)
        self.tool_started.emit()
        _logger.info("sandbox_created", sandbox_id=self.sandbox_id)

        QTimer.singleShot(2000, self._connect_vnc_display)

    def _on_create_error(self, exc: object) -> None:
        """Handle sandbox creation failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to create sandbox: {exc}")
        self.create_btn.setEnabled(True)
        _logger.warning("sandbox_create_failed", error=str(exc))

    def _on_destroy(self) -> None:
        """Destroy the current sandbox environment."""
        if self._bridge is None or self.sandbox_id is None:
            return

        _logger.info("sandbox_destroy_started", sandbox_id=self.sandbox_id)
        self.destroy_btn.setEnabled(False)
        self._run_async(
            self._bridge.destroy(self.sandbox_id),
            on_success=self._on_destroy_success,
            on_error=self._on_destroy_error,
        )

    def _on_destroy_success(self, _result: object) -> None:
        """Handle successful sandbox destruction.

        Args:
            _result: Bridge call result (unused).
        """
        self._disconnect_vnc_display()
        self._log("[+] Sandbox destroyed")
        self.sandbox_id = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(active=False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()
        _logger.info("sandbox_destroyed", sandbox_id=self.sandbox_id)

    def _on_destroy_error(self, exc: object) -> None:
        """Handle sandbox destruction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to destroy sandbox: {exc}")
        self.sandbox_id = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(active=False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()
        _logger.warning("sandbox_destroy_failed", error=str(exc))

    def _on_restart(self) -> None:
        """Restart the sandbox environment."""
        if self._bridge is None or self.sandbox_id is None:
            return

        _logger.debug("sandbox_restart_started", sandbox_id=self.sandbox_id)
        self.restart_btn.setEnabled(False)
        self._run_async(
            self._bridge.destroy(self.sandbox_id),
            on_success=self._on_restart_destroy_success,
            on_error=self._on_restart_error,
        )

    def _on_restart_destroy_success(self, _result: object) -> None:
        """Handle destroy phase of restart, proceed to create.

        Args:
            _result: Bridge call result (unused).
        """
        if self._bridge is None:
            self.restart_btn.setEnabled(True)
            return

        sandbox_type = self._selected_sandbox_type()
        self._run_async(
            self._bridge.create(sandbox_type=sandbox_type),
            on_success=self._on_restart_create_success,
            on_error=self._on_restart_error,
        )

    def _on_restart_create_success(self, result: object) -> None:
        """Handle successful create phase of restart.

        Args:
            result: Dictionary with instance_id from bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            self.sandbox_id = str(typed.get("instance_id", "active"))
        self._log("[+] Sandbox restarted")
        self._clear_report_tabs()
        self.restart_btn.setEnabled(True)
        _logger.info("sandbox_restarted", sandbox_id=self.sandbox_id)

    def _on_restart_error(self, exc: object) -> None:
        """Handle sandbox restart failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to restart sandbox: {exc}")
        self.restart_btn.setEnabled(True)
        _logger.warning("sandbox_restart_failed", error=str(exc))

    def _on_browse_binary(self) -> None:
        """Browse for a binary to execute in the sandbox."""
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary",
            "",
            "Executables (*.exe *.dll *.msi);;All Files (*)",
        )
        if path_str:
            self._binary_path_input.setText(path_str)

    def _on_run_binary(self) -> None:
        """Execute the selected binary inside the sandbox."""
        if self._bridge is None:
            self._log("[!] No sandbox bridge active")
            return

        binary_path = self._binary_path_input.text().strip()
        if not binary_path:
            self._log("[!] No binary path specified")
            return

        binary = Path(binary_path)
        if not binary.exists():
            self._log(f"[!] Binary not found: {binary_path}")
            return

        args = self._args_input.text().strip()
        args_list = args.split() if args else None
        sandbox_type = self._selected_sandbox_type()

        self._log(f"[*] Executing: {binary.name} {args}")
        self._clear_report_tabs()
        self._run_btn.setEnabled(False)
        self._pending_binary = binary
        _logger.debug("sandbox_binary_execution_started", binary=binary.name, exec_args=args)

        self._run_async(
            self._bridge.run_binary(
                binary_path=binary_path,
                args=args_list,
                sandbox_type=sandbox_type,
            ),
            on_success=self._on_run_binary_success,
            on_error=self._on_run_binary_error,
        )

    def _on_run_binary_success(self, result: object) -> None:
        """Handle successful binary execution.

        Args:
            result: Dictionary with execution report from bridge.
        """
        binary_name = self._pending_binary.name
        self._log("[+] Execution completed")
        self._run_btn.setEnabled(True)
        self.execution_completed.emit(binary_name)
        _logger.info("sandbox_binary_executed", binary=binary_name)

        if isinstance(result, dict):
            self._display_report_dict(cast("dict[str, Any]", result))

    def _display_report_dict(self, report: dict[str, Any]) -> None:
        """Populate output tabs from a bridge execution report dictionary.

        Args:
            report: Dictionary returned by the bridge's run_binary.
        """
        stdout = report.get("stdout")
        stderr = report.get("stderr")
        if isinstance(stdout, str) and stdout:
            self._console_output.appendPlainText(f"[stdout] {stdout}")
        if isinstance(stderr, str) and stderr:
            self._console_output.appendPlainText(f"[stderr] {stderr}")

        self._log(f"[*] Exit code: {report.get('exit_code')}, Duration: {report.get('duration_seconds')}s")

        self._populate_file_changes(report.get("file_changes"))
        self._populate_registry_changes(report.get("registry_changes"))
        self._populate_network_activity(report.get("network_activity"))
        self._populate_api_calls(report.get("api_calls"))
        self._populate_dll_loads(report.get("dll_loads"))
        self._populate_service_changes(report.get("service_changes"))
        self._populate_kernel_objects(report.get("kernel_objects"))
        self._populate_injection_events(report.get("injection_events"))
        self._populate_resource_samples(report.get("resource_samples"))
        self._populate_clipboard_events(report.get("clipboard_events"))

    def _populate_file_changes(self, file_changes: object) -> None:
        """Populate the file changes tree from report data.

        Args:
            file_changes: List of file change dictionaries.
        """
        if not isinstance(file_changes, list):
            return
        typed_changes = cast("list[object]", file_changes)
        for raw_change in typed_changes:
            if isinstance(raw_change, dict):
                change = cast("dict[str, object]", raw_change)
                item = QTreeWidgetItem([
                    str(change.get("operation", "")),
                    str(change.get("path", "")),
                    str(change.get("size", "")),
                ])
                self._file_changes_tree.addTopLevelItem(item)

    def _populate_registry_changes(self, registry_changes: object) -> None:
        """Populate the registry changes tree from report data.

        Args:
            registry_changes: List of registry change dictionaries.
        """
        if not isinstance(registry_changes, list):
            return
        typed_regs = cast("list[object]", registry_changes)
        for raw_reg in typed_regs:
            if isinstance(raw_reg, dict):
                reg = cast("dict[str, object]", raw_reg)
                item = QTreeWidgetItem([
                    str(reg.get("operation", "")),
                    str(reg.get("key", "")),
                    str(reg.get("value_data", "")),
                ])
                self._registry_changes_tree.addTopLevelItem(item)

    def _populate_network_activity(self, network_activity: object) -> None:
        """Populate the network activity tree from report data.

        Args:
            network_activity: List of network activity dictionaries.
        """
        if not isinstance(network_activity, list):
            return
        typed_acts = cast("list[object]", network_activity)
        for raw_act in typed_acts:
            if isinstance(raw_act, dict):
                act = cast("dict[str, object]", raw_act)
                sent = act.get("bytes_sent", 0)
                recv = act.get("bytes_received", 0)
                item = QTreeWidgetItem([
                    str(act.get("protocol", "")),
                    str(act.get("remote_address", "")),
                    str(act.get("remote_port", "")),
                    f"{sent}/{recv} bytes",
                ])
                self._network_tree.addTopLevelItem(item)

    def _populate_api_calls(self, api_calls: object) -> None:
        """Populate the API calls tree from report data.

        Args:
            api_calls: List of API call dictionaries.
        """
        if not isinstance(api_calls, list):
            return
        typed_calls = cast("list[object]", api_calls)
        for raw_call in typed_calls:
            if isinstance(raw_call, dict):
                call = cast("dict[str, object]", raw_call)
                item = QTreeWidgetItem([
                    str(call.get("timestamp", "")),
                    str(call.get("process", "")),
                    str(call.get("api", "")),
                    str(call.get("module", "")),
                    str(call.get("args", "")),
                    str(call.get("return_value", "")),
                ])
                self._api_calls_tree.addTopLevelItem(item)

    def _populate_dll_loads(self, dll_loads: object) -> None:
        """Populate the DLL loads tree from report data.

        Args:
            dll_loads: List of DLL load dictionaries.
        """
        if not isinstance(dll_loads, list):
            return
        typed_loads = cast("list[object]", dll_loads)
        for raw_load in typed_loads:
            if isinstance(raw_load, dict):
                load = cast("dict[str, object]", raw_load)
                item = QTreeWidgetItem([
                    str(load.get("timestamp", "")),
                    str(load.get("process", "")),
                    str(load.get("dll_path", "")),
                    str(load.get("base_addr", "")),
                    str(load.get("size", "")),
                ])
                self._dll_loads_tree.addTopLevelItem(item)

    def _populate_service_changes(self, service_changes: object) -> None:
        """Populate the services tree from report data.

        Args:
            service_changes: List of service change dictionaries.
        """
        if not isinstance(service_changes, list):
            return
        typed_svcs = cast("list[object]", service_changes)
        for raw_svc in typed_svcs:
            if isinstance(raw_svc, dict):
                svc = cast("dict[str, object]", raw_svc)
                item = QTreeWidgetItem([
                    str(svc.get("operation", "")),
                    str(svc.get("name", "")),
                    str(svc.get("binary_path", "")),
                    str(svc.get("start_type", "")),
                    str(svc.get("time", "")),
                ])
                self._services_tree.addTopLevelItem(item)

    def _populate_kernel_objects(self, kernel_objects: object) -> None:
        """Populate the kernel objects tree from report data.

        Args:
            kernel_objects: List of kernel object dictionaries.
        """
        if not isinstance(kernel_objects, list):
            return
        typed_objs = cast("list[object]", kernel_objects)
        for raw_obj in typed_objs:
            if isinstance(raw_obj, dict):
                obj = cast("dict[str, object]", raw_obj)
                item = QTreeWidgetItem([
                    str(obj.get("type", "")),
                    str(obj.get("name", "")),
                    str(obj.get("process", "")),
                    str(obj.get("operation", "")),
                    str(obj.get("timestamp", "")),
                ])
                self._kernel_objects_tree.addTopLevelItem(item)

    def _populate_injection_events(self, injection_events: object) -> None:
        """Populate the injections tree from report data.

        Args:
            injection_events: List of injection event dictionaries.
        """
        if not isinstance(injection_events, list):
            return
        typed_injs = cast("list[object]", injection_events)
        for raw_inj in typed_injs:
            if isinstance(raw_inj, dict):
                inj = cast("dict[str, object]", raw_inj)
                item = QTreeWidgetItem([
                    str(inj.get("type", "")),
                    str(inj.get("source", "")),
                    str(inj.get("target", "")),
                    str(inj.get("apis", "")),
                    str(inj.get("timestamp", "")),
                ])
                self._injections_tree.addTopLevelItem(item)

    def _populate_resource_samples(self, resource_samples: object) -> None:
        """Populate the resources tree from report data.

        Args:
            resource_samples: List of resource sample dictionaries.
        """
        if not isinstance(resource_samples, list):
            return
        typed_samples = cast("list[object]", resource_samples)
        for raw_sample in typed_samples:
            if isinstance(raw_sample, dict):
                sample = cast("dict[str, object]", raw_sample)
                item = QTreeWidgetItem([
                    str(sample.get("timestamp", "")),
                    str(sample.get("cpu_percent", "")),
                    str(sample.get("mem_mb", "")),
                    str(sample.get("disk_read", "")),
                    str(sample.get("disk_write", "")),
                    str(sample.get("net_sent", "")),
                    str(sample.get("net_recv", "")),
                ])
                self._resources_tree.addTopLevelItem(item)

    def _populate_clipboard_events(self, clipboard_events: object) -> None:
        """Populate the clipboard tree from report data.

        Args:
            clipboard_events: List of clipboard event dictionaries.
        """
        if not isinstance(clipboard_events, list):
            return
        typed_clips = cast("list[object]", clipboard_events)
        for raw_clip in typed_clips:
            if isinstance(raw_clip, dict):
                clip = cast("dict[str, object]", raw_clip)
                item = QTreeWidgetItem([
                    str(clip.get("timestamp", "")),
                    str(clip.get("operation", "")),
                    str(clip.get("format", "")),
                    str(clip.get("preview", "")),
                    str(clip.get("size", "")),
                ])
                self._clipboard_tree.addTopLevelItem(item)

    def _on_run_binary_error(self, exc: object) -> None:
        """Handle binary execution failure.

        Args:
            exc: The exception from the failed operation.
        """
        name_str = self._pending_binary.name if self._pending_binary.parts else "unknown"
        self._log(f"[-] Execution failed: {exc}")
        self._run_btn.setEnabled(True)
        _logger.warning("sandbox_binary_execution_failed", binary=name_str, error=str(exc))

    def _on_take_snapshot(self) -> None:
        """Take a snapshot of the current sandbox state."""
        if self._bridge is None or self.sandbox_id is None:
            return

        default_label = f"snapshot_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}"
        label, ok = QInputDialog.getText(
            self,
            "Take Snapshot",
            "Snapshot label:",
            text=default_label,
        )
        if not ok:
            return
        snapshot_label = str(label).strip() or default_label
        self._pending_snapshot_label = snapshot_label

        self.snapshot_btn.setEnabled(False)
        self._run_async(
            self._bridge.snapshot_create(self.sandbox_id, snapshot_label),
            on_success=self._on_take_snapshot_success,
            on_error=self._on_take_snapshot_error,
        )

    def _on_take_snapshot_success(self, result: object) -> None:
        """Handle successful snapshot creation.

        Args:
            result: Dictionary with snapshot_id (and optional created_at) from bridge.
        """
        snapshot_id = "unknown"
        created_at = ""
        label = self._pending_snapshot_label or "snapshot"
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            snapshot_id = str(typed.get("snapshot_id", "unknown"))
            created_at = str(typed.get("created_at", ""))
            bridge_label = typed.get("label")
            if isinstance(bridge_label, str) and bridge_label:
                label = bridge_label
        elif result is not None:
            snapshot_id = str(result)
        if not created_at:
            created_at = datetime.now(tz=UTC).isoformat()
        self._log(f"[+] Snapshot taken: {snapshot_id}")
        item = QTreeWidgetItem([snapshot_id, label, created_at])
        self._snapshots_tree.addTopLevelItem(item)
        self.snapshot_btn.setEnabled(True)
        self._pending_snapshot_label = None
        _logger.info("sandbox_snapshot_taken", snapshot_id=snapshot_id, label=label)

    def _on_take_snapshot_error(self, exc: object) -> None:
        """Handle snapshot failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Snapshot failed: {exc}")
        self.snapshot_btn.setEnabled(True)
        _logger.warning("sandbox_snapshot_failed", error=str(exc))

    def _on_restore_snapshot(self) -> None:
        """Restore the selected snapshot."""
        if self._bridge is None or self.sandbox_id is None:
            return

        selected = get_current_tree_item(self._snapshots_tree)
        if selected is None:
            self._log("[!] No snapshot selected")
            return

        snapshot_id = selected.text(0)
        self.restore_btn.setEnabled(False)
        self._pending_snapshot_id = snapshot_id
        self._run_async(
            self._bridge.snapshot_restore(self.sandbox_id, snapshot_id),
            on_success=self._on_restore_snapshot_success,
            on_error=self._on_restore_snapshot_error,
        )

    def _on_restore_snapshot_success(self, _result: object) -> None:
        """Handle successful snapshot restore.

        Args:
            _result: Bridge call result (unused).
        """
        snapshot_id = getattr(self, "_pending_snapshot_id", "unknown")
        self._log(f"[+] Restored snapshot: {snapshot_id}")
        self._clear_report_tabs()
        self.restore_btn.setEnabled(True)
        _logger.info("sandbox_snapshot_restored", snapshot_id=snapshot_id)

    def _on_restore_snapshot_error(self, exc: object) -> None:
        """Handle snapshot restore failure.

        Args:
            exc: The exception from the failed operation.
        """
        snapshot_id = getattr(self, "_pending_snapshot_id", "unknown")
        self._log(f"[-] Restore failed: {exc}")
        self.restore_btn.setEnabled(True)
        _logger.warning("sandbox_snapshot_restore_failed", snapshot_id=snapshot_id, error=str(exc))

    def _on_screenshot(self) -> None:
        """Capture a screenshot of the sandbox display."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.screenshot_btn.setEnabled(False)
        self._run_async(
            self._bridge.screenshot(self.sandbox_id),
            on_success=self._on_screenshot_success,
            on_error=self._on_screenshot_error,
        )

    def _on_screenshot_success(self, result: object) -> None:
        """Handle successful screenshot capture.

        Args:
            result: Dictionary with screenshot path from bridge.
        """
        path = ""
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            path = str(typed.get("screenshot_path", ""))
        self._log(f"[+] Screenshot saved: {path}")
        self.screenshot_btn.setEnabled(True)

    def _on_screenshot_error(self, exc: object) -> None:
        """Handle screenshot capture failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Screenshot failed: {exc}")
        self.screenshot_btn.setEnabled(True)

    def _on_pcap_toggle(self) -> None:
        """Toggle packet capture start/stop."""
        if self._bridge is None or self.sandbox_id is None:
            return

        if self._pcap_capture_id is None:
            self.pcap_btn.setEnabled(False)
            self._run_async(
                self._bridge.pcap_start(self.sandbox_id),
                on_success=self._on_pcap_start_success,
                on_error=self._on_pcap_start_error,
            )
        else:
            self.pcap_btn.setEnabled(False)
            self._run_async(
                self._bridge.pcap_stop(self.sandbox_id, self._pcap_capture_id),
                on_success=self._on_pcap_stop_success,
                on_error=self._on_pcap_stop_error,
            )

    def _on_pcap_start_success(self, result: object) -> None:
        """Handle successful PCAP capture start.

        Args:
            result: Dictionary with capture_id from bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            self._pcap_capture_id = str(typed.get("capture_id", ""))
        else:
            self._pcap_capture_id = "active"
        self._log(f"[+] PCAP capture started: {self._pcap_capture_id}")
        self.pcap_btn.setText("PCAP Stop")
        self.pcap_btn.setEnabled(True)

    def _on_pcap_start_error(self, exc: object) -> None:
        """Handle PCAP capture start failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] PCAP start failed: {exc}")
        self.pcap_btn.setEnabled(True)

    def _on_pcap_stop_success(self, result: object) -> None:
        """Handle successful PCAP capture stop.

        Args:
            result: Dictionary with pcap file path from bridge.
        """
        pcap_path = ""
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            pcap_path = str(typed.get("pcap_path", ""))
        self._log(f"[+] PCAP capture stopped, saved: {pcap_path}")
        self._pcap_capture_id = None
        self.pcap_btn.setText("PCAP Start")
        self.pcap_btn.setEnabled(True)

    def _on_pcap_stop_error(self, exc: object) -> None:
        """Handle PCAP capture stop failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] PCAP stop failed: {exc}")
        self._pcap_capture_id = None
        self.pcap_btn.setText("PCAP Start")
        self.pcap_btn.setEnabled(True)

    def _on_memory_dump(self) -> None:
        """Dump guest memory from the sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.memdump_btn.setEnabled(False)
        self._run_async(
            self._bridge.memory_dump(self.sandbox_id),
            on_success=self._on_memory_dump_success,
            on_error=self._on_memory_dump_error,
        )

    def _on_memory_dump_success(self, result: object) -> None:
        """Handle successful memory dump.

        Args:
            result: Dictionary with dump file path from bridge.
        """
        dump_path = ""
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            dump_path = str(typed.get("dump_path", ""))
        self._log(f"[+] Memory dump saved: {dump_path}")
        self.memdump_btn.setEnabled(True)

    def _on_memory_dump_error(self, exc: object) -> None:
        """Handle memory dump failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Memory dump failed: {exc}")
        self.memdump_btn.setEnabled(True)

    def _on_extract_files(self) -> None:
        """Extract files dropped during sandbox execution."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.extract_files_btn.setEnabled(False)
        self._run_async(
            self._bridge.extract_dropped_files(self.sandbox_id),
            on_success=self._on_extract_files_success,
            on_error=self._on_extract_files_error,
        )

    def _on_extract_files_success(self, result: object) -> None:
        """Handle successful file extraction.

        Args:
            result: Dictionary with ZIP archive path from bridge.
        """
        zip_path = ""
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            zip_path = str(typed.get("zip_path", ""))
        self._log(f"[+] Dropped files extracted: {zip_path}")
        self.extract_files_btn.setEnabled(True)

    def _on_extract_files_error(self, exc: object) -> None:
        """Handle file extraction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] File extraction failed: {exc}")
        self.extract_files_btn.setEnabled(True)

    def _on_yara_scan(self) -> None:
        """Run YARA scan against sandbox artifacts."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.yara_btn.setEnabled(False)
        self._run_async(
            self._bridge.yara_scan(self.sandbox_id),
            on_success=self._on_yara_scan_success,
            on_error=self._on_yara_scan_error,
        )

    def _on_yara_scan_success(self, result: object) -> None:
        """Handle successful YARA scan.

        Args:
            result: Dictionary with YARA match results from bridge.
        """
        match_count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_matches = typed.get("matches", [])
            if isinstance(raw_matches, list):
                typed_matches = cast("list[object]", raw_matches)
                match_count = len(typed_matches)
                for raw_match in typed_matches:
                    if isinstance(raw_match, dict):
                        m = cast("dict[str, object]", raw_match)
                        self._log(
                            f"[YARA] {m.get('rule', 'unknown')}: {m.get('strings', '')} in {m.get('file', '')}",
                        )
        self._log(f"[+] YARA scan complete: {match_count} matches")
        self.yara_btn.setEnabled(True)

    def _on_yara_scan_error(self, exc: object) -> None:
        """Handle YARA scan failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] YARA scan failed: {exc}")
        self.yara_btn.setEnabled(True)

    def _on_extract_iocs(self) -> None:
        """Extract IOCs from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.iocs_btn.setEnabled(False)
        self._run_async(
            self._bridge.extract_iocs(self.sandbox_id),
            on_success=self._on_extract_iocs_success,
            on_error=self._on_extract_iocs_error,
        )

    def _on_extract_iocs_success(self, result: object) -> None:
        """Handle successful IOC extraction.

        Args:
            result: Dictionary with list of IOC entries from bridge.
        """
        self._iocs_tree.clear()
        ioc_count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_iocs = typed.get("iocs", [])
            if isinstance(raw_iocs, list):
                typed_iocs = cast("list[object]", raw_iocs)
                for raw_ioc in typed_iocs:
                    if isinstance(raw_ioc, dict):
                        ioc = cast("dict[str, object]", raw_ioc)
                        item = QTreeWidgetItem([
                            str(ioc.get("ioc_type", "")),
                            str(ioc.get("value", "")),
                            str(ioc.get("source", "")),
                            str(ioc.get("context", "")),
                        ])
                        self._iocs_tree.addTopLevelItem(item)
                        ioc_count += 1
        self._log(f"[+] IOC extraction complete: {ioc_count} indicators")
        self.iocs_btn.setEnabled(True)

    def _on_extract_iocs_error(self, exc: object) -> None:
        """Handle IOC extraction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] IOC extraction failed: {exc}")
        self.iocs_btn.setEnabled(True)

    def _on_timeline(self) -> None:
        """Generate an event timeline from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.timeline_btn.setEnabled(False)
        self._run_async(
            self._bridge.timeline(self.sandbox_id),
            on_success=self._on_timeline_success,
            on_error=self._on_timeline_error,
        )

    def _on_timeline_success(self, result: object) -> None:
        """Handle successful timeline generation.

        Args:
            result: Dictionary with list of timeline events from bridge.
        """
        self._timeline_tree.clear()
        event_count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_events = typed.get("events", [])
            if isinstance(raw_events, list):
                typed_events = cast("list[object]", raw_events)
                for raw_event in typed_events:
                    if isinstance(raw_event, dict):
                        ev = cast("dict[str, object]", raw_event)
                        item = QTreeWidgetItem([
                            str(ev.get("timestamp", "")),
                            str(ev.get("category", "")),
                            str(ev.get("summary", "")),
                        ])
                        self._timeline_tree.addTopLevelItem(item)
                        event_count += 1
        self._log(f"[+] Timeline generated: {event_count} events")
        self.timeline_btn.setEnabled(True)

    def _on_timeline_error(self, exc: object) -> None:
        """Handle timeline generation failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Timeline generation failed: {exc}")
        self.timeline_btn.setEnabled(True)

    def _on_detect_behaviors(self) -> None:
        """Detect behavioral signatures from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.behaviors_btn.setEnabled(False)
        self._run_async(
            self._bridge.detect_behaviors(self.sandbox_id),
            on_success=self._on_detect_behaviors_success,
            on_error=self._on_detect_behaviors_error,
        )

    def _on_detect_behaviors_success(self, result: object) -> None:
        """Handle successful behavior detection.

        Args:
            result: Dictionary with list of behavior matches from bridge.
        """
        self._behaviors_tree.clear()
        match_count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_matches = typed.get("matches", [])
            if isinstance(raw_matches, list):
                typed_matches = cast("list[object]", raw_matches)
                for raw_match in typed_matches:
                    if isinstance(raw_match, dict):
                        m = cast("dict[str, object]", raw_match)
                        item = QTreeWidgetItem([
                            str(m.get("signature", "")),
                            str(m.get("category", "")),
                            str(m.get("severity", "")),
                            str(m.get("mitre", "")),
                            str(m.get("description", "")),
                        ])
                        self._behaviors_tree.addTopLevelItem(item)
                        match_count += 1
        self._log(f"[+] Behavior detection complete: {match_count} signatures matched")
        self.behaviors_btn.setEnabled(True)

    def _on_detect_behaviors_error(self, exc: object) -> None:
        """Handle behavior detection failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Behavior detection failed: {exc}")
        self.behaviors_btn.setEnabled(True)

    def _on_copy_in(self) -> None:
        """Copy a file into the sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            return

        source_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Copy Into Sandbox",
            "",
            "All Files (*)",
        )
        if not source_path:
            return

        dest_path, ok = QInputDialog.getText(
            self,
            "Destination Path",
            "Path inside sandbox:",
        )
        if not ok or not dest_path:
            return

        self._pending_copy_in_source = source_path
        self._pending_copy_in_dest = dest_path
        self.copy_in_btn.setEnabled(False)
        self._run_async(
            self._bridge.copy_to(self.sandbox_id, source_path, dest_path),
            on_success=self._on_copy_in_success,
            on_error=self._on_copy_in_error,
        )

    def _on_copy_in_success(self, _result: object) -> None:
        """Handle successful file copy into sandbox.

        Args:
            _result: Bridge call result (unused).
        """
        self._log(f"[+] Copied into sandbox: {self._pending_copy_in_source} -> {self._pending_copy_in_dest}")
        self.copy_in_btn.setEnabled(True)

    def _on_copy_in_error(self, exc: object) -> None:
        """Handle file copy into sandbox failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Copy into sandbox failed: {exc}")
        self.copy_in_btn.setEnabled(True)

    def _on_copy_out(self) -> None:
        """Copy a file out of the sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            return

        sandbox_path, ok = QInputDialog.getText(
            self,
            "Sandbox File Path",
            "Path inside sandbox to copy out:",
        )
        if not ok or not sandbox_path:
            return

        dest_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File From Sandbox",
            "",
            "All Files (*)",
        )
        if not dest_path:
            return

        self._pending_copy_out_source = sandbox_path
        self._pending_copy_out_dest = dest_path
        self.copy_out_btn.setEnabled(False)
        self._run_async(
            self._bridge.copy_from(self.sandbox_id, sandbox_path, dest_path),
            on_success=self._on_copy_out_success,
            on_error=self._on_copy_out_error,
        )

    def _on_copy_out_success(self, _result: object) -> None:
        """Handle successful file copy from sandbox.

        Args:
            _result: Bridge call result (unused).
        """
        self._log(f"[+] Copied from sandbox: {self._pending_copy_out_source} -> {self._pending_copy_out_dest}")
        self.copy_out_btn.setEnabled(True)

    def _on_copy_out_error(self, exc: object) -> None:
        """Handle file copy from sandbox failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Copy from sandbox failed: {exc}")
        self.copy_out_btn.setEnabled(True)

    def _on_continue_vm(self) -> None:
        """Resume execution of a paused sandbox VM."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.continue_btn.setEnabled(False)
        self._run_async(
            self._bridge.cont(self.sandbox_id),
            on_success=self._on_continue_vm_success,
            on_error=self._on_continue_vm_error,
        )

    def _on_continue_vm_success(self, _result: object) -> None:
        """Handle successful VM resume.

        Args:
            _result: Bridge call result (unused).
        """
        self._log("[+] VM execution resumed")
        self.continue_btn.setEnabled(True)

    def _on_continue_vm_error(self, exc: object) -> None:
        """Handle VM resume failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] VM continue failed: {exc}")
        self.continue_btn.setEnabled(True)

    def _on_delete_snapshot(self) -> None:
        """Delete the selected snapshot from the sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            return

        selected = get_current_tree_item(self._snapshots_tree)
        if selected is None:
            self._log("[!] No snapshot selected for deletion")
            return

        snapshot_name = selected.text(0)
        self._pending_snapshot_id = snapshot_name
        self.delete_snap_btn.setEnabled(False)
        self._run_async(
            self._bridge.snapshot_delete(self.sandbox_id, snapshot_name),
            on_success=self._on_delete_snapshot_success,
            on_error=self._on_delete_snapshot_error,
        )

    def _on_delete_snapshot_success(self, _result: object) -> None:
        """Handle successful snapshot deletion.

        Args:
            _result: Bridge call result (unused).
        """
        snapshot_name = self._pending_snapshot_id
        self._log(f"[+] Snapshot deleted: {snapshot_name}")
        selected = get_current_tree_item(self._snapshots_tree)
        if selected is not None:
            idx = self._snapshots_tree.indexOfTopLevelItem(selected)
            if idx >= 0:
                self._snapshots_tree.takeTopLevelItem(idx)
        self.delete_snap_btn.setEnabled(True)

    def _on_delete_snapshot_error(self, exc: object) -> None:
        """Handle snapshot deletion failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Snapshot deletion failed: {exc}")
        self.delete_snap_btn.setEnabled(True)

    def _on_execute_command(self) -> None:
        """Execute a command inside the sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            return

        command = self._cmd_input.text().strip()
        if not command:
            self._log("[!] No command specified")
            return

        self._exec_cmd_btn.setEnabled(False)
        self._log(f"[*] Executing command: {command}")
        self._run_async(
            self._bridge.execute(self.sandbox_id, command),
            on_success=self._on_execute_command_success,
            on_error=self._on_execute_command_error,
        )

    def _on_execute_command_success(self, result: object) -> None:
        """Handle successful command execution.

        Args:
            result: Dictionary with exit_code, stdout, stderr from bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            exit_code = typed.get("exit_code", "")
            stdout = typed.get("stdout", "")
            stderr = typed.get("stderr", "")
            self._log(f"[+] Command exited with code {exit_code}")
            if isinstance(stdout, str) and stdout:
                self._console_output.appendPlainText(f"[stdout] {stdout}")
            if isinstance(stderr, str) and stderr:
                self._console_output.appendPlainText(f"[stderr] {stderr}")
        else:
            self._log("[+] Command executed")
        self._exec_cmd_btn.setEnabled(True)

    def _on_execute_command_error(self, exc: object) -> None:
        """Handle command execution failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Command execution failed: {exc}")
        self._exec_cmd_btn.setEnabled(True)

    def _poll_status(self) -> None:
        """Poll the sandbox status periodically."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.status(),
            on_success=self._on_poll_status_success,
            on_error=self._on_poll_status_error,
        )

    def _on_poll_status_success(self, result: object) -> None:
        """Handle successful status poll.

        Args:
            result: Status dictionary from bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            active = typed.get("active_count", 0)
            self._status_indicator.setText(f"Active ({active} instances)")
            instances = typed.get("instances")
            if isinstance(instances, list):
                self._populate_instances_tree(cast("list[object]", instances))
        else:
            self._status_indicator.setText("Active")

    def _populate_instances_tree(self, instances: list[object]) -> None:
        """Refresh the Instances tab with incremental row updates keyed by instance_id.

        Args:
            instances: List of per-instance status dicts from the bridge poll result.
        """
        existing: dict[str, QTreeWidgetItem] = {}
        for idx in range(self._instances_tree.topLevelItemCount()):
            item = self._instances_tree.topLevelItem(idx)
            if item is None:
                continue
            existing[item.text(0)] = item

        seen_ids: set[str] = set()
        for raw in instances:
            if not isinstance(raw, dict):
                continue
            entry = cast("dict[str, object]", raw)
            instance_id = str(entry.get("instance_id") or entry.get("id") or "")
            if not instance_id:
                continue
            seen_ids.add(instance_id)
            columns = [
                instance_id,
                str(entry.get("type") or entry.get("isolation_level") or ""),
                str(entry.get("status") or ""),
                str(entry.get("created_at") or ""),
                str(entry.get("last_used") or entry.get("updated_at") or ""),
                str(entry.get("binary") or entry.get("binary_path") or ""),
            ]
            item = existing.get(instance_id)
            if item is None:
                self._instances_tree.addTopLevelItem(QTreeWidgetItem(columns))
            else:
                for col_idx, value in enumerate(columns):
                    item.setText(col_idx, value)

        for stale_id, stale_item in existing.items():
            if stale_id in seen_ids:
                continue
            row = self._instances_tree.indexOfTopLevelItem(stale_item)
            if row >= 0:
                self._instances_tree.takeTopLevelItem(row)

    def _on_poll_status_error(self, _exc: object) -> None:
        """Handle status poll failure.

        Args:
            _exc: The exception from the failed operation.
        """
        self._status_indicator.setText("Active (status unavailable)")

    def _on_vnc_status_changed(self, *, connected: bool) -> None:
        """Handle VNC connection status changes.

        Args:
            connected: True if VNC is now connected.
        """
        if connected:
            self._log("[+] VNC display connected")
        else:
            self._log("[*] VNC display disconnected")

    def _connect_vnc_display(self) -> None:
        """Connect the VNC widget to the sandbox VNC port if available."""
        if self._vnc_widget is None or self._bridge is None or self.sandbox_id is None:
            return

        self._run_async(
            self._bridge.get_vnc_port(self.sandbox_id),
            on_success=self._on_vnc_port_received,
            on_error=lambda _: _logger.debug("vnc_port_query_failed"),
        )

    def _on_vnc_port_received(self, result: object) -> None:
        """Handle VNC port retrieval.

        Args:
            result: VNC port number or None.
        """
        if self._vnc_widget is None:
            return
        vnc_port = result if isinstance(result, int) else None
        if vnc_port is None:
            _logger.debug("sandbox_vnc_port_not_available")
            return
        self._log(f"[*] Connecting VNC display on port {vnc_port}...")
        self._vnc_widget.connect_to_server("127.0.0.1", vnc_port)
        _logger.info("vnc_display_connecting", port=vnc_port)

    def _disconnect_vnc_display(self) -> None:
        """Disconnect the VNC widget if connected."""
        if self._vnc_widget is not None:
            self._vnc_widget.disconnect_from_server()

    def _clear_report_tabs(self) -> None:
        """Clear all execution report display tabs."""
        self._file_changes_tree.clear()
        self._registry_changes_tree.clear()
        self._network_tree.clear()
        self._api_calls_tree.clear()
        self._dll_loads_tree.clear()
        self._services_tree.clear()
        self._kernel_objects_tree.clear()
        self._injections_tree.clear()
        self._resources_tree.clear()
        self._clipboard_tree.clear()
        self._timeline_tree.clear()
        self._iocs_tree.clear()
        self._behaviors_tree.clear()
        self._instances_tree.clear()

    def load_execution_report(self, report: ExecutionReport) -> None:
        """Display an execution report in the output tabs.

        Args:
            report: The execution report to display.
        """
        _logger.debug("execution_report_loading", report_type=type(report).__name__)
        self._clear_report_tabs()

        if hasattr(report, "file_changes"):
            for change in report.file_changes:
                op = getattr(change, "operation", "unknown")
                path = getattr(change, "path", "")
                details = getattr(change, "details", "")
                item = QTreeWidgetItem([str(op), str(path), str(details)])
                self._file_changes_tree.addTopLevelItem(item)

        if hasattr(report, "registry_changes"):
            for reg_change in report.registry_changes:
                op = getattr(reg_change, "operation", "unknown")
                key = getattr(reg_change, "key", "")
                value = getattr(reg_change, "value", "")
                item = QTreeWidgetItem([str(op), str(key), str(value)])
                self._registry_changes_tree.addTopLevelItem(item)

        if hasattr(report, "network_activity"):
            for activity in report.network_activity:
                proto = getattr(activity, "protocol", "unknown")
                dest = getattr(activity, "destination", "")
                port = getattr(activity, "port", 0)
                size = getattr(activity, "data_size", 0)
                item = QTreeWidgetItem([str(proto), str(dest), str(port), f"{size} bytes"])
                self._network_tree.addTopLevelItem(item)

        self._log(
            f"[+] Execution report loaded: {len(report.file_changes)} file changes, "
            f"{len(report.registry_changes)} registry changes, "
            f"{len(report.network_activity)} network events",
        )
        _logger.info(
            "execution_report_loaded",
            file_changes=len(report.file_changes),
            registry_changes=len(report.registry_changes),
            network_events=len(report.network_activity),
        )
