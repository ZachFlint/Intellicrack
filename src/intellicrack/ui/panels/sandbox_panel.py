# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Sandbox management panel for Intellicrack.

Provides sandbox creation, configuration, binary execution,
snapshot management, and execution report viewing.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
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


if TYPE_CHECKING:
    from intellicrack.sandbox.base import ExecutionReport, SandboxBase
    from intellicrack.sandbox.manager import SandboxManager, SandboxType

_logger = get_logger("ui.panels.sandbox")


class SandboxPanel(AnalysisPanelBase):
    """Panel for sandbox environment management and binary execution.

    Provides controls for creating and managing sandboxed environments,
    executing binaries with monitoring, taking/restoring snapshots,
    and reviewing execution reports (file, registry, network activity).

    Args:
        parent: Parent widget.

    Attributes:
        execution_completed: Signal emitted with execution ID when a sandboxed binary run finishes.
        sandbox_created: Signal emitted with sandbox instance ID when a new sandbox is created.
    """

    execution_completed: pyqtSignal = pyqtSignal(str)
    sandbox_created: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sandbox: SandboxBase | None = None
        self._sandbox_manager: SandboxManager | None = None
        self._sandbox_id: str | None = None
        self._pending_binary: Path = Path()
        self._pending_args: list[str] = []
        self._pending_snapshot_id: str = "unknown"
        self._vnc_widget: VNCWidget | None = None
        self._status_poll_timer = QTimer(self)
        self._status_poll_timer.timeout.connect(self._poll_status)

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add sandbox-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._status_indicator = self._add_toolbar_label(toolbar, "Inactive")
        self._status_indicator.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))

        toolbar.addSeparator()

        self._create_btn = self._add_tool_button(toolbar, "Create", self._on_create)
        self._destroy_btn = self._add_danger_button(toolbar, "Destroy", self._on_destroy, enabled=False)
        self._restart_btn = self._add_tool_button(toolbar, "Restart", self._on_restart, enabled=False)

        toolbar.addSeparator()

        self._snapshot_btn = self._add_tool_button(toolbar, "Take Snapshot", self._on_take_snapshot, enabled=False)
        self._restore_btn = self._add_tool_button(toolbar, "Restore Snapshot", self._on_restore_snapshot, enabled=False)

        toolbar.addSeparator()

        self._add_toolbar_label(toolbar, "Type:")

        self._sandbox_type_combo = QComboBox()
        self._sandbox_type_combo.addItems(["Windows Sandbox", "QEMU"])
        self._sandbox_type_combo.setMinimumWidth(120)
        toolbar.addWidget(self._sandbox_type_combo)

    @override
    def _create_content(self) -> QWidget:
        """Create the sandbox management content area.

        Returns:
            QWidget: Splitter with execution controls and output tabs.
        """
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        exec_container = QWidget()
        exec_layout = QVBoxLayout(exec_container)
        exec_layout.setContentsMargins(4, 4, 4, 4)
        exec_layout.setSpacing(4)

        exec_header = QLabel("Binary Execution")
        exec_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        exec_layout.addWidget(exec_header)

        path_row = QHBoxLayout()
        path_label = QLabel("Binary:")
        path_label.setObjectName("toolbar_label")
        path_row.addWidget(path_label)

        self._binary_path_input = QLineEdit()
        self._binary_path_input.setFont(QFont("JetBrains Mono", 9))
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
        self._args_input.setFont(QFont("JetBrains Mono", 9))
        args_row.addWidget(self._args_input)

        self._run_btn = QPushButton("Run in Sandbox")
        self._run_btn.setObjectName("tool_button")
        self._run_btn.setEnabled(False)
        self._run_btn.clicked.connect(self._on_run_binary)
        args_row.addWidget(self._run_btn)
        exec_layout.addLayout(args_row)

        main_splitter.addWidget(exec_container)

        output_tabs = QTabWidget()

        self._console_output = QPlainTextEdit()
        self._console_output.setFont(QFont("JetBrains Mono", 9))
        self._console_output.setReadOnly(True)
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
        vnc_w.connection_status_changed.connect(self._on_vnc_status_changed)
        output_tabs.addTab(vnc_w, "VM Display")

        main_splitter.addWidget(output_tabs)

        main_splitter.setSizes([200, 400])
        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Stop the status poll timer, disconnect VNC, and shut down the sandbox."""
        self._disconnect_vnc_display()
        self._status_poll_timer.stop()
        if self._sandbox is not None and self._sandbox_id is not None:
            try:
                run_bridge_coroutine(self._sandbox.stop())
            except Exception:
                _logger.debug("sandbox_stop_skipped", exc_info=True)

    def set_sandbox(self, sandbox: SandboxBase) -> None:
        """Set the sandbox backend instance.

        Args:
            sandbox: The SandboxBase implementation to use.
        """
        self._sandbox = sandbox
        _logger.info("sandbox_backend_set", backend_type=type(sandbox).__name__)

    def set_sandbox_manager(self, manager: SandboxManager) -> None:
        """Set the sandbox manager for type-aware creation.

        When a manager is set, the Create button uses the combo box
        selection to create the correct sandbox type.

        Args:
            manager: The SandboxManager instance.
        """
        self._sandbox_manager = manager
        _logger.info("sandbox_manager_set", manager_type=type(manager).__name__)
        self._run_async(
            manager.cleanup_stale(),
            on_success=self._on_cleanup_stale_success,
            on_error=self._on_cleanup_stale_error,
        )

    def get_sandbox(self) -> SandboxBase | None:
        """Get the current sandbox backend.

        Returns:
            SandboxBase | None: The attached sandbox or None.
        """
        return self._sandbox

    def _log(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        self._console_output.appendPlainText(message)

    def _set_sandbox_controls_active(self, active: bool) -> None:
        """Enable or disable controls based on sandbox state.

        Args:
            active: True to enable sandbox-active controls.
        """
        self._create_btn.setEnabled(not active)
        self._destroy_btn.setEnabled(active)
        self._restart_btn.setEnabled(active)
        self._run_btn.setEnabled(active)
        self._snapshot_btn.setEnabled(active)
        self._restore_btn.setEnabled(active)

    def _selected_sandbox_type(self) -> SandboxType:
        """Get the sandbox type from the combo box selection.

        Returns:
            SandboxType: Sandbox type literal: ``"windows"`` or ``"qemu"``.
        """
        combo_text = self._sandbox_type_combo.currentText()
        return "qemu" if combo_text == "QEMU" else "windows"

    def _on_create(self) -> None:
        """Create a new sandbox environment."""
        if self._sandbox_manager is not None:
            sandbox_type = self._selected_sandbox_type()
            _logger.debug("sandbox_create_via_manager", sandbox_type=sandbox_type)
            self._create_btn.setEnabled(False)
            self._run_async(
                self._sandbox_manager.create(sandbox_type=sandbox_type, auto_start=True),
                on_success=self._on_mgr_create_success,
                on_error=self._on_create_error,
            )
            return

        if self._sandbox is None:
            self._log("[!] No sandbox backend configured")
            _logger.warning("sandbox_create_failed_no_backend", reason="no backend configured")
            return

        _logger.debug("sandbox_create_started", backend_type=type(self._sandbox).__name__)
        enable_vnc_fn = getattr(self._sandbox, "enable_vnc_display", None)
        if callable(enable_vnc_fn):
            enable_vnc_fn()
        self._create_btn.setEnabled(False)
        self._run_async(
            self._sandbox.start(),
            on_success=self._on_create_success,
            on_error=self._on_create_error,
        )

    def _on_mgr_create_success(self, result: object) -> None:
        """Handle successful sandbox creation via SandboxManager.

        Extracts the SandboxBase from the returned SandboxInstance
        and delegates to the standard creation success handler.

        Args:
            result: The SandboxInstance returned by the manager.
        """
        sandbox = getattr(result, "sandbox", None)
        instance_id = getattr(result, "id", "active")
        if sandbox is not None:
            self._sandbox = sandbox
        self._sandbox_id = str(instance_id)
        self._on_create_success(result)

    def _on_create_success(self, _result: object) -> None:
        """Handle successful sandbox creation.

        Args:
            _result: Bridge call result (unused).
        """
        if self._sandbox_id is None:
            self._sandbox_id = "active"
        self._log("[+] Sandbox created")
        self._status_indicator.setText("Active")
        self._set_sandbox_controls_active(True)
        self._create_btn.setEnabled(False)
        self._status_poll_timer.start(5000)
        self.sandbox_created.emit(self._sandbox_id)
        self.tool_started.emit()
        _logger.info("sandbox_created", sandbox_id=self._sandbox_id)

        QTimer.singleShot(2000, self._connect_vnc_display)

    def _on_create_error(self, exc: object) -> None:
        """Handle sandbox creation failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to create sandbox: {exc}")
        self._create_btn.setEnabled(True)
        _logger.warning("sandbox_create_failed", error=str(exc))

    def _on_cleanup_stale_success(self, result: object) -> None:
        """Handle successful stale sandbox cleanup.

        Args:
            result: Number of instances cleaned up.
        """
        _ = self
        count = result if isinstance(result, int) else 0
        if count > 0:
            _logger.info("stale_sandboxes_cleaned_up", count=count)

    def _on_cleanup_stale_error(self, exc: object) -> None:
        """Handle stale cleanup failure.

        Args:
            exc: The exception from the failed operation.
        """
        _ = self
        _logger.warning("stale_sandbox_cleanup_failed", error=str(exc))

    def _on_destroy(self) -> None:
        """Destroy the current sandbox environment."""
        if self._sandbox is None:
            return

        _logger.debug("sandbox_destroy_started", sandbox_id=self._sandbox_id)
        self._destroy_btn.setEnabled(False)
        self._run_async(
            self._sandbox.stop(),
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
        self._sandbox_id = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()
        _logger.info("sandbox_destroyed", sandbox_id=self._sandbox_id)

    def _on_destroy_error(self, exc: object) -> None:
        """Handle sandbox destruction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to destroy sandbox: {exc}")
        self._sandbox_id = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()
        _logger.warning("sandbox_destroy_failed", error=str(exc))

    def _on_restart(self) -> None:
        """Restart the sandbox environment."""
        if self._sandbox is None:
            return

        _logger.debug("sandbox_restart_started", sandbox_id=self._sandbox_id)
        self._restart_btn.setEnabled(False)
        self._run_async(
            self._sandbox.restart(),
            on_success=self._on_restart_success,
            on_error=self._on_restart_error,
        )

    def _on_restart_success(self, _result: object) -> None:
        """Handle successful sandbox restart.

        Args:
            _result: Bridge call result (unused).
        """
        self._log("[+] Sandbox restarted")
        self._clear_report_tabs()
        self._restart_btn.setEnabled(True)
        _logger.info("sandbox_restarted", sandbox_id=self._sandbox_id)

    def _on_restart_error(self, exc: object) -> None:
        """Handle sandbox restart failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Failed to restart sandbox: {exc}")
        self._restart_btn.setEnabled(True)
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
        if self._sandbox is None:
            self._log("[!] No sandbox active")
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
        args_list = args.split() if args else []

        self._log(f"[*] Executing: {binary.name} {args}")
        self._clear_report_tabs()
        self._run_btn.setEnabled(False)
        _logger.debug("sandbox_binary_execution_started", binary=binary.name, exec_args=args)

        sandbox_dest = f"input/{binary.name}"
        self._pending_binary = binary
        self._pending_args = args_list
        self._run_async(
            self._sandbox.copy_to_sandbox(binary, sandbox_dest),
            on_success=self._on_copy_to_sandbox_success,
            on_error=self._on_run_binary_error,
        )

    def _on_copy_to_sandbox_success(self, _result: object) -> None:
        """Handle successful file copy, proceed to run the binary.

        Args:
            _result: Bridge call result (unused).
        """
        if self._sandbox is None:
            self._run_btn.setEnabled(True)
            return

        binary = self._pending_binary
        args_list = self._pending_args
        self._run_async(
            self._sandbox.run_binary(binary, args_list),
            on_success=self._on_run_binary_success,
            on_error=self._on_run_binary_error,
        )

    def _on_run_binary_success(self, _result: object) -> None:
        """Handle successful binary execution.

        Args:
            _result: Bridge call result (unused).
        """
        binary_name = self._pending_binary.name
        self._log("[+] Execution started")
        self._run_btn.setEnabled(True)
        self.execution_completed.emit(binary_name)
        _logger.info("sandbox_binary_executed", binary=binary_name)

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
        if self._sandbox is None:
            return

        self._snapshot_btn.setEnabled(False)
        self._run_async(
            self._sandbox.take_snapshot("manual_snapshot"),
            on_success=self._on_take_snapshot_success,
            on_error=self._on_take_snapshot_error,
        )

    def _on_take_snapshot_success(self, result: object) -> None:
        """Handle successful snapshot creation.

        Args:
            result: The snapshot ID from the bridge.
        """
        snapshot_id = str(result) if result is not None else "unknown"
        self._log(f"[+] Snapshot taken: {snapshot_id}")
        item = QTreeWidgetItem([snapshot_id, "manual_snapshot", "now"])
        self._snapshots_tree.addTopLevelItem(item)
        self._snapshot_btn.setEnabled(True)
        _logger.info("sandbox_snapshot_taken", snapshot_id=snapshot_id)

    def _on_take_snapshot_error(self, exc: object) -> None:
        """Handle snapshot failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._log(f"[-] Snapshot failed: {exc}")
        self._snapshot_btn.setEnabled(True)
        _logger.warning("sandbox_snapshot_failed", error=str(exc))

    def _on_restore_snapshot(self) -> None:
        """Restore the selected snapshot."""
        if self._sandbox is None:
            return

        selected = get_current_tree_item(self._snapshots_tree)
        if selected is None:
            self._log("[!] No snapshot selected")
            return

        snapshot_id = selected.text(0)
        self._restore_btn.setEnabled(False)
        self._pending_snapshot_id = snapshot_id
        self._run_async(
            self._sandbox.restore_snapshot(snapshot_id),
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
        self._restore_btn.setEnabled(True)
        _logger.info("sandbox_snapshot_restored", snapshot_id=snapshot_id)

    def _on_restore_snapshot_error(self, exc: object) -> None:
        """Handle snapshot restore failure.

        Args:
            exc: The exception from the failed operation.
        """
        snapshot_id = getattr(self, "_pending_snapshot_id", "unknown")
        self._log(f"[-] Restore failed: {exc}")
        self._restore_btn.setEnabled(True)
        _logger.warning("sandbox_snapshot_restore_failed", snapshot_id=snapshot_id, error=str(exc))

    def _poll_status(self) -> None:
        """Poll the sandbox status periodically."""
        if self._sandbox is None:
            return

        try:
            state = self._sandbox.state
            status_text = state.status if hasattr(state, "status") else "Unknown"
            self._status_indicator.setText(f"Active ({status_text})")
        except Exception:
            _logger.exception("sandbox_status_query_failed")
            self._status_indicator.setText("Active (status unavailable)")

    def _on_vnc_status_changed(self, connected: bool) -> None:
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
        if self._vnc_widget is None or self._sandbox is None:
            return

        vnc_port = getattr(self._sandbox, "vnc_port", None)
        if vnc_port is None:
            _logger.debug("sandbox_vnc_port_not_available", sandbox_type=type(self._sandbox).__name__)
            return

        self._log(f"[*] Connecting VNC display on port {vnc_port}...")
        self._vnc_widget.connect_to_server("127.0.0.1", int(vnc_port))
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
            f"{len(report.network_activity)} network events"
        )
        _logger.info(
            "execution_report_loaded",
            file_changes=len(report.file_changes),
            registry_changes=len(report.registry_changes),
            network_events=len(report.network_activity),
        )
