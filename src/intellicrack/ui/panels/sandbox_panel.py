"""Sandbox management panel for Intellicrack.

Provides sandbox creation, configuration, binary execution,
snapshot management, and execution report viewing.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

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

from intellicrack.ui.panels._async_bridge import run_bridge_coroutine
from intellicrack.ui.panels._qt_compat import (
    get_current_tree_item,
    set_header_labels,
    set_max_block_count,
)


if TYPE_CHECKING:
    from intellicrack.sandbox.base import ExecutionReport, SandboxBase

_logger = logging.getLogger(__name__)


class SandboxPanel(QWidget):
    """Panel for sandbox environment management and binary execution.

    Provides controls for creating and managing sandboxed environments,
    executing binaries with monitoring, taking/restoring snapshots,
    and reviewing execution reports (file, registry, network activity).
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()
    execution_completed: pyqtSignal = pyqtSignal(str)
    sandbox_created: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the sandbox panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._sandbox: SandboxBase | None = None
        self._sandbox_id: str | None = None
        self._status_poll_timer = QTimer(self)
        self._status_poll_timer.timeout.connect(self._poll_status)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the sandbox panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        self._status_indicator = QLabel("Inactive")
        self._status_indicator.setObjectName("toolbar_label")
        self._status_indicator.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        toolbar.addWidget(self._status_indicator)

        toolbar.addSeparator()

        self._create_btn = QPushButton("Create")
        self._create_btn.setObjectName("tool_button")
        self._create_btn.clicked.connect(self._on_create)
        toolbar.addWidget(self._create_btn)

        self._destroy_btn = QPushButton("Destroy")
        self._destroy_btn.setObjectName("danger_button")
        self._destroy_btn.setEnabled(False)
        self._destroy_btn.clicked.connect(self._on_destroy)
        toolbar.addWidget(self._destroy_btn)

        self._restart_btn = QPushButton("Restart")
        self._restart_btn.setObjectName("tool_button")
        self._restart_btn.setEnabled(False)
        self._restart_btn.clicked.connect(self._on_restart)
        toolbar.addWidget(self._restart_btn)

        toolbar.addSeparator()

        self._snapshot_btn = QPushButton("Take Snapshot")
        self._snapshot_btn.setObjectName("tool_button")
        self._snapshot_btn.setEnabled(False)
        self._snapshot_btn.clicked.connect(self._on_take_snapshot)
        toolbar.addWidget(self._snapshot_btn)

        self._restore_btn = QPushButton("Restore Snapshot")
        self._restore_btn.setObjectName("tool_button")
        self._restore_btn.setEnabled(False)
        self._restore_btn.clicked.connect(self._on_restore_snapshot)
        toolbar.addWidget(self._restore_btn)

        toolbar.addSeparator()

        sandbox_type_label = QLabel("Type:")
        sandbox_type_label.setObjectName("toolbar_label")
        toolbar.addWidget(sandbox_type_label)

        self._sandbox_type_combo = QComboBox()
        self._sandbox_type_combo.addItems(["Windows Sandbox", "QEMU", "Docker"])
        self._sandbox_type_combo.setMinimumWidth(120)
        toolbar.addWidget(self._sandbox_type_combo)

        layout.addWidget(toolbar)

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

        main_splitter.addWidget(output_tabs)

        main_splitter.setSizes([200, 400])
        layout.addWidget(main_splitter)

    def set_sandbox(self, sandbox: SandboxBase) -> None:
        """Set the sandbox backend instance.

        Args:
            sandbox: The SandboxBase implementation to use.
        """
        self._sandbox = sandbox
        _logger.info("sandbox_backend_set")

    def get_sandbox(self) -> SandboxBase | None:
        """Get the current sandbox backend.

        Returns:
            The attached sandbox or None.
        """
        return self._sandbox

    def _log(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        self._console_output.appendPlainText(message)

    def _on_create(self) -> None:
        """Create a new sandbox environment."""
        if self._sandbox is None:
            self._log("[!] No sandbox backend configured")
            return

        try:
            run_bridge_coroutine(self._sandbox.start())
            self._sandbox_id = "active"
            self._log("[+] Sandbox created")
            self._status_indicator.setText("Active")
            self._create_btn.setEnabled(False)
            self._destroy_btn.setEnabled(True)
            self._restart_btn.setEnabled(True)
            self._run_btn.setEnabled(True)
            self._snapshot_btn.setEnabled(True)
            self._restore_btn.setEnabled(True)
            self._status_poll_timer.start(5000)
            self.sandbox_created.emit(self._sandbox_id)
            self.tool_started.emit()
        except Exception as e:
            self._log(f"[-] Failed to create sandbox: {e}")

    def _on_destroy(self) -> None:
        """Destroy the current sandbox environment."""
        if self._sandbox is None:
            return

        try:
            run_bridge_coroutine(self._sandbox.stop())
            self._log("[+] Sandbox destroyed")
        except Exception as e:
            self._log(f"[-] Failed to destroy sandbox: {e}")

        self._sandbox_id = None
        self._status_indicator.setText("Inactive")
        self._create_btn.setEnabled(True)
        self._destroy_btn.setEnabled(False)
        self._restart_btn.setEnabled(False)
        self._run_btn.setEnabled(False)
        self._snapshot_btn.setEnabled(False)
        self._restore_btn.setEnabled(False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()

    def _on_restart(self) -> None:
        """Restart the sandbox environment."""
        if self._sandbox is None:
            return

        try:
            run_bridge_coroutine(self._sandbox.restart())
            self._log("[+] Sandbox restarted")
            self._clear_report_tabs()
        except Exception as e:
            self._log(f"[-] Failed to restart sandbox: {e}")

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

        try:
            sandbox_dest = f"C:\\Sandbox\\{binary.name}"
            run_bridge_coroutine(self._sandbox.copy_to_sandbox(binary, sandbox_dest))
            sandbox_binary = Path(sandbox_dest)
            run_bridge_coroutine(self._sandbox.run_binary(sandbox_binary, args_list))
            self._log("[+] Execution started")
            self.execution_completed.emit(binary.name)
        except Exception as e:
            self._log(f"[-] Execution failed: {e}")

    def _on_take_snapshot(self) -> None:
        """Take a snapshot of the current sandbox state."""
        if self._sandbox is None:
            return

        try:
            snapshot_result = run_bridge_coroutine(self._sandbox.take_snapshot("manual_snapshot"))
            snapshot_id = str(snapshot_result) if snapshot_result is not None else "unknown"
            self._log(f"[+] Snapshot taken: {snapshot_id}")
            item = QTreeWidgetItem([str(snapshot_id), "manual_snapshot", "now"])
            self._snapshots_tree.addTopLevelItem(item)
        except Exception as e:
            self._log(f"[-] Snapshot failed: {e}")

    def _on_restore_snapshot(self) -> None:
        """Restore the selected snapshot."""
        if self._sandbox is None:
            return

        selected = get_current_tree_item(self._snapshots_tree)
        if selected is None:
            self._log("[!] No snapshot selected")
            return

        snapshot_id = selected.text(0)
        try:
            run_bridge_coroutine(self._sandbox.restore_snapshot(snapshot_id))
            self._log(f"[+] Restored snapshot: {snapshot_id}")
            self._clear_report_tabs()
        except Exception as e:
            self._log(f"[-] Restore failed: {e}")

    def _poll_status(self) -> None:
        """Poll the sandbox status periodically."""
        if self._sandbox is None:
            return

        try:
            state = self._sandbox.state
            status_text = state.status if hasattr(state, "status") else "Unknown"
            self._status_indicator.setText(f"Active ({status_text})")
        except Exception:
            self._status_indicator.setText("Active (status unavailable)")

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
        self._clear_report_tabs()

        if hasattr(report, "file_changes"):
            for change in report.file_changes:
                op = getattr(change, "operation", "unknown")
                path = getattr(change, "path", "")
                details = getattr(change, "details", "")
                item = QTreeWidgetItem([str(op), str(path), str(details)])
                self._file_changes_tree.addTopLevelItem(item)

        if hasattr(report, "registry_changes"):
            for change in report.registry_changes:
                op = getattr(change, "operation", "unknown")
                key = getattr(change, "key", "")
                value = getattr(change, "value", "")
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

        self._log(f"[+] Execution report loaded: {len(report.file_changes)} file changes, "
                  f"{len(report.registry_changes)} registry changes, "
                  f"{len(report.network_activity)} network events")

    def start_tool(self) -> bool:
        """Start the sandbox panel.

        Returns:
            True always since native panels are always ready.
        """
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop the sandbox panel and cleanup.

        Returns:
            True if cleanup succeeded.
        """
        self._status_poll_timer.stop()
        if self._sandbox is not None and self._sandbox_id is not None:
            with contextlib.suppress(Exception):
                run_bridge_coroutine(self._sandbox.stop())
        self.tool_closed.emit()
        return True
