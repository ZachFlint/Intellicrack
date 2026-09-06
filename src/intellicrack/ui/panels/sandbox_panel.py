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
from typing import TYPE_CHECKING, Any, Final, TypedDict, cast, override

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.logging import get_logger
from intellicrack.sandbox.qemu import QEMUSandbox
from intellicrack.sandbox.settings import load_qemu_config
from intellicrack.ui.dialogs_helpers import show_error, show_info
from intellicrack.ui.guest_process_picker import GuestProcessPickerDialog, GuestProcessRow
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase, ToolMenuEntry
from intellicrack.ui.panels.qt_compat import (
    get_current_tree_item,
    set_header_labels,
    set_max_block_count,
)
from intellicrack.ui.panels.vnc_widget import VNCWidget
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from PyQt6.QtGui import QAction

    from intellicrack.sandbox.base import ExecutionReport, SandboxBase
    from intellicrack.sandbox.manager import SandboxManager, SandboxType
    from intellicrack.sandbox.qemu import QEMUConfig

_logger = get_logger(__name__)

_EXEC_MARGIN: Final[int] = 4
_EXEC_SPACING: Final[int] = 4
_SPLIT_LEFT: Final[int] = 200
_SPLIT_RIGHT: Final[int] = 400
_MIN_FIELD_WIDTH: Final[int] = 160
_MIN_SPIN_WIDTH: Final[int] = 110

# Companion paths are separated by ';' rather than by whitespace, because a
# Windows path routinely carries a space and splitting on one would turn a
# single companion into two that do not exist.
_COMPANION_SEPARATOR: Final[str] = ";"

_TIMEOUT_MIN_SECONDS: Final[int] = 1
_TIMEOUT_MAX_SECONDS: Final[int] = 86400
_TIMEOUT_DEFAULT_SECONDS: Final[int] = 300
_MEMORY_MIN_MB: Final[int] = 128
_MEMORY_MAX_MB: Final[int] = 131072
_MEMORY_DEFAULT_MB: Final[int] = 2048

_VM_DISPLAY_UNSUPPORTED_TIP: Final[str] = "The VM display is only available for QEMU sandboxes"


def _configure_result_columns(tree: QTreeWidget) -> None:
    """Size a result tree's columns to their content so long values are not clipped.

    Applies ``ResizeToContents`` to every column so long file paths, registry
    keys and API argument blobs are shown in full instead of being truncated
    with no way to read them, and elides overflow in the middle when a value is
    still wider than the available space.

    Args:
        tree: The result tree widget to configure.
    """
    header = tree.header()
    if header is not None:
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)


def _format_file_change_detail(change: dict[str, object]) -> str:
    """Build a human-readable detail string for a file-change row.

    Describes a rename via its previous path when known, otherwise falls
    back to the recorded file size so the "Details" column always shows
    genuinely descriptive content rather than a mislabeled duplicate of
    another field.

    Args:
        change: File-change mapping with optional ``old_path`` and ``size`` keys.

    Returns:
        str: ``"renamed from <old_path>"`` when a previous path is known,
        ``"<size> bytes"`` when only a size is known, or an empty string
        when neither is available.
    """
    old_path = change.get("old_path")
    if isinstance(old_path, str) and old_path:
        return f"renamed from {old_path}"
    size = change.get("size")
    if isinstance(size, int):
        return f"{size} bytes"
    return ""


class _SandboxCreateConfig(TypedDict):
    """Keyword arguments for ``SandboxBridge.create`` read from the toolbar.

    Attributes:
        timeout_seconds: Execution timeout in seconds.
        network_enabled: Whether network access is enabled.
        memory_limit_mb: Memory limit in megabytes.
    """

    timeout_seconds: int
    network_enabled: bool
    memory_limit_mb: int


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

    _controls_active: bool = False
    _active_sandbox_type: SandboxType | None = None
    _last_poll_error: str | None = None
    _vnc_widget: VNCWidget | None = None

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

        self._add_toolbar_label(toolbar, "Type:")

        self.sandbox_type_combo = QComboBox()
        self.sandbox_type_combo.addItems(["Windows Sandbox", "QEMU"])
        self.sandbox_type_combo.setMinimumWidth(120)
        toolbar.addWidget(self.sandbox_type_combo)

        toolbar.addSeparator()

        snapshot_actions = self._add_tool_menu(
            toolbar,
            "Snapshots",
            [
                ToolMenuEntry("Take Snapshot", self._on_take_snapshot, enabled=False),
                ToolMenuEntry("Restore Snapshot", self._on_restore_snapshot, enabled=False),
                ToolMenuEntry("Delete Snapshot", self._on_delete_snapshot, enabled=False),
            ],
        )
        self.snapshot_btn = snapshot_actions["Take Snapshot"]
        self.restore_btn = snapshot_actions["Restore Snapshot"]
        self.delete_snap_btn = snapshot_actions["Delete Snapshot"]

        capture_actions = self._add_tool_menu(
            toolbar,
            "Capture",
            [
                ToolMenuEntry("Screenshot", self._on_screenshot, enabled=False),
                ToolMenuEntry("PCAP Start", self._on_pcap_toggle, enabled=False),
                ToolMenuEntry("Memory Dump", self._on_memory_dump, enabled=False),
                ToolMenuEntry("Extract Files", self._on_extract_files, enabled=False),
            ],
        )
        self.screenshot_btn = capture_actions["Screenshot"]
        self.pcap_btn = capture_actions["PCAP Start"]
        self.memdump_btn = capture_actions["Memory Dump"]
        self.extract_files_btn = capture_actions["Extract Files"]

        analysis_actions = self._add_tool_menu(
            toolbar,
            "Analysis",
            [
                ToolMenuEntry("YARA Scan", self._on_yara_scan, enabled=False),
                ToolMenuEntry("Extract IOCs", self._on_extract_iocs, enabled=False),
                ToolMenuEntry("Timeline", self._on_timeline, enabled=False),
                ToolMenuEntry("Behaviors", self._on_detect_behaviors, enabled=False),
            ],
        )
        self.yara_btn = analysis_actions["YARA Scan"]
        self.iocs_btn = analysis_actions["Extract IOCs"]
        self.timeline_btn = analysis_actions["Timeline"]
        self.behaviors_btn = analysis_actions["Behaviors"]

        transfer_actions = self._add_tool_menu(
            toolbar,
            "Transfer",
            [
                ToolMenuEntry("Copy In", self._on_copy_in, enabled=False),
                ToolMenuEntry("Copy Out", self._on_copy_out, enabled=False),
            ],
        )
        self.copy_in_btn = transfer_actions["Copy In"]
        self.copy_out_btn = transfer_actions["Copy Out"]

        vm_actions = self._add_tool_menu(
            toolbar,
            "VM Control",
            [
                ToolMenuEntry("Continue VM", self._on_continue_vm, enabled=False),
                ToolMenuEntry("Pause VM", self._on_pause_vm, enabled=False),
            ],
        )
        self.continue_btn = vm_actions["Continue VM"]
        self.pause_btn = vm_actions["Pause VM"]

    def _build_config_row(self, exec_layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the sandbox VM/environment configuration row.

        Adds the timeout, memory-limit, and network-access controls that
        feed ``SandboxBridge.create``'s ``timeout_seconds``,
        ``memory_limit_mb``, and ``network_enabled`` parameters.

        Args:
            exec_layout: Layout to append the configuration header and row to.
            fm: Font manager used for consistent heading styling.
        """
        config_header = QLabel("Sandbox Configuration")
        config_header.setFont(fm.get_heading_font(10))
        exec_layout.addWidget(config_header)

        config_row = QHBoxLayout()
        timeout_label = QLabel("Timeout (s):")
        timeout_label.setObjectName("toolbar_label")
        config_row.addWidget(timeout_label)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(_TIMEOUT_MIN_SECONDS, _TIMEOUT_MAX_SECONDS)
        self._timeout_spin.setValue(_TIMEOUT_DEFAULT_SECONDS)
        self._timeout_spin.setMinimumWidth(_MIN_SPIN_WIDTH)
        self._timeout_spin.setToolTip("Sandbox execution timeout in seconds")
        config_row.addWidget(self._timeout_spin)

        memory_label = QLabel("Memory (MB):")
        memory_label.setObjectName("toolbar_label")
        config_row.addWidget(memory_label)

        self._memory_limit_spin = QSpinBox()
        self._memory_limit_spin.setRange(_MEMORY_MIN_MB, _MEMORY_MAX_MB)
        self._memory_limit_spin.setValue(_MEMORY_DEFAULT_MB)
        self._memory_limit_spin.setMinimumWidth(_MIN_SPIN_WIDTH)
        self._memory_limit_spin.setToolTip("Sandbox memory limit in megabytes")
        config_row.addWidget(self._memory_limit_spin)

        self._network_enabled_check = QCheckBox("Network Enabled")
        self._network_enabled_check.setChecked(False)
        self._network_enabled_check.setToolTip("Allow the sandbox instance to access the network")
        config_row.addWidget(self._network_enabled_check)

        config_row.addStretch(1)
        exec_layout.addLayout(config_row)

    def _build_analysis_controls(self, exec_layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the L3 instance-management and analysis control rows.

        Adds the controls that drive ``SandboxBridge.list`` (refresh the
        Instances tab), ``snapshot_list`` (refresh the Snapshots tab),
        ``get_pending_messages`` (guest-agent inbox), ``anti_evasion``
        (with a profile field), ``detect_c2``, and ``diff`` (two
        instance-id fields plus a Compare action).

        Args:
            exec_layout: Layout to append the analysis control header and rows to.
            fm: Font manager used for consistent heading and input styling.
        """
        controls_header = QLabel("Instances & Analysis")
        controls_header.setFont(fm.get_heading_font(10))
        exec_layout.addWidget(controls_header)

        instances_row = QHBoxLayout()

        self._refresh_instances_btn = QPushButton("Refresh Instances")
        self._refresh_instances_btn.setObjectName("tool_button")
        self._refresh_instances_btn.clicked.connect(self._on_refresh_instances)
        instances_row.addWidget(self._refresh_instances_btn)

        self._refresh_snapshots_btn = QPushButton("Refresh Snapshots")
        self._refresh_snapshots_btn.setObjectName("tool_button")
        self._refresh_snapshots_btn.setEnabled(False)
        self._refresh_snapshots_btn.clicked.connect(self._on_refresh_snapshots)
        instances_row.addWidget(self._refresh_snapshots_btn)

        self._pending_messages_btn = QPushButton("Pending Messages")
        self._pending_messages_btn.setObjectName("tool_button")
        self._pending_messages_btn.setEnabled(False)
        self._pending_messages_btn.clicked.connect(self._on_pending_messages)
        instances_row.addWidget(self._pending_messages_btn)

        self._detect_c2_btn = QPushButton("Detect C2")
        self._detect_c2_btn.setObjectName("tool_button")
        self._detect_c2_btn.setEnabled(False)
        self._detect_c2_btn.clicked.connect(self._on_detect_c2)
        instances_row.addWidget(self._detect_c2_btn)

        instances_row.addStretch(1)
        exec_layout.addLayout(instances_row)

        evasion_row = QHBoxLayout()
        evasion_label = QLabel("Anti-Evasion Profile:")
        evasion_label.setObjectName("toolbar_label")
        evasion_row.addWidget(evasion_label)

        self._anti_evasion_profile_input = QLineEdit()
        self._anti_evasion_profile_input.setFont(fm.get_code_font(9))
        self._anti_evasion_profile_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        self._anti_evasion_profile_input.setPlaceholderText("default")
        self._anti_evasion_profile_input.setToolTip("Anti-evasion hardening profile name (QEMU only)")
        evasion_row.addWidget(self._anti_evasion_profile_input)

        self._anti_evasion_btn = QPushButton("Apply Anti-Evasion")
        self._anti_evasion_btn.setObjectName("tool_button")
        self._anti_evasion_btn.setEnabled(False)
        self._anti_evasion_btn.clicked.connect(self._on_anti_evasion)
        evasion_row.addWidget(self._anti_evasion_btn)
        exec_layout.addLayout(evasion_row)

        diff_row = QHBoxLayout()
        diff_label = QLabel("Diff Instances:")
        diff_label.setObjectName("toolbar_label")
        diff_row.addWidget(diff_label)

        self._diff_instance_a_input = QLineEdit()
        self._diff_instance_a_input.setFont(fm.get_code_font(9))
        self._diff_instance_a_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        self._diff_instance_a_input.setPlaceholderText("Instance A ID")
        diff_row.addWidget(self._diff_instance_a_input)

        self._diff_instance_b_input = QLineEdit()
        self._diff_instance_b_input.setFont(fm.get_code_font(9))
        self._diff_instance_b_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        self._diff_instance_b_input.setPlaceholderText("Instance B ID")
        diff_row.addWidget(self._diff_instance_b_input)

        self._diff_btn = QPushButton("Compare")
        self._diff_btn.setObjectName("tool_button")
        self._diff_btn.setEnabled(False)
        self._diff_btn.clicked.connect(self._on_diff)
        diff_row.addWidget(self._diff_btn)
        exec_layout.addLayout(diff_row)

    @override
    def _create_content(self) -> QWidget:
        """Create the sandbox management content area.

        Returns:
            QWidget: Splitter with execution controls and output tabs.
        """
        fm = FontManager.get_instance()
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False)

        exec_container = QWidget()
        exec_layout = QVBoxLayout(exec_container)
        exec_layout.setContentsMargins(_EXEC_MARGIN, _EXEC_MARGIN, _EXEC_MARGIN, _EXEC_MARGIN)
        exec_layout.setSpacing(_EXEC_SPACING)

        self._build_config_row(exec_layout, fm)

        exec_header = QLabel("Binary Execution")
        exec_header.setFont(fm.get_heading_font(10))
        exec_layout.addWidget(exec_header)

        path_row = QHBoxLayout()
        path_label = QLabel("Binary:")
        path_label.setObjectName("toolbar_label")
        path_row.addWidget(path_label)

        self._binary_path_input = QLineEdit()
        self._binary_path_input.setFont(fm.get_code_font(9))
        self._binary_path_input.setMinimumWidth(_MIN_FIELD_WIDTH)
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
        self._args_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        args_row.addWidget(self._args_input)

        exec_layout.addLayout(args_row)

        companions_row = QHBoxLayout()
        companions_label = QLabel("Companions:")
        companions_label.setObjectName("toolbar_label")
        companions_row.addWidget(companions_label)

        self._companions_input = QLineEdit()
        self._companions_input.setFont(fm.get_code_font(9))
        self._companions_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        self._companions_input.setPlaceholderText("Files or folders the target needs beside it, separated by ;")
        self._companions_input.setToolTip(
            "Anything the target loads from its own directory - a DLL, a resource or locale folder, a config file.\n"
            "Staged without them a target still runs and still exits 0 while doing nothing.",
        )
        companions_row.addWidget(self._companions_input)

        self._companions_browse_btn = QPushButton("Add...")
        self._companions_browse_btn.setObjectName("secondary_button")
        self._companions_browse_btn.clicked.connect(self._on_browse_companions)
        companions_row.addWidget(self._companions_browse_btn)

        self._run_btn = QPushButton("Run in Sandbox")
        self._run_btn.setObjectName("tool_button")
        self._run_btn.setEnabled(False)
        self._run_btn.clicked.connect(self._on_run_binary)
        companions_row.addWidget(self._run_btn)
        exec_layout.addLayout(companions_row)

        cmd_row = QHBoxLayout()
        cmd_label = QLabel("Command:")
        cmd_label.setObjectName("toolbar_label")
        cmd_row.addWidget(cmd_label)

        self._cmd_input = QLineEdit()
        self._cmd_input.setFont(fm.get_code_font(9))
        self._cmd_input.setMinimumWidth(_MIN_FIELD_WIDTH)
        self._cmd_input.setPlaceholderText("Execute command in sandbox...")
        cmd_row.addWidget(self._cmd_input)

        self._exec_cmd_btn = QPushButton("Execute")
        self._exec_cmd_btn.setObjectName("tool_button")
        self._exec_cmd_btn.setEnabled(False)
        self._exec_cmd_btn.clicked.connect(self._on_execute_command)
        cmd_row.addWidget(self._exec_cmd_btn)
        exec_layout.addLayout(cmd_row)

        self._build_analysis_controls(exec_layout, fm)

        main_splitter.addWidget(self._make_scrollable(exec_container))

        output_tabs = QTabWidget()

        self._console_output = QPlainTextEdit()
        self._console_output.setFont(fm.get_code_font(9))
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

        def _vnc_status_slot(c: int) -> None:
            """Forward VNC connection status changes into the panel handler.

            Args:
                c: Connection status integer emitted by the VNC widget.
            """
            self._on_vnc_status_changed(connected=bool(c))

        vnc_w.connection_status_changed.connect(_vnc_status_slot)
        self._vnc_tab_index = output_tabs.addTab(vnc_w, "VM Display")
        self._output_tabs = output_tabs

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

        for result_tree in (
            self._file_changes_tree,
            self._registry_changes_tree,
            self._network_tree,
            self._snapshots_tree,
            self._api_calls_tree,
            self._dll_loads_tree,
            self._services_tree,
            self._kernel_objects_tree,
            self._injections_tree,
            self._resources_tree,
            self._clipboard_tree,
            self._timeline_tree,
            self._iocs_tree,
            self._behaviors_tree,
            self._instances_tree,
        ):
            _configure_result_columns(result_tree)

        main_splitter.addWidget(output_tabs)

        main_splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        self.sandbox_type_combo.currentTextChanged.connect(self._on_sandbox_type_changed)
        self._apply_backend_capability_gating()
        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Stop the status poll timer, disconnect VNC, halt PCAP, and shut down the sandbox."""
        self._disconnect_vnc_display()
        self._status_poll_timer.stop()
        if self._bridge is None or self.sandbox_id is None:
            return

        bridge = self._bridge
        sandbox_id = self.sandbox_id

        def _log_destroy_error(exc: object) -> None:
            """Log a sandbox destroy failure during panel cleanup.

            Args:
                exc: Exception raised by ``bridge.destroy``.
            """
            _logger.warning(
                "sandbox_cleanup_destroy_skipped",
                sandbox_id=sandbox_id,
                error=str(exc),
            )

        def _destroy_sandbox(_result: object) -> None:
            """Clear PCAP state and request sandbox destruction after PCAP stop.

            Args:
                _result: Unused result from the preceding ``stop_pcap`` call.
            """
            self._pcap_capture_id = None
            run_bridge_coroutine_logged(
                bridge.destroy(sandbox_id),
                on_success=None,
                on_error=_log_destroy_error,
                parent=self,
                event="sandbox_cleanup_destroy",
                logger=_logger,
            )

        def _log_stop_pcap_error(exc: object) -> None:
            """Log a PCAP stop failure, then continue with sandbox destruction.

            Args:
                exc: Exception raised by ``bridge.stop_pcap``.
            """
            _logger.warning(
                "sandbox_cleanup_pcap_stop_skipped",
                sandbox_id=sandbox_id,
                error=str(exc),
            )
            _destroy_sandbox(None)

        run_bridge_coroutine_logged(
            bridge.stop_pcap(sandbox_id),
            on_success=_destroy_sandbox,
            on_error=_log_stop_pcap_error,
            parent=self,
            event="sandbox_cleanup_stop_pcap",
            logger=_logger,
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
        """Wire a legacy ``SandboxBase`` into the panel via a bridge adapter.

        The legacy ``SandboxBase`` contract pre-dates the
        ``SandboxBridge``-based panel API. To preserve the public method
        without short-circuiting around the bridge layer, the supplied
        instance is wrapped in a fresh ``SandboxBridge``: a single-slot
        ``SandboxManager`` is constructed, a ``SandboxInstance`` for the
        legacy sandbox is registered against it, and the resulting
        bridge is installed via :meth:`set_bridge` so all subsequent
        panel operations route through the same code path used by the
        production bridge.

        Args:
            sandbox: The SandboxBase implementation to use.
        """
        self._sandbox = sandbox
        bridge = self._build_bridge_from_sandbox(sandbox)
        self.set_bridge(bridge)
        _logger.info(
            "sandbox_set_via_bridge_adapter",
            sandbox_type=type(sandbox).__name__,
            instance_id=self.sandbox_id,
        )

    def set_sandbox_manager(self, manager: SandboxManager) -> None:
        """Wire a legacy ``SandboxManager`` into the panel via a bridge adapter.

        The supplied manager replaces the ``SandboxBridge``'s lazy
        manager slot, so any sandbox instances it already owns are
        directly accessible through the bridge API used by this panel.

        Args:
            manager: The SandboxManager instance.
        """
        self._sandbox_manager = manager
        bridge = self._build_bridge_from_manager(manager)
        self.set_bridge(bridge)
        _logger.info(
            "sandbox_manager_set_via_bridge_adapter",
            instance_count=len(manager.instances),
        )

    def get_sandbox(self) -> SandboxBase | None:
        """Get the legacy sandbox backend reachable through the bridge.

        Returns the ``SandboxBase`` instance currently bound to the
        panel's bridge, looking it up through ``get_bridge`` so it
        reflects any subsequent ``set_bridge`` calls. Falls back to the
        raw value passed to :meth:`set_sandbox` when no bridge is
        wired up.

        Returns:
            SandboxBase | None: The sandbox instance reachable through
            the active bridge, or ``None`` if no sandbox is bound.
        """
        bridge = self.get_bridge()
        if bridge is not None and self.sandbox_id is not None:
            manager = bridge.manager
            if manager is not None:
                instance = manager.instances
                for entry in instance:
                    if entry.id == self.sandbox_id:
                        return entry.sandbox
        return self._sandbox

    def _build_bridge_from_sandbox(self, sandbox: SandboxBase) -> SandboxBridge:
        """Wrap a ``SandboxBase`` in a fresh ``SandboxBridge``.

        Constructs a ``SandboxManager``, registers the supplied legacy
        sandbox as a managed ``SandboxInstance`` (inferring the
        ``sandbox_type`` from the concrete class), and assigns the
        manager to a new ``SandboxBridge``. The resulting bridge can
        therefore drive every panel operation that takes ``sandbox_id``
        without recreating the underlying VM.

        Args:
            sandbox: Legacy sandbox to expose through the bridge.

        Returns:
            SandboxBridge: A bridge that owns a manager pre-populated
            with the supplied sandbox.
        """
        sandbox_type: SandboxType = "qemu" if isinstance(sandbox, QEMUSandbox) else "windows"
        bridge = SandboxBridge()
        instance_id = bridge.register_existing_sandbox(sandbox, sandbox_type)
        self.sandbox_id = instance_id
        return bridge

    @staticmethod
    def _build_bridge_from_manager(manager: SandboxManager) -> SandboxBridge:
        """Wrap a ``SandboxManager`` in a fresh ``SandboxBridge``.

        Args:
            manager: Pre-existing manager owning sandbox instances.

        Returns:
            SandboxBridge: A bridge whose manager slot is populated with
            the supplied manager.
        """
        bridge = SandboxBridge()
        bridge.attach_manager(manager)
        return bridge

    def _log(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        self._console_output.appendPlainText(message)

    def _report_failure(self, title: str, summary: str, exc: object) -> None:
        """Surface a failed user-initiated sandbox operation to the console and a dialog.

        The console line is kept as the durable record of the failure while the
        modal dialog guarantees the user actually sees it: without one, a failed
        Create (or any other toolbar action) was silent unless the Console tab
        happened to be the visible tab.

        Args:
            title: Dialog window title naming the action that failed.
            summary: Human-readable description of the failed action, without
                the error text; used verbatim for both surfaces.
            exc: Exception (or error object) reported by the failed call.
        """
        self._log(f"[-] {summary}: {exc}")
        show_error(
            self,
            title,
            f"{summary}:\n\n{exc}",
            exc=exc if isinstance(exc, BaseException) else None,
        )

    def _set_sandbox_controls_active(self, *, active: bool) -> None:
        """Enable or disable controls based on sandbox state.

        Controls whose backing operation every backend implements follow
        ``active`` directly. The QEMU-only controls are delegated to
        :meth:`_apply_backend_capability_gating`, which additionally requires
        the effective backend to be QEMU.

        Args:
            active: True to enable sandbox-active controls.
        """
        self._controls_active = active
        self.create_btn.setEnabled(not active)
        self.destroy_btn.setEnabled(active)
        self.restart_btn.setEnabled(active)
        self._run_btn.setEnabled(active)
        self.memdump_btn.setEnabled(active)
        self.yara_btn.setEnabled(active)
        self.iocs_btn.setEnabled(active)
        self.timeline_btn.setEnabled(active)
        self.behaviors_btn.setEnabled(active)
        self.copy_in_btn.setEnabled(active)
        self.copy_out_btn.setEnabled(active)
        self._exec_cmd_btn.setEnabled(active)
        self._detect_c2_btn.setEnabled(active)
        self._diff_btn.setEnabled(active)
        self._apply_backend_capability_gating()

    def _apply_backend_capability_gating(self) -> None:
        """Enable the QEMU-only controls only when the effective backend is QEMU.

        ``WindowsSandbox`` implements neither snapshots nor VM pause/continue
        nor the guest-agent message channel - it inherits the ``SandboxBase``
        implementations that raise "not supported" - and it has no VNC port, so
        its ``vnc_port`` is always ``None``. Leaving those controls enabled for
        a Windows sandbox offered actions that could only ever fail.

        The gated set mirrors exactly the ``SandboxBridge`` operations that
        reject a non-QEMU instance outright: ``snapshot_create``,
        ``snapshot_restore``, ``snapshot_list``, ``snapshot_delete``, ``stop``,
        ``cont``, ``get_pending_messages``, ``pcap_start``, ``screenshot``,
        ``anti_evasion``, ``extract_dropped_files`` and ``get_vnc_port``.
        """
        qemu_active = self._qemu_controls_supported()
        self.snapshot_btn.setEnabled(qemu_active)
        self.restore_btn.setEnabled(qemu_active)
        self.delete_snap_btn.setEnabled(qemu_active)
        self._refresh_snapshots_btn.setEnabled(qemu_active)
        self.continue_btn.setEnabled(qemu_active)
        self.pause_btn.setEnabled(qemu_active)
        self._pending_messages_btn.setEnabled(qemu_active)
        self.screenshot_btn.setEnabled(qemu_active)
        self.pcap_btn.setEnabled(qemu_active)
        self.extract_files_btn.setEnabled(qemu_active)
        self._anti_evasion_btn.setEnabled(qemu_active)
        self._set_vm_display_enabled(enabled=qemu_active)

    def _qemu_controls_supported(self) -> bool:
        """Report whether the QEMU-only controls may be enabled right now.

        Returns:
            bool: True when a sandbox is active and the backend that would
            service the QEMU-only operations is QEMU.
        """
        return self._controls_active and self._effective_sandbox_type() == "qemu"

    def _restore_shared_control(self, control: QAction | QPushButton) -> None:
        """Re-enable a finished operation's control, unless the sandbox has gone.

        Every operation disables its own control while the bridge call is in
        flight and re-enables it when the call completes. That completion can
        land *after* the sandbox it addressed was destroyed - the user only has
        to press Destroy and then the operation before the destroy lands - and
        re-enabling unconditionally then leaves a control live with no sandbox
        behind it, where pressing it does nothing at all because the handler
        returns at its own ``sandbox_id is None`` guard.

        Args:
            control: Toolbar control the finished operation had disabled.
        """
        control.setEnabled(self._controls_active)

    def _restore_qemu_only_control(self, control: QAction | QPushButton) -> None:
        """Re-enable a finished QEMU-only operation's control if it is still supported.

        Same completion-ordering problem as :meth:`_restore_shared_control`,
        with the additional requirement that the effective backend still be
        QEMU: re-enabling unconditionally reinstates a control that
        :meth:`_apply_backend_capability_gating` had deliberately gated out.

        Args:
            control: QEMU-only toolbar control the finished operation had disabled.
        """
        control.setEnabled(self._qemu_controls_supported())

    def _set_vm_display_enabled(self, *, enabled: bool) -> None:
        """Enable or disable the VM Display tab and the VNC view it hosts.

        Args:
            enabled: True when the effective backend exposes a VNC display.
        """
        if self._vnc_widget is not None:
            self._vnc_widget.setEnabled(enabled)
        self._output_tabs.setTabEnabled(self._vnc_tab_index, enabled)
        self._output_tabs.setTabToolTip(
            self._vnc_tab_index,
            "" if enabled else _VM_DISPLAY_UNSUPPORTED_TIP,
        )

    def _on_sandbox_type_changed(self, _text: str) -> None:
        """Re-apply backend capability gating after a sandbox-type selection change.

        Args:
            _text: Newly selected combo text. Unused: the effective type is
                re-read through :meth:`_effective_sandbox_type` so an active
                instance keeps precedence over the combo.
        """
        self._apply_backend_capability_gating()

    def _selected_sandbox_type(self) -> SandboxType:
        """Get the sandbox type from the combo box selection.

        Returns:
            SandboxType: Sandbox type literal: ``"windows"`` or ``"qemu"``.
        """
        combo_text = self.sandbox_type_combo.currentText()
        return "qemu" if combo_text == "QEMU" else "windows"

    def _effective_sandbox_type(self) -> SandboxType:
        """Get the sandbox type the panel's controls must be gated against.

        While an instance is live its own backend decides what is supported,
        regardless of what the toolbar combo currently shows; with no live
        instance the combo selection is what the next create would use.

        Returns:
            SandboxType: The live instance's type when one exists, otherwise
            the type currently selected in the toolbar combo.
        """
        active_type = self._active_sandbox_type
        if active_type is not None:
            return active_type
        return self._selected_sandbox_type()

    def _sandbox_create_config(self) -> _SandboxCreateConfig:
        """Read the VM/environment configuration controls for sandbox creation.

        Returns:
            _SandboxCreateConfig: Keyword arguments for
            ``SandboxBridge.create``: ``timeout_seconds``,
            ``network_enabled``, and ``memory_limit_mb`` reflecting the
            current toolbar widget values.
        """
        return {
            "timeout_seconds": self._timeout_spin.value(),
            "network_enabled": self._network_enabled_check.isChecked(),
            "memory_limit_mb": self._memory_limit_spin.value(),
        }

    @staticmethod
    def _qemu_create_config(sandbox_type: SandboxType) -> QEMUConfig | None:
        """Build the QEMU backend configuration for a sandbox creation request.

        The generic ``SandboxConfig`` built from the toolbar cannot express the
        qcow2 disk image QEMU needs to boot, so it is read from the persisted
        sandbox settings written by the configuration dialog. Without this the
        backend receives no image and the QEMU sandbox can never start.

        Args:
            sandbox_type: Sandbox type selected in the toolbar.

        Returns:
            QEMUConfig | None: Configuration loaded from the persisted sandbox
            settings for the ``"qemu"`` type, or None for other backends.
        """
        if sandbox_type != "qemu":
            return None
        return load_qemu_config()

    def _on_create(self) -> None:
        """Create a new sandbox environment."""
        if self._bridge is None:
            self._log("[!] No sandbox bridge configured")
            _logger.warning("sandbox_create_failed_no_bridge")
            return

        sandbox_type = self._selected_sandbox_type()
        config = self._sandbox_create_config()
        qemu_config = self._qemu_create_config(sandbox_type)
        _logger.debug("sandbox_create_via_bridge", sandbox_type=sandbox_type, **config)
        self.create_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.create(sandbox_type=sandbox_type, qemu_config=qemu_config, **config),
            on_success=self._on_bridge_create_success,
            on_error=self._on_create_error,
            parent=self,
            event="sandbox_create",
            logger=_logger,
            level="info",
            sandbox_type=sandbox_type,
            **config,
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
        self._diff_instance_a_input.setText(self.sandbox_id)
        self._status_indicator.setText("Active")
        self._active_sandbox_type = self._selected_sandbox_type()
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
        self._report_failure("Sandbox Creation Failed", "Failed to create sandbox", exc)
        self.create_btn.setEnabled(True)
        _logger.warning("sandbox_create_failed", error=str(exc))

    def _on_destroy(self) -> None:
        """Destroy the current sandbox environment."""
        if self._bridge is None or self.sandbox_id is None:
            return

        _logger.info("sandbox_destroy_started", sandbox_id=self.sandbox_id)
        self.destroy_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.destroy(self.sandbox_id),
            on_success=self._on_destroy_success,
            on_error=self._on_destroy_error,
            parent=self,
            event="sandbox_destroy",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
        )

    def _on_destroy_success(self, _result: object) -> None:
        """Handle successful sandbox destruction.

        Args:
            _result: Bridge call result (unused).
        """
        self._disconnect_vnc_display()
        self._log("[+] Sandbox destroyed")
        self.sandbox_id = None
        self._active_sandbox_type = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(active=False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()
        _logger.info("sandbox_destroyed", sandbox_id=self.sandbox_id)

    def _on_destroy_error(self, exc: object) -> None:
        """Handle sandbox destruction failure.

        The panel state is settled before the dialog is raised: the dialog runs
        a nested Qt event loop, so anything left inconsistent here stays that
        way - and keeps being polled - for as long as the user takes to dismiss
        it.

        Args:
            exc: The exception from the failed operation.
        """
        self.destroy_btn.setEnabled(self.sandbox_id is not None)
        _logger.warning("sandbox_destroy_failed", error=str(exc))
        self._poll_status()
        self._report_failure("Sandbox Destroy Failed", "Failed to destroy sandbox", exc)

    def _on_restart(self) -> None:
        """Restart the sandbox environment through the manager's restart operation.

        Issues a single ``SandboxBridge.restart`` call rather than chaining a
        destroy and a create from the GUI: the teardown/recreate pair and its
        failure semantics belong to the manager, so a failed restart can never
        leave the panel pointing at an instance that no longer exists.
        """
        if self._bridge is None or self.sandbox_id is None:
            return

        sandbox_type = self._effective_sandbox_type()
        config = self._sandbox_create_config()
        qemu_config = self._qemu_create_config(sandbox_type)
        _logger.debug("sandbox_restart_started", sandbox_id=self.sandbox_id)
        self.restart_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.restart(self.sandbox_id, qemu_config=qemu_config, **config),
            on_success=self._on_restart_success,
            on_error=self._on_restart_error,
            parent=self,
            event="sandbox_restart",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            sandbox_type=sandbox_type,
            **config,
        )

    def _on_restart_success(self, result: object) -> None:
        """Handle a completed sandbox restart.

        The replacement is a different instance on a different VNC port, so the
        display is torn down and re-attached rather than left pointing at the
        destroyed VM's port, and the diff selector is re-seeded with the new id.

        Args:
            result: Dictionary with the replacement instance_id from the bridge.
        """
        self._disconnect_vnc_display()
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            self.sandbox_id = str(typed.get("instance_id", "active"))
        if self.sandbox_id is not None:
            self._diff_instance_a_input.setText(self.sandbox_id)
        self._log("[+] Sandbox restarted")
        self._clear_report_tabs()
        self._restore_shared_control(self.restart_btn)
        _logger.info("sandbox_restarted", sandbox_id=self.sandbox_id)

        QTimer.singleShot(2000, self._connect_vnc_display)

    def _on_restart_error(self, exc: object) -> None:
        """Handle sandbox restart failure.

        A failed restart always leaves the panel without a usable instance: the
        manager tears the original down before recreating it, and the only
        failure that skips the teardown is an unknown instance id, which means
        the panel's id was already stale. Either way the panel must stop
        pretending a sandbox is live.

        The teardown runs before the dialog: the dialog spins a nested Qt event
        loop, so raising it first would leave the status-poll timer dispatching
        against the destroyed instance for as long as the dialog stayed open.

        Args:
            exc: The exception from the failed operation.
        """
        _logger.warning("sandbox_restart_failed", error=str(exc))
        self._finish_restart_after_destroy_only()
        self._report_failure("Sandbox Restart Failed", "Failed to restart sandbox", exc)

    def _finish_restart_after_destroy_only(self) -> None:
        """Reflect UI state when a restart tore the old instance down without replacing it.

        Applied when the old sandbox instance has already been torn down server-side but no replacement was created, so ``sandbox_id`` must
        stop referring to the destroyed instance and every sandbox-active control must be disabled again.
        """
        self._disconnect_vnc_display()
        self.sandbox_id = None
        self._active_sandbox_type = None
        self._status_indicator.setText("Inactive")
        self._set_sandbox_controls_active(active=False)
        self._status_poll_timer.stop()
        self.tool_closed.emit()

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

    def _append_companions(self, paths: list[str]) -> None:
        """Add paths to the companions field without dropping what is there.

        Args:
            paths: Host paths to add. Ones already listed are not repeated.
        """
        existing = [entry.strip() for entry in self._companions_input.text().split(_COMPANION_SEPARATOR) if entry.strip()]
        existing.extend(path for path in paths if path not in existing)
        self._companions_input.setText(_COMPANION_SEPARATOR.join(existing))

    def _on_browse_companions(self) -> None:
        """Offer the two shapes a companion really takes: files, or a folder.

        A resource or locale tree has to arrive whole, and picking its members one by one would flatten it, so a folder is its own choice
        rather than a multi-selection of files.
        """
        menu = QMenu(self)
        files_action = menu.addAction("Files...")
        folder_action = menu.addAction("Folder...")
        chosen = menu.exec(self._companions_browse_btn.mapToGlobal(self._companions_browse_btn.rect().bottomLeft()))

        if chosen is files_action:
            paths, _ = QFileDialog.getOpenFileNames(self, "Select companion files", "", "All Files (*)")
            if paths:
                self._append_companions(paths)
        elif chosen is folder_action:
            folder = QFileDialog.getExistingDirectory(self, "Select companion folder")
            if folder:
                self._append_companions([folder])

    def _on_run_binary(self) -> None:
        """Execute the selected binary inside the sandbox.

        The run is given the same backend configuration ``Create`` and ``Restart`` already build, because a QEMU run that reaches the
        backend without a disk image cannot start a virtual machine at all.

        It is also directed at the instance this panel is showing, by id. ``reuse_instance`` alone cannot say *which* one: it takes
        whichever idle sandbox of that type comes first, so with more than one running the binary executed somewhere other than where the
        operator was watching, and the report that came back overwrote the displayed instance's tabs. ``reuse_instance`` stays set for the
        case where nothing has been created yet, where it still avoids booting a second virtual machine beside the first.
        """
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

        companions = [entry.strip() for entry in self._companions_input.text().split(_COMPANION_SEPARATOR) if entry.strip()]
        missing = [entry for entry in companions if not Path(entry).exists()]
        if missing:
            self._log(f"[!] Companion not found: {', '.join(missing)}")
            return

        self._log(f"[*] Executing: {binary.name} {args}")
        self._clear_report_tabs()
        self._run_btn.setEnabled(False)
        self._pending_binary = binary
        _logger.debug("sandbox_binary_execution_started", binary=binary.name, exec_args=args)

        run_bridge_coroutine_logged(
            self._bridge.run_binary(
                binary_path=binary_path,
                args=args_list,
                sandbox_type=sandbox_type,
                companions=companions or None,
                qemu_config=self._qemu_create_config(sandbox_type),
                reuse_instance=True,
                instance_id=self.sandbox_id,
            ),
            on_success=self._on_run_binary_success,
            on_error=self._on_run_binary_error,
            parent=self,
            event="sandbox_run_binary",
            logger=_logger,
            level="info",
            binary_path=str(binary_path),
            arg_count=len(args_list) if args_list is not None else 0,
            companion_count=len(companions),
            sandbox_type=sandbox_type,
        )

    def _on_run_binary_success(self, result: object) -> None:
        """Handle successful binary execution.

        Args:
            result: Dictionary with execution report from bridge.
        """
        binary_name = self._pending_binary.name
        self._log("[+] Execution completed")
        self._restore_shared_control(self._run_btn)
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
                    _format_file_change_detail(change),
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
        self._report_failure("Sandbox Execution Failed", "Execution failed", exc)
        self._restore_shared_control(self._run_btn)
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
        run_bridge_coroutine_logged(
            self._bridge.snapshot_create(self.sandbox_id, snapshot_label),
            on_success=self._on_take_snapshot_success,
            on_error=self._on_take_snapshot_error,
            parent=self,
            event="sandbox_snapshot_create",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            label=snapshot_label,
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
        self._restore_qemu_only_control(self.snapshot_btn)
        self._pending_snapshot_label = None
        _logger.info("sandbox_snapshot_taken", snapshot_id=snapshot_id, label=label)

    def _on_take_snapshot_error(self, exc: object) -> None:
        """Handle snapshot failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Snapshot Failed", "Snapshot failed", exc)
        self._restore_qemu_only_control(self.snapshot_btn)
        self._pending_snapshot_label = None
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
        run_bridge_coroutine_logged(
            self._bridge.snapshot_restore(self.sandbox_id, snapshot_id),
            on_success=self._on_restore_snapshot_success,
            on_error=self._on_restore_snapshot_error,
            parent=self,
            event="sandbox_snapshot_restore",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            snapshot_id=snapshot_id,
        )

    def _on_restore_snapshot_success(self, _result: object) -> None:
        """Handle successful snapshot restore.

        Args:
            _result: Bridge call result (unused).
        """
        snapshot_id = getattr(self, "_pending_snapshot_id", "unknown")
        self._log(f"[+] Restored snapshot: {snapshot_id}")
        self._clear_report_tabs()
        self._restore_qemu_only_control(self.restore_btn)
        _logger.info("sandbox_snapshot_restored", snapshot_id=snapshot_id)

    def _on_restore_snapshot_error(self, exc: object) -> None:
        """Handle snapshot restore failure.

        Args:
            exc: The exception from the failed operation.
        """
        snapshot_id = getattr(self, "_pending_snapshot_id", "unknown")
        self._report_failure("Snapshot Restore Failed", "Restore failed", exc)
        self._restore_qemu_only_control(self.restore_btn)
        _logger.warning("sandbox_snapshot_restore_failed", snapshot_id=snapshot_id, error=str(exc))

    def _on_screenshot(self) -> None:
        """Capture a screenshot of the sandbox display."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.screenshot_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.screenshot(self.sandbox_id),
            on_success=self._on_screenshot_success,
            on_error=self._on_screenshot_error,
            parent=self,
            event="sandbox_screenshot",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
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
        self._restore_qemu_only_control(self.screenshot_btn)

    def _on_screenshot_error(self, exc: object) -> None:
        """Handle screenshot capture failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Screenshot Failed", "Screenshot failed", exc)
        self._restore_qemu_only_control(self.screenshot_btn)

    def _on_pcap_toggle(self) -> None:
        """Toggle packet capture start/stop."""
        if self._bridge is None or self.sandbox_id is None:
            return

        if self._pcap_capture_id is None:
            self.pcap_btn.setEnabled(False)
            run_bridge_coroutine_logged(
                self._bridge.pcap_start(self.sandbox_id),
                on_success=self._on_pcap_start_success,
                on_error=self._on_pcap_start_error,
                parent=self,
                event="sandbox_pcap_start",
                logger=_logger,
                level="info",
                sandbox_id=self.sandbox_id,
            )
        else:
            self.pcap_btn.setEnabled(False)
            run_bridge_coroutine_logged(
                self._bridge.pcap_stop(self.sandbox_id, self._pcap_capture_id),
                on_success=self._on_pcap_stop_success,
                on_error=self._on_pcap_stop_error,
                parent=self,
                event="sandbox_pcap_stop",
                logger=_logger,
                level="info",
                sandbox_id=self.sandbox_id,
                capture_id=self._pcap_capture_id,
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
        self._restore_qemu_only_control(self.pcap_btn)

    def _on_pcap_start_error(self, exc: object) -> None:
        """Handle PCAP capture start failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("PCAP Start Failed", "PCAP start failed", exc)
        self._restore_qemu_only_control(self.pcap_btn)

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
        self._restore_qemu_only_control(self.pcap_btn)

    def _on_pcap_stop_error(self, exc: object) -> None:
        """Handle PCAP capture stop failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("PCAP Stop Failed", "PCAP stop failed", exc)
        self._pcap_capture_id = None
        self.pcap_btn.setText("PCAP Start")
        self._restore_qemu_only_control(self.pcap_btn)

    def _on_memory_dump(self) -> None:
        """Dump guest memory from the sandbox.

        Windows Sandbox targets a specific guest process, so on that backend this first enumerates the live guest processes and lets the
        user pick one via :class:`GuestProcessPickerDialog` before dispatching the dump; ``SandboxBridge.memory_dump`` otherwise rejects the
        call outright for a missing ``target_pid`` (S17-D10b / audit7 F-0021). QEMU dumps the whole guest and needs no PID, so that path
        dispatches directly, unchanged from before this picker existed.
        """
        if self._bridge is None or self.sandbox_id is None:
            return
        if self._effective_sandbox_type() == "windows":
            self._start_windows_memory_dump()
            return
        self._dispatch_memory_dump()

    def _dispatch_memory_dump(self, *, target_pid: int | None = None) -> None:
        """Dispatch the bridge memory-dump call.

        Args:
            target_pid: Guest-side PID to target. ``None`` dispatches a
                whole-guest dump (QEMU); the bridge requires a positive PID
                for Windows Sandbox instances.
        """
        if self._bridge is None or self.sandbox_id is None:
            return
        self.memdump_btn.setEnabled(False)
        coro = (
            self._bridge.memory_dump(self.sandbox_id)
            if target_pid is None
            else self._bridge.memory_dump(self.sandbox_id, target_pid=target_pid)
        )
        run_bridge_coroutine_logged(
            coro,
            on_success=self._on_memory_dump_success,
            on_error=self._on_memory_dump_error,
            parent=self,
            event="sandbox_memory_dump",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
        )

    def _start_windows_memory_dump(self) -> None:
        """Enumerate guest processes so the user can pick a memory-dump target.

        Windows Sandbox's ``MiniDumpWriteDump`` implementation requires a specific guest PID. This dispatches
        :meth:`SandboxBridge.list_guest_processes` and, on success, opens the process picker so the user can choose one.
        """
        if self._bridge is None or self.sandbox_id is None:
            return
        self.memdump_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.list_guest_processes(self.sandbox_id),
            on_success=self._on_list_guest_processes_for_dump_success,
            on_error=self._on_list_guest_processes_for_dump_error,
            parent=self,
            event="sandbox_list_guest_processes",
            logger=_logger,
            level="debug",
            sandbox_id=self.sandbox_id,
        )

    def _on_list_guest_processes_for_dump_success(self, result: object) -> None:
        """Open the guest process picker once enumeration succeeds.

        Args:
            result: Dictionary with a ``processes`` list from the bridge.
        """
        processes = self._parse_guest_process_rows(result)
        if not processes:
            self._restore_shared_control(self.memdump_btn)
            show_info(self, "Memory Dump", "The guest reported no running processes to dump.")
            return

        dialog = GuestProcessPickerDialog(processes, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            self._restore_shared_control(self.memdump_btn)
            return
        pid = dialog.selected_pid()
        if pid is None:
            self._restore_shared_control(self.memdump_btn)
            return
        self._dispatch_memory_dump(target_pid=pid)

    def _on_list_guest_processes_for_dump_error(self, exc: object) -> None:
        """Handle a failed guest process enumeration.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Memory Dump Failed", "Failed to enumerate guest processes", exc)
        self._restore_shared_control(self.memdump_btn)

    @staticmethod
    def _parse_guest_process_rows(result: object) -> list[GuestProcessRow]:
        """Extract process rows from a ``list_guest_processes`` bridge result.

        Args:
            result: Raw bridge return value, expected to be a dict with a
                ``processes`` list of ``{"pid", "name", "path"}`` mappings.

        Returns:
            list[GuestProcessRow]: Well-formed process rows; malformed or
            missing entries are dropped rather than raised.
        """
        if not isinstance(result, dict):
            return []
        typed = cast("dict[str, object]", result)
        raw_processes = typed.get("processes")
        if not isinstance(raw_processes, list):
            return []

        rows: list[GuestProcessRow] = []
        for entry in cast("list[object]", raw_processes):
            if not isinstance(entry, dict):
                continue
            entry_dict = cast("dict[str, object]", entry)
            pid_val = entry_dict.get("pid")
            if not isinstance(pid_val, int) or pid_val <= 0:
                continue
            name_val = entry_dict.get("name")
            path_val = entry_dict.get("path")
            rows.append(
                GuestProcessRow(
                    pid=pid_val,
                    name=str(name_val) if name_val is not None else "",
                    path=str(path_val) if path_val is not None else "",
                ),
            )
        return rows

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
        self._restore_shared_control(self.memdump_btn)

    def _on_memory_dump_error(self, exc: object) -> None:
        """Handle memory dump failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Memory Dump Failed", "Memory dump failed", exc)
        self._restore_shared_control(self.memdump_btn)

    def _on_extract_files(self) -> None:
        """Extract files dropped during sandbox execution."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.extract_files_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.extract_dropped_files(self.sandbox_id),
            on_success=self._on_extract_files_success,
            on_error=self._on_extract_files_error,
            parent=self,
            event="sandbox_extract_dropped_files",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
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
        self._restore_qemu_only_control(self.extract_files_btn)

    def _on_extract_files_error(self, exc: object) -> None:
        """Handle file extraction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("File Extraction Failed", "File extraction failed", exc)
        self._restore_qemu_only_control(self.extract_files_btn)

    def _on_yara_scan(self) -> None:
        """Run YARA scan against sandbox artifacts."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.yara_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.yara_scan(self.sandbox_id),
            on_success=self._on_yara_scan_success,
            on_error=self._on_yara_scan_error,
            parent=self,
            event="sandbox_yara_scan",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
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
        self._restore_shared_control(self.yara_btn)

    def _on_yara_scan_error(self, exc: object) -> None:
        """Handle YARA scan failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("YARA Scan Failed", "YARA scan failed", exc)
        self._restore_shared_control(self.yara_btn)

    def _on_extract_iocs(self) -> None:
        """Extract IOCs from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.iocs_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.extract_iocs(self.sandbox_id),
            on_success=self._on_extract_iocs_success,
            on_error=self._on_extract_iocs_error,
            parent=self,
            event="sandbox_extract_iocs",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
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
        self._restore_shared_control(self.iocs_btn)

    def _on_extract_iocs_error(self, exc: object) -> None:
        """Handle IOC extraction failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("IOC Extraction Failed", "IOC extraction failed", exc)
        self._restore_shared_control(self.iocs_btn)

    def _on_timeline(self) -> None:
        """Generate an event timeline from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.timeline_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.timeline(self.sandbox_id),
            on_success=self._on_timeline_success,
            on_error=self._on_timeline_error,
            parent=self,
            event="sandbox_timeline",
            logger=_logger,
            sandbox_id=self.sandbox_id,
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
        self._restore_shared_control(self.timeline_btn)

    def _on_timeline_error(self, exc: object) -> None:
        """Handle timeline generation failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Timeline Generation Failed", "Timeline generation failed", exc)
        self._restore_shared_control(self.timeline_btn)

    def _on_detect_behaviors(self) -> None:
        """Detect behavioral signatures from the last execution report."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.behaviors_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.detect_behaviors(self.sandbox_id),
            on_success=self._on_detect_behaviors_success,
            on_error=self._on_detect_behaviors_error,
            parent=self,
            event="sandbox_detect_behaviors",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
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
        self._restore_shared_control(self.behaviors_btn)

    def _on_detect_behaviors_error(self, exc: object) -> None:
        """Handle behavior detection failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Behavior Detection Failed", "Behavior detection failed", exc)
        self._restore_shared_control(self.behaviors_btn)

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
        run_bridge_coroutine_logged(
            self._bridge.copy_to(self.sandbox_id, source_path, dest_path),
            on_success=self._on_copy_in_success,
            on_error=self._on_copy_in_error,
            parent=self,
            event="sandbox_copy_to",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            source=source_path,
            dest=dest_path,
        )

    def _on_copy_in_success(self, _result: object) -> None:
        """Handle successful file copy into sandbox.

        Args:
            _result: Bridge call result (unused).
        """
        self._log(f"[+] Copied into sandbox: {self._pending_copy_in_source} -> {self._pending_copy_in_dest}")
        self._restore_shared_control(self.copy_in_btn)

    def _on_copy_in_error(self, exc: object) -> None:
        """Handle file copy into sandbox failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Copy Into Sandbox Failed", "Copy into sandbox failed", exc)
        self._restore_shared_control(self.copy_in_btn)

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
        run_bridge_coroutine_logged(
            self._bridge.copy_from(self.sandbox_id, sandbox_path, dest_path),
            on_success=self._on_copy_out_success,
            on_error=self._on_copy_out_error,
            parent=self,
            event="sandbox_copy_from",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            source=sandbox_path,
            dest=dest_path,
        )

    def _on_copy_out_success(self, _result: object) -> None:
        """Handle successful file copy from sandbox.

        Args:
            _result: Bridge call result (unused).
        """
        self._log(f"[+] Copied from sandbox: {self._pending_copy_out_source} -> {self._pending_copy_out_dest}")
        self._restore_shared_control(self.copy_out_btn)

    def _on_copy_out_error(self, exc: object) -> None:
        """Handle file copy from sandbox failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Copy From Sandbox Failed", "Copy from sandbox failed", exc)
        self._restore_shared_control(self.copy_out_btn)

    def _on_continue_vm(self) -> None:
        """Resume execution of a paused sandbox VM."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.continue_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.cont(self.sandbox_id),
            on_success=self._on_continue_vm_success,
            on_error=self._on_continue_vm_error,
            parent=self,
            event="sandbox_cont",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
        )

    def _on_continue_vm_success(self, _result: object) -> None:
        """Handle successful VM resume.

        Args:
            _result: Bridge call result (unused).
        """
        self._log("[+] VM execution resumed")
        self._restore_qemu_only_control(self.continue_btn)

    def _on_continue_vm_error(self, exc: object) -> None:
        """Handle VM resume failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("VM Continue Failed", "VM continue failed", exc)
        self._restore_qemu_only_control(self.continue_btn)

    def _on_pause_vm(self) -> None:
        """Pause execution of a running sandbox VM."""
        if self._bridge is None or self.sandbox_id is None:
            return
        self.pause_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stop(self.sandbox_id),
            on_success=self._on_pause_vm_success,
            on_error=self._on_pause_vm_error,
            parent=self,
            event="sandbox_stop",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
        )

    def _on_pause_vm_success(self, _result: object) -> None:
        """Handle successful VM pause.

        Args:
            _result: Bridge call result (unused).
        """
        self._log("[+] VM execution paused")
        self._restore_qemu_only_control(self.pause_btn)

    def _on_pause_vm_error(self, exc: object) -> None:
        """Handle VM pause failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("VM Pause Failed", "VM pause failed", exc)
        self._restore_qemu_only_control(self.pause_btn)

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
        run_bridge_coroutine_logged(
            self._bridge.snapshot_delete(self.sandbox_id, snapshot_name),
            on_success=self._on_delete_snapshot_success,
            on_error=self._on_delete_snapshot_error,
            parent=self,
            event="sandbox_snapshot_delete",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            snapshot_name=snapshot_name,
        )

    def _on_delete_snapshot_success(self, _result: object) -> None:
        """Handle successful snapshot deletion.

        Args:
            _result: Bridge call result (unused).
        """
        snapshot_name = self._pending_snapshot_id
        self._log(f"[+] Snapshot deleted: {snapshot_name}")
        for idx in range(self._snapshots_tree.topLevelItemCount()):
            item = self._snapshots_tree.topLevelItem(idx)
            if item is not None and item.text(0) == snapshot_name:
                self._snapshots_tree.takeTopLevelItem(idx)
                break
        self._restore_qemu_only_control(self.delete_snap_btn)

    def _on_delete_snapshot_error(self, exc: object) -> None:
        """Handle snapshot deletion failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Snapshot Deletion Failed", "Snapshot deletion failed", exc)
        self._restore_qemu_only_control(self.delete_snap_btn)

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
        run_bridge_coroutine_logged(
            self._bridge.execute(self.sandbox_id, command),
            on_success=self._on_execute_command_success,
            on_error=self._on_execute_command_error,
            parent=self,
            event="sandbox_execute",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            command=command,
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
        self._restore_shared_control(self._exec_cmd_btn)

    def _on_execute_command_error(self, exc: object) -> None:
        """Handle command execution failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Command Execution Failed", "Command execution failed", exc)
        self._restore_shared_control(self._exec_cmd_btn)

    def _on_refresh_instances(self) -> None:
        """Refresh the Instances tab from the bridge instance list."""
        if self._bridge is None:
            self._log("[!] No sandbox bridge configured")
            _logger.warning("sandbox_refresh_instances_no_bridge")
            return

        self._refresh_instances_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.list(),
            on_success=self._on_refresh_instances_success,
            on_error=self._on_refresh_instances_error,
            parent=self,
            event="sandbox_list_instances",
            logger=_logger,
        )

    def _on_refresh_instances_success(self, result: object) -> None:
        """Handle successful instance list refresh.

        Args:
            result: List of per-instance dictionaries from the bridge.
        """
        if isinstance(result, list):
            instances = cast("list[object]", result)
            self._populate_instances_tree(instances)
            self._log(f"[+] Instances refreshed: {len(instances)} active")
        else:
            self._log("[+] Instances refreshed")
        self._refresh_instances_btn.setEnabled(True)

    def _on_refresh_instances_error(self, exc: object) -> None:
        """Handle instance list refresh failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Instance Refresh Failed", "Instance refresh failed", exc)
        self._refresh_instances_btn.setEnabled(True)

    def _on_refresh_snapshots(self) -> None:
        """Refresh the Snapshots tab for the current QEMU sandbox instance."""
        if self._bridge is None or self.sandbox_id is None:
            self._log("[!] No active sandbox instance")
            return

        self._refresh_snapshots_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.snapshot_list(self.sandbox_id),
            on_success=self._on_refresh_snapshots_success,
            on_error=self._on_refresh_snapshots_error,
            parent=self,
            event="sandbox_snapshot_list",
            logger=_logger,
            sandbox_id=self.sandbox_id,
        )

    def _on_refresh_snapshots_success(self, result: object) -> None:
        """Handle successful snapshot list refresh.

        Args:
            result: Dictionary with instance_id, snapshots (list of names), and count.
        """
        self._snapshots_tree.clear()
        count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_snapshots = typed.get("snapshots", [])
            if isinstance(raw_snapshots, list):
                for raw_name in cast("list[object]", raw_snapshots):
                    name = str(raw_name)
                    self._snapshots_tree.addTopLevelItem(QTreeWidgetItem([name, name, ""]))
                    count += 1
        self._log(f"[+] Snapshots refreshed: {count}")
        self._restore_qemu_only_control(self._refresh_snapshots_btn)

    def _on_refresh_snapshots_error(self, exc: object) -> None:
        """Handle snapshot list refresh failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Snapshot List Failed", "Snapshot list failed", exc)
        self._restore_qemu_only_control(self._refresh_snapshots_btn)

    def _on_pending_messages(self) -> None:
        """Retrieve pending guest-agent messages for the current QEMU sandbox."""
        if self._bridge is None or self.sandbox_id is None:
            self._log("[!] No active sandbox instance")
            return

        self._pending_messages_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_pending_messages(self.sandbox_id),
            on_success=self._on_pending_messages_success,
            on_error=self._on_pending_messages_error,
            parent=self,
            event="sandbox_pending_messages",
            logger=_logger,
            sandbox_id=self.sandbox_id,
        )

    def _on_pending_messages_success(self, result: object) -> None:
        """Handle successful pending-messages retrieval.

        Args:
            result: Dictionary with messages (list) and count from the bridge.
        """
        count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_messages = typed.get("messages", [])
            if isinstance(raw_messages, list):
                typed_messages = cast("list[object]", raw_messages)
                count = len(typed_messages)
                for raw_message in typed_messages:
                    if isinstance(raw_message, dict):
                        message = cast("dict[str, object]", raw_message)
                        self._console_output.appendPlainText(
                            f"[guest-agent] {message.get('type', 'unknown')}: {message.get('data', {})}",
                        )
                    else:
                        self._console_output.appendPlainText(f"[guest-agent] {raw_message}")
        self._log(f"[+] Pending messages retrieved: {count}")
        self._restore_qemu_only_control(self._pending_messages_btn)

    def _on_pending_messages_error(self, exc: object) -> None:
        """Handle pending-messages retrieval failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Pending Messages Failed", "Pending messages retrieval failed", exc)
        self._restore_qemu_only_control(self._pending_messages_btn)

    def _on_anti_evasion(self) -> None:
        """Apply anti-evasion hardening to the current QEMU sandbox instance."""
        if self._bridge is None or self.sandbox_id is None:
            self._log("[!] No active sandbox instance")
            return

        profile = self._anti_evasion_profile_input.text().strip() or "default"
        self._anti_evasion_btn.setEnabled(False)
        self._log(f"[*] Applying anti-evasion profile: {profile}")
        run_bridge_coroutine_logged(
            self._bridge.anti_evasion(self.sandbox_id, profile=profile),
            on_success=self._on_anti_evasion_success,
            on_error=self._on_anti_evasion_error,
            parent=self,
            event="sandbox_anti_evasion",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
            profile=profile,
        )

    def _on_anti_evasion_success(self, result: object) -> None:
        """Handle successful anti-evasion application.

        Args:
            result: Dictionary with profile and applied techniques from the bridge.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            profile = str(typed.get("profile", ""))
            self._log(f"[+] Anti-evasion applied (profile: {profile})")
            self._render_techniques(typed.get("techniques"))
        else:
            self._log("[+] Anti-evasion applied")
        self._restore_qemu_only_control(self._anti_evasion_btn)

    def _on_anti_evasion_error(self, exc: object) -> None:
        """Handle anti-evasion application failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Anti-Evasion Failed", "Anti-evasion failed", exc)
        self._restore_qemu_only_control(self._anti_evasion_btn)

    def _render_techniques(self, techniques: object) -> None:
        """Render applied anti-evasion techniques to the console output.

        Args:
            techniques: Techniques payload returned by the bridge, either a
                list of entries or a mapping of technique name to detail.
        """
        if isinstance(techniques, list):
            for raw in cast("list[object]", techniques):
                self._console_output.appendPlainText(f"[anti-evasion] {raw}")
        elif isinstance(techniques, dict):
            for key, value in cast("dict[object, object]", techniques).items():
                self._console_output.appendPlainText(f"[anti-evasion] {key}: {value}")

    def _on_detect_c2(self) -> None:
        """Detect C2 communication patterns for the current sandbox instance."""
        if self._bridge is None or self.sandbox_id is None:
            self._log("[!] No active sandbox instance")
            return

        self._detect_c2_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.detect_c2(self.sandbox_id),
            on_success=self._on_detect_c2_success,
            on_error=self._on_detect_c2_error,
            parent=self,
            event="sandbox_detect_c2",
            logger=_logger,
            level="info",
            sandbox_id=self.sandbox_id,
        )

    def _on_detect_c2_success(self, result: object) -> None:
        """Handle successful C2 pattern detection.

        Args:
            result: Dictionary with patterns (list) and count from the bridge.
        """
        count = 0
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            raw_patterns = typed.get("patterns", [])
            if isinstance(raw_patterns, list):
                typed_patterns = cast("list[object]", raw_patterns)
                count = len(typed_patterns)
                for raw_pattern in typed_patterns:
                    if isinstance(raw_pattern, dict):
                        pattern = cast("dict[str, object]", raw_pattern)
                        summary = ", ".join(f"{key}={value}" for key, value in pattern.items())
                        self._console_output.appendPlainText(f"[C2] {summary}")
                    else:
                        self._console_output.appendPlainText(f"[C2] {raw_pattern}")
        self._log(f"[+] C2 detection complete: {count} patterns")
        self._restore_shared_control(self._detect_c2_btn)

    def _on_detect_c2_error(self, exc: object) -> None:
        """Handle C2 pattern detection failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("C2 Detection Failed", "C2 detection failed", exc)
        self._restore_shared_control(self._detect_c2_btn)

    def _on_diff(self) -> None:
        """Compare two sandbox instances' execution reports."""
        if self._bridge is None:
            self._log("[!] No sandbox bridge configured")
            return

        instance_a = self._diff_instance_a_input.text().strip() or (self.sandbox_id or "")
        instance_b = self._diff_instance_b_input.text().strip()
        if not instance_a or not instance_b:
            self._log("[!] Both instance IDs are required for diff")
            return

        self._diff_btn.setEnabled(False)
        self._log(f"[*] Comparing instances: {instance_a} vs {instance_b}")
        run_bridge_coroutine_logged(
            self._bridge.diff(instance_a, instance_b),
            on_success=self._on_diff_success,
            on_error=self._on_diff_error,
            parent=self,
            event="sandbox_diff",
            logger=_logger,
            level="info",
            instance_id_a=instance_a,
            instance_id_b=instance_b,
        )

    def _on_diff_success(self, result: object) -> None:
        """Handle successful instance report comparison.

        Args:
            result: Dictionary with instance_id_a, instance_id_b, and diff mapping.
        """
        if isinstance(result, dict):
            typed = cast("dict[str, object]", result)
            instance_a = str(typed.get("instance_id_a", ""))
            instance_b = str(typed.get("instance_id_b", ""))
            self._log(f"[+] Diff complete: {instance_a} vs {instance_b}")
            diff_data = typed.get("diff")
            if isinstance(diff_data, dict):
                self._render_diff(cast("dict[str, object]", diff_data))
        else:
            self._log("[+] Diff complete")
        self._restore_shared_control(self._diff_btn)

    def _render_diff(self, diff_data: dict[str, object]) -> None:
        """Render a per-field report comparison to the console output.

        Args:
            diff_data: Mapping of report field name to its comparison result.
        """
        for field, value in diff_data.items():
            self._console_output.appendPlainText(f"[diff] {field}:")
            if isinstance(value, dict):
                for sub_key, sub_value in cast("dict[str, object]", value).items():
                    self._console_output.appendPlainText(f"    {sub_key}: {sub_value}")
            else:
                self._console_output.appendPlainText(f"    {value}")

    def _on_diff_error(self, exc: object) -> None:
        """Handle instance report comparison failure.

        Args:
            exc: The exception from the failed operation.
        """
        self._report_failure("Diff Failed", "Diff failed", exc)
        self._restore_shared_control(self._diff_btn)

    def _poll_status(self) -> None:
        """Poll the sandbox status periodically."""
        if self._bridge is None:
            return

        run_bridge_coroutine_logged(
            self._bridge.status(),
            on_success=self._on_poll_status_success,
            on_error=self._on_poll_status_error,
            parent=self,
            event="sandbox_status",
            logger=_logger,
        )

    def _on_poll_status_success(self, result: object) -> None:
        """Handle successful status poll.

        Args:
            result: Status dictionary from bridge.
        """
        self._last_poll_error = None
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

    def _on_poll_status_error(self, exc: object) -> None:
        """Handle status poll failure.

        The poll runs every five seconds, so the failure is reported to the
        console and the log only when its text differs from the previous
        failure. That keeps a persistent backend outage from filling the
        console with thousands of identical lines while still making the very
        first occurrence - and any change in the error - visible. A modal
        dialog is deliberately not used here: this path is timer-driven, not
        user-initiated.

        Args:
            exc: The exception from the failed operation.
        """
        self._status_indicator.setText("Active (status unavailable)")
        error_text = str(exc)
        if error_text == self._last_poll_error:
            return
        self._last_poll_error = error_text
        self._log(f"[-] Sandbox status poll failed: {error_text}")
        _logger.warning("sandbox_status_poll_failed", sandbox_id=self.sandbox_id, error=error_text)

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
        """Connect the VNC widget to the sandbox VNC port if available.

        Only the QEMU backend exposes a VNC server; ``WindowsSandbox`` inherits
        ``vnc_port = None``, so the query is skipped entirely rather than
        dispatched and failed for a backend that can never satisfy it.
        """
        if self._vnc_widget is None or self._bridge is None or self.sandbox_id is None:
            return

        if self._effective_sandbox_type() != "qemu":
            _logger.debug("sandbox_vnc_display_unsupported", sandbox_type=self._effective_sandbox_type())
            return

        run_bridge_coroutine_logged(
            self._bridge.get_vnc_port(self.sandbox_id),
            on_success=self._on_vnc_port_received,
            on_error=self._on_vnc_port_error,
            parent=self,
            event="sandbox_get_vnc_port",
            logger=_logger,
            sandbox_id=self.sandbox_id,
        )

    def _on_vnc_port_error(self, exc: object) -> None:
        """Handle a failed VNC port query.

        The previous handler swallowed the failure at debug level without the
        error text, so a VM Display that silently never connected left no
        usable evidence anywhere. The failure is now logged at warning level
        with the real error and mirrored into the console. No dialog is shown:
        the query is issued automatically after a create, not by a direct user
        action, and the VM Display tab itself already shows nothing.

        Args:
            exc: The exception raised by ``bridge.get_vnc_port``.
        """
        error_text = str(exc)
        self._log(f"[-] VNC port query failed: {error_text}")
        _logger.warning("sandbox_vnc_port_query_failed", sandbox_id=self.sandbox_id, error=error_text)

    def _on_vnc_port_received(self, result: object) -> None:
        """Handle VNC port retrieval.

        Forwards the port to :meth:`_connect_vnc_with_password`, which
        retrieves the QEMU VNC password registered on the bridge (if any)
        and passes it through to ``VNCWidget.connect_to_server`` so the
        embedded RFB client can complete VNC Authentication (security
        type 2) instead of failing with ``vnc_auth_missing_password``.

        Args:
            result: VNC port number or None.
        """
        if self._vnc_widget is None:
            return
        vnc_port = result if isinstance(result, int) else None
        if vnc_port is None:
            _logger.debug("sandbox_vnc_port_not_available")
            return
        self._connect_vnc_with_password(vnc_port)

    def _connect_vnc_with_password(self, vnc_port: int) -> None:
        """Connect the VNC widget after retrieving the configured password.

        Args:
            vnc_port: VNC server port returned by ``bridge.get_vnc_port``.
        """
        if self._vnc_widget is None or self._bridge is None or self.sandbox_id is None:
            return
        password = self._bridge.get_vnc_password(self.sandbox_id)
        self._log(f"[*] Connecting VNC display on port {vnc_port}...")
        self._vnc_widget.connect_to_server("127.0.0.1", vnc_port, password=password)
        _logger.info(
            "vnc_display_connecting",
            port=vnc_port,
            authenticated=password is not None,
        )

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
                change_map = cast("dict[str, object]", change)
                op = change_map.get("operation", "unknown")
                path = change_map.get("path", "")
                detail = _format_file_change_detail(change_map)
                item = QTreeWidgetItem([str(op), str(path), detail])
                self._file_changes_tree.addTopLevelItem(item)

        if hasattr(report, "registry_changes"):
            for reg_change in report.registry_changes:
                reg_map = cast("dict[str, object]", reg_change)
                op = reg_map.get("operation", "unknown")
                key = reg_map.get("key", "")
                value = reg_map.get("value_data", "")
                item = QTreeWidgetItem([str(op), str(key), str(value)])
                self._registry_changes_tree.addTopLevelItem(item)

        if hasattr(report, "network_activity"):
            for activity in report.network_activity:
                act_map = cast("dict[str, object]", activity)
                proto = act_map.get("protocol", "unknown")
                dest = act_map.get("remote_address", "")
                port = act_map.get("remote_port", 0)
                sent = act_map.get("bytes_sent", 0)
                recv = act_map.get("bytes_received", 0)
                item = QTreeWidgetItem([str(proto), str(dest), str(port), f"{sent}/{recv} bytes"])
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
