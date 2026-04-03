# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frida instrumentation panel for Intellicrack.

Provides a script editor, console output, and hook manager for interacting with Frida dynamic instrumentation framework.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics, QIntValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import set_max_block_count
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.frida_bridge import FridaBridge

_logger = get_logger("ui.panels.frida")

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_DEVICE_COMBO_MIN_WIDTH: Final[int] = 120
_STALKER_TID_MAX_WIDTH: Final[int] = 100
_TOP_SPLIT: Final[list[int]] = [200, 400, 300]
_MAIN_SPLIT: Final[list[int]] = [400, 200]
_SPACING_STALKER: Final[int] = 4


_DEFAULT_FRIDA_SCRIPT = """Interceptor.attach(ptr('ADDRESS'), {
    onEnter: function(args) {
        console.log('[*] Called with args:', args[0], args[1]);
    },
    onLeave: function(retval) {
        console.log('[*] Return value:', retval);
    }
});
"""

_HOOK_COLUMNS = ["Address", "Module", "Function", "Status"]
_HOOK_COL_ADDRESS = 0
_HOOK_COL_MODULE = 1
_HOOK_COL_FUNCTION = 2
_HOOK_COL_STATUS = 3


class FridaPanel(AnalysisPanelBase):
    """Panel for Frida dynamic instrumentation and hooking.

    Provides a script editor for writing Frida JavaScript,
    a console for viewing output, and a hook manager table
    for managing active function hooks.

    Args:
        parent: Parent widget.

    Attributes:
        hook_added: Signal emitted with hook ID when a Frida hook is registered.
        script_executed: Signal emitted when a Frida script finishes execution.
    """

    hook_added: pyqtSignal = pyqtSignal(str)
    script_executed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._bridge: FridaBridge | None = None
        self._attached_pid: int | None = None
        self._hook_ids: list[str] = []
        self._active_script_id: str | None = None

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add Frida-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._add_toolbar_label(toolbar, "Device:")

        self._device_combo = QComboBox()
        self._device_combo.setMinimumWidth(_DEVICE_COMBO_MIN_WIDTH)
        self._device_combo.addItem("local")
        self._device_combo.currentTextChanged.connect(self._on_device_changed)
        toolbar.addWidget(self._device_combo)

        self._refresh_devices_btn = self._add_secondary_button(toolbar, "Refresh Devices", self.refresh_devices)

        toolbar.addSeparator()

        self._add_toolbar_label(toolbar, "Target:")

        self._target_input = self._add_toolbar_input(toolbar, "PID or process name")

        self._attach_btn = self._add_tool_button(toolbar, "Attach", self._on_attach)
        self._detach_btn = self._add_tool_button(toolbar, "Detach", self._on_detach, enabled=False)

        toolbar.addSeparator()

        self.run_btn = self._add_tool_button(toolbar, "Run Script", self._on_run_script)
        self._stop_btn = self._add_tool_button(toolbar, "Stop", self._on_stop_script, enabled=False)
        self._clear_btn = self._add_secondary_button(toolbar, "Clear Console", self._on_clear_console)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Not attached")

    @override
    def _create_content(self) -> QWidget:
        """Create the Frida instrumentation content area.

        Returns:
            QWidget: Splitter with process browser, editor, hooks/threads, and console.
        """
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._create_process_browser())
        top_splitter.addWidget(self._create_editor_section())
        top_splitter.addWidget(self._create_right_tabs())
        top_splitter.setSizes(_TOP_SPLIT)
        main_splitter.addWidget(top_splitter)

        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        console_layout.setSpacing(_PANEL_SPACING)

        console_title = QLabel("Console Output")
        console_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        console_layout.addWidget(console_title)

        self._console = QPlainTextEdit()
        self._console.setFont(FontManager.get_instance().get_code_font(9))
        self._console.setReadOnly(ro=True)
        set_max_block_count(self._console, 10000)
        console_layout.addWidget(self._console)
        main_splitter.addWidget(console_container)

        main_splitter.setSizes(_MAIN_SPLIT)
        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Detach from the target process if attached."""
        if self._bridge is not None and self._bridge.state.process_attached:
            try:
                run_bridge_coroutine(self._bridge.detach())
            except (RuntimeError, ConnectionError, OSError):
                _logger.debug("frida_detach_skipped", exc_info=True)
        self._attached_pid = None

    def _create_editor_section(self) -> QWidget:
        """Create the script editor section.

        Returns:
            QWidget: Editor container widget.
        """
        editor_container = QWidget()
        editor_layout = QVBoxLayout(editor_container)
        editor_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        editor_layout.setSpacing(_PANEL_SPACING)

        editor_header = QHBoxLayout()
        editor_title = QLabel("Script Editor")
        editor_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        editor_header.addWidget(editor_title)

        self._script_type_combo = QComboBox()
        self._script_type_combo.addItems(["Hook Script", "Stalker", "Memory Scanner", "Custom"])
        editor_header.addWidget(self._script_type_combo)
        editor_header.addStretch()
        editor_layout.addLayout(editor_header)

        self._script_editor = QPlainTextEdit()
        self._script_editor.setFont(FontManager.get_instance().get_code_font(10))
        self._script_editor.setPlainText(_DEFAULT_FRIDA_SCRIPT)
        self._script_editor.setTabStopDistance(QFontMetrics(self._script_editor.font()).horizontalAdvance(" ") * 4)
        editor_layout.addWidget(self._script_editor)
        return editor_container

    def _create_process_browser(self) -> QWidget:
        """Create the process browser panel.

        Returns:
            QWidget: Process browser container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        header = QHBoxLayout()
        title = QLabel("Processes")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        header.addWidget(title)
        header.addStretch()

        self._refresh_procs_btn = QPushButton("Refresh")
        self._refresh_procs_btn.setObjectName("tool_button")
        self._refresh_procs_btn.clicked.connect(self._on_refresh_processes)
        header.addWidget(self._refresh_procs_btn)
        layout.addLayout(header)

        self._process_table = QTableWidget(0, 2)
        self._process_table.setHorizontalHeaderLabels(["PID", "Name"])
        self._process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._process_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._process_table.doubleClicked.connect(self._on_process_double_click)
        proc_header = self._process_table.horizontalHeader()
        if proc_header is not None:
            proc_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            proc_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._process_table)
        return container

    def _create_right_tabs(self) -> QWidget:
        """Create the tabbed right panel with hooks, threads, and stalker.

        Returns:
            QWidget: Tab widget containing hooks, threads, and stalker tabs.
        """
        self._right_tabs = QTabWidget()
        self._right_tabs.addTab(self._create_hooks_section(), "Hooks")
        self._right_tabs.addTab(self._create_threads_section(), "Threads")
        self._right_tabs.addTab(self._create_stalker_section(), "Stalker")
        return self._right_tabs

    def _create_hooks_section(self) -> QWidget:
        """Create the hooks manager section.

        Returns:
            QWidget: Hooks container widget.
        """
        hooks_container = QWidget()
        hooks_layout = QVBoxLayout(hooks_container)
        hooks_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        hooks_layout.setSpacing(_PANEL_SPACING)

        hooks_header = QHBoxLayout()
        hooks_title = QLabel("Active Hooks")
        hooks_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        hooks_header.addWidget(hooks_title)
        hooks_header.addStretch()

        self._add_hook_btn = QPushButton("Add")
        self._add_hook_btn.setObjectName("tool_button")
        self._add_hook_btn.clicked.connect(self._on_add_hook)
        hooks_header.addWidget(self._add_hook_btn)

        self._remove_hook_btn = QPushButton("Remove")
        self._remove_hook_btn.setObjectName("tool_button")
        self._remove_hook_btn.clicked.connect(self._on_remove_hook)
        hooks_header.addWidget(self._remove_hook_btn)

        hooks_layout.addLayout(hooks_header)

        self._hooks_table = QTableWidget(0, len(_HOOK_COLUMNS))
        self._hooks_table.setHorizontalHeaderLabels(_HOOK_COLUMNS)
        self._hooks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hooks_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        hooks_h = self._hooks_table.horizontalHeader()
        if hooks_h is not None:
            hooks_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hooks_layout.addWidget(self._hooks_table)
        return hooks_container

    def _create_threads_section(self) -> QWidget:
        """Create the thread viewer section.

        Returns:
            QWidget: Threads container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        header = QHBoxLayout()
        title = QLabel("Threads")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        header.addWidget(title)
        header.addStretch()

        self._refresh_threads_btn = QPushButton("Refresh")
        self._refresh_threads_btn.setObjectName("tool_button")
        self._refresh_threads_btn.clicked.connect(self._on_refresh_threads)
        header.addWidget(self._refresh_threads_btn)
        layout.addLayout(header)

        self._threads_table = QTableWidget(0, 3)
        self._threads_table.setHorizontalHeaderLabels(["TID", "State", "PC"])
        self._threads_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._threads_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        threads_h = self._threads_table.horizontalHeader()
        if threads_h is not None:
            threads_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._threads_table)
        return container

    def _create_stalker_section(self) -> QWidget:
        """Create the Stalker code tracing controls.

        Returns:
            QWidget: Stalker controls container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_SPACING_STALKER)

        title = QLabel(self.tr("Stalker Tracing"))
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        tid_row = QHBoxLayout()
        tid_row.addWidget(QLabel("Thread ID:"))
        self._stalker_tid_input = QLineEdit()
        self._stalker_tid_input.setToolTip("Leave empty for current thread")
        self._stalker_tid_input.setMaximumWidth(_STALKER_TID_MAX_WIDTH)
        self._stalker_tid_input.setValidator(QIntValidator(0, 999999, self))
        tid_row.addWidget(self._stalker_tid_input)
        tid_row.addStretch()
        layout.addLayout(tid_row)

        events_row = QHBoxLayout()
        events_row.addWidget(QLabel("Events:"))
        self._stalker_call_cb = QCheckBox("call")
        self._stalker_call_cb.setChecked(True)
        events_row.addWidget(self._stalker_call_cb)
        self._stalker_ret_cb = QCheckBox("ret")
        events_row.addWidget(self._stalker_ret_cb)
        self._stalker_exec_cb = QCheckBox("exec")
        events_row.addWidget(self._stalker_exec_cb)
        self._stalker_block_cb = QCheckBox("block")
        events_row.addWidget(self._stalker_block_cb)
        events_row.addStretch()
        layout.addLayout(events_row)

        limit_row = QHBoxLayout()
        limit_row.addWidget(QLabel("Limit:"))
        self._stalker_limit_spin = QSpinBox()
        self._stalker_limit_spin.setRange(100, 1000000)
        self._stalker_limit_spin.setValue(10000)
        self._stalker_limit_spin.setSingleStep(1000)
        limit_row.addWidget(self._stalker_limit_spin)
        limit_row.addStretch()
        layout.addLayout(limit_row)

        btn_row = QHBoxLayout()
        self._stalker_start_btn = QPushButton("Start Trace")
        self._stalker_start_btn.setObjectName("tool_button")
        self._stalker_start_btn.clicked.connect(self._on_stalker_start)
        btn_row.addWidget(self._stalker_start_btn)

        self._stalker_stop_btn = QPushButton("Stop Trace")
        self._stalker_stop_btn.setObjectName("tool_button")
        self._stalker_stop_btn.setEnabled(False)
        self._stalker_stop_btn.clicked.connect(self._on_stalker_stop)
        btn_row.addWidget(self._stalker_stop_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()
        return container

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance for instrumentation.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge
        bridge.set_message_handler(self._on_frida_message)
        _logger.info("frida_bridge_set", bridge_type=type(bridge).__name__)

    def get_bridge(self) -> FridaBridge | None:
        """Get the current FridaBridge instance.

        Returns:
            FridaBridge | None: The attached bridge or None.
        """
        return self._bridge

    def log_message(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        self._console.appendPlainText(message)

    def _on_frida_message(self, message: dict[str, object]) -> None:
        """Handle messages from Frida scripts.

        Args:
            message: Frida message dictionary.
        """
        msg_type = str(message.get("type", ""))
        if msg_type == "send":
            payload = message.get("payload", "")
            self._console.appendPlainText(f"[send] {payload}")
        elif msg_type == "error":
            desc = message.get("description", str(message))
            self._console.appendPlainText(f"[error] {desc}")
        else:
            self._console.appendPlainText(f"[{msg_type}] {message}")

    def _on_attach(self) -> None:
        """Attach to a target process."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            _logger.warning("frida_attach_failed_no_bridge", reason="bridge not set")
            return

        target = self._target_input.text().strip()
        if not target:
            self._console.appendPlainText("[!] Enter a PID or process name")
            return

        _logger.debug("frida_attach_started", target=target)
        self._attach_btn.setEnabled(False)

        try:
            pid = int(target)
        except ValueError:
            _logger.debug("frida_attach_by_name_fallback", target=target)
            self._run_async(
                self._bridge.attach_by_name(target),
                on_success=lambda _: self._on_attach_name_success(target),
                on_error=lambda e: self._on_attach_failed(target, e),
            )
            return

        self._run_async(
            self._bridge.attach(pid),
            on_success=lambda _: self._on_attach_pid_success(pid),
            on_error=lambda e: self._on_attach_failed(target, e),
        )

    def _on_attach_pid_success(self, pid: int) -> None:
        """Handle successful PID-based attach.

        Args:
            pid: The attached process ID.
        """
        self._attached_pid = pid
        self._console.appendPlainText(f"[+] Attached to PID {pid}")
        _logger.info("frida_attached_pid", pid=pid)
        self._set_status("Attached")
        self._attach_btn.setEnabled(False)
        self._detach_btn.setEnabled(True)
        self.tool_started.emit()

    def _on_attach_name_success(self, target: str) -> None:
        """Handle successful name-based attach.

        Args:
            target: The process name attached to.
        """
        self._console.appendPlainText(f"[+] Attached to '{target}'")
        _logger.info("frida_attached_name", process_name=target)
        self._set_status("Attached")
        self._attach_btn.setEnabled(False)
        self._detach_btn.setEnabled(True)
        self.tool_started.emit()

    def _on_attach_failed(self, target: str, exc: object) -> None:
        """Handle attach failure.

        Args:
            target: The target that failed to attach.
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Attach failed: {exc}")
        _logger.warning("frida_attach_failed", target=target, error=str(exc))
        self._attach_btn.setEnabled(True)

    def _on_detach(self) -> None:
        """Detach from the current target process."""
        if self._bridge is None:
            return

        _logger.debug("frida_detach_started", pid=self._attached_pid)
        self._detach_btn.setEnabled(False)

        self._run_async(
            self._bridge.detach(),
            on_success=lambda _: self._on_detach_success(),
            on_error=self._on_detach_error,
        )

    def _on_detach_success(self) -> None:
        """Handle successful detach."""
        self._console.appendPlainText("[+] Detached")
        _logger.info("frida_detached", pid=self._attached_pid)
        self._attached_pid = None
        self._set_status("Not attached")
        self._attach_btn.setEnabled(True)
        self._detach_btn.setEnabled(False)
        self.tool_closed.emit()

    def _on_detach_error(self, exc: object) -> None:
        """Handle detach failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Detach failed: {exc}")
        _logger.warning("frida_detach_failed", error=str(exc))
        self._attached_pid = None
        self._set_status("Not attached")
        self._attach_btn.setEnabled(True)
        self._detach_btn.setEnabled(False)
        self.tool_closed.emit()

    def _on_run_script(self) -> None:
        """Execute the current script persistently in the editor."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        source = self._script_editor.toPlainText()
        if not source.strip():
            self._console.appendPlainText("[!] Script is empty")
            return

        _logger.debug("frida_script_execution_started", script_size=len(source))
        self.run_btn.setEnabled(False)

        self._run_async(
            self._bridge.execute_persistent_script(source),
            on_success=lambda r: self._on_run_script_success(len(source), r),
            on_error=self._on_run_script_error,
        )

    def _on_run_script_success(self, script_size: int, result: object) -> None:
        """Handle successful persistent script load.

        Args:
            script_size: Size of the executed script in characters.
            result: Script ID from the bridge.
        """
        self._active_script_id = str(result) if result else None
        self._console.appendPlainText("[+] Script loaded (persistent)")
        self.run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.script_executed.emit()
        _logger.info("frida_script_executed", script_size=script_size)

    def _on_run_script_error(self, exc: object) -> None:
        """Handle script execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Script execution failed: {exc}")
        _logger.warning("frida_script_execution_failed", error=str(exc))
        self.run_btn.setEnabled(True)

    def _on_stop_script(self) -> None:
        """Stop the currently running script."""
        if self._bridge is None:
            return

        self._stop_btn.setEnabled(False)
        if self._active_script_id is not None:
            self._run_async(
                self._bridge.unload_script(self._active_script_id),
                on_success=lambda _: self._on_stop_script_success(),
                on_error=self._on_stop_script_error,
            )
        else:
            self._run_async(
                self._bridge.unload_all_scripts(),
                on_success=lambda _: self._on_stop_script_success(),
                on_error=self._on_stop_script_error,
            )

    def _on_stop_script_success(self) -> None:
        """Handle successful script stop."""
        self._active_script_id = None
        self.run_btn.setEnabled(True)
        self._console.appendPlainText("[+] Script stopped")

    def _on_stop_script_error(self, exc: object) -> None:
        """Handle script stop failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Stop failed: {exc}")
        _logger.warning("frida_script_stop_failed", error=str(exc))
        self._stop_btn.setEnabled(True)

    def _on_clear_console(self) -> None:
        """Clear the console output."""
        self._console.clear()

    def _on_add_hook(self) -> None:
        """Add a new function hook via dialog and bridge."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge - cannot add hook")
            return

        target, accepted = QInputDialog.getText(
            self,
            "Add Hook",
            "Enter target (address like 0x401000 or module!function):",
        )
        if not accepted or not target.strip():
            return

        target = target.strip()

        row = self._hooks_table.rowCount()
        self._hooks_table.insertRow(row)
        self._hooks_table.setItem(row, _HOOK_COL_ADDRESS, QTableWidgetItem("Resolving..."))
        self._hooks_table.setItem(row, _HOOK_COL_MODULE, QTableWidgetItem(""))
        self._hooks_table.setItem(row, _HOOK_COL_FUNCTION, QTableWidgetItem(target))
        self._hooks_table.setItem(row, _HOOK_COL_STATUS, QTableWidgetItem("Installing..."))

        self._add_hook_btn.setEnabled(False)
        self._run_async(
            self._bridge.hook_function(target),
            on_success=lambda result: self._on_hook_installed(row, target, result),
            on_error=lambda exc: self._on_hook_install_error(row, exc),
        )

    def _on_hook_installed(self, row: int, target: str, result: object) -> None:
        """Handle successful hook installation.

        Args:
            row: Table row index for the hook.
            target: The original hook target string.
            result: HookInfo from the bridge.
        """
        hook_id = str(getattr(result, "id", ""))
        address = getattr(result, "address", None)
        addr_str = f"0x{address:X}" if isinstance(address, int) and address else "0x0"

        module_str = ""
        func_str = target
        if "!" in target:
            parts = target.split("!", 1)
            module_str = parts[0]
            func_str = parts[1]

        addr_item = self._hooks_table.item(row, _HOOK_COL_ADDRESS)
        if addr_item is not None:
            addr_item.setText(addr_str)
        mod_item = self._hooks_table.item(row, _HOOK_COL_MODULE)
        if mod_item is not None:
            mod_item.setText(module_str)
        func_item = self._hooks_table.item(row, _HOOK_COL_FUNCTION)
        if func_item is not None:
            func_item.setText(func_str)
        status_item = self._hooks_table.item(row, _HOOK_COL_STATUS)
        if status_item is not None:
            status_item.setText("Active")

        self._hook_ids.append(hook_id)
        self._add_hook_btn.setEnabled(True)
        self._console.appendPlainText(f"[+] Hook installed: {target} at {addr_str}")
        self.hook_added.emit(addr_str)
        _logger.info("frida_hook_installed", target=target, hook_id=hook_id)

    def _on_hook_install_error(self, row: int, exc: object) -> None:
        """Handle hook installation failure.

        Args:
            row: Table row for the failed hook.
            exc: The exception that occurred.
        """
        status_item = self._hooks_table.item(row, _HOOK_COL_STATUS)
        if status_item is not None:
            status_item.setText("Failed")
        self._add_hook_btn.setEnabled(True)
        self._console.appendPlainText(f"[-] Hook installation failed: {exc}")
        _logger.warning("frida_hook_install_failed", error=str(exc))

    def _on_remove_hook(self) -> None:
        """Remove the selected hook."""
        selected = self._hooks_table.currentRow()
        if selected < 0:
            return

        if selected < len(self._hook_ids) and self._bridge is not None:
            hook_id = self._hook_ids[selected]
            self._remove_hook_btn.setEnabled(False)
            self._run_async(
                self._bridge.remove_hook(hook_id),
                on_success=lambda _: self._on_hook_removed(selected, hook_id),
                on_error=lambda e: self._on_hook_remove_error(hook_id, e),
            )
            return

        self._hooks_table.removeRow(selected)

    def _on_hook_removed(self, row_index: int, hook_id: str) -> None:
        """Handle successful hook removal.

        Args:
            row_index: Table row to remove.
            hook_id: The removed hook identifier.
        """
        self._console.appendPlainText(f"[+] Removed hook {hook_id}")
        _logger.info("frida_hook_removed", hook_id=hook_id)
        if row_index < len(self._hook_ids):
            self._hook_ids.pop(row_index)
        self._hooks_table.removeRow(row_index)
        self._remove_hook_btn.setEnabled(True)

    def _on_hook_remove_error(self, hook_id: str, exc: object) -> None:
        """Handle hook removal failure.

        Args:
            hook_id: The hook that failed to remove.
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Failed to remove hook: {exc}")
        _logger.warning("frida_hook_remove_failed", hook_id=hook_id, error=str(exc))
        self._remove_hook_btn.setEnabled(True)

    def add_hook_entry(
        self,
        address: str,
        module: str,
        function: str,
        status: str = "Active",
        hook_id: str = "",
    ) -> None:
        """Add a hook entry to the table.

        Args:
            address: Hook address (hex string).
            module: Module name containing the hook.
            function: Function name being hooked.
            status: Current hook status.
            hook_id: Bridge hook identifier.
        """
        row = self._hooks_table.rowCount()
        self._hooks_table.insertRow(row)
        self._hooks_table.setItem(row, _HOOK_COL_ADDRESS, QTableWidgetItem(address))
        self._hooks_table.setItem(row, _HOOK_COL_MODULE, QTableWidgetItem(module))
        self._hooks_table.setItem(row, _HOOK_COL_FUNCTION, QTableWidgetItem(function))
        self._hooks_table.setItem(row, _HOOK_COL_STATUS, QTableWidgetItem(status))
        self._hook_ids.append(hook_id)
        self.hook_added.emit(address)
        _logger.debug("frida_hook_entry_added", address=address, target_module=module, function=function)

    def _on_device_changed(self, device_text: str) -> None:
        """Handle device selector change.

        Args:
            device_text: Selected device identifier text.
        """
        if self._bridge is None:
            return

        device_type = "local"
        host: str | None = None
        if device_text.startswith("remote:"):
            device_type = "remote"
            host = device_text.split(":", 1)[1].strip()
        elif device_text == "usb":
            device_type = "usb"

        self._console.appendPlainText(f"[*] Switching to {device_type} device...")
        self._run_async(
            self._bridge.connect_device(device_type, host),
            on_success=lambda r: self._console.appendPlainText(f"[+] Connected to device: {getattr(r, 'name', device_type)}"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Device switch failed: {e}"),
        )

    def _on_refresh_processes(self) -> None:
        """Refresh the process browser table."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        self._refresh_procs_btn.setEnabled(False)
        self._run_async(
            self._bridge.enumerate_processes(),
            on_success=self._populate_process_table,
            on_error=self._on_refresh_processes_error,
        )

    def _populate_process_table(self, result: object) -> None:
        """Populate the process table from enumeration results.

        Args:
            result: List of process dictionaries from the bridge.
        """
        self._process_table.setRowCount(0)
        if isinstance(result, list):
            proc_list = cast("list[object]", result)
            for proc in proc_list:
                if not isinstance(proc, dict):
                    continue
                proc_dict = cast("dict[str, object]", proc)
                row = self._process_table.rowCount()
                self._process_table.insertRow(row)
                pid_val = proc_dict.get("pid", 0)
                name_val = proc_dict.get("name", "")
                self._process_table.setItem(row, 0, QTableWidgetItem(str(pid_val)))
                self._process_table.setItem(row, 1, QTableWidgetItem(str(name_val)))
        self._refresh_procs_btn.setEnabled(True)

    def _on_refresh_processes_error(self, exc: object) -> None:
        """Handle process enumeration failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Process enumeration failed: {exc}")
        _logger.warning("frida_process_enum_failed", error=str(exc))
        self._refresh_procs_btn.setEnabled(True)

    def _on_process_double_click(self) -> None:
        """Attach to the double-clicked process."""
        row = self._process_table.currentRow()
        if row < 0:
            return

        pid_item = self._process_table.item(row, 0)
        if pid_item is None:
            return

        pid_text = pid_item.text()
        self._target_input.setText(pid_text)
        self._on_attach()

    def _on_refresh_threads(self) -> None:
        """Refresh the thread viewer table."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        self._refresh_threads_btn.setEnabled(False)
        self._run_async(
            self._bridge.enumerate_threads(),
            on_success=self._populate_threads_table,
            on_error=self._on_refresh_threads_error,
        )

    def _populate_threads_table(self, result: object) -> None:
        """Populate the threads table from enumeration results.

        Args:
            result: List of ThreadInfo from the bridge.
        """
        self._threads_table.setRowCount(0)
        if isinstance(result, list):
            thread_list = cast("list[object]", result)
            for thread_obj in thread_list:
                row = self._threads_table.rowCount()
                self._threads_table.insertRow(row)
                tid: int = int(getattr(thread_obj, "tid", 0))
                state: str = str(getattr(thread_obj, "state", "unknown"))
                pc: object = getattr(thread_obj, "start_address", 0)
                self._threads_table.setItem(row, 0, QTableWidgetItem(str(tid)))
                self._threads_table.setItem(row, 1, QTableWidgetItem(state))
                self._threads_table.setItem(
                    row,
                    2,
                    QTableWidgetItem(f"0x{pc:X}" if isinstance(pc, int) else str(pc)),
                )
        self._refresh_threads_btn.setEnabled(True)

    def _on_refresh_threads_error(self, exc: object) -> None:
        """Handle thread enumeration failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Thread enumeration failed: {exc}")
        _logger.warning("frida_thread_enum_failed", error=str(exc))
        self._refresh_threads_btn.setEnabled(True)

    def _get_stalker_events_string(self) -> str:
        """Build comma-separated events string from stalker checkboxes.

        Returns:
            str: Comma-separated event type string.
        """
        events: list[str] = []
        if self._stalker_call_cb.isChecked():
            events.append("call")
        if self._stalker_ret_cb.isChecked():
            events.append("ret")
        if self._stalker_exec_cb.isChecked():
            events.append("exec")
        if self._stalker_block_cb.isChecked():
            events.append("block")
        return ",".join(events) if events else "call"

    def _on_stalker_start(self) -> None:
        """Start Stalker code tracing."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        tid_text = self._stalker_tid_input.text().strip()
        thread_id: int | None = None
        if tid_text:
            try:
                thread_id = int(tid_text)
            except ValueError:
                self._console.appendPlainText(f"[-] Invalid thread ID: {tid_text}")
                return

        events = self._get_stalker_events_string()
        limit = self._stalker_limit_spin.value()

        self._stalker_start_btn.setEnabled(False)
        self._console.appendPlainText(f"[*] Starting Stalker trace (tid={thread_id or 'current'}, events={events}, limit={limit})")
        self._run_async(
            self._bridge.stalker_follow(thread_id=thread_id, events=events, limit=limit),
            on_success=self._on_stalker_started,
            on_error=self._on_stalker_start_error,
        )

    def _on_stalker_started(self, result: object) -> None:
        """Handle successful Stalker trace start.

        Args:
            result: Trace ID from the bridge.
        """
        self._console.appendPlainText(f"[+] Stalker tracing started (trace_id={result})")
        self._stalker_start_btn.setEnabled(False)
        self._stalker_stop_btn.setEnabled(True)

    def _on_stalker_start_error(self, exc: object) -> None:
        """Handle Stalker start failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Stalker start failed: {exc}")
        _logger.warning("frida_stalker_start_failed", error=str(exc))
        self._stalker_start_btn.setEnabled(True)

    def _on_stalker_stop(self) -> None:
        """Stop Stalker code tracing and display results."""
        if self._bridge is None:
            return

        tid_text = self._stalker_tid_input.text().strip()
        thread_id: int | None = None
        if tid_text:
            try:
                thread_id = int(tid_text)
            except ValueError:
                _logger.debug("stalker_stop_invalid_tid", tid_text=tid_text)

        self._stalker_stop_btn.setEnabled(False)
        self._run_async(
            self._bridge.stalker_unfollow(thread_id=thread_id),
            on_success=self._on_stalker_stopped,
            on_error=self._on_stalker_stop_error,
        )

    def _on_stalker_stopped(self, result: object) -> None:
        """Handle Stalker trace completion and display results.

        Args:
            result: StalkerTrace from the bridge.
        """
        event_count = getattr(result, "event_count", 0)
        duration = getattr(result, "duration_ms", 0.0)
        self._console.appendPlainText(f"[+] Stalker trace complete: {event_count} events in {duration:.1f}ms")
        events = getattr(result, "events", [])
        display_limit = min(len(events), 50)
        for evt in events[:display_limit]:
            evt_type = getattr(evt, "event_type", "?")
            from_addr = getattr(evt, "from_address", 0)
            to_addr = getattr(evt, "to_address", None)
            depth = getattr(evt, "depth", 0)
            to_str = f" -> 0x{to_addr:X}" if isinstance(to_addr, int) else ""
            self._console.appendPlainText(f"  [{evt_type}] 0x{from_addr:X}{to_str} (depth={depth})")
        if len(events) > display_limit:
            self._console.appendPlainText(f"  ... and {len(events) - display_limit} more events")
        self._stalker_start_btn.setEnabled(True)
        self._stalker_stop_btn.setEnabled(False)

    def _on_stalker_stop_error(self, exc: object) -> None:
        """Handle Stalker stop failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Stalker stop failed: {exc}")
        _logger.warning("frida_stalker_stop_failed", error=str(exc))
        self._stalker_start_btn.setEnabled(True)
        self._stalker_stop_btn.setEnabled(False)

    def refresh_devices(self) -> None:
        """Refresh the device selector combo box."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.enumerate_devices(),
            on_success=self._populate_device_combo,
            on_error=lambda e: _logger.debug("device_enum_failed", error=str(e)),
        )

    def _populate_device_combo(self, result: object) -> None:
        """Populate the device combo box from enumeration results.

        Args:
            result: List of FridaDeviceInfo from the bridge.
        """
        self._device_combo.blockSignals(b=True)
        current = self._device_combo.currentText()
        self._device_combo.clear()
        if isinstance(result, list):
            device_list = cast("list[object]", result)
            for device_obj in device_list:
                dev_id = str(getattr(device_obj, "id", ""))
                dev_name = str(getattr(device_obj, "name", dev_id))
                dev_type = str(getattr(device_obj, "device_type", ""))
                display = f"{dev_name} ({dev_type})" if dev_type else dev_name
                self._device_combo.addItem(display, dev_id)
        idx = self._device_combo.findText(current)
        if idx >= 0:
            self._device_combo.setCurrentIndex(idx)
        self._device_combo.blockSignals(b=False)
