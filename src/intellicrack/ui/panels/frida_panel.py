# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frida instrumentation panel for Intellicrack.

Provides a script editor, console output, and hook manager for interacting with Frida dynamic instrumentation framework.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics, QIntValidator, QKeySequence, QShortcut
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
from intellicrack.ui._hex_format import format_hex_dump
from intellicrack.ui.highlighter import get_highlighter_for_language
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import edit_table_item, set_max_block_count
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.frida_bridge import FridaBridge

_logger = get_logger(__name__)

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

_MODULE_COLUMNS: Final[list[str]] = ["Name", "Base", "Size", "Path"]
_EXPORT_COLUMNS: Final[list[str]] = ["Name", "Address", "Ordinal"]
_IMPORT_COLUMNS: Final[list[str]] = ["Function", "DLL", "Address"]
_CHILD_COLUMNS: Final[list[str]] = ["PID", "Parent PID", "Origin", "Path"]
_CRASH_COLUMNS: Final[list[str]] = ["PID", "Process", "Summary", "Time"]
_NATIVE_TYPES: Final[list[str]] = ["pointer", "int", "uint", "void", "float", "double", "int32", "uint32", "int64", "uint64"]
_CALLING_CONVENTIONS: Final[list[str]] = ["default", "sysv", "stdcall", "thiscall", "fastcall", "mscdecl", "win64"]
_PROTECTIONS: Final[list[str]] = ["---", "r--", "rw-", "r-x", "rwx"]


class FridaPanel(AnalysisPanelBase):
    """Panel for Frida dynamic instrumentation and hooking.

    Provides a script editor for writing Frida JavaScript,
    a console for viewing output, and a hook manager table
    for managing active function hooks.

    Attributes:
        hook_added: Signal emitted with hook ID when a Frida hook is registered.
        script_executed: Signal emitted when a Frida script finishes execution.
    """

    hook_added: pyqtSignal = pyqtSignal(str)
    script_executed: pyqtSignal = pyqtSignal()
    _frida_message_received: pyqtSignal = pyqtSignal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the FridaPanel widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._frida_message_received.connect(self._on_frida_message)
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

        self._spawn_btn = self._add_tool_button(toolbar, "Spawn", self._on_spawn)
        self._resume_btn = self._add_tool_button(toolbar, "Resume", self._on_resume, enabled=False)

        toolbar.addSeparator()

        self.run_btn = self._add_tool_button(toolbar, "Run Script", self._on_run_script)
        self._stop_btn = self._add_tool_button(toolbar, "Stop", self._on_stop_script, enabled=False)
        self._clear_btn = self._add_secondary_button(toolbar, "Clear Console", self._on_clear_console)

        toolbar.addSeparator()

        self.status_label = self._add_toolbar_label(toolbar, "Not attached")

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
                _logger.warning("frida_detach_skipped", exc_info=True)
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
        self._oneshot_script_cb = QCheckBox("One-shot")
        editor_header.addWidget(self._oneshot_script_cb)
        editor_header.addStretch()
        editor_layout.addLayout(editor_header)

        self._script_editor = QPlainTextEdit()
        self._script_editor.setFont(FontManager.get_instance().get_code_font(10))
        self._script_editor.setPlainText(_DEFAULT_FRIDA_SCRIPT)
        self._script_editor.setTabStopDistance(QFontMetrics(self._script_editor.font()).horizontalAdvance(" ") * 4)
        self._js_highlighter = get_highlighter_for_language("javascript", self._script_editor.document())
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
        self._right_tabs.addTab(self._create_modules_section(), "Modules")
        self._right_tabs.addTab(self._create_memory_section(), "Memory")
        self._right_tabs.addTab(self._create_symbols_section(), "Symbols")
        self._right_tabs.addTab(self._create_advanced_section(), "Advanced")
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

        self._intercept_ret_btn = QPushButton("Intercept Ret")
        self._intercept_ret_btn.setObjectName("tool_button")
        self._intercept_ret_btn.clicked.connect(self._on_intercept_return)
        hooks_header.addWidget(self._intercept_ret_btn)

        self._replace_fn_btn = QPushButton("Replace Fn")
        self._replace_fn_btn.setObjectName("tool_button")
        self._replace_fn_btn.clicked.connect(self._on_replace_function)
        hooks_header.addWidget(self._replace_fn_btn)

        self._refresh_hooks_btn = QPushButton("Refresh")
        self._refresh_hooks_btn.setObjectName("tool_button")
        self._refresh_hooks_btn.clicked.connect(self._on_refresh_hooks)
        hooks_header.addWidget(self._refresh_hooks_btn)

        hooks_layout.addLayout(hooks_header)

        self._hooks_table = QTableWidget(0, len(_HOOK_COLUMNS))
        self._hooks_table.setHorizontalHeaderLabels(_HOOK_COLUMNS)
        self._hooks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._hooks_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        hooks_h = self._hooks_table.horizontalHeader()
        if hooks_h is not None:
            hooks_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rename_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F2), self._hooks_table)
        rename_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        rename_shortcut.activated.connect(self._on_hook_rename_shortcut)
        hooks_layout.addWidget(self._hooks_table)
        return hooks_container

    def _on_hook_rename_shortcut(self) -> None:
        """Enter edit mode on the function cell of the currently selected hook row."""
        row = self._hooks_table.currentRow()
        if row < 0:
            return
        item = self._hooks_table.item(row, _HOOK_COL_FUNCTION)
        if item is None:
            return
        edit_table_item(self._hooks_table, item)

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
        self._stalker_compile_cb = QCheckBox("compile")
        events_row.addWidget(self._stalker_compile_cb)
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

        display_row = QHBoxLayout()
        display_row.addWidget(QLabel("Display:"))
        self._stalker_display_limit_spin = QSpinBox()
        self._stalker_display_limit_spin.setRange(10, 10000)
        self._stalker_display_limit_spin.setValue(50)
        self._stalker_display_limit_spin.setSingleStep(50)
        display_row.addWidget(self._stalker_display_limit_spin)
        display_row.addStretch()
        layout.addLayout(display_row)

        layout.addStretch()
        return container

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance for instrumentation.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge
        bridge.set_message_handler(self._frida_message_received.emit)
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
        _logger.debug("frida_panel_log_message", length=len(message))
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
            _logger.warning("frida_attach_by_name_fallback", target=target)
            run_bridge_coroutine_logged(
                self._bridge.attach_by_name(target),
                on_success=lambda _: self._on_attach_name_success(target),
                on_error=lambda e: self._on_attach_failed(target, e),
                parent=self,
                event="frida_attach_by_name",
                logger=_logger,
                level="info",
                target=target,
            )
            return

        run_bridge_coroutine_logged(
            self._bridge.attach(pid),
            on_success=lambda _: self._on_attach_pid_success(pid),
            on_error=lambda e: self._on_attach_failed(target, e),
            parent=self,
            event="frida_attach",
            logger=_logger,
            level="info",
            pid=pid,
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
        if self._bridge is not None:
            self._attached_pid = self._bridge.state.target_pid
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

        _logger.info("frida_detach_started", pid=self._attached_pid)
        self._detach_btn.setEnabled(False)

        run_bridge_coroutine_logged(
            self._bridge.detach(),
            on_success=lambda _: self._on_detach_success(),
            on_error=self._on_detach_error,
            parent=self,
            event="frida_detach",
            logger=_logger,
            level="info",
            pid=self._attached_pid,
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

        if self._oneshot_script_cb.isChecked():
            run_bridge_coroutine_logged(
                self._bridge.execute_script(source),
                on_success=lambda r: self._on_oneshot_script_success(len(source), r),
                on_error=self._on_run_script_error,
                parent=self,
                event="frida_execute_script",
                logger=_logger,
                level="info",
                script_size=len(source),
            )
            return

        run_bridge_coroutine_logged(
            self._bridge.execute_persistent_script(source),
            on_success=lambda r: self._on_run_script_success(len(source), r),
            on_error=self._on_run_script_error,
            parent=self,
            event="frida_execute_persistent_script",
            logger=_logger,
            level="info",
            script_size=len(source),
        )

    def _on_run_script_success(self, script_size: int, result: object) -> None:
        """Handle successful persistent script load.

        Args:
            script_size: Size of the executed script in characters.
            result: Script ID returned by the bridge.

        Raises:
            RuntimeError: If the bridge did not return a usable script handle.
        """
        if not isinstance(result, str) or not result:
            self._active_script_id = None
            self._console.appendPlainText("[-] Unable to track script handle - persistent load aborted")
            self.run_btn.setEnabled(True)
            self._stop_btn.setEnabled(False)
            _logger.error(
                "frida_persistent_script_handle_missing",
                result_type=type(result).__name__,
                script_size=script_size,
            )
            msg = "unable to track script handle"
            raise RuntimeError(msg)
        self._active_script_id = result
        self._console.appendPlainText("[+] Script loaded (persistent)")
        self.run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.script_executed.emit()
        _logger.info("frida_script_executed", script_size=script_size, script_id=result)

    def _on_run_script_error(self, exc: object) -> None:
        """Handle script execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Script execution failed: {exc}")
        _logger.warning("frida_script_execution_failed", error=str(exc))
        self.run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._active_script_id = None

    def _on_stop_script(self) -> None:
        """Stop the currently running persistent script."""
        if self._bridge is None:
            return

        if self._active_script_id is None:
            self._console.appendPlainText("[!] No persistent script handle to stop")
            self._stop_btn.setEnabled(False)
            self.run_btn.setEnabled(True)
            _logger.warning("frida_stop_script_no_handle")
            return

        self._stop_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.unload_script(self._active_script_id),
            on_success=lambda _: self._on_stop_script_success(),
            on_error=self._on_stop_script_error,
            parent=self,
            event="frida_unload_script",
            logger=_logger,
            level="info",
            script_id=self._active_script_id,
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
        function_item = QTableWidgetItem(target)
        self._hooks_table.setItem(row, _HOOK_COL_FUNCTION, function_item)
        self._hooks_table.setItem(row, _HOOK_COL_STATUS, QTableWidgetItem("Installing..."))
        self._hook_ids.append("")

        self._hooks_table.setCurrentCell(row, _HOOK_COL_FUNCTION)
        edit_table_item(self._hooks_table, function_item)

        self._add_hook_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.hook_function(target),
            on_success=lambda result: self._on_hook_installed(row, target, result),
            on_error=lambda exc: self._on_hook_install_error(row, exc),
            parent=self,
            event="frida_hook_function",
            logger=_logger,
            level="info",
            target=target,
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

        if row < len(self._hook_ids):
            self._hook_ids[row] = hook_id
        else:
            self._hook_ids.append(hook_id)
        self._add_hook_btn.setEnabled(True)
        self._console.appendPlainText(f"[+] Hook installed: {target} at {addr_str}")
        self.hook_added.emit(addr_str)
        _logger.info("frida_hook_installed", target=target, hook_id=hook_id)

    def _on_hook_install_error(self, row: int, exc: object) -> None:
        """Handle hook installation failure by removing the pending row.

        Args:
            row: Table row for the failed hook.
            exc: The exception that occurred.
        """
        if row < self._hooks_table.rowCount():
            self._hooks_table.removeRow(row)
        if row < len(self._hook_ids):
            self._hook_ids.pop(row)
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
            run_bridge_coroutine_logged(
                self._bridge.remove_hook(hook_id),
                on_success=lambda _: self._on_hook_removed(selected, hook_id),
                on_error=lambda e: self._on_hook_remove_error(hook_id, e),
                parent=self,
                event="frida_remove_hook",
                logger=_logger,
                level="info",
                hook_id=hook_id,
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
        run_bridge_coroutine_logged(
            self._bridge.connect_device(device_type, host),
            on_success=lambda r: self._console.appendPlainText(f"[+] Connected to device: {getattr(r, 'name', device_type)}"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Device switch failed: {e}"),
            parent=self,
            event="frida_connect_device",
            logger=_logger,
            level="info",
            device_type=device_type,
            host=host,
        )

    def _on_refresh_processes(self) -> None:
        """Refresh the process browser table."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        self._refresh_procs_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.enumerate_processes(),
            on_success=self._populate_process_table,
            on_error=self._on_refresh_processes_error,
            parent=self,
            event="frida_enumerate_processes",
            logger=_logger,
        )

    def _populate_process_table(self, result: object) -> None:
        """Populate the process table from enumeration results.

        Args:
            result: List of FridaProcessEntry objects from the bridge.
        """
        self._process_table.setRowCount(0)
        if isinstance(result, list):
            proc_list = cast("list[object]", result)
            for proc in proc_list:
                row = self._process_table.rowCount()
                self._process_table.insertRow(row)
                pid_val = getattr(proc, "pid", 0)
                name_val = getattr(proc, "name", "")
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
        run_bridge_coroutine_logged(
            self._bridge.enumerate_threads(),
            on_success=self._populate_threads_table,
            on_error=self._on_refresh_threads_error,
            parent=self,
            event="frida_enumerate_threads",
            logger=_logger,
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
        if self._stalker_compile_cb.isChecked():
            events.append("compile")
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
                self._invalid_input(
                    "frida_stalker_start_invalid_tid",
                    input_text=tid_text,
                    console_msg=f"[-] Invalid thread ID: {tid_text}",
                    logger=_logger,
                )
                return

        events = self._get_stalker_events_string()
        limit = self._stalker_limit_spin.value()

        self._stalker_start_btn.setEnabled(False)
        self._console.appendPlainText(f"[*] Starting Stalker trace (tid={thread_id or 'current'}, events={events}, limit={limit})")
        run_bridge_coroutine_logged(
            self._bridge.stalker_follow(thread_id=thread_id, events=events, limit=limit),
            on_success=self._on_stalker_started,
            on_error=self._on_stalker_start_error,
            parent=self,
            event="frida_stalker_follow",
            logger=_logger,
            level="info",
            thread_id=thread_id,
            events=events,
            limit=limit,
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
                self._console.appendPlainText(f"[-] Invalid thread ID: {tid_text}")
                self._stalker_stop_btn.setEnabled(True)
                _logger.warning("frida_stalker_stop_invalid_tid", tid_text=tid_text)
                return

        self._stalker_stop_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stalker_unfollow(thread_id=thread_id),
            on_success=self._on_stalker_stopped,
            on_error=self._on_stalker_stop_error,
            parent=self,
            event="frida_stalker_unfollow",
            logger=_logger,
            level="info",
            thread_id=thread_id,
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
        display_limit = min(len(events), self._stalker_display_limit_spin.value())
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

        run_bridge_coroutine_logged(
            self._bridge.enumerate_devices(),
            on_success=self._populate_device_combo,
            on_error=lambda e: _logger.debug("device_enum_failed", error=str(e)),
            parent=self,
            event="frida_enumerate_devices",
            logger=_logger,
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

    def _on_oneshot_script_success(self, script_size: int, result: object) -> None:
        """Handle successful one-shot script execution.

        Args:
            script_size: Size of the executed script in characters.
            result: Script result string.
        """
        self._console.appendPlainText(f"[+] Script result: {result}")
        self.run_btn.setEnabled(True)
        self.script_executed.emit()
        _logger.info("frida_oneshot_script_executed", script_size=script_size)

    def _on_spawn(self) -> None:
        """Spawn a new process with Frida instrumentation."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        path_str, accepted = QInputDialog.getText(self, "Spawn Process", "Executable path:")
        if not accepted or not path_str.strip():
            return

        args_str, args_accepted = QInputDialog.getText(self, "Arguments", "Command-line arguments (space-separated):")
        spawn_args: list[str] | None = None
        if args_accepted and args_str.strip():
            spawn_args = args_str.strip().split()

        self._spawn_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.spawn(Path(path_str.strip()), spawn_args),
            on_success=lambda pid: self._on_spawn_success(int(pid) if isinstance(pid, (int, float)) else 0),
            on_error=self._on_spawn_error,
            parent=self,
            event="frida_spawn",
            logger=_logger,
            level="info",
            target_path=path_str.strip(),
            spawn_args=spawn_args,
        )

    def _on_spawn_success(self, pid: int) -> None:
        """Handle successful process spawn.

        Args:
            pid: Spawned process ID.
        """
        self._attached_pid = pid
        self._console.appendPlainText(f"[+] Spawned process PID {pid}")
        self._set_status(f"Spawned (PID: {pid})")
        self._spawn_btn.setEnabled(True)
        self._resume_btn.setEnabled(True)
        self._attach_btn.setEnabled(False)
        self._detach_btn.setEnabled(True)
        self.tool_started.emit()

    def _on_spawn_error(self, exc: object) -> None:
        """Handle spawn failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Spawn failed: {exc}")
        _logger.warning("frida_spawn_failed", error=str(exc))
        self._spawn_btn.setEnabled(True)

    def _on_resume(self) -> None:
        """Resume a spawned process."""
        if self._bridge is None:
            return

        self._resume_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.resume(),
            on_success=lambda _: self._on_resume_success(),
            on_error=self._on_resume_error,
            parent=self,
            event="frida_resume",
            logger=_logger,
            level="info",
        )

    def _on_resume_success(self) -> None:
        """Handle successful process resume."""
        self._console.appendPlainText("[+] Process resumed")
        self._set_status("Running")
        self._resume_btn.setEnabled(False)

    def _on_resume_error(self, exc: object) -> None:
        """Handle resume failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Resume failed: {exc}")
        self._resume_btn.setEnabled(True)

    def _on_intercept_return(self) -> None:
        """Set up a return value interception hook."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        target, accepted = QInputDialog.getText(self, "Intercept Return", "Target (address or module!func):")
        if not accepted or not target.strip():
            return

        ret_val, val_accepted = QInputDialog.getInt(self, "Return Value", "Value to return:", value=1)
        if not val_accepted:
            return

        run_bridge_coroutine_logged(
            self._bridge.intercept_return(target.strip(), ret_val),
            on_success=lambda _: self._console.appendPlainText(
                f"[+] Intercept return installed for {target.strip()} -> {ret_val}",
            ),
            on_error=lambda e: self._console.appendPlainText(f"[-] Intercept return failed: {e}"),
            parent=self,
            event="frida_intercept_return",
            logger=_logger,
            level="info",
            target=target.strip(),
            return_value=ret_val,
        )

    def _on_replace_function(self) -> None:
        """Replace a function implementation with custom code."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        target, accepted = QInputDialog.getText(self, "Replace Function", "Target (address or module!func):")
        if not accepted or not target.strip():
            return

        code, code_accepted = QInputDialog.getMultiLineText(
            self,
            "Replacement Code",
            "JavaScript NativeCallback expression:",
        )
        if not code_accepted or not code.strip():
            return

        run_bridge_coroutine_logged(
            self._bridge.replace_function(target.strip(), code.strip()),
            on_success=lambda _: self._console.appendPlainText(f"[+] Function replaced: {target.strip()}"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Replace function failed: {e}"),
            parent=self,
            event="frida_replace_function",
            logger=_logger,
            level="info",
            target=target.strip(),
            replacement_size=len(code.strip()),
        )

    def _on_refresh_hooks(self) -> None:
        """Refresh the hooks table from the bridge."""
        if self._bridge is None:
            return

        self._refresh_hooks_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_hooks(),
            on_success=self._populate_hooks_from_bridge,
            on_error=self._on_refresh_hooks_error,
            parent=self,
            event="frida_get_hooks",
            logger=_logger,
        )

    def _populate_hooks_from_bridge(self, result: object) -> None:
        """Repopulate the hooks table from bridge data.

        Args:
            result: List of HookInfo from the bridge.
        """
        self._hooks_table.setRowCount(0)
        self._hook_ids.clear()
        if isinstance(result, list):
            for hook in cast("list[object]", result):
                hook_id = str(getattr(hook, "id", ""))
                target = str(getattr(hook, "target", ""))
                address = getattr(hook, "address", None)
                addr_str = f"0x{address:X}" if isinstance(address, int) and address else "0x0"
                active = getattr(hook, "active", True)

                module_str = ""
                func_str = target
                if "!" in target:
                    parts = target.split("!", 1)
                    module_str = parts[0]
                    func_str = parts[1]

                row = self._hooks_table.rowCount()
                self._hooks_table.insertRow(row)
                self._hooks_table.setItem(row, _HOOK_COL_ADDRESS, QTableWidgetItem(addr_str))
                self._hooks_table.setItem(row, _HOOK_COL_MODULE, QTableWidgetItem(module_str))
                self._hooks_table.setItem(row, _HOOK_COL_FUNCTION, QTableWidgetItem(func_str))
                self._hooks_table.setItem(row, _HOOK_COL_STATUS, QTableWidgetItem("Active" if active else "Inactive"))
                self._hook_ids.append(hook_id)
        self._refresh_hooks_btn.setEnabled(True)

    def _on_refresh_hooks_error(self, exc: object) -> None:
        """Handle hooks refresh failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Refresh hooks failed: {exc}")
        self._refresh_hooks_btn.setEnabled(True)

    def _create_modules_section(self) -> QWidget:
        """Create the modules browser section.

        Returns:
            QWidget: Modules container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        header = QHBoxLayout()
        title = QLabel("Modules")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        header.addWidget(title)
        header.addStretch()
        self._refresh_modules_btn = QPushButton("Refresh")
        self._refresh_modules_btn.setObjectName("tool_button")
        self._refresh_modules_btn.clicked.connect(self._on_refresh_modules)
        header.addWidget(self._refresh_modules_btn)
        layout.addLayout(header)

        self._modules_table = QTableWidget(0, len(_MODULE_COLUMNS))
        self._modules_table.setHorizontalHeaderLabels(_MODULE_COLUMNS)
        self._modules_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._modules_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        mod_h = self._modules_table.horizontalHeader()
        if mod_h is not None:
            mod_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._modules_table)

        detail_row = QHBoxLayout()
        detail_row.addWidget(QLabel("Module:"))
        self._module_combo = QComboBox()
        self._module_combo.setMinimumWidth(_DEVICE_COMBO_MIN_WIDTH)
        detail_row.addWidget(self._module_combo)
        self._exports_btn = QPushButton("Exports")
        self._exports_btn.setObjectName("tool_button")
        self._exports_btn.clicked.connect(self._on_show_exports)
        detail_row.addWidget(self._exports_btn)
        self._imports_btn = QPushButton("Imports")
        self._imports_btn.setObjectName("tool_button")
        self._imports_btn.clicked.connect(self._on_show_imports)
        detail_row.addWidget(self._imports_btn)
        detail_row.addStretch()
        layout.addLayout(detail_row)

        self._module_detail_tabs = QTabWidget()
        self._exports_table = QTableWidget(0, len(_EXPORT_COLUMNS))
        self._exports_table.setHorizontalHeaderLabels(_EXPORT_COLUMNS)
        exp_h = self._exports_table.horizontalHeader()
        if exp_h is not None:
            exp_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._module_detail_tabs.addTab(self._exports_table, "Exports")

        self._imports_table = QTableWidget(0, len(_IMPORT_COLUMNS))
        self._imports_table.setHorizontalHeaderLabels(_IMPORT_COLUMNS)
        imp_h = self._imports_table.horizontalHeader()
        if imp_h is not None:
            imp_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._module_detail_tabs.addTab(self._imports_table, "Imports")
        layout.addWidget(self._module_detail_tabs)

        return container

    def _on_refresh_modules(self) -> None:
        """Refresh the modules table."""
        if self._bridge is None:
            return
        self._refresh_modules_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.enumerate_modules(),
            on_success=self._populate_modules_table,
            on_error=self._on_modules_error,
            parent=self,
            event="frida_enumerate_modules",
            logger=_logger,
        )

    def _populate_modules_table(self, result: object) -> None:
        """Populate the modules table and combo from results.

        Args:
            result: List of ModuleInfo from the bridge.
        """
        self._modules_table.setRowCount(0)
        self._module_combo.clear()
        if isinstance(result, list):
            for mod in cast("list[object]", result):
                name = str(getattr(mod, "name", ""))
                base = getattr(mod, "base_address", 0)
                size = getattr(mod, "size", 0)
                path = str(getattr(mod, "path", ""))
                row = self._modules_table.rowCount()
                self._modules_table.insertRow(row)
                self._modules_table.setItem(row, 0, QTableWidgetItem(name))
                self._modules_table.setItem(row, 1, QTableWidgetItem(f"0x{base:X}" if isinstance(base, int) else str(base)))
                self._modules_table.setItem(row, 2, QTableWidgetItem(str(size)))
                self._modules_table.setItem(row, 3, QTableWidgetItem(path))
                self._module_combo.addItem(name)
        self._refresh_modules_btn.setEnabled(True)

    def _on_modules_error(self, exc: object) -> None:
        """Handle modules operation failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Modules operation failed: {exc}")
        self._refresh_modules_btn.setEnabled(True)

    def _on_show_exports(self) -> None:
        """Show exports for the selected module."""
        if self._bridge is None:
            return
        if module_name := self._module_combo.currentText():
            run_bridge_coroutine_logged(
                self._bridge.enumerate_exports(module_name),
                on_success=self._populate_exports_table,
                on_error=lambda e: self._console.appendPlainText(f"[-] Exports failed: {e}"),
                parent=self,
                event="frida_enumerate_exports",
                logger=_logger,
                module=module_name,
            )
        else:
            return

    def _populate_exports_table(self, result: object) -> None:
        """Populate the exports table from results.

        Args:
            result: List of ExportInfo from the bridge.
        """
        self._exports_table.setRowCount(0)
        if isinstance(result, list):
            for exp in cast("list[object]", result):
                name = str(getattr(exp, "name", ""))
                addr = getattr(exp, "address", 0)
                ordinal = getattr(exp, "ordinal", 0)
                row = self._exports_table.rowCount()
                self._exports_table.insertRow(row)
                self._exports_table.setItem(row, 0, QTableWidgetItem(name))
                self._exports_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
                self._exports_table.setItem(row, 2, QTableWidgetItem(str(ordinal)))
        self._module_detail_tabs.setCurrentIndex(0)

    def _on_show_imports(self) -> None:
        """Show imports for the selected module."""
        if self._bridge is None:
            return
        if module_name := self._module_combo.currentText():
            run_bridge_coroutine_logged(
                self._bridge.enumerate_imports(module_name),
                on_success=self._populate_imports_table,
                on_error=lambda e: self._console.appendPlainText(f"[-] Imports failed: {e}"),
                parent=self,
                event="frida_enumerate_imports",
                logger=_logger,
                module=module_name,
            )
        else:
            return

    def _populate_imports_table(self, result: object) -> None:
        """Populate the imports table from results.

        Args:
            result: List of ImportInfo from the bridge.
        """
        self._imports_table.setRowCount(0)
        if isinstance(result, list):
            for imp in cast("list[object]", result):
                func = str(getattr(imp, "function", ""))
                dll = str(getattr(imp, "dll", ""))
                addr = getattr(imp, "address", 0)
                row = self._imports_table.rowCount()
                self._imports_table.insertRow(row)
                self._imports_table.setItem(row, 0, QTableWidgetItem(func))
                self._imports_table.setItem(row, 1, QTableWidgetItem(dll))
                self._imports_table.setItem(row, 2, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
        self._module_detail_tabs.setCurrentIndex(1)

    def _create_memory_section(self) -> QWidget:
        """Create the memory operations section.

        Returns:
            QWidget: Memory container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        mem_tabs = QTabWidget()

        rw_widget = QWidget()
        rw_layout = QVBoxLayout(rw_widget)
        read_row = QHBoxLayout()
        read_row.addWidget(QLabel("Address:"))
        self._mem_read_addr = QLineEdit()
        self._mem_read_addr.setPlaceholderText("0x401000")
        read_row.addWidget(self._mem_read_addr)
        read_row.addWidget(QLabel("Size:"))
        self._mem_read_size = QSpinBox()
        self._mem_read_size.setRange(1, 65536)
        self._mem_read_size.setValue(256)
        read_row.addWidget(self._mem_read_size)
        self._mem_read_btn = QPushButton("Read")
        self._mem_read_btn.setObjectName("tool_button")
        self._mem_read_btn.clicked.connect(self._on_read_memory)
        read_row.addWidget(self._mem_read_btn)
        rw_layout.addLayout(read_row)

        self._mem_hex_display = QPlainTextEdit()
        self._mem_hex_display.setFont(FontManager.get_instance().get_code_font(9))
        self._mem_hex_display.setReadOnly(ro=True)
        rw_layout.addWidget(self._mem_hex_display)

        write_row = QHBoxLayout()
        write_row.addWidget(QLabel("Address:"))
        self._mem_write_addr = QLineEdit()
        self._mem_write_addr.setPlaceholderText("0x401000")
        write_row.addWidget(self._mem_write_addr)
        write_row.addWidget(QLabel("Data (hex):"))
        self._mem_write_data = QLineEdit()
        self._mem_write_data.setPlaceholderText("90 90 90")
        write_row.addWidget(self._mem_write_data)
        self._mem_write_btn = QPushButton("Write")
        self._mem_write_btn.setObjectName("tool_button")
        self._mem_write_btn.clicked.connect(self._on_write_memory)
        write_row.addWidget(self._mem_write_btn)
        rw_layout.addLayout(write_row)

        alloc_row = QHBoxLayout()
        alloc_row.addWidget(QLabel("Allocate:"))
        self._mem_alloc_size = QSpinBox()
        self._mem_alloc_size.setRange(1, 1048576)
        self._mem_alloc_size.setValue(4096)
        alloc_row.addWidget(self._mem_alloc_size)
        self._mem_alloc_btn = QPushButton("Allocate")
        self._mem_alloc_btn.setObjectName("tool_button")
        self._mem_alloc_btn.clicked.connect(self._on_allocate_memory)
        alloc_row.addWidget(self._mem_alloc_btn)
        self._mem_alloc_result = QLabel("")
        alloc_row.addWidget(self._mem_alloc_result)
        alloc_row.addStretch()
        rw_layout.addLayout(alloc_row)
        mem_tabs.addTab(rw_widget, "Read/Write")

        scan_widget = QWidget()
        scan_layout = QVBoxLayout(scan_widget)
        scan_row = QHBoxLayout()
        scan_row.addWidget(QLabel("Pattern:"))
        self._mem_scan_pattern = QLineEdit()
        self._mem_scan_pattern.setPlaceholderText("48 8B ?? ??")
        scan_row.addWidget(self._mem_scan_pattern)
        self._mem_scan_btn = QPushButton("Scan")
        self._mem_scan_btn.setObjectName("tool_button")
        self._mem_scan_btn.clicked.connect(self._on_scan_memory)
        scan_row.addWidget(self._mem_scan_btn)
        scan_layout.addLayout(scan_row)
        self._mem_scan_table = QTableWidget(0, 2)
        self._mem_scan_table.setHorizontalHeaderLabels(["Address", "Match"])
        scan_h = self._mem_scan_table.horizontalHeader()
        if scan_h is not None:
            scan_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        scan_layout.addWidget(self._mem_scan_table)
        mem_tabs.addTab(scan_widget, "Scan")

        regions_widget = QWidget()
        regions_layout = QVBoxLayout(regions_widget)
        regions_row = QHBoxLayout()
        regions_row.addWidget(QLabel("Protection:"))
        self._mem_prot_combo = QComboBox()
        self._mem_prot_combo.addItems(_PROTECTIONS)
        regions_row.addWidget(self._mem_prot_combo)
        self._mem_regions_btn = QPushButton("List Regions")
        self._mem_regions_btn.setObjectName("tool_button")
        self._mem_regions_btn.clicked.connect(self._on_list_regions)
        regions_row.addWidget(self._mem_regions_btn)
        regions_row.addStretch()
        regions_layout.addLayout(regions_row)
        self._mem_regions_table = QTableWidget(0, 6)
        self._mem_regions_table.setHorizontalHeaderLabels(["Base", "Size", "Protection", "State", "Type", "Module"])
        reg_h = self._mem_regions_table.horizontalHeader()
        if reg_h is not None:
            reg_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        regions_layout.addWidget(self._mem_regions_table)
        mem_tabs.addTab(regions_widget, "Regions")

        protect_widget = QWidget()
        protect_layout = QVBoxLayout(protect_widget)
        prot_row = QHBoxLayout()
        prot_row.addWidget(QLabel("Address:"))
        self._mem_prot_addr = QLineEdit()
        self._mem_prot_addr.setPlaceholderText("0x401000")
        prot_row.addWidget(self._mem_prot_addr)
        prot_row.addWidget(QLabel("Size:"))
        self._mem_prot_size = QSpinBox()
        self._mem_prot_size.setRange(1, 1048576)
        self._mem_prot_size.setValue(4096)
        prot_row.addWidget(self._mem_prot_size)
        prot_row.addWidget(QLabel("Protection:"))
        self._mem_prot_set_combo = QComboBox()
        self._mem_prot_set_combo.addItems(["rwx", "r-x", "rw-", "r--"])
        prot_row.addWidget(self._mem_prot_set_combo)
        self._mem_prot_set_btn = QPushButton("Set")
        self._mem_prot_set_btn.setObjectName("tool_button")
        self._mem_prot_set_btn.clicked.connect(self._on_set_protection)
        prot_row.addWidget(self._mem_prot_set_btn)
        self._mem_prot_result = QLabel("")
        prot_row.addWidget(self._mem_prot_result)
        prot_row.addStretch()
        protect_layout.addLayout(prot_row)
        protect_layout.addStretch()
        mem_tabs.addTab(protect_widget, "Protect")

        layout.addWidget(mem_tabs)
        return container

    def _on_read_memory(self) -> None:
        """Read memory from the target process."""
        if self._bridge is None:
            return
        addr = self._parse_hex_address(self._mem_read_addr.text())
        if addr is None:
            self._console.appendPlainText("[-] Invalid address")
            return
        size = self._mem_read_size.value()
        captured_addr = addr
        run_bridge_coroutine_logged(
            self._bridge.read_memory(captured_addr, size),
            on_success=lambda r: self._on_read_memory_success(captured_addr, r),
            on_error=lambda e: self._console.appendPlainText(f"[-] Read failed: {e}"),
            parent=self,
            event="frida_read_memory",
            logger=_logger,
            address=hex(captured_addr),
            size=size,
        )

    def _on_read_memory_success(self, base_addr: int, result: object) -> None:
        """Handle successful memory read and display hex dump.

        Args:
            base_addr: Base address for the hex dump display.
            result: Raw bytes from the bridge.
        """
        if isinstance(result, (bytes, bytearray)):
            self._mem_hex_display.setPlainText(format_hex_dump(bytes(result), base_addr))
        else:
            self._mem_hex_display.setPlainText(str(result))

    def _on_write_memory(self) -> None:
        """Write memory in the target process."""
        if self._bridge is None:
            return
        addr = self._parse_hex_address(self._mem_write_addr.text())
        if addr is None:
            self._console.appendPlainText("[-] Invalid address")
            return
        hex_str = self._mem_write_data.text().strip()
        if not hex_str:
            return
        try:
            data = bytes.fromhex(hex_str.replace(" ", ""))
        except ValueError:
            self._invalid_input(
                "frida_write_memory_invalid_hex",
                input_text=hex_str,
                console_msg="[-] Invalid hex data",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.write_memory(addr, data),
            on_success=lambda _: self._console.appendPlainText(f"[+] Wrote {len(data)} bytes to 0x{addr:X}"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Write failed: {e}"),
            parent=self,
            event="frida_write_memory",
            logger=_logger,
            level="info",
            address=hex(addr),
            size=len(data),
        )

    def _on_allocate_memory(self) -> None:
        """Allocate memory in the target process."""
        if self._bridge is None:
            return
        size = self._mem_alloc_size.value()
        run_bridge_coroutine_logged(
            self._bridge.allocate_memory(size),
            on_success=lambda r: self._mem_alloc_result.setText(f"0x{r:X}" if isinstance(r, int) else str(r)),
            on_error=lambda e: self._console.appendPlainText(f"[-] Allocate failed: {e}"),
            parent=self,
            event="frida_allocate_memory",
            logger=_logger,
            level="info",
            size=size,
        )

    def _on_scan_memory(self) -> None:
        """Scan process memory for a pattern."""
        if self._bridge is None:
            return
        pattern_str = self._mem_scan_pattern.text().strip()
        if not pattern_str:
            return
        try:
            pattern_bytes = bytes.fromhex(pattern_str.replace("??", "00").replace(" ", ""))
        except ValueError:
            self._invalid_input(
                "frida_scan_memory_invalid_pattern",
                input_text=pattern_str,
                console_msg="[-] Invalid pattern",
                logger=_logger,
            )
            return
        self._mem_scan_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.scan_memory(pattern_bytes),
            on_success=self._populate_scan_table,
            on_error=self._on_scan_error,
            parent=self,
            event="frida_scan_memory",
            logger=_logger,
            pattern_length=len(pattern_bytes),
        )

    def _populate_scan_table(self, result: object) -> None:
        """Populate the scan results table.

        Args:
            result: List of MemorySearchResult from the bridge.
        """
        self._mem_scan_table.setRowCount(0)
        if isinstance(result, list):
            for match in cast("list[object]", result):
                addr = getattr(match, "address", 0)
                matched = str(getattr(match, "matched_bytes", ""))
                row = self._mem_scan_table.rowCount()
                self._mem_scan_table.insertRow(row)
                self._mem_scan_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
                self._mem_scan_table.setItem(row, 1, QTableWidgetItem(matched))
        self._mem_scan_btn.setEnabled(True)
        self._console.appendPlainText(f"[+] Scan complete: {self._mem_scan_table.rowCount()} matches")

    def _on_scan_error(self, exc: object) -> None:
        """Handle scan failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Scan failed: {exc}")
        self._mem_scan_btn.setEnabled(True)

    def _on_list_regions(self) -> None:
        """List memory regions of the process."""
        if self._bridge is None:
            return
        protection = self._mem_prot_combo.currentText()
        self._mem_regions_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_memory_regions(protection),
            on_success=self._populate_regions_table,
            on_error=self._on_regions_error,
            parent=self,
            event="frida_get_memory_regions",
            logger=_logger,
            protection_filter=protection,
        )

    def _populate_regions_table(self, result: object) -> None:
        """Populate the memory regions table.

        Args:
            result: List of MemoryRegion from the bridge.
        """
        self._mem_regions_table.setRowCount(0)
        if isinstance(result, list):
            for region in cast("list[object]", result):
                base = getattr(region, "base_address", 0)
                size = getattr(region, "size", 0)
                prot = str(getattr(region, "protection", ""))
                state = str(getattr(region, "state", ""))
                rtype = str(getattr(region, "type", ""))
                module = str(getattr(region, "module_name", "") or "")
                row = self._mem_regions_table.rowCount()
                self._mem_regions_table.insertRow(row)
                self._mem_regions_table.setItem(row, 0, QTableWidgetItem(f"0x{base:X}" if isinstance(base, int) else str(base)))
                self._mem_regions_table.setItem(row, 1, QTableWidgetItem(str(size)))
                self._mem_regions_table.setItem(row, 2, QTableWidgetItem(prot))
                self._mem_regions_table.setItem(row, 3, QTableWidgetItem(state))
                self._mem_regions_table.setItem(row, 4, QTableWidgetItem(rtype))
                self._mem_regions_table.setItem(row, 5, QTableWidgetItem(module))
        self._mem_regions_btn.setEnabled(True)

    def _on_regions_error(self, exc: object) -> None:
        """Handle regions listing failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] List regions failed: {exc}")
        self._mem_regions_btn.setEnabled(True)

    def _on_set_protection(self) -> None:
        """Set memory protection for a region."""
        if self._bridge is None:
            return
        addr = self._parse_hex_address(self._mem_prot_addr.text())
        if addr is None:
            self._console.appendPlainText("[-] Invalid address")
            return
        size = self._mem_prot_size.value()
        protection = self._mem_prot_set_combo.currentText()
        run_bridge_coroutine_logged(
            self._bridge.protect_memory(addr, size, protection),
            on_success=lambda r: self._mem_prot_result.setText("OK" if r else "Failed"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Set protection failed: {e}"),
            parent=self,
            event="frida_protect_memory",
            logger=_logger,
            level="info",
            address=hex(addr),
            size=size,
            protection=protection,
        )

    @staticmethod
    def _parse_hex_address(text: str) -> int | None:
        """Parse a hex address string to an integer.

        Args:
            text: Address string (e.g., '0x401000' or '401000').

        Returns:
            int | None: Parsed address or None if invalid.
        """
        text = text.strip()
        if not text:
            return None
        try:
            return int(text, 16)
        except ValueError:
            _logger.warning("frida_address_parse_failed", input_text=text)
            return None

    def _create_symbols_section(self) -> QWidget:
        """Create the symbols resolution section.

        Returns:
            QWidget: Symbols container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel("Symbols")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(title)

        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("Module:"))
        self._sym_module_input = QLineEdit()
        self._sym_module_input.setPlaceholderText("kernel32.dll")
        base_row.addWidget(self._sym_module_input)
        self._sym_find_base_btn = QPushButton("Find Base")
        self._sym_find_base_btn.setObjectName("tool_button")
        self._sym_find_base_btn.clicked.connect(self._on_find_base)
        base_row.addWidget(self._sym_find_base_btn)
        self._sym_base_result = QLabel("")
        base_row.addWidget(self._sym_base_result)
        layout.addLayout(base_row)

        resolve_row = QHBoxLayout()
        resolve_row.addWidget(QLabel("Address:"))
        self._sym_addr_input = QLineEdit()
        self._sym_addr_input.setPlaceholderText("0x401000")
        resolve_row.addWidget(self._sym_addr_input)
        self._sym_resolve_btn = QPushButton("Resolve")
        self._sym_resolve_btn.setObjectName("tool_button")
        self._sym_resolve_btn.clicked.connect(self._on_resolve_symbol)
        resolve_row.addWidget(self._sym_resolve_btn)
        layout.addLayout(resolve_row)

        find_row = QHBoxLayout()
        find_row.addWidget(QLabel("Function:"))
        self._sym_func_input = QLineEdit()
        self._sym_func_input.setPlaceholderText("CreateFileW")
        find_row.addWidget(self._sym_func_input)
        self._sym_find_btn = QPushButton("Find")
        self._sym_find_btn.setObjectName("tool_button")
        self._sym_find_btn.clicked.connect(self._on_find_functions)
        find_row.addWidget(self._sym_find_btn)
        layout.addLayout(find_row)

        api_row = QHBoxLayout()
        api_row.addWidget(QLabel("API:"))
        self._sym_api_input = QLineEdit()
        self._sym_api_input.setPlaceholderText("exports:*!CreateFile*")
        api_row.addWidget(self._sym_api_input)
        self._sym_api_btn = QPushButton("Resolve API")
        self._sym_api_btn.setObjectName("tool_button")
        self._sym_api_btn.clicked.connect(self._on_resolve_api)
        api_row.addWidget(self._sym_api_btn)
        layout.addLayout(api_row)

        sym_tabs = QTabWidget()
        self._sym_results_table = QTableWidget(0, 5)
        self._sym_results_table.setHorizontalHeaderLabels(["Name", "Address", "Module", "File", "Line"])
        sr_h = self._sym_results_table.horizontalHeader()
        if sr_h is not None:
            sr_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        sym_tabs.addTab(self._sym_results_table, "Symbols")

        self._sym_api_table = QTableWidget(0, 2)
        self._sym_api_table.setHorizontalHeaderLabels(["Name", "Address"])
        sa_h = self._sym_api_table.horizontalHeader()
        if sa_h is not None:
            sa_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        sym_tabs.addTab(self._sym_api_table, "API Matches")
        layout.addWidget(sym_tabs)

        return container

    def _on_find_base(self) -> None:
        """Find the base address of a module."""
        if self._bridge is None:
            return
        if module_name := self._sym_module_input.text().strip():
            run_bridge_coroutine_logged(
                self._bridge.find_base_address(module_name),
                on_success=lambda r: self._sym_base_result.setText(f"0x{r:X}" if isinstance(r, int) else str(r)),
                on_error=lambda e: self._console.appendPlainText(f"[-] Find base failed: {e}"),
                parent=self,
                event="frida_find_base_address",
                logger=_logger,
                module=module_name,
            )
        else:
            return

    def _on_resolve_symbol(self) -> None:
        """Resolve a symbol from an address."""
        if self._bridge is None:
            return
        addr = self._parse_hex_address(self._sym_addr_input.text())
        if addr is None:
            self._console.appendPlainText("[-] Invalid address")
            return
        run_bridge_coroutine_logged(
            self._bridge.resolve_symbol(addr),
            on_success=self._on_symbol_resolved,
            on_error=lambda e: self._console.appendPlainText(f"[-] Resolve failed: {e}"),
            parent=self,
            event="frida_resolve_symbol",
            logger=_logger,
            address=hex(addr),
        )

    def _on_symbol_resolved(self, result: object) -> None:
        """Handle successful symbol resolution.

        Args:
            result: SymbolInfo from the bridge.
        """
        name = str(getattr(result, "name", ""))
        addr = getattr(result, "address", 0)
        module = str(getattr(result, "module_name", "") or "")
        self._console.appendPlainText(f"[+] Symbol: {name} at 0x{addr:X} ({module})" if isinstance(addr, int) else f"[+] Symbol: {name}")

    def _on_find_functions(self) -> None:
        """Find functions by name."""
        if self._bridge is None:
            return
        if name := self._sym_func_input.text().strip():
            run_bridge_coroutine_logged(
                self._bridge.find_functions_named(name),
                on_success=self._populate_sym_results_table,
                on_error=lambda e: self._console.appendPlainText(f"[-] Find functions failed: {e}"),
                parent=self,
                event="frida_find_functions_named",
                logger=_logger,
                function_name=name,
            )
        else:
            return

    def _populate_sym_results_table(self, result: object) -> None:
        """Populate the symbols results table.

        Args:
            result: List of SymbolInfo from the bridge.
        """
        self._sym_results_table.setRowCount(0)
        if isinstance(result, list):
            for sym in cast("list[object]", result):
                name = str(getattr(sym, "name", ""))
                addr = getattr(sym, "address", 0)
                module = str(getattr(sym, "module_name", "") or "")
                fname = str(getattr(sym, "file_name", "") or "")
                line = getattr(sym, "line_number", None)
                row = self._sym_results_table.rowCount()
                self._sym_results_table.insertRow(row)
                self._sym_results_table.setItem(row, 0, QTableWidgetItem(name))
                self._sym_results_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))
                self._sym_results_table.setItem(row, 2, QTableWidgetItem(module))
                self._sym_results_table.setItem(row, 3, QTableWidgetItem(fname))
                self._sym_results_table.setItem(row, 4, QTableWidgetItem(str(line) if line is not None else ""))

    def _on_resolve_api(self) -> None:
        """Resolve API functions by pattern."""
        if self._bridge is None:
            return
        if query := self._sym_api_input.text().strip():
            run_bridge_coroutine_logged(
                self._bridge.resolve_api(query),
                on_success=self._populate_api_table,
                on_error=lambda e: self._console.appendPlainText(f"[-] API resolve failed: {e}"),
                parent=self,
                event="frida_resolve_api",
                logger=_logger,
                query=query,
            )
        else:
            return

    def _populate_api_table(self, result: object) -> None:
        """Populate the API matches table.

        Args:
            result: List of ApiResolverMatch from the bridge.
        """
        self._sym_api_table.setRowCount(0)
        if isinstance(result, list):
            for match in cast("list[object]", result):
                name = str(getattr(match, "name", ""))
                addr = getattr(match, "address", 0)
                row = self._sym_api_table.rowCount()
                self._sym_api_table.insertRow(row)
                self._sym_api_table.setItem(row, 0, QTableWidgetItem(name))
                self._sym_api_table.setItem(row, 1, QTableWidgetItem(f"0x{addr:X}" if isinstance(addr, int) else str(addr)))

    def _create_advanced_section(self) -> QWidget:
        """Create the advanced operations section.

        Returns:
            QWidget: Advanced container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        call_title = QLabel("Function Calling")
        call_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(call_title)

        call_row1 = QHBoxLayout()
        call_row1.addWidget(QLabel("Address:"))
        self._adv_call_addr = QLineEdit()
        self._adv_call_addr.setPlaceholderText("0x401000")
        call_row1.addWidget(self._adv_call_addr)
        call_row1.addWidget(QLabel("Args:"))
        self._adv_call_args = QLineEdit()
        self._adv_call_args.setPlaceholderText("0, 1, 2")
        call_row1.addWidget(self._adv_call_args)
        self._adv_call_btn = QPushButton("Call")
        self._adv_call_btn.setObjectName("tool_button")
        self._adv_call_btn.clicked.connect(self._on_call_function)
        call_row1.addWidget(self._adv_call_btn)
        self._adv_call_result = QLabel("")
        call_row1.addWidget(self._adv_call_result)
        layout.addLayout(call_row1)

        call_row2 = QHBoxLayout()
        call_row2.addWidget(QLabel("Return:"))
        self._adv_ret_type = QComboBox()
        self._adv_ret_type.addItems(_NATIVE_TYPES)
        call_row2.addWidget(self._adv_ret_type)
        call_row2.addWidget(QLabel("Arg types:"))
        self._adv_arg_types = QLineEdit()
        self._adv_arg_types.setPlaceholderText("pointer, int, int")
        call_row2.addWidget(self._adv_arg_types)
        call_row2.addWidget(QLabel("Convention:"))
        self._adv_cc = QComboBox()
        self._adv_cc.addItems(_CALLING_CONVENTIONS)
        call_row2.addWidget(self._adv_cc)
        call_row2.addStretch()
        layout.addLayout(call_row2)

        child_title = QLabel("Child Gating")
        child_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(child_title)

        child_btn_row = QHBoxLayout()
        self._adv_enable_child_btn = QPushButton("Enable")
        self._adv_enable_child_btn.setObjectName("tool_button")
        self._adv_enable_child_btn.clicked.connect(self._on_enable_child_gating)
        child_btn_row.addWidget(self._adv_enable_child_btn)
        self._adv_disable_child_btn = QPushButton("Disable")
        self._adv_disable_child_btn.setObjectName("tool_button")
        self._adv_disable_child_btn.clicked.connect(self._on_disable_child_gating)
        child_btn_row.addWidget(self._adv_disable_child_btn)
        self._adv_refresh_children_btn = QPushButton("Refresh")
        self._adv_refresh_children_btn.setObjectName("tool_button")
        self._adv_refresh_children_btn.clicked.connect(self._on_refresh_children)
        child_btn_row.addWidget(self._adv_refresh_children_btn)
        self._adv_resume_child_btn = QPushButton("Resume Selected")
        self._adv_resume_child_btn.setObjectName("tool_button")
        self._adv_resume_child_btn.clicked.connect(self._on_resume_child)
        child_btn_row.addWidget(self._adv_resume_child_btn)
        child_btn_row.addStretch()
        layout.addLayout(child_btn_row)

        self._adv_children_table = QTableWidget(0, len(_CHILD_COLUMNS))
        self._adv_children_table.setHorizontalHeaderLabels(_CHILD_COLUMNS)
        self._adv_children_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        ch_h = self._adv_children_table.horizontalHeader()
        if ch_h is not None:
            ch_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._adv_children_table)

        crash_title = QLabel("Crash Reporting")
        crash_title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        layout.addWidget(crash_title)

        crash_btn_row = QHBoxLayout()
        self._adv_enable_crash_btn = QPushButton("Enable")
        self._adv_enable_crash_btn.setObjectName("tool_button")
        self._adv_enable_crash_btn.clicked.connect(self._on_enable_crash_reporting)
        crash_btn_row.addWidget(self._adv_enable_crash_btn)
        self._adv_refresh_crashes_btn = QPushButton("Refresh")
        self._adv_refresh_crashes_btn.setObjectName("tool_button")
        self._adv_refresh_crashes_btn.clicked.connect(self._on_refresh_crashes)
        crash_btn_row.addWidget(self._adv_refresh_crashes_btn)
        crash_btn_row.addStretch()
        layout.addLayout(crash_btn_row)

        self._adv_crashes_table = QTableWidget(0, len(_CRASH_COLUMNS))
        self._adv_crashes_table.setHorizontalHeaderLabels(_CRASH_COLUMNS)
        cr_h = self._adv_crashes_table.horizontalHeader()
        if cr_h is not None:
            cr_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._adv_crashes_table)

        return container

    def _on_call_function(self) -> None:
        """Call a function in the target process."""
        if self._bridge is None:
            return
        addr = self._parse_hex_address(self._adv_call_addr.text())
        if addr is None:
            self._console.appendPlainText("[-] Invalid address")
            return

        args_text = self._adv_call_args.text().strip()
        args: list[int] | None = None
        if args_text:
            try:
                args = [int(a.strip(), 0) for a in args_text.split(",")]
            except ValueError:
                self._invalid_input(
                    "frida_call_function_invalid_args",
                    input_text=args_text,
                    console_msg="[-] Invalid arguments",
                    logger=_logger,
                )
                return

        ret_type = self._adv_ret_type.currentText()
        arg_types = [t.strip() for t in arg_types_text.split(",")] if (arg_types_text := self._adv_arg_types.text().strip()) else None
        cc = self._adv_cc.currentText()

        run_bridge_coroutine_logged(
            self._bridge.call_function(addr, args, return_type=ret_type, arg_types=arg_types, calling_convention=cc),
            on_success=lambda r: self._adv_call_result.setText(f"0x{r:X}" if isinstance(r, int) else str(r)),
            on_error=lambda e: self._console.appendPlainText(f"[-] Call failed: {e}"),
            parent=self,
            event="frida_call_function",
            logger=_logger,
            level="info",
            address=hex(addr),
            return_type=ret_type,
            arg_count=len(args) if args is not None else 0,
            calling_convention=cc,
        )

    def _on_enable_child_gating(self) -> None:
        """Enable child process gating."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.enable_child_gating(),
            on_success=lambda _: self._console.appendPlainText("[+] Child gating enabled"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Enable child gating failed: {e}"),
            parent=self,
            event="frida_enable_child_gating",
            logger=_logger,
            level="info",
        )

    def _on_disable_child_gating(self) -> None:
        """Disable child process gating."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.disable_child_gating(),
            on_success=lambda _: self._console.appendPlainText("[+] Child gating disabled"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Disable child gating failed: {e}"),
            parent=self,
            event="frida_disable_child_gating",
            logger=_logger,
            level="info",
        )

    def _on_refresh_children(self) -> None:
        """Refresh the pending children table."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_pending_children(),
            on_success=self._populate_children_table,
            on_error=lambda e: self._console.appendPlainText(f"[-] Refresh children failed: {e}"),
            parent=self,
            event="frida_get_pending_children",
            logger=_logger,
        )

    def _populate_children_table(self, result: object) -> None:
        """Populate the children table from results.

        Args:
            result: List of ChildProcessInfo from the bridge.
        """
        self._adv_children_table.setRowCount(0)
        if isinstance(result, list):
            for child in cast("list[object]", result):
                pid = getattr(child, "pid", 0)
                parent = getattr(child, "parent_pid", 0)
                origin = str(getattr(child, "origin", ""))
                path = str(getattr(child, "path", "") or "")
                row = self._adv_children_table.rowCount()
                self._adv_children_table.insertRow(row)
                self._adv_children_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self._adv_children_table.setItem(row, 1, QTableWidgetItem(str(parent)))
                self._adv_children_table.setItem(row, 2, QTableWidgetItem(origin))
                self._adv_children_table.setItem(row, 3, QTableWidgetItem(path))

    def _on_resume_child(self) -> None:
        """Resume the selected child process."""
        if self._bridge is None:
            return
        row = self._adv_children_table.currentRow()
        if row < 0:
            return
        pid_item = self._adv_children_table.item(row, 0)
        if pid_item is None:
            return
        try:
            pid = int(pid_item.text())
        except ValueError:
            _logger.warning("frida_resume_child_pid_parse_failed", input_text=pid_item.text())
            return
        run_bridge_coroutine_logged(
            self._bridge.resume_child(pid),
            on_success=lambda _: self._console.appendPlainText(f"[+] Child {pid} resumed"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Resume child failed: {e}"),
            parent=self,
            event="frida_resume_child",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_enable_crash_reporting(self) -> None:
        """Enable crash event monitoring."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.enable_crash_reporting(),
            on_success=lambda _: self._console.appendPlainText("[+] Crash reporting enabled"),
            on_error=lambda e: self._console.appendPlainText(f"[-] Enable crash reporting failed: {e}"),
            parent=self,
            event="frida_enable_crash_reporting",
            logger=_logger,
            level="info",
        )

    def _on_refresh_crashes(self) -> None:
        """Refresh the crashes table."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_crashes(),
            on_success=self._populate_crashes_table,
            on_error=lambda e: self._console.appendPlainText(f"[-] Refresh crashes failed: {e}"),
            parent=self,
            event="frida_get_crashes",
            logger=_logger,
        )

    def _populate_crashes_table(self, result: object) -> None:
        """Populate the crashes table from results.

        Args:
            result: List of CrashInfo from the bridge.
        """
        self._adv_crashes_table.setRowCount(0)
        if isinstance(result, list):
            for crash in cast("list[object]", result):
                pid = getattr(crash, "pid", 0)
                proc_name = str(getattr(crash, "process_name", ""))
                summary = str(getattr(crash, "summary", ""))
                timestamp = getattr(crash, "timestamp", 0.0)
                time_str = time.strftime("%H:%M:%S", time.localtime(float(timestamp) if isinstance(timestamp, (int, float)) else 0))
                row = self._adv_crashes_table.rowCount()
                self._adv_crashes_table.insertRow(row)
                self._adv_crashes_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self._adv_crashes_table.setItem(row, 1, QTableWidgetItem(proc_name))
                self._adv_crashes_table.setItem(row, 2, QTableWidgetItem(summary))
                self._adv_crashes_table.setItem(row, 3, QTableWidgetItem(time_str))
