# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Frida instrumentation panel for Intellicrack.

Provides a script editor, console output, and hook manager
for interacting with Frida dynamic instrumentation framework.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QFontMetrics
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import set_max_block_count
from intellicrack.ui.resources.font_manager import DEFAULT_CODE_FONT


if TYPE_CHECKING:
    from intellicrack.bridges.frida_bridge import FridaBridge

_logger = get_logger("ui.panels.frida")


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
    """

    hook_added: pyqtSignal = pyqtSignal(str)
    script_executed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Frida panel.

        Args:
            parent: Parent widget.
        """
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
        self._add_toolbar_label(toolbar, "Target:")

        self._target_input = self._add_toolbar_input(toolbar, "PID or process name")

        self._attach_btn = self._add_tool_button(toolbar, "Attach", self._on_attach)
        self._detach_btn = self._add_tool_button(toolbar, "Detach", self._on_detach, enabled=False)

        toolbar.addSeparator()

        self._run_btn = self._add_tool_button(toolbar, "Run Script", self._on_run_script)
        self._stop_btn = self._add_tool_button(toolbar, "Stop", self._on_stop_script, enabled=False)
        self._clear_btn = self._add_secondary_button(toolbar, "Clear Console", self._on_clear_console)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Not attached")

    @override
    def _create_content(self) -> QWidget:
        """Create the Frida instrumentation content area.

        Returns:
            Splitter with script editor, hooks table, and console.
        """
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._create_editor_section())
        top_splitter.addWidget(self._create_hooks_section())
        top_splitter.setSizes([500, 300])
        main_splitter.addWidget(top_splitter)

        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(2)

        console_title = QLabel("Console Output")
        console_title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        console_layout.addWidget(console_title)

        self._console = QPlainTextEdit()
        self._console.setFont(QFont(DEFAULT_CODE_FONT, 9))
        self._console.setReadOnly(True)
        set_max_block_count(self._console, 10000)
        console_layout.addWidget(self._console)
        main_splitter.addWidget(console_container)

        main_splitter.setSizes([400, 200])
        return main_splitter

    @override
    def _cleanup(self) -> None:
        """Detach from the target process if attached."""
        if self._bridge is not None and self._bridge.state.process_attached:
            try:
                run_bridge_coroutine(self._bridge.detach())
            except Exception:
                _logger.debug("frida_detach_skipped", exc_info=True)
        self._attached_pid = None

    def _create_editor_section(self) -> QWidget:
        """Create the script editor section.

        Returns:
            Editor container widget.
        """
        editor_container = QWidget()
        editor_layout = QVBoxLayout(editor_container)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(2)

        editor_header = QHBoxLayout()
        editor_title = QLabel("Script Editor")
        editor_title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        editor_header.addWidget(editor_title)

        self._script_type_combo = QComboBox()
        self._script_type_combo.addItems(["Hook Script", "Stalker", "Memory Scanner", "Custom"])
        editor_header.addWidget(self._script_type_combo)
        editor_header.addStretch()
        editor_layout.addLayout(editor_header)

        self._script_editor = QPlainTextEdit()
        self._script_editor.setFont(QFont(DEFAULT_CODE_FONT, 10))
        self._script_editor.setPlainText(_DEFAULT_FRIDA_SCRIPT)
        self._script_editor.setTabStopDistance(QFontMetrics(self._script_editor.font()).horizontalAdvance(" ") * 4)
        editor_layout.addWidget(self._script_editor)
        return editor_container

    def _create_hooks_section(self) -> QWidget:
        """Create the hooks manager section.

        Returns:
            Hooks container widget.
        """
        hooks_container = QWidget()
        hooks_layout = QVBoxLayout(hooks_container)
        hooks_layout.setContentsMargins(0, 0, 0, 0)
        hooks_layout.setSpacing(2)

        hooks_header = QHBoxLayout()
        hooks_title = QLabel("Active Hooks")
        hooks_title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
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
        self._hooks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hooks_layout.addWidget(self._hooks_table)
        return hooks_container

    def set_bridge(self, bridge: FridaBridge) -> None:
        """Set the FridaBridge instance for instrumentation.

        Args:
            bridge: The FridaBridge to use.
        """
        self._bridge = bridge
        bridge.set_message_handler(self._on_frida_message)
        _logger.info("frida_bridge_set", extra={"bridge_type": type(bridge).__name__})

    def get_bridge(self) -> FridaBridge | None:
        """Get the current FridaBridge instance.

        Returns:
            The attached bridge or None.
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
            _logger.warning("frida_attach_failed_no_bridge", extra={"reason": "bridge not set"})
            return

        target = self._target_input.text().strip()
        if not target:
            self._console.appendPlainText("[!] Enter a PID or process name")
            return

        _logger.debug("frida_attach_started", extra={"target": target})
        self._attach_btn.setEnabled(False)

        try:
            pid = int(target)
        except ValueError:
            _logger.debug("frida_attach_by_name_fallback", extra={"target": target})
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
        _logger.info("frida_attached_pid", extra={"pid": pid})
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
        _logger.info("frida_attached_name", extra={"process_name": target})
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
        _logger.warning("frida_attach_failed", extra={"target": target, "error": str(exc)})
        self._attach_btn.setEnabled(True)

    def _on_detach(self) -> None:
        """Detach from the current target process."""
        if self._bridge is None:
            return

        _logger.debug("frida_detach_started", extra={"pid": self._attached_pid})
        self._detach_btn.setEnabled(False)

        self._run_async(
            self._bridge.detach(),
            on_success=lambda _: self._on_detach_success(),
            on_error=self._on_detach_error,
        )

    def _on_detach_success(self) -> None:
        """Handle successful detach."""
        self._console.appendPlainText("[+] Detached")
        _logger.info("frida_detached", extra={"pid": self._attached_pid})
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
        _logger.warning("frida_detach_failed", extra={"error": str(exc)})
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

        _logger.debug("frida_script_execution_started", extra={"script_size": len(source)})
        self._run_btn.setEnabled(False)

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
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.script_executed.emit()
        _logger.info("frida_script_executed", extra={"script_size": script_size})

    def _on_run_script_error(self, exc: object) -> None:
        """Handle script execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Script execution failed: {exc}")
        _logger.warning("frida_script_execution_failed", extra={"error": str(exc)})
        self._run_btn.setEnabled(True)

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
        self._run_btn.setEnabled(True)
        self._console.appendPlainText("[+] Script stopped")

    def _on_stop_script_error(self, exc: object) -> None:
        """Handle script stop failure.

        Args:
            exc: The exception that occurred.
        """
        self._console.appendPlainText(f"[-] Stop failed: {exc}")
        _logger.warning("frida_script_stop_failed", extra={"error": str(exc)})
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
        _logger.info("frida_hook_installed", extra={"target": target, "hook_id": hook_id})

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
        _logger.warning("frida_hook_install_failed", extra={"error": str(exc)})

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
        _logger.info("frida_hook_removed", extra={"hook_id": hook_id})
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
        _logger.warning("frida_hook_remove_failed", extra={"hook_id": hook_id, "error": str(exc)})
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
        _logger.debug("frida_hook_entry_added", extra={"address": address, "target_module": module, "function": function})
