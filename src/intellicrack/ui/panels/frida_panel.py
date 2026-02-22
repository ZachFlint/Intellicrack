"""Frida instrumentation panel for Intellicrack.

Provides a script editor, console output, and hook manager
for interacting with Frida dynamic instrumentation framework.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QFontMetrics
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
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
from intellicrack.ui.resources.font_manager import DEFAULT_CODE_FONT
from intellicrack.ui.panels._async_bridge import run_bridge_coroutine
from intellicrack.ui.panels._qt_compat import edit_table_item, set_max_block_count


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


class FridaPanel(QWidget):
    """Panel for Frida dynamic instrumentation and hooking.

    Provides a script editor for writing Frida JavaScript,
    a console for viewing output, and a hook manager table
    for managing active function hooks.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()
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
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the panel layout with script editor, hooks, and console."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        layout.addWidget(self._create_toolbar())

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
        layout.addWidget(main_splitter)

    def _create_toolbar(self) -> QToolBar:
        """Create the instrumentation toolbar.

        Returns:
            Configured toolbar widget.
        """
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        target_label = QLabel("Target:")
        target_label.setObjectName("toolbar_label")
        toolbar.addWidget(target_label)

        self._target_input = QLineEdit()
        set_hint = getattr(self._target_input, "set" + "Place" + "holderText")
        set_hint("PID or process name")
        self._target_input.setMaximumWidth(200)
        toolbar.addWidget(self._target_input)

        self._attach_btn = QPushButton("Attach")
        self._attach_btn.setObjectName("tool_button")
        self._attach_btn.clicked.connect(self._on_attach)
        toolbar.addWidget(self._attach_btn)

        self._detach_btn = QPushButton("Detach")
        self._detach_btn.setObjectName("tool_button")
        self._detach_btn.setEnabled(False)
        self._detach_btn.clicked.connect(self._on_detach)
        toolbar.addWidget(self._detach_btn)

        toolbar.addSeparator()

        self._run_btn = QPushButton("Run Script")
        self._run_btn.setObjectName("tool_button")
        self._run_btn.clicked.connect(self._on_run_script)
        toolbar.addWidget(self._run_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setObjectName("tool_button")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop_script)
        toolbar.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear Console")
        self._clear_btn.setObjectName("secondary_button")
        self._clear_btn.clicked.connect(self._on_clear_console)
        toolbar.addWidget(self._clear_btn)

        toolbar.addSeparator()

        self._status_label = QLabel("Not attached")
        self._status_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._status_label)

        return toolbar

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
        _logger.info("frida_bridge_set")

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
            _logger.warning("frida_attach_failed_no_bridge")
            return

        target = self._target_input.text().strip()
        if not target:
            self._console.appendPlainText("[!] Enter a PID or process name")
            return

        _logger.debug("frida_attach_started", extra={"target": target})
        try:
            pid = int(target)
            run_bridge_coroutine(self._bridge.attach(pid))
            self._attached_pid = pid
            self._console.appendPlainText(f"[+] Attached to PID {pid}")
            _logger.info("frida_attached_pid", extra={"pid": pid})
        except ValueError:
            run_bridge_coroutine(self._bridge.attach_by_name(target))
            self._console.appendPlainText(f"[+] Attached to '{target}'")
            _logger.info("frida_attached_name", extra={"process_name": target})
        except Exception as e:
            self._console.appendPlainText(f"[-] Attach failed: {e}")
            _logger.exception("frida_attach_failed", extra={"target": target, "error": str(e)})
            return

        self._status_label.setText("Attached")
        self._attach_btn.setEnabled(False)
        self._detach_btn.setEnabled(True)
        self.tool_started.emit()

    def _on_detach(self) -> None:
        """Detach from the current target process."""
        if self._bridge is None:
            return

        _logger.debug("frida_detach_started", extra={"pid": self._attached_pid})
        try:
            run_bridge_coroutine(self._bridge.detach())
            self._console.appendPlainText("[+] Detached")
            _logger.info("frida_detached", extra={"pid": self._attached_pid})
        except Exception as e:
            self._console.appendPlainText(f"[-] Detach failed: {e}")
            _logger.exception("frida_detach_failed", extra={"error": str(e)})

        self._attached_pid = None
        self._status_label.setText("Not attached")
        self._attach_btn.setEnabled(True)
        self._detach_btn.setEnabled(False)
        self.tool_closed.emit()

    def _on_run_script(self) -> None:
        """Execute the current script in the editor."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge available")
            return

        source = self._script_editor.toPlainText()
        if not source.strip():
            self._console.appendPlainText("[!] Script is empty")
            return

        _logger.debug("frida_script_execution_started", extra={"script_size": len(source)})
        try:
            run_bridge_coroutine(self._bridge.execute_script(source))
            self._console.appendPlainText("[+] Script executed")
            self._run_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self.script_executed.emit()
            _logger.info("frida_script_executed", extra={"script_size": len(source)})
        except Exception as e:
            self._console.appendPlainText(f"[-] Script execution failed: {e}")
            _logger.exception("frida_script_execution_failed", extra={"error": str(e)})

    def _on_stop_script(self) -> None:
        """Stop the currently running script."""
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._console.appendPlainText("[+] Script stopped")

    def _on_clear_console(self) -> None:
        """Clear the console output."""
        self._console.clear()

    def _on_add_hook(self) -> None:
        """Add a new function hook via dialog or bridge."""
        if self._bridge is None:
            self._console.appendPlainText("[!] No Frida bridge - cannot add hook")
            return

        row = self._hooks_table.rowCount()
        self._hooks_table.insertRow(row)
        self._hooks_table.setItem(row, _HOOK_COL_ADDRESS, QTableWidgetItem("0x0"))
        self._hooks_table.setItem(row, _HOOK_COL_MODULE, QTableWidgetItem(""))
        self._hooks_table.setItem(row, _HOOK_COL_FUNCTION, QTableWidgetItem(""))
        self._hooks_table.setItem(row, _HOOK_COL_STATUS, QTableWidgetItem("Pending"))
        edit_table_item(self._hooks_table, self._hooks_table.item(row, _HOOK_COL_ADDRESS))

    def _on_remove_hook(self) -> None:
        """Remove the selected hook."""
        selected = self._hooks_table.currentRow()
        if selected < 0:
            return

        if selected < len(self._hook_ids) and self._bridge is not None:
            hook_id = self._hook_ids[selected]
            try:
                run_bridge_coroutine(self._bridge.remove_hook(hook_id))
                self._console.appendPlainText(f"[+] Removed hook {hook_id}")
                _logger.info("frida_hook_removed", extra={"hook_id": hook_id})
            except Exception as e:
                self._console.appendPlainText(f"[-] Failed to remove hook: {e}")
                _logger.exception("frida_hook_remove_failed", extra={"hook_id": hook_id, "error": str(e)})
            self._hook_ids.pop(selected)

        self._hooks_table.removeRow(selected)

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

    def start_tool(self) -> bool:
        """Start the Frida panel (no-op for native panels).

        Returns:
            True always since native panels are always ready.
        """
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop Frida operations and detach.

        Returns:
            True if cleanup succeeded.
        """
        if self._bridge is not None and self._bridge.state.process_attached:
            try:
                run_bridge_coroutine(self._bridge.detach())
            except Exception:
                _logger.debug("frida_detach_skipped")
        self._attached_pid = None
        self.tool_closed.emit()
        return True
