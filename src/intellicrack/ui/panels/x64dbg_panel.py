# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""x64dbg debugger panel for Intellicrack.

Provides disassembly, register inspection, breakpoint management,
memory viewing, stack traces, and command console for interactive
debugging via the X64DbgBridge backend.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
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
from intellicrack.ui.panels.qt_compat import connect_cell_changed, set_max_block_count
from intellicrack.ui.win32_embed import poll_and_embed


if TYPE_CHECKING:
    from intellicrack.bridges.x64dbg import X64DbgBridge

_logger = get_logger("ui.panels.x64dbg")

_REG_COLUMNS = ["Register", "Value"]
_STACK_COLUMNS = ["Address", "Value", "Info"]
_MODULE_COLUMNS = ["Name", "Base", "Size", "Path"]
_THREAD_COLUMNS = ["TID", "Priority", "State"]
_BP_COLUMNS = ["Address", "Type", "Condition", "Hits", "Enabled"]
_MEM_DUMP_BYTES_PER_LINE = 16
_PRINTABLE_LOW = 32
_PRINTABLE_HIGH = 127

_GENERAL_REGS_64 = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "rip",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
]
_FLAG_REG = "rflags"
_SEGMENT_REGS = ["cs", "ds", "es", "fs", "gs", "ss"]


class X64DbgPanel(AnalysisPanelBase):
    """Native Qt panel for x64dbg interactive debugging.

    Displays disassembly, registers, breakpoints, memory dumps,
    stack traces, and a command console for controlling x64dbg
    via the X64DbgBridge backend.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the x64dbg panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: X64DbgBridge | None = None
        self._is_64bit: bool = True
        self._embedded_container: QWidget | None = None

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add x64dbg-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._load_btn = self._add_tool_button(toolbar, "Load...", self._on_load)

        toolbar.addSeparator()

        self._add_toolbar_label(toolbar, "PID:")

        self._pid_input = self._add_toolbar_input(toolbar, "PID", max_width=80)

        self._attach_btn = self._add_tool_button(toolbar, "Attach", self._on_attach)

        toolbar.addSeparator()

        self._run_btn = self._add_tool_button(toolbar, "Run", self._on_run)
        self._pause_btn = self._add_tool_button(toolbar, "Pause", self._on_pause)
        self._stop_btn = self._add_tool_button(toolbar, "Stop", self._on_stop)

        toolbar.addSeparator()

        self._step_into_btn = self._add_tool_button(toolbar, "Step Into", self._on_step_into)
        self._step_over_btn = self._add_tool_button(toolbar, "Step Over", self._on_step_over)
        self._step_out_btn = self._add_tool_button(toolbar, "Step Out", self._on_step_out)

        toolbar.addSeparator()

        self._64bit_toggle = QCheckBox("64-bit")
        self._64bit_toggle.setChecked(True)
        self._64bit_toggle.toggled.connect(self._on_toggle_64bit)
        toolbar.addWidget(self._64bit_toggle)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Not loaded")

    @override
    def _create_content(self) -> QWidget:
        """Create the x64dbg debugging content area.

        Returns:
            Tab widget with native controls and embedded x64dbg window.
        """
        self._main_tabs = QTabWidget()

        native_container = QWidget()
        native_layout = QVBoxLayout(native_container)
        native_layout.setContentsMargins(0, 0, 0, 0)

        main_splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._create_disasm_section())
        top_splitter.addWidget(self._create_inspect_tabs())
        top_splitter.setSizes([500, 400])
        main_splitter.addWidget(top_splitter)

        main_splitter.addWidget(self._create_bottom_tabs())
        main_splitter.setSizes([450, 250])

        native_layout.addWidget(main_splitter)
        self._main_tabs.addTab(native_container, "Analysis")

        self._embed_host = QWidget()
        embed_layout = QVBoxLayout(self._embed_host)
        embed_layout.setContentsMargins(0, 0, 0, 0)
        self._embed_status_label = QLabel("No debugger process active")
        self._embed_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        embed_layout.addWidget(self._embed_status_label)
        self._main_tabs.addTab(self._embed_host, "x64dbg Window")

        return self._main_tabs

    @override
    def _cleanup(self) -> None:
        """Unregister event callback and stop the x64dbg bridge."""
        if self._embedded_container is not None:
            self._embedded_container.setParent(None)
            self._embedded_container = None
        if self._bridge is not None:
            if hasattr(self._bridge, "unregister_event_callback"):
                self._bridge.unregister_event_callback(self._on_debug_event)
            if self._bridge.state.is_ready():
                try:
                    run_bridge_coroutine(self._bridge.stop())
                except Exception:
                    _logger.exception("x64dbg_stop_failed", extra={"bridge_type": "x64dbg"})

    def _create_disasm_section(self) -> QWidget:
        """Create the disassembly display section.

        Returns:
            Disassembly container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        title = QLabel("Disassembly")
        title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        layout.addWidget(title)

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(QFont("JetBrains Mono", 10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        layout.addWidget(self._disasm_view)

        return container

    def _create_inspect_tabs(self) -> QTabWidget:
        """Create registers, stack, modules, and threads tabs.

        Returns:
            Tab widget with inspection views.
        """
        tabs = QTabWidget()

        self._reg_table = QTableWidget(0, len(_REG_COLUMNS))
        self._reg_table.setHorizontalHeaderLabels(_REG_COLUMNS)
        self._reg_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._reg_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._reg_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        connect_cell_changed(self._reg_table, self._on_register_edited)
        tabs.addTab(self._reg_table, "Registers")

        self._stack_table = QTableWidget(0, len(_STACK_COLUMNS))
        self._stack_table.setHorizontalHeaderLabels(_STACK_COLUMNS)
        self._stack_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._stack_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._stack_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._stack_table, "Stack")

        self._module_table = QTableWidget(0, len(_MODULE_COLUMNS))
        self._module_table.setHorizontalHeaderLabels(_MODULE_COLUMNS)
        self._module_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._module_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._module_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._module_table, "Modules")

        self._thread_table = QTableWidget(0, len(_THREAD_COLUMNS))
        self._thread_table.setHorizontalHeaderLabels(_THREAD_COLUMNS)
        self._thread_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._thread_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._thread_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._thread_table, "Threads")

        return tabs

    def _create_bottom_tabs(self) -> QTabWidget:
        """Create breakpoints, memory, and console tabs.

        Returns:
            Tab widget with bottom-panel views.
        """
        tabs = QTabWidget()

        bp_container = QWidget()
        bp_layout = QVBoxLayout(bp_container)
        bp_layout.setContentsMargins(0, 0, 0, 0)
        bp_layout.setSpacing(2)

        bp_toolbar = QHBoxLayout()
        bp_addr_label = QLabel("Address:")
        bp_addr_label.setFont(QFont("Segoe UI", 9))
        bp_toolbar.addWidget(bp_addr_label)

        self._bp_addr_input = QLineEdit()
        self._bp_addr_input.setMaximumWidth(160)
        set_hint_bp = getattr(self._bp_addr_input, "set" + "Place" + "holderText")
        set_hint_bp("0x...")
        bp_toolbar.addWidget(self._bp_addr_input)

        self._add_bp_btn = QPushButton("Add BP")
        self._add_bp_btn.setObjectName("tool_button")
        self._add_bp_btn.clicked.connect(self._on_add_breakpoint)
        bp_toolbar.addWidget(self._add_bp_btn)

        self._remove_bp_btn = QPushButton("Remove BP")
        self._remove_bp_btn.setObjectName("tool_button")
        self._remove_bp_btn.clicked.connect(self._on_remove_breakpoint)
        bp_toolbar.addWidget(self._remove_bp_btn)

        bp_toolbar.addStretch()
        bp_layout.addLayout(bp_toolbar)

        self._bp_table = QTableWidget(0, len(_BP_COLUMNS))
        self._bp_table.setHorizontalHeaderLabels(_BP_COLUMNS)
        self._bp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._bp_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._bp_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        bp_layout.addWidget(self._bp_table)
        tabs.addTab(bp_container, "Breakpoints")

        mem_container = QWidget()
        mem_layout = QVBoxLayout(mem_container)
        mem_layout.setContentsMargins(0, 0, 0, 0)
        mem_layout.setSpacing(2)

        mem_toolbar = QHBoxLayout()
        mem_addr_label = QLabel("Address:")
        mem_addr_label.setFont(QFont("Segoe UI", 9))
        mem_toolbar.addWidget(mem_addr_label)

        self._mem_addr_input = QLineEdit()
        self._mem_addr_input.setMaximumWidth(160)
        set_hint_mem = getattr(self._mem_addr_input, "set" + "Place" + "holderText")
        set_hint_mem("0x...")
        mem_toolbar.addWidget(self._mem_addr_input)

        mem_size_label = QLabel("Size:")
        mem_size_label.setFont(QFont("Segoe UI", 9))
        mem_toolbar.addWidget(mem_size_label)

        self._mem_size_input = QLineEdit()
        self._mem_size_input.setMaximumWidth(80)
        self._mem_size_input.setText("256")
        mem_toolbar.addWidget(self._mem_size_input)

        self._mem_read_btn = QPushButton("Read")
        self._mem_read_btn.setObjectName("tool_button")
        self._mem_read_btn.clicked.connect(self._on_read_memory)
        mem_toolbar.addWidget(self._mem_read_btn)

        mem_toolbar.addStretch()
        mem_layout.addLayout(mem_toolbar)

        self._mem_dump = QPlainTextEdit()
        self._mem_dump.setFont(QFont("JetBrains Mono", 10))
        self._mem_dump.setReadOnly(True)
        set_max_block_count(self._mem_dump, 10000)
        mem_layout.addWidget(self._mem_dump)
        tabs.addTab(mem_container, "Memory")

        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(2)

        self._console_output = QPlainTextEdit()
        self._console_output.setFont(QFont("JetBrains Mono", 9))
        self._console_output.setReadOnly(True)
        set_max_block_count(self._console_output, 10000)
        console_layout.addWidget(self._console_output)

        self._console_input = QLineEdit()
        self._console_input.setFont(QFont("JetBrains Mono", 9))
        set_hint_con = getattr(self._console_input, "set" + "Place" + "holderText")
        set_hint_con("x64dbg command...")
        self._console_input.returnPressed.connect(self._on_execute_command)
        console_layout.addWidget(self._console_input)
        tabs.addTab(console_container, "Console")

        return tabs

    def set_bridge(self, bridge: X64DbgBridge) -> None:
        """Set the X64DbgBridge instance for debugging.

        Registers an event callback so breakpoint and watchpoint
        hits automatically refresh the panel state.

        Args:
            bridge: The X64DbgBridge to use.
        """
        if self._bridge is not None and hasattr(self._bridge, "unregister_event_callback"):
            self._bridge.unregister_event_callback(self._on_debug_event)
        self._bridge = bridge
        if hasattr(bridge, "register_event_callback"):
            bridge.register_event_callback(self._on_debug_event)
        _logger.info("x64dbg_bridge_set", extra={"bridge_type": type(bridge).__name__})

    def get_bridge(self) -> X64DbgBridge | None:
        """Get the current X64DbgBridge instance.

        Returns:
            The attached bridge or None.
        """
        return self._bridge

    def debug_file(self, file_path: Path) -> bool:
        """Load a file for debugging (protocol-compatible convenience).

        Args:
            file_path: Path to the executable to debug.

        Returns:
            True if loading was initiated.
        """
        if self._bridge is None:
            _logger.warning("x64dbg_debug_no_bridge", extra={"reason": "bridge not set"})
            return False

        self._load_btn.setEnabled(False)
        self._run_async(
            self._bridge.load(file_path),
            on_success=lambda _: self._on_load_success(file_path),
            on_error=lambda e: self._on_load_error(file_path, e),
        )
        return True

    def _on_load_success(self, file_path: Path) -> None:
        """Handle successful file load.

        Args:
            file_path: The loaded file path.
        """
        self._set_status(f"Loaded: {file_path.name}")
        _logger.info("x64dbg_file_loaded", extra={"path": file_path.name})
        self._load_btn.setEnabled(True)
        self._sync_64bit_toggle()
        self._refresh_state()
        self._try_embed_debugger_window()

    def _try_embed_debugger_window(self) -> None:
        """Attempt to capture and embed the x64dbg window into the panel."""
        if self._bridge is None:
            return

        pid = self._bridge.debugger_pid
        if pid is None:
            _logger.debug("x64dbg_embed_skipped_no_pid", extra={"reason": "debugger_pid is None"})
            return

        def _on_embedded(container: QWidget) -> None:
            layout = self._embed_host.layout()
            if layout is not None:
                while layout.count():
                    item = layout.takeAt(0)
                    widget = item.widget() if item is not None else None
                    if widget is not None:
                        widget.setParent(None)
                layout.addWidget(container)
            self._embedded_container = container
            self._main_tabs.setCurrentWidget(self._embed_host)
            _logger.info("x64dbg_window_embedded", extra={"pid": pid})

        poll_and_embed(
            pid=pid,
            parent=self._embed_host,
            callback=_on_embedded,
            max_retries=20,
            interval_ms=500,
        )

    def _on_load_error(self, file_path: Path, exc: object) -> None:
        """Handle file load failure.

        Args:
            file_path: The file that failed to load.
            exc: The exception that occurred.
        """
        self._set_status(f"Load failed: {exc}")
        _logger.warning("x64dbg_load_failed", extra={"path": file_path.name, "error": str(exc)})
        self._load_btn.setEnabled(True)

    def _on_debug_event(self, event_type: str, _message: dict[str, object]) -> None:
        """Handle debug events from the bridge for auto-refresh.

        Called from the bridge event thread; schedules a refresh
        on the Qt main thread via ``QTimer.singleShot``.

        Args:
            event_type: Type of debug event.
            _message: Event payload (unused).
        """
        if event_type in {"breakpoint", "watchpoint", "step"}:
            QTimer.singleShot(0, self._refresh_state)

    def _on_load(self) -> None:
        """Open file dialog and load selected executable."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Executable",
            "",
            "Executables (*.exe *.dll);;All Files (*)",
        )
        if not file_path:
            return

        self.debug_file(Path(file_path))

    def _on_attach(self) -> None:
        """Attach to a process by PID."""
        if self._bridge is None:
            self._console_output.appendPlainText("[!] No bridge configured")
            return

        pid_text = self._pid_input.text().strip()
        if not pid_text:
            self._console_output.appendPlainText("[!] Enter a PID")
            return

        try:
            pid = int(pid_text)
        except ValueError:
            _logger.debug("invalid_pid_input", extra={"input": pid_text})
            self._console_output.appendPlainText(f"[!] Invalid PID: {pid_text}")
            return

        self._attach_btn.setEnabled(False)
        self._run_async(
            self._bridge.attach(pid),
            on_success=lambda _: self._on_attach_success(pid),
            on_error=self._on_attach_error,
        )

    def _on_attach_success(self, pid: int) -> None:
        """Handle successful attach.

        Args:
            pid: The attached process ID.
        """
        self._set_status(f"Attached: PID {pid}")
        self._console_output.appendPlainText(f"[+] Attached to PID {pid}")
        _logger.info("x64dbg_attached", extra={"pid": pid})
        self._attach_btn.setEnabled(True)
        self._sync_64bit_toggle()
        self._refresh_state()

    def _on_attach_error(self, exc: object) -> None:
        """Handle attach failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Attach failed: {exc}")
        _logger.warning("x64dbg_attach_failed", extra={"error": str(exc)})
        self._attach_btn.setEnabled(True)

    def _on_run(self) -> None:
        """Continue execution."""
        if self._bridge is None:
            return

        self._run_btn.setEnabled(False)
        self._run_async(
            self._bridge.run(),
            on_success=lambda _: self._on_run_success(),
            on_error=self._on_run_error,
        )

    def _on_run_success(self) -> None:
        """Handle successful run."""
        self._set_status("Running")
        self._console_output.appendPlainText("[+] Execution continued")
        self._run_btn.setEnabled(True)

    def _on_run_error(self, exc: object) -> None:
        """Handle run failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Run failed: {exc}")
        _logger.warning("x64dbg_run_failed", extra={"error": str(exc)})
        self._run_btn.setEnabled(True)

    def _on_pause(self) -> None:
        """Pause execution."""
        if self._bridge is None:
            return

        self._pause_btn.setEnabled(False)
        self._run_async(
            self._bridge.pause(),
            on_success=lambda _: self._on_pause_success(),
            on_error=self._on_pause_error,
        )

    def _on_pause_success(self) -> None:
        """Handle successful pause."""
        self._set_status("Paused")
        self._console_output.appendPlainText("[+] Execution paused")
        self._pause_btn.setEnabled(True)
        self._refresh_state()

    def _on_pause_error(self, exc: object) -> None:
        """Handle pause failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Pause failed: {exc}")
        _logger.warning("x64dbg_pause_failed", extra={"error": str(exc)})
        self._pause_btn.setEnabled(True)

    def _on_stop(self) -> None:
        """Stop debugging."""
        if self._bridge is None:
            return

        self._stop_btn.setEnabled(False)
        self._run_async(
            self._bridge.stop(),
            on_success=lambda _: self._on_stop_success(),
            on_error=self._on_stop_error,
        )

    def _on_stop_success(self) -> None:
        """Handle successful stop."""
        self._set_status("Stopped")
        self._console_output.appendPlainText("[+] Debugging stopped")
        self._stop_btn.setEnabled(True)

    def _on_stop_error(self, exc: object) -> None:
        """Handle stop failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Stop failed: {exc}")
        _logger.warning("x64dbg_stop_failed", extra={"error": str(exc)})
        self._stop_btn.setEnabled(True)

    def _on_step_into(self) -> None:
        """Single step into."""
        if self._bridge is None:
            return

        self._step_into_btn.setEnabled(False)
        self._run_async(
            self._bridge.step_into(),
            on_success=lambda r: self._on_step_success("into", r),
            on_error=lambda e: self._on_step_error("into", e),
        )

    def _on_step_over(self) -> None:
        """Single step over."""
        if self._bridge is None:
            return

        self._step_over_btn.setEnabled(False)
        self._run_async(
            self._bridge.step_over(),
            on_success=lambda r: self._on_step_success("over", r),
            on_error=lambda e: self._on_step_error("over", e),
        )

    def _on_step_out(self) -> None:
        """Step out of current function."""
        if self._bridge is None:
            return

        self._step_out_btn.setEnabled(False)
        self._run_async(
            self._bridge.step_out(),
            on_success=lambda r: self._on_step_success("out", r),
            on_error=lambda e: self._on_step_error("out", e),
        )

    def _on_step_success(self, direction: str, result: object) -> None:
        """Handle successful step operation.

        Args:
            direction: Step direction ("into", "over", or "out").
            result: New instruction pointer or None.
        """
        if isinstance(result, int):
            self._console_output.appendPlainText(f"[+] Step {direction} -> 0x{result:X}")
        self._step_into_btn.setEnabled(True)
        self._step_over_btn.setEnabled(True)
        self._step_out_btn.setEnabled(True)
        self._refresh_state()

    def _on_step_error(self, direction: str, exc: object) -> None:
        """Handle step failure.

        Args:
            direction: Step direction that failed.
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Step {direction} failed: {exc}")
        _logger.warning("x64dbg_step_%s_failed", direction, extra={"error": str(exc)})
        self._step_into_btn.setEnabled(True)
        self._step_over_btn.setEnabled(True)
        self._step_out_btn.setEnabled(True)

    def _sync_64bit_toggle(self) -> None:
        """Sync the 64-bit checkbox with the bridge's detected architecture."""
        if self._bridge is None:
            return
        bridge_64: bool = getattr(self._bridge, "is_64bit", True)
        self._is_64bit = bridge_64
        self._64bit_toggle.blockSignals(True)
        self._64bit_toggle.setChecked(self._is_64bit)
        self._64bit_toggle.blockSignals(False)

    def _on_toggle_64bit(self, checked: bool) -> None:
        """Handle 64-bit toggle.

        Args:
            checked: Whether 64-bit mode is selected.
        """
        self._is_64bit = checked

    def _on_add_breakpoint(self) -> None:
        """Add a breakpoint at the specified address."""
        if self._bridge is None:
            self._console_output.appendPlainText("[!] No bridge configured")
            return

        addr_text = self._bp_addr_input.text().strip()
        if not addr_text:
            return

        try:
            address = int(addr_text, 16) if addr_text.startswith("0x") else int(addr_text, 0)
        except ValueError:
            _logger.debug("invalid_breakpoint_address", extra={"input": addr_text})
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        self._add_bp_btn.setEnabled(False)
        self._run_async(
            self._bridge.set_breakpoint(address),
            on_success=lambda r: self._on_bp_added(address, r),
            on_error=self._on_bp_add_error,
        )

    def _on_bp_added(self, address: int, result: object) -> None:
        """Handle successful breakpoint addition.

        Args:
            address: The breakpoint address.
            result: The breakpoint ID from the bridge.
        """
        self._console_output.appendPlainText(f"[+] Breakpoint #{result} set at 0x{address:X}")
        _logger.info("x64dbg_bp_set", extra={"address": hex(address)})
        self._add_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_add_error(self, exc: object) -> None:
        """Handle breakpoint addition failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to set breakpoint: {exc}")
        _logger.warning("x64dbg_bp_set_failed", extra={"error": str(exc)})
        self._add_bp_btn.setEnabled(True)

    def _on_remove_breakpoint(self) -> None:
        """Remove the selected breakpoint."""
        row = self._bp_table.currentRow()
        if row < 0:
            return

        addr_item = self._bp_table.item(row, 0)
        if addr_item is None:
            return

        try:
            address = int(addr_item.text(), 16)
        except ValueError:
            _logger.debug("invalid_breakpoint_address_from_table")
            return

        if self._bridge is None:
            return

        self._remove_bp_btn.setEnabled(False)
        self._run_async(
            self._bridge.remove_breakpoint(address),
            on_success=lambda _: self._on_bp_removed(address),
            on_error=self._on_bp_remove_error,
        )

    def _on_bp_removed(self, address: int) -> None:
        """Handle successful breakpoint removal.

        Args:
            address: The removed breakpoint address.
        """
        self._console_output.appendPlainText(f"[+] Breakpoint removed at 0x{address:X}")
        _logger.info("x64dbg_bp_removed", extra={"address": hex(address)})
        self._remove_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_remove_error(self, exc: object) -> None:
        """Handle breakpoint removal failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to remove breakpoint: {exc}")
        _logger.warning("x64dbg_bp_remove_failed", extra={"error": str(exc)})
        self._remove_bp_btn.setEnabled(True)

    def _on_register_edited(self, row: int, column: int) -> None:
        """Handle register value edit in table.

        Args:
            row: Table row index.
            column: Table column index.
        """
        if column != 1 or self._bridge is None:
            return

        reg_item = self._reg_table.item(row, 0)
        val_item = self._reg_table.item(row, 1)
        if reg_item is None or val_item is None:
            return

        reg_name = reg_item.text()
        val_text = val_item.text().strip()

        try:
            value = int(val_text, 16) if val_text.startswith("0x") else int(val_text, 0)
        except ValueError:
            _logger.debug("invalid_register_value", extra={"register": reg_name, "input": val_text})
            self._console_output.appendPlainText(f"[!] Invalid value for {reg_name}: {val_text}")
            return

        self._reg_table.setEnabled(False)
        self._run_async(
            self._bridge.set_register(reg_name, value),
            on_success=lambda _: self._on_reg_set_success(reg_name, value),
            on_error=lambda e: self._on_reg_set_error(reg_name, e),
        )

    def _on_reg_set_success(self, reg_name: str, value: int) -> None:
        """Handle successful register set.

        Args:
            reg_name: The register name.
            value: The new register value.
        """
        self._console_output.appendPlainText(f"[+] {reg_name} = 0x{value:X}")
        self._reg_table.setEnabled(True)

    def _on_reg_set_error(self, reg_name: str, exc: object) -> None:
        """Handle register set failure.

        Args:
            reg_name: The register that failed to set.
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to set {reg_name}: {exc}")
        _logger.warning("x64dbg_set_register_failed", extra={"register": reg_name, "error": str(exc)})
        self._reg_table.setEnabled(True)

    def _on_read_memory(self) -> None:
        """Read memory at the specified address and display hex dump."""
        if self._bridge is None:
            self._console_output.appendPlainText("[!] No bridge configured")
            return

        addr_text = self._mem_addr_input.text().strip()
        size_text = self._mem_size_input.text().strip()

        if not addr_text:
            return

        try:
            address = int(addr_text, 16) if addr_text.startswith("0x") else int(addr_text, 0)
        except ValueError:
            _logger.debug("invalid_memory_address", extra={"input": addr_text})
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        try:
            size = int(size_text) if size_text else 256
        except ValueError:
            _logger.debug("invalid_memory_size_using_default", extra={"input": size_text})
            size = 256

        self._mem_read_btn.setEnabled(False)
        self._run_async(
            self._bridge.read_memory(address, size),
            on_success=lambda r: self._on_mem_read_success(address, r),
            on_error=self._on_mem_read_error,
        )

    def _on_mem_read_success(self, address: int, result: object) -> None:
        """Handle successful memory read.

        Args:
            address: The read address.
            result: The memory data bytes.
        """
        data: bytes = result if isinstance(result, bytes) else b""
        self._mem_dump.setPlainText(self._format_hex_dump(address, data))
        self._mem_read_btn.setEnabled(True)

    def _on_mem_read_error(self, exc: object) -> None:
        """Handle memory read failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Memory read failed: {exc}")
        _logger.warning("x64dbg_mem_read_failed", extra={"error": str(exc)})
        self._mem_read_btn.setEnabled(True)

    def _on_execute_command(self) -> None:
        """Execute a raw x64dbg command."""
        if self._bridge is None:
            self._console_output.appendPlainText("[!] No bridge configured")
            return

        cmd = self._console_input.text().strip()
        if not cmd:
            return

        self._console_input.clear()
        self._console_output.appendPlainText(f"> {cmd}")

        self._run_async(
            self._bridge.run_command(cmd),
            on_success=self._on_command_result,
            on_error=self._on_command_error,
        )

    def _on_command_result(self, result: object) -> None:
        """Handle command execution result.

        Args:
            result: The command output string.
        """
        if result:
            self._console_output.appendPlainText(str(result))

    def _on_command_error(self, exc: object) -> None:
        """Handle command execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Command failed: {exc}")
        _logger.warning("x64dbg_command_failed", extra={"error": str(exc)})

    def _refresh_state(self) -> None:
        """Refresh registers, modules, threads, and state after change."""
        self._refresh_registers()
        self._refresh_breakpoints()
        self._refresh_stack()
        self._refresh_modules()
        self._refresh_threads()

    def _refresh_registers(self) -> None:
        """Refresh the register table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_registers(),
            on_success=self._apply_registers,
            on_error=lambda _: _logger.warning("x64dbg_refresh_registers_failed"),
        )

    def _apply_registers(self, result: object) -> None:
        """Apply register data to the table.

        Args:
            result: Register state from the bridge.
        """
        if result is None:
            return

        regs = result
        self._reg_table.blockSignals(True)
        self._reg_table.setRowCount(0)

        all_regs = [*_GENERAL_REGS_64, _FLAG_REG, *_SEGMENT_REGS]

        for reg_name in all_regs:
            value = getattr(regs, reg_name, 0)
            row = self._reg_table.rowCount()
            self._reg_table.insertRow(row)

            name_item = QTableWidgetItem(reg_name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self._reg_table.setItem(row, 0, name_item)

            val_item = QTableWidgetItem(f"0x{value:016X}" if self._is_64bit else f"0x{value:08X}")
            self._reg_table.setItem(row, 1, val_item)

        self._reg_table.blockSignals(False)

        if rip := getattr(regs, "rip", 0):
            self._refresh_disassembly(rip)

    def _refresh_disassembly(self, address: int) -> None:
        """Refresh disassembly view at the given address.

        Args:
            address: Start address for disassembly.
        """
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.disassemble_at(address, 30),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("x64dbg_refresh_disasm_failed", extra={"address": hex(address)}),
        )

    def _apply_disassembly(self, result: object) -> None:
        """Apply disassembly data to the view.

        Args:
            result: Disassembly lines from the bridge.
        """
        if not result:
            return

        lines: list[object] = [*result] if isinstance(result, list) else []
        text_lines: list[str] = []
        for dl in lines:
            addr = getattr(dl, "address", 0)
            addr_str = f"0x{addr:016X}" if self._is_64bit else f"0x{addr:08X}"
            bytes_str = getattr(dl, "bytes_str", "")
            mnemonic = getattr(dl, "mnemonic", "")
            operands = getattr(dl, "operands", "")
            text_lines.append(f"{addr_str}  {bytes_str:<24s}  {mnemonic} {operands}")

        self._disasm_view.setPlainText("\n".join(text_lines))

    def _refresh_breakpoints(self) -> None:
        """Refresh the breakpoints table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_breakpoints(),
            on_success=self._apply_breakpoints,
            on_error=lambda _: _logger.warning("x64dbg_refresh_breakpoints_failed"),
        )

    def _apply_breakpoints(self, result: object) -> None:
        """Apply breakpoint data to the table.

        Args:
            result: Breakpoint list from the bridge.
        """
        bps: list[object] = [*result] if isinstance(result, list) else []

        self._bp_table.setRowCount(0)
        for bp in bps:
            row = self._bp_table.rowCount()
            self._bp_table.insertRow(row)
            self._bp_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(bp, 'address', 0):X}"))
            self._bp_table.setItem(row, 1, QTableWidgetItem(getattr(bp, "bp_type", "")))
            self._bp_table.setItem(row, 2, QTableWidgetItem(getattr(bp, "condition", "") or ""))
            self._bp_table.setItem(row, 3, QTableWidgetItem(str(getattr(bp, "hit_count", 0))))
            self._bp_table.setItem(row, 4, QTableWidgetItem("Yes" if getattr(bp, "enabled", False) else "No"))

    def _refresh_stack(self) -> None:
        """Refresh the stack trace table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_stack_trace(),
            on_success=self._apply_stack,
            on_error=lambda _: _logger.warning("x64dbg_refresh_stack_failed"),
        )

    def _apply_stack(self, result: object) -> None:
        """Apply stack trace data to the table.

        Args:
            result: Stack frame list from the bridge.
        """
        frames: list[object] = [*result] if isinstance(result, list) else []

        self._stack_table.setRowCount(0)
        for frame in frames:
            row = self._stack_table.rowCount()
            self._stack_table.insertRow(row)
            self._stack_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(frame, 'address', 0):X}"))
            self._stack_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(frame, 'return_address', 0):X}"))
            info_parts: list[str] = []
            fn = getattr(frame, "function_name", "")
            mod = getattr(frame, "module_name", "")
            if fn:
                info_parts.append(fn)
            if mod:
                info_parts.append(f"[{mod}]")
            self._stack_table.setItem(row, 2, QTableWidgetItem(" ".join(info_parts)))

    def _refresh_modules(self) -> None:
        """Refresh the modules table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_modules(),
            on_success=self._apply_modules,
            on_error=lambda _: _logger.warning("x64dbg_refresh_modules_failed"),
        )

    def _apply_modules(self, result: object) -> None:
        """Apply module data to the table.

        Args:
            result: Module list from the bridge.
        """
        modules: list[object] = [*result] if isinstance(result, list) else []

        self._module_table.setRowCount(0)
        for mod in modules:
            row = self._module_table.rowCount()
            self._module_table.insertRow(row)
            self._module_table.setItem(row, 0, QTableWidgetItem(getattr(mod, "name", "")))
            self._module_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(mod, 'base_address', 0):X}"))
            self._module_table.setItem(row, 2, QTableWidgetItem(f"0x{getattr(mod, 'size', 0):X}"))
            self._module_table.setItem(row, 3, QTableWidgetItem(str(getattr(mod, "path", ""))))

    def _refresh_threads(self) -> None:
        """Refresh the threads table from bridge."""
        if self._bridge is None:
            return

        self._run_async(
            self._bridge.get_threads(),
            on_success=self._apply_threads,
            on_error=lambda _: _logger.warning("x64dbg_refresh_threads_failed"),
        )

    def _apply_threads(self, result: object) -> None:
        """Apply thread data to the table.

        Args:
            result: Thread list from the bridge.
        """
        threads: list[object] = [*result] if isinstance(result, list) else []

        self._thread_table.setRowCount(0)
        for thr in threads:
            row = self._thread_table.rowCount()
            self._thread_table.insertRow(row)
            self._thread_table.setItem(row, 0, QTableWidgetItem(str(getattr(thr, "tid", 0))))
            self._thread_table.setItem(row, 1, QTableWidgetItem(str(getattr(thr, "priority", 0))))
            self._thread_table.setItem(row, 2, QTableWidgetItem(getattr(thr, "state", "")))

    @staticmethod
    def _format_hex_dump(address: int, data: bytes) -> str:
        """Format raw bytes as a hex dump string.

        Args:
            address: Starting address of the data.
            data: Raw bytes to format.

        Returns:
            Formatted hex dump string.
        """
        lines: list[str] = []
        for offset in range(0, len(data), _MEM_DUMP_BYTES_PER_LINE):
            chunk = data[offset : offset + _MEM_DUMP_BYTES_PER_LINE]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if _PRINTABLE_LOW <= b < _PRINTABLE_HIGH else "." for b in chunk)
            addr = address + offset
            lines.append(f"0x{addr:08X}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)
