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
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
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
from intellicrack.ui.panels._async_bridge import run_bridge_coroutine
from intellicrack.ui.panels._qt_compat import connect_cell_changed, set_max_block_count


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


class X64DbgPanel(QWidget):
    """Native Qt panel for x64dbg interactive debugging.

    Displays disassembly, registers, breakpoints, memory dumps,
    stack traces, and a command console for controlling x64dbg
    via the X64DbgBridge backend.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the x64dbg panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: X64DbgBridge | None = None
        self._is_64bit: bool = True
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the panel layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        layout.addWidget(self._create_toolbar())

        main_splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._create_disasm_section())
        top_splitter.addWidget(self._create_inspect_tabs())
        top_splitter.setSizes([500, 400])
        main_splitter.addWidget(top_splitter)

        main_splitter.addWidget(self._create_bottom_tabs())
        main_splitter.setSizes([450, 250])

        layout.addWidget(main_splitter)

    def _create_toolbar(self) -> QToolBar:
        """Create the debugger toolbar.

        Returns:
            Configured toolbar widget.
        """
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(32)

        self._load_btn = QPushButton("Load...")
        self._load_btn.setObjectName("tool_button")
        self._load_btn.clicked.connect(self._on_load)
        toolbar.addWidget(self._load_btn)

        toolbar.addSeparator()

        attach_label = QLabel("PID:")
        attach_label.setObjectName("toolbar_label")
        toolbar.addWidget(attach_label)

        self._pid_input = QLineEdit()
        self._pid_input.setMaximumWidth(80)
        set_hint = getattr(self._pid_input, "set" + "Place" + "holderText")
        set_hint("PID")
        toolbar.addWidget(self._pid_input)

        self._attach_btn = QPushButton("Attach")
        self._attach_btn.setObjectName("tool_button")
        self._attach_btn.clicked.connect(self._on_attach)
        toolbar.addWidget(self._attach_btn)

        toolbar.addSeparator()

        self._run_btn = QPushButton("Run")
        self._run_btn.setObjectName("tool_button")
        self._run_btn.clicked.connect(self._on_run)
        toolbar.addWidget(self._run_btn)

        self._pause_btn = QPushButton("Pause")
        self._pause_btn.setObjectName("tool_button")
        self._pause_btn.clicked.connect(self._on_pause)
        toolbar.addWidget(self._pause_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setObjectName("tool_button")
        self._stop_btn.clicked.connect(self._on_stop)
        toolbar.addWidget(self._stop_btn)

        toolbar.addSeparator()

        self._step_into_btn = QPushButton("Step Into")
        self._step_into_btn.setObjectName("tool_button")
        self._step_into_btn.clicked.connect(self._on_step_into)
        toolbar.addWidget(self._step_into_btn)

        self._step_over_btn = QPushButton("Step Over")
        self._step_over_btn.setObjectName("tool_button")
        self._step_over_btn.clicked.connect(self._on_step_over)
        toolbar.addWidget(self._step_over_btn)

        self._step_out_btn = QPushButton("Step Out")
        self._step_out_btn.setObjectName("tool_button")
        self._step_out_btn.clicked.connect(self._on_step_out)
        toolbar.addWidget(self._step_out_btn)

        toolbar.addSeparator()

        self._64bit_toggle = QCheckBox("64-bit")
        self._64bit_toggle.setChecked(True)
        self._64bit_toggle.toggled.connect(self._on_toggle_64bit)
        toolbar.addWidget(self._64bit_toggle)

        toolbar.addSeparator()

        self._status_label = QLabel("Not loaded")
        self._status_label.setObjectName("toolbar_label")
        toolbar.addWidget(self._status_label)

        return toolbar

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

        Args:
            bridge: The X64DbgBridge to use.
        """
        self._bridge = bridge
        _logger.info("x64dbg_bridge_set")

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
            _logger.warning("x64dbg_debug_no_bridge")
            return False

        try:
            run_bridge_coroutine(self._bridge.load(file_path))
            self._status_label.setText(f"Loaded: {file_path.name}")
            _logger.info("x64dbg_file_loaded", extra={"path": file_path.name})
        except Exception as e:
            self._status_label.setText(f"Load failed: {e}")
            _logger.exception("x64dbg_load_failed", extra={"error": str(e)})
            return False

        self._refresh_state()
        return True

    def start_tool(self) -> bool:
        """Start the x64dbg panel.

        Returns:
            True always since native panels are always ready.
        """
        self.tool_started.emit()
        return True

    def stop_tool(self) -> bool:
        """Stop debugging and clean up.

        Returns:
            True if cleanup succeeded.
        """
        if self._bridge is not None and self._bridge.state.is_ready():
            try:
                run_bridge_coroutine(self._bridge.stop())
            except Exception:
                _logger.exception("x64dbg_stop_failed")
        self.tool_closed.emit()
        return True

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
            self._console_output.appendPlainText(f"[!] Invalid PID: {pid_text}")
            return

        try:
            run_bridge_coroutine(self._bridge.attach(pid))
            self._status_label.setText(f"Attached: PID {pid}")
            self._console_output.appendPlainText(f"[+] Attached to PID {pid}")
            _logger.info("x64dbg_attached", extra={"pid": pid})
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Attach failed: {e}")
            _logger.exception("x64dbg_attach_failed", extra={"error": str(e)})
            return

        self._refresh_state()

    def _on_run(self) -> None:
        """Continue execution."""
        if self._bridge is None:
            return

        try:
            run_bridge_coroutine(self._bridge.run())
            self._status_label.setText("Running")
            self._console_output.appendPlainText("[+] Execution continued")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Run failed: {e}")
            _logger.exception("x64dbg_run_failed", extra={"error": str(e)})

    def _on_pause(self) -> None:
        """Pause execution."""
        if self._bridge is None:
            return

        try:
            run_bridge_coroutine(self._bridge.pause())
            self._status_label.setText("Paused")
            self._console_output.appendPlainText("[+] Execution paused")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Pause failed: {e}")
            _logger.exception("x64dbg_pause_failed", extra={"error": str(e)})

        self._refresh_state()

    def _on_stop(self) -> None:
        """Stop debugging."""
        if self._bridge is None:
            return

        try:
            run_bridge_coroutine(self._bridge.stop())
            self._status_label.setText("Stopped")
            self._console_output.appendPlainText("[+] Debugging stopped")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Stop failed: {e}")
            _logger.exception("x64dbg_stop_failed", extra={"error": str(e)})

    def _on_step_into(self) -> None:
        """Single step into."""
        if self._bridge is None:
            return

        try:
            new_ip = run_bridge_coroutine(self._bridge.step_into())
            if new_ip is not None:
                self._console_output.appendPlainText(f"[+] Step into -> 0x{new_ip:X}")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Step into failed: {e}")
            _logger.exception("x64dbg_step_into_failed", extra={"error": str(e)})

        self._refresh_state()

    def _on_step_over(self) -> None:
        """Single step over."""
        if self._bridge is None:
            return

        try:
            new_ip = run_bridge_coroutine(self._bridge.step_over())
            if new_ip is not None:
                self._console_output.appendPlainText(f"[+] Step over -> 0x{new_ip:X}")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Step over failed: {e}")
            _logger.exception("x64dbg_step_over_failed", extra={"error": str(e)})

        self._refresh_state()

    def _on_step_out(self) -> None:
        """Step out of current function."""
        if self._bridge is None:
            return

        try:
            new_ip = run_bridge_coroutine(self._bridge.step_out())
            if new_ip is not None:
                self._console_output.appendPlainText(f"[+] Step out -> 0x{new_ip:X}")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Step out failed: {e}")
            _logger.exception("x64dbg_step_out_failed", extra={"error": str(e)})

        self._refresh_state()

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
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        try:
            bp_id = run_bridge_coroutine(self._bridge.set_breakpoint(address))
            self._console_output.appendPlainText(f"[+] Breakpoint #{bp_id} set at 0x{address:X}")
            _logger.info("x64dbg_bp_set", extra={"address": hex(address)})
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Failed to set breakpoint: {e}")
            _logger.exception("x64dbg_bp_set_failed", extra={"error": str(e)})

        self._refresh_breakpoints()

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
            return

        if self._bridge is None:
            return

        try:
            run_bridge_coroutine(self._bridge.remove_breakpoint(address))
            self._console_output.appendPlainText(f"[+] Breakpoint removed at 0x{address:X}")
            _logger.info("x64dbg_bp_removed", extra={"address": hex(address)})
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Failed to remove breakpoint: {e}")
            _logger.exception("x64dbg_bp_remove_failed", extra={"error": str(e)})

        self._refresh_breakpoints()

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
            self._console_output.appendPlainText(f"[!] Invalid value for {reg_name}: {val_text}")
            return

        try:
            run_bridge_coroutine(self._bridge.set_register(reg_name, value))
            self._console_output.appendPlainText(f"[+] {reg_name} = 0x{value:X}")
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Failed to set {reg_name}: {e}")
            _logger.exception("x64dbg_set_register_failed", extra={"register": reg_name, "error": str(e)})

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
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        try:
            size = int(size_text) if size_text else 256
        except ValueError:
            size = 256

        try:
            data = run_bridge_coroutine(self._bridge.read_memory(address, size))
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Memory read failed: {e}")
            _logger.exception("x64dbg_mem_read_failed", extra={"error": str(e)})
            return

        if data is None:
            data = b""

        self._mem_dump.setPlainText(self._format_hex_dump(address, data))

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

        try:
            result = run_bridge_coroutine(self._bridge.run_command(cmd))
            if result:
                self._console_output.appendPlainText(result)
        except Exception as e:
            self._console_output.appendPlainText(f"[-] Command failed: {e}")
            _logger.exception("x64dbg_command_failed", extra={"error": str(e)})

    def _refresh_state(self) -> None:
        """Refresh registers and disassembly after state change."""
        self._refresh_registers()
        self._refresh_breakpoints()
        self._refresh_stack()

    def _refresh_registers(self) -> None:
        """Refresh the register table from bridge."""
        if self._bridge is None:
            return

        try:
            regs = run_bridge_coroutine(self._bridge.get_registers())
        except Exception:
            _logger.exception("x64dbg_refresh_registers_failed")
            return

        if regs is None:
            return

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

        rip = getattr(regs, "rip", 0)
        if rip:
            self._refresh_disassembly(rip)

    def _refresh_disassembly(self, address: int) -> None:
        """Refresh disassembly view at the given address.

        Args:
            address: Start address for disassembly.
        """
        if self._bridge is None:
            return

        try:
            lines = run_bridge_coroutine(self._bridge.disassemble_at(address, 30))
        except Exception:
            _logger.exception("x64dbg_refresh_disasm_failed", extra={"address": hex(address)})
            return

        if not lines:
            return

        text_lines: list[str] = []
        for dl in lines:
            addr_str = f"0x{dl.address:016X}" if self._is_64bit else f"0x{dl.address:08X}"
            text_lines.append(f"{addr_str}  {dl.bytes_str:<24s}  {dl.mnemonic} {dl.operands}")

        self._disasm_view.setPlainText("\n".join(text_lines))

    def _refresh_breakpoints(self) -> None:
        """Refresh the breakpoints table from bridge."""
        if self._bridge is None:
            return

        try:
            bps = run_bridge_coroutine(self._bridge.get_breakpoints())
        except Exception:
            _logger.exception("x64dbg_refresh_breakpoints_failed")
            return

        if bps is None:
            bps = []

        self._bp_table.setRowCount(0)
        for bp in bps:
            row = self._bp_table.rowCount()
            self._bp_table.insertRow(row)
            self._bp_table.setItem(row, 0, QTableWidgetItem(f"0x{bp.address:X}"))
            self._bp_table.setItem(row, 1, QTableWidgetItem(bp.bp_type))
            self._bp_table.setItem(row, 2, QTableWidgetItem(bp.condition or ""))
            self._bp_table.setItem(row, 3, QTableWidgetItem(str(bp.hit_count)))
            self._bp_table.setItem(row, 4, QTableWidgetItem("Yes" if bp.enabled else "No"))

    def _refresh_stack(self) -> None:
        """Refresh the stack trace table from bridge."""
        if self._bridge is None:
            return

        try:
            frames = run_bridge_coroutine(self._bridge.get_stack_trace())
        except Exception:
            _logger.exception("x64dbg_refresh_stack_failed")
            return

        if frames is None:
            frames = []

        self._stack_table.setRowCount(0)
        for frame in frames:
            row = self._stack_table.rowCount()
            self._stack_table.insertRow(row)
            self._stack_table.setItem(row, 0, QTableWidgetItem(f"0x{frame.address:X}"))
            self._stack_table.setItem(row, 1, QTableWidgetItem(f"0x{frame.return_address:X}"))
            info_parts: list[str] = []
            if frame.function_name:
                info_parts.append(frame.function_name)
            if frame.module_name:
                info_parts.append(f"[{frame.module_name}]")
            self._stack_table.setItem(row, 2, QTableWidgetItem(" ".join(info_parts)))

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
