# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Debugger tab widget for the Cutter/Rizin analysis panel.

Provides a self-contained Qt widget exposing every native rizin debugger operation (attach/detach, breakpoints, stepping, continue,
registers, memory read/write, memory regions, threads, and loaded modules) driven by the ``CutterBridge`` debug surface
(``cutter.py:4029-4551``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QSignalBlocker, Qt
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
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui._hex_format import format_hex_dump
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.qt_compat import connect_cell_changed, set_max_block_count
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160
_SIZE_INPUT_MAX_WIDTH: Final[int] = 80
_TOP_SPLIT_LEFT: Final[int] = 500
_TOP_SPLIT_RIGHT: Final[int] = 400

_REG_COLUMNS: Final[list[str]] = ["Register", "Value"]
_BP_COLUMNS: Final[list[str]] = ["Address", "Type", "Condition", "Hits", "Enabled"]
_MEMORY_REGION_COLUMNS: Final[list[str]] = ["Base", "Size", "Protection", "State", "Type", "Module"]
_THREAD_COLUMNS: Final[list[str]] = ["TID", "Start", "PC", "State"]
_MODULE_COLUMNS: Final[list[str]] = ["Name", "Base", "Size", "Entry Point", "Path"]

_GENERAL_REGS: Final[list[str]] = [
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
_FLAG_REG: Final[str] = "rflags"
_SEGMENT_REGS: Final[list[str]] = ["cs", "ds", "es", "fs", "gs", "ss"]

_DEFAULT_MEMORY_READ_SIZE: Final[int] = 256


def _parse_address(text: str) -> int | None:
    """Parse an address string in hex (``0x``/``0X`` prefix) or decimal form.

    Args:
        text: User-supplied address string.

    Returns:
        int | None: The parsed integer address, or ``None`` on invalid input.
    """
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return int(stripped, 16) if stripped.lower().startswith("0x") else int(stripped)
    except ValueError:
        return None


class DebuggerTab(QWidget):
    """Tab exposing the full native rizin debugger session against an attached process.

    Provides attach/detach, breakpoint management, stepping/continue execution control, register inspection and editing, memory read/write,
    memory-region enumeration, and thread/module listings, all driven by the ``CutterBridge`` debug methods.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the DebuggerTab with all debugger sub-views and controls.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        attach_row = QHBoxLayout()
        attach_label = QLabel(self.tr("PID:"))
        attach_label.setFont(fm.get_ui_font(9))
        attach_row.addWidget(attach_label)
        self._pid_input = QLineEdit()
        self._pid_input.setMaximumWidth(_SIZE_INPUT_MAX_WIDTH)
        attach_row.addWidget(self._pid_input)
        self._attach_btn = QPushButton(self.tr("Attach"))
        self._attach_btn.setObjectName("tool_button")
        self._attach_btn.clicked.connect(self._on_attach)
        attach_row.addWidget(self._attach_btn)
        self._detach_btn = QPushButton(self.tr("Detach"))
        self._detach_btn.setObjectName("tool_button")
        self._detach_btn.clicked.connect(self._on_detach)
        attach_row.addWidget(self._detach_btn)

        attach_row.addSpacing(16)
        self._step_into_btn = QPushButton(self.tr("Step Into"))
        self._step_into_btn.setObjectName("tool_button")
        self._step_into_btn.clicked.connect(self._on_step_into)
        attach_row.addWidget(self._step_into_btn)
        self._step_over_btn = QPushButton(self.tr("Step Over"))
        self._step_over_btn.setObjectName("tool_button")
        self._step_over_btn.clicked.connect(self._on_step_over)
        attach_row.addWidget(self._step_over_btn)
        self._continue_btn = QPushButton(self.tr("Continue"))
        self._continue_btn.setObjectName("tool_button")
        self._continue_btn.clicked.connect(self._on_continue)
        attach_row.addWidget(self._continue_btn)
        self._refresh_btn = QPushButton(self.tr("Refresh"))
        self._refresh_btn.setObjectName("secondary_button")
        self._refresh_btn.clicked.connect(self._refresh_all)
        attach_row.addWidget(self._refresh_btn)
        attach_row.addStretch()

        self._status_label = QLabel(self.tr("Not attached"))
        self._status_label.setFont(fm.get_ui_font(9))
        attach_row.addWidget(self._status_label)
        layout.addLayout(attach_row)

        top_split = QSplitter(Qt.Orientation.Horizontal)
        top_split.setChildrenCollapsible(False)
        top_split.addWidget(self._create_registers_group())
        top_split.addWidget(self._create_bottom_tabs())
        top_split.setSizes([_TOP_SPLIT_LEFT, _TOP_SPLIT_RIGHT])
        layout.addWidget(top_split)

    def _create_registers_group(self) -> QWidget:
        """Create the registers table with an editable value column.

        Returns:
            QWidget: Container widget with the register table.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        reg_label = QLabel(self.tr("Registers"))
        reg_label.setFont(FontManager.get_instance().get_ui_font_bold(9))
        vlayout.addWidget(reg_label)

        self._reg_table = QTableWidget(0, len(_REG_COLUMNS))
        self._reg_table.setHorizontalHeaderLabels(_REG_COLUMNS)
        self._reg_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._reg_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        reg_h = self._reg_table.horizontalHeader()
        if reg_h is not None:
            reg_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        connect_cell_changed(self._reg_table, self._on_register_edited)
        vlayout.addWidget(self._reg_table)
        return container

    def _create_bottom_tabs(self) -> QTabWidget:
        """Create breakpoints, memory, memory-regions, threads, and modules sub-tabs.

        Returns:
            QTabWidget: Tab widget with the debugger detail views.
        """
        tabs = QTabWidget()
        tabs.addTab(self._build_bp_tab(), self.tr("Breakpoints"))
        tabs.addTab(self._build_memory_tab(), self.tr("Memory"))
        tabs.addTab(self._build_regions_tab(), self.tr("Memory Regions"))
        tabs.addTab(self._build_threads_tab(), self.tr("Threads"))
        tabs.addTab(self._build_modules_tab(), self.tr("Modules"))
        return tabs

    def _build_bp_tab(self) -> QWidget:
        """Build the breakpoints sub-tab with add/remove controls.

        Returns:
            QWidget: Breakpoints tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        vlayout.setSpacing(_PANEL_SPACING)

        toolbar = QHBoxLayout()
        addr_label = QLabel(self.tr("Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(addr_label)
        self._bp_addr_input = QLineEdit()
        self._bp_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._bp_addr_input.setPlaceholderText("0x...")
        toolbar.addWidget(self._bp_addr_input)

        type_label = QLabel(self.tr("Type:"))
        type_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(type_label)
        self._bp_type_combo = QComboBox()
        self._bp_type_combo.addItems(["software", "hardware", "memory"])
        toolbar.addWidget(self._bp_type_combo)

        cond_label = QLabel(self.tr("Condition:"))
        cond_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(cond_label)
        self._bp_cond_input = QLineEdit()
        self._bp_cond_input.setPlaceholderText("optional expression")
        toolbar.addWidget(self._bp_cond_input)

        self._add_bp_btn = QPushButton(self.tr("Add"))
        self._add_bp_btn.setObjectName("tool_button")
        self._add_bp_btn.clicked.connect(self._on_add_breakpoint)
        toolbar.addWidget(self._add_bp_btn)

        self._remove_bp_btn = QPushButton(self.tr("Remove"))
        self._remove_bp_btn.setObjectName("tool_button")
        self._remove_bp_btn.clicked.connect(self._on_remove_breakpoint)
        toolbar.addWidget(self._remove_bp_btn)
        toolbar.addStretch()
        vlayout.addLayout(toolbar)

        self._bp_table = QTableWidget(0, len(_BP_COLUMNS))
        self._bp_table.setHorizontalHeaderLabels(_BP_COLUMNS)
        self._bp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._bp_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        bp_h = self._bp_table.horizontalHeader()
        if bp_h is not None:
            bp_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        vlayout.addWidget(self._bp_table)
        return container

    def _build_memory_tab(self) -> QWidget:
        """Build the memory read/write sub-tab.

        Returns:
            QWidget: Memory tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        vlayout.setSpacing(_PANEL_SPACING)

        toolbar = QHBoxLayout()
        addr_label = QLabel(self.tr("Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(addr_label)
        self._mem_addr_input = QLineEdit()
        self._mem_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._mem_addr_input.setPlaceholderText("0x...")
        toolbar.addWidget(self._mem_addr_input)

        size_label = QLabel(self.tr("Size:"))
        size_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(size_label)
        self._mem_size_input = QLineEdit(str(_DEFAULT_MEMORY_READ_SIZE))
        self._mem_size_input.setMaximumWidth(_SIZE_INPUT_MAX_WIDTH)
        toolbar.addWidget(self._mem_size_input)

        self._mem_read_btn = QPushButton(self.tr("Read"))
        self._mem_read_btn.setObjectName("tool_button")
        self._mem_read_btn.clicked.connect(self._on_read_memory)
        toolbar.addWidget(self._mem_read_btn)

        self._mem_write_input = QLineEdit()
        self._mem_write_input.setPlaceholderText("Hex bytes to write (e.g. 90909090)")
        toolbar.addWidget(self._mem_write_input)

        self._mem_write_btn = QPushButton(self.tr("Write"))
        self._mem_write_btn.setObjectName("tool_button")
        self._mem_write_btn.clicked.connect(self._on_write_memory)
        toolbar.addWidget(self._mem_write_btn)
        toolbar.addStretch()
        vlayout.addLayout(toolbar)

        self._mem_dump = QPlainTextEdit()
        self._mem_dump.setFont(fm.get_code_font(9))
        self._mem_dump.setReadOnly(True)
        set_max_block_count(self._mem_dump, 10000)
        vlayout.addWidget(self._mem_dump)
        return container

    def _build_regions_tab(self) -> QWidget:
        """Build the memory-regions enumeration sub-tab.

        Returns:
            QWidget: Memory regions tab container.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._regions_table = QTableWidget(0, len(_MEMORY_REGION_COLUMNS))
        self._regions_table.setHorizontalHeaderLabels(_MEMORY_REGION_COLUMNS)
        self._regions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._regions_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        regions_h = self._regions_table.horizontalHeader()
        if regions_h is not None:
            regions_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        vlayout.addWidget(self._regions_table)
        return container

    def _build_threads_tab(self) -> QWidget:
        """Build the threads enumeration sub-tab.

        Returns:
            QWidget: Threads tab container.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._threads_table = QTableWidget(0, len(_THREAD_COLUMNS))
        self._threads_table.setHorizontalHeaderLabels(_THREAD_COLUMNS)
        self._threads_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._threads_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        threads_h = self._threads_table.horizontalHeader()
        if threads_h is not None:
            threads_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        vlayout.addWidget(self._threads_table)
        return container

    def _build_modules_tab(self) -> QWidget:
        """Build the loaded-modules enumeration sub-tab.

        Returns:
            QWidget: Modules tab container.
        """
        container = QWidget()
        vlayout = QVBoxLayout(container)
        vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._modules_table = QTableWidget(0, len(_MODULE_COLUMNS))
        self._modules_table.setHorizontalHeaderLabels(_MODULE_COLUMNS)
        self._modules_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._modules_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        modules_h = self._modules_table.horizontalHeader()
        if modules_h is not None:
            modules_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        vlayout.addWidget(self._modules_table)
        return container

    def set_bridge(self, bridge: CutterBridge) -> None:
        """Set the CutterBridge instance used for debugger operations.

        Args:
            bridge: The CutterBridge to use.
        """
        self._bridge = bridge

    def _on_attach(self) -> None:
        """Attach the debugger to the process identifier in the PID input."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return
        pid_text = self._pid_input.text().strip()
        if not pid_text:
            return
        try:
            pid = int(pid_text)
        except ValueError:
            _logger.warning("cutter_debugger_invalid_pid", input_text=pid_text)
            self._status_label.setText(self.tr("Invalid PID"))
            return

        self._attach_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.attach(pid),
            on_success=lambda _: self._on_attach_success(pid),
            on_error=self._on_attach_error,
            parent=self,
            event="cutter_debug_attach",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_attach_success(self, pid: int) -> None:
        """Handle successful debugger attach.

        Args:
            pid: The process identifier that was attached to.
        """
        self._status_label.setText(f"Attached to PID {pid}")
        _logger.info("cutter_debug_attached", pid=pid)
        self._attach_btn.setEnabled(True)
        self._refresh_all()

    def _on_attach_error(self, exc: object) -> None:
        """Handle debugger attach failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Attach failed: {exc}")
        _logger.warning("cutter_debug_attach_failed", error=str(exc))
        self._attach_btn.setEnabled(True)

    def _on_detach(self) -> None:
        """Detach the debugger from the currently attached process."""
        if self._bridge is None:
            return
        self._detach_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.detach(),
            on_success=lambda _: self._on_detach_success(),
            on_error=self._on_detach_error,
            parent=self,
            event="cutter_debug_detach",
            logger=_logger,
            level="info",
        )

    def _on_detach_success(self) -> None:
        """Handle successful debugger detach by clearing all views."""
        self._status_label.setText(self.tr("Not attached"))
        _logger.info("cutter_debug_detached")
        self._detach_btn.setEnabled(True)
        self._reg_table.setRowCount(0)
        self._bp_table.setRowCount(0)
        self._regions_table.setRowCount(0)
        self._threads_table.setRowCount(0)
        self._modules_table.setRowCount(0)
        self._mem_dump.clear()

    def _on_detach_error(self, exc: object) -> None:
        """Handle debugger detach failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Detach failed: {exc}")
        _logger.warning("cutter_debug_detach_failed", error=str(exc))
        self._detach_btn.setEnabled(True)

    def _on_step_into(self) -> None:
        """Single-step into the next instruction."""
        if self._bridge is None:
            return
        self._step_into_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.step_into(),
            on_success=self._on_step_complete,
            on_error=self._on_step_error,
            parent=self,
            event="cutter_debug_step_into",
            logger=_logger,
        )

    def _on_step_over(self) -> None:
        """Single-step over the next instruction."""
        if self._bridge is None:
            return
        self._step_over_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.step_over(),
            on_success=self._on_step_complete,
            on_error=self._on_step_error,
            parent=self,
            event="cutter_debug_step_over",
            logger=_logger,
        )

    def _on_step_complete(self, result: object) -> None:
        """Handle successful step completion by refreshing debugger state.

        Args:
            result: New instruction pointer returned by the bridge.
        """
        self._step_into_btn.setEnabled(True)
        self._step_over_btn.setEnabled(True)
        if isinstance(result, int):
            self._status_label.setText(f"PC = 0x{result:X}")
        self._refresh_all()

    def _on_step_error(self, exc: object) -> None:
        """Handle step execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Step failed: {exc}")
        _logger.warning("cutter_debug_step_failed", error=str(exc))
        self._step_into_btn.setEnabled(True)
        self._step_over_btn.setEnabled(True)

    def _on_continue(self) -> None:
        """Continue debugger execution until the next event."""
        if self._bridge is None:
            return
        self._continue_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.run(),
            on_success=lambda _: self._on_continue_success(),
            on_error=self._on_continue_error,
            parent=self,
            event="cutter_debug_run",
            logger=_logger,
            level="info",
        )

    def _on_continue_success(self) -> None:
        """Handle successful continue by refreshing debugger state."""
        self._status_label.setText(self.tr("Stopped"))
        self._continue_btn.setEnabled(True)
        self._refresh_all()

    def _on_continue_error(self, exc: object) -> None:
        """Handle continue-execution failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Continue failed: {exc}")
        _logger.warning("cutter_debug_run_failed", error=str(exc))
        self._continue_btn.setEnabled(True)

    def _on_register_edited(self, row: int, column: int) -> None:
        """Handle in-place register value edits by writing the new value to the debuggee.

        Args:
            row: Edited table row index.
            column: Edited table column index.
        """
        if column != 1 or self._bridge is None:
            return
        reg_item = self._reg_table.item(row, 0)
        val_item = self._reg_table.item(row, 1)
        if reg_item is None or val_item is None:
            return
        reg_name = reg_item.text()
        val_text = val_item.text().strip()
        value = _parse_address(val_text)
        if value is None:
            _logger.warning("cutter_debug_invalid_register_value", register=reg_name, input_text=val_text)
            self._status_label.setText(f"Invalid value for {reg_name}: {val_text}")
            return

        self._reg_table.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_register(reg_name, value),
            on_success=lambda _: self._on_reg_set_success(reg_name, value),
            on_error=lambda e: self._on_reg_set_error(reg_name, e),
            parent=self,
            event="cutter_debug_set_register",
            logger=_logger,
            level="info",
            register=reg_name,
            value=hex(value),
        )

    def _on_reg_set_success(self, reg_name: str, value: int) -> None:
        """Handle successful register set.

        Args:
            reg_name: The register name that was updated.
            value: The new register value.
        """
        self._status_label.setText(f"{reg_name} = 0x{value:X}")
        self._reg_table.setEnabled(True)

    def _on_reg_set_error(self, reg_name: str, exc: object) -> None:
        """Handle register set failure.

        Args:
            reg_name: The register that failed to update.
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Failed to set {reg_name}: {exc}")
        _logger.warning("cutter_debug_set_register_failed", register=reg_name, error=str(exc))
        self._reg_table.setEnabled(True)

    def _on_add_breakpoint(self) -> None:
        """Set a breakpoint at the address in the breakpoint address input."""
        if self._bridge is None:
            return
        address = _parse_address(self._bp_addr_input.text())
        if address is None:
            self._status_label.setText(self.tr("Invalid breakpoint address"))
            return
        bp_type = self._bp_type_combo.currentText()
        condition = self._bp_cond_input.text().strip() or None

        self._add_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_breakpoint(address, bp_type, condition),
            on_success=lambda _: self._on_bp_added(),
            on_error=self._on_bp_error,
            parent=self,
            event="cutter_debug_set_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
            bp_type=bp_type,
        )

    def _on_bp_added(self) -> None:
        """Handle successful breakpoint creation by refreshing the breakpoint table."""
        self._add_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_remove_breakpoint(self) -> None:
        """Remove the breakpoint at the address in the breakpoint address input."""
        if self._bridge is None:
            return
        address = _parse_address(self._bp_addr_input.text())
        if address is None:
            self._status_label.setText(self.tr("Invalid breakpoint address"))
            return

        self._remove_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.remove_breakpoint(address),
            on_success=lambda _: self._on_bp_removed(),
            on_error=self._on_bp_error,
            parent=self,
            event="cutter_debug_remove_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_bp_removed(self) -> None:
        """Handle successful breakpoint removal by refreshing the breakpoint table."""
        self._remove_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_error(self, exc: object) -> None:
        """Handle breakpoint add/remove failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Breakpoint operation failed: {exc}")
        _logger.warning("cutter_debug_breakpoint_failed", error=str(exc))
        self._add_bp_btn.setEnabled(True)
        self._remove_bp_btn.setEnabled(True)

    def _on_read_memory(self) -> None:
        """Read memory at the specified address and render it as a hex dump."""
        if self._bridge is None:
            return
        address = _parse_address(self._mem_addr_input.text())
        if address is None:
            self._mem_dump.setPlainText("[error] Invalid address")
            return
        size_text = self._mem_size_input.text().strip()
        try:
            size = int(size_text) if size_text else _DEFAULT_MEMORY_READ_SIZE
        except ValueError:
            _logger.warning("cutter_debug_invalid_memory_size", input_text=size_text)
            size = _DEFAULT_MEMORY_READ_SIZE

        self._mem_read_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.read_memory(address, size),
            on_success=lambda r: self._on_memory_read(address, r),
            on_error=self._on_memory_error,
            parent=self,
            event="cutter_debug_read_memory",
            logger=_logger,
            address=hex(address),
            size=size,
        )

    def _on_memory_read(self, address: int, result: object) -> None:
        """Display the bytes read from process memory as a hex dump.

        Args:
            address: The address that was read from.
            result: The bytes returned by the bridge.
        """
        data = result if isinstance(result, bytes) else b""
        self._mem_dump.setPlainText(format_hex_dump(data, address, address_prefix="0x"))
        self._mem_read_btn.setEnabled(True)

    def _on_write_memory(self) -> None:
        """Write hex-encoded bytes from the write input to process memory."""
        if self._bridge is None:
            return
        address = _parse_address(self._mem_addr_input.text())
        if address is None:
            self._mem_dump.setPlainText("[error] Invalid address")
            return
        hex_text = self._mem_write_input.text().strip().replace(" ", "")
        if not hex_text:
            return
        try:
            data = bytes.fromhex(hex_text)
        except ValueError:
            _logger.warning("cutter_debug_invalid_write_hex", input_text=hex_text)
            self._mem_dump.setPlainText("[error] Invalid hex data")
            return

        self._mem_write_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.write_memory(address, data),
            on_success=lambda r: self._on_memory_write_success(address, r),
            on_error=self._on_memory_error,
            parent=self,
            event="cutter_debug_write_memory",
            logger=_logger,
            level="info",
            address=hex(address),
            byte_count=len(data),
        )

    def _on_memory_write_success(self, address: int, result: object) -> None:
        """Handle successful memory write and re-read the modified region.

        Args:
            address: The address that was written to.
            result: Number of bytes written returned by the bridge.
        """
        written = result if isinstance(result, int) else 0
        self._status_label.setText(f"Wrote {written} bytes @ 0x{address:X}")
        self._mem_write_btn.setEnabled(True)
        self._on_read_memory()

    def _on_memory_error(self, exc: object) -> None:
        """Handle memory read/write failure.

        Args:
            exc: The exception that occurred.
        """
        self._mem_dump.setPlainText(f"[error] {exc}")
        _logger.warning("cutter_debug_memory_op_failed", error=str(exc))
        self._mem_read_btn.setEnabled(True)
        self._mem_write_btn.setEnabled(True)

    def _refresh_all(self) -> None:
        """Refresh registers, breakpoints, memory regions, threads, and modules."""
        self._refresh_registers()
        self._refresh_breakpoints()
        self._refresh_regions()
        self._refresh_threads()
        self._refresh_modules()

    def _refresh_registers(self) -> None:
        """Refresh the register table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_registers(),
            on_success=self._apply_registers,
            on_error=lambda e: _logger.warning("cutter_debug_get_registers_failed", error=str(e)),
            parent=self,
            event="cutter_debug_get_registers",
            logger=_logger,
        )

    def _apply_registers(self, result: object) -> None:
        """Populate the register table with a RegisterState from the bridge.

        Args:
            result: RegisterState instance returned by the bridge.
        """
        if result is None:
            return
        with QSignalBlocker(self._reg_table):
            self._reg_table.setRowCount(0)
            all_regs = [*_GENERAL_REGS, _FLAG_REG, *_SEGMENT_REGS]
            for reg_name in all_regs:
                value = getattr(result, reg_name, 0)
                row = self._reg_table.rowCount()
                self._reg_table.insertRow(row)
                name_item = QTableWidgetItem(reg_name)
                name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self._reg_table.setItem(row, 0, name_item)
                self._reg_table.setItem(row, 1, QTableWidgetItem(f"0x{value:X}"))

    def _refresh_breakpoints(self) -> None:
        """Refresh the breakpoints table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_breakpoints(),
            on_success=self._apply_breakpoints,
            on_error=lambda e: _logger.warning("cutter_debug_get_breakpoints_failed", error=str(e)),
            parent=self,
            event="cutter_debug_get_breakpoints",
            logger=_logger,
        )

    def _apply_breakpoints(self, result: object) -> None:
        """Populate the breakpoints table.

        Args:
            result: List of BreakpointInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._bp_table.setRowCount(0)
        for bp in items:
            row = self._bp_table.rowCount()
            self._bp_table.insertRow(row)
            self._bp_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(bp, 'address', 0):X}"))
            self._bp_table.setItem(row, 1, QTableWidgetItem(getattr(bp, "bp_type", "")))
            self._bp_table.setItem(row, 2, QTableWidgetItem(getattr(bp, "condition", "") or ""))
            self._bp_table.setItem(row, 3, QTableWidgetItem(str(getattr(bp, "hit_count", 0))))
            self._bp_table.setItem(row, 4, QTableWidgetItem(str(getattr(bp, "enabled", True))))

    def _refresh_regions(self) -> None:
        """Refresh the memory regions table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_memory_regions(),
            on_success=self._apply_regions,
            on_error=lambda e: _logger.warning("cutter_debug_get_memory_regions_failed", error=str(e)),
            parent=self,
            event="cutter_debug_get_memory_regions",
            logger=_logger,
        )

    def _apply_regions(self, result: object) -> None:
        """Populate the memory regions table.

        Args:
            result: List of MemoryRegion from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._regions_table.setRowCount(0)
        for region in items:
            row = self._regions_table.rowCount()
            self._regions_table.insertRow(row)
            self._regions_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(region, 'base_address', 0):X}"))
            self._regions_table.setItem(row, 1, QTableWidgetItem(str(getattr(region, "size", 0))))
            self._regions_table.setItem(row, 2, QTableWidgetItem(getattr(region, "protection", "")))
            self._regions_table.setItem(row, 3, QTableWidgetItem(getattr(region, "state", "")))
            self._regions_table.setItem(row, 4, QTableWidgetItem(getattr(region, "type", "")))
            self._regions_table.setItem(row, 5, QTableWidgetItem(getattr(region, "module_name", "") or ""))

    def _refresh_threads(self) -> None:
        """Refresh the threads table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_threads(),
            on_success=self._apply_threads,
            on_error=lambda e: _logger.warning("cutter_debug_get_threads_failed", error=str(e)),
            parent=self,
            event="cutter_debug_get_threads",
            logger=_logger,
        )

    def _apply_threads(self, result: object) -> None:
        """Populate the threads table.

        Args:
            result: List of ThreadInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._threads_table.setRowCount(0)
        for th in items:
            row = self._threads_table.rowCount()
            self._threads_table.insertRow(row)
            self._threads_table.setItem(row, 0, QTableWidgetItem(str(getattr(th, "tid", 0))))
            self._threads_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(th, 'start_address', 0):X}"))
            self._threads_table.setItem(row, 2, QTableWidgetItem(f"0x{getattr(th, 'current_pc', 0):X}"))
            self._threads_table.setItem(row, 3, QTableWidgetItem(getattr(th, "state", "")))

    def _refresh_modules(self) -> None:
        """Refresh the loaded-modules table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_modules(),
            on_success=self._apply_modules,
            on_error=lambda e: _logger.warning("cutter_debug_get_modules_failed", error=str(e)),
            parent=self,
            event="cutter_debug_get_modules",
            logger=_logger,
        )

    def _apply_modules(self, result: object) -> None:
        """Populate the loaded-modules table.

        Args:
            result: List of ModuleInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._modules_table.setRowCount(0)
        for mod in items:
            row = self._modules_table.rowCount()
            self._modules_table.insertRow(row)
            self._modules_table.setItem(row, 0, QTableWidgetItem(getattr(mod, "name", "")))
            self._modules_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(mod, 'base_address', 0):X}"))
            self._modules_table.setItem(row, 2, QTableWidgetItem(str(getattr(mod, "size", 0))))
            self._modules_table.setItem(row, 3, QTableWidgetItem(f"0x{getattr(mod, 'entry_point', 0):X}"))
            self._modules_table.setItem(row, 4, QTableWidgetItem(str(getattr(mod, "path", ""))))
