# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""X64dbg debugger panel for Intellicrack.

Provides disassembly, register inspection, breakpoint management, memory viewing, stack traces, and command console for interactive
debugging via the X64DbgBridge backend.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final, cast, override

from PyQt6.QtCore import QRegularExpression, QSignalBlocker, Qt, QTimer
from PyQt6.QtGui import QIntValidator, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
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
from intellicrack.ui._hex_format import format_hex_dump
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine, run_bridge_coroutine_logged
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.qt_compat import connect_cell_changed, set_max_block_count
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.win32_embed import poll_and_embed


if TYPE_CHECKING:
    from intellicrack.bridges.x64dbg import BreakpointType, MemoryProtection, X64DbgBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_TOP_SPLIT_LEFT: Final[int] = 500
_TOP_SPLIT_RIGHT: Final[int] = 400
_MAIN_SPLIT_TOP: Final[int] = 450
_MAIN_SPLIT_BOTTOM: Final[int] = 250
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160
_SIZE_INPUT_MAX_WIDTH: Final[int] = 80

_REG_COLUMNS = ["Register", "Value"]
_STACK_COLUMNS = ["Address", "Value", "Info"]
_MODULE_COLUMNS = ["Name", "Base", "Size", "Path"]
_THREAD_COLUMNS = ["TID", "Priority", "State"]
_BP_COLUMNS = ["Address", "Type", "Condition", "Hits", "Enabled"]

_WP_COLUMNS = ["Address", "Size", "Type", "Enabled", "Hits"]
_SEARCH_COLUMNS = ["#", "Address", "Match", "Context"]
_SECTION_DETAIL_COLUMNS = ["Name", "Address", "Size", "Characteristics"]
_EXPORT_DETAIL_COLUMNS = ["Name", "Ordinal", "Address"]
_ANNOT_COLUMNS = ["Address", "Text", "Module"]
_MEMMAP_COLUMNS = ["Base", "Size", "Protection", "State", "Type", "Module"]

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

    Displays disassembly, registers, breakpoints, memory dumps, stack traces, and a command console for controlling x64dbg via the
    X64DbgBridge backend.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the X64DbgPanel widget.

        Args:
            parent: Parent widget.
        """
        self._bridge: X64DbgBridge | None = None
        self._is_64bit: bool = True
        self.embedded_container: QWidget | None = None
        super().__init__(parent)

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
        self._detach_btn = self._add_tool_button(toolbar, "Detach", self._on_detach)
        self._spawn_btn = self._add_tool_button(toolbar, "Spawn", self._on_spawn)
        toolbar.addSeparator()
        self._add_toolbar_label(toolbar, "Run To:")
        self._run_to_input = self._add_toolbar_input(toolbar, "0x...", max_width=120)
        self._run_to_btn = self._add_tool_button(toolbar, "Go", self._on_run_to)
        self._til_ret_btn = self._add_tool_button(toolbar, "Til Ret", self._on_til_ret)
        self._skip_btn = self._add_tool_button(toolbar, "Skip", self._on_skip)
        toolbar.addSeparator()
        self._add_toolbar_label(toolbar, "IP:")
        self._set_ip_input = self._add_toolbar_input(toolbar, "0x...", max_width=120)
        self._set_ip_btn = self._add_tool_button(toolbar, "Set", self._on_set_ip)
        toolbar.addSeparator()
        self._save_db_btn = self._add_tool_button(toolbar, "Save DB", self._on_save_db)
        self._load_db_btn = self._add_tool_button(toolbar, "Load DB", self._on_load_db)

        toolbar.addSeparator()

        self._64bit_toggle = QCheckBox("64-bit")
        self._64bit_toggle.setChecked(True)

        def _toggle_64bit_slot(c: int) -> None:
            self._on_toggle_64bit(checked=bool(c))

        self._64bit_toggle.toggled.connect(_toggle_64bit_slot)
        toolbar.addWidget(self._64bit_toggle)

        toolbar.addSeparator()

        self._status_label = self._add_toolbar_label(toolbar, "Not loaded")
        self._debug_buttons: list[QPushButton] = [
            self._run_btn,
            self._pause_btn,
            self._stop_btn,
            self._step_into_btn,
            self._step_over_btn,
            self._step_out_btn,
            self._detach_btn,
            self._spawn_btn,
            self._run_to_btn,
            self._til_ret_btn,
            self._skip_btn,
            self._set_ip_btn,
            self._save_db_btn,
            self._load_db_btn,
        ]
        self._update_controls_state()

    @override
    def _create_content(self) -> QWidget:
        """Create the x64dbg debugging content area.

        Returns:
            QWidget: Tab widget with native controls and embedded x64dbg window.
        """
        self._main_tabs = QTabWidget()

        native_container = QWidget()
        native_layout = QVBoxLayout(native_container)
        native_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)

        main_splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._create_disasm_section())
        top_splitter.addWidget(self._create_inspect_tabs())
        top_splitter.setSizes([_TOP_SPLIT_LEFT, _TOP_SPLIT_RIGHT])
        main_splitter.addWidget(top_splitter)

        main_splitter.addWidget(self._create_bottom_tabs())
        main_splitter.setSizes([_MAIN_SPLIT_TOP, _MAIN_SPLIT_BOTTOM])

        native_layout.addWidget(main_splitter)
        self._main_tabs.addTab(native_container, self.tr("Analysis"))

        self.embed_host = QWidget()
        embed_layout = QVBoxLayout(self.embed_host)
        embed_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._embed_status_label = QLabel(self.tr("No debugger process active"))
        self._embed_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        embed_layout.addWidget(self._embed_status_label)
        self._main_tabs.addTab(self.embed_host, self.tr("x64dbg Window"))

        return self._main_tabs

    @override
    def _cleanup(self) -> None:
        """Unregister event callback and stop the x64dbg bridge."""
        if self.embedded_container is not None:
            self.embedded_container.setParent(None)
            self.embedded_container = None
        if self._bridge is not None:
            if hasattr(self._bridge, "unregister_event_callback"):
                self._bridge.unregister_event_callback(self._on_debug_event)
            if self._bridge.state.is_ready():
                try:
                    run_bridge_coroutine(self._bridge.stop())
                except (RuntimeError, ConnectionError, OSError):
                    _logger.exception("x64dbg_stop_failed", bridge_type="x64dbg")

    def _create_disasm_section(self) -> QWidget:
        """Create the disassembly display section.

        Returns:
            QWidget: Disassembly container widget.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        fm = FontManager.get_instance()
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        title = QLabel(self.tr("Disassembly"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        self._disasm_view = QPlainTextEdit()
        self._disasm_view.setFont(fm.get_code_font(10))
        self._disasm_view.setReadOnly(True)
        set_max_block_count(self._disasm_view, 50000)
        layout.addWidget(self._disasm_view)

        return container

    def _create_inspect_tabs(self) -> QTabWidget:
        """Create registers, stack, modules, and threads tabs.

        Returns:
            QTabWidget: Tab widget with inspection views.
        """
        tabs = QTabWidget()

        self._reg_table = QTableWidget(0, len(_REG_COLUMNS))
        self._reg_table.setHorizontalHeaderLabels(_REG_COLUMNS)
        self._reg_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._reg_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        reg_h = self._reg_table.horizontalHeader()
        if reg_h is not None:
            reg_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        connect_cell_changed(self._reg_table, self._on_register_edited)
        tabs.addTab(self._reg_table, self.tr("Registers"))

        self._stack_table = QTableWidget(0, len(_STACK_COLUMNS))
        self._stack_table.setHorizontalHeaderLabels(_STACK_COLUMNS)
        self._stack_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._stack_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        stack_h = self._stack_table.horizontalHeader()
        if stack_h is not None:
            stack_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tabs.addTab(self._stack_table, self.tr("Stack"))

        mod_container = QWidget()
        mod_vlayout = QVBoxLayout(mod_container)
        mod_vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._module_table = QTableWidget(0, len(_MODULE_COLUMNS))
        self._module_table.setHorizontalHeaderLabels(_MODULE_COLUMNS)
        self._module_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._module_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        mod_h = self._module_table.horizontalHeader()
        if mod_h is not None:
            mod_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        mod_vlayout.addWidget(self._module_table)
        mod_btn_row = QHBoxLayout()
        self._mod_sections_btn = QPushButton(self.tr("Sections"))
        self._mod_sections_btn.setObjectName("tool_button")
        self._mod_sections_btn.clicked.connect(self._on_show_module_sections)
        mod_btn_row.addWidget(self._mod_sections_btn)
        self._mod_exports_btn = QPushButton(self.tr("Exports"))
        self._mod_exports_btn.setObjectName("tool_button")
        self._mod_exports_btn.clicked.connect(self._on_show_module_exports)
        mod_btn_row.addWidget(self._mod_exports_btn)
        mod_btn_row.addStretch()
        mod_vlayout.addLayout(mod_btn_row)
        self._mod_detail_table = QTableWidget(0, len(_SECTION_DETAIL_COLUMNS))
        self._mod_detail_table.setHorizontalHeaderLabels(_SECTION_DETAIL_COLUMNS)
        self._mod_detail_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._mod_detail_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        detail_h = self._mod_detail_table.horizontalHeader()
        if detail_h is not None:
            detail_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        mod_vlayout.addWidget(self._mod_detail_table)
        tabs.addTab(mod_container, self.tr("Modules"))

        thread_container = QWidget()
        thread_vlayout = QVBoxLayout(thread_container)
        thread_vlayout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._thread_table = QTableWidget(0, len(_THREAD_COLUMNS))
        self._thread_table.setHorizontalHeaderLabels(_THREAD_COLUMNS)
        self._thread_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._thread_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        thread_h = self._thread_table.horizontalHeader()
        if thread_h is not None:
            thread_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        thread_vlayout.addWidget(self._thread_table)
        thread_btn_row = QHBoxLayout()
        self._suspend_thread_btn = QPushButton(self.tr("Suspend"))
        self._suspend_thread_btn.setObjectName("tool_button")
        self._suspend_thread_btn.clicked.connect(self._on_suspend_thread)
        thread_btn_row.addWidget(self._suspend_thread_btn)
        self._resume_thread_btn = QPushButton(self.tr("Resume"))
        self._resume_thread_btn.setObjectName("tool_button")
        self._resume_thread_btn.clicked.connect(self._on_resume_thread)
        thread_btn_row.addWidget(self._resume_thread_btn)
        self._switch_thread_btn = QPushButton(self.tr("Switch To"))
        self._switch_thread_btn.setObjectName("tool_button")
        self._switch_thread_btn.clicked.connect(self._on_switch_thread)
        thread_btn_row.addWidget(self._switch_thread_btn)
        thread_btn_row.addStretch()
        thread_vlayout.addLayout(thread_btn_row)
        tabs.addTab(thread_container, self.tr("Threads"))

        procinfo_container = QWidget()
        procinfo_layout = QVBoxLayout(procinfo_container)
        procinfo_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._procinfo_form = QFormLayout()
        self._procinfo_pid = QLabel("--")
        self._procinfo_name = QLabel("--")
        self._procinfo_path = QLabel("--")
        self._procinfo_cmdline = QLabel("--")
        self._procinfo_ppid = QLabel("--")
        self._procinfo_form.addRow(self.tr("PID:"), self._procinfo_pid)
        self._procinfo_form.addRow(self.tr("Name:"), self._procinfo_name)
        self._procinfo_form.addRow(self.tr("Path:"), self._procinfo_path)
        self._procinfo_form.addRow(self.tr("Command Line:"), self._procinfo_cmdline)
        self._procinfo_form.addRow(self.tr("Parent PID:"), self._procinfo_ppid)
        procinfo_layout.addLayout(self._procinfo_form)
        self._procinfo_refresh_btn = QPushButton(self.tr("Refresh"))
        self._procinfo_refresh_btn.setObjectName("tool_button")
        self._procinfo_refresh_btn.clicked.connect(self._on_refresh_procinfo)
        procinfo_layout.addWidget(self._procinfo_refresh_btn)
        procinfo_layout.addStretch()
        tabs.addTab(procinfo_container, self.tr("Process Info"))

        return tabs

    def _create_bottom_tabs(self) -> QTabWidget:
        """Create breakpoints, memory, console, and analysis tabs.

        Returns:
            QTabWidget: Tab widget with bottom-panel views.
        """
        tabs = QTabWidget()
        hex_validator = QRegularExpressionValidator(QRegularExpression(r"[0-9a-fA-Fx]*"), self)
        tabs.addTab(self._build_bp_tab(hex_validator), self.tr("Breakpoints"))
        tabs.addTab(self._build_mem_tab(hex_validator), self.tr("Memory"))
        tabs.addTab(self._build_console_tab(hex_validator), self.tr("Console"))
        tabs.addTab(self._build_wp_tab(hex_validator), self.tr("Watchpoints"))
        tabs.addTab(self._build_search_tab(), self.tr("Search"))
        tabs.addTab(self._build_trace_tab(), self.tr("Trace"))
        tabs.addTab(self._build_annot_tab(hex_validator), self.tr("Annotations"))
        tabs.addTab(self._build_mmap_tab(hex_validator), self.tr("Memory Map"))
        return tabs

    def _build_bp_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Breakpoints tab widget.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Breakpoints tab container.
        """
        fm = FontManager.get_instance()
        bp_container = QWidget()
        bp_layout = QVBoxLayout(bp_container)
        bp_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        bp_layout.setSpacing(_PANEL_SPACING)
        bp_toolbar = QHBoxLayout()
        bp_addr_label = QLabel(self.tr("Address:"))
        bp_addr_label.setFont(fm.get_ui_font(9))
        bp_toolbar.addWidget(bp_addr_label)
        self._bp_addr_input = QLineEdit()
        self._bp_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._bp_addr_input.setValidator(hex_validator)
        self._bp_addr_input.setPlaceholderText("0x...")
        bp_toolbar.addWidget(self._bp_addr_input)
        bp_type_label = QLabel(self.tr("Type:"))
        bp_type_label.setFont(fm.get_ui_font(9))
        bp_toolbar.addWidget(bp_type_label)
        self._bp_type_combo = QComboBox()
        self._bp_type_combo.addItems(["software", "hardware", "memory"])
        bp_toolbar.addWidget(self._bp_type_combo)
        self._add_bp_btn = QPushButton(self.tr("Add BP"))
        self._add_bp_btn.setObjectName("tool_button")
        self._add_bp_btn.clicked.connect(self._on_add_breakpoint)
        bp_toolbar.addWidget(self._add_bp_btn)
        self._remove_bp_btn = QPushButton(self.tr("Remove BP"))
        self._remove_bp_btn.setObjectName("tool_button")
        self._remove_bp_btn.clicked.connect(self._on_remove_breakpoint)
        bp_toolbar.addWidget(self._remove_bp_btn)
        bp_mod_label = QLabel(self.tr("Module:"))
        bp_mod_label.setFont(fm.get_ui_font(9))
        bp_toolbar.addWidget(bp_mod_label)
        self._bp_mod_input = QLineEdit()
        self._bp_mod_input.setMaximumWidth(100)
        self._bp_mod_input.setPlaceholderText("kernel32")
        bp_toolbar.addWidget(self._bp_mod_input)
        bp_func_label = QLabel(self.tr("Function:"))
        bp_func_label.setFont(fm.get_ui_font(9))
        bp_toolbar.addWidget(bp_func_label)
        self._bp_func_input = QLineEdit()
        self._bp_func_input.setMaximumWidth(120)
        self._bp_func_input.setPlaceholderText("CreateFileW")
        bp_toolbar.addWidget(self._bp_func_input)
        self._set_api_bp_btn = QPushButton(self.tr("Set API BP"))
        self._set_api_bp_btn.setObjectName("tool_button")
        self._set_api_bp_btn.clicked.connect(self._on_set_api_bp)
        bp_toolbar.addWidget(self._set_api_bp_btn)
        self._enable_bp_btn = QPushButton(self.tr("Enable BP"))
        self._enable_bp_btn.setObjectName("tool_button")
        self._enable_bp_btn.clicked.connect(self._on_enable_breakpoint)
        bp_toolbar.addWidget(self._enable_bp_btn)
        self._disable_bp_btn = QPushButton(self.tr("Disable BP"))
        self._disable_bp_btn.setObjectName("tool_button")
        self._disable_bp_btn.clicked.connect(self._on_disable_breakpoint)
        bp_toolbar.addWidget(self._disable_bp_btn)
        bp_toolbar.addStretch()
        bp_layout.addLayout(bp_toolbar)
        self._bp_table = QTableWidget(0, len(_BP_COLUMNS))
        self._bp_table.setHorizontalHeaderLabels(_BP_COLUMNS)
        self._bp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._bp_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        bp_h = self._bp_table.horizontalHeader()
        if bp_h is not None:
            bp_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        bp_layout.addWidget(self._bp_table)
        return bp_container

    def _build_mem_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Memory tab widget.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Memory tab container.
        """
        fm = FontManager.get_instance()
        mem_container = QWidget()
        mem_layout = QVBoxLayout(mem_container)
        mem_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        mem_layout.setSpacing(_PANEL_SPACING)
        mem_toolbar = QHBoxLayout()
        mem_addr_label = QLabel(self.tr("Address:"))
        mem_addr_label.setFont(fm.get_ui_font(9))
        mem_toolbar.addWidget(mem_addr_label)
        self._mem_addr_input = QLineEdit()
        self._mem_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._mem_addr_input.setValidator(hex_validator)
        self._mem_addr_input.setPlaceholderText("0x...")
        mem_toolbar.addWidget(self._mem_addr_input)
        mem_size_label = QLabel(self.tr("Size:"))
        mem_size_label.setFont(fm.get_ui_font(9))
        mem_toolbar.addWidget(mem_size_label)
        self._mem_size_input = QLineEdit()
        self._mem_size_input.setMaximumWidth(_SIZE_INPUT_MAX_WIDTH)
        self._mem_size_input.setValidator(QIntValidator(1, 1048576, self))
        self._mem_size_input.setText("256")
        mem_toolbar.addWidget(self._mem_size_input)
        self._mem_read_btn = QPushButton(self.tr("Read"))
        self._mem_read_btn.setObjectName("tool_button")
        self._mem_read_btn.clicked.connect(self._on_read_memory)
        mem_toolbar.addWidget(self._mem_read_btn)
        self._mem_dump_btn = QPushButton(self.tr("Dump"))
        self._mem_dump_btn.setObjectName("tool_button")
        self._mem_dump_btn.clicked.connect(self._on_dump_memory)
        mem_toolbar.addWidget(self._mem_dump_btn)
        self._mem_write_data_input = QLineEdit()
        self._mem_write_data_input.setMaximumWidth(150)
        self._mem_write_data_input.setPlaceholderText("Hex data...")
        mem_toolbar.addWidget(self._mem_write_data_input)
        self._mem_write_btn = QPushButton(self.tr("Write"))
        self._mem_write_btn.setObjectName("tool_button")
        self._mem_write_btn.clicked.connect(self._on_write_memory)
        mem_toolbar.addWidget(self._mem_write_btn)
        self._asm_instr_input = QLineEdit()
        self._asm_instr_input.setMaximumWidth(150)
        self._asm_instr_input.setPlaceholderText("nop")
        mem_toolbar.addWidget(self._asm_instr_input)
        self._asm_btn = QPushButton(self.tr("Asm"))
        self._asm_btn.setObjectName("tool_button")
        self._asm_btn.clicked.connect(self._on_assemble)
        mem_toolbar.addWidget(self._asm_btn)
        self._nop_size_input = QLineEdit()
        self._nop_size_input.setMaximumWidth(50)
        self._nop_size_input.setValidator(QIntValidator(1, 4096, self))
        self._nop_size_input.setText("1")
        mem_toolbar.addWidget(self._nop_size_input)
        self._nop_btn = QPushButton(self.tr("NOP"))
        self._nop_btn.setObjectName("tool_button")
        self._nop_btn.clicked.connect(self._on_nop_range)
        mem_toolbar.addWidget(self._nop_btn)
        mem_toolbar.addStretch()
        mem_layout.addLayout(mem_toolbar)
        self._mem_dump = QPlainTextEdit()
        self._mem_dump.setFont(fm.get_code_font(10))
        self._mem_dump.setReadOnly(True)
        set_max_block_count(self._mem_dump, 10000)
        mem_layout.addWidget(self._mem_dump)
        return mem_container

    def _build_console_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Console tab widget.

        Args:
            hex_validator: Validator for hex inputs.

        Returns:
            QWidget: Console tab container.
        """
        fm = FontManager.get_instance()
        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        console_layout.setSpacing(_PANEL_SPACING)
        self._console_output = QPlainTextEdit()
        self._console_output.setFont(fm.get_code_font(9))
        self._console_output.setReadOnly(True)
        set_max_block_count(self._console_output, 10000)
        console_layout.addWidget(self._console_output)
        self._console_input = QLineEdit()
        self._console_input.setFont(fm.get_code_font(9))
        self._console_input.setPlaceholderText(self.tr("x64dbg command..."))
        self._console_input.returnPressed.connect(self._on_execute_command)
        console_layout.addWidget(self._console_input)
        eval_row = QHBoxLayout()
        eval_label = QLabel(self.tr("Expr:"))
        eval_label.setFont(fm.get_ui_font(9))
        eval_row.addWidget(eval_label)
        self._eval_input = QLineEdit()
        self._eval_input.setFont(fm.get_code_font(9))
        self._eval_input.setMinimumWidth(200)
        self._eval_input.setPlaceholderText("rax+rbx*4")
        eval_row.addWidget(self._eval_input)
        self._eval_btn = QPushButton(self.tr("Eval"))
        self._eval_btn.setObjectName("tool_button")
        self._eval_btn.clicked.connect(self._on_eval_expression)
        eval_row.addWidget(self._eval_btn)
        eval_row.addSpacing(10)
        exc_label = QLabel(self.tr("Exception:"))
        exc_label.setFont(fm.get_ui_font(9))
        eval_row.addWidget(exc_label)
        self._exc_code_input = QLineEdit()
        self._exc_code_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._exc_code_input.setValidator(hex_validator)
        self._exc_code_input.setPlaceholderText("0xC0000005")
        eval_row.addWidget(self._exc_code_input)
        self._exc_handling_combo = QComboBox()
        self._exc_handling_combo.addItems(["break", "ignore", "log"])
        eval_row.addWidget(self._exc_handling_combo)
        self._exc_set_btn = QPushButton(self.tr("Set"))
        self._exc_set_btn.setObjectName("tool_button")
        self._exc_set_btn.clicked.connect(self._on_set_exception_config)
        eval_row.addWidget(self._exc_set_btn)
        eval_row.addStretch()
        console_layout.addLayout(eval_row)
        return console_container

    def _build_wp_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Watchpoints tab widget.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Watchpoints tab container.
        """
        fm = FontManager.get_instance()
        wp_container = QWidget()
        wp_layout = QVBoxLayout(wp_container)
        wp_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        wp_layout.setSpacing(_PANEL_SPACING)
        wp_toolbar = QHBoxLayout()
        wp_addr_label = QLabel(self.tr("Address:"))
        wp_addr_label.setFont(fm.get_ui_font(9))
        wp_toolbar.addWidget(wp_addr_label)
        self._wp_addr_input = QLineEdit()
        self._wp_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._wp_addr_input.setValidator(hex_validator)
        self._wp_addr_input.setPlaceholderText("0x...")
        wp_toolbar.addWidget(self._wp_addr_input)
        wp_size_label = QLabel(self.tr("Size:"))
        wp_size_label.setFont(fm.get_ui_font(9))
        wp_toolbar.addWidget(wp_size_label)
        self._wp_size_input = QLineEdit()
        self._wp_size_input.setMaximumWidth(_SIZE_INPUT_MAX_WIDTH)
        self._wp_size_input.setValidator(QIntValidator(1, 8, self))
        self._wp_size_input.setText("4")
        wp_toolbar.addWidget(self._wp_size_input)
        wp_type_label = QLabel(self.tr("Type:"))
        wp_type_label.setFont(fm.get_ui_font(9))
        wp_toolbar.addWidget(wp_type_label)
        self._wp_type_combo = QComboBox()
        self._wp_type_combo.addItems(["read", "write", "execute"])
        self._wp_type_combo.setCurrentIndex(1)
        wp_toolbar.addWidget(self._wp_type_combo)
        self._add_wp_btn = QPushButton(self.tr("Add WP"))
        self._add_wp_btn.setObjectName("tool_button")
        self._add_wp_btn.clicked.connect(self._on_add_watchpoint)
        wp_toolbar.addWidget(self._add_wp_btn)
        self._remove_wp_btn = QPushButton(self.tr("Remove WP"))
        self._remove_wp_btn.setObjectName("tool_button")
        self._remove_wp_btn.clicked.connect(self._on_remove_watchpoint)
        wp_toolbar.addWidget(self._remove_wp_btn)
        wp_toolbar.addStretch()
        wp_layout.addLayout(wp_toolbar)
        self._wp_table = QTableWidget(0, len(_WP_COLUMNS))
        self._wp_table.setHorizontalHeaderLabels(_WP_COLUMNS)
        self._wp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._wp_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        wp_h = self._wp_table.horizontalHeader()
        if wp_h is not None:
            wp_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        wp_layout.addWidget(self._wp_table)
        return wp_container

    def _build_search_tab(self) -> QWidget:
        """Build the Search tab widget.

        Returns:
            QWidget: Search tab container.
        """
        fm = FontManager.get_instance()
        search_container = QWidget()
        search_layout = QVBoxLayout(search_container)
        search_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        search_layout.setSpacing(_PANEL_SPACING)
        search_toolbar = QHBoxLayout()
        search_pat_label = QLabel(self.tr("Pattern:"))
        search_pat_label.setFont(fm.get_ui_font(9))
        search_toolbar.addWidget(search_pat_label)
        self._search_pattern_input = QLineEdit()
        self._search_pattern_input.setMinimumWidth(200)
        self._search_pattern_input.setPlaceholderText("48 8B ?? 90...")
        search_toolbar.addWidget(self._search_pattern_input)
        search_mode_label = QLabel(self.tr("Mode:"))
        search_mode_label.setFont(fm.get_ui_font(9))
        search_toolbar.addWidget(search_mode_label)
        self._search_mode_combo = QComboBox()
        self._search_mode_combo.addItems(["Hex", "Byte", "YARA"])
        search_toolbar.addWidget(self._search_mode_combo)
        self._search_btn = QPushButton(self.tr("Search"))
        self._search_btn.setObjectName("tool_button")
        self._search_btn.clicked.connect(self._on_search)
        search_toolbar.addWidget(self._search_btn)
        search_toolbar.addStretch()
        search_layout.addLayout(search_toolbar)
        self._search_table = QTableWidget(0, len(_SEARCH_COLUMNS))
        self._search_table.setHorizontalHeaderLabels(_SEARCH_COLUMNS)
        self._search_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        search_h = self._search_table.horizontalHeader()
        if search_h is not None:
            search_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        search_layout.addWidget(self._search_table)
        return search_container

    def _build_trace_tab(self) -> QWidget:
        """Build the Trace tab widget.

        Returns:
            QWidget: Trace tab container.
        """
        fm = FontManager.get_instance()
        trace_container = QWidget()
        trace_layout = QVBoxLayout(trace_container)
        trace_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        trace_layout.setSpacing(_PANEL_SPACING)
        trace_toolbar = QHBoxLayout()
        trace_cond_label = QLabel(self.tr("Condition:"))
        trace_cond_label.setFont(fm.get_ui_font(9))
        trace_toolbar.addWidget(trace_cond_label)
        self._trace_cond_input = QLineEdit()
        self._trace_cond_input.setMinimumWidth(150)
        trace_toolbar.addWidget(self._trace_cond_input)
        trace_log_label = QLabel(self.tr("Log:"))
        trace_log_label.setFont(fm.get_ui_font(9))
        trace_toolbar.addWidget(trace_log_label)
        self._trace_log_input = QLineEdit()
        self._trace_log_input.setMinimumWidth(150)
        trace_toolbar.addWidget(self._trace_log_input)
        self._trace_start_btn = QPushButton(self.tr("Start"))
        self._trace_start_btn.setObjectName("tool_button")
        self._trace_start_btn.clicked.connect(self._on_trace_start)
        trace_toolbar.addWidget(self._trace_start_btn)
        self._trace_stop_btn2 = QPushButton(self.tr("Stop"))
        self._trace_stop_btn2.setObjectName("tool_button")
        self._trace_stop_btn2.clicked.connect(self._on_trace_stop)
        trace_toolbar.addWidget(self._trace_stop_btn2)
        self._trace_into_btn = QPushButton(self.tr("Trace Into"))
        self._trace_into_btn.setObjectName("tool_button")
        self._trace_into_btn.clicked.connect(self._on_trace_into)
        trace_toolbar.addWidget(self._trace_into_btn)
        self._trace_over_btn = QPushButton(self.tr("Trace Over"))
        self._trace_over_btn.setObjectName("tool_button")
        self._trace_over_btn.clicked.connect(self._on_trace_over)
        trace_toolbar.addWidget(self._trace_over_btn)
        trace_toolbar.addStretch()
        trace_layout.addLayout(trace_toolbar)
        self._trace_output = QPlainTextEdit()
        self._trace_output.setFont(fm.get_code_font(9))
        self._trace_output.setReadOnly(True)
        set_max_block_count(self._trace_output, 50000)
        trace_layout.addWidget(self._trace_output)
        return trace_container

    def _build_annot_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Annotations tab widget (Labels + Comments sub-tabs).

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Annotations tab container.
        """
        annot_container = QWidget()
        annot_layout = QVBoxLayout(annot_container)
        annot_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        annot_tabs = QTabWidget()
        annot_tabs.addTab(self._build_labels_subtab(hex_validator), self.tr("Labels"))
        annot_tabs.addTab(self._build_comments_subtab(hex_validator), self.tr("Comments"))
        annot_layout.addWidget(annot_tabs)
        return annot_container

    def _build_labels_subtab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Labels sub-tab within Annotations.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Labels sub-tab widget.
        """
        fm = FontManager.get_instance()
        lbl_widget = QWidget()
        lbl_layout = QVBoxLayout(lbl_widget)
        lbl_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        lbl_toolbar = QHBoxLayout()
        lbl_addr_label = QLabel(self.tr("Address:"))
        lbl_addr_label.setFont(fm.get_ui_font(9))
        lbl_toolbar.addWidget(lbl_addr_label)
        self._lbl_addr_input = QLineEdit()
        self._lbl_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._lbl_addr_input.setValidator(hex_validator)
        lbl_toolbar.addWidget(self._lbl_addr_input)
        lbl_text_label = QLabel(self.tr("Text:"))
        lbl_text_label.setFont(fm.get_ui_font(9))
        lbl_toolbar.addWidget(lbl_text_label)
        self._lbl_text_input = QLineEdit()
        self._lbl_text_input.setMinimumWidth(150)
        lbl_toolbar.addWidget(self._lbl_text_input)
        self._set_lbl_btn = QPushButton(self.tr("Set Label"))
        self._set_lbl_btn.setObjectName("tool_button")
        self._set_lbl_btn.clicked.connect(self._on_set_label)
        lbl_toolbar.addWidget(self._set_lbl_btn)
        lbl_toolbar.addStretch()
        lbl_layout.addLayout(lbl_toolbar)
        self._lbl_table = QTableWidget(0, len(_ANNOT_COLUMNS))
        self._lbl_table.setHorizontalHeaderLabels(_ANNOT_COLUMNS)
        self._lbl_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        lbl_h = self._lbl_table.horizontalHeader()
        if lbl_h is not None:
            lbl_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        lbl_layout.addWidget(self._lbl_table)
        return lbl_widget

    def _build_comments_subtab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Comments sub-tab within Annotations.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Comments sub-tab widget.
        """
        fm = FontManager.get_instance()
        cmt_widget = QWidget()
        cmt_layout = QVBoxLayout(cmt_widget)
        cmt_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        cmt_toolbar = QHBoxLayout()
        cmt_addr_label = QLabel(self.tr("Address:"))
        cmt_addr_label.setFont(fm.get_ui_font(9))
        cmt_toolbar.addWidget(cmt_addr_label)
        self._cmt_addr_input = QLineEdit()
        self._cmt_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._cmt_addr_input.setValidator(hex_validator)
        cmt_toolbar.addWidget(self._cmt_addr_input)
        cmt_text_label = QLabel(self.tr("Text:"))
        cmt_text_label.setFont(fm.get_ui_font(9))
        cmt_toolbar.addWidget(cmt_text_label)
        self._cmt_text_input = QLineEdit()
        self._cmt_text_input.setMinimumWidth(150)
        cmt_toolbar.addWidget(self._cmt_text_input)
        self._set_cmt_btn = QPushButton(self.tr("Set Comment"))
        self._set_cmt_btn.setObjectName("tool_button")
        self._set_cmt_btn.clicked.connect(self._on_set_comment_btn)
        cmt_toolbar.addWidget(self._set_cmt_btn)
        cmt_toolbar.addStretch()
        cmt_layout.addLayout(cmt_toolbar)
        self._cmt_table = QTableWidget(0, len(_ANNOT_COLUMNS))
        self._cmt_table.setHorizontalHeaderLabels(_ANNOT_COLUMNS)
        self._cmt_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        cmt_h = self._cmt_table.horizontalHeader()
        if cmt_h is not None:
            cmt_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        cmt_layout.addWidget(self._cmt_table)
        return cmt_widget

    def _build_mmap_tab(self, hex_validator: QRegularExpressionValidator) -> QWidget:
        """Build the Memory Map tab widget.

        Args:
            hex_validator: Validator for hex address inputs.

        Returns:
            QWidget: Memory Map tab container.
        """
        fm = FontManager.get_instance()
        mmap_container = QWidget()
        mmap_layout = QVBoxLayout(mmap_container)
        mmap_layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        mmap_layout.setSpacing(_PANEL_SPACING)
        mmap_toolbar = QHBoxLayout()
        self._mmap_refresh_btn = QPushButton(self.tr("Refresh"))
        self._mmap_refresh_btn.setObjectName("tool_button")
        self._mmap_refresh_btn.clicked.connect(self._on_refresh_memmap)
        mmap_toolbar.addWidget(self._mmap_refresh_btn)
        self._mmap_dump_btn = QPushButton(self.tr("Dump Selected"))
        self._mmap_dump_btn.setObjectName("tool_button")
        self._mmap_dump_btn.clicked.connect(self._on_dump_memmap_region)
        mmap_toolbar.addWidget(self._mmap_dump_btn)
        alloc_size_label = QLabel(self.tr("Alloc Size:"))
        alloc_size_label.setFont(fm.get_ui_font(9))
        mmap_toolbar.addWidget(alloc_size_label)
        self._alloc_size_input = QLineEdit()
        self._alloc_size_input.setMaximumWidth(_SIZE_INPUT_MAX_WIDTH)
        self._alloc_size_input.setValidator(QIntValidator(1, 1048576, self))
        self._alloc_size_input.setText("4096")
        mmap_toolbar.addWidget(self._alloc_size_input)
        alloc_prot_label = QLabel(self.tr("Prot:"))
        alloc_prot_label.setFont(fm.get_ui_font(9))
        mmap_toolbar.addWidget(alloc_prot_label)
        self._alloc_prot_combo = QComboBox()
        self._alloc_prot_combo.addItems(["rwx", "rw", "rx", "r"])
        mmap_toolbar.addWidget(self._alloc_prot_combo)
        self._alloc_btn = QPushButton(self.tr("Alloc"))
        self._alloc_btn.setObjectName("tool_button")
        self._alloc_btn.clicked.connect(self._on_alloc_memory)
        mmap_toolbar.addWidget(self._alloc_btn)
        free_addr_label = QLabel(self.tr("Free:"))
        free_addr_label.setFont(fm.get_ui_font(9))
        mmap_toolbar.addWidget(free_addr_label)
        self._free_addr_input = QLineEdit()
        self._free_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._free_addr_input.setValidator(hex_validator)
        mmap_toolbar.addWidget(self._free_addr_input)
        self._free_btn = QPushButton(self.tr("Free"))
        self._free_btn.setObjectName("tool_button")
        self._free_btn.clicked.connect(self._on_free_memory)
        mmap_toolbar.addWidget(self._free_btn)
        mmap_toolbar.addStretch()
        mmap_layout.addLayout(mmap_toolbar)
        self._mmap_table = QTableWidget(0, len(_MEMMAP_COLUMNS))
        self._mmap_table.setHorizontalHeaderLabels(_MEMMAP_COLUMNS)
        self._mmap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        mmap_h = self._mmap_table.horizontalHeader()
        if mmap_h is not None:
            mmap_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        mmap_layout.addWidget(self._mmap_table)
        return mmap_container

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
        _logger.info("x64dbg_bridge_set", bridge_type=type(bridge).__name__)
        self._update_controls_state()

    def _update_controls_state(self) -> None:
        """Enable or disable debug buttons based on bridge plugin readiness.

        When prerequisites are not met, buttons are disabled and a diagnostic message is shown in the status label and console.
        """
        if self._bridge is None:
            enabled = False
            diagnostic = "No bridge configured"
        else:
            status = self._bridge.plugin_status
            ready = bool(status.get("ready", False))
            diagnostic = str(status.get("diagnostic", ""))
            enabled = ready or bool(status.get("plugin_deployed", False))

        for btn in self._debug_buttons:
            btn.setEnabled(enabled)

        if diagnostic and not enabled:
            self._set_status(diagnostic)
            if hasattr(self, "_console_output"):
                self._console_output.appendPlainText(f"[!] {diagnostic}")

    def get_bridge(self) -> X64DbgBridge | None:
        """Get the current X64DbgBridge instance.

        Returns:
            X64DbgBridge | None: The attached bridge or None.
        """
        return self._bridge

    def debug_file(self, file_path: Path) -> bool:
        """Load a file for debugging (protocol-compatible convenience).

        Args:
            file_path: Path to the executable to debug.

        Returns:
            bool: True if loading was initiated.
        """
        if self._bridge is None:
            _logger.warning("x64dbg_debug_no_bridge", reason="bridge not set")
            return False

        self._load_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.load(file_path),
            on_success=lambda _: self._on_load_success(file_path),
            on_error=lambda e: self._on_load_error(file_path, e),
            parent=self,
            event="x64dbg_load",
            logger=_logger,
            level="info",
            file_path=str(file_path),
        )
        return True

    def _on_load_success(self, file_path: Path) -> None:
        """Handle successful file load.

        Args:
            file_path: The loaded file path.
        """
        self._set_status(f"Loaded: {file_path.name}")
        _logger.info("x64dbg_file_loaded", path=file_path.name)
        self._load_btn.setEnabled(True)
        self._sync_64bit_toggle()
        self._update_controls_state()
        self._refresh_state()
        self._try_embed_debugger_window()

    def _try_embed_debugger_window(self) -> None:
        """Attempt to capture and embed the x64dbg window into the panel."""
        if self._bridge is None:
            return

        pid = self._bridge.debugger_pid
        if pid is None:
            _logger.debug("x64dbg_embed_skipped_no_pid", reason="debugger_pid is None")
            return

        def _on_embedded(container: QWidget) -> None:
            layout = self.embed_host.layout()
            if layout is not None:
                while layout.count():
                    item = layout.takeAt(0)
                    widget = item.widget() if item is not None else None
                    if widget is not None:
                        widget.setParent(None)
                layout.addWidget(container)
            self.embedded_container = container
            self._main_tabs.setCurrentWidget(self.embed_host)
            _logger.info("x64dbg_window_embedded", pid=pid)

        poll_and_embed(
            pid=pid,
            parent=self.embed_host,
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
        _logger.warning("x64dbg_load_failed", path=file_path.name, error=str(exc))
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
            _logger.warning("invalid_pid_input", input_text=pid_text)
            self._console_output.appendPlainText(f"[!] Invalid PID: {pid_text}")
            return

        self._attach_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.attach(pid),
            on_success=lambda _: self._on_attach_success(pid),
            on_error=self._on_attach_error,
            parent=self,
            event="x64dbg_attach",
            logger=_logger,
            level="info",
            pid=pid,
        )

    def _on_attach_success(self, pid: int) -> None:
        """Handle successful attach.

        Args:
            pid: The attached process ID.
        """
        self._set_status(f"Attached: PID {pid}")
        self._console_output.appendPlainText(f"[+] Attached to PID {pid}")
        _logger.info("x64dbg_attached", pid=pid)
        self._attach_btn.setEnabled(True)
        self._sync_64bit_toggle()
        self._update_controls_state()
        self._refresh_state()

    def _on_attach_error(self, exc: object) -> None:
        """Handle attach failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Attach failed: {exc}")
        _logger.warning("x64dbg_attach_failed", error=str(exc))
        self._attach_btn.setEnabled(True)

    def _on_run(self) -> None:
        """Continue execution."""
        if self._bridge is None:
            return

        self._run_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.run(),
            on_success=lambda _: self._on_run_success(),
            on_error=self._on_run_error,
            parent=self,
            event="x64dbg_run",
            logger=_logger,
            level="info",
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
        _logger.warning("x64dbg_run_failed", error=str(exc))
        self._run_btn.setEnabled(True)

    def _on_pause(self) -> None:
        """Pause execution."""
        if self._bridge is None:
            return

        self._pause_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.pause(),
            on_success=lambda _: self._on_pause_success(),
            on_error=self._on_pause_error,
            parent=self,
            event="x64dbg_pause",
            logger=_logger,
            level="info",
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
        _logger.warning("x64dbg_pause_failed", error=str(exc))
        self._pause_btn.setEnabled(True)

    def _on_stop(self) -> None:
        """Stop debugging."""
        if self._bridge is None:
            return

        self._stop_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.stop(),
            on_success=lambda _: self._on_stop_success(),
            on_error=self._on_stop_error,
            parent=self,
            event="x64dbg_stop",
            logger=_logger,
            level="info",
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
        _logger.warning("x64dbg_stop_failed", error=str(exc))
        self._stop_btn.setEnabled(True)

    def _on_step_into(self) -> None:
        """Single step into."""
        if self._bridge is None:
            return

        self._step_into_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.step_into(),
            on_success=lambda r: self._on_step_success("into", r),
            on_error=lambda e: self._on_step_error("into", e),
            parent=self,
            event="x64dbg_step_into",
            logger=_logger,
            level="info",
        )

    def _on_step_over(self) -> None:
        """Single step over."""
        if self._bridge is None:
            return

        self._step_over_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.step_over(),
            on_success=lambda r: self._on_step_success("over", r),
            on_error=lambda e: self._on_step_error("over", e),
            parent=self,
            event="x64dbg_step_over",
            logger=_logger,
            level="info",
        )

    def _on_step_out(self) -> None:
        """Step out of current function."""
        if self._bridge is None:
            return

        self._step_out_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.step_out(),
            on_success=lambda r: self._on_step_success("out", r),
            on_error=lambda e: self._on_step_error("out", e),
            parent=self,
            event="x64dbg_step_out",
            logger=_logger,
            level="info",
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
        _logger.warning("x64dbg_step_failed", direction=direction, error=str(exc))
        self._step_into_btn.setEnabled(True)
        self._step_over_btn.setEnabled(True)
        self._step_out_btn.setEnabled(True)

    def _sync_64bit_toggle(self) -> None:
        """Sync the 64-bit checkbox with the bridge's detected architecture."""
        if self._bridge is None:
            return
        bridge_64: bool = getattr(self._bridge, "is_64bit", True)
        self._is_64bit = bridge_64
        with QSignalBlocker(self._64bit_toggle):
            self._64bit_toggle.setChecked(self._is_64bit)

    def _on_toggle_64bit(self, *, checked: bool) -> None:
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
            _logger.warning("invalid_breakpoint_address", input_text=addr_text)
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        bp_type_text = self._bp_type_combo.currentText()
        bp_type = cast(
            "BreakpointType",
            bp_type_text if bp_type_text in {"software", "hardware", "memory"} else "software",
        )
        self._add_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_breakpoint(address, bp_type=bp_type),
            on_success=lambda r: self._on_bp_added(address, r),
            on_error=self._on_bp_add_error,
            parent=self,
            event="x64dbg_set_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
            bp_type=bp_type,
        )

    def _on_bp_added(self, address: int, result: object) -> None:
        """Handle successful breakpoint addition.

        Args:
            address: The breakpoint address.
            result: The breakpoint ID from the bridge.
        """
        self._console_output.appendPlainText(f"[+] Breakpoint #{result} set at 0x{address:X}")
        _logger.info("x64dbg_bp_set", address=hex(address))
        self._add_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_add_error(self, exc: object) -> None:
        """Handle breakpoint addition failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to set breakpoint: {exc}")
        _logger.warning("x64dbg_bp_set_failed", error=str(exc))
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
            _logger.warning("invalid_breakpoint_address_from_table", input_text=addr_item.text())
            return

        if self._bridge is None:
            return

        self._remove_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.remove_breakpoint(address),
            on_success=lambda _: self._on_bp_removed(address),
            on_error=self._on_bp_remove_error,
            parent=self,
            event="x64dbg_remove_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_bp_removed(self, address: int) -> None:
        """Handle successful breakpoint removal.

        Args:
            address: The removed breakpoint address.
        """
        self._console_output.appendPlainText(f"[+] Breakpoint removed at 0x{address:X}")
        _logger.info("x64dbg_bp_removed", address=hex(address))
        self._remove_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_remove_error(self, exc: object) -> None:
        """Handle breakpoint removal failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to remove breakpoint: {exc}")
        _logger.warning("x64dbg_bp_remove_failed", error=str(exc))
        self._remove_bp_btn.setEnabled(True)

    def _on_enable_breakpoint(self) -> None:
        """Enable the selected breakpoint."""
        row = self._bp_table.currentRow()
        if row < 0 or self._bridge is None:
            return

        addr_item = self._bp_table.item(row, 0)
        if addr_item is None:
            return

        try:
            address = int(addr_item.text(), 16)
        except ValueError:
            _logger.warning("x64dbg_enable_breakpoint_invalid_address", input_text=addr_item.text())
            return

        self._enable_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.enable_breakpoint(address),
            on_success=lambda _: self._on_bp_toggle_done("enabled", address),
            on_error=lambda e: self._on_bp_toggle_error("enable", e),
            parent=self,
            event="x64dbg_enable_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_disable_breakpoint(self) -> None:
        """Disable the selected breakpoint."""
        row = self._bp_table.currentRow()
        if row < 0 or self._bridge is None:
            return

        addr_item = self._bp_table.item(row, 0)
        if addr_item is None:
            return

        try:
            address = int(addr_item.text(), 16)
        except ValueError:
            _logger.warning("x64dbg_disable_breakpoint_invalid_address", input_text=addr_item.text())
            return

        self._disable_bp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.disable_breakpoint(address),
            on_success=lambda _: self._on_bp_toggle_done("disabled", address),
            on_error=lambda e: self._on_bp_toggle_error("disable", e),
            parent=self,
            event="x64dbg_disable_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_bp_toggle_done(self, action: str, address: int) -> None:
        """Handle breakpoint enable/disable success.

        Args:
            action: Either "enabled" or "disabled".
            address: The breakpoint address.
        """
        self._console_output.appendPlainText(f"[+] Breakpoint {action} at 0x{address:X}")
        self._enable_bp_btn.setEnabled(True)
        self._disable_bp_btn.setEnabled(True)
        self._refresh_breakpoints()

    def _on_bp_toggle_error(self, action: str, exc: object) -> None:
        """Handle breakpoint enable/disable failure.

        Args:
            action: Either "enable" or "disable".
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Failed to {action} breakpoint: {exc}")
        _logger.warning("x64dbg_bp_toggle_failed", action=action, error=str(exc))
        self._enable_bp_btn.setEnabled(True)
        self._disable_bp_btn.setEnabled(True)

    def _on_show_module_sections(self) -> None:
        """Show sections for the selected module."""
        row = self._module_table.currentRow()
        if row < 0 or self._bridge is None:
            return

        name_item = self._module_table.item(row, 0)
        if name_item is None:
            return

        module_name = name_item.text()
        if not module_name:
            return

        self._mod_detail_table.setHorizontalHeaderLabels(_SECTION_DETAIL_COLUMNS)
        self._mod_sections_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_module_sections(module_name),
            on_success=self._apply_module_sections,
            on_error=lambda e: self._on_mod_detail_error("sections", e),
            parent=self,
            event="x64dbg_get_module_sections",
            logger=_logger,
            module=module_name,
        )

    def _apply_module_sections(self, result: object) -> None:
        """Populate the detail table with section data.

        Args:
            result: Section list from the bridge.
        """
        self._mod_sections_btn.setEnabled(True)
        raw_sections: list[object] = [*result] if isinstance(result, list) else []
        sections: list[dict[str, object]] = [cast("dict[str, object]", s) for s in raw_sections if isinstance(s, dict)]
        self._mod_detail_table.setRowCount(0)
        for sec in sections:
            row = self._mod_detail_table.rowCount()
            self._mod_detail_table.insertRow(row)
            self._mod_detail_table.setItem(row, 0, QTableWidgetItem(str(sec.get("name", ""))))
            self._mod_detail_table.setItem(row, 1, QTableWidgetItem(str(sec.get("address", ""))))
            self._mod_detail_table.setItem(row, 2, QTableWidgetItem(str(sec.get("size", ""))))
            self._mod_detail_table.setItem(row, 3, QTableWidgetItem(str(sec.get("characteristics", ""))))

    def _on_show_module_exports(self) -> None:
        """Show exports for the selected module."""
        row = self._module_table.currentRow()
        if row < 0 or self._bridge is None:
            return

        name_item = self._module_table.item(row, 0)
        if name_item is None:
            return

        module_name = name_item.text()
        if not module_name:
            return

        self._mod_detail_table.setHorizontalHeaderLabels(_EXPORT_DETAIL_COLUMNS)
        self._mod_exports_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_module_exports(module_name),
            on_success=self._apply_module_exports,
            on_error=lambda e: self._on_mod_detail_error("exports", e),
            parent=self,
            event="x64dbg_get_module_exports",
            logger=_logger,
            module=module_name,
        )

    def _apply_module_exports(self, result: object) -> None:
        """Populate the detail table with export data.

        Args:
            result: Export list from the bridge.
        """
        self._mod_exports_btn.setEnabled(True)
        raw_exports: list[object] = [*result] if isinstance(result, list) else []
        exports: list[dict[str, object]] = [cast("dict[str, object]", e) for e in raw_exports if isinstance(e, dict)]
        self._mod_detail_table.setRowCount(0)
        for exp in exports:
            row = self._mod_detail_table.rowCount()
            self._mod_detail_table.insertRow(row)
            self._mod_detail_table.setItem(row, 0, QTableWidgetItem(str(exp.get("name", ""))))
            self._mod_detail_table.setItem(row, 1, QTableWidgetItem(str(exp.get("ordinal", ""))))
            self._mod_detail_table.setItem(row, 2, QTableWidgetItem(str(exp.get("address", ""))))

    def _on_mod_detail_error(self, detail_type: str, exc: object) -> None:
        """Handle module detail retrieval failure.

        Args:
            detail_type: Either "sections" or "exports".
            exc: The exception that occurred.
        """
        self._mod_sections_btn.setEnabled(True)
        self._mod_exports_btn.setEnabled(True)
        _logger.warning("x64dbg_module_detail_failed", detail_type=detail_type, error=str(exc))

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
            _logger.warning("invalid_register_value", register=reg_name, input_text=val_text)
            self._console_output.appendPlainText(f"[!] Invalid value for {reg_name}: {val_text}")
            return

        self._reg_table.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_register(reg_name, value),
            on_success=lambda _: self._on_reg_set_success(reg_name, value),
            on_error=lambda e: self._on_reg_set_error(reg_name, e),
            parent=self,
            event="x64dbg_set_register",
            logger=_logger,
            level="info",
            register=reg_name,
            value=hex(value),
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
        _logger.warning("x64dbg_set_register_failed", register=reg_name, error=str(exc))
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
            _logger.warning("invalid_memory_address", input_text=addr_text)
            self._console_output.appendPlainText(f"[!] Invalid address: {addr_text}")
            return

        try:
            size = int(size_text) if size_text else 256
        except ValueError:
            _logger.warning("invalid_memory_size_using_default", input_text=size_text)
            size = 256

        self._mem_read_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.read_memory(address, size),
            on_success=lambda r: self._on_mem_read_success(address, r),
            on_error=self._on_mem_read_error,
            parent=self,
            event="x64dbg_read_memory",
            logger=_logger,
            address=hex(address),
            size=size,
        )

    def _on_mem_read_success(self, address: int, result: object) -> None:
        """Handle successful memory read.

        Args:
            address: The read address.
            result: The memory data bytes.
        """
        data: bytes = result if isinstance(result, bytes) else b""
        self._mem_dump.setPlainText(format_hex_dump(data, address, address_prefix="0x"))
        self._mem_read_btn.setEnabled(True)

    def _on_mem_read_error(self, exc: object) -> None:
        """Handle memory read failure.

        Args:
            exc: The exception that occurred.
        """
        self._console_output.appendPlainText(f"[-] Memory read failed: {exc}")
        _logger.warning("x64dbg_mem_read_failed", error=str(exc))
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

        run_bridge_coroutine_logged(
            self._bridge.run_command(cmd),
            on_success=self._on_command_result,
            on_error=self._on_command_error,
            parent=self,
            event="x64dbg_run_command",
            logger=_logger,
            level="info",
            command=cmd,
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
        _logger.warning("x64dbg_command_failed", error=str(exc))

    def _refresh_state(self) -> None:
        """Refresh registers, modules, threads, and state after change."""
        self._refresh_registers()
        self._refresh_breakpoints()
        self._refresh_stack()
        self._refresh_modules()
        self._refresh_threads()
        self._refresh_watchpoints()
        self._refresh_memmap()

    def _refresh_registers(self) -> None:
        """Refresh the register table from bridge."""
        if self._bridge is None:
            return

        run_bridge_coroutine_logged(
            self._bridge.get_registers(),
            on_success=self._apply_registers,
            on_error=lambda _: _logger.warning("x64dbg_refresh_registers_failed"),
            parent=self,
            event="x64dbg_get_registers",
            logger=_logger,
        )

    def _apply_registers(self, result: object) -> None:
        """Apply register data to the table.

        Args:
            result: Register state from the bridge.
        """
        if result is None:
            return

        regs = result
        with QSignalBlocker(self._reg_table):
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

        if rip := getattr(regs, "rip", 0):
            self._refresh_disassembly(rip)

    def _refresh_disassembly(self, address: int) -> None:
        """Refresh disassembly view at the given address.

        Args:
            address: Start address for disassembly.
        """
        if self._bridge is None:
            return

        run_bridge_coroutine_logged(
            self._bridge.disassemble_at(address, 30),
            on_success=self._apply_disassembly,
            on_error=lambda _: _logger.warning("x64dbg_refresh_disasm_failed", address=hex(address)),
            parent=self,
            event="x64dbg_disassemble_at",
            logger=_logger,
            address=hex(address),
            count=30,
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

        run_bridge_coroutine_logged(
            self._bridge.get_breakpoints(),
            on_success=self._apply_breakpoints,
            on_error=lambda _: _logger.warning("x64dbg_refresh_breakpoints_failed"),
            parent=self,
            event="x64dbg_get_breakpoints",
            logger=_logger,
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

        run_bridge_coroutine_logged(
            self._bridge.get_stack_trace(),
            on_success=self._apply_stack,
            on_error=lambda _: _logger.warning("x64dbg_refresh_stack_failed"),
            parent=self,
            event="x64dbg_get_stack_trace",
            logger=_logger,
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

        run_bridge_coroutine_logged(
            self._bridge.get_modules(),
            on_success=self._apply_modules,
            on_error=lambda _: _logger.warning("x64dbg_refresh_modules_failed"),
            parent=self,
            event="x64dbg_get_modules",
            logger=_logger,
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

        run_bridge_coroutine_logged(
            self._bridge.get_threads(),
            on_success=self._apply_threads,
            on_error=lambda _: _logger.warning("x64dbg_refresh_threads_failed"),
            parent=self,
            event="x64dbg_get_threads",
            logger=_logger,
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

    def _on_generic_error(self, operation: str, exc: object, btn: QPushButton | None = None) -> None:
        """Handle a generic operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Optional button to re-enable.
        """
        self._console_output.appendPlainText(f"[-] {operation} failed: {exc}")
        _logger.warning("x64dbg_operation_failed", operation=operation, error=str(exc))
        if btn is not None:
            btn.setEnabled(True)

    def _on_detach(self) -> None:
        """Detach from the current process."""
        if self._bridge is None:
            return
        self._detach_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.detach(),
            on_success=lambda _: self._on_detach_success(),
            on_error=lambda e: self._on_generic_error("Detach", e, self._detach_btn),
            parent=self,
            event="x64dbg_detach",
            logger=_logger,
            level="info",
        )

    def _on_detach_success(self) -> None:
        """Handle successful detach."""
        self._set_status("Detached")
        self._console_output.appendPlainText("[+] Detached from process")
        self._detach_btn.setEnabled(True)

    def _on_spawn(self) -> None:
        """Spawn a new process for debugging."""
        if self._bridge is None:
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Spawn Process",
            "",
            "Executables (*.exe *.dll);;All Files (*)",
        )
        if not file_path:
            return
        self._spawn_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.spawn(Path(file_path)),
            on_success=lambda r: self._on_spawn_success(file_path, r),
            on_error=lambda e: self._on_generic_error("Spawn", e, self._spawn_btn),
            parent=self,
            event="x64dbg_spawn",
            logger=_logger,
            level="info",
            file_path=file_path,
        )

    def _on_spawn_success(self, path: str, result: object) -> None:
        """Handle successful spawn.

        Args:
            path: Spawned executable path.
            result: PID result from bridge.
        """
        pid = result if isinstance(result, int) else 0
        self._set_status(f"Spawned: PID {pid}")
        self._console_output.appendPlainText(f"[+] Spawned {path} (PID {pid})")
        self._spawn_btn.setEnabled(True)
        self._refresh_state()

    def _on_run_to(self) -> None:
        """Run to a specific address."""
        if self._bridge is None:
            return
        addr_text = self._run_to_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_run_to_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.run_to(address),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Running to {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Run To", e),
            parent=self,
            event="x64dbg_run_to",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_til_ret(self) -> None:
        """Execute until the current function returns."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.execute_til_return(),
            on_success=lambda _: self._console_output.appendPlainText("[+] Execute til return"),
            on_error=lambda e: self._on_generic_error("Til Return", e),
            parent=self,
            event="x64dbg_execute_til_return",
            logger=_logger,
            level="info",
        )

    def _on_skip(self) -> None:
        """Skip the current instruction."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.skip_instruction(),
            on_success=self._on_skip_success,
            on_error=lambda e: self._on_generic_error("Skip", e),
            parent=self,
            event="x64dbg_skip_instruction",
            logger=_logger,
            level="info",
        )

    def _on_skip_success(self, result: object) -> None:
        """Handle successful instruction skip.

        Args:
            result: Skip result dict from bridge.
        """
        if isinstance(result, dict):
            r = cast("dict[str, object]", result)
            old_ip: object = r.get("old_ip", "?")
            new_ip: object = r.get("new_ip", "?")
            self._console_output.appendPlainText(f"[+] Skipped {old_ip} -> {new_ip}")
        self._refresh_state()

    def _on_set_ip(self) -> None:
        """Set the instruction pointer to a specific address."""
        if self._bridge is None:
            return
        addr_text = self._set_ip_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_set_ip_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.set_ip(address),
            on_success=lambda _: self._on_set_ip_success(address),
            on_error=lambda e: self._on_generic_error("Set IP", e),
            parent=self,
            event="x64dbg_set_ip",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_set_ip_success(self, address: int) -> None:
        """Handle successful IP set.

        Args:
            address: New instruction pointer value.
        """
        self._console_output.appendPlainText(f"[+] IP set to {hex(address)}")
        self._refresh_state()

    def _on_save_db(self) -> None:
        """Save the x64dbg database."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.save_database(),
            on_success=lambda _: self._console_output.appendPlainText("[+] Database saved"),
            on_error=lambda e: self._on_generic_error("Save DB", e),
            parent=self,
            event="x64dbg_save_database",
            logger=_logger,
            level="info",
        )

    def _on_load_db(self) -> None:
        """Load the x64dbg database."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.load_database(),
            on_success=lambda _: self._console_output.appendPlainText("[+] Database loaded"),
            on_error=lambda e: self._on_generic_error("Load DB", e),
            parent=self,
            event="x64dbg_load_database",
            logger=_logger,
            level="info",
        )

    def _on_add_watchpoint(self) -> None:
        """Add a watchpoint at the specified address."""
        if self._bridge is None:
            return
        addr_text = self._wp_addr_input.text().strip()
        size_text = self._wp_size_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_add_watchpoint_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        size = int(size_text) if size_text else 4
        wp_type_text = self._wp_type_combo.currentText()
        wp_type = cast(
            "MemoryProtection",
            wp_type_text if wp_type_text in {"read", "write", "execute"} else "write",
        )
        self._add_wp_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_watchpoint(address, size, wp_type),
            on_success=lambda r: self._on_wp_added(address, r),
            on_error=lambda e: self._on_generic_error("Add WP", e, self._add_wp_btn),
            parent=self,
            event="x64dbg_set_watchpoint",
            logger=_logger,
            level="info",
            address=hex(address),
            size=size,
            wp_type=wp_type,
        )

    def _on_wp_added(self, address: int, result: object) -> None:
        """Handle successful watchpoint addition.

        Args:
            address: Watchpoint address.
            result: Watchpoint ID from bridge.
        """
        self._console_output.appendPlainText(f"[+] Watchpoint #{result} set at 0x{address:X}")
        self._add_wp_btn.setEnabled(True)
        self._refresh_watchpoints()

    def _on_remove_watchpoint(self) -> None:
        """Remove the selected watchpoint."""
        row = self._wp_table.currentRow()
        if row < 0 or self._bridge is None:
            return
        addr_item = self._wp_table.item(row, 0)
        if addr_item is None:
            return
        self._remove_wp_btn.setEnabled(False)
        try:
            wp_id = int(addr_item.data(Qt.ItemDataRole.UserRole) or 0)
        except (TypeError, ValueError):
            self._invalid_input(
                "x64dbg_remove_watchpoint_invalid_id",
                input_text=str(addr_item.data(Qt.ItemDataRole.UserRole)),
                console_msg=f"[!] Invalid watchpoint ID: {addr_item.data(Qt.ItemDataRole.UserRole)}",
                logger=_logger,
            )
            self._remove_wp_btn.setEnabled(True)
            return
        run_bridge_coroutine_logged(
            self._bridge.remove_watchpoint(wp_id),
            on_success=lambda _: self._on_wp_removed(),
            on_error=lambda e: self._on_generic_error("Remove WP", e, self._remove_wp_btn),
            parent=self,
            event="x64dbg_remove_watchpoint",
            logger=_logger,
            level="info",
            wp_id=wp_id,
        )

    def _on_wp_removed(self) -> None:
        """Handle successful watchpoint removal."""
        self._console_output.appendPlainText("[+] Watchpoint removed")
        self._remove_wp_btn.setEnabled(True)
        self._refresh_watchpoints()

    def _on_search(self) -> None:
        """Search memory for a pattern."""
        if self._bridge is None:
            return
        pattern = self._search_pattern_input.text().strip()
        if not pattern:
            return
        mode = self._search_mode_combo.currentText()
        self._search_btn.setEnabled(False)
        if mode == "YARA":
            run_bridge_coroutine_logged(
                self._bridge.yara_scan(rule_text=pattern),
                on_success=self._on_search_complete,
                on_error=lambda e: self._on_generic_error("Search", e, self._search_btn),
                parent=self,
                event="x64dbg_yara_scan",
                logger=_logger,
                rule_length=len(pattern),
            )
        else:
            run_bridge_coroutine_logged(
                self._bridge.find_pattern(pattern),
                on_success=self._on_search_complete,
                on_error=lambda e: self._on_generic_error("Search", e, self._search_btn),
                parent=self,
                event="x64dbg_find_pattern",
                logger=_logger,
                pattern_length=len(pattern),
            )

    def _on_search_complete(self, result: object) -> None:
        """Handle search completion.

        Args:
            result: Search results from bridge.
        """
        self._search_btn.setEnabled(True)
        results: list[object] = [*result] if isinstance(result, list) else []
        self._search_table.setRowCount(0)
        for i, match in enumerate(results):
            row = self._search_table.rowCount()
            self._search_table.insertRow(row)
            self._search_table.setItem(row, 0, QTableWidgetItem(str(i)))
            if isinstance(match, dict):
                md = cast("dict[str, object]", match)
                self._search_table.setItem(row, 1, QTableWidgetItem(str(md.get("address", ""))))
                self._search_table.setItem(row, 2, QTableWidgetItem(str(md.get("matched_bytes", ""))))
                self._search_table.setItem(row, 3, QTableWidgetItem(str(md.get("context_before", ""))))
        self._console_output.appendPlainText(f"[+] Search found {len(results)} matches")

    def _on_trace_start(self) -> None:
        """Start trace recording."""
        if self._bridge is None:
            return
        condition = self._trace_cond_input.text().strip() or None
        log_text = self._trace_log_input.text().strip() or None
        run_bridge_coroutine_logged(
            self._bridge.trace_start(condition=condition, log_text=log_text),
            on_success=lambda _: self._trace_output.appendPlainText("[+] Trace started"),
            on_error=lambda e: self._on_generic_error("Trace Start", e),
            parent=self,
            event="x64dbg_trace_start",
            logger=_logger,
            level="info",
            condition=condition,
        )

    def _on_trace_stop(self) -> None:
        """Stop trace recording."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.trace_stop(),
            on_success=lambda _: self._trace_output.appendPlainText("[+] Trace stopped"),
            on_error=lambda e: self._on_generic_error("Trace Stop", e),
            parent=self,
            event="x64dbg_trace_stop",
            logger=_logger,
            level="info",
        )

    def _on_trace_into(self) -> None:
        """Start trace into."""
        if self._bridge is None:
            return
        condition = self._trace_cond_input.text().strip() or None
        run_bridge_coroutine_logged(
            self._bridge.trace_into(condition=condition),
            on_success=lambda _: self._trace_output.appendPlainText("[+] Trace into started"),
            on_error=lambda e: self._on_generic_error("Trace Into", e),
            parent=self,
            event="x64dbg_trace_into",
            logger=_logger,
            level="info",
            condition=condition,
        )

    def _on_trace_over(self) -> None:
        """Start trace over."""
        if self._bridge is None:
            return
        condition = self._trace_cond_input.text().strip() or None
        run_bridge_coroutine_logged(
            self._bridge.trace_over(condition=condition),
            on_success=lambda _: self._trace_output.appendPlainText("[+] Trace over started"),
            on_error=lambda e: self._on_generic_error("Trace Over", e),
            parent=self,
            event="x64dbg_trace_over",
            logger=_logger,
            level="info",
            condition=condition,
        )

    def _on_set_label(self) -> None:
        """Set a label at the specified address."""
        if self._bridge is None:
            return
        addr_text = self._lbl_addr_input.text().strip()
        label_text = self._lbl_text_input.text().strip()
        if not addr_text or not label_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_set_label_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.set_label(address, label_text),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Label set at {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Set Label", e),
            parent=self,
            event="x64dbg_set_label",
            logger=_logger,
            level="info",
            address=hex(address),
            label=label_text,
        )

    def _on_set_comment_btn(self) -> None:
        """Set a comment at the specified address."""
        if self._bridge is None:
            return
        addr_text = self._cmt_addr_input.text().strip()
        comment_text = self._cmt_text_input.text().strip()
        if not addr_text or not comment_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_set_comment_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.set_comment(address, comment_text),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Comment set at {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Set Comment", e),
            parent=self,
            event="x64dbg_set_comment",
            logger=_logger,
            level="info",
            address=hex(address),
            comment_length=len(comment_text),
        )

    def _on_refresh_memmap(self) -> None:
        """Refresh the memory map table."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_memory_regions(),
            on_success=self._apply_memmap,
            on_error=lambda _: _logger.warning("x64dbg_refresh_memmap_failed"),
            parent=self,
            event="x64dbg_get_memory_regions",
            logger=_logger,
        )

    def _apply_memmap(self, result: object) -> None:
        """Apply memory map data to the table.

        Args:
            result: Memory regions list from bridge.
        """
        regions: list[object] = [*result] if isinstance(result, list) else []
        self._mmap_table.setRowCount(0)
        for region in regions:
            row = self._mmap_table.rowCount()
            self._mmap_table.insertRow(row)
            self._mmap_table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(region, 'base_address', 0):X}"))
            self._mmap_table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(region, 'size', 0):X}"))
            self._mmap_table.setItem(row, 2, QTableWidgetItem(getattr(region, "protection", "")))
            self._mmap_table.setItem(row, 3, QTableWidgetItem(getattr(region, "state", "")))
            self._mmap_table.setItem(row, 4, QTableWidgetItem(getattr(region, "type", "")))
            self._mmap_table.setItem(row, 5, QTableWidgetItem(getattr(region, "module_name", "") or ""))

    def _on_dump_memmap_region(self) -> None:
        """Dump the selected memory map region to a file."""
        row = self._mmap_table.currentRow()
        if row < 0 or self._bridge is None:
            return
        base_item = self._mmap_table.item(row, 0)
        size_item = self._mmap_table.item(row, 1)
        if base_item is None or size_item is None:
            return
        try:
            base = int(base_item.text(), 16)
            size = int(size_item.text(), 16)
        except ValueError:
            _logger.warning(
                "x64dbg_dump_memmap_region_invalid_values",
                base_text=base_item.text(),
                size_text=size_item.text(),
            )
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Memory Dump", "", "Binary Files (*.bin);;All Files (*)")
        if not path:
            return
        run_bridge_coroutine_logged(
            self._bridge.dump_memory_to_file(base, size, path),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Dumped {size} bytes to {path}"),
            on_error=lambda e: self._on_generic_error("Dump Region", e),
            parent=self,
            event="x64dbg_dump_memory_region",
            logger=_logger,
            level="info",
            address=hex(base),
            size=size,
            path=path,
        )

    def _on_alloc_memory(self) -> None:
        """Allocate memory in the target process."""
        if self._bridge is None:
            return
        size_text = self._alloc_size_input.text().strip()
        if not size_text:
            return
        try:
            size = int(size_text)
        except ValueError:
            _logger.warning("x64dbg_alloc_memory_invalid_size", input_text=size_text)
            return
        prot = self._alloc_prot_combo.currentText()
        run_bridge_coroutine_logged(
            self._bridge.allocate_memory(size, prot),
            on_success=lambda r: self._console_output.appendPlainText(f"[+] Allocated at {hex(r) if isinstance(r, int) else r}"),
            on_error=lambda e: self._on_generic_error("Alloc", e),
            parent=self,
            event="x64dbg_allocate_memory",
            logger=_logger,
            level="info",
            size=size,
            protection=prot,
        )

    def _on_free_memory(self) -> None:
        """Free memory in the target process."""
        if self._bridge is None:
            return
        addr_text = self._free_addr_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_free_memory_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.free_memory(address),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Freed {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Free", e),
            parent=self,
            event="x64dbg_free_memory",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_refresh_procinfo(self) -> None:
        """Refresh process information."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_process_info(),
            on_success=self._apply_procinfo,
            on_error=lambda _: _logger.warning("x64dbg_refresh_procinfo_failed"),
            parent=self,
            event="x64dbg_get_process_info",
            logger=_logger,
        )

    def _apply_procinfo(self, result: object) -> None:
        """Apply process info to the form labels.

        Args:
            result: ProcessInfo from bridge.
        """
        if result is None:
            return
        self._procinfo_pid.setText(str(getattr(result, "pid", "--")))
        self._procinfo_name.setText(str(getattr(result, "name", "--")))
        path = getattr(result, "path", None)
        self._procinfo_path.setText(str(path) if path else "--")
        self._procinfo_cmdline.setText(str(getattr(result, "command_line", None) or "--"))
        self._procinfo_ppid.setText(str(getattr(result, "parent_pid", "--")))

    def _on_set_api_bp(self) -> None:
        """Set a breakpoint on an API function."""
        if self._bridge is None:
            return
        module = self._bp_mod_input.text().strip()
        function = self._bp_func_input.text().strip()
        if not module or not function:
            self._console_output.appendPlainText("[!] Enter module and function name")
            return
        run_bridge_coroutine_logged(
            self._bridge.set_breakpoint_on_api(module, function),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] API BP set on {module}.{function}"),
            on_error=lambda e: self._on_generic_error("API BP", e),
            parent=self,
            event="x64dbg_set_breakpoint_on_api",
            logger=_logger,
            level="info",
            module=module,
            function=function,
        )

    def _on_dump_memory(self) -> None:
        """Dump the current memory view to a file."""
        if self._bridge is None:
            return
        addr_text = self._mem_addr_input.text().strip()
        size_text = self._mem_size_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
            size = int(size_text) if size_text else 256
        except ValueError:
            _logger.warning(
                "x64dbg_dump_memory_invalid_values",
                address_text=addr_text,
                size_text=size_text,
            )
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Memory Dump", "", "Binary Files (*.bin);;All Files (*)")
        if not path:
            return
        run_bridge_coroutine_logged(
            self._bridge.dump_memory_to_file(address, size, path),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Dumped to {path}"),
            on_error=lambda e: self._on_generic_error("Dump", e),
            parent=self,
            event="x64dbg_dump_memory_to_file",
            logger=_logger,
            level="info",
            address=hex(address),
            size=size,
            path=path,
        )

    def _on_write_memory(self) -> None:
        """Write hex data to the current memory address."""
        if self._bridge is None:
            return
        addr_text = self._mem_addr_input.text().strip()
        data_text = self._mem_write_data_input.text().strip()
        if not addr_text or not data_text:
            return
        try:
            address = int(addr_text, 0)
            data = bytes.fromhex(data_text.replace(" ", ""))
        except ValueError:
            self._invalid_input(
                "x64dbg_write_memory_invalid_input",
                input_text=f"{addr_text} | {data_text}",
                console_msg="[!] Invalid address or hex data",
                logger=_logger,
                address_text=addr_text,
                data_text=data_text,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.write_memory(address, data),
            on_success=lambda r: self._console_output.appendPlainText(f"[+] Wrote {r} bytes at {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Write", e),
            parent=self,
            event="x64dbg_write_memory",
            logger=_logger,
            level="info",
            address=hex(address),
            size=len(data),
        )

    def _on_assemble(self) -> None:
        """Assemble an instruction at the current address."""
        if self._bridge is None:
            return
        addr_text = self._mem_addr_input.text().strip()
        instr = self._asm_instr_input.text().strip()
        if not addr_text or not instr:
            return
        try:
            address = int(addr_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_assemble_invalid_address",
                input_text=addr_text,
                console_msg=f"[!] Invalid address: {addr_text}",
                logger=_logger,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.patch_instruction(address, instr),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Assembled '{instr}' at {hex(address)}"),
            on_error=lambda e: self._on_generic_error("Assemble", e),
            parent=self,
            event="x64dbg_patch_instruction",
            logger=_logger,
            level="info",
            address=hex(address),
            instruction=instr,
        )

    def _on_nop_range(self) -> None:
        """NOP a range of bytes at the current address."""
        if self._bridge is None:
            return
        addr_text = self._mem_addr_input.text().strip()
        size_text = self._nop_size_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 0)
            size = int(size_text) if size_text else 1
        except ValueError:
            _logger.warning(
                "x64dbg_nop_range_invalid_values",
                address_text=addr_text,
                size_text=size_text,
            )
            return
        run_bridge_coroutine_logged(
            self._bridge.nop_range(address, size),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] NOPed {size} bytes at {hex(address)}"),
            on_error=lambda e: self._on_generic_error("NOP", e),
            parent=self,
            event="x64dbg_nop_range",
            logger=_logger,
            level="info",
            address=hex(address),
            size=size,
        )

    def _on_suspend_thread(self) -> None:
        """Suspend the selected thread."""
        if self._bridge is None:
            return
        row = self._thread_table.currentRow()
        if row < 0:
            return
        tid_item = self._thread_table.item(row, 0)
        if tid_item is None:
            return
        try:
            tid = int(tid_item.text())
        except ValueError:
            _logger.warning("x64dbg_suspend_thread_invalid_tid", input_text=tid_item.text())
            return
        run_bridge_coroutine_logged(
            self._bridge.suspend_thread(tid),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Thread {tid} suspended"),
            on_error=lambda e: self._on_generic_error("Suspend Thread", e),
            parent=self,
            event="x64dbg_suspend_thread",
            logger=_logger,
            level="info",
            tid=tid,
        )

    def _on_resume_thread(self) -> None:
        """Resume the selected thread."""
        if self._bridge is None:
            return
        row = self._thread_table.currentRow()
        if row < 0:
            return
        tid_item = self._thread_table.item(row, 0)
        if tid_item is None:
            return
        try:
            tid = int(tid_item.text())
        except ValueError:
            _logger.warning("x64dbg_resume_thread_invalid_tid", input_text=tid_item.text())
            return
        run_bridge_coroutine_logged(
            self._bridge.resume_thread(tid),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Thread {tid} resumed"),
            on_error=lambda e: self._on_generic_error("Resume Thread", e),
            parent=self,
            event="x64dbg_resume_thread",
            logger=_logger,
            level="info",
            tid=tid,
        )

    def _on_switch_thread(self) -> None:
        """Switch to the selected thread."""
        if self._bridge is None:
            return
        row = self._thread_table.currentRow()
        if row < 0:
            return
        tid_item = self._thread_table.item(row, 0)
        if tid_item is None:
            return
        try:
            tid = int(tid_item.text())
        except ValueError:
            _logger.warning("x64dbg_switch_thread_invalid_tid", input_text=tid_item.text())
            return
        run_bridge_coroutine_logged(
            self._bridge.switch_thread(tid),
            on_success=lambda _: (self._console_output.appendPlainText(f"[+] Switched to thread {tid}"), self._refresh_state())[0],
            on_error=lambda e: self._on_generic_error("Switch Thread", e),
            parent=self,
            event="x64dbg_switch_thread",
            logger=_logger,
            level="info",
            tid=tid,
        )

    def _on_eval_expression(self) -> None:
        """Evaluate an expression."""
        if self._bridge is None:
            return
        if expr := self._eval_input.text().strip():
            run_bridge_coroutine_logged(
                self._bridge.evaluate_expression(expr),
                on_success=lambda r: self._console_output.appendPlainText(f"[+] {expr} = {hex(r) if isinstance(r, int) else r}"),
                on_error=lambda e: self._on_generic_error("Eval", e),
                parent=self,
                event="x64dbg_evaluate_expression",
                logger=_logger,
                expression=expr,
            )
        else:
            return

    def _on_set_exception_config(self) -> None:
        """Configure exception handling."""
        if self._bridge is None:
            return
        code_text = self._exc_code_input.text().strip()
        if not code_text:
            return
        try:
            code = int(code_text, 0)
        except ValueError:
            self._invalid_input(
                "x64dbg_set_exception_config_invalid_code",
                input_text=code_text,
                console_msg=f"[!] Invalid exception code: {code_text}",
                logger=_logger,
            )
            return
        handling = self._exc_handling_combo.currentText()
        run_bridge_coroutine_logged(
            self._bridge.set_exception_config(code, handling),
            on_success=lambda _: self._console_output.appendPlainText(f"[+] Exception {hex(code)} -> {handling}"),
            on_error=lambda e: self._on_generic_error("Exception Config", e),
            parent=self,
            event="x64dbg_set_exception_config",
            logger=_logger,
            level="info",
            exception_code=hex(code),
            handling=handling,
        )

    def _refresh_watchpoints(self) -> None:
        """Refresh the watchpoints table from bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_watchpoints(),
            on_success=self._apply_watchpoints,
            on_error=lambda _: _logger.warning("x64dbg_refresh_watchpoints_failed"),
            parent=self,
            event="x64dbg_get_watchpoints",
            logger=_logger,
        )

    def _apply_watchpoints(self, result: object) -> None:
        """Apply watchpoint data to the table.

        Args:
            result: Watchpoint list from bridge.
        """
        wps: list[object] = [*result] if isinstance(result, list) else []
        self._wp_table.setRowCount(0)
        for wp in wps:
            row = self._wp_table.rowCount()
            self._wp_table.insertRow(row)
            addr_item = QTableWidgetItem(f"0x{getattr(wp, 'address', 0):X}")
            addr_item.setData(Qt.ItemDataRole.UserRole, getattr(wp, "id", 0))
            self._wp_table.setItem(row, 0, addr_item)
            self._wp_table.setItem(row, 1, QTableWidgetItem(str(getattr(wp, "size", 0))))
            self._wp_table.setItem(row, 2, QTableWidgetItem(getattr(wp, "watch_type", "")))
            self._wp_table.setItem(row, 3, QTableWidgetItem("Yes" if getattr(wp, "enabled", False) else "No"))
            self._wp_table.setItem(row, 4, QTableWidgetItem(str(getattr(wp, "hit_count", 0))))

    def _refresh_memmap(self) -> None:
        """Refresh the memory map table from bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_memory_regions(),
            on_success=self._apply_memmap,
            on_error=lambda _: _logger.warning("x64dbg_refresh_memmap_failed"),
            parent=self,
            event="x64dbg_get_memory_regions",
            logger=_logger,
        )
