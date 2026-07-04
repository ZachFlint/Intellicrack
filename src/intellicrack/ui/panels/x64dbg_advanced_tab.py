# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Advanced x64dbg controls not covered by the primary inspection tabs.

Hosts module import/entry-point/PE-directory lookups, process-structure readers (PEB/TEB/SEH), watch expressions, breakpoint-property
configuration, cross-reference discovery, handle enumeration, and the script/plugin engines behind a single "Advanced" tab so
``x64dbg_panel.py`` only needs a small integration edit to surface them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.x64dbg import X64DbgBridge

_logger = get_logger(__name__)

_MARGIN: Final[int] = 4
_SPACING: Final[int] = 4
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160

_MODINFO_IMPORT_COLUMNS: Final[list[str]] = ["Name", "Ordinal", "IAT RVA", "IAT VA"]
_MODINFO_PEDIR_COLUMNS: Final[list[str]] = ["Index", "Name", "RVA", "Size"]
_WATCH_COLUMNS: Final[list[str]] = ["Index", "Expression", "Value"]
_XREF_COLUMNS: Final[list[str]] = ["#", "Reference"]
_HANDLE_COLUMNS: Final[list[str]] = ["Handle", "Object", "Granted Access", "Type Index", "Attributes"]
_PLUGIN_COLUMNS: Final[list[str]] = ["Name", "Path", "Loaded"]


class X64DbgAdvancedTab(QWidget):
    """Advanced x64dbg tab: module info, process structures, watches, xrefs, handles, script/plugin engines."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the advanced tab widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: X64DbgBridge | None = None
        self._setup_ui()

    def set_bridge(self, bridge: X64DbgBridge | None) -> None:
        """Set the active X64DbgBridge instance.

        Args:
            bridge: The bridge to use for subsequent operations, or None to clear it.
        """
        self._bridge = bridge

    def _setup_ui(self) -> None:
        """Build the advanced tab's sub-tab layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        sub_tabs = QTabWidget()
        sub_tabs.addTab(self._build_module_info_tab(), self.tr("Module Info"))
        sub_tabs.addTab(self._build_process_structures_tab(), self.tr("Process Structures"))
        sub_tabs.addTab(self._build_watches_tab(), self.tr("Watches"))
        sub_tabs.addTab(self._build_breakpoint_config_tab(), self.tr("BP Config"))
        sub_tabs.addTab(self._build_xref_tab(), self.tr("Cross-References"))
        sub_tabs.addTab(self._build_handles_tab(), self.tr("Handles"))
        sub_tabs.addTab(self._build_script_tab(), self.tr("Script"))
        sub_tabs.addTab(self._build_plugin_tab(), self.tr("Plugins"))
        layout.addWidget(sub_tabs)

    # -- Module Info: imports, entry point, PE directories -----------------

    def _build_module_info_tab(self) -> QWidget:
        """Build the module-info sub-tab (imports, entry point, PE directories).

        Returns:
            QWidget: Module info tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        toolbar = QHBoxLayout()
        mod_label = QLabel(self.tr("Module:"))
        mod_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(mod_label)
        self._modinfo_name_input = QLineEdit()
        self._modinfo_name_input.setMaximumWidth(160)
        self._modinfo_name_input.setPlaceholderText("kernel32.dll")
        toolbar.addWidget(self._modinfo_name_input)
        self._modinfo_imports_btn = QPushButton(self.tr("Imports"))
        self._modinfo_imports_btn.setObjectName("tool_button")
        self._modinfo_imports_btn.clicked.connect(self._on_get_module_imports)
        toolbar.addWidget(self._modinfo_imports_btn)
        self._modinfo_entry_btn = QPushButton(self.tr("Entry Point"))
        self._modinfo_entry_btn.setObjectName("tool_button")
        self._modinfo_entry_btn.clicked.connect(self._on_get_entry_point)
        toolbar.addWidget(self._modinfo_entry_btn)
        self._modinfo_pedirs_btn = QPushButton(self.tr("PE Directories"))
        self._modinfo_pedirs_btn.setObjectName("tool_button")
        self._modinfo_pedirs_btn.clicked.connect(self._on_get_pe_directories)
        toolbar.addWidget(self._modinfo_pedirs_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._modinfo_entry_label = QLabel(self.tr("Entry point: --"))
        layout.addWidget(self._modinfo_entry_label)

        self._modinfo_table = QTableWidget(0, len(_MODINFO_IMPORT_COLUMNS))
        self._modinfo_table.setHorizontalHeaderLabels(_MODINFO_IMPORT_COLUMNS)
        self._modinfo_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._apply_modinfo_resize_modes(name_column=0)
        layout.addWidget(self._modinfo_table)
        return container

    def _apply_modinfo_resize_modes(self, name_column: int) -> None:
        """Configure the module-info table's column resize modes.

        Stretches the variable-length "Name" column and resizes the
        remaining fixed-format columns to fit their content.

        Args:
            name_column: Index of the variable-length "Name" column for the
                currently displayed view (imports or PE directories).
        """
        modinfo_h = self._modinfo_table.horizontalHeader()
        if modinfo_h is None:
            return
        for column in range(self._modinfo_table.columnCount()):
            mode = QHeaderView.ResizeMode.Stretch if column == name_column else QHeaderView.ResizeMode.ResizeToContents
            modinfo_h.setSectionResizeMode(column, mode)

    def _modinfo_module_name(self) -> str | None:
        """Read and validate the module-name field.

        Returns:
            str | None: The trimmed module name, or None if empty.
        """
        name = self._modinfo_name_input.text().strip()
        return name or None

    def _on_get_module_imports(self) -> None:
        """Fetch and display the import table of the specified module."""
        if self._bridge is None:
            return
        module_name = self._modinfo_module_name()
        if module_name is None:
            return
        self._modinfo_table.setHorizontalHeaderLabels(_MODINFO_IMPORT_COLUMNS)
        self._apply_modinfo_resize_modes(name_column=0)
        self._modinfo_imports_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_module_imports(module_name),
            on_success=self._apply_module_imports,
            on_error=lambda e: self._on_modinfo_error("imports", e),
            parent=self,
            event="x64dbg_get_module_imports",
            logger=_logger,
            module=module_name,
        )

    def _apply_module_imports(self, result: object) -> None:
        """Populate the module-info table with import entries.

        Args:
            result: Import dict list from the bridge.
        """
        self._modinfo_imports_btn.setEnabled(True)
        raw_imports: list[object] = [*result] if isinstance(result, list) else []
        imports: list[dict[str, object]] = [cast("dict[str, object]", entry) for entry in raw_imports if isinstance(entry, dict)]
        self._modinfo_table.setRowCount(0)
        for entry in imports:
            row = self._modinfo_table.rowCount()
            self._modinfo_table.insertRow(row)
            name = str(entry.get("undecoratedName") or entry.get("name", ""))
            name_item = QTableWidgetItem(name)
            name_item.setToolTip(name)
            self._modinfo_table.setItem(row, 0, name_item)
            self._modinfo_table.setItem(row, 1, QTableWidgetItem(str(entry.get("ordinal", ""))))
            self._modinfo_table.setItem(row, 2, QTableWidgetItem(str(entry.get("iatRva", ""))))
            self._modinfo_table.setItem(row, 3, QTableWidgetItem(str(entry.get("iatVa", ""))))

    def _on_get_entry_point(self) -> None:
        """Fetch and display the module's PE entry point."""
        if self._bridge is None:
            return
        module_name = self._modinfo_module_name()
        self._modinfo_entry_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_entry_point(module_name),
            on_success=self._apply_entry_point,
            on_error=lambda e: self._on_modinfo_error("entry_point", e),
            parent=self,
            event="x64dbg_get_entry_point",
            logger=_logger,
            module=module_name or "<attached>",
        )

    def _apply_entry_point(self, result: object) -> None:
        """Display the resolved module entry point.

        Args:
            result: Entry-point dict from the bridge.
        """
        self._modinfo_entry_btn.setEnabled(True)
        if not isinstance(result, dict):
            return
        entry: dict[str, object] = cast("dict[str, object]", result)
        module = entry.get("module", "")
        base = entry.get("base_address", "")
        rva = entry.get("entry_point_rva", "")
        va = entry.get("entry_point_va", "")
        self._modinfo_entry_label.setText(f"Entry point: {module} base={base} rva={rva} va={va}")

    def _on_get_pe_directories(self) -> None:
        """Fetch and display the module's PE data directories."""
        if self._bridge is None:
            return
        module_name = self._modinfo_module_name()
        if module_name is None:
            return
        self._modinfo_table.setHorizontalHeaderLabels(_MODINFO_PEDIR_COLUMNS)
        self._apply_modinfo_resize_modes(name_column=1)
        self._modinfo_pedirs_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_pe_directories(module_name),
            on_success=self._apply_pe_directories,
            on_error=lambda e: self._on_modinfo_error("pe_directories", e),
            parent=self,
            event="x64dbg_get_pe_directories",
            logger=_logger,
            module=module_name,
        )

    def _apply_pe_directories(self, result: object) -> None:
        """Populate the module-info table with PE data directory entries.

        Args:
            result: Directory-entry dict list from the bridge.
        """
        self._modinfo_pedirs_btn.setEnabled(True)
        raw_dirs: list[object] = [*result] if isinstance(result, list) else []
        directories: list[dict[str, object]] = [cast("dict[str, object]", entry) for entry in raw_dirs if isinstance(entry, dict)]
        self._modinfo_table.setRowCount(0)
        for entry in directories:
            row = self._modinfo_table.rowCount()
            self._modinfo_table.insertRow(row)
            self._modinfo_table.setItem(row, 0, QTableWidgetItem(str(entry.get("index", ""))))
            name = str(entry.get("name", ""))
            name_item = QTableWidgetItem(name)
            name_item.setToolTip(name)
            self._modinfo_table.setItem(row, 1, name_item)
            self._modinfo_table.setItem(row, 2, QTableWidgetItem(str(entry.get("rva", ""))))
            self._modinfo_table.setItem(row, 3, QTableWidgetItem(str(entry.get("size", ""))))

    def _on_modinfo_error(self, operation: str, exc: object) -> None:
        """Handle a module-info operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
        """
        self._modinfo_imports_btn.setEnabled(True)
        self._modinfo_entry_btn.setEnabled(True)
        self._modinfo_pedirs_btn.setEnabled(True)
        _logger.warning("x64dbg_modinfo_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Module Info Error"), str(exc))

    # -- Process Structures: PEB / TEB / SEH --------------------------------

    def _build_process_structures_tab(self) -> QWidget:
        """Build the process-structures sub-tab (PEB/TEB/SEH readers).

        Returns:
            QWidget: Process structures tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        toolbar = QHBoxLayout()
        self._peb_btn = QPushButton(self.tr("Read PEB"))
        self._peb_btn.setObjectName("tool_button")
        self._peb_btn.clicked.connect(self._on_read_peb)
        toolbar.addWidget(self._peb_btn)
        teb_tid_label = QLabel(self.tr("TID (optional):"))
        teb_tid_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(teb_tid_label)
        self._teb_tid_input = QLineEdit()
        self._teb_tid_input.setMaximumWidth(100)
        self._teb_tid_input.setPlaceholderText("current")
        toolbar.addWidget(self._teb_tid_input)
        self._teb_btn = QPushButton(self.tr("Read TEB"))
        self._teb_btn.setObjectName("tool_button")
        self._teb_btn.clicked.connect(self._on_read_teb)
        toolbar.addWidget(self._teb_btn)
        self._seh_btn = QPushButton(self.tr("SEH Chain"))
        self._seh_btn.setObjectName("tool_button")
        self._seh_btn.clicked.connect(self._on_get_seh_chain)
        toolbar.addWidget(self._seh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._procstruct_table = QTableWidget(0, 2)
        self._procstruct_table.setHorizontalHeaderLabels(["Field", "Value"])
        procstruct_h = self._procstruct_table.horizontalHeader()
        if procstruct_h is not None:
            procstruct_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._procstruct_table)
        return container

    def _fill_struct_table(self, fields: dict[str, object]) -> None:
        """Replace the process-structure table contents with a field/value dict.

        Args:
            fields: Structure field names mapped to their values.
        """
        self._procstruct_table.setRowCount(0)
        for key, value in fields.items():
            row = self._procstruct_table.rowCount()
            self._procstruct_table.insertRow(row)
            self._procstruct_table.setItem(row, 0, QTableWidgetItem(str(key)))
            self._procstruct_table.setItem(row, 1, QTableWidgetItem(str(value)))

    def _on_read_peb(self) -> None:
        """Read and display the Process Environment Block."""
        if self._bridge is None:
            return
        self._peb_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.read_peb(),
            on_success=self._apply_peb,
            on_error=lambda e: self._on_procstruct_error("peb", e, self._peb_btn),
            parent=self,
            event="x64dbg_read_peb",
            logger=_logger,
        )

    def _apply_peb(self, result: object) -> None:
        """Populate the structure table with PEB fields.

        Args:
            result: PEB field dict from the bridge.
        """
        self._peb_btn.setEnabled(True)
        if isinstance(result, dict):
            self._fill_struct_table(cast("dict[str, object]", result))

    def _on_read_teb(self) -> None:
        """Read and display the Thread Environment Block."""
        if self._bridge is None:
            return
        tid_text = self._teb_tid_input.text().strip()
        tid: int | None = None
        if tid_text:
            try:
                tid = int(tid_text, 0)
            except ValueError:
                _logger.warning("x64dbg_read_teb_invalid_tid", input_text=tid_text)
                QMessageBox.warning(self, self.tr("Read TEB"), self.tr("Invalid thread ID: {0}").format(tid_text))
                return
        self._teb_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.read_teb(tid),
            on_success=self._apply_teb,
            on_error=lambda e: self._on_procstruct_error("teb", e, self._teb_btn),
            parent=self,
            event="x64dbg_read_teb",
            logger=_logger,
            tid=tid,
        )

    def _apply_teb(self, result: object) -> None:
        """Populate the structure table with TEB fields.

        Args:
            result: TEB field dict from the bridge.
        """
        self._teb_btn.setEnabled(True)
        if isinstance(result, dict):
            self._fill_struct_table(cast("dict[str, object]", result))

    def _on_get_seh_chain(self) -> None:
        """Read and display the structured exception handler chain."""
        if self._bridge is None:
            return
        self._seh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_seh_chain(),
            on_success=self._apply_seh_chain,
            on_error=lambda e: self._on_procstruct_error("seh_chain", e, self._seh_btn),
            parent=self,
            event="x64dbg_get_seh_chain",
            logger=_logger,
        )

    def _apply_seh_chain(self, result: object) -> None:
        """Populate the structure table with SEH chain entries.

        Args:
            result: SEH entry dict list from the bridge.
        """
        self._seh_btn.setEnabled(True)
        raw_entries: list[object] = [*result] if isinstance(result, list) else []
        self._procstruct_table.setRowCount(0)
        for index, entry in enumerate(raw_entries):
            if not isinstance(entry, dict):
                continue
            typed_entry: dict[str, object] = cast("dict[str, object]", entry)
            row = self._procstruct_table.rowCount()
            self._procstruct_table.insertRow(row)
            self._procstruct_table.setItem(row, 0, QTableWidgetItem(f"[{index}] handler"))
            self._procstruct_table.setItem(row, 1, QTableWidgetItem(str(typed_entry.get("handler", ""))))
            row = self._procstruct_table.rowCount()
            self._procstruct_table.insertRow(row)
            self._procstruct_table.setItem(row, 0, QTableWidgetItem(f"[{index}] next"))
            self._procstruct_table.setItem(row, 1, QTableWidgetItem(str(typed_entry.get("next", ""))))

    def _on_procstruct_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a process-structure read failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_procstruct_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Process Structure Error"), str(exc))

    # -- Watch expressions ---------------------------------------------------

    def _build_watches_tab(self) -> QWidget:
        """Build the watch-expression sub-tab.

        Returns:
            QWidget: Watches tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        toolbar = QHBoxLayout()
        expr_label = QLabel(self.tr("Expression:"))
        expr_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(expr_label)
        self._watch_expr_input = QLineEdit()
        self._watch_expr_input.setMinimumWidth(180)
        self._watch_expr_input.setPlaceholderText("[rsp]")
        toolbar.addWidget(self._watch_expr_input)
        self._watch_add_btn = QPushButton(self.tr("Add"))
        self._watch_add_btn.setObjectName("tool_button")
        self._watch_add_btn.clicked.connect(self._on_add_watch)
        toolbar.addWidget(self._watch_add_btn)
        self._watch_remove_btn = QPushButton(self.tr("Remove Selected"))
        self._watch_remove_btn.setObjectName("tool_button")
        self._watch_remove_btn.clicked.connect(self._on_remove_watch)
        toolbar.addWidget(self._watch_remove_btn)
        self._watch_refresh_btn = QPushButton(self.tr("Refresh"))
        self._watch_refresh_btn.setObjectName("tool_button")
        self._watch_refresh_btn.clicked.connect(self._on_refresh_watches)
        toolbar.addWidget(self._watch_refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._watch_table = QTableWidget(0, len(_WATCH_COLUMNS))
        self._watch_table.setHorizontalHeaderLabels(_WATCH_COLUMNS)
        self._watch_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._watch_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        watch_h = self._watch_table.horizontalHeader()
        if watch_h is not None:
            watch_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._watch_table)
        return container

    def _on_add_watch(self) -> None:
        """Add a watch expression."""
        if self._bridge is None:
            return
        expression = self._watch_expr_input.text().strip()
        if not expression:
            return
        self._watch_add_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.add_watch(expression),
            on_success=lambda _: self._on_watch_added(),
            on_error=lambda e: self._on_watch_error("add", e, self._watch_add_btn),
            parent=self,
            event="x64dbg_add_watch",
            logger=_logger,
            level="info",
            expression=expression,
        )

    def _on_watch_added(self) -> None:
        """Handle successful watch addition by clearing input and refreshing the list."""
        self._watch_add_btn.setEnabled(True)
        self._watch_expr_input.clear()
        self._on_refresh_watches()

    def _on_remove_watch(self) -> None:
        """Remove the selected watch expression."""
        if self._bridge is None:
            return
        row = self._watch_table.currentRow()
        if row < 0:
            return
        index_item = self._watch_table.item(row, 0)
        if index_item is None:
            return
        try:
            index = int(index_item.text())
        except ValueError:
            _logger.warning("x64dbg_remove_watch_invalid_index", input_text=index_item.text())
            return
        self._watch_remove_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.remove_watch(index),
            on_success=lambda _: self._on_watch_removed(),
            on_error=lambda e: self._on_watch_error("remove", e, self._watch_remove_btn),
            parent=self,
            event="x64dbg_remove_watch",
            logger=_logger,
            level="info",
            index=index,
        )

    def _on_watch_removed(self) -> None:
        """Handle successful watch removal by refreshing the list."""
        self._watch_remove_btn.setEnabled(True)
        self._on_refresh_watches()

    def _on_refresh_watches(self) -> None:
        """Refresh the watch-expression table from the bridge."""
        if self._bridge is None:
            return
        run_bridge_coroutine_logged(
            self._bridge.get_watches(),
            on_success=self._apply_watches,
            on_error=lambda e: self._on_watch_error("refresh", e, self._watch_refresh_btn),
            parent=self,
            event="x64dbg_get_watches",
            logger=_logger,
        )

    def _apply_watches(self, result: object) -> None:
        """Populate the watch table with expression/value entries.

        Args:
            result: Watch dict list from the bridge.
        """
        raw_watches: list[object] = [*result] if isinstance(result, list) else []
        watches: list[dict[str, object]] = [cast("dict[str, object]", entry) for entry in raw_watches if isinstance(entry, dict)]
        self._watch_table.setRowCount(0)
        for index, entry in enumerate(watches):
            row = self._watch_table.rowCount()
            self._watch_table.insertRow(row)
            self._watch_table.setItem(row, 0, QTableWidgetItem(str(entry.get("index", index))))
            self._watch_table.setItem(row, 1, QTableWidgetItem(str(entry.get("expression", ""))))
            self._watch_table.setItem(row, 2, QTableWidgetItem(str(entry.get("value", ""))))

    def _on_watch_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a watch-expression operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_watch_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Watch Error"), str(exc))

    # -- Breakpoint property configuration -----------------------------------

    def _build_breakpoint_config_tab(self) -> QWidget:
        """Build the breakpoint-configuration sub-tab.

        Returns:
            QWidget: Breakpoint config tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        addr_row = QHBoxLayout()
        addr_label = QLabel(self.tr("Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        addr_row.addWidget(addr_label)
        self._bpcfg_addr_input = QLineEdit()
        self._bpcfg_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._bpcfg_addr_input.setPlaceholderText("0x...")
        addr_row.addWidget(self._bpcfg_addr_input)
        addr_row.addStretch()
        layout.addLayout(addr_row)

        cond_row = QHBoxLayout()
        cond_label = QLabel(self.tr("Condition:"))
        cond_label.setFont(fm.get_ui_font(9))
        cond_row.addWidget(cond_label)
        self._bpcfg_cond_input = QLineEdit()
        self._bpcfg_cond_input.setPlaceholderText("eax == 1")
        cond_row.addWidget(self._bpcfg_cond_input)
        layout.addLayout(cond_row)

        log_row = QHBoxLayout()
        log_label = QLabel(self.tr("Log Text:"))
        log_label.setFont(fm.get_ui_font(9))
        log_row.addWidget(log_label)
        self._bpcfg_log_input = QLineEdit()
        self._bpcfg_log_input.setPlaceholderText("{rax}")
        log_row.addWidget(self._bpcfg_log_input)
        layout.addLayout(log_row)

        cmd_row = QHBoxLayout()
        cmd_label = QLabel(self.tr("Command:"))
        cmd_label.setFont(fm.get_ui_font(9))
        cmd_row.addWidget(cmd_label)
        self._bpcfg_cmd_input = QLineEdit()
        self._bpcfg_cmd_input.setPlaceholderText('log "hit"')
        cmd_row.addWidget(self._bpcfg_cmd_input)
        layout.addLayout(cmd_row)

        fast_row = QHBoxLayout()
        self._bpcfg_fast_resume_combo = QComboBox()
        self._bpcfg_fast_resume_combo.addItems(["No Fast Resume", "Fast Resume"])
        fast_row.addWidget(self._bpcfg_fast_resume_combo)
        self._bpcfg_apply_btn = QPushButton(self.tr("Apply Configuration"))
        self._bpcfg_apply_btn.setObjectName("tool_button")
        self._bpcfg_apply_btn.clicked.connect(self._on_configure_breakpoint)
        fast_row.addWidget(self._bpcfg_apply_btn)
        fast_row.addStretch()
        layout.addLayout(fast_row)

        log_bp_row = QHBoxLayout()
        self._bpcfg_logging_btn = QPushButton(self.tr("Set Logging BP (non-stopping)"))
        self._bpcfg_logging_btn.setObjectName("tool_button")
        self._bpcfg_logging_btn.clicked.connect(self._on_set_logging_breakpoint)
        log_bp_row.addWidget(self._bpcfg_logging_btn)
        log_bp_row.addStretch()
        layout.addLayout(log_bp_row)

        dll_row = QHBoxLayout()
        dll_label = QLabel(self.tr("DLL Name:"))
        dll_label.setFont(fm.get_ui_font(9))
        dll_row.addWidget(dll_label)
        self._bpcfg_dll_input = QLineEdit()
        self._bpcfg_dll_input.setMaximumWidth(160)
        self._bpcfg_dll_input.setPlaceholderText("ws2_32.dll")
        dll_row.addWidget(self._bpcfg_dll_input)
        self._bpcfg_dll_event_combo = QComboBox()
        self._bpcfg_dll_event_combo.addItems(["load", "unload"])
        dll_row.addWidget(self._bpcfg_dll_event_combo)
        self._bpcfg_dll_btn = QPushButton(self.tr("Set DLL BP"))
        self._bpcfg_dll_btn.setObjectName("tool_button")
        self._bpcfg_dll_btn.clicked.connect(self._on_set_dll_breakpoint)
        dll_row.addWidget(self._bpcfg_dll_btn)
        dll_row.addStretch()
        layout.addLayout(dll_row)

        self._bpcfg_status_label = QLabel("")
        self._bpcfg_status_label.setWordWrap(True)
        layout.addWidget(self._bpcfg_status_label)
        layout.addStretch()
        return container

    def _bpcfg_address(self) -> int | None:
        """Parse the breakpoint-config address field.

        Returns:
            int | None: Parsed address, or None if empty/invalid.
        """
        text = self._bpcfg_addr_input.text().strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            _logger.warning("x64dbg_bp_config_invalid_address", input_text=text)
            QMessageBox.warning(self, self.tr("Breakpoint Config"), self.tr("Invalid address: {0}").format(text))
            return None

    def _on_configure_breakpoint(self) -> None:
        """Apply condition/log/command/fast-resume properties to a breakpoint."""
        if self._bridge is None:
            return
        address = self._bpcfg_address()
        if address is None:
            return
        condition = self._bpcfg_cond_input.text().strip() or None
        log_text = self._bpcfg_log_input.text().strip() or None
        command = self._bpcfg_cmd_input.text().strip() or None
        fast_resume = self._bpcfg_fast_resume_combo.currentIndex() == 1
        self._bpcfg_apply_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.configure_breakpoint(
                address,
                condition=condition,
                log_text=log_text,
                command=command,
                fast_resume=fast_resume,
            ),
            on_success=lambda _: self._on_bpcfg_success(f"Breakpoint at 0x{address:X} configured", self._bpcfg_apply_btn),
            on_error=lambda e: self._on_bpcfg_error("configure_breakpoint", e, self._bpcfg_apply_btn),
            parent=self,
            event="x64dbg_configure_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_set_logging_breakpoint(self) -> None:
        """Set a non-stopping logging breakpoint."""
        if self._bridge is None:
            return
        address = self._bpcfg_address()
        if address is None:
            return
        log_text = self._bpcfg_log_input.text().strip()
        if not log_text:
            QMessageBox.warning(self, self.tr("Logging Breakpoint"), self.tr("Log text is required."))
            return
        self._bpcfg_logging_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_logging_breakpoint(address, log_text, non_stopping=True),
            on_success=lambda _: self._on_bpcfg_success(f"Logging breakpoint set at 0x{address:X}", self._bpcfg_logging_btn),
            on_error=lambda e: self._on_bpcfg_error("set_logging_breakpoint", e, self._bpcfg_logging_btn),
            parent=self,
            event="x64dbg_set_logging_breakpoint",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_set_dll_breakpoint(self) -> None:
        """Set a DLL load/unload breakpoint via the Librarian."""
        if self._bridge is None:
            return
        dll_name = self._bpcfg_dll_input.text().strip()
        if not dll_name:
            return
        event = self._bpcfg_dll_event_combo.currentText()
        self._bpcfg_dll_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.set_dll_breakpoint(dll_name, event),
            on_success=lambda _: self._on_bpcfg_success(f"DLL breakpoint set on {dll_name} ({event})", self._bpcfg_dll_btn),
            on_error=lambda e: self._on_bpcfg_error("set_dll_breakpoint", e, self._bpcfg_dll_btn),
            parent=self,
            event="x64dbg_set_dll_breakpoint",
            logger=_logger,
            level="info",
            dll_name=dll_name,
            dll_event=event,
        )

    def _on_bpcfg_success(self, message: str, btn: QPushButton) -> None:
        """Handle a successful breakpoint-configuration operation.

        Args:
            message: Status message to display.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        self._bpcfg_status_label.setText(f"[+] {message}")

    def _on_bpcfg_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a breakpoint-configuration operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_bp_config_operation_failed", operation=operation, error=str(exc))
        self._bpcfg_status_label.setText(f"[-] {operation} failed: {exc}")

    # -- Cross-references: xref, CFG, string refs, intermodular calls -------

    def _build_xref_tab(self) -> QWidget:
        """Build the cross-reference discovery sub-tab.

        Returns:
            QWidget: Cross-references tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        addr_row = QHBoxLayout()
        addr_label = QLabel(self.tr("Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        addr_row.addWidget(addr_label)
        self._xref_addr_input = QLineEdit()
        self._xref_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._xref_addr_input.setPlaceholderText("0x...")
        addr_row.addWidget(self._xref_addr_input)
        self._xref_find_btn = QPushButton(self.tr("Find References"))
        self._xref_find_btn.setObjectName("tool_button")
        self._xref_find_btn.clicked.connect(self._on_find_references)
        addr_row.addWidget(self._xref_find_btn)
        self._xref_cfg_btn = QPushButton(self.tr("Function CFG"))
        self._xref_cfg_btn.setObjectName("tool_button")
        self._xref_cfg_btn.clicked.connect(self._on_get_function_cfg)
        addr_row.addWidget(self._xref_cfg_btn)
        addr_row.addStretch()
        layout.addLayout(addr_row)

        mod_row = QHBoxLayout()
        mod_label = QLabel(self.tr("Module:"))
        mod_label.setFont(fm.get_ui_font(9))
        mod_row.addWidget(mod_label)
        self._xref_module_input = QLineEdit()
        self._xref_module_input.setMaximumWidth(160)
        self._xref_module_input.setPlaceholderText("target.exe")
        mod_row.addWidget(self._xref_module_input)
        self._xref_strings_btn = QPushButton(self.tr("String References"))
        self._xref_strings_btn.setObjectName("tool_button")
        self._xref_strings_btn.clicked.connect(self._on_find_string_references)
        mod_row.addWidget(self._xref_strings_btn)
        self._xref_intermod_btn = QPushButton(self.tr("Intermodular Calls"))
        self._xref_intermod_btn.setObjectName("tool_button")
        self._xref_intermod_btn.clicked.connect(self._on_find_intermodular_calls)
        mod_row.addWidget(self._xref_intermod_btn)
        mod_row.addStretch()
        layout.addLayout(mod_row)

        self._xref_table = QTableWidget(0, len(_XREF_COLUMNS))
        self._xref_table.setHorizontalHeaderLabels(_XREF_COLUMNS)
        self._xref_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        xref_h = self._xref_table.horizontalHeader()
        if xref_h is not None:
            xref_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._xref_table)
        return container

    def _xref_address(self) -> int | None:
        """Parse the cross-reference address field.

        Returns:
            int | None: Parsed address, or None if empty/invalid.
        """
        text = self._xref_addr_input.text().strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            _logger.warning("x64dbg_xref_invalid_address", input_text=text)
            QMessageBox.warning(self, self.tr("Cross-References"), self.tr("Invalid address: {0}").format(text))
            return None

    def _apply_reference_list(self, result: object) -> None:
        """Populate the cross-reference table from a references result dict.

        Args:
            result: Dict containing a ``references`` list.
        """
        references: list[object] = []
        if isinstance(result, dict):
            typed_result: dict[str, object] = cast("dict[str, object]", result)
            raw_refs = typed_result.get("references")
            if isinstance(raw_refs, list):
                references = cast("list[object]", raw_refs)
        self._xref_table.setRowCount(0)
        for index, ref in enumerate(references):
            row = self._xref_table.rowCount()
            self._xref_table.insertRow(row)
            self._xref_table.setItem(row, 0, QTableWidgetItem(str(index)))
            self._xref_table.setItem(row, 1, QTableWidgetItem(str(ref)))

    def _on_find_references(self) -> None:
        """Find references to the specified address."""
        if self._bridge is None:
            return
        address = self._xref_address()
        if address is None:
            return
        self._xref_table.setHorizontalHeaderLabels(_XREF_COLUMNS)
        self._xref_find_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.find_references(address),
            on_success=self._apply_reference_list,
            on_error=lambda e: self._on_xref_error("find_references", e, self._xref_find_btn),
            parent=self,
            event="x64dbg_find_references",
            logger=_logger,
            address=hex(address),
        )

    def _on_get_function_cfg(self) -> None:
        """Fetch the control-flow graph of a function."""
        if self._bridge is None:
            return
        address = self._xref_address()
        if address is None:
            return
        self._xref_cfg_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_function_cfg(address),
            on_success=self._apply_function_cfg,
            on_error=lambda e: self._on_xref_error("get_function_cfg", e, self._xref_cfg_btn),
            parent=self,
            event="x64dbg_get_function_cfg",
            logger=_logger,
            address=hex(address),
        )

    def _apply_function_cfg(self, result: object) -> None:
        """Populate the cross-reference table with control-flow-graph blocks and edges.

        Args:
            result: CFG dict from the bridge with ``blocks`` and ``edges`` lists.
        """
        self._xref_cfg_btn.setEnabled(True)
        self._xref_table.setHorizontalHeaderLabels(["Kind", "Detail"])
        self._xref_table.setRowCount(0)
        if not isinstance(result, dict):
            return
        typed_result: dict[str, object] = cast("dict[str, object]", result)
        blocks = typed_result.get("blocks")
        if isinstance(blocks, list):
            for block in cast("list[object]", blocks):
                row = self._xref_table.rowCount()
                self._xref_table.insertRow(row)
                self._xref_table.setItem(row, 0, QTableWidgetItem("block"))
                self._xref_table.setItem(row, 1, QTableWidgetItem(str(block)))
        edges = typed_result.get("edges")
        if isinstance(edges, list):
            for edge in cast("list[object]", edges):
                row = self._xref_table.rowCount()
                self._xref_table.insertRow(row)
                self._xref_table.setItem(row, 0, QTableWidgetItem("edge"))
                self._xref_table.setItem(row, 1, QTableWidgetItem(str(edge)))

    def _on_find_string_references(self) -> None:
        """Find string references in the specified module."""
        if self._bridge is None:
            return
        module = self._xref_module_input.text().strip()
        if not module:
            return
        self._xref_table.setHorizontalHeaderLabels(_XREF_COLUMNS)
        self._xref_strings_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.find_string_references(module),
            on_success=self._apply_reference_list,
            on_error=lambda e: self._on_xref_error("find_string_references", e, self._xref_strings_btn),
            parent=self,
            event="x64dbg_find_string_references",
            logger=_logger,
            module=module,
        )

    def _on_find_intermodular_calls(self) -> None:
        """Find intermodular calls in the specified module."""
        if self._bridge is None:
            return
        module = self._xref_module_input.text().strip()
        if not module:
            return
        self._xref_table.setHorizontalHeaderLabels(_XREF_COLUMNS)
        self._xref_intermod_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.find_intermodular_calls(module),
            on_success=self._apply_reference_list,
            on_error=lambda e: self._on_xref_error("find_intermodular_calls", e, self._xref_intermod_btn),
            parent=self,
            event="x64dbg_find_intermodular_calls",
            logger=_logger,
            module=module,
        )

    def _on_xref_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a cross-reference operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_xref_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Cross-Reference Error"), str(exc))

    # -- Handles --------------------------------------------------------------

    def _build_handles_tab(self) -> QWidget:
        """Build the process-handle enumeration sub-tab.

        Returns:
            QWidget: Handles tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        toolbar = QHBoxLayout()
        self._handles_refresh_btn = QPushButton(self.tr("Enumerate Handles"))
        self._handles_refresh_btn.setObjectName("tool_button")
        self._handles_refresh_btn.clicked.connect(self._on_refresh_handles)
        toolbar.addWidget(self._handles_refresh_btn)
        handle_label = QLabel(self.tr("Handle:"))
        handle_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(handle_label)
        self._handles_close_input = QLineEdit()
        self._handles_close_input.setMaximumWidth(120)
        self._handles_close_input.setPlaceholderText("0x...")
        toolbar.addWidget(self._handles_close_input)
        self._handles_close_btn = QPushButton(self.tr("Close Handle"))
        self._handles_close_btn.setObjectName("tool_button")
        self._handles_close_btn.clicked.connect(self._on_close_handle)
        toolbar.addWidget(self._handles_close_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._handles_table = QTableWidget(0, len(_HANDLE_COLUMNS))
        self._handles_table.setHorizontalHeaderLabels(_HANDLE_COLUMNS)
        self._handles_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._handles_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._handles_table.cellClicked.connect(self._on_handle_row_selected)
        handles_h = self._handles_table.horizontalHeader()
        if handles_h is not None:
            for column in range(len(_HANDLE_COLUMNS)):
                mode = QHeaderView.ResizeMode.Stretch if column == 1 else QHeaderView.ResizeMode.ResizeToContents
                handles_h.setSectionResizeMode(column, mode)
        layout.addWidget(self._handles_table)
        return container

    def _on_refresh_handles(self) -> None:
        """Refresh the handle table from the bridge."""
        if self._bridge is None:
            return
        self._handles_refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_handles(),
            on_success=self._apply_handles,
            on_error=lambda e: self._on_handles_error("get_handles", e, self._handles_refresh_btn),
            parent=self,
            event="x64dbg_get_handles",
            logger=_logger,
        )

    @staticmethod
    def _coerce_handle_value(handle_val: object) -> int:
        """Coerce a bridge-supplied handle value to an integer.

        Args:
            handle_val: Handle value from the bridge, either an int or a hex
                string such as ``"0x1a4"``.

        Returns:
            int: The parsed handle value, or 0 if it could not be parsed.
        """
        if isinstance(handle_val, int):
            return handle_val
        if isinstance(handle_val, str):
            try:
                return int(handle_val, 0)
            except ValueError:
                return 0
        return 0

    def _apply_handles(self, result: object) -> None:
        """Populate the handle table with enumerated handle entries.

        Args:
            result: Handle dict list from the bridge.
        """
        self._handles_refresh_btn.setEnabled(True)
        raw_handles: list[object] = [*result] if isinstance(result, list) else []
        handles: list[dict[str, object]] = [cast("dict[str, object]", entry) for entry in raw_handles if isinstance(entry, dict)]
        self._handles_table.setRowCount(0)
        for entry in handles:
            row = self._handles_table.rowCount()
            self._handles_table.insertRow(row)
            handle_int = self._coerce_handle_value(entry.get("handle", 0))
            handle_item = QTableWidgetItem(f"0x{handle_int:X}")
            handle_item.setData(Qt.ItemDataRole.UserRole, handle_int)
            self._handles_table.setItem(row, 0, handle_item)
            object_text = str(entry.get("object", ""))
            object_item = QTableWidgetItem(object_text)
            object_item.setToolTip(object_text)
            self._handles_table.setItem(row, 1, object_item)
            self._handles_table.setItem(row, 2, QTableWidgetItem(str(entry.get("granted_access", ""))))
            self._handles_table.setItem(row, 3, QTableWidgetItem(str(entry.get("object_type_index", ""))))
            self._handles_table.setItem(row, 4, QTableWidgetItem(str(entry.get("handle_attributes", ""))))

    def _on_handle_row_selected(self, row: int, column: int) -> None:
        """Populate the close-handle field from the selected table row.

        Args:
            row: Table row index that was clicked.
            column: Table column index that was clicked (unused).
        """
        del column
        handle_item = self._handles_table.item(row, 0)
        if handle_item is None:
            return
        handle_int = cast("int", handle_item.data(Qt.ItemDataRole.UserRole))
        self._handles_close_input.setText(f"0x{handle_int:X}")

    def _on_close_handle(self) -> None:
        """Close the handle specified in the close-handle field."""
        if self._bridge is None:
            return
        text = self._handles_close_input.text().strip()
        if not text:
            return
        try:
            handle = int(text, 0)
        except ValueError:
            _logger.warning("x64dbg_close_handle_invalid_value", input_text=text)
            QMessageBox.warning(self, self.tr("Close Handle"), self.tr("Invalid handle value: {0}").format(text))
            return
        self._handles_close_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.close_handle(handle),
            on_success=lambda _: self._on_handle_closed(),
            on_error=lambda e: self._on_handles_error("close_handle", e, self._handles_close_btn),
            parent=self,
            event="x64dbg_close_handle",
            logger=_logger,
            level="info",
            handle=hex(handle),
        )

    def _on_handle_closed(self) -> None:
        """Handle successful handle closure by clearing the field and refreshing the list."""
        self._handles_close_btn.setEnabled(True)
        self._handles_close_input.clear()
        self._on_refresh_handles()

    def _on_handles_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a handle-enumeration operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_handles_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Handle Error"), str(exc))

    # -- Script engine ---------------------------------------------------------

    def _build_script_tab(self) -> QWidget:
        """Build the script-engine sub-tab (load/run/cmd/abort).

        Returns:
            QWidget: Script tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        path_row = QHBoxLayout()
        path_label = QLabel(self.tr("Script Path:"))
        path_label.setFont(fm.get_ui_font(9))
        path_row.addWidget(path_label)
        self._script_path_input = QLineEdit()
        self._script_path_input.setMinimumWidth(250)
        path_row.addWidget(self._script_path_input)
        self._script_browse_btn = QPushButton(self.tr("Browse..."))
        self._script_browse_btn.setObjectName("tool_button")
        self._script_browse_btn.clicked.connect(self._on_browse_script)
        path_row.addWidget(self._script_browse_btn)
        self._script_load_btn = QPushButton(self.tr("Load"))
        self._script_load_btn.setObjectName("tool_button")
        self._script_load_btn.clicked.connect(self._on_script_load)
        path_row.addWidget(self._script_load_btn)
        layout.addLayout(path_row)

        ctrl_row = QHBoxLayout()
        self._script_run_btn = QPushButton(self.tr("Run"))
        self._script_run_btn.setObjectName("tool_button")
        self._script_run_btn.clicked.connect(self._on_script_run)
        ctrl_row.addWidget(self._script_run_btn)
        self._script_abort_btn = QPushButton(self.tr("Abort"))
        self._script_abort_btn.setObjectName("tool_button")
        self._script_abort_btn.clicked.connect(self._on_script_abort)
        ctrl_row.addWidget(self._script_abort_btn)
        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        cmd_row = QHBoxLayout()
        cmd_label = QLabel(self.tr("Command:"))
        cmd_label.setFont(fm.get_ui_font(9))
        cmd_row.addWidget(cmd_label)
        self._script_cmd_input = QLineEdit()
        self._script_cmd_input.setMinimumWidth(250)
        cmd_row.addWidget(self._script_cmd_input)
        self._script_cmd_btn = QPushButton(self.tr("Execute"))
        self._script_cmd_btn.setObjectName("tool_button")
        self._script_cmd_btn.clicked.connect(self._on_script_cmd)
        cmd_row.addWidget(self._script_cmd_btn)
        layout.addLayout(cmd_row)

        self._script_status_label = QLabel("")
        self._script_status_label.setWordWrap(True)
        layout.addWidget(self._script_status_label)
        layout.addStretch()
        return container

    def _on_browse_script(self) -> None:
        """Open a file dialog to select an x64dbg script file."""
        path, _ = QFileDialog.getOpenFileName(self, self.tr("Select Script"), "", "Script Files (*.txt *.script);;All Files (*)")
        if path:
            self._script_path_input.setText(path)

    def _on_script_load(self) -> None:
        """Load the specified x64dbg script file."""
        if self._bridge is None:
            return
        path = self._script_path_input.text().strip()
        if not path:
            return
        self._script_load_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.script_load(path),
            on_success=lambda r: self._on_script_success("load", r, self._script_load_btn),
            on_error=lambda e: self._on_script_error("load", e, self._script_load_btn),
            parent=self,
            event="x64dbg_script_load",
            logger=_logger,
            level="info",
            path=path,
        )

    def _on_script_run(self) -> None:
        """Run the currently loaded script."""
        if self._bridge is None:
            return
        self._script_run_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.script_run(),
            on_success=lambda r: self._on_script_success("run", r, self._script_run_btn),
            on_error=lambda e: self._on_script_error("run", e, self._script_run_btn),
            parent=self,
            event="x64dbg_script_run",
            logger=_logger,
            level="info",
        )

    def _on_script_cmd(self) -> None:
        """Execute a single script command."""
        if self._bridge is None:
            return
        line = self._script_cmd_input.text().strip()
        if not line:
            return
        self._script_cmd_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.script_cmd(line),
            on_success=lambda r: self._on_script_success("cmd", r, self._script_cmd_btn),
            on_error=lambda e: self._on_script_error("cmd", e, self._script_cmd_btn),
            parent=self,
            event="x64dbg_script_cmd",
            logger=_logger,
            level="info",
            line=line,
        )

    def _on_script_abort(self) -> None:
        """Abort the running script."""
        if self._bridge is None:
            return
        self._script_abort_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.script_abort(),
            on_success=lambda r: self._on_script_success("abort", r, self._script_abort_btn),
            on_error=lambda e: self._on_script_error("abort", e, self._script_abort_btn),
            parent=self,
            event="x64dbg_script_abort",
            logger=_logger,
            level="info",
        )

    def _on_script_success(self, operation: str, result: object, btn: QPushButton) -> None:
        """Handle a successful script-engine operation.

        Args:
            operation: Name of the completed operation.
            result: Result dict from the bridge.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        verified = isinstance(result, dict) and cast("dict[str, object]", result).get("verified") is True
        suffix = " (verified)" if verified else ""
        self._script_status_label.setText(f"[+] script_{operation} succeeded{suffix}")

    def _on_script_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a script-engine operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_script_operation_failed", operation=operation, error=str(exc))
        self._script_status_label.setText(f"[-] script_{operation} failed: {exc}")

    # -- Plugin manager ----------------------------------------------------

    def _build_plugin_tab(self) -> QWidget:
        """Build the plugin-manager sub-tab (load/unload/list).

        Returns:
            QWidget: Plugin tab container.
        """
        fm = FontManager.get_instance()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(_MARGIN, _MARGIN, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        path_row = QHBoxLayout()
        path_label = QLabel(self.tr("Plugin Path:"))
        path_label.setFont(fm.get_ui_font(9))
        path_row.addWidget(path_label)
        self._plugin_path_input = QLineEdit()
        self._plugin_path_input.setMinimumWidth(250)
        path_row.addWidget(self._plugin_path_input)
        self._plugin_browse_btn = QPushButton(self.tr("Browse..."))
        self._plugin_browse_btn.setObjectName("tool_button")
        self._plugin_browse_btn.clicked.connect(self._on_browse_plugin)
        path_row.addWidget(self._plugin_browse_btn)
        self._plugin_load_btn = QPushButton(self.tr("Load"))
        self._plugin_load_btn.setObjectName("tool_button")
        self._plugin_load_btn.clicked.connect(self._on_plugin_load)
        path_row.addWidget(self._plugin_load_btn)
        layout.addLayout(path_row)

        unload_row = QHBoxLayout()
        unload_label = QLabel(self.tr("Plugin Name:"))
        unload_label.setFont(fm.get_ui_font(9))
        unload_row.addWidget(unload_label)
        self._plugin_name_input = QLineEdit()
        self._plugin_name_input.setMaximumWidth(160)
        unload_row.addWidget(self._plugin_name_input)
        self._plugin_unload_btn = QPushButton(self.tr("Unload"))
        self._plugin_unload_btn.setObjectName("tool_button")
        self._plugin_unload_btn.clicked.connect(self._on_plugin_unload)
        unload_row.addWidget(self._plugin_unload_btn)
        self._plugin_refresh_btn = QPushButton(self.tr("Refresh List"))
        self._plugin_refresh_btn.setObjectName("tool_button")
        self._plugin_refresh_btn.clicked.connect(self._on_refresh_plugins)
        unload_row.addWidget(self._plugin_refresh_btn)
        unload_row.addStretch()
        layout.addLayout(unload_row)

        self._plugin_table = QTableWidget(0, len(_PLUGIN_COLUMNS))
        self._plugin_table.setHorizontalHeaderLabels(_PLUGIN_COLUMNS)
        self._plugin_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        plugin_h = self._plugin_table.horizontalHeader()
        if plugin_h is not None:
            plugin_h.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._plugin_table)
        return container

    def _on_browse_plugin(self) -> None:
        """Open a file dialog to select a plugin DLL."""
        path, _ = QFileDialog.getOpenFileName(self, self.tr("Select Plugin"), "", "Plugin DLLs (*.dp*);;All Files (*)")
        if path:
            self._plugin_path_input.setText(path)

    def _on_plugin_load(self) -> None:
        """Load the specified plugin DLL."""
        if self._bridge is None:
            return
        path = self._plugin_path_input.text().strip()
        if not path:
            return
        self._plugin_load_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.plugin_load(path),
            on_success=lambda _: self._on_plugin_success("load", self._plugin_load_btn),
            on_error=lambda e: self._on_plugin_error("load", e, self._plugin_load_btn),
            parent=self,
            event="x64dbg_plugin_load",
            logger=_logger,
            level="info",
            path=path,
        )

    def _on_plugin_unload(self) -> None:
        """Unload the specified plugin by name."""
        if self._bridge is None:
            return
        name = self._plugin_name_input.text().strip()
        if not name:
            return
        self._plugin_unload_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.plugin_unload(name),
            on_success=lambda _: self._on_plugin_success("unload", self._plugin_unload_btn),
            on_error=lambda e: self._on_plugin_error("unload", e, self._plugin_unload_btn),
            parent=self,
            event="x64dbg_plugin_unload",
            logger=_logger,
            level="info",
            plugin_name=name,
        )

    def _on_plugin_success(self, operation: str, btn: QPushButton) -> None:
        """Handle a successful plugin-manager operation by refreshing the plugin list.

        Args:
            operation: Name of the completed operation.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.info("x64dbg_plugin_operation_succeeded", operation=operation)
        self._on_refresh_plugins()

    def _on_refresh_plugins(self) -> None:
        """Refresh the loaded-plugins table from the bridge."""
        if self._bridge is None:
            return
        self._plugin_refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.plugin_list(),
            on_success=self._apply_plugins,
            on_error=lambda e: self._on_plugin_error("list", e, self._plugin_refresh_btn),
            parent=self,
            event="x64dbg_plugin_list",
            logger=_logger,
        )

    def _apply_plugins(self, result: object) -> None:
        """Populate the plugin table with loaded-plugin entries.

        Args:
            result: Plugin info dict list from the bridge.
        """
        self._plugin_refresh_btn.setEnabled(True)
        raw_plugins: list[object] = [*result] if isinstance(result, list) else []
        plugins: list[dict[str, object]] = [cast("dict[str, object]", entry) for entry in raw_plugins if isinstance(entry, dict)]
        self._plugin_table.setRowCount(0)
        for entry in plugins:
            row = self._plugin_table.rowCount()
            self._plugin_table.insertRow(row)
            self._plugin_table.setItem(row, 0, QTableWidgetItem(str(entry.get("name", ""))))
            self._plugin_table.setItem(row, 1, QTableWidgetItem(str(entry.get("path", ""))))
            self._plugin_table.setItem(row, 2, QTableWidgetItem("Yes" if entry.get("loaded", True) else "No"))

    def _on_plugin_error(self, operation: str, exc: object, btn: QPushButton) -> None:
        """Handle a plugin-manager operation failure.

        Args:
            operation: Name of the failed operation.
            exc: The exception that occurred.
            btn: Button to re-enable.
        """
        btn.setEnabled(True)
        _logger.warning("x64dbg_plugin_operation_failed", operation=operation, error=str(exc))
        QMessageBox.warning(self, self.tr("Plugin Manager Error"), str(exc))
