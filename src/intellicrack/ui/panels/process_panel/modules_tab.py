# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Module inspection tab for the ProcessPanel.

Provides module list, DLL injection, handle enumeration, heap inspection, and COM/.NET detection with bridge delegation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtWidgets import (
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.qt_compat import set_header_labels


if TYPE_CHECKING:
    from intellicrack.bridges.process import ProcessBridge

_logger = get_logger(__name__)

_MARGIN: Final[int] = 0
_SPACING: Final[int] = 4
_TOOLBAR_HEIGHT: Final[int] = 32


class ModulesTab(QWidget):
    """Tab for module inspection, DLL injection, handles, heaps, and COM/.NET."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ModulesTab.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: ProcessBridge | None = None
        self._attached_pid: int | None = None
        self._setup_ui()

    def set_bridge(self, bridge: ProcessBridge) -> None:
        """Set the process bridge.

        Args:
            bridge: ProcessBridge instance.
        """
        self._bridge = bridge

    def get_bridge(self) -> ProcessBridge | None:
        """Get the current bridge.

        Returns:
            ProcessBridge | None: The bridge or None.
        """
        return self._bridge

    def set_attached_pid(self, pid: int | None) -> None:
        """Set the currently attached process ID.

        Args:
            pid: Process ID or None if detached.
        """
        self._attached_pid = pid

    def refresh(self) -> None:
        """Populate the module list immediately, e.g. after attach or tab activation."""
        self._refresh_modules()

    def _setup_ui(self) -> None:
        """Build the modules tab layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_MARGIN, _SPACING, _MARGIN, _MARGIN)
        layout.setSpacing(_SPACING)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_module_list(), "Module List")
        self._tabs.addTab(self._build_inject(), "DLL Injection")
        self._tabs.addTab(self._build_handles(), "Handles")
        self._tabs.addTab(self._build_heaps(), "Heap")
        self._tabs.addTab(self._build_com_net(), "COM/.NET")
        layout.addWidget(self._tabs)

    def _build_module_list(self) -> QWidget:
        """Build the module list sub-tab.

        Returns:
            QWidget: Module list widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setObjectName("tool_button")
        refresh_btn.clicked.connect(self._refresh_modules)
        toolbar.addWidget(refresh_btn)

        self._mod_filter = QLineEdit()
        self._mod_filter.setPlaceholderText("Filter modules...")
        self._mod_filter.setMaximumWidth(200)
        self._mod_filter.textChanged.connect(self._on_filter_modules)
        toolbar.addWidget(self._mod_filter)

        self._mod_count = QLabel("0 modules")
        self._mod_count.setObjectName("toolbar_label")
        toolbar.addWidget(self._mod_count)

        tab_layout.addWidget(toolbar)

        self._mod_tree = QTreeWidget()
        set_header_labels(self._mod_tree, ["Module", "Base Address", "Size", "Path", "Entry Point"])
        mod_header = self._mod_tree.header()
        if mod_header is not None:
            mod_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            mod_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            mod_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            mod_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            mod_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        tab_layout.addWidget(self._mod_tree)
        return tab

    def _on_filter_modules(self, text: str) -> None:
        """Filter the module tree by case-insensitive substring match on the module name column.

        Args:
            text: The filter text entered by the user.
        """
        needle = text.strip().lower()
        root = self._mod_tree.invisibleRootItem()
        if root is None:
            return
        for i in range(root.childCount()):
            item = root.child(i)
            if item is None:
                continue
            col0 = item.text(0).lower()
            item.setHidden(bool(needle) and needle not in col0)

    def _build_inject(self) -> QWidget:
        """Build the DLL injection sub-tab.

        Returns:
            QWidget: DLL injection widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        toolbar.addWidget(QLabel("DLL Path:"))
        self._inject_path = QLineEdit()
        self._inject_path.setMinimumWidth(300)
        toolbar.addWidget(self._inject_path)

        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("tool_button")
        browse_btn.clicked.connect(self._on_browse_dll)
        toolbar.addWidget(browse_btn)

        inject_btn = QPushButton("Inject")
        inject_btn.setObjectName("danger_button")
        inject_btn.clicked.connect(self._on_inject)
        toolbar.addWidget(inject_btn)

        tab_layout.addWidget(toolbar)

        self._inject_log = QTableWidget(0, 3)
        self._inject_log.setHorizontalHeaderLabels(["DLL Path", "Status", "Details"])
        ilh = self._inject_log.horizontalHeader()
        if ilh is not None:
            ilh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            ilh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            ilh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._inject_log)
        return tab

    def _build_handles(self) -> QWidget:
        """Build the handle enumeration sub-tab.

        Returns:
            QWidget: Handle enumeration widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        enum_btn = QPushButton("Enumerate Handles")
        enum_btn.setObjectName("tool_button")
        enum_btn.clicked.connect(self._refresh_handles)
        toolbar.addWidget(enum_btn)

        self._handle_count = QLabel("0 handles")
        self._handle_count.setObjectName("toolbar_label")
        toolbar.addWidget(self._handle_count)

        tab_layout.addWidget(toolbar)

        columns = ["Handle Value", "Type", "Granted Access", "Object Address"]
        self._handle_table = QTableWidget(0, len(columns))
        self._handle_table.setHorizontalHeaderLabels(columns)
        self._handle_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        handle_header = self._handle_table.horizontalHeader()
        if handle_header is not None:
            handle_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            handle_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            handle_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            handle_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        tab_layout.addWidget(self._handle_table)
        return tab

    def _build_heaps(self) -> QWidget:
        """Build the heap enumeration sub-tab.

        Returns:
            QWidget: Heap enumeration widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        enum_btn = QPushButton("Enumerate Heaps")
        enum_btn.setObjectName("tool_button")
        enum_btn.clicked.connect(self._refresh_heaps)
        toolbar.addWidget(enum_btn)

        tab_layout.addWidget(toolbar)

        self._heap_table = QTableWidget(0, 3)
        self._heap_table.setHorizontalHeaderLabels(["Heap ID", "Flags", "Default"])
        hh = self._heap_table.horizontalHeader()
        if hh is not None:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._heap_table)
        return tab

    def _build_com_net(self) -> QWidget:
        """Build the COM/.NET detection sub-tab.

        Returns:
            QWidget: COM/.NET widget.
        """
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.setSpacing(_SPACING)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFixedHeight(_TOOLBAR_HEIGHT)

        com_btn = QPushButton("Inspect COM")
        com_btn.setObjectName("tool_button")
        com_btn.clicked.connect(self._refresh_com)
        toolbar.addWidget(com_btn)

        net_btn = QPushButton("Detect .NET")
        net_btn.setObjectName("tool_button")
        net_btn.clicked.connect(self._refresh_dotnet)
        toolbar.addWidget(net_btn)

        tab_layout.addWidget(toolbar)

        self._com_table = QTableWidget(0, 3)
        self._com_table.setHorizontalHeaderLabels(["CLSID", "DLL Path", "Loaded Path"])
        ch = self._com_table.horizontalHeader()
        if ch is not None:
            ch.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            ch.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            ch.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        tab_layout.addWidget(self._com_table)

        tab_layout.addWidget(QLabel(".NET CLR Detection"))

        self._net_tree = QTreeWidget()
        self._net_tree.setHeaderLabels(["Field", "Value"])
        tab_layout.addWidget(self._net_tree)
        return tab

    def _refresh_modules(self) -> None:
        """Refresh the module list from bridge."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            typed_result = cast("list[object]", result)
            self._mod_tree.clear()
            for mod in typed_result:
                mod_name = str(getattr(mod, "name", ""))
                base_raw: object = getattr(mod, "base_address", 0)
                base_addr = base_raw if isinstance(base_raw, int) else 0
                size_raw: object = getattr(mod, "size", 0)
                mod_size = size_raw if isinstance(size_raw, int) else 0
                mod_path = str(getattr(mod, "path", ""))
                ep_raw: object = getattr(mod, "entry_point", 0)
                entry_pt = ep_raw if isinstance(ep_raw, int) else 0
                mod_item = QTreeWidgetItem(
                    self._mod_tree,
                    [
                        mod_name,
                        f"0x{base_addr:X}",
                        f"{mod_size:,} bytes",
                        mod_path,
                        f"0x{entry_pt:X}",
                    ],
                )
                mod_item.setToolTip(3, mod_path)
            self._mod_count.setText(f"{len(typed_result)} modules")

        def _on_error(exc: object) -> None:
            _logger.warning("module_enumeration_failed", error=str(exc))
            QMessageBox.warning(self, "Module Enumeration Error", str(exc))

        run_bridge_coroutine_logged(
            self._bridge.get_modules(self._attached_pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_modules",
            logger=_logger,
            pid=self._attached_pid,
        )

    def _on_browse_dll(self) -> None:
        """Open file dialog to select a DLL."""
        path, _ = QFileDialog.getOpenFileName(self, "Select DLL", "", "DLL Files (*.dll)")
        if path:
            _logger.info("dll_injection_target_selected", path=path, pid=self._attached_pid)
            self._inject_path.setText(path)

    def _on_inject(self) -> None:
        """Inject the specified DLL with confirmation."""
        if self._bridge is None:
            return

        path = self._inject_path.text().strip()
        if not path:
            return

        reply = QMessageBox.warning(
            self,
            "DLL Injection",
            f"Inject {path} into the attached process?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        def _on_success(_result: object) -> None:
            _logger.info("dll_injected", path=path, pid=self._attached_pid)
            row = self._inject_log.rowCount()
            self._inject_log.insertRow(row)
            self._inject_log.setItem(row, 0, self._tooltip_item(path))
            self._inject_log.setItem(row, 1, QTableWidgetItem("Success"))
            self._inject_log.setItem(row, 2, QTableWidgetItem(""))

        def _on_error(exc: object) -> None:
            _logger.warning(
                "dll_inject_failed",
                path=path,
                pid=self._attached_pid,
                error=str(exc),
            )
            row = self._inject_log.rowCount()
            self._inject_log.insertRow(row)
            self._inject_log.setItem(row, 0, self._tooltip_item(path))
            self._inject_log.setItem(row, 1, QTableWidgetItem("Failed"))
            self._inject_log.setItem(row, 2, self._tooltip_item(str(exc)))

        run_bridge_coroutine_logged(
            self._bridge.inject_dll(path),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_inject_dll",
            logger=_logger,
            level="info",
            dll_path=path,
        )

    @staticmethod
    def _tooltip_item(text: str) -> QTableWidgetItem:
        """Build a table item whose tooltip mirrors its display text.

        Args:
            text: Cell display text, also used as the tooltip so that
                values wider than the column remain readable on hover.

        Returns:
            QTableWidgetItem: Item populated with text and a matching tooltip.
        """
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        return item

    def _set_handle_cell(self, row: int, column: int, text: str) -> None:
        """Populate a handle table cell with text and a full-value tooltip.

        The tooltip mirrors the cell text so that wide values such as the
        granted-access mask and object address remain readable when the
        column is too narrow to show them in full.

        Args:
            row: Zero-based table row index.
            column: Zero-based table column index.
            text: Cell display text, also used as the tooltip.
        """
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        self._handle_table.setItem(row, column, item)

    def _refresh_handles(self) -> None:
        """Refresh handle list from bridge."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            typed_result = cast("list[object]", result)
            self._handle_table.setRowCount(0)
            for h in typed_result:
                if not isinstance(h, dict):
                    continue
                typed_h = cast("dict[str, object]", h)
                row = self._handle_table.rowCount()
                self._handle_table.insertRow(row)
                hv_raw = typed_h.get("handle_value", 0)
                hv = hv_raw if isinstance(hv_raw, int) else 0
                self._set_handle_cell(row, 0, f"0x{hv:X}")
                type_name_raw = typed_h.get("type_name")
                type_label = type_name_raw if isinstance(type_name_raw, str) and type_name_raw else str(typed_h.get("type_index", 0))
                self._set_handle_cell(row, 1, type_label)
                ga_raw = typed_h.get("granted_access", 0)
                ga = ga_raw if isinstance(ga_raw, int) else 0
                self._set_handle_cell(row, 2, f"0x{ga:X}")
                oa_raw = typed_h.get("object_address", 0)
                oa = oa_raw if isinstance(oa_raw, int) else 0
                self._set_handle_cell(row, 3, f"0x{oa:X}")
            self._handle_count.setText(f"{len(typed_result)} handles")

        def _on_error(exc: object) -> None:
            _logger.warning("handles_enumerate_failed", pid=self._attached_pid, error=str(exc))
            QMessageBox.warning(self, "Handle Enumeration Error", str(exc))

        run_bridge_coroutine_logged(
            self._bridge.get_handles(self._attached_pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_handles",
            logger=_logger,
            pid=self._attached_pid,
        )

    def _refresh_heaps(self) -> None:
        """Refresh heap list from bridge."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._heap_table.setRowCount(0)
            for heap in cast("list[object]", result):
                if not isinstance(heap, dict):
                    continue
                typed_heap = cast("dict[str, object]", heap)
                row = self._heap_table.rowCount()
                self._heap_table.insertRow(row)
                heap_id_raw = typed_heap.get("heap_id", 0)
                heap_id = heap_id_raw if isinstance(heap_id_raw, int) else 0
                self._heap_table.setItem(row, 0, QTableWidgetItem(f"0x{heap_id:X}"))
                self._heap_table.setItem(row, 1, QTableWidgetItem(str(typed_heap.get("flags", 0))))
                self._heap_table.setItem(row, 2, QTableWidgetItem("Yes" if typed_heap.get("is_default") else "No"))

        def _on_error(exc: object) -> None:
            _logger.warning("heaps_enumerate_failed", pid=self._attached_pid, error=str(exc))
            QMessageBox.warning(self, "Heap Enumeration Error", str(exc))

        run_bridge_coroutine_logged(
            self._bridge.get_heaps(self._attached_pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_get_heaps",
            logger=_logger,
            pid=self._attached_pid,
        )

    def _refresh_com(self) -> None:
        """Refresh COM server list from bridge."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, list):
                return
            self._com_table.setRowCount(0)
            for srv in cast("list[object]", result):
                if not isinstance(srv, dict):
                    continue
                typed_srv = cast("dict[str, object]", srv)
                row = self._com_table.rowCount()
                self._com_table.insertRow(row)
                self._com_table.setItem(row, 0, QTableWidgetItem(str(typed_srv.get("clsid", ""))))
                self._com_table.setItem(row, 1, self._tooltip_item(str(typed_srv.get("dll_path", ""))))
                self._com_table.setItem(row, 2, self._tooltip_item(str(typed_srv.get("loaded_path", ""))))

        def _on_error(exc: object) -> None:
            _logger.warning("com_enumerate_failed", pid=self._attached_pid, error=str(exc))
            QMessageBox.warning(self, "COM Enumeration Error", str(exc))

        run_bridge_coroutine_logged(
            self._bridge.enumerate_com_servers(self._attached_pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_enumerate_com_servers",
            logger=_logger,
            pid=self._attached_pid,
        )

    def _refresh_dotnet(self) -> None:
        """Detect .NET CLR in the attached process."""
        if self._bridge is None or self._attached_pid is None:
            return

        def _on_success(result: object) -> None:
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)
            self._net_tree.clear()
            for key, val in typed_result.items():
                if isinstance(val, list):
                    parent = QTreeWidgetItem(self._net_tree, [str(key), ""])
                    for sub_item in cast("list[object]", val):
                        QTreeWidgetItem(parent, ["", str(sub_item)])
                    parent.setExpanded(True)
                else:
                    QTreeWidgetItem(self._net_tree, [str(key), str(val)])

        def _on_error(exc: object) -> None:
            _logger.warning("dotnet_detect_failed", pid=self._attached_pid, error=str(exc))
            QMessageBox.warning(self, ".NET Detection Error", str(exc))

        run_bridge_coroutine_logged(
            self._bridge.detect_dotnet(self._attached_pid),
            on_success=_on_success,
            on_error=_on_error,
            parent=self,
            event="process_detect_dotnet",
            logger=_logger,
            pid=self._attached_pid,
        )
