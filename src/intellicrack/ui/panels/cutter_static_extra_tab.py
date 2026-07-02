# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Advanced static-analysis tab for the Cutter/Rizin analysis panel.

Provides a self-contained Qt widget exposing the native rizin static-analysis
capabilities that have no GUI presence elsewhere in the panel: debug
information (``iDj``), classes/RTTI enumeration (``icj``), the global call
graph (``agcj``), virtual-function table detection (``avj``), syscall
enumeration (``asj``), the four zignature/FLIRT-equivalent operations
(``zj``/``zg``/``za``/``z/j``), per-function basic-block listing (``afbj``),
and linear whole-function disassembly text (``pdf``), all driven by the
``CutterBridge`` static-analysis surface
(``cutter.py:2630-2901,3329-3403,3936-3984``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.types import BlockInfo, ClassInfo, VtableInfo
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_ADDR_INPUT_MAX_WIDTH: Final[int] = 160
_NAME_INPUT_MAX_WIDTH: Final[int] = 160

_CLASS_COLUMNS: Final[list[str]] = ["Class", "Address", "Methods", "Fields"]
_VTABLE_COLUMNS: Final[list[str]] = ["Name", "Address", "Method Count"]
_SYSCALL_COLUMNS: Final[list[str]] = ["Name", "Number", "Address"]
_ZIGNATURE_COLUMNS: Final[list[str]] = ["Name", "Bytes", "Function"]
_BLOCK_COLUMNS: Final[list[str]] = ["Address", "Size", "Jump", "Fail", "Instructions"]
_DEBUG_INFO_COLUMNS: Final[list[str]] = ["Field", "Value"]


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


def _stretch_headers(table: QTableWidget) -> None:
    """Apply stretch resize mode to all table columns.

    Args:
        table: Table widget to configure.
    """
    header = table.horizontalHeader()
    if header is not None:
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)


def _make_table(columns: list[str]) -> QTableWidget:
    """Create a configured QTableWidget with standard settings.

    Args:
        columns: Column header labels.

    Returns:
        QTableWidget: Configured table widget.
    """
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    _stretch_headers(table)
    return table


def _log_error(tab_name: str, rpc: str) -> Callable[[object], None]:
    """Build an error callback that logs bridge RPC failures for a named tab.

    Args:
        tab_name: The tab class name (e.g. 'ClassesTab').
        rpc: The bridge RPC label (e.g. 'get_classes').

    Returns:
        Callable[[object], None]: Error callback suitable for the async bridge runner.
    """

    def _callback(error: object) -> None:
        _logger.warning(
            "cutter_tab_refresh_failed",
            tab=tab_name,
            rpc=rpc,
            error=str(error),
            error_type=type(error).__name__,
        )

    return _callback


class DebugInfoTab(QWidget):
    """Tab showing binary debug information (``iDj``) as a key/value table."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the DebugInfoTab with a refresh action and a key/value table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        toolbar = QHBoxLayout()
        self._refresh_btn = QPushButton(self.tr("Refresh"))
        self._refresh_btn.setObjectName("tool_button")
        self._refresh_btn.clicked.connect(self._on_refresh)
        toolbar.addWidget(self._refresh_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._table = _make_table(_DEBUG_INFO_COLUMNS)
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Store the bridge reference and query debug information.

        Args:
            bridge: CutterBridge instance.
        """
        self._bridge = bridge
        self._on_refresh()

    def _on_refresh(self) -> None:
        """Query the bridge for debug information and populate the table."""
        if self._bridge is None:
            return
        self._refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_debug_info(),
            on_success=self._apply_data,
            on_error=self._on_refresh_error,
            parent=self,
            event="cutter_get_debug_info",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with debug-info key/value pairs.

        Args:
            result: Debug information dictionary from the bridge.
        """
        self._refresh_btn.setEnabled(True)
        self._table.setRowCount(0)
        if not isinstance(result, dict):
            return
        info = cast("dict[str, Any]", result)
        for key, value in info.items():
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(key)))
            self._table.setItem(row, 1, QTableWidgetItem(str(value)))

    def _on_refresh_error(self, exc: object) -> None:
        """Handle debug-info query failure.

        Args:
            exc: The exception that occurred.
        """
        self._refresh_btn.setEnabled(True)
        _logger.warning("cutter_get_debug_info_failed", error=str(exc))


class ClassesTab(QWidget):
    """Tab showing C++ class/RTTI information with expandable methods and fields."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ClassesTab with a tree widget for class display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(_CLASS_COLUMNS)
        layout.addWidget(self._tree)

    def refresh(self, bridge: CutterBridge) -> None:
        """Refresh class/RTTI data from the bridge.

        Args:
            bridge: CutterBridge instance.
        """
        run_bridge_coroutine_logged(
            bridge.get_classes(),
            on_success=self._apply_data,
            on_error=_log_error(type(self).__name__, "get_classes"),
            parent=self,
            event="cutter_get_classes",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the tree with class results.

        Args:
            result: List of :class:`ClassInfo` dataclass instances from the bridge.
        """
        self._tree.clear()
        classes: list[ClassInfo] = []
        if isinstance(result, list):
            entries: list[object] = cast("list[object]", result)
            classes.extend(entry for entry in entries if isinstance(entry, ClassInfo))

        for cls in classes:
            top = QTreeWidgetItem([
                cls.name,
                f"0x{cls.address:X}",
                str(len(cls.methods)),
                str(len(cls.fields)),
            ])
            methods_node = QTreeWidgetItem(top, [f"Methods ({len(cls.methods)})", "", "", ""])
            for method in cls.methods:
                QTreeWidgetItem(
                    methods_node,
                    [
                        str(method.get("name", "")),
                        f"0x{int(method.get('address', 0) or 0):X}",
                        str(method.get("type", "")),
                        "",
                    ],
                )
            fields_node = QTreeWidgetItem(top, [f"Fields ({len(cls.fields)})", "", "", ""])
            for field in cls.fields:
                QTreeWidgetItem(
                    fields_node,
                    [
                        str(field.get("name", "")),
                        f"0x{int(field.get('offset', 0) or 0):X}",
                        str(field.get("type", "")),
                        str(field.get("size", "")),
                    ],
                )
            self._tree.addTopLevelItem(top)


class CallGraphTab(QWidget):
    """Tab showing the global function call graph as caller/callee edges."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CallGraphTab with a table for call-graph edges.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._table = _make_table(["Caller", "Callee", "Address"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Refresh call-graph data from the bridge.

        Args:
            bridge: CutterBridge instance.
        """
        run_bridge_coroutine_logged(
            bridge.get_callgraph(),
            on_success=self._apply_data,
            on_error=_log_error(type(self).__name__, "get_callgraph"),
            parent=self,
            event="cutter_get_callgraph",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with call-graph edge results.

        Args:
            result: List of callgraph edge dictionaries from the bridge.
        """
        self._table.setRowCount(0)
        if not isinstance(result, list):
            return
        edges: list[object] = cast("list[object]", result)
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            edge_dict = cast("dict[str, Any]", edge)
            caller = str(edge_dict.get("name", ""))
            address = edge_dict.get("addr", edge_dict.get("offset", 0))
            imports_raw = edge_dict.get("imports", [])
            targets: list[object] = cast("list[object]", imports_raw) if isinstance(imports_raw, list) else [""]
            for callee in targets:
                row = self._table.rowCount()
                self._table.insertRow(row)
                self._table.setItem(row, 0, QTableWidgetItem(caller))
                self._table.setItem(row, 1, QTableWidgetItem(str(callee)))
                self._table.setItem(row, 2, QTableWidgetItem(f"0x{int(address or 0):X}"))


class VtablesTab(QWidget):
    """Tab showing virtual-function table detection results."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the VtablesTab with a table for vtable display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._table = _make_table(_VTABLE_COLUMNS)
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Refresh vtable data from the bridge.

        Args:
            bridge: CutterBridge instance.
        """
        run_bridge_coroutine_logged(
            bridge.get_vtables(),
            on_success=self._apply_data,
            on_error=_log_error(type(self).__name__, "get_vtables"),
            parent=self,
            event="cutter_get_vtables",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with vtable results.

        Args:
            result: List of :class:`VtableInfo` dataclass instances from the bridge.
        """
        vtables: list[VtableInfo] = []
        if isinstance(result, list):
            entries: list[object] = cast("list[object]", result)
            vtables.extend(entry for entry in entries if isinstance(entry, VtableInfo))
        self._table.setRowCount(len(vtables))
        for row, vt in enumerate(vtables):
            self._table.setItem(row, 0, QTableWidgetItem(vt.name))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{vt.address:X}"))
            self._table.setItem(row, 2, QTableWidgetItem(str(len(vt.methods))))


class SyscallsTab(QWidget):
    """Tab showing syscall-table entries detected in the binary."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SyscallsTab with a table for syscall display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        self._table = _make_table(_SYSCALL_COLUMNS)
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Refresh syscall data from the bridge.

        Args:
            bridge: CutterBridge instance.
        """
        run_bridge_coroutine_logged(
            bridge.get_syscalls(),
            on_success=self._apply_data,
            on_error=_log_error(type(self).__name__, "get_syscalls"),
            parent=self,
            event="cutter_get_syscalls",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with syscall results.

        Args:
            result: List of syscall dictionaries from the bridge.
        """
        self._table.setRowCount(0)
        if not isinstance(result, list):
            return
        entries: list[object] = cast("list[object]", result)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            sc = cast("dict[str, Any]", entry)
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(sc.get("name", ""))))
            self._table.setItem(row, 1, QTableWidgetItem(str(sc.get("swi", sc.get("num", "")))))
            self._table.setItem(row, 2, QTableWidgetItem(f"0x{int(sc.get('addr', sc.get('offset', 0)) or 0):X}"))


class ZignaturesTab(QWidget):
    """Tab exposing the four native rizin zignature (FLIRT-equivalent) operations.

    Provides list/generate/add/search actions for function signatures, all
    driven by the ``CutterBridge`` zignature methods.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ZignaturesTab with action controls and a results table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        gen_row = QHBoxLayout()
        gen_label = QLabel(self.tr("Generate @ address (blank = all):"))
        gen_label.setFont(fm.get_ui_font(9))
        gen_row.addWidget(gen_label)
        self._gen_addr_input = QLineEdit()
        self._gen_addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._gen_addr_input.setPlaceholderText("0x401000")
        gen_row.addWidget(self._gen_addr_input)
        self._generate_btn = QPushButton(self.tr("Generate"))
        self._generate_btn.setObjectName("tool_button")
        self._generate_btn.clicked.connect(self._on_generate)
        gen_row.addWidget(self._generate_btn)
        gen_row.addStretch()
        layout.addLayout(gen_row)

        add_row = QHBoxLayout()
        add_label = QLabel(self.tr("Name:"))
        add_label.setFont(fm.get_ui_font(9))
        add_row.addWidget(add_label)
        self._add_name_input = QLineEdit()
        self._add_name_input.setMaximumWidth(_NAME_INPUT_MAX_WIDTH)
        add_row.addWidget(self._add_name_input)
        add_row.addWidget(QLabel(self.tr("Data:")))
        self._add_data_input = QLineEdit()
        self._add_data_input.setPlaceholderText("zignature bytes/mask string...")
        add_row.addWidget(self._add_data_input)
        self._add_btn = QPushButton(self.tr("Add"))
        self._add_btn.setObjectName("tool_button")
        self._add_btn.clicked.connect(self._on_add)
        add_row.addWidget(self._add_btn)
        layout.addLayout(add_row)

        action_row = QHBoxLayout()
        self._list_btn = QPushButton(self.tr("List"))
        self._list_btn.setObjectName("secondary_button")
        self._list_btn.clicked.connect(self._on_list)
        action_row.addWidget(self._list_btn)
        self._search_btn = QPushButton(self.tr("Search Matches"))
        self._search_btn.setObjectName("secondary_button")
        self._search_btn.clicked.connect(self._on_search)
        action_row.addWidget(self._search_btn)
        action_row.addStretch()
        self._status_label = QLabel(self.tr("Ready"))
        self._status_label.setFont(fm.get_ui_font(9))
        action_row.addWidget(self._status_label)
        layout.addLayout(action_row)

        self._table = _make_table(_ZIGNATURE_COLUMNS)
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Store the bridge reference and list existing zignatures.

        Args:
            bridge: CutterBridge instance.
        """
        self._bridge = bridge
        self._on_list()

    def _on_generate(self) -> None:
        """Generate zignatures from analyzed functions, optionally scoped to an address."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return
        addr_text = self._gen_addr_input.text().strip()
        address = _parse_address(addr_text) if addr_text else None
        if addr_text and address is None:
            self._status_label.setText(self.tr("Invalid address"))
            return

        self._generate_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.generate_zignatures(address),
            on_success=lambda _: self._on_generate_success(),
            on_error=self._on_generate_error,
            parent=self,
            event="cutter_generate_zignatures",
            logger=_logger,
            level="info",
            address=hex(address) if address is not None else "all",
        )

    def _on_generate_success(self) -> None:
        """Handle successful zignature generation and refresh the list."""
        self._status_label.setText(self.tr("Zignatures generated"))
        self._generate_btn.setEnabled(True)
        self._on_list()

    def _on_generate_error(self, exc: object) -> None:
        """Handle zignature generation failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Generate failed: {exc}")
        _logger.warning("cutter_generate_zignatures_failed", error=str(exc))
        self._generate_btn.setEnabled(True)

    def _on_add(self) -> None:
        """Add a manually-defined zignature from the name/data inputs."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return
        name = self._add_name_input.text().strip()
        data = self._add_data_input.text().strip()
        if not name or not data:
            self._status_label.setText(self.tr("Enter both name and data"))
            return

        self._add_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.add_zignature(name, data),
            on_success=lambda _: self._on_add_success(name),
            on_error=self._on_add_error,
            parent=self,
            event="cutter_add_zignature",
            logger=_logger,
            level="info",
            zignature_name=name,
        )

    def _on_add_success(self, name: str) -> None:
        """Handle successful zignature addition and refresh the list.

        Args:
            name: The zignature name that was added.
        """
        self._status_label.setText(f"Added zignature '{name}'")
        self._add_btn.setEnabled(True)
        self._add_name_input.clear()
        self._add_data_input.clear()
        self._on_list()

    def _on_add_error(self, exc: object) -> None:
        """Handle zignature addition failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Add failed: {exc}")
        _logger.warning("cutter_add_zignature_failed", error=str(exc))
        self._add_btn.setEnabled(True)

    def _on_list(self) -> None:
        """List all zignatures currently loaded."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return
        self._list_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_zignatures(),
            on_success=self._apply_list,
            on_error=self._on_list_error,
            parent=self,
            event="cutter_get_zignatures",
            logger=_logger,
        )

    def _apply_list(self, result: object) -> None:
        """Populate the table with zignature list results.

        Args:
            result: List of zignature dictionaries from the bridge.
        """
        self._fill_table(result)
        self._list_btn.setEnabled(True)
        self._status_label.setText(f"{self._table.rowCount()} zignature(s)")

    def _on_list_error(self, exc: object) -> None:
        """Handle zignature list failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"List failed: {exc}")
        _logger.warning("cutter_get_zignatures_failed", error=str(exc))
        self._list_btn.setEnabled(True)

    def _on_search(self) -> None:
        """Search for zignature matches against the current binary."""
        if self._bridge is None:
            self._status_label.setText(self.tr("No bridge configured"))
            return
        self._search_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.search_zignatures(),
            on_success=self._apply_search,
            on_error=self._on_search_error,
            parent=self,
            event="cutter_search_zignatures",
            logger=_logger,
        )

    def _apply_search(self, result: object) -> None:
        """Populate the table with zignature search-match results.

        Args:
            result: List of zignature match dictionaries from the bridge.
        """
        self._fill_table(result)
        self._search_btn.setEnabled(True)
        self._status_label.setText(f"{self._table.rowCount()} match(es)")

    def _on_search_error(self, exc: object) -> None:
        """Handle zignature search failure.

        Args:
            exc: The exception that occurred.
        """
        self._status_label.setText(f"Search failed: {exc}")
        _logger.warning("cutter_search_zignatures_failed", error=str(exc))
        self._search_btn.setEnabled(True)

    def _fill_table(self, result: object) -> None:
        """Populate the shared results table from a zignature dictionary list.

        Args:
            result: List of zignature dictionaries from the bridge (list or search).
        """
        self._table.setRowCount(0)
        if not isinstance(result, list):
            return
        entries: list[object] = cast("list[object]", result)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            zig = cast("dict[str, Any]", entry)
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(zig.get("name", ""))))
            bytes_val = zig.get("bytes", zig.get("body", ""))
            self._table.setItem(row, 1, QTableWidgetItem(str(bytes_val)))
            self._table.setItem(row, 2, QTableWidgetItem(str(zig.get("realname", zig.get("function", "")))))


class BasicBlocksTab(QWidget):
    """Tab showing per-function basic-block listings with a function-address input."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the BasicBlocksTab with an address input and a block table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)

        toolbar = QHBoxLayout()
        addr_label = QLabel(self.tr("Function Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(addr_label)
        self._addr_input = QLineEdit()
        self._addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._addr_input.setPlaceholderText("0x401000")
        self._addr_input.returnPressed.connect(self._on_fetch)
        toolbar.addWidget(self._addr_input)
        self._fetch_btn = QPushButton(self.tr("Get Basic Blocks"))
        self._fetch_btn.setObjectName("tool_button")
        self._fetch_btn.clicked.connect(self._on_fetch)
        toolbar.addWidget(self._fetch_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._table = _make_table(_BLOCK_COLUMNS)
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge) -> None:
        """Store the bridge reference for later address-driven fetches.

        Args:
            bridge: CutterBridge instance.
        """
        self._bridge = bridge

    def set_address(self, address: int) -> None:
        """Populate the address input and fetch basic blocks for it.

        Args:
            address: Function address to fetch basic blocks for.
        """
        self._addr_input.setText(f"0x{address:X}")
        self._on_fetch()

    def _on_fetch(self) -> None:
        """Fetch basic blocks for the address in the address input."""
        if self._bridge is None:
            return
        address = _parse_address(self._addr_input.text())
        if address is None:
            self._table.setRowCount(0)
            return
        self._fetch_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_basic_blocks(address),
            on_success=self._apply_data,
            on_error=_log_error(type(self).__name__, "get_basic_blocks"),
            parent=self,
            event="cutter_get_basic_blocks",
            logger=_logger,
            address=hex(address),
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with basic-block results.

        Args:
            result: List of :class:`BlockInfo` dataclass instances from the bridge.
        """
        self._fetch_btn.setEnabled(True)
        blocks: list[BlockInfo] = []
        if isinstance(result, list):
            entries: list[object] = cast("list[object]", result)
            blocks.extend(entry for entry in entries if isinstance(entry, BlockInfo))
        self._table.setRowCount(len(blocks))
        for row, block in enumerate(blocks):
            self._table.setItem(row, 0, QTableWidgetItem(f"0x{block.address:X}"))
            self._table.setItem(row, 1, QTableWidgetItem(str(block.size)))
            self._table.setItem(row, 2, QTableWidgetItem(f"0x{block.jump:X}" if block.jump is not None else ""))
            self._table.setItem(row, 3, QTableWidgetItem(f"0x{block.fail:X}" if block.fail is not None else ""))
            self._table.setItem(row, 4, QTableWidgetItem(str(len(block.instructions))))


class FunctionDisasmTab(QWidget):
    """Tab showing linear whole-function disassembly text with a function-address input."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the FunctionDisasmTab with an address input and a text view.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: CutterBridge | None = None
        fm = FontManager.get_instance()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)

        toolbar = QHBoxLayout()
        addr_label = QLabel(self.tr("Function Address:"))
        addr_label.setFont(fm.get_ui_font(9))
        toolbar.addWidget(addr_label)
        self._addr_input = QLineEdit()
        self._addr_input.setMaximumWidth(_ADDR_INPUT_MAX_WIDTH)
        self._addr_input.setPlaceholderText("0x401000")
        self._addr_input.returnPressed.connect(self._on_fetch)
        toolbar.addWidget(self._addr_input)
        self._fetch_btn = QPushButton(self.tr("Disassemble Function"))
        self._fetch_btn.setObjectName("tool_button")
        self._fetch_btn.clicked.connect(self._on_fetch)
        toolbar.addWidget(self._fetch_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._output = QPlainTextEdit()
        self._output.setFont(fm.get_code_font(10))
        self._output.setReadOnly(True)
        layout.addWidget(self._output)

    def refresh(self, bridge: CutterBridge) -> None:
        """Store the bridge reference for later address-driven fetches.

        Args:
            bridge: CutterBridge instance.
        """
        self._bridge = bridge

    def set_address(self, address: int) -> None:
        """Populate the address input and fetch the linear disassembly for it.

        Args:
            address: Function address to disassemble.
        """
        self._addr_input.setText(f"0x{address:X}")
        self._on_fetch()

    def _on_fetch(self) -> None:
        """Fetch the linear function disassembly for the address in the address input."""
        if self._bridge is None:
            return
        address = _parse_address(self._addr_input.text())
        if address is None:
            self._output.setPlainText("[error] Invalid address")
            return
        self._fetch_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.disassemble_function(address),
            on_success=self._apply_data,
            on_error=lambda e: self._output.setPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_disassemble_function",
            logger=_logger,
            address=hex(address),
        )

    def _apply_data(self, result: object) -> None:
        """Display the linear function disassembly text.

        Args:
            result: Disassembly text string from the bridge.
        """
        self._fetch_btn.setEnabled(True)
        self._output.setPlainText(str(result) if result else "")


class StaticAnalysisExtrasTab(QWidget):
    """Composite tab hosting the remaining native static-analysis views.

    Groups classes/RTTI, call graph, vtables, syscalls, zignatures,
    basic-block listing, and linear function disassembly into a single
    nested tab widget, following the ``DebuggerTab`` sub-tab convention.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the StaticAnalysisExtrasTab with nested sub-tabs.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)

        self._tabs = QTabWidget()
        self._debug_info_tab = DebugInfoTab()
        self._tabs.addTab(self._debug_info_tab, self.tr("Debug Info"))
        self._classes_tab = ClassesTab()
        self._tabs.addTab(self._classes_tab, self.tr("Classes"))
        self._callgraph_tab = CallGraphTab()
        self._tabs.addTab(self._callgraph_tab, self.tr("Call Graph"))
        self._vtables_tab = VtablesTab()
        self._tabs.addTab(self._vtables_tab, self.tr("Vtables"))
        self._syscalls_tab = SyscallsTab()
        self._tabs.addTab(self._syscalls_tab, self.tr("Syscalls"))
        self._zignatures_tab = ZignaturesTab()
        self._tabs.addTab(self._zignatures_tab, self.tr("Zignatures"))
        self._basic_blocks_tab = BasicBlocksTab()
        self._tabs.addTab(self._basic_blocks_tab, self.tr("Basic Blocks"))
        self._function_disasm_tab = FunctionDisasmTab()
        self._tabs.addTab(self._function_disasm_tab, self.tr("Function Disasm"))
        layout.addWidget(self._tabs)

    def refresh(self, bridge: CutterBridge) -> None:
        """Refresh all binary-wide sub-tabs from the bridge.

        The address-driven sub-tabs (basic blocks, function disassembly)
        are stored a bridge reference but not auto-fetched since they
        require a function address supplied by the user or by
        :meth:`show_function`.

        Args:
            bridge: CutterBridge instance.
        """
        self._debug_info_tab.refresh(bridge)
        self._classes_tab.refresh(bridge)
        self._callgraph_tab.refresh(bridge)
        self._vtables_tab.refresh(bridge)
        self._syscalls_tab.refresh(bridge)
        self._zignatures_tab.refresh(bridge)
        self._basic_blocks_tab.refresh(bridge)
        self._function_disasm_tab.refresh(bridge)

    def show_function(self, address: int) -> None:
        """Populate the address-driven sub-tabs for a selected function.

        Args:
            address: Function address selected in the functions sidebar.
        """
        self._basic_blocks_tab.set_address(address)
        self._function_disasm_tab.set_address(address)
