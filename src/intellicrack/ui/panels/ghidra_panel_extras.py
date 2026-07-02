# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Analysis Extras widget for the Ghidra panel.

Hosts the remaining code-analysis and program-model controls that have no
dedicated tab of their own: single-instruction control-flow inspection
(``get_instruction_flow``), tracked register values (``get_register_value``),
thunk relationship management (``get_thunk_info``/``add_thunk``/
``remove_thunk``), external reference editing (``get_external_references``/
``add_external_reference``/``remove_external_reference``), user-defined
properties lookup (``get_properties``), and the bidirectional call graph
(``get_call_graph``), all backed by ``GhidraBridge``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.qt_compat import set_header_labels, set_selection_mode, tree_add_child
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.ghidra import GhidraBridge


_logger = get_logger(__name__)

_EXT_REF_COLUMNS: list[str] = ["Address", "External Name", "Library", "Type"]
_CALL_GRAPH_COLUMNS: list[str] = ["Name", "Address"]
_PROPERTY_COLUMNS: list[str] = ["Property", "Value"]


def _parse_address(text: str) -> int | None:
    """Parse a hex or decimal address string.

    Args:
        text: Address string, optionally prefixed with '0x'.

    Returns:
        int | None: Parsed integer address, or None on failure.
    """
    try:
        stripped = text.strip()
        return int(stripped, 16) if stripped.startswith(("0x", "0X")) else int(stripped)
    except (ValueError, TypeError):
        _logger.warning("ghidra_extras_parse_address_invalid_input", input_text=text)
        return None


class GhidraAnalysisExtrasWidget(QWidget):
    """Analysis Extras tab for the remaining unwired Ghidra code-analysis controls.

    Owns its own bridge reference (set via ``set_bridge``) so it stays
    self-contained and reusable independently of the host panel.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Analysis Extras widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: GhidraBridge | None = None
        self._setup_ui()

    def set_bridge(self, bridge: GhidraBridge | None) -> None:
        """Set the GhidraBridge instance used by every section.

        Args:
            bridge: The GhidraBridge to use, or None to clear it.
        """
        self._bridge = bridge

    def _require_connected(self) -> GhidraBridge | None:
        """Check the bridge is set and connected, reporting status if not.

        Returns:
            GhidraBridge | None: The connected bridge, or None if not ready.
        """
        if self._bridge is None:
            self._status_label.setText("No bridge configured")
            return None
        if not self._bridge.state.is_ready():
            self._status_label.setText("Ghidra not connected")
            return None
        return self._bridge

    def _setup_ui(self) -> None:
        """Build every section of the Analysis Extras tab."""
        fm = FontManager.get_instance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._build_flow_register_section(layout, fm)
        self._build_thunk_section(layout, fm)
        self._build_external_refs_section(layout, fm)
        self._build_properties_section(layout, fm)
        self._build_call_graph_section(layout, fm)

        self._status_label = QLabel("")
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        layout.addStretch()

    # ------------------------------------------------------------------
    # Instruction Flow / Register Value
    # ------------------------------------------------------------------

    def _build_flow_register_section(self, layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the instruction-flow and register-value lookup section.

        Args:
            layout: Parent layout to append the section to.
            fm: Shared font manager instance.
        """
        title = QLabel(self.tr("Instruction Flow / Register Value"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        row = QHBoxLayout()
        self._flow_addr_input = QLineEdit()
        self._flow_addr_input.setPlaceholderText("Address (hex)")
        row.addWidget(self._flow_addr_input)
        self._flow_btn = QPushButton(self.tr("Get Flow"))
        self._flow_btn.clicked.connect(self._on_get_instruction_flow)
        row.addWidget(self._flow_btn)

        self._register_input = QLineEdit()
        self._register_input.setPlaceholderText("Register (e.g. EAX)")
        row.addWidget(self._register_input)
        self._register_btn = QPushButton(self.tr("Get Register"))
        self._register_btn.clicked.connect(self._on_get_register_value)
        row.addWidget(self._register_btn)
        layout.addLayout(row)

        self._flow_register_result = QPlainTextEdit()
        self._flow_register_result.setReadOnly(True)
        self._flow_register_result.setFont(fm.get_code_font(10))
        self._flow_register_result.setFixedHeight(80)
        layout.addWidget(self._flow_register_result)

    def _on_get_instruction_flow(self) -> None:
        """Query control-flow information for the instruction at the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._flow_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for instruction flow")
            return
        self._flow_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_instruction_flow(address),
            on_success=self._apply_instruction_flow,
            on_error=self._on_flow_register_error,
            parent=self,
            event="ghidra_get_instruction_flow",
            logger=_logger,
            address=hex(address),
        )

    def _apply_instruction_flow(self, result: object) -> None:
        """Render the instruction flow result.

        Args:
            result: Dict with address, mnemonic, flow_type, fall_through, and flows.
        """
        self._flow_btn.setEnabled(True)
        if not isinstance(result, dict):
            self._flow_register_result.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        flows_raw = info.get("flows", [])
        flows_list = cast("list[int]", flows_raw) if isinstance(flows_raw, list) else []
        flows = ", ".join(f"0x{int(f):X}" for f in flows_list)
        parts = [
            f"Mnemonic: {info.get('mnemonic', '')}",
            f"Flow type: {info.get('flow_type', '')}",
            f"Fall through: {info.get('fall_through', '')}",
            f"Flows: {flows}",
        ]
        self._flow_register_result.setPlainText("\n".join(parts))

    def _on_get_register_value(self) -> None:
        """Query the context-tracked register value at the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._flow_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for register value")
            return
        register = self._register_input.text().strip()
        if not register:
            self._status_label.setText("Register name required")
            return
        self._register_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_register_value(address, register),
            on_success=self._apply_register_value,
            on_error=self._on_flow_register_error,
            parent=self,
            event="ghidra_get_register_value",
            logger=_logger,
            address=hex(address),
            register=register,
        )

    def _apply_register_value(self, result: object) -> None:
        """Render the register-value lookup result.

        Args:
            result: Dict with address, register, value, and has_value flag.
        """
        self._register_btn.setEnabled(True)
        if not isinstance(result, dict):
            self._flow_register_result.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        if not info.get("has_value", False):
            self._flow_register_result.setPlainText(f"No tracked value for register '{info.get('register', '')}'")
            return
        self._flow_register_result.setPlainText(f"Register: {info.get('register', '')}\nValue: {info.get('value', '')}")

    def _on_flow_register_error(self, exc: object) -> None:
        """Handle instruction-flow or register-value lookup failure.

        Args:
            exc: The exception that occurred.
        """
        self._flow_btn.setEnabled(True)
        self._register_btn.setEnabled(True)
        self._flow_register_result.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_flow_register_gui_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Thunk management
    # ------------------------------------------------------------------

    def _build_thunk_section(self, layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the thunk-management section.

        Args:
            layout: Parent layout to append the section to.
            fm: Shared font manager instance.
        """
        title = QLabel(self.tr("Thunk Management"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        row = QHBoxLayout()
        self._thunk_addr_input = QLineEdit()
        self._thunk_addr_input.setPlaceholderText("Function address (hex)")
        row.addWidget(self._thunk_addr_input)
        self._thunk_info_btn = QPushButton(self.tr("Get Thunk Info"))
        self._thunk_info_btn.clicked.connect(self._on_get_thunk_info)
        row.addWidget(self._thunk_info_btn)
        layout.addLayout(row)

        row2 = QHBoxLayout()
        self._thunk_target_input = QLineEdit()
        self._thunk_target_input.setPlaceholderText("Thunked target address (hex)")
        row2.addWidget(self._thunk_target_input)
        self._add_thunk_btn = QPushButton(self.tr("Add Thunk"))
        self._add_thunk_btn.clicked.connect(self._on_add_thunk)
        row2.addWidget(self._add_thunk_btn)
        self._remove_thunk_btn = QPushButton(self.tr("Remove Thunk"))
        self._remove_thunk_btn.clicked.connect(self._on_remove_thunk)
        row2.addWidget(self._remove_thunk_btn)
        layout.addLayout(row2)

        self._thunk_result = QPlainTextEdit()
        self._thunk_result.setReadOnly(True)
        self._thunk_result.setFont(fm.get_code_font(10))
        self._thunk_result.setFixedHeight(60)
        layout.addWidget(self._thunk_result)

    def _on_get_thunk_info(self) -> None:
        """Query thunk status and resolved target for the entered function address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._thunk_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for thunk info")
            return
        self._thunk_info_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_thunk_info(address),
            on_success=self._apply_thunk_info,
            on_error=self._on_thunk_error,
            parent=self,
            event="ghidra_get_thunk_info",
            logger=_logger,
            address=hex(address),
        )

    def _apply_thunk_info(self, result: object) -> None:
        """Render the thunk-info lookup result.

        Args:
            result: Dict with address, is_thunk, thunked_function, and thunked_address.
        """
        self._thunk_info_btn.setEnabled(True)
        if not isinstance(result, dict):
            self._thunk_result.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        if not info.get("is_thunk", False):
            self._thunk_result.setPlainText("Function is not a thunk")
            return
        thunked_addr = info.get("thunked_address")
        addr_str = f"0x{thunked_addr:X}" if isinstance(thunked_addr, int) else str(thunked_addr)
        self._thunk_result.setPlainText(f"Thunk -> {info.get('thunked_function', '')} ({addr_str})")

    def _on_add_thunk(self) -> None:
        """Mark the entered function address as a thunk to the target address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._thunk_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid function address for add thunk")
            return
        target = _parse_address(self._thunk_target_input.text())
        if target is None:
            self._status_label.setText("Invalid thunked target address")
            return
        self._add_thunk_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.add_thunk(address, target),
            on_success=lambda _, addr=address: self._on_thunk_mutated(addr),
            on_error=self._on_thunk_error,
            parent=self,
            event="ghidra_add_thunk",
            logger=_logger,
            level="info",
            address=hex(address),
            thunked_address=hex(target),
        )

    def _on_remove_thunk(self) -> None:
        """Clear the thunk relationship on the entered function address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._thunk_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid function address for remove thunk")
            return
        self._remove_thunk_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.remove_thunk(address),
            on_success=lambda _, addr=address: self._on_thunk_mutated(addr),
            on_error=self._on_thunk_error,
            parent=self,
            event="ghidra_remove_thunk",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_thunk_mutated(self, address: int) -> None:
        """Re-enable thunk buttons and refresh thunk info after a mutation.

        Args:
            address: Function address the mutation was applied to.
        """
        self._add_thunk_btn.setEnabled(True)
        self._remove_thunk_btn.setEnabled(True)
        self._thunk_addr_input.setText(hex(address))
        self._on_get_thunk_info()

    def _on_thunk_error(self, exc: object) -> None:
        """Handle a thunk-management operation failure.

        Args:
            exc: The exception that occurred.
        """
        self._thunk_info_btn.setEnabled(True)
        self._add_thunk_btn.setEnabled(True)
        self._remove_thunk_btn.setEnabled(True)
        self._thunk_result.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_thunk_gui_failed", error=str(exc))

    # ------------------------------------------------------------------
    # External References
    # ------------------------------------------------------------------

    def _build_external_refs_section(self, layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the external-references section.

        Args:
            layout: Parent layout to append the section to.
            fm: Shared font manager instance.
        """
        title = QLabel(self.tr("External References"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        row = QHBoxLayout()
        self._ext_ref_addr_input = QLineEdit()
        self._ext_ref_addr_input.setPlaceholderText("From address (hex)")
        row.addWidget(self._ext_ref_addr_input)
        self._ext_ref_refresh_btn = QPushButton(self.tr("Refresh"))
        self._ext_ref_refresh_btn.clicked.connect(self._on_refresh_external_refs)
        row.addWidget(self._ext_ref_refresh_btn)
        self._ext_ref_remove_btn = QPushButton(self.tr("Remove All From Address"))
        self._ext_ref_remove_btn.clicked.connect(self._on_remove_external_ref)
        row.addWidget(self._ext_ref_remove_btn)
        layout.addLayout(row)

        add_row = QHBoxLayout()
        self._ext_ref_library_input = QLineEdit()
        self._ext_ref_library_input.setPlaceholderText("Library name")
        add_row.addWidget(self._ext_ref_library_input)
        self._ext_ref_name_input = QLineEdit()
        self._ext_ref_name_input.setPlaceholderText("External symbol name")
        add_row.addWidget(self._ext_ref_name_input)
        self._ext_ref_add_btn = QPushButton(self.tr("Add External Reference"))
        self._ext_ref_add_btn.clicked.connect(self._on_add_external_ref)
        add_row.addWidget(self._ext_ref_add_btn)
        layout.addLayout(add_row)

        self._ext_refs_table = QTableWidget(0, len(_EXT_REF_COLUMNS))
        self._ext_refs_table.setHorizontalHeaderLabels(_EXT_REF_COLUMNS)
        self._ext_refs_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._ext_refs_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ext_refs_table.setFixedHeight(100)
        layout.addWidget(self._ext_refs_table)

    def _on_refresh_external_refs(self) -> None:
        """Fetch and render external references from the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._ext_ref_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for external references")
            return
        self._ext_ref_refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_external_references(address),
            on_success=self._apply_external_refs,
            on_error=self._on_external_ref_error,
            parent=self,
            event="ghidra_get_external_references",
            logger=_logger,
            address=hex(address),
        )

    def _apply_external_refs(self, result: object) -> None:
        """Render the fetched external references into the table.

        Args:
            result: List of external reference dicts from the bridge.
        """
        self._ext_ref_refresh_btn.setEnabled(True)
        refs = cast("list[dict[str, Any]]", result) if isinstance(result, list) else []
        self._ext_refs_table.setRowCount(0)
        for ref in refs:
            row = self._ext_refs_table.rowCount()
            self._ext_refs_table.insertRow(row)
            addr = int(cast("int", ref.get("address", 0)))
            self._ext_refs_table.setItem(row, 0, QTableWidgetItem(f"0x{addr:X}"))
            self._ext_refs_table.setItem(row, 1, QTableWidgetItem(str(ref.get("external_name", ""))))
            self._ext_refs_table.setItem(row, 2, QTableWidgetItem(str(ref.get("library", ""))))
            self._ext_refs_table.setItem(row, 3, QTableWidgetItem(str(ref.get("type", ""))))

    def _on_add_external_ref(self) -> None:
        """Add an external reference from the entered address to a named symbol."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._ext_ref_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for add external reference")
            return
        library = self._ext_ref_library_input.text().strip()
        name = self._ext_ref_name_input.text().strip()
        if not library or not name:
            self._status_label.setText("Library and external symbol name required")
            return
        self._ext_ref_add_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.add_external_reference(address, library, name),
            on_success=lambda _: self._on_refresh_external_refs(),
            on_error=self._on_external_ref_error,
            parent=self,
            event="ghidra_add_external_reference",
            logger=_logger,
            level="info",
            address=hex(address),
            library=library,
            name=name,
        )

    def _on_remove_external_ref(self) -> None:
        """Remove every external reference originating from the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._ext_ref_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for remove external reference")
            return
        self._ext_ref_remove_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.remove_external_reference(address),
            on_success=lambda _: self._on_refresh_external_refs(),
            on_error=self._on_external_ref_error,
            parent=self,
            event="ghidra_remove_external_reference",
            logger=_logger,
            level="info",
            address=hex(address),
        )

    def _on_external_ref_error(self, exc: object) -> None:
        """Handle an external-reference operation failure.

        Args:
            exc: The exception that occurred.
        """
        self._ext_ref_refresh_btn.setEnabled(True)
        self._ext_ref_add_btn.setEnabled(True)
        self._ext_ref_remove_btn.setEnabled(True)
        self._status_label.setText(f"External reference error: {exc}")
        _logger.warning("ghidra_external_reference_gui_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    def _build_properties_section(self, layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the user-defined properties viewer section.

        Args:
            layout: Parent layout to append the section to.
            fm: Shared font manager instance.
        """
        title = QLabel(self.tr("Properties"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        row = QHBoxLayout()
        self._props_addr_input = QLineEdit()
        self._props_addr_input.setPlaceholderText("Address (hex)")
        row.addWidget(self._props_addr_input)
        self._props_btn = QPushButton(self.tr("Get Properties"))
        self._props_btn.clicked.connect(self._on_get_properties)
        row.addWidget(self._props_btn)
        layout.addLayout(row)

        self._properties_table = QTableWidget(0, len(_PROPERTY_COLUMNS))
        self._properties_table.setHorizontalHeaderLabels(_PROPERTY_COLUMNS)
        self._properties_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._properties_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._properties_table.setFixedHeight(90)
        layout.addWidget(self._properties_table)

    def _on_get_properties(self) -> None:
        """Fetch and render user-defined properties at the entered address."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._props_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for properties")
            return
        self._props_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_properties(address),
            on_success=self._apply_properties,
            on_error=self._on_properties_error,
            parent=self,
            event="ghidra_get_properties",
            logger=_logger,
            address=hex(address),
        )

    def _apply_properties(self, result: object) -> None:
        """Render the fetched properties into the properties table.

        Args:
            result: Dict with address and a nested properties map.
        """
        self._props_btn.setEnabled(True)
        self._properties_table.setRowCount(0)
        if not isinstance(result, dict):
            return
        info = cast("dict[str, Any]", result)
        properties_raw = info.get("properties", {})
        properties = cast("dict[str, Any]", properties_raw) if isinstance(properties_raw, dict) else {}
        for name, value in properties.items():
            row = self._properties_table.rowCount()
            self._properties_table.insertRow(row)
            self._properties_table.setItem(row, 0, QTableWidgetItem(str(name)))
            self._properties_table.setItem(row, 1, QTableWidgetItem(str(value)))

    def _on_properties_error(self, exc: object) -> None:
        """Handle a properties lookup failure.

        Args:
            exc: The exception that occurred.
        """
        self._props_btn.setEnabled(True)
        self._status_label.setText(f"Get properties failed: {exc}")
        _logger.warning("ghidra_get_properties_gui_failed", error=str(exc))

    # ------------------------------------------------------------------
    # Bidirectional Call Graph
    # ------------------------------------------------------------------

    def _build_call_graph_section(self, layout: QVBoxLayout, fm: FontManager) -> None:
        """Build the bidirectional call-graph section.

        Args:
            layout: Parent layout to append the section to.
            fm: Shared font manager instance.
        """
        title = QLabel(self.tr("Bidirectional Call Graph"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        row = QHBoxLayout()
        self._bicg_addr_input = QLineEdit()
        self._bicg_addr_input.setPlaceholderText("Address (hex)")
        row.addWidget(self._bicg_addr_input)
        self._bicg_btn = QPushButton(self.tr("Build Bidirectional Graph"))
        self._bicg_btn.clicked.connect(self._on_build_bidirectional_call_graph)
        row.addWidget(self._bicg_btn)
        layout.addLayout(row)

        self._bicg_tree = QTreeWidget()
        set_header_labels(self._bicg_tree, _CALL_GRAPH_COLUMNS)
        set_selection_mode(self._bicg_tree, QAbstractItemView.SelectionMode.SingleSelection)
        self._bicg_tree.setFixedHeight(140)
        layout.addWidget(self._bicg_tree)

    def _on_build_bidirectional_call_graph(self) -> None:
        """Build a bidirectional (callers + callees in one payload) call graph."""
        bridge = self._require_connected()
        if bridge is None:
            return
        address = _parse_address(self._bicg_addr_input.text())
        if address is None:
            self._status_label.setText("Invalid address for bidirectional call graph")
            return
        self._bicg_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            bridge.get_call_graph(address),
            on_success=self._apply_bidirectional_call_graph,
            on_error=self._on_call_graph_error,
            parent=self,
            event="ghidra_get_call_graph",
            logger=_logger,
            address=hex(address),
        )

    def _apply_bidirectional_call_graph(self, result: object) -> None:
        """Render the bidirectional call graph into the tree widget.

        Args:
            result: Dict with root name/address plus ``callees`` and
                ``callers`` tree lists from the bridge.
        """
        self._bicg_btn.setEnabled(True)
        self._bicg_tree.clear()
        if not isinstance(result, dict):
            return
        data = cast("dict[str, Any]", result)
        root_name = str(data.get("name", ""))
        root_addr = int(cast("int", data.get("address", 0)))
        root_item = QTreeWidgetItem([root_name, f"0x{root_addr:X}"])
        self._bicg_tree.addTopLevelItem(root_item)

        callees_node = QTreeWidgetItem(["Callees", ""])
        tree_add_child(root_item, callees_node)
        for callee in cast("list[dict[str, Any]]", data.get("callees", []) or []):
            self._populate_call_graph_node(callee, callees_node, "callees")

        callers_node = QTreeWidgetItem(["Callers", ""])
        tree_add_child(root_item, callers_node)
        for caller in cast("list[dict[str, Any]]", data.get("callers", []) or []):
            self._populate_call_graph_node(caller, callers_node, "callers")

        self._bicg_tree.expandAll()

    def _populate_call_graph_node(
        self,
        node: dict[str, Any],
        parent_item: QTreeWidgetItem,
        direction_key: str,
    ) -> None:
        """Recursively populate a call-graph tree branch.

        Args:
            node: Node dict with ``name``, ``address``, and a nested list
                under ``direction_key`` for its children.
            parent_item: Parent tree widget item to attach the node to.
            direction_key: Either ``"callees"`` or ``"callers"``, selecting
                which key holds this node's children.
        """
        name = str(node.get("name", ""))
        address = int(cast("int", node.get("address", 0)))
        item = QTreeWidgetItem([name, f"0x{address:X}"])
        tree_add_child(parent_item, item)
        for child in cast("list[dict[str, Any]]", node.get(direction_key, []) or []):
            self._populate_call_graph_node(child, item, direction_key)

    def _on_call_graph_error(self, exc: object) -> None:
        """Handle a bidirectional call-graph build failure.

        Args:
            exc: The exception that occurred.
        """
        self._bicg_btn.setEnabled(True)
        self._status_label.setText(f"Bidirectional call graph failed: {exc}")
        _logger.warning("ghidra_call_graph_gui_failed", error=str(exc))
