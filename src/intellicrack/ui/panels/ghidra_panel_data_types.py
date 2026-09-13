# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Data Type Manager creation widget for the Ghidra panel.

Provides the "Create Type" sub-form embedded in the Data Types tab, letting users define enums, unions, typedefs, and function-definition
types through ``GhidraBridge.create_data_type`` without leaving the GUI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.panels.qt_compat import set_header_labels, tree_add_child
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.ghidra import GhidraBridge


_logger = get_logger(__name__)

_TYPE_KINDS: Final[list[str]] = ["enum", "union", "typedef", "function_def"]
_DEFAULT_CATEGORY: Final[str] = "/Intellicrack"


class DataTypeManagerWidget(QWidget):
    """Data Type Manager "create type" sub-form for the Ghidra Data Types tab.

    Owns its own bridge reference (set via ``set_bridge``) so it stays self-contained and reusable independently of the host panel.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Data Type Manager widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: GhidraBridge | None = None
        self._fields: list[dict[str, Any]] = []
        self._setup_ui()

    def set_bridge(self, bridge: GhidraBridge | None) -> None:
        """Set the GhidraBridge instance used for type creation.

        Args:
            bridge: The GhidraBridge to use, or None to clear it.
        """
        self._bridge = bridge

    def _setup_ui(self) -> None:
        """Build the create-type form controls."""
        fm = FontManager.get_instance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        browse_title = QLabel(self.tr("Browse Data Types"))
        browse_title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(browse_title)

        browse_row = QHBoxLayout()
        self._browse_refresh_btn = QPushButton(self.tr("Refresh Tree"))
        self._browse_refresh_btn.clicked.connect(self._on_refresh_data_type_tree)
        browse_row.addWidget(self._browse_refresh_btn)
        browse_row.addStretch()
        layout.addLayout(browse_row)

        self._data_type_tree = QTreeWidget()
        set_header_labels(self._data_type_tree, ["Name", "Kind", "Size"])
        layout.addWidget(self._data_type_tree)

        interchange_title = QLabel(self.tr("Bulk Interchange"))
        interchange_title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(interchange_title)

        interchange_row = QHBoxLayout()
        self._import_header_btn = QPushButton(self.tr("Import C Header..."))
        self._import_header_btn.clicked.connect(self._on_import_c_header)
        interchange_row.addWidget(self._import_header_btn)
        self._export_gdt_btn = QPushButton(self.tr("Export .gdt..."))
        self._export_gdt_btn.clicked.connect(self._on_export_data_type_archive)
        interchange_row.addWidget(self._export_gdt_btn)
        self._import_gdt_btn = QPushButton(self.tr("Import .gdt..."))
        self._import_gdt_btn.clicked.connect(self._on_import_data_type_archive)
        interchange_row.addWidget(self._import_gdt_btn)
        layout.addLayout(interchange_row)

        title = QLabel(self.tr("Create Type"))
        title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(title)

        kind_row = QHBoxLayout()
        kind_label = QLabel(self.tr("Kind:"))
        kind_label.setFont(fm.get_ui_font(9))
        kind_row.addWidget(kind_label)
        self._kind_combo = QComboBox()
        self._kind_combo.addItems(_TYPE_KINDS)
        self._kind_combo.currentTextChanged.connect(self._on_kind_changed)
        kind_row.addWidget(self._kind_combo)

        name_label = QLabel(self.tr("Name:"))
        name_label.setFont(fm.get_ui_font(9))
        kind_row.addWidget(name_label)
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Type name")
        kind_row.addWidget(self._name_input)

        category_label = QLabel(self.tr("Category:"))
        category_label.setFont(fm.get_ui_font(9))
        kind_row.addWidget(category_label)
        self._category_input = QLineEdit(_DEFAULT_CATEGORY)
        kind_row.addWidget(self._category_input)
        layout.addLayout(kind_row)

        field_row = QHBoxLayout()
        self._add_field_btn = QPushButton(self.tr("Add Member"))
        self._add_field_btn.clicked.connect(self._on_add_field)
        field_row.addWidget(self._add_field_btn)

        self._base_type_input = QLineEdit()
        self._base_type_input.setPlaceholderText("Base type (typedef only, e.g. dword)")
        self._base_type_input.setVisible(False)
        field_row.addWidget(self._base_type_input)

        self._create_btn = QPushButton(self.tr("Create"))
        self._create_btn.setObjectName("tool_button")
        self._create_btn.clicked.connect(self._on_create_type)
        field_row.addWidget(self._create_btn)
        field_row.addStretch()
        layout.addLayout(field_row)

        self._fields_label = QLabel("")
        self._fields_label.setWordWrap(True)
        layout.addWidget(self._fields_label)

        self._result_view = QPlainTextEdit()
        self._result_view.setReadOnly(True)
        self._result_view.setFont(fm.get_code_font(10))
        self._result_view.setFixedHeight(90)
        layout.addWidget(self._result_view)

        self._on_kind_changed(self._kind_combo.currentText())

    def _on_kind_changed(self, kind: str) -> None:
        """Adjust the create-type form controls for the selected type kind.

        Args:
            kind: Selected type kind (enum, union, typedef, or function_def).
        """
        self._fields = []
        self._fields_label.setText("")
        is_typedef = kind == "typedef"
        is_function_def = kind == "function_def"
        self._base_type_input.setVisible(is_typedef)
        self._add_field_btn.setEnabled(not is_typedef and not is_function_def)

    def _on_add_field(self) -> None:
        """Prompt the user to add a member field for an enum or union type."""
        kind = self._kind_combo.currentText()
        member_name, ok1 = QInputDialog.getText(self, self.tr("Add Member"), self.tr("Member name:"))
        if not ok1 or not member_name.strip():
            return

        field: dict[str, Any] = {"name": member_name.strip()}
        if kind == "enum":
            value, ok2 = QInputDialog.getInt(self, self.tr("Add Member"), self.tr("Member value:"))
            if not ok2:
                return
            field["value"] = value
        elif kind == "union":
            member_type, ok2 = QInputDialog.getText(self, self.tr("Add Member"), self.tr("Member type (e.g. dword, byte[4]):"))
            if not ok2 or not member_type.strip():
                return
            field["type"] = member_type.strip()

        self._fields.append(field)
        summary = ", ".join(f"{f['name']}={f['value']}" if "value" in f else f"{f['name']}:{f.get('type', '')}" for f in self._fields)
        self._fields_label.setText(f"Members: {summary}")

    def _on_create_type(self) -> None:
        """Create a new enum, union, typedef, or function-definition data type."""
        if self._bridge is None:
            self._result_view.setPlainText("No bridge configured")
            return
        if not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return

        name = self._name_input.text().strip()
        if not name:
            self._result_view.setPlainText("Data type name required")
            return

        category = self._category_input.text().strip() or _DEFAULT_CATEGORY
        kind = self._kind_combo.currentText()

        fields: list[dict[str, Any]] = list(self._fields)
        if kind == "typedef":
            base_type = self._base_type_input.text().strip()
            if not base_type:
                self._result_view.setPlainText("Base type required for typedef")
                return
            fields = [{"type": base_type}]

        self._create_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.create_data_type(category, name, kind, fields or None),
            on_success=self._apply_create_type,
            on_error=self._on_create_type_error,
            parent=self,
            event="ghidra_create_data_type",
            logger=_logger,
            level="info",
            name=name,
            type_kind=kind,
            category=category,
        )

    def _apply_create_type(self, result: object) -> None:
        """Render the result of a successful data type creation.

        Args:
            result: Dict with name, kind, size, and success from the bridge.
        """
        self._create_btn.setEnabled(True)
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return

        info = cast("dict[str, Any]", result)
        if not info.get("success", False):
            self._result_view.setPlainText(f"Failed to create type '{info.get('name', '')}'")
            return

        parts = [
            f"Name: {info.get('name', '')}",
            f"Kind: {info.get('kind', '')}",
            f"Size: {info.get('size', 0)}",
        ]
        self._result_view.setPlainText("\n".join(parts))

        self._fields = []
        self._fields_label.setText("")

    def _on_create_type_error(self, exc: object) -> None:
        """Handle data type creation failure.

        Args:
            exc: The exception that occurred.
        """
        self._create_btn.setEnabled(True)
        self._result_view.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_create_data_type_gui_failed", error=str(exc))

    def _on_refresh_data_type_tree(self) -> None:
        """Fetch and render the full Data Type Manager tree from the bridge."""
        if self._bridge is None:
            self._result_view.setPlainText("No bridge configured")
            return
        if not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return

        self._browse_refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_data_type_tree(),
            on_success=self._apply_data_type_tree,
            on_error=self._on_refresh_tree_error,
            parent=self,
            event="ghidra_get_data_type_tree",
            logger=_logger,
        )

    def _apply_data_type_tree(self, result: object) -> None:
        """Render the fetched Data Type Manager tree into the browse tree widget.

        Args:
            result: Recursive category dict from
                ``GhidraBridge.get_data_type_tree``, with ``name``,
                ``path``, ``subcategories``, and ``data_types``.
        """
        self._browse_refresh_btn.setEnabled(True)
        self._data_type_tree.clear()
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return

        data = cast("dict[str, Any]", result)
        root_item = QTreeWidgetItem([str(data.get("name", "")), "category", ""])
        self._data_type_tree.addTopLevelItem(root_item)
        self._populate_data_type_node(data, root_item)

        self._data_type_tree.expandAll()
        self._result_view.setPlainText(f"Loaded data type tree at '{data.get('path', '/')}'")

    def _populate_data_type_node(self, node: dict[str, Any], parent_item: QTreeWidgetItem) -> None:
        """Recursively populate the browse tree from a category node.

        Args:
            node: Category node dict with ``subcategories`` (nested
                category dicts) and ``data_types`` (leaf data type
                dicts with ``name``, ``kind``, and ``size``).
            parent_item: Parent tree widget item to attach children to.
        """
        subcategories = node.get("subcategories", [])
        if isinstance(subcategories, list):
            for subcat in cast("list[dict[str, Any]]", subcategories):
                subcat_item = QTreeWidgetItem([str(subcat.get("name", "")), "category", ""])
                tree_add_child(parent_item, subcat_item)
                self._populate_data_type_node(subcat, subcat_item)

        data_types = node.get("data_types", [])
        if isinstance(data_types, list):
            for dt in cast("list[dict[str, Any]]", data_types):
                dt_item = QTreeWidgetItem([str(dt.get("name", "")), str(dt.get("kind", "")), str(dt.get("size", ""))])
                tree_add_child(parent_item, dt_item)

    def _on_refresh_tree_error(self, exc: object) -> None:
        """Handle Data Type Manager tree retrieval failure.

        Args:
            exc: The exception that occurred.
        """
        self._browse_refresh_btn.setEnabled(True)
        self._result_view.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_get_data_type_tree_gui_failed", error=str(exc))

    def _on_import_c_header(self) -> None:
        """Prompt for a C header file and import its declared types into the program."""
        if self._bridge is None or not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return
        file_path, _ = QFileDialog.getOpenFileName(self, self.tr("Select C Header"), "", self.tr("Header Files (*.h);;All Files (*)"))
        if not file_path:
            return
        run_bridge_coroutine_logged(
            self._bridge.import_c_header(file_path),
            on_success=self._apply_import_c_header,
            on_error=lambda e: self._result_view.setPlainText(f"Import header failed: {e}"),
            parent=self,
            event="ghidra_import_c_header",
            logger=_logger,
            level="info",
            header_path=file_path,
        )

    def _apply_import_c_header(self, result: object) -> None:
        """Render the result of a successful C header import.

        Args:
            result: Dict with path, types_added, and success from the bridge.
        """
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        self._result_view.setPlainText(f"Imported {info.get('types_added', 0)} type(s)")

    def _on_export_data_type_archive(self) -> None:
        """Prompt for a destination .gdt path and export every program data type to it."""
        if self._bridge is None or not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            self.tr("Export Data Type Archive"),
            "",
            self.tr("Ghidra Data Type Archives (*.gdt)"),
        )
        if not file_path:
            return
        run_bridge_coroutine_logged(
            self._bridge.export_data_type_archive(file_path),
            on_success=self._apply_export_data_type_archive,
            on_error=lambda e: self._result_view.setPlainText(f"Export archive failed: {e}"),
            parent=self,
            event="ghidra_export_data_type_archive",
            logger=_logger,
            level="info",
            archive_path=file_path,
        )

    def _apply_export_data_type_archive(self, result: object) -> None:
        """Render the result of a successful data type archive export.

        Args:
            result: Dict with path, types_exported, and success from the bridge.
        """
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        self._result_view.setPlainText(f"Exported {info.get('types_exported', 0)} type(s)")

    def _on_import_data_type_archive(self) -> None:
        """Prompt for a source .gdt path and import every data type it contains into the program."""
        if self._bridge is None or not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            self.tr("Import Data Type Archive"),
            "",
            self.tr("Ghidra Data Type Archives (*.gdt)"),
        )
        if not file_path:
            return
        run_bridge_coroutine_logged(
            self._bridge.import_data_type_archive(file_path),
            on_success=self._apply_import_data_type_archive,
            on_error=lambda e: self._result_view.setPlainText(f"Import archive failed: {e}"),
            parent=self,
            event="ghidra_import_data_type_archive",
            logger=_logger,
            level="info",
            archive_path=file_path,
        )

    def _apply_import_data_type_archive(self, result: object) -> None:
        """Render the result of a successful data type archive import.

        Args:
            result: Dict with path, types_imported, and success from the bridge.
        """
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return
        info = cast("dict[str, Any]", result)
        self._result_view.setPlainText(f"Imported {info.get('types_imported', 0)} type(s)")
