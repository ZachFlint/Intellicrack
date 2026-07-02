# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Program Tree widget for the Ghidra panel.

Renders the module/fragment hierarchy returned by ``GhidraBridge.get_program_tree``
in a ``QTreeWidget`` and provides a write form for ``GhidraBridge.edit_program_tree``
(create module, create fragment, move child) without leaving the GUI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
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

_TREE_COLUMNS: Final[list[str]] = ["Name", "Type", "Range"]
_OPERATIONS: Final[list[str]] = ["create_module", "create_fragment", "move_child"]


class ProgramTreeWidget(QWidget):
    """Program Tree browser and editor for the Ghidra Program Tree tab.

    Owns its own bridge reference (set via ``set_bridge``) so it stays
    self-contained and reusable independently of the host panel.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Program Tree widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._bridge: GhidraBridge | None = None
        self._setup_ui()

    def set_bridge(self, bridge: GhidraBridge | None) -> None:
        """Set the GhidraBridge instance used for program tree access.

        Args:
            bridge: The GhidraBridge to use, or None to clear it.
        """
        self._bridge = bridge

    def _setup_ui(self) -> None:
        """Build the program tree view and edit-form controls."""
        fm = FontManager.get_instance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        top_row = QHBoxLayout()
        self._refresh_btn = QPushButton(self.tr("Refresh Program Tree"))
        self._refresh_btn.clicked.connect(self._on_refresh_tree)
        top_row.addWidget(self._refresh_btn)
        top_row.addStretch()
        layout.addLayout(top_row)

        self._tree = QTreeWidget()
        set_header_labels(self._tree, _TREE_COLUMNS)
        layout.addWidget(self._tree)

        edit_title = QLabel(self.tr("Edit Program Tree"))
        edit_title.setFont(fm.get_ui_font_bold(9))
        layout.addWidget(edit_title)

        edit_row1 = QHBoxLayout()
        tree_name_label = QLabel(self.tr("Tree:"))
        tree_name_label.setFont(fm.get_ui_font(9))
        edit_row1.addWidget(tree_name_label)
        self._tree_name_input = QLineEdit()
        self._tree_name_input.setPlaceholderText("Program tree name")
        edit_row1.addWidget(self._tree_name_input)

        op_label = QLabel(self.tr("Operation:"))
        op_label.setFont(fm.get_ui_font(9))
        edit_row1.addWidget(op_label)
        self._operation_combo = QComboBox()
        self._operation_combo.addItems(_OPERATIONS)
        edit_row1.addWidget(self._operation_combo)
        layout.addLayout(edit_row1)

        edit_row2 = QHBoxLayout()
        parent_label = QLabel(self.tr("Parent module:"))
        parent_label.setFont(fm.get_ui_font(9))
        edit_row2.addWidget(parent_label)
        self._parent_module_input = QLineEdit()
        self._parent_module_input.setPlaceholderText("Existing module name")
        edit_row2.addWidget(self._parent_module_input)

        child_label = QLabel(self.tr("Child name:"))
        child_label.setFont(fm.get_ui_font(9))
        edit_row2.addWidget(child_label)
        self._child_name_input = QLineEdit()
        self._child_name_input.setPlaceholderText("Module/fragment to create or move")
        edit_row2.addWidget(self._child_name_input)

        self._apply_btn = QPushButton(self.tr("Apply"))
        self._apply_btn.setObjectName("tool_button")
        self._apply_btn.clicked.connect(self._on_edit_tree)
        edit_row2.addWidget(self._apply_btn)
        layout.addLayout(edit_row2)

        self._result_view = QPlainTextEdit()
        self._result_view.setReadOnly(True)
        self._result_view.setFont(fm.get_code_font(10))
        self._result_view.setFixedHeight(70)
        layout.addWidget(self._result_view)

    def _on_refresh_tree(self) -> None:
        """Fetch and render the program tree hierarchy from the bridge."""
        if self._bridge is None:
            self._result_view.setPlainText("No bridge configured")
            return
        if not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return

        self._refresh_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.get_program_tree(),
            on_success=self._apply_program_tree,
            on_error=self._on_refresh_tree_error,
            parent=self,
            event="ghidra_get_program_tree",
            logger=_logger,
        )

    def _apply_program_tree(self, result: object) -> None:
        """Render the fetched program tree hierarchy into the tree widget.

        Args:
            result: Dict with a ``trees`` list from the bridge.
        """
        self._refresh_btn.setEnabled(True)
        self._tree.clear()
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return

        data = cast("dict[str, Any]", result)
        trees = data.get("trees", [])
        if not isinstance(trees, list):
            self._result_view.setPlainText("No program trees found")
            return

        tree_list = cast("list[dict[str, Any]]", trees)
        for tree_info in tree_list:
            tree_name = str(tree_info.get("name", ""))
            root = tree_info.get("root")
            root_item = QTreeWidgetItem([tree_name, "tree", ""])
            self._tree.addTopLevelItem(root_item)
            if isinstance(root, dict):
                self._populate_node(cast("dict[str, Any]", root), root_item)

        self._tree.expandAll()
        self._result_view.setPlainText(f"Loaded {len(tree_list)} program tree(s)")

    def _populate_node(self, node: dict[str, Any], parent_item: QTreeWidgetItem) -> None:
        """Recursively populate the tree widget from a module/fragment node.

        Args:
            node: Module or fragment node dict with ``name``, ``type``, and
                either ``children`` (module) or ``ranges`` (fragment).
            parent_item: Parent tree widget item to attach children to.
        """
        name = str(node.get("name", ""))
        node_type = str(node.get("type", ""))

        if node_type == "fragment":
            ranges = node.get("ranges", [])
            range_text = ""
            if isinstance(ranges, list) and ranges:
                range_list = cast("list[dict[str, Any]]", ranges)
                first = range_list[0]
                start = int(cast("int", first.get("start", 0)))
                end = int(cast("int", first.get("end", 0)))
                range_text = f"0x{start:X}-0x{end:X}"
                if len(range_list) > 1:
                    range_text += f" (+{len(range_list) - 1} more)"
            item = QTreeWidgetItem([name, node_type, range_text])
            tree_add_child(parent_item, item)
            return

        item = QTreeWidgetItem([name, node_type or "module", ""])
        tree_add_child(parent_item, item)
        children = node.get("children", [])
        if isinstance(children, list):
            for child in cast("list[dict[str, Any]]", children):
                self._populate_node(child, item)

    def _on_refresh_tree_error(self, exc: object) -> None:
        """Handle program tree retrieval failure.

        Args:
            exc: The exception that occurred.
        """
        self._refresh_btn.setEnabled(True)
        self._result_view.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_get_program_tree_gui_failed", error=str(exc))

    def _on_edit_tree(self) -> None:
        """Create or move a module/fragment via ``GhidraBridge.edit_program_tree``."""
        if self._bridge is None:
            self._result_view.setPlainText("No bridge configured")
            return
        if not self._bridge.state.is_ready():
            self._result_view.setPlainText("Ghidra not connected")
            return

        tree_name = self._tree_name_input.text().strip()
        if not tree_name:
            self._result_view.setPlainText("Program tree name required")
            return
        parent_module = self._parent_module_input.text().strip()
        if not parent_module:
            self._result_view.setPlainText("Parent module name required")
            return
        child_name = self._child_name_input.text().strip()
        if not child_name:
            self._result_view.setPlainText("Child name required")
            return
        operation = self._operation_combo.currentText()

        self._apply_btn.setEnabled(False)
        run_bridge_coroutine_logged(
            self._bridge.edit_program_tree(tree_name, operation, parent_module, child_name),
            on_success=self._apply_edit_tree,
            on_error=self._on_edit_tree_error,
            parent=self,
            event="ghidra_edit_program_tree",
            logger=_logger,
            level="info",
            tree_name=tree_name,
            operation=operation,
            parent_module=parent_module,
            child_name=child_name,
        )

    def _apply_edit_tree(self, result: object) -> None:
        """Render the result of a successful program tree edit and refresh the view.

        Args:
            result: Dict with tree_name, operation, child_name, and success
                from the bridge.
        """
        self._apply_btn.setEnabled(True)
        if not isinstance(result, dict):
            self._result_view.setPlainText(str(result))
            return

        info = cast("dict[str, Any]", result)
        if not info.get("success", False):
            self._result_view.setPlainText(f"Edit failed for '{info.get('child_name', '')}'")
            return

        self._result_view.setPlainText(
            f"{info.get('operation', '')}: '{info.get('child_name', '')}' in tree '{info.get('tree_name', '')}' succeeded",
        )
        self._on_refresh_tree()

    def _on_edit_tree_error(self, exc: object) -> None:
        """Handle program tree edit failure.

        Args:
            exc: The exception that occurred.
        """
        self._apply_btn.setEnabled(True)
        self._result_view.setPlainText(f"Error: {exc}")
        _logger.warning("ghidra_edit_program_tree_gui_failed", error=str(exc))
