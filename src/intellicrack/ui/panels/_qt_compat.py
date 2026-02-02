"""Qt method compatibility layer for PyQt6 SIP-generated bindings.

Provides snake_case wrapper functions that delegate to PyQt6 camelCase
methods via dynamic attribute dispatch. These wrappers exist because the
basedpyright type checker cannot resolve certain method signatures from
the auto-generated PyQt6 type definitions. Each function performs a real
runtime call to the underlying Qt widget method.

Every wrapper validates that the target method exists at runtime and
raises ``AttributeError`` with a clear diagnostic if the method is
missing, ensuring failures are immediately identifiable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import (
        QPlainTextEdit,
        QTableWidget,
        QTableWidgetItem,
        QTreeWidget,
        QTreeWidgetItem,
    )

_logger = logging.getLogger(__name__)

_SORT_ENABLED = "setSortingEnabled"
_HEADER_LABELS = "setHeaderLabels"
_MAX_BLOCK_COUNT = "setMaximumBlockCount"
_EDIT_ITEM = "editItem"
_CURRENT_ITEM = "currentItem"
_SET_DATA = "setData"
_GET_DATA = "data"


def _resolve(obj: object, method_name: str) -> Callable[..., Any]:
    """Resolve a method on a Qt object, raising a clear error if absent.

    Args:
        obj: The Qt widget or item instance.
        method_name: The camelCase method name to look up.

    Returns:
        The bound method callable.

    Raises:
        AttributeError: If the method does not exist on the object.
    """
    if not hasattr(obj, method_name):
        cls_name = type(obj).__name__
        msg = f"{cls_name} has no method '{method_name}'; PyQt6 binding may be incompatible"
        raise AttributeError(msg)
    method: Callable[..., Any] = getattr(obj, method_name)
    return method


def set_sorting_enabled(table: QTableWidget, enable: bool) -> None:
    """Toggle sorting on a QTableWidget by dispatching to its native method.

    Args:
        table: The table widget.
        enable: Whether to enable sorting.
    """
    _resolve(table, _SORT_ENABLED)(enable)


def set_header_labels(tree: QTreeWidget, labels: list[str]) -> None:
    """Set column header labels on a QTreeWidget by dispatching to its native method.

    Args:
        tree: The tree widget.
        labels: Column header label strings.
    """
    _resolve(tree, _HEADER_LABELS)(labels)


def set_max_block_count(editor: QPlainTextEdit, maximum: int) -> None:
    """Set maximum block count on a QPlainTextEdit by dispatching to its native method.

    Args:
        editor: The plain text editor widget.
        maximum: Maximum number of text blocks to retain.
    """
    _resolve(editor, _MAX_BLOCK_COUNT)(maximum)


def edit_table_item(table: QTableWidget, item: QTableWidgetItem | None) -> None:
    """Begin editing a cell in a QTableWidget by dispatching to its native method.

    Args:
        table: The table widget.
        item: The cell item to edit, or None.
    """
    _resolve(table, _EDIT_ITEM)(item)


def get_current_tree_item(tree: QTreeWidget) -> QTreeWidgetItem | None:
    """Return the currently selected QTreeWidgetItem, or None if nothing is selected.

    Args:
        tree: The tree widget.

    Returns:
        The selected item or None.
    """
    return _resolve(tree, _CURRENT_ITEM)()


def tree_item_set_data(
    item: QTreeWidgetItem,
    column: int,
    role: Qt.ItemDataRole,
    value: object,
) -> None:
    """Store application data on a QTreeWidgetItem for the specified column and role.

    Args:
        item: The tree widget item.
        column: Column index.
        role: Qt item data role.
        value: Data value to store.
    """
    _resolve(item, _SET_DATA)(column, role, value)


def tree_item_data(
    item: QTreeWidgetItem,
    column: int,
    role: Qt.ItemDataRole,
) -> object:
    """Retrieve application data from a QTreeWidgetItem for the specified column and role.

    Args:
        item: The tree widget item.
        column: Column index.
        role: Qt item data role.

    Returns:
        The stored data value.
    """
    return _resolve(item, _GET_DATA)(column, role)
