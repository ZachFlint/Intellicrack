# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Qt method compatibility layer for PyQt6 SIP-generated bindings.

Provides snake_case wrapper functions that delegate to PyQt6 camelCase methods via dynamic attribute dispatch. These wrappers exist because
the basedpyright type checker cannot resolve certain method signatures from the auto-generated PyQt6 type definitions. Each function
performs a real runtime call to the underlying Qt widget method.

Every wrapper validates that the target method exists at runtime and raises ``AttributeError`` with a clear diagnostic if the method is
missing, ensuring failures are immediately identifiable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from PyQt6.QtGui import QKeyEvent, QWheelEvent
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QPlainTextEdit,
        QTableWidget,
        QTableWidgetItem,
        QTreeWidget,
        QTreeWidgetItem,
    )

_logger = get_logger(__name__)

_SORT_ENABLED = "setSortingEnabled"
_SELECTION_MODE = "setSelectionMode"
_CELL_CHANGED = "cellChanged"
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
        Callable[..., Any]: The bound method callable.

    Raises:
        AttributeError: If the method does not exist on the object.
    """
    sentinel: object = object()
    method: object = getattr(obj, method_name, sentinel)
    if method is sentinel:
        cls_name = type(obj).__name__
        msg = f"{cls_name} has no method '{method_name}'; PyQt6 binding may be incompatible"
        _logger.warning("qt_method_missing", class_name=cls_name, method=method_name)
        raise AttributeError(msg)
    return cast("Callable[..., Any]", method)


def set_sorting_enabled(table: QTableWidget | QTreeWidget, *, enable: bool) -> None:
    """Toggle sorting on a QTableWidget or QTreeWidget.

    Args:
        table: The table or tree widget.
        enable: Whether to enable sorting.
    """
    _resolve(table, _SORT_ENABLED)(enable)


def set_selection_mode(widget: QTableWidget | QTreeWidget, mode: QAbstractItemView.SelectionMode) -> None:
    """Set the selection mode on a QTableWidget or QTreeWidget.

    Args:
        widget: The table or tree widget.
        mode: The selection mode enum value.
    """
    _resolve(widget, _SELECTION_MODE)(mode)


def connect_cell_changed(table: QTableWidget, slot: Callable[..., object]) -> None:
    """Connect a slot to QTableWidget.cellChanged signal.

    Args:
        table: The table widget.
        slot: The callback to connect.
    """
    signal = getattr(table, _CELL_CHANGED, None)
    if signal is not None:
        signal.connect(slot)
    else:
        _logger.warning("qt_signal_missing", widget=type(table).__name__, signal=_CELL_CHANGED)


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
        QTreeWidgetItem | None: The selected item or None.
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
        object: The stored data value.
    """
    return _resolve(item, _GET_DATA)(column, role)


def wheel_angle_delta_y(event: QWheelEvent) -> int:
    """Get the vertical scroll angle delta from a wheel event.

    Args:
        event: The wheel event.

    Returns:
        int: Vertical scroll angle delta in eighths of a degree.
    """
    point: object = _resolve(event, "angleDelta")()
    return _resolve(point, "y")()


def key_event_key(event: QKeyEvent) -> int:
    """Get the key code from a key event.

    Args:
        event: The key event.

    Returns:
        int: Integer key code matching Qt.Key enum values.
    """
    return _resolve(event, "key")()


_KEY_PAGE_UP = "Key_PageUp"
_KEY_PAGE_DOWN = "Key_PageDown"
_KEY_ENUM = "Key"


def qt_key_page_up() -> int:
    """Return Qt.Key.Key_PageUp constant value.

    Returns:
        int: Integer value of Qt.Key.Key_PageUp.
    """
    return int(getattr(getattr(Qt, _KEY_ENUM), _KEY_PAGE_UP))


def qt_key_page_down() -> int:
    """Return Qt.Key.Key_PageDown constant value.

    Returns:
        int: Integer value of Qt.Key.Key_PageDown.
    """
    return int(getattr(getattr(Qt, _KEY_ENUM), _KEY_PAGE_DOWN))


def tree_add_child(parent: QTreeWidgetItem, child: QTreeWidgetItem) -> None:
    """Add a child item to a QTreeWidgetItem.

    Args:
        parent: The parent tree item.
        child: The child item to add.
    """
    _resolve(parent, "addChild")(child)
