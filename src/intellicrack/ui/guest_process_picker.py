# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Guest process picker dialog for sandbox memory-dump target selection.

Presents the live process list returned by
:meth:`~intellicrack.bridges.sandbox_bridge.SandboxBridge.list_guest_processes`
so the user can choose a ``target_pid`` before dumping a Windows Sandbox
guest process (S17-D10b / audit7 F-0021: ``SandboxBridge.memory_dump``
requires an explicit, positive ``target_pid`` for Windows Sandbox instances,
and the GUI could never supply one before this dialog existed).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Sequence

_logger = get_logger(__name__)

_PID_COLUMN = 0
_NAME_COLUMN = 1
_PATH_COLUMN = 2
_COLUMN_COUNT = 3
_MIN_WIDTH = 560
_MIN_HEIGHT = 360


class GuestProcessRow(TypedDict):
    """One guest process record as reported by the sandbox bridge.

    Attributes:
        pid: Guest-side process identifier.
        name: Process image name (e.g. ``notepad.exe``).
        path: Full path to the process executable, or an empty string when
            the guest could not report it (commonly a protected process).
    """

    pid: int
    name: str
    path: str


class GuestProcessPickerDialog(QDialog):
    """Modal dialog that lets the user pick a live guest process by PID.

    Displays the enumerated guest processes in a sortable, filterable table
    and returns the chosen PID via :meth:`selected_pid`. Selecting a row
    enables OK; double-clicking a row accepts immediately. Cancelling, or
    closing the dialog without a selection, leaves :meth:`selected_pid`
    returning ``None`` so the caller can distinguish "no target chosen" from
    a genuine PID.
    """

    def __init__(
        self,
        processes: Sequence[GuestProcessRow],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the picker with the enumerated guest processes.

        Args:
            processes: Guest process records to display, in the order
                supplied by the caller.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._processes: list[GuestProcessRow] = list(processes)
        self._selected_pid: int | None = None
        self.setWindowTitle("Select Guest Process")
        self.setMinimumSize(_MIN_WIDTH, _MIN_HEIGHT)
        self.setModal(True)
        self._build_ui()
        self._populate_table(self._processes)
        _logger.debug("guest_process_picker_opened", process_count=len(self._processes))

    def _build_ui(self) -> None:
        """Construct the dialog's widgets and layout."""
        layout = QVBoxLayout(self)

        header_label = QLabel("Choose the guest process to dump:")
        layout.addWidget(header_label)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("Filter by PID, name, or path")
        self._filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self._filter_edit)
        layout.addLayout(filter_row)

        self._table = QTableWidget()
        self._table.setColumnCount(_COLUMN_COUNT)
        self._table.setHorizontalHeaderLabels(["PID", "Name", "Path"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        v_header = self._table.verticalHeader()
        if v_header is not None:
            v_header.setVisible(False)
        header = self._table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(_PID_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(_NAME_COLUMN, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(_PATH_COLUMN, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

        self._empty_label = QLabel("The guest reported no running processes.")
        self._empty_label.setVisible(not self._processes)
        layout.addWidget(self._empty_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self._ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        if self._ok_button is not None:
            self._ok_button.setEnabled(False)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _populate_table(self, processes: Sequence[GuestProcessRow]) -> None:
        """Fill the table with the given process rows.

        Args:
            processes: Process records to display.
        """
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for row_data in processes:
            row = self._table.rowCount()
            self._table.insertRow(row)

            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, row_data["pid"])
            pid_item.setData(Qt.ItemDataRole.UserRole, row_data["pid"])
            self._table.setItem(row, _PID_COLUMN, pid_item)
            self._table.setItem(row, _NAME_COLUMN, QTableWidgetItem(row_data["name"]))
            self._table.setItem(row, _PATH_COLUMN, QTableWidgetItem(row_data["path"]))
        self._table.setSortingEnabled(True)

    def _apply_filter(self, text: str) -> None:
        """Hide table rows that do not match the filter text.

        Args:
            text: Case-insensitive substring matched against PID, name, and path.
        """
        needle = text.strip().lower()
        show_all = not needle
        for row in range(self._table.rowCount()):
            if show_all:
                self._table.setRowHidden(row, not show_all)
                continue
            parts: list[str] = []
            for column in range(_COLUMN_COUNT):
                item = self._table.item(row, column)
                if item is not None:
                    parts.append(item.text().lower())
            self._table.setRowHidden(row, not any(needle in part for part in parts))

    def _on_selection_changed(self) -> None:
        """Enable the OK button only while a row is selected."""
        model = self._table.selectionModel()
        has_selection = model is not None and bool(model.selectedRows())
        if self._ok_button is not None:
            self._ok_button.setEnabled(has_selection)

    def _on_double_click(self, _item: QTableWidgetItem) -> None:
        """Accept the dialog when a row is double-clicked.

        Args:
            _item: The double-clicked table item (unused; the current
                selection is read directly by :meth:`_on_accept`).
        """
        self._on_accept()

    def _on_accept(self) -> None:
        """Capture the selected PID and accept the dialog, if a row is selected."""
        current_row = self._table.currentRow()
        if current_row < 0:
            return
        pid_item = self._table.item(current_row, _PID_COLUMN)
        if pid_item is None:
            return
        pid_value = pid_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(pid_value, int):
            return
        self._selected_pid = pid_value
        _logger.info("guest_process_picker_selected", pid=pid_value)
        self.accept()

    def selected_pid(self) -> int | None:
        """Return the PID chosen by the user.

        Returns:
            int | None: The selected guest PID, or ``None`` when the dialog
            was cancelled or closed without a selection.
        """
        return self._selected_pid
