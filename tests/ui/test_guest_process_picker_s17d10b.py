# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for :class:`~intellicrack.ui.guest_process_picker.GuestProcessPickerDialog`.

Drives the real dialog widget end to end - construction, row population,
filtering, selection, double-click accept, and cancel - without ever calling
``exec()`` (which would block on a real modal event loop in a headless test).
Selection and acceptance are driven directly through the table widget and the
dialog's own slots, exactly as Qt itself would invoke them from a click.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt

from intellicrack.ui.guest_process_picker import GuestProcessPickerDialog, GuestProcessRow


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_PID_COLUMN = 0
_NAME_COLUMN = 1
_PATH_COLUMN = 2

_SAMPLE_PROCESSES: list[GuestProcessRow] = [
    GuestProcessRow(pid=101, name="explorer.exe", path=r"C:\Windows\explorer.exe"),
    GuestProcessRow(pid=4242, name="notepad.exe", path=r"C:\Windows\notepad.exe"),
    GuestProcessRow(pid=777, name="svchost.exe", path=r"C:\Windows\System32\svchost.exe"),
]


def test_construction_populates_one_row_per_process(qapp: QApplication) -> None:
    """The table gets exactly one row per supplied process, in order.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        assert dialog._table.rowCount() == len(_SAMPLE_PROCESSES)
        pids_in_table = {dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole) for row in range(dialog._table.rowCount())}
        assert pids_in_table == {proc["pid"] for proc in _SAMPLE_PROCESSES}
    finally:
        dialog.deleteLater()


def test_empty_process_list_shows_the_empty_label(qapp: QApplication) -> None:
    """An empty process list produces zero rows and a visible empty-state label.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog([])
    try:
        assert dialog._table.rowCount() == 0
        # The dialog is never shown in this test, so `isVisible()` would read
        # False for every child regardless of its own visibility flag (it
        # also depends on ancestor visibility); `isHidden()` reflects the
        # widget's own flag directly.
        assert not dialog._empty_label.isHidden()
    finally:
        dialog.deleteLater()


def test_no_selection_starts_with_pid_none_and_ok_disabled(qapp: QApplication) -> None:
    """Before any row is selected, ``selected_pid()`` is ``None`` and OK is disabled.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        assert dialog.selected_pid() is None
        assert dialog._ok_button is not None
        assert not dialog._ok_button.isEnabled()
    finally:
        dialog.deleteLater()


def test_selecting_a_row_enables_ok(qapp: QApplication) -> None:
    """Selecting any row enables the OK button.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        dialog._table.selectRow(1)
        assert dialog._ok_button is not None
        assert dialog._ok_button.isEnabled()
    finally:
        dialog.deleteLater()


def test_accept_captures_the_pid_of_the_selected_row(qapp: QApplication) -> None:
    """Accepting after selecting a row captures that row's PID, not another row's.

    Falsified by: an off-by-one row lookup in ``_on_accept`` (e.g. always
    reading row 0) would make this assert the wrong PID for a selection on
    row 1 or row 2.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        target_row = next(
            row for row in range(dialog._table.rowCount()) if dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole) == 4242
        )
        dialog._table.selectRow(target_row)
        dialog._on_accept()

        assert dialog.selected_pid() == 4242
        assert dialog.result() == int(dialog.DialogCode.Accepted.value)
    finally:
        dialog.deleteLater()


def test_double_click_accepts_immediately(qapp: QApplication) -> None:
    """Double-clicking a row accepts the dialog with that row's PID.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        target_row = next(
            row for row in range(dialog._table.rowCount()) if dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole) == 777
        )
        dialog._table.selectRow(target_row)
        item = dialog._table.item(target_row, _NAME_COLUMN)
        assert item is not None
        dialog._on_double_click(item)

        assert dialog.selected_pid() == 777
        assert dialog.result() == int(dialog.DialogCode.Accepted.value)
    finally:
        dialog.deleteLater()


def test_reject_leaves_selected_pid_none(qapp: QApplication) -> None:
    """Rejecting (Cancel) after a selection must not capture any PID.

    Falsified by: wiring the Cancel button to ``_on_accept`` instead of
    ``reject`` would make ``selected_pid()`` return the selected row's PID
    here instead of ``None``.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        dialog._table.selectRow(0)
        dialog.reject()

        assert dialog.selected_pid() is None
        assert dialog.result() == int(dialog.DialogCode.Rejected.value)
    finally:
        dialog.deleteLater()


def test_accept_with_no_row_selected_does_not_accept(qapp: QApplication) -> None:
    """Calling accept-logic with no selection must not close the dialog as accepted.

    Guards the ``current_row < 0`` early-return in ``_on_accept``: without it,
    accepting with nothing selected would either crash or capture a bogus PID.

    Args:
        qapp: Session ``QApplication`` fixture.
    """
    assert qapp is not None
    dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
    try:
        dialog._on_accept()

        assert dialog.selected_pid() is None
        assert dialog.result() != int(dialog.DialogCode.Accepted.value)
    finally:
        dialog.deleteLater()


class TestFiltering:
    """The filter box hides rows that do not match, and restores them when cleared."""

    def test_filter_by_pid_hides_non_matching_rows(self, qapp: QApplication) -> None:
        """Filtering by a PID substring hides every row not containing it.

        Args:
            qapp: Session ``QApplication`` fixture.
        """
        assert qapp is not None
        dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
        try:
            dialog._filter_edit.setText("4242")

            hidden = {
                dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole): dialog._table.isRowHidden(row)
                for row in range(dialog._table.rowCount())
            }
            assert hidden[4242] is False, "the matching row must stay visible"
            assert hidden[101] is True, "a non-matching row must be hidden"
            assert hidden[777] is True, "a non-matching row must be hidden"
        finally:
            dialog.deleteLater()

    def test_filter_by_name_is_case_insensitive(self, qapp: QApplication) -> None:
        """Filtering by process name matches regardless of case.

        Args:
            qapp: Session ``QApplication`` fixture.
        """
        assert qapp is not None
        dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
        try:
            dialog._filter_edit.setText("NOTEPAD")

            hidden = {
                dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole): dialog._table.isRowHidden(row)
                for row in range(dialog._table.rowCount())
            }
            assert hidden[4242] is False
            assert hidden[101] is True
            assert hidden[777] is True
        finally:
            dialog.deleteLater()

    def test_filter_by_path_matches(self, qapp: QApplication) -> None:
        """Filtering by a path substring matches the Path column too.

        Args:
            qapp: Session ``QApplication`` fixture.
        """
        assert qapp is not None
        dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
        try:
            dialog._filter_edit.setText("System32")

            hidden = {
                dialog._table.item(row, _PID_COLUMN).data(Qt.ItemDataRole.UserRole): dialog._table.isRowHidden(row)
                for row in range(dialog._table.rowCount())
            }
            assert hidden[777] is False, "svchost.exe's path contains System32"
            assert hidden[101] is True
            assert hidden[4242] is True
        finally:
            dialog.deleteLater()

    def test_clearing_the_filter_restores_every_row(self, qapp: QApplication) -> None:
        """Clearing the filter text back to empty shows every row again.

        Args:
            qapp: Session ``QApplication`` fixture.
        """
        assert qapp is not None
        dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
        try:
            dialog._filter_edit.setText("4242")
            dialog._filter_edit.setText("")

            still_hidden = [row for row in range(dialog._table.rowCount()) if dialog._table.isRowHidden(row)]
            assert still_hidden == [], f"clearing the filter must show every row again; still hidden: {still_hidden}"
        finally:
            dialog.deleteLater()

    def test_filter_matching_nothing_hides_every_row(self, qapp: QApplication) -> None:
        """A filter string matching no process hides every row.

        Args:
            qapp: Session ``QApplication`` fixture.
        """
        assert qapp is not None
        dialog = GuestProcessPickerDialog(_SAMPLE_PROCESSES)
        try:
            dialog._filter_edit.setText("no-such-process-name")

            all_hidden = all(dialog._table.isRowHidden(row) for row in range(dialog._table.rowCount()))
            assert all_hidden, "a filter matching nothing must hide every row"
        finally:
            dialog.deleteLater()
