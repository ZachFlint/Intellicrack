# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for S14-D04 and S14-D14 in the process System->Pipes sub-tab.

S14-D04: the Pipes sub-tab's pipe table had no ``setSelectionBehavior`` call,
so ``QTableWidget``'s default cell-based selection meant a user click never
selected a full row. ``_selected_pipe`` (and therefore the Read/Write/Close
actions) reads the row via ``selectionModel().selectedRows()``, which only
returns entries when whole rows are selected -- with the default behaviour
that method silently returns an empty list even after the user clicks a
cell, making Read/Write permanently inert. The fix adds
``setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)`` to the
pipe table, matching every other table in this file.

S14-D14: the Pipe/Data (hex) area -- the write box and its border -- was
clipped at the bottom of the tab with no way to scroll to it, because the
tab's content was placed directly in the tab widget with no scroll
fallback. The fix builds the tab content in an inner widget and wraps it
with :func:`intellicrack.ui.panels.base_panel.make_scrollable`, returning a
``QScrollArea`` (vertical policy ``ScrollBarAsNeeded``, never
``ScrollBarAlwaysOff``) as the "Pipes" tab widget.

Both tests drive the real :class:`SystemTab` widget end to end (real Qt
widgets, no mocks) and fail if either fix is reverted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QWidget,
)

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel.system_tab import SystemTab


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def tab(qapp: QApplication) -> Generator[SystemTab]:
    """Build a real :class:`SystemTab` bound to a live, unattached bridge.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        SystemTab: A ``SystemTab`` retained for the test body and
        deterministically torn down afterwards.
    """
    del qapp
    widget = SystemTab()
    widget.set_bridge(ProcessBridge())
    yield widget
    widget.deleteLater()
    app = QApplication.instance()
    if app is not None:
        app.processEvents()


def _activate_pipes_tab(tab: SystemTab) -> QWidget:
    """Select the "Pipes" sub-tab and return its hosting widget.

    Switching the sub-tab to current is required before simulating a real
    mouse click on child widgets: a ``QTabWidget`` hides every page except
    the current one, and hidden pages are never laid out, so their child
    views would report zero-size geometry.

    Args:
        tab: The real ``SystemTab`` under test.

    Returns:
        QWidget: The widget instance ``_tabs`` holds for the "Pipes" tab.

    Raises:
        AssertionError: If no sub-tab titled "Pipes" is found.
    """
    tabs = tab._tabs
    assert isinstance(tabs, QTabWidget)
    for index in range(tabs.count()):
        if tabs.tabText(index) == "Pipes":
            tabs.setCurrentIndex(index)
            widget = tabs.widget(index)
            assert widget is not None
            return widget
    pytest.fail("Pipes sub-tab not found on SystemTab")
    raise AssertionError


def _is_descendant(ancestor: QWidget, widget: QWidget) -> bool:
    """Check whether ``widget`` is a descendant of ``ancestor`` in the Qt widget tree.

    Args:
        ancestor: Candidate ancestor widget.
        widget: Widget to test for descendance.

    Returns:
        bool: True when ``widget``'s parent chain reaches ``ancestor``.
    """
    current: QWidget | None = widget
    while current is not None:
        if current is ancestor:
            return True
        current = current.parentWidget()
    return False


def test_pipe_table_selection_behavior_is_select_rows(tab: SystemTab) -> None:
    """S14-D04: the pipe table must select whole rows so Read/Write can resolve a selection.

    Args:
        tab: Real ``SystemTab`` fixture.
    """
    pipe_table = tab._pipe_table
    assert isinstance(pipe_table, QTableWidget)
    assert pipe_table.selectionBehavior() == QAbstractItemView.SelectionBehavior.SelectRows


def test_pipe_table_click_selects_full_row_for_read_write(tab: SystemTab) -> None:
    """S14-D04: a real mouse click on a single pipe-table cell must select the whole row.

    This exercises Qt's actual mouse-press selection path (``QTest.mouseClick``
    on the viewport), not a synthetic full-row selection helper. ``_selected_pipe``
    (and therefore the Read/Write/Close actions) resolves the acting row via
    ``selectionModel().selectedRows()``, which only reports a row once every
    column in that row is selected. Under the pre-fix default selection
    behaviour (``SelectItems``), clicking a single cell selects only that one
    cell, ``isRowSelected`` is false for every row, ``selectedRows()`` returns
    an empty list, and ``_selected_pipe`` returns ``None`` -- Read/Write can
    never resolve a target. With ``SelectRows`` set, Qt's built-in click
    handling automatically expands the selection to the full row.

    Args:
        tab: Real ``SystemTab`` fixture.
    """
    _activate_pipes_tab(tab)
    pipe_table = tab._pipe_table
    pipe_table.insertRow(0)
    pipe_table.setItem(0, 0, QTableWidgetItem("\\\\.\\pipe\\MyPipe"))
    pipe_table.setItem(0, 1, QTableWidgetItem("0x1234"))

    tab.resize(600, 400)
    tab.show()
    QApplication.processEvents()

    model = pipe_table.model()
    assert model is not None
    index = model.index(0, 1)
    rect = pipe_table.visualRect(index)
    assert rect.isValid()

    pipe_table.clearSelection()
    QTest.mouseClick(pipe_table.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, rect.center())
    QApplication.processEvents()

    selected = tab._selected_pipe()
    tab.hide()
    assert selected == ("\\\\.\\pipe\\MyPipe", 0x1234)


def test_pipes_tab_is_hosted_in_scrollable_area(tab: SystemTab) -> None:
    """S14-D14: the Pipes tab content must be wrapped in a scroll area to avoid bottom clipping.

    Args:
        tab: Real ``SystemTab`` fixture.
    """
    pipes_widget = _activate_pipes_tab(tab)
    assert isinstance(pipes_widget, QScrollArea)
    assert pipes_widget.verticalScrollBarPolicy() != Qt.ScrollBarPolicy.ScrollBarAlwaysOff
    assert pipes_widget.widgetResizable() is True

    inner = pipes_widget.widget()
    assert inner is not None
    pipe_io_data = tab._pipe_io_data
    assert pipe_io_data is not None
    assert _is_descendant(inner, pipe_io_data)
