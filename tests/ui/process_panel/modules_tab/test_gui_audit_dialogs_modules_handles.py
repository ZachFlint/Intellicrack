# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit finding: ModulesTab handle table clipping.

The handle enumeration table (Handle Value / Type / Granted Access / Object
Address) previously used the default equal-width columns with no stretch and
no tooltips, so the wide hexadecimal granted-access mask and object address
were silently clipped. These tests pin the fix:

* The handle table configures a real resize policy with a stretch column and
  content-sized columns for the fixed-width hex values.
* Populated cells expose the full value as a tooltip so clipped text remains
  readable on hover.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QHeaderView

from intellicrack.ui.panels.process_panel.modules_tab import ModulesTab


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication, QTableWidget


def _handle_table(tab: ModulesTab) -> QTableWidget:
    """Return the handle enumeration table without tripping private-usage checks.

    Args:
        tab: The ModulesTab owning the handle table.

    Returns:
        QTableWidget: The handle table widget.
    """
    value: object = getattr(tab, "_handle_table")
    return cast("QTableWidget", value)


def _set_handle_cell(tab: ModulesTab, row: int, column: int, text: str) -> None:
    """Invoke the private handle-cell setter without tripping private-usage checks.

    Args:
        tab: The ModulesTab under test.
        row: Zero-based table row index.
        column: Zero-based table column index.
        text: Cell display text.
    """
    setter: object = getattr(tab, "_set_handle_cell")
    cast("Callable[[int, int, str], None]", setter)(row, column, text)


@pytest.fixture
def modules_tab(qapp: QApplication) -> Iterator[ModulesTab]:
    """Create a ModulesTab ready for handle-table assertions.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        ModulesTab: A ready-to-use tab instance.
    """
    del qapp
    tab = ModulesTab()
    yield tab
    tab.deleteLater()


class TestHandleTableColumnPolicy:
    """The handle table must use a real resize policy instead of clipping."""

    def test_type_column_stretches_and_hex_columns_size_to_contents(self, modules_tab: ModulesTab) -> None:
        """One column stretches while the fixed-width hex columns size to their contents.

        Args:
            modules_tab: ModulesTab fixture.
        """
        table = _handle_table(modules_tab)
        header = table.horizontalHeader()
        assert header is not None, "handle table must have a horizontal header"

        modes = [header.sectionResizeMode(i) for i in range(table.columnCount())]
        assert QHeaderView.ResizeMode.Stretch in modes, (
            f"at least one handle-table column must stretch to fill available width; got modes {modes}"
        )
        assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.ResizeToContents, (
            "the Granted Access column must size to its content so the full mask is shown"
        )
        assert header.sectionResizeMode(3) == QHeaderView.ResizeMode.ResizeToContents, (
            "the Object Address column must size to its content so the full address is shown"
        )

    def test_populated_cell_exposes_full_value_as_tooltip(self, modules_tab: ModulesTab) -> None:
        """A wide object-address cell keeps its full value discoverable via tooltip.

        Args:
            modules_tab: ModulesTab fixture.
        """
        full_value = "0xDEADBEEFCAFEF00D"
        table = _handle_table(modules_tab)
        table.insertRow(0)
        _set_handle_cell(modules_tab, 0, 3, full_value)

        item = table.item(0, 3)
        assert item is not None, "cell must be populated"
        assert item.text() == full_value, "cell text must be the full value"
        assert item.toolTip() == full_value, "the cell tooltip must equal the full value so a clipped address stays readable on hover"
