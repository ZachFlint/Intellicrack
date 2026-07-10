# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gates for ``intellicrack.ui.panels.ghidra_panel_extras``.

Covers the 2026-07-02 audit findings for ``ghidra_panel_extras.py``:

* M48 -- the external references table's header must use
  ``QHeaderView.ResizeMode.Stretch`` so the ``External Name`` / ``Library``
  columns fill the available width instead of clipping at Qt's narrow
  default ``Interactive`` section width.
* M49 -- the properties table's header must use the same ``Stretch`` resize
  mode so long, free-form property values are not clipped either.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QApplication, QHeaderView, QTableWidget

from intellicrack.ui.panels.ghidra_panel_extras import GhidraAnalysisExtrasWidget


def _make_widget(qapp: QApplication) -> GhidraAnalysisExtrasWidget:
    """Build a shown, sized Analysis Extras widget for header-layout checks.

    Args:
        qapp: The shared QApplication fixture.

    Returns:
        GhidraAnalysisExtrasWidget: A sized, visible widget with no bridge attached.
    """
    _ = qapp
    widget = GhidraAnalysisExtrasWidget()
    widget.resize(900, 700)
    widget.show()
    QApplication.processEvents()
    return widget


def _assert_all_sections_stretch(table: QTableWidget) -> None:
    """Assert every column of ``table`` uses the Stretch resize mode.

    Args:
        table: The table whose horizontal header sections are checked.
    """
    header = table.horizontalHeader()
    assert header is not None, "table has no horizontal header"
    for column in range(table.columnCount()):
        assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.Stretch, (
            f"column {column} of {table.objectName() or table!r} is not set to Stretch resize mode"
        )


def _assert_columns_fill_viewport(table: QTableWidget) -> None:
    """Assert the header's total section length fills the table viewport width.

    With ``Stretch`` in effect the header always expands its sections to
    consume the full viewport width; with the pre-fix default
    ``Interactive`` mode the sections stay pinned near Qt's narrow default
    section width regardless of how wide the table is resized.

    Args:
        table: The table to measure after a resize + processEvents cycle.
    """
    header = table.horizontalHeader()
    assert header is not None, "table has no horizontal header"
    viewport = table.viewport()
    assert viewport is not None, "table has no viewport"
    assert abs(header.length() - viewport.width()) <= 2, (
        f"header sections (total {header.length()}px) do not fill the "
        f"{viewport.width()}px viewport; columns are not stretching to the available width"
    )


class TestM48ExtRefsTableStretchResize:
    """M48: the external references table's columns must stretch to fill available width."""

    @staticmethod
    def test_m48_ext_refs_header_uses_stretch_resize_mode(qapp: QApplication) -> None:
        """Every column of ``_ext_refs_table`` must use Stretch resize mode.

        Regression: pre-fix, the table was built with only
        ``setSelectionBehavior``/``setEditTriggers``/``setFixedHeight`` and
        no ``setSectionResizeMode`` call, so the header defaulted to
        ``Interactive`` with narrow fixed-width sections.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            _assert_all_sections_stretch(widget._ext_refs_table)
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m48_ext_refs_columns_fill_full_table_width_after_resize(qapp: QApplication) -> None:
        """Widening the table must widen its columns to fill the new width.

        Regression: with no resize mode set, the pre-fix header stayed
        pinned near Qt's narrow ``Interactive`` default column width even
        after the table itself grew, so long ``External Name`` / ``Library``
        values would still render inside a visually clipped column.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            table = widget._ext_refs_table
            table.resize(1200, table.height())
            QApplication.processEvents()
            _assert_columns_fill_viewport(table)
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m48_long_external_name_and_library_render_in_stretched_columns(qapp: QApplication) -> None:
        """A long mangled symbol name and library path populate under active stretch sizing.

        Drives the real ``_apply_external_refs`` handler with a realistic
        long C++-mangled export name and library path, then confirms the
        ``External Name`` column has grown well past Qt's ~100px
        interactive default once the table is widened, proving the stretch
        policy is actually reserving space for the long value rather than
        leaving it pinned at the narrow default.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            table = widget._ext_refs_table
            long_name = "?_Xlength_error@std@@YAXPEBD@Z"
            long_library = "C:\\Program Files\\VendorSuite\\components\\native_runtime_x64_full.dll"
            widget._apply_external_refs(
                [
                    {
                        "address": 0x1000,
                        "external_name": long_name,
                        "library": long_library,
                        "type": "function",
                    },
                ],
            )
            assert table.rowCount() == 1
            name_item = table.item(0, 1)
            library_item = table.item(0, 2)
            assert name_item is not None
            assert name_item.text() == long_name
            assert library_item is not None
            assert library_item.text() == long_library

            table.resize(1200, table.height())
            QApplication.processEvents()
            _assert_columns_fill_viewport(table)
            header = table.horizontalHeader()
            assert header is not None
            assert header.sectionSize(1) > 100, "External Name column stayed at the narrow default width instead of stretching"
        finally:
            widget.deleteLater()


class TestM49PropertiesTableStretchResize:
    """M49: the properties table's columns must stretch to fill available width."""

    @staticmethod
    def test_m49_properties_header_uses_stretch_resize_mode(qapp: QApplication) -> None:
        """Every column of ``_properties_table`` must use Stretch resize mode.

        Regression: pre-fix, the table was built the same way as
        ``_ext_refs_table`` -- only ``setSelectionBehavior``/
        ``setEditTriggers``/``setFixedHeight`` -- with no
        ``setSectionResizeMode`` call, so the header defaulted to
        ``Interactive`` with narrow fixed-width sections.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            _assert_all_sections_stretch(widget._properties_table)
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m49_properties_columns_fill_full_table_width_after_resize(qapp: QApplication) -> None:
        """Widening the table must widen its columns to fill the new width.

        Regression: with no resize mode set, the pre-fix header stayed
        pinned near Qt's narrow ``Interactive`` default column width even
        after the table itself grew, so a long user-defined property value
        would still render inside a visually clipped ``Value`` column.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            table = widget._properties_table
            table.resize(1200, table.height())
            QApplication.processEvents()
            _assert_columns_fill_viewport(table)
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m49_long_property_value_renders_in_stretched_value_column(qapp: QApplication) -> None:
        """A long analyst-entered property value populates under active stretch sizing.

        Drives the real ``_apply_properties`` handler with a
        dict-shaped bridge result carrying a long free-form note, then
        confirms the ``Value`` column has grown well past Qt's ~100px
        interactive default once the table is widened, proving the stretch
        policy is actually reserving space for the long value rather than
        leaving it pinned at the narrow default.

        Args:
            qapp: The shared QApplication fixture.
        """
        widget = _make_widget(qapp)
        try:
            table = widget._properties_table
            long_value = (
                "Analyst note: this routine re-implements the vendor's licence "
                "check using a rolling XOR over the machine GUID before comparing "
                "against the embedded activation blob at offset 0x4120."
            )
            widget._apply_properties(
                {
                    "address": 0x2000,
                    "properties": {"AnalystNote": long_value},
                },
            )
            assert table.rowCount() == 1
            name_item = table.item(0, 0)
            value_item = table.item(0, 1)
            assert name_item is not None
            assert name_item.text() == "AnalystNote"
            assert value_item is not None
            assert value_item.text() == long_value

            table.resize(1200, table.height())
            QApplication.processEvents()
            _assert_columns_fill_viewport(table)
            header = table.horizontalHeader()
            assert header is not None
            assert header.sectionSize(1) > 100, "Value column stayed at the narrow default width instead of stretching"
        finally:
            widget.deleteLater()
