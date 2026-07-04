# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings in ``x64dbg_advanced_tab``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``H27``: the Handles table must coerce the bridge's hex-string handle
  values (``"0x1a4"``) to real integers instead of silently collapsing every
  row to ``0x0``, both in the rendered cell and in the row-selection
  round-trip that feeds the Close Handle field.
* ``M63``: the Handles table header must stretch only the variable-length
  "Object" column and size the remaining short columns to their content, and
  the "Object" cell must carry a tooltip so elided text is recoverable.
* ``L15``: the Module Info table (shared by the imports and PE-directories
  views) must stretch only the variable-length "Name" column for whichever
  view is active, and "Name" cells must carry a tooltip.
* ``L16``: the breakpoint-config and script-engine status labels must word
  wrap so unbounded error text grows the label vertically instead of
  overflowing or clipping horizontally.

All tests drive a real :class:`X64DbgAdvancedTab` under an offscreen
``QApplication``, calling its real handler/apply methods directly with
synthetic bridge-shaped data (no bridge connection is required to exercise
these code paths).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QHeaderView, QPushButton

from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def _make_tab(qapp: QApplication) -> X64DbgAdvancedTab:
    """Build a real, bridge-less ``X64DbgAdvancedTab`` for direct method calls.

    Args:
        qapp: The shared offscreen ``QApplication`` fixture.

    Returns:
        X64DbgAdvancedTab: A freshly constructed advanced tab widget.
    """
    _ = qapp
    return X64DbgAdvancedTab()


class TestH27HandleValueCoercion:
    """H27: hex-string handle values from the bridge must resolve as real ints."""

    def test_h27_coerce_handle_value_parses_hex_string(self, qapp: QApplication) -> None:
        """``_coerce_handle_value`` parses a bridge hex string to its real int.

        Pre-fix there was no coercion helper; the call site only accepted
        ``isinstance(handle_val, int)`` and silently returned 0 for every
        string value, which is what the bridge always sends.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        assert tab._coerce_handle_value("0x1a4") == 0x1A4
        assert tab._coerce_handle_value("0x0") == 0
        assert tab._coerce_handle_value(4096) == 4096
        assert tab._coerce_handle_value("not-a-handle") == 0

    def test_h27_apply_handles_renders_real_handle_value_not_zero(self, qapp: QApplication) -> None:
        """``_apply_handles`` renders the bridge's real hex-string handle value.

        The bridge (``X64DbgBridge.get_handles``) emits
        ``"handle": hex(int(entry.HandleValue or 0))``, a ``str``. Pre-fix,
        ``handle_val if isinstance(handle_val, int) else 0`` coerced every
        such string to 0, so every row rendered ``"0x0"`` regardless of the
        real handle.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        tab._apply_handles(
            [
                {
                    "handle": "0x1a4",
                    "object": "0xffffb00012345678",
                    "granted_access": "0x1fffff",
                    "object_type_index": 42,
                    "handle_attributes": 0,
                },
            ],
        )

        handle_item = tab._handles_table.item(0, 0)
        assert handle_item is not None
        assert handle_item.text() == "0x1A4", f"expected real handle value, got {handle_item.text()!r}"
        assert handle_item.data(Qt.ItemDataRole.UserRole) == 0x1A4

    def test_h27_row_selection_populates_close_field_with_real_handle(self, qapp: QApplication) -> None:
        """Selecting a handle row must populate Close Handle with the real value.

        ``_on_handle_row_selected`` reads back the same ``UserRole`` data
        that ``_apply_handles`` stored; pre-fix that data was always 0, so
        Close Handle could never target the handle the user actually
        selected.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        tab._apply_handles(
            [{"handle": "0x2bc", "object": "0x1", "granted_access": "0x1", "object_type_index": 1, "handle_attributes": 0}],
        )

        tab._on_handle_row_selected(0, 0)

        assert tab._handles_close_input.text() == "0x2BC", (
            f"Close Handle field was populated with {tab._handles_close_input.text()!r}, not the real selected handle value"
        )


class TestM63HandlesTableLayout:
    """M63: the Handles header stretches only "Object"; others size-to-content."""

    def test_m63_object_column_stretches_other_columns_fit_content(self, qapp: QApplication) -> None:
        """Only the "Object" column (index 1) uses Stretch resize mode.

        Pre-fix, a single header-wide ``setSectionResizeMode(Stretch)`` call
        put all 5 columns in Stretch mode, so every short numeric column
        (Handle, Granted Access, Type Index, Attributes) claimed the same
        width share as the variable-length Object column.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        header = tab._handles_table.horizontalHeader()
        assert header is not None

        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Object column must stretch"
        for column in (0, 2, 3, 4):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} must size to its content, not stretch uniformly"
            )

    def test_m63_object_cell_carries_tooltip_for_elided_text(self, qapp: QApplication) -> None:
        """The "Object" cell's tooltip recovers the full text when elided.

        Pre-fix, no tooltip was set on the Object cell, so eliding the
        squeezed column left no way to recover the full identifier.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        long_object = "0xffffb0001234567890abcdef"
        tab._apply_handles(
            [{"handle": "0x1", "object": long_object, "granted_access": "0x1", "object_type_index": 1, "handle_attributes": 0}],
        )

        object_item = tab._handles_table.item(0, 1)
        assert object_item is not None
        assert object_item.toolTip() == long_object, "Object cell tooltip does not carry the full, un-elided value"


class TestL15ModinfoTableLayout:
    """L15: the Module Info header stretches only the active "Name" column."""

    def test_l15_imports_view_stretches_name_column(self, qapp: QApplication) -> None:
        """In the imports view (built at construction) Name (col 0) stretches.

        Pre-fix, a single header-wide Stretch call put all 4 columns in
        Stretch mode uniformly, regardless of which column held the
        variable-length import name.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        header = tab._modinfo_table.horizontalHeader()
        assert header is not None

        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "Name column must stretch in imports view"
        for column in (1, 2, 3):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} must size to its content in imports view"
            )

    def test_l15_pe_directories_view_moves_stretch_to_name_column(self, qapp: QApplication) -> None:
        """Switching to the PE-directories view re-targets Stretch to col 1.

        The PE-directories view's "Name" column is index 1, not 0. Pre-fix
        there was no per-view resize-mode call at all (and no
        ``_apply_modinfo_resize_modes`` method existed), so the header
        stayed uniformly stretched across all 4 columns no matter which
        view was active.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        tab._apply_modinfo_resize_modes(name_column=1)
        header = tab._modinfo_table.horizontalHeader()
        assert header is not None

        assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Name column must stretch in PE-directories view"
        for column in (0, 2, 3):
            assert header.sectionResizeMode(column) == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} must size to its content in PE-directories view"
            )

    def test_l15_import_name_cell_carries_tooltip(self, qapp: QApplication) -> None:
        """A long undecorated import name gets a matching tooltip.

        Pre-fix, no tooltip was set on the Name cell in the imports view.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        long_name = "?CreateInstanceFromDecoratedTemplateArgumentPack@@YAXPEAVIFactory@@0@Z"
        tab._apply_module_imports([{"undecoratedName": long_name, "ordinal": 12, "iatRva": "0x1000", "iatVa": "0x140001000"}])

        name_item = tab._modinfo_table.item(0, 0)
        assert name_item is not None
        assert name_item.toolTip() == long_name, "import Name cell tooltip does not carry the full name"

    def test_l15_pe_directory_name_cell_carries_tooltip(self, qapp: QApplication) -> None:
        """A long PE-directory name gets a matching tooltip.

        Pre-fix, no tooltip was set on the Name cell in the PE-directories
        view either.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        long_name = "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT_DESCRIPTOR_TABLE"
        tab._apply_pe_directories([{"index": 13, "name": long_name, "rva": "0x2000", "size": "0x100"}])

        name_item = tab._modinfo_table.item(0, 1)
        assert name_item is not None
        assert name_item.toolTip() == long_name, "PE-directory Name cell tooltip does not carry the full name"


class TestL16StatusLabelWordWrap:
    """L16: status labels word wrap unbounded error text instead of clipping."""

    @staticmethod
    def _assert_wraps_within_width(label_text_owner: object, label_attr: str, width: int) -> None:
        """Assert a status label wraps its current text within ``width`` pixels.

        Constrains the label to a narrow width and checks that the
        word-wrapped height for that width spans multiple text lines; a
        label without word wrap reports a fixed single-line height
        regardless of width, which is the pre-fix failure mode.

        Args:
            label_text_owner: The widget instance holding the label attribute.
            label_attr: Name of the ``QLabel`` attribute to check.
            width: Width, in pixels, to constrain the label to.
        """
        label = getattr(label_text_owner, label_attr)
        assert label.wordWrap() is True, f"{label_attr} must have word wrap enabled"
        label.resize(width, 20)
        line_height = label.fontMetrics().height()
        wrapped_height = label.heightForWidth(width)
        assert wrapped_height > line_height * 2, (
            f"{label_attr} did not wrap its long text across multiple lines at width={width} "
            f"(heightForWidth={wrapped_height}, single line={line_height})"
        )

    def test_l16_bpcfg_status_label_wraps_long_error_text(self, qapp: QApplication) -> None:
        """A long breakpoint-config error message wraps instead of clipping.

        Pre-fix ``_bpcfg_status_label`` had no ``setWordWrap(True)``, so
        ``heightForWidth`` at a narrow width would report the same
        single-line height as the unconstrained ``sizeHint``.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        long_error = "connection reset while writing to the x64dbg named-pipe transport " * 6
        btn = tab._bpcfg_apply_btn
        assert isinstance(btn, QPushButton)

        tab._on_bpcfg_error("configure_breakpoint", RuntimeError(long_error), btn)

        assert long_error in tab._bpcfg_status_label.text()
        self._assert_wraps_within_width(tab, "_bpcfg_status_label", width=140)

    def test_l16_script_status_label_wraps_long_error_text(self, qapp: QApplication) -> None:
        """A long script-engine error message wraps instead of clipping.

        Pre-fix ``_script_status_label`` had no ``setWordWrap(True)`` either.

        Args:
            qapp: The shared QApplication fixture.
        """
        tab = _make_tab(qapp)
        long_error = "x64dbg script engine RPC timed out waiting for a response from the plugin " * 6
        btn = tab._script_run_btn
        assert isinstance(btn, QPushButton)

        tab._on_script_error("run", RuntimeError(long_error), btn)

        assert long_error in tab._script_status_label.text()
        self._assert_wraps_within_width(tab, "_script_status_label", width=140)
