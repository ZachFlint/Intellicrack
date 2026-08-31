# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``analysis_panel``.

Each test targets one audit finding for
:class:`intellicrack.ui.panels.analysis_panel.BridgeAnalysisPanel` and fails
against the pre-fix behaviour:

* ``test_h33_*`` (H33): the variable-length data column in every table
  (Value/Function/Name) must use ``QHeaderView.ResizeMode.Stretch`` instead
  of relying on ``setStretchLastSection`` granting space to an unrelated
  trailing column, and every populated cell must carry a tooltip with its
  full, unclipped text.
* ``test_m34_*`` (M34): the address-column accent colour must be re-resolved
  from :class:`ThemeManager` and reapplied to every already-rendered address
  cell when the application theme changes live, instead of staying pinned to
  the colour captured at construction time.
* ``test_m41_*`` (M41): the header's format/sources summary labels must wrap
  instead of being clipped by the panel width, and must carry a tooltip with
  their full text.

All tests drive a real :class:`BridgeAnalysisPanel` under an offscreen
``QApplication`` (no mocks).
"""

from __future__ import annotations

from PyQt6.QtWidgets import QApplication, QHeaderView

from intellicrack.core.types import (
    BridgeAnalysisSummary,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
)
from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel
from intellicrack.ui.resources.theme_manager import THEME_DARK, THEME_LIGHT, ThemeManager


_LONG_STRING_VALUE: str = "C:\\Program Files\\Vendor\\App\\license_validation_error_message_for_expired_trial.dll"
_LONG_DLL_NAME: str = "COMPONENT_LICENSE_VALIDATION_RUNTIME_EXTENDED.DLL"
_LONG_FUNCTION_NAME: str = "?ValidateLicenseSignatureAndExpiryWindow@@YAHPEBD0@Z"


def _make_analysis() -> BridgeAnalysisSummary:
    """Build a real, non-trivial analysis summary for panel population.

    Returns:
        BridgeAnalysisSummary: A summary with long-valued strings, imports,
        and function names, plus a five-bridge source list and a long
        format description, matching the audit's failure scenarios.
    """
    return BridgeAnalysisSummary(
        binary_name="license_check.exe",
        strings=[
            StringInfo(
                address=0x401000,
                value=_LONG_STRING_VALUE,
                encoding="ascii",
                section=".rdata",
            ),
        ],
        imports=[
            ImportInfo(
                dll=_LONG_DLL_NAME,
                function=_LONG_FUNCTION_NAME,
                ordinal=None,
                address=0x402000,
            ),
        ],
        exports=[
            ExportInfo(name="ExportedValidate", ordinal=1, address=0x403000),
        ],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x2000,
                raw_size=0x1800,
                characteristics=0x60000020,
                entropy=6.5,
            ),
        ],
        functions=[
            FunctionInfo(
                name=_LONG_FUNCTION_NAME,
                address=0x404000,
                size=256,
                calling_convention="stdcall",
                return_type="int",
                parameters=[],
                local_variables=[],
            ),
        ],
        format_info="Portable Executable (PE32+) for x86-64, dynamically linked, stripped",
        architecture="x86_64",
        source_bridges=["ghidra", "cutter", "frida", "x64dbg", "sandbox"],
        analysis_notes=["Detected anti-debug check at 0x404050"],
        complete=True,
    )


def _restore_theme() -> None:
    """Restore the shared theme manager to the default dark theme."""
    ThemeManager.get_instance().apply_theme(THEME_DARK)


def test_h33_variable_length_columns_use_stretch_resize_mode(qapp: QApplication) -> None:
    """The variable-length data column in each table stretches, not just the last one.

    Pre-fix, only ``setStretchLastSection(True)`` was used with
    ``QHeaderView.ResizeMode.Interactive`` everywhere, so the Value/Function
    column never had ``Stretch`` mode -- this assertion fails against that
    code because ``sectionResizeMode(1)`` on the strings table would report
    ``Interactive``, not ``Stretch``.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        strings_header = panel._strings_table.horizontalHeader()
        assert strings_header is not None
        assert strings_header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, (
            "Value column (strings table) does not stretch to fill available space"
        )
        assert strings_header.sectionResizeMode(0) == QHeaderView.ResizeMode.ResizeToContents

        imports_header = panel._imports_table.horizontalHeader()
        assert imports_header is not None
        assert imports_header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "DLL column (imports table) does not stretch"
        assert imports_header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Function column (imports table) does not stretch"

        functions_header = panel._functions_table.horizontalHeader()
        assert functions_header is not None
        assert functions_header.sectionResizeMode(1) == QHeaderView.ResizeMode.Stretch, "Name column (functions table) does not stretch"

        exports_header = panel._exports_table.horizontalHeader()
        assert exports_header is not None
        assert exports_header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "Name column (exports table) does not stretch"

        assert strings_header.stretchLastSection() is False, (
            "legacy stretch-last-section is still granting extra space only to the trailing Section column instead of the Value column"
        )
    finally:
        panel.deleteLater()


def test_h33_stretch_column_absorbs_widened_table_space(qapp: QApplication) -> None:
    """The stretch column actually claims the extra space once the table is widened.

    Pre-fix the Value column used ``Interactive`` resize mode, so widening
    the table would leave it at its default ~100px width while the (empty,
    unaffected) last column absorbed the space; this measures real geometry,
    not just the declared resize-mode enum.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        panel.resize(900, 400)
        panel.show()
        QApplication.processEvents()
        table = panel._strings_table
        table.resize(880, 300)
        QApplication.processEvents()

        address_width = table.columnWidth(0)
        value_width = table.columnWidth(1)
        assert value_width > address_width * 3, (
            "Value column did not absorb the widened table's extra space via "
            f"Stretch resize mode (address={address_width}, value={value_width})"
        )
    finally:
        panel.deleteLater()


def test_h33_populated_cells_expose_full_text_via_tooltip(qapp: QApplication) -> None:
    """Every populated data cell carries a tooltip with its full, unclipped text.

    Pre-fix, cells were built with bare ``QTableWidgetItem(text)`` and no
    ``setToolTip`` call anywhere in the file, so ``item.toolTip()`` would be
    the empty string for a genuinely long value -- this assertion fails
    against that code.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        analysis = _make_analysis()
        panel.set_analysis(analysis)

        value_item = panel._strings_table.item(0, 1)
        assert value_item is not None
        assert value_item.toolTip() == _LONG_STRING_VALUE, "long string value has no tooltip to recover text clipped by column width"

        dll_item = panel._imports_table.item(0, 0)
        assert dll_item is not None
        assert dll_item.toolTip() == _LONG_DLL_NAME

        function_item = panel._imports_table.item(0, 1)
        assert function_item is not None
        assert function_item.toolTip() == _LONG_FUNCTION_NAME

        name_item = panel._functions_table.item(0, 1)
        assert name_item is not None
        assert name_item.toolTip() == _LONG_FUNCTION_NAME

        address_item = panel._strings_table.item(0, 0)
        assert address_item is not None
        assert address_item.toolTip() == "0x00401000", "address cell tooltip missing"
    finally:
        panel.deleteLater()


def test_m34_theme_switch_reapplies_address_color_to_existing_cells(qapp: QApplication) -> None:
    """A live theme switch re-resolves and reapplies the address-column colour.

    Proves the panel subscribes to ``ThemeManager.theme_changed``: pre-fix
    ``self._addr_color`` was resolved exactly once in ``__init__`` and never
    updated, so already-rendered address cells would keep the dark-theme
    accent colour after switching to light -- this assertion fails against
    that code because the before/after colours would compare equal.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        panel = BridgeAnalysisPanel()
        try:
            analysis = _make_analysis()
            panel.set_analysis(analysis)

            dark_accent = ThemeManager.get_instance().get_analysis_colors()["accent"]
            item = panel._strings_table.item(0, 0)
            assert item is not None
            assert item.foreground().color().getRgb() == dark_accent.getRgb(), (
                "address cell was not rendered with the dark-theme accent colour"
            )

            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            light_accent = ThemeManager.get_instance().get_analysis_colors()["accent"]
            assert light_accent.getRgb() != dark_accent.getRgb(), "test premise: light and dark accent colours must differ"

            reapplied_item = panel._strings_table.item(0, 0)
            assert reapplied_item is not None
            assert reapplied_item.foreground().color().getRgb() == light_accent.getRgb(), (
                "address cell colour was not re-resolved on theme_changed and is still stale"
            )

            functions_item = panel._functions_table.item(0, 0)
            assert functions_item is not None
            assert functions_item.foreground().color().getRgb() == light_accent.getRgb(), (
                "functions table address cell was not updated by the theme_changed handler"
            )
        finally:
            panel.deleteLater()
    finally:
        _restore_theme()


def test_m34_newly_populated_cells_use_live_theme_after_switch(qapp: QApplication) -> None:
    """Rows populated after a theme switch use the newly resolved colour.

    Pre-fix, ``self._addr_color`` was a stale instance attribute set once in
    ``__init__``; even a fresh ``set_analysis`` call after switching themes
    would keep painting with the original colour, since nothing ever
    re-queried :class:`ThemeManager`.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    try:
        ThemeManager.get_instance().apply_theme(THEME_DARK)
        panel = BridgeAnalysisPanel()
        try:
            ThemeManager.get_instance().apply_theme(THEME_LIGHT)
            light_accent = ThemeManager.get_instance().get_analysis_colors()["accent"]

            panel.set_analysis(_make_analysis())
            item = panel._exports_table.item(0, 2)
            assert item is not None
            assert item.foreground().color().getRgb() == light_accent.getRgb(), "post-switch population used a stale cached accent colour"
        finally:
            panel.deleteLater()
    finally:
        _restore_theme()


def test_m41_header_summary_labels_have_word_wrap_enabled(qapp: QApplication) -> None:
    """The format and sources labels have word wrap enabled.

    Pre-fix, neither ``QLabel`` had ``setWordWrap(True)`` called, so
    ``wordWrap()`` defaults to ``False`` -- this assertion fails against that
    code.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        assert panel._format_label.wordWrap() is True
        assert panel._bridges_label.wordWrap() is True
    finally:
        panel.deleteLater()


def test_m41_bridges_label_wraps_onto_more_lines_when_narrowed(qapp: QApplication) -> None:
    """The sources label grows taller when narrowed, proving it wraps instead of clipping.

    Pre-fix, ``wordWrap`` was disabled, so ``sizePolicy().hasHeightForWidth()``
    is ``False`` and ``heightForWidth`` returns ``-1`` regardless of width --
    the narrow/wide comparison collapses to ``-1 == -1`` and this assertion
    fails against that code.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        analysis = _make_analysis()
        panel.set_analysis(analysis)
        label = panel._bridges_label

        assert label.sizePolicy().hasHeightForWidth() is True, "label does not participate in height-for-width layout; wrap is not active"

        wide_height = label.heightForWidth(600)
        narrow_height = label.heightForWidth(80)
        assert narrow_height > wide_height, (
            f"label does not grow taller (wrap onto more lines) when narrowed; wide={wide_height}, narrow={narrow_height}"
        )
    finally:
        panel.deleteLater()


def test_m41_header_summary_labels_carry_full_text_tooltip(qapp: QApplication) -> None:
    """The format and sources labels carry a tooltip with their full text.

    Pre-fix, no ``setToolTip`` call existed anywhere in the file, so
    ``toolTip()`` on either label would be the empty string, not the full
    (non-empty) summary text -- this assertion fails against that code.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        analysis = _make_analysis()
        panel.set_analysis(analysis)

        expected_format = f"Format: {analysis.format_info}"
        expected_bridges = f"Sources: {', '.join(analysis.source_bridges)}"

        assert panel._format_label.toolTip() == expected_format
        assert panel._bridges_label.toolTip() == expected_bridges
    finally:
        panel.deleteLater()
