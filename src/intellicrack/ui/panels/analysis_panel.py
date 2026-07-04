# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge analysis panel for displaying aggregated analysis results.

Provides a tabbed UI for displaying real bridge data: strings, imports, exports, functions, sections, and analysis notes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QGridLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from intellicrack.core.types import BridgeAnalysisSummary

_logger = get_logger(__name__)

_PANEL_MARGIN: Final[int] = 0
_PANEL_SPACING: Final[int] = 2
_HEADER_MARGIN_H: Final[int] = 8
_HEADER_MARGIN_V: Final[int] = 4
_HEADER_SPACING: Final[int] = 4


class BridgeAnalysisPanel(QWidget):
    """Panel for displaying aggregated bridge analysis results.

    Shows data from connected bridges in tabbed tables: strings, imports,
    exports, functions, sections, and notes.

    Attributes:
        address_navigate: Signal emitted with an address when a cell with
            an address value is double-clicked.
    """

    address_navigate = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the AnalysisPanel widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._current_analysis: BridgeAnalysisSummary | None = None
        self._mono_font = FontManager.get_instance().get_code_font(9)
        self._addr_color = ThemeManager.get_instance().get_analysis_colors()["accent"]
        self._setup_ui()
        ThemeManager.get_instance().theme_changed.connect(self._on_theme_changed)

    def _setup_ui(self) -> None:
        """Build the panel layout with header and tabbed tables."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(
            _PANEL_MARGIN,
            _PANEL_MARGIN,
            _PANEL_MARGIN,
            _PANEL_MARGIN,
        )
        layout.setSpacing(_PANEL_SPACING)

        header = QWidget()
        header_layout = QGridLayout(header)
        header_layout.setContentsMargins(
            _HEADER_MARGIN_H,
            _HEADER_MARGIN_V,
            _HEADER_MARGIN_H,
            _HEADER_MARGIN_V,
        )
        header_layout.setSpacing(_HEADER_SPACING)

        self._binary_label = QLabel("No binary loaded")
        self._binary_label.setProperty("heading", "true")
        self._binary_label.setWordWrap(True)
        header_layout.addWidget(self._binary_label, 0, 0, 1, 2)

        self._format_label = QLabel("")
        self._format_label.setProperty("muted", "true")
        self._format_label.setWordWrap(True)
        header_layout.addWidget(self._format_label, 1, 0)

        self._arch_label = QLabel("")
        self._arch_label.setProperty("muted", "true")
        self._arch_label.setWordWrap(True)
        header_layout.addWidget(self._arch_label, 1, 1)

        self._bridges_label = QLabel("")
        self._bridges_label.setWordWrap(True)
        header_layout.addWidget(self._bridges_label, 2, 0, 1, 2)

        layout.addWidget(header)

        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("analysis_tabs")

        self._strings_table = self._create_table(["Address", "Value", "Encoding", "Section"], [1])
        self._imports_table = self._create_table(["DLL", "Function", "Ordinal", "Address"], [0, 1])
        self._exports_table = self._create_table(["Name", "Ordinal", "Address"], [0])
        self._functions_table = self._create_table(
            ["Address", "Name", "Size", "Convention", "Return Type"],
            [1],
        )
        self._sections_table = self._create_table(
            ["Name", "VA", "VSize", "RawSize", "Characteristics", "Entropy"],
            [0],
        )
        self._notes_edit = QTextEdit()
        self._notes_edit.setReadOnly(True)
        self._notes_edit.setPlaceholderText("No notes available")
        self._notes_edit.setFont(self._mono_font)
        self._notes_edit.setObjectName("code_preview_text")

        self.tab_widget.addTab(self._strings_table, "Strings")
        self.tab_widget.addTab(self._imports_table, "Imports")
        self.tab_widget.addTab(self._exports_table, "Exports")
        self.tab_widget.addTab(self._functions_table, "Functions")
        self.tab_widget.addTab(self._sections_table, "Sections")
        self.tab_widget.addTab(self._notes_edit, "Notes")

        layout.addWidget(self.tab_widget)

        self._strings_table.cellDoubleClicked.connect(self._on_strings_cell_clicked)
        self._imports_table.cellDoubleClicked.connect(self._on_imports_cell_clicked)
        self._exports_table.cellDoubleClicked.connect(self._on_exports_cell_clicked)
        self._functions_table.cellDoubleClicked.connect(self._on_functions_cell_clicked)
        self._sections_table.cellDoubleClicked.connect(self._on_sections_cell_clicked)

    def _on_theme_changed(self, resolved_theme: str) -> None:
        """Re-resolve and reapply the address-column accent color.

        Connected to :attr:`ThemeManager.theme_changed` so already-rendered
        address cells in every table track live theme switches instead of
        keeping the color captured at construction time.

        Args:
            resolved_theme: The concrete theme now active ("dark" or "light").
        """
        _ = resolved_theme
        self._addr_color = ThemeManager.get_instance().get_analysis_colors()["accent"]
        address_columns = (
            (self._strings_table, 0),
            (self._imports_table, 3),
            (self._exports_table, 2),
            (self._functions_table, 0),
            (self._sections_table, 1),
        )
        for table, col in address_columns:
            for row in range(table.rowCount()):
                item = table.item(row, col)
                if item is not None:
                    item.setForeground(self._addr_color)

    def _create_table(self, headers: list[str], stretch_columns: list[int]) -> QTableWidget:
        """Create a styled table widget with given column headers.

        Args:
            headers: Column header labels.
            stretch_columns: Indices of columns holding variable-length data
                that should stretch to fill available space. All other
                columns are sized to fit their contents.

        Returns:
            QTableWidget: Configured QTableWidget.
        """
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        v_header = table.verticalHeader()
        if v_header is not None:
            v_header.setVisible(False)
        table.setFont(self._mono_font)

        h_header = table.horizontalHeader()
        if h_header is not None:
            h_header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            for col in stretch_columns:
                h_header.setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)

        return table

    @staticmethod
    def _make_item(text: str) -> QTableWidgetItem:
        """Create a table item whose tooltip shows its full, unclipped text.

        Args:
            text: Cell text to display.

        Returns:
            QTableWidgetItem: Item with its tooltip set to the same text, so
            values truncated by column width remain readable on hover.
        """
        item = QTableWidgetItem(text)
        item.setToolTip(text)
        return item

    def _on_strings_cell_clicked(self, row: int, _col: int) -> None:
        """Handle double-click on a strings table cell.

        Args:
            row: Row index.
            _col: Column index (unused).
        """
        self._on_address_cell(self._strings_table, row, 0)

    def _on_imports_cell_clicked(self, row: int, _col: int) -> None:
        """Handle double-click on an imports table cell.

        Args:
            row: Row index.
            _col: Column index (unused).
        """
        self._on_address_cell(self._imports_table, row, 3)

    def _on_exports_cell_clicked(self, row: int, _col: int) -> None:
        """Handle double-click on an exports table cell.

        Args:
            row: Row index.
            _col: Column index (unused).
        """
        self._on_address_cell(self._exports_table, row, 2)

    def _on_functions_cell_clicked(self, row: int, _col: int) -> None:
        """Handle double-click on a functions table cell.

        Args:
            row: Row index.
            _col: Column index (unused).
        """
        self._on_address_cell(self._functions_table, row, 0)

    def _on_sections_cell_clicked(self, row: int, _col: int) -> None:
        """Handle double-click on a sections table cell.

        Args:
            row: Row index.
            _col: Column index (unused).
        """
        self._on_address_cell(self._sections_table, row, 1)

    def _on_address_cell(self, table: QTableWidget, row: int, col: int) -> None:
        """Handle double-click on an address cell.

        Args:
            table: The table widget containing the cell.
            row: Row index.
            col: Column index containing the address.
        """
        item = table.item(row, col)
        if item is None:
            return
        text = item.text()
        if text.startswith("0x"):
            try:
                self.address_navigate.emit(int(text, 16))
            except ValueError:
                _logger.warning("invalid_hex_address", address_text=text)
                QMessageBox.warning(
                    self,
                    "Invalid Address",
                    f"Could not parse '{text}' as a hex address.",
                )

    def set_analysis(self, analysis: BridgeAnalysisSummary) -> None:
        """Populate the panel with bridge analysis data.

        Args:
            analysis: The aggregated analysis summary to display.
        """
        self._current_analysis = analysis

        self._binary_label.setText(analysis.binary_name)
        self._binary_label.setToolTip(analysis.binary_name)
        format_text = f"Format: {analysis.format_info}"
        self._format_label.setText(format_text)
        self._format_label.setToolTip(format_text)
        arch_text = f"Arch: {analysis.architecture}"
        self._arch_label.setText(arch_text)
        self._arch_label.setToolTip(arch_text)
        bridges_text = f"Sources: {', '.join(analysis.source_bridges)}"
        self._bridges_label.setText(bridges_text)
        self._bridges_label.setToolTip(bridges_text)

        self._populate_strings(analysis)
        self._populate_imports(analysis)
        self._populate_exports(analysis)
        self._populate_functions(analysis)
        self._populate_sections(analysis)

        self._notes_edit.clear()
        self._notes_edit.setPlainText("\n".join(analysis.analysis_notes))

        _logger.info(
            "analysis_panel_updated",
            binary=analysis.binary_name,
            strings=len(analysis.strings),
            imports=len(analysis.imports),
            exports=len(analysis.exports),
            functions=len(analysis.functions),
        )

    def _populate_strings(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the strings table.

        Args:
            analysis: The analysis summary containing string data.
        """
        self._strings_table.setRowCount(len(analysis.strings))
        for i, s in enumerate(analysis.strings):
            self._set_addr_item(self._strings_table, i, 0, s.address)
            self._strings_table.setItem(i, 1, self._make_item(s.value))
            self._strings_table.setItem(i, 2, self._make_item(s.encoding))
            self._strings_table.setItem(i, 3, self._make_item(s.section))

    def _populate_imports(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the imports table.

        Args:
            analysis: The analysis summary containing import data.
        """
        self._imports_table.setRowCount(len(analysis.imports))
        for i, imp in enumerate(analysis.imports):
            self._imports_table.setItem(i, 0, self._make_item(imp.dll))
            self._imports_table.setItem(i, 1, self._make_item(imp.function))
            ordinal_text = str(imp.ordinal) if imp.ordinal is not None else ""
            self._imports_table.setItem(i, 2, self._make_item(ordinal_text))
            self._set_addr_item(self._imports_table, i, 3, imp.address)

    def _populate_exports(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the exports table.

        Args:
            analysis: The analysis summary containing export data.
        """
        self._exports_table.setRowCount(len(analysis.exports))
        for i, exp in enumerate(analysis.exports):
            self._exports_table.setItem(i, 0, self._make_item(exp.name))
            self._exports_table.setItem(i, 1, self._make_item(str(exp.ordinal)))
            self._set_addr_item(self._exports_table, i, 2, exp.address)

    def _populate_functions(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the functions table.

        Args:
            analysis: The analysis summary containing function data.
        """
        self._functions_table.setRowCount(len(analysis.functions))
        for i, fn in enumerate(analysis.functions):
            self._set_addr_item(self._functions_table, i, 0, fn.address)
            self._functions_table.setItem(i, 1, self._make_item(fn.name))
            self._functions_table.setItem(i, 2, self._make_item(str(fn.size)))
            self._functions_table.setItem(i, 3, self._make_item(fn.calling_convention))
            self._functions_table.setItem(i, 4, self._make_item(fn.return_type))

    def _populate_sections(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the sections table.

        Args:
            analysis: The analysis summary containing section data.
        """
        self._sections_table.setRowCount(len(analysis.sections))
        for i, sec in enumerate(analysis.sections):
            self._sections_table.setItem(i, 0, self._make_item(sec.name))
            self._set_addr_item(self._sections_table, i, 1, sec.virtual_address)
            self._sections_table.setItem(i, 2, self._make_item(f"0x{sec.virtual_size:X}"))
            self._sections_table.setItem(i, 3, self._make_item(f"0x{sec.raw_size:X}"))
            self._sections_table.setItem(i, 4, self._make_item(f"0x{sec.characteristics:08X}"))
            self._sections_table.setItem(i, 5, self._make_item(f"{sec.entropy:.2f}"))

    def _set_addr_item(self, table: QTableWidget, row: int, col: int, address: int) -> None:
        """Set a table cell with a formatted hex address.

        Args:
            table: Target table widget.
            row: Row index.
            col: Column index.
            address: Address value to format.
        """
        addr_text = f"0x{address:08X}"
        item = QTableWidgetItem(addr_text)
        item.setToolTip(addr_text)
        item.setForeground(self._addr_color)
        item.setFont(self._mono_font)
        table.setItem(row, col, item)

    def get_current_analysis(self) -> BridgeAnalysisSummary | None:
        """Get the currently displayed analysis summary.

        Returns:
            BridgeAnalysisSummary | None: The current BridgeAnalysisSummary or None if not set.
        """
        _logger.debug(
            "analysis_panel_current_analysis_requested",
            has_analysis=self._current_analysis is not None,
        )
        return self._current_analysis

    def clear(self) -> None:
        """Clear all displayed data."""
        _logger.info("analysis_panel_cleared")
        self._current_analysis = None
        self._binary_label.setText("No binary loaded")
        self._binary_label.setToolTip("")
        self._format_label.setText("")
        self._format_label.setToolTip("")
        self._arch_label.setText("")
        self._arch_label.setToolTip("")
        self._bridges_label.setText("")
        self._bridges_label.setToolTip("")
        self._strings_table.setRowCount(0)
        self._imports_table.setRowCount(0)
        self._exports_table.setRowCount(0)
        self._functions_table.setRowCount(0)
        self._sections_table.setRowCount(0)
        self._notes_edit.clear()
