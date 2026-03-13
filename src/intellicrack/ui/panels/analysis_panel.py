# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bridge analysis panel for displaying aggregated analysis results.

Provides a tabbed UI for displaying real bridge data: strings, imports,
exports, functions, sections, and analysis notes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QGridLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.font_manager import DEFAULT_CODE_FONT


if TYPE_CHECKING:
    from intellicrack.core.types import BridgeAnalysisSummary

_logger = get_logger("ui.panels.analysis")

_DARK_BG = "#1e1e1e"
_DARK_FG = "#d4d4d4"
_ALT_ROW = "#252526"
_HEADER_BG = "#333333"
_ADDR_FG = "#4ec9b0"

_TABLE_STYLE = f"""
    QTableWidget {{
        background-color: {_DARK_BG};
        color: {_DARK_FG};
        gridline-color: #3c3c3c;
        alternate-background-color: {_ALT_ROW};
        selection-background-color: #264f78;
        border: none;
    }}
    QTableWidget::item {{
        padding: 2px 4px;
    }}
    QHeaderView::section {{
        background-color: {_HEADER_BG};
        color: {_DARK_FG};
        padding: 4px;
        border: 1px solid #3c3c3c;
        font-weight: bold;
    }}
"""


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
        """Initialize the bridge analysis panel.

        Args:
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._current_analysis: BridgeAnalysisSummary | None = None
        self._mono_font = QFont(DEFAULT_CODE_FONT, 9)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Build the panel layout with header and tabbed tables."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        header = QWidget()
        header_layout = QGridLayout(header)
        header_layout.setContentsMargins(8, 4, 8, 4)
        header_layout.setSpacing(4)

        self._binary_label = QLabel("No binary loaded")
        self._binary_label.setStyleSheet(f"color: {_DARK_FG}; font-weight: bold; font-size: 12px;")
        header_layout.addWidget(self._binary_label, 0, 0, 1, 2)

        self._format_label = QLabel("")
        self._format_label.setStyleSheet(f"color: {_ADDR_FG};")
        header_layout.addWidget(self._format_label, 1, 0)

        self._arch_label = QLabel("")
        self._arch_label.setStyleSheet(f"color: {_ADDR_FG};")
        header_layout.addWidget(self._arch_label, 1, 1)

        self._bridges_label = QLabel("")
        self._bridges_label.setStyleSheet(f"color: {_DARK_FG};")
        header_layout.addWidget(self._bridges_label, 2, 0, 1, 2)

        layout.addWidget(header)

        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(f"""
            QTabWidget::pane {{ border: none; background: {_DARK_BG}; }}
            QTabBar::tab {{
                background: {_HEADER_BG}; color: {_DARK_FG};
                padding: 6px 12px; border: 1px solid #3c3c3c;
            }}
            QTabBar::tab:selected {{ background: {_DARK_BG}; }}
        """)

        self._strings_table = self._create_table(["Address", "Value", "Encoding", "Section"])
        self._imports_table = self._create_table(["DLL", "Function", "Ordinal", "Address"])
        self._exports_table = self._create_table(["Name", "Ordinal", "Address"])
        self._functions_table = self._create_table(["Address", "Name", "Size", "Convention", "Return Type"])
        self._sections_table = self._create_table(["Name", "VA", "VSize", "RawSize", "Characteristics", "Entropy"])
        self._notes_edit = QTextEdit()
        self._notes_edit.setReadOnly(True)
        self._notes_edit.setFont(self._mono_font)
        self._notes_edit.setStyleSheet(f"background-color: {_DARK_BG}; color: {_DARK_FG}; border: none;")

        self._tab_widget.addTab(self._strings_table, "Strings")
        self._tab_widget.addTab(self._imports_table, "Imports")
        self._tab_widget.addTab(self._exports_table, "Exports")
        self._tab_widget.addTab(self._functions_table, "Functions")
        self._tab_widget.addTab(self._sections_table, "Sections")
        self._tab_widget.addTab(self._notes_edit, "Notes")

        layout.addWidget(self._tab_widget)

        self._strings_table.cellDoubleClicked.connect(self._on_strings_cell_clicked)
        self._imports_table.cellDoubleClicked.connect(self._on_imports_cell_clicked)
        self._exports_table.cellDoubleClicked.connect(self._on_exports_cell_clicked)
        self._functions_table.cellDoubleClicked.connect(self._on_functions_cell_clicked)
        self._sections_table.cellDoubleClicked.connect(self._on_sections_cell_clicked)

    def _create_table(self, headers: list[str]) -> QTableWidget:
        """Create a styled table widget with given column headers.

        Args:
            headers: Column header labels.

        Returns:
            Configured QTableWidget.
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
        table.setStyleSheet(_TABLE_STYLE)

        h_header = table.horizontalHeader()
        if h_header is not None:
            h_header.setStretchLastSection(True)
            h_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        return table

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
                _logger.debug("invalid_hex_address", extra={"text": text})

    def set_analysis(self, analysis: BridgeAnalysisSummary) -> None:
        """Populate the panel with bridge analysis data.

        Args:
            analysis: The aggregated analysis summary to display.
        """
        self._current_analysis = analysis

        self._binary_label.setText(analysis.binary_name)
        self._format_label.setText(f"Format: {analysis.format_info}")
        self._arch_label.setText(f"Arch: {analysis.architecture}")
        self._bridges_label.setText(f"Sources: {', '.join(analysis.source_bridges)}")

        self._populate_strings(analysis)
        self._populate_imports(analysis)
        self._populate_exports(analysis)
        self._populate_functions(analysis)
        self._populate_sections(analysis)

        self._notes_edit.clear()
        if analysis.analysis_notes:
            self._notes_edit.setPlainText("\n".join(analysis.analysis_notes))
        else:
            self._notes_edit.setPlainText("No notes.")

        _logger.info(
            "analysis_panel_updated",
            extra={
                "binary": analysis.binary_name,
                "strings": len(analysis.strings),
                "imports": len(analysis.imports),
                "exports": len(analysis.exports),
                "functions": len(analysis.functions),
            },
        )

    def _populate_strings(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the strings table.

        Args:
            analysis: The analysis summary containing string data.
        """
        self._strings_table.setRowCount(len(analysis.strings))
        for i, s in enumerate(analysis.strings):
            self._set_addr_item(self._strings_table, i, 0, s.address)
            self._strings_table.setItem(i, 1, QTableWidgetItem(s.value))
            self._strings_table.setItem(i, 2, QTableWidgetItem(s.encoding))
            self._strings_table.setItem(i, 3, QTableWidgetItem(s.section))

    def _populate_imports(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the imports table.

        Args:
            analysis: The analysis summary containing import data.
        """
        self._imports_table.setRowCount(len(analysis.imports))
        for i, imp in enumerate(analysis.imports):
            self._imports_table.setItem(i, 0, QTableWidgetItem(imp.dll))
            self._imports_table.setItem(i, 1, QTableWidgetItem(imp.function))
            ordinal_text = str(imp.ordinal) if imp.ordinal is not None else ""
            self._imports_table.setItem(i, 2, QTableWidgetItem(ordinal_text))
            self._set_addr_item(self._imports_table, i, 3, imp.address)

    def _populate_exports(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the exports table.

        Args:
            analysis: The analysis summary containing export data.
        """
        self._exports_table.setRowCount(len(analysis.exports))
        for i, exp in enumerate(analysis.exports):
            self._exports_table.setItem(i, 0, QTableWidgetItem(exp.name))
            self._exports_table.setItem(i, 1, QTableWidgetItem(str(exp.ordinal)))
            self._set_addr_item(self._exports_table, i, 2, exp.address)

    def _populate_functions(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the functions table.

        Args:
            analysis: The analysis summary containing function data.
        """
        self._functions_table.setRowCount(len(analysis.functions))
        for i, fn in enumerate(analysis.functions):
            self._set_addr_item(self._functions_table, i, 0, fn.address)
            self._functions_table.setItem(i, 1, QTableWidgetItem(fn.name))
            self._functions_table.setItem(i, 2, QTableWidgetItem(str(fn.size)))
            self._functions_table.setItem(i, 3, QTableWidgetItem(fn.calling_convention))
            self._functions_table.setItem(i, 4, QTableWidgetItem(fn.return_type))

    def _populate_sections(self, analysis: BridgeAnalysisSummary) -> None:
        """Fill the sections table.

        Args:
            analysis: The analysis summary containing section data.
        """
        self._sections_table.setRowCount(len(analysis.sections))
        for i, sec in enumerate(analysis.sections):
            self._sections_table.setItem(i, 0, QTableWidgetItem(sec.name))
            self._set_addr_item(self._sections_table, i, 1, sec.virtual_address)
            self._sections_table.setItem(i, 2, QTableWidgetItem(f"0x{sec.virtual_size:X}"))
            self._sections_table.setItem(i, 3, QTableWidgetItem(f"0x{sec.raw_size:X}"))
            self._sections_table.setItem(i, 4, QTableWidgetItem(f"0x{sec.characteristics:08X}"))
            self._sections_table.setItem(i, 5, QTableWidgetItem(f"{sec.entropy:.2f}"))

    def _set_addr_item(self, table: QTableWidget, row: int, col: int, address: int) -> None:
        """Set a table cell with a formatted hex address.

        Args:
            table: Target table widget.
            row: Row index.
            col: Column index.
            address: Address value to format.
        """
        item = QTableWidgetItem(f"0x{address:08X}")
        item.setForeground(QColor(0, 255, 255))
        item.setFont(self._mono_font)
        table.setItem(row, col, item)

    def get_current_analysis(self) -> BridgeAnalysisSummary | None:
        """Get the currently displayed analysis summary.

        Returns:
            The current BridgeAnalysisSummary or None if not set.
        """
        return self._current_analysis

    def clear(self) -> None:
        """Clear all displayed data."""
        self._current_analysis = None
        self._binary_label.setText("No binary loaded")
        self._format_label.setText("")
        self._arch_label.setText("")
        self._bridges_label.setText("")
        self._strings_table.setRowCount(0)
        self._imports_table.setRowCount(0)
        self._exports_table.setRowCount(0)
        self._functions_table.setRowCount(0)
        self._sections_table.setRowCount(0)
        self._notes_edit.clear()
