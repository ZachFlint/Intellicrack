"""Licensing analysis panel for displaying protection analysis results.

Provides a comprehensive UI for displaying licensing protection analysis
including validation functions, crypto API calls, magic constants, and
analysis notes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from intellicrack.core.types import (
        CryptoAPICall,
        LicensingAnalysis,
        MagicConstant,
        ValidationFunctionInfo,
    )

_logger = get_logger("ui.panels.licensing")

_CONFIDENCE_HIGH_THRESHOLD = 75
_CONFIDENCE_MEDIUM_THRESHOLD = 50
_COMPLEXITY_HIGH_THRESHOLD = 10
_COMPLEXITY_MEDIUM_THRESHOLD = 5


class SummaryCard(QFrame):
    """Summary card displaying key licensing analysis metrics."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the summary card.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the summary card UI."""
        self.setObjectName("summary_card")
        self.setStyleSheet("""
            #summary_card {
                background-color: #2d2d30;
                border: 1px solid #3e3e42;
                border-radius: 8px;
                padding: 8px;
            }
        """)

        layout = QGridLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        value_font = QFont("JetBrains Mono", 11)

        self._algorithm_label = QLabel("Unknown")
        self._algorithm_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Algorithm", self._algorithm_label), 0, 0)

        self._format_label = QLabel("Unknown")
        self._format_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Key Format", self._format_label), 0, 1)

        self._length_label = QLabel("--")
        self._length_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Key Length", self._length_label), 0, 2)

        self._confidence_label = QLabel("0%")
        self._confidence_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Confidence", self._confidence_label), 0, 3)

        self._checksum_label = QLabel("None")
        self._checksum_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Checksum", self._checksum_label), 1, 0)

        self._hwid_label = QLabel("No")
        self._hwid_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Hardware ID", self._hwid_label), 1, 1)

        self._time_label = QLabel("No")
        self._time_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Time Check", self._time_label), 1, 2)

        self._online_label = QLabel("No")
        self._online_label.setFont(value_font)
        layout.addWidget(self._create_labeled_value("Online Check", self._online_label), 1, 3)

    @staticmethod
    def _create_labeled_value(label_text: str, value_widget: QLabel) -> QWidget:
        """Create a labeled value display.

        Args:
            label_text: Label text.
            value_widget: Widget to display the value.

        Returns:
            Container widget with label and value.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        label = QLabel(label_text)
        label.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(label)
        layout.addWidget(value_widget)

        return container

    def update_from_analysis(self, analysis: LicensingAnalysis) -> None:
        """Update the summary card from analysis results.

        Args:
            analysis: The licensing analysis results.
        """
        self._algorithm_label.setText(analysis.algorithm_type.value.upper())
        self._format_label.setText(analysis.key_format.value.replace("_", " ").title())
        self._length_label.setText(str(analysis.key_length) if analysis.key_length > 0 else "--")

        confidence_pct = int(analysis.confidence_score * 100)
        self._confidence_label.setText(f"{confidence_pct}%")

        if confidence_pct >= _CONFIDENCE_HIGH_THRESHOLD:
            self._confidence_label.setStyleSheet("color: #4ec9b0;")
        elif confidence_pct >= _CONFIDENCE_MEDIUM_THRESHOLD:
            self._confidence_label.setStyleSheet("color: #dcdcaa;")
        else:
            self._confidence_label.setStyleSheet("color: #f14c4c;")

        checksum_text = analysis.checksum_algorithm or "None"
        if analysis.checksum_position:
            checksum_text += f" ({analysis.checksum_position})"
        self._checksum_label.setText(checksum_text)

        hwid_count = len(analysis.hardware_id_apis)
        self._hwid_label.setText(f"Yes ({hwid_count})" if hwid_count > 0 else "No")
        if hwid_count > 0:
            self._hwid_label.setStyleSheet("color: #ce9178;")
        else:
            self._hwid_label.setStyleSheet("")

        self._time_label.setText("Yes" if analysis.time_check_present else "No")
        if analysis.time_check_present:
            self._time_label.setStyleSheet("color: #ce9178;")
        else:
            self._time_label.setStyleSheet("")

        self._online_label.setText("Yes" if analysis.online_validation else "No")
        if analysis.online_validation:
            self._online_label.setStyleSheet("color: #f14c4c;")
        else:
            self._online_label.setStyleSheet("")


class ValidationFunctionsTable(QTableWidget):
    """Table displaying validation function candidates."""

    address_clicked = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the validation functions table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the table UI."""
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(["Address", "Name", "Return", "Complexity", "Crypto", "Strings"])

        if header := self.horizontalHeader():
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)

        self.cellDoubleClicked.connect(self._on_cell_double_clicked)

    def _on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle cell double-click to emit address signal.

        Args:
            row: Row index.
            _column: Column index (unused).
        """
        if address_item := self.item(row, 0):
            try:
                address = int(address_item.text(), 16)
                self.address_clicked.emit(address)
            except ValueError:
                pass

    def set_functions(self, functions: list[ValidationFunctionInfo]) -> None:
        """Populate the table with validation functions.

        Args:
            functions: List of validation function info objects.
        """
        self.setRowCount(len(functions))

        for row, func in enumerate(functions):
            addr_item = QTableWidgetItem(f"0x{func.address:08X}")
            addr_item.setFont(QFont("JetBrains Mono", 9))
            addr_item.setForeground(QColor("#569cd6"))
            self.setItem(row, 0, addr_item)

            name_item = QTableWidgetItem(func.name)
            self.setItem(row, 1, name_item)

            ret_item = QTableWidgetItem(func.return_type)
            ret_item.setForeground(QColor("#4ec9b0"))
            self.setItem(row, 2, ret_item)

            complexity_item = QTableWidgetItem(str(func.complexity_score))
            if func.complexity_score >= _COMPLEXITY_HIGH_THRESHOLD:
                complexity_item.setForeground(QColor("#f14c4c"))
            elif func.complexity_score >= _COMPLEXITY_MEDIUM_THRESHOLD:
                complexity_item.setForeground(QColor("#dcdcaa"))
            else:
                complexity_item.setForeground(QColor("#4ec9b0"))
            self.setItem(row, 3, complexity_item)

            crypto_item = QTableWidgetItem("Yes" if func.calls_crypto_api else "No")
            if func.calls_crypto_api:
                crypto_item.setForeground(QColor("#ce9178"))
            self.setItem(row, 4, crypto_item)

            strings_item = QTableWidgetItem(str(len(func.string_references)))
            self.setItem(row, 5, strings_item)


class CryptoAPITable(QTableWidget):
    """Table displaying crypto API calls."""

    address_clicked = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the crypto API table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the table UI."""
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Address", "API", "DLL", "Caller", "Parameters"])

        if header := self.horizontalHeader():
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)

        self.cellDoubleClicked.connect(self._on_cell_double_clicked)

    def _on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle cell double-click.

        Args:
            row: Row index.
            _column: Column index (unused).
        """
        if address_item := self.item(row, 0):
            try:
                address = int(address_item.text(), 16)
                self.address_clicked.emit(address)
            except ValueError:
                pass

    def set_calls(self, calls: list[CryptoAPICall]) -> None:
        """Populate the table with crypto API calls.

        Args:
            calls: List of crypto API call info objects.
        """
        self.setRowCount(len(calls))

        for row, call in enumerate(calls):
            addr_item = QTableWidgetItem(f"0x{call.address:08X}")
            addr_item.setFont(QFont("JetBrains Mono", 9))
            addr_item.setForeground(QColor("#569cd6"))
            self.setItem(row, 0, addr_item)

            api_item = QTableWidgetItem(call.api_name)
            api_item.setForeground(QColor("#dcdcaa"))
            self.setItem(row, 1, api_item)

            dll_item = QTableWidgetItem(call.dll)
            dll_item.setForeground(QColor("#4ec9b0"))
            self.setItem(row, 2, dll_item)

            caller_item = QTableWidgetItem(call.caller_function or "Unknown")
            self.setItem(row, 3, caller_item)

            params_item = QTableWidgetItem(call.parameters_hint or "")
            params_item.setForeground(QColor("#888"))
            self.setItem(row, 4, params_item)


class ConstantsTable(QTableWidget):
    """Table displaying magic constants."""

    address_clicked = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the constants table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the table UI."""
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(["Address", "Value (Hex)", "Value (Dec)", "Context"])

        if header := self.horizontalHeader():
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)

        self.cellDoubleClicked.connect(self._on_cell_double_clicked)

    def _on_cell_double_clicked(self, row: int, _column: int) -> None:
        """Handle cell double-click.

        Args:
            row: Row index.
            _column: Column index (unused).
        """
        if address_item := self.item(row, 0):
            try:
                address = int(address_item.text(), 16)
                self.address_clicked.emit(address)
            except ValueError:
                pass

    def set_constants(self, constants: list[MagicConstant]) -> None:
        """Populate the table with magic constants.

        Args:
            constants: List of magic constant info objects.
        """
        self.setRowCount(len(constants))

        for row, const in enumerate(constants):
            addr_item = QTableWidgetItem(f"0x{const.address:08X}")
            addr_item.setFont(QFont("JetBrains Mono", 9))
            addr_item.setForeground(QColor("#569cd6"))
            self.setItem(row, 0, addr_item)

            hex_format = f"0x{{:0{const.bit_width // 4}X}}"
            hex_item = QTableWidgetItem(hex_format.format(const.value))
            hex_item.setFont(QFont("JetBrains Mono", 9))
            hex_item.setForeground(QColor("#b5cea8"))
            self.setItem(row, 1, hex_item)

            dec_item = QTableWidgetItem(str(const.value))
            dec_item.setFont(QFont("JetBrains Mono", 9))
            self.setItem(row, 2, dec_item)

            context_item = QTableWidgetItem(const.usage_context)
            context_item.setForeground(QColor("#ce9178"))
            self.setItem(row, 3, context_item)


class NotesPanel(QTextEdit):
    """Panel for displaying analysis notes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the notes panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the notes panel UI."""
        self.setReadOnly(True)
        self.setFont(QFont("Segoe UI", 10))
        self.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: none;
                padding: 8px;
            }
        """)

    def set_notes(self, notes: list[str]) -> None:
        """Set the analysis notes.

        Args:
            notes: List of note strings.
        """
        if not notes:
            self.setPlainText("No analysis notes available.")
            return

        formatted: list[str] = [f"{i}. {note}" for i, note in enumerate(notes, 1)]
        self.setPlainText("\n\n".join(formatted))


class ProtectionIndicators(QGroupBox):
    """Group box showing protection indicator flags."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize protection indicators.

        Args:
            parent: Parent widget.
        """
        super().__init__("Protection Indicators", parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the indicators UI."""
        layout = QGridLayout(self)
        layout.setSpacing(8)

        self._indicators: dict[str, QLabel] = {}

        indicator_names = [
            ("blacklist", "Blacklist Check"),
            ("hwid", "Hardware ID"),
            ("time", "Time Validation"),
            ("online", "Online Validation"),
            ("secondary_algo", "Secondary Algorithm"),
            ("feature_flags", "Feature Flags"),
        ]

        for i, (key, label_text) in enumerate(indicator_names):
            row = i // 3
            col = i % 3

            container = QWidget()
            container_layout = QHBoxLayout(container)
            container_layout.setContentsMargins(0, 0, 0, 0)
            container_layout.setSpacing(4)

            indicator = QLabel("●")
            indicator.setStyleSheet("color: #555;")
            self._indicators[key] = indicator

            label = QLabel(label_text)
            label.setStyleSheet("color: #aaa; font-size: 10px;")

            container_layout.addWidget(indicator)
            container_layout.addWidget(label)
            container_layout.addStretch()

            layout.addWidget(container, row, col)

    def update_from_analysis(self, analysis: LicensingAnalysis) -> None:
        """Update indicators from analysis.

        Args:
            analysis: The licensing analysis results.
        """
        self._set_indicator("blacklist", analysis.blacklist_present)
        self._set_indicator("hwid", len(analysis.hardware_id_apis) > 0)
        self._set_indicator("time", analysis.time_check_present)
        self._set_indicator("online", analysis.online_validation)
        self._set_indicator("secondary_algo", len(analysis.secondary_algorithms) > 0)
        self._set_indicator("feature_flags", len(analysis.feature_flags) > 0)

    def _set_indicator(self, key: str, active: bool) -> None:
        """Set an indicator's active state.

        Args:
            key: Indicator key.
            active: Whether the indicator should be active.
        """
        if indicator := self._indicators.get(key):
            if active:
                indicator.setStyleSheet("color: #f14c4c; font-weight: bold;")
            else:
                indicator.setStyleSheet("color: #555;")


class LicensingAnalysisPanel(QWidget):
    """Main panel for displaying licensing analysis results.

    Provides summary card, tabbed details view with validation functions,
    crypto APIs, constants, and notes, plus protection indicators.
    """

    address_navigate = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the licensing analysis panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._current_analysis: LicensingAnalysis | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self._summary_card = SummaryCard()
        layout.addWidget(self._summary_card)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("licensing_tabs")

        self._functions_table = ValidationFunctionsTable()
        self._functions_table.address_clicked.connect(self.address_navigate.emit)
        self._tab_widget.addTab(self._functions_table, "Validation Functions")

        self._crypto_table = CryptoAPITable()
        self._crypto_table.address_clicked.connect(self.address_navigate.emit)
        self._tab_widget.addTab(self._crypto_table, "Crypto APIs")

        self._constants_table = ConstantsTable()
        self._constants_table.address_clicked.connect(self.address_navigate.emit)
        self._tab_widget.addTab(self._constants_table, "Constants")

        self._notes_panel = NotesPanel()
        self._tab_widget.addTab(self._notes_panel, "Notes")

        splitter.addWidget(self._tab_widget)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self._indicators = ProtectionIndicators()
        right_layout.addWidget(self._indicators)

        self._secondary_algos_group = QGroupBox("Secondary Algorithms")
        secondary_layout = QVBoxLayout(self._secondary_algos_group)
        self._secondary_algos_label = QLabel("None detected")
        self._secondary_algos_label.setWordWrap(True)
        self._secondary_algos_label.setStyleSheet("color: #aaa; padding: 4px;")
        secondary_layout.addWidget(self._secondary_algos_label)
        right_layout.addWidget(self._secondary_algos_group)

        self._hwid_apis_group = QGroupBox("Hardware ID APIs")
        hwid_layout = QVBoxLayout(self._hwid_apis_group)
        self._hwid_apis_label = QLabel("None detected")
        self._hwid_apis_label.setWordWrap(True)
        self._hwid_apis_label.setStyleSheet("color: #aaa; padding: 4px;")
        hwid_layout.addWidget(self._hwid_apis_label)
        right_layout.addWidget(self._hwid_apis_group)

        right_layout.addStretch()

        right_panel.setMaximumWidth(250)
        splitter.addWidget(right_panel)

        splitter.setSizes([600, 250])
        layout.addWidget(splitter)

    def set_analysis(self, analysis: LicensingAnalysis) -> None:
        """Update the panel with new analysis results.

        Args:
            analysis: The licensing analysis results.
        """
        _logger.debug(
            "analysis_update_started",
            extra={
                "binary_name": analysis.binary_name,
                "validation_functions": len(analysis.validation_functions),
                "crypto_api_calls": len(analysis.crypto_api_calls),
                "magic_constants": len(analysis.magic_constants),
            },
        )
        self._current_analysis = analysis

        self._summary_card.update_from_analysis(analysis)

        self._functions_table.set_functions(analysis.validation_functions)

        self._crypto_table.set_calls(analysis.crypto_api_calls)

        self._constants_table.set_constants(analysis.magic_constants)

        self._notes_panel.set_notes(analysis.analysis_notes)

        self._indicators.update_from_analysis(analysis)

        if analysis.secondary_algorithms:
            algos = [a.value.upper() for a in analysis.secondary_algorithms]
            self._secondary_algos_label.setText(", ".join(algos))
            self._secondary_algos_label.setStyleSheet("color: #4ec9b0; padding: 4px;")
        else:
            self._secondary_algos_label.setText("None detected")
            self._secondary_algos_label.setStyleSheet("color: #aaa; padding: 4px;")

        if analysis.hardware_id_apis:
            self._hwid_apis_label.setText("\n".join(analysis.hardware_id_apis))
            self._hwid_apis_label.setStyleSheet("color: #ce9178; padding: 4px;")
        else:
            self._hwid_apis_label.setText("None detected")
            self._hwid_apis_label.setStyleSheet("color: #aaa; padding: 4px;")

        _logger.info(
            "analysis_panel_updated",
            extra={
                "binary_name": analysis.binary_name,
                "algorithm": analysis.algorithm_type.value,
                "confidence": analysis.confidence_score,
            },
        )

    def get_current_analysis(self) -> LicensingAnalysis | None:
        """Get the current analysis results.

        Returns:
            Current LicensingAnalysis or None if no analysis loaded.
        """
        return self._current_analysis

    def clear(self) -> None:
        """Clear all analysis data from the panel."""
        self._current_analysis = None
        self._functions_table.setRowCount(0)
        self._crypto_table.setRowCount(0)
        self._constants_table.setRowCount(0)
        self._notes_panel.clear()
        self._secondary_algos_label.setText("None detected")
        self._secondary_algos_label.setStyleSheet("color: #aaa; padding: 4px;")
        self._hwid_apis_label.setText("None detected")
        self._hwid_apis_label.setStyleSheet("color: #aaa; padding: 4px;")
        _logger.debug("analysis_panel_cleared")
