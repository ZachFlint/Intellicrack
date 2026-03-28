# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Theme management for Intellicrack UI.

Provides centralized theme and stylesheet management with support for
dark and light themes.
"""

from __future__ import annotations

from typing import ClassVar, Final

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

from ...core.logging import get_logger
from .resource_helper import get_assets_path, get_style_path


_logger = get_logger("ui.resources.themes")


THEME_DARK: Final[str] = "dark"
THEME_LIGHT: Final[str] = "light"
DEFAULT_THEME: Final[str] = THEME_DARK


DARK_THEME_FALLBACK: Final[str] = """
/* ========================================
   Intellicrack Dark Theme
   ======================================== */

/* Main Window */
QMainWindow {
    background-color: #1e1e1e;
    color: #d4d4d4;
}

QWidget {
    background-color: #1e1e1e;
    color: #d4d4d4;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 9pt;
}

/* Menu Bar */
QMenuBar {
    background-color: #2d2d30;
    color: #d4d4d4;
    border-bottom: 1px solid #3e3e42;
    padding: 2px;
}

QMenuBar::item {
    background-color: transparent;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #3e3e42;
}

QMenuBar::item:pressed {
    background-color: #094771;
}

/* Menus */
QMenu {
    background-color: #2d2d30;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px 6px 8px;
    border-radius: 2px;
}

QMenu::item:selected {
    background-color: #094771;
}

QMenu::separator {
    height: 1px;
    background-color: #3e3e42;
    margin: 4px 8px;
}

/* Toolbar */
QToolBar {
    background-color: #2d2d30;
    border: none;
    border-bottom: 1px solid #3e3e42;
    spacing: 4px;
    padding: 4px;
}

QToolBar::separator {
    width: 1px;
    background-color: #3e3e42;
    margin: 4px 8px;
}

/* Push Buttons */
QPushButton {
    background-color: #0e639c;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 24px;
}

QPushButton:hover {
    background-color: #1177bb;
}

QPushButton:pressed {
    background-color: #094771;
}

QPushButton:disabled {
    background-color: #3e3e42;
    color: #6e6e6e;
}

QPushButton[flat="true"] {
    background-color: transparent;
    border: 1px solid #3e3e42;
    color: #d4d4d4;
}

QPushButton[flat="true"]:hover {
    background-color: #3e3e42;
}

/* Secondary Button */
QPushButton[secondary="true"] {
    background-color: transparent;
    border: 1px solid #3e3e42;
    color: #d4d4d4;
}

QPushButton[secondary="true"]:hover {
    background-color: #3e3e42;
}

/* Danger Button */
QPushButton[danger="true"] {
    background-color: #5a1d1d;
    border: 1px solid #f44747;
    color: #f44747;
}

QPushButton[danger="true"]:hover {
    background-color: #6e2222;
}

/* Combo Box */
QComboBox {
    background-color: #3e3e42;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 24px;
}

QComboBox:hover {
    border-color: #007acc;
}

QComboBox:focus {
    border-color: #007acc;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    width: 12px;
    height: 12px;
}

QComboBox QAbstractItemView {
    background-color: #2d2d30;
    color: #d4d4d4;
    selection-background-color: #094771;
    border: 1px solid #3e3e42;
}

/* Line Edit */
QLineEdit {
    background-color: #3c3c3c;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #094771;
}

QLineEdit:focus {
    border-color: #007acc;
}

QLineEdit:disabled {
    background-color: #2d2d30;
    color: #6e6e6e;
}

/* Text Edit */
QTextEdit, QPlainTextEdit {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    selection-background-color: #094771;
    font-family: "JetBrains Mono", "Consolas", monospace;
}

QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #007acc;
}

/* Scroll Area */
QScrollArea {
    background-color: transparent;
    border: none;
}

QScrollArea > QWidget > QWidget {
    background-color: transparent;
}

/* Scroll Bar */
QScrollBar:vertical {
    background-color: #1e1e1e;
    width: 12px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #5a5a5a;
    min-height: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background-color: #6e6e6e;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #1e1e1e;
    height: 12px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #5a5a5a;
    min-width: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #6e6e6e;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #3e3e42;
    background-color: #1e1e1e;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #2d2d30;
    color: #d4d4d4;
    padding: 8px 16px;
    border: none;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:selected {
    background-color: #1e1e1e;
    border-bottom: 2px solid #007acc;
}

QTabBar::tab:hover:!selected {
    background-color: #3e3e42;
}

/* List Widget */
QListWidget, QListView {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    outline: none;
}

QListWidget::item, QListView::item {
    padding: 6px 8px;
    border-radius: 2px;
}

QListWidget::item:selected, QListView::item:selected {
    background-color: #094771;
}

QListWidget::item:hover:!selected, QListView::item:hover:!selected {
    background-color: #2a2d2e;
}

/* Tree Widget */
QTreeWidget, QTreeView {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    outline: none;
}

QTreeWidget::item, QTreeView::item {
    padding: 4px 8px;
}

QTreeWidget::item:selected, QTreeView::item:selected {
    background-color: #094771;
}

QTreeWidget::item:hover:!selected, QTreeView::item:hover:!selected {
    background-color: #2a2d2e;
}

/* Table Widget */
QTableWidget, QTableView {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    gridline-color: #3e3e42;
    outline: none;
}

QTableWidget::item, QTableView::item {
    padding: 4px;
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: #094771;
}

QHeaderView::section {
    background-color: #2d2d30;
    color: #d4d4d4;
    padding: 6px;
    border: none;
    border-right: 1px solid #3e3e42;
    border-bottom: 1px solid #3e3e42;
}

/* Group Box */
QGroupBox {
    background-color: #252526;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 8px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #d4d4d4;
}

/* Check Box */
QCheckBox {
    color: #d4d4d4;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #3e3e42;
    border-radius: 3px;
    background-color: #3c3c3c;
}

QCheckBox::indicator:checked {
    background-color: #007acc;
    border-color: #007acc;
}

QCheckBox::indicator:hover {
    border-color: #007acc;
}

/* Radio Button */
QRadioButton {
    color: #d4d4d4;
    spacing: 8px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #3e3e42;
    border-radius: 8px;
    background-color: #3c3c3c;
}

QRadioButton::indicator:checked {
    background-color: #007acc;
    border-color: #007acc;
}

QRadioButton::indicator:hover {
    border-color: #007acc;
}

/* Spin Box */
QSpinBox, QDoubleSpinBox {
    background-color: #3c3c3c;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 4px 8px;
}

QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #007acc;
}

/* Slider */
QSlider::groove:horizontal {
    background-color: #3e3e42;
    height: 4px;
    border-radius: 2px;
}

QSlider::handle:horizontal {
    background-color: #007acc;
    width: 16px;
    height: 16px;
    margin: -6px 0;
    border-radius: 8px;
}

QSlider::handle:horizontal:hover {
    background-color: #1177bb;
}

/* Progress Bar */
QProgressBar {
    background-color: #3e3e42;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #007acc;
    border-radius: 4px;
}

/* Status Bar */
QStatusBar {
    background-color: #007acc;
    color: #ffffff;
    border: none;
}

QStatusBar::item {
    border: none;
}

/* Splitter */
QSplitter::handle {
    background-color: #3e3e42;
}

QSplitter::handle:horizontal {
    width: 2px;
}

QSplitter::handle:vertical {
    height: 2px;
}

QSplitter::handle:hover {
    background-color: #007acc;
}

/* Tool Tip */
QToolTip {
    background-color: #2d2d30;
    color: #d4d4d4;
    border: 1px solid #3e3e42;
    padding: 4px 8px;
}

/* Dialog */
QDialog {
    background-color: #1e1e1e;
}

/* Frame */
QFrame[frameShape="4"], QFrame[frameShape="5"] {
    color: #3e3e42;
}

/* Label */
QLabel {
    color: #d4d4d4;
    background-color: transparent;
}

QLabel[heading="true"] {
    font-size: 12pt;
    font-weight: bold;
}

QLabel[subheading="true"] {
    font-size: 10pt;
    color: #888888;
}

QLabel[muted="true"] {
    color: #888888;
}

QLabel[success="true"] {
    color: #4CAF50;
}

QLabel[error="true"] {
    color: #F44336;
}

QLabel[warning="true"] {
    color: #FF9800;
}

QLabel[info="true"] {
    color: #2196F3;
}

/* Status Indicator */
QLabel[status="success"] {
    color: #4CAF50;
}

QLabel[status="error"] {
    color: #F44336;
}

QLabel[status="warning"] {
    color: #FF9800;
}

QLabel[status="info"] {
    color: #2196F3;
}

QLabel[status="idle"] {
    color: #888888;
}

/* Dock Widget */
QDockWidget {
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
    color: #d4d4d4;
}

QDockWidget::title {
    background-color: #2d2d30;
    border-bottom: 1px solid #3e3e42;
    padding: 6px;
    text-align: left;
}

/* Message Box */
QMessageBox {
    background-color: #1e1e1e;
}

/* Disabled States */
QComboBox:disabled {
    background-color: #2d2d30;
    color: #6e6e6e;
    border-color: #3e3e42;
}

QCheckBox:disabled { color: #6e6e6e; }
QRadioButton:disabled { color: #6e6e6e; }
QLabel:disabled { color: #6e6e6e; }

QSpinBox:disabled, QDoubleSpinBox:disabled {
    background-color: #2d2d30;
    color: #6e6e6e;
}

/* Focus States */
QTableWidget:focus, QTableView:focus { border-color: #007acc; }
QTreeWidget:focus, QTreeView:focus { border-color: #007acc; }
QListWidget:focus, QListView:focus { border-color: #007acc; }

/* ObjectName Selectors */
QLabel#search_status_label { color: #888888; font-size: 8pt; }
QLabel#muted_label { color: #888888; }
QLabel#bold_label { font-weight: bold; }
QLabel#hint_label { color: #888888; font-style: italic; font-size: 8pt; }

QTabWidget#analysis_tabs::pane { border: none; background: #1e1e1e; }
QTabWidget#analysis_tabs > QTabBar::tab { padding: 6px 12px; }

QTextEdit#code_preview_text {
    background-color: #1e1e1e;
    color: #d4d4d4;
    border: none;
}

QPushButton#execute_button {
    background-color: #0e639c;
    color: #ffffff;
    font-weight: bold;
    padding: 8px 20px;
}
"""


LIGHT_THEME_FALLBACK: Final[str] = """
/* ========================================
   Intellicrack Light Theme
   ======================================== */

/* Main Window */
QMainWindow {
    background-color: #f8f8f8;
    color: #1a1a1a;
}

QWidget {
    background-color: #f8f8f8;
    color: #1a1a1a;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 9pt;
}

/* Menu Bar */
QMenuBar {
    background-color: #ffffff;
    color: #1a1a1a;
    border-bottom: 1px solid #e0e0e0;
    padding: 2px;
}

QMenuBar::item {
    background-color: transparent;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #e8e8e8;
}

QMenuBar::item:pressed {
    background-color: #0078d4;
    color: #ffffff;
}

/* Menus */
QMenu {
    background-color: #ffffff;
    color: #1a1a1a;
    border: 1px solid #e0e0e0;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px 6px 8px;
    border-radius: 2px;
}

QMenu::item:selected {
    background-color: #0078d4;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #e0e0e0;
    margin: 4px 8px;
}

/* Toolbar */
QToolBar {
    background-color: #ffffff;
    border: none;
    border-bottom: 1px solid #e0e0e0;
    spacing: 4px;
    padding: 4px;
}

QToolBar::separator {
    width: 1px;
    background-color: #e0e0e0;
    margin: 4px 8px;
}

/* Push Buttons */
QPushButton {
    background-color: #0078d4;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 24px;
}

QPushButton:hover {
    background-color: #106ebe;
}

QPushButton:pressed {
    background-color: #005a9e;
}

QPushButton:disabled {
    background-color: #e0e0e0;
    color: #a0a0a0;
}

QPushButton[flat="true"] {
    background-color: transparent;
    border: 1px solid #e0e0e0;
    color: #1a1a1a;
}

QPushButton[flat="true"]:hover {
    background-color: #f0f0f0;
}

/* Secondary Button */
QPushButton[secondary="true"] {
    background-color: transparent;
    border: 1px solid #e0e0e0;
    color: #1a1a1a;
}

QPushButton[secondary="true"]:hover {
    background-color: #f0f0f0;
}

/* Danger Button */
QPushButton[danger="true"] {
    background-color: #ffebee;
    border: 1px solid #f44336;
    color: #d32f2f;
}

QPushButton[danger="true"]:hover {
    background-color: #ffcdd2;
}

/* Combo Box */
QComboBox {
    background-color: #ffffff;
    color: #1a1a1a;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 24px;
}

QComboBox:hover {
    border-color: #0078d4;
}

QComboBox:focus {
    border-color: #0078d4;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #1a1a1a;
    selection-background-color: #0078d4;
    selection-color: #ffffff;
    border: 1px solid #e0e0e0;
}

/* Line Edit */
QLineEdit {
    background-color: #ffffff;
    color: #1a1a1a;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #0078d4;
}

QLineEdit:focus {
    border-color: #0078d4;
}

QLineEdit:disabled {
    background-color: #f5f5f5;
    color: #a0a0a0;
}

/* Text Edit */
QTextEdit, QPlainTextEdit {
    background-color: #ffffff;
    color: #1a1a1a;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    selection-background-color: #0078d4;
    font-family: "JetBrains Mono", "Consolas", monospace;
}

QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #0078d4;
}

/* Scroll Bar */
QScrollBar:vertical {
    background-color: #f8f8f8;
    width: 12px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #c0c0c0;
    min-height: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background-color: #a0a0a0;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #f8f8f8;
    height: 12px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #c0c0c0;
    min-width: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #a0a0a0;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #e0e0e0;
    background-color: #ffffff;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #f0f0f0;
    color: #1a1a1a;
    padding: 8px 16px;
    border: none;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    border-bottom: 2px solid #0078d4;
}

QTabBar::tab:hover:!selected {
    background-color: #e8e8e8;
}

/* List Widget */
QListWidget, QListView {
    background-color: #ffffff;
    color: #1a1a1a;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    outline: none;
}

QListWidget::item, QListView::item {
    padding: 6px 8px;
    border-radius: 2px;
}

QListWidget::item:selected, QListView::item:selected {
    background-color: #0078d4;
    color: #ffffff;
}

QListWidget::item:hover:!selected, QListView::item:hover:!selected {
    background-color: #f0f0f0;
}

/* Group Box */
QGroupBox {
    background-color: #ffffff;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 8px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #1a1a1a;
}

/* Check Box */
QCheckBox {
    color: #1a1a1a;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #e0e0e0;
    border-radius: 3px;
    background-color: #ffffff;
}

QCheckBox::indicator:checked {
    background-color: #0078d4;
    border-color: #0078d4;
}

QCheckBox::indicator:hover {
    border-color: #0078d4;
}

/* Status Bar */
QStatusBar {
    background-color: #0078d4;
    color: #ffffff;
    border: none;
}

/* Progress Bar */
QProgressBar {
    background-color: #e0e0e0;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #0078d4;
    border-radius: 4px;
}

/* Splitter */
QSplitter::handle {
    background-color: #e0e0e0;
}

QSplitter::handle:hover {
    background-color: #0078d4;
}

/* Label */
QLabel {
    color: #1a1a1a;
    background-color: transparent;
}

QLabel[success="true"] {
    color: #2e7d32;
}

QLabel[error="true"] {
    color: #c62828;
}

QLabel[warning="true"] {
    color: #ef6c00;
}

QLabel[info="true"] {
    color: #1565c0;
}

QLabel[muted="true"] {
    color: #757575;
}

QLabel[status="success"] {
    color: #2e7d32;
}

QLabel[status="error"] {
    color: #c62828;
}

QLabel[status="warning"] {
    color: #ef6c00;
}

QLabel[status="info"] {
    color: #1565c0;
}

QLabel[status="idle"] {
    color: #757575;
}

/* Dock Widget */
QDockWidget {
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
    color: #1a1a1a;
}

QDockWidget::title {
    background-color: #f0f0f0;
    border-bottom: 1px solid #e0e0e0;
    padding: 6px;
    text-align: left;
}

/* Message Box */
QMessageBox {
    background-color: #f8f8f8;
}

/* Disabled States */
QComboBox:disabled {
    background-color: #f5f5f5;
    color: #a0a0a0;
    border-color: #e0e0e0;
}

QCheckBox:disabled { color: #a0a0a0; }
QRadioButton:disabled { color: #a0a0a0; }
QLabel:disabled { color: #a0a0a0; }

QSpinBox:disabled, QDoubleSpinBox:disabled {
    background-color: #f5f5f5;
    color: #a0a0a0;
}

/* Focus States */
QTableWidget:focus, QTableView:focus { border-color: #0078d4; }
QTreeWidget:focus, QTreeView:focus { border-color: #0078d4; }
QListWidget:focus, QListView:focus { border-color: #0078d4; }

/* ObjectName Selectors */
QLabel#search_status_label { color: #757575; font-size: 8pt; }
QLabel#muted_label { color: #757575; }
QLabel#bold_label { font-weight: bold; }
QLabel#hint_label { color: #757575; font-style: italic; font-size: 8pt; }

QTabWidget#analysis_tabs::pane { border: none; background: #ffffff; }
QTabWidget#analysis_tabs > QTabBar::tab { padding: 6px 12px; }

QTextEdit#code_preview_text {
    background-color: #ffffff;
    color: #1a1a1a;
    border: none;
}

QPushButton#execute_button {
    background-color: #0078d4;
    color: #ffffff;
    font-weight: bold;
    padding: 8px 20px;
}
"""


class ThemeManager:
    """Singleton theme manager for application styling.

    Manages theme loading, switching, and application-wide stylesheet
    management.
    """

    _instance: ClassVar[ThemeManager | None] = None

    def __init__(self) -> None:
        self._current_theme: str = DEFAULT_THEME
        self._theme_cache: dict[str, str] = {}
        self._styles_available: bool = self._check_styles_available()

    @classmethod
    def get_instance(cls) -> ThemeManager:
        """Get the singleton instance of ThemeManager.

        Returns:
            ThemeManager: The ThemeManager singleton instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        cls._instance = None

    @staticmethod
    def _check_styles_available() -> bool:
        """Check if the styles directory is available.

        Returns:
            bool: True if styles directory exists.
        """
        try:
            styles_dir = get_assets_path() / "styles"
            available = styles_dir.exists()
            _logger.debug("styles_availability_check", available=available, path=str(styles_dir))
        except FileNotFoundError as exc:
            _logger.exception("styles_availability_check_failed", error=str(exc))
            return False
        else:
            return available

    def apply_theme(self, theme: str = DEFAULT_THEME) -> bool:
        r"""Apply a theme to the application.

        Args:
            theme: Theme name ("dark" or "light").

        Returns:
            bool: True if theme was applied successfully.
        """
        if theme not in {THEME_DARK, THEME_LIGHT}:
            _logger.warning("unknown_theme", theme=theme, default=DEFAULT_THEME)
            theme = DEFAULT_THEME

        stylesheet = self.get_stylesheet(theme)
        app_instance = QApplication.instance()

        if isinstance(app_instance, QApplication):
            app_instance.setStyleSheet(stylesheet)
            self._current_theme = theme
            _logger.info("theme_applied", theme=theme)
            return True

        _logger.warning("no_qapplication_instance")
        return False

    def get_stylesheet(self, theme: str) -> str:
        """Get the stylesheet for a theme.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if theme in self._theme_cache:
            _logger.debug("theme_cache_hit", theme=theme)
            return self._theme_cache[theme]

        _logger.debug("theme_cache_miss", theme=theme)
        stylesheet = self._load_stylesheet(theme)
        self._theme_cache[theme] = stylesheet
        return stylesheet

    def _load_stylesheet(self, theme: str) -> str:
        """Load a stylesheet from file or use fallback.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if self._styles_available:
            filename = f"{theme}_theme.qss"
            try:
                style_path = get_style_path(filename)
                if style_path.exists():
                    with open(style_path, encoding="utf-8") as f:
                        content = f.read()
                        if content.strip():
                            _logger.debug("stylesheet_loaded", path=str(style_path))
                            return content
            except OSError as e:
                _logger.warning(
                    "stylesheet_load_failed",
                    style_file=filename,
                    error=str(e),
                )

        _logger.debug("using_fallback_stylesheet", theme=theme)
        return DARK_THEME_FALLBACK if theme == THEME_DARK else LIGHT_THEME_FALLBACK

    def toggle_theme(self) -> str:
        """Toggle between dark and light themes.

        Returns:
            str: The new theme name.
        """
        old_theme = self._current_theme
        new_theme = THEME_LIGHT if self._current_theme == THEME_DARK else THEME_DARK
        _logger.debug("theme_toggling", from_theme=old_theme, to_theme=new_theme)
        self.apply_theme(new_theme)
        return new_theme

    @property
    def current_theme(self) -> str:
        """Get the current theme name.

        Returns:
            str: Current theme name.
        """
        return self._current_theme

    def is_dark_theme(self) -> bool:
        """Check if current theme is dark.

        Returns:
            bool: True if dark theme is active.
        """
        return self._current_theme == THEME_DARK

    def get_analysis_colors(self) -> dict[str, QColor]:
        """Get theme-aware semantic colors for custom painting and analysis views.

        Returns:
            dict[str, QColor]: Mapping of semantic color names to QColor instances.
        """
        if self.is_dark_theme():
            return {
                "background": QColor(30, 30, 30),
                "foreground": QColor(212, 212, 212),
                "accent": QColor(0, 122, 204),
                "success": QColor(76, 175, 80),
                "error": QColor(244, 67, 54),
                "warning": QColor(255, 152, 0),
                "info": QColor(33, 150, 243),
                "muted": QColor(136, 136, 136),
                "border": QColor(62, 62, 66),
                "surface": QColor(45, 45, 48),
                "selection": QColor(9, 71, 113),
                "entropy_low": QColor(76, 175, 80),
                "entropy_mid": QColor(255, 152, 0),
                "entropy_high": QColor(244, 67, 54),
                "graph_edge": QColor(100, 100, 100),
                "graph_node_bg": QColor(45, 45, 48),
                "graph_node_border": QColor(62, 62, 66),
                "hex_zero": QColor(100, 100, 100),
                "hex_printable": QColor(156, 220, 254),
                "hex_nonprintable": QColor(244, 67, 54),
                "hex_modified": QColor(255, 152, 0),
                "offset_text": QColor(136, 136, 136),
                "separator": QColor(62, 62, 66),
                "minimap_bg": QColor(37, 37, 38),
                "minimap_indicator": QColor(0, 122, 204, 80),
                "mnemonic_jump": QColor(86, 156, 214),
                "mnemonic_call": QColor(220, 220, 170),
                "mnemonic_ret": QColor(206, 145, 120),
                "mnemonic_nop": QColor(100, 100, 100),
                "operand_register": QColor(78, 201, 176),
                "operand_immediate": QColor(181, 206, 168),
                "operand_memory": QColor(156, 220, 254),
            }
        return {
            "background": QColor(248, 248, 248),
            "foreground": QColor(26, 26, 26),
            "accent": QColor(0, 120, 212),
            "success": QColor(46, 125, 50),
            "error": QColor(198, 40, 40),
            "warning": QColor(239, 108, 0),
            "info": QColor(21, 101, 192),
            "muted": QColor(117, 117, 117),
            "border": QColor(224, 224, 224),
            "surface": QColor(255, 255, 255),
            "selection": QColor(0, 120, 212, 50),
            "entropy_low": QColor(46, 125, 50),
            "entropy_mid": QColor(239, 108, 0),
            "entropy_high": QColor(198, 40, 40),
            "graph_edge": QColor(160, 160, 160),
            "graph_node_bg": QColor(255, 255, 255),
            "graph_node_border": QColor(224, 224, 224),
            "hex_zero": QColor(160, 160, 160),
            "hex_printable": QColor(4, 81, 165),
            "hex_nonprintable": QColor(198, 40, 40),
            "hex_modified": QColor(239, 108, 0),
            "offset_text": QColor(117, 117, 117),
            "separator": QColor(224, 224, 224),
            "minimap_bg": QColor(245, 245, 245),
            "minimap_indicator": QColor(0, 120, 212, 80),
            "mnemonic_jump": QColor(0, 0, 255),
            "mnemonic_call": QColor(121, 94, 38),
            "mnemonic_ret": QColor(163, 21, 21),
            "mnemonic_nop": QColor(160, 160, 160),
            "operand_register": QColor(0, 128, 128),
            "operand_immediate": QColor(9, 134, 88),
            "operand_memory": QColor(4, 81, 165),
        }

    def clear_cache(self) -> None:
        """Clear the stylesheet cache."""
        cache_count = len(self._theme_cache)
        self._theme_cache.clear()
        _logger.debug("theme_cache_cleared", entries_cleared=cache_count)

    @staticmethod
    def get_available_themes() -> list[str]:
        """Get list of available theme names.

        Returns:
            list[str]: List of theme names.
        """
        return [THEME_DARK, THEME_LIGHT]
