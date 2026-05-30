# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Theme management for Intellicrack UI.

Provides centralized theme and stylesheet management with support for dark,
light, and system themes. The system theme follows the operating system's
light/dark preference and tracks live OS changes.
"""

from __future__ import annotations

import sys
from typing import ClassVar, Final

from PyQt6.QtCore import QObject, Qt, pyqtBoundSignal, pyqtSignal
from PyQt6.QtGui import QColor, QGuiApplication
from PyQt6.QtWidgets import QApplication

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.resource_helper import get_assets_path, get_style_path


if sys.platform == "win32":
    import winreg


_logger = get_logger(__name__)


THEME_DARK: Final[str] = "dark"
THEME_LIGHT: Final[str] = "light"
THEME_SYSTEM: Final[str] = "system"
DEFAULT_THEME: Final[str] = THEME_DARK

_WINDOWS_PERSONALIZE_KEY: Final[str] = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
_WINDOWS_APPS_LIGHT_VALUE: Final[str] = "AppsUseLightTheme"


def _detect_windows_system_theme() -> str | None:
    """Detect the active Windows app color mode from the registry.

    Reads ``AppsUseLightTheme`` under the per-user *Personalize* key, which
    Windows updates whenever the user switches the system app color mode
    between light and dark.

    Returns:
        str | None: :data:`THEME_LIGHT` or :data:`THEME_DARK` when the value
        can be read, otherwise ``None`` (non-Windows platforms or when the
        value is absent or unreadable).
    """
    if sys.platform != "win32":
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINDOWS_PERSONALIZE_KEY) as key:
            value, _ = winreg.QueryValueEx(key, _WINDOWS_APPS_LIGHT_VALUE)
    except OSError:
        _logger.debug("windows_theme_registry_unavailable", exc_info=True)
        return None
    return THEME_LIGHT if value else THEME_DARK


class _ThemeNotifier(QObject):
    """Qt signal carrier for theme changes.

    ``ThemeManager`` is a plain singleton, so it delegates Qt signalling to
    this lightweight :class:`~PyQt6.QtCore.QObject` to broadcast the resolved
    theme name whenever the active theme changes.

    Attributes:
        theme_changed: Emitted with the resolved theme name
            (:data:`THEME_DARK` or :data:`THEME_LIGHT`) after a new theme is
            applied to the application.
    """

    theme_changed = pyqtSignal(str)


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
    alternate-background-color: #232326;
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
    background-color: #eceef2;
    color: #1a1d21;
}

QWidget {
    background-color: #eceef2;
    color: #1a1d21;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 9pt;
}

/* Menu Bar */
QMenuBar {
    background-color: #ffffff;
    color: #1a1d21;
    border-bottom: 1px solid #c2c8d0;
    padding: 2px;
}

QMenuBar::item {
    background-color: transparent;
    padding: 4px 8px;
}

QMenuBar::item:selected {
    background-color: #dde1e7;
}

QMenuBar::item:pressed {
    background-color: #0067c0;
    color: #ffffff;
}

/* Menus */
QMenu {
    background-color: #ffffff;
    color: #1a1d21;
    border: 1px solid #c2c8d0;
    padding: 4px;
}

QMenu::item {
    padding: 6px 24px 6px 8px;
    border-radius: 2px;
}

QMenu::item:selected {
    background-color: #0067c0;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #c2c8d0;
    margin: 4px 8px;
}

/* Toolbar */
QToolBar {
    background-color: #ffffff;
    border: none;
    border-bottom: 1px solid #c2c8d0;
    spacing: 4px;
    padding: 4px;
}

QToolBar::separator {
    width: 1px;
    background-color: #c2c8d0;
    margin: 4px 8px;
}

/* Push Buttons */
QPushButton {
    background-color: #0067c0;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    min-height: 24px;
}

QPushButton:hover {
    background-color: #1378d4;
}

QPushButton:pressed {
    background-color: #00529c;
}

QPushButton:disabled {
    background-color: #c2c8d0;
    color: #9aa3ad;
}

QPushButton[flat="true"] {
    background-color: transparent;
    border: 1px solid #c2c8d0;
    color: #1a1d21;
}

QPushButton[flat="true"]:hover {
    background-color: #e3e6eb;
}

/* Secondary Button */
QPushButton[secondary="true"] {
    background-color: transparent;
    border: 1px solid #c2c8d0;
    color: #1a1d21;
}

QPushButton[secondary="true"]:hover {
    background-color: #e3e6eb;
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
    color: #1a1d21;
    border: 1px solid #c2c8d0;
    border-radius: 4px;
    padding: 4px 8px;
    min-height: 24px;
}

QComboBox:hover {
    border-color: #0067c0;
}

QComboBox:focus {
    border-color: #0067c0;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #1a1d21;
    selection-background-color: #0067c0;
    selection-color: #ffffff;
    border: 1px solid #c2c8d0;
}

/* Line Edit */
QLineEdit {
    background-color: #ffffff;
    color: #1a1d21;
    border: 1px solid #c2c8d0;
    border-radius: 4px;
    padding: 6px 8px;
    selection-background-color: #0067c0;
}

QLineEdit:focus {
    border-color: #0067c0;
}

QLineEdit:disabled {
    background-color: #e3e6eb;
    color: #9aa3ad;
}

/* Text Edit */
QTextEdit, QPlainTextEdit {
    background-color: #ffffff;
    color: #1a1d21;
    border: 1px solid #c2c8d0;
    border-radius: 4px;
    selection-background-color: #0067c0;
    font-family: "JetBrains Mono", "Consolas", monospace;
}

QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #0067c0;
}

/* Scroll Bar */
QScrollBar:vertical {
    background-color: #eceef2;
    width: 12px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #b4bcc6;
    min-height: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:vertical:hover {
    background-color: #9aa3ad;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #eceef2;
    height: 12px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #b4bcc6;
    min-width: 20px;
    border-radius: 6px;
    margin: 2px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #9aa3ad;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #c2c8d0;
    background-color: #ffffff;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #e3e6eb;
    color: #1a1d21;
    padding: 8px 16px;
    border: none;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    border-bottom: 2px solid #0067c0;
}

QTabBar::tab:hover:!selected {
    background-color: #dde1e7;
}

/* List Widget */
QListWidget, QListView {
    background-color: #ffffff;
    color: #1a1d21;
    border: 1px solid #c2c8d0;
    border-radius: 4px;
    outline: none;
}

QListWidget::item, QListView::item {
    padding: 6px 8px;
    border-radius: 2px;
}

QListWidget::item:selected, QListView::item:selected {
    background-color: #0067c0;
    color: #ffffff;
}

QListWidget::item:hover:!selected, QListView::item:hover:!selected {
    background-color: #e3e6eb;
}

/* Group Box */
QGroupBox {
    background-color: #ffffff;
    border: 1px solid #c2c8d0;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 8px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #1a1d21;
}

/* Check Box */
QCheckBox {
    color: #1a1d21;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #c2c8d0;
    border-radius: 3px;
    background-color: #ffffff;
}

QCheckBox::indicator:checked {
    background-color: #0067c0;
    border-color: #0067c0;
}

QCheckBox::indicator:hover {
    border-color: #0067c0;
}

/* Status Bar */
QStatusBar {
    background-color: #0067c0;
    color: #ffffff;
    border: none;
}

/* Progress Bar */
QProgressBar {
    background-color: #c2c8d0;
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #0067c0;
    border-radius: 4px;
}

/* Splitter */
QSplitter::handle {
    background-color: #c2c8d0;
}

QSplitter::handle:hover {
    background-color: #0067c0;
}

/* Label */
QLabel {
    color: #1a1d21;
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
    color: #5a6370;
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
    color: #5a6370;
}

/* Dock Widget */
QDockWidget {
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
    color: #1a1d21;
}

QDockWidget::title {
    background-color: #e3e6eb;
    border-bottom: 1px solid #c2c8d0;
    padding: 6px;
    text-align: left;
}

/* Message Box */
QMessageBox {
    background-color: #eceef2;
}

/* Disabled States */
QComboBox:disabled {
    background-color: #e3e6eb;
    color: #9aa3ad;
    border-color: #c2c8d0;
}

QCheckBox:disabled { color: #9aa3ad; }
QRadioButton:disabled { color: #9aa3ad; }
QLabel:disabled { color: #9aa3ad; }

QSpinBox:disabled, QDoubleSpinBox:disabled {
    background-color: #e3e6eb;
    color: #9aa3ad;
}

/* Focus States */
QTableWidget:focus, QTableView:focus { border-color: #0067c0; }
QTreeWidget:focus, QTreeView:focus { border-color: #0067c0; }
QListWidget:focus, QListView:focus { border-color: #0067c0; }

/* ObjectName Selectors */
QLabel#search_status_label { color: #5a6370; font-size: 8pt; }
QLabel#muted_label { color: #5a6370; }
QLabel#bold_label { font-weight: bold; }
QLabel#hint_label { color: #5a6370; font-style: italic; font-size: 8pt; }

QTabWidget#analysis_tabs::pane { border: none; background: #ffffff; }
QTabWidget#analysis_tabs > QTabBar::tab { padding: 6px 12px; }

QTextEdit#code_preview_text {
    background-color: #ffffff;
    color: #1a1d21;
    border: none;
}

QPushButton#execute_button {
    background-color: #0067c0;
    color: #ffffff;
    font-weight: bold;
    padding: 8px 20px;
}
"""


class ThemeManager:
    """Singleton theme manager for application styling.

    Manages theme loading, switching, and application-wide stylesheet management.
    """

    _instance: ClassVar[ThemeManager | None] = None

    def __init__(self) -> None:
        """Initialize the ThemeManager instance."""
        self._current_theme: str = DEFAULT_THEME
        self._requested_theme: str = DEFAULT_THEME
        self._notifier: _ThemeNotifier = _ThemeNotifier()
        self._system_watch_connected: bool = False
        self.theme_cache: dict[str, str] = {}
        self.styles_available: bool = self._check_styles_available()

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
        if cls._instance is not None:
            cls._instance.release()
        cls._instance = None

    def release(self) -> None:
        """Release live OS color-scheme tracking held by this manager.

        Disconnects the ``colorSchemeChanged`` subscription created for the
        ``"system"`` theme. Safe to call when no subscription is active.
        """
        hints = QGuiApplication.styleHints()
        if not self._system_watch_connected or hints is None:
            self._system_watch_connected = False
            return
        try:
            hints.colorSchemeChanged.disconnect(self._on_system_color_scheme_changed)
        except (TypeError, RuntimeError):
            _logger.debug("system_watch_teardown_noop", exc_info=True)
        self._system_watch_connected = False

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
        except FileNotFoundError:
            _logger.exception("styles_availability_check_failed")
            return False
        return available

    @property
    def theme_changed(self) -> pyqtBoundSignal:
        """Signal emitted with the resolved theme name on every theme change.

        Connect to this to refresh widgets that cannot be styled purely
        through the application stylesheet (custom-painted views, cached icon
        colors, syntax highlighters). The payload is the resolved theme name
        (:data:`THEME_DARK` or :data:`THEME_LIGHT`), never ``"system"``.

        Returns:
            pyqtBoundSignal: The bound ``theme_changed`` signal.
        """
        return self._notifier.theme_changed

    @staticmethod
    def _scheme_to_theme(scheme: Qt.ColorScheme) -> str:
        """Map a Qt color scheme to a concrete theme name.

        Args:
            scheme: The color scheme reported by Qt's style hints.

        Returns:
            str: :data:`THEME_LIGHT` or :data:`THEME_DARK`. When Qt reports
            an unknown scheme, the Windows registry is consulted and
            :data:`DEFAULT_THEME` is used as the final fallback.
        """
        if scheme == Qt.ColorScheme.Light:
            return THEME_LIGHT
        if scheme == Qt.ColorScheme.Dark:
            return THEME_DARK
        return _detect_windows_system_theme() or DEFAULT_THEME

    @classmethod
    def detect_system_theme(cls) -> str:
        """Detect the operating system's active light/dark preference.

        Prefers Qt's cross-platform :meth:`QStyleHints.colorScheme`, which on
        Windows tracks the system app color mode. Falls back to a direct
        Windows registry read and finally to :data:`DEFAULT_THEME`.

        Returns:
            str: :data:`THEME_LIGHT` or :data:`THEME_DARK`.
        """
        hints = QGuiApplication.styleHints()
        if QApplication.instance() is not None and hints is not None:
            return cls._scheme_to_theme(hints.colorScheme())
        return _detect_windows_system_theme() or DEFAULT_THEME

    @classmethod
    def resolve_theme(cls, theme: str) -> str:
        """Resolve a requested theme name to a concrete theme.

        Args:
            theme: Requested theme name (``"dark"``, ``"light"`` or
                ``"system"``).

        Returns:
            str: The concrete theme to render: :data:`THEME_DARK` or
            :data:`THEME_LIGHT`. Unknown names resolve to
            :data:`DEFAULT_THEME`.
        """
        if theme == THEME_SYSTEM:
            return cls.detect_system_theme()
        if theme in {THEME_DARK, THEME_LIGHT}:
            return theme
        return DEFAULT_THEME

    def apply_theme(self, theme: str = DEFAULT_THEME) -> bool:
        r"""Apply a theme to the application.

        Args:
            theme: Requested theme name (``"dark"``, ``"light"`` or
                ``"system"``). ``"system"`` follows the OS light/dark
                preference and keeps tracking live OS changes.

        Returns:
            bool: True if theme was applied successfully.
        """
        if theme not in {THEME_DARK, THEME_LIGHT, THEME_SYSTEM}:
            _logger.warning("unknown_theme", theme=theme, default=DEFAULT_THEME)
            theme = DEFAULT_THEME

        resolved = self.resolve_theme(theme)
        stylesheet = self.get_stylesheet(resolved)
        app_instance = QApplication.instance()

        if isinstance(app_instance, QApplication):
            app_instance.setStyleSheet(stylesheet)
            self._requested_theme = theme
            self._current_theme = resolved
            self._update_system_watch()
            _logger.info("theme_applied", requested=theme, resolved=resolved)
            self._notifier.theme_changed.emit(resolved)
            return True

        _logger.warning("no_qapplication_instance")
        return False

    def _update_system_watch(self) -> None:
        """Connect or disconnect live OS color-scheme tracking.

        When the requested theme is ``"system"``, subscribe to Qt's
        ``colorSchemeChanged`` signal so the application restyles itself the
        moment the OS light/dark preference changes. For explicit dark/light
        selections, the subscription is torn down.
        """
        hints = QGuiApplication.styleHints()
        if QApplication.instance() is None or hints is None:
            return
        signal = hints.colorSchemeChanged
        want_watch = self._requested_theme == THEME_SYSTEM
        if want_watch and not self._system_watch_connected:
            signal.connect(self._on_system_color_scheme_changed)
            self._system_watch_connected = True
        elif not want_watch and self._system_watch_connected:
            signal.disconnect(self._on_system_color_scheme_changed)
            self._system_watch_connected = False

    def _on_system_color_scheme_changed(self, scheme: Qt.ColorScheme) -> None:
        """Restyle the application when the OS color scheme changes.

        Args:
            scheme: The new color scheme reported by Qt's style hints.
        """
        if self._requested_theme != THEME_SYSTEM:
            return
        resolved = self._scheme_to_theme(scheme)
        if resolved == self._current_theme:
            return
        app_instance = QApplication.instance()
        if isinstance(app_instance, QApplication):
            app_instance.setStyleSheet(self.get_stylesheet(resolved))
            self._current_theme = resolved
            _logger.info("system_color_scheme_changed", resolved=resolved)
            self._notifier.theme_changed.emit(resolved)

    def get_stylesheet(self, theme: str) -> str:
        """Get the stylesheet for a theme.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if theme in self.theme_cache:
            _logger.debug("theme_cache_hit", theme=theme)
            return self.theme_cache[theme]

        _logger.debug("theme_cache_miss", theme=theme)
        stylesheet = self._load_stylesheet(theme)
        self.theme_cache[theme] = stylesheet
        return stylesheet

    def _load_stylesheet(self, theme: str) -> str:
        """Load a stylesheet from file or use fallback.

        Args:
            theme: Theme name.

        Returns:
            str: CSS stylesheet string.
        """
        if self.styles_available:
            filename = f"{theme}_theme.qss"
            try:
                if loaded := self._read_stylesheet_file(filename):
                    return loaded
            except OSError as e:
                _logger.warning(
                    "stylesheet_load_failed",
                    style_file=filename,
                    error=str(e),
                )

        _logger.debug("using_fallback_stylesheet", theme=theme)
        return DARK_THEME_FALLBACK if theme == THEME_DARK else LIGHT_THEME_FALLBACK

    @staticmethod
    def _read_stylesheet_file(filename: str) -> str | None:
        """Read a bundled QSS stylesheet by file name.

        Args:
            filename: Stylesheet file name, e.g. ``"dark_theme.qss"``.

        Returns:
            str | None: The stylesheet contents when the file exists and is
            non-empty, otherwise ``None``.
        """
        style_path = get_style_path(filename)
        if style_path.exists():
            with style_path.open(encoding="utf-8") as f:
                content = f.read()
            if content.strip():
                _logger.debug("stylesheet_loaded", path=str(style_path))
                return content
        return None

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
        """Get the resolved theme name currently rendered.

        Returns:
            str: The concrete theme being displayed (:data:`THEME_DARK` or
            :data:`THEME_LIGHT`), never ``"system"``.
        """
        return self._current_theme

    @property
    def requested_theme(self) -> str:
        """Get the theme the user requested.

        Returns:
            str: The requested theme name, which may be ``"system"`` when the
            theme follows the OS preference.
        """
        return self._requested_theme

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
            "background": QColor(236, 238, 242),
            "foreground": QColor(26, 29, 33),
            "accent": QColor(0, 103, 192),
            "success": QColor(46, 125, 50),
            "error": QColor(198, 40, 40),
            "warning": QColor(239, 108, 0),
            "info": QColor(21, 101, 192),
            "muted": QColor(90, 99, 112),
            "border": QColor(194, 200, 208),
            "surface": QColor(255, 255, 255),
            "selection": QColor(0, 103, 192, 50),
            "entropy_low": QColor(46, 125, 50),
            "entropy_mid": QColor(239, 108, 0),
            "entropy_high": QColor(198, 40, 40),
            "graph_edge": QColor(154, 163, 173),
            "graph_node_bg": QColor(255, 255, 255),
            "graph_node_border": QColor(194, 200, 208),
            "hex_zero": QColor(154, 163, 173),
            "hex_printable": QColor(4, 81, 165),
            "hex_nonprintable": QColor(198, 40, 40),
            "hex_modified": QColor(239, 108, 0),
            "offset_text": QColor(90, 99, 112),
            "separator": QColor(212, 217, 224),
            "minimap_bg": QColor(227, 230, 235),
            "minimap_indicator": QColor(0, 103, 192, 80),
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
        cache_count = len(self.theme_cache)
        self.theme_cache.clear()
        _logger.info("theme_cache_cleared", entries_cleared=cache_count)

    @staticmethod
    def get_available_themes() -> list[str]:
        """Get list of available theme names.

        Returns:
            list[str]: List of theme names, including the ``"system"`` option
            that follows the OS light/dark preference.
        """
        return [THEME_DARK, THEME_LIGHT, THEME_SYSTEM]
