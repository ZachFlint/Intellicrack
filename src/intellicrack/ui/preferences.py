# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Preferences dialog for Intellicrack.

This module provides a comprehensive preferences dialog with categorized settings for general, appearance, session, and logging options.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import Qt, pyqtSignal


if TYPE_CHECKING:
    from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFontComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.config import Config, LogConfig, SessionConfig, UIConfig
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ConfirmationLevel, ProviderName
from intellicrack.ui.resources.font_manager import FontManager


_logger = get_logger(__name__)


def _combo_find_data(combo: QComboBox, data: object) -> int:
    """Find index of item with given data in a QComboBox.

    Args:
        combo: The combo box to search.
        data: The data value to find.

    Returns:
        int: The index of the item, or -1 if not found.
    """
    find_data = getattr(combo, "findData", None)
    if find_data is not None:
        result = find_data(data)
        return int(result) if isinstance(result, int) else -1
    return next((i for i in range(combo.count()) if combo.itemData(i) == data), -1)


def _combo_current_data(combo: QComboBox) -> object:
    """Get the current item's data from a QComboBox.

    Args:
        combo: The combo box.

    Returns:
        object: The data associated with the current item.
    """
    current_data = getattr(combo, "currentData", None)
    if current_data is not None:
        return current_data()
    idx = combo.currentIndex()
    return combo.itemData(idx) if idx >= 0 else None


def _item_set_font(item: QListWidgetItem, font: QFont) -> None:
    """Set font on a QListWidgetItem.

    Args:
        item: The list widget item.
        font: The font to set.
    """
    set_font = getattr(item, "setFont", None)
    if set_font is not None:
        set_font(font)


class GeneralSettingsWidget(QWidget):
    """Widget for general application settings."""

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the GeneralSettingsWidget with application configuration.

        Args:
            config: Application configuration instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        provider_group = QGroupBox("Default Provider")
        provider_layout = QFormLayout(provider_group)

        self._provider_combo = QComboBox()
        for provider in ProviderName:
            self._provider_combo.addItem(provider.value.title(), provider.value)
        provider_layout.addRow("Default Provider:", self._provider_combo)

        layout.addWidget(provider_group)

        paths_group = QGroupBox("Directories")
        paths_layout = QFormLayout(paths_group)

        tools_row = QHBoxLayout()
        self._tools_path = QLineEdit()
        tools_row.addWidget(self._tools_path)
        tools_browse = QPushButton("Browse...")
        tools_browse.clicked.connect(self._browse_tools)
        tools_row.addWidget(tools_browse)
        paths_layout.addRow("Tools Directory:", tools_row)

        logs_row = QHBoxLayout()
        self._logs_path = QLineEdit()
        logs_row.addWidget(self._logs_path)
        logs_browse = QPushButton("Browse...")
        logs_browse.clicked.connect(self._browse_logs)
        logs_row.addWidget(logs_browse)
        paths_layout.addRow("Logs Directory:", logs_row)

        layout.addWidget(paths_group)

        behavior_group = QGroupBox("Behavior")
        behavior_layout = QFormLayout(behavior_group)

        self._confirm_combo = QComboBox()
        self._confirm_combo.addItem("Auto-approve all (no confirmations)", ConfirmationLevel.NONE.value)
        self._confirm_combo.addItem("Confirm destructive only", ConfirmationLevel.DESTRUCTIVE.value)
        self._confirm_combo.addItem("Confirm all operations", ConfirmationLevel.ALL.value)
        behavior_layout.addRow("Confirmation Level:", self._confirm_combo)

        layout.addWidget(behavior_group)

        layout.addStretch()

    def _browse_tools(self) -> None:
        """Browse for tools directory."""
        if path := QFileDialog.getExistingDirectory(self, "Select Tools Directory", self._tools_path.text()):
            _logger.info("preferences_tools_directory_selected", path=path)
            self._tools_path.setText(path)

    def _browse_logs(self) -> None:
        """Browse for logs directory."""
        if path := QFileDialog.getExistingDirectory(self, "Select Logs Directory", self._logs_path.text()):
            self._logs_path.setText(path)

    def _load_settings(self) -> None:
        """Load settings from configuration."""
        idx = _combo_find_data(
            self._provider_combo,
            self._config.default_provider.value,
        )
        if idx >= 0:
            self._provider_combo.setCurrentIndex(idx)

        self._tools_path.setText(str(self._config.tools_directory))
        self._logs_path.setText(str(self._config.logs_directory))

        idx = _combo_find_data(
            self._confirm_combo,
            self._config.confirmation_level.value,
        )
        if idx >= 0:
            self._confirm_combo.setCurrentIndex(idx)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings.

        Returns:
            dict[str, Any]: Dictionary of settings.
        """
        provider_value = _combo_current_data(self._provider_combo)
        confirm_value = _combo_current_data(self._confirm_combo)

        return {
            "default_provider": ProviderName(provider_value) if provider_value else self._config.default_provider,
            "tools_directory": Path(self._tools_path.text()) if self._tools_path.text() else self._config.tools_directory,
            "logs_directory": Path(self._logs_path.text()) if self._logs_path.text() else self._config.logs_directory,
            "confirmation_level": ConfirmationLevel(confirm_value) if confirm_value else self._config.confirmation_level,
        }


class AppearanceSettingsWidget(QWidget):
    """Widget for appearance settings."""

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the AppearanceSettingsWidget with application configuration.

        Args:
            config: Application configuration instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        theme_group = QGroupBox("Theme")
        theme_layout = QFormLayout(theme_group)

        self._theme_combo = QComboBox()
        self._theme_combo.addItem("Dark", "dark")
        self._theme_combo.addItem("Light", "light")
        self._theme_combo.addItem("System", "system")
        theme_layout.addRow("Theme:", self._theme_combo)

        layout.addWidget(theme_group)

        font_group = QGroupBox("Font")
        font_layout = QFormLayout(font_group)

        self._font_family = QFontComboBox()
        self._font_family.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        self._font_family.setEditable(True)
        font_layout.addRow("Font Family:", self._font_family)

        self._font_size = QSpinBox()
        self._font_size.setRange(8, 24)
        self._font_size.setValue(12)
        font_layout.addRow("Font Size:", self._font_size)

        layout.addWidget(font_group)

        display_group = QGroupBox("Display")
        display_layout = QFormLayout(display_group)

        self._show_tool_calls = QCheckBox("Show tool calls in chat")
        display_layout.addRow(self._show_tool_calls)

        layout.addWidget(display_group)

        layout.addStretch()

    def _load_settings(self) -> None:
        """Load settings from configuration."""
        idx = _combo_find_data(self._theme_combo, self._config.ui.theme)
        if idx >= 0:
            self._theme_combo.setCurrentIndex(idx)

        saved_family = self._config.ui.font_family
        idx = self._font_family.findText(saved_family)
        if idx >= 0:
            self._font_family.setCurrentIndex(idx)
        else:
            self._font_family.setEditText(saved_family)

        self._font_size.setValue(self._config.ui.font_size)
        self._show_tool_calls.setChecked(self._config.ui.show_tool_calls)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings.

        Returns:
            dict[str, Any]: Dictionary of settings.
        """
        theme_data = _combo_current_data(self._theme_combo)
        theme = str(theme_data) if isinstance(theme_data, str) else self._config.ui.theme
        font_family = str(self._font_family.currentText()).strip() or self._config.ui.font_family
        return {
            "ui": UIConfig(
                theme=theme,
                font_family=font_family,
                font_size=self._font_size.value(),
                show_tool_calls=self._show_tool_calls.isChecked(),
            ),
        }


class SessionSettingsWidget(QWidget):
    """Widget for session settings."""

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the SessionSettingsWidget with application configuration.

        Args:
            config: Application configuration instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        autosave_group = QGroupBox("Auto-Save")
        autosave_layout = QFormLayout(autosave_group)

        self._autosave_enabled = QCheckBox("Enable auto-save")
        autosave_layout.addRow(self._autosave_enabled)

        self._autosave_interval = QSpinBox()
        self._autosave_interval.setRange(30, 3600)
        self._autosave_interval.setSingleStep(30)
        self._autosave_interval.setSuffix(" seconds")
        autosave_layout.addRow("Save Interval:", self._autosave_interval)

        layout.addWidget(autosave_group)

        retention_group = QGroupBox("Session Retention")
        retention_layout = QFormLayout(retention_group)

        self._retention_days = QSpinBox()
        self._retention_days.setRange(1, 365)
        self._retention_days.setSuffix(" days")
        retention_layout.addRow("Keep Sessions:", self._retention_days)

        layout.addWidget(retention_group)

        layout.addStretch()

    def _load_settings(self) -> None:
        """Load settings from configuration."""
        self._autosave_enabled.setChecked(self._config.session.auto_save)
        self._autosave_interval.setValue(self._config.session.save_interval_seconds)
        self._retention_days.setValue(self._config.session.retention_days)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings.

        Returns:
            dict[str, Any]: Dictionary of settings.
        """
        return {
            "session": SessionConfig(
                auto_save=self._autosave_enabled.isChecked(),
                save_interval_seconds=self._autosave_interval.value(),
                retention_days=self._retention_days.value(),
            ),
        }


class LoggingSettingsWidget(QWidget):
    """Widget for logging settings."""

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the LoggingSettingsWidget with application configuration.

        Args:
            config: Application configuration instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        level_group = QGroupBox("Log Level")
        level_layout = QFormLayout(level_group)

        self._log_level = QComboBox()
        self._log_level.addItem("Debug", "DEBUG")
        self._log_level.addItem("Info", "INFO")
        self._log_level.addItem("Warning", "WARNING")
        self._log_level.addItem("Error", "ERROR")
        self._log_level.addItem("Critical", "CRITICAL")
        level_layout.addRow("Log Level:", self._log_level)

        layout.addWidget(level_group)

        output_group = QGroupBox("Log Output")
        output_layout = QFormLayout(output_group)

        self._file_logging = QCheckBox("Enable file logging")
        output_layout.addRow(self._file_logging)

        self._console_logging = QCheckBox("Enable console logging")
        output_layout.addRow(self._console_logging)

        layout.addWidget(output_group)

        rotation_group = QGroupBox("Log Rotation")
        rotation_layout = QFormLayout(rotation_group)

        self._max_file_size = QSpinBox()
        self._max_file_size.setRange(1, 100)
        self._max_file_size.setSuffix(" MB")
        rotation_layout.addRow("Max File Size:", self._max_file_size)

        self._backup_count = QSpinBox()
        self._backup_count.setRange(1, 20)
        self._backup_count.setSuffix(" files")
        rotation_layout.addRow("Backup Count:", self._backup_count)

        layout.addWidget(rotation_group)

        layout.addStretch()

    def _load_settings(self) -> None:
        """Load settings from configuration."""
        idx = _combo_find_data(self._log_level, self._config.log.level)
        if idx >= 0:
            self._log_level.setCurrentIndex(idx)

        self._file_logging.setChecked(self._config.log.file_enabled)
        self._console_logging.setChecked(self._config.log.console_enabled)
        self._max_file_size.setValue(self._config.log.max_file_size_mb)
        self._backup_count.setValue(self._config.log.backup_count)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings.

        Returns:
            dict[str, Any]: Dictionary of settings.
        """
        level_data = _combo_current_data(self._log_level)
        level = str(level_data) if isinstance(level_data, str) else self._config.log.level
        return {
            "log": LogConfig(
                level=level,
                file_enabled=self._file_logging.isChecked(),
                console_enabled=self._console_logging.isChecked(),
                max_file_size_mb=self._max_file_size.value(),
                backup_count=self._backup_count.value(),
            ),
        }


class PreferencesDialog(QDialog):
    """Preferences dialog with categorized settings.

    Provides a unified interface for configuring all application
    settings organized into logical categories.

    Attributes:
        settings_changed: Qt signal for settings changed.
    """

    settings_changed = pyqtSignal(Config)

    def __init__(self, config: Config, parent: QWidget | None = None) -> None:
        """Initialize the PreferencesDialog with application configuration.

        Args:
            config: Application configuration instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._config = config
        self._settings_widgets: list[GeneralSettingsWidget | AppearanceSettingsWidget | SessionSettingsWidget | LoggingSettingsWidget] = []
        self._config_path: Path | None = None
        self._setup_ui()

    def set_config_path(self, path: Path) -> None:
        """Set the configuration file path for saving.

        Args:
            path: Path to the configuration file.
        """
        self._config_path = path

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        self.setWindowTitle("Preferences")
        self.setMinimumSize(700, 500)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._category_list = QListWidget()
        self._category_list.setObjectName("preferences_category_list")
        self._category_list.setFixedWidth(160)
        self._category_list.currentRowChanged.connect(self._on_category_changed)

        categories = ["General", "Appearance", "Session", "Logging"]
        for category in categories:
            item = QListWidgetItem(category)
            _item_set_font(item, FontManager.get_instance().get_ui_font(10))
            self._category_list.addItem(item)

        layout.addWidget(self._category_list)

        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._stack = QStackedWidget()
        self._stack.setObjectName("preferences_stack")

        general_widget = GeneralSettingsWidget(self._config)
        self._stack.addWidget(general_widget)
        self._settings_widgets.append(general_widget)

        appearance_widget = AppearanceSettingsWidget(self._config)
        self._stack.addWidget(appearance_widget)
        self._settings_widgets.append(appearance_widget)

        session_widget = SessionSettingsWidget(self._config)
        self._stack.addWidget(session_widget)
        self._settings_widgets.append(session_widget)

        logging_widget = LoggingSettingsWidget(self._config)
        self._stack.addWidget(logging_widget)
        self._settings_widgets.append(logging_widget)

        right_layout.addWidget(self._stack)

        button_container = QWidget()
        button_container.setObjectName("preferences_button_bar")
        button_container.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(16, 12, 16, 12)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply,
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        if apply_button := button_box.button(QDialogButtonBox.StandardButton.Apply):
            apply_button.clicked.connect(self._on_apply)

        button_layout.addStretch()
        button_layout.addWidget(button_box)

        right_layout.addWidget(button_container)

        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        layout.addWidget(right_widget)

        self._category_list.setCurrentRow(0)

    def _on_category_changed(self, index: int) -> None:
        """Handle category selection change.

        Args:
            index: Selected category index.
        """
        self._stack.setCurrentIndex(index)

    def _on_accept(self) -> None:
        """Handle OK button click."""
        self._on_apply()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        new_config = self._build_config()
        self._config = new_config
        _logger.info("preferences_settings_changed_emit")
        self.settings_changed.emit(new_config)

        if self._config_path is not None:
            try:
                new_config.save(self._config_path)
                _logger.info("configuration_saved", path=str(self._config_path))
            except OSError:
                _logger.exception("configuration_save_failed")

    def _build_config(self) -> Config:
        """Build a new Config from all widget settings.

        Returns:
            Config: New Config instance with updated values.
        """
        all_settings: dict[str, Any] = {}
        for widget in self._settings_widgets:
            all_settings |= widget.get_settings()

        return replace(
            self._config,
            default_provider=all_settings.get("default_provider", self._config.default_provider),
            tools_directory=all_settings.get("tools_directory", self._config.tools_directory),
            logs_directory=all_settings.get("logs_directory", self._config.logs_directory),
            confirmation_level=all_settings.get("confirmation_level", self._config.confirmation_level),
            ui=all_settings.get("ui", self._config.ui),
            session=all_settings.get("session", self._config.session),
            log=all_settings.get("log", self._config.log),
        )

    def get_config(self) -> Config:
        """Get the current configuration.

        Returns:
            Config: The current configuration object.
        """
        return self._config
