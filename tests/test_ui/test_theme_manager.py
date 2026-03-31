# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ThemeManager module.

Validates theme loading, stylesheet application, and theme switching
using real stylesheet assets.
"""

from __future__ import annotations

import pytest

from intellicrack.ui.resources.resource_helper import get_assets_path
from intellicrack.ui.resources.theme_manager import (
    DARK_THEME_FALLBACK,
    DEFAULT_THEME,
    LIGHT_THEME_FALLBACK,
    THEME_DARK,
    THEME_LIGHT,
    ThemeManager,
)


_MIN_STYLESHEET_LENGTH: int = 100


@pytest.fixture
def theme_manager() -> ThemeManager:
    """Provide a fresh ThemeManager instance for each test.

    Returns:
        ThemeManager: A fresh singleton instance.
    """
    ThemeManager.reset_instance()
    return ThemeManager.get_instance()


class TestThemeManagerSingleton:
    """Tests for singleton pattern implementation."""

    @staticmethod
    def test_get_instance_returns_same_object() -> None:
        """Singleton returns the same instance."""
        ThemeManager.reset_instance()
        instance1 = ThemeManager.get_instance()
        instance2 = ThemeManager.get_instance()
        assert instance1 is instance2

    @staticmethod
    def test_reset_instance_clears_singleton() -> None:
        """Reset clears the singleton instance."""
        ThemeManager.reset_instance()
        instance1 = ThemeManager.get_instance()
        ThemeManager.reset_instance()
        instance2 = ThemeManager.get_instance()
        assert instance1 is not instance2


class TestThemeConstants:
    """Tests for theme constants."""

    @staticmethod
    def test_theme_dark_constant() -> None:
        """THEME_DARK constant is defined correctly."""
        assert THEME_DARK == "dark"

    @staticmethod
    def test_theme_light_constant() -> None:
        """THEME_LIGHT constant is defined correctly."""
        assert THEME_LIGHT == "light"

    @staticmethod
    def test_default_theme_is_dark() -> None:
        """DEFAULT_THEME is dark."""
        assert DEFAULT_THEME == THEME_DARK


class TestGetStylesheet:
    """Tests for get_stylesheet method."""

    @staticmethod
    def test_get_dark_stylesheet(theme_manager: ThemeManager) -> None:
        """get_stylesheet returns dark theme stylesheet."""
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert isinstance(stylesheet, str)
        assert len(stylesheet) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_get_light_stylesheet(theme_manager: ThemeManager) -> None:
        """get_stylesheet returns light theme stylesheet."""
        stylesheet = theme_manager.get_stylesheet(THEME_LIGHT)
        assert isinstance(stylesheet, str)
        assert len(stylesheet) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_stylesheet_contains_qwidget(theme_manager: ThemeManager) -> None:
        """Stylesheet contains QWidget styling."""
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert "QWidget" in stylesheet

    @staticmethod
    def test_stylesheet_contains_colors(theme_manager: ThemeManager) -> None:
        """Stylesheet contains color definitions."""
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert "#" in stylesheet or "rgb" in stylesheet

    @staticmethod
    def test_stylesheet_cached(theme_manager: ThemeManager) -> None:
        """Stylesheets are cached after first load."""
        stylesheet1 = theme_manager.get_stylesheet(THEME_DARK)
        stylesheet2 = theme_manager.get_stylesheet(THEME_DARK)
        assert stylesheet1 == stylesheet2
        assert THEME_DARK in theme_manager.theme_cache


class TestApplyTheme:
    """Tests for apply_theme method."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_theme_returns_bool(theme_manager: ThemeManager) -> None:
        """apply_theme returns a boolean."""
        result = theme_manager.apply_theme(THEME_DARK)
        assert isinstance(result, bool)

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_dark_theme_succeeds(theme_manager: ThemeManager) -> None:
        """Applying dark theme succeeds."""
        result = theme_manager.apply_theme(THEME_DARK)
        assert result

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_light_theme_succeeds(theme_manager: ThemeManager) -> None:
        """Applying light theme succeeds."""
        result = theme_manager.apply_theme(THEME_LIGHT)
        assert result

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_theme_updates_current_theme(theme_manager: ThemeManager) -> None:
        """apply_theme updates _current_theme."""
        theme_manager.apply_theme(THEME_LIGHT)
        assert theme_manager.current_theme == THEME_LIGHT

        theme_manager.apply_theme(THEME_DARK)
        assert theme_manager.current_theme == THEME_DARK

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_invalid_theme_uses_default(theme_manager: ThemeManager) -> None:
        """Invalid theme name falls back to default."""
        theme_manager.apply_theme("invalid_theme_name")
        assert theme_manager.current_theme == DEFAULT_THEME


class TestCurrentTheme:
    """Tests for current_theme property."""

    @staticmethod
    def test_current_theme_initial_value(theme_manager: ThemeManager) -> None:
        """current_theme has correct initial value."""
        assert theme_manager.current_theme == DEFAULT_THEME

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_current_theme_after_apply(theme_manager: ThemeManager) -> None:
        """current_theme reflects applied theme."""
        theme_manager.apply_theme(THEME_LIGHT)
        assert theme_manager.current_theme == THEME_LIGHT


class TestToggleTheme:
    """Tests for toggle_theme method."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_toggle_from_dark_to_light(theme_manager: ThemeManager) -> None:
        """Toggling from dark goes to light."""
        theme_manager.apply_theme(THEME_DARK)
        result = theme_manager.toggle_theme()
        assert result == THEME_LIGHT
        assert theme_manager.current_theme == THEME_LIGHT

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_toggle_from_light_to_dark(theme_manager: ThemeManager) -> None:
        """Toggling from light goes to dark."""
        theme_manager.apply_theme(THEME_LIGHT)
        result = theme_manager.toggle_theme()
        assert result == THEME_DARK
        assert theme_manager.current_theme == THEME_DARK


class TestAvailableThemes:
    """Tests for get_available_themes method."""

    @staticmethod
    def test_get_available_themes_returns_list() -> None:
        """get_available_themes returns a list."""
        themes = ThemeManager.get_available_themes()
        assert isinstance(themes, list)

    @staticmethod
    def test_available_themes_contains_dark() -> None:
        """Available themes includes dark."""
        themes = ThemeManager.get_available_themes()
        assert THEME_DARK in themes

    @staticmethod
    def test_available_themes_contains_light() -> None:
        """Available themes includes light."""
        themes = ThemeManager.get_available_themes()
        assert THEME_LIGHT in themes


class TestFallbackStylesheets:
    """Tests for fallback stylesheet constants."""

    @staticmethod
    def test_dark_fallback_not_empty() -> None:
        """DARK_THEME_FALLBACK contains content."""
        assert len(DARK_THEME_FALLBACK) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_light_fallback_not_empty() -> None:
        """LIGHT_THEME_FALLBACK contains content."""
        assert len(LIGHT_THEME_FALLBACK) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_dark_fallback_contains_widget_styles() -> None:
        """Dark fallback contains common widget styles."""
        widgets = ["QWidget", "QPushButton", "QLabel"]
        for widget in widgets:
            assert widget in DARK_THEME_FALLBACK, f"Missing {widget} in dark fallback"

    @staticmethod
    def test_light_fallback_contains_widget_styles() -> None:
        """Light fallback contains common widget styles."""
        widgets = ["QWidget", "QPushButton", "QLabel"]
        for widget in widgets:
            assert widget in LIGHT_THEME_FALLBACK, f"Missing {widget} in light fallback"

    @staticmethod
    def test_dark_fallback_has_dark_colors() -> None:
        """Dark fallback uses dark color scheme."""
        dark_colors = ["#1e1e1e", "#2d2d30", "#3e3e42"]
        has_dark = any(color in DARK_THEME_FALLBACK for color in dark_colors)
        assert has_dark, "Dark fallback should have dark colors"

    @staticmethod
    def test_light_fallback_has_light_colors() -> None:
        """Light fallback uses light color scheme."""
        light_colors = ["#ffffff", "#f5f5f5", "#e0e0e0", "#f0f0f0"]
        has_light = any(color in LIGHT_THEME_FALLBACK for color in light_colors)
        assert has_light, "Light fallback should have light colors"


class TestStylesheetFiles:
    """Tests for stylesheet asset files."""

    @staticmethod
    def test_styles_directory_exists() -> None:
        """Styles directory exists in assets."""
        assets = get_assets_path()
        styles_dir = assets / "styles"
        assert styles_dir.exists()
        assert styles_dir.is_dir()

    @staticmethod
    def test_dark_theme_file_exists() -> None:
        """dark_theme.qss file exists."""
        assets = get_assets_path()
        dark_path = assets / "styles" / "dark_theme.qss"
        assert dark_path.exists(), f"dark_theme.qss not found at {dark_path}"

    @staticmethod
    def test_light_theme_file_exists() -> None:
        """light_theme.qss file exists."""
        assets = get_assets_path()
        light_path = assets / "styles" / "light_theme.qss"
        assert light_path.exists(), f"light_theme.qss not found at {light_path}"

    @staticmethod
    def test_dark_theme_file_not_empty() -> None:
        """dark_theme.qss is not empty."""
        assets = get_assets_path()
        dark_path = assets / "styles" / "dark_theme.qss"
        content = dark_path.read_text(encoding="utf-8")
        assert len(content) > _MIN_STYLESHEET_LENGTH, "dark_theme.qss is too short"

    @staticmethod
    def test_light_theme_file_not_empty() -> None:
        """light_theme.qss is not empty."""
        assets = get_assets_path()
        light_path = assets / "styles" / "light_theme.qss"
        content = light_path.read_text(encoding="utf-8")
        assert len(content) > _MIN_STYLESHEET_LENGTH, "light_theme.qss is too short"

    @staticmethod
    def test_stylesheet_files_contain_valid_css() -> None:
        """Stylesheet files contain valid Qt CSS syntax."""
        assets = get_assets_path()

        for theme in ["dark_theme.qss", "light_theme.qss"]:
            path = assets / "styles" / theme
            content = path.read_text(encoding="utf-8")

            assert "{" in content, f"{theme} missing opening braces"
            assert "}" in content, f"{theme} missing closing braces"
            assert ":" in content, f"{theme} missing property separators"
            assert ";" in content, f"{theme} missing statement terminators"


class TestThemeIntegrity:
    """Tests for theme system integrity."""

    @staticmethod
    def test_styles_available_flag(theme_manager: ThemeManager) -> None:
        """ThemeManager correctly detects styles availability."""
        assert theme_manager.styles_available

    @staticmethod
    def test_loaded_stylesheet_matches_file(theme_manager: ThemeManager) -> None:
        """Loaded stylesheet matches file content."""
        assets = get_assets_path()
        dark_path = assets / "styles" / "dark_theme.qss"
        file_content = dark_path.read_text(encoding="utf-8")

        loaded_content = theme_manager.get_stylesheet(THEME_DARK)
        assert loaded_content == file_content

    @staticmethod
    def test_theme_manager_initialization_no_exceptions() -> None:
        """ThemeManager initializes without exceptions."""
        ThemeManager.reset_instance()
        try:
            manager = ThemeManager.get_instance()
            assert manager is not None
        except (RuntimeError, OSError, ValueError) as e:
            pytest.fail(f"ThemeManager initialization failed: {e}")
