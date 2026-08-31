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
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QMainWindow, QToolBar, QWidget

from intellicrack.ui.resources.resource_helper import get_assets_path
from intellicrack.ui.resources.theme_manager import (
    DARK_THEME_FALLBACK,
    DEFAULT_THEME,
    LIGHT_THEME_FALLBACK,
    THEME_DARK,
    THEME_LIGHT,
    THEME_SYSTEM,
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
        """get_stylesheet returns dark theme stylesheet.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert isinstance(stylesheet, str)
        assert len(stylesheet) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_get_light_stylesheet(theme_manager: ThemeManager) -> None:
        """get_stylesheet returns light theme stylesheet.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        stylesheet = theme_manager.get_stylesheet(THEME_LIGHT)
        assert isinstance(stylesheet, str)
        assert len(stylesheet) > _MIN_STYLESHEET_LENGTH

    @staticmethod
    def test_stylesheet_contains_qwidget(theme_manager: ThemeManager) -> None:
        """Stylesheet contains QWidget styling.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert "QWidget" in stylesheet

    @staticmethod
    def test_stylesheet_contains_colors(theme_manager: ThemeManager) -> None:
        """Stylesheet contains color definitions.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        stylesheet = theme_manager.get_stylesheet(THEME_DARK)
        assert "#" in stylesheet or "rgb" in stylesheet

    @staticmethod
    def test_stylesheet_cached(theme_manager: ThemeManager) -> None:
        """Stylesheets are cached after first load.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        stylesheet1 = theme_manager.get_stylesheet(THEME_DARK)
        stylesheet2 = theme_manager.get_stylesheet(THEME_DARK)
        assert stylesheet1 == stylesheet2
        assert THEME_DARK in theme_manager.theme_cache


class TestApplyTheme:
    """Tests for apply_theme method."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_theme_returns_bool(theme_manager: ThemeManager) -> None:
        """apply_theme returns a boolean.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        result = theme_manager.apply_theme(THEME_DARK)
        assert isinstance(result, bool)

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_dark_theme_succeeds(theme_manager: ThemeManager) -> None:
        """Applying dark theme succeeds.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        result = theme_manager.apply_theme(THEME_DARK)
        assert result

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_light_theme_succeeds(theme_manager: ThemeManager) -> None:
        """Applying light theme succeeds.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        result = theme_manager.apply_theme(THEME_LIGHT)
        assert result

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_theme_updates_current_theme(theme_manager: ThemeManager) -> None:
        """apply_theme updates _current_theme.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_LIGHT)
        assert theme_manager.current_theme == THEME_LIGHT

        theme_manager.apply_theme(THEME_DARK)
        assert theme_manager.current_theme == THEME_DARK

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_invalid_theme_uses_default(theme_manager: ThemeManager) -> None:
        """Invalid theme name falls back to default theme with stylesheet applied.

        Asserts that:
        - current_theme tracks DEFAULT_THEME (not the invalid name)
        - theme_changed signal fires with DEFAULT_THEME (not the invalid name)
        - QApplication stylesheet is set to the default-theme stylesheet content

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        received: list[str] = []
        theme_manager.theme_changed.connect(received.append)

        result = theme_manager.apply_theme("invalid_theme_name")

        assert result is True
        assert theme_manager.current_theme == DEFAULT_THEME

        assert len(received) == 1, f"theme_changed emitted {len(received)} times, expected 1"
        assert received[0] == DEFAULT_THEME, f"theme_changed emitted {received[0]!r}, expected DEFAULT_THEME {DEFAULT_THEME!r}"

        app = QApplication.instance()
        assert isinstance(app, QApplication)
        applied_sheet = app.styleSheet()
        expected_sheet = theme_manager.get_stylesheet(DEFAULT_THEME)
        assert applied_sheet == expected_sheet, (
            f"QApplication.styleSheet() does not match DEFAULT_THEME stylesheet "
            f"(got {len(applied_sheet)} chars, expected {len(expected_sheet)} chars)"
        )


class TestCurrentTheme:
    """Tests for current_theme property."""

    @staticmethod
    def test_current_theme_initial_value(theme_manager: ThemeManager) -> None:
        """current_theme has correct initial value.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        assert theme_manager.current_theme == DEFAULT_THEME

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_current_theme_after_apply(theme_manager: ThemeManager) -> None:
        """current_theme reflects applied theme.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_LIGHT)
        assert theme_manager.current_theme == THEME_LIGHT


class TestToggleTheme:
    """Tests for toggle_theme method."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_toggle_from_dark_to_light(theme_manager: ThemeManager) -> None:
        """Toggling from dark goes to light.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_DARK)
        result = theme_manager.toggle_theme()
        assert result == THEME_LIGHT
        assert theme_manager.current_theme == THEME_LIGHT

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_toggle_from_light_to_dark(theme_manager: ThemeManager) -> None:
        """Toggling from light goes to dark.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
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

    @staticmethod
    def test_available_themes_contains_system() -> None:
        """Available themes includes system."""
        themes = ThemeManager.get_available_themes()
        assert THEME_SYSTEM in themes


class TestSystemThemeResolution:
    """Tests for system theme detection and resolution."""

    @staticmethod
    def test_theme_system_constant() -> None:
        """THEME_SYSTEM constant is defined correctly."""
        assert THEME_SYSTEM == "system"

    @staticmethod
    def test_resolve_dark_is_identity() -> None:
        """resolve_theme returns dark unchanged."""
        assert ThemeManager.resolve_theme(THEME_DARK) == THEME_DARK

    @staticmethod
    def test_resolve_light_is_identity() -> None:
        """resolve_theme returns light unchanged."""
        assert ThemeManager.resolve_theme(THEME_LIGHT) == THEME_LIGHT

    @staticmethod
    def test_resolve_invalid_uses_default() -> None:
        """resolve_theme falls back to default for unknown names."""
        assert ThemeManager.resolve_theme("not_a_theme") == DEFAULT_THEME

    @staticmethod
    def test_resolve_system_returns_concrete_theme() -> None:
        """resolve_theme('system') resolves to a concrete theme."""
        assert ThemeManager.resolve_theme(THEME_SYSTEM) in {THEME_DARK, THEME_LIGHT}

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_detect_system_theme_returns_concrete() -> None:
        """detect_system_theme returns a concrete theme name."""
        assert ThemeManager.detect_system_theme() in {THEME_DARK, THEME_LIGHT}


class TestApplySystemTheme:
    """Tests for applying and tracking the system theme."""

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_apply_system_succeeds(theme_manager: ThemeManager) -> None:
        """Applying the system theme succeeds and resolves concretely.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        assert theme_manager.apply_theme(THEME_SYSTEM)
        assert theme_manager.requested_theme == THEME_SYSTEM
        assert theme_manager.current_theme in {THEME_DARK, THEME_LIGHT}

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_current_theme_never_reports_system(theme_manager: ThemeManager) -> None:
        """current_theme exposes the resolved theme, not the requested mode.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_SYSTEM)
        assert theme_manager.current_theme != THEME_SYSTEM

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_theme_changed_signal_emits_resolved(theme_manager: ThemeManager) -> None:
        """theme_changed emits the resolved theme on every apply.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        received: list[str] = []
        theme_manager.theme_changed.connect(received.append)
        theme_manager.apply_theme(THEME_LIGHT)
        assert received == [THEME_LIGHT]

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_system_theme_enables_live_watch(theme_manager: ThemeManager) -> None:
        """Applying the system theme subscribes to live OS color-scheme changes.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_SYSTEM)
        assert theme_manager._system_watch_connected is True

        theme_manager.apply_theme(THEME_DARK)
        assert theme_manager._system_watch_connected is False

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_system_theme_responds_to_os_change(theme_manager: ThemeManager) -> None:
        """While system is active, an OS color-scheme change restyles the app.

        Drives the live-tracking handler with the color scheme Qt would deliver
        so the assertion is deterministic across platforms and test ordering,
        unlike forcing a global override that some QPA plugins ignore.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_SYSTEM)
        received: list[str] = []
        theme_manager.theme_changed.connect(received.append)

        theme_manager._on_system_color_scheme_changed(Qt.ColorScheme.Light)
        assert theme_manager.current_theme == THEME_LIGHT

        theme_manager._on_system_color_scheme_changed(Qt.ColorScheme.Dark)
        assert theme_manager.current_theme == THEME_DARK

        theme_manager._on_system_color_scheme_changed(Qt.ColorScheme.Light)
        assert theme_manager.current_theme == THEME_LIGHT

        assert THEME_DARK in received
        assert THEME_LIGHT in received

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_explicit_theme_ignores_os_change(theme_manager: ThemeManager) -> None:
        """An explicit dark/light selection does not follow OS changes.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        theme_manager.apply_theme(THEME_DARK)
        theme_manager._on_system_color_scheme_changed(Qt.ColorScheme.Light)
        assert theme_manager.current_theme == THEME_DARK


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


class _RecordingStyleStandIn:
    """Duck-typed stand-in for ``QApplication.style()`` that records ``polish``/``unpolish`` calls.

    ``QStyle.polish``/``unpolish`` are C++ virtuals with three
    inconsistently-named PyQt6-stub overloads (``QWidget``, ``QPalette``,
    ``QApplication``): a real ``QStyle`` subclass overriding them cannot be
    typed in a way that is simultaneously compatible with all three
    differently-named base overloads, so this stand-in avoids subclassing
    ``QStyle``/``QProxyStyle`` entirely. ``ThemeManager._repolish_chrome``
    only ever calls ``style().unpolish(widget)`` and ``style().polish(widget)``
    via plain duck typing on whatever ``QApplication.style()`` returns, so a
    plain, precisely-typed Python object serves exactly as well as a real
    ``QStyle`` for observing those two calls, with no override involved at
    all. It is installed only by reassigning the ``style`` attribute on the
    live ``QApplication`` instance for the narrow, fully synchronous duration
    of a single ``ThemeManager.apply_theme`` call, then immediately restored.
    """

    def __init__(self) -> None:
        """Initialize the stand-in with empty call-history lists."""
        self.polished: list[QWidget] = []
        self.unpolished: list[QWidget] = []

    def polish(self, widget: QWidget) -> None:
        """Record a ``polish(widget)`` call.

        Args:
            widget: The widget being polished.
        """
        self.polished.append(widget)

    def unpolish(self, widget: QWidget) -> None:
        """Record an ``unpolish(widget)`` call.

        Args:
            widget: The widget being unpolished.
        """
        self.unpolished.append(widget)


class TestMenuBarToolbarRuntimeRepolish:
    """Regression gate: a live theme toggle must repolish the menu bar and toolbar.

    Reproduces the reported bug where Settings -> Toggle Theme left the main
    menu bar and toolbar rendering the previous theme's colors: on Windows, a
    QMenuBar/QToolBar that has already been polished once keeps its
    first-polished background after a second ``QApplication.setStyleSheet()``
    call unless it is explicitly unpolished and repolished. This asserts the
    fix's actual mechanism -- that ``ThemeManager.apply_theme`` calls
    ``style().unpolish()`` then ``style().polish()`` on the live
    QMenuBar/QToolBar during a runtime toggle -- via
    :class:`_RecordingStyleStandIn`, rather than sampling rendered pixels:
    pixel output does not distinguish a fixed build from a broken one under
    Qt's offscreen platform plugin (used in the sandbox), where
    ``setStyleSheet`` alone already repaints correctly regardless of polish
    state.
    """

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_runtime_toggle_repolishes_menubar_and_toolbar(theme_manager: ThemeManager) -> None:
        """A runtime dark->light toggle unpolishes and repolishes a live QMenuBar and QToolBar.

        Falsifiable: removing the ``self._repolish_chrome(app_instance)`` call
        from ``ThemeManager.apply_theme`` leaves ``unpolished`` (and
        ``polished``) empty for both widgets (confirmed by reverting it
        locally and rerunning this test) -- the stand-in style is never
        consulted at all without that call, since Qt's own stylesheet
        machinery resolves styling internally rather than by calling back
        into ``QApplication.style()``.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        app = QApplication.instance()
        assert isinstance(app, QApplication)

        window = QMainWindow()
        menubar = window.menuBar()
        assert menubar is not None
        menubar.addMenu("&File")
        toolbar = QToolBar("Main Toolbar")
        toolbar.addAction(QAction("Load Binary", toolbar))
        window.addToolBar(toolbar)
        window.resize(400, 200)
        window.show()
        QApplication.processEvents()

        try:
            assert theme_manager.apply_theme(THEME_DARK)
            QApplication.processEvents()

            stand_in = _RecordingStyleStandIn()
            original_style_method = app.style
            setattr(app, "style", lambda: stand_in)
            try:
                assert theme_manager.apply_theme(THEME_LIGHT)
            finally:
                setattr(app, "style", original_style_method)
            QApplication.processEvents()

            assert menubar in stand_in.unpolished, "QMenuBar was not unpolished during the runtime theme toggle"
            assert menubar in stand_in.polished, "QMenuBar was not repolished during the runtime theme toggle"
            assert toolbar in stand_in.unpolished, "QToolBar was not unpolished during the runtime theme toggle"
            assert toolbar in stand_in.polished, "QToolBar was not repolished during the runtime theme toggle"
        finally:
            window.close()
            theme_manager.apply_theme(THEME_DARK)


class TestThemeIntegrity:
    """Tests for theme system integrity."""

    @staticmethod
    def test_styles_available_flag(theme_manager: ThemeManager) -> None:
        """ThemeManager correctly detects styles availability.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
        assert theme_manager.styles_available

    @staticmethod
    def test_loaded_stylesheet_matches_file(theme_manager: ThemeManager) -> None:
        """Loaded stylesheet matches file content.

        Args:
            theme_manager: Fresh ThemeManager fixture instance.
        """
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
