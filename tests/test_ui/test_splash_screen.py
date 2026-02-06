"""Tests for SplashScreen module.

Validates splash screen creation, progress tracking, and asset loading
using real splash image assets.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QApplication, QLabel, QProgressBar

from intellicrack.ui.dialogs.splash_screen import (
    FALLBACK_ACCENT_COLOR,
    FALLBACK_BG_COLOR,
    FALLBACK_TEXT_COLOR,
    SPLASH_HEIGHT,
    SPLASH_WIDTH,
    SplashScreen,
)
from intellicrack.ui.resources.resource_helper import get_assets_path


_FRAMELESS_HINT: int = 2048
_STAYS_ON_TOP_HINT: int = 262144


@pytest.fixture
def splash_screen(
    qapp: QApplication,
) -> Generator[SplashScreen]:
    """Provide a SplashScreen instance for testing."""
    del qapp
    splash = SplashScreen()
    yield splash
    splash.close()


class TestSplashScreenCreation:
    """Tests for splash screen creation."""

    def test_creates_splash_screen(self, qapp: QApplication) -> None:
        """SplashScreen can be instantiated."""
        splash = SplashScreen()
        assert splash is not None
        splash.close()

    def test_splash_has_correct_window_flags(self, splash_screen: SplashScreen) -> None:
        """Splash screen has correct window flags."""
        flags = int(splash_screen.windowFlags())
        assert flags & _FRAMELESS_HINT
        assert flags & _STAYS_ON_TOP_HINT

    def test_splash_has_pixmap(self, splash_screen: SplashScreen) -> None:
        """Splash screen has a valid pixmap."""
        pixmap = splash_screen.pixmap()
        assert not pixmap.isNull()


class TestSplashDimensions:
    """Tests for splash screen dimensions."""

    def test_splash_width_constant(self) -> None:
        """SPLASH_WIDTH constant is defined."""
        assert SPLASH_WIDTH > 0
        assert SPLASH_WIDTH == 600

    def test_splash_height_constant(self) -> None:
        """SPLASH_HEIGHT constant is defined."""
        assert SPLASH_HEIGHT > 0
        assert SPLASH_HEIGHT == 400


class TestSplashColors:
    """Tests for splash screen color constants."""

    def test_fallback_bg_color_is_dark(self) -> None:
        """Fallback background is dark color."""
        assert FALLBACK_BG_COLOR.startswith("#")
        assert FALLBACK_BG_COLOR == "#1e1e1e"

    def test_fallback_text_color_is_light(self) -> None:
        """Fallback text color is light."""
        assert FALLBACK_TEXT_COLOR.startswith("#")
        assert FALLBACK_TEXT_COLOR == "#d4d4d4"

    def test_fallback_accent_color_is_blue(self) -> None:
        """Fallback accent color is blue."""
        assert FALLBACK_ACCENT_COLOR.startswith("#")
        assert FALLBACK_ACCENT_COLOR == "#007acc"


class TestProgressTracking:
    """Tests for progress tracking functionality."""

    def test_initial_progress_is_zero(self, splash_screen: SplashScreen) -> None:
        """Initial progress value is zero."""
        assert splash_screen.progress == 0

    def test_set_progress_updates_value(self, splash_screen: SplashScreen) -> None:
        """set_progress updates progress value."""
        splash_screen.set_progress(50)
        assert splash_screen.progress == 50

    def test_set_progress_with_message(self, splash_screen: SplashScreen) -> None:
        """set_progress can set status message."""
        splash_screen.set_progress(25, "Loading...")
        assert splash_screen.progress == 25
        assert splash_screen.status == "Loading..."

    def test_progress_clamped_to_max(self, splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 100 maximum."""
        splash_screen.set_progress(150)
        assert splash_screen.progress == 100

    def test_progress_clamped_to_min(self, splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 0 minimum."""
        splash_screen.set_progress(-50)
        assert splash_screen.progress == 0

    def test_progress_updates_progress_bar(self, splash_screen: SplashScreen) -> None:
        """Progress update affects the progress bar widget."""
        splash_screen.set_progress(75)
        assert splash_screen._progress_bar.value() == 75


class TestStatusMessage:
    """Tests for status message functionality."""

    def test_initial_status_message(self, splash_screen: SplashScreen) -> None:
        """Initial status message is set."""
        assert len(splash_screen.status) > 0
        assert splash_screen.status == "Initializing..."

    def test_status_updated_with_progress(self, splash_screen: SplashScreen) -> None:
        """Status message is updated via set_progress."""
        splash_screen.set_progress(50, "Test message")
        assert splash_screen.status == "Test message"

    def test_status_preserved_without_message(self, splash_screen: SplashScreen) -> None:
        """Status message is preserved when not provided."""
        splash_screen.set_progress(25, "First message")
        splash_screen.set_progress(50)
        assert splash_screen.status == "First message"


class TestShowLoadingStep:
    """Tests for show_loading_step method."""

    def test_show_loading_step_updates_progress(self, splash_screen: SplashScreen) -> None:
        """show_loading_step updates progress value."""
        splash_screen.show_loading_step("Loading tools...", 30)
        assert splash_screen.progress == 30

    def test_show_loading_step_updates_status(self, splash_screen: SplashScreen) -> None:
        """show_loading_step updates status message."""
        splash_screen.show_loading_step("Loading tools...", 30)
        assert splash_screen.status == "Loading tools..."


class TestProgressSignal:
    """Tests for progress_updated signal."""

    def test_progress_signal_exists(self, splash_screen: SplashScreen) -> None:
        """progress_updated signal is defined."""
        assert hasattr(splash_screen, "progress_updated")

    def test_progress_signal_emits(self, splash_screen: SplashScreen) -> None:
        """Signal can be emitted without error."""
        splash_screen.progress_updated.emit(50, "Test")


class TestOverlayWidgets:
    """Tests for overlay widget components."""

    def test_has_progress_bar(self, splash_screen: SplashScreen) -> None:
        """Splash has progress bar widget."""
        assert hasattr(splash_screen, "_progress_bar")
        assert isinstance(splash_screen._progress_bar, QProgressBar)

    def test_has_status_label(self, splash_screen: SplashScreen) -> None:
        """Splash has status label widget."""
        assert hasattr(splash_screen, "_status_label")
        assert isinstance(splash_screen._status_label, QLabel)

    def test_has_overlay_widget(self, splash_screen: SplashScreen) -> None:
        """Splash has overlay widget."""
        assert hasattr(splash_screen, "_overlay")

    def test_progress_bar_range(self, splash_screen: SplashScreen) -> None:
        """Progress bar has correct range."""
        assert splash_screen._progress_bar.minimum() == 0
        assert splash_screen._progress_bar.maximum() == 100

    def test_progress_bar_text_hidden(self, splash_screen: SplashScreen) -> None:
        """Progress bar text is not visible."""
        assert not splash_screen._progress_bar.isTextVisible()


class TestSplashPixmapLoading:
    """Tests for splash pixmap loading."""

    def test_load_splash_pixmap_returns_qpixmap(self) -> None:
        """_load_splash_pixmap returns QPixmap."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert isinstance(pixmap, QPixmap)

    def test_loaded_pixmap_not_null(self) -> None:
        """Loaded pixmap is not null."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert not pixmap.isNull()

    def test_pixmap_has_correct_dimensions(self) -> None:
        """Loaded pixmap has correct dimensions."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert pixmap.width() <= SPLASH_WIDTH
        assert pixmap.height() <= SPLASH_HEIGHT


class TestFallbackPixmap:
    """Tests for fallback pixmap generation."""

    def test_create_fallback_pixmap_returns_qpixmap(self) -> None:
        """_create_fallback_pixmap returns QPixmap."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert isinstance(pixmap, QPixmap)

    def test_fallback_pixmap_not_null(self) -> None:
        """Fallback pixmap is not null."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert not pixmap.isNull()

    def test_fallback_pixmap_has_correct_dimensions(self) -> None:
        """Fallback pixmap has correct dimensions."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert pixmap.width() == SPLASH_WIDTH
        assert pixmap.height() == SPLASH_HEIGHT


class TestSplashImageAsset:
    """Tests for splash image asset file."""

    def test_splash_image_exists(self) -> None:
        """splash.png file exists in assets."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        assert splash_path.exists(), f"splash.png not found at {splash_path}"

    def test_splash_image_not_empty(self) -> None:
        """splash.png is not empty."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        size = splash_path.stat().st_size
        assert size > 10000, f"splash.png too small: {size} bytes"

    def test_splash_image_loadable(self) -> None:
        """splash.png can be loaded as QPixmap."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        pixmap = QPixmap(str(splash_path))
        assert not pixmap.isNull(), "Failed to load splash.png as QPixmap"

    def test_splash_image_reasonable_dimensions(self) -> None:
        """splash.png has reasonable dimensions."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        pixmap = QPixmap(str(splash_path))

        assert pixmap.width() >= 400, "splash.png too narrow"
        assert pixmap.height() >= 200, "splash.png too short"
        assert pixmap.width() <= 2000, "splash.png too wide"
        assert pixmap.height() <= 1500, "splash.png too tall"


class TestSplashScreenIntegration:
    """Integration tests for splash screen functionality."""

    def test_splash_screen_show_and_hide(self, qapp: QApplication) -> None:
        """Splash screen can be shown and hidden."""
        splash = SplashScreen()
        splash.show()
        assert splash.isVisible()
        splash.hide()
        assert not splash.isVisible()
        splash.close()

    def test_splash_screen_progress_workflow(self, qapp: QApplication) -> None:
        """Splash screen handles typical progress workflow."""
        splash = SplashScreen()
        splash.show()

        splash.set_progress(0, "Starting...")
        assert splash.progress == 0

        splash.set_progress(25, "Loading configuration...")
        assert splash.progress == 25

        splash.set_progress(50, "Initializing tools...")
        assert splash.progress == 50

        splash.set_progress(75, "Loading UI...")
        assert splash.progress == 75

        splash.set_progress(100, "Ready!")
        assert splash.progress == 100

        splash.close()

    def test_splash_screen_no_exceptions_on_operations(self, qapp: QApplication) -> None:
        """Splash screen operations don't raise exceptions."""
        try:
            splash = SplashScreen()
            splash.show()
            splash.set_progress(50, "Testing...")
            splash.show_loading_step("Step 1", 60)
            _ = splash.progress
            _ = splash.status
            splash.close()
        except Exception as e:
            pytest.fail(f"Splash screen operations raised exception: {e}")
