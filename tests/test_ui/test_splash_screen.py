"""Tests for SplashScreen module.

Validates splash screen creation, progress tracking, and asset loading
using real splash image assets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QLabel, QProgressBar

from intellicrack.ui.dialogs.splash_screen import (
    FALLBACK_ACCENT_COLOR,
    FALLBACK_BG_COLOR,
    FALLBACK_TEXT_COLOR,
    SPLASH_HEIGHT,
    SPLASH_WIDTH,
    SplashScreen,
)
from intellicrack.ui.resources.resource_helper import get_assets_path


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


_FRAMELESS_HINT: int = 2048
_STAYS_ON_TOP_HINT: int = 262144
_EXPECTED_SPLASH_WIDTH: int = 600
_EXPECTED_SPLASH_HEIGHT: int = 400
_PROGRESS_25: int = 25
_PROGRESS_30: int = 30
_PROGRESS_50: int = 50
_PROGRESS_60: int = 60
_PROGRESS_75: int = 75
_PROGRESS_100: int = 100
_PROGRESS_MAX_CLAMP: int = 150
_PROGRESS_MIN_CLAMP: int = -50
_PROGRESS_BAR_MIN: int = 0
_PROGRESS_BAR_MAX: int = 100
_MIN_SPLASH_IMAGE_WIDTH: int = 400
_MIN_SPLASH_IMAGE_HEIGHT: int = 200
_MAX_SPLASH_IMAGE_WIDTH: int = 2000
_MAX_SPLASH_IMAGE_HEIGHT: int = 1500
_MIN_SPLASH_FILE_SIZE: int = 10000


@pytest.fixture
def splash_screen(
    qapp: QApplication,
) -> Generator[SplashScreen]:
    """Provide a SplashScreen instance for testing.

    Args:
        qapp: Qt application fixture.

    Yields:
        A SplashScreen instance.
    """
    del qapp
    splash = SplashScreen()
    yield splash
    splash.close()


class TestSplashScreenCreation:
    """Tests for splash screen creation."""

    @staticmethod
    def test_creates_splash_screen(_qapp: QApplication) -> None:
        """SplashScreen can be instantiated."""
        splash = SplashScreen()
        assert splash is not None
        splash.close()

    @staticmethod
    def test_splash_has_correct_window_flags(splash_screen: SplashScreen) -> None:
        """Splash screen has correct window flags."""
        flags = int(splash_screen.windowFlags())
        assert flags & _FRAMELESS_HINT
        assert flags & _STAYS_ON_TOP_HINT

    @staticmethod
    def test_splash_has_pixmap(splash_screen: SplashScreen) -> None:
        """Splash screen has a valid pixmap."""
        pixmap = splash_screen.pixmap()
        assert not pixmap.isNull()


class TestSplashDimensions:
    """Tests for splash screen dimensions."""

    @staticmethod
    def test_splash_width_constant() -> None:
        """SPLASH_WIDTH constant is defined."""
        assert SPLASH_WIDTH > 0
        assert SPLASH_WIDTH == _EXPECTED_SPLASH_WIDTH

    @staticmethod
    def test_splash_height_constant() -> None:
        """SPLASH_HEIGHT constant is defined."""
        assert SPLASH_HEIGHT > 0
        assert SPLASH_HEIGHT == _EXPECTED_SPLASH_HEIGHT


class TestSplashColors:
    """Tests for splash screen color constants."""

    @staticmethod
    def test_fallback_bg_color_is_dark() -> None:
        """Fallback background is dark color."""
        assert FALLBACK_BG_COLOR.startswith("#")
        assert FALLBACK_BG_COLOR == "#1e1e1e"

    @staticmethod
    def test_fallback_text_color_is_light() -> None:
        """Fallback text color is light."""
        assert FALLBACK_TEXT_COLOR.startswith("#")
        assert FALLBACK_TEXT_COLOR == "#d4d4d4"

    @staticmethod
    def test_fallback_accent_color_is_blue() -> None:
        """Fallback accent color is blue."""
        assert FALLBACK_ACCENT_COLOR.startswith("#")
        assert FALLBACK_ACCENT_COLOR == "#007acc"


class TestProgressTracking:
    """Tests for progress tracking functionality."""

    @staticmethod
    def test_initial_progress_is_zero(splash_screen: SplashScreen) -> None:
        """Initial progress value is zero."""
        assert splash_screen.progress == 0

    @staticmethod
    def test_set_progress_updates_value(splash_screen: SplashScreen) -> None:
        """set_progress updates progress value."""
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.progress == _PROGRESS_50

    @staticmethod
    def test_set_progress_with_message(splash_screen: SplashScreen) -> None:
        """set_progress can set status message."""
        splash_screen.set_progress(_PROGRESS_25, "Loading...")
        assert splash_screen.progress == _PROGRESS_25
        assert splash_screen.status == "Loading..."

    @staticmethod
    def test_progress_clamped_to_max(splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 100 maximum."""
        splash_screen.set_progress(_PROGRESS_MAX_CLAMP)
        assert splash_screen.progress == _PROGRESS_100

    @staticmethod
    def test_progress_clamped_to_min(splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 0 minimum."""
        splash_screen.set_progress(_PROGRESS_MIN_CLAMP)
        assert splash_screen.progress == 0

    @staticmethod
    def test_progress_updates_progress_bar(splash_screen: SplashScreen) -> None:
        """Progress update affects the progress bar widget."""
        splash_screen.set_progress(_PROGRESS_75)
        assert splash_screen._progress_bar.value() == _PROGRESS_75


class TestStatusMessage:
    """Tests for status message functionality."""

    @staticmethod
    def test_initial_status_message(splash_screen: SplashScreen) -> None:
        """Initial status message is set."""
        assert len(splash_screen.status) > 0
        assert splash_screen.status == "Initializing..."

    @staticmethod
    def test_status_updated_with_progress(splash_screen: SplashScreen) -> None:
        """Status message is updated via set_progress."""
        splash_screen.set_progress(_PROGRESS_50, "Test message")
        assert splash_screen.status == "Test message"

    @staticmethod
    def test_status_preserved_without_message(splash_screen: SplashScreen) -> None:
        """Status message is preserved when not provided."""
        splash_screen.set_progress(_PROGRESS_25, "First message")
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.status == "First message"


class TestShowLoadingStep:
    """Tests for show_loading_step method."""

    @staticmethod
    def test_show_loading_step_updates_progress(splash_screen: SplashScreen) -> None:
        """show_loading_step updates progress value."""
        splash_screen.show_loading_step("Loading tools...", _PROGRESS_30)
        assert splash_screen.progress == _PROGRESS_30

    @staticmethod
    def test_show_loading_step_updates_status(splash_screen: SplashScreen) -> None:
        """show_loading_step updates status message."""
        splash_screen.show_loading_step("Loading tools...", _PROGRESS_30)
        assert splash_screen.status == "Loading tools..."


class TestProgressSignal:
    """Tests for progress_updated signal."""

    @staticmethod
    def test_progress_signal_exists(splash_screen: SplashScreen) -> None:
        """progress_updated signal is defined."""
        assert hasattr(splash_screen, "progress_updated")

    @staticmethod
    def test_progress_signal_emits(splash_screen: SplashScreen) -> None:
        """Signal can be emitted without error."""
        splash_screen.progress_updated.emit(_PROGRESS_50, "Test")


class TestOverlayWidgets:
    """Tests for overlay widget components."""

    @staticmethod
    def test_has_progress_bar(splash_screen: SplashScreen) -> None:
        """Splash has progress bar widget."""
        assert hasattr(splash_screen, "_progress_bar")
        assert isinstance(splash_screen._progress_bar, QProgressBar)

    @staticmethod
    def test_has_status_label(splash_screen: SplashScreen) -> None:
        """Splash has status label widget."""
        assert hasattr(splash_screen, "_status_label")
        assert isinstance(splash_screen._status_label, QLabel)

    @staticmethod
    def test_has_overlay_widget(splash_screen: SplashScreen) -> None:
        """Splash has overlay widget."""
        assert hasattr(splash_screen, "_overlay")

    @staticmethod
    def test_progress_bar_range(splash_screen: SplashScreen) -> None:
        """Progress bar has correct range."""
        assert splash_screen._progress_bar.minimum() == _PROGRESS_BAR_MIN
        assert splash_screen._progress_bar.maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_progress_bar_text_hidden(splash_screen: SplashScreen) -> None:
        """Progress bar text is not visible."""
        assert not splash_screen._progress_bar.isTextVisible()


class TestSplashPixmapLoading:
    """Tests for splash pixmap loading."""

    @staticmethod
    def test_load_splash_pixmap_returns_qpixmap() -> None:
        """_load_splash_pixmap returns QPixmap."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert isinstance(pixmap, QPixmap)

    @staticmethod
    def test_loaded_pixmap_not_null() -> None:
        """Loaded pixmap is not null."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert not pixmap.isNull()

    @staticmethod
    def test_pixmap_has_correct_dimensions() -> None:
        """Loaded pixmap has correct dimensions."""
        pixmap = SplashScreen._load_splash_pixmap()
        assert pixmap.width() <= SPLASH_WIDTH
        assert pixmap.height() <= SPLASH_HEIGHT


class TestFallbackPixmap:
    """Tests for fallback pixmap generation."""

    @staticmethod
    def test_create_fallback_pixmap_returns_qpixmap() -> None:
        """_create_fallback_pixmap returns QPixmap."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert isinstance(pixmap, QPixmap)

    @staticmethod
    def test_fallback_pixmap_not_null() -> None:
        """Fallback pixmap is not null."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert not pixmap.isNull()

    @staticmethod
    def test_fallback_pixmap_has_correct_dimensions() -> None:
        """Fallback pixmap has correct dimensions."""
        pixmap = SplashScreen._create_fallback_pixmap()
        assert pixmap.width() == SPLASH_WIDTH
        assert pixmap.height() == SPLASH_HEIGHT


class TestSplashImageAsset:
    """Tests for splash image asset file."""

    @staticmethod
    def test_splash_image_exists() -> None:
        """splash.png file exists in assets."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        assert splash_path.exists(), f"splash.png not found at {splash_path}"

    @staticmethod
    def test_splash_image_not_empty() -> None:
        """splash.png is not empty."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        size = splash_path.stat().st_size
        assert size > _MIN_SPLASH_FILE_SIZE, f"splash.png too small: {size} bytes"

    @staticmethod
    def test_splash_image_loadable() -> None:
        """splash.png can be loaded as QPixmap."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        pixmap = QPixmap(str(splash_path))
        assert not pixmap.isNull(), "Failed to load splash.png as QPixmap"

    @staticmethod
    def test_splash_image_reasonable_dimensions() -> None:
        """splash.png has reasonable dimensions."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        pixmap = QPixmap(str(splash_path))

        assert pixmap.width() >= _MIN_SPLASH_IMAGE_WIDTH, "splash.png too narrow"
        assert pixmap.height() >= _MIN_SPLASH_IMAGE_HEIGHT, "splash.png too short"
        assert pixmap.width() <= _MAX_SPLASH_IMAGE_WIDTH, "splash.png too wide"
        assert pixmap.height() <= _MAX_SPLASH_IMAGE_HEIGHT, "splash.png too tall"


class TestSplashScreenIntegration:
    """Integration tests for splash screen functionality."""

    @staticmethod
    def test_splash_screen_show_and_hide(_qapp: QApplication) -> None:
        """Splash screen can be shown and hidden."""
        splash = SplashScreen()
        splash.show()
        assert splash.isVisible()
        splash.hide()
        assert not splash.isVisible()
        splash.close()

    @staticmethod
    def test_splash_screen_progress_workflow(_qapp: QApplication) -> None:
        """Splash screen handles typical progress workflow."""
        splash = SplashScreen()
        splash.show()

        splash.set_progress(0, "Starting...")
        assert splash.progress == 0

        splash.set_progress(_PROGRESS_25, "Loading configuration...")
        assert splash.progress == _PROGRESS_25

        splash.set_progress(_PROGRESS_50, "Initializing tools...")
        assert splash.progress == _PROGRESS_50

        splash.set_progress(_PROGRESS_75, "Loading UI...")
        assert splash.progress == _PROGRESS_75

        splash.set_progress(_PROGRESS_100, "Ready!")
        assert splash.progress == _PROGRESS_100

        splash.close()

    @staticmethod
    def test_splash_screen_no_exceptions_on_operations(_qapp: QApplication) -> None:
        """Splash screen operations don't raise exceptions."""
        try:
            splash = SplashScreen()
            splash.show()
            splash.set_progress(_PROGRESS_50, "Testing...")
            splash.show_loading_step("Step 1", _PROGRESS_60)
            _ = splash.progress
            _ = splash.status
            splash.close()
        except Exception as e:
            pytest.fail(f"Splash screen operations raised exception: {e}")
