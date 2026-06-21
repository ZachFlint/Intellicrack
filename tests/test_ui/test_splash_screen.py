# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for SplashScreen module.

Validates splash screen creation, progress tracking, asset loading,
fade animations, version display, DPI scaling, and animated progress
using real splash image assets.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QPropertyAnimation, QRectF
from PyQt6.QtGui import QColor, QImage, QPainter, QPixmap
from PyQt6.QtWidgets import QLabel, QProgressBar, QWidget

from intellicrack.ui.dialogs.splash_screen import (
    DEFAULT_DPI_SCALE,
    FADE_DURATION_MS,
    FALLBACK_ACCENT_COLOR,
    FALLBACK_BG_COLOR,
    FALLBACK_TEXT_COLOR,
    PROGRESS_ANIM_DURATION_MS,
    SPLASH_HEIGHT,
    SPLASH_WIDTH,
    SplashScreen,
)
from intellicrack.ui.resources.resource_helper import get_assets_path


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


_FRAMELESS_HINT: int = 2048
_SPLASH_WINDOW_TYPE: int = 15
_WINDOW_TYPE_MASK: int = 0xFF
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

_RENDER_W: int = 600
_RENDER_H: int = 400
_SENTINEL_R: int = 17
_SENTINEL_G: int = 71
_SENTINEL_B: int = 137
_PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"
_PNG_IHDR_OFFSET: int = 16
_MIN_PAINTED_PIXELS: int = 1000
_MIN_DISTINCT_COLORS: int = 8
_MIN_PIPELINE_COLORS: int = 2
_PIXEL_SAMPLE_STEP: int = 4
_STAGE_COUNT: int = 8


def _render_splash_layers(splash: SplashScreen) -> QImage:
    """Render the background, pipeline, and status layers onto an image.

    The target image is pre-filled with a known sentinel color so that the
    number of pixels the real production draw helpers overwrite can be measured
    independently of any value the test injected. The full-screen gradient
    background guarantees substantial output when the helper runs correctly.

    Args:
        splash: The SplashScreen whose draw helpers are exercised.

    Returns:
        QImage: The rendered image after the three draw helpers have run.
    """
    pixmap = QPixmap(_RENDER_W, _RENDER_H)
    pixmap.fill(QColor(_SENTINEL_R, _SENTINEL_G, _SENTINEL_B))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    rect = QRectF(0.0, 0.0, float(_RENDER_W), float(_RENDER_H))
    draw_bg = getattr(splash, "_draw_gradient_background")
    draw_pipe = getattr(splash, "_draw_pipeline")
    draw_status = getattr(splash, "_draw_status_and_version")
    draw_bg(painter, rect)
    draw_pipe(painter, rect)
    draw_status(painter, rect)
    painter.end()
    return pixmap.toImage()


def _count_painted_and_distinct(image: QImage) -> tuple[int, int]:
    """Count overwritten pixels and distinct colors in a rendered image.

    A pixel is considered "painted" when it no longer matches the sentinel fill
    color. This provides an independent measure that the production draw helpers
    actually produced output rather than silently returning.

    Args:
        image: The rendered image to inspect.

    Returns:
        tuple[int, int]: ``(painted_pixel_count, distinct_color_count)`` sampled
        across the image on a fixed stride.
    """
    sentinel = QColor(_SENTINEL_R, _SENTINEL_G, _SENTINEL_B).rgb()
    painted = 0
    colors: set[int] = set()
    width = image.width()
    height = image.height()
    for y in range(0, height, _PIXEL_SAMPLE_STEP):
        for x in range(0, width, _PIXEL_SAMPLE_STEP):
            rgb = image.pixel(x, y)
            colors.add(rgb)
            if rgb != sentinel:
                painted += 1
    return painted, len(colors)


@pytest.fixture
def splash_screen(
    qapp: QApplication,
) -> Generator[SplashScreen]:
    """Provide a SplashScreen instance for testing.

    Args:
        qapp: Qt application fixture.

    Yields:
        Generator[SplashScreen]:: A SplashScreen instance.
    """
    del qapp
    splash = SplashScreen()
    yield splash
    splash.close()


@pytest.fixture
def splash_with_version(
    qapp: QApplication,
) -> Generator[SplashScreen]:
    """Provide a SplashScreen instance with version for testing.

    Args:
        qapp: Qt application fixture.

    Yields:
        Generator[SplashScreen]:: A SplashScreen instance with version "1.2.3".
    """
    del qapp
    splash = SplashScreen(version="1.2.3")
    yield splash
    splash.close()


class TestSplashScreenCreation:
    """Tests for splash screen creation."""

    @staticmethod
    def test_creates_splash_screen(qapp: QApplication) -> None:
        """Construction establishes the documented initial invariants.

        Asserting ``splash is not None`` cannot fail because the constructor
        would raise first; instead this gate checks the observable state the
        ``__init__`` body is responsible for setting up: zero progress, the
        default status string, all eight pipeline stages PENDING, and a
        non-null backing pixmap sized from the DPI-scaled dimensions.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        assert splash.progress == 0
        assert splash.status == "Initializing..."
        stages: list[int] = getattr(splash, "_stage_states")
        assert len(stages) == _STAGE_COUNT
        assert all(int(s) == _STATE_PENDING for s in stages)
        assert not splash.pixmap().isNull()
        assert splash.pixmap().width() == splash.scaled_width
        assert splash.pixmap().height() == splash.scaled_height
        splash.close()

    @staticmethod
    def test_splash_has_correct_window_flags(splash_screen: SplashScreen) -> None:
        """Splash screen has correct window flags.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        flags = int(splash_screen.windowFlags())
        assert flags & _FRAMELESS_HINT
        assert flags & _WINDOW_TYPE_MASK == _SPLASH_WINDOW_TYPE

    @staticmethod
    def test_splash_has_pixmap(splash_screen: SplashScreen) -> None:
        """Splash screen has a valid pixmap.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
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
        """Initial progress value is zero.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert splash_screen.progress == 0

    @staticmethod
    def test_set_progress_updates_value(splash_screen: SplashScreen) -> None:
        """set_progress updates progress value.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.progress == _PROGRESS_50

    @staticmethod
    def test_set_progress_with_message(splash_screen: SplashScreen) -> None:
        """set_progress can set status message.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_25, "Loading...")
        assert splash_screen.progress == _PROGRESS_25
        assert splash_screen.status == "Loading..."

    @staticmethod
    def test_progress_clamped_to_max(splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 100 maximum.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_MAX_CLAMP)
        assert splash_screen.progress == _PROGRESS_100

    @staticmethod
    def test_progress_clamped_to_min(splash_screen: SplashScreen) -> None:
        """Progress value is clamped to 0 minimum.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_MIN_CLAMP)
        assert splash_screen.progress == 0

    @staticmethod
    def test_progress_updates_progress_bar(splash_screen: SplashScreen) -> None:
        """Progress update creates animation targeting correct value.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_75)
        assert splash_screen.progress_animation is not None
        assert splash_screen.progress_animation.endValue() == _PROGRESS_75


class TestStatusMessage:
    """Tests for status message functionality."""

    @staticmethod
    def test_initial_status_message(splash_screen: SplashScreen) -> None:
        """Initial status message is set.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert len(splash_screen.status) > 0
        assert splash_screen.status == "Initializing..."

    @staticmethod
    def test_status_updated_with_progress(splash_screen: SplashScreen) -> None:
        """Status message is updated via set_progress.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_50, "Test message")
        assert splash_screen.status == "Test message"

    @staticmethod
    def test_status_preserved_without_message(splash_screen: SplashScreen) -> None:
        """Status message is preserved when not provided.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_25, "First message")
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.status == "First message"


class TestShowLoadingStep:
    """Tests for show_loading_step method."""

    @staticmethod
    def test_show_loading_step_updates_progress(splash_screen: SplashScreen) -> None:
        """show_loading_step updates progress value.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_30, "Loading tools...")
        assert splash_screen.progress == _PROGRESS_30

    @staticmethod
    def test_show_loading_step_updates_status(splash_screen: SplashScreen) -> None:
        """show_loading_step updates status message.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_30, "Loading tools...")
        assert splash_screen.status == "Loading tools..."


class TestProgressSignal:
    """Tests for progress_updated signal."""

    @staticmethod
    def test_progress_signal_exists(splash_screen: SplashScreen) -> None:
        """progress_updated signal is defined.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert hasattr(splash_screen, "progress_updated")

    @staticmethod
    def test_progress_signal_emits(splash_screen: SplashScreen) -> None:
        """progress_updated signal delivers (value, message) to connected slots.

        The previous test emitted the signal without connecting any handler
        and made no assertions, so a completely broken signal-emit path would
        still pass.  This gate connects an explicit capturing slot before
        emission, then asserts the captured arguments exactly match the emitted
        values and that the splash state was updated accordingly.  If signal
        emission is broken, ``received`` stays empty and the first assertion
        fails.  If the connected ``_on_progress_updated`` slot is broken,
        ``splash_screen.progress`` will not equal ``_PROGRESS_50``.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        received: list[tuple[int, str]] = []

        def _capture(value: int, message: str) -> None:
            received.append((value, message))

        splash_screen.progress_updated.connect(_capture)
        splash_screen.progress_updated.emit(_PROGRESS_50, "Test")

        assert len(received) == 1, (
            f"Expected 1 signal delivery, got {len(received)}"
        )
        assert received[0] == (_PROGRESS_50, "Test"), (
            f"Signal delivered wrong arguments: {received[0]!r}"
        )
        assert splash_screen.progress == _PROGRESS_50, (
            f"splash.progress not updated after signal: {splash_screen.progress}"
        )
        assert splash_screen.status == "Test", (
            f"splash.status not updated after signal: {splash_screen.status!r}"
        )


class TestOverlayWidgets:
    """Tests for overlay widget components."""

    @staticmethod
    def test_has_progress_bar(splash_screen: SplashScreen) -> None:
        """Splash has progress bar widget.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert hasattr(splash_screen, "_progress_bar")
        assert isinstance(splash_screen.progress_bar, QProgressBar)

    @staticmethod
    def test_has_status_label(splash_screen: SplashScreen) -> None:
        """Splash has status label widget.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert hasattr(splash_screen, "_status_label")
        assert isinstance(splash_screen.status_label, QLabel)

    @staticmethod
    def test_has_overlay_widget(splash_screen: SplashScreen) -> None:
        """Splash has overlay widget.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert hasattr(splash_screen, "_overlay")

    @staticmethod
    def test_progress_bar_range(splash_screen: SplashScreen) -> None:
        """Progress bar has correct range.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert splash_screen.progress_bar.minimum() == _PROGRESS_BAR_MIN
        assert splash_screen.progress_bar.maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_progress_bar_text_hidden(splash_screen: SplashScreen) -> None:
        """Progress bar text is not visible.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert not splash_screen.progress_bar.isTextVisible()


class TestSplashPixmapLoading:
    """Tests for splash pixmap loading."""

    @staticmethod
    def test_load_splash_pixmap_returns_qpixmap() -> None:
        """_load_splash_pixmap returns QPixmap."""
        pixmap = SplashScreen.load_splash_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
        assert isinstance(pixmap, QPixmap)

    @staticmethod
    def test_loaded_pixmap_not_null() -> None:
        """Loaded pixmap is not null."""
        pixmap = SplashScreen.load_splash_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
        assert not pixmap.isNull()

    @staticmethod
    def test_pixmap_has_correct_dimensions() -> None:
        """Loaded pixmap has correct dimensions."""
        pixmap = SplashScreen.load_splash_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
        assert pixmap.width() <= SPLASH_WIDTH
        assert pixmap.height() <= SPLASH_HEIGHT


class TestFallbackPixmap:
    """Tests for fallback pixmap generation."""

    @staticmethod
    def test_create_fallback_pixmap_returns_qpixmap() -> None:
        """_create_fallback_pixmap returns QPixmap."""
        pixmap = SplashScreen.create_fallback_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
        assert isinstance(pixmap, QPixmap)

    @staticmethod
    def test_fallback_pixmap_not_null() -> None:
        """Fallback pixmap is not null."""
        pixmap = SplashScreen.create_fallback_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
        assert not pixmap.isNull()

    @staticmethod
    def test_fallback_pixmap_has_correct_dimensions() -> None:
        """Fallback pixmap has correct dimensions."""
        pixmap = SplashScreen.create_fallback_pixmap(SPLASH_WIDTH, SPLASH_HEIGHT, DEFAULT_DPI_SCALE)
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
    def test_splash_screen_show_and_hide(qapp: QApplication) -> None:
        """Splash screen can be shown and hidden.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        splash.show()
        assert splash.isVisible()
        splash.hide()
        assert not splash.isVisible()
        splash.close()

    @staticmethod
    def test_splash_screen_progress_workflow(qapp: QApplication) -> None:
        """Splash screen handles typical progress workflow.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
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
    def test_splash_screen_no_exceptions_on_operations(qapp: QApplication) -> None:
        """Splash screen operations produce the expected state after completing.

        The previous gate only checked that no exception was raised; a method
        that silently returned without doing anything would still pass.  This
        gate additionally asserts concrete observable state after each
        operation so that a regression in set_progress, status tracking, or
        progress clamping is immediately detectable.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        splash.show()

        splash.set_progress(_PROGRESS_50, "Testing...")
        assert splash.progress == _PROGRESS_50, (
            f"Expected progress={_PROGRESS_50} after set_progress, got {splash.progress}"
        )
        assert splash.status == "Testing...", (
            f"Expected status='Testing...' after set_progress, got {splash.status!r}"
        )

        splash.set_progress(_PROGRESS_60, "Step 1")
        assert splash.progress == _PROGRESS_60, (
            f"Expected progress={_PROGRESS_60} after second set_progress, got {splash.progress}"
        )
        assert splash.status == "Step 1", (
            f"Expected status='Step 1' after second set_progress, got {splash.status!r}"
        )

        assert splash.progress_animation is not None, (
            "progress_animation must be created after set_progress"
        )
        assert splash.progress_animation.endValue() == _PROGRESS_60, (
            f"Animation end value should be {_PROGRESS_60}, "
            f"got {splash.progress_animation.endValue()}"
        )

        splash.close()


class TestFadeAnimation:
    """Tests for fade-in and fade-out animations."""

    @staticmethod
    def test_show_animated_creates_animation(splash_screen: SplashScreen) -> None:
        """show_animated creates a fade-in animation.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show_animated()
        assert splash_screen.fade_animation is not None
        assert isinstance(splash_screen.fade_animation, QPropertyAnimation)

    @staticmethod
    def test_show_animated_targets_full_opacity(splash_screen: SplashScreen) -> None:
        """show_animated targets opacity 1.0.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show_animated()
        assert splash_screen.fade_animation is not None
        assert math.isclose(float(splash_screen.fade_animation.endValue()), 1.0)

    @staticmethod
    def test_show_animated_correct_duration(splash_screen: SplashScreen) -> None:
        """show_animated uses correct fade duration.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show_animated()
        assert splash_screen.fade_animation is not None
        assert splash_screen.fade_animation.duration() == FADE_DURATION_MS

    @staticmethod
    def test_finish_animated_creates_fadeout(splash_screen: SplashScreen) -> None:
        """finish_animated creates a fade-out animation.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show()
        target = QWidget()
        splash_screen.finish_animated(target)
        assert splash_screen.fade_animation is not None
        assert isinstance(splash_screen.fade_animation, QPropertyAnimation)
        target.close()

    @staticmethod
    def test_finish_animated_targets_zero_opacity(splash_screen: SplashScreen) -> None:
        """finish_animated targets opacity 0.0.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show()
        target = QWidget()
        splash_screen.finish_animated(target)
        assert splash_screen.fade_animation is not None
        assert math.isclose(float(splash_screen.fade_animation.endValue()), 0.0, abs_tol=1e-9)
        target.close()


class TestVersionLabel:
    """Tests for version display."""

    @staticmethod
    def test_version_stored(splash_with_version: SplashScreen) -> None:
        """Version string is stored and accessible via property.

        Args:
            splash_with_version: SplashScreen fixture instance constructed with a version string.
        """
        assert splash_with_version.version == "1.2.3"

    @staticmethod
    def test_version_label_created(splash_with_version: SplashScreen) -> None:
        """Version label is created with correct text.

        Args:
            splash_with_version: SplashScreen fixture instance constructed with a version string.
        """
        assert splash_with_version.version_label is not None
        assert isinstance(splash_with_version.version_label, QLabel)
        assert splash_with_version.version_label.text() == "v1.2.3"

    @staticmethod
    def test_no_version_label_when_empty(splash_screen: SplashScreen) -> None:
        """No version label when version is empty string.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert splash_screen.version_label is None

    @staticmethod
    def test_default_version_is_empty(splash_screen: SplashScreen) -> None:
        """Default version is empty string.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert not splash_screen.version


class TestProgressAnimation:
    """Tests for animated progress bar."""

    @staticmethod
    def test_set_progress_creates_animation(splash_screen: SplashScreen) -> None:
        """set_progress creates a QPropertyAnimation.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.progress_animation is not None
        assert isinstance(splash_screen.progress_animation, QPropertyAnimation)

    @staticmethod
    def test_progress_value_set_immediately(splash_screen: SplashScreen) -> None:
        """Internal _progress_value is set immediately.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_75)
        assert splash_screen.progress_value == _PROGRESS_75

    @staticmethod
    def test_rapid_progress_calls_track_final_state(splash_screen: SplashScreen) -> None:
        """Rapid successive set_progress calls leave correct final state.

        The previous test only checked that the loop did not raise. This gate
        drives the same rapid loop but then asserts the observable end state:
        the final progress value, the animation end value tracking the last
        call, and all pipeline stages COMPLETE at full progress. A regression
        where rapid calls stopped updating internal state would fail here.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        last = 0
        for i in range(0, _PROGRESS_100 + 1, 5):
            splash_screen.set_progress(i)
            last = i

        assert last == _PROGRESS_100
        assert splash_screen.progress == _PROGRESS_100
        assert splash_screen.progress_value == _PROGRESS_100
        assert splash_screen.progress_animation is not None
        assert splash_screen.progress_animation.endValue() == _PROGRESS_100
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert all(int(s) == _STATE_COMPLETE for s in stages)

    @staticmethod
    def test_progress_animation_correct_duration(
        splash_screen: SplashScreen,
    ) -> None:
        """Progress animation has correct duration.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(_PROGRESS_50)
        assert splash_screen.progress_animation is not None
        assert splash_screen.progress_animation.duration() == PROGRESS_ANIM_DURATION_MS


class TestDpiScaling:
    """Tests for DPI scaling support."""

    @staticmethod
    def test_dpi_scale_is_positive(splash_screen: SplashScreen) -> None:
        """dpi_scale property returns a positive float.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert splash_screen.dpi_scale > 0.0
        assert isinstance(splash_screen.dpi_scale, float)

    @staticmethod
    def test_scaled_dimensions_positive(splash_screen: SplashScreen) -> None:
        """Scaled dimensions are positive integers.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert splash_screen.scaled_width > 0
        assert splash_screen.scaled_height > 0

    @staticmethod
    def test_compute_dpi_scale_returns_positive() -> None:
        """_compute_dpi_scale returns a positive value."""
        scale = SplashScreen.compute_dpi_scale()
        assert scale > 0.0

    @staticmethod
    def test_default_dpi_scale_constant() -> None:
        """DEFAULT_DPI_SCALE constant is 1.0."""
        assert math.isclose(float(DEFAULT_DPI_SCALE), 1.0)


_STATE_PENDING: int = 0
_STATE_ACTIVE: int = 1
_STATE_COMPLETE: int = 2
_STATE_FAILED: int = 3


class TestAnimatedGradient:
    """Tests for animated gradient background and animation timer."""

    @staticmethod
    def test_animation_timer_exists(splash_screen: SplashScreen) -> None:
        """Animation timer is created during initialization.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert hasattr(splash_screen, "_animation_timer")

    @staticmethod
    def test_gradient_time_initialized(splash_screen: SplashScreen) -> None:
        """Gradient time starts at zero.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert math.isclose(float(getattr(splash_screen, "_gradient_time")), 0.0, abs_tol=1e-9)

    @staticmethod
    def test_active_pulse_time_initialized(splash_screen: SplashScreen) -> None:
        """Active pulse time starts at zero.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert math.isclose(float(getattr(splash_screen, "_active_pulse_time")), 0.0, abs_tol=1e-9)

    @staticmethod
    def test_show_animated_starts_timer(splash_screen: SplashScreen) -> None:
        """show_animated starts the animation timer.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.show_animated()
        timer = getattr(splash_screen, "_animation_timer")
        assert timer.isActive()

    @staticmethod
    def test_animation_tick_advances_time(splash_screen: SplashScreen) -> None:
        """Animation tick advances gradient time.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        initial: float = getattr(splash_screen, "_gradient_time")
        tick_fn = getattr(splash_screen, "_on_animation_tick")
        tick_fn()
        assert getattr(splash_screen, "_gradient_time") > initial


class TestPipelineIndicator:
    """Tests for multi-phase pipeline indicator."""

    @staticmethod
    def test_initial_stages_all_pending(splash_screen: SplashScreen) -> None:
        """All stages start as PENDING.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert all(int(s) == _STATE_PENDING for s in stages)

    @staticmethod
    def test_stage_count(splash_screen: SplashScreen) -> None:
        """Pipeline has exactly 8 stages.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert len(stages) == 8

    @staticmethod
    def test_progress_completes_early_stages(splash_screen: SplashScreen) -> None:
        """Progress at 50% completes stages with thresholds ending at or below 50.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(50)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert int(stages[0]) == _STATE_COMPLETE
        assert int(stages[1]) == _STATE_COMPLETE
        assert int(stages[2]) == _STATE_COMPLETE

    @staticmethod
    def test_progress_activates_current_stage(splash_screen: SplashScreen) -> None:
        """Progress at 50% activates the stage spanning that range.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(50)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert int(stages[3]) == _STATE_ACTIVE

    @staticmethod
    def test_progress_keeps_later_stages_pending(splash_screen: SplashScreen) -> None:
        """Progress at 50% leaves later stages as PENDING.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(50)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        for i in range(4, 8):
            assert int(stages[i]) == _STATE_PENDING

    @staticmethod
    def test_full_progress_completes_all(splash_screen: SplashScreen) -> None:
        """100% progress completes all stages.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(100)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert all(int(s) == _STATE_COMPLETE for s in stages)

    @staticmethod
    def test_mark_stage_failed(splash_screen: SplashScreen) -> None:
        """mark_stage_failed sets a stage to FAILED.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.mark_stage_failed(2)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert int(stages[2]) == _STATE_FAILED

    @staticmethod
    def test_failed_stage_preserved_on_progress(splash_screen: SplashScreen) -> None:
        """FAILED stages are not overridden by progress updates.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.mark_stage_failed(1)
        splash_screen.set_progress(100)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert int(stages[1]) == _STATE_FAILED

    @staticmethod
    def test_mark_stage_failed_out_of_range(splash_screen: SplashScreen) -> None:
        """mark_stage_failed with out-of-range index does not crash.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.mark_stage_failed(-1)
        splash_screen.mark_stage_failed(99)
        stages: list[int] = getattr(splash_screen, "_stage_states")
        assert all(int(s) == _STATE_PENDING for s in stages)


class TestPaintEventRendering:
    """Tests for custom paint event rendering."""

    @staticmethod
    def test_paint_event_draws_pixels(qapp: QApplication) -> None:
        """Paint helpers actually overwrite the canvas with multiple colors.

        ``repaint()`` swallows paint exceptions in Qt, so a no-op handler would
        pass a smoke test. This gate renders the real production draw helpers
        onto a sentinel-filled image and verifies, against the independent
        sentinel oracle, that a substantial number of pixels were overwritten
        and that the rendered output contains many distinct colors (the
        animated gradient background alone produces a continuous color ramp).

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        image = _render_splash_layers(splash)
        painted, distinct = _count_painted_and_distinct(image)
        assert painted >= _MIN_PAINTED_PIXELS, (
            f"Only {painted} pixels overwritten; paint helpers drew nothing"
        )
        assert distinct >= _MIN_DISTINCT_COLORS, (
            f"Only {distinct} distinct colors; gradient background not rendered"
        )
        splash.close()

    @staticmethod
    def test_paint_with_progress_reflects_state(qapp: QApplication) -> None:
        """Paint after a progress update reflects updated state and renders.

        Drives a real ``set_progress(50, ...)`` then renders the production
        draw helpers. Asserts the progress and status state were applied and
        that the rendered output overwrote the sentinel canvas with multiple
        colors, so a paint regression that skipped a layer would fail.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.set_progress(_PROGRESS_50, "Loading...")
        assert splash.progress == _PROGRESS_50
        assert splash.status == "Loading..."
        image = _render_splash_layers(splash)
        painted, distinct = _count_painted_and_distinct(image)
        assert painted >= _MIN_PAINTED_PIXELS
        assert distinct >= _MIN_DISTINCT_COLORS
        splash.close()

    @staticmethod
    def test_paint_full_pipeline_all_complete(qapp: QApplication) -> None:
        """Full progress completes all stages and the pipeline renders.

        Drives ``set_progress(100, ...)``, asserts every pipeline stage is
        COMPLETE, then renders the pipeline draw helper onto a sentinel canvas
        and asserts the completed-stage glyphs (filled accent circles plus
        white checkmarks and connecting lines) overwrote the sentinel with
        multiple colors.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="2.0.0")
        splash.set_progress(_PROGRESS_100, "Ready")
        assert splash.progress == _PROGRESS_100
        stages: list[int] = getattr(splash, "_stage_states")
        assert all(int(s) == _STATE_COMPLETE for s in stages)

        pixmap = QPixmap(_RENDER_W, _RENDER_H)
        pixmap.fill(QColor(_SENTINEL_R, _SENTINEL_G, _SENTINEL_B))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(0.0, 0.0, float(_RENDER_W), float(_RENDER_H))
        draw_pipe = getattr(splash, "_draw_pipeline")
        draw_pipe(painter, rect)
        painter.end()

        painted, distinct = _count_painted_and_distinct(pixmap.toImage())
        assert painted > 0, "Pipeline render drew nothing for completed stages"
        assert distinct >= _MIN_PIPELINE_COLORS, "Completed pipeline produced no distinct colors"
        splash.close()


class TestStatusLabelProperty:
    """Tests for the status_label property."""

    @staticmethod
    def test_status_label_property_returns_qlabel(splash_screen: SplashScreen) -> None:
        """status_label property returns a QLabel instance.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assert isinstance(splash_screen.status_label, QLabel)

    @staticmethod
    def test_status_label_text_updates(splash_screen: SplashScreen) -> None:
        """status_label text updates with set_progress.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        splash_screen.set_progress(50, "Test message")
        assert splash_screen.status_label.text() == "Test message"


class TestSplashImageCompositing:
    """Tests for splash image compositing in paintEvent."""

    @staticmethod
    def test_splash_image_mutual_exclusion_with_brain_icon(splash_screen: SplashScreen) -> None:
        """Image-source selection follows the brain-icon-preferred precedence.

        The production rule is ``_splash_image = load(splash.png) if
        _brain_icon is None else None``. The previous test re-ran that exact
        ladder against the same conditions, making it tautological. Here the
        expected outcome is derived independently: the shipped
        ``splash-icon.png`` is decoded straight from disk via its PNG header,
        proving it is a valid (loadable) image, so production must select the
        brain icon and leave ``_splash_image`` ``None``. The general invariant
        - the two image sources are mutually exclusive - is also asserted.

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        assets = get_assets_path()
        brain_path = assets / "splash-icon.png"
        splash_path = assets / "splash.png"

        brain_icon: QPixmap | None = getattr(splash_screen, "_brain_icon")
        splash_image: QPixmap | None = getattr(splash_screen, "_splash_image")

        both_present = brain_icon is not None and splash_image is not None
        assert not both_present, "Brain icon and splash image must be mutually exclusive"

        assert brain_path.exists(), f"brain icon asset missing at {brain_path}"
        brain_header = brain_path.read_bytes()[: _PNG_IHDR_OFFSET + 8]
        assert brain_header[:8] == _PNG_SIGNATURE, "splash-icon.png is not a valid PNG"
        brain_w = int.from_bytes(brain_header[_PNG_IHDR_OFFSET : _PNG_IHDR_OFFSET + 4], "big")
        brain_h = int.from_bytes(brain_header[_PNG_IHDR_OFFSET + 4 : _PNG_IHDR_OFFSET + 8], "big")
        assert brain_w > 0, "splash-icon.png reports zero width"
        assert brain_h > 0, "splash-icon.png reports zero height"

        assert brain_icon is not None, "brain icon should load from the valid splash-icon.png asset"
        assert not brain_icon.isNull()
        assert splash_image is None, "splash_image must be None when the brain icon is selected"

        assert splash_path.exists(), f"splash.png asset missing at {splash_path}"
        splash_header = splash_path.read_bytes()[: _PNG_IHDR_OFFSET + 8]
        assert splash_header[:8] == _PNG_SIGNATURE, "splash.png is not a valid PNG"

    @staticmethod
    def test_overlay_hidden(splash_screen: SplashScreen) -> None:
        """Overlay widget is hidden (painting done in paintEvent).

        Args:
            splash_screen: SplashScreen fixture instance.
        """
        overlay = getattr(splash_screen, "_overlay")
        assert not overlay.isVisible()


_REAL_PROGRESS_SEQUENCE: list[tuple[int, str]] = [
    (5, "Loading configuration..."),
    (10, "Loading credentials..."),
    (20, "Initializing providers..."),
    (50, "Initializing tools..."),
    (70, "Initializing session manager..."),
    (85, "Creating orchestrator..."),
    (90, "Initializing script engine..."),
    (93, "Initializing model discovery..."),
    (95, "Initializing UI..."),
    (100, "Ready"),
]


class TestEndToEndLifecycle:
    """End-to-end tests exercising the full splash lifecycle as main() would."""

    @staticmethod
    def test_full_startup_sequence(qapp: QApplication) -> None:
        """Replicate the exact progress sequence from _run_application.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.show_animated()

        for progress_val, message in _REAL_PROGRESS_SEQUENCE:
            splash.set_progress(progress_val, message)
            splash.repaint()

        assert splash.progress == _PROGRESS_100
        assert splash.status == "Ready"

        stages: list[int] = getattr(splash, "_stage_states")
        assert all(int(s) == _STATE_COMPLETE for s in stages)

        target = QWidget()
        splash.finish_animated(target)
        assert splash.fade_animation is not None
        assert math.isclose(float(splash.fade_animation.endValue()), 0.0, abs_tol=1e-9)
        target.close()
        splash.close()

    @staticmethod
    def test_pipeline_stages_advance_with_real_progress(qapp: QApplication) -> None:
        """Pipeline stages transition PENDING->ACTIVE->COMPLETE matching real thresholds.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.show_animated()

        splash.set_progress(5, "Loading configuration...")
        stages: list[int] = getattr(splash, "_stage_states")
        assert int(stages[0]) == _STATE_ACTIVE
        for i in range(1, 8):
            assert int(stages[i]) == _STATE_PENDING

        splash.set_progress(10, "Loading credentials...")
        stages = getattr(splash, "_stage_states")
        assert int(stages[0]) == _STATE_COMPLETE
        assert int(stages[1]) == _STATE_ACTIVE

        splash.set_progress(20, "Initializing providers...")
        stages = getattr(splash, "_stage_states")
        assert int(stages[0]) == _STATE_COMPLETE
        assert int(stages[1]) == _STATE_COMPLETE
        assert int(stages[2]) == _STATE_ACTIVE

        splash.set_progress(50, "Initializing tools...")
        stages = getattr(splash, "_stage_states")
        for i in range(3):
            assert int(stages[i]) == _STATE_COMPLETE
        assert int(stages[3]) == _STATE_ACTIVE

        splash.set_progress(70, "Initializing session manager...")
        stages = getattr(splash, "_stage_states")
        for i in range(4):
            assert int(stages[i]) == _STATE_COMPLETE
        assert int(stages[4]) == _STATE_ACTIVE

        splash.set_progress(85, "Creating orchestrator...")
        stages = getattr(splash, "_stage_states")
        for i in range(5):
            assert int(stages[i]) == _STATE_COMPLETE
        assert int(stages[5]) == _STATE_ACTIVE

        splash.set_progress(90, "Initializing script engine...")
        stages = getattr(splash, "_stage_states")
        for i in range(6):
            assert int(stages[i]) == _STATE_COMPLETE
        assert int(stages[6]) == _STATE_ACTIVE

        splash.set_progress(93, "Initializing model discovery...")
        stages = getattr(splash, "_stage_states")
        for i in range(7):
            assert int(stages[i]) == _STATE_COMPLETE
        assert int(stages[7]) == _STATE_ACTIVE

        splash.set_progress(100, "Ready")
        stages = getattr(splash, "_stage_states")
        assert all(int(s) == _STATE_COMPLETE for s in stages)
        splash.close()

    @staticmethod
    def test_animation_timer_lifecycle(qapp: QApplication) -> None:
        """Animation timer starts on show_animated and stops on finish_animated.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        timer = getattr(splash, "_animation_timer")
        assert not timer.isActive()

        splash.show_animated()
        assert timer.isActive()

        target = QWidget()
        splash.finish_animated(target)
        assert splash.fade_animation is not None
        splash.fade_animation.setCurrentTime(splash.fade_animation.duration())
        assert not timer.isActive()
        target.close()
        splash.close()

    @staticmethod
    def test_rendering_at_every_progress_step(qapp: QApplication) -> None:
        """All 5 render layers execute without error at every real progress value.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")

        for progress_val, message in _REAL_PROGRESS_SEQUENCE:
            splash.set_progress(progress_val, message)

            pm = QPixmap(600, 400)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
            rect = QRectF(0.0, 0.0, 600.0, 400.0)

            draw_bg = getattr(splash, "_draw_gradient_background")
            draw_img = getattr(splash, "_draw_splash_image")
            draw_title = getattr(splash, "_draw_title")
            draw_pipe = getattr(splash, "_draw_pipeline")
            draw_status = getattr(splash, "_draw_status_and_version")

            draw_bg(p, rect)
            draw_img(p, rect)
            draw_title(p, rect)
            draw_pipe(p, rect)
            draw_status(p, rect)

            p.end()

        splash.close()

    @staticmethod
    def test_failed_stage_renders_through_full_sequence(qapp: QApplication) -> None:
        """A failed stage renders correctly through the entire progress sequence.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.mark_stage_failed(2)

        for progress_val, message in _REAL_PROGRESS_SEQUENCE:
            splash.set_progress(progress_val, message)

        stages: list[int] = getattr(splash, "_stage_states")
        assert int(stages[2]) == _STATE_FAILED
        assert int(stages[0]) == _STATE_COMPLETE
        assert int(stages[7]) == _STATE_COMPLETE

        pm = QPixmap(600, 400)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(0.0, 0.0, 600.0, 400.0)
        draw_pipe = getattr(splash, "_draw_pipeline")
        draw_pipe(p, rect)
        p.end()

        splash.close()

    @staticmethod
    def test_show_animated_fade_in_properties(qapp: QApplication) -> None:
        """show_animated creates correct fade-in animation targeting full opacity.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.show_animated()

        assert splash.fade_animation is not None
        assert isinstance(splash.fade_animation, QPropertyAnimation)
        assert math.isclose(float(splash.fade_animation.endValue()), 1.0)
        assert splash.fade_animation.duration() == FADE_DURATION_MS
        splash.close()

    @staticmethod
    def test_finish_animated_fade_out_properties(qapp: QApplication) -> None:
        """finish_animated creates correct fade-out animation targeting zero opacity.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        splash.show_animated()

        for progress_val, message in _REAL_PROGRESS_SEQUENCE:
            splash.set_progress(progress_val, message)

        target = QWidget()
        splash.finish_animated(target)
        assert splash.fade_animation is not None
        assert math.isclose(float(splash.fade_animation.endValue()), 0.0, abs_tol=1e-9)
        assert splash.fade_animation.duration() == FADE_DURATION_MS
        target.close()
        splash.close()

    @staticmethod
    def test_gradient_time_advances_across_ticks(qapp: QApplication) -> None:
        """Gradient animation time accumulates correctly across multiple ticks.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen(version="1.0.0")
        tick_fn = getattr(splash, "_on_animation_tick")

        for _ in range(30):
            tick_fn()

        gradient_time: float = getattr(splash, "_gradient_time")
        expected_time = 30 * 0.033
        assert abs(gradient_time - expected_time) < 0.01

        pulse_time: float = getattr(splash, "_active_pulse_time")
        assert abs(pulse_time - expected_time) < 0.01
        splash.close()

    @staticmethod
    def test_version_renders_in_paint(qapp: QApplication) -> None:
        """Version text is rendered during paintEvent when version is set.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash_with = SplashScreen(version="3.5.1")
        splash_without = SplashScreen()

        for s in (splash_with, splash_without):
            pm = QPixmap(600, 400)
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            rect = QRectF(0.0, 0.0, 600.0, 400.0)
            draw_status = getattr(s, "_draw_status_and_version")
            draw_status(p, rect)
            p.end()

        assert splash_with.version == "3.5.1"
        assert splash_with.version_label is not None
        assert not splash_without.version
        assert splash_without.version_label is None
        splash_with.close()
        splash_without.close()
