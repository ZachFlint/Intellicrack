# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Layout gates for the SplashScreen progress overlay.

The splash paints an eight-stage pipeline, the status message and the version
string itself. The child overlay used to repeat the status and version as
labels and to place its progress bar on top of the pipeline circles. These
gates pin one owner per element at both 100% and 150% display scaling while
keeping the D45 guarantee that progress movement is visible during load.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QPoint, QRect
from PyQt6.QtGui import QColor

from intellicrack.ui.dialogs.splash_screen import (
    FALLBACK_ACCENT_COLOR,
    SPLASH_HEIGHT,
    SPLASH_WIDTH,
    SplashScreen,
)


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QApplication, QWidget


_DPI_SCALES: Final[tuple[float, ...]] = (1.0, 1.5)
_PIPELINE_Y_OFFSET_FROM_BOTTOM: Final[int] = 50
_PIPELINE_CIRCLE_DIAMETER: Final[int] = 20
_STATUS_Y_OFFSET_FROM_PIPELINE: Final[int] = 25
_STATUS_TEXT_HEIGHT: Final[int] = 20
_PROGRESS_BAR_TRACK_COLOR: Final[str] = "#3e3e42"
_VERSION: Final[str] = "9.8.7"
_STATUS_MESSAGE: Final[str] = "Initializing tools..."
_PROGRESS_TARGET: Final[int] = 40
_TRACK_SAMPLE_FRACTION: Final[float] = 0.9
_CHUNK_SAMPLE_FRACTION: Final[float] = 0.2


def _fixed_dpi_scale(scale: float) -> Callable[[], float]:
    """Build a replacement for ``SplashScreen._compute_dpi_scale``.

    Args:
        scale: The device pixel ratio the splash should be constructed with.

    Returns:
        Callable[[], float]: A zero-argument callable returning ``scale``.
    """

    def _scale() -> float:
        return scale

    return _scale


def _make_splash(monkeypatch: pytest.MonkeyPatch, scale: float) -> SplashScreen:
    """Construct a real SplashScreen as if the primary screen had ``scale`` DPR.

    Only the screen device pixel ratio input is substituted; the widget,
    pixmap, overlay and layout are all produced by the production code.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        scale: The device pixel ratio to construct the splash with.

    Returns:
        SplashScreen: A shown splash with progress already applied.
    """
    monkeypatch.setattr(SplashScreen, "_compute_dpi_scale", staticmethod(_fixed_dpi_scale(scale)))
    splash = SplashScreen(_VERSION)
    splash.show()
    splash.set_progress(_PROGRESS_TARGET, _STATUS_MESSAGE)
    assert splash.progress_animation is not None
    splash.progress_animation.setCurrentTime(splash.progress_animation.duration())
    layout = _overlay(splash).layout()
    assert layout is not None
    layout.activate()
    return splash


def _overlay(splash: SplashScreen) -> QWidget:
    """Return the widget hosting the progress bar.

    Args:
        splash: The splash screen under test.

    Returns:
        QWidget: The parent widget of the progress bar.
    """
    host = splash.progress_bar.parentWidget()
    assert host is not None
    return host


def _bar_rect(splash: SplashScreen) -> QRect:
    """Return the progress bar rectangle in splash coordinates.

    Args:
        splash: The splash screen under test.

    Returns:
        QRect: The bar geometry mapped into the splash widget's coordinates.
    """
    top_left = splash.progress_bar.mapTo(splash, QPoint(0, 0))
    return QRect(top_left, splash.progress_bar.size())


def _pipeline_band() -> tuple[int, int]:
    """Return the vertical band occupied by the painted pipeline circles.

    Returns:
        tuple[int, int]: ``(top, bottom)`` in logical pixels at a 400 px tall splash.
    """
    centre = SPLASH_HEIGHT - _PIPELINE_Y_OFFSET_FROM_BOTTOM
    radius = _PIPELINE_CIRCLE_DIAMETER // 2
    return centre - radius, centre + radius


def _status_band() -> tuple[int, int]:
    """Return the vertical band occupied by the painted status text.

    Returns:
        tuple[int, int]: ``(top, bottom)`` in logical pixels at a 400 px tall splash.
    """
    pipeline_centre = SPLASH_HEIGHT - _PIPELINE_Y_OFFSET_FROM_BOTTOM
    bottom = pipeline_centre - _STATUS_Y_OFFSET_FROM_PIPELINE
    return bottom - _STATUS_TEXT_HEIGHT, bottom


@pytest.mark.parametrize("scale", _DPI_SCALES)
class TestOverlayLayout:
    """The overlay must not repeat or overdraw anything the splash paints."""

    @staticmethod
    def test_logical_size_is_independent_of_scale(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """The widget is 600x400 logical pixels at every scale.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        splash = _make_splash(monkeypatch, scale)
        try:
            assert splash.dpi_scale == scale
            assert (splash.width(), splash.height()) == (SPLASH_WIDTH, SPLASH_HEIGHT)
        finally:
            splash.close()

    @staticmethod
    def test_overlay_fills_widget_before_and_after_show(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """The overlay geometry matches the logical widget rect, not the physical pixmap size.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        monkeypatch.setattr(SplashScreen, "_compute_dpi_scale", staticmethod(_fixed_dpi_scale(scale)))
        splash = SplashScreen(_VERSION)
        try:
            assert _overlay(splash).geometry() == splash.rect(), "overlay was sized in physical pixels before show"
            splash.show()
            splash.set_progress(_PROGRESS_TARGET, _STATUS_MESSAGE)
            assert _overlay(splash).geometry() == splash.rect()
        finally:
            splash.close()

    @staticmethod
    def test_progress_bar_clear_of_pipeline_row(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """The progress bar does not intersect the band of the painted pipeline circles.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        splash = _make_splash(monkeypatch, scale)
        try:
            bar = _bar_rect(splash)
            band_top, band_bottom = _pipeline_band()
            assert bar.height() > 0
            assert bar.bottom() < band_top or bar.top() > band_bottom, (
                f"progress bar y={bar.top()}..{bar.bottom()} intersects pipeline circles y={band_top}..{band_bottom}"
            )
        finally:
            splash.close()

    @staticmethod
    def test_progress_bar_clear_of_painted_status_text(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """The progress bar sits below the painted status text and inside the splash.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        splash = _make_splash(monkeypatch, scale)
        try:
            bar = _bar_rect(splash)
            _, status_bottom = _status_band()
            assert bar.top() >= status_bottom, f"progress bar top {bar.top()} overlaps status text ending at {status_bottom}"
            assert splash.rect().contains(bar), f"progress bar {bar} is clipped by the splash {splash.rect()}"
        finally:
            splash.close()

    @staticmethod
    def test_status_and_version_text_have_a_single_owner(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """The overlay labels stay as bindings but are not shown over the painted text.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        splash = _make_splash(monkeypatch, scale)
        try:
            assert splash.status_label.text() == _STATUS_MESSAGE
            assert not splash.status_label.isVisibleTo(splash), "status text is drawn by the overlay and by paintEvent"
            assert splash.version_label is not None
            assert splash.version_label.text() == f"v{_VERSION}"
            assert not splash.version_label.isVisibleTo(splash), "version text is drawn by the overlay and by paintEvent"
            assert splash.status == _STATUS_MESSAGE
            assert splash.version == _VERSION
        finally:
            splash.close()

    @staticmethod
    def test_progress_movement_is_rendered(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        scale: float,
    ) -> None:
        """D45: the filled portion of the bar is really present in the grabbed splash.

        Args:
            qapp: QApplication fixture required by Qt widgets.
            monkeypatch: Pytest monkeypatch fixture.
            scale: Device pixel ratio under test.
        """
        del qapp
        splash = _make_splash(monkeypatch, scale)
        try:
            assert _overlay(splash).isVisible()
            assert splash.progress_bar.isVisible()
            assert splash.progress_bar.value() == _PROGRESS_TARGET

            bar = _bar_rect(splash)
            grab = splash.grab()
            ratio = grab.devicePixelRatio()
            image = grab.toImage()
            y = int((bar.top() + bar.height() / 2.0) * ratio)
            chunk_x = int((bar.left() + bar.width() * _CHUNK_SAMPLE_FRACTION) * ratio)
            track_x = int((bar.left() + bar.width() * _TRACK_SAMPLE_FRACTION) * ratio)

            assert image.pixelColor(chunk_x, y) == QColor(FALLBACK_ACCENT_COLOR), "filled segment of the bar is not visible"
            assert image.pixelColor(track_x, y) == QColor(_PROGRESS_BAR_TRACK_COLOR), "unfilled track of the bar is not visible"
        finally:
            splash.close()
