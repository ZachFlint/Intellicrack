# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for SplashScreen defects D45 and D46.

D45: the progress-bar overlay stayed permanently hidden while ``set_progress``
animated its value, so the user never saw the animated progress bar. D46:
``showMessage`` calls made directly (not through ``set_progress``) never
reached the screen because the custom ``paintEvent`` painted only the
splash artwork and never the stored message text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QRectF
from PyQt6.QtGui import QColor, QImage, QPainter, QPixmap

from intellicrack.ui.dialogs.splash_screen import SplashScreen


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_PROGRESS_TARGET: int = 50
_RENDER_W: int = 600
_RENDER_H: int = 400
_SENTINEL_R: int = 17
_SENTINEL_G: int = 71
_SENTINEL_B: int = 137
_DIRECT_MESSAGE: str = "LOADING XYZ DISTINCT DIAGNOSTIC STATUS TEXT"


def _render_status_layer(splash: SplashScreen) -> QImage:
    """Render only the status/version paint layer onto a sentinel-filled image.

    Isolates ``_draw_status_and_version`` -- the helper the real ``paintEvent``
    calls to paint ``self._status_message`` -- from the gradient/pipeline
    layers, so a pixel comparison reflects only status-text changes.

    Args:
        splash: The SplashScreen whose status/version draw helper is exercised.

    Returns:
        QImage: The rendered image after ``_draw_status_and_version`` has run.
    """
    pixmap = QPixmap(_RENDER_W, _RENDER_H)
    pixmap.fill(QColor(_SENTINEL_R, _SENTINEL_G, _SENTINEL_B))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    rect = QRectF(0.0, 0.0, float(_RENDER_W), float(_RENDER_H))
    splash._draw_status_and_version(painter, rect)
    painter.end()
    return pixmap.toImage()


def _count_non_background(image: QImage) -> int:
    """Count pixels in ``image`` that do not match the sentinel fill color.

    Args:
        image: The rendered image to inspect.

    Returns:
        int: Number of pixels that differ from the sentinel background.
    """
    sentinel = QColor(_SENTINEL_R, _SENTINEL_G, _SENTINEL_B).rgb()
    painted = 0
    for y in range(image.height()):
        for x in range(image.width()):
            if image.pixel(x, y) != sentinel:
                painted += 1
    return painted


class TestOverlayVisibleDuringProgress:
    """D45: the progress-bar overlay must become visible once progress starts."""

    @staticmethod
    def test_overlay_hidden_before_any_progress(qapp: QApplication) -> None:
        """The overlay stays hidden until the first progress update arrives.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        splash.show()
        assert not splash._overlay.isVisible()
        splash.close()

    @staticmethod
    def test_set_progress_reveals_overlay_and_advances_bar(qapp: QApplication) -> None:
        """set_progress reveals the overlay and moves the real progress bar.

        Before the D45 fix, ``_overlay`` was hidden in ``__init__`` and never
        re-shown, so the ``QProgressBar`` animated underneath it was never
        visible to the user. This asserts both halves of that observable
        behavior against the production ``set_progress`` call: the overlay
        becomes visible, and the actual ``QProgressBar`` widget value (forced
        to the end of its animation deterministically, matching the existing
        ``fade_animation.setCurrentTime`` convention in this test suite)
        reflects the new progress rather than staying at zero.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        splash.show()

        splash.set_progress(_PROGRESS_TARGET)

        assert splash._overlay.isVisible(), "overlay must be shown once progress is active (D45)"

        assert splash.progress_animation is not None
        splash.progress_animation.setCurrentTime(splash.progress_animation.duration())
        assert splash.progress_bar.value() == _PROGRESS_TARGET, (
            f"progress bar value did not advance: {splash.progress_bar.value()}"
        )
        splash.close()


class TestDirectShowMessageIsPainted:
    """D46: showMessage() text must reach the screen even called directly."""

    @staticmethod
    def test_direct_showmessage_updates_status_message(qapp: QApplication) -> None:
        """Calling showMessage directly updates the internally tracked status text.

        ``_draw_status_and_version`` (called from the real ``paintEvent``)
        paints ``self._status_message``, not Qt's own internal splash message
        state. Before the D46 fix, that attribute was only ever updated by
        ``set_progress``, so a bare ``showMessage()`` call -- the documented
        public API -- silently failed to affect what gets painted.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        splash = SplashScreen()
        assert splash._status_message == "Initializing..."

        splash.showMessage(_DIRECT_MESSAGE)

        assert splash._status_message == _DIRECT_MESSAGE, (
            "showMessage() must update the painted status text (D46)"
        )
        splash.close()

    @staticmethod
    def test_direct_showmessage_paints_new_text_on_screen(qapp: QApplication) -> None:
        """A message set via showMessage() alone is actually painted on screen.

        Renders the real status/version paint layer for a freshly constructed
        splash (default ``"Initializing..."`` message) and for one that had
        ``showMessage(_DIRECT_MESSAGE)`` called on it directly, with no other
        state differing between the two. Asserts the message region contains
        non-background pixels (the text was painted at all) and that the two
        renders differ (the *new* message reached the paint pipeline, not a
        stale default). Without the D46 fix, ``showMessage`` never updates
        ``self._status_message``, so both renders paint the identical
        ``"Initializing..."`` text and would be pixel-for-pixel equal,
        falsifying this gate.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        baseline_splash = SplashScreen()
        baseline_image = _render_status_layer(baseline_splash)

        direct_splash = SplashScreen()
        direct_splash.showMessage(_DIRECT_MESSAGE)
        direct_image = _render_status_layer(direct_splash)

        painted = _count_non_background(direct_image)
        assert painted > 0, "no non-background pixels painted in the message region"
        assert direct_image != baseline_image, (
            "showMessage() text was not reflected in the painted output (D46)"
        )

        baseline_splash.close()
        direct_splash.close()

    @staticmethod
    def test_direct_showmessage_reflected_in_full_widget_grab(qapp: QApplication) -> None:
        """A message set via showMessage() alone shows up in a full widget grab().

        Exercises the real, unmodified ``paintEvent`` end-to-end (via
        ``grab()``) rather than the isolated draw helper, so a regression that
        broke the wiring between ``paintEvent`` and the status text -- not just
        the helper itself -- is also caught.

        Args:
            qapp: QApplication fixture required by Qt widgets.
        """
        del qapp
        baseline_splash = SplashScreen()
        baseline_splash.show()
        baseline_grab = baseline_splash.grab().toImage()

        direct_splash = SplashScreen()
        direct_splash.show()
        direct_splash.showMessage(_DIRECT_MESSAGE)
        direct_grab = direct_splash.grab().toImage()

        assert direct_grab != baseline_grab, (
            "full-widget grab() did not change after a direct showMessage() call (D46)"
        )

        baseline_splash.close()
        direct_splash.close()
