# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Splash screen for Intellicrack application startup.

Provides a custom splash screen with progress indication and status
messages during application initialization.
"""

from __future__ import annotations

from typing import Final, final, override

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPixmap, QResizeEvent
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QProgressBar,
    QSplashScreen,
    QVBoxLayout,
    QWidget,
)

from ...core.logging import get_logger
from ..resources import get_assets_path


_logger = get_logger("ui.dialogs.splash_screen")


SPLASH_WIDTH: Final[int] = 600
SPLASH_HEIGHT: Final[int] = 400
FALLBACK_BG_COLOR: Final[str] = "#1e1e1e"
FALLBACK_TEXT_COLOR: Final[str] = "#d4d4d4"
FALLBACK_ACCENT_COLOR: Final[str] = "#007acc"
FADE_DURATION_MS: Final[int] = 300
PROGRESS_ANIM_DURATION_MS: Final[int] = 200
DEFAULT_DPI_SCALE: Final[float] = 1.0

_PROGRESS_BAR_BASE_HEIGHT: Final[int] = 6
_OVERLAY_MARGIN_H: Final[int] = 20
_OVERLAY_MARGIN_BOTTOM: Final[int] = 30
_OVERLAY_SPACING: Final[int] = 8
_STATUS_FONT_SIZE: Final[int] = 11
_TITLE_FONT_SIZE: Final[int] = 32
_SUBTITLE_FONT_SIZE: Final[int] = 12
_VERSION_FONT_SIZE: Final[int] = 10
_VERSION_LABEL_COLOR: Final[str] = "rgba(212, 212, 212, 0.6)"
_PROGRESS_BAR_BG_COLOR: Final[str] = "#3e3e42"
_SUBTITLE_COLOR: Final[str] = "#888888"


@final
class SplashScreen(QSplashScreen):
    """Custom splash screen with progress bar and status messages.

    Displays the Intellicrack splash image during application startup
    with real-time progress updates and status messages.

    Args:
        version: Application version string to display.
    """

    progress_updated = pyqtSignal(int, str)

    def __init__(self, version: str = "") -> None:
        """Initialize the splash screen.

        Args:
            version: Application version string to display.
        """
        dpi_scale = SplashScreen._compute_dpi_scale()
        scaled_w = int(SPLASH_WIDTH * dpi_scale)
        scaled_h = int(SPLASH_HEIGHT * dpi_scale)

        pixmap = SplashScreen._load_splash_pixmap(scaled_w, scaled_h, dpi_scale)
        super().__init__(pixmap)

        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen)

        self._dpi_scale: float = dpi_scale
        self._scaled_width: int = scaled_w
        self._scaled_height: int = scaled_h
        self._version: str = version
        self._progress_value: int = 0
        self._status_message: str = "Initializing..."
        self._fade_animation: QPropertyAnimation | None = None
        self._progress_animation: QPropertyAnimation | None = None
        self._finish_target: QWidget | None = None

        self._setup_overlay()
        self.progress_updated.connect(self._on_progress_updated)

    @staticmethod
    def _compute_dpi_scale() -> float:
        """Compute DPI scale factor from the primary screen.

        Returns:
            DPI scale factor (defaults to 1.0 if unavailable).
        """
        app = QApplication.instance()
        if not isinstance(app, QApplication):
            return DEFAULT_DPI_SCALE
        screen = app.primaryScreen()
        if screen is None:
            return DEFAULT_DPI_SCALE
        return float(screen.devicePixelRatio())

    @staticmethod
    def _load_splash_pixmap(width: int, height: int, dpi_scale: float) -> QPixmap:
        """Load the splash screen image or create fallback.

        Args:
            width: Target pixmap width.
            height: Target pixmap height.
            dpi_scale: DPI scale factor.

        Returns:
            QPixmap for the splash screen.
        """
        try:
            splash_path = get_assets_path() / "splash.png"
            if splash_path.exists():
                pixmap = QPixmap(str(splash_path))
                if not pixmap.isNull():
                    scaled = pixmap.scaled(
                        width,
                        height,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    _logger.debug(
                        "splash_image_loaded",
                        extra={"path": str(splash_path)},
                    )
                    return scaled
        except FileNotFoundError:
            _logger.debug("splash_image_not_found_using_fallback", extra={})

        return SplashScreen._create_fallback_pixmap(width, height, dpi_scale)

    @staticmethod
    def _create_fallback_pixmap(width: int, height: int, dpi_scale: float) -> QPixmap:
        """Create a fallback splash screen pixmap.

        Args:
            width: Pixmap width.
            height: Pixmap height.
            dpi_scale: DPI scale factor for font sizing.

        Returns:
            QPixmap with generated splash screen.
        """
        pixmap = QPixmap(width, height)
        pixmap.fill(QColor(FALLBACK_BG_COLOR))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        title_font = QFont(
            "Segoe UI",
            int(_TITLE_FONT_SIZE * dpi_scale),
            QFont.Weight.Bold,
        )
        painter.setFont(title_font)
        painter.setPen(QColor(FALLBACK_TEXT_COLOR))

        title_rect = pixmap.rect()
        title_rect.setBottom(title_rect.center().y())
        painter.drawText(
            title_rect,
            Qt.AlignmentFlag.AlignCenter,
            "INTELLICRACK",
        )

        subtitle_font = QFont("Segoe UI", int(_SUBTITLE_FONT_SIZE * dpi_scale))
        painter.setFont(subtitle_font)
        painter.setPen(QColor(_SUBTITLE_COLOR))

        subtitle_rect = pixmap.rect()
        subtitle_rect.setTop(title_rect.center().y() + int(20 * dpi_scale))
        subtitle_rect.setBottom(subtitle_rect.top() + int(40 * dpi_scale))
        painter.drawText(
            subtitle_rect,
            Qt.AlignmentFlag.AlignCenter,
            "Advanced Binary Analysis Platform",
        )

        accent_rect = pixmap.rect()
        accent_rect.setTop(accent_rect.bottom() - int(4 * dpi_scale))
        painter.fillRect(accent_rect, QColor(FALLBACK_ACCENT_COLOR))

        painter.end()
        return pixmap

    def _setup_overlay(self) -> None:
        """Set up the progress bar and status label overlay."""
        self._overlay = QWidget(self)
        self._overlay.setStyleSheet("background: transparent;")

        margin_h = int(_OVERLAY_MARGIN_H * self._dpi_scale)
        margin_b = int(_OVERLAY_MARGIN_BOTTOM * self._dpi_scale)
        spacing = int(_OVERLAY_SPACING * self._dpi_scale)

        layout = QVBoxLayout(self._overlay)
        layout.setContentsMargins(margin_h, 0, margin_h, margin_b)
        layout.setSpacing(spacing)

        layout.addStretch()

        status_font_size = int(_STATUS_FONT_SIZE * self._dpi_scale)
        self._status_label = QLabel("Initializing...")
        self._status_label.setStyleSheet(f"color: {FALLBACK_TEXT_COLOR}; font-size: {status_font_size}px; background: transparent;")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        bar_height = int(_PROGRESS_BAR_BASE_HEIGHT * self._dpi_scale)
        border_radius = max(1, bar_height // 2)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(bar_height)
        self._progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                background-color: {_PROGRESS_BAR_BG_COLOR};
                border: none;
                border-radius: {border_radius}px;
            }}
            QProgressBar::chunk {{
                background-color: {FALLBACK_ACCENT_COLOR};
                border-radius: {border_radius}px;
            }}
        """
        )
        layout.addWidget(self._progress_bar)

        self._version_label: QLabel | None = None
        if self._version:
            version_font_size = int(_VERSION_FONT_SIZE * self._dpi_scale)
            self._version_label = QLabel(f"v{self._version}")
            self._version_label.setStyleSheet(f"color: {_VERSION_LABEL_COLOR}; font-size: {version_font_size}px; background: transparent;")
            self._version_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            layout.addWidget(self._version_label)

        self._overlay.setGeometry(0, 0, self._scaled_width, self._scaled_height)

    def show_animated(self) -> None:
        """Show the splash screen with a fade-in animation."""
        self.setWindowOpacity(0.0)
        self.show()

        self._fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self._fade_animation.setDuration(FADE_DURATION_MS)
        self._fade_animation.setStartValue(0.0)
        self._fade_animation.setEndValue(1.0)
        self._fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._fade_animation.start()

    def finish_animated(self, window: QWidget) -> None:
        """Finish the splash screen with a fade-out animation.

        Args:
            window: Main window to show after fade-out completes.
        """
        self._finish_target = window

        self._fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self._fade_animation.setDuration(FADE_DURATION_MS)
        self._fade_animation.setStartValue(self.windowOpacity())
        self._fade_animation.setEndValue(0.0)
        self._fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._fade_animation.finished.connect(self._on_fade_out_finished)
        self._fade_animation.start()

    def _on_fade_out_finished(self) -> None:
        """Handle fade-out animation completion."""
        if self._finish_target is not None:
            self._finish_target.show()
        self.close()

    def set_progress(self, value: int, message: str = "") -> None:
        """Update the progress bar and status message.

        Args:
            value: Progress value (0-100).
            message: Status message to display.
        """
        self._progress_value = max(0, min(100, value))
        if message:
            self._status_message = message

        if self._progress_animation is not None:
            self._progress_animation.stop()

        self._progress_animation = QPropertyAnimation(self._progress_bar, b"value")
        self._progress_animation.setDuration(PROGRESS_ANIM_DURATION_MS)
        self._progress_animation.setStartValue(self._progress_bar.value())
        self._progress_animation.setEndValue(self._progress_value)
        self._progress_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._progress_animation.start()

        self._status_label.setText(self._status_message)

        self.showMessage(
            self._status_message,
            Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignHCenter,
            QColor(FALLBACK_TEXT_COLOR),
        )

        app = QApplication.instance()
        if app is not None:
            app.processEvents()

    def _on_progress_updated(self, value: int, message: str) -> None:
        """Handle progress update signal.

        Args:
            value: Progress value.
            message: Status message.
        """
        self.set_progress(value, message)

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Handle resize events to adjust overlay.

        Args:
            a0: Resize event from Qt.
        """
        super().resizeEvent(a0)
        if hasattr(self, "_overlay"):
            self._overlay.setGeometry(0, 0, self.width(), self.height())

    @property
    def progress(self) -> int:
        """Get current progress value.

        Returns:
            Current progress (0-100).
        """
        return self._progress_value

    @property
    def status(self) -> str:
        """Get current status message.

        Returns:
            Current status message.
        """
        return self._status_message

    @property
    def dpi_scale(self) -> float:
        """Get the DPI scale factor.

        Returns:
            DPI scale factor used for this splash screen.
        """
        return self._dpi_scale

    @property
    def version(self) -> str:
        """Get the version string.

        Returns:
            Version string displayed on the splash screen.
        """
        return self._version
