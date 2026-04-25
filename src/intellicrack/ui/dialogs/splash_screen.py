# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Splash screen for Intellicrack application startup.

Provides a custom splash screen with animated gradient background, title glow effects, and a multi-phase pipeline loading indicator during
application initialization.
"""

from __future__ import annotations

import enum
import math
from typing import Final, final, override

from PyQt6.QtCore import QEasingCurve, QPropertyAnimation, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QPixmap,
    QResizeEvent,
)
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QProgressBar,
    QSplashScreen,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources import get_assets_path
from intellicrack.ui.resources.font_manager import FontManager


_logger = get_logger(__name__)

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

_ANIMATION_INTERVAL_MS: Final[int] = 33
_GRADIENT_ROTATION_SPEED: Final[float] = 12.0
_GRADIENT_HSV_COLORS: Final[list[tuple[float, float, float]]] = [
    (0.62, 0.6, 0.18),
    (0.78, 0.5, 0.16),
    (0.50, 0.5, 0.17),
]
_SPLASH_IMAGE_OPACITY: Final[float] = 0.85
_TITLE_TEXT: Final[str] = "INTELLICRACK"

_GLOW_LAYERS: Final[list[tuple[int, int]]] = [
    (80, 8),
    (50, 14),
    (30, 20),
    (15, 28),
]
_GLOW_ACCENT_COLOR: Final[str] = "#007acc"
_GLOW_DIRECTIONS: Final[int] = 8

_PIPELINE_CIRCLE_DIAMETER: Final[int] = 20
_PIPELINE_LABEL_FONT_SIZE: Final[int] = 7
_PIPELINE_MARGIN_H: Final[int] = 40
_PIPELINE_LINE_WIDTH: Final[int] = 2
_PIPELINE_CHECKMARK_PEN_WIDTH: Final[float] = 2.0
_STAGE_COUNT: Final[int] = 8
_STAGE_THRESHOLDS: Final[list[tuple[int, int]]] = [
    (5, 10),
    (10, 20),
    (20, 50),
    (50, 70),
    (70, 85),
    (85, 90),
    (90, 93),
    (93, 100),
]
_STAGE_LABELS: Final[list[str]] = [
    "Creds",
    "Providers",
    "Tools",
    "Session",
    "Engine",
    "Scripts",
    "Models",
    "UI",
]
_STAGE_PENDING_COLOR: Final[str] = "#555555"
_STAGE_ERROR_COLOR: Final[str] = "#cc3333"

_BRAIN_ICON_NAME: Final[str] = "splash-icon.png"
_BRAIN_DISPLAY_HEIGHT: Final[float] = 0.30
_BRAIN_Y_FRACTION: Final[float] = 0.24
_TITLE_Y_FRACTION: Final[float] = 0.50
_TITLE_HEIGHT_FACTOR: Final[int] = 60
_STATUS_Y_OFFSET_FROM_PIPELINE: Final[int] = 25
_STATUS_TEXT_HEIGHT: Final[int] = 20
_VERSION_MARGIN_BOTTOM: Final[int] = 8
_VERSION_MARGIN_RIGHT: Final[int] = 12
_VERSION_TEXT_HEIGHT: Final[int] = 15
_PIPELINE_Y_OFFSET_FROM_BOTTOM: Final[int] = 50
_PIPELINE_LABEL_GAP: Final[int] = 3
_PIPELINE_LABEL_HEIGHT: Final[int] = 12
_ACTIVE_PULSE_SPEED: Final[float] = 4.0
_ACTIVE_BASE_ALPHA: Final[int] = 128
_ACTIVE_RANGE_ALPHA: Final[int] = 127
_DOT_RADIUS_FACTOR: Final[float] = 0.25
_DOT_BASE_ALPHA: Final[int] = 180
_DOT_RANGE_ALPHA: Final[int] = 75
_CHECKMARK_SCALE: Final[float] = 0.4
_X_MARK_SCALE: Final[float] = 0.35
_PENDING_PEN_WIDTH: Final[float] = 1.5
_ACTIVE_PEN_WIDTH: Final[float] = 2.0
_VERSION_ALPHA: Final[int] = 153


class _StageState(enum.IntEnum):
    """Pipeline stage visual state."""

    PENDING = 0
    ACTIVE = 1
    COMPLETE = 2
    FAILED = 3


@final
class SplashScreen(QSplashScreen):
    """Custom splash screen with animated gradient, glow effects, and pipeline indicator.

    Displays the Intellicrack splash image during application startup
    with real-time progress updates, animated visual effects, and a
    multi-phase pipeline loading indicator.

    Attributes:
        progress_updated: Qt signal emitted on progress change with (value, message).
    """

    progress_updated = pyqtSignal(int, str)

    def __init__(self, version: str = "") -> None:
        """Initialize the SplashScreen with the given version string.

        Args:
            version: Application version string to display.
        """
        dpi_scale = SplashScreen._compute_dpi_scale()
        scaled_w = int(SPLASH_WIDTH * dpi_scale)
        scaled_h = int(SPLASH_HEIGHT * dpi_scale)

        transparent_pixmap = QPixmap(scaled_w, scaled_h)
        transparent_pixmap.fill(QColor(0, 0, 0, 0))
        super().__init__(transparent_pixmap)

        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen,
        )

        self._dpi_scale: float = dpi_scale
        self.scaled_width: int = scaled_w
        self.scaled_height: int = scaled_h
        self._version: str = version
        self.progress_value: int = 0
        self._status_message: str = "Initializing..."
        self.fade_animation: QPropertyAnimation | None = None
        self.progress_animation: QPropertyAnimation | None = None
        self._finish_target: QWidget | None = None

        self._brain_icon: QPixmap | None = self._load_brain_icon()
        self._splash_image: QPixmap | None = self._load_splash_image(scaled_w, scaled_h) if self._brain_icon is None else None

        self._gradient_time: float = 0.0
        self._active_pulse_time: float = 0.0
        self._animation_timer: QTimer = QTimer(self)
        self._animation_timer.setInterval(_ANIMATION_INTERVAL_MS)
        self._animation_timer.timeout.connect(self._on_animation_tick)

        self._stage_states: list[_StageState] = [_StageState.PENDING] * _STAGE_COUNT

        self._setup_overlay()
        self._overlay.setVisible(False)

        self.progress_updated.connect(self._on_progress_updated)

        _logger.info(
            "splash_screen_initialized",
            version=self._version,
            scaled_width=scaled_w,
            scaled_height=scaled_h,
            dpi_scale=dpi_scale,
        )

    @staticmethod
    def _load_splash_image(width: int, height: int) -> QPixmap | None:
        """Load the splash.png image for compositing in paintEvent.

        Args:
            width: Target width.
            height: Target height.

        Returns:
            QPixmap | None: Loaded and scaled splash image, or None if unavailable.
        """
        try:
            splash_path = get_assets_path() / "splash.png"
            if splash_path.exists():
                pixmap = QPixmap(str(splash_path))
                if not pixmap.isNull():
                    return pixmap.scaled(
                        width,
                        height,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
        except FileNotFoundError:
            _logger.warning("splash_image_not_found")
        return None

    @staticmethod
    def _compute_dpi_scale() -> float:
        """Compute DPI scale factor from the primary screen.

        Returns:
            float: DPI scale factor (defaults to 1.0 if unavailable).
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
            QPixmap: QPixmap for the splash screen.
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
                    _logger.debug("splash_image_loaded", path=str(splash_path))
                    return scaled
        except FileNotFoundError:
            _logger.warning("splash_image_not_found_using_fallback")
        return SplashScreen._create_fallback_pixmap(width, height, dpi_scale)

    @staticmethod
    def _create_fallback_pixmap(width: int, height: int, dpi_scale: float) -> QPixmap:
        """Create a fallback splash screen pixmap.

        Args:
            width: Pixmap width.
            height: Pixmap height.
            dpi_scale: DPI scale factor for font sizing.

        Returns:
            QPixmap: QPixmap with generated splash screen.
        """
        pixmap = QPixmap(width, height)
        pixmap.fill(QColor(FALLBACK_BG_COLOR))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        title_font = FontManager.get_instance().get_heading_font(int(_TITLE_FONT_SIZE * dpi_scale))
        painter.setFont(title_font)
        painter.setPen(QColor(FALLBACK_TEXT_COLOR))

        title_rect = pixmap.rect()
        title_rect.setBottom(title_rect.center().y())
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, "INTELLICRACK")

        subtitle_font = FontManager.get_instance().get_ui_font(int(_SUBTITLE_FONT_SIZE * dpi_scale))
        painter.setFont(subtitle_font)
        painter.setPen(QColor(_SUBTITLE_COLOR))

        subtitle_rect = pixmap.rect()
        subtitle_rect.setTop(title_rect.center().y() + int(20 * dpi_scale))
        subtitle_rect.setBottom(subtitle_rect.top() + int(40 * dpi_scale))
        painter.drawText(subtitle_rect, Qt.AlignmentFlag.AlignCenter, "Advanced Binary Analysis Platform")

        accent_rect = pixmap.rect()
        accent_rect.setTop(accent_rect.bottom() - int(4 * dpi_scale))
        painter.fillRect(accent_rect, QColor(FALLBACK_ACCENT_COLOR))

        painter.end()
        return pixmap

    @staticmethod
    def compute_dpi_scale() -> float:
        """Compute DPI scale factor from the primary screen.

        Returns:
            float: DPI scale factor (defaults to 1.0 if unavailable).
        """
        return SplashScreen._compute_dpi_scale()

    @staticmethod
    def load_splash_pixmap(width: int, height: int, dpi_scale: float) -> QPixmap:
        """Load the splash screen image or create fallback.

        Args:
            width: Target pixmap width.
            height: Target pixmap height.
            dpi_scale: DPI scale factor.

        Returns:
            QPixmap: QPixmap for the splash screen.
        """
        return SplashScreen._load_splash_pixmap(width, height, dpi_scale)

    @staticmethod
    def create_fallback_pixmap(width: int, height: int, dpi_scale: float) -> QPixmap:
        """Create a fallback splash screen pixmap.

        Args:
            width: Pixmap width.
            height: Pixmap height.
            dpi_scale: DPI scale factor for font sizing.

        Returns:
            QPixmap: QPixmap with generated splash screen.
        """
        return SplashScreen._create_fallback_pixmap(width, height, dpi_scale)

    def _setup_overlay(self) -> None:
        """Set up the progress bar and status label overlay widgets.

        These widgets are hidden but retained for backward compatibility with code that accesses them directly.
        """
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
        self._status_label.setStyleSheet(
            f"color: {FALLBACK_TEXT_COLOR}; font-size: {status_font_size}px; background: transparent;",
        )
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        bar_height = int(_PROGRESS_BAR_BASE_HEIGHT * self._dpi_scale)
        border_radius = max(1, bar_height // 2)
        self.progress_bar = QProgressBar()
        self._progress_bar = self.progress_bar
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(bar_height)
        self.progress_bar.setStyleSheet(
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
        """,
        )
        layout.addWidget(self.progress_bar)

        self.version_label: QLabel | None = None
        if self._version:
            version_font_size = int(_VERSION_FONT_SIZE * self._dpi_scale)
            self.version_label = QLabel(f"v{self._version}")
            self.version_label.setStyleSheet(
                f"color: {_VERSION_LABEL_COLOR}; font-size: {version_font_size}px; background: transparent;",
            )
            self.version_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            layout.addWidget(self.version_label)

        self._overlay.setGeometry(0, 0, self.scaled_width, self.scaled_height)

    def show_animated(self) -> None:
        """Show the splash screen with a fade-in animation and start visual effects."""
        self.setWindowOpacity(0.0)
        self.show()

        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(FADE_DURATION_MS)
        self.fade_animation.setStartValue(0.0)
        self.fade_animation.setEndValue(1.0)
        self.fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_animation.start()

        self._animation_timer.start()

    def finish_animated(self, window: QWidget) -> None:
        """Finish the splash screen with a fade-out animation.

        Args:
            window: Main window to show after fade-out completes.
        """
        self._finish_target = window

        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(FADE_DURATION_MS)
        self.fade_animation.setStartValue(self.windowOpacity())
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_animation.finished.connect(self._on_fade_out_finished)
        self.fade_animation.start()

    def _on_fade_out_finished(self) -> None:
        """Handle fade-out animation completion."""
        self._animation_timer.stop()
        if self._finish_target is not None:
            self._finish_target.show()
        self.close()

    def _on_animation_tick(self) -> None:
        """Advance animation state on each timer tick."""
        dt = _ANIMATION_INTERVAL_MS / 1000.0
        self._gradient_time += dt
        self._active_pulse_time += dt
        self.update()

    def _update_stage_states(self, progress: int) -> None:
        """Update pipeline stage states based on current progress value.

        Args:
            progress: Current progress value (0-100).
        """
        for i, (threshold_start, threshold_end) in enumerate(_STAGE_THRESHOLDS):
            if self._stage_states[i] == _StageState.FAILED:
                continue
            if threshold_end <= progress:
                self._stage_states[i] = _StageState.COMPLETE
            elif threshold_start <= progress < threshold_end:
                self._stage_states[i] = _StageState.ACTIVE
            else:
                self._stage_states[i] = _StageState.PENDING

    def mark_stage_failed(self, stage_index: int) -> None:
        """Mark a pipeline stage as failed.

        Args:
            stage_index: Index of the stage to mark (0-7).
        """
        if 0 <= stage_index < _STAGE_COUNT:
            self._stage_states[stage_index] = _StageState.FAILED

    def set_progress(self, value: int, message: str = "") -> None:
        """Update the progress bar and status message.

        Args:
            value: Progress value (0-100).
            message: Status message to display.
        """
        self.progress_value = max(0, min(100, value))
        if message:
            self._status_message = message

        self._update_stage_states(self.progress_value)

        if self.progress_animation is not None:
            self.progress_animation.stop()

        self.progress_animation = QPropertyAnimation(self.progress_bar, b"value")
        self.progress_animation.setDuration(PROGRESS_ANIM_DURATION_MS)
        self.progress_animation.setStartValue(self.progress_bar.value())
        self.progress_animation.setEndValue(self.progress_value)
        self.progress_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.progress_animation.start()

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
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Render all splash screen visual layers.

        Args:
            a0: Paint event from Qt.
        """
        del a0
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
            rect = QRectF(self.rect())
            if rect.width() <= 0 or rect.height() <= 0:
                return

            self._draw_gradient_background(painter, rect)
            if self._brain_icon is not None:
                self._draw_brain_icon(painter, rect)
                self._draw_title(painter, rect)
            elif self._splash_image is not None:
                self._draw_splash_image(painter, rect)
            else:
                self._draw_title(painter, rect)
            self._draw_pipeline(painter, rect)
            self._draw_status_and_version(painter, rect)
        finally:
            painter.end()

    def _draw_gradient_background(self, painter: QPainter, rect: QRectF) -> None:
        """Render the animated rotating gradient background.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        angle_rad = math.radians(self._gradient_time * _GRADIENT_ROTATION_SPEED)
        cx = rect.center().x()
        cy = rect.center().y()
        half_diag = math.sqrt(rect.width() ** 2 + rect.height() ** 2) / 2.0
        dx = math.cos(angle_rad) * half_diag
        dy = math.sin(angle_rad) * half_diag

        gradient = QLinearGradient(cx - dx, cy - dy, cx + dx, cy + dy)
        for stop_idx in range(3):
            color = self._compute_gradient_stop_color(stop_idx)
            gradient.setColorAt(stop_idx / 2.0, color)

        painter.fillRect(rect, QBrush(gradient))

    def _compute_gradient_stop_color(self, stop_index: int) -> QColor:
        """Compute a gradient color stop using sin-based palette cycling.

        Args:
            stop_index: Gradient stop index (0, 1, or 2).

        Returns:
            QColor: Interpolated gradient color for this stop.
        """
        n = len(_GRADIENT_HSV_COLORS)
        phase = stop_index * 2.0 * math.pi / 3.0
        idx_float = (math.sin(self._gradient_time * 0.3 + phase) + 1.0) / 2.0 * (n - 1)
        idx_low = int(idx_float) % n
        frac = idx_float - int(idx_float)

        low = _GRADIENT_HSV_COLORS[idx_low]
        high = _GRADIENT_HSV_COLORS[(idx_low + 1) % n]

        return QColor.fromHsvF(
            low[0] + (high[0] - low[0]) * frac,
            low[1] + (high[1] - low[1]) * frac,
            low[2] + (high[2] - low[2]) * frac,
        )

    def _draw_splash_image(self, painter: QPainter, rect: QRectF) -> None:
        """Composite the full splash.png image as fallback when brain icon is unavailable.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        if self._splash_image is None:
            return

        img_w = self._splash_image.width()
        img_h = self._splash_image.height()
        x = (rect.width() - img_w) / 2.0
        y = (rect.height() - img_h) / 2.0

        painter.setOpacity(_SPLASH_IMAGE_OPACITY)
        painter.drawPixmap(int(x), int(y), self._splash_image)
        painter.setOpacity(1.0)

    @staticmethod
    def _load_brain_icon() -> QPixmap | None:
        """Load the standalone brain icon from splash-icon.png.

        Returns:
            QPixmap | None: Brain icon pixmap, or None if unavailable.
        """
        try:
            icon_path = get_assets_path() / _BRAIN_ICON_NAME
            if icon_path.exists():
                pixmap = QPixmap(str(icon_path))
                if not pixmap.isNull():
                    return pixmap
        except (FileNotFoundError, OSError):
            _logger.debug("brain_icon_not_found")
        return None

    def _draw_brain_icon(self, painter: QPainter, rect: QRectF) -> None:
        """Draw the brain icon centered in the upper portion of the splash.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        if self._brain_icon is None:
            return

        display_h = int(rect.height() * _BRAIN_DISPLAY_HEIGHT)
        scaled = self._brain_icon.scaled(
            display_h,
            display_h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

        x = (rect.width() - scaled.width()) / 2.0
        y = rect.height() * _BRAIN_Y_FRACTION - scaled.height() / 2.0

        painter.drawPixmap(int(x), int(y), scaled)

    def _draw_title(self, painter: QPainter, rect: QRectF) -> None:
        """Render the title with multi-layer glow effect below the brain icon.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        title_font = FontManager.get_instance().get_heading_font(
            int(_TITLE_FONT_SIZE * self._dpi_scale),
        )
        painter.setFont(title_font)

        title_y = rect.height() * _TITLE_Y_FRACTION
        title_h = float(_TITLE_HEIGHT_FACTOR * self._dpi_scale)
        title_rect = QRectF(rect.left(), title_y - title_h / 2.0, rect.width(), title_h)

        self._draw_glow_title(painter, title_rect, _TITLE_TEXT)

    def _draw_glow_title(self, painter: QPainter, title_rect: QRectF, title: str) -> None:
        """Render title text with multi-layer glow effect.

        Args:
            painter: Active QPainter instance.
            title_rect: Rectangle for title text positioning.
            title: Title text string to render.
        """
        accent = QColor(_GLOW_ACCENT_COLOR)

        for alpha, radius in _GLOW_LAYERS:
            glow_color = QColor(accent.red(), accent.green(), accent.blue(), alpha)
            painter.setPen(glow_color)
            scaled_radius = radius * self._dpi_scale / float(_GLOW_DIRECTIONS)

            for dir_idx in range(_GLOW_DIRECTIONS):
                angle = dir_idx * math.pi / 4.0
                offset_x = math.cos(angle) * scaled_radius
                offset_y = math.sin(angle) * scaled_radius
                offset_rect = title_rect.translated(offset_x, offset_y)
                painter.drawText(offset_rect, Qt.AlignmentFlag.AlignCenter, title)

        painter.setPen(QColor(FALLBACK_TEXT_COLOR))
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, title)

    def _draw_pipeline(self, painter: QPainter, rect: QRectF) -> None:
        """Render the multi-phase pipeline indicator with stage circles and labels.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        scale = self._dpi_scale
        circle_r = int(_PIPELINE_CIRCLE_DIAMETER * scale) / 2.0
        margin_h = int(_PIPELINE_MARGIN_H * scale)
        pipeline_y = rect.height() - _PIPELINE_Y_OFFSET_FROM_BOTTOM * scale
        spacing = (rect.width() - 2.0 * margin_h) / max(1, _STAGE_COUNT - 1)

        colors = (QColor(_STAGE_PENDING_COLOR), QColor(FALLBACK_ACCENT_COLOR), QColor(_STAGE_ERROR_COLOR))

        painter.setPen(QPen(colors[0], _PIPELINE_LINE_WIDTH * scale))
        for i in range(_STAGE_COUNT - 1):
            painter.drawLine(
                int(margin_h + spacing * i + circle_r),
                int(pipeline_y),
                int(margin_h + spacing * (i + 1) - circle_r),
                int(pipeline_y),
            )

        painter.setFont(FontManager.get_instance().get_ui_font(int(_PIPELINE_LABEL_FONT_SIZE * scale)))

        for i in range(_STAGE_COUNT):
            cx = margin_h + spacing * i
            state = self._stage_states[i]

            self._draw_pipeline_stage(painter, cx, pipeline_y, circle_r, state, colors[1], colors[0], colors[2])

            label_color = colors[0]
            if state in {_StageState.ACTIVE, _StageState.COMPLETE}:
                label_color = colors[1]
            if state == _StageState.FAILED:
                label_color = colors[2]
            painter.setPen(label_color)
            painter.drawText(
                QRectF(
                    cx - spacing / 2.0,
                    pipeline_y + circle_r + _PIPELINE_LABEL_GAP * scale,
                    spacing,
                    _PIPELINE_LABEL_HEIGHT * scale,
                ),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                _STAGE_LABELS[i],
            )

    def _draw_pipeline_stage(
        self,
        painter: QPainter,
        cx: float,
        cy: float,
        radius: float,
        state: _StageState,
        accent: QColor,
        pending_color: QColor,
        error_color: QColor,
    ) -> None:
        """Render a single pipeline stage circle with state-dependent appearance.

        Args:
            painter: Active QPainter instance.
            cx: Circle center X coordinate.
            cy: Circle center Y coordinate.
            radius: Circle radius in pixels.
            state: Current visual state of this stage.
            accent: Accent color for active and complete states.
            pending_color: Color for pending state outline.
            error_color: Color for failed state fill.
        """
        circle_rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)

        if state == _StageState.PENDING:
            painter.setPen(QPen(pending_color, _PENDING_PEN_WIDTH * self._dpi_scale))
            painter.setBrush(QBrush(QColor(0, 0, 0, 0)))
            painter.drawEllipse(circle_rect)

        elif state == _StageState.ACTIVE:
            pulse = (math.sin(self._active_pulse_time * _ACTIVE_PULSE_SPEED) + 1.0) / 2.0
            alpha = int(_ACTIVE_BASE_ALPHA + _ACTIVE_RANGE_ALPHA * pulse)
            pulse_color = QColor(accent.red(), accent.green(), accent.blue(), alpha)
            painter.setPen(QPen(pulse_color, _ACTIVE_PEN_WIDTH * self._dpi_scale))
            painter.setBrush(QBrush(QColor(0, 0, 0, 0)))
            painter.drawEllipse(circle_rect)

            dot_r = radius * _DOT_RADIUS_FACTOR
            dot_alpha = min(255, int(_DOT_BASE_ALPHA + _DOT_RANGE_ALPHA * pulse))
            dot_color = QColor(accent.red(), accent.green(), accent.blue(), dot_alpha)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(dot_color))
            painter.drawEllipse(QRectF(cx - dot_r, cy - dot_r, dot_r * 2, dot_r * 2))

        elif state == _StageState.COMPLETE:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(accent))
            painter.drawEllipse(circle_rect)

            check_path = QPainterPath()
            s = radius * _CHECKMARK_SCALE
            check_path.moveTo(cx - s * 0.6, cy)
            check_path.lineTo(cx - s * 0.1, cy + s * 0.5)
            check_path.lineTo(cx + s * 0.7, cy - s * 0.4)
            check_pen = QPen(QColor(255, 255, 255), _PIPELINE_CHECKMARK_PEN_WIDTH * self._dpi_scale)
            check_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            check_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.strokePath(check_path, check_pen)

        elif state == _StageState.FAILED:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(error_color))
            painter.drawEllipse(circle_rect)

            x_size = radius * _X_MARK_SCALE
            x_pen = QPen(QColor(255, 255, 255), _PIPELINE_CHECKMARK_PEN_WIDTH * self._dpi_scale)
            x_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(x_pen)
            painter.drawLine(
                int(cx - x_size),
                int(cy - x_size),
                int(cx + x_size),
                int(cy + x_size),
            )
            painter.drawLine(
                int(cx + x_size),
                int(cy - x_size),
                int(cx - x_size),
                int(cy + x_size),
            )

    def _draw_status_and_version(self, painter: QPainter, rect: QRectF) -> None:
        """Render the status message text and version string.

        Args:
            painter: Active QPainter instance.
            rect: Splash screen bounding rectangle.
        """
        scale = self._dpi_scale
        pipeline_y = rect.height() - _PIPELINE_Y_OFFSET_FROM_BOTTOM * scale

        status_font = FontManager.get_instance().get_ui_font(int(_STATUS_FONT_SIZE * scale))
        painter.setFont(status_font)
        painter.setPen(QColor(FALLBACK_TEXT_COLOR))
        status_y = pipeline_y - _STATUS_Y_OFFSET_FROM_PIPELINE * scale
        status_rect = QRectF(0, status_y - _STATUS_TEXT_HEIGHT * scale, rect.width(), _STATUS_TEXT_HEIGHT * scale)
        painter.drawText(status_rect, Qt.AlignmentFlag.AlignCenter, self._status_message)

        if self._version:
            version_font = FontManager.get_instance().get_ui_font(int(_VERSION_FONT_SIZE * scale))
            painter.setFont(version_font)
            painter.setPen(QColor(212, 212, 212, _VERSION_ALPHA))
            version_margin_b = _VERSION_MARGIN_BOTTOM * scale
            version_margin_r = _VERSION_MARGIN_RIGHT * scale
            version_rect = QRectF(
                0,
                rect.height() - version_margin_b - _VERSION_TEXT_HEIGHT * scale,
                rect.width() - version_margin_r,
                _VERSION_TEXT_HEIGHT * scale,
            )
            painter.drawText(
                version_rect,
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom,
                f"v{self._version}",
            )

    @override
    def resizeEvent(self, a0: QResizeEvent | None) -> None:
        """Handle resize events to adjust the overlay geometry.

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
            int: Current progress (0-100).
        """
        return self.progress_value

    @property
    def status(self) -> str:
        """Get current status message.

        Returns:
            str: Current status message.
        """
        return self._status_message

    @property
    def status_label(self) -> QLabel:
        """Get the status label widget.

        Returns:
            QLabel: The hidden status label widget (retained for backward compatibility).
        """
        return self._status_label

    @property
    def dpi_scale(self) -> float:
        """Get the DPI scale factor.

        Returns:
            float: DPI scale factor used for this splash screen.
        """
        return self._dpi_scale

    @property
    def version(self) -> str:
        """Get the version string.

        Returns:
            str: Version string displayed on the splash screen.
        """
        return self._version
