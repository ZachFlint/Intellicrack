"""Splash screen for Intellicrack application startup.

Provides a custom splash screen with progress indication and status
messages during application initialization.
"""

from __future__ import annotations

from typing import Final, final

from PyQt6.QtCore import Qt, pyqtSignal
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


@final
class SplashScreen(QSplashScreen):
    """Custom splash screen with progress bar and status messages.

    Displays the Intellicrack splash image during application startup
    with real-time progress updates and status messages.
    """

    progress_updated = pyqtSignal(int, str)

    def __init__(self) -> None:
        """Initialize the splash screen."""
        pixmap = SplashScreen._load_splash_pixmap()
        super().__init__(pixmap)

        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint | Qt.WindowType.SplashScreen)

        self._progress_value: int = 0
        self._status_message: str = "Initializing..."

        self._setup_overlay()
        self.progress_updated.connect(self._on_progress_updated)
        self.resizeEvent = self.resize_event_handler

    @staticmethod
    def _load_splash_pixmap() -> QPixmap:
        """Load the splash screen image or create fallback.

        Returns:
            QPixmap for the splash screen.
        """
        try:
            splash_path = get_assets_path() / "splash.png"
            if splash_path.exists():
                pixmap = QPixmap(str(splash_path))
                if not pixmap.isNull():
                    scaled = pixmap.scaled(
                        SPLASH_WIDTH,
                        SPLASH_HEIGHT,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                    _logger.debug("splash_image_loaded", extra={"path": str(splash_path)})
                    return scaled
        except FileNotFoundError:
            _logger.debug("splash_image_not_found_using_fallback", extra={})

        return SplashScreen._create_fallback_pixmap()

    @staticmethod
    def _create_fallback_pixmap() -> QPixmap:
        """Create a fallback splash screen pixmap.

        Returns:
            QPixmap with generated splash screen.
        """
        pixmap = QPixmap(SPLASH_WIDTH, SPLASH_HEIGHT)
        pixmap.fill(QColor(FALLBACK_BG_COLOR))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        title_font = QFont("Segoe UI", 32, QFont.Weight.Bold)
        painter.setFont(title_font)
        painter.setPen(QColor(FALLBACK_TEXT_COLOR))

        title_rect = pixmap.rect()
        title_rect.setBottom(title_rect.center().y())
        painter.drawText(
            title_rect,
            Qt.AlignmentFlag.AlignCenter,
            "INTELLICRACK",
        )

        subtitle_font = QFont("Segoe UI", 12)
        painter.setFont(subtitle_font)
        painter.setPen(QColor("#888888"))

        subtitle_rect = pixmap.rect()
        subtitle_rect.setTop(title_rect.center().y() + 20)
        subtitle_rect.setBottom(subtitle_rect.top() + 40)
        painter.drawText(
            subtitle_rect,
            Qt.AlignmentFlag.AlignCenter,
            "Advanced Binary Analysis Platform",
        )

        accent_rect = pixmap.rect()
        accent_rect.setTop(accent_rect.bottom() - 4)
        painter.fillRect(accent_rect, QColor(FALLBACK_ACCENT_COLOR))

        painter.end()
        return pixmap

    def _setup_overlay(self) -> None:
        """Set up the progress bar and status label overlay."""
        self._overlay = QWidget(self)
        self._overlay.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(self._overlay)
        layout.setContentsMargins(20, 0, 20, 30)
        layout.setSpacing(8)

        layout.addStretch()

        self._status_label = QLabel("Initializing...")
        self._status_label.setStyleSheet(f"color: {FALLBACK_TEXT_COLOR}; font-size: 11px; background: transparent;")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #3e3e42;
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {FALLBACK_ACCENT_COLOR};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self._progress_bar)

        self._overlay.setGeometry(0, 0, SPLASH_WIDTH, SPLASH_HEIGHT)

    def set_progress(self, value: int, message: str = "") -> None:
        """Update the progress bar and status message.

        Args:
            value: Progress value (0-100).
            message: Status message to display.
        """
        self._progress_value = max(0, min(100, value))
        if message:
            self._status_message = message

        self._progress_bar.setValue(self._progress_value)
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

    def show_loading_step(self, step: str, progress: int) -> None:
        """Show a loading step with progress.

        Args:
            step: Description of the current loading step.
            progress: Progress percentage.
        """
        self.set_progress(progress, step)

    def resize_event_handler(self, a0: QResizeEvent | None) -> None:
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
