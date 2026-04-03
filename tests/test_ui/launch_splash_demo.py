"""Visual demo launcher for the Intellicrack splash screen.

Run directly to see the animated splash screen with all effects:
    pixi run python tests/test_ui/launch_splash_demo.py

The splash displays for ~8 seconds, advancing through all pipeline
stages with the same progress values used by main(). Glitch effects
fire automatically via the animation timer. The splash then fades
out to a placeholder window and the process exits.
"""

from __future__ import annotations

import sys
from typing import Final

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.dialogs.splash_screen import SplashScreen
from intellicrack.ui.resources.theme_manager import ThemeManager


_APP_VERSION: Final[str] = "demo"

_PROGRESS_STEPS: Final[list[tuple[int, str, int]]] = [
    (5, "Loading configuration...", 600),
    (10, "Loading credentials...", 500),
    (20, "Initializing providers...", 900),
    (50, "Initializing tools...", 1200),
    (70, "Initializing session manager...", 700),
    (85, "Creating orchestrator...", 500),
    (90, "Initializing script engine...", 400),
    (93, "Initializing model discovery...", 500),
    (95, "Initializing UI...", 600),
    (100, "Ready", 800),
]


class _DemoRunner:
    """Drives the splash through all progress steps on a timer chain.

    Args:
        app: QApplication instance.
        splash: The animated splash screen to drive.
    """

    def __init__(self, app: QApplication, splash: SplashScreen) -> None:
        self._app: QApplication = app
        self._splash: SplashScreen = splash
        self._step: int = 0

    def start(self) -> None:
        """Begin the first step after a short initial delay."""
        QTimer.singleShot(400, self._advance)

    def _advance(self) -> None:
        """Apply the current progress step and schedule the next one."""
        if self._step >= len(_PROGRESS_STEPS):
            self._finish()
            return

        progress, message, _ = _PROGRESS_STEPS[self._step]
        self._splash.set_progress(progress, message)
        self._app.processEvents()
        self._step += 1

        next_delay: int = _PROGRESS_STEPS[self._step][2] if self._step < len(_PROGRESS_STEPS) else 800
        QTimer.singleShot(next_delay, self._advance)

    def _finish(self) -> None:
        """Fade out the splash and quit after a short delay."""
        target = QWidget()
        target.setWindowTitle("Intellicrack (demo target)")
        target.resize(800, 600)
        self._splash.finish_animated(target)
        QTimer.singleShot(2000, self._app.quit)


def _run_demo() -> int:
    """Run the splash screen visual demo.

    Returns:
        int: Exit code (0 for success).
    """
    app = QApplication(sys.argv)
    app.setApplicationName("Intellicrack")
    app.setStyle("Fusion")

    theme = ThemeManager.get_instance()
    theme.apply_theme("dark")

    splash = SplashScreen(version=_APP_VERSION)
    splash.show_animated()
    app.processEvents()

    runner = _DemoRunner(app, splash)
    runner.start()

    return app.exec()


if __name__ == "__main__":
    sys.exit(_run_demo())
