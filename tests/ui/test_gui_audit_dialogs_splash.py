# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit finding M19: HiDPI splash oversizing.

The splash builds its backing pixmap at physical resolution
(``SPLASH_WIDTH * dpi_scale``) but never set the pixmap's
``devicePixelRatio``. ``QSplashScreen`` therefore treated the physical-pixel
dimensions as logical points and, combined with paint code that also scaled by
``dpi_scale``, rendered roughly twice the intended size on a 2x display. The
fix sets ``devicePixelRatio`` on the pixmap so its logical (device-independent)
size stays at ``SPLASH_WIDTH`` x ``SPLASH_HEIGHT`` while the backing store
remains high resolution.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.dialogs import splash_screen as splash_mod
from intellicrack.ui.dialogs.splash_screen import SPLASH_HEIGHT, SPLASH_WIDTH, SplashScreen


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication

_TEST_DPI_SCALE: float = 2.0


@pytest.fixture
def hidpi_splash(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> Iterator[SplashScreen]:
    """Create a SplashScreen forced onto a simulated 2x HiDPI display.

    Args:
        qapp: Session-scoped Qt application fixture.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        SplashScreen: A splash constructed with ``dpi_scale == 2.0``.
    """
    del qapp
    monkeypatch.setattr(splash_mod.SplashScreen, "_compute_dpi_scale", staticmethod(lambda: _TEST_DPI_SCALE))
    splash = SplashScreen(version="9.9.9")
    yield splash
    splash.deleteLater()


class TestM19SplashHiDpiSizing:
    """M19: the splash must render at correct logical size on HiDPI displays."""

    def test_pixmap_device_pixel_ratio_is_set(self, hidpi_splash: SplashScreen) -> None:
        """The backing pixmap carries the display's device pixel ratio.

        Args:
            hidpi_splash: SplashScreen fixture at 2x scale.
        """
        pixmap = hidpi_splash.pixmap()
        assert pixmap.devicePixelRatio() == pytest.approx(_TEST_DPI_SCALE), (
            f"the splash pixmap must have its devicePixelRatio set to the display scale; got {pixmap.devicePixelRatio()}"
        )

    def test_logical_size_is_not_doubled(self, hidpi_splash: SplashScreen) -> None:
        """The pixmap's logical size equals the base splash size, not the scaled size.

        Args:
            hidpi_splash: SplashScreen fixture at 2x scale.
        """
        logical = hidpi_splash.pixmap().deviceIndependentSize()
        assert logical.width() == pytest.approx(float(SPLASH_WIDTH)), (
            f"logical width must be {SPLASH_WIDTH} (not doubled); got {logical.width()}"
        )
        assert logical.height() == pytest.approx(float(SPLASH_HEIGHT)), (
            f"logical height must be {SPLASH_HEIGHT} (not doubled); got {logical.height()}"
        )

    def test_backing_store_is_high_resolution(self, hidpi_splash: SplashScreen) -> None:
        """The physical pixel dimensions remain scaled so the splash stays crisp.

        Args:
            hidpi_splash: SplashScreen fixture at 2x scale.
        """
        pixmap = hidpi_splash.pixmap()
        assert pixmap.width() == int(SPLASH_WIDTH * _TEST_DPI_SCALE), (
            f"physical pixel width must remain {int(SPLASH_WIDTH * _TEST_DPI_SCALE)} for crisp rendering; got {pixmap.width()}"
        )
        assert pixmap.height() == int(SPLASH_HEIGHT * _TEST_DPI_SCALE), (
            f"physical pixel height must remain {int(SPLASH_HEIGHT * _TEST_DPI_SCALE)} for crisp rendering; got {pixmap.height()}"
        )
