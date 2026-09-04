# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the ProcessPanel status bar height and attach-hint overlay theming.

Covers two Phase-code-half findings against real, on-screen (offscreen-platform) widgets:

* D42: the persistent status bar at the bottom of :class:`ProcessPanel` used a hardcoded
  ``_STATUS_HEIGHT = 24`` fixed height, which clips the status labels once the application
  font grows large enough that a single line of text no longer fits in 24px. The fix derives
  the height from :class:`~PyQt6.QtGui.QFontMetrics` instead, so it must grow along with the
  font.
* D37 (code half): :class:`~intellicrack.ui.panels.process_panel.hint_overlay.AttachHintOverlay`
  hardcoded a dark-theme-only stylesheet (``#1e1e1e``-family hex colors baked into the widget),
  which left the overlay unreadable in a light theme. The fix removes the inline stylesheet and
  relies on the ``attach_hint_overlay``/``attach_hint_label`` object names for a sibling agent's
  application-stylesheet rules to theme it instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QFont, QFontMetrics
from PyQt6.QtWidgets import QWidget

from intellicrack.ui.panels.process_panel import (
    ProcessPanel,
    hint_overlay as hint_overlay_module,
)
from intellicrack.ui.panels.process_panel.hint_overlay import AttachHintOverlay


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication

# Comfortably larger than the retired 24px fixed height. A pixel size (not a
# point size) is used so the enlarged font's line height is deterministic and
# independent of the headless platform's logical DPI -- an offscreen QPA at a
# low DPI renders a 28pt font at only ~16px, which is too small to exceed the
# retired 24px floor and would make this gate vacuous.
_ENLARGED_PIXEL_SIZE = 40
_OLD_FIXED_STATUS_HEIGHT = 24


@pytest.fixture
def panel(qapp: QApplication) -> Generator[ProcessPanel]:
    """Create a ProcessPanel and tear it down through its real stop_tool path.

    Args:
        qapp: QApplication fixture from conftest.

    Yields:
        ProcessPanel: ProcessPanel widget.
    """
    p = ProcessPanel()
    yield p
    p.stop_tool()
    qapp.processEvents()
    p.deleteLater()
    qapp.processEvents()


class TestStatusBarHeightDerivedFromFontMetrics:
    """D42: the status bar height must track font metrics, not a hardcoded constant."""

    @staticmethod
    def test_status_bar_height_scales_with_enlarged_application_font(qapp: QApplication) -> None:
        """The status bar must grow tall enough to fit an enlarged application font.

        Sets the application default font to a large point size before
        constructing the panel (so the status bar's own font reflects it),
        then asserts the built status bar is at least as tall as that font's
        own line height, with genuine headroom above it. A restored
        ``_STATUS_HEIGHT = 24`` fixed height fails this outright once the
        enlarged font's line height alone exceeds 24px.

        Args:
            qapp: Session QApplication fixture from conftest.
        """
        original_font = QFont(qapp.font())
        enlarged_font = QFont(original_font)
        enlarged_font.setPixelSize(_ENLARGED_PIXEL_SIZE)
        qapp.setFont(enlarged_font)
        qapp.processEvents()

        built_panel: ProcessPanel | None = None
        try:
            built_panel = ProcessPanel()
            qapp.processEvents()

            bar = built_panel._status_bar
            assert bar is not None, "ProcessPanel did not build a status bar"

            metrics_height = QFontMetrics(bar.font()).height()
            assert metrics_height > _OLD_FIXED_STATUS_HEIGHT, (
                f"enlarged test font's line height {metrics_height}px must exceed the "
                f"retired fixed height {_OLD_FIXED_STATUS_HEIGHT}px for this gate to be meaningful"
            )

            assert bar.height() >= metrics_height, (
                f"status bar height {bar.height()}px is smaller than its own font's line "
                f"height {metrics_height}px at an enlarged application font -- _STATUS_HEIGHT "
                f"may have been hardcoded again instead of derived from QFontMetrics"
            )
            assert bar.height() > metrics_height, (
                f"status bar height {bar.height()}px leaves no chrome/headroom above the "
                f"font's line height {metrics_height}px"
            )
        finally:
            if built_panel is not None:
                built_panel.stop_tool()
                qapp.processEvents()
                built_panel.deleteLater()
                qapp.processEvents()
            qapp.setFont(original_font)
            qapp.processEvents()

    @staticmethod
    def test_status_bar_height_at_default_font_fits_its_own_metrics(panel: ProcessPanel) -> None:
        """Even at the ordinary test-session font, the bar must fit its own line height.

        Args:
            panel: Freshly constructed ProcessPanel fixture.
        """
        bar = panel._status_bar
        assert bar is not None, "ProcessPanel did not build a status bar"
        metrics_height = QFontMetrics(bar.font()).height()
        assert bar.height() >= metrics_height, (
            f"status bar height {bar.height()}px clips its own font's line height {metrics_height}px"
        )


class TestAttachHintOverlayIsThemedNotHardcoded:
    """D37 (code half): the overlay must defer coloring to the app stylesheet."""

    @staticmethod
    def test_source_has_no_hardcoded_color_literals() -> None:
        """hint_overlay.py must not bake dark-theme hex or rgba() colors into the widget."""
        source = Path(hint_overlay_module.__file__).read_text(encoding="utf-8")

        hex_colors = re.findall(r"#[0-9a-fA-F]{3,8}\b", source)
        assert not hex_colors, f"hint_overlay.py still hardcodes color literal(s): {hex_colors}"

        rgba_calls = re.findall(r"rgba?\(", source)
        assert not rgba_calls, "hint_overlay.py still hardcodes an rgb()/rgba() color literal"

        assert "setStyleSheet" not in source, (
            "hint_overlay.py must not set an inline stylesheet -- theming belongs to the "
            "application stylesheet via the attach_hint_overlay/attach_hint_label object names"
        )

    @staticmethod
    def test_source_declares_themed_object_names() -> None:
        """hint_overlay.py must name both widgets for the app stylesheet to match."""
        source = Path(hint_overlay_module.__file__).read_text(encoding="utf-8")
        assert '"attach_hint_overlay"' in source
        assert '"attach_hint_label"' in source

    @staticmethod
    def test_overlay_widgets_carry_the_themed_object_names(qapp: QApplication) -> None:
        """A real AttachHintOverlay instance and its label must expose the themed object names.

        Args:
            qapp: Session QApplication fixture from conftest.
        """
        host = QWidget()
        overlay = AttachHintOverlay(host, "Attach to a process first")
        try:
            assert overlay.objectName() == "attach_hint_overlay"
            assert overlay._label.objectName() == "attach_hint_label"
        finally:
            overlay.deleteLater()
            host.deleteLater()
            qapp.processEvents()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
