# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for log-viewer level color theming (GUI audit finding H4).

The pre-fix model shipped a hard-coded dark palette: ``INFO`` was near-white
``QColor(220, 220, 220)`` with no background override, so under the light theme
it rendered white text on a near-white background. These tests apply both the
light and dark themes to the real :class:`ThemeManager` singleton and assert the
model resolves per-level foreground colors with sufficient WCAG contrast against
the active background, and that switching themes re-resolves the colors and
repaints existing rows via ``dataChanged``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QColor

from intellicrack.ui.log_viewer import LogRecordTableModel
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_MIN_CONTRAST_RATIO: float = 3.0
_SRGB_LINEAR_THRESHOLD: float = 0.03928


def _linearize(value: int) -> float:
    """Linearize a single 8-bit sRGB channel for luminance math.

    Args:
        value: Channel value in the range 0-255.

    Returns:
        float: The linearized channel value in the range 0.0-1.0.
    """
    channel = value / 255.0
    if channel <= _SRGB_LINEAR_THRESHOLD:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def _relative_luminance(color: QColor) -> float:
    """Compute the WCAG relative luminance of a color.

    Args:
        color: The color to measure.

    Returns:
        float: Relative luminance in the range 0.0-1.0.
    """
    return 0.2126 * _linearize(color.red()) + 0.7152 * _linearize(color.green()) + 0.0722 * _linearize(color.blue())


def _contrast_ratio(foreground: QColor, background: QColor) -> float:
    """Compute the WCAG contrast ratio between two colors.

    Args:
        foreground: Foreground (text) color.
        background: Background color.

    Returns:
        float: Contrast ratio in the range 1.0-21.0.
    """
    lum_fg = _relative_luminance(foreground)
    lum_bg = _relative_luminance(background)
    lighter = max(lum_fg, lum_bg)
    darker = min(lum_fg, lum_bg)
    return (lighter + 0.05) / (darker + 0.05)


def _record(level: str) -> dict[str, object]:
    """Build a minimal normalized log record at the given level.

    Args:
        level: Log level name (e.g. ``"INFO"``).

    Returns:
        dict[str, object]: A populated record dictionary matching the shape the
            model coalesces into its ring buffer.
    """
    return {
        "timestamp": "2026-05-25 10:00:00",
        "level": level,
        "logger": "intellicrack.tests",
        "module": "test_gui_audit_logtheme_model",
        "function": "_record",
        "line_number": 1,
        "event": "evt",
        "extras": {},
    }


@pytest.fixture
def theme_manager() -> Iterator[ThemeManager]:
    """Yield the theme manager singleton and restore its theme afterward.

    Yields:
        ThemeManager: The application theme manager singleton.
    """
    manager = ThemeManager.get_instance()
    original = manager.requested_theme
    try:
        yield manager
    finally:
        manager.apply_theme(original)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_info_and_debug_readable_in_both_themes(theme_manager: ThemeManager, theme: str) -> None:
    """INFO and DEBUG foreground colors keep adequate contrast in each theme.

    Catches the H4 regression where the hard-coded near-white INFO color
    rendered white-on-white under the light theme.

    Args:
        theme_manager: The theme manager singleton fixture.
        theme: The theme name to apply for this parametrization.
    """
    theme_manager.apply_theme(theme)
    model = LogRecordTableModel()
    background = theme_manager.get_analysis_colors()["background"]

    info_fg = model.level_foreground("INFO")
    debug_fg = model.level_foreground("DEBUG")
    assert info_fg is not None
    assert debug_fg is not None
    assert _contrast_ratio(info_fg, background) >= _MIN_CONTRAST_RATIO
    assert _contrast_ratio(debug_fg, background) >= _MIN_CONTRAST_RATIO


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_severity_levels_stay_distinguishable(theme_manager: ThemeManager, theme: str) -> None:
    """WARNING, ERROR and CRITICAL stay visually distinct in each theme.

    Args:
        theme_manager: The theme manager singleton fixture.
        theme: The theme name to apply for this parametrization.
    """
    theme_manager.apply_theme(theme)
    model = LogRecordTableModel()

    warning_fg = model.level_foreground("WARNING")
    error_fg = model.level_foreground("ERROR")
    critical_fg = model.level_foreground("CRITICAL")
    critical_bg = model.level_background("CRITICAL")

    assert warning_fg is not None
    assert error_fg is not None
    assert critical_fg is not None
    assert critical_bg is not None
    assert warning_fg != error_fg
    assert _contrast_ratio(critical_fg, critical_bg) >= _MIN_CONTRAST_RATIO


def test_theme_switch_changes_resolved_info_color(theme_manager: ThemeManager) -> None:
    """Switching themes re-resolves the INFO foreground to a different color.

    Args:
        theme_manager: The theme manager singleton fixture.
    """
    theme_manager.apply_theme("dark")
    model = LogRecordTableModel()
    dark_info = model.level_foreground("INFO")
    assert dark_info is not None
    dark_info_copy = QColor(dark_info)

    theme_manager.apply_theme("light")
    light_info = model.level_foreground("INFO")
    assert light_info is not None
    assert QColor(light_info) != dark_info_copy


def test_theme_switch_repaints_existing_rows(theme_manager: ThemeManager, qtbot: QtBot) -> None:
    """A theme change emits ``dataChanged`` so populated rows repaint.

    Args:
        theme_manager: The theme manager singleton fixture.
        qtbot: pytest-qt bot fixture.
    """
    theme_manager.apply_theme("dark")
    model = LogRecordTableModel()
    model.append_record(_record("INFO"))
    model.flush()

    with qtbot.waitSignal(model.dataChanged, timeout=2_000):
        theme_manager.apply_theme("light")
