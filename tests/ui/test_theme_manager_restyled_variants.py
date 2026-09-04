# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the restyled ``dark2`` / ``light2`` theme variants.

Validates that the two new themes are registered, resolvable, load their real
restyled QSS assets, and -- critically -- that ``dark2`` is treated as part of
the dark family so custom-painted views and generated icons stay dark.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.resources.resource_helper import get_style_path
from intellicrack.ui.resources.theme_manager import (
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ThemeManager,
)


_DARK2_ACCENT: str = "#3d8bfd"
_DARK_OLD_ACCENT: str = "#007acc"
_LIGHT2_ACCENT: str = "#0969da"
_LIGHT_OLD_ACCENT: str = "#0067c0"
_MIN_STYLESHEET_LENGTH: int = 100


@pytest.fixture
def theme_manager() -> ThemeManager:
    """Provide a fresh ThemeManager instance for each test.

    Returns:
        ThemeManager: A fresh singleton instance.
    """
    ThemeManager.reset_instance()
    return ThemeManager.get_instance()


class TestRestyledVariantRegistration:
    """Registration and resolution of the restyled variants."""

    @staticmethod
    def test_variants_listed_as_available() -> None:
        """Both restyled variants appear in the selectable theme list."""
        available = ThemeManager.get_available_themes()
        assert THEME_DARK2 in available
        assert THEME_LIGHT2 in available

    @staticmethod
    def test_variants_resolve_to_themselves() -> None:
        """Restyled variants are concrete themes, not aliases."""
        assert ThemeManager.resolve_theme(THEME_DARK2) == THEME_DARK2
        assert ThemeManager.resolve_theme(THEME_LIGHT2) == THEME_LIGHT2


class TestRestyledVariantStylesheets:
    """The restyled variants load their real, distinct QSS assets."""

    @staticmethod
    def test_dark2_file_exists() -> None:
        """The dark2 QSS asset is present on disk."""
        assert get_style_path("dark2_theme.qss").exists()

    @staticmethod
    def test_light2_file_exists() -> None:
        """The light2 QSS asset is present on disk."""
        assert get_style_path("light2_theme.qss").exists()

    @staticmethod
    def test_dark2_carries_new_accent_not_old(theme_manager: ThemeManager) -> None:
        """dark2 stylesheet uses the restyled accent and drops the old one."""
        sheet = theme_manager.get_stylesheet(THEME_DARK2)
        assert len(sheet) > _MIN_STYLESHEET_LENGTH
        assert _DARK2_ACCENT in sheet
        assert _DARK_OLD_ACCENT not in sheet

    @staticmethod
    def test_light2_carries_new_accent_not_old(theme_manager: ThemeManager) -> None:
        """light2 stylesheet uses the restyled accent and drops the old one."""
        sheet = theme_manager.get_stylesheet(THEME_LIGHT2)
        assert len(sheet) > _MIN_STYLESHEET_LENGTH
        assert _LIGHT2_ACCENT in sheet
        assert _LIGHT_OLD_ACCENT not in sheet

    @staticmethod
    def test_dark2_differs_from_dark(theme_manager: ThemeManager) -> None:
        """The restyled dark2 is not identical to the original dark theme."""
        assert theme_manager.get_stylesheet(THEME_DARK2) != theme_manager.get_stylesheet(THEME_DARK)

    @staticmethod
    def test_light2_differs_from_light(theme_manager: ThemeManager) -> None:
        """The restyled light2 is not identical to the original light theme."""
        assert theme_manager.get_stylesheet(THEME_LIGHT2) != theme_manager.get_stylesheet(THEME_LIGHT)

    @staticmethod
    def test_dark2_preserves_selector_structure(theme_manager: ThemeManager) -> None:
        """dark2 keeps every rule block of the original dark theme.

        The restyle is a pure color remap, so the number of QSS rule blocks
        (opening braces) must be identical -- a drop would mean a selector was
        lost during generation.
        """
        dark_blocks = theme_manager.get_stylesheet(THEME_DARK).count("{")
        dark2_blocks = theme_manager.get_stylesheet(THEME_DARK2).count("{")
        assert dark2_blocks == dark_blocks
        assert dark2_blocks > 0


@pytest.mark.usefixtures("qapp")
class TestRestyledVariantDarkFamily:
    """dark2 must be treated as dark; light2 must not.

    These gate the correctness of every ``is_dark_theme()`` consumer -- the
    custom-painted analysis views (hex grid, disassembly, graphs) and the
    generated icons -- which would otherwise render light-theme colors on the
    dark2 surface.
    """

    @staticmethod
    def test_dark2_is_reported_dark(theme_manager: ThemeManager) -> None:
        """Applying dark2 makes is_dark_theme() report dark."""
        assert theme_manager.apply_theme(THEME_DARK2) is True
        assert theme_manager.current_theme == THEME_DARK2
        assert theme_manager.is_dark_theme() is True

    @staticmethod
    def test_light2_is_reported_light(theme_manager: ThemeManager) -> None:
        """Applying light2 makes is_dark_theme() report light."""
        assert theme_manager.apply_theme(THEME_LIGHT2) is True
        assert theme_manager.current_theme == THEME_LIGHT2
        assert theme_manager.is_dark_theme() is False

    @staticmethod
    def test_dark2_analysis_colors_match_dark(theme_manager: ThemeManager) -> None:
        """dark2 yields the dark analysis palette, not the light one."""
        theme_manager.apply_theme(THEME_DARK2)
        dark2_colors = theme_manager.get_analysis_colors()
        theme_manager.apply_theme(THEME_DARK)
        dark_colors = theme_manager.get_analysis_colors()
        assert dark2_colors["background"] == dark_colors["background"]
        assert dark2_colors["hex_printable"] == dark_colors["hex_printable"]

    @staticmethod
    def test_apply_dark2_sets_app_stylesheet(theme_manager: ThemeManager) -> None:
        """Applying dark2 installs its stylesheet on the QApplication."""
        assert theme_manager.apply_theme(THEME_DARK2) is True
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        assert app.styleSheet() == theme_manager.get_stylesheet(THEME_DARK2)


@pytest.mark.usefixtures("qapp")
class TestRestyledVariantToggle:
    """toggle_theme stays within the current theme family."""

    @staticmethod
    def test_toggle_from_dark2_goes_to_light2(theme_manager: ThemeManager) -> None:
        """Toggling from dark2 lands on light2, not the base light theme."""
        theme_manager.apply_theme(THEME_DARK2)
        assert theme_manager.toggle_theme() == THEME_LIGHT2
        assert theme_manager.current_theme == THEME_LIGHT2

    @staticmethod
    def test_toggle_from_light2_goes_to_dark2(theme_manager: ThemeManager) -> None:
        """Toggling from light2 lands on dark2, not the base dark theme."""
        theme_manager.apply_theme(THEME_LIGHT2)
        assert theme_manager.toggle_theme() == THEME_DARK2
        assert theme_manager.current_theme == THEME_DARK2

    @staticmethod
    def test_toggle_base_themes_unchanged(theme_manager: ThemeManager) -> None:
        """The base dark <-> light toggle behaviour is preserved."""
        theme_manager.apply_theme(THEME_DARK)
        assert theme_manager.toggle_theme() == THEME_LIGHT
        assert theme_manager.toggle_theme() == THEME_DARK
