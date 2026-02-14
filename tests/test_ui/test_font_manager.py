"""Tests for FontManager module.

Validates font loading, fallback behavior, and font configuration
using real font assets.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtGui import QFont

from intellicrack.ui.resources.font_manager import (
    DEFAULT_CODE_FONT,
    DEFAULT_UI_FONT,
    FALLBACK_CODE_FONTS,
    FALLBACK_UI_FONTS,
    FontManager,
)
from intellicrack.ui.resources.resource_helper import get_assets_path


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


_STYLE_HINT_MONOSPACE_VALUE: int = 7
_STYLE_HINT_SANS_SERIF_VALUE: int = 0
_EXPECTED_FONT_SIZE_14: int = 14
_EXPECTED_FONT_SIZE_12: int = 12
_EXPECTED_FONT_SIZE_16: int = 16
_MIN_FONT_FILE_SIZE: int = 1000


@pytest.fixture
def font_manager(
    qapp: QApplication,
) -> Generator[FontManager]:
    """Provide a fresh FontManager instance for each test.

    Requires qapp fixture for Qt font database access.

    Args:
        qapp: Qt application fixture.

    Yields:
        A fresh FontManager instance.
    """
    del qapp
    FontManager.reset_instance()
    yield FontManager.get_instance()
    FontManager.reset_instance()


class TestFontManagerSingleton:
    """Tests for singleton pattern implementation."""

    @staticmethod
    def test_get_instance_returns_same_object(_qapp: QApplication) -> None:
        """Singleton returns the same instance."""
        FontManager.reset_instance()
        instance1 = FontManager.get_instance()
        instance2 = FontManager.get_instance()
        assert instance1 is instance2
        FontManager.reset_instance()

    @staticmethod
    def test_reset_instance_clears_singleton(_qapp: QApplication) -> None:
        """Reset clears the singleton instance."""
        FontManager.reset_instance()
        instance1 = FontManager.get_instance()
        FontManager.reset_instance()
        instance2 = FontManager.get_instance()
        assert instance1 is not instance2
        FontManager.reset_instance()


class TestFontLoading:
    """Tests for font loading functionality."""

    @staticmethod
    def test_load_fonts_returns_bool(font_manager: FontManager) -> None:
        """load_fonts returns a boolean."""
        result = font_manager.load_fonts()
        assert isinstance(result, bool)

    @staticmethod
    def test_load_fonts_succeeds(font_manager: FontManager) -> None:
        """Font loading succeeds with available fonts."""
        result = font_manager.load_fonts()
        assert result, "Font loading should succeed with assets available"

    @staticmethod
    def test_fonts_loaded_flag_set(font_manager: FontManager) -> None:
        """_fonts_loaded flag is set after loading."""
        font_manager.load_fonts()
        assert font_manager._fonts_loaded

    @staticmethod
    def test_loaded_families_populated(font_manager: FontManager) -> None:
        """loaded_families is populated after loading."""
        font_manager.load_fonts()
        families = font_manager.loaded_families
        assert len(families) > 0, "No font families were loaded"

    @staticmethod
    def test_jetbrains_mono_loaded(font_manager: FontManager) -> None:
        """JetBrains Mono font is loaded."""
        font_manager.load_fonts()
        families = font_manager.loaded_families
        has_jetbrains = any("JetBrains" in f for f in families)
        assert has_jetbrains, f"JetBrains Mono not loaded. Loaded: {families}"

    @staticmethod
    def test_load_fonts_idempotent(font_manager: FontManager) -> None:
        """Calling load_fonts multiple times is safe."""
        result1 = font_manager.load_fonts()
        result2 = font_manager.load_fonts()
        assert result1 == result2


class TestCodeFont:
    """Tests for code font retrieval."""

    @staticmethod
    def test_get_code_font_returns_qfont(font_manager: FontManager) -> None:
        """get_code_font returns a QFont instance."""
        font = font_manager.get_code_font()
        assert isinstance(font, QFont)

    @staticmethod
    def test_code_font_is_monospace(font_manager: FontManager) -> None:
        """Code font has monospace style hint."""
        font = font_manager.get_code_font()
        assert font.styleHint().value == _STYLE_HINT_MONOSPACE_VALUE

    @staticmethod
    def test_code_font_is_fixed_pitch(font_manager: FontManager) -> None:
        """Code font is fixed pitch."""
        font = font_manager.get_code_font()
        assert font.fixedPitch()

    @staticmethod
    def test_code_font_respects_size(font_manager: FontManager) -> None:
        """Code font uses requested size."""
        font = font_manager.get_code_font(size=_EXPECTED_FONT_SIZE_14)
        assert font.pointSize() == _EXPECTED_FONT_SIZE_14

    @staticmethod
    def test_get_code_font_bold(font_manager: FontManager) -> None:
        """get_code_font_bold returns bold font."""
        font = font_manager.get_code_font_bold()
        assert font.bold()

    @staticmethod
    def test_code_font_family_set(font_manager: FontManager) -> None:
        """Code font family is properly set."""
        font_manager.load_fonts()
        family = font_manager.code_font_family
        assert len(family) > 0, "Code font family is empty"


class TestUIFont:
    """Tests for UI font retrieval."""

    @staticmethod
    def test_get_ui_font_returns_qfont(font_manager: FontManager) -> None:
        """get_ui_font returns a QFont instance."""
        font = font_manager.get_ui_font()
        assert isinstance(font, QFont)

    @staticmethod
    def test_ui_font_is_sans_serif(font_manager: FontManager) -> None:
        """UI font has sans-serif style hint."""
        font = font_manager.get_ui_font()
        assert font.styleHint().value == _STYLE_HINT_SANS_SERIF_VALUE

    @staticmethod
    def test_ui_font_respects_size(font_manager: FontManager) -> None:
        """UI font uses requested size."""
        font = font_manager.get_ui_font(size=_EXPECTED_FONT_SIZE_12)
        assert font.pointSize() == _EXPECTED_FONT_SIZE_12

    @staticmethod
    def test_get_ui_font_bold(font_manager: FontManager) -> None:
        """get_ui_font_bold returns bold font."""
        font = font_manager.get_ui_font_bold()
        assert font.bold()

    @staticmethod
    def test_ui_font_family_set(font_manager: FontManager) -> None:
        """UI font family is properly set."""
        font_manager.load_fonts()
        family = font_manager.ui_font_family
        assert len(family) > 0, "UI font family is empty"


class TestHeadingFont:
    """Tests for heading font retrieval."""

    @staticmethod
    def test_get_heading_font_returns_qfont(font_manager: FontManager) -> None:
        """get_heading_font returns a QFont instance."""
        font = font_manager.get_heading_font()
        assert isinstance(font, QFont)

    @staticmethod
    def test_heading_font_is_bold(font_manager: FontManager) -> None:
        """Heading font is bold."""
        font = font_manager.get_heading_font()
        assert font.bold()

    @staticmethod
    def test_heading_font_respects_size(font_manager: FontManager) -> None:
        """Heading font uses requested size."""
        font = font_manager.get_heading_font(size=_EXPECTED_FONT_SIZE_16)
        assert font.pointSize() == _EXPECTED_FONT_SIZE_16


class TestFontFamilyProperties:
    """Tests for font family properties."""

    @staticmethod
    def test_code_font_family_auto_loads(_font_manager: FontManager) -> None:
        """Accessing code_font_family triggers font loading."""
        FontManager.reset_instance()
        manager = FontManager.get_instance()
        _ = manager.code_font_family
        assert manager._fonts_loaded

    @staticmethod
    def test_ui_font_family_auto_loads(_font_manager: FontManager) -> None:
        """Accessing ui_font_family triggers font loading."""
        FontManager.reset_instance()
        manager = FontManager.get_instance()
        _ = manager.ui_font_family
        assert manager._fonts_loaded

    @staticmethod
    def test_loaded_families_is_copy(font_manager: FontManager) -> None:
        """loaded_families returns a copy, not the internal list."""
        font_manager.load_fonts()
        families1 = font_manager.loaded_families
        families2 = font_manager.loaded_families
        assert families1 is not families2
        assert families1 == families2


class TestCustomFontStatus:
    """Tests for custom font status checking."""

    @staticmethod
    def test_is_custom_font_loaded_after_load(font_manager: FontManager) -> None:
        """is_custom_font_loaded returns True after successful loading."""
        font_manager.load_fonts()
        assert font_manager.is_custom_font_loaded()

    @staticmethod
    def test_is_custom_font_loaded_before_load(_qapp: QApplication) -> None:
        """is_custom_font_loaded returns False before loading."""
        FontManager.reset_instance()
        manager = FontManager()
        assert not manager.is_custom_font_loaded()
        FontManager.reset_instance()


class TestFontInfo:
    """Tests for get_font_info method."""

    @staticmethod
    def test_get_font_info_returns_dict(font_manager: FontManager) -> None:
        """get_font_info returns a dictionary."""
        info = font_manager.get_font_info()
        assert isinstance(info, dict)

    @staticmethod
    def test_font_info_contains_required_keys(font_manager: FontManager) -> None:
        """Font info contains all required keys."""
        font_manager.load_fonts()
        info = font_manager.get_font_info()

        required_keys = [
            "fonts_loaded",
            "custom_fonts_available",
            "loaded_families",
            "code_font",
            "ui_font",
        ]

        for key in required_keys:
            assert key in info, f"Missing key in font info: {key}"

    @staticmethod
    def test_font_info_values_correct_types(font_manager: FontManager) -> None:
        """Font info values have correct types."""
        font_manager.load_fonts()
        info = font_manager.get_font_info()

        assert isinstance(info["fonts_loaded"], bool)
        assert isinstance(info["custom_fonts_available"], bool)
        assert isinstance(info["loaded_families"], list)
        assert isinstance(info["code_font"], str)
        assert isinstance(info["ui_font"], str)


class TestFallbackFonts:
    """Tests for fallback font configuration."""

    @staticmethod
    def test_fallback_code_fonts_not_empty() -> None:
        """FALLBACK_CODE_FONTS list is not empty."""
        assert len(FALLBACK_CODE_FONTS) > 0

    @staticmethod
    def test_fallback_ui_fonts_not_empty() -> None:
        """FALLBACK_UI_FONTS list is not empty."""
        assert len(FALLBACK_UI_FONTS) > 0

    @staticmethod
    def test_fallback_code_fonts_contains_common_fonts() -> None:
        """FALLBACK_CODE_FONTS contains commonly available fonts."""
        common_fonts = ["Consolas", "Courier New", "monospace"]
        for font in common_fonts:
            assert font in FALLBACK_CODE_FONTS, f"Missing common font: {font}"

    @staticmethod
    def test_fallback_ui_fonts_contains_common_fonts() -> None:
        """FALLBACK_UI_FONTS contains commonly available fonts."""
        common_fonts = ["Arial", "sans-serif"]
        for font in common_fonts:
            assert font in FALLBACK_UI_FONTS, f"Missing common font: {font}"

    @staticmethod
    def test_default_code_font_in_fallback_list() -> None:
        """DEFAULT_CODE_FONT is in fallback list."""
        assert DEFAULT_CODE_FONT in FALLBACK_CODE_FONTS

    @staticmethod
    def test_default_ui_font_in_fallback_list() -> None:
        """DEFAULT_UI_FONT is in fallback list."""
        assert DEFAULT_UI_FONT in FALLBACK_UI_FONTS


class TestFontAssets:
    """Tests for font asset files."""

    @staticmethod
    def test_fonts_directory_exists() -> None:
        """Fonts directory exists in assets."""
        assets = get_assets_path()
        fonts_dir = assets / "fonts"
        assert fonts_dir.exists(), "Fonts directory missing"
        assert fonts_dir.is_dir(), "Fonts path is not a directory"

    @staticmethod
    def test_ttf_fonts_present() -> None:
        """TTF font files are present."""
        assets = get_assets_path()
        fonts_dir = assets / "fonts"
        ttf_files = list(fonts_dir.glob("*.ttf"))
        assert ttf_files, "No TTF fonts found"

    @staticmethod
    def test_font_files_not_empty() -> None:
        """Font files are not empty."""
        assets = get_assets_path()
        fonts_dir = assets / "fonts"

        for font_file in fonts_dir.glob("*.ttf"):
            size = font_file.stat().st_size
            assert size > _MIN_FONT_FILE_SIZE, f"Font file too small: {font_file.name}"

    @staticmethod
    def test_font_config_exists() -> None:
        """Font config JSON exists."""
        assets = get_assets_path()
        config_path = assets / "fonts" / "font_config.json"
        assert config_path.exists(), "font_config.json missing"

    @staticmethod
    def test_font_config_valid_json() -> None:
        """Font config is valid JSON."""
        assets = get_assets_path()
        config_path = assets / "fonts" / "font_config.json"

        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)

        assert isinstance(config, dict), "Font config should be a dict"
