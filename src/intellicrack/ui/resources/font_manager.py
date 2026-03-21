# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Font management for Intellicrack UI.

Provides custom font loading and application for the Intellicrack interface.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar, Final, cast

from PyQt6.QtGui import QFont, QFontDatabase

from ...core.logging import get_logger
from .resource_helper import get_assets_path, get_font_path, resource_exists


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger("ui.resources.fonts")


DEFAULT_CODE_FONT: Final[str] = "JetBrains Mono"
DEFAULT_UI_FONT: Final[str] = "Segoe UI"

FALLBACK_CODE_FONTS: Final[list[str]] = [
    "JetBrains Mono",
    "Cascadia Code",
    "Fira Code",
    "Source Code Pro",
    "Consolas",
    "Monaco",
    "Courier New",
    "monospace",
]

FALLBACK_UI_FONTS: Final[list[str]] = [
    "Segoe UI",
    "Inter",
    "Roboto",
    "Helvetica Neue",
    "Arial",
    "sans-serif",
]


class FontManager:
    """Singleton font manager for custom font loading and management.

    Handles loading custom fonts from the assets directory and provides
    font instances for code and UI elements.
    """

    _instance: ClassVar[FontManager | None] = None

    def __init__(self) -> None:
        self._fonts_loaded: bool = False
        self._loaded_families: list[str] = []
        self._code_font_family: str = ""
        self._ui_font_family: str = ""
        self._font_config: dict[str, object] = {}

    @classmethod
    def get_instance(cls) -> FontManager:
        """Get the singleton instance of FontManager.

        Returns:
            FontManager: The FontManager singleton instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        cls._instance = None

    def load_fonts(self) -> bool:
        """Load all custom fonts from the fonts directory.

        Returns:
            bool: True if at least one font was loaded successfully.
        """
        if self._fonts_loaded:
            _logger.debug("fonts_already_loaded", families_count=len(self._loaded_families))
            return bool(self._loaded_families)

        self._fonts_loaded = True
        self._load_font_config()

        try:
            if not resource_exists("fonts"):
                _logger.warning("fonts_directory_not_found", resource_key="fonts")
                self._setup_fallback_fonts()
                return False

            fonts_dir = get_assets_path() / "fonts"

            font_files = list(fonts_dir.glob("*.ttf")) + list(fonts_dir.glob("*.otf"))

            for font_file in font_files:
                self._load_font_file(font_file)

            if not self._loaded_families:
                self._setup_fallback_fonts()
                fonts_loaded = False
            else:
                _logger.info("custom_fonts_loaded", count=len(self._loaded_families))
                self._setup_fonts_from_loaded()
                fonts_loaded = True

        except (FileNotFoundError, PermissionError) as e:
            _logger.warning("font_loading_error", error=str(e))
            self._setup_fallback_fonts()
            fonts_loaded = False

        return fonts_loaded

    def _load_font_config(self) -> None:
        """Load font configuration from font_config.json."""
        try:
            config_path = get_font_path("font_config.json")
            if config_path.exists():
                with open(config_path, encoding="utf-8") as f:
                    self._font_config = cast("dict[str, object]", json.load(f))
                    _logger.debug("font_config_loaded", config=self._font_config)
        except (json.JSONDecodeError, OSError) as e:
            _logger.debug("font_config_load_failed", error=str(e))
            self._font_config = {}

    def _load_font_file(self, font_path: Path) -> bool:
        """Load a single font file.

        Args:
            font_path: Path to the font file.

        Returns:
            bool: True if the font was loaded successfully.
        """
        font_id = QFontDatabase.addApplicationFont(str(font_path))

        if font_id < 0:
            _logger.warning("font_load_failed", path=str(font_path))
            return False

        if families := QFontDatabase.applicationFontFamilies(font_id):
            self._loaded_families.extend(families)
            _logger.debug("font_families_loaded", families=families, file=font_path.name)
            return True

        return False

    def _setup_fonts_from_loaded(self) -> None:
        """Set up code and UI fonts from loaded font families."""
        for family in self._loaded_families:
            lower_family = family.lower()
            if "mono" in lower_family or "code" in lower_family:
                if not self._code_font_family:
                    self._code_font_family = family
            elif not self._ui_font_family:
                self._ui_font_family = family

        if not self._code_font_family:
            self._code_font_family = FontManager._find_available_font(FALLBACK_CODE_FONTS)

        if not self._ui_font_family:
            self._ui_font_family = FontManager._find_available_font(FALLBACK_UI_FONTS)

    def _setup_fallback_fonts(self) -> None:
        """Set up fallback fonts when custom fonts are not available."""
        self._code_font_family = FontManager._find_available_font(FALLBACK_CODE_FONTS)
        ui_font = FontManager._find_available_font(FALLBACK_UI_FONTS)
        self._ui_font_family = ui_font if ui_font != "sans-serif" else DEFAULT_UI_FONT
        _logger.warning(
            "using_fallback_fonts",
            code_font=self._code_font_family,
            ui_font=self._ui_font_family,
            default_ui_font=DEFAULT_UI_FONT,
        )

    @staticmethod
    def _find_available_font(candidates: list[str]) -> str:
        """Find the first available font from a list of candidates.

        Args:
            candidates: List of font family names to try.

        Returns:
            str: The first available font family name, or the last candidate if none found.
        """
        families = QFontDatabase.families()

        for candidate in candidates:
            if candidate in families:
                return candidate

            for family in families:
                if candidate.lower() in family.lower():
                    return family

        return candidates[-1] if candidates else "monospace"

    def get_code_font(self, size: int = 10) -> QFont:
        """Get a font suitable for code display.

        Args:
            size: Font size in points.

        Returns:
            QFont: QFont configured for code display.
        """
        if not self._fonts_loaded:
            self.load_fonts()

        _logger.debug("get_code_font", family=self._code_font_family, size=size)
        font = QFont(self._code_font_family, size)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        return font

    def get_code_font_bold(self, size: int = 10) -> QFont:
        """Get a bold font suitable for code display.

        Args:
            size: Font size in points.

        Returns:
            QFont: QFont configured for bold code display.
        """
        font = self.get_code_font(size)
        font.setBold(True)
        return font

    def get_ui_font(self, size: int = 9) -> QFont:
        """Get a font suitable for UI elements.

        Args:
            size: Font size in points.

        Returns:
            QFont: QFont configured for UI display.
        """
        if not self._fonts_loaded:
            self.load_fonts()

        _logger.debug("get_ui_font", family=self._ui_font_family, size=size)
        font = QFont(self._ui_font_family, size)
        font.setStyleHint(QFont.StyleHint.SansSerif)
        return font

    def get_ui_font_bold(self, size: int = 9) -> QFont:
        """Get a bold font suitable for UI elements.

        Args:
            size: Font size in points.

        Returns:
            QFont: QFont configured for bold UI display.
        """
        font = self.get_ui_font(size)
        font.setBold(True)
        return font

    def get_heading_font(self, size: int = 12) -> QFont:
        """Get a font suitable for headings.

        Args:
            size: Font size in points.

        Returns:
            QFont: QFont configured for heading display.
        """
        font = self.get_ui_font(size)
        font.setBold(True)
        return font

    @property
    def code_font_family(self) -> str:
        """Get the current code font family name.

        Returns:
            str: Code font family name.
        """
        if not self._fonts_loaded:
            self.load_fonts()
        return self._code_font_family

    @property
    def ui_font_family(self) -> str:
        """Get the current UI font family name.

        Returns:
            str: UI font family name.
        """
        if not self._fonts_loaded:
            self.load_fonts()
        return self._ui_font_family

    @property
    def loaded_families(self) -> list[str]:
        """Get list of all loaded font families.

        Returns:
            list[str]: List of loaded font family names.
        """
        return self._loaded_families.copy()

    def is_custom_font_loaded(self) -> bool:
        """Check if any custom fonts were loaded.

        Returns:
            bool: True if custom fonts were loaded successfully.
        """
        return bool(self._loaded_families)

    def get_font_info(self) -> dict[str, object]:
        """Get information about loaded fonts.

        Returns:
            dict[str, object]: Dictionary with font loading status and details.
        """
        return {
            "fonts_loaded": self._fonts_loaded,
            "custom_fonts_available": self.is_custom_font_loaded(),
            "loaded_families": self._loaded_families,
            "code_font": self._code_font_family,
            "ui_font": self._ui_font_family,
            "config": self._font_config,
        }
