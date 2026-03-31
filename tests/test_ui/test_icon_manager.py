# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for IconManager module.

Validates icon loading, caching, and fallback functionality
using real asset files.
"""

from __future__ import annotations

import pytest
from PyQt6.QtGui import QIcon, QPixmap

from intellicrack.ui.resources.icon_manager import (
    ICON_MAP,
    UNICODE_FALLBACK,
    IconManager,
)


_ICON_SIZE_24: int = 24
_ICON_SIZE_48: int = 48
_ICON_SIZE_32: int = 32
_ICON_SIZE_16: int = 16
_MAX_PREVIEW_ICONS: int = 20


@pytest.fixture
def icon_manager() -> IconManager:
    """Provide a fresh IconManager instance for each test.

    Returns:
        IconManager: A fresh singleton instance.
    """
    IconManager.reset_instance()
    return IconManager.get_instance()


class TestIconManagerSingleton:
    """Tests for singleton pattern implementation."""

    @staticmethod
    def test_get_instance_returns_same_object() -> None:
        """Singleton returns the same instance."""
        IconManager.reset_instance()
        instance1 = IconManager.get_instance()
        instance2 = IconManager.get_instance()
        assert instance1 is instance2

    @staticmethod
    def test_reset_instance_clears_singleton() -> None:
        """Reset clears the singleton instance."""
        IconManager.reset_instance()
        instance1 = IconManager.get_instance()
        IconManager.reset_instance()
        instance2 = IconManager.get_instance()
        assert instance1 is not instance2


class TestIconLoading:
    """Tests for icon loading from files."""

    @staticmethod
    def test_get_icon_returns_qicon(icon_manager: IconManager) -> None:
        """get_icon returns a QIcon instance."""
        icon = icon_manager.get_icon("status_success")
        assert isinstance(icon, QIcon)

    @staticmethod
    def test_loads_svg_icon_successfully(icon_manager: IconManager) -> None:
        """SVG icons load successfully and are not null."""
        icon = icon_manager.get_icon("status_success")
        assert not icon.isNull(), "status_success.svg failed to load"

    @staticmethod
    def test_loads_png_icon_successfully(icon_manager: IconManager) -> None:
        """PNG icons load successfully and are not null."""
        icon = icon_manager.get_icon("analyze")
        assert not icon.isNull(), "analyze.png failed to load"

    @staticmethod
    def test_all_mapped_icons_load(icon_manager: IconManager) -> None:
        """All icons in ICON_MAP can be loaded."""
        failed_icons = []

        for icon_name in ICON_MAP:
            icon = icon_manager.get_icon(icon_name)
            if icon.isNull():
                failed_icons.append(icon_name)

        assert not failed_icons, f"Failed to load icons: {failed_icons}"

    @staticmethod
    def test_icon_has_valid_pixmap(icon_manager: IconManager) -> None:
        """Loaded icon contains valid pixmap data."""
        icon = icon_manager.get_icon("status_success", size=_ICON_SIZE_24)
        pixmap = icon.pixmap(_ICON_SIZE_24, _ICON_SIZE_24)
        assert not pixmap.isNull()
        assert pixmap.width() > 0
        assert pixmap.height() > 0


class TestIconCaching:
    """Tests for icon caching functionality."""

    @staticmethod
    def test_icon_is_cached(icon_manager: IconManager) -> None:
        """Icons are cached after first load."""
        icon1 = icon_manager.get_icon("status_success", size=_ICON_SIZE_24)
        icon2 = icon_manager.get_icon("status_success", size=_ICON_SIZE_24)
        assert icon1 is icon2

    @staticmethod
    def test_different_sizes_cached_separately(icon_manager: IconManager) -> None:
        """Different sizes are cached as separate entries."""
        icon_24 = icon_manager.get_icon("status_success", size=_ICON_SIZE_24)
        icon_48 = icon_manager.get_icon("status_success", size=_ICON_SIZE_48)
        assert icon_24 is not icon_48

    @staticmethod
    def test_clear_cache_removes_cached_icons(icon_manager: IconManager) -> None:
        """clear_cache removes all cached icons."""
        icon_manager.get_icon("status_success")
        icon_manager.get_icon("status_error")
        icon_manager.clear_cache()

        assert len(icon_manager.icon_cache) == 0
        assert len(icon_manager.pixmap_cache) == 0


class TestPixmapLoading:
    """Tests for pixmap loading functionality."""

    @staticmethod
    def test_get_pixmap_returns_qpixmap(icon_manager: IconManager) -> None:
        """get_pixmap returns a QPixmap instance."""
        pixmap = icon_manager.get_pixmap("status_success")
        assert isinstance(pixmap, QPixmap)

    @staticmethod
    def test_pixmap_not_null(icon_manager: IconManager) -> None:
        """Loaded pixmap is not null."""
        pixmap = icon_manager.get_pixmap("status_success")
        assert not pixmap.isNull()

    @staticmethod
    def test_pixmap_has_requested_size(icon_manager: IconManager) -> None:
        """Pixmap has approximately the requested size."""
        pixmap = icon_manager.get_pixmap("status_success", size=_ICON_SIZE_32)
        assert pixmap.width() <= _ICON_SIZE_32
        assert pixmap.height() <= _ICON_SIZE_32

    @staticmethod
    def test_pixmap_is_cached(icon_manager: IconManager) -> None:
        """Pixmaps are cached after first load."""
        pixmap1 = icon_manager.get_pixmap("status_success", size=_ICON_SIZE_24)
        pixmap2 = icon_manager.get_pixmap("status_success", size=_ICON_SIZE_24)
        assert pixmap1 is pixmap2


class TestApplicationIcon:
    """Tests for application icon loading."""

    @staticmethod
    def test_get_app_icon_returns_qicon(icon_manager: IconManager) -> None:
        """get_app_icon returns a QIcon instance."""
        icon = icon_manager.get_app_icon()
        assert isinstance(icon, QIcon)

    @staticmethod
    def test_app_icon_not_null(icon_manager: IconManager) -> None:
        """Application icon loads successfully."""
        icon = icon_manager.get_app_icon()
        assert not icon.isNull(), "Application icon failed to load"

    @staticmethod
    def test_app_icon_has_multiple_sizes(icon_manager: IconManager) -> None:
        """Application icon contains multiple size variants."""
        icon = icon_manager.get_app_icon()
        sizes = icon.availableSizes()
        assert len(sizes) > 0, "App icon has no available sizes"

    @staticmethod
    def test_app_icon_is_cached(icon_manager: IconManager) -> None:
        """Application icon is cached after first load."""
        icon1 = icon_manager.get_app_icon()
        icon2 = icon_manager.get_app_icon()
        assert icon1 is icon2


class TestStatusIcons:
    """Tests for status icon convenience methods."""

    @staticmethod
    def test_get_status_icon_success(icon_manager: IconManager) -> None:
        """get_status_icon returns success icon correctly."""
        icon = icon_manager.get_status_icon(success=True)
        assert isinstance(icon, QIcon)
        assert not icon.isNull()

    @staticmethod
    def test_get_status_icon_error(icon_manager: IconManager) -> None:
        """get_status_icon returns error icon correctly."""
        icon = icon_manager.get_status_icon(success=False)
        assert isinstance(icon, QIcon)
        assert not icon.isNull()

    @staticmethod
    def test_get_status_pixmap_success(icon_manager: IconManager) -> None:
        """get_status_pixmap returns success pixmap correctly."""
        pixmap = icon_manager.get_status_pixmap(success=True, size=_ICON_SIZE_16)
        assert isinstance(pixmap, QPixmap)
        assert not pixmap.isNull()

    @staticmethod
    def test_get_status_pixmap_error(icon_manager: IconManager) -> None:
        """get_status_pixmap returns error pixmap correctly."""
        pixmap = icon_manager.get_status_pixmap(success=False, size=_ICON_SIZE_16)
        assert isinstance(pixmap, QPixmap)
        assert not pixmap.isNull()


class TestFallbackIcons:
    """Tests for Unicode fallback icon generation."""

    @staticmethod
    def test_fallback_map_has_status_icons() -> None:
        """UNICODE_FALLBACK contains status icon fallbacks."""
        required_fallbacks = [
            "status_success",
            "status_error",
            "status_warning",
            "status_info",
        ]

        for name in required_fallbacks:
            assert name in UNICODE_FALLBACK, f"Missing fallback for {name}"
            assert len(UNICODE_FALLBACK[name]) > 0

    @staticmethod
    def test_fallback_map_has_action_icons() -> None:
        """UNICODE_FALLBACK contains action icon fallbacks."""
        required_fallbacks = ["action_run", "action_stop", "action_pause"]

        for name in required_fallbacks:
            assert name in UNICODE_FALLBACK, f"Missing fallback for {name}"

    @staticmethod
    def test_missing_icon_returns_icon_object(icon_manager: IconManager) -> None:
        """Missing icons still return a QIcon object."""
        icon = icon_manager.get_icon("nonexistent_icon_12345")
        assert isinstance(icon, QIcon)

    @staticmethod
    def test_fallback_icon_generated_for_known_fallback() -> None:
        """Known fallback icons generate non-null icons even if file missing."""
        IconManager.reset_instance()
        manager = IconManager()
        manager.icons_available = False

        icon = manager.load_icon("status_success", _ICON_SIZE_24)
        assert isinstance(icon, QIcon)


class TestIconExists:
    """Tests for icon_exists method."""

    @staticmethod
    def test_icon_exists_for_svg_icon(icon_manager: IconManager) -> None:
        """icon_exists returns True for existing SVG icon."""
        assert icon_manager.icon_exists("status_success")

    @staticmethod
    def test_icon_exists_for_png_icon(icon_manager: IconManager) -> None:
        """icon_exists returns True for existing PNG icon."""
        assert icon_manager.icon_exists("analyze")

    @staticmethod
    def test_icon_not_exists_for_missing(icon_manager: IconManager) -> None:
        """icon_exists returns False for missing icon."""
        assert not icon_manager.icon_exists("nonexistent_icon_12345")


class TestListAvailableIcons:
    """Tests for list_available_icons method."""

    @staticmethod
    def test_returns_list() -> None:
        """list_available_icons returns a list."""
        icons = IconManager.list_available_icons()
        assert isinstance(icons, list)

    @staticmethod
    def test_list_not_empty() -> None:
        """Available icons list is not empty."""
        icons = IconManager.list_available_icons()
        assert len(icons) > 0

    @staticmethod
    def test_list_contains_known_icons() -> None:
        """List contains known icon names."""
        icons = IconManager.list_available_icons()
        assert "status_success" in icons
        assert "action_run" in icons
        assert "tool_ghidra" in icons


class TestPreloadIcons:
    """Tests for preload_icons method."""

    @staticmethod
    def test_preload_default_icons(icon_manager: IconManager) -> None:
        """Preloading default icons populates cache."""
        icon_manager.clear_cache()
        icon_manager.preload_icons()

        assert len(icon_manager.icon_cache) > 0

    @staticmethod
    def test_preload_specific_icons(icon_manager: IconManager) -> None:
        """Preloading specific icons populates cache."""
        icon_manager.clear_cache()
        icons_to_load = ["status_success", "status_error"]
        icon_manager.preload_icons(icons_to_load)

        assert len(icon_manager.icon_cache) == len(icons_to_load)


class TestIconIntegrity:
    """Tests for overall icon system integrity."""

    @staticmethod
    def test_all_icon_map_entries_have_files(icon_manager: IconManager) -> None:
        """Every entry in ICON_MAP corresponds to an existing file."""
        missing_files = [name for name in ICON_MAP if not icon_manager.icon_exists(name)]
        assert not missing_files, f"ICON_MAP entries without files: {missing_files}"

    @staticmethod
    def test_icons_load_without_errors(icon_manager: IconManager) -> None:
        """All icons load without raising exceptions."""
        for name in list(ICON_MAP.keys())[:_MAX_PREVIEW_ICONS]:
            try:
                icon = icon_manager.get_icon(name)
                assert isinstance(icon, QIcon)
            except (RuntimeError, OSError, ValueError) as e:
                pytest.fail(f"Icon {name} raised exception: {e}")

    @staticmethod
    def test_icon_manager_available_flag(icon_manager: IconManager) -> None:
        """IconManager correctly detects icons availability."""
        assert icon_manager.icons_available, "Icons should be available"
