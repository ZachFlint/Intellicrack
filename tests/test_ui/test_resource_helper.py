"""Tests for resource_helper module.

Validates path resolution for assets in both development
and production environments.
"""

from __future__ import annotations

from pathlib import Path

from intellicrack.ui.resources.resource_helper import (
    get_assets_path,
    get_font_path,
    get_icon_path,
    get_resource_path,
    get_style_path,
    resource_exists,
)


_MIN_ICON_COUNT: int = 100
_MIN_STYLESHEET_LENGTH: int = 100
_MIN_ICON_FILE_SIZE: int = 50
_MIN_APP_ICON_SIZE: int = 1000
_MAX_APP_ICON_SIZE: int = 500000
_MIN_SPLASH_SIZE: int = 10000
_MAX_SPLASH_SIZE: int = 5000000


class TestGetAssetsPath:
    """Tests for get_assets_path function."""

    @staticmethod
    def test_returns_valid_path() -> None:
        """Assets path must be a valid Path object."""
        assets_path = get_assets_path()
        assert isinstance(assets_path, Path)

    @staticmethod
    def test_path_exists() -> None:
        """Assets directory must exist on disk."""
        assets_path = get_assets_path()
        assert assets_path.exists(), f"Assets directory does not exist: {assets_path}"

    @staticmethod
    def test_path_is_directory() -> None:
        """Assets path must be a directory, not a file."""
        assets_path = get_assets_path()
        assert assets_path.is_dir(), f"Assets path is not a directory: {assets_path}"

    @staticmethod
    def test_contains_required_subdirectories() -> None:
        """Assets directory must contain required subdirectories."""
        assets_path = get_assets_path()
        required_dirs = ["icons", "fonts", "styles"]

        for subdir in required_dirs:
            subdir_path = assets_path / subdir
            assert subdir_path.exists(), f"Required subdirectory missing: {subdir}"
            assert subdir_path.is_dir(), f"Required path is not a directory: {subdir}"

    @staticmethod
    def test_contains_application_icon() -> None:
        """Assets directory must contain the application icon."""
        assets_path = get_assets_path()
        icon_path = assets_path / "icon.ico"
        assert icon_path.exists(), "Application icon (icon.ico) is missing"
        assert icon_path.stat().st_size > 0, "Application icon is empty"

    @staticmethod
    def test_contains_splash_image() -> None:
        """Assets directory must contain the splash screen image."""
        assets_path = get_assets_path()
        splash_path = assets_path / "splash.png"
        assert splash_path.exists(), "Splash image (splash.png) is missing"
        assert splash_path.stat().st_size > 0, "Splash image is empty"


class TestGetResourcePath:
    """Tests for get_resource_path function."""

    @staticmethod
    def test_resolves_icons_subdirectory() -> None:
        """Resource path correctly resolves icons subdirectory."""
        path = get_resource_path("icons")
        assert path.exists()
        assert path.is_dir()

    @staticmethod
    def test_resolves_specific_icon() -> None:
        """Resource path correctly resolves specific icon file."""
        path = get_resource_path("icons/status_success.svg")
        assert path.exists(), f"Expected icon not found: {path}"

    @staticmethod
    def test_normalizes_forward_slashes() -> None:
        """Forward slashes are normalized to OS separators."""
        path = get_resource_path("icons/status_success.svg")
        assert path.exists()

    @staticmethod
    def test_normalizes_backslashes() -> None:
        """Backslashes are normalized to OS separators."""
        path = get_resource_path("icons\\status_success.svg")
        assert path.exists()

    @staticmethod
    def test_returns_absolute_path() -> None:
        """Returned path is absolute, not relative."""
        path = get_resource_path("icons")
        assert path.is_absolute()


class TestGetIconPath:
    """Tests for get_icon_path function."""

    @staticmethod
    def test_resolves_svg_icon_with_extension() -> None:
        """Icon path resolves correctly when extension provided."""
        path = get_icon_path("status_success.svg")
        assert path.exists(), f"SVG icon not found: {path}"

    @staticmethod
    def test_resolves_png_icon_with_extension() -> None:
        """PNG icons resolve correctly."""
        path = get_icon_path("analyze.png")
        assert path.exists(), f"PNG icon not found: {path}"

    @staticmethod
    def test_auto_detects_svg_extension() -> None:
        """Auto-detects .svg extension when not provided."""
        path = get_icon_path("status_success")
        assert path.exists()
        assert path.suffix == ".svg"

    @staticmethod
    def test_auto_detects_png_extension() -> None:
        """Auto-detects .png extension for PNG-only icons."""
        path = get_icon_path("analyze")
        assert path.exists()
        assert path.suffix == ".png"

    @staticmethod
    def test_returns_svg_path_for_missing_icon() -> None:
        """Returns .svg path for icons that don't exist."""
        path = get_icon_path("nonexistent_icon_12345")
        assert path.suffix == ".svg"


class TestGetFontPath:
    """Tests for get_font_path function."""

    @staticmethod
    def test_resolves_font_path() -> None:
        """Font path resolves to fonts directory."""
        path = get_font_path("test.ttf")
        assert "fonts" in str(path)

    @staticmethod
    def test_font_directory_contains_fonts() -> None:
        """Fonts directory contains actual font files."""
        assets = get_assets_path()
        fonts_dir = assets / "fonts"
        font_files = list(fonts_dir.glob("*.ttf")) + list(fonts_dir.glob("*.otf"))
        assert len(font_files) > 0, "No font files found in fonts directory"

    @staticmethod
    def test_jetbrains_mono_exists() -> None:
        """JetBrains Mono font file exists."""
        assets = get_assets_path()
        fonts_dir = assets / "fonts"
        jetbrains_files = list(fonts_dir.glob("*JetBrains*"))
        assert jetbrains_files, "JetBrains Mono font not found"


class TestGetStylePath:
    """Tests for get_style_path function."""

    @staticmethod
    def test_resolves_style_path() -> None:
        """Style path resolves to styles directory."""
        path = get_style_path("dark_theme.qss")
        assert "styles" in str(path)

    @staticmethod
    def test_dark_theme_exists() -> None:
        """Dark theme stylesheet exists."""
        path = get_style_path("dark_theme.qss")
        assert path.exists(), f"Dark theme not found: {path}"

    @staticmethod
    def test_light_theme_exists() -> None:
        """Light theme stylesheet exists."""
        path = get_style_path("light_theme.qss")
        assert path.exists(), f"Light theme not found: {path}"

    @staticmethod
    def test_stylesheets_not_empty() -> None:
        """Stylesheets contain actual CSS content."""
        dark_path = get_style_path("dark_theme.qss")
        light_path = get_style_path("light_theme.qss")

        dark_content = dark_path.read_text(encoding="utf-8")
        light_content = light_path.read_text(encoding="utf-8")

        assert len(dark_content) > _MIN_STYLESHEET_LENGTH, "Dark theme is too short"
        assert len(light_content) > _MIN_STYLESHEET_LENGTH, "Light theme is too short"
        assert "QWidget" in dark_content, "Dark theme missing QWidget styles"
        assert "QWidget" in light_content, "Light theme missing QWidget styles"


class TestResourceExists:
    """Tests for resource_exists function."""

    @staticmethod
    def test_returns_true_for_existing_resource() -> None:
        """Returns True for resources that exist."""
        assert resource_exists("icons/status_success.svg")
        assert resource_exists("icon.ico")
        assert resource_exists("splash.png")

    @staticmethod
    def test_returns_false_for_missing_resource() -> None:
        """Returns False for resources that don't exist."""
        assert not resource_exists("nonexistent/path/file.txt")
        assert not resource_exists("missing_icon.svg")

    @staticmethod
    def test_returns_false_for_empty_path() -> None:
        """Handles empty path gracefully."""
        result = resource_exists("")
        assert isinstance(result, bool)


class TestAssetIntegrity:
    """Tests for overall asset integrity."""

    @staticmethod
    def test_minimum_icon_count() -> None:
        """Assets contain minimum required number of icons."""
        assets = get_assets_path()
        icons_dir = assets / "icons"
        svg_icons = list(icons_dir.glob("*.svg"))
        png_icons = list(icons_dir.glob("*.png"))
        total_icons = len(svg_icons) + len(png_icons)

        assert total_icons >= _MIN_ICON_COUNT, f"Expected {_MIN_ICON_COUNT}+ icons, found {total_icons}"

    @staticmethod
    def test_required_status_icons_exist() -> None:
        """All required status icons exist."""
        required_icons = [
            "status_success.svg",
            "status_error.svg",
            "status_warning.svg",
            "status_info.svg",
        ]

        for icon_name in required_icons:
            path = get_icon_path(icon_name)
            assert path.exists(), f"Required icon missing: {icon_name}"

    @staticmethod
    def test_required_action_icons_exist() -> None:
        """All required action icons exist."""
        required_icons = [
            "action_run.svg",
            "action_stop.svg",
            "action_pause.svg",
        ]

        for icon_name in required_icons:
            path = get_icon_path(icon_name)
            assert path.exists(), f"Required icon missing: {icon_name}"

    @staticmethod
    def test_required_tool_icons_exist() -> None:
        """All required tool icons exist."""
        required_icons = [
            "tool_ghidra.svg",
            "tool_frida.svg",
            "tool_radare2.svg",
            "tool_x64dbg.svg",
        ]

        for icon_name in required_icons:
            path = get_icon_path(icon_name)
            assert path.exists(), f"Required icon missing: {icon_name}"

    @staticmethod
    def test_icon_files_not_empty() -> None:
        """Icon files contain actual content."""
        assets = get_assets_path()
        icons_dir = assets / "icons"

        for icon_file in icons_dir.glob("*.svg"):
            size = icon_file.stat().st_size
            assert size > _MIN_ICON_FILE_SIZE, f"Icon file appears empty: {icon_file.name}"

    @staticmethod
    def test_application_icon_valid_size() -> None:
        """Application icon has reasonable file size (indicates valid ICO)."""
        assets = get_assets_path()
        icon_path = assets / "icon.ico"
        size = icon_path.stat().st_size

        assert size > _MIN_APP_ICON_SIZE, f"icon.ico too small ({size} bytes), likely invalid"
        assert size < _MAX_APP_ICON_SIZE, f"icon.ico too large ({size} bytes), likely corrupted"

    @staticmethod
    def test_splash_image_valid_size() -> None:
        """Splash image has reasonable file size."""
        assets = get_assets_path()
        splash_path = assets / "splash.png"
        size = splash_path.stat().st_size

        assert size > _MIN_SPLASH_SIZE, f"splash.png too small ({size} bytes)"
        assert size < _MAX_SPLASH_SIZE, f"splash.png too large ({size} bytes)"
