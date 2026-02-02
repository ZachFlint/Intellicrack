"""Resource path resolution for Intellicrack assets.

Provides centralized path resolution supporting both development environments
and PyInstaller frozen applications.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

from ...core.logging import get_logger


_logger = get_logger("ui.resources.helper")

_ASSETS_DIR_NAME: Final[str] = "assets"
_PACKAGE_NAME: Final[str] = "intellicrack"


def _get_package_root() -> Path:
    """Get the root directory of the intellicrack package.

    Returns:
        Path to the package root directory.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass: str = getattr(sys, "_MEIPASS")  # noqa: B009
        base_path = Path(meipass)
        package_path = base_path / _PACKAGE_NAME
        return package_path if package_path.exists() else base_path
    current_file = Path(__file__).resolve()
    ui_resources_dir = current_file.parent
    ui_dir = ui_resources_dir.parent
    return ui_dir.parent


def get_assets_path() -> Path:
    """Get the path to the assets directory.

    Returns:
        Path to the assets directory.

    Raises:
        FileNotFoundError: If the assets directory cannot be found.
    """
    package_root = _get_package_root()
    assets_path = package_root / _ASSETS_DIR_NAME

    if assets_path.exists():
        _logger.debug("assets_path_found", extra={"path": str(assets_path)})
        return assets_path

    search_paths = [
        package_root / _ASSETS_DIR_NAME,
        package_root.parent / _ASSETS_DIR_NAME,
        package_root.parent / _PACKAGE_NAME / _ASSETS_DIR_NAME,
    ]

    for path in search_paths:
        if path.exists():
            _logger.debug("assets_path_found", extra={"path": str(path)})
            return path

    _logger.error(
        "assets_path_not_found",
        extra={"searched_paths": [str(p) for p in search_paths]},
    )
    raise FileNotFoundError(  # noqa: TRY003
        f"Assets directory not found. Searched: {[str(p) for p in search_paths]}"
    )


def get_resource_path(resource_path: str) -> Path:
    """Resolve a resource path relative to the assets directory.

    Args:
        resource_path: Relative path to the resource within assets directory.
            Forward slashes are automatically converted to OS-specific separators.

    Returns:
        Absolute path to the resource.

    Example:
        >>> path = get_resource_path("icons/status_success.svg")
        >>> print(path)
        /path/to/intellicrack/assets/icons/status_success.svg
    """
    normalized_path = resource_path.replace("/", os.sep).replace("\\", os.sep)
    assets_dir = get_assets_path()
    resolved = assets_dir / normalized_path
    _logger.debug("resource_path_resolved", extra={"resource": resource_path, "resolved": str(resolved)})
    return resolved


def get_icon_path(icon_name: str) -> Path:
    """Get the path to an icon file.

    Args:
        icon_name: Name of the icon file (with or without extension).

    Returns:
        Path to the icon file.
    """
    icons_dir = get_assets_path() / "icons"

    if "." in icon_name:
        resolved = icons_dir / icon_name
        _logger.debug("icon_path_resolved", extra={"icon_name": icon_name, "path": str(resolved)})
        return resolved

    for ext in (".svg", ".png", ".ico"):
        path = icons_dir / f"{icon_name}{ext}"
        if path.exists():
            _logger.debug("icon_path_resolved", extra={"icon_name": icon_name, "path": str(path)})
            return path

    fallback_path = icons_dir / f"{icon_name}.svg"
    _logger.debug("icon_path_fallback", extra={"icon_name": icon_name, "path": str(fallback_path)})
    return fallback_path


def get_font_path(font_name: str) -> Path:
    """Get the path to a font file.

    Args:
        font_name: Name of the font file.

    Returns:
        Path to the font file.
    """
    resolved = get_assets_path() / "fonts" / font_name
    _logger.debug("font_path_resolved", extra={"font_name": font_name, "path": str(resolved)})
    return resolved


def get_style_path(style_name: str) -> Path:
    """Get the path to a stylesheet file.

    Args:
        style_name: Name of the stylesheet file.

    Returns:
        Path to the stylesheet file.
    """
    resolved = get_assets_path() / "styles" / style_name
    _logger.debug("style_path_resolved", extra={"style_name": style_name, "path": str(resolved)})
    return resolved


def resource_exists(resource_path: str) -> bool:
    """Check if a resource exists.

    Args:
        resource_path: Relative path to the resource within assets directory.

    Returns:
        True if the resource exists, False otherwise.
    """
    try:
        path = get_resource_path(resource_path)
        exists = path.exists()
        _logger.debug("resource_exists_check", extra={"resource": resource_path, "exists": exists})
    except FileNotFoundError:
        _logger.warning("resource_not_found", extra={"resource": resource_path})
        return False
    else:
        return exists
