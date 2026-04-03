# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Icon management for Intellicrack UI.

Provides centralized icon loading with caching and fallback support.
"""

from __future__ import annotations

from typing import ClassVar, Final

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.resource_helper import get_assets_path, get_icon_path
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger("ui.resources.icons")


ICON_MAP: Final[dict[str, str]] = {
    "app": "ai_brain.svg",
    "binary": "binary_exe.svg",
    "tools": "tool_x64dbg.svg",
    "provider": "ai_model.svg",
    "sandbox": "security_shield.svg",
    "process": "action_run.svg",
    "action_build": "action_build.svg",
    "action_debug": "action_debug.svg",
    "action_deploy": "action_deploy.svg",
    "action_generate": "action_generate.svg",
    "action_pause": "action_pause.svg",
    "action_restart": "action_restart.svg",
    "action_run": "action_run.svg",
    "action_stop": "action_stop.svg",
    "action_test": "action_test.svg",
    "ai_brain": "ai_brain.svg",
    "ai_inference": "ai_inference.svg",
    "ai_model": "ai_model.svg",
    "ai_neural": "ai_neural.svg",
    "ai_training": "ai_training.svg",
    "binary_disasm": "binary_disasm.svg",
    "binary_dll": "binary_dll.svg",
    "binary_entropy": "binary_entropy.svg",
    "binary_exe": "binary_exe.svg",
    "binary_hex": "binary_hex.svg",
    "binary_so": "binary_so.svg",
    "db_connect": "db_connect.svg",
    "db_export": "db_export.svg",
    "db_query": "db_query.svg",
    "db_table": "db_table.svg",
    "edit_copy": "edit_copy.svg",
    "edit_cut": "edit_cut.svg",
    "edit_delete": "edit_delete.svg",
    "edit_paste": "edit_paste.svg",
    "edit_redo": "edit_redo.svg",
    "edit_replace": "edit_replace.svg",
    "edit_search": "edit_search.svg",
    "edit_undo": "edit_undo.svg",
    "file_close": "file_close.svg",
    "file_import": "file_import.svg",
    "file_new": "file_new.svg",
    "file_open": "file_open.svg",
    "file_save": "file_save.svg",
    "file_save_as": "file_save_as.svg",
    "help_about": "help_about.svg",
    "help_docs": "help_docs.svg",
    "help_documentation": "help_documentation.svg",
    "help_support": "help_support.svg",
    "help_tutorial": "help_tutorial.svg",
    "nav_back": "nav_back.svg",
    "nav_down": "nav_down.svg",
    "nav_forward": "nav_forward.svg",
    "nav_home": "nav_home.svg",
    "nav_refresh": "nav_refresh.svg",
    "nav_up": "nav_up.svg",
    "security_firewall": "security_firewall.svg",
    "security_key": "security_key.svg",
    "security_lock": "security_lock.svg",
    "security_scan": "security_scan.svg",
    "security_shield": "security_shield.svg",
    "security_warning": "security_warning.svg",
    "status_error": "status_error.svg",
    "status_idle": "status_idle.svg",
    "status_info": "status_info.svg",
    "status_loading": "status_loading.svg",
    "status_question": "status_question.svg",
    "status_ready": "status_ready.svg",
    "status_success": "status_success.svg",
    "status_warning": "status_warning.svg",
    "tool_cheat_engine": "tool_cheat_engine.svg",
    "tool_frida": "tool_frida.svg",
    "tool_gdb": "tool_gdb.svg",
    "tool_ghidra": "tool_ghidra.svg",
    "tool_ollydbg": "tool_ollydbg.svg",
    "tool_cutter": "tool_cutter.svg",
    "tool_x64dbg": "tool_x64dbg.svg",
    "accessories_text_editor": "accessories-text-editor.png",
    "ai_assistant": "ai-assistant.png",
    "application_certificate": "application-certificate.png",
    "binary_file": "binary-file-icon.png",
    "cancel_button": "cancel-button.png",
    "computer": "computer-icon.png",
    "desktop": "desktop-icon.png",
    "detailed_view": "detailed-view.png",
    "dialog_auth": "dialog-password.png",
    "document_edit": "document-edit.png",
    "document_open": "document-open.png",
    "document_save": "document-save.png",
    "document_save_as": "document-save-as.png",
    "file": "file-icon.png",
    "folder": "folder-icon.png",
    "frida_tool": "frida-tool.png",
    "ghidra_tool": "ghidra-tool.png",
    "import": "import.png",
    "export": "export.png",
    "list_add": "list-add.png",
    "mail_send": "mail-send.png",
    "media_play": "media-play.png",
    "media_playback_start": "media-playback-start.png",
    "network_server": "network-server.png",
    "network_workgroup": "network-workgroup.png",
    "package_generic": "package-x-generic.png",
    "preferences_system": "preferences-system.png",
    "progress_spinner": "progress-spinner.png",
    "python_file": "python-file-icon.png",
    "refresh": "refresh.png",
    "security_medium": "security-medium.png",
    "settings": "settings.png",
    "stop": "stop.png",
    "system_search": "system-search.png",
    "analyze": "analyze.png",
    "open": "open.png",
    "vulnerability": "vulnerability.png",
}

UNICODE_FALLBACK: Final[dict[str, str]] = {
    "app": "\u2699",
    "binary": "\u2b22",
    "tools": "\u2692",
    "provider": "\u2601",
    "sandbox": "\u2610",
    "process": "\u2699",
    "status_success": "\u2713",
    "status_error": "\u2717",
    "status_warning": "\u26a0",
    "status_info": "\u2139",
    "status_question": "?",
    "status_loading": "\u23f3",
    "status_idle": "\u25cf",
    "status_ready": "\u25cf",
    "action_run": "\u25b6",
    "action_stop": "\u25a0",
    "action_pause": "\u23f8",
    "action_restart": "\u21bb",
    "nav_back": "\u2190",
    "nav_forward": "\u2192",
    "nav_up": "\u2191",
    "nav_down": "\u2193",
    "nav_home": "\u2302",
    "nav_refresh": "\u21bb",
    "file_new": "+",
    "file_open": "\U0001f4c2",
    "file_save": "\U0001f4be",
    "file_close": "\u2715",
    "edit_copy": "\U0001f4cb",
    "edit_cut": "\u2702",
    "edit_paste": "\U0001f4cb",
    "edit_delete": "\u2715",
    "edit_undo": "\u21b6",
    "edit_redo": "\u21b7",
    "edit_search": "\U0001f50d",
    "security_lock": "\U0001f512",
    "security_key": "\U0001f511",
    "security_shield": "\U0001f6e1",
    "security_warning": "\u26a0",
    "binary_exe": "\U0001f4e6",
    "binary_dll": "\U0001f4e6",
    "ai_brain": "\U0001f9e0",
    "tool_ghidra": "G",
    "tool_frida": "F",
    "tool_cutter": "C",
    "tool_x64dbg": "x64",
    "tool_gdb": "gdb",
}


class IconManager:
    """Singleton icon manager with caching and fallback support.

    Provides centralized icon loading for the Intellicrack UI with performance optimization through caching and graceful degradation when
    icon files are not available.
    """

    _instance: ClassVar[IconManager | None] = None

    def __init__(self) -> None:
        self.icon_cache: dict[str, QIcon] = {}
        self.pixmap_cache: dict[tuple[str, int], QPixmap] = {}
        self.icons_available: bool = self._check_icons_available()

    @classmethod
    def get_instance(cls) -> IconManager:
        """Get the singleton instance of IconManager.

        Returns:
            IconManager: The IconManager singleton instance.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (primarily for testing)."""
        cls._instance = None

    @staticmethod
    def _check_icons_available() -> bool:
        """Check if the icons directory is available.

        Returns:
            bool: True if icons directory exists and contains files.
        """
        try:
            icons_dir = get_assets_path() / "icons"
            available = any(icons_dir.iterdir()) if icons_dir.exists() else False
            _logger.debug("icons_availability_check", available=available, path=str(icons_dir))
        except (FileNotFoundError, PermissionError) as exc:
            _logger.exception("icons_availability_check_failed", error=str(exc))
            return False
        else:
            return available

    def get_icon(self, name: str, size: int = 24) -> QIcon:
        """Get an icon by name with caching.

        Args:
            name: Icon name (key in ICON_MAP or filename without extension).
            size: Preferred icon size in pixels.

        Returns:
            QIcon: QIcon instance (may be empty if icon not found and no fallback).
        """
        cache_key = f"{name}_{size}"
        if cache_key in self.icon_cache:
            _logger.debug("icon_cache_hit", icon_name=name, size=size)
            return self.icon_cache[cache_key]

        _logger.debug("icon_cache_miss", icon_name=name, size=size)
        icon = self._load_icon(name, size)
        self.icon_cache[cache_key] = icon
        return icon

    def _load_icon(self, name: str, size: int) -> QIcon:
        """Load an icon from file or generate fallback.

        Args:
            name: Icon name.
            size: Preferred icon size.

        Returns:
            QIcon: QIcon instance.
        """
        if self.icons_available:
            filename = ICON_MAP.get(name, f"{name}.svg")
            icon_path = get_icon_path(filename)

            if icon_path.exists():
                icon = QIcon(str(icon_path))
                if not icon.isNull():
                    _logger.debug("icon_loaded_from_file", icon_name=name, path=str(icon_path))
                    return icon
                _logger.warning("icon_load_failed", icon_path=str(icon_path))
            else:
                _logger.debug("icon_file_not_found", icon_name=name, path=str(icon_path))

        _logger.warning("icon_using_fallback", icon_name=name, size=size)
        return IconManager._create_fallback_icon(name, size)

    @staticmethod
    def _create_fallback_icon(name: str, size: int) -> QIcon:
        """Create a fallback icon using Unicode characters.

        Args:
            name: Icon name for fallback lookup.
            size: Icon size in pixels.

        Returns:
            QIcon: QIcon with rendered Unicode character or empty icon.
        """
        if fallback_char := UNICODE_FALLBACK.get(name, ""):
            _logger.debug("fallback_icon_generated", icon_name=name, char=fallback_char, size=size)
            return IconManager._render_text_icon(fallback_char, size)
        _logger.warning("no_fallback_icon_available", icon_name=name)
        return QIcon()

    @staticmethod
    def _render_text_icon(
        text: str,
        size: int,
        color: QColor | None = None,
    ) -> QIcon:
        """Render a text character as an icon.

        Args:
            text: Character or text to render.
            size: Icon size in pixels.
            color: Text color (defaults to light gray).

        Returns:
            QIcon: QIcon containing the rendered text.
        """
        if color is None:
            color = QColor("#d4d4d4") if ThemeManager.get_instance().is_dark_theme() else QColor("#1a1a1a")

        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(0, 0, 0, 0))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        font = painter.font()
        font.setPixelSize(int(size * 0.7))
        painter.setFont(font)

        painter.setPen(color)
        painter.drawText(
            pixmap.rect(),
            Qt.AlignmentFlag.AlignCenter,
            text,
        )
        painter.end()

        return QIcon(pixmap)

    def get_pixmap(self, name: str, size: int = 24) -> QPixmap:
        """Get a pixmap by icon name.

        Args:
            name: Icon name.
            size: Desired pixmap size.

        Returns:
            QPixmap: QPixmap of the requested size.
        """
        cache_key = (name, size)
        if cache_key in self.pixmap_cache:
            _logger.debug("pixmap_cache_hit", icon_name=name, size=size)
            return self.pixmap_cache[cache_key]

        _logger.debug("pixmap_cache_miss", icon_name=name, size=size)
        icon = self.get_icon(name, size)
        pixmap = icon.pixmap(QSize(size, size))
        self.pixmap_cache[cache_key] = pixmap
        return pixmap

    def get_app_icon(self) -> QIcon:
        """Get the main application icon.

        Returns:
            QIcon: QIcon for the application window and taskbar.
        """
        if "app_icon" in self.icon_cache:
            return self.icon_cache["app_icon"]

        try:
            icon_path = get_assets_path() / "icon.ico"
            if icon_path.exists():
                icon = QIcon(str(icon_path))
                if not icon.isNull():
                    _logger.debug("app_icon_loaded", path=str(icon_path))
                    self.icon_cache["app_icon"] = icon
                    return icon
                _logger.warning("app_icon_load_failed", path=str(icon_path))
        except FileNotFoundError:
            _logger.warning("app_icon_not_found")

        _logger.debug("app_icon_using_fallback")
        accent = QColor("#007acc") if ThemeManager.get_instance().is_dark_theme() else QColor("#0078d4")
        fallback = IconManager._render_text_icon("IC", 256, accent)
        self.icon_cache["app_icon"] = fallback
        return fallback

    def get_status_icon(self, *, success: bool) -> QIcon:
        """Get a status icon indicating success or failure.

        Args:
            success: True for success icon, False for error icon.

        Returns:
            QIcon: Appropriate status icon.
        """
        name = "status_success" if success else "status_error"
        return self.get_icon(name)

    def get_status_pixmap(self, *, success: bool, size: int = 16) -> QPixmap:
        """Get a status pixmap indicating success or failure.

        Args:
            success: True for success, False for error.
            size: Pixmap size in pixels.

        Returns:
            QPixmap: Appropriate status pixmap.
        """
        name = "status_success" if success else "status_error"
        return self.get_pixmap(name, size)

    def clear_cache(self) -> None:
        """Clear all cached icons and pixmaps."""
        icon_count = len(self.icon_cache)
        pixmap_count = len(self.pixmap_cache)
        self.icon_cache.clear()
        self.pixmap_cache.clear()
        _logger.debug(
            "icon_cache_cleared",
            icons_cleared=icon_count,
            pixmaps_cleared=pixmap_count,
        )

    def preload_icons(self, names: list[str] | None = None) -> None:
        """Preload icons into cache for faster access.

        Args:
            names: List of icon names to preload. If None, preloads common icons.
        """
        if names is None:
            names = [
                "status_success",
                "status_error",
                "status_warning",
                "status_info",
                "action_run",
                "action_stop",
                "file_open",
                "file_save",
            ]

        _logger.debug("preloading_icons", count=len(names))
        for name in names:
            self.get_icon(name)

    @staticmethod
    def list_available_icons() -> list[str]:
        """List all available icon names.

        Returns:
            list[str]: List of icon names from ICON_MAP.
        """
        return list(ICON_MAP.keys())

    def icon_exists(self, name: str) -> bool:
        """Check if an icon file exists.

        Args:
            name: Icon name to check.

        Returns:
            bool: True if the icon file exists.
        """
        if not self.icons_available:
            return False

        filename = ICON_MAP.get(name, f"{name}.svg")
        icon_path = get_icon_path(filename)
        return icon_path.exists()
