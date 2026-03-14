# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Main application window for Intellicrack.

This module provides the main PyQt6 application window that combines
all UI components and connects them to the orchestrator.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QToolBar,
    QWidget,
)

from .._metadata import __copyright__, __license__, __version__
from ..bridges.installer import ToolInstaller
from ..core.config import get_config_dir, get_config_file
from ..core.logging import get_logger
from ..core.script_gen import ScriptManager
from ..core.types import Message, ModelInfo, ProviderCredentials, ProviderName, ToolCall, ToolName, ToolResult
from ..providers.discovery import ModelDiscovery
from ..sandbox import SandboxManager
from ._screen_compat import get_screen_geometry, move_widget
from .chat import ChatPanel
from .provider_config import ModelRefreshWorker, ModelSelectionDialog, ProviderConfigDialog
from .resources import FontManager, IconManager, ThemeManager
from .sandbox_config import SandboxConfigDialog
from .session_manager import SessionManagerDialog
from .tool_config import ToolConfigDialog, ToolStatusDialog
from .tools import ToolOutputPanel


try:
    from ..providers.model_loader import get_global_model_cache, set_global_cache_size
except ImportError:
    get_logger("ui.app").debug("model_loader_unavailable")
    get_global_model_cache = None
    set_global_cache_size = None


if TYPE_CHECKING:
    import types
    from collections.abc import Callable, Coroutine

    from PyQt6.QtGui import QCloseEvent

    from ..core.config import Config
    from ..core.orchestrator import Orchestrator


_logger = get_logger("ui.app")

_MAX_RESULT_DISPLAY_LEN = 500

_original_excepthook = sys.excepthook


def _unhandled_exception_hook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_tb: types.TracebackType | None,
) -> None:
    """Global exception hook for unhandled exceptions during Qt event loop.

    Args:
        exc_type: Exception type.
        exc_value: Exception instance.
        exc_tb: Traceback object.
    """
    _logger.critical(
        "unhandled_exception",
        exc_type=exc_type.__name__,
        exc_value=str(exc_value),
        exc_info=(exc_type, exc_value, exc_tb),
    )
    _original_excepthook(exc_type, exc_value, exc_tb)


class AsyncWorker(QThread):
    """Worker thread for running async operations.

    Runs an asyncio event loop in a separate thread to execute
    async operations without blocking the UI.
    """

    finished = pyqtSignal(object)
    error = pyqtSignal(Exception)

    def __init__(
        self,
        coro: Coroutine[object, object, object],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the async worker.

        Args:
            coro: Coroutine to execute.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._coro: Coroutine[object, object, object] = coro

    def run(self) -> None:
        """Run the coroutine in a new event loop."""
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result: object = loop.run_until_complete(self._coro)
            self.finished.emit(result)
        except Exception as e:
            _logger.exception("async_worker_failed")
            self.error.emit(e)
        finally:
            if loop is not None:
                loop.close()


class MainWindow(QMainWindow):
    """Main application window for Intellicrack.

    Combines chat panel, tool output panel, menus, and toolbar
    into the main application interface.
    """

    message_received = pyqtSignal(Message)
    tool_call_received = pyqtSignal(ToolCall)
    tool_result_received = pyqtSignal(ToolResult)
    stream_chunk_received = pyqtSignal(str)
    status_update = pyqtSignal(str)
    bridge_analysis_received = pyqtSignal(object)

    def __init__(
        self,
        config: Config,
        orchestrator: Orchestrator,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the main window.

        Args:
            config: Application configuration.
            orchestrator: AI agent orchestrator.
            parent: Parent widget.
        """
        super().__init__(parent)
        sys.excepthook = _unhandled_exception_hook
        self._config = config
        self._orchestrator = orchestrator
        self._current_worker: AsyncWorker | None = None
        self._stream_append: Callable[[str], None] | None = None
        self._sandbox_manager = SandboxManager()
        self._model_refresh_worker: ModelRefreshWorker | None = None
        self._model_browse_worker: AsyncWorker | None = None

        self._current_binary: Path | None = None
        self._script_manager: object | None = None
        self._script_validator: object | None = None
        self._model_discovery: ModelDiscovery | None = None

        _logger.debug("loading_icon_manager")
        self._icon_manager = IconManager.get_instance()
        _logger.debug("loading_font_manager")
        self._font_manager = FontManager.get_instance()
        _logger.debug("loading_theme_manager")
        self._theme_manager = ThemeManager.get_instance()

        _logger.debug("loading_fonts")
        self._font_manager.load_fonts()

        self._icon_manager.preload_icons(["app", "binary", "tools", "provider", "sandbox", "process"])

        self._initialize_model_cache()

        _logger.info("ui_init_setup_ui")
        self._setup_ui()
        _logger.info("ui_init_setup_menus")
        self._setup_menus()
        _logger.info("ui_init_setup_toolbar")
        self._setup_toolbar()
        _logger.info("ui_init_setup_statusbar")
        self._setup_statusbar()
        _logger.info("ui_init_connect_signals")
        self._connect_signals()
        _logger.info("ui_init_configure_orchestrator")
        self._configure_orchestrator()

        self.setWindowTitle("Intellicrack")
        self.setWindowIcon(self._icon_manager.get_app_icon())

        self._apply_smart_window_size()

    def _apply_smart_window_size(self) -> None:
        """Size and center the window based on available screen geometry.

        Detects the primary monitor's usable area (excluding taskbar) and
        sizes the window slightly smaller with a small margin. Caps at
        1400x900 on large screens and floors at 800x600 minimum. Falls
        back to 1400x900 if screen detection fails.
        """
        max_w, max_h = 1400, 900
        min_w, min_h = 800, 600
        margin_w, margin_h = 6, 8

        try:
            app = QApplication.instance()
            if not isinstance(app, QApplication):
                self.resize(max_w, max_h)
                return

            geometry = get_screen_geometry(app)
            if geometry is None:
                self.resize(max_w, max_h)
                return

            avail_x, avail_y, avail_w, avail_h = geometry
            target_w = max(min_w, min(max_w, avail_w - margin_w))
            target_h = max(min_h, min(max_h, avail_h - margin_h))

            self.resize(target_w, target_h)
            move_widget(
                self,
                avail_x + (avail_w - target_w) // 2,
                avail_y + (avail_h - target_h) // 2,
            )
        except Exception:
            _logger.debug("screen_detection_failed_using_default_size", exc_info=True)
            self.resize(max_w, max_h)

    def wire_script_manager(self, manager: object, validator: object | None = None) -> None:
        """Wire a script manager and validator into the UI.

        Stores references and forwards to the tool panel for
        deferred backend wiring.

        Args:
            manager: ScriptManager instance.
            validator: Optional ScriptValidator instance.
        """
        self._script_manager = manager
        self._script_validator = validator
        self._tool_panel.wire_script_backend(manager, validator)

    def set_model_discovery(self, discovery: ModelDiscovery) -> None:
        """Set the model discovery instance.

        Args:
            discovery: ModelDiscovery for provider model enumeration.
        """
        self._model_discovery = discovery

    def _initialize_model_cache(self) -> None:
        """Initialize model cache settings from configuration."""
        if set_global_cache_size is None:
            return
        try:
            max_cache = getattr(self._config, "max_model_cache_bytes", None)
            if isinstance(max_cache, int) and max_cache > 0:
                set_global_cache_size(max_cache)
        except Exception:
            _logger.debug("model_cache_init_skipped", exc_info=True)

    def _setup_ui(self) -> None:
        """Set up the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Horizontal)

        self._chat_panel = ChatPanel()
        self._chat_panel.setMinimumWidth(400)
        self._splitter.addWidget(self._chat_panel)

        self._tool_panel = ToolOutputPanel()
        self._tool_panel.setMinimumWidth(500)
        self._splitter.addWidget(self._tool_panel)

        self._splitter.setSizes([500, 900])

        layout.addWidget(self._splitter)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QMenuBar {
                background-color: #2d2d30;
                color: #d4d4d4;
                border-bottom: 1px solid #3e3e42;
            }
            QMenuBar::item:selected {
                background-color: #3e3e42;
            }
            QMenu {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            QToolBar {
                background-color: #2d2d30;
                border: none;
                border-bottom: 1px solid #3e3e42;
                spacing: 4px;
            }
            QStatusBar {
                background-color: #007acc;
                color: white;
            }
        """)

    def _add_menu_action(
        self,
        menu: QMenu,
        text: str,
        handler: Callable[[], object],
        shortcut: str | None = None,
    ) -> None:
        """Add an action to a menu with optional shortcut.

        Args:
            menu: The menu to add the action to.
            text: The action text/label.
            handler: The slot to connect to the triggered signal.
            shortcut: Optional keyboard shortcut.
        """
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(shortcut)
        action.triggered.connect(handler)
        menu.addAction(action)

    def _setup_file_menu(self, menubar: QMenuBar) -> None:
        """Set up the File menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        file_menu: QMenu | None = menubar.addMenu("&File")
        if file_menu is None:
            msg = "Failed to create File menu"
            raise TypeError(msg)

        self._add_menu_action(file_menu, "Load Binary...", self._on_load_binary, "Ctrl+O")
        file_menu.addSeparator()
        self._add_menu_action(file_menu, "New Session", self._on_new_session, "Ctrl+N")
        self._add_menu_action(file_menu, "Load Session...", self._on_load_session)
        self._add_menu_action(file_menu, "Save Session", self._on_save_session, "Ctrl+S")
        file_menu.addSeparator()
        self._add_menu_action(file_menu, "Export Chat...", self._on_export_chat)
        self._add_menu_action(file_menu, "Export Session...", self._on_export_session)
        self._add_menu_action(file_menu, "Import Session...", self._on_import_session)
        file_menu.addSeparator()
        self._add_menu_action(file_menu, "Save Patched Binary...", self._on_save_patched_binary)
        self._add_menu_action(file_menu, "Export Analysis...", self._on_export_analysis)
        file_menu.addSeparator()
        self._add_menu_action(file_menu, "Exit", self.close, "Alt+F4")

    def _setup_view_menu(self, menubar: QMenuBar) -> None:
        """Set up the View menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        view_menu: QMenu | None = menubar.addMenu("&View")
        if view_menu is None:
            msg = "Failed to create View menu"
            raise TypeError(msg)

        self._add_menu_action(view_menu, "Analysis", self._on_view_analysis)
        self._add_menu_action(view_menu, "Scripts Manager", self._on_view_scripts)
        self._add_menu_action(view_menu, "Stack Viewer", self._on_view_stack)

    def _on_view_analysis(self) -> None:
        """Show the bridge analysis panel."""
        self._tool_panel.activate_analysis_tab()

    def _on_view_scripts(self) -> None:
        """Show the scripts manager panel."""
        script_state = self._tool_panel.get_script_panel_state()
        selected_id, current_script = script_state
        if selected_id is not None:
            _logger.debug("scripts_panel_state", selected=selected_id)
        if current_script is not None:
            _logger.debug("current_script", script_name=current_script[0])
        self._tool_panel.activate_scripts_tab()

    def _on_view_stack(self) -> None:
        """Show the stack viewer panel."""
        self._tool_panel.activate_stack_tab()

    def _setup_tools_menu(self, menubar: QMenuBar) -> None:
        """Set up the Tools menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu or submenu could not be created.
        """
        tools_menu: QMenu | None = menubar.addMenu("&Tools")
        if tools_menu is None:
            msg = "Failed to create Tools menu"
            raise TypeError(msg)

        self._add_menu_action(tools_menu, "Tool Status...", self._on_tool_status)
        self._add_menu_action(tools_menu, "Configure Tools...", self._on_configure_tools)
        tools_menu.addSeparator()

        embedded_menu: QMenu | None = tools_menu.addMenu("&Embedded Tools")
        if embedded_menu is None:
            msg = "Failed to create Embedded Tools menu"
            raise TypeError(msg)

        self._add_menu_action(embedded_menu, "Open x64dbg Debugger", self._on_open_x64dbg)
        self._add_menu_action(embedded_menu, "Open Cutter Analysis", self._on_open_cutter)
        self._add_menu_action(embedded_menu, "Open HxD Hex Editor", self._on_open_hxd)
        embedded_menu.addSeparator()
        self._add_menu_action(embedded_menu, "Debug Current Binary...", self._on_debug_current_binary)
        self._add_menu_action(embedded_menu, "Analyze Current Binary...", self._on_analyze_current_binary)
        self._add_menu_action(embedded_menu, "Hex Edit Current Binary...", self._on_hex_edit_current_binary)

        tools_menu.addSeparator()
        self._add_menu_action(tools_menu, "Open in Ghidra...", self._on_open_binary_in_ghidra)

    def _setup_providers_menu(self, menubar: QMenuBar) -> None:
        """Set up the Providers menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        providers_menu: QMenu | None = menubar.addMenu("&Providers")
        if providers_menu is None:
            msg = "Failed to create Providers menu"
            raise TypeError(msg)

        self._add_menu_action(providers_menu, "Configure Providers...", self._on_configure_providers)
        self._add_menu_action(providers_menu, "Refresh Models", self._on_refresh_models)
        self._add_menu_action(providers_menu, "Browse Models...", self._on_browse_models)

    def _setup_sandbox_menu(self, menubar: QMenuBar) -> None:
        """Set up the Sandbox menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        sandbox_menu: QMenu | None = menubar.addMenu("&Sandbox")
        if sandbox_menu is None:
            msg = "Failed to create Sandbox menu"
            raise TypeError(msg)

        self._add_menu_action(sandbox_menu, "Configure Sandbox...", self._on_configure_sandbox)
        self._add_menu_action(sandbox_menu, "Open Sandbox", self._on_open_sandbox)

    def _setup_settings_menu(self, menubar: QMenuBar) -> None:
        """Set up the Settings menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        settings_menu: QMenu | None = menubar.addMenu("&Settings")
        if settings_menu is None:
            msg = "Failed to create Settings menu"
            raise TypeError(msg)

        self._add_menu_action(settings_menu, "Preferences...", self._on_preferences)
        settings_menu.addSeparator()
        self._add_menu_action(settings_menu, "Toggle Theme", self._on_toggle_theme)
        settings_menu.addSeparator()
        self._add_menu_action(settings_menu, "Focus Chat Input", self._on_focus_chat_input, "Ctrl+/")

    def _setup_help_menu(self, menubar: QMenuBar) -> None:
        """Set up the Help menu.

        Args:
            menubar: The menu bar to add the menu to.

        Raises:
            TypeError: If the menu could not be created.
        """
        help_menu: QMenu | None = menubar.addMenu("&Help")
        if help_menu is None:
            msg = "Failed to create Help menu"
            raise TypeError(msg)

        self._add_menu_action(help_menu, "About", self._on_about)

    def _setup_menus(self) -> None:
        """Set up the menu bar.

        Raises:
            TypeError: If the menu bar could not be retrieved.
        """
        menubar: QMenuBar | None = self.menuBar()
        if menubar is None:
            msg = "Failed to get menu bar"
            raise TypeError(msg)

        self._setup_file_menu(menubar)
        self._setup_view_menu(menubar)
        self._setup_tools_menu(menubar)
        self._setup_providers_menu(menubar)
        self._setup_sandbox_menu(menubar)
        self._setup_settings_menu(menubar)
        self._setup_help_menu(menubar)

    def _setup_toolbar(self) -> None:
        """Set up the toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setFixedHeight(40)
        self.addToolBar(toolbar)

        load_btn = QPushButton("Load Binary")
        load_btn.setObjectName("secondary_button")
        load_btn.clicked.connect(self._on_load_binary)
        toolbar.addWidget(load_btn)

        toolbar.addSeparator()

        provider_label = QLabel("Provider:")
        provider_label.setObjectName("toolbar_label")
        toolbar.addWidget(provider_label)

        self._provider_combo = QComboBox()
        self._provider_combo.setMinimumWidth(120)
        self._provider_combo.setObjectName("toolbar_combo")
        for provider in ProviderName:
            self._provider_combo.addItem(provider.value.title(), provider)
        self._provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        toolbar.addWidget(self._provider_combo)

        model_label = QLabel("Model:")
        model_label.setObjectName("toolbar_label")
        toolbar.addWidget(model_label)

        self._model_combo = QComboBox()
        self._model_combo.setMinimumWidth(200)
        self._model_combo.setObjectName("toolbar_combo")
        toolbar.addWidget(self._model_combo)

        toolbar.addSeparator()

        tools_label = QLabel("Tools:")
        tools_label.setObjectName("toolbar_label")
        toolbar.addWidget(tools_label)

        self._x64dbg_btn = QPushButton("x64dbg")
        self._x64dbg_btn.setObjectName("tool_button")
        self._x64dbg_btn.setToolTip("Open x64dbg Debugger")
        self._x64dbg_btn.clicked.connect(self._on_open_x64dbg)
        toolbar.addWidget(self._x64dbg_btn)

        self._cutter_btn = QPushButton("Cutter")
        self._cutter_btn.setObjectName("tool_button")
        self._cutter_btn.setToolTip("Open Cutter Analysis")
        self._cutter_btn.clicked.connect(self._on_open_cutter)
        toolbar.addWidget(self._cutter_btn)

        self._hxd_btn = QPushButton("HxD")
        self._hxd_btn.setObjectName("tool_button")
        self._hxd_btn.setToolTip("Open HxD Hex Editor")
        self._hxd_btn.clicked.connect(self._on_open_hxd)
        toolbar.addWidget(self._hxd_btn)

        self._ghidra_btn = QPushButton("Ghidra")
        self._ghidra_btn.setObjectName("tool_button")
        self._ghidra_btn.setToolTip("Open Ghidra Reverse Engineering")
        self._ghidra_btn.clicked.connect(self._on_open_ghidra)
        toolbar.addWidget(self._ghidra_btn)

        self._frida_btn = QPushButton("Frida")
        self._frida_btn.setObjectName("tool_button")
        self._frida_btn.setToolTip("Open Frida Instrumentation Panel")
        self._frida_btn.clicked.connect(self._on_open_frida)
        toolbar.addWidget(self._frida_btn)

        self._process_btn = QPushButton("Process")
        self._process_btn.setObjectName("tool_button")
        self._process_btn.setToolTip("Open Process Manager")
        self._process_btn.clicked.connect(self._on_open_process)
        toolbar.addWidget(self._process_btn)

        self._binary_btn = QPushButton("Binary")
        self._binary_btn.setObjectName("tool_button")
        self._binary_btn.setToolTip("Open Binary Hex Viewer")
        self._binary_btn.clicked.connect(self._on_open_binary)
        toolbar.addWidget(self._binary_btn)

        self._sandbox_tool_btn = QPushButton("Sandbox")
        self._sandbox_tool_btn.setObjectName("tool_button")
        self._sandbox_tool_btn.setToolTip("Open Sandbox Manager")
        self._sandbox_tool_btn.clicked.connect(self._on_open_sandbox_panel)
        toolbar.addWidget(self._sandbox_tool_btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        self._auto_approve_btn = QPushButton("Auto-approve: OFF")
        self._auto_approve_btn.setCheckable(True)
        self._auto_approve_btn.setObjectName("toggle_button")
        self._auto_approve_btn.toggled.connect(self._on_auto_approve_toggled)
        toolbar.addWidget(self._auto_approve_btn)

        self._sandbox_btn = QPushButton("Sandbox: OFF")
        self._sandbox_btn.setCheckable(True)
        self._sandbox_btn.setObjectName("toggle_button")
        self._sandbox_btn.toggled.connect(self._on_sandbox_toggled)
        toolbar.addWidget(self._sandbox_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("danger_button")
        cancel_btn.clicked.connect(self._on_cancel)
        toolbar.addWidget(cancel_btn)

    def _setup_statusbar(self) -> None:
        """Set up the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        self._status_label = QLabel("Ready")
        self._statusbar.addWidget(self._status_label)

        self._binary_label = QLabel()
        self._statusbar.addPermanentWidget(self._binary_label)

        self._memory_label = QLabel()
        self._statusbar.addPermanentWidget(self._memory_label)

        self._model_status_label = QLabel()
        self._statusbar.addPermanentWidget(self._model_status_label)

        self._token_label = QLabel()
        self._statusbar.addPermanentWidget(self._token_label)

        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_system_status)
        self._status_timer.start(30000)

    def _refresh_system_status(self) -> None:
        """Periodically refresh the system status display."""
        from .panels.async_bridge import run_bridge_coroutine

        async def fetch_status() -> dict[str, object]:
            return await self._orchestrator.get_system_status()

        try:
            status = run_bridge_coroutine(fetch_status())
            if status is not None:
                state = status.get("state", "unknown")
                session_id = status.get("session_id")
                session_text = f" | Session: {session_id}" if session_id else ""
                self._status_label.setText(f"State: {state}{session_text}")
        except Exception:
            _logger.debug("system_status_refresh_failed", exc_info=True)

        self._refresh_memory_status()
        self._refresh_model_discovery_status()

    def _refresh_memory_status(self) -> None:
        """Update the memory usage display in the status bar."""
        if get_global_model_cache is None:
            self._memory_label.setText("")
            return
        try:
            total_bytes = get_global_model_cache().get_memory_usage()
            if total_bytes > 0:
                mb = total_bytes / (1024 * 1024)
                self._memory_label.setText(f"Cache: {mb:.0f}MB")
            else:
                self._memory_label.setText("")
        except Exception:
            _logger.debug("memory_label_update_failed", exc_info=True)
            self._memory_label.setText("")

    def _refresh_model_discovery_status(self) -> None:
        """Update the model discovery status in the status bar."""
        if self._model_discovery is None:
            return
        try:
            if events := self._model_discovery.get_discovery_events():
                last_event = events[-1]
                provider_str = last_event.provider.value
                status_str = "OK" if last_event.success else (last_event.error_message or "failed")
                self._model_status_label.setText(f"Discovery: {provider_str} {status_str}")
        except Exception:
            _logger.debug("model_discovery_status_refresh_failed", exc_info=True)

    def _connect_signals(self) -> None:
        """Connect Qt signals."""
        self._chat_panel.message_submitted.connect(self._on_user_message)
        self.message_received.connect(self._chat_panel.add_message)
        self.tool_call_received.connect(self._on_tool_call)
        self.tool_result_received.connect(self._on_tool_result)
        self.stream_chunk_received.connect(self._on_stream_chunk)
        self.status_update.connect(self._update_status)
        self._tool_panel.address_clicked.connect(self._on_address_clicked)
        self.bridge_analysis_received.connect(self._on_bridge_analysis_activated)

    def _configure_orchestrator(self) -> None:
        """Configure orchestrator callbacks."""
        self._orchestrator.set_message_callback(self.message_received.emit)
        self._orchestrator.set_tool_call_callback(self.tool_call_received.emit)
        self._orchestrator.set_tool_result_callback(self.tool_result_received.emit)
        self._orchestrator.set_stream_callback(self.stream_chunk_received.emit)
        self._orchestrator.set_async_confirmation_callback(self._request_tool_confirmation)
        self._orchestrator.set_bridge_analysis_callback(self._on_bridge_analysis_received)
        self._orchestrator.configure_hooks(
            on_bridge_analysis=self._on_bridge_analysis_received,
            on_confirmation=None,
        )
        self.bridge_analysis_received.connect(self._tool_panel.update_bridge_analysis)

        try:
            scripts_dir = get_config_dir() / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            script_mgr = ScriptManager(scripts_dir)
            self._orchestrator.set_script_manager(script_mgr)
        except OSError as e:
            _logger.debug("script_manager_init_skipped", error=str(e))

        available_tools = self._orchestrator.get_available_tool_names()
        _logger.info("orchestrator_tools_available", tools=available_tools)

        tool_reg = getattr(self._orchestrator, "_tool_registry", None)
        if tool_reg is not None:
            self._tool_panel.set_tool_registry(tool_reg)
            _logger.info("tool_registry_wired_to_panel", registry=type(tool_reg).__name__)

        bridge = self._orchestrator.get_typed_bridge("process")
        if bridge is not None:
            _logger.debug("process_bridge_available", bridge_type="process")

        try:
            tools_dir = get_config_dir() / "tools"
            tools_dir.mkdir(parents=True, exist_ok=True)
            installer = ToolInstaller(tools_dir)
            self._tool_installer = installer
            _logger.info(
                "tool_installer_initialized",
                tools_dir=str(tools_dir),
            )
        except OSError as e:
            _logger.debug("tool_installer_init_skipped", error=str(e))

    async def _refresh_tool_status(self) -> dict[str, object]:
        """Refresh tool installation status asynchronously.

        Returns:
            Dictionary mapping tool names to (available, path) tuples.
        """
        installer = getattr(self, "_tool_installer", None)
        if installer is None:
            return {}

        statuses = await installer.get_all_tool_status()
        result = {str(k): v for k, v in statuses.items()}
        _logger.info(
            "tool_status_refreshed",
            tool_count=len(result),
        )
        return result

    def _on_bridge_analysis_received(self, analysis: object) -> None:
        """Handle bridge analysis completion from orchestrator.

        Marshals the analysis data to the Qt main thread via signal emission.
        This callback is invoked from an async worker thread, so direct UI
        updates are unsafe.

        Args:
            analysis: The BridgeAnalysisSummary result from the orchestrator.
        """
        self._tool_panel.clear_analysis_tab("analysis")
        self._tool_panel.display_analysis_result("analysis", str(analysis))
        self.bridge_analysis_received.emit(analysis)

    def _on_bridge_analysis_activated(self, _analysis: object) -> None:
        """Activate the analysis tab after bridge analysis completes.

        Args:
            _analysis: The bridge analysis result (unused here).
        """
        self._tool_panel.activate_analysis_tab()

    def _request_tool_confirmation(self, call: ToolCall) -> asyncio.Future[bool]:
        """Request user confirmation for a tool call.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            Future that resolves to True if approved, False otherwise.
        """
        confirmation_module = importlib.import_module(".confirmation_dialog", "intellicrack.ui")

        future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()

        def show_dialog() -> None:
            dialog = confirmation_module.ToolConfirmationDialog(call, self)
            dialog.exec()
            self._orchestrator.resolve_confirmation(dialog.approved)
            try:
                future.set_result(dialog.approved)
            except asyncio.InvalidStateError:
                _logger.debug("confirmation_dialog_state_error", exc_info=True)

        QTimer.singleShot(0, show_dialog)

        return future

    def _on_user_message(self, text: str) -> None:
        """Handle user message submission.

        Args:
            text: User's message text.
        """
        self._chat_panel.set_input_enabled(False)
        self._stream_append = self._chat_panel.add_streaming_message()
        self.status_update.emit("Processing...")

        active_pid = self._tool_panel.get_active_process_pid()
        if active_pid is not None:
            _logger.debug("user_message_process_context", pid=active_pid)

        async def process() -> None:
            await self._orchestrator.process_user_input(text)

        self._run_async(process())

    def _on_stream_chunk(self, chunk: str) -> None:
        """Handle streaming response chunk.

        Args:
            chunk: Text chunk from LLM.
        """
        if self._stream_append:
            self._stream_append(chunk)

    def _on_tool_call(self, call: ToolCall) -> None:
        """Handle tool call notification.

        Args:
            call: The tool call being executed.
        """
        self.status_update.emit(f"Running: {call.tool_name}.{call.function_name}")
        self._tool_panel.log(f"[CALL] {call.tool_name}.{call.function_name}")

    def _on_tool_result(self, result: ToolResult) -> None:
        """Handle tool result notification.

        Args:
            result: The tool execution result.
        """
        status = "SUCCESS" if result.success else "FAILED"
        self._tool_panel.log(f"[{status}] Duration: {result.duration_ms:.1f}ms")

        if result.success and result.result:
            result_str = str(result.result)
            if len(result_str) > _MAX_RESULT_DISPLAY_LEN:
                result_str = f"{result_str[: _MAX_RESULT_DISPLAY_LEN - 3]}..."
            self._tool_panel.log(f"Result: {result_str}")

            tool_name = getattr(result, "tool_name", "")
            if tool_name == "patch_binary" and isinstance(result.result, dict):
                patch_data = cast("dict[str, object]", result.result)
                address_val = patch_data.get("offset", 0)
                orig_val = patch_data.get("original", b"")
                new_val = patch_data.get("patched", b"")
                desc_val = patch_data.get("description", "Manual patch")
                self._run_async(
                    self._orchestrator.register_manual_patch(
                        address=int(address_val) if isinstance(address_val, (int, str)) else 0,
                        original_bytes=bytes(orig_val) if isinstance(orig_val, (bytes, bytearray)) else b"",
                        new_bytes=bytes(new_val) if isinstance(new_val, (bytes, bytearray)) else b"",
                        description=str(desc_val),
                    )
                )

        if result.error:
            self._tool_panel.log(f"Error: {result.error}")

    def _run_async(self, coro: Coroutine[object, object, object]) -> None:
        """Run an async operation in a worker thread.

        Args:
            coro: Coroutine to execute.
        """
        self._current_worker = AsyncWorker(coro, self)
        self._current_worker.finished.connect(self._on_async_finished)
        self._current_worker.error.connect(self._on_async_error)
        self._current_worker.start()

    def _on_async_finished(self, result: object) -> None:
        """Handle async operation completion.

        Args:
            result: Operation result.
        """
        del result
        self._chat_panel.set_input_enabled(True)
        self._stream_append = None
        self.status_update.emit("Ready")

    def _on_async_error(self, error: Exception) -> None:
        """Handle async operation error.

        Args:
            error: The error that occurred.
        """
        self._chat_panel.set_input_enabled(True)
        self._stream_append = None
        self.status_update.emit("Error")
        QMessageBox.critical(self, "Error", str(error))

    def _update_status(self, status: str) -> None:
        """Update the status bar.

        Args:
            status: Status message.
        """
        self._status_label.setText(status)

    def _on_address_clicked(self, address: int) -> None:
        """Handle address click in the tool panel.

        Args:
            address: The clicked memory address.
        """
        self._tool_panel.set_current_address(address)
        self.status_update.emit(f"Navigated to 0x{address:08X}")

    def _on_load_binary(self) -> None:
        """Handle load binary action."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "Executables (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if path:
            self._load_binary(Path(path))

    def _load_binary(self, path: Path) -> None:
        """Load a binary file.

        Args:
            path: Path to the binary.
        """
        self._current_binary = path
        binary_name = path.name

        async def load() -> None:
            await self._orchestrator.add_binary(path)
            await self._orchestrator.activate_binary_by_name(binary_name)
            await self._orchestrator.refresh_session_state()

        self.status_update.emit(f"Loading {binary_name}...")
        self._run_async(load())

        cached_analysis = self._orchestrator.get_current_bridge_analysis(binary_name)
        if cached_analysis is not None:
            self._tool_panel.display_analysis_result(
                "analysis",
                str(cached_analysis),
            )

    def _on_new_session(self) -> None:
        """Handle new session action."""
        session_mgr_mod = importlib.import_module(".session_manager", "intellicrack.ui")
        new_session_cls = getattr(session_mgr_mod, "NewSessionDialog", None)
        if new_session_cls is not None:
            dialog = new_session_cls(parent=self)
            if not dialog.exec():
                return
            description = dialog.get_description()
            _logger.debug("new_session_dialog", description=description)

        provider_data: object = self._provider_combo.currentData()
        model = self._model_combo.currentText()

        if not model:
            QMessageBox.warning(self, "Warning", "Please select a model first.")
            return

        provider: str | ProviderName = provider_data if isinstance(provider_data, ProviderName) else str(provider_data)

        async def create_session() -> None:
            await self._orchestrator.start_session(provider, model)

        self._chat_panel.clear_messages()
        self._tool_panel.clear_all()
        self.status_update.emit("Creating new session...")
        self._run_async(create_session())

    def _on_load_session(self) -> None:
        """Handle load session action."""
        dialog = SessionManagerDialog(parent=self)
        if dialog.exec():
            session_id = dialog.get_selected_session_id()
            if session_id:

                async def load_session() -> None:
                    await self._orchestrator.load_session(session_id)

                self._chat_panel.clear_messages()
                self._tool_panel.clear_all()
                self.status_update.emit(f"Loading session {session_id}...")
                self._run_async(load_session())

    def _on_save_session(self) -> None:
        """Handle save session action."""

        async def save_session() -> None:
            await self._orchestrator.save_session()

        self.status_update.emit("Saving session...")
        self._run_async(save_session())

    def _on_export_chat(self) -> None:
        """Handle export chat action."""
        messages = self._chat_panel.get_messages()
        if not messages:
            QMessageBox.information(self, "Export", "No messages to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Chat",
            "",
            "Text Files (*.txt);;Markdown (*.md);;All Files (*)",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for msg in messages:
                    role = msg.role.upper()
                    f.write(f"[{role}] {msg.timestamp.strftime('%H:%M:%S')}\n")
                    f.write(f"{msg.content}\n\n")
            QMessageBox.information(self, "Export", f"Chat exported to {path}")

    def _on_export_session(self) -> None:
        """Export the current session to a JSON file."""
        session = self._orchestrator.current_session
        if session is None:
            QMessageBox.information(self, "Export", "No active session to export.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Session",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            session_mgr = getattr(self._orchestrator, "_sessions", None)
            if session_mgr is not None:
                export_current = getattr(session_mgr, "export_current", None)
                if callable(export_current):
                    coro = export_current(Path(path))
                    self._run_async(cast("Coroutine[object, object, object]", coro))
                elif hasattr(session_mgr, "export_json"):
                    coro2 = session_mgr.export_json(session.id, Path(path))
                    self._run_async(cast("Coroutine[object, object, object]", coro2))
                else:
                    QMessageBox.warning(self, "Export", "Session manager unavailable.")
                    return
                QMessageBox.information(self, "Export", f"Session exported to {path}")
            else:
                QMessageBox.warning(self, "Export", "Session manager unavailable.")

    def _on_import_session(self) -> None:
        """Import a session from a JSON file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Session",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            session_mgr = getattr(self._orchestrator, "_session_manager", None)
            if session_mgr is not None:
                imported = session_mgr.import_json(Path(path))
                if imported is not None:
                    QMessageBox.information(self, "Import", "Session imported successfully.")
                    self.status_update.emit("Session imported")
                else:
                    QMessageBox.warning(self, "Import", "Failed to import session.")
            else:
                QMessageBox.warning(self, "Import", "Session manager unavailable.")

    def _on_save_patched_binary(self) -> None:
        """Save the currently loaded binary with applied patches."""
        binary_panel = self._tool_panel.get_panel("binary")
        if binary_panel is None:
            QMessageBox.information(self, "Save", "No binary panel loaded.")
            return

        file_data: bytes | None = None
        get_file_data = getattr(binary_panel, "get_file_data", None)
        if callable(get_file_data):
            raw_data = get_file_data()
            if isinstance(raw_data, (bytes, bytearray)):
                file_data = bytes(raw_data)

        if file_data is None:
            QMessageBox.information(self, "Save", "No binary data available.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Patched Binary",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if path:
            with open(path, "wb") as f:
                f.write(file_data)

            patches: list[object] = []
            get_patches = getattr(binary_panel, "get_patches", None)
            if callable(get_patches):
                raw_patches = get_patches()
                if isinstance(raw_patches, list):
                    patches = cast("list[object]", raw_patches)

            report_path = Path(path).with_suffix(".patch_report.txt")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(f"Patch Report for {Path(path).name}\n")
                f.write(f"{'=' * 40}\n")
                f.write(f"Total patches applied: {len(patches)}\n\n")
                for i, patch in enumerate(patches, 1):
                    f.write(f"Patch {i}: {patch}\n")

            QMessageBox.information(self, "Save", f"Patched binary saved to {path}\nReport: {report_path}")

    def _on_export_analysis(self) -> None:
        """Export the current bridge analysis to a JSON file."""
        analysis_panel = self._tool_panel.get_panel("analysis")
        if analysis_panel is None:
            QMessageBox.information(self, "Export", "No analysis available.")
            return

        get_analysis = getattr(analysis_panel, "get_current_analysis", None)
        analysis = get_analysis() if callable(get_analysis) else None
        if analysis is None:
            QMessageBox.information(self, "Export", "No analysis data available.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if path:
            analysis_dict: object
            to_dict_fn = getattr(analysis, "to_dict", None)
            if callable(to_dict_fn):
                analysis_dict = to_dict_fn()
            elif hasattr(analysis, "__dict__"):
                analysis_dict = vars(analysis)
            else:
                analysis_dict = str(analysis)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(analysis_dict, f, indent=2, default=str)

            QMessageBox.information(self, "Export", f"Analysis exported to {path}")

    def _on_tool_status(self) -> None:
        """Handle tool status action."""
        success_pixmap = self._icon_manager.get_status_pixmap(True, 16)
        failure_pixmap = self._icon_manager.get_status_pixmap(False, 16)
        _logger.debug(
            "tool_status_icons",
            success_icon=not success_pixmap.isNull(),
            failure_icon=not failure_pixmap.isNull(),
        )

        try:
            loop = asyncio.new_event_loop()
            tool_statuses = loop.run_until_complete(self._refresh_tool_status())
            loop.close()
            _logger.info(
                "tool_status_dialog_opened",
                tool_count=len(tool_statuses),
            )
        except Exception:
            _logger.debug("tool_status_refresh_before_dialog_failed", exc_info=True)

        dialog = ToolStatusDialog(parent=self)
        dialog.exec()

    def _on_configure_tools(self) -> None:
        """Handle configure tools action."""
        dialog = ToolConfigDialog(
            tools_directory=self._config.tools_directory,
            parent=self,
        )
        if dialog.exec():
            settings: dict[str, dict[str, object]] = dialog.get_settings()
            self._apply_tool_settings(settings)

    def _apply_tool_settings(self, settings: dict[str, dict[str, object]]) -> None:
        """Apply tool configuration settings at runtime.

        The ToolConfigDialog handles persistence via its own JSON config file.
        This method updates runtime state: for tools that have a changed path
        or enabled state, it schedules re-initialization through the orchestrator.

        Args:
            settings: Tool settings dictionary mapping tool IDs to their settings.
        """
        tools_to_init: list[str] = []
        for tool_id, tool_settings in settings.items():
            enabled = bool(tool_settings.get("enabled", False))
            path_value = str(tool_settings.get("path", ""))
            config_enabled = True
            if hasattr(self._config, "is_tool_enabled"):
                try:
                    config_enabled = self._config.is_tool_enabled(ToolName(tool_id.lower()))
                except (ValueError, AttributeError):
                    _logger.debug("tool_name_parse_fallback", tool_id=tool_id)
                    config_enabled = True
            if enabled and path_value and config_enabled:
                tools_to_init.append(tool_id)

        if tools_to_init:

            async def _reinit_tools() -> None:
                for tid in tools_to_init:
                    try:
                        await self._orchestrator.initialize_tool(tid)
                        _logger.info("tool_reinitialized", tool_id=tid)
                    except Exception as e:
                        _logger.warning("tool_reinit_failed", tool_id=tid, error=str(e))

            worker = AsyncWorker(_reinit_tools(), self)
            worker.finished.connect(self._on_tool_reinit_finished)
            worker.error.connect(self._on_tool_reinit_error)
            worker.start()

        count = len(settings)
        self.status_update.emit(f"Tool settings applied ({count} tools configured)")

    def _on_tool_reinit_finished(self, result: object) -> None:
        """Handle tool re-initialization completion.

        Args:
            result: Worker result (unused).
        """
        del result
        self.status_update.emit("Tool re-initialization complete")

    def _on_tool_reinit_error(self, error: Exception) -> None:
        """Handle tool re-initialization failure.

        Args:
            error: The exception that occurred.
        """
        _logger.warning("tool_reinit_batch_failed", error=str(error))
        self.status_update.emit("Tool re-initialization failed")

    def _on_configure_providers(self) -> None:
        """Handle configure providers action."""
        registry = self._orchestrator.provider_registry
        discovery = ModelDiscovery(registry)
        dialog = ProviderConfigDialog(
            provider_registry=registry,
            model_discovery=discovery,
            parent=self,
        )
        if dialog.exec():
            settings: dict[str, dict[str, object]] = dialog.get_settings()
            self._apply_provider_settings(settings)

    def _apply_provider_settings(self, settings: dict[str, dict[str, object]]) -> None:
        """Apply provider configuration settings at runtime.

        The ProviderConfigDialog handles persistence via its own JSON config file.
        This method reconnects providers with updated API keys and credentials
        so changes take effect without an application restart.

        Args:
            settings: Provider settings dictionary mapping provider IDs to their settings.
        """
        registry = self._orchestrator.provider_registry
        providers_to_connect: list[tuple[ProviderName, ProviderCredentials]] = []

        for provider_id, provider_settings in settings.items():
            enabled = bool(provider_settings.get("enabled", False))
            api_key = str(provider_settings.get("api_key", ""))
            api_base = str(provider_settings.get("api_base", "")) or None
            org_id = str(provider_settings.get("organization_id", "")) or None

            if not enabled or not api_key:
                continue

            try:
                pname = ProviderName(provider_id)
            except ValueError:
                _logger.warning("unknown_provider_id", provider_id=provider_id)
                continue

            provider = registry.get(pname)
            if provider is None:
                continue

            creds = ProviderCredentials(api_key=api_key, api_base=api_base, organization_id=org_id)
            providers_to_connect.append((pname, creds))

        if providers_to_connect:

            async def _reconnect_providers() -> None:
                for pname, creds in providers_to_connect:
                    try:
                        await registry.connect_provider(pname, creds)
                        _logger.info("provider_reconnected", provider=pname.value)
                    except Exception as e:
                        _logger.warning(
                            "provider_reconnect_failed",
                            provider=pname.value,
                            error=str(e),
                        )

            worker = AsyncWorker(_reconnect_providers(), self)
            worker.finished.connect(self._on_provider_reconnect_finished)
            worker.error.connect(self._on_provider_reconnect_error)
            worker.start()

        count = len(settings)
        self.status_update.emit(f"Provider settings applied ({count} providers configured)")

    def _on_provider_reconnect_finished(self, result: object) -> None:
        """Handle provider reconnection completion.

        Args:
            result: Worker result (unused).
        """
        del result
        self.status_update.emit("Provider connections updated")

    def _on_provider_reconnect_error(self, error: Exception) -> None:
        """Handle provider reconnection failure.

        Args:
            error: The exception that occurred.
        """
        _logger.warning("provider_reconnect_batch_failed", error=str(error))
        self.status_update.emit("Provider reconnection failed")

    def _on_refresh_models(self) -> None:
        """Handle refresh models action."""
        provider_data: object = self._provider_combo.currentData()
        if not provider_data:
            QMessageBox.warning(self, "Warning", "Please select a provider first.")
            return

        provider_id: str = provider_data.value if isinstance(provider_data, ProviderName) else str(provider_data)

        if (
            hasattr(self._config, "is_provider_enabled")
            and isinstance(provider_data, ProviderName)
            and not self._config.is_provider_enabled(provider_data)
        ):
            QMessageBox.warning(self, "Warning", f"Provider {provider_id} is disabled in configuration.")
            return

        env_vars: dict[str, str] = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        api_key = ""
        if provider_id in env_vars:
            api_key = os.environ.get(env_vars[provider_id], "")

        config_path = get_config_file("providers.json")
        if config_path.exists():
            try:
                with open(config_path, encoding="utf-8") as f:
                    loaded_json: dict[str, dict[str, str]] = json.load(f)
                    provider_section = loaded_json.get(provider_id, {})
                    if config_key := provider_section.get("api_key", ""):
                        api_key = config_key
            except (json.JSONDecodeError, OSError):
                _logger.debug("config_file_load_failed", exc_info=True)
        self.status_update.emit("Refreshing models...")
        self._model_combo.clear()
        self._model_combo.setEnabled(False)

        if self._model_discovery is not None:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._model_discovery.discover_all())
                loop.close()
            except Exception:
                _logger.debug("model_discovery_refresh_failed", exc_info=True)

        self._model_refresh_worker = ModelRefreshWorker(provider_id, api_key, parent=self)
        self._model_refresh_worker.refresh_finished.connect(self._on_models_refresh_finished)
        self._model_refresh_worker.start()

    def _on_models_refresh_finished(self, success: bool, models: list[str], message: str) -> None:
        """Handle models refresh completion.

        Args:
            success: Whether the refresh was successful.
            models: List of available model names.
            message: Status message.
        """
        self._model_combo.setEnabled(True)
        if success and models:
            self._model_combo.clear()
            self._model_combo.addItems(models)
            self.status_update.emit(f"Found {len(models)} models")
        else:
            self.status_update.emit("Failed to refresh models")
            QMessageBox.warning(self, "Model Refresh Failed", message)

    def _on_browse_models(self) -> None:
        """Open the model selection dialog for browsing available models."""
        registry = self._orchestrator.provider_registry
        active_provider = registry.active
        if active_provider is None:
            QMessageBox.information(self, "Browse Models", "No active provider connected.")
            return

        async def fetch() -> list[ModelInfo]:
            return await active_provider.list_models()

        worker = AsyncWorker(fetch(), self)
        worker.finished.connect(self._on_browse_models_result)
        worker.error.connect(self._on_async_error)
        self._model_browse_worker = worker
        worker.start()
        self.status_update.emit("Fetching models...")

    def _on_browse_models_result(self, result: object) -> None:
        """Handle browse models async result.

        Args:
            result: The list of ModelInfo objects from the provider.
        """
        self.status_update.emit("Ready")
        if not isinstance(result, list):
            return

        items = cast("list[object]", result)
        model_infos: list[ModelInfo] = [item for item in items if isinstance(item, ModelInfo)]

        if not model_infos:
            QMessageBox.information(self, "Browse Models", "No models available.")
            return

        if self._model_discovery is not None:
            first_model = model_infos[0]
            model_detail = self._model_discovery.get_by_id(first_model.provider, first_model.id)
            if model_detail is not None:
                _logger.debug(
                    "model_detail_fetched",
                    model_id=first_model.id,
                )

        dialog = ModelSelectionDialog(models=model_infos, parent=self)
        if dialog.exec() and (selected := dialog.get_selected_model()):
            idx = self._model_combo.findText(selected)
            if idx >= 0:
                self._model_combo.setCurrentIndex(idx)

    def _on_configure_sandbox(self) -> None:
        """Handle configure sandbox action."""
        dialog = SandboxConfigDialog(
            sandbox_manager=self._sandbox_manager,
            parent=self,
        )
        if dialog.exec():
            settings: dict[str, object] = dialog.get_settings()
            self._apply_sandbox_settings(settings)

    def _apply_sandbox_settings(self, settings: dict[str, object]) -> None:
        """Apply sandbox configuration settings.

        The SandboxConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Sandbox settings dictionary.
        """
        del settings
        self.status_update.emit("Sandbox settings saved")

    def _on_open_sandbox(self) -> None:
        """Handle open sandbox action."""
        if not SandboxConfigDialog().is_sandbox_available():
            QMessageBox.warning(
                self,
                "Sandbox Unavailable",
                "Sandbox functionality is not available on this system.",
            )
            return

        async def open_sandbox() -> object:
            available_types = await self._sandbox_manager.get_available_types()
            if not available_types:
                return None

            sandbox_type = available_types[0]
            return await self._sandbox_manager.create(
                sandbox_type=sandbox_type,
                auto_start=True,
            )

        def on_sandbox_opened(result: object) -> None:
            if result is None:
                QMessageBox.warning(
                    self,
                    "Sandbox Unavailable",
                    "No sandbox environment is available.\n\n"
                    "Windows Sandbox requires Windows 10/11 Pro or Enterprise.\n"
                    "QEMU requires QEMU to be installed.",
                )
                self.status_update.emit("No sandbox available")
            else:
                self._sandbox_btn.setChecked(True)
                self._tool_panel.wire_sandbox_backend(result)
                report_path = getattr(result, "last_report_path", None)
                if isinstance(report_path, str):
                    self._tool_panel.load_sandbox_report(report_path)
                self.status_update.emit("Sandbox opened")

        def on_sandbox_error(e: Exception) -> None:
            QMessageBox.critical(self, "Error", str(e))

        self.status_update.emit("Opening sandbox...")
        worker = AsyncWorker(open_sandbox(), self)
        worker.finished.connect(on_sandbox_opened)
        worker.error.connect(on_sandbox_error)
        worker.start()
        self._current_worker = worker

    def _on_preferences(self) -> None:
        """Handle preferences action."""
        preferences_module = importlib.import_module(".preferences", "intellicrack.ui")
        dialog = preferences_module.PreferencesDialog(self._config, self)
        config_path = get_config_file("config.json")
        set_config_path = getattr(dialog, "set_config_path", None)
        if callable(set_config_path):
            set_config_path(config_path)
        if dialog.exec():
            self._config = dialog.get_config()
            self.status_update.emit("Preferences saved")

    def _on_toggle_theme(self) -> None:
        """Toggle between dark and light themes."""
        self._theme_manager.toggle_theme()
        self._icon_manager.clear_cache()
        is_dark = self._theme_manager.is_dark_theme()
        theme_name = "dark" if is_dark else "light"
        _logger.info("theme_toggled", theme=theme_name)

        heading_font = self._font_manager.get_heading_font(12)
        code_bold = self._font_manager.get_code_font_bold(10)
        ui_bold = self._font_manager.get_ui_font_bold(9)
        _logger.debug(
            "theme_fonts_resolved",
            heading=heading_font.family(),
            code_bold=code_bold.family(),
            ui_bold=ui_bold.family(),
        )

        code_highlighter = self._tool_panel.get_code_highlighter()
        if code_highlighter is not None:
            code_highlighter.rehighlight()

        self.status_update.emit(f"Theme switched to {theme_name}")

    def _on_focus_chat_input(self) -> None:
        """Focus the chat input field."""
        self._chat_panel.set_focus_input()

    def _on_about(self) -> None:
        """Handle about action."""
        font_info = self._font_manager.get_font_info()
        code_font = font_info.get("code_font", "unknown")
        ui_font = font_info.get("ui_font", "unknown")
        custom_loaded = font_info.get("custom_fonts_available", False)

        status_icon = self._icon_manager.get_status_icon(True)
        has_icon = not status_icon.isNull()

        about_text = (
            "Intellicrack\n\n"
            "AI-powered reverse engineering platform for analyzing\n"
            "software licensing protections.\n\n"
            f"Version {__version__}\n"
            f"License: {__license__}\n"
            f"{__copyright__}\n\n"
            f"Code Font: {code_font}\n"
            f"UI Font: {ui_font}\n"
            f"Custom Fonts: {'Yes' if custom_loaded else 'No'}\n"
            f"Icons Loaded: {'Yes' if has_icon else 'No'}"
        )
        QMessageBox.about(self, "About Intellicrack", about_text)

    def _on_open_x64dbg(self) -> None:
        """Open x64dbg debugger panel."""
        try:
            tool_reg = getattr(self._orchestrator, "_tool_registry", None)
            if tool_reg is not None:
                ensure_ready = getattr(tool_reg, "ensure_tool_ready", None)
                if callable(ensure_ready):
                    ensure_ready("x64dbg")

            widget = self._tool_panel.add_x64dbg_tab(is_64bit=True)
            if widget is None:
                self._show_tool_error("x64dbg", "Failed to initialize x64dbg panel")
                return
            widget.start_tool()
        except Exception as e:
            _logger.exception("tool_open_failed", tool_name="x64dbg", error=str(e))
            self._show_tool_error("x64dbg", f"Failed to open x64dbg panel: {e}")

    def _on_open_cutter(self) -> None:
        """Open Cutter reverse engineering panel."""
        try:
            widget = self._tool_panel.add_cutter_tab()
            if widget is None:
                self._show_tool_error("Cutter", "Failed to initialize Cutter panel")
                return
            widget.start_tool()
        except Exception as e:
            _logger.exception("tool_open_failed", tool_name="Cutter", error=str(e))
            self._show_tool_error("Cutter", f"Failed to open Cutter panel: {e}")

    def _on_open_hxd(self) -> None:
        """Open hex editor panel."""
        try:
            widget = self._tool_panel.add_hxd_tab()
            if widget is None:
                self._show_tool_error("Hex Editor", "Failed to initialize hex editor panel")
                return
            widget.start_tool()
        except Exception as e:
            _logger.exception("tool_open_failed", tool_name="HxD", error=str(e))
            self._show_tool_error("Hex Editor", f"Failed to open hex editor panel: {e}")

    def _on_open_ghidra(self) -> None:
        """Open Ghidra analysis panel."""
        try:
            tool_reg = getattr(self._orchestrator, "_tool_registry", None)
            if tool_reg is not None:
                ensure_ready = getattr(tool_reg, "ensure_tool_ready", None)
                if callable(ensure_ready):
                    ensure_ready("ghidra")

            widget = self._tool_panel.add_ghidra_tab()
            if widget is None:
                self._show_tool_error("Ghidra", "Failed to initialize Ghidra panel")
                return
            widget.start_tool()
        except Exception as e:
            _logger.exception("tool_open_failed", tool_name="Ghidra", error=str(e))
            self._show_tool_error("Ghidra", f"Failed to open Ghidra panel: {e}")

    def _on_open_frida(self) -> None:
        """Open Frida instrumentation panel."""
        try:
            tool_reg = getattr(self._orchestrator, "_tool_registry", None)
            if tool_reg is not None:
                ensure_ready = getattr(tool_reg, "ensure_tool_ready", None)
                if callable(ensure_ready):
                    ensure_ready("frida")

            panel = self._tool_panel.add_frida_tab()
            if panel is None:
                self._show_tool_error("Frida", "Failed to initialize Frida panel")
                return
            panel.start_tool()

            frida_bridge = self._tool_panel.get_bridge_for_tool("frida")
            if frida_bridge is not None:
                set_handler = getattr(frida_bridge, "set_message_handler", None)
                if callable(set_handler):

                    def _frida_msg_handler(message: object) -> None:
                        text = message if isinstance(message, str) else str(message)
                        self._tool_panel.log_frida_message(text)
                        if isinstance(message, dict):
                            msg_dict = cast("dict[str, object]", message)
                            if msg_dict.get("type") == "hook":
                                self._tool_panel.add_frida_hook_entry(msg_dict)

                    set_handler(_frida_msg_handler)
        except Exception as e:
            _logger.exception("tool_open_failed", tool_name="Frida", error=str(e))
            self._show_tool_error("Frida", f"Failed to open Frida panel: {e}")

    def _on_open_process(self) -> None:
        """Open process manager panel."""
        panel = self._tool_panel.add_process_tab()
        if panel is None:
            self._show_tool_error("Process", "Failed to initialize Process panel")
            return
        panel.start_tool()

    def _on_open_binary(self) -> None:
        """Open binary hex viewer panel."""
        panel = self._tool_panel.add_binary_tab()
        if panel is None:
            self._show_tool_error("Binary", "Failed to initialize Binary panel")
            return
        panel.start_tool()
        if self._current_binary is not None:
            self._tool_panel.open_in_binary(self._current_binary)

    def _on_open_sandbox_panel(self) -> None:
        """Open sandbox manager panel."""
        panel = self._tool_panel.add_sandbox_tab()
        if panel is None:
            self._show_tool_error("Sandbox", "Failed to initialize Sandbox panel")
            return
        self._tool_panel.wire_sandbox_backend(self._sandbox_manager, manager=self._sandbox_manager)
        panel.start_tool()

        sandbox_backend = self._tool_panel.get_sandbox_backend()
        if sandbox_backend is not None:
            _logger.debug("sandbox_backend_available", backend_type=type(sandbox_backend).__name__)

        sandbox_widget = self._tool_panel.get_active_tool_widget("sandbox")
        if sandbox_widget is not None:
            _logger.debug("sandbox_widget_active", widget_type=type(sandbox_widget).__name__)

    def _on_debug_current_binary(self) -> None:
        """Debug the currently loaded binary with x64dbg."""
        if self._current_binary is None:
            self._show_no_binary_warning("debug")
            return
        if not self._tool_panel.open_in_x64dbg(self._current_binary):
            self._show_tool_error("x64dbg", "Failed to open binary in x64dbg")

    def _on_analyze_current_binary(self) -> None:
        """Analyze the currently loaded binary with Cutter."""
        if self._current_binary is None:
            self._show_no_binary_warning("analyze")
            return
        if not self._tool_panel.open_in_cutter(self._current_binary):
            self._show_tool_error("Cutter", "Failed to open binary in Cutter")

    def _on_hex_edit_current_binary(self) -> None:
        """Open the currently loaded binary in HxD hex editor."""
        if self._current_binary is None:
            self._show_no_binary_warning("hex edit")
            return
        if not self._tool_panel.open_in_hxd(self._current_binary):
            self._show_tool_error("HxD", "Failed to open binary in HxD")

    def _on_open_binary_in_ghidra(self) -> None:
        """Open the currently loaded binary in the Ghidra panel."""
        if self._current_binary is None:
            self._show_no_binary_warning("Ghidra analysis")
            return
        if not self._tool_panel.open_in_ghidra(self._current_binary):
            self._show_tool_error("Ghidra", "Failed to open binary in Ghidra")

    def _show_tool_error(self, tool_name: str, message: str) -> None:
        """Show tool-related error dialog.

        Args:
            tool_name: Name of the tool.
            message: Error message to display.
        """
        _logger.error("tool_error", tool_name=tool_name, error=message)
        QMessageBox.warning(
            self,
            f"{tool_name} Error",
            message,
            QMessageBox.StandardButton.Ok,
        )

    def _show_no_binary_warning(self, action: str) -> None:
        """Show warning when no binary is loaded.

        Args:
            action: The action being attempted.
        """
        QMessageBox.information(
            self,
            "No Binary Loaded",
            f"Please load a binary first before attempting to {action} it.",
            QMessageBox.StandardButton.Ok,
        )

    def _on_provider_changed(self, index: int) -> None:
        """Handle provider selection change.

        Args:
            index: New selection index.
        """
        del index
        provider: object = self._provider_combo.currentData()
        provider_value = provider.value if isinstance(provider, ProviderName) else None
        _logger.info("provider_changed", provider=provider_value)

    def _on_sandbox_toggled(self, checked: bool) -> None:
        """Handle sandbox toggle.

        Args:
            checked: Whether sandbox is enabled.
        """
        self._sandbox_btn.setText(f"Sandbox: {'ON' if checked else 'OFF'}")

    def _on_auto_approve_toggled(self, checked: bool) -> None:
        """Handle auto-approve toggle.

        Args:
            checked: Whether auto-approve is enabled.
        """
        types_module = importlib.import_module("intellicrack.core.types")

        self._auto_approve_btn.setText(f"Auto-approve: {'ON' if checked else 'OFF'}")

        if checked:
            self._orchestrator.set_confirmation_level(types_module.ConfirmationLevel.NONE)
            self.status_update.emit("Auto-approve enabled - all tool calls will be approved automatically")
        else:
            self._orchestrator.set_confirmation_level(types_module.ConfirmationLevel.DESTRUCTIVE)
            self.status_update.emit("Auto-approve disabled - destructive operations require confirmation")

    def _on_cancel(self) -> None:
        """Handle cancel button click."""

        async def cancel() -> None:
            await self._orchestrator.cancel()

        self._run_async(cancel())
        self.status_update.emit("Cancelling...")

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Handle window close event.

        Args:
            a0: Close event.
        """
        self._tool_panel.close_embedded_tools()

        shutdown_fn = getattr(
            importlib.import_module(".panels.async_bridge", "intellicrack.ui"),
            "shutdown_bridge_loop",
            None,
        )
        if callable(shutdown_fn):
            shutdown_fn()

        if self._current_worker and self._current_worker.isRunning():
            self._current_worker.wait()

        if a0 is not None:
            a0.accept()
