# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Main application window for Intellicrack.

This module provides the main PyQt6 application window that combines all UI components and connects them to the orchestrator.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PyQt6.QtCore import QByteArray, QObject, QSettings, QSignalBlocker, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack._metadata import __copyright__, __license__, __version__
from intellicrack.bridges.installer import ToolInstaller
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.config import get_config_dir, get_config_file
from intellicrack.core.logging import get_logger, log_tool_call
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.script_gen import ScriptGenerator, ScriptManager
from intellicrack.core.types import (
    ConfigurationError,
    Message,
    ModelInfo,
    ProviderCredentials,
    ProviderError,
    ProviderName,
    ToolCall,
    ToolError,
    ToolName,
    ToolResult,
)
from intellicrack.credentials import get_credentials
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.sandbox import SandboxConfig, SandboxManager
from intellicrack.ui._screen_compat import get_screen_geometry, move_widget
from intellicrack.ui.chat import ChatPanel
from intellicrack.ui.log_viewer import LogViewerWindow, install_qt_log_handler
from intellicrack.ui.overflow_toolbar import OverflowToolBar
from intellicrack.ui.panels.async_bridge import (
    run_bridge_coroutine,
    run_bridge_coroutine_async,
    run_bridge_coroutine_logged,
)
from intellicrack.ui.panels.hxd_panel import HxDPanel, find_hxd_executable
from intellicrack.ui.provider_config import ModelRefreshWorker, ModelSelectionDialog, ProviderConfigDialog
from intellicrack.ui.resources import FontManager, IconManager, ThemeManager
from intellicrack.ui.sandbox_config import SandboxConfigDialog, SandboxMonitorWidget
from intellicrack.ui.session_manager import SessionManagerDialog
from intellicrack.ui.tool_config import ToolConfigDialog, ToolStatusDialog, ToolStatusEntry
from intellicrack.ui.tools import ToolOutputPanel
from intellicrack.ui.xpu_status import XPUStatusDialog


_logger = get_logger(__name__)


try:
    from intellicrack.providers.model_loader import get_global_model_cache, set_global_cache_size
except ImportError:
    _logger.debug("model_loader_unavailable")
    get_global_model_cache = None
    set_global_cache_size = None


try:
    import intellicrack_hexcore as _hexcore
except ImportError:
    _logger.debug("hexcore_unavailable")
    _hexcore = None


if TYPE_CHECKING:
    import types
    from collections.abc import Callable, Coroutine

    from PyQt6.QtGui import QCloseEvent

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.template_manager import TemplateManager
    from intellicrack.sandbox.base import SandboxBase

_MAX_RESULT_DISPLAY_LEN = 500
_STATUS_REFRESH_FAILURE_THRESHOLD = 5
_SPLITTER_PANE_COUNT = 2

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
    _logger.error(
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

    Attributes:
        finished: Qt signal for finished.
        error: Qt signal for error.
    """

    finished = pyqtSignal(object)
    error = pyqtSignal(Exception)

    def __init__(
        self,
        coro: Coroutine[object, object, object],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the AsyncWorker with the given coroutine.

        Args:
            coro: Coroutine to execute in a separate thread.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._coro: Coroutine[object, object, object] = coro

    def run(self) -> None:
        """Run the coroutine in a new event loop.

        Cancels any still-pending tasks and awaits their completion before
        closing the loop so ``asyncio.CancelledError`` cannot leak and orphan
        tasks are not abandoned.  Non-``SystemExit`` failures are reported
        back to the UI thread via the ``error`` signal; ``SystemExit`` is
        propagated so the interpreter can shut down.

        Raises:
            SystemExit: Re-raised to allow interpreter shutdown when the
                worker coroutine (or its teardown) exits the process.
        """
        loop: asyncio.AbstractEventLoop | None = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result: object = loop.run_until_complete(self._coro)
            self.finished.emit(result)
        except asyncio.CancelledError:
            _logger.info("async_worker_cancelled")
            self.error.emit(RuntimeError("async operation cancelled"))
        except SystemExit:
            raise
        except BaseException as exc:
            _logger.exception("async_worker_failed")
            self.error.emit(exc if isinstance(exc, Exception) else RuntimeError(str(exc) or type(exc).__name__))
        finally:
            if loop is not None:
                try:
                    pending = asyncio.all_tasks(loop=loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except (RuntimeError, OSError):
                    _logger.debug("async_worker_pending_cancel_failed", exc_info=True)
                loop.close()


class MainWindow(QMainWindow):
    """Main application window for Intellicrack.

    Combines chat panel, tool output panel, menus, and toolbar
    into the main application interface.

    Attributes:
        message_received: Qt signal for message received.
        tool_call_received: Qt signal for tool call received.
        tool_result_received: Qt signal for tool result received.
        stream_chunk_received: Qt signal for stream chunk received.
        status_update: Qt signal for status update.
        bridge_analysis_received: Qt signal for bridge analysis received.
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
        """Initialize the MainWindow with the given configuration and orchestrator.

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
        self.sandbox_manager = SandboxManager()
        self.model_refresh_worker: ModelRefreshWorker | None = None
        self.model_browse_worker: AsyncWorker | None = None
        self._shutting_down: bool = False

        self.current_binary: Path | None = None
        self._script_manager: object | None = None
        self._script_validator: object | None = None
        self._script_generator: ScriptGenerator | None = None
        self.template_manager: TemplateManager | None = None
        self.model_discovery: ModelDiscovery | None = None
        self._hxd_panel: HxDPanel | None = None
        self._sandbox_monitor_wired_widgets: weakref.WeakSet[QObject] = weakref.WeakSet()
        self._process_attached_wired: weakref.WeakSet[QObject] = weakref.WeakSet()
        self._status_failure_count: int = 0
        self._session_token_total: int = 0
        self._binary_dependent_buttons: list[QPushButton] = []
        self._initial_discovery_triggered: bool = False

        _logger.debug("loading_icon_manager")
        self._icon_manager = IconManager.get_instance()
        _logger.debug("loading_font_manager")
        self._font_manager = FontManager.get_instance()
        _logger.debug("loading_theme_manager")
        self._theme_manager = ThemeManager.get_instance()
        self._theme_manager.theme_changed.connect(self._on_theme_changed)

        _logger.debug("loading_fonts")
        self._font_manager.load_fonts()

        self._icon_manager.preload_icons(["app", "binary", "tools", "provider", "sandbox", "process"])

        try:
            install_qt_log_handler()
        except (RuntimeError, OSError, ValueError):
            _logger.exception("qt_log_handler_install_failed")

        self._log_viewer_window: LogViewerWindow | None = None

        self._initialize_model_cache()

        _logger.info("ui_init_setup_ui")
        self._setup_ui()
        _logger.info("ui_init_register_hxd_panel")
        self._register_hxd_panel_if_available()
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

        _logger.info("ui_init_apply_configured_theme", theme=self._config.ui.theme)
        self._theme_manager.apply_theme(self._config.ui.theme)

        self._apply_smart_window_size()
        self._restore_window_state()
        QTimer.singleShot(250, self._kickoff_initial_discovery)

    def _apply_smart_window_size(self) -> None:
        """Size and center the window based on available screen geometry.

        Detects the primary monitor's usable area (excluding taskbar) and sizes the window slightly smaller with a small margin. Caps at
        1400x900 on large screens and floors at 800x600 minimum. Falls back to 1400x900 if screen detection fails.
        """
        max_w, max_h = 1400, 900
        min_w, min_h = 800, 600
        margin_w, margin_h = 6, 8

        geometry = self._resolve_screen_geometry()
        if geometry is None:
            self.resize(max_w, max_h)
            return

        try:
            avail_x, avail_y, avail_w, avail_h = geometry
            target_w = max(min_w, min(max_w, avail_w - margin_w))
            target_h = max(min_h, min(max_h, avail_h - margin_h))

            self.resize(target_w, target_h)
            move_widget(
                self,
                avail_x + (avail_w - target_w) // 2,
                avail_y + (avail_h - target_h) // 2,
            )
        except (AttributeError, RuntimeError, ValueError):
            _logger.debug("screen_detection_failed_using_default_size", exc_info=True)
            self.resize(max_w, max_h)

    @staticmethod
    def _resolve_screen_geometry() -> tuple[int, int, int, int] | None:
        """Resolve the usable screen geometry tuple for window sizing.

        Returns:
            tuple[int, int, int, int] | None: ``(x, y, width, height)`` tuple
            of the primary screen's available geometry, or ``None`` when no
            ``QApplication`` instance is active or the geometry cannot be
            resolved.
        """
        app = QApplication.instance()
        if not isinstance(app, QApplication):
            _logger.debug("screen_geometry_unavailable_using_default", reason="no_qapplication")
            return None
        geometry = get_screen_geometry(app)
        if geometry is None:
            _logger.debug("screen_geometry_unavailable_using_default", reason="geometry_none")
            return None
        return geometry

    def _save_window_state(self) -> None:
        """Persist window geometry, splitter sizes, tab state, and detached panels to QSettings."""
        settings = QSettings("Intellicrack", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("splitter_sizes", self._splitter.sizes())

        tab_state = self.tool_panel.save_tab_state()
        settings.setValue("tab_state/tab_names", tab_state.get("tab_names"))
        settings.setValue("tab_state/active_index", tab_state.get("active_index"))
        settings.setValue("tab_state/splitter_sizes", tab_state.get("splitter_sizes"))

        detached_titles = self.tool_panel.get_detached_state()
        settings.setValue("detached_panels", detached_titles)

        _logger.debug("window_state_saved")

    def _restore_window_state(self) -> None:
        """Restore window geometry, splitter sizes, and tab state from QSettings."""
        settings = QSettings("Intellicrack", "MainWindow")

        geometry = settings.value("geometry")
        if isinstance(geometry, QByteArray):
            self.restoreGeometry(geometry)

        raw_splitter = settings.value("splitter_sizes")
        if isinstance(raw_splitter, list):
            parsed_sizes: list[int] = [int(val) for val in cast("list[object]", raw_splitter) if isinstance(val, (str, int, float))]
            if len(parsed_sizes) == _SPLITTER_PANE_COUNT:
                self._splitter.setSizes(parsed_sizes)

        tab_state: dict[str, object] = {}
        tab_names = settings.value("tab_state/tab_names")
        if tab_names is not None:
            tab_state["tab_names"] = tab_names
        active_idx = settings.value("tab_state/active_index")
        if isinstance(active_idx, str):
            tab_state["active_index"] = int(active_idx)
        elif isinstance(active_idx, int):
            tab_state["active_index"] = active_idx
        tool_splitter = settings.value("tab_state/splitter_sizes")
        if tool_splitter is not None:
            tab_state["splitter_sizes"] = tool_splitter

        if tab_state:
            self.tool_panel.restore_tab_state(tab_state)

        detached_raw = settings.value("detached_panels")
        if isinstance(detached_raw, list):
            detached_list = cast("list[str]", detached_raw)
            for title in detached_list:
                tab_idx = self.tool_panel.find_tab_by_title(title)
                if tab_idx >= 0:
                    self.tool_panel.detach_tab(tab_idx)

        _logger.debug("window_state_restored")

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
        self.tool_panel.wire_script_backend(manager, validator)
        _logger.debug("script_manager_wired")

    def wire_sandbox_backend(self, sandbox: SandboxBase, manager: SandboxManager | None = None) -> None:
        """Inject an externally constructed sandbox backend into the UI.

        Public entry point used by plugins, CLI bootstraps, and the
        application startup path to register a pre-existing ``SandboxBase``
        (and optional ``SandboxManager``) so the sandbox tab, chat workflow,
        and AI bridges can drive it. When ``manager`` is supplied it
        replaces the lazy manager on the resulting ``SandboxBridge``;
        otherwise the bridge constructs its own. The supplied manager (or
        the bridge's lazily created one) is also installed on the window
        as :attr:`sandbox_manager` so the sandbox configuration dialog and
        teardown paths see the same instance the panel sees.

        Args:
            sandbox: Pre-constructed ``SandboxBase`` implementation.
            manager: Optional pre-constructed ``SandboxManager`` to install
                on the resulting bridge. When ``None`` the bridge's lazy
                manager is used.
        """
        self.tool_panel.wire_sandbox_backend(sandbox, manager)
        wired_bridge = self.tool_panel.get_sandbox_bridge()
        wired_manager = getattr(wired_bridge, "manager", None)
        if isinstance(wired_manager, SandboxManager):
            self.sandbox_manager = wired_manager
        _logger.info(
            "main_window_sandbox_backend_wired",
            sandbox_type=type(sandbox).__name__,
            had_manager=manager is not None,
        )

    def set_script_generator(self, generator: ScriptGenerator) -> None:
        """Persist the application-scoped ScriptGenerator instance.

        ``ScriptGenerator`` is the API surface used by AI/tool bridges to
        prepare prompts for script generation. Holding the instance on the
        main window keeps it alive for the lifetime of the application and
        gives downstream panels a stable handle to reach it.

        Args:
            generator: ScriptGenerator instance constructed during startup.
        """
        self._script_generator = generator
        _logger.debug("script_generator_set")

    def set_template_manager(self, manager: TemplateManager) -> None:
        """Persist the application-scoped TemplateManager instance.

        ``TemplateManager`` owns the on-disk built-in and user template
        directories under ``config_dir/templates/`` and surfaces them to
        the hex editor pattern UI.

        Args:
            manager: TemplateManager instance bootstrapped during startup.
        """
        self.template_manager = manager
        _logger.debug("template_manager_set")

    def set_model_discovery(self, discovery: ModelDiscovery) -> None:
        """Set the model discovery instance.

        Args:
            discovery: ModelDiscovery for provider model enumeration.
        """
        self.model_discovery = discovery
        _logger.debug("model_discovery_set")

    def _initialize_model_cache(self) -> None:
        """Initialize model cache settings from configuration."""
        if set_global_cache_size is None:
            return
        try:
            max_cache = getattr(self._config, "max_model_cache_bytes", None)
            if isinstance(max_cache, int) and max_cache > 0:
                set_global_cache_size(max_cache)
        except (RuntimeError, ValueError, TypeError):
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

        self.tool_panel = ToolOutputPanel()
        self.tool_panel.setMinimumWidth(500)
        self._splitter.addWidget(self.tool_panel)

        self._splitter.setSizes([500, 900])

        layout.addWidget(self._splitter)

    @property
    def hxd_panel(self) -> HxDPanel | None:
        """Return the registered ``HxDPanel`` instance, if any.

        Returns:
            HxDPanel | None: The pre-registered ``HxDPanel`` instance, or
            ``None`` when HxD.exe was not locatable at MainWindow init time.
        """
        return self._hxd_panel

    def _register_hxd_panel_if_available(self) -> None:
        """Register HxDPanel as a docked tab next to HexEditorPanel when HxD.exe is reachable.

        Looks up the HxD executable using the shared finder. If found, instantiates ``HxDPanel`` and attaches it as a tab in the tool
        panel's ``QTabWidget`` so it sits alongside the built-in hex editor. If HxD is not installed, logs a debug record and returns
        silently without attaching anything.
        """
        if find_hxd_executable() is None:
            _logger.debug("hxd_panel_skipped_executable_not_found")
            return

        try:
            panel = HxDPanel()
        except (RuntimeError, OSError) as exc:
            _logger.warning("hxd_panel_construction_failed", error=str(exc))
            return

        try:
            self.tool_panel.tab_widget.addTab(panel, "HxD")
            self.tool_panel.embedded_tools["hxd"] = panel
        except (RuntimeError, AttributeError) as exc:
            _logger.warning("hxd_panel_tab_register_failed", error=str(exc))
            panel.cleanup()
            panel.deleteLater()
            return

        self._hxd_panel = panel
        _logger.info("hxd_panel_registered", tab="HxD")

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
        view_menu.addSeparator()
        self._add_menu_action(view_menu, "Detach Current Panel", self._on_detach_current, "Ctrl+Shift+D")

    def _on_view_analysis(self) -> None:
        """Show the bridge analysis panel."""
        self.tool_panel.activate_analysis_tab()

    def _on_view_scripts(self) -> None:
        """Show the scripts manager panel and surface the current script context.

        After activating the scripts tab, the previously selected script ID and current draft script name (if any) are reported through the
        application status bar so the user can confirm which script the panel is editing.
        """
        self.tool_panel.activate_scripts_tab()
        selected_id, current_script = self.tool_panel.get_script_panel_state()
        if current_script is not None:
            self.status_update.emit(f"Scripts: editing '{current_script[0]}'")
        elif selected_id is not None:
            self.status_update.emit(f"Scripts: selected '{selected_id}'")
        else:
            self.status_update.emit("Scripts: no script selected")

    def _on_view_stack(self) -> None:
        """Show the stack viewer panel."""
        self.tool_panel.activate_stack_tab()

    def _on_detach_current(self) -> None:
        """Detach the currently active tool panel into a floating window."""
        self.tool_panel.detach_current_tab()

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
        self._add_menu_action(embedded_menu, "Open Hex Editor", self._on_open_hex_editor)
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
        help_menu.addSeparator()
        self._add_menu_action(help_menu, "Log Viewer...", self._on_log_viewer)
        self._add_menu_action(help_menu, "XPU Status...", self._on_xpu_status)

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
        toolbar = OverflowToolBar("Main Toolbar")
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

        self.model_combo = QComboBox()
        self.model_combo.setMinimumWidth(200)
        self.model_combo.setObjectName("toolbar_combo")
        self.model_combo.setEditable(True)
        model_line_edit = self.model_combo.lineEdit()
        if model_line_edit is not None:
            model_line_edit.editingFinished.connect(self._on_model_combo_text_committed)
        toolbar.addWidget(self.model_combo)

        toolbar.addSeparator()

        tools_label = QLabel("Tools:")
        tools_label.setObjectName("toolbar_label")
        toolbar.addWidget(tools_label)

        self.x64dbg_btn = QPushButton("x64dbg")
        self.x64dbg_btn.setObjectName("tool_button")
        self.x64dbg_btn.setToolTip("Open x64dbg Debugger")
        self.x64dbg_btn.clicked.connect(self._on_open_x64dbg)
        self.x64dbg_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self.x64dbg_btn)
        toolbar.addWidget(self.x64dbg_btn)

        self.cutter_btn = QPushButton("Cutter")
        self.cutter_btn.setObjectName("tool_button")
        self.cutter_btn.setToolTip("Open Cutter Analysis")
        self.cutter_btn.clicked.connect(self._on_open_cutter)
        self.cutter_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self.cutter_btn)
        toolbar.addWidget(self.cutter_btn)

        self.hxd_btn = QPushButton("HxD")
        self.hxd_btn.setObjectName("tool_button")
        self.hxd_btn.setToolTip("Open HxD Hex Editor")
        self.hxd_btn.clicked.connect(self._on_open_hxd)
        self.hxd_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self.hxd_btn)
        toolbar.addWidget(self.hxd_btn)

        self._hex_editor_btn = QPushButton("Hex Editor")
        self._hex_editor_btn.setObjectName("tool_button")
        self._hex_editor_btn.setToolTip("Open Hex Editor")
        self._hex_editor_btn.clicked.connect(self._on_open_hex_editor)
        self._hex_editor_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self._hex_editor_btn)
        toolbar.addWidget(self._hex_editor_btn)

        self._ghidra_btn = QPushButton("Ghidra")
        self._ghidra_btn.setObjectName("tool_button")
        self._ghidra_btn.setToolTip("Open Ghidra Reverse Engineering")
        self._ghidra_btn.clicked.connect(self._on_open_ghidra)
        self._ghidra_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self._ghidra_btn)
        toolbar.addWidget(self._ghidra_btn)

        self._frida_btn = QPushButton("Frida")
        self._frida_btn.setObjectName("tool_button")
        self._frida_btn.setToolTip("Open Frida Instrumentation Panel")
        self._frida_btn.clicked.connect(self._on_open_frida)
        self._frida_btn.setEnabled(False)
        self._binary_dependent_buttons.append(self._frida_btn)
        toolbar.addWidget(self._frida_btn)

        self.process_btn = QPushButton("Process")
        self.process_btn.setObjectName("tool_button")
        self.process_btn.setToolTip("Open Process Manager")
        self.process_btn.clicked.connect(self._on_open_process)
        toolbar.addWidget(self.process_btn)

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
        saved_auto_approve_raw: object = QSettings("Intellicrack", "MainWindow").value("auto_approve", defaultValue=False)
        initial_auto_approve: bool = (
            bool(saved_auto_approve_raw)
            if isinstance(saved_auto_approve_raw, bool)
            else str(saved_auto_approve_raw).lower() in {"true", "1"}
        )
        self._auto_approve_btn.setChecked(initial_auto_approve)
        self._auto_approve_btn.setText(f"Auto-approve: {'ON' if initial_auto_approve else 'OFF'}")

        def _auto_approve_slot(state: int) -> None:
            self._on_auto_approve_toggled(checked=bool(state))

        self._auto_approve_btn.toggled.connect(_auto_approve_slot)
        toolbar.addWidget(self._auto_approve_btn)

        self._sandbox_btn = QPushButton("Sandbox: OFF")
        self._sandbox_btn.setCheckable(True)
        self._sandbox_btn.setObjectName("toggle_button")

        def _sandbox_slot(state: int) -> None:
            self._on_sandbox_toggled(checked=bool(state))

        self._sandbox_btn.toggled.connect(_sandbox_slot)
        toolbar.addWidget(self._sandbox_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("danger_button")
        cancel_btn.clicked.connect(self._on_cancel)
        toolbar.addWidget(cancel_btn)

    def _setup_statusbar(self) -> None:
        """Set up the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        self.status_label = QLabel("Ready")
        self._statusbar.addWidget(self.status_label)

        self._binary_label = QLabel("")
        self._statusbar.addPermanentWidget(self._binary_label)

        self._memory_label = QLabel("")
        self._statusbar.addPermanentWidget(self._memory_label)

        self.model_status_label = QLabel("")
        self._statusbar.addPermanentWidget(self.model_status_label)

        self._token_label = QLabel("")
        self._statusbar.addPermanentWidget(self._token_label)

        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_system_status)
        self._status_timer.start(30000)

    def _refresh_system_status(self) -> None:
        """Periodically refresh the system status display.

        Tracks consecutive failures of the orchestrator status fetch and stops the periodic timer after
        :data:`_STATUS_REFRESH_FAILURE_THRESHOLD` consecutive errors so the status bar does not silently mask a broken orchestrator with
        debug logs forever.
        """
        if self._shutting_down:
            return

        async def fetch_status() -> dict[str, object]:
            return await self._orchestrator.get_system_status()

        try:
            status = run_bridge_coroutine(fetch_status())
        except (RuntimeError, AttributeError, OSError) as exc:
            self._status_failure_count += 1
            _logger.warning(
                "system_status_refresh_failed",
                error=str(exc),
                failure_count=self._status_failure_count,
                threshold=_STATUS_REFRESH_FAILURE_THRESHOLD,
            )
            if self._status_failure_count >= _STATUS_REFRESH_FAILURE_THRESHOLD:
                self._status_timer.stop()
                _logger.exception(
                    "system_status_timer_stopped",
                    consecutive_failures=self._status_failure_count,
                )
                self.status_label.setText("Status refresh disabled (see logs)")
            return

        self._status_failure_count = 0
        if status is not None:
            state = status.get("state", "unknown")
            session_id = status.get("session_id")
            session_text = f" | Session: {session_id}" if session_id else ""
            self.status_label.setText(f"State: {state}{session_text}")
            metrics_obj: object = status.get("metrics")
            if isinstance(metrics_obj, dict):
                metrics_dict = cast("dict[str, object]", metrics_obj)
                total_tokens_obj: object = metrics_dict.get("provider_total_tokens", 0)
                if isinstance(total_tokens_obj, int) and total_tokens_obj > 0 and total_tokens_obj != self._session_token_total:
                    self._session_token_total = total_tokens_obj
                    self._token_label.setText(f"Tokens: {self._session_token_total:,}")

        self._refresh_memory_status()
        self._refresh_model_discovery_status()

    @staticmethod
    def _compute_memory_label_text() -> str:
        """Compute the memory usage label text from the global model cache.

        Returns:
            str: Formatted cache usage string, or empty string when no usage.
        """
        if get_global_model_cache is None:
            return ""
        total_bytes = get_global_model_cache().get_memory_usage()
        if total_bytes > 0:
            mb = total_bytes / (1024 * 1024)
            return f"Cache: {mb:.0f}MB"
        return ""

    def _refresh_memory_status(self) -> None:
        """Update the memory usage display in the status bar."""
        if get_global_model_cache is None:
            self._memory_label.setText("")
            return
        try:
            self._memory_label.setText(self._compute_memory_label_text())
        except (RuntimeError, AttributeError, ValueError):
            _logger.debug("memory_label_update_failed", exc_info=True)
            self._memory_label.setText("")

    def _refresh_model_discovery_status(self) -> None:
        """Update the model discovery status in the status bar."""
        if self.model_discovery is None:
            return
        try:
            if events := self.model_discovery.get_discovery_events():
                last_event = events[-1]
                provider_str = last_event.provider.value
                status_str = "OK" if last_event.success else (last_event.error_message or "failed")
                self.model_status_label.setText(f"Discovery: {provider_str} {status_str}")
        except (RuntimeError, AttributeError, ValueError):
            _logger.debug("model_discovery_status_refresh_failed", exc_info=True)

    def _connect_signals(self) -> None:
        """Connect Qt signals."""
        self._chat_panel.message_submitted.connect(self._on_user_message)
        self.message_received.connect(self._chat_panel.add_message)
        self.tool_call_received.connect(self._on_tool_call)
        self.tool_result_received.connect(self._on_tool_result)
        self.stream_chunk_received.connect(self._on_stream_chunk)
        self.status_update.connect(self._update_status)
        self.tool_panel.address_clicked.connect(self._on_address_clicked)
        self.tool_panel.hex_context_ready.connect(self._on_hex_context_ready)
        self.tool_panel.embedded_tool_started.connect(self._on_embedded_tool_started)
        self.tool_panel.embedded_tool_closed.connect(self._on_embedded_tool_closed)
        self.bridge_analysis_received.connect(self._on_bridge_analysis_activated)

    def _on_embedded_tool_started(self, tool_id: str) -> None:
        """Handle embedded-tool start broadcast from ``ToolOutputPanel``.

        Args:
            tool_id: Identifier of the embedded tool that started.
        """
        _logger.info("embedded_tool_started", tool_id=tool_id)
        self.status_update.emit(f"{tool_id} started")

    def _on_embedded_tool_closed(self, tool_id: str) -> None:
        """Handle embedded-tool close broadcast from ``ToolOutputPanel``.

        Args:
            tool_id: Identifier of the embedded tool that closed.
        """
        _logger.info("embedded_tool_closed", tool_id=tool_id)
        self.status_update.emit(f"{tool_id} closed")

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
        self.bridge_analysis_received.connect(self.tool_panel.update_bridge_analysis)

        try:
            scripts_dir = get_config_dir() / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            script_mgr = ScriptManager(scripts_dir)
            self._orchestrator.set_script_manager(script_mgr)
        except OSError:
            _logger.warning("script_manager_init_skipped")

        available_tools = self._orchestrator.get_available_tool_names()
        _logger.info("orchestrator_tools_available", tools=available_tools)

        tool_reg = self._orchestrator.tool_registry
        self.tool_panel.set_tool_registry(tool_reg)
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
        except OSError:
            _logger.warning("tool_installer_init_skipped")

    async def _refresh_tool_status(self) -> dict[str, ToolStatusEntry]:
        """Refresh tool installation status asynchronously.

        Builds a snapshot of every tool's current availability suitable for
        feeding directly into :class:`ToolStatusDialog` (and any future
        prefetch-aware consumer). Keys are the lowercase ``ToolName.value``
        identifiers used elsewhere in the UI (``"ghidra"``, ``"x64dbg"``,
        ``"frida"``, ``"cutter"``, ``"process"``, ``"sandbox"``,
        ``"hex_editor"``).

        Returns:
            dict[str, ToolStatusEntry]: Mapping of tool IDs to typed status
            payloads with ``available``, ``path`` and ``message`` fields.
            An empty dict is returned when the installer is unavailable.
        """
        installer = getattr(self, "_tool_installer", None)
        if installer is None:
            return {}

        statuses = await installer.get_all_tool_status()
        result: dict[str, ToolStatusEntry] = {}
        for tool_name, (available, path) in statuses.items():
            tool_id = tool_name.value if isinstance(tool_name, ToolName) else str(tool_name)
            message = (f"Installed at {path}" if path is not None else "Available") if available else "Not installed"
            entry: ToolStatusEntry = {
                "available": bool(available),
                "path": str(path) if path is not None else None,
                "message": message,
            }
            result[tool_id] = entry
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
        _logger.debug("bridge_analysis_received", analysis_type=type(analysis).__name__)
        self.tool_panel.clear_analysis_tab("analysis")
        self.tool_panel.display_analysis_result("analysis", str(analysis))
        self.bridge_analysis_received.emit(analysis)

    def _on_bridge_analysis_activated(self, _analysis: object) -> None:
        """Activate the analysis tab after bridge analysis completes.

        Args:
            _analysis: The bridge analysis result (unused here).
        """
        self.tool_panel.activate_analysis_tab()

    def _request_tool_confirmation(self, call: ToolCall) -> asyncio.Future[bool]:
        """Request user confirmation for a tool call.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            asyncio.Future[bool]: Future that resolves to True if approved, False otherwise.
        """
        confirmation_module = importlib.import_module(".confirmation_dialog", "intellicrack.ui")

        future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()

        def show_dialog() -> None:
            dialog = confirmation_module.ToolConfirmationDialog(call, self)
            dialog.exec()
            self._orchestrator.resolve_confirmation(approved=dialog.approved)
            try:
                future.set_result(dialog.approved)
            except asyncio.InvalidStateError:
                _logger.debug("confirmation_dialog_state_error", exc_info=True)

        QTimer.singleShot(0, show_dialog)

        return future

    def _on_user_message(self, text: str) -> None:
        """Handle user message submission.

        When no session is active yet, a new one is created implicitly from the
        provider and model currently selected in the toolbar so the message can
        be processed without requiring an explicit "New Session" action first.

        Args:
            text: User's message text.
        """
        needs_session = self._orchestrator.current_session is None
        provider: str | ProviderName | None = None
        model = ""
        if needs_session:
            provider, model = self._selected_provider_model()
            if not model:
                self.status_update.emit("Select a model before sending")
                QMessageBox.warning(
                    self,
                    "No Model Selected",
                    "Select a model in the toolbar before sending a message.",
                )
                return

        self._chat_panel.set_input_enabled(enabled=False)
        self._stream_append = self._chat_panel.add_streaming_message()
        self.status_update.emit("Processing...")

        _logger.debug("user_message_received", length=len(text))
        active_pid = self.tool_panel.get_active_process_pid()
        if active_pid is not None:
            _logger.debug("user_message_process_context", pid=active_pid)

        async def process() -> None:
            if needs_session and provider is not None:
                await self._ensure_active_session(provider, model)
            await self._orchestrator.process_user_input(text)

        self._run_async(process())

    def _selected_provider_model(self) -> tuple[str | ProviderName, str]:
        """Return the provider and model currently selected in the toolbar.

        Returns:
            tuple[str | ProviderName, str]: The selected provider (a
            :class:`ProviderName` when the combo carries enum data, otherwise
            its string form) and the trimmed model identifier.
        """
        provider_data: object = self._provider_combo.currentData()
        model = self.model_combo.currentText().strip()
        provider: str | ProviderName = (
            provider_data if isinstance(provider_data, ProviderName) else str(provider_data)
        )
        return provider, model

    async def _ensure_active_session(self, provider: str | ProviderName, model: str) -> None:
        """Ensure an active session exists, creating one if necessary.

        Connects the selected provider first when it is not already connected,
        loading saved credentials from the credential store, then starts a new
        session bound to the provider and model.

        Args:
            provider: Provider selected in the toolbar.
            model: Model identifier selected in the toolbar.
        """
        if self._orchestrator.current_session is not None:
            return

        provider_name = provider if isinstance(provider, ProviderName) else ProviderName(str(provider).lower())

        registry = self._orchestrator.provider_registry
        instance = registry.get(provider_name)
        if instance is None or not instance.is_connected:
            await self._connect_provider_for_session(provider_name)

        _logger.info("implicit_session_create", provider=provider_name.value, model=model)
        await self._orchestrator.start_session(provider_name, model)

    async def _connect_provider_for_session(self, provider: ProviderName) -> None:
        """Connect a provider using stored credentials for implicit session start.

        Args:
            provider: Provider to connect.

        Raises:
            RuntimeError: If the provider cannot be connected, with guidance to
                configure credentials in Preferences.
        """
        credentials = await get_credentials(provider)
        if credentials is None:
            credentials = ProviderCredentials()

        registry = self._orchestrator.provider_registry
        try:
            await registry.connect_provider(provider, credentials)
        except (
            ProviderError,
            ConfigurationError,
            ConnectionError,
            TimeoutError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            _logger.warning("implicit_provider_connect_failed", provider=provider.value, error=str(exc))
            message = (
                f"Could not connect to provider '{provider.value}'. "
                "Configure its credentials in Preferences, then try again.\n\n"
                f"Details: {exc}"
            )
            raise RuntimeError(message) from exc

    def _on_stream_chunk(self, chunk: str) -> None:
        """Handle streaming response chunk.

        Args:
            chunk: Text chunk from LLM.
        """
        if self._stream_append:
            self._stream_append(chunk)
        self._accumulate_usage_from_payload(chunk)

    def _on_tool_call(self, call: ToolCall) -> None:
        """Handle tool call notification.

        Args:
            call: The tool call being executed.
        """
        self.status_update.emit(f"Running: {call.tool_name}.{call.function_name}")
        log_tool_call(
            call.tool_name,
            call.function_name,
            dict(getattr(call, "arguments", {})),
        )

    def _on_tool_result(self, result: ToolResult) -> None:
        """Handle tool result notification.

        Args:
            result: The tool execution result.
        """
        tool_name = getattr(result, "tool_name", "")
        if result.success:
            _logger.info(
                "orchestrator_tool_result",
                call_id=getattr(result, "call_id", ""),
                tool_name=tool_name,
                duration_ms=result.duration_ms,
            )
        else:
            _logger.warning(
                "orchestrator_tool_result_failed",
                call_id=getattr(result, "call_id", ""),
                tool_name=tool_name,
                duration_ms=result.duration_ms,
                error=result.error,
            )
        self._accumulate_usage_from_payload(result.result)

        if result.success and result.result:
            result_str = str(result.result)
            if len(result_str) > _MAX_RESULT_DISPLAY_LEN:
                result_str = f"{result_str[: _MAX_RESULT_DISPLAY_LEN - 3]}..."
            _logger.info(
                "orchestrator_tool_result_payload",
                tool_name=tool_name,
                call_id=getattr(result, "call_id", ""),
                result_preview=result_str,
            )

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
                    ),
                )

        if result.error:
            _logger.error(
                "orchestrator_tool_error",
                tool_name=tool_name,
                call_id=getattr(result, "call_id", ""),
                error=str(result.error),
            )

    def _accumulate_usage_from_payload(self, payload: object) -> None:
        """Accumulate ``total_tokens`` from a payload's ``usage`` dict into the session token total.

        The payload is inspected defensively: only mapping-style values with a
        ``usage`` member that exposes integer token counts are considered. Any
        other shape is ignored so streaming string chunks and arbitrary tool
        result objects can be passed without raising.

        Args:
            payload: Stream chunk or tool result payload that may carry a
                ``usage`` mapping with ``total_tokens`` (or
                ``input_tokens`` + ``output_tokens``) entries.
        """
        if not isinstance(payload, dict):
            return
        payload_dict = cast("dict[str, object]", payload)
        usage_obj: object = payload_dict.get("usage")
        if not isinstance(usage_obj, dict):
            return
        usage_dict = cast("dict[str, object]", usage_obj)
        total_raw: object = usage_dict.get("total_tokens")
        delta: int = 0
        if isinstance(total_raw, int):
            delta = total_raw
        else:
            input_raw: object = usage_dict.get("input_tokens", 0)
            output_raw: object = usage_dict.get("output_tokens", 0)
            input_val = input_raw if isinstance(input_raw, int) else 0
            output_val = output_raw if isinstance(output_raw, int) else 0
            delta = input_val + output_val
        if delta <= 0:
            return
        self._session_token_total += delta
        self._token_label.setText(f"Tokens: {self._session_token_total:,}")

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
        self._chat_panel.set_input_enabled(enabled=True)
        self._stream_append = None
        self.status_update.emit("Ready")

    def _on_async_error(self, error: Exception) -> None:
        """Handle async operation error.

        Args:
            error: The error that occurred.
        """
        self._chat_panel.set_input_enabled(enabled=True)
        self._stream_append = None
        self.status_update.emit("Error")
        QMessageBox.critical(self, "Error", str(error))

    def _update_status(self, status: str) -> None:
        """Update the status bar.

        Args:
            status: Status message.
        """
        self.status_label.setText(status)

    def _on_address_clicked(self, address: int) -> None:
        """Handle address click in the tool panel.

        Args:
            address: The clicked memory address.
        """
        self.tool_panel.set_current_address(address)
        self.status_update.emit(f"Navigated to 0x{address:08X}")

    def _on_hex_context_ready(self, context_text: str) -> None:
        """Handle hex editor context ready for AI analysis.

        Inserts the formatted hex editor context into the chat input
        so the user can review and submit it as a prompt.

        Args:
            context_text: Formatted hex context string.
        """
        self._chat_panel.insert_context_text(context_text)
        self.status_update.emit("Hex context loaded into chat input")
        _logger.info("hex_context_forwarded_to_chat", length=len(context_text))

    def _on_load_binary(self) -> None:
        """Handle load binary action."""
        _logger.info("load_binary_dialog_opened")
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "Executables (*.exe *.dll *.so *.dylib);;All Files (*)",
        )
        if path:
            _logger.info("load_binary_dialog_selection", path=path)
            self._load_binary(Path(path))
        else:
            _logger.info("load_binary_dialog_cancelled")

    def _load_binary(self, path: Path) -> None:
        """Load a binary file.

        Args:
            path: Path to the binary.
        """
        _logger.info("binary_loaded", path=str(path), binary_name=path.name)
        self.current_binary = path
        self._binary_label.setText(f"Binary: {path.name}")
        for button in self._binary_dependent_buttons:
            button.setEnabled(True)
        binary_name = path.name

        async def load() -> None:
            await self._orchestrator.add_binary(path)
            await self._orchestrator.activate_binary_by_name(binary_name)
            await self._orchestrator.refresh_session_state()

        self.status_update.emit(f"Loading {binary_name}...")
        self._run_async(load())

        self.tool_panel.open_in_hex_editor(str(path))

        cached_analysis = self._orchestrator.get_current_bridge_analysis(binary_name)
        if cached_analysis is not None:
            self.tool_panel.display_analysis_result(
                "analysis",
                str(cached_analysis),
            )

    def _on_new_session(self) -> None:
        """Handle new session action.

        Collects optional name and description from ``NewSessionDialog`` and forwards them to :meth:`Orchestrator.start_session`, which
        persists the name on the new session and stores the description as ``Session.notes``.
        """
        session_mgr_mod = importlib.import_module(".session_manager", "intellicrack.ui")
        new_session_cls = getattr(session_mgr_mod, "NewSessionDialog", None)
        session_name: str = ""
        description: str = ""
        if new_session_cls is not None:
            dialog = new_session_cls(parent=self)
            if not dialog.exec():
                return
            get_name = getattr(dialog, "get_session_name", None)
            if callable(get_name):
                session_name = str(get_name()).strip()
            get_desc = getattr(dialog, "get_description", None)
            if callable(get_desc):
                description = str(get_desc()).strip()
            _logger.debug("new_session_dialog", session_name=session_name, description=description)

        provider, model = self._selected_provider_model()

        if not model:
            QMessageBox.warning(self, "Warning", "Please select a model first.")
            return

        async def create_session() -> None:
            await self._orchestrator.start_session(
                provider,
                model,
                name=session_name or None,
                description=description or None,
            )

        _logger.info(
            "session_create_requested",
            provider=str(provider),
            model=model,
            session_name=session_name or None,
        )
        self._chat_panel.clear_messages()
        self.tool_panel.clear_all()
        self.status_update.emit("Creating new session...")
        self._run_async(create_session())

    def _on_load_session(self) -> None:
        """Handle load session action.

        Connects :attr:`SessionManagerDialog.session_loaded` and :attr:`SessionManagerDialog.session_deleted` to MainWindow handlers so the
        dialog's load button (which emits ``session_loaded`` and accepts the dialog) and delete button (which emits ``session_deleted``
        while keeping the dialog open) both trigger orchestrator-side state changes.
        """
        _logger.info("session_load_dialog_opened")
        dialog = SessionManagerDialog(parent=self)
        dialog.session_loaded.connect(self._on_session_load_requested)
        dialog.session_deleted.connect(self._on_session_deleted)
        if dialog.exec() and (session_id := dialog.get_selected_session_id()):
            _logger.info("session_load_dialog_selection", session_id=session_id)
            self._on_session_load_requested(session_id)

    def _on_session_load_requested(self, session_id: str) -> None:
        """Load a session by ID through the orchestrator.

        Args:
            session_id: Identifier of the session to load.
        """
        _logger.info("session_load_requested", session_id=session_id)

        async def load_session() -> None:
            await self._orchestrator.load_session(session_id)

        self._chat_panel.clear_messages()
        self.tool_panel.clear_all()
        self.status_update.emit(f"Loading session {session_id}...")
        self._run_async(load_session())

    def _on_session_deleted(self, session_id: str) -> None:
        """Handle a session deletion broadcast from the dialog.

        If the deleted session is the orchestrator's current session, request a
        cancel so any pending work tied to that session is aborted.

        Args:
            session_id: Identifier of the session that was deleted.
        """
        _logger.info("session_deleted_from_manager", session_id=session_id)
        current = self._orchestrator.current_session
        if current is not None and current.id == session_id:

            async def cancel_active() -> None:
                await self._orchestrator.cancel()

            self.status_update.emit(f"Active session {session_id} deleted; cancelling work")
            self._run_async(cancel_active())
        else:
            self.status_update.emit(f"Session deleted: {session_id}")

    def _on_save_session(self) -> None:
        """Handle save session action."""
        current = self._orchestrator.current_session
        _logger.info(
            "session_save_requested",
            session_id=current.id if current is not None else None,
        )

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
            _logger.info("chat_export_started", path=path, message_count=len(messages))
            with Path(path).open("w", encoding="utf-8") as f:
                for msg in messages:
                    role = msg.role.upper()
                    f.write(f"[{role}] {msg.timestamp.strftime('%H:%M:%S')}\n")
                    f.write(f"{msg.content}\n\n")
            _logger.info("chat_export_completed", path=path, message_count=len(messages))
            QMessageBox.information(self, "Export", f"Chat exported to {path}")

    def _on_export_session(self) -> None:
        """Export the current session to a JSON file.

        Success and failure dialogs are only shown after the async export coroutine completes so the user is not told the file was saved
        before it has actually been written.
        """
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
        if not path:
            return

        session_mgr = getattr(self._orchestrator, "_sessions", None)
        if session_mgr is None:
            QMessageBox.warning(self, "Export", "Session manager unavailable.")
            return

        export_current = getattr(session_mgr, "export_current", None)
        if callable(export_current):
            coro = export_current(Path(path))
        elif hasattr(session_mgr, "export_json"):
            coro = session_mgr.export_json(session.id, Path(path))
        else:
            QMessageBox.warning(self, "Export", "Session manager unavailable.")
            return

        def _on_export_done(_result: object) -> None:
            self.status_update.emit("Session exported")
            QMessageBox.information(self, "Export", f"Session exported to {path}")

        def _on_export_failed(err: Exception) -> None:
            _logger.warning("session_export_failed", path=path, error=str(err))
            self.status_update.emit("Session export failed")
            QMessageBox.warning(self, "Export", f"Failed to export session: {err}")

        worker = AsyncWorker(cast("Coroutine[object, object, object]", coro), self)
        worker.finished.connect(_on_export_done)
        worker.error.connect(_on_export_failed)
        self._current_worker = worker
        _logger.info("session_export_started", session_id=session.id, path=path)
        self.status_update.emit("Exporting session...")
        worker.start()

    def _on_import_session(self) -> None:
        """Import a session from a JSON file.

        The import coroutine runs on an ``AsyncWorker`` so the success dialog only appears after the import actually completes. Duplicate-
        session errors surface a replace-and-retry prompt and malformed JSON files surface a friendly parse-error dialog.
        """
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Session",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not path:
            return

        session_mgr = getattr(self._orchestrator, "_sessions", None)
        if session_mgr is None:
            QMessageBox.warning(self, "Import", "Session manager unavailable.")
            return

        import_json_attr = getattr(session_mgr, "import_json", None)
        if not callable(import_json_attr):
            QMessageBox.warning(self, "Import", "Session manager does not support import.")
            return

        _logger.info("session_import_started", path=path)
        self._start_session_import(
            cast("Callable[..., Coroutine[object, object, object]]", import_json_attr),
            Path(path),
            replace=False,
        )

    def _start_session_import(
        self,
        import_json: Callable[..., Coroutine[object, object, object]],
        source_path: Path,
        *,
        replace: bool,
    ) -> None:
        """Schedule ``SessionManager.import_json`` on an async worker.

        Args:
            import_json: Bound ``import_json`` coroutine function from the
                session manager.
            source_path: Path to the session JSON file.
            replace: Whether to overwrite an existing session with the same id.
        """
        coro = import_json(source_path, replace=replace)

        def _on_import_done(_result: object) -> None:
            self.status_update.emit("Session imported")
            QMessageBox.information(self, "Import", "Session imported successfully.")

        def _on_import_failed(err: Exception) -> None:
            self._handle_session_import_error(err, import_json, source_path)

        worker = AsyncWorker(coro, self)
        worker.finished.connect(_on_import_done)
        worker.error.connect(_on_import_failed)
        self._current_worker = worker
        self.status_update.emit("Importing session...")
        worker.start()

    def _handle_session_import_error(
        self,
        err: Exception,
        import_json: Callable[..., Coroutine[object, object, object]],
        source_path: Path,
    ) -> None:
        """Classify an import failure and surface an appropriate dialog.

        Args:
            err: Exception raised by the async import worker.
            import_json: Bound ``import_json`` coroutine function, reused if the
                user chooses to replace an existing session.
            source_path: Path of the file that failed to import.
        """
        _logger.warning("session_import_failed", path=str(source_path), error=str(err), error_type=type(err).__name__)
        self.status_update.emit("Session import failed")

        if isinstance(err, json.JSONDecodeError):
            QMessageBox.warning(
                self,
                "Import",
                f"Invalid session file: could not parse JSON.\n\n{err}",
            )
            return

        if isinstance(err, ValueError):
            message = str(err)
            if "already exists" in message.lower():
                reply = QMessageBox.question(
                    self,
                    "Import",
                    "A session with the same identifier already exists.\n\nReplace the existing session?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self._start_session_import(import_json, source_path, replace=True)
                return
            QMessageBox.warning(self, "Import", f"Failed to import session: {message}")
            return

        QMessageBox.warning(self, "Import", f"Failed to import session: {err}")

    def _on_save_patched_binary(self) -> None:
        """Save the currently loaded binary with applied patches via the hex editor.

        The hex editor lives in :attr:`ToolOutputPanel.embedded_tools` (registered by :meth:`ToolOutputPanel.add_hex_editor_tab`), not
        :attr:`panels`, so this method resolves it through :meth:`ToolOutputPanel.get_embedded_tool`.
        """
        _logger.info(
            "save_patched_binary_requested",
            binary=str(self.current_binary) if self.current_binary is not None else None,
        )
        hex_panel = self.tool_panel.get_embedded_tool("hex_editor")
        if hex_panel is None:
            _logger.info("save_patched_binary_no_hex_editor")
            QMessageBox.information(self, "Save", "No hex editor loaded.")
            return

        save_as_fn = getattr(hex_panel, "save_as", None)
        if callable(save_as_fn):
            _logger.info("save_patched_binary_dispatched", method="save_as")
            save_as_fn()
            return

        save_fn = getattr(hex_panel, "save", None)
        if callable(save_fn):
            _logger.info("save_patched_binary_dispatched", method="save")
            save_fn()
            return

        _logger.info("save_patched_binary_unsupported")
        QMessageBox.information(self, "Save", "Hex editor does not support saving.")

    def _on_export_analysis(self) -> None:
        """Export the current bridge analysis to a JSON file."""
        analysis_panel = self.tool_panel.get_panel("analysis")
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
            _logger.info("analysis_export_started", path=path)
            analysis_dict: object
            to_dict_fn = getattr(analysis, "to_dict", None)
            if callable(to_dict_fn):
                analysis_dict = to_dict_fn()
            elif hasattr(analysis, "__dict__"):
                analysis_dict = vars(analysis)
            else:
                analysis_dict = str(analysis)

            with Path(path).open("w", encoding="utf-8") as f:
                json.dump(analysis_dict, f, indent=2, default=str)

            _logger.info("analysis_export_completed", path=path)
            QMessageBox.information(self, "Export", f"Analysis exported to {path}")

    def _on_tool_status(self) -> None:
        """Handle tool status action.

        Constructs :class:`ToolStatusDialog` without a pre-fetched status map so the dialog spawns its own background status-check workers
        and the Qt event loop is never blocked while ``_on_tool_status`` runs.
        """
        tool_registry = self._orchestrator.tool_registry
        dialog = ToolStatusDialog(
            tool_registry=tool_registry,
            parent=self,
            tool_statuses=None,
        )
        _logger.info("tool_status_dialog_opened")
        dialog.exec()

    def _on_configure_tools(self) -> None:
        """Handle configure tools action.

        Passes the live tool registry from the orchestrator to ``ToolConfigDialog`` so per-tool widgets can query real registry state for
        status checks. Wires :attr:`ToolConfigDialog.tool_updated` and each :attr:`ToolSettingsWidget.status_changed` signal to MainWindow
        handlers so config saves and per-tool status changes update the application state and status bar in real time.
        """
        tool_registry = self._orchestrator.tool_registry
        dialog = ToolConfigDialog(
            tool_registry=tool_registry,
            tools_directory=self._config.tools_directory,
            parent=self,
        )
        dialog.tool_updated.connect(self._on_tool_config_updated)
        widgets_attr = getattr(dialog, "_tool_widgets", None)
        if isinstance(widgets_attr, dict):

            def _status_slot(tool_id: str, available: int) -> None:
                self._on_tool_status_changed(tool_id=tool_id, available=bool(available))

            for widget in cast("dict[str, object]", widgets_attr).values():
                status_changed = getattr(widget, "status_changed", None)
                if status_changed is not None:
                    status_changed.connect(_status_slot)
        if dialog.exec():
            settings: dict[str, dict[str, object]] = dialog.get_settings()
            self._apply_tool_settings(settings)

    def _on_tool_config_updated(self, tool_id: str) -> None:
        """Handle a per-tool config save broadcast from ``ToolConfigDialog``.

        Args:
            tool_id: Identifier of the tool whose configuration was just saved.
        """
        _logger.info("tool_config_updated", tool_id=tool_id)
        self.status_update.emit(f"Tool configuration updated: {tool_id}")

    def _on_tool_status_changed(self, *, tool_id: str, available: bool) -> None:
        """Handle per-widget tool status checks emitted from ``ToolSettingsWidget``.

        Args:
            tool_id: Identifier of the tool whose status was checked.
            available: Whether the tool is currently available.
        """
        state = "available" if available else "unavailable"
        _logger.info("tool_status_changed", tool_id=tool_id, available=available)
        self.status_update.emit(f"Tool status: {tool_id} {state}")

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
                    except (RuntimeError, OSError, ValueError) as e:
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
        """Handle configure providers action.

        Wires :attr:`ProviderConfigDialog.provider_updated` (fired per-provider on
        Save/Apply) and :attr:`ProviderConfigDialog.active_provider_changed` (fired
        when the user clicks "Set Active" inside the dialog) to MainWindow handlers
        so credential edits and active-provider switches surface in the toolbar
        combo and status bar without waiting for dialog acceptance.
        """
        registry = self._orchestrator.provider_registry
        discovery = ModelDiscovery(registry)
        dialog = ProviderConfigDialog(
            provider_registry=registry,
            model_discovery=discovery,
            parent=self,
        )
        dialog.provider_updated.connect(self._on_provider_dialog_updated)
        dialog.active_provider_changed.connect(self._on_active_provider_changed)
        if dialog.exec():
            settings: dict[str, dict[str, object]] = dialog.get_settings()
            self._apply_provider_settings(settings)

    def _on_provider_dialog_updated(self, provider_id: str) -> None:
        """Handle per-provider save broadcast from ``ProviderConfigDialog``.

        Args:
            provider_id: Identifier of the provider whose settings were saved.
        """
        _logger.info("provider_dialog_updated", provider_id=provider_id)
        self.status_update.emit(f"Provider configuration updated: {provider_id}")

    def _on_active_provider_changed(self, provider_id: str) -> None:
        """Handle active-provider switch broadcast from ``ProviderConfigDialog``.

        Synchronizes the toolbar provider combo with the dialog's selection so
        future requests issued through the toolbar match the provider the user
        just activated.

        Args:
            provider_id: Identifier of the provider that was made active.
        """
        try:
            new_active = ProviderName(provider_id)
        except ValueError:
            _logger.warning("active_provider_changed_unknown_id", provider_id=provider_id)
            return

        for index in range(self._provider_combo.count()):
            data = self._provider_combo.itemData(index)
            if isinstance(data, ProviderName) and data == new_active:
                with QSignalBlocker(self._provider_combo):
                    self._provider_combo.setCurrentIndex(index)
                break

        _logger.info("toolbar_provider_synced", provider_id=provider_id)
        self.status_update.emit(f"Active provider: {provider_id}")

    def _apply_provider_settings(self, settings: dict[str, dict[str, object]]) -> None:
        """Apply provider configuration settings at runtime.

        The ProviderConfigDialog handles persistence via its own JSON config file.
        This method reconnects providers with updated API keys and credentials
        and explicitly disconnects providers the user has disabled or cleared
        credentials for, so changes take effect without an application restart.

        Args:
            settings: Provider settings dictionary mapping provider IDs to their settings.
        """
        registry = self._orchestrator.provider_registry
        providers_to_connect: list[tuple[ProviderName, ProviderCredentials]] = []
        providers_to_disconnect: list[ProviderName] = []

        for provider_id, provider_settings in settings.items():
            enabled = bool(provider_settings.get("enabled", False))
            api_key = str(provider_settings.get("api_key", ""))
            api_base = str(provider_settings.get("api_base", "")) or None
            org_id = str(provider_settings.get("organization_id", "")) or None

            try:
                pname = ProviderName(provider_id)
            except ValueError:
                _logger.warning("unknown_provider_id", provider_id=provider_id)
                continue

            existing_provider = registry.get(pname)

            if not enabled or not api_key:
                if existing_provider is not None and existing_provider.is_connected:
                    providers_to_disconnect.append(pname)
                continue

            if existing_provider is None:
                continue

            creds = ProviderCredentials(api_key=api_key, api_base=api_base, organization_id=org_id)
            providers_to_connect.append((pname, creds))

        if providers_to_connect or providers_to_disconnect:

            async def _apply_provider_changes() -> None:
                for pname in providers_to_disconnect:
                    try:
                        await registry.disconnect_provider(pname)
                        _logger.info("provider_disconnected", provider=pname.value)
                    except (RuntimeError, OSError, ValueError) as e:
                        _logger.warning(
                            "provider_disconnect_failed",
                            provider=pname.value,
                            error=str(e),
                        )
                for pname, creds in providers_to_connect:
                    try:
                        await registry.connect_provider(pname, creds)
                        _logger.info("provider_reconnected", provider=pname.value)
                    except (RuntimeError, OSError, ValueError) as e:
                        _logger.warning(
                            "provider_reconnect_failed",
                            provider=pname.value,
                            error=str(e),
                        )

            worker = AsyncWorker(_apply_provider_changes(), self)
            worker.finished.connect(self._on_provider_reconnect_finished)
            worker.error.connect(self._on_provider_reconnect_error)
            worker.start()

        count = len(settings)
        self.status_update.emit(
            f"Provider settings applied ({count} providers configured, {len(providers_to_disconnect)} disabled)",
        )

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
                with config_path.open(encoding="utf-8") as f:
                    loaded_json: dict[str, dict[str, str]] = json.load(f)
                    provider_section = loaded_json.get(provider_id, {})
                    if config_key := provider_section.get("api_key", ""):
                        api_key = config_key
            except (json.JSONDecodeError, OSError):
                _logger.debug("config_file_load_failed", exc_info=True)
        _logger.info(
            "models_refresh_requested",
            provider=provider_id,
            has_credentials=bool(api_key),
        )
        self.status_update.emit("Refreshing models...")
        self.model_combo.clear()
        self.model_combo.setEnabled(False)

        if self.model_discovery is not None:
            try:
                run_bridge_coroutine(self.model_discovery.discover_all())
            except (RuntimeError, OSError):
                _logger.debug("model_discovery_refresh_failed", exc_info=True)

        self.model_refresh_worker = ModelRefreshWorker(provider_id, api_key, parent=self)

        def _refresh_slot(s: int, m: list[str], msg: str) -> None:
            self._on_models_refresh_finished(success=bool(s), models=m, message=msg)

        self.model_refresh_worker.refresh_finished.connect(_refresh_slot)
        self.model_refresh_worker.start()

    def _on_models_refresh_finished(self, *, success: bool, models: list[str], message: str) -> None:
        """Handle models refresh completion.

        Args:
            success: Whether the refresh was successful.
            models: List of available model names.
            message: Status message.
        """
        self.model_combo.setEnabled(True)
        if success and models:
            previous_model = self.model_combo.currentText().strip()
            with QSignalBlocker(self.model_combo):
                self.model_combo.clear()
                self.model_combo.addItems(models)
                if previous_model:
                    idx = self.model_combo.findText(previous_model)
                    if idx >= 0:
                        self.model_combo.setCurrentIndex(idx)
                    else:
                        self.model_combo.setCurrentText(previous_model)
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
        self.model_browse_worker = worker
        _logger.info("provider_list_models_requested", provider=active_provider.name.value)
        worker.start()
        self.status_update.emit("Fetching models...")

    def _on_browse_models_result(self, result: object) -> None:
        """Handle browse models async result.

        Constructs ``ModelSelectionDialog`` with the active provider's name, the
        currently selected toolbar model (so the dialog highlights it), and the
        shared :class:`ModelDiscovery` so the dialog can render
        provider-aware status. Also wires :attr:`ModelSelectionDialog.model_selected`
        so a model selection (Ok or double-click) updates the toolbar combo
        immediately.

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

        active_provider = self._orchestrator.provider_registry.active
        provider_name = active_provider.name if active_provider is not None else None

        current_model_text = self.model_combo.currentText() or None

        dialog = ModelSelectionDialog(
            models=model_infos,
            current_model=current_model_text,
            provider_name=provider_name,
            discovery=self.model_discovery,
            parent=self,
        )
        dialog.model_selected.connect(self._on_model_selected_from_browse)
        if dialog.exec() and (selected := dialog.get_selected_model()):
            self._sync_model_combo(selected)

    def _on_model_selected_from_browse(self, model_id: str) -> None:
        """Handle the live ``model_selected`` signal emitted on dialog accept.

        Args:
            model_id: Identifier of the model the user selected.
        """
        _logger.info("model_selected_from_browse", model_id=model_id)
        self._sync_model_combo(model_id)

    def _sync_model_combo(self, model_id: str) -> None:
        """Select ``model_id`` in the toolbar model combo, adding it if missing.

        Args:
            model_id: Identifier of the model to make current in the combo.
        """
        idx = self.model_combo.findText(model_id)
        if idx < 0:
            self.model_combo.addItem(model_id)
            idx = self.model_combo.findText(model_id)
        if idx >= 0:
            self.model_combo.setCurrentIndex(idx)
        self.status_update.emit(f"Model selected: {model_id}")

    def _on_model_combo_text_committed(self) -> None:
        """Warn when a manually typed model id is not in the provider catalog.

        The slot fires when the user finishes editing the model combo's line edit. If the entered text does not match any known model id in
        the combo it is forwarded to the user via the status bar and a structured log entry so a custom request is still attempted but the
        user is told it may not be valid.
        """
        line_edit = self.model_combo.lineEdit()
        if line_edit is None:
            return
        text = line_edit.text().strip()
        if not text:
            return
        if self.model_combo.findText(text) == -1:
            _logger.warning("model_combo_text_not_in_catalog", model_id=text)
            self.status_update.emit(
                f"Custom model id '{text}' not present in provider catalog - request may fail",
            )

    def _kickoff_initial_discovery(self) -> None:
        """Trigger a one-shot non-blocking model discovery pass after startup.

        Guards against duplicate invocations via ``_initial_discovery_triggered`` so repeated re-entries (e.g. provider config changes that
        re-enter :meth:`_sync_model_combo` paths) do not re-fire the initial discovery. Skipped entirely when no :class:`ModelDiscovery`
        instance has been wired into the window yet.
        """
        if self._initial_discovery_triggered:
            return
        if self.model_discovery is None:
            _logger.debug("initial_discovery_skipped_no_discovery")
            return
        self._initial_discovery_triggered = True

        _logger.info("initial_model_discovery_kickoff")
        run_bridge_coroutine_async(
            self.model_discovery.discover_all(),
            self._on_initial_discovery_done,
            self._on_initial_discovery_error,
            self,
        )

    def _on_initial_discovery_done(self, result: object) -> None:
        """Handle initial discovery completion.

        Args:
            result: Mapping of provider names to lists of ``ModelInfo``.
        """
        if isinstance(result, dict):
            result_dict = cast("dict[object, object]", result)
            counts: dict[str, int] = {}
            for provider_name_obj, models_obj in result_dict.items():
                key = provider_name_obj.value if isinstance(provider_name_obj, ProviderName) else str(provider_name_obj)
                counts[key] = len(cast("list[object]", models_obj)) if isinstance(models_obj, list) else 0
            _logger.info("initial_model_discovery_completed", per_provider_counts=counts)
        else:
            _logger.info("initial_model_discovery_completed", provider_count=0)
        self._refresh_model_discovery_status()

    def _on_initial_discovery_error(self, error: object) -> None:
        """Handle initial discovery failure.

        Args:
            error: Exception raised during discovery.
        """
        _logger.warning("initial_model_discovery_failed", error=str(error))
        self._refresh_model_discovery_status()

    def _on_configure_sandbox(self) -> None:
        """Handle configure sandbox action.

        Wires :attr:`SandboxConfigDialog.settings_updated` to :meth:`_on_sandbox_settings_updated` so an Apply press inside the dialog
        (which fires the signal without dialog acceptance) propagates settings to the runtime sandbox manager just like an OK acceptance
        does.
        """
        _logger.info("sandbox_config_dialog_opened")
        dialog = SandboxConfigDialog(
            sandbox_manager=self.sandbox_manager,
            parent=self,
        )
        dialog.settings_updated.connect(self._on_sandbox_settings_updated)
        if dialog.exec():
            settings: dict[str, object] = dialog.get_settings()
            self._apply_sandbox_settings(settings)

    def _on_sandbox_settings_updated(self) -> None:
        """Apply runtime sandbox settings when the dialog signals an Apply event.

        ``SandboxConfigDialog.settings_updated`` carries no payload (the dialog already persisted to disk and rebuilt its own
        ``SandboxConfig``); this slot pulls the dialog's current settings via ``sender()`` and routes them through
        :meth:`_apply_sandbox_settings`.
        """
        sender = self.sender()
        if sender is None:
            _logger.debug("sandbox_settings_updated_without_sender")
            return
        get_settings = getattr(sender, "get_settings", None)
        if not callable(get_settings):
            _logger.debug("sandbox_settings_updated_sender_missing_get_settings")
            return
        settings_obj = get_settings()
        if not isinstance(settings_obj, dict):
            _logger.debug("sandbox_settings_updated_invalid_payload")
            return
        self._apply_sandbox_settings(cast("dict[str, object]", settings_obj))

    def _apply_sandbox_settings(self, settings: dict[str, object]) -> None:
        """Apply sandbox configuration settings to the runtime manager.

        Tears down every active sandbox instance whose configuration no longer
        matches the dialog-selected isolation parameters and rebuilds the
        ``SandboxManager`` so subsequent sandboxes honour the new defaults.
        This is the documented fallback pattern used while
        ``SandboxManager.update_default_config`` is pending on the sandbox
        back end (Group D scope).

        Args:
            settings: Sandbox settings dictionary produced by
                :class:`~intellicrack.ui.sandbox_config.SandboxConfigDialog`.
        """
        new_config = self._build_sandbox_config(settings)

        try:
            instances = list(self.sandbox_manager.instances)
        except (RuntimeError, AttributeError):
            _logger.debug("sandbox_instances_listing_failed", exc_info=True)
            instances = []

        stale_count = 0
        for inst in instances:
            existing_cfg = getattr(inst.sandbox, "_config", None)
            if not isinstance(existing_cfg, SandboxConfig) or not self._sandbox_configs_match(existing_cfg, new_config):
                stale_count += 1

        try:
            run_bridge_coroutine(self.sandbox_manager.destroy_all())
        except (RuntimeError, OSError) as e:
            _logger.warning("sandbox_manager_teardown_failed", error=str(e))

        self.sandbox_manager = SandboxManager(default_config=new_config)
        _logger.info(
            "sandbox_manager_rebuilt",
            timeout_seconds=new_config.timeout_seconds,
            memory_limit_mb=new_config.memory_limit_mb,
            network_enabled=new_config.network_enabled,
            stale_instances=stale_count,
            total_instances=len(instances),
        )
        if instances:
            self.status_update.emit(
                f"Sandbox settings applied ({stale_count} of {len(instances)} instance(s) had stale config)",
            )
        else:
            self.status_update.emit("Sandbox settings applied")

    @staticmethod
    def _build_sandbox_config(settings: dict[str, object]) -> SandboxConfig:
        """Translate a dialog settings dict into a :class:`SandboxConfig`.

        Args:
            settings: Raw settings dictionary from the sandbox config dialog.

        Returns:
            SandboxConfig: Config built from the provided settings, falling back
            to dataclass defaults for any missing or wrongly typed fields.
        """
        defaults = SandboxConfig()
        timeout_seconds = MainWindow._coerce_int(settings.get("timeout_seconds"), defaults.timeout_seconds)
        memory_limit_mb = MainWindow._coerce_int(settings.get("memory_limit_mb"), defaults.memory_limit_mb)
        network_enabled = bool(settings.get("network_enabled", defaults.network_enabled))

        shared_folder_raw = settings.get("shared_folder", "")
        read_only_raw = settings.get("shared_folder_read_only", False)
        shared_folders: list[tuple[Path, str, bool]] = []
        if isinstance(shared_folder_raw, str) and shared_folder_raw:
            shared_folders.append((Path(shared_folder_raw), "C:\\Shared", bool(read_only_raw)))

        return SandboxConfig(
            timeout_seconds=timeout_seconds,
            memory_limit_mb=memory_limit_mb,
            network_enabled=network_enabled,
            shared_folders=shared_folders,
        )

    @staticmethod
    def _coerce_int(value: object, default: int) -> int:
        """Coerce a setting value to int, returning the default on failure.

        Args:
            value: Raw value from a settings dictionary.
            default: Fallback integer when ``value`` is not coercible.

        Returns:
            int: Parsed integer or ``default`` when coercion is not possible.
        """
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip())
            except ValueError:
                _logger.warning("setting_int_coerce_failed", raw_value=value, default=default)
                return default
        return default

    @staticmethod
    def _sandbox_configs_match(existing: SandboxConfig, incoming: SandboxConfig) -> bool:
        """Return True if the two configs describe equivalent isolation.

        Args:
            existing: Currently installed sandbox config.
            incoming: Newly requested sandbox config.

        Returns:
            bool: True when all fields controlled by the dialog agree, False
            otherwise.
        """
        return (
            existing.timeout_seconds == incoming.timeout_seconds
            and existing.memory_limit_mb == incoming.memory_limit_mb
            and existing.network_enabled == incoming.network_enabled
            and list(existing.shared_folders) == list(incoming.shared_folders)
        )

    def _get_or_create_sandbox_bridge(self) -> SandboxBridge:
        """Get an existing SandboxBridge from the tool registry or create a new one.

        Returns:
            SandboxBridge: An initialized SandboxBridge instance.
        """
        try:
            return self._orchestrator.tool_registry.get_sandbox_bridge()
        except ToolError:
            _logger.debug("sandbox_bridge_registry_lookup_failed", exc_info=True)

        bridge = SandboxBridge()
        try:
            run_bridge_coroutine(bridge.initialize())
        except (RuntimeError, OSError):
            _logger.debug("sandbox_bridge_initialize_failed", exc_info=True)
        return bridge

    def _on_open_sandbox(self) -> None:
        """Handle open sandbox action.

        Routes the availability check through ``SandboxBridge.is_available`` (the same API the dialog ultimately depends on for
        ``create()``) instead of constructing a throwaway ``SandboxConfigDialog`` purely to call its instance ``is_sandbox_available()``.
        The bridge is reused for the subsequent ``create()`` call so the availability probe and the create path target the same backend
        instance.
        """
        _logger.info("sandbox_open_requested")
        bridge = self._get_or_create_sandbox_bridge()

        async def open_sandbox() -> object:
            available = await bridge.is_available()
            return await bridge.create() if available else None

        def on_sandbox_opened(result: object) -> None:
            if result is None:
                _logger.info("sandbox_open_unavailable")
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
                self.tool_panel.wire_sandbox_bridge(bridge)
                instance_id = cast("dict[str, object]", result).get("instance_id") if isinstance(result, dict) else None
                if isinstance(instance_id, str):
                    _logger.info("sandbox_opened_via_bridge", instance_id=instance_id)
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
        """Handle preferences action.

        Wires :attr:`PreferencesDialog.settings_changed` to :meth:`_on_preferences_changed` so that pressing Apply (which fires the signal
        without closing the dialog) immediately propagates the new config to MainWindow, instead of only being captured on the OK acceptance
        path.
        """
        _logger.info("preferences_dialog_opened")
        preferences_module = importlib.import_module(".preferences", "intellicrack.ui")
        dialog = preferences_module.PreferencesDialog(self._config, self)
        config_path = get_config_file("config.json")
        set_config_path = getattr(dialog, "set_config_path", None)
        if callable(set_config_path):
            set_config_path(config_path)
        dialog.settings_changed.connect(self._on_preferences_changed)
        if dialog.exec():
            self._config = dialog.get_config()
            self.status_update.emit("Preferences saved")

    def _on_preferences_changed(self, new_config: Config) -> None:
        """Handle preferences applied without dialog acceptance.

        Re-applies the selected UI theme so changing it in the Preferences
        dialog takes effect immediately, then refreshes model state.

        Args:
            new_config: The freshly built :class:`Config` emitted by the dialog
                when the user pressed Apply.
        """
        theme_changed = new_config.ui.theme != self._config.ui.theme
        self._config = new_config
        if theme_changed:
            _logger.info("preferences_theme_changed", theme=new_config.ui.theme)
            self._theme_manager.apply_theme(new_config.ui.theme)
        self._initialize_model_cache()
        _logger.info("preferences_applied")
        self.status_update.emit("Preferences applied")

    def _on_toggle_theme(self) -> None:
        """Toggle the live theme between dark and light."""
        theme_name = self._theme_manager.toggle_theme()
        _logger.info("theme_toggled", theme=theme_name)
        self.status_update.emit(f"Theme switched to {theme_name}")

    def _on_theme_changed(self, resolved_theme: str) -> None:
        """Refresh theme-dependent widgets when the active theme changes.

        Connected to :attr:`ThemeManager.theme_changed`, this runs for explicit
        theme selections, the Toggle Theme action, and live OS color-scheme
        changes while the ``"system"`` theme is active. The application
        stylesheet is re-applied by the theme manager itself; this handler
        refreshes elements that are not styled purely through that stylesheet:
        cached icon colors and the code-output syntax highlighter.

        Args:
            resolved_theme: The concrete theme now active ("dark" or "light").
        """
        self._icon_manager.clear_cache()

        tool_panel = getattr(self, "tool_panel", None)
        if tool_panel is not None:
            code_highlighter = tool_panel.get_code_highlighter()
            if code_highlighter is not None:
                code_highlighter.rehighlight()

        _logger.debug("theme_refreshed", resolved=resolved_theme)

    def _on_focus_chat_input(self) -> None:
        """Focus the chat input field."""
        self._chat_panel.set_focus_input()

    def _on_xpu_status(self) -> None:
        """Open the XPU status dialog showing device, memory, and cache state."""
        _logger.debug("xpu_status_dialog_opened")
        dialog = XPUStatusDialog(self)
        dialog.exec()

    @property
    def log_viewer_window(self) -> LogViewerWindow | None:
        """Return the live Log Viewer instance, if one has been opened.

        Returns:
            LogViewerWindow | None: The cached viewer instance, or
                ``None`` when it has not been constructed yet (or was
                disposed after the main window closed).
        """
        return self._log_viewer_window

    def open_log_viewer(self) -> LogViewerWindow:
        """Open (or raise) the modeless Log Viewer window.

        The viewer is constructed lazily on first call and reused on
        subsequent calls so window state, filters, and history are
        preserved across re-opens.

        Returns:
            LogViewerWindow: The active viewer instance.
        """
        if self._log_viewer_window is None:
            self._log_viewer_window = LogViewerWindow(self._config, parent=self)
        viewer = self._log_viewer_window
        viewer.show()
        viewer.raise_()
        viewer.activateWindow()
        viewer.setWindowState(viewer.windowState() & ~Qt.WindowState.WindowMinimized)
        _logger.info("log_viewer_opened")
        return viewer

    def _on_log_viewer(self) -> None:
        """Slot for the ``Help -> Log Viewer...`` menu action."""
        self.open_log_viewer()

    def _on_about(self) -> None:
        """Handle about action."""
        font_info = self._font_manager.get_font_info()
        code_font = font_info.get("code_font", "unknown")
        ui_font = font_info.get("ui_font", "unknown")
        custom_loaded = font_info.get("custom_fonts_available", False)

        status_icon = self._icon_manager.get_status_icon(success=True)
        has_icon = not status_icon.isNull()

        _logger.debug(
            "about_dialog_opened",
            code_font=str(code_font),
            ui_font=str(ui_font),
            custom_fonts=bool(custom_loaded),
            has_icon=has_icon,
        )

        about_text = (
            "Intellicrack\n\n"
            "Unified workspace that bridges binary-analysis tools and AI providers.\n\n"
            f"Version {__version__}\n"
            f"License: {__license__}\n"
            f"{__copyright__}\n\n"
            f"Code Font: {code_font}\n"
            f"UI Font: {ui_font}\n"
            f"Custom Fonts: {'Yes' if custom_loaded else 'No'}\n"
            f"Icons Loaded: {'Yes' if has_icon else 'No'}"
        )
        QMessageBox.about(self, "About Intellicrack", about_text)

    def on_open_x64dbg(self) -> None:
        """Open x64dbg debugger panel."""
        self._on_open_x64dbg()

    def _open_x64dbg_impl(self) -> None:
        """Initialize the x64dbg panel and start the tool."""
        run_bridge_coroutine_logged(
            self._orchestrator.tool_registry.ensure_tool_ready(ToolName.X64DBG),
            None,
            None,
            self,
            event="ensure_tool_ready",
            logger=_logger,
            tool=ToolName.X64DBG.value,
        )

        widget = self.tool_panel.add_x64dbg_tab(is_64bit=True)
        if widget is None:
            self._show_tool_error("x64dbg", "Failed to initialize x64dbg panel")
            return
        widget.start_tool()

    def _on_open_x64dbg(self) -> None:
        """Open x64dbg debugger panel."""
        try:
            self._open_x64dbg_impl()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="x64dbg")
            self._show_tool_error("x64dbg", f"Failed to open x64dbg panel: {e}")

    def on_open_cutter(self) -> None:
        """Open Cutter reverse engineering panel."""
        self._on_open_cutter()

    def _on_open_cutter(self) -> None:
        """Open Cutter reverse engineering panel."""
        try:
            widget = self.tool_panel.add_cutter_tab()
            if widget is None:
                self._show_tool_error("Cutter", "Failed to initialize Cutter panel")
                return
            widget.start_tool()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="Cutter")
            self._show_tool_error("Cutter", f"Failed to open Cutter panel: {e}")

    def on_open_hxd(self) -> None:
        """Open the HxD hex editor panel (public wrapper for external callers)."""
        self._on_open_hxd()

    def _open_hxd_impl(self) -> None:
        """Activate the HxD hex editor panel, registering it late when needed."""
        if self._hxd_panel is None:
            self._register_hxd_panel_if_available()

        widget: HxDPanel | None = self._hxd_panel
        if widget is None:
            self._show_tool_error(
                "HxD",
                "HxD executable not found. Install HxD and restart Intellicrack to use this tab.",
            )
            return

        tab_idx = self.tool_panel.tab_widget.indexOf(widget)
        if tab_idx >= 0:
            self.tool_panel.tab_widget.setCurrentIndex(tab_idx)
        widget.start_tool()

    def _on_open_hxd(self) -> None:
        """Open the HxD hex editor panel.

        Prefers the pre-registered ``HxDPanel`` instance attached to the tool panel during MainWindow initialization. If HxD was installed
        after launch and no panel was pre-registered, attempts late registration via :meth:`_register_hxd_panel_if_available` before opening
        the tab.
        """
        try:
            self._open_hxd_impl()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="HxD")
            self._show_tool_error("HxD", f"Failed to open HxD panel: {e}")

    def _on_open_hex_editor(self) -> None:
        """Open hex editor panel."""
        try:
            widget = self.tool_panel.add_hex_editor_tab()
            if widget is None:
                self._show_tool_error("Hex Editor", "Failed to initialize hex editor panel")
                return
            widget.start_tool()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="HexEditor")
            self._show_tool_error("Hex Editor", f"Failed to open hex editor panel: {e}")

    def _open_ghidra_impl(self) -> None:
        """Initialize the Ghidra panel and start the tool."""
        run_bridge_coroutine_logged(
            self._orchestrator.tool_registry.ensure_tool_ready(ToolName.GHIDRA),
            None,
            None,
            self,
            event="ensure_tool_ready",
            logger=_logger,
            tool=ToolName.GHIDRA.value,
        )

        widget = self.tool_panel.add_ghidra_tab()
        if widget is None:
            self._show_tool_error("Ghidra", "Failed to initialize Ghidra panel")
            return
        widget.start_tool()

    def _on_open_ghidra(self) -> None:
        """Open Ghidra analysis panel."""
        try:
            self._open_ghidra_impl()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="Ghidra")
            self._show_tool_error("Ghidra", f"Failed to open Ghidra panel: {e}")

    def _open_frida_impl(self) -> None:
        """Initialize the Frida panel and start the tool."""
        run_bridge_coroutine_logged(
            self._orchestrator.tool_registry.ensure_tool_ready(ToolName.FRIDA),
            None,
            None,
            self,
            event="ensure_tool_ready",
            logger=_logger,
            tool=ToolName.FRIDA.value,
        )

        panel = self.tool_panel.add_frida_tab()
        if panel is None:
            self._show_tool_error("Frida", "Failed to initialize Frida panel")
            return
        panel.start_tool()

    def _on_open_frida(self) -> None:
        """Open Frida instrumentation panel."""
        try:
            self._open_frida_impl()
        except (RuntimeError, ImportError, AttributeError) as e:
            _logger.exception("tool_open_failed", tool_name="Frida")
            self._show_tool_error("Frida", f"Failed to open Frida panel: {e}")

    def _on_open_process(self) -> None:
        """Open process manager panel and wire process_attached signal."""
        panel = self.tool_panel.add_process_tab()
        if panel is None:
            self._show_tool_error("Process", "Failed to initialize Process panel")
            return
        panel.start_tool()

        signal = getattr(panel, "process_attached", None)
        panel_obj: QObject = cast("QObject", panel)
        if signal is not None and panel_obj not in self._process_attached_wired:
            signal.connect(self._on_process_attached)
            self._process_attached_wired.add(panel_obj)

    def _on_process_attached(self, pid: int) -> None:
        """Handle process attachment by showing a memory region picker.

        When the user attaches to a process via the Process panel,
        list its readable memory regions and let the user select one
        to open in the hex editor.

        Args:
            pid: Process ID that was attached.
        """
        if _hexcore is None:
            _logger.debug("hexcore_unavailable_for_process_memory", pid=pid)
            return

        try:
            regions: list[tuple[int, int, int, int]] = _hexcore.HexDocument.list_process_memory_regions(pid)
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("process_regions_list_failed", pid=pid, error=str(exc))
            QMessageBox.warning(self, "Process Memory", f"Failed to list memory regions: {exc}")
            return

        if not regions:
            QMessageBox.information(self, "Process Memory", f"No readable memory regions found for PID {pid}.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Memory Regions - PID {pid}")
        dialog.resize(640, 400)
        layout = QVBoxLayout(dialog)

        table = QTableWidget(len(regions), 4, dialog)
        table.setHorizontalHeaderLabels(["Base Address", "Size", "Protection", "State"])
        header = table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        for row, (base, sz, prot, state) in enumerate(regions):
            table.setItem(row, 0, QTableWidgetItem(f"0x{base:016X}"))
            table.setItem(row, 1, QTableWidgetItem(f"0x{sz:X} ({sz:,} bytes)"))
            table.setItem(row, 2, QTableWidgetItem(f"0x{prot:08X}"))
            table.setItem(row, 3, QTableWidgetItem(f"0x{state:08X}"))

        layout.addWidget(table)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            dialog,
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        selected = table.currentRow()
        if selected < 0 or selected >= len(regions):
            return

        base_addr, region_size, _prot, _state = regions[selected]

        hex_bridge = self._orchestrator.get_typed_bridge("hex_editor")
        if hex_bridge is None:
            _logger.debug("hex_bridge_unavailable_for_process_memory", pid=pid)
            return

        open_fn = getattr(hex_bridge, "open_process_memory", None)
        if not callable(open_fn):
            return

        coro_result: object = open_fn(pid, base_addr, region_size)
        if not asyncio.iscoroutine(coro_result):
            return

        task: asyncio.Task[dict[str, object]] = asyncio.ensure_future(coro_result)

        def _on_done(fut: asyncio.Future[dict[str, object]]) -> None:
            try:
                result = fut.result()
                _logger.info("process_memory_loaded", pid=pid, address=hex(base_addr), length=result.get("document_length"))
            except (RuntimeError, OSError) as exc:
                _logger.warning("process_memory_open_failed", pid=pid, error=str(exc))
                QMessageBox.warning(self, "Process Memory", f"Failed to open memory: {exc}")

        task.add_done_callback(_on_done)

    def _on_open_sandbox_panel(self) -> None:
        """Open sandbox manager panel."""
        panel = self.tool_panel.add_sandbox_tab()
        if panel is None:
            self._show_tool_error("Sandbox", "Failed to initialize Sandbox panel")
            return

        bridge = self._get_or_create_sandbox_bridge()
        self.tool_panel.wire_sandbox_bridge(bridge)
        panel.start_tool()

        sandbox_bridge = self.tool_panel.get_sandbox_bridge()
        if sandbox_bridge is not None:
            _logger.debug("sandbox_bridge_available", bridge_type=type(sandbox_bridge).__name__)

        sandbox_widget = self.tool_panel.get_panel("sandbox")
        if sandbox_widget is not None:
            _logger.debug("sandbox_widget_active", widget_type=type(sandbox_widget).__name__)
            self._wire_sandbox_monitor_widgets(sandbox_widget)

        _logger.info("sandbox_panel_opened", bridge_attached=bool(sandbox_bridge))

    def _wire_sandbox_monitor_widgets(self, sandbox_widget: QWidget) -> None:
        """Connect ``SandboxMonitorWidget.sandbox_stopped`` for monitors under ``sandbox_widget``.

        Args:
            sandbox_widget: Root widget hosting the sandbox panel.
        """
        monitors = sandbox_widget.findChildren(SandboxMonitorWidget)
        for monitor in monitors:
            if monitor in self._sandbox_monitor_wired_widgets:
                continue
            monitor.sandbox_stopped.connect(self._on_sandbox_monitor_stopped)
            self._sandbox_monitor_wired_widgets.add(monitor)
        _logger.debug("sandbox_monitor_signals_wired", count=len(monitors))

    def _on_sandbox_monitor_stopped(self) -> None:
        """Reflect a SandboxMonitorWidget stop event in MainWindow state."""
        _logger.info("sandbox_monitor_stopped")
        with QSignalBlocker(self._sandbox_btn):
            self._sandbox_btn.setChecked(False)
            self._sandbox_btn.setText("Sandbox: OFF")
        self.status_update.emit("Sandbox stopped")

    def _on_debug_current_binary(self) -> None:
        """Debug the currently loaded binary with x64dbg."""
        if self.current_binary is None:
            self._show_no_binary_warning("debug")
            return
        _logger.info("binary_debug_requested", binary=str(self.current_binary))
        if not self.tool_panel.open_in_x64dbg(self.current_binary):
            self._show_tool_error("x64dbg", "Failed to open binary in x64dbg")

    def _on_analyze_current_binary(self) -> None:
        """Analyze the currently loaded binary with Cutter."""
        if self.current_binary is None:
            self._show_no_binary_warning("analyze")
            return
        _logger.info("analyze_binary_requested", binary=str(self.current_binary))
        if not self.tool_panel.open_in_cutter(self.current_binary):
            self._show_tool_error("Cutter", "Failed to open binary in Cutter")

    def _on_hex_edit_current_binary(self) -> None:
        """Open the currently loaded binary in the hex editor."""
        if self.current_binary is None:
            self._show_no_binary_warning("hex edit")
            return
        _logger.info("hex_edit_binary_requested", binary=str(self.current_binary))
        if not self.tool_panel.open_in_hex_editor(self.current_binary):
            self._show_tool_error("Hex Editor", "Failed to open binary in hex editor")

    def _on_open_binary_in_ghidra(self) -> None:
        """Open the currently loaded binary in the Ghidra panel."""
        if self.current_binary is None:
            self._show_no_binary_warning("Ghidra analysis")
            return
        _logger.info("open_binary_in_ghidra_requested", binary=str(self.current_binary))
        if not self.tool_panel.open_in_ghidra(self.current_binary):
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

        Sets the registry's active provider so subsequent requests are routed to
        the user's selection. When the selected provider has no live connection
        the user is prompted with a "Configure Now / Cancel" dialog: the
        configure choice opens the provider configuration dialog and the cancel
        choice restores the previously active provider in the combo.

        Args:
            index: New selection index.
        """
        del index
        registry = self._orchestrator.provider_registry
        active_provider = getattr(registry, "active", None)
        prev_idx = self._provider_combo.findData(active_provider.name) if active_provider is not None else -1

        provider: object = self._provider_combo.currentData()
        if not isinstance(provider, ProviderName):
            _logger.debug("provider_changed_invalid_data")
            return

        instance = registry.get(provider)
        if instance is None or not instance.is_connected:
            _logger.info(
                "provider_changed_not_connected",
                provider=provider.value,
            )
            choice = self._prompt_provider_not_connected(provider.value)
            if choice == "configure":
                self._on_configure_providers()
            else:
                with QSignalBlocker(self._provider_combo):
                    if prev_idx >= 0:
                        self._provider_combo.setCurrentIndex(prev_idx)
            self.status_update.emit(
                f"Provider {provider.value} selected but not connected. Configure credentials in Providers menu.",
            )
            return

        try:
            registry.set_active(provider)
        except (ProviderError, RuntimeError, ValueError) as exc:
            _logger.warning(
                "provider_set_active_failed",
                provider=provider.value,
                error=str(exc),
            )
            self.status_update.emit(
                f"Failed to activate provider {provider.value}: {exc}",
            )
            return

        _logger.info("provider_changed", provider=provider.value)
        self.status_update.emit(f"Active provider: {provider.value}")

    def _prompt_provider_not_connected(self, provider_name: str) -> str:
        """Show the disconnected-provider dialog and return the user's choice.

        Isolated so unit tests can override this method on a holder double
        without instantiating a real :class:`QMessageBox`.

        Args:
            provider_name: Display name of the disconnected provider.

        Returns:
            str: ``"configure"`` when the user chose to open the provider
            configuration dialog; ``"cancel"`` otherwise.
        """
        message_box = QMessageBox(self)
        message_box.setIcon(QMessageBox.Icon.Warning)
        message_box.setWindowTitle("Provider Not Connected")
        message_box.setText(
            f"Provider '{provider_name}' is not connected.\n\n"
            "Configure its credentials now, or cancel and stay on the previously active provider.",
        )
        configure_button = message_box.addButton("Configure Now...", QMessageBox.ButtonRole.AcceptRole)
        message_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        message_box.setDefaultButton(configure_button)
        message_box.exec()
        if message_box.clickedButton() is configure_button:
            return "configure"
        return "cancel"

    def _on_sandbox_toggled(self, *, checked: bool) -> None:
        """Handle sandbox toggle.

        Args:
            checked: Whether sandbox is enabled.
        """
        _logger.debug("sandbox_button_toggled", checked=checked)
        self._sandbox_btn.setText(f"Sandbox: {'ON' if checked else 'OFF'}")

    def _on_auto_approve_toggled(self, *, checked: bool) -> None:
        """Handle auto-approve toggle.

        Args:
            checked: Whether auto-approve is enabled.
        """
        _logger.debug("auto_approve_button_toggled", checked=checked)
        types_module = importlib.import_module("intellicrack.core.types")

        self._auto_approve_btn.setText(f"Auto-approve: {'ON' if checked else 'OFF'}")

        if checked:
            self._orchestrator.set_confirmation_level(types_module.ConfirmationLevel.NONE)
            self.status_update.emit("Auto-approve enabled - all tool calls will be approved automatically")
        else:
            self._orchestrator.set_confirmation_level(types_module.ConfirmationLevel.DESTRUCTIVE)
            self.status_update.emit("Auto-approve disabled - destructive operations require confirmation")

        QSettings("Intellicrack", "MainWindow").setValue("auto_approve", checked)

    def _on_cancel(self) -> None:
        """Handle cancel button click."""

        async def cancel() -> None:
            await self._orchestrator.cancel()

        self._run_async(cancel())
        self.status_update.emit("Cancelling...")

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Handle window close event.

        Checks for unsaved hex editor changes, persists window state,
        then shuts down bridges, sandbox, and background workers.

        Args:
            a0: Close event.
        """
        _logger.info("main_window_closing")
        if self.tool_panel.has_unsaved_changes():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "The hex editor has unsaved changes. Save before closing?",
                QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save,
            )
            if reply == QMessageBox.StandardButton.Cancel:
                if a0 is not None:
                    a0.ignore()
                return
            if reply == QMessageBox.StandardButton.Save:
                self.tool_panel.save_hex_editor()

        self._shutting_down = True
        self._status_timer.stop()

        self._save_window_state()
        self.tool_panel.close_detached_windows()

        if self._log_viewer_window is not None:
            try:
                self._log_viewer_window.close()
            except (RuntimeError, OSError) as e:
                _logger.warning("log_viewer_close_failed", error=str(e))
            self._log_viewer_window = None

        try:
            pm = ProcessManager.get_instance()
            request_shutdown = getattr(pm, "request_shutdown", None)
            if callable(request_shutdown):
                request_shutdown()
        except (RuntimeError, AttributeError, ImportError) as e:
            _logger.warning("process_manager_shutdown_failed", error=str(e))

        self.tool_panel.close_embedded_tools()

        if self._hxd_panel is not None:
            try:
                self._hxd_panel.cleanup()
            except (RuntimeError, OSError) as e:
                _logger.warning("hxd_panel_cleanup_failed", error=str(e))
            self._hxd_panel = None

        try:
            run_bridge_coroutine(self.sandbox_manager.destroy_all())
        except (RuntimeError, OSError) as e:
            _logger.warning("sandbox_manager_destroy_all_failed", error=str(e))

        if self._current_worker and self._current_worker.isRunning():
            self._current_worker.wait()

        _logger.info("main_window_closed")
        if a0 is not None:
            a0.accept()
