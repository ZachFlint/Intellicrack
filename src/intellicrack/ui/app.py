"""Main application window for Intellicrack.

This module provides the main PyQt6 application window that combines
all UI components and connects them to the orchestrator.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

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

from ..core.logging import get_logger
from ..core.types import Message, ProviderName, ToolCall, ToolResult
from ..providers.discovery import ModelDiscovery
from ..sandbox import SandboxManager
from ._screen_compat import get_screen_geometry, move_widget
from .chat import ChatPanel
from .provider_config import ModelRefreshWorker, ProviderConfigDialog
from .resources import FontManager, IconManager, ThemeManager
from .sandbox_config import SandboxConfigDialog
from .session_manager import SessionManagerDialog
from .tool_config import ToolConfigDialog, ToolStatusDialog
from .tools import ToolOutputPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from PyQt6.QtGui import QCloseEvent

    from ..core.config import Config
    from ..core.orchestrator import Orchestrator


_logger = get_logger("ui.app")

_MAX_RESULT_DISPLAY_LEN = 500


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
        self._config = config
        self._orchestrator = orchestrator
        self._current_worker: AsyncWorker | None = None
        self._stream_append: Callable[[str], None] | None = None
        self._sandbox_manager = SandboxManager()
        self._model_refresh_worker: ModelRefreshWorker | None = None

        self._current_binary: Path | None = None

        _logger.debug("loading_icon_manager", extra={})
        self._icon_manager = IconManager.get_instance()
        _logger.debug("loading_font_manager", extra={})
        self._font_manager = FontManager.get_instance()
        _logger.debug("loading_theme_manager", extra={})
        self._theme_manager = ThemeManager.get_instance()

        _logger.debug("loading_fonts", extra={})
        self._font_manager.load_fonts()

        _logger.info("ui_init_setup_ui", extra={})
        self._setup_ui()
        _logger.info("ui_init_setup_menus", extra={})
        self._setup_menus()
        _logger.info("ui_init_setup_toolbar", extra={})
        self._setup_toolbar()
        _logger.info("ui_init_setup_statusbar", extra={})
        self._setup_statusbar()
        _logger.info("ui_init_connect_signals", extra={})
        self._connect_signals()
        _logger.info("ui_init_configure_orchestrator", extra={})
        self._configure_orchestrator()

        self.setWindowTitle("Intellicrack")
        self.setWindowIcon(self._icon_manager.get_app_icon())

        self._apply_smart_window_size()

        self.closeEvent = self.close_event_handler

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
            _logger.debug("screen_detection_failed_using_default_size")
            self.resize(max_w, max_h)

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
        file_menu.addSeparator()
        self._add_menu_action(file_menu, "Exit", self.close, "Alt+F4")

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

        self._radare2_btn = QPushButton("radare2")
        self._radare2_btn.setObjectName("tool_button")
        self._radare2_btn.setToolTip("Open radare2/iaito GUI")
        self._radare2_btn.clicked.connect(self._on_open_radare2)
        toolbar.addWidget(self._radare2_btn)

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

        self._token_label = QLabel()
        self._statusbar.addPermanentWidget(self._token_label)

    def _connect_signals(self) -> None:
        """Connect Qt signals."""
        self._chat_panel.message_submitted.connect(self._on_user_message)
        self.message_received.connect(self._chat_panel.add_message)
        self.tool_call_received.connect(self._on_tool_call)
        self.tool_result_received.connect(self._on_tool_result)
        self.stream_chunk_received.connect(self._on_stream_chunk)
        self.status_update.connect(self._update_status)
        self._tool_panel.address_clicked.connect(self._on_address_clicked)

    def _configure_orchestrator(self) -> None:
        """Configure orchestrator callbacks."""
        self._orchestrator.set_message_callback(self.message_received.emit)
        self._orchestrator.set_tool_call_callback(self.tool_call_received.emit)
        self._orchestrator.set_tool_result_callback(self.tool_result_received.emit)
        self._orchestrator.set_stream_callback(self.stream_chunk_received.emit)
        self._orchestrator.set_async_confirmation_callback(self._request_tool_confirmation)

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
            with contextlib.suppress(asyncio.InvalidStateError):
                future.set_result(dialog.approved)

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

        async def load() -> None:
            await self._orchestrator.add_binary(path)

        self.status_update.emit(f"Loading {path.name}...")
        self._run_async(load())

    def _on_new_session(self) -> None:
        """Handle new session action."""
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

    def _on_tool_status(self) -> None:
        """Handle tool status action."""
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
        """Apply tool configuration settings.

        The ToolConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Tool settings dictionary mapping tool IDs to their settings.
        """
        del settings
        self.status_update.emit("Tool settings saved")

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
        """Apply provider configuration settings.

        The ProviderConfigDialog handles persistence via its own JSON config file.
        This method is called after the dialog saves settings to update any
        runtime state if needed.

        Args:
            settings: Provider settings dictionary mapping provider IDs to their settings.
        """
        del settings
        self.status_update.emit("Provider settings saved")

    def _on_refresh_models(self) -> None:
        """Handle refresh models action."""
        provider_data: object = self._provider_combo.currentData()
        if not provider_data:
            QMessageBox.warning(self, "Warning", "Please select a provider first.")
            return

        provider_id: str = provider_data.value if isinstance(provider_data, ProviderName) else str(provider_data)

        env_vars: dict[str, str] = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GOOGLE_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
        }
        api_key = ""
        if provider_id in env_vars:
            api_key = os.environ.get(env_vars[provider_id], "")

        config_path = Path.home() / ".intellicrack" / "providers.json"
        if config_path.exists():
            try:
                with open(config_path, encoding="utf-8") as f:
                    loaded_json: dict[str, dict[str, str]] = json.load(f)
                    provider_section = loaded_json.get(provider_id, {})
                    if config_key := provider_section.get("api_key", ""):
                        api_key = config_key
            except (json.JSONDecodeError, OSError):
                pass

        self.status_update.emit("Refreshing models...")
        self._model_combo.clear()
        self._model_combo.setEnabled(False)

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
        if dialog.exec():
            self._config = dialog.get_config()
            self.status_update.emit("Preferences saved")

    def _on_about(self) -> None:
        """Handle about action."""
        QMessageBox.about(
            self,
            "About Intellicrack",
            "Intellicrack\n\nAI-powered reverse engineering platform for analyzing\nsoftware licensing protections.\n\nVersion 2.0.0",
        )

    def _on_open_x64dbg(self) -> None:
        """Open x64dbg debugger in embedded tab."""
        try:
            widget = self._tool_panel.add_x64dbg_tab(is_64bit=True)
            if widget is None:
                self._show_tool_error("x64dbg", "Failed to initialize x64dbg widget")
                return
            if not widget.start_tool():
                self._show_tool_error(
                    "x64dbg",
                    "x64dbg executable not found. Check tools/x64dbg/ directory.",
                )
        except Exception as e:
            _logger.exception("tool_embed_failed", extra={"tool_name": "x64dbg", "error": str(e)})
            self._show_tool_error("x64dbg", f"Exception embedding x64dbg: {e}")

    def _on_open_cutter(self) -> None:
        """Open Cutter analysis tool in embedded tab."""
        try:
            widget = self._tool_panel.add_cutter_tab()
            if widget is None:
                self._show_tool_error("Cutter", "Failed to initialize Cutter widget")
                return
            if not widget.start_tool():
                self._show_tool_error(
                    "Cutter",
                    "Cutter executable not found. Check tools/cutter/ directory.",
                )
        except Exception as e:
            _logger.exception("tool_embed_failed", extra={"tool_name": "Cutter", "error": str(e)})
            self._show_tool_error("Cutter", f"Exception embedding Cutter: {e}")

    def _on_open_hxd(self) -> None:
        """Open HxD hex editor in embedded tab."""
        try:
            widget = self._tool_panel.add_hxd_tab()
            if widget is None:
                self._show_tool_error("HxD", "Failed to initialize HxD widget")
                return
            if not widget.start_tool():
                self._show_tool_error(
                    "HxD",
                    "HxD executable not found. Check tools/hxd/ directory.",
                )
        except Exception as e:
            _logger.exception("tool_embed_failed", extra={"tool_name": "HxD", "error": str(e)})
            self._show_tool_error("HxD", f"Exception embedding HxD: {e}")

    def _on_open_ghidra(self) -> None:
        """Open Ghidra in embedded tab."""
        try:
            widget = self._tool_panel.add_ghidra_tab()
            if widget is None:
                self._show_tool_error("Ghidra", "Failed to initialize Ghidra widget")
                return
            if not widget.start_tool():
                self._show_tool_error(
                    "Ghidra",
                    "Ghidra executable not found. Set GHIDRA_HOME or check tools/ghidra/ directory.",
                )
        except Exception as e:
            _logger.exception("tool_embed_failed", extra={"tool_name": "Ghidra", "error": str(e)})
            self._show_tool_error("Ghidra", f"Exception embedding Ghidra: {e}")

    def _on_open_radare2(self) -> None:
        """Open radare2/iaito GUI in embedded tab."""
        try:
            widget = self._tool_panel.add_radare2_tab()
            if widget is None:
                self._show_tool_error("radare2", "Failed to initialize radare2 widget")
                return
            if not widget.start_tool():
                self._show_tool_error(
                    "radare2",
                    "iaito/Cutter executable not found. Check tools/iaito/ or tools/cutter/ directory.",
                )
        except Exception as e:
            _logger.exception("tool_embed_failed", extra={"tool_name": "radare2", "error": str(e)})
            self._show_tool_error("radare2", f"Exception embedding radare2: {e}")

    def _on_open_frida(self) -> None:
        """Open Frida instrumentation panel."""
        panel = self._tool_panel.add_frida_tab()
        if panel is None:
            self._show_tool_error("Frida", "Failed to initialize Frida panel")
            return
        panel.start_tool()

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
        panel.start_tool()

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

    def _show_tool_error(self, tool_name: str, message: str) -> None:
        """Show tool-related error dialog.

        Args:
            tool_name: Name of the tool.
            message: Error message to display.
        """
        _logger.error("tool_error", extra={"tool_name": tool_name, "error": message})
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
        _logger.info("provider_changed", extra={"provider": provider_value})

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

    def close_event_handler(self, a0: QCloseEvent | None) -> None:
        """Handle window close event.

        Args:
            a0: Close event.
        """
        self._tool_panel.close_embedded_tools()

        async def shutdown() -> None:
            await self._orchestrator.shutdown()

        if self._current_worker and self._current_worker.isRunning():
            self._current_worker.wait()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(shutdown())
        loop.close()

        if a0 is not None:
            a0.accept()
