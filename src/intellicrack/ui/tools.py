# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tool output panel widget for the Intellicrack UI.

This module provides the tool output display panel showing
decompiled code, disassembly, and analysis results from tools,
as well as native analysis panels (Ghidra, x64dbg, Cutter,
Frida, Binary) and specialized panels (Licensing, Scripts, Stack).
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, cast, runtime_checkable

from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtGui import QSyntaxHighlighter, QTextCursor
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.logging import get_logger
from .highlighter import (
    get_highlighter_for_language,
)
from .panel_dock import DetachedPanelWindow
from .resources.font_manager import FontManager


@runtime_checkable
class ToolWidget(Protocol):
    """Protocol for embedded tool widgets."""

    @property
    def tool_started(self) -> Any:
        """Get the signal emitted when the tool process starts.

        Returns:
            Any: The tool-started signal, or None if not implemented.
        """
        return None

    @property
    def tool_closed(self) -> Any:
        """Get the signal emitted when the tool process closes.

        Returns:
            Any: The tool-closed signal, or None if not implemented.
        """
        return None

    def start_tool(self) -> bool:
        """Launch the external tool process.

        Returns:
            bool: True if the tool was started successfully.
        """
        _ = self
        return False

    def stop_tool(self) -> bool:
        """Terminate the external tool process.

        Returns:
            bool: True if the tool was stopped successfully.
        """
        _ = self
        return False


@runtime_checkable
class HexEditorPanelProtocol(ToolWidget, Protocol):
    """Protocol for the built-in hex editor panel."""

    def load_file(self, file_path: Path | str) -> bool:
        """Load a file into the hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            bool: True if the file was loaded successfully.
        """
        _ = (self, file_path)
        return False

    def goto_offset(self, offset: int) -> None:
        """Navigate to a byte offset.

        Args:
            offset: Target byte offset.
        """
        _ = (self, offset)


@runtime_checkable
class X64DbgWidgetProtocol(ToolWidget, Protocol):
    """Protocol for x64dbg debugger widget integration."""

    def set_bridge(self, bridge: Any) -> None:
        """Set the X64DbgBridge instance.

        Args:
            bridge: X64DbgBridge instance for debugging.
        """
        _ = (self, bridge)

    def debug_file(self, file_path: Path) -> bool:
        """Launch a file in the debugger.

        Args:
            file_path: Path to the executable to debug.

        Returns:
            bool: True if debugging was started successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class CutterWidgetProtocol(ToolWidget, Protocol):
    """Protocol for Cutter reverse engineering widget integration."""

    def set_bridge(self, bridge: Any) -> None:
        """Set the CutterBridge instance.

        Args:
            bridge: CutterBridge instance for analysis.
        """
        _ = (self, bridge)

    def analyze_binary(self, file_path: Path) -> bool:
        """Open a binary for analysis in Cutter.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            bool: True if analysis was started successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class GhidraWidgetProtocol(ToolWidget, Protocol):
    """Protocol for Ghidra reverse engineering widget integration."""

    def set_bridge(self, bridge: Any) -> None:
        """Set the GhidraBridge instance.

        Args:
            bridge: GhidraBridge instance for analysis.
        """
        _ = (self, bridge)

    def load_binary(self, binary_path: Path) -> bool:
        """Load a binary into Ghidra for analysis.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            bool: True if the binary was loaded successfully.
        """
        _ = (self, binary_path)
        return False


@runtime_checkable
class FridaPanelProtocol(ToolWidget, Protocol):
    """Protocol for Frida instrumentation panel."""

    def set_bridge(self, bridge: Any) -> None:
        """Set the FridaBridge instance.

        Args:
            bridge: FridaBridge instance for instrumentation.
        """
        _ = (self, bridge)

    def log_message(self, message: str) -> None:
        """Append a message to the console output.

        Args:
            message: Text to display.
        """
        _ = (self, message)

    def add_hook_entry(
        self,
        address: str,
        module: str,
        function: str,
        status: str = "",
        hook_id: str = "",
    ) -> None:
        """Add a hook entry to the table.

        Args:
            address: Hook address (hex string).
            module: Module name containing the hook.
            function: Function name being hooked.
            status: Current hook status.
            hook_id: Unique hook identifier.
        """
        _ = (self, address, module, function, status, hook_id)


@runtime_checkable
class ProcessPanelProtocol(ToolWidget, Protocol):
    """Protocol for process management panel."""

    @property
    def process_attached(self) -> Any:
        """Get the signal emitted with PID when a process is attached.

        Returns:
            Any: The process-attached signal, or None if not implemented.
        """
        return None

    def get_selected_pid(self) -> int | None:
        """Get the currently selected process ID.

        Returns:
            int | None: The selected PID or None.
        """
        _ = self
        return None


@runtime_checkable
class BinaryPanelProtocol(ToolWidget, Protocol):
    """Protocol for binary hex viewer and patching panel."""

    def load_file(self, file_path: Path | str) -> bool:
        """Load a binary file for viewing and patching.

        Args:
            file_path: Path to the binary file.

        Returns:
            bool: True if the file was loaded successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class SandboxPanelProtocol(ToolWidget, Protocol):
    """Protocol for sandbox management panel."""

    def set_sandbox(self, sandbox: Any) -> None:
        """Set the sandbox backend instance.

        Args:
            sandbox: SandboxBase implementation.
        """
        _ = (self, sandbox)

    def get_sandbox(self) -> SandboxBase | None:
        """Get the current sandbox backend.

        Returns:
            SandboxBase | None: The attached sandbox or None.
        """
        _ = self
        return None

    def set_sandbox_manager(self, manager: object) -> None:
        """Set the sandbox manager for type-aware sandbox creation.

        Args:
            manager: SandboxManager instance.
        """
        _ = (self, manager)


if TYPE_CHECKING:
    from collections.abc import Callable

    from ..core.script_gen import ScriptManager, ScriptValidator
    from ..core.types import BridgeAnalysisSummary
    from ..sandbox.base import SandboxBase
    from .panels.analysis_panel import BridgeAnalysisPanel
    from .panels.script_manager import ScriptManagerPanel
    from .panels.stack_viewer import StackViewerPanel

_logger = get_logger("ui.tools")

_PANEL_MARGIN: Final[int] = 0
_INFO_MARGIN: Final[int] = 8
_INFO_MAX_HEIGHT: Final[int] = 150
_HEADER_HEIGHT: Final[int] = 32
_MAIN_HEADER_HEIGHT: Final[int] = 40
_HEADER_MARGIN_H: Final[int] = 8
_MAIN_HEADER_MARGIN_H: Final[int] = 12
_LEFT_MIN_WIDTH: Final[int] = 300
_RIGHT_MIN_WIDTH: Final[int] = 150
_DEFAULT_SPLIT_LEFT: Final[int] = 600
_DEFAULT_SPLIT_RIGHT: Final[int] = 200
_CODE_SPLIT_LEFT: Final[int] = 400
_CODE_SPLIT_RIGHT: Final[int] = 100


OutputType = Literal[
    "ghidra",
    "frida",
    "x64dbg",
    "log",
    "analysis",
    "scripts",
    "stack",
    "hex_editor",
    "cutter",
    "process",
    "binary",
    "sandbox",
]


class CodeDisplay(QPlainTextEdit):
    """Code display widget with syntax highlighting.

    Provides a read-only text area for displaying code with
    appropriate syntax highlighting based on language.

    Args:
        language: Programming language for highlighting.
        parent: Parent widget.
    """

    def __init__(
        self,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent=parent)
        self._language = language
        self._setup_ui()
        self.set_language(language)

    def _setup_ui(self) -> None:
        """Set up the code display UI."""
        self.setReadOnly(True)
        self.setFont(FontManager.get_instance().get_code_font(10))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setObjectName("code_display")

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Args:
            language: Programming language.
        """
        self._language = language
        self._highlighter = get_highlighter_for_language(language, self.document())
        # Ensure highlighter is attached to the document
        if self._highlighter:
            self._highlighter.setDocument(self.document())

    def get_highlighter(self) -> QSyntaxHighlighter | None:
        """Get the current syntax highlighter.

        Returns:
            QSyntaxHighlighter | None: The syntax highlighter or None.
        """
        return self._highlighter

    def set_content(self, content: str) -> None:
        """Set the displayed content.

        Args:
            content: Text content to display.
        """
        self.setPlainText(content)
        self.moveCursor(QTextCursor.MoveOperation.Start)

    def append_content(self, content: str) -> None:
        """Append content to the display.

        Args:
            content: Text content to append.
        """
        self.appendPlainText(content)

    def goto_line(self, line_number: int) -> None:
        """Scroll to a specific line.

        Args:
            line_number: 1-based line number.
        """
        doc = self.document()
        if doc is None:
            return
        block = doc.findBlockByLineNumber(line_number - 1)
        if block.isValid():
            cursor = QTextCursor(block)
            self.setTextCursor(cursor)
            self.centerCursor()


class ToolTab(QFrame):
    """A single tool output tab.

    Contains a code display area and optional metadata panel
    for showing tool-specific output.

    Args:
        name: Tab name.
        language: Default syntax highlighting language.
        parent: Parent widget.
    """

    def __init__(
        self,
        name: str,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._name = name
        self._language = language
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the tool tab UI."""
        self.setObjectName(f"tool_tab_{self._name.lower()}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Vertical)

        self._code_display = CodeDisplay(self._language)
        self._splitter.addWidget(self._code_display)

        self._info_panel = QFrame()
        self._info_panel.setMaximumHeight(_INFO_MAX_HEIGHT)
        self._info_panel.setObjectName("info_panel")

        info_layout = QVBoxLayout(self._info_panel)
        info_layout.setContentsMargins(_INFO_MARGIN, _INFO_MARGIN, _INFO_MARGIN, _INFO_MARGIN)
        info_layout.setSpacing(4)

        self._info_header = QLabel("Details")
        self._info_header.setFont(FontManager.get_instance().get_ui_font_bold(9))
        self._info_header.setObjectName("panel_title")
        info_layout.addWidget(self._info_header)

        self._info_content = QLabel()
        self._info_content.setFont(FontManager.get_instance().get_code_font(9))
        self._info_content.setObjectName("code_label")
        self._info_content.setWordWrap(True)
        self._info_content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info_layout.addWidget(self._info_content)
        info_layout.addStretch()

        self._splitter.addWidget(self._info_panel)
        self._splitter.setSizes([_CODE_SPLIT_LEFT, _CODE_SPLIT_RIGHT])

        layout.addWidget(self._splitter)

    def set_content(self, content: str) -> None:
        """Set the main content.

        Args:
            content: Text content to display.
        """
        self._code_display.set_content(content)

    def set_info(self, header: str, content: str) -> None:
        """Set the info panel content.

        Args:
            header: Info header text.
            content: Info content text.
        """
        self._info_header.setText(header)
        self._info_content.setText(content)

    def set_language(self, language: str) -> None:
        """Set the syntax highlighting language.

        Args:
            language: Programming language.
        """
        self._code_display.set_language(language)

    def goto_line(self, line_number: int) -> None:
        """Scroll to a specific line.

        Args:
            line_number: 1-based line number.
        """
        self._code_display.goto_line(line_number)

    def append_content(self, content: str) -> None:
        """Append content to the display.

        Args:
            content: Text content to append.
        """
        self._code_display.append_content(content)


class FunctionListPanel(QFrame):
    """Panel showing list of functions in the binary.

    Allows navigation to specific functions by clicking.

    Args:
        parent: Parent widget.

    Attributes:
        function_selected: Qt signal for function selected.
    """

    function_selected = pyqtSignal(str, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._functions: list[tuple[str, int]] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the function list UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(_HEADER_HEIGHT)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(_HEADER_MARGIN_H, 0, _HEADER_MARGIN_H, 0)

        title = QLabel("Functions")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)

        self._count_label = QLabel("(0)")
        self._count_label.setObjectName("secondary_text")
        header_layout.addWidget(self._count_label)
        header_layout.addStretch()

        layout.addWidget(header)

        self._list_widget = QListWidget()
        self._list_widget.setFont(FontManager.get_instance().get_code_font(9))
        self._list_widget.setObjectName("function_list")
        self._list_widget.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self._list_widget)

        self.setObjectName("function_list_panel")

    def _on_item_double_clicked(self, item: QListWidgetItem) -> None:
        """Handle double click on a function.

        Args:
            item: The clicked list item.
        """
        address_str = item.text().split("  ")[0]
        try:
            address = int(address_str, 16)
            name = item.text().split("  ")[1]
            self.function_selected.emit(name, address)
        except (ValueError, IndexError):
            _logger.warning("failed_to_parse_function_item", text=item.text())

    def set_functions(self, functions: list[tuple[str, int]]) -> None:
        """Set the function list.

        Args:
            functions: List of (name, address) tuples.
        """
        self._functions = functions
        self._count_label.setText(f"({len(functions)})")

        self._list_widget.clear()
        for name, address in functions:
            self._list_widget.addItem(f"0x{address:08X}  {name}")

    def get_functions(self) -> list[tuple[str, int]]:
        """Get the current list of functions.

        Returns:
            list[tuple[str, int]]: List of (name, address) tuples.
        """
        return self._functions


class XRefPanel(QFrame):
    """Panel showing cross-references to/from an address.

    Displays incoming and outgoing references for navigation.

    Args:
        parent: Parent widget.

    Attributes:
        xref_selected: Qt signal for xref selected.
    """

    xref_selected = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the xref panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(_HEADER_HEIGHT)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(_HEADER_MARGIN_H, 0, _HEADER_MARGIN_H, 0)

        title = QLabel("Cross References")
        title.setFont(FontManager.get_instance().get_ui_font_bold(9))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        layout.addWidget(header)

        self._xref_display = QTreeWidget()
        self._xref_display.setHeaderHidden(True)
        self._xref_display.setFont(FontManager.get_instance().get_code_font(9))
        self._xref_display.setObjectName("xref_display")
        self._xref_display.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self._xref_display)

        self.setObjectName("xref_panel")

    def _on_item_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Handle click on an xref.

        Args:
            item: The clicked tree item.
            column: The clicked column index.
        """
        del column
        address_str = item.text(0).strip().split("  ")[0]
        if address_str.startswith("0x"):
            try:
                address = int(address_str, 16)
                self.xref_selected.emit(address)
            except ValueError:
                _logger.debug("xref_address_parse_failed", address=address_str)

    def set_xrefs(
        self,
        incoming: list[tuple[int, str]],
        outgoing: list[tuple[int, str]],
    ) -> None:
        """Set the cross-reference data.

        Args:
            incoming: List of (address, description) for refs to this location.
            outgoing: List of (address, description) for refs from this location.
        """
        self._xref_display.clear()

        if incoming:
            incoming_root = QTreeWidgetItem(self._xref_display, ["=== References TO ==="])
            incoming_root.setExpanded(True)
            for addr, desc in incoming:
                QTreeWidgetItem(incoming_root, [f"0x{addr:08X}  {desc}"])

        if outgoing:
            outgoing_root = QTreeWidgetItem(self._xref_display, ["=== References FROM ==="])
            outgoing_root.setExpanded(True)
            for addr, desc in outgoing:
                QTreeWidgetItem(outgoing_root, [f"0x{addr:08X}  {desc}"])


class ToolOutputPanel(QFrame):
    """Main tool output panel widget.

    Contains tabbed interface for different tool outputs including
    decompiled code, disassembly, strings, cross-references, embedded
    external tools, and specialized analysis panels.

    Args:
        parent: Parent widget.

    Attributes:
        address_clicked: Signal emitted when an address is clicked.
        embedded_tool_started: Signal emitted when embedded tool starts.
        embedded_tool_closed: Signal emitted when embedded tool closes.
    """

    address_clicked: pyqtSignal = pyqtSignal(int)
    embedded_tool_started: pyqtSignal = pyqtSignal(str)
    embedded_tool_closed: pyqtSignal = pyqtSignal(str)
    hex_context_ready: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tabs: dict[str, ToolTab] = {}
        self._embedded_tools: dict[str, QWidget] = {}
        self._panels: dict[str, QWidget] = {}
        self._detached_windows: dict[str, DetachedPanelWindow] = {}
        self._setup_ui()
        self._setup_embedded_tabs()

    def _setup_ui(self) -> None:
        """Set up the tool output panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(_MAIN_HEADER_HEIGHT)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(_MAIN_HEADER_MARGIN_H, 0, _MAIN_HEADER_MARGIN_H, 0)

        title = QLabel("Analysis Output")
        title.setFont(FontManager.get_instance().get_ui_font_bold(11))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._address_label = QLabel()
        self._address_label.setFont(FontManager.get_instance().get_code_font(10))
        self._address_label.setObjectName("code_label")
        header_layout.addWidget(self._address_label)

        layout.addWidget(header)

        self._main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_panel.setMinimumWidth(_LEFT_MIN_WIDTH)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("analysis_tabs")
        self._tab_widget.setTabsClosable(True)
        tab_bar = self._tab_widget.tabBar()
        if tab_bar is not None:
            tab_bar.setMovable(True)
            tab_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            tab_bar.customContextMenuRequested.connect(self._on_tab_context_menu)
        self._tab_widget.tabCloseRequested.connect(self._on_tab_close_requested)

        left_layout.addWidget(self._tab_widget)
        self._main_splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_panel.setMinimumWidth(_RIGHT_MIN_WIDTH)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._func_list = FunctionListPanel()
        self._func_list.function_selected.connect(self._on_function_selected)
        right_layout.addWidget(self._func_list)

        self._xref_panel = XRefPanel()
        self._xref_panel.xref_selected.connect(self._on_xref_selected)
        right_layout.addWidget(self._xref_panel)

        self._main_splitter.addWidget(right_panel)
        self._main_splitter.setSizes([_DEFAULT_SPLIT_LEFT, _DEFAULT_SPLIT_RIGHT])

        layout.addWidget(self._main_splitter)

        self.setObjectName("analysis_panel")

    def _on_function_selected(self, name: str, address: int) -> None:
        """Handle function selection in the list.

        Args:
            name: Function name.
            address: Function address.
        """
        del name
        self.address_clicked.emit(address)

    def _on_xref_selected(self, address: int) -> None:
        """Handle xref selection.

        Args:
            address: Target address.
        """
        self.address_clicked.emit(address)

    def set_tab_content(self, tab_name: OutputType, content: str) -> None:
        """Set content for a specific tab.

        Args:
            tab_name: Name of the tab.
            content: Text content to display.
        """
        if tab := self._tabs.get(tab_name.lower()):
            tab.set_content(content)

    def set_tab_info(self, tab_name: OutputType, header: str, content: str) -> None:
        """Set info panel content for a specific tab.

        Args:
            tab_name: Name of the tab.
            header: Info header text.
            content: Info content text.
        """
        if tab := self._tabs.get(tab_name.lower()):
            tab.set_info(header, content)

    def append_tab_content(self, tab_name: OutputType, content: str) -> None:
        """Append content to a specific tab.

        Args:
            tab_name: Name of the tab.
            content: Text content to append.
        """
        if tab := self._tabs.get(tab_name.lower()):
            tab.append_content(content)

    def set_current_address(self, address: int) -> None:
        """Set the currently displayed address.

        Args:
            address: Memory address.
        """
        self._address_label.setText(f"0x{address:08X}")

    def set_functions(self, functions: list[tuple[str, int]]) -> None:
        """Set the function list.

        Args:
            functions: List of (name, address) tuples.
        """
        self._func_list.set_functions(functions)

    def set_xrefs(
        self,
        incoming: list[tuple[int, str]],
        outgoing: list[tuple[int, str]],
    ) -> None:
        """Set the cross-reference data.

        Args:
            incoming: List of (address, description) for refs to this location.
            outgoing: List of (address, description) for refs from this location.
        """
        self._xref_panel.set_xrefs(incoming, outgoing)

    def activate_tab(self, tab_name: OutputType) -> None:
        """Activate a specific tab.

        Args:
            tab_name: Name of the tab to activate.
        """
        if tab := self._tabs.get(tab_name.lower()):
            index = self._tab_widget.indexOf(tab)
            if index >= 0:
                self._tab_widget.setCurrentIndex(index)
        elif widget := self._panels.get(tab_name.lower()) or self._embedded_tools.get(tab_name.lower()):
            self._activate_tab_by_widget(widget)

    def log(self, message: str) -> None:
        """Append a message to the log tab.

        Creates the Log tab on-demand if it does not already exist.

        Args:
            message: Message to log.
        """
        if "log" not in self._tabs:
            log_tab = ToolTab("Log", "python")
            self._tabs["log"] = log_tab
            self._tab_widget.addTab(log_tab, "Log")
        self.append_tab_content("log", message)

    def clear_tab(self, tab_name: OutputType) -> None:
        """Clear content of a specific tab.

        Args:
            tab_name: Name of the tab to clear.
        """
        if tab := self._tabs.get(tab_name.lower()):
            tab.set_content("")

    def clear_all(self) -> None:
        """Clear all tab contents."""
        for tab in self._tabs.values():
            tab.set_content("")
        self._func_list.set_functions([])
        self._xref_panel.set_xrefs([], [])
        self._address_label.setText("")

    def _setup_embedded_tabs(self) -> None:
        """Set up tabs for embedded tools and analysis panels."""
        self._analysis_panel: BridgeAnalysisPanel | None = None
        self._script_panel: ScriptManagerPanel | None = None
        self._stack_panel: StackViewerPanel | None = None
        self._hex_editor_panel: HexEditorPanelProtocol | None = None
        self._hex_tools_panel: QWidget | None = None
        self._x64dbg_widget: X64DbgWidgetProtocol | None = None
        self._cutter_widget: CutterWidgetProtocol | None = None
        self._ghidra_widget: GhidraWidgetProtocol | None = None
        self._frida_panel: FridaPanelProtocol | None = None
        self._process_panel: ProcessPanelProtocol | None = None
        self._binary_panel: BinaryPanelProtocol | None = None
        self._sandbox_panel: SandboxPanelProtocol | None = None

        self._x64dbg_bridge: object | None = None
        self._ghidra_bridge: object | None = None
        self._cutter_bridge: object | None = None
        self._frida_bridge: object | None = None

        self._tool_registry: object | None = None

        self._pending_sandbox_backend: object | None = None
        self._pending_script_backend: object | None = None
        self._pending_script_validator: object | None = None

    def set_tool_registry(self, registry: object) -> None:
        """Set the shared tool registry for bridge reuse.

        Args:
            registry: ToolRegistry instance providing bridge accessors.
        """
        self._tool_registry = registry
        _logger.info("tool_registry_set", registry_type=type(registry).__name__)

    def add_analysis_panel(self) -> BridgeAnalysisPanel:
        """Add the bridge analysis panel as a tab.

        Returns:
            BridgeAnalysisPanel: The created BridgeAnalysisPanel widget.
        """
        if self._analysis_panel is not None:
            return self._analysis_panel

        panel_module = importlib.import_module(".panels.analysis_panel", "intellicrack.ui")
        panel = cast("BridgeAnalysisPanel", panel_module.BridgeAnalysisPanel())
        self._analysis_panel = panel
        self._tab_widget.addTab(panel, "Analysis")
        self._panels["analysis"] = panel
        _logger.info("analysis_panel_added", tab="Analysis")
        return panel

    def add_script_panel(self) -> QWidget:
        """Add the script manager panel as a tab.

        Returns:
            QWidget: The created ScriptManagerPanel widget.
        """
        if self._script_panel is not None:
            return self._script_panel

        panel_module = importlib.import_module(".panels.script_manager", "intellicrack.ui")
        raw_widget = panel_module.ScriptManagerPanel()
        self._script_panel = cast("ScriptManagerPanel", raw_widget)
        qwidget = cast("QWidget", raw_widget)
        self._tab_widget.addTab(qwidget, "Scripts")
        self._panels["scripts"] = qwidget

        if self._pending_script_backend is not None:
            self._script_panel.set_backend(
                cast("ScriptManager", self._pending_script_backend),
                validator=cast("ScriptValidator | None", self._pending_script_validator),
            )
            self._pending_script_backend = None
            self._pending_script_validator = None

        _logger.info("script_panel_added", tab="Scripts")
        return qwidget

    def add_stack_panel(self) -> QWidget:
        """Add the stack viewer panel as a tab.

        Returns:
            QWidget: The created StackViewerPanel widget.
        """
        if self._stack_panel is not None:
            return self._stack_panel

        panel_module = importlib.import_module(".panels.stack_viewer", "intellicrack.ui")
        raw_widget = panel_module.StackViewerPanel()
        self._stack_panel = cast("StackViewerPanel", raw_widget)
        qwidget = cast("QWidget", raw_widget)
        self._tab_widget.addTab(qwidget, "Stack")
        self._panels["stack"] = qwidget

        add_source = getattr(self._stack_panel, "add_source", None)
        if callable(add_source):
            add_source("orchestrator", self)

        _logger.info("stack_panel_added", tab="Stack")
        return qwidget

    def add_hex_editor_tab(self) -> HexEditorPanelProtocol | None:
        """Add the built-in hex editor as a panel tab.

        Returns:
            HexEditorPanelProtocol | None: The created HexEditorPanel or None on failure.
        """
        if self._hex_editor_panel is not None:
            return self._hex_editor_panel

        try:
            panel_module = importlib.import_module(".panels.hex_editor_panel", "intellicrack.ui")
            raw_widget = panel_module.HexEditorPanel()
            self._hex_editor_panel = cast("HexEditorPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._hex_editor_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("hex_editor"))
            self._hex_editor_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("hex_editor"))
            self._tab_widget.addTab(qwidget, "Hex Editor")
            self._embedded_tools["hex_editor"] = qwidget

            self._wire_hex_editor_state(raw_widget)

            _logger.info("hex_editor_tab_added", tab="Hex Editor")
        except Exception as e:
            _logger.warning("hex_editor_tab_add_failed", error=str(e))
            return None
        else:
            return self._hex_editor_panel

    def add_hex_tools_tab(self) -> QWidget | None:
        """Add the hex analysis tools panel as a tab.

        Returns:
            QWidget | None: The created HexToolsPanel or None on failure.
        """
        if self._hex_tools_panel is not None:
            return self._hex_tools_panel

        try:
            panel_module = importlib.import_module(".panels.hex_tools_panel", "intellicrack.ui")
            panel = panel_module.HexToolsPanel()
            self._hex_tools_panel = panel
            self._tab_widget.addTab(panel, "Hex Tools")
            _logger.info("hex_tools_tab_added")
        except Exception as exc:
            _logger.warning("hex_tools_tab_add_failed", error=str(exc))
            return None
        else:
            return self._hex_tools_panel

    def add_x64dbg_tab(self, is_64bit: bool = True) -> X64DbgWidgetProtocol | None:
        """Add the x64dbg debugger as a native panel tab.

        Args:
            is_64bit: Whether to use 64-bit mode (True) or 32-bit (False).

        Returns:
            X64DbgWidgetProtocol | None: The created X64DbgPanel or None if creation failed.
        """
        if self._x64dbg_widget is not None:
            return self._x64dbg_widget

        try:
            panel_module = importlib.import_module(".panels.x64dbg_panel", "intellicrack.ui")
            raw_widget = panel_module.X64DbgPanel()
            self._x64dbg_widget = cast("X64DbgWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._x64dbg_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("x64dbg"))
            self._x64dbg_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("x64dbg"))
            tab_name = "x64dbg" if is_64bit else "x32dbg"
            self._tab_widget.addTab(qwidget, tab_name)
            self._embedded_tools["x64dbg"] = qwidget

            bridge: object | None = None
            reg_getter = getattr(self._tool_registry, "get_x64dbg_bridge", None)
            if callable(reg_getter):
                try:
                    bridge = reg_getter()
                    _logger.info("x64dbg_bridge_from_registry", source="registry")
                except Exception:
                    _logger.debug("x64dbg_bridge_registry_fallback", exc_info=True)

            if bridge is None:
                try:
                    bridge_module = importlib.import_module("intellicrack.bridges.x64dbg")
                    bridge = bridge_module.X64DbgBridge()
                except Exception as bridge_err:
                    _logger.warning("x64dbg_bridge_create_failed", error=str(bridge_err))

            if bridge is not None:
                self._x64dbg_widget.set_bridge(bridge)
                self._x64dbg_bridge = bridge
                self._wire_stack_viewer_bridges()
                _logger.info("x64dbg_bridge_set", bridge_type=type(bridge).__name__)

            _logger.info("x64dbg_tab_added", is_64bit=is_64bit)
        except Exception as e:
            _logger.warning("x64dbg_tab_add_failed", error=str(e))
            return None
        else:
            return self._x64dbg_widget

    def add_cutter_tab(self) -> CutterWidgetProtocol | None:
        """Add the Cutter reverse engineering panel as a native tab.

        Returns:
            CutterWidgetProtocol | None: The created CutterPanel or None if creation failed.
        """
        if self._cutter_widget is not None:
            return self._cutter_widget

        try:
            panel_module = importlib.import_module(".panels.cutter_panel", "intellicrack.ui")
            raw_widget = panel_module.CutterPanel()
            self._cutter_widget = cast("CutterWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._cutter_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("cutter"))
            self._cutter_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("cutter"))
            self._tab_widget.addTab(qwidget, "Cutter")
            self._embedded_tools["cutter"] = qwidget

            bridge: object | None = None
            reg_getter = getattr(self._tool_registry, "get_cutter_bridge", None)
            if callable(reg_getter):
                try:
                    bridge = reg_getter()
                    _logger.info("cutter_bridge_from_registry", source="registry")
                except Exception:
                    _logger.debug("cutter_bridge_registry_fallback", exc_info=True)

            if bridge is None:
                try:
                    bridge_module = importlib.import_module("intellicrack.bridges.cutter")
                    bridge = bridge_module.CutterBridge()
                except Exception as bridge_err:
                    _logger.warning("cutter_bridge_create_failed", error=str(bridge_err))

            if bridge is not None:
                self._cutter_widget.set_bridge(bridge)
                self._cutter_bridge = bridge
                _logger.info("cutter_bridge_set", bridge_type=type(bridge).__name__)

            _logger.info("cutter_tab_added", tab="Cutter")
        except Exception as e:
            _logger.warning("cutter_tab_add_failed", error=str(e))
            return None
        else:
            return self._cutter_widget

    def add_ghidra_tab(self) -> GhidraWidgetProtocol | None:
        """Add the Ghidra analysis panel as a native tab.

        Returns:
            GhidraWidgetProtocol | None: The created GhidraPanel or None if creation failed.
        """
        if self._ghidra_widget is not None:
            return self._ghidra_widget

        try:
            panel_module = importlib.import_module(".panels.ghidra_panel", "intellicrack.ui")
            raw_widget = panel_module.GhidraPanel()
            self._ghidra_widget = cast("GhidraWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._ghidra_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("ghidra"))
            self._ghidra_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("ghidra"))
            self._tab_widget.addTab(qwidget, "Ghidra")
            self._embedded_tools["ghidra"] = qwidget

            bridge: object | None = None
            reg_getter = getattr(self._tool_registry, "get_ghidra_bridge", None)
            if callable(reg_getter):
                try:
                    bridge = reg_getter()
                    _logger.info("ghidra_bridge_from_registry", source="registry")
                except Exception:
                    _logger.debug("ghidra_bridge_registry_fallback", exc_info=True)

            if bridge is None:
                try:
                    bridge_module = importlib.import_module("intellicrack.bridges.ghidra")
                    bridge = bridge_module.GhidraBridge()
                except Exception as bridge_err:
                    _logger.warning("ghidra_bridge_create_failed", error=str(bridge_err))

            if bridge is not None:
                self._ghidra_widget.set_bridge(bridge)
                self._ghidra_bridge = bridge
                _logger.info("ghidra_bridge_set", bridge_type=type(bridge).__name__)

            _logger.info("ghidra_tab_added", tab="Ghidra")
        except Exception as e:
            _logger.warning("ghidra_tab_add_failed", error=str(e))
            return None
        else:
            return self._ghidra_widget

    def add_frida_tab(self) -> FridaPanelProtocol | None:
        """Add the Frida instrumentation panel as a tab.

        Returns:
            FridaPanelProtocol | None: The created FridaPanel or None if creation failed.
        """
        if self._frida_panel is not None:
            return self._frida_panel

        try:
            panel_module = importlib.import_module(".panels.frida_panel", "intellicrack.ui")
            raw_widget = panel_module.FridaPanel()
            self._frida_panel = cast("FridaPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._frida_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("frida"))
            self._frida_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("frida"))
            self._tab_widget.addTab(qwidget, "Frida")
            self._panels["frida"] = qwidget

            bridge: object | None = None
            reg_getter = getattr(self._tool_registry, "get_frida_bridge", None)
            if callable(reg_getter):
                try:
                    bridge = reg_getter()
                    _logger.info("frida_bridge_from_registry", source="registry")
                except Exception:
                    _logger.debug("frida_bridge_registry_fallback", exc_info=True)

            if bridge is None:
                try:
                    bridge_module = importlib.import_module("intellicrack.bridges.frida_bridge")
                    bridge = bridge_module.FridaBridge()
                except Exception as bridge_err:
                    _logger.warning("frida_bridge_create_failed", error=str(bridge_err))

            if bridge is not None:
                self._frida_panel.set_bridge(bridge)
                self._frida_bridge = bridge
                self._wire_stack_viewer_bridges()
                _logger.info("frida_bridge_set", bridge_type=type(bridge).__name__)

            _logger.info("frida_tab_added", tab="Frida")
        except Exception as e:
            _logger.warning("frida_tab_add_failed", error=str(e))
            return None
        else:
            return self._frida_panel

    def add_process_tab(self) -> ProcessPanelProtocol | None:
        """Add the process management panel as a tab.

        Returns:
            ProcessPanelProtocol | None: The created ProcessPanel or None if creation failed.
        """
        if self._process_panel is not None:
            return self._process_panel

        try:
            panel_module = importlib.import_module(".panels.process_panel", "intellicrack.ui")
            raw_widget = panel_module.ProcessPanel()
            self._process_panel = cast("ProcessPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._process_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("process"))
            self._process_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("process"))
            self._tab_widget.addTab(qwidget, "Process")
            self._panels["process"] = qwidget
            _logger.info("process_tab_added", tab="Processes")
        except Exception as e:
            _logger.warning("process_tab_add_failed", error=str(e))
            return None
        else:
            return self._process_panel

    def add_binary_tab(self) -> BinaryPanelProtocol | None:
        """Add the binary hex viewer and patching panel as a tab.

        Returns:
            BinaryPanelProtocol | None: The created BinaryPanel or None if creation failed.
        """
        if self._binary_panel is not None:
            return self._binary_panel

        try:
            panel_module = importlib.import_module(".panels.binary_panel", "intellicrack.ui")
            raw_widget = panel_module.BinaryPanel()
            self._binary_panel = cast("BinaryPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._binary_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("binary"))
            self._binary_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("binary"))
            self._tab_widget.addTab(qwidget, "Binary")
            self._panels["binary"] = qwidget
            _logger.info("binary_tab_added", tab="Binary")
        except Exception as e:
            _logger.warning("binary_tab_add_failed", error=str(e))
            return None
        else:
            return self._binary_panel

    def add_sandbox_tab(self) -> SandboxPanelProtocol | None:
        """Add the sandbox management panel as a tab.

        Returns:
            SandboxPanelProtocol | None: The created SandboxPanel or None if creation failed.
        """
        if self._sandbox_panel is not None:
            return self._sandbox_panel

        try:
            sandbox_config_mod = importlib.import_module(".sandbox_config", "intellicrack.ui")
            dialog_cls = getattr(sandbox_config_mod, "SandboxConfigDialog", None)
            if dialog_cls is not None and not dialog_cls().is_sandbox_available():
                _logger.info("sandbox_not_available_skipping_tab", tab="Sandbox")
                return None

            panel_module = importlib.import_module(".panels.sandbox_panel", "intellicrack.ui")
            raw_widget = panel_module.SandboxPanel()
            self._sandbox_panel = cast("SandboxPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._sandbox_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("sandbox"))
            self._sandbox_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("sandbox"))
            self._tab_widget.addTab(qwidget, "Sandbox")
            self._panels["sandbox"] = qwidget

            if self._pending_sandbox_backend is not None:
                if hasattr(self._sandbox_panel, "set_sandbox"):
                    self._sandbox_panel.set_sandbox(self._pending_sandbox_backend)
                self._pending_sandbox_backend = None

            monitor_cls = getattr(sandbox_config_mod, "SandboxMonitorWidget", None)
            if monitor_cls is not None:
                monitor = monitor_cls(parent=qwidget)
                layout = qwidget.layout()
                if layout is not None:
                    layout.addWidget(monitor)

            _logger.info("sandbox_tab_added", tab="Sandbox")
        except Exception as e:
            _logger.warning("sandbox_tab_add_failed", error=str(e))
            return None
        else:
            return self._sandbox_panel

    def open_in_ghidra(self, file_path: Path | str) -> bool:
        """Open a file in the embedded Ghidra tool.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            bool: True if the file was opened successfully.
        """
        if self._ghidra_widget is None:
            widget = self.add_ghidra_tab()
            if widget is None:
                return False

        if self._ghidra_widget is None:
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path
        success = self._ghidra_widget.load_binary(path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._ghidra_widget))
        return success

    def open_in_binary(self, file_path: Path | str) -> bool:
        """Open a file in the binary hex viewer panel.

        Args:
            file_path: Path to the binary file.

        Returns:
            bool: True if the file was opened successfully.
        """
        if self._binary_panel is None:
            widget = self.add_binary_tab()
            if widget is None:
                return False

        if self._binary_panel is None:
            return False

        success = self._binary_panel.load_file(file_path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._binary_panel))
        return success

    def open_in_hex_editor(self, file_path: Path | str) -> bool:
        """Open a file in the built-in hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            bool: True if the file was opened successfully.
        """
        if self._hex_editor_panel is None:
            widget = self.add_hex_editor_tab()
            if widget is None:
                return False

        if self._hex_editor_panel is None:
            return False

        success = self._hex_editor_panel.load_file(file_path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._hex_editor_panel))
        return success

    def open_in_x64dbg(
        self,
        file_path: Path | str,
        is_64bit: bool = True,
    ) -> bool:
        """Open a file in the embedded x64dbg debugger.

        Args:
            file_path: Path to the executable to debug.
            is_64bit: Whether to use x64dbg (True) or x32dbg (False).

        Returns:
            bool: True if the file was opened successfully.
        """
        if self._x64dbg_widget is None:
            widget = self.add_x64dbg_tab(is_64bit)
            if widget is None:
                return False

        if self._x64dbg_widget is None:
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path
        success = self._x64dbg_widget.debug_file(path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._x64dbg_widget))
        return success

    def open_in_cutter(self, file_path: Path | str) -> bool:
        """Open a file in the embedded Cutter reverse engineering tool.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            bool: True if the file was opened successfully.
        """
        if self._cutter_widget is None:
            widget = self.add_cutter_tab()
            if widget is None:
                return False

        if self._cutter_widget is None:
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path
        success = self._cutter_widget.analyze_binary(path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._cutter_widget))
        return success

    def _activate_tab_by_widget(self, widget: QWidget) -> None:
        """Activate a tab by its widget.

        Args:
            widget: The widget whose tab should be activated.
        """
        index = self._tab_widget.indexOf(widget)
        if index >= 0:
            self._tab_widget.setCurrentIndex(index)

    def get_embedded_tool(self, tool_id: OutputType) -> QWidget | None:
        """Get an embedded tool widget by ID.

        Args:
            tool_id: The tool identifier.

        Returns:
            QWidget | None: The embedded tool widget or None if not available.
        """
        return self._embedded_tools.get(tool_id.lower())

    def get_panel(self, panel_id: OutputType) -> QWidget | None:
        """Get a panel widget by ID.

        Args:
            panel_id: The panel identifier.

        Returns:
            QWidget | None: The panel widget or None if not available.
        """
        return self._panels.get(panel_id.lower())

    def update_bridge_analysis(self, analysis: BridgeAnalysisSummary) -> None:
        """Update the analysis panel with new bridge analysis data.

        Args:
            analysis: The bridge analysis data to display.
        """
        if self._analysis_panel is None:
            self.add_analysis_panel()

        if self._analysis_panel is not None:
            self._analysis_panel.set_analysis(analysis)
            _logger.info("bridge_analysis_updated", has_panel=True)

    def activate_analysis_tab(self) -> None:
        """Activate the bridge analysis tab."""
        if self._analysis_panel is None:
            self.add_analysis_panel()
        if self._analysis_panel is not None:
            self._activate_tab_by_widget(self._analysis_panel)

    def activate_scripts_tab(self) -> None:
        """Activate the scripts manager tab."""
        if self._script_panel is None:
            self.add_script_panel()
        if self._script_panel is not None:
            self._activate_tab_by_widget(self._script_panel)

    def activate_stack_tab(self) -> None:
        """Activate the stack viewer tab."""
        if self._stack_panel is None:
            self.add_stack_panel()
        if self._stack_panel is not None:
            self._activate_tab_by_widget(self._stack_panel)

    @staticmethod
    def _cleanup_bridge(bridge: object, bridge_attr: str) -> None:
        """Safely clean up a bridge, handling both sync and async methods.

        Args:
            bridge: The bridge instance to clean up.
            bridge_attr: Attribute name for logging.
        """
        async_mod = importlib.import_module(".panels.async_bridge", "intellicrack.ui")
        run_coro = async_mod.run_bridge_coroutine

        for method_name in ("detach", "shutdown", "stop"):
            method = getattr(bridge, method_name, None)
            if method is not None and callable(method):
                try:
                    if inspect.iscoroutinefunction(method):
                        run_coro(method())
                    else:
                        method()
                except Exception:
                    _logger.warning(
                        "bridge_cleanup_error",
                        exc_info=True,
                        bridge=bridge_attr,
                        method=method_name,
                    )

    def _on_tab_close_requested(self, index: int) -> None:
        """Handle a tab close request.

        Identifies the widget at the given tab index, stops any associated
        tool/bridge, removes it from tracking dicts, and frees Qt resources.

        Args:
            index: Tab index to close.
        """
        widget = self._tab_widget.widget(index)
        if widget is None:
            return

        panel_registry: tuple[tuple[str, str | None], ...] = (
            ("_ghidra_widget", "_ghidra_bridge"),
            ("_cutter_widget", "_cutter_bridge"),
            ("_x64dbg_widget", "_x64dbg_bridge"),
            ("_hex_editor_panel", None),
            ("_frida_panel", "_frida_bridge"),
            ("_process_panel", None),
            ("_binary_panel", None),
            ("_sandbox_panel", None),
            ("_analysis_panel", None),
            ("_script_panel", None),
            ("_stack_panel", None),
        )

        widget_id = id(widget)
        matched_attrs: list[tuple[str, str | None]] = []
        for attr_name, bridge_attr in panel_registry:
            ref = getattr(self, attr_name, None)
            if ref is not None and id(ref) == widget_id:
                matched_attrs.append((attr_name, bridge_attr))

        if matched_attrs:
            stopped = False
            for attr_name, bridge_attr in matched_attrs:
                ref = getattr(self, attr_name)
                if not stopped and hasattr(ref, "stop_tool"):
                    ref.stop_tool()
                    stopped = True

                if bridge_attr is not None:
                    bridge = getattr(self, bridge_attr, None)
                    if bridge is not None:
                        self._cleanup_bridge(bridge, bridge_attr)
                        setattr(self, bridge_attr, None)

                setattr(self, attr_name, None)

            for tracking_dict in (self._embedded_tools, self._panels):
                keys_to_remove = [k for k, v in tracking_dict.items() if id(v) == widget_id]
                for k in keys_to_remove:
                    del tracking_dict[k]
        else:
            keys_to_remove = [k for k, v in self._tabs.items() if id(v) == widget_id]
            for k in keys_to_remove:
                del self._tabs[k]

        self._tab_widget.removeTab(index)
        widget.deleteLater()
        _logger.debug("tab_closed", tab_index=index)

    def close_embedded_tools(self) -> None:
        """Close all embedded tool instances and null their references."""
        if self._hex_editor_panel is not None:
            self._hex_editor_panel.stop_tool()
            self._hex_editor_panel = None

        if self._x64dbg_widget is not None:
            self._x64dbg_widget.stop_tool()
            self._x64dbg_widget = None

        if self._cutter_widget is not None:
            self._cutter_widget.stop_tool()
            self._cutter_widget = None

        if self._ghidra_widget is not None:
            self._ghidra_widget.stop_tool()
            self._ghidra_widget = None

        if self._frida_panel is not None:
            self._frida_panel.stop_tool()
            self._frida_panel = None

        if self._process_panel is not None:
            self._process_panel.stop_tool()
            self._process_panel = None

        if self._binary_panel is not None:
            self._binary_panel.stop_tool()
            self._binary_panel = None

        if self._sandbox_panel is not None:
            self._sandbox_panel.stop_tool()
            self._sandbox_panel = None

        if self._analysis_panel is not None:
            self._analysis_panel = None

        if self._script_panel is not None:
            self._script_panel = None

        if self._stack_panel is not None:
            self._stack_panel = None

        for attr_name in ("_x64dbg_bridge", "_ghidra_bridge", "_cutter_bridge", "_frida_bridge"):
            if getattr(self, attr_name, None) is not None:
                setattr(self, attr_name, None)
                _logger.debug("bridge_reference_released", bridge=attr_name)

        self._embedded_tools.clear()
        self._panels.clear()
        self._tabs.clear()

        _logger.info("embedded_tools_closed", panel_count=len(self._panels))

    def _on_tab_context_menu(self, pos: QPoint) -> None:
        """Show a context menu for the tab bar at the given position.

        Args:
            pos: Position of the right-click in tab bar coordinates.
        """
        tab_bar = self._tab_widget.tabBar()
        if tab_bar is None:
            return
        index = tab_bar.tabAt(pos)
        if index < 0:
            return

        menu = QMenu(self)

        detach_action = menu.addAction("Detach to Window")
        if detach_action is not None:
            detach_action.triggered.connect(lambda: self.detach_tab(index))

        menu.addSeparator()

        close_action = menu.addAction("Close Tab")
        if close_action is not None:
            close_action.triggered.connect(lambda: self._on_tab_close_requested(index))

        close_others_action = menu.addAction("Close Other Tabs")
        if close_others_action is not None:
            close_others_action.triggered.connect(lambda: self._close_other_tabs(index))

        close_all_action = menu.addAction("Close All Tabs")
        if close_all_action is not None:
            close_all_action.triggered.connect(self._close_all_tabs)

        global_pos = tab_bar.mapToGlobal(pos)
        menu.exec(global_pos)

    def detach_tab(self, index: int) -> DetachedPanelWindow | None:
        """Detach a tab into a separate floating window.

        Removes the widget from the tab container and hosts it in a
        ``DetachedPanelWindow``. The panel is not destroyed; it can
        be re-docked via the window's re-dock button or close event.

        Args:
            index: Tab index to detach.

        Returns:
            DetachedPanelWindow | None: The created window, or None
                if the index is invalid.
        """
        widget = self._tab_widget.widget(index)
        if widget is None:
            return None

        title = self._tab_widget.tabText(index)
        self._tab_widget.removeTab(index)

        window = DetachedPanelWindow(widget, title, self)
        window.reattach_requested.connect(self._reattach_panel)
        self._detached_windows[title] = window
        window.show()

        _logger.info("tab_detached", title=title)
        return window

    def _reattach_panel(self, widget: QWidget, title: str) -> None:
        """Re-dock a previously detached panel back into the tab bar.

        Args:
            widget: The panel widget being returned.
            title: The tab title to restore.
        """
        window = self._detached_windows.pop(title, None)
        if window is not None:
            window.hide()

        self._tab_widget.addTab(widget, title)
        self._tab_widget.setCurrentWidget(widget)
        _logger.info("tab_reattached", title=title)

    def _close_other_tabs(self, keep_index: int) -> None:
        """Close all tabs except the one at the given index.

        Args:
            keep_index: Tab index to keep open.
        """
        keep_widget = self._tab_widget.widget(keep_index)
        indices_to_close = [i for i in range(self._tab_widget.count() - 1, -1, -1) if self._tab_widget.widget(i) is not keep_widget]
        for i in indices_to_close:
            self._on_tab_close_requested(i)

    def _close_all_tabs(self) -> None:
        """Close every tab in the tab widget."""
        for i in range(self._tab_widget.count() - 1, -1, -1):
            self._on_tab_close_requested(i)

    def detach_current_tab(self) -> DetachedPanelWindow | None:
        """Detach the currently active tab into a floating window.

        Returns:
            DetachedPanelWindow | None: The created window, or None
                if no tab is active.
        """
        index = self._tab_widget.currentIndex()
        if index < 0:
            return None
        return self.detach_tab(index)

    def close_detached_windows(self) -> None:
        """Close all detached panel windows and re-dock their panels."""
        for title in list(self._detached_windows):
            window = self._detached_windows.get(title)
            if window is not None:
                self._reattach_panel(window.panel, window.panel_title)

    def get_detached_state(self) -> list[str]:
        """Get the titles of currently detached panels.

        Returns:
            list[str]: Titles of detached panel windows.
        """
        return list(self._detached_windows.keys())

    def find_tab_by_title(self, title: str) -> int:
        """Find a tab index by its title text.

        Args:
            title: Tab title to search for.

        Returns:
            int: Tab index, or -1 if not found.
        """
        for i in range(self._tab_widget.count()):
            if self._tab_widget.tabText(i) == title:
                return i
        return -1

    def get_bridge_for_tool(self, tool_id: str) -> object | None:
        """Get the bridge instance for a specific tool.

        Delegates to the appropriate panel's get_bridge() method.

        Args:
            tool_id: Tool identifier (e.g., "frida", "ghidra", "cutter", "x64dbg").

        Returns:
            object | None: Bridge instance or None if not available.
        """
        panel_map: dict[str, str] = {
            "frida": "_frida_panel",
            "ghidra": "_ghidra_widget",
            "cutter": "_cutter_widget",
            "x64dbg": "_x64dbg_widget",
        }
        attr_name = panel_map.get(tool_id.lower())
        if attr_name is None:
            return None
        panel = getattr(self, attr_name, None)
        if panel is not None and hasattr(panel, "get_bridge"):
            return panel.get_bridge()
        return None

    def get_active_process_pid(self) -> int | None:
        """Get the currently selected PID from the process panel.

        Returns:
            int | None: Selected process ID or None if no process selected.
        """
        if self._process_panel is not None and hasattr(self._process_panel, "get_selected_pid"):
            return self._process_panel.get_selected_pid()
        return None

    def display_analysis_result(
        self,
        tab_name: OutputType,
        content: str,
        info: str = "",
    ) -> None:
        """Display analysis results in a specific tab.

        Routes analysis output from the orchestrator to the appropriate
        tab using set_tab_content and set_tab_info.

        Args:
            tab_name: Name of the tab to display in.
            content: Content to display.
            info: Additional info text for the tab header.
        """
        self.set_tab_content(tab_name, content)
        if info:
            self.set_tab_info(tab_name, tab_name, info)
        self.activate_tab(tab_name)

    def clear_analysis_tab(self, tab_name: OutputType) -> None:
        """Clear a specific analysis tab's content.

        Args:
            tab_name: Name of the tab to clear.
        """
        self.clear_tab(tab_name)

    def get_active_tool_widget(self, tool_id: OutputType) -> QWidget | None:
        """Get the active embedded tool widget by ID.

        Args:
            tool_id: Tool identifier string.

        Returns:
            QWidget | None: The embedded tool widget or None.
        """
        return self.get_embedded_tool(tool_id)

    def log_frida_message(self, message: str) -> None:
        """Log a message to the Frida panel.

        Args:
            message: Message to log.
        """
        if self._frida_panel is not None and hasattr(self._frida_panel, "log_message"):
            self._frida_panel.log_message(message)

    def add_frida_hook_entry(self, hook_info: dict[str, object]) -> None:
        """Add a hook entry to the Frida panel.

        Args:
            hook_info: Dictionary with hook details.
        """
        if self._frida_panel is not None and hasattr(self._frida_panel, "add_hook_entry"):
            self._frida_panel.add_hook_entry(
                address=str(hook_info.get("address", "")),
                module=str(hook_info.get("module", "")),
                function=str(hook_info.get("function", "")),
                status=str(hook_info.get("status", "Active")),
                hook_id=str(hook_info.get("hook_id", "")),
            )

    def get_sandbox_backend(self) -> object | None:
        """Get the sandbox backend from the sandbox panel.

        Returns:
            object | None: Sandbox backend or None.
        """
        if self._sandbox_panel is not None and hasattr(self._sandbox_panel, "get_sandbox"):
            return self._sandbox_panel.get_sandbox()
        return None

    def load_sandbox_report(self, report_path: str) -> None:
        """Load an execution report into the sandbox panel.

        Args:
            report_path: Path to the execution report.
        """
        if self._sandbox_panel is not None:
            loader = getattr(self._sandbox_panel, "load_execution_report", None)
            if callable(loader):
                loader(report_path)

    def get_script_panel_state(self) -> tuple[str | None, tuple[str, str, str] | None]:
        """Get the current script panel state.

        Returns:
            tuple[str | None, tuple[str, str, str] | None]: Tuple of
                (selected_script_id, current_script_data).
                current_script_data is (name, type, content) or None.
        """
        selected_id: str | None = None
        current_script: tuple[str, str, str] | None = None
        if self._script_panel is not None:
            get_id = getattr(self._script_panel, "get_selected_id", None)
            if callable(get_id):
                raw_id = get_id()
                if isinstance(raw_id, str):
                    selected_id = raw_id
            current_script = self._script_panel.get_current_script()
        return selected_id, current_script

    def get_code_highlighter(self) -> QSyntaxHighlighter | None:
        """Get the syntax highlighter from the current tab's code display.

        Traverses the active tab widget to find a QPlainTextEdit child
        and retrieves its document's syntax highlighter.

        Returns:
            QSyntaxHighlighter | None: Syntax highlighter or None if not available.
        """
        current_widget = self._tab_widget.currentWidget()
        if current_widget is None:
            return None
        code_display = current_widget.findChild(QPlainTextEdit)
        doc = code_display.document()
        return None if doc is None else doc.findChild(QSyntaxHighlighter)

    def _wire_hex_editor_state(self, panel_widget: object) -> None:
        """Create a shared HexDocumentState and wire it to the bridge and panel.

        Args:
            panel_widget: The HexEditorPanel instance.
        """
        try:
            state_mod = importlib.import_module("intellicrack.bridges.hex_state")
            state_holder = state_mod.HexDocumentState()

            set_state = getattr(panel_widget, "set_state_holder", None)
            if callable(set_state):
                set_state(state_holder)

            reg_getter = getattr(self._tool_registry, "get_hex_editor_bridge", None)
            if callable(reg_getter):
                try:
                    bridge = reg_getter()
                    bridge_set_state = getattr(bridge, "set_state_holder", None)
                    if callable(bridge_set_state):
                        bridge_set_state(state_holder)
                    bridge_set_reg = getattr(bridge, "set_tool_registry", None)
                    if callable(bridge_set_reg):
                        bridge_set_reg(self._tool_registry)
                    _logger.info("hex_editor_state_wired", source="registry")
                except Exception:
                    _logger.debug("hex_editor_bridge_state_wire_failed", exc_info=True)

            context_signal = getattr(panel_widget, "context_push_requested", None)
            if context_signal is not None and hasattr(context_signal, "connect"):
                context_signal.connect(self._on_hex_context_push)

        except Exception:
            _logger.debug("hex_editor_state_wire_failed", exc_info=True)

    def _on_hex_context_push(self, context: dict[str, object]) -> None:
        """Handle hex editor context push for AI integration.

        Formats the hex editor context into a readable analysis prompt
        and emits it via the ``hex_context_ready`` signal for the chat
        panel to consume.

        Args:
            context: Hex editor context dictionary.
        """
        cursor_val: object = context.get("cursor", 0)
        cursor_offset: int = int(cursor_val) if isinstance(cursor_val, (int, float)) else 0

        parts: list[str] = ["[Hex Editor Context]"]

        file_path: object = context.get("file_path")
        if file_path is not None:
            parts.append(f"File: {file_path}")

        size_val: object = context.get("size")
        if isinstance(size_val, int):
            parts.append(f"Size: {size_val} bytes")

        parts.append(f"Offset: 0x{cursor_offset:08X}")

        bytes_data: object = context.get("bytes_at_cursor")
        if isinstance(bytes_data, str):
            parts.append(f"Data: {bytes_data}")

        inspection: object = context.get("inspection")
        if isinstance(inspection, dict):
            for key, val in cast("dict[str, str]", inspection).items():
                parts.append(f"  {key}: {val}")

        parts.append("\nPlease analyze this binary data.")

        formatted = "\n".join(parts)
        self.hex_context_ready.emit(formatted)
        self.log(f"[Hex Editor Context] cursor=0x{cursor_offset:08X}")
        _logger.info("hex_context_pushed", keys=list(context.keys()))

    def _wire_stack_viewer_bridges(self) -> None:
        """Wire bridge instances to the stack viewer panel.

        Connects x64dbg and Frida bridges to the stack viewer
        for stack trace display.
        """
        if self._stack_panel is None:
            return
        if hasattr(self._stack_panel, "set_x64dbg_bridge") and self._x64dbg_bridge is not None:
            self._stack_panel.set_x64dbg_bridge(self._x64dbg_bridge)
        if hasattr(self._stack_panel, "set_frida_bridge") and self._frida_bridge is not None:
            self._stack_panel.set_frida_bridge(self._frida_bridge)

    def wire_sandbox_backend(self, sandbox: object, manager: object | None = None) -> None:
        """Wire a sandbox backend and optional manager to the sandbox panel.

        Stores the backend for deferred wiring if the panel hasn't been
        created yet. If the panel exists, wires immediately. When a
        manager is provided, it is also forwarded to the panel.

        Args:
            sandbox: Sandbox backend instance.
            manager: Optional SandboxManager instance for type-aware creation.
        """
        self._pending_sandbox_backend = sandbox
        if self._sandbox_panel is not None and hasattr(self._sandbox_panel, "set_sandbox"):
            self._sandbox_panel.set_sandbox(sandbox)
            self._pending_sandbox_backend = None
        if manager is not None and self._sandbox_panel is not None and hasattr(self._sandbox_panel, "set_sandbox_manager"):
            self._sandbox_panel.set_sandbox_manager(manager)

    def wire_script_backend(self, backend: object, validator: object | None = None) -> None:
        """Wire a script generation backend to the script manager.

        Stores the backend for deferred wiring if the panel hasn't been
        created yet. If the panel exists, wires immediately.

        Args:
            backend: Script generation backend instance.
            validator: Optional script validator instance.
        """
        self._pending_script_backend = backend
        self._pending_script_validator = validator
        if self._script_panel is not None and hasattr(self._script_panel, "set_backend"):
            self._script_panel.set_backend(
                cast("ScriptManager", backend),
                validator=cast("ScriptValidator | None", validator),
            )
            self._pending_script_backend = None
            self._pending_script_validator = None

    def save_tab_state(self) -> dict[str, object]:
        """Capture the current tab layout state for persistence.

        Returns:
            dict[str, object]: Serialisable snapshot of open tabs, their
                order, the active tab index, and splitter proportions.
        """
        tab_names: list[str] = []
        for i in range(self._tab_widget.count()):
            text = self._tab_widget.tabText(i)
            tab_names.append(text)

        return {
            "tab_names": tab_names,
            "active_index": self._tab_widget.currentIndex(),
            "splitter_sizes": self._main_splitter.sizes(),
        }

    def restore_tab_state(self, state: dict[str, object]) -> None:
        """Restore a previously saved tab layout.

        Re-opens panels whose names appear in *state* and sets the
        active tab and splitter proportions.

        Args:
            state: Dict previously returned by ``save_tab_state``.
        """
        tab_openers: dict[str, Callable[[], object]] = {
            "Hex Editor": self.add_hex_editor_tab,
            "Hex Tools": self.add_hex_tools_tab,
            "Frida": self.add_frida_tab,
            "Ghidra": self.add_ghidra_tab,
            "Cutter": self.add_cutter_tab,
            "Process": self.add_process_tab,
            "Binary": self.add_binary_tab,
            "Sandbox": self.add_sandbox_tab,
            "Analysis": self.add_analysis_panel,
            "Scripts": self.add_script_panel,
            "Stack": self.add_stack_panel,
        }

        names_val: object = state.get("tab_names")
        stored_names = cast("list[str]", names_val) if isinstance(names_val, list) else []
        for tab_name in stored_names:
            opener = tab_openers.get(tab_name)
            if opener is not None:
                opener()

        idx_val: object = state.get("active_index")
        if isinstance(idx_val, int) and 0 <= idx_val < self._tab_widget.count():
            self._tab_widget.setCurrentIndex(idx_val)

        sizes_val: object = state.get("splitter_sizes")
        stored_sizes = cast("list[int]", sizes_val) if isinstance(sizes_val, list) else []
        if len(stored_sizes) == 2:  # noqa: PLR2004
            self._main_splitter.setSizes([int(stored_sizes[0]), int(stored_sizes[1])])

    def has_unsaved_changes(self) -> bool:
        """Check whether any panel has unsaved modifications.

        Currently checks the hex editor document state.

        Returns:
            bool: True if unsaved changes exist.
        """
        if self._hex_editor_panel is None:
            return False
        has_changes_fn = getattr(self._hex_editor_panel, "has_unsaved_changes", None)
        if callable(has_changes_fn):
            return bool(has_changes_fn())
        return False

    def save_hex_editor(self) -> bool:
        """Delegate save to the hex editor panel.

        Returns:
            bool: True if saved successfully.
        """
        if self._hex_editor_panel is None:
            return False
        save_fn = getattr(self._hex_editor_panel, "save", None)
        if callable(save_fn):
            return bool(save_fn())
        return False
