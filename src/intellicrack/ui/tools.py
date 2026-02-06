"""Tool output panel widget for the Intellicrack UI.

This module provides the tool output display panel showing
decompiled code, disassembly, and analysis results from tools,
as well as embedded external tools (HxD, x64dbg, Cutter) and
specialized analysis panels (Licensing, Scripts, Stack).
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QSyntaxHighlighter, QTextCursor
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
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
            True if the tool was started successfully.
        """
        _ = self
        return False

    def stop_tool(self) -> bool:
        """Terminate the external tool process.

        Returns:
            True if the tool was stopped successfully.
        """
        _ = self
        return False


@runtime_checkable
class HxDWidgetProtocol(ToolWidget, Protocol):
    """Protocol for HxD hex editor widget integration."""

    def load_file(self, file_path: Path) -> bool:
        """Load a file into the hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            True if the file was loaded successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class X64DbgWidgetProtocol(ToolWidget, Protocol):
    """Protocol for x64dbg debugger widget integration."""

    def debug_file(self, file_path: Path) -> bool:
        """Launch a file in the debugger.

        Args:
            file_path: Path to the executable to debug.

        Returns:
            True if debugging was started successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class CutterWidgetProtocol(ToolWidget, Protocol):
    """Protocol for Cutter reverse engineering widget integration."""

    def analyze_binary(self, file_path: Path) -> bool:
        """Open a binary for analysis in Cutter.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            True if analysis was started successfully.
        """
        _ = (self, file_path)
        return False


@runtime_checkable
class GhidraWidgetProtocol(ToolWidget, Protocol):
    """Protocol for Ghidra reverse engineering widget integration."""

    def load_binary(self, binary_path: Path) -> bool:
        """Load a binary into Ghidra for analysis.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            True if the binary was loaded successfully.
        """
        _ = (self, binary_path)
        return False


@runtime_checkable
class Radare2WidgetProtocol(ToolWidget, Protocol):
    """Protocol for radare2/iaito GUI widget integration."""

    def analyze_binary(self, binary_path: Path) -> bool:
        """Load and analyze a binary in the radare2 GUI.

        Args:
            binary_path: Path to the binary to analyze.

        Returns:
            True if analysis was started successfully.
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


@runtime_checkable
class ProcessPanelProtocol(ToolWidget, Protocol):
    """Protocol for process management panel."""

    def get_selected_pid(self) -> int | None:
        """Get the currently selected process ID.

        Returns:
            The selected PID or None.
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
            True if the file was loaded successfully.
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


@runtime_checkable
class AnalysisPanel(Protocol):
    """Protocol for analysis panels."""

    def set_analysis(self, analysis: LicensingAnalysis) -> None:
        """Update the panel with new licensing analysis data.

        Args:
            analysis: The licensing analysis results to display.
        """


if TYPE_CHECKING:
    from ..core.types import LicensingAnalysis
    from .panels.licensing_panel import LicensingAnalysisPanel

_logger = get_logger("ui.tools")


OutputType = Literal[
    "ghidra",
    "frida",
    "radare2",
    "x64dbg",
    "log",
    "licensing",
    "scripts",
    "stack",
    "hxd",
    "cutter",
    "process",
    "binary",
    "sandbox",
]


class CodeDisplay(QPlainTextEdit):
    """Code display widget with syntax highlighting.

    Provides a read-only text area for displaying code with
    appropriate syntax highlighting based on language.
    """

    def __init__(
        self,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the code display.

        Args:
            language: Programming language for highlighting.
            parent: Parent widget.
        """
        super().__init__(parent=parent)
        self._language = language
        self._setup_ui()
        self.set_language(language)

    def _setup_ui(self) -> None:
        """Set up the code display UI."""
        self.setReadOnly(True)
        self.setFont(QFont("JetBrains Mono", 10))
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
            The syntax highlighter or None.
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
        block = self.document().findBlockByLineNumber(line_number - 1)
        if block.isValid():
            cursor = QTextCursor(block)
            self.setTextCursor(cursor)
            self.centerCursor()


class ToolTab(QFrame):
    """A single tool output tab.

    Contains a code display area and optional metadata panel
    for showing tool-specific output.
    """

    def __init__(
        self,
        name: str,
        language: str = "c",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool tab.

        Args:
            name: Tab name.
            language: Default syntax highlighting language.
            parent: Parent widget.
        """
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
        self._info_panel.setMaximumHeight(150)
        self._info_panel.setObjectName("info_panel")

        info_layout = QVBoxLayout(self._info_panel)
        info_layout.setContentsMargins(8, 8, 8, 8)
        info_layout.setSpacing(4)

        self._info_header = QLabel("Details")
        self._info_header.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._info_header.setObjectName("panel_title")
        info_layout.addWidget(self._info_header)

        self._info_content = QLabel()
        self._info_content.setFont(QFont("JetBrains Mono", 9))
        self._info_content.setObjectName("code_label")
        self._info_content.setWordWrap(True)
        self._info_content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        info_layout.addWidget(self._info_content)
        info_layout.addStretch()

        self._splitter.addWidget(self._info_panel)
        self._splitter.setSizes([400, 100])

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
    """

    function_selected = pyqtSignal(str, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the function list panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._functions: list[tuple[str, int]] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the function list UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(32)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(8, 0, 8, 0)

        title = QLabel("Functions")
        title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)

        self._count_label = QLabel("(0)")
        self._count_label.setObjectName("secondary_text")
        header_layout.addWidget(self._count_label)
        header_layout.addStretch()

        layout.addWidget(header)

        self._list_widget = QListWidget()
        self._list_widget.setFont(QFont("JetBrains Mono", 9))
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
            _logger.warning("failed_to_parse_function_item", extra={"text": item.text()})

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
            List of (name, address) tuples.
        """
        return self._functions


class XRefPanel(QFrame):
    """Panel showing cross-references to/from an address.

    Displays incoming and outgoing references for navigation.
    """

    xref_selected = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the xref panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the xref panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(32)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(8, 0, 8, 0)

        title = QLabel("Cross References")
        title.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        layout.addWidget(header)

        self._xref_display = QTreeWidget()
        self._xref_display.setHeaderHidden(True)
        self._xref_display.setFont(QFont("JetBrains Mono", 9))
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
                pass

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

    Attributes:
        address_clicked: Signal emitted when an address is clicked.
        embedded_tool_started: Signal emitted when embedded tool starts.
        embedded_tool_closed: Signal emitted when embedded tool closes.
    """

    address_clicked: pyqtSignal = pyqtSignal(int)
    embedded_tool_started: pyqtSignal = pyqtSignal(str)
    embedded_tool_closed: pyqtSignal = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the tool output panel.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tabs: dict[str, ToolTab] = {}
        self._embedded_tools: dict[str, QWidget] = {}
        self._panels: dict[str, QWidget] = {}
        self._setup_ui()
        self._setup_embedded_tabs()

    def _setup_ui(self) -> None:
        """Set up the tool output panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setFixedHeight(40)
        header.setObjectName("panel_header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        title = QLabel("Analysis Output")
        title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title.setObjectName("panel_title")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self._address_label = QLabel()
        self._address_label.setFont(QFont("JetBrains Mono", 10))
        self._address_label.setObjectName("code_label")
        header_layout.addWidget(self._address_label)

        layout.addWidget(header)

        self._main_splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        self._tab_widget = QTabWidget()
        self._tab_widget.setObjectName("analysis_tabs")

        ghidra_tab = ToolTab("Ghidra", "c")
        self._tabs["ghidra"] = ghidra_tab
        self._tab_widget.addTab(ghidra_tab, "Ghidra")

        frida_tab = ToolTab("Frida", "javascript")
        self._tabs["frida"] = frida_tab
        self._tab_widget.addTab(frida_tab, "Frida")

        r2_tab = ToolTab("radare2", "asm")
        self._tabs["radare2"] = r2_tab
        self._tab_widget.addTab(r2_tab, "radare2")

        x64dbg_tab = ToolTab("x64dbg", "asm")
        self._tabs["x64dbg"] = x64dbg_tab
        self._tab_widget.addTab(x64dbg_tab, "x64dbg")

        log_tab = ToolTab("Log", "python")
        self._tabs["log"] = log_tab
        self._tab_widget.addTab(log_tab, "Log")

        left_layout.addWidget(self._tab_widget)
        self._main_splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_panel.setMaximumWidth(250)
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
        self._main_splitter.setSizes([600, 200])

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

        Args:
            message: Message to log.
        """
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
        self._licensing_panel: LicensingAnalysisPanel | None = None
        self._script_panel: QWidget | None = None
        self._stack_panel: QWidget | None = None
        self._hxd_widget: HxDWidgetProtocol | None = None
        self._x64dbg_widget: X64DbgWidgetProtocol | None = None
        self._cutter_widget: CutterWidgetProtocol | None = None
        self._ghidra_widget: GhidraWidgetProtocol | None = None
        self._radare2_widget: Radare2WidgetProtocol | None = None
        self._frida_panel: FridaPanelProtocol | None = None
        self._process_panel: ProcessPanelProtocol | None = None
        self._binary_panel: BinaryPanelProtocol | None = None
        self._sandbox_panel: SandboxPanelProtocol | None = None

    def add_licensing_panel(self) -> LicensingAnalysisPanel:
        """Add the licensing analysis panel as a tab.

        Returns:
            The created LicensingAnalysisPanel widget.
        """
        if self._licensing_panel is not None:
            return self._licensing_panel

        panel_module = importlib.import_module(".panels.licensing_panel", "intellicrack.ui")
        panel = cast("LicensingAnalysisPanel", panel_module.LicensingAnalysisPanel())
        self._licensing_panel = panel
        self._tab_widget.addTab(panel, "Licensing")
        self._panels["licensing"] = panel
        _logger.info("licensing_panel_added")
        return panel

    def add_script_panel(self) -> QWidget:
        """Add the script manager panel as a tab.

        Returns:
            The created ScriptManagerPanel widget.
        """
        if self._script_panel is not None:
            return self._script_panel

        panel_module = importlib.import_module(".panels.script_manager", "intellicrack.ui")
        panel = cast("QWidget", panel_module.ScriptManagerPanel())
        self._script_panel = panel
        self._tab_widget.addTab(panel, "Scripts")
        self._panels["scripts"] = panel
        _logger.info("script_panel_added")
        return panel

    def add_stack_panel(self) -> QWidget:
        """Add the stack viewer panel as a tab.

        Returns:
            The created StackViewerPanel widget.
        """
        if self._stack_panel is not None:
            return self._stack_panel

        panel_module = importlib.import_module(".panels.stack_viewer", "intellicrack.ui")
        panel = cast("QWidget", panel_module.StackViewerPanel())
        self._stack_panel = panel
        self._tab_widget.addTab(panel, "Stack")
        self._panels["stack"] = panel
        _logger.info("stack_panel_added")
        return panel

    def add_hxd_tab(self) -> HxDWidgetProtocol | None:
        """Add the HxD hex editor as an embedded tab.

        Returns:
            The created HxDWidget or None if creation failed.
        """
        if self._hxd_widget is not None:
            return self._hxd_widget

        try:
            widget_module = importlib.import_module(".embedding.hxd_widget", "intellicrack.ui")
            raw_widget = widget_module.HxDWidget()
            self._hxd_widget = cast("HxDWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._hxd_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("hxd"))
            self._hxd_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("hxd"))
            self._tab_widget.addTab(qwidget, "HxD")
            self._embedded_tools["hxd"] = qwidget
            _logger.info("hxd_tab_added")
        except Exception as e:
            _logger.warning("hxd_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._hxd_widget

    def add_x64dbg_tab(self, is_64bit: bool = True) -> X64DbgWidgetProtocol | None:
        """Add the x64dbg/x32dbg debugger as an embedded tab.

        Args:
            is_64bit: Whether to use x64dbg (True) or x32dbg (False).

        Returns:
            The created X64DbgWidget or None if creation failed.
        """
        if self._x64dbg_widget is not None:
            return self._x64dbg_widget

        try:
            widget_module = importlib.import_module(".embedding.x64dbg_widget", "intellicrack.ui")
            raw_widget = widget_module.X64DbgWidget(use_64bit=is_64bit)
            self._x64dbg_widget = cast("X64DbgWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._x64dbg_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("x64dbg"))
            self._x64dbg_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("x64dbg"))
            tab_name = "x64dbg" if is_64bit else "x32dbg"
            self._tab_widget.addTab(qwidget, tab_name)
            self._embedded_tools["x64dbg"] = qwidget
            _logger.info("x64dbg_tab_added", extra={"is_64bit": is_64bit})
        except Exception as e:
            _logger.warning("x64dbg_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._x64dbg_widget

    def add_cutter_tab(self) -> CutterWidgetProtocol | None:
        """Add the Cutter reverse engineering tool as an embedded tab.

        Returns:
            The created CutterWidget or None if creation failed.
        """
        if self._cutter_widget is not None:
            return self._cutter_widget

        try:
            widget_module = importlib.import_module(".embedding.cutter_widget", "intellicrack.ui")
            raw_widget = widget_module.CutterWidget()
            self._cutter_widget = cast("CutterWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._cutter_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("cutter"))
            self._cutter_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("cutter"))
            self._tab_widget.addTab(qwidget, "Cutter")
            self._embedded_tools["cutter"] = qwidget
            _logger.info("cutter_tab_added")
        except Exception as e:
            _logger.warning("cutter_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._cutter_widget

    def add_ghidra_tab(self) -> GhidraWidgetProtocol | None:
        """Add the Ghidra reverse engineering tool as an embedded tab.

        Returns:
            The created GhidraWidget or None if creation failed.
        """
        if self._ghidra_widget is not None:
            return self._ghidra_widget

        try:
            widget_module = importlib.import_module(".embedding.ghidra_widget", "intellicrack.ui")
            raw_widget = widget_module.GhidraWidget()
            self._ghidra_widget = cast("GhidraWidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._ghidra_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("ghidra"))
            self._ghidra_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("ghidra"))
            self._tab_widget.addTab(qwidget, "Ghidra (Embed)")
            self._embedded_tools["ghidra"] = qwidget
            _logger.info("ghidra_tab_added")
        except Exception as e:
            _logger.warning("ghidra_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._ghidra_widget

    def add_radare2_tab(self) -> Radare2WidgetProtocol | None:
        """Add the radare2/iaito GUI as an embedded tab.

        Returns:
            The created Radare2Widget or None if creation failed.
        """
        if self._radare2_widget is not None:
            return self._radare2_widget

        try:
            widget_module = importlib.import_module(".embedding.radare2_widget", "intellicrack.ui")
            raw_widget = widget_module.Radare2Widget()
            self._radare2_widget = cast("Radare2WidgetProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._radare2_widget.tool_started.connect(lambda: self.embedded_tool_started.emit("radare2"))
            self._radare2_widget.tool_closed.connect(lambda: self.embedded_tool_closed.emit("radare2"))
            self._tab_widget.addTab(qwidget, "radare2")
            self._embedded_tools["radare2_gui"] = qwidget
            _logger.info("radare2_tab_added")
        except Exception as e:
            _logger.warning("radare2_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._radare2_widget

    def add_frida_tab(self) -> FridaPanelProtocol | None:
        """Add the Frida instrumentation panel as a tab.

        Returns:
            The created FridaPanel or None if creation failed.
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
            _logger.info("frida_tab_added")
        except Exception as e:
            _logger.warning("frida_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._frida_panel

    def add_process_tab(self) -> ProcessPanelProtocol | None:
        """Add the process management panel as a tab.

        Returns:
            The created ProcessPanel or None if creation failed.
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
            _logger.info("process_tab_added")
        except Exception as e:
            _logger.warning("process_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._process_panel

    def add_binary_tab(self) -> BinaryPanelProtocol | None:
        """Add the binary hex viewer and patching panel as a tab.

        Returns:
            The created BinaryPanel or None if creation failed.
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
            _logger.info("binary_tab_added")
        except Exception as e:
            _logger.warning("binary_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._binary_panel

    def add_sandbox_tab(self) -> SandboxPanelProtocol | None:
        """Add the sandbox management panel as a tab.

        Returns:
            The created SandboxPanel or None if creation failed.
        """
        if self._sandbox_panel is not None:
            return self._sandbox_panel

        try:
            panel_module = importlib.import_module(".panels.sandbox_panel", "intellicrack.ui")
            raw_widget = panel_module.SandboxPanel()
            self._sandbox_panel = cast("SandboxPanelProtocol", raw_widget)
            qwidget = cast("QWidget", raw_widget)
            self._sandbox_panel.tool_started.connect(lambda: self.embedded_tool_started.emit("sandbox"))
            self._sandbox_panel.tool_closed.connect(lambda: self.embedded_tool_closed.emit("sandbox"))
            self._tab_widget.addTab(qwidget, "Sandbox")
            self._panels["sandbox"] = qwidget
            _logger.info("sandbox_tab_added")
        except Exception as e:
            _logger.warning("sandbox_tab_add_failed", extra={"error": str(e)})
            return None
        else:
            return self._sandbox_panel

    def open_in_ghidra(self, file_path: Path | str) -> bool:
        """Open a file in the embedded Ghidra tool.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            True if the file was opened successfully.
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

    def open_in_radare2(self, file_path: Path | str) -> bool:
        """Open a file in the embedded radare2/iaito tool.

        Args:
            file_path: Path to the binary to analyze.

        Returns:
            True if the file was opened successfully.
        """
        if self._radare2_widget is None:
            widget = self.add_radare2_tab()
            if widget is None:
                return False

        if self._radare2_widget is None:
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path
        success = self._radare2_widget.analyze_binary(path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._radare2_widget))
        return success

    def open_in_binary(self, file_path: Path | str) -> bool:
        """Open a file in the binary hex viewer panel.

        Args:
            file_path: Path to the binary file.

        Returns:
            True if the file was opened successfully.
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

    def open_in_hxd(self, file_path: Path | str) -> bool:
        """Open a file in the embedded HxD hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            True if the file was opened successfully.
        """
        if self._hxd_widget is None:
            widget = self.add_hxd_tab()
            if widget is None:
                return False

        if self._hxd_widget is None:
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path
        success = self._hxd_widget.load_file(path)
        if success:
            self._activate_tab_by_widget(cast("QWidget", self._hxd_widget))
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
            True if the file was opened successfully.
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
            True if the file was opened successfully.
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
            The embedded tool widget or None if not available.
        """
        return self._embedded_tools.get(tool_id.lower())

    def get_panel(self, panel_id: OutputType) -> QWidget | None:
        """Get a panel widget by ID.

        Args:
            panel_id: The panel identifier.

        Returns:
            The panel widget or None if not available.
        """
        return self._panels.get(panel_id.lower())

    def update_licensing_analysis(self, analysis: LicensingAnalysis) -> None:
        """Update the licensing panel with new analysis data.

        Args:
            analysis: The licensing analysis data to display.
        """
        if self._licensing_panel is None:
            self.add_licensing_panel()

        if self._licensing_panel is not None:
            self._licensing_panel.set_analysis(analysis)
            _logger.info("licensing_analysis_updated")

    def activate_licensing_tab(self) -> None:
        """Activate the licensing analysis tab."""
        if self._licensing_panel is None:
            self.add_licensing_panel()
        if self._licensing_panel is not None:
            self._activate_tab_by_widget(self._licensing_panel)

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

    def close_embedded_tools(self) -> None:
        """Close all embedded tool instances."""
        if self._hxd_widget is not None:
            self._hxd_widget.stop_tool()

        if self._x64dbg_widget is not None:
            self._x64dbg_widget.stop_tool()

        if self._cutter_widget is not None:
            self._cutter_widget.stop_tool()

        if self._ghidra_widget is not None:
            self._ghidra_widget.stop_tool()

        if self._radare2_widget is not None:
            self._radare2_widget.stop_tool()

        if self._frida_panel is not None:
            self._frida_panel.stop_tool()

        if self._process_panel is not None:
            self._process_panel.stop_tool()

        if self._binary_panel is not None:
            self._binary_panel.stop_tool()

        if self._sandbox_panel is not None:
            self._sandbox_panel.stop_tool()

        _logger.info("embedded_tools_closed")
