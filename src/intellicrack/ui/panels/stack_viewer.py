# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Unified stack viewer panel for debugging.

Provides a Qt-based stack frame viewer that reads from both X64DbgBridge and FridaBridge for synchronized debugging views.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any, Final, Protocol, cast, runtime_checkable

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.font_manager import FontManager
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger("ui.panels.stack_viewer")

_PANEL_MARGIN: Final[int] = 8
_PANEL_SPACING: Final[int] = 8
_TOOLBAR_MARGIN: Final[int] = 0
_INFO_MARGIN: Final[int] = 4
_SOURCE_COMBO_MIN_WIDTH: Final[int] = 120


def _get_stack_colors() -> dict[str, QColor]:
    """
    Get theme-aware colors for stack frame rendering.

    Returns:
        dict[str, QColor]: Mapping of semantic names to QColor values.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return {
            "index_highlight": QColor("#4ec9b0"),
            "address": QColor("#569cd6"),
            "function_known": QColor("#dcdcaa"),
            "function_unknown": QColor("#888888"),
            "module": QColor("#4ec9b0"),
            "offset": QColor("#b5cea8"),
            "pointer": QColor("#ce9178"),
            "muted": QColor("#888888"),
            "error": QColor("#f14c4c"),
            "connected": QColor("#4ec9b0"),
        }
    return {
        "index_highlight": QColor("#0078d4"),
        "address": QColor("#0451a5"),
        "function_known": QColor("#795e26"),
        "function_unknown": QColor("#757575"),
        "module": QColor("#0078d4"),
        "offset": QColor("#098658"),
        "pointer": QColor("#a31515"),
        "muted": QColor("#757575"),
        "error": QColor("#c62828"),
        "connected": QColor("#2e7d32"),
    }


@dataclass
class StackFrame:
    """
    Represents a single stack frame entry.

    Attributes:
        index: Position in the call stack.
        return_address: Return address for this frame.
        function_name: Name of the function at this frame.
        module_name: Name of the module containing the function.
        offset: Offset within the function.
        frame_pointer: Frame pointer value if available.
        stack_pointer: Stack pointer value if available.
    """

    index: int
    return_address: int
    function_name: str
    module_name: str
    offset: int = 0
    frame_pointer: int = 0
    stack_pointer: int = 0


@runtime_checkable
class StackDataSource(Protocol):
    """
    Protocol for stack frame data sources.

    Implementations should provide methods to retrieve current stack frames from debugging sessions.
    """

    @staticmethod
    def get_stack_frames() -> list[StackFrame]:
        """
        Get current stack frames from the data source.

        Returns:
            list[StackFrame]: List of StackFrame objects representing the call stack.
        """
        return []

    @staticmethod
    def is_connected() -> bool:
        """
        Check if the data source is connected.

        Returns:
            bool: True if connected and can provide stack data.
        """
        return False

    @staticmethod
    def get_source_name() -> str:
        """
        Get the name of this data source.

        Returns:
            str: Human-readable source name.
        """
        return "Unknown"


class X64DbgStackSource:
    """
    Stack data source backed by X64DbgBridge.

    Retrieves stack frames from an active x64dbg debugging session using the bridge interface.
    """

    def __init__(self) -> None:
        self._bridge: object | None = None

    def set_bridge(self, bridge: object) -> None:
        """
        Set the X64DbgBridge instance.

        Args:
            bridge: The X64DbgBridge to use for stack data.
        """
        self._bridge = bridge

    def get_stack_frames(self) -> list[StackFrame]:
        """
        Get stack frames from x64dbg.

        Returns:
            list[StackFrame]: List of StackFrame objects.
        """
        if not self._bridge:
            return []

        try:
            empty_trace: list[dict[str, Any]] = []
            raw_frames: list[dict[str, Any]] = getattr(self._bridge, "get_stack_trace", lambda: empty_trace)()
            frames: list[StackFrame] = []
            for i, raw in enumerate(raw_frames):
                frame = StackFrame(
                    index=i,
                    return_address=raw.get("return_address", 0),
                    function_name=raw.get("function", "unknown"),
                    module_name=raw.get("module", "unknown"),
                    offset=raw.get("offset", 0),
                    frame_pointer=raw.get("frame_pointer", 0),
                    stack_pointer=raw.get("stack_pointer", 0),
                )
                frames.append(frame)
        except (RuntimeError, ConnectionError, OSError):
            _logger.exception("x64dbg_stack_frames_failed", bridge_type="x64dbg")
            return []
        else:
            return frames

    def is_connected(self) -> bool:
        """
        Check if x64dbg bridge is connected.

        Returns:
            bool: True if bridge is attached and connected.
        """
        if not self._bridge:
            return False
        try:
            return getattr(self._bridge, "is_connected", lambda: False)()
        except (RuntimeError, ConnectionError, OSError):
            _logger.debug("x64dbg_connection_check_failed", exc_info=True)
            return False

    @staticmethod
    def get_source_name() -> str:
        """
        Get the source name.

        Returns:
            str: 'x64dbg' string.
        """
        return "x64dbg"


class FridaStackSource:
    """
    Stack data source backed by FridaBridge.

    Retrieves stack frames from an active Frida instrumentation session using the bridge interface.
    """

    def __init__(self) -> None:
        self._bridge: object | None = None
        self._cached_frames: list[StackFrame] = []

    def set_bridge(self, bridge: object) -> None:
        """
        Set the FridaBridge instance.

        Args:
            bridge: The FridaBridge to use for stack data.
        """
        self._bridge = bridge

    def get_stack_frames(self) -> list[StackFrame]:
        """
        Get stack frames from Frida.

        Returns:
            list[StackFrame]: List of StackFrame objects.
        """
        if not self._bridge:
            return self._cached_frames

        try:
            empty_bt: list[Any] = []
            raw_frames: list[Any] = getattr(self._bridge, "get_backtrace", lambda: empty_bt)()
            frames: list[StackFrame] = []
            for i, raw in enumerate(raw_frames):
                if isinstance(raw, dict):
                    raw_dict: dict[str, Any] = cast("dict[str, Any]", raw)
                    frame = StackFrame(
                        index=i,
                        return_address=raw_dict.get("address", 0),
                        function_name=raw_dict.get("name", "unknown"),
                        module_name=raw_dict.get("moduleName", "unknown"),
                        offset=raw_dict.get("offset", 0),
                    )
                else:
                    frame = StackFrame(
                        index=i,
                        return_address=getattr(raw, "address", 0),
                        function_name=getattr(raw, "name", "unknown"),
                        module_name=getattr(raw, "moduleName", "unknown"),
                    )
                frames.append(frame)
            self._cached_frames = frames
        except (RuntimeError, ConnectionError, OSError):
            _logger.exception("frida_stack_frames_failed", bridge_type="frida")
            return self._cached_frames
        else:
            return frames

    def is_connected(self) -> bool:
        """
        Check if Frida bridge is connected.

        Returns:
            bool: True if bridge is attached and session is active.
        """
        if not self._bridge:
            return False
        try:
            return getattr(self._bridge, "is_attached", lambda: False)()
        except (RuntimeError, ConnectionError, OSError):
            _logger.debug("frida_connection_check_failed", exc_info=True)
            return False

    @staticmethod
    def get_source_name() -> str:
        """
        Get the source name.

        Returns:
            str: 'Frida' string.
        """
        return "Frida"


class StackFrameTable(QTableWidget):
    """
    Table widget for displaying stack frames.

    Args:
        parent: Parent widget.

    Attributes:
        frame_clicked: Qt signal for frame clicked.
        frame_double_clicked: Qt signal for frame double clicked.
    """

    frame_clicked = pyqtSignal(int)
    frame_double_clicked = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent=parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the table UI."""
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(["#", "Return Address", "Function", "Module", "Offset", "FP", "SP"])

        if header := self.horizontalHeader():
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(enable=True)
        sv_v_header = self.verticalHeader()
        if sv_v_header is not None:
            sv_v_header.setVisible(v=False)
        self.setShowGrid(show=False)

        self.cellClicked.connect(self._on_cell_clicked)
        self.cellDoubleClicked.connect(self._on_cell_double_clicked)

    def _on_cell_clicked(self, row: int, _column: int) -> None:
        """
        Handle cell click.

        Args:
            row: Row index.
            _column: Column index (unused).
        """
        if addr_item := self.item(row, 1):
            try:
                address = int(addr_item.text(), 16)
                self.frame_clicked.emit(address)
            except ValueError:
                _logger.debug("stack_frame_address_parse_failed")

    def _on_cell_double_clicked(self, row: int, _column: int) -> None:
        """
        Handle cell double-click.

        Args:
            row: Row index.
            _column: Column index (unused).
        """
        if addr_item := self.item(row, 1):
            try:
                address = int(addr_item.text(), 16)
                self.frame_double_clicked.emit(address)
            except ValueError:
                _logger.debug("stack_frame_address_parse_failed")

    def set_frames(self, frames: list[StackFrame]) -> None:
        """
        Populate the table with stack frames.

        Args:
            frames: List of StackFrame objects.
        """
        self.setRowCount(len(frames))

        fm = FontManager.get_instance()
        mono_font = fm.get_code_font(9)
        mono_font_bold = fm.get_code_font_bold(9)
        colors = _get_stack_colors()

        for row, frame in enumerate(frames):
            index_item = QTableWidgetItem(str(frame.index))
            index_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if frame.index == 0:
                index_item.setForeground(colors["index_highlight"])
                index_item.setFont(mono_font_bold)
            self.setItem(row, 0, index_item)

            addr_item = QTableWidgetItem(f"0x{frame.return_address:016X}")
            addr_item.setFont(mono_font)
            addr_item.setForeground(colors["address"])
            self.setItem(row, 1, addr_item)

            func_item = QTableWidgetItem(frame.function_name)
            if frame.function_name != "unknown":
                func_item.setForeground(colors["function_known"])
            else:
                func_item.setForeground(colors["function_unknown"])
            self.setItem(row, 2, func_item)

            mod_item = QTableWidgetItem(frame.module_name)
            mod_item.setForeground(colors["module"])
            self.setItem(row, 3, mod_item)

            offset_text = f"+0x{frame.offset:X}" if frame.offset > 0 else ""
            offset_item = QTableWidgetItem(offset_text)
            offset_item.setFont(mono_font)
            offset_item.setForeground(colors["offset"])
            self.setItem(row, 4, offset_item)

            fp_text = f"0x{frame.frame_pointer:016X}" if frame.frame_pointer else ""
            fp_item = QTableWidgetItem(fp_text)
            fp_item.setFont(mono_font)
            fp_item.setForeground(colors["pointer"])
            self.setItem(row, 5, fp_item)

            sp_text = f"0x{frame.stack_pointer:016X}" if frame.stack_pointer else ""
            sp_item = QTableWidgetItem(sp_text)
            sp_item.setFont(mono_font)
            sp_item.setForeground(colors["pointer"])
            self.setItem(row, 6, sp_item)


class StackViewerPanel(QWidget):
    """
    Unified stack viewer panel for debugging sessions.

    Displays call stack frames from x64dbg or Frida sources
    with auto-refresh during debugging.

    Args:
        parent: Parent widget.

    Attributes:
        address_navigate: Qt signal for address navigate.
    """

    address_navigate = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sources: dict[str, X64DbgStackSource | FridaStackSource] = {}
        self._active_source: str | None = None
        self.refresh_timer: QTimer | None = None
        self._setup_ui()
        self._setup_default_sources()

    def _setup_ui(self) -> None:
        """Set up the panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(_PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN, _PANEL_MARGIN)
        layout.setSpacing(_PANEL_SPACING)

        toolbar = QFrame()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(_TOOLBAR_MARGIN, _TOOLBAR_MARGIN, _TOOLBAR_MARGIN, _TOOLBAR_MARGIN)
        toolbar_layout.setSpacing(_PANEL_SPACING)

        source_label = QLabel(self.tr("Source:"))
        toolbar_layout.addWidget(source_label)

        self._source_combo = QComboBox()
        self._source_combo.setMinimumWidth(_SOURCE_COMBO_MIN_WIDTH)
        self._source_combo.currentTextChanged.connect(self._on_source_changed)
        toolbar_layout.addWidget(self._source_combo)

        self.status_label = QLabel(self.tr("Not connected"))
        self.status_label.setProperty("status", "idle")
        toolbar_layout.addWidget(self.status_label)

        toolbar_layout.addStretch()

        self._refresh_btn = QPushButton(self.tr("Refresh"))
        self._refresh_btn.clicked.connect(self.refresh)
        toolbar_layout.addWidget(self._refresh_btn)

        self._auto_refresh_btn = QPushButton(self.tr("Auto"))
        self._auto_refresh_btn.setCheckable(True)

        def _auto_refresh_slot(c: int) -> None:
            self._on_auto_refresh_toggled(checked=bool(c))

        self._auto_refresh_btn.toggled.connect(_auto_refresh_slot)
        toolbar_layout.addWidget(self._auto_refresh_btn)

        layout.addWidget(toolbar)

        self._frame_table = StackFrameTable()
        self._frame_table.frame_clicked.connect(self.address_navigate.emit)
        self._frame_table.frame_double_clicked.connect(self._on_frame_double_clicked)
        layout.addWidget(self._frame_table)

        info_frame = QFrame()
        info_layout = QHBoxLayout(info_frame)
        info_layout.setContentsMargins(_INFO_MARGIN, _INFO_MARGIN, _INFO_MARGIN, _INFO_MARGIN)

        self._frame_count_label = QLabel(self.tr("0 frames"))
        self._frame_count_label.setObjectName("search_status_label")
        info_layout.addWidget(self._frame_count_label)

        info_layout.addStretch()

        self._last_update_label = QLabel("")
        self._last_update_label.setObjectName("search_status_label")
        info_layout.addWidget(self._last_update_label)

        layout.addWidget(info_frame)

    def _setup_default_sources(self) -> None:
        """Set up default stack data sources."""
        self._sources["x64dbg"] = X64DbgStackSource()
        self._sources["Frida"] = FridaStackSource()

        self._source_combo.addItems(list(self._sources.keys()))
        if self._sources:
            self._active_source = next(iter(self._sources.keys()))

    def _on_source_changed(self, source_name: str) -> None:
        """
        Handle source selection change.

        Args:
            source_name: Name of the selected source.
        """
        _logger.debug("stack_source_changed", source=source_name)
        self._active_source = source_name
        self._update_status()
        self.refresh()

    def _on_auto_refresh_toggled(self, *, checked: bool) -> None:
        """
        Handle auto-refresh toggle.

        Args:
            checked: Whether auto-refresh is enabled.
        """
        if checked:
            if not self.refresh_timer:
                self.refresh_timer = QTimer(self)
                self.refresh_timer.timeout.connect(self.refresh)
            self.refresh_timer.start(500)
        elif self.refresh_timer:
            self.refresh_timer.stop()

    def _on_frame_double_clicked(self, address: int) -> None:
        """
        Handle frame double-click for navigation.

        Args:
            address: Address to navigate to.
        """
        self.address_navigate.emit(address)
        _logger.info("stack_frame_navigate", address=hex(address))

    def _update_status(self) -> None:
        """Update connection status display."""
        if not self._active_source:
            self.status_label.setText(self.tr("No source selected"))
            self.status_label.setProperty("status", "idle")
            self._restyle_status_label()
            return

        source = self._sources.get(self._active_source)
        if not source:
            self.status_label.setText(self.tr("Source not found"))
            self.status_label.setProperty("status", "error")
            self._restyle_status_label()
            return

        if source.is_connected():
            self.status_label.setText(self.tr("Connected"))
            self.status_label.setProperty("status", "success")
        else:
            self.status_label.setText(self.tr("Not connected"))
            self.status_label.setProperty("status", "idle")
        self._restyle_status_label()

    def _restyle_status_label(self) -> None:
        """Force the status label to re-evaluate QSS after property change."""
        style = self.status_label.style()
        if style is not None:
            style.unpolish(self.status_label)
            style.polish(self.status_label)

    def refresh(self) -> None:
        """Refresh the stack frames from the active source."""
        if not self._active_source:
            return

        source = self._sources.get(self._active_source)
        if not source:
            return

        self._update_status()

        frames = source.get_stack_frames()
        self._frame_table.set_frames(frames)
        _logger.debug("stack_frames_refreshed", source=self._active_source, frame_count=len(frames))

        self._frame_count_label.setText(f"{len(frames)} frames")

        now = datetime.datetime.now(tz=datetime.UTC)
        self._last_update_label.setText(f"Updated: {now.strftime('%H:%M:%S')}")

    def set_x64dbg_bridge(self, bridge: object) -> None:
        """
        Set the x64dbg bridge for stack retrieval.

        Args:
            bridge: The X64DbgBridge instance.
        """
        source = self._sources.get("x64dbg")
        if isinstance(source, X64DbgStackSource):
            source.set_bridge(bridge)
            _logger.info("bridge_attached", source="x64dbg", component="stack_viewer")

    def set_frida_bridge(self, bridge: object) -> None:
        """
        Set the Frida bridge for stack retrieval.

        Args:
            bridge: The FridaBridge instance.
        """
        source = self._sources.get("Frida")
        if isinstance(source, FridaStackSource):
            source.set_bridge(bridge)
            _logger.info("bridge_attached", source="frida", component="stack_viewer")

    def add_source(self, name: str, source: X64DbgStackSource | FridaStackSource) -> None:
        """
        Add a custom stack data source.

        Args:
            name: Display name for the source.
            source: The stack data source instance.
        """
        self._sources[name] = source
        if name not in [self._source_combo.itemText(i) for i in range(self._source_combo.count())]:
            self._source_combo.addItem(name)

    def clear(self) -> None:
        """Clear the stack frame display."""
        self._frame_table.setRowCount(0)
        self._frame_count_label.setText("0 frames")
        self._last_update_label.setText("")
