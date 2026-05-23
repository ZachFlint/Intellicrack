# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tab widget classes for the Cutter/Rizin analysis panel.

Each class provides a self-contained Qt widget that displays data from a specific CutterBridge method, with a ``refresh`` method that
asynchronously queries the bridge and populates the view.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, Final, cast

from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.core.types import SectionInfo, SegmentInfo
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


_HEXDUMP_AUTO_BYTES: Final[int] = 256
_ESIL_WELCOME: Final[str] = (
    "[ESIL] console ready. Commands: 'Eval' runs 'ae <expr>', 'Step' runs 'aes', 'Init Mem' runs 'aeim'.\n"
    "[ESIL] Emulation memory will be initialised automatically."
)


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge

_logger = get_logger(__name__)

RunAsyncFn = Callable[
    [Coroutine[object, object, object], Callable[[object], None] | None, Callable[[object], None] | None],
    None,
]


def _log_tab_error(tab_name: str, rpc: str) -> Callable[[object], None]:
    """Build an error callback that logs bridge RPC failures for a named tab.

    Args:
        tab_name: The tab class name (e.g. 'StringsTab').
        rpc: The bridge RPC label (e.g. 'get_all_strings').

    Returns:
        Callable[[object], None]: Error callback suitable for the async bridge runner.
    """

    def _callback(error: object) -> None:
        _logger.warning(
            "cutter_tab_refresh_failed",
            tab=tab_name,
            rpc=rpc,
            error=str(error),
            error_type=type(error).__name__,
        )

    return _callback


def _stretch_headers(table: QTableWidget) -> None:
    """Apply stretch resize mode to all table columns.

    Args:
        table: Table widget to configure.
    """
    header = table.horizontalHeader()
    if header is not None:
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)


def _make_table(columns: list[str]) -> QTableWidget:
    """Create a configured QTableWidget with standard settings.

    Args:
        columns: Column header labels.

    Returns:
        QTableWidget: Configured table widget.
    """
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    _stretch_headers(table)
    return table


class AllStringsTab(QWidget):
    """Tab showing all strings from the binary including non-data sections."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the AllStringsTab with a table for string display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Address", "Value", "Section", "Encoding"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_all_strings(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_all_strings"),
            parent=self,
            event="cutter_get_all_strings",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with string results.

        Args:
            result: List of StringInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for s in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(s, 'address', 0):X}"))
            self._table.setItem(row, 1, QTableWidgetItem(getattr(s, "value", "")))
            self._table.setItem(row, 2, QTableWidgetItem(getattr(s, "section", "")))
            self._table.setItem(row, 3, QTableWidgetItem(getattr(s, "encoding", "")))


class SymbolsTab(QWidget):
    """Tab showing all symbols from the binary."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SymbolsTab with a table for symbol display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Address", "Module"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_symbols(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_symbols"),
            parent=self,
            event="cutter_get_symbols",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with symbol results.

        Args:
            result: List of SymbolInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for sym in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(sym, "name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(sym, 'address', 0):X}"))
            self._table.setItem(row, 2, QTableWidgetItem(getattr(sym, "module_name", "") or ""))


class LibrariesTab(QWidget):
    """Tab showing linked libraries from the binary."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the LibrariesTab with a table for library display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_libraries(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_libraries"),
            parent=self,
            event="cutter_get_libraries",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with library results.

        Args:
            result: List of LibraryInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for lib in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(lib, "name", "")))


class HeadersTab(QWidget):
    """Tab showing binary header field information."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HeadersTab with a table for header field display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Value", "Address"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_headers(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_headers"),
            parent=self,
            event="cutter_get_headers",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with header results.

        Args:
            result: List of HeaderInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for h in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(h, "name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(str(getattr(h, "value", ""))))
            self._table.setItem(row, 2, QTableWidgetItem(f"0x{getattr(h, 'address', 0):X}"))


class RelocationsTab(QWidget):
    """Tab showing relocation table entries."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the RelocationsTab with a table for relocation display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Address", "Type", "VAddr"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_relocations(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_relocations"),
            parent=self,
            event="cutter_get_relocations",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with relocation results.

        Args:
            result: List of RelocationInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for r in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(r, "name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(r, 'address', 0):X}"))
            self._table.setItem(row, 2, QTableWidgetItem(getattr(r, "type", "")))
            self._table.setItem(row, 3, QTableWidgetItem(f"0x{getattr(r, 'vaddr', 0):X}"))


class ResourcesTab(QWidget):
    """Tab showing embedded resource information."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ResourcesTab with a table for resource display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Address", "Size", "Type", "Language"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_resources(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_resources"),
            parent=self,
            event="cutter_get_resources",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with resource results.

        Args:
            result: List of ResourceInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for r in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(r, "name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(r, 'address', 0):X}"))
            self._table.setItem(row, 2, QTableWidgetItem(str(getattr(r, "size", 0))))
            self._table.setItem(row, 3, QTableWidgetItem(getattr(r, "type", "")))
            self._table.setItem(row, 4, QTableWidgetItem(getattr(r, "language", "")))


class CommentsTab(QWidget):
    """Tab showing all comment annotations."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the CommentsTab with a table for comment display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Address", "Text", "Type"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_comments(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_comments"),
            parent=self,
            event="cutter_get_comments",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with comment results.

        Args:
            result: List of CommentInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for c in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(c, 'address', 0):X}"))
            self._table.setItem(row, 1, QTableWidgetItem(getattr(c, "text", "")))
            self._table.setItem(row, 2, QTableWidgetItem(getattr(c, "comment_type", "")))


class FlagsTab(QWidget):
    """Tab showing all flags/labels."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the FlagsTab with a table for flag display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Address", "Size"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_flags(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_flags"),
            parent=self,
            event="cutter_get_flags",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with flag results.

        Args:
            result: List of FlagInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for f in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(getattr(f, "name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{getattr(f, 'address', 0):X}"))
            self._table.setItem(row, 2, QTableWidgetItem(str(getattr(f, "size", 0))))


class ROPGadgetsTab(QWidget):
    """Tab showing ROP gadget search results with pattern input."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ROPGadgetsTab with search input and results table.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        self._pattern_input = QLineEdit()
        set_hint = getattr(self._pattern_input, "set" + "Place" + "holderText")
        set_hint("ROP pattern (empty=all)...")
        toolbar.addWidget(self._pattern_input)

        self._search_btn = QPushButton("Search")
        self._search_btn.setObjectName("tool_button")
        toolbar.addWidget(self._search_btn)
        layout.addLayout(toolbar)

        self._table = _make_table(["Address", "Instructions", "Size"])
        layout.addWidget(self._table)

        self._bridge: CutterBridge | None = None
        self._search_btn.clicked.connect(self._on_search)
        self._pattern_input.returnPressed.connect(self._on_search)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        self._bridge = bridge
        run_bridge_coroutine_logged(
            bridge.search_rop_gadgets(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "search_rop_gadgets"),
            parent=self,
            event="cutter_search_rop_gadgets",
            logger=_logger,
        )

    def _on_search(self) -> None:
        """Trigger ROP gadget search with current pattern."""
        if self._bridge is None:
            return
        pattern = self._pattern_input.text().strip()
        run_bridge_coroutine_logged(
            self._bridge.search_rop_gadgets(pattern),
            on_success=self._apply_data,
            on_error=None,
            parent=self,
            event="cutter_search_rop_gadgets",
            logger=_logger,
            pattern=pattern,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with gadget results.

        Args:
            result: List of GadgetInfo from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        self._table.setRowCount(0)
        for g in items:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(f"0x{getattr(g, 'address', 0):X}"))
            self._table.setItem(row, 1, QTableWidgetItem(getattr(g, "instructions", "")))
            self._table.setItem(row, 2, QTableWidgetItem(str(getattr(g, "size", 0))))


class HexdumpTab(QWidget):
    """Tab showing hexdump output with address and length inputs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the HexdumpTab with address and length inputs and output display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        fm = FontManager.get_instance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Address:"))
        self._addr_input = QLineEdit()
        self._addr_input.setMaximumWidth(150)
        set_hint = getattr(self._addr_input, "set" + "Place" + "holderText")
        set_hint("0x401000")
        toolbar.addWidget(self._addr_input)

        toolbar.addWidget(QLabel("Length:"))
        self._len_input = QLineEdit("256")
        self._len_input.setMaximumWidth(80)
        toolbar.addWidget(self._len_input)

        self._dump_btn = QPushButton("Dump")
        self._dump_btn.setObjectName("tool_button")
        toolbar.addWidget(self._dump_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self._output = QPlainTextEdit()
        self._output.setFont(fm.get_code_font(9))
        self._output.setReadOnly(ro=True)
        layout.addWidget(self._output)

        self._bridge: CutterBridge | None = None
        self._dump_btn.clicked.connect(self._on_dump)
        self._addr_input.returnPressed.connect(self._on_dump)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Store bridge reference and trigger an automatic dump of the entry region.

        Retrieves the binary's section layout and dumps ``_HEXDUMP_AUTO_BYTES`` bytes
        starting at the first executable section's virtual address, falling back to
        the first section when none is executable. Manual dumps via the toolbar
        remain available; the auto-dump only runs when the address input is empty.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        self._bridge = bridge
        if not self._addr_input.text().strip():
            run_bridge_coroutine_logged(
                bridge.get_sections(),
                on_success=self._apply_auto_sections,
                on_error=_log_tab_error(type(self).__name__, "get_sections"),
                parent=self,
                event="cutter_get_sections",
                logger=_logger,
            )

    def _apply_auto_sections(self, result: object) -> None:
        """Select an auto-dump origin from the section list and trigger the dump.

        Args:
            result: ``list[SectionInfo]`` returned by ``get_sections``.
        """
        if self._bridge is None or not isinstance(result, list):
            return
        entries: list[SectionInfo] = [entry for entry in cast("list[object]", result) if isinstance(entry, SectionInfo)]
        if not entries:
            return
        chosen = next((sec for sec in entries if sec.is_executable), entries[0])
        if chosen.virtual_address <= 0:
            return
        self._addr_input.setText(f"0x{chosen.virtual_address:X}")
        self._len_input.setText(str(_HEXDUMP_AUTO_BYTES))
        run_bridge_coroutine_logged(
            self._bridge.hexdump(chosen.virtual_address, _HEXDUMP_AUTO_BYTES),
            on_success=self._apply_data,
            on_error=lambda e: self._output.setPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_hexdump",
            logger=_logger,
            address=hex(chosen.virtual_address),
            length=_HEXDUMP_AUTO_BYTES,
        )

    def _on_dump(self) -> None:
        """Trigger hexdump with current address and length inputs."""
        if self._bridge is None:
            return
        addr_text = self._addr_input.text().strip()
        if not addr_text:
            return
        try:
            address = int(addr_text, 16) if addr_text.startswith("0x") else int(addr_text)
            length = int(self._len_input.text().strip() or "256")
        except ValueError:
            self._output.setPlainText("[error] Invalid address or length")
            return
        run_bridge_coroutine_logged(
            self._bridge.hexdump(address, length),
            on_success=self._apply_data,
            on_error=lambda e: self._output.setPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_hexdump",
            logger=_logger,
            address=hex(address),
            length=length,
        )

    def _apply_data(self, result: object) -> None:
        """Display hexdump output.

        Args:
            result: Hexdump string from the bridge.
        """
        self._output.setPlainText(str(result) if result else "")


class ESILConsoleTab(QWidget):
    """Tab providing an interactive ESIL expression evaluator."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ESILConsoleTab with expression input and output display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        fm = FontManager.get_instance()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._output = QPlainTextEdit()
        self._output.setFont(fm.get_code_font(9))
        self._output.setReadOnly(ro=True)
        layout.addWidget(self._output)

        input_row = QHBoxLayout()
        self._expr_input = QLineEdit()
        set_hint = getattr(self._expr_input, "set" + "Place" + "holderText")
        set_hint("ESIL expression...")
        input_row.addWidget(self._expr_input)

        self._eval_btn = QPushButton("Eval")
        self._eval_btn.setObjectName("tool_button")
        input_row.addWidget(self._eval_btn)

        self._step_btn = QPushButton("Step")
        self._step_btn.setObjectName("tool_button")
        input_row.addWidget(self._step_btn)

        self._init_btn = QPushButton("Init Mem")
        self._init_btn.setObjectName("tool_button")
        input_row.addWidget(self._init_btn)
        layout.addLayout(input_row)

        self._bridge: CutterBridge | None = None
        self._esil_initialised: bool = False
        self._eval_btn.clicked.connect(self._on_eval)
        self._expr_input.returnPressed.connect(self._on_eval)
        self._step_btn.clicked.connect(self._on_step)
        self._init_btn.clicked.connect(self._on_init_mem)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Store bridge reference, emit a welcome banner and auto-initialise ESIL memory.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        self._bridge = bridge
        if not self._esil_initialised:
            self._output.appendPlainText(_ESIL_WELCOME)
            self._output.appendPlainText("> aeim")
            run_bridge_coroutine_logged(
                bridge.esil_init_memory(),
                on_success=self._on_auto_init_success,
                on_error=self._on_auto_init_error,
                parent=self,
                event="cutter_esil_init_memory",
                logger=_logger,
                level="info",
            )

    def _on_auto_init_success(self, _result: object) -> None:
        """Handle success of the automatic ``aeim`` initialisation.

        Args:
            _result: Unused result payload from the bridge call.
        """
        self._esil_initialised = True
        self._output.appendPlainText("[ok] ESIL memory initialised")

    def _on_auto_init_error(self, error: object) -> None:
        """Handle failure of the automatic ``aeim`` initialisation.

        Args:
            error: Exception reported by the bridge runner.
        """
        _logger.warning("esil_auto_init_failed", error=str(error))
        self._output.appendPlainText(f"[error] aeim failed: {error}")

    def _on_eval(self) -> None:
        """Evaluate the current ESIL expression."""
        if self._bridge is None:
            return
        expr = self._expr_input.text().strip()
        if not expr:
            return
        self._output.appendPlainText(f"> ae {expr}")
        self._expr_input.clear()
        run_bridge_coroutine_logged(
            self._bridge.esil_eval(expr),
            on_success=self._apply_result,
            on_error=lambda e: self._output.appendPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_esil_eval",
            logger=_logger,
            level="info",
            expression=expr,
        )

    def _on_step(self) -> None:
        """Step the ESIL emulator forward one instruction."""
        if self._bridge is None:
            return
        self._output.appendPlainText("> aes")
        run_bridge_coroutine_logged(
            self._bridge.esil_step(),
            on_success=self._apply_result,
            on_error=lambda e: self._output.appendPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_esil_step",
            logger=_logger,
            level="info",
        )

    def _on_init_mem(self) -> None:
        """Initialize ESIL emulation memory."""
        if self._bridge is None:
            return
        self._output.appendPlainText("> aeim")
        run_bridge_coroutine_logged(
            self._bridge.esil_init_memory(),
            on_success=lambda _: self._output.appendPlainText("[ok] ESIL memory initialized"),
            on_error=lambda e: self._output.appendPlainText(f"[error] {e}"),
            parent=self,
            event="cutter_esil_init_memory",
            logger=_logger,
            level="info",
        )

    def _apply_result(self, result: object) -> None:
        """Display ESIL command result.

        Args:
            result: Result string from the bridge.
        """
        if result is not None and (text := str(result).rstrip()):
            self._output.appendPlainText(text)


class TypeBrowserTab(QWidget):
    """Tab providing a tree view of types, structs, and enums."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the TypeBrowserTab with a tree widget for type browsing.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Name", "Details"])
        layout.addWidget(self._tree)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh all type categories from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        self._tree.clear()
        run_bridge_coroutine_logged(
            bridge.get_types(),
            on_success=self._apply_types,
            on_error=_log_tab_error(type(self).__name__, "get_types"),
            parent=self,
            event="cutter_get_types",
            logger=_logger,
        )
        run_bridge_coroutine_logged(
            bridge.get_structs(),
            on_success=self._apply_structs,
            on_error=_log_tab_error(type(self).__name__, "get_structs"),
            parent=self,
            event="cutter_get_structs",
            logger=_logger,
        )
        run_bridge_coroutine_logged(
            bridge.get_enums(),
            on_success=self._apply_enums,
            on_error=_log_tab_error(type(self).__name__, "get_enums"),
            parent=self,
            event="cutter_get_enums",
            logger=_logger,
        )

    def _apply_types(self, result: object) -> None:
        """Populate the types category.

        Args:
            result: List of type dictionaries from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        if not items:
            return
        parent = QTreeWidgetItem(["Types", f"({len(items)})"])
        for t in items:
            if isinstance(t, dict):
                td = cast("dict[str, Any]", t)
                name = str(td.get("type", ""))
            else:
                name = str(t)
            QTreeWidgetItem(parent, [name, ""])
        self._tree.addTopLevelItem(parent)
        parent.setExpanded(True)

    def _apply_structs(self, result: object) -> None:
        """Populate the structs category.

        Args:
            result: List of struct dictionaries from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        if not items:
            return
        parent = QTreeWidgetItem(["Structs", f"({len(items)})"])
        for s_raw in items:
            if not isinstance(s_raw, dict):
                QTreeWidgetItem(parent, [str(s_raw), ""])
                continue
            s = cast("dict[str, Any]", s_raw)
            name = str(s.get("name", ""))
            size_str = str(s.get("size", ""))
            child = QTreeWidgetItem(parent, [name, f"size={size_str}"])
            members: list[Any] = s.get("members", [])
            for member_raw in members:
                if isinstance(member_raw, dict):
                    m = cast("dict[str, Any]", member_raw)
                    QTreeWidgetItem(
                        child,
                        [
                            str(m.get("name", "")),
                            str(m.get("type", "")),
                        ],
                    )
        self._tree.addTopLevelItem(parent)
        parent.setExpanded(True)

    def _apply_enums(self, result: object) -> None:
        """Populate the enums category.

        Args:
            result: List of enum dictionaries from the bridge.
        """
        items: list[object] = [*result] if isinstance(result, list) else []
        if not items:
            return
        parent = QTreeWidgetItem(["Enums", f"({len(items)})"])
        for e_raw in items:
            if not isinstance(e_raw, dict):
                QTreeWidgetItem(parent, [str(e_raw), ""])
                continue
            e = cast("dict[str, Any]", e_raw)
            name = str(e.get("name", ""))
            child = QTreeWidgetItem(parent, [name, ""])
            values: list[Any] = e.get("values", [])
            for val_raw in values:
                if isinstance(val_raw, dict):
                    v = cast("dict[str, Any]", val_raw)
                    QTreeWidgetItem(
                        child,
                        [
                            str(v.get("name", "")),
                            str(v.get("value", "")),
                        ],
                    )
        self._tree.addTopLevelItem(parent)
        parent.setExpanded(True)


class SegmentsTab(QWidget):
    """Tab showing binary segment information."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the SegmentsTab with a table for segment display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._table = _make_table(["Name", "Address", "Size", "Permissions", "Type"])
        layout.addWidget(self._table)

    def refresh(self, bridge: CutterBridge, _run_async: RunAsyncFn) -> None:
        """Refresh data from the bridge.

        Args:
            bridge: CutterBridge instance.
            _run_async: Deprecated parameter, retained for backward compatibility.
        """
        run_bridge_coroutine_logged(
            bridge.get_segments(),
            on_success=self._apply_data,
            on_error=_log_tab_error(type(self).__name__, "get_segments"),
            parent=self,
            event="cutter_get_segments",
            logger=_logger,
        )

    def _apply_data(self, result: object) -> None:
        """Populate the table with segment results.

        Args:
            result: List of :class:`SegmentInfo` dataclass instances from the bridge.
        """
        segments: list[SegmentInfo] = []
        if isinstance(result, list):
            entries: list[object] = cast("list[object]", result)
            segments.extend(entry for entry in entries if isinstance(entry, SegmentInfo))
        self._table.setRowCount(len(segments))
        for row, seg in enumerate(segments):
            self._table.setItem(row, 0, QTableWidgetItem(seg.name))
            self._table.setItem(row, 1, QTableWidgetItem(f"0x{seg.address:X}"))
            self._table.setItem(row, 2, QTableWidgetItem(str(seg.size)))
            self._table.setItem(row, 3, QTableWidgetItem(seg.permissions))
            self._table.setItem(row, 4, QTableWidgetItem(seg.type))
