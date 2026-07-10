# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-Qt coverage for the panel support layer and tool-panel helpers.

The audit flagged ``qt_compat.py``, ``base_panel.py``, and the Frida / Ghidra /
Cutter panels as having missing or server-only coverage. A live Frida agent,
Ghidra server, and Cutter/Rizin backend are genuine external infrastructure
that is absent in the container; the network-bound operations are therefore
out of scope here and covered by the bridge suites.

What *can* be proven without that infrastructure is exercised for real:

* ``qt_compat`` wrappers are driven against **real** ``QTableWidget`` /
  ``QTreeWidget`` instances and the round trip of stored item data is checked.
* ``base_panel`` lifecycle signals, status updates, and the ``_invalid_input``
  console routing are validated on a real concrete subclass.
* The tool panels' address parsers are round-tripped against **real virtual
  addresses** read from a real Windows System32 PE (entry point and section
  VAs), and the Frida console renderer is driven with the real Frida message
  protocol shapes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pefile
import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QPlainTextEdit,
    QTableWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels import qt_compat
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.frida_panel import FridaPanel
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from pathlib import Path


_logger = get_logger(__name__)


def _real_addresses(path: Path) -> list[int]:
    """Collect real virtual addresses from a real PE.

    Args:
        path: Path to a real PE binary.

    Returns:
        list[int]: Real entry-point and section virtual addresses.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        base = int(pe.OPTIONAL_HEADER.ImageBase)
        entry = base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        section_vas = [base + int(section.VirtualAddress) for section in pe.sections]
    finally:
        pe.close()
    return [entry, *section_vas]


@pytest.mark.usefixtures("qapp")
class TestQtCompatRealWidgets:
    """qt_compat wrappers must operate on real Qt widgets."""

    @staticmethod
    def test_set_header_labels_on_real_tree() -> None:
        """Header labels must apply to a real QTreeWidget."""
        tree = QTreeWidget()
        qt_compat.set_header_labels(tree, ["Address", "Symbol", "Module"])

        header = tree.headerItem()
        assert header is not None
        assert [header.text(col) for col in range(3)] == ["Address", "Symbol", "Module"]

    @staticmethod
    def test_tree_item_data_round_trip() -> None:
        """Storing and reading item data must round-trip a real value."""
        item = QTreeWidgetItem(["entry"])
        qt_compat.tree_item_set_data(item, 0, Qt.ItemDataRole.UserRole, 0x401000)

        stored = qt_compat.tree_item_data(item, 0, Qt.ItemDataRole.UserRole)
        assert stored == 0x401000

    @staticmethod
    def test_sorting_toggle_and_selection_mode_on_real_table() -> None:
        """Sorting toggle and selection mode must apply to a real QTableWidget."""
        table = QTableWidget(3, 2)
        qt_compat.set_sorting_enabled(table, enable=True)
        assert table.isSortingEnabled() is True

        qt_compat.set_selection_mode(table, QTableWidget.SelectionMode.SingleSelection)
        assert table.selectionMode() == QTableWidget.SelectionMode.SingleSelection

    @staticmethod
    def test_current_tree_item_and_add_child() -> None:
        """Current-item lookup and child insertion must work on a real tree."""
        tree = QTreeWidget()
        parent = QTreeWidgetItem(["parent"])
        tree.addTopLevelItem(parent)
        child = QTreeWidgetItem(["child"])
        qt_compat.tree_add_child(parent, child)
        assert parent.childCount() == 1
        assert parent.child(0) is child

        tree.setCurrentItem(child)
        assert qt_compat.get_current_tree_item(tree) is child

    @staticmethod
    def test_resolve_raises_on_missing_method() -> None:
        """The resolver must raise a clear error for an absent Qt method."""
        table = QTableWidget(0, 0)
        with pytest.raises(AttributeError, match="no method"):
            qt_compat._resolve(table, "definitelyNotAQtMethod")

    @staticmethod
    def test_qt_key_constants_are_real() -> None:
        """Key constant helpers must return the real Qt enum values."""
        assert qt_compat.qt_key_page_up() == int(Qt.Key.Key_PageUp)
        assert qt_compat.qt_key_page_down() == int(Qt.Key.Key_PageDown)


class _ConcretePanel(AnalysisPanelBase):
    """Concrete ``AnalysisPanelBase`` exposing a console for lifecycle tests."""

    def __init__(self) -> None:
        """Initialise the panel and record cleanup invocations."""
        self.cleanup_calls: int = 0
        super().__init__()

    def _create_content(self) -> QToolBar:
        """Build a minimal content widget and a real console attribute.

        Returns:
            QToolBar: A throwaway content widget; the console used by
            ``_invalid_input`` is created here as ``_console_output``.
        """
        self._console_output: QPlainTextEdit = QPlainTextEdit()
        toolbar = QToolBar()
        toolbar.addWidget(self._console_output)
        return toolbar

    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add a real status label to the toolbar.

        Args:
            toolbar: Toolbar to populate.
        """
        self.status_label = self._add_toolbar_label(toolbar, "idle")

    def _cleanup(self) -> None:
        """Record that cleanup ran."""
        self.cleanup_calls += 1


@pytest.mark.usefixtures("qapp")
class TestBasePanelLifecycle:
    """AnalysisPanelBase lifecycle and helpers must work on a real subclass."""

    @staticmethod
    def test_start_and_stop_emit_lifecycle_signals() -> None:
        """start_tool / stop_tool must emit signals and run cleanup."""
        panel = _ConcretePanel()
        started: list[int] = []
        closed: list[int] = []
        panel.tool_started.connect(lambda: started.append(1))
        panel.tool_closed.connect(lambda: closed.append(1))

        assert panel.start_tool() is True
        assert panel.stop_tool() is True

        assert started == [1]
        assert closed == [1]
        assert panel.cleanup_calls == 1

    @staticmethod
    def test_set_status_updates_real_label() -> None:
        """_set_status must update the real status label text."""
        panel = _ConcretePanel()
        panel._set_status("connected to target")
        assert panel.status_label is not None
        assert panel.status_label.text() == "connected to target"

    @staticmethod
    def test_invalid_input_routes_to_real_console() -> None:
        """_invalid_input must append the message to the real console widget."""
        panel = _ConcretePanel()
        panel._invalid_input(
            "panel_test_invalid_address",
            input_text="zzz",
            console_msg="[error] not a valid address",
            logger=_logger,
            field="address",
        )
        console: QPlainTextEdit = panel._console_output
        assert "[error] not a valid address" in console.toPlainText()


@pytest.mark.usefixtures("qapp")
class TestToolPanelAddressParsersRealAddresses:
    """Tool-panel address parsers must round-trip real binary addresses."""

    @staticmethod
    def test_ghidra_parser_round_trips_real_addresses(real_pe_exe: Path) -> None:
        """GhidraPanel must parse hex and decimal forms of real addresses.

        Args:
            real_pe_exe: Real System32 PE executable fixture.
        """
        for addr in _real_addresses(real_pe_exe):
            assert GhidraPanel._parse_address(hex(addr)) == addr
            assert GhidraPanel._parse_address(str(addr)) == addr
        assert GhidraPanel._parse_address("not-hex") is None

    @staticmethod
    def test_cutter_parser_round_trips_real_addresses(real_pe_exe: Path) -> None:
        """CutterPanel must parse hex and decimal forms of real addresses.

        Args:
            real_pe_exe: Real System32 PE executable fixture.
        """
        for addr in _real_addresses(real_pe_exe):
            assert CutterPanel._parse_address(f"0x{addr:X}") == addr
            assert CutterPanel._parse_address(str(addr)) == addr
        assert CutterPanel._parse_address("") is None
        assert CutterPanel._parse_address("   ") is None

    @staticmethod
    def test_frida_parser_round_trips_real_addresses(real_pe_exe: Path) -> None:
        """FridaPanel must parse hex forms of real addresses.

        Args:
            real_pe_exe: Real System32 PE executable fixture.
        """
        for addr in _real_addresses(real_pe_exe):
            assert FridaPanel._parse_hex_address(hex(addr)) == addr
            assert FridaPanel._parse_hex_address(f"{addr:x}") == addr
        assert FridaPanel._parse_hex_address("") is None
        assert FridaPanel._parse_hex_address("xyz") is None


@pytest.mark.usefixtures("qapp")
class TestFridaPanelConsoleRendering:
    """The Frida panel must render the real Frida message protocol shapes."""

    @staticmethod
    def test_send_message_rendered() -> None:
        """A real Frida 'send' message must render its payload to the console."""
        panel = FridaPanel()
        panel._on_frida_message({"type": "send", "payload": "0x140001000 hooked"})
        assert "[send] 0x140001000 hooked" in panel._console.toPlainText()

    @staticmethod
    def test_error_message_rendered() -> None:
        """A real Frida 'error' message must render its description."""
        panel = FridaPanel()
        panel._on_frida_message(
            {"type": "error", "description": "ReferenceError: Module is not defined"},
        )
        assert "[error] ReferenceError: Module is not defined" in panel._console.toPlainText()

    @staticmethod
    def test_attach_without_bridge_reports_error() -> None:
        """Attaching without a bridge must surface the no-bridge error line."""
        panel = FridaPanel()
        panel._on_attach()
        assert "[!] No Frida bridge available" in panel._console.toPlainText()

    @staticmethod
    def test_log_message_appends_real_text() -> None:
        """log_message must append the verbatim text to the console."""
        panel = FridaPanel()
        panel.log_message("[*] script loaded")
        assert "[*] script loaded" in panel._console.toPlainText()
