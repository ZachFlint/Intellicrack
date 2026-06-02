# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ToolOutputPanel and related widgets logic.

Tests interactivity, signal emission, tab close handling, and integration
of function list and cross-reference panels. Every test drives a real Qt
widget through a real user-interaction path (item population, double-click,
tree click, tab close) and asserts the exact observable result so that
breaking the underlying parsing, population, routing, or cleanup logic
turns the test red.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QListWidgetItem

from intellicrack.core.types import BridgeAnalysisSummary, FunctionInfo
from intellicrack.ui.app import MainWindow
from intellicrack.ui.tools import FunctionListPanel, ToolOutputPanel, XRefPanel

from .conftest import SignalRecorder


_ADDR_MAIN: int = 0x401000
_ADDR_TEST: int = 0x402000
_ADDR_PARSE: int = 0x4015AB
_EMPTY_LABEL: str = ""
_EXPECTED_THREE_TABS: int = 3
_EXPECTED_TWO_TABS: int = 2
_EXPECTED_ONE_TAB: int = 1


def _double_click_first_function(panel: ToolOutputPanel, name: str, address: int) -> None:
    """Populate one function and drive a real double-click on it.

    Args:
        panel: The tool output panel whose function list to drive.
        name: Function name to populate.
        address: Function address to populate.
    """
    panel.func_list.set_functions([(name, address)])
    item = panel.func_list.list_widget.item(0)
    assert item is not None
    panel.func_list._on_item_double_clicked(item)


def _make_summary(functions: list[FunctionInfo]) -> BridgeAnalysisSummary:
    """Build a real BridgeAnalysisSummary carrying the given functions.

    Args:
        functions: Function records the summary should expose.

    Returns:
        BridgeAnalysisSummary: Summary with empty supporting tables and the
            supplied function list, marked complete with a real source bridge.
    """
    return BridgeAnalysisSummary(
        binary_name="sample.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=functions,
        format_info="PE32",
        architecture="x86",
        source_bridges=["ghidra"],
        analysis_notes=[],
        complete=True,
    )


def _func(name: str, address: int) -> FunctionInfo:
    """Construct a minimal real FunctionInfo record.

    Args:
        name: Function name.
        address: Function start address.

    Returns:
        FunctionInfo: Record with empty parameter and variable lists.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=0x20,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


@pytest.mark.usefixtures("qapp")
class TestFunctionListPanel:
    """Tests for FunctionListPanel population and interactivity."""

    @staticmethod
    def test_set_functions_populates_items_with_exact_formatting() -> None:
        """Verify set_functions renders each entry as ``0x{addr:08X}  {name}``."""
        panel = FunctionListPanel()
        functions: list[tuple[str, int]] = [("main", _ADDR_MAIN), ("decode", _ADDR_PARSE)]
        panel.set_functions(functions)

        assert panel.list_widget.count() == 2
        first = panel.list_widget.item(0)
        second = panel.list_widget.item(1)
        assert first is not None
        assert second is not None
        assert first.text() == "0x00401000  main"
        assert second.text() == "0x004015AB  decode"
        assert panel.get_functions() == functions

    @staticmethod
    def test_double_click_parses_address_and_name_from_item_text() -> None:
        """Verify a real double-click parses the rendered hex and name back out."""
        panel = FunctionListPanel()
        recorder = SignalRecorder()
        panel.function_selected.connect(recorder)

        panel.set_functions([("main", _ADDR_MAIN), ("decode", _ADDR_PARSE)])

        second = panel.list_widget.item(1)
        assert second is not None
        assert second.text() == "0x004015AB  decode"
        panel._on_item_double_clicked(second)

        recorder.verify_single_call("decode", _ADDR_PARSE)

    @staticmethod
    def test_double_click_on_malformed_item_emits_nothing() -> None:
        """Verify malformed item text (no separator) yields no signal."""
        panel = FunctionListPanel()
        recorder = SignalRecorder()
        panel.function_selected.connect(recorder)

        bad_item: QListWidgetItem = QListWidgetItem("not-a-valid-entry")
        panel.list_widget.addItem(bad_item)
        panel._on_item_double_clicked(bad_item)

        assert recorder.times_called == 0


@pytest.mark.usefixtures("qapp")
class TestXRefPanel:
    """Tests for XRefPanel tree population and interactivity."""

    @staticmethod
    def test_set_xrefs_builds_two_roots_with_exact_children() -> None:
        """Verify the tree has TO/FROM roots with correctly formatted children."""
        panel = XRefPanel()
        incoming: list[tuple[int, str]] = [(_ADDR_MAIN, "call main"), (_ADDR_PARSE, "jmp decode")]
        outgoing: list[tuple[int, str]] = [(_ADDR_TEST, "call helper")]
        panel.set_xrefs(incoming, outgoing)

        assert panel.xref_display.topLevelItemCount() == 2

        to_root = panel.xref_display.topLevelItem(0)
        from_root = panel.xref_display.topLevelItem(1)
        assert to_root is not None
        assert from_root is not None
        assert to_root.text(0) == "=== References TO ==="
        assert from_root.text(0) == "=== References FROM ==="

        assert to_root.childCount() == 2
        assert from_root.childCount() == 1

        to_child0 = to_root.child(0)
        to_child1 = to_root.child(1)
        from_child0 = from_root.child(0)
        assert to_child0 is not None
        assert to_child1 is not None
        assert from_child0 is not None
        assert to_child0.text(0) == "0x00401000  call main"
        assert to_child1.text(0) == "0x004015AB  jmp decode"
        assert from_child0.text(0) == "0x00402000  call helper"

    @staticmethod
    def test_click_child_parses_address_from_rendered_text() -> None:
        """Verify clicking a child parses its leading hex into the emitted int."""
        panel = XRefPanel()
        recorder = SignalRecorder()
        panel.xref_selected.connect(recorder)

        panel.set_xrefs([(_ADDR_PARSE, "call decode")], [])

        to_root = panel.xref_display.topLevelItem(0)
        assert to_root is not None
        child = to_root.child(0)
        assert child is not None

        address_str = child.text(0).strip().split("  ")[0]
        assert int(address_str, 16) == _ADDR_PARSE

        panel._on_item_clicked(child, 0)
        recorder.verify_single_call(_ADDR_PARSE)

    @staticmethod
    def test_click_on_root_header_emits_nothing() -> None:
        """Verify clicking a non-address root header emits no signal."""
        panel = XRefPanel()
        recorder = SignalRecorder()
        panel.xref_selected.connect(recorder)

        panel.set_xrefs([(_ADDR_MAIN, "call main")], [])

        to_root = panel.xref_display.topLevelItem(0)
        assert to_root is not None
        assert to_root.text(0) == "=== References TO ==="
        panel._on_item_clicked(to_root, 0)

        assert recorder.times_called == 0


@pytest.mark.usefixtures("qapp")
class TestToolOutputPanelIntegration:
    """Tests for ToolOutputPanel routing real sub-panel interactions."""

    @staticmethod
    def test_function_double_click_routes_to_address_clicked() -> None:
        """Verify a real function double-click drives address_clicked with the parsed address."""
        panel = ToolOutputPanel()
        recorder = SignalRecorder()
        panel.address_clicked.connect(recorder)

        panel.func_list.set_functions([("main", _ADDR_MAIN)])
        item = panel.func_list.list_widget.item(0)
        assert item is not None
        assert item.text() == "0x00401000  main"

        panel.func_list._on_item_double_clicked(item)
        recorder.verify_single_call(_ADDR_MAIN)

    @staticmethod
    def test_xref_child_click_routes_to_address_clicked() -> None:
        """Verify a real xref tree-item click drives address_clicked with the parsed address."""
        panel = ToolOutputPanel()
        recorder = SignalRecorder()
        panel.address_clicked.connect(recorder)

        panel.xref_panel.set_xrefs([], [(_ADDR_TEST, "call helper")])
        from_root = panel.xref_panel.xref_display.topLevelItem(0)
        assert from_root is not None
        assert from_root.text(0) == "=== References FROM ==="
        child = from_root.child(0)
        assert child is not None
        assert child.text(0) == "0x00402000  call helper"

        panel.xref_panel._on_item_clicked(child, 0)
        recorder.verify_single_call(_ADDR_TEST)


@pytest.mark.usefixtures("qapp")
class TestMainWindowIntegration:
    """Tests for MainWindow handling tool-panel address navigation end to end."""

    @staticmethod
    def test_function_click_updates_address_label_through_full_chain(
        real_config: object,
        real_orchestrator: object,
    ) -> None:
        """Verify a real function double-click propagates to the address label.

        Drives the full signal chain: FunctionListPanel double-click ->
        ToolOutputPanel._on_function_selected -> address_clicked ->
        MainWindow._on_address_clicked -> set_current_address -> label text.
        Uses the real SandboxManager (no mock).

        Args:
            real_config: Real Config fixture used to construct MainWindow.
            real_orchestrator: Real Orchestrator fixture used to construct MainWindow.
        """
        window = MainWindow(real_config, real_orchestrator)
        try:
            assert window.tool_panel.address_label.text() == _EMPTY_LABEL
            _double_click_first_function(window.tool_panel, "main", _ADDR_MAIN)
            assert window.tool_panel.address_label.text() == "0x00401000"
        finally:
            window.close()

    @staticmethod
    def test_signal_disconnect_breaks_label_update(
        real_config: object,
        real_orchestrator: object,
    ) -> None:
        """Verify the label update depends on the wired address_clicked connection.

        Disconnecting the tool-panel handler from the window must leave the
        label unchanged after a click, proving the assertion gates the real
        signal wiring rather than an incidental side effect.

        Args:
            real_config: Real Config fixture used to construct MainWindow.
            real_orchestrator: Real Orchestrator fixture used to construct MainWindow.
        """
        window = MainWindow(real_config, real_orchestrator)
        try:
            window.tool_panel.address_clicked.disconnect(window._on_address_clicked)
            _double_click_first_function(window.tool_panel, "main", _ADDR_MAIN)
            assert window.tool_panel.address_label.text() == _EMPTY_LABEL
        finally:
            window.close()


@pytest.mark.usefixtures("qapp")
class TestToolOutputPanelTabLifecycle:
    """Tests for tab add/close behavior on ToolOutputPanel."""

    @staticmethod
    def test_panel_starts_with_no_tabs_and_closable_bar() -> None:
        """Verify the panel begins empty and exposes a closable tab bar."""
        panel = ToolOutputPanel()
        assert panel.tab_widget.count() == 0
        assert len(panel.tabs) == 0
        assert len(panel.panels) == 0
        assert len(panel.embedded_tools) == 0
        assert panel.tab_widget.tabsClosable() is True

    @staticmethod
    def test_add_analysis_panel_then_close_returns_to_empty() -> None:
        """Verify adding then closing the analysis panel restores the empty state."""
        panel = ToolOutputPanel()

        analysis_w = panel.add_analysis_panel()
        assert panel.tab_widget.count() == 1
        assert panel.panels["analysis"] is analysis_w
        assert panel.analysis_panel is analysis_w

        tab_index = panel.tab_widget.indexOf(analysis_w)
        assert tab_index == 0
        panel._on_tab_close_requested(tab_index)

        assert panel.tab_widget.count() == 0
        assert panel.tab_widget.indexOf(analysis_w) == -1
        assert "analysis" not in panel.panels
        assert panel.analysis_panel is None


@pytest.mark.usefixtures("qapp")
class TestTabCloseRequested:
    """Tests for _on_tab_close_requested cleanup correctness."""

    @staticmethod
    def test_close_analysis_panel_removes_tab_and_nulls_reference() -> None:
        """Verify closing the analysis panel removes the tab and clears tracking."""
        panel = ToolOutputPanel()
        analysis_w = panel.add_analysis_panel()
        tab_index = panel.tab_widget.indexOf(analysis_w)

        panel._on_tab_close_requested(tab_index)

        assert panel.analysis_panel is None
        assert "analysis" not in panel.panels
        assert panel.tab_widget.indexOf(analysis_w) == -1
        assert panel.tab_widget.count() == 0

    @staticmethod
    def test_close_analysis_allows_readd_with_working_instance() -> None:
        """Verify the re-added analysis panel is fresh and functionally wired.

        The second instance must actually accept analysis data through the
        live ``update_bridge_analysis`` path and populate the function list,
        proving the re-add reconnects the panel into the panel's data flow
        rather than merely allocating a new object.
        """
        panel = ToolOutputPanel()
        first = panel.add_analysis_panel()
        panel._on_tab_close_requested(panel.tab_widget.indexOf(first))
        assert panel.analysis_panel is None

        summary = _make_summary([_func("decode", _ADDR_PARSE)])
        panel.update_bridge_analysis(summary)

        second = panel.analysis_panel
        assert second is not None
        assert second is not first
        assert panel.tab_widget.indexOf(second) >= 0
        assert second.get_current_analysis() is summary

        item = panel.func_list.list_widget.item(0)
        assert item is not None
        assert item.text() == "0x004015AB  decode"

    @staticmethod
    def test_close_embedded_tool_tab_invokes_real_stop_tool() -> None:
        """Verify closing an embedded tool tab runs its real stop cleanup.

        Builds a real X64Dbg panel and bridge, records the panel's
        ``tool_closed`` signal (emitted only by the real ``stop_tool`` ->
        ``_cleanup`` path), then closes the tab and asserts the signal fired
        once, the bridge reference was detached, and the tab was removed.
        """
        panel = ToolOutputPanel()
        widget = panel.add_x64dbg_tab(is_64bit=True)
        assert widget is not None
        assert panel.x64dbg_bridge is not None

        closed = SignalRecorder()
        widget.tool_closed.connect(closed)

        tab_index = panel.tab_widget.indexOf(widget)
        assert tab_index >= 0
        panel._on_tab_close_requested(tab_index)

        assert closed.times_called == 1
        assert panel._x64dbg_widget is None
        assert panel.x64dbg_bridge is None
        assert panel.tab_widget.indexOf(widget) == -1
        assert "x64dbg" not in panel.embedded_tools

    @staticmethod
    def test_close_invalid_index_is_noop() -> None:
        """Verify closing an out-of-range index leaves the panel untouched."""
        panel = ToolOutputPanel()
        panel.add_analysis_panel()
        assert panel.tab_widget.count() == 1

        panel._on_tab_close_requested(99)

        assert panel.tab_widget.count() == 1
        assert panel.analysis_panel is not None

    @staticmethod
    def test_close_multiple_tabs_leaves_correct_survivors() -> None:
        """Verify sequential closes remove exactly the closed tab each time."""
        panel = ToolOutputPanel()
        analysis_w = panel.add_analysis_panel()
        script_w = panel.add_script_panel()
        stack_w = panel.add_stack_panel()
        assert panel.tab_widget.count() == _EXPECTED_THREE_TABS

        panel._on_tab_close_requested(panel.tab_widget.indexOf(analysis_w))
        assert panel.tab_widget.count() == _EXPECTED_TWO_TABS
        assert panel.tab_widget.indexOf(analysis_w) == -1
        assert panel.tab_widget.indexOf(script_w) >= 0
        assert panel.tab_widget.indexOf(stack_w) >= 0
        assert panel.analysis_panel is None
        assert panel.script_panel is script_w
        assert panel.stack_panel is stack_w

        panel._on_tab_close_requested(panel.tab_widget.indexOf(script_w))
        assert panel.tab_widget.count() == _EXPECTED_ONE_TAB
        assert panel.tab_widget.indexOf(script_w) == -1
        assert panel.tab_widget.indexOf(stack_w) >= 0
        assert panel.script_panel is None
        assert panel.stack_panel is stack_w

        panel._on_tab_close_requested(panel.tab_widget.indexOf(stack_w))
        assert panel.tab_widget.count() == 0
        assert panel.stack_panel is None


@pytest.mark.usefixtures("qapp")
class TestCloseEmbeddedTools:
    """Tests for close_embedded_tools full-teardown behavior."""

    @staticmethod
    def test_close_embedded_tools_runs_real_stop_and_clears_panels() -> None:
        """Verify close_embedded_tools stops embedded tools and empties tracking.

        Populates the panel with a real embedded x64dbg tool (with bridge)
        plus the analysis, script, and stack panels, records the x64dbg
        panel's ``tool_closed`` signal, then closes everything and asserts the
        real stop fired, the bridge detached, every reference nulled, and all
        tracking dicts emptied.
        """
        panel = ToolOutputPanel()
        x64dbg_w = panel.add_x64dbg_tab(is_64bit=True)
        panel.add_analysis_panel()
        panel.add_script_panel()
        panel.add_stack_panel()

        assert x64dbg_w is not None
        assert panel.x64dbg_bridge is not None
        assert panel.analysis_panel is not None
        assert panel.script_panel is not None
        assert panel.stack_panel is not None

        closed = SignalRecorder()
        x64dbg_w.tool_closed.connect(closed)

        panel.close_embedded_tools()

        assert closed.times_called == 1
        assert panel._x64dbg_widget is None
        assert panel.x64dbg_bridge is None
        assert panel.analysis_panel is None
        assert panel.script_panel is None
        assert panel.stack_panel is None
        assert len(panel.tabs) == 0
        assert len(panel.panels) == 0
        assert len(panel.embedded_tools) == 0

    @staticmethod
    def test_close_embedded_tools_nulls_all_bridge_refs() -> None:
        """Verify close_embedded_tools detaches every static/dynamic bridge.

        Constructs real x64dbg, cutter, ghidra, and frida tabs so each bridge
        reference is live, then verifies close_embedded_tools nulls them all.
        """
        panel = ToolOutputPanel()
        panel.add_x64dbg_tab(is_64bit=True)
        panel.add_cutter_tab()
        panel.add_ghidra_tab()
        panel.add_frida_tab()

        assert panel.x64dbg_bridge is not None
        assert panel.cutter_bridge is not None
        assert panel.ghidra_bridge is not None
        assert panel.frida_bridge is not None

        panel.close_embedded_tools()

        assert panel.x64dbg_bridge is None
        assert panel.ghidra_bridge is None
        assert panel.cutter_bridge is None
        assert panel.frida_bridge is None
