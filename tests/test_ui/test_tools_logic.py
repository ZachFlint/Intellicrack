# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for ToolOutputPanel and related widgets logic.

Tests interactivity, signal emission, tab close handling, lazy log
creation, and integration of function list and cross-reference panels.
"""

from __future__ import annotations

import pytest

from intellicrack.ui.app import MainWindow
from intellicrack.ui.tools import FunctionListPanel, ToolOutputPanel, ToolTab, XRefPanel

from .conftest import NoOpSandboxManager, SignalRecorder


_ADDR_MAIN: int = 0x401000
_ADDR_TEST: int = 0x402000


@pytest.mark.usefixtures("qapp")
class TestFunctionListPanel:
    """Tests for FunctionListPanel interactivity."""

    @staticmethod
    def test_function_selected_signal() -> None:
        """Verify function_selected signal is emitted on double click."""
        panel = FunctionListPanel()
        recorder = SignalRecorder()
        panel.function_selected.connect(recorder)

        functions = [("main", _ADDR_MAIN), ("test", _ADDR_TEST)]
        panel.set_functions(functions)

        item = panel.list_widget.item(0)
        assert item is not None
        panel.on_item_double_clicked(item)

        recorder.verify_single_call("main", _ADDR_MAIN)


@pytest.mark.usefixtures("qapp")
class TestXRefPanel:
    """Tests for XRefPanel interactivity."""

    @staticmethod
    def test_xref_selected_signal() -> None:
        """Verify xref_selected signal is emitted on click."""
        panel = XRefPanel()
        recorder = SignalRecorder()
        panel.xref_selected.connect(recorder)

        incoming = [(_ADDR_MAIN, "call main")]
        outgoing = [(_ADDR_TEST, "jump test")]
        panel.set_xrefs(incoming, outgoing)

        root = panel.xref_display.topLevelItem(0)
        assert root is not None
        assert root.text(0) == "=== References TO ==="

        child = root.child(0)
        assert child is not None
        panel.on_item_clicked(child, 0)

        recorder.verify_single_call(_ADDR_MAIN)


@pytest.mark.usefixtures("qapp")
class TestToolOutputPanelIntegration:
    """Tests for ToolOutputPanel signal integration."""

    @staticmethod
    def test_address_clicked_propagation() -> None:
        """Verify signals from sub-panels propagate to address_clicked."""
        panel = ToolOutputPanel()
        recorder = SignalRecorder()
        panel.address_clicked.connect(recorder)

        panel.func_list.function_selected.emit("main", _ADDR_MAIN)
        recorder.verify_any_call(_ADDR_MAIN)

        panel.xref_panel.xref_selected.emit(_ADDR_TEST)
        recorder.verify_any_call(_ADDR_TEST)


@pytest.mark.usefixtures("qapp")
class TestMainWindowIntegration:
    """Tests for MainWindow handling of tool panel signals."""

    @staticmethod
    def test_on_address_clicked_updates_ui(
        real_config: object,
        real_orchestrator: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify MainWindow handles address_clicked signal."""
        monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
        window = MainWindow(real_config, real_orchestrator)

        window.tool_panel.address_clicked.emit(_ADDR_MAIN)

        assert "0x00401000" in window.tool_panel.address_label.text()
        window.close()


@pytest.mark.usefixtures("qapp")
class TestToolOutputPanelNoDefaultTabs:
    """Tests verifying ToolOutputPanel starts with no placeholder tabs."""

    @staticmethod
    def test_panel_starts_with_zero_tabs() -> None:
        """Verify the panel has no tabs immediately after construction."""
        panel = ToolOutputPanel()
        assert panel.tab_widget.count() == 0

    @staticmethod
    def test_tabs_dict_starts_empty() -> None:
        """Verify _tabs dict is empty on construction."""
        panel = ToolOutputPanel()
        assert len(panel.tabs) == 0

    @staticmethod
    def test_embedded_tools_dict_starts_empty() -> None:
        """Verify _embedded_tools dict is empty on construction."""
        panel = ToolOutputPanel()
        assert len(panel.embedded_tools) == 0

    @staticmethod
    def test_panels_dict_starts_empty() -> None:
        """Verify _panels dict is empty on construction."""
        panel = ToolOutputPanel()
        assert len(panel.panels) == 0

    @staticmethod
    def test_tabs_are_closable() -> None:
        """Verify the tab widget has closable tabs enabled."""
        panel = ToolOutputPanel()
        assert panel.tab_widget.tabsClosable() is True


@pytest.mark.usefixtures("qapp")
class TestLogTabLazyCreation:
    """Tests for on-demand Log tab creation."""

    @staticmethod
    def test_log_creates_tab_on_first_call() -> None:
        """Verify log() creates the Log tab when it does not exist."""
        panel = ToolOutputPanel()
        assert "log" not in panel.tabs
        assert panel.tab_widget.count() == 0

        panel.log("test message")

        assert "log" in panel.tabs
        assert panel.tab_widget.count() == 1
        assert panel.tab_widget.tabText(0) == "Log"

    @staticmethod
    def test_log_reuses_existing_tab() -> None:
        """Verify log() does not create duplicate tabs on subsequent calls."""
        panel = ToolOutputPanel()
        panel.log("first message")
        panel.log("second message")

        assert panel.tab_widget.count() == 1
        assert len(panel.tabs) == 1

    @staticmethod
    def test_log_tab_is_tooltab_instance() -> None:
        """Verify the lazily-created Log tab is a ToolTab."""
        panel = ToolOutputPanel()
        panel.log("message")

        log_tab = panel.tabs.get("log")
        assert log_tab is not None
        assert isinstance(log_tab, ToolTab)

    @staticmethod
    def test_log_appends_content() -> None:
        """Verify log() appends message content to the tab."""
        panel = ToolOutputPanel()
        panel.log("line one")
        panel.log("line two")

        log_tab = panel.tabs["log"]
        content = log_tab.code_display.toPlainText()
        assert "line one" in content
        assert "line two" in content


_EXPECTED_TABS_AFTER_THREE_ADDS: int = 3


@pytest.mark.usefixtures("qapp")
class TestTabCloseRequested:
    """Tests for _on_tab_close_requested handler."""

    @staticmethod
    def test_close_tooltab_removes_from_tabs_dict() -> None:
        """Verify closing a ToolTab removes it from _tabs and the tab widget."""
        panel = ToolOutputPanel()
        panel.log("seed the log tab")
        assert panel.tab_widget.count() == 1
        assert "log" in panel.tabs

        panel.on_tab_close_requested(0)

        assert panel.tab_widget.count() == 0
        assert "log" not in panel.tabs

    @staticmethod
    def test_close_tooltab_allows_recreation() -> None:
        """Verify a closed Log tab can be recreated by calling log() again."""
        panel = ToolOutputPanel()
        panel.log("first")
        assert panel.tab_widget.count() == 1

        panel.on_tab_close_requested(0)
        assert panel.tab_widget.count() == 0

        panel.log("second")
        assert panel.tab_widget.count() == 1
        assert "log" in panel.tabs

    @staticmethod
    def test_close_analysis_panel_nulls_reference() -> None:
        """Verify closing the analysis panel nulls _analysis_panel."""
        panel = ToolOutputPanel()
        analysis_w = panel.add_analysis_panel()
        assert panel.analysis_panel is not None
        assert "analysis" in panel.panels

        tab_index = panel.tab_widget.indexOf(analysis_w)
        assert tab_index >= 0

        panel.on_tab_close_requested(tab_index)

        assert panel.analysis_panel is None
        assert "analysis" not in panel.panels
        assert panel.tab_widget.indexOf(analysis_w) == -1

    @staticmethod
    def test_close_analysis_allows_readd() -> None:
        """Verify re-adding analysis panel after close creates a fresh instance."""
        panel = ToolOutputPanel()
        first = panel.add_analysis_panel()
        tab_index = panel.tab_widget.indexOf(first)
        panel.on_tab_close_requested(tab_index)

        assert panel.analysis_panel is None

        second = panel.add_analysis_panel()
        assert panel.analysis_panel is not None
        assert panel.analysis_panel is second
        assert second is not first

    @staticmethod
    def test_close_script_panel_nulls_reference() -> None:
        """Verify closing the script panel nulls _script_panel."""
        panel = ToolOutputPanel()
        scripts = panel.add_script_panel()
        assert panel.script_panel is not None

        tab_index = panel.tab_widget.indexOf(scripts)
        panel.on_tab_close_requested(tab_index)

        assert panel.script_panel is None
        assert "scripts" not in panel.panels

    @staticmethod
    def test_close_stack_panel_nulls_reference() -> None:
        """Verify closing the stack panel nulls _stack_panel."""
        panel = ToolOutputPanel()
        stack = panel.add_stack_panel()
        assert panel.stack_panel is not None

        tab_index = panel.tab_widget.indexOf(stack)
        panel.on_tab_close_requested(tab_index)

        assert panel.stack_panel is None
        assert "stack" not in panel.panels

    @staticmethod
    def test_close_invalid_index_is_noop() -> None:
        """Verify closing an out-of-range index does not crash."""
        panel = ToolOutputPanel()
        panel.on_tab_close_requested(99)
        assert panel.tab_widget.count() == 0

    @staticmethod
    def test_close_multiple_tabs_sequentially() -> None:
        """Verify multiple tabs can be closed one after another."""
        panel = ToolOutputPanel()
        panel.log("log msg")
        panel.add_analysis_panel()
        panel.add_script_panel()
        assert panel.tab_widget.count() == _EXPECTED_TABS_AFTER_THREE_ADDS

        panel.on_tab_close_requested(0)
        assert panel.tab_widget.count() == _EXPECTED_TABS_AFTER_THREE_ADDS - 1

        panel.on_tab_close_requested(0)
        assert panel.tab_widget.count() == _EXPECTED_TABS_AFTER_THREE_ADDS - 2

        panel.on_tab_close_requested(0)
        assert panel.tab_widget.count() == 0


@pytest.mark.usefixtures("qapp")
class TestCloseEmbeddedTools:
    """Tests for close_embedded_tools method."""

    @staticmethod
    def test_close_embedded_tools_clears_all_dicts() -> None:
        """Verify close_embedded_tools empties all tracking dictionaries."""
        panel = ToolOutputPanel()
        panel.log("message")
        panel.add_analysis_panel()
        assert len(panel.tabs) > 0
        assert len(panel.panels) > 0

        panel.close_embedded_tools()

        assert len(panel.tabs) == 0
        assert len(panel.panels) == 0
        assert len(panel.embedded_tools) == 0

    @staticmethod
    def test_close_embedded_tools_nulls_panel_refs() -> None:
        """Verify close_embedded_tools sets all panel references to None."""
        panel = ToolOutputPanel()
        panel.add_analysis_panel()
        panel.add_script_panel()
        panel.add_stack_panel()

        assert panel.analysis_panel is not None
        assert panel.script_panel is not None
        assert panel.stack_panel is not None

        panel.close_embedded_tools()

        assert panel.analysis_panel is None
        assert panel.script_panel is None
        assert panel.stack_panel is None

    @staticmethod
    def test_close_embedded_tools_nulls_bridge_refs() -> None:
        """Verify close_embedded_tools sets all bridge references to None."""
        panel = ToolOutputPanel()

        panel.close_embedded_tools()

        assert panel.x64dbg_bridge is None
        assert panel.ghidra_bridge is None
        assert panel.cutter_bridge is None
        assert panel.frida_bridge is None
