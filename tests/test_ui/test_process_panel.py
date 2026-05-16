# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the ProcessPanel UI widget, state machine, and bridge wiring."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QWidget

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels import ProcessPanel as ProcessPanelFromPanels
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.process_panel._memory_tab import MemoryTab
from tests.test_ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


@pytest.fixture
def panel(qapp: QApplication) -> Generator[ProcessPanel]:
    """Create a ProcessPanel and clean up after test.

    Args:
        qapp: QApplication fixture from conftest.

    Yields:
        Generator[ProcessPanel]: ProcessPanel widget.
    """
    del qapp
    p = ProcessPanel()
    yield p
    p.deleteLater()


@pytest.fixture
def bridge() -> ProcessBridge:
    """Create an uninitialized ProcessBridge for wiring tests.

    Returns:
        ProcessBridge: Uninitialized ProcessBridge instance.
    """
    return ProcessBridge()


class TestPanelConstruction:
    """Verify ProcessPanel construction and initial widget structure."""

    def test_panel_creates(self, panel: ProcessPanel) -> None:
        """Verify panel is a QWidget instance.

        Args:
            panel: ProcessPanel fixture instance.
        """
        assert isinstance(panel, QWidget)

    def test_panel_has_five_tabs(self, panel: ProcessPanel) -> None:
        """Verify panel has exactly 5 tabs.

        Args:
            panel: ProcessPanel fixture instance.
        """
        assert panel._tab_widget.count() == 5

    def test_panel_tab_names(self, panel: ProcessPanel) -> None:
        """Verify tab names are Processes, Memory, Threads, Modules, System.

        Args:
            panel: ProcessPanel fixture instance.
        """
        expected = ["Processes", "Memory", "Threads", "Modules", "System"]
        actual = [panel._tab_widget.tabText(i) for i in range(panel._tab_widget.count())]
        assert actual == expected

    def test_panel_has_status_bar(self, panel: ProcessPanel) -> None:
        """Verify panel has a status bar.

        Args:
            panel: ProcessPanel fixture instance.
        """
        assert panel._status_bar is not None

    def test_panel_initial_state_disconnected(self, panel: ProcessPanel) -> None:
        """Verify panel starts in disconnected state.

        Args:
            panel: ProcessPanel fixture instance.
        """
        assert panel._state.value == "disconnected"


class TestBridgeWiring:
    """Verify set_bridge propagates to all tabs."""

    def test_set_bridge_propagates_to_process_tab(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify bridge propagates to the process tab.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._process_tab.get_bridge() is bridge

    def test_set_bridge_propagates_to_memory_tab(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify bridge propagates to the memory tab.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._memory_tab.get_bridge() is bridge

    def test_set_bridge_propagates_to_threads_tab(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify bridge propagates to the threads tab.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._threads_tab.get_bridge() is bridge

    def test_set_bridge_propagates_to_modules_tab(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify bridge propagates to the modules tab.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._modules_tab.get_bridge() is bridge

    def test_set_bridge_propagates_to_system_tab(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify bridge propagates to the system tab.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._system_tab.get_bridge() is bridge

    def test_set_bridge_transitions_to_detached(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify set_bridge transitions state to detached.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel._state.value == "detached"

    def test_get_bridge_returns_set_bridge(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify get_bridge returns the same bridge that was set.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert panel.get_bridge() is bridge


class TestStateMachine:
    """Verify state transitions enable/disable detail tabs correctly."""

    def test_disconnected_disables_detail_tabs(self, panel: ProcessPanel) -> None:
        """Verify detail tabs are disabled in disconnected state.

        Args:
            panel: ProcessPanel fixture instance.
        """
        assert not panel._memory_tab.isEnabled()
        assert not panel._threads_tab.isEnabled()
        assert not panel._modules_tab.isEnabled()
        assert not panel._system_tab.isEnabled()

    def test_detached_disables_detail_tabs(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify detail tabs remain disabled after set_bridge (detached).

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert not panel._memory_tab.isEnabled()
        assert not panel._threads_tab.isEnabled()
        assert not panel._modules_tab.isEnabled()
        assert not panel._system_tab.isEnabled()

    def test_attached_enables_detail_tabs(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify all detail tabs become enabled after process attachment.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        panel._on_process_attached(1234)
        assert panel._memory_tab.isEnabled()
        assert panel._threads_tab.isEnabled()
        assert panel._modules_tab.isEnabled()
        assert panel._system_tab.isEnabled()

    def test_detach_disables_tabs_again(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify detaching disables tabs and resets state.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        panel._on_process_attached(1234)
        panel._on_process_detached()
        assert not panel._memory_tab.isEnabled()
        assert not panel._threads_tab.isEnabled()
        assert not panel._modules_tab.isEnabled()
        assert not panel._system_tab.isEnabled()
        assert panel._state.value == "detached"

    def test_attach_updates_status_pid(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify attach updates the PID label.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        panel._on_process_attached(1234)
        assert panel._status_pid.text() == "PID: 1234"

    def test_detach_clears_status_pid(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify detach clears the PID label.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        panel._on_process_attached(1234)
        panel._on_process_detached()
        assert panel._status_pid.text() == "PID: --"


class TestMemoryTabFormatMemory:
    """Verify MemoryTab._format_memory static method (no qapp needed)."""

    def test_format_memory_hex(self) -> None:
        """Verify hex format contains hex bytes and address prefix."""
        data = b"ABC"
        result = MemoryTab._format_memory(data, 0x1000, "Hex")
        assert "41 42 43" in result
        assert "0000000000001000" in result

    def test_format_memory_ascii(self) -> None:
        """Verify ASCII format contains the ASCII characters."""
        data = b"ABC"
        result = MemoryTab._format_memory(data, 0x1000, "ASCII")
        assert "ABC" in result

    def test_format_memory_both(self) -> None:
        """Verify Both format contains hex and ASCII delimiters."""
        data = b"AB\x01"
        result = MemoryTab._format_memory(data, 0x1000, "Both")
        assert "41 42 01" in result
        assert "|AB.|" in result

    def test_format_memory_nonprintable_dot(self) -> None:
        """Verify non-printable byte 0x01 shows as '.' in ASCII mode."""
        data = bytes([0x01])
        result = MemoryTab._format_memory(data, 0x1000, "ASCII")
        assert "." in result

    def test_format_memory_16_byte_line(self) -> None:
        """Verify 16-byte input produces exactly one line."""
        data = bytes(range(16))
        result = MemoryTab._format_memory(data, 0x0, "Hex")
        lines = result.strip().split("\n")
        assert len(lines) == 1


class TestImportCompatibility:
    """Verify ProcessPanel can be imported from expected paths."""

    def test_import_from_package(self) -> None:
        """Verify import from process_panel package."""
        assert ProcessPanel is not None

    def test_import_from_panels(self) -> None:
        """Verify import from panels package."""
        assert ProcessPanelFromPanels is not None

    def test_both_imports_same_class(self) -> None:
        """Verify both import paths resolve to the same class."""
        assert ProcessPanel is ProcessPanelFromPanels


class TestSignalEmission:
    """Verify signal emissions from ProcessPanel."""

    def test_process_selected_signal(self, panel: ProcessPanel) -> None:
        """Verify process_selected signal fires with correct PID.

        Args:
            panel: ProcessPanel fixture instance.
        """
        recorder = SignalRecorder()
        panel.process_selected.connect(recorder)
        panel._on_process_selected(42)
        recorder.verify_single_call(42)

    def test_process_attached_signal(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify process_attached signal fires with correct PID.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        recorder = SignalRecorder()
        panel.set_bridge(bridge)
        panel.process_attached.connect(recorder)
        panel._on_process_attached(42)
        recorder.verify_single_call(42)

    def test_process_detached_signal(self, panel: ProcessPanel, bridge: ProcessBridge) -> None:
        """Verify process_detached signal fires once.

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        recorder = SignalRecorder()
        panel.set_bridge(bridge)
        panel._on_process_attached(42)
        panel.process_detached.connect(recorder)
        panel._on_process_detached()
        assert recorder.times_called == 1


class TestToolDefinition:
    """Verify ProcessBridge tool definition structure."""

    def test_tool_definition_count(self) -> None:
        """Verify tool definition exposes the expected number of functions.

        The exact count drifts as the bridge grows; assert against the
        current ``54`` baseline so additions or removals fail loudly and
        force the bridge author to bump the expectation deliberately.
        """
        b = ProcessBridge()
        assert len(b.tool_definition.functions) == 54

    def test_all_names_start_with_process(self) -> None:
        """Verify all function names start with 'process.'."""
        b = ProcessBridge()
        for func in b.tool_definition.functions:
            assert func.name.startswith("process.")

    def test_function_names_map_to_methods(self) -> None:
        """Verify function names map to actual bridge methods."""
        b = ProcessBridge()
        renamed = {
            "process.list": "list_processes",
            "process.list_detailed": "list_processes_detailed",
            "process.open": "open_process",
        }
        for func in b.tool_definition.functions:
            method_name = renamed[func.name] if func.name in renamed else func.name.removeprefix("process.")
            assert hasattr(b, method_name), f"Missing method: {method_name} for {func.name}"
