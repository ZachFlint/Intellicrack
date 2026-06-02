# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the ProcessPanel UI widget, state machine, and bridge wiring."""

from __future__ import annotations

import asyncio
import inspect
import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QWidget

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProcessInfo, ToolError, ToolName
from intellicrack.ui.panels import ProcessPanel as ProcessPanelFromPanels
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from tests.test_ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async bridge coroutine to completion on a private event loop.

    Args:
        coro: The awaitable coroutine to execute.

    Returns:
        T: The resolved result of the coroutine.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


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


@pytest.fixture
def process_registry(tmp_path: Path) -> ToolRegistry:
    """Build a real ToolRegistry with a live, initialized ProcessBridge registered.

    Args:
        tmp_path: Pytest temporary directory used as the tools install root.

    Returns:
        ToolRegistry: Registry exposing the process bridge for end-to-end dispatch.
    """
    registry = ToolRegistry(tmp_path / "tools")
    bridge = ProcessBridge()
    _run(bridge.initialize())
    registry.register_bridge(ToolName.PROCESS, bridge)
    return registry


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
    """Verify ProcessBridge tool definition is fully wired to callable bridge methods.

    The audit flagged a bare count assertion and a bare ``hasattr`` loop as
    non-gating: neither proved the advertised functions are actually invokable
    through the production orchestration dispatch path. These tests instead
    drive every advertised function through the real
    :meth:`ToolRegistry.execute_tool_call` resolution rule (suffix after the
    ``process.`` prefix) and confirm each resolves to a callable, bound,
    parameter-compatible coroutine method, then invoke one end to end against
    real live OS processes.
    """

    @staticmethod
    def test_every_function_is_fully_formed_and_unique() -> None:
        """Every advertised function carries a unique ``process.``-scoped name plus docs.

        A dummy stub added merely to inflate the count would be caught here:
        empty/duplicate names, empty descriptions, or empty return docs fail.
        """
        bridge = ProcessBridge()
        functions = bridge.tool_definition.functions

        names = [f.name for f in functions]
        assert len(names) == len(set(names)), f"duplicate tool-function names: {sorted({n for n in names if names.count(n) > 1})}"

        for func in functions:
            assert func.name.startswith("process."), f"function {func.name!r} is not scoped under the process tool"
            suffix = func.name.split(".", maxsplit=1)[1]
            assert suffix, f"function {func.name!r} has an empty dispatch suffix"
            assert func.description.strip(), f"function {func.name!r} has an empty description"
            assert func.returns.strip(), f"function {func.name!r} has an empty return description"

    @staticmethod
    def test_dispatch_suffix_resolves_to_callable_signature_compatible_coroutine() -> None:
        """Each function resolves (via production suffix rule) to a compatible async method.

        Mirrors the exact lookup ``ToolRegistry.execute_tool_call`` performs:
        ``getattr(bridge, name.split('.')[-1])``. For every advertised function
        the attribute must exist, be callable, be a coroutine function, and
        accept every required tool parameter as a real method parameter (or
        absorb it through ``**kwargs``). A property that raises, a non-callable
        attribute, or a signature mismatch all fail here.
        """
        bridge = ProcessBridge()
        for func in bridge.tool_definition.functions:
            suffix = func.name.split(".", maxsplit=1)[1]
            method = getattr(bridge, suffix, None)
            assert method is not None, f"{func.name}: no bridge attribute {suffix!r}"
            assert callable(method), f"{func.name}: bridge attribute {suffix!r} is not callable"
            assert asyncio.iscoroutinefunction(method), f"{func.name}: {suffix!r} must be an async (coroutine) method"

            sig = inspect.signature(method)
            accepts_kwargs = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            for param in func.parameters:
                if param.required and not accepts_kwargs:
                    assert param.name in sig.parameters, f"{func.name}: required parameter {param.name!r} absent from {suffix} signature"

    @staticmethod
    def test_list_function_executes_end_to_end_through_real_registry(process_registry: ToolRegistry) -> None:
        """The advertised ``process.list`` runs through the real registry against live PIDs.

        Invokes the advertised function through a real :class:`ToolRegistry`
        holding a live, initialized :class:`ProcessBridge`, exactly as the
        orchestrator would. The result must enumerate the current Python test
        process itself (an independent oracle: ``os.getpid()`` / ``python`` are
        known to be running), proving the tool definition is wired to working
        functionality rather than merely declared.

        Args:
            process_registry: Registry with a live process bridge registered.
        """
        result = _run(process_registry.execute_tool_call("process", "process.list", {}))
        assert isinstance(result, list), f"process.list must return a list, got {type(result).__name__}"
        assert result, "process.list returned no processes, but at least this test process must be running"
        assert all(isinstance(p, ProcessInfo) for p in result), "every entry must be a ProcessInfo record"

        current_pid = os.getpid()
        matched = [p for p in result if p.pid == current_pid]
        assert len(matched) == 1, f"the live test process (pid={current_pid}) must appear exactly once in process.list"
        assert matched[0].name.lower().startswith("python"), f"the test process name must be a python image, got {matched[0].name!r}"

    @staticmethod
    def test_list_detailed_filter_argument_flows_through_registry(process_registry: ToolRegistry) -> None:
        """A filter argument passes through the registry into the live enumeration.

        Drives ``process.list_detailed`` with ``filter_name='python'`` end to
        end. The independent oracle is the live OS: every returned record must
        match the filter and the current Python process must be among them,
        confirming the argument is forwarded (not silently dropped) by the
        production dispatch path.

        Args:
            process_registry: Registry with a live process bridge registered.
        """
        result = _run(process_registry.execute_tool_call("process", "process.list_detailed", {"filter_name": "python"}))
        assert isinstance(result, list), f"process.list_detailed must return a list, got {type(result).__name__}"
        assert result, "filtered list_detailed must include at least this python test process"
        names = [str(entry["name"]).lower() for entry in result]
        assert all("python" in name for name in names), f"filter 'python' leaked non-matching processes: {sorted(set(names))}"
        assert any(int(entry["pid"]) == os.getpid() for entry in result), "the live python test process must survive the filter"

    @staticmethod
    def test_unknown_function_raises_tool_error_through_registry(process_registry: ToolRegistry) -> None:
        """An undeclared function name surfaces a ToolError, never a silent no-op.

        Confirms the error path: a name that is not backed by a bridge method
        must raise :class:`ToolError`, proving the dispatcher rejects bogus
        calls rather than swallowing them.

        Args:
            process_registry: Registry with a live process bridge registered.
        """
        with pytest.raises(ToolError):
            _run(process_registry.execute_tool_call("process", "process.this_function_does_not_exist", {}))
