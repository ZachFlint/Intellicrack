# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the ProcessPanel UI widget, state machine, and bridge wiring."""

from __future__ import annotations

import asyncio
import inspect
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QTableWidget, QTableWidgetItem

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProcessInfo, ToolError, ToolName
from intellicrack.ui.panels import ProcessPanel as ProcessPanelFromPanels
from intellicrack.ui.panels.process_panel import ProcessPanel
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from intellicrack.ui.panels.process_panel.process_tab import ProcessTab
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


_MAX_WAIT_S: Final[float] = 5.0
_POLL_INTERVAL_S: Final[float] = 0.02


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


def _pump_until(qapp: QApplication, predicate: Callable[[], bool]) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or time runs out.

    Args:
        qapp: The QApplication instance whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + _MAX_WAIT_S
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


@pytest.fixture
def panel(qapp: QApplication) -> Generator[ProcessPanel]:
    """Create a ProcessPanel and tear it down cleanly after the test.

    Teardown routes through the panel's own ``stop_tool`` -> ``_cleanup`` path,
    which joins every bridge-call worker owned by the panel subtree (status-bar
    architecture / privilege refreshes and the process tab's list / info /
    environment coroutines). The pumped ``processEvents`` then delivers each
    now-settled worker's queued result callback while the widgets are still
    alive, so no callback lands on a deleted ``QLabel`` / ``QTableWidget`` /
    ``QTreeWidget`` once ``deleteLater`` destroys the tree.

    Args:
        qapp: QApplication fixture from conftest.

    Yields:
        ProcessPanel: ProcessPanel widget.
    """
    p = ProcessPanel()
    yield p
    p.stop_tool()
    qapp.processEvents()
    p.deleteLater()
    qapp.processEvents()


@pytest.fixture
def bridge() -> ProcessBridge:
    """Create an uninitialized ProcessBridge for wiring tests.

    Returns:
        ProcessBridge: Uninitialized ProcessBridge instance.
    """
    return ProcessBridge()


@pytest.fixture
def process_registry(tmp_path: object) -> ToolRegistry:
    """Build a real ToolRegistry with a live, initialized ProcessBridge registered.

    Args:
        tmp_path: Pytest temporary directory used as the tools install root.

    Returns:
        ToolRegistry: Registry exposing the process bridge for end-to-end dispatch.
    """
    registry = ToolRegistry(Path(str(tmp_path)) / "tools")
    pb = ProcessBridge()
    _run(pb.initialize())
    registry.register_bridge(ToolName.PROCESS, pb)
    return registry


class TestPanelConstruction:
    """Verify ProcessPanel construction and initial widget structure."""

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
        """Verify per-process tabs stay disabled after set_bridge while System enables.

        In the ``detached`` state (a bridge is connected but no process is
        attached) the per-process detail tabs (Memory, Threads, Modules) must
        remain disabled because they require an attached target, whereas the
        System tab exposes system-wide operations that only need a connected
        bridge and therefore becomes enabled. This mirrors the enable rule in
        ``ProcessPanel._update_controls_for_state`` (System gated on connection,
        the rest gated on attachment).

        Args:
            panel: ProcessPanel fixture instance.
            bridge: Uninitialized ProcessBridge fixture instance.
        """
        panel.set_bridge(bridge)
        assert not panel._memory_tab.isEnabled()
        assert not panel._threads_tab.isEnabled()
        assert not panel._modules_tab.isEnabled()
        assert panel._system_tab.isEnabled()

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
        """Verify detaching re-gates the per-process tabs and resets state to detached.

        After attach then detach the panel returns to the ``detached`` state:
        the per-process detail tabs (Memory, Threads, Modules) must be disabled
        again while the System tab stays enabled (the bridge is still connected),
        matching ``ProcessPanel._update_controls_for_state``.

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
        assert panel._system_tab.isEnabled()
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


_CANONICAL_PROCESS_FUNCTION_NAMES: frozenset[str] = frozenset({
    "process.list",
    "process.list_detailed",
    "process.enumerate_system_processes",
    "process.open",
    "process.close",
    "process.terminate",
    "process.suspend",
    "process.resume",
    "process.read_memory",
    "process.write_memory",
    "process.allocate",
    "process.free",
    "process.protect",
    "process.decommit_memory",
    "process.get_modules",
    "process.get_threads",
    "process.get_memory_map",
    "process.search_pattern",
    "process.inject_dll",
    "process.get_process_info",
    "process.get_process_memory_mb",
    "process.detect_architecture",
    "process.get_token_privileges",
    "process.adjust_token_privilege",
    "process.get_handles",
    "process.enumerate_handles",
    "process.enum_handles",
    "process.get_windows",
    "process.list_services",
    "process.enumerate_services",
    "process.read_peb",
    "process.read_teb",
    "process.get_heaps",
    "process.get_thread_context",
    "process.set_thread_context",
    "process.stack_walk",
    "process.get_seh_chain",
    "process.get_mitigation_policies",
    "process.get_mitigation_policy",
    "process.get_extension_policy",
    "process.get_environment",
    "process.pipe_connect",
    "process.pipe_read",
    "process.pipe_write",
    "process.pipe_close",
    "process.enumerate_com_servers",
    "process.detect_dotnet",
    "process.device_open",
    "process.device_ioctl",
    "process.device_close",
    "process.get_job_info",
    "process.get_gui_resources",
    "process.reg_read_value",
    "process.read_registry",
    "process.reg_enum_keys",
    "process.reg_enum_values",
    "process.create_section",
    "process.map_section",
    "process.unmap_section",
    "process.get_tls_values",
    "process.get_fiber_data",
    "process.query_system_info",
    "process.duplicate_token",
    "process.remove_privilege",
    "process.time_thread_wait",
    "process.detect_kernel_debugger",
})

# Maps each tool function name to the bridge method attribute that ToolRegistry.execute_tool_call
# resolves via the production dispatch rule in tools.py: the suffix after the first dot.
# Three functions have shim methods whose suffix differs from the underlying implementation:
#   "process.list"          -> bridge attribute "list"          (delegates to list_processes)
#   "process.list_detailed" -> bridge attribute "list_detailed" (delegates to list_processes_detailed)
#   "process.open"          -> bridge attribute "open"          (delegates to open_process)
# All other functions resolve to a method whose name equals the suffix directly.
_CANONICAL_FUNCTION_TO_DISPATCH_METHOD: dict[str, str] = {fn: fn.split(".", maxsplit=1)[-1] for fn in _CANONICAL_PROCESS_FUNCTION_NAMES}


class TestToolDefinition:
    """Verify ProcessBridge tool definition is fully wired to callable bridge methods.

    The audit flagged a bare count assertion and a bare hasattr loop as non-gating:
    neither proved the advertised functions are actually invokable through the
    production orchestration dispatch path. These tests instead drive every
    advertised function through the real ToolRegistry.execute_tool_call resolution
    rule (suffix after the first dot) and confirm each resolves to a callable,
    bound, parameter-compatible coroutine method, then invoke several end-to-end
    against live OS processes.
    """

    def test_tool_definition_exact_function_set(self) -> None:
        """Verify the tool definition exposes exactly the canonical set of 66 process functions.

        Asserts the full set of declared function names matches the independently
        enumerated canonical set. A stub that declares fewer, more, or differently-named
        functions will fail; adding or removing a function from the bridge without
        updating both the definition and this oracle causes a red test.
        """
        b = ProcessBridge()
        td = b.tool_definition
        assert td.tool_name is ToolName.PROCESS
        actual_names: frozenset[str] = frozenset(f.name for f in td.functions)
        missing = _CANONICAL_PROCESS_FUNCTION_NAMES - actual_names
        extra = actual_names - _CANONICAL_PROCESS_FUNCTION_NAMES
        assert not missing, f"Functions removed from definition: {sorted(missing)}"
        assert not extra, f"Functions added to definition without canonical update: {sorted(extra)}"
        assert len(td.functions) == len(_CANONICAL_PROCESS_FUNCTION_NAMES), (
            f"Duplicate function names in definition: {[f.name for f in td.functions if [g.name for g in td.functions].count(f.name) > 1]}"
        )

    def test_tool_definition_all_descriptions_nonempty(self) -> None:
        """Verify every function in the tool definition carries a non-empty description.

        A bridge function missing a description cannot be used meaningfully by LLM
        tool-calling: providers reject or silently drop tool schemas with empty
        descriptions.
        """
        b = ProcessBridge()
        for func in b.tool_definition.functions:
            assert func.description, f"Function '{func.name}' has empty description"

    def test_all_names_start_with_process(self) -> None:
        """Verify all function names start with 'process.'."""
        b = ProcessBridge()
        for func in b.tool_definition.functions:
            assert func.name.startswith("process.")

    def test_dispatch_suffix_resolves_to_callable_coroutine(self) -> None:
        """Verify every tool function maps to a callable async coroutine via the production dispatch rule.

        Mirrors the exact lookup ToolRegistry.execute_tool_call (tools.py:587) performs:

            attr_name = function_name.split('.', maxsplit=1)[-1]

        For every advertised function the derived attribute must exist on the bridge,
        be callable, and be an async coroutine function. A property that raises,
        a non-callable attribute, or a synchronous stub all produce a red test.

        This correctly uses the dispatch suffix ('list', 'list_detailed', 'open')
        rather than the internal implementation methods ('list_processes',
        'list_processes_detailed', 'open_process'), so deleting or renaming the
        shim methods breaks this test.
        """
        b = ProcessBridge()
        for func in b.tool_definition.functions:
            dispatch_name = _CANONICAL_FUNCTION_TO_DISPATCH_METHOD[func.name]
            method = getattr(b, dispatch_name, None)
            assert method is not None, f"{func.name}: no bridge attribute '{dispatch_name}' (dispatch suffix rule)"
            assert callable(method), f"{func.name}: bridge attribute '{dispatch_name}' is not callable"
            assert asyncio.iscoroutinefunction(method), (
                f"{func.name}: '{dispatch_name}' must be an async coroutine; the dispatch layer awaits every bridge call"
            )

    def test_function_parameter_names_match_dispatch_method_signatures(self) -> None:
        """Verify each tool function's declared parameters align with the dispatch-level method signature.

        The tool definition's parameter names are what the LLM sends as JSON keys.
        If the dispatch-level method signature differs from the definition, every LLM
        invocation of that function will produce a TypeError at dispatch time. This
        test uses the production dispatch rule (split suffix) to locate the exact
        method the orchestrator will call, then compares sorted parameter names from
        the tool definition against sorted parameter names in that method's Python
        signature for every one of the 66 functions.
        """
        b = ProcessBridge()
        for func in b.tool_definition.functions:
            dispatch_name = _CANONICAL_FUNCTION_TO_DISPATCH_METHOD[func.name]
            method = getattr(b, dispatch_name)
            sig = inspect.signature(method)
            sig_params: list[str] = [
                p for p in sig.parameters if sig.parameters[p].kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
            ]
            definition_params: list[str] = [p.name for p in func.parameters]
            assert sorted(sig_params) == sorted(definition_params), (
                f"Parameter mismatch for '{func.name}' -> dispatch method '{dispatch_name}': "
                f"definition={sorted(definition_params)}, "
                f"signature={sorted(sig_params)}"
            )

    @staticmethod
    def test_list_function_executes_end_to_end_through_real_registry(process_registry: ToolRegistry) -> None:
        """The advertised process.list runs through the real registry against live PIDs.

        Invokes the advertised function through a real ToolRegistry holding a live,
        initialized ProcessBridge, exactly as the orchestrator would. The result must
        enumerate the current Python test process itself (an independent oracle:
        os.getpid() / 'python' are known to be running), proving the tool definition
        is wired to working functionality rather than merely declared.

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

        Drives process.list_detailed with filter_name='python' end to end. The
        independent oracle is the live OS: every returned record must match the
        filter and the current Python process must be among them, confirming the
        argument is forwarded (not silently dropped) by the production dispatch path.

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

        Confirms the error path: a name that is not backed by a bridge method must
        raise ToolError, proving the dispatcher rejects bogus calls rather than
        swallowing them.

        Args:
            process_registry: Registry with a live process bridge registered.
        """
        with pytest.raises(ToolError):
            _run(process_registry.execute_tool_call("process", "process.this_function_does_not_exist", {}))


class TestAttachEnablesOnSelection:
    """F5: selecting a process row must enable the Attach action.

    Regression gate for ``ProcessPanel._on_process_selected`` (base.py):
    pre-fix it only re-emitted ``process_selected`` and never called
    ``_update_controls_for_state()``, so ``set_action_buttons_enabled`` was
    never re-evaluated on selection and Attach stayed disabled until some
    unrelated attach/detach transition happened to run. This drives a real,
    live ``ProcessBridge`` process listing and a real row selection through
    the actual ``QTableWidget`` selection model, so the test fails if the
    ``_update_controls_for_state()`` call is removed from
    ``_on_process_selected``.
    """

    def test_selecting_process_row_enables_attach_and_reports_pid(self, panel: ProcessPanel, qapp: QApplication) -> None:
        """Selecting a live process row enables Attach and exposes the matching PID.

        Args:
            panel: ProcessPanel fixture instance.
            qapp: Session QApplication fixture from conftest.
        """
        live_bridge = ProcessBridge()
        _run(live_bridge.initialize())
        panel.set_bridge(live_bridge)

        proc_tab = panel._process_tab
        assert not proc_tab._attach_btn.isEnabled(), "Attach must start disabled with nothing selected"

        proc_tab.start_refresh()
        populated = _pump_until(qapp, lambda: proc_tab._process_table.rowCount() > 0)
        assert populated, "live process listing never populated the process table"

        pid_item = proc_tab._process_table.item(0, 0)
        assert pid_item is not None
        expected_pid = int(pid_item.data(Qt.ItemDataRole.DisplayRole))

        proc_tab._process_table.setCurrentCell(0, 0)
        qapp.processEvents()

        assert panel.get_selected_pid() == expected_pid
        assert proc_tab._attach_btn.isEnabled(), "Attach must become enabled once a process row is selected"
        assert proc_tab._terminate_btn.isEnabled(), "Terminate must also become enabled once a process row is selected"


class TestProcessTablesReadOnly:
    """F6: process-related tables must reject in-place cell editing.

    Regression gate for ``ProcessTab._build_system_tab`` /
    ``_build_tracked_tab`` / ``_build_info_tab``: pre-fix none of the three
    tables (system process list, tracked processes, environment variables)
    called ``setEditTriggers(NoEditTriggers)``, so Qt's default
    ``AllEditTriggers`` let a user double-click or press F2 on a populated
    cell and overwrite live process data in the view. Each test drives a
    real, shown table through the actual Qt interaction pipeline (F2 on the
    current index) rather than asserting on the property alone, so the test
    fails if the trigger were removed even though the delegate might
    otherwise silently refuse an edit for other reasons.
    """

    @staticmethod
    def _assert_f2_does_not_enter_edit_mode(table: QTableWidget, row: int, col: int, qapp: QApplication) -> None:
        """Drive a real F2 "edit" key press on a cell and confirm no editor opens.

        Args:
            table: The populated table under test.
            row: Row of the cell to attempt to edit.
            col: Column of the cell to attempt to edit.
            qapp: Session QApplication fixture from conftest.
        """
        model = table.model()
        assert model is not None
        index = model.index(row, col)
        table.setCurrentIndex(index)
        QTest.keyClick(table, Qt.Key.Key_F2)
        qapp.processEvents()
        assert table.state() != QAbstractItemView.State.EditingState, (
            f"F2 opened an editor on a table with editTriggers={table.editTriggers()!r}"
        )

    def test_system_process_table_is_read_only(self, panel: ProcessPanel, qapp: QApplication) -> None:
        """The system process table must have NoEditTriggers and refuse an F2 edit.

        Args:
            panel: ProcessPanel fixture instance.
            qapp: Session QApplication fixture from conftest.
        """
        live_bridge = ProcessBridge()
        _run(live_bridge.initialize())
        panel.set_bridge(live_bridge)

        proc_tab = panel._process_tab
        proc_tab.show()
        proc_tab.start_refresh()
        populated = _pump_until(qapp, lambda: proc_tab._process_table.rowCount() > 0)
        assert populated, "live process listing never populated the process table"

        table = proc_tab._process_table
        assert table.editTriggers() == QAbstractItemView.EditTrigger.NoEditTriggers
        self._assert_f2_does_not_enter_edit_mode(table, 0, 1, qapp)
        proc_tab.cleanup()
        qapp.processEvents()

    def test_tracked_process_table_is_read_only(self, panel: ProcessPanel, qapp: QApplication) -> None:
        """The tracked-processes table must have NoEditTriggers and refuse an F2 edit.

        Args:
            panel: ProcessPanel fixture instance.
            qapp: Session QApplication fixture from conftest.
        """
        del panel
        tab = ProcessTab()
        tab.show()
        tab._on_tracked_finished([{"pid": 4, "name": "tracked.exe", "process_type": "target", "status": "running", "registered_at": "now"}])

        table = tab._tracked_table
        assert table.editTriggers() == QAbstractItemView.EditTrigger.NoEditTriggers
        self._assert_f2_does_not_enter_edit_mode(table, 0, 1, qapp)
        tab.cleanup()
        tab.deleteLater()
        qapp.processEvents()

    def test_environment_table_is_read_only(self, panel: ProcessPanel, qapp: QApplication) -> None:
        """The environment-variables table must have NoEditTriggers and refuse an F2 edit.

        Args:
            panel: ProcessPanel fixture instance.
            qapp: Session QApplication fixture from conftest.
        """
        del panel
        tab = ProcessTab()
        tab.show()
        tab._env_table.setRowCount(1)
        tab._env_table.setItem(0, 0, QTableWidgetItem("PATH"))
        tab._env_table.setItem(0, 1, QTableWidgetItem("C:\\Windows"))

        table = tab._env_table
        assert table.editTriggers() == QAbstractItemView.EditTrigger.NoEditTriggers
        self._assert_f2_does_not_enter_edit_mode(table, 0, 0, qapp)
        tab.cleanup()
        tab.deleteLater()
        qapp.processEvents()
