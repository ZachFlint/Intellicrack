# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the GUI audit findings in ``ui.tools``.

Each test class targets one audit finding and fails against the pre-fix
behaviour:

* ``TestH21BridgeCleanupDoesNotBlock`` (H21): ``_cleanup_bridge`` (invoked on
  every interactive tab close) must dispatch a bridge's ``detach``/
  ``shutdown``/``stop`` coroutines onto the persistent background bridge loop
  via ``run_bridge_coroutine_async`` instead of blocking the calling (GUI)
  thread with an unbounded ``run_bridge_coroutine`` wait.
* ``TestH31CloseEmbeddedToolsShutsDownBridges`` (H31): ``close_embedded_tools``
  (invoked from ``MainWindow.closeEvent`` on every app shutdown) must actually
  await each bridge's teardown coroutine -- via the bounded, synchronous
  ``_cleanup_bridge_blocking`` -- before nulling the reference, instead of
  dropping the bridge object without ever calling ``shutdown()`` and leaking
  its OS handles.
* ``TestM32GenericTabContentRouting`` (M32): ``set_tab_content``/
  ``set_tab_info``/``clear_tab`` must actually update visible content for
  every ``OutputType``, not just ``"log"``, and ``display_analysis_result``
  must route a ``BridgeAnalysisSummary`` into ``BridgeAnalysisPanel``'s
  structured tables instead of being silently discarded.
* ``TestM33X64dbgTabRestoration`` (M33): ``restore_tab_state`` must be able to
  reopen the ``"x64dbg"``/``"x32dbg"`` tabs that ``save_tab_state`` records.
* ``TestM69MainSplitterCannotCollapse`` (M69): ``main_splitter`` must not let
  a drag collapse the tab area or the Functions/XRefs navigator to 0 width.
* ``TestL19ToolTabSplitterCannotCollapse`` (L19): ``ToolTab._splitter`` must
  not let a drag collapse the Details/info panel to 0 height.

All tests drive real ``ToolOutputPanel``/``ToolTab`` instances (and real
``ToolBridgeBase`` subclasses) under an offscreen ``QApplication``. None of
these tests spawn a real OS process.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.core.types import BridgeAnalysisSummary, StringInfo, ToolDefinition, ToolName
from intellicrack.ui.tools import _LEFT_MIN_WIDTH, _RIGHT_MIN_WIDTH, ToolOutputPanel, ToolTab


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


class _RecordingBridge(ToolBridgeBase):
    """Minimal concrete ``ToolBridgeBase`` whose ``shutdown`` records its progress.

    ``shutdown_started`` is set the instant the coroutine begins running and
    ``shutdown_completed`` is set only after an optional artificial delay,
    letting tests distinguish "dispatched but not finished yet" from
    "actually completed" without any mocking of the bridge itself.
    """

    def __init__(self, tool_name: ToolName, *, delay_s: float = 0.0) -> None:
        """Initialize the recording bridge.

        Args:
            tool_name: ``ToolName`` this bridge reports as its identity.
            delay_s: Seconds ``shutdown`` sleeps before completing, used to
                simulate a slow external tool RPC.
        """
        super().__init__()
        self._tool_name = tool_name
        self._delay_s = delay_s
        self.shutdown_started: threading.Event = threading.Event()
        self.shutdown_completed: threading.Event = threading.Event()

    @property
    def name(self) -> ToolName:
        """The configured tool name.

        Returns:
            ToolName: The tool name enum value passed at construction.
        """
        return self._tool_name

    @property
    def tool_definition(self) -> ToolDefinition:
        """A minimal tool definition for tests.

        Returns:
            ToolDefinition: Definition with no callable functions.
        """
        return ToolDefinition(tool_name=self._tool_name, description="test bridge", functions=[])

    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialize.

        Args:
            tool_path: Unused tool path.
        """
        del tool_path

    async def shutdown(self) -> None:
        """Record start/completion, optionally sleeping to simulate a slow RPC."""
        self.shutdown_started.set()
        if self._delay_s:
            await asyncio.sleep(self._delay_s)
        self.shutdown_completed.set()
        await super().shutdown()

    async def is_available(self) -> bool:
        """Report the bridge as always available.

        Returns:
            bool: Always True.
        """
        return True


class _FakeGhidraWidget(QWidget):
    """Minimal widget structurally matching ``GhidraWidgetProtocol``.

    Stands in for the real Ghidra panel so ``_on_tab_close_requested`` can be
    driven through its real matching logic (``panel_registry``) without
    constructing the actual Ghidra integration.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self) -> None:
        """Initialize the fake widget with no tool running."""
        super().__init__()
        self.stop_tool_called: bool = False

    def start_tool(self) -> bool:
        """Report a successful start without doing real work.

        Returns:
            bool: Always True.
        """
        return True

    def stop_tool(self) -> bool:
        """Record that teardown was requested and emit ``tool_closed``.

        Returns:
            bool: Always True.
        """
        self.stop_tool_called = True
        self.tool_closed.emit()
        return True

    def set_bridge(self, bridge: object) -> None:
        """Discard the bridge; this fake does not forward it anywhere.

        Args:
            bridge: The bridge instance (unused).
        """
        del bridge

    def load_binary(self, binary_path: Path) -> bool:
        """Report failure without touching the filesystem.

        Args:
            binary_path: Path to the binary (unused).

        Returns:
            bool: Always False.
        """
        del binary_path
        return False


@pytest.mark.usefixtures("qapp")
class TestH21BridgeCleanupDoesNotBlock:
    """H21: bridge cleanup on tab close must not block the GUI thread."""

    @staticmethod
    def test_h21_cleanup_bridge_dispatches_asynchronously_and_completes(qtbot: QtBot) -> None:
        """``_cleanup_bridge`` returns promptly and finishes teardown on the background loop.

        Pre-fix, ``_cleanup_bridge`` was a ``@staticmethod`` that resolved
        ``run_bridge_coroutine`` (the blocking variant, no ``timeout_s``) and
        called ``run_coro(method())`` directly, so this call would not return
        until the full simulated RPC latency had elapsed. Post-fix the
        teardown coroutine is dispatched via ``run_bridge_coroutine_async``
        onto the persistent background bridge loop, so the call must return
        long before the delayed ``shutdown`` completes.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the async
                worker's completion.
        """
        panel = ToolOutputPanel()
        bridge = _RecordingBridge(ToolName.GHIDRA, delay_s=0.6)
        try:
            start = time.monotonic()
            panel._cleanup_bridge(bridge, "ghidra_bridge")
            dispatch_elapsed = time.monotonic() - start

            assert dispatch_elapsed < 0.3, (
                f"_cleanup_bridge blocked the calling thread for {dispatch_elapsed:.3f}s; "
                "teardown appears to be awaited synchronously instead of dispatched"
            )
            assert not bridge.shutdown_completed.is_set(), "shutdown already completed synchronously before dispatch returned"

            qtbot.waitUntil(bridge.shutdown_completed.is_set, timeout=5000)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_h21_tab_close_dispatches_bridge_cleanup_asynchronously(qtbot: QtBot) -> None:
        """Clicking a tab's close button must not freeze the GUI thread on a slow bridge.

        Drives ``_on_tab_close_requested`` -- the real slot connected to
        ``tabCloseRequested`` -- for a tab matched to a Ghidra-like widget and
        bridge. Pre-fix this call would block until the bridge's ``shutdown``
        RPC finished; post-fix it must return immediately while the teardown
        continues on the background loop.

        Args:
            qtbot: pytest-qt bot used to pump the event loop for the async
                worker's completion.
        """
        panel = ToolOutputPanel()
        widget = _FakeGhidraWidget()
        bridge = _RecordingBridge(ToolName.GHIDRA, delay_s=0.6)
        panel.tab_widget.addTab(widget, "Ghidra")
        panel._ghidra_widget = widget
        panel.ghidra_bridge = bridge
        index = panel.tab_widget.indexOf(widget)
        try:
            start = time.monotonic()
            panel._on_tab_close_requested(index)
            dispatch_elapsed = time.monotonic() - start

            assert dispatch_elapsed < 0.3, f"tab close blocked the GUI thread for {dispatch_elapsed:.3f}s waiting on the bridge RPC"
            assert widget.stop_tool_called
            assert panel.ghidra_bridge is None
            assert not bridge.shutdown_completed.is_set(), "shutdown already completed synchronously before the handler returned"

            qtbot.waitUntil(bridge.shutdown_completed.is_set, timeout=5000)
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestH31CloseEmbeddedToolsShutsDownBridges:
    """H31: close_embedded_tools must await bridge teardown, not just drop the reference."""

    @staticmethod
    def test_h31_close_embedded_tools_shuts_down_process_bridge_synchronously() -> None:
        """``close_embedded_tools`` must actually call ``ProcessBridge.shutdown``.

        Pre-fix, the bridge-clearing loop only did
        ``setattr(self, "process_bridge", None)`` -- ``shutdown()`` was never
        invoked, so ``ProcessBridge``'s tracked Win32 handles (attached
        process, mapped sections, pipes/devices) leaked on every app exit.
        Post-fix ``_cleanup_bridge_blocking`` is called first and blocks
        (bounded by a timeout) until teardown genuinely completes, so
        ``shutdown_completed`` must already be set by the time this method
        returns.
        """
        panel = ToolOutputPanel()
        bridge = _RecordingBridge(ToolName.PROCESS, delay_s=0.05)
        panel.process_bridge = bridge
        try:
            panel.close_embedded_tools()

            assert bridge.shutdown_completed.is_set(), (
                "process_bridge.shutdown() was never invoked by close_embedded_tools(); its Win32 handles were never released"
            )
            assert panel.process_bridge is None
        finally:
            panel.deleteLater()

    @staticmethod
    def test_h31_close_embedded_tools_shuts_down_every_bridge_type() -> None:
        """Every bridge attribute in the teardown loop must be shut down, not just process_bridge.

        Pre-fix, the loop unconditionally nulled every bridge attribute
        (``x64dbg_bridge``, ``ghidra_bridge``, ``cutter_bridge``,
        ``frida_bridge``, ``process_bridge``) without invoking any teardown
        method on any of them. Post-fix each one is torn down via
        ``_cleanup_bridge_blocking`` before being nulled.
        """
        panel = ToolOutputPanel()
        bridges: dict[str, _RecordingBridge] = {
            "x64dbg_bridge": _RecordingBridge(ToolName.X64DBG, delay_s=0.02),
            "ghidra_bridge": _RecordingBridge(ToolName.GHIDRA, delay_s=0.02),
            "cutter_bridge": _RecordingBridge(ToolName.CUTTER, delay_s=0.02),
            "frida_bridge": _RecordingBridge(ToolName.FRIDA, delay_s=0.02),
            "process_bridge": _RecordingBridge(ToolName.PROCESS, delay_s=0.02),
        }
        for attr_name, bridge in bridges.items():
            setattr(panel, attr_name, bridge)
        try:
            panel.close_embedded_tools()

            for attr_name, bridge in bridges.items():
                assert bridge.shutdown_completed.is_set(), f"{attr_name}.shutdown() was never invoked by close_embedded_tools()"
                assert getattr(panel, attr_name) is None, f"{attr_name} was not cleared after teardown"
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM32GenericTabContentRouting:
    """M32: set_tab_content/set_tab_info/clear_tab must work for every OutputType."""

    @staticmethod
    def test_m32_set_tab_content_creates_and_populates_generic_tab() -> None:
        """A non-``"log"`` ``OutputType`` with no native panel gets a real, populated tab.

        Pre-fix, ``set_tab_content`` only looked up ``self.tabs.get(...)``,
        which was never populated for any type other than ``"log"``, so this
        call was a silent no-op. Post-fix it creates a real ``ToolTab`` on
        demand.
        """
        panel = ToolOutputPanel()
        try:
            panel.set_tab_content("binary", "binary blob text")

            tab = panel.tabs.get("binary")
            assert tab is not None, "no generic tab was created for a non-log OutputType"
            assert tab.code_display.toPlainText() == "binary blob text"
            assert panel.find_tab_by_title("Binary") >= 0
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m32_set_tab_info_populates_info_panel() -> None:
        """``set_tab_info`` must populate the Details header/content for a non-log tab.

        Pre-fix this was a silent no-op for any ``OutputType`` other than
        ``"log"`` because ``self.tabs`` never contained the key.
        """
        panel = ToolOutputPanel()
        try:
            panel.set_tab_info("binary", "Header", "info body")

            tab = panel.tabs.get("binary")
            assert tab is not None
            assert tab._info_header.text() == "Header"
            assert tab._info_content.text() == "info body"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m32_clear_tab_clears_generic_content() -> None:
        """``clear_tab`` must actually clear content for a generically-created tab."""
        panel = ToolOutputPanel()
        try:
            panel.set_tab_content("binary", "some content")
            panel.clear_tab("binary")

            tab = panel.tabs["binary"]
            assert not tab.code_display.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m32_display_analysis_result_routes_bridge_summary_into_analysis_panel() -> None:
        """A ``BridgeAnalysisSummary`` must populate ``BridgeAnalysisPanel``'s real tables.

        Pre-fix, ``display_analysis_result`` always routed through
        ``set_tab_content``, which is a no-op for ``"analysis"`` (never a key
        in ``self.tabs``) -- the structured summary was discarded entirely.
        Post-fix a ``BridgeAnalysisSummary`` for the ``"analysis"`` tab is
        routed directly into ``BridgeAnalysisPanel.set_analysis``.
        """
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            summary = BridgeAnalysisSummary(
                binary_name="target.exe",
                strings=[StringInfo(address=0x1000, value="hello", encoding="ascii", section=".rdata")],
                imports=[],
                exports=[],
                sections=[],
                functions=[],
                format_info="PE",
                architecture="x86_64",
                source_bridges=["ghidra"],
                analysis_notes=["note"],
                complete=True,
            )

            panel.display_analysis_result("analysis", summary)

            assert panel.analysis_panel is not None
            assert panel.analysis_panel._strings_table.rowCount() == 1
            item = panel.analysis_panel._strings_table.item(0, 1)
            assert item is not None
            assert item.text() == "hello"
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM33X64dbgTabRestoration:
    """M33: restore_tab_state must be able to reopen x64dbg/x32dbg tabs."""

    @staticmethod
    def test_m33_x64dbg_tab_reopens_on_restore() -> None:
        """A saved ``"x64dbg"`` tab name must reopen the x64dbg tab on restore.

        Pre-fix, ``tab_openers`` had no ``"x64dbg"``/``"x32dbg"`` entries, so
        ``opener = tab_openers.get(tab_name)`` resolved to ``None`` and the
        debugger tab was silently dropped on restore.
        """
        state: dict[str, object] = {
            "tab_names": ["x64dbg"],
            "active_index": 0,
            "splitter_sizes": [600, 200],
        }
        panel = ToolOutputPanel()
        try:
            panel.restore_tab_state(state)

            idx = panel.find_tab_by_title("x64dbg")
            assert idx >= 0, "x64dbg tab was not reopened by restore_tab_state"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m33_x32dbg_tab_reopens_on_restore() -> None:
        """A saved ``"x32dbg"`` tab name must reopen the 32-bit x64dbg tab on restore."""
        state: dict[str, object] = {
            "tab_names": ["x32dbg"],
            "active_index": 0,
            "splitter_sizes": [600, 200],
        }
        panel = ToolOutputPanel()
        try:
            panel.restore_tab_state(state)

            idx = panel.find_tab_by_title("x32dbg")
            assert idx >= 0, "x32dbg tab was not reopened by restore_tab_state"
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestM69MainSplitterCannotCollapse:
    """M69: main_splitter must not let a drag hide the tab area or the navigator."""

    @staticmethod
    def test_m69_children_collapsible_is_false() -> None:
        """``main_splitter`` must have ``childrenCollapsible`` disabled.

        QSplitter defaults to ``childrenCollapsible=True``, which lets a
        dragged handle snap a child to 0 width regardless of its
        ``minimumWidth``.
        """
        panel = ToolOutputPanel()
        try:
            assert panel.main_splitter.childrenCollapsible() is False, "main_splitter left childrenCollapsible at its Qt default of True"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_m69_dragging_handle_to_edge_cannot_collapse_right_navigator() -> None:
        """Dragging the handle fully right must not collapse the Functions/XRefs navigator.

        Pre-fix (``childrenCollapsible=True``), Qt lets the drag snap the
        right panel to 0 width regardless of ``setMinimumWidth``. Post-fix
        the right panel must clamp at its minimum width.
        """
        panel = ToolOutputPanel()
        try:
            panel.resize(1000, 600)
            panel.show()
            QApplication.processEvents()

            width = panel.main_splitter.width()
            panel.main_splitter.moveSplitter(width, 1)
            QApplication.processEvents()

            sizes = panel.main_splitter.sizes()
            assert sizes[1] >= _RIGHT_MIN_WIDTH, (
                f"right navigator collapsed to {sizes[1]}px when dragged to the edge; "
                f"expected it to clamp at its minimum of {_RIGHT_MIN_WIDTH}px"
            )
        finally:
            panel.hide()
            panel.deleteLater()

    @staticmethod
    def test_m69_dragging_handle_to_edge_cannot_collapse_left_tab_area() -> None:
        """Dragging the handle fully left must not collapse the tab area.

        Pre-fix (``childrenCollapsible=True``), Qt lets the drag snap the
        left panel to 0 width regardless of ``setMinimumWidth``. Post-fix
        the left panel must clamp at its minimum width.
        """
        panel = ToolOutputPanel()
        try:
            panel.resize(1000, 600)
            panel.show()
            QApplication.processEvents()

            panel.main_splitter.moveSplitter(0, 1)
            QApplication.processEvents()

            sizes = panel.main_splitter.sizes()
            assert sizes[0] >= _LEFT_MIN_WIDTH, (
                f"left tab area collapsed to {sizes[0]}px when dragged to the edge; "
                f"expected it to clamp at its minimum of {_LEFT_MIN_WIDTH}px"
            )
        finally:
            panel.hide()
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestL19ToolTabSplitterCannotCollapse:
    """L19: ToolTab's internal splitter must not let a drag hide the info panel."""

    @staticmethod
    def test_l19_children_collapsible_is_false() -> None:
        """``ToolTab._splitter`` must have ``childrenCollapsible`` disabled."""
        tab = ToolTab("Log", "python")
        try:
            assert tab._splitter.childrenCollapsible() is False, "ToolTab._splitter left childrenCollapsible at its Qt default of True"
        finally:
            tab.deleteLater()

    @staticmethod
    def test_l19_dragging_handle_to_bottom_cannot_collapse_info_panel() -> None:
        """Dragging the handle fully down must not collapse the Details/info panel to 0 height.

        Pre-fix (``childrenCollapsible=True``), Qt lets the drag snap the
        info panel to exactly 0 height regardless of its layout content.
        Post-fix it must clamp at a positive height.
        """
        tab = ToolTab("Log", "python")
        try:
            tab.resize(500, 400)
            tab.show()
            QApplication.processEvents()

            height = tab._splitter.height()
            tab._splitter.moveSplitter(height, 1)
            QApplication.processEvents()

            sizes = tab._splitter.sizes()
            assert sizes[1] > 0, "info panel collapsed to 0 height when dragged to the bottom edge"
        finally:
            tab.hide()
            tab.deleteLater()
