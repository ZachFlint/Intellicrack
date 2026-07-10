# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression tests for the Ghidra and Cutter analysis panels.

Covers the remaining Ghidra/Cutter findings:

* M15 -- ``GhidraPanel._apply_cfg`` must call the graph view's ``fit_to_view``
  after ``load_graph`` so a new CFG is fitted instead of keeping prior zoom.
* M17 -- the function filter must debounce via a single-shot timer instead of
  issuing one bridge query per keystroke (both panels).
* block_clicked -- clicking a CFG block must navigate: Ghidra disassembles the
  block address and switches to the disassembly tab; Cutter seeks to it.
* esil-latch -- loading a new binary must reset the ESIL init latch so ESIL
  memory re-initialises for the new binary's layout.
* splitters -- content splitters must set ``childrenCollapsible(False)`` so a
  pane cannot be dragged to zero width and vanish.
* ghidra tr -- the delete-function prompt must translate a static template,
  not an f-string with the address already interpolated.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSplitter

from intellicrack.bridges.base import BridgeState
from intellicrack.ui.panels import (
    cutter_panel as cutter_module,
    ghidra_panel as ghidra_module,
)
from intellicrack.ui.panels.cutter_debugger_tab import DebuggerTab
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.cutter_search_tab import SearchTab
from intellicrack.ui.panels.cutter_tabs import ESILConsoleTab
from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.graph_view import CFGGraphView


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from types import ModuleType

    from intellicrack.bridges.cutter import CutterBridge
    from intellicrack.bridges.ghidra import GhidraBridge


class _CallCounter:
    """Counts invocations without unittest.mock."""

    def __init__(self) -> None:
        """Initialise the counter at zero."""
        self.count = 0

    def __call__(self, *_args: object, **_kwargs: object) -> None:
        """Record one invocation.

        Args:
            *_args: Ignored positional arguments.
            **_kwargs: Ignored keyword arguments.
        """
        self.count += 1


class _GhidraRecordingBridge:
    """Recording stub capturing get_functions and disassemble calls."""

    def __init__(self) -> None:
        """Initialise a ready BridgeState and empty call logs."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.get_functions_calls: list[str | None] = []
        self.disassemble_calls: list[int] = []

    async def get_functions(self, filter_text: str | None = None) -> list[object]:
        """Record a get_functions invocation.

        Args:
            filter_text: Filter forwarded by the panel.

        Returns:
            list[object]: Always empty; the panel only needs a coroutine.
        """
        self.get_functions_calls.append(filter_text)
        return []

    async def disassemble(self, address: int) -> list[object]:
        """Record a disassemble invocation.

        Args:
            address: Target address requested by the panel.

        Returns:
            list[object]: Always empty; the panel only needs a coroutine.
        """
        self.disassemble_calls.append(address)
        return []


class _CutterRecordingBridge:
    """Recording stub capturing get_functions and seek calls."""

    def __init__(self) -> None:
        """Initialise a ready BridgeState and empty call logs."""
        self.state = BridgeState(connected=True, tool_running=True)
        self.get_functions_calls: list[str | None] = []
        self.seek_calls: list[int] = []

    async def get_functions(self, filter_text: str | None = None) -> list[object]:
        """Record a get_functions invocation.

        Args:
            filter_text: Filter forwarded by the panel.

        Returns:
            list[object]: Always empty; the panel only needs a coroutine.
        """
        self.get_functions_calls.append(filter_text)
        return []

    async def seek(self, address: int) -> None:
        """Record a seek invocation.

        Args:
            address: Target address requested by the panel.
        """
        self.seek_calls.append(address)


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine to completion for deterministic tests.

    The production dispatcher hands coroutines to a background thread; tests need
    in-thread execution so the recording stub observes the call and no
    "coroutine was never awaited" warning is emitted.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Unused success callback.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (event, logger, level, context).
    """
    del on_success, on_error, parent
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(coro)
    finally:
        loop.close()


def _patch_dispatch(module: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``run_bridge_coroutine_logged`` in a panel module with the sync driver.

    Args:
        module: The panel module whose dispatcher should be patched.
        monkeypatch: Pytest monkeypatch fixture (auto-restored after the test).
    """
    monkeypatch.setattr(module, "run_bridge_coroutine_logged", _drive)


@pytest.mark.usefixtures("qapp")
class TestApplyCfgFitsView:
    """M15: _apply_cfg must fit the graph view after loading a new CFG."""

    @staticmethod
    def test_apply_cfg_calls_fit_to_view(monkeypatch: pytest.MonkeyPatch) -> None:
        """Loading basic blocks into the CFG view must trigger fit_to_view once.

        Regression: Ghidra loaded the graph but never fitted it, so a new CFG
        inherited the previous function's zoom and scroll. Cutter already fits;
        Ghidra must match. Reverting the fix removes the fit_to_view call and
        drops the recorder count to zero.
        """
        panel = GhidraPanel()
        assert isinstance(panel._cfg_view, CFGGraphView)
        recorder = _CallCounter()
        monkeypatch.setattr(panel._cfg_view, "fit_to_view", recorder)

        panel._apply_cfg({"blocks": [{"offset": 0x401000, "ops": [{"disasm": "ret"}]}]})

        assert recorder.count == 1, "expected _apply_cfg to fit the graph view exactly once"


@pytest.mark.usefixtures("qapp")
class TestFilterDebounce:
    """M17: rapid typing must produce one query after the pause, not one per key."""

    @staticmethod
    def test_ghidra_filter_is_debounced(monkeypatch: pytest.MonkeyPatch) -> None:
        """Ten keystrokes must issue zero queries until the debounce timer fires.

        Regression: ``textChanged`` was wired straight to ``_on_refresh_functions``,
        firing a full bridge RPC per keystroke (10 concurrent, out-of-order
        queries). The fix debounces through a single-shot timer. Without it, the
        ``get_functions_calls == []`` assertion sees 10 calls and fails.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the dispatcher.
        """
        panel = GhidraPanel()
        bridge = _GhidraRecordingBridge()
        panel._bridge = cast("GhidraBridge", bridge)
        _patch_dispatch(ghidra_module, monkeypatch)

        for i in range(10):
            panel._func_filter.setText(f"f{i}")

        assert bridge.get_functions_calls == [], "no bridge query may fire while typing is in flight"
        assert panel._filter_debounce.isActive(), "a debounce must be pending after the last keystroke"
        assert panel._filter_debounce.isSingleShot(), "the debounce timer must be single-shot"

        panel._filter_debounce.timeout.emit()

        assert bridge.get_functions_calls == ["f9"], f"exactly one query with the final filter must fire, got {bridge.get_functions_calls}"

    @staticmethod
    def test_cutter_filter_is_debounced(monkeypatch: pytest.MonkeyPatch) -> None:
        """Ten keystrokes must issue zero queries until the debounce timer fires.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the dispatcher.
        """
        panel = CutterPanel()
        bridge = _CutterRecordingBridge()
        panel._bridge = cast("CutterBridge", bridge)
        _patch_dispatch(cutter_module, monkeypatch)

        for i in range(10):
            panel._func_filter.setText(f"f{i}")

        assert bridge.get_functions_calls == [], "no bridge query may fire while typing is in flight"
        assert panel._filter_debounce.isActive(), "a debounce must be pending after the last keystroke"
        assert panel._filter_debounce.isSingleShot(), "the debounce timer must be single-shot"

        panel._filter_debounce.timeout.emit()

        assert bridge.get_functions_calls == ["f9"], f"exactly one query with the final filter must fire, got {bridge.get_functions_calls}"


@pytest.mark.usefixtures("qapp")
class TestBlockClickNavigation:
    """block_clicked must navigate to the clicked block's address."""

    @staticmethod
    def test_ghidra_block_click_disassembles_and_switches_tab(monkeypatch: pytest.MonkeyPatch) -> None:
        """A Ghidra CFG block click must disassemble its address and show the disasm tab.

        Regression: ``block_clicked`` was emitted but connected nowhere, so
        clicking a block did nothing. The fix wires it to a navigation handler.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the dispatcher.
        """
        panel = GhidraPanel()
        bridge = _GhidraRecordingBridge()
        panel._bridge = cast("GhidraBridge", bridge)
        _patch_dispatch(ghidra_module, monkeypatch)
        assert isinstance(panel._cfg_view, CFGGraphView)

        panel._cfg_view.block_clicked.emit(0x401234)

        assert bridge.disassemble_calls == [0x401234], "block click must disassemble the block address"
        assert panel._code_tabs.currentWidget() is panel._disasm_view, "block click must show the disassembly tab"

    @staticmethod
    def test_cutter_block_click_seeks_and_switches_tab(monkeypatch: pytest.MonkeyPatch) -> None:
        """A Cutter CFG block click must seek to its address and show the disasm tab.

        Args:
            monkeypatch: Pytest monkeypatch fixture for patching the dispatcher.
        """
        panel = CutterPanel()
        bridge = _CutterRecordingBridge()
        panel._bridge = cast("CutterBridge", bridge)
        _patch_dispatch(cutter_module, monkeypatch)

        panel._cfg_view.block_clicked.emit(0x401234)

        assert bridge.seek_calls == [0x401234], "block click must seek to the block address"
        assert panel._code_tabs.currentWidget() is panel._disasm_view, "block click must show the disassembly tab"


@pytest.mark.usefixtures("qapp")
class TestEsilLatchReset:
    """esil-latch: a new binary must re-arm ESIL memory initialisation."""

    @staticmethod
    def test_reset_esil_state_clears_latch() -> None:
        """reset_esil_state must clear an initialised latch so aeim re-runs."""
        tab = ESILConsoleTab()
        tab._esil_initialised = True
        tab.reset_esil_state()
        assert not tab._esil_initialised

    @staticmethod
    def test_binary_load_resets_esil_latch() -> None:
        """Loading a new binary via the panel hook must reset the ESIL latch.

        Regression: the latch stayed True across binaries, so ESIL eval/step ran
        against the previous binary's memory layout. The load hook now resets it.
        """
        panel = CutterPanel()
        panel._esil_tab._esil_initialised = True
        panel._on_binary_loaded(Path("sample.bin"))
        assert not panel._esil_tab._esil_initialised


@pytest.mark.usefixtures("qapp")
class TestSplittersNotCollapsible:
    """splitters: content splitters must forbid collapsing a pane to zero."""

    @staticmethod
    def test_ghidra_content_splitters(monkeypatch: pytest.MonkeyPatch) -> None:
        """The Ghidra main and left content splitters must be non-collapsible.

        Args:
            monkeypatch: Unused; present for signature symmetry with sibling tests.
        """
        del monkeypatch
        panel = GhidraPanel()
        horizontal = [s for s in panel.findChildren(QSplitter) if s.orientation() == Qt.Orientation.Horizontal]
        assert len(horizontal) == 1, "the Ghidra content area must expose exactly one horizontal splitter"
        main_splitter = horizontal[0]
        assert main_splitter.childrenCollapsible() is False, "main content splitter must be non-collapsible"
        left = main_splitter.widget(0)
        assert isinstance(left, QSplitter)
        assert left.childrenCollapsible() is False, "left code/data splitter must be non-collapsible"

    @staticmethod
    def test_cutter_splitters() -> None:
        """Every splitter owned by the Cutter panel tree must be non-collapsible."""
        panel = CutterPanel()
        splitters = panel.findChildren(QSplitter)
        assert splitters, "the Cutter panel must contain splitters"
        assert all(s.childrenCollapsible() is False for s in splitters), "no Cutter splitter may allow a pane to collapse to zero"

    @staticmethod
    def test_debugger_tab_splitter() -> None:
        """The debugger tab's registers/tabs splitter must be non-collapsible."""
        tab = DebuggerTab()
        splitters = tab.findChildren(QSplitter)
        assert splitters, "the debugger tab must contain a splitter"
        assert all(s.childrenCollapsible() is False for s in splitters)

    @staticmethod
    def test_search_tab_splitter() -> None:
        """The search tab's search/compare splitter must be non-collapsible."""
        tab = SearchTab()
        splitters = tab.findChildren(QSplitter)
        assert splitters, "the search tab must contain a splitter"
        assert all(s.childrenCollapsible() is False for s in splitters)


class TestGhidraDeletePromptStaticTemplate:
    """ghidra tr: the delete prompt must translate a static template string."""

    @staticmethod
    def test_delete_prompt_tr_source_is_static() -> None:
        """The delete confirmation must call tr on a static format template.

        Regression: ``self.tr(f"Delete function '{name}' at 0x{addr:X}?")`` passed
        a runtime-built string to tr, so the interpolated address became part of
        the translation key and defeated i18n. The fix translates a static
        template and substitutes afterwards. This inspects the module source so
        reintroducing the f-string turns the test red.
        """
        source_path = ghidra_module.__file__
        assert source_path is not None
        source = Path(source_path).read_text(encoding="utf-8")

        assert 'self.tr(f"Delete function' not in source, "tr must not receive an f-string (i18n key must be static)"
        assert "self.tr(\"Delete function '{name}' at 0x{addr:X}?\").format(" in source, (
            "delete prompt must translate a static template and substitute afterwards"
        )
