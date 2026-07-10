# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-05 binary-load-path audit cluster.

Covers:

* **N1 / F11** -- optimistic load UI (enabling tool buttons, the status label)
  is deferred until the async load succeeds and the format is supported; a
  failed or unsupported load leaves tools disabled and no phantom "loaded"
  label, clearing any stale analysis.
* **F8 / N4** -- a real ``BridgeAnalysisSummary`` populates the Strings and
  Functions tables (rather than being stringified away).
* **N3** -- the intermediate "Loaded - not analyzed" header state.
* **F1** -- a section virtual address maps to the correct raw file offset, and
  the analysis panel's ``address_navigate`` signal is wired into the shared
  address chain (it was emitted but never connected before).
* **duplicate-tab** -- exactly one "Analysis" tab per binary.

Every test drives real widgets (``ToolOutputPanel`` / ``BridgeAnalysisPanel`` /
``MainWindow``) with real ``BridgeAnalysisSummary`` data; modal dialogs are
recorded (not mocked away silently) to keep the offscreen event loop from
blocking.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    FunctionInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
)
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel
from intellicrack.ui.tools import ToolOutputPanel

from .conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_POLL_INTERVAL_S: float = 0.01
_MAX_WAIT_S: float = 5.0
_TEXT_VADDR: int = 0x1000
_TEXT_VSIZE: int = 0x2000
_TEXT_RAW_OFFSET: int = 0x400


def _make_summary(binary_name: str = "sample.exe") -> BridgeAnalysisSummary:
    """Build a real, non-trivial analysis summary.

    Args:
        binary_name: Name recorded on the summary.

    Returns:
        BridgeAnalysisSummary: A summary with one string, one function and one
            ``.text`` section carrying a known raw file offset.
    """
    return BridgeAnalysisSummary(
        binary_name=binary_name,
        strings=[StringInfo(address=0x401000, value="license invalid", encoding="ascii", section=".rdata")],
        imports=[ImportInfo(dll="kernel32.dll", function="IsDebuggerPresent", ordinal=None, address=0x402000)],
        exports=[],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=_TEXT_VADDR,
                virtual_size=_TEXT_VSIZE,
                raw_size=0x1800,
                characteristics=0x60000020,
                entropy=6.5,
                raw_offset=_TEXT_RAW_OFFSET,
            ),
        ],
        functions=[
            FunctionInfo(
                name="check_license",
                address=0x1100,
                size=256,
                calling_convention="stdcall",
                return_type="int",
                parameters=[],
                local_variables=[],
            ),
        ],
        format_info="PE32+",
        architecture="x86_64",
        source_bridges=["cutter"],
        analysis_notes=[],
        complete=True,
    )


def _pump_until(qapp: QApplication, predicate: Callable[[], object], *, timeout_s: float = _MAX_WAIT_S) -> None:
    """Pump the Qt event loop until ``predicate()`` is truthy or time runs out.

    Args:
        qapp: QApplication used to dispatch queued cross-thread signals.
        predicate: Zero-argument callable returning a truthiness value.
        timeout_s: Maximum wall-clock time to keep pumping, in seconds.
    """
    deadline = time.monotonic() + timeout_s
    while not predicate() and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    qapp.processEvents()


def _count_tabs_titled(panel: ToolOutputPanel, title: str) -> int:
    """Count tabs in the panel's tab widget whose label equals ``title``.

    Args:
        panel: The tool output panel to inspect.
        title: Exact tab label to match.

    Returns:
        int: Number of matching tabs.
    """
    return sum(1 for i in range(panel.tab_widget.count()) if panel.tab_widget.tabText(i) == title)


@pytest.fixture
def main_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Construct a real, unshown ``MainWindow`` with a no-op sandbox manager.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real Config instance from the shared fixtures.
        real_orchestrator: Real Orchestrator instance from the shared fixtures.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        MainWindow: A constructed, unshown MainWindow instance.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


@pytest.mark.usefixtures("qapp")
class TestAnalysisPanelPopulation:
    """F8/N4, N3 and F1-mapping behaviours on the real analysis panel."""

    @staticmethod
    def test_update_bridge_analysis_populates_strings_and_functions() -> None:
        """A real summary must fill the Strings and Functions tables (F8 / N4)."""
        panel = ToolOutputPanel()
        try:
            summary = _make_summary()
            panel.update_bridge_analysis(summary)
            assert panel.analysis_panel is not None
            assert panel.analysis_panel._strings_table.rowCount() == len(summary.strings)
            assert panel.analysis_panel._functions_table.rowCount() == len(summary.functions)
            assert panel.analysis_panel._sections_table.rowCount() == len(summary.sections)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_mark_loaded_shows_intermediate_state_then_analysis_name() -> None:
        """N3: header distinguishes "loaded, not analyzed" from analyzed."""
        panel = BridgeAnalysisPanel()
        try:
            panel.mark_loaded("sample.exe")
            header = panel._binary_label.text()
            assert "sample.exe" in header
            assert "not analyzed" in header.lower()
            assert panel.current_analysis is None

            panel.set_analysis(_make_summary("sample.exe"))
            assert panel._binary_label.text() == "sample.exe"
            assert panel.current_analysis is not None
        finally:
            panel.deleteLater()

    @staticmethod
    def test_va_maps_to_raw_file_offset() -> None:
        """F1: a VA inside a section maps to ``raw_offset + (va - vaddr)``."""
        panel = ToolOutputPanel()
        try:
            panel.update_bridge_analysis(_make_summary())
            inside = _TEXT_VADDR + 0x50
            assert panel._map_va_to_file_offset(inside) == _TEXT_RAW_OFFSET + 0x50
            assert panel._map_va_to_file_offset(_TEXT_VADDR + _TEXT_VSIZE + 1) is None
        finally:
            panel.deleteLater()

    @staticmethod
    def test_address_navigate_is_wired_into_address_chain(qapp: QApplication) -> None:
        """F1: the panel's ``address_navigate`` reaches the shared address signal.

        Before the fix this signal was emitted but never connected, so Section
        VA links were dead. Emitting it must now re-emit ``address_clicked``.

        Args:
            qapp: QApplication fixture used to dispatch the signal.
        """
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            received: list[int] = []
            _ = panel.address_clicked.connect(received.append)
            assert panel.analysis_panel is not None
            panel.analysis_panel.address_navigate.emit(_TEXT_VADDR)
            _pump_until(qapp, lambda: bool(received))
            assert received == [_TEXT_VADDR]
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
class TestLoadPathMainWindow:
    """N1/F11/duplicate-tab behaviours on the real MainWindow."""

    @staticmethod
    def test_failed_load_leaves_tools_disabled(
        qapp: QApplication,
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """N1: a failing async load must not leave tool buttons enabled.

        Args:
            qapp: QApplication fixture used to pump queued signals.
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        criticals: list[tuple[object, ...]] = []
        monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda *a, **_k: criticals.append(a)))

        async def _raise(*_a: object, **_k: object) -> BinaryInfo:
            await asyncio.sleep(0)
            msg = "no active session"
            raise RuntimeError(msg)

        async def _noop_session(*_a: object, **_k: object) -> None:
            await asyncio.sleep(0)

        monkeypatch.setattr(main_window._orchestrator, "add_binary", _raise)
        monkeypatch.setattr(main_window, "_ensure_active_session", _noop_session)
        for button in main_window._binary_dependent_buttons:
            button.setEnabled(False)

        main_window._load_binary(Path(sys.executable))
        _pump_until(qapp, lambda: bool(criticals))

        assert main_window.current_binary is None, "current_binary set despite a failed load"
        assert all(not button.isEnabled() for button in main_window._binary_dependent_buttons), (
            "tool buttons were enabled despite the load failing (optimistic UI was not deferred)"
        )

    @staticmethod
    def test_unsupported_format_disables_tools_and_clears_analysis(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """F11: an unknown-format result disables tools and clears stale analysis.

        Args:
            main_window: Real MainWindow under test.
            monkeypatch: Pytest monkeypatch fixture.
        """
        warnings: list[tuple[object, ...]] = []
        monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **_k: warnings.append(a)))

        # Seed a prior binary's analysis so the clear is observable.
        main_window.tool_panel.update_bridge_analysis(_make_summary("old.bin"))
        assert main_window.tool_panel.analysis_panel is not None
        assert main_window.tool_panel.analysis_panel.current_analysis is not None
        for button in main_window._binary_dependent_buttons:
            button.setEnabled(True)

        unknown = BinaryInfo(
            path=Path("garbage.bin"),
            name="garbage.bin",
            size=10,
            sha256="0" * 64,
            file_type="unknown",
            architecture="unknown",
            is_64bit=False,
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
        )
        main_window._on_binary_loaded(unknown)

        assert warnings, "no unsupported-format warning was shown"
        assert main_window.current_binary is None
        assert all(not button.isEnabled() for button in main_window._binary_dependent_buttons), (
            "tools were enabled for an unsupported format"
        )
        assert main_window.tool_panel.analysis_panel.current_analysis is None, "stale analysis was not cleared (F11)"

    @staticmethod
    def test_single_analysis_tab_after_bridge_analysis(qapp: QApplication, main_window: MainWindow) -> None:
        """duplicate-tab: routing a real summary must yield exactly one Analysis tab.

        Args:
            qapp: QApplication fixture used to pump queued signals.
            main_window: Real MainWindow under test.
        """
        main_window.tool_panel.add_analysis_panel()
        main_window.bridge_analysis_received.emit(_make_summary())
        qapp.processEvents()

        assert _count_tabs_titled(main_window.tool_panel, "Analysis") == 1, (
            "a second (stringified) Analysis tab was created (duplicate-tab regression)"
        )
