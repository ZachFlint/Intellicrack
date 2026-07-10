# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for audit F3/F18 (detach) and N2 (dock readability).

* **F3 / F18** -- a detached tool panel must render its body immediately in the
  floating window (not stay blank until re-dock), and re-docking must restore
  the tab at its original position (not append it at the end).
* **N2** -- analysis table headers carry tooltips so a header truncated in a
  narrow dock stays readable on hover.

Tests drive the real ``ToolOutputPanel`` / ``BridgeAnalysisPanel`` widgets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel
from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


@pytest.mark.usefixtures("qapp")
class TestDetachRedock:
    """F3/F18 detach and re-dock behaviours."""

    @staticmethod
    def test_detached_panel_body_is_visible_immediately() -> None:
        """A detached panel's central widget must be visible without re-docking."""
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            index = panel.tab_widget.indexOf(panel.analysis_panel)
            assert index >= 0

            window = panel.detach_tab(index)
            assert window is not None
            central = window.centralWidget()
            assert central is not None
            assert central.isVisible(), "detached tool panel body stayed hidden (F18 blank-body regression)"
            window.close()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_redock_restores_original_tab_index() -> None:
        """Re-docking must return the tab to its original position, not the end."""
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            panel.add_script_panel()
            panel.add_stack_panel()

            target = panel.analysis_panel
            original_index = panel.tab_widget.indexOf(target)
            total_before = panel.tab_widget.count()
            minimum_tabs = 3
            assert original_index >= 0
            assert total_before >= minimum_tabs

            window = panel.detach_tab(original_index)
            assert window is not None
            panel._reattach_panel(window.panel, window.panel_title)

            assert panel.tab_widget.count() == total_before, "tab count changed across detach/re-dock"
            assert panel.tab_widget.indexOf(target) == original_index, "re-docked tab did not return to its original index (F3 regression)"
        finally:
            panel.deleteLater()


@pytest.mark.usefixtures("qapp")
def test_analysis_table_headers_carry_tooltips(qapp: QApplication) -> None:
    """N2: analysis table headers must expose their full label via tooltip.

    Args:
        qapp: The shared QApplication fixture.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        header = panel._strings_table.horizontalHeader()
        assert header is not None
        for col in range(panel._strings_table.columnCount()):
            item = panel._strings_table.horizontalHeaderItem(col)
            assert item is not None
            assert item.toolTip() == item.text(), f"header column {col} lacks a full-text tooltip (N2)"
            assert item.toolTip(), "header tooltip is empty"
    finally:
        panel.deleteLater()
