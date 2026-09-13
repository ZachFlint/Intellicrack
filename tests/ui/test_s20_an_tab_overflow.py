# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for S20-D16 (Analysis Output share): sub-tab strip overflow degrade.

``BridgeAnalysisPanel`` hosts its own ``QTabWidget`` (Strings / Imports /
Exports / Functions / Sections / Notes). At the fresh-launch tool-pane width
(~530px, per the S20 live-audit sweep) that six-tab strip clips mid-glyph
with no way to reach the hidden tabs. This mirrors the fix already applied to
``ToolOutputPanel``'s own tab strip in ``ui/tools.py``: an explicit
``ElideRight`` elide mode plus enabled scroll buttons so a clipped tab
degrades to a legible partial label ("Str...") with a reachable nav arrow,
instead of Qt's default of silently shrinking every label illegibly with no
indication more tabs exist.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt

from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_analysis_tab_bar_elides_overflowing_labels(qapp: QApplication) -> None:
    """The Strings/Imports/.../Notes tab bar must elide overflowing labels, not clip them.

    Qt's tab bar defaults to ``TextElideMode.ElideNone`` (verified by the
    sibling ``ElideRight`` regression gates already in this test suite, e.g.
    ``test_s20_pp_tab_overflow.py``), so a clipped label is otherwise cut off
    mid-glyph with no ellipsis at all.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        bar = panel.tab_widget.tabBar()
        assert bar is not None
        assert bar.elideMode() == Qt.TextElideMode.ElideRight, (
            f"analysis tab bar elideMode()={bar.elideMode()!r} -- a tab label clipped by a "
            "narrow tool pane is cut off mid-glyph instead of degrading to a legible 'Str...'"
        )
    finally:
        panel.deleteLater()
        qapp.processEvents()


def test_analysis_tab_widget_keeps_scroll_buttons_enabled(qapp: QApplication) -> None:
    """The analysis tab widget must keep scroll-button paging enabled so every tab stays reachable.

    Args:
        qapp: QApplication fixture required by Qt widgets.
    """
    _ = qapp
    panel = BridgeAnalysisPanel()
    try:
        assert panel.tab_widget.usesScrollButtons() is True, (
            "analysis tab widget usesScrollButtons() is False -- a tab pushed past the "
            "viewport by the six-tab strip has no chevron control to bring it into view"
        )
        bar = panel.tab_widget.tabBar()
        assert bar is not None
        assert bar.usesScrollButtons() is True
    finally:
        panel.deleteLater()
        qapp.processEvents()
