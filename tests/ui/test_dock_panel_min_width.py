# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for audit N2 -- docked tool panels clipped at default dock width.

Before the fix, ``ToolOutputPanel``'s left dock column (hosting the
Frida/Cutter/Ghidra tabs) and right dock column (function list/xref panel)
each carried a static ``setMinimumWidth`` floor with no relationship to what
the embedded content actually needs to render without clipping -- the Frida
panel alone has a ``minimumSizeHint`` of ~991px, far above both the static
240px floor and the 600px default split. Because ``main_splitter`` disables
child collapsing but never raises its floor to match, the splitter was free
to squeeze the active tab narrower than it could render.

The fix keeps the static constants as an absolute floor but layers a real
measurement on top: the right column's floor is computed once from its
fixed children's own ``minimumSizeHint``, and the left column's floor is
resynced on every tab change to the currently active tab's real
``minimumSizeHint``.

Tests drive the real ``ToolOutputPanel`` with real embedded tool panels
(Frida/Cutter/Ghidra) -- no mocked geometry.
"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.tools import ToolOutputPanel


def _tab_index(panel: ToolOutputPanel, title: str) -> int:
    """Find the index of the tab with the given title.

    Args:
        panel: The ToolOutputPanel to search.
        title: Tab title to look up.

    Returns:
        int: The matching tab index.

    Raises:
        AssertionError: If no tab with ``title`` is present.
    """
    for index in range(panel.tab_widget.count()):
        if panel.tab_widget.tabText(index) == title:
            return index
    message = f"tab {title!r} not found"
    raise AssertionError(message)


@pytest.mark.usefixtures("qapp")
class TestLeftPanelMinWidthTracksActiveTab:
    """Tests for N2: the docked left column's min-width floor must track the active tab's real content."""

    @staticmethod
    def test_frida_tab_raises_floor_to_its_minimum_size_hint() -> None:
        """Selecting the Frida tab raises left_panel's floor to Frida's real minimumSizeHint width.

        Frida's embedded panel carries multi-column tables and control rows
        whose natural minimum width is far above the static
        ``_LEFT_MIN_WIDTH`` constant (240px). Without the active-tab sync,
        the splitter is free to squeeze the Frida panel narrower than it can
        render, clipping its content (N2).
        """
        panel = ToolOutputPanel()
        panel.add_frida_tab()
        index = _tab_index(panel, "Frida")
        panel.tab_widget.setCurrentIndex(index)
        widget = panel.tab_widget.widget(index)
        assert widget is not None

        assert panel.left_panel.minimumWidth() >= widget.minimumSizeHint().width()

    @staticmethod
    def test_floor_drops_back_down_for_a_lighter_tab() -> None:
        """Switching from a wide tab (Frida) to a narrower one (Ghidra) lowers the floor accordingly.

        Confirms the floor is genuinely driven by the *currently active*
        tab's content rather than latching onto the widest tab ever seen.
        """
        panel = ToolOutputPanel()
        panel.add_frida_tab()
        panel.add_ghidra_tab()

        frida_index = _tab_index(panel, "Frida")
        panel.tab_widget.setCurrentIndex(frida_index)
        frida_floor = panel.left_panel.minimumWidth()

        ghidra_index = _tab_index(panel, "Ghidra")
        ghidra_widget = panel.tab_widget.widget(ghidra_index)
        assert ghidra_widget is not None
        panel.tab_widget.setCurrentIndex(ghidra_index)
        ghidra_floor = panel.left_panel.minimumWidth()

        assert ghidra_floor >= ghidra_widget.minimumSizeHint().width()
        assert ghidra_floor <= frida_floor

    @staticmethod
    def test_splitter_refuses_to_shrink_active_tab_below_its_render_minimum() -> None:
        """Forcing the panel narrow does not shrink the active tab below its real minimum width.

        End-to-end check through the real Qt layout engine (QSplitter with
        ``setChildrenCollapsible(False)``): with the Frida tab active and the
        host panel resized far narrower than Frida's natural content needs,
        the splitter's first section must still be at least as wide as
        Frida's ``minimumSizeHint().width()`` rather than silently clipping
        it.
        """
        panel = ToolOutputPanel()
        panel.add_frida_tab()
        index = _tab_index(panel, "Frida")
        panel.tab_widget.setCurrentIndex(index)
        widget = panel.tab_widget.widget(index)
        assert widget is not None
        required_width = widget.minimumSizeHint().width()

        panel.show()
        panel.resize(200, 200)
        QApplication.processEvents()

        assert panel.main_splitter.sizes()[0] >= required_width


@pytest.mark.usefixtures("qapp")
class TestRightPanelMinWidthCoversContent:
    """Tests for N2: the docked right column's min-width floor must cover its real content."""

    @staticmethod
    def test_right_panel_floor_covers_function_list_and_xref_panel() -> None:
        """right_panel's minimum width covers both the function list and xref panel's natural minimums.

        A hardcoded constant drifts out of sync as ``FunctionListPanel``/
        ``XRefPanel`` gain columns; measuring the real widgets' own
        ``minimumSizeHint`` keeps the floor honest.
        """
        panel = ToolOutputPanel()

        assert panel.right_panel.minimumWidth() >= panel.func_list.minimumSizeHint().width()
        assert panel.right_panel.minimumWidth() >= panel.xref_panel.minimumSizeHint().width()


@pytest.mark.usefixtures("qapp")
class TestLeftPanelMinWidthFallsBackForPlainTabs:
    """Tests for N2: a lightweight, non-tool tab still gets a sane floor."""

    @staticmethod
    def test_plain_widget_tab_uses_static_floor_when_it_has_no_natural_minimum() -> None:
        """A trivial QWidget tab (no meaningful minimumSizeHint) still yields at least the static floor."""
        panel = ToolOutputPanel()
        plain = QWidget()
        panel.tab_widget.addTab(plain, "Plain")
        index = _tab_index(panel, "Plain")
        panel.tab_widget.setCurrentIndex(index)

        assert panel.left_panel.minimumWidth() >= 240
