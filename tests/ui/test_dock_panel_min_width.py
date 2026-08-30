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

S19-D02 later refined the left floor with a width-aware cap: pinning the
floor to a tab's raw ``minimumSizeHint`` unconditionally combines with the
right column's own minimum to exceed the splitter's available width, which
froze every handle and pushed the right column off-screen. The floor is now
``min(content_minimum, splitter_width - right_minimum - handle_slack)`` once
the splitter width is known, so N2's content-covering floor still applies
when the window is wide enough, but a window narrower than the content needs
keeps the handle movable (with scroll relief) instead of freezing it.

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
    def test_frida_tab_floor_covers_content_when_window_is_wide() -> None:
        """When the window is wide enough, left_panel's floor covers Frida's real minimumSizeHint width.

        Frida's embedded panel carries multi-column tables and control rows
        whose natural minimum width is far above the static
        ``_LEFT_MIN_WIDTH`` constant (240px). With room to spare (the
        S19-D02 width-aware cap does not bind), the active-tab sync must
        still raise the floor to the tab's real content minimum so the
        splitter cannot squeeze the Frida panel narrower than it renders
        (N2, preserved).
        """
        panel = ToolOutputPanel()
        panel.add_frida_tab()
        index = _tab_index(panel, "Frida")
        panel.tab_widget.setCurrentIndex(index)
        widget = panel.tab_widget.widget(index)
        assert widget is not None

        # Make the window comfortably wider than the content minimum plus the
        # right column, so the D02 cap leaves the full content floor in place.
        wide = widget.minimumSizeHint().width() + panel.right_panel.minimumWidth() + 400
        panel.show()
        panel.resize(wide, 900)
        QApplication.processEvents()

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
        frida_widget = panel.tab_widget.widget(frida_index)
        assert frida_widget is not None
        ghidra_index = _tab_index(panel, "Ghidra")
        ghidra_widget = panel.tab_widget.widget(ghidra_index)
        assert ghidra_widget is not None

        # Keep the window wide enough that the D02 cap never binds, so the
        # floor is driven purely by the active tab's content minimum.
        widest = max(frida_widget.minimumSizeHint().width(), ghidra_widget.minimumSizeHint().width())
        panel.show()
        panel.resize(widest + panel.right_panel.minimumWidth() + 400, 900)

        panel.tab_widget.setCurrentIndex(frida_index)
        QApplication.processEvents()
        frida_floor = panel.left_panel.minimumWidth()

        panel.tab_widget.setCurrentIndex(ghidra_index)
        QApplication.processEvents()
        ghidra_floor = panel.left_panel.minimumWidth()

        assert ghidra_floor >= ghidra_widget.minimumSizeHint().width()
        assert ghidra_floor <= frida_floor

    @staticmethod
    def test_splitter_stays_movable_when_forced_narrow() -> None:
        """Forcing the panel narrower than the active tab needs keeps the handle movable (S19-D02).

        End-to-end check through the real Qt layout engine (QSplitter with
        ``setChildrenCollapsible(False)``): with the Frida tab active and the
        host panel resized far narrower than Frida's natural content needs,
        the width-aware cap must let the left column fall below Frida's raw
        ``minimumSizeHint().width()`` so the child minimums fit inside the
        splitter and every handle can still move. Pinning the floor to the
        raw content minimum (the pre-D02 behavior) would force the left
        section to Frida's full width, overflow the splitter, and freeze the
        handle -- this test falsifies that regression.
        """
        panel = ToolOutputPanel()
        panel.add_frida_tab()
        index = _tab_index(panel, "Frida")
        panel.tab_widget.setCurrentIndex(index)
        widget = panel.tab_widget.widget(index)
        assert widget is not None
        required_width = widget.minimumSizeHint().width()

        # A window narrower than the Frida content minimum: the cap must bind.
        narrow_width = max(700, required_width - 200)
        panel.show()
        panel.resize(narrow_width, 600)
        QApplication.processEvents()

        sizes = panel.main_splitter.sizes()
        # The left section is allowed below the raw content minimum (D02 cap),
        # and the sections fit inside the splitter (no off-screen overflow).
        assert sizes[0] < required_width
        assert sum(sizes) <= panel.main_splitter.width()

        # The handle genuinely moves: a requested split is honored rather than
        # being clamped back to a frozen content-driven minimum.
        target_left = panel.left_panel.minimumWidth() + 40
        panel.main_splitter.setSizes([target_left, panel.main_splitter.width() - target_left])
        QApplication.processEvents()
        assert panel.main_splitter.sizes()[0] != required_width


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
