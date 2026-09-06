# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for S19-D02 with the Hex Editor tab specifically active.

``ToolOutputPanel`` (``ui/tools.py``) docks every embedded tool -- including
the built-in Hex Editor -- inside a ``main_splitter`` whose left column
(``left_panel``) hosts the tab widget and whose right column
(``right_panel``) hosts the fixed function-list/xref panel.
``_sync_left_panel_min_width`` raises ``left_panel``'s floor to the active
tab's real ``minimumSizeHint().width()`` so a tab's content is never
squeezed narrower than it can render (N2). Pinning that floor
unconditionally, however, combines with ``right_panel``'s own minimum to
exceed the splitter's available width once the window is narrower than
their sum, freezing every handle and pushing ``right_panel`` toward (or
past) the edge -- the original S19-D02 regression. The fix caps the floor
to ``min(content_minimum, splitter_width - right_minimum - handle_slack)``
once the splitter's width is known.

``tests/ui/test_dock_panel_min_width.py`` already covers this mechanism
generically via the Frida/Ghidra tabs. This module re-verifies the same
fix specifically with the Hex Editor tab active (the tab actually named in
S19-D02), driving the real ``ToolOutputPanel`` and real
``HexEditorPanel`` -- no mocked geometry.

Reverting the cap (pinning ``left_panel``'s floor to the Hex tab's raw,
uncapped ``minimumSizeHint().width()``) turns
``test_left_panel_floor_is_capped_below_raw_content_minimum`` and
``test_splitter_handle_remains_movable`` RED: the floor no longer drops
below the tab's raw content minimum, and the handle stops responding to
``setSizes`` because the splitter has no slack left to redistribute.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QWidget


def _hex_tab_widget(panel: ToolOutputPanel) -> QWidget:
    """Add the Hex Editor tab, select it, and return its content widget.

    Args:
        panel: The ``ToolOutputPanel`` to add the tab to.

    Returns:
        QWidget: The Hex Editor tab's content widget, now the current tab.

    Raises:
        AssertionError: If the Hex Editor tab could not be added or found.
    """
    added = panel.add_hex_editor_tab()
    assert added is not None, "add_hex_editor_tab must succeed (hexcore extension required)"

    for index in range(panel.tab_widget.count()):
        if panel.tab_widget.tabText(index) == "Hex Editor":
            panel.tab_widget.setCurrentIndex(index)
            widget = panel.tab_widget.widget(index)
            assert widget is not None
            return widget
    message = "Hex Editor tab not found after add_hex_editor_tab"
    raise AssertionError(message)


@pytest.mark.usefixtures("qapp")
class TestHexTabSplitterStaysWithinBounds:
    """With the Hex tab active, the splitter must never overflow its own width."""

    @staticmethod
    def test_sizes_never_exceed_splitter_width(qapp: QApplication) -> None:
        """``main_splitter.sizes()`` must sum to at most the splitter's own width.

        Checked at both a comfortably wide window and a window narrow
        enough that the D02 cap must bind, since ``setChildrenCollapsible(False)``
        makes an uncapped floor capable of forcing the splitter's
        computed minimum size above the window's actual width.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = ToolOutputPanel()
        widget = _hex_tab_widget(panel)
        required_width = widget.minimumSizeHint().width()
        right_min = panel.right_panel.minimumWidth()

        panel.show()
        for width in (required_width + right_min + 400, max(500, required_width + right_min - 50)):
            panel.resize(width, 700)
            qapp.processEvents()

            sizes = panel.main_splitter.sizes()
            assert sum(sizes) <= panel.main_splitter.width(), (
                f"main_splitter.sizes() {sizes} sums to more than its own width {panel.main_splitter.width()}px at window width {width}px"
            )


@pytest.mark.usefixtures("qapp")
class TestHexTabLeftFloorCappedWhenNarrow:
    """S19-D02: the left column's floor must be capped, not pinned, when the window is narrow."""

    @staticmethod
    def test_left_panel_floor_is_capped_below_raw_content_minimum(qapp: QApplication) -> None:
        """Below the content+right+slack threshold, the floor must drop under the raw minimum.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = ToolOutputPanel()
        widget = _hex_tab_widget(panel)
        required_width = widget.minimumSizeHint().width()
        right_min = panel.right_panel.minimumWidth()

        # A window narrower than content_minimum + right_minimum + handle slack:
        # the D02 cap must bind here (uncapped code cannot shrink below required_width).
        narrow_width = max(500, required_width + right_min - 50)
        panel.show()
        panel.resize(narrow_width, 700)
        qapp.processEvents()

        assert panel.left_panel.minimumWidth() < required_width, (
            f"left_panel.minimumWidth() {panel.left_panel.minimumWidth()}px was not capped "
            f"below the Hex tab's raw minimumSizeHint {required_width}px at window width "
            f"{narrow_width}px -- the left floor is pinned uncapped (S19-D02 regression)"
        )

    @staticmethod
    def test_right_panel_stays_within_the_rendered_window(qapp: QApplication) -> None:
        """``right_panel`` must never render past the panel's own rendered width.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = ToolOutputPanel()
        widget = _hex_tab_widget(panel)
        required_width = widget.minimumSizeHint().width()
        right_min = panel.right_panel.minimumWidth()

        narrow_width = max(500, required_width + right_min - 50)
        panel.show()
        panel.resize(narrow_width, 700)
        qapp.processEvents()

        right_edge = panel.right_panel.x() + panel.right_panel.width()
        assert right_edge <= panel.width(), (
            f"right_panel's right edge ({right_edge}px) extends past the panel's own rendered "
            f"width ({panel.width()}px) -- the Bookmarks/Inspector side pane is off-screen"
        )

    @staticmethod
    def test_splitter_handle_remains_movable(qapp: QApplication) -> None:
        """Dragging the handle (via ``setSizes``) must actually change the reported sizes.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = ToolOutputPanel()
        widget = _hex_tab_widget(panel)
        required_width = widget.minimumSizeHint().width()
        right_min = panel.right_panel.minimumWidth()

        narrow_width = max(500, required_width + right_min - 50)
        panel.show()
        panel.resize(narrow_width, 700)
        qapp.processEvents()

        before = panel.main_splitter.sizes()
        target_left = panel.left_panel.minimumWidth() + 40
        panel.main_splitter.setSizes([target_left, panel.main_splitter.width() - target_left])
        qapp.processEvents()
        after = panel.main_splitter.sizes()

        assert after != before, (
            f"programmatically moving the handle did not change main_splitter.sizes() "
            f"({before} -> {after}) -- the handle is frozen because the uncapped left floor "
            "leaves the splitter no slack to redistribute"
        )
