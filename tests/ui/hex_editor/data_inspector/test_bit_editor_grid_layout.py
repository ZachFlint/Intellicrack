# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the R07 bit-editor 2x4 grid layout fix.

``DataInspectorMixin._create_bit_editor_group`` used to lay its 8 bit-toggle
buttons out in a single ``QHBoxLayout`` row. Each button is sized by the
live :func:`~intellicrack.ui.panels.hex_editor.data_inspector.DataInspectorMixin._compute_bit_button_width`
probe (which reflects the real stylesheet's padding/border), so the row's
minimum width (8 buttons plus spacing) ran to roughly 350px -- well past the
``_HSPLIT_SIDE_MIN_WIDTH = 200`` floor the hex editor's side pane is allowed
to shrink to. Dragging the horizontal splitter toward that floor clipped the
three lowest-order bit buttons out of the visible pane.

The fix rearranges the same 8 buttons into a 2-row by 4-column
``QGridLayout`` (MSB to LSB, left to right, top to bottom), so the group's
minimum width is only 4 buttons wide and fits inside the 200px pane.

Both gates below build the real :class:`HexEditorPanel` headlessly under the
real bundled ``dark_theme.qss`` and assert on live Qt geometry:

* :func:`test_bit_editor_group_min_width_fits_side_pane` measures the real
  ``QGroupBox.minimumSizeHint()`` output and asserts it fits within the live
  ``_HSPLIT_SIDE_MIN_WIDTH`` module constant.
* :func:`test_bit_buttons_visible_at_pane_minimum_width` drags the panel's
  real horizontal splitter down to that same minimum width and asserts every
  button in ``panel._bit_buttons`` still reports a non-empty
  ``visibleRegion()`` -- i.e. no button is clipped out of the pane.

Reverting ``_create_bit_editor_group`` to its original single-row
``QHBoxLayout`` turns both gates RED: the group's minimum width jumps back
above 200px, and the three lowest-order buttons (bits 2, 1, 0) lose their
visible region once the pane is dragged down to the floor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QApplication, QGroupBox, QSplitter

from intellicrack.ui.panels.hex_editor.panel import _HSPLIT_SIDE_MIN_WIDTH, HexEditorPanel
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def themed_qapp(qapp: QApplication) -> Generator[QApplication]:
    """Install the real bundled dark stylesheet and restore it on teardown.

    Args:
        qapp: The session-scoped QApplication from the shared fixtures.

    Yields:
        QApplication: The application with the dark theme applied.
    """
    previous = qapp.styleSheet()
    qapp.setStyleSheet(ThemeManager.get_instance().get_stylesheet("dark"))
    qapp.processEvents()
    try:
        yield qapp
    finally:
        qapp.setStyleSheet(previous)


def _find_bit_editor_group(panel: HexEditorPanel) -> QGroupBox:
    """Locate the real "Bit Editor" group box built by the panel.

    Args:
        panel: The panel whose descendants are searched.

    Returns:
        QGroupBox: The bit-editor group box.
    """
    for group in panel.findChildren(QGroupBox):
        if group.title() == "Bit Editor":
            return group
    pytest.fail("Bit Editor group box was not found on the real HexEditorPanel")


def _activate_inspector_tab(panel: HexEditorPanel) -> None:
    """Make the side-tab widget's "Inspector" page the current page.

    A ``QTabWidget`` only lays out its current page, so the bit buttons only
    receive real geometry (and a non-empty ``visibleRegion``) once the
    Inspector tab is frontmost.

    Args:
        panel: The panel whose side-tab widget is switched.
    """
    side_tabs = panel._side_tabs
    assert side_tabs is not None, "panel side_tabs was not built"
    for index in range(side_tabs.count()):
        if side_tabs.tabText(index) == "Inspector":
            side_tabs.setCurrentIndex(index)
            return
    pytest.fail("Inspector tab was not found on the real HexEditorPanel side tabs")


def test_bit_editor_group_min_width_fits_side_pane(themed_qapp: QApplication) -> None:
    """The real Bit Editor group's minimum width must fit the 200px side pane.

    Args:
        themed_qapp: QApplication with the real dark stylesheet applied.
    """
    panel = HexEditorPanel()
    try:
        panel.resize(1200, 800)
        panel.show()
        panel.ensurePolished()
        themed_qapp.processEvents()
        _activate_inspector_tab(panel)
        themed_qapp.processEvents()

        bit_group = _find_bit_editor_group(panel)
        width = bit_group.minimumSizeHint().width()
        assert width <= _HSPLIT_SIDE_MIN_WIDTH, (
            f"Bit Editor group minimumSizeHint().width() is {width}px, which exceeds the "
            f"{_HSPLIT_SIDE_MIN_WIDTH}px side-pane minimum ({_HSPLIT_SIDE_MIN_WIDTH} is the live "
            "_HSPLIT_SIDE_MIN_WIDTH module constant) -- the 8 bit-toggle buttons no longer fit a "
            "single row within the collapsible side pane"
        )
    finally:
        panel.close()


def test_bit_buttons_visible_at_pane_minimum_width(themed_qapp: QApplication) -> None:
    """Every bit-toggle button must stay visible when the side pane is dragged to its floor.

    Args:
        themed_qapp: QApplication with the real dark stylesheet applied.
    """
    panel = HexEditorPanel()
    try:
        panel.resize(1200, 800)
        panel.show()
        panel.ensurePolished()
        themed_qapp.processEvents()
        _activate_inspector_tab(panel)
        themed_qapp.processEvents()

        assert panel._main_vsplit is not None, "panel main vsplit was not built"
        hsplit = cast("QSplitter", panel._main_vsplit.widget(0))
        assert isinstance(hsplit, QSplitter), "first main-vsplit child must be the horizontal splitter"

        total_width = hsplit.width()
        hsplit.setSizes([total_width - _HSPLIT_SIDE_MIN_WIDTH, _HSPLIT_SIDE_MIN_WIDTH])
        themed_qapp.processEvents()

        side_pane = hsplit.widget(1)
        assert side_pane is not None
        assert side_pane.width() <= _HSPLIT_SIDE_MIN_WIDTH + 1, (
            f"side pane did not settle at its {_HSPLIT_SIDE_MIN_WIDTH}px floor; "
            f"actual width {side_pane.width()}px -- the drag-to-minimum setup did not take effect"
        )

        assert panel._bit_buttons, "panel._bit_buttons is empty -- gate would be vacuous"
        assert len(panel._bit_buttons) == 8, f"expected 8 bit buttons, got {len(panel._bit_buttons)}"
        for i, btn in enumerate(panel._bit_buttons):
            bit_index = 7 - i
            region = btn.visibleRegion()
            assert not region.isEmpty(), (
                f"bit button for bit {bit_index} has an empty visibleRegion at the {_HSPLIT_SIDE_MIN_WIDTH}px "
                "pane minimum width -- it is clipped out of the visible side pane"
            )
    finally:
        panel.close()
