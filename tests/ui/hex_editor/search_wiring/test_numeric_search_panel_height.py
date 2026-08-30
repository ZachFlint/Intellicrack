# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the R01 numeric/pattern splitter-pane drag-collapse fix.

``HexEditorPanel._create_content`` builds ``_main_vsplit`` as a
``QSplitter(Vertical)`` holding the hex/side-panel split (index
``VSPLIT_HSPLIT_IDX``), the pattern-editor frame (index
``VSPLIT_PATTERN_IDX``), and the numeric-search frame (index
``VSPLIT_NUMERIC_IDX``). ``QSplitter`` panes are collapsible by default,
which means a user dragging a splitter handle can squeeze the pattern or
numeric pane down to 0px -- below its own ``minimumSizeHint()`` -- making the
pattern editor or the Value/Size/Type/Endian/Search/Replace controls
unreachable even though the pane is technically still "visible".

Empirical probing of the real ``QSplitter``/``QSplitterHandle`` drag path
(``moveSplitter``) on this Qt build confirms this is the one concrete,
reproducible defect in this area: showing a hidden pane via ``setVisible``
alone already receives a correct, non-zero, ``sizeHint``-based size from
Qt's own layout pass (verified directly against the real widget tree), so a
gate built around "does the pane get *some* height after ``setVisible``"
cannot distinguish fixed code from reverted code. Only a real drag toward
the pane (``QSplitter.moveSplitter``, the same primitive a mouse-drag on the
handle drives) proves the difference: with the default collapsible splitter
panes, the drag drives the target pane's stored size to 0; with
``setCollapsible(..., False)`` applied (the actual fix, in
``HexEditorPanel._create_content``), Qt clamps the drag at the pane's
``minimumSizeHint()`` and the pane never collapses below it.

Both gates below build the real :class:`HexEditorPanel` headlessly, drive
its real ``_search_mode_combo`` / ``_toggle_pattern_editor`` and real
``_main_vsplit``, and then drag the real splitter handle -- no fakes or
restated constants. Reverting the two
``self._main_vsplit.setCollapsible(VSPLIT_PATTERN_IDX, False)`` /
``self._main_vsplit.setCollapsible(VSPLIT_NUMERIC_IDX, False)`` calls in
``_create_content`` (Qt's default ``collapsible=True`` reasserts itself)
turns both gates RED: dragging the handle collapses the pane to 0px.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.ui.panels.hex_editor.base import (
    VSPLIT_NUMERIC_IDX,
    VSPLIT_PATTERN_IDX,
)
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


def test_numeric_pane_resists_drag_collapse_below_minimum(qapp: QApplication) -> None:
    """Dragging the splitter handle cannot squeeze the numeric pane to 0px.

    Args:
        qapp: QApplication fixture (ensures Qt is available).
    """
    panel = HexEditorPanel()
    try:
        panel.resize(1200, 800)
        panel.show()
        panel.ensurePolished()
        qapp.processEvents()

        assert panel._search_mode_combo is not None, "panel search mode combo was not built"
        assert panel._numeric_search_frame is not None, "panel numeric search frame was not built"
        assert panel._main_vsplit is not None, "panel main vsplit was not built"

        panel._search_mode_combo.setCurrentText("Numeric")
        qapp.processEvents()

        frame = panel._numeric_search_frame
        vsplit = panel._main_vsplit
        assert frame.isVisible(), "numeric search frame must be visible after switching to Numeric mode"
        assert frame.height() > 0, "setup precondition: numeric frame must have real height before the drag probe"

        min_height = frame.minimumSizeHint().height()
        assert min_height > 0, "numeric frame minimumSizeHint().height() must be positive -- gate would be vacuous"

        vsplit.moveSplitter(vsplit.height(), VSPLIT_NUMERIC_IDX)
        qapp.processEvents()

        collapsed_height = vsplit.sizes()[VSPLIT_NUMERIC_IDX]
        assert collapsed_height >= min_height, (
            f"dragging the splitter handle toward the numeric pane collapsed it to "
            f"{collapsed_height}px (its minimumSizeHint is {min_height}px) -- the "
            "Value/Size/Type/Endian/Search/Replace controls became unreachable by drag"
        )
    finally:
        panel.close()


def test_pattern_pane_resists_drag_collapse_below_minimum(qapp: QApplication) -> None:
    """Dragging the splitter handle cannot squeeze the pattern editor pane to 0px.

    Args:
        qapp: QApplication fixture (ensures Qt is available).
    """
    panel = HexEditorPanel()
    try:
        panel.resize(1200, 800)
        panel.show()
        panel.ensurePolished()
        qapp.processEvents()

        assert panel._pattern_frame is not None, "panel pattern editor frame was not built"
        assert panel._main_vsplit is not None, "panel main vsplit was not built"

        panel._toggle_pattern_editor()
        qapp.processEvents()

        frame = panel._pattern_frame
        vsplit = panel._main_vsplit
        assert frame.isVisible(), "pattern editor frame must be visible after toggling it on"
        assert frame.height() > 0, "setup precondition: pattern frame must have real height before the drag probe"

        min_height = frame.minimumSizeHint().height()
        assert min_height > 0, "pattern frame minimumSizeHint().height() must be positive -- gate would be vacuous"

        vsplit.moveSplitter(vsplit.height(), VSPLIT_PATTERN_IDX)
        qapp.processEvents()

        collapsed_height = vsplit.sizes()[VSPLIT_PATTERN_IDX]
        assert collapsed_height >= min_height, (
            f"dragging the splitter handle toward the pattern pane collapsed it to "
            f"{collapsed_height}px (its minimumSizeHint is {min_height}px) -- the pattern "
            "editor became unreachable by drag"
        )
    finally:
        panel.close()
