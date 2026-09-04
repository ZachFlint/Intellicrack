# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate: the x64dbg bottom tabs must fit inside the viewport (D09).

The x64dbg panel's "Analysis" tab stacks a disassembly/inspect splitter pane
above a bottom tabbed section (Breakpoints/Memory/Console/...) inside a
draggable ``QSplitter``, which is itself wrapped in a scroll area so the
whole cluster still fits a short window. Before the D09 fix, that scroll
area's minimum height was hard-pinned to the *comfortable default* split
size (450 + 250 = 700px) rather than a sane floor, so at a realistic window
size the bottom tabs - and the Add-Breakpoint row inside them - rendered
below the visible viewport instead of sharing the available space with the
top pane. This module drives the real panel at a realistic window size and
asserts the Breakpoints tab's "Add BP" button is genuinely inside every
enclosing scroll viewport, not merely reachable by scrolling further down.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QPoint, QRect
from PyQt6.QtWidgets import QScrollArea

from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QWidget


# A modest, realistic window size for a single docked analysis panel - wide
# enough that the breakpoint control row never needs to scroll horizontally
# (see test_x64dbg_control_rows.py, which only reproduces that at 560px),
# so height is the only variable this test exercises. 580px is comfortably
# inside the band (empirically ~560-600px) where the pre-D09 700px-forced
# content minimum pushes the bottom tabs below the viewport while this
# fix's ~300px sane floor still leaves them fully visible.
_REALISTIC_WINDOW_WIDTH = 1000
_REALISTIC_WINDOW_HEIGHT = 580


def _global_rect(widget: QWidget) -> QRect:
    """Return ``widget``'s true on-screen rectangle in global coordinates.

    Args:
        widget: The widget to locate.

    Returns:
        QRect: The widget's geometry translated to global screen space via
        its actual position in the window, independent of whether any
        ancestor is currently clipping it out of view.
    """
    return QRect(widget.mapToGlobal(QPoint(0, 0)), widget.size())


def _fully_visible_within_scroll_ancestors(widget: QWidget) -> tuple[bool, str]:
    """Check that every enclosing ``QScrollArea`` viewport fully contains ``widget``.

    Walks the ancestor chain from ``widget`` up to the top-level window. At
    each ``QScrollArea`` ancestor, ``widget``'s true global rectangle must
    lie entirely within that scroll area's viewport rectangle - a widget
    positioned below an ancestor viewport's visible height (for example
    because the splitter above it squeezed the bottom pane out of the
    default scroll position) fails this check even though it still has a
    well-defined ``geometry()`` inside its immediate parent.

    Args:
        widget: The widget whose visibility is checked.

    Returns:
        tuple[bool, str]: Whether ``widget`` is fully visible without
        scrolling, and a diagnostic string describing every scroll
        ancestor examined (for use in an assertion failure message).
    """
    widget_rect = _global_rect(widget)
    diagnostics: list[str] = [f"widget_rect={widget_rect}"]
    ok = True
    ancestor = widget.parentWidget()
    while ancestor is not None:
        if isinstance(ancestor, QScrollArea):
            viewport = ancestor.viewport()
            if viewport is not None:
                viewport_rect = _global_rect(viewport)
                contained = viewport_rect.contains(widget_rect)
                diagnostics.append(
                    f"scroll_area={ancestor.objectName() or type(ancestor).__name__} "
                    f"viewport_rect={viewport_rect} contained={contained}",
                )
                if not contained:
                    ok = False
        ancestor = ancestor.parentWidget()
    return ok, "; ".join(diagnostics)


@pytest.mark.usefixtures("qapp")
def test_add_breakpoint_button_visible_at_realistic_window_size(qapp: QApplication) -> None:
    """The Breakpoints "Add BP" button must sit inside the viewport, not below it.

    Falsifiable: reverting the D09 fix (restoring ``_MAIN_SPLIT_TOP=450``/
    ``_MAIN_SPLIT_BOTTOM=250``, ``bottom_tabs.setMinimumHeight(_MIN_PANE_HEIGHT)``,
    and the content scroll area's ``min_height=_MAIN_SPLIT_TOP + _MAIN_SPLIT_BOTTOM``
    (700px)) forces the content cluster to demand 700px of height regardless
    of the window's actual size. At the realistic window size used here,
    that leaves the bottom tabbed section - and the "Add BP" button inside
    it - positioned below the scroll viewport's visible area, so
    ``_fully_visible_within_scroll_ancestors`` returns ``False`` and this
    test goes red.
    """
    panel = X64DbgPanel()
    try:
        panel.resize(_REALISTIC_WINDOW_WIDTH, _REALISTIC_WINDOW_HEIGHT)
        panel.show()
        qapp.processEvents()
        qapp.processEvents()

        button = panel._add_bp_btn
        assert button.isVisible(), "Add BP button must be a realized, visible widget before checking its viewport position"

        ok, diagnostics = _fully_visible_within_scroll_ancestors(button)
        assert ok, (
            f"Add BP button rendered outside a scroll viewport at a {_REALISTIC_WINDOW_WIDTH}x"
            f"{_REALISTIC_WINDOW_HEIGHT} window: {diagnostics}"
        )
    finally:
        panel.close()
        qapp.processEvents()
