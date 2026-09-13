# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S20-D09 -- Ghidra Analysis Extras tab section overlap.

``GhidraAnalysisExtrasWidget._setup_ui``
(src/intellicrack/ui/panels/ghidra_panel_extras.py) used to stack five group
sections (Instruction Flow / Register Value, Thunk Management, External
References, Properties, Bidirectional Call Graph) directly onto the widget's
own ``QVBoxLayout`` with no per-section minimum height and no scroll area.
When the bottom detail pane hosting this tab was shorter than the sections'
combined natural height, Qt's layout engine compressed several sections into
overlapping strips -- concretely, this made the Instruction-Flow address
field untypeable, because a click at its screen position landed on whatever
section had actually been drawn on top of it instead.

The fix builds every section as its own container with a real, explicit
``minimumHeight`` derived from its ``sizeHint()`` and hosts the full stack
inside :func:`intellicrack.ui.panels.base_panel.make_scrollable`, so a short
host pane grows a scrollbar instead of crushing the stack.

Every assertion reads live Qt geometry off a real, fully constructed
``GhidraAnalysisExtrasWidget`` under an offscreen ``QApplication`` -- no
mocked widgets, no restated section-count literal.
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QPoint
from PyQt6.QtWidgets import QApplication, QScrollArea, QWidget

from intellicrack.ui.panels.ghidra_panel import GhidraPanel
from intellicrack.ui.panels.ghidra_panel_extras import GhidraAnalysisExtrasWidget


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def extras_widget(qapp: object) -> Iterator[GhidraAnalysisExtrasWidget]:
    """Provide a fully constructed ``GhidraAnalysisExtrasWidget`` and tear it down afterward.

    Args:
        qapp: The session ``QApplication`` fixture (from ``tests/ui/conftest.py``),
            required before any ``QWidget`` can be constructed.

    Yields:
        GhidraAnalysisExtrasWidget: A live widget instance with every section built.
    """
    del qapp
    instance = GhidraAnalysisExtrasWidget()
    try:
        yield instance
    finally:
        instance.deleteLater()


def _content_scroll_area(extras_widget: GhidraAnalysisExtrasWidget) -> QScrollArea:
    """Return the scroll area hosting the widget's stacked sections.

    Args:
        extras_widget: A live ``GhidraAnalysisExtrasWidget`` fixture instance.

    Returns:
        QScrollArea: The scroll area wrapping every section's content.
    """
    layout = extras_widget.layout()
    assert layout is not None
    assert layout.count() == 1, "GhidraAnalysisExtrasWidget must host exactly one top-level child"
    item = layout.itemAt(0)
    assert item is not None
    child = item.widget()
    assert isinstance(child, QScrollArea), (
        f"Analysis Extras top-level child is {type(child).__name__}, not a QScrollArea -- "
        "stacked sections overdraw one another at a short pane height instead of scrolling"
    )
    return child


class TestAnalysisExtrasIsScrollable:
    """The Analysis Extras tab must scroll its stacked sections rather than overlap them."""

    @staticmethod
    def test_content_is_wrapped_in_a_resizable_scroll_area(extras_widget: GhidraAnalysisExtrasWidget) -> None:
        """The widget's content must be hosted in a widget-resizable ``QScrollArea``.

        Args:
            extras_widget: A live ``GhidraAnalysisExtrasWidget`` fixture instance.
        """
        scroll = _content_scroll_area(extras_widget)
        assert scroll.widgetResizable() is True, (
            "Analysis Extras QScrollArea.widgetResizable() is False -- the content would not "
            "track the viewport width and could collapse instead of scrolling"
        )
        content = scroll.widget()
        assert isinstance(content, QWidget)
        assert content.layout() is not None, "Analysis Extras content has no layout"

    @staticmethod
    def test_each_section_carries_a_real_minimum_height(extras_widget: GhidraAnalysisExtrasWidget) -> None:
        """Every section container must carry an explicit, nonzero minimum height.

        Regression: with sections appended directly to a shared layout (no
        per-section container), no widget in the chain carries an explicit
        minimum, so Qt's layout engine is free to compress any of them under
        starvation from an oversized sibling pane.

        Args:
            extras_widget: A live ``GhidraAnalysisExtrasWidget`` fixture instance.
        """
        sections = [
            ("flow_register", extras_widget._flow_addr_input.parentWidget()),
            ("thunk", extras_widget._thunk_addr_input.parentWidget()),
            ("external_refs", extras_widget._ext_ref_addr_input.parentWidget()),
            ("properties", extras_widget._props_addr_input.parentWidget()),
            ("call_graph", extras_widget._bicg_addr_input.parentWidget()),
        ]
        for name, section in sections:
            assert section is not None, f"{name} section container not found"
            assert section is not extras_widget, f"{name} input has no dedicated section container"
            assert section.minimumHeight() > 0, (
                f"{name} section minimumHeight()={section.minimumHeight()} -- it can be "
                "compressed below its natural size by the surrounding layout"
            )

    @staticmethod
    def test_short_viewport_scrolls_instead_of_crushing_sections(extras_widget: GhidraAnalysisExtrasWidget) -> None:
        """Forced shorter than its content floor, the widget must scroll rather than crush its sections.

        Args:
            extras_widget: A live ``GhidraAnalysisExtrasWidget`` fixture instance.
        """
        scroll = _content_scroll_area(extras_widget)
        content = scroll.widget()
        assert content is not None

        scroll.resize(640, 900)
        scroll.show()
        QApplication.processEvents()
        floor = content.minimumSizeHint().height()
        assert floor > 300, f"unexpected: Analysis Extras content minimum height {floor} too small to exercise overflow"

        scroll.resize(640, floor // 2)
        QApplication.processEvents()

        assert content.height() >= floor, (
            f"content height {content.height()} was crushed below its no-overlap floor {floor} -- "
            "sections are being compressed instead of scrolled"
        )
        vbar = scroll.verticalScrollBar()
        assert vbar is not None
        assert vbar.maximum() > 0, "vertical scrollbar is inactive at a viewport below the content floor -- overflow is not scrollable"

    @staticmethod
    def test_sections_do_not_overlap_at_short_viewport(qapp: object) -> None:
        """At a short viewport, every section must occupy a disjoint, ordered vertical band.

        This is the user-facing property S20-D09 broke: the Instruction-Flow
        address field became untypeable because a later section was drawn on
        top of it.

        Regression: a standalone, never-shown ``GhidraAnalysisExtrasWidget``
        cannot exercise this -- Qt only starves a plain (non-scrolling)
        container's children below their declared minimums when that
        container is genuinely part of a visible layout chain that has
        nowhere else to put the deficit (here, the Analysis Extras tab page
        of a real, shown ``GhidraPanel`` squeezed shorter than the widget's
        natural content height); a bare top-level widget instead gets
        auto-clamped by Qt to its own layout's minimum size and never
        actually gets squeezed. Section geometry is read in ``extras``'s own
        coordinate space via ``mapTo``, which follows the scroll area's
        internal viewport offset and so reflects each section's true
        position in the (possibly taller-than-visible) scrolled content,
        exactly like a user scrolling down would see it.

        Args:
            qapp: The session ``QApplication`` fixture (from ``tests/ui/conftest.py``),
                required before any ``QWidget`` can be constructed.
        """
        del qapp
        panel = GhidraPanel()
        try:
            panel.resize(1400, 900)
            panel.show()
            tabs = panel._data_tabs
            assert tabs is not None
            extras_index = next((i for i in range(tabs.count()) if tabs.tabText(i) == "Analysis Extras"), -1)
            assert extras_index >= 0, "Ghidra data tabs have no 'Analysis Extras' tab"
            tabs.setCurrentIndex(extras_index)
            QApplication.processEvents()

            panel.resize(1400, 260)
            QApplication.processEvents()
            QApplication.processEvents()

            extras = panel._analysis_extras
            ordered = [
                ("flow_register", extras._flow_addr_input.parentWidget()),
                ("thunk", extras._thunk_addr_input.parentWidget()),
                ("external_refs", extras._ext_ref_addr_input.parentWidget()),
                ("properties", extras._props_addr_input.parentWidget()),
                ("call_graph", extras._bicg_addr_input.parentWidget()),
            ]

            bands: list[tuple[str, int, int]] = []
            for name, section in ordered:
                assert section is not None, f"{name} section container not found"
                top = section.mapTo(extras, QPoint(0, 0)).y()
                bands.append((name, top, top + section.height()))

            for (_, _, prev_bottom), (next_name, next_top, _) in pairwise(bands):
                assert prev_bottom <= next_top, (
                    f"section '{next_name}' (top={next_top}) overlaps the section above it "
                    f"(bottom={prev_bottom}) -- Analysis Extras sections are overdrawing each other"
                )
        finally:
            panel.deleteLater()
