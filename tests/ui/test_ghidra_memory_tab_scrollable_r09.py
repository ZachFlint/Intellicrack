# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S19 finding R09 -- Ghidra Memory tab section overlap.

``GhidraPanel._create_memory_tab`` (src/intellicrack/ui/panels/ghidra_panel.py)
stacks, in a single ``QVBoxLayout``, the memory-map ``QTableWidget`` (with a
minimum visible-row height), a ``Read Bytes`` form, a min-height hex-dump
``QPlainTextEdit``, a ``Write Bytes`` form, a ``Create Memory Block`` form, the
Remove/Split/Join block-operation rows, and a ``Create Overlay Space`` form.
Their combined minimum height exceeds the docked pane, so before the fix the
tab returned that container directly: at the real pane height Qt could not
satisfy every minimum and the sections overdrew one another, leaving the
Read/Write Bytes forms unreadable and unclickable.

The fix hosts the container in a vertically scrolling ``QScrollArea``
(``setWidgetResizable(True)``) so overflow scrolls instead of compressing the
stacked sections into each other.

Every assertion reads live Qt geometry off a real, fully constructed
``GhidraPanel`` under an offscreen ``QApplication`` -- no mocked widgets. The
tab is driven at a viewport deliberately shorter than the content's natural
height (the docked-pane condition that triggered the overlap), and the checks
falsify on a revert: with the plain-``QWidget`` container the Memory tab is not
a ``QScrollArea`` (structural check) and, forced to that short height, its
sections' vertical bands overlap (behavioural check).
"""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QPoint
from PyQt6.QtWidgets import QApplication, QScrollArea, QWidget

from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def panel(qapp: object) -> Iterator[GhidraPanel]:
    """Provide a fully constructed ``GhidraPanel`` and tear it down afterward.

    Args:
        qapp: The session ``QApplication`` fixture (from ``tests/ui/conftest.py``),
            required before any ``QWidget`` can be constructed.

    Yields:
        GhidraPanel: A live panel instance with every tab built.
    """
    del qapp
    instance = GhidraPanel()
    try:
        yield instance
    finally:
        instance.deleteLater()


def _memory_tab(panel: GhidraPanel) -> QScrollArea:
    """Return the live Memory tab widget wired into the panel's data tabs.

    Args:
        panel: A live ``GhidraPanel`` fixture instance.

    Returns:
        QScrollArea: The widget hosting the Memory tab content.
    """
    tabs = panel._data_tabs
    assert tabs is not None
    index = next((i for i in range(tabs.count()) if tabs.tabText(i) == "Memory"), -1)
    assert index >= 0, "Ghidra data tabs have no 'Memory' tab"
    widget = tabs.widget(index)
    assert isinstance(widget, QScrollArea), (
        f"Memory tab widget is {type(widget).__name__}, not a QScrollArea -- stacked forms "
        "overdraw one another at docked pane height instead of scrolling"
    )
    return widget


class TestMemoryTabIsScrollable:
    """The Ghidra Memory tab must scroll its stacked forms rather than overlap them."""

    @staticmethod
    def test_memory_tab_is_a_resizable_scroll_area(panel: GhidraPanel) -> None:
        """The Memory tab must be a ``QScrollArea`` in widget-resizable mode hosting a real content widget.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        scroll = _memory_tab(panel)
        assert scroll.widgetResizable() is True, (
            "Memory tab QScrollArea.widgetResizable() is False -- the content would not track the "
            "viewport width and could collapse instead of scrolling"
        )
        content = scroll.widget()
        assert isinstance(content, QWidget)
        assert content.layout() is not None, "Memory tab content has no layout"

    @staticmethod
    def test_short_viewport_scrolls_instead_of_compressing(panel: GhidraPanel) -> None:
        """Forced shorter than its content floor, the tab must scroll rather than crush its sections.

        The content's ``minimumSizeHint`` height is the point at which every
        stacked section just fits without overlap. Under ``widgetResizable``
        the scroll area holds the content at ``max(viewport, that floor)``, so
        with a viewport below the floor the content stays at the floor and the
        vertical scrollbar becomes active. Regression: without the scroll area
        the container's ``QVBoxLayout`` would instead absorb the deficit by
        compressing the sections below their minimums (overlap) and the
        scrollbar would never appear.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        scroll = _memory_tab(panel)
        content = scroll.widget()
        assert content is not None

        scroll.resize(640, 720)
        scroll.show()
        QApplication.processEvents()
        floor = content.minimumSizeHint().height()
        assert floor > 260, f"unexpected: Memory content minimum height {floor} too small to exercise overflow"

        scroll.resize(640, floor // 2)
        QApplication.processEvents()

        assert content.height() >= floor, (
            f"content height {content.height()} was crushed below its no-overlap floor {floor} -- "
            "sections are being compressed instead of scrolled"
        )
        vbar = scroll.verticalScrollBar()
        assert vbar is not None
        assert vbar.maximum() > 0, (
            "vertical scrollbar is inactive at a viewport below the content floor -- overflow is not scrollable"
        )

    @staticmethod
    def test_sections_do_not_overlap_at_short_viewport(panel: GhidraPanel) -> None:
        """At a short viewport, the stacked section widgets must occupy disjoint, ordered vertical bands.

        This is the user-facing property R09 broke: with the plain container
        forced to the docked height, later forms overdrew earlier ones. Mapped
        into content coordinates the ordered anchors must be strictly stacked
        top-to-bottom with no band overlapping the next.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        scroll = _memory_tab(panel)
        content = scroll.widget()
        assert content is not None

        scroll.resize(640, 720)
        scroll.show()
        QApplication.processEvents()
        floor = content.minimumSizeHint().height()
        scroll.resize(640, max(240, floor // 2))
        QApplication.processEvents()

        ordered = [
            ("memory_table", panel._memory_table),
            ("read_addr_input", panel._read_addr_input),
            ("hex_dump_view", panel._hex_dump_view),
            ("write_addr_input", panel._write_addr_input),
            ("block_name_input", panel._block_name_input),
            ("overlay_name_input", panel._overlay_name_input),
        ]

        bands: list[tuple[str, int, int]] = []
        for name, widget in ordered:
            assert widget is not None, f"{name} was not constructed"
            top = widget.mapTo(content, QPoint(0, 0)).y()
            bands.append((name, top, top + widget.height()))

        for (_, _, prev_bottom), (next_name, next_top, _) in pairwise(bands):
            assert prev_bottom <= next_top, (
                f"section '{next_name}' (top={next_top}) overlaps the section above it "
                f"(bottom={prev_bottom}) -- Memory tab forms are overdrawing each other"
            )
