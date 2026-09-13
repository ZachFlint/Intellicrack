# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the Ghidra share of S20-D14 -- Scripting tab control overlap.

``GhidraPanel._create_scripting_tab`` (src/intellicrack/ui/panels/ghidra_panel.py)
stacks a script editor, run buttons, an output view, decompiler-options
controls, and analysis-configuration controls directly in a plain
``QVBoxLayout`` with no scroll boundary. Their combined minimum height can
exceed the docked bottom-detail pane, so before the fix the tab returned that
container directly: at the real pane height Qt's layout engine could not
satisfy every control's minimum and the rows overdrew one another (the
reported symptoms were the Run button rendered on top of the Output label,
"Simplification style" overlapping "Analysis Configuration", the "Params
(JSON):" label overlapping its placeholder, and the "Analyzer name" row cut
off at the bottom edge).

The fix hosts the container in a vertically scrolling viewport
(:func:`intellicrack.ui.panels.base_panel.make_scrollable`) so overflow scrolls
instead of compressing the stacked rows into each other, and gives the script
editor a real minimum height matching the output view's.

Every assertion reads live Qt geometry off a real, fully constructed
``GhidraPanel`` under an offscreen ``QApplication`` -- no mocked widgets.
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


def _scripting_tab(panel: GhidraPanel) -> QScrollArea:
    """Return the live Scripting tab widget wired into the panel's data tabs.

    Args:
        panel: A live ``GhidraPanel`` fixture instance.

    Returns:
        QScrollArea: The widget hosting the Scripting tab content.
    """
    tabs = panel._data_tabs
    assert tabs is not None
    index = next((i for i in range(tabs.count()) if tabs.tabText(i) == "Scripting"), -1)
    assert index >= 0, "Ghidra data tabs have no 'Scripting' tab"
    widget = tabs.widget(index)
    assert isinstance(widget, QScrollArea), (
        f"Scripting tab widget is {type(widget).__name__}, not a QScrollArea -- stacked rows "
        "overdraw one another at docked pane height instead of scrolling"
    )
    return widget


class TestScriptingTabIsScrollable:
    """The Ghidra Scripting tab must scroll its stacked rows rather than overlap them."""

    @staticmethod
    def test_scripting_tab_is_a_resizable_scroll_area(panel: GhidraPanel) -> None:
        """The Scripting tab must be a ``QScrollArea`` in widget-resizable mode hosting a real content widget.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        scroll = _scripting_tab(panel)
        assert scroll.widgetResizable() is True, (
            "Scripting tab QScrollArea.widgetResizable() is False -- the content would not track "
            "the viewport width and could collapse instead of scrolling"
        )
        content = scroll.widget()
        assert isinstance(content, QWidget)
        assert content.layout() is not None, "Scripting tab content has no layout"

    @staticmethod
    def test_script_editor_has_a_real_minimum_height(panel: GhidraPanel) -> None:
        """The script editor must carry an explicit, nonzero minimum height like the output view.

        Regression: the editor previously had no minimum at all, so it could
        be squeezed to zero height while its stretch factor gave it no
        protection under starvation.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        assert panel._script_editor.minimumHeight() > 0, (
            f"_script_editor.minimumHeight()={panel._script_editor.minimumHeight()} -- it can be "
            "compressed to zero height by the surrounding layout"
        )

    @staticmethod
    def test_short_viewport_scrolls_instead_of_crushing_rows(panel: GhidraPanel) -> None:
        """Forced shorter than its content floor, the tab must scroll rather than crush its rows.

        The panel is genuinely shown and the Scripting tab made current
        before any geometry is measured or resized: a ``QScrollArea`` that
        is still hidden inside a background (non-current) tab page of an
        unshown top-level widget does not reliably update its viewport size
        or scrollbar range when resized, which makes geometry read off it
        meaningless regardless of what the underlying implementation does.
        Once genuinely visible and current, resizing the scroll area itself
        (rather than the panel) exercises exactly the squeeze a docked pane
        applies without tripping Qt's top-level-window auto-clamp to the
        layout's minimum size.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        scripting_index = next((i for i in range(tabs.count()) if tabs.tabText(i) == "Scripting"), -1)
        assert scripting_index >= 0, "Ghidra data tabs have no 'Scripting' tab"

        panel.resize(1400, 900)
        panel.show()
        tabs.setCurrentIndex(scripting_index)
        QApplication.processEvents()

        scroll = _scripting_tab(panel)
        content = scroll.widget()
        assert content is not None

        floor = content.minimumSizeHint().height()
        assert floor > 300, f"unexpected: Scripting tab content minimum height {floor} too small to exercise overflow"

        scroll.resize(640, floor // 2)
        QApplication.processEvents()
        QApplication.processEvents()

        assert content.height() >= floor, (
            f"content height {content.height()} was crushed below its no-overlap floor {floor} -- "
            "rows are being compressed instead of scrolled"
        )
        vbar = scroll.verticalScrollBar()
        assert vbar is not None
        assert vbar.maximum() > 0, "vertical scrollbar is inactive at a viewport below the content floor -- overflow is not scrollable"

    @staticmethod
    def test_rows_do_not_overlap_at_short_viewport(panel: GhidraPanel) -> None:
        """At a short viewport, the stacked control rows must occupy disjoint, ordered vertical bands.

        This is the user-facing property S20-D14 broke for the Ghidra
        Scripting tab: with the plain container forced to the docked height,
        later rows overdrew earlier ones (Run over Output, Simplification
        style over Analysis Configuration).

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        scroll = _scripting_tab(panel)
        content = scroll.widget()
        assert content is not None

        scroll.resize(640, 900)
        scroll.show()
        QApplication.processEvents()
        floor = content.minimumSizeHint().height()
        scroll.resize(640, max(240, floor // 2))
        QApplication.processEvents()

        ordered = [
            ("script_editor", panel._script_editor),
            ("script_params_input", panel._script_params_input),
            ("run_script_btn", panel._run_script_btn),
            ("script_output", panel._script_output),
            ("decomp_simplification_input", panel._decomp_simplification_input),
            ("analyzer_name_input", panel._analyzer_name_input),
            ("analyzer_options_input", panel._analyzer_options_input),
        ]

        bands: list[tuple[str, int, int]] = []
        for name, widget in ordered:
            assert widget is not None, f"{name} was not constructed"
            top = widget.mapTo(content, QPoint(0, 0)).y()
            bands.append((name, top, top + widget.height()))

        for (_, _, prev_bottom), (next_name, next_top, _) in pairwise(bands):
            assert prev_bottom <= next_top, (
                f"row '{next_name}' (top={next_top}) overlaps the row above it "
                f"(bottom={prev_bottom}) -- Scripting tab rows are overdrawing each other"
            )
