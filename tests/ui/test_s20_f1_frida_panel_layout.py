# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Frida panel layout in :mod:`intellicrack.ui.panels.frida_panel`.

The Frida panel's Modules/Stalker sub-tab strip must not clip. The right-hand
``QTabWidget`` reports a combined minimum width driven by its widest page (the
unwrapped Hooks header row alone forces a ~523px floor), which would push the whole
three-pane splitter past any reasonable docked-panel width. Each right-tab page is
therefore wrapped in the same ``_make_scrollable`` viewport ``AnalysisPanelBase``
uses for the Advanced tab, and the sub-tab strip's overflow behaviour is set
explicitly rather than left to a style-dependent default.

The Console Output pane must not be squeezed off the visible area. A plain
``QPlainTextEdit`` carries no real minimum height, so the taller top splitter above
it consumes all available room first. The pane therefore gets a deliberate,
font-derived minimum height, and ``[error]`` script messages are mirrored into the
structured application log so an agent-side script exception is never silent even if
the console itself is scrolled out of view.

Each test targets one concrete behavioural property: real reported minimum sizes, a
real wrapped-widget type, real post-layout geometry under a squeeze, and a real
captured log record, never a stubbed return value.
"""

from __future__ import annotations

import os

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QPlainTextEdit, QScrollArea, QTabWidget, QWidget
from structlog.testing import capture_logs

from intellicrack.ui.panels.frida_panel import FridaPanel


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_SQUEEZED_PANEL_WIDTH = 1414
_SQUEEZED_PANEL_HEIGHT = 300
_MIN_CONSOLE_HEIGHT_FLOOR = 100
_MAX_PANEL_MIN_WIDTH = 750


@pytest.mark.usefixtures("qapp")
class TestRightTabsOverflow:
    """The right-hand sub-tab strip must never force the panel past a docked width."""

    @staticmethod
    def test_configure_tab_overflow_forces_no_elide_and_scroll_buttons() -> None:
        """``_configure_tab_overflow`` must force ElideNone and scroll buttons on a tab bar left in the opposite state."""
        tabs = QTabWidget()
        tabs.addTab(QWidget(), "Advanced")
        tab_bar = tabs.tabBar()
        assert tab_bar is not None
        tab_bar.setElideMode(Qt.TextElideMode.ElideRight)
        tab_bar.setUsesScrollButtons(False)

        FridaPanel._configure_tab_overflow(tabs)

        assert tab_bar.elideMode() == Qt.TextElideMode.ElideNone, (
            "a right-aligned elide mode truncates long tab labels (e.g. 'Advanced' -> 'Adv') even when scroll buttons exist"
        )
        assert tab_bar.usesScrollButtons() is True, "without scroll buttons a clipped tab becomes unreachable"

    @staticmethod
    def test_right_tabs_pages_are_wrapped_in_scroll_areas() -> None:
        """Every page hosted by the right-hand tab widget must be a scroll-area wrapper, not the raw section widget."""
        panel = FridaPanel()
        for index in range(panel._right_tabs.count()):
            page = panel._right_tabs.widget(index)
            assert isinstance(page, QScrollArea), (
                f"tab {panel._right_tabs.tabText(index)!r} page is a bare {type(page).__name__}, "
                "not scroll-wrapped, so its unwrapped control rows inflate the tab widget's minimum width"
            )

    @staticmethod
    def test_frida_panel_minimum_width_recovers_from_tab_bloat() -> None:
        """The panel's reported minimum width must stay well below the ~991px floor the Hooks tab would otherwise drive."""
        panel = FridaPanel()
        min_width = panel.minimumSizeHint().width()
        assert min_width < _MAX_PANEL_MIN_WIDTH, (
            f"panel minimumSizeHint width is {min_width}px; an unwrapped right-tabs page is again forcing "
            f"the whole panel past a reasonable docked width (must stay under {_MAX_PANEL_MIN_WIDTH}px)"
        )


@pytest.mark.usefixtures("qapp")
class TestConsoleOutputMinimumHeight:
    """The Console Output pane must keep a real, usable minimum height under vertical pressure."""

    @staticmethod
    def test_console_output_resists_vertical_squeeze() -> None:
        """Squeezing the panel's total height must not push Console Output below a legible height."""
        panel = FridaPanel()
        panel.resize(_SQUEEZED_PANEL_WIDTH, _SQUEEZED_PANEL_HEIGHT)
        panel.show()
        try:
            QApplication.processEvents()
            console_height = panel._console.height()
        finally:
            panel.hide()
        assert console_height >= _MIN_CONSOLE_HEIGHT_FLOOR, (
            f"Console Output rendered at {console_height}px under a {_SQUEEZED_PANEL_HEIGHT}px panel height; "
            f"it must never be squeezed below {_MIN_CONSOLE_HEIGHT_FLOOR}px or script output/errors become invisible"
        )


@pytest.mark.usefixtures("qapp")
class TestScriptEditorWrapping:
    """The Frida script editor must wrap long lines rather than truncating them."""

    @staticmethod
    def test_script_editor_wraps_long_lines_instead_of_truncating() -> None:
        """The script editor must use widget-width line wrapping, not ``NoWrap``."""
        panel = FridaPanel()
        assert panel._script_editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth, (
            "script editor must wrap hook code to the widget width instead of truncating each line off-screen"
        )


@pytest.mark.usefixtures("qapp")
class TestFridaScriptErrorVisibility:
    """A Frida script's runtime error must never be silent, even if the console pane is not visible."""

    @staticmethod
    def test_frida_script_error_message_is_logged_and_echoed_to_console() -> None:
        """An ``error``-typed Frida message must reach both the console text and the structured app log."""
        panel = FridaPanel()

        with capture_logs() as captured:
            panel._on_frida_message({"type": "error", "description": "TypeError: bad arg count"})

        console_text = panel._console.toPlainText()
        assert "[error] TypeError: bad arg count" in console_text, (
            f"script error text never reached the console; console holds {console_text!r}"
        )
        error_events = [entry for entry in captured if entry.get("event") == "frida_script_error"]
        assert error_events, f"no frida_script_error record was logged; captured {captured!r}"
        assert any(entry.get("description") == "TypeError: bad arg count" for entry in error_events), (
            f"the logged record dropped the real error text: {error_events!r}"
        )
