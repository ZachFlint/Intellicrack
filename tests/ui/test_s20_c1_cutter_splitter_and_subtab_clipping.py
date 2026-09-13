# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the Cutter detached-panel splitter and sub-tab clipping fix (S20-D21).

Guards three real defects the live audit reproduced against the docked/detached
Cutter panel: the top/bottom outer splitter had no genuine minimum height on
its sub-tab pane, so an ordinary window resize could squeeze it to a sliver;
the outer splitter's proportions were never persisted, so a user's dragged
layout did not survive a redock/relaunch; and the Advanced Search mode row and
the Debugger attach/step row were built as bare ``QHBoxLayout``s with no floor,
so they could be compressed to zero height or have their leftmost controls
clipped off-screen. Every assertion below exercises real Qt widget geometry
and real ``QSettings`` round-trips, never a stubbed value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication, QComboBox, QScrollArea

from intellicrack.ui.panels import cutter_panel as cutter_panel_module
from intellicrack.ui.panels.cutter_debugger_tab import DebuggerTab
from intellicrack.ui.panels.cutter_panel import CutterPanel
from intellicrack.ui.panels.cutter_search_tab import SearchTab


if TYPE_CHECKING:
    from collections.abc import Generator


_EXTREME_TOP_HEAVY_SIZES: list[int] = [5000, 5, 5]
_PERSISTED_TEST_SIZES: list[int] = [321, 322, 157]


@pytest.fixture
def _clean_cutter_panel_settings() -> Generator[None]:
    """Clear persisted Cutter outer-splitter ``QSettings`` before and after a test.

    ``CutterPanel`` persists real ``QSettings`` state under
    ``Intellicrack/CutterPanel``. Clearing the key before and after each test
    keeps the persistence gate hermetic regardless of what a prior test run or
    a live app session left behind on this machine.

    Yields:
        None: The fixture only performs setup/teardown side effects.
    """
    settings = QSettings(cutter_panel_module._SETTINGS_ORG, cutter_panel_module._SETTINGS_APP)
    settings.remove(cutter_panel_module._SETTINGS_KEY_OUTER_SPLITTER)
    try:
        yield
    finally:
        settings.remove(cutter_panel_module._SETTINGS_KEY_OUTER_SPLITTER)


@pytest.mark.usefixtures("qapp", "_clean_cutter_panel_settings")
class TestCutterOuterSplitterMinimumHeight:
    """The sub-tab and console panes must carry a genuine minimum height floor."""

    @staticmethod
    def test_data_tabs_and_console_panes_have_real_minimum_height() -> None:
        """Data-tabs and console panes must report the module's minimum-height constants.

        A ``QSplitter`` only honours a child's real ``minimumHeight()``
        property as a resize floor; sizes seeded via ``setSizes()`` alone are
        not enough (S20-D21). This asserts the actual Qt property, not a
        splitter size hint.
        """
        panel = CutterPanel()
        splitter = panel._outer_splitter
        assert splitter is not None
        assert splitter.count() == 3

        data_tabs_widget = splitter.widget(1)
        console_widget = splitter.widget(2)
        assert data_tabs_widget is not None
        assert console_widget is not None
        assert data_tabs_widget.minimumHeight() == cutter_panel_module._DATA_TABS_MIN_HEIGHT
        assert console_widget.minimumHeight() == cutter_panel_module._CONSOLE_MIN_HEIGHT

    @staticmethod
    def test_extreme_top_heavy_resize_cannot_collapse_data_tabs_pane() -> None:
        """An extreme top-heavy resize must not squeeze the data-tabs pane below its floor.

        Reproduces the S20-D21 repro directly: a ``MoveWindow``/resize handing
        the top (code/decompiler) pane nearly all the height and squeezing the
        sub-tab pane to a sliver. ``QSplitter.setSizes()`` clamps requested
        sizes to each widget's real minimum size, so the fix must keep the
        data-tabs pane at or above its floor even when asked for 5px.
        """
        panel = CutterPanel()
        splitter = panel._outer_splitter
        assert splitter is not None
        splitter.resize(900, 900)
        splitter.show()
        QApplication.processEvents()

        splitter.setSizes(_EXTREME_TOP_HEAVY_SIZES)
        QApplication.processEvents()

        sizes = splitter.sizes()
        assert sizes[1] >= cutter_panel_module._DATA_TABS_MIN_HEIGHT, (
            f"data-tabs pane collapsed to {sizes[1]}px despite the {cutter_panel_module._DATA_TABS_MIN_HEIGHT}px floor"
        )
        splitter.hide()


@pytest.mark.usefixtures("qapp", "_clean_cutter_panel_settings")
class TestCutterOuterSplitterPersistence:
    """Manually dragged outer-splitter proportions must persist and be restored."""

    @staticmethod
    def test_splitter_moved_persists_sizes_to_qsettings() -> None:
        """Invoking the splitterMoved handler must write the current sizes to QSettings."""
        panel = CutterPanel()
        splitter = panel._outer_splitter
        assert splitter is not None
        splitter.setSizes(list(_PERSISTED_TEST_SIZES))

        panel._on_outer_splitter_moved(0, 1)

        settings = QSettings(cutter_panel_module._SETTINGS_ORG, cutter_panel_module._SETTINGS_APP)
        stored = settings.value(cutter_panel_module._SETTINGS_KEY_OUTER_SPLITTER)
        assert stored is not None, "dragging the splitter must persist its sizes"
        assert [int(v) for v in stored] == splitter.sizes()

    @staticmethod
    def test_new_panel_restores_persisted_sizes() -> None:
        """A freshly constructed panel must seed its splitter from persisted QSettings sizes.

        Establishes the "first" splitter's pre-drag geometry through
        ``_apply_outer_splitter_sizes()`` -- the same resize-to-exact-fit
        helper ``_create_content()`` itself uses to seed a splitter from
        loaded sizes -- rather than calling ``setSizes()`` on the splitter's
        incidental unshown-widget size. An unshown ``QSplitter`` that has
        never been resized by a real window carries an ambient default size
        that is undefined and can differ between two otherwise-identical
        ``CutterPanel`` constructions (Qt/style-internal caching state such
        as font metrics), so asserting pixel-exact equality against a
        splitter sized that way is not a meaningful gate. Giving the
        splitter exactly the room its target sizes need before dragging it
        -- exactly mirroring what a live, docked splitter with adequate
        screen space provides -- makes the persisted sizes and the resolved
        sizes deterministic and directly comparable. This still exercises
        the real ``QSettings`` round trip end to end: a broken
        ``_load_outer_splitter_sizes()``/``_on_outer_splitter_moved()`` pair,
        or a regression that silently falls back to defaults, still fails
        this assertion. The chosen proportions (roughly 40/40/20) differ
        sharply enough from the seeded defaults (roughly 50/31/19) that a
        regression which silently falls back to the defaults still produces
        a distinguishable result.
        """
        first = CutterPanel()
        first_splitter = first._outer_splitter
        assert first_splitter is not None
        CutterPanel._apply_outer_splitter_sizes(first_splitter, list(_PERSISTED_TEST_SIZES))
        first._on_outer_splitter_moved(0, 1)

        loaded = CutterPanel._load_outer_splitter_sizes()
        assert loaded == first_splitter.sizes()
        assert loaded != [
            cutter_panel_module._OUTER_SPLIT_TOP,
            cutter_panel_module._OUTER_SPLIT_MID,
            cutter_panel_module._OUTER_SPLIT_BOT,
        ], "persisted sizes must not silently equal the seeded defaults, or this gate could not detect a regression"

        second = CutterPanel()
        second_splitter = second._outer_splitter
        assert second_splitter is not None
        assert second_splitter.sizes() == loaded


@pytest.mark.usefixtures("qapp")
class TestSearchTabModeRowNeverCollapses:
    """The Advanced Search mode selector must be protected against zero-height squeeze."""

    @staticmethod
    def test_mode_row_is_wrapped_in_a_fixed_height_scroll_area() -> None:
        """The mode row must be hosted in a QScrollArea with a genuine fixed, non-zero height.

        Without this wrap, a squeezed sub-tab pane could compress the header
        label and Mode combo down toward zero height (S20-D21), making the
        Wildcard/String/Assembly/Crypto/Magic/Numeric modes unselectable.
        """
        tab = SearchTab()
        scroll = tab.findChild(QScrollArea)
        assert scroll is not None, "search panel must wrap its mode row in a QScrollArea"
        assert scroll.minimumHeight() > 0
        assert scroll.minimumHeight() == scroll.maximumHeight(), "control row must be a fixed, uncompressible height"

    @staticmethod
    def test_mode_combo_lives_inside_the_protected_row() -> None:
        """The real mode combo widget must be a descendant of the protected scroll area."""
        tab = SearchTab()
        scroll = tab.findChild(QScrollArea)
        assert scroll is not None
        inner = scroll.widget()
        assert inner is not None
        assert inner.isAncestorOf(tab._mode_combo)
        combos_in_row = inner.findChildren(QComboBox)
        assert tab._mode_combo in combos_in_row
        assert tab._value_size_combo in combos_in_row


@pytest.mark.usefixtures("qapp")
class TestDebuggerTabAttachRowNeverClips:
    """The debugger attach/step control row must stay reachable at natural size."""

    @staticmethod
    def test_attach_row_is_wrapped_in_a_fixed_height_scroll_area() -> None:
        """The attach/step row must be hosted in a QScrollArea with a genuine fixed, non-zero height.

        Without this wrap, a squeezed sub-tab pane clipped the Start/Attach/
        Spawn entry control off the left edge, leaving only Step Into/Over/
        Continue/Refresh reachable (S20-D21).
        """
        tab = DebuggerTab()
        scroll = tab.findChild(QScrollArea)
        assert scroll is not None, "debugger attach row must wrap its controls in a QScrollArea"
        assert scroll.minimumHeight() > 0
        assert scroll.minimumHeight() == scroll.maximumHeight(), "control row must be a fixed, uncompressible height"

    @staticmethod
    def test_attach_and_step_controls_live_inside_the_protected_row() -> None:
        """Attach and step controls must all be descendants of the protected scroll area."""
        tab = DebuggerTab()
        scroll = tab.findChild(QScrollArea)
        assert scroll is not None
        inner = scroll.widget()
        assert inner is not None
        for control in (
            tab._pid_input,
            tab._attach_btn,
            tab._detach_btn,
            tab._step_into_btn,
            tab._step_over_btn,
            tab._continue_btn,
            tab._refresh_btn,
        ):
            assert inner.isAncestorOf(control), f"{control} must remain inside the protected attach row"

    @staticmethod
    def test_protected_row_preserves_natural_unclipped_width() -> None:
        """The scrolled inner widget must reserve its full natural width, not a squeezed one.

        make_control_row() pins the inner widget's minimum width to its
        unclipped size hint; this asserts that floor is a real, positive Qt
        property rather than the layout's un-pinned default of zero.
        """
        tab = DebuggerTab()
        scroll = tab.findChild(QScrollArea)
        assert scroll is not None
        inner = scroll.widget()
        assert inner is not None
        assert inner.minimumWidth() > 0
