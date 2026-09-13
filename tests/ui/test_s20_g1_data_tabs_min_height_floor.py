# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for the Ghidra share of S20-D09/S20-D14 -- the data-tabs pane floor.

``GhidraPanel._create_data_tabs`` (src/intellicrack/ui/panels/ghidra_panel.py)
used to call ``tabs.setMinimumHeight(32)``. Because an explicit
``QWidget.minimumSize`` overrides a widget's own computed layout minimum
outright when a parent layout asks for it (Qt's ``qSmartMinSize``:
``if (minSize.height() > 0) s.setHeight(minSize.height())`` replaces, rather
than maxes with, whatever the widget's real content needs), that 32px value
let the vertical splitter hosting ``_data_tabs`` (``left_splitter`` in
``GhidraPanel._create_content``) squeeze the whole 18-tab pane down to a
sliver no matter how tall the active tab's own content actually needed to be
-- the proximate cause of the Analysis Extras and Scripting tab crush/overlap
findings (S20-D09, S20-D14).

The fix raises that floor to a genuinely usable height. Individual data tabs
(Scripting, Analysis Extras) additionally carry their own internal scrollable
floor, so this constant only needs to keep the pane itself from collapsing
below a usable size -- overflow within the active tab scrolls (see
``test_s20_g1_scripting_tab_scroll.py`` and
``test_s20_g1_analysis_extras_scroll.py``).

The assertion reads the live ``minimumHeight()`` off a real, fully
constructed ``GhidraPanel`` under an offscreen ``QApplication`` -- no mocked
widgets, no restated constant value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Iterator

# The pre-fix value (S20-D09/S20-D14 root cause) was 32px -- smaller than any
# real data tab could use without being crushed. The fix must clear this by a
# wide margin so a genuinely usable amount of the active tab stays visible
# before its own internal scroll area needs to take over.
_MIN_USABLE_DATA_TABS_HEIGHT_PX = 150


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


class TestDataTabsPaneHasAUsableFloor:
    """The bottom data-tabs pane must not be squeezable below a usable height."""

    @staticmethod
    def test_data_tabs_minimum_height_clears_the_pre_fix_floor(panel: GhidraPanel) -> None:
        """``_data_tabs.minimumHeight()`` must exceed the crushed-sliver floor the bug shipped with.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        tabs = panel._data_tabs
        assert tabs is not None
        assert tabs.minimumHeight() >= _MIN_USABLE_DATA_TABS_HEIGHT_PX, (
            f"_data_tabs.minimumHeight()={tabs.minimumHeight()} -- the surrounding vertical "
            "splitter can still squeeze the active data tab into an unusable sliver regardless "
            "of that tab's own content"
        )
