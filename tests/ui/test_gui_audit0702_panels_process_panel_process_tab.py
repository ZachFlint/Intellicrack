# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""GUI-audit regression gates for :mod:`intellicrack.ui.panels.process_panel.process_tab`.

Finding M59: the ``QSplitter`` built for the "Process Info" sub-tab was left
with Qt's default ``childrenCollapsible=True`` and neither pane (the info
tree, nor the environment-variables widget) had a minimum size set. Dragging
the splitter handle to either edge -- or a user double-clicking it, a
standard Qt splitter gesture -- fully collapsed one pane to 0px with no
visible affordance to restore it. The fix calls
``splitter.setChildrenCollapsible(False)`` and gives both panes
``setMinimumHeight(_SPLIT_MIN_HEIGHT)``, so Qt refuses to shrink either pane
below its minimum size regardless of how far the handle is dragged.

Each test drives a real, shown :class:`ProcessTab` and a real
:class:`QSplitter` (no mocks/stubs) and calls ``QSplitter.moveSplitter`` --
the same primitive Qt uses internally when the user drags the handle or
double-clicks it to snap a pane to zero -- to verify the panes cannot be
collapsed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QSplitter, QTableWidget, QTreeWidget, QWidget

from intellicrack.ui.panels.process_panel.process_tab import _SPLIT_MIN_HEIGHT, ProcessTab


if TYPE_CHECKING:
    from collections.abc import Generator


_INFO_TAB_INDEX: int = 2
_SPLITTER_HEIGHT: int = 900
_SPLITTER_WIDTH: int = 400


def _find_info_splitter(widget: ProcessTab) -> QSplitter:
    """Locate the single ``QSplitter`` inside the Process Info sub-tab.

    Args:
        widget: The ``ProcessTab`` to search.

    Returns:
        QSplitter: The splitter dividing the info tree from the
        environment-variables table.
    """
    splitters = widget.findChildren(QSplitter)
    assert len(splitters) == 1, f"expected exactly one QSplitter in ProcessTab, found {len(splitters)}"
    return splitters[0]


@pytest.fixture
def process_tab(qapp: QApplication) -> Generator[ProcessTab]:
    """Build a real, shown :class:`ProcessTab` on its "Process Info" sub-tab.

    Args:
        qapp: Session ``QApplication`` fixture ensuring Qt is initialised.

    Yields:
        ProcessTab: A shown ``ProcessTab`` with the "Process Info"
        sub-tab selected and the info splitter sized to a known geometry.
    """
    del qapp
    widget = ProcessTab()
    widget.resize(_SPLITTER_WIDTH, _SPLITTER_HEIGHT + 100)
    widget.show()
    widget._tabs.setCurrentIndex(_INFO_TAB_INDEX)

    splitter = _find_info_splitter(widget)
    splitter.resize(_SPLITTER_WIDTH, _SPLITTER_HEIGHT)
    QApplication.processEvents()

    yield widget

    widget.deleteLater()


def test_m59_splitter_children_not_collapsible(process_tab: ProcessTab) -> None:
    """The info/env splitter must disable Qt's default pane-collapsing.

    Pre-fix, the splitter was constructed with no call to
    ``setChildrenCollapsible``, leaving Qt's default of ``True`` in effect,
    which is what permits a drag-to-edge or handle double-click to snap a
    pane to 0px.

    Args:
        process_tab: Real, shown ``ProcessTab`` fixture.
    """
    splitter = _find_info_splitter(process_tab)
    assert splitter.childrenCollapsible() is False


def test_m59_dragging_handle_to_top_edge_keeps_info_tree_visible(process_tab: ProcessTab) -> None:
    """Dragging the splitter handle to the top edge must not collapse the info tree.

    ``QSplitter.moveSplitter(0, 1)`` is the same primitive Qt uses when a
    user drags the handle (or double-clicks it) all the way to the top edge.
    Pre-fix (default ``childrenCollapsible=True``, no minimum height on the
    info tree) this collapsed the tree to 0px, as verified directly against
    an unpatched splitter/widget pair with the same construction. Post-fix,
    the enforced minimum height keeps the tree at least ``_SPLIT_MIN_HEIGHT``
    px tall.

    Args:
        process_tab: Real, shown ``ProcessTab`` fixture.
    """
    splitter = _find_info_splitter(process_tab)
    info_tree = splitter.widget(0)
    assert isinstance(info_tree, QTreeWidget)

    splitter.moveSplitter(0, 1)
    QApplication.processEvents()

    assert info_tree.height() >= _SPLIT_MIN_HEIGHT
    assert info_tree.isVisible()


def test_m59_dragging_handle_to_bottom_edge_keeps_env_table_visible(process_tab: ProcessTab) -> None:
    """Dragging the splitter handle to the bottom edge must not collapse the env pane.

    Mirrors the top-edge case for the second pane (the environment-variables
    widget containing ``_env_table``): pre-fix this pane had no minimum
    height either, so dragging the handle all the way down collapsed it to
    0px, hiding the environment-variables table entirely.

    Args:
        process_tab: Real, shown ``ProcessTab`` fixture.
    """
    splitter = _find_info_splitter(process_tab)
    env_widget = splitter.widget(1)
    assert isinstance(env_widget, QWidget)
    env_table = env_widget.findChild(QTableWidget)
    assert env_table is not None

    splitter.moveSplitter(splitter.height(), 1)
    QApplication.processEvents()

    assert env_widget.height() >= _SPLIT_MIN_HEIGHT
    assert env_widget.isVisible()
    assert env_table.isVisible()


def test_m59_both_panes_have_minimum_height_configured(process_tab: ProcessTab) -> None:
    """Both splitter panes must carry an explicit, non-trivial minimum height.

    This is the concrete configuration the fix introduces
    (``setMinimumHeight(_SPLIT_MIN_HEIGHT)`` on both the info tree and the
    environment-variables widget); pre-fix neither widget had any minimum
    size set (``minimumHeight()`` defaults to ``0``), which is precisely
    what let ``moveSplitter`` collapse either pane to zero.

    Args:
        process_tab: Real, shown ``ProcessTab`` fixture.
    """
    splitter = _find_info_splitter(process_tab)
    info_tree = splitter.widget(0)
    env_widget = splitter.widget(1)
    assert info_tree is not None
    assert env_widget is not None

    assert info_tree.minimumHeight() >= _SPLIT_MIN_HEIGHT
    assert env_widget.minimumHeight() >= _SPLIT_MIN_HEIGHT
