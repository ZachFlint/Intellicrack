# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit fixes in ``script_manager``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``M62``: the script list/editor ``QSplitter`` must have
  ``childrenCollapsible() is False``, matching the codebase's established
  fix (``app.py``, ``cutter_panel.py``, ``ghidra_panel.py``, ...), so
  dragging the handle toward the left edge cannot hide the entire script
  list and type filter.
* ``L14``: ``ScriptListWidget._refresh_list`` must attach a tooltip
  carrying the full, un-elided ``"[Type] Name"`` text to every list item,
  so a long user-entered script name that Qt visually elides in the
  narrow (140-250px) left panel can still be read by hovering the item.

All tests drive real :class:`ScriptListWidget` / :class:`ScriptManagerPanel`
instances under an offscreen ``QApplication``; nothing is mocked.
"""

from __future__ import annotations

from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QApplication, QSplitter

from intellicrack.ui.panels.script_manager import ScriptListWidget, ScriptManagerPanel


_LONG_SCRIPT_NAME = "License Validation Bypass For XYZ Application version Two"


def test_m62_splitter_children_not_collapsible(qapp: QApplication) -> None:
    """The script list/editor splitter must disable child collapsing.

    Pre-fix, ``splitter`` was constructed with no
    ``setChildrenCollapsible(False)`` call, so Qt's default
    ``childrenCollapsible=True`` let the handle be dragged (via
    ``moveSplitter``) past the left panel's minimum size hint, collapsing
    it -- and the entire script list plus type filter combo -- to zero
    width. Post-fix, ``childrenCollapsible()`` is ``False`` and Qt clamps
    the drag to the left pane's minimum size instead of collapsing it.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = ScriptManagerPanel()
    panel.resize(900, 500)
    panel.show()
    QApplication.processEvents()
    try:
        splitter = panel.findChild(QSplitter)
        assert splitter is not None, "panel must contain the list/editor splitter"
        assert splitter.childrenCollapsible() is False, "splitter must disable child collapsing so the script list cannot vanish"

        before = splitter.sizes()
        assert len(before) == 2
        assert all(size > 0 for size in before), "test premise: both panes start with nonzero size"

        splitter.moveSplitter(0, 1)
        QApplication.processEvents()
        after = splitter.sizes()

        assert after[0] > 0, "left panel (script list + type filter) collapsed to zero width on a drag-to-left"
        assert after[1] > 0, "right panel (editor) collapsed to zero width on a drag-to-left"
    finally:
        panel.hide()


def test_m62_left_panel_widget_stays_visible_after_extreme_drag(qapp: QApplication) -> None:
    """Even an extreme handle drag must leave the script list widget visible.

    Exercises the concrete downstream consequence of the M62 defect: with
    collapsing enabled, the ``ScriptListWidget`` inside the left panel would
    be reduced to zero width and disappear from view. Post-fix it keeps a
    positive width.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    panel = ScriptManagerPanel()
    panel.resize(900, 500)
    panel.show()
    QApplication.processEvents()
    try:
        splitter = panel.findChild(QSplitter)
        assert splitter is not None

        script_list = panel.findChild(ScriptListWidget)
        assert script_list is not None

        splitter.moveSplitter(-500, 1)
        QApplication.processEvents()

        assert script_list.width() > 0, "script list collapsed to zero width, hiding it from the user"
    finally:
        panel.hide()


def _make_list_with_long_name(qapp: QApplication) -> ScriptListWidget:
    """Build a narrow ``ScriptListWidget`` populated with one long-named script.

    Args:
        qapp: Session QApplication fixture required for widget construction.

    Returns:
        ScriptListWidget: A shown, narrow list widget containing one item.
    """
    _ = qapp
    widget = ScriptListWidget()
    widget.setFixedWidth(140)
    widget.resize(140, 300)
    widget.add_script("script-1", _LONG_SCRIPT_NAME, "frida")
    widget.show()
    QApplication.processEvents()
    return widget


def test_l14_long_script_name_gets_full_tooltip(qapp: QApplication) -> None:
    """A long script name gets a tooltip carrying the full, un-elided text.

    Pre-fix, ``_refresh_list`` never called ``item.setToolTip(...)``, so
    ``QListWidgetItem.toolTip()`` was empty and hovering an elided item
    revealed nothing. Post-fix the tooltip equals the full ``"[Type] Name"``
    string.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    widget = _make_list_with_long_name(qapp)
    try:
        item = widget.item(0)
        assert item is not None
        expected_text = f"[Frida] {_LONG_SCRIPT_NAME}"
        assert item.text() == expected_text
        assert item.toolTip() == expected_text, "list item has no tooltip (or a mismatched one) carrying the full script name"
    finally:
        widget.deleteLater()


def test_l14_display_text_is_actually_elided_at_narrow_width(qapp: QApplication) -> None:
    """The narrow panel genuinely elides the long name, motivating the tooltip.

    Confirms the failure scenario is real: at the 140px minimum splitter
    width, Qt's font metrics report the full label wider than the visible
    row, so without a tooltip the rest of the name is unreadable.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    widget = _make_list_with_long_name(qapp)
    try:
        item = widget.item(0)
        assert item is not None
        full_text = item.text()

        metrics = QFontMetrics(widget.font())
        full_width = metrics.horizontalAdvance(full_text)
        viewport = widget.viewport()
        assert viewport is not None
        available_width = viewport.width()

        assert full_width > available_width, "test premise: the full item text must be wider than the visible row to prove elision occurs"
    finally:
        widget.deleteLater()


def test_l14_tooltip_survives_filter_refresh(qapp: QApplication) -> None:
    """The tooltip is rebuilt correctly when ``_refresh_list`` reruns on filter change.

    ``_refresh_list`` clears and rebuilds every item, so the tooltip fix
    must not be a one-off applied only at initial population.

    Args:
        qapp: Session QApplication fixture required for widget construction.
    """
    _ = qapp
    widget = ScriptListWidget()
    try:
        widget.add_script("script-1", _LONG_SCRIPT_NAME, "frida")
        widget.add_script("script-2", "short", "python")

        widget.set_filter("frida")
        assert widget.count() == 1
        item = widget.item(0)
        assert item is not None
        expected_text = f"[Frida] {_LONG_SCRIPT_NAME}"
        assert item.toolTip() == expected_text

        widget.set_filter(None)
        assert widget.count() == 2
        rebuilt_item = widget.item(0) if widget.item(0) and widget.item(0).text().startswith("[Frida]") else widget.item(1)
        assert rebuilt_item is not None
        assert rebuilt_item.toolTip() == expected_text, "tooltip was not reattached after _refresh_list rebuilt the item"
    finally:
        widget.deleteLater()
