# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for S20-D18: opening a tool must switch the tab widget to it.

Before the fix, ``add_hex_editor_tab``/``add_x64dbg_tab``/``add_cutter_tab``/
``add_ghidra_tab``/``add_frida_tab``/``add_process_tab``/``add_sandbox_tab``
all called ``self.tab_widget.addTab(...)`` (or returned an already-created
widget) without ever calling ``setCurrentWidget``/``setCurrentIndex``, so
with any other tool tab already open the newly created or re-surfaced panel
was appended/left behind the current tab and the user saw no visible change
(S20-D18). This test drives the real ``ToolOutputPanel`` with real embedded
tool widgets and asserts ``tab_widget.currentWidget()`` is the panel just
opened, both when it is freshly created and when it already existed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

_ALL_ADD_METHODS: tuple[str, ...] = (
    "add_x64dbg_tab",
    "add_cutter_tab",
    "add_ghidra_tab",
    "add_frida_tab",
    "add_process_tab",
    "add_hex_editor_tab",
    "add_sandbox_tab",
)


def _filler_method_for(target_method: str) -> str:
    """Pick a filler ``add_*_tab`` method distinct from ``target_method``.

    Args:
        target_method: The method under test, which must not also be used
            to create the filler tab.

    Returns:
        str: The name of a different ``add_*_tab`` method to open first so
        the tab widget has a current tab other than ``target_method``'s.
    """
    return "add_cutter_tab" if target_method == "add_x64dbg_tab" else "add_x64dbg_tab"


@pytest.mark.usefixtures("qapp")
@pytest.mark.parametrize("target_method", _ALL_ADD_METHODS)
def test_add_tab_focuses_newly_created_panel_over_current_tab(target_method: str) -> None:
    """Creating a new tool tab must make it the current tab, not leave another tab focused.

    Args:
        target_method: Name of the ``add_*_tab`` method under test.
    """
    panel = ToolOutputPanel()
    try:
        filler_method = _filler_method_for(target_method)
        filler_widget: QWidget | None = getattr(panel, filler_method)()
        assert filler_widget is not None, f"test premise: {filler_method} must produce a widget in this environment"
        filler_index = panel.tab_widget.indexOf(filler_widget)
        panel.tab_widget.setCurrentIndex(filler_index)
        assert panel.tab_widget.currentWidget() is filler_widget, (
            f"test premise: {filler_method}'s tab is current before opening {target_method}"
        )

        target_widget: QWidget | None = getattr(panel, target_method)()
        if target_widget is None:
            pytest.skip(f"{target_method} is unavailable in this test environment")

        assert panel.tab_widget.currentWidget() is target_widget, (
            f"{target_method} did not focus its newly created tab while {filler_method}'s tab was current (D18)"
        )
    finally:
        panel.deleteLater()


@pytest.mark.usefixtures("qapp")
@pytest.mark.parametrize("target_method", _ALL_ADD_METHODS)
def test_reopening_an_already_open_tab_refocuses_it(target_method: str) -> None:
    """Re-invoking ``add_*_tab`` for an already-open panel must re-raise/focus it, not leave it hidden.

    Args:
        target_method: Name of the ``add_*_tab`` method under test.
    """
    panel = ToolOutputPanel()
    try:
        target_widget: QWidget | None = getattr(panel, target_method)()
        if target_widget is None:
            pytest.skip(f"{target_method} is unavailable in this test environment")

        filler_method = _filler_method_for(target_method)
        filler_widget: QWidget | None = getattr(panel, filler_method)()
        assert filler_widget is not None, f"test premise: {filler_method} must produce a widget in this environment"
        assert panel.tab_widget.currentWidget() is filler_widget, (
            f"test premise: {filler_method}'s tab is current before re-opening {target_method}"
        )

        reopened: QWidget | None = getattr(panel, target_method)()
        assert reopened is target_widget, f"{target_method} must return the existing widget when the tab is already open"
        assert panel.tab_widget.currentWidget() is target_widget, (
            f"re-opening the already-open {target_method} tab did not refocus it while {filler_method}'s tab was current (D18)"
        )
    finally:
        panel.deleteLater()
