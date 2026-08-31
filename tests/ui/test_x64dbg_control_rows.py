# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate: x64dbg dense control rows must stay readable when the panel is narrow.

The x64dbg bottom tabs (Breakpoints, Memory, Watchpoints, ...) each pack a
label/input/button row into a plain ``QHBoxLayout``. When the panel is squeezed
narrow, Qt shrinks every button below its caption and elides it to unreadable
fragments (``Enable BP`` -> ``ble``). Hosting each row in a horizontally
scrollable viewport keeps the controls at their natural width and scrolls
instead. This module drives the real panel narrow and asserts the breakpoint
buttons never render smaller than the width their captions require.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QScrollArea

from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication, QPushButton, QWidget


def _enclosing_scroll_area(widget: QWidget) -> QScrollArea | None:
    """Return the nearest ancestor QScrollArea of ``widget``, if any.

    Args:
        widget: The widget whose ancestry is walked.

    Returns:
        QScrollArea | None: The closest enclosing scroll area, or None.
    """
    node = widget.parentWidget()
    while node is not None:
        if isinstance(node, QScrollArea):
            return node
        node = node.parentWidget()
    return None


@pytest.mark.usefixtures("qapp")
def test_breakpoint_buttons_stay_readable_when_panel_is_narrow(qapp: QApplication) -> None:
    """Squeezed narrow, every breakpoint button must keep at least its caption's width."""
    panel = X64DbgPanel()
    try:
        panel.resize(560, 760)
        panel.show()
        qapp.processEvents()

        buttons: list[QPushButton] = [
            panel._add_bp_btn,
            panel._remove_bp_btn,
            panel._set_api_bp_btn,
            panel._enable_bp_btn,
            panel._disable_bp_btn,
        ]

        scroll = _enclosing_scroll_area(panel._add_bp_btn)
        assert scroll is not None, "the breakpoint control row must be hosted in a scroll area"

        hbar = scroll.horizontalScrollBar()
        assert hbar is not None
        assert hbar.maximum() > 0, "the row must genuinely overflow at 560px wide, otherwise this gate proves nothing"

        for btn in buttons:
            required = btn.sizeHint().width()
            assert btn.width() >= required, f"button {btn.text()!r} rendered {btn.width()}px, narrower than its {required}px caption"
    finally:
        panel.close()
        qapp.processEvents()
