# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate: x64dbg option combos show capitalized labels but keep bridge-token values.

The Breakpoints/Watchpoints/Console/Memory-Map combos previously listed their
options in lowercase (``software``/``hardware``/``memory``), which doubled as
both the display text and the exact token handed to the x64dbg bridge enums.
This gate pins the fix: each item must render a capitalized caption while
carrying the original lowercase token as its item data, so the bridge still
receives ``software``/``hardware``/``memory`` etc. even though the user sees
``Software``/``Hardware``/``Memory``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_EXPECTED_ITEMS: dict[str, list[tuple[str, str]]] = {
    "_bp_type_combo": [("Software", "software"), ("Hardware", "hardware"), ("Memory", "memory")],
    "_wp_type_combo": [("Read", "read"), ("Write", "write"), ("Execute", "execute")],
    "_exc_handling_combo": [("Break", "break"), ("Ignore", "ignore"), ("Log", "log")],
    "_alloc_prot_combo": [("RWX", "rwx"), ("RW", "rw"), ("RX", "rx"), ("R", "r")],
}


@pytest.mark.usefixtures("qapp")
def test_option_combos_show_capitalized_labels_with_lowercase_token_data(qapp: QApplication) -> None:
    """Every option combo must pair a capitalized caption with its lowercase bridge token."""
    panel = X64DbgPanel()
    try:
        for attr, expected in _EXPECTED_ITEMS.items():
            combo = getattr(panel, attr)
            actual = [(combo.itemText(i), combo.itemData(i)) for i in range(combo.count())]
            assert actual == expected, f"{attr} items were {actual}, expected {expected}"

            label = combo.currentText()
            token = combo.currentData()
            assert label != token, f"{attr} caption {label!r} must differ from its bridge token"
            assert isinstance(token, str), f"{attr} token {token!r} must be stored as item data"
            assert token.islower(), f"{attr} current token {token!r} must be a lowercase bridge token read via currentData()"
    finally:
        panel.close()
        qapp.processEvents()
