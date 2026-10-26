# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for the 64-bit address signals the Analysis tab depends on.

``ToolOutputPanel.address_clicked`` carries ``qint64`` so image-based x64 virtual
addresses are not truncated, so ``BridgeAnalysisPanel.address_navigate`` must carry
the same type. PyQt refuses a signal-to-signal connection whose argument types differ,
and a mismatch would make the connection at ``ToolOutputPanel.add_analysis_panel``
raise ``TypeError: connect() failed between BridgeAnalysisPanel.address_navigate[int]
and address_clicked()``. That throw lands *after* ``self.analysis_panel`` is
assigned but *before* ``addTab`` and the ``panels["analysis"]`` registration,
leaving a panel object with no tab. The application then logs
``analysis_summary_dropped reason=no_analysis_panel`` and discards real analysis results.

Both halves are gated here against real widgets: that constructing the panel
registers its tab, and that a >32-bit address emitted by either
address-carrying panel arrives at the receiver unmodified. The signals are
the production signals and the assertion is on the value a real
connected slot received.
"""

from __future__ import annotations

import pytest

from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel
from intellicrack.ui.panels.stack_viewer import StackViewerPanel
from intellicrack.ui.tools import ToolOutputPanel


pytestmark = pytest.mark.usefixtures("qapp")

_IMAGE_BASED_VA: int = 0x1400019C0
_TRUNCATED_VA: int = 0x400019C0


def test_add_analysis_panel_registers_its_tab() -> None:
    """Constructing the Analysis panel must wire its signal and register the tab."""
    panel = ToolOutputPanel()
    try:
        analysis_panel = panel.add_analysis_panel()

        assert isinstance(analysis_panel, BridgeAnalysisPanel)
        assert panel.panels.get("analysis") is analysis_panel, (
            "add_analysis_panel returned a panel it never registered in panels['analysis']"
        )
        tab_titles = [panel.tab_widget.tabText(index) for index in range(panel.tab_widget.count())]
        assert "Analysis" in tab_titles, f"the Analysis tab was never added; tabs are {tab_titles}"
    finally:
        panel.close()


def test_analysis_address_navigate_reaches_address_clicked_untruncated() -> None:
    """A >32-bit VA emitted by the Analysis panel must arrive whole at ``address_clicked``."""
    panel = ToolOutputPanel()
    try:
        analysis_panel = panel.add_analysis_panel()
        received: list[int] = []
        panel.address_clicked.connect(received.append)

        analysis_panel.address_navigate.emit(_IMAGE_BASED_VA)

        assert received == [_IMAGE_BASED_VA], (
            f"expected {_IMAGE_BASED_VA:#x} to reach address_clicked; got {[hex(value) for value in received]}"
        )
        assert _TRUNCATED_VA not in received, "the address was truncated to 32 bits in transit"
    finally:
        panel.close()


def test_stack_viewer_address_navigate_carries_a_64bit_address() -> None:
    """A >32-bit return address emitted by the stack viewer must not be truncated."""
    viewer = StackViewerPanel()
    try:
        received: list[int] = []
        viewer.address_navigate.connect(received.append)

        viewer.address_navigate.emit(_IMAGE_BASED_VA)

        assert received == [_IMAGE_BASED_VA], (
            f"expected {_IMAGE_BASED_VA:#x} from the stack viewer; got {[hex(value) for value in received]}"
        )
    finally:
        viewer.close()
