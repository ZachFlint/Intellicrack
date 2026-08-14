# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate: ``ToolOutputPanel.reset_analysis`` must clear Functions/XRefs too.

``reset_analysis`` (tools.py) is invoked from ``app.py._on_binary_loaded``
when a freshly loaded binary turns out to be an unsupported/unrecognised
format (F11): the analysis panel's header resets to "No binary loaded" so no
stale data is shown against the failed load. Pre-fix, ``reset_analysis`` only
called ``self.analysis_panel.clear()`` and never touched ``func_list`` /
``xref_panel`` -- both populated independently by
``update_bridge_analysis`` -- so the right-hand Functions navigator and
Cross References tree kept showing the *previous* binary's data even though
the header said no binary was loaded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.types import BridgeAnalysisSummary, FunctionInfo
from intellicrack.ui.tools import ToolOutputPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

_ADDR_MAIN: Final[int] = 0x401000
_ADDR_HELPER: Final[int] = 0x402000


def _make_summary(functions: list[FunctionInfo]) -> BridgeAnalysisSummary:
    """Build a ``BridgeAnalysisSummary`` populated only with functions.

    Args:
        functions: Functions to embed in the summary.

    Returns:
        BridgeAnalysisSummary: Summary with empty lists for unrelated fields.
    """
    return BridgeAnalysisSummary(
        binary_name="stale_target.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=functions,
        format_info="pe",
        architecture="x86_64",
        source_bridges=["cutter"],
        analysis_notes=[],
        complete=True,
    )


def _make_function(name: str, address: int) -> FunctionInfo:
    """Build a minimal ``FunctionInfo`` for the function-list panel test.

    Args:
        name: Function name to display.
        address: Function start address.

    Returns:
        FunctionInfo: Dataclass instance with mandatory fields populated.
    """
    return FunctionInfo(
        name=name,
        address=address,
        size=64,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
    )


class TestResetAnalysisClearsFunctionsAndXrefs:
    """``reset_analysis`` must clear the function list and xref panel."""

    @staticmethod
    def test_reset_analysis_clears_stale_function_list(qapp: QApplication) -> None:
        """A previous binary's functions must not survive ``reset_analysis``.

        Populates the right-hand Functions navigator exactly the way a real
        binary load does (via ``update_bridge_analysis``), then drives the
        real unsupported-format reset path and asserts the navigator is
        empty afterward.

        Args:
            qapp: Session QApplication fixture from conftest.
        """
        del qapp
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            summary = _make_summary([
                _make_function("main", _ADDR_MAIN),
                _make_function("helper", _ADDR_HELPER),
            ])
            panel.update_bridge_analysis(summary)
            assert panel.func_list.get_functions() != [], "test setup must populate the function list first"

            panel.reset_analysis()

            assert panel.func_list.get_functions() == [], "reset_analysis left the previous binary's functions in the right-hand navigator"
            assert panel.func_list.list_widget.count() == 0
        finally:
            panel.deleteLater()

    @staticmethod
    def test_reset_analysis_clears_stale_xrefs(qapp: QApplication) -> None:
        """A previous binary's cross-references must not survive ``reset_analysis``.

        Args:
            qapp: Session QApplication fixture from conftest.
        """
        del qapp
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            panel.xref_panel.set_xrefs([(0x401, "caller")], [(0x402, "callee")])
            assert panel.xref_panel.xref_display.topLevelItemCount() == 2, "test setup must populate the xref panel first"

            panel.reset_analysis()

            assert panel.xref_panel.xref_display.topLevelItemCount() == 0, (
                "reset_analysis left the previous binary's cross-references in the xref panel"
            )
        finally:
            panel.deleteLater()

    @staticmethod
    def test_reset_analysis_still_clears_the_analysis_panel_header(qapp: QApplication) -> None:
        """The pre-existing analysis-panel clear behaviour must not regress.

        Args:
            qapp: Session QApplication fixture from conftest.
        """
        del qapp
        panel = ToolOutputPanel()
        try:
            panel.add_analysis_panel()
            summary = _make_summary([_make_function("main", _ADDR_MAIN)])
            panel.update_bridge_analysis(summary)
            assert panel.analysis_panel is not None
            assert panel.analysis_panel.current_analysis is not None

            panel.reset_analysis()

            assert panel.analysis_panel is not None
            assert panel.analysis_panel.current_analysis is None
        finally:
            panel.deleteLater()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
