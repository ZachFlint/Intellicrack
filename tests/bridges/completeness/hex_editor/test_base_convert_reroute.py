# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for the hex-editor calculator base-convert reroute.

Covers the calculator tab's "Convert" action
(``ui/panels/hex_editor/calculator.py`` ``CalculatorMixin._on_convert``),
which now dispatches to ``HexEditorBridge.base_convert`` when a bridge is
attached, so the AI-callable tool and the GUI's base/type-representation
computation share a single implementation. A local, purely synchronous
fallback (``_convert_local``) remains for headless/no-bridge callers and
is exercised separately to confirm it stays intact.

Every test drives the real, unmodified ``CalculatorMixin`` wiring through
a real ``HexEditorPanel``; the only test double is a recording
``HexEditorBridge`` subclass (``RecordingHexEditorBridge`` in
``conftest.py``) that delegates to the real ``base_convert`` classmethod
after appending to its call ledger, so the rendered results remain a
genuine end-to-end check rather than a canned response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QLineEdit, QTreeWidget

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import RecordingHexEditorBridge, priv, priv_method, pump_until, tree_row_map


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


class TestBaseConvertRoutesThroughBridge:
    """The "Convert" action must call ``HexEditorBridge.base_convert`` when a bridge is attached."""

    @staticmethod
    def test_convert_with_bridge_dispatches_base_convert_and_renders_result(qapp: QApplication) -> None:
        """Triggering convert with a bridge attached must call ``bridge.base_convert`` and render its result.

        Falsifiable: if ``_on_convert`` were reverted to call
        ``self._convert_local(...)`` unconditionally (the
        pre-remediation behaviour), ``base_convert_calls`` would stay
        empty even though a bridge was attached. Broken production
        line: ``run_bridge_coroutine_logged(bridge.base_convert(text,
        from_base="auto"), ...)`` in ``CalculatorMixin._on_convert``
        (``ui/panels/hex_editor/calculator.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        try:
            panel.set_bridge(bridge)

            priv(panel, "_calc_input", QLineEdit).setText("0xFF")
            priv_method(panel, "_on_convert")()

            pump_until(qapp, lambda: len(bridge.base_convert_calls) > 0)

            assert bridge.base_convert_calls == [{"value": "0xFF", "from_base": "auto"}]

            results_tree = priv(panel, "_calc_results_tree", QTreeWidget)
            pump_until(qapp, lambda: results_tree.topLevelItemCount() > 0)
            rendered = tree_row_map(results_tree, 0, 1)
            assert rendered["Decimal"] == "255"
            assert rendered["Hex"] == "0xff"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_convert_without_bridge_uses_local_fallback_and_never_calls_bridge(qapp: QApplication) -> None:
        """With no bridge attached, convert must use ``_convert_local`` and never touch the bridge.

        Confirms the local fallback remains functional and distinct
        from the bridge path: this test constructs its own
        ``RecordingHexEditorBridge`` but never attaches it to the
        panel, so any call recorded on it would prove the panel
        reached for a bridge instance it was never given.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        unattached_bridge = RecordingHexEditorBridge()
        try:
            assert priv(panel, "_bridge", (RecordingHexEditorBridge, type(None))) is None

            priv(panel, "_calc_input", QLineEdit).setText("42")
            priv_method(panel, "_on_convert")()
            pump_until(qapp, lambda: False, timeout_s=0.5)

            assert unattached_bridge.base_convert_calls == []

            results_tree = priv(panel, "_calc_results_tree", QTreeWidget)
            rendered = tree_row_map(results_tree, 0, 1)
            assert rendered["Decimal"] == "42"
            assert rendered["Hex"] == "0x2A"
        finally:
            panel.deleteLater()
