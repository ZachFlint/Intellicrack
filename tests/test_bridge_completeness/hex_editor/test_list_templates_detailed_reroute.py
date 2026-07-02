# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for the hex-editor template-combo listing reroute.

Covers the templates tab's combo-box population
(``ui/panels/hex_editor/templates.py``
``TemplatesMixin._populate_template_combo``), which now dispatches to
``HexEditorBridge.list_templates_detailed`` when a bridge is attached
instead of calling the document's plain ``list_templates()`` directly.
The bridge method returns the same richer ``(name, description,
category, field_count)`` metadata the AI-callable tool sees, so the
combo box is populated from that single source even though only the
name is currently rendered into the widget.

Every test drives the real, unmodified ``TemplatesMixin`` wiring through
a real ``HexEditorPanel`` against a real
``intellicrack_hexcore.HexDocument``; the only test double is a
recording ``HexEditorBridge`` subclass (``RecordingHexEditorBridge`` in
``conftest.py``) that delegates to the real ``list_templates_detailed``
after appending to its call ledger, so the combo's contents remain a
genuine end-to-end result rather than a canned response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import intellicrack_hexcore
from PyQt6.QtWidgets import QComboBox

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import RecordingHexEditorBridge, open_doc, priv, priv_method, pump_until, release_and_unlink


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


class TestPopulateTemplateComboRoutesThroughBridge:
    """The template combo must populate via ``HexEditorBridge.list_templates_detailed``."""

    @staticmethod
    def test_populate_with_bridge_dispatches_bridge_and_matches_its_names(qapp: QApplication) -> None:
        """Populating the combo with a bridge attached must call the bridge and render its names exactly.

        Falsifiable: if ``_populate_template_combo`` were reverted to
        call ``self._populate_template_combo_fallback()``
        unconditionally (the pre-remediation behaviour),
        ``list_templates_detailed_calls`` would stay at 0 even though a
        bridge was attached. Broken production line:
        ``run_bridge_coroutine_logged(bridge.list_templates_detailed(),
        ...)`` in ``TemplatesMixin._populate_template_combo``
        (``ui/panels/hex_editor/templates.py:308``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, b"\x00" * 16)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv_method(panel, "_populate_template_combo")()
            pump_until(qapp, lambda: bridge.list_templates_detailed_calls > 0)

            assert bridge.list_templates_detailed_calls == 1

            combo = priv(panel, "_template_combo", QComboBox)
            pump_until(qapp, lambda: combo.count() > 0)

            document = priv(bridge, "document", intellicrack_hexcore.HexDocument)
            direct_detailed = document.list_templates_detailed()
            expected_ordered_names = [str(entry[0]) for entry in direct_detailed]

            assert combo.count() == len(expected_ordered_names)
            rendered_names = [combo.itemText(i) for i in range(combo.count())]
            assert rendered_names == expected_ordered_names
            assert "IMAGE_DOS_HEADER" in rendered_names
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_populate_without_bridge_uses_local_fallback_and_never_calls_bridge(qapp: QApplication) -> None:
        """With no bridge attached, the combo must populate via the local fallback and never touch the bridge.

        Confirms the local fallback remains functional and distinct
        from the bridge path: this test constructs its own
        ``RecordingHexEditorBridge`` but never attaches it to the
        panel, so any call recorded on it would prove the panel reached
        for a bridge instance it was never given.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        unattached_bridge = RecordingHexEditorBridge()
        local_bridge = HexEditorBridge()
        path = open_doc(local_bridge, b"\x00" * 16)
        try:
            assert priv(panel, "_bridge", (RecordingHexEditorBridge, type(None))) is None
            panel.document = local_bridge.document

            priv_method(panel, "_populate_template_combo")()

            assert unattached_bridge.list_templates_detailed_calls == 0

            combo = priv(panel, "_template_combo", QComboBox)
            assert combo.count() > 0
            assert "IMAGE_DOS_HEADER" in [combo.itemText(i) for i in range(combo.count())]
        finally:
            release_and_unlink(local_bridge, path)
            panel.deleteLater()
