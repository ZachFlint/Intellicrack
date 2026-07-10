# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for the hex-editor auto-bookmark-structure reroute.

Covers the templates tab's "Auto Bookmark Structure" action
(``ui/panels/hex_editor/templates.py``
``TemplatesMixin._on_auto_bookmark_structure``), which now dispatches to
``HexEditorBridge.generate_structure_bookmarks`` when a bridge is
attached instead of the GUI-local PE/ELF-only walk
(``_auto_bookmark_structure_local``). The bridge implementation also
covers Mach-O, which the local fallback does not, so an AI/orchestration
caller and the toolbar action now share one detection-and-bookmark
implementation.

Every test drives the real, unmodified ``TemplatesMixin`` wiring through
a real ``HexEditorPanel`` against a real
``intellicrack_hexcore.HexDocument``; the only test double is a
recording ``HexEditorBridge`` subclass (``RecordingHexEditorBridge`` in
``conftest.py``) that delegates to the real
``generate_structure_bookmarks`` after appending to its call ledger, so
the resulting bookmarks tree reflects a genuine end-to-end
detect-and-bookmark pass rather than a canned response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QTreeWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import RecordingHexEditorBridge, open_doc, priv, priv_method, pump_until, release_and_unlink, tree_columns


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


_MINIMAL_MZ_DOC = b"MZ" + b"\x00" * 62
"""A 64-byte document whose only recognisable structure is the DOS "MZ" magic.

Short enough that ``e_lfanew`` cannot be read, so
``HexEditorBridge._bookmark_pe_structure`` creates exactly one bookmark
("DOS Header") and returns -- giving a small, deterministic, real bridge
result to assert on without needing a full PE image.
"""


class TestAutoBookmarkStructureRoutesThroughBridge:
    """ "Auto Bookmark Structure" must call ``HexEditorBridge.generate_structure_bookmarks``."""

    @staticmethod
    def test_click_with_bridge_dispatches_bridge_and_renders_its_bookmark(qapp: QApplication) -> None:
        """Triggering auto-bookmark with a bridge attached must call the bridge and render its bookmark.

        Falsifiable: if ``_on_auto_bookmark_structure`` were reverted to
        call ``self._auto_bookmark_structure_local()`` unconditionally
        (the pre-remediation behaviour),
        ``generate_structure_bookmarks_calls`` would stay at 0 even
        though a bridge was attached, and the bookmark would have been
        created by the local walk against ``self.document`` directly
        rather than by the bridge's own ``document.add_bookmark`` call.
        Broken production line:
        ``run_bridge_coroutine_logged(bridge.generate_structure_bookmarks(),
        ...)`` in ``TemplatesMixin._on_auto_bookmark_structure``
        (``ui/panels/hex_editor/templates.py:512``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, _MINIMAL_MZ_DOC)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv_method(panel, "_on_auto_bookmark_structure")()
            pump_until(qapp, lambda: bridge.generate_structure_bookmarks_calls > 0)

            assert bridge.generate_structure_bookmarks_calls == 1

            bookmarks_tree = priv(panel, "_bookmarks_tree", QTreeWidget)
            pump_until(qapp, lambda: bookmarks_tree.topLevelItemCount() > 0)
            rows = tree_columns(bookmarks_tree, 0, 2)
            assert rows == [("0x00000000", "DOS Header")]
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_click_without_bridge_uses_local_walk_and_never_calls_bridge(qapp: QApplication) -> None:
        """With no bridge attached, the action must use the local PE walk and never touch the bridge.

        Confirms the local fallback remains functional and distinct
        from the bridge path: this test constructs its own
        ``RecordingHexEditorBridge`` but never attaches it to the
        panel, so any call recorded on it would prove the panel reached
        for a bridge instance it was never given.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        unattached_bridge = RecordingHexEditorBridge()
        local_bridge = HexEditorBridge()
        path = open_doc(local_bridge, _MINIMAL_MZ_DOC)
        try:
            assert priv(panel, "_bridge", (RecordingHexEditorBridge, type(None))) is None
            panel.document = local_bridge.document

            priv_method(panel, "_on_auto_bookmark_structure")()
            pump_until(qapp, lambda: False, timeout_s=0.5)

            assert unattached_bridge.generate_structure_bookmarks_calls == 0

            bookmarks_tree = priv(panel, "_bookmarks_tree", QTreeWidget)
            pump_until(qapp, lambda: bookmarks_tree.topLevelItemCount() > 0)
            rows = tree_columns(bookmarks_tree, 2)
            assert rows == [("DOS Header",)]
        finally:
            release_and_unlink(local_bridge, path)
            panel.deleteLater()
