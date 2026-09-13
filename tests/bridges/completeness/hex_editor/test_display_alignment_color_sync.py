# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate: display mode / alignment grid / color mode must sync in both directions.

Covers the hex-editor bridge-routing finding's display-config sub-item.

GUI -> bridge: ``HexEditorPanel._on_display_mode_changed`` /
``_on_alignment_changed`` / ``_on_color_mode_changed``
(``ui/panels/hex_editor/panel.py``) only ever called the widget's own
``set_display_mode`` / ``set_alignment_grid_size`` / ``set_color_mode``.
They never informed the bridge, so ``hex_editor.get_display_mode`` /
``get_color_mode`` / ``get_alignment_grid`` never reflected what the user
actually picked in the toolbar.

Bridge -> GUI: ``HexEditorPanel._on_state_event`` handled
``DOCUMENT_OPENED`` / ``CURSOR_MOVED`` / ``DATA_MODIFIED`` /
``SELECTION_CHANGED`` (plus template/highlight events) but had no case for
``DISPLAY_MODE_CHANGED`` / ``ALIGNMENT_GRID_CHANGED`` / ``COLOR_MODE_CHANGED``,
so an AI-issued ``hex_editor.set_display_mode(...)`` changed bridge state and
nothing visible happened in the open window.

The fix adds synchronous ``HexEditorBridge.update_display_mode_from_gui`` /
``update_alignment_grid_from_gui`` / ``update_color_mode_from_gui`` methods
(mirroring the existing ``update_selection_from_gui``), calls them -- plus
the matching ``HexDocumentState.notify_*_changed(..., source="panel")`` --
from the three GUI handlers, and adds the three missing inbound cases to
``_on_state_event`` that apply the bridge-driven value to
``self._hex_widget``.

Every test here drives the REAL, unmodified ``HexEditorPanel`` /
``HexEditorBridge`` / ``HexDocumentState`` against a real
``intellicrack_hexcore.HexDocument`` opened on a real temp file, changing
the GUI side through the actual toolbar ``QComboBox`` widgets (the same
controls a user clicks) and the bridge side through the actual async
``HexEditorBridge`` setter coroutines (the same calls an AI tool makes).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QComboBox

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentState
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget

from .conftest import open_doc, priv, release_and_unlink


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


class TestGuiChangesPushToBridge:
    """Picking a value from the toolbar combos must update the real bridge state."""

    @staticmethod
    def test_display_mode_combo_updates_bridge_get_display_mode(qapp: QApplication) -> None:
        """Selecting a display mode in the toolbar must be readable via ``bridge.get_display_mode``.

        Falsifiable: if ``_on_display_mode_changed`` were reverted to
        applying only ``self._hex_widget.set_display_mode(mode)``,
        ``bridge.get_display_mode()`` would stay at the bridge's default
        ``"hex8"`` instead of reflecting ``"hex16_le"``. Broken
        production line: the ``self._bridge.update_display_mode_from_gui(mode)``
        call in ``HexEditorPanel._on_display_mode_changed``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_hex_widget", HexEditorWidget).set_document(bridge.document)

            assert _run(bridge.get_display_mode()) == "hex8"
            priv(panel, "_display_mode_combo", QComboBox).setCurrentText("hex16_le")

            assert _run(bridge.get_display_mode()) == "hex16_le"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_alignment_combo_updates_bridge_get_alignment_grid(qapp: QApplication) -> None:
        """Selecting an alignment grid size in the toolbar must be readable via ``bridge.get_alignment_grid``.

        Falsifiable: if ``_on_alignment_changed`` were reverted to
        applying only ``self._hex_widget.set_alignment_grid_size(size)``,
        ``bridge.get_alignment_grid()`` would stay at the bridge's
        default ``0`` instead of reflecting ``4096``. Broken production
        line: the ``self._bridge.update_alignment_grid_from_gui(size)``
        call in ``HexEditorPanel._on_alignment_changed``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_hex_widget", HexEditorWidget).set_document(bridge.document)

            assert _run(bridge.get_alignment_grid()) == 0
            priv(panel, "_alignment_combo", QComboBox).setCurrentText("4096 (Page)")

            assert _run(bridge.get_alignment_grid()) == 4096
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_color_mode_combo_updates_bridge_get_color_mode(qapp: QApplication) -> None:
        """Selecting a color mode in the toolbar must be readable via ``bridge.get_color_mode``.

        Falsifiable: if ``_on_color_mode_changed`` were reverted to
        applying only ``self._hex_widget.set_color_mode(mode)``,
        ``bridge.get_color_mode()`` would stay at the bridge's default
        ``"none"`` instead of reflecting ``"entropy"``. Broken
        production line: the ``self._bridge.update_color_mode_from_gui(mode)``
        call in ``HexEditorPanel._on_color_mode_changed``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv(panel, "_hex_widget", HexEditorWidget).set_document(bridge.document)

            assert _run(bridge.get_color_mode()) == "none"
            priv(panel, "_color_mode_combo", QComboBox).setCurrentText("Entropy Heatmap")

            assert _run(bridge.get_color_mode()) == "entropy"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestBridgeChangesApplyToWidget:
    """An AI/CLI-issued bridge setter must become visible in the real hex-view widget."""

    @staticmethod
    def test_bridge_set_display_mode_applies_to_widget(qapp: QApplication) -> None:
        """``bridge.set_display_mode`` must change the real widget's display mode.

        Falsifiable: without the new ``DISPLAY_MODE_CHANGED`` case in
        ``_on_state_event``, the widget's ``_display_mode`` would stay
        at its default ``"hex8"`` after this bridge call, even though
        the bridge itself accepted and stored ``"dec_u32"``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            hex_widget = priv(panel, "_hex_widget", HexEditorWidget)
            hex_widget.set_document(bridge.document)

            assert priv(hex_widget, "_display_mode", str) == "hex8"
            _run(bridge.set_display_mode("dec_u32"))

            assert priv(hex_widget, "_display_mode", str) == "dec_u32"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_bridge_set_alignment_grid_applies_to_widget(qapp: QApplication) -> None:
        """``bridge.set_alignment_grid`` must change the real widget's alignment grid size.

        Falsifiable: without the new ``ALIGNMENT_GRID_CHANGED`` case in
        ``_on_state_event``, the widget's ``_alignment_grid_size`` would
        stay at its default ``0`` after this bridge call, even though
        the bridge itself accepted and stored ``8192``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            hex_widget = priv(panel, "_hex_widget", HexEditorWidget)
            hex_widget.set_document(bridge.document)

            assert priv(hex_widget, "_alignment_grid_size", int) == 0
            _run(bridge.set_alignment_grid(8192))

            assert priv(hex_widget, "_alignment_grid_size", int) == 8192
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_bridge_set_color_mode_applies_to_widget(qapp: QApplication) -> None:
        """``bridge.set_color_mode`` must change the real widget's color mode.

        Falsifiable: without the new ``COLOR_MODE_CHANGED`` case in
        ``_on_state_event``, the widget's ``_color_mode`` would stay at
        its default ``"none"`` after this bridge call, even though the
        bridge itself accepted and stored ``"byte_value"``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        state_holder = HexDocumentState()
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            panel.set_state_holder(state_holder)
            bridge.set_state_holder(state_holder)
            panel.set_bridge(bridge)
            panel.document = bridge.document
            hex_widget = priv(panel, "_hex_widget", HexEditorWidget)
            hex_widget.set_document(bridge.document)

            assert priv(hex_widget, "_color_mode", str) == "none"
            _run(bridge.set_color_mode("byte_value"))

            assert priv(hex_widget, "_color_mode", str) == "byte_value"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()
