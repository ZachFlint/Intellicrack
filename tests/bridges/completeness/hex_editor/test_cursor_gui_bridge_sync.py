# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate: ordinary GUI cursor navigation must reach the bridge/state holder.

Covers the hex-editor bridge-routing finding's cursor sub-item:
``HexEditorPanel._on_cursor_moved`` (``ui/panels/hex_editor/panel.py``), the
handler for ordinary click / arrow-key caret navigation, updated only the
local data-inspector/disassembly side panels and never told the shared
``HexDocumentState`` or the attached ``HexEditorBridge`` about the new
cursor offset -- unlike its sibling ``_on_selection_changed``, which already
pushed selection changes to both. Consequence: an AI orchestrator calling
``hex_editor.get_cursor_position`` after the user moved the caret read a
stale offset.

The fix adds a synchronous ``HexEditorBridge.update_cursor_from_gui`` method
(mirroring the existing ``update_selection_from_gui``) and calls it -- plus
``HexDocumentState.set_cursor(..., source="panel")`` -- from
``_on_cursor_moved``, guarded by a new ``_suppress_cursor_echo`` reentrancy
flag. The guard matters because ``_on_state_event``'s ``CURSOR_MOVED``
branch applies a bridge-originated move by calling the widget's own
``goto_offset``, which unconditionally re-emits the widget's ``cursor_moved``
signal; without the guard that re-emission would call back into
``_on_cursor_moved`` and publish a second, redundant GUI-sourced update for
a move that already came from the bridge.

Every test here drives the REAL, unmodified ``HexEditorPanel`` /
``HexEditorBridge`` / ``HexDocumentState`` against a real
``intellicrack_hexcore.HexDocument`` opened on a real temp file, moving the
cursor through the actual ``HexEditorWidget.goto_offset`` entry point (the
same call the widget's own mouse/keyboard handlers use) rather than invoking
any private panel handler directly.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
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


class TestGuiCursorMovePushesToBridgeAndStateHolder:
    """Ordinary GUI cursor navigation must publish the new offset forward."""

    @staticmethod
    def test_real_widget_goto_offset_updates_bridge_and_state_holder(qapp: QApplication) -> None:
        """Moving the caret via the real widget must update both sync targets.

        Falsifiable: if ``_on_cursor_moved`` were reverted to its pre-fix
        form (side-panel updates only, no bridge/state-holder push),
        ``bridge.get_cursor_position()`` would stay ``0`` and
        ``state_holder.cursor_offset`` would stay ``0`` even though the
        widget's own caret moved to byte 256. Broken production line:
        the ``self.state_holder.set_cursor(offset, source="panel")`` /
        ``self._bridge.update_cursor_from_gui(offset)`` calls in
        ``HexEditorPanel._on_cursor_moved``
        (``ui/panels/hex_editor/panel.py``).

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

            hex_widget.goto_offset(256)

            assert priv(hex_widget, "_cursor_offset", int) == 256
            assert _run(bridge.get_cursor_position()) == 256
            assert state_holder.cursor_offset == 256
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestAiIssuedCursorMoveDoesNotBounceBack:
    """A bridge-originated cursor move must not re-publish as a second GUI update."""

    @staticmethod
    def test_bridge_goto_offset_moves_widget_without_a_second_cursor_moved_publish(qapp: QApplication) -> None:
        """An AI-issued ``goto_offset`` must move the widget but publish CURSOR_MOVED exactly once.

        Falsifiable: if the ``_suppress_cursor_echo`` guard (or the
        ``try``/``finally`` around it in ``_on_state_event``) were
        removed while keeping the forward-sync fix, the widget's own
        ``cursor_moved`` signal -- re-emitted synchronously by
        ``goto_offset`` inside ``_on_state_event``'s ``CURSOR_MOVED``
        branch -- would call back into ``_on_cursor_moved``, which would
        publish a second, redundant ``CURSOR_MOVED`` notification with
        ``source="panel"``. This test's independent observer callback
        (registered under a distinct ``source_id`` so it receives every
        ``CURSOR_MOVED`` regardless of origin) would then record two
        events instead of one.

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

            cursor_events: list[dict[str, Any]] = []

            def _record(event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
                """Record every CURSOR_MOVED payload delivered to this observer.

                Args:
                    event_type: The event type being delivered.
                    data: Event-specific payload dictionary.
                """
                if event_type == HexDocumentEvent.CURSOR_MOVED:
                    cursor_events.append(data)

            state_holder.register_callback(_record, source_id="test-observer")

            _run(bridge.goto_offset(512))

            assert priv(hex_widget, "_cursor_offset", int) == 512
            assert cursor_events == [{"offset": 512}]
            assert _run(bridge.get_cursor_position()) == 512
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()
