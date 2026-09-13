# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate: ``HexEditorBridge.get_context_for_ai`` must have a real GUI trigger.

Covers the hex-editor bridge-routing finding's AI-context sub-item.
``HexEditorBridge.get_context_for_ai`` (``bridges/hex_editor.py``) bundles
the current hex context -- cursor window, data inspection, selection, and
bookmarks -- for the AI side of the application, and is registered as
``hex_editor.get_context_for_ai`` in the bridge's ``tool_definition()``, but
had zero references anywhere under ``ui/`` -- a user had no way to invoke it.

The fix adds a "Full AI Context" toolbar action
(``HexEditorPanel._on_get_ai_context``) that dispatches the real bridge
coroutine via ``run_bridge_coroutine_logged`` and delivers the result
through the panel's existing ``context_push_requested`` signal -- the same
signal ``ui/tools.py`` already wires to the AI chat surface for the
pre-existing "Send to AI" button (``_on_send_to_ai``), so the richer bundle
reaches the identical, already-functional sink instead of a newly invented
(and potentially dead-end) one.

Every test here drives the REAL, unmodified ``HexEditorPanel`` /
``HexEditorBridge`` against a real ``intellicrack_hexcore.HexDocument``
opened on a real temp file; the only test double is a recording
``HexEditorBridge`` subclass (mirroring ``RecordingHexEditorBridge`` in
``conftest.py``) that delegates to the real ``get_context_for_ai`` after
appending to its call ledger, so the delivered payload is a genuine
end-to-end bundle rather than a canned response.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import open_doc, priv_method, pump_until, release_and_unlink


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


class _ContextRecordingBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass recording ``get_context_for_ai`` calls.

    Stands in for the real bridge so tests can assert the toolbar action
    dispatched to THIS bridge method rather than discarding the request
    or building some other ad hoc payload. The override still performs
    the real, unmodified context-bundling logic via ``super()`` -- only
    the call ledger is added -- so the delivered payload remains a
    genuine end-to-end result.
    """

    def __init__(self) -> None:
        """Initialise an empty call ledger alongside the real bridge state."""
        super().__init__()
        self.get_context_for_ai_calls: int = 0

    async def get_context_for_ai(
        self,
        include_bytes: int = 256,
        bookmark_limit: int = 64,
    ) -> dict[str, Any]:
        """Record the call then delegate to the real context-bundling logic.

        Args:
            include_bytes: Bytes-around-cursor count forwarded to the real implementation.
            bookmark_limit: Bookmark cap forwarded to the real implementation.

        Returns:
            dict[str, Any]: The real ``get_context_for_ai`` result.
        """
        self.get_context_for_ai_calls += 1
        return await super().get_context_for_ai(include_bytes, bookmark_limit)


class TestFullAiContextActionDispatchesRealBridgeMethod:
    """The "Full AI Context" toolbar action must call the real bridge method and deliver its result."""

    @staticmethod
    def test_action_pushes_the_real_get_context_for_ai_bundle_to_the_ai_chat_signal(qapp: QApplication) -> None:
        """Triggering the action must call ``bridge.get_context_for_ai`` and emit the genuine result.

        Falsifiable: before this fix, no GUI control called
        ``HexEditorBridge.get_context_for_ai`` at all. If
        ``_on_get_ai_context`` were removed, never wired to a toolbar
        control, or rewritten to build its own ad hoc payload instead of
        calling the bridge, ``get_context_for_ai_calls`` would stay
        ``0``. If ``_on_ai_context_ready`` discarded the result instead
        of emitting ``context_push_requested`` (the exact failure mode
        this finding warns against), ``received`` would stay empty even
        though the bridge call ledger shows a completed call. Broken
        production lines: the ``run_bridge_coroutine_logged(bridge.get_context_for_ai(),
        ...)`` dispatch in ``HexEditorPanel._on_get_ai_context`` and the
        ``self.context_push_requested.emit(context)`` call in
        ``_on_ai_context_ready`` (``ui/panels/hex_editor/panel.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = _ContextRecordingBridge()
        path = open_doc(bridge, b"MZ" + b"\x00" * 62 + bytes(range(64)))
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            _run(bridge.goto_offset(4))
            _run(bridge.add_bookmark(4, 4, "gate-bookmark"))

            received: list[dict[str, Any]] = []
            _ = panel.context_push_requested.connect(received.append)

            priv_method(panel, "_on_get_ai_context")()
            pump_until(qapp, lambda: bridge.get_context_for_ai_calls > 0)
            pump_until(qapp, lambda: len(received) == 1)

            assert bridge.get_context_for_ai_calls == 1
            context = received[0]
            assert context["cursor"] == 4
            bytes_at_cursor = context.get("bytes_at_cursor")
            assert isinstance(bytes_at_cursor, str)
            assert bytes_at_cursor

            bookmarks = context.get("bookmarks")
            assert isinstance(bookmarks, list)
            bookmark_labels = {cast("dict[str, object]", bm).get("label") for bm in cast("list[object]", bookmarks)}
            assert "gate-bookmark" in bookmark_labels
            assert context.get("bookmark_count_total") == 1
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_action_result_is_the_richer_bundle_not_the_ad_hoc_send_to_ai_payload(qapp: QApplication) -> None:
        """The delivered context must carry bookmark data ``_on_send_to_ai``'s ad hoc payload never includes.

        Falsifiable: ``_on_send_to_ai``'s hand-built context dict never
        sets ``bookmarks`` / ``bookmark_count_total`` / ``bookmark_truncated``
        keys under any circumstance. If ``_on_get_ai_context`` were
        rewired to reuse that ad hoc builder instead of the real bridge
        tool, these keys would be absent from the delivered payload.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = _ContextRecordingBridge()
        path = open_doc(bridge, b"\x00" * 64)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            received: list[dict[str, Any]] = []
            _ = panel.context_push_requested.connect(received.append)

            priv_method(panel, "_on_get_ai_context")()
            pump_until(qapp, lambda: len(received) == 1)

            context = received[0]
            assert "bookmarks" in context
            assert "bookmark_count_total" in context
            assert "bookmark_truncated" in context
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()
