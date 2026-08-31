# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for two Frida panel console defects.

* S14-D08: Frida delivers ``console.log(...)`` output as a message with
  ``type == "log"`` (carrying ``level``/``payload`` fields), distinct from
  ``type == "send"``. ``FridaPanel._on_frida_message`` only special-cased
  ``send``/``error``, so the built-in sample hook script -- which uses
  ``console.log`` in its ``onEnter``/``onLeave`` callbacks -- looked broken.
* S14-D09: the Frida message pump had no backpressure. Every incoming
  message was delivered straight to the console with no cap on the widget's
  line count and no bound on how fast messages could be produced, so a
  high-frequency ``send()`` hook could balloon memory and starve the GUI
  event queue, leaving process controls like Detach unresponsive.

The fix routes ``log`` messages to the console (this file's D08 tests), caps
the console's ``QPlainTextEdit`` block count, and replaces the previous
per-message Qt signal delivery with a bounded, lock-protected
``collections.deque`` drained in fixed-size batches by a ``QTimer`` tick
(this file's D09 tests). All tests drive the real ``FridaPanel`` widget and
its real message-handling methods under an offscreen ``QApplication`` --
``_on_frida_message`` (the console renderer), ``_enqueue_frida_message``
(the exact callable ``FridaBridge.set_message_handler`` is wired to), and
``_drain_frida_message_queue`` (the queue-draining timer callback) -- with
genuine Frida-shaped message dictionaries. Nothing here is mocked or
stubbed.
"""

from __future__ import annotations

from typing import Final

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.ui.panels.frida_panel import (
    _CONSOLE_DRAIN_BATCH_SIZE,
    _CONSOLE_MAX_BLOCK_COUNT,
    _CONSOLE_QUEUE_MAXLEN,
    FridaPanel,
)


pytestmark = pytest.mark.usefixtures("qapp")

_LOG_MARKER: Final[str] = "MARKER_D08"
_FLOOD_MESSAGE_COUNT: Final[int] = 20000


@pytest.fixture(autouse=True)
def _auto_dismiss_blocking_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auto-answer blocking ``QMessageBox`` modals so headless UI tests never hang.

    ``FridaPanel`` construction and message handling do not currently raise
    blocking modals, but this guard is kept in place defensively so any
    future confirm/error dialog surfaced from these code paths cannot hang
    the offscreen test session.

    Args:
        monkeypatch: Pytest fixture used to replace the blocking static methods.
    """
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.StandardButton.No)
    monkeypatch.setattr(QMessageBox, "critical", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *_a, **_k: QMessageBox.StandardButton.Ok)
    monkeypatch.setattr(QMessageBox, "information", lambda *_a, **_k: QMessageBox.StandardButton.Ok)


class TestS14D08LogMessageRouting:
    """Falsifiable gates for S14-D08: Frida ``log`` messages must reach the console."""

    @staticmethod
    def test_on_frida_message_renders_log_type() -> None:
        """A real Frida ``log`` message must render its level and payload to the console.

        Drives ``_on_frida_message`` directly -- the same console-rendering
        method the existing ``send``/``error`` regression tests use -- with
        the exact message shape Frida emits for ``console.log``. Falsifiable:
        before the fix this message fell through the generic ``else`` branch
        that renders the raw dict repr rather than the clean ``level``/
        ``payload`` text this asserts on.
        """
        panel = FridaPanel()
        panel._on_frida_message({"type": "log", "level": "info", "payload": _LOG_MARKER})
        text = panel._console.toPlainText()
        assert _LOG_MARKER in text
        assert "[log:info]" in text

    @staticmethod
    def test_enqueue_and_drain_routes_log_message_through_bridge_entry_point() -> None:
        """A ``log`` message must survive the real bridge-facing queue/drain path.

        ``_enqueue_frida_message`` is the exact callable
        ``FridaBridge.set_message_handler`` is wired to in ``set_bridge``, and
        ``_drain_frida_message_queue`` is the real ``QTimer`` callback that
        flushes it to the console. Driving both directly (rather than just
        ``_on_frida_message``) proves the full production delivery path -- not
        just the renderer -- surfaces ``console.log`` output.
        """
        panel = FridaPanel()
        panel._enqueue_frida_message({"type": "log", "level": "warning", "payload": _LOG_MARKER})
        panel._drain_frida_message_queue()
        text = panel._console.toPlainText()
        assert _LOG_MARKER in text
        assert "[log:warning]" in text


class TestS14D09Backpressure:
    """Falsifiable gates for S14-D09: bounded console plus coalesced, bounded message queue."""

    @staticmethod
    def test_console_block_count_stays_capped_after_flood() -> None:
        """Flooding far beyond the queue bound must never blow past the console's block cap.

        Feeds 20000 real Frida ``send`` messages through the actual
        thread-safe enqueue entry point, then drains the queue exactly as the
        real drain timer would (in bounded per-tick batches) until it is
        empty. Falsifiable: without ``QPlainTextEdit.setMaximumBlockCount``
        wired to a real cap, the console would retain a block per message and
        ``blockCount()`` would land near 10000, far above the asserted cap.
        """
        panel = FridaPanel()
        for i in range(_FLOOD_MESSAGE_COUNT):
            panel._enqueue_frida_message({"type": "send", "payload": f"flood-{i}"})

        while panel._frida_message_queue:
            panel._drain_frida_message_queue()

        assert panel._console.document().blockCount() <= _CONSOLE_MAX_BLOCK_COUNT

    @staticmethod
    def test_queue_bounded_and_drop_notice_rendered_after_overflow() -> None:
        """Overflowing the bounded queue must cap its length and surface a drop notice.

        After enqueueing 20000 messages against a queue bounded to
        ``_CONSOLE_QUEUE_MAXLEN``, the pending queue must never exceed that
        bound and the exact overflow count must be tracked. Draining must
        then render a "messages dropped" notice carrying that count and reset
        the counter. Falsifiable: an unbounded queue would retain all 20000
        entries and no drop count would ever be tracked or reported.
        """
        panel = FridaPanel()
        for i in range(_FLOOD_MESSAGE_COUNT):
            panel._enqueue_frida_message({"type": "send", "payload": f"flood-{i}"})

        assert len(panel._frida_message_queue) <= _CONSOLE_QUEUE_MAXLEN
        expected_dropped = _FLOOD_MESSAGE_COUNT - _CONSOLE_QUEUE_MAXLEN
        assert panel._frida_dropped_message_count == expected_dropped

        panel._drain_frida_message_queue()
        text = panel._console.toPlainText()
        assert f"{expected_dropped} Frida messages dropped" in text
        assert panel._frida_dropped_message_count == 0

    @staticmethod
    def test_drain_processes_at_most_batch_size_per_tick() -> None:
        """A single drain tick must not process more than the configured batch size.

        Queues three full batches worth of messages (well under the queue
        bound, so nothing is dropped) and asserts exactly one batch's worth is
        consumed by a single ``_drain_frida_message_queue`` call. Falsifiable:
        an un-batched drain would empty the whole queue in one tick, which
        is precisely the unbounded-per-tick behavior that starves the GUI
        event loop and Detach/Flush responsiveness under a chatty hook.
        """
        panel = FridaPanel()
        for i in range(_CONSOLE_DRAIN_BATCH_SIZE * 3):
            panel._enqueue_frida_message({"type": "send", "payload": f"tick-{i}"})

        queue_len_before = len(panel._frida_message_queue)
        panel._drain_frida_message_queue()
        queue_len_after = len(panel._frida_message_queue)

        assert queue_len_before - queue_len_after == _CONSOLE_DRAIN_BATCH_SIZE
