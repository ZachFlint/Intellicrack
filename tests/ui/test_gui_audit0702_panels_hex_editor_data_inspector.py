# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for GUI audit findings M4 and M5 in ``data_inspector``.

* ``TestM4BitToggleAsyncDispatch`` (M4): clicking a bit-editor toggle
  button must dispatch ``HexEditorBridge.toggle_bit`` through the
  non-blocking ``run_bridge_coroutine_logged`` machinery instead of the
  blocking ``run_bridge_coroutine`` call, so the Qt GUI thread stays
  responsive while the bridge round trip completes on the background
  event-loop thread.
* ``TestM5EncodeTextAsyncDispatch`` (M5): clicking "Encode" must
  dispatch ``HexEditorBridge.encode_text`` the same non-blocking way
  instead of blocking the GUI thread for the codec round trip.

Both gates drive the real, unmodified ``DataInspectorMixin`` handlers
against a real ``intellicrack_hexcore.HexDocument`` and a real
``HexEditorBridge`` subclass whose ``toggle_bit``/``encode_text``
overrides insert an artificial ``asyncio.sleep`` delay before
delegating to the genuine implementation via ``super()``. The delay
makes the blocking-vs-non-blocking distinction observable from the
calling (GUI) thread: a blocking dispatch makes the handler call itself
take as long as the delay, while a non-blocking dispatch returns near-
instantly and the handler's side effects only land once the background
worker's completion signal is pumped through the Qt event loop.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.data_inspector import DataInspectorMixin


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real hex documents",
)


pytestmark = pytest.mark.integration


_BRIDGE_DELAY_S: float = 0.6
"""Artificial delay inserted into the bridge round trip.

Large enough that a blocking dispatch is trivially distinguishable from
GUI-thread scheduling jitter, small enough to keep the test suite fast.
"""

_NON_BLOCKING_CEILING_S: float = 0.3
"""Wall-clock ceiling for a non-blocking dispatch to return.

Well under ``_BRIDGE_DELAY_S`` (a 2x margin) so a blocking dispatch,
which must wait out the full delay before the calling frame returns,
fails this bound decisively even under loaded-CI scheduling jitter.
"""


class _Harness(QWidget, DataInspectorMixin):
    """Minimal real ``QWidget`` host exercising ``DataInspectorMixin`` handlers.

    Populates every attribute the mixin's bit-editor and encode/decode
    handlers read, using real Qt widgets throughout (no stand-ins for
    the widgets under test), so ``_on_bit_toggled`` and
    ``_on_encode_text`` run exactly as they do inside the real hex
    editor panel.
    """

    def __init__(self) -> None:
        """Build the widget tree and reset mixin state to its unattached defaults."""
        super().__init__()
        self._data_inspector_tree = None
        self._document = None
        self.document = None
        self.state_holder = None
        self._bridge = None
        self._hex_widget = None
        self._decode_output = None
        self._decode_combo = None
        self._decode_length_spin = None
        self._encode_input = QLineEdit(self)
        self._encode_output = QLabel(self)
        self._encode_combo = QComboBox(self)
        self._bit_editor_box = self._create_bit_editor_group()


class _DelayedHexEditorBridge(HexEditorBridge):
    """``HexEditorBridge`` subclass adding an artificial round-trip delay.

    ``toggle_bit`` and ``encode_text`` each record the OS thread they
    ran on before sleeping ``delay_s`` and delegating to the real
    implementation via ``super()``, so the resulting document/encoding
    state is genuine end-to-end output rather than a canned response.

    Attributes:
        toggle_bit_thread_ids: OS thread identifier recorded on each
            ``toggle_bit`` invocation.
        encode_text_thread_ids: OS thread identifier recorded on each
            ``encode_text`` invocation.
    """

    toggle_bit_thread_ids: list[int]
    encode_text_thread_ids: list[int]

    def __init__(self, *, delay_s: float) -> None:
        """Initialize the bridge with a fixed artificial delay.

        Args:
            delay_s: Seconds each overridden coroutine sleeps before
                delegating to the real implementation.
        """
        super().__init__()
        self._delay_s = delay_s
        self.toggle_bit_thread_ids = []
        self.encode_text_thread_ids = []

    async def toggle_bit(self, offset: int, bit_index: int) -> bool:
        """Record the calling thread, sleep, then perform the real bit flip.

        Args:
            offset: Byte offset forwarded to the real implementation.
            bit_index: Bit position forwarded to the real implementation.

        Returns:
            bool: The real ``toggle_bit`` result.
        """
        self.toggle_bit_thread_ids.append(threading.get_ident())
        await asyncio.sleep(self._delay_s)
        return await super().toggle_bit(offset, bit_index)

    async def encode_text(self, text: str, encoding: str = "utf-8") -> str:
        """Record the calling thread, sleep, then perform the real encode.

        Args:
            text: Text forwarded to the real implementation.
            encoding: Codec name forwarded to the real implementation.

        Returns:
            str: The real ``encode_text`` result.
        """
        self.encode_text_thread_ids.append(threading.get_ident())
        await asyncio.sleep(self._delay_s)
        return await super().encode_text(text, encoding)


class TestM4BitToggleAsyncDispatch:
    """M4: bit-editor toggle clicks must not block the GUI thread on the bridge round trip."""

    @staticmethod
    def test_m4_bit_toggle_returns_promptly_and_syncs_after_bridge_completes(qtbot: QtBot) -> None:
        """A bit-toggle click returns near-instantly and only mutates state once the bridge finishes.

        Pre-fix, ``_toggle_bit_via_bridge`` called the blocking
        ``run_bridge_coroutine(bridge.toggle_bit(offset, bit_index))``
        directly on the Qt main thread, so ``_on_bit_toggled`` would not
        return until the full ``_BRIDGE_DELAY_S`` round trip finished on
        the calling thread and the state mutations would already be
        visible the instant the handler call returned. Post-fix,
        ``run_bridge_coroutine_logged`` dispatches to a background
        ``QThread`` worker, so the handler returns immediately, the
        button/document stay at their pre-click state until the
        background thread signals completion, and the write itself runs
        off the GUI thread.

        Args:
            qtbot: pytest-qt bot fixture used to pump the event loop
                while waiting for the cross-thread signal delivery.
        """
        main_thread_id = threading.get_ident()
        document = hexcore.HexDocument.open_bytes(b"\x00")
        bridge = _DelayedHexEditorBridge(delay_s=_BRIDGE_DELAY_S)
        bridge.document = document
        widget = _Harness()
        try:
            widget.document = document
            widget._bridge = bridge
            widget._update_bit_buttons(0)
            assert widget._bit_buttons[7].isChecked() is False, "setup: bit 0 must start clear"

            started = time.monotonic()
            widget._on_bit_toggled(0, checked=True)
            elapsed = time.monotonic() - started

            assert elapsed < _NON_BLOCKING_CEILING_S, (
                f"_on_bit_toggled blocked the calling thread for {elapsed:.3f}s "
                "waiting on the bridge round trip instead of dispatching asynchronously"
            )
            assert widget._bit_buttons[7].isChecked() is False, (
                "bit button was already updated before the bridge worker could have completed; "
                "the write did not go through the async dispatcher"
            )
            assert bool(document.get_bit(0, 0)) is False, "document bit was already flipped before the bridge worker could have completed"

            qtbot.waitUntil(lambda: bool(document.get_bit(0, 0)) is True, timeout=3000)

            assert len(bridge.toggle_bit_thread_ids) == 1
            assert bridge.toggle_bit_thread_ids[0] != main_thread_id, "toggle_bit ran on the GUI thread, not a background worker"
            assert document.read(0, 1) == b"\x01"
            qtbot.waitUntil(lambda: widget._bit_buttons[7].isChecked() is True, timeout=3000)
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m4_bit_toggle_bridge_failure_falls_back_without_blocking(qtbot: QtBot) -> None:
        """A failing bridge dispatch still returns promptly and falls back to a direct document write.

        Exercises the ``on_error`` branch added by the M4 fix: when the
        background bridge call raises, ``_write_bit_directly`` performs
        the write locally so the click still takes effect, and the
        handler call itself never blocks waiting for that failure to
        surface.

        Args:
            qtbot: pytest-qt bot fixture used to pump the event loop
                while waiting for the cross-thread error signal.
        """
        document = hexcore.HexDocument.open_bytes(b"\x00")

        class _FailingBridge(_DelayedHexEditorBridge):
            """Bridge whose ``toggle_bit`` raises after the artificial delay."""

            async def toggle_bit(self, offset: int, bit_index: int) -> bool:
                """Record the call, sleep, then raise instead of flipping the bit.

                Args:
                    offset: Byte offset (unused; the call always fails).
                    bit_index: Bit position (unused; the call always fails).

                Returns:
                    bool: Never returns; always raises.

                Raises:
                    RuntimeError: Always, to exercise the failure fallback.
                """
                self.toggle_bit_thread_ids.append(threading.get_ident())
                await asyncio.sleep(self._delay_s)
                del offset, bit_index
                msg = "simulated bridge failure"
                raise RuntimeError(msg)

        bridge = _FailingBridge(delay_s=_BRIDGE_DELAY_S)
        bridge.document = document
        widget = _Harness()
        try:
            widget.document = document
            widget._bridge = bridge
            widget._update_bit_buttons(0)

            started = time.monotonic()
            widget._on_bit_toggled(0, checked=True)
            elapsed = time.monotonic() - started

            assert elapsed < _NON_BLOCKING_CEILING_S, f"_on_bit_toggled blocked for {elapsed:.3f}s even on the failure path"
            assert bool(document.get_bit(0, 0)) is False, "document was mutated before the bridge failure could be observed"

            qtbot.waitUntil(lambda: bool(document.get_bit(0, 0)) is True, timeout=3000)
            assert document.read(0, 1) == b"\x01", "failure fallback did not perform the direct document write"
            qtbot.waitUntil(lambda: widget._bit_buttons[7].isChecked() is True, timeout=3000)
        finally:
            widget.deleteLater()


class TestM5EncodeTextAsyncDispatch:
    """M5: the Encode button must not block the GUI thread on the bridge round trip."""

    @staticmethod
    def test_m5_encode_text_returns_promptly_and_updates_after_bridge_completes(qtbot: QtBot) -> None:
        """Clicking Encode returns near-instantly and only fills the output once the bridge finishes.

        Pre-fix, ``_on_encode_text`` called the blocking
        ``run_bridge_coroutine(bridge.encode_text(text, encoding))``
        directly on the Qt main thread, so the handler would not return
        until the full ``_BRIDGE_DELAY_S`` round trip finished and the
        output label would already hold the encoded hex the instant the
        handler call returned. Post-fix, ``run_bridge_coroutine_logged``
        dispatches to a background ``QThread`` worker, so the handler
        returns immediately, the output label stays empty until the
        background thread signals completion, and ``encode_text`` itself
        runs off the GUI thread.

        Args:
            qtbot: pytest-qt bot fixture used to pump the event loop
                while waiting for the cross-thread signal delivery.
        """
        main_thread_id = threading.get_ident()
        document = hexcore.HexDocument.open_bytes(b"\x00" * 8)
        bridge = _DelayedHexEditorBridge(delay_s=_BRIDGE_DELAY_S)
        bridge.document = document
        widget = _Harness()
        try:
            widget.document = document
            widget._bridge = bridge
            widget._encode_combo.addItem("UTF-8", userData="utf-8")
            widget._encode_input.setText("HELLO")

            started = time.monotonic()
            widget._on_encode_text()
            elapsed = time.monotonic() - started

            assert elapsed < _NON_BLOCKING_CEILING_S, (
                f"_on_encode_text blocked the calling thread for {elapsed:.3f}s "
                "waiting on the bridge round trip instead of dispatching asynchronously"
            )
            assert not widget._encode_output.text(), (
                "encode output was already populated before the bridge worker could have completed; "
                "the encode call did not go through the async dispatcher"
            )

            qtbot.waitUntil(lambda: bool(widget._encode_output.text()), timeout=3000)

            assert len(bridge.encode_text_thread_ids) == 1
            assert bridge.encode_text_thread_ids[0] != main_thread_id, "encode_text ran on the GUI thread, not a background worker"
            assert widget._encode_output.text() == "48 45 4C 4C 4F"
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m5_encode_text_bridge_failure_reports_error_without_blocking(qtbot: QtBot) -> None:
        """A failing encode dispatch still returns promptly and surfaces the error asynchronously.

        Exercises the ``on_error`` branch added by the M5 fix: the
        output label is set to an error message once the background
        worker's failure signal is delivered, and the handler call
        itself never blocks waiting for that failure to surface.

        Args:
            qtbot: pytest-qt bot fixture used to pump the event loop
                while waiting for the cross-thread error signal.
        """
        document = hexcore.HexDocument.open_bytes(b"\x00" * 8)

        class _FailingBridge(_DelayedHexEditorBridge):
            """Bridge whose ``encode_text`` raises after the artificial delay."""

            async def encode_text(self, text: str, encoding: str = "utf-8") -> str:
                """Record the call, sleep, then raise instead of encoding.

                Args:
                    text: Text to encode (unused; the call always fails).
                    encoding: Codec name (unused; the call always fails).

                Returns:
                    str: Never returns; always raises.

                Raises:
                    RuntimeError: Always, to exercise the failure fallback.
                """
                self.encode_text_thread_ids.append(threading.get_ident())
                await asyncio.sleep(self._delay_s)
                del text, encoding
                msg = "simulated codec failure"
                raise RuntimeError(msg)

        bridge = _FailingBridge(delay_s=_BRIDGE_DELAY_S)
        bridge.document = document
        widget = _Harness()
        try:
            widget.document = document
            widget._bridge = bridge
            widget._encode_combo.addItem("UTF-8", userData="utf-8")
            widget._encode_input.setText("HELLO")

            started = time.monotonic()
            widget._on_encode_text()
            elapsed = time.monotonic() - started

            assert elapsed < _NON_BLOCKING_CEILING_S, f"_on_encode_text blocked for {elapsed:.3f}s even on the failure path"
            assert not widget._encode_output.text(), "output was populated before the bridge failure could be observed"

            qtbot.waitUntil(lambda: bool(widget._encode_output.text()), timeout=3000)
            assert widget._encode_output.text() == "Error: simulated codec failure"
        finally:
            widget.deleteLater()
