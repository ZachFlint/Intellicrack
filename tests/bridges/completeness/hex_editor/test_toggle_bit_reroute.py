# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gate for the hex-editor bit-editor toggle-bit reroute.

Covers the data-inspector tab's bit-editor buttons
(``ui/panels/hex_editor/data_inspector.py``
``DataInspectorMixin._on_bit_toggled`` /
``_toggle_bit_via_bridge``), which now dispatch a bit flip to the
bridge's atomic ``HexEditorBridge.toggle_bit`` when a bridge is
attached AND the document's current bit differs from the button's new
state (the normal case, since the button starts synced to the
document). ``toggle_bit`` unconditionally flips the current bit and
cannot express "set to this exact value", so a no-op click (current bit
already equals the requested state) and the no-bridge case both fall
back to ``document.set_bit`` directly.

Every test drives the real, unmodified ``DataInspectorMixin`` wiring
through a real ``HexEditorPanel`` against a real
``intellicrack_hexcore.HexDocument``; the only test double is a
recording ``HexEditorBridge`` subclass (``RecordingHexEditorBridge`` in
``conftest.py``) that delegates to the real ``toggle_bit`` after
appending to its call ledger, so the resulting byte value reflects a
genuine end-to-end bit flip rather than a canned response.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import RecordingHexEditorBridge, open_doc, priv, priv_method, priv_set, pump_until, release_and_unlink


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


class TestToggleBitRoutesThroughBridge:
    """The bit-editor buttons must call ``HexEditorBridge.toggle_bit`` when flipping a differing bit."""

    @staticmethod
    def test_flip_with_bridge_dispatches_toggle_bit_and_writes_the_real_flip(qapp: QApplication) -> None:
        """Flipping a bit that differs from the document's current value must call ``bridge.toggle_bit``.

        Starts from ``0x00`` (all bits clear) and clicks the LSB button
        checked, so the document's current bit (0) differs from the
        requested state (1) -- the normal case ``toggle_bit`` handles.

        Falsifiable: if ``_on_bit_toggled``/``_toggle_bit_via_bridge``
        were reverted to call ``document.set_bit`` directly (the
        pre-remediation behaviour), ``toggle_bit_calls`` would stay
        empty even though a bridge was attached and the bit genuinely
        changed. Broken production line:
        ``run_bridge_coroutine(bridge.toggle_bit(offset, bit_index))``
        in ``DataInspectorMixin._toggle_bit_via_bridge``
        (``ui/panels/hex_editor/data_inspector.py:265``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, b"\x00")
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv_set(panel, "_bit_editor_offset", 0)

            priv_method(panel, "_on_bit_toggled")(0, checked=True)
            pump_until(qapp, lambda: bool(bridge.toggle_bit_calls))

            assert bridge.toggle_bit_calls == [{"offset": 0, "bit_index": 0}]
            assert bridge.document is not None
            assert bool(bridge.document.get_bit(0, 0))
            assert bridge.document.read(0, 1) == b"\x01"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_noop_flip_with_bridge_falls_back_to_set_bit_and_never_calls_toggle_bit(qapp: QApplication) -> None:
        """Clicking a bit button to its already-current state must never call ``bridge.toggle_bit``.

        ``toggle_bit`` unconditionally flips, so it cannot express a
        no-op write; ``_toggle_bit_via_bridge`` must detect the
        current-bit-equals-requested case and fall back to
        ``document.set_bit`` instead. Starts from ``0x01`` (bit 0 set)
        and clicks bit 0 checked again (already ``True``).

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = RecordingHexEditorBridge()
        path = open_doc(bridge, b"\x01")
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv_set(panel, "_bit_editor_offset", 0)

            priv_method(panel, "_on_bit_toggled")(0, checked=True)

            assert bridge.toggle_bit_calls == []
            assert bridge.document is not None
            assert bridge.document.read(0, 1) == b"\x01"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_flip_without_bridge_uses_set_bit_and_never_calls_bridge(qapp: QApplication) -> None:
        """With no bridge attached, flipping a bit must use ``document.set_bit`` and never touch the bridge.

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
        local_bridge = RecordingHexEditorBridge()
        path = open_doc(local_bridge, b"\x00")
        try:
            assert priv(panel, "_bridge", (RecordingHexEditorBridge, type(None))) is None
            panel.document = local_bridge.document
            priv_set(panel, "_bit_editor_offset", 0)

            priv_method(panel, "_on_bit_toggled")(0, checked=True)

            assert unattached_bridge.toggle_bit_calls == []
            assert local_bridge.toggle_bit_calls == []
            assert local_bridge.document is not None
            assert local_bridge.document.read(0, 1) == b"\x01"
        finally:
            release_and_unlink(local_bridge, path)
            panel.deleteLater()
