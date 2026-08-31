# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 regression gates for the hex-editor pattern auto-detect reroute (row #57).

Covers ``audit/bridge-completeness/agent-09-hex-editor.md`` row #57:
``SectionsMixin._try_pattern_registry_match`` (``ui/panels/hex_editor/sections.py``)
previously instantiated its own GUI-local ``PatternRegistry`` and called
``registry.match_file(DataReaderCls.from_document(self.document))`` directly,
bypassing ``HexEditorBridge.auto_detect_pattern`` entirely -- so an AI/
orchestration caller asking the bridge to auto-detect a pattern exercised a
wholly untested-against-the-GUI code path. The remediation routes the
auto-detect-on-open feature through
``run_bridge_coroutine_logged(bridge.auto_detect_pattern())``.

Every test drives the real ``HexEditorBridge.auto_detect_pattern`` (real
``PatternRegistry.match_file`` magic-byte matching, real
``intellicrack_hexcore.HexDocument``). A real, minimal ``.hexpat`` file
(written to a temp directory, in the dialect the registry's own pragma
parser accepts: ``#pragma magic [ 0xOFFSET, "HEXBYTES" ]``) is injected as
the bridge's pattern registry so the match is genuine and deterministic,
rather than depending on whichever vendored community patterns happen to
match arbitrary binary content.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import QLabel

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.hexpat.pattern_registry import PatternRegistry
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import open_doc, priv, priv_method, priv_set, pump_until, release_and_unlink


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication


_GATE_MAGIC = bytes.fromhex("deadbeef")
_GATE_PATTERN_SOURCE = '#pragma magic [ 0x0, "DEADBEEF" ]\n#pragma description "gate test pattern"\nstruct Root { u8 data[4]; };\n'


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _make_gate_registry() -> PatternRegistry:
    """Build a real ``PatternRegistry`` over a temp directory holding one real ``.hexpat`` file.

    Returns:
        PatternRegistry: A freshly scanned registry whose single pattern
        matches ``_GATE_MAGIC`` at offset 0.
    """
    pattern_dir = Path(tempfile.mkdtemp())
    (pattern_dir / "gate_test.hexpat").write_text(_GATE_PATTERN_SOURCE, encoding="utf-8")
    registry = PatternRegistry([pattern_dir])
    registry.scan()
    return registry


class TestAutoDetectPatternBridgeL1:
    """L1: ``HexEditorBridge.auto_detect_pattern`` performs a real magic-byte match."""

    @staticmethod
    def test_matching_document_returns_the_real_pattern_metadata() -> None:
        """A document whose first bytes equal the pattern's magic must match by name.

        Independent oracle: the pattern name and description are literal
        strings this test itself wrote into the ``.hexpat`` source file --
        never a value re-derived from the production matching logic.
        """
        bridge = HexEditorBridge()
        priv_set(bridge, "_pattern_registry", _make_gate_registry())
        path = open_doc(bridge, _GATE_MAGIC + b"\x00" * 12)
        try:
            matches = _run(bridge.auto_detect_pattern())
            assert len(matches) == 1
            assert matches[0]["name"] == "gate_test"
            assert matches[0]["description"] == "gate test pattern"
        finally:
            release_and_unlink(bridge, path)

    @staticmethod
    def test_non_matching_document_returns_empty_list() -> None:
        """A document without the magic bytes must not match.

        Falsifiable: if the offset/byte comparison in
        ``PatternRegistry.match_file`` were broken (e.g. comparing against
        the wrong slice), this negative-control document could spuriously
        match.
        """
        bridge = HexEditorBridge()
        priv_set(bridge, "_pattern_registry", _make_gate_registry())
        path = open_doc(bridge, b"\x11\x22\x33\x44" + b"\x00" * 12)
        try:
            matches = _run(bridge.auto_detect_pattern())
            assert matches == []
        finally:
            release_and_unlink(bridge, path)


class TestPatternAutoDetectGuiRoutesThroughBridge:
    """L3: ``SectionsMixin._try_pattern_registry_match`` dispatches the real bridge method."""

    @staticmethod
    def test_matching_open_populates_status_label_from_real_bridge_result(qapp: QApplication) -> None:
        """Triggering auto-detect on a matching document must render the bridge's real match name.

        Falsifiable: if ``_try_pattern_registry_match`` were reverted to
        instantiate its own local ``PatternRegistry``/``DataReader`` pair
        (the pre-remediation behaviour) instead of calling
        ``bridge.auto_detect_pattern()``, the panel's own
        ``bridge._pattern_registry`` (set directly by this test to the gate
        registry) would never be consulted, and the status label would
        never show "gate_test". Broken production line:
        ``run_bridge_coroutine_logged(bridge.auto_detect_pattern(), ...)``
        in ``SectionsMixin._try_pattern_registry_match``
        (``ui/panels/hex_editor/sections.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        priv_set(bridge, "_pattern_registry", _make_gate_registry())
        path = open_doc(bridge, _GATE_MAGIC + b"\x00" * 12)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv_method(panel, "_try_pattern_registry_match")()
            pump_until(qapp, lambda: "gate_test" in priv(panel, "_pattern_status_label", QLabel).text())

            assert priv(panel, "_pattern_status_label", QLabel).text() == "Detected patterns: gate_test"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_result_matches_direct_bridge_call_exactly(qapp: QApplication) -> None:
        """The GUI path and a direct ``bridge.auto_detect_pattern()`` call must agree exactly.

        Proves the GUI is genuinely dispatching to the SAME bridge/registry
        state rather than any independent matcher: this test opens the
        document on a shared bridge, calls the bridge directly first to
        capture the oracle result, then drives the GUI's own
        ``_try_pattern_registry_match`` against the identical bridge/
        document/registry and confirms the label reflects that same result.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        priv_set(bridge, "_pattern_registry", _make_gate_registry())
        path = open_doc(bridge, _GATE_MAGIC + b"\x00" * 12)
        try:
            direct_result = _run(bridge.auto_detect_pattern())
            expected_names = ", ".join(m["name"] for m in direct_result[:3])

            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv_method(panel, "_try_pattern_registry_match")()
            pump_until(qapp, lambda: expected_names in priv(panel, "_pattern_status_label", QLabel).text())

            assert priv(panel, "_pattern_status_label", QLabel).text() == f"Detected patterns: {expected_names}"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_no_bridge_attached_does_not_raise_and_leaves_label_unset(qapp: QApplication) -> None:
        """With no bridge attached, the method must return quietly without touching the label.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, _GATE_MAGIC + b"\x00" * 12)
        try:
            panel.document = bridge.document
            assert priv(panel, "_bridge", (HexEditorBridge, type(None))) is None

            priv_method(panel, "_try_pattern_registry_match")()

            assert not priv(panel, "_pattern_status_label", QLabel).text()
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_non_matching_document_leaves_label_empty(qapp: QApplication) -> None:
        """A real bridge call that returns no matches must not overwrite the label with a match string.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        priv_set(bridge, "_pattern_registry", _make_gate_registry())
        path = open_doc(bridge, b"\xff\xff\xff\xff" + b"\x00" * 12)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv_method(panel, "_try_pattern_registry_match")()
            # Pump briefly so the background worker has a chance to run; the
            # label must remain the empty default since no match exists.
            pump_until(qapp, lambda: False, timeout_s=1.0)

            assert not priv(panel, "_pattern_status_label", QLabel).text()
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()
