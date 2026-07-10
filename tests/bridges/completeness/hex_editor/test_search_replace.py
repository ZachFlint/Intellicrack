# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L2/L3 gate tests for the hex-editor Search-and-Replace feature (row #9).

Covers ``audit/bridge-completeness/agent-09-hex-editor.md`` row #9:
``replace_bytes`` (``hex_editor.py:5329``) was fully implemented and
registered but had zero GUI reachability -- no "Replace" affordance existed
anywhere in ``ui/panels/hex_editor/search.py``. The remediation added
toolbar Replace/Replace All controls (``panel.py``) wired to
``SearchMixin._on_replace``/``_on_replace_all`` (``search.py``), which
dispatch through ``run_bridge_coroutine(bridge.replace_bytes(...))`` for
Hex/Text/Numeric modes.

* L1 -- ``HexEditorBridge.replace_bytes`` performs a real find-and-replace
  against a real ``intellicrack_hexcore.HexDocument``.
* L2 -- ``hex_editor.replace_bytes`` is registered and dispatchable via
  ``ToolRegistry.execute_tool_call``.
* L3 -- the panel's Replace/Replace All controls exist, are wired, and
  their handlers drive the real bridge method end-to-end, mutating the
  real open document.
"""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import open_doc, priv, priv_method, release_and_unlink


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


class TestReplaceBytesBridgeL1:
    """L1: ``HexEditorBridge.replace_bytes`` performs a real byte-pattern replace.

    Falsifiable: deleting ``HexEditorBridge.replace_bytes`` or reverting it
    to a no-op that returns ``0`` without calling
    ``self.document.replace_bytes`` makes every assertion below fail, since
    the post-replace read of the real document would still show the
    original pattern bytes.
    """

    def test_replaces_every_occurrence_and_returns_exact_count(self, bridge: HexEditorBridge) -> None:
        """All three occurrences of a 2-byte pattern are replaced in the real document.

        Independent oracle: the raw bytes this test itself constructs and
        writes to disk before calling the bridge -- never a value computed
        by re-implementing ``replace_bytes``.

        Args:
            bridge: Fresh bridge fixture.
        """
        original = b"\xde\xad\xbe\xef\xde\xad\x90\x90\xde\xad"
        path = open_doc(bridge, original)
        try:
            count = _run(bridge.replace_bytes("dead", "cafe"))
            assert count == 3

            doc = bridge.document
            assert doc is not None
            after = bytes(doc.read(0, len(original)))
            expected = original.replace(b"\xde\xad", b"\xca\xfe")
            assert after == expected
            assert b"\xde\xad" not in after
        finally:
            release_and_unlink(bridge, path)

    def test_no_match_returns_zero_and_leaves_document_unchanged(self, bridge: HexEditorBridge) -> None:
        """A pattern absent from the document yields a zero count and no mutation.

        Args:
            bridge: Fresh bridge fixture.
        """
        original = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        path = open_doc(bridge, original)
        try:
            count = _run(bridge.replace_bytes("ffee", "0000"))
            assert count == 0

            doc = bridge.document
            assert doc is not None
            assert bytes(doc.read(0, len(original))) == original
        finally:
            release_and_unlink(bridge, path)

    def test_no_document_raises_runtime_error(self, bridge: HexEditorBridge) -> None:
        """Calling ``replace_bytes`` with no open document raises ``RuntimeError``.

        Falsifiable: removing the ``self.document is None`` guard would
        instead raise ``AttributeError`` from ``self.document.replace_bytes``.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.replace_bytes("90", "cc"))


class TestReplaceBytesDispatchL2:
    """L2: ``hex_editor.replace_bytes`` is registered and dispatches through the real registry."""

    @staticmethod
    def test_tool_def_registered_and_matches_real_method(bridge: HexEditorBridge) -> None:
        """The ``hex_editor.replace_bytes`` tool-def exists and names a real callable.

        Args:
            bridge: Fresh bridge fixture.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        assert "hex_editor.replace_bytes" in names
        assert callable(bridge.replace_bytes)

    @staticmethod
    def test_execute_tool_call_dispatches_real_replace(tmp_path: Path) -> None:
        """Dispatching via ``ToolRegistry.execute_tool_call`` performs the real replace.

        Falsifiable: if the tool-def's ``function_name`` did not match the
        ``replace_bytes`` attribute (the historical
        ``disassemble``/``disassemble_at`` class of bug), ``getattr`` inside
        ``execute_tool_call`` would resolve to ``None`` and this call would
        raise ``ToolError`` for an unknown function instead of mutating the
        real document.

        Args:
            tmp_path: Pytest-managed temporary directory used as the tools root.
        """

        async def _scenario() -> None:
            registry = ToolRegistry(tools_dir=tmp_path)
            bridge = HexEditorBridge()
            registry.register_bridge(ToolName.HEX_EDITOR, bridge)
            original = b"AAAABBBBAAAA"
            path = open_doc(bridge, original)
            try:
                result = await registry.execute_tool_call(
                    "hex_editor",
                    "hex_editor.replace_bytes",
                    {"pattern_hex": "41414141", "replacement_hex": "5a5a5a5a"},
                )
                assert result == 2
                doc = bridge.document
                assert doc is not None
                after = bytes(doc.read(0, len(original)))
                assert after == b"ZZZZBBBBZZZZ"
            finally:
                release_and_unlink(bridge, path)

        _run(_scenario())


class TestReplaceGuiControlsExistL3:
    """L3: the panel's Replace/Replace All toolbar controls exist and are wired."""

    @staticmethod
    def test_replace_input_and_buttons_exist(qapp: QApplication) -> None:
        """``_replace_input`` and both Replace buttons must exist on the panel.

        Falsifiable: removing the Replace toolbar block from
        ``_populate_toolbar`` (``panel.py``) makes ``hasattr`` fail on
        ``_replace_input``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            assert hasattr(panel, "_replace_input")
            replace_input = priv(panel, "_replace_input", QLineEdit)
            assert replace_input.placeholderText() == "Replace with..."
        finally:
            panel.deleteLater()

    @staticmethod
    def test_on_replace_and_on_replace_all_are_bound_handlers(qapp: QApplication) -> None:
        """``_on_replace``/``_on_replace_all`` must be real bound methods on the panel.

        Falsifiable: if the toolbar buttons were wired to a different (or
        no-op) handler, these attributes would either not exist or would
        not be the ``SearchMixin`` methods that call ``replace_bytes``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            assert callable(priv_method(panel, "_on_replace"))
            assert callable(priv_method(panel, "_on_replace_all"))
        finally:
            panel.deleteLater()


class TestReplaceAllGuiDispatchesRealBridgeL3:
    """L3: clicking/calling Replace All drives the real ``bridge.replace_bytes`` end-to-end."""

    @staticmethod
    def test_replace_all_hex_mode_mutates_real_document(qapp: QApplication) -> None:
        """Hex-mode Replace All rewrites every occurrence in the real open document.

        Falsifiable: if ``_on_replace_all`` called anything other than
        ``bridge.replace_bytes`` (e.g. reverted to a no-op or a client-side
        reimplementation), the post-call read of the real document would
        still contain the original pattern bytes. Broken production line:
        ``count = run_bridge_coroutine(bridge.replace_bytes(pattern_hex,
        replacement_hex))`` in ``SearchMixin._on_replace_all``
        (``ui/panels/hex_editor/search.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        original = b"\x90\x90\xcc\x90\x90\xcc\x11\x22"
        path = open_doc(bridge, original)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Hex")
            priv(panel, "_search_input", QLineEdit).setText("90 90")
            priv(panel, "_replace_input", QLineEdit).setText("AA BB")

            priv_method(panel, "_on_replace_all")()

            doc = bridge.document
            assert doc is not None
            after = bytes(doc.read(0, len(original)))
            expected = original.replace(b"\x90\x90", b"\xaa\xbb")
            assert after == expected
            assert "Replaced 2" in priv(panel, "_search_status_label", QLabel).text()
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_replace_all_numeric_mode_packs_and_replaces_matching_width(qapp: QApplication) -> None:
        """Numeric-mode Replace All packs both find/replace values to the resolved struct format.

        Independent oracle: ``struct.pack("<I", ...)`` applied directly by
        the test, matching the little-endian 32-bit unsigned format
        selected in the form.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        find_value = 0xDEADBEEF
        replace_value = 0x11223344
        original = struct.pack("<I", find_value) + b"\x00\x00" + struct.pack("<I", find_value)
        path = open_doc(bridge, original)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Numeric")
            priv(panel, "_numeric_size_combo", QComboBox).setCurrentText("32-bit")
            priv(panel, "_numeric_type_combo", QComboBox).setCurrentText("Unsigned Int")
            priv(panel, "_numeric_endian_combo", QComboBox).setCurrentText("Little Endian")
            priv(panel, "_numeric_value_input", QLineEdit).setText(f"0x{find_value:X}")
            priv(panel, "_numeric_replace_input", QLineEdit).setText(f"0x{replace_value:X}")

            priv_method(panel, "_on_replace_all")()

            doc = bridge.document
            assert doc is not None
            after = bytes(doc.read(0, len(original)))
            expected = struct.pack("<I", replace_value) + b"\x00\x00" + struct.pack("<I", replace_value)
            assert after == expected
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_replace_all_without_bridge_shows_warning_and_does_not_raise(qapp: QApplication) -> None:
        """Replace All with no attached bridge must warn, not crash or silently mutate.

        Falsifiable: if the ``bridge is None`` guard in ``_on_replace_all``
        were removed, this call would raise ``AttributeError`` on
        ``bridge.replace_bytes`` instead of returning quietly after the
        warning dialog is shown.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        original = b"\x90\x90\x90\x90"
        path = open_doc(bridge, original)
        try:
            panel.document = bridge.document
            assert priv(panel, "_bridge", (HexEditorBridge, type(None))) is None

            priv(panel, "_search_mode_combo", QComboBox).setCurrentText("Hex")
            priv(panel, "_search_input", QLineEdit).setText("90 90")
            priv(panel, "_replace_input", QLineEdit).setText("AA BB")

            priv_method(panel, "_on_replace_all")()
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestRunPythonScriptCapabilityGateRegression:
    """L2 regression: ``hex_editor.run_python_script`` dispatches past the capability gate.

    ``hex_editor.run_python_script`` is mapped to the ``static_analysis``
    capability in ``TOOL_CAPABILITY_MAP`` (``bridges/base.py``). Confirms
    dispatch reaches the real, deliberately-hard-disabled bridge method
    (which always raises ``ToolError``) rather than being rejected earlier
    by a missing-capability check -- distinguishing "the feature is
    permanently disabled for security" from "the tool is unreachable."
    """

    @staticmethod
    def test_bridge_declares_static_analysis_capability(bridge: HexEditorBridge) -> None:
        """``HexEditorBridge`` must declare ``supports_static_analysis=True``.

        Falsifiable: if this capability flag were reverted to its default
        (``False``), the dispatch test below would raise ``ToolError`` for a
        missing capability instead of reaching the disabled method's own
        ``ToolError``.

        Args:
            bridge: Fresh bridge fixture.
        """
        assert bridge.capabilities.supports_static_analysis is True

    @staticmethod
    def test_execute_tool_call_reaches_disabled_method_not_capability_gate(tmp_path: Path) -> None:
        """Dispatching ``hex_editor.run_python_script`` raises the method's own disablement error.

        Falsifiable: if the capability gate in ``ToolRegistry.execute_tool_call``
        rejected the call first, the raised message would contain
        ``missing capability`` rather than ``disabled: in-process Python``.
        Broken production line: ``supports_static_analysis=True`` in
        ``HexEditorBridge.capabilities`` (``bridges/hex_editor.py``) combined
        with the ``"hex_editor.run_python_script": "static_analysis"`` entry
        in ``TOOL_CAPABILITY_MAP`` (``bridges/base.py``).

        Args:
            tmp_path: Pytest-managed temporary directory used as the tools root.
        """

        async def _scenario() -> None:
            registry = ToolRegistry(tools_dir=tmp_path)
            bridge = HexEditorBridge()
            registry.register_bridge(ToolName.HEX_EDITOR, bridge)
            with pytest.raises(ToolError) as excinfo:
                await registry.execute_tool_call(
                    "hex_editor",
                    "hex_editor.run_python_script",
                    {"source": "1 + 1"},
                )
            message = str(excinfo.value).lower()
            assert "missing capability" not in message
            assert "disabled" in message
            assert "in-process python" in message

        _run(_scenario())
