# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate: ``HexEditorPanel.load_file`` must wire its hexcore document into the bridge.

Prior to this fix, ``HexEditorPanel._load_file_impl`` (``ui/panels/hex_editor/panel.py``)
opened ``intellicrack_hexcore.HexDocument`` directly for the panel's own hex
widget but never told the attached ``HexEditorBridge`` about the new
document. The bridge's own ``document`` attribute stayed ``None`` forever, so
every AI/GUI operation dispatched through the bridge -- ``get_pe_sections``,
``get_pe_imports``, ``get_pe_exports``, ``auto_detect_pattern``,
``disassemble``, VA-mapping auto-detect -- raised
``RuntimeError("no document open")`` even though the panel was visibly
displaying a loaded file, and the sidebar auto-refresh that fires from
``_load_file_impl`` itself failed the same way on every load.

The fix adds ``HexEditorBridge.adopt_document`` (a synchronous method that
mirrors ``open_file``'s state bookkeeping without re-reading the file from
disk or publishing a second ``DOCUMENT_OPENED`` notification back through the
shared ``HexDocumentState`` -- which would otherwise re-enter
``HexEditorPanel._on_state_event`` -> ``load_file`` in a loop) and calls it
from ``_load_file_impl`` immediately after the panel opens its own document,
before any of the auto-refresh sub-features fire.

Every test here drives the REAL, unmodified ``HexEditorPanel.load_file`` entry
point (the actual GUI open path, not a manual
``panel.document = bridge.document`` workaround used elsewhere in this
package) against a real ``HexEditorBridge`` and a real System32 DLL, and
cross-validates the bridge's section/import data against the independent
``pefile`` oracle.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pefile
import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import pump_until, tree_columns


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async coroutine to completion synchronously.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    return asyncio.run(coro)


def _pefile_section_names(path: Path) -> set[str]:
    """Collect section names via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        set[str]: Section name strings from the section table.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        return {s.Name.split(b"\x00", 1)[0].decode("ascii", errors="replace") for s in pe.sections}
    finally:
        pe.close()


class TestLoadFileAdoptsBridgeDocument:
    """``HexEditorPanel.load_file`` must open the SAME document in the attached bridge."""

    @staticmethod
    def test_bridge_document_is_the_same_object_after_real_load(qapp: QApplication, real_pe_dll: Path) -> None:
        """After ``load_file``, ``bridge.document`` must be the panel's own document.

        Falsifiable: if ``_load_file_impl`` never calls
        ``HexEditorBridge.adopt_document`` (the pre-fix state), ``bridge.document``
        stays ``None`` and this assertion fails.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        try:
            panel.set_bridge(bridge)
            loaded = panel.load_file(str(real_pe_dll))
            assert loaded is True
            assert panel.document is not None
            assert bridge.document is panel.document
        finally:
            panel.deleteLater()

    @staticmethod
    def test_get_pe_sections_returns_real_sections_matching_pefile(qapp: QApplication, real_pe_dll: Path) -> None:
        """``bridge.get_pe_sections`` must succeed and match the pefile oracle after a real GUI load.

        Falsifiable: without the fix, ``bridge.document`` is ``None`` and this
        raises ``RuntimeError("no document open")`` instead of returning data.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(real_pe_dll)) is True

            sections = _run(bridge.get_pe_sections())
            assert sections
            actual_names = {str(s["name"]) for s in sections}
            expected_names = _pefile_section_names(real_pe_dll)
            assert actual_names == expected_names
        finally:
            panel.deleteLater()

    @staticmethod
    def test_no_document_open_error_is_not_raised_for_any_document_backed_op(qapp: QApplication, real_pe_dll: Path) -> None:
        """All document-backed bridge ops used at load time must run without raising.

        Exercises ``get_pe_sections``, ``get_pe_imports``, ``get_pe_exports``,
        and ``auto_detect_pattern`` -- the operations the audit reported as
        failing with ``RuntimeError("no document open")`` immediately after
        opening a binary through the Hex Editor panel.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(real_pe_dll)) is True

            sections = _run(bridge.get_pe_sections())
            imports = _run(bridge.get_pe_imports())
            exports = _run(bridge.get_pe_exports())
            patterns = _run(bridge.auto_detect_pattern())

            assert sections
            dll_names = {str(i["dll"]).lower() for i in imports}
            assert any("kernelbase" in name or "ntdll" in name for name in dll_names)
            names = {str(e["name"]) for e in exports}
            assert "LoadLibraryA" in names
            assert isinstance(patterns, list)
        finally:
            panel.deleteLater()


class TestLoadFileGuiAutoRefreshPopulatesFromBridge:
    """The panel's own auto-refresh (sections/imports/exports trees) must populate on real load."""

    @staticmethod
    def test_sections_tree_populates_with_real_section_names(qapp: QApplication, real_pe_dll: Path) -> None:
        """The sections tree must show real section rows after ``load_file``, with no lingering failure.

        Falsifiable: without the fix, ``_populate_sections`` (fired from
        inside ``_load_file_impl`` itself) dispatches ``bridge.get_pe_sections()``
        against a bridge whose document is ``None``; the worker fails and the
        tree is never populated.

        Args:
            qapp: Session QApplication fixture.
            real_pe_dll: Path to a real kernel32.dll fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        try:
            panel.set_bridge(bridge)
            assert panel.load_file(str(real_pe_dll)) is True

            tree = panel.sections_tree
            assert tree is not None
            pump_until(qapp, lambda: tree.topLevelItemCount() > 0)

            names = {row[0] for row in tree_columns(tree, 0)}
            expected_names = _pefile_section_names(real_pe_dll)
            assert names == expected_names
        finally:
            panel.deleteLater()
