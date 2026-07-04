# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L2/L3 gate tests for the hex-editor VA-mapping tab (rows #72-73, #77-78).

Covers ``audit/bridge-completeness/agent-09-hex-editor.md``:

* Row #72 -- ``set_va_base``/``list_va_mappings``/``auto_detect_va_mappings``/
  ``remove_va_mapping`` (``hex_editor.py:8187-8274``) had zero GUI surface.
* Row #73 -- ``file_offset_to_va``/``va_to_file_offset`` (``hex_editor.py:8302,8320``)
  had zero GUI surface.
* Row #77 -- ``set_chunk_size`` had zero GUI surface.
* Row #78 -- ``get_memory_usage``/``set_memory_budget`` had zero GUI surface.

The remediation adds a new "VA Mapping" side tab
(``ui/panels/hex_editor/va_mapping.py``, wired into the panel at
``panel.py:465``) with add/remove/auto-detect/refresh controls, a
goto-by-VA / cursor-offset-to-VA navigation pair, and a "Performance
Settings..." entry point for chunk-size/memory-budget tuning.

All tests drive the real ``HexEditorBridge`` VA methods against a real
``intellicrack_hexcore.HexDocument`` (a synthetic document for the
manual-mapping CRUD path, and a real ``kernel32.dll`` for the
auto-detect path, cross-validated against ``pefile`` as an independent
oracle for the PE image base).
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, ClassVar

import intellicrack_hexcore
import pefile
import pytest
from PyQt6.QtWidgets import QDialog, QLabel, QLineEdit, QTreeWidget, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.ui.panels.hex_editor import va_mapping as va_mapping_module
from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel

from .conftest import open_doc, priv, priv_method, pump_until, release_and_unlink


class _StubPerformanceDialog:
    """Stand-in for ``LargeFileSettingsDialog`` recording the values it was opened with.

    Records the ``current_chunk_kb``/``current_budget_mb`` the handler
    derived from ``get_memory_usage`` (proving the read happened) and
    forces an accepted dialog exposing new chunk/budget values (proving
    the apply path runs).
    """

    opened_with: ClassVar[list[tuple[int, int]]] = []
    result_chunk_kb: ClassVar[int] = 128
    result_budget_mb: ClassVar[int] = 8

    def __init__(
        self,
        current_chunk_kb: int,
        current_budget_mb: int,
        current_usage_mb: float,
        parent: QWidget | None,
    ) -> None:
        """Record the current values and expose the forced result values.

        Args:
            current_chunk_kb: Current chunk size in KiB the handler read.
            current_budget_mb: Current memory budget in MiB the handler read.
            current_usage_mb: Current usage in MiB (unused by the stub).
            parent: Parent widget (unused by the stub).
        """
        del current_usage_mb, parent
        type(self).opened_with.append((current_chunk_kb, current_budget_mb))
        self.chunk_size_kb: int = type(self).result_chunk_kb
        self.memory_budget_mb: int = type(self).result_budget_mb

    def exec(self) -> QDialog.DialogCode:
        """Return an accepted dialog code without showing a modal.

        Returns:
            QDialog.DialogCode: ``Accepted`` so the handler applies the values.
        """
        return QDialog.DialogCode.Accepted


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


class TestVaMappingCrudBridgeL1:
    """L1: ``set_va_base``/``list_va_mappings``/``remove_va_mapping``/conversion methods."""

    @staticmethod
    def test_set_then_list_then_convert_round_trips(bridge: HexEditorBridge) -> None:
        """A manually added mapping round-trips through list/convert exactly.

        Independent oracle: the literal file_offset/virtual_address/length
        values this test supplies directly to ``set_va_base``.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = open_doc(bridge, b"\x00" * 64)
        try:
            added = _run(bridge.set_va_base(0x10, 0x140001000, 0x20))
            assert added is True

            mappings = _run(bridge.list_va_mappings())
            assert len(mappings) == 1
            assert mappings[0] == {"file_offset": 0x10, "virtual_address": 0x140001000, "length": 0x20}

            va = _run(bridge.file_offset_to_va(0x18))
            assert va == 0x140001008

            offset = _run(bridge.va_to_file_offset(0x140001008))
            assert offset == 0x18
        finally:
            release_and_unlink(bridge, path)

    @staticmethod
    def test_remove_va_mapping_by_index_clears_the_list(bridge: HexEditorBridge) -> None:
        """Removing the only mapping by index must empty the list.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = open_doc(bridge, b"\x00" * 64)
        try:
            _run(bridge.set_va_base(0, 0x400000, 64))
            assert len(_run(bridge.list_va_mappings())) == 1

            removed = _run(bridge.remove_va_mapping(0))
            assert removed is True
            assert _run(bridge.list_va_mappings()) == []
        finally:
            release_and_unlink(bridge, path)

    @staticmethod
    def test_unmapped_offset_and_va_return_none(bridge: HexEditorBridge) -> None:
        """Conversion for an offset/VA outside any mapping must return ``None``, not raise.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = open_doc(bridge, b"\x00" * 64)
        try:
            _run(bridge.set_va_base(0, 0x400000, 16))
            assert _run(bridge.file_offset_to_va(0x1000)) is None
            assert _run(bridge.va_to_file_offset(0x999999)) is None
        finally:
            release_and_unlink(bridge, path)

    @staticmethod
    def test_no_document_raises_runtime_error(bridge: HexEditorBridge) -> None:
        """Calling ``set_va_base`` with no open document raises ``RuntimeError``.

        Args:
            bridge: Fresh bridge fixture with no document.
        """
        with pytest.raises(RuntimeError, match="no document open"):
            _run(bridge.set_va_base(0, 0x400000, 16))


@pytest.mark.skipif(sys.platform != "win32", reason="requires a real Windows System32 PE DLL")
class TestAutoDetectVaMappingsBridgeL1:
    """L1: ``auto_detect_va_mappings`` parses a real PE image base, cross-checked via ``pefile``."""

    @staticmethod
    def test_image_base_matches_pefile_oracle(bridge: HexEditorBridge) -> None:
        """The detected image-base mapping matches ``pefile``'s independently parsed ``ImageBase``.

        Independent oracle: ``pefile``, a wholly separate PE-parsing
        library never invoked by production code under test.

        Args:
            bridge: Fresh bridge fixture.
        """
        dll_path = r"C:\Windows\System32\kernel32.dll"
        pe = pefile.PE(dll_path, fast_load=True)
        expected_image_base = pe.OPTIONAL_HEADER.ImageBase
        pe.close()

        bridge.document = intellicrack_hexcore.HexDocument.open(dll_path)
        try:
            mappings = _run(bridge.auto_detect_va_mappings())
            assert len(mappings) > 0
            assert mappings[0]["file_offset"] == 0
            assert mappings[0]["virtual_address"] == expected_image_base
        finally:
            bridge.document = None


class TestVaMappingGuiTabExistsAndIsWiredL3:
    """L3: the VA Mapping tab's widgets exist and are connected to their handlers."""

    @staticmethod
    def test_tab_widgets_exist(qapp: QApplication) -> None:
        """The panel must expose the VA-mapping tree, add/remove/goto fields, and status label.

        Falsifiable: if the VA Mapping tab were removed from
        ``_build_side_tabs`` (``panel.py:465``), these attributes would
        remain ``None`` (never populated by ``_create_va_mapping_tab``).

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            assert priv(panel, "_va_mappings_tree", QTreeWidget).columnCount() == 3
            priv(panel, "_va_file_offset_edit", QLineEdit)
            priv(panel, "_va_address_edit", QLineEdit)
            priv(panel, "_va_length_edit", QLineEdit)
            priv(panel, "_va_goto_edit", QLineEdit)
            priv(panel, "_va_status_label", QLabel)
        finally:
            panel.deleteLater()


class TestVaMappingGuiDispatchesRealBridgeL3:
    """L3: the VA Mapping tab's handlers drive the real bridge methods end-to-end."""

    @staticmethod
    def test_add_mapping_dispatches_set_va_base_and_refreshes_tree(qapp: QApplication) -> None:
        """The Add Mapping button must call the real ``bridge.set_va_base`` and populate the tree from ``list_va_mappings``.

        Falsifiable: if ``_on_add_va_mapping`` called anything other than
        ``bridge.set_va_base`` (or skipped the refresh), the tree would
        never show the real hex-formatted offset/VA/length this test
        submitted. Broken production line:
        ``run_bridge_coroutine_logged(bridge.set_va_base(file_offset,
        virtual_address, length), ...)`` in
        ``VaMappingMixin._on_add_va_mapping`` (``ui/panels/hex_editor/va_mapping.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, b"\x00" * 64)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv(panel, "_va_file_offset_edit", QLineEdit).setText("0x10")
            priv(panel, "_va_address_edit", QLineEdit).setText("0x140001000")
            priv(panel, "_va_length_edit", QLineEdit).setText("0x20")

            priv_method(panel, "_on_add_va_mapping")()
            mappings_tree = priv(panel, "_va_mappings_tree", QTreeWidget)
            pump_until(qapp, lambda: mappings_tree.topLevelItemCount() > 0)

            assert mappings_tree.topLevelItemCount() == 1
            item = mappings_tree.topLevelItem(0)
            assert item is not None
            assert item.text(0) == "0x10"
            assert item.text(1) == "0x140001000"
            assert item.text(2) == "0x20"

            real_mappings = _run(bridge.list_va_mappings())
            assert real_mappings == [{"file_offset": 0x10, "virtual_address": 0x140001000, "length": 0x20}]
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_goto_va_converts_via_real_bridge_and_navigates(qapp: QApplication) -> None:
        """The Go (VA -> offset) button must call ``bridge.va_to_file_offset`` and update the status label.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, b"\x00" * 64)
        try:
            _run(bridge.set_va_base(0x10, 0x140001000, 0x20))
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv(panel, "_va_goto_edit", QLineEdit).setText("0x140001008")
            priv_method(panel, "_on_goto_va")()

            assert priv(panel, "_va_status_label", QLabel).text() == "0x140001008 -> file offset 0x18"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_goto_va_unmapped_reports_not_mapped_without_raising(qapp: QApplication) -> None:
        """A VA outside any mapping must produce a clear status message, not an exception.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, b"\x00" * 64)
        try:
            panel.set_bridge(bridge)
            panel.document = bridge.document

            priv(panel, "_va_goto_edit", QLineEdit).setText("0xDEADBEEF")
            priv_method(panel, "_on_goto_va")()

            assert priv(panel, "_va_status_label", QLabel).text() == "0xDEADBEEF is not mapped to a file offset"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()

    @staticmethod
    def test_remove_selected_mapping_dispatches_remove_va_mapping(qapp: QApplication) -> None:
        """The Remove Selected button must call ``bridge.remove_va_mapping`` with the selected row index.

        Args:
            qapp: Session QApplication fixture.
        """
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, b"\x00" * 64)
        try:
            _run(bridge.set_va_base(0, 0x400000, 16))
            panel.set_bridge(bridge)
            panel.document = bridge.document
            priv_method(panel, "_on_refresh_va_mappings")()
            mappings_tree = priv(panel, "_va_mappings_tree", QTreeWidget)
            pump_until(qapp, lambda: mappings_tree.topLevelItemCount() > 0)
            mappings_tree.setCurrentItem(mappings_tree.topLevelItem(0))

            priv_method(panel, "_on_remove_va_mapping")()
            pump_until(qapp, lambda: len(_run(bridge.list_va_mappings())) == 0)

            assert _run(bridge.list_va_mappings()) == []
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestPerformanceSettingsEntryPointDispatchesRealBridgeL3:
    """L3 (row #77-78): the "Performance Settings..." entry point reads real chunk/budget state."""

    @staticmethod
    def test_open_performance_settings_reads_then_applies_via_real_bridge(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Invoking the handler must read ``get_memory_usage`` then apply the dialog's new chunk/budget.

        Sets a known chunk-size (64 KiB) and budget (4 MiB) on the real
        bridge, patches ``LargeFileSettingsDialog`` with a stub that records
        the current values the handler passes it and returns an accepted
        dialog carrying new values (128 KiB / 8 MiB), then invokes the real
        ``_on_open_performance_settings`` handler and asserts BOTH: (a) the
        stub was constructed with ``(64, 4)`` -- proving the handler read
        ``get_memory_usage`` and derived the dialog's current values from
        it; and (b) a fresh ``get_memory_usage`` afterwards reports the new
        128 KiB / 8 MiB -- proving the handler applied them via
        ``set_chunk_size``/``set_memory_budget``.

        Falsifiable: if ``_on_open_performance_settings`` skipped the
        ``get_memory_usage`` read, ``opened_with`` would not equal
        ``[(64, 4)]``; if it skipped the ``set_chunk_size``/
        ``set_memory_budget`` apply, the readback would still show the
        original 64 KiB / 4 MiB. Broken production lines:
        ``run_bridge_coroutine(bridge.get_memory_usage())`` and the
        ``set_chunk_size``/``set_memory_budget`` calls in
        ``_on_open_performance_settings`` (``ui/panels/hex_editor/va_mapping.py``).

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        del qapp
        panel = HexEditorPanel()
        bridge = HexEditorBridge()
        path = open_doc(bridge, b"\x00" * (1024 * 1024))
        try:
            _run(bridge.set_chunk_size(64 * 1024))
            _run(bridge.set_memory_budget(4 * 1024 * 1024))
            panel.set_bridge(bridge)
            panel.document = bridge.document

            _StubPerformanceDialog.opened_with = []
            monkeypatch.setattr(va_mapping_module, "LargeFileSettingsDialog", _StubPerformanceDialog)

            priv_method(panel, "_on_open_performance_settings")()

            assert _StubPerformanceDialog.opened_with == [(64, 4)], (
                "the handler must read get_memory_usage and open the dialog with the current "
                f"chunk-KiB/budget-MiB; recorded {_StubPerformanceDialog.opened_with!r}"
            )
            applied = _run(bridge.get_memory_usage())
            assert applied["chunk_size"] == 128 * 1024, "accepted dialog's new chunk size must be applied via set_chunk_size"
            assert applied["memory_budget"] == 8 * 1024 * 1024, "accepted dialog's new memory budget must be applied via set_memory_budget"
        finally:
            release_and_unlink(bridge, path)
            panel.deleteLater()


class TestChunkSizeAndMemoryBudgetBridgeL1:
    """L1: ``set_chunk_size``/``get_memory_usage``/``set_memory_budget`` mutate real backend state."""

    @staticmethod
    def test_set_chunk_size_then_get_memory_usage_reflects_it(bridge: HexEditorBridge) -> None:
        """A chunk size set via ``set_chunk_size`` is echoed back by ``get_memory_usage``.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = open_doc(bridge, b"\x00" * 4096)
        try:
            accepted = _run(bridge.set_chunk_size(131072))
            assert accepted is True
            usage = _run(bridge.get_memory_usage())
            assert usage["chunk_size"] == 131072
        finally:
            release_and_unlink(bridge, path)

    @staticmethod
    def test_non_positive_chunk_size_raises_value_error(bridge: HexEditorBridge) -> None:
        """A zero or negative chunk size must raise ``ValueError``.

        Args:
            bridge: Fresh bridge fixture.
        """
        path = open_doc(bridge, b"\x00" * 64)
        try:
            with pytest.raises(ValueError, match="positive integer"):
                _run(bridge.set_chunk_size(0))
        finally:
            release_and_unlink(bridge, path)
