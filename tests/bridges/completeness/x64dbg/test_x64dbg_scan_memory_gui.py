# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg memory-search GUI controls (slice-2 row 8).

``X64DbgBridge.scan_memory`` (an exact-byte memory scan that returns
``MemorySearchResult`` records carrying real surrounding-byte context) had
no direct GUI control: the Search tab's "Hex" and "Byte" mode options were
wired identically in ``_on_search``, both dispatching to ``find_pattern``
(the wildcard-capable pattern search, which returns bare
``{"address": ..., "offset": ...}`` dicts with no match bytes or context).
"Byte" mode was therefore dead -- selecting it changed nothing -- and
``scan_memory`` was reachable only indirectly, through ``find_pattern``'s
own no-wildcard fallback.

The remediation gives "Byte" mode its own branch in ``_on_search`` that
calls ``self._bridge.scan_memory(pattern)`` directly, and extends
``_on_search_complete`` to render ``MemorySearchResult`` dataclass rows (in
addition to the pre-existing dict-shaped rows from ``find_pattern`` /
``yara_scan``) so the Match and Context columns are populated with real
matched-byte and surrounding-context data instead of staying permanently
empty.

This module proves, against the real production code:

* ``TestByteModeDispatch`` -- selecting "Byte" mode calls
  ``bridge.scan_memory`` and never calls ``bridge.find_pattern``; selecting
  "Hex" mode still calls ``bridge.find_pattern`` (regression guard for the
  wildcard-search workflow).
* ``TestSearchResultsRendering`` -- ``_on_search_complete`` renders genuine
  ``MemorySearchResult`` instances into the Address/Match/Context columns
  with the real field values, and continues to render dict-shaped results
  (the ``find_pattern``/``yara_scan`` shape) without regression.
* ``TestScanMemoryErrorSurfacing`` -- the real, unmodified
  ``X64DbgBridge.scan_memory`` raising ``ToolError`` for a pattern shorter
  than ``MIN_PATTERN_LENGTH`` reaches the console as a clear message (not a
  silent no-op), through the same ``_on_generic_error`` convention used by
  every other Search-tab failure.
"""

from __future__ import annotations

import asyncio
import sys
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget

from intellicrack.bridges.base import MemorySearchResult
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_SIXTEEN_BYTE_PATTERN = "48 8B 05 11 22 33 44 55 66 77 88 99 AA BB CC DD"
_WILDCARD_PATTERN = "48 8B ?? 90"


def _cell_text(table: QTableWidget, row: int, column: int) -> str:
    """Read the text of a table cell, failing loudly if the cell is empty.

    Args:
        table: The table widget to read from.
        row: Row index.
        column: Column index.

    Returns:
        str: The cell's text.
    """
    item = table.item(row, column)
    assert item is not None, f"expected an item at ({row}, {column})"
    return item.text()


class TestByteModeDispatch:
    """L3: the Search tab's "Byte" mode must call ``scan_memory``, never ``find_pattern``."""

    @staticmethod
    def test_byte_mode_click_calls_scan_memory_and_never_find_pattern(qapp: QApplication) -> None:
        """Clicking Search in "Byte" mode must invoke ``bridge.scan_memory`` directly.

        Falsifiable: reverting ``_on_search`` to its pre-remediation form
        (only ``"YARA"`` vs. an ``else`` branch calling ``find_pattern``)
        makes ``scan_calls`` stay empty and ``find_calls`` receive the
        pattern instead, failing both assertions below. Broken production
        line: the ``elif mode == "Byte":`` branch in ``X64DbgPanel._on_search``
        (``ui/panels/x64dbg_panel.py``).

        Args:
            qapp: Session QApplication fixture used to pump the Qt event
                loop so the cross-thread async result can be delivered.
        """
        panel = X64DbgPanel()
        bridge = X64DbgBridge()
        scan_calls: list[str | bytes] = []
        find_calls: list[str] = []

        async def _fake_scan_memory(pattern: str | bytes) -> list[MemorySearchResult]:
            await asyncio.sleep(0)
            scan_calls.append(pattern)
            return [
                MemorySearchResult(
                    address=0x401000,
                    matched_bytes="488b0511223344",
                    context_before="9090909090909090",
                    context_after="c3c3c3c3c3c3c3c3",
                ),
            ]

        async def _fake_find_pattern(pattern: str, alignment: int = 1) -> list[dict[str, Any]]:
            del alignment
            await asyncio.sleep(0)
            find_calls.append(pattern)
            return [{"address": hex(0x402000), "offset": 0x402000}]

        setattr(bridge, "scan_memory", _fake_scan_memory)
        setattr(bridge, "find_pattern", _fake_find_pattern)

        panel.set_bridge(bridge)
        mode_combo = priv(panel, "_search_mode_combo", QComboBox)
        pattern_input = priv(panel, "_search_pattern_input", QLineEdit)
        search_btn = priv(panel, "_search_btn", QPushButton)
        search_table = priv(panel, "_search_table", QTableWidget)

        try:
            mode_combo.setCurrentText("Byte")
            pattern_input.setText(_SIXTEEN_BYTE_PATTERN)
            search_btn.click()

            pump_until(qapp, lambda: search_table.rowCount() >= 1)

            assert scan_calls == [_SIXTEEN_BYTE_PATTERN], (
                f"Byte mode must call bridge.scan_memory with the raw pattern text; got {scan_calls!r}"
            )
            assert find_calls == [], f"Byte mode must never call bridge.find_pattern; got {find_calls!r}"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_hex_mode_click_still_calls_find_pattern_and_never_scan_memory(qapp: QApplication) -> None:
        """"Hex" mode must keep dispatching to ``find_pattern``, unaffected by the "Byte" wiring.

        Regression guard: proves the new "Byte" branch was added as an
        ``elif``, not by replacing the pre-existing wildcard-capable "Hex"
        path.

        Args:
            qapp: Session QApplication fixture used to pump the Qt event
                loop so the cross-thread async result can be delivered.
        """
        panel = X64DbgPanel()
        bridge = X64DbgBridge()
        scan_calls: list[str | bytes] = []
        find_calls: list[str] = []

        async def _fake_scan_memory(pattern: str | bytes) -> list[MemorySearchResult]:
            await asyncio.sleep(0)
            scan_calls.append(pattern)
            return []

        async def _fake_find_pattern(pattern: str, alignment: int = 1) -> list[dict[str, Any]]:
            del alignment
            await asyncio.sleep(0)
            find_calls.append(pattern)
            return [{"address": hex(0x402000), "offset": 0x402000}]

        setattr(bridge, "scan_memory", _fake_scan_memory)
        setattr(bridge, "find_pattern", _fake_find_pattern)

        panel.set_bridge(bridge)
        mode_combo = priv(panel, "_search_mode_combo", QComboBox)
        pattern_input = priv(panel, "_search_pattern_input", QLineEdit)
        search_btn = priv(panel, "_search_btn", QPushButton)
        search_table = priv(panel, "_search_table", QTableWidget)

        try:
            mode_combo.setCurrentText("Hex")
            pattern_input.setText(_WILDCARD_PATTERN)
            search_btn.click()

            pump_until(qapp, lambda: search_table.rowCount() >= 1)

            assert find_calls == [_WILDCARD_PATTERN], f"Hex mode must call bridge.find_pattern; got {find_calls!r}"
            assert scan_calls == [], f"Hex mode must never call bridge.scan_memory directly; got {scan_calls!r}"
        finally:
            panel.deleteLater()


class TestSearchResultsRendering:
    """L3: ``_on_search_complete`` must render both the dict shape and the ``MemorySearchResult`` shape."""

    @staticmethod
    def test_memory_search_result_rows_populate_address_match_and_context(qapp: QApplication) -> None:
        """A real ``MemorySearchResult`` list must populate all three data columns with real field values.

        Falsifiable: reverting ``_on_search_complete`` to only branch on
        ``isinstance(match, dict)`` (the pre-remediation form) makes every
        column past "#" stay empty for these rows, failing every assertion
        below. Broken production line: the
        ``if isinstance(match, MemorySearchResult):`` branch in
        ``X64DbgPanel._on_search_complete`` (``ui/panels/x64dbg_panel.py``).

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = X64DbgPanel()
        search_table = priv(panel, "_search_table", QTableWidget)

        result = MemorySearchResult(
            address=0x7FFABCDE1000,
            matched_bytes="488b0511223344",
            context_before="9090909090909090",
            context_after="c3c3c3c3c3c3c3c3",
        )

        try:
            getattr(panel, "_on_search_complete")([result])

            assert search_table.rowCount() == 1
            assert _cell_text(search_table, 0, 0) == "0"
            assert _cell_text(search_table, 0, 1) == f"0x{result.address:X}"
            assert _cell_text(search_table, 0, 2) == result.matched_bytes
            context = _cell_text(search_table, 0, 3)
            assert result.context_before in context, f"context_before must appear in the Context cell; got {context!r}"
            assert result.context_after in context, f"context_after must appear in the Context cell; got {context!r}"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_dict_shaped_results_still_render_without_regression(qapp: QApplication) -> None:
        """The pre-existing ``find_pattern``/``yara_scan`` dict shape must keep rendering correctly.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = X64DbgPanel()
        search_table = priv(panel, "_search_table", QTableWidget)

        yara_shaped = {"address": hex(0x403000), "rule": "gate_rule", "matched_bytes": "cafebabe", "context_before": "deadbeef"}
        find_pattern_shaped = {"address": hex(0x404000), "offset": 0x404000}

        try:
            getattr(panel, "_on_search_complete")([yara_shaped, find_pattern_shaped])

            assert search_table.rowCount() == 2
            assert _cell_text(search_table, 0, 1) == hex(0x403000)
            assert _cell_text(search_table, 0, 2) == "cafebabe"
            assert _cell_text(search_table, 0, 3) == "deadbeef"

            assert _cell_text(search_table, 1, 1) == hex(0x404000)
            assert not _cell_text(search_table, 1, 2)
            assert not _cell_text(search_table, 1, 3)
        finally:
            panel.deleteLater()

    @staticmethod
    def test_mixed_dataclass_and_dict_results_both_render_in_one_pass(qapp: QApplication) -> None:
        """A single results list mixing both shapes must render every row correctly.

        Exercises the ``isinstance`` branch selection row-by-row rather than
        assuming a uniform result-list shape.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = X64DbgPanel()
        search_table = priv(panel, "_search_table", QTableWidget)

        scan_result = MemorySearchResult(
            address=0x500000,
            matched_bytes="aabbccdd",
            context_before="11223344",
            context_after="55667788",
        )
        pattern_result = {"address": hex(0x600000), "offset": 0x600000}

        try:
            getattr(panel, "_on_search_complete")([scan_result, pattern_result])

            assert search_table.rowCount() == 2
            assert _cell_text(search_table, 0, 1) == f"0x{scan_result.address:X}"
            assert _cell_text(search_table, 0, 2) == "aabbccdd"
            assert _cell_text(search_table, 1, 1) == hex(0x600000)
            assert not _cell_text(search_table, 1, 2)
        finally:
            panel.deleteLater()


class TestScanMemoryErrorSurfacing:
    """L1+L3: the real, unmodified ``scan_memory`` ``ToolError`` must reach the operator, not fail silently."""

    @staticmethod
    def test_pattern_shorter_than_minimum_reports_clear_console_error(qapp: QApplication) -> None:
        """Typing a too-short pattern in "Byte" mode must surface the real ``ToolError`` text in the console.

        Uses the real, unmodified ``X64DbgBridge.scan_memory``: no pipe or
        method substitution. ``scan_memory`` validates pattern length before
        touching any Windows API, so this raises deterministically.

        Falsifiable: if the "Byte" branch omitted its ``on_error=`` callback
        (or called a bridge method that does not validate pattern length),
        the console would never receive a "failed" line and ``pump_until``
        would time out, failing the assertions below.

        Args:
            qapp: Session QApplication fixture used to pump the Qt event
                loop so the cross-thread async error can be delivered.
        """
        panel = X64DbgPanel()
        bridge = X64DbgBridge()
        panel.set_bridge(bridge)

        mode_combo = priv(panel, "_search_mode_combo", QComboBox)
        pattern_input = priv(panel, "_search_pattern_input", QLineEdit)
        search_btn = priv(panel, "_search_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            mode_combo.setCurrentText("Byte")
            pattern_input.setText("90")
            search_btn.click()

            pump_until(qapp, lambda: "failed" in console_output.toPlainText().lower())

            console_text = console_output.toPlainText()
            assert "Search failed" in console_text, f"expected a clear failure line; got {console_text!r}"
            assert "pattern too short for reliable scan" in console_text
            assert "got 1 bytes, need at least 16" in console_text
            assert search_btn.isEnabled(), "the Search button must be re-enabled after the error is reported"
        finally:
            panel.deleteLater()
