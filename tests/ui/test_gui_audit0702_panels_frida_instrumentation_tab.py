# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gates for ``intellicrack.ui.panels.frida_instrumentation_tab``.

Covers the 2026-07-02 audit findings for ``frida_instrumentation_tab.py``'s
``SymbolLookupControls`` and ``ScriptMessagingControls`` widgets:

* M20 -- ``_populate_symbols_from_module`` (the ``Enumerate Symbols`` handler)
  must populate the symbols table's third and fourth columns from real symbol
  data (module name and source file:line) instead of unconditionally
  inserting empty-string cells.
* M21 -- the third column must carry the same semantic value (the symbol's
  module name) regardless of whether the row came from ``Enumerate Symbols``
  or ``Find Functions Matching``, instead of one path leaving it blank and
  the other stuffing the module name into a column labelled ``Is Global``.
* M22 -- the shared ``_on_symbol_lookup_error`` handler must re-enable only
  the button belonging to the operation that actually failed, not all three
  symbol-lookup buttons unconditionally.
* L7 -- the symbols table header must stretch only the ``Name`` column and
  size the remaining columns to their contents, instead of applying
  ``Stretch`` to every column uniformly.
* L8 -- the RPC result label must word-wrap and expose the full result text
  via tooltip instead of clipping a long, unwrapped single line.

All tests drive real, constructed ``SymbolLookupControls`` /
``ScriptMessagingControls`` widgets under an offscreen ``QApplication``; no
widget behaviour under test is mocked or stubbed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QHeaderView

from intellicrack.core.types import SymbolInfo
from intellicrack.ui.panels.frida_instrumentation_tab import (
    ScriptMessagingControls,
    SymbolLookupControls,
)


if TYPE_CHECKING:
    from collections.abc import Callable


pytestmark = pytest.mark.usefixtures("qapp")


def _make_symbol(
    name: str,
    address: int,
    module_name: str | None,
    file_name: str | None = None,
    line_number: int | None = None,
) -> SymbolInfo:
    """Build a real ``SymbolInfo`` as returned by ``FridaBridge`` symbol lookups.

    Args:
        name: Symbol name.
        address: Symbol address.
        module_name: Module containing the symbol, or ``None``.
        file_name: Source file name if resolved, or ``None``.
        line_number: Source line number if resolved, or ``None``.

    Returns:
        SymbolInfo: A populated symbol record matching the bridge's real return type.
    """
    return SymbolInfo(
        name=name,
        address=address,
        module_name=module_name,
        file_name=file_name,
        line_number=line_number,
    )


def test_m20_enumerate_symbols_populates_module_and_source_columns() -> None:
    """``_populate_symbols_from_module`` must fill columns 2/3 with real data, not blanks.

    Regression: pre-fix, every row from the ``Enumerate Symbols`` path got
    ``QTableWidgetItem("")`` unconditionally in columns 2 and 3 regardless of
    the symbol's actual module/source data, so this assertion would see empty
    strings in both cells for every row.
    """
    controls = SymbolLookupControls()
    try:
        symbols = [
            _make_symbol("CreateFileW", 0x7FFE_1000, "kernel32.dll", "file.c", 42),
            _make_symbol("VirtualAlloc", 0x7FFE_2000, "kernel32.dll"),
        ]
        controls._populate_symbols_from_module(symbols)

        assert controls._symbols_table.rowCount() == 2

        module_item_0 = controls._symbols_table.item(0, 2)
        source_item_0 = controls._symbols_table.item(0, 3)
        assert module_item_0 is not None
        assert source_item_0 is not None
        assert module_item_0.text() == "kernel32.dll", "column 2 was left blank instead of the symbol's module"
        assert source_item_0.text() == "file.c:42", "column 3 was left blank instead of the symbol's source location"

        module_item_1 = controls._symbols_table.item(1, 2)
        source_item_1 = controls._symbols_table.item(1, 3)
        assert module_item_1 is not None
        assert source_item_1 is not None
        assert module_item_1.text() == "kernel32.dll"
        assert not source_item_1.text(), "a symbol with no file_name must render an empty (not fabricated) source"
    finally:
        controls.deleteLater()


def test_m20_enumerate_symbols_name_and_address_still_populated() -> None:
    """The pre-existing Name/Address columns must remain correct alongside the new columns.

    Ensures the M20 fix did not regress the columns that already worked.
    """
    controls = SymbolLookupControls()
    try:
        controls._populate_symbols_from_module([_make_symbol("VirtualProtect", 0x1000, "kernel32.dll")])
        name_item = controls._symbols_table.item(0, 0)
        addr_item = controls._symbols_table.item(0, 1)
        assert name_item is not None
        assert addr_item is not None
        assert name_item.text() == "VirtualProtect"
        assert addr_item.text() == "0x1000"
    finally:
        controls.deleteLater()


def test_m21_module_column_semantics_match_between_enumerate_and_matching_paths() -> None:
    """Column 2 must carry the identical module-name semantic from both populate paths.

    Regression: pre-fix, ``_populate_symbols_from_matching`` wrote the
    symbol's module name into column 2 (labelled ``Is Global``) while
    ``_populate_symbols_from_module`` left the same column blank -- two
    populate paths feeding the same table gave column 2 two different,
    both-wrong meanings. Post-fix both paths must write the same module-name
    value for symbols sharing a module.
    """
    controls = SymbolLookupControls()
    try:
        symbol = _make_symbol("NtCreateFile", 0x7FFE_3000, "ntdll.dll")

        controls._populate_symbols_from_module([symbol])
        enumerate_module_item = controls._symbols_table.item(0, 2)
        assert enumerate_module_item is not None
        enumerate_value = enumerate_module_item.text()

        controls._populate_symbols_from_matching([symbol])
        matching_module_item = controls._symbols_table.item(0, 2)
        assert matching_module_item is not None
        matching_value = matching_module_item.text()

        assert enumerate_value == "ntdll.dll", "enumerate-symbols path must populate the module column, not leave it blank"
        assert matching_value == "ntdll.dll"
        assert enumerate_value == matching_value, (
            f"column 2 has inconsistent semantics between populate paths: enumerate={enumerate_value!r} vs matching={matching_value!r}"
        )
    finally:
        controls.deleteLater()


def test_m21_symbol_columns_header_no_longer_mislabels_module_as_is_global() -> None:
    """The declared header for column 2 must not be the misleading ``Is Global`` label.

    Regression: with the header literally reading ``Is Global`` while the
    matching-path handler wrote a module name (e.g. ``kernel32.dll``) into
    it, the column header and its actual content were semantically
    incompatible. The fixed header must describe the module-name content
    that both populate paths now write.
    """
    controls = SymbolLookupControls()
    try:
        header = controls._symbols_table.horizontalHeaderItem(2)
        assert header is not None
        assert header.text() != "Is Global", "column 2 is still labelled Is Global despite holding a module name"
        assert header.text() == "Module"
    finally:
        controls.deleteLater()


def test_m22_error_handler_reenables_only_the_failed_operations_button() -> None:
    """``_on_symbol_lookup_error`` must re-enable only the button for the failed operation.

    Regression: pre-fix, the shared handler unconditionally re-enabled all
    three symbol-lookup buttons on any single failure. Simulates the race
    from the finding: two operations in flight (both buttons disabled), one
    fails; only that operation's button may come back enabled while the
    still-in-flight operation's button must remain disabled.
    """
    controls = SymbolLookupControls()
    try:
        controls._enum_symbols_btn.setEnabled(False)
        controls._find_module_btn.setEnabled(False)
        controls._find_matching_btn.setEnabled(False)

        controls._on_symbol_lookup_error("Find module by address", RuntimeError("boom"), controls._find_module_btn)

        assert controls._find_module_btn.isEnabled() is True, "the failed operation's own button must be re-enabled"
        assert controls._enum_symbols_btn.isEnabled() is False, (
            "an unrelated in-flight button was force re-enabled by another operation's failure"
        )
        assert controls._find_matching_btn.isEnabled() is False, (
            "an unrelated in-flight button was force re-enabled by another operation's failure"
        )
    finally:
        controls.deleteLater()


def test_m22_error_handler_requires_explicit_button_argument() -> None:
    """The handler's signature must take an explicit ``button`` parameter, matching the fixed pattern.

    Regression: pre-fix ``_on_symbol_lookup_error(self, operation, exc)`` took
    no button argument at all and reached into all three button attributes
    directly. Calling it with only ``(operation, exc)`` must now be a
    ``TypeError`` since the third positional argument is mandatory.
    """
    controls = SymbolLookupControls()
    try:
        handler = cast("Callable[..., None]", controls._on_symbol_lookup_error)
        raised = False
        try:
            handler("op", RuntimeError("x"))
        except TypeError:
            raised = True
        assert raised, "_on_symbol_lookup_error no longer requires the button parameter the M22 fix introduced"
    finally:
        controls.deleteLater()


def test_l7_only_name_column_stretches_others_resize_to_contents() -> None:
    """Header resize modes: column 0 stretches, columns 1-3 size to their contents.

    Regression: pre-fix ``setSectionResizeMode(QHeaderView.ResizeMode.Stretch)``
    was called with no column index, which applies Stretch to every section
    in the header -- all four columns would report ``Stretch`` here instead
    of only column 0.
    """
    controls = SymbolLookupControls()
    try:
        header = controls._symbols_table.horizontalHeader()
        assert header is not None
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "Name column must stretch to fill space"
        for column in (1, 2, 3):
            mode = header.sectionResizeMode(column)
            assert mode == QHeaderView.ResizeMode.ResizeToContents, (
                f"column {column} has resize mode {mode!r}; expected ResizeToContents, not uniform Stretch"
            )
    finally:
        controls.deleteLater()


def test_l7_long_symbol_name_gets_a_tooltip_with_the_full_text() -> None:
    """A long mangled symbol name must be recoverable via tooltip even when the cell elides it.

    Regression: pre-fix ``QTableWidgetItem(name)`` was created with no
    ``setToolTip`` call anywhere in either populate path, so hovering a
    truncated long name showed nothing.
    """
    controls = SymbolLookupControls()
    try:
        long_name = "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ_mangled_export_symbol"
        controls._populate_symbols_from_module([_make_symbol(long_name, 0x1000, "msvcp140.dll")])
        name_item = controls._symbols_table.item(0, 0)
        assert name_item is not None
        assert name_item.toolTip() == long_name, "the full symbol name must be recoverable via tooltip"
    finally:
        controls.deleteLater()


def test_l8_rpc_result_label_has_word_wrap_enabled_at_construction() -> None:
    """``_rpc_result_label`` must have word wrap enabled at construction.

    Regression: pre-fix, the bare ``QLabel("")`` never called
    ``setWordWrap(True)``, so a long RPC return value forced the panel to
    grow past its available width instead of wrapping onto multiple lines.
    """
    controls = ScriptMessagingControls()
    try:
        assert controls._rpc_result_label.wordWrap() is True
    finally:
        controls.deleteLater()


def test_l8_rpc_call_done_sets_full_text_and_tooltip_for_long_result() -> None:
    """A long RPC return value must populate both the label text and its tooltip in full.

    Drives the real ``_on_rpc_call_done`` handler with a long, structured
    return value (as an arbitrary ``rpc.exports`` function might return) and
    asserts the complete stringified value is present in both the label text
    and the tooltip.

    Regression: pre-fix ``_on_rpc_call_done`` only called
    ``self._rpc_result_label.setText(...)`` with no tooltip assignment, so
    ``toolTip()`` stayed the empty string regardless of result length, and
    with no word wrap the tail of a long unwrapped line was unreadable.
    """
    controls = ScriptMessagingControls()
    try:
        long_result = {
            "status": "ok",
            "addresses": [hex(0x7FFE_0000 + i * 0x1000) for i in range(40)],
            "note": "a long structured RPC export return value that exceeds one visible line",
        }

        controls._on_rpc_call_done(long_result)

        text = controls._rpc_result_label.text()
        tooltip = controls._rpc_result_label.toolTip()
        expected_body = str(long_result)

        assert text == f"Result: {expected_body}"
        assert tooltip == expected_body, "the full RPC result must be available via tooltip, not truncated"
        assert controls._rpc_result_label.wordWrap() is True
        assert controls._rpc_call_btn.isEnabled() is True
    finally:
        controls.deleteLater()
