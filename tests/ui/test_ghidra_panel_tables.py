# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the Ghidra panel result-table layout defects D12/D39/D41.

Covers ``intellicrack.ui.panels.ghidra_panel``:

* D12 -- the Memory Map tab rendered at most ~1 of 8 returned blocks because
  ``self._memory_table`` had no minimum height and no stretch factor in its
  ``QVBoxLayout``, so the surrounding form rows (read/write/create-block/
  remove-split-join/overlay) squeezed it down to a sliver. ``_apply_memory_map``
  itself always looped over every returned block; the residual defect was
  purely layout sizing.
* D39 -- eleven result-display widgets across the panel (the memory hex dump
  view, the comment text input, the namespaces/equates/relocations tables,
  the script output view, the analyzer options input, and the data-type
  result view) were pinned with ``setFixedHeight``, clipping them to a fixed
  handful of pixels regardless of how much content the bridge returned.
* D41 -- ``self._dt_get_addr_input``, ``self._dt_set_addr_input``, and
  ``self._dt_type_input`` had their ``setMaximumWidth`` driven by the
  splitter-ratio constants ``_MAIN_SPLIT_RATIO_RIGHT`` /
  ``_CODE_SPLIT_RATIO_BOTTOM`` (250 / 300), which are fractions of a splitter
  size, not pixel widths for a single-line address/type field.

Every table/text-edit assertion below reads live Qt geometry off a real,
fully constructed ``GhidraPanel`` (no mocked geometry, no stubbed widgets).
"""

from __future__ import annotations

import os


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QPlainTextEdit, QTableWidget

from intellicrack.ui.panels import ghidra_panel as ghidra_panel_module
from intellicrack.ui.panels.ghidra_panel import GhidraPanel


if TYPE_CHECKING:
    from collections.abc import Iterator

_MEMORY_BLOCK_COUNT = 8

# Mirrors the exact dict shape ``GhidraBridge.get_memory_map`` builds from
# ``currentProgram.getMemory().getBlocks()`` (src/intellicrack/bridges/ghidra.py,
# ``get_memory_map``): name/start/end/size/read/write/execute/initialized/volatile
# per block. C1 owns ghidra.py; this fixture is a standalone stand-in so the
# panel test needs no live bridge.
_MEMORY_BLOCKS: list[dict[str, object]] = [
    {
        "name": ".text",
        "start": 0x140001000,
        "end": 0x140010FFF,
        "size": 0x10000,
        "read": True,
        "write": False,
        "execute": True,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".rdata",
        "start": 0x140011000,
        "end": 0x140018FFF,
        "size": 0x8000,
        "read": True,
        "write": False,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".data",
        "start": 0x140019000,
        "end": 0x14001CFFF,
        "size": 0x4000,
        "read": True,
        "write": True,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".pdata",
        "start": 0x14001D000,
        "end": 0x14001DFFF,
        "size": 0x1000,
        "read": True,
        "write": False,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".idata",
        "start": 0x14001E000,
        "end": 0x14001FFFF,
        "size": 0x2000,
        "read": True,
        "write": False,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".rsrc",
        "start": 0x140020000,
        "end": 0x140025FFF,
        "size": 0x6000,
        "read": True,
        "write": False,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".reloc",
        "start": 0x140026000,
        "end": 0x140027FFF,
        "size": 0x2000,
        "read": True,
        "write": False,
        "execute": False,
        "initialized": True,
        "volatile": False,
    },
    {
        "name": ".bss",
        "start": 0x140028000,
        "end": 0x14002FFFF,
        "size": 0x8000,
        "read": True,
        "write": True,
        "execute": False,
        "initialized": False,
        "volatile": False,
    },
]


@pytest.fixture
def panel(qapp: object) -> Iterator[GhidraPanel]:
    """Provide a fully constructed ``GhidraPanel`` and tear it down afterward.

    Args:
        qapp: The session ``QApplication`` fixture (from ``tests/ui/conftest.py``),
            required before any ``QWidget`` can be constructed.

    Yields:
        GhidraPanel: A live panel instance with every tab built.
    """
    del qapp
    instance = GhidraPanel()
    try:
        yield instance
    finally:
        instance.deleteLater()


def _rows_worth_of_height(table: QTableWidget, visible_rows: int) -> int:
    """Compute a conservative lower-bound height for N visible table rows.

    Reads the table's own live Qt geometry (vertical header row size) rather
    than any hardcoded pixel constant, so the bound tracks whatever style is
    active in the test environment.

    Args:
        table: The table widget to measure.
        visible_rows: Number of rows the bound should cover.

    Returns:
        int: A height in pixels that ``visible_rows`` worth of table rows
        must fit under, ignoring header/frame overhead (so it is a strict
        lower bound, not the exact minimum the panel sets).
    """
    v_header = table.verticalHeader()
    row_height = v_header.defaultSectionSize() if v_header is not None else 20
    return row_height * visible_rows


class TestD12MemoryMapTableRendersAllBlocks:
    """D12: the memory map table must show all returned blocks, not ~1 row."""

    @staticmethod
    def test_apply_memory_map_inserts_one_row_per_block(panel: GhidraPanel) -> None:
        """``_apply_memory_map`` must insert exactly one row per returned block.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        panel._apply_memory_map(_MEMORY_BLOCKS)

        assert panel._memory_table.rowCount() == _MEMORY_BLOCK_COUNT, (
            f"expected {_MEMORY_BLOCK_COUNT} memory-map rows (one per returned block), got {panel._memory_table.rowCount()}"
        )

        first_name_item = panel._memory_table.item(0, 0)
        assert first_name_item is not None
        assert first_name_item.text() == ".text"

        last_name_item = panel._memory_table.item(_MEMORY_BLOCK_COUNT - 1, 0)
        assert last_name_item is not None
        assert last_name_item.text() == ".bss"

        last_start_item = panel._memory_table.item(_MEMORY_BLOCK_COUNT - 1, 1)
        assert last_start_item is not None
        assert last_start_item.text() == "0x140028000"

    @staticmethod
    def test_memory_table_can_show_at_least_seven_rows_without_a_fixed_clip(panel: GhidraPanel) -> None:
        """The memory table's minimum height must fit >= 7 rows, and its max height must not be pinned.

        Regression: pre-fix, ``self._memory_table`` had no ``setMinimumHeight``
        and no layout stretch factor, so the surrounding read/write/create-
        block/remove-split-join/overlay form rows in the Memory tab's
        ``QVBoxLayout`` squeezed it to a sliver (its ``minimumHeight()``
        stayed at Qt's unset default of 0). Reverting the fix restores that
        0-height floor, well under the 7-row bound checked here.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        panel._apply_memory_map(_MEMORY_BLOCKS)

        min_seven_rows = _rows_worth_of_height(panel._memory_table, 7)
        assert panel._memory_table.minimumHeight() >= min_seven_rows, (
            f"memory table minimumHeight()={panel._memory_table.minimumHeight()} cannot fit "
            f"7 rows (needs >= {min_seven_rows}); the table is still clipped to a sliver"
        )

        assert panel._memory_table.maximumHeight() >= 1000, (
            f"memory table maximumHeight()={panel._memory_table.maximumHeight()} looks pinned "
            "to a tiny fixed value; it must be free to grow with the splitter"
        )


class TestD39ResultTablesAreNotFixedHeight:
    """D39: result-display tables/text views must not be clipped with setFixedHeight."""

    @staticmethod
    @pytest.mark.parametrize(
        ("attr", "visible_rows"),
        [
            ("_namespaces_table", 4),
            ("_equates_table", 4),
            ("_relocations_table", 4),
        ],
    )
    def test_symbols_tab_secondary_tables_report_a_growable_minimum_height(
        panel: GhidraPanel,
        attr: str,
        visible_rows: int,
    ) -> None:
        """Namespaces/equates/relocations tables must fit >= 4 rows and allow growth.

        Regression: pre-fix, each of these three tables called
        ``setFixedHeight(80)``, which pins both ``minimumHeight()`` and
        ``maximumHeight()`` to exactly 80px -- far below what 4 rows plus a
        header need in any real Qt style, and impossible to grow past.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
            attr: Name of the table attribute under test.
            visible_rows: Minimum number of data rows the table must fit.
        """
        table = getattr(panel, attr)
        assert isinstance(table, QTableWidget)

        min_needed = _rows_worth_of_height(table, visible_rows)
        assert table.minimumHeight() >= min_needed, (
            f"{attr}.minimumHeight()={table.minimumHeight()} cannot fit {visible_rows} rows (needs >= {min_needed})"
        )
        assert table.maximumHeight() >= 1000, f"{attr}.maximumHeight()={table.maximumHeight()} looks pinned to a tiny fixed value"

    @staticmethod
    @pytest.mark.parametrize(
        "attr",
        [
            "_hex_dump_view",
            "_cmt_text_input",
            "_script_output",
            "_analyzer_options_input",
            "_dt_result_view",
        ],
    )
    def test_result_text_views_are_not_pinned_to_a_fixed_height(panel: GhidraPanel, attr: str) -> None:
        """Every former ``setFixedHeight`` text-edit site must allow growth past its minimum.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
            attr: Name of the ``QPlainTextEdit`` attribute under test.
        """
        edit = getattr(panel, attr)
        assert isinstance(edit, QPlainTextEdit)

        assert edit.minimumHeight() > 0, f"{attr}.minimumHeight()=0 -- no minimum-visible-content floor was set"
        assert edit.maximumHeight() >= 1000, (
            f"{attr}.maximumHeight()={edit.maximumHeight()} looks pinned to a tiny fixed value; "
            "a setFixedHeight regression clamps minimum == maximum"
        )
        assert edit.minimumHeight() != edit.maximumHeight(), (
            f"{attr} has minimumHeight() == maximumHeight() == {edit.minimumHeight()}, which is exactly what setFixedHeight produces"
        )

    @staticmethod
    def test_no_setfixedheight_call_remains_in_the_panel_source() -> None:
        """The panel source must contain zero ``setFixedHeight`` call sites.

        A direct source-level gate: however the sizing is implemented, no
        result widget in this file may go back to a hard pixel clip.
        """
        source_path = Path(str(ghidra_panel_module.__file__))
        source_text = source_path.read_text(encoding="utf-8")
        assert "setFixedHeight" not in source_text, "ghidra_panel.py still contains a setFixedHeight(...) call on a result widget"


class TestD41WidthsUseNamedPixelConstantsNotSplitRatios:
    """D41: address/type input max-widths must not reuse splitter-ratio constants as pixels."""

    @staticmethod
    @pytest.mark.parametrize(
        "attr",
        ["_dt_get_addr_input", "_dt_set_addr_input"],
    )
    def test_address_inputs_use_the_address_width_constant(panel: GhidraPanel, attr: str) -> None:
        """The Get/Set Data Type address fields must use ``_ADDRESS_INPUT_MAX_WIDTH``.

        Regression: pre-fix, both fields called
        ``setMaximumWidth(_MAIN_SPLIT_RATIO_RIGHT)`` -- the *right pane's
        splitter-size fraction* (250), not a pixel width chosen for a short
        hex-address field.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
            attr: Name of the address ``QLineEdit`` attribute under test.
        """
        field = getattr(panel, attr)
        assert field.maximumWidth() == ghidra_panel_module._ADDRESS_INPUT_MAX_WIDTH
        assert field.maximumWidth() != ghidra_panel_module._MAIN_SPLIT_RATIO_RIGHT, (
            f"{attr}.maximumWidth() still equals the splitter-ratio constant "
            f"_MAIN_SPLIT_RATIO_RIGHT ({ghidra_panel_module._MAIN_SPLIT_RATIO_RIGHT})"
        )

    @staticmethod
    def test_type_input_uses_the_type_width_constant(panel: GhidraPanel) -> None:
        """The Set Data Type type field must use ``_TYPE_INPUT_MAX_WIDTH``.

        Regression: pre-fix, this field called
        ``setMaximumWidth(_CODE_SPLIT_RATIO_BOTTOM)`` -- the *bottom code-pane
        splitter fraction* (300), not a pixel width chosen for a type string
        like ``byte[16]``.

        Args:
            panel: A live ``GhidraPanel`` fixture instance.
        """
        field = panel._dt_type_input
        assert field.maximumWidth() == ghidra_panel_module._TYPE_INPUT_MAX_WIDTH
        assert field.maximumWidth() != ghidra_panel_module._CODE_SPLIT_RATIO_BOTTOM, (
            f"_dt_type_input.maximumWidth() still equals the splitter-ratio constant "
            f"_CODE_SPLIT_RATIO_BOTTOM ({ghidra_panel_module._CODE_SPLIT_RATIO_BOTTOM})"
        )

    @staticmethod
    def test_split_ratio_constants_are_no_longer_passed_to_set_maximum_width() -> None:
        """Neither split-ratio constant may appear in a ``setMaximumWidth`` call site.

        A direct source-level gate on the specific misuse D41 describes.
        """
        source_path = Path(str(ghidra_panel_module.__file__))
        source_text = source_path.read_text(encoding="utf-8")
        assert "setMaximumWidth(_MAIN_SPLIT_RATIO_RIGHT)" not in source_text
        assert "setMaximumWidth(_CODE_SPLIT_RATIO_BOTTOM)" not in source_text
