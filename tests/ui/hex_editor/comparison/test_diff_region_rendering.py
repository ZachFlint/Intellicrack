# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the Diff panel rendering the keys the engine actually emits.

The engine emits ``offset_a``/``offset_b``, ``diff_type`` and
``length_a``/``length_b`` on each region and reports no ``offset``, ``type``,
``size_a`` or ``size_b``; reading those keys would render every row as
``0x00000000`` / ``unknown`` under a caption that always read ``0 vs 0
bytes``. The engine also reports the byte-identical ``match`` runs it walked,
which must not be listed as differences.

Every expectation here is derived from a live ``diff_bytes`` call rather than
from a hand-written region dict, so the gate fails if either side of the
contract moves: the engine renaming or dropping a key, or the panel reading
the wrong one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QLabel, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.ui.panels.hex_editor.comparison import (
    MATCH_DIFF_TYPE,
    ComparisonMixin,
    diff_region_rows,
    diff_summary,
)


if TYPE_CHECKING:
    from collections.abc import Generator, Sequence
    from pathlib import Path

hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required to produce a real diff result",
)

_RUN: Final[int] = 16
_EDIT: Final[int] = 8
_PERIOD: Final[int] = 64
_TOP_BIT: Final[int] = 0x80
_EDIT_STRIDE: Final[int] = 7
_FIRST_EDIT: Final[int] = 3


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: Qt application instance shared by all tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _DiffHarness(ComparisonMixin, QWidget):
    """Minimal widget exposing the mixin's diff-completion path."""

    def __init__(self) -> None:
        """Wire only the attributes the completion path touches."""
        super().__init__()
        self.document: Any | None = None
        self.file_path: Path | None = None
        self._hex_widget: Any | None = None
        self._diff_results_tree: QTreeWidget | None = QTreeWidget(self)
        self._diff_results_tree.setColumnCount(4)
        self._diff_summary_label: QLabel | None = QLabel(self)
        self._diff_worker: Any | None = None
        self._diff_temp_path: Path | None = None
        self.navigated_to: list[int] = []

    def goto_offset(self, offset: int) -> None:
        """Record a navigation request instead of driving a hex widget.

        Args:
            offset: Target byte offset.
        """
        self.navigated_to.append(offset)

    def render_result(self, result: dict[str, Any]) -> None:
        """Drive the success completion handler exactly as the worker would.

        Args:
            result: Diff result payload to render.
        """
        self._on_diff_finished(result)

    def activate_row(self, index: int) -> None:
        """Double-click a rendered row the way the tree's signal would.

        Args:
            index: Index of the top-level row to activate.
        """
        self._on_diff_item_double_clicked(self.row_item(index), 0)

    def row_count(self) -> int:
        """Return the number of rows currently in the results tree.

        Returns:
            int: Top-level item count.
        """
        tree = self._diff_results_tree
        assert tree is not None
        return tree.topLevelItemCount()

    def row_item(self, index: int) -> QTreeWidgetItem:
        """Return one rendered row.

        Args:
            index: Index of the top-level row.

        Returns:
            QTreeWidgetItem: The row at that index.
        """
        tree = self._diff_results_tree
        assert tree is not None
        item = tree.topLevelItem(index)
        assert item is not None
        return item

    def row_cells(self, index: int) -> tuple[str, str, str, str]:
        """Return the four visible cells of one rendered row.

        Args:
            index: Index of the top-level row.

        Returns:
            tuple[str, str, str, str]: Offset, length, type and details text.
        """
        item = self.row_item(index)
        return item.text(0), item.text(1), item.text(2), item.text(3)

    def summary_text(self) -> str:
        """Return the caption the panel rendered.

        Returns:
            str: Current summary label text.
        """
        label = self._diff_summary_label
        assert label is not None
        return label.text()


def _substitution() -> tuple[bytes, bytes]:
    """Build a pair differing by an in-place run of the same length.

    Returns:
        tuple[bytes, bytes]: The two buffers to compare.
    """
    head = b"\x00" * _RUN
    tail = b"\x00" * _RUN
    return head + b"\xaa" * _EDIT + tail, head + b"\xbb" * _EDIT + tail


def _insertion() -> tuple[bytes, bytes]:
    """Build a pair differing by bytes present only in the second buffer.

    Returns:
        tuple[bytes, bytes]: The two buffers to compare.
    """
    head = b"\x00" * _RUN
    tail = b"\x11" * _RUN
    return head + tail, head + b"\xff" * _EDIT + tail


def _shifted_edit() -> tuple[bytes, bytes]:
    """Build a pair whose later edit sits at a different offset on each side.

    An insertion near the front shifts everything after it, so the trailing
    modified run has ``offset_a != offset_b``.

    Returns:
        tuple[bytes, bytes]: The two buffers to compare.
    """
    head = b"\x00" * _RUN
    middle = b"\x11" * _RUN
    tail = b"\x22" * _RUN
    data_a = head + middle + b"\xaa" * _EDIT + tail
    data_b = head + b"\xff" * _EDIT + middle + b"\xbb" * _EDIT + tail
    return data_a, data_b


def _diff(data_a: bytes, data_b: bytes) -> dict[str, Any]:
    """Run the real engine diff over two buffers.

    Args:
        data_a: First buffer.
        data_b: Second buffer.

    Returns:
        dict[str, Any]: The engine's diff result.
    """
    result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b)
    return result


def _regions(result: dict[str, Any]) -> Sequence[dict[str, Any]]:
    """Extract the regions list from an engine diff result.

    Args:
        result: The engine's diff result.

    Returns:
        Sequence[dict[str, Any]]: The regions the engine reported.
    """
    regions: Sequence[dict[str, Any]] = result["regions"]
    return regions


def test_engine_reports_the_sizes_it_compared() -> None:
    """The engine must report the byte counts it actually diffed."""
    data_a, data_b = _substitution()
    result = _diff(data_a, data_b)
    assert result["size_a"] == len(data_a)
    assert result["size_b"] == len(data_b)


def test_match_regions_are_dropped_from_the_rows() -> None:
    """Byte-identical runs must not be listed as differences."""
    result = _diff(*_substitution())
    regions = _regions(result)
    matches = [r for r in regions if r["diff_type"] == MATCH_DIFF_TYPE]
    assert matches, "engine must report match runs for this input, or the gate proves nothing"

    rows = diff_region_rows(regions)
    assert len(rows) == len(regions) - len(matches)
    assert all(row.diff_type != MATCH_DIFF_TYPE for row in rows)


def test_substitution_row_carries_the_real_offset_and_length() -> None:
    """A same-size edit must render the engine's offset and length, not zeros."""
    result = _diff(*_substitution())
    regions = _regions(result)
    rows = diff_region_rows(regions)
    assert len(rows) == 1

    region = next(r for r in regions if r["diff_type"] != MATCH_DIFF_TYPE)
    row = rows[0]
    assert row.diff_type == region["diff_type"]
    assert row.navigate_offset == region["offset_a"]
    assert row.offset == f"0x{int(region['offset_a']):08X}"
    assert row.length == str(region["length_a"])
    assert row.offset != "0x00000000"
    assert row.length != "0"


def test_insertion_row_shows_both_sides() -> None:
    """A size-changing region must show A's and B's spans, not just one."""
    result = _diff(*_insertion())
    regions = _regions(result)
    rows = diff_region_rows(regions)

    divergent = [
        region for region in regions if region["diff_type"] != MATCH_DIFF_TYPE and int(region["length_a"]) != int(region["length_b"])
    ]
    assert divergent, "insertion must yield a region whose sides differ in length"

    region = divergent[0]
    row = rows[[r for r in regions if r["diff_type"] != MATCH_DIFF_TYPE].index(region)]
    assert row.length == f"{region['length_a']} → {region['length_b']}"
    assert row.length != str(region["length"])
    assert f"A {int(region['offset_a']):#010x}" in row.details
    assert f"B {int(region['offset_b']):#010x}" in row.details


def test_rendered_tree_matches_the_rows(qapp: QApplication) -> None:
    """The tree must contain exactly the differing rows, with their real text.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    harness = _DiffHarness()
    result = _diff(*_substitution())
    rows = diff_region_rows(_regions(result))

    harness.render_result(result)

    assert harness.row_count() == len(rows)
    offset_cell, length_cell, type_cell, details_cell = harness.row_cells(0)
    assert offset_cell == rows[0].offset
    assert length_cell == rows[0].length
    assert type_cell == rows[0].diff_type
    assert details_cell == rows[0].details


def test_summary_reports_the_compared_sizes(qapp: QApplication) -> None:
    """The caption must quote the real file sizes, never ``0 vs 0``.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    harness = _DiffHarness()
    data_a, data_b = _substitution()
    harness.render_result(_diff(data_a, data_b))

    text = harness.summary_text()
    assert f"[{len(data_a)} vs {len(data_b)} bytes]" in text
    assert "0 vs 0 bytes" not in text


def test_double_click_navigates_to_the_regions_offset(qapp: QApplication) -> None:
    """Activating a row must jump to that region's offset in the open document.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    harness = _DiffHarness()
    result = _diff(*_substitution())
    harness.render_result(result)

    region = next(r for r in _regions(result) if r["diff_type"] != MATCH_DIFF_TYPE)
    harness.activate_row(0)

    assert harness.navigated_to == [int(region["offset_a"])]


def test_row_offset_is_stored_as_data_not_reparsed_from_text(qapp: QApplication) -> None:
    """Navigation must read the stored offset, not re-parse the offset cell.

    An earlier insertion shifts the trailing edit, so that row's offset cell
    carries both sides and is not parseable as a single address.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    result = _diff(*_shifted_edit())
    regions = _regions(result)
    rows = diff_region_rows(regions)

    index = next(i for i, row in enumerate(rows) if " / " in row.offset)
    region = [r for r in regions if r["diff_type"] != MATCH_DIFF_TYPE][index]
    assert int(region["offset_a"]) != int(region["offset_b"])

    harness = _DiffHarness()
    harness.render_result(result)

    cell = harness.row_cells(index)[0]
    assert " / " in cell
    with pytest.raises(ValueError, match="invalid literal"):
        int(cell, 16)

    stored = harness.row_item(index).data(0, Qt.ItemDataRole.UserRole)
    assert stored == int(region["offset_a"])

    harness.activate_row(index)
    assert harness.navigated_to == [int(region["offset_a"])]


def _many_edits(count: int) -> tuple[bytes, bytes]:
    """Build a pair differing by ``count`` isolated one-byte substitutions.

    The first buffer repeats the values ``0..63`` and the second sets the top
    bit of every seventh byte from offset 3, so a changed byte equals nothing
    in the first and each edit is the only minimal alignment: ``2 * count + 1``
    regions, ``count`` of them differences.

    Args:
        count: Number of edits.

    Returns:
        tuple[bytes, bytes]: The two buffers to compare.
    """
    source = bytes(index % _PERIOD for index in range(_FIRST_EDIT + _EDIT_STRIDE * count + 4))
    edited = bytearray(source)
    for edit in range(count):
        edited[_FIRST_EDIT + _EDIT_STRIDE * edit] |= _TOP_BIT
    return source, bytes(edited)


def test_summary_says_how_many_of_the_regions_are_shown_when_the_list_was_cut_short(qapp: QApplication) -> None:
    """A capped result must read ``showing N of M regions``, with M from the engine.

    Twenty edits are twenty differing regions. Capping the list at four leaves
    two of them in the tree, and the caption must say two of twenty rather than
    claim the two it can see are all there are.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    data_a, data_b = _many_edits(20)
    result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b, max_regions=4)
    assert result["truncated"] is True
    assert result["change_count"] == 20

    harness = _DiffHarness()
    harness.render_result(result)

    assert harness.row_count() == 2
    text = harness.summary_text()
    assert text.startswith("showing 2 of 20 regions, 20 byte(s) differ")
    assert f"[{len(data_a)} vs {len(data_b)} bytes]" in text


def test_summary_is_unchanged_when_every_difference_is_listed(qapp: QApplication) -> None:
    """An uncapped result keeps the plain count, with no ``showing`` notice.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    data_a, data_b = _many_edits(20)
    result = _diff(data_a, data_b)
    assert result["truncated"] is False

    harness = _DiffHarness()
    harness.render_result(result)

    assert harness.row_count() == 20
    text = harness.summary_text()
    assert text.startswith("20 region(s), 20 byte(s) differ")
    assert "showing" not in text


def test_summary_stays_plain_when_only_matching_regions_were_left_out(qapp: QApplication) -> None:
    """A cap that drops only the trailing ``match`` must not claim differences are missing.

    The result is truncated, but the one difference is in the tree, so there is
    nothing the user could be missing.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    result: dict[str, Any] = hexcore.diff_bytes(b"xAy", b"xBy", max_regions=2)
    assert result["truncated"] is True
    assert (result["region_count"], result["change_count"]) == (3, 1)

    harness = _DiffHarness()
    harness.render_result(result)

    assert harness.row_count() == 1
    text = harness.summary_text()
    assert text.startswith("1 region(s), 1 byte(s) differ")
    assert "showing" not in text


def test_a_cap_of_zero_does_not_read_as_identical(qapp: QApplication) -> None:
    """A result with nothing listed but differences counted is not ``Files are identical``.

    Args:
        qapp: Qt application fixture.
    """
    _ = qapp
    data_a, data_b = _many_edits(3)
    result: dict[str, Any] = hexcore.diff_bytes(data_a, data_b, max_regions=0)

    harness = _DiffHarness()
    harness.render_result(result)

    assert harness.row_count() == 0
    assert harness.summary_text().startswith("showing 0 of 3 regions, 3 byte(s) differ")


def test_summary_line_for_each_kind_of_result() -> None:
    """``diff_summary`` words identical, complete and cut-short results differently."""
    assert diff_summary({"files_identical": True}, 0) == "Files are identical"
    complete = {"total_differences": 5, "size_a": 10, "size_b": 12, "change_count": 2}
    assert diff_summary(complete, 2) == "2 region(s), 5 byte(s) differ  [10 vs 12 bytes]"
    assert diff_summary({**complete, "change_count": 9}, 2) == "showing 2 of 9 regions, 5 byte(s) differ  [10 vs 12 bytes]"
    assert diff_summary({"total_differences": 1, "size_a": 4, "size_b": 4}, 1) == "1 region(s), 1 byte(s) differ  [4 vs 4 bytes]"
