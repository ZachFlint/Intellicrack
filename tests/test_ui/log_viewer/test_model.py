# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`LogRecordTableModel`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtGui import QColor

from intellicrack.ui.log_viewer import LogRecordDict, LogRecordTableModel


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_TWO_RECORDS: int = 2
_RING_CAP: int = 1_000
_PRE_EVICTION_TOTAL: int = 2_500
_PRE_SHRINK_TOTAL: int = 2_000
_SHRINK_TARGET: int = 1_000


def _make(event: str = "evt", level: str = "INFO", **extras: object) -> LogRecordDict:
    """Build a minimal :class:`LogRecordDict` for testing.

    Args:
        event: Event identifier to set on the record.
        level: Log level name.
        **extras: Additional extras to attach.

    Returns:
        LogRecordDict: A populated record dictionary.
    """
    return LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level=level,
        logger="intellicrack.tests",
        module="test_model",
        function="_make",
        line_number=42,
        event=event,
        extras=dict(extras),
    )


def test_append_record_flushes_after_coalesce(qtbot: QtBot) -> None:
    """Verify pending records are inserted after the coalesce delay.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    model = LogRecordTableModel(max_rows=10_000)
    with qtbot.waitSignal(model.rowsInserted, timeout=1_000):
        model.append_record(dict(_make("a")))
        model.append_record(dict(_make("b")))
    assert model.rowCount() == _TWO_RECORDS
    assert model.record_at(0) == _make("a")
    assert model.record_at(1) == _make("b")


def test_flush_inserts_immediately() -> None:
    """Verify :meth:`flush` drains the pending buffer synchronously."""
    model = LogRecordTableModel(max_rows=1_000)
    model.append_record(dict(_make("a")))
    model.append_record(dict(_make("b")))
    model.flush()
    assert model.rowCount() == _TWO_RECORDS


def test_column_data_for_display_role() -> None:
    """Verify column data covers all six visible columns with exact values.

    The Extras column must serialize the record's ``extras`` mapping as a
    single-line JSON object. This drives several extras of distinct JSON
    types (string, int, bool) so the assertion proves correct, lossless,
    round-trippable serialization rather than mere substring presence.
    """
    model = LogRecordTableModel(max_rows=100)
    model.append_record(dict(_make("hello", level="WARNING", widget="x", count=3, active=True)))
    model.flush()

    index = model.index(0, 0)
    assert model.data(index, Qt.ItemDataRole.DisplayRole) == "2026-05-25 10:00:00"
    assert model.data(model.index(0, 1), Qt.ItemDataRole.DisplayRole) == "WARNING"
    assert model.data(model.index(0, 2), Qt.ItemDataRole.DisplayRole) == "intellicrack.tests"
    assert model.data(model.index(0, 3), Qt.ItemDataRole.DisplayRole) == "_make:42"
    assert model.data(model.index(0, 4), Qt.ItemDataRole.DisplayRole) == "hello"

    extras_text = model.data(model.index(0, 5), Qt.ItemDataRole.DisplayRole)
    assert isinstance(extras_text, str)
    parsed = json.loads(extras_text)
    assert parsed == {"widget": "x", "count": 3, "active": True}
    assert isinstance(parsed["count"], int)
    assert parsed["active"] is True
    assert "\n" not in extras_text
    assert "\t" not in extras_text

    raw = model.data(model.index(0, 0), Qt.ItemDataRole.UserRole)
    assert raw == _make("hello", level="WARNING", widget="x", count=3, active=True)


def test_clear_empties_model() -> None:
    """Verify clear resets row count and pending buffer."""
    model = LogRecordTableModel(max_rows=10)
    model.append_record(dict(_make("a")))
    model.flush()
    assert model.rowCount() == 1
    model.clear()
    assert model.rowCount() == 0


def test_ring_buffer_eviction_at_max_rows() -> None:
    """Verify the buffer evicts the oldest record when capacity is hit."""
    model = LogRecordTableModel(max_rows=_RING_CAP)
    model.set_max_rows(_RING_CAP)
    for i in range(_PRE_EVICTION_TOTAL):
        model.append_record(dict(_make(f"e{i}")))
    model.flush()
    assert model.rowCount() == _RING_CAP
    first = model.record_at(0)
    assert first is not None
    assert first["event"] == f"e{_PRE_EVICTION_TOTAL - _RING_CAP}"


def test_set_max_rows_shrink_evicts() -> None:
    """Verify shrinking the row cap drops the oldest rows."""
    model = LogRecordTableModel(max_rows=10_000)
    for i in range(_PRE_SHRINK_TOTAL):
        model.append_record(dict(_make(f"x{i}")))
    model.flush()
    assert model.rowCount() == _PRE_SHRINK_TOTAL
    model.set_max_rows(_SHRINK_TARGET)
    assert model.rowCount() == _SHRINK_TARGET
    first = model.record_at(0)
    assert first is not None
    assert first["event"] == f"x{_PRE_SHRINK_TOTAL - _SHRINK_TARGET}"


def test_foreground_role_per_level() -> None:
    """Verify ForegroundRole returns the level-specific QColor for every level."""
    model = LogRecordTableModel()
    for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        model.append_record(dict(_make(level=level)))
    model.flush()
    expected = {
        "DEBUG": QColor(120, 120, 120),
        "INFO": QColor(220, 220, 220),
        "WARNING": QColor(255, 200, 0),
        "ERROR": QColor(255, 90, 90),
        "CRITICAL": QColor(255, 50, 200),
    }
    for row, level in enumerate(("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")):
        color = model.data(model.index(row, 0), Qt.ItemDataRole.ForegroundRole)
        assert isinstance(color, QColor)
        assert color == expected[level]


def test_background_role_tints_warn_error_critical_only() -> None:
    """Verify BackgroundRole returns the exact tint per severity level.

    DEBUG and INFO must carry no background tint (``None``) so routine
    chatter stays visually flat, while WARNING / ERROR / CRITICAL must
    each return their own distinct, exact QColor. The expected RGB values
    are the published severity palette; a swapped, inverted, or dropped
    mapping is caught here because each color is asserted by value.
    """
    expected_background: dict[str, QColor | None] = {
        "DEBUG": None,
        "INFO": None,
        "WARNING": QColor(60, 48, 16),
        "ERROR": QColor(70, 24, 24),
        "CRITICAL": QColor(70, 16, 56),
    }
    levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

    model = LogRecordTableModel()
    for level in levels:
        model.append_record(dict(_make(level=level)))
    model.flush()

    seen_colors: list[QColor] = []
    for row, level in enumerate(levels):
        background = model.data(model.index(row, 0), Qt.ItemDataRole.BackgroundRole)
        expected = expected_background[level]
        if expected is None:
            assert background is None, f"{level} must have no background tint, got {background!r}"
        else:
            assert isinstance(background, QColor), f"{level} must yield a QColor, got {background!r}"
            assert background == expected, f"{level} background {background.getRgb()} != expected {expected.getRgb()}"
            seen_colors.append(background)

    rgb_triples = {color.getRgb() for color in seen_colors}
    assert len(rgb_triples) == len(seen_colors), "each tinted level must use a distinct color"


def test_header_data_horizontal_returns_titles() -> None:
    """Verify horizontal DisplayRole headerData yields the 6 column titles."""
    model = LogRecordTableModel()
    expected = ("Time", "Level", "Logger", "Function:Line", "Event", "Extras")
    for section, title in enumerate(expected):
        assert model.headerData(section, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole) == title


def test_header_data_non_display_role_returns_none() -> None:
    """Verify non-DisplayRole headerData returns None."""
    model = LogRecordTableModel()
    assert model.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.UserRole) is None


def test_header_data_vertical_returns_none() -> None:
    """Verify vertical headerData returns None (row numbers are hidden)."""
    model = LogRecordTableModel()
    assert model.headerData(0, Qt.Orientation.Vertical, Qt.ItemDataRole.DisplayRole) is None


def test_data_invalid_index_returns_none() -> None:
    """Verify data() with an invalid QModelIndex returns None."""
    model = LogRecordTableModel()
    assert model.data(QModelIndex(), Qt.ItemDataRole.DisplayRole) is None


def test_event_column_flattens_multiline_text() -> None:
    """Verify multi-line event text is collapsed to one line for table display."""
    model = LogRecordTableModel()
    model.append_record(dict(_make("first line\nsecond line\tthird")))
    model.flush()
    text = model.data(model.index(0, 4), Qt.ItemDataRole.DisplayRole)
    assert text == "first line second line third"


def test_location_column_falls_back_to_function_line_or_module() -> None:
    """Verify the Function:Line column degrades gracefully when fields are missing."""
    model = LogRecordTableModel()
    both = _make("with_both")
    func_only = dict(_make("func_only"))
    func_only["line_number"] = 0
    line_only = dict(_make("line_only"))
    line_only["function"] = ""
    neither = dict(_make("neither"))
    neither["function"] = ""
    neither["line_number"] = 0
    neither["module"] = "fallback_module"
    model.append_record(dict(both))
    model.append_record(func_only)
    model.append_record(line_only)
    model.append_record(neither)
    model.flush()
    assert model.data(model.index(0, 3), Qt.ItemDataRole.DisplayRole) == "_make:42"
    assert model.data(model.index(1, 3), Qt.ItemDataRole.DisplayRole) == "_make"
    assert model.data(model.index(2, 3), Qt.ItemDataRole.DisplayRole) == "42"
    assert model.data(model.index(3, 3), Qt.ItemDataRole.DisplayRole) == "fallback_module"
