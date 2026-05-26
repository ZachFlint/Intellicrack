# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`LogFilterProxyModel`."""

from __future__ import annotations

import logging

import pytest

from intellicrack.ui.log_viewer import LogFilterProxyModel, LogRecordDict, LogRecordTableModel


pytestmark = pytest.mark.usefixtures("qapp")


def _record(event: str, level: str = "INFO", logger: str = "intellicrack.core", **extras: object) -> LogRecordDict:
    """Build a :class:`LogRecordDict` for proxy tests.

    Args:
        event: Event name.
        level: Log level.
        logger: Logger name.
        **extras: Extras dict entries.

    Returns:
        LogRecordDict: A populated record.
    """
    return LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level=level,
        logger=logger,
        module="m",
        function="f",
        line_number=1,
        event=event,
        extras=dict(extras),
    )


def _build_pair() -> tuple[LogRecordTableModel, LogFilterProxyModel]:
    """Construct a model + proxy pair with three seeded records.

    Returns:
        tuple[LogRecordTableModel, LogFilterProxyModel]: model, proxy.
    """
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("info_event")))
    model.append_record(dict(_record("warn_event", level="WARNING", logger="intellicrack.orchestrator")))
    model.append_record(dict(_record("debug_event", level="DEBUG", logger="third_party")))
    model.flush()
    return model, proxy


def test_min_level_filter() -> None:
    """Verify records below the min level are hidden."""
    _, proxy = _build_pair()
    proxy.set_min_level(logging.WARNING)
    assert proxy.rowCount() == 1


def test_logger_regex_filter() -> None:
    """Verify the compiled logger regex filters non-matching rows."""
    _, proxy = _build_pair()
    proxy.set_min_level(logging.DEBUG)
    proxy.set_logger_pattern(r"^intellicrack\.")
    assert proxy.rowCount() == 2


def test_invalid_regex_falls_back() -> None:
    """Verify a malformed regex silently clears the logger filter."""
    _, proxy = _build_pair()
    proxy.set_min_level(logging.DEBUG)
    proxy.set_logger_pattern(r"[")
    assert not proxy.logger_pattern_source()
    assert proxy.rowCount() == 3


def test_text_search_across_event_and_extras() -> None:
    """Verify text search matches the event id and the extras JSON."""
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("hello_world", widget="alpha")))
    model.append_record(dict(_record("goodbye", widget="beta")))
    model.flush()
    proxy.set_min_level(logging.DEBUG)

    proxy.set_text_query("alpha")
    assert proxy.rowCount() == 1

    proxy.set_text_query("goodbye")
    assert proxy.rowCount() == 1


def test_case_sensitivity_toggle() -> None:
    """Verify case-sensitive search is stricter than the default."""
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("ABC_event")))
    model.flush()
    proxy.set_min_level(logging.DEBUG)
    proxy.set_text_query("abc")
    assert proxy.rowCount() == 1
    proxy.set_case_sensitive(case_sensitive=True)
    assert proxy.rowCount() == 0
    proxy.set_text_query("ABC")
    assert proxy.rowCount() == 1


def test_combined_filters() -> None:
    """Verify level + regex + text filters compose correctly."""
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("a", level="INFO", logger="intellicrack.core", widget="W")))
    model.append_record(dict(_record("b", level="WARNING", logger="intellicrack.core", widget="W")))
    model.append_record(dict(_record("c", level="WARNING", logger="third_party", widget="W")))
    model.flush()
    proxy.set_min_level(logging.WARNING)
    proxy.set_logger_pattern(r"^intellicrack\.")
    proxy.set_text_query("W")
    assert proxy.rowCount() == 1
