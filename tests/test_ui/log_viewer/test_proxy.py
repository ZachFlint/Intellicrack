# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`LogFilterProxyModel`."""

from __future__ import annotations

import logging
from typing import cast

import pytest
from PyQt6.QtCore import Qt

from intellicrack.ui.log_viewer import (
    LogFilterProxyModel,
    LogRecordDict,
    LogRecordTableModel,
    level_name_to_int,
)


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


def _surviving_records(model: LogRecordTableModel, proxy: LogFilterProxyModel) -> list[LogRecordDict]:
    """Collect all records that pass the proxy filter.

    Args:
        model: The source model.
        proxy: The filter proxy.

    Returns:
        list[LogRecordDict]: Records visible through the proxy, in proxy order.
    """
    results: list[LogRecordDict] = []
    for proxy_row in range(proxy.rowCount()):
        proxy_idx = proxy.index(proxy_row, 0)
        src_idx = proxy.mapToSource(proxy_idx)
        raw = model.data(src_idx, Qt.ItemDataRole.UserRole)
        assert isinstance(raw, dict), f"row {proxy_row}: UserRole must return a dict, got {type(raw)}"
        results.append(cast("LogRecordDict", raw))
    return results


def test_level_name_to_int_known_names() -> None:
    """Verify that every canonical level name maps to its stdlib integer value.

    The ``filterAcceptsRow`` implementation delegates all numeric lookups to
    ``level_name_to_int``.  If this mapping regresses, the filter silently
    applies the wrong threshold for any level name it misidentifies.
    """
    assert level_name_to_int("DEBUG") == logging.DEBUG
    assert level_name_to_int("INFO") == logging.INFO
    assert level_name_to_int("WARNING") == logging.WARNING
    assert level_name_to_int("ERROR") == logging.ERROR
    assert level_name_to_int("CRITICAL") == logging.CRITICAL


def test_level_name_to_int_case_insensitive() -> None:
    """Verify that lower-case level names resolve identically to upper-case.

    The production code calls ``name.upper()`` before lookup, so
    ``level_name_to_int("warning")`` must equal ``logging.WARNING``.
    """
    assert level_name_to_int("debug") == logging.DEBUG
    assert level_name_to_int("info") == logging.INFO
    assert level_name_to_int("warning") == logging.WARNING
    assert level_name_to_int("error") == logging.ERROR
    assert level_name_to_int("critical") == logging.CRITICAL


def test_level_name_to_int_unknown_falls_back_to_info() -> None:
    """Verify that an unrecognised level name returns INFO (20), not 0 or -1.

    The contract is that an unknown name is treated as INFO so malformed
    records are not silently suppressed by a WARNING or higher threshold.
    Unknown levels must NOT map to DEBUG (10) either, which would allow them
    to pass any threshold unchecked.
    """
    fallback: int = level_name_to_int("BOGUS")
    assert fallback == logging.INFO, f"unknown level must fall back to INFO(20), got {fallback}"
    assert fallback != logging.DEBUG, "unknown level must not fall back to DEBUG(10)"
    assert fallback != 0, "unknown level must not return 0"


def test_min_level_filter() -> None:
    """Verify that only the WARNING record survives a WARNING min-level filter.

    Three records are seeded: INFO (intellicrack.core), WARNING
    (intellicrack.orchestrator), and DEBUG (third_party).  After raising
    the threshold to WARNING exactly one row must remain, and that row must
    be the WARNING record -- not an INFO or DEBUG record that happened to
    survive due to a fence-post error in the level comparison.

    Additional boundary checks:
    - INFO is strictly below WARNING and must be hidden (fence-post).
    - ERROR threshold hides all three seeded records (none are ERROR/CRITICAL).
    - DEBUG threshold exposes all three records in insertion order.
    - CRITICAL record added to a WARNING-threshold proxy must pass.
    """
    model, proxy = _build_pair()
    proxy.set_min_level(logging.WARNING)

    assert proxy.rowCount() == 1, "exactly one record (WARNING) must survive a WARNING filter"

    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 1
    surviving = survivors[0]
    assert surviving["level"] == "WARNING", f"surviving record must be WARNING, got {surviving['level']!r}"
    assert surviving["event"] == "warn_event", f"surviving record must be warn_event, got {surviving['event']!r}"
    assert surviving["logger"] == "intellicrack.orchestrator", f"wrong logger: {surviving['logger']!r}"

    proxy.set_min_level(logging.ERROR)
    assert proxy.rowCount() == 0, "no ERROR/CRITICAL records seeded; rowCount must be 0 at ERROR threshold"

    proxy.set_min_level(logging.DEBUG)
    assert proxy.rowCount() == 3, "DEBUG threshold must expose all three seeded records"
    all_survivors = _surviving_records(model, proxy)
    all_events = [r["event"] for r in all_survivors]
    assert "info_event" in all_events, "info_event must be visible at DEBUG threshold"
    assert "warn_event" in all_events, "warn_event must be visible at DEBUG threshold"
    assert "debug_event" in all_events, "debug_event must be visible at DEBUG threshold"

    model.append_record(dict(_record("critical_event", level="CRITICAL", logger="intellicrack.core")))
    model.flush()
    proxy.set_min_level(logging.WARNING)
    warning_plus = _surviving_records(model, proxy)
    warning_plus_events = [r["event"] for r in warning_plus]
    assert "critical_event" in warning_plus_events, "CRITICAL record must pass a WARNING threshold"
    assert "warn_event" in warning_plus_events, "WARNING record must pass a WARNING threshold"
    assert "info_event" not in warning_plus_events, "INFO record must be hidden at WARNING threshold (fence-post)"
    assert "debug_event" not in warning_plus_events, "DEBUG record must be hidden at WARNING threshold"

    model.append_record(dict(_record("info_boundary", level="INFO", logger="intellicrack.core")))
    model.flush()
    proxy.set_min_level(logging.WARNING)
    boundary_survivors = _surviving_records(model, proxy)
    boundary_events = [r["event"] for r in boundary_survivors]
    assert "info_boundary" not in boundary_events, "INFO (level=20) is strictly below WARNING (level=30) and must be hidden"


def test_logger_regex_filter() -> None:
    """Verify the compiled logger regex filters non-matching rows, and the surviving rows are the correct ones."""
    model, proxy = _build_pair()
    proxy.set_min_level(logging.DEBUG)
    proxy.set_logger_pattern(r"^intellicrack\.")
    assert proxy.rowCount() == 2

    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 2
    surviving_loggers = {r["logger"] for r in survivors}
    assert "third_party" not in surviving_loggers, "third_party logger must be filtered out by ^intellicrack\\."
    assert "intellicrack.core" in surviving_loggers, "intellicrack.core must pass the filter"
    assert "intellicrack.orchestrator" in surviving_loggers, "intellicrack.orchestrator must pass the filter"

    surviving_events = {r["event"] for r in survivors}
    assert "info_event" in surviving_events, "info_event (intellicrack.core) must survive"
    assert "warn_event" in surviving_events, "warn_event (intellicrack.orchestrator) must survive"
    assert "debug_event" not in surviving_events, "debug_event (third_party) must be filtered out"


def test_invalid_regex_falls_back() -> None:
    """Verify a malformed regex silently clears the logger filter."""
    _, proxy = _build_pair()
    proxy.set_min_level(logging.DEBUG)
    proxy.set_logger_pattern(r"[")
    assert not proxy.logger_pattern_source()
    assert proxy.rowCount() == 3


def test_text_search_across_event_and_extras() -> None:
    """Verify text search matches the event id and the extras JSON, and only the correct record survives."""
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("hello_world", widget="alpha")))
    model.append_record(dict(_record("goodbye", widget="beta")))
    model.flush()
    proxy.set_min_level(logging.DEBUG)

    proxy.set_text_query("alpha")
    assert proxy.rowCount() == 1
    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 1
    assert survivors[0]["event"] == "hello_world", "alpha is in hello_world extras; goodbye must be excluded"
    assert survivors[0]["extras"].get("widget") == "alpha"

    proxy.set_text_query("goodbye")
    assert proxy.rowCount() == 1
    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 1
    assert survivors[0]["event"] == "goodbye", "goodbye matches the event field; hello_world must be excluded"

    proxy.set_text_query("beta")
    assert proxy.rowCount() == 1
    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 1
    assert survivors[0]["event"] == "goodbye", "beta is in goodbye extras; hello_world must be excluded"
    assert survivors[0]["extras"].get("widget") == "beta"


def test_case_sensitivity_toggle() -> None:
    """Verify case-sensitive search is stricter than the default, and the correct record identity is preserved."""
    model = LogRecordTableModel()
    proxy = LogFilterProxyModel()
    proxy.setSourceModel(model)
    model.append_record(dict(_record("ABC_event")))
    model.flush()
    proxy.set_min_level(logging.DEBUG)

    proxy.set_text_query("abc")
    assert proxy.rowCount() == 1
    survivors_ci = _surviving_records(model, proxy)
    assert survivors_ci[0]["event"] == "ABC_event", "case-insensitive 'abc' must match ABC_event"

    proxy.set_case_sensitive(case_sensitive=True)
    assert proxy.rowCount() == 0, "case-sensitive 'abc' must not match 'ABC_event'"

    proxy.set_text_query("ABC")
    assert proxy.rowCount() == 1
    survivors_cs = _surviving_records(model, proxy)
    assert survivors_cs[0]["event"] == "ABC_event", "case-sensitive 'ABC' must match ABC_event"


def test_combined_filters() -> None:
    """Verify level + regex + text filters compose correctly, and the surviving record has the right identity."""
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

    survivors = _surviving_records(model, proxy)
    assert len(survivors) == 1
    sole = survivors[0]
    assert sole["event"] == "b", f"only record 'b' (WARNING + intellicrack.core + widget=W) must survive; got {sole['event']!r}"
    assert sole["level"] == "WARNING", f"surviving record must be WARNING, got {sole['level']!r}"
    assert sole["logger"] == "intellicrack.core", f"surviving logger must be intellicrack.core, got {sole['logger']!r}"
    assert sole["extras"].get("widget") == "W", "text query matched via extras widget field"
