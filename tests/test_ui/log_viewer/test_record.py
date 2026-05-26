# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the Log Viewer record parsers and serializers.

Covers :func:`parse_json_line`, :func:`from_logging_record`,
:func:`record_to_json_text`, and :func:`extras_to_compact_json`.
"""

from __future__ import annotations

import json
import logging

import pytest

from intellicrack.ui.log_viewer import LogRecordDict, parse_json_line, record_to_json_text
from intellicrack.ui.log_viewer._record import extras_to_compact_json, from_logging_record


pytestmark = pytest.mark.usefixtures("qapp")


_VALID_LINE: str = json.dumps(
    {
        "timestamp": "2026-05-25 10:00:00",
        "level": "info",
        "logger": "intellicrack.test",
        "module": "test_record",
        "function": "f",
        "line_number": 42,
        "event": "sample_event",
        "widget": "alpha",
        "count": 3,
    },
)


def test_parse_json_line_populates_all_fields() -> None:
    """Verify a fully populated JSON line maps to the expected record dict."""
    record = parse_json_line(_VALID_LINE)
    assert record is not None
    assert record["timestamp"] == "2026-05-25 10:00:00"
    assert record["level"] == "INFO"
    assert record["logger"] == "intellicrack.test"
    assert record["module"] == "test_record"
    assert record["function"] == "f"
    assert record["line_number"] == 42
    assert record["event"] == "sample_event"
    assert record["extras"] == {"widget": "alpha", "count": 3}


def test_parse_json_line_blank_returns_none() -> None:
    """Verify a blank line yields ``None`` so the caller can skip it."""
    assert parse_json_line("") is None
    assert parse_json_line("   \n") is None


def test_parse_json_line_invalid_json_returns_none() -> None:
    """Verify malformed JSON does not raise; it yields ``None``."""
    assert parse_json_line("{not valid json") is None
    assert parse_json_line("garbage") is None


def test_parse_json_line_non_object_returns_none() -> None:
    """Verify non-object JSON payloads (lists, numbers) are rejected."""
    assert parse_json_line("[1, 2, 3]") is None
    assert parse_json_line("42") is None
    assert parse_json_line('"a string"') is None


def test_parse_json_line_missing_fields_use_defaults() -> None:
    """Verify a near-empty JSON object falls back to safe defaults."""
    record = parse_json_line("{}")
    assert record is not None
    assert not record["timestamp"]
    assert record["level"] == "INFO"
    assert not record["logger"]
    assert not record["module"]
    assert not record["function"]
    assert record["line_number"] == 0
    assert not record["event"]
    assert record["extras"] == {}


def test_from_logging_record_foreign_record_uses_stdlib_fields() -> None:
    """Verify a vanilla ``LogRecord`` falls back to stdlib field values."""
    raw = logging.LogRecord(
        name="intellicrack.foreign",
        level=logging.WARNING,
        pathname=__file__,
        lineno=123,
        msg="vanilla %s",
        args=("payload",),
        exc_info=None,
        func="some_func",
    )
    converted = from_logging_record(raw)
    assert converted["level"] == "WARNING"
    assert converted["logger"] == "intellicrack.foreign"
    assert converted["function"] == "some_func"
    assert converted["line_number"] == 123
    assert converted["event"] == "vanilla payload"


def test_from_logging_record_structlog_payload_overrides_stdlib() -> None:
    """Verify an embedded structlog event dict wins over stdlib fields."""
    raw = logging.LogRecord(
        name="intellicrack.std",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg={
            "event": "structlog_event",
            "level": "error",
            "logger": "intellicrack.struct",
            "module": "struct_module",
            "function": "struct_func",
            "line_number": 999,
            "timestamp": "2026-05-25 11:11:11",
            "widget": "beta",
        },
        args=None,
        exc_info=None,
    )
    converted = from_logging_record(raw)
    assert converted["event"] == "structlog_event"
    assert converted["level"] == "ERROR"
    assert converted["logger"] == "intellicrack.struct"
    assert converted["module"] == "struct_module"
    assert converted["function"] == "struct_func"
    assert converted["line_number"] == 999
    assert converted["timestamp"] == "2026-05-25 11:11:11"
    assert converted["extras"] == {"widget": "beta"}


def test_record_to_json_text_pretty_printed() -> None:
    """Verify ``record_to_json_text`` produces indented JSON suitable for display."""
    record = LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level="WARNING",
        logger="intellicrack.test",
        module="m",
        function="f",
        line_number=7,
        event="evt",
        extras={"k": "v"},
    )
    text = record_to_json_text(record)
    assert "\n" in text
    assert '"event": "evt"' in text
    assert '"k": "v"' in text


def test_record_to_json_text_non_serializable_falls_back_to_repr() -> None:
    """Verify non-JSON values are coerced via ``repr`` rather than raising."""

    class _Unserializable:
        def __repr__(self) -> str:
            return "<unserializable-marker>"

    record = LogRecordDict(
        timestamp="2026-05-25 10:00:00",
        level="INFO",
        logger="intellicrack.test",
        module="m",
        function="f",
        line_number=1,
        event="evt",
        extras={"weird": _Unserializable()},
    )
    text = record_to_json_text(record)
    assert "<unserializable-marker>" in text


def test_extras_to_compact_json_empty_returns_empty_string() -> None:
    """Verify an empty extras dict produces the empty string (no JSON literal)."""
    assert not extras_to_compact_json({})


def test_extras_to_compact_json_non_serializable_falls_back_to_repr() -> None:
    """Verify non-JSON values in compact extras are coerced via ``repr``."""

    class _Custom:
        def __repr__(self) -> str:
            return "<custom>"

    text = extras_to_compact_json({"obj": _Custom(), "n": 1})
    assert "<custom>" in text
    assert '"n":1' in text or '"n": 1' in text
