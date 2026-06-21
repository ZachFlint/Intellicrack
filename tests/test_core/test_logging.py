# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.logging module - structured logging infrastructure."""

from __future__ import annotations

import json
import logging as stdlib_logging
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, Protocol

import pytest
from structlog.testing import capture_logs

import intellicrack.core.logging as logging_mod
from intellicrack.core.logging import (
    ColoredConsoleRenderer,
    IntellicrackLogger,
    OperationTimer,
    cleanup_old_logs,
    get_logger,
    log_analysis_operation,
    log_binary_operation,
    log_provider_request,
    log_provider_response,
    log_sandbox_operation,
    log_session_operation,
    log_tool_call,
)


class _LoggerStateProtocol(Protocol):
    """Protocol describing the public interface of ``_LoggerState``."""

    app_logger: IntellicrackLogger | None
    configured_log_dir: Path | None


_logger_state: _LoggerStateProtocol = getattr(logging_mod, "_logger_state")


_SanitizeFn = Callable[[dict[str, object]], dict[str, str]]
_SANITIZE_FN_ATTR: Final[str] = "_sanitize_arguments"
sanitize_arguments: _SanitizeFn = getattr(logging_mod, _SANITIZE_FN_ATTR)


_RETENTION_DAYS: Final[int] = 7
_OLD_AGE_DAYS: Final[int] = 10
_SECONDS_PER_DAY: Final[int] = 86400
_SHORT_STRING_LEN: Final[int] = 50
_LONG_STRING_LEN: Final[int] = 300
_SMALL_LIST_LEN: Final[int] = 5
_LARGE_LIST_LEN: Final[int] = 15
_SMALL_DICT_LEN: Final[int] = 3
_LARGE_DICT_LEN: Final[int] = 15
_SMALL_TUPLE_LEN: Final[int] = 3
_LARGE_TUPLE_LEN: Final[int] = 15
_TRUNCATE_THRESHOLD: Final[int] = 10
_BYTES_LEN: Final[int] = 100
_DURATION_MS: Final[float] = 42.5
_MESSAGES_COUNT: Final[int] = 3
_TOOLS_COUNT: Final[int] = 5
_TOOL_CALLS_COUNT: Final[int] = 2
_TOKENS_USED: Final[int] = 1500
_TIMER_SLEEP: Final[float] = 0.01
_UNROUNDED_DURATION_MS: Final[float] = 42.567
_ROUNDED_DURATION_MS: Final[float] = 42.57
_LOG_FILENAME: Final[str] = "intellicrack.log"


def _read_json_log_records(log_file: Path) -> list[dict[str, Any]]:
    """Parse a JSON-rendered Intellicrack log file into structured records.

    Reads the rotated log file written by :meth:`IntellicrackLogger.configure`
    with ``json_file=True`` and decodes each newline-delimited JSON object. This
    provides an independent oracle: the assertions read back exactly what the
    production logging pipeline serialised to disk rather than trusting the
    in-memory call.

    Args:
        log_file: Path to the JSON-rendered log file on disk.

    Returns:
        list[dict[str, Any]]: One decoded record per emitted log line, in
            emission order.
    """
    raw = log_file.read_text(encoding="utf-8")
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped:
            decoded: dict[str, Any] = json.loads(stripped)
            records.append(decoded)
    return records


_DEFAULT_TIMESTAMP: Final[str] = "2026-03-07 12:00:00"
_DEFAULT_EVENT: Final[str] = "test_event"
_DEFAULT_LOCATION: Final[str] = "test_module:test_func:42"
_RESET: Final[str] = "\033[0m"
_LEVEL_FIELD_WIDTH: Final[int] = 8


def _make_event_dict(**overrides: object) -> dict[str, Any]:
    """Create a base event dict for renderer tests.

    Args:
        **overrides: Key-value overrides for the event dict.

    Returns:
        dict[str, Any]: Event dictionary with defaults merged with overrides.
    """
    base: dict[str, Any] = {
        "timestamp": _DEFAULT_TIMESTAMP,
        "level": "info",
        "logger": "test",
        "event": _DEFAULT_EVENT,
        "module": "test_module",
        "function": "test_func",
        "line_number": "42",
    } | overrides
    return base


def _expected_render(
    level_label: str,
    color: str,
    *,
    timestamp: str = _DEFAULT_TIMESTAMP,
    location: str = _DEFAULT_LOCATION,
    event: str = _DEFAULT_EVENT,
    context: str = "",
) -> str:
    """Build the exact renderer output string from an independent format spec.

    This mirrors the documented format
    ``"{timestamp} | {color}{LEVEL.ljust(8)}{reset} | {location} | {event}{context}"``
    without invoking any production rendering code, so it acts as a trusted
    oracle for full-string equality assertions.

    Args:
        level_label: Upper-cased level name (e.g. ``"INFO"``) before padding.
        color: ANSI color escape sequence prefixing the padded level, or an
            empty string when the level is unknown.
        timestamp: Timestamp text expected at the start of the line.
        location: ``module:func:line`` (or fallback) location segment.
        event: Event name segment.
        context: Trailing bracketed extra-context segment, including its leading
            space and surrounding brackets, or an empty string when absent.

    Returns:
        str: The complete expected rendered line.
    """
    padded_level = level_label.ljust(_LEVEL_FIELD_WIDTH)
    return f"{timestamp} | {color}{padded_level}{_RESET} | {location} | {event}{context}"


# --- ColoredConsoleRenderer ---


def test_renderer_info_level() -> None:
    """Verify renderer renders the full info line with the green color code.

    Asserts the complete formatted string (timestamp, green-coloured padded
    ``INFO`` label, reset code, location, event) against an independently
    constructed oracle, so any structural regression - wrong colour, wrong
    padding, missing reset, reordered fields - fails the test.
    """
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="info"))
    assert result == _expected_render("INFO", "\033[32m")


def test_renderer_debug_level() -> None:
    """Verify renderer renders the full debug line with the cyan color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="debug"))
    assert result == _expected_render("DEBUG", "\033[36m")


def test_renderer_warning_level() -> None:
    """Verify renderer renders the full warning line with the yellow color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="warning"))
    assert result == _expected_render("WARNING", "\033[33m")


def test_renderer_error_level() -> None:
    """Verify renderer renders the full error line with the red color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="error"))
    assert result == _expected_render("ERROR", "\033[31m")


def test_renderer_critical_level() -> None:
    """Verify renderer renders the full critical line with the magenta color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="critical"))
    assert result == _expected_render("CRITICAL", "\033[35m")


def test_renderer_level_codes_are_distinct_per_level() -> None:
    """Verify each level renders with its own distinct ANSI color, not a shared one.

    Guards against a regression where one level's colour code leaks into
    another. Builds every level's full expected line with the documented
    colour and asserts equality, and confirms the five colour codes are
    mutually distinct.
    """
    renderer = ColoredConsoleRenderer()
    level_colors: dict[str, str] = {
        "debug": "\033[36m",
        "info": "\033[32m",
        "warning": "\033[33m",
        "error": "\033[31m",
        "critical": "\033[35m",
    }
    for level, color in level_colors.items():
        result = renderer(None, "", _make_event_dict(level=level))
        assert result == _expected_render(level.upper(), color)
    assert len(set(level_colors.values())) == len(level_colors)


def test_renderer_unknown_level() -> None:
    """Verify renderer renders an unknown level uppercased with no color codes.

    An unknown level has no entry in ``LEVEL_COLORS`` so the colour prefix must
    be empty while the reset code is still emitted. The full-string oracle
    proves the label is uppercased and padded, no stray ANSI colour sequence
    is injected, and the rest of the line is intact.
    """
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="custom"))
    assert result == _expected_render("CUSTOM", "")
    for color in ColoredConsoleRenderer.LEVEL_COLORS.values():
        assert color not in result


def test_renderer_includes_timestamp() -> None:
    """Verify renderer includes the timestamp in output."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict())
    assert "2026-03-07 12:00:00" in result


def test_renderer_includes_event() -> None:
    """Verify renderer includes the event text in output."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(event="my_event"))
    assert "my_event" in result


def test_renderer_location_with_module_and_line() -> None:
    """Verify renderer formats location as module:func:line."""
    renderer = ColoredConsoleRenderer()
    result = renderer(
        None,
        "",
        _make_event_dict(module="core", function="run", line_number="10"),
    )
    assert "core:run:10" in result


def test_renderer_location_module_no_func() -> None:
    """Verify renderer formats location as module:line when no function."""
    renderer = ColoredConsoleRenderer()
    result = renderer(
        None,
        "",
        _make_event_dict(module="core", function="", line_number="10"),
    )
    assert "core:10" in result


def test_renderer_location_fallback_to_logger() -> None:
    """Verify renderer falls back to logger name when no module."""
    renderer = ColoredConsoleRenderer()
    result = renderer(
        None,
        "",
        _make_event_dict(module="", line_number="", logger="my.logger"),
    )
    assert "my.logger" in result


def test_renderer_extra_context_single_field() -> None:
    """Verify a single extra field renders as a trailing bracketed key=repr segment.

    Asserts the full line equals the oracle whose context segment is
    ``" [extra_key='extra_value']"`` - the leading space, brackets, ``key=``
    delimiter and ``repr`` of the value are all checked, not mere substring
    presence.
    """
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(extra_key="extra_value"))
    assert result == _expected_render("INFO", "\033[32m", context=" [extra_key='extra_value']")


def test_renderer_extra_context_multiple_fields_sorted() -> None:
    """Verify multiple extra fields render sorted, comma-joined, inside one bracket.

    The renderer sorts keys and joins with ``", "``. Passing keys out of order
    and asserting the exact sorted, ``repr``-formatted segment proves ordering,
    the separator, value reprs (int kept bare, str quoted) and single
    enclosing bracket pair.
    """
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(zeta="last", alpha=1))
    assert result == _expected_render("INFO", "\033[32m", context=" [alpha=1, zeta='last']")


def test_renderer_no_extra_context() -> None:
    """Verify renderer emits no bracketed segment when there are no extra fields.

    The full line must equal the oracle with an empty context segment, so the
    output ends exactly at the event name with no trailing space, bracket, or
    delimiter.
    """
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict())
    assert result == _expected_render("INFO", "\033[32m")
    event_segment = result.rsplit(" | ", 1)[-1]
    assert event_segment == _DEFAULT_EVENT
    assert "[" not in event_segment


def test_renderer_skips_underscore_keys() -> None:
    """Verify renderer ignores keys starting with underscore."""
    renderer = ColoredConsoleRenderer()
    result = renderer(
        None,
        "",
        _make_event_dict(_internal="hidden"),
    )
    assert "_internal" not in result


# --- cleanup_old_logs ---


def test_cleanup_nonexistent_directory() -> None:
    """Verify cleanup returns 0 for non-existent directory."""
    result = cleanup_old_logs(Path("/nonexistent/path/xyz"), _RETENTION_DAYS)
    assert result == 0


def test_cleanup_empty_directory(tmp_path: Path) -> None:
    """Verify cleanup returns 0 for empty directory.

    Args:
        tmp_path: Pytest temporary directory.
    """
    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 0


def test_cleanup_retains_recent_files(tmp_path: Path) -> None:
    """Verify cleanup keeps files newer than retention period.

    Args:
        tmp_path: Pytest temporary directory.
    """
    recent_file = tmp_path / "recent.log"
    recent_file.write_text("recent log data")
    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 0
    assert recent_file.exists()


def test_cleanup_deletes_old_files(tmp_path: Path) -> None:
    """Verify cleanup deletes files older than retention period.

    Args:
        tmp_path: Pytest temporary directory.
    """
    old_file = tmp_path / "old.log"
    old_file.write_text("old log data")
    old_mtime = time.time() - (_OLD_AGE_DAYS * _SECONDS_PER_DAY)
    os.utime(old_file, (old_mtime, old_mtime))
    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 1
    assert not old_file.exists()


def test_cleanup_mixed_old_and_new(tmp_path: Path) -> None:
    """Verify cleanup deletes only old files, keeps new ones.

    Args:
        tmp_path: Pytest temporary directory.
    """
    old_file = tmp_path / "old.log"
    old_file.write_text("old")
    old_mtime = time.time() - (_OLD_AGE_DAYS * _SECONDS_PER_DAY)
    os.utime(old_file, (old_mtime, old_mtime))

    new_file = tmp_path / "new.log"
    new_file.write_text("new")

    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 1
    assert not old_file.exists()
    assert new_file.exists()


def test_cleanup_ignores_non_log_files(tmp_path: Path) -> None:
    """Verify cleanup only targets .log* files.

    Args:
        tmp_path: Pytest temporary directory.
    """
    txt_file = tmp_path / "data.txt"
    txt_file.write_text("not a log")
    old_mtime = time.time() - (_OLD_AGE_DAYS * _SECONDS_PER_DAY)
    os.utime(txt_file, (old_mtime, old_mtime))
    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 0
    assert txt_file.exists()


def test_cleanup_handles_rotated_logs(tmp_path: Path) -> None:
    """Verify cleanup deletes old rotated log files (.log.1, .log.2).

    Args:
        tmp_path: Pytest temporary directory.
    """
    rotated = tmp_path / "app.log.1"
    rotated.write_text("rotated")
    old_mtime = time.time() - (_OLD_AGE_DAYS * _SECONDS_PER_DAY)
    os.utime(rotated, (old_mtime, old_mtime))
    result = cleanup_old_logs(tmp_path, _RETENTION_DAYS)
    assert result == 1


# --- _sanitize_arguments ---


def test_sanitize_bytes_value() -> None:
    """Verify bytes values are replaced with length indicator."""
    result = sanitize_arguments({"data": b"\x00" * _BYTES_LEN})
    assert result["data"] == f"<bytes len={_BYTES_LEN}>"


def test_sanitize_short_string() -> None:
    """Verify short strings are kept as repr."""
    result = sanitize_arguments({"msg": "hello"})
    assert result["msg"] == "'hello'"


def test_sanitize_long_string() -> None:
    """Verify long strings are truncated with char count."""
    long_str = "x" * _LONG_STRING_LEN
    result = sanitize_arguments({"msg": long_str})
    assert "chars)" in result["msg"]
    assert "..." in result["msg"]


def test_sanitize_small_list() -> None:
    """Verify small lists are kept as repr."""
    small_list = list(range(_SMALL_LIST_LEN))
    result = sanitize_arguments({"items": small_list})
    assert result["items"] == repr(small_list)


def test_sanitize_large_list() -> None:
    """Verify large lists are replaced with length indicator."""
    large_list = list(range(_LARGE_LIST_LEN))
    result = sanitize_arguments({"items": large_list})
    assert result["items"] == f"<list len={_LARGE_LIST_LEN}>"


def test_sanitize_small_tuple() -> None:
    """Verify small tuples are kept as repr."""
    small_tuple = tuple(range(_SMALL_TUPLE_LEN))
    result = sanitize_arguments({"items": small_tuple})
    assert result["items"] == repr(small_tuple)


def test_sanitize_large_tuple() -> None:
    """Verify large tuples are replaced with length indicator."""
    large_tuple = tuple(range(_LARGE_TUPLE_LEN))
    result = sanitize_arguments({"items": large_tuple})
    assert result["items"] == f"<tuple len={_LARGE_TUPLE_LEN}>"


def test_sanitize_small_dict() -> None:
    """Verify small dicts are kept as repr."""
    small_dict = {f"k{i}": i for i in range(_SMALL_DICT_LEN)}
    result = sanitize_arguments({"data": small_dict})
    assert result["data"] == repr(small_dict)


def test_sanitize_large_dict() -> None:
    """Verify large dicts are replaced with length indicator."""
    large_dict = {f"k{i}": i for i in range(_LARGE_DICT_LEN)}
    result = sanitize_arguments({"data": large_dict})
    assert result["data"] == f"<dict len={_LARGE_DICT_LEN}>"


def test_sanitize_int_value() -> None:
    """Verify int values are kept as repr."""
    result = sanitize_arguments({"count": 42})
    assert result["count"] == "42"


def test_sanitize_none_value() -> None:
    """Verify None values are kept as repr."""
    result = sanitize_arguments({"val": None})
    assert result["val"] == "None"


def test_sanitize_empty_dict() -> None:
    """Verify empty arguments returns empty dict."""
    result = sanitize_arguments({})
    assert result == {}


# --- IntellicrackLogger ---


def test_intellicrack_logger_default_name() -> None:
    """Verify IntellicrackLogger default name is 'intellicrack'."""
    logger = IntellicrackLogger()
    assert logger.name == "intellicrack"


def test_intellicrack_logger_custom_name() -> None:
    """Verify IntellicrackLogger accepts custom name."""
    logger = IntellicrackLogger("custom")
    assert logger.name == "custom"


def test_intellicrack_logger_get_logger_root(tmp_path: Path) -> None:
    """Verify get_logger() binds the instance name as the emitted logger name.

    Configures real JSON file routing, emits through the root logger of an
    ``IntellicrackLogger("test_root")`` instance, and asserts the persisted
    record carries logger name ``"test_root"`` (the bare instance name with no
    child suffix). The independent oracle is the composition contract
    ``logger_name = self.name`` when ``name is None``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    bound = IntellicrackLogger("test_root").get_logger()
    bound.info("root_routing_probe", marker="root_marker")
    stdlib_logging.shutdown()

    records = _read_json_log_records(tmp_path / _LOG_FILENAME)
    matching = [r for r in records if r.get("event") == "root_routing_probe"]
    assert len(matching) == 1
    assert matching[0]["logger"] == "test_root"
    assert matching[0]["marker"] == "root_marker"


def test_intellicrack_logger_get_logger_child(tmp_path: Path) -> None:
    """Verify get_logger(name) composes the logger name as ``parent.child``.

    Emits through a child logger and asserts the persisted record's logger name
    equals ``"test_parent.child"``. The oracle is the production composition
    rule ``f"{self.name}.{name}"`` - a regression dropping the dotted suffix or
    using the bare instance name would fail.

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    bound = IntellicrackLogger("test_parent").get_logger("child")
    bound.info("child_routing_probe", marker="child_marker")
    stdlib_logging.shutdown()

    records = _read_json_log_records(tmp_path / _LOG_FILENAME)
    matching = [r for r in records if r.get("event") == "child_routing_probe"]
    assert len(matching) == 1
    assert matching[0]["logger"] == "test_parent.child"
    assert matching[0]["marker"] == "child_marker"


def test_intellicrack_logger_configure(tmp_path: Path) -> None:
    """Verify configure routes JSON file output at the configured DEBUG level.

    Configures DEBUG-level JSON file logging, emits both a DEBUG and an INFO
    event, then asserts the persisted file contains both as decodable JSON with
    their exact event names and injected-but-transformed structured fields. The
    oracle is the JSON serialisation contract: a regression that failed to add
    the file handler, mis-set the level so DEBUG was dropped, or skipped the
    JSON renderer would fail because the file would be missing the record.

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        max_file_size_mb=1,
        backup_count=1,
        retention_days=1,
        json_file=True,
    )
    bound = get_logger("configure_probe")
    bound.debug("configure_debug_event", marker="dbg", count=2)
    bound.info("configure_info_event", marker="inf")
    stdlib_logging.shutdown()

    log_file = tmp_path / _LOG_FILENAME
    assert log_file.exists()
    records = _read_json_log_records(log_file)
    by_event = {r["event"]: r for r in records}
    assert "configure_debug_event" in by_event
    assert "configure_info_event" in by_event
    assert by_event["configure_debug_event"]["level"] == "debug"
    assert by_event["configure_debug_event"]["count"] == 2
    assert by_event["configure_info_event"]["level"] == "info"


def test_intellicrack_logger_configure_no_file(tmp_path: Path) -> None:
    """Verify configure with file_enabled=False writes no log file.

    Passes a writable directory but disables file logging, emits an event, and
    asserts no log file is created in that directory. The oracle is the
    ``file_enabled and log_dir is not None`` gate in ``_configure_structlog``: a
    regression that always installed the file handler would create the file and
    fail this assertion.

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="INFO",
        log_dir=tmp_path,
        file_enabled=False,
        console_enabled=False,
    )
    get_logger("no_file_probe").info("no_file_event")
    stdlib_logging.shutdown()

    assert not (tmp_path / _LOG_FILENAME).exists()
    assert list(tmp_path.glob("*.log*")) == []


def test_intellicrack_logger_configure_plain_text(tmp_path: Path) -> None:
    """Verify non-JSON configure writes human-readable text, filtered by level.

    Configures WARNING-level plain-text file output, emits a sub-threshold INFO
    event and a WARNING event, then asserts the file is NOT valid JSON (proving
    the dev ``ConsoleRenderer`` ran, not ``JSONRenderer``), that the INFO event
    was filtered out by the WARNING level, and that the WARNING event text is
    present. The independent oracles are the JSON-decode failure and the
    level-threshold contract.

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="WARNING",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=False,
    )
    bound = get_logger("plain_probe")
    bound.info("plain_info_filtered", marker="below_threshold")
    bound.warning("plain_warning_kept", marker="at_threshold")
    stdlib_logging.shutdown()

    log_file = tmp_path / _LOG_FILENAME
    assert log_file.exists()
    text = log_file.read_text(encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        json.loads(text.splitlines()[0])
    assert "plain_info_filtered" not in text
    assert "plain_warning_kept" in text
    assert "at_threshold" in text


# --- get_logger ---


def test_get_logger_returns_bound_logger(tmp_path: Path) -> None:
    """Verify module get_logger(name) emits under the ``intellicrack.name`` namespace.

    Resets the module-level logger state so the fallback naming path runs,
    configures JSON file routing, emits an event, and asserts the persisted
    record carries logger name ``"intellicrack.test_module"``. The oracle is the
    ``f"intellicrack.{name}"`` composition in the production ``get_logger``.

    Args:
        tmp_path: Pytest temporary directory.
    """
    _logger_state.app_logger = None
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    get_logger("test_module").info("module_named_probe", marker="named")
    stdlib_logging.shutdown()

    records = _read_json_log_records(tmp_path / _LOG_FILENAME)
    matching = [r for r in records if r.get("event") == "module_named_probe"]
    assert len(matching) == 1
    assert matching[0]["logger"] == "intellicrack.test_module"
    assert matching[0]["marker"] == "named"


def test_get_logger_no_name(tmp_path: Path) -> None:
    """Verify module get_logger() emits under the bare ``intellicrack`` namespace.

    Resets the module-level logger state, configures JSON file routing, emits a
    nameless-logger event, and asserts the persisted record's logger name is
    exactly ``"intellicrack"`` with no trailing component. The oracle is the
    ``"intellicrack"`` fallback branch taken when ``name`` is falsy.

    Args:
        tmp_path: Pytest temporary directory.
    """
    _logger_state.app_logger = None
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    get_logger().info("module_root_probe", marker="rootless")
    stdlib_logging.shutdown()

    records = _read_json_log_records(tmp_path / _LOG_FILENAME)
    matching = [r for r in records if r.get("event") == "module_root_probe"]
    assert len(matching) == 1
    assert matching[0]["logger"] == "intellicrack"
    assert matching[0]["marker"] == "rootless"


def test_get_logger_with_name(tmp_path: Path) -> None:
    """Verify get_logger routes through a configured app logger instance.

    When ``setup_logging`` has registered an app logger, the module-level
    ``get_logger`` must delegate to it and compose ``f"{instance}.{name}"``.
    This test installs a known app-logger instance, configures file routing,
    emits, and asserts the persisted logger name is ``"app_root.my_module"``.
    The oracle is the delegation branch (``_logger_state.app_logger`` not None).

    Args:
        tmp_path: Pytest temporary directory.
    """
    IntellicrackLogger.configure(
        level="DEBUG",
        log_dir=tmp_path,
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    _logger_state.app_logger = IntellicrackLogger("app_root")
    try:
        get_logger("my_module").info("module_delegated_probe", marker="delegated")
        stdlib_logging.shutdown()
    finally:
        _logger_state.app_logger = None

    records = _read_json_log_records(tmp_path / _LOG_FILENAME)
    matching = [r for r in records if r.get("event") == "module_delegated_probe"]
    assert len(matching) == 1
    assert matching[0]["logger"] == "app_root.my_module"
    assert matching[0]["marker"] == "delegated"


# --- log convenience functions (verify no exceptions) ---


def test_log_tool_call_minimal() -> None:
    """Verify log_tool_call emits tool_call with sanitised arguments only.

    Captures the emitted event and asserts the event name, info level, the
    ``tool``/``function`` fields, the sanitised ``arguments`` mapping (recomputed
    independently via ``repr`` of the short string value), and the absence of the
    optional ``duration_ms``/``success`` fields when they were not supplied.
    """
    with capture_logs() as caps:
        log_tool_call("binary", "load_file", {"path": "/test"})
    matching = [c for c in caps if c.get("event") == "tool_call"]
    assert len(matching) == 1
    record = matching[0]
    assert record["log_level"] == "info"
    assert record["tool"] == "binary"
    assert record["function"] == "load_file"
    assert record["arguments"] == {"path": repr("/test")}
    assert "duration_ms" not in record
    assert "success" not in record


def test_log_tool_call_with_duration_and_success() -> None:
    """Verify log_tool_call emits rounded duration and the success flag.

    Passes an unrounded duration and asserts the emitted ``duration_ms`` equals
    ``round(value, 2)`` recomputed independently, that ``success`` is True, and
    that the event name and core fields are correct.
    """
    with capture_logs() as caps:
        log_tool_call(
            "binary",
            "load_file",
            {"path": "/test"},
            duration_ms=_UNROUNDED_DURATION_MS,
            success=True,
        )
    matching = [c for c in caps if c.get("event") == "tool_call"]
    assert len(matching) == 1
    record = matching[0]
    assert record["duration_ms"] == round(_UNROUNDED_DURATION_MS, 2)
    assert record["duration_ms"] == _ROUNDED_DURATION_MS
    assert record["success"] is True


def test_log_tool_call_with_failure() -> None:
    """Verify log_tool_call emits success=False when the call failed.

    Asserts the emitted record carries ``success`` exactly ``False`` (not a
    truthy or missing value) and an empty sanitised ``arguments`` mapping.
    """
    with capture_logs() as caps:
        log_tool_call("ghidra", "analyze", {}, success=False)
    matching = [c for c in caps if c.get("event") == "tool_call"]
    assert len(matching) == 1
    record = matching[0]
    assert record["success"] is False
    assert record["arguments"] == {}
    assert record["tool"] == "ghidra"


def test_log_provider_request() -> None:
    """Verify log_provider_request emits llm_request_started with all counts.

    Asserts the event name plus the four structured fields (provider, model,
    messages_count, tools_count) equal the supplied values, gating that the
    helper forwards every argument into the structured record.
    """
    with capture_logs() as caps:
        log_provider_request("anthropic", "claude-3", _MESSAGES_COUNT, _TOOLS_COUNT)
    matching = [c for c in caps if c.get("event") == "llm_request_started"]
    assert len(matching) == 1
    record = matching[0]
    assert record["log_level"] == "info"
    assert record["provider"] == "anthropic"
    assert record["model"] == "claude-3"
    assert record["messages_count"] == _MESSAGES_COUNT
    assert record["tools_count"] == _TOOLS_COUNT


def test_log_provider_response_minimal() -> None:
    """Verify log_provider_response omits tokens_used when not supplied.

    Asserts the emitted llm_request_complete record carries the rounded
    duration and the tool-call count but does NOT contain a ``tokens_used``
    field, gating the conditional-inclusion branch.
    """
    with capture_logs() as caps:
        log_provider_response("anthropic", "claude-3", _TOOL_CALLS_COUNT, _UNROUNDED_DURATION_MS)
    matching = [c for c in caps if c.get("event") == "llm_request_complete"]
    assert len(matching) == 1
    record = matching[0]
    assert record["tool_calls_count"] == _TOOL_CALLS_COUNT
    assert record["duration_ms"] == round(_UNROUNDED_DURATION_MS, 2)
    assert "tokens_used" not in record


def test_log_provider_response_with_tokens() -> None:
    """Verify log_provider_response includes tokens_used when supplied.

    Asserts the emitted record carries ``tokens_used`` equal to the supplied
    count and the rounded duration, gating the documented token path.
    """
    with capture_logs() as caps:
        log_provider_response(
            "openai",
            "gpt-4",
            _TOOL_CALLS_COUNT,
            _UNROUNDED_DURATION_MS,
            tokens_used=_TOKENS_USED,
        )
    matching = [c for c in caps if c.get("event") == "llm_request_complete"]
    assert len(matching) == 1
    record = matching[0]
    assert record["tokens_used"] == _TOKENS_USED
    assert record["duration_ms"] == round(_UNROUNDED_DURATION_MS, 2)
    assert record["provider"] == "openai"


def test_log_binary_operation() -> None:
    """Verify log_binary_operation emits operation, path, and extra context.

    Asserts the event name, the ``operation`` field, the stringified ``path``,
    and the forwarded ``size`` keyword all appear in the emitted record.
    """
    with capture_logs() as caps:
        log_binary_operation("load", "/test/binary.exe", size=1024)
    matching = [c for c in caps if c.get("event") == "binary_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "load"
    assert record["path"] == "/test/binary.exe"
    assert record["size"] == 1024


def test_log_binary_operation_path_object() -> None:
    """Verify log_binary_operation stringifies a Path argument.

    Passes a :class:`pathlib.Path` and asserts the emitted ``path`` field equals
    ``str(path)`` recomputed independently, gating the documented Path-handling
    behaviour rather than merely that the call did not raise.
    """
    target = Path("/test/patched.exe")
    with capture_logs() as caps:
        log_binary_operation("save", target)
    matching = [c for c in caps if c.get("event") == "binary_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "save"
    assert record["path"] == str(target)
    assert isinstance(record["path"], str)


def test_log_sandbox_operation() -> None:
    """Verify log_sandbox_operation emits operation, sandbox_type, and kwargs.

    Asserts the event name and that the operation, sandbox type, and forwarded
    ``timeout`` keyword are recorded with their exact values.
    """
    with capture_logs() as caps:
        log_sandbox_operation("start", "qemu", timeout=300)
    matching = [c for c in caps if c.get("event") == "sandbox_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "start"
    assert record["sandbox_type"] == "qemu"
    assert record["timeout"] == 300


def test_log_session_operation_minimal() -> None:
    """Verify log_session_operation omits session_id when not supplied.

    Asserts the emitted session_operation record carries the operation but does
    NOT contain a ``session_id`` field, gating the ``if session_id`` branch.
    """
    with capture_logs() as caps:
        log_session_operation("create")
    matching = [c for c in caps if c.get("event") == "session_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "create"
    assert "session_id" not in record


def test_log_session_operation_with_id() -> None:
    """Verify log_session_operation includes session_id when supplied.

    Asserts the emitted record carries ``session_id`` equal to the supplied
    identifier alongside the operation, gating the truthy-session-id branch.
    """
    with capture_logs() as caps:
        log_session_operation("load", session_id="abc-123")
    matching = [c for c in caps if c.get("event") == "session_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "load"
    assert record["session_id"] == "abc-123"


def test_log_session_operation_with_kwargs() -> None:
    """Verify log_session_operation forwards extra keyword context.

    Asserts the emitted record carries the operation, the session id, and the
    forwarded ``messages`` keyword, gating that arbitrary context survives.
    """
    with capture_logs() as caps:
        log_session_operation("save", session_id="abc-123", messages=10)
    matching = [c for c in caps if c.get("event") == "session_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "save"
    assert record["session_id"] == "abc-123"
    assert record["messages"] == 10


def test_log_analysis_operation() -> None:
    """Verify log_analysis_operation emits operation, target, and context.

    Asserts the event name plus the operation, target, and forwarded
    ``protection`` keyword are recorded with their exact values.
    """
    with capture_logs() as caps:
        log_analysis_operation("license_check", "/test/app.exe", protection="vmprotect")
    matching = [c for c in caps if c.get("event") == "analysis_operation"]
    assert len(matching) == 1
    record = matching[0]
    assert record["operation"] == "license_check"
    assert record["target"] == "/test/app.exe"
    assert record["protection"] == "vmprotect"


# --- OperationTimer ---


def test_operation_timer_success() -> None:
    """Verify OperationTimer emits operation_complete with a duration on success.

    Captures the emitted events across the timer lifecycle and asserts that on
    normal exit it emits an info-level ``operation_complete`` event naming the
    operation with a non-negative rounded ``duration_ms`` and that NO
    ``operation_failed`` event is emitted. This gates the success branch of
    ``__exit__`` rather than merely echoing the constructor argument.
    """
    with capture_logs() as caps, OperationTimer("test_op"):
        pass
    complete = [c for c in caps if c.get("event") == "operation_complete"]
    failed = [c for c in caps if c.get("event") == "operation_failed"]
    assert len(complete) == 1
    assert failed == []
    record = complete[0]
    assert record["log_level"] == "info"
    assert record["operation"] == "test_op"
    assert isinstance(record["duration_ms"], float)
    assert record["duration_ms"] >= 0.0


def test_operation_timer_with_context() -> None:
    """Verify OperationTimer threads constructor context into the completion log.

    Passes extra context to the timer and asserts the emitted
    ``operation_complete`` record carries that context field, gating that the
    ``**self.context`` expansion reaches the structured log rather than only
    being stored on the instance.
    """
    with capture_logs() as caps, OperationTimer("analysis", logger_name="test", target="app.exe"):
        pass
    complete = [c for c in caps if c.get("event") == "operation_complete"]
    assert len(complete) == 1
    record = complete[0]
    assert record["operation"] == "analysis"
    assert record["target"] == "app.exe"


def test_operation_timer_on_exception() -> None:
    """Verify OperationTimer re-raises and logs operation_failed on exception.

    Asserts the timer re-raises the original ``ValueError`` (the propagation
    gate) AND that ``__exit__`` emitted an error-level ``operation_failed``
    record naming the operation with exception info, while emitting NO
    ``operation_complete`` event. This gates the documented failure-logging
    side effect.

    Raises:
        ValueError: Deliberately raised to test exception handling.
    """
    msg = "test error"
    with capture_logs() as caps, pytest.raises(ValueError, match="test error"), OperationTimer("failing_op"):
        raise ValueError(msg)
    failed = [c for c in caps if c.get("event") == "operation_failed"]
    complete = [c for c in caps if c.get("event") == "operation_complete"]
    assert len(failed) == 1
    assert complete == []
    record = failed[0]
    assert record["log_level"] == "error"
    assert record["operation"] == "failing_op"
    assert "exc_info" in record


def test_operation_timer_measures_time() -> None:
    """Verify OperationTimer records nonzero elapsed time."""
    with OperationTimer("timed_op") as timer:
        time.sleep(_TIMER_SLEEP)
    assert timer.elapsed_ms > 0


# --- LEVEL_COLORS class attribute ---


def test_level_colors_contains_all_levels() -> None:
    """Verify LEVEL_COLORS has entries for all 5 standard levels."""
    colors = ColoredConsoleRenderer.LEVEL_COLORS
    expected = {"debug", "info", "warning", "error", "critical"}
    assert set(colors.keys()) == expected


def test_reset_code() -> None:
    """Verify RESET is the ANSI reset escape code."""
    assert ColoredConsoleRenderer.RESET == "\033[0m"
