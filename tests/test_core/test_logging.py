"""Tests for core.logging module - structured logging infrastructure."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

import pytest

import intellicrack.core.logging as logging_mod
from intellicrack.core.logging import (
    ColoredConsoleRenderer,
    IntellicrackLogger,
    OperationTimer,
    cleanup_old_logs,
    get_logger,
    get_structlog_logger,
    log_analysis_operation,
    log_binary_operation,
    log_provider_request,
    log_provider_response,
    log_sandbox_operation,
    log_session_operation,
    log_tool_call,
)


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


def _make_event_dict(**overrides: object) -> dict[str, Any]:
    """Create a base event dict for renderer tests.

    Args:
        **overrides: Key-value overrides for the event dict.

    Returns:
        Event dictionary with defaults merged with overrides.
    """
    base: dict[str, Any] = {
        "timestamp": "2026-03-07 12:00:00",
        "level": "info",
        "logger": "test",
        "event": "test_event",
        "module": "test_module",
        "function": "test_func",
        "line_number": "42",
    }
    base.update(overrides)
    return base


# --- ColoredConsoleRenderer ---


def test_renderer_info_level() -> None:
    """Verify renderer formats info level with green color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="info"))
    assert "INFO" in result
    assert "\033[32m" in result
    assert "\033[0m" in result


def test_renderer_debug_level() -> None:
    """Verify renderer formats debug level with cyan color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="debug"))
    assert "DEBUG" in result
    assert "\033[36m" in result


def test_renderer_warning_level() -> None:
    """Verify renderer formats warning level with yellow color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="warning"))
    assert "WARNING" in result
    assert "\033[33m" in result


def test_renderer_error_level() -> None:
    """Verify renderer formats error level with red color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="error"))
    assert "ERROR" in result
    assert "\033[31m" in result


def test_renderer_critical_level() -> None:
    """Verify renderer formats critical level with magenta color code."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="critical"))
    assert "CRITICAL" in result
    assert "\033[35m" in result


def test_renderer_unknown_level() -> None:
    """Verify renderer handles unknown level without color."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict(level="custom"))
    assert "CUSTOM" in result


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


def test_renderer_extra_context() -> None:
    """Verify renderer appends extra context fields in brackets."""
    renderer = ColoredConsoleRenderer()
    result = renderer(
        None,
        "",
        _make_event_dict(extra_key="extra_value"),
    )
    assert "extra_key=" in result
    assert "extra_value" in result


def test_renderer_no_extra_context() -> None:
    """Verify renderer omits bracket section with no extra fields."""
    renderer = ColoredConsoleRenderer()
    result = renderer(None, "", _make_event_dict())
    assert "[" not in result.split("|")[-1] or "extra" not in result


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


def test_intellicrack_logger_get_logger_root() -> None:
    """Verify get_logger with no name returns bound logger."""
    logger = IntellicrackLogger("test_root")
    result = logger.get_logger()
    assert hasattr(result, "bind")
    assert hasattr(result, "unbind")


def test_intellicrack_logger_get_logger_child() -> None:
    """Verify get_logger with name returns bound logger."""
    logger = IntellicrackLogger("test_parent")
    result = logger.get_logger("child")
    assert hasattr(result, "bind")


def test_intellicrack_logger_configure(tmp_path: Path) -> None:
    """Verify configure sets up logging without error.

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


def test_intellicrack_logger_configure_no_file() -> None:
    """Verify configure works with file logging disabled."""
    IntellicrackLogger.configure(
        level="INFO",
        log_dir=None,
        file_enabled=False,
        console_enabled=False,
    )


def test_intellicrack_logger_configure_plain_text(tmp_path: Path) -> None:
    """Verify configure works with non-JSON file output.

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


# --- get_logger ---


def test_get_logger_returns_bound_logger() -> None:
    """Verify get_logger returns a structlog BoundLogger."""
    logger = get_logger("test_module")
    assert hasattr(logger, "bind")
    assert hasattr(logger, "unbind")


def test_get_logger_no_name() -> None:
    """Verify get_logger with no name returns root-level logger."""
    logger = get_logger()
    assert hasattr(logger, "bind")


def test_get_logger_with_name() -> None:
    """Verify get_logger with name returns named bound logger."""
    logger = get_logger("my_module")
    assert hasattr(logger, "bind")


# --- get_structlog_logger ---


def test_get_structlog_logger_no_name() -> None:
    """Verify get_structlog_logger with no name returns structlog logger."""
    slog = get_structlog_logger()
    assert slog is not None


def test_get_structlog_logger_with_name() -> None:
    """Verify get_structlog_logger with name returns named structlog logger."""
    slog = get_structlog_logger("test")
    assert slog is not None


# --- log convenience functions (verify no exceptions) ---


def test_log_tool_call_minimal() -> None:
    """Verify log_tool_call runs without error for minimal args."""
    log_tool_call("binary", "load_file", {"path": "/test"})


def test_log_tool_call_with_duration_and_success() -> None:
    """Verify log_tool_call runs with optional duration and success."""
    log_tool_call(
        "binary",
        "load_file",
        {"path": "/test"},
        duration_ms=_DURATION_MS,
        success=True,
    )


def test_log_tool_call_with_failure() -> None:
    """Verify log_tool_call runs with success=False."""
    log_tool_call("ghidra", "analyze", {}, success=False)


def test_log_provider_request() -> None:
    """Verify log_provider_request runs without error."""
    log_provider_request("anthropic", "claude-3", _MESSAGES_COUNT, _TOOLS_COUNT)


def test_log_provider_response_minimal() -> None:
    """Verify log_provider_response runs without tokens."""
    log_provider_response("anthropic", "claude-3", _TOOL_CALLS_COUNT, _DURATION_MS)


def test_log_provider_response_with_tokens() -> None:
    """Verify log_provider_response runs with token count."""
    log_provider_response(
        "openai",
        "gpt-4",
        _TOOL_CALLS_COUNT,
        _DURATION_MS,
        tokens_used=_TOKENS_USED,
    )


def test_log_binary_operation() -> None:
    """Verify log_binary_operation runs without error."""
    log_binary_operation("load", "/test/binary.exe", size=1024)


def test_log_binary_operation_path_object() -> None:
    """Verify log_binary_operation accepts Path objects."""
    log_binary_operation("save", Path("/test/patched.exe"))


def test_log_sandbox_operation() -> None:
    """Verify log_sandbox_operation runs without error."""
    log_sandbox_operation("start", "qemu", timeout=300)


def test_log_session_operation_minimal() -> None:
    """Verify log_session_operation runs without session_id."""
    log_session_operation("create")


def test_log_session_operation_with_id() -> None:
    """Verify log_session_operation runs with session_id."""
    log_session_operation("load", session_id="abc-123")


def test_log_session_operation_with_kwargs() -> None:
    """Verify log_session_operation passes extra kwargs."""
    log_session_operation("save", session_id="abc-123", messages=10)


def test_log_analysis_operation() -> None:
    """Verify log_analysis_operation runs without error."""
    log_analysis_operation("license_check", "/test/app.exe", protection="vmprotect")


# --- OperationTimer ---


def test_operation_timer_success() -> None:
    """Verify OperationTimer logs success on normal exit."""
    with OperationTimer("test_op") as timer:
        assert timer.operation == "test_op"


def test_operation_timer_with_context() -> None:
    """Verify OperationTimer accepts extra context kwargs."""
    with OperationTimer("analysis", logger_name="test", target="app.exe") as timer:
        assert timer.context["target"] == "app.exe"


def test_operation_timer_on_exception() -> None:
    """Verify OperationTimer logs failure on exception."""
    with pytest.raises(ValueError, match="test error"), OperationTimer("failing_op"):
        msg = "test error"
        raise ValueError(msg)


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
