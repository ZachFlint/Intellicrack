# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Log record data structures and parsers for the Log Viewer.

Provides a normalized :class:`LogRecordDict` representation that bridges
structlog-enriched ``logging.LogRecord`` instances and JSON-Lines disk
records into a single shape consumed by the Qt model layer.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, TypedDict, cast


if TYPE_CHECKING:
    import logging


_RESERVED_LOGRECORD_FIELDS: frozenset[str] = frozenset({
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
    "_record",
    "_from_structlog",
    "message",
    "asctime",
    "color_message",
})


_KNOWN_STRUCTLOG_KEYS: frozenset[str] = frozenset({
    "timestamp",
    "level",
    "logger",
    "event",
    "module",
    "function",
    "line_number",
})


class LogRecordDict(TypedDict):
    """Normalized log record shape consumed by the viewer model.

    Attributes:
        timestamp: Human-readable timestamp string in local time.
        level: Upper-case level name (e.g. ``"INFO"``).
        logger: Dotted logger name.
        module: Source module short name.
        function: Source function name.
        line_number: Source line number, or ``0`` when unknown.
        event: The structured event identifier (the structlog ``event`` key).
        extras: Remaining structured key/value pairs from the event dict.
    """

    timestamp: str
    level: str
    logger: str
    module: str
    function: str
    line_number: int
    event: str
    extras: dict[str, object]


def _coerce_line_number(value: object) -> int:
    """Best-effort conversion of a line-number-like value to ``int``.

    Args:
        value: Value to coerce.

    Returns:
        int: The parsed integer, or ``0`` when conversion fails.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _safe_str(value: object, *, default: str = "") -> str:
    """Coerce a JSON value to a string, returning ``default`` for ``None``.

    Args:
        value: Source value from the parsed JSON payload.
        default: Returned when ``value`` is ``None``.

    Returns:
        str: The string representation of ``value`` or ``default``.
    """
    if value is None:
        return default
    return str(value)


def parse_json_line(line: str) -> LogRecordDict | None:
    """Parse a single JSON-Lines log entry into a :class:`LogRecordDict`.

    Lines that are blank, not valid JSON, or not JSON objects are skipped
    by returning ``None``. Missing fields fall back to safe defaults so
    the viewer never crashes on partially-written or non-structlog lines.

    Args:
        line: A single text line from the log file.

    Returns:
        LogRecordDict | None: The parsed record, or ``None`` when the
            line cannot be parsed as a structured record.
    """
    stripped = line.strip()
    if not stripped:
        return None
    try:
        parsed: object = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    payload = cast("dict[str, object]", parsed)

    return LogRecordDict(
        timestamp=_safe_str(payload.get("timestamp", "")),
        level=_safe_str(payload.get("level", "info"), default="INFO").upper(),
        logger=_safe_str(payload.get("logger", "")),
        module=_safe_str(payload.get("module", "")),
        function=_safe_str(payload.get("function", "")),
        line_number=_coerce_line_number(payload.get("line_number", 0)),
        event=_safe_str(payload.get("event", "")),
        extras={key: value for key, value in payload.items() if key not in _KNOWN_STRUCTLOG_KEYS},
    )


def _structlog_event_dict(record: logging.LogRecord) -> dict[str, object] | None:
    """Return the structlog event dict embedded in the log record, if any.

    Newer structlog (>=24) leaves the original event mapping on
    ``record.msg`` after :meth:`ProcessorFormatter.format` runs. Older
    versions attached it as ``record._record``. This helper returns
    whichever shape is present so the parser tolerates both.

    Args:
        record: The standard logging record.

    Returns:
        dict[str, object] | None: The event mapping when structlog
            populated it, or ``None`` for foreign records.
    """
    msg = record.msg
    if isinstance(msg, dict):
        return cast("dict[str, object]", msg)
    legacy = getattr(record, "_record", None)
    if isinstance(legacy, dict):
        return cast("dict[str, object]", legacy)
    return None


def _extract_event_text(record: logging.LogRecord) -> str:
    """Return the best representation of the event/message for a record.

    Args:
        record: The standard logging record.

    Returns:
        str: The event identifier when structlog enriched the record, or
            the formatted message otherwise.
    """
    event_dict = _structlog_event_dict(record)
    if event_dict is not None:
        event_val = event_dict.get("event")
        if event_val is not None:
            return str(event_val)
    try:
        return record.getMessage()
    except (TypeError, ValueError):
        return str(record.msg)


def _extract_extras(record: logging.LogRecord) -> dict[str, object]:
    """Collect structured extras from a structlog-enriched log record.

    Reads the structlog event dict (see :func:`_structlog_event_dict`)
    when present; otherwise falls back to scanning ``record.__dict__``
    for non-reserved keys so foreign ``logging.LoggerAdapter`` extras
    still surface in the viewer.

    Args:
        record: The standard logging record.

    Returns:
        dict[str, object]: Mapping of extra keys to JSON-friendly values.
    """
    event_dict = _structlog_event_dict(record)
    if event_dict is not None:
        return {key: value for key, value in event_dict.items() if key not in _KNOWN_STRUCTLOG_KEYS}

    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _RESERVED_LOGRECORD_FIELDS and key not in _KNOWN_STRUCTLOG_KEYS
    }


def _structlog_payload(record: logging.LogRecord) -> dict[str, object]:
    """Return the structlog event dict, or an empty dict.

    Args:
        record: The standard logging record.

    Returns:
        dict[str, object]: The structlog event dict if present, else ``{}``.
    """
    event_dict = _structlog_event_dict(record)
    return event_dict if event_dict is not None else {}


def _resolve_timestamp(payload: dict[str, object], record: logging.LogRecord) -> str:
    """Resolve the display timestamp from payload or stdlib record.

    Args:
        payload: structlog payload (may be empty).
        record: The standard logging record.

    Returns:
        str: Display-ready timestamp.
    """
    timestamp_val = payload.get("timestamp")
    if isinstance(timestamp_val, str) and timestamp_val:
        return timestamp_val
    return datetime.fromtimestamp(record.created, tz=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def from_logging_record(record: logging.LogRecord) -> LogRecordDict:
    """Build a :class:`LogRecordDict` from a stdlib log record.

    Reads structlog-enriched attributes (``module``, ``function``,
    ``line_number``, the ``_record`` mapping) when present, and falls
    back to standard ``LogRecord`` fields when not.

    Args:
        record: The standard logging record produced by the structlog
            ``ProcessorFormatter`` pipeline (or a foreign record).

    Returns:
        LogRecordDict: Normalized record consumed by the viewer model.
    """
    payload = _structlog_payload(record)
    level_val = payload.get("level")
    logger_val = payload.get("logger")
    module_val = payload.get("module")
    func_val = payload.get("function")
    line_val = payload.get("line_number")

    return LogRecordDict(
        timestamp=_resolve_timestamp(payload, record),
        level=(
            str(level_val).upper() if isinstance(level_val, str) and level_val else record.levelname
        ).upper(),
        logger=str(logger_val) if isinstance(logger_val, str) and logger_val else record.name,
        module=module_val if isinstance(module_val, str) and module_val else record.module,
        function=func_val if isinstance(func_val, str) and func_val else record.funcName,
        line_number=line_val if isinstance(line_val, int) else record.lineno,
        event=_extract_event_text(record),
        extras=_extract_extras(record),
    )


def _json_default(value: object) -> str:
    """Fall-back JSON serializer for non-encodable values.

    Args:
        value: The value JSON cannot encode natively.

    Returns:
        str: A safe string representation.
    """
    return repr(value)


def record_to_json_text(record: LogRecordDict) -> str:
    """Render a record as a pretty-printed JSON string for the details dialog.

    Args:
        record: Normalized log record.

    Returns:
        str: Indented JSON text safe to display in a monospace viewer.
    """
    return json.dumps(
        dict(record),
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
        default=_json_default,
    )


def extras_to_compact_json(extras: dict[str, object]) -> str:
    """Render extras as a single-line JSON string for table display.

    Args:
        extras: The extras mapping.

    Returns:
        str: Compact JSON text, or an empty string when extras is empty.
    """
    if not extras:
        return ""
    return json.dumps(extras, ensure_ascii=False, default=_json_default, sort_keys=False)
