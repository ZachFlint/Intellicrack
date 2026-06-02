# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the shared streaming JSON parse-skip helper on LLMProviderBase.

The tests exercise :meth:`LLMProviderBase._safe_parse_stream_json` against
real ``structlog`` loggers (no mocks) and assert the behaviour every
provider depends on: parsing succeeds for valid JSON objects, malformed
lines and empty lines are skipped without raising, JSON values that decode
to non-objects (numbers, lists, bare strings, null, booleans) are also
skipped, and warnings carry the expected event name.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Any, cast

import structlog

from intellicrack.providers.base import LLMProviderBase


_PARSE_ATTR = "_safe_parse_stream_json"
_DEFAULT_EVENT = "stream_json_parse_skipped"
_safe_parse_stream_json: Any = getattr(LLMProviderBase, _PARSE_ATTR)


def _make_capture_logger(stream: io.StringIO) -> structlog.stdlib.BoundLogger:
    """Build a real structlog BoundLogger that writes JSON to ``stream``.

    The returned logger has its own isolated stdlib handler so test
    assertions can read the rendered events without touching the
    application's global logging configuration.

    Args:
        stream: In-memory text buffer that receives one JSON event per
            log call.

    Returns:
        structlog.stdlib.BoundLogger: A bound logger emitting JSON events
        into ``stream``.
    """
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        ),
    )
    logger_name = f"intellicrack.tests.safe_parse_stream_json.{id(stream):x}"
    stdlib_logger = logging.getLogger(logger_name)
    stdlib_logger.handlers.clear()
    stdlib_logger.addHandler(handler)
    stdlib_logger.setLevel(logging.DEBUG)
    stdlib_logger.propagate = False
    bound = structlog.wrap_logger(
        stdlib_logger,
        wrapper_class=structlog.stdlib.BoundLogger,
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
    )
    return cast("structlog.stdlib.BoundLogger", bound)


def _read_events(stream: io.StringIO) -> list[dict[str, Any]]:
    """Decode each line of ``stream`` as a JSON event dict.

    Args:
        stream: Buffer populated by :func:`_make_capture_logger`.

    Returns:
        list[dict[str, Any]]: One dict per emitted log event in order.
    """
    events: list[dict[str, Any]] = []
    for raw in stream.getvalue().splitlines():
        line = raw.strip()
        if not line:
            continue
        events.append(cast("dict[str, Any]", json.loads(line)))
    return events


def test_parse_valid_object_returns_dict() -> None:
    """A well-formed JSON object line is returned as a dict."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    payload = '{"choices": [{"delta": {"content": "hi"}}]}'
    result = _safe_parse_stream_json(payload, logger=logger)

    assert isinstance(result, dict)
    assert cast("dict[str, Any]", result)["choices"][0]["delta"]["content"] == "hi"
    assert _read_events(stream) == []


def test_parse_empty_string_returns_none_silently() -> None:
    """An empty line yields ``None`` and emits no log event."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    result = _safe_parse_stream_json("", logger=logger)

    assert result is None
    assert _read_events(stream) == []


def test_parse_malformed_json_logs_and_returns_none() -> None:
    """Malformed JSON yields ``None`` and emits the default warning event."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    result = _safe_parse_stream_json("{not json", logger=logger)

    assert result is None
    events = _read_events(stream)
    assert len(events) == 1
    assert events[0]["event"] == _DEFAULT_EVENT
    assert events[0]["level"] == "warning"
    assert "error" in events[0]


def test_parse_truncated_json_logs_and_returns_none() -> None:
    """Truncated JSON (broken mid-stream) yields ``None`` with a warning."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    result = _safe_parse_stream_json('{"choices": [{"delta": {', logger=logger)

    assert result is None
    events = _read_events(stream)
    assert len(events) == 1
    assert events[0]["event"] == _DEFAULT_EVENT


def test_parse_non_object_values_return_none() -> None:
    """Valid JSON that decodes to a non-object is rejected silently.

    A streaming chunk that decodes to a number, array, bare string, ``null``,
    or boolean is not a usable provider event, so the helper returns ``None``.
    Critically this rejection must be SILENT: unlike a malformed line (which is
    a transport fault worth warning about), a well-formed non-object is an
    ordinary skip and must emit no log event. The final assertion that the
    capture stream stays empty is the load-bearing gate - it would catch the
    helper regressing into ``logger.warning(...)`` on every non-object chunk
    and flooding provider logs.

    Each payload is paired with the concrete JSON value it decodes to, so a
    regression that accidentally accepted, say, a JSON array (returning the
    list instead of ``None``) is caught precisely rather than lumped together.
    """
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    non_object_payloads: list[tuple[str, object]] = [
        ("42", 42),
        ("[1, 2, 3]", [1, 2, 3]),
        ('"hello"', "hello"),
        ("null", None),
        ("true", True),
        ("false", False),
    ]
    for payload, decoded in non_object_payloads:
        assert json.loads(payload) == decoded, f"payload {payload!r} must decode to {decoded!r}"
        assert _safe_parse_stream_json(payload, logger=logger) is None, f"{payload!r} must be rejected as a non-object"

    assert _read_events(stream) == []

    # Control: prove the capture logger is wired correctly, so the empty-events
    # assertion above is meaningful and not vacuously green from a dead logger.
    # A malformed line on the SAME logger MUST surface exactly one warning.
    assert _safe_parse_stream_json("{not json", logger=logger) is None
    control_events = _read_events(stream)
    assert len(control_events) == 1
    assert control_events[0]["event"] == _DEFAULT_EVENT
    assert control_events[0]["level"] == "warning"


def test_parse_object_with_nested_arrays_preserved() -> None:
    """Nested arrays and dicts in the payload survive the round-trip."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    payload = json.dumps({
        "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "f"}}]}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
    })
    result = _safe_parse_stream_json(payload, logger=logger)

    assert isinstance(result, dict)
    parsed = cast("dict[str, Any]", result)
    assert parsed["usage"]["total_tokens"] == 12
    assert parsed["choices"][0]["delta"]["tool_calls"][0]["function"]["name"] == "f"


def test_parse_custom_event_name_used_in_warning() -> None:
    """Caller-supplied ``event`` overrides the default log event name."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream)
    custom_event = "ollama_pull_status_decode_failed"

    result = _safe_parse_stream_json("{bad", logger=logger, event=custom_event)

    assert result is None
    events = _read_events(stream)
    assert len(events) == 1
    assert events[0]["event"] == custom_event


def test_logger_binding_is_preserved_in_emitted_event() -> None:
    """Provider-specific bindings flow through into the warning event."""
    stream = io.StringIO()
    logger = _make_capture_logger(stream).bind(provider="openrouter", model="x/y")

    result = _safe_parse_stream_json("{bad", logger=logger)

    assert result is None
    events = _read_events(stream)
    assert len(events) == 1
    assert events[0]["provider"] == "openrouter"
    assert events[0]["model"] == "x/y"


def test_whitespace_only_line_returns_none_with_warning() -> None:
    """Whitespace-only lines parse to ``None`` and emit a warning.

    ``json.loads("   ")`` raises ``JSONDecodeError`` so the helper must
    log the failure rather than silently swallow it. This documents the
    contract: the helper does NOT pre-strip whitespace, so any caller
    that wants to skip pure-whitespace lines silently must do so itself.
    """
    stream = io.StringIO()
    logger = _make_capture_logger(stream)

    result = _safe_parse_stream_json("   ", logger=logger)

    assert result is None
    events = _read_events(stream)
    assert len(events) == 1
    assert events[0]["event"] == _DEFAULT_EVENT
