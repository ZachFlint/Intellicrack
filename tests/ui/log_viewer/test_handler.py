# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for :class:`QtSignalingHandler` and its installation helpers."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer import (
    QtSignalingHandler,
    get_qt_log_handler,
    install_qt_log_handler,
    uninstall_qt_log_handler,
)


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

pytestmark = pytest.mark.usefixtures("qapp")


def test_install_handler_is_idempotent() -> None:
    """Verify install_qt_log_handler returns the same singleton."""
    first = install_qt_log_handler()
    second = install_qt_log_handler()
    assert first is second
    assert get_qt_log_handler() is first
    root_handlers = [h for h in logging.getLogger().handlers if isinstance(h, QtSignalingHandler)]
    assert len(root_handlers) == 1


def test_uninstall_removes_from_root() -> None:
    """Verify uninstall_qt_log_handler detaches the handler."""
    install_qt_log_handler()
    uninstall_qt_log_handler()
    assert get_qt_log_handler() is None
    qt_handlers = [h for h in logging.getLogger().handlers if isinstance(h, QtSignalingHandler)]
    assert not qt_handlers


def test_record_dispatched_with_event_and_extras(qtbot: QtBot, configured_logging: Path) -> None:
    """Verify a structured log emission produces a fully formed record dict.

    The ``module`` and ``function`` fields must identify the actual calling
    frame (this test function in ``test_handler.py``), not an internal frame
    from structlog or ``intellicrack.core.logging``.  If the
    ``_add_call_info`` processor regresses by resolving to the wrong frame
    (e.g., returning ``"logging"`` or ``"_handler"`` instead of
    ``"test_handler"``), these exact-value assertions will fail.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Logging configuration fixture (ensures structlog
            is wired up; the file path is not used by this test).
    """
    del configured_logging
    handler = install_qt_log_handler()
    logger = get_logger("tests.handler")
    with qtbot.waitSignal(handler.record_received, timeout=2000) as blocker:
        logger.info("unit_test_event", widget="x", count=3)
    record = blocker.args[0]
    assert isinstance(record, dict)
    assert record["event"] == "unit_test_event"
    assert record["level"] == "INFO"
    assert "tests.handler" in record["logger"]
    assert record["module"] == "test_handler", (
        f"Expected module 'test_handler' (the test file), got {record['module']!r}. "
        "This indicates _add_call_info resolved to the wrong frame."
    )
    assert record["function"] == "test_record_dispatched_with_event_and_extras", (
        f"Expected function 'test_record_dispatched_with_event_and_extras', got {record['function']!r}. "
        "This indicates _add_call_info resolved to the wrong frame."
    )
    assert record["line_number"] > 0
    assert record["extras"].get("widget") == "x"
    assert record["extras"].get("count") == 3


def test_cross_thread_emit(qtbot: QtBot, configured_logging: Path) -> None:
    """Verify a log call from a worker thread reaches the Qt signal.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Logging configuration fixture.
    """
    del configured_logging
    handler = install_qt_log_handler()
    logger = get_logger("tests.handler.cross_thread")

    def emit_from_thread() -> None:
        logger.warning("cross_thread_event", origin="worker")

    with qtbot.waitSignal(handler.record_received, timeout=2000) as blocker:
        thread = threading.Thread(target=emit_from_thread, daemon=True)
        thread.start()
        thread.join(timeout=2.0)
    record = blocker.args[0]
    assert record["event"] == "cross_thread_event"
    assert record["level"] == "WARNING"
    assert record["extras"].get("origin") == "worker"


def test_reentrancy_guard_drops_inner_emit(qtbot: QtBot, configured_logging: Path) -> None:
    """Verify a slot that logs does not provoke recursion.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Logging configuration fixture.
    """
    del configured_logging
    handler = install_qt_log_handler()
    inner_logger = get_logger("tests.handler.reentry")
    received: list[dict[str, object]] = []

    def on_record(record: dict[str, object]) -> None:
        received.append(record)
        if len(received) < 2:
            inner_logger.info("inner_event")

    handler.record_received.connect(on_record)
    try:
        with qtbot.waitSignal(handler.record_received, timeout=2000):
            inner_logger.info("outer_event")
        qtbot.wait(50)
    finally:
        handler.record_received.disconnect(on_record)
    assert any(r["event"] == "outer_event" for r in received)
    assert all(r["event"] != "inner_event" for r in received)


def test_pause_suppresses_signal_but_disk_unaffected(
    qtbot: QtBot,
    configured_logging: Path,
) -> None:
    """Verify pause stops the signal while disk logging continues.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Logging configuration fixture providing the
            on-disk log path.
    """
    handler = install_qt_log_handler()
    handler.set_paused(paused=True)

    received: list[object] = []
    handler.record_received.connect(received.append)
    try:
        get_logger("tests.handler.pause").info("paused_event", x=1)
        qtbot.wait(100)
    finally:
        handler.record_received.disconnect(received.append)
    assert not received

    for handler_obj in logging.getLogger().handlers:
        handler_obj.flush()
    assert configured_logging.exists()
    text = configured_logging.read_text(encoding="utf-8")
    assert "paused_event" in text


def test_emit_failure_routes_to_handle_error(
    monkeypatch: pytest.MonkeyPatch,
    configured_logging: Path,
) -> None:
    """Verify an exception during conversion is captured by handleError.

    The gate must confirm:
    1. Exactly one ``handleError`` invocation (not zero, not a spurious prior
       one from handler initialisation or test-isolation gaps).
    2. The captured argument is the specific ``logging.LogRecord`` that was
       emitted for ``"event_that_breaks_handler"``—identified by level
       ``INFO`` and logger name ``"intellicrack.tests.handler.error"``—not
       some unrelated record that happened to arrive earlier.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to break the
            converter and capture ``handleError`` invocations.
        configured_logging: Logging configuration fixture (the path
            is unused; the fixture ensures DEBUG level is active).
    """
    del configured_logging
    handler = install_qt_log_handler()
    handler_errors: list[logging.LogRecord] = []

    def failing_from_logging_record(_record: object) -> object:
        msg = "induced failure"
        raise RuntimeError(msg)

    monkeypatch.setattr("intellicrack.ui.log_viewer._handler.from_logging_record", failing_from_logging_record)
    monkeypatch.setattr(handler, "handleError", handler_errors.append)

    logger = get_logger("tests.handler.error")
    logger.info("event_that_breaks_handler", widget="x")

    assert len(handler_errors) == 1, (
        f"Expected exactly 1 handleError call, got {len(handler_errors)}. Either the error path did not fire or a spurious call occurred."
    )
    captured: logging.LogRecord = handler_errors[0]
    assert isinstance(captured, logging.LogRecord), f"handleError received {type(captured)!r}, expected logging.LogRecord"
    assert captured.levelname == "INFO", f"Record levelname is {captured.levelname!r}; expected 'INFO' matching the emitted call"
    assert "tests.handler.error" in captured.name, (
        f"Record name {captured.name!r} does not contain 'tests.handler.error'; the wrong LogRecord was passed to handleError"
    )
