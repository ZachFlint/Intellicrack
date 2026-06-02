# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-structlog coverage for :class:`LogFileTailReader`.

The existing tail-reader suite seeds the log file with hand-crafted JSON
dicts. These tests instead emit *real* events through the application's
configured ``structlog`` pipeline (via the ``configured_logging`` fixture,
which calls :func:`intellicrack.core.logging.setup_logging`) and then point a
:class:`LogFileTailReader` at the resulting ``intellicrack.log`` file. This
proves the reader's field parsing matches the genuine on-disk JSON-Lines
format the application actually produces.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer import LogFileTailReader


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

# The structlog pipeline writes timestamps with this exact strftime format
# (see ``TimeStamper(fmt="%Y-%m-%d %H:%M:%S")`` in intellicrack.core.logging).
# Independent oracle for validating that the reader preserves the on-disk
# timestamp verbatim rather than mangling it.
_DISK_TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S"

# ``intellicrack.core.logging`` prepends ``intellicrack.`` to every logger name
# via ``structlog.stdlib.add_logger_name`` against the package root, so a logger
# requested as ``intellicrack.tests.tail_real`` lands on disk doubled.
_TAIL_REAL_LOGGER_NAME: str = "intellicrack.tests.tail_real"
_DISK_LOGGER_NAME: str = "intellicrack.intellicrack.tests.tail_real"

# ``_add_call_info`` records the source filename (sans ``.py``) and the calling
# function. When ``logger.info`` is invoked directly inside the test body these
# resolve to this module's filename and the test function name.
_THIS_MODULE_NAME: str = "test_realcov_15_tail_reader_real_logs"


def _flush_handlers() -> None:
    """Flush every root logging handler so emitted records hit disk."""
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_reader_parses_real_structlog_records(
    qtbot: QtBot,
    configured_logging: Path,
) -> None:
    """The reader parses every field of a real structlog record with exact values.

    Two events are emitted through the genuine ``setup_logging`` pipeline so the
    on-disk JSON-Lines text is produced by production code, not hand-crafted.
    The reader then backfills them and every field of the ``INFO`` record is
    checked against an independently-known expected value: the verbatim event
    name and logger name, the level upper-cased from the on-disk ``"info"``, the
    source module/function of this very call site, a strptime-parseable
    timestamp in the documented format, a positive integer line number, and the
    exact extras mapping with no spurious keys.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Path to the active ``intellicrack.log`` file
            produced by the real ``setup_logging`` configuration.
    """
    logger = get_logger(_TAIL_REAL_LOGGER_NAME)
    logger.info("real_alpha_event", widget="hex", count=7)
    logger.warning("real_beta_event", origin="worker")
    _flush_handlers()

    assert configured_logging.exists()

    reader = LogFileTailReader(configured_logging)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.wait(50)
    reader.stop()

    events = [r["event"] for r in received]
    assert "real_alpha_event" in events
    assert "real_beta_event" in events

    alpha = next(r for r in received if r["event"] == "real_alpha_event")

    assert alpha["event"] == "real_alpha_event"
    assert alpha["level"] == "INFO"
    assert alpha["logger"] == _DISK_LOGGER_NAME
    assert alpha["module"] == _THIS_MODULE_NAME
    assert alpha["function"] == "test_reader_parses_real_structlog_records"

    timestamp = alpha["timestamp"]
    assert isinstance(timestamp, str)
    parsed_ts = time.strptime(timestamp, _DISK_TIMESTAMP_FORMAT)
    assert parsed_ts.tm_year >= 2026
    assert 1 <= parsed_ts.tm_mon <= 12
    assert 1 <= parsed_ts.tm_mday <= 31

    line_number = alpha["line_number"]
    assert isinstance(line_number, int)
    assert line_number > 0

    extras = alpha["extras"]
    assert extras == {"widget": "hex", "count": 7}

    beta = next(r for r in received if r["event"] == "real_beta_event")
    assert beta["level"] == "WARNING"
    assert beta["logger"] == _DISK_LOGGER_NAME
    assert beta["extras"] == {"origin": "worker"}


def test_reader_picks_up_live_real_appends(
    qtbot: QtBot,
    configured_logging: Path,
) -> None:
    """New real events appended after start reach the reader via polling.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Path to the active ``intellicrack.log`` file.
    """
    logger = get_logger("intellicrack.tests.tail_live")
    logger.info("seed_real_event")
    _flush_handlers()

    reader = LogFileTailReader(configured_logging)
    received: list[dict[str, object]] = []
    reader.record_emitted.connect(received.append)
    with qtbot.waitSignal(reader.initial_load_complete, timeout=3_000):
        reader.start()
    qtbot.wait(50)

    logger.error("appended_real_event", phase="late")
    _flush_handlers()
    reader.force_poll()
    qtbot.wait(150)
    reader.stop()

    appended = [r for r in received if r["event"] == "appended_real_event"]
    assert appended, "live-appended real structlog record was not observed"
    record = appended[-1]
    assert record["level"] == "ERROR"
    extras = record.get("extras")
    assert isinstance(extras, dict)
    assert extras.get("phase") == "late"
