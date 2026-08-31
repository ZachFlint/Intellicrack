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
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging import get_logger
from intellicrack.ui.log_viewer import LogFileTailReader


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")

_REQUIRED_FIELDS: tuple[str, ...] = (
    "timestamp",
    "level",
    "logger",
    "event",
    "module",
    "function",
    "line_number",
)


def _flush_handlers() -> None:
    """Flush every root logging handler so emitted records hit disk."""
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_reader_parses_real_structlog_records(
    qtbot: QtBot,
    configured_logging: Path,
) -> None:
    """The reader backfills records emitted through the real structlog pipeline.

    Args:
        qtbot: pytest-qt bot fixture.
        configured_logging: Path to the active ``intellicrack.log`` file
            produced by the real ``setup_logging`` configuration.
    """
    logger = get_logger("intellicrack.tests.tail_real")
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
    for field in _REQUIRED_FIELDS:
        assert field in alpha, f"real structlog record missing field {field!r}"
    assert alpha["level"] == "INFO"
    assert "intellicrack.tests.tail_real" in str(alpha["logger"])
    assert str(alpha["module"])
    assert str(alpha["function"])
    assert int(alpha["line_number"]) > 0

    extras = alpha.get("extras")
    assert isinstance(extras, dict)
    assert extras.get("widget") == "hex"
    assert extras.get("count") == 7


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
