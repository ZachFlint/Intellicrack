# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-structlog coverage for :class:`LogViewerWindow`.

The existing window suite seeds the log file with hand-crafted JSON dicts.
These tests instead emit real events through the application's configured
``structlog`` pipeline and then open a :class:`LogViewerWindow` pointed at the
same on-disk log, proving the window's history backfill parses the genuine
field layout that :func:`intellicrack.core.logging.setup_logging` writes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.config import Config, LogConfig
from intellicrack.core.logging import get_logger, setup_logging
from intellicrack.ui.log_viewer import LogViewerWindow


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot

    from intellicrack.ui.log_viewer._record import LogRecordDict


pytestmark = pytest.mark.usefixtures("qapp", "qsettings_tmp")

_DEFAULT_TIMEOUT_MS: int = 3_000


def _make_config(tmp_path: Path) -> Config:
    """Build a :class:`Config` rooted at ``tmp_path``.

    Args:
        tmp_path: Pytest temp directory.

    Returns:
        Config: Config whose logs directory is created under ``tmp_path``.
    """
    cfg = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    cfg.logs_directory.mkdir(parents=True, exist_ok=True)
    return cfg


def _configure_real_logging(log_dir: Path) -> None:
    """Wire the real structlog pipeline to write JSON Lines into ``log_dir``.

    Args:
        log_dir: Directory that will receive ``intellicrack.log``.
    """
    setup_logging(
        LogConfig(
            level="DEBUG",
            file_enabled=True,
            console_enabled=False,
            json_file=True,
            max_file_size_mb=10,
            backup_count=1,
            retention_days=1,
        ),
        log_dir=log_dir,
    )


def _flush_handlers() -> None:
    """Flush every root logging handler so emitted records hit disk."""
    for handler in logging.getLogger().handlers:
        handler.flush()


def _visible_records(window: LogViewerWindow) -> list[LogRecordDict]:
    """Return the records currently visible through the window's proxy filter.

    Maps every proxy row back to its source record so the result reflects the
    exact post-filter contents rather than the unfiltered model.

    Args:
        window: The log viewer whose proxy is queried.

    Returns:
        list[LogRecordDict]: Records that survive the active filters, in
            proxy row order.
    """
    records: list[LogRecordDict] = []
    proxy = window.proxy
    for row in range(proxy.rowCount()):
        source_row = proxy.mapToSource(proxy.index(row, 0)).row()
        record = window.model.record_at(source_row)
        if record is not None:
            records.append(record)
    return records


def test_window_backfills_real_structlog_history(qtbot: QtBot, tmp_path: Path) -> None:
    """The window's model parses real events emitted before it opens.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _configure_real_logging(config.logs_directory)

    logger = get_logger("intellicrack.tests.window_real")
    logger.info("real_history_event", subsystem="hexcore", attempt=2)
    logger.warning("real_history_warning")
    _flush_handlers()

    log_path = config.logs_directory / "intellicrack.log"
    assert log_path.exists()

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    def _has_event() -> bool:
        return any(r["event"] == "real_history_event" for r in window.model.all_records())

    qtbot.waitUntil(_has_event, timeout=_DEFAULT_TIMEOUT_MS)

    record = next(r for r in window.model.all_records() if r["event"] == "real_history_event")
    assert record["level"] == "INFO"
    assert record["logger"] == "intellicrack.intellicrack.tests.window_real"
    assert record["event"] == "real_history_event"
    extras = record["extras"]
    assert isinstance(extras, dict)
    assert extras == {"subsystem": "hexcore", "attempt": 2}
    window.close()


def test_window_level_filter_excludes_lower_levels(qtbot: QtBot, tmp_path: Path) -> None:
    """The ERROR filter keeps ERROR/CRITICAL and drops INFO/WARNING exactly.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _configure_real_logging(config.logs_directory)

    logger = get_logger("intellicrack.tests.window_filter")
    logger.info("real_info_only")
    logger.warning("real_warning_only")
    logger.error("real_error_only")
    logger.critical("real_critical_only")
    _flush_handlers()

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    emitted_events = {
        "real_info_only",
        "real_warning_only",
        "real_error_only",
        "real_critical_only",
    }

    def _all_present() -> bool:
        events = {r["event"] for r in window.model.all_records()}
        return emitted_events <= events

    qtbot.waitUntil(_all_present, timeout=_DEFAULT_TIMEOUT_MS)

    window.set_min_level(logging.ERROR)

    visible = _visible_records(window)
    visible_events = {record["event"] for record in visible}
    visible_levels = {record["level"] for record in visible}

    assert visible_events == {"real_error_only", "real_critical_only"}
    assert visible_levels == {"ERROR", "CRITICAL"}
    assert "real_info_only" not in visible_events
    assert "real_warning_only" not in visible_events
    assert window.proxy.rowCount() == 2

    window.close()


def test_window_level_filter_relaxation_restores_records(qtbot: QtBot, tmp_path: Path) -> None:
    """Lowering the filter back to INFO re-admits the previously hidden events.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _configure_real_logging(config.logs_directory)

    logger = get_logger("intellicrack.tests.window_relax")
    logger.info("relax_info_event")
    logger.error("relax_error_event")
    _flush_handlers()

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    def _both_present() -> bool:
        events = {r["event"] for r in window.model.all_records()}
        return {"relax_info_event", "relax_error_event"} <= events

    qtbot.waitUntil(_both_present, timeout=_DEFAULT_TIMEOUT_MS)

    window.set_min_level(logging.ERROR)
    narrowed = {record["event"] for record in _visible_records(window)}
    assert narrowed == {"relax_error_event"}

    window.set_min_level(logging.INFO)
    widened = {record["event"] for record in _visible_records(window)}
    assert {"relax_info_event", "relax_error_event"} <= widened
    assert "relax_info_event" in widened

    window.close()
