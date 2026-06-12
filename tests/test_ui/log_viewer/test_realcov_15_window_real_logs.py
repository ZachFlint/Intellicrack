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
    assert "intellicrack.tests.window_real" in str(record["logger"])
    extras = record["extras"]
    assert isinstance(extras, dict)
    assert extras.get("subsystem") == "hexcore"
    assert extras.get("attempt") == 2
    window.close()


def _visible_events(window: LogViewerWindow) -> set[str]:
    """Collect the event names of all proxy-visible rows.

    Args:
        window: The open :class:`LogViewerWindow` under test.

    Returns:
        set[str]: Set of ``event`` field values for every row that passes
            the proxy filter.
    """
    all_records = list(window.model.all_records())
    events: set[str] = set()
    for row in range(window.proxy.rowCount()):
        source_idx = window.proxy.mapToSource(window.proxy.index(row, 0))
        source_row = source_idx.row()
        if 0 <= source_row < len(all_records):
            events.add(all_records[source_row]["event"])
    return events


def _visible_levels(window: LogViewerWindow) -> set[str]:
    """Collect the level names of all proxy-visible rows.

    Args:
        window: The open :class:`LogViewerWindow` under test.

    Returns:
        set[str]: Set of ``level`` field values for every row that passes
            the proxy filter.
    """
    all_records = list(window.model.all_records())
    levels: set[str] = set()
    for row in range(window.proxy.rowCount()):
        source_idx = window.proxy.mapToSource(window.proxy.index(row, 0))
        source_row = source_idx.row()
        if 0 <= source_row < len(all_records):
            levels.add(all_records[source_row]["level"])
    return levels


def test_window_level_filter_over_real_records(qtbot: QtBot, tmp_path: Path) -> None:
    """The level filter narrows real records parsed from the live log.

    This test uses a fresh ``tmp_path`` so the log file contains only the two
    events emitted here (plus internal DEBUG/INFO messages from construction).
    After applying an ERROR-level filter the proxy must show exactly one level
    value: ``"ERROR"``.  The assertion is strict equality against the
    independent oracle ``{"ERROR"}`` — a subset check would pass on an empty
    set and cannot detect a filter that silently hides all rows, while equality
    would also catch a broken filter that lets sub-ERROR levels through.

    Specifically:

    * ``"real_error_only"`` (ERROR) must be visible — proves the filter keeps
      matching records.
    * ``"real_info_only"`` (INFO) must be absent — proves the filter removes
      sub-ERROR records.
    * ``vis_levels == {"ERROR"}`` — proves no other level survives; an empty
      set, a set containing ``"INFO"`` / ``"WARNING"`` / ``"DEBUG"``, or a set
      also containing ``"CRITICAL"`` (impossible since no CRITICAL was emitted)
      all cause the assertion to fail.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _configure_real_logging(config.logs_directory)

    logger = get_logger("intellicrack.tests.window_filter")
    logger.info("real_info_only")
    logger.error("real_error_only")
    _flush_handlers()

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    def _both_present() -> bool:
        events = {r["event"] for r in window.model.all_records()}
        return {"real_info_only", "real_error_only"} <= events

    qtbot.waitUntil(_both_present, timeout=_DEFAULT_TIMEOUT_MS)

    window.set_min_level(logging.ERROR)

    def _filter_settled() -> bool:
        vis_events = _visible_events(window)
        return "real_error_only" in vis_events and "real_info_only" not in vis_events

    qtbot.waitUntil(_filter_settled, timeout=_DEFAULT_TIMEOUT_MS)

    vis_events = _visible_events(window)
    vis_levels = _visible_levels(window)

    assert "real_error_only" in vis_events, f"ERROR-level event must be visible after ERROR filter; visible events: {vis_events}"
    assert "real_info_only" not in vis_events, f"INFO-level event must be hidden after ERROR filter; visible events: {vis_events}"
    assert window.proxy.rowCount() >= 1, "At least the real_error_only row must remain visible after ERROR filter"
    assert vis_levels == {"ERROR"}, (
        f'Visible levels must be exactly {{"ERROR"}} after ERROR filter (no CRITICAL emitted, subset check insufficient); got: {vis_levels}'
    )
    assert "INFO" not in vis_levels, f"INFO must not appear in visible levels after ERROR filter; got: {vis_levels}"
    assert "WARNING" not in vis_levels, f"WARNING must not appear in visible levels after ERROR filter; got: {vis_levels}"
    assert "DEBUG" not in vis_levels, f"DEBUG must not appear in visible levels after ERROR filter; got: {vis_levels}"

    window.close()
