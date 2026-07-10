# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for two low-severity Log Viewer GUI audit findings.

Covers:

- Column sizing: the Time and Level header sections previously kept their
  default width and clipped their contents until the user dragged them. They
  must now use content-fitting resize modes so they render legibly on first
  open.
- Reload reader leak: :meth:`LogViewerWindow._on_reload_from_disk` stopped the
  old tail reader but never deleted it, so dead readers accumulated for the
  window's lifetime. The old reader must now be scheduled for deletion.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from PyQt6 import sip
from PyQt6.QtWidgets import QHeaderView

from intellicrack.core.config import Config
from intellicrack.ui.log_viewer import LogViewerWindow


if TYPE_CHECKING:
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp", "qsettings_tmp")

_TIME_COLUMN: int = 0
_LEVEL_COLUMN: int = 1
_SEED_RECORDS: int = 3


def _make_config(tmp_path: Path) -> Config:
    """Build a minimal :class:`Config` rooted at ``tmp_path``.

    Args:
        tmp_path: Pytest temp directory.

    Returns:
        Config: Config with directories pointed at ``tmp_path``.
    """
    cfg = Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )
    cfg.logs_directory.mkdir(parents=True, exist_ok=True)
    return cfg


def _seed_log_file(path: Path, count: int) -> None:
    """Seed a JSON-Lines log file with ``count`` records.

    Args:
        path: Target log file.
        count: Number of records to write.
    """
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for i in range(count):
            handle.write(
                json.dumps(
                    {
                        "timestamp": "2026-05-25 10:00:00",
                        "level": "INFO",
                        "logger": "intellicrack.tests",
                        "module": "m",
                        "function": "f",
                        "line_number": i,
                        "event": f"seed_event_{i}",
                    },
                ),
            )
            handle.write("\n")


def test_time_and_level_columns_fit_contents_on_open(qtbot: QtBot, tmp_path: Path) -> None:
    """The Time and Level columns use content-fitting resize modes on first open.

    On the pre-fix code both sections used the default Interactive mode and
    clipped until dragged.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=_SEED_RECORDS)

    window = LogViewerWindow(config)
    qtbot.addWidget(window)
    window.show()

    table_view = getattr(window, "_table_view")
    assert table_view is not None
    header = table_view.horizontalHeader()
    assert header is not None
    assert header.sectionResizeMode(_TIME_COLUMN) == QHeaderView.ResizeMode.ResizeToContents
    assert header.sectionResizeMode(_LEVEL_COLUMN) == QHeaderView.ResizeMode.ResizeToContents
    window.close()


def test_reload_from_disk_deletes_old_reader(qtbot: QtBot, tmp_path: Path) -> None:
    """Reloading from disk schedules the previous tail reader for deletion.

    On the pre-fix code the old reader was stopped but never deleted, so it
    survived (parented to the window) and accumulated across reloads.

    Args:
        qtbot: pytest-qt bot fixture.
        tmp_path: Pytest temp directory.
    """
    config = _make_config(tmp_path)
    _seed_log_file(config.logs_directory / "intellicrack.log", count=_SEED_RECORDS)

    window = LogViewerWindow(config)
    qtbot.addWidget(window)

    old_reader = getattr(window, "_tail_reader")
    reload_from_disk = getattr(window, "_on_reload_from_disk")
    reload_from_disk()
    new_reader = getattr(window, "_tail_reader")

    assert new_reader is not old_reader
    qtbot.waitUntil(lambda: sip.isdeleted(old_reader), timeout=2_000)
    window.close()
