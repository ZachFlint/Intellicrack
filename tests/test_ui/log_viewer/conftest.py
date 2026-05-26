# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fixtures for the Log Viewer test suite.

Provides:

- ``cleanup_qt_log_handler``: autouse fixture that detaches the global
  handler after each test so cases are independent.
- ``configured_logging``: configures the real :func:`setup_logging` so
  records land in a JSON-Lines file under ``tmp_path``.
- ``qsettings_tmp``: redirects :class:`QSettings` into ``tmp_path`` so
  geometry persistence never touches the developer's user profile.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QSettings

from intellicrack.core.config import LogConfig
from intellicrack.core.logging import setup_logging
from intellicrack.ui.log_viewer import uninstall_qt_log_handler


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture(autouse=True)
def cleanup_qt_log_handler() -> Generator[None]:
    """Detach the shared Qt log handler after each test.

    Yields:
        None: nothing; runs uninstall on teardown.
    """
    yield
    uninstall_qt_log_handler()


@pytest.fixture
def configured_logging(tmp_path: Path) -> Path:
    """Configure real structlog logging into ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Absolute path to the active ``intellicrack.log`` file.
    """
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
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
    return log_dir / "intellicrack.log"


@pytest.fixture
def qsettings_tmp(tmp_path: Path) -> None:
    """Redirect QSettings IniFormat storage into the temp dir.

    Works in tandem with :meth:`LogViewerWindow._build_settings`, which
    constructs ``QSettings`` with explicit ``IniFormat``; this fixture
    therefore fully isolates persisted geometry and filter state per
    test (the ``QSettings(org, app)`` constructor default uses
    ``NativeFormat`` / the Windows registry which cannot be redirected).

    Args:
        tmp_path: Pytest temporary directory.
    """
    QSettings.setPath(
        QSettings.Format.IniFormat,
        QSettings.Scope.UserScope,
        str(tmp_path / "qsettings"),
    )
