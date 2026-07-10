# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Structured-logging side-effect coverage for the dialog helpers.

The forwarding behavior of ``show_error`` / ``show_warning`` / ``show_info`` is
already covered. These tests add the missing assertion that the helpers emit
the real structured log entries documented in their contract: when an
exception is supplied, ``show_error`` and ``show_warning`` must record the
exception type (and traceback) through the real ``structlog`` pipeline.

Logging is exercised for real (records are written to a JSON-Lines file via
:func:`setup_logging`). Only the irreplaceable OS-modal ``QMessageBox`` call is
isolated -- it cannot run headlessly and is not the side-effect under test.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.config import LogConfig
from intellicrack.core.logging import setup_logging
from intellicrack.ui import dialogs_helpers
from intellicrack.ui.dialogs_helpers import show_error, show_warning


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.usefixtures("qapp")


def _configure_logging(log_dir: Path) -> Path:
    """Wire real structlog JSON-Lines logging into ``log_dir``.

    Args:
        log_dir: Directory to receive ``intellicrack.log``.

    Returns:
        Path: The active log file path.
    """
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


def _read_records(log_file: Path) -> list[dict[str, object]]:
    """Parse JSON-Lines records from a log file, flushing handlers first.

    Args:
        log_file: Path to the JSON-Lines log file.

    Returns:
        list[dict[str, object]]: Parsed log records.
    """
    for handler in logging.getLogger().handlers:
        handler.flush()
    records: list[dict[str, object]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            continue
    return records


def test_show_error_with_exception_logs_error_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``show_error`` with an exception logs ``dialog_error`` and the error type.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the OS modal).
    """
    log_file = _configure_logging(tmp_path / "logs")
    monkeypatch.setattr(
        dialogs_helpers.QMessageBox,
        "critical",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Ok),
    )

    exc = ValueError("section header is corrupt")
    result = show_error(None, "Parse Failed", "Could not parse the binary.", exc=exc)
    assert result == QMessageBox.StandardButton.Ok

    records = _read_records(log_file)
    matching = [r for r in records if r.get("event") == "dialog_error" and r.get("error_type") == "ValueError"]
    assert matching, "show_error did not emit a dialog_error record carrying the exception type"
    record = matching[-1]
    assert str(record["level"]).upper() == "ERROR"
    assert record.get("title") == "Parse Failed"
    assert "section header is corrupt" in str(record.get("error"))


def test_show_warning_with_exception_logs_warning_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``show_warning`` with an exception logs ``dialog_warning`` and error type.

    Args:
        tmp_path: Pytest temporary directory.
        monkeypatch: Pytest monkeypatch fixture (isolates the OS modal).
    """
    log_file = _configure_logging(tmp_path / "logs")
    monkeypatch.setattr(
        dialogs_helpers.QMessageBox,
        "warning",
        staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Ok),
    )

    exc = OSError("disk full")
    show_warning(None, "Save Warning", "Could not write file.", exc=exc)

    records = _read_records(log_file)
    matching = [r for r in records if r.get("event") == "dialog_warning" and r.get("error_type") == "OSError"]
    assert matching, "show_warning did not emit a dialog_warning record carrying the exception type"
    assert "disk full" in str(matching[-1].get("error"))
