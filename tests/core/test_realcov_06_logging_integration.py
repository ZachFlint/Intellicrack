# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end real-data coverage for :mod:`intellicrack.core.logging` setup.

These tests run the real logging pipeline: they call ``setup_logging`` with a
real :class:`LogConfig`, emit real events through a real bound logger, and
then read the real log file off disk to confirm the structured payload was
serialised. Nothing about the pipeline is mocked. Each test restores the
process-wide logging/structlog configuration afterwards so it does not leak
handlers into later tests.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import pytest
import structlog

from intellicrack.core.config import LogConfig
from intellicrack.core.logging import get_logger, setup_logging


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

_LOG_FILE_NAME = "intellicrack.log"
_NOISY_LEVEL_FLOOR = logging.WARNING


@pytest.fixture
def restore_logging() -> Generator[None]:
    """Snapshot and restore global logging/structlog state around a test.

    Yields:
        None: Control returns to the test; on teardown the root logger
        handlers, levels, and structlog defaults are reset so the shared
        process state is not polluted.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
            handler.close()
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        structlog.reset_defaults()


@pytest.mark.usefixtures("restore_logging")
def test_setup_logging_writes_real_json_event_to_file(tmp_path: Path) -> None:
    """A real event emitted after ``setup_logging`` lands in the JSON log file.

    Args:
        tmp_path: Pytest temporary directory used as the real log directory.
    """
    config = LogConfig(
        level="DEBUG",
        file_enabled=True,
        console_enabled=False,
        json_file=True,
    )
    setup_logging(config, tmp_path)
    logger = get_logger("realcov.logging")

    logger.info("realcov_logging_event", target="kernel32.dll", count=3)

    for handler in logging.getLogger().handlers:
        handler.flush()

    log_file = tmp_path / _LOG_FILE_NAME
    assert log_file.is_file()
    content = log_file.read_text(encoding="utf-8")
    lines = [line for line in content.splitlines() if "realcov_logging_event" in line]
    assert lines

    payload = json.loads(lines[-1])
    assert payload["event"] == "realcov_logging_event"
    assert payload["target"] == "kernel32.dll"
    assert payload["count"] == 3
    assert payload["level"] == "info"
    assert payload["logger"] == "intellicrack.realcov.logging"


@pytest.mark.usefixtures("restore_logging")
def test_setup_logging_plain_text_file_format(tmp_path: Path) -> None:
    """Non-JSON file output renders the real event in console-style text.

    Args:
        tmp_path: Pytest temporary directory used as the real log directory.
    """
    config = LogConfig(
        level="INFO",
        file_enabled=True,
        console_enabled=False,
        json_file=False,
    )
    setup_logging(config, tmp_path)
    logger = get_logger("realcov.plain")

    logger.warning("realcov_plaintext_event", detail="value-42")

    for handler in logging.getLogger().handlers:
        handler.flush()

    content = (tmp_path / _LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "realcov_plaintext_event" in content
    assert "detail" in content
    assert "value-42" in content
    with pytest.raises(json.JSONDecodeError):
        json.loads(content.splitlines()[-1])


@pytest.mark.usefixtures("restore_logging")
def test_setup_logging_suppresses_third_party_noisy_loggers(tmp_path: Path) -> None:
    """``setup_logging`` raises noisy third-party loggers to WARNING level.

    Args:
        tmp_path: Pytest temporary directory used as the real log directory.
    """
    config = LogConfig(level="DEBUG", file_enabled=False, console_enabled=False)
    setup_logging(config, tmp_path)

    for name in ("httpx", "httpcore", "openai._base_client", "anthropic._base_client"):
        assert logging.getLogger(name).level == _NOISY_LEVEL_FLOOR


@pytest.mark.usefixtures("restore_logging")
def test_setup_logging_rotation_creates_backup_file(tmp_path: Path) -> None:
    """Real ``RotatingFileHandler`` rolls the active log when the cap is hit.

    Emits enough real events to exceed a tiny ``max_file_size_mb`` cap so the
    real handler performs a real rollover and produces a real ``.log.1``
    backup file alongside the active log.

    Args:
        tmp_path: Pytest temporary directory used as the real log directory.
    """
    config = LogConfig(
        level="INFO",
        file_enabled=True,
        console_enabled=False,
        json_file=True,
        max_file_size_mb=1,
        backup_count=2,
    )
    setup_logging(config, tmp_path)
    logger = get_logger("realcov.rotate")

    filler = "x" * 4096
    for index in range(600):
        logger.info("realcov_rotation_event", index=index, filler=filler)

    for handler in logging.getLogger().handlers:
        handler.flush()

    backup = tmp_path / f"{_LOG_FILE_NAME}.1"
    assert backup.is_file(), "RotatingFileHandler did not produce a real backup file"
    assert (tmp_path / _LOG_FILE_NAME).is_file()
