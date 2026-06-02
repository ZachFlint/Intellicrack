# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 CORE-D regression tests for ``intellicrack.core.logging``.

Exercises end-to-end (no mocked log sinks) that:

    * F-0016 - ``_default_log_dir`` honours the configured ``logs_directory``
      rather than always returning ``Path.cwd() / "logs"`` and that the
      resolved directory is the one ``setup_logging`` actually writes real log
      files into. Each test drives a real :func:`setup_logging` call with file
      logging enabled and asserts a real ``intellicrack.log`` file appears in
      the resolved directory containing the JSON record that was emitted.
"""

from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

import intellicrack.core.logging as logging_mod
from intellicrack.core.config import Config, LogConfig


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


_UNIQUE_EVENT = "audit6_real_logfile_probe_event"


def _default_log_dir() -> Path:
    """Return the resolved default log directory via ``getattr``.

    Returns:
        Path: The resolved default log directory.
    """
    fn = cast("Callable[[], Path]", getattr(logging_mod, "_default_log_dir"))
    return fn()


def _logger_state() -> object:
    """Return the module-level ``_logger_state`` container via ``getattr``.

    Returns:
        object: The shared ``_LoggerState`` container instance.
    """
    return getattr(logging_mod, "_logger_state")


def _file_logging_config() -> LogConfig:
    """Build a real ``LogConfig`` that writes JSON log files to disk.

    Returns:
        LogConfig: Configuration with file logging enabled and JSON output so
            emitted records can be parsed and asserted on field-by-field.
    """
    return LogConfig(
        level="INFO",
        file_enabled=True,
        console_enabled=False,
        max_file_size_mb=1,
        backup_count=1,
        retention_days=1,
        json_file=True,
    )


def _close_root_handlers() -> None:
    """Close and detach every handler ``setup_logging`` installed.

    On Windows a :class:`~logging.handlers.RotatingFileHandler` keeps the log
    file open, which would block ``tmp_path`` teardown. Closing the handlers
    releases the file locks deterministically.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        handler.close()
        root.removeHandler(handler)


def _emit_and_flush(event: str) -> None:
    """Emit a single info record through the configured app logger and flush.

    Args:
        event: The structured event name to emit so the test can locate the
            exact record inside the on-disk log file.
    """
    logging_mod.get_logger("audit6").info(event, probe=True)
    for handler in logging.getLogger().handlers:
        handler.flush()


def _read_logged_events(log_file: Path) -> list[dict[str, object]]:
    """Parse a JSON-lines log file into a list of decoded record dicts.

    Args:
        log_file: Path to the ``intellicrack.log`` file written by structlog.

    Returns:
        list[dict[str, object]]: One decoded dict per non-empty JSON line.
    """
    records: list[dict[str, object]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        records.append(cast("dict[str, object]", json.loads(stripped)))
    return records


@pytest.fixture(autouse=True)
def reset_logger_state() -> Iterator[None]:
    """Reset cached logger state and release log handlers around each test.

    Yields:
        None: Control to the test body; teardown closes file handlers so the
            temporary log directory can be removed on Windows.
    """
    state = _logger_state()
    setattr(state, "configured_log_dir", None)
    setattr(state, "app_logger", None)
    _close_root_handlers()
    try:
        yield
    finally:
        _close_root_handlers()
        setattr(state, "configured_log_dir", None)
        setattr(state, "app_logger", None)


class TestF0016DefaultLogDirHonoursConfig:
    """``_default_log_dir`` must resolve the directory logging truly writes to."""

    @staticmethod
    def test_no_config_writes_logs_under_cwd_logs(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """With no config file, real logs land under ``Path.cwd() / 'logs'``.

        Drives ``setup_logging`` (no explicit ``log_dir``) so the production
        fallback chain resolves the directory, then asserts a real
        ``intellicrack.log`` file is created there containing the emitted
        record. ``cwd`` is pointed at a clean ``tmp_path`` so the assertion is
        hermetic and does not pollute the repository.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: pytest temporary directory.
        """
        config_module = importlib.import_module("intellicrack.core.config")
        monkeypatch.setattr(
            config_module,
            "get_config_dir",
            lambda: tmp_path / "no_such_config_dir",
        )
        monkeypatch.chdir(tmp_path)

        expected_dir = Path.cwd() / "logs"
        assert _default_log_dir() == expected_dir

        logging_mod.setup_logging(_file_logging_config())
        _emit_and_flush(_UNIQUE_EVENT)

        log_file = expected_dir / "intellicrack.log"
        assert log_file.is_file()
        events = _read_logged_events(log_file)
        probe = [rec for rec in events if rec.get("event") == _UNIQUE_EVENT]
        assert len(probe) == 1
        assert probe[0]["probe"] is True
        assert probe[0]["level"] == "info"

    @staticmethod
    def test_configured_logs_directory_receives_real_logs(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A persisted config's ``logs_directory`` is where logs are written.

        Builds a real ``Config`` saved to a real ``config.toml`` on disk, points
        the production ``get_config_dir`` at it, and confirms both that
        ``_default_log_dir`` resolves the configured directory and that
        ``setup_logging`` writes the real log file there - not under cwd.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: pytest temporary directory.
        """
        pytest.importorskip("tomli_w")
        config_module = importlib.import_module("intellicrack.core.config")
        config_dir = tmp_path / "intellicrack_config"
        config_dir.mkdir()
        target_logs = tmp_path / "configured_logs"

        config = Config.default()
        config.tools_directory = tmp_path / "tools"
        config.logs_directory = target_logs
        config.data_directory = tmp_path / "data"
        config.save(config_dir / "config.toml")

        monkeypatch.setattr(config_module, "get_config_dir", lambda: config_dir)
        cwd_logs = tmp_path / "cwd_root"
        cwd_logs.mkdir()
        monkeypatch.chdir(cwd_logs)

        assert _default_log_dir() == target_logs

        logging_mod.setup_logging(_file_logging_config())
        _emit_and_flush(_UNIQUE_EVENT)

        target_file = target_logs / "intellicrack.log"
        assert target_file.is_file()
        assert not (cwd_logs / "logs" / "intellicrack.log").exists()

        events = _read_logged_events(target_file)
        probe = [rec for rec in events if rec.get("event") == _UNIQUE_EVENT]
        assert len(probe) == 1
        assert probe[0]["logger"] == "intellicrack.audit6"

    @staticmethod
    def test_state_after_setup_logging_drives_real_log_files(
        tmp_path: Path,
    ) -> None:
        """A second ``setup_logging`` with no ``log_dir`` reuses the state dir.

        The first call records ``target_logs`` in ``_logger_state``. A second
        call with no explicit directory must resolve through that state and
        write its real log file into the same directory.

        Args:
            tmp_path: pytest temporary directory.
        """
        target_logs = tmp_path / "via_state"
        logging_mod.setup_logging(_file_logging_config(), log_dir=target_logs)
        _close_root_handlers()

        assert _default_log_dir() == target_logs

        logging_mod.setup_logging(_file_logging_config())
        _emit_and_flush(_UNIQUE_EVENT)

        log_file = target_logs / "intellicrack.log"
        assert log_file.is_file()
        events = _read_logged_events(log_file)
        probe = [rec for rec in events if rec.get("event") == _UNIQUE_EVENT]
        assert len(probe) == 1
        assert probe[0]["probe"] is True

    @staticmethod
    def test_explicit_log_dir_is_written_and_recorded(
        tmp_path: Path,
    ) -> None:
        """``setup_logging`` writes to and records the explicit directory.

        Asserts end-to-end that the real ``intellicrack.log`` file appears in
        the explicit target, contains the emitted JSON record with correct
        fields, and that ``_logger_state.configured_log_dir`` records the same
        path for later default resolution.

        Args:
            tmp_path: pytest temporary directory.
        """
        target = tmp_path / "explicit_logs"
        logging_mod.setup_logging(_file_logging_config(), log_dir=target)
        _emit_and_flush(_UNIQUE_EVENT)

        log_file = target / "intellicrack.log"
        assert log_file.is_file()
        events = _read_logged_events(log_file)
        probe = [rec for rec in events if rec.get("event") == _UNIQUE_EVENT]
        assert len(probe) == 1
        assert probe[0]["probe"] is True
        assert probe[0]["level"] == "info"

        state = _logger_state()
        assert getattr(state, "configured_log_dir") == target

    @staticmethod
    def test_file_logging_disabled_writes_no_log_file(
        tmp_path: Path,
    ) -> None:
        """With ``file_enabled=False`` no log file is created in the target.

        Covers the error/edge dimension: the bridge between config and sinks
        must not silently produce a file when file logging is off, even though
        the directory is recorded for default resolution.

        Args:
            tmp_path: pytest temporary directory.
        """
        target = tmp_path / "disabled_logs"
        cfg = LogConfig(
            level="INFO",
            file_enabled=False,
            console_enabled=False,
            max_file_size_mb=1,
            backup_count=1,
            retention_days=1,
            json_file=True,
        )
        logging_mod.setup_logging(cfg, log_dir=target)
        _emit_and_flush(_UNIQUE_EVENT)

        assert not (target / "intellicrack.log").exists()
