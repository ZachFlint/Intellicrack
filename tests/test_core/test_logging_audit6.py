# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 CORE-D regression tests for ``intellicrack.core.logging``.

Exercises:
    * F-0016 - ``_default_log_dir`` honours the configured ``logs_directory``
      rather than always returning ``Path.cwd() / "logs"``.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

import intellicrack.core.logging as logging_mod
from intellicrack.core.config import LogConfig


if TYPE_CHECKING:
    from collections.abc import Callable


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


@pytest.fixture(autouse=True)
def reset_logger_state() -> None:
    """Reset cached logger state between tests."""
    state = _logger_state()
    setattr(state, "configured_log_dir", None)
    setattr(state, "app_logger", None)


class TestF0016DefaultLogDirHonoursConfig:
    """``_default_log_dir`` must use the configured ``logs_directory``."""

    @staticmethod
    def test_default_falls_back_to_cwd_when_no_config(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """With no config file, fall back to ``Path.cwd() / 'logs'``.

        Also verifies that ``setup_logging`` with no explicit log_dir and no
        config actually creates files under ``Path.cwd() / 'logs'`` when
        ``file_enabled=True``.

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

        result = _default_log_dir()
        assert result == Path.cwd() / "logs"

        fallback_dir = tmp_path / "fallback_logs"
        cfg = LogConfig(
            level="INFO",
            file_enabled=True,
            console_enabled=False,
            max_file_size_mb=1,
            backup_count=1,
            retention_days=1,
            json_file=False,
        )
        logging_mod.setup_logging(cfg, log_dir=fallback_dir)
        assert fallback_dir.exists(), "setup_logging must create the log directory"
        log_files = list(fallback_dir.glob("*.log"))
        assert log_files, (
            f"setup_logging with file_enabled=True must create a log file in {fallback_dir}"
        )

    @staticmethod
    def test_default_uses_configured_logs_directory(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A persisted config's ``logs_directory`` must override cwd.

        Also verifies that ``setup_logging`` with ``file_enabled=True`` creates
        the log file under the directory resolved from the config.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: pytest temporary directory.
        """
        config_module = importlib.import_module("intellicrack.core.config")
        config_dir = tmp_path / "intellicrack_config"
        config_dir.mkdir()
        target_logs = tmp_path / "configured_logs"

        config_path = config_dir / "config.toml"
        config_path.write_text(
            f"""\
[general]
tools_directory = "{(tmp_path / "tools").as_posix()}"
logs_directory = "{target_logs.as_posix()}"
data_directory = "{(tmp_path / "data").as_posix()}"
default_provider = "anthropic"
confirmation_level = "destructive"
""",
            encoding="utf-8",
        )

        monkeypatch.setattr(config_module, "get_config_dir", lambda: config_dir)

        result = _default_log_dir()
        assert result == target_logs

        cfg = LogConfig(
            level="INFO",
            file_enabled=True,
            console_enabled=False,
            max_file_size_mb=1,
            backup_count=1,
            retention_days=1,
            json_file=False,
        )
        logging_mod.setup_logging(cfg, log_dir=target_logs)
        assert target_logs.exists(), "setup_logging must create the configured log directory"
        log_files = list(target_logs.glob("*.log"))
        assert log_files, (
            f"setup_logging with file_enabled=True must create a log file in {target_logs}"
        )

    @staticmethod
    def test_default_uses_state_after_setup_logging(
        tmp_path: Path,
    ) -> None:
        """After ``setup_logging`` records a log dir, the default uses it.

        Also verifies that the log directory is physically created and that a
        log file appears there when ``file_enabled=True``.

        Args:
            tmp_path: pytest temporary directory.
        """
        target_logs = tmp_path / "via_state"
        cfg_file = LogConfig(
            level="INFO",
            file_enabled=True,
            console_enabled=False,
            max_file_size_mb=1,
            backup_count=1,
            retention_days=1,
            json_file=False,
        )
        logging_mod.setup_logging(cfg_file, log_dir=target_logs)

        result = _default_log_dir()
        assert result == target_logs
        assert target_logs.exists(), "setup_logging must create the log directory"
        log_files = list(target_logs.glob("*.log"))
        assert log_files, (
            f"setup_logging with file_enabled=True must write a log file to {target_logs}"
        )

    @staticmethod
    def test_setup_logging_records_resolved_dir(
        tmp_path: Path,
    ) -> None:
        """``setup_logging`` must update ``_logger_state.configured_log_dir``.

        Also verifies that the resolved directory is physically created when
        ``file_enabled=True`` so the state update is backed by real I/O, not
        just an in-memory write.

        Args:
            tmp_path: pytest temporary directory.
        """
        target = tmp_path / "explicit_logs"
        cfg = LogConfig(
            level="INFO",
            file_enabled=True,
            console_enabled=False,
            max_file_size_mb=1,
            backup_count=1,
            retention_days=1,
            json_file=False,
        )
        logging_mod.setup_logging(cfg, log_dir=target)

        state = _logger_state()
        assert getattr(state, "configured_log_dir") == target
        assert target.exists(), "configured log directory must exist after setup_logging"
        log_files = list(target.glob("*.log"))
        assert log_files, (
            f"setup_logging must create a log file in the target directory {target}"
        )
