# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Audit3 U4 tests for ``resource_monitor.ps1`` remediation.

Validates the two fixes applied to
``src/intellicrack/sandbox/scripts/resource_monitor.ps1``:

* F-0005 - the script honors the caller-supplied ``-LogDir`` instead of
  the hardcoded ``C:\sandbox_shared\logs`` path.
* F-0006 - the script no longer suppresses errors with a file-level
  ``$ErrorActionPreference = 'SilentlyContinue'``; ``Get-Counter``
  failures are caught explicitly and emitted as structured JSONL records
  in ``resource_monitor.errors.jsonl``.

The tests run the real script under ``pwsh`` against the live
filesystem and live performance counters. They are skipped on
non-Windows platforms.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "resource_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 4.0
_PWSH_KILL_GRACE_SEC: Final[float] = 3.0
_SAMPLE_SETTLE_SEC: Final[float] = 8.0
_LOG_NAME: Final[str] = "resource_monitor.log"
_ERROR_LOG_NAME: Final[str] = "resource_monitor.errors.jsonl"
_HARDCODED_LEGACY_LOG_DIR: Final[str] = r"C:\sandbox_shared\logs"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="resource_monitor.ps1 targets Windows performance counters",
)


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Calls ``pytest.skip`` if ``pwsh`` is not on ``PATH``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for resource_monitor tests")
    return pwsh


def _start_script(
    log_dir: Path,
    pwsh: str,
    *,
    sample_interval_seconds: int = 1,
    counter_paths: list[str] | None = None,
) -> subprocess.Popen[str]:
    """Spawn ``resource_monitor.ps1`` with the supplied parameters.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.
        sample_interval_seconds: Value forwarded as
            ``-SampleIntervalSeconds`` to keep the test loop responsive.
        counter_paths: Optional list of counter paths supplied via
            ``-CounterPaths`` (used to force counter failures).

    Returns:
        subprocess.Popen[str]: The running script process.
    """
    args: list[str] = [
        pwsh,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(_SCRIPT_PATH),
        "-LogDir",
        str(log_dir),
        "-SampleIntervalSeconds",
        str(sample_interval_seconds),
    ]
    if counter_paths:
        args.append("-CounterPaths")
        args.extend(counter_paths)
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _terminate(proc: subprocess.Popen[str]) -> tuple[str, str, int | None]:
    """Terminate the script process and collect its output.

    Args:
        proc: The running script process.

    Returns:
        tuple[str, str, int | None]: A 3-tuple ``(stdout, stderr,
        returncode)``. ``returncode`` is ``None`` when ``terminate``
        is ignored and the process must be killed.
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
    else:
        stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
    return stdout or "", stderr or "", proc.returncode


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_script_does_not_use_blanket_silentlycontinue() -> None:
    """F-0006: the file-level ``SilentlyContinue`` preference must be gone.

    The script must opt into ``$ErrorActionPreference = 'Stop'`` so that
    failed counter reads surface as catchable errors instead of being
    silently swallowed forever.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "$ErrorActionPreference = 'Stop'" in text, "script must use 'Stop' preference so counter failures are catchable"
    assert "$ErrorActionPreference = 'SilentlyContinue'" not in text, "blanket SilentlyContinue masks counter failures and is not allowed"


def test_script_does_not_hardcode_legacy_log_path() -> None:
    r"""F-0005: the hardcoded ``C:\sandbox_shared\logs`` path must be gone.

    The script must not reference the legacy hardcoded shared-folder
    location anywhere; every log write must be derived from the
    caller-supplied ``-LogDir``.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert _HARDCODED_LEGACY_LOG_DIR not in text, (
        f"legacy hardcoded path {_HARDCODED_LEGACY_LOG_DIR!r} must not appear in resource_monitor.ps1"
    )


def test_script_declares_logdir_parameter() -> None:
    """F-0005: the script must declare a ``-LogDir`` parameter."""
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "[string]$LogDir" in text, "resource_monitor.ps1 must declare -LogDir parameter"


def test_script_writes_logs_to_supplied_logdir(tmp_path: Path) -> None:
    """F-0005 runtime check: log lines must land in the supplied ``-LogDir``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "isolated_logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    proc = _start_script(log_dir, pwsh, sample_interval_seconds=1)
    try:
        time.sleep(_SAMPLE_SETTLE_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    assert log_path.exists(), f"expected log file at {log_path}; stdout={stdout!r} stderr={stderr!r} dir contents={list(log_dir.iterdir())}"
    contents = log_path.read_text(encoding="utf-8", errors="replace")
    assert contents.strip(), f"log file at {log_path} is empty; stdout={stdout!r} stderr={stderr!r}"

    legacy_dir = Path(_HARDCODED_LEGACY_LOG_DIR)
    legacy_log = legacy_dir / _LOG_NAME
    assert not legacy_log.exists() or legacy_log.stat().st_mtime < log_path.stat().st_mtime - 60, (
        "legacy hardcoded log path must not be written by this run"
    )


def _has_bogus_counter_error(error_log_text: str) -> bool:
    """Return whether the error log records a Bogus-counter failure record.

    Args:
        error_log_text: Full text of the error log file.

    Returns:
        bool: ``True`` if at least one JSONL record matches the
        expected ``stage`` and references the ``BogusCounter`` path.
    """
    for raw in error_log_text.splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        stage = payload.get("stage", "")
        counter_path = payload.get("counter_path", "")
        if stage in {"get_counter_batch", "get_counter_single"} and "BogusCounter" in counter_path:
            return True
    return False


def test_script_logs_counter_failure_instead_of_silently_continuing(
    tmp_path: Path,
) -> None:
    """F-0006 runtime check: invalid counters must be reported, not swallowed.

    Pointing ``-CounterPaths`` at a counter that does not exist must
    cause the script to write structured JSONL error records to
    ``resource_monitor.errors.jsonl`` rather than continuing to write
    bogus zeros to ``resource_monitor.log``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "err_logs"
    log_dir.mkdir()
    error_log_path = log_dir / _ERROR_LOG_NAME
    main_log_path = log_dir / _LOG_NAME

    proc = _start_script(
        log_dir,
        pwsh,
        sample_interval_seconds=1,
        counter_paths=[r"\BogusCategory(_Total)\BogusCounter"],
    )
    try:
        time.sleep(_SAMPLE_SETTLE_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    assert error_log_path.exists(), (
        f"expected error log at {error_log_path}; stdout={stdout!r} stderr={stderr!r} dir contents={list(log_dir.iterdir())}"
    )

    error_contents = error_log_path.read_text(encoding="utf-8", errors="replace").strip()
    assert error_contents, "counter failures must produce structured error records, not silent continuation"

    assert _has_bogus_counter_error(error_contents), (
        f"expected JSONL error record for the bogus counter; errors={error_contents!r} stdout={stdout!r} stderr={stderr!r}"
    )

    if main_log_path.exists():
        main_contents = main_log_path.read_text(encoding="utf-8", errors="replace").strip()
        assert not main_contents, (
            f"with no successful counter samples the main log must be empty, not filled with bogus zeros; main_contents={main_contents!r}"
        )


def test_script_emits_real_sample_lines(tmp_path: Path) -> None:
    """Smoke test: real counters produce parser-compatible pipe-delimited rows.

    The pipe-delimited format must continue to satisfy ``parse_resource_log``
    (``timestamp|cpu_percent|memory_mb|disk_read_bytes|disk_write_bytes|net_sent|net_recv``).

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    proc = _start_script(log_dir, pwsh, sample_interval_seconds=1)
    try:
        time.sleep(_SAMPLE_SETTLE_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    assert log_path.exists(), f"smoke log not created at {log_path}; stdout={stdout!r} stderr={stderr!r}"
    contents = log_path.read_text(encoding="utf-8", errors="replace").strip()
    assert contents, f"smoke log at {log_path} is empty; stdout={stdout!r} stderr={stderr!r}"

    saw_valid_row = _has_valid_sample_row(contents)

    assert saw_valid_row, f"expected at least one parser-compatible sample line; contents={contents!r}"


def _has_valid_sample_row(contents: str) -> bool:
    """Return True if any line in ``contents`` is parser-compatible.

    Args:
        contents: Raw text content of the smoke log.

    Returns:
        bool: ``True`` if at least one well-formed sample row was found.
    """
    for raw in contents.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        if _row_fields_are_numeric(parts):
            return True
    return False


_FLOAT_FIELD_INDEXES: tuple[int, ...] = (1, 2)
_INT_FIELD_INDEXES: tuple[int, ...] = (3, 4, 5, 6)


def _row_fields_are_numeric(parts: list[str]) -> bool:
    """Return True when the sample row's numeric fields parse cleanly.

    Args:
        parts: Pipe-split fields from a single sample row.

    Returns:
        bool: ``True`` when the expected numeric coercions all succeed.
    """
    try:
        for idx in _FLOAT_FIELD_INDEXES:
            float(parts[idx])
        for idx in _INT_FIELD_INDEXES:
            int(parts[idx])
    except ValueError:
        return False
    return True
