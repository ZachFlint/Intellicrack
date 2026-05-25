# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Audit3 U4 tests for ``service_monitor.ps1`` remediation.

Validates the three fixes applied to
``src/intellicrack/sandbox/scripts/service_monitor.ps1``:

* F-0007 - the script honors the caller-supplied ``-LogDir`` instead of
  the hardcoded ``C:\sandbox_shared\logs`` path.
* F-0008 - the script no longer suppresses errors with a file-level
  ``$ErrorActionPreference = 'SilentlyContinue'``; registry-read
  failures are caught explicitly and surfaced through
  ``service_monitor.errors.jsonl``.
* F-0009 - the racy 2-second polling loop is replaced by event-driven
  ``Register-CimIndicationEvent`` subscriptions on
  ``__InstanceModificationEvent``, ``__InstanceCreationEvent`` and
  ``__InstanceDeletionEvent`` for ``Win32_Service``. Every state
  transition (Stopped/StartPending/Running/StopPending/...) is logged
  in both the parser-compatible pipe-delimited log and a structured
  JSONL stream.

The tests run the real script under ``pwsh`` against the live
filesystem and the live Service Control Manager. They are skipped on
non-Windows platforms.
"""

from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final, cast

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "service_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 6.0
_PWSH_KILL_GRACE_SEC: Final[float] = 5.0
_BASELINE_SETTLE_SEC: Final[float] = 8.0
_LIFECYCLE_SETTLE_SEC: Final[float] = 6.0
_LIFECYCLE_RAPID_GAP_SEC: Final[float] = 0.4
_LOG_NAME: Final[str] = "service_monitor.log"
_JSONL_NAME: Final[str] = "service_monitor.jsonl"
_ERROR_LOG_NAME: Final[str] = "service_monitor.errors.jsonl"
_HARDCODED_LEGACY_LOG_DIR: Final[str] = r"C:\sandbox_shared\logs"
_TARGET_SERVICE: Final[str] = "Spooler"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="service_monitor.ps1 targets the Windows Service Control Manager",
)


def _is_admin() -> bool:
    """Return whether the current process has administrator privileges.

    Returns:
        bool: ``True`` if the process is elevated, ``False`` otherwise.
    """
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Calls ``pytest.skip`` if ``pwsh`` is not on ``PATH``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for service_monitor tests")
    return pwsh


def _service_exists(service_name: str, pwsh: str) -> bool:
    """Return whether a Windows service is installed.

    Args:
        service_name: Service short name (e.g. ``"Spooler"``).
        pwsh: Absolute path to ``pwsh``.

    Returns:
        bool: ``True`` if the service is registered, ``False`` otherwise.
    """
    completed = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"if (Get-Service -Name {service_name} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_PWSH_LAUNCH_TIMEOUT_SEC,
    )
    return completed.returncode == 0


def _control_service(action: str, service_name: str, pwsh: str) -> int:
    """Send ``Stop-Service`` or ``Start-Service`` against a service.

    Args:
        action: Either ``"Stop-Service"`` or ``"Start-Service"``.
        service_name: Target service short name.
        pwsh: Absolute path to ``pwsh``.

    Returns:
        int: Process return code from ``pwsh``.
    """
    cmd = f"{action} -Name {service_name} -Force -ErrorAction Stop"
    if action == "Start-Service":
        cmd = f"{action} -Name {service_name} -ErrorAction Stop"
    completed = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            cmd,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_PWSH_LAUNCH_TIMEOUT_SEC + _PWSH_KILL_GRACE_SEC,
    )
    return completed.returncode


def _drive_spooler_stop_start(pwsh: str) -> None:
    """Cycle the Spooler service through stop/start with controlled gaps.

    Args:
        pwsh: Absolute path to ``pwsh.exe`` used for the Service-Control calls.
    """
    time.sleep(_BASELINE_SETTLE_SEC)

    stop_rc = _control_service("Stop-Service", _TARGET_SERVICE, pwsh)
    assert stop_rc == 0, f"Stop-Service {_TARGET_SERVICE} failed with rc={stop_rc}"
    time.sleep(_LIFECYCLE_RAPID_GAP_SEC)
    start_rc = _control_service("Start-Service", _TARGET_SERVICE, pwsh)
    assert start_rc == 0, f"Start-Service {_TARGET_SERVICE} failed with rc={start_rc}"

    time.sleep(_LIFECYCLE_SETTLE_SEC)


def _start_script(log_dir: Path, pwsh: str) -> subprocess.Popen[str]:
    """Spawn ``service_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        subprocess.Popen[str]: The running script process.
    """
    return subprocess.Popen(
        [
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
        ],
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


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    """Read a JSONL file into a list of decoded objects.

    Skips blank lines and records that fail to decode.

    Args:
        path: Filesystem path to read.

    Returns:
        list[dict[str, object]]: Decoded JSON records.
    """
    records: list[dict[str, object]] = []
    if not path.exists():
        return records
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line.startswith("{"):
            continue
        try:
            obj: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        raw_items = cast("dict[object, object]", obj).items()
        record: dict[str, object] = {str(k): v for k, v in raw_items}
        records.append(record)
    return records


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_script_does_not_use_blanket_silentlycontinue() -> None:
    """F-0008: the file-level ``SilentlyContinue`` preference must be gone.

    The script must opt into ``$ErrorActionPreference = 'Stop'`` so that
    registry read failures and WMI subscription failures surface as
    catchable errors instead of being silently swallowed forever.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "$ErrorActionPreference = 'Stop'" in text, "script must use 'Stop' preference so registry/WMI failures are catchable"
    assert "$ErrorActionPreference = 'SilentlyContinue'" not in text, (
        "blanket SilentlyContinue masks registry-read failures and is not allowed"
    )


def test_script_does_not_hardcode_legacy_log_path() -> None:
    r"""F-0007: the hardcoded ``C:\sandbox_shared\logs`` path must be gone.

    The script must not reference the legacy hardcoded shared-folder
    location anywhere; every log write must be derived from the
    caller-supplied ``-LogDir``.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert _HARDCODED_LEGACY_LOG_DIR not in text, (
        f"legacy hardcoded path {_HARDCODED_LEGACY_LOG_DIR!r} must not appear in service_monitor.ps1"
    )


def test_script_declares_logdir_parameter() -> None:
    """F-0007: the script must declare a ``-LogDir`` parameter."""
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "[string]$LogDir" in text, "service_monitor.ps1 must declare -LogDir parameter"


def test_script_uses_event_driven_subscriptions_not_polling_loop() -> None:
    """F-0009: replace the racy polling loop with WMI event subscriptions.

    The remediated script must use ``Register-CimIndicationEvent`` (or
    ``Register-WmiEvent``) against ``__InstanceModificationEvent``,
    ``__InstanceCreationEvent`` and ``__InstanceDeletionEvent`` queries
    on ``Win32_Service``.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "Register-CimIndicationEvent" in text or "Register-WmiEvent" in text, (
        "service_monitor.ps1 must register WMI/CIM indication events instead of polling"
    )
    assert "__InstanceModificationEvent" in text, "service_monitor.ps1 must subscribe to __InstanceModificationEvent for Win32_Service"
    assert "__InstanceCreationEvent" in text, "service_monitor.ps1 must subscribe to __InstanceCreationEvent for Win32_Service"
    assert "__InstanceDeletionEvent" in text, "service_monitor.ps1 must subscribe to __InstanceDeletionEvent for Win32_Service"
    assert "ISA 'Win32_Service'" in text, "service_monitor.ps1 WQL must filter on TargetInstance ISA 'Win32_Service'"


def test_script_writes_logs_to_supplied_logdir(tmp_path: Path) -> None:
    """F-0007 runtime check: log files must land under the supplied ``-LogDir``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "isolated_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_BASELINE_SETTLE_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    log_path = log_dir / _LOG_NAME
    jsonl_path = log_dir / _JSONL_NAME

    assert log_path.exists(), f"expected pipe log at {log_path}; stdout={stdout!r} stderr={stderr!r} contents={list(log_dir.iterdir())}"
    assert jsonl_path.exists(), (
        f"expected jsonl log at {jsonl_path}; stdout={stdout!r} stderr={stderr!r} contents={list(log_dir.iterdir())}"
    )

    pipe_contents = log_path.read_text(encoding="utf-8", errors="replace").strip()
    assert pipe_contents, f"pipe log at {log_path} is empty; stdout={stdout!r} stderr={stderr!r}"

    jsonl_records = _read_jsonl(jsonl_path)
    assert any(rec.get("event") == "baseline" for rec in jsonl_records), f"expected a baseline jsonl record; records={jsonl_records!r}"
    assert any(rec.get("event") == "monitor_started" for rec in jsonl_records), (
        f"expected a monitor_started jsonl record; records={jsonl_records!r}"
    )

    legacy_dir = Path(_HARDCODED_LEGACY_LOG_DIR)
    legacy_log = legacy_dir / _LOG_NAME
    if legacy_log.exists():
        assert legacy_log.stat().st_mtime < log_path.stat().st_mtime - 60, "legacy hardcoded log path must not be written by this run"


def test_script_records_lifecycle_transitions(tmp_path: Path) -> None:
    """F-0009 runtime check: lifecycle transitions are captured event-driven.

    Spawns the monitor, then stops and immediately restarts the
    ``Spooler`` service in rapid succession (well under any 2-second
    polling window). The monitor must capture at least one transition
    event in both the pipe log (``state_changed`` operation) and the
    JSONL log (``event=modified``) for ``Spooler``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if not _is_admin():
        pytest.skip("lifecycle test requires administrator privileges to control the Spooler service")

    pwsh = _resolve_pwsh()
    if not _service_exists(_TARGET_SERVICE, pwsh):
        pytest.skip(f"target service {_TARGET_SERVICE!r} is not installed on this host")

    log_dir = tmp_path / "lifecycle_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        _drive_spooler_stop_start(pwsh)
    finally:
        stdout, stderr, _ = _terminate(proc)

    log_path = log_dir / _LOG_NAME
    jsonl_path = log_dir / _JSONL_NAME

    assert log_path.exists(), f"expected pipe log at {log_path}; stdout={stdout!r} stderr={stderr!r}"
    assert jsonl_path.exists(), f"expected jsonl log at {jsonl_path}; stdout={stdout!r} stderr={stderr!r}"

    pipe_contents = log_path.read_text(encoding="utf-8", errors="replace")
    pipe_transitions = [line for line in pipe_contents.splitlines() if "|state_changed|" in line and f"|{_TARGET_SERVICE}|" in line]
    assert pipe_transitions, f"expected at least one state_changed pipe line for {_TARGET_SERVICE}; pipe_contents={pipe_contents!r}"

    jsonl_records = _read_jsonl(jsonl_path)
    target_transitions = [rec for rec in jsonl_records if rec.get("event") == "modified" and rec.get("service") == _TARGET_SERVICE]
    assert target_transitions, f"expected at least one jsonl modified record for {_TARGET_SERVICE}; records={jsonl_records!r}"


def test_script_idempotency_dedupes_rapid_duplicate_transitions(tmp_path: Path) -> None:
    """F-0009 idempotency: identical back-to-back transitions are deduped.

    Subsequent identical state observations within 250 ms must not
    multiply log records (the in-memory ``$script:lastTransition``
    table guards against duplicate WMI emissions).

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if not _is_admin():
        pytest.skip("idempotency test requires administrator privileges to control the Spooler service")

    pwsh = _resolve_pwsh()
    if not _service_exists(_TARGET_SERVICE, pwsh):
        pytest.skip(f"target service {_TARGET_SERVICE!r} is not installed on this host")

    log_dir = tmp_path / "idempotent_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        _drive_spooler_stop_start(pwsh)
    finally:
        _terminate(proc)

    log_path = log_dir / _LOG_NAME
    pipe_contents = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""

    state_lines: dict[str, int] = {}
    for raw in pipe_contents.splitlines():
        if "|state_changed|" not in raw or f"|{_TARGET_SERVICE}|" not in raw:
            continue
        parts = raw.split("|")
        if len(parts) < 6:
            continue
        state = parts[5]
        key = f"{state}"
        state_lines[key] = state_lines.get(key, 0) + 1

    for state, count in state_lines.items():
        assert count <= 4, (
            f"transition state {state!r} was emitted {count} times for {_TARGET_SERVICE}; "
            "duplicate WMI events should be deduped within the idempotency window"
        )
