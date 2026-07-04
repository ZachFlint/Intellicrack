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
import sys
import time
from pathlib import Path
from typing import Final, cast

import pytest

from intellicrack.core.subprocess_compat import (
    PIPE,
    Popen,
    TimeoutExpired,
    run,
)


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
    completed = run(
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
    completed = run(
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


def _start_script(log_dir: Path, pwsh: str) -> Popen[str]:
    """Spawn ``service_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        Popen[str]: The running script process.
    """
    return Popen(
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
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _terminate(proc: Popen[str]) -> tuple[str, str, int | None]:
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
        except TimeoutExpired:
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


def _build_dedup_harness(log_dir: Path) -> str:
    """Construct a PowerShell harness that exercises the dedup logic.

    Extracts the exact function bodies from the production
    ``service_monitor.ps1`` (verbatim, not reimplemented) and assembles
    a standalone script that:

    1. Calls ``Publish-LifecycleTransition`` five times in rapid
       succession with identical (service, state) inputs.
    2. Sleeps 350 ms (> 250 ms dedup window).
    3. Calls ``Publish-LifecycleTransition`` once more.
    4. Prints the total JSONL record count to stdout.

    The expected count is **2**: one from the first burst (the four
    duplicates are suppressed) and one after the window expires.

    Args:
        log_dir: Writable directory for JSONL/pipe/error log files.

    Returns:
        str: Full PowerShell script text for the harness.
    """
    script_text = _SCRIPT_PATH.read_text(encoding="utf-8")

    log_path_ps = str(log_dir / _LOG_NAME).replace("\\", "/")
    jsonl_path_ps = str(log_dir / _JSONL_NAME).replace("\\", "/")
    error_path_ps = str(log_dir / _ERROR_LOG_NAME).replace("\\", "/")

    harness_lines = [
        "$ErrorActionPreference = 'Stop'",
        f"$logPath     = '{log_path_ps}'",
        f"$jsonlPath   = '{jsonl_path_ps}'",
        f"$errorLogPath = '{error_path_ps}'",
        "$script:lastTransition   = @{}",
        "$script:duplicateWindowMs = 250",
        "",
    ]

    func_names = [
        "Format-Field",
        "Write-ErrorRecord",
        "Write-PipeRecord",
        "Write-JsonlRecord",
        "ConvertTo-StateName",
        "Test-DuplicateTransition",
        "Publish-LifecycleTransition",
    ]

    lines = script_text.splitlines()
    for func_name in func_names:
        start_idx: int | None = next(
            (i for i, line in enumerate(lines) if line.strip().startswith(f"function {func_name}")),
            None,
        )
        assert start_idx is not None, f"function {func_name} not found in {_SCRIPT_PATH}"

        brace_depth = 0
        end_idx: int | None = None
        for j in range(start_idx, len(lines)):
            brace_depth += lines[j].count("{") - lines[j].count("}")
            if brace_depth <= 0 and j > start_idx:
                end_idx = j
                break
        assert end_idx is not None, f"function {func_name} body not closed in {_SCRIPT_PATH}"

        harness_lines.extend(lines[start_idx : end_idx + 1])
        harness_lines.append("")

    harness_lines.extend([
        "$syntheticSvc = [PSCustomObject]@{",
        "    Name        = 'TestDedup'",
        "    DisplayName = 'Test Dedup Service'",
        "    PathName    = 'C:/Windows/test.exe'",
        "    StartMode   = 'Auto'",
        "    State       = 'Stopped'",
        "}",
        "",
        "for ($i = 0; $i -lt 5; $i++) {",
        "    Publish-LifecycleTransition -Instance $syntheticSvc -EventKind 'modified'",
        "}",
        "",
        "Start-Sleep -Milliseconds 350",
        "",
        "Publish-LifecycleTransition -Instance $syntheticSvc -EventKind 'modified'",
        "",
        "$jsonlContent = if (Test-Path -LiteralPath $jsonlPath) {",
        "    Get-Content -LiteralPath $jsonlPath -Raw -Encoding utf8",
        "} else { '' }",
        "$count = ($jsonlContent.Trim().Split(\"`n\") | Where-Object { $_.Trim().StartsWith('{') }).Count",
        'Write-Output "DEDUP_COUNT=$count"',
    ])

    return "\n".join(harness_lines)


def test_script_idempotency_dedupes_rapid_duplicate_transitions(tmp_path: Path) -> None:
    """F-0009 idempotency: identical back-to-back transitions are deduped.

    Runs a PowerShell harness that loads the exact production function
    bodies from ``service_monitor.ps1`` verbatim (not reimplemented)
    and exercises ``Publish-LifecycleTransition`` with five rapid
    back-to-back calls sharing the same ``(service, state)`` key,
    followed by a 350 ms pause and one additional call.

    Independent oracle: the JSONL record count emitted by the harness
    must equal **2** (one from the first burst, one after the dedup
    window expires). Under the documented production mutation --- removing
    the ``Test-DuplicateTransition`` guard at line 196 of
    ``service_monitor.ps1`` so that ``Publish-LifecycleTransition``
    writes a record on every call --- all six calls write JSONL records,
    yielding a count of 6, which fails the ``== 2`` assertion.

    Documented falsifying mutation: in ``service_monitor.ps1`` at
    line 196, remove ``if (Test-DuplicateTransition -ServiceName
    $serviceName -State "$EventKind::$stateName") { return }``.  Under
    that mutation the harness emits 6 JSONL records and the assertion
    ``count == 2`` fails.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "dedup_harness_logs"
    log_dir.mkdir()

    harness_text = _build_dedup_harness(log_dir)
    harness_path = tmp_path / "dedup_harness.ps1"
    harness_path.write_text(harness_text, encoding="utf-8")

    completed = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(harness_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=15.0,
    )

    assert completed.returncode == 0, (
        f"dedup harness exited with rc={completed.returncode}; stderr={completed.stderr!r}; stdout={completed.stdout!r}"
    )

    count_line = next(
        (ln for ln in completed.stdout.splitlines() if ln.startswith("DEDUP_COUNT=")),
        None,
    )
    assert count_line is not None, f"harness did not emit DEDUP_COUNT= line; stdout={completed.stdout!r} stderr={completed.stderr!r}"

    actual_count = int(count_line.split("=", 1)[1].strip())

    assert actual_count == 2, (
        f"dedup gate FAILED: expected 2 JSONL records (1 from initial burst + 1 after "
        f"window expiry) but got {actual_count}. "
        f"The Test-DuplicateTransition guard in Publish-LifecycleTransition "
        f"(service_monitor.ps1 line 196) is not suppressing rapid duplicate events. "
        f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )
