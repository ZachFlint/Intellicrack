# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U6 tests for ``dll_monitor.ps1`` remediation.

Validates the three fixes applied to
``src/intellicrack/sandbox/scripts/dll_monitor.ps1``:

* F-0018 - the file-mode logman session that collided with the realtime
  TraceEventSession is removed; only the realtime path remains.
* F-0019 - events whose payload field set is unrecognised are recorded
  as ``dll_event_unparsed`` diagnostic lines instead of being silently
  dropped.
* F-0020 - when ETW is unavailable and the script falls back to WMI it
  emits both a ``Write-Warning`` line and a structured
  ``etw_unavailable_falling_back_to_wmi`` diagnostic record.

Tests run the real script under ``pwsh`` against the live filesystem
and Windows ETW/WMI subsystems. They are skipped on non-Windows
platforms because the script targets Windows-only telemetry providers.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "dll_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 4.0
_PWSH_KILL_GRACE_SEC: Final[float] = 3.0
_LOG_NAME: Final[str] = "dll_monitor.log"
_DIAG_NAME: Final[str] = "dll_monitor.diag.log"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="dll_monitor.ps1 targets Windows ETW/WMI providers",
)


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Calls ``pytest.skip`` if ``pwsh`` is not on ``PATH``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for dll_monitor tests")
    return pwsh


def _is_admin() -> bool:
    """Return whether the current process holds administrator rights.

    Returns:
        bool: ``True`` if the current process is elevated, otherwise
        ``False``. Returns ``False`` on any API failure.
    """
    try:
        shell32 = ctypes.WinDLL("shell32")
        is_admin = shell32.IsUserAnAdmin
        is_admin.argtypes = []
        is_admin.restype = ctypes.c_bool
        return bool(is_admin())
    except (OSError, AttributeError):
        return False


def _start_script(
    log_dir: Path,
    pwsh: str,
    target_pid: int = 0,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    """Spawn ``dll_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.
        target_pid: Optional PID to filter on (0 = all processes).
        extra_env: Additional environment variables to merge into the
            child process environment.

    Returns:
        subprocess.Popen[str]: The running script process.
    """
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
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
            "-TargetPid",
            str(target_pid),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _terminate(proc: subprocess.Popen[str]) -> tuple[str, str, int | None]:
    """Terminate the script process and collect its output.

    Args:
        proc: The running script process.

    Returns:
        tuple[str, str, int | None]: A 3-tuple ``(stdout, stderr,
        returncode)``. ``returncode`` is ``None`` if the process had to
        be killed because it ignored ``terminate``.
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


def _spawn_dll_load_helper(pwsh: str) -> subprocess.Popen[str]:
    """Spawn a helper process that periodically loads a Windows DLL.

    The helper invokes ``LoadLibraryW`` against ``user32.dll`` (already
    typically loaded but the call still emits an ETW image-load event
    on first reference) and ``imm32.dll`` (commonly not pre-loaded), in
    a loop, so the dll_monitor has live events to observe.

    Args:
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        subprocess.Popen[str]: The running helper process.
    """
    helper_script = (
        '$sig = \'[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] '
        "public static extern System.IntPtr LoadLibraryW(string lpFileName);';"
        "Add-Type -MemberDefinition $sig -Name 'Native' -Namespace 'AuditDllMon' -PassThru | Out-Null;"
        "for($i=0;$i -lt 30;$i++){"
        "[AuditDllMon.Native]::LoadLibraryW('imm32.dll') | Out-Null;"
        "[AuditDllMon.Native]::LoadLibraryW('winmm.dll') | Out-Null;"
        "[AuditDllMon.Native]::LoadLibraryW('user32.dll') | Out-Null;"
        "Start-Sleep -Milliseconds 200}"
    )
    return subprocess.Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            helper_script,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_script_no_longer_creates_file_mode_logman_session() -> None:
    """F-0018: file-mode ``logman create trace`` invocation must be gone.

    The remediated script uses only realtime ``TraceEventSession``; any
    use of ``logman`` would re-introduce the session-name collision.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "logman" not in text, "dll_monitor.ps1 must not invoke logman; realtime-only after F-0018"
    assert "EnableProvider" in text, "expected realtime EnableProvider call after F-0018"


def test_script_logs_unparsed_events_instead_of_silently_returning() -> None:
    """F-0019: the image-load handler must log ``dll_event_unparsed``.

    The remediated script must call ``Write-DllDiagnostic`` with
    ``dll_event_unparsed`` whenever a payload field set is unrecognised
    so future tuning has data, instead of silently ``return``ing.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "dll_event_unparsed" in text, "expected dll_event_unparsed diagnostic category after F-0019"
    assert "Write-DllDiagnostic" in text, "expected Write-DllDiagnostic helper after F-0019"


def test_script_emits_structured_unparsed_record_to_main_log() -> None:
    """F-0019 (audit7): unparsed events must reach the main log too.

    The remediated handler does not stop at a diagnostic-log entry.
    When the payload schema is unrecognised it now also writes a
    structured record to ``dll_monitor.log`` with ``image_path=`` empty,
    the raw ``event_id``, and the observed ``payload_schema`` so the
    report consumer can see the dropped event.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "-EventId $eventIdValue -PayloadSchema $fields" in text, (
        "unparsed branch must call Write-DllRecord with EventId and PayloadSchema"
    )
    assert "-ImagePath ''" in text, "unparsed records must use empty image path"
    assert "PayloadSchema" in text, "Write-DllRecord must accept PayloadSchema"
    assert "EventId" in text, "Write-DllRecord must accept EventId"


def test_script_auto_extends_payload_field_candidates() -> None:
    """F-0019 (audit7): observed payload fields must be auto-cached.

    The handler must dynamically extend the candidate field name lists
    so subsequent events with non-default payload schemas are parsed
    correctly. The implementation registers the new names against the
    ``ImagePathFieldNames`` / ``ImageBaseFieldNames`` / ``ImageSizeFieldNames``
    script-scope collections.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "Sync-PayloadFieldCandidate" in text, "expected Sync-PayloadFieldCandidate helper"
    assert "script:ImagePathFieldNames.Add" in text, "auto-extension must mutate the path field list"
    assert "Import-ProviderManifestField" in text, "expected manifest-driven field bootstrap helper"


def test_script_logs_etw_fallback_warning() -> None:
    """F-0020: the WMI fallback must surface a structured warning.

    Both a ``Write-Warning`` and an
    ``etw_unavailable_falling_back_to_wmi`` diagnostic line are
    required so degraded mode is visible to operators.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "etw_unavailable_falling_back_to_wmi" in text, "expected fallback diagnostic category after F-0020"
    assert "Write-Warning" in text, "expected Write-Warning on WMI fallback after F-0020"


def test_script_emits_fallback_diagnostic_when_etw_unavailable(tmp_path: Path) -> None:
    """F-0020 runtime check: forcing ETW unavailability triggers the diagnostic.

    We force ``Test-TraceEventAvailable`` to fail by running a poisoned
    copy of the script that returns ``$false`` from that helper, and
    assert a ``etw_unavailable_falling_back_to_wmi`` diagnostic record
    plus a ``WARNING:`` line on stderr.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    original = _SCRIPT_PATH.read_text(encoding="utf-8")
    poisoned = original.replace(
        "if (-not (Test-TraceEventAvailable)) {",
        "if ($true) {",
        1,
    )
    assert poisoned != original, "failed to inject ETW unavailability"

    poisoned_script = tmp_path / "dll_monitor_poisoned.ps1"
    poisoned_script.write_text(poisoned, encoding="utf-8")

    proc = subprocess.Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(poisoned_script),
            "-LogDir",
            str(log_dir),
            "-TargetPid",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    diag_path = log_dir / _DIAG_NAME
    assert diag_path.exists(), f"expected diagnostic log at {diag_path}; stdout={stdout!r} stderr={stderr!r}"
    diag_contents = diag_path.read_text(encoding="utf-8", errors="replace")
    assert "etw_unavailable_falling_back_to_wmi" in diag_contents, f"expected fallback diagnostic in {diag_contents!r}; stderr={stderr!r}"
    assert "WARNING:" in stderr or "WARNING:" in stdout or "etw_unavailable_falling_back_to_wmi" in stderr, (
        f"expected Write-Warning output on stderr; stdout={stdout!r} stderr={stderr!r}"
    )


def test_smoke_script_runs_and_writes_logs(tmp_path: Path) -> None:
    """End-to-end smoke: the script must start and create its log directory.

    On non-elevated runs the script may fall back to WMI; on elevated
    runs it uses realtime ETW. Either path is acceptable for smoke -
    the assertion is that the log directory exists and the script
    produced some on-disk artefact (either the main log, the diagnostic
    log, or a warning on stderr).

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    helper: subprocess.Popen[str] | None = None
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        helper = _spawn_dll_load_helper(pwsh)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC + 1.0)
    finally:
        if helper is not None:
            _terminate(helper)
        stdout, stderr, _ = _terminate(proc)

    assert log_dir.is_dir(), f"log directory missing after run: {log_dir}"
    log_path = log_dir / _LOG_NAME
    diag_path = log_dir / _DIAG_NAME
    produced_artefact = log_path.exists() or diag_path.exists() or bool((stderr or "").strip())
    assert produced_artefact, (
        f"script produced no observable output; stdout={stdout!r} stderr={stderr!r} dir contents={list(log_dir.iterdir())!r}"
    )


def test_etw_load_event_is_captured_when_admin(tmp_path: Path) -> None:
    """F-0019 runtime check: a real DLL load should not be silently dropped.

    When the test runner has administrator rights, the realtime
    ``TraceEventSession`` path must produce either a parsed
    ``dll_monitor.log`` line for the helper's image loads or, if the
    payload format is unexpected for this Windows build, a
    ``dll_event_unparsed`` diagnostic. A completely empty log directory
    (no main log, no diagnostic log) would indicate F-0019 has
    regressed.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if not _is_admin():
        pytest.skip("realtime ETW kernel-process provider requires administrator rights")

    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "etw_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    helper: subprocess.Popen[str] | None = None
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        helper = _spawn_dll_load_helper(pwsh)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC + 2.0)
    finally:
        if helper is not None:
            _terminate(helper)
        stdout, stderr, _ = _terminate(proc)

    log_path = log_dir / _LOG_NAME
    diag_path = log_dir / _DIAG_NAME

    main_has_lines = log_path.exists() and bool(log_path.read_text(encoding="utf-8", errors="replace").strip())
    diag_text = diag_path.read_text(encoding="utf-8", errors="replace") if diag_path.exists() else ""
    saw_unparsed = "dll_event_unparsed" in diag_text
    saw_handler_attempt = main_has_lines or saw_unparsed

    assert saw_handler_attempt, (
        "F-0019 regression: real DLL loads were neither parsed nor logged as "
        f"dll_event_unparsed; stdout={stdout!r} stderr={stderr!r} "
        f"main_log_exists={log_path.exists()} diag_text={diag_text!r}"
    )
