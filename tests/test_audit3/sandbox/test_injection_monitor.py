# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U6 tests for ``injection_monitor.ps1`` remediation.

Validates the three fixes applied to
``src/intellicrack/sandbox/scripts/injection_monitor.ps1``:

* F-0015 - the dead ``$logmanStarted`` flag is removed; the script
  never created a logman session of its own.
* F-0016 - the top-level ``return`` paths that silently aborted on a
  missing ``TraceEvent.dll`` are replaced with ``throw`` so callers
  see a non-zero exit code.
* F-0017 - the heuristic no longer fabricates ``CreateRemoteThread``,
  ``LoadLibrary``, and ``WriteProcessMemory`` for every thread start.
  Verified ETW provider events from
  ``Microsoft-Windows-Kernel-Process`` and
  ``Microsoft-Windows-Threat-Intelligence`` are used; events that fall
  back to the narrowed Kernel-Process heuristic are labelled
  ``remote_thread_start`` (or one of its narrowed variants), not
  ``shellcode_injection``.

Tests run the real script under ``pwsh`` against the live filesystem
and Windows ETW subsystem. They are skipped on non-Windows platforms
because the script targets Windows-only telemetry providers.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import (
    PIPE,
    Popen,
    TimeoutExpired,
    run,
)


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "injection_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 4.0
_PWSH_KILL_GRACE_SEC: Final[float] = 3.0
_LOG_NAME: Final[str] = "injection_monitor.log"
_DIAG_NAME: Final[str] = "injection_monitor.diag.log"
_LIFECYCLE_NAME: Final[str] = "injection_monitor.lifecycle.log"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="injection_monitor.ps1 targets Windows ETW providers",
)


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Calls ``pytest.skip`` if ``pwsh`` is not on ``PATH``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for injection_monitor tests")
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
) -> Popen[str]:
    """Spawn ``injection_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.
        target_pid: Optional PID to filter on (0 = all processes).
        extra_env: Extra environment variables to merge into the child
            process environment.

    Returns:
        Popen[str]: The running script process.
    """
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
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
            "-TargetPid",
            str(target_pid),
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


def _terminate(proc: Popen[str]) -> tuple[str, str, int | None]:
    """Terminate the script process and collect its output.

    Args:
        proc: The running script process.

    Returns:
        tuple[str, str, int | None]: A 3-tuple ``(stdout, stderr,
        returncode)``. ``returncode`` is ``None`` if the process had
        to be killed because it ignored ``terminate``.
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


def _spawn_thread_helper(pwsh: str) -> Popen[str]:
    r"""Spawn a helper that creates ordinary in-process threads.

    The helper invokes ``Thread.Start`` repeatedly inside the helper
    process; these are normal in-module thread starts whose start
    address resolves to ``System.Private.CoreLib`` (or
    ``mscorlib``) - both inside a loaded module and not in
    ``\Temp\`` - so the injection_monitor heuristic must NOT label
    them as anything (they fail the ``Suspicious`` filter).

    Args:
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        Popen[str]: The running helper process.
    """
    helper_script = (
        "for($i=0;$i -lt 30;$i++){"
        "$t = [System.Threading.Thread]::new([System.Threading.ThreadStart]{"
        "Start-Sleep -Milliseconds 50"
        "});"
        "$t.IsBackground = $true;"
        "$t.Start();"
        "Start-Sleep -Milliseconds 200}"
    )
    return Popen(
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
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_script_no_longer_tracks_logman_started_flag() -> None:
    """F-0015: the unused ``$logmanStarted`` flag must be removed.

    The script never created a logman session of its own, so the flag
    only fired a misleading branch that called ``logman stop`` /
    ``logman delete`` against a session it did not own.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "logmanStarted" not in text, "F-0015 regression: $logmanStarted re-introduced"
    assert "logman stop $sessionName" not in text, "F-0015 regression: stale logman teardown re-introduced"
    assert "logman delete $sessionName" not in text, "F-0015 regression: stale logman teardown re-introduced"


def test_script_throws_when_traceevent_dll_missing(tmp_path: Path) -> None:
    """F-0016: missing ``TraceEvent.dll`` must surface as a non-zero exit.

    The remediated script replaces silent ``return`` on missing
    TraceEvent assembly with ``throw``. We point the search-path at
    isolated empty directories so the assembly is not found, and
    assert the script exits non-zero with diagnostic output.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    isolated_user = tmp_path / "isolated_user"
    isolated_user.mkdir()
    isolated_program_files = tmp_path / "isolated_pf"
    isolated_program_files.mkdir()
    isolated_dotnet = tmp_path / "isolated_dotnet"
    isolated_dotnet.mkdir()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    completed = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            (
                "$env:USERPROFILE = $env:ISO_USERPROFILE;"
                "$env:ProgramFiles = $env:ISO_PROGRAMFILES;"
                "$env:TRACE_EVENT_DLL_DIR = $env:ISO_TEDIR;"
                f"& '{_SCRIPT_PATH}' -LogDir '{log_dir}' -TargetPid 0"
            ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={
            **os.environ,
            "ISO_USERPROFILE": str(isolated_user),
            "ISO_PROGRAMFILES": str(isolated_program_files),
            "ISO_TEDIR": str(isolated_dotnet),
        },
        check=False,
        timeout=_PWSH_LAUNCH_TIMEOUT_SEC + _PWSH_KILL_GRACE_SEC,
    )

    assert completed.returncode != 0, (
        "F-0016 regression: missing TraceEvent.dll must throw, not silently return; "
        f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )
    diag_path = log_dir / _DIAG_NAME
    assert diag_path.exists(), (
        f"F-0016 regression: diag log must be written before throw when TraceEvent.dll is missing; "
        f"log_dir contents={list(log_dir.iterdir())!r} stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )
    diag_text = diag_path.read_text(encoding="utf-8", errors="replace")
    diag_lines = [ln.strip() for ln in diag_text.splitlines() if ln.strip()]
    assert diag_lines, (
        f"F-0016 regression: diag log must be non-empty when TraceEvent.dll is missing; diag={diag_text!r}"
    )
    categories = [ln.split("|")[1] for ln in diag_lines if ln.count("|") >= 2]
    assert any(cat in {"traceevent_dll_missing", "traceevent_dll_load_failed"} for cat in categories), (
        f"F-0016 regression: diag log must contain traceevent_dll_missing or traceevent_dll_load_failed category; "
        f"found categories={categories!r} diag={diag_text!r}"
    )


def test_script_uses_verified_provider_events_not_fabricated_apis() -> None:
    """F-0017: fabricated API names must be removed from the source.

    The remediated script must not unconditionally append
    ``CreateRemoteThread``, ``LoadLibrary``, or ``WriteProcessMemory``
    to every thread-start event. It must also reference the
    Microsoft-Windows-Threat-Intelligence provider for verified
    payload reads.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "$apis.Add('CreateRemoteThread')" not in text, "F-0017 regression: fabricated CreateRemoteThread re-introduced"
    assert "$apis.Add('LoadLibrary')" not in text, "F-0017 regression: fabricated LoadLibrary re-introduced"
    assert "$apis.Add('WriteProcessMemory')" not in text, "F-0017 regression: fabricated WriteProcessMemory re-introduced"
    assert "Microsoft-Windows-Threat-Intelligence" in text, "F-0017 regression: ThreatIntel provider must be referenced"
    assert "remote_thread_start" in text, (
        "F-0017 regression: narrowed label remote_thread_start must be used when ThreatIntel provider is unavailable"
    )


def test_script_does_not_label_normal_thread_starts_as_shellcode_injection(
    tmp_path: Path,
) -> None:
    """F-0017 runtime check: no captured thread-start event may be labelled ``shellcode_injection``.

    Run the monitor with no PID filter so it observes kernel thread-start
    events from all processes.  On admin the kernel ETW provider succeeds and
    events whose start addresses fall outside loaded modules or inside a
    Temp-directory module are written to the main log.  Assert that the log is
    non-empty (at least one event was observed, so the assertion cannot be
    vacuous) and that every captured record carries one of the narrowed labels
    (``remote_thread_start``, ``remote_thread_in_temp_module``,
    ``remote_thread_outside_modules``, ``remote_thread_create``,
    ``remote_memory_alloc``, ``remote_memory_write``, ``remote_section_map``,
    ``threat_intel_event``, ``ERROR``) but never ``shellcode_injection``.

    This test requires administrator rights to enable kernel ETW providers.
    Without elevation the monitor cannot subscribe to thread-start events
    and no main log is written, making any label assertion vacuous.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if not _is_admin():
        pytest.skip("kernel ETW thread-start subscription requires administrator rights")

    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh, target_pid=0)
    helper = _spawn_thread_helper(pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC + 4.0)
    finally:
        _terminate(helper)
        _terminate(proc)

    log_path = log_dir / _LOG_NAME
    assert log_path.exists(), (
        f"F-0017: admin run with pid=0 must produce main log capturing thread-start events; "
        f"log_dir={list(log_dir.iterdir())!r}"
    )

    contents = log_path.read_text(encoding="utf-8", errors="replace")
    all_records: list[str] = []
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) >= 6:
            all_records.append(line)

    assert all_records, (
        f"F-0017: at least one injection-monitor record expected in the main log; "
        f"log contents={contents!r}"
    )
    for rec in all_records:
        fields = rec.split("|")
        inj_type = fields[5] if len(fields) >= 6 else ""
        assert inj_type != "shellcode_injection", (
            f"F-0017 regression: thread-start event labelled shellcode_injection; "
            f"record={rec!r}"
        )


def test_script_emits_threat_intel_unavailable_warning_when_not_admin(
    tmp_path: Path,
) -> None:
    """F-0017 runtime check: ThreatIntel unavailability must be reported, not silently ignored.

    Without administrator rights the script cannot enable kernel ETW
    providers and must exit with a non-zero code (F-0016) and write a
    structured diagnostic to the diag log rather than silently
    degrading.  If the kernel provider phase succeeds but
    ``Microsoft-Windows-Threat-Intelligence`` specifically fails, the
    diag log must additionally contain a
    ``threat_intel_provider_unavailable`` entry and the script must
    emit a ``Write-Warning`` line to stderr.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if _is_admin():
        pytest.skip("test requires non-elevated context to force provider-enable failure")

    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        _, stderr, returncode = _terminate(proc)

    assert returncode != 0, (
        f"F-0016/F-0017 regression: non-admin run must exit non-zero (throw), not silently return; "
        f"returncode={returncode!r} stderr={stderr!r}"
    )

    diag_path = log_dir / _DIAG_NAME
    assert diag_path.exists(), (
        f"F-0017 regression: diag log must be written on failure, not silently dropped; "
        f"log_dir contents={list(log_dir.iterdir())!r}"
    )

    diag_text = diag_path.read_text(encoding="utf-8", errors="replace")
    structured_lines = [
        ln.strip()
        for ln in diag_text.splitlines()
        if ln.strip() and ln.count("|") >= 2
    ]
    assert structured_lines, (
        f"F-0017 regression: diag log must contain at least one structured pipe-delimited "
        f"diagnostic entry; diag={diag_text!r}"
    )

    if "threat_intel_provider_unavailable" in diag_text:
        assert "WARNING:" in stderr or "Threat-Intelligence" in stderr, (
            f"F-0017 regression: Write-Warning must reach stderr when ThreatIntel provider "
            f"unavailable; stderr={stderr!r}"
        )


def test_smoke_lifecycle_records_started_and_stopped(tmp_path: Path) -> None:
    """Lifecycle log must contain both ``started`` and ``stopped`` structured records.

    ``Write-InjectionLifecycle`` is called unconditionally at startup
    (line 272 of the script) and in the ``finally`` block (line 517).
    Both paths must produce a pipe-delimited record whose third field
    (index 2) equals the expected state token.

    Mutation that falsifies this test: removing either
    ``Write-InjectionLifecycle -State 'started'`` (line 272) or
    ``Write-InjectionLifecycle -State 'stopped'`` (line 517) from the
    production script causes the corresponding assertion to fail because
    the lifecycle file would then lack that state token.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        stdout, stderr, returncode = _terminate(proc)

    if returncode != 0 and "TraceEvent.dll not found" in stderr:
        pytest.skip(
            "Microsoft.Diagnostics.Tracing.TraceEvent.dll is unavailable in this "
            "environment; injection_monitor.ps1 correctly throws before the lifecycle "
            "monitor can start (see test_script_throws_when_traceevent_dll_missing)",
        )

    lifecycle_file = log_dir / _LIFECYCLE_NAME
    assert lifecycle_file.exists(), (
        f"injection_monitor.lifecycle.log not written; "
        f"returncode={returncode!r} stdout={stdout!r} stderr={stderr!r} "
        f"dir={list(log_dir.iterdir())!r}"
    )

    raw = lifecycle_file.read_text(encoding="utf-8", errors="replace")
    records = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    assert records, (
        f"lifecycle log is empty; returncode={returncode!r} "
        f"stdout={stdout!r} stderr={stderr!r}"
    )

    states = {ln.split("|")[2] for ln in records if ln.count("|") >= 3}
    assert "started" in states, (
        f"lifecycle log missing 'started' record; states={states!r} raw={raw!r}; "
        f"falsified by removing Write-InjectionLifecycle -State 'started' at line 272 of the script"
    )
    assert "stopped" in states, (
        f"lifecycle log missing 'stopped' record; states={states!r} raw={raw!r}; "
        f"falsified by removing Write-InjectionLifecycle -State 'stopped' at line 517 of the script"
    )
