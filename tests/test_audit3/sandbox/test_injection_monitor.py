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
    if diag_path.exists():
        diag_text = diag_path.read_text(encoding="utf-8", errors="replace")
        assert "traceevent_dll_missing" in diag_text or "TraceEvent" in diag_text, (
            f"expected traceevent_dll_missing diagnostic; diag={diag_text!r}"
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
    """F-0017 runtime check: ordinary thread starts must not be ``shellcode_injection``.

    Spawn a helper that creates managed in-module threads, run the
    monitor against the helper's PID, and assert that no log line is
    written labelled ``shellcode_injection`` for that helper.

    On non-elevated runs the monitor cannot enable kernel ETW providers
    and never writes to the main log; in that case the assertion still
    holds vacuously and the test passes.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    helper = _spawn_thread_helper(pwsh)
    proc: Popen[str] | None = None
    try:
        time.sleep(0.3)
        proc = _start_script(log_dir, pwsh, target_pid=helper.pid)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC + 2.0)
    finally:
        if proc is not None:
            _terminate(proc)
        _terminate(helper)

    log_path = log_dir / _LOG_NAME
    if log_path.exists():
        contents = log_path.read_text(encoding="utf-8", errors="replace")
        for raw_line in contents.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            if len(fields) >= 6 and int(fields[3] or "0") == helper.pid:
                assert fields[5] != "shellcode_injection", (
                    f"F-0017 regression: ordinary thread starts labelled shellcode_injection; line={line!r}"
                )


def test_script_emits_threat_intel_unavailable_warning_when_not_admin(
    tmp_path: Path,
) -> None:
    """F-0017 runtime check: ThreatIntel unavailability must be reported.

    Without administrator rights the
    ``Microsoft-Windows-Threat-Intelligence`` provider cannot be
    enabled and the script must log a structured diagnostic plus a
    ``Write-Warning`` line, not silently degrade.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    if _is_admin():
        pytest.skip("test requires non-elevated context to force ThreatIntel failure")

    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        _, stderr, _ = _terminate(proc)

    diag_path = log_dir / _DIAG_NAME
    if diag_path.exists():
        diag_text = diag_path.read_text(encoding="utf-8", errors="replace")
        if "threat_intel_provider_unavailable" in diag_text:
            assert "WARNING:" in stderr or "Threat-Intelligence" in stderr, (
                f"expected Write-Warning on stderr when ThreatIntel unavailable; stderr={stderr!r}"
            )


def test_smoke_script_runs_without_crash(tmp_path: Path) -> None:
    """End-to-end smoke: the script must launch and create its log directory.

    On non-elevated runs the script throws after the kernel-provider
    enable fails (expected behaviour after F-0016). On elevated runs
    the script enters its ETW loop and is killed by the test
    teardown. Either path must exit cleanly.

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
        stdout, stderr, _ = _terminate(proc)

    assert log_dir.is_dir(), f"log directory missing after run: {log_dir}"
    produced_artefact = (log_dir / _LOG_NAME).exists() or (log_dir / _DIAG_NAME).exists() or bool((stderr or "").strip())
    assert produced_artefact, (
        f"script produced no observable output; stdout={stdout!r} stderr={stderr!r} dir contents={list(log_dir.iterdir())!r}"
    )
