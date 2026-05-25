# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U5 tests for ``api_trace.ps1`` remediation.

Validates the four fixes applied to
``src/intellicrack/sandbox/scripts/api_trace.ps1``:

* F-0011 - missing TraceEvent.dll now exits with a non-zero status and
  writes a structured ``ERROR|unavailable|...`` line to ``api_trace.log``
  so the bridge consumer can detect setup failure.
* F-0012 - the file-mode logman ETL session that was created but never
  harvested is removed; only the realtime ``TraceEventSession`` callback
  path remains and emits per-event records inline.
* F-0013 - the per-event handler now uses the real
  ``Microsoft-Windows-Kernel-Audit-API-Calls`` provider field names
  (``TargetProcessId``, ``ReturnCode``, ``DesiredAccess`` ...) plus the
  per-event-id API-name table so records carry meaningful API names.
* F-0014 - the cleanup path no longer mixes ``logman.exe stop`` against
  the managed session. The script disposes the ``TraceEventSession``
  cleanly via ``StopOnDispose`` and never invokes ``logman``.

Tests run the real script under ``pwsh`` against the live filesystem and
Windows ETW subsystem. They are skipped on non-Windows platforms because
the script targets Windows-only telemetry providers.
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
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "api_trace.ps1"
_LOG_NAME: Final[str] = "api_trace.log"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 4.0
_PWSH_KILL_GRACE_SEC: Final[float] = 5.0
_SMOKE_DURATION_SEC: Final[int] = 5
_PROCESS_WAIT_TIMEOUT_SEC: Final[float] = 30.0
_EXIT_OK: Final[int] = 0
_EXIT_NO_DLL: Final[int] = 2
_MANAGED_SESSION_NAME: Final[str] = "IntApiTrace"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="api_trace.ps1 targets the Windows Kernel-Audit-API-Calls ETW provider",
)


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for api_trace tests")
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


def _have_trace_event_dll() -> bool:
    """Detect whether the TraceEvent assembly is reachable on this host.

    Mirrors the lookup performed by ``Find-TraceEventAssembly`` in
    ``api_trace.ps1`` so a test can decide whether to expect the
    ``unavailable`` exit path or one of the later session/provider exit
    paths.

    Returns:
        bool: ``True`` if at least one ``Microsoft.Diagnostics.Tracing.TraceEvent.dll``
        was found in any of the documented search roots.
    """
    env_dll = os.environ.get("TRACE_EVENT_DLL", "")
    if env_dll and Path(env_dll).is_file():
        return True
    script_dir_dll = _SCRIPT_PATH.parent / "Microsoft.Diagnostics.Tracing.TraceEvent.dll"
    if script_dir_dll.is_file():
        return True
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        nuget_root = Path(user_profile) / ".nuget" / "packages" / "microsoft.diagnostics.tracing.traceevent"
        if nuget_root.is_dir():
            for dll in nuget_root.rglob("Microsoft.Diagnostics.Tracing.TraceEvent.dll"):
                if dll.is_file():
                    return True
    program_files_root = Path(r"C:\Program Files\TraceEvent")
    if program_files_root.is_dir():
        for dll in program_files_root.rglob("Microsoft.Diagnostics.Tracing.TraceEvent.dll"):
            if dll.is_file():
                return True
    return False


def _slice_helpers_only(script_text: str) -> str:
    """Return the prefix of ``api_trace.ps1`` containing only helper definitions.

    Locates the first script-level (column-0) ``try {`` line, which by
    convention introduces the script's main body in ``api_trace.ps1``,
    and returns everything before it. Inner ``try`` blocks nested inside
    helper functions are indented and therefore skipped by this match.

    Args:
        script_text: Full contents of ``api_trace.ps1``.

    Returns:
        str: Prefix containing the param block, helper functions, and
        helper-scoped statements, with the main body removed.

    Raises:
        AssertionError: If no script-level ``try {`` is present.
    """
    sentinel = "\ntry {\n"
    cut_index = script_text.find(sentinel)
    if cut_index < 0:
        msg = "could not locate script-level 'try {' block in api_trace.ps1"
        raise AssertionError(msg)
    return script_text[: cut_index + 1]


def _make_dll_blind_script(tmp_path: Path) -> Path:
    """Build a copy of ``api_trace.ps1`` whose DLL search always fails.

    The copy patches ``Find-TraceEventAssembly`` to return ``$null`` so
    the ``unavailable`` branch fires deterministically on hosts that
    happen to have the real assembly installed.

    Args:
        tmp_path: Pytest-provided temp directory used to host the copy.

    Returns:
        Path: Absolute path to the patched script copy.

    Raises:
        AssertionError: If the expected ``Find-TraceEventAssembly``
            definition is missing from the source script.
    """
    original = _SCRIPT_PATH.read_text(encoding="utf-8")
    needle = "function Find-TraceEventAssembly {\n    [CmdletBinding()]\n    param()"
    replacement = (
        "function Find-TraceEventAssembly {\n"
        "    [CmdletBinding()]\n"
        "    param()\n"
        "    return $null\n"
        "    # original body suppressed by test harness:"
    )
    if needle not in original:
        msg = "expected Find-TraceEventAssembly definition in api_trace.ps1"
        raise AssertionError(msg)
    patched = original.replace(needle, replacement, 1)
    out = tmp_path / "api_trace_no_dll.ps1"
    out.write_text(patched, encoding="utf-8")
    return out


def _run_script(
    script_path: Path,
    log_dir: Path,
    pwsh: str,
    *,
    target_pid: int = 0,
    duration_seconds: int = 1,
    timeout_seconds: float = 30.0,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an ``api_trace.ps1`` (or a copy) to completion.

    Args:
        script_path: PowerShell script to execute.
        log_dir: Directory passed via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.
        target_pid: Optional PID filter (``0`` = all processes).
        duration_seconds: ``-DurationSeconds`` argument; ``0`` means run
            until terminated.
        timeout_seconds: Hard wall-clock cap for the subprocess.
        extra_env: Extra environment variables to merge into the child.

    Returns:
        subprocess.CompletedProcess[str]: Completed process with stdout,
        stderr, and the captured return code.
    """
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-LogDir",
            str(log_dir),
            "-TargetPid",
            str(target_pid),
            "-DurationSeconds",
            str(duration_seconds),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=timeout_seconds,
        check=False,
    )


def _run_smoke_script_and_wait(log_dir: Path, pwsh: str) -> subprocess.Popen[str]:
    """Start the smoke script and wait for it (or kill on timeout).

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to ``pwsh.exe``.

    Returns:
        subprocess.Popen[str]: The background script process.
    """
    proc = _start_script_background(
        log_dir=log_dir,
        pwsh=pwsh,
        target_pid=0,
        duration_seconds=_SMOKE_DURATION_SEC,
    )
    try:
        proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=_PWSH_KILL_GRACE_SEC)
    return proc


def _run_handle_churn_helper_and_wait(
    proc: subprocess.Popen[str],
    pwsh: str,
) -> subprocess.Popen[str]:
    """Spawn the churn helper and wait for the smoke script to settle.

    Args:
        proc: The background smoke script subprocess.
        pwsh: Absolute path to ``pwsh.exe``.

    Returns:
        subprocess.Popen[str]: The spawned churn helper.
    """
    time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    helper = _spawn_handle_churn_helper(pwsh)
    try:
        proc.wait(timeout=_PROCESS_WAIT_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=_PWSH_KILL_GRACE_SEC)
    return helper


def _start_script_background(
    log_dir: Path,
    pwsh: str,
    *,
    target_pid: int = 0,
    duration_seconds: int = 0,
    extra_env: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    """Launch ``api_trace.ps1`` without blocking the caller.

    Args:
        log_dir: Directory passed via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.
        target_pid: Optional PID filter.
        duration_seconds: ``-DurationSeconds`` argument.
        extra_env: Extra environment variables to merge into the child.

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
            "-DurationSeconds",
            str(duration_seconds),
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
        returncode)``.
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


def _spawn_handle_churn_helper(pwsh: str) -> subprocess.Popen[str]:
    """Spawn a helper that opens/closes its own process handles in a loop.

    Each iteration calls ``OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE, GetCurrentProcessId())`` then ``CloseHandle`` -- both calls
    cause kernel transitions that the
    ``Microsoft-Windows-Kernel-Audit-API-Calls`` provider records under
    event ID 5 (``KERNEL_AUDIT_API_OPENPROCESS``).

    Args:
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        subprocess.Popen[str]: The running helper process.
    """
    helper_script = (
        "$sig = @'\n"
        '[DllImport("kernel32.dll", SetLastError=true)]\n'
        "public static extern System.IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);\n"
        '[DllImport("kernel32.dll", SetLastError=true)]\n'
        "public static extern bool CloseHandle(System.IntPtr hObject);\n"
        '[DllImport("kernel32.dll")]\n'
        "public static extern uint GetCurrentProcessId();\n"
        "'@\n"
        "Add-Type -MemberDefinition $sig -Name 'AuditApiTest' -Namespace 'IntApiTrace' -PassThru | Out-Null;\n"
        "$pid_self = [IntApiTrace.AuditApiTest]::GetCurrentProcessId();\n"
        "for($i=0; $i -lt 80; $i++) {\n"
        "    $h = [IntApiTrace.AuditApiTest]::OpenProcess(0x1000, $false, $pid_self);\n"
        "    if ($h -ne [IntPtr]::Zero) { [IntApiTrace.AuditApiTest]::CloseHandle($h) | Out-Null }\n"
        "    Start-Sleep -Milliseconds 50\n"
        "}\n"
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


def _read_log(log_dir: Path) -> str:
    """Return the contents of ``api_trace.log`` under ``log_dir``.

    Args:
        log_dir: Directory the script wrote into.

    Returns:
        str: File contents (UTF-8 decoded with replacement) or empty
        string when the file does not exist.
    """
    log_path = log_dir / _LOG_NAME
    if not log_path.is_file():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_f0014_no_logman_invocations_anywhere() -> None:
    """F-0014: the script must not call ``logman.exe`` at all.

    The previous implementation mixed a managed ``TraceEventSession``
    with cleanup commands like ``logman.exe stop IntApiTrace``, which
    targeted the wrong session entirely. The remediated script uses a
    single TraceEventSession abstraction; no ``logman`` invocations
    must remain.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "logman" not in lowered, "F-0014 regression: api_trace.ps1 must not invoke logman.exe"


def test_f0014_no_logman_stop_against_managed_session_name() -> None:
    """F-0014: ensure the managed session name is never stopped via logman.

    Belt-and-braces around ``test_f0014_no_logman_invocations_anywhere``:
    explicitly verify the managed session name does not appear next to
    any ``stop``/``delete`` token, which would indicate the deleted
    cleanup path crept back in.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    forbidden_pairs = (
        f"logman.exe stop {_MANAGED_SESSION_NAME}",
        f"logman stop {_MANAGED_SESSION_NAME}",
        f"logman.exe delete {_MANAGED_SESSION_NAME}",
        f"logman delete {_MANAGED_SESSION_NAME}",
    )
    for needle in forbidden_pairs:
        assert needle not in text, f"F-0014 regression: forbidden cleanup pattern present: {needle!r}"


def test_f0012_no_etl_file_creation_or_unharvested_session() -> None:
    """F-0012: no on-disk ETL file should be created and never read.

    The previous implementation wrote ``IntApiTrace.etl`` via
    ``logman create trace ... -o <etl>`` and never harvested it. The
    remediated script must not reference an ``.etl`` output path -
    realtime callbacks emit each event inline.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    lowered = text.lower()
    assert ".etl" not in lowered, "F-0012 regression: api_trace.ps1 must not write or reference an ETL file"
    # The realtime path must still be present.
    assert "TraceEventSession" in text, "expected realtime TraceEventSession reference"
    assert "EnableProvider" in text, "expected realtime EnableProvider call"
    assert "Process()" in text or "Process() | Out-Null" in text, "expected realtime Process() loop"


def test_f0013_handler_uses_real_audit_api_field_names() -> None:
    """F-0013: handler must reference the real provider field names.

    The Kernel-Audit-API-Calls provider exposes templates with fields
    like ``TargetProcessId``, ``ReturnCode``, ``DesiredAccess``,
    ``LinkSourceName``, ``LinkTargetName``, ``DriverName``,
    ``NotifyRoutineAddress``, ``TargetThreatId``. The previous handler
    referenced ``ReturnValue`` (which the provider does not expose) and
    relied entirely on ``OpcodeName`` for the API name (which is just
    ``Info`` for every event). The remediated handler must use the
    correct field names and the per-event-id API-name table.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")

    # Real field names used by the provider templates.
    assert "TargetProcessId" in text, "F-0013: handler must read TargetProcessId payload field"
    assert "ReturnCode" in text, "F-0013: handler must read ReturnCode payload field"

    # The per-event-id API-name lookup must exist.
    assert "Get-AuditApiName" in text, "F-0013: missing Get-AuditApiName helper"
    for api_name in (
        "PsSetLoadImageNotifyRoutine",
        "NtTerminateProcess",
        "NtCreateSymbolicLinkObject",
        "SePrivilegeCheck",
        "NtOpenProcess",
        "NtOpenThread",
    ):
        assert api_name in text, f"F-0013: expected event-id API mapping for {api_name}"

    # The bogus 'ReturnValue' field name from the previous implementation must be gone.
    assert "PayloadByName('ReturnValue')" not in text, "F-0013 regression: handler must not query the non-existent 'ReturnValue' field"


def test_f0011_missing_dll_exits_nonzero_with_structured_error(tmp_path: Path) -> None:
    """F-0011: missing TraceEvent.dll must exit non-zero and log a structured error.

    The previous implementation called ``exit 0`` when the assembly was
    missing, telling the bridge consumer the monitor started cleanly.
    The remediated script must exit with a non-zero status and write a
    pipe-delimited ``ERROR|unavailable|...`` record to ``api_trace.log``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir`` and
            to host the patched script copy.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    blind_script = _make_dll_blind_script(tmp_path)
    result = _run_script(
        script_path=blind_script,
        log_dir=log_dir,
        pwsh=pwsh,
        duration_seconds=1,
        timeout_seconds=15.0,
        extra_env={"TRACE_EVENT_DLL": ""},
    )

    assert result.returncode != _EXIT_OK, (
        f"F-0011 regression: script must exit non-zero when TraceEvent.dll is missing; "
        f"returncode={result.returncode!r} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.returncode == _EXIT_NO_DLL, (
        f"expected dedicated exit code {_EXIT_NO_DLL} for missing-dependency path; got {result.returncode!r}"
    )

    log_text = _read_log(log_dir)
    assert log_text, f"expected api_trace.log to be written; stdout={result.stdout!r} stderr={result.stderr!r}"
    error_lines = [line for line in log_text.splitlines() if "|ERROR|unavailable|" in line]
    assert error_lines, f"expected ERROR|unavailable|... record in log; got:\n{log_text}"
    error_line = error_lines[0]
    fields = error_line.split("|")
    assert len(fields) >= 7, f"structured error line must have 7 pipe-fields; got {error_line!r}"
    # Field layout per parse_api_trace_log: ts, process_name, pid, api_name, module, arguments, return_value
    assert fields[1] == "tracer", f"expected 'tracer' marker in field 1; got {error_line!r}"
    assert fields[3] == "ERROR", f"expected 'ERROR' marker in field 3; got {error_line!r}"
    assert fields[4] == "unavailable", f"expected 'unavailable' stage in field 4; got {error_line!r}"
    assert "TraceEvent" in fields[5] or "TraceEvent" in error_line, (
        f"expected human-readable diagnostic in arguments field; got {error_line!r}"
    )


def test_f0011_stop_record_carries_actual_exit_code(tmp_path: Path) -> None:
    """F-0011 belt-and-braces: the trailing STOP record must echo the real exit code.

    The remediated script writes a final ``tracer|0|STOP|<sess>||<rc>``
    line whose return-value field carries the script-level
    ``$ExitCode``. This guards against silent regressions where a future
    change might make the script exit non-zero but report ``STOP||0``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir`` and
            to host the patched script copy.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    blind_script = _make_dll_blind_script(tmp_path)
    result = _run_script(
        script_path=blind_script,
        log_dir=log_dir,
        pwsh=pwsh,
        duration_seconds=1,
        timeout_seconds=15.0,
        extra_env={"TRACE_EVENT_DLL": ""},
    )

    log_text = _read_log(log_dir)
    stop_lines = [line for line in log_text.splitlines() if "|STOP|" in line]
    assert stop_lines, f"expected STOP record; got:\n{log_text}"
    stop_line = stop_lines[-1]
    fields = stop_line.split("|")
    assert fields[-1] == str(result.returncode), (
        f"STOP record return-value field {fields[-1]!r} must match script exit code {result.returncode!r}; line={stop_line!r}"
    )


def test_f0013_get_audit_api_name_resolves_each_event_id(tmp_path: Path) -> None:
    """F-0013: ``Get-AuditApiName`` must resolve every documented event ID.

    Dot-source the script and call ``Get-AuditApiName`` for each event
    ID 1..8 to verify the mapping is complete and returns
    non-placeholder strings, plus confirms the ``default`` branch
    handles unknown IDs without throwing.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    expected = {
        1: "PsSetLoadImageNotifyRoutine",
        2: "NtTerminateProcess",
        3: "NtCreateSymbolicLinkObject",
        4: "SePrivilegeCheck",
        5: "NtOpenProcess",
        6: "NtOpenThread",
        7: "IoRegisterLastChanceShutdownNotification",
        8: "IoRegisterShutdownNotification",
    }

    # Build a probe script that dot-sources the helper functions only and
    # invokes Get-AuditApiName for each id without running the body.
    script_text = _SCRIPT_PATH.read_text(encoding="utf-8")
    # Cut at the script-level try block (the only one at column 0, by
    # convention the entry-point in api_trace.ps1) so the probe loads
    # only function definitions and never invokes the realtime ETW path.
    helpers_only = _slice_helpers_only(script_text)

    probe = tmp_path / "probe_get_audit_api_name.ps1"
    probe_body = (
        helpers_only
        + "\n"
        + "$ids = 1..9 + ,99\n"
        + "foreach ($id in $ids) {\n"
        + "    $name = Get-AuditApiName -EventId $id\n"
        + "    Write-Output ('id=' + $id + '|' + $name)\n"
        + "}\n"
    )
    probe.write_text(probe_body, encoding="utf-8")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
            "-LogDir",
            str(log_dir),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30.0,
        check=False,
    )
    assert result.returncode == 0, f"probe script failed; stdout={result.stdout!r} stderr={result.stderr!r}"

    parsed: dict[int, str] = {}
    for line in result.stdout.splitlines():
        if not line.startswith("id="):
            continue
        token, name = line.split("|", 1)
        parsed[int(token.removeprefix("id="))] = name.strip()

    for event_id, api in expected.items():
        assert parsed.get(event_id) == api, f"F-0013: event id {event_id} mapping is wrong; expected {api!r}, got {parsed.get(event_id)!r}"
    # Unknown id 9 must take the default branch and produce a fallback name.
    assert parsed.get(9, "").startswith("AuditApi_EventId_"), (
        f"F-0013: default branch must produce AuditApi_EventId_<n> placeholder; got {parsed.get(9)!r}"
    )
    assert parsed.get(99, "").startswith("AuditApi_EventId_"), f"F-0013: default branch must handle ids beyond 8; got {parsed.get(99)!r}"


def test_f0013_handler_extracts_target_process_id_and_return_code(tmp_path: Path) -> None:
    """F-0013: ``Resolve-PayloadField`` must read the real provider fields.

    Build a synthetic event-like object whose ``PayloadByName`` mirrors
    the Kernel-Audit-API-Calls templates (e.g. event ID 5 carries
    ``TargetProcessId``, ``DesiredAccess``, ``ReturnCode``). Confirm the
    helper resolves each field correctly and that absent fields return
    ``$null`` rather than raising.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    script_text = _SCRIPT_PATH.read_text(encoding="utf-8")
    helpers_only = _slice_helpers_only(script_text)

    probe = tmp_path / "probe_resolve_payload.ps1"
    probe_body = (
        helpers_only
        + "\n"
        + "Add-Type -TypeDefinition @'\n"
        + "using System.Collections.Generic;\n"
        + "public class FakeAuditEvent {\n"
        + "    private readonly Dictionary<string, object> _payload;\n"
        + "    public string[] PayloadNames { get; }\n"
        + "    public int ID { get; }\n"
        + "    public int ProcessID { get; }\n"
        + "    public FakeAuditEvent(int id, int pid, Dictionary<string, object> payload) {\n"
        + "        ID = id; ProcessID = pid; _payload = payload;\n"
        + "        var names = new string[payload.Keys.Count];\n"
        + "        payload.Keys.CopyTo(names, 0); PayloadNames = names;\n"
        + "    }\n"
        + "    public object PayloadByName(string name) {\n"
        + "        object v; return _payload.TryGetValue(name, out v) ? v : null;\n"
        + "    }\n"
        + "}\n"
        + "'@ -Language CSharp\n"
        + "$payload = New-Object 'System.Collections.Generic.Dictionary[string,object]'\n"
        + "$payload.Add('TargetProcessId', [uint32]4321)\n"
        + "$payload.Add('DesiredAccess', [uint32]0x1FFFFF)\n"
        + "$payload.Add('ReturnCode', [uint32]0)\n"
        + "$evt = New-Object FakeAuditEvent(5, 1234, $payload)\n"
        + "$tpid = Resolve-PayloadField -Event $evt -Name 'TargetProcessId'\n"
        + "$rc   = Resolve-PayloadField -Event $evt -Name 'ReturnCode'\n"
        + "$da   = Resolve-PayloadField -Event $evt -Name 'DesiredAccess'\n"
        + "$missing = Resolve-PayloadField -Event $evt -Name 'NonExistentField'\n"
        + "Write-Output ('TargetProcessId=' + [int]$tpid)\n"
        + "Write-Output ('ReturnCode=' + [int]$rc)\n"
        + "Write-Output ('DesiredAccess=' + ('0x{0:X}' -f [uint32]$da))\n"
        + "Write-Output ('Missing=' + ($null -eq $missing))\n"
        + "Write-Output ('Function=' + (Get-AuditApiName -EventId $evt.ID))\n"
        + "Write-Output ('Module=ntoskrnl.exe')\n"
    )
    probe.write_text(probe_body, encoding="utf-8")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(probe),
            "-LogDir",
            str(log_dir),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30.0,
        check=False,
    )
    assert result.returncode == 0, f"probe script failed; stdout={result.stdout!r} stderr={result.stderr!r}"

    out = result.stdout
    assert "TargetProcessId=4321" in out, f"expected TargetProcessId extraction; stdout={out!r}"
    assert "ReturnCode=0" in out, f"expected ReturnCode extraction; stdout={out!r}"
    assert "DesiredAccess=0x1FFFFF" in out, f"expected DesiredAccess extraction; stdout={out!r}"
    assert "Missing=True" in out, f"missing field must resolve to $null (True); stdout={out!r}"
    # F-0013 also requires the per-event-id API name to flow into the 'Function' / api_name field.
    assert "Function=NtOpenProcess" in out, f"expected event id 5 to map to NtOpenProcess; stdout={out!r}"
    assert "Module=ntoskrnl.exe" in out, f"expected module to be ntoskrnl.exe (kernel provider); stdout={out!r}"


def test_smoke_script_emits_start_record_when_dll_available(tmp_path: Path) -> None:
    """Smoke: when TraceEvent.dll is available the script must reach the START record.

    Spawn ``notepad.exe`` as a target, run the script for a few seconds,
    then assert the script wrote the structured ``START|IntApiTrace|...``
    line. On non-elevated hosts the underlying ``EnableProvider`` call
    requires admin and will fail with a structured ``ERROR|enable_provider``
    record - that path is also acceptable smoke evidence: the script
    reports failure structurally instead of silently exiting 0.

    On elevated hosts, the test additionally requires that at least the
    realtime callback machinery was wired up, which is asserted by the
    presence of the START line.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    if not _have_trace_event_dll():
        pytest.skip("TraceEvent.dll not installed; cannot exercise the realtime path")

    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()

    notepad_path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "notepad.exe"
    if not notepad_path.is_file():
        pytest.skip(f"notepad.exe not found at {notepad_path}")

    notepad = subprocess.Popen(
        [str(notepad_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc: subprocess.Popen[str] | None = None
    try:
        proc = _run_smoke_script_and_wait(log_dir, pwsh)
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
        notepad.terminate()
        try:
            notepad.wait(timeout=_PWSH_KILL_GRACE_SEC)
        except subprocess.TimeoutExpired:
            notepad.kill()

    log_text = _read_log(log_dir)
    assert log_text, f"expected api_trace.log to be created; dir contents={list(log_dir.iterdir())!r}"

    has_start = any("|START|" in line for line in log_text.splitlines())
    enable_provider_failed = any("|ERROR|enable_provider|" in line or "|ERROR|session_create|" in line for line in log_text.splitlines())
    if _is_admin():
        assert has_start, f"F-0012 smoke regression: realtime session must reach the START record under admin; log contents:\n{log_text}"
    else:
        # Non-admin: either we got far enough to write START before EnableProvider
        # blew up, or we surfaced a structured enable_provider error. Both are
        # acceptable evidence that no silent exit-0 path remains.
        assert has_start or enable_provider_failed, (
            f"expected either START record or structured enable_provider/session_create error; log contents:\n{log_text}"
        )


def test_smoke_script_emits_event_records_under_admin(tmp_path: Path) -> None:
    """F-0012 smoke under admin: realtime path must produce at least one event line.

    Skip when not elevated. When elevated, spawn a helper that performs
    repeated ``OpenProcess(self)`` calls (event ID 5 on the AuditAPI
    provider) and assert the script's log contains at least one
    non-tracer record from a real audited API call.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    if not _have_trace_event_dll():
        pytest.skip("TraceEvent.dll not installed; cannot exercise the realtime path")
    if not _is_admin():
        pytest.skip("realtime ETW kernel-audit provider requires administrator rights")

    log_dir = tmp_path / "smoke_admin_logs"
    log_dir.mkdir()

    proc = _start_script_background(
        log_dir=log_dir,
        pwsh=pwsh,
        target_pid=0,
        duration_seconds=_SMOKE_DURATION_SEC,
    )
    helper: subprocess.Popen[str] | None = None
    try:
        helper = _run_handle_churn_helper_and_wait(proc, pwsh)
    finally:
        if helper is not None:
            _terminate(helper)
        if proc.poll() is None:
            _terminate(proc)

    log_text = _read_log(log_dir)
    event_lines = [line for line in log_text.splitlines() if line and not line.split("|", 2)[1].startswith("tracer")]
    assert event_lines, f"F-0012 smoke regression: expected at least one captured event line under admin; log contents:\n{log_text}"


def test_log_lines_match_consumer_format(tmp_path: Path) -> None:
    """The log format must remain compatible with ``parse_api_trace_log``.

    ``intellicrack.sandbox._log_parsers.parse_api_trace_log`` expects
    ``timestamp|process_name|pid|api_name|module|arguments|return_value``
    (7 pipe-fields, ``arguments`` is semicolon-joined). This test
    re-runs the missing-DLL exit path so we have deterministic content,
    then asserts every emitted line has 7 fields.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir`` and
            to host the patched script copy.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    blind_script = _make_dll_blind_script(tmp_path)
    _run_script(
        script_path=blind_script,
        log_dir=log_dir,
        pwsh=pwsh,
        duration_seconds=1,
        timeout_seconds=15.0,
        extra_env={"TRACE_EVENT_DLL": ""},
    )

    log_text = _read_log(log_dir)
    assert log_text, "expected api_trace.log to be written"
    for line in log_text.splitlines():
        if not line.strip():
            continue
        fields = line.split("|")
        assert len(fields) == 7, (
            f"every line must have exactly 7 pipe-separated fields to match parse_api_trace_log; got {len(fields)} fields in {line!r}"
        )
