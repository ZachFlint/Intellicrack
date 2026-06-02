# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Audit3 U7 tests for ``start_monitors.cmd`` / ``stop_monitors.cmd``.

Validates the three findings tracked against
``src/intellicrack/sandbox/scripts/start_monitors.cmd`` plus the new
companion ``stop_monitors.cmd``:

* F-0010 - the launcher must capture every spawned monitor's PID into a
  state file under the supplied ``-LogDir`` and propagate non-zero on
  any failure to start.
* F-0024 - the launcher's default ``-LogDir`` must match the monitor
  scripts (``%ProgramData%\Intellicrack\Sandbox\logs``) and must be
  forwarded to every spawned monitor.
* F-0025 - shutdown must be coordinated through the new
  ``stop_monitors.cmd`` companion, which reads the PID file and
  terminates every tracked child via ``taskkill``.

The tests run the real ``.cmd`` scripts under ``cmd.exe`` against a
temporary log directory. They are skipped on non-Windows platforms
because the scripts target Windows-only tooling.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
import time
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import (
    DEVNULL,
    CompletedProcess,
    SubprocessError,
    run,
)


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts"
_START_SCRIPT: Final[Path] = _SCRIPTS_DIR / "start_monitors.cmd"
_STOP_SCRIPT: Final[Path] = _SCRIPTS_DIR / "stop_monitors.cmd"
_STOP_HELPER_SCRIPT: Final[Path] = _SCRIPTS_DIR / "_stop_monitors_helper.ps1"
_PID_FILE_NAME: Final[str] = "monitors.pids"
_START_TIMEOUT_SEC: Final[float] = 90.0
_STOP_TIMEOUT_SEC: Final[float] = 30.0
_SETTLE_SEC: Final[float] = 1.5


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="start_monitors.cmd / stop_monitors.cmd target Windows cmd.exe",
)


def _resolve_cmd() -> str:
    """Locate ``cmd.exe`` for invoking ``.cmd`` scripts.

    Returns:
        str: Absolute path to ``cmd.exe``.
    """
    cmd = shutil.which("cmd.exe") or shutil.which("cmd")
    if cmd is None:
        pytest.skip("cmd.exe is required for start_monitors tests")
    return cmd


def _resolve_pwsh() -> str:
    """Locate ``pwsh.exe`` (used by helper queries against the live OS).

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for monitor lifecycle tests")
    return pwsh


def _run_stop(log_dir: Path) -> CompletedProcess[str]:
    """Invoke ``stop_monitors.cmd`` directly against the supplied log dir.

    Args:
        log_dir: Directory containing the PID file.

    Returns:
        CompletedProcess[str]: The completed process.
    """
    cmd = _resolve_cmd()
    return run(
        [cmd, "/c", str(_STOP_SCRIPT), str(log_dir)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_STOP_TIMEOUT_SEC,
    )


def _read_pid_file(log_dir: Path) -> list[tuple[int, str]]:
    """Read ``monitors.pids`` and return the parsed entries.

    Args:
        log_dir: Directory containing the PID file.

    Returns:
        list[tuple[int, str]]: List of ``(pid, script_name)`` entries.
    """
    pid_file = log_dir / _PID_FILE_NAME
    assert pid_file.is_file(), f"PID file missing at {pid_file}; dir={list(log_dir.iterdir())}"
    entries: list[tuple[int, str]] = []
    for raw_line in pid_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        pid_str = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        entries.append((int(pid_str), name))
    return entries


def _process_alive(pid: int, pwsh: str) -> bool:
    """Return ``True`` if ``pid`` is currently alive.

    Args:
        pid: Process identifier to check.
        pwsh: Absolute path to ``pwsh.exe``.

    Returns:
        bool: ``True`` if the process exists.
    """
    completed = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10.0,
    )
    return completed.returncode == 0


def _kill_pids(pids: list[int]) -> None:
    """Best-effort terminate any leftover PIDs from a failed test.

    Args:
        pids: List of process identifiers to terminate.
    """
    taskkill = shutil.which("taskkill")
    if taskkill is None:
        return
    for pid in pids:
        try:
            run(
                [taskkill, "/PID", str(pid), "/F", "/T"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10.0,
            )
        except (SubprocessError, OSError):
            continue


def test_start_script_runs_and_writes_valid_pid_file(tmp_path: Path) -> None:
    """F-0010 runtime gate: a single-monitor launch produces a valid PID file.

    Replaces the prior existence-only smoke check. Runs the real launcher
    against a scratch directory holding exactly one inert monitor and asserts
    the launcher exits 0, writes ``monitors.pids`` containing exactly one
    ``<pid> <script>`` entry whose script name is the monitor we provided and
    whose PID is a live process. A launcher that merely exists but never
    spawns, never tracks, or writes a malformed PID line fails here.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count=1)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    completed = _run_scratch_start(scripts_dir, log_dir)
    pids: list[int] = []
    try:
        pids = _verify_single_monitor_pid_file(completed, log_dir, pwsh)
    finally:
        _kill_pids(pids)


def test_stop_script_terminates_a_started_monitor(tmp_path: Path) -> None:
    """F-0025 runtime gate: running stop after start reaps the tracked PID.

    Replaces the prior existence-only smoke check. Starts a single inert
    monitor, confirms it is live, then runs the real ``stop_monitors.cmd``
    against the same log dir and asserts the stopper exits 0, the previously
    live monitor PID is dead, and the PID file is removed. A stopper that
    exists but never reads the PID file or never kills anything fails here.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count=1)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    started = _run_scratch_start(scripts_dir, log_dir)
    assert started.returncode == 0, f"start must succeed before stop gate; stderr={started.stderr!r}"
    entries = _read_pid_file(log_dir)
    assert len(entries) == 1, f"expected one tracked monitor; entries={entries!r}"
    pid = entries[0][0]

    try:
        _verify_single_monitor_stop(pid, scripts_dir, log_dir, pwsh)
    finally:
        _kill_pids([pid])


def test_start_script_default_logdir_resolves_to_programdata(tmp_path: Path) -> None:
    r"""F-0024 runtime gate: omitting LogDir writes under ``%ProgramData%``.

    Replaces the prior source-string match. Runs the launcher with NO
    positional LogDir argument and a ``ProgramData`` environment variable
    redirected to a scratch root, then asserts the launcher actually creates
    and writes its PID file at ``<ProgramData>\Intellicrack\Sandbox\logs``.
    This proves the default path is computed from ``%ProgramData%`` at
    runtime rather than merely appearing as a literal in the file. A launcher
    whose default logic was broken (wrong subpath, stale WDAG default,
    ignoring ``%ProgramData%``) would not place the PID file here.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count=1)

    fake_programdata = tmp_path / "ProgramData"
    fake_programdata.mkdir()
    expected_log_dir = fake_programdata / "Intellicrack" / "Sandbox" / "logs"

    child_env = dict(os.environ)
    child_env["ProgramData"] = str(fake_programdata)

    cmd = _resolve_cmd()
    completed = _run_capturing_to_files(
        [cmd, "/c", str(scripts_dir / "start_monitors.cmd")],
        tmp_path,
        "default_logdir",
        _START_TIMEOUT_SEC,
        env=child_env,
    )

    pids: list[int] = []
    try:
        pids = _verify_default_logdir_pid_file(completed, fake_programdata, expected_log_dir, pwsh)
    finally:
        _kill_pids(pids)
        _run_scratch_stop(scripts_dir, expected_log_dir)


def test_start_script_legacy_wdag_default_removed() -> None:
    """F-0024: the legacy hardcoded WDAG sandbox default must not reappear.

    A focused, fast regression guard complementing the runtime default-path
    gate: the script must never re-introduce the old
    ``WDAGUtilityAccount`` desktop path that contradicted the monitor
    scripts. This is a content invariant, not the behavioral gate.
    """
    text = _START_SCRIPT.read_text(encoding="utf-8")
    assert "WDAGUtilityAccount" not in text, "legacy hardcoded WDAG default must stay removed"


_SLEEPER_MONITOR: Final[str] = textwrap.dedent("""\
    param([string]$LogDir = '.')
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $log = Join-Path -Path $LogDir -ChildPath ($MyInvocation.MyCommand.Name + '.log')
    Add-Content -LiteralPath $log -Value ((Get-Date).ToString('o') + '|started') -Encoding utf8
    $created = $false
    $stop = $null
    try {
        $stop = New-Object System.Threading.EventWaitHandle(
            $false,
            [System.Threading.EventResetMode]::ManualReset,
            'IntellicrackMonitorStop',
            [ref]$created)
    } catch {
        $stop = $null
    }
    try {
        while ($true) {
            if ($null -ne $stop) {
                if ($stop.WaitOne(1000)) { break }
            } else {
                Start-Sleep -Milliseconds 1000
            }
        }
    } finally {
        if ($null -ne $stop) { $stop.Dispose() }
        Add-Content -LiteralPath $log -Value ((Get-Date).ToString('o') + '|stopped') -Encoding utf8
    }
    """)


def _build_scratch_scripts_dir(scratch_root: Path, monitor_count: int) -> Path:
    """Create an isolated copy of the launcher with N inert monitor scripts.

    The scratch monitors are simple infinite-sleep PowerShell scripts so
    they do not depend on any optional binary dependency (such as the
    Microsoft.Diagnostics.Tracing.TraceEvent assembly required by the
    real ``api_trace.ps1`` monitor).

    Args:
        scratch_root: Directory in which to materialise the scripts.
        monitor_count: Number of inert monitor scripts to create.

    Returns:
        Path: The materialised scripts directory.
    """
    scripts_dir = scratch_root / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    launcher = scripts_dir / "start_monitors.cmd"
    launcher.write_text(
        _START_SCRIPT.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    stopper = scripts_dir / "stop_monitors.cmd"
    stopper.write_text(
        _STOP_SCRIPT.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    helper = scripts_dir / _STOP_HELPER_SCRIPT.name
    helper.write_text(
        _STOP_HELPER_SCRIPT.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    for idx in range(monitor_count):
        (scripts_dir / f"sleeper_{idx:02d}.ps1").write_text(
            _SLEEPER_MONITOR,
            encoding="utf-8",
        )
    return scripts_dir


def _run_capturing_to_files(
    args: list[str],
    workspace: Path,
    label: str,
    timeout_sec: float,
    env: dict[str, str] | None = None,
) -> CompletedProcess[str]:
    """Run a launcher capturing output through files instead of OS pipes.

    The monitor launchers spawn detached background children. Capturing the
    launcher's output through OS pipes (``capture_output=True``) lets those
    children inherit the pipe write end and hold it open after the launcher
    itself exits. :func:`subprocess.run` then waits the full ``timeout`` for
    the pipe to reach EOF and, on Windows, its post-timeout cleanup calls
    ``communicate()`` with no timeout, which blocks indefinitely on the still
    open pipe. Redirecting to real files removes the pipes entirely: ``run``
    only waits on the launcher process (bounded by ``timeout_sec``) and the
    captured text is read back from disk afterwards.

    Args:
        args: Command argument vector to execute.
        workspace: Directory in which to place the capture files.
        label: Filename stem distinguishing concurrent captures.
        timeout_sec: Maximum number of seconds to allow the command to run.
        env: Optional full environment mapping for the child process. When
            ``None`` the parent environment is inherited unchanged.

    Returns:
        CompletedProcess[str]: The completed process with ``stdout`` and
        ``stderr`` populated from the capture files.
    """
    out_path = workspace / f"_{label}.stdout.txt"
    err_path = workspace / f"_{label}.stderr.txt"
    with out_path.open("wb") as out_handle, err_path.open("wb") as err_handle:
        completed = run(
            args,
            stdout=out_handle,
            stderr=err_handle,
            stdin=DEVNULL,
            check=False,
            timeout=timeout_sec,
            env=env,
        )
    stdout = out_path.read_text(encoding="utf-8", errors="replace")
    stderr = err_path.read_text(encoding="utf-8", errors="replace")
    return CompletedProcess(completed.args, completed.returncode, stdout, stderr)


def _run_scratch_start(
    scripts_dir: Path,
    log_dir: Path,
) -> CompletedProcess[str]:
    """Run ``start_monitors.cmd`` from a scratch scripts directory.

    Args:
        scripts_dir: Directory containing a copy of the launcher.
        log_dir: Directory for the PID file and per-monitor logs.

    Returns:
        CompletedProcess[str]: The completed process.
    """
    cmd = _resolve_cmd()
    return _run_capturing_to_files(
        [cmd, "/c", str(scripts_dir / "start_monitors.cmd"), str(log_dir)],
        log_dir,
        "start_monitors",
        _START_TIMEOUT_SEC,
    )


def _run_scratch_stop(
    scripts_dir: Path,
    log_dir: Path,
) -> CompletedProcess[str]:
    """Run ``stop_monitors.cmd`` from a scratch scripts directory.

    Args:
        scripts_dir: Directory containing a copy of the stopper.
        log_dir: Directory containing the PID file.

    Returns:
        CompletedProcess[str]: The completed process.
    """
    cmd = _resolve_cmd()
    return _run_capturing_to_files(
        [cmd, "/c", str(scripts_dir / "stop_monitors.cmd"), str(log_dir)],
        log_dir,
        "stop_monitors",
        _STOP_TIMEOUT_SEC,
    )


def test_start_script_tracks_pids(tmp_path: Path) -> None:
    """F-0010 runtime check: PID file must contain valid PIDs.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    monitor_count = 3
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    completed = _run_scratch_start(scripts_dir, log_dir)
    pids: list[int] = []
    try:
        pids = _verify_start_tracks_pids(completed, log_dir, monitor_count, pwsh)
    finally:
        _kill_pids(pids)


def test_start_script_propagates_failure(tmp_path: Path) -> None:
    """F-0010 runtime check: launcher must exit non-zero on monitor failure.

    Build a scratch scripts directory containing one inert sleeper plus
    one poisoned ``*.ps1`` script that exits immediately with a
    parameter binding error so the launcher's post-spawn liveness check
    fires. The launcher must then return non-zero.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count=1)
    poisoned = scripts_dir / "always_fails_monitor.ps1"
    poisoned.write_text(
        textwrap.dedent("""\
            param([Parameter(Mandatory=$true)][int]$RequiredArg)
            Write-Output $RequiredArg
            """),
        encoding="utf-8",
    )

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    completed = _run_scratch_start(scripts_dir, log_dir)

    pids: list[int] = []
    try:
        assert completed.returncode != 0, (
            f"launcher must exit non-zero when a monitor fails to start; stdout={completed.stdout!r} stderr={completed.stderr!r}"
        )
        # Diagnostic message must reach stderr.
        assert "monitor" in (completed.stderr or "").lower(), f"launcher must surface the failure on stderr; stderr={completed.stderr!r}"
        # Any PIDs that did get tracked should be cleaned up.
        if (log_dir / _PID_FILE_NAME).is_file():
            pids = [pid for pid, _ in _read_pid_file(log_dir)]
    finally:
        _kill_pids(pids)


def test_stop_script_terminates_tracked_pids(tmp_path: Path) -> None:
    """F-0025 runtime check: stop_monitors.cmd must terminate all tracked PIDs.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    monitor_count = 3
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    started = _run_scratch_start(scripts_dir, log_dir)
    assert started.returncode == 0, f"start_monitors must succeed before stop test; stdout={started.stdout!r} stderr={started.stderr!r}"
    entries = _read_pid_file(log_dir)
    pids = [pid for pid, _ in entries]

    try:
        _verify_stop_terminates_tracked_pids(entries, scripts_dir, log_dir, pwsh)
    finally:
        _kill_pids(pids)


def test_stop_script_errors_when_pid_file_missing(tmp_path: Path) -> None:
    """The stop script must exit non-zero when its PID file is missing.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    log_dir = tmp_path / "empty_logs"
    log_dir.mkdir()

    completed = _run_stop(log_dir)
    assert completed.returncode != 0, (
        f"stop_monitors must exit non-zero when PID file absent; stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )
    assert "PID file not found" in (completed.stderr or ""), (
        f"stop_monitors must report the missing PID file on stderr; stderr={completed.stderr!r}"
    )


def test_full_lifecycle_no_orphan_pwsh(tmp_path: Path) -> None:
    """Full smoke: start + stop must leave no orphan child pwsh processes.

    We snapshot the set of pwsh PIDs before start and ensure that, after
    stop_monitors returns, every PID tracked in the PID file has been
    reaped.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    monitor_count = 3
    scripts_dir = _build_scratch_scripts_dir(tmp_path / "scratch", monitor_count)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    started = _run_scratch_start(scripts_dir, log_dir)
    assert started.returncode == 0, f"start failed; stdout={started.stdout!r} stderr={started.stderr!r}"
    entries = _read_pid_file(log_dir)
    tracked = {pid for pid, _ in entries}

    try:
        _verify_full_lifecycle_no_orphans(scripts_dir, log_dir, pwsh, tracked)
    finally:
        _kill_pids(list(tracked))


def _verify_start_tracks_pids(
    completed: CompletedProcess[str],
    log_dir: Path,
    monitor_count: int,
    pwsh: str,
) -> list[int]:
    """Assert start_monitors exited 0 and PIDs in the file are alive.

    Args:
        completed: Completed start launcher process.
        log_dir: Directory containing the PID file written by the launcher.
        monitor_count: Expected number of tracked monitors.
        pwsh: Absolute path to ``pwsh.exe`` for liveness checks.

    Returns:
        list[int]: PIDs recorded in the PID file.
    """
    assert completed.returncode == 0, (
        f"start_monitors exited {completed.returncode}; stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )

    entries = _read_pid_file(log_dir)
    assert entries, "PID file is empty"
    pids = [pid for pid, _ in entries]
    assert len(entries) == monitor_count, f"expected {monitor_count} tracked monitors, got {len(entries)}; entries={entries!r}"

    time.sleep(_SETTLE_SEC)
    for pid, name in entries:
        assert _process_alive(pid, pwsh), f"tracked monitor pid {pid} ({name}) is not running"
    return pids


def _verify_stop_terminates_tracked_pids(
    entries: list[tuple[int, str]],
    scripts_dir: Path,
    log_dir: Path,
    pwsh: str,
) -> None:
    """Run stop_monitors and assert all tracked PIDs are reaped.

    Args:
        entries: PID/name entries read from the PID file before stop.
        scripts_dir: Scratch scripts directory passed to the stop launcher.
        log_dir: Directory containing the PID file.
        pwsh: Absolute path to ``pwsh.exe`` for liveness checks.
    """
    time.sleep(_SETTLE_SEC)
    for pid, name in entries:
        assert _process_alive(pid, pwsh), f"monitor pid {pid} ({name}) did not start"

    stopped = _run_scratch_stop(scripts_dir, log_dir)
    assert stopped.returncode == 0, f"stop_monitors must exit 0 on success; stdout={stopped.stdout!r} stderr={stopped.stderr!r}"

    time.sleep(_SETTLE_SEC)
    for pid, name in entries:
        assert not _process_alive(pid, pwsh), f"monitor pid {pid} ({name}) still alive after stop_monitors"

    pid_file = log_dir / _PID_FILE_NAME
    assert not pid_file.exists(), f"PID file at {pid_file} must be deleted after stop_monitors"


def _verify_full_lifecycle_no_orphans(
    scripts_dir: Path,
    log_dir: Path,
    pwsh: str,
    tracked: set[int],
) -> None:
    """Run stop_monitors and assert no tracked PID survives.

    Args:
        scripts_dir: Scratch scripts directory.
        log_dir: Directory containing the PID file.
        pwsh: Absolute path to ``pwsh.exe`` for PID enumeration.
        tracked: Set of PIDs tracked by the start launcher.
    """
    time.sleep(_SETTLE_SEC)
    stopped = _run_scratch_stop(scripts_dir, log_dir)
    assert stopped.returncode == 0, f"stop failed; stdout={stopped.stdout!r} stderr={stopped.stderr!r}"

    time.sleep(_SETTLE_SEC)
    post_pids = _list_pwsh_pids(pwsh)

    leaked_tracked = {pid for pid in tracked if pid in post_pids}
    assert not leaked_tracked, f"tracked monitor PIDs survived stop_monitors: {leaked_tracked}"


def _list_pwsh_pids(pwsh: str) -> set[int]:
    """Return the set of PIDs for currently running pwsh / powershell processes.

    Args:
        pwsh: Absolute path to ``pwsh.exe``.

    Returns:
        set[int]: PIDs of all pwsh / powershell instances.
    """
    completed = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Process -Name pwsh,powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id) -join ','",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10.0,
    )
    output = (completed.stdout or "").strip()
    if not output:
        return set()
    return {int(p) for p in output.split(",") if p.strip().isdigit()}


def _verify_single_monitor_pid_file(
    completed: CompletedProcess[str],
    log_dir: Path,
    pwsh: str,
) -> list[int]:
    """Assert a one-monitor launch wrote a valid, live PID file.

    Args:
        completed: Completed start launcher process.
        log_dir: Directory containing the PID file written by the launcher.
        pwsh: Absolute path to ``pwsh.exe`` for liveness checks.

    Returns:
        list[int]: The single tracked PID, for caller cleanup.
    """
    assert completed.returncode == 0, f"launcher must exit 0 on a healthy monitor; stderr={completed.stderr!r}"
    entries = _read_pid_file(log_dir)
    assert len(entries) == 1, f"exactly one monitor must be tracked; entries={entries!r}"
    pid, name = entries[0]
    assert name == "sleeper_00.ps1", f"PID file must record the spawned monitor's script name; got {name!r}"
    assert pid > 0, f"tracked PID must be a positive integer; got {pid}"
    time.sleep(_SETTLE_SEC)
    assert _process_alive(pid, pwsh), f"tracked monitor pid {pid} must be a live process"
    return [pid]


def _verify_single_monitor_stop(
    pid: int,
    scripts_dir: Path,
    log_dir: Path,
    pwsh: str,
) -> None:
    """Assert stop_monitors reaps a single live monitor and clears its PID file.

    Args:
        pid: PID of the started monitor expected to be alive then reaped.
        scripts_dir: Scratch scripts directory for the stop launcher.
        log_dir: Directory containing the PID file.
        pwsh: Absolute path to ``pwsh.exe`` for liveness checks.
    """
    time.sleep(_SETTLE_SEC)
    assert _process_alive(pid, pwsh), f"monitor pid {pid} must be alive before stop"

    stopped = _run_scratch_stop(scripts_dir, log_dir)
    assert stopped.returncode == 0, f"stop_monitors must exit 0; stderr={stopped.stderr!r}"

    time.sleep(_SETTLE_SEC)
    assert not _process_alive(pid, pwsh), f"monitor pid {pid} must be dead after stop_monitors"
    assert not (log_dir / _PID_FILE_NAME).exists(), "PID file must be deleted after a successful stop"


def _verify_default_logdir_pid_file(
    completed: CompletedProcess[str],
    fake_programdata: Path,
    expected_log_dir: Path,
    pwsh: str,
) -> list[int]:
    r"""Assert a no-arg launch wrote its PID file under ``%ProgramData%``.

    Args:
        completed: Completed start launcher process (run with no LogDir arg).
        fake_programdata: Redirected ``%ProgramData%`` root for diagnostics.
        expected_log_dir: ``<ProgramData>\Intellicrack\Sandbox\logs`` path.
        pwsh: Absolute path to ``pwsh.exe`` for liveness checks.

    Returns:
        list[int]: The single tracked PID, for caller cleanup.
    """
    assert completed.returncode == 0, f"launcher must succeed with default LogDir; stderr={completed.stderr!r}"
    pid_file = expected_log_dir / _PID_FILE_NAME
    assert pid_file.is_file(), (
        f"default run must write PID file under %ProgramData%; expected {pid_file}, "
        f"programdata tree={[str(p) for p in fake_programdata.rglob('*')]}"
    )
    entries = _read_pid_file(expected_log_dir)
    assert len(entries) == 1, f"expected one tracked monitor in default log dir; entries={entries!r}"
    pid = entries[0][0]
    time.sleep(_SETTLE_SEC)
    assert _process_alive(pid, pwsh), f"monitor pid {pid} spawned via default LogDir must be live"
    return [pid]
