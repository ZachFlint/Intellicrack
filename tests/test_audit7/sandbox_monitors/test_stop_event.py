# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit7 F-0025 tests for coordinated monitor shutdown.

Validates the named ``IntellicrackMonitorStop`` event wired into the
four monitor scripts (``api_trace.ps1``, ``dll_monitor.ps1``,
``injection_monitor.ps1``, ``kernel_object_monitor.ps1``) and the
``stop_monitors.cmd`` driver / ``_stop_monitors_helper.ps1`` shim that
signals it.

Test surfaces:

* Source-level guards confirm every monitor opens the named event,
  polls it, and emits a lifecycle ``stopped`` record in its
  ``finally`` clause.
* ``_stop_monitors_helper.ps1`` is exercised end-to-end on Windows:
  a long-running consumer process is signalled via the helper and
  must exit voluntarily within the configured grace window.
* On Windows the real ``kernel_object_monitor.ps1`` is started and
  signalled, and the lifecycle log must record both ``started`` and
  ``stopped`` entries (proving its ``finally`` ran).
"""

from __future__ import annotations

import contextlib
import shutil
import sys
import time
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import (
    DEVNULL,
    PIPE,
    Popen,
    SubprocessError,
    TimeoutExpired,
    run,
)


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts"
_DLL_MONITOR: Final[Path] = _SCRIPTS_DIR / "dll_monitor.ps1"
_API_TRACE: Final[Path] = _SCRIPTS_DIR / "api_trace.ps1"
_INJECTION_MONITOR: Final[Path] = _SCRIPTS_DIR / "injection_monitor.ps1"
_KERNEL_OBJECT_MONITOR: Final[Path] = _SCRIPTS_DIR / "kernel_object_monitor.ps1"
_STOP_HELPER: Final[Path] = _SCRIPTS_DIR / "_stop_monitors_helper.ps1"
_STOP_MONITORS_CMD: Final[Path] = _SCRIPTS_DIR / "stop_monitors.cmd"
_START_MONITORS_CMD: Final[Path] = _SCRIPTS_DIR / "start_monitors.cmd"

_STOP_EVENT_NAME: Final[str] = "IntellicrackMonitorStop"

_KERNEL_OBJECT_LIFECYCLE_LOG: Final[str] = "kernel_object_monitor.lifecycle.log"

_HELPER_TIMEOUT_SEC: Final[float] = 30.0
_PWSH_KILL_GRACE_SEC: Final[float] = 8.0
_FINALLY_FLUSH_TIMEOUT_SEC: Final[float] = 240.0
_FAST_POLL_INTERVAL_MS: Final[int] = 100


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable for invoking PowerShell scripts.

    Returns:
        str: Absolute path to the ``pwsh`` executable.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for F-0025 tests")
    return pwsh


def _resolve_cmd() -> str:
    """Locate ``cmd.exe`` for invoking the stop_monitors.cmd driver.

    Returns:
        str: Absolute path to ``cmd.exe``.
    """
    cmd = shutil.which("cmd.exe") or shutil.which("cmd")
    if cmd is None:
        pytest.skip("cmd.exe is required for stop_monitors driver tests")
    return cmd


def _wait_for_marker(path: Path, marker: str, timeout_sec: float) -> bool:
    """Poll ``path`` until ``marker`` appears or ``timeout_sec`` elapses.

    Args:
        path: File whose contents are searched for ``marker``.
        marker: Substring whose presence completes the wait.
        timeout_sec: Maximum number of seconds to wait.

    Returns:
        bool: ``True`` if the marker was observed before the deadline,
        otherwise ``False``.
    """
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                if marker in path.read_text(encoding="utf-8", errors="replace"):
                    return True
            except OSError:
                pass
        time.sleep(0.25)
    return False


# ----------------------------------------------------------------------
# Source-level guards (run on every platform).
# ----------------------------------------------------------------------


def test_helper_script_exists_with_required_modes() -> None:
    """The helper script must exist and expose ``SignalEvent`` / ``WaitForExit``."""
    assert _STOP_HELPER.is_file(), f"missing helper script: {_STOP_HELPER}"
    text = _STOP_HELPER.read_text(encoding="utf-8")
    assert "ValidateSet('SignalEvent', 'WaitForExit')" in text
    assert "EventWaitHandle" in text
    assert "WaitForExit" in text


def test_stop_monitors_cmd_signals_event_and_waits() -> None:
    """``stop_monitors.cmd`` must signal the event before falling back to ``taskkill``."""
    assert _STOP_MONITORS_CMD.is_file()
    text = _STOP_MONITORS_CMD.read_text(encoding="utf-8")
    assert _STOP_EVENT_NAME in text
    assert "DEFAULT_GRACE_SECONDS=10" in text, "default grace window must be 10 seconds"
    assert "-Mode SignalEvent" in text
    assert "-Mode WaitForExit" in text
    assert "taskkill /PID !TARGET_PID! /F /T" in text, "must retain taskkill fallback for unhonoured PIDs"


def test_start_monitors_skips_underscore_prefixed_scripts() -> None:
    """``start_monitors.cmd`` must not try to launch helper PS1 files.

    The filter lives inside ``:launch_one`` so the outer simple for-loop
    over ``*.ps1`` stays single-statement (no parenthesised body) — a
    parenthesised body around ``call :launch_one`` interacts badly with
    cmd's control-flow on some Windows builds and can leave the launcher
    hanging after the first monitor spawns.
    """
    text = _START_MONITORS_CMD.read_text(encoding="utf-8")
    assert '%SCRIPT_NAME:~0,1%"=="_"' in text, "leading-underscore filter must be present in :launch_one"
    assert "goto :eof" in text, "filter must skip via goto :eof"


@pytest.mark.parametrize(
    "script_path",
    [
        _DLL_MONITOR,
        _API_TRACE,
        _INJECTION_MONITOR,
        _KERNEL_OBJECT_MONITOR,
    ],
    ids=[
        "dll_monitor",
        "api_trace",
        "injection_monitor",
        "kernel_object_monitor",
    ],
)
def test_monitor_opens_named_stop_event(script_path: Path) -> None:
    """Each of the four monitors must open the named stop event at startup.

    Args:
        script_path: Path to the monitor script under test.
    """
    text = script_path.read_text(encoding="utf-8")
    assert "IntellicrackMonitorStop" in text, f"{script_path.name} must reference the named stop event"
    assert "Open-MonitorStopEvent" in text, f"{script_path.name} must define / use Open-MonitorStopEvent"
    assert "WaitOne(0)" in text, f"{script_path.name} must poll the stop event non-blocking"


@pytest.mark.parametrize(
    ("script_path", "lifecycle_helper"),
    [
        (_DLL_MONITOR, "Write-DllLifecycle"),
        (_API_TRACE, "Write-TraceLifecycle"),
        (_INJECTION_MONITOR, "Write-InjectionLifecycle"),
        (_KERNEL_OBJECT_MONITOR, "Write-KernelLifecycle"),
    ],
    ids=[
        "dll_monitor",
        "api_trace",
        "injection_monitor",
        "kernel_object_monitor",
    ],
)
def test_monitor_emits_lifecycle_records(script_path: Path, lifecycle_helper: str) -> None:
    """Each monitor must emit ``started`` and ``stopped`` lifecycle records.

    Args:
        script_path: Path to the monitor script under test.
        lifecycle_helper: Name of the script's lifecycle helper function.
    """
    text = script_path.read_text(encoding="utf-8")
    assert lifecycle_helper in text, f"{script_path.name} must define {lifecycle_helper}"
    assert f"{lifecycle_helper} -State 'started'" in text
    assert f"{lifecycle_helper} -State 'stopped'" in text


# ----------------------------------------------------------------------
# Windows-only integration tests.
# ----------------------------------------------------------------------


_WINDOWS_ONLY: Final = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Monitor stop-event integration requires Windows pwsh + Win32 named events",
)


@_WINDOWS_ONLY
def test_helper_signal_event_then_waitforexit_releases_consumer(tmp_path: Path) -> None:
    """The helper must signal the event and let a consumer exit voluntarily.

    Spawns a synthetic monitor-like consumer that opens the named event,
    polls it, and exits when set. Signals the event via the helper's
    ``SignalEvent`` mode and waits for the consumer via ``WaitForExit``.

    Uses a per-test event name so a previously-signalled manual-reset
    handle from another test cannot prematurely release the consumer.

    Args:
        tmp_path: Pytest-provided temp directory (unused — kept for
            parametrisation symmetry with future tests).
    """
    _ = tmp_path
    pwsh = _resolve_pwsh()
    test_event_name = f"IntellicrackMonitorStopTest_{int(time.monotonic_ns())}"
    consumer_script = (
        "$createdNew = $false;"
        f"$h = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::ManualReset, '{test_event_name}', [ref]$createdNew);"
        "$deadline = (Get-Date).AddSeconds(30);"
        "while ((Get-Date) -lt $deadline) {"
        "  if ($h.WaitOne(100)) { exit 0 };"
        "}"
        "exit 7"
    )

    consumer = Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            consumer_script,
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        _drive_consumer_signal_and_wait(consumer, pwsh, test_event_name)
    finally:
        if consumer.poll() is None:
            consumer.kill()
            with contextlib.suppress(TimeoutExpired):
                consumer.communicate(timeout=_PWSH_KILL_GRACE_SEC)


@_WINDOWS_ONLY
def test_kernel_object_monitor_finally_emits_stopped_record(tmp_path: Path) -> None:
    """The kernel-object monitor must run its ``finally`` after the stop event.

    Launches the real monitor against a temporary log directory, waits
    for the ``started`` lifecycle record, signals the named stop event,
    and asserts the ``stopped`` lifecycle record appears within the
    grace window. A successful run proves the main loop honoured the
    event and the ``finally`` clause flushed STOP telemetry.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    lifecycle_log = log_dir / _KERNEL_OBJECT_LIFECYCLE_LOG

    monitor = Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_KERNEL_OBJECT_MONITOR),
            "-LogDir",
            str(log_dir),
            "-PollIntervalMilliseconds",
            str(_FAST_POLL_INTERVAL_MS),
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        _drive_kernel_object_monitor_finally(monitor, lifecycle_log, pwsh)
    finally:
        if monitor.poll() is None:
            monitor.kill()
            with contextlib.suppress(TimeoutExpired):
                monitor.communicate(timeout=_PWSH_KILL_GRACE_SEC)


def _drive_consumer_signal_and_wait(
    consumer: Popen[str],
    pwsh: str,
    test_event_name: str,
) -> None:
    """Signal the stop event and assert the consumer exits cleanly.

    Args:
        consumer: Running consumer subprocess.
        pwsh: Absolute path to ``pwsh.exe`` driving the helper.
        test_event_name: Named event the consumer waits on.
    """
    time.sleep(1.5)
    assert consumer.poll() is None, "consumer must still be running before signal"

    signal = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_STOP_HELPER),
            "-Mode",
            "SignalEvent",
            "-EventName",
            test_event_name,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=_HELPER_TIMEOUT_SEC,
    )
    assert signal.returncode == 0, f"helper SignalEvent must exit 0; stderr={signal.stderr!r}"

    wait = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_STOP_HELPER),
            "-Mode",
            "WaitForExit",
            "-TargetPid",
            str(consumer.pid),
            "-WaitMilliseconds",
            "10000",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=_HELPER_TIMEOUT_SEC,
    )
    assert wait.returncode in {0, 2}, (
        f"helper WaitForExit must indicate graceful exit (0) or process gone (2); rc={wait.returncode} stderr={wait.stderr!r}"
    )

    consumer.communicate(timeout=_PWSH_KILL_GRACE_SEC)
    assert consumer.returncode == 0, f"consumer must exit 0 when stop event is signalled; rc={consumer.returncode}"


def _drive_kernel_object_monitor_finally(
    monitor: Popen[str],
    lifecycle_log: Path,
    pwsh: str,
) -> None:
    """Signal the kernel-object monitor and assert its finally fired.

    Args:
        monitor: Running monitor subprocess.
        lifecycle_log: Lifecycle log file the monitor writes to.
        pwsh: Absolute path to ``pwsh.exe`` driving the helper.
    """
    started = _wait_for_marker(lifecycle_log, "|started|", _FINALLY_FLUSH_TIMEOUT_SEC)
    if not started:
        stdout, stderr = monitor.communicate(timeout=_PWSH_KILL_GRACE_SEC)
        pytest.fail(
            f"kernel_object_monitor did not emit started lifecycle record within "
            f"{_FINALLY_FLUSH_TIMEOUT_SEC}s; stdout={stdout!r} stderr={stderr!r}",
        )

    signal = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(_STOP_HELPER),
            "-Mode",
            "SignalEvent",
            "-EventName",
            _STOP_EVENT_NAME,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=_HELPER_TIMEOUT_SEC,
    )
    assert signal.returncode == 0, f"failed to signal stop event; stderr={signal.stderr!r}"

    stopped = _wait_for_marker(lifecycle_log, "|stopped|", _FINALLY_FLUSH_TIMEOUT_SEC)
    try:
        monitor.wait(timeout=_FINALLY_FLUSH_TIMEOUT_SEC)
        graceful_exit = True
    except TimeoutExpired:
        graceful_exit = False

    contents = lifecycle_log.read_text(encoding="utf-8", errors="replace") if lifecycle_log.is_file() else ""
    assert stopped, f"kernel_object_monitor.lifecycle.log must record |stopped|; contents={contents!r}"
    assert graceful_exit, "monitor must exit voluntarily once the stop event is signalled"


def _drive_stop_monitors_consumer(
    consumer: Popen[bytes],
    cmd: str,
    scripts_dir: Path,
    log_dir: Path,
) -> None:
    """Run stop_monitors against the consumer PID and assert lifecycle.

    Args:
        consumer: Running consumer subprocess.
        cmd: Absolute path to ``cmd.exe`` for running the .cmd shim.
        scripts_dir: Scratch scripts directory with ``stop_monitors.cmd``.
        log_dir: Log directory referenced by both consumer and stopper.
    """
    time.sleep(2.0)
    assert consumer.poll() is None, "consumer must still be running before stop"

    stop = run(
        [cmd, "/c", str(scripts_dir / "stop_monitors.cmd"), str(log_dir), "5"],
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        check=False,
        timeout=60.0,
    )
    assert stop.returncode == 0, f"stop_monitors must succeed; returncode={stop.returncode}"

    info_path = log_dir / "stop_monitors.info.log"
    info_contents = info_path.read_text(encoding="utf-8", errors="replace") if info_path.is_file() else ""
    assert "graceful=" in info_contents, f"info log must record graceful count; contents={info_contents!r}"
    graceful_count = _parse_graceful_count(info_contents)
    assert graceful_count >= 1, f"at least one PID must exit gracefully; info={info_contents!r}"

    consumer_lifecycle = log_dir / "consumer.lifecycle.log"
    assert consumer_lifecycle.is_file(), f"consumer.ps1 finally clause must have written its lifecycle log; dir={list(log_dir.iterdir())!r}"
    consumer_text = consumer_lifecycle.read_text(encoding="utf-8", errors="replace")
    assert "|consumer|stopped" in consumer_text, f"consumer finally did not run; contents={consumer_text!r}"


def _ensure_taskkill() -> str:
    """Locate ``taskkill.exe`` for cleanup of leaked monitor processes.

    Returns:
        str: Absolute path to ``taskkill.exe``, or the literal name
        ``taskkill`` if it cannot be resolved (the call site uses it
        only for best-effort cleanup).
    """
    return shutil.which("taskkill") or "taskkill"


def _materialise_stop_driver_scripts(scripts_dir: Path) -> None:
    """Copy ``start_monitors`` / ``stop_monitors`` / helper into ``scripts_dir``.

    Args:
        scripts_dir: Existing directory that will receive the scratch
            launcher, stopper, and helper.
    """
    (scripts_dir / "start_monitors.cmd").write_text(
        _START_MONITORS_CMD.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (scripts_dir / "stop_monitors.cmd").write_text(
        _STOP_MONITORS_CMD.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (scripts_dir / _STOP_HELPER.name).write_text(
        _STOP_HELPER.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def _materialise_consumer_monitor(scripts_dir: Path, event_name: str) -> None:
    """Create a long-running consumer monitor for the F-0025 driver test.

    The consumer opens the named stop event, polls it, and writes a
    lifecycle record from its ``finally`` clause so the test can assert
    graceful shutdown.

    Args:
        scripts_dir: Directory to receive ``consumer.ps1``.
        event_name: Named kernel event to honour.
    """
    consumer_source = (
        "param([string]$LogDir = '.')\n"
        "$createdNew = $false\n"
        f"$h = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::ManualReset, '{event_name}', [ref]$createdNew)\n"
        "try {\n"
        "  $deadline = (Get-Date).AddSeconds(300)\n"
        "  while ((Get-Date) -lt $deadline) {\n"
        "    if ($h.WaitOne(100)) { break }\n"
        "  }\n"
        "} finally {\n"
        "  $line = (Get-Date).ToString('o') + '|consumer|stopped'\n"
        "  Add-Content -LiteralPath (Join-Path $LogDir 'consumer.lifecycle.log') -Value $line -Encoding utf8\n"
        "}\n"
    )
    (scripts_dir / "consumer.ps1").write_text(consumer_source, encoding="utf-8")


def _parse_graceful_count(info_contents: str) -> int:
    """Return the ``graceful=N`` count from the stop_monitors info log.

    Args:
        info_contents: Full text of ``stop_monitors.info.log``.

    Returns:
        int: Number of PIDs reported as gracefully reaped (zero when
        the summary line is missing or malformed).
    """
    summary_lines = [line for line in info_contents.splitlines() if "summary:" in line]
    if not summary_lines:
        return 0
    summary_line = summary_lines[-1]
    graceful_token = next((tok for tok in summary_line.split() if tok.startswith("graceful=")), "")
    if "=" not in graceful_token:
        return 0
    try:
        return int(graceful_token.split("=", 1)[1])
    except ValueError:
        return 0


@_WINDOWS_ONLY
def test_stop_monitors_driver_signals_event_before_taskkill(tmp_path: Path) -> None:
    """``stop_monitors.cmd`` must honour stop-event-aware consumers first.

    Spawns a stop-event-aware consumer process directly (bypassing
    ``start_monitors.cmd`` so the test is not entangled with the
    inherited-handle quirks of cmd-spawned grandchildren), records its
    PID in the ``monitors.pids`` file consumed by ``stop_monitors.cmd``,
    runs the stop driver with a 5 s grace window, and asserts the
    info log shows the consumer was reaped as ``graceful`` (not via the
    ``taskkill`` fallback) and the consumer's ``finally`` clause ran.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    cmd = _resolve_cmd()
    taskkill_exe = _ensure_taskkill()

    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    _materialise_stop_driver_scripts(scripts_dir)
    _materialise_consumer_monitor(scripts_dir, _STOP_EVENT_NAME)

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    # Spawn the consumer directly so the cmd.exe -> powershell.exe ->
    # Start-Process inherited-handle chain in start_monitors.cmd does not
    # interfere with this assertion. The test on start_monitors.cmd itself
    # lives in tests/test_audit3/sandbox/test_start_monitors.py.
    consumer = Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(scripts_dir / "consumer.ps1"),
            "-LogDir",
            str(log_dir),
        ],
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
    )
    pids = [consumer.pid]
    pid_file = log_dir / "monitors.pids"
    pid_file.write_text(f"{consumer.pid} consumer.ps1\n", encoding="utf-8")

    try:
        _drive_stop_monitors_consumer(consumer, cmd, scripts_dir, log_dir)
    finally:
        for pid in pids:
            try:
                run(
                    [taskkill_exe, "/PID", str(pid), "/F", "/T"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10.0,
                )
            except (SubprocessError, OSError):
                continue
