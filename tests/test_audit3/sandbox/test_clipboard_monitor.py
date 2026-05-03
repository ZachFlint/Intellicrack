# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U3 tests for ``clipboard_monitor.ps1`` remediation.

Validates the four fixes applied to
``src/intellicrack/sandbox/scripts/clipboard_monitor.ps1``:

* F-0001 - the polling fallback is reachable when ``Add-Type`` fails.
* F-0002 - the file no longer relies on ``$ErrorActionPreference =
  'SilentlyContinue'``; failures are caught explicitly and emitted as
  structured JSON log records.
* F-0003 - the caller-supplied ``-LogDir`` is honored for all log writes.
* F-0004 - the handler does not assign to the read-only automatic
  variable ``$pid`` (renamed to ``$ownerPid``).

The tests run the real script under ``pwsh`` against the live filesystem
and clipboard. They are skipped on non-Windows platforms because the
script targets the Windows clipboard subsystem.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

import pytest


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "clipboard_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 4.0
_PWSH_KILL_GRACE_SEC: Final[float] = 2.0
_LOG_NAME: Final[str] = "clipboard_monitor.log"


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="clipboard_monitor.ps1 targets Windows clipboard APIs",
)


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Calls ``pytest.skip`` if ``pwsh`` is not on ``PATH``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for clipboard_monitor tests")
    return pwsh


def _pwsh_argv(pwsh: str, script: Path, log_dir: Path | None) -> list[str]:
    """Build the argv used to invoke a PowerShell monitor script.

    Args:
        pwsh: Absolute path to the ``pwsh`` executable.
        script: Path to the ``.ps1`` script to run.
        log_dir: Directory to pass via ``-LogDir``, or ``None`` to omit
            the parameter so the script falls back to its default.

    Returns:
        list[str]: The full argv list ready to be passed to
        ``subprocess.Popen`` or ``subprocess.run``.
    """
    argv = [
        pwsh,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    if log_dir is not None:
        argv.extend(["-LogDir", str(log_dir)])
    return argv


def _start_script(log_dir: Path, pwsh: str) -> subprocess.Popen[str]:
    """Spawn ``clipboard_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        subprocess.Popen[str]: The running script process.
    """
    return subprocess.Popen(
        _pwsh_argv(pwsh, _SCRIPT_PATH, log_dir),
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


def _set_clipboard(value: str, pwsh: str) -> None:
    """Write a value to the Windows clipboard via ``Set-Clipboard``.

    Asserts that ``Set-Clipboard`` returns a zero exit code.

    Args:
        value: Text to place on the clipboard.
        pwsh: Absolute path to the ``pwsh`` executable.
    """
    completed = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Set-Clipboard -Value '{value}'",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_PWSH_LAUNCH_TIMEOUT_SEC,
    )
    assert completed.returncode == 0, f"Set-Clipboard failed: rc={completed.returncode} stderr={completed.stderr!r}"


def _scan_fallback_log(contents: str) -> tuple[bool, bool]:
    """Parse a clipboard-monitor log to look for fallback-mode markers.

    Args:
        contents: Full text of the log file.

    Returns:
        tuple[bool, bool]: ``(saw_add_type_error, saw_fallback_line)``,
        where the first element is ``True`` if a JSON record with
        ``event == "init.add_type_failed"`` was observed and the second
        element is ``True`` if at least one pipe-delimited fallback log
        line of the form ``ts|changed|...`` was observed.
    """
    saw_add_type_error = False
    saw_fallback_line = False
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if payload.get("event") == "init.add_type_failed":
                saw_add_type_error = True
        else:
            fields = line.split("|")
            if len(fields) >= 7 and fields[1] == "changed":
                saw_fallback_line = True
    return saw_add_type_error, saw_fallback_line


def test_script_file_exists() -> None:
    """The remediated script must exist on disk."""
    assert _SCRIPT_PATH.is_file(), f"missing script: {_SCRIPT_PATH}"


def test_script_does_not_use_blanket_silentlycontinue() -> None:
    """F-0002: file-level ``SilentlyContinue`` must be gone.

    The script must opt into ``$ErrorActionPreference = 'Stop'`` rather
    than swallowing every error globally.
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "$ErrorActionPreference = 'Stop'" in text
    assert "$ErrorActionPreference = 'SilentlyContinue'" not in text


def test_script_does_not_clobber_pid_automatic_variable() -> None:
    """F-0004: assignment to the automatic variable ``$pid`` is forbidden.

    The user-supplied pid must use a different name (``$ownerPid``).
    """
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "$pid =" not in text
    assert "$pid=" not in text
    assert "$ownerPid" in text


def test_script_accepts_logdir_parameter() -> None:
    """F-0003: the script must declare a ``-LogDir`` parameter."""
    text = _SCRIPT_PATH.read_text(encoding="utf-8")
    assert "[Parameter()][string]$LogDir" in text


def test_script_runs_without_pid_readonly_error(tmp_path: Path) -> None:
    """Verify the script does not crash with the read-only ``$pid`` error.

    F-0004 runtime check: starting the script must not raise the "PID is
    read-only" error from clobbering ``$pid``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    combined = f"{stdout}\n{stderr}"
    assert "Cannot overwrite variable PID" not in combined, f"script attempted to clobber $pid: {combined}"
    assert "read-only or constant" not in combined, f"script tripped a read-only assignment: {combined}"


def test_script_writes_logs_to_supplied_logdir(tmp_path: Path) -> None:
    """F-0003 runtime check: log lines must land in the supplied ``-LogDir``.

    Args:
        tmp_path: Pytest-provided temp directory used as ``-LogDir``.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "isolated_logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        _set_clipboard("audit3-logdir-check", pwsh)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        _terminate(proc)

    assert log_path.exists(), f"expected log file at {log_path}; tmp dir contents: {list(log_dir.iterdir())}"
    contents = log_path.read_text(encoding="utf-8", errors="replace")
    assert contents.strip(), f"log file at {log_path} is empty"


def _find_unused_drive_letter() -> str | None:
    """Find an uppercase drive letter that is not currently mounted.

    Returns:
        str | None: An uppercase drive letter (without a colon) that is
        not in use, or ``None`` if every letter from ``Z`` down to ``E``
        is mounted.
    """
    for letter in "ZYXWVUTSRQPONMLKJIHGFE":
        if not Path(f"{letter}:\\").exists():
            return letter
    return None


def test_script_emits_structured_error_when_logdir_is_unwritable() -> None:
    """Verify the script surfaces errors instead of swallowing them silently.

    F-0002 runtime check: pointing ``-LogDir`` at a path on a drive that
    does not exist should cause the script to fail fast under
    ``$ErrorActionPreference = 'Stop'`` rather than exit 0 with no
    output.
    """
    pwsh = _resolve_pwsh()
    drive = _find_unused_drive_letter()
    if drive is None:
        pytest.skip("no unused drive letter available to construct an unwritable LogDir")

    bad_log_dir = Path(f"{drive}:\\intellicrack-audit3-no-such-drive\\logs")

    completed = subprocess.run(
        _pwsh_argv(pwsh, _SCRIPT_PATH, bad_log_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_PWSH_LAUNCH_TIMEOUT_SEC + _PWSH_KILL_GRACE_SEC,
    )

    assert completed.returncode != 0, (
        "script should raise on unwritable LogDir under -ErrorActionPreference Stop "
        f"but returned 0; stdout={completed.stdout!r} stderr={completed.stderr!r}"
    )
    combined = completed.stdout + completed.stderr
    assert combined.strip(), "script returned non-zero but produced no diagnostic output; errors are being swallowed"


def test_script_logs_structured_json_when_add_type_fails(tmp_path: Path) -> None:
    """Verify the polling fallback runs when ``Add-Type`` fails.

    F-0001 runtime check: to trigger the failure path we run the script
    under a transformed copy that injects an invalid C# source so
    ``Add-Type`` raises. The original script's structured error logger
    must record ``init.add_type_failed`` in the supplied ``-LogDir``,
    and the polling loop must execute (we kill it before it spins
    indefinitely).

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    original = _SCRIPT_PATH.read_text(encoding="utf-8")
    poisoned = original.replace(
        "Add-Type -TypeDefinition $clipSource",
        "Add-Type -TypeDefinition '<<<not valid c#>>>'",
        1,
    )
    assert poisoned != original, "failed to inject Add-Type failure"

    poisoned_script = tmp_path / "clipboard_monitor_poisoned.ps1"
    poisoned_script.write_text(poisoned, encoding="utf-8")

    proc = subprocess.Popen(
        _pwsh_argv(pwsh, poisoned_script, log_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        _set_clipboard("audit3-fallback-check", pwsh)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        stdout, stderr, _ = _terminate(proc)

    log_path = log_dir / _LOG_NAME
    assert log_path.exists(), f"expected log file at {log_path}; stdout={stdout!r} stderr={stderr!r}"

    contents = log_path.read_text(encoding="utf-8", errors="replace")
    assert contents.strip(), f"fallback path produced no log output; stdout={stdout!r} stderr={stderr!r}"

    saw_add_type_error, saw_fallback_line = _scan_fallback_log(contents)
    assert saw_add_type_error, f"expected init.add_type_failed JSON record in log; contents={contents!r}"
    assert saw_fallback_line, f"expected at least one polling-fallback log line; contents={contents!r}"


def test_smoke_script_logs_clipboard_change(tmp_path: Path) -> None:
    """Verify a real ``Set-Clipboard`` write produces a log line.

    End-to-end smoke: copying text to the live Windows clipboard must
    produce a log entry in the supplied ``-LogDir``.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    proc = _start_script(log_dir, pwsh)
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        _set_clipboard("audit3-smoke", pwsh)
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
    finally:
        _terminate(proc)

    assert log_path.exists(), f"smoke log not created at {log_path}"
    contents = log_path.read_text(encoding="utf-8", errors="replace")
    assert contents.strip(), f"smoke log at {log_path} is empty"


def test_script_default_logdir_when_omitted(tmp_path: Path) -> None:
    """Verify the script supplies a default for ``-LogDir``.

    Callers (such as ``start_monitors.cmd``) that omit the argument
    must not crash with a parameter binding error, and the default
    directory must be created on demand.

    Args:
        tmp_path: Pytest-provided temp directory used to override
            ``USERPROFILE`` so the default path stays inside the test
            sandbox.
    """
    pwsh = _resolve_pwsh()

    env = dict(os.environ)
    env["USERPROFILE"] = str(tmp_path)

    proc = subprocess.Popen(
        _pwsh_argv(pwsh, _SCRIPT_PATH, log_dir=None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    try:
        time.sleep(_PWSH_LAUNCH_TIMEOUT_SEC)
        still_running = proc.poll() is None
    finally:
        stdout, stderr, _ = _terminate(proc)

    assert still_running, f"script exited immediately when -LogDir omitted; stdout={stdout!r} stderr={stderr!r}"

    expected_default = tmp_path / "Desktop" / "Shared" / "logs"
    assert expected_default.is_dir(), f"default -LogDir was not created at {expected_default}; stdout={stdout!r} stderr={stderr!r}"
