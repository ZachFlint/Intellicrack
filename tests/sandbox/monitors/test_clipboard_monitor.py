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
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import (
    PIPE,
    Popen,
    TimeoutExpired,
    run,
)


if TYPE_CHECKING:
    from collections.abc import Callable


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "clipboard_monitor.ps1"
_PWSH_LAUNCH_TIMEOUT_SEC: Final[float] = 60.0
_PWSH_KILL_GRACE_SEC: Final[float] = 15.0
_READY_DEADLINE_SEC: Final[float] = 90.0
_RECORD_DEADLINE_SEC: Final[float] = 30.0
_POLL_INTERVAL_SEC: Final[float] = 0.25
_READY_EVENT: Final[str] = "monitor.ready"
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
        ``Popen`` or ``run``.
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


def _start_script(log_dir: Path, pwsh: str) -> Popen[str]:
    """Spawn ``clipboard_monitor.ps1`` with the supplied log directory.

    Args:
        log_dir: Directory passed to the script via ``-LogDir``.
        pwsh: Absolute path to the ``pwsh`` executable.

    Returns:
        Popen[str]: The running script process.
    """
    return Popen(
        _pwsh_argv(pwsh, _SCRIPT_PATH, log_dir),
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
        returncode)``. ``returncode`` is ``None`` if the process had to
        be killed because it ignored ``terminate``.
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


def _set_clipboard(value: str, pwsh: str) -> None:
    """Write a value to the Windows clipboard via ``Set-Clipboard``.

    Asserts that ``Set-Clipboard`` returns a zero exit code.

    Args:
        value: Text to place on the clipboard.
        pwsh: Absolute path to the ``pwsh`` executable.
    """
    completed = run(
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


def _read_log(log_path: Path) -> str:
    """Return the monitor log's current contents, or empty string if absent.

    Args:
        log_path: Path to the monitor log file.

    Returns:
        str: The file's text, or ``""`` when it does not yet exist.
    """
    if not log_path.exists():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")


def _wait_for_ready(log_path: Path, proc: Popen[str], deadline_sec: float) -> bool:
    """Wait until the monitor records that its clipboard listener is active.

    Polling for the readiness marker replaces a fixed warm-up sleep that races
    the monitor's cold start: ``pwsh`` startup and the C# ``Add-Type`` compile
    can take several seconds under load, and a clipboard change written before
    the listener is registered is never seen.

    Args:
        log_path: Path to the monitor log file.
        proc: The running monitor process, polled so a crash ends the wait early.
        deadline_sec: Longest time to wait for readiness.

    Returns:
        bool: ``True`` once the readiness marker is present, else ``False``.
    """
    end = time.monotonic() + deadline_sec
    while time.monotonic() < end:
        if _READY_EVENT in _read_log(log_path):
            return True
        if proc.poll() is not None:
            break
        time.sleep(_POLL_INTERVAL_SEC)
    return _READY_EVENT in _read_log(log_path)


def _wait_for_log(log_path: Path, predicate: Callable[[str], bool], deadline_sec: float) -> str:
    """Poll the monitor log until ``predicate`` accepts its contents or time runs out.

    Args:
        log_path: Path to the monitor log file.
        predicate: Returns ``True`` once the log holds the awaited record.
        deadline_sec: Longest time to wait.

    Returns:
        str: The log contents at the moment the predicate passed, or the final
        contents read when the deadline elapsed.
    """
    end = time.monotonic() + deadline_sec
    while time.monotonic() < end:
        contents = _read_log(log_path)
        if predicate(contents):
            return contents
        time.sleep(_POLL_INTERVAL_SEC)
    return _read_log(log_path)


def _parse_json_log_records(contents: str) -> list[dict[str, object]]:
    """Extract all valid JSON log records from clipboard-monitor log text.

    Scans each line; lines that start with ``{`` and parse as valid JSON
    objects are collected and returned.

    Args:
        contents: Full text of the log file.

    Returns:
        list[dict[str, object]]: Each element is a parsed JSON record dict.
    """
    records: list[dict[str, object]] = []
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload: dict[str, object] = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(payload)
    return records


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

    sentinel = "audit3-logdir-check"
    proc = _start_script(log_dir, pwsh)
    try:
        assert _wait_for_ready(log_path, proc, _READY_DEADLINE_SEC), f"monitor never became ready; log contents: {_read_log(log_path)!r}"
        _set_clipboard(sentinel, pwsh)
        contents = _wait_for_log(
            log_path,
            lambda text: any(len(rec) > 3 and sentinel in rec[3] for rec in _parse_pipe_log_records(text)),
            _RECORD_DEADLINE_SEC,
        )
    finally:
        _terminate(proc)

    assert log_path.exists(), f"expected log file at {log_path}; tmp dir contents: {list(log_dir.iterdir())}"
    assert any(len(rec) > 3 and sentinel in rec[3] for rec in _parse_pipe_log_records(contents)), (
        f"no change record for {sentinel!r} landed in {log_path}; contents: {contents!r}"
    )


def _find_unused_drive_letter() -> str | None:
    """Find an uppercase drive letter that is not currently mounted.

    Returns:
        str | None: An uppercase drive letter (without a colon) that is
        not in use, or ``None`` if every letter from ``Z`` down to ``E``
        is mounted.
    """
    return next(
        (letter for letter in "ZYXWVUTSRQPONMLKJIHGFE" if not Path(f"{letter}:\\").exists()),
        None,
    )


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

    completed = run(
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


def _assert_add_type_failed_record(rec: dict[str, object], log_path: Path) -> None:
    """Assert exact structure of an ``init.add_type_failed`` JSON log record.

    Validates all required fields emitted by ``Write-StructuredError`` when
    ``Add-Type`` compilation fails during script initialisation.

    Args:
        rec: Parsed JSON record dict to validate.
        log_path: Path to the log file, included in failure messages.

    Raises:
        AssertionError: If any required field is absent, has the wrong type,
            or fails its value constraint.
    """
    required_keys = {"timestamp", "event", "error", "fallback"}
    assert set(rec.keys()) >= required_keys, (
        f"init.add_type_failed record missing keys {required_keys - set(rec.keys())!r}; got keys={set(rec.keys())!r} from {log_path}"
    )
    assert rec["event"] == "init.add_type_failed", f"event field must be 'init.add_type_failed', got {rec['event']!r}"
    assert rec["fallback"] == "polling", f"fallback field must be 'polling', got {rec['fallback']!r}"

    ts_raw = rec["timestamp"]
    assert isinstance(ts_raw, str), f"timestamp field must be a string, got {type(ts_raw)!r}"
    assert ts_raw, f"timestamp field must not be empty; full record: {rec!r}"
    try:
        datetime.fromisoformat(ts_raw)
    except ValueError as exc:
        msg = f"timestamp {ts_raw!r} is not a valid ISO 8601 datetime: {exc}"
        raise AssertionError(msg) from exc

    error_raw = rec["error"]
    assert isinstance(error_raw, str), f"error field must be a string, got {type(error_raw)!r}"
    assert error_raw, f"error field must not be empty; full record: {rec!r}"
    assert "CS" in error_raw or "error" in error_raw.lower(), f"error field must contain a C# compiler diagnostic; got {error_raw!r}"


def test_script_logs_structured_json_when_add_type_fails(tmp_path: Path) -> None:
    """Verify the exact JSON structure emitted when ``Add-Type`` compilation fails.

    F-0001 runtime check: injecting invalid C# into ``Add-Type`` must cause the
    script to emit a JSON record whose fields exactly match the schema defined by
    ``Write-StructuredError``:

    * ``event`` == ``"init.add_type_failed"``
    * ``fallback`` == ``"polling"``
    * ``timestamp`` is a non-empty ISO 8601 string
    * ``error`` is a non-empty string containing C# compiler diagnostic text

    After writing that record the script must remain alive, which proves
    ``Invoke-FallbackPolling`` was called rather than the script exiting on error.

    Note: the fallback polling loop cannot detect clipboard changes in a headless
    subprocess because ``Get-Clipboard -Raw`` returns an empty string when invoked
    without a window station (production defect).  This test therefore validates
    the error-record structure and fallback-loop entry only; it does not assert
    that a clipboard change record was produced.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    original = _SCRIPT_PATH.read_text(encoding="utf-8")
    poisoned = original.replace(
        "Add-Type -TypeDefinition $clipSource",
        "Add-Type -TypeDefinition '<<<not valid c#>>>'",
        1,
    )
    assert poisoned != original, "failed to inject Add-Type failure into script text"

    poisoned_script = tmp_path / "clipboard_monitor_poisoned.ps1"
    poisoned_script.write_text(poisoned, encoding="utf-8")

    proc = Popen(
        _pwsh_argv(pwsh, poisoned_script, log_dir),
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        contents = _wait_for_log(
            log_path,
            lambda text: any(r.get("event") == "init.add_type_failed" for r in _parse_json_log_records(text)),
            _READY_DEADLINE_SEC,
        )
        still_alive_after_init = proc.poll() is None
    finally:
        stdout, stderr, _ = _terminate(proc)

    assert log_path.exists(), f"expected log file at {log_path}; stdout={stdout!r} stderr={stderr!r}"
    assert contents.strip(), f"fallback path produced no log output; stdout={stdout!r} stderr={stderr!r}"

    json_records = _parse_json_log_records(contents)
    assert json_records, f"no valid JSON records in log; full contents={contents!r} stdout={stdout!r} stderr={stderr!r}"

    add_type_records = [r for r in json_records if r.get("event") == "init.add_type_failed"]
    assert add_type_records, f"no record with event='init.add_type_failed'; json_records={json_records!r}"

    _assert_add_type_failed_record(add_type_records[0], log_path)

    assert still_alive_after_init, (
        "script must stay alive after Add-Type failure (polling loop must be entered), "
        f"but process exited; stdout={stdout!r} stderr={stderr!r}"
    )


_SMOKE_SENTINEL: Final[str] = "audit3-smoke-gate"
_SMOKE_SENTINEL_BYTES: Final[int] = len(_SMOKE_SENTINEL.encode("utf-8"))


def _parse_pipe_log_records(contents: str) -> list[list[str]]:
    """Extract all valid pipe-delimited clipboard change records from log text.

    A valid record is a non-JSON line that splits into exactly 7 pipe-separated
    fields where the second field (index 1) is ``"changed"``.

    Args:
        contents: Full text content of the clipboard monitor log file.

    Returns:
        list[list[str]]: Each element is a 7-element list of field strings from
        one valid change record.
    """
    records: list[list[str]] = []
    for raw in contents.splitlines():
        line = raw.strip()
        if not line or line.startswith("{"):
            continue
        fields = line.split("|")
        if len(fields) == 7 and fields[1] == "changed":
            records.append(fields)
    return records


def _validate_pipe_log_record(rec: list[str], sentinel: str, sentinel_bytes: int, before: datetime) -> None:
    """Assert that a single pipe-delimited clipboard change record is structurally correct.

    Validates all seven fields of the format produced by ``clipboard_monitor.ps1``
    for a text clipboard event.  This function is an independent oracle: expected
    values are computed from the known sentinel string and the test's start time,
    not derived from the implementation being tested.

    Args:
        rec: A 7-element list of strings from a pipe-split log line.
        sentinel: The exact sentinel string that was written to the clipboard.
        sentinel_bytes: The independently computed UTF-8 byte count of ``sentinel``.
        before: The UTC ``datetime`` recorded just before the script was started;
            used as the lower bound for the log record timestamp.

    Raises:
        AssertionError: If any field fails its structural or value constraint.
    """
    assert len(rec) == 7, f"change record must have exactly 7 pipe-separated fields, got {len(rec)}: {rec!r}"

    try:
        ts = datetime.fromisoformat(rec[0])
    except ValueError as exc:
        msg = f"field[0] (timestamp) {rec[0]!r} is not a valid ISO 8601 datetime: {exc}"
        raise AssertionError(msg) from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    assert ts >= before, f"field[0] timestamp {ts.isoformat()} predates test start {before.isoformat()}"

    assert rec[1] == "changed", f"field[1] must be the literal 'changed', got {rec[1]!r}"

    assert rec[2] == "Text", f"field[2] (clipboard format) must be 'Text' for a text Set-Clipboard write, got {rec[2]!r}"

    assert sentinel in rec[3], f"field[3] (preview) must contain sentinel {sentinel!r}, got {rec[3]!r}"

    assert rec[4] == str(sentinel_bytes), (
        f"field[4] (size) must equal {sentinel_bytes} (independent UTF-8 byte count of sentinel), got {rec[4]!r}"
    )

    try:
        owner_pid = int(rec[5])
    except ValueError as exc:
        msg = f"field[5] (owner PID) {rec[5]!r} is not a valid integer: {exc}"
        raise AssertionError(msg) from exc
    assert owner_pid >= 0, f"field[5] (owner PID) must be non-negative, got {owner_pid}"

    assert rec[6].strip(), f"field[6] (process name) must be a non-empty string, got {rec[6]!r}"


def test_smoke_script_logs_clipboard_change(tmp_path: Path) -> None:
    """Verify a real ``Set-Clipboard`` write produces a structurally correct log record.

    End-to-end gate: copying a sentinel string to the live Windows clipboard must
    produce a pipe-delimited log entry in the supplied ``-LogDir`` whose fields
    precisely match the format produced by ``clipboard_monitor.ps1``:

    * 7 pipe-separated fields
    * field[0] is a valid ISO 8601 timestamp not earlier than the test start
    * field[1] is the literal string ``"changed"``
    * field[2] is ``"Text"`` (the clipboard data type for a text write)
    * field[3] contains the sentinel string (the preview field, truncated to 100 chars)
    * field[4] is the exact decimal UTF-8 byte count of the sentinel string
    * field[5] is a non-negative integer (the owner process PID)
    * field[6] is a non-empty string (the owning process name)

    The expected byte count in field[4] is independently derived from
    ``len(sentinel.encode("utf-8"))`` -- a separate computation that does not
    invoke any production code -- making this a genuine falsifiable oracle.

    This exercises the event-driven clipboard path. The listener records a
    readiness marker once it is registered, which the test waits for before it
    writes the clipboard, so the change is written while the listener is live
    and is caught by ``WM_CLIPBOARDUPDATE`` rather than depending on the polling
    fallback. The script references the ``System.ComponentModel.Primitives``,
    ``System.Windows.Forms.Primitives`` and ``System.Drawing.Primitives``
    assemblies on PowerShell Core so the listener compiles under .NET as well as
    under Windows PowerShell.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    pwsh = _resolve_pwsh()
    log_dir = tmp_path / "smoke_logs"
    log_dir.mkdir()
    log_path = log_dir / _LOG_NAME

    proc = _start_script(log_dir, pwsh)
    try:
        assert _wait_for_ready(log_path, proc, _READY_DEADLINE_SEC), f"monitor never became ready; log contents: {_read_log(log_path)!r}"
        before = datetime.now(tz=UTC)
        _set_clipboard(_SMOKE_SENTINEL, pwsh)
        contents = _wait_for_log(
            log_path,
            lambda text: any(len(rec) > 3 and _SMOKE_SENTINEL in rec[3] for rec in _parse_pipe_log_records(text)),
            _RECORD_DEADLINE_SEC,
        )
    finally:
        _terminate(proc)

    assert log_path.exists(), f"smoke log not created at {log_path}"
    assert contents.strip(), f"smoke log at {log_path} is empty"

    records = _parse_pipe_log_records(contents)
    assert records, (
        f"no valid pipe-delimited 'changed' records found in log;\n"
        f"expected: a line matching ts|changed|Text|{_SMOKE_SENTINEL!r}|{_SMOKE_SENTINEL_BYTES}|<pid>|<proc>\n"
        f"actual log contents:\n{contents!r}"
    )

    matching = [r for r in records if _SMOKE_SENTINEL in r[3]]
    assert matching, (
        f"no pipe-delimited record whose preview field[3] contains sentinel {_SMOKE_SENTINEL!r};\nall change records found: {records!r}"
    )

    _validate_pipe_log_record(matching[0], _SMOKE_SENTINEL, _SMOKE_SENTINEL_BYTES, before)


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

    proc = Popen(
        _pwsh_argv(pwsh, _SCRIPT_PATH, log_dir=None),
        stdout=PIPE,
        stderr=PIPE,
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
