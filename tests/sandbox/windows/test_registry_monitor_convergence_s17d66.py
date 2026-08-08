# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D66: the Windows Sandbox Registry Changes tab reported garbage.

Measured live: every row of the Registry Changes tab showed the literal
constant ``Microsoft.PowerShell.Core\Registry`` in its key column, the real key
path in its value-name column, and ``<name>::<type>`` in its type column, and a
deleted registry value was never reported at all.

:meth:`WindowsSandbox._create_monitor_scripts` copies every bundled ``.ps1``
into the guest monitor folder - including the correct
``sandbox/scripts/registry_monitor.ps1`` - and then calls
:meth:`WindowsSandbox._emit_inline_monitors`, which used to write a second,
divergent registry monitor over the top of it. That embedded copy built its
tracking key by joining PowerShell's provider-qualified ``PSPath`` with
``'::'`` and split it back with ``-split '::', 3``. ``PSPath`` already contains
``'::'``, so every field landed one boundary off. Its deletion branch compared
a provider-qualified key against a drive-qualified root prefix, two forms that
can never share a prefix, so the branch was unreachable.

These gates never restate which script should win. They drive the real
production staging path into a temporary directory and observe which script
actually lands in the guest monitor folder, then launch that staged file under
a real ``powershell.exe``, make it observe a real ``HKCU`` value being created,
modified and deleted, and read the resulting ``registry_monitor.log`` back
through :meth:`WindowsSandbox._attach_all_logs` - the same host-side path the
report tab draws from.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import time
import winreg
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.base import ExecutionReport, SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.sandbox.base import RegistryChange


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="registry_monitor.ps1 targets the Windows registry provider",
)

_SCRIPT_NAME: Final[str] = "registry_monitor.ps1"
_LOG_NAME: Final[str] = "registry_monitor.log"
_MONITOR_DIR_NAME: Final[str] = "monitor"
_LOGS_DIR_NAME: Final[str] = "logs"

_WATCHED_RUN_KEY: Final[str] = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_PROBE_SUBKEY: Final[str] = "IntellicrackS17D66RegistryProbe"
_PROBE_KEY_PATH: Final[str] = f"{_WATCHED_RUN_KEY}\\{_PROBE_SUBKEY}"
_PROBE_VALUE_NAME: Final[str] = "ProbeCommand"
_PROBE_VALUE_CREATED: Final[str] = r"C:\IntellicrackProbe\first.exe"
_PROBE_VALUE_MODIFIED: Final[str] = r"C:\IntellicrackProbe\second.exe"
_EXPECTED_KEY_PREFIX: Final[str] = "HKCU\\"
_PROVIDER_PREFIX: Final[str] = "Microsoft.PowerShell.Core"

_STARTUP_GRACE_S: Final[float] = 45.0
_DETECTION_TIMEOUT_S: Final[float] = 180.0
_DETECTION_POLL_S: Final[float] = 1.0
_PROCESS_KILL_GRACE_S: Final[float] = 5.0


class _RegistryReportSandbox(WindowsSandbox):
    """``WindowsSandbox`` staged against, and read back from, a host directory."""

    async def stage_monitor_fleet(self, shared: Path) -> Path:
        """Run the real monitor staging path against ``shared``.

        Args:
            shared: Host directory standing in for the guest's shared folder.

        Returns:
            Path: The guest monitor folder the production code staged into.
        """
        self._shared_folder = shared
        monitor_folder = shared / _MONITOR_DIR_NAME
        self._monitor_folder = monitor_folder
        await asyncio.to_thread(monitor_folder.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread((shared / _LOGS_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_monitor_scripts()
        return monitor_folder

    async def collect_registry_changes(self) -> list[RegistryChange]:
        """Read the guest's registry log through the real report-building path.

        Returns:
            list[RegistryChange]: Exactly the records the Registry Changes tab
            renders, produced by :meth:`WindowsSandbox._attach_all_logs`.
        """
        report = ExecutionReport(
            result="success",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.0,
        )
        await self._attach_all_logs(report)
        return report.registry_changes


@dataclass(frozen=True)
class _RunOutcome:
    """What one live monitor process observed and printed.

    Attributes:
        saw_created: Whether the monitor logged a created action for the probe.
        saw_modified: Whether the monitor logged a modified action.
        saw_deleted: Whether the monitor logged a deleted action.
        stdout: Standard output the monitor process produced.
        stderr: Standard error the monitor process produced.
    """

    saw_created: bool
    saw_modified: bool
    saw_deleted: bool
    stdout: str
    stderr: str


@dataclass(frozen=True)
class _ProbeObservation:
    """Everything one live monitor run produced, shared by the gates below.

    Attributes:
        staged_bytes: Bytes of the registry monitor the staging path left in
            the guest monitor folder.
        bundled_bytes: Bytes of the bundled ``registry_monitor.ps1``.
        saw_created: Whether the monitor logged a created action for the probe.
        saw_modified: Whether the monitor logged a modified action.
        saw_deleted: Whether the monitor logged a deleted action.
        raw_log: Final contents of ``registry_monitor.log``.
        stdout: Standard output the monitor process produced.
        stderr: Standard error the monitor process produced.
        all_rows: Every record the host-side report path parsed.
        probe_rows: The subset of ``all_rows`` naming the probe subkey in any
            column.
    """

    staged_bytes: bytes
    bundled_bytes: bytes
    saw_created: bool
    saw_modified: bool
    saw_deleted: bool
    raw_log: str
    stdout: str
    stderr: str
    all_rows: list[RegistryChange]
    probe_rows: list[RegistryChange]


def _delete_probe_key() -> None:
    """Remove the probe subkey, tolerating it already being absent."""
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, _PROBE_KEY_PATH)
    except FileNotFoundError:
        return


def _write_probe_value(data: str) -> None:
    """Create or overwrite the probe value under the watched ``Run`` key.

    Args:
        data: String data to store in the probe value.
    """
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _PROBE_KEY_PATH, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, _PROBE_VALUE_NAME, 0, winreg.REG_SZ, data)
    finally:
        winreg.CloseKey(key)


def _read_log(log_path: Path) -> str:
    """Read the monitor log as text, tolerating a not-yet-created file.

    Args:
        log_path: Path to ``registry_monitor.log``.

    Returns:
        str: Current log contents, or the empty string if the file is absent.
    """
    if not log_path.is_file():
        return ""
    return log_path.read_text(encoding="utf-8", errors="replace")


def _probe_log_lines(log_path: Path, action: str) -> list[str]:
    """Return raw log lines naming the probe subkey with the given action.

    Args:
        log_path: Path to ``registry_monitor.log``.
        action: Action token to match, such as ``"created"``.

    Returns:
        list[str]: Matching raw lines, in the order the monitor wrote them.
    """
    marker = f"|{action}|"
    return [line for line in _read_log(log_path).splitlines() if _PROBE_SUBKEY in line and marker in line]


async def _await_action(log_path: Path, action: str) -> bool:
    """Poll the monitor log until it reports ``action`` for the probe value.

    Args:
        log_path: Path to ``registry_monitor.log``.
        action: Action token to wait for, such as ``"deleted"``.

    Returns:
        bool: Whether the action appeared before the detection timeout.
    """
    deadline = time.monotonic() + _DETECTION_TIMEOUT_S
    while True:
        if _probe_log_lines(log_path, action):
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(_DETECTION_POLL_S)


def _terminate(proc: Popen[str]) -> tuple[str, str]:
    """Stop the monitor process and collect whatever it wrote.

    Args:
        proc: The running monitor process.

    Returns:
        tuple[str, str]: Captured ``(stdout, stderr)``.
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=_PROCESS_KILL_GRACE_S)
        except TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=_PROCESS_KILL_GRACE_S)
    else:
        stdout, stderr = proc.communicate(timeout=_PROCESS_KILL_GRACE_S)
    return stdout or "", stderr or ""


def _mentions_probe(change: RegistryChange) -> bool:
    """Report whether a parsed record names the probe subkey in any column.

    The broken embedded monitor put the real key path in the value-name
    column, so matching on the key column alone would silently drop its rows
    and degrade a precise column assertion into a vague "nothing was reported".

    Args:
        change: One parsed registry change record.

    Returns:
        bool: Whether the probe subkey appears in the key, value name, or
        value type column.
    """
    columns = (change["key"], change["value_name"], change["value_type"])
    return any(_PROBE_SUBKEY in (column or "") for column in columns)


def _launch_staged_monitor(script_path: Path, logs_dir: Path, powershell: str) -> Popen[str]:
    """Start the staged monitor exactly as ``start_monitors.cmd`` does.

    Args:
        script_path: Staged ``registry_monitor.ps1`` in the guest monitor folder.
        logs_dir: Directory passed through ``-LogDir``.
        powershell: Absolute path to ``powershell.exe``.

    Returns:
        Popen[str]: The running monitor process.
    """
    argv = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
        str(script_path),
        "-LogDir",
        str(logs_dir),
    ]
    return Popen(argv, stdout=PIPE, stderr=PIPE, text=True, encoding="utf-8", errors="replace")


async def _drive_probe_lifecycle(script: Path, logs_dir: Path, powershell: str) -> _RunOutcome:
    """Run the staged monitor while a real value is created, changed and removed.

    Args:
        script: Staged ``registry_monitor.ps1`` to run.
        logs_dir: Directory the monitor writes its log into.
        powershell: Absolute path to ``powershell.exe``.

    Returns:
        _RunOutcome: Which actions the monitor logged, plus its output.

    Raises:
        AssertionError: If the monitor died during its baseline snapshot,
            before it could observe anything at all.
    """
    log_path = logs_dir / _LOG_NAME
    saw_created = False
    saw_modified = False
    saw_deleted = False

    _delete_probe_key()
    proc = _launch_staged_monitor(script, logs_dir, powershell)
    try:
        await asyncio.sleep(_STARTUP_GRACE_S)
        if proc.poll() is not None:
            early_out, early_err = _terminate(proc)
            msg = f"the staged registry monitor exited during its baseline snapshot; stdout={early_out!r} stderr={early_err!r}"
            raise AssertionError(msg)

        _write_probe_value(_PROBE_VALUE_CREATED)
        saw_created = await _await_action(log_path, "created")
        if saw_created:
            _write_probe_value(_PROBE_VALUE_MODIFIED)
            saw_modified = await _await_action(log_path, "modified")
        if saw_modified:
            _delete_probe_key()
            saw_deleted = await _await_action(log_path, "deleted")
    finally:
        stdout, stderr = _terminate(proc)
        _delete_probe_key()

    return _RunOutcome(
        saw_created=saw_created,
        saw_modified=saw_modified,
        saw_deleted=saw_deleted,
        stdout=stdout,
        stderr=stderr,
    )


async def _observe_probe_lifecycle(root: Path) -> _ProbeObservation:
    """Stage the fleet, drive a real value through its lifecycle, read the report.

    Args:
        root: Temporary directory to use as the sandbox shared folder root.

    Returns:
        _ProbeObservation: What the run produced, for the gates to assert on.

    Raises:
        AssertionError: If ``powershell.exe`` is unavailable or the staging
            path left no registry monitor for the guest to run.
    """
    powershell = shutil.which("powershell")
    if powershell is None:
        msg = "Windows PowerShell 5.1 (powershell.exe) is required to run the staged registry_monitor.ps1"
        raise AssertionError(msg)

    shared = root / "shared"
    sandbox = _RegistryReportSandbox(SandboxConfig())
    monitor_folder = await sandbox.stage_monitor_fleet(shared)

    staged = monitor_folder / _SCRIPT_NAME
    if not staged.is_file():
        msg = f"no registry monitor was staged into the guest monitor folder at {staged}"
        raise AssertionError(msg)

    logs_dir = shared / _LOGS_DIR_NAME
    outcome = await _drive_probe_lifecycle(staged, logs_dir, powershell)
    all_rows = await sandbox.collect_registry_changes()

    return _ProbeObservation(
        staged_bytes=staged.read_bytes(),
        bundled_bytes=(WindowsSandbox.bundled_scripts_dir() / _SCRIPT_NAME).read_bytes(),
        saw_created=outcome.saw_created,
        saw_modified=outcome.saw_modified,
        saw_deleted=outcome.saw_deleted,
        raw_log=_read_log(logs_dir / _LOG_NAME),
        stdout=outcome.stdout,
        stderr=outcome.stderr,
        all_rows=all_rows,
        probe_rows=[row for row in all_rows if _mentions_probe(row)],
    )


@pytest.fixture(scope="module")
def observation(tmp_path_factory: pytest.TempPathFactory) -> _ProbeObservation:
    """Run the live monitor lifecycle once and share it with every gate.

    Args:
        tmp_path_factory: pytest-provided temporary directory factory.

    Returns:
        _ProbeObservation: Result of the single live run.
    """
    return asyncio.run(_observe_probe_lifecycle(tmp_path_factory.mktemp("s17d66")))


class TestTheGuestReceivesOneRegistryMonitor:
    """Whatever reaches the guest monitor folder must be the converged script."""

    def test_the_staged_script_is_the_bundled_script(self, observation: _ProbeObservation) -> None:
        """The staged bytes must equal the bundled script's bytes.

        This observes the file the production staging path actually left
        behind. When a second monitor is emitted over the top of the bundled
        one, the bytes differ and this fails.

        Args:
            observation: The shared live-run result.
        """
        assert observation.staged_bytes == observation.bundled_bytes, (
            f"the guest receives a different registry monitor than the bundled one; "
            f"staged {len(observation.staged_bytes)} bytes starting {observation.staged_bytes[:120]!r}, "
            f"bundled {len(observation.bundled_bytes)} bytes starting {observation.bundled_bytes[:120]!r}"
        )


class TestTheReportColumnsHoldTheRightFields:
    """The columns the live audit found misaligned on every row."""

    def test_the_probe_value_is_reported_at_all(self, observation: _ProbeObservation) -> None:
        """A real created and modified value must reach the parsed report.

        Args:
            observation: The shared live-run result.
        """
        assert observation.saw_created, (
            f"the monitor never reported the probe value being created within {_DETECTION_TIMEOUT_S}s; "
            f"log={observation.raw_log!r} stdout={observation.stdout!r} stderr={observation.stderr!r}"
        )
        assert observation.saw_modified, (
            f"the monitor never reported the probe value being modified within {_DETECTION_TIMEOUT_S}s; "
            f"log={observation.raw_log!r} stdout={observation.stdout!r} stderr={observation.stderr!r}"
        )
        assert observation.probe_rows, (
            f"the probe value reached the log but no parsed row names it; parsed={observation.all_rows!r} log={observation.raw_log!r}"
        )

    def test_the_key_column_is_a_hive_path(self, observation: _ProbeObservation) -> None:
        r"""The key column must be ``HKCU\...``, not a provider constant.

        Args:
            observation: The shared live-run result.
        """
        assert observation.probe_rows, f"no parsed row names the probe value; parsed={observation.all_rows!r}"
        misfiled = [row for row in observation.probe_rows if not row["key"].startswith(_EXPECTED_KEY_PREFIX)]
        assert not misfiled, (
            f"the key column is not a hive path an analyst can act on; expected every key to start with "
            f"{_EXPECTED_KEY_PREFIX!r}, saw {[row['key'] for row in misfiled]!r}"
        )
        provider_qualified = [row for row in observation.probe_rows if row["key"].startswith(_PROVIDER_PREFIX)]
        assert not provider_qualified, (
            f"the key column still holds PowerShell's provider constant instead of the key path; "
            f"saw {[row['key'] for row in provider_qualified]!r}"
        )
        truncated = [row for row in observation.probe_rows if not row["key"].endswith(_PROBE_SUBKEY)]
        assert not truncated, (
            f"the key column does not end at the probe subkey {_PROBE_SUBKEY!r}; saw {[row['key'] for row in truncated]!r}"
        )

    def test_the_value_name_column_holds_the_value_name(self, observation: _ProbeObservation) -> None:
        """The value-name column must hold the value name, not the key path.

        Args:
            observation: The shared live-run result.
        """
        assert observation.probe_rows, f"no parsed row names the probe value; parsed={observation.all_rows!r}"
        wrong = [row for row in observation.probe_rows if row["value_name"] != _PROBE_VALUE_NAME]
        assert not wrong, (
            f"the value-name column does not hold the real value name {_PROBE_VALUE_NAME!r}; "
            f"saw {[(row['key'], row['value_name'], row['value_type']) for row in wrong]!r}"
        )

    def test_the_value_type_column_holds_only_a_type(self, observation: _ProbeObservation) -> None:
        """The type column must carry a bare type, not a merged name and type.

        Args:
            observation: The shared live-run result.
        """
        assert observation.probe_rows, f"no parsed row names the probe value; parsed={observation.all_rows!r}"
        merged = [row for row in observation.probe_rows if _PROBE_VALUE_NAME in (row["value_type"] or "")]
        assert not merged, f"the value-type column carries the value name merged into it; saw {[row['value_type'] for row in merged]!r}"
        assert all(row["value_type"] == "String" for row in observation.probe_rows), (
            f"the value-type column does not report the REG_SZ value's real kind; "
            f"saw {[row['value_type'] for row in observation.probe_rows]!r}"
        )

    def test_the_modified_row_carries_the_data_that_was_written(self, observation: _ProbeObservation) -> None:
        """A modified row's data column must hold the newly written data.

        Args:
            observation: The shared live-run result.
        """
        modified = [row for row in observation.probe_rows if row["operation"] == "modified"]
        assert modified, f"no modified row reached the report for the probe value; parsed rows={observation.probe_rows!r}"
        assert all(row["value_data"] == _PROBE_VALUE_MODIFIED for row in modified), (
            f"the value-data column does not carry the data actually written; expected {_PROBE_VALUE_MODIFIED!r}, "
            f"saw {[row['value_data'] for row in modified]!r}"
        )


class TestADeletedValueIsReported:
    """The second half of S17-D66: deletion detection was unreachable."""

    def test_the_monitor_logs_the_deletion(self, observation: _ProbeObservation) -> None:
        """Deleting a watched value must produce a deleted line in the log.

        Args:
            observation: The shared live-run result.
        """
        assert observation.saw_deleted, (
            f"the monitor never reported the probe value being deleted within {_DETECTION_TIMEOUT_S}s; "
            f"log={observation.raw_log!r} stdout={observation.stdout!r} stderr={observation.stderr!r}"
        )

    def test_a_deleted_row_reaches_the_report(self, observation: _ProbeObservation) -> None:
        """The parsed report must contain a deleted row for the probe value.

        Args:
            observation: The shared live-run result.
        """
        deleted = [row for row in observation.probe_rows if row["operation"] == "deleted"]
        assert deleted, (
            f"no deleted row reached the report for the probe value; parsed rows={observation.probe_rows!r} log={observation.raw_log!r}"
        )
        assert all(row["value_name"] == _PROBE_VALUE_NAME for row in deleted), (
            f"a deleted row does not name the deleted value; saw {[(row['key'], row['value_name']) for row in deleted]!r}"
        )
