# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S18-D22: the tabs were read before the collectors had written.

Measured live on a Windows Sandbox run that genuinely made registry changes and
genuinely touched the clipboard: the Registry Changes and Clipboard tabs came
back empty. The host read them at ``14:47:29``. The surviving collectors' logs
reached the host across a 21-second spread after that point - dll and file at
+0s, kernel_object and process at +1s, resource and service at +2s, registry at
+5s, network at +21s - against a three-second quiescence budget.

The budget could not have detected this. What it waited on was the aggregate
size of the log files holding still, and a collector that has not written yet
has no file at all: it contributes zero bytes, which is perfectly stable. The
check therefore returned almost immediately and reported "settled" for a fleet
where four collectors had not produced a single record.

:meth:`WindowsSandbox._wait_for_monitor_quiescence` now waits on the *set* of
collectors that have produced a log, taken from the ``monitors.pids`` file the
launcher's readiness gate leaves behind.

These gates never restate that file's format or which monitors are in it. They
run the real ``start_monitors.cmd`` from ``src/intellicrack/sandbox/scripts``
against a scratch monitor folder, so the pid file under test is one production
wrote, and they drive the real wait against the real log files real PowerShell
children produce. The late collector holds its first record until the test
releases it, which is what puts the arrival on the far side of the old budget.
"""

from __future__ import annotations

import ast
import shutil
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, SubprocessError, run
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Generator, Mapping


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="start_monitors.cmd and the monitor fleet are Windows-only",
)

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SANDBOX_DIR: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox"
_SCRIPTS_DIR: Final[Path] = _SANDBOX_DIR / "scripts"
_START_SCRIPT: Final[Path] = _SCRIPTS_DIR / "start_monitors.cmd"
_BACKEND_SOURCE: Final[Path] = _SANDBOX_DIR / "windows.py"
_ERR_NO_CONSTANT: Final[str] = "{name} is not declared as a numeric constant in {path}"
_LAUNCH_TIMEOUT_S: Final[float] = 120.0
_STOP_FLAG_NAME: Final[str] = "stop.flag"
_TRIGGER_NAME: Final[str] = "reading.trigger"
# Long enough to outlive the slowest gate here, short enough that a scratch
# monitor cannot outlive the test session if cleanup is skipped.
_MONITOR_LIFETIME_S: Final[int] = 240
# The arrival the old three-second budget could not have waited for. It has to
# clear that budget by a wide margin and stay well inside the settle window, so
# that reaching it proves the completion path rather than the settle path.
_LATE_ARRIVAL_S: Final[int] = 8
_STOP_GRACE_S: Final[float] = 3.0
_KILL_TIMEOUT_S: Final[float] = 15.0

_PREAMBLE: Final[str] = (
    "param([string]$LogDir = '.')\n"
    "$ErrorActionPreference = 'Stop'\n"
    "$stem = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)\n"
    "$log = Join-Path -Path $LogDir -ChildPath ($stem + '.log')\n"
)
_WRITE_RECORD: Final[str] = "Add-Content -LiteralPath $log -Value ((Get-Date).ToString('o') + '|record') -Encoding utf8\n"
_AWAIT_TRIGGER: Final[str] = (
    "$trigger = Join-Path -Path $LogDir -ChildPath '__TRIGGER__'\n"
    "$triggerDeadline = (Get-Date).AddSeconds(__LIFETIME__)\n"
    "while (-not (Test-Path -LiteralPath $trigger) -and (Get-Date) -lt $triggerDeadline) {\n"
    "    Start-Sleep -Milliseconds 100\n"
    "}\n"
    "Start-Sleep -Seconds __DELAY__\n"
)
_IDLE_TAIL: Final[str] = (
    "$stop = Join-Path -Path $LogDir -ChildPath '__STOP__'\n"
    "$idleDeadline = (Get-Date).AddSeconds(__LIFETIME__)\n"
    "while (-not (Test-Path -LiteralPath $stop) -and (Get-Date) -lt $idleDeadline) {\n"
    "    Start-Sleep -Milliseconds 200\n"
    "}\n"
)


def _production_seconds(name: str) -> float:
    """Read one of the backend's own quiescence budgets out of its source.

    The bounds these gates assert against have to be the budgets production
    actually uses, and importing them would reach into another module's private
    namespace. Parsing the declaration keeps the value derived rather than
    restated, and a rename or removal fails here instead of quietly leaving the
    gate measuring a number nothing enforces.

    Args:
        name: Module-level constant to read from the Windows backend.

    Returns:
        float: The declared value in seconds.

    Raises:
        AssertionError: If the backend declares no such numeric constant.
    """
    tree = ast.parse(_BACKEND_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, int | float):
            return float(value.value)
    raise AssertionError(_ERR_NO_CONSTANT.format(name=name, path=_BACKEND_SOURCE))


_SETTLE_S: Final[float] = _production_seconds("_MONITOR_QUIESCENCE_SETTLE_S")
_CEILING_S: Final[float] = _production_seconds("_MONITOR_QUIESCENCE_CEILING_S")


def _fill(template: str, *, delay: int = 0) -> str:
    """Substitute the scratch-monitor placeholders in a PowerShell fragment.

    Args:
        template: Fragment containing ``__STOP__``, ``__TRIGGER__``,
            ``__LIFETIME__`` or ``__DELAY__`` placeholders.
        delay: Seconds substituted for ``__DELAY__``.

    Returns:
        str: The fragment with every placeholder resolved.
    """
    return (
        template.replace("__STOP__", _STOP_FLAG_NAME)
        .replace("__TRIGGER__", _TRIGGER_NAME)
        .replace("__LIFETIME__", str(_MONITOR_LIFETIME_S))
        .replace("__DELAY__", str(delay))
    )


def _prompt_monitor() -> str:
    """Build a collector that writes its first record at startup.

    Returns:
        str: PowerShell source for a monitor whose log exists before the
        quiescence wait begins.
    """
    return _PREAMBLE + _WRITE_RECORD + _fill(_IDLE_TAIL)


def _late_monitor() -> str:
    """Build a collector that writes only after the test releases it.

    The delay is measured from the trigger file rather than from launch, so the
    arrival lands on the far side of the old budget no matter how long the
    launcher's own readiness gate took.

    Returns:
        str: PowerShell source for a monitor whose log appears
        :data:`_LATE_ARRIVAL_S` seconds after the trigger.
    """
    return _PREAMBLE + _fill(_AWAIT_TRIGGER, delay=_LATE_ARRIVAL_S) + _WRITE_RECORD + _fill(_IDLE_TAIL)


def _silent_monitor() -> str:
    """Build a collector that survives startup and never writes a record.

    Returns:
        str: PowerShell source for a monitor that never creates its log, which
        is how a real collector with nothing to report behaves.
    """
    return _PREAMBLE + _fill(_IDLE_TAIL)


@dataclass(frozen=True)
class _Fleet:
    """A launched scratch monitor fleet and the folders it writes into.

    Attributes:
        shared: Host-side shared folder root handed to the sandbox.
        logs: ``logs`` subfolder the launcher and monitors write into.
    """

    shared: Path
    logs: Path

    def log_of(self, stem: str) -> Path:
        """Return the log path a collector with ``stem`` would create.

        Args:
            stem: Script stem of the collector.

        Returns:
            Path: Path to that collector's log file.
        """
        return self.logs / f"{stem}.log"

    def release_late_collectors(self) -> None:
        """Drop the trigger file the late collector is waiting on."""
        (self.logs / _TRIGGER_NAME).write_text("go", encoding="ascii")


class _QuiescenceSandbox(WindowsSandbox):
    """Exposes the quiescence wait and its inputs without private access.

    ``basedpyright`` reports ``reportPrivateUsage`` for a test that reaches into
    a private member directly, so the members under test are forwarded through
    public methods on a subclass - the same pattern the other sandbox gates use.
    """

    def use_shared_folder(self, path: Path) -> None:
        """Point the sandbox at a host-side shared folder.

        Args:
            path: Folder whose ``logs`` subfolder holds the monitor output.
        """
        self._shared_folder = path

    def surviving_collectors(self) -> set[str]:
        """Forward to :meth:`WindowsSandbox._surviving_collectors`.

        Returns:
            set[str]: Script stems the launcher recorded as survivors.
        """
        return self._surviving_collectors()

    async def wait_for_monitor_quiescence(self) -> None:
        """Forward to :meth:`WindowsSandbox._wait_for_monitor_quiescence`."""
        await self._wait_for_monitor_quiescence()


def _resolve_cmd() -> str:
    """Locate ``cmd.exe`` for invoking the launcher.

    Returns:
        str: Absolute path to ``cmd.exe``.
    """
    cmd = shutil.which("cmd.exe") or shutil.which("cmd")
    if cmd is None:
        pytest.skip("cmd.exe is required to run start_monitors.cmd")
    return cmd


def _stop_fleet(fleet: _Fleet) -> None:
    """Shut the scratch monitors down and reap anything that ignores the flag.

    Args:
        fleet: The launched fleet to shut down.
    """
    (fleet.logs / _STOP_FLAG_NAME).write_text("stop", encoding="ascii")
    time.sleep(_STOP_GRACE_S)
    taskkill = shutil.which("taskkill")
    pid_file = fleet.logs / "monitors.pids"
    if taskkill is None or not pid_file.is_file():
        return
    for line in pid_file.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split(maxsplit=1)
        if not fields or not fields[0].isdigit():
            continue
        try:
            run(
                [taskkill, "/PID", fields[0], "/F", "/T"],
                stdout=DEVNULL,
                stderr=DEVNULL,
                check=False,
                timeout=_KILL_TIMEOUT_S,
            )
        except (SubprocessError, OSError):
            continue


@contextmanager
def _launched_fleet(workspace: Path, monitors: Mapping[str, str]) -> Generator[_Fleet]:
    """Run the real launcher over a scratch monitor folder and yield the fleet.

    The launcher, not the test, writes ``monitors.pids``: that file is the input
    the wait under test reads, and deriving it from production is the only way
    the gate can notice if its format or contents ever change.

    Args:
        workspace: Directory in which to materialise the scratch layout.
        monitors: Mapping of script file name to PowerShell source.

    Yields:
        _Fleet: The launched fleet, shut down again when the block exits.
    """
    scripts_dir = workspace / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_START_SCRIPT, scripts_dir / _START_SCRIPT.name)
    for helper in _SCRIPTS_DIR.glob("_*.ps1"):
        shutil.copy2(helper, scripts_dir / helper.name)
    for name, source in monitors.items():
        (scripts_dir / name).write_text(source, encoding="utf-8")

    shared = workspace / "shared"
    logs = shared / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    fleet = _Fleet(shared=shared, logs=logs)

    stderr_path = workspace / "launcher.stderr.txt"
    try:
        with stderr_path.open("wb") as err_handle:
            completed = run(
                [_resolve_cmd(), "/c", str(scripts_dir / _START_SCRIPT.name), str(logs)],
                stdout=DEVNULL,
                stderr=err_handle,
                stdin=DEVNULL,
                check=False,
                timeout=_LAUNCH_TIMEOUT_S,
            )
        assert completed.returncode == 0, (
            f"start_monitors.cmd exited {completed.returncode}; stderr={stderr_path.read_text(encoding='utf-8', errors='replace')!r}"
        )
        yield fleet
    finally:
        _stop_fleet(fleet)


def _build_sandbox(fleet: _Fleet) -> _QuiescenceSandbox:
    """Build a sandbox whose shared folder is the fleet's output folder.

    Args:
        fleet: The launched fleet.

    Returns:
        _QuiescenceSandbox: Sandbox ready to run the quiescence wait. No
        Windows Sandbox process is started.
    """
    sandbox = _QuiescenceSandbox()
    sandbox.use_shared_folder(fleet.shared)
    return sandbox


@pytest.mark.asyncio
async def test_the_wait_does_not_return_before_a_late_collector_has_written(tmp_path: Path) -> None:
    """A collector whose first record lands after the old budget is waited for.

    Two collectors report at startup and a third holds its record until the
    trigger is dropped, eight seconds before it writes. That is the shape of the
    live failure: the tab reader was released while a collector still had
    nothing on disk, and the tab it fills came back empty.

    Args:
        tmp_path: Workspace for the scratch scripts and shared folder.
    """
    monitors = {
        "prompt_alpha.ps1": _prompt_monitor(),
        "prompt_beta.ps1": _prompt_monitor(),
        "late_gamma.ps1": _late_monitor(),
    }
    with _launched_fleet(tmp_path, monitors) as fleet:
        late_log = fleet.log_of("late_gamma")
        assert fleet.log_of("prompt_alpha").is_file(), "prompt collector never reported; the fleet did not start"
        assert not late_log.exists(), (
            f"late_gamma reported before the trigger was dropped, so this run cannot distinguish "
            f"waiting for it from returning early; log={late_log}"
        )

        sandbox = _build_sandbox(fleet)
        fleet.release_late_collectors()
        started = time.monotonic()
        await sandbox.wait_for_monitor_quiescence()
        elapsed = time.monotonic() - started

        assert late_log.is_file(), (
            f"the wait returned after {elapsed:.1f}s with late_gamma's log still absent; "
            f"a report read at this point renders that collector's tab empty. "
            f"present={sorted(p.name for p in fleet.logs.glob('*.log'))}"
        )
        assert elapsed >= _LATE_ARRIVAL_S, (
            f"the wait returned after {elapsed:.1f}s but late_gamma does not write for {_LATE_ARRIVAL_S}s "
            f"after the trigger; the log must have been left over rather than waited for"
        )
        assert elapsed < _SETTLE_S, (
            f"the wait took {elapsed:.1f}s with every collector reporting; it should have returned as soon "
            f"as the last one arrived rather than sitting out the {_SETTLE_S:.0f}s settle window"
        )


@pytest.mark.asyncio
async def test_the_command_dispatcher_is_not_waited_on_as_a_collector(tmp_path: Path) -> None:
    """The dispatcher shares the pid file but fills no tab, so it is excluded.

    It is recorded by the same launcher as every monitor and it never writes a
    ``.log``. Counting it as a collector would make the fleet permanently
    incomplete and cost the whole settle window on every single run.

    Args:
        tmp_path: Workspace for the scratch scripts and shared folder.
    """
    monitors = {
        "prompt_alpha.ps1": _prompt_monitor(),
        "prompt_beta.ps1": _prompt_monitor(),
        "sandbox_dispatcher.ps1": _silent_monitor(),
    }
    with _launched_fleet(tmp_path, monitors) as fleet:
        sandbox = _build_sandbox(fleet)

        assert sandbox.surviving_collectors() == {"prompt_alpha", "prompt_beta"}, (
            f"the collector fleet read back from the launcher's pid file was "
            f"{sorted(sandbox.surviving_collectors())}; the dispatcher serves commands and has no tab"
        )

        started = time.monotonic()
        await sandbox.wait_for_monitor_quiescence()
        elapsed = time.monotonic() - started

        assert elapsed < _SETTLE_S, (
            f"the wait took {elapsed:.1f}s with both collectors already reporting; that is the settle window, "
            f"which is what waiting for the dispatcher's log - a file it never writes - would cost"
        )


@pytest.mark.asyncio
async def test_a_collector_that_never_writes_settles_instead_of_running_to_the_ceiling(tmp_path: Path) -> None:
    """A collector with nothing to report must not hold the report hostage.

    Several monitors legitimately produce no log at all on a quiet run, so the
    fleet can never be completed. The wait has to give up on the stragglers once
    no further log has arrived, and it has to do that on the settle window
    rather than on the ceiling.

    Args:
        tmp_path: Workspace for the scratch scripts and shared folder.
    """
    monitors = {
        "prompt_alpha.ps1": _prompt_monitor(),
        "silent_delta.ps1": _silent_monitor(),
    }
    with _launched_fleet(tmp_path, monitors) as fleet:
        sandbox = _build_sandbox(fleet)
        assert not fleet.log_of("silent_delta").exists(), "silent_delta wrote a log; it cannot stand in for a quiet collector"

        started = time.monotonic()
        await sandbox.wait_for_monitor_quiescence()
        elapsed = time.monotonic() - started

        assert elapsed >= _SETTLE_S - 1.0, (
            f"the wait returned after {elapsed:.1f}s with silent_delta still absent; it gave up before the "
            f"{_SETTLE_S:.0f}s settle window, which is the same early release the live run made"
        )
        assert elapsed < _CEILING_S, (
            f"the wait ran {elapsed:.1f}s, to its {_CEILING_S:.0f}s ceiling; a collector with "
            f"nothing to report has to be settled out, not waited for until the budget expires"
        )
