# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: every script the Windows backend stages tells the launcher whether it started.

``start_monitors.cmd`` used to decide that a monitor had started by waiting out
a time window and counting whatever was still alive at the end of it. It now
takes a monitor's own report as the only proof: the launcher hands each script
the path of a file, and the script creates that file once its startup can no
longer fail. A script that exits without creating it failed; one that keeps
running without creating it is reported as failed when the launcher's wait
limit runs out.

That makes the report part of what a staged script has to do. One that never
makes it would hold the guest's bootstrap for the whole wait limit on every
sandbox start and be reported as a failure while working perfectly. So this
gate stages the fleet with the backend's own staging code, runs the real
launcher over it with its default wait limit, and requires that no script was
left running unreported and that every script able to start anywhere did start.

The dispatcher is staged beside the monitors and launched with them. Its guest
paths are pointed at a scratch directory so that running it here leaves nothing
behind outside the test's own folder.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, SubprocessError, run
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="start_monitors.cmd and the PowerShell monitor fleet it launches are Windows-only",
)

_LAUNCHER_NAME: Final[str] = "start_monitors.cmd"
_PID_FILE_NAME: Final[str] = "monitors.pids"
_MONITOR_DIR_NAME: Final[str] = "monitor"
_LOGS_DIR_NAME: Final[str] = "logs"
_GUEST_DIR_NAME: Final[str] = "guest"
_HELPER_PREFIX: Final[str] = "_"
_UNREPORTED: Final[str] = "did not report ready"
_NOT_LAUNCHED: Final[str] = "failed to launch"
_LAUNCH_TIMEOUT_S: Final[float] = 420.0
_KILL_TIMEOUT_S: Final[float] = 15.0
_NEED_A_TRACE_SESSION: Final[frozenset[str]] = frozenset({"api_trace.ps1", "dll_monitor.ps1", "injection_monitor.ps1"})


class _StagingSandbox(WindowsSandbox):
    """``WindowsSandbox`` staged into a host directory instead of a guest."""

    async def stage_fleet(self, shared: Path) -> Path:
        """Run the real staging path for the monitors and the dispatcher.

        Args:
            shared: Host directory standing in for the guest's shared folder.

        Returns:
            Path: The monitor folder the production code staged into.
        """
        self.SANDBOX_SHARED_PATH = str(shared / _GUEST_DIR_NAME)
        self._shared_folder = shared
        monitor_folder = shared / _MONITOR_DIR_NAME
        self._monitor_folder = monitor_folder
        await asyncio.to_thread(monitor_folder.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread((shared / _LOGS_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_monitor_scripts()
        await self._create_dispatcher_scripts()
        return monitor_folder


@dataclass(frozen=True)
class _FleetStart:
    """What one run of the launcher over the staged fleet produced.

    Attributes:
        staged: File names of the scripts the launcher was given to start.
        running: File names the launcher left tracked in its PID file.
        stderr: Everything the launcher wrote to standard error.
    """

    staged: frozenset[str]
    running: frozenset[str]
    stderr: str


def _tracked(pid_file: Path) -> dict[int, str]:
    """Read the launcher's PID file.

    Args:
        pid_file: Path to ``monitors.pids``.

    Returns:
        dict[int, str]: Script file name by process id, empty when the
        launcher left no file.
    """
    if not pid_file.is_file():
        return {}
    tracked: dict[int, str] = {}
    for line in pid_file.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split(maxsplit=1)
        if fields and fields[0].isdigit():
            tracked[int(fields[0])] = fields[1].strip() if len(fields) > 1 else ""
    return tracked


def _kill(pids: list[int]) -> None:
    """End the launched scripts and anything they started.

    Args:
        pids: Process ids the launcher recorded.
    """
    taskkill = shutil.which("taskkill")
    if taskkill is None:
        return
    for pid in pids:
        try:
            run(
                [taskkill, "/PID", str(pid), "/F", "/T"],
                stdout=DEVNULL,
                stderr=DEVNULL,
                check=False,
                timeout=_KILL_TIMEOUT_S,
            )
        except (SubprocessError, OSError):
            continue


async def _start_staged_fleet(root: Path) -> _FleetStart:
    """Stage the fleet, run the launcher over it, and stop what it started.

    Args:
        root: Scratch directory for the staged folders and the launcher's output.

    Returns:
        _FleetStart: What the launcher decided about the fleet.

    Raises:
        AssertionError: If ``cmd.exe`` is unavailable.
    """
    cmd = shutil.which("cmd.exe") or shutil.which("cmd")
    if cmd is None:
        msg = "cmd.exe is required to run start_monitors.cmd"
        raise AssertionError(msg)

    shared = root / "shared"
    monitor_folder = await _StagingSandbox(SandboxConfig()).stage_fleet(shared)
    logs = shared / _LOGS_DIR_NAME
    staged = frozenset(script.name for script in monitor_folder.glob("*.ps1") if not script.name.startswith(_HELPER_PREFIX))

    stderr_path = root / "launcher.stderr.txt"
    try:
        with stderr_path.open("wb") as err_handle:
            await asyncio.to_thread(
                run,
                [cmd, "/c", str(monitor_folder / _LAUNCHER_NAME), str(logs)],
                stdout=DEVNULL,
                stderr=err_handle,
                stdin=DEVNULL,
                check=False,
                timeout=_LAUNCH_TIMEOUT_S,
            )
        tracked = _tracked(logs / _PID_FILE_NAME)
    finally:
        _kill(list(_tracked(logs / _PID_FILE_NAME)))

    return _FleetStart(
        staged=staged,
        running=frozenset(tracked.values()),
        stderr=stderr_path.read_text(encoding="utf-8", errors="replace"),
    )


@pytest.fixture(scope="module")
def fleet_start(tmp_path_factory: pytest.TempPathFactory) -> _FleetStart:
    """Start the staged fleet once and share the outcome with every gate.

    Args:
        tmp_path_factory: pytest-provided temporary directory factory.

    Returns:
        _FleetStart: Result of the single launcher run.
    """
    return asyncio.run(_start_staged_fleet(tmp_path_factory.mktemp("fleet_ready")))


def test_the_backend_stages_the_fleet_the_launcher_starts(fleet_start: _FleetStart) -> None:
    """The launcher must have been given the bundled monitors, the inline ones and the dispatcher.

    Args:
        fleet_start: Outcome of running the launcher over the staged fleet.
    """
    bundled = {script.name for script in WindowsSandbox.bundled_scripts_dir().glob("*.ps1") if not script.name.startswith(_HELPER_PREFIX)}

    assert bundled, "the backend bundles no monitor scripts to stage"
    assert bundled < fleet_start.staged, (
        f"the staged fleet {sorted(fleet_start.staged)} is not the bundled monitors plus the backend's own scripts"
    )
    assert _NOT_LAUNCHED not in fleet_start.stderr, f"the launcher could not start a staged script; stderr={fleet_start.stderr!r}"


def test_no_staged_script_is_left_running_without_reporting(fleet_start: _FleetStart) -> None:
    """Every staged script either reports that it started or exits.

    Falsifiable: a staged script that enters its collection loop without
    creating the file the launcher handed it is still running, unreported,
    when the launcher's wait limit runs out.

    Args:
        fleet_start: Outcome of running the launcher over the staged fleet.
    """
    unreported = [line for line in fleet_start.stderr.splitlines() if _UNREPORTED in line]

    assert not unreported, f"staged scripts kept running without telling the launcher they had started: {unreported}"


def test_every_script_that_can_start_anywhere_did_start(fleet_start: _FleetStart) -> None:
    """A script with nothing to fail on must be among the monitors the launcher kept.

    The three trace collectors are left out because whether they start is a
    property of the machine: they need the TraceEvent assembly and the right
    to open a trace session, and exit when they have neither. Every other
    staged script depends on nothing but PowerShell.

    Args:
        fleet_start: Outcome of running the launcher over the staged fleet.
    """
    expected = fleet_start.staged - _NEED_A_TRACE_SESSION

    assert expected <= fleet_start.running, (
        f"scripts that depend on nothing but PowerShell did not start: {sorted(expected - fleet_start.running)}; "
        f"stderr={fleet_start.stderr!r}"
    )
