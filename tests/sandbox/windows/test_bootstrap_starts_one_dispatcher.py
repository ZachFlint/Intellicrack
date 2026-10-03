# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate: the guest bootstrap leaves one dispatcher running, and a command runs once.

The dispatcher was staged in the monitor folder, and ``start_monitors.cmd``
starts every script in that folder. The bootstrap had already started the
dispatcher itself, so the guest ran two copies. Each copy keeps its own record
of the trigger files it has handled, so both took every command. Driven on a
real pair of copies, about half of a batch of short commands executed twice,
and for the rest the second copy truncated or locked the first one's output
file or appended a second exit code to its result file, which the host then
could not read as a number.

Nothing here stands in for the guest side. The dispatcher and the bootstrap are
the ones the backend stages, with the guest path pointed at a scratch directory
so that they run on this host; the launcher is the bundled one; the bootstrap is
run by ``cmd.exe`` the way the guest's logon command runs it; and the commands
go through the production ``run_command``.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import shutil
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import psutil
import pytest

from intellicrack.core.subprocess_compat import DEVNULL, run
from intellicrack.sandbox.base import SandboxError
from intellicrack.sandbox.windows import MONITOR_READY_ANNOUNCEMENT, WindowsSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the Windows Sandbox guest bootstrap, launcher and dispatcher are cmd.exe and PowerShell scripts",
)

_MONITOR_DIR_NAME: Final[str] = "monitor"
_LAUNCHER_NAME: Final[str] = "start_monitors.cmd"
_BOOTSTRAP_NAME: Final[str] = "sandbox_bootstrap.cmd"
_PID_FILE_NAME: Final[str] = "monitors.pids"
_SCRATCH_MONITOR_NAME: Final[str] = "scratch_monitor.ps1"
_SCRATCH_MONITOR_LIFETIME_S: Final[int] = 240
_SCRIPT_THE_BOOTSTRAP_STARTS: Final[re.Pattern[str]] = re.compile(r'-File "[^"]*\\([^"\\]+\.ps1)"')
_POWERSHELL_PROCESS: Final[str] = "powershell"
_BOOTSTRAP_TIMEOUT_S: Final[float] = 300.0
_READY_TIMEOUT_S: Final[float] = 90.0
_POLL_S: Final[float] = 0.25
_COMMAND_TIME_LIMIT_S: Final[int] = 60
_COMMANDS: Final[int] = 8


class _BootstrappedSandbox(WindowsSandbox):
    """A ``WindowsSandbox`` whose guest is a directory on this host.

    Only what a live sandbox would supply is arranged: where the share is,
    and that the sandbox is running. Staging, the dispatcher, the bootstrap
    and the command round trip are all production code.
    """

    async def stage(self, shared: Path) -> Path:
        """Stage the dispatcher and the bootstrap, with the guest path pointed at ``shared``.

        Args:
            shared: Host directory standing in for the guest's shared folder.

        Returns:
            Path: The monitor folder the bootstrap runs the launcher from.
        """
        self.SANDBOX_SHARED_PATH = str(shared)
        self._shared_folder = shared
        monitor_folder = shared / _MONITOR_DIR_NAME
        self._monitor_folder = monitor_folder
        await asyncio.to_thread(monitor_folder.mkdir, parents=True, exist_ok=True)
        await self._create_dispatcher_scripts()
        self.state.status = "running"
        return monitor_folder

    def ready_flag(self) -> Path:
        """Return the flag file the dispatcher writes when it comes up.

        Returns:
            Path: Host path of the readiness flag.
        """
        assert self._shared_folder is not None
        return self._shared_folder / "flags" / self.DISPATCHER_READY_MARKER


@dataclass(frozen=True)
class _CommandOutcome:
    """What one command sent through the dispatcher did.

    Attributes:
        marker: Text the command prints, unique to it.
        executions: How many times the command's body ran.
        exit_code: Exit code the host read back, or ``None`` if the round trip failed.
        output: Standard output the host read back, or the failure when there was none.
    """

    marker: str
    executions: int
    exit_code: int | None
    output: str


@dataclass(frozen=True)
class _Observation:
    """What running the bootstrap, then a batch of commands, produced.

    Attributes:
        started_by_bootstrap: File names of the scripts the bootstrap starts itself.
        dispatcher_processes: How many processes were running such a script once the bootstrap had returned.
        tracked_by_launcher: File names the launcher left in its PID file.
        commands: Outcome of each command, in the order they were sent.
    """

    started_by_bootstrap: frozenset[str]
    dispatcher_processes: int
    tracked_by_launcher: frozenset[str]
    commands: tuple[_CommandOutcome, ...]


def _command_lines_under(shared: Path) -> dict[int, str]:
    """Collect the command line of every PowerShell process working inside ``shared``.

    Args:
        shared: The scratch shared folder.

    Returns:
        dict[int, str]: Lower-cased command line by process id.
    """
    root = str(shared).lower()
    found: dict[int, str] = {}
    for process in psutil.process_iter():
        with contextlib.suppress(psutil.Error):
            if _POWERSHELL_PROCESS not in process.name().lower():
                continue
            command_line = " ".join(process.cmdline()).lower()
            if root in command_line:
                found[process.pid] = command_line
    return found


def _kill_everything_under(shared: Path) -> None:
    """End every process the bootstrap left working inside ``shared``.

    Args:
        shared: The scratch shared folder.
    """
    for pid in _command_lines_under(shared):
        with contextlib.suppress(psutil.Error):
            psutil.Process(pid).kill()


def _tracked_names(pid_file: Path) -> frozenset[str]:
    """Read the script names out of the launcher's PID file.

    Args:
        pid_file: Path to ``monitors.pids``.

    Returns:
        frozenset[str]: Script file names the launcher is tracking.
    """
    names: set[str] = set()
    for line in pid_file.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) > 1 and fields[0].isdigit():
            names.add(fields[1].strip())
    return frozenset(names)


async def _send(sandbox: _BootstrappedSandbox, work: Path, index: int) -> _CommandOutcome:
    """Send one command through the dispatcher and record what came back.

    The command appends a line to a file of its own every time its body runs,
    which is what makes a second execution visible afterwards.

    Args:
        sandbox: The sandbox whose dispatcher is running.
        work: Directory for the per-command execution records.
        index: Position of the command in the batch.

    Returns:
        _CommandOutcome: The round trip's result, with the execution count still to be filled in.
    """
    marker = f"dispatched-{index}"
    record = work / f"{marker}.txt"
    try:
        exit_code, output, _ = await sandbox.run_command(f'echo ran>>"{record}" & echo {marker}', time_limit=_COMMAND_TIME_LIMIT_S)
    except (OSError, SandboxError) as failure:
        return _CommandOutcome(marker=marker, executions=0, exit_code=None, output=repr(failure))
    return _CommandOutcome(marker=marker, executions=0, exit_code=exit_code, output=output)


def _run_bootstrap(bootstrap: Path, root: Path) -> None:
    """Run the staged bootstrap the way the guest's logon command does.

    Its output goes to files rather than pipes: the dispatcher it starts
    inherits them and outlives it, and a pipe would never reach end of file.

    Args:
        bootstrap: The staged ``sandbox_bootstrap.cmd``.
        root: Scratch directory for the bootstrap's captured output.

    Raises:
        AssertionError: If ``cmd.exe`` is unavailable.
    """
    cmd = shutil.which("cmd.exe") or shutil.which("cmd")
    if cmd is None:
        msg = "cmd.exe is required to run the guest bootstrap"
        raise AssertionError(msg)
    with (root / "bootstrap.out.txt").open("wb") as out_handle, (root / "bootstrap.err.txt").open("wb") as err_handle:
        run(
            [cmd, "/c", str(bootstrap)],
            stdout=out_handle,
            stderr=err_handle,
            stdin=DEVNULL,
            check=False,
            timeout=_BOOTSTRAP_TIMEOUT_S,
        )


def _dispatcher_signalled_ready(flag: Path) -> bool:
    """Wait for the dispatcher's ready flag.

    Args:
        flag: Host path of the readiness flag.

    Returns:
        bool: Whether the flag appeared before the timeout.
    """
    deadline = time.monotonic() + _READY_TIMEOUT_S
    while not flag.is_file() and time.monotonic() < deadline:
        time.sleep(_POLL_S)
    return flag.is_file()


def _with_execution_counts(sent: list[_CommandOutcome], work: Path) -> tuple[_CommandOutcome, ...]:
    """Fill in how many times each command's body ran.

    Args:
        sent: Round-trip results, in the order the commands were sent.
        work: Directory holding the per-command execution records.

    Returns:
        tuple[_CommandOutcome, ...]: The same outcomes with their execution counts.
    """
    counted: list[_CommandOutcome] = []
    for outcome in sent:
        record = work / f"{outcome.marker}.txt"
        executions = len(record.read_text(encoding="utf-8", errors="replace").split()) if record.is_file() else 0
        counted.append(_CommandOutcome(marker=outcome.marker, executions=executions, exit_code=outcome.exit_code, output=outcome.output))
    return tuple(counted)


async def _observe(root: Path) -> _Observation:
    """Stage the guest side, run the bootstrap, and drive a batch of commands.

    Args:
        root: Scratch directory for the shared folder and the execution records.

    Returns:
        _Observation: What the bootstrap left running and what each command did.

    Raises:
        AssertionError: If the dispatcher never came up.
    """
    shared = root / "shared"
    work = root / "work"
    await asyncio.to_thread(work.mkdir)
    sandbox = _BootstrappedSandbox()
    monitor_folder = await sandbox.stage(shared)
    await asyncio.to_thread(shutil.copy2, WindowsSandbox.bundled_scripts_dir() / _LAUNCHER_NAME, monitor_folder / _LAUNCHER_NAME)
    scratch_monitor = f"param([string]$LogDir = '.')\n{MONITOR_READY_ANNOUNCEMENT}Start-Sleep -Seconds {_SCRATCH_MONITOR_LIFETIME_S}\n"
    await asyncio.to_thread((monitor_folder / _SCRATCH_MONITOR_NAME).write_text, scratch_monitor, encoding="utf-8")
    bootstrap = monitor_folder / _BOOTSTRAP_NAME
    started_by_bootstrap = frozenset(_SCRIPT_THE_BOOTSTRAP_STARTS.findall(await asyncio.to_thread(bootstrap.read_text, encoding="utf-8")))

    try:
        await asyncio.to_thread(_run_bootstrap, bootstrap, root)
        dispatcher_processes = sum(
            1
            for command_line in _command_lines_under(shared).values()
            if any(name.lower() in command_line for name in started_by_bootstrap)
        )
        tracked = _tracked_names(shared / "logs" / _PID_FILE_NAME)
        if not await asyncio.to_thread(_dispatcher_signalled_ready, sandbox.ready_flag()):
            msg = "no dispatcher signalled ready after the bootstrap had run"
            raise AssertionError(msg)
        sent = [await _send(sandbox, work, index) for index in range(_COMMANDS)]
    finally:
        _kill_everything_under(shared)

    return _Observation(
        started_by_bootstrap=started_by_bootstrap,
        dispatcher_processes=dispatcher_processes,
        tracked_by_launcher=tracked,
        commands=_with_execution_counts(sent, work),
    )


@pytest.fixture(scope="module")
def observation(tmp_path_factory: pytest.TempPathFactory) -> _Observation:
    """Run the bootstrap and the command batch once and share the outcome with every gate.

    Args:
        tmp_path_factory: pytest-provided temporary directory factory.

    Returns:
        _Observation: Result of the single run.
    """
    return asyncio.run(_observe(tmp_path_factory.mktemp("one_dispatcher")))


def test_the_bootstrap_leaves_exactly_one_dispatcher_running(observation: _Observation) -> None:
    """Once the bootstrap has returned, one process is running the dispatcher.

    Falsifiable: with the dispatcher staged in the monitor folder there are two,
    the bootstrap's own and the one the launcher started.

    Args:
        observation: Outcome of the single bootstrap run.
    """
    assert observation.started_by_bootstrap, "the bootstrap starts no script, so there is no dispatcher to count"
    assert observation.dispatcher_processes == 1, (
        f"{observation.dispatcher_processes} processes were running {sorted(observation.started_by_bootstrap)} after the bootstrap returned"
    )


def test_the_launcher_does_not_track_the_dispatcher(observation: _Observation) -> None:
    """The launcher's PID file holds the monitor and nothing the bootstrap started.

    A dispatcher recorded there would also be ended by ``stop_monitors.cmd``,
    which is meant to stop collection, not the command channel.

    Args:
        observation: Outcome of the single bootstrap run.
    """
    assert observation.tracked_by_launcher == {_SCRATCH_MONITOR_NAME}, (
        f"the launcher tracked {sorted(observation.tracked_by_launcher)}; it was given one monitor"
    )


def test_every_command_runs_once_and_returns_its_own_result(observation: _Observation) -> None:
    """Each command's body runs exactly once and its exit code and output come back intact.

    Falsifiable: a second dispatcher takes the same trigger file, so the body
    runs twice, or the output file is truncated or locked under the reader, or
    the result file holds two exit codes and reads back as unknown.

    Args:
        observation: Outcome of the single bootstrap run.
    """
    wrong = [
        outcome
        for outcome in observation.commands
        if outcome.executions != 1 or outcome.exit_code != 0 or outcome.output.strip() != outcome.marker
    ]

    assert len(observation.commands) == _COMMANDS
    assert not wrong, f"commands that did not run exactly once and return their own result: {wrong}"
