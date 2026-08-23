# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""S18-D18: the guest's monitor launcher has to report the monitors it did not start.

Across six headless re-drives against the same real Windows guest the agent's launcher started a
different subset of the eight monitors every time - run 3 started none of them at all, run 5 came
back without the dll, service and resource collectors, run 6 without ``dll_monitor`` alone - and it
said nothing whatever about the ones it missed. Its loop was
``if (Test-Path $scriptPath) { Start-Process ... }``: a script that was not on the share was skipped
in silence, and a ``Start-Process`` that threw went nowhere. The report that came back showed an
empty DLL tab with nothing anywhere in it to separate that from a sample that loaded no libraries.

Three things have to hold for that to stop happening, and there is a group of gates here for each.
The launcher must *record* what it did with every monitor it was asked to start; the record must
leave the guest with the other diagnostics, because a log inside a discarded VM is no record at all;
and the host must fold the launcher's cause onto the outage it already reports, so a collector that
never started says why rather than only that it did not.

The launcher gates drive the real generated ``agent.ps1`` under a real ``powershell.exe``, but
against stand-in monitors of their own rather than the staged ones: the shipped collectors open ETW
sessions and run until they are stopped, which must never happen in a test run. What that costs in
fidelity it takes back by observing the children - each stand-in records that it ran, into the
``-LogDir`` the launcher passed it - so a ``launched`` line has to correspond to a process that
really started with the arguments production gives it, not merely to a line of text.

One launcher state is deliberately gated one layer down. ``launch_failed`` is written when
``Start-Process`` itself fails, and the only per-monitor input that loop has is the script path:
measured on a real Windows host, ``Test-Path`` accepts a directory under a monitor's name, and
``Start-Process`` then launches ``powershell.exe`` - which Windows resolves through its App Paths
registry entry even with an empty ``PATH`` - whatever that path points at. There is no honest way to
make one monitor's ``Start-Process`` throw from outside the script, so that state is driven through
the host parser instead, carrying the exact diagnostic a failing ``Start-Process`` produces.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.log_parsers import collect_collector_outages, parse_monitor_launch_failures
from intellicrack.sandbox.qemu import COLLECTOR_DIAGNOSTIC_LOG_NAMES, MONITOR_SCRIPT_NAMES, GuestOS, QEMUConfig, QEMUSandbox
from tests._helpers.process_cleanup import kill_pid_tree


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_LOGS_DIR_NAME: Final[str] = "logs"
_MONITOR_DIR_NAME: Final[str] = "monitor"
_AGENT_SCRIPT_NAME: Final[str] = "agent.ps1"
_GUEST_MONITOR_DIR_NAME: Final[str] = "guest_monitors"
_DRIVER_SCRIPT_NAME: Final[str] = "drive_launcher.ps1"
_LAUNCHER_LOG_NAME: Final[str] = "monitor_launcher.log"
_SCRIPT_SUFFIX: Final[str] = ".ps1"

_SECTION_START_PREFIX: Final[str] = "$launcherLog = Join-Path $logDir"
_SECTION_END_MARKER: Final[str] = "'launch_finished'"
_MONITOR_ARRAY_PREFIX: Final[str] = "$monitorScripts = @("
_ARRAY_CLOSE: Final[str] = ")"
_SCRIPT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"'(?P<name>[^']+\.ps1)'")
_LAUNCHER_LOG_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^\$launcherLog\s*=\s*Join-Path\s+\$logDir\s+'(?P<name>[^']+)'",
    re.MULTILINE,
)
_ERROR_ACTION_RE: Final[re.Pattern[str]] = re.compile(r"^\$ErrorActionPreference\s*=\s*'[A-Za-z]+'", re.MULTILINE)

_LAUNCHER_FIELD_COUNT: Final[int] = 5
_LAUNCHER_NAME_IDX: Final[int] = 2
_LAUNCHER_STATE_IDX: Final[int] = 3
_LAUNCHER_DETAIL_IDX: Final[int] = 4
_LAUNCHER_SOURCE_IDX: Final[int] = 1
_LAUNCHER_SELF_NAME: Final[str] = "monitor_launcher"
_STATE_MISSING: Final[str] = "missing"
_STATE_LAUNCHED: Final[str] = "launched"
_STATE_LAUNCH_FAILED: Final[str] = "launch_failed"
_STATE_LAUNCH_STARTED: Final[str] = "launch_started"
_STATE_LAUNCH_FINISHED: Final[str] = "launch_finished"

_DRIVER_TIMEOUT_S: Final[float] = 180.0
_CHILD_READY_TIMEOUT_S: Final[float] = 90.0
_CHILD_STOP_TIMEOUT_S: Final[float] = 45.0
_POLL_DELAY_S: Final[float] = 0.05
_STOP_FLAG_NAME: Final[str] = "stop.flag"
_STARTED_SUFFIX: Final[str] = ".started"
_STOPPED_SUFFIX: Final[str] = ".stopped"

# A monitor that runs until it is told to stop, which is how every shipped collector behaves, and
# which is what makes a launched child observable at all: a script that exited immediately could not
# be told apart from one that never ran. It records the -LogDir the launcher handed it, so the marker
# it leaves behind is evidence about the launcher's arguments and not only about its own existence.
_STAND_IN_MONITOR: Final[str] = (
    """param([string]$LogDir)
$name = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$stop = Join-Path $LogDir '@STOP@'
New-Item -ItemType File -Path (Join-Path $LogDir ($name + '@STARTED@')) -Force | Out-Null
for ($i = 0; $i -lt 2400; $i++) {
    if (Test-Path $stop) { break }
    Start-Sleep -Milliseconds 50
}
New-Item -ItemType File -Path (Join-Path $LogDir ($name + '@STOPPED@')) -Force | Out-Null
"""
    .replace("@STOP@", _STOP_FLAG_NAME)
    .replace("@STARTED@", _STARTED_SUFFIX)
    .replace("@STOPPED@", _STOPPED_SUFFIX)
)

_TS: Final[str] = "2026-08-15 10:00:00"
_LIFECYCLE_STARTED_DETAIL: Final[str] = "stop_event=IntellicrackMonitorStop"
_GUEST_MONITOR_PATH: Final[str] = r"E:\monitor\dll_monitor.ps1"
# The diagnostic a real Start-Process writes when it cannot resolve what it was asked to launch,
# measured on a Windows host rather than invented, because it is what the guest would record.
_START_PROCESS_DIAGNOSTIC: Final[str] = "This command cannot be run due to the error: The system cannot find the file specified."


@dataclass(frozen=True)
class _LauncherEvent:
    """One line the guest's monitor launcher recorded.

    Attributes:
        name: Monitor script the line speaks about, or the launcher itself.
        state: What the launcher did with that monitor.
        detail: The launcher's detail field - a path, a child PID or a diagnostic.
    """

    name: str
    state: str
    detail: str


@dataclass(frozen=True)
class _LauncherRun:
    """Everything one drive of the generated launcher produced.

    Attributes:
        events: Every line the launcher wrote, in the order it wrote them.
        started: Stems of the stand-in monitors that really ran as child processes.
        returncode: Exit status of the PowerShell process that ran the launcher.
        output: Combined stdout and stderr, carried for assertion messages.
    """

    events: tuple[_LauncherEvent, ...]
    started: frozenset[str]
    returncode: int
    output: str


class _AgentScriptSandbox(QEMUSandbox):
    """``QEMUSandbox`` given only the shared folder the generator needs.

    Nothing about the script under test is arranged here: the agent body, the monitor list and the
    launcher section all come from the production generator.
    """

    def generate_agent_script(self, workspace: Path) -> str:
        """Write the guest agent bundle into ``workspace`` and read the agent back.

        Args:
            workspace: Directory standing in for the sandbox working directory.

        Returns:
            str: Full text of the ``agent.ps1`` the production generator wrote.
        """
        shared_folder = workspace / "shared"
        (shared_folder / _MONITOR_DIR_NAME).mkdir(parents=True, exist_ok=True)
        self._shared_folder = shared_folder
        asyncio.run(self._create_guest_agent_script())
        return (shared_folder / _MONITOR_DIR_NAME / _AGENT_SCRIPT_NAME).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def agent_script(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Generate the Windows guest agent script through the production generator.

    Args:
        tmp_path_factory: pytest-provided temporary directory factory.

    Returns:
        str: Full text of the generated ``agent.ps1``.
    """
    workspace = tmp_path_factory.mktemp("agent_bundle")
    image = workspace / "guest.qcow2"
    image.write_bytes(b"QFI\xfb")
    sandbox = _AgentScriptSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image, display="none"),
    )
    return sandbox.generate_agent_script(workspace)


def _extract_launcher_section(agent_script_text: str) -> str:
    """Cut the launcher out of the generated agent, from its log path to its last line.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.

    Returns:
        str: The launcher section exactly as production wrote it, never retyped.
    """
    lines = agent_script_text.splitlines()
    start = next((index for index, line in enumerate(lines) if line.startswith(_SECTION_START_PREFIX)), None)
    assert start is not None, (
        f"the generated agent declares no {_SECTION_START_PREFIX!r}, so it records nothing about the monitors it starts "
        f"and every launcher gate below would be driving an empty script"
    )
    end = next((index for index in range(start, len(lines)) if _SECTION_END_MARKER in lines[index]), None)
    assert end is not None, (
        "the generated agent's launcher never records reaching the end of its loop, so a launcher that died halfway looks clean"
    )
    section = "\n".join(lines[start : end + 1])
    assert "$monitorScripts" in section, (
        f"the extracted launcher section drives no monitor list, so it cannot report on any monitor: {section!r}"
    )
    assert "Start-Process" in section, f"the extracted launcher section starts nothing, so it is not the launcher: {section!r}"
    return section


def _extract_monitor_array(agent_script_text: str) -> str:
    """Cut the ``$monitorScripts`` array literal out of the generated agent.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.

    Returns:
        str: The array literal exactly as production wrote it.
    """
    lines = agent_script_text.splitlines()
    start = next((index for index, line in enumerate(lines) if line.startswith(_MONITOR_ARRAY_PREFIX)), None)
    assert start is not None, f"the generated agent declares no {_MONITOR_ARRAY_PREFIX!r}, so it asks its launcher to start nothing"
    end = next((index for index in range(start, len(lines)) if lines[index].strip() == _ARRAY_CLOSE), None)
    assert end is not None, "the generated agent's monitor list is never closed"
    return "\n".join(lines[start : end + 1])


def _monitor_names(agent_script_text: str) -> tuple[str, ...]:
    """Read the monitor script names the generated launcher is asked to start.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.

    Returns:
        tuple[str, ...]: The script names, in the order the launcher walks them.
    """
    names = tuple(match["name"] for match in _SCRIPT_NAME_RE.finditer(_extract_monitor_array(agent_script_text)))
    assert names, "the generated agent's monitor list holds no script names"
    return names


def _launcher_log_name(agent_script_text: str) -> str:
    """Read the file name the generated launcher writes its account into.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.

    Returns:
        str: The log file name, relative to the guest's log directory.
    """
    match = _LAUNCHER_LOG_NAME_RE.search(agent_script_text)
    assert match is not None, "the generated agent names no launcher log, so nothing it records could ever be collected"
    return match["name"]


def _error_action_preference(agent_script_text: str) -> str:
    """Read the error preference the generated agent runs its launcher under.

    The preference decides whether a failing cmdlet inside the loop throws into the launcher's
    ``catch`` or merely returns nothing, so a driver that guessed it would not be running the
    launcher the guest runs.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.

    Returns:
        str: The assignment line, exactly as production wrote it.
    """
    match = _ERROR_ACTION_RE.search(agent_script_text)
    assert match is not None, "the generated agent sets no $ErrorActionPreference, so the launcher's failure handling cannot be reproduced"
    return match.group(0)


def _ps_literal(value: Path) -> str:
    """Quote a path as a PowerShell single-quoted string literal.

    Args:
        value: Path to quote.

    Returns:
        str: The quoted literal, with any embedded quote doubled.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _build_driver(agent_script_text: str, logs_dir: Path, monitor_dir: Path) -> str:
    """Assemble a script that runs the production launcher against a chosen directory.

    Everything but the three leading assignments is lifted verbatim out of the generated agent.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.
        logs_dir: Directory the launcher writes its account into.
        monitor_dir: Directory the launcher looks for monitor scripts in.

    Returns:
        str: PowerShell source for the driver script.
    """
    return "\n".join((
        _error_action_preference(agent_script_text),
        f"$logDir = {_ps_literal(logs_dir)}",
        f"$monitorDir = {_ps_literal(monitor_dir)}",
        _extract_monitor_array(agent_script_text),
        _extract_launcher_section(agent_script_text),
        "",
    ))


def _powershell() -> str:
    """Locate the PowerShell host the guest's launcher is started by.

    Returns:
        str: Absolute path to ``powershell.exe``.
    """
    executable = shutil.which("powershell")
    assert executable is not None, (
        "powershell.exe is not on PATH, so the guest agent's launcher cannot be driven the way the guest drives it"
    )
    return executable


def _read_launcher_events(log_path: Path) -> tuple[_LauncherEvent, ...]:
    """Read the launcher's account, requiring the shape the host parser reads.

    Args:
        log_path: Path the launcher wrote its account to.

    Returns:
        tuple[_LauncherEvent, ...]: One record per line, in the order recorded.
    """
    assert log_path.is_file(), f"the launcher wrote no account of what it started, which is the whole of the reported defect: {log_path}"
    events: list[_LauncherEvent] = []
    for raw_line in log_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("|", _LAUNCHER_FIELD_COUNT - 1)
        assert len(parts) == _LAUNCHER_FIELD_COUNT, f"the launcher wrote a line the host parser drops on the floor: {line!r}"
        assert parts[_LAUNCHER_SOURCE_IDX] == _LAUNCHER_SELF_NAME, (
            f"the launcher's line does not identify itself as the launcher, so the host cannot tell it "
            f"apart from a collector's own lifecycle line: {line!r}"
        )
        events.append(
            _LauncherEvent(
                name=parts[_LAUNCHER_NAME_IDX],
                state=parts[_LAUNCHER_STATE_IDX],
                detail=parts[_LAUNCHER_DETAIL_IDX],
            ),
        )
    return tuple(events)


def _recorded_pids(logs_dir: Path) -> dict[str, int]:
    """Map each monitor the launcher reported starting to the child PID it recorded.

    Read leniently, because this is used during cleanup and must work even when the run under test
    produced something the strict reader would reject.

    Args:
        logs_dir: Directory the launcher wrote its account into.

    Returns:
        dict[str, int]: Monitor stem mapped to the recorded child PID.
    """
    log_path = logs_dir / _LAUNCHER_LOG_NAME
    if not log_path.is_file():
        return {}
    pids: dict[str, int] = {}
    for raw_line in log_path.read_text(encoding="utf-8-sig").splitlines():
        parts = raw_line.strip().split("|", _LAUNCHER_FIELD_COUNT - 1)
        if len(parts) < _LAUNCHER_FIELD_COUNT:
            continue
        if parts[_LAUNCHER_STATE_IDX] != _STATE_LAUNCHED or not parts[_LAUNCHER_DETAIL_IDX].isdigit():
            continue
        pids[parts[_LAUNCHER_NAME_IDX].removesuffix(_SCRIPT_SUFFIX)] = int(parts[_LAUNCHER_DETAIL_IDX])
    return pids


def _wait_for_markers(logs_dir: Path, stems: Sequence[str], suffix: str, timeout: float) -> frozenset[str]:
    """Wait until every named stand-in has left a marker, or the deadline passes.

    Args:
        logs_dir: Directory the stand-ins write their markers into.
        stems: Monitor stems whose markers are awaited.
        suffix: Marker file suffix to look for.
        timeout: Seconds to wait before returning whatever has appeared.

    Returns:
        frozenset[str]: The stems whose markers exist when this returns.
    """
    wanted = set(stems)
    deadline = time.monotonic() + timeout
    while True:
        found = {stem for stem in wanted if (logs_dir / f"{stem}{suffix}").is_file()}
        if found == wanted or time.monotonic() >= deadline:
            return frozenset(found)
        time.sleep(_POLL_DELAY_S)


def _stop_children(logs_dir: Path, stems: Sequence[str]) -> None:
    """Stop every stand-in this run started and reap anything that ignored the request.

    Args:
        logs_dir: Directory the stand-ins watch for the stop flag.
        stems: Monitor stems that were staged for this run.
    """
    (logs_dir / _STOP_FLAG_NAME).write_text("", encoding="utf-8")
    stopped = _wait_for_markers(logs_dir, stems, _STOPPED_SUFFIX, _CHILD_STOP_TIMEOUT_S)
    pids = _recorded_pids(logs_dir)
    for stem in stems:
        if stem in stopped:
            continue
        pid = pids.get(stem)
        if pid is not None:
            kill_pid_tree(pid)


def _drive_launcher(agent_script_text: str, workspace: Path, present: Sequence[str]) -> _LauncherRun:
    """Run the production launcher over a monitor directory holding only ``present``.

    Args:
        agent_script_text: Full text of the generated ``agent.ps1``.
        workspace: Directory the run's logs, monitors and driver are created under.
        present: Monitor script names staged for the launcher to find.

    Returns:
        _LauncherRun: What the launcher recorded and what its children did.
    """
    logs_dir = workspace / _LOGS_DIR_NAME
    logs_dir.mkdir(parents=True, exist_ok=True)
    monitor_dir = workspace / _GUEST_MONITOR_DIR_NAME
    monitor_dir.mkdir(parents=True, exist_ok=True)
    for name in present:
        (monitor_dir / name).write_text(_STAND_IN_MONITOR, encoding="utf-8")

    driver = workspace / _DRIVER_SCRIPT_NAME
    driver.write_text(_build_driver(agent_script_text, logs_dir, monitor_dir), encoding="utf-8")
    stems = tuple(name.removesuffix(_SCRIPT_SUFFIX) for name in present)

    try:
        completed = subprocess.run(
            [_powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=_DRIVER_TIMEOUT_S,
        )
        started = _wait_for_markers(logs_dir, stems, _STARTED_SUFFIX, _CHILD_READY_TIMEOUT_S)
        return _LauncherRun(
            events=_read_launcher_events(logs_dir / _LAUNCHER_LOG_NAME),
            started=started,
            returncode=completed.returncode,
            output=f"{completed.stdout}\n{completed.stderr}",
        )
    finally:
        _stop_children(logs_dir, stems)


def _monitor_events(run: _LauncherRun) -> dict[str, _LauncherEvent]:
    """Index the run's per-monitor lines by monitor script name.

    Args:
        run: The completed launcher run.

    Returns:
        dict[str, _LauncherEvent]: Monitor script name mapped to its single line.
    """
    events = [event for event in run.events if event.name != _LAUNCHER_SELF_NAME]
    indexed = {event.name: event for event in events}
    assert len(indexed) == len(events), (
        f"the launcher reported some monitor more than once, so its account is not one line per monitor: {run.events!r}"
    )
    return indexed


def _bracket(run: _LauncherRun) -> tuple[tuple[str, str], ...]:
    """Return the launcher's own lines, which bracket the loop.

    Args:
        run: The completed launcher run.

    Returns:
        tuple[tuple[str, str], ...]: ``(state, detail)`` pairs, in order.
    """
    return tuple((event.state, event.detail) for event in run.events if event.name == _LAUNCHER_SELF_NAME)


def _write_launcher_log(logs_dir: Path, records: Sequence[tuple[str, str, str]]) -> None:
    """Write a launcher account in the encoding and shape the guest produces.

    Windows PowerShell's ``Out-File -Encoding utf8`` writes a byte-order mark and CRLF endings, both
    of which the host parser has to survive.

    Args:
        logs_dir: Directory the host collected the guest's logs into.
        records: ``(name, state, detail)`` triples, in the order recorded.
    """
    logs_dir.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{_TS}|{_LAUNCHER_SELF_NAME}|{name}|{state}|{detail}\r\n" for name, state, detail in records)
    (logs_dir / _LAUNCHER_LOG_NAME).write_text(body, encoding="utf-8-sig")


def _write_lifecycle(logs_dir: Path, collector: str, states: Sequence[tuple[str, str]]) -> None:
    """Write a collector's own lifecycle log exactly as its script writes it.

    Args:
        logs_dir: Directory the host collected the guest's logs into.
        collector: Collector name written into the second field.
        states: ``(state, detail)`` pairs to record, in order.
    """
    logs_dir.mkdir(parents=True, exist_ok=True)
    body = "".join(f"{_TS}|{collector}|{state}|{detail}\r\n" for state, detail in states)
    (logs_dir / f"{collector}.lifecycle.log").write_text(body, encoding="utf-8-sig")


async def _outages_by_collector(shared_folder: Path) -> dict[str, str]:
    """Collect the reported outages and index their reasons by collector.

    Args:
        shared_folder: Sandbox shared folder root holding a ``logs`` directory.

    Returns:
        dict[str, str]: Collector name mapped to the reason reported for it.
    """
    return {outage["collector"]: outage["reason"] for outage in await collect_collector_outages(shared_folder)}


class TestTheLauncherUnderTestIsTheProductionOne:
    """The launcher gates are worthless if the section they drive was not found."""

    def test_the_generated_agent_still_carries_a_reporting_launcher(self, agent_script: str) -> None:
        """The section boundaries, the monitor list and the report call all have to be present.

        Args:
            agent_script: Text of the agent script the production generator wrote.
        """
        section = _extract_launcher_section(agent_script)
        assert _STATE_MISSING in section, f"the launcher has no way to say a monitor was not on the share: {section!r}"
        assert _STATE_LAUNCHED in section, f"the launcher has no way to say a monitor was started: {section!r}"
        assert _STATE_LAUNCH_FAILED in section, f"the launcher has no way to say starting a monitor failed: {section!r}"

    def test_the_launcher_walks_exactly_the_monitor_set_the_agent_stages(self, agent_script: str) -> None:
        """A launcher walking a different list would report on monitors nobody staged.

        Args:
            agent_script: Text of the agent script the production generator wrote.
        """
        assert _monitor_names(agent_script) == MONITOR_SCRIPT_NAMES, (
            f"the generated launcher walks {_monitor_names(agent_script)!r} while the agent stages "
            f"{MONITOR_SCRIPT_NAMES!r}, so it would report a staged monitor missing or say nothing about one"
        )


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="the guest launcher is Windows PowerShell and is driven here by a real powershell.exe")
class TestTheGeneratedLauncherReportsWhatItStarted:
    """Run the real launcher and require an account of every monitor it was asked to start."""

    def test_a_monitor_missing_from_the_share_is_reported_by_name(self, agent_script: str, tmp_path: Path) -> None:
        """Live run 6 started every monitor but ``dll_monitor`` and reported nothing about it.

        Args:
            agent_script: Text of the agent script the production generator wrote.
            tmp_path: pytest-provided temporary directory fixture.
        """
        names = _monitor_names(agent_script)
        omitted = names[-2]
        present = tuple(name for name in names if name != omitted)
        run = _drive_launcher(agent_script, tmp_path, present)

        assert run.returncode == 0, f"the launcher section itself failed to run: {run.output}"
        events = _monitor_events(run)
        assert set(events) == set(names), (
            f"the launcher accounted for {sorted(events)} out of {sorted(names)}, so the monitors it "
            f"skipped leave an empty report tab and no explanation: {run.output}"
        )
        assert events[omitted].state == _STATE_MISSING, f"a monitor that was not on the share was not reported missing: {events[omitted]!r}"
        assert events[omitted].detail == str(tmp_path / _GUEST_MONITOR_DIR_NAME / omitted), (
            f"the launcher reported a missing monitor without saying where it looked for it: {events[omitted]!r}"
        )
        for name in present:
            assert events[name].state == _STATE_LAUNCHED, f"a monitor that was on the share was not reported as launched: {events[name]!r}"
            assert events[name].detail.isdigit(), (
                f"the launcher reported starting {name} without a child PID, so nothing can be traced back to the process: {events[name]!r}"
            )
            assert int(events[name].detail) > 0, f"the launcher reported starting {name} as PID {events[name].detail}: {events[name]!r}"
        assert run.started == {name.removesuffix(_SCRIPT_SUFFIX) for name in present}, (
            f"the launcher recorded monitors as launched that never ran with the -LogDir it was given; "
            f"ran={sorted(run.started)}: {run.output}"
        )
        assert _bracket(run) == ((_STATE_LAUNCH_STARTED, str(len(names))), (_STATE_LAUNCH_FINISHED, str(len(names)))), (
            f"the launcher did not bracket its loop with the count it was asked to start, so a launcher "
            f"that died halfway through cannot be told from one that finished: {run.events!r}"
        )

    def test_monitors_it_cannot_start_do_not_cost_the_rest_of_the_fleet(self, agent_script: str, tmp_path: Path) -> None:
        """A partial fleet was the live symptom, so a skipped monitor must not end the loop.

        The first and last entries are the ones withheld: a launcher that stopped at the first
        monitor it could not start would leave every later one unreported and unstarted, which is
        exactly the "different subset every run" shape the report showed.

        Args:
            agent_script: Text of the agent script the production generator wrote.
            tmp_path: pytest-provided temporary directory fixture.
        """
        names = _monitor_names(agent_script)
        withheld = (names[0], names[-1])
        present = tuple(name for name in names if name not in withheld)
        run = _drive_launcher(agent_script, tmp_path, present)

        assert run.returncode == 0, f"the launcher section itself failed to run: {run.output}"
        events = _monitor_events(run)
        assert set(events) == set(names), f"the launcher stopped accounting for monitors partway through its list: {run.events!r}"
        for name in withheld:
            assert events[name].state == _STATE_MISSING, f"a withheld monitor was not reported missing: {events[name]!r}"
        for name in present:
            assert events[name].state == _STATE_LAUNCHED, (
                f"{name} follows a monitor the launcher could not start and was not launched itself: {events[name]!r}"
            )
        assert run.started == {name.removesuffix(_SCRIPT_SUFFIX) for name in present}, (
            f"a monitor the launcher could not start cost the others their processes; ran={sorted(run.started)}: {run.output}"
        )
        assert _bracket(run)[-1] == (_STATE_LAUNCH_FINISHED, str(len(names))), (
            f"the launcher never reached the end of its loop: {run.events!r}"
        )

    def test_a_share_with_no_monitors_at_all_is_fully_accounted_for(self, agent_script: str, tmp_path: Path) -> None:
        """Live run 3 started none of the eight monitors and the report said nothing at all.

        Args:
            agent_script: Text of the agent script the production generator wrote.
            tmp_path: pytest-provided temporary directory fixture.
        """
        names = _monitor_names(agent_script)
        run = _drive_launcher(agent_script, tmp_path, ())

        assert run.returncode == 0, f"the launcher section itself failed to run: {run.output}"
        events = _monitor_events(run)
        assert set(events) == set(names), (
            f"a run that started no monitors at all accounted for only {sorted(events)}, so the whole "
            f"empty report reads as a sample that did nothing: {run.output}"
        )
        for name in names:
            assert events[name].state == _STATE_MISSING, f"{name} was neither started nor reported missing: {events[name]!r}"
            assert events[name].detail == str(tmp_path / _GUEST_MONITOR_DIR_NAME / name), (
                f"the launcher did not record where it looked for {name}: {events[name]!r}"
            )
        assert run.started == frozenset(), "a run staged with no monitor scripts started a process anyway"
        assert _bracket(run) == ((_STATE_LAUNCH_STARTED, str(len(names))), (_STATE_LAUNCH_FINISHED, str(len(names)))), (
            f"the launcher did not bracket a completely failed fleet with its own start and finish lines: {run.events!r}"
        )


@pytest.mark.asyncio
class TestTheLauncherCauseReachesTheOutage:
    """A collector that never started has to say why, not only that it did not."""

    async def test_a_monitor_the_launcher_never_found_carries_that_cause(self, tmp_path: Path) -> None:
        """The measured failure: an empty DLL tab with no way to tell why it was empty.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", _LIFECYCLE_STARTED_DETAIL),))
        _write_launcher_log(
            logs_dir,
            (
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_STARTED, "8"),
                ("dll_monitor.ps1", _STATE_MISSING, _GUEST_MONITOR_PATH),
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_FINISHED, "8"),
            ),
        )

        reasons = await _outages_by_collector(tmp_path)
        assert set(reasons) == {"dll_monitor", "kernel_object_monitor"}, (
            f"the collectors reported as out do not match the logs on disk: {reasons!r}"
        )

        plain = reasons["kernel_object_monitor"]
        decorated = reasons["dll_monitor"]
        assert decorated.startswith(plain), (
            f"the launcher's cause replaced the outage the host already reported instead of being added to it: {decorated!r}"
        )
        assert decorated != plain, (
            "the report still cannot say why dll_monitor never started, which is what made the empty DLL tab unreadable"
        )
        assert _GUEST_MONITOR_PATH in decorated, (
            f"the outage dropped the path the launcher looked in, so nobody can tell what was not staged: {decorated!r}"
        )
        assert "launcher" in decorated.lower(), f"the outage does not attribute the cause to the guest's launcher: {decorated!r}"

    async def test_a_monitor_the_launcher_could_not_start_reports_the_diagnostic(self, tmp_path: Path) -> None:
        """A ``Start-Process`` that failed used to go nowhere; its message must reach the report.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", _LIFECYCLE_STARTED_DETAIL),))
        _write_launcher_log(
            logs_dir,
            (
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_STARTED, "8"),
                ("dll_monitor.ps1", _STATE_LAUNCH_FAILED, _START_PROCESS_DIAGNOSTIC),
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_FINISHED, "8"),
            ),
        )

        reasons = await _outages_by_collector(tmp_path)
        plain = reasons["kernel_object_monitor"]
        decorated = reasons["dll_monitor"]
        assert decorated.startswith(plain), f"the launch failure replaced the outage instead of explaining it: {decorated!r}"
        assert _START_PROCESS_DIAGNOSTIC in decorated, (
            f"the outage dropped the diagnostic the guest recorded for the failed launch: {decorated!r}"
        )
        assert "launcher" in decorated.lower(), f"the outage does not attribute the failure to the guest's launcher: {decorated!r}"

    async def test_a_monitor_the_launcher_started_is_not_blamed_on_the_launcher(self, tmp_path: Path) -> None:
        """A collector that was started and then died must not read as one that never launched.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", _LIFECYCLE_STARTED_DETAIL),))
        _write_launcher_log(
            logs_dir,
            (
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_STARTED, "8"),
                ("dll_monitor.ps1", _STATE_LAUNCHED, "4242"),
                (_LAUNCHER_SELF_NAME, _STATE_LAUNCH_FINISHED, "8"),
            ),
        )

        reasons = await _outages_by_collector(tmp_path)
        assert reasons["dll_monitor"] == reasons["kernel_object_monitor"], (
            f"a collector the launcher really started was decorated with a launch failure anyway: {reasons['dll_monitor']!r}"
        )
        assert "launcher" not in reasons["dll_monitor"].lower(), (
            f"a started collector's outage blames the launcher: {reasons['dll_monitor']!r}"
        )

    async def test_a_guest_that_wrote_no_launcher_log_still_reports_its_outages(self, tmp_path: Path) -> None:
        """The pre-fix guest wrote no launcher log at all, and must not break the host.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        for collector in ("api_trace", "injection_monitor"):
            _write_lifecycle(logs_dir, collector, (("started", _LIFECYCLE_STARTED_DETAIL),))

        reasons = await _outages_by_collector(tmp_path)
        assert set(reasons) == {"dll_monitor", "kernel_object_monitor"}, (
            f"a guest without a launcher log lost its outages entirely: {reasons!r}"
        )
        assert reasons["dll_monitor"] == reasons["kernel_object_monitor"], (
            f"an outage was decorated from a launcher log that does not exist: {reasons!r}"
        )
        assert await parse_monitor_launch_failures(tmp_path) == {}, "launch failures were reported for a guest that recorded none"

    async def test_a_launcher_that_started_everything_reports_no_failures(self, tmp_path: Path) -> None:
        """Every monitor launched means no collector may be attributed to the launcher.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        records = [(_LAUNCHER_SELF_NAME, _STATE_LAUNCH_STARTED, str(len(MONITOR_SCRIPT_NAMES)))]
        records.extend((name, _STATE_LAUNCHED, str(4000 + index)) for index, name in enumerate(MONITOR_SCRIPT_NAMES))
        records.append((_LAUNCHER_SELF_NAME, _STATE_LAUNCH_FINISHED, str(len(MONITOR_SCRIPT_NAMES))))
        _write_launcher_log(logs_dir, records)

        assert await parse_monitor_launch_failures(tmp_path) == {}, (
            "a launcher that started every monitor was read as having failed to start some"
        )

    async def test_a_truncated_launcher_line_neither_raises_nor_invents_a_cause(self, tmp_path: Path) -> None:
        """A guest killed mid-write leaves a partial line, which must not cost the whole log.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)
        body = "\r\n".join((
            "this line is not a launcher record at all",
            f"{_TS}|{_LAUNCHER_SELF_NAME}|dll_monitor.ps1",
            f"{_TS}|{_LAUNCHER_SELF_NAME}|dll_monitor.ps1|{_STATE_MISSING}",
            "",
            f"{_TS}|{_LAUNCHER_SELF_NAME}|kernel_object_monitor.ps1|{_STATE_MISSING}|{_GUEST_MONITOR_PATH}",
            "\x00\x01\x02 partial write",
        ))
        (logs_dir / _LAUNCHER_LOG_NAME).write_text(body, encoding="utf-8-sig")

        failures = await parse_monitor_launch_failures(tmp_path)
        assert set(failures) == {"kernel_object_monitor"}, (
            f"a truncated line either cost the whole launcher log or invented a cause from an incomplete record: {failures!r}"
        )
        assert _GUEST_MONITOR_PATH in failures["kernel_object_monitor"], f"the surviving record lost its detail: {failures!r}"


class TestTheLauncherLogLeavesTheGuest:
    """An account of the fleet that stays inside a discarded VM is no account at all."""

    def test_the_log_the_agent_writes_is_one_the_host_collects(self, agent_script: str) -> None:
        """The name the guest writes has to be in the set the host pulls off the share.

        Args:
            agent_script: Text of the agent script the production generator wrote.
        """
        name = _launcher_log_name(agent_script)
        assert name == _LAUNCHER_LOG_NAME, (
            f"the generated agent writes its launcher account to {name!r}, which is not the name this gate tracks"
        )
        assert name in COLLECTOR_DIAGNOSTIC_LOG_NAMES, (
            f"the guest writes {name!r} and the host never fetches it, so the launcher's account of the "
            f"fleet is destroyed with the VM: {COLLECTOR_DIAGNOSTIC_LOG_NAMES!r}"
        )

    @pytest.mark.asyncio
    async def test_the_collected_log_is_the_file_the_host_parser_reads(self, agent_script: str, tmp_path: Path) -> None:
        """Collecting one name and parsing another would surface nothing at all.

        Args:
            agent_script: Text of the agent script the production generator wrote.
            tmp_path: pytest-provided temporary directory fixture.
        """
        logs_dir = tmp_path / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / _launcher_log_name(agent_script)).write_text(
            f"{_TS}|{_LAUNCHER_SELF_NAME}|dll_monitor.ps1|{_STATE_MISSING}|{_GUEST_MONITOR_PATH}\r\n",
            encoding="utf-8-sig",
        )

        failures = await parse_monitor_launch_failures(tmp_path)
        assert set(failures) == {"dll_monitor"}, f"the host parser does not read the file the guest's launcher writes: {failures!r}"
        assert _GUEST_MONITOR_PATH in failures["dll_monitor"], f"the parsed cause lost the launcher's detail: {failures!r}"
