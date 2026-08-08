# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D50(b): a recorder that dies must be reported as an outage.

Measured live: because ``api_trace.ps1`` exits 0.6 seconds after starting,
the report's API Calls tab held exactly one row and that row *was* the
recorder's own failure text - an analyst reading it could not tell "the
sample made no API calls" from "we never watched". ``injection_monitor.ps1``
never even wrote a ``started`` line to its lifecycle log before dying, and
its data log held a single fabricated ``ERROR`` record instead.

These gates never restate what the fix should compute. The unit-level tests
drive :func:`intellicrack.sandbox.log_parsers.parse_collector_lifecycle`
directly against the exact ``timestamp|collector|state|detail`` lines
``Write-TraceLifecycle`` (``api_trace.ps1``) and ``Write-InjectionLifecycle``
(``injection_monitor.ps1``) emit. The end-to-end test reproduces the live
failure for real: it stages the genuine bundled scripts into a guest monitor
directory *without* the vendored ETW assemblies - the exact provisioning gap
S17-D50(a) fixes - launches both under a real ``powershell.exe``, and reads
the resulting shared folder back through the real
:meth:`QEMUSandbox._collect_monitoring_logs`, the same path
:meth:`QEMUSandbox.run_binary` builds an :class:`ExecutionReport` from. If a
collector's failure is not surfaced as a distinct outage there, this test
observes only the single fabricated data row the live run did.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.log_parsers import parse_collector_lifecycle
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.sandbox.base import CollectorOutage


_TS: Final[str] = "2026-08-07T10:00:00.0000000Z"
_LOG_NAME: Final[str] = "api_trace.lifecycle.log"
_COLLECTOR: Final[str] = "api_trace"

_MONITOR_DIR_NAME: Final[str] = "monitor"
_LOGS_DIR_NAME: Final[str] = "logs"
_API_TRACE_SCRIPT_NAME: Final[str] = "api_trace.ps1"
_INJECTION_MONITOR_SCRIPT_NAME: Final[str] = "injection_monitor.ps1"

_POLL_S: Final[float] = 0.5
_PROCESS_EXIT_WAIT_S: Final[float] = 30.0
_PROCESS_KILL_GRACE_S: Final[float] = 5.0


def _write_log(tmp_path: Path, name: str, content: str) -> None:
    """Write a log file under ``tmp_path/logs/<name>``.

    Args:
        tmp_path: Root directory standing in for the shared folder.
        name: Log file name.
        content: Full file content to write.
    """
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / name).write_text(content, encoding="utf-8")


class TestParseCollectorLifecycleNeverStarted:
    """A collector that never reported starting must be an outage."""

    @pytest.mark.asyncio
    async def test_missing_lifecycle_log_is_an_outage(self, tmp_path: Path) -> None:
        """No lifecycle log at all - the live ``injection_monitor.ps1`` failure mode.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is not None, "a collector with no lifecycle log at all must be reported as an outage"
        assert outage["collector"] == _COLLECTOR
        assert outage["exit_code"] is None
        assert "never reported starting" in outage["reason"]

    @pytest.mark.asyncio
    async def test_empty_lifecycle_log_is_an_outage(self, tmp_path: Path) -> None:
        """An empty lifecycle log file is equivalent to no log at all.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        _write_log(tmp_path, _LOG_NAME, "")
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is not None
        assert "never reported starting" in outage["reason"]

    @pytest.mark.asyncio
    async def test_none_shared_folder_is_an_outage(self) -> None:
        """A ``None`` shared folder (sandbox not yet initialised) is also never-started."""
        outage = await parse_collector_lifecycle(None, _COLLECTOR, _LOG_NAME)
        assert outage is not None
        assert "never reported starting" in outage["reason"]


class TestParseCollectorLifecycleStoppedEarly:
    """A collector that reported stopping mid-run must be an outage carrying its detail."""

    @pytest.mark.asyncio
    async def test_stopped_with_exit_code_carries_the_parsed_exit_code(self, tmp_path: Path) -> None:
        """The measured live line: ``stopped|exit_code=2 stop_requested=False``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        content = f"{_TS}|{_COLLECTOR}|started|pid_filter=0 duration=0 stop_event=IntellicrackMonitorStop\n{_TS}|{_COLLECTOR}|stopped|exit_code=2 stop_requested=False\n"
        _write_log(tmp_path, _LOG_NAME, content)
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is not None, "a collector that reported stopping mid-run must be an outage, not treated as healthy"
        assert outage["collector"] == _COLLECTOR
        assert outage["exit_code"] == 2
        assert "stopped before the run finished" in outage["reason"]
        assert "exit_code=2" in outage["reason"]

    @pytest.mark.asyncio
    async def test_stopped_without_an_exit_code_still_reports_an_outage(self, tmp_path: Path) -> None:
        """Some collectors' ``stopped`` detail (e.g. ``kernel_object_monitor.ps1``) carries no exit code.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        content = f"{_TS}|{_COLLECTOR}|started|stop_event=IntellicrackMonitorStop\n{_TS}|{_COLLECTOR}|stopped|stop_requested=True\n"
        _write_log(tmp_path, _LOG_NAME, content)
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is not None
        assert outage["exit_code"] is None
        assert "stopped before the run finished" in outage["reason"]

    @pytest.mark.asyncio
    async def test_last_stopped_line_wins_when_a_log_has_several(self, tmp_path: Path) -> None:
        """A restarted collector's most recent lifecycle state must be used, not its first.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        content = (
            f"{_TS}|{_COLLECTOR}|started|first\n"
            f"{_TS}|{_COLLECTOR}|stopped|exit_code=2 first_failure\n"
            f"{_TS}|{_COLLECTOR}|started|second\n"
            f"{_TS}|{_COLLECTOR}|stopped|exit_code=5 second_failure\n"
        )
        _write_log(tmp_path, _LOG_NAME, content)
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is not None
        assert outage["exit_code"] == 5


class TestParseCollectorLifecycleHealthy:
    """A collector still running - started with no stop reported - is not an outage."""

    @pytest.mark.asyncio
    async def test_started_with_no_stopped_line_is_not_an_outage(self, tmp_path: Path) -> None:
        """The healthy case: the collector is presumed still watching.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        content = f"{_TS}|{_COLLECTOR}|started|pid_filter=0 duration=0 stop_event=IntellicrackMonitorStop\n"
        _write_log(tmp_path, _LOG_NAME, content)
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is None, "a collector that reported starting and has not since reported stopping must not be an outage"

    @pytest.mark.asyncio
    async def test_malformed_short_lines_do_not_prevent_detecting_started(self, tmp_path: Path) -> None:
        """Lines below the four-field minimum must be ignored, not treated as state.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        content = f"garbage\n{_TS}|only_two\n{_TS}|{_COLLECTOR}|started|ok\n"
        _write_log(tmp_path, _LOG_NAME, content)
        outage = await parse_collector_lifecycle(tmp_path, _COLLECTOR, _LOG_NAME)
        assert outage is None


def _terminate(proc: Popen[str]) -> tuple[str, str]:
    """Terminate a running monitor process and collect its output.

    Args:
        proc: The running script process.

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


async def _run_to_completion(powershell: str, script_path: Path, logs_dir: Path) -> tuple[str, str]:
    """Run a bundled monitor script to completion under real ``powershell.exe``.

    Args:
        powershell: Path to ``powershell.exe``.
        script_path: Monitor script to run.
        logs_dir: ``-LogDir`` argument.

    Returns:
        tuple[str, str]: Captured ``(stdout, stderr)``.
    """
    argv = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-LogDir",
        str(logs_dir),
    ]
    proc = Popen(argv, stdout=PIPE, stderr=PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        deadline = time.monotonic() + _PROCESS_EXIT_WAIT_S
        while True:
            if proc.poll() is not None:
                break
            if time.monotonic() >= deadline:
                break
            await asyncio.sleep(_POLL_S)
    finally:
        stdout, stderr = _terminate(proc)
    return stdout, stderr


class _WindowsAgentSandboxWithoutTraceEvent(QEMUSandbox):
    """Stages only the bundled ``api_trace.ps1`` and ``injection_monitor.ps1``.

    Reproduces the S17-D50(a) provisioning gap deterministically - the
    vendored ETW assemblies are deliberately not staged - so this outage
    detection gate does not depend on that fix having run.
    """

    async def stage_scripts_without_traceevent(self, share: Path) -> None:
        """Copy the two real ETW-based monitor scripts into ``share/monitor``, no assemblies.

        Args:
            share: Host directory standing in for the guest's shared folder.
        """
        self._shared_folder = share
        monitor_dir = share / _MONITOR_DIR_NAME
        await asyncio.to_thread(monitor_dir.mkdir, parents=True, exist_ok=True)
        scripts_src = await asyncio.to_thread(self.bundled_scripts_dir)
        for script_name in (_API_TRACE_SCRIPT_NAME, _INJECTION_MONITOR_SCRIPT_NAME):
            await asyncio.to_thread(shutil.copy2, scripts_src / script_name, monitor_dir / script_name)


class _ReportReadingSandbox(QEMUSandbox):
    """``QEMUSandbox`` that reads monitor logs from a chosen shared folder."""

    def use_shared_folder(self, share: Path) -> None:
        """Point the sandbox at the folder holding the guest's monitor logs.

        Args:
            share: Shared folder root.
        """
        self._shared_folder = share

    async def collect_outages(self) -> list[CollectorOutage]:
        """Parse the guest's collector outages through the real host-side reader.

        Returns:
            list[CollectorOutage]: Outages the real
            :meth:`QEMUSandbox._collect_monitoring_logs` reports.
        """
        logs = await self._collect_monitoring_logs()
        return logs.collector_outages

    async def collect_api_calls(self) -> list[dict[str, object]]:
        """Parse the guest's raw API-call records through the real host-side reader.

        Returns:
            list[dict[str, object]]: Parsed API-call records, cast for the
            test's own inspection.
        """
        logs = await self._collect_monitoring_logs()
        return [dict(call) for call in logs.api_calls]


@pytest.mark.asyncio
class TestARealDeadRecorderIsReportedAsAnOutageNotARecord:
    """The end-to-end path the live defect broke: a dead recorder to a distinct outage."""

    async def test_unprovisioned_recorders_surface_as_outages_in_collect_monitoring_logs(self, tmp_path: Path) -> None:
        """Both real ETW-based scripts, run without their DLL, must surface as outages.

        This drives the whole S17-D50(b) path for real: the genuine bundled
        scripts are staged without the vendored assemblies - the exact
        provisioning gap S17-D50(a) fixes - launched under the real
        ``powershell.exe``, and the resulting shared folder is read back
        through the real :meth:`QEMUSandbox._collect_monitoring_logs`. A
        pass here is exactly what "the report says these collectors are
        unavailable" means.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run the bundled monitor scripts")

        share = tmp_path / "shared"
        stage_sandbox = _WindowsAgentSandboxWithoutTraceEvent(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
        await stage_sandbox.stage_scripts_without_traceevent(share)

        logs_dir = share / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)

        api_trace_stdout, api_trace_stderr = await _run_to_completion(
            powershell,
            share / _MONITOR_DIR_NAME / _API_TRACE_SCRIPT_NAME,
            logs_dir,
        )
        injection_stdout, injection_stderr = await _run_to_completion(
            powershell,
            share / _MONITOR_DIR_NAME / _INJECTION_MONITOR_SCRIPT_NAME,
            logs_dir,
        )

        read_sandbox = _ReportReadingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
        read_sandbox.use_shared_folder(share)
        outages = await read_sandbox.collect_outages()
        by_collector = {outage["collector"]: outage for outage in outages}

        assert "api_trace" in by_collector, (
            f"api_trace.ps1's early exit was not surfaced as a collector outage; "
            f"outages={outages!r} stdout={api_trace_stdout!r} stderr={api_trace_stderr!r}"
        )
        assert by_collector["api_trace"]["exit_code"] == 2, (
            f"api_trace outage did not carry the recorded exit code: {by_collector['api_trace']!r}"
        )

        assert "injection_monitor" in by_collector, (
            f"injection_monitor.ps1's failure to ever start was not surfaced as a collector outage; "
            f"outages={outages!r} stdout={injection_stdout!r} stderr={injection_stderr!r}"
        )
        assert "never reported starting" in by_collector["injection_monitor"]["reason"]
        assert by_collector["injection_monitor"]["exit_code"] is None

        api_calls = await read_sandbox.collect_api_calls()
        assert any(call["api_name"] == "ERROR" for call in api_calls), (
            "the fabricated ERROR row api_trace.ps1 wrote to its data log for lack of any other channel "
            f"should still be readable alongside the new outage signal, not silently dropped: {api_calls!r}"
        )


class _FullyStagedWindowsAgentSandbox(QEMUSandbox):
    """Stages the real, complete Windows agent bundle, vendored ETW assemblies included."""

    async def stage_monitor_directory(self, share: Path) -> None:
        """Write the production agent, every bundled monitor script, and the vendored assemblies into ``share``.

        Args:
            share: Host directory standing in for the guest's shared folder.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()


@pytest.mark.asyncio
class TestARealDeadRecorderIsReportedAsAnOutageEvenWithAssembliesStaged:
    """The S17-D50(b) outage guarantee must hold against today's real, fully-staged agent bundle.

    S17-D50(a) fixes assembly *discovery*; a distinct, already-tracked
    load-time gap documented in
    ``test_traceevent_provisioning_s17d50a.py::TestKnownResidualLoadGap``
    means both real ETW-based collectors still fail today even with every
    vendored assembly staged. This is the strongest gate for S17-D50(b): it
    proves the outage guarantee holds against production's actual current
    behaviour - the real :meth:`QEMUSandbox._create_guest_agent_script`
    staging everything it stages today - not only against the deliberately
    DLL-less staging variant above, which isolates outage detection from
    whatever S17-D50(a) does or does not fully resolve.
    """

    async def test_fully_staged_recorders_still_surface_as_outages_not_records(self, tmp_path: Path) -> None:
        """Run both real recorders against the real, fully-staged bundle and read the report back.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run the bundled monitor scripts")

        share = tmp_path / "shared"
        stage_sandbox = _FullyStagedWindowsAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
        await stage_sandbox.stage_monitor_directory(share)

        logs_dir = share / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)

        api_trace_stdout, api_trace_stderr = await _run_to_completion(
            powershell,
            share / _MONITOR_DIR_NAME / _API_TRACE_SCRIPT_NAME,
            logs_dir,
        )
        injection_stdout, injection_stderr = await _run_to_completion(
            powershell,
            share / _MONITOR_DIR_NAME / _INJECTION_MONITOR_SCRIPT_NAME,
            logs_dir,
        )

        read_sandbox = _ReportReadingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
        read_sandbox.use_shared_folder(share)
        outages = await read_sandbox.collect_outages()
        by_collector = {outage["collector"]: outage for outage in outages}

        assert "api_trace" in by_collector, (
            f"api_trace.ps1's early exit against the real staged bundle was not surfaced as a collector outage; "
            f"outages={outages!r} stdout={api_trace_stdout!r} stderr={api_trace_stderr!r}"
        )
        assert by_collector["api_trace"]["exit_code"] not in {None, 0}, (
            f"a live api_trace failure must carry a non-zero exit code, not be reported as healthy: {by_collector['api_trace']!r}"
        )

        assert "injection_monitor" in by_collector, (
            f"injection_monitor.ps1's failure to ever start against the real staged bundle was not surfaced as a "
            f"collector outage; outages={outages!r} stdout={injection_stdout!r} stderr={injection_stderr!r}"
        )
        assert by_collector["injection_monitor"]["exit_code"] is None


@pytest.mark.asyncio
class TestCollectorOutagesAreWindowsOnly:
    """A Linux guest has no ETW-based collectors, so it must report no outages for them."""

    async def test_linux_guest_reports_no_collector_outages(self, tmp_path: Path) -> None:
        """No lifecycle logs exist on a Linux guest; that must not manufacture outages.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "shared"
        (share / _LOGS_DIR_NAME).mkdir(parents=True, exist_ok=True)

        read_sandbox = _ReportReadingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.LINUX))
        read_sandbox.use_shared_folder(share)
        outages = await read_sandbox.collect_outages()
        assert outages == [], (
            f"a Linux guest has no api_trace/injection_monitor collectors and must report no outages for them: {outages!r}"
        )
