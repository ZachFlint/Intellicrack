# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for S17-D78: the injection monitor's own failure is not an injection.

``injection_monitor.ps1`` has no channel but its own data log in which to
report that its ETW trace session died, so several of its failure paths call
``Write-InjectionRecord`` with ``-SourceName 'tracer'`` and
``-InjectionType 'ERROR'``. :func:`parse_injection_log` used to hand those
rows to the report as genuine injection events, and :func:`match_behaviors`
turned each one into a *critical* ``T1055`` "Process Injection" finding
against whatever the sandbox happened to be running. On the live Windows 11
QEMU guest that produced a critical injection finding for a sample that had
injected into nothing at all - the collector had merely failed to start.

Nothing here restates what the guest writes. The record writer and the
tracer-error call sites are lifted out of the real ``injection_monitor.ps1``
and executed by a real PowerShell, so the bytes under test are the bytes the
guest would have produced, and a rename or a change of marker in the script
reddens these tests instead of silently passing them.

Dropping the rows loses no information: the outage is reported through
:func:`intellicrack.sandbox.log_parsers.parse_collector_lifecycle`, which is
the channel built for it.
"""

from __future__ import annotations

import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import run
from intellicrack.sandbox.analysis import match_behaviors
from intellicrack.sandbox.base import ExecutionReport
from intellicrack.sandbox.log_parsers import parse_injection_log


if TYPE_CHECKING:
    from intellicrack.sandbox.base import InjectionEvent


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "injection_monitor.ps1"

_LOG_NAME: Final[str] = "injection_monitor.log"
_RECORD_WRITER: Final[str] = "Write-InjectionRecord"

# Locators, not restatements: the record layout, the injection type and the
# collector-error marker all come out of the script text these two prefixes
# find. Both extractions are asserted non-empty, so renaming a call site in
# the script fails the gate rather than quietly emptying it.
_GENUINE_CALL_PREFIX: Final[str] = f"{_RECORD_WRITER} -Timestamp $ts -SourcePid $sourcePid"
_TRACER_CALL_PREFIX: Final[str] = f"{_RECORD_WRITER} -Timestamp $ts -SourcePid 0 -SourceName 'tracer'"
_INJECTION_TYPE_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(r"\$injType = '([A-Za-z_]+)'")
_INJECTION_TYPE_ARGUMENT: Final[re.Pattern[str]] = re.compile(r"-InjectionType '([^']+)'")

_SOURCE_PID: Final[int] = 4321
_SOURCE_NAME: Final[str] = "loader.exe"
_TARGET_PID: Final[int] = 8765
_TARGET_NAME: Final[str] = "explorer.exe"
_GENUINE_TIMESTAMP: Final[str] = "2026-08-09T11:04:18.4412207+00:00"
_ERROR_TIMESTAMP: Final[str] = "2026-08-09T11:04:19.8830115+00:00"
_TRACE_FAILURE_MESSAGE: Final[str] = "The trace session could not be started"
_MITRE_PROCESS_INJECTION: Final[str] = "T1055"
_POWERSHELL_TIMEOUT_SEC: Final[float] = 60.0


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the lifted injection_monitor.ps1 record writer needs a Windows PowerShell",
)


@dataclass(frozen=True)
class _Emission:
    """One PowerShell run of the lifted record writer and what it produced.

    Attributes:
        raw_lines: Non-empty lines the lifted writer appended to the log.
        injection_type: The injection type the script assigns to a resolved
            remote-thread start, taken from the script itself.
        error_marker: The injection type the script uses to report its own
            failure, taken from the script itself.
        tracer_rows: How many collector-error rows the run emitted.
    """

    raw_lines: list[str]
    injection_type: str
    error_marker: str
    tracer_rows: int


def _resolve_powershell() -> str:
    """Locate a PowerShell interpreter able to run the lifted script.

    Returns:
        str: Absolute path to ``pwsh`` or to Windows PowerShell.
    """
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell interpreter is available to run the lifted record writer")
    return shell


def _script_lines() -> list[str]:
    """Read ``injection_monitor.ps1`` as newline-normalised lines.

    Returns:
        list[str]: The script's lines, without their line terminators.
    """
    return _SCRIPT_PATH.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n")


def _extract_function(lines: list[str], name: str) -> str:
    """Lift one whole PowerShell function definition out of the script.

    Args:
        lines: The script's lines.
        name: Name of the function to lift.

    Returns:
        str: The function's source text, from its ``function`` line through
        its closing brace.
    """
    opening = f"function {name} {{"
    start = next((index for index, line in enumerate(lines) if line.strip() == opening), -1)
    assert start >= 0, f"{_SCRIPT_PATH.name} no longer defines {name}"
    end = next((index for index in range(start + 1, len(lines)) if lines[index] == "}"), -1)
    assert end > start, f"{name} has no closing brace in {_SCRIPT_PATH.name}"
    return "\n".join(lines[start : end + 1])


def _extract_statements(lines: list[str], prefix: str) -> list[str]:
    """Lift every statement that begins with ``prefix``, backticks included.

    A PowerShell statement continues onto the next line when the current one
    ends in a backtick, which every ``Write-InjectionRecord`` call in the
    script does, so the continuation lines are gathered with it.

    Args:
        lines: The script's lines.
        prefix: Text each wanted statement's first line starts with.

    Returns:
        list[str]: Each matching statement as one dedented source block.
    """
    found: list[str] = []
    for index, line in enumerate(lines):
        if not line.strip().startswith(prefix):
            continue
        block = [line.strip()]
        cursor = index
        while lines[cursor].rstrip().endswith("`") and cursor + 1 < len(lines):
            cursor += 1
            block.append(lines[cursor].strip())
        found.append("\n".join(block))
    return found


def _sole_match(pattern: re.Pattern[str], text: str, what: str) -> str:
    """Return the first capture of ``pattern`` in ``text``.

    Args:
        pattern: Expression whose first group carries the wanted value.
        text: Text to search.
        what: What is being looked for, used in the failure message.

    Returns:
        str: The first captured group.
    """
    match = pattern.search(text)
    assert match is not None, f"{_SCRIPT_PATH.name} no longer states {what}"
    return match.group(1)


def _emit_records(shared: Path, *, with_tracer_errors: bool) -> _Emission:
    """Write an injection log using the script's own record writer.

    The writer function and the call sites are lifted from
    ``injection_monitor.ps1`` and run by a real PowerShell against a real
    file, so the log carries the guest's byte layout rather than this
    module's idea of it.

    Args:
        shared: Shared-folder root; the log lands under ``<shared>/logs/``.
        with_tracer_errors: Whether to also run the script's own
            failure-reporting call sites.

    Returns:
        _Emission: The lines written and the markers they were built from.
    """
    lines = _script_lines()
    writer = _extract_function(lines, _RECORD_WRITER)
    genuine = _extract_statements(lines, _GENUINE_CALL_PREFIX)
    assert genuine, f"{_SCRIPT_PATH.name} no longer records a resolved remote-thread start"
    tracer = _extract_statements(lines, _TRACER_CALL_PREFIX)
    assert tracer, f"{_SCRIPT_PATH.name} no longer records its own trace-session failure"

    injection_type = _sole_match(_INJECTION_TYPE_ASSIGNMENT, "\n".join(lines), "an injection type for a thread start")
    error_marker = _sole_match(_INJECTION_TYPE_ARGUMENT, tracer[0], "an injection type for its own failure")

    logs = shared / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_path = logs / _LOG_NAME
    quoted_log_path = str(log_path).replace("'", "''")

    driver = [
        "$ErrorActionPreference = 'Stop'",
        f"$script:logPathRef = '{quoted_log_path}'",
        writer,
        f"$ts = '{_GENUINE_TIMESTAMP}'",
        f"$sourcePid = {_SOURCE_PID}",
        f"$sourceName = '{_SOURCE_NAME}'",
        f"$evtPid = {_TARGET_PID}",
        f"$targetName = '{_TARGET_NAME}'",
        f"$injType = '{injection_type}'",
        "$unique = @('KernelTrace/ThreadStart', 'KernelTrace/VirtualAlloc')",
        genuine[0],
    ]
    if with_tracer_errors:
        driver.extend([f"$ts = '{_ERROR_TIMESTAMP}'", f"$msg = '{_TRACE_FAILURE_MESSAGE}'", *tracer])

    driver_path = shared / "emit_injection_records.ps1"
    driver_path.write_text("\n".join(driver), encoding="utf-8")

    completed = run(
        [
            _resolve_powershell(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(driver_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=_POWERSHELL_TIMEOUT_SEC,
    )
    assert completed.returncode == 0, f"the lifted record writer failed: {completed.stderr.strip()}"

    raw_lines = [line for line in log_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return _Emission(
        raw_lines=raw_lines,
        injection_type=injection_type,
        error_marker=error_marker,
        tracer_rows=len(tracer) if with_tracer_errors else 0,
    )


def _assert_log_holds_what_was_asked_for(emission: _Emission) -> None:
    """Confirm PowerShell really wrote the rows the assertions depend on.

    Without this the parser assertions would also pass on an empty log,
    which is the failure mode of a driver that silently did nothing.

    Args:
        emission: The run to check.
    """
    assert len(emission.raw_lines) == 1 + emission.tracer_rows, f"unexpected log contents: {emission.raw_lines}"
    written_errors = sum(1 for line in emission.raw_lines if f"|{emission.error_marker}|" in line)
    assert written_errors == emission.tracer_rows, f"the collector-error rows were not written: {emission.raw_lines}"


def _report_for(events: list[InjectionEvent]) -> ExecutionReport:
    """Wrap injection events in the report the behaviour matcher consumes.

    Args:
        events: Injection events to place in the report.

    Returns:
        ExecutionReport: A report carrying nothing but those events.
    """
    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=1.0,
        injection_events=events,
    )


class TestTheCollectorsOwnErrorRowIsNotAnInjection:
    """Tests that the monitor's self-reported failure never becomes a finding."""

    @pytest.mark.asyncio
    async def test_no_tracer_error_row_survives_parsing(self, tmp_path: Path) -> None:
        """Confirm only the genuine injection is parsed out of the log.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_tracer_errors=True)
        assert emission.tracer_rows > 0, "the script wrote no collector-error row, so nothing is under test"
        _assert_log_holds_what_was_asked_for(emission)

        events = await parse_injection_log(tmp_path, _LOG_NAME)

        assert len(events) == 1, f"the collector's own rows were parsed as injections: {events}"
        assert events[0]["injection_type"] == emission.injection_type
        assert events[0]["source_name"] == _SOURCE_NAME
        assert events[0]["target_pid"] == _TARGET_PID
        assert all(event["injection_type"] != emission.error_marker for event in events)

    @pytest.mark.asyncio
    async def test_no_tracer_error_row_becomes_a_t1055_finding(self, tmp_path: Path) -> None:
        """Confirm a dead collector does not raise a critical injection finding.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_tracer_errors=True)
        _assert_log_holds_what_was_asked_for(emission)
        events = await parse_injection_log(tmp_path, _LOG_NAME)

        matches = match_behaviors(_report_for(events))
        injections = [match for match in matches if match["mitre_attack_id"] == _MITRE_PROCESS_INJECTION]

        assert len(injections) == 1, f"a dead collector was reported as process injection: {injections}"
        assert _SOURCE_NAME in injections[0]["description"]
        assert all("tracer" not in match["description"] for match in injections)

    @pytest.mark.asyncio
    async def test_a_genuine_injection_is_still_reported(self, tmp_path: Path) -> None:
        """Confirm the filter costs nothing: a real injection still lands.

        This is the control. It keeps the gate honest about what it proves -
        without it, a parser that dropped every row would pass the two tests
        above.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_tracer_errors=False)
        _assert_log_holds_what_was_asked_for(emission)

        events = await parse_injection_log(tmp_path, _LOG_NAME)
        assert len(events) == 1
        assert events[0]["injection_type"] == emission.injection_type

        matches = match_behaviors(_report_for(events))
        injections = [match for match in matches if match["mitre_attack_id"] == _MITRE_PROCESS_INJECTION]

        assert len(injections) == 1
        assert injections[0]["severity"] == "critical"
        assert _TARGET_NAME in injections[0]["description"]
