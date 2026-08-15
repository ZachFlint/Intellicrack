# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for S18-D09: the API tracer's own rows are not API calls.

``api_trace.ps1`` has no channel but its own data log in which to announce
that it started, that it stopped, and that it failed, so it writes all
three into ``api_trace.log`` as records carrying the marker ``tracer`` in
the process-name field. :func:`parse_api_trace_log` handed those rows to
the report as genuine API calls. Live on the Windows 11 QEMU guest that
turned a collector which had captured nothing at all - its trace session
died before processing a single event - into an API Calls tab reporting
two calls, named ``ERROR`` and ``STOP``.

The injection monitor's identical rows were already skipped (S17-D78);
the API tracer's were not.

Nothing here restates what the guest writes. The log writers and the call
sites are lifted out of the real ``api_trace.ps1`` and executed by a real
PowerShell, so the bytes under test are the bytes the guest would have
produced. Dropping the rows loses no information: the outage is reported
through :func:`intellicrack.sandbox.log_parsers.parse_collector_lifecycle`,
which is the channel built for it, and that is asserted here too.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import run
from intellicrack.sandbox.log_parsers import collect_collector_outages, parse_api_trace_log


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_SCRIPT_PATH: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "api_trace.ps1"

_LOG_NAME: Final[str] = "api_trace.log"
_LIFECYCLE_LOG_NAME: Final[str] = "api_trace.lifecycle.log"
_COLLECTOR: Final[str] = "api_trace"

# Locators, not restatements. Each names one statement in the script; every
# extraction is asserted to have found exactly what it looked for, so renaming
# a call site in the script fails the gate instead of quietly emptying it.
_BODY_SENTINEL: Final[str] = "\ntry {\n"
_RECORD_EMIT: Final[str] = 'Write-TraceLine -Line "$ts|$procName|$procIdRaw|$apiName|'
_STOP_EMIT: Final[str] = 'Write-TraceLine -Line "$tsStop|tracer|0|STOP|'
_START_EMIT: Final[str] = 'Write-TraceLine -Line "$tsStart|tracer|0|START|'
_FATAL_EMIT: Final[str] = "Write-TraceFatal -Code 2 -Stage 'unavailable'"
_LIFECYCLE_STOPPED_EMIT: Final[str] = "Write-TraceLifecycle -State 'stopped'"

_OBSERVED_PROCESS: Final[str] = "loader.exe"
_OBSERVED_PID: Final[int] = 4321
_OBSERVED_EVENT_ID: Final[int] = 5
_OBSERVED_API: Final[str] = "NtOpenProcess"
_EXPECTED_EXIT_CODE: Final[int] = 2
_EXPECTED_STAGE: Final[str] = "unavailable"
_EXPECTED_DETAIL: Final[str] = "Microsoft.Diagnostics.Tracing.TraceEvent.dll not found"
_POWERSHELL_TIMEOUT_SEC: Final[float] = 60.0
_COLLECTOR_MARKERS: Final[frozenset[str]] = frozenset({"START", "STOP", "ERROR"})

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the lifted api_trace.ps1 log writers need a Windows PowerShell",
)


@dataclass(frozen=True)
class _Emission:
    """One PowerShell run of the lifted log writers and what it produced.

    Attributes:
        raw_lines: Non-empty lines the lifted writers appended to the log.
        collector_rows: How many of those lines are the collector's own.
    """

    raw_lines: list[str]
    collector_rows: int


def _resolve_powershell() -> str:
    """Locate a PowerShell interpreter able to run the lifted writers.

    Returns:
        str: Absolute path to ``pwsh`` or to Windows PowerShell.
    """
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("no PowerShell interpreter is available to run the lifted log writers")
    return shell


def _script_text() -> str:
    """Read ``api_trace.ps1`` with newlines normalised.

    Returns:
        str: The script's source text.
    """
    return _SCRIPT_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")


def _helpers_prefix(text: str) -> str:
    """Return the script's parameter block, helpers and script-scoped state.

    The main body begins at the script's only column-zero ``try {``; the
    prefix before it defines the log paths and every writer this gate
    drives, without starting an ETW session.

    Args:
        text: The script's source text.

    Returns:
        str: The prefix, ending just before the main body.

    Raises:
        AssertionError: If the script has no column-zero ``try {``.
    """
    cut = text.find(_BODY_SENTINEL)
    if cut < 0:
        msg = f"{_SCRIPT_PATH.name} no longer has a script-level 'try {{' introducing its body"
        raise AssertionError(msg)
    return text[: cut + 1]


def _lift_statement(text: str, needle: str) -> str:
    """Lift the single source line that carries ``needle``.

    Args:
        text: The script's source text.
        needle: Text identifying the wanted statement.

    Returns:
        str: The statement, stripped of its indentation.

    Raises:
        AssertionError: If the script does not carry exactly one such line.
    """
    matched = [line.strip() for line in text.split("\n") if needle in line]
    if len(matched) != 1:
        msg = f"{_SCRIPT_PATH.name} carries {len(matched)} statements matching {needle!r}, expected exactly 1"
        raise AssertionError(msg)
    return matched[0]


def _emit_records(shared: Path, *, with_collector_rows: bool) -> _Emission:
    """Write an API-trace log using the script's own writers.

    Args:
        shared: Sandbox shared-folder root; the log lands under ``logs/``.
        with_collector_rows: Whether to also run the script's own
            start/stop/failure announcements.

    Returns:
        _Emission: The lines written and how many are the collector's own.
    """
    shell = _resolve_powershell()
    text = _script_text()
    log_dir = shared / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    collector_statements = [
        "$tsStart = Get-Date -Format 'o'",
        "$sessionName = 'IntApiTrace'",
        "$auditApiProviderGuid = [Guid]'E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23'",
        "$FilterPid = 0",
        _lift_statement(text, _START_EMIT),
        _lift_statement(text, _FATAL_EMIT),
        "$tsStop = Get-Date -Format 'o'",
        _lift_statement(text, _STOP_EMIT),
        _lift_statement(text, _LIFECYCLE_STOPPED_EMIT),
    ]
    observed_statements = [
        "$ts = Get-Date -Format 'o'",
        f"$procName = '{_OBSERVED_PROCESS}'",
        f"$procIdRaw = {_OBSERVED_PID}",
        f"$apiName = Get-AuditApiName -EventId {_OBSERVED_EVENT_ID}",
        "$module = 'ntoskrnl.exe'",
        f"$arguments = 'TargetProcessId={_OBSERVED_PID}'",
        "$returnValue = '0x0'",
        _lift_statement(text, _RECORD_EMIT),
    ]

    driver_lines = [_helpers_prefix(text)]
    if with_collector_rows:
        driver_lines.extend(collector_statements)
    driver_lines.extend(observed_statements)

    driver = shared / "emit_api_trace_records.ps1"
    driver.write_text("\n".join(driver_lines) + "\n", encoding="utf-8")

    result = run(
        [
            shell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(driver),
            "-LogDir",
            str(log_dir),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_POWERSHELL_TIMEOUT_SEC,
        check=False,
    )
    assert result.returncode == 0, f"the lifted writers failed: stdout={result.stdout!r} stderr={result.stderr!r}"

    log_path = log_dir / _LOG_NAME
    assert log_path.is_file(), f"the lifted writers produced no {_LOG_NAME}; stderr={result.stderr!r}"
    raw_lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    collector_rows = sum(1 for line in raw_lines if line.split("|")[1] == "tracer")
    return _Emission(raw_lines=raw_lines, collector_rows=collector_rows)


def _assert_log_holds_what_was_asked_for(emission: _Emission, *, expect_collector_rows: bool) -> None:
    """Confirm PowerShell really wrote the rows the assertions depend on.

    Without this the parser assertions would also pass on an empty log,
    which is the failure mode of a driver that silently did nothing.

    Args:
        emission: The run to check.
        expect_collector_rows: Whether the run was asked for the
            collector's own announcements.
    """
    assert len(emission.raw_lines) == 1 + emission.collector_rows, f"unexpected log contents: {emission.raw_lines}"
    if expect_collector_rows:
        assert emission.collector_rows >= len(_COLLECTOR_MARKERS), (
            f"the collector's own rows were not all written, so nothing is under test: {emission.raw_lines}"
        )
    else:
        assert emission.collector_rows == 0, f"unexpected collector rows: {emission.raw_lines}"


class TestTheApiTracersOwnRowsAreNotApiCalls:
    """Tests that the tracer's own announcements never reach the report."""

    @pytest.mark.asyncio
    async def test_no_collector_row_survives_parsing(self, tmp_path: Path) -> None:
        """Confirm only the observed call is parsed out of the log.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_collector_rows=True)
        _assert_log_holds_what_was_asked_for(emission, expect_collector_rows=True)

        calls = await parse_api_trace_log(tmp_path, _LOG_NAME)

        assert len(calls) == 1, f"the collector's own rows were parsed as API calls: {calls}"
        assert calls[0]["api_name"] == _OBSERVED_API
        assert calls[0]["process_name"] == _OBSERVED_PROCESS
        assert calls[0]["pid"] == _OBSERVED_PID
        assert all(call["api_name"] not in _COLLECTOR_MARKERS for call in calls)

    @pytest.mark.asyncio
    async def test_the_failure_text_still_reaches_the_report(self, tmp_path: Path) -> None:
        """Confirm skipping the rows loses none of the failure information.

        The row is moved, not dropped: its stage and message are carried
        on the collector's outage, which is the channel built for exactly
        this and the only one left once the row leaves the API tab.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_collector_rows=True)
        _assert_log_holds_what_was_asked_for(emission, expect_collector_rows=True)

        outages = await collect_collector_outages(tmp_path)
        by_collector = {outage["collector"]: outage for outage in outages}

        assert _COLLECTOR in by_collector, f"a collector that announced its own failure was reported as healthy: {outages}"
        outage = by_collector[_COLLECTOR]
        assert outage["exit_code"] == _EXPECTED_EXIT_CODE, f"the collector's exit code was lost: {outage}"
        assert _EXPECTED_STAGE in outage["reason"], f"the failing stage was lost with the row: {outage}"
        assert _EXPECTED_DETAIL in outage["reason"], f"the collector's own failure text was lost with the row: {outage}"

    @pytest.mark.asyncio
    async def test_an_observed_call_is_still_reported(self, tmp_path: Path) -> None:
        """Confirm the filter costs nothing: a real API call still lands.

        This is the control. Without it, a parser that dropped every row
        would pass the test above.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        emission = _emit_records(tmp_path, with_collector_rows=False)
        _assert_log_holds_what_was_asked_for(emission, expect_collector_rows=False)

        calls = await parse_api_trace_log(tmp_path, _LOG_NAME)

        assert len(calls) == 1, f"the observed API call did not survive parsing: {calls}"
        assert calls[0]["api_name"] == _OBSERVED_API
