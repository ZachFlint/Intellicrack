# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""S18-D08 gates for the ETW collectors' trace-source statements.

Two defects, one statement apart, kept every ETW collector from ever
consuming an event.

``api_trace.ps1`` and ``injection_monitor.ps1`` register a catch-all
handler for events no parser claimed, and both did it by reading
``$source.UnhandledEvents`` and calling ``add_All`` on the result.
``UnhandledEvents`` is a .NET *event* declared on
``Microsoft.Diagnostics.Tracing.TraceEventDispatcher``, not a parser
property like ``Dynamic``; PowerShell exposes events only as ``add_``/
``remove_`` methods, so the member read always produced ``$null`` and the
call on it always threw ``You cannot call a method on a null-valued
expression``.

One statement later, all three collectors - ``dll_monitor.ps1`` too -
pumped with ``$source.Process()``. PowerShell's adapted-member binder
refuses that specific call with ``the result type 'System.Boolean' ... is
not compatible with the result type 'System.Object' expected by the call
site``, on both PowerShell editions, against both ``ETWTraceEventSource``
and ``EventPipeEventSource``, with or without a handler registered. It is
specific to the member name: the equally Boolean ``EnableProvider``
binds normally, and ``$source.psbase.Process()`` runs and delivers.

So the API Calls and Injections tabs were empty on every run, and every
record in ``dll_monitor.log`` came from that collector's WMI fallback.

The gates below execute the collectors' own ``$source`` statements,
lifted verbatim from the production scripts and in source order, against
a real ``TraceEventDispatcher`` fed by a real event stream, and require
events to actually arrive. The stream is a genuine ``.nettrace`` captured
from a child ``pwsh`` through EventPipe, which needs no elevation and no
ETW session, so the gates exercise the real member surface of the real
TraceEvent assembly the collectors load in the guest.

A final gate covers why the failure stayed undiagnosable: the catch-all
around ``Invoke-ApiTrace`` reported only ``$_.Exception.Message``, which
names neither the statement nor the line.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import CompletedProcess, run


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT_DIR: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts"
_API_TRACE_SCRIPT: Final[Path] = _SCRIPT_DIR / "api_trace.ps1"
_INJECTION_SCRIPT: Final[Path] = _SCRIPT_DIR / "injection_monitor.ps1"
_DLL_MONITOR_SCRIPT: Final[Path] = _SCRIPT_DIR / "dll_monitor.ps1"
_VENDOR_TRACE_EVENT: Final[Path] = _REPO_ROOT / "vendor" / "traceevent"
_TRACE_EVENT_DLL_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"
_FAST_SERIALIZATION_DLL_NAME: Final[str] = "Microsoft.Diagnostics.FastSerialization.dll"

_EVENTPIPE_PROVIDER_CONFIG: Final[str] = "Microsoft-Windows-DotNETRuntime:4c14fccbd:5"
_HARNESS_TIMEOUT_SEC: Final[float] = 180.0
_CAPTURE_TIMEOUT_SEC: Final[float] = 120.0
_SCRIPT_TIMEOUT_SEC: Final[float] = 60.0
_EXIT_SESSION_FATAL: Final[int] = 5
_API_LOG_FIELD_COUNT: Final[int] = 7
_STAGE_FIELD_INDEX: Final[int] = 4
_DETAIL_FIELD_INDEX: Final[int] = 5

_SOURCE_STATEMENT: Final[re.Pattern[str]] = re.compile(
    r"^[ \t]*((?:\[void\])?\$source\.\S*(?:add_\w+|Process)\(.*)$",
    re.MULTILINE,
)
_DELIVERED_PREFIX: Final[str] = "DELIVERED="
_PUMPED_PREFIX: Final[str] = "PUMPED="
_ASSEMBLY_LOOKUP_STATEMENT: Final[str] = "    $traceEventDll = Find-TraceEventAssembly"
_FAULT_STATEMENT: Final[str] = "    $traceEventDll = $null.ResolveAssembly()"

pytestmark = [
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="the ETW collectors and the TraceEvent assembly they load are Windows-only",
    ),
    pytest.mark.spawns_process,
]


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Returns:
        str: Absolute path to ``pwsh``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required to drive the TraceEvent assembly")
    return pwsh


def _stage_trace_event_assembly(tmp_path: Path) -> Path:
    """Copy the vendored TraceEvent assembly into an isolated directory.

    ``Assembly.LoadFrom`` probes the loaded file's own directory for
    dependencies. The vendored directory also carries the netstandard2.0
    compatibility facades the guest's Windows PowerShell needs, and those
    are rejected by the .NET runtime ``pwsh`` runs on, so the assembly is
    staged on its own together with the serializer it genuinely needs.

    Args:
        tmp_path: Pytest-provided temp directory.

    Returns:
        Path: Absolute path to the staged TraceEvent assembly.
    """
    source_dll = _VENDOR_TRACE_EVENT / _TRACE_EVENT_DLL_NAME
    if not source_dll.is_file():
        pytest.skip(f"vendored TraceEvent assembly is absent: {source_dll}")
    staged_dir = tmp_path / "traceevent"
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged_dll = staged_dir / _TRACE_EVENT_DLL_NAME
    shutil.copy2(source_dll, staged_dll)
    serializer = _VENDOR_TRACE_EVENT / _FAST_SERIALIZATION_DLL_NAME
    if serializer.is_file():
        shutil.copy2(serializer, staged_dir / _FAST_SERIALIZATION_DLL_NAME)
    return staged_dll


def _capture_event_stream(tmp_path: Path, pwsh: str) -> Path:
    """Capture a real ``.nettrace`` event stream from a child ``pwsh``.

    EventPipe is driven entirely through the runtime's own environment
    variables, so the capture needs neither elevation nor an ETW session
    while still producing a genuine event stream that
    ``EventPipeEventSource`` - a real ``TraceEventDispatcher`` - replays.

    Args:
        tmp_path: Pytest-provided temp directory.
        pwsh: Absolute path to ``pwsh``.

    Returns:
        Path: Absolute path to the captured ``.nettrace`` file.
    """
    trace_path = tmp_path / "collector_gate.nettrace"
    env = dict(os.environ)
    env["DOTNET_EnableEventPipe"] = "1"
    env["DOTNET_EventPipeOutputPath"] = str(trace_path)
    env["DOTNET_EventPipeConfig"] = _EVENTPIPE_PROVIDER_CONFIG
    result = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$acc = 1..2000 | ForEach-Object { $_ * 2 }; $acc.Length",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=_CAPTURE_TIMEOUT_SEC,
        check=False,
    )
    assert result.returncode == 0, f"EventPipe capture child failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    assert trace_path.is_file(), f"EventPipe produced no trace at {trace_path}"
    assert trace_path.stat().st_size > 0, f"EventPipe produced an empty trace at {trace_path}"
    return trace_path


def _lift_source_statements(script_path: Path, *, expect_unhandled: bool) -> list[str]:
    """Lift a collector's handler registrations and its pump from its source.

    Every statement of the form ``$source.<...>add_<Event>(...)`` and the
    ``$source....Process()`` pump is taken verbatim and in source order, so
    the gate runs the collector's own code rather than a restatement of it.

    Args:
        script_path: Collector script to lift from.
        expect_unhandled: Whether this collector registers a catch-all
            handler for unparsed events.

    Returns:
        list[str]: The statements, outermost indentation stripped, in
        source order.

    Raises:
        AssertionError: If the script drives nothing through ``$source``,
            never pumps it, or has lost its ``UnhandledEvents``
            registration when one is expected.
    """
    text = script_path.read_text(encoding="utf-8")
    statements = [match.group(1).rstrip() for match in _SOURCE_STATEMENT.finditer(text)]
    if not statements:
        msg = f"{script_path.name} drives nothing through $source; the gate would cover nothing"
        raise AssertionError(msg)
    if not any("Process(" in statement for statement in statements):
        msg = f"{script_path.name} no longer pumps its source; the gate would cover nothing"
        raise AssertionError(msg)
    if expect_unhandled and not any("UnhandledEvents" in statement for statement in statements):
        msg = f"{script_path.name} no longer registers an UnhandledEvents handler; the gate would cover nothing"
        raise AssertionError(msg)
    return statements


def _build_registration_harness(
    tmp_path: Path,
    name: str,
    staged_dll: Path,
    trace_path: Path,
    statements: list[str],
) -> Path:
    """Write a harness that runs a collector's own ``$source`` statements.

    The harness asserts up front that ``$source.UnhandledEvents`` still
    reads as ``$null``, which is the property that made the old
    registration form throw. Without that precondition the gate could go
    quietly vacuous if a future TraceEvent exposed the event as a
    readable member.

    Two counters are reported. ``DELIVERED`` counts what the collector's
    own handler registrations received; ``PUMPED`` counts what a witness
    the harness attaches to ``UnhandledEvents`` just before the pump
    received, which is the only signal a collector that registers nothing
    on ``$source`` at all can give. Either being non-zero means the pump
    ran: a collector whose own parser subscription claims every event
    leaves the witness at zero, and vice versa.

    Args:
        tmp_path: Pytest-provided temp directory.
        name: Base name for the generated harness file.
        staged_dll: TraceEvent assembly to load.
        trace_path: ``.nettrace`` file to replay.
        statements: ``$source`` statements lifted from a collector, in
            source order, the pump last.

    Returns:
        Path: Absolute path to the generated harness script.
    """
    registrations = "\n".join(statements[:-1])
    pump = statements[-1]
    harness = f"""$ErrorActionPreference = 'Stop'
Add-Type -LiteralPath '{staged_dll}'
$source = [Microsoft.Diagnostics.Tracing.EventPipeEventSource]::new('{trace_path}')
if ($null -ne $source.UnhandledEvents) {{
    throw 'precondition failed: TraceEventDispatcher.UnhandledEvents no longer reads as $null'
}}
$script:Delivered = 0
$script:Pumped = 0
$counting = [Action[Microsoft.Diagnostics.Tracing.TraceEvent]] {{
    param($observed)
    $null = $observed
    $script:Delivered = $script:Delivered + 1
}}
$witness = [Action[Microsoft.Diagnostics.Tracing.TraceEvent]] {{
    param($observed)
    $null = $observed
    $script:Pumped = $script:Pumped + 1
}}
$boundHandler = $counting
$threatIntelHandler = $counting
{registrations}
$source.add_UnhandledEvents($witness)
{pump}
Write-Output ('{_DELIVERED_PREFIX}' + $script:Delivered)
Write-Output ('{_PUMPED_PREFIX}' + $script:Pumped)
$source.Dispose()
"""
    harness_path = tmp_path / f"{name}_registration_harness.ps1"
    harness_path.write_text(harness, encoding="utf-8")
    return harness_path


def _run_pwsh_script(pwsh: str, script_path: Path) -> CompletedProcess[str]:
    """Run a PowerShell script file to completion.

    Args:
        pwsh: Absolute path to ``pwsh``.
        script_path: Script to execute.

    Returns:
        CompletedProcess[str]: The completed process.
    """
    return run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_HARNESS_TIMEOUT_SEC,
        check=False,
    )


def _counter(stdout: str, prefix: str) -> int:
    """Extract one of the counts a registration harness printed.

    Args:
        stdout: Harness standard output.
        prefix: Line prefix carrying the wanted count.

    Returns:
        int: The count, or ``-1`` when the harness printed no such line.
    """
    for line in stdout.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix).strip())
    return -1


def _assert_source_statements_deliver(
    tmp_path: Path,
    script_path: Path,
    name: str,
    *,
    expect_unhandled: bool,
) -> None:
    """Run one collector's lifted ``$source`` statements and require delivery.

    Args:
        tmp_path: Pytest-provided temp directory.
        script_path: Collector script whose statements are lifted.
        name: Base name for the generated harness file.
        expect_unhandled: Whether this collector registers a catch-all
            handler for unparsed events.
    """
    pwsh = _resolve_pwsh()
    staged_dll = _stage_trace_event_assembly(tmp_path)
    trace_path = _capture_event_stream(tmp_path, pwsh)
    statements = _lift_source_statements(script_path, expect_unhandled=expect_unhandled)
    harness = _build_registration_harness(tmp_path, name, staged_dll, trace_path, statements)

    result = _run_pwsh_script(pwsh, harness)

    assert result.returncode == 0, (
        f"{script_path.name}'s own trace-source statements failed against a real "
        f"TraceEventDispatcher: {statements!r}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    delivered = _counter(result.stdout, _DELIVERED_PREFIX)
    pumped = _counter(result.stdout, _PUMPED_PREFIX)
    assert delivered >= 0, f"the harness printed no delivered count\nstdout={result.stdout!r}"
    assert pumped >= 0, f"the harness printed no pumped count\nstdout={result.stdout!r}"
    assert delivered + pumped > 0, (
        f"{script_path.name}'s pump ({statements[-1]!r}) drove no events off a real "
        f"stream\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    if expect_unhandled:
        assert delivered > 0, (
            f"{script_path.name}'s own handler registrations received none of the events "
            f"its pump drove\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        )


def test_api_trace_registers_and_pumps_on_a_real_dispatcher(tmp_path: Path) -> None:
    """``api_trace.ps1``'s registrations and pump must deliver events.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    _assert_source_statements_deliver(tmp_path, _API_TRACE_SCRIPT, "api_trace", expect_unhandled=True)


def test_injection_monitor_registers_and_pumps_on_a_real_dispatcher(tmp_path: Path) -> None:
    """``injection_monitor.ps1``'s registrations and pump must deliver events.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    _assert_source_statements_deliver(tmp_path, _INJECTION_SCRIPT, "injection_monitor", expect_unhandled=True)


def test_dll_monitor_pumps_its_realtime_source(tmp_path: Path) -> None:
    """``dll_monitor.ps1``'s pump must run instead of falling back to WMI.

    ``dll_monitor.ps1`` carries a WMI fallback, so a realtime path that
    never pumps still fills its log - with records whose base address and
    event id are zero. Only this gate distinguishes the two.

    Args:
        tmp_path: Pytest-provided temp directory.
    """
    _assert_source_statements_deliver(tmp_path, _DLL_MONITOR_SCRIPT, "dll_monitor", expect_unhandled=False)


def test_api_trace_fatal_record_names_the_failing_statement(tmp_path: Path) -> None:
    """A fatal escaping ``Invoke-ApiTrace`` must name its script line.

    Faults the assembly lookup in a copy of the collector so a real
    unguarded exception escapes to the catch-all that reports stage
    ``session``, then requires the logged record to carry the innermost
    frame - function, script and line - rather than the bare exception
    text that made S18-D08 unlocatable.

    Args:
        tmp_path: Pytest-provided temp directory.

    Raises:
        AssertionError: If the collector's assembly-lookup statement is
            no longer present to fault.
    """
    pwsh = _resolve_pwsh()
    original = _API_TRACE_SCRIPT.read_text(encoding="utf-8")
    if _ASSEMBLY_LOOKUP_STATEMENT not in original:
        msg = f"expected {_ASSEMBLY_LOOKUP_STATEMENT!r} in api_trace.ps1 to fault"
        raise AssertionError(msg)
    patched = original.replace(_ASSEMBLY_LOOKUP_STATEMENT, _FAULT_STATEMENT, 1)
    faulted = tmp_path / "api_trace_faulted.ps1"
    faulted.write_text(patched, encoding="utf-8")

    expected_line = patched[: patched.index(_FAULT_STATEMENT)].count("\n") + 1
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    result = run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(faulted),
            "-LogDir",
            str(log_dir),
            "-TargetPid",
            "0",
            "-DurationSeconds",
            "1",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_SCRIPT_TIMEOUT_SEC,
        check=False,
    )
    assert result.returncode == _EXIT_SESSION_FATAL, (
        f"the faulted lookup must reach the catch-all fatal path (exit {_EXIT_SESSION_FATAL}); "
        f"got {result.returncode!r} stdout={result.stdout!r} stderr={result.stderr!r}"
    )

    log_text = (log_dir / "api_trace.log").read_text(encoding="utf-8", errors="replace")
    fatal_lines = [line for line in log_text.splitlines() if "|ERROR|session|" in line]
    assert fatal_lines, f"expected an ERROR|session| record; log was:\n{log_text}"
    fields = fatal_lines[0].split("|")
    assert len(fields) == _API_LOG_FIELD_COUNT, f"fatal record must keep the 7-field layout; got {fatal_lines[0]!r}"
    assert fields[_STAGE_FIELD_INDEX] == "session", f"unexpected stage in {fatal_lines[0]!r}"
    detail = fields[_DETAIL_FIELD_INDEX]
    assert faulted.name in detail, f"fatal record must name the failing script; got {detail!r}"
    assert f"line {expected_line}" in detail, f"fatal record must carry line {expected_line}; got {detail!r}"
    assert "Invoke-ApiTrace" in detail, f"fatal record must name the innermost frame; got {detail!r}"
