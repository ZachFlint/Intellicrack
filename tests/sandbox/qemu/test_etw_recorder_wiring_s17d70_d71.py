# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D70 and S17-D71: the two ETW recorders that die in every run.

Both were found on the first Windows sandbox session that survived long enough
to be asked (2026-08-09), and both had been invisible for the whole audit
because every earlier session aborted before a monitor could be read back.
Neither is a capability gap - the recorders are wired to ETW correctly in every
other respect - and both are one wrong identifier.

* **S17-D70.** ``api_trace.ps1`` built its session as
  ``$sessionType::new($sessionName, $null)``, intending a real-time session.
  TraceEvent 3.2.5 declares no ``(name, fileName)`` constructor at all - only
  ``(name, options)`` and ``(name, fileName, options)`` - so the ``$null``
  bound the *options* parameter and produced a **file** session with no file.
  Construction succeeded; the first ``EnableProvider`` then failed with
  ``ERROR_BAD_PATHNAME`` (``0x800700A1``) and the monitor exited 4 about six
  seconds into every run, leaving the API Calls tab with two entries.
* **S17-D71.** ``injection_monitor.ps1`` registered
  ``$kernelParser.add_VirtualMemVirtualAlloc`` and ``add_VirtualMemVirtualFree``.
  ``KernelTraceEventParser`` calls them ``VirtualMemAlloc`` and
  ``VirtualMemFree``. PowerShell resolves ``add_*`` late, so nothing failed at
  load: the monitor started, reported itself healthy, enabled its kernel
  provider and then died about a second in, taking its own Kernel-Process
  fallback with it and leaving the Injections tab with one entry.

Both gates run against the **real vendored assembly**, loaded by the
**production** dependency resolver lifted verbatim out of the staged script,
under a real ``powershell.exe`` - the same approach as
:mod:`tests.sandbox.qemu.test_traceevent_provisioning_s17d50a`, whose fix made
that assembly loadable in the first place.

What each gate asserts is taken from the staged script rather than restated
here, which is what makes them gates rather than agreements:

* the session-construction expression is **extracted from** ``api_trace.ps1``
  and evaluated, and the resulting session is asked whether it is real-time;
* the event names are **extracted from** ``injection_monitor.ps1``'s
  ``$kernelParser.add_*`` registrations and each is looked up on the real
  ``KernelTraceEventParser`` type.

Neither needs an ETW session to be started, so neither needs elevation:
constructing a ``TraceEventSession`` defers ``StartTrace`` to the first
``EnableProvider``, and an event lookup is pure reflection. That is deliberate -
it is what lets the property that was actually wrong be checked without the
privileges that would make the check unrunnable here.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
from subprocess import PIPE, Popen, TimeoutExpired
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="api_trace.ps1 and injection_monitor.ps1 target Windows ETW",
)

_MONITOR_DIR_NAME: Final[str] = "monitor"
_API_TRACE_SCRIPT_NAME: Final[str] = "api_trace.ps1"
_INJECTION_MONITOR_SCRIPT_NAME: Final[str] = "injection_monitor.ps1"
_MAIN_ASSEMBLY_FILE_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

_RESOLVER_REGION_RE: Final[re.Pattern[str]] = re.compile(
    r"#region TraceEventDependencyResolver\r?\n(.*?)#endregion TraceEventDependencyResolver\r?\n",
    re.DOTALL,
)
_SESSION_CONSTRUCTION_RE: Final[re.Pattern[str]] = re.compile(
    r"\$script:Session\s*=\s*(?P<expression>\$sessionType::new\(.+?\))\s*\r?\n",
)
_KERNEL_REGISTRATION_RE: Final[re.Pattern[str]] = re.compile(r"\$kernelParser\.add_(?P<event>\w+)\(")

_SESSION_TYPE_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.Session.TraceEventSession"
_KERNEL_PARSER_TYPE_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser"
_ASSEMBLY_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.TraceEvent"

_PROBE_SESSION_NAME: Final[str] = "IntellicrackApiTraceGate"
_REAL_TIME_MARKER: Final[str] = "ISREALTIME="
_EVENT_MARKER: Final[str] = "EVENT|"
_PRESENT: Final[str] = "PRESENT"

_POWERSHELL_TIMEOUT_S: Final[float] = 120.0
_PROCESS_KILL_GRACE_S: Final[float] = 5.0

# The registrations the injection monitor makes on the kernel parser. Asserted
# non-empty before any of them is checked, so a script that stopped registering
# anything at all cannot pass this gate by having nothing to disagree with.
_MINIMUM_KERNEL_REGISTRATIONS: Final[int] = 2


class _WindowsAgentSandbox(QEMUSandbox):
    """``QEMUSandbox`` used only to stage the real Windows guest agent files."""

    async def stage_monitor_directory(self, share: Path) -> None:
        """Write the production agent, monitor scripts and ETW assemblies into ``share``.

        Args:
            share: Host directory standing in for the guest's shared folder.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()


async def _staged_monitor_dir(tmp_path: Path) -> Path:
    """Stage the production monitor directory and return it.

    Args:
        tmp_path: Directory the share is created under.

    Returns:
        Path: The staged ``monitor`` directory.
    """
    share = tmp_path / "shared"
    sandbox = _WindowsAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))
    await sandbox.stage_monitor_directory(share)
    return share / _MONITOR_DIR_NAME


def _resolver_source(script_path: Path) -> str:
    """Pull the production TraceEvent dependency resolver out of a staged script.

    Args:
        script_path: Staged copy of a monitor script.

    Returns:
        str: Literal PowerShell source of the resolver function.

    Raises:
        AssertionError: If the region markers are missing.
    """
    text = script_path.read_text(encoding="utf-8")
    match = _RESOLVER_REGION_RE.search(text)
    if match is None:
        msg = f"the TraceEventDependencyResolver region markers are gone from {script_path}"
        raise AssertionError(msg)
    return match.group(1)


def _run_powershell(script: str) -> tuple[int, str, str]:
    """Run one PowerShell script and return its outcome.

    Args:
        script: PowerShell source to run.

    Returns:
        tuple[int, str, str]: Exit status, standard output and standard error.

    Raises:
        TimeoutExpired: If PowerShell does not exit in time.
    """
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to load the vendored TraceEvent assembly")
    argv = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]
    process = Popen(argv, stdout=PIPE, stderr=PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        stdout, stderr = process.communicate(timeout=_POWERSHELL_TIMEOUT_S)
    except TimeoutExpired:
        process.kill()
        process.communicate(timeout=_PROCESS_KILL_GRACE_S)
        raise
    return process.returncode, stdout, stderr


def _assembly_preamble(monitor_dir: Path) -> list[str]:
    """Build the statements that load the vendored assembly the production way.

    Args:
        monitor_dir: Staged monitor directory holding the assemblies.

    Returns:
        list[str]: PowerShell statements ending with the assembly loaded.
    """
    return [
        "$ErrorActionPreference = 'Stop'",
        "function Write-TraceError { param([string]$Stage, [string]$Message) }",
        _resolver_source(monitor_dir / _API_TRACE_SCRIPT_NAME),
        f"Register-TraceEventDependencyResolver -AssemblyDir '{monitor_dir}'",
        f"Add-Type -LiteralPath '{monitor_dir / _MAIN_ASSEMBLY_FILE_NAME}' -ErrorAction Stop",
    ]


@pytest.mark.asyncio
class TestTheApiTraceSessionIsRealTime:
    """S17-D70: the recorder's own session expression must build a real-time session."""

    async def test_the_staged_construction_expression_yields_a_real_time_session(self, tmp_path: Path) -> None:
        """Evaluate ``api_trace.ps1``'s own session construction and ask what it built.

        A file session is what the defect produced, and it is indistinguishable
        from a working one until the first ``EnableProvider`` fails - so the
        session is interrogated directly rather than through an ETW start that
        would need privileges this suite does not have.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        monitor_dir = await _staged_monitor_dir(tmp_path)
        source = (monitor_dir / _API_TRACE_SCRIPT_NAME).read_text(encoding="utf-8")
        match = _SESSION_CONSTRUCTION_RE.search(source)
        assert match is not None, f"no '$script:Session = $sessionType::new(...)' statement remains in {_API_TRACE_SCRIPT_NAME}"
        expression = match["expression"]

        script = "\r\n".join([
            *_assembly_preamble(monitor_dir),
            f"$sessionType = [System.Type]::GetType('{_SESSION_TYPE_NAME}, {_ASSEMBLY_NAME}', $true)",
            f"$sessionName = '{_PROBE_SESSION_NAME}'",
            f"$session = {expression}",
            "try {",
            f"    [Console]::Out.WriteLine('{_REAL_TIME_MARKER}' + $session.IsRealTime)",
            "} finally {",
            "    $session.Dispose()",
            "}",
        ])
        returncode, stdout, stderr = _run_powershell(script)

        assert returncode == 0, (
            f"the staged session construction {expression!r} could not even be evaluated: stdout={stdout!r} stderr={stderr!r}"
        )
        assert f"{_REAL_TIME_MARKER}True" in stdout, (
            f"{_API_TRACE_SCRIPT_NAME} builds a session that is not real-time, so its first EnableProvider fails with "
            f"ERROR_BAD_PATHNAME and the API Calls tab stays empty (S17-D70). Expression: {expression!r}; output: {stdout!r}"
        )


@pytest.mark.asyncio
class TestTheInjectionMonitorSubscribesToRealEvents:
    """S17-D71: every kernel event the recorder registers for must exist."""

    async def test_every_registered_kernel_event_exists_on_the_parser(self, tmp_path: Path) -> None:
        """Look up each ``add_*`` registration on the real ``KernelTraceEventParser``.

        PowerShell binds ``add_*`` at call time, so a name that does not exist
        is not a load error - it kills the monitor mid-run, which is exactly
        how this survived. Reflection over the real type is what settles it.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        monitor_dir = await _staged_monitor_dir(tmp_path)
        source = (monitor_dir / _INJECTION_MONITOR_SCRIPT_NAME).read_text(encoding="utf-8")
        registered = sorted({match["event"] for match in _KERNEL_REGISTRATION_RE.finditer(source)})

        assert len(registered) >= _MINIMUM_KERNEL_REGISTRATIONS, (
            f"{_INJECTION_MONITOR_SCRIPT_NAME} registers {registered!r} on the kernel parser; a monitor that subscribes to "
            f"nothing cannot report an injection, and would pass an existence check vacuously"
        )

        names = ", ".join(f"'{name}'" for name in registered)
        script = "\r\n".join([
            *_assembly_preamble(monitor_dir),
            f"$parserType = [System.Type]::GetType('{_KERNEL_PARSER_TYPE_NAME}, {_ASSEMBLY_NAME}', $true)",
            f"foreach ($name in @({names})) {{",
            "    $declared = $parserType.GetEvent($name)",
            f"    $state = if ($null -eq $declared) {{ 'ABSENT' }} else {{ '{_PRESENT}' }}",
            f"    [Console]::Out.WriteLine('{_EVENT_MARKER}' + $name + '|' + $state)",
            "}",
        ])
        returncode, stdout, stderr = _run_powershell(script)

        assert returncode == 0, f"the kernel parser could not be reflected on: stdout={stdout!r} stderr={stderr!r}"

        reported = dict(
            line.removeprefix(_EVENT_MARKER).split("|", 1)
            for line in stdout.replace("\r\n", "\n").split("\n")
            if line.startswith(_EVENT_MARKER)
        )
        assert set(reported) == set(registered), f"the probe reported on {sorted(reported)!r} rather than the registered {registered!r}"
        absent = sorted(name for name, state in reported.items() if state != _PRESENT)
        assert not absent, (
            f"{_INJECTION_MONITOR_SCRIPT_NAME} registers for {absent!r}, which KernelTraceEventParser does not declare; "
            f"PowerShell binds add_* late, so the monitor dies on that line mid-run and the Injections tab stays empty (S17-D71)"
        )
