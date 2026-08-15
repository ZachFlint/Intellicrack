# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""S18-D11: dll_monitor.ps1 must actually load TraceEvent before probing for it.

``Test-TraceEventAvailable`` asked ``[System.Type]::GetType`` whether the
TraceEvent session type resolved. ``GetType`` only ever finds a type in an
assembly that is *already* loaded, and the script - unlike its two siblings -
never loaded one: no search roots, no ``AssemblyResolve`` handler, no
``Add-Type``. In a fresh PowerShell the probe therefore answered "no" every
single time, so the whole realtime-ETW branch was unreachable and every DLL
Loads row came from the ``Win32_ModuleLoadTrace`` WMI fallback instead - which
is why each one carried image base ``0x0``. Measured live in the guest:

    ...|etw_unavailable_falling_back_to_wmi|TraceEvent.dll not loaded

The gate lifts the loader out of the real ``dll_monitor.ps1`` and runs it under
a real PowerShell against the real vendored assembly, so what is proven is that
the script's own bytes resolve the type - not that a restatement of them would.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import run
from intellicrack.sandbox.qemu import enumerate_traceevent_assembly_files
from tests.sandbox.monitors.powershell_lift import lift_function


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "dll_monitor.ps1"
_VENDOR: Final[Path] = _REPO_ROOT / "vendor" / "traceevent"
_ASSEMBLY: Final[str] = "Microsoft.Diagnostics.Tracing.TraceEvent.dll"
_TYPE_NAME: Final[str] = "Microsoft.Diagnostics.Tracing.Session.TraceEventSession, Microsoft.Diagnostics.Tracing.TraceEvent"
_LOADER_FUNCTIONS: Final[tuple[str, ...]] = ("Register-TraceEventDependencyResolver", "Import-TraceEventAssembly")
# Lifted together so the harness can call the collector's own decision function
# rather than the loader directly: that is what proves the load is actually
# reached on the path that chooses between realtime ETW and the WMI fallback.
_PROBE_FUNCTION: Final[str] = "Test-TraceEventAvailable"
_POWERSHELL_TIMEOUT_S: Final[float] = 180.0


def _stage_assembly(tmp_path: Path) -> Path:
    """Stage exactly what the guest is given, using production's own enumerator.

    TraceEvent 3.2.5 ships no net4x build, so it only loads once the whole
    .NET Standard 2.0 support-pack closure sits beside it - including
    ``KernelTraceControl.dll`` under its ``amd64`` subdirectory. Staging a
    hand-picked subset here would make the loader fail for a reason of the
    harness's own making, so the file list comes from the same function that
    stages the guest.

    Args:
        tmp_path: Directory the test may write to.

    Returns:
        Path: Directory holding the staged assemblies.
    """
    staged = tmp_path / "traceevent"
    staged.mkdir()
    for relative in enumerate_traceevent_assembly_files(_VENDOR):
        destination = staged / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_VENDOR / relative, destination)
    return staged


def _run_loader(tmp_path: Path, script_text: str) -> str:
    """Run the lifted loader under a real PowerShell and report the outcome.

    Args:
        tmp_path: Directory the test may write to.
        script_text: Text of ``dll_monitor.ps1`` to lift the loader from.

    Returns:
        str: The harness's stdout, holding the AVAILABLE and RESOLVED verdicts.
    """
    assert (_VENDOR / _ASSEMBLY).is_file(), f"the vendored assembly is missing: {_VENDOR / _ASSEMBLY}"
    staged = _stage_assembly(tmp_path)
    diag = tmp_path / "diag.log"

    lifted = [lift_function(script_text, name) for name in (*_LOADER_FUNCTIONS, _PROBE_FUNCTION)]
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:DiagPath = '{diag}'\n"
        "function Write-DllDiagnostic {\n"
        "    param([string]$Timestamp, [string]$Category, [string]$Detail)\n"
        '    Add-Content -LiteralPath $script:DiagPath -Value "$Timestamp|$Category|$Detail" -Encoding utf8\n'
        "}\n"
        + "\n".join(part for part in lifted if part)
        + "\n"
        + f"if (-not (Get-Command {_PROBE_FUNCTION} -ErrorAction SilentlyContinue)) {{\n"
        "    Write-Output 'AVAILABLE=absent'\n"
        "    Write-Output 'RESOLVED=absent'\n"
        "    exit 0\n"
        "}\n"
        f"$available = {_PROBE_FUNCTION}\n"
        'Write-Output "AVAILABLE=$available"\n'
        f"$type = [System.Type]::GetType('{_TYPE_NAME}', $false)\n"
        'Write-Output "RESOLVED=$($null -ne $type)"\n',
        encoding="utf-8",
    )

    completed = run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=_POWERSHELL_TIMEOUT_S,
        check=False,
        env={**os.environ, "TRACE_EVENT_DLL_DIR": str(staged), "USERPROFILE": str(tmp_path)},
    )
    return completed.stdout


@pytest.mark.skipif(shutil.which("powershell.exe") is None, reason="Windows PowerShell is the guest's own host")
class TestTheDllMonitorLoadsTraceEventBeforeProbingForIt:
    """The collector's ETW branch has to be reachable at all."""

    def test_the_loader_is_defined_in_the_script(self) -> None:
        """A missing loader is the defect itself, not a harness problem."""
        text = _SCRIPT.read_text(encoding="utf-8")
        missing = [name for name in _LOADER_FUNCTIONS if not lift_function(text, name)]
        assert not missing, (
            f"dll_monitor.ps1 defines no {missing}, so nothing ever loads the TraceEvent assembly "
            "and Test-TraceEventAvailable can only answer no"
        )

    def test_the_probe_reports_traceevent_available_in_a_fresh_powershell(self, tmp_path: Path) -> None:
        """The collector's own decision function chooses ETW, not the fallback."""
        stdout = _run_loader(tmp_path, _SCRIPT.read_text(encoding="utf-8"))
        assert "AVAILABLE=True" in stdout, (
            f"{_PROBE_FUNCTION} answered no in a fresh PowerShell, so dll_monitor.ps1 would take the "
            f"Win32_ModuleLoadTrace fallback and every DLL Loads row would carry image base 0x0: {stdout!r}"
        )
        assert "RESOLVED=True" in stdout, f"TraceEventSession still does not resolve after the script's own probe ran: {stdout!r}"
