# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D50(a): the vendored ETW assemblies must reach the guest.

Measured live: neither ``api_trace.ps1`` nor ``injection_monitor.ps1`` ever
found ``Microsoft.Diagnostics.Tracing.TraceEvent.dll``, because nothing ever
placed it inside the guest. ``api_trace.lifecycle.log`` recorded
``stopped|exit_code=2`` 0.6 seconds after ``started``, and
``injection_monitor.log`` held a single ``ERROR|TraceEvent.dll not found``
row - the assemblies were vendored at ``vendor/traceevent/`` but never
staged, so both scripts' own directory search (``$PSScriptRoot``, the first
place either script looks after an unset environment variable) never found
them.

These gates never restate what the fix should do. They drive the real
:meth:`QEMUSandbox._create_guest_agent_script` to stage a real guest monitor
directory exactly as a booting guest would receive it, then launch the real
bundled ``api_trace.ps1`` and ``injection_monitor.ps1`` under a real
``powershell.exe`` against that staged directory - the same scripts, the
same search order, the same failure text the live run produced. If the
assemblies are not actually staged where either script looks, this test
observes the same "not found" text and diagnostic category the live run did.

A real run against a full Windows PowerShell 5.1 (Desktop CLR) surfaced a
second, distinct problem once discovery itself was fixed: ``Add-Type``
eagerly enumerates every type in ``Microsoft.Diagnostics.Tracing.TraceEvent.dll``
to register PowerShell type accelerators, and that enumeration throws a
``ReflectionTypeLoadException`` naming ``System.Memory``,
``System.Text.Json``, and ``System.Reflection.Metadata`` as assemblies it
cannot find - none of which are part of ``vendor/traceevent/`` or of the
Desktop CLR's GAC on any Windows version, because they are exclusively
NuGet-distributed .NET Standard 2.0 support-pack assemblies. Completing that
would mean vendoring several more files, which is outside this fix's
read-only ``vendor/traceevent/**`` allowance and its "do not download
anything" constraint. The gates below therefore verify precisely what
S17-D50(a) claims - that discovery no longer fails - and
``TestKnownResidualLoadGap`` pins the distinct, still-open load failure as an
``xfail`` so a future change that vendors the missing facades turns it into a
loud regression rather than a silent one.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import TRACE_EVENT_ASSEMBLY_FILES, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="api_trace.ps1 and injection_monitor.ps1 target Windows ETW",
)

_MONITOR_DIR_NAME: Final[str] = "monitor"
_LOGS_DIR_NAME: Final[str] = "logs"
_API_TRACE_SCRIPT_NAME: Final[str] = "api_trace.ps1"
_INJECTION_MONITOR_SCRIPT_NAME: Final[str] = "injection_monitor.ps1"
_KERNEL_TRACE_CONTROL_REL_PATH: Final[str] = "amd64/KernelTraceControl.dll"

_POLL_S: Final[float] = 0.5
_API_TRACE_EXIT_WAIT_S: Final[float] = 40.0
_INJECTION_MONITOR_STARTED_WAIT_S: Final[float] = 30.0
_PROCESS_KILL_GRACE_S: Final[float] = 5.0
_API_TRACE_DURATION_SECONDS: Final[str] = "5"

_ERR_UNAVAILABLE_TEXT: Final[str] = "TraceEvent.dll not found"
_DIAG_CATEGORY_DLL_MISSING: Final[str] = "traceevent_dll_missing"
_API_TRACE_UNAVAILABLE_EXIT_CODE: Final[int] = 2
_STOPPED_EXIT_CODE_RE: Final[re.Pattern[str]] = re.compile(r"\|stopped\|exit_code=(-?\d+)")
_ADD_TYPE_TIMEOUT_S: Final[float] = 60.0


class _WindowsAgentSandbox(QEMUSandbox):
    """``QEMUSandbox`` used only to stage the real Windows guest agent files."""

    async def stage_monitor_directory(self, share: Path) -> None:
        """Write the production agent, bundled monitor scripts, and ETW assemblies into ``share``.

        Args:
            share: Host directory standing in for the guest's shared folder.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()


def _make_windows_agent_sandbox() -> _WindowsAgentSandbox:
    """Build a Windows-guest sandbox for staging the monitor directory.

    Returns:
        _WindowsAgentSandbox: Sandbox ready to stage the monitor directory.
    """
    return _WindowsAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))


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


def _read_text_if_present(path: Path) -> str:
    """Read a file's text, tolerating that it may not exist yet.

    Args:
        path: File to read.

    Returns:
        str: File contents, or the empty string if the file does not exist.
    """
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


async def _run_and_wait_for_exit(argv: list[str], timeout_s: float) -> tuple[str, str]:
    """Launch a monitor script and wait for it to exit on its own.

    Args:
        argv: Full ``powershell.exe`` command line.
        timeout_s: Maximum time to wait before terminating the process.

    Returns:
        tuple[str, str]: Captured ``(stdout, stderr)``.
    """
    proc = Popen(argv, stdout=PIPE, stderr=PIPE, text=True, encoding="utf-8", errors="replace")
    try:
        deadline = time.monotonic() + timeout_s
        while True:
            if proc.poll() is not None:
                break
            if time.monotonic() >= deadline:
                break
            await asyncio.sleep(_POLL_S)
    finally:
        stdout, stderr = _terminate(proc)
    return stdout, stderr


class TestTraceEventAssembliesAreVendored:
    """The assemblies the fix stages must actually be shipped in the checkout."""

    def test_every_named_assembly_exists_on_disk(self) -> None:
        """Every path named in ``TRACE_EVENT_ASSEMBLY_FILES`` must resolve to a real file."""
        vendor_dir = QEMUSandbox.traceevent_assemblies_dir()
        for rel_path in TRACE_EVENT_ASSEMBLY_FILES:
            assembly_path = vendor_dir / rel_path
            assert assembly_path.is_file(), f"{rel_path} is listed in TRACE_EVENT_ASSEMBLY_FILES but missing from {vendor_dir}"


class TestTraceEventAssembliesAreStagedIntoTheGuestMonitorDirectory:
    """The vendored assemblies must be a real member of the staged bundle."""

    @pytest.mark.asyncio
    async def test_every_named_assembly_is_staged_byte_identical(self, tmp_path: Path) -> None:
        """``_create_guest_agent_script`` must copy the real files into the share.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "shared"
        sandbox = _make_windows_agent_sandbox()
        await sandbox.stage_monitor_directory(share)

        vendor_dir = QEMUSandbox.traceevent_assemblies_dir()
        for rel_path in TRACE_EVENT_ASSEMBLY_FILES:
            staged = share / _MONITOR_DIR_NAME / rel_path
            assert staged.is_file(), f"{rel_path} was never staged into the guest monitor directory at {staged}"
            source_bytes = (vendor_dir / rel_path).read_bytes()
            assert staged.read_bytes() == source_bytes, f"the staged bytes for {rel_path} differ from the vendored source"

    @pytest.mark.asyncio
    async def test_kernel_trace_control_keeps_its_amd64_subdirectory(self, tmp_path: Path) -> None:
        r"""``KernelTraceControl.dll`` must land under ``amd64\`` beside ``TraceEvent.dll``.

        TraceEvent resolves this native dependency relative to its own
        assembly directory by processor architecture - the same layout the
        NuGet package ships it in - so staging it flat beside the managed
        assemblies would leave it unfound.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "shared"
        sandbox = _make_windows_agent_sandbox()
        await sandbox.stage_monitor_directory(share)

        staged = share / _MONITOR_DIR_NAME / _KERNEL_TRACE_CONTROL_REL_PATH
        assert staged.is_file(), f"KernelTraceControl.dll was not staged under its amd64 subdirectory at {staged}"
        assert staged.parent.name == "amd64", f"KernelTraceControl.dll's staged parent directory is {staged.parent.name!r}, not 'amd64'"


@pytest.mark.asyncio
class TestARealApiTraceRecorderLoadsTraceEvent:
    """The end-to-end path the live defect broke: staged assembly to a loaded session."""

    async def test_api_trace_no_longer_reports_the_dll_as_unavailable(self, tmp_path: Path) -> None:
        """A real, staged ``api_trace.ps1`` run must get past assembly discovery.

        This drives the whole S17-D50(a) path for ``api_trace.ps1``: the
        bundled script and the vendored assemblies are staged by production
        code, and the script is launched under the real ``powershell.exe`` a
        guest would run it under with a bounded ``-DurationSeconds`` so it
        exits on its own. A pass here means the recorder's own lifecycle log
        shows it starting, and neither its exit code nor its data log carry
        the "unavailable" (exit code 2) assembly-*discovery* failure the live
        run measured - the specific defect S17-D50(a) fixes. A distinct,
        already-tracked *load-time* failure (exit code 3) remains open past
        discovery; :class:`TestKnownResidualLoadGap` pins it separately so it
        is not silently reasserted here.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run api_trace.ps1")

        share = tmp_path / "shared"
        stage_sandbox = _make_windows_agent_sandbox()
        await stage_sandbox.stage_monitor_directory(share)

        logs_dir = share / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)
        lifecycle_path = logs_dir / "api_trace.lifecycle.log"

        argv = [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(share / _MONITOR_DIR_NAME / _API_TRACE_SCRIPT_NAME),
            "-LogDir",
            str(logs_dir),
            "-DurationSeconds",
            _API_TRACE_DURATION_SECONDS,
        ]
        stdout, stderr = await _run_and_wait_for_exit(argv, _API_TRACE_EXIT_WAIT_S)

        assert lifecycle_path.is_file(), f"api_trace.ps1 never wrote its lifecycle log; stdout={stdout!r} stderr={stderr!r}"
        lifecycle_text = lifecycle_path.read_text(encoding="utf-8", errors="replace")
        assert "|started|" in lifecycle_text, f"api_trace.ps1 never recorded starting: {lifecycle_text!r}"

        log_text = _read_text_if_present(logs_dir / "api_trace.log")
        assert _ERR_UNAVAILABLE_TEXT not in log_text, (
            f"api_trace.ps1 still could not find its TraceEvent assembly after staging: {log_text!r}"
        )

        stop_match = _STOPPED_EXIT_CODE_RE.search(lifecycle_text)
        if stop_match is not None:
            exit_code = int(stop_match.group(1))
            assert exit_code != _API_TRACE_UNAVAILABLE_EXIT_CODE, (
                f"api_trace.ps1 still could not discover its TraceEvent assembly after staging "
                f"(exit code {_API_TRACE_UNAVAILABLE_EXIT_CODE} is the discovery-failure code S17-D50(a) targets): "
                f"{lifecycle_text!r}"
            )


@pytest.mark.asyncio
class TestARealInjectionMonitorRecorderLoadsTraceEvent:
    """The end-to-end path the live defect broke: staged assembly to a loaded session."""

    async def test_injection_monitor_no_longer_reports_the_dll_as_missing(self, tmp_path: Path) -> None:
        """A real, staged ``injection_monitor.ps1`` run must get past assembly discovery.

        The live defect measured a ``traceevent_dll_missing`` diagnostic
        category and an ``ERROR|...|TraceEvent.dll not found`` data row,
        because ``Find`` never located the assembly at all. With the
        assembly staged, ``injection_monitor.ps1`` locates it -
        :meth:`Add-Type` is reached, so the diagnostic category and data-row
        text both move from "missing" to "load failed" - proving discovery
        itself, the specific defect S17-D50(a) fixes, no longer fails.

        ``injection_monitor.ps1`` still never reaches its own ``started``
        lifecycle line even after this fix: unlike ``api_trace.ps1``, its
        assembly-discovery block runs before that line is written and
        outside any enclosing ``try``/``finally``, so the distinct,
        already-tracked load-time failure :class:`TestKnownResidualLoadGap`
        pins (below) still terminates the script before it gets there. That
        is not a silent gap: :func:`intellicrack.sandbox.log_parsers.parse_collector_lifecycle`
        reports an absent lifecycle log as a "never reported starting"
        outage rather than as a healthy, silent recorder, which is exactly
        what S17-D50(b) verifies in ``test_collector_outage_reporting_s17d50b.py``.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run injection_monitor.ps1")

        share = tmp_path / "shared"
        stage_sandbox = _make_windows_agent_sandbox()
        await stage_sandbox.stage_monitor_directory(share)

        logs_dir = share / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)
        data_log_path = logs_dir / "injection_monitor.log"
        diag_path = logs_dir / "injection_monitor.diag.log"

        argv = [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(share / _MONITOR_DIR_NAME / _INJECTION_MONITOR_SCRIPT_NAME),
            "-LogDir",
            str(logs_dir),
        ]
        stdout, stderr = await _run_and_wait_for_exit(argv, _INJECTION_MONITOR_STARTED_WAIT_S)

        diag_text = _read_text_if_present(diag_path)
        assert _DIAG_CATEGORY_DLL_MISSING not in diag_text, (
            f"injection_monitor.ps1 still could not find its TraceEvent assembly after staging: "
            f"diag={diag_text!r} stdout={stdout!r} stderr={stderr!r}"
        )

        data_text = _read_text_if_present(data_log_path)
        assert _ERR_UNAVAILABLE_TEXT not in data_text, (
            f"injection_monitor.ps1's data log still carries the discovery-failure text after staging: {data_text!r}"
        )


@pytest.mark.asyncio
class TestKnownResidualLoadGap:
    """S17-D50(a) resolves assembly *discovery*; a distinct load-time gap remains open.

    Both recorder scripts reach ``Add-Type -LiteralPath <staged assembly>``
    once the assembly is staged. Under the Desktop CLR (Windows PowerShell
    5.1, the interpreter both scripts are written for), ``Add-Type`` eagerly
    walks every type in the loaded assembly to register PowerShell type
    accelerators, and that walk throws a ``ReflectionTypeLoadException``
    naming ``System.Memory``, ``System.Text.Json``, and
    ``System.Reflection.Metadata`` as dependencies it cannot find. These are
    .NET Standard 2.0 support-pack facades distributed as their own separate
    NuGet packages - they are not part of ``vendor/traceevent/`` (see its
    ``PROVENANCE.md``) and are not present in the Desktop CLR's GAC on any
    Windows version. Closing this gap means vendoring more files, which is
    outside this fix's read-only ``vendor/traceevent/**`` allowance and its
    "do not download anything" constraint.

    This gate is ``xfail(strict=True)``: it pins the exact failure so a
    future change that vendors the missing facades turns an unexpected pass
    here into a hard failure demanding this test (and the two tests above
    that document the same gap) be updated, rather than the completed fix
    going unnoticed.
    """

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "System.Memory, System.Text.Json, and System.Reflection.Metadata are not vendored; "
            "Add-Type cannot yet fully load TraceEvent under the Desktop CLR"
        ),
    )
    async def test_add_type_loads_the_vendored_assembly_without_a_reflection_type_load_exception(self, tmp_path: Path) -> None:
        """Pin the residual ``Add-Type`` failure against the real staged assembly.

        Args:
            tmp_path: pytest-provided temporary directory fixture.

        Raises:
            TimeoutExpired: If ``powershell.exe`` does not exit within
                :data:`_ADD_TYPE_TIMEOUT_S` seconds.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run Add-Type against the vendored assembly")

        share = tmp_path / "shared"
        stage_sandbox = _make_windows_agent_sandbox()
        await stage_sandbox.stage_monitor_directory(share)
        dll = share / _MONITOR_DIR_NAME / "Microsoft.Diagnostics.Tracing.TraceEvent.dll"

        script = f"$ErrorActionPreference = 'Stop'; Add-Type -LiteralPath '{dll}' -ErrorAction Stop"
        argv = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]
        proc = Popen(argv, stdout=PIPE, stderr=PIPE, text=True, encoding="utf-8", errors="replace")
        try:
            stdout, stderr = proc.communicate(timeout=_ADD_TYPE_TIMEOUT_S)
        except TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=_PROCESS_KILL_GRACE_S)
            raise

        assert proc.returncode == 0, f"Add-Type failed against the vendored assembly: stdout={stdout!r} stderr={stderr!r}"
