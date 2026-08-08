# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D49: the Registry Changes tab must have a source on QEMU.

Measured live: the Registry Changes tab parses ``registry_changes.log``, but
no component ever wrote a file by any name that carries registry data.
``MONITOR_SCRIPT_NAMES`` listed seven telemetry collectors staged into the
guest and none of them observed the registry, so a run in which the guest's
logs directory held seventeen files still reported zero registry entries.
The Windows Sandbox backend already solves this - it stages
``registry_monitor.ps1`` and parses ``registry_monitor.log`` - so this is a
missing port between two backends of the same application, not a design gap,
and the two backends' log filenames are converged here as part of the port.

These gates never restate what the fix should do. They import
:data:`intellicrack.sandbox.qemu.MONITOR_SCRIPT_NAMES` directly - the very
list the live run showed missing an eighth entry - and drive the real
:meth:`QEMUSandbox._create_guest_agent_script` to stage a real monitor
directory, exactly as a booting guest would receive it. The strongest gate
here then launches the real bundled ``registry_monitor.ps1`` under a real
``powershell.exe`` against the live Windows registry - creating and deleting
an actual subkey - and reads the resulting log back through the real
:meth:`QEMUSandbox._collect_monitoring_logs`, the exact path the Registry
Changes tab is populated from. If the guest never wrote the file, or wrote it
under a name the host does not read, this test observes nothing, the same way
the tab did on the live run.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
import winreg
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import MONITOR_SCRIPT_NAMES, GuestOS, QEMUConfig, QEMUSandbox


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.sandbox.base import RegistryChange


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="registry_monitor.ps1 targets the Windows registry provider",
)

_REGISTRY_SCRIPT_NAME: Final[str] = "registry_monitor.ps1"
_REGISTRY_LOG_NAME: Final[str] = "registry_monitor.log"
_MONITOR_DIR_NAME: Final[str] = "monitor"
_LOGS_DIR_NAME: Final[str] = "logs"
_MONITOR_SCRIPTS_ARRAY_RE: Final[re.Pattern[str]] = re.compile(r"\$monitorScripts\s*=\s*@\((.*?)\)", re.DOTALL)
_QUOTED_NAME_RE: Final[re.Pattern[str]] = re.compile(r"'([^']+)'")


def _bundled_script_path(name: str) -> Path:
    """Return the on-disk path of a real bundled monitor script.

    Args:
        name: File name of the bundled script.

    Returns:
        Path: Absolute path resolved the same way production locates it, via
        :meth:`QEMUSandbox.bundled_scripts_dir`, so this gate cannot drift
        from the file production actually stages into a guest.
    """
    return QEMUSandbox.bundled_scripts_dir() / name


_WATCHED_RUN_KEY: Final[str] = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_TEST_SUBKEY_NAME: Final[str] = "IntellicrackS17D49RegistryProbe"
_TEST_VALUE_NAME: Final[str] = "ProbePath"
_TEST_VALUE_DATA: Final[str] = r"C:\IntellicrackProbe\probe.exe"

_STARTUP_GRACE_S: Final[float] = 20.0
_DETECTION_TIMEOUT_S: Final[float] = 45.0
_DETECTION_POLL_S: Final[float] = 1.0
_PROCESS_KILL_GRACE_S: Final[float] = 5.0


class _WindowsAgentSandbox(QEMUSandbox):
    """``QEMUSandbox`` used only to stage the real Windows guest agent files."""

    async def stage_monitor_directory(self, share: Path) -> None:
        """Write the production agent and every bundled monitor script into ``share``.

        Args:
            share: Host directory standing in for the guest's shared folder.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIR_NAME).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()


class _ReportReadingSandbox(QEMUSandbox):
    """``QEMUSandbox`` that reads monitor logs from a chosen shared folder."""

    def use_shared_folder(self, share: Path) -> None:
        """Point the sandbox at the folder holding the guest's monitor logs.

        Args:
            share: Shared folder root.
        """
        self._shared_folder = share

    async def collect_registry_changes(self) -> list[RegistryChange]:
        """Parse the guest's registry log through the real host-side reader.

        Returns:
            list[RegistryChange]: Records the report's Registry Changes tab
            draws.
        """
        logs = await self._collect_monitoring_logs()
        return logs.registry_changes


def _make_windows_agent_sandbox() -> _WindowsAgentSandbox:
    """Build a Windows-guest sandbox for staging the monitor directory.

    Returns:
        _WindowsAgentSandbox: Sandbox ready to stage the monitor directory.
    """
    return _WindowsAgentSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))


def _make_report_reading_sandbox() -> _ReportReadingSandbox:
    """Build a sandbox for reading monitor logs back through production parsing.

    Returns:
        _ReportReadingSandbox: Sandbox ready to read a shared folder's logs.
    """
    return _ReportReadingSandbox(config=SandboxConfig(), qemu_config=QEMUConfig(guest_os=GuestOS.WINDOWS))


class TestRegistryMonitorIsWiredIntoTheAgentBundle:
    """The registry collector must be a real member of the staged bundle."""

    def test_registry_monitor_is_in_the_bundled_script_list(self) -> None:
        """The live gap - a missing eighth entry - must not recur."""
        assert _REGISTRY_SCRIPT_NAME in MONITOR_SCRIPT_NAMES, (
            f"registry_monitor.ps1 is absent from MONITOR_SCRIPT_NAMES: {MONITOR_SCRIPT_NAMES}"
        )

    def test_registry_monitor_script_exists_on_disk(self) -> None:
        """The bundled script the constant names must actually be shipped."""
        script_path = _bundled_script_path(_REGISTRY_SCRIPT_NAME)
        assert script_path.is_file(), f"registry_monitor.ps1 is listed but missing from disk at {script_path}"

    @pytest.mark.asyncio
    async def test_registry_monitor_is_staged_into_the_guest_monitor_directory(self, tmp_path: Path) -> None:
        """``_create_guest_agent_script`` must copy the real file into the share.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "shared"
        sandbox = _make_windows_agent_sandbox()
        await sandbox.stage_monitor_directory(share)

        staged = share / _MONITOR_DIR_NAME / _REGISTRY_SCRIPT_NAME
        assert staged.is_file(), f"registry_monitor.ps1 was never staged into the guest monitor directory at {staged}"

        source_bytes = _bundled_script_path(_REGISTRY_SCRIPT_NAME).read_bytes()
        assert staged.read_bytes() == source_bytes, "the staged script's bytes differ from the bundled source"

    @pytest.mark.asyncio
    async def test_the_generated_agent_launches_registry_monitor(self, tmp_path: Path) -> None:
        """The generated ``agent.ps1`` must actually start the registry collector.

        Staging the script is not enough by itself - the live defect was that
        seven collectors were launched and an eighth was never even attempted.
        This reads the real, generated ``agent.ps1`` back off disk and confirms
        its ``$monitorScripts`` array - the one the launch loop iterates - names
        every entry :data:`MONITOR_SCRIPT_NAMES` does, in particular this one.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        share = tmp_path / "shared"
        sandbox = _make_windows_agent_sandbox()
        await sandbox.stage_monitor_directory(share)

        agent_text = (share / _MONITOR_DIR_NAME / "agent.ps1").read_text(encoding="utf-8")
        array_match = _MONITOR_SCRIPTS_ARRAY_RE.search(agent_text)
        assert array_match is not None, "agent.ps1 does not declare a $monitorScripts array"

        launched = _QUOTED_NAME_RE.findall(array_match.group(1))
        assert _REGISTRY_SCRIPT_NAME in launched, f"the generated agent never launches registry_monitor.ps1; scripts launched: {launched}"
        assert set(launched) == set(MONITOR_SCRIPT_NAMES), (
            f"the generated agent's launch list has drifted from MONITOR_SCRIPT_NAMES: "
            f"launched={sorted(launched)} constant={sorted(MONITOR_SCRIPT_NAMES)}"
        )


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


def _create_probe_subkey() -> None:
    """Create the real HKCU test subkey this gate writes and watches for."""
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, f"{_WATCHED_RUN_KEY}\\{_TEST_SUBKEY_NAME}", 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, _TEST_VALUE_NAME, 0, winreg.REG_SZ, _TEST_VALUE_DATA)
    finally:
        winreg.CloseKey(key)


def _delete_probe_subkey() -> None:
    """Remove the real HKCU test subkey, tolerating it already being gone."""
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, f"{_WATCHED_RUN_KEY}\\{_TEST_SUBKEY_NAME}")
    except FileNotFoundError:
        return


def _log_names_the_probe_key(log_path: Path) -> bool:
    """Check whether the monitor's own log file already names the probe subkey.

    Args:
        log_path: Path to ``registry_monitor.log``.

    Returns:
        bool: Whether a line in the log mentions the probe subkey name.
    """
    if not log_path.is_file():
        return False
    return _TEST_SUBKEY_NAME in log_path.read_text(encoding="utf-8", errors="replace")


@pytest.mark.asyncio
class TestARealRegistryWriteReachesTheReportedChangeList:
    """The end-to-end path the live defect broke: guest write to host report."""

    async def test_a_written_registry_key_is_named_in_the_registry_changes_report(self, tmp_path: Path) -> None:
        """A key the guest writes must be named by the host's registry-changes reader.

        This drives the whole S17-D49 path for real: the bundled script is
        staged by production code, launched under the real Windows PowerShell
        that a guest would run it under, and made to observe a real registry
        write. The resulting log is then handed to the same
        :meth:`QEMUSandbox._collect_monitoring_logs` the Sandbox panel calls,
        so a pass here is exactly what "the Registry Changes section names
        that key" means.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        powershell = shutil.which("powershell")
        if powershell is None:
            pytest.skip("Windows PowerShell 5.1 (powershell.exe) is required to run registry_monitor.ps1")

        share = tmp_path / "shared"
        stage_sandbox = _make_windows_agent_sandbox()
        await stage_sandbox.stage_monitor_directory(share)

        script_path = share / _MONITOR_DIR_NAME / _REGISTRY_SCRIPT_NAME
        logs_dir = share / _LOGS_DIR_NAME
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / _REGISTRY_LOG_NAME

        _delete_probe_subkey()
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
        proc = Popen(
            argv,
            stdout=PIPE,
            stderr=PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            await asyncio.sleep(_STARTUP_GRACE_S)
            assert proc.poll() is None, "registry_monitor.ps1 exited during its baseline snapshot instead of entering its watch loop"

            _create_probe_subkey()

            deadline = time.monotonic() + _DETECTION_TIMEOUT_S
            while True:
                if _log_names_the_probe_key(log_path):
                    break
                if time.monotonic() >= deadline:
                    break
                await asyncio.sleep(_DETECTION_POLL_S)
        finally:
            stdout, stderr = _terminate(proc)
            _delete_probe_subkey()

        assert log_path.is_file(), f"registry_monitor.ps1 never created {log_path}; stdout={stdout!r} stderr={stderr!r}"
        raw_contents = log_path.read_text(encoding="utf-8", errors="replace")
        assert _TEST_SUBKEY_NAME in raw_contents, (
            f"the probe subkey never appeared in registry_monitor.log within {_DETECTION_TIMEOUT_S}s; "
            f"log contents={raw_contents!r} stdout={stdout!r} stderr={stderr!r}"
        )

        read_sandbox = _make_report_reading_sandbox()
        read_sandbox.use_shared_folder(share)
        registry_changes = await read_sandbox.collect_registry_changes()

        matching = [change for change in registry_changes if _TEST_SUBKEY_NAME in (change["key"] or "")]
        assert matching, (
            f"the probe subkey reached the log but not the parsed registry-changes report; "
            f"parsed changes={registry_changes!r} log contents={raw_contents!r}"
        )
        assert matching[0]["operation"] == "created", f"a newly written registry key was not reported as 'created': {matching[0]!r}"
        assert matching[0]["value_name"] == _TEST_VALUE_NAME, (
            f"the value name was not carried through to the report intact: {matching[0]!r}"
        )
        assert (matching[0]["key"] or "").startswith("HKCU\\"), (
            f"the report shows PowerShell's provider-qualified path instead of a hive path an analyst can act on: {matching[0]['key']!r}"
        )
