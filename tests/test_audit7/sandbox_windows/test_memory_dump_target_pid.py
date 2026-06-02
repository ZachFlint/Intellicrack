# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0021: minidump must target the analysis PID.

Pre-fix, :meth:`WindowsSandbox.dump_memory` ran a PowerShell snippet that
invoked ``MiniDumpWriteDump`` with ``GetCurrentProcess()``. That dumps the
PowerShell host that the dispatcher spawned, *not* the analysis target, so
every dump produced was an empty (from the analyst's perspective) PowerShell
snapshot rather than the binary under inspection.

The fix threads a required ``target_pid`` argument through
:meth:`WindowsSandbox.dump_memory`, injects it into the in-guest PowerShell
script, opens the target with
``OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)``
and passes that handle to ``MiniDumpWriteDump``, closes the handle in a
PowerShell ``finally`` block, and exposes the same surface through
:meth:`intellicrack.bridges.sandbox_bridge.SandboxBridge.memory_dump`.

These tests run the *real* PowerShell script that production emits through a
real ``powershell.exe`` interpreter against a real, owned child process, then
decode the produced minidump's ``MINIDUMP_MISC_INFO`` stream to recover the
embedded process id. The embedded id is an independent oracle written by the
Windows ``MiniDumpWriteDump`` API itself: it equals the target pid only when
the production script opens the correct process. A spy that merely pattern
matches the command string cannot prove the emitted PowerShell parses, that
``OpenProcess`` succeeds, or that the resulting dump describes the target.
"""

from __future__ import annotations

import asyncio
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Iterator


_MINIDUMP_SIGNATURE: bytes = b"MDMP"
_MISC_INFO_STREAM_TYPE: int = 15
_STREAM_DIRECTORY_ENTRY_SIZE: int = 12
_NUMBER_OF_STREAMS_OFFSET: int = 8
_STREAM_DIRECTORY_RVA_OFFSET: int = 12
_MISC_PROCESS_ID_OFFSET: int = 8

requires_windows = pytest.mark.skipif(
    sys.platform != "win32",
    reason="WindowsSandbox.dump_memory and MiniDumpWriteDump are Windows-only.",
)


def _parse_minidump_process_id(data: bytes) -> int:
    """Decode the target process id from a real minidump's MISC_INFO stream.

    Walks the ``MINIDUMP_HEADER`` stream directory, finds the
    ``MiscInfoStream`` (type 15), and reads its ``ProcessId`` field. This is
    the value Windows ``MiniDumpWriteDump`` records for the dumped process,
    independent of the production code under test.

    Args:
        data: Raw bytes of a minidump file produced by ``MiniDumpWriteDump``.

    Returns:
        int: The embedded ``ProcessId``.

    Raises:
        ValueError: If the buffer is not a minidump or carries no MISC stream.
    """
    if data[:4] != _MINIDUMP_SIGNATURE:
        msg = f"not a minidump: magic={data[:4]!r}"
        raise ValueError(msg)
    number_of_streams = struct.unpack_from("<I", data, _NUMBER_OF_STREAMS_OFFSET)[0]
    directory_rva = struct.unpack_from("<I", data, _STREAM_DIRECTORY_RVA_OFFSET)[0]
    for index in range(number_of_streams):
        entry = directory_rva + index * _STREAM_DIRECTORY_ENTRY_SIZE
        stream_type, _size, rva = struct.unpack_from("<III", data, entry)
        if stream_type == _MISC_INFO_STREAM_TYPE:
            return struct.unpack_from("<I", data, rva + _MISC_PROCESS_ID_OFFSET)[0]
    msg = "minidump carries no MISC_INFO stream"
    raise ValueError(msg)


@pytest.fixture
def live_target_process() -> Iterator[int]:
    """Spawn a real, owned child process and yield its pid for dumping.

    The current user owns the child, so the in-guest
    ``OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, ...)`` succeeds
    without elevation. The child sleeps long enough for the minidump to be
    written and is terminated on teardown.

    Yields:
        int: The pid of the live child process.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
    )
    try:
        time.sleep(0.4)
        yield child.pid
    finally:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=10)


class _RealPowerShellSandbox(WindowsSandbox):
    """WindowsSandbox whose ``run_command`` runs the real emitted script.

    Instead of replacing the operation under test with a spy, this subclass
    executes the exact PowerShell command that production constructs through
    a real ``powershell.exe`` process. The only rewrite applied is the guest
    ``Create('<guest path>')`` destination, which is remapped to the host
    shared-folder path where production then looks for the dump. The
    ``$targetPid``, ``OpenProcess`` call, ``MiniDumpWriteDump`` invocation,
    here-string, and ``finally`` block all execute verbatim.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the sandbox and the command-capture buffer.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self.commands: list[str] = []

    def install_shared_folder(self, path: Path) -> None:
        """Point the sandbox at a host directory used as the shared folder.

        Args:
            path: Directory that should be treated as the shared folder root.
        """
        self._shared_folder = path
        (path / "output").mkdir(parents=True, exist_ok=True)

    def get_shared_folder(self) -> Path | None:
        """Return the configured shared folder.

        Returns:
            Path | None: Shared folder pointer or ``None``.
        """
        return self._shared_folder

    async def yara_scan(
        self,
        rules_path: str | None = None,
        scan_target: str = "files",
    ) -> list[dict[str, object]]:
        """Skip the orthogonal post-dump memory yara scan.

        ``dump_memory`` runs a best-effort yara scan over the produced dump as
        a non-essential side step (production already wraps it in a tolerant
        ``try``/``except``). That scan is outside the F-0021 target-pid
        contract under test here, so it is neutralised to keep the gate focused
        and deterministic without touching the dump-production path.

        Args:
            rules_path: Ignored rules path.
            scan_target: Ignored scan target selector.

        Returns:
            list[dict[str, object]]: Always an empty match list.
        """
        del rules_path, scan_target
        return []

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute the production PowerShell script via real ``powershell.exe``.

        Args:
            command: Full dispatcher command (``powershell -Command "..."``).
            time_limit: Ignored.
            working_directory: Ignored.

        Returns:
            tuple[int, str, str]: Real ``(exit_code, stdout, stderr)`` from
                the spawned PowerShell process.
        """
        del time_limit, working_directory
        self.commands.append(command)

        prefix = 'powershell -Command "'
        if not command.startswith(prefix) or not command.endswith('"'):
            return (1, "", "unexpected dispatcher command shape")
        script = command[len(prefix) : -1]

        match = re.search(r"::Create\('([^']+)'\)", script)
        if match is None:
            return (1, "", "no Create('...') destination in script")
        guest_path = match.group(1)
        filename = Path(guest_path.replace("\\", "/")).name
        shared = self._shared_folder
        if shared is None:
            return (1, "", "shared folder not initialised")
        host_path = shared / "output" / filename
        host_script = script.replace(guest_path, str(host_path))

        completed = await asyncio.to_thread(
            subprocess.run,
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", host_script],
            capture_output=True,
            text=True,
            check=False,
        )
        return (completed.returncode, completed.stdout, completed.stderr)


def _make_real_sandbox(tmp_path: Path) -> _RealPowerShellSandbox:
    """Build a running sandbox backed by a host shared folder.

    Args:
        tmp_path: Pytest temporary directory used for the shared folder.

    Returns:
        _RealPowerShellSandbox: Ready-to-use sandbox with status ``running``.
    """
    sb = _RealPowerShellSandbox(config=SandboxConfig())
    shared = tmp_path / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    sb.install_shared_folder(shared)
    sb.state.status = "running"
    return sb


class TestF0021DumpMemoryRequiresTargetPid:
    """F-0021: ``dump_memory`` must reject calls without a valid ``target_pid``."""

    @requires_windows
    def test_missing_target_pid_raises_sandbox_error(self, tmp_path: Path) -> None:
        """Calling ``dump_memory`` without ``target_pid`` raises ``SandboxError``.

        The validation must fire before any command is dispatched so a
        host-snapshotting PowerShell run can never start.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_real_sandbox(tmp_path)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory())
        assert "target_pid" in str(exc.value)
        assert sb.commands == [], "no command may dispatch before target_pid validation"

    @requires_windows
    @pytest.mark.parametrize("bad_pid", [0, -1, -4242])
    def test_non_positive_target_pid_raises(self, tmp_path: Path, bad_pid: int) -> None:
        """A non-positive ``target_pid`` is rejected before any dispatch.

        Args:
            tmp_path: Pytest temporary directory fixture.
            bad_pid: Invalid pid value (zero or negative).
        """
        sb = _make_real_sandbox(tmp_path)
        with pytest.raises(SandboxError):
            asyncio.run(sb.dump_memory(target_pid=bad_pid))
        assert sb.commands == [], "no command may dispatch for an invalid target_pid"


class TestF0021RealPowerShellDumpTargetsTheRequestedProcess:
    """F-0021: the real emitted script dumps the requested process."""

    @requires_windows
    def test_real_minidump_embeds_target_pid_not_host_pid(
        self,
        tmp_path: Path,
        live_target_process: int,
    ) -> None:
        """The real dump's embedded ProcessId equals the requested target pid.

        Drives the unmodified production ``dump_memory`` flow: it builds the
        PowerShell script, the sandbox runs it through real ``powershell.exe``
        against a live owned process, and ``MiniDumpWriteDump`` writes a real
        minidump. Decoding the dump's MISC_INFO ``ProcessId`` (an oracle the
        OS, not the test, produced) proves the script targeted the requested
        process rather than the PowerShell host. The pre-fix
        ``GetCurrentProcess()`` code path would embed the PowerShell host pid.

        Args:
            tmp_path: Pytest temporary directory fixture.
            live_target_process: Pid of a live owned child process.
        """
        sb = _make_real_sandbox(tmp_path)
        out_path = tmp_path / "analysis.dmp"

        result = asyncio.run(sb.dump_memory(output_path=out_path, target_pid=live_target_process))

        assert result == out_path
        dispatched = sb.commands[0]
        assert "GetCurrentProcess()" not in dispatched, "GetCurrentProcess is the F-0021 bug pattern"
        assert f"$targetPid = {live_target_process}" in dispatched
        assert "OpenProcess" in dispatched
        assert "CloseHandle" in dispatched
        assert "} finally {" in dispatched

        dump_bytes = out_path.read_bytes()
        assert dump_bytes[:4] == _MINIDUMP_SIGNATURE
        embedded_pid = _parse_minidump_process_id(dump_bytes)
        assert embedded_pid == live_target_process, (
            f"minidump embedded ProcessId {embedded_pid} != requested target {live_target_process}; the script dumped the wrong process"
        )
        assert embedded_pid != os.getpid(), "the dump must describe the analysis target, not the dispatching host process"

    @requires_windows
    def test_dump_filename_embeds_target_pid_for_traceability(
        self,
        tmp_path: Path,
        live_target_process: int,
    ) -> None:
        """The produced dump path encodes the target pid for traceability.

        Args:
            tmp_path: Pytest temporary directory fixture.
            live_target_process: Pid of a live owned child process.
        """
        sb = _make_real_sandbox(tmp_path)
        result = asyncio.run(sb.dump_memory(target_pid=live_target_process))
        assert f"pid{live_target_process}" in result.name
        assert result.read_bytes()[:4] == _MINIDUMP_SIGNATURE

    @requires_windows
    def test_openprocess_failure_surfaces_as_sandbox_error(self, tmp_path: Path) -> None:
        """A pid that cannot be opened makes the real script fail loudly.

        Uses pid 4 (the Windows ``System`` process), which a non-elevated user
        cannot open for ``PROCESS_VM_READ``. The production script throws on
        the ``OpenProcess`` failure, the PowerShell exit code is non-zero, no
        dump file is written, and ``dump_memory`` surfaces a ``SandboxError``
        rather than silently returning an empty dump.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_real_sandbox(tmp_path)
        system_pid = 4
        with pytest.raises(SandboxError):
            asyncio.run(sb.dump_memory(target_pid=system_pid))
        assert sb.commands, "the script must have been dispatched before failing"
        produced = list((tmp_path / "shared" / "output").glob("*.dmp"))
        assert produced == [], "no dump file may remain when OpenProcess fails"


class TestF0021BridgeThreadsTargetPidThroughRealSandbox:
    """F-0021: the bridge requires and forwards ``target_pid`` to a real sandbox."""

    @requires_windows
    def test_bridge_rejects_windows_call_without_target_pid(self, tmp_path: Path) -> None:
        """``memory_dump`` refuses a Windows instance call missing ``target_pid``.

        Registers a real ``WindowsSandbox`` in the bridge's real manager via the
        bridge's own ``register_existing_sandbox`` API, then calls the real
        ``memory_dump`` without a pid and asserts the ``ToolError`` guard fires
        before any sandbox work begins.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_real_sandbox(tmp_path)
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> None:
            """Invoke ``memory_dump`` without a pid and expect a ``ToolError``."""
            with pytest.raises(ToolError) as exc:
                await bridge.memory_dump(instance_id)
            assert "target_pid" in str(exc.value)

        asyncio.run(run())
        assert sb.commands == [], "the bridge must reject the call before dispatching to the sandbox"

    @requires_windows
    def test_bridge_forwards_target_pid_and_produces_real_dump(
        self,
        tmp_path: Path,
        live_target_process: int,
    ) -> None:
        """The bridge forwards ``target_pid`` into a real dump of the target.

        Drives the full bridge path against a real registered sandbox that
        runs real PowerShell. The returned payload echoes the pid, and the
        produced minidump's embedded ProcessId proves the pid reached
        ``MiniDumpWriteDump`` and dumped the right process.

        Args:
            tmp_path: Pytest temporary directory fixture.
            live_target_process: Pid of a live owned child process.
        """
        bridge = SandboxBridge()
        sb = _make_real_sandbox(tmp_path)
        instance_id = bridge.register_existing_sandbox(sb, "windows")
        out_path = tmp_path / "bridge.dmp"

        async def run() -> dict[str, object]:
            """Call the bridge ``memory_dump`` with a real target pid.

            Returns:
                dict[str, object]: The bridge response payload.
            """
            return await bridge.memory_dump(
                instance_id,
                output_path=str(out_path),
                target_pid=live_target_process,
            )

        payload = asyncio.run(run())

        assert payload["target_pid"] == live_target_process
        assert payload["dump_path"] == str(out_path)
        dump_bytes = out_path.read_bytes()
        assert dump_bytes[:4] == _MINIDUMP_SIGNATURE
        assert _parse_minidump_process_id(dump_bytes) == live_target_process
