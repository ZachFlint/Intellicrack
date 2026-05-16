# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0021: minidump must target the analysis PID.

Pre-fix, :meth:`WindowsSandbox.dump_memory` ran a PowerShell snippet that
invoked ``MiniDumpWriteDump`` with ``GetCurrentProcess()``. That dumps the
PowerShell host that the dispatcher spawned, *not* the analysis target — so
every dump produced was an empty (from the analyst's perspective) PowerShell
snapshot rather than the binary under inspection.

The fix:

* threads a required ``target_pid`` argument through the public
  :meth:`WindowsSandbox.dump_memory` API,
* injects that PID into the in-guest PowerShell script,
* calls ``OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)``
  and passes the returned handle (not ``GetCurrentProcess``) to
  ``MiniDumpWriteDump``,
* closes the handle in the PowerShell ``finally`` block so handles never leak
  on the success or failure path,
* exposes the same surface through :meth:`intellicrack.bridges.sandbox_bridge.SandboxBridge.memory_dump`
  with a ``target_pid`` argument that is required for Windows Sandbox
  instances and ignored for QEMU.

The tests below assert each of those properties by replacing
``WindowsSandbox.run_command`` with a recording fake so we never have to
launch a real sandbox.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable


class _RecordingSandbox(WindowsSandbox):
    """WindowsSandbox subclass with a recording ``run_command``.

    Replaces :meth:`WindowsSandbox.run_command` so tests can drive
    :meth:`WindowsSandbox.dump_memory` without launching a real sandbox.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the recording sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self.commands: list[str] = []
        self._handler: Callable[[str], tuple[int, str, str]] | None = None

    def install_shared_folder(self, path: Path) -> None:
        """Pre-populate the shared folder pointer for tests.

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

    def set_handler(self, handler: Callable[[str], tuple[int, str, str]]) -> None:
        """Install a dispatch handler for canned responses.

        Args:
            handler: Callable mapping a command string to
                ``(exit_code, stdout, stderr)``.
        """
        self._handler = handler

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Record ``command`` and dispatch to the installed handler.

        Args:
            command: Command sent to the sandbox dispatcher.
            time_limit: Ignored.
            working_directory: Ignored.

        Returns:
            tuple[int, str, str]: Canned ``(exit_code, stdout, stderr)``.
        """
        del time_limit, working_directory
        self.commands.append(command)
        if self._handler is None:
            return (0, "", "")
        return self._handler(command)


def _make_recording_sandbox(tmp_path: Path) -> _RecordingSandbox:
    """Build a recording sandbox set to ``running`` with a shared folder.

    Args:
        tmp_path: Pytest temporary directory to use as the shared folder.

    Returns:
        _RecordingSandbox: Ready-to-use sandbox with status ``running``.
    """
    sb = _RecordingSandbox(config=SandboxConfig())
    shared = tmp_path / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    sb.install_shared_folder(shared)
    sb.state.status = "running"
    return sb


def _real_minidump_bytes(pid: int) -> bytes:
    """Produce a minidump-shaped byte buffer carrying a PID-embedded marker.

    The byte sequence opens with the real ``MDMP`` magic followed by a
    little-endian ``ProcessId`` field at offset 0x20. Tests can decode the PID
    from the produced file without depending on dbghelp.

    Args:
        pid: PID to embed.

    Returns:
        bytes: Synthetic minidump-shaped buffer of length 64 bytes.
    """
    header = bytearray(b"MDMP" + b"\xa7\x93" + b"\x00\x00")
    header.extend(b"\x00" * 24)
    header.extend(pid.to_bytes(4, "little"))
    header.extend(b"\x00" * (64 - len(header)))
    return bytes(header)


class TestF0021DumpMemoryRequiresTargetPid:
    """F-0021: ``dump_memory`` must reject calls without ``target_pid``."""

    def test_missing_target_pid_raises_sandbox_error(self, tmp_path: Path) -> None:
        """Calling ``dump_memory`` without ``target_pid`` raises ``SandboxError``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory())
        assert "target_pid" in str(exc.value)
        assert not sb.commands, "no commands should be dispatched before target_pid validation"

    def test_zero_target_pid_raises(self, tmp_path: Path) -> None:
        """``target_pid`` must be a positive integer; zero is rejected.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError):
            asyncio.run(sb.dump_memory(target_pid=0))

    def test_negative_target_pid_raises(self, tmp_path: Path) -> None:
        """A negative ``target_pid`` is rejected before any dispatch.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError):
            asyncio.run(sb.dump_memory(target_pid=-1))


class TestF0021DumpMemoryUsesOpenProcessAndTargetPid:
    """F-0021: dispatched PowerShell must use ``OpenProcess`` against ``target_pid``."""

    def test_powershell_script_uses_openprocess_not_getcurrentprocess(self, tmp_path: Path) -> None:
        """The generated script must call ``OpenProcess`` and avoid ``GetCurrentProcess``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 4242

        captured_dump_path: dict[str, str] = {}

        def handler(cmd: str) -> tuple[int, str, str]:
            """Materialise the dump file referenced in the script.

            Args:
                cmd: Dispatched PowerShell command.

            Returns:
                tuple[int, str, str]: ``(0, "", "")``.
            """
            match = re.search(r"::Create\('([^']+)'\)", cmd)
            if match:
                captured_dump_path["path"] = match.group(1)
                shared = sb.get_shared_folder()
                assert shared is not None
                filename = PureWindowsPath(match.group(1)).name
                dump_file = shared / "output" / filename
                dump_file.write_bytes(_real_minidump_bytes(target_pid))
            return (0, "", "")

        sb.set_handler(handler)

        out_path = tmp_path / "out.dmp"
        result = asyncio.run(sb.dump_memory(output_path=out_path, target_pid=target_pid))

        assert sb.commands, "expected at least one dispatched command"
        dispatched = sb.commands[0]
        assert "OpenProcess" in dispatched, f"OpenProcess missing from dispatched script: {dispatched!r}"
        assert "GetCurrentProcess()" not in dispatched, "GetCurrentProcess is the F-0021 bug pattern and must not appear"
        assert f"$targetPid = {target_pid}" in dispatched, "target_pid not embedded into PowerShell script"
        assert "CloseHandle" in dispatched, "process handle must be closed in finally"
        assert "finally" in dispatched, "PowerShell finally block missing"

        assert result == out_path
        assert out_path.read_bytes().startswith(b"MDMP")

    def test_dump_filename_embeds_target_pid(self, tmp_path: Path) -> None:
        """The generated dump filename embeds the target PID for traceability.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 13371

        def handler(cmd: str) -> tuple[int, str, str]:
            """Materialise the dump file referenced in the script.

            Args:
                cmd: Dispatched PowerShell command.

            Returns:
                tuple[int, str, str]: ``(0, "", "")``.
            """
            match = re.search(r"::Create\('([^']+)'\)", cmd)
            if match:
                shared = sb.get_shared_folder()
                assert shared is not None
                filename = PureWindowsPath(match.group(1)).name
                (shared / "output" / filename).write_bytes(_real_minidump_bytes(target_pid))
            return (0, "", "")

        sb.set_handler(handler)
        result = asyncio.run(sb.dump_memory(target_pid=target_pid))
        assert f"pid{target_pid}" in result.name


class TestF0021DumpMemoryProducesPIDMatchingMinidump:
    """F-0021: the resulting minidump must carry the target PID, not the host PID."""

    def test_minidump_pid_matches_target_not_powershell_host(self, tmp_path: Path) -> None:
        """The minidump's embedded PID matches ``target_pid``, not the dispatcher host PID.

        The recording handler materialises a minidump-shaped buffer whose
        ``ProcessId`` field at offset 0x20 reflects whichever PID the
        production code embedded into the PowerShell script. A successful
        fix means the script reads ``$targetPid`` and the handler embeds it;
        the pre-fix bug would have embedded the PowerShell host PID instead.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 9911
        powershell_host_pid = 9999

        embedded: dict[str, int] = {}

        def handler(cmd: str) -> tuple[int, str, str]:
            """Embed whichever PID the dispatched script identifies as the target.

            Args:
                cmd: Dispatched PowerShell command.

            Returns:
                tuple[int, str, str]: ``(0, "", "")``.
            """
            pid_for_dump: int
            match_target = re.search(r"\$targetPid = (\d+);", cmd)
            if match_target and "OpenProcess" in cmd and "GetCurrentProcess()" not in cmd:
                pid_for_dump = int(match_target.group(1))
            else:
                pid_for_dump = powershell_host_pid

            embedded["pid"] = pid_for_dump

            match_path = re.search(r"::Create\('([^']+)'\)", cmd)
            if match_path:
                shared = sb.get_shared_folder()
                assert shared is not None
                filename = PureWindowsPath(match_path.group(1)).name
                (shared / "output" / filename).write_bytes(_real_minidump_bytes(pid_for_dump))
            return (0, "", "")

        sb.set_handler(handler)
        result = asyncio.run(sb.dump_memory(target_pid=target_pid))

        dump_bytes = result.read_bytes()
        assert dump_bytes.startswith(b"MDMP")
        embedded_pid = int.from_bytes(dump_bytes[0x20:0x24], "little")
        assert embedded_pid == target_pid, f"minidump embedded PID {embedded_pid} != target {target_pid}; pre-fix would yield host PID"
        assert embedded["pid"] == target_pid, "production script must drive the dump with target_pid, not the PowerShell host PID"
        assert embedded["pid"] != powershell_host_pid


class TestF0021BridgeRequiresTargetPidForWindows:
    """F-0021: bridge ``memory_dump`` requires ``target_pid`` for Windows instances."""

    def test_bridge_rejects_windows_call_without_target_pid(self) -> None:
        """SandboxBridge.memory_dump refuses Windows calls missing ``target_pid``."""
        bridge = SandboxBridge()

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "windows"

        async def run() -> None:
            """Patch the manager and assert ToolError on missing target_pid."""
            with patch.object(bridge, "ensure_manager") as mock_ensure:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_ensure.return_value = manager
                with pytest.raises(ToolError) as exc:
                    await bridge.memory_dump("some-id")
                assert "target_pid" in str(exc.value)

        asyncio.run(run())

    def test_bridge_threads_target_pid_into_sandbox_call(self) -> None:
        """SandboxBridge.memory_dump forwards target_pid into the sandbox call."""
        bridge = SandboxBridge()

        captured_kwargs: dict[str, int | None] = {}
        dump_calls = AsyncMock(return_value=Path("X:/dummy.dmp"))

        def record(*args: object, **kwargs: object) -> Path:
            """Record the kwargs ``target_pid`` passed into the sandbox method.

            Args:
                *args: Ignored positional arguments.
                **kwargs: Captured keyword arguments.

            Returns:
                Path: Sentinel path used by the AsyncMock return value.
            """
            del args
            target_pid_value = kwargs.get("target_pid")
            captured_kwargs["target_pid"] = int(target_pid_value) if isinstance(target_pid_value, int) else None
            return Path("X:/dummy.dmp")

        dump_calls.side_effect = record

        mock_instance = MagicMock()
        mock_instance.sandbox_type = "windows"
        mock_instance.sandbox = MagicMock()
        mock_instance.sandbox.dump_memory = dump_calls

        async def run() -> None:
            """Patch the manager and confirm target_pid propagation."""
            with patch.object(bridge, "ensure_manager") as mock_ensure:
                manager = AsyncMock()
                manager.get = AsyncMock(return_value=mock_instance)
                mock_ensure.return_value = manager
                result = await bridge.memory_dump("some-id", target_pid=7777)
                assert result["target_pid"] == 7777

        asyncio.run(run())
        assert captured_kwargs["target_pid"] == 7777
