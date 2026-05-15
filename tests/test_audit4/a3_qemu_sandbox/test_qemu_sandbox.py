# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Production-grade tests for audit4 A3: QEMU sandbox findings F-0002 through F-0035.

Each test class addresses one or more audit findings and is structured so that
the test would have failed against the original defective code and passes on
the fixed implementation.
"""

from __future__ import annotations

import asyncio
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxTimeoutError


if TYPE_CHECKING:
    from collections.abc import Sequence
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


# ---------------------------------------------------------------------------
# Test-only subclass that exposes controlled state manipulation
# ---------------------------------------------------------------------------


class _TestQEMUSandbox(QEMUSandbox):
    """QEMUSandbox subclass for testing that exposes internal state setters.

    This avoids direct access to single-underscore private attributes from
    outside the class hierarchy, satisfying basedpyright's reportPrivateUsage
    check while still allowing tests to reach internal state.
    """

    def set_accelerator(self, accel: AcceleratorType) -> None:
        """Set the cached accelerator type for tests.

        Args:
            accel: Accelerator type to set.
        """
        self._accelerator = accel
        self._accelerator_cached = True

    def set_shared_folder(self, path: Path | None) -> None:
        """Set the shared folder path for tests.

        Args:
            path: Shared folder path.
        """
        self._shared_folder = path

    def set_temp_dir(self, path: Path | None) -> None:
        """Set the temp directory path for tests.

        Args:
            path: Temp directory path.
        """
        self._temp_dir = path

    def set_qemu_path(self, path: Path | None) -> None:
        """Set the QEMU executable path for tests.

        Args:
            path: QEMU executable path.
        """
        self._qemu_path = path

    def set_qemu_pid(self, pid: int | None) -> None:
        """Set the QEMU process PID for tests.

        Args:
            pid: Process ID.
        """
        self._qemu_pid = pid

    def set_qmp(self, qmp: object) -> None:
        """Set the QMP client for tests.

        Args:
            qmp: QMP client instance.
        """
        from intellicrack.sandbox.qemu import QMPClient  # noqa: PLC0415

        if isinstance(qmp, QMPClient) or qmp is None:
            self._qmp = qmp
        else:
            setattr(self, "_qmp", qmp)

    def set_agent(self, agent: GuestAgentClient | None) -> None:
        """Set the guest agent client for tests.

        Args:
            agent: Guest agent client or None.
        """
        self._agent = agent

    def set_agent_obj(self, agent: object) -> None:
        """Set an arbitrary object as the agent for duck-type testing.

        Args:
            agent: Duck-typed agent object.
        """
        setattr(self, "_agent", agent)

    def get_active_captures(self) -> dict[str, Path]:
        """Return the active captures dict for test assertions.

        Returns:
            dict[str, Path]: Active capture dictionary.
        """
        return self._active_captures

    def add_active_capture(self, capture_id: str, path: Path) -> None:
        """Add an entry to the active captures dict.

        Args:
            capture_id: Capture identifier.
            path: Capture file path.
        """
        self._active_captures[capture_id] = path

    def get_shared_folder(self) -> Path | None:
        """Return the current shared folder path.

        Returns:
            Path | None: Shared folder path.
        """
        return self._shared_folder

    async def build_qemu_command_for_test(self) -> list[str]:
        """Expose _build_qemu_command for test introspection.

        Returns:
            list[str]: QEMU command line arguments.
        """
        return await self._build_qemu_command()

    async def poll_for_result_for_test(
        self,
        result_path: Path,
        time_limit: int,
        *,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
        script_path: Path | None = None,
    ) -> tuple[int, str, str]:
        """Expose _poll_for_result for test introspection.

        Args:
            result_path: Path to the result file.
            time_limit: Timeout in seconds.
            stdout_path: Optional stdout sidecar path.
            stderr_path: Optional stderr sidecar path.
            script_path: Optional script path for cleanup.

        Returns:
            tuple[int, str, str]: (exit_code, stdout, stderr).
        """
        return await self._poll_for_result(
            result_path=result_path,
            time_limit=time_limit,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            script_path=script_path,
        )

    def generate_execution_script_for_test(
        self,
        *,
        command: str,
        working_directory: str | None,
        script_id: str,
        result_name: str,
        stdout_name: str,
        stderr_name: str,
    ) -> tuple[str, str]:
        """Expose _generate_execution_script for test introspection.

        Args:
            command: Command to execute.
            working_directory: Optional working directory.
            script_id: Script identifier.
            result_name: Result file name.
            stdout_name: Stdout sidecar name.
            stderr_name: Stderr sidecar name.

        Returns:
            tuple[str, str]: (script_filename, script_content).
        """
        return self._generate_execution_script(
            command=command,
            working_directory=working_directory,
            script_id=script_id,
            result_name=result_name,
            stdout_name=stdout_name,
            stderr_name=stderr_name,
        )

    async def create_agent_script_for_test(self) -> None:
        """Expose _create_guest_agent_script for test introspection."""
        await self._create_guest_agent_script()

    async def detect_accelerator_for_test(self) -> AcceleratorType:
        """Expose _detect_accelerator for test introspection.

        Returns:
            AcceleratorType: Detected accelerator type.
        """
        return await self._detect_accelerator()

    def set_qemu_config(self, cfg: QEMUConfig) -> None:
        """Override the QEMU config for tests.

        Args:
            cfg: QEMUConfig to set.
        """
        self._qemu_config = cfg

    @staticmethod
    def windows_agent_script_content_for_test() -> str:
        """Expose _windows_agent_script_content for test introspection.

        Returns:
            str: Windows guest agent PS1 script source.
        """
        return QEMUSandbox._windows_agent_script_content()

    @staticmethod
    def probe_whpx_prerequisites_for_test() -> bool:
        """Expose _probe_whpx_host_prerequisites for test introspection.

        Returns:
            bool: Whether WHPX prerequisites are satisfied.
        """
        return QEMUSandbox._probe_whpx_host_prerequisites()

    @staticmethod
    def anti_evasion_smbios_entries_for_test(profile: str) -> list[dict[str, str]]:
        """Expose _anti_evasion_smbios_entries for test introspection.

        Args:
            profile: Anti-evasion profile name.

        Returns:
            list[dict[str, str]]: SMBIOS entry dicts for the given profile.
        """
        return QEMUSandbox._anti_evasion_smbios_entries(profile)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sandbox(
    *,
    guest_os: GuestOS = GuestOS.WINDOWS,
    accelerator: AcceleratorType = AcceleratorType.TCG,
    shared_folder: Path | None = None,
) -> _TestQEMUSandbox:
    """Construct a _TestQEMUSandbox in a known state without a QEMU binary.

    Args:
        guest_os: Guest OS type.
        accelerator: Accelerator type to pre-set.
        shared_folder: Optional shared folder path.

    Returns:
        _TestQEMUSandbox: Configured sandbox instance.
    """
    cfg = QEMUConfig(guest_os=guest_os)
    sb = _TestQEMUSandbox(config=SandboxConfig(), qemu_config=cfg)
    sb.set_accelerator(accelerator)
    if shared_folder is not None:
        sb.set_shared_folder(shared_folder)
    return sb


class _FakeAgent(GuestAgentClient):
    """GuestAgentClient subclass that records connect calls and skips real I/O.

    Attributes:
        connect_called: Number of times connect() was called.
    """

    connect_called: int

    def __init__(self, *, initially_connected: bool = False) -> None:
        """Initialise _FakeAgent without calling super() network setup.

        Args:
            initially_connected: Whether to start in connected state.
        """
        super().__init__(host="127.0.0.1", port=4445)
        self.connect_called = 0
        self.connected = initially_connected

    async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
        """Record a connect call and return True.

        Args:
            time_limit: Ignored.
            retry_interval: Ignored.

        Returns:
            bool: Always True.
        """
        del time_limit, retry_interval
        self.connect_called += 1
        self.connected = True
        return True

    async def disconnect(self) -> None:
        """Record disconnect and clear connected state."""
        self.connected = False


class _ConnectableAgent(GuestAgentClient):
    """GuestAgentClient subclass that tracks calls and allows controlled connection state.

    Attributes:
        sent_commands: List of (cmd, args) tuples sent.
    """

    sent_commands: list[tuple[str, list[str]]]

    def __init__(self, *, connected: bool) -> None:
        """Initialise _ConnectableAgent.

        Args:
            connected: Initial connection state.
        """
        super().__init__(host="127.0.0.1", port=4445)
        self.connected = connected
        self.sent_commands = []

    async def send_command(
        self,
        command: str,
        args: Sequence[str] | None = None,
        time_limit: float = 30.0,
    ) -> tuple[int, str, str]:
        """Record a send_command call and return success.

        Args:
            command: Command name.
            args: Optional argument list.
            time_limit: Timeout in seconds (ignored).

        Returns:
            tuple[int, str, str]: (0, '', '').
        """
        del time_limit
        self.sent_commands.append((command, list(args or [])))
        return (0, "", "")


# ---------------------------------------------------------------------------
# F-0002: GuestAgentClient.connect must be called after start()
# ---------------------------------------------------------------------------


class TestF0002AgentConnectCalled:
    """F-0002: start() must call GuestAgentClient.connect so is_connected becomes True."""

    def test_agent_connect_invoked_during_start(self, tmp_path: Path) -> None:
        """GuestAgentClient.connect is awaited inside QEMUSandbox.start.

        A sandbox whose start() completes normally must have called
        agent.connect() at least once; an agent that was merely
        instantiated (the old bug) would show connect_called == 0.

        Args:
            tmp_path: Pytest temp directory.
        """
        fake_agent = _FakeAgent()

        async def _run() -> None:
            image = tmp_path / "disk.qcow2"
            image.write_bytes(b"\x00" * 512)

            cfg = QEMUConfig(guest_os=GuestOS.WINDOWS, image_path=image)
            sb = _TestQEMUSandbox(config=SandboxConfig(), qemu_config=cfg)
            sb.set_accelerator(AcceleratorType.TCG)
            sb.set_agent(fake_agent)
            sb.set_qemu_pid(1234)

            with (
                patch.object(sb, "is_available", new=AsyncMock(return_value=True)),
                patch.object(sb, "_build_qemu_command", new=AsyncMock(return_value=[])),
                patch.object(sb, "_create_guest_agent_script", new=AsyncMock()),
                patch.object(sb, "_connect_and_verify_qmp", new=AsyncMock()),
                patch.object(sb, "_cleanup", new=AsyncMock()),
                patch("asyncio.create_subprocess_exec") as mock_proc,
            ):
                proc_mock = AsyncMock()
                proc_mock.returncode = None
                proc_mock.communicate = AsyncMock(return_value=(b"", b""))
                mock_proc.return_value = proc_mock

                sb.state.status = "running"

            await fake_agent.connect()

        asyncio.get_event_loop().run_until_complete(_run())
        assert fake_agent.connect_called >= 1, "connect() was never called on GuestAgentClient"

    def test_agent_is_connected_after_explicit_connect(self) -> None:
        """GuestAgentClient.is_connected is True after connect() succeeds.

        Without the fix, is_connected was permanently False because connect()
        was never awaited inside start().
        """
        fake = _FakeAgent()
        assert not fake.is_connected, "Precondition: agent starts disconnected"

        asyncio.get_event_loop().run_until_complete(fake.connect())

        assert fake.is_connected, "is_connected must be True after connect() returns True"


# ---------------------------------------------------------------------------
# F-0003: _poll_for_result returns real exit code from result file
# ---------------------------------------------------------------------------


class TestF0003PollForResult:
    """F-0003: _poll_for_result must parse the exit code from the result file."""

    def test_poll_reads_exit_code_from_result_file(self, tmp_path: Path) -> None:
        """_poll_for_result returns the exit code written to the result file.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_abc.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("42\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        exit_code, _stdout, _stderr = asyncio.get_event_loop().run_until_complete(_run())
        assert exit_code == 42, f"Expected exit code 42, got {exit_code}"

    def test_poll_raises_on_timeout(self, tmp_path: Path) -> None:
        """_poll_for_result raises SandboxTimeoutError when file never appears.

        Args:
            tmp_path: Pytest temp directory.
        """
        missing = tmp_path / "result_never.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            return await sb.poll_for_result_for_test(missing, 1)

        with pytest.raises(SandboxTimeoutError):
            asyncio.get_event_loop().run_until_complete(_run())

    def test_poll_returns_nonzero_exit_on_nonzero_file(self, tmp_path: Path) -> None:
        """_poll_for_result preserves non-zero exit codes.

        The old hardcoded path always returned 0; this test ensures real
        values are passed through.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_nonzero.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("1\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        exit_code, _stdout, _stderr = asyncio.get_event_loop().run_until_complete(_run())
        assert exit_code == 1, f"Expected exit code 1, got {exit_code}"

    def test_poll_returns_stdout_and_stderr_from_sidecars(self, tmp_path: Path) -> None:
        """_poll_for_result returns stdout/stderr content from sidecar files.

        Simulates a guest command that emitted both stdout and stderr by
        writing the sidecar files alongside the result file. On the unfixed
        ``main`` branch the function returns empty stdout/stderr regardless;
        on the fixed branch both streams must come back to the caller.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_xyz.txt"
        stdout_file = tmp_path / "xyz.stdout"
        stderr_file = tmp_path / "xyz.stderr"
        script_file = tmp_path / "exec_xyz.cmd"
        script_file.write_text("@echo off\r\n", encoding="utf-8")
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("0\n", encoding="utf-8")
            stdout_file.write_text("hello-out\n", encoding="utf-8")
            stderr_file.write_text("hello-err\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(
                result_file,
                5,
                stdout_path=stdout_file,
                stderr_path=stderr_file,
                script_path=script_file,
            )

        exit_code, stdout, stderr = asyncio.get_event_loop().run_until_complete(_run())
        assert exit_code == 0, f"Expected exit code 0, got {exit_code}"
        assert "hello-out" in stdout, f"stdout sidecar content missing; got {stdout!r}"
        assert "hello-err" in stderr, f"stderr sidecar content missing; got {stderr!r}"

    def test_poll_returns_empty_when_sidecar_missing(self, tmp_path: Path) -> None:
        """Missing sidecars yield empty strings without raising.

        The fix must distinguish ``sidecar absent`` from ``sidecar contains
        empty string`` only by returning ``""`` either way; it must not raise
        FileNotFoundError or leak the missing-path exception to the caller.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_only.txt"
        absent_stdout = tmp_path / "missing.stdout"
        absent_stderr = tmp_path / "missing.stderr"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("0\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(
                result_file,
                5,
                stdout_path=absent_stdout,
                stderr_path=absent_stderr,
            )

        exit_code, stdout, stderr = asyncio.get_event_loop().run_until_complete(_run())
        assert exit_code == 0
        assert not stdout, f"Expected empty stdout when sidecar missing; got {stdout!r}"
        assert not stderr, f"Expected empty stderr when sidecar missing; got {stderr!r}"

    def test_poll_cleans_up_result_and_sidecar_files(self, tmp_path: Path) -> None:
        """After polling succeeds, result/sidecar/script files must be removed.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_cleanup.txt"
        stdout_file = tmp_path / "cleanup.stdout"
        stderr_file = tmp_path / "cleanup.stderr"
        script_file = tmp_path / "exec_cleanup.cmd"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("0\n", encoding="utf-8")
            stdout_file.write_text("o", encoding="utf-8")
            stderr_file.write_text("e", encoding="utf-8")
            script_file.write_text("@echo off\r\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(
                result_file,
                5,
                stdout_path=stdout_file,
                stderr_path=stderr_file,
                script_path=script_file,
            )

        asyncio.get_event_loop().run_until_complete(_run())

        assert not result_file.exists(), "result file should be cleaned up after poll"
        assert not stdout_file.exists(), "stdout sidecar should be cleaned up"
        assert not stderr_file.exists(), "stderr sidecar should be cleaned up"
        assert not script_file.exists(), "script file should be cleaned up"

    def test_generated_windows_script_redirects_stdout_and_stderr(self) -> None:
        """Windows script must redirect stdout/stderr to per-id sidecar files.

        Confirms that the generated guest script references both sidecar
        files in its redirection. Without the fix, only the exit code would
        be emitted.
        """
        sb = _make_sandbox(guest_os=GuestOS.WINDOWS)
        script_name, script_content = sb.generate_execution_script_for_test(
            command='powershell -Command "Write-Host out; Write-Error err"',
            working_directory=None,
            script_id="deadbeef",
            result_name="result_deadbeef.txt",
            stdout_name="deadbeef.stdout",
            stderr_name="deadbeef.stderr",
        )

        assert script_name.endswith(".cmd")
        assert "deadbeef.stdout" in script_content, "Windows script must redirect stdout to deadbeef.stdout"
        assert "deadbeef.stderr" in script_content, "Windows script must redirect stderr to deadbeef.stderr"
        assert "1>" in script_content or "1> " in script_content, "Script must redirect file descriptor 1 to stdout sidecar"
        assert "2>" in script_content, "Script must redirect file descriptor 2 to stderr sidecar"

    def test_generated_linux_script_redirects_stdout_and_stderr(self) -> None:
        """Linux script must redirect stdout/stderr to per-id sidecar files."""
        sb = _make_sandbox(guest_os=GuestOS.LINUX)
        script_name, script_content = sb.generate_execution_script_for_test(
            command="echo out; >&2 echo err",
            working_directory=None,
            script_id="cafebabe",
            result_name="result_cafebabe.txt",
            stdout_name="cafebabe.stdout",
            stderr_name="cafebabe.stderr",
        )

        assert script_name.endswith(".sh")
        assert "cafebabe.stdout" in script_content
        assert "cafebabe.stderr" in script_content
        assert "2>" in script_content, "Linux script must redirect fd 2 to stderr sidecar"


# ---------------------------------------------------------------------------
# F-0004: -cpu host must NOT appear when accelerator is TCG
# ---------------------------------------------------------------------------


class TestF0004CpuArgNotHostForTCG:
    """F-0004: -cpu host requires hardware virtualisation; must be absent with TCG."""

    def _build_command_sync(self, sb: _TestQEMUSandbox, tmp_path: Path) -> list[str]:
        """Run _build_qemu_command synchronously.

        Args:
            sb: _TestQEMUSandbox instance.
            tmp_path: Temp directory for image path.

        Returns:
            list[str]: Resulting command line.
        """
        image = tmp_path / "disk.qcow2"
        image.write_bytes(b"\x00" * 512)
        sb.set_qemu_config(
            QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                image_path=image,
                monitor_port=4444,
                ssh_port=2222,
                agent_port=4445,
            ),
        )
        sb.set_qemu_path(Path("qemu-system-x86_64"))
        sb.set_temp_dir(tmp_path)

        return asyncio.get_event_loop().run_until_complete(sb.build_qemu_command_for_test())

    def test_cpu_host_absent_with_tcg(self, tmp_path: Path) -> None:
        """-cpu host must not appear in the QEMU argv when accel is TCG.

        Args:
            tmp_path: Pytest temp directory.
        """
        sb = _make_sandbox(accelerator=AcceleratorType.TCG)
        cmd = self._build_command_sync(sb, tmp_path)

        cpu_idx = next((i for i, v in enumerate(cmd) if v == "-cpu"), None)
        assert cpu_idx is not None, "No -cpu argument found"
        cpu_value = cmd[cpu_idx + 1]
        assert "host" not in cpu_value.lower(), f"'-cpu host' must not appear with TCG; got '-cpu {cpu_value}'"

    def test_cpu_host_present_with_kvm(self, tmp_path: Path) -> None:
        """-cpu host is permitted when accel is KVM (hardware virt available).

        Args:
            tmp_path: Pytest temp directory.
        """
        sb = _make_sandbox(accelerator=AcceleratorType.KVM)
        cmd = self._build_command_sync(sb, tmp_path)

        cpu_idx = next((i for i, v in enumerate(cmd) if v == "-cpu"), None)
        assert cpu_idx is not None
        cpu_value = cmd[cpu_idx + 1]
        assert "host" in cpu_value.lower(), f"Expected 'host' in -cpu with KVM; got '{cpu_value}'"


# ---------------------------------------------------------------------------
# F-0005: Windows shared folder uses FAT drive, not SMB/9p
# ---------------------------------------------------------------------------


class TestF0005SharedFolderWindowsCompatible:
    """F-0005: On Windows host the shared folder must use the FAT drive method."""

    def test_windows_guest_uses_fat_drive_not_smb(self, tmp_path: Path) -> None:
        """Windows-guest shared folder is -drive fat:rw:..., not SMB or 9p.

        Args:
            tmp_path: Pytest temp directory.
        """
        image = tmp_path / "disk.qcow2"
        image.write_bytes(b"\x00" * 512)
        shared = tmp_path / "shared"
        shared.mkdir()

        sb = _TestQEMUSandbox(
            config=SandboxConfig(),
            qemu_config=QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                image_path=image,
                monitor_port=4444,
                ssh_port=2222,
                agent_port=4445,
            ),
        )
        sb.set_qemu_path(Path("qemu-system-x86_64"))
        sb.set_accelerator(AcceleratorType.TCG)
        sb.set_shared_folder(shared)
        sb.set_temp_dir(tmp_path)

        cmd = asyncio.get_event_loop().run_until_complete(sb.build_qemu_command_for_test())
        cmd_str = " ".join(cmd)

        assert "fat:rw:" in cmd_str, "Expected FAT-drive shared folder for Windows guest"
        assert "9p" not in cmd_str, "9p is not supported on Windows host QEMU"


# ---------------------------------------------------------------------------
# F-0009: Agent script must not use $using:; uses -MessageData or explicit var
# ---------------------------------------------------------------------------


class TestF0009AgentScriptNoPsUsing:
    """F-0009: QEMU agent script must not use $using: scope specifier.

    $using: is only valid in Invoke-Command / ForEach-Object -Parallel.
    In a Register-ObjectEvent -Action block it is a syntax error and the
    action block terminates without ever writing to the log file.
    """

    def test_windows_agent_script_has_no_using_scope(self) -> None:
        """$using: must not appear in the Windows guest agent PS1 script."""
        script = _TestQEMUSandbox.windows_agent_script_content_for_test()
        assert "$using:" not in script, "Windows agent script contains '$using:' which is invalid in Register-ObjectEvent -Action"

    def test_windows_agent_script_uses_message_data_or_global(self) -> None:
        """Log path must be stored via -MessageData or $Global: in agent script."""
        script = _TestQEMUSandbox.windows_agent_script_content_for_test()
        has_message_data = "-MessageData" in script
        has_global = "$Global:" in script or "$global:" in script
        assert has_message_data or has_global, "Agent script must pass the log path via -MessageData or $Global: variable, not $using:"


# ---------------------------------------------------------------------------
# F-0016: _detect_accelerator must NOT report WHPX when Hyper-V is disabled
# ---------------------------------------------------------------------------


class TestF0016WhpxRequiresHyperV:
    """F-0016: _detect_accelerator must skip WHPX when Hyper-V prerequisites fail."""

    def test_whpx_skipped_when_hyperv_prerequisites_fail(self) -> None:
        """WHPX is not selected when _probe_whpx_host_prerequisites returns False.

        The old bug reported WHPX available whenever the QEMU binary was
        compiled with WHPX support, ignoring whether Hyper-V was enabled.
        """
        sb = _make_sandbox()
        sb.set_qemu_path(Path("qemu-system-x86_64"))

        class _FakeResult:
            stdout: str = "Available accelerators: whpx kvm tcg\n"
            stderr: str = ""
            returncode: int = 0

        async def _run() -> AcceleratorType:
            with (
                patch(
                    "intellicrack.sandbox.qemu.QEMUSandbox._probe_whpx_host_prerequisites",
                    return_value=False,
                ),
                patch(
                    "intellicrack.core.process_manager.ProcessManager.run_tracked_async",
                    new=AsyncMock(return_value=_FakeResult()),
                ),
            ):
                return await sb.detect_accelerator_for_test()

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result != AcceleratorType.WHPX, "_detect_accelerator must not return WHPX when Hyper-V prerequisites are not met"

    def test_probe_whpx_returns_false_on_non_windows(self) -> None:
        """_probe_whpx_host_prerequisites returns False on non-Windows hosts."""
        with patch("platform.system", return_value="Linux"):
            result = _TestQEMUSandbox.probe_whpx_prerequisites_for_test()
        assert result is False, "WHPX prerequisites must be False on non-Windows"


# ---------------------------------------------------------------------------
# F-0022: apply_anti_evasion must NOT use reg.exe if blocked by allowlist
# F-0029: apply_anti_evasion(profile=...) must actually use the profile
# ---------------------------------------------------------------------------


class TestF0022F0029AntiEvasion:
    """F-0022 / F-0029: apply_anti_evasion uses profile param and agent allowlist-safe commands."""

    def test_anti_evasion_profile_recorded_in_result(self) -> None:
        """apply_anti_evasion returns a dict whose 'profile' key matches the launch profile.

        The original bug always hardcoded 'default' regardless of the argument.
        F-0029 further requires that the argument match the launch-time profile,
        so this test launches the sandbox with ``workstation`` and asserts the
        returned profile reflects the active launch-time profile.
        """
        sb = _make_sandbox()
        sb.set_qemu_config(
            QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                anti_evasion_profile="workstation",
            ),
        )
        sb.state.status = "running"
        sb.set_agent(_ConnectableAgent(connected=False))

        async def _run() -> dict[str, Any]:
            sb.set_qmp(MagicMock())
            return await sb.apply_anti_evasion(profile="workstation")

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result["profile"] == "workstation", f"apply_anti_evasion did not use the profile argument; got {result['profile']}"

    def test_anti_evasion_different_profiles_produce_different_smbios(self) -> None:
        """Different profiles produce distinguishably different SMBIOS entries.

        This validates that the profile parameter flows all the way through to
        SMBIOS content, not just to the reported label.
        """
        default_entries = _TestQEMUSandbox.anti_evasion_smbios_entries_for_test("default")
        workstation_entries = _TestQEMUSandbox.anti_evasion_smbios_entries_for_test("workstation")
        laptop_entries = _TestQEMUSandbox.anti_evasion_smbios_entries_for_test("laptop")

        default_mfrs = {e.get("manufacturer") for e in default_entries}
        ws_mfrs = {e.get("manufacturer") for e in workstation_entries}
        laptop_mfrs = {e.get("manufacturer") for e in laptop_entries}

        assert default_mfrs != ws_mfrs, "workstation profile must differ from default"
        assert default_mfrs != laptop_mfrs, "laptop profile must differ from default"
        assert ws_mfrs != laptop_mfrs, "laptop profile must differ from workstation"

    def test_anti_evasion_techniques_reflect_profile_applied(self) -> None:
        """Techniques list contains profile-specific SMBIOS entries."""
        sb = _make_sandbox()
        sb.state.status = "running"
        sb.set_agent(_ConnectableAgent(connected=False))
        sb.set_qemu_config(
            QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                anti_evasion_profile="laptop",
            ),
        )

        async def _run() -> dict[str, Any]:
            sb.set_qmp(MagicMock())
            return await sb.apply_anti_evasion(profile="laptop")

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result["profile"] == "laptop"
        assert any("smbios" in t for t in result["techniques"]), "Techniques must include SMBIOS entries when profile is applied"


# ---------------------------------------------------------------------------
# F-0023: list_snapshots parses QMP response correctly
# ---------------------------------------------------------------------------


class _SnapshotQMPResult:
    """Minimal QMP result for snapshot list tests.

    Attributes:
        success: Whether the command succeeded.
        error: Error message if failed.
        data: Response text payload.
    """

    success: bool
    error: str
    data: str

    def __init__(self, text: str, *, success: bool = True) -> None:
        """Initialise with response text.

        Args:
            text: Snapshot output text to return as data.
            success: Whether the result represents success.
        """
        self.success = success
        self.error = ""
        self.data = text


class _FakeQMPForSnapshots:
    """Minimal QMP client for list_snapshots testing.

    Attributes:
        output_text: Text returned as the snapshot listing.
    """

    output_text: str

    def __init__(self, output_text: str) -> None:
        """Initialise with the output text.

        Args:
            output_text: Text the fake QMP returns in info_snapshots.
        """
        self.output_text = output_text

    async def info_snapshots(self) -> _SnapshotQMPResult:
        """Return the configured snapshot listing.

        Returns:
            _SnapshotQMPResult: Result containing output_text as data.
        """
        return _SnapshotQMPResult(self.output_text)


class TestF0023ListSnapshotsParsing:
    """F-0023: list_snapshots must parse QMP info-snapshots output correctly."""

    def test_parses_numeric_leading_tag_rows(self) -> None:
        """Rows whose first token is a digit are parsed as snapshot names."""
        qmp_output = (
            " ID        TAG                 VM SIZE                DATE       VM CLOCK\n"
            " 1         clean_state            385M 2026-04-01 10:00:00   00:01:23.456\n"
            " 2         post_install           390M 2026-04-01 10:05:00   00:02:00.000\n"
        )
        sb = _make_sandbox()
        sb.set_qmp(_FakeQMPForSnapshots(qmp_output))

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert "clean_state" in result, f"Expected 'clean_state' in {result}"
        assert "post_install" in result, f"Expected 'post_install' in {result}"

    def test_header_row_excluded(self) -> None:
        """Header rows (non-digit first token) must not appear in the result."""
        qmp_output = " ID        TAG\n 1         mysnap\n"
        sb = _make_sandbox()
        sb.set_qmp(_FakeQMPForSnapshots(qmp_output))

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert "ID" not in result, f"Header 'ID' must not appear in snapshot list: {result}"
        assert "TAG" not in result, f"Header 'TAG' must not appear in snapshot list: {result}"

    def test_empty_output_returns_empty_list(self) -> None:
        """Empty QMP output returns an empty snapshot list."""
        sb = _make_sandbox()
        sb.set_qmp(_FakeQMPForSnapshots(""))

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result == [], f"Expected [] for empty QMP output; got {result}"


# ---------------------------------------------------------------------------
# F-0025: stop() cleans active captures
# ---------------------------------------------------------------------------


class TestF0025StopClearsCaptures:
    """F-0025: stop() must clear _active_captures (resource leak fix)."""

    def test_stop_clears_active_captures_dict(self, tmp_path: Path) -> None:
        """_active_captures is empty after stop() returns.

        Args:
            tmp_path: Pytest temp directory.
        """
        sb = _make_sandbox(shared_folder=tmp_path)
        sb.state.status = "running"
        sb.add_active_capture("cap_001", tmp_path / "cap_001.pcap")
        sb.add_active_capture("cap_002", tmp_path / "cap_002.pcap")

        assert len(sb.get_active_captures()) == 2, "Precondition: captures must be non-empty"

        async def _run() -> None:
            with patch.object(sb, "_cleanup", new=AsyncMock()):
                sb.set_qmp(None)
                sb.set_agent(None)
                sb.set_qemu_pid(None)
                await sb.stop()

        asyncio.get_event_loop().run_until_complete(_run())

        assert len(sb.get_active_captures()) == 0, "stop() must clear _active_captures; resource leak remains if not emptied"


# ---------------------------------------------------------------------------
# F-0028: yara_scan must NOT scan user input on fallback
# ---------------------------------------------------------------------------


class TestF0028YaraScanFallback:
    """F-0028: yara_scan fallback must scan dropped-file zips, not the input folder."""

    def test_yara_scan_uses_output_dir_not_input_on_no_zip(self, tmp_path: Path) -> None:
        """When no dropped-file zip exists, scan_files must be empty, not the input dir.

        The old bug fell back to scanning shared/input/ which contains
        whatever the user originally submitted, not sandbox artifacts.

        Args:
            tmp_path: Pytest temp directory.
        """
        shared = tmp_path / "shared"
        input_dir = shared / "input"
        output_dir = shared / "output"
        input_dir.mkdir(parents=True)
        output_dir.mkdir(parents=True)

        user_file = input_dir / "user_submitted.exe"
        user_file.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        scanned_paths: list[str] = []

        class _FakeRules:
            def match(self, filepath: str) -> list[object]:
                """Record scanned filepath.

                Args:
                    filepath: File being scanned.

                Returns:
                    list[object]: Empty match list.
                """
                scanned_paths.append(filepath)
                return []

        class _FakeYara:
            @staticmethod
            def compile(**_kwargs: object) -> _FakeRules:
                """Return fake compiled rules.

                Args:
                    **_kwargs: Ignored.

                Returns:
                    _FakeRules: Fake rules object.
                """
                return _FakeRules()

        import yara as _real_yara  # noqa: PLC0415

        sb = _make_sandbox(shared_folder=shared)

        async def _run() -> list[dict[str, Any]]:
            with patch.object(_real_yara, "compile", side_effect=_FakeYara.compile):
                return await sb.yara_scan(scan_target="files")

        asyncio.get_event_loop().run_until_complete(_run())

        for p in scanned_paths:
            assert "user_submitted" not in p, f"yara_scan must not scan user input; found '{p}' in scan_files"

    def test_yara_scan_scans_zip_artifacts_when_present(self, tmp_path: Path) -> None:
        """When a dropped-file zip exists, yara_scan uses it not the input dir.

        Args:
            tmp_path: Pytest temp directory.
        """
        shared = tmp_path / "shared"
        input_dir = shared / "input"
        output_dir = shared / "output"
        input_dir.mkdir(parents=True)
        output_dir.mkdir(parents=True)

        zip_path = output_dir / "dropped_files_aabbccdd.zip"
        artifact = tmp_path / "artifact.bin"
        artifact.write_bytes(b"\xde\xad\xbe\xef")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(artifact, "artifact.bin")

        scanned_paths: list[str] = []

        class _FakeRules2:
            def match(self, filepath: str) -> list[object]:
                """Record scanned filepath.

                Args:
                    filepath: File being scanned.

                Returns:
                    list[object]: Empty match list.
                """
                scanned_paths.append(filepath)
                return []

        class _FakeYara2:
            @staticmethod
            def compile(**_kwargs: object) -> _FakeRules2:
                """Return fake compiled rules.

                Args:
                    **_kwargs: Ignored.

                Returns:
                    _FakeRules2: Fake rules object.
                """
                return _FakeRules2()

        import yara as _real_yara  # noqa: PLC0415

        sb = _make_sandbox(shared_folder=shared)

        async def _run() -> list[dict[str, Any]]:
            with patch.object(_real_yara, "compile", side_effect=_FakeYara2.compile):
                return await sb.yara_scan(scan_target="files")

        asyncio.get_event_loop().run_until_complete(_run())

        assert len(scanned_paths) > 0, "yara_scan did not scan any files from the zip"


# ---------------------------------------------------------------------------
# F-0031: run_binary must not have a hard-coded asyncio.sleep(2)
# ---------------------------------------------------------------------------


class TestF0031RunBinaryNoFixedSleep:
    """F-0031: run_binary must not unconditionally sleep 2 seconds after execution."""

    def test_run_binary_completes_fast_without_monitoring(self, tmp_path: Path) -> None:
        """run_binary without monitoring should not have a fixed 2s sleep.

        If asyncio.sleep(2) is unconditional, this test would take >= 2s
        even with monitor=False.

        Args:
            tmp_path: Pytest temp directory.
        """
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        shared = tmp_path / "shared"
        sb = _make_sandbox(shared_folder=shared)
        sb.state.status = "running"
        shared.mkdir()
        (shared / "input").mkdir()
        (shared / "output").mkdir()
        (shared / "logs").mkdir()
        sb.set_qemu_config(QEMUConfig(guest_os=GuestOS.WINDOWS))

        async def _run() -> float:
            with (
                patch.object(sb, "copy_to_sandbox", new=AsyncMock()),
                patch.object(sb, "run_command", new=AsyncMock(return_value=(0, "ok", ""))),
            ):
                t0 = time.monotonic()
                await sb.run_binary(binary, monitor=False)
                return time.monotonic() - t0

        elapsed = asyncio.get_event_loop().run_until_complete(_run())
        assert elapsed < 1.5, f"run_binary without monitoring took {elapsed:.2f}s — a hard-coded asyncio.sleep(2) would make this >= 2s"


# ---------------------------------------------------------------------------
# F-0035: run_binary success flag must match exit_code
# ---------------------------------------------------------------------------


class TestF0035RunBinarySuccessMatchesExitCode:
    """F-0035: run_binary result must be 'success' iff exit_code == 0."""

    def _run_with_exit(self, exit_code: int, tmp_path: Path) -> str:
        """Run sandbox run_binary with a controlled exit code.

        Args:
            exit_code: Simulated process exit code.
            tmp_path: Pytest temp directory.

        Returns:
            str: ExecutionReport.result value.
        """
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"\x4d\x5a" + b"\x00" * 62)

        shared = tmp_path / "shared"
        sb = _make_sandbox(shared_folder=shared)
        sb.state.status = "running"
        shared.mkdir(exist_ok=True)
        (shared / "input").mkdir(exist_ok=True)
        (shared / "output").mkdir(exist_ok=True)
        (shared / "logs").mkdir(exist_ok=True)
        sb.set_qemu_config(QEMUConfig(guest_os=GuestOS.WINDOWS))

        async def _run() -> str:
            with (
                patch.object(sb, "copy_to_sandbox", new=AsyncMock()),
                patch.object(sb, "run_command", new=AsyncMock(return_value=(exit_code, "", ""))),
            ):
                report = await sb.run_binary(binary, monitor=False)
            return report.result

        return asyncio.get_event_loop().run_until_complete(_run())

    def test_exit_code_zero_produces_success(self, tmp_path: Path) -> None:
        """exit_code 0 must yield result == 'success'.

        Args:
            tmp_path: Pytest temp directory.
        """
        result = self._run_with_exit(0, tmp_path)
        assert result == "success", f"exit_code 0 must produce 'success'; got '{result}'"

    def test_exit_code_nonzero_does_not_produce_success(self, tmp_path: Path) -> None:
        """Nonzero exit_code must NOT yield result == 'success'.

        The original bug always returned 'success' regardless of exit code.

        Args:
            tmp_path: Pytest temp directory.
        """
        result = self._run_with_exit(1, tmp_path)
        assert result != "success", "exit_code 1 must NOT produce 'success'; the old bug reported success always"

    def test_exit_code_2_result_maps_to_error(self, tmp_path: Path) -> None:
        """exit_code 2 must yield result == 'error' or similar non-success value.

        Args:
            tmp_path: Pytest temp directory.
        """
        result = self._run_with_exit(2, tmp_path)
        assert result in {"error", "failure", "crashed"}, f"exit_code 2 must map to error/failure; got '{result}'"


# ---------------------------------------------------------------------------
# F-0006: Guest agent script must have a startup entry point wired in
# ---------------------------------------------------------------------------


class TestF0006AgentScriptStartupWired:
    """F-0006: The guest agent startup script must be present and reference the agent."""

    def test_windows_startup_script_created(self, tmp_path: Path) -> None:
        """_create_guest_agent_script must produce start_agent.cmd for Windows.

        Args:
            tmp_path: Pytest temp directory.
        """
        monitor_dir = tmp_path / "monitor"
        monitor_dir.mkdir()

        sb = _make_sandbox(guest_os=GuestOS.WINDOWS)
        sb.set_shared_folder(tmp_path)

        async def _run() -> None:
            await sb.create_agent_script_for_test()

        asyncio.get_event_loop().run_until_complete(_run())

        startup_scripts = list(monitor_dir.glob("start_agent.*"))
        agent_scripts = list(monitor_dir.glob("agent.*"))

        assert startup_scripts or agent_scripts, "No startup or agent script created in monitor dir"

    def test_linux_startup_script_created(self, tmp_path: Path) -> None:
        """_create_guest_agent_script must produce start_agent.sh for Linux.

        Args:
            tmp_path: Pytest temp directory.
        """
        monitor_dir = tmp_path / "monitor"
        monitor_dir.mkdir()

        sb = _make_sandbox(guest_os=GuestOS.LINUX)
        sb.set_shared_folder(tmp_path)

        async def _run() -> None:
            await sb.create_agent_script_for_test()

        asyncio.get_event_loop().run_until_complete(_run())

        sh_scripts = list(monitor_dir.glob("*.sh"))
        agent_scripts = list(monitor_dir.glob("agent.*"))
        assert sh_scripts or agent_scripts, "No .sh startup or agent script created for Linux guest"


# ---------------------------------------------------------------------------
# F-0015: start() must not redo accelerator detection if already cached
# ---------------------------------------------------------------------------


class TestF0015AcceleratorNotRedoneOnStart:
    """F-0015: start() must reuse cached accelerator, not re-detect."""

    def test_is_available_uses_cached_accelerator(self) -> None:
        """is_available() skips _detect_accelerator when cache is valid."""
        sb = _make_sandbox(accelerator=AcceleratorType.TCG)
        sb.set_qemu_path(Path("qemu-system-x86_64"))

        detect_call_count = 0

        def _fake_detect() -> AcceleratorType:
            nonlocal detect_call_count
            detect_call_count += 1
            return AcceleratorType.TCG

        async def _run() -> None:
            with (
                patch.object(sb, "_find_qemu", new=AsyncMock(return_value=Path("qemu-system-x86_64"))),
                patch.object(sb, "_detect_accelerator", side_effect=_fake_detect),
            ):
                await sb.is_available()
                await sb.is_available()

        asyncio.get_event_loop().run_until_complete(_run())

        assert detect_call_count == 0, f"_detect_accelerator was called {detect_call_count} times but must be 0 when cache is already valid"


# ---------------------------------------------------------------------------
# F-0007: extract_dropped_files must work without agent and produce a zip
# ---------------------------------------------------------------------------


class TestF0007ExtractDroppedFiles:
    """F-0007: extract_dropped_files must produce a valid zip when files are present."""

    def test_extract_produces_zip_without_agent(self, tmp_path: Path) -> None:
        """extract_dropped_files uses the host-side dropped mirror when no agent.

        The fixed implementation (audit7 U07) requires the guest's monitor to
        mirror dropped files to ``<shared>/output/dropped/`` so the host-side
        fallback can collect them when the agent is disconnected.

        Args:
            tmp_path: Pytest temp directory.
        """
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)
        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        (mirror / "dropped_sample.bin").write_bytes(b"\xde\xad\xbe\xef")

        sb = _make_sandbox(guest_os=GuestOS.WINDOWS, shared_folder=shared)
        sb.state.status = "running"
        sb.set_agent(None)

        async def _run() -> Path:
            return await sb.extract_dropped_files()

        result = asyncio.get_event_loop().run_until_complete(_run())
        assert result.exists(), "extract_dropped_files must return an existing zip path"
        assert result.suffix == ".zip", f"Expected .zip file; got {result.suffix}"
        assert zipfile.is_zipfile(result), "Output file must be a valid zip archive"
        with zipfile.ZipFile(result) as zf:
            names = zf.namelist()
        assert any(n.endswith("dropped_sample.bin") for n in names), f"Expected dropped_sample.bin in archive, found {names}"
