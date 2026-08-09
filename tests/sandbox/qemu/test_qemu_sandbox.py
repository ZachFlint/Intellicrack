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
import os
import shutil
import socket
import subprocess
import time
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError, SandboxTimeoutError


if TYPE_CHECKING:
    from collections.abc import Sequence
from intellicrack.core._optional_imports import require_yara
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
    QMPClient,
    QMPResponse,
)
from tests.sandbox.qemu.guest_agent_server import IntellicrackAgentServer


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
    async def ensure_agent_connected_for_test(agent: GuestAgentClient, time_limit: float) -> None:
        """Expose _ensure_agent_connected for test introspection.

        Args:
            agent: Guest agent client to drive through the production connect path.
            time_limit: Total seconds to wait for the agent to become reachable.
        """
        await QEMUSandbox._ensure_agent_connected(agent, time_limit)

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


def _resolve_cmd_exe() -> str:
    """Return the absolute path to the Windows command interpreter.

    Resolves ``cmd.exe`` to a full path so the generated guest ``.cmd`` script
    can be executed without relying on a partial executable name.

    Returns:
        str: Absolute path to ``cmd.exe``.
    """
    com_spec = os.environ.get("COMSPEC")
    if com_spec and Path(com_spec).is_file():
        return com_spec
    resolved = shutil.which("cmd.exe") or shutil.which("cmd")
    assert resolved is not None, "cmd.exe must be available to execute the generated Windows guest script"
    return resolved


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
    """F-0002: start() must drive GuestAgentClient.connect against a live agent socket.

    These tests exercise the real production method ``_ensure_agent_connected``
    (the single code path that ``start`` -> ``_start_impl`` -> ``_attach_qemu_agents``
    uses to await ``agent.connect``) against a *real* ``GuestAgentClient`` and a
    *real* loopback TCP server. Nothing in the connect path is mocked: a genuine
    socket is opened end to end. If production stopped awaiting ``agent.connect``
    (the original bug) the agent would never reach ``is_connected == True`` and
    the failure path would not raise, so both tests would go red.
    """

    def test_ensure_agent_connected_opens_real_socket(self) -> None:
        """``_ensure_agent_connected`` connects a real agent to a live agent.

        A real in-guest monitor agent is bound on an ephemeral loopback port; a
        real ``GuestAgentClient`` is pointed at it and driven through the
        production ``QEMUSandbox._ensure_agent_connected`` helper. The peer
        records the accepted connection, proving an actual TCP connection was
        established by the production connect path. A socket that merely
        accepts would not do: that is the dead hostfwd of S17-D25, and a client
        that called it connected would pass a test written against one.
        """

        async def _run() -> tuple[bool, int]:
            server = IntellicrackAgentServer()
            await server.start()
            agent = GuestAgentClient(host="127.0.0.1", port=server.port)
            try:
                await _TestQEMUSandbox.ensure_agent_connected_for_test(agent, 5.0)
                return agent.is_connected, server.accepted
            finally:
                await agent.disconnect()
                await server.stop()

        connected, accept_count = asyncio.run(_run())
        assert connected is True, "_ensure_agent_connected must leave the agent in the connected state"
        assert accept_count == 1, f"the production connect path must open exactly one real socket; server accepted {accept_count}"

    def test_ensure_agent_connected_raises_when_no_listener(self) -> None:
        """``_ensure_agent_connected`` surfaces a ``SandboxError`` when nothing listens.

        A free loopback port is reserved and then released so no server is
        listening. Driving the real connect path against it must fail loudly:
        ``connect`` returns ``False`` and the production helper raises
        ``SandboxError`` rather than silently leaving the agent disconnected.
        """

        async def _run() -> bool:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                dead_port = probe.getsockname()[1]

            agent = GuestAgentClient(host="127.0.0.1", port=dead_port)
            with pytest.raises(SandboxError):
                await _TestQEMUSandbox.ensure_agent_connected_for_test(agent, 1.0)
            return agent.is_connected

        connected = asyncio.run(_run())
        assert connected is False, "agent must remain disconnected after a failed connect"

    def test_real_agent_connect_returns_true_against_live_server(self) -> None:
        """``GuestAgentClient.connect`` returns True only against a live agent.

        Drives the real ``connect`` method (no override) against a real
        in-guest monitor agent on loopback and asserts both the boolean
        contract and ``is_connected``.
        """

        async def _run() -> tuple[bool, bool, bool]:
            server = IntellicrackAgentServer()
            await server.start()
            agent = GuestAgentClient(host="127.0.0.1", port=server.port)
            before = agent.is_connected
            try:
                ok = await agent.connect(time_limit=5.0, retry_interval=1.0)
                return before, ok, agent.is_connected
            finally:
                await agent.disconnect()
                await server.stop()

        before, ok, after = asyncio.run(_run())
        assert before is False, "precondition: agent starts disconnected"
        assert ok is True, "connect() must return True against a live server"
        assert after is True, "is_connected must be True after a successful real connect()"


# ---------------------------------------------------------------------------
# F-0003: _poll_for_result returns real exit code from result file
# ---------------------------------------------------------------------------


class TestF0003PollForResult:
    """F-0003: _poll_for_result must parse the exit code from the result file."""

    def test_poll_reads_exit_code_from_result_file(self, tmp_path: Path) -> None:
        """_poll_for_result returns the full 3-tuple with the parsed exit code.

        Drives the real ``_poll_for_result`` with a well-formed result file and
        no sidecars, then asserts the exact tuple structure: the exit code is
        parsed from the file and stdout/stderr default to empty strings.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_abc.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("42\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        outcome = asyncio.run(_run())
        assert outcome == (42, "", ""), f"Expected exact tuple (42, '', ''); got {outcome!r}"

    @pytest.mark.parametrize(
        ("file_text", "expected_code"),
        [
            ("0\n", 0),
            ("1\n", 1),
            ("42\n", 42),
            ("255\n", 255),
            ("007\n", 7),
            ("   13   \n", 13),
        ],
    )
    def test_poll_parses_well_formed_integer_codes(self, tmp_path: Path, file_text: str, expected_code: int) -> None:
        """_poll_for_result parses a stripped all-digit result file to its integer value.

        Expected values are derived from the documented contract (the result
        file holds the guest command's decimal exit code), not from the
        implementation's own output.

        Args:
            tmp_path: Pytest temp directory.
            file_text: Raw result-file contents written by the guest script.
            expected_code: Independently-known exit code the file encodes.
        """
        result_file = tmp_path / "result_wellformed.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text(file_text, encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        exit_code, stdout, stderr = asyncio.run(_run())
        assert exit_code == expected_code, f"file {file_text!r} must parse to {expected_code}; got {exit_code}"
        assert not stdout, f"stdout must be empty without a sidecar; got {stdout!r}"
        assert not stderr, f"stderr must be empty without a sidecar; got {stderr!r}"

    @pytest.mark.parametrize(
        "file_text",
        ["", "abc\n", "0x42\n", "-1\n", "1.5\n", "exit: 0\n", "42 43\n"],
    )
    def test_poll_returns_sentinel_for_malformed_result(self, tmp_path: Path, file_text: str) -> None:
        """_poll_for_result yields the -1 sentinel for any non-decimal result file.

        The contract is that only a stripped, all-digit body is a valid exit
        code; everything else (empty, hex, signed, float, prose, multi-token)
        maps to -1 so a malformed guest result is never silently reported as a
        success (0). This guards against a regression that parsed hex, took the
        last line, or defaulted to 0.

        Args:
            tmp_path: Pytest temp directory.
            file_text: Malformed result-file contents.
        """
        result_file = tmp_path / "result_malformed.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text(file_text, encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        exit_code, stdout, stderr = asyncio.run(_run())
        assert exit_code == -1, f"malformed result {file_text!r} must map to -1; got {exit_code}"
        assert not stdout, f"stdout must be empty; got {stdout!r}"
        assert not stderr, f"stderr must be empty; got {stderr!r}"

    def test_poll_does_not_take_last_line_as_exit_code(self, tmp_path: Path) -> None:
        r"""A multi-line result whose last line is a digit must still be -1.

        Pins the whole-file-strip semantics: ``"garbage\n7"`` is not an
        all-digit body, so it is the -1 sentinel rather than 7. A regression
        that read only the last line would return 7 and fail this gate.

        Args:
            tmp_path: Pytest temp directory.
        """
        result_file = tmp_path / "result_multiline.txt"
        sb = _make_sandbox()

        async def _run() -> tuple[int, str, str]:
            result_file.write_text("garbage\n7\n", encoding="utf-8")
            return await sb.poll_for_result_for_test(result_file, 5)

        exit_code, _stdout, _stderr = asyncio.run(_run())
        assert exit_code == -1, f"multi-line result must not be read as its last line; got {exit_code}"

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
            asyncio.run(_run())

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

        exit_code, _stdout, _stderr = asyncio.run(_run())
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

        exit_code, stdout, stderr = asyncio.run(_run())
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

        exit_code, stdout, stderr = asyncio.run(_run())
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

        asyncio.run(_run())

        assert not result_file.exists(), "result file should be cleaned up after poll"
        assert not stdout_file.exists(), "stdout sidecar should be cleaned up"
        assert not stderr_file.exists(), "stderr sidecar should be cleaned up"
        assert not script_file.exists(), "script file should be cleaned up"

    def test_generated_windows_script_executes_and_writes_exact_sidecars(self, tmp_path: Path) -> None:
        r"""The generated Windows .cmd actually redirects to the sidecars when run.

        The guest script is generated by production, its hard-coded guest path
        prefix (``Z:\output\``) is rewritten onto a real host output folder,
        and the script is executed by ``cmd.exe``. A command with a *known*
        stdout token, a *known* stderr token, and a *known* non-zero exit code
        is used as an independent oracle. The test asserts the exact captured
        stdout, the exact captured stderr, and the exact exit code recorded in
        the result file - proving the redirection syntax (``1>``/``2>`` and
        ``echo %ERRORLEVEL%``) is correct, not merely textually present.

        Args:
            tmp_path: Pytest temp directory.
        """
        out_dir = tmp_path / "output"
        out_dir.mkdir()
        sb = _make_sandbox(guest_os=GuestOS.WINDOWS)
        command = 'cmd /c "echo HELLO_OUT& echo HELLO_ERR 1>&2& exit /b 3"'
        script_name, script_content = sb.generate_execution_script_for_test(
            command=command,
            working_directory=None,
            script_id="deadbeef",
            result_name="result_deadbeef.txt",
            stdout_name="deadbeef.stdout",
            stderr_name="deadbeef.stderr",
        )
        assert script_name.endswith(".cmd"), f"Windows script name must end in .cmd; got {script_name}"

        runnable = script_content.replace("Z:\\output\\", f"{out_dir}\\")
        script_path = tmp_path / script_name
        script_path.write_text(runnable, encoding="ascii")

        cmd_exe = _resolve_cmd_exe()
        completed = subprocess.run(
            [cmd_exe, "/c", str(script_path)],
            check=False,
            capture_output=True,
            timeout=30,
        )
        assert completed.returncode == 0, f"cmd wrapper itself must exit 0; stderr={completed.stderr!r}"

        stdout_text = (out_dir / "deadbeef.stdout").read_text(encoding="ascii")
        stderr_text = (out_dir / "deadbeef.stderr").read_text(encoding="ascii")
        result_text = (out_dir / "result_deadbeef.txt").read_text(encoding="ascii").strip()

        assert "HELLO_OUT" in stdout_text, f"stdout sidecar must capture the command's stdout; got {stdout_text!r}"
        assert "HELLO_OUT" not in stderr_text, f"stdout token leaked into stderr sidecar: {stderr_text!r}"
        assert "HELLO_ERR" in stderr_text, f"stderr sidecar must capture the command's stderr; got {stderr_text!r}"
        assert "HELLO_ERR" not in stdout_text, f"stderr token leaked into stdout sidecar: {stdout_text!r}"
        assert result_text == "3", f"result file must record the command exit code 3; got {result_text!r}"

    def test_generated_linux_script_executes_and_writes_exact_sidecars(self, tmp_path: Path) -> None:
        """The generated Linux .sh actually redirects to the sidecars when run.

        The production-generated script's guest prefix (``/mnt/shared/output/``)
        is rewritten onto a real host output folder and executed with ``bash``.
        A command with known stdout, known stderr, and a known non-zero exit
        code serves as the oracle; the test asserts the exact sidecar contents
        and the exact exit code captured by ``echo $?``.

        Args:
            tmp_path: Pytest temp directory.
        """
        bash_path = shutil.which("bash")
        assert bash_path is not None, "bash must be available to execute the generated Linux guest script"

        out_dir = tmp_path / "output"
        out_dir.mkdir()
        sb = _make_sandbox(guest_os=GuestOS.LINUX)
        command = "echo LINUX_OUT; echo LINUX_ERR 1>&2; exit 5"
        script_name, script_content = sb.generate_execution_script_for_test(
            command=command,
            working_directory=None,
            script_id="cafebabe",
            result_name="result_cafebabe.txt",
            stdout_name="cafebabe.stdout",
            stderr_name="cafebabe.stderr",
        )
        assert script_name.endswith(".sh"), f"Linux script name must end in .sh; got {script_name}"

        host_prefix = f"{out_dir.as_posix()}/"
        runnable = script_content.replace("/mnt/shared/output/", host_prefix)
        script_path = tmp_path / script_name
        script_path.write_text(runnable, encoding="utf-8", newline="\n")

        completed = subprocess.run(
            [bash_path, script_path.as_posix()],
            check=False,
            capture_output=True,
            timeout=30,
        )
        assert completed.returncode == 0, f"bash wrapper itself must exit 0; stderr={completed.stderr!r}"

        stdout_text = (out_dir / "cafebabe.stdout").read_text(encoding="utf-8")
        stderr_text = (out_dir / "cafebabe.stderr").read_text(encoding="utf-8")
        result_text = (out_dir / "result_cafebabe.txt").read_text(encoding="utf-8").strip()

        assert "LINUX_OUT" in stdout_text, f"stdout sidecar must capture the command's stdout; got {stdout_text!r}"
        assert "LINUX_OUT" not in stderr_text, f"stdout token leaked into stderr sidecar: {stderr_text!r}"
        assert "LINUX_ERR" in stderr_text, f"stderr sidecar must capture the command's stderr; got {stderr_text!r}"
        assert "LINUX_ERR" not in stdout_text, f"stderr token leaked into stdout sidecar: {stdout_text!r}"
        assert result_text == "5", f"result file must record the command exit code 5; got {result_text!r}"


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

        return asyncio.run(sb.build_qemu_command_for_test())

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
        """Windows-guest shared folder is a read-only FAT drive, not SMB or 9p.

        The volume is ``fat:`` rather than ``fat:rw:`` because vvfat's
        write-back path aborts the virtual machine (S17-D69); the guest writes
        to its own disk instead.

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

        cmd = asyncio.run(sb.build_qemu_command_for_test())
        cmd_str = " ".join(cmd)

        assert "file=fat:" in cmd_str, "Expected FAT-drive shared folder for Windows guest"
        assert "readonly=on" in cmd_str, "the FAT share must be read-only or vvfat can abort the VM (S17-D69)"
        assert "fat:rw:" not in cmd_str, "a writable vvfat share is what S17-D69 removed"
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

    def test_windows_agent_script_binds_and_reads_log_path_via_messagedata(self) -> None:
        """The log path must be bound via ``-MessageData`` and read via ``$Event.MessageData``.

        The earlier form accepted either ``-MessageData`` or ``$Global:``
        appearing anywhere, which does not prove the log path is actually
        carried into the ``-Action`` block. PowerShell's
        ``Register-ObjectEvent ... -MessageData <value> -Action { ... }`` exposes
        the bound value only as ``$Event.MessageData`` inside the action block;
        if the registration binds the path but the action never reads
        ``$Event.MessageData`` (or vice versa), the file-change log is never
        written. This gate requires both halves of that contract: at least one
        ``Register-ObjectEvent`` registration binds the file log via
        ``-MessageData $fileLog`` and the corresponding action reads it through
        ``$Event.MessageData``.
        """
        script = _TestQEMUSandbox.windows_agent_script_content_for_test()
        assert "$using:" not in script, "Register-ObjectEvent action blocks must not use $using: (invalid scope)"
        assert "Register-ObjectEvent $watcher 'Created' -MessageData $fileLog -Action {" in script, (
            "The file-creation watcher must bind the log path into the event via '-MessageData $fileLog'"
        )
        assert "$Event.MessageData" in script, "Agent action block must read the bound log path via '$Event.MessageData'"
        assert "Out-File -Append $Event.MessageData" in script, (
            "Agent action block must append the file-change record to the log path carried by $Event.MessageData"
        )


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

        result = asyncio.run(_run())
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

    def test_anti_evasion_profile_drives_real_smbios_argv(self, tmp_path: Path) -> None:
        """The launch profile drives the actual ``-smbios`` manufacturer in the QEMU argv.

        The earlier weak form only checked that ``apply_anti_evasion`` echoed
        its own ``profile`` argument back into the result dict. This gate
        instead drives the real ``_build_qemu_command`` with a ``workstation``
        launch config and verifies the observable side effect: the SMBIOS
        ``-smbios`` arguments carry the workstation vendor identity
        (``Dell Inc.``), and never the default vendor (``HP``). The expected
        vendor strings are the documented identity values
        (``_anti_evasion_identity``: workstation -> ``Dell Inc.``/``OptiPlex
        7090``; default -> ``HP``), used here as an independent oracle. A
        regression that ignored the profile and always emitted the default
        identity would leave ``Dell Inc.`` out of the argv and trip this gate.

        Args:
            tmp_path: Pytest temp directory.
        """
        image = tmp_path / "disk.qcow2"
        image.write_bytes(b"\x00" * 512)
        sb = _make_sandbox(accelerator=AcceleratorType.TCG)
        sb.set_qemu_config(
            QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                image_path=image,
                monitor_port=4444,
                ssh_port=2222,
                agent_port=4445,
                anti_evasion_profile="workstation",
            ),
        )
        sb.set_qemu_path(Path("qemu-system-x86_64"))
        sb.set_temp_dir(tmp_path)

        cmd = asyncio.run(sb.build_qemu_command_for_test())
        smbios_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-smbios"]
        assert smbios_values, "build must emit at least one -smbios argument"
        joined = "\n".join(smbios_values)

        assert "manufacturer=Dell Inc." in joined, (
            f"workstation profile must drive Dell Inc. SMBIOS vendor; argv smbios entries were {smbios_values!r}"
        )
        assert "product=OptiPlex 7090" in joined, (
            f"workstation profile must drive the OptiPlex 7090 product; argv smbios entries were {smbios_values!r}"
        )
        assert "manufacturer=HP" not in joined, (
            f"default HP vendor must not appear when launched as workstation; argv smbios entries were {smbios_values!r}"
        )

        sb.state.status = "running"
        sb.set_agent(_ConnectableAgent(connected=False))

        async def _run() -> dict[str, Any]:
            sb.set_qmp(MagicMock())
            return await sb.apply_anti_evasion(profile="workstation")

        result = asyncio.run(_run())
        assert result["profile"] == "workstation", f"apply_anti_evasion did not use the launch profile; got {result['profile']}"

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

    def test_laptop_profile_emits_laptop_specific_smbios_argv(self, tmp_path: Path) -> None:
        """The ``laptop`` profile produces laptop-specific SMBIOS argv distinct from default.

        ``apply_anti_evasion`` reports launch-time SMBIOS techniques as one
        ``smbios_type_N_launch_arg`` per entry, and the count must equal the
        number of SMBIOS entries the laptop profile defines (three). To pin the
        profile-to-guest-mutation flow itself - not just the count - this test
        also drives the real ``_build_qemu_command`` with a laptop launch config
        and asserts the laptop identity strings appear in the ``-smbios`` argv:
        manufacturer ``Lenovo``, product ``ThinkPad T14 Gen 3``, the type-2
        board product ``21AHS00000`` and the type-3 ``asset=21AHS00000``. The
        default type-3 asset ``8767`` and HP vendor must be absent. (SMBIOS
        type-3 exposes no ``chassis-type`` parameter in QEMU - passing one is
        rejected outright, S17-D19 - so the laptop chassis is distinguished by
        its asset tag instead.) These literals are the documented laptop
        identity (independent oracle), so confusing laptop with
        default/workstation trips the gate.

        Args:
            tmp_path: Pytest temp directory.
        """
        image = tmp_path / "disk.qcow2"
        image.write_bytes(b"\x00" * 512)
        sb = _make_sandbox(accelerator=AcceleratorType.TCG)
        sb.set_qemu_config(
            QEMUConfig(
                guest_os=GuestOS.WINDOWS,
                image_path=image,
                monitor_port=4444,
                ssh_port=2222,
                agent_port=4445,
                anti_evasion_profile="laptop",
            ),
        )
        sb.set_qemu_path(Path("qemu-system-x86_64"))
        sb.set_temp_dir(tmp_path)

        cmd = asyncio.run(sb.build_qemu_command_for_test())
        smbios_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-smbios"]
        assert len(smbios_values) == 3, f"laptop profile defines exactly three SMBIOS entries; got {smbios_values!r}"
        joined = "\n".join(smbios_values)

        assert "manufacturer=Lenovo" in joined, f"laptop profile must emit the Lenovo vendor; argv smbios entries were {smbios_values!r}"
        assert "product=ThinkPad T14 Gen 3" in joined, (
            f"laptop profile must emit the ThinkPad product; argv smbios entries were {smbios_values!r}"
        )
        assert "product=21AHS00000" in joined, (
            f"laptop profile must emit the laptop board product 21AHS00000; argv smbios entries were {smbios_values!r}"
        )
        assert "asset=21AHS00000" in joined, (
            f"laptop profile must emit the laptop type-3 asset tag; argv smbios entries were {smbios_values!r}"
        )
        assert "asset=8767" not in joined, (
            f"laptop profile must not emit the default desktop asset tag; argv smbios entries were {smbios_values!r}"
        )
        assert "chassis-type" not in joined, (
            f"chassis-type is not a valid SMBIOS type-3 parameter and must never be emitted; argv smbios entries were {smbios_values!r}"
        )
        assert "manufacturer=HP" not in joined, (
            f"default HP vendor must not appear for laptop profile; argv smbios entries were {smbios_values!r}"
        )

        sb.state.status = "running"
        sb.set_agent(_ConnectableAgent(connected=False))

        async def _run() -> dict[str, Any]:
            sb.set_qmp(MagicMock())
            return await sb.apply_anti_evasion(profile="laptop")

        result = asyncio.run(_run())
        assert result["profile"] == "laptop"
        smbios_techniques = [t for t in result["techniques"] if t.startswith("smbios_type_")]
        assert len(smbios_techniques) == 3, (
            f"apply_anti_evasion must report one technique per laptop SMBIOS entry; got {result['techniques']!r}"
        )


# ---------------------------------------------------------------------------
# F-0023 / S17-D59: list_snapshots reads the block layer, not a monitor table
# ---------------------------------------------------------------------------


def _snapshot_record(name: str) -> dict[str, object]:
    """Build one snapshot record in QEMU's own shape.

    Args:
        name: Snapshot tag.

    Returns:
        dict[str, object]: A record with the members QEMU reports.
    """
    return {
        "vm-clock-nsec": 931606000,
        "name": name,
        "date-sec": 1786140936,
        "date-nsec": 624721000,
        "vm-clock-sec": 1,
        "id": "1",
        "vm-state-size": 910100,
    }


def _block_device(node_name: str, snapshots: list[dict[str, object]] | None) -> dict[str, object]:
    """Build one ``query-block`` device record in QEMU's own shape.

    Args:
        node_name: Node name of the device's topmost layer.
        snapshots: Snapshot records the image holds, or None for an image
            that reports no ``snapshots`` member at all.

    Returns:
        dict[str, object]: A device record with an ``inserted`` medium.
    """
    image: dict[str, object] = {"filename": "guest.qcow2", "format": "qcow2"}
    if snapshots is not None:
        image["snapshots"] = snapshots
    return {
        "device": "virtio0",
        "locked": False,
        "removable": False,
        "inserted": {"node-name": node_name, "drv": "qcow2", "ro": False, "image": image},
    }


class _RecordedQueryBlock:
    """QMP stand-in that answers ``query-block`` with a real reply shape.

    The payloads are the ones a real QEMU 10.1 returns, captured from a live
    monitor. This deliberately exposes no ``info_snapshots``: an implementation
    that went back to parsing the monitor's text table would find nothing to
    call.

    Attributes:
        devices: Device records to return.
        success: Whether the query is reported as having succeeded.
    """

    devices: list[dict[str, object]]
    success: bool

    def __init__(self, devices: list[dict[str, object]], *, success: bool = True) -> None:
        """Record what the monitor should answer.

        Args:
            devices: Device records to return.
            success: Whether the query is reported as having succeeded.
        """
        self.devices = devices
        self.success = success

    async def query_block(self) -> QMPResponse:
        """Answer the block-device query.

        Returns:
            QMPResponse: The recorded reply.
        """
        return QMPResponse(success=self.success, data=list(self.devices))


class TestListSnapshotsReadsTheBlockLayer:
    """S17-D59: the snapshot list must come from structured block-layer data.

    The previous implementation parsed the ``info snapshots`` monitor table by
    column and kept only rows whose first field was numeric. QEMU 10.1 prints
    ``--`` in that column, so every row was discarded and the list came back
    empty for a disk that plainly held snapshots - which is what produced the
    live ``count: 0`` immediately after a snapshot was created.
    """

    def test_names_come_back_from_a_real_query_block_reply(self) -> None:
        """Every snapshot the block layer reports must be listed."""
        sb = _make_sandbox()
        sb.set_qmp(
            _RecordedQueryBlock([
                _block_device("#block190", [_snapshot_record("clean_state"), _snapshot_record("post_install")]),
            ]),
        )

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.run(_run())
        assert result == ["clean_state", "post_install"], f"expected both snapshots in device order; got {result}"

    def test_a_disk_holding_no_snapshots_contributes_nothing(self) -> None:
        """An image with no ``snapshots`` member yields no names."""
        sb = _make_sandbox()
        sb.set_qmp(_RecordedQueryBlock([_block_device("#block190", None)]))

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.run(_run())
        assert result == [], f"expected [] for a disk with no snapshots; got {result}"

    def test_a_name_spanning_two_disks_is_listed_once(self) -> None:
        """A snapshot taken across several disks is one snapshot, not several.

        ``snapshot-save`` writes the tag into every device it is given, so a
        two-disk guest reports the same name twice.
        """
        sb = _make_sandbox()
        sb.set_qmp(
            _RecordedQueryBlock([
                _block_device("#block190", [_snapshot_record("checkpoint")]),
                _block_device("#block240", [_snapshot_record("checkpoint")]),
            ]),
        )

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        result = asyncio.run(_run())
        assert result == ["checkpoint"], f"a snapshot spanning two disks must be listed once; got {result}"

    def test_a_refused_query_is_not_reported_as_an_empty_list(self) -> None:
        """A monitor that refuses the query must not look like "no snapshots".

        This is the same false-negative shape as the defect itself: "there are
        none" and "I could not find out" must not be the same answer.
        """
        sb = _make_sandbox()
        sb.set_qmp(_RecordedQueryBlock([], success=False))

        async def _run() -> list[str]:
            return await sb.list_snapshots()

        with pytest.raises(SandboxError):
            asyncio.run(_run())


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

        asyncio.run(_run())

        assert len(sb.get_active_captures()) == 0, "stop() must clear _active_captures; resource leak remains if not emptied"


# ---------------------------------------------------------------------------
# F-0028: yara_scan must NOT scan user input on fallback
# ---------------------------------------------------------------------------


class TestF0028YaraScanFallback:
    """F-0028: yara_scan fallback must scan dropped-file zips, not the input folder."""

    def test_yara_scan_uses_output_dir_not_input_on_no_zip(self, tmp_path: Path) -> None:
        """With no dropped-file zip the scan reads collected output, never the input dir.

        The old bug fell back to scanning shared/input/, which holds whatever
        the user originally submitted rather than anything the guest produced.
        Both files here carry content the built-in rules match, so a scan that
        strayed into the input directory would say so in its own results: the
        real engine runs, and the only rule that may come back is the one from
        the collected artifact.

        Args:
            tmp_path: Pytest temp directory.
        """
        shared = tmp_path / "shared"
        input_dir = shared / "input"
        output_dir = shared / "output"
        input_dir.mkdir(parents=True)
        output_dir.mkdir(parents=True)

        user_file = input_dir / "user_submitted.exe"
        user_file.write_bytes(b"MZ" + b"\x00" * 32 + b"CreateRemoteThread\x00")
        collected = output_dir / "collected.bin"
        collected.write_bytes(b"MZ" + b"\x00" * 32 + b"UPX!" + b"\x00" * 16)

        sb = _make_sandbox(shared_folder=shared)
        matches = asyncio.run(sb.yara_scan(scan_target="files"))

        sources = {Path(str(match["source"])).resolve() for match in matches}
        assert sources == {collected.resolve()}, f"yara_scan scanned something other than the collected artifact: {sources}"
        assert {match["rule"] for match in matches} == {"PackedBinary"}

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

        yara_module = require_yara()

        sb = _make_sandbox(shared_folder=shared)

        async def _run() -> list[dict[str, Any]]:
            with patch.object(yara_module, "compile", side_effect=_FakeYara2.compile):
                return await sb.yara_scan(scan_target="files")

        asyncio.run(_run())

        assert scanned_paths, "yara_scan did not scan any files from the zip"
        normalized = [Path(p) for p in scanned_paths]
        assert any(p.name == "artifact.bin" for p in normalized), (
            f"yara_scan must scan the artifact extracted from the dropped-files zip; scanned {scanned_paths!r}"
        )
        input_dir_resolved = input_dir.resolve()
        for p in normalized:
            assert input_dir_resolved not in p.resolve().parents, f"yara_scan must not scan anything under shared/input; found '{p}'"


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

        elapsed = asyncio.run(_run())
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

        return asyncio.run(_run())

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

    def test_windows_startup_script_wires_agent(self, tmp_path: Path) -> None:
        """``start_agent.cmd`` must exist and actually launch the Windows agent script.

        F-0006 is "startup entry point wired in", so existence of *some* file is
        not enough: the startup wrapper itself must be present and must reference
        and launch the agent it is meant to start. This gate requires the
        specific ``start_agent.cmd`` file and asserts (a) it invokes
        ``powershell.exe`` and (b) it targets the guest agent script
        ``agent.ps1`` that ``_create_guest_agent_script`` also wrote into the
        same directory. Both the agent and the wiring must be present.

        Args:
            tmp_path: Pytest temp directory.
        """
        monitor_dir = tmp_path / "monitor"
        monitor_dir.mkdir()

        sb = _make_sandbox(guest_os=GuestOS.WINDOWS)
        sb.set_shared_folder(tmp_path)

        async def _run() -> None:
            await sb.create_agent_script_for_test()

        asyncio.run(_run())

        startup_script = monitor_dir / "start_agent.cmd"
        agent_script = monitor_dir / "agent.ps1"
        assert startup_script.is_file(), "Windows startup wrapper start_agent.cmd was not created"
        assert agent_script.is_file(), "Windows agent.ps1 was not created"

        startup_text = startup_script.read_text(encoding="utf-8")
        assert "powershell.exe" in startup_text.lower(), f"start_agent.cmd must launch powershell.exe; got {startup_text!r}"
        assert "agent.ps1" in startup_text, f"start_agent.cmd must reference the agent script agent.ps1; got {startup_text!r}"

    def test_linux_startup_script_wires_agent(self, tmp_path: Path) -> None:
        """``start_agent.sh`` must exist and actually launch the Linux agent script.

        Mirrors the Windows gate: the specific ``start_agent.sh`` wrapper must be
        created and must invoke the Python agent it starts
        (``python3 .../agent.py``), and the ``agent.py`` itself must also be
        written. Existence of an ``agent.*`` file alone is insufficient because
        the F-0006 fix is the startup wiring.

        Args:
            tmp_path: Pytest temp directory.
        """
        monitor_dir = tmp_path / "monitor"
        monitor_dir.mkdir()

        sb = _make_sandbox(guest_os=GuestOS.LINUX)
        sb.set_shared_folder(tmp_path)

        async def _run() -> None:
            await sb.create_agent_script_for_test()

        asyncio.run(_run())

        startup_script = monitor_dir / "start_agent.sh"
        agent_script = monitor_dir / "agent.py"
        assert startup_script.is_file(), "Linux startup wrapper start_agent.sh was not created"
        assert agent_script.is_file(), "Linux agent.py was not created"

        startup_text = startup_script.read_text(encoding="utf-8")
        assert "python3" in startup_text, f"start_agent.sh must invoke python3; got {startup_text!r}"
        assert "agent.py" in startup_text, f"start_agent.sh must reference the agent script agent.py; got {startup_text!r}"


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

        asyncio.run(_run())

        assert detect_call_count == 0, f"_detect_accelerator was called {detect_call_count} times but must be 0 when cache is already valid"


# ---------------------------------------------------------------------------
# F-0007: extract_dropped_files must work without agent and produce a zip
# ---------------------------------------------------------------------------


class TestF0007ExtractDroppedFiles:
    """F-0007: extract_dropped_files must produce a valid zip when files are present."""

    def test_extract_produces_zip_without_agent(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """extract_dropped_files uses the host-side dropped mirror when no agent.

        The fixed implementation (audit7 U07) requires the guest's monitor to
        mirror dropped files to ``<shared>/output/dropped/`` so the host-side
        fallback can collect them when the agent is disconnected. That mirror
        only exists on the virtio-9p transport: since S17-D69 the FAT transport
        exposes the share read-only, because vvfat's write-back path aborts the
        machine, so the host constant is redirected here to select the
        transport whose contract this is.

        Args:
            monkeypatch: Fixture used to select the virtio-9p transport.
            tmp_path: Pytest temp directory.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", False)
        shared = tmp_path / "shared"
        (shared / "input").mkdir(parents=True)
        (shared / "output").mkdir(parents=True)
        mirror = shared / "output" / "dropped"
        mirror.mkdir(parents=True)
        (mirror / "dropped_sample.bin").write_bytes(b"\xde\xad\xbe\xef")

        sb = _make_sandbox(guest_os=GuestOS.LINUX, shared_folder=shared)
        sb.state.status = "running"
        sb.set_agent(None)

        async def _run() -> Path:
            return await sb.extract_dropped_files()

        result = asyncio.run(_run())
        assert result.exists(), "extract_dropped_files must return an existing zip path"
        assert result.suffix == ".zip", f"Expected .zip file; got {result.suffix}"
        assert zipfile.is_zipfile(result), "Output file must be a valid zip archive"
        with zipfile.ZipFile(result) as zf:
            names = zf.namelist()
        assert any(n.endswith("dropped_sample.bin") for n in names), f"Expected dropped_sample.bin in archive, found {names}"
