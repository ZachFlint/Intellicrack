# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the sandboxed launch of a local MCP server.

The platform-independent half of a confined launch -- the environment
allowlist, program resolution, the command line a ``.cmd`` shim runs under,
the creation flags, the stated limitations, and the pipe bridge the session
talks through -- is gated here on every platform, the bridge against a real
``MCPServer`` subprocess.

The Win32 half -- a process created suspended inside its job with a
restricted Low integrity token, and writes confined to ``allowWrite`` -- can
only run on Windows, and those gates are skipped elsewhere with the behaviour
they cover named in the reason.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import psutil
import pytest
from anyio.streams.file import FileReadStream, FileWriteStream
from mcp import Client
from mcp.shared.exceptions import MCPError

from intellicrack.mcp.config import McpSandboxSpec, StdioServerSpec
from intellicrack.mcp.errors import McpConfigError, McpConnectionError
from intellicrack.mcp.sandbox_launch import (
    CREATE_SUSPENDED,
    SANDBOX_TEMP_DIRNAME,
    JobLimits,
    build_sandboxed_startup,
    environment_block,
    pipe_session_streams,
    plan_sandboxed_launch,
    quote_windows_argument,
    render_command_line,
    sandbox_limitations,
)
from tests._helpers.mcp_lifecycle_support import SERVER_SCRIPT, approving_gate, call_text, connection_for, stdio_config


_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_WINDOWS_ROOT = "C:\\Windows"
_SECRET_NAME = "INTELLICRACK_SANDBOX_TEST_SECRET"
_CONNECT_TIMEOUT_S = 120.0
_TEARDOWN_TIMEOUT_S = 30.0
_GONE_TIMEOUT_S = 15.0


def _program(directory: Path, name: str) -> Path:
    """Create an empty file standing for an installed program.

    Args:
        directory: Where to create it.
        name: Its file name.

    Returns:
        Path: The created file.
    """
    path = directory / name
    path.write_bytes(b"")
    return path


def _inherited(bin_dir: Path) -> dict[str, str]:
    """Build an environment like the one Intellicrack runs with on Windows.

    Args:
        bin_dir: Directory the program under test is installed in.

    Returns:
        dict[str, str]: The environment, credentials included.
    """
    return {
        "PATH": str(bin_dir),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "SystemRoot": _WINDOWS_ROOT,
        "TEMP": "C:\\Users\\operator\\AppData\\Local\\Temp",
        "USERPROFILE": "C:\\Users\\operator",
        "APPDATA": "C:\\Users\\operator\\AppData\\Roaming",
        "OPENAI_API_KEY": "sk-not-for-the-server",
        _SECRET_NAME: "secret",
    }


def _sandbox(*writable: Path, domains: tuple[str, ...] = ()) -> McpSandboxSpec:
    """Build an enabled sandbox.

    Args:
        *writable: Directories the server may write to.
        domains: Hosts the operator expects the server to reach.

    Returns:
        McpSandboxSpec: The sandbox settings.
    """
    return McpSandboxSpec(enabled=True, allow_write=tuple(str(path) for path in writable), allowed_domains=domains)


class TestEnvironmentAllowlist:
    """The confined child's environment is exactly the allowlist plus its own entries."""

    def test_environment_is_the_allowlist_and_nothing_else(self, tmp_path: Path) -> None:
        """Credentials, profile paths and the operator's TEMP do not reach the child.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        _ = _program(bin_dir, "server.exe")
        spec = StdioServerSpec(command="server")
        launch = plan_sandboxed_launch(spec, _sandbox(work), {"SERVER_FLAG": "1"}, _inherited(bin_dir))
        temp = str(work.resolve() / SANDBOX_TEMP_DIRNAME)
        assert dict(launch.env) == {
            "PATH": str(bin_dir),
            "PATHEXT": ".COM;.EXE;.BAT;.CMD",
            "SystemRoot": _WINDOWS_ROOT,
            "TEMP": temp,
            "TMP": temp,
            "SERVER_FLAG": "1",
        }
        assert launch.temp_dir == temp

    def test_environment_block_is_sorted_and_terminated(self) -> None:
        """The Win32 block is sorted case-insensitively and double-NUL terminated."""
        block = environment_block({"b": "2", "A": "1", "c": "3"})
        assert block == "A=1\0b=2\0c=3\0\0"

    def test_environment_block_refuses_an_unrepresentable_name(self) -> None:
        """A name containing ``=`` cannot be expressed in a Win32 block."""
        with pytest.raises(McpConfigError):
            _ = environment_block({"A=B": "1"})


class TestProgramResolution:
    """The program is found on the child's own PATH and launched without a shell."""

    def test_native_program_is_created_suspended_without_breakaway(self, tmp_path: Path) -> None:
        """The launch is suspended at creation, never breaks away, and uses the job limits.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        program = _program(bin_dir, "server.exe")
        spec = StdioServerSpec(command="server", args=("--port", "a b", 'say "hi"'))
        launch = plan_sandboxed_launch(spec, _sandbox(work), {}, _inherited(bin_dir))
        assert launch.command == str(program.resolve())
        assert launch.application == launch.command
        assert launch.creation_flags & CREATE_SUSPENDED
        assert not launch.creation_flags & _CREATE_BREAKAWAY_FROM_JOB
        assert launch.limits == JobLimits()
        assert launch.command_line == subprocess.list2cmdline([launch.command, "--port", "a b", 'say "hi"'])

    def test_batch_shim_runs_under_the_system_command_interpreter(self, tmp_path: Path) -> None:
        """A ``.cmd`` shim runs through ``cmd.exe`` with every token quoted.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        shim = _program(bin_dir, "npx.cmd")
        spec = StdioServerSpec(command="npx", args=("-y", "@scope/server & calc"))
        inherited = _inherited(bin_dir) | {"COMSPEC": "C:\\attacker\\cmd.exe"}
        launch = plan_sandboxed_launch(spec, _sandbox(work), {}, inherited)
        interpreter = "C:\\Windows\\System32\\cmd.exe"
        assert launch.is_batch_script
        assert launch.command == str(shim.resolve())
        assert launch.application == interpreter
        assert launch.command_line == f'"{interpreter}" /d /v:off /s /c ""{shim.resolve()}" "-y" "@scope/server & calc""'

    @pytest.mark.parametrize("argument", ["%USERPROFILE%", 'a"b', "line\nbreak"])
    def test_batch_shim_refuses_arguments_cmd_would_rewrite(self, argument: str) -> None:
        """An argument the command interpreter would expand or re-quote is refused.

        Args:
            argument: The dangerous argument.
        """
        with pytest.raises(McpConfigError, match="command interpreter"):
            _ = render_command_line("C:\\Windows\\System32\\cmd.exe", "C:\\tools\\npx.cmd", ["-y", argument])

    def test_missing_program_is_refused(self, tmp_path: Path) -> None:
        """A command absent from the child's PATH fails before anything is created.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        with pytest.raises(McpConfigError, match="cannot find"):
            _ = plan_sandboxed_launch(StdioServerSpec(command="absent"), _sandbox(work), {}, _inherited(tmp_path))

    @pytest.mark.parametrize(
        "argument",
        ["plain", "", "with space", "tab\there", 'quote"inside', "trailing\\", 'slash\\\\before\\"quote', "C:\\Program Files\\x\\"],
    )
    def test_argument_quoting_matches_the_msvc_rules(self, argument: str) -> None:
        """Quoting agrees with the standard library's rendering of the MSVC rules.

        Args:
            argument: The argument to quote.
        """
        assert quote_windows_argument(argument) == subprocess.list2cmdline([argument])


class TestStatedLimitations:
    """The sandbox says plainly what it does not enforce."""

    def test_allowed_domains_are_reported_as_not_enforced(self) -> None:
        """Listing domains does not claim network confinement."""
        limitations = sandbox_limitations(_sandbox(Path("C:\\work"), domains=("models.internal", "registry.internal")))
        assert limitations[0] == (
            "Network access is not restricted: allowedDomains (models.internal, registry.internal) is recorded only and is not enforced."
        )

    def test_disabled_sandbox_claims_nothing(self) -> None:
        """A disabled sandbox has no limitations to state because it claims nothing."""
        assert sandbox_limitations(McpSandboxSpec()) == ()


class TestPipeBridge:
    """The confined launch's pipe bridge carries a real session."""

    def test_bridge_drives_a_real_server_and_reports_its_exit(self) -> None:
        """A session runs over the bridge, and the server's exit ends the read stream."""
        process = subprocess.Popen(
            [sys.executable, str(SERVER_SCRIPT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        stdin, stdout = process.stdin, process.stdout
        assert stdin is not None
        assert stdout is not None
        stopped: list[int | None] = []

        async def shutdown() -> None:
            if process.poll() is None:
                process.terminate()
            stopped.append(await asyncio.to_thread(process.wait, 10))

        async def body() -> tuple[str, str]:
            async with Client(pipe_session_streams(FileReadStream(stdout), FileWriteStream(stdin), shutdown)) as client:
                result = await client.call_tool("whoami", {})
                pid = getattr(result.content[0], "text", "")
                _ = await client.call_tool("quit", {})
                await asyncio.sleep(1.5)
                try:
                    _ = await client.call_tool("whoami", {})
                except MCPError as exc:
                    return pid, exc.error.message
                return pid, "still answering"

        pid, after = asyncio.run(asyncio.wait_for(body(), timeout=_CONNECT_TIMEOUT_S))
        assert pid == str(process.pid)
        assert after == "Connection closed"
        assert stopped == [0]


@pytest.mark.skipif(sys.platform == "win32", reason="the refusal applies only where Windows confinement is unavailable")
class TestRefusedOffWindows:
    """A sandboxed server is never started unconfined."""

    def test_sandboxed_launch_is_refused(self, tmp_path: Path) -> None:
        """Planning a launch works, but building one on this platform is refused.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        with pytest.raises(McpConfigError, match="not available on this platform"):
            _ = build_sandboxed_startup(StdioServerSpec(command=sys.executable), _sandbox(tmp_path), {})

    def test_sandboxed_connection_starts_nothing(self, tmp_path: Path) -> None:
        """The connection refuses before any process is spawned.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        before = {child.pid for child in psutil.Process().children(recursive=True)}
        config = stdio_config("sandboxed", sandbox=_sandbox(tmp_path))
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))
        with pytest.raises(McpConnectionError, match="sandboxed"):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))
        after = {child.pid for child in psutil.Process().children(recursive=True)}
        assert after <= before


def _is_in_job(pid: int) -> bool:
    """Ask Windows whether a process runs inside any job object.

    Args:
        pid: The process to inspect.

    Returns:
        bool: ``True`` when it is in a job.

    Raises:
        ctypes.WinError: If the process could not be opened or queried.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(0x1000, 0, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = wintypes.BOOL()
        if not kernel32.IsProcessInJob(wintypes.HANDLE(handle), None, ctypes.byref(result)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(result.value)
    finally:
        _ = kernel32.CloseHandle(wintypes.HANDLE(handle))


def _gone(pid: int) -> bool:
    """Wait for a process to disappear.

    Args:
        pid: The process.

    Returns:
        bool: ``True`` once it is gone.
    """
    deadline = time.monotonic() + _GONE_TIMEOUT_S
    while time.monotonic() < deadline:
        if not psutil.pid_exists(pid):
            return True
        time.sleep(0.1)
    return False


async def _run_confined(server_id: str, tmp_path: Path, command: str, args: tuple[str, ...], work: Path) -> tuple[int, bool]:
    """Connect to a confined server, check it is in a job, and tear it down.

    Args:
        server_id: The server id.
        tmp_path: Directory backing the trust store.
        command: The launch command.
        args: Its arguments.
        work: The sandbox's writable directory.

    Returns:
        tuple[int, bool]: The server's process id and whether it ran in a job.
    """
    config = stdio_config(server_id, command=command, args=args, sandbox=_sandbox(work))
    connection = connection_for(config, approving_gate(tmp_path / "trust.json"))
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        pid = int(await call_text(connection, "whoami"))
        return pid, _is_in_job(pid)
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows job object: process created suspended inside its job, tree killed on close")
class TestWindowsJobConfinement:
    """The server and everything it starts are inside the job from creation."""

    def test_server_and_its_startup_child_are_confined(self, tmp_path: Path) -> None:
        """A child started before the handshake is in the job and dies with it.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        pid_file = work / "early.pid"
        pid, in_job = asyncio.run(
            _run_confined("confined", tmp_path, sys.executable, (str(SERVER_SCRIPT), "--spawn-at-start", str(pid_file)), work),
        )
        early = int(pid_file.read_text(encoding="utf-8"))
        assert in_job
        assert _gone(pid)
        assert _gone(early), "a child the server started before its handshake survived the job"

    def test_cmd_shim_server_is_confined(self, tmp_path: Path) -> None:
        """A server launched through a ``.cmd`` shim connects and is confined.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        shim = work / "server.cmd"
        shim.write_text(f'@echo off\r\n"{sys.executable}" "{SERVER_SCRIPT}" %*\r\n', encoding="utf-8")
        pid_file = work / "early.pid"
        pid, in_job = asyncio.run(_run_confined("shim", tmp_path, str(shim), ("--spawn-at-start", str(pid_file)), work))
        assert in_job
        assert _gone(pid)
        assert _gone(int(pid_file.read_text(encoding="utf-8")))

    def test_venv_launcher_server_is_confined(self, tmp_path: Path) -> None:
        """A venv ``python.exe``, a launcher that starts the real interpreter, is confined.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        venv = tmp_path / "venv"
        _ = subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=300)
        interpreter = venv / "Scripts" / "python.exe"
        site = os.pathsep.join(entry for entry in sys.path if entry)
        config = stdio_config("venv", command=str(interpreter), args=(str(SERVER_SCRIPT),), sandbox=_sandbox(work))
        spec = config.stdio
        assert spec is not None
        config = type(config)(
            server_id=config.server_id,
            kind=config.kind,
            stdio=type(spec)(command=spec.command, args=spec.args, env={"PYTHONPATH": site}),
            enabled=True,
            sandbox=config.sandbox,
            request_timeout_s=config.request_timeout_s,
        )
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))

        async def body() -> int:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                return int(await call_text(connection, "whoami"))
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        pid = asyncio.run(body())
        assert _gone(pid)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows restricted Low integrity token and allowWrite write confinement")
class TestWindowsTokenAndWrites:
    """The server's token confines its writes and its environment."""

    def test_writes_are_confined_to_allow_write(self, tmp_path: Path) -> None:
        """The server can write inside ``allowWrite`` and nowhere else the operator owns.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        config = stdio_config("writes", sandbox=_sandbox(work))
        connection = connection_for(config, approving_gate(tmp_path / "trust.json"))

        async def body() -> tuple[str, str]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                inside = await call_text(connection, "write_probe", {"path": str(work / "inside.txt")})
                denied = await call_text(connection, "write_probe", {"path": str(outside / "outside.txt")})
                return inside, denied
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        inside, denied = asyncio.run(body())
        assert inside == "written"
        assert denied.startswith("denied"), f"a write outside allowWrite succeeded: {denied}"
        assert not (outside / "outside.txt").exists()

    def test_server_environment_is_the_allowlist(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nothing outside the allowlist reaches the server, not even the SDK's defaults.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest fixture used to plant a secret in the environment.
        """
        monkeypatch.setenv(_SECRET_NAME, "secret")
        work = tmp_path / "work"
        work.mkdir()
        connection = connection_for(stdio_config("environ", sandbox=_sandbox(work)), approving_gate(tmp_path / "trust.json"))

        async def body() -> set[str]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                return {name.upper() for name in (await call_text(connection, "env_keys")).splitlines()}
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        names = asyncio.run(body())
        assert _SECRET_NAME not in names
        assert not names & {"USERPROFILE", "APPDATA", "LOCALAPPDATA", "USERNAME", "HOMEPATH"}
