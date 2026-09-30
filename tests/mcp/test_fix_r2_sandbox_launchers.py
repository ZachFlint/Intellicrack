# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 10: common launchers run sandboxed, with their own home, arguments intact, and advice when they need more.

The platform-independent half is gated everywhere: the command line a ``.cmd`` shim runs under, parsed back with the MSVC rules the
program behind the shim uses; the environment that points every launcher at the server's own sandbox home; the variables the operator
chose to pass through; the notes each launcher comes with; the advice drawn from a refused access; and the rule that a failed resume is a
failure whatever the last error reads.

The Win32 half runs real launchers -- node, npx, python, uv, uvx and pipx -- confined at Low integrity inside their job, each reporting
where its temporary directory and home are and whether it could write there, and runs a sandboxed server through a ``.cmd`` shim with an
argument ending in a backslash. It can only run on Windows and is skipped elsewhere with the behaviour it covers named in the reason.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
import threading
import zipfile
from itertools import starmap
from pathlib import Path
from typing import TYPE_CHECKING, Final

import anyio
import pytest
from mcp_types import JSONRPCNotification

from intellicrack.core.handle_inheritance import INHERITANCE_LOCK
from intellicrack.core.json_payload import JsonObject, is_json_object
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import McpSandboxSpec, StdioServerSpec, launcher_name, launcher_notes
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.sandbox_launch import (
    SANDBOX_HOME_LAYOUT,
    SandboxConfinementError,
    SandboxHome,
    build_sandboxed_startup,
    check_resumed,
    confined_stdio_client,
    plan_sandboxed_launch,
    render_command_line,
    sandbox_access_guidance,
)
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_lifecycle_support import SERVER_SCRIPT, approving_gate, call_text, stdio_config


if TYPE_CHECKING:
    from intellicrack.mcp.config import McpServerConfig


_INTERPRETER: Final[str] = "C:\\Windows\\System32\\cmd.exe"
_SHIM: Final[str] = "C:\\tools\\npx.cmd"
_RESUME_FAILED: Final[int] = 0xFFFFFFFF
_ACCESS_DENIED_WIN32: Final[int] = 5
_PROBE_TIMEOUT_S: Final[float] = 300.0
_CONNECT_TIMEOUT_S: Final[float] = 120.0
_TEARDOWN_TIMEOUT_S: Final[float] = 30.0
_LOCK_HELD_S: Final[float] = 3.0


def _msvc_argv(command_line: str) -> list[str]:
    """Split a command line the way the Microsoft C runtime does.

    Backslashes are literal except before a double quote: ``2n`` of them and a quote give ``n`` backslashes and toggle quoting, ``2n + 1``
    of them and a quote give ``n`` backslashes and a literal quote.

    Args:
        command_line: The command line.

    Returns:
        list[str]: The arguments.
    """
    arguments: list[str] = []
    current: list[str] = []
    quoted = False
    started = False
    index = 0
    while index < len(command_line):
        character = command_line[index]
        if character == "\\":
            run = len(command_line[index:]) - len(command_line[index:].lstrip("\\"))
            index += run
            if index < len(command_line) and command_line[index] == '"':
                current.append("\\" * (run // 2))
                if run % 2:
                    current.append('"')
                    index += 1
                started = True
                continue
            current.append("\\" * run)
            started = True
            continue
        if character == '"':
            quoted = not quoted
            started = True
        elif character in " \t" and not quoted:
            if started:
                arguments.append("".join(current))
                current, started = [], False
        else:
            current.append(character)
            started = True
        index += 1
    if started:
        arguments.append("".join(current))
    return arguments


def _arguments_behind_shim(command_line: str) -> list[str]:
    """Recover the arguments the program behind a batch shim receives.

    ``cmd /s /c "..."`` strips the outer quotes and runs the rest; the shim hands everything after its own name on as ``%*``, which the
    program parses with the MSVC rules.

    Args:
        command_line: The rendered command line.

    Returns:
        list[str]: The shim's path followed by the arguments the program sees.
    """
    inner = command_line.split(' /c "', 1)[1]
    assert inner.endswith('"')
    return _msvc_argv(inner[:-1])


class TestBatchShimArguments:
    """An argument ending in a backslash reaches the program behind a ``.cmd`` shim intact."""

    @pytest.mark.parametrize(
        "arguments",
        [
            ["-y", "@scope/server", "C:\\proj\\", "--flag"],
            ["C:\\a b\\", "C:\\c\\\\", "last"],
            ["--root=C:\\", "x & y", "(z)"],
        ],
        ids=["trailing-backslash", "doubled-backslashes", "drive-root"],
    )
    def test_arguments_arrive_as_given(self, arguments: list[str]) -> None:
        """Every argument, trailing backslashes included, is parsed back exactly.

        Args:
            arguments: The arguments configured for the server.
        """
        line = render_command_line(_INTERPRETER, _SHIM, arguments)

        assert _arguments_behind_shim(line) == [_SHIM, *arguments]


class TestSandboxHome:
    """Every launcher is pointed at the server's own home, and the operator's choices win over it."""

    def test_every_launcher_variable_names_a_directory_in_the_home(self, tmp_path: Path) -> None:
        """Temporary files, profile, application data and the npm, uv, pip and pipx locations are all inside the home.

        Args:
            tmp_path: Per-test directory.
        """
        home = SandboxHome(str(tmp_path / "home"))
        environment = home.environment()

        expected = {name for _, names in SANDBOX_HOME_LAYOUT for name in names}
        assert expected >= {
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HOME",
            "LOCALAPPDATA",
            "APPDATA",
            "npm_config_cache",
            "UV_CACHE_DIR",
            "UV_TOOL_DIR",
            "UV_PYTHON_INSTALL_DIR",
            "PIP_CACHE_DIR",
            "PIPX_HOME",
        }
        assert set(environment) == expected
        for value in environment.values():
            assert Path(value).is_relative_to(tmp_path / "home")
        home.create()
        assert all(Path(directory).is_dir() for directory in home.directories())

    def test_inherited_and_configured_variables_win_without_duplicates(self, tmp_path: Path) -> None:
        """A variable named in inheritEnv passes through over the home, a configured one over both, and no name appears twice.

        Args:
            tmp_path: Per-test directory.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "server.exe").write_bytes(b"")
        work = tmp_path / "work"
        work.mkdir()
        home = SandboxHome(str(tmp_path / "home"))
        inherited = {
            "PATH": str(bin_dir),
            "PATHEXT": ".EXE",
            "Https_Proxy": "http://proxy.internal:3128",
            "localappdata": "C:\\Users\\operator\\AppData\\Local",
            "OPENAI_API_KEY": "sk-not-for-the-server",
        }
        sandbox = McpSandboxSpec(enabled=True, allow_write=(str(work),), inherit_env=("HTTPS_PROXY", "LOCALAPPDATA"))

        launch = plan_sandboxed_launch(StdioServerSpec(command="server"), sandbox, {"uv_cache_dir": "D:\\cache"}, inherited, home=home)

        upper = [name.upper() for name in launch.env]
        assert len(upper) == len(set(upper))
        assert launch.env["Https_Proxy"] == "http://proxy.internal:3128"
        assert launch.env["localappdata"] == "C:\\Users\\operator\\AppData\\Local"
        assert launch.env["uv_cache_dir"] == "D:\\cache"
        assert launch.env["TEMP"] == home.temp
        assert "OPENAI_API_KEY" not in launch.env


class TestLauncherNotes:
    """Each common launcher comes with what the operator needs to know when it runs sandboxed."""

    @pytest.mark.parametrize(
        ("command", "name"),
        [
            ("npx", "npx"),
            ("C:\\Program Files\\nodejs\\npx.cmd", "npx"),
            ("uvx.exe", "uvx"),
            ("C:/Python313/python.exe", "python"),
            ("python3.13", "python"),
            ("docker", "docker"),
        ],
    )
    def test_launcher_is_recognised(self, command: str, name: str) -> None:
        """A bare name, a path, a suffix or a version all reduce to the launcher.

        Args:
            command: The configured command.
            name: The launcher it runs.
        """
        assert launcher_name(command) == name
        assert launcher_notes(command)

    def test_container_client_is_told_to_turn_the_sandbox_off(self) -> None:
        """A sandboxed container client cannot reach the engine, and the note says what to do instead."""
        [note] = launcher_notes("docker")

        assert "Low integrity" in note
        assert "Turn this server's sandbox off" in note

    def test_other_programs_have_no_notes(self) -> None:
        """A program that is not a known launcher gets nothing."""
        assert launcher_notes("C:\\tools\\my-server.exe") == ()


class TestRefusedAccessAdvice:
    """A server that failed on a refused access tells the operator which setting to change."""

    @pytest.mark.parametrize(
        ("stderr", "path"),
        [
            (
                ["Error: EPERM: operation not permitted, mkdir 'C:\\Users\\op\\AppData\\Local\\npm-cache'"],
                "C:\\Users\\op\\AppData\\Local\\npm-cache",
            ),
            (["PermissionError: [WinError 5] Access is denied: 'C:\\\\data\\\\out.txt'"], "C:\\data\\out.txt"),
            (
                [
                    "error: Failed to initialize cache at `C:\\Users\\op\\AppData\\Local\\uv\\cache`",
                    "  Caused by: Access is denied. (os error 5)",
                ],
                "C:\\Users\\op\\AppData\\Local\\uv\\cache",
            ),
        ],
        ids=["node", "python", "uv"],
    )
    def test_refused_path_is_named_with_the_settings_to_change(self, stderr: list[str], path: str) -> None:
        """The advice names the refused path and both settings that can fix it.

        Args:
            stderr: What the server wrote before it failed.
            path: The path it was refused.
        """
        advice = sandbox_access_guidance(stderr)

        assert advice is not None
        assert f"access to {path}." in advice
        assert "sandbox.allowWrite" in advice
        assert "sandbox.inheritEnv" in advice

    def test_other_failures_get_no_advice(self) -> None:
        """A server that failed for another reason is not told to change its sandbox."""
        assert sandbox_access_guidance(["Traceback (most recent call last):", "ValueError: bad port"]) is None


class TestResumeFailure:
    """A resume that failed is a failure whatever the last error reads."""

    def test_failure_without_an_error_code_is_still_a_failure(self) -> None:
        """``ResumeThread`` returning -1 with a zero last error raises instead of leaving the server suspended."""
        with pytest.raises(SandboxConfinementError, match="without reporting a reason") as caught:
            check_resumed(_RESUME_FAILED, 0)

        assert isinstance(caught.value, OSError)
        assert caught.value.step == "ResumeThread"

    def test_failure_with_an_error_code_carries_it(self) -> None:
        """A failure with a last error reports that error."""
        with pytest.raises(SandboxConfinementError) as caught:
            check_resumed(_RESUME_FAILED, _ACCESS_DENIED_WIN32)

        assert caught.value.error == _ACCESS_DENIED_WIN32

    def test_a_resumed_thread_passes(self) -> None:
        """A thread that was suspended once and is now running is not a failure."""
        check_resumed(1, 0)


_PYTHON_PROBE: Final[str] = """
import json, os, pathlib, sys, tempfile

def main():
    report = {"tmp": tempfile.gettempdir(), "home": os.path.expanduser("~"), "env": {k: os.environ.get(k, "") for k in sys.argv[1:]}}
    for key in ("tmp", "home"):
        try:
            pathlib.Path(report[key], "probe.txt").write_text("x")
            report[key + "_written"] = True
        except OSError as exc:
            report[key + "_written"] = str(exc)
    print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": report}}), flush=True)

if __name__ == "__main__":
    main()
"""

_NODE_PROBE: Final[str] = """#!/usr/bin/env node
const fs = require("fs"), os = require("os"), path = require("path");
const report = {tmp: os.tmpdir(), home: os.homedir(), env: {npm_config_cache: process.env.npm_config_cache || ""}};
for (const key of ["tmp", "home"]) {
  try { fs.writeFileSync(path.join(report[key], "probe.txt"), "x"); report[key + "_written"] = true; }
  catch (error) { report[key + "_written"] = String(error); }
}
process.stdout.write(JSON.stringify({jsonrpc: "2.0", method: "notifications/message", params: {level: "info", data: report}}) + "\\n");
"""


def _probe_package(directory: Path) -> Path:
    """Write a local npm package whose command reports where it runs.

    Args:
        directory: Where to create the package.

    Returns:
        Path: The package directory.
    """
    package = directory / "probe-package"
    package.mkdir()
    (package / "package.json").write_text(
        json.dumps({"name": "intellicrack-probe", "version": "1.0.0", "bin": {"intellicrack-probe": "probe.js"}}),
        encoding="utf-8",
    )
    (package / "probe.js").write_text(_NODE_PROBE, encoding="utf-8")
    return package


def _record_line(name: str, data: bytes) -> str:
    """Render one wheel ``RECORD`` line.

    Args:
        name: The file's path inside the wheel.
        data: Its contents.

    Returns:
        str: The line.
    """
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"{name},sha256={digest},{len(data)}"


def _probe_wheel(directory: Path) -> Path:
    """Write a local wheel whose console script reports where it runs.

    Args:
        directory: Where to write the wheel.

    Returns:
        Path: The wheel.
    """
    info = "intellicrack_probe-1.0.dist-info"
    files = {
        "intellicrack_probe/__init__.py": _PYTHON_PROBE.encode(),
        f"{info}/METADATA": b"Metadata-Version: 2.1\nName: intellicrack-probe\nVersion: 1.0\n",
        f"{info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: intellicrack-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{info}/entry_points.txt": b"[console_scripts]\nintellicrack-probe = intellicrack_probe:main\n",
    }
    record = "\n".join([*starmap(_record_line, files.items()), f"{info}/RECORD,,"]) + "\n"
    wheel = directory / "intellicrack_probe-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr(f"{info}/RECORD", record)
    return wheel


async def _run_probe(tmp_path: Path, server_id: str, command: str, args: tuple[str, ...]) -> JsonObject:
    """Run one launcher confined and read the report its probe prints.

    Args:
        tmp_path: Per-test directory; the sandbox home lives under it.
        server_id: The server id, which names the home.
        command: The launcher.
        args: Its arguments.

    Returns:
        JsonObject: The probe's report.
    """
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    sandbox = McpSandboxSpec(enabled=True, allow_write=(str(work),))
    launch = build_sandboxed_startup(StdioServerSpec(command=command, args=args), sandbox, {}, server_id=server_id)
    with (tmp_path / f"{server_id}.stderr").open("w+", encoding="utf-8") as errlog:
        async with confined_stdio_client(launch, sandbox, errlog) as (read_stream, _):
            with anyio.fail_after(_PROBE_TIMEOUT_S):
                message = await read_stream.receive()
    assert not isinstance(message, Exception), f"the probe printed something that is not a message: {message}"
    notification = message.message
    assert isinstance(notification, JSONRPCNotification)
    params = notification.params or {}
    data = params.get("data")
    assert is_json_object(data), (tmp_path / f"{server_id}.stderr").read_text(encoding="utf-8")
    return data


def _assert_confined_home(report: JsonObject, tmp_path: Path, server_id: str) -> None:
    """Check a probe ran with its temporary directory and home inside its own sandbox home, and could write both.

    Args:
        report: The probe's report.
        tmp_path: Per-test directory holding the state directory.
        server_id: The server id.
    """
    home_root = (tmp_path / "state" / ".intellicrack" / "mcp-sandbox" / server_id).resolve()
    assert Path(str(report["tmp"])).resolve().is_relative_to(home_root)
    assert Path(str(report["home"])).resolve().is_relative_to(home_root)
    assert report["tmp_written"] is True
    assert report["home_written"] is True


@pytest.fixture
def private_state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point Intellicrack's state directory, and so every sandbox home, at the test's own directory.

    Args:
        tmp_path: Per-test directory, which Windows places under the user's local application data.
        monkeypatch: Restores the environment afterwards.

    Returns:
        Path: The state directory.
    """
    state = tmp_path / "state"
    state.mkdir()
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state))
    return state


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Low integrity sandbox: launchers run confined with a per-server home")
@pytest.mark.usefixtures("private_state_dir")
class TestLaunchersRunConfined:
    """Each common launcher starts, finds a writable home and temporary directory, and writes there, at Low integrity."""

    def test_python(self, tmp_path: Path) -> None:
        """Python writes to its temporary directory and home inside the sandbox home.

        Args:
            tmp_path: Per-test directory.
        """
        probe = tmp_path / "probe.py"
        probe.write_text(_PYTHON_PROBE, encoding="utf-8")
        report = asyncio.run(_run_probe(tmp_path, "python-probe", sys.executable, (str(probe),)))
        _assert_confined_home(report, tmp_path, "python-probe")

    def test_node(self, tmp_path: Path) -> None:
        """Node's ``os.tmpdir()`` and ``os.homedir()`` are inside the sandbox home and writable.

        Args:
            tmp_path: Per-test directory.
        """
        package = _probe_package(tmp_path)
        report = asyncio.run(_run_probe(tmp_path, "node-probe", "node", (str(package / "probe.js"),)))
        _assert_confined_home(report, tmp_path, "node-probe")

    def test_npx_with_a_path_ending_in_a_backslash(self, tmp_path: Path) -> None:
        """``npx`` runs a local package, named by a path ending in a backslash, through its ``.cmd`` shim with its cache in the home.

        Args:
            tmp_path: Per-test directory.
        """
        package = _probe_package(tmp_path)
        report = asyncio.run(_run_probe(tmp_path, "npx-probe", "npx", ("--yes", "--prefer-offline", f"{package}\\")))
        _assert_confined_home(report, tmp_path, "npx-probe")
        env = report["env"]
        assert is_json_object(env)
        assert Path(str(env["npm_config_cache"])).is_relative_to(tmp_path / "state")

    def test_uv_run(self, tmp_path: Path) -> None:
        """``uv run`` initializes its cache in the home instead of failing with "Access is denied".

        Args:
            tmp_path: Per-test directory.
        """
        probe = tmp_path / "probe.py"
        probe.write_text(_PYTHON_PROBE, encoding="utf-8")
        args = ("run", "--no-project", "--offline", "--python", sys.executable, str(probe), "UV_CACHE_DIR")
        report = asyncio.run(_run_probe(tmp_path, "uv-probe", "uv", args))
        _assert_confined_home(report, tmp_path, "uv-probe")
        env = report["env"]
        assert is_json_object(env)
        assert any(Path(str(env["UV_CACHE_DIR"])).iterdir())

    def test_uvx(self, tmp_path: Path) -> None:
        """``uvx`` installs a local wheel into its tool environment in the home and runs its command.

        Args:
            tmp_path: Per-test directory.
        """
        wheel = _probe_wheel(tmp_path)
        args = ("--offline", "--python", sys.executable, "--from", str(wheel), "intellicrack-probe")
        report = asyncio.run(_run_probe(tmp_path, "uvx-probe", "uvx", args))
        _assert_confined_home(report, tmp_path, "uvx-probe")

    def test_pipx_run(self, tmp_path: Path) -> None:
        """``pipx run`` builds its environment in the home and runs a local wheel's command.

        Args:
            tmp_path: Per-test directory.
        """
        wheel = _probe_wheel(tmp_path)
        args = ("run", "--pip-args=--no-index", "--spec", str(wheel), "intellicrack-probe")
        report = asyncio.run(_run_probe(tmp_path, "pipx-probe", "pipx", args))
        _assert_confined_home(report, tmp_path, "pipx-probe")


def _connection(tmp_path: Path, config: McpServerConfig) -> McpConnection:
    """Build a connection over a credential store confined to the test.

    Args:
        tmp_path: Per-test directory.
        config: The server.

    Returns:
        McpConnection: The connection.
    """
    resolver = McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")))
    return McpConnection(config, resolver, consent=approving_gate(tmp_path / "trust.json"))


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows sandboxed launch through a .cmd shim, refused-access advice and the spawn lock",
)
@pytest.mark.usefixtures("private_state_dir")
class TestSandboxedServers:
    """A sandboxed MCP server gets its arguments intact, advice when refused, and never spawns inside another's window."""

    def test_shim_passes_a_trailing_backslash_intact(self, tmp_path: Path) -> None:
        """A server started through a ``.cmd`` shim sees an argument ending in a backslash, and the arguments after it, unchanged.

        Args:
            tmp_path: Per-test directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        shim = work / "server.cmd"
        shim.write_text(f'@echo off\r\n"{sys.executable}" "{SERVER_SCRIPT}" %*\r\n', encoding="utf-8")
        args = ("--note", "C:\\proj\\", "--note", "after")
        config = stdio_config("shim-args", command=str(shim), args=args, sandbox=McpSandboxSpec(enabled=True, allow_write=(str(work),)))
        connection = _connection(tmp_path, config)

        async def body() -> list[str]:
            await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
            try:
                return json.loads(await call_text(connection, "argv"))
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        assert asyncio.run(body()) == list(args)

    def test_refused_write_at_start_names_the_path_and_the_settings(self, tmp_path: Path) -> None:
        """A server that dies on a refused write says which path and which settings to change.

        Args:
            tmp_path: Per-test directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        outside = tmp_path / "outside" / "data.txt"
        outside.parent.mkdir()
        script = f"open({str(outside)!r}, 'w').write('x')"
        config = stdio_config(
            "refused",
            command=sys.executable,
            args=("-c", script),
            sandbox=McpSandboxSpec(enabled=True, allow_write=(str(work),)),
        )
        connection = _connection(tmp_path, config)

        with pytest.raises(McpConnectionError) as caught:
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))

        message = str(caught.value)
        assert f"access to {outside}." in message
        assert "sandbox.allowWrite" in message
        assert not outside.exists()

    def test_spawn_waits_while_another_spawn_holds_inheritable_handles(self, tmp_path: Path) -> None:
        """While the inheritance lock is held elsewhere no sandboxed server is created, and it is created once the lock is free.

        Args:
            tmp_path: Per-test directory.
        """
        work = tmp_path / "work"
        work.mkdir()
        config = stdio_config("locked", sandbox=McpSandboxSpec(enabled=True, allow_write=(str(work),)))
        connection = _connection(tmp_path, config)
        held = threading.Event()
        release = threading.Event()

        def hold() -> None:
            with INHERITANCE_LOCK:
                held.set()
                _ = release.wait(_CONNECT_TIMEOUT_S)

        holder = threading.Thread(target=hold, name="inheritance-holder")
        holder.start()
        assert held.wait(_CONNECT_TIMEOUT_S)

        async def body() -> tuple[bool, bool]:
            task = asyncio.create_task(connection.connect())
            await asyncio.sleep(_LOCK_HELD_S)
            ready_while_held = connection.is_ready
            release.set()
            await asyncio.wait_for(task, timeout=_CONNECT_TIMEOUT_S)
            ready = connection.is_ready
            await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)
            return ready_while_held, ready

        try:
            ready_while_held, ready = asyncio.run(body())
        finally:
            release.set()
            holder.join()

        assert not ready_while_held
        assert ready
