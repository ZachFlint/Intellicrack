# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D26: the two halves of the guest command protocol must agree.

``QEMUSandbox.run_command`` is the app's host-side guest-command API. It takes a
command line for the guest's own interpreter - shell operators, redirections,
quoted paths and all - and is documented to answer with the
``(exit_code, stdout, stderr)`` that command line really produced. The other
half of that protocol is the in-guest agent, whose source **the application
itself generates** in :meth:`QEMUSandbox._create_guest_agent_script`. S17-D26 is
that the two halves do not describe the same thing: the host composes a shell
command line, and the agent decides on its own what to do with it.

This gate runs both halves for real. The guest OS is configured as Windows, so
the interpreter the host names is ``cmd.exe`` - a real interpreter that exists
on the host this suite runs on, so the command line the host composes is really
parsed and really executed, redirections included. The peer is not a model of
the agent: the decision and execution statements it runs are lifted verbatim out
of the ``agent.ps1`` the production code just generated - its
``$allowedNames``/``$allowedRoots`` declarations, its ``Test-AllowedCommand``,
its ``Send-Message`` and its whole ``if ($request.type -eq 'execute')`` branch -
and run by a real ``powershell.exe`` subprocess listening on a real loopback
socket, exactly as the guest runs them. Only the accept loop around them belongs
to this test. Restating the agent's behaviour here instead would make the test
agree with the code by construction and gate nothing, which is precisely the
trap S17-D26 was found in.

The production :class:`GuestAgentClient` connects to that socket, so every byte
of the request and of the reply crosses a real TCP connection, and every command
is a real child process.

Two properties of the pipeline are asserted:

* The command line has to *run as a command line*. ``cd /d "<dir>" && type
  payload.txt && echo ERRTEXT 1>&2 && exit /b 3`` only produces the payload and
  the exit status 3 if an interpreter parsed the ``&&`` chain; an argv exec
  handed the same text as a program name produces neither. This is the half of
  S17-D26 the host satisfies by naming the interpreter itself, and pinning it
  keeps that from silently regressing.
* What the command wrote has to come back, on the stream it wrote it to. The
  agent used to capture the child with ``& $cmd @cmdArgs 2>&1 | Out-String``,
  which folds a native child's standard error into the same PowerShell error
  stream that the script's own ``$ErrorActionPreference = 'SilentlyContinue'``
  discards, and then re-renders standard output through a formatter that
  appends a line ending the command never wrote - so the host was told the
  command produced no diagnostics at all and handed bytes on standard output
  that differ from the ones the command emitted. Both were measured against a
  real ``powershell.exe``; only a redirected ``System.Diagnostics.Process``
  returns either stream intact, which is what the agent now launches.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import free_port
from tests.sandbox.qemu.powershell_script import matching_bracket


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

_POWERSHELL: Final[str] = "powershell.exe"
_AGENT_SCRIPT_NAME: Final[str] = "agent.ps1"
_PEER_SCRIPT_NAME: Final[str] = "s17d26_peer.ps1"
_MONITOR_DIRECTORY: Final[str] = "monitor"

# Statements lifted out of the generated agent, addressed by the text they
# begin with. Every one of them is a whole line of the generated script.
_ERROR_ACTION_LINE: Final[str] = "$ErrorActionPreference"
_MONITOR_DIR_LINE: Final[str] = "$monitorDir ="
_SHARE_ROOT_LINE: Final[str] = "$shareRoot ="
_SHARE_ROOT_PREFIX_LINE: Final[str] = "$shareRootPrefix ="
_SHARE_ROOT_PREFIX_FALLBACK_LINE: Final[str] = "if (-not $shareRootPrefix"
_SYSTEM_ROOT_LINE: Final[str] = "$systemRoot ="
_SYSTEM_ROOT_FALLBACK_LINE: Final[str] = "if (-not $systemRoot)"
_ALLOWED_NAMES_LINE: Final[str] = "$allowedNames ="
_ALLOWED_ROOTS_LINE: Final[str] = "$allowedRoots ="
_QUOTE_CHAR_LINE: Final[str] = "$quoteChar ="

_PING_BRANCH_HEADER: Final[str] = "if ($request.type -eq 'ping') {"
_EXECUTE_BRANCH_HEADER: Final[str] = "elseif ($request.type -eq 'execute') {"
_ALLOWLIST_FUNCTION: Final = re.compile(r"function\s+Test-AllowedCommand\s*\([^)]*\)\s*\{")
_SEND_MESSAGE_FUNCTION: Final = re.compile(r"function\s+Send-Message\s*\([^)]*\)\s*\{")
_ARGUMENT_FUNCTION: Final = re.compile(r"function\s+ConvertTo-CommandLineArgument\s*\([^)]*\)\s*\{")
_INVOKE_FUNCTION: Final = re.compile(r"function\s+Invoke-GuestCommand\s*\([^)]*\)\s*\{")

_ERR_NO_FRAGMENT: Final[str] = "the generated agent script contains no {fragment}"
_ERR_AMBIGUOUS_FRAGMENT: Final[str] = "the generated agent script contains {count} lines beginning {fragment!r}"
_ERR_UNCLOSED_FRAGMENT: Final[str] = "the block opened by {fragment!r} is never closed in the generated agent script"
_ERR_PEER_FAILED: Final[str] = "the in-guest agent peer failed: exit {code}, stderr {stderr!r}"

_WORK_DIRECTORY: Final[str] = "work"
_PAYLOAD_NAME: Final[str] = "payload.txt"
_PAYLOAD_TEXT: Final[str] = "collected from the working directory\r\n"
_UNTERMINATED_NAME: Final[str] = "unterminated.txt"
_UNTERMINATED_TEXT: Final[str] = "no trailing newline"
_STDERR_MARKER: Final[str] = "ERRTEXT"
_PIPELINE_EXIT_CODE: Final[int] = 3
_PIPELINE_COMMAND: Final[str] = f"type {_PAYLOAD_NAME} && echo {_STDERR_MARKER} 1>&2 && exit /b {_PIPELINE_EXIT_CODE}"
_UNTERMINATED_COMMAND: Final[str] = f"type {_UNTERMINATED_NAME}"

_AGENT_CONNECT_TIMEOUT: Final[float] = 30.0
_COMMAND_TIME_LIMIT: Final[int] = 30
_PEER_EXIT_TIMEOUT: Final[float] = 15.0


def _script_line(script: str, beginning: str) -> str:
    """Return the one line of the generated agent script starting with ``beginning``.

    Args:
        script: Full text of the generated ``agent.ps1``.
        beginning: Text the wanted line begins with, ignoring indentation.

    Returns:
        str: The line itself, stripped of indentation.

    Raises:
        AssertionError: If the script holds no such line, or more than one.
    """
    matched = [line.strip() for line in script.splitlines() if line.strip().startswith(beginning)]
    if len(matched) != 1:
        raise AssertionError(_ERR_AMBIGUOUS_FRAGMENT.format(count=len(matched), fragment=beginning))
    return matched[0]


def _script_block(script: str, start: int, opening: int, fragment: str) -> str:
    """Return the braced block of the generated agent script, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        start: Index the returned text begins at.
        opening: Index of the block's opening brace.
        fragment: Description of the block, for the failure message.

    Returns:
        str: Source from ``start`` through the matching closing brace.

    Raises:
        AssertionError: If the block is never closed.
    """
    closing = matching_bracket(script, opening)
    if closing < 0:
        raise AssertionError(_ERR_UNCLOSED_FRAGMENT.format(fragment=fragment))
    return script[start : closing + 1]


def _script_function(script: str, header: re.Pattern[str]) -> str:
    """Return one whole function of the generated agent script, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        header: Pattern matching the function's declaration through its opening
            brace.

    Returns:
        str: The function's declaration and body.

    Raises:
        AssertionError: If the script declares no such function.
    """
    declaration = header.search(script)
    if declaration is None:
        raise AssertionError(_ERR_NO_FRAGMENT.format(fragment=header.pattern))
    return _script_block(script, declaration.start(), declaration.end() - 1, header.pattern)


def _script_branch(script: str, header: str) -> str:
    """Return one request branch of the generated agent's dispatch, verbatim.

    Args:
        script: Full text of the generated ``agent.ps1``.
        header: The branch's whole declaration through its opening brace.

    Returns:
        str: The whole ``if``/``elseif`` statement the header opens, which is
        where the agent decides what a request of that type means.

    Raises:
        AssertionError: If the script has no such branch.
    """
    start = script.find(header)
    if start < 0:
        raise AssertionError(_ERR_NO_FRAGMENT.format(fragment=header))
    return _script_block(script, start, start + len(header) - 1, header)


def _peer_script(agent_script: str) -> str:
    """Build the in-guest agent peer out of the generated agent's own statements.

    Everything that decides or performs anything - the roots the allowlist is
    built from, the allowlist itself, the reply framing and both dispatch
    branches - is the generated script's own source, unedited. Only the
    listener that hands requests to those branches is written here, and it is
    given the port the test chose because the generated script's own listener
    is fixed to the port the guest uses.

    Lifting the readiness branch rather than answering the probe here is what
    makes this peer a gate on it: the production client handshakes before it
    reports itself connected, so if the generated agent ever stopped answering
    that probe, every test in this module would fail to connect at all.

    Args:
        agent_script: Full text of the generated ``agent.ps1``.

    Returns:
        str: A runnable PowerShell script that answers the agent protocol.
    """
    return (
        "\r\n".join(
            [
                "param([int]$Port)",
                _script_line(agent_script, _ERROR_ACTION_LINE),
                _script_line(agent_script, _MONITOR_DIR_LINE),
                _script_line(agent_script, _SHARE_ROOT_LINE),
                _script_line(agent_script, _SHARE_ROOT_PREFIX_LINE),
                _script_line(agent_script, _SHARE_ROOT_PREFIX_FALLBACK_LINE),
                _script_line(agent_script, _SYSTEM_ROOT_LINE),
                _script_line(agent_script, _SYSTEM_ROOT_FALLBACK_LINE),
                _script_line(agent_script, _ALLOWED_NAMES_LINE),
                _script_line(agent_script, _ALLOWED_ROOTS_LINE),
                _script_line(agent_script, _QUOTE_CHAR_LINE),
                _script_function(agent_script, _ALLOWLIST_FUNCTION),
                _script_function(agent_script, _SEND_MESSAGE_FUNCTION),
                _script_function(agent_script, _ARGUMENT_FUNCTION),
                _script_function(agent_script, _INVOKE_FUNCTION),
                "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), $Port)",
                "$listener.Start()",
                "$client = $listener.AcceptTcpClient()",
                "$stream = $client.GetStream()",
                "$reader = New-Object System.IO.StreamReader($stream)",
                "while ($client.Connected) {",
                "    $line = $reader.ReadLine()",
                "    if ($null -eq $line) { break }",
                "    $request = ConvertFrom-Json $line",
                _script_branch(agent_script, _PING_BRANCH_HEADER),
                _script_branch(agent_script, _EXECUTE_BRANCH_HEADER),
                "}",
                "$client.Close()",
                "$listener.Stop()",
            ],
        )
        + "\r\n"
    )


class _GeneratedAgentPeer:
    """The generated in-guest agent, running as a real ``powershell.exe`` process.

    Attributes:
        port: Loopback port the peer listens on.
    """

    port: int

    def __init__(self, script_path: Path, port: int) -> None:
        """Prepare the peer.

        Args:
            script_path: Peer script assembled from the generated agent.
            port: Loopback port the peer is to listen on.
        """
        self._script_path = script_path
        self.port = port
        self._process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        """Launch the peer process."""
        self._process = await asyncio.create_subprocess_exec(
            _POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self._script_path),
            "-Port",
            str(self.port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def stop(self) -> None:
        """Wait for the peer to finish and fail the test if it broke.

        The peer ends by itself once the client under test closes the
        connection. A peer that instead died of its own fault would otherwise
        show up as a client-side timeout, which reads like a production defect.

        Raises:
            AssertionError: If the peer exited with a failure status or wrote
                anything to its standard error.
        """
        process = self._process
        if process is None:
            return
        self._process = None
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=_PEER_EXIT_TIMEOUT)
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
        diagnostics = stderr.decode(errors="replace").strip()
        if process.returncode or diagnostics:
            raise AssertionError(
                _ERR_PEER_FAILED.format(
                    code=process.returncode,
                    stderr=diagnostics or stdout.decode(errors="replace").strip(),
                ),
            )


class _ProtocolTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` wired to a peer built from its own generated agent.

    Only the share location and the agent connection are arranged here;
    ``run_command`` and the agent-script generator are the production
    implementations.
    """

    async def generate_agent_script(self, share: Path) -> str:
        """Generate the real in-guest agent into ``share`` and read it back.

        Args:
            share: Host directory standing in for the guest's shared folder.

        Returns:
            str: Full text of the generated ``agent.ps1``.
        """
        self._shared_folder = share
        await self._create_guest_agent_script()
        return await asyncio.to_thread(
            (share / _MONITOR_DIRECTORY / _AGENT_SCRIPT_NAME).read_text,
            encoding="utf-8",
        )

    async def connect_agent(self) -> None:
        """Connect the production guest-agent client to the running peer."""
        agent = GuestAgentClient(port=self._qemu_config.agent_port)
        await self._ensure_agent_connected(agent, _AGENT_CONNECT_TIMEOUT)
        self._agent = agent

    async def close_agent(self) -> None:
        """Disconnect the guest-agent client the test opened."""
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None

    def mark_running(self) -> None:
        """Put the sandbox in the state its data-plane methods require."""
        self.state.status = "running"


def _guest_working_directory(tmp_path: Path) -> Path:
    """Create the directory the dispatched commands are to run in.

    Args:
        tmp_path: Directory the guest's files are created under.

    Returns:
        Path: The working directory, holding both payload files.
    """
    work = tmp_path / _WORK_DIRECTORY
    work.mkdir()
    (work / _PAYLOAD_NAME).write_bytes(_PAYLOAD_TEXT.encode("utf-8"))
    (work / _UNTERMINATED_NAME).write_bytes(_UNTERMINATED_TEXT.encode("utf-8"))
    return work


@asynccontextmanager
async def _guest_session(tmp_path: Path) -> AsyncGenerator[_ProtocolTestSandbox]:
    """Run a sandbox against a peer assembled from its own generated agent.

    Args:
        tmp_path: Directory the share and the peer script are created under.

    Yields:
        _ProtocolTestSandbox: Started sandbox whose agent channel is connected
        to the running peer.
    """
    share = tmp_path / "shared"
    monitor = share / _MONITOR_DIRECTORY
    monitor.mkdir(parents=True)

    port = free_port()
    sandbox = _ProtocolTestSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            agent_port=port,
            agent_connect_timeout=_AGENT_CONNECT_TIMEOUT,
        ),
    )
    agent_script = await sandbox.generate_agent_script(share)
    peer_path = monitor / _PEER_SCRIPT_NAME
    await asyncio.to_thread(peer_path.write_text, _peer_script(agent_script), encoding="utf-8")

    peer = _GeneratedAgentPeer(peer_path, port)
    await peer.start()
    try:
        await sandbox.connect_agent()
        sandbox.mark_running()
        yield sandbox
    finally:
        await sandbox.close_agent()
        await peer.stop()


class TestShellCommandLineReachesTheGuestInterpreter:
    """A command line dispatched by ``run_command`` must run as a command line."""

    @pytest.mark.asyncio
    async def test_the_chain_runs_and_its_exit_status_comes_back(
        self,
        tmp_path: Path,
    ) -> None:
        r"""Every link of the ``&&`` chain must run and set the reported status.

        The guest path here targets ``cmd.exe``, the interpreter the host names
        for a Windows guest. ``cd /d "<dir>" && type payload.txt && echo
        ERRTEXT 1>&2 && exit /b 3`` reaches exit status 3 only if an
        interpreter parsed all four links; handed to an argv exec as one
        program name it produces no output and no such status.

        Args:
            tmp_path: Directory the share and the guest files are created
                under.
        """
        work = _guest_working_directory(tmp_path)
        async with _guest_session(tmp_path) as sandbox:
            exit_code, stdout, _stderr = await sandbox.run_command(
                _PIPELINE_COMMAND,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=str(work),
            )

            assert _PAYLOAD_TEXT.strip() in stdout, f"the command line never reached an interpreter: {stdout!r}"
            assert exit_code == _PIPELINE_EXIT_CODE, f"the pipeline's exit status was lost: {exit_code} with {stdout!r}"

    @pytest.mark.asyncio
    async def test_what_the_command_wrote_to_standard_error_comes_back(
        self,
        tmp_path: Path,
    ) -> None:
        r"""The guest command's diagnostics must reach the caller's ``stderr``.

        ``echo ERRTEXT 1>&2`` writes to the child's standard error, so
        ``run_command`` has to hand that text back on the standard-error
        element of its result. Losing it leaves the caller unable to tell a
        command that failed silently from one that explained itself.

        Args:
            tmp_path: Directory the share and the guest files are created
                under.
        """
        work = _guest_working_directory(tmp_path)
        async with _guest_session(tmp_path) as sandbox:
            _exit_code, stdout, stderr = await sandbox.run_command(
                _PIPELINE_COMMAND,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=str(work),
            )

            assert _STDERR_MARKER in stderr, (
                f"what the guest command wrote to standard error never reached the caller: stderr={stderr!r}, stdout={stdout!r}"
            )

    @pytest.mark.asyncio
    async def test_standard_output_is_the_bytes_the_command_wrote(
        self,
        tmp_path: Path,
    ) -> None:
        r"""``stdout`` must be the command's own output, unedited.

        ``type`` on a file with no trailing newline writes exactly those bytes
        and nothing after them, so anything the caller receives beyond them was
        added between the command and the caller - and a caller that hashes,
        diffs or parses the output of a guest tool is handed something the tool
        never produced.

        Args:
            tmp_path: Directory the share and the guest files are created
                under.
        """
        work = _guest_working_directory(tmp_path)
        async with _guest_session(tmp_path) as sandbox:
            exit_code, stdout, stderr = await sandbox.run_command(
                _UNTERMINATED_COMMAND,
                time_limit=_COMMAND_TIME_LIMIT,
                working_directory=str(work),
            )

            assert exit_code == 0, f"the guest could not run the command line: {stderr!r}"
            assert stdout == _UNTERMINATED_TEXT, f"the caller was handed output the command never wrote: {stdout!r}"
