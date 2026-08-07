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
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.generated_agent_peer import (
    AGENT_SCRIPT_NAME,
    LOOPBACK_LISTENER_STATEMENT,
    MONITOR_DIRECTORY,
    GeneratedAgentPeer,
    build_peer_script,
)
from tests.sandbox.qemu.guest_agent_server import free_port


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

_PEER_SCRIPT_NAME: Final[str] = "s17d26_peer.ps1"

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
            (share / MONITOR_DIRECTORY / AGENT_SCRIPT_NAME).read_text,
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
    monitor = share / MONITOR_DIRECTORY
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
    peer_script = build_peer_script(agent_script, listener_statement=LOOPBACK_LISTENER_STATEMENT)
    await asyncio.to_thread(peer_path.write_text, peer_script, encoding="utf-8")

    peer = GeneratedAgentPeer(peer_path, port)
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
