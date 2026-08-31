# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S17-D73: an argument must reach the guest as the argument that was sent.

Found by being bitten by it on a live Windows guest. A probe sent one
``powershell.exe -NoProfile -Command <script>`` argument whose script contained
double quotes, and the guest answered ``ParserError ... UnexpectedToken`` at a
character offset *inside* that script: the agent had rewritten the argument
before PowerShell ever saw it.

``ConvertTo-CommandLineArgument`` in the generated Windows agent wrapped an
argument in quotes whenever it contained a space or a tab, and did nothing
else. ``Invoke-GuestCommand`` then joins the rendered arguments into one string
and hands it to ``ProcessStartInfo.Arguments``, which the callee splits by
``CommandLineToArgvW``'s rules. Those rules need two escapes the old code did
neither of:

* a quote inside the argument has to be written ``\"``, or it ends the quoted
  run and everything after it is re-parsed as new arguments;
* a run of backslashes immediately before a quote - including the closing quote
  the wrapper itself appends - has to be doubled, or the last backslash escapes
  that quote and the argument swallows whatever follows it.

So ``value with "quoted" text`` arrived stripped of its quotes, and a path
ending in a separator ate the next argument entirely. Nothing reported either:
the guest simply received a different argument vector than the host sent.

Those rules belong to ``CommandLineToArgvW``, which is every callee here except
one: ``cmd.exe`` never sees an argv and re-parses its own tail, where a
backslash is an ordinary path character. Escaping for the wrong one of the two
is not a smaller mistake than not escaping at all - it hands the interpreter
``cd /d \"C:\dir\"`` - so the interpreter keeps its own rendering, and the gate
on that half is
:mod:`tests.sandbox.qemu.test_guest_command_protocol_s17d26`, which drives a
real shell command line through the same agent. This module gates the other
half, so its callee is a real ``powershell.exe``.

The gate measures the round trip rather than the string the host built. The
peer is :mod:`tests.sandbox.qemu.generated_agent_peer`, which lifts
``ConvertTo-CommandLineArgument`` and ``Invoke-GuestCommand`` **verbatim** out
of the ``agent.ps1`` production has just generated and runs them in a real
``powershell.exe`` over a real socket, with the production
:class:`GuestAgentClient` on the other end. The callee is a second real
``powershell.exe`` whose script echoes its own ``$args`` back, so what is
compared is the argument vector the operating system really handed the child
against the one the caller really asked for. Asserting on the composed command
line instead would let this test agree with whatever quoting the code happens
to do, which is exactly how the defect survived.
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
    POWERSHELL,
    GeneratedAgentPeer,
    build_peer_script,
)
from tests.sandbox.qemu.guest_agent_server import free_port


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Sequence
    from pathlib import Path

_PEER_SCRIPT_NAME: Final[str] = "s17d73_peer.ps1"
_ECHO_SCRIPT_NAME: Final[str] = "echo_argv.ps1"

# The callee writes its own argument vector back, joined on a separator no
# argument can contain, so the comparison is against the vector the operating
# system produced rather than against any re-quoting of it.
_ARGUMENT_SEPARATOR: Final[str] = "\x1f"
_ECHO_SCRIPT_BODY: Final[str] = (
    "$parts = @()\r\nforeach ($item in $args) { $parts += [string]$item }\r\n[Console]::Out.Write($parts -join [char]0x1F)\r\n"
)

_QUOTED_ARGUMENT: Final[str] = 'value with "quoted" text'
_TRAILING_SEPARATOR_ARGUMENT: Final[str] = "C:\\some dir\\"
_SENTINEL_ARGUMENT: Final[str] = "sentinel"
_PLAIN_SPACED_ARGUMENT: Final[str] = "an ordinary spaced value"
_BARE_ARGUMENT: Final[str] = "unremarkable"

_AGENT_CONNECT_TIMEOUT: Final[float] = 30.0
_COMMAND_TIME_LIMIT: Final[int] = 60
_SUCCESS: Final[int] = 0


class _QuotingTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` wired to a peer built from its own generated agent."""

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

    async def echo_arguments(self, echo_script: Path, arguments: Sequence[str]) -> list[str]:
        """Send ``arguments`` to a real child and return the vector it received.

        Args:
            echo_script: Script the callee runs, which writes its own ``$args``
                back joined on :data:`_ARGUMENT_SEPARATOR`.
            arguments: Argument vector the caller wants the child to receive.

        Returns:
            list[str]: The arguments the child actually received.

        Raises:
            AssertionError: If the agent is not connected, or the callee failed
                rather than answering - a callee that died of a syntax error
                would otherwise read as an empty argument vector.
        """
        agent = self._agent
        if agent is None:
            msg = "the guest-agent client is not connected"
            raise AssertionError(msg)

        exit_code, stdout, stderr = await agent.send_command(
            POWERSHELL,
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(echo_script), *arguments],
            time_limit=_COMMAND_TIME_LIMIT,
        )
        if exit_code != _SUCCESS:
            msg = f"the callee failed instead of echoing its arguments: exit={exit_code} stderr={stderr!r}"
            raise AssertionError(msg)
        return stdout.split(_ARGUMENT_SEPARATOR) if stdout else []


@asynccontextmanager
async def _guest_session(tmp_path: Path) -> AsyncGenerator[tuple[_QuotingTestSandbox, Path]]:
    """Run a sandbox against a peer assembled from its own generated agent.

    Args:
        tmp_path: Directory the share, the peer and the callee are created under.

    Yields:
        tuple[_QuotingTestSandbox, Path]: The connected sandbox and the path of
        the callee script that echoes its arguments.
    """
    share = tmp_path / "shared"
    monitor = share / MONITOR_DIRECTORY
    monitor.mkdir(parents=True)

    echo_script = tmp_path / _ECHO_SCRIPT_NAME
    await asyncio.to_thread(echo_script.write_text, _ECHO_SCRIPT_BODY, encoding="utf-8")

    port = free_port()
    sandbox = _QuotingTestSandbox(
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
        yield sandbox, echo_script
    finally:
        await sandbox.close_agent()
        await peer.stop()


@pytest.mark.asyncio
class TestArgumentsSurviveTheGuestCommandLine:
    """Every argument the caller sends must arrive as the argument it sent."""

    async def test_an_argument_containing_quotes_arrives_intact(self, tmp_path: Path) -> None:
        """Quotes inside an argument must not split it or vanish from it.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        async with _guest_session(tmp_path) as (sandbox, echo_script):
            received = await sandbox.echo_arguments(echo_script, [_QUOTED_ARGUMENT, _BARE_ARGUMENT])

        assert received == [_QUOTED_ARGUMENT, _BARE_ARGUMENT], (
            f"the guest received {received!r} rather than the vector that was sent; "
            f"an unescaped quote ends the quoted run and everything after it is re-parsed (S17-D73)"
        )

    async def test_an_argument_ending_in_a_separator_does_not_eat_the_next_one(self, tmp_path: Path) -> None:
        """A trailing backslash must not escape the wrapper's own closing quote.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        async with _guest_session(tmp_path) as (sandbox, echo_script):
            received = await sandbox.echo_arguments(
                echo_script,
                [_TRAILING_SEPARATOR_ARGUMENT, _SENTINEL_ARGUMENT],
            )

        assert received == [_TRAILING_SEPARATOR_ARGUMENT, _SENTINEL_ARGUMENT], (
            f"the guest received {received!r}; a backslash before the closing quote escaped it, "
            f"so the path swallowed {_SENTINEL_ARGUMENT!r} (S17-D73)"
        )

    async def test_ordinary_arguments_still_arrive_intact(self, tmp_path: Path) -> None:
        """The escaping must not disturb the arguments that already worked.

        A fix for the two cases above that broke plain spaced arguments would
        be a regression rather than a fix, so the ordinary shape is pinned in
        the same place.

        Args:
            tmp_path: pytest-provided temporary directory fixture.
        """
        async with _guest_session(tmp_path) as (sandbox, echo_script):
            received = await sandbox.echo_arguments(
                echo_script,
                [_PLAIN_SPACED_ARGUMENT, _BARE_ARGUMENT],
            )

        assert received == [_PLAIN_SPACED_ARGUMENT, _BARE_ARGUMENT], (
            f"the guest received {received!r} for a vector that needs no escaping at all"
        )
