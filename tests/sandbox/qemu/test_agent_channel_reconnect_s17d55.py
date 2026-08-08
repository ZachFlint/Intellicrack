# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D55: a dropped agent channel must be recoverable, not terminal.

The in-guest Intellicrack agent is reached over a QEMU SLIRP ``hostfwd``. That
forwarded connection can be reset while the guest itself is perfectly healthy -
measured live three times over: a ``mkdir`` completed over ``run_command``, the
very next ``run_command`` came back ``(-1, "", "[WinError 64] The specified
network name is no longer available")``, and the guest then powered itself off
cleanly on request. Nothing in the client re-opened the socket, so every command
for the rest of that session failed on a channel that was never coming back.

Two properties are gated here, and they pull in opposite directions - which is
the whole difficulty of the defect:

* **The session survives a drop.** A command, a genuine socket close by the
  agent, and then another command that has to run. Proven from the server's own
  records: it must have accepted a second connection, answered a second
  readiness handshake, and received both commands.
* **A lost command is never run twice.** A request the agent already took
  delivery of may be executing inside the guest right now. Re-sending it would
  run the analysis target a second time, which is a worse outcome than
  reporting that one run's result is unknown. The server records every command
  it took delivery of, whether or not it answered, so a client that answers a
  lost channel with a blind retry shows up as two executions of the same
  binary.

Both drive the real :class:`~tests.sandbox.qemu.guest_agent_server.IntellicrackAgentServer`
over a real loopback socket: the connection really is closed by the peer, the
reconnect really is a fresh TCP connection carrying the production readiness
handshake, and every assertion is made against what that server observed rather
than against the client's opinion of itself.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.sandbox.qemu import GuestAgentClient
from tests.sandbox.qemu.guest_agent_server import GuestCommandResult, IntellicrackAgentServer


if TYPE_CHECKING:
    from collections.abc import Sequence


_CONNECT_BUDGET_S: Final[float] = 15.0
_RETRY_INTERVAL_S: Final[float] = 0.25
_COMMAND_BUDGET_S: Final[float] = 10.0
_CLOSE_OBSERVED_BUDGET_S: Final[float] = 10.0
# Recovery is a fresh connect and handshake against a server in this process, so
# it costs milliseconds. Half the command's own deadline is far above that and
# still well below it, which is the band a backed-off retry loop would land in.
_RECOVERY_BUDGET_S: Final[float] = _COMMAND_BUDGET_S / 2
_CLOSE_POLL_INTERVAL_S: Final[float] = 0.02

_EXPECTED_EXIT_CODE: Final[int] = 0
_FAILED_COMMAND_EXIT: Final[int] = -1

# The three commands of the live sequence: the directory that succeeded, the
# analysis target whose reply never came back, and the command that had to work
# afterwards for the session to be worth anything.
_MKDIR_COMMAND: Final[tuple[str, tuple[str, ...]]] = ("cmd.exe", ("/c", "mkdir", "C:\\intellicrack\\work"))
_TARGET_COMMAND: Final[tuple[str, tuple[str, ...]]] = ("C:\\intellicrack\\work\\target.exe", ("--analyze",))
_FOLLOW_COMMAND: Final[tuple[str, tuple[str, ...]]] = ("cmd.exe", ("/c", "dir", "C:\\intellicrack\\work"))

# Substrings of the failure the caller must be given. The point of the message
# is that it says which side of the dispatch boundary the channel died on, so
# these are the words that carry the contract rather than the whole sentence.
_DISPATCHED_TEXT: Final[str] = "after the command was dispatched"
_NOT_REPEATED_TEXT: Final[str] = "not sent again"

_ONE_EXECUTION: Final[int] = 1
_EXPECTED_CONNECTIONS: Final[int] = 2
_EXPECTED_HANDSHAKES: Final[int] = 2


def _modelled_guest(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Answer one in-guest command with output naming the invocation.

    Every command gets a distinct stdout, so a reply can be traced back to the
    request that produced it and a command that ran when it should not have
    cannot hide behind a shared default.

    Args:
        path: Executable the client asked the guest to run.
        args: Argument list passed with the executable.

    Returns:
        GuestCommandResult: Success carrying the invocation as its stdout.
    """
    return GuestCommandResult(exit_code=_EXPECTED_EXIT_CODE, stdout=_guest_stdout(path, tuple(args)), stderr="")


def _guest_stdout(path: str, args: tuple[str, ...]) -> str:
    """Build the stdout the modelled guest produces for one invocation.

    Args:
        path: Executable the client asked the guest to run.
        args: Argument list passed with the executable.

    Returns:
        str: The invocation rendered exactly as :func:`_modelled_guest` does.
    """
    return " ".join([path, *args]) + "\n"


def _expected_reply(invocation: tuple[str, tuple[str, ...]]) -> tuple[int, str, str]:
    """Build the process triple a successful invocation must come back as.

    Args:
        invocation: Executable and arguments the client sent.

    Returns:
        tuple[int, str, str]: ``(exit_code, stdout, stderr)`` the modelled
        guest produces for ``invocation``.
    """
    return (_EXPECTED_EXIT_CODE, _guest_stdout(invocation[0], invocation[1]), "")


async def _wait_until_channel_lost(client: GuestAgentClient, budget: float) -> float:
    """Wait for the client to notice the peer closed the channel.

    Args:
        client: Client whose channel the agent has hung up on.
        budget: Seconds to wait before giving up.

    Returns:
        float: Seconds spent waiting, whether or not the close was observed.
    """
    started = time.monotonic()
    while time.monotonic() - started < budget:
        if not client.is_connected:
            break
        await asyncio.sleep(_CLOSE_POLL_INTERVAL_S)
    return time.monotonic() - started


class TestADroppedChannelIsReopenedForTheNextCommand:
    """A channel the agent hung up on must not end the session."""

    @pytest.mark.asyncio
    async def test_command_after_a_real_peer_close_still_reaches_the_guest(self) -> None:
        """The command after a genuine socket close must run in the guest.

        The first command proves the channel was live, so the state that
        follows is produced by the agent's close and nothing else. The second
        command can only succeed by opening a new connection, handshaking on it
        and dispatching again - all three of which the server counts itself.
        """
        server = IntellicrackAgentServer(_modelled_guest, close_after_replies=1)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            connected = await client.connect(time_limit=_CONNECT_BUDGET_S, retry_interval=_RETRY_INTERVAL_S)
            assert connected is True, f"the client never reached the modelled agent; server.accepted={server.accepted}"

            first = await client.send_command(
                _MKDIR_COMMAND[0],
                list(_MKDIR_COMMAND[1]),
                time_limit=_COMMAND_BUDGET_S,
            )
            assert first == _expected_reply(_MKDIR_COMMAND), f"the channel was not live before the drop; got {first!r}"

            waited = await _wait_until_channel_lost(client, _CLOSE_OBSERVED_BUDGET_S)
            assert client.is_connected is False, (
                f"the agent closed the connection and {waited:.2f}s later the client still reports it connected, "
                f"so this test would not be exercising a drop at all; server.accepted={server.accepted}"
            )

            started = time.monotonic()
            second = await client.send_command(
                _FOLLOW_COMMAND[0],
                list(_FOLLOW_COMMAND[1]),
                time_limit=_COMMAND_BUDGET_S,
            )
            recovered_in = time.monotonic() - started

            assert recovered_in < _RECOVERY_BUDGET_S, (
                f"recovery ate most of the command's deadline at {recovered_in:.2f}s; a session that spends that "
                f"long per command after every drop is no more usable than one that fails outright"
            )
            assert server.requests == [_MKDIR_COMMAND, _FOLLOW_COMMAND], (
                f"the agent did not receive both commands; the server recorded requests={server.requests!r}"
            )
            assert server.accepted == _EXPECTED_CONNECTIONS, (
                f"the client never opened a second connection to the agent; server.accepted={server.accepted}"
            )
            assert server.handshakes == _EXPECTED_HANDSHAKES, (
                f"the re-opened channel was used without proving the agent answers on it; server.handshakes={server.handshakes}"
            )
            assert second == _expected_reply(_FOLLOW_COMMAND), f"the command issued after the drop did not run in the guest; got {second!r}"
            assert client.is_connected is True, f"the session did not end on a live channel; server.accepted={server.accepted}"
        finally:
            await client.disconnect()
            await server.stop()


class TestACommandLostAfterDispatchIsNotRunTwice:
    """A request the agent already has must never be sent a second time."""

    @pytest.mark.asyncio
    async def test_target_lost_after_dispatch_is_reported_and_executed_once(self) -> None:
        """The lost command fails, runs once, and the session carries on.

        The modelled agent takes delivery of the target and then loses the
        connection before its reply can be written, which is the one case a
        host cannot resolve: the guest may be running that binary right now. A
        client that reconnects and re-sends turns one analysis run into two,
        and the server's own record of what it received is what catches it.
        """
        server = IntellicrackAgentServer(_modelled_guest, drop_requests=1)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            connected = await client.connect(time_limit=_CONNECT_BUDGET_S, retry_interval=_RETRY_INTERVAL_S)
            assert connected is True, f"the client never reached the modelled agent; server.accepted={server.accepted}"

            exit_code, stdout, stderr = await client.send_command(
                _TARGET_COMMAND[0],
                list(_TARGET_COMMAND[1]),
                time_limit=_COMMAND_BUDGET_S,
            )

            assert server.dropped_requests == [_TARGET_COMMAND], (
                f"the agent did not take delivery of the target before losing the connection, so nothing here is "
                f"gating a post-dispatch loss; server.dropped_requests={server.dropped_requests!r}"
            )
            executions = server.requests.count(_TARGET_COMMAND)
            assert executions == _ONE_EXECUTION, (
                f"the analysis target reached the guest {executions} times for one caller request; "
                f"the server recorded requests={server.requests!r}"
            )
            assert exit_code == _FAILED_COMMAND_EXIT, (
                f"a command whose outcome the host cannot know was reported as exit_code={exit_code} with stdout={stdout!r}"
            )
            assert not stdout, f"a command that never produced a reply cannot have produced output; got {stdout!r}"
            assert _DISPATCHED_TEXT in stderr, f"the caller was not told the channel died after the command was dispatched; got {stderr!r}"
            assert _NOT_REPEATED_TEXT in stderr, f"the caller was not told the command was left un-repeated; got {stderr!r}"

            follow = await client.send_command(
                _FOLLOW_COMMAND[0],
                list(_FOLLOW_COMMAND[1]),
                time_limit=_COMMAND_BUDGET_S,
            )

            assert follow == _expected_reply(_FOLLOW_COMMAND), (
                f"the session did not survive the lost command; the next command returned {follow!r}"
            )
            assert server.requests == [_TARGET_COMMAND, _FOLLOW_COMMAND], (
                f"the agent received something other than the target once and the follow-up once; "
                f"the server recorded requests={server.requests!r}"
            )
            assert server.accepted == _EXPECTED_CONNECTIONS, (
                f"the client did not replace the lost connection with exactly one new one; server.accepted={server.accepted}"
            )
        finally:
            await client.disconnect()
            await server.stop()
