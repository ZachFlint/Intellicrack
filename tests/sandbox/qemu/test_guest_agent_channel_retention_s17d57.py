# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D57: retrying the agent handshake must not spend the channel.

QEMU hands out the ``org.qemu.guest_agent.0`` chardev socket **once**. It
accepts a single connection and refuses every later one with a reset for the
life of the VM. The app closed and reopened that socket on each failed
handshake, in two places, both sound for a QMP monitor and fatal here:
``QemuJsonProtocolClient.connect`` closed the socket when the handshake failed,
and ``_attempt_guest_agent_connect`` disconnected before every attempt after
the first.

The reasoning above the second one was right - an unanswered
``guest-sync-delimited`` means the guest has not started qemu-guest-agent yet,
not that it never will - but the response did not follow from it. The chardev
socket is bound by QEMU on the host side before the guest leaves firmware, so
the guest's readiness says nothing about it, and reconnecting cannot make the
guest readier while it does cost the only connection there is.

Measured on a cold ``windows11-intellicrack-v4`` boot: connect at 10:46:55, two
expected sync failures while the guest booted, then from 10:47:59 every attempt
answered ``[WinError 1225] The remote computer refused the network connection``
once every three seconds until the budget ran out. QEMU was alive and still
listening on that port with no peer attached, and an independent client outside
the application was refused three times in a row - so the channel was genuinely
gone, not merely unreachable from the app.

:class:`OneShotGuestAgentChannelServer` reproduces that contract exactly: it
closes its listening socket on accept, so a client that hangs up cannot come
back. The guest is modelled separately from the channel, by leaving the first
few resync requests unanswered - which is what a booting guest looks like from
the host. A client that must reconnect to retry therefore cannot pass these
tests, and one that retries in place can.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from intellicrack.core.types import SandboxError
from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import (
    GuestOS,
    QEMUConfig,
    QemuGuestAgentClient,
    QEMUSandbox,
)
from tests.sandbox.qemu.guest_agent_server import (
    GuestAgentProtocolServer,
    OneShotGuestAgentChannelServer,
    SilentGuestAgentServer,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


# Long enough for several attempts at the retry interval below, short enough
# that a regression fails the test in seconds rather than stalling the suite.
_CHANNEL_BUDGET_S: Final[float] = 12.0
_ATTEMPT_TIMEOUT_S: Final[float] = 1.0
_RETRY_INTERVAL_S: Final[float] = 0.2
_SILENT_SYNCS: Final[int] = 3
_ONE_CONNECTION: Final[int] = 1
_STALL_COMMAND: Final[str] = "guest-ping"
# Longer than the ping deadline plus the resync deadline the recovery path
# spends, so the resync goes unanswered too and the recovery genuinely fails.
_STALL_SECONDS: Final[float] = 8.0
_PING_TIMEOUT_S: Final[float] = 0.5
# An unanswered sync attempt costs the client its own per-attempt deadline, so a
# retained channel needs a budget covering every silent attempt still owed plus
# the one that gets answered. It returns as soon as the agent replies, so a
# generous ceiling costs nothing in practice.
_RESYNC_BUDGET_S: Final[float] = 30.0


class _ChannelRetentionSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing the channel helpers to test code.

    Only public wrappers are added; every wrapped method is the real
    production implementation.
    """

    async def open_guest_agent_channel(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_guest_agent_channel`."""
        await self._connect_guest_agent_channel(
            time_limit=_CHANNEL_BUDGET_S,
            attempt_timeout=_ATTEMPT_TIMEOUT_S,
            retry_interval=_RETRY_INTERVAL_S,
        )

    @property
    def agent_client(self) -> QemuGuestAgentClient | None:
        """The guest-agent client the channel helper is working with.

        Returns:
            QemuGuestAgentClient | None: The client, or None before the first
            attempt.
        """
        return self._qga

    async def close_client(self) -> None:
        """Disconnect the guest-agent client if one was opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None


def _make_sandbox(channel_port: int) -> _ChannelRetentionSandbox:
    """Build a sandbox whose agent channel points at a test server.

    Args:
        channel_port: Port of the guest-agent-shaped server. The sandbox
            derives it as ``agent_port + 1``, so ``agent_port`` is set one
            below it.

    Returns:
        _ChannelRetentionSandbox: Sandbox ready for direct method invocation.
    """
    config = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        agent_port=channel_port - 1,
        guest_agent_ready_timeout=_CHANNEL_BUDGET_S,
    )
    return _ChannelRetentionSandbox(config=SandboxConfig(), qemu_config=config)


@pytest_asyncio.fixture
async def slow_guest_channel() -> AsyncIterator[OneShotGuestAgentChannelServer]:
    """Start a one-shot channel whose guest agent starts late.

    Yields:
        OneShotGuestAgentChannelServer: A listening channel that will accept
        exactly one connection.
    """
    server = OneShotGuestAgentChannelServer(silent_syncs=_SILENT_SYNCS)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest.mark.asyncio
class TestAChannelHandedOutOnceStillReachesASlowGuest:
    """The retry has to happen on the open socket, not on a new one."""

    async def test_the_channel_opens_despite_a_guest_that_answers_late(
        self,
        slow_guest_channel: OneShotGuestAgentChannelServer,
    ) -> None:
        """A guest whose agent starts late must still be reached.

        Args:
            slow_guest_channel: One-shot channel with a late guest agent.
        """
        sandbox = _make_sandbox(slow_guest_channel.port)
        try:
            await sandbox.open_guest_agent_channel()

            client = sandbox.agent_client
            assert client is not None, "the channel helper returned without ever building a client"
            assert client.connected, "the channel helper returned with the agent channel unusable"
        finally:
            await sandbox.close_client()

    async def test_only_one_connection_is_ever_taken(
        self,
        slow_guest_channel: OneShotGuestAgentChannelServer,
    ) -> None:
        """Reconnecting is a forfeit, so the retries must not reconnect.

        Args:
            slow_guest_channel: One-shot channel with a late guest agent.
        """
        sandbox = _make_sandbox(slow_guest_channel.port)
        try:
            await sandbox.open_guest_agent_channel()
        finally:
            await sandbox.close_client()

        assert slow_guest_channel.accepted == _ONE_CONNECTION, (
            f"the channel was connected {slow_guest_channel.accepted} times; QEMU accepts it once"
        )
        assert slow_guest_channel.refused_syncs == _SILENT_SYNCS, (
            f"the guest was modelled as unready for {_SILENT_SYNCS} syncs but only "
            f"{slow_guest_channel.refused_syncs} went unanswered, so the retry path never ran"
        )


@pytest.mark.asyncio
class TestAFailedHandshakeLeavesTheSocketOpen:
    """The transport decides whether a socket is worth keeping, per peer."""

    async def test_the_guest_agent_client_keeps_its_socket(
        self,
        slow_guest_channel: OneShotGuestAgentChannelServer,
    ) -> None:
        """A guest-agent handshake failure must not close the channel.

        Args:
            slow_guest_channel: One-shot channel with a late guest agent.
        """
        client = QemuGuestAgentClient(port=slow_guest_channel.port)
        try:
            with pytest.raises(SandboxError):
                await client.connect(time_limit=_ATTEMPT_TIMEOUT_S)

            assert client.socket_open, "the only connection QEMU will accept was closed on a handshake failure"
            assert not client.connected, "an unsynchronised channel must not be reported as connected"

            assert await client.resynchronise(_RESYNC_BUDGET_S), (
                "the retained channel never synchronised once the guest agent started answering"
            )
        finally:
            await client.disconnect()

    async def test_a_peer_that_never_accepts_leaves_nothing_open(self) -> None:
        """Retention must not turn a refused connect into a phantom channel.

        Nothing is listening on the port, so no socket was ever taken and the
        client must report both flags false rather than claiming to hold a
        channel it does not have.
        """
        server = SilentGuestAgentServer()
        port = await server.start()
        await server.stop()

        client = QemuGuestAgentClient(port=port)
        try:
            assert not await client.connect(time_limit=_ATTEMPT_TIMEOUT_S), "a connect to a port with no listener reported success"
            assert not client.socket_open, "a refused connect left a socket behind"
            assert not client.connected, "a refused connect reported the channel connected"
        finally:
            await client.disconnect()


@pytest.mark.asyncio
class TestATimedOutCommandDoesNotForfeitTheChannel:
    """A slow guest is not a broken socket, and must not be treated as one."""

    async def test_an_unanswered_resync_leaves_the_channel_open(self) -> None:
        """A command timeout whose resync also times out must keep the socket.

        The recovery path used to close the channel on any failure "so the next
        call opens a fresh one" - and on this channel there is no fresh one to
        open, which is the most likely mechanism behind S17-D55.
        """
        server = GuestAgentProtocolServer(stall_command=_STALL_COMMAND, stall_seconds=_STALL_SECONDS)
        await server.start()
        client = QemuGuestAgentClient(port=server.port)
        try:
            assert await client.connect(time_limit=_ATTEMPT_TIMEOUT_S), "the test server refused the initial connection"

            response = await client.ping(time_limit=_PING_TIMEOUT_S)

            assert not response.success, "the stalled command was expected to time out"
            assert client.socket_open, "a timed-out command closed a channel QEMU will not hand out again"
        finally:
            await client.disconnect()
            await server.stop()


@pytest.mark.asyncio
async def test_the_one_shot_channel_really_refuses_a_second_connection(
    slow_guest_channel: OneShotGuestAgentChannelServer,
) -> None:
    """The server must model QEMU, or the gates above prove nothing.

    Args:
        slow_guest_channel: One-shot channel with a late guest agent.
    """
    first = QemuGuestAgentClient(port=slow_guest_channel.port)
    try:
        with pytest.raises(SandboxError):
            await first.connect(time_limit=_ATTEMPT_TIMEOUT_S)
        assert first.socket_open, "the first client did not retain the connection it took"

        await first.disconnect()
        await asyncio.sleep(_RETRY_INTERVAL_S)

        second = QemuGuestAgentClient(port=slow_guest_channel.port)
        assert not await second.connect(time_limit=_ATTEMPT_TIMEOUT_S), (
            "a second connection succeeded, so this server does not model QEMU's one-shot chardev"
        )
    finally:
        await first.disconnect()
