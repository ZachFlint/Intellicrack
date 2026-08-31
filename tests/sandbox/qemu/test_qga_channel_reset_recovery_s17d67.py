# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D55/S17-D67: a hard mid-session QGA channel reset must recover.

:class:`OneShotGuestAgentChannelServer` (``tests/sandbox/qemu/guest_agent_server.py``)
already proves that QEMU's ``org.qemu.guest_agent.0`` chardev refuses a second
connection when the *first* one never got past the handshake - S17-D57's
contract, which :class:`~intellicrack.sandbox.qemu.QemuGuestAgentClient` must
keep honouring. This file covers the other half: a channel that completed its
handshake, ran commands successfully, and only *afterwards* had its socket
reset - a guest reboot severing the virtio-serial connection mid-session is the
production trigger named in the defect. Before this fix,
``QemuGuestAgentClient`` reacted to that kind of failure by closing the socket
and stopping there: nothing ever opened a replacement, so every command for
the rest of the session failed on a channel that was never coming back, the
same terminal outcome S17-D55 fixed for the forwarded-port agent channel.

The server below is a genuine local asyncio TCP listener, not a mock: it
speaks the real ``guest-sync-delimited`` handshake, including the leading
``0xFF`` parser-flush sentinel ``qga/main.c`` prepends to that one reply, and
answers ``guest-ping`` the way a live agent does. After answering a configured
number of pings on its first accepted connection it closes that socket
outright - a genuine TCP teardown, standing in for the reset the defect
describes - and then keeps listening and accepts a second connection exactly
as it did the first. Whether a real QEMU chardev really re-listens like this is
not assumed either way: :class:`OneShotGuestAgentChannelServer` still gates the
opposite, empirically-measured case (a refusal), and this server exists to
prove the client behaves correctly when the peer *does* accept - see
``QemuGuestAgentClient._on_channel_reset`` for how both outcomes are handled
without regressing the other.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
import pytest_asyncio

from intellicrack.sandbox.qemu import QemuGuestAgentClient


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_FLUSH_BYTE: Final[bytes] = b"\xff"
_SYNC_DELIMITED: Final[str] = "guest-sync-delimited"
_SYNC_PLAIN: Final[str] = "guest-sync"
_SYNC_COMMANDS: Final[frozenset[str]] = frozenset({_SYNC_DELIMITED, _SYNC_PLAIN})

_CONNECT_TIMEOUT_S: Final[float] = 5.0
_PING_TIMEOUT_S: Final[float] = 5.0
# Long enough for the FIN this server's forced close sends to reach the
# client's socket over loopback, short enough that the suite stays fast.
_CLOSE_SETTLE_S: Final[float] = 0.2

_TWO_CONNECTIONS: Final[int] = 2
_ONE_CONNECTION: Final[int] = 1


class _ResetAndReacceptChannel:
    """Local QGA chardev double: answers, resets its first client, then re-listens.

    Attributes:
        port: TCP port the server is bound to, set once :meth:`start` returns.
        connections: Number of connections accepted since :meth:`start`.
        pings_answered: Total ``guest-ping`` replies written across every
            connection.
        sync_ids: Every id echoed back for a ``guest-sync*`` request, in
            arrival order, across every connection.
    """

    port: int
    connections: int
    pings_answered: int
    sync_ids: list[int]

    def __init__(self, drop_after_pings: int = 1) -> None:
        """Initialise the double before it is bound to a port.

        Args:
            drop_after_pings: How many ``guest-ping`` replies the first
                connection answers before this server closes it outright.
        """
        self.port = 0
        self.connections = 0
        self.pings_answered = 0
        self.sync_ids = []
        self._drop_after_pings = drop_after_pings
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        """Bind an ephemeral loopback port and begin accepting connections.

        Returns:
            int: The bound TCP port.
        """
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        sockname = self._server.sockets[0].getsockname()
        self.port = int(sockname[1])
        return self.port

    async def stop(self) -> None:
        """Stop accepting connections and release the bound port."""
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one accepted connection with the real QGA wire protocol.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        self.connections += 1
        drop_after = self._drop_after_pings if self.connections == _ONE_CONNECTION else None
        try:
            await self._serve_connection(reader, writer, drop_after)
        except (OSError, ConnectionError):
            return
        finally:
            writer.close()

    async def _serve_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        drop_after: int | None,
    ) -> None:
        """Answer requests on one connection, closing it once ``drop_after`` pings land.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
            drop_after: How many ``guest-ping`` replies this connection may
                answer before it is torn down, or ``None`` to never drop it.
        """
        pings_this_connection = 0
        while True:
            line = await reader.readline()
            if not line:
                return
            request = self._decode_request(line)
            name = str(request.get("execute", ""))
            if name in _SYNC_COMMANDS:
                await self._answer_sync(writer, name, request)
                continue
            if name == "guest-ping":
                await self._answer_ping(writer)
                pings_this_connection += 1
                if drop_after is not None and pings_this_connection >= drop_after:
                    return
                continue
            await self._answer_unsupported(writer, name)

    @staticmethod
    def _decode_request(line: bytes) -> dict[str, Any]:
        """Decode one newline-terminated JSON request line.

        A real client prepends the ``0xFF`` parser-flush sentinel to the
        ``guest-sync-delimited`` request itself, not only to the agent's reply
        - see ``QemuGuestAgentClient._attempt_sync`` - so bytes ahead of the
        last such marker are discarded exactly the way a live agent's own
        parser reset discards them, rather than passed to the JSON decoder.

        Args:
            line: Raw request bytes, including the trailing newline.

        Returns:
            dict[str, Any]: Decoded mapping, or an empty mapping when the line
            holds a JSON value that is not an object.
        """
        marker = line.rfind(_FLUSH_BYTE)
        payload = line if marker < 0 else line[marker + 1 :]
        decoded: object = json.loads(payload.decode())
        return cast("dict[str, Any]", decoded) if isinstance(decoded, dict) else {}

    async def _answer_sync(self, writer: asyncio.StreamWriter, name: str, request: dict[str, Any]) -> None:
        """Answer one ``guest-sync``/``guest-sync-delimited`` request.

        Args:
            writer: Stream writer for the accepted connection.
            name: Which of the two sync command names was received.
            request: Decoded request object, carrying the sync id under
                ``arguments.id``.
        """
        arguments = request.get("arguments")
        args_map = cast("dict[str, Any]", arguments) if isinstance(arguments, dict) else {}
        sync_id = int(args_map.get("id", 0))
        self.sync_ids.append(sync_id)
        prefix = _FLUSH_BYTE if name == _SYNC_DELIMITED else b""
        writer.write(prefix + json.dumps({"return": sync_id}).encode() + b"\n")
        await writer.drain()

    async def _answer_ping(self, writer: asyncio.StreamWriter) -> None:
        """Answer one ``guest-ping`` request the way a live agent does.

        Args:
            writer: Stream writer for the accepted connection.
        """
        writer.write(json.dumps({"return": {}}).encode() + b"\n")
        await writer.drain()
        self.pings_answered += 1

    @staticmethod
    async def _answer_unsupported(writer: asyncio.StreamWriter, name: str) -> None:
        """Answer any other command with the agent's ``CommandNotFound`` error.

        Args:
            writer: Stream writer for the accepted connection.
            name: Command name this double does not implement.
        """
        writer.write(json.dumps({"error": {"class": "CommandNotFound", "desc": name}}).encode() + b"\n")
        await writer.drain()


@pytest_asyncio.fixture
async def reset_channel() -> AsyncIterator[_ResetAndReacceptChannel]:
    """Start a channel double that resets its first client after one ping.

    Yields:
        _ResetAndReacceptChannel: A listening channel ready for a client.
    """
    server = _ResetAndReacceptChannel(drop_after_pings=1)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest.mark.asyncio
class TestAHardChannelResetRecoversWithoutRestartingTheSession:
    """A genuinely reset QGA socket must be replaced, not abandoned."""

    async def test_the_command_after_the_reset_reaches_the_agent(self, reset_channel: _ResetAndReacceptChannel) -> None:
        """The command that follows a hard reset must succeed on the same client.

        Three pings on one :class:`QemuGuestAgentClient` instance: the first
        proves the channel is live before anything breaks, the second is the
        one that discovers the server tore the connection down and is allowed
        to fail, and the third has to succeed - on the very same client object,
        so nothing about this is a fresh session - or the reset was never
        actually recovered from.

        Args:
            reset_channel: Channel double that resets its first client after
                one ping.
        """
        client = QemuGuestAgentClient(port=reset_channel.port)
        try:
            connected = await client.connect(time_limit=_CONNECT_TIMEOUT_S)
            assert connected, "the client never reached the modelled channel before anything was reset"

            first = await client.ping(time_limit=_PING_TIMEOUT_S)
            assert first.success, f"the channel was not live before the reset; got {first!r}"

            await asyncio.sleep(_CLOSE_SETTLE_S)

            second = await client.ping(time_limit=_PING_TIMEOUT_S)
            assert not second.success, f"the command that discovers the reset was expected to fail once, but reported success: {second!r}"

            third = await client.ping(time_limit=_PING_TIMEOUT_S)
            assert third.success, (
                f"the command after the reset did not recover on the same client; got {third!r} "
                f"(server saw connections={reset_channel.connections}, sync_ids={reset_channel.sync_ids})"
            )
            assert reset_channel.connections == _TWO_CONNECTIONS, (
                f"recovery did not open a genuine second connection to the server; connections={reset_channel.connections}"
            )
            assert len(reset_channel.sync_ids) >= _TWO_CONNECTIONS, (
                f"the reopened channel was used without resynchronising it first; sync_ids={reset_channel.sync_ids!r}"
            )
            assert client.connected, "the session did not end on a channel the client considers live"
        finally:
            await client.disconnect()


@pytest.mark.asyncio
class TestAPermanentlyRefusedResetFailsPromptlyWithoutHanging:
    """A peer that never re-listens must not turn one reset into a stall."""

    async def test_a_reset_against_no_listener_reports_failure_and_stays_disconnected(self) -> None:
        """A reset whose reopen is refused outright must fail cleanly.

        This is the peer behaviour S17-D57 measured for real against a live
        QEMU build: once the one connection it hands out is gone, a fresh
        connect is refused for the rest of the VM's life. Recovery must try
        the reopen and accept that outcome rather than hang retrying it or
        raise something a caller does not expect.
        """
        server = _ResetAndReacceptChannel(drop_after_pings=1)
        await server.start()
        client = QemuGuestAgentClient(port=server.port)
        try:
            connected = await client.connect(time_limit=_CONNECT_TIMEOUT_S)
            assert connected, "the client never reached the modelled channel before anything was reset"

            first = await client.ping(time_limit=_PING_TIMEOUT_S)
            assert first.success, f"the channel was not live before the reset; got {first!r}"

            await server.stop()
            await asyncio.sleep(_CLOSE_SETTLE_S)

            second = await asyncio.wait_for(client.ping(time_limit=_PING_TIMEOUT_S), timeout=_PING_TIMEOUT_S * 3)
            assert not second.success, f"a ping against a peer with nothing listening reported success: {second!r}"

            third = await asyncio.wait_for(client.ping(time_limit=_PING_TIMEOUT_S), timeout=_PING_TIMEOUT_S * 3)
            assert not third.success, f"a ping against a peer with nothing listening reported success: {third!r}"
            assert not client.connected, "a channel whose reopen was refused must not be reported as connected"
        finally:
            await client.disconnect()
