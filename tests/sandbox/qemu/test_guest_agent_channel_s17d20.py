# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D20: qemu-guest-agent commands must not travel over QMP.

``guest-ping``/``guest-exec``/``guest-exec-status`` are qemu-guest-agent (QGA)
commands. QEMU's QMP monitor does not implement them and answers
``{"error": {"class": "CommandNotFound", "desc": "The command guest-ping has
not been found"}}`` - the exact reply captured from a live Debian guest on the
development host. The agent is reachable only through the chardev socket bound
to ``org.qemu.guest_agent.0``, which QEMU exposes one port above the configured
``agent_port``.

Two *real* asyncio TCP servers back these tests, shared with the other QEMU
guest-agent gates through :mod:`tests.sandbox.qemu.guest_agent_server`:

* :class:`QmpProtocolServer` speaks genuine QMP - greeting banner,
  ``qmp_capabilities`` negotiation, ``query-status`` - and rejects every
  ``guest-*`` command exactly the way QEMU does. Routing guest-agent traffic
  back to the QMP client therefore turns these tests red.
* :class:`GuestAgentProtocolServer` speaks genuine QGA - no banner, no
  capability negotiation, no asynchronous events, a ``guest-sync-delimited``
  reply carrying the leading ``0xFF`` sentinel that ``qga/main.c`` prepends,
  the leftovers of a previous client ahead of that sentinel, and
  ``guest-ping``/``guest-exec``/``guest-exec-status`` replies with base64
  ``out-data``/``err-data``.

The same server models the two ways a real channel refuses to answer straight
away: a port that is bound but not yet listening because the guest has not
booted, and an agent that answers a command only after the client has given up
waiting for it.

Every assertion drives the real :class:`QEMUSandbox` methods and the real
:class:`QemuGuestAgentClient`; nothing here is mocked or stubbed.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

import pytest
import pytest_asyncio

from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    GuestAgentClient,
    GuestExecStatus,
    GuestOS,
    QEMUConfig,
    QemuGuestAgentClient,
    QEMUSandbox,
)
from tests.sandbox.qemu.guest_agent_server import (
    DEFAULT_GUEST_EXEC_PID,
    DEFAULT_GUEST_STDERR,
    DEFAULT_GUEST_STDOUT,
    FLUSH_BYTE,
    STALE_DELIMITER_ID,
    SYNC_COMMANDS,
    SYNC_DELIMITED_COMMAND,
    SYNC_PLAIN_COMMAND,
    UNDECODABLE_LINE,
    GuestAgentProtocolServer,
    GuestCommandResult,
    IntellicrackAgentServer,
    QmpProtocolServer,
    SilentGuestAgentServer,
    decode_object,
    free_port,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

_EXPECTED_EXIT_CODE: Final[int] = 0
_LINUX_LAUNCH_PATH: Final[str] = "/mnt/shared/monitor/start_agent.sh"
_CHANNEL_READY_BUDGET_S: Final[float] = 3.0
_BOOT_RETRY_BUDGET_S: Final[float] = 25.0
_AGENT_BOOT_DELAY_S: Final[float] = 5.0
_AGENT_STALL_S: Final[float] = 0.6
_PING_GIVE_UP_S: Final[float] = 0.15
_SOCKET_CLOSE_WAIT_S: Final[float] = 2.0
_EXPECTED_SYNC_COUNT: Final[int] = 2

# Read out of the production module rather than restated here, so a change to the
# order or contents of the sync fallback chain is reflected in the assertion
# instead of silently diverging from it.
_EXPECTED_SYNC_ORDER: Final[tuple[str, ...]] = getattr(qemu_module, "_QGA_SYNC_COMMANDS")
_TRUNCATED_STDOUT: Final[str] = "first 4096 bytes of monitor output"
_TRUNCATED_STDERR: Final[str] = "first 4096 bytes of monitor errors"
_STATUS_POLLS_BEFORE_EXIT: Final[int] = 3
_STATUS_POLLS_NEVER_EXIT: Final[int] = 1_000_000
_GUEST_RUN_BUDGET_S: Final[float] = 2.0
_MINIMUM_TIMEOUT_POLLS: Final[int] = 2
_ASYNCIO_DEFAULT_STREAM_LIMIT: Final[int] = 64 * 1024
_LARGE_OUTPUT_LINES: Final[int] = 3400
_LARGE_GUEST_STDOUT: Final[str] = "".join(f"{index:06d}-captured-guest-output-line\n" for index in range(_LARGE_OUTPUT_LINES))
_NARROW_READ_LIMIT: Final[int] = 4096
_RESET_DURING_RESYNC: Final[str] = "channel reset while re-issuing guest-sync-delimited"
_COMMAND_TIMED_OUT: Final[str] = "Command timed out"
_AGENT_RESULT_BUDGET_S: Final[float] = 2.0
_OVERLONG_DEADLINE_S: Final[float] = 6.0
_FAILED_COMMAND_EXIT: Final[int] = -1


class _ChannelTestSandbox(QEMUSandbox):
    """``QEMUSandbox`` subclass exposing the channel helpers to test code.

    Only public wrappers are added; every wrapped method is the real
    production implementation.
    """

    async def connect_qmp(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_and_verify_qmp`."""
        await self._connect_and_verify_qmp()

    async def open_guest_agent_channel(self) -> None:
        """Drive the real :meth:`QEMUSandbox._connect_guest_agent_channel`."""
        await self._connect_guest_agent_channel()

    async def bootstrap(self) -> None:
        """Drive the real :meth:`QEMUSandbox._bootstrap_guest_agent`."""
        await self._bootstrap_guest_agent()

    async def wait_for_guest_agent(self, ping_timeout: float, poll_interval: float) -> None:
        """Drive the real :meth:`QEMUSandbox._wait_for_qemu_ga`.

        Args:
            ping_timeout: Maximum total wait time in seconds.
            poll_interval: Delay in seconds between ping attempts.
        """
        await self._wait_for_qemu_ga(ping_timeout=ping_timeout, poll_interval=poll_interval)

    async def guest_exec(self, path: str, args: list[str], *, capture_output: bool = False) -> int:
        """Drive the real :meth:`QEMUSandbox._guest_agent_exec`.

        Args:
            path: Executable path inside the guest.
            args: Argument list for the executable.
            capture_output: Whether the agent should buffer stdout/stderr.

        Returns:
            int: Guest-side process id reported by the agent.
        """
        return await self._guest_agent_exec(path, args, capture_output=capture_output)

    async def guest_run(self, path: str, args: list[str], time_limit: float) -> GuestExecStatus:
        """Drive the real :meth:`QEMUSandbox._guest_run`.

        Args:
            path: Executable name or path inside the guest.
            args: Argument list for the executable.
            time_limit: Maximum time in seconds to wait for the process.

        Returns:
            GuestExecStatus: Terminal status of the guest-side process.
        """
        return await self._guest_run(path, args, time_limit)

    def channel_port(self) -> int:
        """Return the resolved guest-agent channel port.

        Returns:
            int: ``agent_port`` plus the guest-agent channel offset.
        """
        return self._guest_agent_channel_port()

    def agent_guest_pid(self) -> int | None:
        """Return the guest pid recorded by the bootstrap.

        Returns:
            int | None: Recorded pid, or None if bootstrap did not run.
        """
        return self._agent_guest_pid

    async def close_clients(self) -> None:
        """Disconnect both protocol clients if they were opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None
        if self._qmp is not None:
            await self._qmp.disconnect()
            self._qmp = None


@pytest_asyncio.fixture
async def qmp_server() -> AsyncIterator[QmpProtocolServer]:
    """Start the real QMP-shaped server.

    Yields:
        QmpProtocolServer: A listening QMP server.
    """
    server = QmpProtocolServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest_asyncio.fixture
async def ga_server() -> AsyncIterator[GuestAgentProtocolServer]:
    """Start the real qemu-guest-agent-shaped server.

    Yields:
        GuestAgentProtocolServer: A listening guest-agent server.
    """
    server = GuestAgentProtocolServer()
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


def _make_sandbox(
    qmp_port: int,
    ga_channel_port: int,
    guest_os: GuestOS = GuestOS.LINUX,
    ready_timeout: float = _CHANNEL_READY_BUDGET_S,
) -> _ChannelTestSandbox:
    """Build a sandbox wired to the two protocol servers.

    Args:
        qmp_port: Port of the QMP-shaped server.
        ga_channel_port: Port of the guest-agent-shaped server. The sandbox
            derives it as ``agent_port + 1``, so ``agent_port`` is set one
            below it.
        guest_os: Guest OS family to configure.
        ready_timeout: Total budget the channel may spend becoming usable.

    Returns:
        _ChannelTestSandbox: Sandbox ready for direct method invocation.
    """
    cfg = QEMUConfig(
        guest_os=guest_os,
        monitor_port=qmp_port,
        agent_port=ga_channel_port - 1,
        guest_agent_ready_timeout=ready_timeout,
    )
    return _ChannelTestSandbox(config=SandboxConfig(), qemu_config=cfg)


async def _settle_socket_state(server: SilentGuestAgentServer) -> None:
    """Give the server time to observe a close, so an open socket means one.

    Waiting for the close event and finding it never fires is the expected
    outcome under the S17-D57 contract: a failed handshake keeps the channel.
    The wait exists so that "still open" is a settled observation rather than a
    race against a close that simply had not been processed yet.

    Args:
        server: Silent agent server whose connections are being watched.
    """
    try:
        await asyncio.wait_for(server.all_closed.wait(), timeout=_SOCKET_CLOSE_WAIT_S)
    except TimeoutError:
        return


class TestGuestAgentTrafficUsesTheAgentChannel:
    """guest-* commands must reach the agent channel and never the monitor."""

    @pytest.mark.asyncio
    async def test_bootstrap_pings_and_execs_over_the_guest_agent_channel(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """The full bootstrap runs against the agent server, not the monitor.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.bootstrap()

            assert sandbox.channel_port() == ga_server.port
            assert sandbox.agent_guest_pid() == DEFAULT_GUEST_EXEC_PID
            assert "guest-ping" in ga_server.commands
            assert ga_server.commands.count("guest-exec") == 1
            assert ga_server.exec_arguments[0]["path"] == "/bin/bash"
            assert ga_server.exec_arguments[0]["arg"] == [_LINUX_LAUNCH_PATH]

            guest_commands_on_monitor = [name for name in qmp_server.commands if name.startswith("guest-")]
            assert not guest_commands_on_monitor, (
                f"guest-agent commands were sent to the QMP monitor: {guest_commands_on_monitor}; "
                "QEMU answers those with CommandNotFound, so the data plane would be dead"
            )
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_guest_exec_helper_returns_agent_reported_pid(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """``_guest_agent_exec`` returns the pid the agent server reported.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            pid = await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=True)

            assert pid == DEFAULT_GUEST_EXEC_PID
            assert not [name for name in qmp_server.commands if name.startswith("guest-")]
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_capture_output_flag_reaches_the_agent_unchanged(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """Both capture-output values travel to the agent as sent.

        Driving the same helper twice with opposite values is what makes this
        falsifiable: a hardcoded ``capture-output`` passes one call and fails
        the other.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=True)
            await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=False)

            assert [record.capture_output for record in ga_server.exec_records] == [True, False]
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_wait_for_guest_agent_succeeds_against_agent_server(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """``_wait_for_qemu_ga`` pings the agent channel and returns.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            await sandbox.wait_for_guest_agent(ping_timeout=5.0, poll_interval=0.05)

            assert ga_server.commands.count("guest-ping") == 1
            assert "guest-ping" not in qmp_server.commands
        finally:
            await sandbox.close_clients()


class TestSyncHandshake:
    """The QGA resynchronisation must actually happen on the wire."""

    @pytest.mark.asyncio
    async def test_flush_byte_and_delimiter_id_round_trip(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """The client writes 0xFF then a delimiter whose id the agent echoes.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            raw = bytes(ga_server.received)
            assert raw.startswith(FLUSH_BYTE), f"first byte on the channel must be the 0xFF parser flush; got {raw[:16]!r}"

            first_request = decode_object(raw[1:].split(b"\n", 1)[0])
            assert first_request["execute"] == "guest-sync-delimited"
            arguments = cast("dict[str, Any]", first_request["arguments"])
            sent_id = int(arguments["id"])

            assert ga_server.sync_ids == [sent_id], f"agent must have echoed the delimiter id {sent_id}; recorded {ga_server.sync_ids}"
            assert sent_id != STALE_DELIMITER_ID, "client must not adopt the stale delimiter id already on the wire"
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_agent_without_the_delimited_command_still_synchronises(self) -> None:
        """An agent that rejects the delimited sync must still be usable.

        Agent builds differ in which sync commands they carry, and one that does
        not implement the preferred name answers ``CommandNotFound`` rather than
        staying silent. The client must recognise that as a definitive rejection
        of that command, fall back to the other name, and complete the handshake.
        """
        server = GuestAgentProtocolServer(unsupported_commands=frozenset({SYNC_DELIMITED_COMMAND}))
        await server.start()
        try:
            client = QemuGuestAgentClient(port=server.port)
            try:
                connected = await client.connect(time_limit=10.0)
                assert connected, "the client must fall back to a sync command the agent implements"
                assert server.commands[:2] == [SYNC_DELIMITED_COMMAND, SYNC_PLAIN_COMMAND], (
                    f"the rejected command must be followed by the fallback; saw {server.commands}"
                )
                assert server.sync_ids, "the accepted sync command must have recorded its id"
                reply = await client.ping(time_limit=10.0)
                assert reply.success, f"the channel must be usable after the fallback sync; error={reply.error}"
            finally:
                await client.disconnect()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_rejected_sync_does_not_consume_the_connect_budget(self) -> None:
        """A rejected sync command must fail fast, not wait out the deadline.

        The agent answers ``CommandNotFound`` immediately. Treating that reply as
        just another line to skip makes the client sit on its deadline for every
        attempt, turning a legible rejection into a silent multi-minute stall.
        """
        server = GuestAgentProtocolServer(unsupported_commands=SYNC_COMMANDS)
        await server.start()
        budget = 30.0
        try:
            client = QemuGuestAgentClient(port=server.port)
            started = time.monotonic()
            with pytest.raises(SandboxError):
                await client.connect(time_limit=budget)
            elapsed = time.monotonic() - started
            await client.disconnect()

            assert elapsed < budget / 2, (
                f"a rejected sync must be detected from the agent's reply, not by waiting out the "
                f"budget; took {elapsed:.2f}s of a {budget}s budget"
            )
            assert set(server.commands) == set(_EXPECTED_SYNC_ORDER), (
                f"every supported sync name must be tried before giving up; saw {server.commands}"
            )
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_sync_reframes_on_the_sentinel_after_a_partial_line(
        self,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """A partial line ahead of the 0xFF sentinel must not break the sync.

        The agent server reproduces ``qga/main.c``: the previous client left a
        complete delimiter reply and an object cut off mid-write in the output
        stream, and the reply to ``guest-sync-delimited`` is prefixed with the
        raw ``0xFF`` sentinel byte. A client that decodes the line as strict
        UTF-8 without re-framing on that byte cannot even connect.

        Args:
            ga_server: Real guest-agent-shaped server.
        """
        client = QemuGuestAgentClient(port=ga_server.port)
        try:
            connected = await client.connect(time_limit=5.0)

            assert connected is True
            assert client.connected is True
            assert len(ga_server.sync_ids) == 1

            response = await client.ping(time_limit=5.0)
            assert response.success is True, f"the reply stream stayed misframed after the sentinel: {response.error}"
        finally:
            await client.disconnect()

    @pytest.mark.asyncio
    async def test_sync_discards_stale_reply_before_matching_id(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """A stale delimiter reply already on the wire must not satisfy the sync.

        The agent server writes ``{"return": 987654321}`` and a truncated
        object before any request arrives. A client that accepted the first
        line as its answer would then mis-frame every later reply; the ping
        and the status query issued afterwards prove the stream stayed aligned.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            await sandbox.wait_for_guest_agent(ping_timeout=5.0, poll_interval=0.05)

            agent = sandbox.qemu_guest_agent
            assert agent is not None
            status_pid = await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=True)
            status = await agent.guest_exec_status(status_pid)

            assert status.exited is True
            assert status.stdout == DEFAULT_GUEST_STDOUT
        finally:
            await sandbox.close_clients()


class TestChannelWaitsForTheGuestToBoot:
    """The channel must keep trying while the guest is still coming up."""

    @pytest.mark.asyncio
    async def test_channel_retries_until_the_agent_starts_listening(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A port that starts out refusing connections is retried, not given up on.

        QEMU binds the chardev with ``server,nowait``, so the sandbox reaches
        this step while the guest is still booting. The agent server models
        that by refusing connections outright until it comes up, for longer
        than one connect attempt - including the kernel's own SYN retries -
        can span.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        ga_server = GuestAgentProtocolServer(listen_delay=_AGENT_BOOT_DELAY_S)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port, ready_timeout=_BOOT_RETRY_BUDGET_S)
        try:
            await sandbox.connect_qmp()
            started = time.monotonic()

            await sandbox.open_guest_agent_channel()

            elapsed = time.monotonic() - started
            agent = sandbox.qemu_guest_agent
            assert agent is not None
            assert agent.connected is True
            assert elapsed >= _AGENT_BOOT_DELAY_S, f"the channel opened in {elapsed:.3f}s, before the agent could possibly be listening"
            assert len(ga_server.sync_ids) == 1, "the retry that succeeded must still have completed the sync"
        finally:
            await sandbox.close_clients()
            await ga_server.stop()


class TestClientTimeoutResynchronisation:
    """A command that times out must not leave the reply stream offset."""

    @pytest.mark.asyncio
    async def test_late_reply_is_discarded_by_a_resync(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A reply that arrives after the client gave up must not be reused.

        The agent server holds the ``guest-ping`` reply back past the client's
        deadline and writes it afterwards, exactly as a loaded guest does.
        Without a fresh ``guest-sync-delimited`` the next command reads that
        stale reply and the channel stays one message behind for good.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        ga_server = GuestAgentProtocolServer(stall_command="guest-ping", stall_seconds=_AGENT_STALL_S)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            agent = sandbox.qemu_guest_agent
            assert agent is not None

            timed_out = await agent.ping(time_limit=_PING_GIVE_UP_S)
            assert timed_out.success is False, "the stalled ping must have hit the client-side deadline"

            pid = await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=True)

            assert pid == DEFAULT_GUEST_EXEC_PID
            assert len(ga_server.sync_ids) == _EXPECTED_SYNC_COUNT, (
                f"guest-sync-delimited must be re-issued after a client-side timeout; ids seen: {ga_server.sync_ids}"
            )
            assert ga_server.sync_ids[0] != ga_server.sync_ids[1], "each resync must use a fresh delimiter id"
        finally:
            await sandbox.close_clients()
            await ga_server.stop()


class TestExecStatusDecoding:
    """``guest-exec-status`` must decode the agent's base64 output."""

    @pytest.mark.asyncio
    async def test_out_data_and_err_data_are_decoded(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """Base64 ``out-data``/``err-data`` become real text on the result.

        A live agent omits ``out-truncated``/``err-truncated`` unless its
        capture buffer overflowed, so their absence must decode to False.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            agent = sandbox.qemu_guest_agent
            assert agent is not None

            status = await agent.guest_exec_status(DEFAULT_GUEST_EXEC_PID)

            assert ga_server.exec_status_pids == [DEFAULT_GUEST_EXEC_PID]
            assert status.exited is True
            assert status.exit_code == _EXPECTED_EXIT_CODE
            assert status.stdout == DEFAULT_GUEST_STDOUT
            assert status.stderr == DEFAULT_GUEST_STDERR
            assert status.stdout_truncated is False
            assert status.stderr_truncated is False
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_truncated_capture_is_reported_per_stream(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """``out-truncated`` is decoded independently of ``err-truncated``.

        Args:
            qmp_server: Real QMP-shaped server.
        """

        def _overflowing_guest(path: str, args: Sequence[str]) -> GuestCommandResult:
            """Return a result whose stdout capture buffer overflowed.

            Args:
                path: Executable the client asked the guest to run.
                args: Argument list passed with the executable.

            Returns:
                GuestCommandResult: Truncated stdout, intact stderr.
            """
            del path, args
            return GuestCommandResult(
                exit_code=0,
                stdout=_TRUNCATED_STDOUT,
                stderr=_TRUNCATED_STDERR,
                stdout_truncated=True,
                stderr_truncated=False,
            )

        ga_server = GuestAgentProtocolServer(_overflowing_guest)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            agent = sandbox.qemu_guest_agent
            assert agent is not None

            pid = await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=True)
            status = await agent.guest_exec_status(pid)

            assert status.stdout == _TRUNCATED_STDOUT
            assert status.stderr == _TRUNCATED_STDERR
            assert status.stdout_truncated is True
            assert status.stderr_truncated is False
        finally:
            await sandbox.close_clients()
            await ga_server.stop()


class TestGuestRunWaitsForTheProcessToFinish:
    """``_guest_run`` must poll a running process instead of reading once."""

    @pytest.mark.asyncio
    async def test_status_is_polled_until_the_process_exits(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A process still running on the first query must be waited on.

        The agent server answers ``{"exited": false}`` for the first queries,
        exactly as a live agent does while the child is alive; a caller that
        reads the status once takes that non-terminal answer as the result.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        ga_server = GuestAgentProtocolServer(status_polls_before_exit=_STATUS_POLLS_BEFORE_EXIT)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            status = await sandbox.guest_run("/bin/bash", ["-c", "true"], _GUEST_RUN_BUDGET_S)

            assert status.exited is True
            assert status.exit_code == _EXPECTED_EXIT_CODE
            assert status.stdout == DEFAULT_GUEST_STDOUT
            assert len(ga_server.exec_status_pids) == _STATUS_POLLS_BEFORE_EXIT + 1, (
                f"the status must be re-read until the process exits; queries: {ga_server.exec_status_pids}"
            )
        finally:
            await sandbox.close_clients()
            await ga_server.stop()

    @pytest.mark.asyncio
    async def test_process_that_never_exits_raises_the_timeout_error(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A guest process that never finishes must surface as a timeout.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        ga_server = GuestAgentProtocolServer(status_polls_before_exit=_STATUS_POLLS_NEVER_EXIT)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            with pytest.raises(SandboxError, match="did not exit within"):
                await sandbox.guest_run("/bin/bash", ["-c", "sleep 600"], _GUEST_RUN_BUDGET_S)

            assert len(ga_server.exec_status_pids) >= _MINIMUM_TIMEOUT_POLLS, (
                f"the timeout must follow repeated status queries; queries: {ga_server.exec_status_pids}"
            )
        finally:
            await sandbox.close_clients()
            await ga_server.stop()

    @pytest.mark.asyncio
    async def test_guest_run_asks_the_agent_to_capture_output(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """Without ``capture-output`` the agent buffers nothing to return.

        A live agent only fills ``out-data``/``err-data`` for a process it was
        asked to capture; every in-guest discovery step reads that output, so
        the flag is what makes them work at all.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            status = await sandbox.guest_run("/bin/bash", ["-c", "true"], _GUEST_RUN_BUDGET_S)

            assert [record.capture_output for record in ga_server.exec_records] == [True]
            assert status.stdout == DEFAULT_GUEST_STDOUT
            assert status.stderr == DEFAULT_GUEST_STDERR
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_uncaptured_process_reports_no_output(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """A ``guest-exec`` without capture yields a status carrying no streams.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            agent = sandbox.qemu_guest_agent
            assert agent is not None

            pid = await sandbox.guest_exec("/bin/bash", ["-c", "true"], capture_output=False)
            status = await agent.guest_exec_status(pid)

            assert status.exited is True
            assert not status.stdout, f"an uncaptured process cannot report stdout: {status.stdout!r}"
            assert not status.stderr, f"an uncaptured process cannot report stderr: {status.stderr!r}"
        finally:
            await sandbox.close_clients()


class TestMonitorChannelUnaffected:
    """The QMP client keeps serving genuine monitor operations."""

    @pytest.mark.asyncio
    async def test_query_status_still_goes_to_the_monitor(
        self,
        qmp_server: QmpProtocolServer,
        ga_server: GuestAgentProtocolServer,
    ) -> None:
        """``query-status`` reaches the QMP server and not the agent server.

        Args:
            qmp_server: Real QMP-shaped server.
            ga_server: Real guest-agent-shaped server.
        """
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()
            qmp = sandbox.qmp
            assert qmp is not None

            response = await qmp.query_status()

            assert response.success is True
            assert qmp_server.commands.count("qmp_capabilities") == 1
            assert qmp_server.commands.count("query-status") >= 1
            assert "query-status" not in ga_server.commands
        finally:
            await sandbox.close_clients()


class TestChannelFailureModes:
    """Unreachable and wedged agent channels surface as ``SandboxError``."""

    @pytest.mark.asyncio
    async def test_unreachable_channel_raises_sandbox_error(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A closed guest-agent port fails the channel open with the port named.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        closed_port = free_port()
        sandbox = _make_sandbox(qmp_server.port, closed_port)
        try:
            await sandbox.connect_qmp()

            with pytest.raises(SandboxError) as err:
                await sandbox.open_guest_agent_channel()

            assert str(closed_port) in str(err.value)
        finally:
            await sandbox.close_clients()

    @pytest.mark.asyncio
    async def test_agent_that_never_answers_sync_raises_sandbox_error(self) -> None:
        """A silent agent fails the sync, and the channel it was reached on survives.

        Keeping the socket is the S17-D57 contract: QEMU accepts the
        ``org.qemu.guest_agent.0`` chardev once for the life of the VM, so a
        client that closes it on a failed handshake has thrown away the only
        channel there is. A guest that has not started its agent yet is exactly
        the case that must be retried in place.
        """
        server = SilentGuestAgentServer()
        await server.start()
        client = QemuGuestAgentClient(port=server.port)
        try:
            with pytest.raises(SandboxError) as err:
                await client.connect(time_limit=0.5)

            assert "sync" in str(err.value), f"the failure must name the handshake that failed; got {err.value}"
            assert client.connected is False

            await _settle_socket_state(server)
            assert server.open_connections == 1, (
                f"the failed handshake forfeited the one channel QEMU hands out; {server.open_connections} open"
            )
        finally:
            await client.disconnect()
            await server.stop()

    @pytest.mark.asyncio
    async def test_failed_sync_keeps_the_only_channel_it_has(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A channel whose sync fails must hold the connection it already has.

        The sandbox keeps the client instance so a later call can retry, and
        under S17-D57 that retry must reuse the open socket rather than opening
        a fresh one: QEMU accepts the guest-agent chardev a single time per VM
        and refuses every reconnection with a reset, so dropping it here ends
        all guest communication for the life of the guest.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        server = SilentGuestAgentServer()
        await server.start()
        sandbox = _make_sandbox(qmp_server.port, server.port)
        try:
            await sandbox.connect_qmp()

            with pytest.raises(SandboxError):
                await sandbox.open_guest_agent_channel()

            agent = sandbox.qemu_guest_agent
            assert agent is not None
            assert agent.connected is False
            assert server.accepted >= 1

            await _settle_socket_state(server)
            assert server.open_connections == 1, (
                f"{server.accepted} connection(s) were accepted and {server.open_connections} are still open; "
                "a failed sync must keep the one channel socket QEMU hands out"
            )
        finally:
            await sandbox.close_clients()
            await server.stop()


def _large_output_guest(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Return a result whose captured stdout is larger than 64 KiB.

    A hundred kilobytes of captured output is unremarkable for an in-guest
    discovery command and is two orders of magnitude below qemu-guest-agent's
    own 16 MiB capture cap, but base64-encoding it into a single reply line
    puts that line far past asyncio's default StreamReader limit.

    Args:
        path: Executable the client asked the guest to run.
        args: Argument list passed with the executable.

    Returns:
        GuestCommandResult: Successful result carrying the large stdout.
    """
    del path, args
    return GuestCommandResult(exit_code=0, stdout=_LARGE_GUEST_STDOUT, stderr="")


class _NarrowLimitGuestAgentClient(QemuGuestAgentClient):
    """Real client whose channel line limit is far below one agent reply.

    Nothing else changes: every byte still crosses a real socket and comes
    from the real agent server, so the overrun is produced by a genuine reply
    that does not fit rather than by an injected error.
    """

    _read_limit: ClassVar[int] = _NARROW_READ_LIMIT


class _NarrowLimitAgentClient(GuestAgentClient):
    """Real in-guest agent client whose line limit is below one reply.

    Nothing else changes: the reply still crosses a real socket and is still
    produced by the real agent server, so the overrun comes from a genuine
    message that does not fit rather than from an injected error.
    """

    _read_limit: ClassVar[int] = _NARROW_READ_LIMIT


class _ResetOnResyncGuestAgentClient(QemuGuestAgentClient):
    """Real client whose post-timeout resync hits a broken channel.

    :meth:`QemuGuestAgentClient._on_command_timeout` writes a fresh
    ``guest-sync-delimited`` and reads until the agent echoes it, so a channel
    that dropped while the timed-out command was outstanding makes it raise
    ``ConnectionResetError``. It runs from inside ``_send_command``'s
    ``except TimeoutError`` handler, where the sibling ``except`` clauses
    cannot catch anything it raises.
    """

    async def _on_command_timeout(self) -> None:
        """Fail the resync the way a reset channel fails it.

        Raises:
            ConnectionResetError: Always.
        """
        raise ConnectionResetError(_RESET_DURING_RESYNC)


class TestRepliesLargerThanTheDefaultStreamLimit:
    """Captured guest output must survive the read that carries it."""

    @pytest.mark.asyncio
    async def test_guest_run_reads_a_reply_past_the_default_limit(
        self,
        qmp_server: QmpProtocolServer,
    ) -> None:
        """A 100 KB captured stdout arrives intact through the real client.

        ``_guest_run`` always asks for ``capture-output``, so every in-guest
        discovery step routes the guest's stdout through this read. asyncio's
        default 64 KiB StreamReader limit turns that read into a bare
        ``ValueError`` which no handler on the path expects.

        Args:
            qmp_server: Real QMP-shaped server.
        """
        ga_server = GuestAgentProtocolServer(_large_output_guest)
        await ga_server.start()
        sandbox = _make_sandbox(qmp_server.port, ga_server.port)
        try:
            await sandbox.connect_qmp()
            await sandbox.open_guest_agent_channel()

            status = await sandbox.guest_run("/bin/bash", ["-c", "ls -R /"], _GUEST_RUN_BUDGET_S)

            assert len(_LARGE_GUEST_STDOUT) > _ASYNCIO_DEFAULT_STREAM_LIMIT, "the fixture must exceed the limit it is gating"
            assert status.exited is True
            assert status.stdout == _LARGE_GUEST_STDOUT
        finally:
            await sandbox.close_clients()
            await ga_server.stop()

    @pytest.mark.asyncio
    async def test_overlong_reply_fails_the_command_and_closes_the_channel(self) -> None:
        """A frame past the channel limit must not escape as a ``ValueError``.

        The overrun leaves the rest of the frame unread, so the stream can no
        longer be framed; the command has to fail as a command and the channel
        has to be closed, not raise an exception its callers never handle.
        """
        ga_server = GuestAgentProtocolServer(_large_output_guest)
        await ga_server.start()
        client = _NarrowLimitGuestAgentClient(port=ga_server.port)
        try:
            assert await client.connect(time_limit=5.0) is True

            started = await client.guest_exec("/bin/bash", ["-c", "ls -R /"], capture_output=True, time_limit=5.0)
            assert started.success is True, f"the small guest-exec reply must still fit: {started.error}"
            pid_payload = cast("dict[str, Any]", started.data)

            with pytest.raises(SandboxError, match="guest-exec-status reply could not be read"):
                await client.guest_exec_status(int(pid_payload["pid"]), time_limit=5.0)

            assert client.connected is False, "a channel that can no longer be framed must be closed"
        finally:
            await client.disconnect()
            await ga_server.stop()

    @pytest.mark.asyncio
    async def test_intellicrack_agent_result_past_the_default_limit_is_delivered(self) -> None:
        """The in-guest agent's result message carries whole command output.

        ``extract_dropped_files`` and ``run_command`` both read an in-guest
        command's stdout out of a single ``result`` line, which passes the
        default limit long before it reaches any size the agent would refuse
        to send.
        """
        server = IntellicrackAgentServer(_large_output_guest)
        await server.start()
        agent = GuestAgentClient(port=server.port)
        try:
            assert await agent.connect(time_limit=5.0, retry_interval=0.5) is True

            exit_code, stdout, stderr = await agent.send_command(
                "cmd.exe",
                ["/c", "dir", "/s"],
                time_limit=_AGENT_RESULT_BUDGET_S,
            )

            assert server.requests == [("cmd.exe", ("/c", "dir", "/s"))]
            assert exit_code == 0
            assert stdout == _LARGE_GUEST_STDOUT
            assert not stderr, f"the modelled guest wrote nothing to stderr: {stderr!r}"
        finally:
            await agent.disconnect()
            await server.stop()


class TestAgentReaderSurvivesWhatItCanAndStopsAtWhatItCannot:
    """One unreadable message and an unframeable stream differ."""

    @pytest.mark.asyncio
    async def test_overlong_result_fails_the_command_and_closes_the_channel(self) -> None:
        """A result line past the reader's limit must end the channel.

        ``StreamReader.readline`` reports the overrun as a bare ``ValueError``
        and leaves the rest of that line unread, so the stream can no longer be
        framed on newlines. Unguarded it kills the reader task with an
        exception nobody is waiting on, and the command that is waiting sits
        out its whole deadline before reporting a timeout it never suffered.
        """
        server = IntellicrackAgentServer(_large_output_guest)
        await server.start()
        agent = _NarrowLimitAgentClient(port=server.port)
        try:
            assert await agent.connect(time_limit=5.0, retry_interval=0.5) is True
            started = time.monotonic()

            exit_code, stdout, stderr = await agent.send_command(
                "cmd.exe",
                ["/c", "dir", "/s"],
                time_limit=_OVERLONG_DEADLINE_S,
            )

            elapsed = time.monotonic() - started
            assert len(_LARGE_GUEST_STDOUT) > _NARROW_READ_LIMIT, "the fixture must exceed the limit it is gating"
            assert exit_code == _FAILED_COMMAND_EXIT
            assert not stdout
            assert "channel limit" in stderr, f"the command reported something other than the framing failure: {stderr!r}"
            assert agent.is_connected is False, "a channel that can no longer be framed must be closed"
            assert elapsed < _OVERLONG_DEADLINE_S, f"the command waited out its whole deadline instead of failing: {elapsed:.3f}s"
        finally:
            await agent.disconnect()
            await server.stop()

    @pytest.mark.asyncio
    async def test_undecodable_line_does_not_cost_the_next_reply(self) -> None:
        """A line that is not valid UTF-8 must not end the reader.

        The newline framing around such a line is intact, so it is one message
        the client cannot read and nothing more; the reply that follows it on
        the same connection still has to arrive.
        """
        server = IntellicrackAgentServer(undecodable_lines=1)
        await server.start()
        agent = GuestAgentClient(port=server.port)
        try:
            assert await agent.connect(time_limit=5.0, retry_interval=0.5) is True

            exit_code, stdout, stderr = await agent.send_command(
                "cmd.exe",
                ["/c", "echo", "hello"],
                time_limit=_AGENT_RESULT_BUDGET_S,
            )

            assert UNDECODABLE_LINE.endswith(b"\n"), "the fixture must be a complete line, not a truncated stream"
            assert exit_code == 0, f"the reply after the unreadable line never arrived: {stderr!r}"
            assert stdout == DEFAULT_GUEST_STDOUT
            assert agent.is_connected is True, "one unreadable message must not close the channel"
        finally:
            await agent.disconnect()
            await server.stop()


class TestTimeoutRecoveryIsContained:
    """A failing post-timeout resync must not escape the command call."""

    @pytest.mark.asyncio
    async def test_reset_during_resync_surfaces_as_a_failed_command(self) -> None:
        """The command reports a timeout and the channel is closed.

        The resync runs inside ``_send_command``'s ``except TimeoutError``
        handler; anything it raises other than the failure the handler already
        expects would travel out through ``guest_exec_status``, ``_guest_run``,
        ``_mount_guest_shared_volume`` and ``start``.
        """
        ga_server = GuestAgentProtocolServer(stall_command="guest-ping", stall_seconds=_AGENT_STALL_S)
        await ga_server.start()
        client = _ResetOnResyncGuestAgentClient(port=ga_server.port)
        try:
            assert await client.connect(time_limit=5.0) is True

            response = await client.ping(time_limit=_PING_GIVE_UP_S)

            assert response.success is False
            assert response.error == _COMMAND_TIMED_OUT
            assert client.connected is False, "a channel whose recovery failed must be closed for the next call to reopen"
        finally:
            await client.disconnect()
            await ga_server.stop()
