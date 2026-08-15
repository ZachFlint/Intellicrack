# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for S18-D05: one slow command must not poison the channel forever.

qemu-guest-agent carries no request id. A reply is attributed to a command by
position alone, so a command the client stops waiting for is not merely lost:
its reply is still coming, and from the moment it lands every read is offset by
one. The protocol's answer is to resynchronise, and the client did - but with a
five-second budget against a two-command sync list whose per-attempt share was
also five seconds. The first command consumed the whole budget, the fallback
was never sent, and the offset survived.

Measured on a cold ``windows11-intellicrack-v4`` boot driven through the real
``SandboxBridge`` on 2026-08-14. The channel synchronised over seven seconds
and answered ``guest-ping`` at 16:50:44. The first ``guest-exec`` was still
unanswered when its ten-second deadline expired at 16:50:54; the resync behind
it gave up at 16:50:59 having tried both sync commands and landed neither. What
followed is the whole of this defect:

* ``qemu_ga_exec_status_unreadable`` - a status query answered by something
  that was not a status,
* ``qemu_ga_exec_no_pid ... response_payload=982749383`` - a bare 31-bit sync
  id handed back as the answer to ``guest-exec``,
* ``qemu_ga_exec_failed ... error='PID lld does not exist'`` - the agent
  reporting on a pid the host never really had.

The fix is in three parts, and these gates aim at each of them separately:

1. a reply deadline sized for the slowest reply the agent is actually asked
   for rather than the fastest,
2. a sync budget that reaches every sync command it claims to try, and
3. a channel that remembers it is offset, so no reply can be attributed to a
   command that did not earn it.

Every gate runs the production client against
:class:`GuestAgentProtocolServer`, a real TCP server speaking the
qemu-guest-agent wire protocol. Its ``stall_command`` blocks the connection
exactly as the live agent did, so the late reply reaches the client ahead of
anything written after it - the defect's mechanism, not an approximation of it.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Final, cast

import pytest
import pytest_asyncio

from intellicrack.sandbox.qemu import (
    QEMU_GA_EXEC_TIMEOUT,
    QEMUConfig,
    QemuGuestAgentClient,
)
from tests.sandbox.qemu.guest_agent_server import (
    DEFAULT_GUEST_EXEC_PID,
    SYNC_COMMANDS,
    SYNC_DELIMITED_COMMAND,
    GuestAgentProtocolServer,
)


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


_EXEC_COMMAND: Final[str] = "guest-exec"
_PING_COMMAND: Final[str] = "guest-ping"
_PLAIN_SYNC_COMMAND: Final[str] = "guest-sync"
_GUEST_PATH: Final[str] = "cmd.exe"
_GUEST_ARGS: Final[tuple[str, ...]] = ("/c", "exit", "0")

# The deadline the client sets on the command it abandons. Deliberately far
# below the production one: what is under test is what the channel does after a
# deadline expires, and every second spent proving that a deadline does expire
# is a second the suite spends learning nothing.
_ABANDON_AFTER_S: Final[float] = 1.0
# Resync budget for the offset-channel gates, patched over the production one
# for the same reason: two failed resyncs have to fit inside the stall below,
# which at the production budget would cost a minute of wall clock.
_SHORT_RESYNC_S: Final[float] = 1.0
# Long enough to outlast the abandoned command and both resyncs behind it, so
# every attempt to realign the channel fails while the agent is still holding
# the reply. That is what leaves the channel marked offset; the gates then wait
# for the stall to clear, because the misattribution being tested can only
# happen once the abandoned reply is actually readable.
_STALL_S: Final[float] = 8.0
_RECOVERY_MARGIN_S: Final[float] = 15.0
_RESYNCS_INSIDE_THE_STALL: Final[int] = 2

# How long the first command took on the live guest that produced this defect:
# the drive probe issued at 16:50:44 had not been answered when its deadline
# expired ten seconds later. A cold Windows guest faulting cmd.exe in off a
# qcow2 overlay is slow, not broken, and the production deadline has to absorb
# it without spending a resync.
_COLD_GUEST_FIRST_COMMAND_S: Final[float] = 12.0
# The same guest's connect-time sync, from the channel opening at 16:50:37 to
# guest-sync matching at 16:50:44. A resync budget under this cannot complete a
# handshake that guest completes.
_COLD_GUEST_SYNC_S: Final[float] = 7.0

# A sync budget deliberately smaller than one full per-attempt share, which is
# the condition under which the fallback sync command was never reached. The
# gate asserts on which commands were sent, not on this number.
_TIGHT_SYNC_BUDGET_S: Final[float] = 4.0

_CONNECT_BUDGET_S: Final[float] = 15.0
_MEASURE_BUDGET_S: Final[float] = 120.0
_FIRST_GUEST_PID: Final[int] = DEFAULT_GUEST_EXEC_PID
_SECOND_GUEST_PID: Final[int] = DEFAULT_GUEST_EXEC_PID + 1
_THIRD_GUEST_PID: Final[int] = DEFAULT_GUEST_EXEC_PID + 2
_NO_RESYNC: Final[int] = 0
_ATTEMPTS_A_BUDGET_MUST_HOLD: Final[int] = 2


async def _connected_client(server: GuestAgentProtocolServer) -> QemuGuestAgentClient:
    """Open a synchronised client against a running agent server.

    Args:
        server: The listening guest-agent server.

    Returns:
        QemuGuestAgentClient: A client whose handshake has completed.
    """
    client = QemuGuestAgentClient(port=server.port)
    connected = await client.connect(_CONNECT_BUDGET_S)
    assert connected, "the gate needs a synchronised channel before it can desynchronise one"
    return client


async def _abandon_a_command(client: QemuGuestAgentClient) -> None:
    """Issue a command the stalled agent will not answer in time.

    Args:
        client: A connected guest-agent client.
    """
    response = await client.guest_exec(_GUEST_PATH, _GUEST_ARGS, time_limit=_ABANDON_AFTER_S)
    assert not response.success, f"the agent answered inside {_ABANDON_AFTER_S}s, so no reply was ever left in flight: {response.data!r}"


async def _wait_for_stall_to_clear(server: GuestAgentProtocolServer, time_limit: float) -> None:
    """Wait until the stalled agent has produced the reply it held back.

    Args:
        server: The listening guest-agent server.
        time_limit: Seconds to wait for the agent to come out of its stall. An
            agent that does not is a broken test double rather than a failing
            client, so the wait is left to raise rather than be absorbed into
            an assertion about the channel.
    """
    await asyncio.wait_for(server.exec_answered.wait(), timeout=time_limit)


def _returned_pid(payload: object) -> object:
    """Extract the ``pid`` member of a ``guest-exec`` return payload.

    Args:
        payload: Whatever the client returned as the command's data.

    Returns:
        object: The ``pid`` member, or None when the payload is not a mapping
        at all - which is itself one of the shapes this defect produced.
    """
    if not isinstance(payload, dict):
        return None
    return cast("dict[str, object]", payload).get("pid")


@pytest_asyncio.fixture
async def stalled_agent() -> AsyncIterator[GuestAgentProtocolServer]:
    """Run an agent that holds back the first ``guest-exec`` reply.

    Yields:
        GuestAgentProtocolServer: The listening server.
    """
    server = GuestAgentProtocolServer(stall_command=_EXEC_COMMAND, stall_seconds=_STALL_S)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest.fixture
def short_resync(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the resync budget so two failed resyncs fit inside the stall.

    What the offset-channel gates test is the state the channel is left in once
    a resync has failed, which does not depend on how long it waited first.
    Shrinking the wait keeps them fast; the precondition keeps them from quietly
    ceasing to reproduce the condition they exist for.

    Args:
        monkeypatch: Fixture used to replace the module-level budget.
    """
    monkeypatch.setattr("intellicrack.sandbox.qemu._QEMU_GA_RESYNC_TIMEOUT", _SHORT_RESYNC_S)
    assert _ABANDON_AFTER_S + (_SHORT_RESYNC_S * _RESYNCS_INSIDE_THE_STALL) < _STALL_S, (
        "the stall no longer outlasts the abandoned command and the resyncs behind it, "
        "so the client would be realigned before the gate ever looks at it"
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("short_resync")
class TestAnOffsetChannelNeverAnswersTheWrongCommand:
    """A reply belongs to the command that earned it, or to no command at all."""

    async def test_the_next_command_does_not_receive_the_abandoned_reply(
        self,
        stalled_agent: GuestAgentProtocolServer,
    ) -> None:
        """The stalled ``guest-exec`` payload must never surface as a ping result.

        This is the live failure in miniature, and the order of events is the
        whole of it. The client gives up on ``guest-exec`` and the resync behind
        it goes unanswered, so the channel is left offset; only then does the
        agent come out of its stall and write the reply it was holding. That
        reply is now the next thing readable on the socket, which is exactly
        where the real guest was when the following command read it and the
        backend acted on a process id it had never been given.

        The gate waits for that reply to land before issuing the ping, because
        a ping issued while the agent is still stalled is refused by its own
        deadline no matter what the channel does - which proves nothing about
        whether replies are attributed correctly.

        Args:
            stalled_agent: Agent holding back the first ``guest-exec`` reply.
        """
        client = await _connected_client(stalled_agent)
        try:
            await _abandon_a_command(client)
            await _wait_for_stall_to_clear(stalled_agent, _RECOVERY_MARGIN_S)
            response = await client.ping(time_limit=_RECOVERY_MARGIN_S)
        finally:
            await client.disconnect()

        assert _returned_pid(response.data) != _FIRST_GUEST_PID, (
            f"guest-ping was answered with the abandoned command's process id: {response.data!r}"
        )
        assert response.success, f"the channel never recovered far enough to answer a ping of its own: {response.error}"

    async def test_a_bare_sync_id_is_never_returned_as_a_guest_exec_result(
        self,
        stalled_agent: GuestAgentProtocolServer,
    ) -> None:
        """No ``guest-exec`` may be answered with the shape of a sync reply.

        An offset channel does not merely shift replies by one. Behind the
        abandoned reply sit the answers to the resyncs that failed while the
        agent was stalled, and a client reading blind reaches those next -
        which is why the live symptom was not a wrong pid but no pid at all:
        ``qemu_ga_exec_no_pid ... response_payload=982749383``, a bare 31-bit
        sync id returned as the answer to a request for a process id.

        Two commands are issued once the agent starts answering again because
        that is how far into the stream the sync replies sit. Each must be
        answered with the process id the guest allocated for it and nothing
        else.

        Args:
            stalled_agent: Agent holding back the first ``guest-exec`` reply.
        """
        client = await _connected_client(stalled_agent)
        try:
            await _abandon_a_command(client)
            await _wait_for_stall_to_clear(stalled_agent, _RECOVERY_MARGIN_S)
            first = await client.guest_exec(_GUEST_PATH, _GUEST_ARGS, time_limit=_RECOVERY_MARGIN_S)
            second = await client.guest_exec(_GUEST_PATH, _GUEST_ARGS, time_limit=_RECOVERY_MARGIN_S)
        finally:
            await client.disconnect()

        for label, response in (("first", first), ("second", second)):
            assert not isinstance(response.data, int), (
                f"the {label} guest-exec after the agent recovered was answered with a bare sync id: {response.data!r}"
            )
        assert _returned_pid(first.data) == _SECOND_GUEST_PID, (
            f"the first guest-exec after recovery was answered with pid {_returned_pid(first.data)!r}; "
            f"{_FIRST_GUEST_PID} is the abandoned command's and {_SECOND_GUEST_PID} is this one's"
        )
        assert _returned_pid(second.data) == _THIRD_GUEST_PID, (
            f"the second guest-exec after recovery was answered with pid {_returned_pid(second.data)!r} "
            f"rather than its own {_THIRD_GUEST_PID}"
        )

    async def test_the_channel_comes_back_once_the_agent_answers_again(
        self,
        stalled_agent: GuestAgentProtocolServer,
    ) -> None:
        """Refusing an offset channel must not mean abandoning it.

        QEMU accepts this socket once for the life of the VM, so a channel that
        is merely offset has to be recoverable in place. Once the agent has
        written the reply it was holding, the next command must get its own -
        the second pid the guest allocated, not the first one's.

        Args:
            stalled_agent: Agent holding back the first ``guest-exec`` reply.
        """
        client = await _connected_client(stalled_agent)
        try:
            await _abandon_a_command(client)
            await _wait_for_stall_to_clear(stalled_agent, _RECOVERY_MARGIN_S)
            response = await client.guest_exec(_GUEST_PATH, _GUEST_ARGS, time_limit=_RECOVERY_MARGIN_S)
        finally:
            await client.disconnect()

        assert response.success, f"the channel never recovered after the agent started answering: {response.error}"
        assert _returned_pid(response.data) == _SECOND_GUEST_PID, (
            f"the recovered command was answered with pid {_returned_pid(response.data)!r}; "
            f"{_FIRST_GUEST_PID} is the abandoned command's pid and {_SECOND_GUEST_PID} is this one's"
        )


@pytest.mark.asyncio
class TestASlowFirstCommandIsNotALostCommand:
    """A cold guest is slow to run its first command, and that is not a fault."""

    async def test_the_reply_deadline_absorbs_a_cold_guests_first_command(self) -> None:
        """A first command as slow as the live guest's must not be abandoned.

        The whole cascade starts with a deadline the guest could not meet. A
        deadline sized for a warm Linux agent turns the ordinary cost of
        faulting ``cmd.exe`` in off a qcow2 overlay into a lost command, and a
        lost command into an offset channel. The production default has to
        absorb it outright - not recover from it, absorb it - so no resync is
        spent at all.
        """
        server = GuestAgentProtocolServer(
            stall_command=_EXEC_COMMAND,
            stall_seconds=_COLD_GUEST_FIRST_COMMAND_S,
        )
        await server.start()
        client = await _connected_client(server)
        syncs_at_connect = len(server.sync_ids)
        try:
            response = await client.guest_exec(_GUEST_PATH, _GUEST_ARGS)
        finally:
            await client.disconnect()
            await server.stop()

        assert response.success, (
            f"a first command that took {_COLD_GUEST_FIRST_COMMAND_S:.0f}s - what the live Windows guest took - "
            f"was abandoned by a {QEMU_GA_EXEC_TIMEOUT:.0f}s reply deadline: {response.error}"
        )
        assert _returned_pid(response.data) == _FIRST_GUEST_PID, (
            f"the slow command was answered with something other than its own pid: {response.data!r}"
        )
        assert len(server.sync_ids) - syncs_at_connect == _NO_RESYNC, (
            "a command that was answered inside its deadline still cost the channel a resync"
        )


@pytest.mark.asyncio
class TestTheSyncBudgetReachesEverySyncCommand:
    """An agent build carrying only one of the sync commands must be reachable."""

    async def test_a_tight_budget_still_tries_the_fallback_sync_command(self) -> None:
        """Every sync command must be sent before the budget is declared spent.

        The sync list exists because agent builds differ in which commands they
        answer. A per-attempt share the whole budget cannot outgrow makes that
        list a lie: the first command takes all of it and the rest are never
        sent, which is why the resync on the live guest failed without ever
        reaching the command that guest answers.
        """
        server = GuestAgentProtocolServer(silent_commands=frozenset({SYNC_DELIMITED_COMMAND}))
        await server.start()
        client = QemuGuestAgentClient(port=server.port)
        try:
            connected = await client.connect(_CONNECT_BUDGET_S)
            synchronised = await client.resynchronise(_TIGHT_SYNC_BUDGET_S)
        finally:
            await client.disconnect()
            await server.stop()

        assert connected, "the channel never opened, so the resync under test never ran"
        assert SYNC_DELIMITED_COMMAND in server.commands, "the silent command was never sent, so the budget was never put under pressure"
        assert _PLAIN_SYNC_COMMAND in server.commands, (
            f"the fallback sync command was never sent inside a {_TIGHT_SYNC_BUDGET_S:.0f}s budget, "
            f"so an agent build carrying only that command is unreachable: {server.commands}"
        )
        assert synchronised, "the resync failed against an agent that answers one of the two sync commands"


@pytest.mark.asyncio
class TestTheResyncBudgetIsSizedForTheGuestItRunsAgainst:
    """The budgets are edited independently, so their relationship is the gate."""

    async def test_the_resync_budget_covers_a_cold_guests_own_sync(self) -> None:
        """A timed-out command's resync must be able to finish what connect does.

        The resync is the same negotiation against the same agent that opening
        the channel performs. The live guest needed seven seconds for it; the
        resync was given five, so a handshake that had already succeeded once on
        that guest could not succeed a second time. The budget is measured here
        through the production path rather than read off a constant, so a change
        to how the resync spends it is caught along with a change to its size.
        """
        server = GuestAgentProtocolServer()
        await server.start()
        client = await _connected_client(server)
        server.silent_commands = frozenset({_PING_COMMAND, *SYNC_COMMANDS})
        started = time.monotonic()
        try:
            response = await client.ping(time_limit=_ABANDON_AFTER_S)
        finally:
            await client.disconnect()
            await server.stop()
        resync_budget = (time.monotonic() - started) - _ABANDON_AFTER_S

        assert not response.success, "the agent answered a command it was configured never to answer"
        assert resync_budget >= _COLD_GUEST_SYNC_S, (
            f"the resync gave up after {resync_budget:.1f}s; the guest that produced this defect "
            f"needed {_COLD_GUEST_SYNC_S:.0f}s to complete the very same handshake at connect time"
        )
        assert set(SYNC_COMMANDS).issubset(server.commands), f"the resync did not try every sync command it advertises: {server.commands}"

    async def test_the_readiness_budget_holds_more_than_one_lost_command(self) -> None:
        """Readiness must survive a command being lost, not just one attempt.

        A lost command costs its own reply deadline and then the resync behind
        it. The default readiness budget was ninety seconds when that pair cost
        fifteen, and would have stayed ninety while the reply deadline grew to
        fit a cold Windows guest - at which point one lost command consumes the
        entire handshake and there is nothing left to retry with.
        """
        server = GuestAgentProtocolServer()
        await server.start()
        client = await _connected_client(server)
        server.silent_commands = frozenset({_PING_COMMAND, *SYNC_COMMANDS})
        started = time.monotonic()
        try:
            await client.ping(time_limit=_ABANDON_AFTER_S)
        finally:
            await client.disconnect()
            await server.stop()
        lost_command_cost = (time.monotonic() - started) - _ABANDON_AFTER_S + QEMU_GA_EXEC_TIMEOUT
        budget = QEMUConfig().guest_agent_ready_timeout

        assert lost_command_cost < _MEASURE_BUDGET_S, (
            f"a single lost command now costs {lost_command_cost:.0f}s, which is longer than this gate "
            "was written to believe possible; the measurement, not the assertion, needs revisiting"
        )
        assert budget >= lost_command_cost * _ATTEMPTS_A_BUDGET_MUST_HOLD, (
            f"a {budget:.0f}s readiness budget cannot hold {_ATTEMPTS_A_BUDGET_MUST_HOLD} lost commands "
            f"at {lost_command_cost:.0f}s each, so the first slow command ends the whole start"
        )
