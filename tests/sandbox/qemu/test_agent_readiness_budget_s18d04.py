# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S18-D04: the start path must outwait the agent's serve cadence.

Measured live against a Windows 11 QEMU guest under WHPX: the guest booted,
virtio-net came up with ``10.0.2.15``, and ``agent.ps1`` bound and listened on
``:4445`` - all confirmed through the qemu-guest-agent channel while the
monitor channel was untouched. The sandbox nevertheless spent its entire
300-second budget logging ``guest_agent_connect_retry`` and failed with "guest
agent failed to connect", so no Windows run could ever reach the report tabs.

Nothing was wrong with the guest. ``agent.ps1`` is single-threaded: one
iteration of its main loop runs a whole ``Get-Process`` /
``Get-NetTCPConnection`` / ``Get-NetUDPEndpoint`` sweep and a one-second sleep
before it looks at its listener again, and under WHPX that iteration routinely
runs longer than the two seconds :meth:`GuestAgentClient.connect` allows a
single attempt by default. The connection itself is established the moment it
is offered - the guest's kernel accepts it into the listen backlog, and the
SLIRP hostfwd in front of that accepts unconditionally - so every attempt got a
real socket, wrote its readiness ping into it, gave up two seconds later and
threw the socket away while the agent was still working towards it. A healthy,
listening agent was declared unreachable for the whole timeout.

The fix widens the per-attempt budget the start path hands ``connect``. Three
properties are gated here: the one that fix delivers, and the two that stop it
costing more than it is worth.

* **Patience.** The real :meth:`QEMUSandbox.start` must complete against an
  agent that answers only after a sweep longer than the client's own default
  patience. The control in the same class drives the unmodified client at that
  default against the same agent and must fail, so the gate cannot pass by
  virtue of the modelled agent being an easy one.
* **Still prompt.** How long one attempt may take and how long to wait before
  the next are different questions. Before the agent binds, its port is refused
  outright and an attempt costs nothing, so the wait between attempts is the
  only thing deciding how quickly the sandbox notices it come up. An agent that
  binds late must therefore still be picked up promptly, not one handshake
  budget later.
* **The deadline still means something.** A caller that asked for a deadline
  did not ask for a deadline plus one more retry. Against a channel that never
  comes up, ``connect`` must return inside its ``time_limit`` rather than one
  whole interval past it.

The peer is the real :class:`IntellicrackAgentServer` over a real loopback
socket, and the client under test is the unmodified production one.
"""

from __future__ import annotations

import time
from typing import Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import (
    DEFAULT_GUEST_STDOUT,
    IntellicrackAgentServer,
)


# One monitoring sweep of the in-guest agent's main loop. Longer than the two
# seconds the client allows an attempt by default, and well short of what the
# start path now allows one, so the same modelled agent is out of reach for the
# first and comfortably in reach for the second.
_AGENT_SWEEP_S: Final[float] = 5.0

# Budget for the control. Long enough for several attempts at the client's own
# default interval, so its failure is a repeated one rather than a single
# unlucky attempt.
_CONTROL_BUDGET_S: Final[float] = 12.0
_MIN_CONTROL_ATTEMPTS: Final[int] = 2

# Budget the start path is given. Several sweeps long, so a start that fails
# here failed on the per-attempt budget and not on the total one.
_START_BUDGET_S: Final[float] = 25.0

# How long the modelled agent's port stays refused before it binds, and how
# promptly the start path has to notice once it does. An attempt against a
# refused port costs nothing, so what decides this is the wait between attempts
# and nothing else.
_AGENT_BIND_DELAY_S: Final[float] = 6.0
_BIND_NOTICE_TOLERANCE_S: Final[float] = 4.0

# A channel that never comes up, and the budget a caller gives it. The interval
# is far wider than the budget, which is the case the clamp exists for.
_NEVER_LISTENS: Final[int] = 10_000
_DEAD_CHANNEL_BUDGET_S: Final[float] = 3.0
_WIDE_RETRY_INTERVAL_S: Final[float] = 30.0
# What overrunning by a whole interval would cost, versus what honouring the
# deadline costs. The assertion sits between the two with room on both sides.
_OVERRUN_TOLERANCE_S: Final[float] = 4.0

_COMMAND_BUDGET_S: Final[float] = 5.0
_EXPECTED_EXIT_CODE: Final[int] = 0
_ECHO_COMMAND: Final[str] = "cmd.exe"
_ECHO_ARGS: Final[list[str]] = ["/c", "echo", "intellicrack"]

_QEMU_PID_STANDIN: Final[int] = -1
_EXPECTED_HANDSHAKES: Final[int] = 1
_EXPECTED_CONNECTIONS: Final[int] = 1


class _StartPathSandbox(QEMUSandbox):
    """``QEMUSandbox`` whose QEMU-hardware steps are genuine no-ops.

    The part the defect lives in is left entirely alone:
    ``_attach_qemu_agents`` builds the real :class:`GuestAgentClient` and drives
    the real ``_ensure_agent_connected`` against a real socket with the real
    per-attempt budget, and the real :meth:`QEMUSandbox.start` decides what
    status that leaves behind. Only the steps that need a running hypervisor -
    launching QEMU, registering its pid, the QMP monitor, the shared-volume
    mount and the qemu-guest-agent bootstrap - are replaced, by subclassing
    rather than by patching.
    """

    async def is_available(self) -> bool:
        """Report the backend as usable without probing for a QEMU binary.

        Returns:
            bool: Always True.
        """
        return True

    async def _spawn_qemu_process(self) -> None:
        """Skip launching QEMU; no hypervisor is involved in this gate."""

    async def _resolve_qemu_pid(self) -> int | None:
        """Return the stand-in pid of the VM that was never launched.

        Returns:
            int | None: The stand-in QEMU pid.
        """
        return _QEMU_PID_STANDIN

    async def _register_qemu_pid(self, qemu_pid: int | None) -> int:
        """Record the stand-in pid without touching the process manager.

        Args:
            qemu_pid: Pid resolved for the QEMU process.

        Returns:
            int: The pid stored on the sandbox state.
        """
        resolved = _QEMU_PID_STANDIN if qemu_pid is None else qemu_pid
        self.state.pid = resolved
        return resolved

    async def _connect_and_verify_qmp(self) -> None:
        """Skip the QMP monitor; no QEMU monitor socket exists here."""

    async def _mount_guest_shared_volume(self) -> None:
        """Skip the in-guest mount; no guest exists here."""

    async def _bootstrap_guest_agent(self) -> None:
        """Skip the qemu-guest-agent bootstrap; no guest exists here."""

    async def release_agent(self) -> None:
        """Close whatever agent client the start path left behind."""
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None


def _make_start_path_sandbox(agent_port: int, connect_timeout: float) -> _StartPathSandbox:
    """Build a sandbox whose agent channel points at the given port.

    Args:
        agent_port: Port the in-guest Intellicrack agent is reached on.
        connect_timeout: Total budget the start path may spend reaching it.

    Returns:
        _StartPathSandbox: Sandbox ready for a real ``start`` call.
    """
    return _StartPathSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            agent_port=agent_port,
            agent_connect_timeout=connect_timeout,
        ),
    )


class TestTheStartPathOutwaitsTheAgentsServeCadence:
    """A listening agent mid-sweep must not be mistaken for an absent one."""

    @pytest.mark.asyncio
    async def test_the_clients_default_patience_cannot_reach_this_agent(self) -> None:
        """The control: the unmodified default budget abandons every attempt.

        This is the observed failure reproduced at its own scale, and the shape
        of it is the point. Every attempt gets a real established socket and
        writes a real readiness ping into it. The agent is mid-sweep, so the
        ping sits in its receive buffer; the client gives up two seconds later
        and throws the socket away; the agent then reaches its listener,
        reads the ping and answers it to nobody. ``handshakes`` counts those
        answers, so a non-zero count next to ``connected is False`` is the whole
        defect in two numbers: the agent replied to probes the host had already
        abandoned.

        Without this control the gate below would pass just as happily against
        an agent that answers instantly, and would prove nothing.
        """
        server = IntellicrackAgentServer(serve_delay=_AGENT_SWEEP_S)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            connected = await client.connect(time_limit=_CONTROL_BUDGET_S)

            assert server.accepted >= _MIN_CONTROL_ATTEMPTS, (
                f"the control must have made repeated attempts for its failure to mean anything; accepted={server.accepted}"
            )
            assert server.handshakes >= 1, (
                "the modelled agent never answered a probe at all, so this control is failing over a dead agent "
                "rather than over one whose answers arrive after the client has stopped listening"
            )
            assert connected is False, "the client reached an agent whose sweep outlasts its own default patience"
            assert client.is_connected is False, "the client is holding a socket it abandoned mid-handshake"
        finally:
            await client.disconnect()
            await server.stop()

    @pytest.mark.asyncio
    async def test_start_reaches_an_agent_that_answers_after_its_sweep(self) -> None:
        """The gate: the real start path waits out one sweep and connects.

        The same agent the control could not reach, driven through the real
        :meth:`QEMUSandbox.start`. One accepted connection and one answered
        probe is the whole point: the start path must hold the first socket it
        opens until the agent gets round to it, rather than discarding it and
        opening another. The command afterwards proves the channel it kept is a
        working one and not merely a socket reported as connected.
        """
        server = IntellicrackAgentServer(serve_delay=_AGENT_SWEEP_S)
        await server.start()
        sandbox = _make_start_path_sandbox(server.port, _START_BUDGET_S)
        try:
            await sandbox.start()

            assert sandbox.state.status == "running", (
                f"the start path gave up on a listening agent; status={sandbox.state.status!r} last_error={sandbox.state.last_error!r}"
            )
            agent = sandbox.agent
            assert agent is not None, "a successful start left no agent client behind"
            assert agent.is_connected is True, "the start path reported success over a channel it does not hold"
            assert server.handshakes == _EXPECTED_HANDSHAKES, (
                f"the agent answered {server.handshakes} readiness probes; the start path is still discarding sockets "
                f"the agent had not reached yet"
            )
            assert server.accepted == _EXPECTED_CONNECTIONS, (
                f"the start path opened {server.accepted} connections for one agent that came up on the first; "
                f"each discarded socket is an attempt abandoned mid-sweep"
            )

            exit_code, stdout, stderr = await agent.send_command(
                _ECHO_COMMAND,
                _ECHO_ARGS,
                time_limit=_COMMAND_BUDGET_S,
            )

            assert exit_code == _EXPECTED_EXIT_CODE, f"the channel the start path kept could not run a command: {stderr!r}"
            assert stdout == DEFAULT_GUEST_STDOUT
            assert server.requests == [(_ECHO_COMMAND, tuple(_ECHO_ARGS))], (
                f"the command never reached the modelled agent; requests={server.requests}"
            )
        finally:
            await sandbox.release_agent()
            await server.stop()


class TestTheStartPathStillNoticesAnAgentComingUp:
    """A wider attempt budget must not become a wider wait between attempts."""

    @pytest.mark.asyncio
    async def test_start_picks_up_an_agent_that_binds_late(self) -> None:
        """The start path must keep knocking while the port is still refused.

        Until the in-guest agent reaches ``listen`` its port is refused
        outright, so an attempt costs nothing and the only thing deciding how
        quickly the sandbox notices it come up is the wait between attempts. If
        that wait is tied to the widened per-attempt budget, a start spends the
        whole budget asleep and reaches a long-since-listening agent seconds
        late - or, inside a shorter total budget, never.

        The assertion is on the clock, and only on the clock: a connection
        refused before the agent binds is never accepted, so the server's
        ``accepted`` count cannot see the retries and asserting on it would be
        an assertion that success alone satisfies.
        """
        server = IntellicrackAgentServer(listen_delay=_AGENT_BIND_DELAY_S)
        await server.start()
        sandbox = _make_start_path_sandbox(server.port, _START_BUDGET_S)
        started = time.monotonic()
        try:
            await sandbox.start()
            elapsed = time.monotonic() - started

            assert sandbox.state.status == "running", (
                f"the start path never reached an agent that bound after {_AGENT_BIND_DELAY_S}s; "
                f"status={sandbox.state.status!r} last_error={sandbox.state.last_error!r}"
            )
            assert elapsed <= _AGENT_BIND_DELAY_S + _BIND_NOTICE_TOLERANCE_S, (
                f"the agent bound at {_AGENT_BIND_DELAY_S}s and the start path only reached it at {elapsed:.2f}s; "
                f"it is sleeping out a whole handshake budget between attempts"
            )
        finally:
            await sandbox.release_agent()
            await server.stop()


class TestAWiderIntervalStillHonoursTheTotalBudget:
    """Widening the per-attempt budget must not widen the caller's deadline."""

    @pytest.mark.asyncio
    async def test_connect_returns_inside_its_deadline_on_a_dead_channel(self) -> None:
        """A hopeless connect must not overrun by a whole retry interval.

        The per-attempt interval here is ten times the total budget, which is
        the shape the fix above introduces: a caller widens the interval so a
        slow agent can be waited out, and a channel that never comes up then
        fails its first attempt immediately and sleeps. If that sleep is not
        clamped to what is left of the budget, a caller asking for three
        seconds waits thirty - and a start that should have surfaced its
        failure promptly instead sits on a dead guest.
        """
        server = IntellicrackAgentServer(dead_connections=_NEVER_LISTENS)
        await server.start()
        client = GuestAgentClient(port=server.port)
        started = time.monotonic()
        try:
            connected = await client.connect(
                time_limit=_DEAD_CHANNEL_BUDGET_S,
                retry_interval=_WIDE_RETRY_INTERVAL_S,
            )
            elapsed = time.monotonic() - started

            assert server.accepted >= 1, f"the client never reached the modelled channel; accepted={server.accepted}"
            assert connected is False, "connect() reported success over a channel the peer closed without speaking"
            assert elapsed <= _DEAD_CHANNEL_BUDGET_S + _OVERRUN_TOLERANCE_S, (
                f"connect() was given {_DEAD_CHANNEL_BUDGET_S}s and took {elapsed:.2f}s; it is sleeping out a whole "
                f"{_WIDE_RETRY_INTERVAL_S}s retry interval past the caller's deadline"
            )
        finally:
            await client.disconnect()
            await server.stop()
